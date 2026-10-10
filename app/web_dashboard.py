"""Web dashboard.  Start with:  uvicorn app.web_dashboard:app --reload

Binds to 127.0.0.1 by default; local folders are limited to the allowed roots
(quality-gates.yml server.allowed_roots or REVIEWER_ALLOWED_ROOTS).
"""
from __future__ import annotations

import asyncio
import json
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import BackgroundTasks, FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator

from app.config import DATA_DIR, allowed_roots, load_config
from app.core.diff import SAFE_REF
from app.core.orchestrator import CodeReviewOrchestrator, clone_github_repo, validate_github_url
from app.core.rescore import rescore
from app.core.storage import Storage
from app.reports.pdf_report import generate_pdf_report
from app.scanners.base import ToolMissing, find_tool
from app.scanners.sonarqube_client import SonarQubeClient

WEB_DIR = Path(__file__).resolve().parent / "web"
app = FastAPI(title="Code Reviewer", version="2.0")
app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
storage = Storage()

# scan id -> list of progress events (kept in memory while the server runs)
PROGRESS: Dict[str, List[Dict[str, Any]]] = {}
PROGRESS_LOCK = threading.Lock()
RUNNING: Dict[str, str] = {}  # project id -> scan id


# --------------------------------------------------------------------------- #
# Request models
# --------------------------------------------------------------------------- #

def _check_ref(value: Optional[str]) -> str:
    value = (value or "").strip()
    if value and not SAFE_REF.match(value):
        raise ValueError("branch or ref contains invalid characters")
    return value


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    source_type: Literal["local", "github"]
    path_or_url: str = Field(min_length=1, max_length=1000)
    base_ref: str = ""
    sonar_host: str = ""
    sonar_token: str = ""
    sonar_project_key: str = ""

    @field_validator("base_ref")
    @classmethod
    def _valid_ref(cls, value):
        return _check_ref(value)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    base_ref: Optional[str] = None
    sonar_host: Optional[str] = None
    sonar_token: Optional[str] = None
    sonar_project_key: Optional[str] = None

    @field_validator("base_ref")
    @classmethod
    def _valid_ref(cls, value):
        return _check_ref(value)


class ScanIn(BaseModel):
    base_ref: Optional[str] = None
    use_ai: bool = True

    @field_validator("base_ref")
    @classmethod
    def _valid_ref(cls, value):
        return _check_ref(value)


class SuppressIn(BaseModel):
    fingerprint: str = Field(min_length=4, max_length=80)
    kind: Literal["ignore", "false_positive"]
    reason: str = Field(default="", max_length=300)


class SonarTestIn(BaseModel):
    host: str
    token: str
    project_key: str
    project_id: Optional[str] = None


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #

def validate_local_path(raw: str) -> str:
    path = Path(raw.strip().strip('"')).expanduser()
    try:
        path = path.resolve(strict=True)
    except (FileNotFoundError, OSError):
        raise HTTPException(400, f"folder not found: {raw}") from None
    if not path.is_dir():
        raise HTTPException(400, "path must be a folder")
    roots = allowed_roots(load_config())
    if not any(path == root or root in path.parents for root in roots):
        allowed = ", ".join(str(r) for r in roots)
        raise HTTPException(400, f"folder is outside the allowed locations ({allowed}). "
                                 "Add it to server.allowed_roots in quality-gates.yml.")
    return str(path)


def public_project(p: Dict[str, Any]) -> Dict[str, Any]:
    out = {k: v for k, v in p.items() if k != "sonar_token"}
    out["has_sonar_token"] = bool(p.get("sonar_token"))
    out["running_scan"] = RUNNING.get(p["id"])
    return out


def get_project_or_404(pid: str) -> Dict[str, Any]:
    project = storage.get_project(pid)
    if not project:
        raise HTTPException(404, "project not found")
    return project


def emit(scan_id: str, event: Dict[str, Any]) -> None:
    event = {**event, "t": round(time.time(), 2)}
    with PROGRESS_LOCK:
        PROGRESS.setdefault(scan_id, []).append(event)


def run_scan(scan_id: str, project: Dict[str, Any], base_ref: str, use_ai: bool) -> None:
    pid = project["id"]
    try:
        target = project["path_or_url"]
        is_remote = project["source_type"] == "github"
        if is_remote:
            emit(scan_id, {"stage": "clone", "message": "Cloning repository"})
            target = clone_github_repo(target, pid, full_history=bool(base_ref))
        sonar = None
        if project.get("sonar_host") and project.get("sonar_token") and project.get("sonar_project_key"):
            sonar = {"host": project["sonar_host"], "token": project["sonar_token"],
                     "project_key": project["sonar_project_key"]}
        orchestrator = CodeReviewOrchestrator(
            target, sonar_config=sonar, base_ref=base_ref, use_ai=use_ai, is_remote=is_remote,
            baseline=storage.baseline(pid), suppressions=storage.suppressions(pid),
            progress=lambda e: emit(scan_id, e), cache_get=storage.cache_get, cache_set=storage.cache_set,
        )
        result = orchestrator.run_full_review()
        storage.finish_scan(scan_id, result.to_dict())
        emit(scan_id, {"stage": "end", "status": "done", "verdict": result.verdict})
    except Exception as exc:  # report every failure to the UI instead of hanging
        storage.fail_scan(scan_id, f"{type(exc).__name__}: {exc}")
        emit(scan_id, {"stage": "end", "status": "error", "message": str(exc)})
    finally:
        RUNNING.pop(pid, None)


def _latest_done(pid: str) -> Dict[str, Any]:
    scan = storage.latest_scan(pid)
    if not scan or scan.get("status") != "done" or "result" not in scan:
        raise HTTPException(404, "no finished scan for this project yet")
    return scan


def _rescore_latest(pid: str) -> Dict[str, Any]:
    scan = _latest_done(pid)
    result = rescore(scan["result"], storage.suppressions(pid), storage.baseline(pid), scan["result"].get("target"))
    storage.update_result(scan["id"], result)
    scan["result"] = result
    scan["verdict"], scan["score"] = result["verdict"], result["health"]["score"]
    return scan


# --------------------------------------------------------------------------- #
# Pages
# --------------------------------------------------------------------------- #

@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"version": app.version})


# --------------------------------------------------------------------------- #
# Projects
# --------------------------------------------------------------------------- #

@app.get("/api/projects")
async def list_projects():
    return [public_project(p) for p in storage.list_projects()]


@app.post("/api/projects", status_code=201)
async def add_project(req: ProjectIn):
    data = req.model_dump()
    if req.source_type == "local":
        data["path_or_url"] = validate_local_path(req.path_or_url)
    else:
        try:
            data["path_or_url"] = validate_github_url(req.path_or_url)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
    return public_project(storage.add_project(data))


@app.patch("/api/projects/{pid}")
async def update_project(pid: str, req: ProjectUpdate):
    get_project_or_404(pid)
    data = req.model_dump(exclude_none=True)
    if data.get("sonar_token") == "":
        data.pop("sonar_token")  # empty field in the form means "keep the stored token"
    updated = storage.update_project(pid, data)
    if updated is None:
        raise HTTPException(404, "project not found")
    return public_project(updated)


@app.delete("/api/projects/{pid}", status_code=204)
async def delete_project(pid: str):
    get_project_or_404(pid)
    storage.delete_project(pid)


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #

@app.post("/api/projects/{pid}/scans", status_code=202)
async def start_scan(pid: str, req: ScanIn, background: BackgroundTasks):
    project = get_project_or_404(pid)
    if pid in RUNNING:
        raise HTTPException(409, "a scan is already running for this project")
    base_ref = req.base_ref if req.base_ref is not None else project.get("base_ref", "")
    scan_id = storage.start_scan(pid)
    RUNNING[pid] = scan_id
    emit(scan_id, {"stage": "queued", "message": "Scan queued"})
    background.add_task(run_scan, scan_id, project, base_ref or "", req.use_ai)
    return {"scan_id": scan_id}


@app.get("/api/projects/{pid}/latest")
async def latest(pid: str):
    get_project_or_404(pid)
    scan = storage.latest_scan(pid)
    if not scan:
        return {"scan": None}
    return {"scan": scan}


@app.get("/api/projects/{pid}/history")
async def history(pid: str):
    get_project_or_404(pid)
    return storage.history(pid)


@app.get("/api/scans/{sid}")
async def get_scan(sid: str):
    scan = storage.get_scan(sid)
    if not scan:
        raise HTTPException(404, "scan not found")
    return scan


@app.get("/api/scans/{sid}/events")
async def scan_events(sid: str, request: Request):
    if not storage.get_scan(sid, with_result=False):
        raise HTTPException(404, "scan not found")

    async def stream():
        sent = 0
        last_ping = time.time()
        while True:
            if await request.is_disconnected():
                return
            with PROGRESS_LOCK:
                events = list(PROGRESS.get(sid, []))
            for event in events[sent:]:
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("stage") == "end":
                    return
            sent = len(events)
            if not events:  # server restarted or old scan: report the stored state
                scan = storage.get_scan(sid, with_result=False) or {}
                if scan.get("status") != "running":
                    yield f"data: {json.dumps({'stage': 'end', 'status': scan.get('status', 'error')})}\n\n"
                    return
            if time.time() - last_ping > 15:
                last_ping = time.time()
                yield ": keep-alive\n\n"
            await asyncio.sleep(0.4)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.get("/api/scans/{sid}/report.pdf")
async def pdf_report(sid: str):
    scan = storage.get_scan(sid)
    if not scan or "result" not in scan:
        raise HTTPException(404, "no finished result for this scan")
    project = storage.get_project(scan["project_id"]) or {"name": "project"}
    out_dir = DATA_DIR / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{sid}.pdf"
    await asyncio.to_thread(generate_pdf_report, project["name"], scan["result"], str(path))
    safe_name = "".join(c if c.isalnum() or c in "-_" else "_" for c in project["name"])[:60] or "report"
    return FileResponse(str(path), media_type="application/pdf", filename=f"{safe_name}_code_review.pdf")


# --------------------------------------------------------------------------- #
# Suppressions and baseline
# --------------------------------------------------------------------------- #

@app.post("/api/projects/{pid}/suppressions")
async def suppress(pid: str, req: SuppressIn):
    get_project_or_404(pid)
    storage.add_suppression(pid, req.fingerprint, req.kind, req.reason.strip())
    return _rescore_latest(pid)


@app.delete("/api/projects/{pid}/suppressions/{fingerprint}")
async def unsuppress(pid: str, fingerprint: str):
    get_project_or_404(pid)
    storage.remove_suppression(pid, fingerprint)
    return _rescore_latest(pid)


@app.post("/api/projects/{pid}/baseline")
async def set_baseline(pid: str):
    scan = _latest_done(pid)
    fingerprints = {f["fingerprint"] for f in scan["result"].get("findings", []) if f.get("fingerprint")}
    storage.set_baseline(pid, fingerprints)
    return _rescore_latest(pid)


@app.delete("/api/projects/{pid}/baseline")
async def clear_baseline(pid: str):
    get_project_or_404(pid)
    storage.clear_baseline(pid)
    return _rescore_latest(pid)


# --------------------------------------------------------------------------- #
# Settings and tools
# --------------------------------------------------------------------------- #

TOOLS = [
    ("ruff", "ruff", "pip install ruff"), ("semgrep", "semgrep", "pip install semgrep (or use WSL)"),
    ("bandit", "bandit", "pip install bandit"), ("mypy", "mypy", "pip install mypy"),
    ("lizard", "lizard", "pip install lizard"), ("gitleaks", None, "download from github.com/gitleaks/gitleaks/releases"),
    ("trivy", None, "download from github.com/aquasecurity/trivy/releases"), ("pytest", "pytest", "pip install pytest pytest-cov"),
    ("jscpd", None, "npm install -g jscpd"), ("git", None, "install Git"),
    ("mvn", None, "install Maven and a JDK (or use the project's mvnw)"),
    ("pmd", None, "download PMD 7 from pmd.github.io and add its bin folder to PATH"),
]


@app.get("/api/tools")
async def tools():
    cfg = load_config()
    out = []
    for name, module, hint in TOOLS:
        try:
            cmd = find_tool(name, cfg, python_module=module)
            out.append({"name": name, "installed": True, "path": cmd[0] if len(cmd) == 1 else f"{cmd[0]} -m {module}"})
        except ToolMissing:
            out.append({"name": name, "installed": False, "hint": hint})
    from app.core.llm_analyzer import AIReviewer

    ai = AIReviewer(cfg)
    out.append({"name": "AI review", "installed": ai.available,
                "path": f"{ai.provider}/{ai.model}" if ai.available else None, "hint": ai.reason})
    return out


@app.post("/api/sonar/test")
async def sonar_test(req: SonarTestIn):
    token = req.token
    if not token and req.project_id:
        token = (storage.get_project(req.project_id) or {}).get("sonar_token", "")
    if not token:
        return {"ok": False, "error": "token is required"}
    client = SonarQubeClient(req.host, token, timeout=10)
    return await asyncio.to_thread(client.test_connection, req.project_key)


if __name__ == "__main__":  # python -m app.web_dashboard
    import uvicorn

    uvicorn.run("app.web_dashboard:app", host="127.0.0.1", port=8000, reload=False)
