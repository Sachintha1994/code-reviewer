"""Web dashboard.  Start with:  python -m uvicorn app.web_dashboard:app --reload

Binds to 127.0.0.1 by default; local folders are limited to the allowed roots
(reviewer.yml server.allowed_roots or REVIEWER_ALLOWED_ROOTS).
"""
from __future__ import annotations

import asyncio
import json
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator

from app.config import DATA_DIR, allowed_roots, load_config
from app.core.ai_review import AIReviewer
from app.core.diff import SAFE_REF
from app.core.orchestrator import CodeReviewOrchestrator, clone_github_repo, validate_github_url
from app.core.rescore import rescore
from app.core.storage import Storage
from app.core.uploads import UploadError, extract_zip, limits
from app.reports.pdf_report import generate_pdf_report

WEB_DIR = Path(__file__).resolve().parent / "web"
app = FastAPI(title="AI Code Reviewer", version="3.0")
app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
storage = Storage()

UPLOAD_DIR = DATA_DIR / "uploads"                 # unpacked ZIP uploads, one folder per project
PROGRESS: Dict[str, List[Dict[str, Any]]] = {}   # scan id -> progress events
PROGRESS_LOCK = threading.Lock()
RUNNING: Dict[str, str] = {}                      # project id -> scan id


def _check_ref(value: Optional[str]) -> str:
    value = (value or "").strip()
    if value and not SAFE_REF.match(value):
        raise ValueError("branch name contains invalid characters")
    return value


class ProjectIn(BaseModel):
    name: str = Field(min_length=1, max_length=100)
    source_type: Literal["local", "github"]
    path_or_url: str = Field(min_length=1, max_length=1000)
    base_ref: str = Field(default="", max_length=200)   # empty = review the whole project

    @field_validator("base_ref")
    @classmethod
    def _valid_ref(cls, value):
        return _check_ref(value)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    base_ref: Optional[str] = Field(default=None, max_length=200)

    @field_validator("base_ref")
    @classmethod
    def _valid_ref(cls, value):
        return _check_ref(value)


class ScanIn(BaseModel):
    base_ref: Optional[str] = None
    whole_project: bool = False

    @field_validator("base_ref")
    @classmethod
    def _valid_ref(cls, value):
        return _check_ref(value)


class SuppressIn(BaseModel):
    fingerprint: str = Field(min_length=4, max_length=80)
    kind: Literal["ignore", "false_positive"]
    reason: str = Field(default="", max_length=300)


def validate_local_path(raw: str, needs_git: bool = True) -> str:
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
                                 "Add it to server.allowed_roots in reviewer.yml.")
    if needs_git and not (path / ".git").exists():
        raise HTTPException(400, "this folder isn't a git repository, so there are no changes to compare. "
                                 "Leave the branch empty to review the whole project instead.")
    return str(path)


def public_project(p: Dict[str, Any]) -> Dict[str, Any]:
    keep = ("id", "name", "source_type", "path_or_url", "base_ref", "created_at", "last_verdict", "last_scan")
    out = {k: p.get(k) for k in keep}
    if p.get("source_type") == "zip":
        out["path_or_url"] = f"Uploaded ZIP: {Path(p['path_or_url']).name}"
        out["base_ref"] = ""
    out["running_scan"] = RUNNING.get(p["id"])
    return out


def get_project_or_404(pid: str) -> Dict[str, Any]:
    project = storage.get_project(pid)
    if not project:
        raise HTTPException(404, "project not found")
    return project


def emit(scan_id: str, event: Dict[str, Any]) -> None:
    with PROGRESS_LOCK:
        PROGRESS.setdefault(scan_id, []).append({**event, "t": round(time.time(), 2)})


def run_scan(scan_id: str, project: Dict[str, Any], base_ref: str) -> None:
    pid = project["id"]
    try:
        target = project["path_or_url"]
        if project["source_type"] == "zip":
            base_ref = ""  # an uploaded ZIP has no history: always a whole-project review
        if project["source_type"] == "github":
            emit(scan_id, {"stage": "clone", "message": "Cloning repository"})
            target = clone_github_repo(target, pid)
        result = CodeReviewOrchestrator(
            target, base_ref=base_ref, suppressions=storage.suppressions(pid),
            progress=lambda e: emit(scan_id, e), cache_get=storage.cache_get, cache_set=storage.cache_set,
        ).run_full_review()
        storage.finish_scan(scan_id, result.to_dict())
        emit(scan_id, {"stage": "end", "status": "done", "verdict": result.verdict})
    except Exception as exc:  # report every failure to the UI instead of hanging
        storage.fail_scan(scan_id, str(exc))
        emit(scan_id, {"stage": "end", "status": "error", "message": str(exc)})
    finally:
        RUNNING.pop(pid, None)


def _latest_done(pid: str) -> Dict[str, Any]:
    scan = storage.latest_scan(pid)
    if not scan or scan.get("status") != "done" or "files" not in (scan.get("result") or {}):
        raise HTTPException(404, "no finished review for this project yet")
    return scan


def _rescore_latest(pid: str) -> Dict[str, Any]:
    scan = _latest_done(pid)
    result = rescore(scan["result"], storage.suppressions(pid))
    storage.update_result(scan["id"], result)
    scan["result"], scan["verdict"] = result, result["verdict"]
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
        data["path_or_url"] = validate_local_path(req.path_or_url, needs_git=bool(req.base_ref))
    else:
        try:
            data["path_or_url"] = validate_github_url(req.path_or_url)
        except ValueError as exc:
            raise HTTPException(400, str(exc)) from None
    return public_project(storage.add_project(data))


async def _receive_zip(upload: UploadFile) -> Path:
    """Stream the upload to a temporary file, enforcing the size limit."""
    if not (upload.filename or "").lower().endswith(".zip"):
        raise HTTPException(400, "choose a .zip file")
    max_bytes = limits(load_config())["max_zip_mb"] * 1024 * 1024
    incoming = UPLOAD_DIR / "_incoming"
    incoming.mkdir(parents=True, exist_ok=True)
    tmp = incoming / f"{uuid.uuid4()}.zip"
    size = 0
    try:
        with open(tmp, "wb") as out:
            while True:
                chunk = await upload.read(1024 * 1024)
                if not chunk:
                    break
                size += len(chunk)
                if size > max_bytes:
                    raise HTTPException(413, f"the ZIP is larger than {max_bytes // (1024 * 1024)} MB")
                out.write(chunk)
    except BaseException:
        tmp.unlink(missing_ok=True)
        raise
    return tmp


async def _unpack(pid: str, tmp: Path) -> str:
    try:
        root = await asyncio.to_thread(extract_zip, tmp, UPLOAD_DIR / pid, load_config())
    except UploadError as exc:
        raise HTTPException(400, str(exc)) from None
    finally:
        tmp.unlink(missing_ok=True)
    return str(root)


@app.post("/api/projects/zip", status_code=201)
async def add_zip_project(name: str = Form(..., min_length=1, max_length=100),  # noqa: B008
                          file: UploadFile = File(...)):  # noqa: B008
    tmp = await _receive_zip(file)
    project = storage.add_project({"name": name.strip(), "source_type": "zip", "path_or_url": "", "base_ref": ""})
    try:
        root = await _unpack(project["id"], tmp)
    except HTTPException:
        storage.delete_project(project["id"])
        shutil.rmtree(UPLOAD_DIR / project["id"], ignore_errors=True)
        raise
    return public_project(storage.update_project(project["id"], {"path_or_url": root}) or project)


@app.post("/api/projects/{pid}/zip")
async def replace_zip(pid: str, file: UploadFile = File(...)):  # noqa: B008
    project = get_project_or_404(pid)
    if project["source_type"] != "zip":
        raise HTTPException(400, "only projects created from a ZIP can take a new ZIP")
    if pid in RUNNING:
        raise HTTPException(409, "wait for the running review to finish")
    tmp = await _receive_zip(file)
    root = await _unpack(pid, tmp)
    return public_project(storage.update_project(pid, {"path_or_url": root}) or project)


@app.patch("/api/projects/{pid}")
async def update_project(pid: str, req: ProjectUpdate):
    get_project_or_404(pid)
    updated = storage.update_project(pid, req.model_dump(exclude_none=True))
    if updated is None:
        raise HTTPException(404, "project not found")
    return public_project(updated)


@app.delete("/api/projects/{pid}", status_code=204)
async def delete_project(pid: str):
    get_project_or_404(pid)
    storage.delete_project(pid)
    for folder in (DATA_DIR / "cloned_projects" / pid, UPLOAD_DIR / pid):
        if folder.is_dir():
            shutil.rmtree(folder, ignore_errors=True)


# --------------------------------------------------------------------------- #
# Reviews
# --------------------------------------------------------------------------- #

@app.post("/api/projects/{pid}/scans", status_code=202)
async def start_scan(pid: str, req: ScanIn, background: BackgroundTasks):
    project = get_project_or_404(pid)
    if pid in RUNNING:
        raise HTTPException(409, "a review is already running for this project")
    # an empty branch means the whole project is reviewed; uploaded ZIPs are always reviewed whole
    whole = req.whole_project or project.get("source_type") == "zip"
    base_ref = "" if whole else (req.base_ref or project.get("base_ref") or "")
    reviewer = AIReviewer(load_config())
    if not reviewer.available:
        raise HTTPException(400, reviewer.reason)
    scan_id = storage.start_scan(pid)
    RUNNING[pid] = scan_id
    emit(scan_id, {"stage": "queued", "message": "Review queued"})
    background.add_task(run_scan, scan_id, project, base_ref)
    return {"scan_id": scan_id}


@app.get("/api/projects/{pid}/latest")
async def latest(pid: str):
    get_project_or_404(pid)
    return {"scan": storage.latest_scan(pid)}


@app.get("/api/projects/{pid}/history")
async def history(pid: str):
    get_project_or_404(pid)
    return storage.history(pid)


@app.get("/api/scans/{sid}")
async def get_scan(sid: str):
    scan = storage.get_scan(sid)
    if not scan:
        raise HTTPException(404, "review not found")
    return scan


@app.get("/api/scans/{sid}/events")
async def scan_events(sid: str, request: Request):
    if not storage.get_scan(sid, with_result=False):
        raise HTTPException(404, "review not found")

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
            if not events:  # server restarted or old review: report the stored state
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
    if not scan or "files" not in (scan.get("result") or {}):
        raise HTTPException(404, "no finished review to export")
    project = storage.get_project(scan["project_id"]) or {"name": "project"}
    out_dir = DATA_DIR / "reports"
    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{sid}.pdf"
    await asyncio.to_thread(generate_pdf_report, project["name"], scan["result"], str(path))
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in project["name"])[:60] or "report"
    return FileResponse(str(path), media_type="application/pdf", filename=f"{safe}_ai_review.pdf")


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


@app.get("/api/ai")
async def ai_status():
    reviewer = AIReviewer(load_config())
    return {"available": reviewer.available, "provider": reviewer.provider, "model": reviewer.model,
            "reason": reviewer.reason, "git": bool(shutil.which("git"))}


if __name__ == "__main__":  # python -m app.web_dashboard
    import uvicorn

    uvicorn.run("app.web_dashboard:app", host="127.0.0.1", port=8000, reload=False)
