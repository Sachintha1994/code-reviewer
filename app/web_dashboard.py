"""Web dashboard.  Start with:  python -m uvicorn app.web_dashboard:app --reload

Binds to 127.0.0.1 by default; local folders are limited to the allowed roots
(reviewer.yml server.allowed_roots or REVIEWER_ALLOWED_ROOTS).
"""
from __future__ import annotations

import asyncio
import json
import os
import shutil
import threading
import time
import uuid
from pathlib import Path
from typing import Any, Dict, List, Literal, Optional

from fastapi import BackgroundTasks, FastAPI, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import FileResponse, HTMLResponse, Response, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, Field, field_validator

from app.config import DATA_DIR, allowed_roots, load_config, read_ui_settings, ui_settings_path, write_ui_settings
from app.core.ai_review import PROVIDERS, AIReviewer
from app.core.compare import compare_results
from app.core.diff import SAFE_REF
from app.core.files import exclude_patterns, is_excluded, language_of, long_path
from app.core.orchestrator import CodeReviewOrchestrator, clone_github_repo, normalize_paths, validate_github_url
from app.core.rescore import rescore
from app.core.storage import Storage
from app.core.uploads import UploadError, extract_zip, limits
from app.reports.exports import to_csv, to_json, to_markdown, to_patch
from app.reports.pdf_report import generate_pdf_report

WEB_DIR = Path(__file__).resolve().parent / "web"
app = FastAPI(title="AI Code Reviewer", version="3.1")
app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")
templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
storage = Storage()

UPLOAD_DIR = DATA_DIR / "uploads"                 # unpacked ZIP uploads, one folder per project
KEEP_ALWAYS = {"reviewer.yml", ".reviewerignore"}


def upload_dir(pid: str) -> Path:
    return UPLOAD_DIR / pid[:8]   # short, so deep source paths stay under Windows' path limit
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
    rules: str = Field(default="", max_length=4000)        # extra review rules, one per line
    extra_exclude: str = Field(default="", max_length=4000)  # extra exclude patterns, one per line

    @field_validator("base_ref")
    @classmethod
    def _valid_ref(cls, value):
        return _check_ref(value)


class ProjectUpdate(BaseModel):
    name: Optional[str] = Field(default=None, min_length=1, max_length=100)
    base_ref: Optional[str] = Field(default=None, max_length=200)
    rules: Optional[str] = Field(default=None, max_length=4000)
    extra_exclude: Optional[str] = Field(default=None, max_length=4000)

    @field_validator("base_ref")
    @classmethod
    def _valid_ref(cls, value):
        return _check_ref(value)


class ScanIn(BaseModel):
    base_ref: Optional[str] = None
    whole_project: bool = False
    paths: List[str] = Field(default_factory=list, max_length=50000)   # review only these files/folders

    @field_validator("base_ref")
    @classmethod
    def _valid_ref(cls, value):
        return _check_ref(value)


class SuppressIn(BaseModel):
    fingerprint: str = Field(min_length=4, max_length=80)
    kind: Literal["ignore", "false_positive"]
    reason: str = Field(default="", max_length=300)


class SettingsIn(BaseModel):
    provider: Literal["", "gemini", "groq", "openai", "ollama"] = ""
    model: str = Field(default="", max_length=100)
    focus: List[str] = Field(default_factory=list, max_length=40)
    min_confidence: float = Field(default=0.5, ge=0, le=1)
    max_lines_per_request: int = Field(default=0, ge=0, le=20000)
    max_workers: int = Field(default=2, ge=1, le=16)
    max_files: int = Field(default=1000, ge=1, le=20000)
    whole_file_up_to: int = Field(default=400, ge=0, le=20000)
    context_lines: int = Field(default=25, ge=0, le=200)
    summary: bool = True
    daily_request_limit: int = Field(default=0, ge=0, le=1_000_000)
    exclude: List[str] = Field(default_factory=list, max_length=300)

    @field_validator("focus", "exclude")
    @classmethod
    def _clean(cls, items):
        out = [str(i).strip()[:300] for i in items]
        return [i for i in out if i]


AI_SETTING_KEYS = [k for k in SettingsIn.model_fields if k != "exclude"]
KEY_ENV = {"gemini": ("GEMINI_API_KEY", "GOOGLE_API_KEY"), "groq": ("GROQ_API_KEY",), "openai": ("OPENAI_API_KEY",)}


def lines_of(text: Optional[str]) -> List[str]:
    return [line.strip() for line in (text or "").splitlines() if line.strip()]


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
    keep = ("id", "name", "source_type", "path_or_url", "base_ref", "rules", "extra_exclude",
            "created_at", "last_verdict", "last_scan")
    out = {k: p.get(k) or ("" if k in ("rules", "extra_exclude") else p.get(k)) for k in keep}
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


def project_overrides(project: Dict[str, Any], target: str) -> Optional[Dict[str, Any]]:
    """The project's own review rules and excludes, added to the configured ones."""
    rules, extra = lines_of(project.get("rules")), lines_of(project.get("extra_exclude"))
    if not rules and not extra:
        return None
    cfg = load_config(target)
    out: Dict[str, Any] = {}
    if rules:
        out["ai"] = {"focus": list((cfg.get("ai") or {}).get("focus") or []) + rules}
    if extra:
        out["exclude"] = list(cfg.get("exclude") or []) + extra
    return out


def project_target(project: Dict[str, Any], fresh_clone: bool = False) -> str:
    if project["source_type"] != "github":
        return project["path_or_url"]
    existing = DATA_DIR / "cloned_projects" / project["id"]
    if not fresh_clone and (existing / ".git").exists():
        return str(existing)
    return clone_github_repo(project["path_or_url"], project["id"])


def scan_base_ref(project: Dict[str, Any], req: ScanIn) -> str:
    # an empty branch means the whole project is reviewed; uploaded ZIPs are always reviewed whole
    whole = req.whole_project or project.get("source_type") == "zip"
    return "" if whole else (req.base_ref or project.get("base_ref") or "")


def run_scan(scan_id: str, project: Dict[str, Any], base_ref: str, paths: Optional[List[str]] = None) -> None:
    pid = project["id"]
    try:
        if project["source_type"] == "github":
            emit(scan_id, {"stage": "clone", "message": "Cloning repository"})
        target = project_target(project, fresh_clone=True)
        previous = storage.latest_done_scan(pid)
        result = CodeReviewOrchestrator(
            target, base_ref=base_ref, config_overrides=project_overrides(project, target),
            suppressions=storage.suppressions(pid), progress=lambda e: emit(scan_id, e),
            cache_get=storage.cache_get, cache_set=storage.cache_set, include_paths=paths,
            on_request=lambda provider, model: storage.add_usage(provider, model),
        ).run_full_review()
        data = compare_results(result.to_dict(), (previous or {}).get("result"), previous)
        storage.finish_scan(scan_id, data)
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
    cfg = load_config()
    excludes = exclude_patterns(Path("."), {"exclude": cfg.get("exclude")})

    def keep(rel: str) -> bool:
        # only what the reviewer reads: source and config files outside build/dependency folders
        name = rel.rsplit("/", 1)[-1]
        return name in KEEP_ALWAYS or (bool(language_of(rel)) and not is_excluded(rel, excludes))

    try:
        root = await asyncio.to_thread(extract_zip, tmp, upload_dir(pid), cfg, keep)
    except UploadError as exc:
        raise HTTPException(400, str(exc)) from None
    except OSError as exc:
        raise HTTPException(400, f"couldn't unpack the ZIP: {exc}") from None
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
    except Exception:  # never leave a half-created project behind
        storage.delete_project(project["id"])
        shutil.rmtree(long_path(upload_dir(project["id"])), ignore_errors=True)
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
    for folder in (DATA_DIR / "cloned_projects" / pid, upload_dir(pid)):
        if folder.is_dir():
            shutil.rmtree(long_path(folder), ignore_errors=True)


# --------------------------------------------------------------------------- #
# Reviews
# --------------------------------------------------------------------------- #

@app.post("/api/projects/{pid}/scans", status_code=202)
async def start_scan(pid: str, req: ScanIn, background: BackgroundTasks):
    project = get_project_or_404(pid)
    if pid in RUNNING:
        raise HTTPException(409, "a review is already running for this project")
    base_ref = scan_base_ref(project, req)
    try:
        paths = normalize_paths(req.paths)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    reviewer = AIReviewer(load_config())
    if not reviewer.available:
        raise HTTPException(400, reviewer.reason)
    scan_id = storage.start_scan(pid)
    RUNNING[pid] = scan_id
    emit(scan_id, {"stage": "queued", "message": "Review queued"})
    background.add_task(run_scan, scan_id, project, base_ref, paths)
    return {"scan_id": scan_id}


async def _orchestrator(project: Dict[str, Any], req: ScanIn) -> CodeReviewOrchestrator:
    try:
        target = await asyncio.to_thread(project_target, project)
        paths = normalize_paths(req.paths)
    except (ValueError, RuntimeError) as exc:
        raise HTTPException(400, str(exc)) from None
    return CodeReviewOrchestrator(target, base_ref=scan_base_ref(project, req),
                                  config_overrides=project_overrides(project, target), include_paths=paths)


@app.get("/api/projects/{pid}/files")
async def project_files(pid: str, base_ref: str = "", whole_project: bool = False):
    """The files a review would look at, for choosing what to review."""
    project = get_project_or_404(pid)
    try:
        req = ScanIn(base_ref=base_ref or None, whole_project=whole_project)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    orch = await _orchestrator(project, req)
    try:
        files = await asyncio.to_thread(orch.candidates)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None
    return {"base_ref": scan_base_ref(project, req), "files": files}


@app.post("/api/projects/{pid}/estimate")
async def estimate(pid: str, req: ScanIn):
    """Files, lines and AI requests a review would need, without running it."""
    orch = await _orchestrator(get_project_or_404(pid), req)
    try:
        return await asyncio.to_thread(orch.estimate)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from None


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


EXPORTS = {"csv": ("text/csv; charset=utf-8", "csv"), "md": ("text/markdown; charset=utf-8", "md"),
           "json": ("application/json", "json"), "patch": ("text/x-diff; charset=utf-8", "patch")}


@app.get("/api/scans/{sid}/export/{fmt}")
async def export_scan(sid: str, fmt: str, ignored: bool = False):
    if fmt not in EXPORTS:
        raise HTTPException(404, "unknown export format (use csv, md, json or patch)")
    scan = storage.get_scan(sid)
    if not scan or "files" not in (scan.get("result") or {}):
        raise HTTPException(404, "no finished review to export")
    project = storage.get_project(scan["project_id"]) or {"name": "project"}
    result = scan["result"]
    headers = {}
    if fmt == "csv":
        body = to_csv(result, ignored)
    elif fmt == "md":
        body = to_markdown(project["name"], result, ignored)
    elif fmt == "json":
        body = to_json(project["name"], result)
    else:
        body, counts = await asyncio.to_thread(to_patch, result, Path(result.get("target") or ""))
        headers = {"X-Fixes-Applied": str(counts["applied"]), "X-Fixes-Skipped": str(counts["skipped"])}
    media, ext = EXPORTS[fmt]
    safe = "".join(c if c.isalnum() or c in "-_" else "_" for c in project["name"])[:60] or "review"
    name = f"{safe}_ai_review.{ext}" if fmt != "patch" else f"{safe}_fixes.patch"
    headers["Content-Disposition"] = f'attachment; filename="{name}"'
    return Response(body, media_type=media, headers=headers)


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


def _ai_info() -> Dict[str, Any]:
    cfg = load_config()
    reviewer = AIReviewer(cfg)
    limit = int((cfg.get("ai") or {}).get("daily_request_limit") or 0)
    used = storage.usage_last_24h(reviewer.provider or "", reviewer.model) if reviewer.available else 0
    return {"available": reviewer.available, "provider": reviewer.provider, "model": reviewer.model,
            "reason": reviewer.reason, "git": bool(shutil.which("git")),
            "requests_24h": used, "daily_request_limit": limit}


@app.get("/api/ai")
async def ai_status():
    return _ai_info()


@app.post("/api/ai/test")
async def ai_test():
    """Send one tiny request to check the key and model (uses one request of the quota)."""
    reviewer = AIReviewer(load_config(), on_request=lambda provider, model: storage.add_usage(provider, model))
    if not reviewer.available:
        raise HTTPException(400, reviewer.reason)
    started = time.time()
    try:
        reply = await asyncio.to_thread(reviewer.test_connection)
    except Exception as exc:
        return {"ok": False, "label": reviewer.label, "message": f"{type(exc).__name__}: {str(exc)[:400]}"}
    return {"ok": True, "label": reviewer.label, "message": f"answered in {time.time() - started:.1f} s", "reply": reply}


def _settings_view() -> Dict[str, Any]:
    cfg, defaults = load_config(), load_config(ui_settings=False)
    ai, default_ai = cfg.get("ai") or {}, defaults.get("ai") or {}
    saved = read_ui_settings()
    customized = sorted(set((saved.get("ai") or {}).keys()) | ({"exclude"} if "exclude" in saved else set()))
    values = {k: ai.get(k, SettingsIn.model_fields[k].default) for k in AI_SETTING_KEYS}
    values["focus"] = list(ai.get("focus") or [])
    values["exclude"] = list(cfg.get("exclude") or [])
    keys = {name: any(os.getenv(v) for v in env) for name, env in KEY_ENV.items()}
    keys["ollama"] = True
    return {"values": values, "customized": customized, "keys": keys,
            "default_models": {name: spec[2] for name, spec in PROVIDERS.items()},
            "defaults": {**{k: default_ai.get(k) for k in AI_SETTING_KEYS}, "exclude": defaults.get("exclude") or []},
            "file": str(ui_settings_path())}


@app.get("/api/settings")
async def get_settings():
    return _settings_view()


@app.put("/api/settings")
async def save_settings(req: SettingsIn):
    """Saved to data/settings.yml; only values that differ from reviewer.yml are stored."""
    defaults = load_config(ui_settings=False)
    default_ai = defaults.get("ai") or {}
    data = req.model_dump()
    ai = {k: data[k] for k in AI_SETTING_KEYS if data[k] != default_ai.get(k, SettingsIn.model_fields[k].default)}
    out: Dict[str, Any] = {"ai": ai} if ai else {}
    if data["exclude"] != list(defaults.get("exclude") or []):
        out["exclude"] = data["exclude"]
    write_ui_settings(out)
    return {**_settings_view(), "ai": _ai_info()}


@app.delete("/api/settings")
async def reset_settings():
    ui_settings_path().unlink(missing_ok=True)
    return {**_settings_view(), "ai": _ai_info()}


if __name__ == "__main__":  # python -m app.web_dashboard
    import uvicorn

    uvicorn.run("app.web_dashboard:app", host="127.0.0.1", port=8000, reload=False)
