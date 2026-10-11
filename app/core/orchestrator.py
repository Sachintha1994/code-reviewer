"""Finds the code to review (changes since a base branch, or the whole project),
has the AI review it, and builds the result."""
from __future__ import annotations

import os
import re
import shutil
import subprocess
import threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Tuple

from app.config import DATA_DIR, load_config
from app.core import findings as fx
from app.core.ai_review import AIReviewer, QuotaExhausted, Unit
from app.core.diff import DiffError, collect_diff
from app.core.files import clear_line_cache, exclude_patterns, is_excluded, language_of, read_lines
from app.core.models import FileReview, Finding, ReviewResult

ProgressFn = Callable[[Dict[str, Any]], None]
GITHUB_URL = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(\.git)?/?$")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class CodeReviewOrchestrator:
    def __init__(self, target_path: str, base_ref: Optional[str] = None, config_overrides: Optional[dict] = None,
                 suppressions: Optional[Dict[str, str]] = None, progress: Optional[ProgressFn] = None,
                 cache_get=None, cache_set=None, include_paths: Optional[List[str]] = None, on_request=None):
        self.root = Path(target_path).expanduser().resolve()
        self.include_paths = normalize_paths(include_paths)
        self.on_request = on_request
        self.base_ref = base_ref
        self.config_overrides = config_overrides
        self.suppressions = suppressions or {}
        self.progress: ProgressFn = progress or (lambda event: None)
        self.cache_get, self.cache_set = cache_get, cache_set

    def _emit(self, stage: str, message: str, **extra: Any) -> None:
        self.progress({"stage": stage, "message": message, **extra})

    def _prepare(self):
        if not self.root.is_dir():
            raise ValueError(f"folder not found: {self.root}")
        clear_line_cache()
        cfg = load_config(self.root, self.config_overrides)
        ai_cfg = cfg.get("ai") or {}
        base_ref = (self.base_ref if self.base_ref is not None else cfg.get("base_ref") or "").strip()
        excludes = exclude_patterns(self.root, cfg)
        if base_ref:
            self._emit("diff", f"Finding changes since {base_ref}")
            diff = self._diff(base_ref)
            added, removed, changed_files = diff.added, diff.removed_count, diff.changed_files
        else:
            self._emit("diff", "Reviewing the whole project (no base branch set)")
            added = self._whole_project(excludes)
            removed, changed_files = 0, sorted(added)
        if self.include_paths:
            added = {p: v for p, v in added.items() if in_selection(p, self.include_paths)}
            changed_files = [p for p in changed_files if in_selection(p, self.include_paths)]
        return cfg, ai_cfg, base_ref, excludes, added, removed, changed_files

    def candidates(self) -> List[Dict[str, Any]]:
        """Files a review would look at, before any selection: path, lines in scope and whether it's reviewable."""
        keep, self.include_paths = self.include_paths, []
        try:
            cfg, ai_cfg, base_ref, excludes, added, _, _ = self._prepare()
        finally:
            self.include_paths = keep
        files, _ = self._plan(added, excludes, ai_cfg, whole=not base_ref, limit_files=False)
        return [{"path": f.path, "lines": f.lines_added, "reviewable": f.status == "pending", "note": f.message}
                for f in files]

    def estimate(self) -> Dict[str, Any]:
        """How much a review would send to the AI, without calling it."""
        cfg, ai_cfg, base_ref, excludes, added, _, _ = self._prepare()
        files, to_review = self._plan(added, excludes, ai_cfg, whole=not base_ref)
        reviewer = AIReviewer(cfg)
        batches = reviewer.plan_requests(self.root, [(p, set(added[p])) for p in to_review]) if to_review else []
        return {"files": len(to_review), "lines": sum(len(added[p]) for p in to_review), "requests": len(batches),
                "skipped": sum(1 for f in files if f.status == "skipped"), "lines_per_request": reviewer.batch_lines}

    def run_full_review(self) -> ReviewResult:
        started = _now()
        if not self.root.is_dir():
            raise ValueError(f"folder not found: {self.root}")
        cfg = load_config(self.root, self.config_overrides)
        reviewer = AIReviewer(cfg, self.cache_get, self.cache_set, on_request=self.on_request)
        if not reviewer.available:
            raise ValueError(reviewer.reason)
        cfg, ai_cfg, base_ref, excludes, added, removed, changed_files = self._prepare()
        if self.include_paths and not added:
            raise ValueError("none of the selected files have anything to review")
        files, to_review = self._plan(added, excludes, ai_cfg, whole=not base_ref)
        self._emit("review", f"Reviewing {len(to_review)} files with {reviewer.label}", total=len(to_review))
        for f in files:
            if f.status == "skipped":
                self.progress({"stage": "review", "tool": f.path, "status": "skipped", "message": f.message})

        findings: List[Finding] = []
        by_path = {f.path: f for f in files}
        batches = reviewer.plan_requests(self.root, [(p, set(added[p])) for p in to_review])
        if len(batches) > 1:
            self._emit("review", f"{len(to_review)} files packed into {len(batches)} AI requests", total=len(to_review))
        parts_left = {p: 0 for p in to_review}
        for batch in batches:
            for rel in {u.rel for u in batch}:
                parts_left[rel] += 1
        stop = threading.Event()
        quota_message = ""
        lock = threading.Lock()

        def work(batch: List[Unit]) -> Tuple[List[Unit], Dict[str, List[Finding]], bool, Optional[str]]:
            if stop.is_set():
                return batch, {}, False, "quota"
            for rel in {u.rel for u in batch}:
                self.progress({"stage": "review", "tool": rel, "status": "running"})
            try:
                result, cached = reviewer.review_batch(batch, base_ref)
                return batch, result, cached, None
            except QuotaExhausted as exc:
                nonlocal quota_message
                with lock:
                    quota_message = quota_message or str(exc)
                stop.set()
                return batch, {}, False, "quota"
            except Exception as exc:
                return batch, {}, False, f"{type(exc).__name__}: {exc}"

        with ThreadPoolExecutor(max_workers=max(1, int(ai_cfg.get("max_workers", 4)))) as pool:
            for batch, result, cached, error in pool.map(work, batches):
                for rel in dict.fromkeys(u.rel for u in batch):
                    review = by_path[rel]
                    parts_left[rel] -= 1
                    if error == "quota":
                        if review.status != "error":
                            review.status = "skipped"
                            review.message = ("AI quota reached; run the review again later to continue "
                                              "(finished files are cached)")
                    elif error:
                        review.status, review.message = "error", error[:500]
                    elif review.status == "pending":
                        review.status = "reviewed"
                        review.cached = cached
                    elif review.status == "reviewed":
                        review.cached = review.cached and cached
                    if not error:
                        issues = result.get(rel, [])
                        review.issues += len(issues)
                        review.chunks += sum(1 for u in batch if u.rel == rel)
                        findings.extend(issues)
                    if parts_left[rel] == 0:
                        self.progress({"stage": "review", "tool": rel, "status": review.status,
                                       "message": review.message, "findings": review.issues})

        # a file with some parts reviewed and some cut off by the quota is partial: keep its issues, flag it
        reviewed = [f for f in files if f.status == "reviewed"]
        errors = [f for f in files if f.status == "error"]
        quota_skipped = [f for f in files if f.status == "skipped" and f.message.startswith("AI quota")]
        if to_review and not reviewed:
            if quota_message:
                raise RuntimeError(quota_message)
            raise RuntimeError(f"the AI review failed for every file. First error: {errors[0].message}")

        self._emit("process", "Merging results")
        findings = fx.deduplicate(findings)
        fx.attach_context(findings, self.root)
        fx.assign_fingerprints(findings, self.root)
        fx.apply_inline_ignores(findings, self.root)
        fx.apply_user_suppressions(findings, self.suppressions)
        findings = fx.sort_findings(findings)

        summary = ""
        if ai_cfg.get("summary", True) and to_review and not quota_message:
            self._emit("summary", "Writing the summary")
            try:
                summary = reviewer.summarize(base_ref, {p: added[p] for p in to_review},
                                             [f for f in findings if f.counts])
            except Exception as exc:
                summary = f"(summary unavailable: {exc})"

        verdict, label, reason = fx.decide_verdict(findings)
        if errors:
            reason += f"; {len(errors)} file{'s' if len(errors) != 1 else ''} couldn't be reviewed"
        if quota_skipped:
            reason += (f"; partial review: the AI quota ran out with {len(quota_skipped)} "
                       f"file{'s' if len(quota_skipped) != 1 else ''} left. Run it again later to continue")
        stats = {
            "scope": "changes" if base_ref else "project",
            "files_changed": len(changed_files), "files_reviewed": len(reviewed),
            "files_skipped": sum(1 for f in files if f.status == "skipped"), "files_failed": len(errors),
            "lines_added": sum(len(added[p]) for p in to_review) if not base_ref else sum(len(v) for v in added.values()),
            "lines_removed": removed,
            "issues": sum(1 for f in findings if f.counts), "ignored": sum(1 for f in findings if f.suppressed),
            "by_severity": fx.counts_by_severity(findings),
            "requests": len(batches), "files_quota_skipped": len(quota_skipped),
            "cached_files": sum(1 for f in reviewed if f.cached),
            "selection": self.include_paths[:200],
        }
        self._emit("done", f"{label}: {reason}", verdict=verdict)
        return ReviewResult(
            target=str(self.root), base_ref=base_ref, verdict=verdict, verdict_label=label, verdict_reason=reason,
            summary=summary, model=reviewer.label, findings=findings, files=files, stats=stats,
            started_at=started, finished_at=_now(),
        )

    # ------------------------------------------------------------------------ #
    def _diff(self, base_ref: str):
        try:
            return collect_diff(self.root, base_ref)
        except DiffError as first:
            if not base_ref.startswith("origin/"):
                try:
                    return collect_diff(self.root, f"origin/{base_ref}")
                except DiffError:
                    pass
            raise ValueError(f"can't compare with {base_ref!r}: {first}") from first

    def _whole_project(self, excludes: List[str]) -> Dict[str, Dict[int, str]]:
        """Every reviewable file, with all its lines in scope."""
        added: Dict[str, Dict[int, str]] = {}
        for dirpath, dirnames, filenames in os.walk(self.root):
            rel_dir = Path(dirpath).relative_to(self.root).as_posix()
            rel_dir = "" if rel_dir == "." else rel_dir
            dirnames[:] = sorted(d for d in dirnames if not is_excluded(f"{rel_dir}/{d}".strip("/"), excludes))
            for name in sorted(filenames):
                rel = f"{rel_dir}/{name}".strip("/")
                if is_excluded(rel, excludes) or not language_of(rel):
                    continue
                lines = read_lines(self.root / rel)
                if any(text.strip() for text in lines):
                    added[rel] = {i: text for i, text in enumerate(lines, 1)}
        return added

    def _plan(self, added: Dict[str, Dict[int, str]], excludes: List[str], ai_cfg: Dict[str, Any],
              whole: bool = False, limit_files: bool = True) -> Tuple[List[FileReview], List[str]]:
        max_files = int(ai_cfg.get("max_files", 1000))
        too_big = int(ai_cfg.get("skip_files_with_more_changed_lines_than", 3000))
        files: List[FileReview] = []
        to_review: List[str] = []
        for path in sorted(added):
            lines = added[path]
            review = FileReview(path=path, status="pending", lines_added=len(lines))
            if not lines:
                review.status, review.message = "skipped", "only deletions"
            elif is_excluded(path, excludes):
                review.status, review.message = "skipped", "excluded (reviewer.yml or .reviewerignore)"
            elif not language_of(path):
                review.status, review.message = "skipped", "not a source or config file"
            elif len(lines) > too_big:
                review.status, review.message = "skipped", f"{len(lines)} {'lines' if whole else 'changed lines'}; too large to review"
            elif limit_files and len(to_review) >= max_files:
                review.status, review.message = "skipped", f"limit of {max_files} files per scan (ai.max_files)"
            else:
                to_review.append(path)
            files.append(review)
        return files, to_review


def normalize_paths(paths: Optional[List[str]]) -> List[str]:
    """Selected files or folders, as clean relative paths. Rejects anything that leaves the project."""
    out: List[str] = []
    for raw in paths or []:
        p = str(raw).replace("\\", "/").strip().strip("/")
        if not p or p == ".":
            continue
        if p.startswith("~") or ":" in p.split("/")[0] or any(part == ".." for part in p.split("/")):
            raise ValueError(f"invalid path in selection: {raw}")
        out.append(p)
    return sorted(set(out))


def in_selection(path: str, selection: List[str]) -> bool:
    return any(path == s or path.startswith(s + "/") for s in selection)


def validate_github_url(url: str) -> str:
    url = (url or "").strip()
    if not GITHUB_URL.match(url):
        raise ValueError("enter a GitHub repository URL like https://github.com/owner/repo")
    return url


def clone_github_repo(repo_url: str, project_id: str) -> str:
    """Clone with full history (but no file contents up front) so the base branch can be compared."""
    url = validate_github_url(repo_url)
    if not re.fullmatch(r"[A-Za-z0-9-]{1,64}", project_id or ""):
        raise ValueError("invalid project id")
    base = (DATA_DIR / "cloned_projects").resolve()
    base.mkdir(parents=True, exist_ok=True)
    dest = (base / project_id).resolve()
    if base not in dest.parents:
        raise ValueError("refusing to clone outside the clone folder")
    if dest.exists():
        shutil.rmtree(dest)
    proc = subprocess.run(["git", "clone", "--filter=blob:none", "--no-single-branch", "--", url, str(dest)],
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {proc.stderr.strip()[:500]}")
    return str(dest)

