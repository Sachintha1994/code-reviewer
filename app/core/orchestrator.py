"""Runs every scanner, post-processes the findings and evaluates the gates."""
from __future__ import annotations

import re
import shutil
import subprocess
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional, Set

from app.config import DATA_DIR, load_config
from app.core import findings as fx
from app.core.context import clear_cache as clear_ast_cache
from app.core.context import extract_context
from app.core.diff import DiffError, collect_diff
from app.core.gates import decide_verdict, evaluate_gates, health_score
from app.core.llm_analyzer import AIReviewer
from app.core.models import Category, Finding, ReviewResult, ScanResult, ScanStatus
from app.scanners.base import (
    LANGUAGE_BY_EXT, ScanContext, Scanner, clear_line_cache, detect_languages, discover_files, exclude_patterns,
    is_excluded, read_lines,
)
from app.scanners.codecov_client import CodecovScanner
from app.scanners.github_security import GitHubSecurityScanner
from app.scanners.lint import ESLintScanner, PythonLintScanner
from app.scanners.quality import (
    BuildScanner, ComplexityScanner, DuplicationScanner, HygieneScanner, PytestScanner, TypeCheckScanner,
)
from app.scanners.security import BanditScanner, SecretsScanner, SemgrepScanner, TrivyScanner
from app.scanners.sonarqube_client import SonarQubeScanner

ProgressFn = Callable[[Dict[str, Any]], None]
GITHUB_URL = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+?(\.git)?/?$")
MAX_CONTEXT_FINDINGS = 300


class CodeReviewOrchestrator:
    def __init__(self, target_path: str, sonar_config: Optional[dict] = None, codecov_config: Optional[dict] = None,
                 ghas_config: Optional[dict] = None, base_ref: Optional[str] = None,
                 config_overrides: Optional[dict] = None, use_ai: bool = True, baseline: Optional[Set[str]] = None,
                 suppressions: Optional[Dict[str, str]] = None, is_remote: bool = False,
                 progress: Optional[ProgressFn] = None, cache_get=None, cache_set=None, max_workers: int = 4):
        self.root = Path(target_path).expanduser().resolve()
        self.sonar_config, self.codecov_config, self.ghas_config = sonar_config, codecov_config, ghas_config
        self.base_ref = base_ref
        self.config_overrides = config_overrides
        self.use_ai = use_ai
        self.baseline = baseline or set()
        self.suppressions = suppressions or {}
        self.is_remote = is_remote
        self.progress: ProgressFn = progress or (lambda event: None)
        self.cache_get, self.cache_set = cache_get, cache_set
        self.max_workers = max_workers

    def _emit(self, stage: str, message: str, **extra: Any) -> None:
        self.progress({"stage": stage, "message": message, **extra})

    def scanners(self) -> List[Scanner]:
        return [
            BuildScanner(), SecretsScanner(), PythonLintScanner(), ESLintScanner(), TypeCheckScanner(),
            SemgrepScanner(), BanditScanner(), TrivyScanner(), ComplexityScanner(), DuplicationScanner(),
            PytestScanner(), HygieneScanner(), SonarQubeScanner(self.sonar_config),
            CodecovScanner(self.codecov_config), GitHubSecurityScanner(self.ghas_config),
        ]

    def run_full_review(self) -> ReviewResult:
        started = datetime.now(timezone.utc).isoformat(timespec="seconds")
        if not self.root.is_dir():
            raise ValueError(f"folder not found: {self.root}")
        clear_line_cache()
        clear_ast_cache()
        cfg = load_config(self.root, self.config_overrides)
        excludes = exclude_patterns(self.root, cfg)

        self._emit("discover", "Finding source files")
        files = discover_files(self.root, excludes)
        languages = detect_languages(files)
        ctx = ScanContext(root=self.root, config=cfg, files=files, languages=languages,
                          is_remote=self.is_remote, progress=lambda e: self.progress({"stage": "scan", **e}))

        base_ref = (self.base_ref if self.base_ref is not None else cfg.get("base_ref")) or ""
        if base_ref:
            self._emit("diff", f"Comparing with {base_ref}")
            diff = self._diff(base_ref)
            added = {p: lines for p, lines in diff.added.items() if not is_excluded(p, excludes)}
            ctx.changed_lines = {p: set(lines) for p, lines in added.items()}
            ctx.extra["added_lines"] = added
            ctx.extra["diff_changed_lines"] = sum(len(v) for v in added.values()) + diff.removed_count

        self._emit("scan", f"Running scanners on {len(files)} files ({', '.join(languages) or 'no code'})")
        with ThreadPoolExecutor(max_workers=self.max_workers) as pool:
            scans: List[ScanResult] = list(pool.map(lambda s: s.run(ctx), self.scanners()))

        self._emit("process", "Merging and filtering findings")
        all_findings = fx.prepare([f for s in scans for f in s.findings], self.root, excludes)
        fx.apply_inline_suppressions(all_findings, self.root)
        if ctx.changed_lines is not None:
            all_findings = fx.filter_to_changes(all_findings, ctx.changed_lines)
        fx.assign_fingerprints(all_findings, self.root)
        findings = fx.deduplicate(all_findings)
        fx.apply_baseline(findings, self.baseline)
        fx.apply_user_suppressions(findings, self.suppressions)

        scans.append(self._ai_pass(cfg, findings, ctx))
        findings = fx.sort_findings(findings)
        self._attach_context(findings, cfg)

        self._emit("gates", "Evaluating quality gates")
        gates = evaluate_gates(findings, scans, cfg, diff_mode=ctx.changed_lines is not None)
        verdict, reason = decide_verdict(gates, cfg)
        source_lines = next((s.metrics.get("source_lines") for s in scans if s.metrics.get("source_lines")), None)
        if source_lines is None:
            source_lines = sum(len(read_lines(self.root / f)) for f in files if Path(f).suffix.lower() in LANGUAGE_BY_EXT)
        health = health_score(findings, source_lines, verdict)

        stats = {
            "files": len(files), "source_lines": source_lines, "findings_total": len(findings),
            "findings_counted": sum(1 for f in findings if f.counts),
            "suppressed": sum(1 for f in findings if f.suppressed), "baseline": sum(1 for f in findings if not f.is_new),
            "ai_dismissed": sum(1 for f in findings if f.ai_dismissed),
            "changed_files": len(ctx.changed_lines) if ctx.changed_lines is not None else None,
        }
        self._emit("done", f"{verdict}: {reason}", verdict=verdict)
        return ReviewResult(
            target=str(self.root), verdict=verdict, verdict_reason=reason, health=health, gates=gates,
            findings=findings, scans=scans, languages=languages, base_ref=base_ref or None, stats=stats,
            started_at=started, finished_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
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

    def _ai_pass(self, cfg: Dict[str, Any], findings: List[Finding], ctx: ScanContext) -> ScanResult:
        reviewer = AIReviewer(cfg, self.cache_get, self.cache_set)
        if not self.use_ai or not reviewer.available:
            reason = "AI turned off for this scan" if not self.use_ai else reviewer.reason
            return ScanResult(tool="AI review", category="ai", status=ScanStatus.SKIPPED, message=reason)
        self._emit("ai", f"AI triage with {reviewer.provider}/{reviewer.model}")
        try:
            metrics = reviewer.triage(findings, self.root, ctx.progress)
            errors = list(metrics.pop("errors", []))
            added = ctx.extra.get("added_lines")
            if added and (cfg.get("ai") or {}).get("file_review", True):
                self._emit("ai", "AI review of changed files")
                extra_findings, file_errors = reviewer.review_changes(self.root, added)
                fx.assign_fingerprints(extra_findings, self.root)
                fx.apply_user_suppressions(extra_findings, self.suppressions)
                findings.extend(extra_findings)
                errors += file_errors
                metrics["file_review_issues"] = len(extra_findings)
        except Exception as exc:
            return ScanResult(tool="AI review", category="ai", status=ScanStatus.ERROR, message=f"{type(exc).__name__}: {exc}")
        status = ScanStatus.ERROR if errors and not metrics.get("analysed") else ScanStatus.RAN
        message = f"{reviewer.provider}/{reviewer.model}" + (f"; {len(errors)} errors: {errors[0]}" if errors else "")
        return ScanResult(tool="AI review", category="ai", status=status, message=message, metrics=metrics)

    def _attach_context(self, findings: List[Finding], cfg: Dict[str, Any]) -> None:
        window = int((cfg.get("ai") or {}).get("context_lines", 20))
        for f in findings[:MAX_CONTEXT_FINDINGS]:
            if f.context is None and f.line > 0 and f.category not in (Category.DEPENDENCIES, Category.EXTERNAL):
                code, start = extract_context(self.root, f, window)
                if code:
                    f.context, f.context_start = code, start


def validate_github_url(url: str) -> str:
    url = (url or "").strip()
    if not GITHUB_URL.match(url):
        raise ValueError("enter a GitHub repository URL like https://github.com/owner/repo")
    return url


def clone_github_repo(repo_url: str, project_id: str, full_history: bool = False) -> str:
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
    cmd = ["git", "clone", "--filter=blob:none" if full_history else "--depth=1", "--", url, str(dest)]
    proc = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=900)
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {proc.stderr.strip()[:500]}")
    return str(dest)
