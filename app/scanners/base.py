"""Shared plumbing for every scanner.

Each scanner returns a ScanResult whose status says whether the tool actually
ran. A missing tool is reported as SKIPPED, never as an empty (clean) result.
"""
from __future__ import annotations

import fnmatch
import os
import re
import shutil
import subprocess
import sys
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, Iterator, List, Optional, Sequence

from app.config import APP_ROOT
from app.core.models import Finding, ScanResult, ScanStatus

LANGUAGE_BY_EXT = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin",
    ".cs": "csharp",
    ".go": "go", ".rb": "ruby", ".php": "php", ".rs": "rust",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".swift": "swift", ".scala": "scala",
}
TEXT_EXTS = set(LANGUAGE_BY_EXT) | {
    ".env", ".yml", ".yaml", ".json", ".toml", ".ini", ".cfg", ".conf", ".properties",
    ".xml", ".sh", ".ps1", ".bat", ".sql", ".tf", ".txt", ".md", ".html", ".vue", ".svelte",
}
MAX_TEXT_FILE_BYTES = 2_000_000


class ToolMissing(Exception):
    """Raised when an external tool is not installed."""


@dataclass
class ScanContext:
    root: Path
    config: Dict[str, Any]
    files: List[str]                                 # relative posix paths, excludes applied
    languages: List[str]
    changed_lines: Optional[Dict[str, set]] = None   # diff mode: file -> changed line numbers
    is_remote: bool = False
    progress: Callable[[Dict[str, Any]], None] = lambda event: None
    extra: Dict[str, Any] = field(default_factory=dict)

    def files_for(self, *languages: str) -> List[str]:
        wanted = set(languages)
        return [f for f in self.files if LANGUAGE_BY_EXT.get(Path(f).suffix.lower()) in wanted]

    def abs(self, rel: str) -> Path:
        return self.root / rel


# --------------------------------------------------------------------------- #
# File discovery and excludes
# --------------------------------------------------------------------------- #

def read_ignore_file(root: Path) -> List[str]:
    path = root / ".reviewerignore"
    if not path.is_file():
        return []
    patterns = []
    for raw in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        line = raw.strip()
        if line and not line.startswith("#"):
            patterns.append(line)
    return patterns


def is_excluded(rel_path: str, patterns: Sequence[str]) -> bool:
    """True if any path segment (or the whole path) matches an exclude glob."""
    rel = rel_path.replace("\\", "/").strip("/")
    parts = rel.split("/")
    for raw in patterns:
        pat = raw.replace("\\", "/").strip("/")
        if not pat:
            continue
        if "/" in pat:
            if fnmatch.fnmatch(rel, pat) or fnmatch.fnmatch(rel, pat + "/*"):
                return True
            continue
        if any(fnmatch.fnmatch(part, pat) for part in parts):
            return True
    return False


def exclude_patterns(root: Path, config: Dict[str, Any]) -> List[str]:
    return list(config.get("exclude") or []) + read_ignore_file(root)


def discover_files(root: Path, patterns: Sequence[str]) -> List[str]:
    files: List[str] = []
    for dirpath, dirnames, filenames in os.walk(root):
        rel_dir = Path(dirpath).relative_to(root).as_posix()
        rel_dir = "" if rel_dir == "." else rel_dir
        dirnames[:] = [d for d in dirnames if not is_excluded(f"{rel_dir}/{d}".strip("/"), patterns)]
        for name in filenames:
            rel = f"{rel_dir}/{name}".strip("/")
            if not is_excluded(rel, patterns):
                files.append(rel)
    return sorted(files)


def detect_languages(files: Iterable[str]) -> List[str]:
    counts: Dict[str, int] = {}
    for f in files:
        lang = LANGUAGE_BY_EXT.get(Path(f).suffix.lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    return [lang for lang, _ in sorted(counts.items(), key=lambda kv: -kv[1])]


def to_rel(path: str, root: Path) -> str:
    """Normalise a tool-reported path to a project-relative posix path."""
    if not path:
        return ""
    p = Path(path)
    try:
        if p.is_absolute():
            return p.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return p.as_posix()
    rel = p.as_posix()
    return rel[2:] if rel.startswith("./") else rel


# --------------------------------------------------------------------------- #
# Running tools
# --------------------------------------------------------------------------- #

def find_tool(name: str, config: Dict[str, Any], python_module: Optional[str] = None) -> List[str]:
    """Return the command prefix for a tool, or raise ToolMissing.

    Looks in: tools.<name> in config, the app folder (e.g. trivy.exe shipped next
    to the app), PATH, and finally `python -m <module>` when one is given.
    """
    configured = ((config.get("tools") or {}).get(name) or "").strip()
    if configured:
        if Path(configured).is_file() or shutil.which(configured):
            return [configured]
        raise ToolMissing(f"{name} not found at configured path {configured}")
    for candidate in (APP_ROOT / f"{name}.exe", APP_ROOT / name, APP_ROOT / "bin" / f"{name}.exe", APP_ROOT / "bin" / name):
        if candidate.is_file():
            return [str(candidate)]
    found = shutil.which(name)
    if found:
        return [found]
    if python_module:
        try:
            import importlib.util

            if importlib.util.find_spec(python_module) is not None:
                return [sys.executable, "-m", python_module]
        except (ImportError, ValueError):
            pass
    raise ToolMissing(f"{name} is not installed")


def run_tool(cmd: List[str], cwd: Path, timeout: int = 600, env: Optional[Dict[str, str]] = None) -> subprocess.CompletedProcess:
    merged_env = dict(os.environ)
    merged_env.setdefault("PYTHONIOENCODING", "utf-8")
    if env:
        merged_env.update(env)
    try:
        return subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True, encoding="utf-8",
            errors="replace", timeout=timeout, check=False, env=merged_env,
        )
    except FileNotFoundError as exc:
        raise ToolMissing(f"{cmd[0]} is not installed") from exc


def chunks(items: Sequence[str], size: int = 150) -> Iterator[Sequence[str]]:
    for i in range(0, len(items), size):
        yield items[i:i + size]


# --------------------------------------------------------------------------- #
# Source helpers
# --------------------------------------------------------------------------- #

_LINE_CACHE: Dict[str, List[str]] = {}


def read_lines(path: Path) -> List[str]:
    key = str(path)
    if key not in _LINE_CACHE:
        try:
            if path.stat().st_size > MAX_TEXT_FILE_BYTES:
                _LINE_CACHE[key] = []
            else:
                _LINE_CACHE[key] = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            _LINE_CACHE[key] = []
    return _LINE_CACHE[key]


def clear_line_cache() -> None:
    _LINE_CACHE.clear()


def source_line(root: Path, rel: str, line: int) -> str:
    lines = read_lines(root / rel)
    if 1 <= line <= len(lines):
        return lines[line - 1]
    return ""


_SECRET_VALUE = re.compile(r"""(['"`])([^'"`\s]{4,})\1""")
_KNOWN_SECRET = re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_|glpat-|xox[abprs]-|[sr]k_live_|AIza|gsk_|sk-|eyJ|-----BEGIN")


def mask_secret(value: str) -> str:
    value = value or ""
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(12, len(value) - 6)}{value[-2:]}"


def _entropy(value: str) -> float:
    import math
    from collections import Counter

    if not value:
        return 0.0
    return -sum(c / len(value) * math.log2(c / len(value)) for c in Counter(value).values())


def mask_line(line: str) -> str:
    """Mask quoted literals that look like secrets (long and random-looking), so
    reports and AI prompts never contain the secret itself."""
    def repl(m: "re.Match[str]") -> str:
        value = m.group(2)
        if len(value) < 8:
            return m.group(0)
        known = _KNOWN_SECRET.match(value) is not None
        # env var names, identifiers and plain words ("API_TOKEN", "changeme") aren't secrets
        looks_like_name = (re.fullmatch(r"[A-Za-z_][A-Za-z_.-]*", value) is not None)
        if known or (not looks_like_name and _entropy(value) >= 2.5):
            return f"{m.group(1)}{mask_secret(value)}{m.group(1)}"
        return m.group(0)
    return _SECRET_VALUE.sub(repl, line or "")


# --------------------------------------------------------------------------- #
# Base class
# --------------------------------------------------------------------------- #

class Scanner:
    name = "scanner"
    category = "lint"
    languages: Sequence[str] = ()   # empty = any project

    def applies(self, ctx: ScanContext) -> Optional[str]:
        """Return a reason string when the scanner doesn't apply, else None."""
        if self.languages and not any(lang in ctx.languages for lang in self.languages):
            return f"no {'/'.join(self.languages)} files"
        return None

    def scan(self, ctx: ScanContext) -> ScanResult:  # pragma: no cover - abstract
        raise NotImplementedError

    def run(self, ctx: ScanContext) -> ScanResult:
        start = time.time()
        started_as = self.name
        disabled = {str(n).lower() for n in (ctx.config.get("disabled_scanners") or [])}
        reason = "turned off in quality-gates.yml (disabled_scanners)" if self.name.lower() in disabled else self.applies(ctx)
        if reason:
            result = ScanResult(tool=self.name, category=self.category, status=ScanStatus.SKIPPED, message=reason,
                                not_applicable=True)
        else:
            ctx.progress({"tool": self.name, "category": self.category, "status": "running"})
            try:
                result = self.scan(ctx)
            except ToolMissing as exc:
                result = ScanResult(tool=self.name, category=self.category, status=ScanStatus.SKIPPED, message=str(exc))
            except subprocess.TimeoutExpired:
                result = ScanResult(tool=self.name, category=self.category, status=ScanStatus.ERROR, message="timed out")
            except Exception as exc:  # a broken tool must never look like a clean pass
                result = ScanResult(tool=self.name, category=self.category, status=ScanStatus.ERROR,
                                    message=f"{type(exc).__name__}: {exc}")
        result.duration_seconds = round(time.time() - start, 2)
        for f in result.findings:
            if not f.tools:
                f.tools = [f.tool]
        if self.name != started_as:
            # e.g. gitleaks missing, built-in patterns used instead: close the first entry too
            ctx.progress({"tool": started_as, "category": self.category, "status": "skipped",
                          "message": f"not installed; used {self.name} instead", "findings": 0})
        ctx.progress({"tool": self.name, "category": self.category, "status": result.status.value,
                      "message": result.message, "findings": len(result.findings)})
        return result

    # helpers -------------------------------------------------------------- #
    def ran(self, findings: List[Finding], message: str = "", **metrics: Any) -> ScanResult:
        return ScanResult(tool=self.name, category=self.category, status=ScanStatus.RAN,
                          findings=findings, message=message, metrics=metrics)

    def error(self, message: str) -> ScanResult:
        return ScanResult(tool=self.name, category=self.category, status=ScanStatus.ERROR, message=message[:2000])
