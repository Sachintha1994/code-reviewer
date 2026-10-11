"""File helpers: which files are reviewed, reading lines, and masking secrets
before code is sent to the AI."""
from __future__ import annotations

import fnmatch
import math
import re
from collections import Counter
from pathlib import Path
from typing import Any, Dict, List, Optional, Sequence

LANGUAGE_BY_EXT = {
    ".py": "python", ".pyw": "python",
    ".js": "javascript", ".jsx": "javascript", ".mjs": "javascript", ".cjs": "javascript",
    ".ts": "typescript", ".tsx": "typescript",
    ".java": "java", ".kt": "kotlin", ".kts": "kotlin", ".groovy": "groovy", ".gradle": "groovy",
    ".cs": "csharp", ".go": "go", ".rb": "ruby", ".php": "php", ".rs": "rust",
    ".c": "c", ".h": "c", ".cpp": "cpp", ".cc": "cpp", ".hpp": "cpp",
    ".swift": "swift", ".scala": "scala", ".vue": "javascript", ".svelte": "javascript",
    ".sql": "sql", ".sh": "bash", ".ps1": "powershell",
    ".yml": "yaml", ".yaml": "yaml", ".properties": "properties", ".xml": "xml",
    ".html": "xml", ".json": "json", ".toml": "toml", ".tf": "terraform",
}
SPECIAL_FILES = {"dockerfile": "dockerfile", "jenkinsfile": "groovy", "makefile": "makefile"}
MAX_TEXT_FILE_BYTES = 2_000_000


def language_of(path: str) -> Optional[str]:
    name = Path(path).name.lower()
    if name in SPECIAL_FILES:
        return SPECIAL_FILES[name]
    return LANGUAGE_BY_EXT.get(Path(path).suffix.lower())


# --------------------------------------------------------------------------- #
# Excludes
# --------------------------------------------------------------------------- #

def read_ignore_file(root: Path) -> List[str]:
    path = root / ".reviewerignore"
    if not path.is_file():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8", errors="ignore").splitlines()
            if line.strip() and not line.strip().startswith("#")]


def exclude_patterns(root: Path, config: Dict[str, Any]) -> List[str]:
    return list(config.get("exclude") or []) + read_ignore_file(root)


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
        elif any(fnmatch.fnmatch(part, pat) for part in parts):
            return True
    return False


# --------------------------------------------------------------------------- #
# Reading
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
    return lines[line - 1] if 1 <= line <= len(lines) else ""


# --------------------------------------------------------------------------- #
# Secrets
# --------------------------------------------------------------------------- #

_QUOTED = re.compile(r"""(['"`])([^'"`\s]{8,})\1""")
_KNOWN_SECRET = re.compile(r"(AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_|glpat-|xox[abprs]-|[sr]k_live_|AIza|gsk_|sk-|eyJ|-----BEGIN")


def _entropy(value: str) -> float:
    counts = Counter(value)
    return -sum(c / len(value) * math.log2(c / len(value)) for c in counts.values())


def mask_secret(value: str) -> str:
    if len(value) <= 8:
        return "*" * len(value)
    return f"{value[:4]}{'*' * min(12, len(value) - 6)}{value[-2:]}"


def looks_like_secret(value: str) -> bool:
    if _KNOWN_SECRET.match(value):
        return True
    has_letter = any(c.isalpha() for c in value)
    has_digit = any(c.isdigit() for c in value)
    return len(value) >= 16 and has_letter and has_digit and "/" not in value and _entropy(value) >= 3.5


def mask_secrets(line: str) -> str:
    """Mask quoted values that look like real credentials, so they are never sent to the AI."""
    return _QUOTED.sub(lambda m: f"{m.group(1)}{mask_secret(m.group(2))}{m.group(1)}"
                       if looks_like_secret(m.group(2)) else m.group(0), line or "")
