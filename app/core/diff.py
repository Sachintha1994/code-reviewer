"""Git diff helpers for reviewing only new or changed code."""
from __future__ import annotations

import re
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

SAFE_REF = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._/@^~-]{0,199}$")
HUNK = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")


class DiffError(Exception):
    pass


@dataclass
class DiffInfo:
    base_ref: str
    added: Dict[str, Dict[int, str]] = field(default_factory=dict)   # file -> {line: text}
    removed_count: int = 0
    deleted_files: List[str] = field(default_factory=list)

    @property
    def changed_files(self) -> List[str]:
        return sorted(set(self.added) | set(self.deleted_files))

    @property
    def added_count(self) -> int:
        return sum(len(lines) for lines in self.added.values())

    @property
    def changed_lines(self) -> Dict[str, set]:
        return {path: set(lines) for path, lines in self.added.items()}


def _git(root: Path, *args: str) -> str:
    try:
        proc = subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True,
                              encoding="utf-8", errors="replace", timeout=120, check=False)
    except FileNotFoundError as exc:
        raise DiffError("git is not installed") from exc
    if proc.returncode != 0:
        raise DiffError(proc.stderr.strip() or f"git {' '.join(args)} failed")
    return proc.stdout


def parse_unified_diff(text: str, base_ref: str = "") -> DiffInfo:
    info = DiffInfo(base_ref=base_ref)
    current = None
    new_line = 0
    minus_path = None
    for raw in text.splitlines():
        if raw.startswith("diff --git"):
            current, minus_path = None, None
            continue
        if raw.startswith("--- "):
            minus_path = raw[4:].strip()
            minus_path = minus_path[2:] if minus_path.startswith("a/") else minus_path
            continue
        if raw.startswith("+++ "):
            path = raw[4:].strip()
            if path == "/dev/null":
                current = None
                if minus_path and minus_path != "/dev/null":
                    info.deleted_files.append(minus_path)
            else:
                current = path[2:] if path.startswith("b/") else path
                info.added.setdefault(current, {})
            continue
        m = HUNK.match(raw)
        if m:
            new_line = int(m.group(3))
            continue
        if raw.startswith("+") and current is not None:
            info.added[current][new_line] = raw[1:]
            new_line += 1
        elif raw.startswith("-"):
            info.removed_count += 1
        elif raw.startswith(" "):
            new_line += 1
    info.added = {k: v for k, v in info.added.items()}
    return info


def collect_diff(root: Path, base_ref: str) -> DiffInfo:
    if not SAFE_REF.match(base_ref or ""):
        raise DiffError(f"invalid base ref: {base_ref!r}")
    _git(root, "rev-parse", "--verify", f"{base_ref}^{{commit}}")
    info = parse_unified_diff(_git(root, "diff", "--unified=0", "--no-color", "--no-ext-diff", base_ref, "--"), base_ref)
    # Untracked files count as entirely new.
    for rel in _git(root, "ls-files", "--others", "--exclude-standard").splitlines():
        rel = rel.strip()
        path = root / rel
        if rel and path.is_file() and path.stat().st_size < 2_000_000:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            info.added[rel] = {i: text for i, text in enumerate(lines, 1)}
    return info
