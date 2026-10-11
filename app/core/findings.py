"""Post-processing of AI findings: duplicates, ignores, fingerprints, code context and the verdict."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Dict, Iterable, List, Tuple

from app.core.files import read_lines, source_line
from app.core.models import Finding, Severity

INLINE_IGNORE = re.compile(r"reviewer:\s*ignore(?P<reason>[^\n]*)", re.IGNORECASE)
USER_PREFIXES = ("marked false positive", "ignored")


def deduplicate(findings: List[Finding]) -> List[Finding]:
    """The same issue can come back from two overlapping requests: keep one."""
    kept: List[Finding] = []
    for f in sorted(findings, key=lambda x: (-x.severity.rank, -x.confidence)):
        same = any(k.file_path == f.file_path and (
            (abs(k.line - f.line) <= 2 and k.title.strip().lower() == f.title.strip().lower())
            or (k.line == f.line and (k.end_line or k.line) == (f.end_line or f.line) and k.category == f.category))
            for k in kept)
        if not same:
            kept.append(f)
    return kept


def attach_context(findings: Iterable[Finding], root: Path, around: int = 4) -> None:
    """Original code for each issue. With a fix, exactly the lines the fix replaces
    (so the dashboard can show a clean diff); otherwise a few lines either side."""
    for f in findings:
        lines = read_lines(root / f.file_path)
        if not lines:
            continue
        end = f.end_line or f.line
        start, stop = (f.line, end) if f.fix else (max(1, f.line - around), min(len(lines), end + around))
        f.context = "\n".join(lines[start - 1:stop])
        f.context_start = start


def apply_inline_ignores(findings: Iterable[Finding], root: Path) -> None:
    """`// reviewer: ignore <reason>` (any comment style) on the line or the line above."""
    for f in findings:
        for n in (f.line, f.line - 1):
            m = INLINE_IGNORE.search(source_line(root, f.file_path, n))
            if m:
                reason = (m.group("reason") or "").strip(" -:#*/") or "ignored inline"
                f.suppressed = f"inline: {reason}"
                break


def fingerprint(f: Finding, root: Path) -> str:
    """Stable across line shifts: file, category and the code on the flagged line."""
    code = re.sub(r"\s+", " ", source_line(root, f.file_path, f.line)).strip()
    basis = f"{f.file_path}|{f.category}|{code or f.title.lower()}"
    return hashlib.sha1(basis.encode("utf-8", "ignore")).hexdigest()[:16]


def assign_fingerprints(findings: Iterable[Finding], root: Path) -> None:
    seen: Dict[str, int] = {}
    for f in findings:
        fp = fingerprint(f, root)
        n = seen.get(fp, 0)
        seen[fp] = n + 1
        f.fingerprint = fp if n == 0 else f"{fp}-{n}"


def apply_user_suppressions(findings: Iterable[Finding], suppressions: Dict[str, str]) -> None:
    for f in findings:
        if f.suppressed and f.suppressed.startswith(USER_PREFIXES):
            f.suppressed = None  # re-applied from the current list
        if not f.suppressed and f.fingerprint in suppressions:
            f.suppressed = suppressions[f.fingerprint]


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (not f.counts, -f.severity.rank, f.file_path, f.line))


def decide_verdict(findings: List[Finding]) -> Tuple[str, str, str]:
    """(verdict, label, reason) from the issues that count."""
    active = [f for f in findings if f.counts]
    serious = [f for f in active if f.severity.rank >= Severity.HIGH.rank]
    medium = [f for f in active if f.severity == Severity.MEDIUM]
    if serious:
        n = len(serious)
        return "FAIL", "Changes requested", f"{n} critical or high-severity issue{'s' if n != 1 else ''} to fix before merging"
    if medium:
        n = len(medium)
        return "WARN", "Approve with comments", f"{n} medium-severity issue{'s' if n != 1 else ''} worth a look"
    if active:
        return "PASS", "Looks good", f"only minor suggestions ({len(active)})"
    return "PASS", "Looks good", "no issues found in the changed code"


def counts_by_severity(findings: List[Finding]) -> Dict[str, int]:
    out = {s.value: 0 for s in Severity}
    for f in findings:
        if f.counts:
            out[f.severity.value] += 1
    return out
