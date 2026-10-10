"""Post-processing of raw findings: excludes, snippets, inline suppressions,
fingerprints, de-duplication, baseline and diff filtering."""
from __future__ import annotations

import hashlib
import re
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Set

from app.core.models import Category, Finding
from app.scanners.base import LANGUAGE_BY_EXT, is_excluded, mask_line, source_line

INLINE_IGNORE = re.compile(r"reviewer:\s*ignore(?:\[(?P<rules>[^\]]*)\])?(?P<reason>[^\n]*)", re.IGNORECASE)
CROSS_TOOL_FAMILIES = {Category.SECRETS, Category.SAST, Category.DEPENDENCIES}
# The same problem reported under different rule names by a linter and a type checker.
EQUIVALENT_RULES = [
    {"F821", "name-defined", "no-undef"},
    {"F811", "no-redef"},
    {"F822", "attr-defined"},
    {"syntax-error", "E999", "invalid-syntax"},
]


def prepare(findings: Iterable[Finding], root: Path, excludes: Sequence[str]) -> List[Finding]:
    """Drop excluded paths, fill missing snippets and languages, mask secrets."""
    out = []
    for f in findings:
        f.file_path = (f.file_path or "").replace("\\", "/")
        if f.file_path and f.category != Category.EXTERNAL and is_excluded(f.file_path, excludes):
            continue
        if not f.code_snippet and f.line > 0:
            f.code_snippet = source_line(root, f.file_path, f.line).strip() or None
        if f.category == Category.SECRETS and f.code_snippet:
            f.code_snippet = mask_line(f.code_snippet)
        f.language = f.language or LANGUAGE_BY_EXT.get(Path(f.file_path).suffix.lower())
        out.append(f)
    return out


def _rule_matches(rule_list: str, finding: Finding) -> bool:
    wanted = [r.strip().lower() for r in rule_list.split(",") if r.strip()]
    rid = finding.rule_id.lower()
    return any(rid == w or rid.startswith(w) or rid.endswith(w) or w == finding.category.value for w in wanted)


def apply_inline_suppressions(findings: Iterable[Finding], root: Path) -> None:
    """`# reviewer: ignore` or `# reviewer: ignore[rule-id, category] reason` on the
    flagged line or the line above it."""
    for f in findings:
        if f.line <= 0 or f.suppressed:
            continue
        for line_no in (f.line, f.line - 1):
            m = INLINE_IGNORE.search(source_line(root, f.file_path, line_no))
            if not m:
                continue
            rules = m.group("rules")
            if rules is None or _rule_matches(rules, f):
                reason = (m.group("reason") or "").strip(" -:#*/") or "ignored inline"
                f.suppressed = f"inline: {reason}"
                break


def _normalise(text: str) -> str:
    return re.sub(r"\s+", " ", text or "").strip()


def fingerprint(f: Finding, root: Path) -> str:
    """Stable id that survives line shifts: based on rule, file and the code on the line."""
    if f.category == Category.DEPENDENCIES:
        basis = f"{f.category.value}|{f.rule_id}|{f.extra.get('package', '')}|{f.file_path}"
    else:
        code = _normalise(source_line(root, f.file_path, f.line)) if f.line > 0 else ""
        rule = f.rule_id.split(":")[0]
        basis = f"{f.category.value}|{f.tool}|{rule}|{f.file_path}|{code or _normalise(f.message)}"
    return hashlib.sha1(basis.encode("utf-8", "ignore")).hexdigest()[:16]


def assign_fingerprints(findings: Iterable[Finding], root: Path) -> None:
    seen: Dict[str, int] = {}
    for f in findings:
        fp = fingerprint(f, root)
        # identical code repeated in a file: keep fingerprints unique
        count = seen.get(fp, 0)
        seen[fp] = count + 1
        f.fingerprint = fp if count == 0 else f"{fp}-{count}"


def _same_issue(a: Finding, b: Finding) -> bool:
    if a.file_path != b.file_path:
        return False
    if a.tool == b.tool:
        return a.rule_id == b.rule_id and a.line == b.line
    if a.line == b.line and any({a.rule_id, b.rule_id} <= group for group in EQUIVALENT_RULES):
        return True
    if a.category != b.category or a.category not in CROSS_TOOL_FAMILIES:
        return False
    if a.category == Category.DEPENDENCIES:
        return a.rule_id == b.rule_id
    return a.line > 0 and b.line > 0 and abs(a.line - b.line) <= 2


def deduplicate(findings: List[Finding]) -> List[Finding]:
    """Merge reports of the same issue from different tools, keeping the most severe."""
    merged: List[Finding] = []
    for f in sorted(findings, key=lambda x: -x.severity.rank):
        match = next((m for m in merged if _same_issue(m, f)), None)
        if match is None:
            if not f.tools:
                f.tools = [f.tool]
            merged.append(f)
            continue
        for tool in f.tools or [f.tool]:
            if tool not in match.tools:
                match.tools.append(tool)
        if f.tool != match.tool:
            match.extra.setdefault("also_reported", []).append(
                {"tool": f.tool, "rule_id": f.rule_id, "message": f.message})
        match.suppressed = match.suppressed or f.suppressed
    return merged


def filter_to_changes(findings: List[Finding], changed: Dict[str, Set[int]]) -> List[Finding]:
    """Keep findings on changed lines (or, for function-level findings, in changed functions)."""
    kept = []
    for f in findings:
        lines = changed.get(f.file_path)
        if f.category == Category.EXTERNAL or not f.file_path:
            kept.append(f)
        elif lines is None:
            continue
        elif f.category == Category.DEPENDENCIES or f.line <= 0:
            kept.append(f)  # manifest changed: its dependency findings are new
        else:
            end = f.end_line if f.end_line and f.end_line >= f.line else f.line
            if f.category in (Category.COMPLEXITY, Category.SIZE, Category.DUPLICATION):
                if any(f.line <= n <= end for n in lines):
                    kept.append(f)
            elif f.line in lines:
                kept.append(f)
    return kept


def apply_baseline(findings: Iterable[Finding], baseline: Optional[Set[str]]) -> None:
    if not baseline:
        return
    for f in findings:
        if f.fingerprint in baseline:
            f.is_new = False


def apply_user_suppressions(findings: Iterable[Finding], suppressions: Dict[str, str]) -> None:
    for f in findings:
        reason = suppressions.get(f.fingerprint)
        if reason and not f.suppressed:
            f.suppressed = reason


def sort_findings(findings: List[Finding]) -> List[Finding]:
    return sorted(findings, key=lambda f: (not f.counts, -f.effective_severity.rank, f.file_path, f.line))
