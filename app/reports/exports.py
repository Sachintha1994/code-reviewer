"""Exports of a review: CSV (opens in Excel), Markdown (for a pull request), JSON and a
patch file with every suggested fix."""
from __future__ import annotations

import csv
import difflib
import io
import json
from pathlib import Path
from typing import Any, Dict, List, Tuple

from app.core.files import long_path

SEVERITY_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}


def _issues(result: Dict[str, Any], include_ignored: bool) -> List[Dict[str, Any]]:
    items = [f for f in result.get("findings") or [] if include_ignored or not f.get("suppressed")]
    return sorted(items, key=lambda f: (-SEVERITY_ORDER.get(f.get("severity", ""), 0), f.get("file_path", ""), f.get("line", 0)))


def _lines(f: Dict[str, Any]) -> str:
    end = f.get("end_line") or f.get("line")
    return f"{f.get('line')}" if end == f.get("line") else f"{f.get('line')}-{end}"


def to_csv(result: Dict[str, Any], include_ignored: bool = False) -> str:
    buf = io.StringIO()
    buf.write("﻿")  # so Excel reads UTF-8
    writer = csv.writer(buf)
    writer.writerow(["Severity", "Category", "File", "Lines", "Title", "Explanation", "Suggested fix",
                     "Confidence", "New", "Ignored"])
    for f in _issues(result, include_ignored):
        new = "" if f.get("is_new") is None else ("yes" if f.get("is_new") else "no")
        writer.writerow([f.get("severity"), f.get("category"), f.get("file_path"), _lines(f), f.get("title"),
                         f.get("explanation") or "", f.get("fix") or "", f"{round(100 * (f.get('confidence') or 0))}%",
                         new, f.get("suppressed") or ""])
    return buf.getvalue()


def _fence(code: str) -> str:
    ticks = "```"
    while ticks in code:
        ticks += "`"
    return ticks


def to_markdown(project: str, result: Dict[str, Any], include_ignored: bool = False) -> str:
    stats = result.get("stats") or {}
    scope = f"changes since `{result['base_ref']}`" if result.get("base_ref") else "whole project"
    out = [f"# AI code review: {project}", "",
           f"**{result.get('verdict_label', '')}**: {result.get('verdict_reason', '')}", "",
           f"- Scope: {scope}",
           f"- Files reviewed: {stats.get('files_reviewed', 0)}",
           f"- Issues: {stats.get('issues', 0)}" + (f" ({stats.get('ignored')} ignored)" if stats.get("ignored") else ""),
           f"- Model: {result.get('model', '')}", ""]
    by_sev = stats.get("by_severity") or {}
    if by_sev:
        out += ["| Critical | High | Medium | Low |", "|---|---|---|---|",
                f"| {by_sev.get('CRITICAL', 0)} | {by_sev.get('HIGH', 0)} | {by_sev.get('MEDIUM', 0)} | {by_sev.get('LOW', 0)} |", ""]
    comparison = result.get("comparison")
    if comparison:
        new = sum(1 for f in result.get("findings") or [] if f.get("is_new") and not f.get("suppressed"))
        out += [f"Since the previous review: {new} new, {len(comparison.get('fixed') or [])} fixed.", ""]
    if result.get("summary"):
        out += ["## Summary", "", result["summary"], ""]
    issues = _issues(result, include_ignored)
    out += [f"## Issues ({len(issues)})", ""]
    if not issues:
        out.append("No issues found.")
    for f in issues:
        tags = [f.get("severity", ""), f.get("category", "")]
        if f.get("is_new"):
            tags.append("new")
        if f.get("suppressed"):
            tags.append(f"ignored: {f['suppressed']}")
        out += [f"### {f.get('title', '')}", "",
                f"`{f.get('file_path')}:{_lines(f)}` · {' · '.join(t for t in tags if t)}", ""]
        if f.get("explanation"):
            out += [f["explanation"], ""]
        if f.get("fix"):
            fence = _fence(f["fix"])
            out += ["Suggested fix:", "", f"{fence}{f.get('language') or ''}", f["fix"], fence, ""]
    return "\n".join(out).rstrip() + "\n"


def to_json(project: str, result: Dict[str, Any]) -> str:
    return json.dumps({"project": project, **result}, indent=2, ensure_ascii=False)


def _read(path: Path) -> Tuple[List[str], str]:
    with open(long_path(path), encoding="utf-8", errors="replace", newline="") as fh:
        text = fh.read()
    newline = "\r\n" if "\r\n" in text else "\n"
    return text.splitlines(), newline


def to_patch(result: Dict[str, Any], root: Path) -> Tuple[str, Dict[str, int]]:
    """A unified diff applying every suggested fix (`git apply review.patch`).

    A fix is left out when the code it replaces has changed since the review, or when it
    overlaps another fix in the same place. Returns (patch text, counts)."""
    by_file: Dict[str, List[Dict[str, Any]]] = {}
    for f in result.get("findings") or []:
        if f.get("fix") and not f.get("suppressed") and f.get("context") is not None:
            by_file.setdefault(f["file_path"], []).append(f)
    applied = skipped = 0
    chunks: List[str] = []
    for rel in sorted(by_file):
        try:
            original, newline = _read(root / rel)
        except OSError:
            skipped += len(by_file[rel])
            continue
        lines = list(original)
        last_start = len(lines) + 1
        # bottom-up so earlier line numbers stay valid
        for f in sorted(by_file[rel], key=lambda x: x["line"], reverse=True):
            start, end = f["line"], f.get("end_line") or f["line"]
            expected = f["context"].split("\n")
            if end >= last_start or lines[start - 1:end] != expected:
                skipped += 1
                continue
            lines[start - 1:end] = f["fix"].rstrip("\n").split("\n")
            last_start = start
            applied += 1
        if lines != original:
            # code lines keep the file's own line endings so the patch applies to CRLF files too
            diff = difflib.unified_diff([s + newline for s in original], [s + newline for s in lines],
                                        fromfile=f"a/{rel}", tofile=f"b/{rel}", lineterm="\n")
            chunks.append("".join(diff))
    header = (f"# Suggested fixes from the AI review ({applied} applied, {skipped} left out because the code changed\n"
              f"# or they overlap). Check them, then run:  git apply --3way review.patch\n")
    return header + "".join(chunks), {"applied": applied, "skipped": skipped}
