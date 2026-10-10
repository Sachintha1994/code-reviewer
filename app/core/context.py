"""Extracts the code around a finding: the enclosing Python function when it is
short enough, otherwise a window of lines either side."""
from __future__ import annotations

import ast
from pathlib import Path
from typing import Dict, Optional, Tuple

from app.core.models import Category, Finding
from app.scanners.base import mask_line, read_lines

MAX_FUNCTION_LINES = 120
_AST_CACHE: Dict[str, Optional[ast.AST]] = {}


def _python_tree(path: Path) -> Optional[ast.AST]:
    key = str(path)
    if key not in _AST_CACHE:
        try:
            _AST_CACHE[key] = ast.parse("\n".join(read_lines(path)))
        except (SyntaxError, ValueError):
            _AST_CACHE[key] = None
    return _AST_CACHE[key]


def enclosing_function(path: Path, line: int) -> Optional[Tuple[int, int]]:
    tree = _python_tree(path)
    if tree is None:
        return None
    best: Optional[Tuple[int, int]] = None
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            start = min([node.lineno] + [d.lineno for d in node.decorator_list])
            end = getattr(node, "end_lineno", None) or node.lineno
            if start <= line <= end and (best is None or end - start < best[1] - best[0]):
                best = (start, end)
    return best


def extract_context(root: Path, finding: Finding, window: int = 20) -> Tuple[str, int]:
    """Return (code, first_line_number). Lines of secrets findings are masked."""
    path = root / finding.file_path
    lines = read_lines(path)
    if not lines or finding.line <= 0:
        return "", 0
    line = min(finding.line, len(lines))
    span = None
    if path.suffix == ".py":
        span = enclosing_function(path, line)
        if span and span[1] - span[0] + 1 > MAX_FUNCTION_LINES:
            span = None
    if span is None:
        span = (max(1, line - window), min(len(lines), line + window))
    start, end = span
    chunk = lines[start - 1:end]
    if finding.category == Category.SECRETS:
        chunk = [mask_line(text) for text in chunk]
    return "\n".join(chunk), start


def numbered(code: str, start: int, flagged: int) -> str:
    out = []
    for i, text in enumerate(code.splitlines(), start):
        marker = ">>" if i == flagged else "  "
        out.append(f"{marker}{i:5d} | {text}")
    return "\n".join(out)


def clear_cache() -> None:
    _AST_CACHE.clear()
