"""Lint scanners: Ruff (Python, falls back to Flake8) and ESLint (JS/TS).

Rule codes are kept, and each code is mapped to a severity so real bugs
(undefined names, syntax errors) are told apart from style nits.
"""
from __future__ import annotations

import json
import re
from pathlib import Path
from typing import List, Optional

from app.core.models import Category, Finding, Severity
from app.scanners.base import ScanContext, Scanner, ToolMissing, chunks, find_tool, run_tool, to_rel

# Codes that are real bugs: the code will fail or misbehave at runtime.
PY_ERROR_PREFIXES = ("E9", "F63", "F7", "F82", "PLE")
PY_ERROR_CODES = {"F821", "F822", "F823", "F811", "F402", "F404", "F406", "F407", "F501", "F502", "F503",
                  "F504", "F505", "F506", "F507", "F508", "F509", "F521", "F522", "F523", "F524", "F525"}
PY_MEDIUM_PREFIXES = ("B", "E722", "PLW")
PY_INFO_PREFIXES = ("E1", "E2", "E3", "E4", "E5", "W", "D", "I", "Q", "COM")


def python_severity(code: Optional[str]) -> Severity:
    if not code or code in ("E999", "syntax-error", "invalid-syntax"):
        return Severity.HIGH
    if code in PY_ERROR_CODES or code.startswith(PY_ERROR_PREFIXES):
        return Severity.HIGH
    if code.startswith(PY_MEDIUM_PREFIXES):
        return Severity.MEDIUM
    if code.startswith(("E7", "E40")):  # E401/E402 imports, E7xx statements
        return Severity.LOW
    if code.startswith(PY_INFO_PREFIXES):
        return Severity.INFO
    return Severity.LOW


def has_ruff_config(root: Path) -> bool:
    for name in ("ruff.toml", ".ruff.toml"):
        if (root / name).is_file():
            return True
    pyproject = root / "pyproject.toml"
    if pyproject.is_file():
        try:
            return "[tool.ruff" in pyproject.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            return False
    return False


def parse_ruff(output: str, root: Path) -> List[Finding]:
    findings = []
    data = json.loads(output or "[]")
    for item in data:
        code = item.get("code")
        loc = item.get("location") or {}
        end = item.get("end_location") or {}
        findings.append(Finding(
            tool="Ruff",
            rule_id=code or "syntax-error",
            file_path=to_rel(item.get("filename", ""), root),
            line=int(loc.get("row") or 0),
            column=loc.get("column"),
            end_line=end.get("row"),
            message=item.get("message", ""),
            severity=python_severity(code),
            category=Category.LINT,
            url=item.get("url"),
            extra={"fixable": bool(item.get("fix"))},
        ))
    return findings


FLAKE8_FORMAT = "%(path)s\t%(row)d\t%(col)d\t%(code)s\t%(text)s"


def parse_flake8(output: str, root: Path) -> List[Finding]:
    findings = []
    for line in (output or "").splitlines():
        parts = line.split("\t", 4)
        if len(parts) != 5:
            continue
        path, row, col, code, text = parts
        findings.append(Finding(
            tool="Flake8", rule_id=code, file_path=to_rel(path, root),
            line=int(row) if row.isdigit() else 0, column=int(col) if col.isdigit() else None,
            message=text.strip(), severity=python_severity(code), category=Category.LINT,
        ))
    return findings


class PythonLintScanner(Scanner):
    name = "Ruff"
    category = "lint"
    languages = ("python",)

    def scan(self, ctx: ScanContext):
        files = ctx.files_for("python")
        try:
            ruff = find_tool("ruff", ctx.config, python_module="ruff")
        except ToolMissing:
            return self._flake8(ctx, files)
        cmd = ruff + ["check", "--output-format", "json", "--no-cache", "--exit-zero"]
        if not has_ruff_config(ctx.root):
            cmd += ["--select", "E4,E7,E9,F,B,PLE"]
        findings: List[Finding] = []
        for batch in chunks(files):
            proc = run_tool(cmd + list(batch), ctx.root)
            if proc.returncode not in (0, 1) and not proc.stdout.strip():
                return self.error(proc.stderr or f"ruff exited with {proc.returncode}")
            findings.extend(parse_ruff(proc.stdout, ctx.root))
        return self.ran(findings, f"{len(files)} files")

    def _flake8(self, ctx: ScanContext, files: List[str]):
        flake8 = find_tool("flake8", ctx.config, python_module="flake8")
        self.name = "Flake8"
        findings: List[Finding] = []
        for batch in chunks(files):
            proc = run_tool(flake8 + ["--format", FLAKE8_FORMAT] + list(batch), ctx.root)
            findings.extend(parse_flake8(proc.stdout, ctx.root))
        return self.ran(findings, f"{len(files)} files (Ruff not installed, used Flake8)")


# ESLint rules that indicate real bugs rather than style.
ESLINT_BUG_RULES = {
    "no-undef", "no-unreachable", "no-dupe-keys", "no-dupe-args", "no-redeclare", "no-unsafe-finally",
    "no-func-assign", "no-import-assign", "no-const-assign", "no-self-assign", "use-isnan", "valid-typeof",
    "no-dupe-class-members", "no-unsafe-negation", "no-obj-calls", "getter-return", "no-setter-return",
    "constructor-super", "no-this-before-super", "@typescript-eslint/no-floating-promises",
}


def parse_eslint(output: str, root: Path) -> List[Finding]:
    findings = []
    for file_result in json.loads(output or "[]"):
        rel = to_rel(file_result.get("filePath", ""), root)
        for msg in file_result.get("messages", []):
            rule = msg.get("ruleId") or "parse-error"
            if msg.get("fatal") or (rule in ESLINT_BUG_RULES and msg.get("severity") == 2):
                sev = Severity.HIGH
            elif msg.get("severity") == 2:
                sev = Severity.MEDIUM
            else:
                sev = Severity.LOW
            findings.append(Finding(
                tool="ESLint", rule_id=rule, file_path=rel, line=int(msg.get("line") or 0),
                column=msg.get("column"), end_line=msg.get("endLine"), message=msg.get("message", ""),
                severity=sev, category=Category.LINT,
            ))
    return findings


ESLINT_CONFIGS = re.compile(r"^(\.eslintrc(\.\w+)?|eslint\.config\.(js|mjs|cjs|ts))$")


class ESLintScanner(Scanner):
    name = "ESLint"
    category = "lint"
    languages = ("javascript", "typescript")

    def applies(self, ctx: ScanContext):
        reason = super().applies(ctx)
        if reason:
            return reason
        top_level = [p.name for p in ctx.root.iterdir()] if ctx.root.is_dir() else []
        if not any(ESLINT_CONFIGS.match(name) for name in top_level):
            pkg = ctx.root / "package.json"
            if not (pkg.is_file() and "eslint" in pkg.read_text(encoding="utf-8", errors="ignore")):
                return "project has no ESLint configuration"
        if not (ctx.root / "node_modules").is_dir():
            return "node_modules missing (run npm install in the project first)"
        return None

    def scan(self, ctx: ScanContext):
        npx = find_tool("npx", ctx.config)
        files = ctx.files_for("javascript", "typescript")
        findings: List[Finding] = []
        for batch in chunks(files, 100):
            proc = run_tool(npx + ["--no-install", "eslint", "-f", "json"] + list(batch), ctx.root)
            if not proc.stdout.strip().startswith("["):
                return self.error(proc.stderr or proc.stdout or "eslint produced no JSON")
            findings.extend(parse_eslint(proc.stdout, ctx.root))
        return self.ran(findings, f"{len(files)} files")
