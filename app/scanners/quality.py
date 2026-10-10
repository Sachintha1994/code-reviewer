"""Correctness and maintainability scanners: build, tests, types, complexity,
size, duplication and change hygiene."""
from __future__ import annotations

import csv
import io
import json
import os
import re
import sys
import tempfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List

from app.config import gate_cfg
from app.core.models import Category, Finding, Severity
from app.scanners.base import (
    LANGUAGE_BY_EXT, ScanContext, Scanner, ToolMissing, chunks, exclude_patterns, find_tool, read_lines,
    run_tool, to_rel,
)

# --------------------------------------------------------------------------- #
# Build
# --------------------------------------------------------------------------- #

TSC_LINE = re.compile(r"^(.+?)\((\d+),(\d+)\): error (TS\d+): (.*)$")


class BuildScanner(Scanner):
    name = "Build"
    category = "build"

    def applies(self, ctx: ScanContext):
        if not ({"python", "typescript"} & set(ctx.languages)):
            return "build check supports Python and TypeScript; none found"
        return None

    def scan(self, ctx: ScanContext):
        findings: List[Finding] = []
        notes = []
        for rel in ctx.files_for("python"):
            try:
                source = (ctx.root / rel).read_bytes()
                compile(source, rel, "exec", dont_inherit=True)
            except SyntaxError as exc:
                findings.append(Finding(
                    tool="Python compile", rule_id="syntax-error", file_path=rel, line=exc.lineno or 0,
                    column=exc.offset, message=f"Does not compile: {exc.msg}", severity=Severity.CRITICAL,
                    category=Category.BUILD,
                ))
            except (ValueError, OSError) as exc:
                notes.append(f"{rel}: {exc}")
        if "typescript" in ctx.languages and (ctx.root / "tsconfig.json").is_file():
            tsc_bin = ctx.root / "node_modules" / ".bin" / ("tsc.cmd" if os.name == "nt" else "tsc")
            if tsc_bin.exists():
                proc = run_tool([str(tsc_bin), "--noEmit", "--pretty", "false", "-p", "."], ctx.root, timeout=900)
                for line in proc.stdout.splitlines():
                    m = TSC_LINE.match(line.strip())
                    if m:
                        findings.append(Finding(
                            tool="tsc", rule_id=m.group(4), file_path=to_rel(m.group(1), ctx.root),
                            line=int(m.group(2)), column=int(m.group(3)), message=m.group(5),
                            severity=Severity.HIGH, category=Category.BUILD,
                        ))
            else:
                notes.append("TypeScript compiler not installed in node_modules; skipped tsc")
        return self.ran(findings, "; ".join(notes))


# --------------------------------------------------------------------------- #
# Types (mypy)
# --------------------------------------------------------------------------- #

MYPY_LINE = re.compile(r"^(?P<path>.+?):(?P<line>\d+):(?:(?P<col>\d+):)? (?P<kind>error|warning|note): (?P<msg>.*?)(?:\s+\[(?P<code>[\w-]+)\])?$")


def parse_mypy(output: str, root: Path) -> List[Finding]:
    findings = []
    for line in (output or "").splitlines():
        m = MYPY_LINE.match(line.strip())
        if not m or m.group("kind") != "error":
            continue
        findings.append(Finding(
            tool="mypy", rule_id=m.group("code") or "type-error", file_path=to_rel(m.group("path"), root),
            line=int(m.group("line")), column=int(m.group("col")) if m.group("col") else None,
            message=m.group("msg"), severity=Severity.MEDIUM, category=Category.TYPES,
        ))
    return findings


class TypeCheckScanner(Scanner):
    name = "mypy"
    category = "types"
    languages = ("python",)

    def scan(self, ctx: ScanContext):
        mypy = find_tool("mypy", ctx.config, python_module="mypy")
        files = ctx.files_for("python")
        base = mypy + ["--ignore-missing-imports", "--no-error-summary", "--show-column-numbers",
                       "--show-error-codes", "--no-pretty", "--hide-error-context", "--follow-imports=silent",
                       "--no-incremental"]
        findings: List[Finding] = []
        for batch in chunks(files, 400):
            proc = run_tool(base + list(batch), ctx.root, timeout=900)
            if proc.returncode == 2 and not proc.stdout.strip():
                return self.error(proc.stderr or "mypy crashed")
            findings.extend(parse_mypy(proc.stdout, ctx.root))
        return self.ran(findings, f"{len(files)} files")


# --------------------------------------------------------------------------- #
# Complexity and size (Lizard, falls back to Radon)
# --------------------------------------------------------------------------- #

def parse_lizard_csv(output: str, root: Path) -> List[Dict]:
    functions = []
    for row in csv.reader(io.StringIO(output or "")):
        if len(row) < 11 or not row[1].strip().isdigit():
            continue
        functions.append({
            "file": to_rel(row[6], root), "name": row[7], "ccn": int(row[1]), "nloc": int(row[0]),
            "length": int(row[4]), "start": int(row[9]), "end": int(row[10]),
        })
    return functions


def parse_radon_cc(output: str, root: Path) -> List[Dict]:
    functions = []
    for path, blocks in (json.loads(output or "{}") or {}).items():
        if not isinstance(blocks, list):
            continue  # radon reports parse errors as {"error": "..."}
        for block in blocks:
            if block.get("type") == "class":
                continue
            name = f"{block['classname']}.{block['name']}" if block.get("classname") else block.get("name", "?")
            start, end = int(block.get("lineno", 0)), int(block.get("endline", block.get("lineno", 0)))
            functions.append({"file": to_rel(path, root), "name": name, "ccn": int(block.get("complexity", 0)),
                              "nloc": end - start + 1, "length": end - start + 1, "start": start, "end": end})
    return functions


def complexity_findings(functions: List[Dict], file_lengths: Dict[str, int], config: Dict, tool: str) -> List[Finding]:
    comp = gate_cfg(config, "complexity")
    size = gate_cfg(config, "size")
    warn_over, fail_over = int(comp.get("warn_over", 15)), int(comp.get("fail_over", 25))
    max_fn, max_file = int(size.get("max_function_lines", 60)), int(size.get("max_file_lines", 500))
    findings = []
    for fn in functions:
        if fn["ccn"] > warn_over:
            findings.append(Finding(
                tool=tool, rule_id="complexity", file_path=fn["file"], line=fn["start"], end_line=fn["end"],
                message=f"Function '{fn['name']}' has cyclomatic complexity {fn['ccn']} (limit {warn_over}).",
                severity=Severity.HIGH if fn["ccn"] > fail_over else Severity.MEDIUM,
                category=Category.COMPLEXITY, extra={"ccn": fn["ccn"]},
            ))
        if fn["length"] > max_fn:
            findings.append(Finding(
                tool=tool, rule_id="function-length", file_path=fn["file"], line=fn["start"], end_line=fn["end"],
                message=f"Function '{fn['name']}' is {fn['length']} lines long (limit {max_fn}).",
                severity=Severity.LOW, category=Category.SIZE, extra={"lines": fn["length"]},
            ))
    for rel, count in file_lengths.items():
        if count > max_file:
            findings.append(Finding(
                tool=tool, rule_id="file-length", file_path=rel, line=1,
                message=f"File is {count} lines long (limit {max_file}).", severity=Severity.LOW,
                category=Category.SIZE, extra={"lines": count},
            ))
    return findings


class ComplexityScanner(Scanner):
    name = "Lizard"
    category = "complexity"

    def applies(self, ctx: ScanContext):
        return None if ctx.languages else "no source files"

    def scan(self, ctx: ScanContext):
        source_files = [f for f in ctx.files if Path(f).suffix.lower() in LANGUAGE_BY_EXT]
        file_lengths = {f: len(read_lines(ctx.root / f)) for f in source_files}
        try:
            lizard = find_tool("lizard", ctx.config, python_module="lizard")
            functions: List[Dict] = []
            for batch in chunks(source_files):
                proc = run_tool(lizard + ["--csv"] + list(batch), ctx.root, timeout=900)
                functions.extend(parse_lizard_csv(proc.stdout, ctx.root))
            tool = "Lizard"
        except ToolMissing:
            py_files = ctx.files_for("python")
            if not py_files:
                raise ToolMissing("lizard is not installed (radon only covers Python)") from None
            try:
                radon = find_tool("radon", ctx.config, python_module="radon")
            except ToolMissing:
                raise ToolMissing("lizard and radon are not installed") from None
            functions = []
            for batch in chunks(py_files):
                proc = run_tool(radon + ["cc", "-j", "-s"] + list(batch), ctx.root, timeout=900)
                functions.extend(parse_radon_cc(proc.stdout, ctx.root))
            tool = self.name = "Radon"
        findings = complexity_findings(functions, file_lengths, ctx.config, tool)
        ccns = [fn["ccn"] for fn in functions]
        return self.ran(findings, f"{len(functions)} functions", functions=len(functions),
                        max_ccn=max(ccns) if ccns else 0,
                        max_function_lines=max((fn["length"] for fn in functions), default=0),
                        max_file_lines=max(file_lengths.values(), default=0),
                        source_lines=sum(file_lengths.values()))


# --------------------------------------------------------------------------- #
# Tests and coverage (pytest)
# --------------------------------------------------------------------------- #

def parse_junit(xml_text: str, root: Path) -> Dict:
    tree = ET.fromstring(xml_text)
    suites = [tree] if tree.tag == "testsuite" else tree.findall("testsuite")
    totals: Dict[str, Any] = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0}
    failed: List[Finding] = []
    for suite in suites:
        for key in totals:
            totals[key] += int(suite.get(key, 0) or 0)
        for case in suite.iter("testcase"):
            problem = case.find("failure")
            if problem is None:
                problem = case.find("error")
            if problem is None:
                continue
            rel = case.get("file") or (case.get("classname", "").replace(".", "/") + ".py")
            failed.append(Finding(
                tool="pytest", rule_id="test-failed", file_path=to_rel(rel, root), line=int(case.get("line") or 0) + 1,
                message=f"Test {case.get('name')} failed: {(problem.get('message') or '').strip()[:300]}",
                severity=Severity.HIGH, category=Category.TESTS, code_snippet=(problem.text or "")[-1500:],
            ))
    run = totals["tests"] - totals["skipped"]
    passed = run - totals["failures"] - totals["errors"]
    totals["passed"] = passed
    totals["pass_rate"] = round(100.0 * passed / run, 1) if run else None
    return {"totals": totals, "failed": failed}


def has_python_tests(files: List[str]) -> bool:
    for f in files:
        name = Path(f).name
        if f.endswith(".py") and (name.startswith("test_") or name.endswith("_test.py")):
            return True
    return False


class PytestScanner(Scanner):
    name = "pytest"
    category = "tests"
    languages = ("python",)

    def applies(self, ctx: ScanContext):
        reason = super().applies(ctx)
        if reason:
            return reason
        if not gate_cfg(ctx.config, "tests").get("enabled", True):
            return "tests gate disabled"
        if ctx.is_remote and not (ctx.config.get("tests") or {}).get("run_for_remote_repos", False):
            return "running tests of remote repos is disabled (tests.run_for_remote_repos)"
        if not has_python_tests(ctx.files):
            return "no test files found (test_*.py or *_test.py)"
        return None

    def scan(self, ctx: ScanContext):
        import importlib.util

        if importlib.util.find_spec("pytest") is None:
            raise ToolMissing("pytest is not installed")
        with_cov = importlib.util.find_spec("pytest_cov") is not None
        timeout = int(gate_cfg(ctx.config, "tests").get("timeout_seconds", 600))
        with tempfile.TemporaryDirectory() as tmp:
            junit, cov = os.path.join(tmp, "junit.xml"), os.path.join(tmp, "coverage.json")
            cmd = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "--disable-warnings",
                   "-o", "junit_family=xunit1", f"--junitxml={junit}"]
            if with_cov:
                cmd += ["--cov=.", f"--cov-report=json:{cov}", "--cov-report="]
            proc = run_tool(cmd, ctx.root, timeout=timeout)
            if proc.returncode == 5:
                return self.ran([], "no tests collected", tests=0)
            if not os.path.isfile(junit):
                return self.error((proc.stdout + proc.stderr)[-2000:] or "pytest produced no report")
            with open(junit, encoding="utf-8") as fh:
                parsed = parse_junit(fh.read(), ctx.root)
            totals = parsed["totals"]
            if totals["errors"] and not totals["passed"] and not totals["failures"]:
                # Every test errored, usually because the project's dependencies aren't
                # installed in the reviewer's environment. That says nothing about the code.
                return self.error("tests couldn't run (collection errors). Run the reviewer from the project's "
                                  "environment, or set gates.tests.enabled: false. "
                                  + (proc.stdout.strip().splitlines() or [""])[-1][:300])
            metrics: Dict = dict(totals)
            if with_cov and os.path.isfile(cov):
                with open(cov, encoding="utf-8") as fh:
                    metrics.update(coverage_metrics(json.load(fh), ctx))
        msg = "" if with_cov else "pytest-cov not installed; coverage not measured"
        return self.ran(parsed["failed"], msg, **metrics)


def coverage_metrics(cov: Dict, ctx: ScanContext) -> Dict:
    out: Dict = {"coverage_overall": round(float((cov.get("totals") or {}).get("percent_covered", 0.0)), 1)}
    if ctx.changed_lines is not None:
        covered = total = 0
        for path, data in (cov.get("files") or {}).items():
            rel = to_rel(path, ctx.root)
            changed = ctx.changed_lines.get(rel)
            if not changed:
                continue
            executed, missing = set(data.get("executed_lines", [])), set(data.get("missing_lines", []))
            covered += len(changed & executed)
            total += len(changed & (executed | missing))
        out["coverage_new"] = round(100.0 * covered / total, 1) if total else None
        out["coverage_new_lines"] = total
    return out


# --------------------------------------------------------------------------- #
# Duplication (jscpd)
# --------------------------------------------------------------------------- #

class DuplicationScanner(Scanner):
    name = "jscpd"
    category = "duplication"

    def applies(self, ctx: ScanContext):
        return None if ctx.languages else "no source files"

    def scan(self, ctx: ScanContext):
        try:
            cmd = find_tool("jscpd", ctx.config)
        except ToolMissing:
            local = ctx.root / "node_modules" / ".bin" / ("jscpd.cmd" if os.name == "nt" else "jscpd")
            if not local.exists():
                raise ToolMissing("jscpd is not installed (npm install -g jscpd)") from None
            cmd = [str(local)]
        ignore = ",".join(f"**/{p.strip('/')}/**" if "." not in p.lstrip(".") else f"**/{p}"
                          for p in exclude_patterns(ctx.root, ctx.config))
        with tempfile.TemporaryDirectory() as tmp:
            proc = run_tool(cmd + ["--silent", "--reporters", "json", "--output", tmp, "--ignore", ignore, "."],
                            ctx.root, timeout=900)
            report = Path(tmp) / "jscpd-report.json"
            if not report.is_file():
                return self.error(proc.stderr or "jscpd produced no report")
            data = json.loads(report.read_text(encoding="utf-8"))
        findings = []
        for dup in data.get("duplicates", [])[:200]:
            first, second = dup.get("firstFile", {}), dup.get("secondFile", {})
            findings.append(Finding(
                tool="jscpd", rule_id="duplicate-code", file_path=to_rel(first.get("name", ""), ctx.root),
                line=int(first.get("start") or 0), end_line=first.get("end"), severity=Severity.LOW,
                category=Category.DUPLICATION,
                message=f"{dup.get('lines')} lines duplicated in {to_rel(second.get('name', ''), ctx.root)}:{second.get('start')}",
            ))
        pct = float(((data.get("statistics") or {}).get("total") or {}).get("percentage", 0.0))
        return self.ran(findings, duplication_percent=round(pct, 2))


# --------------------------------------------------------------------------- #
# Change hygiene (needs a base ref)
# --------------------------------------------------------------------------- #

DEBUG_PATTERNS = {
    "python": [(re.compile(r"^\s*print\("), "print() call"), (re.compile(r"\bbreakpoint\(\)"), "breakpoint()"),
               (re.compile(r"\bpdb\.set_trace\(|^\s*import pdb\b"), "pdb debugger")],
    "javascript": [(re.compile(r"\bconsole\.(log|debug|trace)\("), "console.log"), (re.compile(r"\bdebugger\s*;?"), "debugger statement")],
    "typescript": [(re.compile(r"\bconsole\.(log|debug|trace)\("), "console.log"), (re.compile(r"\bdebugger\s*;?"), "debugger statement")],
    "java": [(re.compile(r"\bSystem\.out\.print(ln)?\(|\.printStackTrace\(\)"), "debug print")],
    "csharp": [(re.compile(r"\bConsole\.Write(Line)?\("), "Console.WriteLine")],
}
TODO_PATTERN = re.compile(r"(#|//|/\*|\*)\s*(TODO|FIXME|XXX|HACK)\b")


def is_test_file(rel: str) -> bool:
    lower = rel.lower()
    name = Path(lower).name
    return ("/test" in f"/{lower}" or "/spec" in f"/{lower}" or name.startswith("test_")
            or name.endswith(("_test.py", ".test.js", ".test.ts", ".spec.js", ".spec.ts", "tests.cs", "test.java")))


class HygieneScanner(Scanner):
    name = "Change hygiene"
    category = "debug"

    def applies(self, ctx: ScanContext):
        return None if ctx.changed_lines is not None else "needs a base branch to compare against"

    def scan(self, ctx: ScanContext):
        added: Dict[str, Dict[int, str]] = ctx.extra.get("added_lines", {})
        findings = []
        for rel, lines in added.items():
            lang = LANGUAGE_BY_EXT.get(Path(rel).suffix.lower())
            if not lang or is_test_file(rel):
                continue
            for no, text in lines.items():
                for pattern, label in DEBUG_PATTERNS.get(lang, []):
                    if pattern.search(text):
                        findings.append(Finding(tool=self.name, rule_id="debug-leftover", file_path=rel, line=no,
                                                message=f"Debug leftover in new code: {label}", severity=Severity.LOW,
                                                category=Category.DEBUG, code_snippet=text.strip()))
                        break
                if TODO_PATTERN.search(text):
                    findings.append(Finding(tool=self.name, rule_id="todo-comment", file_path=rel, line=no,
                                            message="TODO/FIXME left in new code", severity=Severity.INFO,
                                            category=Category.DEBUG, code_snippet=text.strip()))
        source_changed = [f for f in added if LANGUAGE_BY_EXT.get(Path(f).suffix.lower()) and not is_test_file(f)]
        tests_changed = [f for f in added if is_test_file(f)]
        return self.ran(findings, changed_lines=ctx.extra.get("diff_changed_lines", 0),
                        source_files_changed=len(source_changed), test_files_changed=len(tests_changed))
