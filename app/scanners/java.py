"""Java scanners: Maven (build, tests, JaCoCo coverage) and PMD (lint)."""
from __future__ import annotations

import json
import os
import re
import tempfile
import time
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from app.config import gate_cfg
from app.core.models import Category, Finding, Severity
from app.scanners.base import ScanContext, Scanner, ToolMissing, find_tool, run_tool, to_rel
from app.scanners.quality import parse_junit

# [ERROR] /C:/proj/src/main/java/a/Foo.java:[12,8] cannot find symbol
MAVEN_ERROR = re.compile(r"^\[ERROR\]\s+(?P<path>.+?\.java):\[(?P<line>\d+)(?:,(?P<col>\d+))?\]\s*(?P<msg>.*)$")
DEFAULT_JACOCO = "0.8.12"


def _clean_maven_path(path: str) -> str:
    # Maven on Windows prints /C:/Users/... ; strip the leading slash
    return path[1:] if re.match(r"^/[A-Za-z]:[/\\]", path) else path


def parse_maven_errors(output: str, root: Path) -> List[Finding]:
    seen: Set[tuple] = set()
    findings = []
    for raw in (output or "").splitlines():
        m = MAVEN_ERROR.match(raw.strip())
        if not m:
            continue
        rel = to_rel(_clean_maven_path(m.group("path")), root)
        key = (rel, m.group("line"), m.group("msg"))
        if key in seen:  # Maven prints each error twice (log and summary)
            continue
        seen.add(key)
        findings.append(Finding(
            tool="Maven", rule_id="compile-error", file_path=rel, line=int(m.group("line")),
            column=int(m.group("col")) if m.group("col") else None,
            message=f"Does not compile: {m.group('msg').strip()}", severity=Severity.CRITICAL, category=Category.BUILD,
        ))
    return findings


def _fresh(paths: List[Path], since: float) -> List[Path]:
    return [p for p in paths if p.stat().st_mtime >= since - 2]


def _skip_dir(path: Path, root: Path) -> bool:
    parts = path.relative_to(root).parts
    return any(p in ("node_modules", ".git") for p in parts)


def collect_surefire(root: Path, since: float, java_files: List[str]) -> Dict[str, Any]:
    reports = [p for p in root.rglob("TEST-*.xml")
               if p.parent.name in ("surefire-reports", "failsafe-reports") and not _skip_dir(p, root)]
    totals: Dict[str, Any] = {"tests": 0, "failures": 0, "errors": 0, "skipped": 0, "passed": 0}
    failed: List[Finding] = []
    for report in _fresh(reports, since):
        try:
            parsed = parse_junit(report.read_text(encoding="utf-8", errors="replace"), root)
        except ET.ParseError:
            continue
        for key in totals:
            totals[key] += parsed["totals"].get(key, 0) or 0
        failed.extend(parsed["failed"])
    # point failed tests at their .java file and line instead of a guessed path
    by_suffix = {f: f for f in java_files}
    for f in failed:
        cls_path = f.file_path[:-3] if f.file_path.endswith(".py") else f.file_path
        match = next((p for p in by_suffix if p.endswith(cls_path + ".java")), None)
        if match:
            f.file_path = match
            simple = Path(match).stem
            line = re.search(rf"\({re.escape(simple)}\.java:(\d+)\)", f.code_snippet or "")
            f.line = int(line.group(1)) if line else 1
        f.tool = "Maven (surefire)"
    run = totals["tests"] - totals["skipped"]
    totals["pass_rate"] = round(100.0 * totals["passed"] / run, 1) if run else None
    totals["test_reports"] = len(_fresh(reports, since))
    return {"totals": totals, "failed": failed}


def collect_jacoco(root: Path, since: float, changed: Optional[Dict[str, Set[int]]]) -> Dict[str, Any]:
    reports = [p for p in root.rglob("jacoco.xml") if not _skip_dir(p, root)]
    reports = _fresh(reports, since)
    if not reports:
        return {}
    covered = missed = 0
    new_covered = new_total = 0
    changed_items = list((changed or {}).items())
    for report in reports:
        try:
            tree = ET.parse(str(report)).getroot()
        except ET.ParseError:
            continue
        for counter in tree.findall("counter"):
            if counter.get("type") == "LINE":
                covered += int(counter.get("covered", 0))
                missed += int(counter.get("missed", 0))
        if changed is None:
            continue
        for package in tree.findall("package"):
            pkg = package.get("name", "")
            for source in package.findall("sourcefile"):
                suffix = f"{pkg}/{source.get('name', '')}"
                lines = next((ls for path, ls in changed_items if path.endswith(suffix)), None)
                if not lines:
                    continue
                for line in source.findall("line"):
                    nr = int(line.get("nr", 0))
                    if nr in lines:
                        new_total += 1
                        if int(line.get("ci", 0)) > 0:
                            new_covered += 1
    out: Dict[str, Any] = {}
    if covered + missed:
        out["coverage_overall"] = round(100.0 * covered / (covered + missed), 1)
    if changed is not None:
        out["coverage_new"] = round(100.0 * new_covered / new_total, 1) if new_total else None
        out["coverage_new_lines"] = new_total
    return out


class MavenScanner(Scanner):
    """Compiles the project, runs its tests and measures coverage with JaCoCo,
    in a single Maven run (no changes to the project's pom.xml needed)."""

    name = "Maven"
    category = "build"
    languages = ("java", "kotlin")

    def applies(self, ctx: ScanContext):
        reason = super().applies(ctx)
        if reason:
            return reason
        if not (ctx.root / "pom.xml").is_file():
            return "no pom.xml in the project root (only Maven builds are supported)"
        return None

    def _command(self, ctx: ScanContext) -> List[str]:
        for wrapper in (("mvnw.cmd",) if os.name == "nt" else ("mvnw",)):
            path = ctx.root / wrapper
            if path.is_file():
                return [str(path)]
        try:
            return find_tool("mvn", ctx.config)
        except ToolMissing:
            raise ToolMissing("Maven is not installed (install Maven and a JDK, or add mvnw to the project)") from None

    def scan(self, ctx: ScanContext):
        cfg = ctx.config.get("maven") or {}
        mvn = self._command(ctx)
        tests_cfg = gate_cfg(ctx.config, "tests")
        run_tests = tests_cfg.get("enabled", True) and not (
            ctx.is_remote and not (ctx.config.get("tests") or {}).get("run_for_remote_repos", False))
        jacoco = f"org.jacoco:jacoco-maven-plugin:{cfg.get('jacoco_version', DEFAULT_JACOCO)}"
        cmd = mvn + ["-B", "-ntp", "-Dstyle.color=never", "-Dmaven.test.failure.ignore=true"]
        cmd += list(cfg.get("extra_args") or [])
        if run_tests:
            cmd += [f"{jacoco}:prepare-agent", "test", f"{jacoco}:report"]
        else:
            cmd += ["-DskipTests", "test-compile"]
        started = time.time()
        proc = run_tool(cmd, ctx.root, timeout=int(cfg.get("timeout_seconds", 1800)))
        output = proc.stdout + "\n" + proc.stderr
        compile_errors = parse_maven_errors(output, ctx.root)
        tail = "\n".join(line for line in output.strip().splitlines()[-15:] if line.strip())
        if proc.returncode != 0 and not compile_errors:
            if "BUILD FAILURE" in output or "ERROR" in output:
                return self.error(f"Maven failed (not a compile error): {tail[-1500:]}")
            return self.error(f"Maven exited with {proc.returncode}: {tail[-1500:]}")
        if compile_errors:
            return self.ran(compile_errors, f"{len(compile_errors)} compile errors; tests not run")
        findings: List[Finding] = []
        metrics: Dict[str, Any] = {}
        message = "compiled"
        if run_tests:
            java_files = [f for f in ctx.files if f.endswith((".java", ".kt"))]
            tests = collect_surefire(ctx.root, started, java_files)
            findings.extend(tests["failed"])
            metrics.update(tests["totals"])
            coverage = collect_jacoco(ctx.root, started, ctx.changed_lines)
            metrics.update(coverage)
            parts = [f"{tests['totals']['tests']} tests"]
            if "coverage_overall" in coverage:
                parts.append(f"line coverage {coverage['coverage_overall']}%")
            elif tests["totals"]["tests"]:
                parts.append("no JaCoCo report (the pom may override surefire's argLine without @{argLine})")
            message = ", ".join(parts)
        else:
            message = "compiled (tests not run for remote repos or tests gate disabled)"
        return self.ran(findings, message, **metrics)


# --------------------------------------------------------------------------- #
# PMD
# --------------------------------------------------------------------------- #

BUG_RULESETS = ("errorprone", "multithreading", "security")


def pmd_severity(priority: int, ruleset: str) -> Severity:
    rs = (ruleset or "").lower().replace(" ", "")
    if priority <= 1:
        return Severity.HIGH
    if priority == 2 or (priority == 3 and any(b in rs for b in BUG_RULESETS)):
        return Severity.MEDIUM
    if priority == 3:
        return Severity.LOW
    return Severity.INFO


def parse_pmd(output: str, root: Path) -> List[Finding]:
    data = json.loads(output or "{}")
    findings = []
    for file_result in data.get("files", []):
        rel = to_rel(file_result.get("filename", ""), root)
        for v in file_result.get("violations", []):
            findings.append(Finding(
                tool="PMD", rule_id=v.get("rule", "pmd"), file_path=rel, line=int(v.get("beginline") or 0),
                column=v.get("begincolumn"), end_line=v.get("endline"), message=v.get("description", "").strip(),
                severity=pmd_severity(int(v.get("priority") or 3), v.get("ruleset", "")), category=Category.LINT,
                url=v.get("externalInfoUrl"), extra={"ruleset": v.get("ruleset")},
            ))
    return findings


class PMDScanner(Scanner):
    name = "PMD"
    category = "lint"
    languages = ("java",)

    def scan(self, ctx: ScanContext):
        try:
            pmd = find_tool("pmd", ctx.config)
        except ToolMissing:
            raise ToolMissing("PMD is not installed (download PMD 7 and add its bin folder to PATH)") from None
        cfg = ctx.config.get("pmd") or {}
        rulesets = ",".join(cfg.get("rulesets") or ["rulesets/java/quickstart.xml"])
        files = ctx.files_for("java")
        with tempfile.TemporaryDirectory() as tmp:
            file_list = Path(tmp) / "files.txt"
            file_list.write_text("\n".join(str(ctx.root / f) for f in files), encoding="utf-8")
            report = Path(tmp) / "pmd.json"
            cmd = pmd + ["check", "--file-list", str(file_list), "-R", rulesets, "-f", "json", "-r", str(report),
                         "--no-progress", "--no-cache", "--no-fail-on-violation"]
            proc = run_tool(cmd, ctx.root, timeout=int(cfg.get("timeout_seconds", 900)))
            if not report.is_file():
                text = (proc.stderr or proc.stdout).strip()
                if "check" in text and ("Unknown" in text or "usage" in text.lower()):
                    return self.error("PMD 7 or newer is required")
                return self.error(text[-1500:] or f"pmd exited with {proc.returncode}")
            findings = parse_pmd(report.read_text(encoding="utf-8", errors="replace"), ctx.root)
        return self.ran(findings, f"{len(files)} files, rules: {rulesets}")
