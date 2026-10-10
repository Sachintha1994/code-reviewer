"""Quality gates, verdict and health score, as described in QUALITY_GATES.md."""
from __future__ import annotations

from collections import Counter, defaultdict
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from app.config import gate_cfg
from app.core.models import Category, Finding, GateResult, GateStatus, ScanResult, ScanStatus, Severity

GATE_NAMES = {
    "build": "Build", "tests": "Tests", "coverage_new": "Coverage (new code)",
    "coverage_overall": "Coverage (overall)", "secrets": "Secrets", "sast": "SAST", "dependencies": "Dependency CVEs",
    "lint": "Lint", "types": "Type check", "complexity": "Complexity", "duplication": "Duplication",
    "size": "Function/file size", "debug_leftovers": "Debug leftovers", "diff": "Diff size",
    "tests_with_source": "Tests with source changes", "sonarqube": "SonarQube gate",
}
SEVERITY_POINTS = {Severity.CRITICAL: 10.0, Severity.HIGH: 5.0, Severity.MEDIUM: 1.0, Severity.LOW: 0.25, Severity.INFO: 0.0}


class _Ctx:
    def __init__(self, findings: List[Finding], scans: List[ScanResult], cfg: Dict[str, Any], diff_mode: bool):
        self.findings = [f for f in findings if f.counts]
        self.scans = scans
        self.cfg = cfg
        self.diff_mode = diff_mode
        self.by_cat: Dict[Category, List[Finding]] = defaultdict(list)
        for f in self.findings:
            self.by_cat[f.category].append(f)

    def scans_for(self, *names: str) -> List[ScanResult]:
        return [s for s in self.scans if s.tool in names or s.category in names]

    def metric(self, key: str, *scan_names: str) -> Any:
        for s in self.scans_for(*scan_names):
            if s.status == ScanStatus.RAN and s.metrics.get(key) is not None:
                return s.metrics[key]
        return None


def _top_files(findings: Sequence[Finding]) -> List[Dict[str, Any]]:
    counts = Counter(f.file_path for f in findings if f.file_path)
    out = []
    for path, n in counts.most_common(5):
        lines = sorted({f.line for f in findings if f.file_path == path and f.line})[:5]
        out.append({"file": path, "count": n, "lines": lines})
    return out


def _tool_state(scans: List[ScanResult]) -> Tuple[List[str], List[str], str]:
    """Tools that ran, and tools that should have run but didn't (missing or errored).
    Scans that don't apply to this project (e.g. ESLint with no JS) are left out."""
    ran = [s.tool for s in scans if s.status == ScanStatus.RAN]
    missing = [f"{s.tool}: {s.message}" for s in scans if s.status != ScanStatus.RAN and not s.not_applicable]
    return ran, missing, "; ".join(missing)


def _not_applicable(scans: List[ScanResult]) -> Optional[str]:
    if scans and all(s.not_applicable for s in scans):
        return "; ".join(sorted({s.message for s in scans}))
    return None


def _count_gate(key: str, ctx: _Ctx, scans: List[ScanResult], bad: List[Finding], limit: int,
                what: str, extra_details: str = "") -> GateResult:
    gcfg = gate_cfg(ctx.cfg, key)
    ran, _, missing = _tool_state(scans)
    sev = gcfg.get("severity", "blocker")
    if not ran:
        na = _not_applicable(scans)
        return GateResult(key=key, name=GATE_NAMES[key], status=GateStatus.SKIPPED, severity=sev,
                          threshold=f"<= {limit}", details=na or missing or "no tool ran",
                          tools=[s.tool for s in scans], not_applicable=bool(na))
    status = GateStatus.FAILED if len(bad) > limit else GateStatus.PASSED
    details = f"{len(bad)} {what}" + (f" (not run: {missing})" if missing else "") + extra_details
    return GateResult(key=key, name=GATE_NAMES[key], status=status, severity=sev, actual=str(len(bad)),
                      threshold=f"<= {limit}", details=details, tools=ran, top_files=_top_files(bad))


def _high_plus(findings: List[Finding]) -> List[Finding]:
    return [f for f in findings if f.effective_severity.rank >= Severity.HIGH.rank]


def gate_build(ctx: _Ctx) -> GateResult:
    return _count_gate("build", ctx, ctx.scans_for("Build", "Maven"), ctx.by_cat[Category.BUILD], 0, "compile errors")


def gate_tests(ctx: _Ctx) -> GateResult:
    gcfg = gate_cfg(ctx.cfg, "tests")
    scans = ctx.scans_for("pytest", "Maven")
    rate = ctx.metric("pass_rate", "pytest", "Maven")
    minimum = float(gcfg.get("min_pass_rate", 100))
    sev = gcfg.get("severity", "blocker")
    if rate is None:
        _, _, missing = _tool_state(scans)
        na = _not_applicable(scans)
        if not na and any(s.status == ScanStatus.RAN and s.metrics.get("tests") == 0 for s in scans):
            na = "no tests found"
        return GateResult(key="tests", name=GATE_NAMES["tests"], status=GateStatus.SKIPPED, severity=sev,
                          threshold=f">= {minimum:g}%", details=na or missing or "no tests ran",
                          tools=[s.tool for s in scans], not_applicable=bool(na))
    source = next(s for s in scans if s.status == ScanStatus.RAN and s.metrics.get("pass_rate") is not None)
    totals = source.metrics
    status = GateStatus.PASSED if rate >= minimum else GateStatus.FAILED
    return GateResult(key="tests", name=GATE_NAMES["tests"], status=status, severity=sev, actual=f"{rate:g}%",
                      threshold=f">= {minimum:g}%", tools=[source.tool],
                      details=f"{totals.get('passed', 0)} passed, {totals.get('failures', 0)} failed, "
                              f"{totals.get('errors', 0)} errors, {totals.get('skipped', 0)} skipped",
                      top_files=_top_files(ctx.by_cat[Category.TESTS]))


def _coverage_gate(key: str, ctx: _Ctx, value: Optional[float], reason: str, tools: List[str]) -> GateResult:
    gcfg = gate_cfg(ctx.cfg, key)
    minimum = float(gcfg.get("min", 80 if key == "coverage_new" else 70))
    sev = gcfg.get("severity", "blocker" if key == "coverage_new" else "warn")
    if value is None:
        return GateResult(key=key, name=GATE_NAMES[key], status=GateStatus.SKIPPED, severity=sev,
                          threshold=f">= {minimum:g}%", details=reason, tools=tools)
    status = GateStatus.PASSED if value >= minimum else GateStatus.FAILED
    return GateResult(key=key, name=GATE_NAMES[key], status=status, severity=sev, actual=f"{value:g}%",
                      threshold=f">= {minimum:g}%", tools=tools)


def gate_coverage_new(ctx: _Ctx) -> GateResult:
    if not ctx.diff_mode:
        gate = _coverage_gate("coverage_new", ctx, None, "needs a base branch to know which code is new", [])
        gate.not_applicable = True  # a whole-project review has no "new code"
        return gate
    value = ctx.metric("coverage_new", "pytest", "Maven")
    reason = "coverage not measured (needs tests plus pytest-cov or JaCoCo)" if value is None else ""
    if value is None and ctx.metric("coverage_new_lines", "pytest", "Maven") == 0:
        reason = "no executable new lines"
    return _coverage_gate("coverage_new", ctx, value, reason, ["pytest-cov", "JaCoCo"])


def gate_coverage_overall(ctx: _Ctx) -> GateResult:
    value = ctx.metric("coverage_overall", "pytest", "Maven", "Codecov")
    return _coverage_gate("coverage_overall", ctx, value, "coverage not measured (needs pytest-cov, JaCoCo or Codecov)",
                          ["pytest-cov", "JaCoCo", "Codecov"])


def gate_secrets(ctx: _Ctx) -> GateResult:
    gcfg = gate_cfg(ctx.cfg, "secrets")
    real = [f for f in ctx.by_cat[Category.SECRETS] if f.effective_severity.rank >= Severity.MEDIUM.rank]
    test_data = len(ctx.by_cat[Category.SECRETS]) - len(real)
    extra = f"; {test_data} in test data (not counted)" if test_data else ""
    scans = ctx.scans_for("secrets")
    return _count_gate("secrets", ctx, scans, real, int(gcfg.get("max_findings", 0)), "secrets", extra)


def _sev_limit_gate(key: str, ctx: _Ctx, cat: Category, scans: List[ScanResult], what: str) -> GateResult:
    gcfg = gate_cfg(ctx.cfg, key)
    crit = [f for f in ctx.by_cat[cat] if f.effective_severity == Severity.CRITICAL]
    high = [f for f in ctx.by_cat[cat] if f.effective_severity == Severity.HIGH]
    max_c, max_h = int(gcfg.get("max_critical", 0)), int(gcfg.get("max_high", 0))
    result = _count_gate(key, ctx, scans, crit + high, max_c + max_h, what)
    if result.status != GateStatus.SKIPPED:
        failed = len(crit) > max_c or len(high) > max_h
        result.status = GateStatus.FAILED if failed else GateStatus.PASSED
        result.actual = f"{len(crit)} critical, {len(high)} high"
        result.threshold = f"<= {max_c} critical, <= {max_h} high"
    return result


def gate_sast(ctx: _Ctx) -> GateResult:
    return _sev_limit_gate("sast", ctx, Category.SAST, ctx.scans_for("Semgrep", "Bandit"), "high/critical issues")


def gate_dependencies(ctx: _Ctx) -> GateResult:
    return _sev_limit_gate("dependencies", ctx, Category.DEPENDENCIES, ctx.scans_for("Trivy"),
                           "high/critical vulnerable dependencies")


def gate_lint(ctx: _Ctx) -> GateResult:
    gcfg = gate_cfg(ctx.cfg, "lint")
    lint = ctx.by_cat[Category.LINT]
    errors = _high_plus(lint)
    extra = f"; {len(lint) - len(errors)} warnings/style issues (not blocking)" if len(lint) > len(errors) else ""
    return _count_gate("lint", ctx, ctx.scans_for("Ruff", "Flake8", "ESLint", "PMD"), errors,
                       int(gcfg.get("max_errors", 0)), "errors", extra)


def gate_types(ctx: _Ctx) -> GateResult:
    gcfg = gate_cfg(ctx.cfg, "types")
    return _count_gate("types", ctx, ctx.scans_for("mypy"), ctx.by_cat[Category.TYPES],
                       int(gcfg.get("max_errors", 0)), "type errors")


def gate_complexity(ctx: _Ctx) -> GateResult:
    gcfg = gate_cfg(ctx.cfg, "complexity")
    warn_over, fail_over = int(gcfg.get("warn_over", 15)), int(gcfg.get("fail_over", 25))
    scans = ctx.scans_for("Lizard", "Radon")
    ran, _, missing = _tool_state(scans)
    if not ran:
        na = _not_applicable(scans)
        return GateResult(key="complexity", name=GATE_NAMES["complexity"], status=GateStatus.SKIPPED,
                          severity="warn", threshold=f"<= {warn_over} (fail > {fail_over})",
                          details=na or missing or "no tool ran", tools=[s.tool for s in scans], not_applicable=bool(na))
    found = ctx.by_cat[Category.COMPLEXITY]
    worst = max((int(f.extra.get("ccn", 0)) for f in found), default=0)
    if worst > fail_over:
        status, sev = GateStatus.FAILED, "blocker"
    elif worst > warn_over:
        status, sev = GateStatus.FAILED, "warn"
    else:
        status, sev = GateStatus.PASSED, "warn"
    return GateResult(key="complexity", name=GATE_NAMES["complexity"], status=status, severity=sev,
                      actual=f"max {worst}" if found else "ok", threshold=f"<= {warn_over} (fail > {fail_over})",
                      details=f"{len(found)} functions over {warn_over}", tools=ran, top_files=_top_files(found))


def gate_duplication(ctx: _Ctx) -> GateResult:
    gcfg = gate_cfg(ctx.cfg, "duplication")
    limit = float(gcfg.get("max_percent", 5))
    scans = ctx.scans_for("jscpd")
    pct = ctx.metric("duplication_percent", "jscpd")
    sev = gcfg.get("severity", "warn")
    if pct is None:
        _, _, missing = _tool_state(scans)
        return GateResult(key="duplication", name=GATE_NAMES["duplication"], status=GateStatus.SKIPPED, severity=sev,
                          threshold=f"< {limit:g}%", details=missing or "no tool ran", tools=["jscpd"])
    status = GateStatus.PASSED if pct < limit else GateStatus.FAILED
    return GateResult(key="duplication", name=GATE_NAMES["duplication"], status=status, severity=sev,
                      actual=f"{pct:g}%", threshold=f"< {limit:g}%", tools=["jscpd"],
                      top_files=_top_files(ctx.by_cat[Category.DUPLICATION]))


def gate_size(ctx: _Ctx) -> GateResult:
    gcfg = gate_cfg(ctx.cfg, "size")
    result = _count_gate("size", ctx, ctx.scans_for("Lizard", "Radon"), ctx.by_cat[Category.SIZE], 0,
                         "functions or files over the size limit")
    result.severity = gcfg.get("severity", "warn")
    result.threshold = f"functions <= {gcfg.get('max_function_lines', 60)} lines, files <= {gcfg.get('max_file_lines', 500)}"
    return result


def _diff_skip(key: str, ctx: _Ctx) -> Optional[GateResult]:
    if ctx.diff_mode:
        return None
    return GateResult(key=key, name=GATE_NAMES[key], status=GateStatus.SKIPPED,
                      severity=gate_cfg(ctx.cfg, key).get("severity", "warn"),
                      details="needs a base branch to compare against")


def gate_debug(ctx: _Ctx) -> GateResult:
    skipped = _diff_skip("debug_leftovers", ctx)
    if skipped:
        return skipped
    bad = [f for f in ctx.by_cat[Category.DEBUG] if f.rule_id == "debug-leftover"]
    todos = len(ctx.by_cat[Category.DEBUG]) - len(bad)
    result = _count_gate("debug_leftovers", ctx, ctx.scans_for("Change hygiene"), bad, 0, "debug statements",
                         f"; {todos} TODO/FIXME (not counted)" if todos else "")
    result.severity = gate_cfg(ctx.cfg, "debug_leftovers").get("severity", "warn")
    return result


def gate_diff(ctx: _Ctx) -> GateResult:
    skipped = _diff_skip("diff", ctx)
    if skipped:
        return skipped
    gcfg = gate_cfg(ctx.cfg, "diff")
    limit = int(gcfg.get("max_changed_lines", 400))
    changed = int(ctx.metric("changed_lines", "Change hygiene") or 0)
    status = GateStatus.PASSED if changed <= limit else GateStatus.FAILED
    return GateResult(key="diff", name=GATE_NAMES["diff"], status=status, severity=gcfg.get("severity", "warn"),
                      actual=str(changed), threshold=f"<= {limit} changed lines", tools=["git"],
                      details="large diffs are hard to review well" if status == GateStatus.FAILED else "")


def gate_tests_with_source(ctx: _Ctx) -> GateResult:
    skipped = _diff_skip("tests_with_source", ctx)
    if skipped:
        return skipped
    src = int(ctx.metric("source_files_changed", "Change hygiene") or 0)
    tests = int(ctx.metric("test_files_changed", "Change hygiene") or 0)
    failed = src > 0 and tests == 0
    return GateResult(key="tests_with_source", name=GATE_NAMES["tests_with_source"],
                      status=GateStatus.FAILED if failed else GateStatus.PASSED,
                      severity=gate_cfg(ctx.cfg, "tests_with_source").get("severity", "warn"),
                      actual=f"{src} source, {tests} test files changed", tools=["git"],
                      details="source changed but no tests did" if failed else "")


def gate_sonarqube(ctx: _Ctx) -> Optional[GateResult]:
    scans = ctx.scans_for("SonarQube")
    if not scans or scans[0].status == ScanStatus.SKIPPED:
        return None  # not configured: don't show the gate at all
    sev = gate_cfg(ctx.cfg, "sonarqube").get("severity", "blocker")
    scan = scans[0]
    if scan.status != ScanStatus.RAN:
        return GateResult(key="sonarqube", name=GATE_NAMES["sonarqube"], status=GateStatus.SKIPPED, severity=sev,
                          details=scan.message, tools=["SonarQube"])
    gate = scan.metrics.get("quality_gate", "UNKNOWN")
    failing = [c for c in scan.metrics.get("conditions", []) if c.get("status") == "ERROR"]
    details = ", ".join(f"{c.get('metricKey')} {c.get('actualValue')} (limit {c.get('errorThreshold')})" for c in failing)
    status = GateStatus.FAILED if gate == "ERROR" else GateStatus.PASSED if gate in ("OK", "WARN") else GateStatus.SKIPPED
    return GateResult(key="sonarqube", name=GATE_NAMES["sonarqube"], status=status, severity=sev, actual=gate,
                      threshold="OK", details=details, tools=["SonarQube"])


GATE_FUNCS: List[Tuple[str, Callable[[_Ctx], Optional[GateResult]]]] = [
    ("build", gate_build), ("tests", gate_tests), ("coverage_new", gate_coverage_new),
    ("coverage_overall", gate_coverage_overall), ("secrets", gate_secrets), ("sast", gate_sast),
    ("dependencies", gate_dependencies), ("lint", gate_lint), ("types", gate_types),
    ("complexity", gate_complexity), ("duplication", gate_duplication), ("size", gate_size),
    ("debug_leftovers", gate_debug), ("diff", gate_diff), ("tests_with_source", gate_tests_with_source),
    ("sonarqube", gate_sonarqube),
]


def evaluate_gates(findings: List[Finding], scans: List[ScanResult], cfg: Dict[str, Any], diff_mode: bool) -> List[GateResult]:
    ctx = _Ctx(findings, scans, cfg, diff_mode)
    results = []
    for key, fn in GATE_FUNCS:
        if not gate_cfg(cfg, key).get("enabled", True):
            continue
        result = fn(ctx)
        if result is not None:
            results.append(result)
    return results


def decide_verdict(gates: List[GateResult], cfg: Dict[str, Any]) -> Tuple[str, str]:
    failed_blockers = [g for g in gates if g.status == GateStatus.FAILED and g.severity == "blocker"]
    failed_warns = [g for g in gates if g.status == GateStatus.FAILED and g.severity != "blocker"]
    skipped_blockers = [g for g in gates if g.status == GateStatus.SKIPPED and g.severity == "blocker"
                        and not g.not_applicable]
    if failed_blockers:
        n = len(failed_blockers)
        return "FAIL", f"{n} blocker gate{'s' if n != 1 else ''} failed: {', '.join(g.name for g in failed_blockers)}"
    if failed_warns:
        n = len(failed_warns)
        return "WARN", f"{n} warning gate{'s' if n != 1 else ''} failed: {', '.join(g.name for g in failed_warns)}"
    if skipped_blockers and (cfg.get("verdict") or {}).get("skipped_blocker_is_warn", True):
        return "WARN", f"no failures, but these blocker gates couldn't run: {', '.join(g.name for g in skipped_blockers)}"
    return "PASS", "all gates passed"


def health_score(findings: List[Finding], source_lines: int, verdict: str) -> Dict[str, Any]:
    """Score from 0 to 100 based on weighted findings per 1,000 lines of code,
    so large healthy projects aren't punished for their size."""
    # AI-only findings are suggestions, not measured facts: shown, but not scored.
    active = [f for f in findings if f.counts and f.category != Category.AI]
    counts = Counter(f.effective_severity.value for f in active)
    points = sum(SEVERITY_POINTS[f.effective_severity] for f in active)
    kloc = max(source_lines / 1000.0, 1.0)
    density = points / kloc
    raw = 100.0 / (1.0 + density / 20.0)
    cap = {"FAIL": 69, "WARN": 89}.get(verdict, 100)
    score = int(round(min(raw, cap)))
    grade = "A" if score >= 90 else "B" if score >= 80 else "C" if score >= 70 else "D" if score >= 60 else "F"
    notes = []
    if raw > cap:
        notes.append(f"capped at {cap} because the verdict is {verdict}")
    return {
        "score": score, "grade": grade, "raw_score": round(raw, 1), "points": round(points, 2),
        "kloc": round(kloc, 2), "density": round(density, 2),
        "by_severity": {s.value: counts.get(s.value, 0) for s in Severity}, "notes": notes,
    }
