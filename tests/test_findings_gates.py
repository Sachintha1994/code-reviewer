"""Post-processing, gates, verdict and score."""

from app.config import load_config
from app.core import findings as fx
from app.core.gates import decide_verdict, evaluate_gates, health_score
from app.core.models import Category, Finding, GateStatus, ScanResult, ScanStatus, Severity
from app.scanners.base import is_excluded, mask_line


def F(**kw):
    base = dict(tool="Ruff", rule_id="F401", file_path="a.py", line=1, message="m", severity=Severity.LOW, category=Category.LINT)
    base.update(kw)
    return Finding(**base)


def scan(tool, category, status=ScanStatus.RAN, **kw):
    return ScanResult(tool=tool, category=category, status=status, **kw)


def test_excludes_match_folders_and_globs():
    pats = ["node_modules", "venv", "*.min.js", "_backup*", "docs/generated"]
    assert is_excluded("web/node_modules/x/y.js", pats)
    assert is_excluded("venv/lib/site.py", pats)
    assert is_excluded("static/app.min.js", pats)
    assert is_excluded("_backup_before_upgrade/main.py", pats)
    assert is_excluded("docs/generated/a.md", pats)
    assert not is_excluded("src/venvironment.py", pats)
    assert not is_excluded("docs/manual.md", pats)


def test_inline_suppression_with_rule_and_reason(tmp_path):
    (tmp_path / "a.py").write_text("x = 1\nkey = 'abc'  # reviewer: ignore[secrets] sample value\n# reviewer: ignore\ny = z\n")
    s1 = F(file_path="a.py", line=2, category=Category.SECRETS, rule_id="generic-secret")
    s2 = F(file_path="a.py", line=2, rule_id="E501")                 # different rule: not suppressed
    s3 = F(file_path="a.py", line=4, rule_id="F821")                 # comment on the line above
    fx.apply_inline_suppressions([s1, s2, s3], tmp_path)
    assert s1.suppressed == "inline: sample value"
    assert s2.suppressed is None
    assert s3.suppressed == "inline: ignored inline"


def test_dedup_merges_same_issue_across_tools():
    a = F(tool="Semgrep", rule_id="sqli", line=12, severity=Severity.HIGH, category=Category.SAST)
    b = F(tool="Bandit", rule_id="B608", line=13, severity=Severity.MEDIUM, category=Category.SAST)
    c = F(tool="Ruff", rule_id="F821", line=21, severity=Severity.HIGH)
    d = F(tool="mypy", rule_id="name-defined", line=21, severity=Severity.MEDIUM, category=Category.TYPES)
    e = F(tool="Ruff", rule_id="E501", line=21, severity=Severity.INFO)  # different problem on the same line
    merged = fx.deduplicate([a, b, c, d, e])
    assert len(merged) == 3
    sql = next(f for f in merged if f.category == Category.SAST)
    assert sql.tools == ["Semgrep", "Bandit"] and sql.severity == Severity.HIGH
    undefined = next(f for f in merged if f.rule_id == "F821")
    assert undefined.tools == ["Ruff", "mypy"]


def test_fingerprint_survives_line_shifts(tmp_path):
    (tmp_path / "a.py").write_text("import os\n")
    before = fx.fingerprint(F(line=1), tmp_path)
    (tmp_path / "a.py").write_text("\n\n# header\nimport os\n")
    from app.scanners.base import clear_line_cache
    clear_line_cache()
    after = fx.fingerprint(F(line=4), tmp_path)
    assert before == after


def test_filter_to_changes_keeps_changed_lines_and_functions():
    changed = {"a.py": {5, 6}, "requirements.txt": {2}}
    keep_line = F(line=5)
    drop_line = F(line=9)
    keep_fn = F(line=1, end_line=20, category=Category.COMPLEXITY, rule_id="complexity")
    dep = F(file_path="requirements.txt", line=1, category=Category.DEPENDENCIES, rule_id="CVE-1")
    other_file = F(file_path="b.py", line=5)
    kept = fx.filter_to_changes([keep_line, drop_line, keep_fn, dep, other_file], changed)
    assert kept == [keep_line, keep_fn, dep]


def test_baseline_and_user_suppressions():
    a, b = F(fingerprint="aaa"), F(fingerprint="bbb")
    fx.apply_baseline([a, b], {"aaa"})
    fx.apply_user_suppressions([a, b], {"bbb": "marked false positive"})
    assert not a.is_new and not a.counts
    assert b.suppressed and not b.counts


def test_mask_line_hides_secrets_but_not_names():
    assert "Xk9#mP2vL8qR4tZ7wN3s" not in mask_line('PW = "Xk9#mP2vL8qR4tZ7wN3s"')
    assert mask_line('t = os.getenv("API_TOKEN", "changeme")') == 't = os.getenv("API_TOKEN", "changeme")'
    assert "AKIAIOSFODNN7EXAMPLE" not in mask_line('k = "AKIAIOSFODNN7EXAMPLE"')


CFG = load_config()


def test_verdict_fail_on_blocker():
    findings = [F(category=Category.SECRETS, severity=Severity.HIGH, rule_id="aws")]
    scans = [scan("Gitleaks", "secrets"), scan("Ruff", "lint")]
    gates = evaluate_gates(findings, scans, CFG, diff_mode=False)
    secrets = next(g for g in gates if g.key == "secrets")
    assert secrets.status == GateStatus.FAILED
    verdict, reason = decide_verdict(gates, CFG)
    assert verdict == "FAIL" and "Secrets" in reason


def test_style_issues_do_not_block_lint_gate():
    findings = [F(rule_id="E501", severity=Severity.INFO), F(rule_id="F401", severity=Severity.LOW)]
    gates = evaluate_gates(findings, [scan("Ruff", "lint")], CFG, diff_mode=False)
    lint = next(g for g in gates if g.key == "lint")
    assert lint.status == GateStatus.PASSED and "not blocking" in lint.details


def test_missing_blocker_tool_is_skipped_and_caps_verdict_at_warn():
    scans = [scan("Semgrep", "sast", ScanStatus.SKIPPED, message="semgrep is not installed"),
             scan("Bandit", "sast", ScanStatus.SKIPPED, message="bandit is not installed")]
    gates = evaluate_gates([], scans, CFG, diff_mode=False)
    sast = next(g for g in gates if g.key == "sast")
    assert sast.status == GateStatus.SKIPPED and "not installed" in sast.details
    assert decide_verdict([sast], CFG)[0] == "WARN"


def test_not_applicable_scans_do_not_lower_verdict():
    scans = [scan("pytest", "tests", ScanStatus.SKIPPED, message="no test files found", not_applicable=True)]
    gates = [g for g in evaluate_gates([], scans, CFG, diff_mode=False) if g.key == "tests"]
    assert gates[0].not_applicable
    assert decide_verdict(gates, CFG)[0] == "PASS"


def test_complexity_gate_warns_then_blocks():
    scans = [scan("Lizard", "complexity")]
    warn = F(category=Category.COMPLEXITY, rule_id="complexity", severity=Severity.MEDIUM, extra={"ccn": 18})
    block = F(category=Category.COMPLEXITY, rule_id="complexity", severity=Severity.HIGH, extra={"ccn": 30}, line=40)
    g1 = next(g for g in evaluate_gates([warn], scans, CFG, False) if g.key == "complexity")
    g2 = next(g for g in evaluate_gates([warn, block], scans, CFG, False) if g.key == "complexity")
    assert (g1.status, g1.severity) == (GateStatus.FAILED, "warn")
    assert (g2.status, g2.severity) == (GateStatus.FAILED, "blocker")


def test_disabled_gate_is_left_out():
    cfg = load_config(overrides={"gates": {"types": {"enabled": False}}})
    assert all(g.key != "types" for g in evaluate_gates([], [], cfg, False))


def test_health_score_scales_with_size_and_caps_by_verdict():
    findings = [F(severity=Severity.HIGH) for _ in range(4)]   # 20 points
    small = health_score(findings, 1000, "PASS")
    large = health_score(findings, 20000, "PASS")
    assert large["score"] > small["score"]
    assert health_score([], 5000, "FAIL")["score"] == 69
    assert health_score([], 5000, "PASS")["score"] == 100
    dismissed = F(severity=Severity.CRITICAL, ai_dismissed=True)
    assert health_score([dismissed], 1000, "PASS")["score"] == 100
