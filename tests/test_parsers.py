"""Parsers for each tool's output, using saved samples."""
import json
from pathlib import Path

from app.core.models import Category, Severity
from app.scanners.lint import parse_eslint, parse_flake8, parse_ruff, python_severity
from app.scanners.quality import parse_junit, parse_lizard_csv, parse_mypy, parse_radon_cc
from app.scanners.security import parse_bandit, parse_gitleaks, parse_semgrep, parse_trivy

ROOT = Path("/proj")


def test_python_severity_separates_bugs_from_style():
    assert python_severity("F821") == Severity.HIGH          # undefined name
    assert python_severity(None) == Severity.HIGH            # syntax error (newer ruff)
    assert python_severity("E999") == Severity.HIGH
    assert python_severity("B006") == Severity.MEDIUM        # bugbear
    assert python_severity("F401") == Severity.LOW           # unused import
    assert python_severity("E501") == Severity.INFO          # line too long
    assert python_severity("W291") == Severity.INFO


def test_parse_ruff_keeps_rule_codes_and_relative_paths():
    out = json.dumps([
        {"code": "F821", "message": "Undefined name `x`", "filename": "/proj/src/a.py",
         "location": {"row": 3, "column": 5}, "end_location": {"row": 3, "column": 6}, "fix": None, "url": "https://docs"},
        {"code": None, "message": "SyntaxError: invalid syntax", "filename": "/proj/b.py",
         "location": {"row": 1, "column": 1}, "end_location": {"row": 1, "column": 2}, "fix": None, "url": None},
    ])
    findings = parse_ruff(out, ROOT)
    assert [f.rule_id for f in findings] == ["F821", "syntax-error"]
    assert findings[0].file_path == "src/a.py" and findings[0].line == 3
    assert all(f.severity == Severity.HIGH for f in findings)


def test_parse_flake8_handles_windows_drive_letters():
    # The old parser split on ":" and broke on C:\ paths.
    out = "C:\\proj\\a.py\t12\t1\tF401\t'os' imported but unused\n"
    [f] = parse_flake8(out, Path("C:/proj"))
    assert f.line == 12 and f.rule_id == "F401" and f.severity == Severity.LOW


SEMGREP = {
    "results": [
        {"check_id": "python.lang.security.audit.formatted-sql-query", "path": "app.py",
         "start": {"line": 12, "col": 5}, "end": {"line": 12, "col": 60},
         "extra": {"message": "SQL built with string formatting", "severity": "ERROR", "lines": "requires login",
                   "metadata": {"confidence": "HIGH", "cwe": ["CWE-89"]}}},
        {"check_id": "python.lang.noisy-rule", "path": "app.py", "start": {"line": 3}, "end": {"line": 3},
         "extra": {"message": "noisy", "severity": "WARNING", "lines": "x", "metadata": {"confidence": "LOW"}}},
        {"check_id": "generic.secrets.security.detected-aws-key", "path": "cfg.py", "start": {"line": 1}, "end": {"line": 1},
         "extra": {"message": "AWS key", "severity": "ERROR", "lines": 'k = "AKIAIOSFODNN7EXAMPLE"', "metadata": {}}},
    ]
}


def test_parse_semgrep_drops_low_confidence_and_reads_real_code(tmp_path):
    (tmp_path / "app.py").write_text("\n" * 11 + "    cur.execute('SELECT * FROM t WHERE id=%s' % uid)\n")
    findings = parse_semgrep(json.dumps(SEMGREP), tmp_path, drop_low_confidence=True)
    assert len(findings) == 2
    sql = findings[0]
    assert sql.category == Category.SAST and sql.severity == Severity.HIGH
    assert "requires login" not in sql.code_snippet and "cur.execute" in sql.code_snippet
    secret = findings[1]
    assert secret.category == Category.SECRETS and "AKIAIOSFODNN7EXAMPLE" not in secret.code_snippet


def test_parse_semgrep_downgrades_low_confidence_when_kept():
    findings = parse_semgrep(json.dumps(SEMGREP), ROOT, drop_low_confidence=False)
    noisy = [f for f in findings if f.rule_id == "python.lang.noisy-rule"][0]
    assert noisy.severity == Severity.LOW


def test_parse_bandit():
    out = json.dumps({"results": [
        {"filename": "/proj/a.py", "line_number": 7, "line_range": [7], "test_id": "B602", "test_name": "subprocess_popen_with_shell_equals_true",
         "issue_severity": "HIGH", "issue_confidence": "HIGH", "issue_text": "shell=True", "issue_cwe": {"id": 78}, "more_info": "https://b"},
        {"filename": "/proj/a.py", "line_number": 9, "test_id": "B105", "test_name": "hardcoded_password_string",
         "issue_severity": "LOW", "issue_confidence": "LOW", "issue_text": "maybe"},
    ]})
    [f] = parse_bandit(out, ROOT)
    assert f.rule_id.startswith("B602") and f.severity == Severity.HIGH and f.extra["cwe"] == "CWE-78"


def test_parse_gitleaks_masks_and_downgrades_test_data():
    out = json.dumps([
        {"RuleID": "aws-access-token", "Description": "AWS key", "File": "src/cfg.py", "StartLine": 4,
         "Match": 'key = "AKIAIOSFODNN7EXAMPLE"', "Secret": "AKIAIOSFODNN7EXAMPLE"},
        {"RuleID": "generic-api-key", "Description": "Generic key", "File": "tests/test_x.py", "StartLine": 2,
         "Match": 'k = "abcdef1234567890ab"', "Secret": "abcdef1234567890ab"},
    ])
    real, test = parse_gitleaks(out, ROOT, ["tests"])
    assert real.severity == Severity.HIGH and "AKIAIOSFODNN7EXAMPLE" not in real.code_snippet
    assert test.severity == Severity.LOW and test.extra["test_data"]


def test_parse_trivy_finds_manifest_line(tmp_path):
    (tmp_path / "requirements.txt").write_text("flask==2.0\nrequests==2.19.0\n")
    out = json.dumps({"Results": [{"Target": "requirements.txt", "Vulnerabilities": [
        {"VulnerabilityID": "CVE-2018-18074", "PkgName": "requests", "InstalledVersion": "2.19.0",
         "FixedVersion": "2.20.0", "Severity": "HIGH", "Title": "Credential leak"}]}]})
    [f] = parse_trivy(out, tmp_path)
    assert f.category == Category.DEPENDENCIES and f.line == 2 and "upgrade to 2.20.0" in f.message


def test_parse_mypy():
    out = "app.py:21:23: error: Name \"itemz\" is not defined  [name-defined]\napp.py:3: note: see docs\n"
    [f] = parse_mypy(out, ROOT)
    assert f.rule_id == "name-defined" and f.line == 21 and f.column == 23


def test_parse_radon_skips_classes_and_errors():
    out = json.dumps({"a.py": [
        {"type": "class", "name": "C", "complexity": 30, "lineno": 1, "endline": 90},
        {"type": "method", "name": "m", "classname": "C", "complexity": 18, "lineno": 2, "endline": 40}],
        "bad.py": {"error": "invalid syntax"}})
    [fn] = parse_radon_cc(out, ROOT)
    assert fn["name"] == "C.m" and fn["ccn"] == 18 and fn["length"] == 39


def test_parse_lizard_csv():
    out = '12,27,80,1,40,"grade@24-63@./app.py","./app.py","grade","grade( score )",24,63\n'
    [fn] = parse_lizard_csv(out, ROOT)
    assert fn["ccn"] == 27 and fn["start"] == 24 and fn["file"] == "app.py"


def test_parse_eslint_marks_bug_rules_high():
    out = json.dumps([{"filePath": "/proj/a.js", "messages": [
        {"ruleId": "no-undef", "severity": 2, "message": "x is not defined", "line": 3, "column": 1},
        {"ruleId": "semi", "severity": 1, "message": "Missing semicolon", "line": 4, "column": 9}]}])
    bug, style = parse_eslint(out, ROOT)
    assert bug.severity == Severity.HIGH and style.severity == Severity.LOW


def test_parse_junit():
    xml = """<testsuites><testsuite tests="3" failures="1" errors="0" skipped="1">
      <testcase classname="tests.test_a" name="test_ok" file="tests/test_a.py" line="3"/>
      <testcase classname="tests.test_a" name="test_bad" file="tests/test_a.py" line="9"><failure message="assert 1 == 2">trace</failure></testcase>
      <testcase classname="tests.test_a" name="test_skip"><skipped/></testcase>
    </testsuite></testsuites>"""
    parsed = parse_junit(xml, ROOT)
    assert parsed["totals"]["pass_rate"] == 50.0
    [f] = parsed["failed"]
    assert f.line == 10 and "test_bad" in f.message
