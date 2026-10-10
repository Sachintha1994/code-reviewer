"""Java support: Maven build/tests/coverage, PMD, and turning scanners off."""
import json
import os
import stat
import textwrap

import pytest

from app.config import load_config
from app.core.models import Category, ScanStatus, Severity
from app.scanners.base import ScanContext
from app.scanners.java import MavenScanner, parse_maven_errors, parse_pmd, pmd_severity
from app.scanners.quality import TypeCheckScanner
from app.scanners.security import TrivyScanner


def ctx_for(root, files, langs=("java",), changed=None, cfg=None):
    return ScanContext(root=root, config=cfg or load_config(), files=list(files), languages=list(langs), changed_lines=changed)


def test_parse_maven_errors_handles_windows_paths_and_duplicates(tmp_path):
    out = textwrap.dedent(f"""
        [ERROR] /C:/proj/src/main/java/a/Foo.java:[12,8] cannot find symbol
        [ERROR] /C:/proj/src/main/java/a/Foo.java:[12,8] cannot find symbol
        [ERROR] {tmp_path}/src/main/java/a/Bar.java:[3] ';' expected
        [INFO] BUILD FAILURE
    """)
    errors = parse_maven_errors(out, tmp_path)
    assert len(errors) == 2
    assert errors[0].file_path == "C:/proj/src/main/java/a/Foo.java" and errors[0].line == 12
    assert errors[1].file_path == "src/main/java/a/Bar.java" and errors[1].severity == Severity.CRITICAL


def test_pmd_parsing_and_severity():
    out = json.dumps({"files": [{"filename": "/proj/src/A.java", "violations": [
        {"beginline": 5, "begincolumn": 3, "endline": 5, "description": "Avoid empty catch blocks", "rule": "EmptyCatchBlock",
         "ruleset": "Error Prone", "priority": 3, "externalInfoUrl": "https://pmd"},
        {"beginline": 9, "description": "Unused import", "rule": "UnnecessaryImport", "ruleset": "Code Style", "priority": 4}]}]})
    from pathlib import Path
    a, b = parse_pmd(out, Path("/proj"))
    assert a.file_path == "src/A.java" and a.severity == Severity.MEDIUM and a.category == Category.LINT
    assert b.severity == Severity.INFO
    assert pmd_severity(1, "Best Practices") == Severity.HIGH


def test_disabled_scanner_is_not_run(tmp_path):
    cfg = load_config(overrides={"disabled_scanners": ["Trivy"]})
    result = TrivyScanner().run(ctx_for(tmp_path, [], cfg=cfg))
    assert result.status == ScanStatus.SKIPPED and result.not_applicable and "turned off" in result.message


def test_mypy_explains_java():
    result = TypeCheckScanner().run(ctx_for(None, []))
    assert result.not_applicable and "compiler" in result.message


FAKE_MVNW = r'''#!/bin/sh
mkdir -p target/surefire-reports target/site/jacoco
cat > target/surefire-reports/TEST-a.FooTest.xml <<'XML'
<testsuite name="a.FooTest" tests="3" failures="1" errors="0" skipped="0">
  <testcase classname="a.FooTest" name="ok1"/>
  <testcase classname="a.FooTest" name="ok2"/>
  <testcase classname="a.FooTest" name="adds"><failure message="expected 5 but was 4">org.opentest4j.AssertionFailedError
	at a.FooTest.adds(FooTest.java:17)</failure></testcase>
</testsuite>
XML
cat > target/site/jacoco/jacoco.xml <<'XML'
<?xml version="1.0" encoding="UTF-8"?><report name="demo">
  <package name="a"><sourcefile name="Foo.java">
    <line nr="3" mi="0" ci="2" mb="0" cb="0"/><line nr="4" mi="2" ci="0" mb="0" cb="0"/>
  </sourcefile></package>
  <counter type="LINE" missed="1" covered="3"/>
</report>
XML
echo "[INFO] BUILD SUCCESS"
'''


@pytest.mark.skipif(os.name == "nt", reason="fake mvnw is a shell script")
def test_maven_scanner_reads_tests_and_coverage(tmp_path):
    (tmp_path / "pom.xml").write_text("<project/>")
    wrapper = tmp_path / "mvnw"
    wrapper.write_text(FAKE_MVNW)
    wrapper.chmod(wrapper.stat().st_mode | stat.S_IEXEC)
    files = ["pom.xml", "src/main/java/a/Foo.java", "src/test/java/a/FooTest.java"]
    result = MavenScanner().run(ctx_for(tmp_path, files, changed={"src/main/java/a/Foo.java": {3, 4}}))
    assert result.status == ScanStatus.RAN, result.message
    assert result.metrics["tests"] == 3 and result.metrics["pass_rate"] == pytest.approx(66.7)
    assert result.metrics["coverage_overall"] == 75.0 and result.metrics["coverage_new"] == 50.0
    [failed] = result.findings
    assert failed.file_path == "src/test/java/a/FooTest.java" and failed.line == 17


def test_maven_not_applicable_without_pom(tmp_path):
    result = MavenScanner().run(ctx_for(tmp_path, ["A.java"]))
    assert result.not_applicable and "pom.xml" in result.message
