"""Diff parsing, git integration and the AI layer (with a fake model)."""
import subprocess

import pytest

from app.core.diff import SAFE_REF, DiffError, collect_diff, parse_unified_diff
from app.core.llm_analyzer import AIReviewer, parse_json_object, parse_triage
from app.core.models import Category, Finding, Severity

DIFF = """diff --git a/a.py b/a.py
index 1..2 100644
--- a/a.py
+++ b/a.py
@@ -3,0 +4,2 @@ def f():
+    x = 1
+    print(x)
@@ -10 +12 @@
-old
+new
diff --git a/gone.py b/gone.py
--- a/gone.py
+++ /dev/null
@@ -1 +0,0 @@
-bye
"""


def test_parse_unified_diff():
    info = parse_unified_diff(DIFF, "main")
    assert info.added["a.py"] == {4: "    x = 1", 5: "    print(x)", 12: "new"}
    assert info.removed_count == 2
    assert info.deleted_files == ["gone.py"]


def test_safe_ref_rejects_option_injection():
    assert SAFE_REF.match("main") and SAFE_REF.match("origin/release-1.2") and SAFE_REF.match("HEAD~3")
    assert not SAFE_REF.match("--output=/tmp/x") and not SAFE_REF.match("main; rm -rf /")


def _git(cwd, *args):
    subprocess.run(["git", "-c", "user.email=t@t", "-c", "user.name=t", *args], cwd=cwd, check=True, capture_output=True)


def test_collect_diff_includes_untracked_files(tmp_path):
    (tmp_path / "a.py").write_text("a = 1\n")
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "add", ".")
    _git(tmp_path, "commit", "-qm", "init")
    (tmp_path / "a.py").write_text("a = 1\nb = 2\n")
    (tmp_path / "new.py").write_text("c = 3\n")
    info = collect_diff(tmp_path, "HEAD")
    assert info.added["a.py"] == {2: "b = 2"}
    assert info.added["new.py"] == {1: "c = 3"}
    with pytest.raises(DiffError):
        collect_diff(tmp_path, "no-such-branch")


def test_parse_json_object_handles_fences_and_noise():
    assert parse_json_object('```json\n{"a": 1}\n```') == {"a": 1}
    assert parse_json_object('Sure! {"verdict": "UNSURE"} hope this helps') == {"verdict": "UNSURE"}


def test_parse_triage_normalises_values():
    r = parse_triage({"verdict": "maybe", "confidence": "7", "severity": "high", "fix": "```python\nx = 1\n```"})
    assert r["verdict"] == "UNSURE" and r["confidence"] == 1.0 and r["severity"] == Severity.HIGH and r["fix"] == "x = 1"


def test_ai_unavailable_without_keys(monkeypatch):
    for var in ("GROQ_API_KEY", "OPENAI_API_KEY", "LLM_API_KEY", "LLM_PROVIDER", "LLM_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    reviewer = AIReviewer({"ai": {"enabled": True}})
    assert not reviewer.available and "GROQ_API_KEY" in reviewer.reason


def _reviewer(monkeypatch, answer):
    monkeypatch.setenv("GROQ_API_KEY", "test-key")
    cache = {}
    reviewer = AIReviewer({"ai": {"enabled": True, "max_workers": 2}}, cache.get, cache.__setitem__)
    calls = []

    def fake(system, user):
        calls.append(user)
        return answer
    reviewer.complete_json = fake
    return reviewer, calls


def test_ai_dismisses_confident_false_positives(monkeypatch, tmp_path):
    (tmp_path / "a.py").write_text("def f():\n    q = 'SELECT 1'\n    cur.execute(q)\n")
    f = Finding(tool="Bandit", rule_id="B608", file_path="a.py", line=3, message="sql", severity=Severity.MEDIUM, category=Category.SAST)
    low = Finding(tool="Ruff", rule_id="F401", file_path="a.py", line=1, message="unused", severity=Severity.LOW)
    reviewer, calls = _reviewer(monkeypatch, {"verdict": "FALSE_POSITIVE", "confidence": 0.92, "severity": "LOW", "explanation": "constant query", "fix": ""})
    metrics = reviewer.triage([f, low], tmp_path)
    assert metrics["selected"] == 1                 # LOW findings aren't sent
    assert f.ai_dismissed and f.ai_verdict == "FALSE_POSITIVE" and f.ai_severity is None
    assert ">>    3 |     cur.execute(q)" in calls[0]  # code context with the flagged line marked


def test_ai_changes_severity_only_when_confident(monkeypatch, tmp_path):
    (tmp_path / "a.py").write_text("x = eval(input())\n")
    sure = Finding(tool="Semgrep", rule_id="eval", file_path="a.py", line=1, message="eval", severity=Severity.MEDIUM, category=Category.SAST)
    reviewer, _ = _reviewer(monkeypatch, {"verdict": "TRUE_POSITIVE", "confidence": 0.9, "severity": "CRITICAL", "explanation": "rce", "fix": "x = int(input())"})
    reviewer.triage([sure], tmp_path)
    assert sure.ai_severity == Severity.CRITICAL and sure.ai_fix == "x = int(input())" and not sure.ai_dismissed
    unsure = Finding(tool="Semgrep", rule_id="eval", file_path="a.py", line=1, message="eval", severity=Severity.MEDIUM, category=Category.SAST)
    reviewer, _ = _reviewer(monkeypatch, {"verdict": "TRUE_POSITIVE", "confidence": 0.5, "severity": "CRITICAL", "explanation": "", "fix": ""})
    reviewer.triage([unsure], tmp_path)
    assert unsure.ai_severity is None


def test_ai_errors_are_reported_not_raised(monkeypatch, tmp_path):
    (tmp_path / "a.py").write_text("x = 1\n")
    f = Finding(tool="Semgrep", rule_id="r", file_path="a.py", line=1, message="m", severity=Severity.HIGH, category=Category.SAST)
    monkeypatch.setenv("GROQ_API_KEY", "k")
    reviewer = AIReviewer({"ai": {}})

    def boom(system, user):
        raise RuntimeError("rate limited")
    reviewer.complete_json = boom
    metrics = reviewer.triage([f], tmp_path)
    assert metrics["analysed"] == 0 and "rate limited" in metrics["errors"][0]
