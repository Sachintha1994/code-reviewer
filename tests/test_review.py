"""AI-only review of changed code, with the AI replaced by a fake."""
import re
import subprocess

import pytest

from app.core.ai_review import AIReviewer, build_chunks, parse_json_object, render_chunk
from app.core.diff import SAFE_REF, parse_unified_diff
from app.core.findings import decide_verdict, deduplicate
from app.core.models import Finding, Severity
from app.core.orchestrator import CodeReviewOrchestrator, validate_github_url
from app.core.rescore import rescore
from app.core.storage import Storage
from conftest import ROOT

GIT = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]


def make_repo(tmp_path):
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "Auth.java").write_text("class Auth {\n    String user;\n}\n")
    (repo / "README.md").write_text("docs\n")
    subprocess.run(GIT + ["init", "-q"], cwd=repo, check=True)
    subprocess.run(GIT + ["add", "."], cwd=repo, check=True)
    subprocess.run(GIT + ["commit", "-qm", "init"], cwd=repo, check=True)
    subprocess.run(GIT + ["branch", "-q", "base"], cwd=repo, check=True)
    (repo / "src" / "Auth.java").write_text(
        "class Auth {\n    String user;\n    static final String KEY = \"Zq8vT3kLm9Pw2xR7yB4n\";\n"
        "    boolean check(String p) { return p == KEY; }\n    // reviewer: ignore known\n    int retries = 3;\n}\n")
    (repo / "logo.png").write_bytes(b"\x89PNG")
    (repo / "README.md").write_text("docs\nmore docs\n")
    return repo


def fake_ai(monkeypatch, issues, summary="Adds a password check."):
    monkeypatch.setenv("GROQ_API_KEY", "test")
    calls = []

    def complete_json(self, system, user):
        calls.append(user)
        if '"summary"' in user:
            return {"summary": summary}, False
        return {"issues": issues}, False
    monkeypatch.setattr(AIReviewer, "complete_json", complete_json)
    return calls


ISSUES = [
    {"line": 4, "end_line": 4, "severity": "HIGH", "category": "bug", "title": "Strings compared with ==",
     "explanation": "Reference comparison.", "confidence": 0.9,
     "fix": "    boolean check(String p) { return KEY.equals(p); }"},
    {"line": 3, "severity": "CRITICAL", "category": "security", "title": "Hardcoded key", "confidence": 0.95, "fix": ""},
    {"line": 2, "severity": "HIGH", "category": "bug", "title": "on an unchanged line", "confidence": 0.9},
    {"line": 6, "severity": "LOW", "category": "style", "title": "ignored inline", "confidence": 0.9},
    {"line": 3, "severity": "MEDIUM", "category": "bug", "title": "unsure", "confidence": 0.2},
]


def test_review_of_changed_code(tmp_path, monkeypatch):
    calls = fake_ai(monkeypatch, ISSUES)
    result = CodeReviewOrchestrator(str(make_repo(tmp_path)), base_ref="base").run_full_review()
    titles = {f.title for f in result.findings}
    assert titles == {"Strings compared with ==", "Hardcoded key", "ignored inline"}
    assert result.verdict == "FAIL" and result.verdict_label == "Changes requested"
    assert "Adds a password check." == result.summary
    files = {f.path: f for f in result.files}
    assert files["src/Auth.java"].status == "reviewed"
    assert files["logo.png"].status == "skipped"          # not source
    assert files["README.md"].status == "skipped"         # markdown isn't reviewed
    review_prompt = calls[0]
    assert "Zq8vT3kLm9Pw2xR7yB4n" not in review_prompt    # secrets are masked before sending
    assert "+    4 |" in review_prompt and "     2 |" in review_prompt  # changed lines marked, context unmarked
    fix = next(f for f in result.findings if f.fix)
    assert fix.context == "    boolean check(String p) { return p == KEY; }" and fix.context_start == 4
    inline = next(f for f in result.findings if f.title == "ignored inline")
    assert inline.suppressed and inline.suppressed.startswith("inline")


def test_requires_base_and_ai(tmp_path, monkeypatch):
    repo = make_repo(tmp_path)
    for var in ("GEMINI_API_KEY", "GOOGLE_API_KEY", "GROQ_API_KEY", "OPENAI_API_KEY", "LLM_API_KEY", "LLM_PROVIDER", "LLM_BASE_URL"):
        monkeypatch.delenv(var, raising=False)
    with pytest.raises(ValueError, match="GEMINI_API_KEY"):
        CodeReviewOrchestrator(str(repo), base_ref="base").run_full_review()
    fake_ai(monkeypatch, [])
    with pytest.raises(ValueError, match="branch"):
        CodeReviewOrchestrator(str(repo), base_ref="").run_full_review()
    with pytest.raises(ValueError, match="can't compare"):
        CodeReviewOrchestrator(str(repo), base_ref="nope").run_full_review()


def test_no_issues_passes(tmp_path, monkeypatch):
    fake_ai(monkeypatch, [])
    result = CodeReviewOrchestrator(str(make_repo(tmp_path)), base_ref="base").run_full_review()
    assert result.verdict == "PASS" and result.verdict_label == "Looks good"


def test_ai_failure_on_every_file_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test")

    def boom(self, system, user):
        raise RuntimeError("401 invalid api key")
    monkeypatch.setattr(AIReviewer, "complete_json", boom)
    with pytest.raises(RuntimeError, match="invalid api key"):
        CodeReviewOrchestrator(str(make_repo(tmp_path)), base_ref="base").run_full_review()


def test_build_chunks_whole_file_and_windows():
    assert build_chunks(50, {10}, 400, 25, 600) == [list(range(1, 51))]
    chunks = build_chunks(2000, {100, 110, 1500}, 400, 10, 600)
    flat = [n for c in chunks for n in c]
    assert 90 in flat and 120 in flat and 1490 in flat and 1510 in flat and 500 not in flat
    big = build_chunks(5000, set(range(1000, 2500)), 400, 25, 600)
    assert all(len(c) <= 600 for c in big) and len(big) >= 3


def test_render_chunk_marks_gaps_and_changes():
    text = render_chunk(["a", "b", "c", "d", "e"], [1, 2, 4, 5], {2})
    assert text.splitlines() == ["     1 | a", "+    2 | b", "   ...", "     4 | d", "     5 | e"]


def test_parse_json_object_handles_fences():
    assert parse_json_object('```json\n{"issues": []}\n```') == {"issues": []}
    assert parse_json_object('Here you go: {"a": 1} thanks') == {"a": 1}


def F(**kw):
    base = dict(file_path="a.java", line=1, severity=Severity.LOW, category="bug", title="t", confidence=0.8)
    base.update(kw)
    return Finding(**base)


def test_dedup_keeps_neighbouring_different_issues():
    kept = deduplicate([F(line=14, title="NPE"), F(line=15, title="== compare", severity=Severity.HIGH),
                        F(line=15, title="== compare", severity=Severity.HIGH)])
    assert sorted(f.line for f in kept) == [14, 15]


def test_verdict_levels():
    assert decide_verdict([F(severity=Severity.CRITICAL)])[0] == "FAIL"
    assert decide_verdict([F(severity=Severity.MEDIUM)])[1] == "Approve with comments"
    assert decide_verdict([F(severity=Severity.LOW)])[0] == "PASS"
    assert decide_verdict([F(severity=Severity.HIGH, suppressed="ignored")])[0] == "PASS"


def test_storage_and_rescore(tmp_path, monkeypatch):
    fake_ai(monkeypatch, ISSUES)
    repo = make_repo(tmp_path)
    st = Storage(tmp_path / "db.sqlite")
    p = st.add_project({"name": "Demo", "source_type": "local", "path_or_url": str(repo), "base_ref": "base"})
    sid = st.start_scan(p["id"])
    result = CodeReviewOrchestrator(str(repo), base_ref="base").run_full_review().to_dict()
    st.finish_scan(sid, result)
    assert st.latest_scan(p["id"])["verdict"] == "FAIL"
    for f in result["findings"]:
        if f["severity"] in ("HIGH", "CRITICAL"):
            st.add_suppression(p["id"], f["fingerprint"], "false_positive", "")
    updated = rescore(result, st.suppressions(p["id"]))
    assert updated["verdict"] == "PASS" and updated["stats"]["ignored"] == 3
    st.remove_suppression(p["id"], result["findings"][0]["fingerprint"])
    assert rescore(updated, st.suppressions(p["id"]))["verdict"] == "FAIL"


def test_diff_parsing_and_ref_safety():
    info = parse_unified_diff("diff --git a/x.py b/x.py\n--- a/x.py\n+++ b/x.py\n@@ -1,0 +2,1 @@\n+new\n", "main")
    assert info.added == {"x.py": {2: "new"}}
    assert SAFE_REF.match("pm-dev") and not SAFE_REF.match("--output=x")


def test_github_url_validation():
    assert validate_github_url("https://github.com/owner/repo")
    for bad in ["file:///etc/passwd", "--upload-pack=x", "https://evil.com/a/b"]:
        with pytest.raises(ValueError):
            validate_github_url(bad)


WEB = ROOT / "app" / "web"


def test_page_assets_exist_and_no_cdn_scripts():
    from jinja2 import Environment, FileSystemLoader

    html = Environment(loader=FileSystemLoader(str(WEB / "templates")), autoescape=True).get_template(
        "index.html").render(url_for=lambda name, path: f"/static/{path}", version="t")
    assert '<script src="https://' not in html
    for ref in re.findall(r"/static/([\w/.-]+)", html):
        assert (WEB / "static" / ref).is_file(), ref
    used = set(re.findall(r'href="#i-([\w-]+)"', html)) | set(re.findall(r"icon\('([\w-]+)'", (WEB / "static/js/app.js").read_text()))
    defined = set(re.findall(r'<symbol id="i-([\w-]+)"', html))
    assert used <= defined, used - defined


def test_review_text_is_never_inserted_as_html():
    js = (WEB / "static" / "js" / "app.js").read_text()
    uses = [line.strip() for line in js.splitlines() if "innerHTML" in line and not line.strip().startswith(("//", "*", "/*"))]
    assert uses == ["if (html !== null) code.innerHTML = html; // highlight.js output is escaped"]


def test_gemini_is_picked_from_its_key(monkeypatch):
    for var in ("GROQ_API_KEY", "OPENAI_API_KEY", "LLM_API_KEY", "LLM_PROVIDER", "LLM_BASE_URL", "LLM_MODEL", "GOOGLE_API_KEY"):
        monkeypatch.delenv(var, raising=False)
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    r = AIReviewer({"ai": {}})
    assert (r.provider, r.model, r.api_key) == ("gemini", "gemini-3.8-flash", "g-key")
    assert r.base_url.startswith("https://generativelanguage.googleapis.com/")
    assert AIReviewer({"ai": {"model": "gemini-3.8-pro"}}).model == "gemini-3.8-pro"


def test_json_mode_falls_back_when_rejected(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g-key")
    r = AIReviewer({"ai": {}})
    seen = []

    class Err(Exception):
        status_code = 400

    class Completions:
        def create(self, **kw):
            seen.append("response_format" in kw)
            if "response_format" in kw:
                raise Err("Invalid argument")
            msg = type("M", (), {"content": '{"issues": []}'})
            return type("R", (), {"choices": [type("C", (), {"message": msg})]})

    r._client = type("Client", (), {"chat": type("Chat", (), {"completions": Completions()})})
    assert r.complete_json("s", "u") == ({"issues": []}, False)
    assert r.complete_json("s", "u2")[0] == {"issues": []}
    assert seen == [True, False, False]   # JSON mode is tried once, then skipped
