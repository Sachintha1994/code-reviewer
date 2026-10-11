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


def test_whole_project_review_without_base(tmp_path, monkeypatch):
    calls = fake_ai(monkeypatch, [
        {"line": 2, "severity": "MEDIUM", "category": "bug", "title": "Field never set", "confidence": 0.8},
    ])
    repo = tmp_path / "plain"          # not a git repository
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "A.java").write_text("class A {\n    String user;\n}\n")
    (repo / "node_modules").mkdir()
    (repo / "node_modules" / "x.js").write_text("var a = 1;\n")
    (repo / "notes.md").write_text("hello\n")
    result = CodeReviewOrchestrator(str(repo), base_ref="").run_full_review()
    assert result.base_ref == "" and result.stats["scope"] == "project"
    assert [f.path for f in result.files] == ["src/A.java"]           # excluded and non-source files left out
    assert [f.title for f in result.findings] == ["Field never set"]   # every line is in scope
    assert result.verdict == "WARN"
    assert "Whole-file review" in calls[0] and "+    1 | class A {" in calls[0]
    assert "whole project" in calls[-1]


# ------------------------------------------------------------------ ZIP uploads
import zipfile  # noqa: E402

from app.core.uploads import UploadError, extract_zip  # noqa: E402


def make_zip(path, files, symlink=None):
    with zipfile.ZipFile(path, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
        if symlink:
            info = zipfile.ZipInfo(symlink)
            info.external_attr = (0o120777 << 16)
            z.writestr(info, "/etc/passwd")
    return path


def test_zip_with_single_top_folder_becomes_the_root(tmp_path):
    z = make_zip(tmp_path / "a.zip", {"my-app/src/A.java": "class A {}\n", "my-app/pom.xml": "<project/>\n",
                                      "__MACOSX/._A.java": "junk"}, symlink="my-app/link")
    root = extract_zip(z, tmp_path / "out", {})
    assert root.name == "my-app"
    assert (root / "src" / "A.java").read_text() == "class A {}\n"
    assert not (root / "link").exists() and not (tmp_path / "out" / "__MACOSX").exists()


@pytest.mark.parametrize("name", ["../evil.py", "a/../../evil.py", "/etc/evil", "C:/evil.py"])
def test_zip_slip_is_refused(tmp_path, name):
    z = make_zip(tmp_path / "bad.zip", {"ok.py": "x = 1\n", name: "boom"})
    with pytest.raises(UploadError):
        extract_zip(z, tmp_path / "out", {})
    assert not (tmp_path / "evil.py").exists()


def test_zip_limits(tmp_path):
    z = make_zip(tmp_path / "big.zip", {f"f{i}.py": "x" for i in range(5)})
    with pytest.raises(UploadError, match="more than 3 files"):
        extract_zip(z, tmp_path / "out", {"uploads": {"max_files": 3}})
    bomb = make_zip(tmp_path / "bomb.zip", {"a.txt": "0" * (3 * 1024 * 1024)})
    with pytest.raises(UploadError, match="MB"):
        extract_zip(bomb, tmp_path / "out2", {"uploads": {"max_unzipped_mb": 1}})
    (tmp_path / "not.zip").write_bytes(b"hello")
    with pytest.raises(UploadError, match="valid ZIP"):
        extract_zip(tmp_path / "not.zip", tmp_path / "out3", {})


def test_review_of_an_unzipped_project(tmp_path, monkeypatch):
    fake_ai(monkeypatch, [{"line": 1, "severity": "HIGH", "category": "bug", "title": "Empty class", "confidence": 0.9}])
    root = extract_zip(make_zip(tmp_path / "a.zip", {"app/A.java": "class A {}\n"}), tmp_path / "out", {})
    result = CodeReviewOrchestrator(str(root), base_ref="").run_full_review()
    assert [f.path for f in result.files] == ["A.java"] and result.verdict == "FAIL"



def test_zip_keeps_only_reviewable_files(tmp_path):
    long_name = "target/classes/lk/" + "x" * 150 + "/Builder$Inner$Deep.class"
    z = make_zip(tmp_path / "app.zip", {"svc/src/A.java": "class A {}\n", f"svc/{long_name}": "bin",
                                        "svc/node_modules/x/i.js": "1", "svc/reviewer.yml": "ai: {}\n"})
    from app.core.files import is_excluded, language_of
    keep = lambda rel: rel.endswith("reviewer.yml") or (bool(language_of(rel)) and not is_excluded(rel, ["target", "node_modules"]))  # noqa: E731
    root = extract_zip(z, tmp_path / "out", {}, keep)
    files = sorted(p.relative_to(root).as_posix() for p in root.rglob("*") if p.is_file())
    assert files == ["reviewer.yml", "src/A.java"]
    with pytest.raises(UploadError, match="no source files"):
        extract_zip(make_zip(tmp_path / "bin.zip", {"a/b.class": "x"}), tmp_path / "out2", {}, keep)


# ------------------------------------------------------------- batching and quotas
from app.core.ai_review import QuotaExhausted, parse_retry_seconds  # noqa: E402


def make_project(tmp_path, count, lines=3):
    repo = tmp_path / "many"
    (repo / "src").mkdir(parents=True)
    for i in range(count):
        body = "\n".join(f"    int f{j} = {j};" for j in range(lines))
        (repo / "src" / f"C{i:03}.java").write_text(f"class C{i:03} {{\n{body}\n}}\n")
    return repo


def test_small_files_are_packed_into_few_requests(tmp_path, monkeypatch):
    calls = fake_ai(monkeypatch, [])
    repo = make_project(tmp_path, 120)
    result = CodeReviewOrchestrator(str(repo), base_ref="", config_overrides={"ai": {"summary": False}}).run_full_review()
    assert result.stats["files_reviewed"] == 120 and result.stats["files_skipped"] == 0
    assert result.stats["requests"] == len(calls) == 3        # 40 files per request at most
    assert "### File: src/C000.java" in calls[0] and "### File: src/C039.java" in calls[0]


def test_issues_are_matched_to_their_file_in_a_batch(tmp_path, monkeypatch):
    fake_ai(monkeypatch, [
        {"file": "src/C001.java", "line": 2, "severity": "HIGH", "category": "bug", "title": "in one", "confidence": 0.9},
        {"file": "C002.java", "line": 3, "severity": "LOW", "category": "bug", "title": "in two", "confidence": 0.9},
        {"file": "elsewhere.java", "line": 2, "severity": "HIGH", "category": "bug", "title": "unknown", "confidence": 0.9},
    ])
    result = CodeReviewOrchestrator(str(make_project(tmp_path, 3)), base_ref="").run_full_review()
    assert {(f.file_path, f.title) for f in result.findings} == {("src/C001.java", "in one"), ("src/C002.java", "in two")}
    assert result.stats["requests"] == 1


def test_large_file_is_split_across_requests(tmp_path, monkeypatch):
    calls = fake_ai(monkeypatch, [])
    repo = make_project(tmp_path, 1, lines=1200)
    cfg = {"ai": {"summary": False, "max_lines_per_request": 500, "whole_file_up_to": 400}}
    result = CodeReviewOrchestrator(str(repo), base_ref="", config_overrides=cfg).run_full_review()
    assert len(calls) == result.stats["requests"] >= 3
    assert "part 1 of" in calls[0]
    assert result.files[0].status == "reviewed"


def test_parse_retry_seconds():
    assert parse_retry_seconds("Please retry in 22h3m18.4s.") == pytest.approx(22 * 3600 + 3 * 60 + 18.4)
    assert parse_retry_seconds("Please retry in 25.3s") == pytest.approx(25.3)
    assert parse_retry_seconds("'retryDelay': '41s'") == 41
    assert parse_retry_seconds("nothing here") is None


def test_quota_stops_the_review_and_keeps_partial_results(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test")
    seen = []

    def complete_json(self, system, user):
        seen.append(user)
        if len(seen) > 1:
            raise QuotaExhausted("groq quota used up; it resets in about 22 hours.")
        return {"issues": [{"file": "src/C000.java", "line": 2, "severity": "MEDIUM", "category": "bug",
                            "title": "found", "confidence": 0.9}]}, False
    monkeypatch.setattr(AIReviewer, "complete_json", complete_json)
    cfg = {"ai": {"max_workers": 1, "max_lines_per_request": 50}}
    result = CodeReviewOrchestrator(str(make_project(tmp_path, 30)), base_ref="", config_overrides=cfg).run_full_review()
    statuses = [f.status for f in result.files]
    assert statuses.count("reviewed") > 0 and statuses.count("skipped") > 0 and "error" not in statuses
    assert all(f.message.startswith("AI quota") for f in result.files if f.status == "skipped")
    assert [f.title for f in result.findings] == ["found"]
    assert "partial review" in result.verdict_reason
    assert len(seen) == 2                                      # stopped instead of failing every remaining request


def test_quota_on_the_first_request_is_an_error(tmp_path, monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test")

    def complete_json(self, system, user):
        raise QuotaExhausted("gemini quota used up; it resets in about 22 hours.")
    monkeypatch.setattr(AIReviewer, "complete_json", complete_json)
    with pytest.raises(RuntimeError, match="resets in about 22 hours"):
        CodeReviewOrchestrator(str(make_project(tmp_path, 2)), base_ref="").run_full_review()


def fake_client(replies):
    class Completions:
        def create(self, **kw):
            reply = replies.pop(0)
            if isinstance(reply, Exception):
                raise reply
            msg = type("M", (), {"content": reply})
            return type("R", (), {"choices": [type("C", (), {"message": msg})]})
    return type("Client", (), {"chat": type("Chat", (), {"completions": Completions()})})


class RateLimit(Exception):
    status_code = 429


def test_invalid_json_is_retried_once(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "test")
    r = AIReviewer({"ai": {}})
    replies = ['{"issues": [ broken', '{"issues": []}']
    r._client = fake_client(replies)
    assert r.complete_json("s", "u") == ({"issues": []}, False)
    assert replies == []


def test_short_rate_limit_waits_and_daily_limit_stops(monkeypatch):
    monkeypatch.setenv("GEMINI_API_KEY", "g")
    slept = []
    monkeypatch.setattr("app.core.ai_review.time.sleep", lambda s: slept.append(s))
    r = AIReviewer({"ai": {}})
    r._json_mode = False
    r._client = fake_client([RateLimit("429 Please retry in 12s"), '{"issues": []}'])
    assert r.complete_json("s", "a")[0] == {"issues": []} and slept == [12]
    r._client = fake_client([RateLimit("429 Quota exceeded, limit: 20. Please retry in 22h3m1s")])
    with pytest.raises(QuotaExhausted, match="about 22 hours"):
        r.complete_json("s", "b")
