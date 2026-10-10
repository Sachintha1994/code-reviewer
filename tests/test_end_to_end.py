"""Full runs on the sample project, storage, re-scoring and the web page assets."""
import re
import shutil
import subprocess

import pytest

from app.core.orchestrator import CodeReviewOrchestrator, validate_github_url
from app.core.rescore import rescore
from app.core.storage import Storage
from app.scanners.security import builtin_secret_scan
from conftest import FIXTURE, ROOT


def run(path, **kw):
    return CodeReviewOrchestrator(str(path), use_ai=False, **kw).run_full_review()


def test_builtin_secret_patterns():
    findings = builtin_secret_scan(FIXTURE, ["app.py", "tests/test_app.py"], ["tests"])
    by_line = {(f.file_path, f.line): f for f in findings}
    assert ("app.py", 6) in by_line                      # high-entropy password
    assert ("app.py", 7) not in by_line                  # os.getenv(..., "changeme") is a placeholder
    assert by_line[("tests/test_app.py", 3)].severity.value == "LOW"   # test data
    assert all("Xk9#mP2vL8qR4tZ7wN3s" not in (f.code_snippet or "") for f in findings)


def test_full_review_of_sample_project():
    result = run(FIXTURE)
    gates = {g.key: g for g in result.gates}
    assert result.verdict == "FAIL"
    assert gates["secrets"].status.value == "failed"
    assert gates["lint"].status.value == "failed"
    assert gates["build"].status.value == "passed"
    # missing tools show as skipped with a reason, never as passed
    for scan in result.scans:
        if scan.status.value == "skipped" and not scan.not_applicable:
            assert scan.message
    undefined = [f for f in result.findings if f.rule_id == "F821"]
    assert len(undefined) == 1
    suppressed = [f for f in result.findings if f.suppressed]
    assert suppressed and suppressed[0].line == 65       # reviewer: ignore[secrets] comment
    assert result.health["score"] <= 69                  # FAIL caps the score
    data = result.to_dict()
    assert all("findings" not in s for s in data["scans"])


def test_review_only_changed_code(tmp_path):
    repo = tmp_path / "repo"
    shutil.copytree(FIXTURE, repo)
    git = ["git", "-c", "user.email=t@t", "-c", "user.name=t"]
    subprocess.run(git + ["init", "-q"], cwd=repo, check=True)
    subprocess.run(git + ["add", "."], cwd=repo, check=True)
    subprocess.run(git + ["commit", "-qm", "init"], cwd=repo, check=True)
    with open(repo / "app.py", "a") as fh:
        fh.write("\n\ndef fee(x: int) -> int:\n    print(x)  # TODO\n    return x + missing_name\n")
    result = run(repo, base_ref="HEAD")
    files_lines = {(f.file_path, f.rule_id) for f in result.findings}
    assert ("app.py", "F821") in files_lines
    assert all(f.line > 65 for f in result.findings if f.file_path == "app.py")   # old issues left out
    gates = {g.key: g for g in result.gates}
    assert gates["debug_leftovers"].status.value == "failed"
    assert gates["tests_with_source"].status.value == "failed"
    with pytest.raises(ValueError):
        run(repo, base_ref="does-not-exist")


def test_storage_and_rescore(tmp_path):
    st = Storage(tmp_path / "db.sqlite")
    p = st.add_project({"name": "Demo", "source_type": "local", "path_or_url": str(FIXTURE)})
    sid = st.start_scan(p["id"])
    result = run(FIXTURE).to_dict()
    st.finish_scan(sid, result)
    assert st.latest_scan(p["id"])["verdict"] == "FAIL"
    # mark the secret as a false positive: the secrets gate should pass afterwards
    secret = next(f for f in result["findings"] if f["category"] == "secrets" and not f["suppressed"] and f["severity"] == "HIGH")
    st.add_suppression(p["id"], secret["fingerprint"], "false_positive", "test value")
    updated = rescore(result, st.suppressions(p["id"]), st.baseline(p["id"]), str(FIXTURE))
    gates = {g["key"]: g for g in updated["gates"]}
    assert gates["secrets"]["status"] == "passed"
    assert "Secrets" not in updated["verdict_reason"]
    # a baseline of everything leaves nothing counted
    st.set_baseline(p["id"], {f["fingerprint"] for f in result["findings"]})
    based = rescore(result, {}, st.baseline(p["id"]), str(FIXTURE))
    assert based["stats"]["findings_counted"] == 0
    st.delete_project(p["id"])
    assert st.get_project(p["id"]) is None


def test_github_url_validation():
    assert validate_github_url("https://github.com/owner/repo") == "https://github.com/owner/repo"
    for bad in ["file:///etc/passwd", "https://github.com/owner", "--upload-pack=x", "https://evil.com/a/b", "ext::sh -c x"]:
        with pytest.raises(ValueError):
            validate_github_url(bad)


WEB = ROOT / "app" / "web"


def test_page_has_no_cdn_scripts_and_renders():
    from jinja2 import Environment, FileSystemLoader

    env = Environment(loader=FileSystemLoader(str(WEB / "templates")), autoescape=True)
    html = env.get_template("index.html").render(url_for=lambda name, path: f"/static/{path}", version="t")
    assert "<script src=\"https://" not in html
    for ref in re.findall(r'/static/([\w/.-]+)', html):
        assert (WEB / "static" / ref).is_file(), ref


def test_scan_text_is_never_inserted_as_html():
    js = (WEB / "static" / "js" / "app.js").read_text()
    uses = [line.strip() for line in js.splitlines() if "innerHTML" in line and not line.strip().startswith(("//", "*", "/*"))]
    assert uses == ["if (html !== null) code.innerHTML = html; // highlight.js output is escaped"]
