"""API tests. Run where FastAPI is installed (skipped otherwise)."""
import subprocess

import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("REVIEWER_DATA_DIR", str(tmp_path / "data"))
    monkeypatch.setenv("REVIEWER_ALLOWED_ROOTS", str(tmp_path))
    import importlib

    import app.config
    import app.core.storage
    import app.web_dashboard

    importlib.reload(app.config)
    importlib.reload(app.core.storage)
    web = importlib.reload(app.web_dashboard)
    from fastapi.testclient import TestClient

    return TestClient(web.app)


def test_index_and_static(client):
    assert "AI Code Reviewer" in client.get("/").text
    assert client.get("/static/js/app.js").status_code == 200


def test_project_validation(client, tmp_path):
    plain = tmp_path / "plain"
    plain.mkdir()
    not_git = client.post("/api/projects", json={"name": "x", "source_type": "local", "path_or_url": str(plain), "base_ref": "main"})
    assert not_git.status_code == 400 and "git" in not_git.json()["detail"]
    whole = client.post("/api/projects", json={"name": "x", "source_type": "local", "path_or_url": str(plain)})
    assert whole.status_code == 201 and whole.json()["base_ref"] == ""   # no branch: whole-project reviews
    bad_url = client.post("/api/projects", json={"name": "x", "source_type": "github", "path_or_url": "https://evil.com/a/b", "base_ref": "main"})
    assert bad_url.status_code == 400
    bad_ref = client.post("/api/projects", json={"name": "x", "source_type": "local", "path_or_url": str(plain), "base_ref": "--output=x"})
    assert bad_ref.status_code == 422


def test_project_lifecycle(client, tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True)
    created = client.post("/api/projects", json={"name": "Demo", "source_type": "local", "path_or_url": str(repo), "base_ref": "main"})
    assert created.status_code == 201
    pid = created.json()["id"]
    assert client.get(f"/api/projects/{pid}/latest").json() == {"scan": None}
    assert client.patch(f"/api/projects/{pid}", json={"base_ref": "pm-dev"}).json()["base_ref"] == "pm-dev"
    assert client.delete(f"/api/projects/{pid}").status_code == 204


def test_ai_status(client, monkeypatch):
    body = client.get("/api/ai").json()
    assert set(body) >= {"available", "provider", "model", "reason"}


def _zip(files):
    import io
    import zipfile

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        for name, text in files.items():
            z.writestr(name, text)
    return buf.getvalue()


def test_zip_project_upload_and_replace(client):
    pytest.importorskip("multipart")
    files = {"file": ("auth-service.zip", _zip({"auth-service/src/A.java": "class A {}\n"}), "application/zip")}
    created = client.post("/api/projects/zip", data={"name": "Auth"}, files=files)
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["source_type"] == "zip" and body["path_or_url"] == "Uploaded ZIP: auth-service" and body["base_ref"] == ""
    pid = body["id"]
    new = {"file": ("v2.zip", _zip({"v2/src/B.java": "class B {}\n"}), "application/zip")}
    assert client.post(f"/api/projects/{pid}/zip", files=new).json()["path_or_url"] == "Uploaded ZIP: v2"
    bad = client.post("/api/projects/zip", data={"name": "x"}, files={"file": ("a.txt", b"hi", "text/plain")})
    assert bad.status_code == 400
    slip = client.post("/api/projects/zip", data={"name": "x"},
                       files={"file": ("e.zip", _zip({"../evil.py": "x"}), "application/zip")})
    assert slip.status_code == 400 and len(client.get("/api/projects").json()) == 1
    assert client.delete(f"/api/projects/{pid}").status_code == 204


def test_failed_zip_upload_leaves_no_project(client):
    pytest.importorskip("multipart")
    only_binaries = {"file": ("b.zip", _zip({"svc/target/A.class": "bin"}), "application/zip")}
    resp = client.post("/api/projects/zip", data={"name": "x"}, files=only_binaries)
    assert resp.status_code == 400 and "no source files" in resp.json()["detail"]
    assert client.get("/api/projects").json() == []


def test_settings_api(client):
    view = client.get("/api/settings").json()
    assert view["values"]["max_files"] == 1000 and view["customized"] == [] and "gemini" in view["keys"]
    body = {**view["values"], "max_files": 50, "focus": ["only security", "  "], "daily_request_limit": 20}
    saved = client.put("/api/settings", json=body).json()
    assert saved["values"]["max_files"] == 50 and saved["values"]["focus"] == ["only security"]
    assert saved["customized"] == ["daily_request_limit", "focus", "max_files"]   # only what differs is stored
    assert saved["ai"]["daily_request_limit"] == 20
    assert client.put("/api/settings", json={**body, "max_workers": 99}).status_code == 422
    assert client.put("/api/settings", json={**body, "provider": "evil"}).status_code == 422
    assert client.delete("/api/settings").json()["customized"] == []


def test_files_estimate_scan_with_selection_and_exports(client, tmp_path, monkeypatch):
    from app.core.ai_review import AIReviewer

    monkeypatch.setenv("GROQ_API_KEY", "test")
    monkeypatch.setattr(AIReviewer, "complete_json", lambda self, s, u: ({"summary": "ok"} if '"summary"' in u else {"issues": [
        {"file": "src/A.java", "line": 2, "severity": "HIGH", "category": "bug", "title": "Bad", "confidence": 0.9,
         "fix": "    int a = 2;"}]}, False))
    proj = tmp_path / "proj"
    (proj / "src").mkdir(parents=True)
    (proj / "lib").mkdir()
    (proj / "src" / "A.java").write_text("class A {\n    int a = 1;\n}\n")
    (proj / "lib" / "B.java").write_text("class B {\n}\n")
    pid = client.post("/api/projects", json={"name": "P", "source_type": "local", "path_or_url": str(proj),
                                             "rules": "check roles"}).json()["id"]
    files = client.get(f"/api/projects/{pid}/files?whole_project=true").json()["files"]
    assert [f["path"] for f in files] == ["lib/B.java", "src/A.java"]
    est = client.post(f"/api/projects/{pid}/estimate", json={"whole_project": True, "paths": ["src"]}).json()
    assert est["files"] == 1 and est["requests"] == 1
    assert client.post(f"/api/projects/{pid}/estimate", json={"paths": ["../x"]}).status_code == 400
    sid = client.post(f"/api/projects/{pid}/scans", json={"whole_project": True, "paths": ["src"]}).json()["scan_id"]
    scan = client.get(f"/api/scans/{sid}").json()
    assert scan["status"] == "done", scan.get("error")
    assert [f["path"] for f in scan["result"]["files"]] == ["src/A.java"] and scan["result"]["comparison"] is None
    sid2 = client.post(f"/api/projects/{pid}/scans", json={"whole_project": True}).json()["scan_id"]
    second = client.get(f"/api/scans/{sid2}").json()["result"]
    assert second["comparison"]["fixed"] == [] and second["findings"][0]["is_new"] is False
    assert len(client.get(f"/api/projects/{pid}/history").json()) == 2
    csv_resp = client.get(f"/api/scans/{sid2}/export/csv")
    assert csv_resp.status_code == 200 and "Bad" in csv_resp.text and "attachment" in csv_resp.headers["content-disposition"]
    patch = client.get(f"/api/scans/{sid2}/export/patch")
    assert patch.headers["x-fixes-applied"] == "1" and "+    int a = 2;" in patch.text
    assert client.get(f"/api/scans/{sid2}/export/exe").status_code == 404
