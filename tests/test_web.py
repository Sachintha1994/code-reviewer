"""API tests. Run where FastAPI is installed (skipped otherwise)."""
import pytest

pytest.importorskip("fastapi")
pytest.importorskip("httpx")


@pytest.fixture()
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("REVIEWER_DATA_DIR", str(tmp_path))
    monkeypatch.setenv("REVIEWER_ALLOWED_ROOTS", str(tmp_path.parent.parent))
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
    page = client.get("/")
    assert page.status_code == 200 and "Code Reviewer" in page.text
    assert client.get("/static/js/app.js").status_code == 200


def test_project_validation(client, tmp_path):
    bad = client.post("/api/projects", json={"name": "x", "source_type": "github", "path_or_url": "https://evil.com/a/b"})
    assert bad.status_code == 400
    missing = client.post("/api/projects", json={"name": "x", "source_type": "local", "path_or_url": str(tmp_path / "nope")})
    assert missing.status_code == 400
    outside = client.post("/api/projects", json={"name": "x", "source_type": "local", "path_or_url": "/"})
    assert outside.status_code == 400
    bad_ref = client.post("/api/projects", json={"name": "x", "source_type": "local", "path_or_url": str(tmp_path), "base_ref": "--output=x"})
    assert bad_ref.status_code == 422


def test_project_lifecycle_hides_token(client, tmp_path):
    (tmp_path / "proj").mkdir()
    created = client.post("/api/projects", json={"name": "Demo", "source_type": "local", "path_or_url": str(tmp_path / "proj"),
                                                 "sonar_token": "secret-token"})
    assert created.status_code == 201
    body = created.json()
    assert "sonar_token" not in body and body["has_sonar_token"] is True
    listed = client.get("/api/projects").json()
    assert listed[0]["name"] == "Demo" and "sonar_token" not in listed[0]
    assert client.get(f"/api/projects/{body['id']}/latest").json() == {"scan": None}
    assert client.delete(f"/api/projects/{body['id']}").status_code == 204


def test_tools_endpoint(client):
    names = {t["name"] for t in client.get("/api/tools").json()}
    assert {"ruff", "semgrep", "trivy", "AI review"} <= names
