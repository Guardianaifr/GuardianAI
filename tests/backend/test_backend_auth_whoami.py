import base64

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str, password: str):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _setup_auth_db(tmp_path, monkeypatch):
    db_path = tmp_path / "auth_whoami_test.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "TELEMETRY_REQUIRE_API_KEY", False)
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    monkeypatch.setattr(
        backend_main,
        "_auth_users",
        {
            "admin": {"password": "admin-pass", "role": "admin"},
            "auditor": {"password": "auditor-pass", "role": "auditor"},
            "user1": {"password": "user-pass", "role": "user"},
        },
    )
    backend_main.init_db()


def test_whoami_supports_basic_auth_and_returns_auditor_permissions(tmp_path, monkeypatch):
    _setup_auth_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    response = client.get("/api/v1/auth/whoami", headers=_basic_auth_headers("auditor", "auditor-pass"))
    assert response.status_code == 200
    body = response.json()
    assert body["user"] == "auditor"
    assert body["role"] == "auditor"
    assert body["auth_type"] == "basic"
    assert "audit:read" in body["permissions"]
    assert "api_keys:manage" not in body["permissions"]


def test_whoami_supports_bearer_auth_and_returns_user_permissions(tmp_path, monkeypatch):
    _setup_auth_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    token_res = client.post("/api/v1/auth/token", headers=_basic_auth_headers("user1", "user-pass"))
    assert token_res.status_code == 200
    token = token_res.json()["access_token"]

    response = client.get("/api/v1/auth/whoami", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 200
    body = response.json()
    assert body["user"] == "user1"
    assert body["role"] == "user"
    assert body["auth_type"] == "bearer"
    assert "events:read" in body["permissions"]
    assert "audit:read" not in body["permissions"]
    assert "compliance:read" not in body["permissions"]


def test_whoami_requires_authentication(tmp_path, monkeypatch):
    _setup_auth_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    response = client.get("/api/v1/auth/whoami")
    assert response.status_code == 401
