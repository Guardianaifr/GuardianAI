import base64

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str, password: str):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _setup_rbac_db(tmp_path, monkeypatch):
    db_path = tmp_path / "rbac_test.db"
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


def test_token_includes_role_claim(tmp_path, monkeypatch):
    _setup_rbac_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    token_res = client.post("/api/v1/auth/token", headers=_basic_auth_headers("auditor", "auditor-pass"))
    assert token_res.status_code == 200
    body = token_res.json()
    assert body["user"] == "auditor"
    assert body["role"] == "auditor"


def test_auditor_can_read_audit_but_cannot_modify_api_keys(tmp_path, monkeypatch):
    _setup_rbac_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    # Auditor can read audit failure queue.
    read_res = client.get("/api/v1/audit-log/failures", headers=_basic_auth_headers("auditor", "auditor-pass"))
    assert read_res.status_code == 200

    # Auditor cannot create API keys (admin-only).
    create_res = client.post(
        "/api/v1/api-keys",
        json={"key_name": "blocked_for_auditor"},
        headers=_basic_auth_headers("auditor", "auditor-pass"),
    )
    assert create_res.status_code == 403

    # Auditor cannot trigger retry of failures (admin-only).
    retry_res = client.post("/api/v1/audit-log/retry-failures", headers=_basic_auth_headers("auditor", "auditor-pass"))
    assert retry_res.status_code == 403


def test_regular_user_cannot_access_audit_log_endpoints(tmp_path, monkeypatch):
    _setup_rbac_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    response = client.get("/api/v1/audit-log", headers=_basic_auth_headers("user1", "user-pass"))
    assert response.status_code == 403
