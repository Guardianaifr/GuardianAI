import base64

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str, password: str):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _setup_rbac_policy_db(tmp_path, monkeypatch):
    db_path = tmp_path / "rbac_policy_test.db"
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


def test_rbac_policy_endpoint_exposes_roles_and_access_matrix(tmp_path, monkeypatch):
    _setup_rbac_policy_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    response = client.get("/api/v1/rbac/policy", headers=_basic_auth_headers("auditor", "auditor-pass"))
    assert response.status_code == 200
    body = response.json()

    assert "generated_at" in body
    assert "roles" in body
    assert "endpoints" in body
    assert "admin" in body["roles"]
    assert "auditor" in body["roles"]
    assert "user" in body["roles"]
    assert "rbac:read" in body["roles"]["admin"]
    assert "rbac:read" in body["roles"]["auditor"]
    assert "rbac:read" not in body["roles"]["user"]
    assert "auth:lockouts:manage" in body["roles"]["admin"]
    assert "auth:lockouts:read" in body["roles"]["auditor"]
    assert "auth:lockouts:read" not in body["roles"]["user"]
    assert "auth:sessions:revoke_all" in body["roles"]["admin"]
    assert "auth:sessions:revoke_all" not in body["roles"]["auditor"]

    retry_policy = next(
        item for item in body["endpoints"] if item["path"] == "/api/v1/audit-log/retry-failures" and item["method"] == "POST"
    )
    assert retry_policy["allowed_roles"] == ["admin"]
    assert retry_policy["permission"] == "audit:retry"

    compliance_policy = next(
        item for item in body["endpoints"] if item["path"] == "/api/v1/compliance/report" and item["method"] == "GET"
    )
    assert compliance_policy["allowed_roles"] == ["admin", "auditor"]

    lockouts_read_policy = next(
        item for item in body["endpoints"] if item["path"] == "/api/v1/auth/lockouts" and item["method"] == "GET"
    )
    assert lockouts_read_policy["allowed_roles"] == ["admin", "auditor"]
    assert lockouts_read_policy["permission"] == "auth:lockouts:read"

    lockouts_clear_policy = next(
        item for item in body["endpoints"] if item["path"] == "/api/v1/auth/lockouts/clear" and item["method"] == "POST"
    )
    assert lockouts_clear_policy["allowed_roles"] == ["admin"]
    assert lockouts_clear_policy["permission"] == "auth:lockouts:manage"

    sessions_revoke_all_policy = next(
        item for item in body["endpoints"] if item["path"] == "/api/v1/auth/sessions/revoke-all" and item["method"] == "POST"
    )
    assert sessions_revoke_all_policy["allowed_roles"] == ["admin"]
    assert sessions_revoke_all_policy["permission"] == "auth:sessions:revoke_all"


def test_rbac_policy_allows_admin_and_blocks_regular_user(tmp_path, monkeypatch):
    _setup_rbac_policy_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    admin_res = client.get("/api/v1/rbac/policy", headers=_basic_auth_headers("admin", "admin-pass"))
    assert admin_res.status_code == 200

    user_res = client.get("/api/v1/rbac/policy", headers=_basic_auth_headers("user1", "user-pass"))
    assert user_res.status_code == 403
