import base64
import json

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str, password: str):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _setup_lockout_mgmt_db(tmp_path, monkeypatch):
    db_path = tmp_path / "auth_lockout_mgmt.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    monkeypatch.setattr(backend_main, "_auth_lockout_state", {})
    monkeypatch.setattr(backend_main, "AUTH_RATE_LIMIT_PER_MIN", 500)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_ENABLED", True)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_DURATION_SEC", 120.0)
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


def test_admin_can_list_and_clear_lockout_with_audit_entry(tmp_path, monkeypatch):
    _setup_lockout_mgmt_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    for _ in range(2):
        failed = client.post(
            "/api/v1/auth/token",
            headers={**_basic_auth_headers("user1", "wrong-pass"), "x-forwarded-for": "10.0.0.1"},
        )
        assert failed.status_code == 401

    locked = client.post(
        "/api/v1/auth/token",
        headers={**_basic_auth_headers("user1", "user-pass"), "x-forwarded-for": "10.0.0.1"},
    )
    assert locked.status_code == 429

    auditor_list = client.get("/api/v1/auth/lockouts", headers=_basic_auth_headers("auditor", "auditor-pass"))
    assert auditor_list.status_code == 200
    lockouts = auditor_list.json()
    assert any(item["username"] == "user1" and item["source"] == "10.0.0.1" and item["active"] for item in lockouts)

    clear = client.post(
        "/api/v1/auth/lockouts/clear",
        json={"username": "user1", "source": "10.0.0.1"},
        headers=_basic_auth_headers("admin", "admin-pass"),
    )
    assert clear.status_code == 200
    clear_body = clear.json()
    assert clear_body["cleared"] == 1
    assert clear_body["remaining"] == 0

    after_clear = client.post(
        "/api/v1/auth/token",
        headers={**_basic_auth_headers("user1", "user-pass"), "x-forwarded-for": "10.0.0.1"},
    )
    assert after_clear.status_code == 200

    audit_log = client.get("/api/v1/audit-log?limit=50", headers=_basic_auth_headers("admin", "admin-pass"))
    assert audit_log.status_code == 200
    entries = [entry for entry in audit_log.json() if entry["action"] == "auth_clear_lockouts"]
    assert entries
    details = json.loads(entries[0]["details"])
    assert details["cleared"] == 1
    assert details["scope"] == "user+source:user1@10.0.0.1"


def test_lockout_management_endpoints_enforce_rbac(tmp_path, monkeypatch):
    _setup_lockout_mgmt_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    for _ in range(2):
        client.post(
            "/api/v1/auth/token",
            headers={**_basic_auth_headers("user1", "wrong-pass"), "x-forwarded-for": "10.0.0.7"},
        )

    user_forbidden = client.get("/api/v1/auth/lockouts", headers=_basic_auth_headers("user1", "user-pass"))
    assert user_forbidden.status_code == 403

    auditor_forbidden = client.post(
        "/api/v1/auth/lockouts/clear",
        json={"clear_all": True},
        headers=_basic_auth_headers("auditor", "auditor-pass"),
    )
    assert auditor_forbidden.status_code == 403

    admin_clear_all = client.post(
        "/api/v1/auth/lockouts/clear",
        json={"clear_all": True},
        headers=_basic_auth_headers("admin", "admin-pass"),
    )
    assert admin_clear_all.status_code == 200
    assert admin_clear_all.json()["cleared"] >= 1
