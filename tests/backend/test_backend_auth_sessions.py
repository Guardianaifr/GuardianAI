import base64
import json

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str, password: str):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _setup_sessions_db(tmp_path, monkeypatch):
    db_path = tmp_path / "auth_sessions_test.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
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


def test_auditor_can_list_sessions_and_user_cannot(tmp_path, monkeypatch):
    _setup_sessions_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    user_token = client.post("/api/v1/auth/token", headers=_basic_auth_headers("user1", "user-pass"))
    assert user_token.status_code == 200

    sessions_res = client.get("/api/v1/auth/sessions?limit=20", headers=_basic_auth_headers("auditor", "auditor-pass"))
    assert sessions_res.status_code == 200
    sessions = sessions_res.json()
    assert any(item["subject"] == "user1" and item["role"] == "user" and item["active"] for item in sessions)

    user_sessions_res = client.get("/api/v1/auth/sessions", headers=_basic_auth_headers("user1", "user-pass"))
    assert user_sessions_res.status_code == 403


def test_admin_can_revoke_user_sessions_and_action_is_audited(tmp_path, monkeypatch):
    _setup_sessions_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    token_a = client.post("/api/v1/auth/token", headers=_basic_auth_headers("user1", "user-pass"))
    token_b = client.post("/api/v1/auth/token", headers=_basic_auth_headers("user1", "user-pass"))
    assert token_a.status_code == 200
    assert token_b.status_code == 200

    bearer_a = {"Authorization": f"Bearer {token_a.json()['access_token']}"}
    before = client.get("/api/v1/analytics", headers=bearer_a)
    assert before.status_code == 200

    revoke_user = client.post(
        "/api/v1/auth/sessions/revoke-user",
        json={"username": "user1", "active_only": True, "reason": "incident_containment"},
        headers=_basic_auth_headers("admin", "admin-pass"),
    )
    assert revoke_user.status_code == 200
    body = revoke_user.json()
    assert body["target_user"] == "user1"
    assert body["matched"] >= 2
    assert body["revoked"] >= 2

    after = client.get("/api/v1/analytics", headers=bearer_a)
    assert after.status_code == 401
    assert "revoked" in after.json()["detail"].lower()

    sessions_res = client.get(
        "/api/v1/auth/sessions?include_expired=true&include_revoked=true",
        headers=_basic_auth_headers("admin", "admin-pass"),
    )
    assert sessions_res.status_code == 200
    sessions = [s for s in sessions_res.json() if s["subject"] == "user1"]
    assert sessions
    assert any((not s["active"]) and s["revoked_by"] == "admin" for s in sessions)

    audit_log = client.get("/api/v1/audit-log?limit=50", headers=_basic_auth_headers("admin", "admin-pass"))
    assert audit_log.status_code == 200
    entries = [entry for entry in audit_log.json() if entry["action"] == "auth_revoke_user_sessions"]
    assert entries
    details = json.loads(entries[0]["details"])
    assert details["target_user"] == "user1"


def test_admin_can_revoke_single_session_by_jti_and_auditor_cannot(tmp_path, monkeypatch):
    _setup_sessions_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    token_res = client.post("/api/v1/auth/token", headers=_basic_auth_headers("user1", "user-pass"))
    assert token_res.status_code == 200
    token = token_res.json()["access_token"]
    jti = backend_main._decode_jwt(token)["jti"]

    auditor_forbidden = client.post(
        "/api/v1/auth/sessions/revoke-jti",
        json={"jti": jti, "reason": "should_fail"},
        headers=_basic_auth_headers("auditor", "auditor-pass"),
    )
    assert auditor_forbidden.status_code == 403

    revoke_res = client.post(
        "/api/v1/auth/sessions/revoke-jti",
        json={"jti": jti, "reason": "incident_containment"},
        headers=_basic_auth_headers("admin", "admin-pass"),
    )
    assert revoke_res.status_code == 200
    body = revoke_res.json()
    assert body["jti"] == jti
    assert body["target_user"] == "user1"
    assert body["revoked"] is True
    assert body["already_revoked"] is False

    # Session token is now blocked.
    bearer = {"Authorization": f"Bearer {token}"}
    after = client.get("/api/v1/analytics", headers=bearer)
    assert after.status_code == 401
    assert "revoked" in after.json()["detail"].lower()

    # Re-revoke same session reports already revoked.
    second = client.post(
        "/api/v1/auth/sessions/revoke-jti",
        json={"jti": jti},
        headers=_basic_auth_headers("admin", "admin-pass"),
    )
    assert second.status_code == 200
    assert second.json()["already_revoked"] is True

    audit_log = client.get("/api/v1/audit-log?limit=50", headers=_basic_auth_headers("admin", "admin-pass"))
    assert audit_log.status_code == 200
    entries = [entry for entry in audit_log.json() if entry["action"] == "auth_revoke_session_jti"]
    assert entries
    details = json.loads(entries[0]["details"])
    assert details["jti"] == jti


def test_admin_can_revoke_all_sessions_with_self_exclusion(tmp_path, monkeypatch):
    _setup_sessions_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    user1_token_res = client.post("/api/v1/auth/token", headers=_basic_auth_headers("user1", "user-pass"))
    auditor_token_res = client.post("/api/v1/auth/token", headers=_basic_auth_headers("auditor", "auditor-pass"))
    admin_token_res = client.post("/api/v1/auth/token", headers=_basic_auth_headers("admin", "admin-pass"))
    assert user1_token_res.status_code == 200
    assert auditor_token_res.status_code == 200
    assert admin_token_res.status_code == 200

    user1_bearer = {"Authorization": f"Bearer {user1_token_res.json()['access_token']}"}
    auditor_bearer = {"Authorization": f"Bearer {auditor_token_res.json()['access_token']}"}
    admin_bearer = {"Authorization": f"Bearer {admin_token_res.json()['access_token']}"}

    assert client.get("/api/v1/analytics", headers=user1_bearer).status_code == 200
    assert client.get("/api/v1/analytics", headers=auditor_bearer).status_code == 200
    assert client.get("/api/v1/analytics", headers=admin_bearer).status_code == 200

    auditor_forbidden = client.post(
        "/api/v1/auth/sessions/revoke-all",
        json={"active_only": True, "exclude_self": True},
        headers=_basic_auth_headers("auditor", "auditor-pass"),
    )
    assert auditor_forbidden.status_code == 403

    revoke_res = client.post(
        "/api/v1/auth/sessions/revoke-all",
        json={"active_only": True, "exclude_self": True, "reason": "global_incident_containment"},
        headers=_basic_auth_headers("admin", "admin-pass"),
    )
    assert revoke_res.status_code == 200
    body = revoke_res.json()
    assert body["revoked"] >= 2
    assert body["excluded"] >= 1
    assert "admin" in body["excluded_users"]

    assert client.get("/api/v1/analytics", headers=user1_bearer).status_code == 401
    assert client.get("/api/v1/analytics", headers=auditor_bearer).status_code == 401
    assert client.get("/api/v1/analytics", headers=admin_bearer).status_code == 200

    sessions_res = client.get(
        "/api/v1/auth/sessions?include_expired=true&include_revoked=true",
        headers=_basic_auth_headers("admin", "admin-pass"),
    )
    assert sessions_res.status_code == 200
    sessions = sessions_res.json()
    assert any(s["subject"] == "admin" and s["active"] for s in sessions)
    assert any(s["subject"] == "user1" and (not s["active"]) and s["revoked_by"] == "admin" for s in sessions)

    audit_log = client.get("/api/v1/audit-log?limit=50", headers=_basic_auth_headers("admin", "admin-pass"))
    assert audit_log.status_code == 200
    entries = [entry for entry in audit_log.json() if entry["action"] == "auth_revoke_all_sessions"]
    assert entries
    details = json.loads(entries[0]["details"])
    assert details["exclude_self"] is True
    assert "admin" in details["excluded_users"]
