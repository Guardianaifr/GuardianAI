import base64
import sqlite3
import time

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str, password: str):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _setup_revocation_db(tmp_path, monkeypatch):
    db_path = tmp_path / "auth_revocations_test.db"
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
    return db_path


def test_auditor_can_list_revocations_and_user_cannot(tmp_path, monkeypatch):
    _setup_revocation_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    admin_token_res = client.post("/api/v1/auth/token", headers=_basic_auth_headers("admin", "admin-pass"))
    assert admin_token_res.status_code == 200
    admin_bearer = {"Authorization": f"Bearer {admin_token_res.json()['access_token']}"}
    revoke_res = client.post("/api/v1/auth/revoke", headers=admin_bearer)
    assert revoke_res.status_code == 200
    revoked_jti = revoke_res.json()["revoked_jti"]

    auditor_list = client.get("/api/v1/auth/revocations?limit=10", headers=_basic_auth_headers("auditor", "auditor-pass"))
    assert auditor_list.status_code == 200
    body = auditor_list.json()
    assert isinstance(body, list)
    assert len(body) >= 1
    assert any(item["jti"] == revoked_jti for item in body)
    assert all("expired" in item for item in body)

    user_list = client.get("/api/v1/auth/revocations", headers=_basic_auth_headers("user1", "user-pass"))
    assert user_list.status_code == 403


def test_revocation_list_include_expired_and_admin_prune(tmp_path, monkeypatch):
    db_path = _setup_revocation_db(tmp_path, monkeypatch)
    now = time.time()

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO revoked_tokens (jti, revoked_by, revoked_at, expires_at) VALUES (?, ?, ?, ?)",
        ("expired-jti", "admin", now - 1000, now - 10),
    )
    cur.execute(
        "INSERT INTO revoked_tokens (jti, revoked_by, revoked_at, expires_at) VALUES (?, ?, ?, ?)",
        ("active-jti", "admin", now - 100, now + 3600),
    )
    conn.commit()
    conn.close()

    client = TestClient(backend_main.app)

    default_list = client.get("/api/v1/auth/revocations", headers=_basic_auth_headers("admin", "admin-pass"))
    assert default_list.status_code == 200
    assert all(item["jti"] != "expired-jti" for item in default_list.json())

    include_expired = client.get(
        "/api/v1/auth/revocations?include_expired=true",
        headers=_basic_auth_headers("admin", "admin-pass"),
    )
    assert include_expired.status_code == 200
    payload = include_expired.json()
    assert any(item["jti"] == "expired-jti" and item["expired"] is True for item in payload)
    assert any(item["jti"] == "active-jti" and item["expired"] is False for item in payload)

    auditor_prune = client.post(
        "/api/v1/auth/revocations/prune",
        headers=_basic_auth_headers("auditor", "auditor-pass"),
    )
    assert auditor_prune.status_code == 403

    admin_prune = client.post(
        "/api/v1/auth/revocations/prune",
        headers=_basic_auth_headers("admin", "admin-pass"),
    )
    assert admin_prune.status_code == 200
    prune_body = admin_prune.json()
    assert prune_body["deleted"] >= 1
    assert prune_body["expired_only"] is True

    post_prune = client.get(
        "/api/v1/auth/revocations?include_expired=true",
        headers=_basic_auth_headers("admin", "admin-pass"),
    )
    assert post_prune.status_code == 200
    assert all(item["jti"] != "expired-jti" for item in post_prune.json())
