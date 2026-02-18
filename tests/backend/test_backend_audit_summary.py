import base64
import sqlite3
import time

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str, password: str):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _setup_summary_db(tmp_path, monkeypatch):
    db_path = tmp_path / "audit_summary_test.db"
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


def test_audit_summary_reports_counts_and_sink_breakdown(tmp_path, monkeypatch):
    db_path = _setup_summary_db(tmp_path, monkeypatch)
    now = time.time()

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute(
        "INSERT INTO audit_logs (guardian_id, action, user, details, timestamp, signature, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("g1", "admin_action", "admin", "{}", now, "sig1", "", "h1"),
    )
    cur.execute(
        "INSERT INTO audit_logs (guardian_id, action, user, details, timestamp, signature, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("g1", "admin_action", "admin", "{}", now - 3600, "sig2", "h1", "h2"),
    )
    cur.execute(
        "INSERT INTO audit_logs (guardian_id, action, user, details, timestamp, signature, prev_hash, entry_hash) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
        ("g1", "admin_action", "admin", "{}", now - 172800, "sig3", "", None),
    )
    cur.execute(
        "INSERT INTO audit_delivery_failures (sink_type, payload, error, retry_count, created_at, last_attempt_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("http", "{}", "x", 0, now, now),
    )
    cur.execute(
        "INSERT INTO audit_delivery_failures (sink_type, payload, error, retry_count, created_at, last_attempt_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("http", "{}", "x", 0, now, now),
    )
    cur.execute(
        "INSERT INTO audit_delivery_failures (sink_type, payload, error, retry_count, created_at, last_attempt_at) VALUES (?, ?, ?, ?, ?, ?)",
        ("syslog", "{}", "x", 0, now, now),
    )
    conn.commit()
    conn.close()

    monkeypatch.setattr(
        backend_main,
        "_verify_audit_log_chain_internal",
        lambda: {"ok": True, "entries": 2, "message": "Verified hashed entries; skipped 1 legacy unhashed entries"},
    )

    client = TestClient(backend_main.app)
    response = client.get("/api/v1/audit-log/summary", headers=_basic_auth_headers("auditor", "auditor-pass"))
    assert response.status_code == 200
    body = response.json()
    assert body["total_entries"] == 3
    assert body["hashed_entries"] == 2
    assert body["legacy_unhashed_entries"] == 1
    assert body["recent_admin_actions_24h"] == 2
    assert body["failed_deliveries_total"] == 3
    assert body["failed_deliveries_by_sink"]["http"] == 2
    assert body["failed_deliveries_by_sink"]["syslog"] == 1
    assert body["chain_ok"] is True
    assert body["chain_entries_checked"] == 2


def test_audit_summary_includes_chain_failure_details(tmp_path, monkeypatch):
    _setup_summary_db(tmp_path, monkeypatch)
    monkeypatch.setattr(
        backend_main,
        "_verify_audit_log_chain_internal",
        lambda: {"ok": False, "entries": 1, "failed_id": 17, "reason": "entry_hash mismatch"},
    )
    client = TestClient(backend_main.app)

    response = client.get("/api/v1/audit-log/summary", headers=_basic_auth_headers("admin", "admin-pass"))
    assert response.status_code == 200
    body = response.json()
    assert body["chain_ok"] is False
    assert body["chain_entries_checked"] == 1
    assert body["chain_failed_id"] == 17
    assert body["chain_reason"] == "entry_hash mismatch"


def test_audit_summary_is_not_accessible_to_user_role(tmp_path, monkeypatch):
    _setup_summary_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    response = client.get("/api/v1/audit-log/summary", headers=_basic_auth_headers("user1", "user-pass"))
    assert response.status_code == 403
