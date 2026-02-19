import base64
import json
import sqlite3
import time

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str = "admin", password: str = "guardian_default"):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _admin_action_event(action: str):
    return {
        "guardian_id": "test-guardian",
        "event_type": "admin_action",
        "severity": "high",
        "details": {"action": action, "user": "admin", "path": "/admin"},
    }


def test_audit_chain_verification_passes(tmp_path, monkeypatch):
    db_path = tmp_path / "audit_chain_ok.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    backend_main.init_db()

    client = TestClient(backend_main.app)
    assert client.post("/api/v1/telemetry", json=_admin_action_event("rotate_token")).status_code == 200
    assert client.post("/api/v1/telemetry", json=_admin_action_event("update_policy")).status_code == 200

    verify = client.get("/api/v1/audit-log/verify", headers=_basic_auth_headers())
    assert verify.status_code == 200
    body = verify.json()
    assert body["ok"] is True
    assert body["entries"] == 2


def test_audit_chain_verification_detects_tamper(tmp_path, monkeypatch):
    db_path = tmp_path / "audit_chain_bad.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    backend_main.init_db()

    client = TestClient(backend_main.app)
    assert client.post("/api/v1/telemetry", json=_admin_action_event("rotate_token")).status_code == 200
    assert client.post("/api/v1/telemetry", json=_admin_action_event("update_policy")).status_code == 200

    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute("UPDATE audit_logs SET details = ? WHERE id = 1", ('{"action":"tampered"}',))
    conn.commit()
    conn.close()

    verify = client.get("/api/v1/audit-log/verify", headers=_basic_auth_headers())
    assert verify.status_code == 200
    body = verify.json()
    assert body["ok"] is False
    assert body["reason"] in {"entry_hash mismatch", "prev_hash mismatch"}


def test_audit_chain_verification_skips_legacy_unhashed_rows(tmp_path, monkeypatch):
    db_path = tmp_path / "audit_chain_legacy.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    backend_main.init_db()

    now = time.time()
    details_json = json.dumps({"action": "legacy_action", "user": "admin"})
    signature = "legacy_signature"
    conn = sqlite3.connect(str(db_path))
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO audit_logs (guardian_id, action, user, details, timestamp, signature, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, NULL, NULL)
        """,
        ("legacy-guardian", "legacy_action", "admin", details_json, now, signature),
    )

    hashed_details = json.dumps({"action": "new_action", "user": "admin"})
    hashed_signature = "hashed_signature"
    hashed_ts = now + 1
    entry_hash = backend_main._compute_audit_entry_hash(
        guardian_id="guardian-2",
        action="new_action",
        user="admin",
        details_json=hashed_details,
        timestamp=hashed_ts,
        signature=hashed_signature,
        prev_hash="",
    )
    cur.execute(
        """
        INSERT INTO audit_logs (guardian_id, action, user, details, timestamp, signature, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        ("guardian-2", "new_action", "admin", hashed_details, hashed_ts, hashed_signature, "", entry_hash),
    )
    conn.commit()
    conn.close()

    client = TestClient(backend_main.app)
    verify = client.get("/api/v1/audit-log/verify", headers=_basic_auth_headers())
    assert verify.status_code == 200
    body = verify.json()
    assert body["ok"] is True
    assert body["entries"] == 1
    assert "skipped 1 legacy unhashed entries" in (body.get("message") or "")
