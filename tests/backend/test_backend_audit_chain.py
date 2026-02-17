import base64
import sqlite3

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
