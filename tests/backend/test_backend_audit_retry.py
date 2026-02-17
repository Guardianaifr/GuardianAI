import base64

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str = "admin", password: str = "guardian_default"):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _admin_action_event():
    return {
        "guardian_id": "test-guardian",
        "event_type": "admin_action",
        "severity": "high",
        "details": {"action": "update_policy", "user": "admin"},
    }


def test_audit_delivery_failure_is_queued(tmp_path, monkeypatch):
    db_path = tmp_path / "audit_retry_queue.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    backend_main.init_db()

    # Force HTTP sink failure and syslog success so exactly one queue row is created.
    monkeypatch.setattr(backend_main, "_forward_external_audit_log", lambda payload, strict=False: False)
    monkeypatch.setattr(backend_main, "_forward_syslog_audit_log", lambda payload, strict=False: True)

    client = TestClient(backend_main.app)
    ingest = client.post("/api/v1/telemetry", json=_admin_action_event())
    assert ingest.status_code == 200

    failures = client.get("/api/v1/audit-log/failures", headers=_basic_auth_headers())
    assert failures.status_code == 200
    body = failures.json()
    assert len(body) == 1
    assert body[0]["sink_type"] == "http"


def test_retry_failures_endpoint_resolves_queue(tmp_path, monkeypatch):
    db_path = tmp_path / "audit_retry_resolve.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    backend_main.init_db()

    backend_main._queue_audit_delivery_failure("http", {"action": "admin_action"}, "temporary outage")

    monkeypatch.setattr(backend_main, "_forward_external_audit_log", lambda payload, strict=False: True)
    monkeypatch.setattr(backend_main, "_forward_syslog_audit_log", lambda payload, strict=False: True)

    client = TestClient(backend_main.app)
    retry = client.post("/api/v1/audit-log/retry-failures", headers=_basic_auth_headers())
    assert retry.status_code == 200
    result = retry.json()
    assert result["retried"] == 1
    assert result["resolved"] == 1
    assert result["failed"] == 0

    failures = client.get("/api/v1/audit-log/failures", headers=_basic_auth_headers())
    assert failures.status_code == 200
    assert failures.json() == []
