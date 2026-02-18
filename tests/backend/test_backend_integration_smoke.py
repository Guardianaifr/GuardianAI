import base64

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str = "admin", password: str = "guardian_default"):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def test_hardening_end_to_end_smoke(tmp_path, monkeypatch):
    db_path = tmp_path / "backend_hardening_smoke.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    monkeypatch.setattr(backend_main, "TELEMETRY_REQUIRE_API_KEY", True)
    backend_main.init_db()

    client = TestClient(backend_main.app)

    token_res = client.post("/api/v1/auth/token", headers=_basic_auth_headers())
    assert token_res.status_code == 200
    token = token_res.json()["access_token"]
    bearer = {"Authorization": f"Bearer {token}"}

    create_key = client.post("/api/v1/api-keys", json={"key_name": "smoke_key"}, headers=bearer)
    assert create_key.status_code == 200
    api_key = create_key.json()["api_key"]

    monkeypatch.setattr(backend_main, "_forward_external_audit_log", lambda payload, strict=False: False)
    monkeypatch.setattr(backend_main, "_forward_syslog_audit_log", lambda payload, strict=False: True)

    event_payload = {
        "guardian_id": "smoke-guardian",
        "event_type": "admin_action",
        "severity": "high",
        "details": {"action": "smoke_test", "user": "admin"},
    }
    ingest = client.post("/api/v1/telemetry", json=event_payload, headers={"x-api-key": api_key})
    assert ingest.status_code == 200

    verify = client.get("/api/v1/audit-log/verify", headers=bearer)
    assert verify.status_code == 200
    assert verify.json()["ok"] is True
    assert verify.json()["entries"] >= 1

    failures = client.get("/api/v1/audit-log/failures", headers=bearer)
    assert failures.status_code == 200
    failures_body = failures.json()
    assert len(failures_body) >= 1
    assert failures_body[0]["sink_type"] == "http"

    monkeypatch.setattr(backend_main, "_forward_external_audit_log", lambda payload, strict=False: True)
    retry = client.post("/api/v1/audit-log/retry-failures", headers=bearer)
    assert retry.status_code == 200
    retry_body = retry.json()
    assert retry_body["retried"] >= 1
    assert retry_body["resolved"] >= 1
    assert retry_body["failed"] == 0
