import base64

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str, password: str):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _setup_db_and_users(tmp_path, monkeypatch):
    db_path = tmp_path / "compliance_test.db"
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


def test_compliance_report_pass_when_hardening_controls_enabled(tmp_path, monkeypatch):
    _setup_db_and_users(tmp_path, monkeypatch)
    monkeypatch.setattr(backend_main, "ADMIN_PASS", "strong-admin-pass")
    monkeypatch.setattr(backend_main, "JWT_SECRET", "strong-jwt-secret")
    monkeypatch.setattr(backend_main, "JWT_EXPIRES_MIN", 60)
    monkeypatch.setattr(backend_main, "AUTH_RATE_LIMIT_PER_MIN", 30)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_ENABLED", True)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_MAX_ATTEMPTS", 5)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_DURATION_SEC", 300.0)
    monkeypatch.setattr(backend_main, "API_RATE_LIMIT_PER_MIN", 240)
    monkeypatch.setattr(backend_main, "TELEMETRY_REQUIRE_API_KEY", True)
    monkeypatch.setattr(backend_main, "ENFORCE_HTTPS", True)
    monkeypatch.setattr(backend_main, "METRICS_ENABLED", True)
    monkeypatch.setattr(backend_main, "AUDIT_SINK_URL", "https://audit-sink.local/ingest")
    monkeypatch.setattr(backend_main, "AUDIT_SYSLOG_HOST", "")
    monkeypatch.setattr(backend_main, "AUDIT_SPLUNK_HEC_URL", "")
    monkeypatch.setattr(backend_main, "AUDIT_DATADOG_API_KEY", "")
    monkeypatch.setattr(backend_main, "RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setattr(backend_main, "RATE_LIMIT_REDIS_FAIL_OPEN", False)
    monkeypatch.setattr(backend_main, "_get_redis_client", lambda: object())
    monkeypatch.setattr(backend_main, "_enforce_rate_limit", lambda identity, limit_per_minute: None)
    monkeypatch.setattr(backend_main, "_verify_audit_log_chain_internal", lambda: {"ok": True, "entries": 0})

    client = TestClient(backend_main.app)
    response = client.get(
        "/api/v1/compliance/report",
        headers={**_basic_auth_headers("auditor", "auditor-pass"), "x-forwarded-proto": "https"},
    )

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "pass"
    assert body["summary"]["failed"] == 0
    assert body["summary"]["warnings"] == 0
    assert body["summary"]["passed"] == len(body["controls"])

    controls = {c["control"]: c for c in body["controls"]}
    assert controls["jwt_secret_configured"]["status"] == "pass"
    assert controls["auth_failed_login_lockout"]["status"] == "pass"
    assert controls["distributed_rate_limit_backend"]["status"] == "pass"
    assert controls["audit_chain_integrity"]["status"] == "pass"


def test_compliance_report_fails_for_critical_hardening_gaps(tmp_path, monkeypatch):
    _setup_db_and_users(tmp_path, monkeypatch)
    monkeypatch.setattr(backend_main, "ADMIN_PASS", "guardian_default")
    monkeypatch.setattr(backend_main, "JWT_SECRET", "guardian_jwt_dev_secret_change_me")
    monkeypatch.setattr(backend_main, "JWT_EXPIRES_MIN", 0)
    monkeypatch.setattr(backend_main, "AUTH_RATE_LIMIT_PER_MIN", 0)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_ENABLED", False)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_MAX_ATTEMPTS", 5)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_DURATION_SEC", 300.0)
    monkeypatch.setattr(backend_main, "API_RATE_LIMIT_PER_MIN", 0)
    monkeypatch.setattr(backend_main, "TELEMETRY_REQUIRE_API_KEY", False)
    monkeypatch.setattr(backend_main, "ENFORCE_HTTPS", False)
    monkeypatch.setattr(backend_main, "METRICS_ENABLED", False)
    monkeypatch.setattr(backend_main, "AUDIT_SINK_URL", "")
    monkeypatch.setattr(backend_main, "AUDIT_SYSLOG_HOST", "")
    monkeypatch.setattr(backend_main, "AUDIT_SPLUNK_HEC_URL", "")
    monkeypatch.setattr(backend_main, "AUDIT_DATADOG_API_KEY", "")
    monkeypatch.setattr(backend_main, "RATE_LIMIT_BACKEND", "memory")
    monkeypatch.setattr(backend_main, "_enforce_rate_limit", lambda identity, limit_per_minute: None)
    monkeypatch.setattr(
        backend_main,
        "_verify_audit_log_chain_internal",
        lambda: {"ok": False, "entries": 0, "failed_id": 2, "reason": "entry_hash mismatch"},
    )

    client = TestClient(backend_main.app)
    response = client.get("/api/v1/compliance/report", headers=_basic_auth_headers("admin", "admin-pass"))

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "fail"
    assert body["summary"]["failed"] >= 1

    controls = {c["control"]: c for c in body["controls"]}
    assert controls["admin_password_configured"]["status"] == "fail"
    assert controls["jwt_secret_configured"]["status"] == "fail"
    assert controls["auth_failed_login_lockout"]["status"] == "warn"
    assert controls["audit_chain_integrity"]["status"] == "fail"
    assert controls["distributed_rate_limit_backend"]["status"] == "warn"


def test_compliance_report_is_not_accessible_to_user_role(tmp_path, monkeypatch):
    _setup_db_and_users(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    response = client.get("/api/v1/compliance/report", headers=_basic_auth_headers("user1", "user-pass"))
    assert response.status_code == 403
