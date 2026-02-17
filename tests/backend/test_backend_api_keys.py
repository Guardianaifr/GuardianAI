import base64

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str = "admin", password: str = "guardian_default"):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _setup_test_db(tmp_path, monkeypatch):
    db_path = tmp_path / "backend_test.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "TELEMETRY_REQUIRE_API_KEY", False)
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    backend_main.init_db()


def test_api_key_lifecycle(tmp_path, monkeypatch):
    _setup_test_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)

    create_res = client.post(
        "/api/v1/api-keys",
        json={"key_name": "svc_ingest"},
        headers=_basic_auth_headers(),
    )
    assert create_res.status_code == 200
    created = create_res.json()
    assert created["key_name"] == "svc_ingest"
    assert created["api_key"].startswith("gk_")

    list_res = client.get("/api/v1/api-keys", headers=_basic_auth_headers())
    assert list_res.status_code == 200
    listed = list_res.json()
    assert len(listed) == 1
    assert listed[0]["key_name"] == "svc_ingest"
    key_id = listed[0]["id"]

    revoke_res = client.post(f"/api/v1/api-keys/{key_id}/revoke", headers=_basic_auth_headers())
    assert revoke_res.status_code == 200
    assert revoke_res.json()["is_active"] is False

    rotate_res = client.post(f"/api/v1/api-keys/{key_id}/rotate", headers=_basic_auth_headers())
    assert rotate_res.status_code == 200
    assert rotate_res.json()["is_active"] is True
    assert rotate_res.json()["api_key"].startswith("gk_")


def test_telemetry_requires_valid_api_key_when_enabled(tmp_path, monkeypatch):
    _setup_test_db(tmp_path, monkeypatch)
    monkeypatch.setattr(backend_main, "TELEMETRY_REQUIRE_API_KEY", True)
    client = TestClient(backend_main.app)

    create_res = client.post(
        "/api/v1/api-keys",
        json={"key_name": "telemetry_client"},
        headers=_basic_auth_headers(),
    )
    key_value = create_res.json()["api_key"]

    event_payload = {
        "guardian_id": "test-guardian",
        "event_type": "allowed_request",
        "severity": "low",
        "details": {"path": "/v1/chat/completions", "latency_ms": "12ms"},
    }

    missing_key = client.post("/api/v1/telemetry", json=event_payload)
    assert missing_key.status_code == 401

    bad_key = client.post("/api/v1/telemetry", json=event_payload, headers={"x-api-key": "bad-key"})
    assert bad_key.status_code == 401

    good_key = client.post("/api/v1/telemetry", json=event_payload, headers={"x-api-key": key_value})
    assert good_key.status_code == 200
