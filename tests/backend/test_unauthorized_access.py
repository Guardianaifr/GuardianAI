import importlib
import sys
from pathlib import Path
from unittest.mock import patch

from fastapi.testclient import TestClient


def _load_backend(
    monkeypatch,
    tmp_path: Path,
    backend_token: str | None,
    service_token: str | None = None,
    siem_enabled: bool = False,
):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GUARDIAN_ADMIN_USER", "admin")
    monkeypatch.setenv("GUARDIAN_ADMIN_PASS", "guardian_default")
    if backend_token is None:
        monkeypatch.delenv("GUARDIAN_BACKEND_TOKEN", raising=False)
    else:
        monkeypatch.setenv("GUARDIAN_BACKEND_TOKEN", backend_token)
    if service_token is None:
        monkeypatch.delenv("GUARDIAN_SERVICE_AUTH_TOKEN", raising=False)
    else:
        monkeypatch.setenv("GUARDIAN_SERVICE_AUTH_TOKEN", service_token)
    monkeypatch.setenv("GUARDIAN_SERVICE_ID", "guardian-proxy")
    if siem_enabled:
        monkeypatch.setenv("GUARDIAN_SIEM_ENABLED", "true")
    else:
        monkeypatch.delenv("GUARDIAN_SIEM_ENABLED", raising=False)
    monkeypatch.setenv("GUARDIAN_SIEM_OUT", str(tmp_path / "siem_alerts.log"))
    monkeypatch.setenv("GUARDIAN_SIEM_FORMAT", "json")

    sys.modules.pop("backend.main", None)
    module = importlib.import_module("backend.main")
    return importlib.reload(module)


def test_telemetry_requires_bearer_token_when_configured(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path, backend_token="telemetry-token")
    client = TestClient(backend.app)
    payload = {
        "guardian_id": "g-1",
        "event_type": "allowed_request",
        "severity": "LOW",
        "details": {"path": "fast_path_allowlist", "latency_ms": "1.0ms"},
        "timestamp": 0.0,
    }

    r_no_auth = client.post("/api/v1/telemetry", json=payload)
    assert r_no_auth.status_code == 401

    r_bad_auth = client.post(
        "/api/v1/telemetry",
        json=payload,
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert r_bad_auth.status_code == 401

    r_ok = client.post(
        "/api/v1/telemetry",
        json=payload,
        headers={"Authorization": "Bearer telemetry-token"},
    )
    assert r_ok.status_code == 200


def test_events_endpoint_requires_basic_auth(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path, backend_token=None)
    client = TestClient(backend.app)

    r_no_auth = client.get("/api/v1/events")
    assert r_no_auth.status_code == 401

    r_ok = client.get("/api/v1/events", auth=("admin", "guardian_default"))
    assert r_ok.status_code == 200


def test_backend_run_defaults_to_container_bind(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path, backend_token=None)
    with patch("uvicorn.run") as mock_run:
        backend.run_backend()
    mock_run.assert_called_once()
    args, kwargs = mock_run.call_args
    assert kwargs["host"] == "0.0.0.0"
    assert kwargs["port"] == 8001


def test_telemetry_requires_service_headers_when_service_auth_enabled(monkeypatch, tmp_path):
    backend = _load_backend(
        monkeypatch,
        tmp_path,
        backend_token="telemetry-token",
        service_token="service-secret",
    )
    client = TestClient(backend.app)
    payload = {
        "guardian_id": "g-1",
        "event_type": "injection",
        "severity": "HIGH",
        "details": {"path": "fast_path_keyword", "latency_ms": "1.0ms"},
        "timestamp": 0.0,
    }

    no_service = client.post(
        "/api/v1/telemetry",
        json=payload,
        headers={"Authorization": "Bearer telemetry-token"},
    )
    assert no_service.status_code == 401

    ok = client.post(
        "/api/v1/telemetry",
        json=payload,
        headers={
            "Authorization": "Bearer telemetry-token",
            "X-Guardian-Service-Id": "guardian-proxy",
            "X-Guardian-Service-Token": "service-secret",
        },
    )
    assert ok.status_code == 200


def test_high_severity_events_are_routed_to_siem_file(monkeypatch, tmp_path):
    backend = _load_backend(
        monkeypatch,
        tmp_path,
        backend_token="telemetry-token",
        service_token=None,
        siem_enabled=True,
    )
    client = TestClient(backend.app)
    payload = {
        "guardian_id": "g-1",
        "event_type": "data_leak",
        "severity": "CRITICAL",
        "details": {"path": "output_validator", "reason": "PII leak"},
        "timestamp": 0.0,
    }

    r_ok = client.post(
        "/api/v1/telemetry",
        json=payload,
        headers={"Authorization": "Bearer telemetry-token"},
    )
    assert r_ok.status_code == 200
    siem_path = tmp_path / "siem_alerts.log"
    assert siem_path.exists()
    line = siem_path.read_text(encoding="utf-8").strip()
    assert '"event_type":"data_leak"' in line
    assert '"playbook_id":"PB-DLP-001"' in line
