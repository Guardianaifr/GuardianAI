import json

import pytest
from fastapi import HTTPException

import backend.main as backend_main


class _DummyResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


def test_splunk_sink_noop_when_not_configured(monkeypatch):
    called = {"value": False}

    def _fake_post(*args, **kwargs):
        called["value"] = True
        return _DummyResponse(200)

    monkeypatch.setattr(backend_main, "AUDIT_SPLUNK_HEC_URL", "")
    monkeypatch.setattr(backend_main.requests, "post", _fake_post)

    result = backend_main._forward_splunk_audit_log({"action": "admin_action"})
    assert result is True
    assert called["value"] is False


def test_splunk_sink_formats_hec_event(monkeypatch):
    captured = {}

    def _fake_post(url, json, headers, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        return _DummyResponse(200)

    monkeypatch.setattr(backend_main, "AUDIT_SPLUNK_HEC_URL", "https://splunk.local:8088/services/collector")
    monkeypatch.setattr(backend_main, "AUDIT_SPLUNK_HEC_TOKEN", "hec-token")
    monkeypatch.setattr(backend_main, "AUDIT_SPLUNK_INDEX", "guardian_audit")
    monkeypatch.setattr(backend_main, "AUDIT_SPLUNK_SOURCE", "guardian-backend")
    monkeypatch.setattr(backend_main, "AUDIT_SPLUNK_SOURCETYPE", "_json")
    monkeypatch.setattr(backend_main, "AUDIT_SINK_TIMEOUT_SEC", 1.0)
    monkeypatch.setattr(backend_main.requests, "post", _fake_post)

    payload = {"action": "rotate_key", "user": "admin", "timestamp": 1_739_835_000.0}
    result = backend_main._forward_splunk_audit_log(payload)
    assert result is True
    assert captured["url"].endswith("/services/collector")
    assert captured["json"]["event"] == payload
    assert captured["json"]["index"] == "guardian_audit"
    assert captured["headers"]["Authorization"] == "Splunk hec-token"


def test_datadog_sink_success(monkeypatch):
    captured = {}

    def _fake_post(url, json, headers, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        return _DummyResponse(202)

    monkeypatch.setattr(backend_main, "AUDIT_DATADOG_API_KEY", "dd-key")
    monkeypatch.setattr(backend_main, "AUDIT_DATADOG_LOGS_URL", "https://http-intake.logs.datadoghq.com/api/v2/logs")
    monkeypatch.setattr(backend_main, "AUDIT_DATADOG_SERVICE", "guardian-backend")
    monkeypatch.setattr(backend_main, "AUDIT_DATADOG_SOURCE", "guardianai")
    monkeypatch.setattr(backend_main, "AUDIT_DATADOG_TAGS", "env:test,app:guardianai")
    monkeypatch.setattr(backend_main.requests, "post", _fake_post)

    payload = {"action": "admin_action", "user": "admin"}
    result = backend_main._forward_datadog_audit_log(payload)
    assert result is True
    assert captured["headers"]["DD-API-KEY"] == "dd-key"
    assert isinstance(captured["json"], list)
    assert json.loads(captured["json"][0]["message"]) == payload


def test_datadog_sink_strict_failure_raises(monkeypatch):
    monkeypatch.setattr(backend_main, "AUDIT_DATADOG_API_KEY", "dd-key")
    monkeypatch.setattr(backend_main.requests, "post", lambda *args, **kwargs: _DummyResponse(500))

    with pytest.raises(HTTPException) as exc:
        backend_main._forward_datadog_audit_log({"action": "admin_action"}, strict=True)
    assert exc.value.status_code == 503


def test_retry_failures_supports_splunk_and_datadog(tmp_path, monkeypatch):
    db_path = tmp_path / "vendor_retry.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    backend_main.init_db()

    backend_main._queue_audit_delivery_failure("splunk", {"a": 1}, "x")
    backend_main._queue_audit_delivery_failure("datadog", {"b": 2}, "y")

    monkeypatch.setattr(backend_main, "_forward_splunk_audit_log", lambda payload, strict=False: True)
    monkeypatch.setattr(backend_main, "_forward_datadog_audit_log", lambda payload, strict=False: True)

    result = backend_main._retry_failed_audit_deliveries(limit=10)
    assert result["retried"] == 2
    assert result["resolved"] == 2
    assert result["failed"] == 0
