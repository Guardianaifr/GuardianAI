import pytest
from fastapi import HTTPException

import backend.main as backend_main


class _DummyResponse:
    def __init__(self, status_code: int):
        self.status_code = status_code


def test_external_audit_log_noop_when_sink_not_configured(monkeypatch):
    called = {"value": False}

    def _fake_post(*args, **kwargs):
        called["value"] = True
        return _DummyResponse(200)

    monkeypatch.setattr(backend_main, "AUDIT_SINK_URL", "")
    monkeypatch.setattr(backend_main.requests, "post", _fake_post)

    result = backend_main._forward_external_audit_log({"event": "admin_action"})
    assert result is True
    assert called["value"] is False


def test_external_audit_log_success_with_auth_header(monkeypatch):
    captured = {}

    def _fake_post(url, json, headers, timeout):
        captured["url"] = url
        captured["json"] = json
        captured["headers"] = headers
        captured["timeout"] = timeout
        return _DummyResponse(201)

    monkeypatch.setattr(backend_main, "AUDIT_SINK_URL", "https://audit.example.local/ingest")
    monkeypatch.setattr(backend_main, "AUDIT_SINK_TOKEN", "secret-token")
    monkeypatch.setattr(backend_main, "AUDIT_SINK_TIMEOUT_SEC", 1.25)
    monkeypatch.setattr(backend_main.requests, "post", _fake_post)

    payload = {"action": "rotate_key", "user": "admin"}
    result = backend_main._forward_external_audit_log(payload)

    assert result is True
    assert captured["url"] == "https://audit.example.local/ingest"
    assert captured["json"] == payload
    assert captured["headers"]["Authorization"] == "Bearer secret-token"
    assert captured["timeout"] == 1.25


def test_external_audit_log_retries_then_succeeds(monkeypatch):
    attempts = {"count": 0}

    def _fake_post(url, json, headers, timeout):
        attempts["count"] += 1
        if attempts["count"] < 3:
            raise RuntimeError("temporary failure")
        return _DummyResponse(200)

    monkeypatch.setattr(backend_main, "AUDIT_SINK_URL", "https://audit.example.local/ingest")
    monkeypatch.setattr(backend_main, "AUDIT_SINK_RETRIES", 4)
    monkeypatch.setattr(backend_main.requests, "post", _fake_post)
    monkeypatch.setattr(backend_main.time, "sleep", lambda *_: None)

    result = backend_main._forward_external_audit_log({"action": "admin_action"})
    assert result is True
    assert attempts["count"] == 3


def test_external_audit_log_failure_non_strict(monkeypatch):
    def _fake_post(url, json, headers, timeout):
        return _DummyResponse(500)

    monkeypatch.setattr(backend_main, "AUDIT_SINK_URL", "https://audit.example.local/ingest")
    monkeypatch.setattr(backend_main, "AUDIT_SINK_RETRIES", 1)
    monkeypatch.setattr(backend_main.requests, "post", _fake_post)
    monkeypatch.setattr(backend_main.time, "sleep", lambda *_: None)

    result = backend_main._forward_external_audit_log({"action": "admin_action"}, strict=False)
    assert result is False


def test_external_audit_log_failure_strict_raises(monkeypatch):
    def _fake_post(url, json, headers, timeout):
        return _DummyResponse(503)

    monkeypatch.setattr(backend_main, "AUDIT_SINK_URL", "https://audit.example.local/ingest")
    monkeypatch.setattr(backend_main, "AUDIT_SINK_RETRIES", 1)
    monkeypatch.setattr(backend_main.requests, "post", _fake_post)
    monkeypatch.setattr(backend_main.time, "sleep", lambda *_: None)

    with pytest.raises(HTTPException) as exc:
        backend_main._forward_external_audit_log({"action": "admin_action"}, strict=True)

    assert exc.value.status_code == 503
