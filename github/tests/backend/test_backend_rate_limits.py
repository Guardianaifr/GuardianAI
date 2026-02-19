import backend.main as backend_main
from fastapi import HTTPException
import pytest


def test_parse_limit_overrides_valid_json():
    raw = '{"admin": 100, "analyst": "50", "bad": 0, "skip": "x"}'
    parsed = backend_main._parse_limit_overrides(raw, "test")
    assert parsed["admin"] == 100
    assert parsed["analyst"] == 50
    assert "bad" not in parsed
    assert "skip" not in parsed


def test_parse_limit_overrides_invalid_json():
    parsed = backend_main._parse_limit_overrides("{not-json}", "test")
    assert parsed == {}


def test_get_user_rate_limit_prefers_override(monkeypatch):
    monkeypatch.setattr(backend_main, "_user_rate_limit_overrides", {"admin": 12})
    monkeypatch.setattr(backend_main, "API_RATE_LIMIT_PER_MIN", 240)
    assert backend_main._get_user_rate_limit("admin") == 12
    assert backend_main._get_user_rate_limit("someone") == 240


def test_get_telemetry_rate_limit_prefers_override(monkeypatch):
    monkeypatch.setattr(backend_main, "_telemetry_rate_limit_overrides", {"key-1": 7})
    monkeypatch.setattr(backend_main, "TELEMETRY_RATE_LIMIT_PER_MIN", 600)
    assert backend_main._get_telemetry_rate_limit("key-1") == 7
    assert backend_main._get_telemetry_rate_limit("other") == 600


def test_rate_limit_uses_distributed_backend_when_enabled(monkeypatch):
    calls = []
    monkeypatch.setattr(backend_main, "RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})

    def _fake_distributed(identity: str, limit: int) -> bool:
        calls.append((identity, limit))
        return True

    monkeypatch.setattr(backend_main, "_enforce_rate_limit_distributed", _fake_distributed)

    backend_main._enforce_rate_limit("user:admin", 2)
    assert calls == [("user:admin", 2)]
    assert backend_main._rate_limit_state == {}


def test_rate_limit_falls_back_to_memory_when_distributed_unavailable(monkeypatch):
    monkeypatch.setattr(backend_main, "RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    monkeypatch.setattr(backend_main, "_enforce_rate_limit_distributed", lambda identity, limit: False)

    backend_main._enforce_rate_limit("user:admin", 1)
    with pytest.raises(HTTPException) as exc_info:
        backend_main._enforce_rate_limit("user:admin", 1)
    assert exc_info.value.status_code == 429
