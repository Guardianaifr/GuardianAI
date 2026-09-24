import pytest
from fastapi import HTTPException
from unittest.mock import MagicMock
import backend.main as backend_main


def test_redis_required_in_production_rate_limiting(monkeypatch):
    monkeypatch.setattr(backend_main, "_is_testing_env", lambda: False)
    monkeypatch.setattr(backend_main, "_is_production_env", lambda: True)
    monkeypatch.setattr(backend_main, "RATE_LIMIT_REDIS_URL", "")
    monkeypatch.setattr(backend_main, "RATE_LIMIT_BACKEND", "redis")

    with pytest.raises(HTTPException) as exc_info:
        backend_main._enforce_rate_limit("user:test", 10)
    assert exc_info.value.status_code == 503
    assert "Redis is required in production" in exc_info.value.detail


def test_redis_connection_failed_in_production_rate_limiting(monkeypatch):
    monkeypatch.setattr(backend_main, "_is_testing_env", lambda: False)
    monkeypatch.setattr(backend_main, "_is_production_env", lambda: True)
    monkeypatch.setattr(backend_main, "RATE_LIMIT_REDIS_URL", "redis://localhost:6379/0")
    monkeypatch.setattr(backend_main, "RATE_LIMIT_BACKEND", "redis")
    monkeypatch.setattr(backend_main, "_get_redis_client", lambda: None)

    with pytest.raises(HTTPException) as exc_info:
        backend_main._enforce_rate_limit("user:test", 10)
    assert exc_info.value.status_code == 503
    assert "Redis connection failed" in exc_info.value.detail


def test_rate_limiting_succeeds_in_testing_fallback(monkeypatch):
    monkeypatch.setattr(backend_main, "_is_testing_env", lambda: True)
    monkeypatch.setattr(backend_main, "_is_production_env", lambda: False)
    monkeypatch.setattr(backend_main, "_use_distributed_rate_limit", lambda: False)
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})

    # Should not raise
    backend_main._enforce_rate_limit("user:test_fallback", 10)
    assert "user:test_fallback" in backend_main._rate_limit_state


def test_redis_required_in_production_lockout(monkeypatch):
    monkeypatch.setattr(backend_main, "_is_testing_env", lambda: False)
    monkeypatch.setattr(backend_main, "_is_production_env", lambda: True)
    monkeypatch.setattr(backend_main, "_get_redis_client", lambda: None)

    with pytest.raises(HTTPException) as exc_info:
        backend_main._get_lockout_entry("test_user")
    assert exc_info.value.status_code == 503
    assert "Redis is required in production" in exc_info.value.detail

    with pytest.raises(HTTPException) as exc_info:
        backend_main._set_lockout_entry("test_user", 1.0, 1000.0)
    assert exc_info.value.status_code == 503
    assert "Redis is required in production" in exc_info.value.detail

    with pytest.raises(HTTPException) as exc_info:
        backend_main._delete_lockout_entry("test_user")
    assert exc_info.value.status_code == 503
    assert "Redis is required in production" in exc_info.value.detail
