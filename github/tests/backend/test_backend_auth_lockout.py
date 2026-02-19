import base64

from fastapi.testclient import TestClient

import backend.main as backend_main


class _FakeClock:
    def __init__(self, now: float = 1_700_000_000.0):
        self._now = now

    def time(self) -> float:
        return self._now

    def advance(self, seconds: float):
        self._now += seconds


def _basic_auth_headers(username: str = "admin", password: str = "guardian_default"):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _configure_lockout_state(monkeypatch):
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_ENABLED", True)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_MAX_ATTEMPTS", 2)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_DURATION_SEC", 30.0)
    monkeypatch.setattr(backend_main, "_auth_lockout_state", {})
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})


def test_auth_lockout_blocks_repeated_failed_credentials_per_source(monkeypatch):
    _configure_lockout_state(monkeypatch)
    fake_clock = _FakeClock()
    monkeypatch.setattr(backend_main.time, "time", fake_clock.time)
    client = TestClient(backend_main.app)

    fail_a = client.post(
        "/api/v1/auth/token",
        headers={**_basic_auth_headers(password="wrong-pass"), "x-forwarded-for": "10.0.0.1"},
    )
    fail_b = client.post(
        "/api/v1/auth/token",
        headers={**_basic_auth_headers(password="wrong-pass"), "x-forwarded-for": "10.0.0.1"},
    )
    assert fail_a.status_code == 401
    assert fail_b.status_code == 401

    locked = client.post(
        "/api/v1/auth/token",
        headers={**_basic_auth_headers(), "x-forwarded-for": "10.0.0.1"},
    )
    assert locked.status_code == 429
    assert "retry-after" in {k.lower() for k in locked.headers}

    different_source = client.post(
        "/api/v1/auth/token",
        headers={**_basic_auth_headers(), "x-forwarded-for": "10.0.0.2"},
    )
    assert different_source.status_code == 200

    fake_clock.advance(31.0)
    after_expiry = client.post(
        "/api/v1/auth/token",
        headers={**_basic_auth_headers(), "x-forwarded-for": "10.0.0.1"},
    )
    assert after_expiry.status_code == 200


def test_auth_lockout_can_be_disabled(monkeypatch):
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_ENABLED", False)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_MAX_ATTEMPTS", 1)
    monkeypatch.setattr(backend_main, "AUTH_LOCKOUT_DURATION_SEC", 60.0)
    monkeypatch.setattr(backend_main, "_auth_lockout_state", {})
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    client = TestClient(backend_main.app)

    fail = client.post(
        "/api/v1/auth/token",
        headers={**_basic_auth_headers(password="wrong-pass"), "x-forwarded-for": "10.0.0.9"},
    )
    assert fail.status_code == 401

    success = client.post(
        "/api/v1/auth/token",
        headers={**_basic_auth_headers(), "x-forwarded-for": "10.0.0.9"},
    )
    assert success.status_code == 200
