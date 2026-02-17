import base64

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str = "admin", password: str = "guardian_default"):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def test_auth_rate_limit_blocks_repeated_token_requests(monkeypatch):
    monkeypatch.setattr(backend_main, "AUTH_RATE_LIMIT_PER_MIN", 1)
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    client = TestClient(backend_main.app)

    first = client.post("/api/v1/auth/token", headers=_basic_auth_headers())
    assert first.status_code == 200

    second = client.post("/api/v1/auth/token", headers=_basic_auth_headers())
    assert second.status_code == 429


def test_auth_rate_limit_isolated_by_forwarded_ip(monkeypatch):
    monkeypatch.setattr(backend_main, "AUTH_RATE_LIMIT_PER_MIN", 1)
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    client = TestClient(backend_main.app)

    first = client.post(
        "/api/v1/auth/token",
        headers={**_basic_auth_headers(), "x-forwarded-for": "10.0.0.1"},
    )
    assert first.status_code == 200

    second_different_ip = client.post(
        "/api/v1/auth/token",
        headers={**_basic_auth_headers(), "x-forwarded-for": "10.0.0.2"},
    )
    assert second_different_ip.status_code == 200
