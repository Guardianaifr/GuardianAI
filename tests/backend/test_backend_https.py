from fastapi.testclient import TestClient

import backend.main as backend_main


def test_is_https_request_by_scheme():
    assert backend_main._is_https_request("https", "") is True
    assert backend_main._is_https_request("http", "") is False


def test_is_https_request_by_forwarded_proto():
    assert backend_main._is_https_request("http", "https") is True
    assert backend_main._is_https_request("http", "http, https") is True
    assert backend_main._is_https_request("http", "http") is False


def test_https_middleware_blocks_plain_http_when_enabled(monkeypatch):
    monkeypatch.setattr(backend_main, "ENFORCE_HTTPS", True)
    client = TestClient(backend_main.app)
    response = client.get("/health")
    assert response.status_code == 400
    assert "HTTPS required" in response.json()["detail"]


def test_https_middleware_allows_forwarded_https_when_enabled(monkeypatch):
    monkeypatch.setattr(backend_main, "ENFORCE_HTTPS", True)
    client = TestClient(backend_main.app)
    response = client.get("/health", headers={"x-forwarded-proto": "https"})
    assert response.status_code == 200
    assert response.json()["status"] == "healthy"


def test_https_middleware_allows_http_when_disabled(monkeypatch):
    monkeypatch.setattr(backend_main, "ENFORCE_HTTPS", False)
    client = TestClient(backend_main.app)
    response = client.get("/health")
    assert response.status_code == 200
