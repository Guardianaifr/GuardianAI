from fastapi.testclient import TestClient

import backend.main as backend_main


def test_health_endpoint_reports_components(tmp_path, monkeypatch):
    db_path = tmp_path / "health_ok.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    backend_main.init_db()

    client = TestClient(backend_main.app)
    response = client.get("/health")
    assert response.status_code == 200

    body = response.json()
    assert body["status"] == "healthy"
    assert "uptime_sec" in body
    assert body["components"]["database"]["ok"] is True
    assert "metrics_enabled" in body["components"]
    assert "https_enforced" in body["components"]


def test_health_endpoint_returns_503_when_db_unavailable(tmp_path, monkeypatch):
    # Point DB_PATH to a directory to force sqlite connect failure.
    monkeypatch.setattr(backend_main, "DB_PATH", str(tmp_path))

    client = TestClient(backend_main.app)
    response = client.get("/health")
    assert response.status_code == 503

    body = response.json()
    assert body["status"] == "unhealthy"
    assert body["components"]["database"]["ok"] is False
