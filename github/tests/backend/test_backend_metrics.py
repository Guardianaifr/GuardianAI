from fastapi.testclient import TestClient

import backend.main as backend_main


def test_metrics_endpoint_exposes_core_metrics(monkeypatch):
    monkeypatch.setattr(backend_main, "METRICS_ENABLED", True)
    client = TestClient(backend_main.app)

    health_response = client.get("/health")
    assert health_response.status_code == 200

    metrics_response = client.get("/metrics")
    assert metrics_response.status_code == 200
    body = metrics_response.text
    assert "guardian_http_requests_total" in body
    assert "guardian_http_request_latency_avg_ms" in body
    assert "guardian_http_requests_per_second_1m" in body
    assert "guardian_process_cpu_percent" in body
    assert "guardian_process_memory_bytes" in body


def test_metrics_endpoint_disabled_returns_404(monkeypatch):
    monkeypatch.setattr(backend_main, "METRICS_ENABLED", False)
    client = TestClient(backend_main.app)

    response = client.get("/metrics")
    assert response.status_code == 404
    assert response.json()["detail"] == "Metrics disabled"
