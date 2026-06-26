import importlib
import sys
from pathlib import Path

from fastapi.testclient import TestClient


def _load_backend(monkeypatch, tmp_path: Path, dp_enabled: bool = False, dp_epsilon: float = 1.0, dp_seed: int | None = None):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("GUARDIAN_ADMIN_USER", "admin")
    monkeypatch.setenv("GUARDIAN_ADMIN_PASS", "guardian_default")
    monkeypatch.delenv("GUARDIAN_BACKEND_TOKEN", raising=False)
    monkeypatch.delenv("GUARDIAN_SERVICE_AUTH_TOKEN", raising=False)
    monkeypatch.setenv("GUARDIAN_SERVICE_ID", "guardian-proxy")
    monkeypatch.delenv("GUARDIAN_SIEM_ENABLED", raising=False)
    if dp_enabled:
        monkeypatch.setenv("GUARDIAN_DP_ENABLED", "true")
        monkeypatch.setenv("GUARDIAN_DP_EPSILON", str(dp_epsilon))
        if dp_seed is None:
            monkeypatch.delenv("GUARDIAN_DP_SEED", raising=False)
        else:
            monkeypatch.setenv("GUARDIAN_DP_SEED", str(dp_seed))
    else:
        monkeypatch.delenv("GUARDIAN_DP_ENABLED", raising=False)
        monkeypatch.delenv("GUARDIAN_DP_EPSILON", raising=False)
        monkeypatch.delenv("GUARDIAN_DP_SEED", raising=False)

    sys.modules.pop("backend.main", None)
    module = importlib.import_module("backend.main")
    return importlib.reload(module)


def test_backend_persists_and_filters_tenant_scoped_events(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path)
    client = TestClient(backend.app)

    base = {
        "guardian_id": "g-1",
        "event_type": "allowed_request",
        "severity": "LOW",
        "details": {"path": "fast_path_allowlist", "latency_ms": "1.0ms"},
        "timestamp": 0.0,
    }
    r1 = client.post("/api/v1/telemetry", json={**base, "tenant_id": "tenant-a"})
    r2 = client.post("/api/v1/telemetry", json={**base, "tenant_id": "tenant-b"})
    assert r1.status_code == 200
    assert r2.status_code == 200

    events_a = client.get("/api/v1/events?tenant_id=tenant-a", auth=("admin", "guardian_default"))
    assert events_a.status_code == 200
    rows_a = events_a.json()
    assert len(rows_a) == 1
    assert rows_a[0]["tenant_id"] == "tenant-a"

    events_b = client.get("/api/v1/events?tenant_id=tenant-b", auth=("admin", "guardian_default"))
    assert events_b.status_code == 200
    rows_b = events_b.json()
    assert len(rows_b) == 1
    assert rows_b[0]["tenant_id"] == "tenant-b"


def test_backend_analytics_can_scope_by_tenant(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path)
    client = TestClient(backend.app)

    payload = {
        "guardian_id": "g-1",
        "event_type": "allowed_request",
        "severity": "LOW",
        "details": {"path": "fast_path_allowlist", "latency_ms": "5.0ms"},
        "timestamp": 0.0,
    }
    client.post("/api/v1/telemetry", json={**payload, "tenant_id": "tenant-x"})
    client.post("/api/v1/telemetry", json={**payload, "tenant_id": "tenant-y"})

    scoped = client.get("/api/v1/analytics?tenant_id=tenant-x", auth=("admin", "guardian_default"))
    assert scoped.status_code == 200
    body = scoped.json()
    assert body["total_requests"] == 1


def test_backend_can_delete_tenant_data(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path)
    client = TestClient(backend.app)

    payload = {
        "guardian_id": "g-1",
        "tenant_id": "tenant-z",
        "event_type": "allowed_request",
        "severity": "LOW",
        "details": {"path": "fast_path_allowlist", "latency_ms": "5.0ms"},
        "timestamp": 0.0,
    }
    client.post("/api/v1/telemetry", json=payload)

    before = client.get("/api/v1/events?tenant_id=tenant-z", auth=("admin", "guardian_default"))
    assert len(before.json()) == 1

    deleted = client.delete("/api/v1/admin/tenant-data?tenant_id=tenant-z", auth=("admin", "guardian_default"))
    assert deleted.status_code == 200
    assert deleted.json()["deleted_security_events"] >= 1

    after = client.get("/api/v1/events?tenant_id=tenant-z", auth=("admin", "guardian_default"))
    assert after.status_code == 200
    assert after.json() == []


def test_backend_analytics_dp_noise_enabled(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path, dp_enabled=True, dp_epsilon=0.7, dp_seed=7)
    client = TestClient(backend.app)

    payload = {
        "guardian_id": "g-1",
        "event_type": "allowed_request",
        "severity": "LOW",
        "details": {"path": "fast_path_allowlist", "latency_ms": "5.0ms"},
        "timestamp": 0.0,
    }
    client.post("/api/v1/telemetry", json={**payload, "tenant_id": "tenant-dp"})
    client.post("/api/v1/telemetry", json={**payload, "tenant_id": "tenant-dp"})

    resp = client.get("/api/v1/analytics?tenant_id=tenant-dp", auth=("admin", "guardian_default"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["differential_privacy"]["enabled"] is True
    assert body["differential_privacy"]["mechanism"] == "laplace"
    assert body["differential_privacy"]["epsilon"] == 0.7


def test_backend_analytics_dp_can_be_overridden_off(monkeypatch, tmp_path):
    backend = _load_backend(monkeypatch, tmp_path, dp_enabled=True, dp_epsilon=0.7, dp_seed=7)
    client = TestClient(backend.app)

    payload = {
        "guardian_id": "g-1",
        "event_type": "allowed_request",
        "severity": "LOW",
        "details": {"path": "fast_path_allowlist", "latency_ms": "5.0ms"},
        "timestamp": 0.0,
    }
    client.post("/api/v1/telemetry", json={**payload, "tenant_id": "tenant-dp2"})

    resp = client.get("/api/v1/analytics?tenant_id=tenant-dp2&dp=false", auth=("admin", "guardian_default"))
    assert resp.status_code == 200
    body = resp.json()
    assert body["differential_privacy"]["enabled"] is False
    assert body["total_requests"] == 1
