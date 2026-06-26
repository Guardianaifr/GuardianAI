import base64
import json
import sqlite3
import time

from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str, password: str):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


def _setup_db(tmp_path, monkeypatch):
    db_path = tmp_path / "agentic_control_plane.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    monkeypatch.setattr(
        backend_main,
        "_auth_users",
        {
            "admin": {"password": "admin-pass", "role": "admin"},
            "auditor": {"password": "auditor-pass", "role": "auditor"},
            "user1": {"password": "user-pass", "role": "user"},
        },
    )
    backend_main.init_db()
    return db_path


def test_agentic_key_lifecycle_and_config_snapshot(tmp_path, monkeypatch):
    _setup_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)
    admin = _basic_auth_headers("admin", "admin-pass")
    auditor = _basic_auth_headers("auditor", "auditor-pass")

    created = client.post(
        "/api/v1/agentic/keys",
        headers=admin,
        json={"agent_id": "agent-a", "key_id": "key-1", "cert_fingerprints": ["AA:BB:CC"]},
    )
    assert created.status_code == 200
    body = created.json()
    assert body["agent_id"] == "agent-a"
    assert body["key_id"] == "key-1"
    assert body["key_secret"].startswith("ga_")
    assert body["cert_fingerprints"] == ["aabbcc"]

    listed = client.get("/api/v1/agentic/keys", headers=auditor)
    assert listed.status_code == 200
    assert listed.json()[0]["key_secret_hash"]
    assert "key_secret" not in listed.json()[0]

    snapshot = client.get("/api/v1/agentic/config-snapshot", headers=admin)
    assert snapshot.status_code == 200
    assert snapshot.json()["agent_attestation_keys"]["agent-a"]["key-1"] == body["key_secret"]
    assert snapshot.json()["agent_cert_fingerprints"]["agent-a"] == ["aabbcc"]

    auditor_snapshot = client.get("/api/v1/agentic/config-snapshot", headers=auditor)
    assert auditor_snapshot.status_code == 403

    rotated = client.post(f"/api/v1/agentic/keys/{body['id']}/rotate", headers=admin)
    assert rotated.status_code == 200
    assert rotated.json()["key_secret"] != body["key_secret"]

    revoked = client.post(
        "/api/v1/agentic/revocations",
        headers=admin,
        json={"agent_id": "agent-a", "key_id": "key-1", "reason": "compromised"},
    )
    assert revoked.status_code == 200
    assert revoked.json()["affected_keys"] == 1

    snapshot_after_revoke = client.get("/api/v1/agentic/config-snapshot", headers=admin).json()
    assert "key-1" in snapshot_after_revoke["revoked_agent_key_ids"]
    assert "agent-a" not in snapshot_after_revoke["agent_attestation_keys"]


def test_agentic_grants_policy_graph_and_metrics(tmp_path, monkeypatch):
    db_path = _setup_db(tmp_path, monkeypatch)
    client = TestClient(backend_main.app)
    admin = _basic_auth_headers("admin", "admin-pass")
    auditor = _basic_auth_headers("auditor", "auditor-pass")

    edge = client.post(
        "/api/v1/agentic/policy-edges",
        headers=admin,
        json={
            "parent_agent": "parent-a",
            "child_agent": "child-a",
            "scopes": ["read_only"],
            "tools": ["search_docs"],
            "max_hops": 2,
        },
    )
    assert edge.status_code == 200

    grant = client.post(
        "/api/v1/agentic/grants",
        headers=admin,
        json={
            "execution_id": "exec-1",
            "agent_id": "child-a",
            "parent_agent": "parent-a",
            "scopes": ["read_only"],
            "tools": ["search_docs"],
            "ttl_seconds": 600,
        },
    )
    assert grant.status_code == 200
    assert grant.json()["expires_at"] > time.time()

    snapshot = client.get("/api/v1/agentic/config-snapshot", headers=admin).json()
    assert snapshot["cross_agent_policy_graph"]["parent-a"]["children"]["child-a"]["tools"] == ["search_docs"]
    assert snapshot["execution_grants"]["exec-1"]["agent_id"] == "child-a"

    conn = sqlite3.connect(str(db_path))
    conn.execute(
        "INSERT INTO security_events (guardian_id, tenant_id, event_type, severity, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        (
            "g1",
            "default",
            "agentic_policy_block",
            "HIGH",
            json.dumps({"reason": "untrusted_mcp_server"}),
            time.time(),
        ),
    )
    conn.execute(
        "INSERT INTO security_events (guardian_id, tenant_id, event_type, severity, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        (
            "g1",
            "default",
            "agentic_policy_block",
            "HIGH",
            json.dumps({"reason": "scope_escalation_detected"}),
            time.time(),
        ),
    )
    conn.commit()
    conn.close()

    metrics = client.get("/api/v1/agentic/metrics", headers=auditor)
    assert metrics.status_code == 200
    metrics_body = metrics.json()
    assert metrics_body["unauthorized_mcp_server_attempts"] == 1
    assert metrics_body["scope_escalation_attempts_blocked"] == 1
    assert metrics_body["active_execution_grants"] == 1

    prometheus = client.get("/metrics")
    assert prometheus.status_code == 200
    assert "guardian_agentic_unauthorized_mcp_server_attempts 1" in prometheus.text

    revoked = client.post("/api/v1/agentic/grants/exec-1/revoke?reason=done", headers=admin)
    assert revoked.status_code == 200
    active = client.get("/api/v1/agentic/grants?active_only=true", headers=auditor)
    assert active.status_code == 200
    assert active.json() == []
