import base64
import pytest
from fastapi.testclient import TestClient

import backend.main as backend_main


def _basic_auth_headers(username: str = "admin", password: str = "guardian_default"):
    token = base64.b64encode(f"{username}:{password}".encode("utf-8")).decode("ascii")
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
def auth_client(tmp_path, monkeypatch):
    """Provides an authenticated TestClient with an isolated test database."""
    db_path = tmp_path / "test_mera_memory_routes.db"
    monkeypatch.setattr(backend_main, "DB_PATH", str(db_path))
    monkeypatch.setattr(backend_main, "_rate_limit_state", {})
    backend_main.init_db()

    client = TestClient(backend_main.app)
    token_res = client.post("/api/v1/auth/token", headers=_basic_auth_headers())
    assert token_res.status_code == 200
    token = token_res.json()["access_token"]
    bearer = {"Authorization": f"Bearer {token}"}
    return client, bearer


class TestMeraMemoryRoutes:
    def test_store_and_retrieve_encrypted_memory(self, auth_client):
        """Valid encrypted memory blob is blind-stored and retrieved accurately."""
        client, headers = auth_client
        agent_id = "sentinel-live-01"

        raw_ciphertext = b"encrypted_payload_bytes_32_chars_long_!"
        raw_iv = b"123456789012"  # Exact 12 bytes
        aad = f"{agent_id}:session-live:1:1789220000"

        payload = {
            "agent_id": agent_id,
            "session_id": "session-live",
            "seq_no": 1,
            "ciphertext_b64": base64.b64encode(raw_ciphertext).decode(),
            "iv_b64": base64.b64encode(raw_iv).decode(),
            "aad": aad,
            "timestamp": 1789220000.0,
        }

        # Store
        res = client.post("/api/v1/passport/memory", json=payload, headers=headers)
        assert res.status_code == 200
        data = res.json()
        assert data["stored"] is True
        assert data["agent_id"] == agent_id
        assert data["ciphertext_size"] == len(raw_ciphertext)

        # Retrieve
        get_res = client.get(f"/api/v1/passport/memory/{agent_id}", headers=headers)
        assert get_res.status_code == 200
        memories = get_res.json()["memories"]
        assert len(memories) == 1
        assert memories[0]["agent_id"] == agent_id
        assert memories[0]["session_id"] == "session-live"
        assert memories[0]["seq_no"] == 1
        assert memories[0]["aad"] == aad
        assert base64.b64decode(memories[0]["ciphertext_b64"]) == raw_ciphertext
        assert base64.b64decode(memories[0]["iv_b64"]) == raw_iv

    def test_unauthenticated_request_rejected(self, auth_client):
        """Unauthenticated requests are rejected with 401."""
        client, _ = auth_client
        res = client.get("/api/v1/passport/memory/some-agent")
        assert res.status_code == 401

        store_res = client.post("/api/v1/passport/memory", json={})
        assert store_res.status_code == 401

    def test_missing_required_fields_returns_400(self, auth_client):
        """Missing mandatory fields returns 400 Bad Request."""
        client, headers = auth_client
        incomplete_payload = {
            "agent_id": "sentinel-01",
            "session_id": "sess-1",
            # missing ciphertext_b64, iv_b64, aad, timestamp
        }
        res = client.post("/api/v1/passport/memory", json=incomplete_payload, headers=headers)
        assert res.status_code == 400
        assert "Missing required field" in res.json()["detail"]

    def test_invalid_base64_returns_400(self, auth_client):
        """Corrupt base64 encoding returns 400."""
        client, headers = auth_client
        corrupt_payload = {
            "agent_id": "sentinel-01",
            "session_id": "sess-1",
            "seq_no": 1,
            "ciphertext_b64": "!!!not_valid_base64@@@",
            "iv_b64": base64.b64encode(b"123456789012").decode(),
            "aad": "aad",
            "timestamp": 100.0,
        }
        res = client.post("/api/v1/passport/memory", json=corrupt_payload, headers=headers)
        assert res.status_code == 400
        assert "Invalid base64" in res.json()["detail"]

    def test_non_12_byte_iv_returns_400(self, auth_client):
        """IV of invalid length (e.g. 16 bytes or 8 bytes) is rejected for AES-GCM."""
        client, headers = auth_client
        wrong_iv_payload = {
            "agent_id": "sentinel-01",
            "session_id": "sess-1",
            "seq_no": 1,
            "ciphertext_b64": base64.b64encode(b"ciphertext").decode(),
            "iv_b64": base64.b64encode(b"12345678").decode(),  # 8 bytes instead of 12
            "aad": "aad",
            "timestamp": 100.0,
        }
        res = client.post("/api/v1/passport/memory", json=wrong_iv_payload, headers=headers)
        assert res.status_code == 400
        assert "IV must be exactly 12 bytes" in res.json()["detail"]

    def test_tamper_endpoint_alters_ciphertext(self, auth_client):
        """The /tamper endpoint flips a byte in SQLite, simulating a database-level breach."""
        client, headers = auth_client
        agent_id = "agent-to-tamper"
        raw_ciphertext = b"original_unpoisoned_bytes"

        client.post(
            "/api/v1/passport/memory",
            json={
                "agent_id": agent_id,
                "session_id": "sess-tamper",
                "seq_no": 1,
                "ciphertext_b64": base64.b64encode(raw_ciphertext).decode(),
                "iv_b64": base64.b64encode(b"123456789012").decode(),
                "aad": "aad",
                "timestamp": 100.0,
            },
            headers=headers,
        )

        # Trigger tamper
        tamper_res = client.post(f"/api/v1/passport/memory/{agent_id}/tamper", headers=headers)
        assert tamper_res.status_code == 200
        assert tamper_res.json()["tampered"] is True

        # Fetch and verify ciphertext was altered
        get_res = client.get(f"/api/v1/passport/memory/{agent_id}", headers=headers)
        tampered_ciphertext = base64.b64decode(get_res.json()["memories"][0]["ciphertext_b64"])
        assert tampered_ciphertext != raw_ciphertext
        assert tampered_ciphertext[0] == raw_ciphertext[0] ^ 0xFF

    def test_multi_record_sequence_and_agent_isolation(self, auth_client):
        """Multiple sequential records are stored and partitioned by agent."""
        client, headers = auth_client

        # Store 3 records for Agent A
        for seq in [1, 2, 3]:
            client.post(
                "/api/v1/passport/memory",
                json={
                    "agent_id": "agent-A",
                    "session_id": "sess-A",
                    "seq_no": seq,
                    "ciphertext_b64": base64.b64encode(f"data_A_{seq}".encode()).decode(),
                    "iv_b64": base64.b64encode(b"123456789012").decode(),
                    "aad": f"agent-A:sess-A:{seq}",
                    "timestamp": 1000.0 + seq,
                },
                headers=headers,
            )

        # Store 1 record for Agent B
        client.post(
            "/api/v1/passport/memory",
            json={
                "agent_id": "agent-B",
                "session_id": "sess-B",
                "seq_no": 1,
                "ciphertext_b64": base64.b64encode(b"data_B_1").decode(),
                "iv_b64": base64.b64encode(b"123456789012").decode(),
                "aad": "agent-B:sess-B:1",
                "timestamp": 2000.0,
            },
            headers=headers,
        )

        # Query Agent A
        res_A = client.get("/api/v1/passport/memory/agent-A", headers=headers)
        memories_A = res_A.json()["memories"]
        assert len(memories_A) == 3
        assert [m["seq_no"] for m in memories_A] == [1, 2, 3]

        # Query Agent B
        res_B = client.get("/api/v1/passport/memory/agent-B", headers=headers)
        memories_B = res_B.json()["memories"]
        assert len(memories_B) == 1
        assert memories_B[0]["agent_id"] == "agent-B"
