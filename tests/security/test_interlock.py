"""
Tests for InterlockProtocol — cross-agent mutual proof creation and verification.
"""

import pytest

from guardian.cortex.interlock import InterlockProtocol, InterlockProof


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_interlock.db")


@pytest.fixture
def protocol(db_path):
    return InterlockProtocol(db_path=db_path)


class TestInterlockCreation:

    def test_create_basic_interlock(self, protocol):
        proof = protocol.create_interlock(
            agent_a_id="agent-a",
            agent_b_id="agent-b",
        )
        assert proof.interlock_id != ""
        assert proof.agent_a_id == "agent-a"
        assert proof.agent_b_id == "agent-b"
        assert proof.nonce != ""
        assert proof.interaction_hash != ""
        assert proof.proof_hash != ""
        assert proof.timestamp > 0

    def test_create_interlock_with_data(self, protocol):
        proof = protocol.create_interlock(
            agent_a_id="agent-a",
            agent_b_id="agent-b",
            interaction_type="trade",
            interaction_data={"amount": 100, "token": "USDC"},
        )
        assert proof.metadata["interaction_type"] == "trade"

    def test_unique_interlock_ids(self, protocol):
        p1 = protocol.create_interlock("a", "b")
        p2 = protocol.create_interlock("a", "b")
        assert p1.interlock_id != p2.interlock_id

    def test_unique_nonces(self, protocol):
        p1 = protocol.create_interlock("a", "b")
        p2 = protocol.create_interlock("a", "b")
        assert p1.nonce != p2.nonce

    def test_interlock_with_event_ids(self, protocol):
        proof = protocol.create_interlock(
            agent_a_id="a",
            agent_b_id="b",
            agent_a_event_id="evt-111",
            agent_b_event_id="evt-222",
        )
        assert proof.agent_a_event_id == "evt-111"
        assert proof.agent_b_event_id == "evt-222"


class TestInterlockVerification:

    def test_verify_valid(self, protocol):
        proof = protocol.create_interlock("a", "b")
        result = protocol.verify_interlock(proof)
        assert result["verified"] is True
        assert result["hash_valid"] is True
        assert result["db_exists"] is True
        assert result["db_matches"] is True

    def test_verify_tampered_proof_hash(self, protocol):
        proof = protocol.create_interlock("a", "b")
        proof.proof_hash = "tampered_hash"
        result = protocol.verify_interlock(proof)
        assert result["verified"] is False
        assert result["hash_valid"] is False

    def test_verify_tampered_nonce(self, protocol):
        proof = protocol.create_interlock("a", "b")
        original_hash = proof.proof_hash
        proof.nonce = "tampered_nonce"
        # Proof hash won't match recomputed value
        result = protocol.verify_interlock(proof)
        assert result["hash_valid"] is False

    def test_verify_nonexistent_interlock(self, protocol):
        fake = InterlockProof(
            interlock_id="nonexistent",
            agent_a_id="a",
            agent_b_id="b",
            nonce="n",
            interaction_hash="h",
            timestamp=0,
            proof_hash="p",
        )
        result = protocol.verify_interlock(fake)
        assert result["db_exists"] is False
        assert result["verified"] is False


class TestInterlockRetrieval:

    def test_get_interlocks_by_agent(self, protocol):
        protocol.create_interlock("a", "b")
        protocol.create_interlock("a", "c")
        protocol.create_interlock("d", "e")

        results = protocol.get_interlocks("a")
        assert len(results) == 2

    def test_get_interlocks_as_either_party(self, protocol):
        protocol.create_interlock("x", "y")
        assert len(protocol.get_interlocks("x")) == 1
        assert len(protocol.get_interlocks("y")) == 1

    def test_get_specific_interlock(self, protocol):
        proof = protocol.create_interlock("a", "b")
        retrieved = protocol.get_interlock(proof.interlock_id)
        assert retrieved is not None
        assert retrieved.agent_a_id == "a"

    def test_get_nonexistent_interlock(self, protocol):
        assert protocol.get_interlock("nonexistent") is None

    def test_serialization(self, protocol):
        proof = protocol.create_interlock("a", "b")
        d = proof.to_dict()
        assert "interlock_id" in d
        assert "nonce" in d
        assert "proof_hash" in d
