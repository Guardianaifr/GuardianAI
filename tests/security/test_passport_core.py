"""
Tests for the PassportEngine — agent identity lifecycle management.
"""

import os
import sqlite3
import time
import pytest

from guardian.passport.passport_core import (
    AgentPassport,
    PassportEngine,
    classify_tier,
    _generate_passport_id,
)


@pytest.fixture
def db_path(tmp_path):
    """Create a temporary database path for testing."""
    return str(tmp_path / "test_passport.db")


@pytest.fixture
def engine(db_path):
    """Create a PassportEngine with a temporary database."""
    return PassportEngine(db_path=db_path)


class TestClassifyTier:
    def test_diamond(self):
        assert classify_tier(90.0) == "DIAMOND"
        assert classify_tier(100.0) == "DIAMOND"
        assert classify_tier(95.5) == "DIAMOND"

    def test_gold(self):
        assert classify_tier(75.0) == "GOLD"
        assert classify_tier(89.9) == "GOLD"

    def test_silver(self):
        assert classify_tier(50.0) == "SILVER"
        assert classify_tier(74.9) == "SILVER"

    def test_unverified(self):
        assert classify_tier(0.0) == "UNVERIFIED"
        assert classify_tier(49.9) == "UNVERIFIED"


class TestPassportIdGeneration:
    def test_deterministic(self):
        """Same inputs always produce the same passport ID."""
        id1 = _generate_passport_id("agent-1", "0xabc", "base")
        id2 = _generate_passport_id("agent-1", "0xabc", "base")
        assert id1 == id2

    def test_different_inputs(self):
        """Different inputs produce different passport IDs."""
        id1 = _generate_passport_id("agent-1", "0xabc", "base")
        id2 = _generate_passport_id("agent-2", "0xabc", "base")
        assert id1 != id2

    def test_hex_format(self):
        """Passport ID is a valid hex string."""
        pid = _generate_passport_id("agent-1", "0xabc", "base")
        assert len(pid) == 64  # SHA-256 hex
        int(pid, 16)  # Should not raise


class TestPassportEngine:
    def test_issue_passport(self, engine):
        """Issue a passport and verify all fields are populated."""
        passport = engine.issue_passport("agent-1", "0xabc123", "base")
        assert isinstance(passport, AgentPassport)
        assert passport.agent_id == "agent-1"
        assert passport.owner_pubkey == "0xabc123"
        assert passport.chain_id == "base"
        assert passport.trust_score == 0.0
        assert passport.tier == "UNVERIFIED"
        assert passport.is_active is True
        assert passport.issued_at > 0
        assert len(passport.passport_id) == 64

    def test_issue_passport_deterministic_id(self, engine):
        """Same agent produces same passport ID."""
        p1 = engine.issue_passport("agent-1", "0xabc", "base")
        expected_id = _generate_passport_id("agent-1", "0xabc", "base")
        assert p1.passport_id == expected_id

    def test_get_passport(self, engine):
        """Retrieve an issued passport."""
        engine.issue_passport("agent-1", "0xabc", "base")
        passport = engine.get_passport("agent-1")
        assert passport is not None
        assert passport.agent_id == "agent-1"

    def test_get_passport_not_found(self, engine):
        """Returns None for non-existent agent."""
        assert engine.get_passport("nonexistent") is None

    def test_update_trust_score(self, engine):
        """Update trust score and verify tier changes."""
        engine.issue_passport("agent-1", "0xabc", "base")
        result = engine.update_trust_score("agent-1", 92.5)
        assert result is True

        passport = engine.get_passport("agent-1")
        assert passport.trust_score == 92.5
        assert passport.tier == "DIAMOND"

    def test_update_trust_score_nonexistent(self, engine):
        """Updating score for nonexistent agent returns False."""
        result = engine.update_trust_score("nonexistent", 50.0)
        assert result is False

    def test_revoke_passport(self, engine):
        """Revoke and verify is_active=False."""
        engine.issue_passport("agent-1", "0xabc", "base")
        result = engine.revoke_passport("agent-1")
        assert result is True

        passport = engine.get_passport("agent-1")
        assert passport.is_active is False

    def test_revoke_already_revoked(self, engine):
        """Revoking a non-existent passport returns False."""
        result = engine.revoke_passport("nonexistent")
        assert result is False

    def test_revoke_twice(self, engine):
        """Revoking same passport twice: second returns False."""
        engine.issue_passport("agent-1", "0xabc", "base")
        assert engine.revoke_passport("agent-1") is True
        assert engine.revoke_passport("agent-1") is False

    def test_duplicate_issuance(self, engine):
        """Issuing same agent twice returns existing passport."""
        p1 = engine.issue_passport("agent-1", "0xabc", "base")
        p2 = engine.issue_passport("agent-1", "0xabc", "base")
        assert p1.passport_id == p2.passport_id

    def test_list_passports(self, engine):
        """List passports with limit."""
        for i in range(5):
            engine.issue_passport(f"agent-{i}", f"0x{i}", "base")
        passports = engine.list_passports(limit=3)
        assert len(passports) == 3

    def test_list_passports_active_only(self, engine):
        """List only active passports."""
        engine.issue_passport("agent-1", "0x1", "base")
        engine.issue_passport("agent-2", "0x2", "base")
        engine.revoke_passport("agent-2")

        active = engine.list_passports(active_only=True)
        assert len(active) == 1
        assert active[0].agent_id == "agent-1"

    def test_get_leaderboard(self, engine):
        """Leaderboard sorted by trust_score descending."""
        engine.issue_passport("agent-a", "0xa", "base")
        engine.issue_passport("agent-b", "0xb", "base")
        engine.issue_passport("agent-c", "0xc", "base")

        engine.update_trust_score("agent-a", 50.0)
        engine.update_trust_score("agent-b", 90.0)
        engine.update_trust_score("agent-c", 75.0)

        leaders = engine.get_leaderboard(limit=3)
        assert len(leaders) == 3
        assert leaders[0].agent_id == "agent-b"
        assert leaders[0].trust_score == 90.0
        assert leaders[1].agent_id == "agent-c"
        assert leaders[2].agent_id == "agent-a"

    def test_add_credential(self, engine):
        """Attach a credential to a passport."""
        engine.issue_passport("agent-1", "0xabc", "base")
        cred_data = {"type": "GuardianAI:SecurityAudit", "score": 85}
        result = engine.add_credential("agent-1", cred_data)
        assert result is True

        passport = engine.get_passport("agent-1")
        assert len(passport.credentials) == 1
        assert passport.credentials[0]["type"] == "GuardianAI:SecurityAudit"

    def test_passport_to_dict(self, engine):
        """Verify to_dict produces a complete dictionary."""
        passport = engine.issue_passport("agent-1", "0xabc", "base")
        d = passport.to_dict()
        assert isinstance(d, dict)
        assert "passport_id" in d
        assert "agent_id" in d
        assert "trust_score" in d
        assert "tier" in d
        assert "is_active" in d

    def test_metadata_preserved(self, engine):
        """Custom metadata is preserved."""
        meta = {"name": "My Agent", "version": "2.0"}
        passport = engine.issue_passport("agent-1", "0xabc", metadata=meta)
        assert passport.metadata["name"] == "My Agent"
        assert passport.metadata["version"] == "2.0"

    def test_update_cortex_status_persists_metadata_and_boost(self, engine):
        """Cortex transparency fields are persisted on passports."""
        engine.issue_passport("agent-1", "0xabc", "base")
        engine.update_trust_score("agent-1", 70.0)
        engine._BOOST_COOLDOWN_SECONDS = 0

        updated = engine.update_cortex_status(
            "agent-1",
            cortex_events_count=42,
            last_anchor_tx="0xabc123",
            trust_boost=2.5,
        )

        passport = engine.get_passport("agent-1")
        assert updated is True
        assert passport.cortex_events_count == 42
        assert passport.last_anchor_tx == "0xabc123"
        assert passport.trust_score == 72.5
