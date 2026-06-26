"""
Tests for InsuranceCertificateGenerator — certificate generation,
risk assessment, and data aggregation.
"""

import time
import sqlite3
import pytest

from guardian.cortex.insurance import InsuranceCertificateGenerator, InsuranceCertificate
from guardian.cortex.cortex_engine import CortexEngine
from guardian.cortex.interlock import InterlockProtocol


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_insurance.db")


@pytest.fixture
def engine(db_path):
    return CortexEngine(db_path=db_path)


@pytest.fixture
def interlock(db_path):
    return InterlockProtocol(db_path=db_path)


@pytest.fixture
def generator(db_path):
    CortexEngine(db_path=db_path)
    InterlockProtocol(db_path=db_path)
    return InsuranceCertificateGenerator(db_path=db_path)


def _seed_events(engine, agent_id: str, count: int = 20, event_types=None):
    """Seed test events into the Cortex."""
    types = event_types or ["decision", "llm_call", "tool_invocation"]
    for i in range(count):
        engine.record_event(
            agent_id=agent_id,
            event_type=types[i % len(types)],
            action=f"action-{i}",
            confidence=0.8 + (i % 5) * 0.04,
        )


class TestCertificateGeneration:

    def test_generate_empty_certificate(self, generator, engine):
        """Certificate for agent with no events."""
        now = time.time()
        cert = generator.generate_certificate(
            agent_id="empty-agent",
            period_start=now - 86400,
            period_end=now,
        )
        assert cert.certificate_id != ""
        assert cert.total_events == 0
        assert cert.risk_level == "UNKNOWN"

    def test_generate_with_events(self, generator, engine):
        """Certificate with seeded events."""
        _seed_events(engine, "agent-1", count=30)
        now = time.time()
        cert = generator.generate_certificate(
            agent_id="agent-1",
            period_start=now - 86400,
            period_end=now + 1,
        )
        assert cert.total_events == 30
        assert cert.total_decisions == 10  # 30 / 3 event types
        assert "decision" in cert.event_type_breakdown
        assert "llm_call" in cert.event_type_breakdown

    def test_certificate_has_id_and_signature(self, generator, engine):
        _seed_events(engine, "agent-1", count=5)
        now = time.time()
        cert = generator.generate_certificate(
            agent_id="agent-1",
            period_start=now - 86400,
            period_end=now + 1,
        )
        assert cert.data_hash != ""
        assert cert.certificate_signature != ""
        assert len(cert.data_hash) == 64  # SHA-256 hex

    def test_certificate_with_trust_score(self, generator, engine):
        _seed_events(engine, "agent-1", count=10)
        now = time.time()
        cert = generator.generate_certificate(
            agent_id="agent-1",
            period_start=now - 86400,
            period_end=now + 1,
            trust_score=94.2,
            trust_tier="DIAMOND",
        )
        assert cert.trust_score == 94.2
        assert cert.trust_tier == "DIAMOND"

    def test_certificate_includes_anchors(self, generator, engine):
        _seed_events(engine, "agent-1", count=10)
        now = time.time()
        # Save an anchor
        engine.save_anchor(
            agent_id="agent-1",
            merkle_root="0xfake",
            event_count=10,
            period_start=now - 86400,
            period_end=now,
            chain_id="monad",
            tx_hash="0xtx",
        )
        cert = generator.generate_certificate(
            agent_id="agent-1",
            period_start=now - 86400,
            period_end=now + 1,
        )
        assert cert.merkle_anchors == 1
        assert "monad" in cert.chains_used

    def test_certificate_includes_interlocks(self, generator, engine, interlock):
        _seed_events(engine, "agent-1", count=5)
        interlock.create_interlock("agent-1", "agent-2")
        interlock.create_interlock("agent-1", "agent-3")

        now = time.time()
        cert = generator.generate_certificate(
            agent_id="agent-1",
            period_start=now - 86400,
            period_end=now + 1,
        )
        assert cert.cross_agent_interlocks == 2

    def test_certificate_serialization(self, generator, engine):
        _seed_events(engine, "agent-1", count=5)
        now = time.time()
        cert = generator.generate_certificate(
            agent_id="agent-1",
            period_start=now - 86400,
            period_end=now + 1,
        )
        d = cert.to_dict()
        assert "certificate_id" in d
        assert "risk_level" in d
        assert "coverage_recommendation" in d
        assert "event_type_breakdown" in d


class TestRiskAssessment:

    def test_unknown_risk_no_events(self, generator, engine):
        now = time.time()
        cert = generator.generate_certificate(
            agent_id="agent-1",
            period_start=now - 86400,
            period_end=now,
        )
        assert cert.risk_level == "UNKNOWN"

    def test_low_risk_high_trust(self, generator, engine):
        """High trust + anchors + activity = LOW risk."""
        _seed_events(engine, "agent-1", count=50)
        now = time.time()
        # Add daily anchors
        for d in range(30):
            engine.save_anchor(
                agent_id="agent-1",
                merkle_root=f"0x{d:064x}",
                event_count=10,
                period_start=now - (d + 1) * 86400,
                period_end=now - d * 86400,
                chain_id="monad",
            )
        cert = generator.generate_certificate(
            agent_id="agent-1",
            period_start=now - 30 * 86400,
            period_end=now + 1,
            trust_score=95.0,
        )
        assert cert.risk_level == "LOW"

    def test_high_risk_low_trust(self, generator, engine):
        """Low trust + no anchors = HIGH risk."""
        _seed_events(engine, "agent-1", count=3,
                     event_types=["policy_gate", "decision", "policy_gate"])
        now = time.time()
        cert = generator.generate_certificate(
            agent_id="agent-1",
            period_start=now - 86400,
            period_end=now + 1,
            trust_score=15.0,
        )
        assert cert.risk_level == "HIGH"

    def test_coverage_recommendation_populated(self, generator, engine):
        _seed_events(engine, "agent-1", count=5)
        now = time.time()
        cert = generator.generate_certificate(
            agent_id="agent-1",
            period_start=now - 86400,
            period_end=now + 1,
        )
        assert cert.coverage_recommendation != ""
        assert len(cert.coverage_recommendation) > 20
