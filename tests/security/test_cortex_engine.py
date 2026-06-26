"""
Tests for CortexEngine — event recording, trial management, time-travel replay.
"""

import os
import time
import tempfile
import pytest

from guardian.cortex.cortex_engine import (
    CortexEngine, CortexEvent, EventType, PrivacyMode,
    TRIAL_DURATION_SECONDS, _sha256, _compute_merkle_leaf,
)


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "test_cortex.db")


@pytest.fixture
def engine(db_path):
    return CortexEngine(db_path=db_path, privacy_mode="hash_only")


@pytest.fixture
def engine_full_text(db_path):
    return CortexEngine(db_path=db_path, privacy_mode="full_text")


# ── Trial Management ──────────────────────────────────────────

class TestTrialManagement:

    def test_start_trial(self, engine):
        result = engine.start_trial("agent-1")
        assert result["agent_id"] == "agent-1"
        assert result["is_active"] is True
        assert result["days_remaining"] == pytest.approx(10, abs=0.1)
        assert result["already_existed"] is False

    def test_start_trial_idempotent(self, engine):
        engine.start_trial("agent-1")
        result = engine.start_trial("agent-1")
        assert result["already_existed"] is True
        assert result["is_active"] is True

    def test_check_trial_nonexistent(self, engine):
        result = engine.check_trial("unknown")
        assert result["has_trial"] is False
        assert result["is_active"] is False

    def test_trial_auto_expire(self, db_path):
        """Manually insert an expired trial and verify auto-expiry."""
        import sqlite3
        engine = CortexEngine(db_path=db_path)
        past = time.time() - 100
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO cortex_trials (agent_id, started_at, expires_at, is_active) VALUES (?, ?, ?, 1)",
            ("expired-agent", past - TRIAL_DURATION_SECONDS, past),
        )
        conn.commit()
        conn.close()

        result = engine.check_trial("expired-agent")
        assert result["has_trial"] is True
        assert result["is_active"] is False
        assert result["expired"] is True


# ── Event Recording ───────────────────────────────────────────

class TestEventRecording:

    def test_record_event_basic(self, engine):
        event = engine.record_event(
            agent_id="agent-1",
            event_type="decision",
            action="approve_transaction",
            category="finance",
            input_text="Should I approve this swap?",
            output_text="Yes, approved",
            reasoning="RSI divergence detected",
            confidence=0.87,
        )
        assert event is not None
        assert event.agent_id == "agent-1"
        assert event.event_type == "decision"
        assert event.action == "approve_transaction"
        assert event.confidence == 0.87
        assert event.merkle_leaf != ""

    def test_privacy_hash_only(self, engine):
        """In HASH_ONLY mode, reasoning_text should be empty."""
        event = engine.record_event(
            agent_id="agent-1",
            event_type="llm_call",
            reasoning="This is secret reasoning",
        )
        assert event.reasoning_text == ""
        assert event.reasoning_hash == _sha256("This is secret reasoning")

    def test_privacy_full_text(self, engine_full_text):
        """In FULL_TEXT mode, reasoning_text should be stored."""
        event = engine_full_text.record_event(
            agent_id="agent-1",
            event_type="llm_call",
            reasoning="This is visible reasoning",
        )
        assert event.reasoning_text == "This is visible reasoning"

    def test_input_output_hashed(self, engine):
        """Input and output text should always be hashed."""
        event = engine.record_event(
            agent_id="agent-1",
            event_type="tool_invocation",
            input_text="raw input data",
            output_text="raw output data",
        )
        assert event.input_hash == _sha256("raw input data")
        assert event.output_hash == _sha256("raw output data")

    def test_auto_start_trial_on_first_event(self, engine):
        """Recording an event for a new agent auto-starts trial."""
        event = engine.record_event(agent_id="new-agent", event_type="decision")
        assert event is not None
        trial = engine.check_trial("new-agent")
        assert trial["has_trial"] is True
        assert trial["is_active"] is True

    def test_recording_blocked_after_trial_expires(self, db_path):
        """Events should not be recorded after trial expiry."""
        import sqlite3
        engine = CortexEngine(db_path=db_path)
        past = time.time() - 100
        conn = sqlite3.connect(db_path)
        conn.execute(
            "INSERT INTO cortex_trials (agent_id, started_at, expires_at, is_active) VALUES (?, ?, ?, 1)",
            ("expired-agent", past - TRIAL_DURATION_SECONDS, past),
        )
        conn.commit()
        conn.close()

        event = engine.record_event(agent_id="expired-agent", event_type="decision")
        assert event is None

    def test_merkle_leaf_deterministic(self, engine):
        """Two events with same data produce different leaves (different IDs/timestamps)."""
        e1 = engine.record_event(agent_id="a", event_type="decision", action="x")
        e2 = engine.record_event(agent_id="a", event_type="decision", action="x")
        assert e1.merkle_leaf != e2.merkle_leaf

    def test_event_with_metadata(self, engine):
        event = engine.record_event(
            agent_id="agent-1",
            event_type="tool_invocation",
            action="api_call",
            metadata={"url": "https://api.example.com", "status": 200},
        )
        assert event.metadata["url"] == "https://api.example.com"

    def test_parent_event_chain(self, engine):
        """Events can reference parent events."""
        e1 = engine.record_event(agent_id="a", event_type="llm_call")
        e2 = engine.record_event(agent_id="a", event_type="decision", parent_event_id=e1.event_id)
        assert e2.parent_event_id == e1.event_id


# ── Event Retrieval ───────────────────────────────────────────

class TestEventRetrieval:

    def test_get_events(self, engine):
        for i in range(5):
            engine.record_event(agent_id="a", event_type="decision", action=f"action-{i}")
        events = engine.get_events("a")
        assert len(events) == 5

    def test_get_events_with_type_filter(self, engine):
        engine.record_event(agent_id="a", event_type="decision")
        engine.record_event(agent_id="a", event_type="llm_call")
        engine.record_event(agent_id="a", event_type="decision")
        events = engine.get_events("a", event_type="decision")
        assert len(events) == 2

    def test_get_event_by_id(self, engine):
        e = engine.record_event(agent_id="a", event_type="decision", action="test")
        retrieved = engine.get_event(e.event_id)
        assert retrieved is not None
        assert retrieved.action == "test"

    def test_get_event_nonexistent(self, engine):
        assert engine.get_event("nonexistent") is None

    def test_get_event_count(self, engine):
        for _ in range(3):
            engine.record_event(agent_id="a", event_type="decision")
        assert engine.get_event_count("a") == 3
        assert engine.get_event_count("unknown") == 0

    def test_get_event_chain(self, engine):
        e1 = engine.record_event(agent_id="a", event_type="llm_call")
        e2 = engine.record_event(agent_id="a", event_type="decision", parent_event_id=e1.event_id)
        e3 = engine.record_event(agent_id="a", event_type="tool_invocation", parent_event_id=e2.event_id)

        chain = engine.get_event_chain(e3.event_id)
        assert len(chain) == 3
        assert chain[0].event_id == e1.event_id  # Oldest first
        assert chain[2].event_id == e3.event_id


# ── Time-Travel Replay ────────────────────────────────────────

class TestReplay:

    def test_replay_empty(self, engine):
        result = engine.replay_at("unknown", time.time())
        assert result["total_events"] == 0

    def test_replay_returns_snapshot(self, engine):
        engine.record_event(agent_id="a", event_type="decision", action="d1")
        time.sleep(0.01)
        engine.record_event(agent_id="a", event_type="llm_call", action="l1")

        result = engine.replay_at("a", time.time())
        assert result["total_events"] == 2
        assert "decision" in result["event_type_counts"]
        assert "llm_call" in result["event_type_counts"]


# ── Anchor Management ─────────────────────────────────────────

class TestAnchorManagement:

    def test_get_unanchored_events(self, engine):
        for _ in range(3):
            engine.record_event(agent_id="a", event_type="decision")
        events = engine.get_unanchored_events("a")
        assert len(events) == 3

    def test_mark_events_anchored(self, engine):
        e = engine.record_event(agent_id="a", event_type="decision")
        engine.mark_events_anchored("a", [e.event_id], "0xtx123")
        events = engine.get_unanchored_events("a")
        assert len(events) == 0

    def test_save_and_get_anchors(self, engine):
        engine.save_anchor(
            agent_id="a", merkle_root="0xabc", event_count=5,
            period_start=100.0, period_end=200.0, chain_id="monad", tx_hash="0xtx1",
        )
        anchors = engine.get_anchors("a")
        assert len(anchors) == 1
        assert anchors[0]["chain_id"] == "monad"
        assert anchors[0]["merkle_root"] == "0xabc"
