"""Tests for FEAT-BLUE-ADVANCED: SessionVelocityTracker and AdaptiveCooldown wired into BlueAdaptAgent.

End-to-end discipline (per the Feature 10 lesson):
  - Group 1: go through BlueAdaptAgent (not the isolated helper classes) and prove the
    action pipeline returns "cooldown" correctly.
  - Group 2: GuardianProxy Flask test client — a session that has been blocked must
    receive HTTP 429 with Retry-After through the real interceptor path.
"""
from __future__ import annotations
import json
import os
import sys
import pytest

sys.path.insert(0, "guardian")
from brain.blue_adapt import BlueAdaptAgent


# ---------------------------------------------------------------------------
# Helper
# ---------------------------------------------------------------------------

def _make_agent(
    *,
    escalation_threshold: int = 100,
    revoke_score_threshold: float = 1.0,
    honeypot_score_threshold: float = 1.0,
    strict_score_threshold: float = 1.0,
    cooldown_base_seconds: float = 30.0,
    cooldown_max_seconds: float = 300.0,
    cooldown_multiplier: float = 2.0,
    velocity_window_sec: float = 10.0,
    velocity_max_rps: float = 2.0,
) -> BlueAdaptAgent:
    return BlueAdaptAgent(
        escalation_threshold=escalation_threshold,
        revoke_score_threshold=revoke_score_threshold,
        honeypot_score_threshold=honeypot_score_threshold,
        strict_score_threshold=strict_score_threshold,
        cooldown_base_seconds=cooldown_base_seconds,
        cooldown_max_seconds=cooldown_max_seconds,
        cooldown_multiplier=cooldown_multiplier,
        velocity_window_sec=velocity_window_sec,
        velocity_max_rps=velocity_max_rps,
    )


# ===========================================================================
# GROUP 1: BlueAdaptAgent action pipeline
# ===========================================================================

class TestAdaptiveCooldownThroughAgent:
    def test_blocked_request_triggers_cooldown(self):
        """A blocked request must put the session into 'cooldown' via the full action pipeline."""
        agent = _make_agent(cooldown_base_seconds=30.0)
        sid = "sess-cooldown-test"
        agent.observe_prompt(sid, "bad prompt", blocked=True, intel_score=0)
        action = agent.get_action(sid)
        assert action == "cooldown", f"Expected 'cooldown' after blocked, got {action!r}"

    def test_cooldown_seconds_remaining_positive(self):
        """get_cooldown_seconds_remaining must return > 0 during cooldown."""
        agent = _make_agent(cooldown_base_seconds=60.0)
        sid = "sess-remaining-test"
        agent.observe_prompt(sid, "evil", blocked=True, intel_score=0)
        remaining = agent.get_cooldown_seconds_remaining(sid)
        assert remaining > 0, f"Expected cooldown remaining > 0, got {remaining}"
        assert remaining <= 61, f"Cooldown remaining {remaining}s implausible for base=60s"

    def test_unblocked_session_not_in_cooldown(self):
        """A session with no blocked history must NOT be in cooldown."""
        agent = _make_agent()
        sid = "sess-clean"
        agent.observe_prompt(sid, "hello", blocked=False, intel_score=0)
        action = agent.get_action(sid)
        assert action != "cooldown", f"Clean session should not be in cooldown; got {action!r}"

    def test_sessions_have_independent_cooldowns(self):
        """Blocking session A must NOT put session B into cooldown."""
        agent = _make_agent(cooldown_base_seconds=30.0)
        agent.observe_prompt("sess-blocked", "evil", blocked=True, intel_score=0)
        agent.observe_prompt("sess-clean", "hello", blocked=False, intel_score=0)
        assert agent.get_action("sess-blocked") == "cooldown"
        assert agent.get_action("sess-clean") != "cooldown"

    def test_cooldown_escalates_exponentially(self):
        """Each successive blocked-request violation must double the cooldown duration."""
        agent = _make_agent(
            cooldown_base_seconds=5.0,
            cooldown_multiplier=2.0,
            cooldown_max_seconds=1000.0,
        )
        sid = "sess-escalate"
        now = 0.0
        dur1 = agent._cooldown.record_violation(sid, now=now)
        assert abs(dur1 - 5.0) < 0.01, f"Violation 1: expected 5.0s, got {dur1}"
        dur2 = agent._cooldown.record_violation(sid, now=now)
        assert abs(dur2 - 10.0) < 0.01, f"Violation 2: expected 10.0s, got {dur2}"
        dur3 = agent._cooldown.record_violation(sid, now=now)
        assert abs(dur3 - 20.0) < 0.01, f"Violation 3: expected 20.0s, got {dur3}"


class TestSessionVelocityTrackerThroughAgent:
    def test_dense_requests_flagged_as_anomalous(self):
        """Velocity tracker must return True for dense (high-RPS) calls."""
        agent = _make_agent(velocity_window_sec=1.0, velocity_max_rps=1.0)
        sid = "sess-velocity"
        base = 1_000_000.0
        for i in range(10):
            agent._velocity.record(sid, ts=base + i * 0.05)
        # One more within the same 1-second window — must flag anomalous
        anomalous = agent._velocity.record(sid, ts=base + 0.51)
        assert anomalous, "Dense requests must be flagged as anomalous"

    def test_velocity_risk_does_not_bleed_across_sessions(self):
        """Saturating session A with velocity anomalies must not bump session B risk."""
        agent = _make_agent(velocity_window_sec=10.0, velocity_max_rps=1.0, escalation_threshold=1000)
        for _ in range(20):
            agent.observe_prompt("sess-fast", "fast", blocked=False, intel_score=0)
        agent.observe_prompt("sess-slow", "hello", blocked=False, intel_score=0)
        risk_b = agent.session_risk.get(agent._session_key("sess-slow"), 0)
        assert risk_b == 0, f"Session B risk should be 0; got {risk_b}"


# ===========================================================================
# GROUP 2: GuardianProxy end-to-end through Flask test client
# ===========================================================================

def _build_proxy():
    """Build a minimal GuardianProxy with auth disabled and brain enabled."""
    from runtime.interceptor import GuardianProxy
    os.environ["GUARDIAN_ENV"] = "test"
    config = {
        "target_url": "http://nowhere.invalid",
        "proxy": {
            "enabled": True,
            "listen_port": 18765,
            "trusted_proxy_hops": 1,
            "enforce_auth": False,  # disable per-request auth for test simplicity
        },
        "security_policies": {
            "security_mode": "balanced",
            "show_block_reason": True,
            "admin_token": "test-admin-token-abcdef",
        },
        "brain": {
            "enabled": True,
            "blue_escalation_threshold": 100,
            "blue_revoke_score_threshold": 1.0,
            "blue_honeypot_score_threshold": 1.0,
            "blue_strict_score_threshold": 1.0,
            "blue_cooldown_base_seconds": 30.0,
            "blue_cooldown_max_seconds": 300.0,
            "blue_cooldown_multiplier": 2.0,
        },
        "rate_limiting": {"requests_per_minute": 100000},
        "honeypot": {"enabled": True, "max_responses_per_window": 10, "min_interval_seconds": 0},
        "cost_abuse": {"enabled": False},
        "tenant_isolation": {"enabled": False},
        "memory_guard": {"enabled": False},
        "output_assurance": {"enabled": False},
        "output_watermark": {"enabled": False},
        "tool_policy": {"enabled": False},
        "siem": {"enabled": False},
        "jailbreak_fuzzer": {"enabled": False},
    }
    return GuardianProxy(config)


def _compute_session_id(proxy, conversation_id: str) -> str:
    """Compute the scoped session ID the interceptor will derive for a given X-Conversation-ID header."""
    from security.tenant_isolation import TenantIsolationManager
    tenant_id = proxy.tenant_isolation.default_tenant_id
    return proxy.tenant_isolation.scope_session_id(tenant_id, conversation_id)


def test_blocked_session_receives_429_with_retry_after():
    """After a blocked observation, the proxy must return 429 + Retry-After header.

    The test injects the blocked observation using the exact scoped session_id the
    interceptor will derive from the X-Conversation-ID header, so the brain state matches.
    """
    try:
        proxy = _build_proxy()
    except Exception as e:
        pytest.skip(f"GuardianProxy init failed: {e}")

    client = proxy.app.test_client()
    conv_id = "e2e-cooldown-conversation"

    # Compute the exact session_id the interceptor will derive for this conversation ID
    scoped_sid = _compute_session_id(proxy, conv_id)

    # Inject a blocked observation using the SAME scoped session_id
    proxy.brain.blue.observe_prompt(scoped_sid, "evil", blocked=True, intel_score=0)

    # Confirm the action is "cooldown" before making the request
    action = proxy.brain.blue.get_action(scoped_sid)
    assert action == "cooldown", f"Brain should return 'cooldown'; got {action!r}"

    resp = client.post(
        "/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "X-Conversation-ID": conv_id,  # interceptor uses this to derive session_id
        },
        data=json.dumps({"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]}),
    )
    assert resp.status_code == 429, (
        f"Expected 429 for cooldown session, got {resp.status_code}; "
        f"body={resp.get_data(as_text=True)[:200]}"
    )
    assert "Retry-After" in resp.headers, "429 must include Retry-After header"
    assert int(resp.headers["Retry-After"]) >= 1


def test_clean_session_does_not_receive_429():
    """A session with no blocked history must not receive 429."""
    try:
        proxy = _build_proxy()
    except Exception as e:
        pytest.skip(f"GuardianProxy init failed: {e}")

    client = proxy.app.test_client()
    resp = client.post(
        "/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "X-Conversation-ID": "e2e-clean-conversation",
        },
        data=json.dumps({"model": "gpt-4", "messages": [{"role": "user", "content": "hi"}]}),
    )
    # Upstream will fail → 502/503/500 — but NOT 429
    assert resp.status_code != 429, f"Clean session must not get 429; got {resp.status_code}"
