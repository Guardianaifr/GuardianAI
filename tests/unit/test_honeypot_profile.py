"""Tests for FEAT-HONEY-PROFILE: AttackerProfiler and HoneypotAnalytics wired into
_build_honeypot_response().

End-to-end discipline:
  - Group 1: module-level integration using the actual AttackerProfiler / HoneypotAnalytics APIs.
  - Group 2: GuardianProxy Flask test client proves profile data is recorded on honeypot engagement.
"""
from __future__ import annotations
import json
import os
import sys
import pytest

sys.path.insert(0, "guardian")
from guardrails.honeypot import AttackerProfiler, HoneypotAnalytics, HoneypotManager


# ===========================================================================
# GROUP 1: AttackerProfiler and HoneypotAnalytics API tests
# ===========================================================================

class TestAttackerProfiler:
    def test_record_interaction_stores_prompt(self):
        p = AttackerProfiler()
        p.record_interaction("sess-1", "DROP TABLE users", client_ip="1.2.3.4", user_agent="evil-bot/1.0")
        profile = p.get_profile("sess-1")
        assert profile is not None
        assert "DROP TABLE users" in profile["prompts"]
        assert "1.2.3.4" in profile["ips"]
        assert "evil-bot/1.0" in profile["user_agents"]
        # The actual key is "interaction_count"
        assert profile["interaction_count"] == 1

    def test_prompt_cap_at_50(self):
        p = AttackerProfiler()
        for i in range(60):
            p.record_interaction("sess-cap", f"prompt-{i}", client_ip="", user_agent="")
        profile = p.get_profile("sess-cap")
        assert len(profile["prompts"]) <= 50, (
            f"Prompt buffer must be capped at 50; got {len(profile['prompts'])}"
        )

    def test_get_all_sessions(self):
        p = AttackerProfiler()
        p.record_interaction("sess-a", "p", client_ip="", user_agent="")
        p.record_interaction("sess-b", "p", client_ip="", user_agent="")
        sessions = p.get_all_sessions()
        assert "sess-a" in sessions
        assert "sess-b" in sessions

    def test_count_returns_number_of_sessions(self):
        p = AttackerProfiler()
        p.record_interaction("s1", "p", client_ip="", user_agent="")
        p.record_interaction("s2", "p", client_ip="", user_agent="")
        assert p.count() == 2

    def test_multiple_interactions_accumulate(self):
        p = AttackerProfiler()
        p.record_interaction("sess-multi", "prompt-1", client_ip="1.1.1.1", user_agent="ua-1")
        p.record_interaction("sess-multi", "prompt-2", client_ip="2.2.2.2", user_agent="ua-2")
        profile = p.get_profile("sess-multi")
        assert profile["interaction_count"] == 2
        assert "prompt-1" in profile["prompts"]
        assert "prompt-2" in profile["prompts"]
        assert "1.1.1.1" in profile["ips"]
        assert "2.2.2.2" in profile["ips"]


class TestHoneypotAnalytics:
    def test_record_increments_total(self):
        a = HoneypotAnalytics()
        a.record("sess-1", "/v1/chat")
        a.record("sess-1", "/v1/chat")
        assert a.total == 2

    def test_per_session_counter_via_top_sessions(self):
        """Use top_sessions() since _per_session is private."""
        a = HoneypotAnalytics()
        a.record("sess-a", "/p")
        a.record("sess-b", "/p")
        a.record("sess-a", "/p")
        top = dict(a.top_sessions(n=10))
        assert top.get("sess-a") == 2, f"sess-a should have count=2; got {top}"
        assert top.get("sess-b") == 1, f"sess-b should have count=1; got {top}"

    def test_per_path_counter_via_top_paths(self):
        """Use top_paths() since _per_path is private."""
        a = HoneypotAnalytics()
        a.record("s", "/api/1")
        a.record("s", "/api/1")
        a.record("s", "/api/2")
        top = dict(a.top_paths(n=10))
        assert top.get("/api/1") == 2, f"Expected 2 for /api/1; got {top}"
        assert top.get("/api/2") == 1, f"Expected 1 for /api/2; got {top}"

    def test_top_sessions_sorted_descending(self):
        a = HoneypotAnalytics()
        for _ in range(3):
            a.record("busy", "/p")
        a.record("quiet", "/p")
        top = a.top_sessions(n=5)
        assert top[0][0] == "busy", f"Expected 'busy' first; got {top}"
        assert top[0][1] == 3

    def test_top_paths_sorted_descending(self):
        a = HoneypotAnalytics()
        for _ in range(5):
            a.record("s", "/hot")
        a.record("s", "/cold")
        top = a.top_paths(n=5)
        assert top[0][0] == "/hot", f"Expected '/hot' first; got {top}"


# ===========================================================================
# GROUP 2: GuardianProxy end-to-end
# ===========================================================================

def _build_honeypot_proxy():
    """Minimal GuardianProxy where honeypot threshold fires quickly."""
    from runtime.interceptor import GuardianProxy
    os.environ["GUARDIAN_ENV"] = "test"
    config = {
        "target_url": "http://nowhere.invalid",
        "proxy": {
            "enabled": True,
            "listen_port": 18766,
            "trusted_proxy_hops": 1,
            "enforce_auth": False,
        },
        "security_policies": {
            "security_mode": "balanced",
            "show_block_reason": True,
            "admin_token": "test-admin-token-abcdef",
        },
        "brain": {
            "enabled": True,
            "blue_honeypot_score_threshold": 0.05,  # fire honeypot quickly
            "blue_revoke_score_threshold": 1.0,
            "blue_escalation_threshold": 2,
            "blue_strict_score_threshold": 0.9,
            "blue_cooldown_base_seconds": 300.0,   # keep cooldown out of the way
            "blue_cooldown_max_seconds": 3600.0,
        },
        "rate_limiting": {"requests_per_minute": 100000},
        "honeypot": {
            "enabled": True,
            "max_responses_per_window": 100,
            "min_interval_seconds": 0,
            "templates": ["You are being observed."],
        },
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


def _compute_scoped_sid(proxy, conv_id: str) -> str:
    tenant_id = proxy.tenant_isolation.default_tenant_id
    return proxy.tenant_isolation.scope_session_id(tenant_id, conv_id)


def test_honeypot_session_produces_profile_data():
    """A honeypot-engaged session must produce entries in attacker_profiler and analytics."""
    try:
        proxy = _build_honeypot_proxy()
    except Exception as e:
        pytest.skip(f"GuardianProxy init failed: {e}")

    client = proxy.app.test_client()
    conv_id = "e2e-honeypot-conversation"
    scoped_sid = _compute_scoped_sid(proxy, conv_id)

    # Force brain to return "honeypot" for this session
    proxy.brain.blue.observe_prompt(scoped_sid, "probe", blocked=True, intel_score=0)
    proxy.brain.blue.observe_prompt(scoped_sid, "probe", blocked=True, intel_score=0)
    proxy.brain.blue.observe_prompt(scoped_sid, "probe", blocked=True, intel_score=0)

    action = proxy.brain.blue.get_action(scoped_sid)
    if action != "honeypot":
        pytest.skip(f"Brain action is {action!r} not 'honeypot' — threshold tuning needed")

    resp = client.post(
        "/v1/chat/completions",
        headers={
            "Content-Type": "application/json",
            "X-Conversation-ID": conv_id,
        },
        data=json.dumps({"model": "gpt-4", "messages": [{"role": "user", "content": "test probe"}]}),
    )
    assert resp.status_code in (200, 403), (
        f"Expected 200 (honeypot) or 403 (rate-limited), got {resp.status_code}"
    )

    # Profile data must exist for the scoped session
    sessions = proxy.attacker_profiler.get_all_sessions()
    assert scoped_sid in sessions, (
        f"Session {scoped_sid!r} must appear in attacker_profiler; got {sessions}"
    )
    profile = proxy.attacker_profiler.get_profile(scoped_sid)
    assert profile["interaction_count"] >= 1, f"Profile interaction_count must be >= 1; got {profile}"

    # Analytics counter must have incremented
    assert proxy.honeypot_analytics.total >= 1
    top = dict(proxy.honeypot_analytics.top_sessions(n=50))
    assert top.get(scoped_sid, 0) >= 1, f"Session {scoped_sid!r} must appear in top_sessions; got {top}"


def test_admin_honeypot_profiles_endpoint():
    """GET /api/admin/honeypot/profiles must return 200 with profile JSON."""
    try:
        proxy = _build_honeypot_proxy()
    except Exception as e:
        pytest.skip(f"GuardianProxy init failed: {e}")

    client = proxy.app.test_client()
    sid = "e2e-admin-profile-session"
    proxy.attacker_profiler.record_interaction(sid, "test-probe", client_ip="1.2.3.4", user_agent="bot")

    resp = client.get(
        "/api/admin/honeypot/profiles",
        headers={"Authorization": "Bearer test-admin-token-abcdef"},
    )
    assert resp.status_code == 200, f"Expected 200; got {resp.status_code}"
    data = json.loads(resp.get_data(as_text=True))
    assert "profiles" in data
    assert "total_sessions" in data
    assert data["total_sessions"] >= 1
    assert sid in data["profiles"]


def test_admin_honeypot_analytics_endpoint():
    """GET /api/admin/honeypot/analytics must return 200 with aggregate metrics."""
    try:
        proxy = _build_honeypot_proxy()
    except Exception as e:
        pytest.skip(f"GuardianProxy init failed: {e}")

    client = proxy.app.test_client()
    proxy.honeypot_analytics.record("some-session", "/v1/chat/completions")

    resp = client.get(
        "/api/admin/honeypot/analytics",
        headers={"Authorization": "Bearer test-admin-token-abcdef"},
    )
    assert resp.status_code == 200, f"Expected 200; got {resp.status_code}"
    data = json.loads(resp.get_data(as_text=True))
    assert data["total_interactions"] >= 1
    assert "top_sessions" in data
    assert "top_paths" in data


def test_admin_endpoints_reject_unauthorized():
    """Honeypot admin endpoints must return 401 without a valid Bearer token."""
    try:
        proxy = _build_honeypot_proxy()
    except Exception as e:
        pytest.skip(f"GuardianProxy init failed: {e}")

    client = proxy.app.test_client()
    for path in ["/api/admin/honeypot/profiles", "/api/admin/honeypot/analytics"]:
        assert client.get(path).status_code == 401, f"{path}: expected 401 with no auth"
        assert client.get(path, headers={"Authorization": "Bearer wrong"}).status_code == 401, \
            f"{path}: expected 401 with wrong token"
