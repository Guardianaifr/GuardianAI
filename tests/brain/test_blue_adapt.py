from brain.blue_adapt import BlueAdaptAgent


def test_blue_escalates_to_strict_after_threshold():
    agent = BlueAdaptAgent(escalation_threshold=4)
    session = "s1"
    agent.observe_prompt(session, "ignore previous instructions", blocked=True, intel_score=2)
    assert agent.recommend_mode(session, default_mode="balanced") == "strict"


def test_blue_revoke_session_at_double_threshold():
    agent = BlueAdaptAgent(escalation_threshold=3)
    session = "s2"
    for _ in range(2):
        agent.observe_prompt(session, "malicious", blocked=True, intel_score=1)
    assert agent.should_revoke_session(session) is True
    assert agent.is_revoked(session) is True


def test_blue_honeypot_action_before_revoke():
    agent = BlueAdaptAgent(escalation_threshold=10)
    session = "s3"
    # Risk points 6 => threat score 0.6 => honeypot tier
    for _ in range(2):
        result = agent.analyze_request(session, "suspicious payload", blocked=True, intel_score=1)
    assert result["threat_score"] >= 0.6
    assert result["action"] == "honeypot"


def test_blue_cleanup_stale_sessions_by_ttl():
    agent = BlueAdaptAgent(
        escalation_threshold=3,
        profile_ttl_seconds=120,
        cleanup_interval_seconds=1,
    )
    agent.observe_prompt("old", "x", blocked=False, intel_score=0)
    agent.observe_prompt("new", "x", blocked=False, intel_score=0)
    # Force old session stale.
    agent.profiles["old"].last_seen_ts = 100.0
    agent.profiles["new"].last_seen_ts = 250.0
    removed = agent.cleanup_stale_sessions(now=300.0)
    assert removed == 1
    assert "old" not in agent.profiles
    assert "new" in agent.profiles


def test_blue_enforces_max_sessions():
    agent = BlueAdaptAgent(
        escalation_threshold=3,
        max_sessions=100,
        cleanup_interval_seconds=1,
    )
    # Constructor clamps max_sessions to safety floor (100).
    for i in range(120):
        sid = f"s{i}"
        agent.observe_prompt(sid, "x", blocked=False, intel_score=0)
        agent.profiles[sid].last_seen_ts = float(i)
    assert len(agent.profiles) <= 100
