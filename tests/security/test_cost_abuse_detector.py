from guardian.security.cost_abuse import CostAbuseDetector


def test_cost_abuse_detector_allows_normal_usage():
    detector = CostAbuseDetector(
        {
            "enabled": True,
            "window_seconds": 120,
            "min_events": 3,
            "max_tokens_per_window": 1000,
            "max_cost_usd_per_window": 1.0,
            "spike_multiplier": 4.0,
            "quarantine_seconds": 60,
            "cost_per_1k_tokens_usd": 0.01,
        }
    )

    for _ in range(3):
        decision = detector.register_usage("sess-1", tokens=120, cost_usd=0.0012)
    assert decision.action == "allow"
    is_quarantined, _remaining = detector.is_quarantined("sess-1")
    assert is_quarantined is False


def test_cost_abuse_detector_quarantines_wallet_drain_pattern():
    detector = CostAbuseDetector(
        {
            "enabled": True,
            "window_seconds": 120,
            "min_events": 2,
            "max_tokens_per_window": 200,
            "max_cost_usd_per_window": 0.005,
            "quarantine_seconds": 120,
            "cost_per_1k_tokens_usd": 0.02,
        }
    )

    first = detector.register_usage("sess-drain", tokens=120, cost_usd=0.0024)
    second = detector.register_usage("sess-drain", tokens=120, cost_usd=0.0024)

    assert first.action == "allow"
    assert second.action == "quarantine"
    assert "tokens_per_window" in second.metrics["thresholds_exceeded"]

    is_quarantined, remaining = detector.is_quarantined("sess-drain")
    assert is_quarantined is True
    assert remaining > 0


def test_cost_abuse_detector_quarantines_cross_session_slow_drain():
    detector = CostAbuseDetector(
        {
            "enabled": True,
            "window_seconds": 120,
            "min_events": 10,
            "max_tokens_per_window": 999999,
            "max_cost_usd_per_window": 999.0,
            "tenant_window_seconds": 300,
            "min_sessions_for_tenant_anomaly": 3,
            "max_tokens_per_tenant_window": 300,
            "max_cost_usd_per_tenant_window": 999.0,
            "min_tokens_per_session_for_slow_drain": 100,
            "quarantine_seconds": 120,
            "cost_per_1k_tokens_usd": 0.02,
        }
    )

    d1 = detector.register_usage("sess-a", tokens=110, cost_usd=0.0022, tenant_id="tenant-1")
    d2 = detector.register_usage("sess-b", tokens=110, cost_usd=0.0022, tenant_id="tenant-1")
    d3 = detector.register_usage("sess-c", tokens=110, cost_usd=0.0022, tenant_id="tenant-1")

    assert d1.action == "allow"
    assert d2.action == "allow"
    assert d3.action == "quarantine"
    assert "tenant_tokens_slow_drain" in d3.metrics["thresholds_exceeded"]
    assert d3.metrics["tenant_active_sessions"] == 3


def test_cost_abuse_detector_allows_small_multi_session_usage():
    detector = CostAbuseDetector(
        {
            "enabled": True,
            "window_seconds": 120,
            "min_events": 10,
            "max_tokens_per_window": 999999,
            "max_cost_usd_per_window": 999.0,
            "tenant_window_seconds": 300,
            "min_sessions_for_tenant_anomaly": 3,
            "max_tokens_per_tenant_window": 1000,
            "max_cost_usd_per_tenant_window": 999.0,
            "min_tokens_per_session_for_slow_drain": 100,
            "quarantine_seconds": 120,
            "cost_per_1k_tokens_usd": 0.02,
        }
    )

    d1 = detector.register_usage("sess-a", tokens=20, cost_usd=0.0004, tenant_id="tenant-1")
    d2 = detector.register_usage("sess-b", tokens=20, cost_usd=0.0004, tenant_id="tenant-1")
    d3 = detector.register_usage("sess-c", tokens=20, cost_usd=0.0004, tenant_id="tenant-1")

    assert d1.action == "allow"
    assert d2.action == "allow"
    assert d3.action == "allow"
