"""
Tests for Usage Metering & Pricing Tiers.

Covers:
  - Pricing tier definitions and limits
  - Usage recording and tracking
  - Rate limit enforcement per tier
  - Tier assignment and changes
  - Usage history and reporting
  - Enterprise unlimited access
  - Concurrent metering
  - Edge cases
"""
import pytest
import sys
import os
import time
import threading

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from backend.metering import (
    UsageMeter,
    PRICING_TIERS,
    PricingTier,
    UsageRecord,
    MeteringDecision,
)


@pytest.fixture
def db_path(tmp_path):
    return str(tmp_path / "metering_test.db")


@pytest.fixture
def meter(db_path):
    return UsageMeter(db_path=db_path)


# ---------------------------------------------------------------------------
# Test: Pricing Tier Definitions
# ---------------------------------------------------------------------------

class TestPricingTiers:
    def test_four_tiers_defined(self):
        assert len(PRICING_TIERS) == 4
        assert set(PRICING_TIERS.keys()) == {"free", "starter", "pro", "enterprise"}

    def test_free_tier_limits(self):
        free = PRICING_TIERS["free"]
        assert free.daily_request_limit == 50
        assert free.daily_token_limit == 10_000
        assert free.monthly_usd == 0

    def test_starter_tier(self):
        t = PRICING_TIERS["starter"]
        assert t.daily_request_limit == 5_000
        assert t.monthly_usd == 49

    def test_pro_tier(self):
        t = PRICING_TIERS["pro"]
        assert t.daily_request_limit == 50_000
        assert t.monthly_usd == 299

    def test_enterprise_unlimited(self):
        t = PRICING_TIERS["enterprise"]
        assert t.daily_request_limit == 0  # 0 = unlimited
        assert t.daily_token_limit == 0

    def test_tier_hierarchy_pricing(self):
        assert PRICING_TIERS["free"].monthly_usd < PRICING_TIERS["starter"].monthly_usd
        assert PRICING_TIERS["starter"].monthly_usd < PRICING_TIERS["pro"].monthly_usd

    def test_all_tiers_have_features(self):
        for name, tier in PRICING_TIERS.items():
            assert len(tier.features) > 0, f"{name} has no features"
            assert tier.support_level, f"{name} has no support level"


# ---------------------------------------------------------------------------
# Test: Tier Assignment
# ---------------------------------------------------------------------------

class TestTierAssignment:
    def test_default_tier_is_free(self, meter):
        assert meter.get_tenant_tier("new_tenant") == "free"

    def test_set_tier(self, meter):
        meter.set_tenant_tier("acme", "pro")
        assert meter.get_tenant_tier("acme") == "pro"

    def test_change_tier(self, meter):
        meter.set_tenant_tier("acme", "starter")
        assert meter.get_tenant_tier("acme") == "starter"
        meter.set_tenant_tier("acme", "pro")
        assert meter.get_tenant_tier("acme") == "pro"

    def test_invalid_tier_rejected(self, meter):
        with pytest.raises(ValueError, match="Invalid tier"):
            meter.set_tenant_tier("acme", "platinum")

    def test_multiple_tenants_independent(self, meter):
        meter.set_tenant_tier("tenant_a", "starter")
        meter.set_tenant_tier("tenant_b", "pro")
        assert meter.get_tenant_tier("tenant_a") == "starter"
        assert meter.get_tenant_tier("tenant_b") == "pro"
        assert meter.get_tenant_tier("tenant_c") == "free"


# ---------------------------------------------------------------------------
# Test: Usage Recording
# ---------------------------------------------------------------------------

class TestUsageRecording:
    def test_first_request_allowed(self, meter):
        decision = meter.record_usage("tenant1", tokens=100)
        assert decision.allowed is True
        assert decision.reason == "ok"
        assert decision.tier == "free"

    def test_usage_incrementing(self, meter):
        for i in range(5):
            meter.record_usage("tenant2", tokens=50)
        usage = meter.get_usage("tenant2")
        assert usage.request_count == 5
        assert usage.token_count == 250

    def test_free_tier_limit_enforced(self, meter):
        """Free tier: 50 requests/day — 51st should be blocked."""
        for i in range(50):
            decision = meter.record_usage("free_tenant", tokens=10)
            assert decision.allowed is True

        # 51st request should be blocked
        decision = meter.record_usage("free_tenant", tokens=10)
        assert decision.allowed is False
        assert decision.reason == "request_limit_exceeded"

    def test_token_limit_enforced(self, meter):
        """Free tier: 10K tokens/day."""
        # Use 9,999 tokens in one request
        decision = meter.record_usage("token_tenant", tokens=9_999)
        assert decision.allowed is True

        # Next request pushes over 10K
        decision = meter.record_usage("token_tenant", tokens=100)
        assert decision.allowed is False
        assert decision.reason == "token_limit_exceeded"

    def test_pro_tier_higher_limits(self, meter):
        """Pro tier should allow 50K requests."""
        meter.set_tenant_tier("pro_tenant", "pro")
        for i in range(100):
            decision = meter.record_usage("pro_tenant", tokens=10)
            assert decision.allowed is True

    def test_enterprise_unlimited(self, meter):
        """Enterprise tier should never block."""
        meter.set_tenant_tier("ent_tenant", "enterprise")
        for i in range(1000):
            decision = meter.record_usage("ent_tenant", tokens=1000)
            assert decision.allowed is True
        usage = meter.get_usage("ent_tenant")
        assert usage.request_count == 1000
        assert usage.is_rate_limited is False

    def test_remaining_counts_accurate(self, meter):
        decision = meter.record_usage("count_tenant", tokens=100)
        assert decision.remaining_requests == 49  # 50 - 1
        assert decision.remaining_tokens == 9_900  # 10K - 100

    def test_usage_percentage(self, meter):
        for _ in range(25):
            meter.record_usage("pct_tenant", tokens=0)
        decision = meter.record_usage("pct_tenant", tokens=0)
        # 26 out of 50 = 52%
        assert 50.0 <= decision.usage_pct <= 54.0, f"Usage pct was {decision.usage_pct}"


# ---------------------------------------------------------------------------
# Test: Usage Reporting
# ---------------------------------------------------------------------------

class TestUsageReporting:
    def test_get_usage_returns_record(self, meter):
        meter.record_usage("report_tenant", tokens=500)
        usage = meter.get_usage("report_tenant")
        assert isinstance(usage, UsageRecord)
        assert usage.tenant_id == "report_tenant"
        assert usage.request_count == 1
        assert usage.token_count == 500

    def test_get_usage_empty_tenant(self, meter):
        usage = meter.get_usage("nobody")
        assert usage.request_count == 0
        assert usage.token_count == 0
        assert usage.is_rate_limited is False

    def test_get_all_tenant_usage(self, meter):
        meter.record_usage("t1", tokens=100)
        meter.record_usage("t2", tokens=200)
        meter.record_usage("t2", tokens=300)
        all_usage = meter.get_all_tenant_usage()
        assert len(all_usage) >= 2
        t2 = next(u for u in all_usage if u["tenant_id"] == "t2")
        assert t2["requests"] == 2
        assert t2["tokens"] == 500

    def test_usage_history(self, meter):
        meter.record_usage("hist_tenant", tokens=100)
        history = meter.get_usage_history("hist_tenant", days=7)
        assert len(history) >= 1
        assert history[0]["requests"] == 1


# ---------------------------------------------------------------------------
# Test: Concurrent Metering
# ---------------------------------------------------------------------------

class TestConcurrentMetering:
    def test_concurrent_recording(self, meter):
        """50 threads recording usage simultaneously."""
        errors = []

        def record(i):
            try:
                meter.record_usage("concurrent_tenant", tokens=10)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=record, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0
        usage = meter.get_usage("concurrent_tenant")
        assert usage.request_count == 50

    def test_concurrent_different_tenants(self, meter):
        """20 tenants recording simultaneously."""
        errors = []

        def record(tenant_id):
            try:
                for _ in range(5):
                    meter.record_usage(tenant_id, tokens=10)
            except Exception as e:
                errors.append(str(e))

        threads = [threading.Thread(target=record, args=(f"par_t_{i}",)) for i in range(20)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert len(errors) == 0


# ---------------------------------------------------------------------------
# Test: Edge Cases
# ---------------------------------------------------------------------------

class TestMeteringEdgeCases:
    def test_zero_tokens(self, meter):
        decision = meter.record_usage("zero_tok", tokens=0)
        assert decision.allowed is True

    def test_large_token_count(self, meter):
        meter.set_tenant_tier("big_tenant", "enterprise")
        decision = meter.record_usage("big_tenant", tokens=10_000_000)
        assert decision.allowed is True

    def test_tier_change_mid_day(self, meter):
        """If tenant upgrades mid-day, usage persists but new limits apply."""
        for _ in range(45):
            meter.record_usage("upgrade_tenant", tokens=10)

        # Still on free tier, close to limit
        decision = meter.record_usage("upgrade_tenant", tokens=10)
        assert decision.allowed is True  # 46/50

        # Upgrade to pro
        meter.set_tenant_tier("upgrade_tenant", "pro")
        for _ in range(100):
            decision = meter.record_usage("upgrade_tenant", tokens=10)
            assert decision.allowed is True  # Pro limit is 50K
