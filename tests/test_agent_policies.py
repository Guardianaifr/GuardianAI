"""Tests for Function Selector Allowlists and Spending Caps.

Verifies the two features identified as missing in the 6.5/10 audit:
1. Per-agent function selector allowlists (deny-by-default)
2. Per-agent spending caps (per-tx and rolling 24h outflow)
"""
import time
import pytest
from guardian.relayer.attestation_service import (
    SafetyAttestationService,
    AgentPolicy,
    OutflowTracker,
)


# ── Helpers ──────────────────────────────────────────────────────────────

TRANSFER_SELECTOR = "0xa9059cbb"  # transfer(address,uint256)
APPROVE_SELECTOR = "0x095ea7b3"   # approve(address,uint256)
SWAP_SELECTOR = "0x38ed1739"      # swapExactTokensForTokens
DRAIN_SELECTOR = "0xdeadbeef"     # hypothetical drain function

# Valid ERC-20 transfer calldata: transfer(0xdead..., 1e18)
VALID_TRANSFER_CALLDATA = (
    "0xa9059cbb"
    "000000000000000000000000deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
    "0000000000000000000000000000000000000000000000000de0b6b3a7640000"
)

# Calldata with the drain selector
DRAIN_CALLDATA = (
    "0xdeadbeef"
    "0000000000000000000000000000000000000000000000000000000000000001"
)


def make_service(agent_policies=None):
    """Create a SafetyAttestationService with a deterministic test key."""
    return SafetyAttestationService(
        private_key="0x" + "ab" * 32,
        verifying_contract="0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101",
        chain_id=10143,
        max_allowed_risk_score=25,
        agent_policies=agent_policies or {},
    )


# ── Function Selector Allowlist Tests ────────────────────────────────────

class TestSelectorAllowlist:
    """Tests for per-agent function selector allowlists."""

    def test_allowed_selector_passes(self):
        """An agent with an allowlist can call permitted functions."""
        svc = make_service(agent_policies={
            "agent-1": AgentPolicy(allowed_selectors={TRANSFER_SELECTOR, APPROVE_SELECTOR}),
        })
        result = svc.evaluate_and_attest(
            agent_id="agent-1",
            target="0x1234567890abcdef1234567890abcdef12345678",
            data=VALID_TRANSFER_CALLDATA,
            value=0,
        )
        assert result.status == "approved"
        assert result.risk_score <= 25

    def test_disallowed_selector_blocked(self):
        """An agent with an allowlist is blocked from calling unpermitted functions."""
        svc = make_service(agent_policies={
            "agent-1": AgentPolicy(allowed_selectors={TRANSFER_SELECTOR}),  # Only transfer allowed
        })
        result = svc.evaluate_and_attest(
            agent_id="agent-1",
            target="0x1234567890abcdef1234567890abcdef12345678",
            data=DRAIN_CALLDATA,  # Uses 0xdeadbeef selector — NOT in allowlist
            value=0,
        )
        assert result.status == "blocked"
        assert result.risk_score == 100
        assert "not in agent allowlist" in result.reasons[0]

    def test_empty_allowlist_blocks_everything(self):
        """An agent with an empty allowlist (set()) can't call any function."""
        svc = make_service(agent_policies={
            "agent-locked": AgentPolicy(allowed_selectors=set()),  # Empty = nothing allowed
        })
        result = svc.evaluate_and_attest(
            agent_id="agent-locked",
            target="0x1234567890abcdef1234567890abcdef12345678",
            data=VALID_TRANSFER_CALLDATA,
            value=0,
        )
        assert result.status == "blocked"
        assert result.risk_score == 100

    def test_no_policy_uses_blocklist_only(self):
        """An agent without a policy falls back to blocklist-only mode (backwards compatible)."""
        svc = make_service(agent_policies={})
        result = svc.evaluate_and_attest(
            agent_id="agent-no-policy",
            target="0x1234567890abcdef1234567890abcdef12345678",
            data=VALID_TRANSFER_CALLDATA,
            value=0,
        )
        assert result.status == "approved"  # No allowlist → blocklist only → passes

    def test_none_allowlist_disables_allowlisting(self):
        """A policy with allowed_selectors=None disables allowlisting (blocklist-only)."""
        svc = make_service(agent_policies={
            "agent-2": AgentPolicy(allowed_selectors=None),  # None = no allowlist
        })
        result = svc.evaluate_and_attest(
            agent_id="agent-2",
            target="0x1234567890abcdef1234567890abcdef12345678",
            data=DRAIN_CALLDATA,
            value=0,
        )
        # Without allowlist, drain selector passes unless blocklist catches it
        assert result.status == "approved"


# ── Spending Cap Tests ───────────────────────────────────────────────────

class TestSpendingCaps:
    """Tests for per-agent spending limits."""

    def test_per_tx_cap_allows_under_limit(self):
        """A transaction under the per-tx cap is approved."""
        svc = make_service(agent_policies={
            "agent-1": AgentPolicy(max_value_per_tx=10**18),  # 1 ETH cap
        })
        result = svc.evaluate_and_attest(
            agent_id="agent-1",
            target="0x1234567890abcdef1234567890abcdef12345678",
            data="0x",  # Native transfer
            value=5 * 10**17,  # 0.5 ETH — under cap
        )
        assert result.status == "approved"

    def test_per_tx_cap_blocks_over_limit(self):
        """A transaction over the per-tx cap is blocked."""
        svc = make_service(agent_policies={
            "agent-1": AgentPolicy(max_value_per_tx=10**18),  # 1 ETH cap
        })
        result = svc.evaluate_and_attest(
            agent_id="agent-1",
            target="0x1234567890abcdef1234567890abcdef12345678",
            data="0x",
            value=2 * 10**18,  # 2 ETH — over cap
        )
        assert result.status == "blocked"
        assert result.risk_score == 100
        assert "exceeds per-tx cap" in result.reasons[0]

    def test_daily_cap_blocks_cumulative_overflow(self):
        """Multiple approved transactions that exceed the daily cap are blocked."""
        svc = make_service(agent_policies={
            "agent-1": AgentPolicy(
                max_value_per_tx=10**18,     # 1 ETH per tx
                max_daily_outflow=2 * 10**18,  # 2 ETH daily
            ),
        })
        target = "0x1234567890abcdef1234567890abcdef12345678"

        # First tx: 1 ETH → approved (cumulative: 1 ETH)
        r1 = svc.evaluate_and_attest(agent_id="agent-1", target=target, data="0x", value=10**18)
        assert r1.status == "approved"

        # Second tx: 1 ETH → approved (cumulative: 2 ETH = at cap)
        r2 = svc.evaluate_and_attest(agent_id="agent-1", target=target, data="0x", value=10**18)
        assert r2.status == "approved"

        # Third tx: 1 ETH → BLOCKED (would push to 3 ETH, exceeding 2 ETH cap)
        r3 = svc.evaluate_and_attest(agent_id="agent-1", target=target, data="0x", value=10**18)
        assert r3.status == "blocked"
        assert r3.risk_score == 100
        assert "exceeding daily cap" in r3.reasons[0]

    def test_zero_value_tx_not_tracked(self):
        """Transactions with value=0 don't consume outflow budget."""
        svc = make_service(agent_policies={
            "agent-1": AgentPolicy(max_daily_outflow=10**18),
        })
        target = "0x1234567890abcdef1234567890abcdef12345678"

        # 10 zero-value calls should never trigger daily cap
        for _ in range(10):
            r = svc.evaluate_and_attest(
                agent_id="agent-1", target=target,
                data=VALID_TRANSFER_CALLDATA, value=0,
            )
            assert r.status == "approved"

    def test_different_agents_have_separate_budgets(self):
        """Each agent has its own independent outflow budget."""
        svc = make_service(agent_policies={
            "agent-a": AgentPolicy(max_value_per_tx=10**18, max_daily_outflow=10**18),
            "agent-b": AgentPolicy(max_value_per_tx=10**18, max_daily_outflow=10**18),
        })
        target = "0x1234567890abcdef1234567890abcdef12345678"

        # Agent A uses full budget
        r1 = svc.evaluate_and_attest(agent_id="agent-a", target=target, data="0x", value=10**18)
        assert r1.status == "approved"

        # Agent B should still have full budget (independent)
        r2 = svc.evaluate_and_attest(agent_id="agent-b", target=target, data="0x", value=10**18)
        assert r2.status == "approved"

        # Agent A is now over budget
        r3 = svc.evaluate_and_attest(agent_id="agent-a", target=target, data="0x", value=1)
        assert r3.status == "blocked"


# ── OutflowTracker Unit Tests ────────────────────────────────────────────

class TestOutflowTracker:
    """Unit tests for the rolling-window outflow tracker."""

    def test_fresh_tracker_has_zero_cumulative(self):
        tracker = OutflowTracker()
        assert tracker.cumulative("agent-x") == 0

    def test_records_accumulate(self):
        tracker = OutflowTracker()
        tracker.record("agent-x", 100)
        tracker.record("agent-x", 200)
        assert tracker.cumulative("agent-x") == 300

    def test_would_exceed_check(self):
        tracker = OutflowTracker()
        tracker.record("agent-x", 900)
        assert tracker.would_exceed("agent-x", 200, 1000) is True
        assert tracker.would_exceed("agent-x", 100, 1000) is False
        assert tracker.would_exceed("agent-x", 100, 999) is True

    def test_different_agents_are_independent(self):
        tracker = OutflowTracker()
        tracker.record("agent-a", 500)
        tracker.record("agent-b", 100)
        assert tracker.cumulative("agent-a") == 500
        assert tracker.cumulative("agent-b") == 100


# ── Combined Allowlist + Spending Cap Tests ──────────────────────────────

class TestCombinedPolicies:
    """Tests that allowlists and spending caps work together."""

    def test_allowed_selector_but_over_cap_is_blocked(self):
        """Even if the function is allowed, exceeding the spending cap blocks it."""
        svc = make_service(agent_policies={
            "agent-1": AgentPolicy(
                allowed_selectors={TRANSFER_SELECTOR},
                max_value_per_tx=10**17,  # 0.1 ETH cap
            ),
        })
        result = svc.evaluate_and_attest(
            agent_id="agent-1",
            target="0x1234567890abcdef1234567890abcdef12345678",
            data=VALID_TRANSFER_CALLDATA,
            value=10**18,  # 1 ETH — over 0.1 ETH cap
        )
        assert result.status == "blocked"
        assert "exceeds per-tx cap" in result.reasons[0]

    def test_under_cap_but_disallowed_selector_is_blocked(self):
        """Even if under the spending cap, a disallowed selector blocks it."""
        svc = make_service(agent_policies={
            "agent-1": AgentPolicy(
                allowed_selectors={TRANSFER_SELECTOR},
                max_value_per_tx=10**18,
            ),
        })
        result = svc.evaluate_and_attest(
            agent_id="agent-1",
            target="0x1234567890abcdef1234567890abcdef12345678",
            data=DRAIN_CALLDATA,  # Wrong selector
            value=10**17,  # Under cap
        )
        assert result.status == "blocked"
        assert "not in agent allowlist" in result.reasons[0]
