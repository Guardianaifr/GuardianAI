"""
Tests for guardian.onchain_safety — ownership pre-flight check.

All tests mock web3 and eth_account so no real network is required.
"""

from __future__ import annotations

import importlib
import os
import sys
from typing import Any, Dict
from unittest.mock import MagicMock, patch, call

import pytest


# ── Helpers ───────────────────────────────────────────────────────────────────

TIMELOCK_ADDR   = "0xTimel0ck000000000000000000000000000000C0"
DEPLOYER_ADDR   = "0xDeployer0000000000000000000000000000000D"
DEPLOYER_KEY    = "0x" + "ab" * 32   # fake but valid-looking hex key

CONTRACT_ADDRS = {
    "GUARDIAN_CORTEX_CONTRACT_MONAD":       "0xC0rtex0000000000000000000000000000000001",
    "GUARDIAN_INSURANCE_CONTRACT_MONAD":    "0x1nsurance000000000000000000000000000002",
    "GUARDIAN_INTERLOCK_CONTRACT_MONAD":    "0x1nterl0ck00000000000000000000000000003",
    "GUARDIAN_THREATFEED_CONTRACT_MONAD":   "0x7hreatFeed0000000000000000000000000004",
    "GUARDIAN_RISK_CONTRACT_MONAD":         "0xR1sk0000000000000000000000000000000005",
}

BASE_ENV = {
    "GUARDIAN_ANCHOR_MODE":       "live",
    "GUARDIAN_TIMELOCK_ADDRESS":  TIMELOCK_ADDR,
    "GUARDIAN_DEPLOYER_PRIVATE_KEY": DEPLOYER_KEY,
    **CONTRACT_ADDRS,
}


def _reload_module():
    """Re-import onchain_safety with a clean cache each time."""
    mod_name = "guardian.onchain_safety"
    if mod_name in sys.modules:
        del sys.modules[mod_name]
    import guardian.onchain_safety as m
    return m


def _make_w3_mock(owner_returns: str | Exception):
    """
    Build a minimal web3.Web3 mock whose contract().functions.owner().call()
    returns *owner_returns* (or raises it if it's an Exception).
    """
    w3 = MagicMock()
    w3.to_checksum_address.side_effect = lambda addr: addr  # identity

    contract_mock = MagicMock()
    if isinstance(owner_returns, Exception):
        contract_mock.functions.owner.return_value.call.side_effect = owner_returns
    else:
        contract_mock.functions.owner.return_value.call.return_value = owner_returns

    w3.eth.contract.return_value = contract_mock
    return w3


# ── Tests ─────────────────────────────────────────────────────────────────────


class TestSimulatedMode:
    """Function must be a no-op when not in live mode."""

    def test_simulated_mode_does_nothing(self, monkeypatch):
        monkeypatch.setenv("GUARDIAN_ANCHOR_MODE", "simulated")
        mod = _reload_module()
        # Should return without touching web3 at all
        with patch("guardian.onchain_safety._run_ownership_check") as run_mock:
            mod.assert_timelock_owns_all(chain="monad")
            run_mock.assert_not_called()

    def test_absent_mode_defaults_to_simulated(self, monkeypatch):
        monkeypatch.delenv("GUARDIAN_ANCHOR_MODE", raising=False)
        mod = _reload_module()
        with patch("guardian.onchain_safety._run_ownership_check") as run_mock:
            mod.assert_timelock_owns_all()
            run_mock.assert_not_called()

    def test_case_insensitive_simulated(self, monkeypatch):
        monkeypatch.setenv("GUARDIAN_ANCHOR_MODE", "  SIMULATED  ")
        mod = _reload_module()
        with patch("guardian.onchain_safety._run_ownership_check") as run_mock:
            mod.assert_timelock_owns_all()
            run_mock.assert_not_called()


class TestMissingTimelockAddress:
    """Must raise EnvironmentError when GUARDIAN_TIMELOCK_ADDRESS is absent."""

    def test_raises_when_timelock_address_missing(self, monkeypatch):
        env = {**BASE_ENV}
        env.pop("GUARDIAN_TIMELOCK_ADDRESS")

        for k, v in env.items():
            monkeypatch.setenv(k, v)
        monkeypatch.delenv("GUARDIAN_TIMELOCK_ADDRESS", raising=False)

        mod = _reload_module()

        with patch.dict("sys.modules", {"web3": MagicMock(), "eth_account": MagicMock()}):
            with pytest.raises(EnvironmentError, match="GUARDIAN_TIMELOCK_ADDRESS"):
                mod.assert_timelock_owns_all(chain="monad")


class TestAllContractsOwnedByTimelock:
    """Happy path: all contracts return timelock as owner → no exception."""

    def test_all_ok_passes_silently(self, monkeypatch):
        for k, v in BASE_ENV.items():
            monkeypatch.setenv(k, v)

        mod = _reload_module()

        w3_mock = _make_w3_mock(owner_returns=TIMELOCK_ADDR)
        account_mock = MagicMock()

        with patch.dict("sys.modules", {
            "web3": MagicMock(Web3=MagicMock(return_value=w3_mock,
                                              HTTPProvider=MagicMock())),
            "eth_account": MagicMock(Account=account_mock),
        }):
            # Should complete without raising
            mod.assert_timelock_owns_all(chain="monad")

    def test_passes_when_no_contracts_configured(self, monkeypatch):
        """If no contract addresses are set, the check passes vacuously."""
        monkeypatch.setenv("GUARDIAN_ANCHOR_MODE", "live")
        monkeypatch.setenv("GUARDIAN_TIMELOCK_ADDRESS", TIMELOCK_ADDR)
        for k in CONTRACT_ADDRS:
            monkeypatch.delenv(k, raising=False)

        mod = _reload_module()

        w3_mock = _make_w3_mock(owner_returns=TIMELOCK_ADDR)

        with patch.dict("sys.modules", {
            "web3": MagicMock(Web3=MagicMock(return_value=w3_mock,
                                              HTTPProvider=MagicMock())),
            "eth_account": MagicMock(),
        }):
            mod.assert_timelock_owns_all(chain="monad")  # must not raise


class TestOwnershipViolations:
    """Contracts still owned by deployer EOA → OwnershipNotTransferredError."""

    def _setup_partial_eoa_owner(self, monkeypatch, bad_contract_env_var: str):
        """All contracts return timelock EXCEPT the one specified."""
        for k, v in BASE_ENV.items():
            monkeypatch.setenv(k, v)
        mod = _reload_module()

        def owner_call_side_effect(contract_addr=None):
            if contract_addr and contract_addr == CONTRACT_ADDRS.get(bad_contract_env_var):
                return DEPLOYER_ADDR
            return TIMELOCK_ADDR

        # We need to make each contract return a different value based on its address.
        w3_mock = MagicMock()
        w3_mock.to_checksum_address.side_effect = lambda a: a

        def contract_factory(address, abi):
            c = MagicMock()
            if address == CONTRACT_ADDRS.get(bad_contract_env_var):
                c.functions.owner.return_value.call.return_value = DEPLOYER_ADDR
            else:
                c.functions.owner.return_value.call.return_value = TIMELOCK_ADDR
            return c

        w3_mock.eth.contract.side_effect = contract_factory
        return mod, w3_mock

    def test_single_eoa_owner_raises(self, monkeypatch):
        mod, w3_mock = self._setup_partial_eoa_owner(
            monkeypatch, "GUARDIAN_CORTEX_CONTRACT_MONAD"
        )

        account_mock = MagicMock()
        account_mock.Account.from_key.return_value.address = DEPLOYER_ADDR

        with patch.dict("sys.modules", {
            "web3": MagicMock(Web3=MagicMock(return_value=w3_mock,
                                              HTTPProvider=MagicMock())),
            "eth_account": account_mock,
        }):
            from guardian.onchain_safety import OwnershipNotTransferredError
            with pytest.raises(OwnershipNotTransferredError) as exc_info:
                mod.assert_timelock_owns_all(chain="monad")

        err = exc_info.value
        assert len(err.violations) == 1
        assert err.violations[0]["contract"] == "GuardianCortexAnchor"
        assert err.violations[0]["is_deployer_eoa"] is True
        assert "LIVE MODE BLOCKED" in str(err)
        assert "transfer_ownership_to_timelock.js" in str(err)

    def test_all_eoa_owned_lists_all_five(self, monkeypatch):
        for k, v in BASE_ENV.items():
            monkeypatch.setenv(k, v)

        mod = _reload_module()

        # All contracts return deployer
        w3_mock = _make_w3_mock(owner_returns=DEPLOYER_ADDR)

        account_mock = MagicMock()
        account_mock.Account.from_key.return_value.address = DEPLOYER_ADDR

        with patch.dict("sys.modules", {
            "web3": MagicMock(Web3=MagicMock(return_value=w3_mock,
                                              HTTPProvider=MagicMock())),
            "eth_account": account_mock,
        }):
            from guardian.onchain_safety import OwnershipNotTransferredError
            with pytest.raises(OwnershipNotTransferredError) as exc_info:
                mod.assert_timelock_owns_all(chain="monad")

        assert len(exc_info.value.violations) == 5
        contract_names = {v["contract"] for v in exc_info.value.violations}
        assert contract_names == {
            "GuardianCortexAnchor",
            "GuardianInsuranceLedger",
            "GuardianInterlockRegistry",
            "GuardianThreatFeedRegistry",
            "GuardianRiskAttestation",
        }

    def test_unknown_third_party_owner_also_blocks(self, monkeypatch):
        """A non-EOA, non-timelock owner (e.g., old multisig) should also be blocked."""
        for k, v in BASE_ENV.items():
            monkeypatch.setenv(k, v)

        mod = _reload_module()

        UNKNOWN_ADDR = "0x0ther00000000000000000000000000000000FF"
        w3_mock = _make_w3_mock(owner_returns=UNKNOWN_ADDR)
        account_mock = MagicMock()
        account_mock.Account.from_key.return_value.address = DEPLOYER_ADDR

        with patch.dict("sys.modules", {
            "web3": MagicMock(Web3=MagicMock(return_value=w3_mock,
                                              HTTPProvider=MagicMock())),
            "eth_account": account_mock,
        }):
            from guardian.onchain_safety import OwnershipNotTransferredError
            with pytest.raises(OwnershipNotTransferredError) as exc_info:
                mod.assert_timelock_owns_all(chain="monad")

        # is_deployer_eoa should be False since owner != deployer
        assert all(not v["is_deployer_eoa"] for v in exc_info.value.violations)


class TestNetworkFailure:
    """RPC failure during owner() call → RuntimeError (not silently swallowed)."""

    def test_rpc_failure_raises_runtime_error(self, monkeypatch):
        for k, v in BASE_ENV.items():
            monkeypatch.setenv(k, v)

        mod = _reload_module()
        w3_mock = _make_w3_mock(owner_returns=ConnectionError("RPC timeout"))

        with patch.dict("sys.modules", {
            "web3": MagicMock(Web3=MagicMock(return_value=w3_mock,
                                              HTTPProvider=MagicMock())),
            "eth_account": MagicMock(),
        }):
            with pytest.raises(RuntimeError, match="Ownership check RPC failed"):
                mod.assert_timelock_owns_all(chain="monad")


class TestCaching:
    """The check must only run once per chain per process lifetime."""

    def test_second_call_skips_rpc(self, monkeypatch):
        for k, v in BASE_ENV.items():
            monkeypatch.setenv(k, v)

        mod = _reload_module()
        w3_mock = _make_w3_mock(owner_returns=TIMELOCK_ADDR)

        with patch.dict("sys.modules", {
            "web3": MagicMock(Web3=MagicMock(return_value=w3_mock,
                                              HTTPProvider=MagicMock())),
            "eth_account": MagicMock(),
        }):
            mod.assert_timelock_owns_all(chain="monad")  # first call — runs check
            first_call_count = w3_mock.eth.contract.call_count

            mod.assert_timelock_owns_all(chain="monad")  # second call — cached
            second_call_count = w3_mock.eth.contract.call_count

        assert first_call_count == 5      # one per contract
        assert second_call_count == 5     # no additional calls

    def test_different_chains_checked_independently(self, monkeypatch):
        for k, v in BASE_ENV.items():
            monkeypatch.setenv(k, v)
        # Also set base contracts so the check has something to call
        monkeypatch.setenv("GUARDIAN_CORTEX_CONTRACT_BASE", "0xC0rtexBase000000000000000000000000001")

        mod = _reload_module()
        w3_mock = _make_w3_mock(owner_returns=TIMELOCK_ADDR)

        with patch.dict("sys.modules", {
            "web3": MagicMock(Web3=MagicMock(return_value=w3_mock,
                                              HTTPProvider=MagicMock())),
            "eth_account": MagicMock(),
        }):
            mod.assert_timelock_owns_all(chain="monad")  # check monad
            calls_after_monad = w3_mock.eth.contract.call_count

            mod.assert_timelock_owns_all(chain="base")   # check base (different chain)
            calls_after_base = w3_mock.eth.contract.call_count

        # base check should have triggered at least one more RPC call
        assert calls_after_base > calls_after_monad

    def test_reset_cache_for_testing_works(self, monkeypatch):
        for k, v in BASE_ENV.items():
            monkeypatch.setenv(k, v)

        mod = _reload_module()
        w3_mock = _make_w3_mock(owner_returns=TIMELOCK_ADDR)

        with patch.dict("sys.modules", {
            "web3": MagicMock(Web3=MagicMock(return_value=w3_mock,
                                              HTTPProvider=MagicMock())),
            "eth_account": MagicMock(),
        }):
            mod.assert_timelock_owns_all(chain="monad")
            first_count = w3_mock.eth.contract.call_count

            mod._reset_cache_for_testing()

            mod.assert_timelock_owns_all(chain="monad")
            second_count = w3_mock.eth.contract.call_count

        # After reset, the check ran again
        assert second_count == first_count * 2


class TestEnvVarCoverage:
    """Env var names must match what each integration module reads."""

    _EXPECTED_PATTERNS = {
        "GuardianCortexAnchor":       "GUARDIAN_CORTEX_CONTRACT_MONAD",
        "GuardianInsuranceLedger":    "GUARDIAN_INSURANCE_CONTRACT_MONAD",
        "GuardianInterlockRegistry":  "GUARDIAN_INTERLOCK_CONTRACT_MONAD",
        "GuardianThreatFeedRegistry": "GUARDIAN_THREATFEED_CONTRACT_MONAD",
        "GuardianRiskAttestation":    "GUARDIAN_RISK_CONTRACT_MONAD",
    }

    def test_env_var_patterns_match_integration_modules(self):
        """
        Assert that the env var names baked into onchain_safety match exactly
        those read by the individual integration files, avoiding a silent
        mismatch where the safety check monitors a different variable than
        the integration code.
        """
        import guardian.onchain_safety as mod

        for name, pattern in mod._CONTRACT_ENV_PATTERNS.items():
            expected = self._EXPECTED_PATTERNS[name]
            actual = pattern.format(chain="MONAD")
            assert actual == expected, (
                f"{name}: onchain_safety reads '{actual}' "
                f"but integration module reads '{expected}'"
            )
