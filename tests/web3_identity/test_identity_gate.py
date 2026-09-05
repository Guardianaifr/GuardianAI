"""
Offline tests for guardian.passport.identity_gate.IdentityGate.

No network, no chain — mirrors the offline convention used by
test_erc8004_registrar.py. Uses a minimal fake passport engine rather than
a real PassportEngine/sqlite DB so these stay fast and deterministic; the
DB-backed paths (get_passport_by_owner_address, the owner_pubkey index) are
covered separately in test_passport_core.py.
"""
from __future__ import annotations

import importlib
import os
import sqlite3
import time

import pytest

from guardian.passport import identity_gate as ig_module
from guardian.passport.identity_gate import IdentityGate


# ── Fixtures ─────────────────────────────────────────────────────────────

class FakePassport:
    def __init__(self, agent_id, tier="UNVERIFIED", is_active=True, token_id=None, owner_pubkey=None):
        self.agent_id = agent_id
        self.tier = tier
        self.is_active = is_active
        self.token_id = token_id
        self.owner_pubkey = owner_pubkey


class FakePassportEngine:
    """Duck-types PassportEngine's two read methods the gate depends on."""

    def __init__(self, db_path=None):
        self.db_path = db_path
        self._by_id = {}
        self._by_addr = {}
        self.get_passport_calls = 0

    def get_passport(self, agent_id):
        self.get_passport_calls += 1
        return self._by_id.get(agent_id)

    def get_passport_by_owner_address(self, address):
        return self._by_addr.get(address.lower())


GOOD_ADDR_LOWER = "0x" + "ab" * 19 + "cd"
GOOD_ADDR_MIXED = "0x" + "AB" * 19 + "cD"


@pytest.fixture(autouse=True)
def _clean_env(monkeypatch):
    """Every IDENTITY_GATE_* var starts unset for each test; each test sets
    exactly the ones it cares about, so no test can leak config into another."""
    for key in list(os.environ):
        if key.startswith("GUARDIAN_IDENTITY_GATE_"):
            monkeypatch.delenv(key, raising=False)
    yield


@pytest.fixture
def engine():
    return FakePassportEngine()


def make_gate(engine, **env):
    for k, v in env.items():
        os.environ[k] = v
    return IdentityGate(engine)


# ── Tests ────────────────────────────────────────────────────────────────

def test_gate_disabled_allows_all(engine):
    gate = make_gate(engine, GUARDIAN_IDENTITY_GATE_ENABLED="false")
    result = gate.check_agent("anyone")
    assert result.allowed is True
    assert result.source == "disabled"
    assert engine.get_passport_calls == 0  # disabled gate must not touch the DB


def test_gate_allows_unverified_by_default(engine):
    engine._by_id["agent-1"] = FakePassport("agent-1", tier="UNVERIFIED", is_active=True)
    gate = make_gate(engine, GUARDIAN_IDENTITY_GATE_ENABLED="true")
    result = gate.check_agent("agent-1")
    assert result.allowed is True
    assert result.tier == "UNVERIFIED"


def test_gate_blocks_revoked_passport(engine):
    engine._by_id["agent-2"] = FakePassport("agent-2", tier="GOLD", is_active=False)
    gate = make_gate(engine, GUARDIAN_IDENTITY_GATE_ENABLED="true")
    result = gate.check_agent("agent-2")
    assert result.allowed is False
    assert result.reason == "revoked_passport"


def test_gate_blocks_below_min_tier(engine):
    engine._by_id["agent-3"] = FakePassport("agent-3", tier="UNVERIFIED", is_active=True)
    gate = make_gate(
        engine,
        GUARDIAN_IDENTITY_GATE_ENABLED="true",
        GUARDIAN_IDENTITY_GATE_MIN_TIER="SILVER",
    )
    result = gate.check_agent("agent-3")
    assert result.allowed is False
    assert result.reason == "below_minimum_tier"


def test_gate_allows_silver_when_silver_required(engine):
    engine._by_id["agent-4"] = FakePassport("agent-4", tier="SILVER", is_active=True)
    gate = make_gate(
        engine,
        GUARDIAN_IDENTITY_GATE_ENABLED="true",
        GUARDIAN_IDENTITY_GATE_MIN_TIER="SILVER",
    )
    result = gate.check_agent("agent-4")
    assert result.allowed is True
    assert result.tier == "SILVER"


def test_gate_unknown_agent_warns_allow(engine):
    gate = make_gate(
        engine,
        GUARDIAN_IDENTITY_GATE_ENABLED="true",
        GUARDIAN_IDENTITY_GATE_UNREGISTERED_BLOCK="false",
    )
    result = gate.check_agent("ghost-agent")
    assert result.allowed is True
    assert result.tier == "UNKNOWN"
    assert result.source == "unregistered"


def test_gate_unknown_agent_blocks_when_configured(engine):
    gate = make_gate(
        engine,
        GUARDIAN_IDENTITY_GATE_ENABLED="true",
        GUARDIAN_IDENTITY_GATE_UNREGISTERED_BLOCK="true",
    )
    result = gate.check_agent("ghost-agent-2")
    assert result.allowed is False
    assert result.reason == "no_passport"


def test_gate_cache_hit(engine):
    engine._by_id["agent-5"] = FakePassport("agent-5", tier="SILVER", is_active=True)
    gate = make_gate(
        engine,
        GUARDIAN_IDENTITY_GATE_ENABLED="true",
        GUARDIAN_IDENTITY_GATE_CACHE_TTL="60",
    )
    gate.check_agent("agent-5")
    gate.check_agent("agent-5")
    assert engine.get_passport_calls == 1


def test_gate_cache_disabled_hits_db_every_time(engine):
    engine._by_id["agent-6"] = FakePassport("agent-6", tier="SILVER", is_active=True)
    gate = make_gate(
        engine,
        GUARDIAN_IDENTITY_GATE_ENABLED="true",
        GUARDIAN_IDENTITY_GATE_CACHE_TTL="0",
    )
    gate.check_agent("agent-6")
    gate.check_agent("agent-6")
    assert engine.get_passport_calls == 2


def test_gate_shadow_mode_allows_but_reports_real_reason(engine):
    engine._by_id["agent-7"] = FakePassport("agent-7", tier="UNVERIFIED", is_active=True)
    gate = make_gate(
        engine,
        GUARDIAN_IDENTITY_GATE_ENABLED="true",
        GUARDIAN_IDENTITY_GATE_MIN_TIER="GOLD",
        GUARDIAN_IDENTITY_GATE_MODE="shadow",
    )
    result = gate.check_agent("agent-7")
    assert result.allowed is True  # shadow mode never actually blocks
    assert result.reason == "below_minimum_tier"  # but the real verdict is visible


def test_gate_lookup_error_fails_open_by_default(engine):
    def boom(agent_id):
        raise RuntimeError("db is on fire")
    engine.get_passport = boom
    gate = make_gate(engine, GUARDIAN_IDENTITY_GATE_ENABLED="true")
    result = gate.check_agent("agent-8")
    assert result.allowed is True
    assert result.source == "error"


def test_gate_lookup_error_blocks_when_fail_closed(engine):
    def boom(agent_id):
        raise RuntimeError("db is on fire")
    engine.get_passport = boom
    gate = make_gate(
        engine,
        GUARDIAN_IDENTITY_GATE_ENABLED="true",
        GUARDIAN_IDENTITY_GATE_FAIL_CLOSED="true",
    )
    result = gate.check_agent("agent-9")
    assert result.allowed is False
    assert result.source == "error"


def test_gate_malformed_address_is_unregistered_not_error(engine):
    gate = make_gate(engine, GUARDIAN_IDENTITY_GATE_ENABLED="true")
    result = gate.check_address("not-an-address")
    assert result.allowed is True
    assert result.reason == "malformed_address"
    assert result.source == "unregistered"


def test_gate_address_resolves_case_insensitively(engine):
    engine._by_addr[GOOD_ADDR_LOWER] = FakePassport("addr-agent", tier="GOLD", is_active=True)
    gate = make_gate(engine, GUARDIAN_IDENTITY_GATE_ENABLED="true")
    result = gate.check_address(GOOD_ADDR_MIXED)
    assert result.allowed is True
    assert result.tier == "GOLD"


def test_gate_unknown_min_tier_falls_back_to_unverified(engine, caplog):
    engine._by_id["agent-10"] = FakePassport("agent-10", tier="UNVERIFIED", is_active=True)
    gate = make_gate(
        engine,
        GUARDIAN_IDENTITY_GATE_ENABLED="true",
        GUARDIAN_IDENTITY_GATE_MIN_TIER="PLATINUM",  # not a real tier
    )
    assert gate.min_tier == "UNVERIFIED"
    result = gate.check_agent("agent-10")
    assert result.allowed is True


# ── Relay integration (identity_gate wired via check_address) ─────────────
# Full HTTP-level relay integration (test_relay_identity_block /
# test_relay_identity_disabled_passthrough from the original plan) belongs
# in tests/web3_identity/test_rpc_relay_identity_integration.py once Flask
# test-client fixtures for GuardianRPCRelay exist in this suite — kept
# separate so this file stays dependency-light and fast.


# ── erc8004_registrations collision (real sqlite, not the fake engine) ────
# The fake engine above can't exercise _agent_id_for_confirmed_owner_address,
# which talks to erc8004_registrations directly via raw sqlite3. This case
# needs a real on-disk DB with both tables, matching production (both live
# in the same file by default — see erc8004_registrar.default_db_path()).

@pytest.fixture
def real_db(tmp_path, monkeypatch):
    for key in list(os.environ):
        if key.startswith("GUARDIAN_IDENTITY_GATE_"):
            monkeypatch.delenv(key, raising=False)
    from guardian.passport.passport_core import PassportEngine
    db_path = str(tmp_path / "guardian.db")
    engine = PassportEngine(db_path=db_path)

    conn = sqlite3.connect(db_path)
    conn.execute(
        "CREATE TABLE IF NOT EXISTS erc8004_registrations "
        "(agent_id TEXT, owner_address TEXT, status TEXT, updated_at REAL, token_id INTEGER)"
    )
    conn.commit()
    conn.close()
    return engine, db_path


REAL_OWNER = "0x1d4549b95dccac8203393543187b25b3137d0bf6"


def _insert_registration(db_path, agent_id, owner_address, updated_at, token_id):
    conn = sqlite3.connect(db_path)
    conn.execute(
        "INSERT INTO erc8004_registrations (agent_id, owner_address, status, updated_at, token_id) VALUES (?,?,?,?,?)",
        (agent_id, owner_address, "confirmed", updated_at, token_id),
    )
    conn.commit()
    conn.close()


def test_address_resolution_prefers_active_over_more_recent_revoked(real_db):
    """Regression test: a wallet shared by an active and a revoked agent's
    confirmed ERC-8004 registrations must resolve to the ACTIVE agent, even
    when the revoked agent's registration row was touched more recently.

    Without the LEFT JOIN agent_passports / COALESCE(is_active, 0) DESC
    ordering, this previously resolved to the revoked agent purely by
    updated_at recency — which meant the real, active agent's real on-chain
    wallet got blocked as "revoked_passport" instead of allowed. Found via
    a live drift-reconciliation run (2026-08) where nova-treasury (active)
    and demo-trading-agent (revoked) ended up sharing an owner_address
    after a manual data fix touched demo-trading-agent's row last.
    """
    engine, db_path = real_db
    engine.issue_passport("nova-treasury", "placeholder-addr-1")
    engine.issue_passport("demo-trading-agent", "placeholder-addr-2")
    engine.revoke_passport("demo-trading-agent")

    now = time.time()
    _insert_registration(db_path, "nova-treasury", REAL_OWNER, now, 5)
    _insert_registration(db_path, "demo-trading-agent", REAL_OWNER, now + 5, 3)  # touched later

    gate = ig_module.IdentityGate(engine, erc8004_db_path=db_path)
    os.environ["GUARDIAN_IDENTITY_GATE_ENABLED"] = "true"
    gate2 = ig_module.IdentityGate(engine, erc8004_db_path=db_path)  # re-init to pick up env

    resolved_agent_id = gate2._agent_id_for_confirmed_owner_address(REAL_OWNER)
    assert resolved_agent_id == "nova-treasury"

    result = gate2.check_address(REAL_OWNER)
    assert result.allowed is True
    assert result.reason == "ok"
    assert result.details.get("agent_id") == "nova-treasury"


def test_address_resolution_still_blocks_lone_revoked_agent(real_db):
    """Sanity check the fix above didn't break the simple case: a wallet
    with only a revoked match (no active alternative) still blocks."""
    engine, db_path = real_db
    engine.issue_passport("lonely-revoked-agent", "placeholder-addr-3")
    engine.revoke_passport("lonely-revoked-agent")

    solo_owner = "0x" + "c1" * 20
    _insert_registration(db_path, "lonely-revoked-agent", solo_owner, time.time(), 1)

    os.environ["GUARDIAN_IDENTITY_GATE_ENABLED"] = "true"
    gate = ig_module.IdentityGate(engine, erc8004_db_path=db_path)

    result = gate.check_address(solo_owner)
    assert result.allowed is False
    assert result.reason == "revoked_passport"


def test_onchain_verify_defaults_and_ownership_mismatch(engine, monkeypatch):
    """Verify onchain_verify defaults to True in production and blocks on ownership mismatch."""
    from unittest.mock import MagicMock, patch

    # 1. Defaults to True in production
    monkeypatch.setenv("GUARDIAN_ENV", "production")
    gate_prod = ig_module.IdentityGate(engine)
    assert gate_prod.onchain_verify is True

    # 2. Ownership verification: match vs mismatch
    passport = FakePassport("agent-onchain", tier="GOLD", is_active=True, token_id=42)
    gate = ig_module.IdentityGate(engine, onchain_verify=True)

    mock_contract = MagicMock()
    mock_contract.functions.ownerOf(42).call.return_value = "0x2222222222222222222222222222222222222222"
    with patch("web3.eth.Eth.contract", return_value=mock_contract):
        # Claimed address matches ownerOf -> allowed
        res_match = gate._verify_onchain(passport, claimed_address="0x2222222222222222222222222222222222222222")
        assert res_match is not None
        assert res_match.allowed is True
        assert res_match.source == "onchain"

        # Claimed address does NOT match ownerOf -> blocked
        res_mismatch = gate._verify_onchain(passport, claimed_address="0x3333333333333333333333333333333333333333")
        assert res_mismatch is not None
        assert res_mismatch.allowed is False
        assert res_mismatch.reason == "onchain_owner_mismatch"

