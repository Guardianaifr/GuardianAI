"""Per-agent rules: built-in defaults, allowlists, token caps, the rules API."""
import json

import pytest

from guardian.relayer.agent_rules import AgentRulesStore, build_policy
from guardian.relayer.attestation_service import SafetyAttestationService

USDC = "0x534b2f3A21130d7a60830c2Df862319e593943A3"
VENDOR = "0x1111111111111111111111111111111111111111"
STRANGER = "0x7a3B9c1D2e4F5a6B7c8D9e0F1a2B3c4D5e6F7a8B"
ETH = 10**18
KEY = "0x" + "11" * 32


def _transfer(to, amount):
    return "0xa9059cbb" + to[2:].lower().rjust(64, "0") + hex(amount)[2:].rjust(64, "0")


def _svc(store):
    return SafetyAttestationService(private_key=KEY, agent_policies=store.per_agent, default_policy=store.default)


@pytest.fixture
def store(tmp_path):
    return AgentRulesStore(str(tmp_path / "agent_policies.json"))


def test_built_in_defaults_cap_native_and_usdc(store):
    svc = _svc(store)
    assert svc.evaluate_and_attest("any", STRANGER, "0x", ETH // 2, "pay").status == "approved"
    assert svc.evaluate_and_attest("any", STRANGER, "0x", 2 * ETH, "pay").status == "blocked"
    assert svc.evaluate_and_attest("any", USDC, _transfer(STRANGER, 50 * 10**6), 0, "pay").status == "approved"
    assert svc.evaluate_and_attest("any", USDC, _transfer(STRANGER, 500 * 10**6), 0, "pay").status == "blocked"


def test_daily_cap_stops_split_payments(store):
    svc = _svc(store)
    results = [svc.evaluate_and_attest("split", STRANGER, "0x", 9 * ETH // 10, "pay").status for _ in range(10)]
    assert results.count("approved") == 5  # 5 x 0.9 = 4.5 MON; the 6th would exceed 5 MON


def test_recipient_allowlist_for_native_and_tokens(store):
    store.set_agent("payroll", {"allowed_recipients": [VENDOR]})
    svc = _svc(store)
    assert svc.evaluate_and_attest("payroll", VENDOR, "0x", ETH // 10, "pay").status == "approved"
    r = svc.evaluate_and_attest("payroll", STRANGER, "0x", ETH // 10, "pay")
    assert r.status == "blocked" and "allowed list" in r.reasons[0]
    assert svc.evaluate_and_attest("payroll", USDC, _transfer(STRANGER, 10**6), 0, "pay").status == "blocked"
    assert svc.evaluate_and_attest("payroll", USDC, _transfer(VENDOR, 10**6), 0, "pay").status == "approved"


def test_require_prompt(store):
    store.set_agent("strict", {"require_prompt": True})
    svc = _svc(store)
    assert svc.evaluate_and_attest("strict", VENDOR, "0x", 1, None).status == "blocked"
    assert svc.evaluate_and_attest("strict", VENDOR, "0x", 1, "pay the vendor").status == "approved"


def test_rules_persist_and_reload(store):
    store.set_agent("bot-7", {"max_value_per_tx_mon": "0.1"})
    again = AgentRulesStore(str(store.path))
    rules, custom = again.rules_for("bot-7")
    assert custom and rules["max_value_per_tx_mon"] == "0.1"
    assert again.per_agent["bot-7"].max_value_per_tx == ETH // 10


@pytest.mark.parametrize("bad", [
    {"max_value_per_tx_mon": "-1"},
    {"allowed_recipients": ["not-an-address"]},
    {"max_token_per_tx": {"0x2222222222222222222222222222222222222222": "5"}},  # no decimals
    {"surprise": True},
])
def test_invalid_rules_rejected_and_not_saved(store, bad):
    with pytest.raises((ValueError, ArithmeticError)):
        store.set_agent("x", bad)
    assert not store.path.exists()


def test_rules_api_requires_admin_token(tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_AGENT_POLICIES_FILE", str(tmp_path / "rules.json"))
    monkeypatch.setenv("GUARDIAN_THREAT_FEED_CHECK", "false")
    monkeypatch.setenv("GUARDIAN_ATTESTATION_SIGNER_KEY", KEY)
    monkeypatch.setenv("GUARDIAN_ADMIN_TOKEN", "t0ken")
    monkeypatch.delenv("GUARDIAN_X402_ENABLED", raising=False)
    from guardian.web3sec.rpc_relay import GuardianRPCRelay
    c = GuardianRPCRelay({}).app.test_client()

    assert c.get("/api/v1/agents/bot-1/rules").get_json()["rules"]["max_value_per_tx_mon"] == "1"
    assert c.put("/api/v1/agents/bot-1/rules", json={"max_value_per_tx_mon": "0.2"}).status_code == 401
    r = c.put("/api/v1/agents/bot-1/rules", json={"max_value_per_tx_mon": "0.2"},
              headers={"Authorization": "Bearer t0ken"})
    assert r.status_code == 200 and r.get_json()["rules"]["max_value_per_tx_mon"] == "0.2"
    assert c.put("/api/v1/agents/bot-1/rules", json={"oops": 1},
                 headers={"Authorization": "Bearer t0ken"}).status_code == 400
    body = c.post("/api/v1/attest", json={"agent_id": "bot-1", "target": STRANGER, "value": ETH // 2, "prompt": "pay"}).get_json()
    assert body["status"] == "blocked"
    assert json.loads((tmp_path / "rules.json").read_text())["agents"]["bot-1"] == {"max_value_per_tx_mon": "0.2"}
