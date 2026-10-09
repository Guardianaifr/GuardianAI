"""Passkey agent cards (Mera identity namespace) checked by the relay before /api/v1/attest."""
import json
from unittest.mock import MagicMock

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

from guardian.relayer.agent_card import card_message, load_registry, verify_card

# Signed in headless Chromium by website/mera/ with a WebAuthn virtual authenticator (real PRF ceremony,
# real Mera Ed25519 session), so this also proves the browser and Python agree on the message bytes.
BROWSER_CARD = {
    "version": 1,
    "agent_id": "treasury-agent",
    "wallet": "0xccb137694f2910c8ec4883d108c989648019d335",
    "expires_at": 1792140750,
    "did": "did:guardian:ed25519:8ad8a88196f35f4a925b2c2a1800ff9702149a1f219fd86aa1091e1b82128c44",
    "signature": "2f685975f8576ee80154b948eb45189bec63ac51befcfbc983013984518fce13"
                 "be97b0846a7743a457281346c7b1dcbf10bfc1761aa6669c60f16e20693a7909",
}
WALLET = "0xCCb137694f2910c8Ec4883d108c989648019D335"
NOW = 1792140750 - 7 * 86400 + 60  # one minute after the card was issued
REGISTRY = {"treasury-agent": BROWSER_CARD["did"]}


def _card(key: Ed25519PrivateKey, agent: str, wallet: str, expires: int) -> dict:
    pub = key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    return {"version": 1, "agent_id": agent, "wallet": wallet.lower(), "expires_at": expires,
            "did": f"did:guardian:ed25519:{pub}", "signature": key.sign(card_message(agent, wallet, expires)).hex()}


def test_browser_signed_card_verifies():
    r = verify_card("treasury-agent", WALLET, BROWSER_CARD, REGISTRY, now=NOW)
    assert r.required and r.ok, r.reason


def test_unregistered_agent_needs_no_card():
    r = verify_card("someone-else", WALLET, None, REGISTRY, now=NOW)
    assert not r.required and r.ok


@pytest.mark.parametrize("mutate, reason", [
    (lambda c: None, "agent card required"),
    (lambda c: {**c, "expires_at": c["expires_at"] + 1}, "invalid agent card signature"),
    (lambda c: {**c, "wallet": "0x" + "1" * 40}, "different wallet"),
    (lambda c: {**c, "agent_id": "other"}, "different agent"),
    (lambda c: {**c, "version": 2}, "version"),
    (lambda c: {**c, "signature": "zz"}, "malformed agent card signature"),
    (lambda c: {k: v for k, v in c.items() if k != "did"}, "malformed"),
])
def test_tampered_cards_rejected(mutate, reason):
    r = verify_card("treasury-agent", WALLET, mutate(dict(BROWSER_CARD)), REGISTRY, now=NOW)
    assert r.required and not r.ok and reason in r.reason


def test_card_from_another_passkey_rejected():
    forged = _card(Ed25519PrivateKey.generate(), "treasury-agent", WALLET, NOW + 3600)
    r = verify_card("treasury-agent", WALLET, forged, REGISTRY, now=NOW)
    assert not r.ok and "registered passkey identity" in r.reason


def test_expired_and_too_long_cards_rejected():
    assert "expired" in verify_card("treasury-agent", WALLET, BROWSER_CARD, REGISTRY, now=BROWSER_CARD["expires_at"]).reason
    key = Ed25519PrivateKey.generate()
    card = _card(key, "a", WALLET, NOW + 31 * 86400)
    assert "30 days" in verify_card("a", WALLET, card, {"a": card["did"]}, now=NOW).reason


def test_registry_file(tmp_path, monkeypatch):
    p = tmp_path / "ids.json"
    p.write_text(json.dumps({"_comment": "x", "treasury-agent": BROWSER_CARD["did"]}))
    monkeypatch.setenv("GUARDIAN_AGENT_CARD_REGISTRY", str(p))
    assert load_registry() == REGISTRY
    p.write_text(json.dumps({"a": "did:key:nope"}))
    with pytest.raises(ValueError):
        load_registry()
    monkeypatch.setenv("GUARDIAN_AGENT_CARD_REGISTRY", str(tmp_path / "missing.json"))
    assert load_registry() == {}


@pytest.fixture
def relay(tmp_path, monkeypatch):
    from guardian.web3sec.rpc_relay import GuardianRPCRelay
    reg = tmp_path / "ids.json"
    reg.write_text(json.dumps(REGISTRY))
    monkeypatch.setenv("GUARDIAN_AGENT_CARD_REGISTRY", str(reg))
    r = GuardianRPCRelay({"web3_security": {"upstream_rpc": "http://127.0.0.1:1"}})
    r.app.config["TESTING"] = True
    svc = MagicMock()
    svc.evaluate_and_attest.return_value.status = "approved"
    svc.evaluate_and_attest.return_value.to_dict.return_value = {"status": "approved", "risk_score": 0, "reasons": []}
    r.attestation_service = svc
    return r


def test_relay_blocks_registered_agent_without_card(relay):
    with relay.app.test_client() as c:
        resp = c.post("/api/v1/attest", json={"agent_id": "treasury-agent", "target": "0x" + "2" * 40, "wallet": WALLET})
    assert resp.status_code == 403
    assert resp.get_json()["agent_identity"] == "rejected"
    relay.attestation_service.evaluate_and_attest.assert_not_called()


def test_relay_accepts_valid_card_and_reports_it(relay, monkeypatch):
    import guardian.relayer.agent_card as ac
    monkeypatch.setattr(ac.time, "time", lambda: NOW)
    with relay.app.test_client() as c:
        resp = c.post("/api/v1/attest", json={"agent_id": "treasury-agent", "target": "0x" + "2" * 40,
                                              "wallet": WALLET, "agent_card": BROWSER_CARD})
    assert resp.status_code == 200, resp.get_json()
    assert resp.get_json()["agent_identity"] == "passkey-verified"
    relay.attestation_service.evaluate_and_attest.assert_called_once()


def test_relay_unregistered_agent_unchanged(relay):
    with relay.app.test_client() as c:
        resp = c.post("/api/v1/attest", json={"agent_id": "privy-agent:0xabc", "target": "0x" + "2" * 40})
    assert resp.status_code == 200
    assert "agent_identity" not in resp.get_json()
