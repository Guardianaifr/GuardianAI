"""Offline tests: the relay refuses payments to wallets on the on-chain scam list."""
from eth_abi import encode

from guardian.relayer.attestation_service import SafetyAttestationService
from guardian.relayer.threat_feed import ThreatFeedChecker, value_destinations

SCAM = "0x535eA8d8eABA5D072f7DfCef98C32d8D1d8E1CBd"
OK = "0x7a3B9c1D2e4F5a6B7c8D9e0F1a2B3c4D5e6F7a8B"
USDC = "0x534b2f3A21130d7a60830c2Df862319e593943A3"


def _pad(a):
    return a[2:].lower().rjust(64, "0")


def _fake_call(flagged):
    calls = []

    def call(to, data):
        addr = "0x" + data[-40:]
        calls.append(addr)
        hit = addr.lower() in {f.lower() for f in flagged}
        return encode(["bool", "string"], [hit, "drainer" if hit else ""])
    return call, calls


def _svc(checker, **kw):
    return SafetyAttestationService(private_key="0x" + "11" * 32, threat_checker=checker, **kw)


def test_value_destinations_decodes_token_recipients():
    assert value_destinations(USDC, "0xa9059cbb" + _pad(SCAM) + "0" * 64) == [USDC.lower(), SCAM.lower()]
    assert value_destinations(USDC, "0x23b872dd" + _pad(OK) + _pad(SCAM) + "0" * 64)[1] == SCAM.lower()
    assert value_destinations(OK, "0x") == [OK.lower()]


def test_blocks_native_payment_to_listed_wallet_even_without_prompt():
    call, _ = _fake_call([SCAM])
    r = _svc(ThreatFeedChecker("http://unused", call=call)).evaluate_and_attest("a", SCAM, "0x", 10**18, None)
    assert r.status == "blocked" and r.risk_score == 100 and "scam list" in r.reasons[0]


def test_blocks_erc20_transfer_to_listed_wallet():
    call, _ = _fake_call([SCAM])
    data = "0xa9059cbb" + _pad(SCAM) + hex(10**12)[2:].rjust(64, "0")
    r = _svc(ThreatFeedChecker("http://unused", call=call)).evaluate_and_attest("a", USDC, data, 0, "Settle the vendor")
    assert r.status == "blocked"


def test_allows_unlisted_recipient_and_caches_lookups():
    call, calls = _fake_call([SCAM])
    svc = _svc(ThreatFeedChecker("http://unused", call=call))
    assert svc.evaluate_and_attest("a", OK, "0x", 1, "pay").status == "approved"
    svc.evaluate_and_attest("a", OK, "0x", 1, "pay")
    assert len(calls) == 1  # second lookup served from cache


def test_fails_closed_when_scam_list_unreachable():
    def boom(to, data):
        raise ConnectionError("rpc down")
    r = _svc(ThreatFeedChecker("http://unused", call=boom)).evaluate_and_attest("a", OK, "0x", 1, "pay")
    assert r.status == "blocked" and "failing closed" in r.reasons[0]


def test_set_approval_for_all_is_blocked():
    data = "0xa22cb465" + _pad(OK) + "1".rjust(64, "0")
    r = _svc(None).evaluate_and_attest("a", OK, data, 0, "List my NFTs")
    assert r.status == "blocked"
