import json

import pytest
from web3 import Web3

from guardian.relayer.threat_oracle_feed import build_feed, canonical_entries_json, load_entries


def _write(tmp_path, entries):
    p = tmp_path / "feed.json"
    p.write_text(json.dumps({"entries": entries}), encoding="utf-8")
    return str(p)


def test_feed_is_deterministic_sorted_and_deduplicated(tmp_path):
    a, b = "0x" + "b" * 40, "0x" + "A" * 40
    p = _write(tmp_path, [{"address": a}, {"address": b, "flagged": True}, {"address": a, "flagged": False}])
    entries = load_entries(p)
    assert entries == [{"address": "0x" + "a" * 40, "flagged": True}, {"address": a, "flagged": False}]
    f1, f2 = build_feed({"blocked": 2, "intercepted": 5, "passed": 3}, p), build_feed({"blocked": 2}, p)
    assert f1["entries_json"] == f2["entries_json"] and f1["digest"] == f2["digest"]
    assert f1["digest"] == "0x" + Web3.keccak(text=canonical_entries_json(entries)).hex().removeprefix("0x")
    assert f1["stats"] == {"blocked": 2, "intercepted": 5, "passed": 3}


def test_invalid_address_and_oversized_feed_are_refused(tmp_path):
    with pytest.raises(ValueError, match="Invalid address"):
        load_entries(_write(tmp_path, [{"address": "0x123"}]))
    many = [{"address": "0x" + format(i + 1, "040x")} for i in range(101)]
    with pytest.raises(ValueError, match="max per report"):
        load_entries(_write(tmp_path, many))


def test_missing_file_is_an_empty_feed(tmp_path):
    f = build_feed({}, str(tmp_path / "nope.json"))
    assert f["count"] == 0 and f["entries_json"] == "[]"


def test_shipped_feed_file_is_valid():
    f = build_feed({})
    assert f["count"] >= 1


def test_relay_endpoint_serves_feed_and_counts_attestations(monkeypatch):
    monkeypatch.setenv("GUARDIAN_THREAT_FEED_CHECK", "false")
    monkeypatch.setenv("GUARDIAN_ATTESTATION_SIGNER_KEY", "0x" + "22" * 32)
    from guardian.web3sec.rpc_relay import GuardianRPCRelay
    relay = GuardianRPCRelay({"web3_security": {"listen_port": 0}})
    c = relay.app.test_client()
    before = c.get("/api/v1/threat-oracle/feed").get_json()
    assert before["count"] >= 1 and before["digest"].startswith("0x")
    c.post("/api/v1/attest", json={"agent_id": "t", "target": "0x534b2f3A21130d7a60830c2Df862319e593943A3", "data": "0x"})
    after = c.get("/api/v1/threat-oracle/feed").get_json()
    assert after["stats"]["intercepted"] == before["stats"]["intercepted"] + 1
