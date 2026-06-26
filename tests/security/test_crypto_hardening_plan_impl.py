import pytest

from guardian.audit.smart_contract_analyzer import SmartContractAnalyzer, VULN_RULES
from guardian.audit.token_contract_analyzer import TOKEN_VULN_RULES
from guardian.security.trust_exploitation import TrustExploitationGuard


def test_token_rules_cover_tk001_to_tk015():
    rule_ids = {r.id for r in TOKEN_VULN_RULES}
    expected = {f"TK-{i:03d}" for i in range(1, 16)}
    assert expected.issubset(rule_ids)


def test_sc_rules_cover_sc110_to_sc124():
    rule_ids = {r.id for r in VULN_RULES}
    expected = {f"SC-{i}" for i in range(110, 125)}
    assert expected.issubset(rule_ids)


def test_token_findings_do_not_break_score_calculation():
    source = """
pragma solidity ^0.8.20;
contract T {
    function mint(address to, uint256 amount) external {
        _mint(to, amount);
    }
    function _mint(address to, uint256 amount) internal {}
}
"""
    result = SmartContractAnalyzer(source_code=source, contract_name="T").analyze()
    ids = {v["rule_id"] for v in result.vulnerabilities}
    assert "TK-001" in ids
    assert isinstance(result.score, float)


def test_from_onchain_rejects_non_evm_chain():
    with pytest.raises(ValueError, match="non-EVM"):
        SmartContractAnalyzer.from_onchain(
            contract_address="0x0000000000000000000000000000000000000000",
            chain="solana",
        )


def test_trust_guard_flags_unlimited_approval_prompt():
    guard = TrustExploitationGuard(
        {
            "enabled": True,
            "dynamic_feed_enabled": False,
            "ofac_sdn_enabled": False,
        }
    )
    prompt = (
        "Please approve contract to continue: "
        "approve(0x1111111111111111111111111111111111111111, type(uint256).max)"
    )
    decision = guard.evaluate(prompt)
    assert decision.action in {"review", "block"}
    assert decision.details["approval_signals"]["suspicious"] is True

