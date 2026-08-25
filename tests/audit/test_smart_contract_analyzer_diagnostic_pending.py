import os, re, pytest
from guardian.audit.smart_contract_analyzer import SmartContractAnalyzer

FIXTURES_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../../guardian/audit/test_fixtures/smart_contracts",
    )
)

KNOWN_PENDING_EVASIONS = [
    "SC-032_evasion.sol",
    "SC-080_evasion.vy",
]

@pytest.mark.xfail(strict=True, reason="Pending evasion edge-case detection — see SmartContractAnalyzer_gap_and_fix_spec.md")
@pytest.mark.parametrize("filename", KNOWN_PENDING_EVASIONS)
def test_smart_contract_analyzer_diagnostic_pending(filename):
    match = re.search(r"((?:VY|SC)-\d{3})", filename)
    assert match, f"Filename {filename} does not contain rule ID (VY-XXX or SC-XXX)"
    rule_id = match.group(1)

    filepath = os.path.join(FIXTURES_DIR, filename)
    with open(filepath, "r", encoding="utf-8") as f:
        snippet = f.read()

    analyzer = SmartContractAnalyzer(source_code=snippet, contract_name="TestWrapper")
    result = analyzer.analyze()

    found = any(v["rule_id"] == rule_id for v in result.vulnerabilities)
    is_vuln_or_evasion = "vuln" in filename or "evasion" in filename
    is_safe = "safe" in filename

    if is_vuln_or_evasion:
        assert found, f"[{rule_id}] Expected vulnerability in {filename}"
    elif is_safe:
        assert not found, f"[{rule_id}] Unexpected false positive in safe fixture {filename}"
