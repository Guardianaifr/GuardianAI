import os, re, pytest
from guardian.audit.smart_contract_analyzer import SmartContractAnalyzer

FIXTURES_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../../guardian/audit/test_fixtures/smart_contracts",
    )
)

UNTESTED_19_RULES = [
    "SC-121",
    "SC-123",
    "SC-124",
    "VY-001",
    "VY-003",
    "VY-004",
    "VY-005",
    "SC-130",
    "SC-132",
    "SC-133",
    "SC-134",
    "SC-135"
]

def get_untested_fixtures():
    if not os.path.exists(FIXTURES_DIR):
        return []
    files = []
    for f in sorted(os.listdir(FIXTURES_DIR)):
        for rid in UNTESTED_19_RULES:
            if f.startswith(rid + "_"):
                files.append(f)
                break
    return files

@pytest.mark.xfail(reason="diagnostic only, not yet fixed — see SmartContractAnalyzer_gap_and_fix_spec.md")
@pytest.mark.parametrize("filename", get_untested_fixtures())
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
