"""
Test: eBTC/Echo Protocol exploit pattern detection.

Simulates the exact contract governance setup that enabled the Monad eBTC exploit:
  - AccessControl with single-EOA admin
  - grantRole / revokeRole with no timelock
  - Uncapped mint function
  - DEFAULT_ADMIN_ROLE can grant MINTER_ROLE directly

Verifies that GuardianAI's Smart Contract Analyzer catches ALL of these.
"""
import sys, io, json, os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")

from guardian.audit.smart_contract_analyzer import SmartContractAnalyzer, VULN_RULES
from dataclasses import asdict

PASS = True

def check(label, ok, detail=""):
    global PASS
    icon = "[OK]" if ok else "[FAIL]"
    print(f"  {icon} {label}", f"-- {detail}" if detail else "")
    if not ok:
        PASS = False


# ── Simulated eBTC-style contract ────────────────────────────────────────────
EBTC_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessControl.sol";

contract eBTC is ERC20, AccessControl {
    bytes32 public constant MINTER_ROLE = keccak256("MINTER_ROLE");

    constructor() ERC20("Echo BTC", "eBTC") {
        _setupRole(DEFAULT_ADMIN_ROLE, msg.sender);  // single EOA admin
        _setupRole(MINTER_ROLE, msg.sender);
    }

    // No supply cap, no timelock, admin can grant minter to anyone
    function mint(address to, uint256 amount) external onlyRole(MINTER_ROLE) {
        _mint(to, amount);
    }

    // Anyone with DEFAULT_ADMIN_ROLE can instantly grant/revoke any role
    function grantMinter(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        grantRole(MINTER_ROLE, account);
    }

    function revokeMinter(address account) external onlyRole(DEFAULT_ADMIN_ROLE) {
        revokeRole(MINTER_ROLE, account);
    }
}
"""

# ── A hardened version (what eBTC SHOULD have looked like) ───────────────────
HARDENED_CONTRACT = """
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import "@openzeppelin/contracts/token/ERC20/ERC20.sol";
import "@openzeppelin/contracts/access/AccessManager.sol";
import "@openzeppelin/contracts/governance/TimelockController.sol";

contract HardenedBTC is ERC20 {
    uint256 public constant MAX_SUPPLY = 21_000 * 1e18;
    TimelockController public immutable timelock;
    address public immutable multiSig;

    constructor(address _timelock, address _multiSig) ERC20("Hardened BTC", "hBTC") {
        timelock = TimelockController(payable(_timelock));
        multiSig = _multiSig;
    }

    function mint(address to, uint256 amount) external {
        require(msg.sender == address(timelock), "Only timelock");
        require(totalSupply() + amount <= MAX_SUPPLY, "Cap exceeded");
        _mint(to, amount);
    }
}
"""


def main():
    print("=" * 60)
    print("  eBTC EXPLOIT PATTERN DETECTION TEST")
    print("  (Echo Protocol / Monad - May 2026)")
    print("=" * 60)

    # ── Test 1: Analyze the vulnerable eBTC-style contract ───────────────
    print("\n[1] Analyzing eBTC-style vulnerable contract...")
    analyzer = SmartContractAnalyzer(
        source_code=EBTC_CONTRACT,
        contract_name="eBTC",
        contract_address="0xA338e1234567890abcdef1234567890abcdef1234",
        chain="monad",
    )
    result = analyzer.analyze()
    data = asdict(result)

    check("Chain is monad", data["chain"] == "monad")
    check("Language is solidity", data["language"] == "solidity")

    vuln_ids = [v["rule_id"] for v in data["vulnerabilities"]]
    vuln_cats = [v["category"] for v in data["vulnerabilities"]]

    print(f"\n  Detected {data['vulnerabilities_found']} vulnerabilities:")
    for v in data["vulnerabilities"]:
        print(f"    [{v['severity'].upper():8s}] {v['rule_id']} {v['name']}")

    # ── Core governance checks that MUST fire ────────────────────────────
    print("\n[2] Verifying eBTC attack chain detection...")
    check("SC-100: Single-EOA Admin detected",     "SC-100" in vuln_ids)
    check("SC-101: No Timelock on Roles detected",  "SC-101" in vuln_ids)
    check("SC-102: Uncapped Minting detected",      "SC-102" in vuln_ids)
    check("SC-103: Admin Can Mint detected",         "SC-103" in vuln_ids)
    check("SC-104: Instant Role Grant detected",     "SC-104" in vuln_ids)

    # ── Compliance mappings ──────────────────────────────────────────────
    print("\n[3] Verifying compliance mappings...")
    for v in data["vulnerabilities"]:
        if v["rule_id"] == "SC-100":
            cm = v.get("compliance_mappings", {})
            check("SC-100 has SOC-2 mapping", "SOC-2" in cm, str(cm.get("SOC-2")))
            check("SC-100 has ISO 27001 mapping", "ISO 27001" in cm, str(cm.get("ISO 27001")))
            break

    # ── Score should be very low ─────────────────────────────────────────
    print(f"\n[4] Score: {data['score']}/100  Grade: {data['grade']}")
    check("Score is below 50 (high-risk)", data["score"] < 50, str(data["score"]))
    check("Grade is D or F", data["grade"] in ("D", "F"), data["grade"])

    # ── Remediation advice is actionable ─────────────────────────────────
    print("\n[5] Checking remediation advice...")
    for v in data["vulnerabilities"]:
        if v["rule_id"] == "SC-100":
            check("SC-100 mentions multisig",  "multisig" in v["remediation"].lower())
            check("SC-100 mentions Gnosis Safe", "gnosis" in v["remediation"].lower())
        if v["rule_id"] == "SC-101":
            check("SC-101 mentions TimelockController", "timelock" in v["remediation"].lower())
            check("SC-101 mentions 24-48h delay", "24" in v["remediation"])
        if v["rule_id"] == "SC-102":
            check("SC-102 mentions MAX_SUPPLY", "MAX_SUPPLY" in v["remediation"])

    # ── Test 2: Hardened contract should score much better ───────────────
    print("\n[6] Analyzing hardened contract (what eBTC should have been)...")
    analyzer2 = SmartContractAnalyzer(
        source_code=HARDENED_CONTRACT,
        contract_name="HardenedBTC",
        chain="monad",
    )
    result2 = analyzer2.analyze()
    data2 = asdict(result2)

    vuln_ids2 = [v["rule_id"] for v in data2["vulnerabilities"]]
    print(f"  Score: {data2['score']}/100  Grade: {data2['grade']}")
    print(f"  Vulnerabilities: {data2['vulnerabilities_found']}")
    check("Hardened contract scores higher", data2["score"] > data["score"],
          f"{data2['score']} vs {data['score']}")
    check("SC-100 NOT triggered (no AccessControl/Ownable)", "SC-100" not in vuln_ids2)
    check("SC-101 NOT triggered (no grantRole)", "SC-101" not in vuln_ids2)
    check("SC-104 NOT triggered (no _setupRole)", "SC-104" not in vuln_ids2)

    # ── Total rule count ─────────────────────────────────────────────────
    print(f"\n[7] Total analyzer rules: {len(VULN_RULES)}")
    governance_rules = [r for r in VULN_RULES if r.id.startswith("SC-10")]
    check(f"Governance rules added: {len(governance_rules)}", len(governance_rules) >= 8)

    print("\n" + "=" * 60)
    print(f"  {'eBTC EXPLOIT DETECTION: ALL CHECKS PASSED' if PASS else 'SOME CHECKS FAILED'}")
    print("=" * 60)
    sys.exit(0 if PASS else 1)


if __name__ == "__main__":
    main()
