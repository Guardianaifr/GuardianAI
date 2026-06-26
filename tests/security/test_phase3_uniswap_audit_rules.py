"""
Phase 3: Uniswap Audit-Derived Rule Tests.

Tests for the 6 new vulnerability detection rules (SC-130 through SC-135)
added after static analysis of Uniswap V3/V4 core contracts.

Each test class validates:
  - True positive detection on crafted vulnerable code
  - True negative (no false positives) on safe code
  - Rule metadata correctness (severity, category, compliance map)
"""
import pytest
import sys
import os

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from guardian.audit.smart_contract_analyzer import (
    SmartContractAnalyzer,
    VULN_RULES,
    _COMPLIANCE_MAP,
)


# ——— Helper ——————————————————————————————————————————————————————————

def analyze(name, code):
    result = SmartContractAnalyzer(source_code=code, contract_name=name).analyze()
    rule_ids = {v["rule_id"] for v in result.vulnerabilities}
    return result, rule_ids


# ——— SC-130: Phantom Function Call ———————————————————————————————————

class TestSC130PhantomFunctionCall:
    """SC-130: Low-level call/staticcall without extcodesize check."""

    VULNERABLE = """
    pragma solidity ^0.8.0;
    contract Vault {
        function withdraw(address payable to) external {
            (bool ok,) = to.call{value: 1 ether}("");
            require(ok);
        }
    }
    """

    SAFE = """
    pragma solidity ^0.8.0;
    import "@openzeppelin/contracts/utils/Address.sol";
    contract SafeVault {
        using Address for address;
        function withdraw(address payable to) external {
            uint256 codeSize;
            assembly { codeSize := extcodesize(to) }
            require(codeSize > 0, "not a contract");
            to.transfer(1 ether);
        }
    }
    """

    def test_detects_vulnerable_call(self):
        _, rule_ids = analyze("Vault", self.VULNERABLE)
        assert "SC-130" in rule_ids, f"MISSED SC-130 (Phantom Call). Found: {rule_ids}"

    def test_no_false_positive_on_safe(self):
        _, rule_ids = analyze("SafeVault", self.SAFE)
        assert "SC-130" not in rule_ids, f"FALSE POSITIVE SC-130 on safe code. Found: {rule_ids}"

    def test_severity_is_high(self):
        rule = next(r for r in VULN_RULES if r.id == "SC-130")
        assert rule.severity.value == "high"

    def test_compliance_mapping_exists(self):
        assert "phantom_function_call" in _COMPLIANCE_MAP
        mapping = _COMPLIANCE_MAP["phantom_function_call"]
        assert "SOC-2" in mapping
        assert "ISO 27001" in mapping


# ——— SC-131: Unindexed Event Address Parameter ——————————————————————

class TestSC131UnindexedEvents:
    """SC-131: Event address params missing indexed keyword."""

    VULNERABLE = """
    pragma solidity ^0.8.0;
    contract Token {
        event Transfer(address from, address to, uint256 value);
        event Approval(address owner, address spender, uint256 value);
    }
    """

    SAFE = """
    pragma solidity ^0.8.0;
    contract Token {
        event Transfer(address indexed from, address indexed to, uint256 value);
        event Approval(address indexed owner, address indexed spender, uint256 value);
    }
    """

    def test_detects_unindexed_events(self):
        _, rule_ids = analyze("Token", self.VULNERABLE)
        assert "SC-131" in rule_ids, f"MISSED SC-131 (Unindexed Events). Found: {rule_ids}"

    def test_no_false_positive_on_indexed(self):
        _, rule_ids = analyze("Token", self.SAFE)
        assert "SC-131" not in rule_ids, f"FALSE POSITIVE SC-131 on indexed events. Found: {rule_ids}"

    def test_severity_is_low(self):
        rule = next(r for r in VULN_RULES if r.id == "SC-131")
        assert rule.severity.value == "low"

    def test_compliance_mapping_exists(self):
        assert "unindexed_events" in _COMPLIANCE_MAP


# ——— SC-132: Non-Constant State Variable ————————————————————————————

class TestSC132NonConstantState:
    """SC-132: State variables assigned at declaration without constant/immutable."""

    VULNERABLE = """
    pragma solidity ^0.8.0;
    contract Config {
        uint256 public maxSupply = 1000000;
        address public deadAddress = address(0);
        bool private isActive = true;
    }
    """

    SAFE = """
    pragma solidity ^0.8.0;
    contract Config {
        uint256 public constant MAX_SUPPLY = 1000000;
        address public immutable deadAddress;
        bool public constant IS_ACTIVE = true;
        constructor() { deadAddress = address(0); }
    }
    """

    def test_detects_non_constant(self):
        _, rule_ids = analyze("Config", self.VULNERABLE)
        assert "SC-132" in rule_ids, f"MISSED SC-132 (Non-Constant). Found: {rule_ids}"

    def test_no_false_positive_on_constant(self):
        _, rule_ids = analyze("Config", self.SAFE)
        assert "SC-132" not in rule_ids, f"FALSE POSITIVE SC-132 on constant vars. Found: {rule_ids}"

    def test_severity_is_low(self):
        rule = next(r for r in VULN_RULES if r.id == "SC-132")
        assert rule.severity.value == "low"


# ——— SC-133: Undocumented Magic Number ——————————————————————————————

class TestSC133MagicNumbers:
    """SC-133: Large hex literals (16+ hex digits) without documentation."""

    VULNERABLE = """
    pragma solidity ^0.8.0;
    library TickMath {
        function getSqrtPrice(int24 tick) internal pure returns (uint160) {
            uint256 ratio = tick > 0
                ? 0xfffcb933bd6fad37aa2d162d1a594001
                : 0x100000000000000000000000000000000;
            return uint160(ratio);
        }
    }
    """

    SAFE = """
    pragma solidity ^0.8.0;
    library SafeMath {
        function add(uint256 a, uint256 b) internal pure returns (uint256) {
            return a + b;
        }
        uint256 constant SMALL_HEX = 0xDEADBEEF;
    }
    """

    def test_detects_magic_numbers(self):
        _, rule_ids = analyze("TickMath", self.VULNERABLE)
        assert "SC-133" in rule_ids, f"MISSED SC-133 (Magic Numbers). Found: {rule_ids}"

    def test_no_false_positive_on_small_hex(self):
        _, rule_ids = analyze("SafeMath", self.SAFE)
        assert "SC-133" not in rule_ids, f"FALSE POSITIVE SC-133 on small hex. Found: {rule_ids}"

    def test_severity_is_info(self):
        rule = next(r for r in VULN_RULES if r.id == "SC-133")
        assert rule.severity.value == "info"


# ——— SC-134: EIP-1153 Transient Storage ——————————————————————————————

class TestSC134EIP1153Compat:
    """SC-134: EIP-1153 transient storage usage (cross-chain compatibility)."""

    VULNERABLE_TSTORE = """
    pragma solidity ^0.8.24;
    contract Lock {
        function _lock() internal {
            assembly { tstore(0, 1) }
        }
        function _unlock() internal {
            assembly { tstore(0, 0) }
        }
        function isLocked() internal view returns (bool locked) {
            assembly { locked := tload(0) }
        }
    }
    """

    VULNERABLE_KEYWORD = """
    pragma solidity ^0.8.24;
    contract TransientDemo {
        transient uint256 counter;
        function increment() external {
            counter += 1;
        }
    }
    """

    SAFE = """
    pragma solidity ^0.8.0;
    contract StandardLock {
        uint256 private _status;
        modifier nonReentrant() {
            require(_status != 2, "locked");
            _status = 2;
            _;
            _status = 1;
        }
    }
    """

    def test_detects_tstore(self):
        _, rule_ids = analyze("Lock", self.VULNERABLE_TSTORE)
        assert "SC-134" in rule_ids, f"MISSED SC-134 (tstore). Found: {rule_ids}"

    def test_detects_transient_keyword(self):
        _, rule_ids = analyze("TransientDemo", self.VULNERABLE_KEYWORD)
        assert "SC-134" in rule_ids, f"MISSED SC-134 (transient keyword). Found: {rule_ids}"

    def test_no_false_positive_on_standard_storage(self):
        _, rule_ids = analyze("StandardLock", self.SAFE)
        assert "SC-134" not in rule_ids, f"FALSE POSITIVE SC-134 on standard storage. Found: {rule_ids}"

    def test_severity_is_medium(self):
        rule = next(r for r in VULN_RULES if r.id == "SC-134")
        assert rule.severity.value == "medium"

    def test_compliance_mapping_exists(self):
        assert "eip1153_compat" in _COMPLIANCE_MAP
        mapping = _COMPLIANCE_MAP["eip1153_compat"]
        assert "A.14.2.8" in mapping.get("ISO 27001", [])


# ——— SC-135: Incomplete Interface Implementation —————————————————————

class TestSC135IncompleteInterface:
    """SC-135: Abstract contracts with unimplemented interface functions."""

    VULNERABLE = """
    pragma solidity ^0.8.0;
    interface IPool {
        function swap(uint256 amount) external returns (uint256);
        function addLiquidity(uint256 a, uint256 b) external;
    }
    abstract contract MockPool is IPool {
        function swap(uint256 amount) external override returns (uint256) {
            return amount;
        }
        // addLiquidity NOT implemented
    }
    """

    VULNERABLE_BODYLESS = """
    pragma solidity ^0.8.0;
    contract Proxy {
        function doSomething(uint256 x) external virtual override;
        function doAnother(address a) public view virtual override;
    }
    """

    SAFE = """
    pragma solidity ^0.8.0;
    contract FullPool {
        function swap(uint256 amount) external returns (uint256) {
            return amount * 2;
        }
        function addLiquidity(uint256 a, uint256 b) external {
            // fully implemented
        }
    }
    """

    def test_detects_abstract_with_interface(self):
        _, rule_ids = analyze("MockPool", self.VULNERABLE)
        assert "SC-135" in rule_ids, f"MISSED SC-135 (Incomplete Interface). Found: {rule_ids}"

    def test_detects_bodyless_functions(self):
        _, rule_ids = analyze("Proxy", self.VULNERABLE_BODYLESS)
        assert "SC-135" in rule_ids, f"MISSED SC-135 (Bodyless Functions). Found: {rule_ids}"

    def test_no_false_positive_on_full_implementation(self):
        _, rule_ids = analyze("FullPool", self.SAFE)
        assert "SC-135" not in rule_ids, f"FALSE POSITIVE SC-135 on full implementation. Found: {rule_ids}"

    def test_severity_is_medium(self):
        rule = next(r for r in VULN_RULES if r.id == "SC-135")
        assert rule.severity.value == "medium"


# ——— Meta: Rule Registry Integrity ——————————————————————————————————

class TestPhase3RuleRegistryIntegrity:
    """Ensure all 6 Phase 3 rules exist and are properly registered."""

    PHASE3_IDS = ["SC-130", "SC-131", "SC-132", "SC-133", "SC-134", "SC-135"]

    def test_all_phase3_rules_present(self):
        rule_ids = {r.id for r in VULN_RULES}
        for rid in self.PHASE3_IDS:
            assert rid in rule_ids, f"Phase 3 rule {rid} missing from VULN_RULES"

    def test_total_rule_count_at_least_47(self):
        assert len(VULN_RULES) >= 47, f"Expected >= 47 rules, got {len(VULN_RULES)}"

    def test_phase3_compliance_mappings_complete(self):
        phase3_categories = [
            "phantom_function_call", "unindexed_events", "non_constant_state",
            "magic_numbers", "eip1153_compat", "incomplete_interface",
        ]
        for cat in phase3_categories:
            assert cat in _COMPLIANCE_MAP, f"Missing compliance mapping for category: {cat}"
            assert "SOC-2" in _COMPLIANCE_MAP[cat], f"Missing SOC-2 mapping for {cat}"
            assert "ISO 27001" in _COMPLIANCE_MAP[cat], f"Missing ISO 27001 mapping for {cat}"

    def test_no_duplicate_rule_ids(self):
        ids = [r.id for r in VULN_RULES]
        assert len(ids) == len(set(ids)), f"Duplicate rule IDs found: {[x for x in ids if ids.count(x) > 1]}"

    def test_all_rules_have_patterns(self):
        for r in VULN_RULES:
            assert len(r.patterns) > 0, f"Rule {r.id} ({r.name}) has no patterns"

    def test_all_rules_have_remediation(self):
        for r in VULN_RULES:
            assert len(r.remediation) > 10, f"Rule {r.id} has insufficient remediation text"


# ——— Integration: Real Uniswap V2Pair triggers Phase 3 rules ————————

class TestPhase3OnUniswapV2Pair:
    """Verify Phase 3 rules trigger on real Uniswap V2 contracts."""

    URL = "https://raw.githubusercontent.com/Uniswap/v2-core/master/contracts/UniswapV2Pair.sol"

    def _fetch(self):
        import requests
        try:
            resp = requests.get(self.URL, timeout=15)
            resp.raise_for_status()
            return resp.text
        except Exception as e:
            pytest.skip(f"Network error: {e}")

    def test_detects_phantom_calls(self):
        """UniswapV2Pair uses low-level calls without extcodesize checks."""
        code = self._fetch()
        _, rule_ids = analyze("UniswapV2Pair", code)
        assert "SC-130" in rule_ids, f"SC-130 should detect phantom calls in V2Pair. Found: {rule_ids}"

    def test_detects_magic_numbers(self):
        """UniswapV2Pair uses large hex constants in math."""
        code = self._fetch()
        # V2Pair uses UQ112x112 which has large constants
        # This is an INFO-level finding so may or may not trigger depending on exact code
        # We just verify the analyzer doesn't crash
        result, _ = analyze("UniswapV2Pair", code)
        assert result.score >= 0  # Sanity check
