import os
import re
import pytest
from guardian.audit.smart_contract_analyzer import SmartContractAnalyzer


UNTESTED_24_RULES = [
    "SC-021",
    "SC-032",
    "SC-040",
    "SC-070",
    "SC-115",
    "SC-117",
    "SC-118",
    "SC-120",
    "SC-121",
    "SC-123",
    "SC-124",
    "SC-080",
    "SC-081",
    "VY-001",
    "VY-002",
    "VY-003",
    "VY-004",
    "VY-005",
    "SC-130",
    "SC-131",
    "SC-132",
    "SC-133",
    "SC-134",
    "SC-135"
]

FIXTURES_DIR = os.path.abspath(
    os.path.join(
        os.path.dirname(__file__),
        "../../guardian/audit/test_fixtures/smart_contracts",
    )
)


def build_wrapper(snippet: str) -> str:
    if "contract " in snippet or "interface " in snippet:
        return snippet

    pragma = "pragma solidity ^0.8.20;"
    pragma_match = re.search(r"pragma solidity[^;]+;", snippet)
    if pragma_match:
        pragma = pragma_match.group(0)
        snippet = snippet.replace(pragma, "")

    wrapper = f"""{pragma}
contract Token {{
    mapping(address => uint) public balances;
    address public owner;
    bool public paused;
    uint public totalSupply;
    uint public maxSupply = 10000;
    address public implementation;
    uint public lastUpdate;
    address public priceOracle;
    uint public price;
    address public TRUSTED_TARGET = address(this);
    address[] public users;
    bool private _initialized;
    uint public version;
    // SC-101 stubs
    uint256 public totalMinted;
    // SC-102 stubs
    uint256 public constant LIMIT = 10000;
    // SC-111 stubs
    mapping(address => uint256) public seq;
    // SC-122 stubs
    address public oracle1;
    address public oracle2;
    address public oracle3;
    // SC-114 stubs (addLiquidity/provideLiquidity argument variables)
    uint public a;
    uint public b;
    uint public c;

    modifier onlyOwner() {{ require(msg.sender == owner); _; }}
    modifier onlyRole(bytes32) {{ require(true); _; }}
    modifier auth() {{ require(true); _; }}
    modifier nonReentrant() {{ _; }}
    modifier requiresAuth() {{ _; }}
    // SC-119 guard modifiers
    modifier isInitializer() {{ require(!_initialized, "already initialized"); _initialized = true; _; }}
    modifier initializer() {{ require(!_initialized, "already initialized"); _initialized = true; _; }}
    modifier onlyDeploy() {{ _; }}
    modifier onlyTimelock() {{ require(msg.sender == owner); _; }}
    // SC-101 modifier
    modifier onlyGovDAO() {{ require(true); _; }}

    function _mint(address to, uint amount) internal {{
        balances[to] += amount;
        totalSupply += amount;
        totalMinted += amount;
    }}
    function ecrecover(bytes32, uint8, bytes32, bytes32) internal pure returns (address) {{ return address(0); }}
    // SC-101 stubs
    function _grantRole(bytes32, address) internal {{}}
    // SC-111 stubs — ECDSA library stub
    function ECDSA_recover(bytes32, uint8, bytes32, bytes32) internal pure returns (address) {{ return address(0); }}
    // SC-114 stub
    function checkSlippage() internal view returns (bool) {{ return true; }}
    // SC-116 stub
    function _castVote() internal {{}}
    function requestFlash() internal {{}}
    function submitChoice() internal {{}}
    function provideLiquidity(uint, uint, uint) internal {{}}
    function addLiquidity(uint, uint, uint) internal {{}}
    // SC-122 stubs
    function median(address, address, address) internal view returns (uint) {{ return price; }}

    function execute() public {{}}
    function flashloan() public {{}}

    // win() writes state so Slither's dataflow analysis recognises it as security-critical.
    function win() public {{ balances[msg.sender] += 1000; }}

    // Stub for flash-loan / oracle test fixtures
    function getReserves() external view nonReentrant returns (uint, uint, uint) {{ return (0, 0, 0); }}
    function spotPrice() external view nonReentrant returns (uint) {{ return price; }}

    // SNIPPET START
    {snippet}
    // SNIPPET END
}}
"""
    return wrapper


def get_fixture_files():
    if not os.path.exists(FIXTURES_DIR):
        return []
    return sorted([f for f in os.listdir(FIXTURES_DIR) if f.endswith(".sol") and not any(f.startswith(r) for r in UNTESTED_24_RULES)])


@pytest.mark.parametrize("filename", get_fixture_files())
def test_smart_contract_analyzer_fixture(filename):
    match = re.search(r"(SC-\d{3})", filename)
    assert match, f"Filename {filename} does not contain rule ID (SC-XXX)"
    rule_id = match.group(1)

    filepath = os.path.join(FIXTURES_DIR, filename)
    with open(filepath, "r", encoding="utf-8") as f:
        snippet = f.read()

    full_contract = build_wrapper(snippet)
    analyzer = SmartContractAnalyzer(
        source_code=full_contract,
        contract_name="TestWrapper",
        chain="ethereum",
    )
    result = analyzer.analyze()

    found = any(v["rule_id"] == rule_id for v in result.vulnerabilities)
    is_vuln_or_evasion = "vuln" in filename or "evasion" in filename
    is_safe = "safe" in filename

    if is_vuln_or_evasion:
        assert found, (
            f"[{rule_id}] Expected vulnerability in {filename}, but none was"
            " detected"
        )
    elif is_safe:
        assert not found, (
            f"[{rule_id}] Unexpected false positive in safe fixture {filename}"
        )
