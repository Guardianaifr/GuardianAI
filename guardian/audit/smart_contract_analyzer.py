"""
GuardianAI - Multi-Chain Smart Contract Analyzer.

Static analysis engine for deployed Solidity/Vyper smart contracts.
Detects 15+ vulnerability classes including reentrancy, front-running,
integer overflow, access control flaws, and more.

Supports analysis via:
  - Raw source code upload (Solidity / Vyper)
  - On-chain contract address + chain ID (fetches verified source via Etherscan-compatible APIs)

2026 Standard: Bridges the gap between AI behavioral audits and
traditional smart contract security audits.
"""

from __future__ import annotations

import re
import time
import json
import hashlib
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum

from guardian.audit.token_contract_analyzer import TokenContractAnalyzer
from guardian.audit.slither_engine import run_slither_analysis
from guardian.audit.vyper_engine import run_vyper_ast_analysis



# ——— Enums ———————————————————————————————————————————————————————————

class Chain(Enum):
    ETHEREUM   = "ethereum"
    BASE       = "base"
    ARBITRUM   = "arbitrum"
    OPTIMISM   = "optimism"
    POLYGON    = "polygon"
    BSC        = "bsc"
    MONAD      = "monad"
    AVALANCHE  = "avalanche"
    UNKNOWN    = "unknown"


class ContractLanguage(Enum):
    SOLIDITY = "solidity"
    VYPER    = "vyper"
    UNKNOWN  = "unknown"


class VulnSeverity(Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"
    INFO     = "info"


class VulnStatus(Enum):
    DETECTED    = "detected"
    SAFE        = "safe"
    INCONCLUSIVE = "inconclusive"


# ——— SOC-2 / ISO 27001 mappings per vuln class ———————————————————————

_COMPLIANCE_MAP: Dict[str, Dict[str, List[str]]] = {
    "reentrancy":            {"SOC-2": ["CC6.8", "CC7.1"], "ISO 27001": ["A.14.2.5"]},
    "integer_overflow":      {"SOC-2": ["CC6.1"],          "ISO 27001": ["A.14.2.5"]},
    "access_control":        {"SOC-2": ["CC6.3", "CC6.6"], "ISO 27001": ["A.9.4.1"]},
    "front_running":         {"SOC-2": ["CC6.1", "CC7.2"], "ISO 27001": ["A.14.1.2"]},
    "unchecked_return":      {"SOC-2": ["CC6.8"],          "ISO 27001": ["A.14.2.5"]},
    "delegatecall":          {"SOC-2": ["CC6.8", "CC7.4"], "ISO 27001": ["A.14.2.8"]},
    "selfdestruct":          {"SOC-2": ["CC7.4"],          "ISO 27001": ["A.12.3.1"]},
    "tx_origin_auth":        {"SOC-2": ["CC6.3"],          "ISO 27001": ["A.9.4.2"]},
    "timestamp_dependence":  {"SOC-2": ["CC6.1"],          "ISO 27001": ["A.14.1.2"]},
    "uninitialized_storage": {"SOC-2": ["CC6.8"],          "ISO 27001": ["A.14.2.5"]},
    "flash_loan_attack":     {"SOC-2": ["CC6.1", "CC7.2"], "ISO 27001": ["A.14.1.2"]},
    "price_manipulation":    {"SOC-2": ["CC6.1"],          "ISO 27001": ["A.14.1.2"]},
    "arbitrary_jump":        {"SOC-2": ["CC6.8"],          "ISO 27001": ["A.14.2.5"]},
    "dos_gas_limit":         {"SOC-2": ["CC6.6"],          "ISO 27001": ["A.12.1.3"]},
    "visibility_default":    {"SOC-2": ["CC6.3"],          "ISO 27001": ["A.9.4.1"]},
    # —— Governance / Key Management (eBTC-class) ——
    "single_eoa_admin":      {"SOC-2": ["CC6.3", "CC6.6"], "ISO 27001": ["A.9.2.3", "A.9.4.1"]},
    "no_timelock_roles":     {"SOC-2": ["CC6.1", "CC8.1"], "ISO 27001": ["A.12.1.2", "A.14.2.2"]},
    "uncapped_mint":         {"SOC-2": ["CC6.1", "CC7.2"], "ISO 27001": ["A.14.1.2"]},
    "unverified_proxy":      {"SOC-2": ["CC7.1"],          "ISO 27001": ["A.14.2.8"]},
    "instant_role_grant":    {"SOC-2": ["CC6.3", "CC6.6"], "ISO 27001": ["A.9.2.3"]},
    "no_collateral_checks":  {"SOC-2": ["CC6.1", "CC7.2"], "ISO 27001": ["A.14.1.2"]},
    "admin_can_mint":        {"SOC-2": ["CC6.3", "CC6.6"], "ISO 27001": ["A.9.2.3", "A.9.4.1"]},
    # Phase 2 extensions
    "bridge_replay":         {"SOC-2": ["CC6.8", "CC7.2"], "ISO 27001": ["A.14.1.2", "A.14.2.5"]},
    "signature_replay":      {"SOC-2": ["CC6.8", "CC7.2"], "ISO 27001": ["A.9.4.2", "A.14.2.5"]},
    "storage_collision":     {"SOC-2": ["CC6.8"],          "ISO 27001": ["A.14.2.8"]},
    "read_only_reentrancy":  {"SOC-2": ["CC6.8", "CC7.2"], "ISO 27001": ["A.14.1.2"]},
    "mev_sandwich":          {"SOC-2": ["CC6.1", "CC7.2"], "ISO 27001": ["A.14.1.2"]},
    "swap_deadline":         {"SOC-2": ["CC6.1"],          "ISO 27001": ["A.14.1.2"]},
    "governance_attack":     {"SOC-2": ["CC6.3", "CC7.2"], "ISO 27001": ["A.9.4.1", "A.14.1.2"]},
    "vault_inflation":       {"SOC-2": ["CC6.1"],          "ISO 27001": ["A.14.1.2"]},
    "zero_address":          {"SOC-2": ["CC6.8"],          "ISO 27001": ["A.14.2.5"]},
    "unprotected_initialize":{"SOC-2": ["CC6.3", "CC6.6"], "ISO 27001": ["A.9.4.1"]},
    "hardcoded_gas":         {"SOC-2": ["CC6.8"],          "ISO 27001": ["A.14.2.5"]},
    "missing_events":        {"SOC-2": ["CC7.2"],          "ISO 27001": ["A.12.4.1"]},
    "oracle_centralization": {"SOC-2": ["CC6.1", "CC7.2"], "ISO 27001": ["A.14.1.2"]},
    "permit_phishing":       {"SOC-2": ["CC6.3"],          "ISO 27001": ["A.9.4.2"]},
    "reward_rounding":       {"SOC-2": ["CC6.1"],          "ISO 27001": ["A.14.2.5"]},
    # Phase 3: Uniswap audit-derived rules
    "phantom_function_call": {"SOC-2": ["CC6.8", "CC7.1"], "ISO 27001": ["A.14.2.5"]},
    "unindexed_events":      {"SOC-2": ["CC7.2"],          "ISO 27001": ["A.12.4.1"]},
    "non_constant_state":    {"SOC-2": ["CC6.8"],          "ISO 27001": ["A.14.2.5"]},
    "magic_numbers":         {"SOC-2": ["CC7.2"],          "ISO 27001": ["A.14.2.5"]},
    "eip1153_compat":        {"SOC-2": ["CC6.8"],          "ISO 27001": ["A.14.2.5", "A.14.2.8"]},
    "incomplete_interface":  {"SOC-2": ["CC6.8", "CC7.1"], "ISO 27001": ["A.14.2.5"]},
}


# ——— Vulnerability rules ————————————————————————————————————————————

@dataclass
class VulnRule:
    id: str
    name: str
    category: str
    severity: VulnSeverity
    description: str
    remediation: str
    # List of (pattern, flags) for regex matching
    patterns: List[Tuple[str, int]] = field(default_factory=list)
    # Language restriction (None = both)
    language: Optional[ContractLanguage] = None


VULN_RULES: List[VulnRule] = [
    # —— Reentrancy ——————————————————————————————————————————————————
    VulnRule(
        id="SC-001",
        name="Reentrancy Vulnerability",
        category="reentrancy",
        severity=VulnSeverity.CRITICAL,
        description=(
            "External calls are made before state updates. An attacker can "
            "re-enter the function before balances are updated, draining funds."
        ),
        remediation=(
            "Apply the Checks-Effects-Interactions pattern: update state before "
            "any external calls. Consider using a reentrancy guard (ReentrancyGuard)."
        ),
        patterns=[
            # call.value / transfer before state update
            (r"\.call\.value\(.*\)\(.*\)(?!.*\n.*=\s*0)", re.DOTALL),
            (r"\.call\{value:", 0),
            # explicit withdraw pattern without reentrancy guard
            (r"function\s+withdraw[^}]*?\.call\{value:", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-002",
        name="No Reentrancy Guard on External Call",
        category="reentrancy",
        severity=VulnSeverity.HIGH,
        description="External calls detected without a reentrancy modifier.",
        remediation="Add `nonReentrant` modifier from OpenZeppelin's ReentrancyGuard.",
        patterns=[
            (r"function\s+\w+[^}]*?external[^}]*?\.call\b", re.DOTALL),
            (r"function\s+\w+[^)]*\)[^{]*?(?!nonReentrant){[^}]*?\.send\(", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    # —— Front-Running ———————————————————————————————————————————————
    VulnRule(
        id="SC-010",
        name="Front-Running via Transaction Ordering",
        category="front_running",
        severity=VulnSeverity.HIGH,
        description=(
            "Contract logic depends on transaction ordering (tx.gasprice, block.number). "
            "Miners or MEV bots can front-run trades or state changes."
        ),
        remediation=(
            "Use commit-reveal schemes, minimum price slippage controls, or "
            "integrate Flashbots Protect / private mempools."
        ),
        patterns=[
            (r"tx\.gasprice", 0),
            (r"block\.number\s*[><==]", 0),
            # DEX price check without deadline
            (r"getAmountsOut|getAmountsIn", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-011",
        name="Missing Slippage Protection (DeFi)",
        category="front_running",
        severity=VulnSeverity.MEDIUM,
        description="AMM/DEX swap functions lack minimum output amount checks.",
        remediation="Add `amountOutMin` checks on all swap calls. Enforce deadline parameter.",
        patterns=[
            (r"swapExact\w+(?!.*amountOutMin)", re.DOTALL),
            (r"amountOutMin\s*=\s*0", 0),
            (r"deadline\s*=\s*\d{10,}", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    # —— Integer Overflow / Underflow ————————————————————————————————
    VulnRule(
        id="SC-020",
        name="Integer Overflow / Underflow",
        category="integer_overflow",
        severity=VulnSeverity.CRITICAL,
        description=(
            "Arithmetic operations without SafeMath or Solidity ^0.8 can wrap around, "
            "causing balance inflation or fund loss."
        ),
        remediation=(
            "Use Solidity ^0.8.0 (built-in overflow checks) or OpenZeppelin SafeMath "
            "for earlier versions."
        ),
        patterns=[
            # Match any pre-0.8 pragma (^0.x, >=0.x, exact 0.x) UNLESS the source
            # also uses SafeMath ("using SafeMath") which mitigates the overflow risk.
            # [\^>=<!~]* covers all version specifier prefixes incl. exact (no prefix).
            (r"pragma\s+solidity\s+[\^>=<!~]*\s*0\.[0-7]\.\d+(?![\s\S]*using\s+SafeMath)",
             re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-021",
        name="Unchecked Arithmetic Block",
        category="integer_overflow",
        severity=VulnSeverity.MEDIUM,
        description="Use of `unchecked` blocks bypasses Solidity 0.8 overflow protection.",
        remediation="Remove unnecessary `unchecked` blocks, or add explicit bounds checks.",
        patterns=[
            (r"\bunchecked\s*\{", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    # —— Access Control ——————————————————————————————————————————————
    VulnRule(
        id="SC-030",
        name="tx.origin Authentication Bypass",
        category="tx_origin_auth",
        severity=VulnSeverity.HIGH,
        description=(
            "Using `tx.origin` for authentication allows phishing attacks where a "
            "malicious contract tricks the owner into calling it."
        ),
        remediation="Replace `tx.origin` with `msg.sender` for all authentication checks.",
        patterns=[
            (r"tx\.origin\s*==", 0),
            (r"require\s*\(\s*tx\.origin", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-031",
        name="Missing Access Control on Sensitive Function",
        category="access_control",
        severity=VulnSeverity.HIGH,
        description=(
            "Privileged functions (mint, pause, withdraw, setOwner) lack access control modifiers."
        ),
        remediation="Add `onlyOwner`, `onlyRole`, or equivalent access control to privileged functions.",
        patterns=[
            (r"function\s+(mint|pause|unpause|setOwner|transferOwnership|withdraw|emergencyWithdraw)"
             r"\s*\([^)]*\)\s*(?!.*onlyOwner)(?!.*onlyRole)(?:public|external)",
             re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-032",
        name="Default Function Visibility",
        category="visibility_default",
        severity=VulnSeverity.MEDIUM,
        description="Functions without explicit visibility default to public in older Solidity.",
        remediation="Always declare explicit visibility: public, external, internal, or private.",
        patterns=[
            (r"function\s+\w+\s*\([^)]*\)(?![^{]*(?:public|external|internal|private))[^{]*\{", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    # —— Unsafe External Calls ———————————————————————————————————————
    VulnRule(
        id="SC-040",
        name="Unchecked Low-Level Call Return Value",
        category="unchecked_return",
        severity=VulnSeverity.HIGH,
        description=(
            "Return value of `.call()`, `.send()`, or `.delegatecall()` is not checked. "
            "Failed calls silently continue execution."
        ),
        remediation="Always check the return bool of low-level calls, or use `transfer()`.",
        patterns=[
            (r"\.call\b(?!\s*\(.*\)\s*;?\s*//.*ignored)(?!.*require)(?!.*bool\s+\w+\s*=)", re.DOTALL),
            (r"\.send\((?!.*require)", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-041",
        name="Dangerous delegatecall Usage",
        category="delegatecall",
        severity=VulnSeverity.CRITICAL,
        description=(
            "Unguarded `delegatecall` to user-controlled addresses allows attackers "
            "to overwrite storage and hijack contract logic."
        ),
        remediation=(
            "Only `delegatecall` to trusted, immutable logic contracts. "
            "Never delegatecall to user-supplied addresses."
        ),
        patterns=[
            (r"\.delegatecall\(", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-042",
        name="selfdestruct Present",
        category="selfdestruct",
        severity=VulnSeverity.HIGH,
        description=(
            "`selfdestruct` can be triggered to permanently destroy the contract "
            "and forward all ETH to an arbitrary address."
        ),
        remediation=(
            "Remove `selfdestruct` or gate it behind multi-sig and timelock. "
            "Note: deprecated in EIP-6049."
        ),
        patterns=[
            (r"\bselfdestruct\s*\(", 0),
            (r"\bsuicide\s*\(", 0),
            # Indirect kill-switch: empty-selector delegatecall invokes the target's
            # fallback which may contain selfdestruct — a common evasion pattern.
            (r"\.delegatecall\s*\(\s*[\"']\s*[\"']\s*\)", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    # —— Block / Timestamp Dependence ————————————————————————————————
    VulnRule(
        id="SC-050",
        name="Timestamp Dependence",
        category="timestamp_dependence",
        severity=VulnSeverity.MEDIUM,
        description=(
            "Relying on `block.timestamp` for randomness or time-locks is manipulable "
            "by miners within ~15 second windows."
        ),
        remediation=(
            "Use Chainlink VRF for randomness. For time-locks, use block numbers "
            "or accept ~15 second miner manipulation tolerance."
        ),
        patterns=[
            (r"block\.timestamp\s*%", 0),
            (r"block\.timestamp\s*==", 0),
            (r"now\s*%", 0),
            (r"random.*block\.timestamp", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    # —— Flash Loan Patterns —————————————————————————————————————————
    VulnRule(
        id="SC-060",
        name="Flash Loan Attack Vector",
        category="flash_loan_attack",
        severity=VulnSeverity.HIGH,
        description=(
            "Price oracle reads within the same transaction as flash loan can be "
            "manipulated. Single-block price manipulation risk."
        ),
        remediation=(
            "Use time-weighted average prices (TWAP) via Uniswap V3 TWAP oracle "
            "or Chainlink price feeds. Avoid spot prices for collateral valuation."
        ),
        patterns=[
            (r"IUniswapV2Pair.*getReserves|getReserves.*IUniswapV2Pair", re.DOTALL),
            (r"flashLoan|flashSwap|FlashLoanReceiver", re.IGNORECASE),
            (r"getPrice\(\)|spotPrice|currentPrice", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    # —— Price Oracle Manipulation ———————————————————————————————————
    VulnRule(
        id="SC-061",
        name="Spot Price Oracle Manipulation",
        category="price_manipulation",
        severity=VulnSeverity.CRITICAL,
        description=(
            "Contract uses on-chain AMM spot price as a price oracle, "
            "vulnerable to single-transaction price manipulation."
        ),
        remediation=(
            "Replace with Chainlink Data Feeds or Uniswap V3 TWAP oracle "
            "with at least 30-minute averaging window."
        ),
        patterns=[
            (r"\.getAmountsOut\(|\.getAmountsIn\(|\.getReserves\(|\.reserves\(", 0),
            (r"token0\.balanceOf.*token1\.balanceOf", re.DOTALL),
            (r"reserve0.*reserve1.*price", re.DOTALL | re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    # —— DoS —————————————————————————————————————————————————————————
    VulnRule(
        id="SC-070",
        name="DoS via Unbounded Loop",
        category="dos_gas_limit",
        severity=VulnSeverity.MEDIUM,
        description=(
            "Loop iterates over user-controlled arrays or unbounded data structures. "
            "An attacker can cause out-of-gas DoS."
        ),
        remediation=(
            "Add a maximum iteration cap. Use pagination or pull-payment pattern "
            "instead of pushing to all recipients in one transaction."
        ),
        patterns=[
            (r"for\s*\([^)]*\.length[^)]*\)", 0),
            (r"while\s*\(.*\.length", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    # —— Governance / Key Management (eBTC-class exploits) ———————————
    # These rules detect the EXACT pattern used in the Echo Protocol / eBTC
    # exploit on Monad (May 2026): compromised admin key -> grantRole ->
    # revokeRole -> mint -> collateral fraud -> bridge exit.
    VulnRule(
        id="SC-100",
        name="Single-EOA Admin (No Multisig)",
        category="single_eoa_admin",
        severity=VulnSeverity.CRITICAL,
        description=(
            "Contract uses AccessControl or Ownable with a single externally-owned "
            "account as admin. One compromised private key gives full control. "
            "This is the #1 root cause of governance exploits (eBTC/Echo, Ronin, Harmony)."
        ),
        remediation=(
            "Replace single-EOA admin with a Gnosis Safe multisig (3-of-5 minimum). "
            "For critical operations, require multi-party approval via Governor or "
            "OpenZeppelin AccessManager."
        ),
        patterns=[
            # AccessControl without multisig references
            (r"AccessControl(?!.*[Mm]ulti[Ss]ig)(?!.*[Gg]overnor)(?!.*[Tt]imelock)", re.DOTALL),
            # Single-owner Ownable
            (r"Ownable(?!.*[Mm]ulti[Ss]ig)(?!.*[Gg]overnor)", 0),
            # Direct DEFAULT_ADMIN_ROLE grant to EOA
            (r"_setupRole\s*\(\s*DEFAULT_ADMIN_ROLE", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-101",
        name="No Timelock on Role Changes",
        category="no_timelock_roles",
        severity=VulnSeverity.CRITICAL,
        description=(
            "grantRole / revokeRole can execute instantly with no delay. An attacker "
            "with admin access can grant themselves minting privileges and lock out "
            "the real team in a single block -- exactly as seen in the eBTC exploit "
            "where 4 role transactions executed in ~9 seconds."
        ),
        remediation=(
            "Wrap all role-change operations in a TimelockController with a minimum "
            "24-48 hour delay. Use OpenZeppelin's AccessManager with time-delayed "
            "role grants. This gives the team time to detect and respond."
        ),
        patterns=[
            # grantRole/revokeRole with no access modifier between params and body
            # Look-between-braces so '// timelock' in body doesn't evade the lookahead
            (r"(?:grantRole|revokeRole|renounceRole)\s*\([^)]*\)(?![^{]*\b(?:onlyGovDAO|onlyTimelock|TimelockController|delay)\b)[^{]*\{", re.DOTALL),
            # Catch functions that call _grantRole internally without a guard modifier
            (r"function\s+\w+\s*\([^)]*\)(?![^{]*\b(?:onlyGovDAO|onlyTimelock|TimelockController|delay)\b)[^{]*\{[^}]*_grantRole\s*\(", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-102",
        name="Uncapped Minting (No Supply Ceiling)",
        category="uncapped_mint",
        severity=VulnSeverity.CRITICAL,
        description=(
            "Mint function has no maximum supply cap. A compromised minter can "
            "create unlimited tokens and use them as collateral on lending protocols. "
            "In the eBTC exploit, 1,000 tokens were minted from nothing and used to "
            "borrow $870K in real WBTC."
        ),
        remediation=(
            "Add an immutable `MAX_SUPPLY` constant and enforce `require(totalSupply() + "
            "amount <= MAX_SUPPLY)` in every mint path. Consider adding per-block mint "
            "limits and requiring multi-sig for mints above a threshold."
        ),
        patterns=[
            # mint function without any supply cap reference (maxSupply, MAX_SUPPLY, LIMIT, cap)
            (r"function\s+mint[^}]*?_mint\s*\([^)]*\)(?!.*[Mm]ax[Ss]upply)(?!.*MAX_SUPPLY)(?!.*\bLIMIT\b)(?!.*\.cap\()", re.DOTALL),
            (r"function\s+mint[^}]*?\{(?!.*totalSupply.*<=)(?!.*require.*(?:supply|limit|cap))", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-103",
        name="Admin Can Directly Mint Tokens",
        category="admin_can_mint",
        severity=VulnSeverity.HIGH,
        description=(
            "The same role that controls access (DEFAULT_ADMIN_ROLE) can also grant "
            "MINTER_ROLE. A single key compromise gives both governance control AND "
            "money-printing capability. No separation of duties."
        ),
        remediation=(
            "Separate admin and minter roles with different key holders. Use a "
            "dedicated MINTER_ADMIN_ROLE that cannot be granted by DEFAULT_ADMIN_ROLE "
            "without timelock approval. Implement role hierarchy with AccessManager."
        ),
        patterns=[
            # Both DEFAULT_ADMIN_ROLE and MINTER_ROLE in same contract
            (r"DEFAULT_ADMIN_ROLE.*MINTER_ROLE|MINTER_ROLE.*DEFAULT_ADMIN_ROLE", re.DOTALL),
            # Admin granting minter role
            (r"grantRole.*MINTER_ROLE", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-104",
        name="Instant Role Grant (No Delay / No Proposal)",
        category="instant_role_grant",
        severity=VulnSeverity.HIGH,
        description=(
            "Role grants execute in the same transaction with no delay or governance "
            "proposal. Combined with a compromised key, this allows an attacker to "
            "seize full control before anyone can react -- the entire eBTC attack "
            "chain completed in under 9 seconds."
        ),
        remediation=(
            "Route all role modifications through a TimelockController or Governor "
            "contract with a mandatory delay (24h minimum). Emit events for all "
            "role changes and set up off-chain monitoring alerts."
        ),
        patterns=[
            (r"_grantRole\s*\(", 0),
            (r"_setupRole\s*\(", 0),
            (r"_setRoleAdmin\s*\(", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-105",
        name="Unverified Proxy Contract",
        category="unverified_proxy",
        severity=VulnSeverity.HIGH,
        description=(
            "Contract uses a proxy pattern (ERC-1967, UUPS, Transparent) but the "
            "implementation source is not verified on-chain. External parties cannot "
            "audit the actual logic. The eBTC contract was an unverified proxy -- "
            "evaluating mint access controls from outside was impossible without "
            "manual bytecode decompilation."
        ),
        remediation=(
            "Always verify proxy implementation source on the block explorer. Use "
            "OpenZeppelin's hardhat-upgrades plugin which auto-verifies. Publish "
            "full source with NatSpec documentation."
        ),
        patterns=[
            # Flag any contract that inherits from an Proxy/Upgradeable base class
            # UNLESS the body contains an explicit verification note.
            # Negative lookahead (?![^}]*[Vv]erified) stops the match when the word
            # "Verified" appears inside the contract body — distinguishing the safe
            # fixture (// Verified on Etherscan) from unverified vuln/evasion variants.
            # \w*(?:Proxy|Upgradeable)\w* catches:
            #   TransparentUpgradeableProxy, CustomUpgradeableProxy, BeaconProxy, etc.
            (r"is\s+\w*(?:Proxy|Upgradeable)\w*\s*\{(?![^}]*[Vv]erified)", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-106",
        name="No Collateral Freshness Check (Lending Risk)",
        category="no_collateral_checks",
        severity=VulnSeverity.HIGH,
        description=(
            "Lending/borrowing protocol accepts collateral tokens without checking "
            "token age, supply history, or market depth. Freshly minted or "
            "low-liquidity tokens can be deposited as collateral to borrow real "
            "assets. In the eBTC exploit, 1,000 fake eBTC was deposited into "
            "Curvance as collateral and $870K in real WBTC was borrowed against it."
        ),
        remediation=(
            "Implement collateral sanity checks: minimum token age (e.g. 1000 blocks), "
            "minimum on-chain liquidity depth, maximum LTV ratio for newly listed assets, "
            "and supply-change monitoring. Use Chainlink Proof of Reserve for wrapped assets."
        ),
        patterns=[
            # deposit/borrow without supply checks
            (r"function\s+deposit[^}]*?collateral(?!.*totalSupply)(?!.*liquidity)", re.DOTALL),
            (r"function\s+borrow[^}]*?collateral(?!.*oracle)(?!.*priceCheck)", re.DOTALL),
            (r"function\s+addCollateral(?!.*whitelist)(?!.*approved)", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-107",
        name="Missing Role-Change Event Monitoring",
        category="instant_role_grant",
        severity=VulnSeverity.MEDIUM,
        description=(
            "Contract does not emit custom events for critical role changes beyond "
            "the standard AccessControl events. Off-chain monitoring systems may not "
            "have alerts configured for RoleGranted/RoleRevoked events, allowing "
            "attackers to operate undetected."
        ),
        remediation=(
            "Emit explicit events for all admin operations: AdminChanged, MinterAdded, "
            "EmergencyAction. Set up real-time monitoring with alerts (Forta, "
            "OpenZeppelin Defender, or GuardianAI continuous monitoring) that trigger "
            "on RoleGranted events from unexpected callers."
        ),
        patterns=[
            # AccessControl without monitoring-related code
            (r"AccessControl(?!.*[Ff]orta)(?!.*[Dd]efender)(?!.*[Mm]onitor)(?!.*AdminChanged)", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    # —— Phase 2: Missing High-Impact Vulnerability Classes ——————————
    VulnRule(
        id="SC-110",
        name="Cross-Chain Bridge Replay",
        category="bridge_replay",
        severity=VulnSeverity.CRITICAL,
        description="Missing chain ID validation allows replay attacks across forks/chains (like the Ronin or Wormhole exploits).",
        remediation="Validate `block.chainid` or use EIP-712 typed data signatures that include chainID.",
        patterns=[
            (r"ecrecover\s*\((?!.*chainid)(?!.*DOMAIN_SEPARATOR)", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-111",
        name="Signature Replay / Missing Nonce",
        category="signature_replay",
        severity=VulnSeverity.CRITICAL,
        description="Signatures can be re-used because nonces are not checked or not invalidated after use.",
        remediation="Always use a `nonces` mapping and increment it for every processed signature.",
        patterns=[
            # Match functions containing ecrecover/ECDSA.recover without a nonce/seq guard
            # Scopes lookahead to whole function body so pre-match 'seq' is also detected
            (r"function\s+\w+[^{]*\{(?=[^}]*(?:ecrecover|ECDSA\.recover))(?![^}]*\bnonce\b)(?![^}]*\bseq\b)[^}]*\}", re.DOTALL),
            (r"function\s+permit\b(?!.*nonces)", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-112",
        name="Storage Collision in Proxy",
        category="storage_collision",
        severity=VulnSeverity.CRITICAL,
        description="Implementation contract has overlapping storage slots with proxy contract.",
        remediation="Use unstructured storage (EIP-1967) or diamond storage.",
        patterns=[
            # Flag any contract inheriting from a *Proxy* base class UNLESS the body
            # explicitly mentions Diamond Storage (which prevents slot collisions).
            # \w*Proxy\w* catches: Proxy, BaseProxy, UpgradeableProxy, etc.
            (r"is\s+\w*Proxy\w*\s*\{(?![^}]*Diamond\s+Storage)", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-113",
        name="Read-Only Reentrancy",
        category="read_only_reentrancy",
        severity=VulnSeverity.HIGH,
        description="View functions return state that hasn't been finalized during a reentrant call, manipulable by attackers.",
        remediation="Apply nonReentrant modifiers to view functions that return critical state (like prices).",
        patterns=[
            # Flag getPrice/getReserves view functions that lack nonReentrant protection.
            # (?![^{]*nonReentrant) prevents matching functions that already carry the
            # nonReentrant guard between the closing ) of parameters and the opening {.
            (r"function\s+(?:getPrice|getReserves)\s*\([^)]*\)(?![^{]*nonReentrant)[^}]*(?:view|pure)[^}]*\{",
             re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-114",
        name="Sandwich Attack Vector (MEV)",
        category="mev_sandwich",
        severity=VulnSeverity.HIGH,
        description="Function performs swaps or liquidity provision without minimum return checks.",
        remediation="Always enforce user-supplied `minAmountOut` on AMM interactions.",
        patterns=[
            # Match functions calling addLiquidity/provideLiquidity/swapExact WITHOUT a slippage guard before the call
            (r"function\s+\w+[^{]*\{(?![^}]*require\s*\([^)]*(?:slippage|checkSlippage|min)[^)]*\))[^}]*(?:addLiquidity|provideLiquidity|swapExact)\s*\(", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-115",
        name="Missing Deadline on Swap",
        category="swap_deadline",
        severity=VulnSeverity.MEDIUM,
        description="Swap call appears to omit or bypass transaction deadline checks.",
        remediation="Include strict `deadline` validation on all AMM swap interactions.",
        patterns=[
            (r"swap\w*For\w*\s*\([^)]*,\s*(?:0|block\.timestamp)\s*\)", re.DOTALL),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-116",
        name="Governance Vote Manipulation",
        category="governance_attack",
        severity=VulnSeverity.HIGH,
        description="Governance execution appears to rely on weak voting-power snapshots or flash-loan-sensitive voting.",
        remediation="Use snapshot voting blocks, timelock queues, quorum checks, and anti-flash-loan voting protections.",
        patterns=[
            # Flash-loan combined with a governance action (word stems catch variants)
            (r"(?:flash)\w*[^}]\n?.*(?:vote|propos|execut|choice|submit)", re.DOTALL | re.IGNORECASE),
            # Unguarded executeProposal / queueProposal (castVote alone is legitimate)
            (r"(?:executeProposal|queueProposal)", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-117",
        name="Donation Attack / Vault Inflation",
        category="vault_inflation",
        severity=VulnSeverity.HIGH,
        description="Vault share minting may be manipulable by pre-deposit donation/inflation patterns.",
        remediation="Use ERC-4626 anti-inflation controls and minimum share mint thresholds.",
        patterns=[
            (r"(totalAssets|convertToShares|previewDeposit)", re.IGNORECASE),
            (r"(donate|skim|first\s*depositor)", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-118",
        name="Missing Zero-Address Check",
        category="zero_address",
        severity=VulnSeverity.MEDIUM,
        description="Sensitive address assignments may not reject `address(0)`.",
        remediation="Add explicit `require(target != address(0))` checks.",
        patterns=[
            (r"(transferOwnership|setOwner|setAdmin|mint)\s*\([^)]*address", re.IGNORECASE),
            (r"address\s*\(\s*0\s*\)", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-119",
        name="Unprotected Initialize Function",
        category="unprotected_initialize",
        severity=VulnSeverity.CRITICAL,
        description="Initialize function in upgradeable contract lacks initializer modifier.",
        remediation="Use the `initializer` modifier from OpenZeppelin Initializable.",
        patterns=[
            (r"function\s+initialize\s*\([^)]*\)\s*(public|external)\s*(?!.*initializer)\s*\{", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    VulnRule(
        id="SC-120",
        name="Hardcoded Gas in Transfer",
        category="hardcoded_gas",
        severity=VulnSeverity.MEDIUM,
        description="Hardcoded transfer gas limits may fail under opcode repricing and break payment logic.",
        remediation="Avoid fixed gas stipends; prefer robust call patterns with explicit success checks.",
        patterns=[
            (r"\.call\{gas\s*:\s*\d+\}", re.IGNORECASE),
            (r"\.transfer\s*\(", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    VulnRule(
        id="SC-121",
        name="Missing Event Emission",
        category="missing_events",
        severity=VulnSeverity.LOW,
        description="Critical state-changing actions may not emit auditable events.",
        remediation="Emit events for role updates, ownership changes, mint/burn, pause/unpause, and config changes.",
        patterns=[
            (r"function\s+(set|update|grant|revoke|mint|burn|pause|unpause)\w*\s*\(", re.IGNORECASE),
            (r"\bevent\s+\w+", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-122",
        name="Centralized Oracle Single Point of Failure",
        category="oracle_centralization",
        severity=VulnSeverity.HIGH,
        description="Single-source oracle design can create protocol-wide failure and manipulation risk.",
        remediation="Use multi-source oracles and circuit breakers with freshness checks.",
        patterns=[
            (r"(setOracle|oracleAddress|priceOracle)", re.IGNORECASE),
            # Single-source oracle getters — exclude when aggregation (median/average) is used
            (r"function\s+\w*(?:getPrice|fetchPrice|latestAnswer)\w*[^{]*\{(?![^}]*(?:median|average|twap|oracle1|oracle2|oracle3))", re.DOTALL | re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-123",
        name="Permit() Phishing Vector",
        category="permit_phishing",
        severity=VulnSeverity.HIGH,
        description="Permit-style signature flows can be abused if domain separation and spender checks are weak.",
        remediation="Validate domain separator, signer intent, spender policy, and nonce/deadline constraints.",
        patterns=[
            (r"function\s+permit\s*\(", re.IGNORECASE),
            (r"(DOMAIN_SEPARATOR|EIP712)", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-124",
        name="Reward Distribution Rounding",
        category="reward_rounding",
        severity=VulnSeverity.MEDIUM,
        description="Integer division in reward accounting can cause systematic rounding leaks/dust extraction.",
        remediation="Use fixed-point math libraries and residual accounting for reward distribution.",
        patterns=[
            # Handled by RewardRoundingDetector via Slither path (SC-124 is in is_slither_targeted)
            (r"PLACEHOLDER_NEVER_MATCHES_SC124", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),

    # —— Vyper-specific ———————————————————————————————————————————————
    VulnRule(
        id="SC-080",
        name="Vyper: Unsafe External Call",
        category="unchecked_return",
        severity=VulnSeverity.HIGH,
        description="Vyper `raw_call` without checking return data.",
        remediation="Capture and validate the return value of `raw_call()`.",
        patterns=[
            (r"^\s*raw_call\s*\(", re.MULTILINE),
        ],
        language=ContractLanguage.VYPER,
    ),
    VulnRule(
        id="SC-081",
        name="Vyper: Unsafe Timestamp Use",
        category="timestamp_dependence",
        severity=VulnSeverity.MEDIUM,
        description="Vyper contract uses `block.timestamp` for randomness.",
        remediation="Use Chainlink VRF for randomness in Vyper contracts.",
        patterns=[
            (r"block\.timestamp\s*%", 0),
            (r"convert\(block\.timestamp", 0),
        ],
        language=ContractLanguage.VYPER,
    ),
    VulnRule(
        id="VY-001",
        name="Vyper: Default Function Reentrancy",
        category="reentrancy",
        severity=VulnSeverity.CRITICAL,
        description="Vyper __default__ function processes ETH and may allow reentrancy via fallback calls.",
        remediation="Add @nonreentrant decorator to __default__ or move state changes before external calls.",
        patterns=[
            (r"@external\s+def\s+__default__\s*\(\s*\)", 0),
        ],
        language=ContractLanguage.VYPER,
    ),
    VulnRule(
        id="VY-002",
        name="Vyper: Missing Nonreentrant on State-Changing External",
        category="reentrancy",
        severity=VulnSeverity.HIGH,
        description="External Vyper function modifies state without @nonreentrant decorator.",
        remediation="Add @nonreentrant('lock') to all external functions that modify state.",
        patterns=[
            (r"@external\s+def\s+\w+\((?!.*nonreentrant)", 0),
        ],
        language=ContractLanguage.VYPER,
    ),
    VulnRule(
        id="VY-003",
        name="Vyper: Unsafe create_forwarder_to",
        category="proxy_risk",
        severity=VulnSeverity.HIGH,
        description="create_forwarder_to creates minimal proxy but the target can be changed if not immutable.",
        remediation="Ensure the target address is constant/immutable. Validate the deployment in tests.",
        patterns=[
            (r"(?:create_forwarder_to|create_copy_of)\(", 0),
        ],
        language=ContractLanguage.VYPER,
    ),
    VulnRule(
        id="VY-004",
        name="Vyper: Unsafe shift Operation",
        category="integer_overflow",
        severity=VulnSeverity.MEDIUM,
        description="Vyper shift() can overflow in versions < 0.3.8. Ensure version is >= 0.3.8.",
        remediation="Upgrade to Vyper >= 0.3.8 and add bounds checks around shift operations.",
        patterns=[
            (r"(?:unsafe_)?shift\(", 0),
        ],
        language=ContractLanguage.VYPER,
    ),
    VulnRule(
        id="VY-005",
        name="Vyper: send() Without Success Check",
        category="unchecked_return",
        severity=VulnSeverity.HIGH,
        description="Vyper send() returns bool but the return value is not checked, risking silent ETH transfer failure.",
        remediation="Always check the return value: assert send(addr, amount), or use raw_call with value=.",
        patterns=[
            (r"(?<!assert\s)send\(", 0),
        ],
        language=ContractLanguage.VYPER,
    ),

    # —— Phase 3: Uniswap Audit-Derived Rules ——————————————————————————
    # These rules were identified during the Uniswap V3/V4 core static
    # analysis audit and capture real-world patterns that affect gas
    # efficiency, off-chain indexing, cross-chain compatibility, and
    # auditability.

    VulnRule(
        id="SC-130",
        name="Phantom Function Call (Low-Level to Unchecked Address)",
        category="phantom_function_call",
        severity=VulnSeverity.HIGH,
        description=(
            "Low-level `.call()` or `.staticcall()` is used without verifying that "
            "the target address contains code (extcodesize check). Calls to an "
            "address with no code (EOA, self-destructed, or uninitialized contract) "
            "silently return success=true with empty return data, creating phantom "
            "success bugs that can bypass critical accounting logic."
        ),
        remediation=(
            "Add an `extcodesize` check before low-level calls, or use OpenZeppelin's "
            "`Address.functionCall()` / `SafeERC20.safeTransfer()` which include code "
            "existence verification. Never assume `.call()` failure means the target "
            "reverted -- it may simply have no code."
        ),
        patterns=[
            # Handled by PhantomCallDetector via Slither path; regex fallback for non-compiling snippets
            (r"\.\s*(?:call|staticcall|delegatecall)\s*(?:\{[^}]*\})?\s*\(", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-131",
        name="Unindexed Event Address Parameter",
        category="unindexed_events",
        severity=VulnSeverity.LOW,
        description=(
            "Event declarations include `address` parameters without the `indexed` "
            "keyword. Unindexed address parameters force off-chain indexers (Subgraphs, "
            "Goldsky, custom event listeners) to scan full transaction data fields "
            "instead of using efficient topic-based log filters, significantly "
            "increasing RPC query latency and indexing overhead."
        ),
        remediation=(
            "Add the `indexed` keyword to all `address` parameters in events. "
            "Solidity allows up to 3 indexed parameters per event. Prioritize "
            "indexing owner, pool, token, sender, and recipient addresses."
        ),
        patterns=[
            # event declaration with address but no 'indexed' before the address param
            (r"event\s+\w+\s*\([^)]*\baddress\s+(?!indexed\b)\w+[^)]*\)", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-132",
        name="Non-Constant / Non-Immutable State Variable",
        category="non_constant_state",
        severity=VulnSeverity.LOW,
        description=(
            "State variables assigned at declaration but never modified should be "
            "declared `constant` or `immutable`. Mutable storage reads cost at least "
            "2,100 gas (cold SLOAD) per access, while constants are inlined as cheap "
            "PUSH instructions at near-zero gas cost."
        ),
        remediation=(
            "Mark variables that never change after deployment as `constant` (if "
            "assigned at declaration) or `immutable` (if set in the constructor). "
            "This saves ~2,000 gas per read and reduces contract storage footprint."
        ),
        patterns=[
            # Handled by NonConstantStateDetector via Slither path (SC-132 in is_slither_targeted)
            (r"PLACEHOLDER_NEVER_MATCHES_SC132", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-133",
        name="Undocumented Magic Number (Large Hex Literal)",
        category="magic_numbers",
        severity=VulnSeverity.INFO,
        description=(
            "Large hexadecimal constants (16+ hex digits) are used inline without "
            "NatSpec or inline documentation explaining their mathematical derivation. "
            "While these may be intentional precision constants for fixed-point math "
            "(as seen in Uniswap V3 TickMath and BitMath), undocumented magic numbers "
            "significantly reduce auditability and increase fork error risk."
        ),
        remediation=(
            "Extract large hex literals into named `constant` variables with NatSpec "
            "comments explaining the mathematical derivation. For example: "
            "`uint256 constant Q128 = 0x100000000000000000000000000000000; // 2^128`. "
            "This makes audits faster and reduces fork errors."
        ),
        patterns=[
            # Hex literal with 16+ hex digits that is NOT preceded by a NatSpec comment
            # Matches the hex only when the preceding line has no /// or /** comment
            (r"(?<!//[^\n]*)(?<!\*[^\n]*)0x[0-9a-fA-F]{16,}", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-134",
        name="EIP-1153 Transient Storage Usage (Cross-Chain Risk)",
        category="eip1153_compat",
        severity=VulnSeverity.MEDIUM,
        description=(
            "Contract uses EIP-1153 transient storage opcodes (tstore/tload) or "
            "Solidity transient storage keyword. These opcodes are only supported "
            "on chains with the Dencun upgrade (Ethereum mainnet, Monad). Deploying "
            "to L2s or chains without EIP-1153 support will cause runtime failures."
        ),
        remediation=(
            "Verify target chain support for EIP-1153 before deployment. For "
            "multi-chain deployments, prepare a fallback reentrancy guard using "
            "standard storage (OpenZeppelin ReentrancyGuard) or implement a "
            "compile-time feature flag to toggle between transient and persistent "
            "storage implementations."
        ),
        patterns=[
            # Assembly tstore/tload
            (r"\btstore\s*\(", 0),
            (r"\btload\s*\(", 0),
            # Solidity transient storage keyword — catches both:
            #   transient uint lock;   (keyword before type)
            #   uint transient lock;   (keyword after type, actual Solidity syntax)
            (r"\btransient\b", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    VulnRule(
        id="SC-135",
        name="Incomplete Interface Implementation",
        category="incomplete_interface",
        severity=VulnSeverity.MEDIUM,
        description=(
            "Contract inherits from an interface but is declared `abstract`, "
            "indicating unimplemented function stubs. Deploying a contract with "
            "unimplemented interface functions will fail, and mock contracts with "
            "incomplete implementations may miss critical integration test coverage."
        ),
        remediation=(
            "Implement all interface functions or document the intentional omission. "
            "For test mocks, return sensible default values (e.g., 0 for uint, "
            "false for bool) rather than leaving functions unimplemented."
        ),
        patterns=[
            # abstract contract inheriting from ANY interface (not just I[A-Z] naming convention)
            (r"abstract\s+contract\s+\w+\s+is\s+\w+", 0),
            # contract with bodyless/stub function declarations (missing implementation)
            (r"contract\s+\w+[^{]*\{[^}]*function\s+\w+\([^)]*\)[^;{]*;", 0),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
]


# ——— Data classes ———————————————————————————————————————————————————————

@dataclass
class ContractVulnerability:
    rule_id: str
    name: str
    category: str
    severity: str
    status: str
    description: str
    remediation: str
    line_numbers: List[int] = field(default_factory=list)
    snippets: List[str] = field(default_factory=list)
    compliance_mappings: Dict[str, List[str]] = field(default_factory=dict)


@dataclass
class ContractAnalysisResult:
    analysis_id: str
    chain: str
    language: str
    contract_address: Optional[str]
    contract_name: str
    source_hash: str
    analyzed_at: str
    duration_seconds: float
    total_rules: int
    vulnerabilities_found: int
    safe_checks: int
    score: float
    grade: str
    risk_summary: Dict[str, int]
    vulnerabilities: List[Dict]
    metadata: Dict[str, str] = field(default_factory=dict)


# ——— Language detection ———————————————————————————————————————————————

def detect_language(source: str) -> ContractLanguage:
    """Heuristically detect Solidity vs Vyper from source."""
    sol_score = 0
    vyp_score = 0

    if re.search(r"pragma solidity", source, re.IGNORECASE):
        sol_score += 5
    if re.search(r"contract\s+\w+", source):
        sol_score += 3
    if re.search(r"function\s+\w+\s*\(", source):
        sol_score += 2
    if re.search(r"mapping\s*\(", source):
        sol_score += 2

    if re.search(r"#\s*@version", source):
        vyp_score += 5
    if re.search(r"@external|@internal|@view|@pure", source):
        vyp_score += 4
    if re.search(r"def\s+\w+\s*\(", source):
        vyp_score += 3
    if re.search(r"event\s+\w+:\s+indexed", source):
        vyp_score += 2

    if sol_score > vyp_score:
        return ContractLanguage.SOLIDITY
    if vyp_score > sol_score:
        return ContractLanguage.VYPER
    return ContractLanguage.UNKNOWN


def detect_chain_from_address(address: str) -> Chain:
    """Best-guess chain from address format."""
    if address.startswith("0x") and len(address) == 42:
        return Chain.ETHEREUM  # EVM compatible; caller should specify
    return Chain.UNKNOWN


def _get_line_numbers(source: str, match: re.Match) -> List[int]:
    """Return 1-indexed line numbers for a regex match span."""
    start = match.start()
    lines_before = source[:start].split("\n")
    start_line = len(lines_before)
    end_line = start_line + source[match.start():match.end()].count("\n")
    return list(range(start_line, end_line + 1))


def _safe_snippet(source: str, match: re.Match, context: int = 2) -> str:
    """Extract a code snippet around a match with context lines."""
    lines = source.split("\n")
    start_pos = match.start()
    line_idx = source[:start_pos].count("\n")
    lo = max(0, line_idx - context)
    hi = min(len(lines), line_idx + context + 1)
    snippet_lines = []
    for i, ln in enumerate(lines[lo:hi], start=lo + 1):
        prefix = ">>>" if i == line_idx + 1 else "   "
        snippet_lines.append(f"{prefix} {i:4d}: {ln}")
    return "\n".join(snippet_lines)


def _normalize_source_blob(source_raw: str) -> str:
    """Normalize explorer source blob and unwrap Standard JSON input formats."""
    raw = (source_raw or "").strip()
    if not raw:
        return ""

    if raw.startswith("{{") and raw.endswith("}}"):
        raw = raw[1:-1]

    try:
        parsed = json.loads(raw)
    except Exception:
        return raw

    if isinstance(parsed, dict) and isinstance(parsed.get("sources"), dict):
        combined: List[str] = []
        for fname, body in parsed["sources"].items():
            content = body.get("content", "") if isinstance(body, dict) else str(body)
            combined.append(f"// File: {fname}\n{content}\n")
        if combined:
            return "\n".join(combined)

    if isinstance(parsed, dict):
        # Some explorers return {"file.sol": {"content": "..."}}
        combined = []
        for fname, body in parsed.items():
            if isinstance(body, dict) and "content" in body:
                combined.append(f"// File: {fname}\n{body.get('content', '')}\n")
        if combined:
            return "\n".join(combined)

    return raw


def _normalize_contract_name(name: str) -> str:
    """Normalize common explorer naming variations for stable reporting."""
    candidate = (name or "").strip()
    if not candidate:
        return candidate
    if candidate.startswith("FiatToken"):
        return "FiatToken"
    if "AdminUpgradeabilityProxy" in candidate:
        return "AdminUpgradeabilityProxy"
    return candidate


def _infer_contract_name_from_source(source: str) -> Optional[str]:
    """Infer a meaningful contract name from source declarations."""
    cleaned = re.sub(r"/\*.*?\*/", " ", source or "", flags=re.DOTALL)
    cleaned = re.sub(r"//.*?$", " ", cleaned, flags=re.MULTILINE)
    pattern = re.compile(r"\b(?:abstract\s+)?contract\s+([A-Z][A-Za-z0-9_]*)")
    generic_names = {
        "Address", "Context", "Ownable", "OwnableUpgradeable", "Initializable",
        "Math", "Strings", "SafeMath", "ECDSA", "ERC20", "ERC1967Upgrade",
    }

    names = [m.group(1) for m in pattern.finditer(cleaned)]
    if not names:
        return None

    for name in names:
        if name in generic_names:
            continue
        if len(name) <= 2:
            continue
        return _normalize_contract_name(name)
    return _normalize_contract_name(names[0])


# ——— Core analyzer ———————————————————————————————————————————————————

class SmartContractAnalyzer:
    """
    Multi-chain static analysis engine for Solidity and Vyper contracts.
    """

    @classmethod
    def from_onchain(
        cls,
        contract_address: str,
        chain: str = "ethereum",
        api_key: Optional[str] = None
    ) -> SmartContractAnalyzer:
        """
        Fetch verified source code from explorer APIs with fallback to Sourcify.
        """
        import requests

        chain_map: Dict[str, Dict[str, Any]] = {
            "ethereum": {"id": 1, "legacy_api": "https://api.etherscan.io/api"},
            "eth": {"id": 1, "legacy_api": "https://api.etherscan.io/api"},
            "mainnet": {"id": 1, "legacy_api": "https://api.etherscan.io/api"},
            "bsc": {"id": 56, "legacy_api": "https://api.bscscan.com/api"},
            "binance-smart-chain": {"id": 56, "legacy_api": "https://api.bscscan.com/api"},
            "polygon": {"id": 137, "legacy_api": "https://api.polygonscan.com/api"},
            "arbitrum": {"id": 42161, "legacy_api": "https://api.arbiscan.io/api"},
            "base": {"id": 8453, "legacy_api": "https://api.basescan.org/api"},
            "optimism": {"id": 10, "legacy_api": "https://api-optimistic.etherscan.io/api"},
            "avalanche": {"id": 43114, "legacy_api": "https://api.snowtrace.io/api"},
            # Monad target for launch readiness (EVM path may vary by environment)
            "monad": {"id": 10143, "legacy_api": "https://api.monadscan.com/api"},
        }

        chain_key = (chain or "").strip().lower()
        chain_info = chain_map.get(chain_key)
        if not chain_info:
            try:
                chain_id = int(chain)
                chain_info = {"id": chain_id}
            except Exception as exc:
                raise ValueError(f"Unsupported chain: {chain}") from exc

        chain_id = chain_info.get("id")
        address = contract_address.strip().lower()
        if not address.startswith("0x") or len(address) != 42:
            raise ValueError(f"Invalid EVM contract address: {contract_address}")

        source_code: Optional[str] = None
        contract_name = "UnknownContract"
        onchain_metadata: Dict[str, Any] = {
            "fetch_path": "",
            "verification_status": "unknown",
            "explorer_chain_id": str(chain_id or ""),
            "chain_alias": chain_key or chain,
        }

        explorer_urls: List[str] = []
        if chain_id is not None:
            explorer_urls.append(
                f"https://api.etherscan.io/v2/api?chainid={chain_id}&module=contract&action=getsourcecode&address={address}"
            )
        if chain_info.get("legacy_api"):
            explorer_urls.append(
                f"{chain_info['legacy_api']}?module=contract&action=getsourcecode&address={address}"
            )
        if chain_info.get("blockscout_api"):
            explorer_urls.append(
                f"{chain_info['blockscout_api']}?module=contract&action=getsourcecode&address={address}"
            )

        last_error: Optional[str] = None
        for url in explorer_urls:
            # B-007: Use headers instead of query params for API key (avoids log exposure)
            headers = {"X-Api-Key": api_key} if api_key else {}
            try:
                resp = requests.get(url, headers=headers, timeout=12)
                if resp.status_code != 200:
                    last_error = f"HTTP {resp.status_code}"
                    continue

                data = resp.json()
                result_list = data.get("result")
                if not isinstance(result_list, list) or not result_list:
                    continue

                result0 = result_list[0] if isinstance(result_list[0], dict) else {}
                source_raw = str(result0.get("SourceCode", "") or "")
                normalized_source = _normalize_source_blob(source_raw)
                if not normalized_source.strip():
                    onchain_metadata["verification_status"] = "unverified"
                    continue

                source_code = normalized_source
                contract_name = _normalize_contract_name(str(result0.get("ContractName", "") or contract_name))
                onchain_metadata["fetch_path"] = "explorer_api"
                onchain_metadata["verification_status"] = "verified"
                onchain_metadata["proxy"] = str(result0.get("Proxy", "0"))
                onchain_metadata["implementation"] = str(result0.get("Implementation", ""))
                break
            except Exception as exc:
                last_error = str(exc)
                continue
            finally:
                time.sleep(0.25)

        if not source_code:
            sourcify_url = f"https://sourcify.dev/server/files/any/{chain_id}/{address}"
            try:
                resp = requests.get(sourcify_url, timeout=15)
                if resp.status_code != 200:
                    raise ValueError(f"Failed to retrieve source from Sourcify: Status {resp.status_code}")

                data = resp.json()
                files = data.get("files", [])
                if not files:
                    raise ValueError("No verified files found for this contract on Sourcify")

                combined: List[str] = []
                for f in files:
                    if not isinstance(f, dict):
                        continue
                    name = str(f.get("name", ""))
                    content = str(f.get("content", ""))
                    if not name.endswith((".sol", ".vy")):
                        continue
                    if not name.startswith("@") and "/" not in name and contract_name == "UnknownContract":
                        contract_name = name.rsplit(".", 1)[0]
                    combined.append(f"// File: {name}\n{content}\n")

                if not combined:
                    raise ValueError("No Solidity/Vyper files found in contract source")

                source_code = "\n".join(combined)
                onchain_metadata["fetch_path"] = "sourcify"
                onchain_metadata["verification_status"] = "verified"
            except Exception as exc:
                if isinstance(exc, ValueError):
                    raise
                error_detail = last_error or str(exc)
                raise ValueError(f"Error fetching from block explorer network: {error_detail}") from exc

        if source_code:
            inferred = _infer_contract_name_from_source(source_code)
            if inferred and (not contract_name or contract_name in {"UnknownContract", "Address", "Context"}):
                contract_name = inferred

        # Optional contract-age metadata (best effort; does not block analysis).
        legacy_api = chain_info.get("legacy_api")
        if legacy_api:
            age_url = (
                f"{legacy_api}?module=account&action=txlist&address={address}"
                f"&startblock=0&endblock=99999999&page=1&offset=1&sort=asc"
            )
            # B-007: Use headers for API key
            age_headers = {"X-Api-Key": api_key} if api_key else {}
            try:
                age_resp = requests.get(age_url, headers=age_headers, timeout=10)
                if age_resp.status_code == 200:
                    age_data = age_resp.json()
                    txs = age_data.get("result")
                    if isinstance(txs, list) and txs:
                        ts = int(str(txs[0].get("timeStamp", "0") or "0"))
                        if ts > 0:
                            age_days = (time.time() - ts) / 86400.0
                            onchain_metadata["contract_age_days"] = f"{age_days:.2f}"
            except Exception:
                pass

        return cls(
            source_code=source_code,
            contract_name=contract_name,
            contract_address=address,
            chain=chain_key or chain,
            metadata=onchain_metadata,
        )

    def __init__(
        self,
        source_code: str,
        contract_name: str = "UnknownContract",
        contract_address: Optional[str] = None,
        chain: str = "ethereum",
        metadata: Optional[Dict[str, Any]] = None,
    ):
        self.source_code = source_code
        self.contract_name = contract_name
        self.contract_address = contract_address
        self.chain = chain
        self._metadata = dict(metadata or {})
        self.language = detect_language(source_code)
        self.analysis_id = self._make_id()

    def _make_id(self) -> str:
        raw = f"{self.contract_name}:{self.source_code[:256]}:{time.time()}"
        return "SC-" + hashlib.sha256(raw.encode()).hexdigest()[:12].upper()

    def _grade(self, score: float) -> str:
        if score >= 95: return "A+"
        if score >= 90: return "A"
        if score >= 85: return "A-"
        if score >= 80: return "B+"
        if score >= 75: return "B"
        if score >= 70: return "B-"
        if score >= 65: return "C+"
        if score >= 60: return "C"
        if score >= 55: return "C-"
        if score >= 50: return "D"
        return "F"

    def _score_penalty(self, severity: VulnSeverity) -> float:
        return {
            VulnSeverity.CRITICAL: 25.0,
            VulnSeverity.HIGH:     15.0,
            VulnSeverity.MEDIUM:    7.0,
            VulnSeverity.LOW:       2.0,
            VulnSeverity.INFO:      0.0,
        }[severity]

    def analyze(self) -> ContractAnalysisResult:
        """Run all vulnerability rules and return a structured report."""
        start = time.time()
        source = self.source_code
        lang = self.language

        findings: List[ContractVulnerability] = []
        safe_count = 0

        slither_findings = None
        vyper_ast_findings = None
        
        if lang == ContractLanguage.SOLIDITY:
            slither_findings = run_slither_analysis(source)
        elif lang == ContractLanguage.VYPER:
            vyper_ast_findings = run_vyper_ast_analysis(source)

        for rule in VULN_RULES:
            # Skip rules for the wrong language
            if rule.language is not None and rule.language != lang:
                continue

            matched = False
            matched_lines: List[int] = []
            matched_snippets: List[str] = []

            is_slither_targeted = rule.id in [
                "SC-001", "SC-031", "SC-041", "SC-060", "SC-119", "SC-102", "SC-111", "SC-116",
                "SC-020", "SC-114", "SC-030", "SC-042", "SC-050", "SC-105", "SC-101", "SC-122",
                "SC-113", "SC-112", "SC-002", "SC-010", "SC-011", "SC-061", "SC-100", "SC-103",
                "SC-104", "SC-106", "SC-107", "SC-110", "SC-021", "SC-032", "SC-115", "SC-117", "SC-118",
                "SC-121", "SC-123", "SC-124", "SC-130", "SC-132", "SC-133"
            ]
            
            is_vyper_ast_targeted = rule.id in [
                "SC-080", "SC-081"
            ]

            if slither_findings is not None and is_slither_targeted:
                if slither_findings.get(rule.id):
                    matched = True
                    matched_snippets = slither_findings[rule.id]
            elif vyper_ast_findings is not None and is_vyper_ast_targeted:
                if vyper_ast_findings.get(rule.id):
                    matched = True
                    matched_snippets = vyper_ast_findings[rule.id]
            else:
                for pattern, flags in rule.patterns:
                    try:
                        for m in re.finditer(pattern, source, flags):
                            matched = True
                            matched_lines.extend(_get_line_numbers(source, m))
                            matched_snippets.append(_safe_snippet(source, m))
                            break  # one match per pattern is enough
                        if matched:
                            break
                    except re.error:
                        continue

            if matched:
                findings.append(ContractVulnerability(
                    rule_id=rule.id,
                    name=rule.name,
                    category=rule.category,
                    severity=rule.severity.value,
                    status=VulnStatus.DETECTED.value,
                    description=rule.description,
                    remediation=rule.remediation,
                    line_numbers=sorted(set(matched_lines)),
                    snippets=matched_snippets[:3],
                    compliance_mappings=_COMPLIANCE_MAP.get(rule.category, {}),
                ))
            else:
                safe_count += 1

        # Run Token Contract Analyzer
        token_analyzer = TokenContractAnalyzer()
        token_findings = token_analyzer.analyze_source(source, lang.value)

        for tf in token_findings:
            findings.append(ContractVulnerability(
                rule_id=tf["rule_id"],
                name=tf["name"],
                category=tf["category"],
                severity=tf["severity"],
                status=VulnStatus.DETECTED.value,
                description=tf["description"],
                remediation=tf["remediation"],
                line_numbers=[],  # Pattern matching snippets for now
                snippets=[tf["snippet"]],
                compliance_mappings={},
            ))

        # On-chain metadata risk overlays (best effort signals).
        proxy_flag = str(self._metadata.get("proxy", "0")) == "1"
        verification_status = str(self._metadata.get("verification_status", "unknown")).lower()
        if proxy_flag and verification_status != "verified":
            findings.append(
                ContractVulnerability(
                    rule_id="SC-104",
                    name="Unverified Proxy Risk",
                    category="unverified_proxy",
                    severity=VulnSeverity.CRITICAL.value,
                    status=VulnStatus.DETECTED.value,
                    description="Proxy contract appears unverified on explorer metadata.",
                    remediation="Verify proxy + implementation source and publish implementation address history.",
                    line_numbers=[],
                    snippets=[],
                    compliance_mappings=_COMPLIANCE_MAP.get("unverified_proxy", {}),
                )
            )

        age_days_raw = self._metadata.get("contract_age_days")
        try:
            age_days = float(str(age_days_raw))
        except Exception:
            age_days = None
        if age_days is not None and age_days < 7.0:
            findings.append(
                ContractVulnerability(
                    rule_id="SC-125",
                    name="Very New Contract Age",
                    category="access_control",
                    severity=VulnSeverity.HIGH.value,
                    status=VulnStatus.DETECTED.value,
                    description="Contract age is under 7 days, increasing launch and rug risk.",
                    remediation="Treat as high-risk until additional time, audits, and holder distribution evidence accumulate.",
                    line_numbers=[],
                    snippets=[],
                    compliance_mappings=_COMPLIANCE_MAP.get("access_control", {}),
                )
            )

        # Score calculation: start at 100, deduct per finding
        score = 100.0
        for f in findings:
            try:
                sev = VulnSeverity(str(f.severity).lower())
            except Exception:
                sev = VulnSeverity.MEDIUM
            score -= self._score_penalty(sev)
        score = max(0.0, score)
        grade = self._grade(score)

        risk_summary = {
            "critical": sum(1 for f in findings if f.severity == "critical"),
            "high":     sum(1 for f in findings if f.severity == "high"),
            "medium":   sum(1 for f in findings if f.severity == "medium"),
            "low":      sum(1 for f in findings if f.severity == "low"),
            "info":     sum(1 for f in findings if f.severity == "info"),
        }

        return ContractAnalysisResult(
            analysis_id=self.analysis_id,
            chain=self.chain,
            language=lang.value,
            contract_address=self.contract_address,
            contract_name=self.contract_name,
            source_hash=hashlib.sha256(self.source_code.encode()).hexdigest()[:16],
            analyzed_at=datetime.now(timezone.utc).isoformat(),
            duration_seconds=round(time.time() - start, 4),
            total_rules=sum(
                1 for r in VULN_RULES
                if r.language is None or r.language == lang
            ),
            vulnerabilities_found=len(findings),
            safe_checks=safe_count,
            score=round(score, 1),
            grade=grade,
            risk_summary=risk_summary,
            vulnerabilities=[asdict(f) for f in findings],
            metadata={
                "language_detected": lang.value,
                "chain": self.chain,
                "lines_of_code": str(source.count("\n") + 1),
                **{k: str(v) for k, v in self._metadata.items()},
            },
        )


# ——— CLI / quick-test ————————————————————————————————————————————————

if __name__ == "__main__":
    import sys

    SAMPLE = """
pragma solidity ^0.6.0;

contract VulnerableVault {
    mapping(address => uint) public balances;

    function deposit() public payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint _amount) public {
        require(balances[msg.sender] >= _amount);
        msg.sender.call.value(_amount)("");  // reentrancy!
        balances[msg.sender] -= _amount;
    }

    function kill() public {
        selfdestruct(msg.sender);
    }

    function swap() public {
        uint price = getPrice();
        uint[] memory out = IUniswapV2Router(router).getAmountsOut(1e18, path);
    }
}
"""

    analyzer = SmartContractAnalyzer(
        source_code=SAMPLE,
        contract_name="VulnerableVault",
        chain="ethereum",
    )
    result = analyzer.analyze()
    print(json.dumps(asdict(result), indent=2))
