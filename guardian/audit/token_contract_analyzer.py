from dataclasses import dataclass, field
from enum import Enum
import re
from typing import List, Optional, Tuple


class ContractLanguage(Enum):
    SOLIDITY = "solidity"
    VYPER = "vyper"


class VulnSeverity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass
class TokenVulnRule:
    id: str
    name: str
    category: str
    severity: VulnSeverity
    description: str
    remediation: str
    patterns: List[Tuple[str, int]] = field(default_factory=list)
    language: Optional[ContractLanguage] = None


TOKEN_VULN_RULES: List[TokenVulnRule] = [
    TokenVulnRule(
        id="TK-001",
        name="Hidden Mint Function",
        category="uncapped_mint",
        severity=VulnSeverity.CRITICAL,
        description="Mint-like paths are present and may allow unbounded token issuance.",
        remediation="Gate mint operations behind strict role controls and hard max-supply checks.",
        patterns=[
            (r"function\s+(mint|issue|generate)\w*\s*\(", re.IGNORECASE),
            (r"\b_mint\s*\(", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-002",
        name="Fee-on-Transfer (Honeypot)",
        category="honeypot",
        severity=VulnSeverity.CRITICAL,
        description="Transfer taxes/fees can trap exits or silently drain transfers.",
        remediation="Hard-cap transfer fees and prevent post-deploy arbitrary fee mutation.",
        patterns=[
            (r"(buyTax|sellTax|transferTax|feeOnTransfer|taxFee)", re.IGNORECASE),
            (r"function\s+set\w*(tax|fee)\w*\s*\(", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-003",
        name="Transfer Blacklist / Whitelist",
        category="transfer_restriction",
        severity=VulnSeverity.HIGH,
        description="Address lists can be used to block user exits.",
        remediation="Avoid owner-operated blocklists in tradable tokens or place behind DAO governance.",
        patterns=[
            (r"(isBlacklisted|blacklist|whitelist|excludedFromTrading)", re.IGNORECASE),
            (r"require\s*\(\s*!\s*\w*(blacklist|blocked)\w*", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-004",
        name="Owner Can Pause Transfers",
        category="centralization",
        severity=VulnSeverity.HIGH,
        description="Token transfers can be centrally frozen.",
        remediation="Use timelocked governance for pause controls and publish freeze policy.",
        patterns=[
            (r"\bPausable\b", re.IGNORECASE),
            (r"\bwhenNotPaused\b", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-005",
        name="Max Transaction Limit Manipulation",
        category="transfer_restriction",
        severity=VulnSeverity.HIGH,
        description="Max-tx settings can be changed to censor or trap users.",
        remediation="Cap and timelock changes to max transaction / wallet limits.",
        patterns=[
            (r"(maxTxAmount|maxTransaction|maxWallet)", re.IGNORECASE),
            (r"function\s+set\w*(maxTx|maxWallet)\w*\s*\(", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-006",
        name="Hidden Balance Manipulation",
        category="balance_manipulation",
        severity=VulnSeverity.CRITICAL,
        description="Token balance accounting appears to include non-standard adjustments.",
        remediation="Ensure balance reads/writes are transparent and consistent with ERC semantics.",
        patterns=[
            (r"function\s+balanceOf\s*\([^)]*\)[^}]*return[^;]*[+\-*\/]", re.DOTALL | re.IGNORECASE),
            (r"(hiddenBalance|virtualBalance|bonusBalance)", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-007",
        name="Proxy Token (Upgradeable Logic)",
        category="upgradeability_risk",
        severity=VulnSeverity.HIGH,
        description="Upgradeable token logic increases governance/upgrade abuse risk.",
        remediation="Use transparent upgrade controls with multisig + timelock and on-chain announcements.",
        patterns=[
            (r"(upgradeTo|upgradeToAndCall|_authorizeUpgrade)", re.IGNORECASE),
            (r"\b(UUPSUpgradeable|TransparentUpgradeableProxy)\b", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-008",
        name="No Renounced Ownership",
        category="centralization",
        severity=VulnSeverity.MEDIUM,
        description="Owner privileges appear active without ownership renounce flow.",
        remediation="If decentralization is claimed, publish ownership transfer/renounce evidence.",
        patterns=[
            (r"\bOwnable\b", re.IGNORECASE),
            (r"(onlyOwner|owner\s*\()", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-009",
        name="Liquidity Lock Check Missing",
        category="liquidity_risk",
        severity=VulnSeverity.HIGH,
        description="No explicit LP lock/locker signals increase rugpull risk.",
        remediation="Lock LP with auditable locker contracts and disclose unlock schedules.",
        patterns=[
            (r"(addLiquidity|removeLiquidity)", re.IGNORECASE),
            (r"(liquidity|lp)\s*(unlock|release|withdraw)", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-010",
        name="Supply Concentration Risk",
        category="centralization",
        severity=VulnSeverity.CRITICAL,
        description="Initial mint concentration appears heavily skewed to owner/deployer.",
        remediation="Distribute supply via vesting/treasury contracts and disclose holder concentration.",
        patterns=[
            (r"constructor[^}]*_mint\s*\(\s*msg\.sender", re.DOTALL | re.IGNORECASE),
            (r"_mint\s*\(\s*owner\s*,", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-011",
        name="Hidden Approve/TransferFrom Backdoor",
        category="unauthorized_transfer",
        severity=VulnSeverity.CRITICAL,
        description="Allowance flow may permit unsafe transfer behavior.",
        remediation="Require strict allowance checks and emit approval/transfer audit events.",
        patterns=[
            (r"function\s+transferFrom\s*\(", re.IGNORECASE),
            (r"_spendAllowance|allowance\s*\[", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-012",
        name="Self-Destruct in Token",
        category="destructive_opcode",
        severity=VulnSeverity.CRITICAL,
        description="Self-destruct logic can permanently disrupt token behavior.",
        remediation="Remove selfdestruct/suicide paths from token contracts.",
        patterns=[
            (r"\bselfdestruct\s*\(", re.IGNORECASE),
            (r"\bsuicide\s*\(", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-013",
        name="Cooldown Manipulation",
        category="transfer_restriction",
        severity=VulnSeverity.MEDIUM,
        description="Cooldowns can be used to trap users during volatile windows.",
        remediation="Expose immutable or tightly-governed cooldown logic.",
        patterns=[
            (r"(cooldown|coolDown|cool_time|tradeCooldown)", re.IGNORECASE),
            (r"function\s+set\w*cool\w*\s*\(", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-014",
        name="Tax Rate Changeable Post-Deploy",
        category="honeypot",
        severity=VulnSeverity.HIGH,
        description="Post-deploy mutability of tax/fee rates can enable sudden 99% sell-tax behavior.",
        remediation="Use immutable fee parameters or transparent governance timelocks.",
        patterns=[
            (r"function\s+set\w*(tax|fee)\w*\s*\(", re.IGNORECASE),
            (r"(newTax|newFee|updateTax|updateFee)", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
    TokenVulnRule(
        id="TK-015",
        name="Missing Decimal Verification",
        category="precision_risk",
        severity=VulnSeverity.MEDIUM,
        description="Non-standard decimal behavior can break integrations and pricing math.",
        remediation="Explicitly declare decimals and validate assumptions in dependent math.",
        patterns=[
            (r"function\s+decimals\s*\(", re.IGNORECASE),
            (r"uint8\s+(public\s+)?decimals", re.IGNORECASE),
        ],
        language=ContractLanguage.SOLIDITY,
    ),
]


class TokenContractAnalyzer:
    def __init__(self) -> None:
        self.rules = TOKEN_VULN_RULES

    def analyze_source(self, source_code: str, language: str) -> List[dict]:
        findings: List[dict] = []
        lang_value = (language or "").lower()
        lang_enum = ContractLanguage.SOLIDITY if lang_value == "solidity" else ContractLanguage.VYPER

        for rule in self.rules:
            if rule.language and rule.language != lang_enum:
                continue

            match_obj = None
            for pattern, flags in rule.patterns:
                try:
                    match_obj = re.search(pattern, source_code, flags)
                except re.error:
                    match_obj = None
                if match_obj:
                    break

            if not match_obj:
                continue

            snippet_start = max(0, match_obj.start() - 80)
            snippet_end = min(len(source_code), match_obj.end() + 80)
            findings.append(
                {
                    "rule_id": rule.id,
                    "name": rule.name,
                    "category": rule.category,
                    "severity": rule.severity.value,
                    "description": rule.description,
                    "remediation": rule.remediation,
                    "snippet": source_code[snippet_start:snippet_end].strip(),
                }
            )

        return findings
