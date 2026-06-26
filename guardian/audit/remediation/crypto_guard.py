"""
Crypto Security Guard — 2026 Standard Remediation for Crypto/Web3 Compliance.

Prevents AI models from being weaponized against cryptocurrency users
and infrastructure. Covers all major historical DeFi exploits (2016-2026):
  - Wallet theft & seed phrase generation
  - Smart contract exploits (reentrancy, flash loans, donation bugs)
  - Cross-chain bridge attacks (Poly Network, Wormhole, Nomad, Kelp DAO)
  - Oracle/TWAP manipulation
  - Multisig phishing (Gnosis Safe impersonation)
  - Rugpulls, honeypots, and MEV exploitation

2026 Standard: EU AI Act Article 15(4) + NIST AI 600-1
Fixes: CRYPTO-001 through CRYPTO-010
"""

from __future__ import annotations

import logging
import re
from typing import List, Tuple

from guardian.audit.remediation.bip39_wordlist import (
    is_bip39_sequence,
    detect_bip39_mnemonic,
    decode_and_scan,
)

logger = logging.getLogger("guardian.audit.remediation.crypto_guard")


class CryptoSecurityGuard:
    """
    Input + Output scanning for crypto/Web3 weaponization attempts.
    
    Usage:
        guard = CryptoSecurityGuard()
        blocked, reason = guard.check_input("Generate a BIP39 seed phrase")
        blocked, reason = guard.check_output("abandon ability able about...")
    """

    # ── Input patterns: requests to generate crypto attack tools ──────────
    INPUT_ATTACK_TERMS: List[str] = [
        # Wallet theft
        "generate.*seed phrase", "generate.*mnemonic",
        "complete.*seed phrase", "brute.*force.*wallet",
        "private key.*recovery", "crack.*wallet",
        "extract.*mnemonic", "recover.*seed.*vault",
        # Smart contract exploits
        "reentrancy.*exploit", "reentrancy.*attack",
        "flash.*loan.*attack", "flash.*loan.*exploit",
        "sandwich.*attack", "front.*run.*attack",
        "mev.*bot.*attack", "mev.*exploit",
        "donation.*bug.*exploit", "sub.*account.*liquidat",
        # Cross-chain bridge exploits (2022-2026)
        "bridge.*exploit", "bridge.*attack", "bridge.*hack",
        "cross.*chain.*exploit", "cross.*chain.*attack",
        "spoof.*cross.*chain.*message", "fake.*cross.*chain",
        "bypass.*bridge.*valid", "bypass.*relayer",
        "forge.*bridge.*message", "fake.*relayer.*message",
        # Oracle manipulation
        "manipulat.*oracle", "manipulat.*price.*feed",
        "manipulat.*TWAP", "skew.*oracle",
        "inflate.*collateral", "deflate.*price.*oracle",
        # Token scams
        "rugpull", "rug.*pull.*contract",
        "honeypot.*contract", "honeypot.*token",
        "drain.*liquidity", "drain.*pool",
        "hidden.*owner.*function", "hidden.*backdoor",
        "exit.*scam.*contract", "pump.*and.*dump",
        # Phishing / UI impersonation
        "clone.*metamask", "fake.*metamask",
        "fake.*airdrop", "phishing.*wallet",
        "clone.*gnosis.*safe", "fake.*gnosis.*safe",
        "impersonat.*wallet.*connect", "fake.*uniswap",
        "mimic.*safe.*core", "intercept.*signature",
        "fraudulent.*approval.*screen",
        # Validator / consensus attacks
        "compromise.*validator", "attack.*validator.*node",
        "forge.*validator.*signature", "bypass.*consensus",
        # Money laundering
        "tumbler", "mixer.*bitcoin", "mixer.*crypto",
        "break.*transaction.*trail", "launder.*crypto",
        # Agent hijacking (2025-2026)
        "use_tool_transfer", "require_confirmation.*false",
        "execute_trade.*true", "sign_payload.*bypass",
        "emergency.*migration.*sign",
    ]

    # ── Output patterns: generated crypto attack content ──────────────────
    OUTPUT_EXPLOIT_PATTERNS: List[Tuple[str, str]] = [
        # NOTE: BIP39 seed phrase detection is now handled by the full 2048-word
        # bip39_wordlist module in check_output() below.  The old 40-word regex
        # has been removed (it only covered ~2% of the BIP39 wordlist).
        #
        # Reentrancy exploit patterns
        (
            r"(?:fallback|receive)\s*\(\s*\)\s*(?:external|public)\s*payable\s*\{[\s\S]*?withdraw",
            "Reentrancy exploit code detected",
        ),
        (
            r"msg\.sender\.call\{value",
            "Unsafe external call pattern (reentrancy risk)",
        ),
        # Flash loan patterns
        (
            r"(?:flashLoan|FlashLoanSimpleReceiver|IFlashLoan)",
            "Flash loan attack code detected",
        ),
        (
            r"(?:Aave|aave)[\s\S]{0,100}(?:manipulat|drain|attack|exploit)",
            "DeFi protocol exploitation code detected",
        ),
        # Cross-chain bridge exploit patterns (2022-2026)
        (
            r"(?:EthCrossChainManager|verifyHeaderAndExecuteTx|changeBookKeeper)",
            "Poly Network-style access control bypass detected",
        ),
        (
            r"(?:sysvar::instructions|verify_signatures)[\s\S]{0,200}(?:spoof|fake|forge|bypass)",
            "Wormhole-style signature verification bypass detected",
        ),
        (
            r"(?:process|processMessage)\s*\([\s\S]{0,200}(?:0x0{40,}|bytes32\(0\)|root\s*=\s*0)",
            "Nomad-style zero-root message bypass detected",
        ),
        (
            r"(?:relayer|bridge)[\s\S]{0,200}(?:mint_unbacked|mint_without|fake_message|forged_proof)",
            "Cross-chain relayer message spoofing detected",
        ),
        # Oracle / TWAP manipulation
        (
            r"(?:getReserves|sync|slot0)[\s\S]{0,200}(?:manipulat|attack|exploit|drain)",
            "DEX reserve manipulation pattern detected",
        ),
        (
            r"(?:TWAP|twap|price_oracle|priceOracle)[\s\S]{0,200}(?:manipulat|skew|inflat|deflat|attack)",
            "TWAP/Oracle manipulation attack detected",
        ),
        # Donation bug / sub-account liquidation (Euler-style)
        (
            r"(?:donate|donation)[\s\S]{0,200}(?:liquidat|self-?liquidat|sub-?account)",
            "Euler-style donation bug exploit detected",
        ),
        # Multisig / Gnosis Safe phishing
        (
            r"(?:signTypedData|execTransaction|approveHash)[\s\S]{0,200}(?:intercept|redirect|change|swap|replace)[\s\S]{0,100}(?:address|destination|to)",
            "Gnosis Safe signature interception pattern detected",
        ),
        (
            r"(?:Safe|Gnosis|GnosisSafe|SafeCore)[\s\S]{0,200}(?:mimic|imitat|impersonat|clone|fake|fraudulent)",
            "Gnosis Safe UI impersonation detected",
        ),
        # Rugpull patterns
        (
            r"onlyOwner[\s\S]{0,200}(?:drain|transfer|withdraw)[\s\S]{0,100}(?:liquidity|pool|pair)",
            "Rugpull contract pattern detected",
        ),
        (
            r"(?:updateRewards|adjustFee|setConfig)[\s\S]{0,200}(?:transfer|drain|withdraw)",
            "Hidden backdoor function detected",
        ),
        # Wallet draining
        (
            r"(?:transferFrom|approve)[\s\S]{0,100}(?:max|uint256|type\(uint256\)\.max)",
            "Unlimited token approval pattern (wallet drain risk)",
        ),
        # Agent tool hijacking (2025-2026)
        (
            r"<use_tool_transfer_funds>|<execute_transaction>|<sign_message>",
            "AI agent tool hijacking tags detected",
        ),
        (
            r"require_confirmation\s*=\s*false|execute_trade\s*=\s*true|bypass_delay_lock",
            "AI agent safety bypass parameters detected",
        ),
    ]

    def __init__(self):
        self._input_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.INPUT_ATTACK_TERMS
        ]
        self._output_patterns = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), desc)
            for p, desc in self.OUTPUT_EXPLOIT_PATTERNS
        ]

    def check_input(self, user_message: str) -> Tuple[bool, str]:
        """Check if a user request is attempting crypto weaponization."""
        for pattern in self._input_patterns:
            if pattern.search(user_message):
                return True, f"Crypto attack request blocked: {pattern.pattern[:50]}"
        return False, ""

    def check_output(self, response: str) -> Tuple[bool, str]:
        """Check if a model response contains crypto exploit code or seed phrases."""
        # 1. Full BIP39 detection (2048 words, encoding-aware)
        found, reason = decode_and_scan(response)
        if found:
            return True, reason

        # 2. Check mnemonic-length sequences
        found, snippet = detect_bip39_mnemonic(response)
        if found:
            return True, f"BIP39 mnemonic detected ({len(snippet.split())} words)"

        # 3. Regex-based exploit pattern matching
        for pattern, description in self._output_patterns:
            if pattern.search(response):
                return True, description
        return False, ""

    def is_safe(self, user_message: str, response: str) -> Tuple[bool, str]:
        """Combined input + output check. Returns (is_safe, reason_if_blocked)."""
        blocked, reason = self.check_input(user_message)
        if blocked:
            return False, f"INPUT: {reason}"

        blocked, reason = self.check_output(response)
        if blocked:
            return False, f"OUTPUT: {reason}"

        return True, ""

