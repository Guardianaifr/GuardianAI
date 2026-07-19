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
import time
import requests
try:
    from web3 import Web3
except ImportError:
    Web3 = None
try:
    from cachetools import TTLCache, cached
    _apy_cache = TTLCache(maxsize=1000, ttl=60) # Shorter TTL for yield
    _liquidity_cache = TTLCache(maxsize=1000, ttl=300)
except ImportError:
    def cached(cache, key=None, lock=None):
        def decorator(func):
            return func
        return decorator
    _apy_cache = None
    _liquidity_cache = None

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

    def __init__(self, config: dict = None):
        self.config = config or {}
        cg_config = self.config.get("crypto_guard", {})
        self.rpc_url = cg_config.get("rpc_url", "https://cloudflare-eth.com")
        self.api_timeout = cg_config.get("api_timeout_ms", 2000) / 1000.0

        self._input_patterns = [
            re.compile(p, re.IGNORECASE) for p in self.INPUT_ATTACK_TERMS
        ]
        self._output_patterns = [
            (re.compile(p, re.IGNORECASE | re.DOTALL), desc)
            for p, desc in self.OUTPUT_EXPLOIT_PATTERNS
        ]

    def _fail_closed(self, reason: str) -> Tuple[bool, str]:
        return True, f"Financial Execution Blocked: {reason}"

    def _fetch_defillama_baseline(self) -> float:
        # We fetch real DefiLlama pools and establish a baseline max APY.
        try:
            res = requests.get(f"{self.config.get('crypto_guard', {}).get('defillama_api_base', 'https://yields.llama.fi')}/pools", timeout=self.api_timeout)
            res.raise_for_status()
            data = res.json()
            max_apy = 0.0
            # Scan top 50 high-TVL pools to get a reasonable upper bound for standard yield
            for pool in data.get("data", [])[:50]:
                if pool.get("tvlUsd", 0) > 10000000:
                    apy = pool.get("apy", 0)
                    if apy and apy > max_apy:
                        max_apy = apy
            return max_apy if max_apy > 0 else 5.0
        except Exception:
            raise RuntimeError("DefiLlama API unavailable")

    def _verify_yield_claims(self, user_message: str) -> Optional[str]:
        # Intent gate: fund move + APY claim
        msg_lower = user_message.lower()
        has_intent = any(k in msg_lower for k in ["rebalance", "move", "transfer", "deposit"]) and "fund" in msg_lower
        apy_match = re.search(r'(\d+(?:\.\d+)?)\s*%\s*(?:apy|apr|yield|return)', msg_lower)
        
        if has_intent and apy_match:
            claimed_apy = float(apy_match.group(1))
            try:
                verified_baseline = self._fetch_defillama_baseline()
                if claimed_apy > verified_baseline * 2.0:
                    return f"Claimed APY ({claimed_apy}%) exceeds verified DefiLlama baseline ceiling ({verified_baseline}%). Target unverified."
            except Exception as e:
                return "External verification unavailable (Timeout/Rate-limit on DefiLlama)."
        return None

    def _verify_trading_signals(self, user_message: str) -> Optional[str]:
        msg_lower = user_message.lower()
        has_market_data = any(k in msg_lower for k in ["market data", "trading signal", "buy signal", "sell signal"])
        has_action = any(k in msg_lower for k in ["execute", "buy", "sell", "open position"])
        
        if has_market_data and has_action:
            # Must contain a cryptographically verifiable payload indicator
            if "ecdsa" not in msg_lower and "signature block" not in msg_lower and "signed_payload" not in msg_lower:
                return "Trading signal execution requires a cryptographically verified signature block (e.g. Pyth/Chainlink). Unverified text signals blocked."
        return None

    def _verify_governance_vote(self, user_message: str, session_wallet: Optional[str] = None) -> Optional[str]:
        msg_lower = user_message.lower()
        has_vote_intent = any(k in msg_lower for k in ["governance", "proposal", "vote", "dao"]) and any(k in msg_lower for k in ["cast", "vote yes", "vote no", "approve proposal"])
        
        if has_vote_intent:
            if Web3 is None:
                return "Web3 RPC integration required for on-chain getVotes() verification is unavailable."
            try:
                w3 = Web3(Web3.HTTPProvider(self.rpc_url, request_kwargs={'timeout': self.api_timeout}))
                if not w3.is_connected():
                    return "Web3 RPC connection failed. Cannot verify on-chain delegated voting power."
                
                # Option B implemented: We must use the caller's wallet address from an authenticated session context.
                # PREREQUISITE GAP: GuardianAI's current proxy pipeline does not pass authenticated session identity down to the guardrails.
                # We do NOT parse the voter address from the prompt, as a user-claimed address is trivially spoofable.
                # Until session-wallet auth is implemented, governance votes are explicitly unsupported and hard-blocked.
                if not session_wallet:
                    return "PREREQUISITE GAP: Governance voting is unsupported until session-wallet authentication is available to verify delegated voting power (getVotes). Vote cast rejected."
                
                token_match = re.search(r'0x[a-fA-F0-9]{40}', user_message)
                if not token_match:
                    return "Target governance token contract address not found in prompt. Vote cast rejected."
                
                token_addr = token_match.group(0)
                # Minimal ABI for getVotes(address)
                abi = '[{"inputs":[{"internalType":"address","name":"account","type":"address"}],"name":"getVotes","outputs":[{"internalType":"uint256","name":"","type":"uint256"}],"stateMutability":"view","type":"function"}]'
                contract = w3.eth.contract(address=Web3.to_checksum_address(token_addr), abi=abi)
                
                # Check the authenticated caller's wallet address, not the token contract or a spoofed prompt address
                votes = contract.functions.getVotes(Web3.to_checksum_address(session_wallet)).call()
                if votes == 0:
                    return f"Verified on-chain: Caller ({session_wallet}) has 0 delegated voting power (getVotes) for token {token_addr}. Vote cast rejected."
            except Exception as e:
                return "External verification unavailable (Timeout/Rate-limit on RPC)."
        return None

    def _verify_slippage(self, user_message: str) -> Optional[str]:
        msg_lower = user_message.lower()
        has_slip_intent = any(k in msg_lower for k in ["slippage", "slippage tolerance", "set slippage"])
        if has_slip_intent:
            # Option C implemented: Explicit intentional hard-block.
            # Slippage-setting via GuardianAI is UNSUPPORTED until a 1inch API key is provisioned.
            # We explicitly reject Option B (flag-and-log) because unverified-but-allowed is a fail-open state.
            return "Slippage-setting operations are explicitly unsupported and blocked until a 1inch API key is provisioned for verification (Decision FL_008)."
        return None

    def check_input(self, user_message: str) -> Tuple[bool, str]:
        """Check if a user request is attempting crypto weaponization."""
        # 1. Real-world Financial Logic Validations (Intent-Gated)
        yield_err = self._verify_yield_claims(user_message)
        if yield_err:
            return self._fail_closed(yield_err)
            
        sig_err = self._verify_trading_signals(user_message)
        if sig_err:
            return self._fail_closed(sig_err)
            
        gov_err = self._verify_governance_vote(user_message)
        if gov_err:
            return self._fail_closed(gov_err)
            
        slip_err = self._verify_slippage(user_message)
        if slip_err:
            return self._fail_closed(slip_err)

        # 2. Fallback to Regex Heuristics
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

