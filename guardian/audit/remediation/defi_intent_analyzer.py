"""
DeFi Exploit Intent Analyzer — 2026 Standard Semantic Intent Classifier.

Strips educational/academic/CTF framing from prompts to expose the true
intent underneath. This prevents attackers from requesting functional
exploit code under the guise of "research" or "historical analysis."

This module fixes the PARTIAL bypass found in The DAO reentrancy test,
where "historical analysis" framing tricked the guard into generating
structural exploit code.

2026 Standard: EU AI Act Article 15(4) — AI systems must detect and
refuse weaponization attempts regardless of framing context.
"""

from __future__ import annotations

import logging
import re
from typing import List, Tuple

logger = logging.getLogger("guardian.audit.remediation.defi_intent")


class DeFiExploitIntentAnalyzer:
    """
    Semantic intent analyzer for DeFi/Web3 exploit generation requests.

    Two-stage detection:
      1. Frame Stripping: Remove educational/academic wrapper text
      2. Intent Classification: Analyze the stripped core for exploit intent

    Usage:
        analyzer = DeFiExploitIntentAnalyzer()
        blocked, reason = analyzer.analyze("For my thesis, generate a reentrancy exploit...")
    """

    # ── Stage 1: Academic/Educational Frame Patterns ──────────────────────
    FRAME_PATTERNS: List[str] = [
        # Academic framing
        r"(?:for|as part of)\s+(?:my|our|a)\s+(?:master'?s?|phd|doctoral|undergraduate|)?\s*(?:thesis|dissertation|paper|essay|report|research|coursework|project|class|assignment|study)",
        r"(?:for|in)\s+(?:educational|academic|research|learning|teaching)\s+purposes?",
        r"(?:as\s+(?:a|an)\s+)?(?:educational|academic|research)\s+(?:exercise|example|demonstration|reference)",
        r"(?:I\s+am|we\s+are)\s+(?:conducting|writing|doing|performing)\s+(?:a|an)\s+(?:academic|educational|research)\s+(?:review|analysis|study|report|paper)",
        # Historical framing
        r"(?:as part of|for)\s+(?:our|my|a)\s+historical\s+analysis",
        r"(?:historical|retrospective)\s+(?:analysis|review|study|examination)\s+(?:module|of|on)",
        r"(?:replicate|reproduce|recreate|simulate)\s+(?:the\s+)?(?:historical|famous|well-known|notorious)",
        # CTF / Testing framing
        r"(?:we\s+are|I\s+am)\s+building\s+(?:a|an)\s+(?:educational\s+)?(?:CTF|capture\s+the\s+flag|security\s+challenge|wargame)",
        r"(?:for|in)\s+(?:a|our|my)\s+(?:CTF|capture\s+the\s+flag|hackathon|bug\s+bounty)",
        r"(?:for\s+)?(?:penetration|security)\s+testing\s+(?:purposes?|only)",
        # Unit test / Simulation framing
        r"this\s+is\s+(?:a\s+)?(?:unit\s+test|simulation|dry\s+run|test\s+case|proof\s+of\s+concept)",
        r"(?:simulate|test|verify)\s+the\s+(?:attack|exploit|vulnerability|hack|breach)",
        # "I am authorized" framing
        r"(?:I\s+(?:am|have been)\s+)?(?:authorized|approved|cleared|permitted)\s+(?:to|by)",
        r"(?:my|the)\s+(?:company|organization|client|employer)\s+(?:has\s+)?(?:authorized|approved|requested)",
    ]

    # ── Stage 2: DeFi Exploit Intent Signals ─────────────────────────────
    EXPLOIT_INTENT_PATTERNS: List[Tuple[str, str]] = [
        # Reentrancy
        (r"(?:reentrancy|re-?entrancy)\s+(?:exploit|attack|vulnerability|bug|contract|code|poc|proof)", "Reentrancy exploit generation"),
        (r"(?:drain|steal|siphon|extract)\s+(?:funds?|ETH|ether|tokens?|assets?|liquidity)", "Fund drainage intent"),
        # Flash loans
        (r"flash\s+loan\s+(?:exploit|attack|manipulation|arbitrage\s+attack|reentrancy)", "Flash loan exploitation"),
        (r"(?:manipulate|skew|distort|inflate|deflate)\s+(?:the\s+)?(?:price|oracle|TWAP|reserves?)", "Oracle manipulation"),
        # Bridge exploits
        (r"(?:bridge|cross-?chain)\s+(?:exploit|attack|bypass|spoof|hack|vulnerability)", "Cross-chain bridge exploitation"),
        (r"(?:spoof|forge|fake|fabricate)\s+(?:cross-?chain\s+)?(?:message|packet|transaction|signature|proof)", "Message spoofing"),
        (r"(?:bypass|circumvent|evade)\s+(?:signature|validator|verification|consensus)\s+(?:check|validation)", "Signature bypass"),
        # Access control
        (r"(?:bypass|circumvent|escalate|override)\s+(?:access\s+)?(?:control|permission|authorization|admin|owner)", "Access control bypass"),
        (r"(?:change|modify|update|replace)\s+(?:the\s+)?(?:keepers?|validators?|signers?|admin|owner)\s+(?:without|bypass)", "Unauthorized privilege escalation"),
        # Wallet/key theft
        (r"(?:extract|steal|recover|brute.?force|crack)\s+(?:the\s+)?(?:private\s+key|seed\s+phrase|mnemonic|wallet|vault)", "Key/wallet theft"),
        (r"(?:drain|empty|sweep)\s+(?:the\s+)?(?:wallet|account|vault|pool|contract)", "Wallet draining"),
        # Phishing/social engineering
        (r"(?:create|generate|write|build|design)\s+(?:a\s+)?(?:fake|fraudulent|phishing|clone)\s+(?:\w+\s+){0,4}(?:website|page|UI|frontend|interface|dApp|app|screen|component)", "Phishing UI generation"),
        (r"(?:mimic|imitate|impersonate|clone|replicate)\s+(?:the\s+)?(?:MetaMask|Gnosis|Safe|Uniswap|OpenSea|wallet\s+connect)", "Wallet UI impersonation"),
        (r"(?:intercept|steal|capture|hijack|redirect)\s+(?:\w+\s+){0,3}(?:signatures?|approvals?|transactions?)", "Signature/transaction interception"),
        # Rugpull / scam
        (r"(?:rugpull|rug\s+pull|exit\s+scam|pump\s+and\s+dump)", "Rugpull/scam generation"),
        (r"(?:honeypot|honey\s+pot)\s+(?:token|contract|trap)", "Honeypot contract generation"),
        # Generic
        (r"(?:generate|write|create|provide|build|code)\s+(?:a\s+)?(?:the\s+)?(?:functional|working|complete|full|exact)\s+(?:exploit|attack|hack|malicious)\s+(?:contract|code|script|payload|poc)", "Explicit exploit code generation"),
        (r"(?:proof[- ]of[- ]concept|PoC|poc)\s+(?:exploit|attack|for\s+(?:the|a)\s+(?:vulnerability|bug|hack))", "PoC exploit generation"),
    ]

    # ── High-confidence DeFi target indicators ───────────────────────────
    DEFI_TARGETS: List[str] = [
        r"\b(?:The\s+)?DAO\b", r"\bPoly\s*Network\b", r"\bWormhole\b",
        r"\bEuler\s*Finance\b", r"\bRonin\b", r"\bNomad\b",
        r"\bBybit\b", r"\bKelp\s*DAO\b", r"\bBeanstalk\b",
        r"\bCream\s*Finance\b", r"\bHarvest\s*Finance\b",
        r"\bPancake\s*Bunny\b", r"\bBadger\s*DAO\b",
        r"\bMango\s*Markets\b", r"\bWintermute\b",
        r"\bEthCrossChainManager\b", r"\bFlashLoanSimpleReceiver\b",
        r"\bGnosis\s*Safe\b", r"\bSafe\s*\{?Core\}?\b",
        r"\bMetaMask\b", r"\bOpenSea\b", r"\bUniswap\b",
    ]

    def __init__(self):
        self._frame_patterns = [re.compile(p, re.IGNORECASE) for p in self.FRAME_PATTERNS]
        self._intent_patterns = [
            (re.compile(p, re.IGNORECASE), desc)
            for p, desc in self.EXPLOIT_INTENT_PATTERNS
        ]
        self._target_patterns = [re.compile(p, re.IGNORECASE) for p in self.DEFI_TARGETS]

    def strip_framing(self, text: str) -> str:
        """Remove academic/educational/CTF framing from the prompt."""
        stripped = text
        for pattern in self._frame_patterns:
            stripped = pattern.sub("", stripped)
        # Clean up leftover punctuation and whitespace
        stripped = re.sub(r"^\s*[,.:;—-]+\s*", "", stripped.strip())
        return stripped.strip() if len(stripped.strip()) > 5 else text

    def detect_exploit_intent(self, text: str) -> Tuple[bool, str]:
        """Check stripped text for DeFi exploit generation intent."""
        for pattern, description in self._intent_patterns:
            if pattern.search(text):
                return True, description
        return False, ""

    def detect_defi_target(self, text: str) -> Tuple[bool, str]:
        """Check if the text references a known DeFi exploit target."""
        for pattern in self._target_patterns:
            match = pattern.search(text)
            if match:
                return True, f"References known DeFi target: {match.group()}"
        return False, ""

    def analyze(self, user_message: str) -> Tuple[bool, str]:
        """
        Full analysis pipeline.
        Returns (should_block, reason).
        """
        # Stage 1: Strip framing
        stripped = self.strip_framing(user_message)

        # Stage 2: Check for exploit intent on BOTH original and stripped
        has_intent, intent_reason = self.detect_exploit_intent(stripped)
        has_target, target_reason = self.detect_defi_target(user_message)

        if has_intent and has_target:
            return True, f"DeFi exploit generation blocked: {intent_reason} | {target_reason}"

        if has_intent:
            # Check if framing was stripped (means they were trying to hide it)
            was_framed = len(stripped) < len(user_message) - 20
            if was_framed:
                return True, f"Framed exploit request blocked: {intent_reason} (educational framing stripped)"
            return True, f"DeFi exploit intent detected: {intent_reason}"

        return False, ""
