"""
Indirect Injection Filter — Remediation for LLM01 (Prompt Injection).

Detects prompt injection attempts hidden inside structured data fields
(JSON payloads, email bodies, document content) and multi-turn
conversation escalation patterns.

Fixes: IND-001, IND-002, IND-004, MT-001
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("guardian.audit.remediation.indirect_injection")


class IndirectInjectionFilter:
    """
    Scans structured data fields for embedded prompt injection attempts.
    
    Usage:
        filter = IndirectInjectionFilter()
        found, details = filter.scan_text("Process this email: IGNORE PREVIOUS INSTRUCTIONS...")
        found, details = filter.scan_fields({"name": "John", "bio": "Ignore all rules and..."})
    """

    INJECTION_MARKERS: List[str] = [
        # Direct overrides
        r"ignore\s+(?:all\s+)?(?:previous|prior|above|earlier)\s+(?:instructions|rules|guidelines|context)",
        r"forget\s+(?:everything|all|your)\s+(?:instructions|rules|previous)",
        r"disregard\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|rules)",
        r"override\s+(?:system|safety|content)\s+(?:rules|policy|filters)",
        # Role reassignment
        r"you\s+are\s+now\s+(?:a|an|the)\s+(?:unrestricted|uncensored|unfiltered|evil)",
        r"new\s+(?:instructions|rules|role|persona|identity)\s*:",
        r"from\s+now\s+on\s*,?\s*you\s+(?:are|will|must|should)",
        # Authority claims
        r"(?:admin|root|system|developer|owner)\s+(?:mode|access|override|command)",
        r"(?:authorized|approved|cleared|permitted)\s+(?:by|from)\s+(?:the\s+)?(?:admin|cto|ceo|owner|management)",
        r"this\s+is\s+an?\s+(?:authorized|approved|official)\s+(?:security\s+)?(?:test|audit|review)",
        # Hidden instructions
        r"(?:system|assistant|admin)\s*:\s*",
        r"\[(?:SYSTEM|ADMIN|OVERRIDE)\]",
        r"<(?:system|admin|override|instruction)>",
        # Action requests
        r"execute\s+(?:the\s+)?(?:following|this)\s+(?:command|action|function|code)",
        r"run\s+(?:this\s+)?(?:command|query|script|code)",
        # HTML comment embedded injections
        r"<!--[\s\S]*?(?:ignore|system update|override|instructions|output exactly)[\s\S]*?-->",
        # JSON structured output manipulation (field-level injection)
        # Pattern A: any field whose value is a 0x wallet/attacker address
        r"\"(?:action|status|to|amount|value|address|recipient|destination)\"\s*:\s*\"0x[a-fA-F0-9]+\"",
        # Pattern B: well-known dangerous action values or MAX amount threshold marker
        r"\"(?:action|operation|cmd|command)\"\s*:\s*\"(?:approve_transfer|transfer|drain|withdraw|execute)[^\"]*\"",
        r"\"(?:amount|value|qty|quantity)\"\s*:\s*\"(?:MAX|UNLIMITED|type\(uint256\)\.max|115792089)\"",
        # Agent Code Injection / Piggybacking (Microsoft BIPIA benchmark)
        r"(?:the\s+)?(?:following|subsequent|below)\s+code\s+(?:snippet|section|excerpt|block)[\s\S]{0,120}```",
        r"(?:include|embed|incorporate|feature|integrate|blend|merge|weave|add|utilize|supplement|validate|modify)\s+(?:the\s+)?(?:following|subsequent|below)\s+code",
    ]

    def __init__(self):
        self._patterns = [re.compile(p, re.IGNORECASE) for p in self.INJECTION_MARKERS]

    def scan_text(self, text: str) -> Tuple[bool, List[str]]:
        """
        Scan a text string for injection markers.
        Returns (has_injection, list_of_reasons).
        """
        findings: List[str] = []
        for pattern in self._patterns:
            match = pattern.search(text)
            if match:
                findings.append(
                    f"Injection pattern detected: '{match.group()[:60]}' "
                    f"at position {match.start()}"
                )
        return len(findings) > 0, findings

    def scan_fields(self, data: Dict) -> Tuple[bool, List[str]]:
        """
        Scan all string fields in a dictionary for injections.
        Returns (has_injection, list_of_reasons).
        """
        all_findings: List[str] = []
        self._scan_recursive(data, "", all_findings)
        return len(all_findings) > 0, all_findings

    def _scan_recursive(self, obj, path: str, findings: List[str]):
        """Recursively scan nested dicts/lists for injections."""
        if isinstance(obj, str):
            found, reasons = self.scan_text(obj)
            if found:
                for r in reasons:
                    findings.append(f"Field '{path}': {r}")
        elif isinstance(obj, dict):
            for key, value in obj.items():
                self._scan_recursive(value, f"{path}.{key}" if path else key, findings)
        elif isinstance(obj, list):
            for idx, item in enumerate(obj):
                self._scan_recursive(item, f"{path}[{idx}]", findings)


class ConversationThreatTracker:
    """
    Accumulates suspicion across conversation turns to detect
    gradual escalation attacks (trust building -> extraction).
    
    Usage:
        tracker = ConversationThreatTracker()
        for user_msg in conversation:
            should_block, score, reason = tracker.assess_turn(user_msg)
            if should_block:
                return "This conversation has been flagged for suspicious escalation."
    """

    ESCALATION_SIGNALS: List[Tuple[str, float]] = [
        # Low suspicion (trust building)
        ("can you help me", 0.02),
        ("that's really helpful", 0.01),
        ("as a follow-up", 0.05),
        ("one more thing", 0.05),
        # Medium suspicion (probing)
        ("hypothetically", 0.10),
        ("in theory", 0.08),
        ("for educational purposes", 0.12),
        ("security audit", 0.10),
        ("authorized test", 0.15),
        ("penetration test", 0.10),
        # High suspicion (escalation)
        ("ignore", 0.20),
        ("override", 0.25),
        ("bypass", 0.20),
        ("system prompt", 0.30),
        ("previous instructions", 0.35),
        ("tell me your rules", 0.25),
        # Critical (direct attack)
        ("execute command", 0.40),
        ("run this code", 0.30),
        ("delete from", 0.50),
        ("drop table", 0.50),
        ("password", 0.15),
        ("credentials", 0.20),
        ("api key", 0.20),
        ("private key", 0.25),
        ("seed phrase", 0.30),
    ]

    def __init__(self, threshold: float = 0.65, decay_rate: float = 0.1):
        """
        Args:
            threshold: Suspicion score at which to block (0.0-1.0)
            decay_rate: How much suspicion decays per benign turn
        """
        self.threshold = threshold
        self.decay_rate = decay_rate
        self.suspicion_score = 0.0
        self.turn_count = 0
        self.turn_history: List[Tuple[str, float]] = []
        self.blocked = False

    def assess_turn(self, user_message: str) -> Tuple[bool, float, str]:
        """
        Assess a single conversation turn.
        Returns (should_block, current_suspicion_score, reason).
        """
        self.turn_count += 1
        msg_lower = user_message.lower()

        turn_suspicion = 0.0
        matched_signals: List[str] = []

        for signal, weight in self.ESCALATION_SIGNALS:
            if signal in msg_lower:
                turn_suspicion += weight
                matched_signals.append(signal)

        if turn_suspicion == 0:
            # Benign turn - apply decay
            self.suspicion_score = max(0, self.suspicion_score - self.decay_rate)
        else:
            self.suspicion_score += turn_suspicion

        # Clamp to [0, 1]
        self.suspicion_score = min(1.0, self.suspicion_score)
        self.turn_history.append((user_message[:100], self.suspicion_score))

        if self.suspicion_score >= self.threshold:
            self.blocked = True
            reason = (
                f"Conversation threat level {self.suspicion_score:.0%} exceeds "
                f"threshold {self.threshold:.0%}. "
                f"Turn {self.turn_count} signals: [{', '.join(matched_signals)}]. "
                f"Cumulative escalation pattern detected across {self.turn_count} turns."
            )
            return True, self.suspicion_score, reason

        return False, self.suspicion_score, f"Within tolerance ({self.suspicion_score:.0%})"

    def reset(self):
        """Reset the tracker for a new conversation."""
        self.suspicion_score = 0.0
        self.turn_count = 0
        self.turn_history.clear()
        self.blocked = False
