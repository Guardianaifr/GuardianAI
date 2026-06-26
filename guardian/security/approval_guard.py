from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Dict, List


MAX_UINT256_DECIMAL = "115792089237316195423570985008687907853269984665640564039457584007913129639935"


@dataclass
class ApprovalGuardDecision:
    suspicious: bool
    score: float
    reasons: List[str]
    matched_spenders: List[str]


class ApprovalGuard:
    def __init__(self, known_drainers: List[str] | None = None, trusted_spenders: List[str] | None = None):
        self.known_drainers = {a.lower() for a in (known_drainers or [])}
        self.trusted_spenders = {a.lower() for a in (trusted_spenders or [])}

        self._approve_patterns = [
            re.compile(
                r"approve\s*\(\s*(0x[a-fA-F0-9]{40})\s*,\s*(?:type\s*\(\s*uint256\s*\)\s*\.\s*max|max_uint256|"
                + re.escape(MAX_UINT256_DECIMAL)
                + r")\s*\)",
                re.IGNORECASE,
            ),
            re.compile(r"(infinite|unlimited|max)\s+approval", re.IGNORECASE),
            re.compile(r"revoke\s+and\s+re-approve", re.IGNORECASE),
            re.compile(r"approve\s+contract\s+to\s+continue", re.IGNORECASE),
        ]

    def evaluate(self, text: str) -> ApprovalGuardDecision:
        prompt = text or ""
        lowered = prompt.lower()
        score = 0.0
        reasons: List[str] = []
        matched_spenders: List[str] = []

        for pattern in self._approve_patterns:
            m = pattern.search(prompt)
            if not m:
                continue
            pattern_score = 0.25
            if m.groups():
                # Explicit spender + max approval is high-risk on its own.
                pattern_score = 0.45
            elif "approval" in pattern.pattern:
                pattern_score = 0.30
            score += pattern_score
            reasons.append(pattern.pattern)
            if m.groups():
                spender = m.group(1).lower()
                matched_spenders.append(spender)

        for spender in matched_spenders:
            if spender in self.known_drainers:
                score += 0.45
                reasons.append("known_drainer_spender")
            elif self.trusted_spenders and spender not in self.trusted_spenders:
                score += 0.20
                reasons.append("unknown_spender")

        if "permit(" in lowered and "deadline" not in lowered:
            score += 0.25
            reasons.append("permit_missing_deadline_signal")

        score = min(1.0, score)
        return ApprovalGuardDecision(
            suspicious=score >= 0.45,
            score=score,
            reasons=reasons,
            matched_spenders=matched_spenders,
        )
