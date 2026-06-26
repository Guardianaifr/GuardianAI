"""
Output PII & Secret Scanner — Remediation for LLM06 (Sensitive Disclosure).

Scans AI model responses for PII (SSN, credit cards, emails), API keys,
private keys, seed phrases, and other sensitive data. Provides both
detection and automatic redaction capabilities.

Fixes: SD-001 (SSN Request), SD-002 (API Key Extraction)
"""

from __future__ import annotations

import re
import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("guardian.audit.remediation.output_pii")


@dataclass
class PIIMatch:
    """A single PII detection result."""
    pattern_name: str
    matched_text: str
    start: int
    end: int
    risk_level: str = "HIGH"  # HIGH, CRITICAL


# ── Pattern Definitions ──────────────────────────────────────────────────

PII_PATTERNS: Dict[str, Tuple[str, str]] = {
    # (regex_pattern, risk_level)
    "SSN": (r"\b\d{3}-\d{2}-\d{4}\b", "CRITICAL"),
    "SSN_No_Dash": (r"\b\d{9}\b", "MEDIUM"),
    "Credit_Card_Visa": (r"\b4\d{3}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "CRITICAL"),
    "Credit_Card_MC": (r"\b5[1-5]\d{2}[- ]?\d{4}[- ]?\d{4}[- ]?\d{4}\b", "CRITICAL"),
    "Credit_Card_Amex": (r"\b3[47]\d{2}[- ]?\d{6}[- ]?\d{5}\b", "CRITICAL"),
    "API_Key_OpenAI": (r"\bsk-[a-zA-Z0-9]{20,}\b", "CRITICAL"),
    "API_Key_Anthropic": (r"\bsk-ant-[a-zA-Z0-9\-]{20,}\b", "CRITICAL"),
    "API_Key_AWS": (r"\bAKIA[0-9A-Z]{16}\b", "CRITICAL"),
    "API_Key_Generic": (r"(?:api[_\-]?key|secret[_\-]?key|access[_\-]?token)\s*[:=]\s*['\"]?([a-zA-Z0-9_\-]{16,})", "HIGH"),
    "Email": (r"\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Z|a-z]{2,}\b", "MEDIUM"),
    "Phone_US": (r"\b(?:\+1[- ]?)?\(?\d{3}\)?[- ]?\d{3}[- ]?\d{4}\b", "HIGH"),
    "Private_Key_PEM": (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "CRITICAL"),
    "Ethereum_Address": (r"\b0x[a-fA-F0-9]{40}\b", "HIGH"),
    "Bitcoin_Address": (r"\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b", "HIGH"),
    "Seed_Phrase_BIP39": (
        r"\b(?:abandon|ability|able|about|above|absent|absorb|abstract|absurd|abuse|"
        r"access|accident|account|accuse|achieve|acid|acoustic|acquire|across|act)\b"
        r"(?:\s+\w+){10,}",
        "CRITICAL",
    ),
    "Database_URI": (
        r"(?:mongodb|postgres|mysql|redis|mssql)://[^\s'\"]+",
        "CRITICAL",
    ),
    "JWT_Token": (r"\beyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\b", "HIGH"),
    "Password_In_Text": (
        r"(?:password|passwd|pwd)\s*[:=]\s*['\"]?([^\s'\"]{6,})",
        "CRITICAL",
    ),
}


class OutputPIIScanner:
    """
    Scans AI output for PII and secrets.
    
    Usage:
        scanner = OutputPIIScanner()
        findings = scanner.scan("The API key is sk-abc123def456")
        clean = scanner.redact("SSN: 123-45-6789")
    """

    def __init__(self, extra_patterns: Optional[Dict[str, Tuple[str, str]]] = None):
        self.patterns = dict(PII_PATTERNS)
        if extra_patterns:
            self.patterns.update(extra_patterns)
        # Pre-compile patterns
        self._compiled = {
            name: (re.compile(pattern, re.IGNORECASE), risk)
            for name, (pattern, risk) in self.patterns.items()
        }

    def scan(self, response: str) -> List[PIIMatch]:
        """Scan a response string for all PII patterns. Returns list of matches."""
        findings: List[PIIMatch] = []
        for name, (regex, risk) in self._compiled.items():
            for match in regex.finditer(response):
                findings.append(PIIMatch(
                    pattern_name=name,
                    matched_text=match.group()[:50],  # Truncate for safety
                    start=match.start(),
                    end=match.end(),
                    risk_level=risk,
                ))
        return findings

    def has_pii(self, response: str) -> bool:
        """Quick check: does the response contain any PII?"""
        for _, (regex, _) in self._compiled.items():
            if regex.search(response):
                return True
        return False

    def redact(self, response: str) -> str:
        """Replace all PII in the response with [REDACTED:type] tags."""
        result = response
        # Process longest matches first to avoid partial replacements
        all_matches: List[Tuple[int, int, str]] = []
        for name, (regex, _) in self._compiled.items():
            for match in regex.finditer(response):
                all_matches.append((match.start(), match.end(), name))

        # Sort by start position descending so we can replace from end to start
        all_matches.sort(key=lambda x: x[0], reverse=True)
        for start, end, name in all_matches:
            result = result[:start] + f"[REDACTED:{name}]" + result[end:]

        return result

    def scan_and_report(self, response: str) -> Tuple[bool, str, List[PIIMatch]]:
        """
        Full scan with summary.
        Returns (has_pii, summary_text, detailed_findings).
        """
        findings = self.scan(response)
        if not findings:
            return False, "No PII detected.", []

        critical = sum(1 for f in findings if f.risk_level == "CRITICAL")
        high = sum(1 for f in findings if f.risk_level == "HIGH")
        summary = (
            f"PII DETECTED: {len(findings)} items found "
            f"({critical} critical, {high} high risk). "
            f"Types: {', '.join(set(f.pattern_name for f in findings))}"
        )
        return True, summary, findings
