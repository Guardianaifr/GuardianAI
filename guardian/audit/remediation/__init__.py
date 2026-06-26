"""
GuardianAI Audit — Remediation Modules Package (2026 Standard).

Production-grade defense modules that address each OWASP LLM failure
category discovered during audit scanning. Covers 10 years of historical
crypto/DeFi exploit vectors (2016-2026).

Module Registry:
  - OutputPIIScanner: PII/secrets redaction (LLM06)
  - SystemPromptGuard: System prompt extraction prevention (LLM07)
  - CryptoSecurityGuard: DeFi/Web3 weaponization prevention (CRYPTO)
  - SafetyDisclaimerEnforcer: Context-aware disclaimers (LLM09)
  - IndirectInjectionFilter: Structured data injection (LLM01)
  - ConversationThreatTracker: Multi-turn escalation detection (LLM01)
  - DeFiExploitIntentAnalyzer: Academic framing bypass detection (CRYPTO)
  - MalwareOutputScanner: VBA/PowerShell/reverse shell detection (MALWARE)
  - ExfiltrationScanner: DNS tunneling/credential harvesting (EXFIL)
"""

from guardian.audit.remediation.output_pii_scanner import OutputPIIScanner
from guardian.audit.remediation.system_prompt_guard import SystemPromptGuard
from guardian.audit.remediation.crypto_guard import CryptoSecurityGuard
from guardian.audit.remediation.disclaimer_enforcer import SafetyDisclaimerEnforcer
from guardian.audit.remediation.indirect_injection import (
    IndirectInjectionFilter,
    ConversationThreatTracker,
)
from guardian.audit.remediation.defi_intent_analyzer import DeFiExploitIntentAnalyzer
from guardian.audit.remediation.malware_output_scanner import MalwareOutputScanner
from guardian.audit.remediation.exfiltration_scanner import ExfiltrationScanner

__all__ = [
    "OutputPIIScanner",
    "SystemPromptGuard",
    "CryptoSecurityGuard",
    "SafetyDisclaimerEnforcer",
    "IndirectInjectionFilter",
    "ConversationThreatTracker",
    "DeFiExploitIntentAnalyzer",
    "MalwareOutputScanner",
    "ExfiltrationScanner",
]
