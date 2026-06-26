"""
GuardianAI Agent Passport — Soulbound Trust Identity for AI Agents.

Provides verifiable, on-chain-anchored identity and reputation scoring
for autonomous AI agents in the agentic economy.
"""

from guardian.passport.passport_core import AgentPassport, PassportEngine
from guardian.passport.trust_scorer import TrustScorer, TrustScoreResult
from guardian.passport.credentials import CredentialIssuer, VerifiableCredential, CredentialType
from guardian.passport.verification import PassportVerifier, VerificationResult

__all__ = [
    "AgentPassport",
    "PassportEngine",
    "TrustScorer",
    "TrustScoreResult",
    "CredentialIssuer",
    "VerifiableCredential",
    "CredentialType",
    "PassportVerifier",
    "VerificationResult",
]
