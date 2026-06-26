"""
Passport Verification — Cross-agent trust verification protocol.

Verifies passport validity, credential integrity, and supports
agent-to-agent mutual verification for the agentic economy.
"""

from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

from guardian.passport.passport_core import PassportEngine, AgentPassport
from guardian.passport.credentials import CredentialIssuer, VerifiableCredential

logger = logging.getLogger("guardian.passport.verification")


@dataclass
class VerificationResult:
    """Result of a passport verification check."""

    verified: bool
    agent_id: str = ""
    passport_id: str = ""
    trust_score: float = 0.0
    tier: str = "UNVERIFIED"
    credentials_count: int = 0
    credentials_valid: int = 0
    last_updated: float = 0.0
    is_active: bool = False
    errors: List[str] = field(default_factory=list)
    warnings: List[str] = field(default_factory=list)
    verified_at: float = 0.0

    def to_dict(self) -> Dict:
        return asdict(self)


class PassportVerifier:
    """
    Verifies AI Agent Passports and their credentials.

    Supports:
      - Single-agent verification (check passport + credentials)
      - Cross-agent mutual verification (agent A verifies agent B)
      - Credential signature validation
      - Trust score freshness checks
    """

    FRESHNESS_THRESHOLD = 7 * 86400  # Score older than 7 days triggers warning

    def __init__(
        self,
        passport_engine: PassportEngine,
        credential_issuer: CredentialIssuer,
    ):
        self.engine = passport_engine
        self.issuer = credential_issuer

    def verify_passport(self, agent_id: str) -> VerificationResult:
        """
        Verify an agent's passport: existence, active status, score freshness,
        and credential signature validity.
        """
        now = time.time()
        errors: List[str] = []
        warnings: List[str] = []

        passport = self.engine.get_passport(agent_id)
        if passport is None:
            return VerificationResult(
                verified=False,
                agent_id=agent_id,
                errors=["Passport not found for agent"],
                verified_at=now,
            )

        if not passport.is_active:
            return VerificationResult(
                verified=False,
                agent_id=agent_id,
                passport_id=passport.passport_id,
                trust_score=passport.trust_score,
                tier=passport.tier,
                is_active=False,
                errors=["Passport has been revoked"],
                verified_at=now,
            )

        # Check score freshness
        score_age = now - passport.updated_at
        if score_age > self.FRESHNESS_THRESHOLD:
            warnings.append(
                f"Trust score is {score_age / 86400:.1f} days old; may be stale"
            )

        # Verify embedded credentials
        valid_creds = 0
        for cred_data in passport.credentials:
            if self._verify_credential_data(cred_data):
                valid_creds += 1
            else:
                warnings.append(
                    f"Credential {cred_data.get('type', 'unknown')} failed verification"
                )

        verified = len(errors) == 0
        return VerificationResult(
            verified=verified,
            agent_id=agent_id,
            passport_id=passport.passport_id,
            trust_score=passport.trust_score,
            tier=passport.tier,
            credentials_count=len(passport.credentials),
            credentials_valid=valid_creds,
            last_updated=passport.updated_at,
            is_active=passport.is_active,
            errors=errors,
            warnings=warnings,
            verified_at=now,
        )

    def verify_credential(self, credential_data: Dict) -> bool:
        """Verify a single credential's signature."""
        return self._verify_credential_data(credential_data)

    def cross_verify(
        self, requesting_agent_id: str, target_agent_id: str
    ) -> Dict:
        """
        Cross-agent verification: agent A wants to verify agent B.

        Returns a verification report suitable for the requesting agent
        to make a trust decision.
        """
        now = time.time()

        # Verify the requesting agent has a valid passport too
        requester = self.engine.get_passport(requesting_agent_id)
        if requester is None or not requester.is_active:
            return {
                "verified": False,
                "protocol": "guardian-passport-v1",
                "error": "Requesting agent does not have a valid passport",
                "timestamp": now,
            }

        # Verify the target agent
        target_result = self.verify_passport(target_agent_id)
        target_passport = self.engine.get_passport(target_agent_id)

        response = {
            "protocol": "guardian-passport-v1",
            "verified": target_result.verified,
            "requesting_agent": {
                "agent_id": requesting_agent_id,
                "passport_id": requester.passport_id,
                "trust_score": requester.trust_score,
                "tier": requester.tier,
            },
            "target_agent": {
                "agent_id": target_agent_id,
                "passport_id": target_result.passport_id,
                "trust_score": target_result.trust_score,
                "tier": target_result.tier,
                "credentials_count": target_result.credentials_count,
                "credentials_valid": target_result.credentials_valid,
                "is_active": target_result.is_active,
            },
            "verification": {
                "errors": target_result.errors,
                "warnings": target_result.warnings,
            },
            "recommendation": self._make_recommendation(target_result),
            "timestamp": now,
        }
        return response

    # ── Internal helpers ──────────────────────────────────────

    def _verify_credential_data(self, cred_data: Dict) -> bool:
        """Verify a credential dict's signature."""
        try:
            return self.issuer.verify_credential(cred_data)
        except Exception as exc:
            logger.debug("Credential verification failed: %s", exc)
            return False

    @staticmethod
    def _make_recommendation(result: VerificationResult) -> str:
        """Generate a human-readable trust recommendation."""
        if not result.verified:
            return "DENY — Agent passport is invalid or revoked"
        if result.trust_score >= 90:
            return "TRUST — Diamond-tier agent with excellent security track record"
        if result.trust_score >= 75:
            return "TRUST_WITH_MONITORING — Gold-tier agent, proceed with standard monitoring"
        if result.trust_score >= 50:
            return "PROCEED_WITH_CAUTION — Silver-tier agent, apply enhanced monitoring"
        return "HIGH_RISK — Unverified agent, apply maximum restrictions"
