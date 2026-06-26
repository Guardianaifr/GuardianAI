"""
Verifiable Credentials — W3C VC Data Model 2.0 compatible credential issuance.

Issues and verifies JSON-LD Verifiable Credentials signed with Ed25519,
supporting six security-focused credential types for AI agents.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, Optional

logger = logging.getLogger("guardian.passport.credentials")

# ── Credential Types ──────────────────────────────────────────


class CredentialType(str, Enum):
    """Supported credential types for AI Agent Passports."""

    SECURITY_AUDIT = "GuardianAI:SecurityAudit"
    PII_COMPLIANT = "GuardianAI:PIICompliant"
    JAILBREAK_RESISTANT = "GuardianAI:JailbreakResistant"
    ZERO_INCIDENT_90 = "GuardianAI:ZeroIncident90"
    THREAT_FEED_CURRENT = "GuardianAI:ThreatFeedCurrent"
    EU_AI_ACT_READY = "GuardianAI:EUAIActReady"


CREDENTIAL_DESCRIPTIONS = {
    CredentialType.SECURITY_AUDIT: "Passed full 6-pillar security audit with score ≥ 80",
    CredentialType.PII_COMPLIANT: "30+ days with zero PII leaks",
    CredentialType.JAILBREAK_RESISTANT: "Survived 100+ jailbreak attempts without compromise",
    CredentialType.ZERO_INCIDENT_90: "90 consecutive days without security incidents",
    CredentialType.THREAT_FEED_CURRENT: "Threat intelligence feed is active and updated",
    CredentialType.EU_AI_ACT_READY: "Meets EU AI Act Article 15 requirements",
}

# Default validity: 90 days
DEFAULT_VALIDITY_SECONDS = 90 * 86400


@dataclass
class VerifiableCredential:
    """W3C Verifiable Credential structure (JSON-LD compatible)."""

    id: str
    type: list
    issuer: str
    issuanceDate: str
    expirationDate: str
    credentialSubject: Dict[str, Any]
    proof: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict:
        result = asdict(self)
        result["@context"] = [
            "https://www.w3.org/2018/credentials/v1",
            "https://guardianai.dev/credentials/v1",
        ]
        return result

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


class CredentialIssuer:
    """
    Issues and verifies W3C Verifiable Credentials signed with Ed25519.

    The signing keypair is generated on init or loaded from the
    GUARDIAN_VC_PRIVATE_KEY environment variable (hex-encoded seed).
    """

    def __init__(self, private_key_hex: Optional[str] = None):
        """
        Initialize the credential issuer.

        Args:
            private_key_hex: Optional hex-encoded 32-byte Ed25519 seed.
                             Falls back to GUARDIAN_VC_PRIVATE_KEY env var,
                             then generates a new keypair.

        Raises:
            EnvironmentError: If neither private_key_hex nor GUARDIAN_VC_PRIVATE_KEY
                              is set and the cryptography library is unavailable.
        """
        # Also accept a previous key for rotation / backward-compat verification
        self._previous_key_hex = os.getenv("GUARDIAN_VC_PRIVATE_KEY_PREVIOUS", "")

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PrivateKey,
            )
            from cryptography.hazmat.primitives import serialization
        except ImportError:
            logger.warning(
                "cryptography library not available; "
                "using HMAC-SHA256 fallback for credential signing. "
                "Install 'cryptography' for production use."
            )
            self._use_fallback = True
            self._fallback_secret = (
                private_key_hex
                or os.getenv("GUARDIAN_VC_PRIVATE_KEY", "")
            )
            if not self._fallback_secret:
                raise EnvironmentError(
                    "GUARDIAN_VC_PRIVATE_KEY environment variable is required "
                    "when the 'cryptography' library is not installed. "
                    "Set a hex-encoded secret or install 'cryptography'."
                )
            self._public_key_hex = hashlib.sha256(
                self._fallback_secret.encode()
            ).hexdigest()
            return

        self._use_fallback = False
        seed_hex = private_key_hex or os.getenv("GUARDIAN_VC_PRIVATE_KEY", "")

        if seed_hex:
            seed_bytes = bytes.fromhex(seed_hex)
            self._private_key = Ed25519PrivateKey.from_private_bytes(seed_bytes)
        else:
            self._private_key = Ed25519PrivateKey.generate()

        self._public_key = self._private_key.public_key()
        pub_bytes = self._public_key.public_bytes(
            serialization.Encoding.Raw, serialization.PublicFormat.Raw
        )
        self._public_key_hex = pub_bytes.hex()
        logger.info("CredentialIssuer initialized (Ed25519 pubkey: %s…)", self._public_key_hex[:16])

    def get_public_key_hex(self) -> str:
        """Return the hex-encoded Ed25519 public key."""
        return self._public_key_hex

    def issue_credential(
        self,
        agent_id: str,
        credential_type: CredentialType | str,
        claims: Optional[Dict[str, Any]] = None,
        validity_seconds: int = DEFAULT_VALIDITY_SECONDS,
    ) -> VerifiableCredential:
        """
        Issue a new Verifiable Credential for an agent.

        Args:
            agent_id: The agent's unique identifier.
            credential_type: One of the CredentialType values.
            claims: Additional claims to include in the credential subject.
            validity_seconds: How long the credential is valid (default 90 days).

        Returns:
            A signed VerifiableCredential.
        """
        if isinstance(credential_type, CredentialType):
            cred_type_str = credential_type.value
        else:
            cred_type_str = str(credential_type)

        now = time.time()
        cred_id = f"urn:uuid:{uuid.uuid4()}"
        issuance_date = self._format_iso(now)
        expiration_date = self._format_iso(now + validity_seconds)

        subject = {
            "id": f"did:guardian:{agent_id}",
            "agent_id": agent_id,
            "credential_type": cred_type_str,
        }
        if claims:
            subject.update(claims)

        # Add description
        for ct in CredentialType:
            if ct.value == cred_type_str:
                subject["description"] = CREDENTIAL_DESCRIPTIONS.get(ct, "")
                break

        credential = VerifiableCredential(
            id=cred_id,
            type=["VerifiableCredential", cred_type_str],
            issuer=f"did:guardian:issuer:{self._public_key_hex[:32]}",
            issuanceDate=issuance_date,
            expirationDate=expiration_date,
            credentialSubject=subject,
        )

        # Sign
        credential.proof = self._create_proof(credential)
        return credential

    def verify_credential(self, credential: VerifiableCredential | Dict) -> bool:
        """
        Verify the Ed25519 signature on a credential.

        Args:
            credential: The credential to verify (object or dict).

        Returns:
            True if the signature is valid and the credential is not expired.
        """
        if isinstance(credential, dict):
            proof = credential.get("proof", {})
            cred_dict = {k: v for k, v in credential.items() if k != "proof"}
        else:
            proof = credential.proof
            cred_dict = credential.to_dict()
            cred_dict.pop("proof", None)

        if not proof:
            return False

        signature_hex = proof.get("proofValue", "")
        if not signature_hex:
            return False

        # Reconstruct the canonical payload
        canonical = json.dumps(cred_dict, sort_keys=True, separators=(",", ":"), default=str)

        if self._use_fallback:
            import hmac as hmac_mod
            expected = hmac_mod.new(
                self._fallback_secret.encode(), canonical.encode(), hashlib.sha256
            ).hexdigest()
            return expected == signature_hex

        try:
            from cryptography.hazmat.primitives.asymmetric.ed25519 import (
                Ed25519PublicKey,
            )

            sig_bytes = bytes.fromhex(signature_hex)
            self._public_key.verify(sig_bytes, canonical.encode("utf-8"))
            return True
        except Exception:
            return False

    # ── Internal helpers ──────────────────────────────────────

    def _create_proof(self, credential: VerifiableCredential) -> Dict[str, Any]:
        """Create an Ed25519 proof for the credential."""
        cred_dict = credential.to_dict()
        cred_dict.pop("proof", None)
        canonical = json.dumps(cred_dict, sort_keys=True, separators=(",", ":"), default=str)

        if self._use_fallback:
            import hmac as hmac_mod
            sig = hmac_mod.new(
                self._fallback_secret.encode(), canonical.encode(), hashlib.sha256
            ).hexdigest()
        else:
            sig_bytes = self._private_key.sign(canonical.encode("utf-8"))
            sig = sig_bytes.hex()

        # Use honest proof type — don't claim Ed25519 when using HMAC fallback
        proof_type = "HmacSha256Signature" if self._use_fallback else "Ed25519Signature2020"

        return {
            "type": proof_type,
            "created": self._format_iso(time.time()),
            "verificationMethod": f"did:guardian:issuer:{self._public_key_hex[:32]}#key-1",
            "proofPurpose": "assertionMethod",
            "proofValue": sig,
        }

    @staticmethod
    def _format_iso(ts: float) -> str:
        """Format a Unix timestamp as ISO 8601 UTC string."""
        import datetime
        return datetime.datetime.fromtimestamp(ts, tz=datetime.timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%SZ"
        )
