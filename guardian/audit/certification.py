"""
GuardianAI Certification System.

Generates verifiable cryptographic badges for AI products that pass the
GuardianAI Security Audit with a score of 80 (B+) or higher.
The badge includes an HMAC signature to prove authenticity.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import logging
from datetime import datetime, timezone
from typing import Dict, Any

from guardian.audit.models import ScanMode

logger = logging.getLogger("guardian.audit.certification")


class CertificationEngine:
    """Generates and verifies GuardianAI certification badges."""

    def __init__(self, signing_key: str):
        """
        Args:
            signing_key: Secret key used to generate the HMAC signatures.
                         Must be kept secure on the backend.
        """
        self.signing_key = signing_key.encode("utf-8")

    def generate_badge(
        self,
        target_uri: str,
        score: float,
        grade: str,
        mode: ScanMode,
        report_id: str
    ) -> Dict[str, Any]:
        """
        Generate a cryptographically signed badge if the target qualifies.
        
        Args:
            target_uri: The URI of the audited AI endpoint.
            score: The final GSS score (0.0 to 100.0).
            grade: The letter grade (e.g., 'A', 'B+').
            mode: The scan mode used (must be STANDARD or FULL).
            report_id: The ID of the full audit report.
            
        Returns:
            A dictionary containing the badge data and cryptographic signature.
            
        Raises:
            ValueError: If the score is too low or the scan mode is insufficient.
        """
        if score < 80.0:
            raise ValueError(f"Target does not qualify. Score {score} < 80.0")
        
        if mode not in (ScanMode.STANDARD, ScanMode.FULL):
            raise ValueError("Certification requires at least a STANDARD scan mode.")

        # Construct the badge payload
        issued_at = datetime.now(timezone.utc).isoformat()
        payload = {
            "version": "1.0",
            "issuer": "GuardianAI Security Audit",
            "target": target_uri,
            "score": round(score, 2),
            "grade": grade,
            "scan_mode": mode.value,
            "report_id": report_id,
            "issued_at": issued_at,
        }

        # Canonicalize the payload for signing
        payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        
        # Generate the HMAC-SHA256 signature
        signature = hmac.new(
            self.signing_key,
            payload_str.encode("utf-8"),
            hashlib.sha256
        ).hexdigest()

        # Create the final verifiable badge
        badge = {
            "payload": payload,
            "signature": signature,
            "verification_url": f"https://guardianai.example.com/verify?id={report_id}"
        }
        
        logger.info(f"Generated certification badge for {target_uri} (Score: {score})")
        return badge

    def verify_badge(self, badge_data: Dict[str, Any]) -> bool:
        """
        Verify the authenticity of a provided badge.
        
        Returns True if the signature is valid, False otherwise.
        """
        try:
            payload = badge_data.get("payload", {})
            provided_signature = badge_data.get("signature", "")
            
            payload_str = json.dumps(payload, sort_keys=True, separators=(",", ":"))
            
            expected_signature = hmac.new(
                self.signing_key,
                payload_str.encode("utf-8"),
                hashlib.sha256
            ).hexdigest()
            
            return hmac.compare_digest(expected_signature, provided_signature)
        except Exception as e:
            logger.error(f"Badge verification failed: {e}")
            return False

    def get_badge_svg(self, badge_data: Dict[str, Any]) -> str:
        """Generate an SVG visual representation of the badge."""
        payload = badge_data.get("payload", {})
        grade = payload.get("grade", "N/A")
        
        # Color based on grade
        color = "#28a745" if grade.startswith("A") else "#17a2b8"
        
        svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="220" height="40" viewBox="0 0 220 40">
  <rect width="130" height="40" fill="#2d3748" rx="4" />
  <rect x="130" width="90" height="40" fill="{color}" rx="4" />
  <path d="M130 0h4v40h-4z" fill="{color}"/>
  
  <text x="65" y="25" fill="#ffffff" font-family="Arial, sans-serif" font-size="14" font-weight="bold" text-anchor="middle">
    GuardianAI
  </text>
  <text x="175" y="25" fill="#ffffff" font-family="Arial, sans-serif" font-size="14" font-weight="bold" text-anchor="middle">
    CERT {grade}
  </text>
</svg>"""
        return svg
