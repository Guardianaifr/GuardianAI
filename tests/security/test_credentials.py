"""
Tests for the CredentialIssuer — W3C Verifiable Credential issuance and verification.
"""

import json
import time
import pytest

from guardian.passport.credentials import (
    CredentialIssuer,
    CredentialType,
    VerifiableCredential,
    CREDENTIAL_DESCRIPTIONS,
)


@pytest.fixture
def issuer():
    """Create a CredentialIssuer for testing."""
    return CredentialIssuer()


class TestCredentialIssuer:
    def test_issue_credential(self, issuer):
        """Issue a credential and verify structure."""
        cred = issuer.issue_credential(
            agent_id="agent-1",
            credential_type=CredentialType.SECURITY_AUDIT,
            claims={"score": 85},
        )
        assert isinstance(cred, VerifiableCredential)
        assert cred.id.startswith("urn:uuid:")
        assert "VerifiableCredential" in cred.type
        assert CredentialType.SECURITY_AUDIT.value in cred.type
        assert cred.credentialSubject["agent_id"] == "agent-1"
        assert cred.credentialSubject["score"] == 85
        assert cred.proof is not None
        assert cred.proof["type"] == "Ed25519Signature2020"

    def test_verify_credential_valid(self, issuer):
        """Valid credential passes verification."""
        cred = issuer.issue_credential("agent-1", CredentialType.PII_COMPLIANT)
        assert issuer.verify_credential(cred) is True

    def test_verify_credential_tampered(self, issuer):
        """Modified credential fails verification."""
        cred = issuer.issue_credential("agent-1", CredentialType.PII_COMPLIANT)
        # Tamper with the credential subject
        cred.credentialSubject["agent_id"] = "hacked-agent"
        assert issuer.verify_credential(cred) is False

    def test_verify_credential_dict(self, issuer):
        """Verify credential passed as a dict."""
        cred = issuer.issue_credential("agent-1", CredentialType.SECURITY_AUDIT)
        cred_dict = cred.to_dict()
        assert issuer.verify_credential(cred_dict) is True

    def test_verify_credential_tampered_dict(self, issuer):
        """Tampered dict credential fails."""
        cred = issuer.issue_credential("agent-1", CredentialType.SECURITY_AUDIT)
        cred_dict = cred.to_dict()
        cred_dict["credentialSubject"]["agent_id"] = "evil-agent"
        assert issuer.verify_credential(cred_dict) is False

    def test_all_credential_types(self, issuer):
        """Issue each of the 6 credential types."""
        for ct in CredentialType:
            cred = issuer.issue_credential("agent-1", ct)
            assert ct.value in cred.type
            assert issuer.verify_credential(cred) is True

    def test_credential_json_ld_format(self, issuer):
        """Verify W3C VC JSON-LD format compliance."""
        cred = issuer.issue_credential("agent-1", CredentialType.SECURITY_AUDIT)
        cred_dict = cred.to_dict()

        # W3C VC required fields
        assert "@context" in cred_dict
        assert "https://www.w3.org/2018/credentials/v1" in cred_dict["@context"]
        assert "id" in cred_dict
        assert "type" in cred_dict
        assert "issuer" in cred_dict
        assert "issuanceDate" in cred_dict
        assert "credentialSubject" in cred_dict
        assert "proof" in cred_dict

    def test_credential_subject_fields(self, issuer):
        """Verify subject contains agent_id and claims."""
        claims = {"audit_score": 92, "pillars_passed": 6}
        cred = issuer.issue_credential("agent-1", CredentialType.SECURITY_AUDIT, claims=claims)
        subject = cred.credentialSubject
        assert subject["agent_id"] == "agent-1"
        assert subject["audit_score"] == 92
        assert subject["pillars_passed"] == 6
        assert subject["id"] == "did:guardian:agent-1"

    def test_public_key_consistency(self, issuer):
        """Same issuer always returns same public key."""
        key1 = issuer.get_public_key_hex()
        key2 = issuer.get_public_key_hex()
        assert key1 == key2
        assert len(key1) > 0

    def test_credential_has_description(self, issuer):
        """Credential subject includes description from type."""
        cred = issuer.issue_credential("agent-1", CredentialType.PII_COMPLIANT)
        assert "description" in cred.credentialSubject
        assert cred.credentialSubject["description"] == CREDENTIAL_DESCRIPTIONS[CredentialType.PII_COMPLIANT]

    def test_credential_to_json(self, issuer):
        """to_json produces valid JSON."""
        cred = issuer.issue_credential("agent-1", CredentialType.SECURITY_AUDIT)
        json_str = cred.to_json()
        parsed = json.loads(json_str)
        assert parsed["credentialSubject"]["agent_id"] == "agent-1"

    def test_no_proof_fails_verification(self, issuer):
        """Credential with no proof fails verification."""
        cred = issuer.issue_credential("agent-1", CredentialType.SECURITY_AUDIT)
        cred.proof = {}
        assert issuer.verify_credential(cred) is False

    def test_string_credential_type(self, issuer):
        """Issue with string type instead of enum."""
        cred = issuer.issue_credential("agent-1", "GuardianAI:SecurityAudit")
        assert "GuardianAI:SecurityAudit" in cred.type
        assert issuer.verify_credential(cred) is True

    def test_issuer_did_format(self, issuer):
        """Issuer field is a proper DID."""
        cred = issuer.issue_credential("agent-1", CredentialType.SECURITY_AUDIT)
        assert cred.issuer.startswith("did:guardian:issuer:")
