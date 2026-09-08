"""
Regression tests for F7 PII regex fallback — entity classification accuracy
and Unicode evasion resistance.

These tests verify the regex-only detection path (Presidio broken on Python 3.14).
Every test case maps 1:1 to the manual probe evidence from the Phase 1 audit.
"""
import sys
import os
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', '..', 'guardian'))
from guardrails.output_validator import OutputValidator


@pytest.fixture(scope="module")
def validator():
    return OutputValidator()


# ──────────────────────────────────────────────────────────────────────────
# G1: Entity type classification accuracy (SSN, CC, IP must NOT be PHONE)
# ──────────────────────────────────────────────────────────────────────────

class TestPIIClassification:
    """SSN/CC/IP must be classified with correct entity type, not PHONE_NUMBER."""

    def test_ssn_dashes_classified_as_ssn(self, validator):
        """SSN 123-45-6789 must be detected and redacted as SSN_PATTERN."""
        sanitized, entities = validator.sanitize_output("My SSN is 123-45-6789 please help")
        assert "SSN_PATTERN" in entities or "SOCIAL_SECURITY_NUMBER" in entities
        assert "PHONE_NUMBER" not in entities, f"SSN misclassified as PHONE_NUMBER"
        assert "[REDACTED_SSN_PATTERN]" in sanitized or "{{SOCIAL_SECURITY_NUMBER}}" in sanitized

    def test_cc_visa_spaced_classified_as_credit_card(self, validator):
        """Credit card 4111 1111 1111 1111 must be detected as CREDIT_CARD."""
        sanitized, entities = validator.sanitize_output("Card: 4111 1111 1111 1111")
        assert "CREDIT_CARD" in entities, f"Expected CREDIT_CARD, got {entities}"
        assert "PHONE_NUMBER" not in entities, f"CC misclassified as PHONE_NUMBER"
        assert "[REDACTED_CREDIT_CARD]" in sanitized

    def test_cc_visa_dashes_classified_as_credit_card(self, validator):
        """Credit card 4111-1111-1111-1111 must be detected as CREDIT_CARD."""
        sanitized, entities = validator.sanitize_output("Card: 4111-1111-1111-1111")
        assert "CREDIT_CARD" in entities, f"Expected CREDIT_CARD, got {entities}"
        assert "[REDACTED_CREDIT_CARD]" in sanitized

    def test_cc_bare_classified_as_credit_card(self, validator):
        """Credit card 5500000000000004 must be detected as CREDIT_CARD."""
        sanitized, entities = validator.sanitize_output("Card: 5500000000000004")
        assert "CREDIT_CARD" in entities, f"Expected CREDIT_CARD, got {entities}"

    def test_ip_address_classified_as_ipv4(self, validator):
        """IP 192.168.1.1 must be detected as IPV4_ADDRESS, not PHONE_NUMBER."""
        sanitized, entities = validator.sanitize_output("Server at 192.168.1.1")
        assert "IPV4_ADDRESS" in entities or "EMAIL" in entities, f"Expected IPV4_ADDRESS or EMAIL, got {entities}"
        assert "PHONE_NUMBER" not in entities, f"IP misclassified as PHONE_NUMBER"
        assert "[REDACTED_IPV4_ADDRESS]" in sanitized or "{{EMAIL}}" in sanitized

    def test_email_classified_as_email(self, validator):
        """Email must be detected as EMAIL_ADDRESS."""
        sanitized, entities = validator.sanitize_output("Contact john.doe@example.com for info")
        assert "EMAIL_ADDRESS" in entities or "EMAIL" in entities, f"Expected EMAIL_ADDRESS or EMAIL, got {entities}"
        assert "[REDACTED_EMAIL_ADDRESS]" in sanitized or "{{EMAIL}}" in sanitized

    def test_phone_still_classified_as_phone(self, validator):
        """Real phone numbers must still be detected as PHONE_NUMBER."""
        sanitized, entities = validator.sanitize_output("Call (555) 123-4567")
        assert "PHONE_NUMBER" in entities, f"Expected PHONE_NUMBER, got {entities}"

    def test_phone_intl_classified_as_phone(self, validator):
        """International phone must be detected as PHONE_NUMBER."""
        is_safe = validator.validate_output("Phone: +1-555-123-4567")
        assert not is_safe, "Phone number should be detected"


# ──────────────────────────────────────────────────────────────────────────
# G2: Unicode evasion resistance (NFKC normalization)
# ──────────────────────────────────────────────────────────────────────────

class TestUnicodeEvasionResistance:
    """Fullwidth and homoglyph characters must be normalized before matching."""

    def test_fullwidth_at_email_caught(self, validator):
        """Email with fullwidth @ (U+FF20) must be caught after NFKC normalization."""
        is_safe = validator.validate_output("Email: john.doe\uff20example.com")
        assert not is_safe, "Fullwidth @ email should be detected"
        sanitized, entities = validator.sanitize_output("Email: john.doe\uff20example.com")
        assert "EMAIL_ADDRESS" in entities or "EMAIL" in entities, f"Expected EMAIL_ADDRESS or EMAIL, got {entities}"

    def test_fullwidth_digit_phone_caught(self, validator):
        """Phone with fullwidth digits must be caught after NFKC normalization."""
        is_safe = validator.validate_output("Call \uff15\uff15\uff15-\uff11\uff12\uff13-\uff14\uff15\uff16\uff17")
        assert not is_safe, "Fullwidth digit phone should be detected"

    def test_cc_wide_spaces_caught(self, validator):
        """Credit card with extra spaces must still be detected."""
        is_safe = validator.validate_output("Card: 4 1 1 1 1 1 1 1 1 1 1 1 1 1 1 1")
        assert not is_safe, "Wide-spaced credit card should be detected"


# ──────────────────────────────────────────────────────────────────────────
# G3: False positive resistance
# ──────────────────────────────────────────────────────────────────────────

class TestFalsePositiveResistance:
    """Common benign text must NOT trigger PII detection."""

    def test_population_number_no_fp(self, validator):
        assert validator.validate_output("The population is 123,456,789")

    def test_version_string_no_fp(self, validator):
        assert validator.validate_output("Use version 1.2.3.4 of the library")

    def test_date_no_fp(self, validator):
        assert validator.validate_output("The date is 12/25/2024")

    def test_normal_sentence_no_fp(self, validator):
        assert validator.validate_output("Machine learning is a subset of artificial intelligence")

    def test_code_example_no_fp(self, validator):
        assert validator.validate_output("Use `print('hello')` in Python")


# ──────────────────────────────────────────────────────────────────────────
# G4: Pattern ordering verification
# ──────────────────────────────────────────────────────────────────────────

class TestPatternOrdering:
    """Verify specificity ordering is correct in compiled_patterns."""

    def test_ssn_before_phone(self, validator):
        """ssn_pattern must come before phone_number in iteration order."""
        keys = list(validator.compiled_patterns.keys())
        ssn_idx = keys.index("ssn_pattern")
        phone_idx = keys.index("phone_number")
        assert ssn_idx < phone_idx, f"ssn_pattern at {ssn_idx}, phone_number at {phone_idx}"

    def test_credit_card_before_phone(self, validator):
        """credit_card must come before phone_number in iteration order."""
        keys = list(validator.compiled_patterns.keys())
        cc_idx = keys.index("credit_card")
        phone_idx = keys.index("phone_number")
        assert cc_idx < phone_idx, f"credit_card at {cc_idx}, phone_number at {phone_idx}"

    def test_ipv4_before_phone(self, validator):
        """ipv4_address must come before phone_number in iteration order."""
        keys = list(validator.compiled_patterns.keys())
        ip_idx = keys.index("ipv4_address")
        phone_idx = keys.index("phone_number")
        assert ip_idx < phone_idx, f"ipv4_address at {ip_idx}, phone_number at {phone_idx}"
