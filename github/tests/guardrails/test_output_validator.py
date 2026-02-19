"""
Tests for OutputValidator - PII Redaction
"""
import pytest
from guardrails.output_validator import OutputValidator


class TestOutputValidator:
    """Test suite for OutputValidator PII redaction."""

    def test_initialization(self):
        """Test that OutputValidator initializes correctly."""
        validator = OutputValidator()
        assert validator is not None

    def test_email_redaction(self):
        """Test that email addresses are detected and redacted."""
        validator = OutputValidator()
        test_cases = [
            ("Contact me at john.doe@example.com", "john.doe@example.com"),
            ("Email: admin@company.org", "admin@company.org"),
            ("user123@test.co.uk", "user123@test.co.uk"),
        ]
        for text, email in test_cases:
            # Test detection
            is_safe = validator.validate_output(text)
            assert is_safe is False, f"Email not detected in: {text}"
            
            # Test redaction
            sanitized, entities = validator.sanitize_output(text)
            assert email not in sanitized, f"Email not redacted in: {text}"
            assert "EMAIL" in str(entities).upper() or "REDACTED" in sanitized

    def test_phone_number_redaction(self):
        """Test that phone numbers are detected and redacted."""
        validator = OutputValidator()
        test_cases = [
            "Call me at +1-555-123-4567",
            "Phone: (555) 123-4567",
            "Mobile: +44 20 7123 4567",
        ]
        for text in test_cases:
            # Test detection
            is_safe = validator.validate_output(text)
            assert is_safe is False, f"Phone not detected in: {text}"
            
            # Test redaction
            sanitized, entities = validator.sanitize_output(text)
            assert "PHONE" in str(entities).upper() or "REDACTED" in sanitized

    def test_ssn_redaction(self):
        """Test that Social Security Numbers are detected and redacted."""
        validator = OutputValidator()
        test_cases = [
            "SSN: 123-45-6789",
            "Social Security: 987-65-4321",
        ]
        for text in test_cases:
            # Test detection
            is_safe = validator.validate_output(text)
            assert is_safe is False, f"SSN not detected in: {text}"
            
            # Test redaction
            sanitized, entities = validator.sanitize_output(text)
            assert "SSN" in str(entities).upper() or "REDACTED" in sanitized

    def test_credit_card_redaction(self):
        """Test that credit card numbers are detected and redacted."""
        validator = OutputValidator()
        test_cases = [
            "Card: 4532-1234-5678-9010",
            "Visa: 4111 1111 1111 1111",
        ]
        for text in test_cases:
            # Test detection
            is_safe = validator.validate_output(text)
            assert is_safe is False, f"Credit card not detected in: {text}"
            
            # Test redaction
            sanitized, entities = validator.sanitize_output(text)
            assert "CREDIT" in str(entities).upper() or "REDACTED" in sanitized

    def test_api_key_redaction(self):
        """Test that API keys are detected and redacted."""
        validator = OutputValidator()
        test_cases = [
            "API Key: sk-1234567890abcdef1234567890abcdef1234567890abcdef",
            "Token: AKIA1234567890ABCDEF",
        ]
        for text in test_cases:
            # Test detection
            is_safe = validator.validate_output(text)
            assert is_safe is False, f"API key not detected in: {text}"
            
            # Test redaction
            sanitized, entities = validator.sanitize_output(text)
            assert "API" in str(entities).upper() or "AWS" in str(entities).upper() or "REDACTED" in sanitized

    def test_multiple_pii_types(self):
        """Test detection of multiple PII types in one text."""
        validator = OutputValidator()
        text = "Contact John at john@example.com or call +1-555-123-4567"
        
        # Should detect PII
        is_safe = validator.validate_output(text)
        assert is_safe is False, "Multiple PII not detected"
        
        # Should redact PII
        sanitized, entities = validator.sanitize_output(text)
        assert len(entities) > 0, "No entities detected"
        assert "john@example.com" not in sanitized or "REDACTED" in sanitized

    def test_no_pii_passthrough(self):
        """Test that text without PII is marked as safe."""
        validator = OutputValidator()
        clean_texts = [
            "Hello, how are you?",
            "The weather is nice today.",
            "Python is a great programming language.",
        ]
        for text in clean_texts:
            is_safe = validator.validate_output(text)
            assert is_safe is True, f"Clean text flagged as unsafe: {text}"

    def test_partial_pii_patterns(self):
        """Test that partial patterns don't trigger false positives."""
        validator = OutputValidator()
        false_positive_tests = [
            "The year 1234-56-7890 is not an SSN",  # Might trigger, but context matters
            "Version 4.5.3.2 is released",  # Not a credit card
            "Call function at line 555",  # Not a phone number
        ]
        # These should ideally not be redacted, but some might be
        # This test documents current behavior
        for text in false_positive_tests:
            is_safe = validator.validate_output(text)
            print(f"Partial pattern '{text}': {'flagged' if not is_safe else 'passed'}")


class TestOutputValidatorEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_empty_string(self):
        """Test handling of empty strings."""
        validator = OutputValidator()
        is_safe = validator.validate_output("")
        assert is_safe is True, "Empty string should be safe"

    def test_very_long_text(self):
        """Test handling of very long text."""
        validator = OutputValidator()
        long_text = "Hello " * 1000
        is_safe = validator.validate_output(long_text)
        assert is_safe is True, "Long clean text should be safe"

    def test_special_characters(self):
        """Test handling of special characters."""
        validator = OutputValidator()
        special_text = "!@#$%^&*()_+-=[]{}|;:',.<>?/~`"
        is_safe = validator.validate_output(special_text)
        assert is_safe is True, "Special characters should be safe"

    def test_unicode_text(self):
        """Test handling of Unicode characters."""
        validator = OutputValidator()
        unicode_text = "Hello 世界 🌍 Привет"
        is_safe = validator.validate_output(unicode_text)
        assert is_safe is True, "Unicode text should be safe"

    def test_mixed_case_pii(self):
        """Test PII detection with mixed case."""
        validator = OutputValidator()
        text = "Email: JOHN.DOE@EXAMPLE.COM"
        is_safe = validator.validate_output(text)
        # Should still detect email regardless of case
        assert is_safe is False, "Mixed case email should be detected"


class TestOutputValidatorCustomPII:
    """Test custom PII patterns."""

    def test_custom_patterns_if_supported(self):
        """Test if custom PII patterns can be added."""
        validator = OutputValidator()
        
        # Check if validator supports custom patterns
        if hasattr(validator, 'add_custom_pattern'):
            validator.add_custom_pattern('employee_id', r'EMP-\d{6}')
            text = "Employee ID: EMP-123456"
            result = validator.validate(text)
            assert "EMP-123456" not in result or "[EMPLOYEE_ID]" in result
        else:
            # Document that custom patterns are not yet supported
            print("Custom patterns not supported yet")


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
