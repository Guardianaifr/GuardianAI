from guardrails.output_validator import OutputValidator


def test_obfuscated_openai_key_is_blocked_and_redacted():
    validator = OutputValidator()
    content = (
        "Retrieved chunk contains key: "
        "s k - a b c d e f 1 2 3 4 g h i j 5 6 7 8 k l m n 9 0 p q r s t u"
    )

    assert validator.validate_output(content) is False
    sanitized, entities = validator.sanitize_output(content)
    assert "s k -" not in sanitized.lower()
    assert "REDACTED" in sanitized
    assert any(entity in entities for entity in ["OPENAI_API_KEY", "GENERIC_SECRET"])
