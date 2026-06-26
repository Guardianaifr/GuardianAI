from security.output_assurance import OutputAssuranceGuard


def test_output_assurance_blocks_when_required_fields_missing():
    guard = OutputAssuranceGuard(
        {
            "enabled": True,
            "require_json_output": True,
            "required_json_fields": ["answer", "citations", "confidence"],
        }
    )
    decision = guard.evaluate({"answer": "ok", "confidence": 0.8})
    assert decision.action == "block"
    assert decision.reason == "required_fields_missing"


def test_output_assurance_blocks_on_low_confidence():
    guard = OutputAssuranceGuard(
        {
            "enabled": True,
            "require_json_output": True,
            "required_json_fields": ["answer", "citations", "confidence"],
            "require_citations": True,
            "min_citations": 1,
            "block_on_low_confidence": True,
            "min_confidence": 0.75,
        }
    )
    decision = guard.evaluate(
        {
            "answer": "ok",
            "citations": ["https://example.org/doc"],
            "confidence": 0.51,
        }
    )
    assert decision.action == "block"
    assert decision.reason == "confidence_below_threshold"


def test_output_assurance_allows_valid_structured_output():
    guard = OutputAssuranceGuard(
        {
            "enabled": True,
            "require_json_output": True,
            "required_json_fields": ["answer", "citations", "confidence"],
            "require_citations": True,
            "min_citations": 1,
            "block_on_low_confidence": True,
            "min_confidence": 0.75,
        }
    )
    decision = guard.evaluate(
        {
            "answer": "ok",
            "citations": ["https://example.org/doc"],
            "confidence": 0.92,
        }
    )
    assert decision.action == "allow"
    assert decision.reason == "ok"


def test_output_assurance_blocks_high_stakes_confidence_citation_conflict():
    guard = OutputAssuranceGuard(
        {
            "enabled": True,
            "require_citations": True,
            "min_citations": 1,
            "block_on_low_confidence": True,
            "min_confidence": 0.7,
            "high_stakes_abstain_enabled": True,
            "min_citation_quality": 0.8,
        }
    )
    decision = guard.evaluate(
        {
            "answer": "This financial treatment plan is definitely safe.",
            "domain": "financial",
            "citations": ["https://example.org/forum-post"],
            "confidence": 0.93,
            "citation_quality": 0.25,
        }
    )
    assert decision.action == "block"
    assert decision.reason == "high_stakes_confidence_citation_conflict"


def test_output_assurance_allows_high_stakes_abstain_on_conflict():
    guard = OutputAssuranceGuard(
        {
            "enabled": True,
            "require_citations": True,
            "min_citations": 1,
            "block_on_low_confidence": True,
            "min_confidence": 0.7,
            "high_stakes_abstain_enabled": True,
            "min_citation_quality": 0.8,
        }
    )
    decision = guard.evaluate(
        {
            "answer": "I cannot verify this with enough reliable information.",
            "domain": "medical",
            "citations": ["https://example.org/weak"],
            "confidence": 0.91,
            "citation_quality": 0.2,
            "abstain": True,
        }
    )
    assert decision.action == "allow"
    assert decision.reason == "ok"
