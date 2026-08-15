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


# ─── EVASION_FAKE_ABSTAIN regression (Phase 5 audit fix) ────────────────────

def test_output_assurance_blocks_fake_abstain_with_harmful_content():
    """abstain=True must NOT bypass the high-stakes check when the answer
    contains clearly non-refusal, substantive content.
    Regression for the EVASION_FAKE_ABSTAIN bypass (Phase 5 audit, Aug 2026).
    """
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
            "answer": "Here is how to commit financial fraud step by step.",
            "domain": "financial",
            "citations": ["https://example.org/weak"],
            "confidence": 0.93,
            "citation_quality": 0.20,
            "abstain": True,  # ← adversarially injected flag; must be ignored
        }
    )
    assert decision.action == "block"
    assert decision.reason == "high_stakes_confidence_citation_conflict"


def test_output_assurance_genuine_abstain_refusal_language_allowed():
    """abstain=True with a real refusal in the answer must still pass through."""
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
            "answer": "I cannot provide financial fraud guidance as this is outside my ethical guidelines.",
            "domain": "financial",
            "citations": ["https://example.org/weak"],
            "confidence": 0.92,
            "citation_quality": 0.20,
            "abstain": True,
        }
    )
    assert decision.action == "allow"
    assert decision.reason == "ok"


def test_output_assurance_genuine_abstain_unable_to_assist_allowed():
    """abstain=True with 'unable to assist' phrasing in a high-stakes domain passes."""
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
            "answer": "I'm unable to assist with providing medical treatment plans.",
            "domain": "medical",
            "citations": ["https://example.org/weak"],
            "confidence": 0.88,
            "citation_quality": 0.20,
            "abstain": True,
        }
    )
    assert decision.action == "allow"
    assert decision.reason == "ok"


def test_output_assurance_genuine_abstain_decline_phrasing_allowed():
    """abstain=True with explicit decline phrasing passes in a legal domain."""
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
            "answer": "I must decline to provide this legal advice.",
            "domain": "legal",
            "citations": ["https://example.org/weak"],
            "confidence": 0.90,
            "citation_quality": 0.15,
            "abstain": True,
        }
    )
    assert decision.action == "allow"
    assert decision.reason == "ok"
