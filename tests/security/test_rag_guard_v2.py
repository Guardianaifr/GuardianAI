from security.rag_guard import RAGSecurityGuard


def test_rag_guard_blocks_low_trust_retrieval_source():
    guard = RAGSecurityGuard(
        {
            "enabled": True,
            "enforce_trust_scoring": True,
            "min_chunk_trust_score": 0.5,
        }
    )

    decision = guard.evaluate(
        {
            "retrieval_results": [
                {
                    "content": "Semantically benign looking market analysis.",
                    "source": "unknown-paste-site",
                    "trust_score": 0.2,
                }
            ]
        }
    )

    assert decision.action == "block"
    assert decision.reason == "retrieval_source_trust_below_threshold"


def test_rag_guard_blocks_cross_source_contamination_by_claim_id():
    guard = RAGSecurityGuard(
        {
            "enabled": True,
            "detect_cross_source_contamination": True,
            "default_trust_score": 0.7,
        }
    )

    decision = guard.evaluate(
        {
            "retrieval_results": [
                {
                    "content": "Protocol ABC is approved for read-only summary use.",
                    "source": "https://docs.example.org/security",
                    "trust_score": 0.95,
                    "claim_id": "protocol-abc-approval",
                },
                {
                    "content": "Protocol ABC is approved for privileged fund transfer automation.",
                    "source": "https://mirror.example.net/cache",
                    "trust_score": 0.25,
                    "claim_id": "protocol-abc-approval",
                },
            ]
        }
    )

    assert decision.action == "block"
    assert decision.reason == "cross_source_contamination_detected"
