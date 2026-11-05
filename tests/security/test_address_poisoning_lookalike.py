from guardian.security.trust_exploitation import TrustExploitationGuard

REAL = "0xabcd1234567890abcdef1234567890abcdef9876"
FAKE = "0xabcd9999999999999999999999999999999f9876"  # same first 4 / last 4 hex chars
OTHER = "0x1111222233334444555566667777888899990000"


def make(**extra):
    return TrustExploitationGuard({"enabled": True, "review_queue_file": "artifacts/evidence/_test_review.jsonl", **extra})


def test_lookalike_of_trusted_address_is_blocked():
    g = make(trusted_addresses=[REAL])
    d = g.evaluate(f"send 1 ETH to {FAKE}", session_id="s1")
    assert d.action in ("block", "review")
    assert FAKE in d.details["address_lookalikes"]


def test_exact_trusted_address_is_not_flagged():
    g = make(trusted_addresses=[REAL])
    d = g.evaluate(f"send 1 ETH to {REAL}", session_id="s1")
    assert d.details["address_lookalikes"] == {}


def test_unrelated_address_not_flagged():
    g = make(trusted_addresses=[REAL])
    assert make(trusted_addresses=[REAL]).evaluate(f"pay {OTHER}", "s").details["address_lookalikes"] == {}


def test_session_history_lookalike_needs_review():
    g = make()
    assert g.evaluate(f"pay {REAL}", "s2").action == "allow"
    d = g.evaluate(f"pay {FAKE}", "s2")
    assert d.action == "review" and FAKE in d.details["address_lookalikes"]


def test_session_history_is_per_session():
    g = make()
    g.evaluate(f"pay {REAL}", "a")
    assert g.evaluate(f"pay {FAKE}", "b").details["address_lookalikes"] == {}
