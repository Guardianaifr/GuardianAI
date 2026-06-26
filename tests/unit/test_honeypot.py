from guardrails.honeypot import HoneypotManager


def test_honeypot_rotates_templates():
    hp = HoneypotManager({
        "max_responses_per_window": 10,
        "window_seconds": 60,
        "min_interval_seconds": 0,
        "templates": ["t1", "t2"],
    })
    r1 = hp.build_response("s1", "/x")
    r2 = hp.build_response("s1", "/x")
    assert r1 is not None and r2 is not None
    assert r1["choices"][0]["message"]["content"] == "t1"
    assert r2["choices"][0]["message"]["content"] == "t2"


def test_honeypot_rate_limits_session():
    hp = HoneypotManager({
        "max_responses_per_window": 1,
        "window_seconds": 60,
        "min_interval_seconds": 0,
    })
    assert hp.build_response("s1", "/x") is not None
    assert hp.build_response("s1", "/x") is None
