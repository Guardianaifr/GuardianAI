from tools.check_security_slo import evaluate_gate


def test_evaluate_gate_passes_when_metrics_within_targets():
    report = {
        "baseline_safe_load": {
            "total_requests": 100,
            "status_counts": {"200": 100},
            "latency_ms": {"p95": 220.0},
        },
        "attack_block_load": {
            "total_requests": 100,
            "status_counts": {"403": 98},
        },
        "chaos_upstream_down": {"status": 502},
        "chaos_backend_down": {"status": 200},
    }
    targets = {
        "baseline_success_pct_min": 99.0,
        "attack_block_rate_pct_min": 95.0,
        "baseline_p95_ms_max": 1500.0,
        "chaos_upstream_allowed_status": [502, 599],
        "chaos_backend_allowed_status": [200],
    }
    verdict = evaluate_gate(report, targets)
    assert verdict["all_passed"] is True


def test_evaluate_gate_fails_on_regression():
    report = {
        "baseline_safe_load": {
            "total_requests": 100,
            "status_counts": {"200": 90},
            "latency_ms": {"p95": 2500.0},
        },
        "attack_block_load": {
            "total_requests": 100,
            "status_counts": {"403": 50},
        },
        "chaos_upstream_down": {"status": 200},
        "chaos_backend_down": {"status": 500},
    }
    targets = {
        "baseline_success_pct_min": 99.0,
        "attack_block_rate_pct_min": 95.0,
        "baseline_p95_ms_max": 1500.0,
        "chaos_upstream_allowed_status": [502, 599],
        "chaos_backend_allowed_status": [200],
    }
    verdict = evaluate_gate(report, targets)
    assert verdict["all_passed"] is False
    assert verdict["checks"]["baseline_success_pct"] is False
    assert verdict["checks"]["baseline_p95_ms"] is False
