from tools.adversarial_regression_delta import compare_reports


def test_compare_reports_passes_when_deltas_are_within_budget():
    previous = {
        "attack_detection_rate": 0.98,
        "blocked_rate": 0.97,
        "precision": 0.95,
        "recall": 0.96,
        "false_positive_rate": 0.01,
        "false_negative_rate": 0.02,
    }
    current = {
        "attack_detection_rate": 0.975,
        "blocked_rate": 0.966,
        "precision": 0.949,
        "recall": 0.955,
        "false_positive_rate": 0.011,
        "false_negative_rate": 0.021,
    }
    verdict = compare_reports(current, previous, max_regression_pct=2.0)
    assert verdict["passed"] is True
    assert verdict["regressions"] == []


def test_compare_reports_fails_on_significant_regression():
    previous = {
        "attack_detection_rate": 0.98,
        "blocked_rate": 0.97,
        "precision": 0.95,
        "recall": 0.96,
        "false_positive_rate": 0.01,
        "false_negative_rate": 0.02,
    }
    current = {
        "attack_detection_rate": 0.90,
        "blocked_rate": 0.89,
        "precision": 0.88,
        "recall": 0.87,
        "false_positive_rate": 0.05,
        "false_negative_rate": 0.08,
    }
    verdict = compare_reports(current, previous, max_regression_pct=2.0)
    assert verdict["passed"] is False
    assert len(verdict["regressions"]) >= 2
