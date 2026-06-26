from pathlib import Path

from security.leak_benchmark import run_benchmark, fuzz_secret, evaluate_fuzz


def test_ground_truth_benchmark_scores():
    root = Path(__file__).resolve().parents[2]
    metrics = run_benchmark(
        root / "tests" / "data" / "leak_ground_truth.json",
        root / "tests" / "data" / "leak_benign_ground_truth.json",
    )
    assert metrics.recall >= 0.8
    assert metrics.precision >= 0.8


def test_fuzz_secret_detection_rate():
    samples = fuzz_secret("sk-abc123def456ghi789jkl012mno345pqr")
    blocked, total = evaluate_fuzz(samples)
    assert total > 0
    assert blocked / total >= 0.75
