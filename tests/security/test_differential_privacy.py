from security.differential_privacy import benchmark_count_noise, noisy_count

import random


def test_noisy_count_non_negative():
    rng = random.Random(42)
    v = noisy_count(true_count=0, epsilon=0.5, rng=rng)
    assert v >= 0


def test_dp_benchmark_error_trend_improves_with_higher_epsilon():
    report = benchmark_count_noise(
        true_count=1000,
        epsilons=[0.3, 1.0, 2.0],
        trials=400,
        seed=7,
    )
    rows = report["rows"]
    low = rows[0]["mean_absolute_error"]
    mid = rows[1]["mean_absolute_error"]
    high = rows[2]["mean_absolute_error"]
    assert low >= mid >= high
