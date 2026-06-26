"""
UNSEEN DATA TEST - Feature #32 Differential Privacy
===================================================
Tests advanced 2026 DP mechanisms (Gaussian, Exponential,
Budget Tracking, Local DP, Noisy Sum/Average).
"""
import sys, os, math, random
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), "guardian"))

from security.differential_privacy import (
    gaussian_noise, PrivacyBudgetTracker, clip_value,
    noisy_sum, noisy_average, exponential_mechanism, LocalDPResponse
)

RESULTS = {}

def run_test(name, fn):
    try:
        fn()
        RESULTS[name] = "PASS"
        print(f"  [PASS] {name}")
    except Exception as e:
        RESULTS[name] = f"FAIL: {e}"
        print(f"  [FAIL] {name}: {e}")

# ============ GAUSSIAN MECHANISM ============

def test_gaussian_noise():
    rng = random.Random(42)
    # Check that scale impacts variance
    vals_small = [gaussian_noise(1.0, rng) for _ in range(1000)]
    vals_large = [gaussian_noise(10.0, rng) for _ in range(1000)]
    var_small = sum(v*v for v in vals_small) / len(vals_small)
    var_large = sum(v*v for v in vals_large) / len(vals_large)
    
    # Large scale should have larger variance (~100 vs ~1)
    assert var_large > var_small * 50
    # Mean should be near 0
    mean_large = sum(vals_large) / len(vals_large)
    assert abs(mean_large) < 1.5

def test_gaussian_zero_scale():
    rng = random.Random(42)
    assert gaussian_noise(0.0, rng) == 0.0
    assert gaussian_noise(-1.0, rng) == 0.0

# ============ PRIVACY BUDGET TRACKER ============

def test_budget_tracker_consume():
    tracker = PrivacyBudgetTracker(max_epsilon=1.0, max_delta=1e-5)
    assert tracker.consume(0.3, 1e-6)
    assert tracker.consume(0.5, 1e-6)
    assert abs(tracker.remaining_epsilon() - 0.2) < 1e-6
    # Exceeds epsilon
    assert not tracker.consume(0.3)
    # Exceeds delta
    assert not tracker.consume(0.1, 1e-4)

def test_budget_tracker_exhaustion():
    tracker = PrivacyBudgetTracker(max_epsilon=0.5)
    assert tracker.consume(0.5)
    assert tracker.remaining_epsilon() == 0.0
    assert not tracker.consume(0.001)

# ============ VALUE CLIPPING ============

def test_clip_value():
    assert clip_value(5.0, 0.0, 10.0) == 5.0
    assert clip_value(-5.0, 0.0, 10.0) == 0.0
    assert clip_value(15.0, 0.0, 10.0) == 10.0

# ============ NOISY SUM & AVERAGE ============

def test_noisy_sum():
    rng = random.Random(42)
    values = [1.0, 5.0, 10.0, 15.0] # Sum = 31
    # Clipping bounds [0, 10]. Clamped values: [1, 5, 10, 10] -> sum = 26
    # Sens = 10. eps = 1.0 -> scale = 10
    n_sum = noisy_sum(values, epsilon=1.0, lower=0.0, upper=10.0, rng=rng)
    # We just ensure it runs and outputs a float
    assert isinstance(n_sum, float)

def test_noisy_average():
    rng = random.Random(42)
    values = [5.0] * 1000 # True average = 5.0
    # With large N, noise impact on average is small
    n_avg = noisy_average(values, epsilon=2.0, lower=0.0, upper=10.0, rng=rng)
    assert 4.0 < n_avg < 6.0

def test_noisy_average_empty():
    rng = random.Random(42)
    assert noisy_average([], epsilon=1.0, lower=0.0, upper=10.0, rng=rng) == 0.0

# ============ EXPONENTIAL MECHANISM ============

def test_exponential_mechanism_selects_best():
    rng = random.Random(42)
    candidates = ["A", "B", "C"]
    
    def score_fn(c):
        return {"A": 10, "B": 0, "C": -10}[c]
        
    # High epsilon -> highly likely to pick highest score ("A")
    selected = exponential_mechanism(candidates, score_fn, epsilon=10.0, sensitivity=1.0, rng=rng)
    assert selected == "A"

def test_exponential_mechanism_low_epsilon():
    rng = random.Random(42)
    candidates = ["A", "B"]
    def score_fn(c):
        return {"A": 1, "B": 0}[c]
    
    # Near zero epsilon -> almost uniform random. We just test it doesn't crash.
    selected = exponential_mechanism(candidates, score_fn, epsilon=1e-5, sensitivity=1.0, rng=rng)
    assert selected in candidates

# ============ LOCAL DP (RAPPOR-LITE) ============

def test_local_dp_response():
    # High epsilon -> truth probability close to 1
    ldp = LocalDPResponse(epsilon=10.0, rng=random.Random(42))
    assert ldp.p_truth > 0.99
    assert ldp.randomize_boolean(True) is True
    
    # Low epsilon -> truth probability close to 0.5
    ldp_low = LocalDPResponse(epsilon=0.0, rng=random.Random(42))
    assert abs(ldp_low.p_truth - 0.5) < 1e-4

# ============ MAIN ============

def main():
    print("=" * 72)
    print("  UNSEEN DATA TEST - Feature #32 Differential Privacy")
    print("=" * 72)

    print("\n  [A] Gaussian Mechanism")
    run_test("gaussian_noise", test_gaussian_noise)
    run_test("gaussian_zero", test_gaussian_zero_scale)

    print("\n  [B] Privacy Budget Tracker")
    run_test("budget_consume", test_budget_tracker_consume)
    run_test("budget_exhaust", test_budget_tracker_exhaustion)

    print("\n  [C] Clipping & Noisy Aggregates")
    run_test("clip_value", test_clip_value)
    run_test("noisy_sum", test_noisy_sum)
    run_test("noisy_avg", test_noisy_average)
    run_test("noisy_avg_empty", test_noisy_average_empty)

    print("\n  [D] Exponential Mechanism")
    run_test("exp_mech_best", test_exponential_mechanism_selects_best)
    run_test("exp_mech_uniform", test_exponential_mechanism_low_epsilon)

    print("\n  [E] Local DP")
    run_test("local_dp", test_local_dp_response)

    passed = sum(1 for v in RESULTS.values() if v == "PASS")
    total = len(RESULTS)
    print(f"\n{'='*72}")
    print(f"  RESULT: {passed}/{total} unseen data tests passed")
    if any(v != "PASS" for v in RESULTS.values()):
        for k, v in RESULTS.items():
            if v != "PASS": print(f"    {k}: {v}")
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
