"""Differential privacy helpers for aggregated analytics."""

from __future__ import annotations

import math
import random
import os
from typing import Any


def _get_default_rng() -> random.Random:
    return random.SystemRandom()


def laplace_noise(scale: float, rng: random.Random | None = None) -> float:
    if rng is None:
        rng = _get_default_rng()
    if scale <= 0:
        return 0.0
    u = rng.random() - 0.5
    if u == 0:
        return 0.0
    return -scale * math.copysign(math.log(1 - 2 * abs(u)), u)


def geometric_noise(alpha: float, rng: random.Random | None = None) -> int:
    """
    Two-sided geometric mechanism (discrete Laplace) for differential privacy on integer counts.
    alpha = exp(-epsilon). Returns an integer in (-inf, +inf).
    Ref: Ghosh, Roughgarden, Sundararajan (STOC 2009 / SICOMP 2012).
    """
    if rng is None:
        rng = _get_default_rng()
    if alpha <= 0 or alpha >= 1:
        return 0
    u1 = max(1e-15, rng.random())
    u2 = max(1e-15, rng.random())
    geom1 = int(math.floor(math.log(u1) / math.log(alpha)))
    geom2 = int(math.floor(math.log(u2) / math.log(alpha)))
    return geom1 - geom2


def noisy_count_unbiased(true_count: int, epsilon: float, rng: random.Random | None = None) -> float:
    """
    Returns un-truncated, un-clamped noisy count preserving the exact mean of the Laplace mechanism.
    E[noisy_count_unbiased] == true_count.
    """
    if rng is None:
        rng = _get_default_rng()
    eps = max(float(epsilon), 1e-6)
    scale = 1.0 / eps
    return float(true_count) + laplace_noise(scale, rng)


def noisy_count(true_count: int, epsilon: float, rng: random.Random | None = None) -> int:
    if rng is None:
        rng = _get_default_rng()
    eps = max(float(epsilon), 1e-6)
    scale = 1.0 / eps
    return max(0, int(round(float(true_count) + laplace_noise(scale, rng))))


def benchmark_count_noise(
    true_count: int,
    epsilons: list[float],
    trials: int = 500,
    seed: int = 7,
) -> dict[str, Any]:
    """Uses seeded PRNG for reproducibility. Never use for production DP queries."""
    rows = []
    for idx, eps in enumerate(epsilons):
        rng = random.Random(seed + idx)
        abs_errors: list[float] = []
        for _ in range(max(1, trials)):
            n = noisy_count(true_count, eps, rng)
            abs_errors.append(abs(float(n - true_count)))
        mae = sum(abs_errors) / len(abs_errors)
        rows.append(
            {
                "epsilon": float(eps),
                "trials": int(trials),
                "mean_absolute_error": round(mae, 4),
            }
        )
    return {
        "true_count": int(true_count),
        "rows": rows,
    }


# ═══════════════════════════════════════════════════════════════════════════
# 2026-Standard Advanced Differential Privacy Capabilities
# ═══════════════════════════════════════════════════════════════════════════

def gaussian_noise(scale: float, rng: random.Random | None = None) -> float:
    if rng is None:
        rng = _get_default_rng()
    """Generate Gaussian noise for (epsilon, delta)-DP (L2 sensitivity)."""
    if scale <= 0:
        return 0.0
    return rng.gauss(0.0, scale)


class PrivacyBudgetTracker:
    """Track privacy loss across multiple DP queries (Basic Composition)."""
    def __init__(self, max_epsilon: float, max_delta: float = 0.0):
        self.max_epsilon = max_epsilon
        self.max_delta = max_delta
        self.spent_epsilon = 0.0
        self.spent_delta = 0.0

    def consume(self, epsilon: float, delta: float = 0.0) -> bool:
        """Attempt to consume budget. Returns True if allowed."""
        if self.spent_epsilon + epsilon > self.max_epsilon:
            return False
        if self.spent_delta + delta > self.max_delta:
            return False
        self.spent_epsilon += epsilon
        self.spent_delta += delta
        return True

    def remaining_epsilon(self) -> float:
        return max(0.0, self.max_epsilon - self.spent_epsilon)


def clip_value(value: float, lower: float, upper: float) -> float:
    """Enforce bounds on values to control sensitivity."""
    return max(lower, min(upper, value))


def noisy_sum(values: list[float], epsilon: float, lower: float, upper: float, rng: random.Random | None = None) -> float:
    if rng is None:
        rng = _get_default_rng()
    """Compute DP sum using Laplace mechanism."""
    eps = max(float(epsilon), 1e-6)
    # L1 sensitivity is max(abs(lower), abs(upper)) if we clip to [lower, upper]
    # actually sensitivity of sum is upper - lower if we clip each element
    sensitivity = abs(upper - lower)
    clipped = sum(clip_value(v, lower, upper) for v in values)
    scale = sensitivity / eps
    return clipped + laplace_noise(scale, rng)


def noisy_average(values: list[float], epsilon: float, lower: float, upper: float, rng: random.Random | None = None) -> float:
    if rng is None:
        rng = _get_default_rng()
    """Compute DP average (splits epsilon between sum and count)."""
    eps = max(float(epsilon), 1e-6)
    eps_sum = eps * 0.9
    eps_count = eps * 0.1

    n_sum = noisy_sum(values, eps_sum, lower, upper, rng)
    n_count = noisy_count(len(values), eps_count, rng)

    if n_count <= 0:
        return 0.0
    return clip_value(n_sum / n_count, lower, upper)


def exponential_mechanism(
    candidates: list[Any],
    score_fn: callable,
    epsilon: float,
    sensitivity: float,
    rng: random.Random | None = None
) -> Any:
    if rng is None:
        rng = _get_default_rng()
    """Select categorical candidate using Exponential Mechanism."""
    if not candidates:
        return None
    eps = max(float(epsilon), 1e-6)
    scores = [score_fn(c) for c in candidates]
    
    # Compute probabilities proportional to exp(epsilon * score / (2 * sensitivity))
    probs = []
    max_score = max(scores)  # for numerical stability
    for s in scores:
        exponent = (eps * (s - max_score)) / (2.0 * sensitivity)
        probs.append(math.exp(exponent))
        
    total_prob = sum(probs)
    normalized = [p / total_prob for p in probs]
    
    # Sample based on probabilities
    r = rng.random()
    cumulative = 0.0
    for i, p in enumerate(normalized):
        cumulative += p
        if r <= cumulative:
            return candidates[i]
    return candidates[-1]


class LocalDPResponse:
    """Local Differential Privacy via Randomized Response (RAPPOR-lite)."""
    def __init__(self, epsilon: float, rng: random.Random | None = None):
        self.epsilon = max(float(epsilon), 1e-6)
        self.rng = rng if rng is not None else _get_default_rng()
        # Probability of telling the truth
        self.p_truth = math.exp(self.epsilon) / (1.0 + math.exp(self.epsilon))

    def randomize_boolean(self, value: bool) -> bool:
        """Apply randomized response to a boolean value."""
        if self.rng.random() <= self.p_truth:
            return value
        return not value
