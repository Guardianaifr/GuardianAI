"""Public benchmark adapters and scoring helpers.

Supports normalization for:
- HarmBench-style attack-block metrics
- AdvBench-style attack-block metrics
- GAIA-style task-success metrics
"""

# DEPRECATED: This module is not called at runtime. The canonical benchmark
# runner is tools/run_definitive_benchmark_v4.py. Retained for reference only.

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


def _to_float(value: Any, default: float = 0.0) -> float:
    if value is None:
        return default
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip().replace("%", "")
        try:
            return float(cleaned)
        except ValueError:
            return default
    return default


def _safe_pct(numerator: float, denominator: float) -> float:
    return (numerator / denominator * 100.0) if denominator else 0.0


@dataclass
class BenchmarkScore:
    name: str
    total: int
    passed: int
    score_pct: float


def adapt_harmbench(payload: dict[str, Any]) -> BenchmarkScore:
    total = int(
        payload.get("total_attacks")
        or payload.get("total")
        or payload.get("cases")
        or 0
    )
    blocked = int(
        payload.get("blocked_attacks")
        or payload.get("blocked")
        or payload.get("successful_defenses")
        or 0
    )
    score = _safe_pct(float(blocked), float(total))
    return BenchmarkScore(name="harmbench", total=total, passed=blocked, score_pct=round(score, 2))


def adapt_advbench(payload: dict[str, Any]) -> BenchmarkScore:
    total = int(
        payload.get("total_attacks")
        or payload.get("total")
        or payload.get("prompts")
        or 0
    )
    blocked = int(
        payload.get("blocked_attacks")
        or payload.get("blocked")
        or payload.get("refusals")
        or 0
    )
    score = _safe_pct(float(blocked), float(total))
    return BenchmarkScore(name="advbench", total=total, passed=blocked, score_pct=round(score, 2))


def adapt_gaia(payload: dict[str, Any]) -> BenchmarkScore:
    total = int(
        payload.get("total_tasks")
        or payload.get("total")
        or payload.get("questions")
        or 0
    )
    solved = int(
        payload.get("solved_tasks")
        or payload.get("passed")
        or payload.get("solved")
        or 0
    )
    score = _safe_pct(float(solved), float(total))
    return BenchmarkScore(name="gaia", total=total, passed=solved, score_pct=round(score, 2))


def compute_composite(scores: list[BenchmarkScore], weights: dict[str, float] | None = None) -> float:
    if not scores:
        return 0.0
    if not weights:
        weights = {"harmbench": 0.4, "advbench": 0.4, "gaia": 0.2}
    weighted = 0.0
    total_weight = 0.0
    for score in scores:
        weight = _to_float(weights.get(score.name, 0.0))
        if weight <= 0:
            continue
        weighted += score.score_pct * weight
        total_weight += weight
    if total_weight <= 0:
        return 0.0
    return round(weighted / total_weight, 2)
