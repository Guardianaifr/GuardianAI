"""Ground-truth and fuzz benchmark helpers for leak detection."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json
import random

try:
    from guardian.guardrails.output_validator import OutputValidator
except ImportError:
    from guardrails.output_validator import OutputValidator


@dataclass
class BenchmarkMetrics:
    total: int
    blocked: int
    recall: float
    precision: float


def _load_json_list(path: Path) -> list[str]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(data, list):
        return [str(item) for item in data]
    raise ValueError(f"Expected list JSON in {path}")


def evaluate_ground_truth(leak_samples: list[str], benign_samples: list[str]) -> BenchmarkMetrics:
    validator = OutputValidator()
    tp = sum(1 for text in leak_samples if validator.validate_output(text) is False)
    fp = sum(1 for text in benign_samples if validator.validate_output(text) is False)
    fn = len(leak_samples) - tp
    recall = tp / len(leak_samples) if leak_samples else 1.0
    precision = tp / (tp + fp) if (tp + fp) else 1.0
    return BenchmarkMetrics(total=len(leak_samples) + len(benign_samples), blocked=tp + fp, recall=recall, precision=precision)


def fuzz_secret(secret: str, seed: int = 7) -> list[str]:
    rng = random.Random(seed)
    variants = {
        secret,
        secret.upper(),
        secret.lower(),
        f"token={secret}",
        f"api_key: {secret}",
        f"\"{secret}\"",
        f"Bearer {secret}",
        f"{secret}.",
    }
    chars = list(secret)
    for _ in range(4):
        idx = rng.randrange(3, len(chars))  # skip the "sk-" prefix anchor
        mutated = chars.copy()
        mutated[idx] = mutated[idx].upper() if mutated[idx].islower() else mutated[idx].lower()
        variants.add("".join(mutated))
    return sorted(variants)


def evaluate_fuzz(samples: list[str]) -> tuple[int, int]:
    validator = OutputValidator()
    blocked = sum(1 for text in samples if validator.validate_output(text) is False)
    return blocked, len(samples)


def run_benchmark(leak_path: Path, benign_path: Path) -> BenchmarkMetrics:
    leak_samples = _load_json_list(leak_path)
    benign_samples = _load_json_list(benign_path)
    return evaluate_ground_truth(leak_samples, benign_samples)
