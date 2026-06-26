"""Compare adversarial evaluation reports and detect security regressions."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


def _load_report(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _get_metric(report: dict[str, Any], key: str) -> float:
    value = report.get(key, 0.0)
    try:
        return float(value)
    except Exception:
        return 0.0


def compare_reports(current: dict[str, Any], previous: dict[str, Any], max_regression_pct: float) -> dict[str, Any]:
    # Higher-is-better metrics.
    hi_metrics = ["attack_detection_rate", "blocked_rate", "precision", "recall"]
    # Lower-is-better metrics.
    lo_metrics = ["false_positive_rate", "false_negative_rate"]

    regressions: list[dict[str, Any]] = []
    summary: dict[str, Any] = {"max_regression_pct": max_regression_pct, "metrics": {}}

    for metric in hi_metrics:
        curr = _get_metric(current, metric)
        prev = _get_metric(previous, metric)
        delta = curr - prev
        summary["metrics"][metric] = {"current": curr, "previous": prev, "delta": delta}
        if prev > 0 and ((prev - curr) / prev * 100.0) > max_regression_pct:
            regressions.append({"metric": metric, "direction": "down", "delta": delta})

    for metric in lo_metrics:
        curr = _get_metric(current, metric)
        prev = _get_metric(previous, metric)
        delta = curr - prev
        summary["metrics"][metric] = {"current": curr, "previous": prev, "delta": delta}
        if prev >= 0 and ((curr - prev) * 100.0) > max_regression_pct:
            regressions.append({"metric": metric, "direction": "up", "delta": delta})

    summary["regressions"] = regressions
    summary["passed"] = len(regressions) == 0
    return summary


def parse_args():
    p = argparse.ArgumentParser(description="Detect adversarial evaluation regressions.")
    p.add_argument("--current", required=True, help="Path to current eval report JSON.")
    p.add_argument("--previous", required=True, help="Path to previous eval report JSON.")
    p.add_argument("--max-regression-pct", type=float, default=2.0, help="Allowed regression percentage.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    current = _load_report(Path(args.current))
    previous = _load_report(Path(args.previous))
    verdict = compare_reports(current, previous, max_regression_pct=float(args.max_regression_pct))
    print(json.dumps(verdict, indent=2))
    return 0 if verdict["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
