"""Evaluate security SLO/error budget gates from perf+chaos report."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[1]


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def _safe_div(n: float, d: float) -> float:
    return n / d if d else 0.0


def evaluate_gate(report: dict[str, Any], targets: dict[str, Any]) -> dict[str, Any]:
    baseline = report.get("baseline_safe_load", {})
    attack = report.get("attack_block_load", {})
    chaos_up = report.get("chaos_upstream_down", {})
    chaos_be = report.get("chaos_backend_down", {})

    baseline_total = float(baseline.get("total_requests", 0))
    baseline_status = baseline.get("status_counts", {}) or {}
    attack_total = float(attack.get("total_requests", 0))
    attack_status = attack.get("status_counts", {}) or {}

    baseline_success = _safe_div(float(baseline_status.get("200", 0)), baseline_total) * 100.0
    attack_block_rate = _safe_div(float(attack_status.get("403", 0)), attack_total) * 100.0
    baseline_p95 = float(((baseline.get("latency_ms", {}) or {}).get("p95", 0.0)))

    checks = {
        "baseline_success_pct": baseline_success >= float(targets["baseline_success_pct_min"]),
        "attack_block_rate_pct": attack_block_rate >= float(targets["attack_block_rate_pct_min"]),
        "baseline_p95_ms": baseline_p95 <= float(targets["baseline_p95_ms_max"]),
        "chaos_upstream_status": int(chaos_up.get("status", 0)) in set(targets["chaos_upstream_allowed_status"]),
        "chaos_backend_status": int(chaos_be.get("status", 0)) in set(targets["chaos_backend_allowed_status"]),
    }
    return {
        "checks": checks,
        "all_passed": all(checks.values()),
        "metrics": {
            "baseline_success_pct": round(baseline_success, 2),
            "attack_block_rate_pct": round(attack_block_rate, 2),
            "baseline_p95_ms": round(baseline_p95, 2),
            "chaos_upstream_status": int(chaos_up.get("status", 0)),
            "chaos_backend_status": int(chaos_be.get("status", 0)),
        },
        "targets": targets,
    }


def parse_args():
    p = argparse.ArgumentParser(description="Check security SLO gates from perf/chaos report.")
    p.add_argument(
        "--report",
        default=str(ROOT / "artifacts" / "performance" / "perf_chaos_report.json"),
        help="Path to perf+chaos report JSON.",
    )
    p.add_argument(
        "--targets",
        default=str(ROOT / "artifacts" / "performance" / "security_slo_targets.json"),
        help="Path to SLO target JSON.",
    )
    return p.parse_args()


def main() -> int:
    args = parse_args()
    report = _load_json(Path(args.report))
    targets = _load_json(Path(args.targets))
    verdict = evaluate_gate(report, targets)
    print(json.dumps(verdict, indent=2))
    return 0 if verdict["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
