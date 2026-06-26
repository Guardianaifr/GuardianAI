"""Run public benchmark alignment gate and publish score artifacts."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "guardian"))

from security.public_benchmark import (  # noqa: E402
    BenchmarkScore,
    adapt_advbench,
    adapt_gaia,
    adapt_harmbench,
    compute_composite,
)


DEFAULT_INPUT = ROOT / "tests" / "data" / "public_benchmark_sample.json"
DEFAULT_TARGETS = ROOT / "artifacts" / "performance" / "public_benchmark_targets.json"
DEFAULT_OUTPUT = ROOT / "artifacts" / "performance" / "public_benchmark_report.json"
DEFAULT_OUTPUT_MD = ROOT / "artifacts" / "performance" / "public_benchmark_report.md"


def _load_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8"))


def evaluate_public_benchmark_gate(report: dict[str, Any], targets: dict[str, Any]) -> dict[str, Any]:
    harm = adapt_harmbench(report.get("harmbench", {}))
    adv = adapt_advbench(report.get("advbench", {}))
    gaia = adapt_gaia(report.get("gaia", {}))
    scores = [harm, adv, gaia]
    composite = compute_composite(scores, report.get("weights") or None)

    checks = {
        "harmbench_block_rate_pct": harm.score_pct >= float(targets["harmbench_block_rate_pct_min"]),
        "advbench_block_rate_pct": adv.score_pct >= float(targets["advbench_block_rate_pct_min"]),
        "gaia_success_rate_pct": gaia.score_pct >= float(targets["gaia_success_rate_pct_min"]),
        "composite_score_pct": composite >= float(targets["composite_score_pct_min"]),
    }
    return {
        "all_passed": all(checks.values()),
        "checks": checks,
        "metrics": {
            "harmbench_block_rate_pct": harm.score_pct,
            "advbench_block_rate_pct": adv.score_pct,
            "gaia_success_rate_pct": gaia.score_pct,
            "composite_score_pct": composite,
        },
        "totals": {
            "harmbench": {"passed": harm.passed, "total": harm.total},
            "advbench": {"passed": adv.passed, "total": adv.total},
            "gaia": {"passed": gaia.passed, "total": gaia.total},
        },
        "targets": targets,
    }


def build_markdown_summary(verdict: dict[str, Any]) -> str:
    m = verdict["metrics"]
    c = verdict["checks"]
    return "\n".join(
        [
            "# Public Benchmark Alignment Report",
            "",
            f"- all_passed: `{str(verdict['all_passed']).lower()}`",
            "",
            "## Metrics",
            f"- HarmBench block rate: **{m['harmbench_block_rate_pct']:.2f}%**",
            f"- AdvBench block rate: **{m['advbench_block_rate_pct']:.2f}%**",
            f"- GAIA success rate: **{m['gaia_success_rate_pct']:.2f}%**",
            f"- Composite score: **{m['composite_score_pct']:.2f}%**",
            "",
            "## Gate Checks",
            f"- harmbench_block_rate_pct: `{c['harmbench_block_rate_pct']}`",
            f"- advbench_block_rate_pct: `{c['advbench_block_rate_pct']}`",
            f"- gaia_success_rate_pct: `{c['gaia_success_rate_pct']}`",
            f"- composite_score_pct: `{c['composite_score_pct']}`",
        ]
    )


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Evaluate public benchmark alignment and publish scores.")
    p.add_argument("--input", default=str(DEFAULT_INPUT), help="Input benchmark JSON.")
    p.add_argument("--targets", default=str(DEFAULT_TARGETS), help="Benchmark target JSON.")
    p.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output verdict JSON.")
    p.add_argument("--output-md", default=str(DEFAULT_OUTPUT_MD), help="Output verdict markdown.")
    return p.parse_args()


def main() -> int:
    args = parse_args()
    input_path = Path(args.input)
    targets_path = Path(args.targets)
    out_path = Path(args.output)
    out_md_path = Path(args.output_md)

    report = _load_json(input_path)
    targets = _load_json(targets_path)
    verdict = evaluate_public_benchmark_gate(report, targets)

    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_md_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(verdict, indent=2), encoding="utf-8")
    out_md_path.write_text(build_markdown_summary(verdict) + "\n", encoding="utf-8")
    print(json.dumps(verdict, indent=2))
    return 0 if verdict["all_passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
