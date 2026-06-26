"""Run a differential privacy benchmark for analytics count distortion."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys


ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "guardian"))

from security.differential_privacy import benchmark_count_noise  # noqa: E402


DEFAULT_OUTPUT = ROOT / "artifacts" / "performance" / "dp_benchmark_report.json"
DEFAULT_OUTPUT_MD = ROOT / "artifacts" / "performance" / "dp_benchmark_report.md"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Benchmark DP analytics count distortion over epsilon values.")
    p.add_argument("--true-count", type=int, default=1000, help="Reference aggregate count.")
    p.add_argument("--epsilons", default="0.3,0.5,1.0,2.0", help="Comma-separated epsilon values.")
    p.add_argument("--trials", type=int, default=500, help="Trials per epsilon.")
    p.add_argument("--seed", type=int, default=7, help="Random seed for repeatability.")
    p.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Output report JSON path.")
    p.add_argument("--output-md", default=str(DEFAULT_OUTPUT_MD), help="Output report markdown path.")
    return p.parse_args()


def _render_markdown(report: dict) -> str:
    lines = [
        "# Differential Privacy Benchmark Report",
        "",
        f"- true_count: `{report['true_count']}`",
        "",
        "| epsilon | trials | mean_absolute_error |",
        "| --- | ---: | ---: |",
    ]
    for row in report.get("rows", []):
        lines.append(f"| {row['epsilon']} | {row['trials']} | {row['mean_absolute_error']} |")
    return "\n".join(lines) + "\n"


def main() -> int:
    args = parse_args()
    eps = [float(v.strip()) for v in str(args.epsilons).split(",") if v.strip()]
    report = benchmark_count_noise(
        true_count=int(args.true_count),
        epsilons=eps,
        trials=int(args.trials),
        seed=int(args.seed),
    )

    out = Path(args.output)
    out_md = Path(args.output_md)
    out.parent.mkdir(parents=True, exist_ok=True)
    out_md.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    out_md.write_text(_render_markdown(report), encoding="utf-8")
    print(json.dumps(report, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
