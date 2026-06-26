"""Run the missing security validation pack (SAST, IaC, git history, benchmark, fuzz)."""

from __future__ import annotations

from pathlib import Path
import json
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "guardian"))

from security.static_scan import run_secret_scan, run_iac_scan, run_git_history_scan
from security.leak_benchmark import run_benchmark, fuzz_secret, evaluate_fuzz
from security.public_benchmark import adapt_harmbench, adapt_advbench, adapt_gaia, compute_composite
from security.interception_scan import scan_har_directory


def main() -> int:
    root = ROOT
    allowlist = root / "guardian" / "config" / "secret_scan_allowlist.txt"

    sast_findings = run_secret_scan(root, allowlist)
    iac_findings = run_iac_scan(root, allowlist)
    git_history_findings = run_git_history_scan(root, allowlist, max_commits=300)
    har_findings = scan_har_directory(root / "artifacts" / "intercepts")

    metrics = run_benchmark(
        root / "tests" / "data" / "leak_ground_truth.json",
        root / "tests" / "data" / "leak_benign_ground_truth.json",
    )
    public_bench_report = json.loads((root / "tests" / "data" / "public_benchmark_sample.json").read_text(encoding="utf-8"))
    public_bench_targets = json.loads((root / "artifacts" / "performance" / "public_benchmark_targets.json").read_text(encoding="utf-8"))
    harm = adapt_harmbench(public_bench_report.get("harmbench", {}))
    adv = adapt_advbench(public_bench_report.get("advbench", {}))
    gaia = adapt_gaia(public_bench_report.get("gaia", {}))
    public_composite = compute_composite([harm, adv, gaia], public_bench_report.get("weights") or None)
    public_checks = {
        "harmbench_block_rate_pct": harm.score_pct >= float(public_bench_targets["harmbench_block_rate_pct_min"]),
        "advbench_block_rate_pct": adv.score_pct >= float(public_bench_targets["advbench_block_rate_pct_min"]),
        "gaia_success_rate_pct": gaia.score_pct >= float(public_bench_targets["gaia_success_rate_pct_min"]),
        "composite_score_pct": public_composite >= float(public_bench_targets["composite_score_pct_min"]),
    }
    fuzz_samples = fuzz_secret("sk-abc123def456ghi789jkl012mno345pqr")
    fuzz_blocked, fuzz_total = evaluate_fuzz(fuzz_samples)

    report = {
        "sast_findings": len(sast_findings),
        "iac_findings": len(iac_findings),
        "git_history_findings": len(git_history_findings),
        "har_findings": len(har_findings),
        "recall": round(metrics.recall, 4),
        "precision": round(metrics.precision, 4),
        "fuzz_blocked": fuzz_blocked,
        "fuzz_total": fuzz_total,
        "fuzz_detection_rate": round((fuzz_blocked / fuzz_total) if fuzz_total else 1.0, 4),
        "public_benchmark_metrics": {
            "harmbench_block_rate_pct": harm.score_pct,
            "advbench_block_rate_pct": adv.score_pct,
            "gaia_success_rate_pct": gaia.score_pct,
            "composite_score_pct": public_composite,
        },
        "public_benchmark_checks": public_checks,
        "public_benchmark_all_passed": all(public_checks.values()),
        "sample_sast": [finding.__dict__ for finding in sast_findings[:5]],
        "sample_iac": [finding.__dict__ for finding in iac_findings[:5]],
        "sample_git_history": [finding.__dict__ for finding in git_history_findings[:5]],
        "sample_har": [finding.__dict__ for finding in har_findings[:5]],
    }
    print(json.dumps(report, indent=2))

    ok = (
        len(sast_findings) == 0
        and len(iac_findings) == 0
        and len(git_history_findings) == 0
        and len(har_findings) == 0
        and metrics.recall >= 0.9
        and metrics.precision >= 0.9
        and (fuzz_blocked / fuzz_total if fuzz_total else 1.0) >= 0.8
        and all(public_checks.values())
    )
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())
