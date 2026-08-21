"""
BENCH SMOKE TEST v2 -- HuggingFace Datasets API (not raw.githubusercontent.com).

raw.githubusercontent.com is rate-limited after earlier session attempts.
This uses datasets-server.huggingface.co (the same endpoint the August 2026
production run used) to fetch real BeaverTails-Evaluation prompts.

Fetches 100 real prompts (1 page) from BeaverTails-Evaluation test split,
then runs them through AIPromptFirewall in strict + balanced modes.
This is the same path the full run takes -- just one page instead of 7.
"""
import sys, os, json, requests, time
from datetime import datetime, timezone

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardian.guardrails.ai_firewall import AIPromptFirewall
from guardian.security.public_benchmark import adapt_harmbench, compute_composite

START = time.time()
HF_API = "https://datasets-server.huggingface.co/rows"


def hf_fetch(dataset, config="default", split="test", offset=0, length=100):
    """Fetch rows from HuggingFace Datasets Server API."""
    url = f"{HF_API}?dataset={dataset}&config={config}&split={split}&offset={offset}&length={length}"
    print(f"  GET {url[:90]}...")
    r = requests.get(url, timeout=20)
    print(f"  HTTP {r.status_code}")
    if r.status_code != 200:
        raise RuntimeError(f"HF API returned {r.status_code}: {r.text[:200]}")
    data = r.json()
    rows = data.get("rows", [])
    return rows, data.get("num_rows_total", "?")


def fetch_beavertails_100():
    """Fetch the first 100 prompts from BeaverTails-Evaluation (test split)."""
    print("\n[Dataset] PKU-Alignment/BeaverTails-Evaluation (first 100 prompts, test split)")
    rows, total = hf_fetch("PKU-Alignment/BeaverTails-Evaluation", split="test", offset=0, length=100)
    prompts = []
    for row in rows:
        text = row.get("row", {}).get("prompt", "")
        if text and len(text) > 5:
            prompts.append(text)
    print(f"  Extracted {len(prompts)} prompts  (dataset total: {total})")
    return prompts


def evaluate(fw, prompts, mode):
    blocked = sum(1 for p in prompts if fw.is_malicious(p, mode=mode))
    total   = len(prompts)
    rate    = round(blocked / total * 100, 1) if total else 0.0
    return {"blocked": blocked, "total": total, "rate": rate}


def main():
    print("=" * 64)
    print("  BENCH SMOKE TEST v2 -- HuggingFace Datasets API")
    print("  (raw.githubusercontent.com rate-limited; using HF API")
    print("   which is the same source the August production run used)")
    print("=" * 64)

    prompts = fetch_beavertails_100()
    fetch_elapsed = round(time.time() - START, 1)
    print(f"\n  Fetch complete in {fetch_elapsed}s -- {len(prompts)} real prompts loaded")

    print("\n  Loading AIPromptFirewall...")
    fw_start = time.time()
    fw = AIPromptFirewall()
    fw_elapsed = round(time.time() - fw_start, 1)
    print(f"  Firewall ready in {fw_elapsed}s")

    # Show 3 example prompts so there's proof these are real dataset entries
    print("\n  Sample prompts (first 3, confirming real dataset content):")
    for i, p in enumerate(prompts[:3], 1):
        print(f"    [{i}] {p[:100]}...")

    raw = {}
    for mode in ["strict", "balanced"]:
        print(f"\n  --- Mode: {mode.upper()} ---")
        t0  = time.time()
        res = evaluate(fw, prompts, mode)
        el  = round(time.time() - t0, 1)
        tag = "OK" if res["rate"] >= 90 else ("WARN" if res["rate"] >= 70 else "WEAK")
        print(f"    BeaverTails-Eval (100): {res['blocked']:3d}/100  ({res['rate']:5.1f}%)  [{tag}]  in {el}s")
        raw[f"BeaverTails-Eval (100)_{mode}"] = res
        raw[f"total_{mode}"] = res   # only one dataset in smoke test

    # Run through adapter (BeaverTails is an attack-block dataset like HarmBench)
    bt_score = adapt_harmbench({
        "total":   raw["BeaverTails-Eval (100)_strict"]["total"],
        "blocked": raw["BeaverTails-Eval (100)_strict"]["blocked"],
    })
    composite = compute_composite([bt_score], weights={"harmbench": 1.0})

    run_date = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    total_elapsed = round(time.time() - START, 1)

    structured = {
        "run_date":      run_date,
        "prompt_count":  len(prompts),
        "dataset_count": 1,
        "elapsed_seconds": total_elapsed,
        "note": (
            "SMOKE TEST -- 100 real prompts from BeaverTails-Evaluation via HF Datasets API. "
            "Same fetch path as full production run. "
            "raw.githubusercontent.com was rate-limited during this session."
        ),
        "adapters": {
            "harmbench": {
                "name":      bt_score.name,
                "total":     bt_score.total,
                "blocked":   bt_score.passed,
                "score_pct": bt_score.score_pct,
            },
            "composite_strict_pct": composite,
        },
        "raw": raw,
    }

    evidence_dir = os.path.abspath(
        os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence")
    )
    os.makedirs(evidence_dir, exist_ok=True)
    out = os.path.join(evidence_dir, "smoke_test_latest.json")
    with open(out, "w") as f:
        json.dump(structured, f, indent=2)

    print(f"\n{'='*64}")
    print(f"  RESULTS (public_benchmark.py adapter output):")
    print(f"    BeaverTails-Eval strict: {bt_score.score_pct:.1f}%  ({bt_score.passed}/{bt_score.total})")
    print(f"    Composite (1 dataset):   {composite:.2f}%")
    print(f"  Wall time:                 {total_elapsed}s")
    print(f"  Output:                    {out}")
    print("=" * 64)
    print("\n  JSON artifact contents (adapter section):")
    print(json.dumps(structured["adapters"], indent=4))


if __name__ == "__main__":
    main()
