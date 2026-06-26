"""
MEGA UNSEEN BENCHMARK — 3 Independent Datasets
================================================
Tests GuardianAI against 3 completely unseen, published adversarial datasets:

1. AdvBench (520 harmful behaviors) — The original adversarial prompt benchmark
2. SimpleSafetyTests (100 prompts) — Handcrafted by safety researchers
3. Do-Not-Answer (939 prompts) — Multi-category harm taxonomy

NONE of these were used during any firewall calibration.
"""
import sys
import os
import json
import csv
import requests
import io

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardian.guardrails.ai_firewall import AIPromptFirewall


def fetch_advbench():
    """Fetch AdvBench 520 harmful behaviors from llm-attacks GitHub."""
    print("  Fetching AdvBench (520 behaviors)...")
    url = "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv"
    resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        print(f"    FAILED ({resp.status_code})")
        return []
    reader = csv.DictReader(io.StringIO(resp.text))
    prompts = []
    for row in reader:
        goal = row.get("goal", "")
        if goal and len(goal) > 5:
            prompts.append(goal)
    print(f"    Loaded {len(prompts)} prompts")
    return prompts


def fetch_simple_safety():
    """Fetch SimpleSafetyTests from GitHub."""
    print("  Fetching SimpleSafetyTests (100 prompts)...")
    url = "https://raw.githubusercontent.com/bertiev/SimpleSafetyTests/main/sst_prompts.csv"
    resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        url = "https://raw.githubusercontent.com/bertiev/SimpleSafetyTests/main/data/prompts.csv"
        resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        url = "https://huggingface.co/datasets/Bertievidgen/SimpleSafetyTests/resolve/main/sst_prompts.csv"
        resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        url = "https://huggingface.co/datasets/Bertievidgen/SimpleSafetyTests/resolve/main/prompts.csv"
        resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        print(f"    FAILED ({resp.status_code})")
        return []
    reader = csv.DictReader(io.StringIO(resp.text))
    prompts = []
    for row in reader:
        # Try common column names
        prompt = row.get("prompt", row.get("Prompt", row.get("text", "")))
        if prompt and len(prompt) > 5:
            prompts.append(prompt)
    if not prompts:
        # Maybe it's a single-column format
        lines = resp.text.strip().split("\n")
        for line in lines[1:]:  # Skip header
            line = line.strip().strip('"')
            if line and len(line) > 5:
                prompts.append(line)
    print(f"    Loaded {len(prompts)} prompts")
    return prompts


def fetch_donotanswer():
    """Fetch Do-Not-Answer from GitHub."""
    print("  Fetching Do-Not-Answer (939 prompts)...")
    url = "https://raw.githubusercontent.com/Libr-AI/do-not-answer/main/data/do_not_answer.csv"
    resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        url = "https://raw.githubusercontent.com/Libr-AI/do-not-answer/main/data/do_not_answer_en.csv"
        resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        url = "https://raw.githubusercontent.com/Libr-AI/do-not-answer/main/do_not_answer.csv"
        resp = requests.get(url, timeout=10)
    if resp.status_code != 200:
        print(f"    FAILED ({resp.status_code})")
        return []
    reader = csv.DictReader(io.StringIO(resp.text))
    prompts = []
    for row in reader:
        prompt = row.get("question", row.get("prompt", row.get("instruction", "")))
        if prompt and len(prompt) > 5:
            prompts.append(prompt)
    print(f"    Loaded {len(prompts)} prompts")
    return prompts


def run_benchmark(fw, prompts, name, mode):
    """Run firewall against a set of prompts and return stats."""
    blocked = 0
    total = 0
    passed_examples = []
    for prompt in prompts:
        total += 1
        if fw.is_malicious(prompt, mode=mode):
            blocked += 1
        else:
            if len(passed_examples) < 5:
                passed_examples.append(prompt[:120])
    return blocked, total, passed_examples


def main():
    print("=" * 70)
    print("  MEGA UNSEEN BENCHMARK — 3 Independent Adversarial Datasets")
    print("  (NONE of these were used during firewall calibration)")
    print("=" * 70)
    print()

    # Fetch all datasets
    advbench = fetch_advbench()
    sst = fetch_simple_safety()
    dna = fetch_donotanswer()

    total_prompts = len(advbench) + len(sst) + len(dna)
    print(f"\n  Total unseen prompts to test: {total_prompts}")

    # Initialize
    print("\nInitializing firewall (loading ML model)...")
    fw = AIPromptFirewall()

    all_results = {}

    for mode in ["strict", "balanced"]:
        print(f"\n{'='*70}")
        print(f"  RESULTS — Mode: {mode.upper()}")
        print(f"{'='*70}")

        datasets = [
            ("AdvBench (520)", advbench),
            ("SimpleSafetyTests (100)", sst),
            ("Do-Not-Answer (939)", dna),
        ]

        mode_total_blocked = 0
        mode_total_prompts = 0

        for name, prompts in datasets:
            if not prompts:
                print(f"  {name:30s} : SKIPPED (fetch failed)")
                continue
            blocked, total, passed = run_benchmark(fw, prompts, name, mode)
            rate = (blocked / total * 100) if total > 0 else 0
            mode_total_blocked += blocked
            mode_total_prompts += total
            print(f"  {name:30s} : {blocked:4d}/{total:4d} blocked ({rate:5.1f}%)")
            if passed:
                for p in passed[:3]:
                    print(f"      Passed: {p}...")

            all_results[f"{name}_{mode}"] = {
                "blocked": blocked, "total": total, "rate_pct": round(rate, 1)
            }

        overall = (mode_total_blocked / mode_total_prompts * 100) if mode_total_prompts > 0 else 0
        print(f"  {'-'*50}")
        print(f"  {'OVERALL':30s} : {mode_total_blocked:4d}/{mode_total_prompts:4d} blocked ({overall:5.1f}%)")
        all_results[f"overall_{mode}"] = {
            "blocked": mode_total_blocked, "total": mode_total_prompts, "rate_pct": round(overall, 1)
        }

    print(f"\n{'='*70}")

    # Save
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence"))
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "mega_unseen_benchmark_results.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nFull results saved to {out_file}")


if __name__ == "__main__":
    main()
