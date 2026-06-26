import csv
import sys
import os
import json

# Ensure the project root is on the path when running from tools/
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from guardian.guardrails.ai_firewall import AIPromptFirewall

def main():
    print("Initializing AI Firewall (loading ML model)...")
    firewall = AIPromptFirewall()
    
    csv_path = r"f:\Saas\guardianai-basic-launch\.venv312\Lib\site-packages\jailbreakbench\data\behaviors.csv"
    
    results = {mode: {"blocked": 0, "total": 0, "passed": []} for mode in ["strict", "balanced", "lenient"]}
    all_results = []

    print(f"\nStarting Official JailbreakBench Evaluation (100 Behaviors)...")
    print(f"Running in 3 security modes: strict / balanced / lenient")
    print("-" * 60)

    with open(csv_path, "r", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        rows = list(reader)

    for row in rows:
        prompt = row.get("Goal", "")
        behavior = row.get("Behavior", "")
        category = row.get("Category", "")
        if not prompt:
            continue
        
        row_result = {"behavior": behavior, "category": category, "prompt": prompt}
        for mode in ["strict", "balanced", "lenient"]:
            results[mode]["total"] += 1
            blocked = firewall.is_malicious(prompt, mode=mode)
            results[mode]["blocked"] += int(blocked)
            row_result[f"blocked_{mode}"] = blocked
            if not blocked:
                results[mode]["passed"].append(behavior)
        
        all_results.append(row_result)

    print(f"\n{'='*60}")
    print(f"  OFFICIAL JAILBREAKBENCH RESULTS - GUARDIANAI")
    print(f"{'='*60}")
    for mode in ["strict", "balanced", "lenient"]:
        r = results[mode]
        rate = (r["blocked"] / r["total"]) * 100
        print(f"  Mode [{mode:8s}]: {r['blocked']:3d}/{r['total']} blocked  ({rate:.1f}%)")
    
    # Show what slipped through at balanced mode
    passed_balanced = results["balanced"]["passed"]
    if passed_balanced:
        print(f"\n  Passed at 'balanced' ({len(passed_balanced)} behaviors):")
        for b in passed_balanced[:15]:
            print(f"    - {b}")
        if len(passed_balanced) > 15:
            print(f"    ... and {len(passed_balanced) - 15} more")
    print(f"{'='*60}")

    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "artifacts", "evidence"))
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "jbb_official_full_results.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump({
            "summary": {
                mode: {
                    "blocked": results[mode]["blocked"],
                    "total": results[mode]["total"],
                    "block_rate_pct": round((results[mode]["blocked"] / results[mode]["total"]) * 100, 2)
                } for mode in ["strict", "balanced", "lenient"]
            },
            "detailed_results": all_results
        }, f, indent=2)
    print(f"\nFull results saved to {out_file}")

if __name__ == "__main__":
    main()
