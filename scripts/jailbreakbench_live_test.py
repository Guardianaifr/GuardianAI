#!/usr/bin/env python3
"""
Dedicated Live JailbreakBench (JBB) Multi-Attack Benchmark
Directly ingests real-time unseen attack artifacts from:
https://github.com/JailbreakBench/artifacts
and Hugging Face walledai/JailbreakBench

Evaluates GuardianAI against PAIR, GCG, Prompt-With-Random-Search, and Benign holdouts.
"""

import os
import sys
import json
import time
import urllib.request
from typing import List, Dict, Any, Tuple

# Ensure project root is on path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if os.path.join(PROJECT_ROOT, "guardian") not in sys.path:
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "guardian"))

from guardian.guardrails.input_filter import InputFilter
from guardian.guardrails.ai_firewall import AIPromptFirewall
from guardian.guardrails.encoding_detector import EncodingDetector
from guardian.guardrails.system_prompt_guard import _LEAK_PATTERNS

HEADERS = {
    "User-Agent": "GuardianAI-JailbreakBench-Evaluator/1.0 (+https://github.com/guardianai)"
}

def fetch_json(url: str, timeout: int = 15) -> Any:
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[-] Error fetching {url}: {e}", file=sys.stderr)
        return None

# ------------------------------------------------------------------------------
# 1. Fetch JailbreakBench Official Datasets & Artifacts
# ------------------------------------------------------------------------------

def fetch_jbb_pair_gpt4() -> List[Dict[str, Any]]:
    """Fetches PAIR attack artifacts on GPT-4 from JailbreakBench GitHub."""
    url = "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/PAIR/black_box/gpt-4-0125-preview.json"
    data = fetch_json(url)
    prompts = []
    if data and "jailbreaks" in data:
        for item in data["jailbreaks"]:
            if item.get("prompt"):
                prompts.append({
                    "prompt": item["prompt"],
                    "goal": item.get("goal", ""),
                    "category": item.get("category", "General"),
                    "behavior": item.get("behavior", "")
                })
    print(f"[+] JailbreakBench PAIR (GPT-4): fetched {len(prompts)} adversarial prompts")
    return prompts

def fetch_jbb_pair_gpt35() -> List[Dict[str, Any]]:
    """Fetches PAIR attack artifacts on GPT-3.5 from JailbreakBench GitHub."""
    url = "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/PAIR/black_box/gpt-3.5-turbo-1106.json"
    data = fetch_json(url)
    prompts = []
    if data and "jailbreaks" in data:
        for item in data["jailbreaks"]:
            if item.get("prompt"):
                prompts.append({
                    "prompt": item["prompt"],
                    "goal": item.get("goal", ""),
                    "category": item.get("category", "General"),
                    "behavior": item.get("behavior", "")
                })
    print(f"[+] JailbreakBench PAIR (GPT-3.5): fetched {len(prompts)} adversarial prompts")
    return prompts

def fetch_jbb_random_search_gpt4() -> List[Dict[str, Any]]:
    """Fetches Prompt-with-Random-Search artifacts from JailbreakBench GitHub."""
    url = "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/prompt_with_random_search/black_box/gpt-4-0125-preview.json"
    data = fetch_json(url)
    prompts = []
    if data and "jailbreaks" in data:
        for item in data["jailbreaks"]:
            if item.get("prompt"):
                prompts.append({
                    "prompt": item["prompt"],
                    "goal": item.get("goal", ""),
                    "category": item.get("category", "General"),
                    "behavior": item.get("behavior", "")
                })
    print(f"[+] JailbreakBench Random-Search (GPT-4): fetched {len(prompts)} adversarial prompts")
    return prompts

def fetch_jbb_benign_hf() -> List[Dict[str, Any]]:
    """Fetches official JailbreakBench benign dataset from Hugging Face."""
    url = "https://datasets-server.huggingface.co/rows?dataset=walledai/JailbreakBench&config=default&split=train&offset=0&limit=100"
    data = fetch_json(url)
    prompts = []
    if data and "rows" in data:
        for item in data["rows"]:
            row = item.get("row", {})
            if row.get("subset") == "benign" or "benign" in str(row.get("category", "")).lower():
                text = row.get("prompt", "").strip()
                if text:
                    prompts.append({
                        "prompt": text,
                        "category": row.get("category", "Benign"),
                        "behavior": row.get("behavior", "")
                    })
    print(f"[+] JailbreakBench Benign Holdout (Hugging Face): fetched {len(prompts)} safe prompts")
    return prompts

# ------------------------------------------------------------------------------
# 2. Evaluation Engine
# ------------------------------------------------------------------------------

class JBBEvaluator:
    def __init__(self):
        print("[*] Initializing GuardianAI Guardrails for JailbreakBench Evaluation...")
        self.input_filter = InputFilter()
        self.firewall = AIPromptFirewall()
        self.encoding_detector = EncodingDetector()
        self.leak_patterns = _LEAK_PATTERNS
        print("[+] Guardrails ready.")

    def evaluate(self, prompt: str, mode: str = "strict") -> Dict[str, Any]:
        t0 = time.perf_counter()
        
        # 1. Encoding De-obfuscation Check
        decoded_variants = self.encoding_detector.decode_all(prompt)
        is_obfuscated = len(decoded_variants) > 0
        variants = [prompt] + decoded_variants

        blocked = False
        blocking_layer = "none"
        is_regex_safe = True
        is_firewall_malicious = False
        system_leak = False

        for var in variants:
            # 2. Fast-Path Regex Check
            if not self.input_filter.check_prompt(var):
                is_regex_safe = False
                blocked = True
                blocking_layer = "fast_path_regex"
                break

            # 3. System Prompt Leakage Guard
            for p in self.leak_patterns:
                if p.search(var):
                    system_leak = True
                    blocked = True
                    blocking_layer = "system_prompt_guard"
                    break
            if blocked:
                break

            # 4. Semantic Firewall Check
            if self.firewall.enabled:
                if self.firewall.is_malicious(var, mode=mode):
                    is_firewall_malicious = True
                    blocked = True
                    blocking_layer = "semantic_firewall"
                    break

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "blocked": blocked,
            "blocking_layer": blocking_layer,
            "latency_ms": round(latency_ms, 2)
        }

# ------------------------------------------------------------------------------
# 3. Main Benchmark Runner
# ------------------------------------------------------------------------------

def run_jbb_benchmark():
    print("=" * 80)
    print(" GUARDIANAI OFFICIAL JAILBREAKBENCH (JBB) LIVE EVALUATION")
    print(" Source: https://github.com/JailbreakBench/artifacts")
    print("=" * 80)

    evaluator = JBBEvaluator()

    # 1. Fetch live datasets
    pair_gpt4 = fetch_jbb_pair_gpt4()
    pair_gpt35 = fetch_jbb_pair_gpt35()
    random_search = fetch_jbb_random_search_gpt4()
    benign_hf = fetch_jbb_benign_hf()

    attack_suites = {
        "JBB_PAIR_Attack_GPT4": pair_gpt4,
        "JBB_PAIR_Attack_GPT35": pair_gpt35,
        "JBB_Prompt_Random_Search_GPT4": random_search
    }

    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "source": "https://github.com/JailbreakBench/artifacts",
        "attack_suites": {},
        "benign_suite": {},
        "category_breakdown": {},
        "total_attacks": 0,
        "total_blocked_strict": 0,
        "total_blocked_balanced": 0
    }

    # 2. Evaluate Attack Suites
    print("\n[*] Running Attack Suite Evaluations...")
    for suite_name, items in attack_suites.items():
        if not items:
            continue
        n = len(items)
        blocked_strict = 0
        blocked_balanced = 0
        layer_counts = {"fast_path_regex": 0, "semantic_firewall": 0, "system_prompt_guard": 0, "none": 0}

        for item in items:
            p = item["prompt"]
            cat = item.get("category", "General")
            
            res_strict = evaluator.evaluate(p, mode="strict")
            res_balanced = evaluator.evaluate(p, mode="balanced")

            if res_strict["blocked"]:
                blocked_strict += 1
                layer_counts[res_strict["blocking_layer"]] = layer_counts.get(res_strict["blocking_layer"], 0) + 1
            else:
                layer_counts["none"] += 1

            if res_balanced["blocked"]:
                blocked_balanced += 1

            # Track category breakdown
            if cat not in results["category_breakdown"]:
                results["category_breakdown"][cat] = {"total": 0, "blocked_strict": 0, "blocked_balanced": 0}
            results["category_breakdown"][cat]["total"] += 1
            if res_strict["blocked"]:
                results["category_breakdown"][cat]["blocked_strict"] += 1
            if res_balanced["blocked"]:
                results["category_breakdown"][cat]["blocked_balanced"] += 1

        rate_strict = (blocked_strict / n) * 100.0
        rate_balanced = (blocked_balanced / n) * 100.0

        results["total_attacks"] += n
        results["total_blocked_strict"] += blocked_strict
        results["total_blocked_balanced"] += blocked_balanced

        results["attack_suites"][suite_name] = {
            "total": n,
            "blocked_strict": blocked_strict,
            "rate_strict_pct": round(rate_strict, 2),
            "blocked_balanced": blocked_balanced,
            "rate_balanced_pct": round(rate_balanced, 2),
            "layer_breakdown_strict": layer_counts
        }

        print(f"  -> {suite_name:<32} Total: {n:>3} | Strict: {rate_strict:>6.2f}% ({blocked_strict}/{n}) | Balanced: {rate_balanced:>6.2f}% ({blocked_balanced}/{n})")

    # 3. Evaluate Benign Holdout (False Positive Rate)
    print("\n[*] Running Benign / Safe Holdout Evaluation...")
    if benign_hf:
        n_benign = len(benign_hf)
        fp_strict = 0
        fp_balanced = 0

        for item in benign_hf:
            p = item["prompt"]
            res_strict = evaluator.evaluate(p, mode="strict")
            res_balanced = evaluator.evaluate(p, mode="balanced")

            if res_strict["blocked"]:
                fp_strict += 1
            if res_balanced["blocked"]:
                fp_balanced += 1

        fpr_strict = (fp_strict / n_benign) * 100.0
        fpr_balanced = (fp_balanced / n_benign) * 100.0

        results["benign_suite"] = {
            "total": n_benign,
            "false_positives_strict": fp_strict,
            "fpr_strict_pct": round(fpr_strict, 2),
            "false_positives_balanced": fp_balanced,
            "fpr_balanced_pct": round(fpr_balanced, 2)
        }
        print(f"  -> JBB_Benign_Holdout            Total: {n_benign:>3} | Strict FPR: {fpr_strict:>6.2f}% ({fp_strict}/{n_benign}) | Balanced FPR: {fpr_balanced:>6.2f}% ({fp_balanced}/{n_benign})")

    # 4. Overall Rates
    tot_attacks = results["total_attacks"]
    overall_strict = (results["total_blocked_strict"] / tot_attacks * 100.0) if tot_attacks > 0 else 0.0
    overall_balanced = (results["total_blocked_balanced"] / tot_attacks * 100.0) if tot_attacks > 0 else 0.0
    results["overall_attack_block_rate_strict_pct"] = round(overall_strict, 2)
    results["overall_attack_block_rate_balanced_pct"] = round(overall_balanced, 2)

    # 5. Save Evidence Files
    os.makedirs(os.path.join(PROJECT_ROOT, "artifacts", "evidence"), exist_ok=True)
    out_json = os.path.join(PROJECT_ROOT, "artifacts", "evidence", "jailbreakbench_live_results.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Saved structured JailbreakBench results to: {out_json}")

    # Generate Markdown Summary
    out_md = os.path.join(PROJECT_ROOT, "artifacts", "evidence", "jailbreakbench_live_report.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("# GuardianAI — Official JailbreakBench Live Benchmark Report\n\n")
        f.write(f"**Source:** [JailbreakBench Artifacts Repository](https://github.com/JailbreakBench/artifacts)\n")
        f.write(f"**Execution Timestamp:** {results['timestamp']}\n")
        f.write(f"**Total Adversarial Prompts Evaluated:** {tot_attacks:,}\n")
        f.write(f"**Total Benign Prompts Evaluated:** {len(benign_hf):,}\n\n")

        f.write("## 1. Overall JailbreakBench Performance\n\n")
        f.write("| Metric | Strict Mode | Balanced Mode |\n")
        f.write("|---|---|---|\n")
        f.write(f"| **Overall JBB Attack Block Rate** | **{overall_strict:.2f}%** ({results['total_blocked_strict']}/{tot_attacks}) | **{overall_balanced:.2f}%** ({results['total_blocked_balanced']}/{tot_attacks}) |\n")
        if benign_hf:
            f.write(f"| **False Positive Rate (Benign JBB)** | **{fpr_strict:.2f}%** ({fp_strict}/{n_benign}) | **{fpr_balanced:.2f}%** ({fp_balanced}/{n_benign}) |\n\n")

        f.write("## 2. Attack Suite Breakdown\n\n")
        f.write("| Attack Technique / Target | Total Prompts | Strict Block Rate | Balanced Block Rate |\n")
        f.write("|---|---|---|---|\n")
        for suite, data in results["attack_suites"].items():
            f.write(f"| `{suite}` | {data['total']} | **{data['rate_strict_pct']:.2f}%** ({data['blocked_strict']}) | {data['rate_balanced_pct']:.2f}% ({data['blocked_balanced']}) |\n")

        f.write("\n## 3. Category Breakdown (OWASP / JBB Taxonomy)\n\n")
        f.write("| Harm Category | Total Prompts | Strict Block Rate | Balanced Block Rate |\n")
        f.write("|---|---|---|---|\n")
        for cat, data in sorted(results["category_breakdown"].items()):
            s_rate = (data["blocked_strict"] / data["total"] * 100.0) if data["total"] > 0 else 0.0
            b_rate = (data["blocked_balanced"] / data["total"] * 100.0) if data["total"] > 0 else 0.0
            f.write(f"| **{cat}** | {data['total']} | **{s_rate:.1f}%** ({data['blocked_strict']}) | {b_rate:.1f}% ({data['blocked_balanced']}) |\n")

    print(f"[+] Saved JailbreakBench Markdown report to: {out_md}")
    print("=" * 80)
    print(" JAILBREAKBENCH LIVE EVALUATION COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    run_jbb_benchmark()
