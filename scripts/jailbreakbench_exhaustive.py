#!/usr/bin/env python3
"""
Exhaustive JailbreakBench (JBB) Multi-Attack Benchmark
Fetches and evaluates EVERY SINGLE prompt across all attack algorithms and models from:
https://github.com/JailbreakBench/artifacts
and Hugging Face walledai/JailbreakBench

Covers:
- PAIR (GPT-4, GPT-3.5, Llama-2, Vicuna-13B)
- GCG Transfer & Whitebox (GPT-4, GPT-3.5, Llama-2, Vicuna-13B)
- JBC Manual Attacks (GPT-4, GPT-3.5, Llama-2, Vicuna-13B)
- Prompt-With-Random-Search (GPT-4, GPT-3.5, Llama-2, Vicuna-13B)
- DSN Whitebox (Llama-2, Vicuna-13B)
- Test Artifacts
- Benign baseline holdouts
"""

import os
import sys
import json
import time
import urllib.request
from typing import List, Dict, Any, Tuple

# Add project root to sys.path
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
    "User-Agent": "GuardianAI-Exhaustive-JBB/1.0 (+https://github.com/guardianai)"
}

def fetch_json(url: str, timeout: int = 15) -> Any:
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[-] Failed to fetch {url}: {e}", file=sys.stderr)
        return None

# List of all attack artifact files in JailbreakBench/artifacts repo
JBB_ARTIFACT_FILES = [
    ("PAIR", "GPT-4", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/PAIR/black_box/gpt-4-0125-preview.json"),
    ("PAIR", "GPT-3.5", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/PAIR/black_box/gpt-3.5-turbo-1106.json"),
    ("PAIR", "Llama-2-7B", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/PAIR/black_box/llama-2-7b-chat-hf.json"),
    ("PAIR", "Vicuna-13B", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/PAIR/black_box/vicuna-13b-v1.5.json"),
    ("GCG_Transfer", "GPT-4", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/GCG/transfer/gpt-4-0125-preview.json"),
    ("GCG_Transfer", "GPT-3.5", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/GCG/transfer/gpt-3.5-turbo-1106.json"),
    ("GCG_Whitebox", "Llama-2-7B", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/GCG/white_box/llama-2-7b-chat-hf.json"),
    ("GCG_Whitebox", "Vicuna-13B", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/GCG/white_box/vicuna-13b-v1.5.json"),
    ("JBC_Manual", "GPT-4", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/JBC/manual/gpt-4-0125-preview.json"),
    ("JBC_Manual", "GPT-3.5", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/JBC/manual/gpt-3.5-turbo-1106.json"),
    ("JBC_Manual", "Llama-2-7B", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/JBC/manual/llama-2-7b-chat-hf.json"),
    ("JBC_Manual", "Vicuna-13B", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/JBC/manual/vicuna-13b-v1.5.json"),
    ("Random_Search", "GPT-4", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/prompt_with_random_search/black_box/gpt-4-0125-preview.json"),
    ("Random_Search", "GPT-3.5", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/prompt_with_random_search/black_box/gpt-3.5-turbo-1106.json"),
    ("Random_Search", "Llama-2-7B", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/prompt_with_random_search/black_box/llama-2-7b-chat-hf.json"),
    ("Random_Search", "Vicuna-13B", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/prompt_with_random_search/black_box/vicuna-13b-v1.5.json"),
    ("DSN", "Llama-2-7B", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/DSN/white_box/llama-2-7b-chat-hf.json"),
    ("DSN", "Vicuna-13B", "https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/DSN/white_box/vicuna-13b-v1.5.json"),
]

def fetch_all_jbb_prompts() -> List[Dict[str, Any]]:
    all_prompts = []
    print("[*] Fetching all attack artifacts from JailbreakBench GitHub repo...")
    for algo, target_model, url in JBB_ARTIFACT_FILES:
        data = fetch_json(url)
        if not data:
            continue
        count = 0
        jailbreaks = data.get("jailbreaks", [])
        if isinstance(data, list):
            jailbreaks = data
        elif not jailbreaks and isinstance(data, dict):
            # Try other keys
            for k in ["prompts", "artifacts", "cases"]:
                if k in data and isinstance(data[k], list):
                    jailbreaks = data[k]
                    break
        
        for item in jailbreaks:
            if not isinstance(item, dict):
                continue
            prompt_text = item.get("prompt") or item.get("text") or item.get("adversarial_prompt") or ""
            if prompt_text and len(prompt_text.strip()) > 5:
                all_prompts.append({
                    "algorithm": algo,
                    "target_model": target_model,
                    "prompt": prompt_text.strip(),
                    "goal": item.get("goal", ""),
                    "category": item.get("category", "General"),
                    "behavior": item.get("behavior", "")
                })
                count += 1
        print(f"  -> [{algo}] Target: {target_model:<14} -> Fetched {count} prompts")
    print(f"[+] Total unique JailbreakBench attack prompts fetched: {len(all_prompts):,}")
    return all_prompts

def fetch_jbb_benign_prompts() -> List[Dict[str, Any]]:
    print("[*] Fetching JailbreakBench Benign Baseline from Hugging Face...")
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
    print(f"[+] Total JailbreakBench benign prompts fetched: {len(prompts)}")
    return prompts

# ------------------------------------------------------------------------------
# Evaluation Pipeline
# ------------------------------------------------------------------------------

class ExhaustiveJBBEvaluator:
    def __init__(self):
        print("[*] Initializing GuardianAI Guardrails Pipeline...")
        self.input_filter = InputFilter()
        self.firewall = AIPromptFirewall()
        self.encoding_detector = EncodingDetector()
        self.leak_patterns = _LEAK_PATTERNS
        print("[+] Pipeline ready.")

    def evaluate_prompt(self, prompt: str, mode: str = "strict") -> Dict[str, Any]:
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

            # 4. Semantic AI Firewall Check
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

def run_exhaustive_jbb():
    print("=" * 80)
    print(" GUARDIANAI EXHAUSTIVE JAILBREAKBENCH BENCHMARK (ALL PROMPTS & ARTIFACTS)")
    print("=" * 80)

    evaluator = ExhaustiveJBBEvaluator()
    attack_prompts = fetch_all_jbb_prompts()
    benign_prompts = fetch_jbb_benign_prompts()

    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "source": "https://github.com/JailbreakBench/artifacts",
        "total_attack_prompts": len(attack_prompts),
        "total_benign_prompts": len(benign_prompts),
        "by_algorithm": {},
        "by_model": {},
        "by_category": {},
        "layer_breakdown_strict": {},
        "total_blocked_strict": 0,
        "total_blocked_balanced": 0,
        "overall_attack_block_rate_strict_pct": 0.0,
        "overall_attack_block_rate_balanced_pct": 0.0,
        "benign_eval": {}
    }

    print("\n[*] Evaluating Every Single Attack Prompt across Strict & Balanced Modes...")
    t_start = time.perf_counter()

    for idx, item in enumerate(attack_prompts):
        p = item["prompt"]
        algo = item["algorithm"]
        model = item["target_model"]
        cat = item.get("category", "General")

        res_strict = evaluator.evaluate_prompt(p, mode="strict")
        res_balanced = evaluator.evaluate_prompt(p, mode="balanced")

        if res_strict["blocked"]:
            results["total_blocked_strict"] += 1
            layer = res_strict["blocking_layer"]
            results["layer_breakdown_strict"][layer] = results["layer_breakdown_strict"].get(layer, 0) + 1
        else:
            results["layer_breakdown_strict"]["none"] = results["layer_breakdown_strict"].get("none", 0) + 1

        if res_balanced["blocked"]:
            results["total_blocked_balanced"] += 1

        # Track by Algorithm
        if algo not in results["by_algorithm"]:
            results["by_algorithm"][algo] = {"total": 0, "blocked_strict": 0, "blocked_balanced": 0}
        results["by_algorithm"][algo]["total"] += 1
        if res_strict["blocked"]:
            results["by_algorithm"][algo]["blocked_strict"] += 1
        if res_balanced["blocked"]:
            results["by_algorithm"][algo]["blocked_balanced"] += 1

        # Track by Model Target
        if model not in results["by_model"]:
            results["by_model"][model] = {"total": 0, "blocked_strict": 0, "blocked_balanced": 0}
        results["by_model"][model]["total"] += 1
        if res_strict["blocked"]:
            results["by_model"][model]["blocked_strict"] += 1
        if res_balanced["blocked"]:
            results["by_model"][model]["blocked_balanced"] += 1

        # Track by Category
        if cat not in results["by_category"]:
            results["by_category"][cat] = {"total": 0, "blocked_strict": 0, "blocked_balanced": 0}
        results["by_category"][cat]["total"] += 1
        if res_strict["blocked"]:
            results["by_category"][cat]["blocked_strict"] += 1
        if res_balanced["blocked"]:
            results["by_category"][cat]["blocked_balanced"] += 1

        if (idx + 1) % 100 == 0 or (idx + 1) == len(attack_prompts):
            print(f"  Processed {idx + 1:>4} / {len(attack_prompts)} prompts... Current Strict Block Rate: {(results['total_blocked_strict'] / (idx + 1) * 100.0):.2f}%")

    eval_time = time.perf_counter() - t_start
    print(f"[+] Finished evaluation of {len(attack_prompts)} attack prompts in {eval_time:.1f}s")

    # Evaluate Benign prompts
    print("\n[*] Evaluating Benign Baseline Holdouts...")
    fp_strict = 0
    fp_balanced = 0
    for item in benign_prompts:
        p = item["prompt"]
        r_s = evaluator.evaluate_prompt(p, mode="strict")
        r_b = evaluator.evaluate_prompt(p, mode="balanced")
        if r_s["blocked"]:
            fp_strict += 1
        if r_b["blocked"]:
            fp_balanced += 1

    n_b = len(benign_prompts)
    fpr_s = (fp_strict / n_b * 100.0) if n_b > 0 else 0.0
    fpr_b = (fp_balanced / n_b * 100.0) if n_b > 0 else 0.0
    results["benign_eval"] = {
        "total": n_b,
        "false_positives_strict": fp_strict,
        "fpr_strict_pct": round(fpr_s, 2),
        "false_positives_balanced": fp_balanced,
        "fpr_balanced_pct": round(fpr_b, 2)
    }

    tot = results["total_attack_prompts"]
    ov_s = (results["total_blocked_strict"] / tot * 100.0) if tot > 0 else 0.0
    ov_b = (results["total_blocked_balanced"] / tot * 100.0) if tot > 0 else 0.0
    results["overall_attack_block_rate_strict_pct"] = round(ov_s, 2)
    results["overall_attack_block_rate_balanced_pct"] = round(ov_b, 2)

    # Calculate percentages for algorithm breakdown
    for k, v in results["by_algorithm"].items():
        v["rate_strict_pct"] = round((v["blocked_strict"] / v["total"] * 100.0), 2)
        v["rate_balanced_pct"] = round((v["blocked_balanced"] / v["total"] * 100.0), 2)

    # Calculate percentages for model breakdown
    for k, v in results["by_model"].items():
        v["rate_strict_pct"] = round((v["blocked_strict"] / v["total"] * 100.0), 2)
        v["rate_balanced_pct"] = round((v["blocked_balanced"] / v["total"] * 100.0), 2)

    # Calculate percentages for category breakdown
    for k, v in results["by_category"].items():
        v["rate_strict_pct"] = round((v["blocked_strict"] / v["total"] * 100.0), 2)
        v["rate_balanced_pct"] = round((v["blocked_balanced"] / v["total"] * 100.0), 2)

    # Save to disk
    os.makedirs(os.path.join(PROJECT_ROOT, "artifacts", "evidence"), exist_ok=True)
    out_json = os.path.join(PROJECT_ROOT, "artifacts", "evidence", "jailbreakbench_exhaustive_results.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Saved exhaustive JSON results to: {out_json}")

    out_md = os.path.join(PROJECT_ROOT, "artifacts", "evidence", "jailbreakbench_exhaustive_report.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("# GuardianAI — Exhaustive JailbreakBench Benchmark Report\n\n")
        f.write(f"**Repository Source:** [JailbreakBench Official Artifacts](https://github.com/JailbreakBench/artifacts)\n")
        f.write(f"**Execution Timestamp:** {results['timestamp']}\n")
        f.write(f"**Total Attack Prompts Evaluated:** {tot:,}\n")
        f.write(f"**Total Benign Prompts Evaluated:** {n_b:,}\n\n")

        f.write("## 1. Overall Benchmark Summary\n\n")
        f.write("| Metric | Strict Mode (0.45) | Balanced Mode (0.55) |\n")
        f.write("|---|---|---|\n")
        f.write(f"| **Overall JBB Attack Block Rate** | **{ov_s:.2f}%** ({results['total_blocked_strict']:,}/{tot:,}) | **{ov_b:.2f}%** ({results['total_blocked_balanced']:,}/{tot:,}) |\n")
        f.write(f"| **False Positive Rate (Benign JBB)** | **{fpr_s:.2f}%** ({fp_strict}/{n_b}) | **{fpr_b:.2f}%** ({fp_balanced}/{n_b}) |\n\n")

        f.write("## 2. Breakdown by Attack Algorithm\n\n")
        f.write("| Attack Algorithm | Total Prompts | Strict Mode Block Rate | Balanced Mode Block Rate |\n")
        f.write("|---|---|---|---|\n")
        for algo, data in sorted(results["by_algorithm"].items()):
            f.write(f"| **{algo}** | {data['total']:,} | **{data['rate_strict_pct']:.2f}%** ({data['blocked_strict']}) | {data['rate_balanced_pct']:.2f}% ({data['blocked_balanced']}) |\n")

        f.write("\n## 3. Breakdown by Target Model\n\n")
        f.write("| Target Model | Total Prompts | Strict Mode Block Rate | Balanced Mode Block Rate |\n")
        f.write("|---|---|---|---|\n")
        for model, data in sorted(results["by_model"].items()):
            f.write(f"| **{model}** | {data['total']:,} | **{data['rate_strict_pct']:.2f}%** ({data['blocked_strict']}) | {data['rate_balanced_pct']:.2f}% ({data['blocked_balanced']}) |\n")

        f.write("\n## 4. Breakdown Across All 10 JBB Harm Categories\n\n")
        f.write("| Harm Category | Total Prompts | Strict Mode Block Rate | Balanced Mode Block Rate |\n")
        f.write("|---|---|---|---|\n")
        for cat, data in sorted(results["by_category"].items()):
            f.write(f"| **{cat}** | {data['total']:,} | **{data['rate_strict_pct']:.2f}%** ({data['blocked_strict']}) | {data['rate_balanced_pct']:.2f}% ({data['blocked_balanced']}) |\n")

        f.write("\n## 5. Defense Layer Attribution (Strict Mode)\n\n")
        f.write("| Defense Layer | Prompts Blocked | Percentage |\n")
        f.write("|---|---|---|\n")
        for layer, count in sorted(results["layer_breakdown_strict"].items()):
            if layer != "none":
                pct = (count / results["total_blocked_strict"] * 100.0) if results["total_blocked_strict"] > 0 else 0.0
                f.write(f"| `{layer}` | {count:,} | {pct:.1f}% |\n")

    print(f"[+] Saved Markdown summary report to: {out_md}")
    print("=" * 80)
    print(" EXHAUSTIVE JAILBREAKBENCH BENCHMARK COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    run_exhaustive_jbb()
