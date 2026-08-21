#!/usr/bin/env python3
"""
Live & Unseen Multi-Source Benchmark for GuardianAI Security Control Plane
Fetches live data from Hugging Face and GitHub, runs empirical evaluations,
and records comprehensive proof and telemetry.
"""

import os
import sys
import json
import time
import urllib.request
import urllib.parse
import csv
import io
import concurrent.futures
from typing import List, Dict, Any, Optional

# Ensure project root is on sys.path
PROJECT_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
if PROJECT_ROOT not in sys.path:
    sys.path.insert(0, PROJECT_ROOT)
if os.path.join(PROJECT_ROOT, "guardian") not in sys.path:
    sys.path.insert(0, os.path.join(PROJECT_ROOT, "guardian"))

from guardian.guardrails.input_filter import InputFilter
from guardian.guardrails.ai_firewall import AIPromptFirewall
from guardian.guardrails.encoding_detector import EncodingDetector
from guardian.guardrails.system_prompt_guard import _LEAK_PATTERNS

# Headers for HTTP requests
HEADERS = {
    "User-Agent": "GuardianAI-Empirical-Benchmark/1.0 (Security-Testing; +https://github.com/guardianai)"
}

def fetch_json(url: str, timeout: int = 15) -> Optional[Dict[str, Any]]:
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except Exception as e:
        print(f"[-] Failed to fetch JSON from {url}: {e}", file=sys.stderr)
        return None

def fetch_text(url: str, timeout: int = 15) -> Optional[str]:
    req = urllib.request.Request(url, headers=HEADERS)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        print(f"[-] Failed to fetch text from {url}: {e}", file=sys.stderr)
        return None

# ------------------------------------------------------------------------------
# 1. Dataset Fetchers (Hugging Face + GitHub)
# ------------------------------------------------------------------------------

def fetch_hf_prompt_injections(limit: int = 100) -> tuple[List[str], List[str]]:
    """Fetches real prompt injection and safe prompts from deepset/prompt-injections on HuggingFace."""
    url = f"https://datasets-server.huggingface.co/rows?dataset=deepset/prompt-injections&config=default&split=train&offset=0&limit={limit}"
    data = fetch_json(url)
    attacks, safes = [], []
    if data and "rows" in data:
        for item in data["rows"]:
            row = item.get("row", {})
            text = row.get("text", "").strip()
            label = row.get("label", None)
            if not text:
                continue
            if label == 1:
                attacks.append(text)
            elif label == 0:
                safes.append(text)
    print(f"[+] HuggingFace deepset/prompt-injections: fetched {len(attacks)} attacks, {len(safes)} safe prompts")
    return attacks, safes

def fetch_hf_jailbreak_prompts(limit: int = 100) -> List[str]:
    """Fetches real jailbreak prompts from rubend18/ChatGPT-Jailbreak-Prompts on HuggingFace."""
    url = f"https://datasets-server.huggingface.co/rows?dataset=rubend18/ChatGPT-Jailbreak-Prompts&config=default&split=train&offset=0&limit={limit}"
    data = fetch_json(url)
    prompts = []
    if data and "rows" in data:
        for item in data["rows"]:
            row = item.get("row", {})
            text = row.get("Prompt", row.get("text", "")).strip()
            if text:
                prompts.append(text)
    print(f"[+] HuggingFace rubend18/ChatGPT-Jailbreak-Prompts: fetched {len(prompts)} jailbreaks")
    return prompts

def fetch_hf_jailbreak_classification(limit: int = 100) -> tuple[List[str], List[str]]:
    """Fetches jailbreak and benign prompts from jackhhao/jailbreak-classification on HuggingFace."""
    url = f"https://datasets-server.huggingface.co/rows?dataset=jackhhao/jailbreak-classification&config=default&split=train&offset=0&limit={limit}"
    data = fetch_json(url)
    attacks, safes = [], []
    if data and "rows" in data:
        for item in data["rows"]:
            row = item.get("row", {})
            text = row.get("prompt", "").strip()
            t_type = row.get("type", "").lower()
            if not text:
                continue
            if "jailbreak" in t_type or "attack" in t_type:
                attacks.append(text)
            elif "benign" in t_type or "safe" in t_type:
                safes.append(text)
    print(f"[+] HuggingFace jackhhao/jailbreak-classification: fetched {len(attacks)} attacks, {len(safes)} safe prompts")
    return attacks, safes

def fetch_hf_alpaca_safe(limit: int = 100) -> List[str]:
    """Fetches benign / safe instruction prompts from tatsu-lab/alpaca on HuggingFace."""
    url = f"https://datasets-server.huggingface.co/rows?dataset=tatsu-lab/alpaca&config=default&split=train&offset=0&limit={limit}"
    data = fetch_json(url)
    prompts = []
    if data and "rows" in data:
        for item in data["rows"]:
            row = item.get("row", {})
            instr = row.get("instruction", "").strip()
            inp = row.get("input", "").strip()
            text = f"{instr} {inp}".strip()
            if text:
                prompts.append(text)
    print(f"[+] HuggingFace tatsu-lab/alpaca: fetched {len(prompts)} benign prompts")
    return prompts

def fetch_github_advbench() -> List[str]:
    """Fetches AdvBench harmful behaviors dataset from llm-attacks GitHub repo."""
    url = "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv"
    content = fetch_text(url)
    prompts = []
    if content:
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            goal = row.get("goal", "").strip()
            if goal:
                prompts.append(goal)
    print(f"[+] GitHub llm-attacks/AdvBench: fetched {len(prompts)} harmful prompts")
    return prompts

def fetch_github_harmbench() -> List[str]:
    """Fetches HarmBench behaviors dataset from centerforaisafety GitHub repo."""
    url = "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_all.csv"
    content = fetch_text(url)
    prompts = []
    if content:
        reader = csv.DictReader(io.StringIO(content))
        for row in reader:
            behavior = row.get("Behavior", row.get("behavior", "")).strip()
            if behavior:
                prompts.append(behavior)
    print(f"[+] GitHub centerforaisafety/HarmBench: fetched {len(prompts)} behaviors")
    return prompts

# ------------------------------------------------------------------------------
# 2. Evaluation Pipeline
# ------------------------------------------------------------------------------

class GuardianEvaluator:
    def __init__(self):
        print("[*] Initializing GuardianAI Security Pipeline...")
        self.input_filter = InputFilter()
        self.firewall = AIPromptFirewall()
        self.encoding_detector = EncodingDetector()
        self.leak_patterns = _LEAK_PATTERNS
        print("[+] Pipeline initialized successfully.")

    def evaluate_prompt(self, prompt: str, mode: str = "strict") -> Dict[str, Any]:
        t0 = time.perf_counter()
        
        # 1. Encoding De-obfuscation Check
        decoded_variants = self.encoding_detector.decode_all(prompt)
        is_obfuscated = len(decoded_variants) > 0
        variants_to_check = [prompt] + decoded_variants

        blocked = False
        blocking_layer = "none"
        is_regex_safe = True
        is_firewall_malicious = False
        system_leak_detected = False
        sim_score = 0.0

        for text_variant in variants_to_check:
            # 2. Input Filter (Fast-path Regex)
            if not self.input_filter.check_prompt(text_variant):
                is_regex_safe = False
                blocked = True
                blocking_layer = "encoding_deobfuscator" if is_obfuscated else "fast_path_regex"
                break

            # 3. System Prompt Leakage Guard
            for p in self.leak_patterns:
                if p.search(text_variant):
                    system_leak_detected = True
                    blocked = True
                    blocking_layer = "system_prompt_guard"
                    break
            if blocked:
                break

            # 4. Semantic Firewall (SentenceTransformers Embedding Similarity)
            if self.firewall.enabled:
                if self.firewall.is_malicious(text_variant, mode=mode):
                    is_firewall_malicious = True
                    blocked = True
                    blocking_layer = "encoding_deobfuscator" if is_obfuscated else "semantic_firewall"
                    break

        # Calculate max similarity score for logging if firewall enabled
        try:
            if hasattr(self.firewall, "model") and hasattr(self.firewall, "bad_embeddings") and self.firewall.model:
                from sklearn.metrics.pairwise import cosine_similarity
                import numpy as np
                emb = self.firewall.model.encode([prompt[:500]])
                sims = cosine_similarity(emb, self.firewall.bad_embeddings)[0]
                sim_score = float(np.max(sims))
        except Exception:
            pass

        latency_ms = (time.perf_counter() - t0) * 1000.0

        return {
            "blocked": blocked,
            "blocking_layer": blocking_layer,
            "regex_safe": is_regex_safe,
            "system_leak": system_leak_detected,
            "firewall_malicious": is_firewall_malicious,
            "semantic_score": round(sim_score, 4),
            "is_obfuscated": is_obfuscated,
            "latency_ms": round(latency_ms, 2)
        }

# ------------------------------------------------------------------------------
# 3. Performance & Throughput Benchmark
# ------------------------------------------------------------------------------

def measure_throughput_and_latency(evaluator: GuardianEvaluator, prompts: List[str], concurrency: int = 10, mode: str = "strict") -> Dict[str, Any]:
    latencies = []
    t_start = time.perf_counter()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as executor:
        futures = [executor.submit(evaluator.evaluate_prompt, p, mode) for p in prompts]
        for f in concurrent.futures.as_completed(futures):
            res = f.result()
            latencies.append(res["latency_ms"])
            
    total_time = time.perf_counter() - t_start
    rps = len(prompts) / total_time if total_time > 0 else 0.0
    
    latencies.sort()
    p50 = latencies[int(len(latencies) * 0.50)] if latencies else 0.0
    p90 = latencies[int(len(latencies) * 0.90)] if latencies else 0.0
    p95 = latencies[int(len(latencies) * 0.95)] if latencies else 0.0
    p99 = latencies[int(len(latencies) * 0.99)] if latencies else 0.0

    return {
        "count": len(prompts),
        "concurrency": concurrency,
        "total_time_sec": round(total_time, 2),
        "throughput_rps": round(rps, 2),
        "latency_p50_ms": round(p50, 2),
        "latency_p90_ms": round(p90, 2),
        "latency_p95_ms": round(p95, 2),
        "latency_p99_ms": round(p99, 2),
    }

# ------------------------------------------------------------------------------
# 4. Main Execution Routine
# ------------------------------------------------------------------------------

def run_live_benchmark():
    print("=" * 80)
    print(" GUARDIANAI LIVE & UNSEEN MULTI-SOURCE BENCHMARK (Hugging Face + GitHub)")
    print("=" * 80)
    
    evaluator = GuardianEvaluator()
    
    # 1. Fetch Datasets
    print("\n[*] Fetching Real-Time Datasets from Hugging Face & GitHub...")
    hf_injections, hf_safe_pi = fetch_hf_prompt_injections(limit=100)
    hf_jailbreaks = fetch_hf_jailbreak_prompts(limit=100)
    hf_jb_class_attacks, hf_jb_class_safes = fetch_hf_jailbreak_classification(limit=100)
    hf_alpaca_safe = fetch_hf_alpaca_safe(limit=100)
    gh_advbench = fetch_github_advbench()
    gh_harmbench = fetch_github_harmbench()

    # Combine attack datasets
    attack_datasets = {
        "HF_Prompt_Injections": hf_injections,
        "HF_ChatGPT_Jailbreaks": hf_jailbreaks,
        "HF_Jailbreak_Classification": hf_jb_class_attacks,
        "GitHub_AdvBench_Harmful": gh_advbench,
        "GitHub_HarmBench_Official": gh_harmbench,
    }

    # Combine safe datasets
    safe_datasets = {
        "HF_Safe_Prompts_PI": hf_safe_pi,
        "HF_Jailbreak_Classification_Benign": hf_jb_class_safes,
        "HF_Alpaca_Benign": hf_alpaca_safe
    }

    results = {
        "timestamp": time.strftime("%Y-%m-%d %H:%M:%SZ", time.gmtime()),
        "summary": {},
        "attack_breakdown": {},
        "safe_breakdown": {},
        "performance": {},
        "samples_evaluated": 0
    }

    print("\n[*] Evaluating Attack Datasets (Strict & Balanced Modes)...")
    total_attacks = 0
    total_blocked_strict = 0
    total_blocked_balanced = 0

    all_attack_prompts = []
    layer_counts_strict = {"fast_path_regex": 0, "semantic_firewall": 0, "encoding_deobfuscator": 0, "system_prompt_guard": 0, "none": 0}

    for name, prompts in attack_datasets.items():
        if not prompts:
            print(f"[-] Skipping empty dataset {name}")
            continue
            
        all_attack_prompts.extend(prompts)
        n = len(prompts)
        blocked_strict = 0
        blocked_balanced = 0
        ds_layer_counts = {"fast_path_regex": 0, "semantic_firewall": 0, "encoding_deobfuscator": 0, "system_prompt_guard": 0, "none": 0}

        for p in prompts:
            res_strict = evaluator.evaluate_prompt(p, mode="strict")
            res_balanced = evaluator.evaluate_prompt(p, mode="balanced")
            
            if res_strict["blocked"]:
                blocked_strict += 1
                layer_counts_strict[res_strict["blocking_layer"]] += 1
                ds_layer_counts[res_strict["blocking_layer"]] += 1
            else:
                layer_counts_strict["none"] += 1
                ds_layer_counts["none"] += 1

            if res_balanced["blocked"]:
                blocked_balanced += 1

        rate_strict = (blocked_strict / n) * 100.0 if n > 0 else 0.0
        rate_balanced = (blocked_balanced / n) * 100.0 if n > 0 else 0.0

        total_attacks += n
        total_blocked_strict += blocked_strict
        total_blocked_balanced += blocked_balanced

        results["attack_breakdown"][name] = {
            "total": n,
            "blocked_strict": blocked_strict,
            "rate_strict_pct": round(rate_strict, 2),
            "blocked_balanced": blocked_balanced,
            "rate_balanced_pct": round(rate_balanced, 2),
            "layers_strict": ds_layer_counts
        }
        print(f"  -> {name:<35} Total: {n:>4} | Strict: {rate_strict:>6.2f}% ({blocked_strict}/{n}) | Balanced: {rate_balanced:>6.2f}% ({blocked_balanced}/{n})")

    # 2. Evaluate Safe Datasets (False Positive Test)
    print("\n[*] Evaluating Safe / Benign Datasets (False Positive Test)...")
    total_safe = 0
    total_false_positives_strict = 0
    total_false_positives_balanced = 0
    all_safe_prompts = []

    for name, prompts in safe_datasets.items():
        if not prompts:
            continue
        all_safe_prompts.extend(prompts)
        n = len(prompts)
        fp_strict = 0
        fp_balanced = 0

        for p in prompts:
            res_strict = evaluator.evaluate_prompt(p, mode="strict")
            res_balanced = evaluator.evaluate_prompt(p, mode="balanced")
            if res_strict["blocked"]:
                fp_strict += 1
            if res_balanced["blocked"]:
                fp_balanced += 1

        fpr_strict = (fp_strict / n) * 100.0 if n > 0 else 0.0
        fpr_balanced = (fp_balanced / n) * 100.0 if n > 0 else 0.0

        total_safe += n
        total_false_positives_strict += fp_strict
        total_false_positives_balanced += fp_balanced

        results["safe_breakdown"][name] = {
            "total": n,
            "false_positives_strict": fp_strict,
            "fpr_strict_pct": round(fpr_strict, 2),
            "false_positives_balanced": fp_balanced,
            "fpr_balanced_pct": round(fpr_balanced, 2)
        }
        print(f"  -> {name:<35} Total: {n:>4} | Strict FPR: {fpr_strict:>6.2f}% ({fp_strict}/{n}) | Balanced FPR: {fpr_balanced:>6.2f}% ({fp_balanced}/{n})")

    # 3. Overall Summaries
    overall_strict_rate = (total_blocked_strict / total_attacks * 100.0) if total_attacks > 0 else 0.0
    overall_balanced_rate = (total_blocked_balanced / total_attacks * 100.0) if total_attacks > 0 else 0.0
    overall_fpr_strict = (total_false_positives_strict / total_safe * 100.0) if total_safe > 0 else 0.0
    overall_fpr_balanced = (total_false_positives_balanced / total_safe * 100.0) if total_safe > 0 else 0.0

    results["summary"] = {
        "total_attack_prompts": total_attacks,
        "total_blocked_strict": total_blocked_strict,
        "overall_attack_block_rate_strict_pct": round(overall_strict_rate, 2),
        "total_blocked_balanced": total_blocked_balanced,
        "overall_attack_block_rate_balanced_pct": round(overall_balanced_rate, 2),
        "total_safe_prompts": total_safe,
        "total_false_positives_strict": total_false_positives_strict,
        "overall_false_positive_rate_strict_pct": round(overall_fpr_strict, 2),
        "total_false_positives_balanced": total_false_positives_balanced,
        "overall_false_positive_rate_balanced_pct": round(overall_fpr_balanced, 2),
        "layer_breakdown_strict": layer_counts_strict
    }

    # 4. Measure Throughput & Latency under concurrent load
    print("\n[*] Measuring Real-Time Throughput & Latency (Concurrency 20)...")
    if all_attack_prompts:
        perf_attack = measure_throughput_and_latency(evaluator, all_attack_prompts[:500], concurrency=20, mode="strict")
        results["performance"]["attack_load"] = perf_attack
        print(f"  -> Attack Load: {perf_attack['throughput_rps']} rps | p50: {perf_attack['latency_p50_ms']}ms | p95: {perf_attack['latency_p95_ms']}ms | p99: {perf_attack['latency_p99_ms']}ms")

    if all_safe_prompts:
        perf_safe = measure_throughput_and_latency(evaluator, all_safe_prompts[:500], concurrency=20, mode="strict")
        results["performance"]["safe_load"] = perf_safe
        print(f"  -> Safe Load:   {perf_safe['throughput_rps']} rps | p50: {perf_safe['latency_p50_ms']}ms | p95: {perf_safe['latency_p95_ms']}ms | p99: {perf_safe['latency_p99_ms']}ms")

    # 5. Save Evidence Files
    os.makedirs(os.path.join(PROJECT_ROOT, "artifacts", "evidence"), exist_ok=True)
    out_json = os.path.join(PROJECT_ROOT, "artifacts", "evidence", "live_unseen_benchmark_results.json")
    with open(out_json, "w", encoding="utf-8") as f:
        json.dump(results, f, indent=2)
    print(f"\n[+] Successfully saved structured benchmark results to: {out_json}")

    # Generate Markdown Report
    out_md = os.path.join(PROJECT_ROOT, "artifacts", "evidence", "live_unseen_benchmark_report.md")
    with open(out_md, "w", encoding="utf-8") as f:
        f.write("# GuardianAI — Live & Unseen Empirical Benchmark Report\n\n")
        f.write(f"**Execution Timestamp:** {results['timestamp']}\n")
        f.write(f"**Total Prompts Evaluated:** {total_attacks + total_safe:,}\n\n")
        
        f.write("## 1. Overall Security Metrics\n\n")
        f.write("| Metric | Strict Mode | Balanced Mode |\n")
        f.write("|---|---|---|\n")
        f.write(f"| **Overall Attack Block Rate** | **{overall_strict_rate:.2f}%** ({total_blocked_strict:,}/{total_attacks:,}) | **{overall_balanced_rate:.2f}%** ({total_blocked_balanced:,}/{total_attacks:,}) |\n")
        f.write(f"| **False Positive Rate (Benign Data)** | **{overall_fpr_strict:.2f}%** ({total_false_positives_strict}/{total_safe}) | **{overall_fpr_balanced:.2f}%** ({total_false_positives_balanced}/{total_safe}) |\n\n")
        
        f.write("## 2. Dataset-by-Dataset Breakdown\n\n")
        f.write("| Dataset | Source | Total Prompts | Strict Block Rate | Balanced Block Rate |\n")
        f.write("|---|---|---|---|---|\n")
        for ds, data in results["attack_breakdown"].items():
            f.write(f"| `{ds}` | {'Hugging Face' if 'HF' in ds else 'GitHub'} | {data['total']:,} | **{data['rate_strict_pct']:.2f}%** ({data['blocked_strict']}) | {data['rate_balanced_pct']:.2f}% ({data['blocked_balanced']}) |\n")
        for ds, data in results["safe_breakdown"].items():
            f.write(f"| `{ds}` (Safe) | Hugging Face | {data['total']:,} | FPR: {data['fpr_strict_pct']:.2f}% ({data['false_positives_strict']}) | FPR: {data['fpr_balanced_pct']:.2f}% ({data['false_positives_balanced']}) |\n")

        f.write("\n## 3. Defense Layer Attribution (Strict Mode)\n\n")
        f.write("| Defense Layer | Prompts Blocked | Percentage of Total Blocks |\n")
        f.write("|---|---|---|\n")
        for layer, count in layer_counts_strict.items():
            if layer != "none":
                pct = (count / total_blocked_strict * 100.0) if total_blocked_strict > 0 else 0.0
                f.write(f"| `{layer}` | {count:,} | {pct:.1f}% |\n")

        if "performance" in results:
            f.write("\n## 4. Live Performance & Latency Telemetry\n\n")
            f.write("| Traffic Load | Throughput | p50 Latency | p90 Latency | p95 Latency | p99 Latency |\n")
            f.write("|---|---|---|---|---|---|\n")
            if "safe_load" in results["performance"]:
                s = results["performance"]["safe_load"]
                f.write(f"| **Safe Traffic Load** | **{s['throughput_rps']} rps** | {s['latency_p50_ms']} ms | {s['latency_p90_ms']} ms | **{s['latency_p95_ms']} ms** | {s['latency_p99_ms']} ms |\n")
            if "attack_load" in results["performance"]:
                a = results["performance"]["attack_load"]
                f.write(f"| **Attack Traffic Load** | **{a['throughput_rps']} rps** | {a['latency_p50_ms']} ms | {a['latency_p90_ms']} ms | **{a['latency_p95_ms']} ms** | {a['latency_p99_ms']} ms |\n")

    print(f"[+] Successfully generated Markdown report at: {out_md}")
    print("\n" + "=" * 80)
    print(" BENCHMARK EXECUTION COMPLETE")
    print("=" * 80)

if __name__ == "__main__":
    run_live_benchmark()
