"""
ULTIMATE UNSEEN BENCHMARK — Every Public Adversarial Dataset
=============================================================
Tests GuardianAI against EVERY publicly available adversarial LLM dataset:

1. AdvBench (520 behaviors) — Original adversarial benchmark
2. StrongREJECT (313 forbidden prompts) — NeurIPS 2024 jailbreak eval
3. XSTest (250 safe prompts) — FALSE POSITIVE test (should NOT block)
4. ToxicChat (subset) — Real toxic user prompts from LMSYS
5. JBB PAIR+GCG (152 attacks) — Algorithmic jailbreaks
6. SALAD-Bench (subset) — Multi-category safety benchmark
7. HarmfulQA — Harmful question-answer pairs
8. CategoricalHarmfulQA — Category-organized harmful prompts
"""
import sys
import os
import json
import csv
import requests
import io
import time

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardian.guardrails.ai_firewall import AIPromptFirewall


def fetch_csv(url, prompt_col, max_rows=None, label_col=None, label_filter=None):
    """Generic CSV fetcher."""
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return []
        reader = csv.DictReader(io.StringIO(resp.text))
        prompts = []
        for row in reader:
            if max_rows and len(prompts) >= max_rows:
                break
            # Try multiple column names
            prompt = ""
            if isinstance(prompt_col, list):
                for col in prompt_col:
                    if col in row and row[col]:
                        prompt = row[col]
                        break
            else:
                prompt = row.get(prompt_col, "")
            if not prompt or len(prompt) < 5:
                continue
            # Optional label filtering (e.g., only toxic=1)
            if label_col and label_filter is not None:
                label = row.get(label_col, "")
                if str(label).strip() != str(label_filter):
                    continue
            prompts.append(prompt)
        return prompts
    except Exception as e:
        return []


def fetch_json_lines(url, prompt_key, max_rows=None, label_key=None, label_filter=None):
    """Fetch JSONL format."""
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code != 200:
            return []
        prompts = []
        for line in resp.text.strip().split("\n"):
            if max_rows and len(prompts) >= max_rows:
                break
            try:
                obj = json.loads(line)
                prompt = obj.get(prompt_key, "")
                if not prompt or len(prompt) < 5:
                    continue
                if label_key and label_filter is not None:
                    if str(obj.get(label_key, "")) != str(label_filter):
                        continue
                prompts.append(prompt)
            except:
                continue
        return prompts
    except:
        return []


def fetch_strongreject():
    """StrongREJECT — 313 forbidden prompts across 6 harm categories."""
    print("  [1/8] StrongREJECT (313 forbidden prompts)...")
    urls = [
        "https://raw.githubusercontent.com/dsbowen/strong_reject/main/strongreject_dataset/strongreject_dataset.csv",
        "https://raw.githubusercontent.com/dsbowen/strong_reject/main/strongreject_dataset.csv",
        "https://raw.githubusercontent.com/dsbowen/strong_reject/main/data/strongreject_dataset.csv",
    ]
    for url in urls:
        prompts = fetch_csv(url, ["forbidden_prompt", "prompt", "question"])
        if prompts:
            print(f"      Loaded {len(prompts)} prompts")
            return prompts
    print("      FAILED")
    return []


def fetch_xstest():
    """XSTest — 250 safe prompts that SHOULD NOT be blocked (false-positive test)."""
    print("  [2/8] XSTest (250 safe prompts — FALSE POSITIVE test)...")
    urls = [
        "https://raw.githubusercontent.com/paul-rottger/xstest/main/xstest_v2_prompts.csv",
        "https://raw.githubusercontent.com/paul-rottger/xstest/main/data/xstest_v2_prompts.csv",
    ]
    for url in urls:
        prompts = fetch_csv(url, ["prompt", "text"])
        if prompts:
            print(f"      Loaded {len(prompts)} prompts")
            return prompts
    print("      FAILED")
    return []


def fetch_advbench():
    """AdvBench — 520 harmful behaviors."""
    print("  [3/8] AdvBench (520 harmful behaviors)...")
    url = "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv"
    prompts = fetch_csv(url, "goal")
    if prompts:
        print(f"      Loaded {len(prompts)} prompts")
    else:
        print("      FAILED")
    return prompts


def fetch_toxicchat():
    """ToxicChat — Real toxic prompts from LMSYS conversations."""
    print("  [4/8] ToxicChat (real toxic user prompts)...")
    urls = [
        "https://huggingface.co/datasets/lmsys/toxic-chat/resolve/main/data/0124/toxic-chat_annotation_test.csv",
        "https://huggingface.co/datasets/lmsys/toxic-chat/resolve/main/toxic-chat_annotation_test.csv",
        "https://huggingface.co/datasets/lmsys/toxic-chat/resolve/main/data/toxic-chat_annotation_test.csv",
    ]
    for url in urls:
        prompts = fetch_csv(url, ["user_input", "prompt", "text"], max_rows=200, label_col="toxicity", label_filter="1")
        if prompts:
            print(f"      Loaded {len(prompts)} toxic prompts")
            return prompts
    # Try JSONL
    jsonl_urls = [
        "https://huggingface.co/datasets/lmsys/toxic-chat/resolve/main/data/0124/toxic-chat_annotation_test.jsonl",
    ]
    for url in jsonl_urls:
        prompts = fetch_json_lines(url, "user_input", max_rows=200, label_key="toxicity", label_filter=1)
        if prompts:
            print(f"      Loaded {len(prompts)} toxic prompts")
            return prompts
    print("      FAILED (may require HF auth)")
    return []


def fetch_jbb_attacks():
    """JBB PAIR+GCG — Real algorithmic jailbreak prompts."""
    print("  [5/8] JBB PAIR+GCG (152 real attacks)...")
    all_prompts = []
    for method in ["PAIR", "GCG"]:
        for model in ["vicuna-13b-v1.5", "llama-2-7b-chat-hf"]:
            for at in ["black_box", "white_box", "transfer"]:
                url = f"https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/{method}/{at}/{model}.json"
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code == 200:
                        data = resp.json()
                        for jb in data.get("jailbreaks", []):
                            if jb.get("jailbroken") and jb.get("prompt") and len(jb["prompt"]) > 10:
                                all_prompts.append(jb["prompt"])
                except:
                    pass
    print(f"      Loaded {len(all_prompts)} successful jailbreaks")
    return all_prompts


def fetch_salad_bench():
    """SALAD-Bench — Multi-category safety benchmark."""
    print("  [6/8] SALAD-Bench (safety alignment)...")
    urls = [
        "https://raw.githubusercontent.com/OpenSafetyLab/SALAD-BENCH/main/data/base_set.csv",
        "https://raw.githubusercontent.com/OpenSafetyLab/SALAD-BENCH/main/data/attack_enhanced_set.csv",
        "https://huggingface.co/datasets/OpenSafetyLab/Salad-Data/resolve/main/salad_bench_base.csv",
    ]
    for url in urls:
        prompts = fetch_csv(url, ["question", "prompt", "text", "instruction"], max_rows=300)
        if prompts:
            print(f"      Loaded {len(prompts)} prompts")
            return prompts
    print("      FAILED")
    return []


def fetch_harmful_qa():
    """HarmfulQA — Harmful question-answer dataset."""
    print("  [7/8] HarmfulQA (harmful questions)...")
    urls = [
        "https://raw.githubusercontent.com/declare-lab/HarmfulQA/main/data/harmful_questions.csv",
        "https://huggingface.co/datasets/declare-lab/HarmfulQA/resolve/main/data/harmful_questions.csv",
    ]
    for url in urls:
        prompts = fetch_csv(url, ["question", "prompt", "text"], max_rows=200)
        if prompts:
            print(f"      Loaded {len(prompts)} prompts")
            return prompts
    print("      FAILED")
    return []


def fetch_categorical_harmful():
    """CategoricalHarmfulQA — Category-organized harmful prompts."""
    print("  [8/8] CategoricalHarmfulQA...")
    urls = [
        "https://raw.githubusercontent.com/declare-lab/HarmfulQA/main/data/category_questions.csv",
        "https://huggingface.co/datasets/declare-lab/CategoricalHarmfulQA/resolve/main/data/category_questions.csv",
    ]
    for url in urls:
        prompts = fetch_csv(url, ["question", "prompt", "text"], max_rows=200)
        if prompts:
            print(f"      Loaded {len(prompts)} prompts")
            return prompts
    print("      FAILED")
    return []


def run_test(fw, prompts, mode):
    """Run firewall test, return (blocked, total, samples_passed)."""
    blocked = 0
    passed_samples = []
    for p in prompts:
        if fw.is_malicious(p, mode=mode):
            blocked += 1
        elif len(passed_samples) < 5:
            passed_samples.append(p[:120])
    return blocked, len(prompts), passed_samples


def main():
    print("=" * 72)
    print("  ULTIMATE UNSEEN BENCHMARK")
    print("  Testing against EVERY public adversarial dataset available")
    print("  (NONE used during firewall calibration)")
    print("=" * 72)
    print()

    # Fetch all datasets
    datasets = {}

    # Harmful prompt datasets (should be BLOCKED)
    datasets["AdvBench (520)"] = {"prompts": fetch_advbench(), "type": "harmful"}
    datasets["StrongREJECT (313)"] = {"prompts": fetch_strongreject(), "type": "harmful"}
    datasets["JBB PAIR+GCG"] = {"prompts": fetch_jbb_attacks(), "type": "harmful"}
    datasets["ToxicChat"] = {"prompts": fetch_toxicchat(), "type": "harmful"}
    datasets["SALAD-Bench"] = {"prompts": fetch_salad_bench(), "type": "harmful"}
    datasets["HarmfulQA"] = {"prompts": fetch_harmful_qa(), "type": "harmful"}
    datasets["CategoricalHarmfulQA"] = {"prompts": fetch_categorical_harmful(), "type": "harmful"}

    # Safe prompt dataset (should NOT be blocked)
    datasets["XSTest (safe)"] = {"prompts": fetch_xstest(), "type": "safe"}

    total_harmful = sum(len(d["prompts"]) for d in datasets.values() if d["type"] == "harmful" and d["prompts"])
    total_safe = sum(len(d["prompts"]) for d in datasets.values() if d["type"] == "safe" and d["prompts"])
    print(f"\n  Total harmful prompts to test: {total_harmful}")
    print(f"  Total safe prompts to test: {total_safe}")
    print(f"  Grand total: {total_harmful + total_safe}")

    # Init firewall
    print("\nInitializing firewall (loading ML model)...")
    fw = AIPromptFirewall()

    all_results = {}

    for mode in ["strict", "balanced"]:
        print(f"\n{'='*72}")
        print(f"  RESULTS - Mode: {mode.upper()}")
        print(f"{'='*72}")

        # Harmful prompts (want high block rate)
        print(f"\n  --- HARMFUL PROMPTS (should be BLOCKED) ---")
        total_blocked = 0
        total_count = 0
        for name, data in datasets.items():
            if data["type"] != "harmful" or not data["prompts"]:
                if data["type"] == "harmful":
                    print(f"    {name:30s} : SKIPPED")
                continue
            blocked, total, passed = run_test(fw, data["prompts"], mode)
            rate = blocked / total * 100
            total_blocked += blocked
            total_count += total
            print(f"    {name:30s} : {blocked:4d}/{total:4d} blocked ({rate:5.1f}%)")
            all_results[f"{name}_{mode}"] = {"blocked": blocked, "total": total, "rate": round(rate, 1)}
            if passed:
                for p in passed[:2]:
                    print(f"        Missed: {p}...")

        if total_count > 0:
            overall_block = total_blocked / total_count * 100
            print(f"    {'-'*55}")
            print(f"    {'HARMFUL TOTAL':30s} : {total_blocked:4d}/{total_count:4d} blocked ({overall_block:5.1f}%)")
            all_results[f"harmful_total_{mode}"] = {"blocked": total_blocked, "total": total_count, "rate": round(overall_block, 1)}

        # Safe prompts (want low false-positive rate)
        print(f"\n  --- SAFE PROMPTS (should NOT be blocked) ---")
        total_fp = 0
        total_safe_count = 0
        for name, data in datasets.items():
            if data["type"] != "safe" or not data["prompts"]:
                continue
            blocked, total, _ = run_test(fw, data["prompts"], mode)
            fp_rate = blocked / total * 100
            total_fp += blocked
            total_safe_count += total
            print(f"    {name:30s} : {blocked:4d}/{total:4d} false positives ({fp_rate:5.1f}%)")
            all_results[f"{name}_{mode}_fp"] = {"false_positives": blocked, "total": total, "fp_rate": round(fp_rate, 1)}

        if total_safe_count > 0:
            overall_fp = total_fp / total_safe_count * 100
            print(f"    {'-'*55}")
            print(f"    {'FP TOTAL':30s} : {total_fp:4d}/{total_safe_count:4d} false positives ({overall_fp:5.1f}%)")
            all_results[f"safe_fp_total_{mode}"] = {"false_positives": total_fp, "total": total_safe_count, "fp_rate": round(overall_fp, 1)}

    print(f"\n{'='*72}")

    # Save results
    out_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence"))
    os.makedirs(out_dir, exist_ok=True)
    out_file = os.path.join(out_dir, "ultimate_unseen_benchmark.json")
    with open(out_file, "w", encoding="utf-8") as f:
        json.dump(all_results, f, indent=2)
    print(f"\nResults saved to {out_file}")


if __name__ == "__main__":
    main()
