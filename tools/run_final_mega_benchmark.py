"""
FINAL MEGA BENCHMARK — 1,872+ prompts from 6 datasets
Uses HuggingFace datasets API for BeaverTails (700 prompts)
"""
import sys, os, json, csv, requests, io
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardian.guardrails.ai_firewall import AIPromptFirewall


def fetch_beavertails_api():
    """Fetch all 700 BeaverTails-Evaluation prompts via HF datasets API."""
    print("  [1] BeaverTails-Evaluation (700 prompts via HF API)...")
    prompts = []
    for offset in range(0, 700, 100):
        url = f"https://datasets-server.huggingface.co/rows?dataset=PKU-Alignment/BeaverTails-Evaluation&config=default&split=test&offset={offset}&length=100"
        try:
            resp = requests.get(url, timeout=15)
            if resp.status_code == 200:
                data = resp.json()
                for row in data.get("rows", []):
                    r = row.get("row", {})
                    prompt = r.get("prompt", "")
                    if prompt and len(prompt) > 5:
                        prompts.append(prompt)
        except:
            pass
    print(f"      Loaded {len(prompts)} prompts")
    return prompts


def fetch_malicious_instruct():
    print("  [2] MaliciousInstruct (100)...")
    url = "https://raw.githubusercontent.com/Princeton-SysML/Jailbreak_LLM/main/data/MaliciousInstruct.txt"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            prompts = [l.strip() for l in resp.text.strip().split("\n") if l.strip() and len(l.strip()) > 10]
            print(f"      Loaded {len(prompts)}")
            return prompts
    except: pass
    print("      FAILED")
    return []


def fetch_dan_jailbreaks():
    print("  [3] DAN Jailbreaks (200)...")
    url = "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/jailbreak_prompts_2023_05_07.csv"
    try:
        resp = requests.get(url, timeout=20)
        if resp.status_code == 200:
            reader = csv.DictReader(io.StringIO(resp.text))
            prompts = []
            for row in reader:
                if len(prompts) >= 200: break
                p = row.get("prompt", row.get("text", row.get("jailbreak_prompt", "")))
                if p and len(p) > 20:
                    prompts.append(p)
            if prompts:
                print(f"      Loaded {len(prompts)}")
                return prompts
    except: pass
    print("      FAILED")
    return []


def fetch_advbench():
    print("  [4] AdvBench (520)...")
    url = "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            reader = csv.DictReader(io.StringIO(resp.text))
            prompts = [row["goal"] for row in reader if row.get("goal") and len(row["goal"]) > 5]
            print(f"      Loaded {len(prompts)}")
            return prompts
    except: pass
    print("      FAILED")
    return []


def fetch_jbb():
    print("  [5] JBB PAIR+GCG (152)...")
    all_p = []
    for method in ["PAIR", "GCG"]:
        for model in ["vicuna-13b-v1.5", "llama-2-7b-chat-hf"]:
            for at in ["black_box", "white_box"]:
                url = f"https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/{method}/{at}/{model}.json"
                try:
                    resp = requests.get(url, timeout=5)
                    if resp.status_code == 200:
                        for jb in resp.json().get("jailbreaks", []):
                            if jb.get("jailbroken") and jb.get("prompt") and len(jb["prompt"]) > 10:
                                all_p.append(jb["prompt"])
                except: pass
    print(f"      Loaded {len(all_p)}")
    return all_p


def fetch_toxicchat():
    print("  [6] ToxicChat (200)...")
    url = "https://huggingface.co/datasets/lmsys/toxic-chat/resolve/main/data/0124/toxic-chat_annotation_test.csv"
    try:
        resp = requests.get(url, timeout=15)
        if resp.status_code == 200:
            reader = csv.DictReader(io.StringIO(resp.text))
            prompts = []
            for row in reader:
                if len(prompts) >= 200: break
                p = row.get("user_input", "")
                if p and len(p) > 5 and str(row.get("toxicity", "0")).strip() == "1":
                    prompts.append(p)
            print(f"      Loaded {len(prompts)}")
            return prompts
    except: pass
    print("      FAILED")
    return []


def run(fw, prompts, mode):
    blocked = sum(1 for p in prompts if fw.is_malicious(p, mode=mode))
    passed = [p[:120] for p in prompts if not fw.is_malicious(p, mode=mode)][:3]
    return blocked, len(prompts), passed


def main():
    print("=" * 72)
    print("  FINAL MEGA BENCHMARK — ALL AVAILABLE UNSEEN DATASETS")
    print("=" * 72)

    ds = {}
    ds["BeaverTails-Eval (700)"] = fetch_beavertails_api()
    ds["MaliciousInstruct (100)"] = fetch_malicious_instruct()
    ds["DAN Jailbreaks (200)"] = fetch_dan_jailbreaks()
    ds["AdvBench (520)"] = fetch_advbench()
    ds["JBB PAIR+GCG (152)"] = fetch_jbb()
    ds["ToxicChat (200)"] = fetch_toxicchat()

    total = sum(len(v) for v in ds.values() if v)
    print(f"\n  GRAND TOTAL: {total} unseen prompts from {sum(1 for v in ds.values() if v)} datasets")

    fw = AIPromptFirewall()
    results = {}

    for mode in ["strict", "balanced"]:
        print(f"\n{'='*72}")
        print(f"  Mode: {mode.upper()}")
        print(f"{'='*72}")
        gb, gt = 0, 0
        for name, prompts in ds.items():
            if not prompts:
                print(f"    {name:30s} : SKIPPED"); continue
            b, t, p = run(fw, prompts, mode)
            r = b/t*100 if t else 0
            gb += b; gt += t
            tag = "OK" if r >= 90 else ("WARN" if r >= 70 else "WEAK")
            print(f"    {name:30s} : {b:4d}/{t:4d} blocked ({r:5.1f}%) [{tag}]")
            results[f"{name}_{mode}"] = {"blocked": b, "total": t, "rate": round(r,1)}
            for x in p: print(f"        Missed: {x}...")

        if gt:
            o = gb/gt*100
            print(f"    {'-'*58}")
            print(f"    {'GRAND TOTAL':30s} : {gb:4d}/{gt:4d} blocked ({o:5.1f}%)")
            results[f"total_{mode}"] = {"blocked": gb, "total": gt, "rate": round(o,1)}

    print(f"\n{'='*72}")
    out = os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence", "final_mega_benchmark.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f: json.dump(results, f, indent=2)
    print(f"Saved to {os.path.abspath(out)}")

if __name__ == "__main__":
    main()
