"""
EXPANDED MEGA BENCHMARK v3 — 4 NEW datasets added
=====================================================
NEW datasets not previously tested:
1. HarmBench Official (test+val) — centerforaisafety, 400+ behaviors
2. TDC2023 Red Teaming — Trojan Detection Challenge prompts
3. RealToxicityPrompts (high-toxicity subset) — allenai, 100K prompts

Plus all 6 existing datasets from v2.
"""
import sys, os, json, csv, requests, io
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardian.guardrails.ai_firewall import AIPromptFirewall


def fetch_url(url, timeout=15):
    try:
        r = requests.get(url, timeout=timeout)
        return r if r.status_code == 200 else None
    except:
        return None


def fetch_harmbench_official():
    """HarmBench official — 400+ behaviors from centerforaisafety."""
    print("  [NEW-1] HarmBench Official (test+val)...")
    prompts = []
    for f in ["harmbench_behaviors_text_test.csv", "harmbench_behaviors_text_val.csv"]:
        url = f"https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/{f}"
        resp = fetch_url(url)
        if resp:
            reader = csv.DictReader(io.StringIO(resp.text))
            for row in reader:
                b = row.get("Behavior", row.get("behavior", row.get("goal", "")))
                if b and len(b) > 10:
                    prompts.append(b)
    if prompts:
        print(f"      Loaded {len(prompts)} behaviors")
    else:
        # Try alternate column names
        url = "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_all.csv"
        resp = fetch_url(url)
        if resp:
            reader = csv.DictReader(io.StringIO(resp.text))
            for row in reader:
                for col in ["Behavior", "behavior", "goal", "Goal", "prompt"]:
                    if col in row and row[col] and len(row[col]) > 10:
                        prompts.append(row[col])
                        break
            print(f"      Loaded {len(prompts)} behaviors (all)")
        else:
            print("      FAILED")
    return prompts


def fetch_tdc_redteam():
    """TDC2023 Red Teaming — Trojan Detection Challenge."""
    print("  [NEW-2] TDC2023 Red Teaming...")
    urls = [
        "https://raw.githubusercontent.com/centerforaisafety/tdc2023-starter-kit/main/red_teaming/data/behaviors.csv",
        "https://raw.githubusercontent.com/centerforaisafety/tdc2023-starter-kit/main/data/red_teaming/behaviors.csv",
        "https://raw.githubusercontent.com/centerforaisafety/tdc2023-starter-kit/main/red_teaming/behaviors.csv",
    ]
    for url in urls:
        resp = fetch_url(url)
        if resp:
            reader = csv.DictReader(io.StringIO(resp.text))
            prompts = []
            for row in reader:
                for col in ["Behavior", "behavior", "goal", "Goal"]:
                    if col in row and row[col] and len(row[col]) > 10:
                        prompts.append(row[col])
                        break
            if prompts:
                print(f"      Loaded {len(prompts)} behaviors")
                return prompts
    print("      FAILED")
    return []


def fetch_realtoxicity():
    """RealToxicityPrompts — high-toxicity subset via HF API."""
    print("  [NEW-3] RealToxicityPrompts (high-toxicity)...")
    prompts = []
    for offset in range(0, 500, 100):
        url = f"https://datasets-server.huggingface.co/rows?dataset=allenai/real-toxicity-prompts&config=default&split=train&offset={offset}&length=100"
        resp = fetch_url(url)
        if not resp:
            break
        try:
            data = resp.json()
            for row in data.get("rows", []):
                r = row.get("row", {})
                prompt_data = r.get("prompt", {})
                if isinstance(prompt_data, dict):
                    text = prompt_data.get("text", "")
                    toxicity = prompt_data.get("toxicity", 0)
                    if text and toxicity and float(toxicity) >= 0.8 and len(text) > 10:
                        prompts.append(text)
                elif isinstance(prompt_data, str) and len(prompt_data) > 10:
                    prompts.append(prompt_data)
        except:
            pass
    if prompts:
        print(f"      Loaded {len(prompts)} high-toxicity prompts")
    else:
        print("      FAILED")
    return prompts


def fetch_beavertails():
    print("  [6] BeaverTails-Eval (700)...")
    prompts = []
    for offset in range(0, 700, 100):
        url = f"https://datasets-server.huggingface.co/rows?dataset=PKU-Alignment/BeaverTails-Evaluation&config=default&split=test&offset={offset}&length=100"
        resp = fetch_url(url)
        if resp:
            try:
                for row in resp.json().get("rows", []):
                    p = row.get("row", {}).get("prompt", "")
                    if p and len(p) > 5: prompts.append(p)
            except: pass
    print(f"      Loaded {len(prompts)}")
    return prompts


def fetch_malicious():
    print("  [7] MaliciousInstruct (100)...")
    resp = fetch_url("https://raw.githubusercontent.com/Princeton-SysML/Jailbreak_LLM/main/data/MaliciousInstruct.txt")
    if resp:
        p = [l.strip() for l in resp.text.strip().split("\n") if l.strip() and len(l.strip()) > 10]
        print(f"      Loaded {len(p)}"); return p
    print("      FAILED"); return []


def fetch_dan():
    print("  [8] DAN Jailbreaks (200)...")
    resp = fetch_url("https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/jailbreak_prompts_2023_05_07.csv", 20)
    if resp:
        reader = csv.DictReader(io.StringIO(resp.text))
        p = []
        for row in reader:
            if len(p) >= 200: break
            t = row.get("prompt", row.get("text", ""))
            if t and len(t) > 20: p.append(t)
        print(f"      Loaded {len(p)}"); return p
    print("      FAILED"); return []


def fetch_advbench():
    print("  [9] AdvBench (520)...")
    resp = fetch_url("https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv")
    if resp:
        p = [r["goal"] for r in csv.DictReader(io.StringIO(resp.text)) if r.get("goal") and len(r["goal"]) > 5]
        print(f"      Loaded {len(p)}"); return p
    print("      FAILED"); return []


def fetch_jbb():
    print("  [10] JBB PAIR+GCG (152)...")
    p = []
    for m in ["PAIR", "GCG"]:
        for mdl in ["vicuna-13b-v1.5", "llama-2-7b-chat-hf"]:
            for at in ["black_box", "white_box"]:
                resp = fetch_url(f"https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/{m}/{at}/{mdl}.json", 5)
                if resp:
                    for jb in resp.json().get("jailbreaks", []):
                        if jb.get("jailbroken") and jb.get("prompt") and len(jb["prompt"]) > 10: p.append(jb["prompt"])
    print(f"      Loaded {len(p)}"); return p


def fetch_toxic():
    print("  [11] ToxicChat (200)...")
    resp = fetch_url("https://huggingface.co/datasets/lmsys/toxic-chat/resolve/main/data/0124/toxic-chat_annotation_test.csv")
    if resp:
        p = []
        for r in csv.DictReader(io.StringIO(resp.text)):
            if len(p) >= 200: break
            if r.get("user_input") and len(r["user_input"]) > 5 and str(r.get("toxicity", "0")).strip() == "1": p.append(r["user_input"])
        print(f"      Loaded {len(p)}"); return p
    print("      FAILED"); return []


def run(fw, prompts, mode):
    b = sum(1 for p in prompts if fw.is_malicious(p, mode=mode))
    missed = [p[:120] for p in prompts if not fw.is_malicious(p, mode=mode)][:3]
    return b, len(prompts), missed


def main():
    print("=" * 72)
    print("  EXPANDED MEGA BENCHMARK v3 — 9 PUBLIC DATASETS")
    print("=" * 72)

    ds = {}
    ds["HarmBench Official"] = fetch_harmbench_official()
    ds["TDC2023 Red Team"] = fetch_tdc_redteam()
    ds["RealToxicity (high)"] = fetch_realtoxicity()
    ds["BeaverTails-Eval (700)"] = fetch_beavertails()
    ds["MaliciousInstruct (100)"] = fetch_malicious()
    ds["DAN Jailbreaks (200)"] = fetch_dan()
    ds["AdvBench (520)"] = fetch_advbench()
    ds["JBB PAIR+GCG (152)"] = fetch_jbb()
    ds["ToxicChat (200)"] = fetch_toxic()

    total = sum(len(v) for v in ds.values() if v)
    active = sum(1 for v in ds.values() if v)
    print(f"\n  GRAND TOTAL: {total} prompts from {active} datasets")

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
            b, t, missed = run(fw, prompts, mode)
            r = b/t*100 if t else 0
            gb += b; gt += t
            tag = "OK" if r >= 90 else ("WARN" if r >= 70 else "WEAK")
            print(f"    {name:30s} : {b:4d}/{t:4d} blocked ({r:5.1f}%) [{tag}]")
            results[f"{name}_{mode}"] = {"blocked": b, "total": t, "rate": round(r,1)}
            for x in missed: print(f"        Missed: {x}...")
        if gt:
            o = gb/gt*100
            print(f"    {'-'*58}")
            print(f"    {'GRAND TOTAL':30s} : {gb:4d}/{gt:4d} blocked ({o:5.1f}%)")
            results[f"total_{mode}"] = {"blocked": gb, "total": gt, "rate": round(o,1)}

    print(f"\n{'='*72}")
    out = os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence", "expanded_mega_v3.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f: json.dump(results, f, indent=2)
    print(f"Saved to {os.path.abspath(out)}")

if __name__ == "__main__":
    main()
