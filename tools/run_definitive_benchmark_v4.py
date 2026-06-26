"""
DEFINITIVE BENCHMARK v4 — retry-safe, rate-limit aware
All available datasets combined with sleep between HF API calls.
"""
import sys, os, json, csv, requests, io, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardian.guardrails.ai_firewall import AIPromptFirewall


def hf_rows(dataset, config="default", split="test", offset=0, length=100, retries=2):
    url = f"https://datasets-server.huggingface.co/rows?dataset={dataset}&config={config}&split={split}&offset={offset}&length={length}"
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, timeout=15)
            if r.status_code == 200:
                return r.json().get("rows", [])
            elif r.status_code == 429:
                time.sleep(3 * (attempt + 1))
                continue
        except:
            pass
    return []


def fetch_beavertails():
    print("  [1] BeaverTails-Eval (700)...")
    p = []
    for offset in range(0, 700, 100):
        rows = hf_rows("PKU-Alignment/BeaverTails-Evaluation", split="test", offset=offset)
        for row in rows:
            t = row.get("row", {}).get("prompt", "")
            if t and len(t) > 5: p.append(t)
        time.sleep(0.5)
    print(f"      Loaded {len(p)}"); return p


def fetch_harmbench():
    print("  [2] HarmBench Official (400)...")
    p = []
    for split in ["test", "train"]:
        for offset in range(0, 500, 100):
            rows = hf_rows("centerforaisafety/HarmBench", config="standard_behaviors", split=split, offset=offset)
            if not rows:
                rows = hf_rows("centerforaisafety/HarmBench", config="default", split=split, offset=offset)
            if not rows: break
            for row in rows:
                r = row.get("row", {})
                for col in ["Behavior", "behavior", "goal", "prompt"]:
                    if col in r and r[col] and len(r[col]) > 10:
                        p.append(r[col]); break
            time.sleep(0.5)
    if not p:
        # Fallback: raw CSV GitHub (different paths)
        for url in [
            "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_test.csv",
            "https://raw.githubusercontent.com/centerforaisafety/HarmBench/main/data/behavior_datasets/harmbench_behaviors_text_val.csv",
        ]:
            try:
                resp = requests.get(url, timeout=15)
                if resp.status_code == 200 and "Behavior" in resp.text[:200]:
                    for row in csv.DictReader(io.StringIO(resp.text)):
                        b = row.get("Behavior", "")
                        if b and len(b) > 10: p.append(b)
            except: pass
    print(f"      Loaded {len(p)}"); return p


def fetch_do_not_answer():
    print("  [3] Do-Not-Answer (939)...")
    p = []
    for offset in range(0, 1000, 100):
        rows = hf_rows("LibrAI/do-not-answer", split="train", offset=offset)
        if not rows:
            rows = hf_rows("LibrAI/do-not-answer", config="default", split="test", offset=offset)
        if not rows: break
        for row in rows:
            r = row.get("row", {})
            q = r.get("question", r.get("prompt", r.get("instruction", "")))
            if q and len(q) > 10: p.append(q)
        time.sleep(0.5)
    if not p:
        # Try github
        for url in [
            "https://raw.githubusercontent.com/Libr-AI/do-not-answer/main/data/do_not_answer_en.csv",
            "https://raw.githubusercontent.com/Libr-AI/do-not-answer/main/do_not_answer_en.csv",
        ]:
            try:
                resp = requests.get(url, timeout=15)
                if resp.status_code == 200:
                    for row in csv.DictReader(io.StringIO(resp.text)):
                        q = row.get("question", row.get("prompt", ""))
                        if q and len(q) > 10: p.append(q)
                    if p: break
            except: pass
    print(f"      Loaded {len(p)}"); return p


def fetch_realtoxicity():
    print("  [4] RealToxicityPrompts (high-tox subset)...")
    p = []
    for offset in range(0, 30000, 100):
        if len(p) >= 300: break
        rows = hf_rows("allenai/real-toxicity-prompts", split="train", offset=offset, length=100)
        if not rows: break
        for row in rows:
            r = row.get("row", {})
            pd = r.get("prompt", {})
            if isinstance(pd, dict):
                text = pd.get("text", "")
                tox = pd.get("toxicity")
                if text and tox is not None and float(tox) >= 0.7 and len(text) > 15:
                    p.append(text)
        time.sleep(0.3)
    print(f"      Loaded {len(p)}"); return p


def fetch_malicious():
    print("  [5] MaliciousInstruct (100)...")
    try:
        r = requests.get("https://raw.githubusercontent.com/Princeton-SysML/Jailbreak_LLM/main/data/MaliciousInstruct.txt", timeout=15)
        if r.status_code == 200:
            p = [l.strip() for l in r.text.strip().split("\n") if l.strip() and len(l.strip()) > 10]
            print(f"      Loaded {len(p)}"); return p
    except: pass
    print("      FAILED"); return []


def fetch_dan():
    print("  [6] DAN Jailbreaks (200)...")
    try:
        r = requests.get("https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/jailbreak_prompts_2023_05_07.csv", timeout=20)
        if r.status_code == 200:
            p = []
            for row in csv.DictReader(io.StringIO(r.text)):
                if len(p) >= 200: break
                t = row.get("prompt", "")
                if t and len(t) > 20: p.append(t)
            print(f"      Loaded {len(p)}"); return p
    except: pass
    print("      FAILED"); return []


def fetch_advbench():
    print("  [7] AdvBench (520)...")
    try:
        r = requests.get("https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv", timeout=15)
        if r.status_code == 200:
            p = [row["goal"] for row in csv.DictReader(io.StringIO(r.text)) if row.get("goal") and len(row["goal"]) > 5]
            print(f"      Loaded {len(p)}"); return p
    except: pass
    print("      FAILED"); return []


def fetch_jbb():
    print("  [8] JBB PAIR+GCG (152)...")
    p = []
    for m in ["PAIR", "GCG"]:
        for mdl in ["vicuna-13b-v1.5", "llama-2-7b-chat-hf"]:
            for at in ["black_box", "white_box"]:
                try:
                    r = requests.get(f"https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/{m}/{at}/{mdl}.json", timeout=5)
                    if r.status_code == 200:
                        for jb in r.json().get("jailbreaks", []):
                            if jb.get("jailbroken") and jb.get("prompt"): p.append(jb["prompt"])
                except: pass
    print(f"      Loaded {len(p)}"); return p


def fetch_toxic():
    print("  [9] ToxicChat (200)...")
    try:
        r = requests.get("https://huggingface.co/datasets/lmsys/toxic-chat/resolve/main/data/0124/toxic-chat_annotation_test.csv", timeout=15)
        if r.status_code == 200:
            p = []
            for row in csv.DictReader(io.StringIO(r.text)):
                if len(p) >= 200: break
                if row.get("user_input") and str(row.get("toxicity", "0")).strip() == "1": p.append(row["user_input"])
            print(f"      Loaded {len(p)}"); return p
    except: pass
    print("      FAILED"); return []


def run(fw, prompts, mode):
    b = sum(1 for p in prompts if fw.is_malicious(p, mode=mode))
    missed = [p[:120] for p in prompts if not fw.is_malicious(p, mode=mode)][:3]
    return b, len(prompts), missed


def main():
    print("=" * 72)
    print("  DEFINITIVE BENCHMARK v4 — ALL AVAILABLE UNSEEN DATASETS")
    print("  Rate-limit aware with retries")
    print("=" * 72)

    ds = {}
    ds["BeaverTails-Eval (700)"] = fetch_beavertails()
    ds["HarmBench Official (400)"] = fetch_harmbench()
    ds["Do-Not-Answer (939)"] = fetch_do_not_answer()
    ds["RealToxicity (high)"] = fetch_realtoxicity()
    ds["MaliciousInstruct (100)"] = fetch_malicious()
    ds["DAN Jailbreaks (200)"] = fetch_dan()
    ds["AdvBench (520)"] = fetch_advbench()
    ds["JBB PAIR+GCG (152)"] = fetch_jbb()
    ds["ToxicChat (200)"] = fetch_toxic()

    total = sum(len(v) for v in ds.values() if v)
    active = sum(1 for v in ds.values() if v)
    print(f"\n  TOTAL: {total} prompts from {active} datasets\n")

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
    out = os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence", "definitive_benchmark_v4.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f: json.dump(results, f, indent=2)
    print(f"Saved to {os.path.abspath(out)}")

if __name__ == "__main__":
    main()
