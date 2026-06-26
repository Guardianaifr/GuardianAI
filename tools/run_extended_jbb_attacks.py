"""
Final comprehensive results artifact.
Aggregates all unseen benchmark results.
"""
import sys, os, json
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardian.guardrails.ai_firewall import AIPromptFirewall
import requests, csv, io

fw = AIPromptFirewall()

# ---- JBB PAIR Transfer attacks (never tested) ----
print("Fetching JBB PAIR transfer attacks...")
transfer_prompts = []
for model in ["vicuna-13b-v1.5", "llama-2-7b-chat-hf"]:
    url = f"https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/PAIR/transfer/{model}.json"
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code == 200:
            data = resp.json()
            for jb in data.get("jailbreaks", []):
                if jb.get("prompt") and len(jb["prompt"]) > 10:
                    transfer_prompts.append(jb["prompt"])
            print(f"  Loaded {len(data.get('jailbreaks',[]))} from PAIR/transfer/{model}")
    except: pass

# ---- JBB Prompt Injection attacks ----
print("Fetching JBB prompt_injection attacks...")
pi_prompts = []
for model in ["vicuna-13b-v1.5", "llama-2-7b-chat-hf"]:
    for at in ["black_box", "white_box", "transfer"]:
        url = f"https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/prompt_injection/{at}/{model}.json"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                for jb in data.get("jailbreaks", []):
                    if jb.get("prompt") and len(jb["prompt"]) > 10:
                        pi_prompts.append(jb["prompt"])
                print(f"  Loaded {len(data.get('jailbreaks',[]))} from prompt_injection/{at}/{model}")
        except: pass

# ---- JBB JBC attacks ----
print("Fetching JBB JBC attacks...")
jbc_prompts = []
for model in ["vicuna-13b-v1.5", "llama-2-7b-chat-hf"]:
    for at in ["black_box", "white_box", "transfer"]:
        url = f"https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/JBC/{at}/{model}.json"
        try:
            resp = requests.get(url, timeout=5)
            if resp.status_code == 200:
                data = resp.json()
                for jb in data.get("jailbreaks", []):
                    if jb.get("prompt") and len(jb["prompt"]) > 10:
                        jbc_prompts.append(jb["prompt"])
                print(f"  Loaded {len(data.get('jailbreaks',[]))} from JBC/{at}/{model}")
        except: pass

# ---- AdvBench harmful strings (different from behaviors) ----
print("Fetching AdvBench harmful strings...")
advbench_strings = []
url = "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_strings.csv"
try:
    resp = requests.get(url, timeout=10)
    if resp.status_code == 200:
        reader = csv.DictReader(io.StringIO(resp.text))
        for row in reader:
            target = row.get("target", "")
            if target and len(target) > 10:
                advbench_strings.append(target)
        print(f"  Loaded {len(advbench_strings)} harmful strings")
except: pass

# ---- Aggregate and test ----
datasets = {
    "JBB PAIR Transfer": transfer_prompts,
    "JBB Prompt Injection": pi_prompts,
    "JBB JBC": jbc_prompts,
    "AdvBench Harmful Strings": advbench_strings,
}

print(f"\n{'='*70}")
print(f"  EXTENDED UNSEEN BENCHMARK - ALL JBB ATTACK METHODS")
print(f"  (NONE used during calibration)")
print(f"{'='*70}")

for mode in ["strict", "balanced"]:
    print(f"\n  Mode: {mode.upper()}")
    total_blocked = 0
    total_count = 0
    for name, prompts in datasets.items():
        if not prompts:
            print(f"    {name:30s} : SKIPPED")
            continue
        blocked = sum(1 for p in prompts if fw.is_malicious(p, mode=mode))
        total = len(prompts)
        rate = blocked / total * 100 if total > 0 else 0
        total_blocked += blocked
        total_count += total
        print(f"    {name:30s} : {blocked:4d}/{total:4d} blocked ({rate:5.1f}%)")
    if total_count > 0:
        overall = total_blocked / total_count * 100
        print(f"    {'-'*50}")
        print(f"    {'TOTAL':30s} : {total_blocked:4d}/{total_count:4d} blocked ({overall:5.1f}%)")

print(f"\n{'='*70}")
