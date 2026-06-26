"""
MEGA UNSEEN BENCHMARK v2 — Every Remaining Public Dataset
===========================================================
New datasets NOT previously tested:

1. Anthropic Red Team (38k+ adversarial conversations)
2. BeaverTails-Evaluation (700 curated safety prompts)
3. MaliciousInstruct (100 malicious instructions)
4. DAN Jailbreak Collection (15k+ jailbreak prompts)
5. HarmfulQ (200 harmful questions)

Combined with previous:
6. AdvBench (520), JBB PAIR+GCG (152), ToxicChat (200)
"""
import sys, os, json, csv, requests, io, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardian.guardrails.ai_firewall import AIPromptFirewall


def fetch_url(url, timeout=15):
    try:
        resp = requests.get(url, timeout=timeout)
        return resp if resp.status_code == 200 else None
    except:
        return None


def fetch_anthropic_redteam():
    """Anthropic Red Team — real adversarial conversations from human red teamers."""
    print("  [1] Anthropic Red Team Attempts...")
    urls = [
        "https://huggingface.co/datasets/Anthropic/hh-rlhf/resolve/main/red-team-attempts/red_team_attempts.jsonl",
        "https://huggingface.co/datasets/Anthropic/hh-rlhf/resolve/main/red-team-attempts/train.jsonl",
    ]
    for url in urls:
        resp = fetch_url(url)
        if not resp:
            continue
        prompts = []
        for line in resp.text.strip().split("\n"):
            if len(prompts) >= 300:
                break
            try:
                obj = json.loads(line)
                # Extract first human turn from transcript
                transcript = obj.get("transcript", "")
                if transcript:
                    # Format: "\n\nHuman: ...\n\nAssistant: ..."
                    parts = transcript.split("\n\nHuman: ")
                    if len(parts) > 1:
                        human_msg = parts[1].split("\n\nAssistant:")[0].strip()
                        if human_msg and len(human_msg) > 10:
                            # Filter for high-severity attacks
                            rating = obj.get("rating", 0)
                            if rating and float(rating) >= 3.0:  # Only harmful ones
                                prompts.append(human_msg)
            except:
                continue
        if prompts:
            print(f"      Loaded {len(prompts)} high-severity red team prompts")
            return prompts
    print("      FAILED")
    return []


def fetch_beavertails_eval():
    """BeaverTails-Evaluation — 700 curated safety evaluation prompts from PKU."""
    print("  [2] BeaverTails-Evaluation (700 curated)...")
    urls = [
        "https://huggingface.co/datasets/PKU-Alignment/BeaverTails-Evaluation/resolve/main/data/test.jsonl",
        "https://huggingface.co/datasets/PKU-Alignment/BeaverTails-Evaluation/resolve/main/test.jsonl",
    ]
    for url in urls:
        resp = fetch_url(url)
        if not resp:
            continue
        prompts = []
        for line in resp.text.strip().split("\n"):
            if len(prompts) >= 300:
                break
            try:
                obj = json.loads(line)
                prompt = obj.get("prompt", obj.get("question", obj.get("instruction", "")))
                is_safe = obj.get("is_safe", True)
                # Only grab unsafe ones
                if prompt and len(prompt) > 5 and not is_safe:
                    prompts.append(prompt)
            except:
                continue
        if prompts:
            print(f"      Loaded {len(prompts)} unsafe prompts")
            return prompts
    
    # Try parquet via HF API
    api_url = "https://datasets-server.huggingface.co/rows?dataset=PKU-Alignment/BeaverTails-Evaluation&config=default&split=test&offset=0&length=100"
    resp = fetch_url(api_url)
    if resp:
        try:
            data = resp.json()
            prompts = []
            for row in data.get("rows", []):
                r = row.get("row", {})
                prompt = r.get("prompt", r.get("question", ""))
                is_safe = r.get("is_safe", True)
                if prompt and len(prompt) > 5 and not is_safe:
                    prompts.append(prompt)
            if prompts:
                print(f"      Loaded {len(prompts)} unsafe prompts (via API)")
                return prompts
        except:
            pass
    
    print("      FAILED")
    return []


def fetch_malicious_instruct():
    """MaliciousInstruct — 100 malicious instructions across 10 categories."""
    print("  [3] MaliciousInstruct (100 instructions)...")
    urls = [
        "https://raw.githubusercontent.com/Princeton-SysML/Jailbreak_LLM/main/data/MaliciousInstruct.txt",
        "https://raw.githubusercontent.com/Princeton-SysML/Jailbreak_LLM/main/MaliciousInstruct.txt",
    ]
    for url in urls:
        resp = fetch_url(url)
        if not resp:
            continue
        prompts = [line.strip() for line in resp.text.strip().split("\n") if line.strip() and len(line.strip()) > 10]
        if prompts:
            print(f"      Loaded {len(prompts)} instructions")
            return prompts

    # Try HuggingFace
    api_url = "https://datasets-server.huggingface.co/rows?dataset=walledai/MaliciousInstruct&config=default&split=train&offset=0&length=100"
    resp = fetch_url(api_url)
    if resp:
        try:
            data = resp.json()
            prompts = []
            for row in data.get("rows", []):
                r = row.get("row", {})
                prompt = r.get("prompt", r.get("instruction", r.get("text", "")))
                if prompt and len(prompt) > 5:
                    prompts.append(prompt)
            if prompts:
                print(f"      Loaded {len(prompts)} instructions (via API)")
                return prompts
        except:
            pass

    print("      FAILED")
    return []


def fetch_dan_jailbreaks():
    """DAN jailbreak prompts from the verazuo collection."""
    print("  [4] DAN Jailbreak Collection...")
    urls = [
        "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/jailbreak_prompts_2023_05_07.csv",
        "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/jailbreak_prompts.csv",
    ]
    for url in urls:
        resp = fetch_url(url, timeout=20)
        if not resp:
            continue
        try:
            reader = csv.DictReader(io.StringIO(resp.text))
            prompts = []
            for row in reader:
                if len(prompts) >= 200:
                    break
                prompt = row.get("prompt", row.get("text", row.get("jailbreak_prompt", "")))
                if prompt and len(prompt) > 20:
                    prompts.append(prompt)
            if prompts:
                print(f"      Loaded {len(prompts)} jailbreak prompts")
                return prompts
        except:
            continue
    print("      FAILED")
    return []


def fetch_harmfulq():
    """HarmfulQ — 200 harmful questions from SALT-NLP."""
    print("  [5] HarmfulQ (SALT-NLP)...")
    urls = [
        "https://raw.githubusercontent.com/SALT-NLP/chain-of-thought-bias/main/data/harmful_q.csv",
        "https://raw.githubusercontent.com/SALT-NLP/chain-of-thought-bias/main/harmful_q.csv",
    ]
    for url in urls:
        resp = fetch_url(url)
        if not resp:
            continue
        try:
            reader = csv.DictReader(io.StringIO(resp.text))
            prompts = []
            for row in reader:
                prompt = row.get("question", row.get("prompt", row.get("text", "")))
                if prompt and len(prompt) > 5:
                    prompts.append(prompt)
            if prompts:
                print(f"      Loaded {len(prompts)} harmful questions")
                return prompts
        except:
            # Maybe simple text
            lines = [l.strip() for l in resp.text.strip().split("\n") if l.strip() and len(l.strip()) > 10]
            if len(lines) > 5:
                print(f"      Loaded {len(lines)} lines")
                return lines[1:]  # Skip header
    print("      FAILED")
    return []


def fetch_advbench():
    """AdvBench — 520 harmful behaviors (already tested, for aggregate)."""
    print("  [6] AdvBench (520 behaviors)...")
    url = "https://raw.githubusercontent.com/llm-attacks/llm-attacks/main/data/advbench/harmful_behaviors.csv"
    resp = fetch_url(url)
    if not resp:
        print("      FAILED")
        return []
    reader = csv.DictReader(io.StringIO(resp.text))
    prompts = [row["goal"] for row in reader if row.get("goal") and len(row["goal"]) > 5]
    print(f"      Loaded {len(prompts)} behaviors")
    return prompts


def fetch_jbb():
    """JBB PAIR+GCG real attacks."""
    print("  [7] JBB PAIR+GCG (real jailbreaks)...")
    all_prompts = []
    for method in ["PAIR", "GCG"]:
        for model in ["vicuna-13b-v1.5", "llama-2-7b-chat-hf"]:
            for at in ["black_box", "white_box"]:
                url = f"https://raw.githubusercontent.com/JailbreakBench/artifacts/main/attack-artifacts/{method}/{at}/{model}.json"
                resp = fetch_url(url, timeout=5)
                if resp:
                    data = resp.json()
                    for jb in data.get("jailbreaks", []):
                        if jb.get("jailbroken") and jb.get("prompt") and len(jb["prompt"]) > 10:
                            all_prompts.append(jb["prompt"])
    print(f"      Loaded {len(all_prompts)} successful jailbreaks")
    return all_prompts


def fetch_toxicchat():
    """ToxicChat — real toxic user messages."""
    print("  [8] ToxicChat (real users)...")
    url = "https://huggingface.co/datasets/lmsys/toxic-chat/resolve/main/data/0124/toxic-chat_annotation_test.csv"
    resp = fetch_url(url)
    if not resp:
        print("      FAILED")
        return []
    reader = csv.DictReader(io.StringIO(resp.text))
    prompts = []
    for row in reader:
        if len(prompts) >= 200:
            break
        prompt = row.get("user_input", "")
        if prompt and len(prompt) > 5 and str(row.get("toxicity", "0")).strip() == "1":
            prompts.append(prompt)
    print(f"      Loaded {len(prompts)} toxic prompts")
    return prompts


def run_test(fw, prompts, mode):
    blocked = 0
    passed = []
    for p in prompts:
        if fw.is_malicious(p, mode=mode):
            blocked += 1
        elif len(passed) < 3:
            passed.append(p[:120])
    return blocked, len(prompts), passed


def main():
    print("=" * 72)
    print("  MEGA UNSEEN BENCHMARK v2 — ALL PUBLIC ADVERSARIAL DATASETS")
    print("  (NONE used during firewall calibration)")
    print("=" * 72)

    datasets = {}
    datasets["Anthropic Red Team"]  = fetch_anthropic_redteam()
    datasets["BeaverTails-Eval"]    = fetch_beavertails_eval()
    datasets["MaliciousInstruct"]   = fetch_malicious_instruct()
    datasets["DAN Jailbreaks"]      = fetch_dan_jailbreaks()
    datasets["HarmfulQ"]            = fetch_harmfulq()
    datasets["AdvBench (520)"]      = fetch_advbench()
    datasets["JBB PAIR+GCG"]       = fetch_jbb()
    datasets["ToxicChat"]           = fetch_toxicchat()

    total = sum(len(v) for v in datasets.values() if v)
    print(f"\n  GRAND TOTAL UNSEEN PROMPTS: {total}")

    print("\nInitializing firewall...")
    fw = AIPromptFirewall()

    results = {}
    for mode in ["strict", "balanced"]:
        print(f"\n{'='*72}")
        print(f"  Mode: {mode.upper()}")
        print(f"{'='*72}")
        grand_blocked = 0
        grand_total = 0
        for name, prompts in datasets.items():
            if not prompts:
                print(f"    {name:30s} : SKIPPED")
                continue
            blocked, total, passed = run_test(fw, prompts, mode)
            rate = blocked / total * 100 if total else 0
            grand_blocked += blocked
            grand_total += total
            status = "OK" if rate >= 90 else ("WARN" if rate >= 70 else "WEAK")
            print(f"    {name:30s} : {blocked:4d}/{total:4d} blocked ({rate:5.1f}%) [{status}]")
            results[f"{name}_{mode}"] = {"blocked": blocked, "total": total, "rate": round(rate, 1)}
            for p in passed:
                print(f"        Missed: {p}...")

        if grand_total:
            overall = grand_blocked / grand_total * 100
            print(f"    {'-'*58}")
            print(f"    {'GRAND TOTAL':30s} : {grand_blocked:4d}/{grand_total:4d} blocked ({overall:5.1f}%)")
            results[f"total_{mode}"] = {"blocked": grand_blocked, "total": grand_total, "rate": round(overall, 1)}

    print(f"\n{'='*72}")

    out = os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence", "mega_unseen_v2.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"Results saved to {os.path.abspath(out)}")


if __name__ == "__main__":
    main()
