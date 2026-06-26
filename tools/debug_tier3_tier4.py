"""Diagnostic: dump ALL missed DAN + ToxicChat prompts for pattern analysis."""
import sys, os, json, csv, requests, io
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardian.guardrails.ai_firewall import AIPromptFirewall
fw = AIPromptFirewall()

# --- DAN Jailbreaks ---
print("=== DAN JAILBREAKS MISSED AT STRICT ===")
url = "https://raw.githubusercontent.com/verazuo/jailbreak_llms/main/data/prompts/jailbreak_prompts_2023_05_07.csv"
resp = requests.get(url, timeout=20)
reader = csv.DictReader(io.StringIO(resp.text))
dan_prompts = []
for row in reader:
    if len(dan_prompts) >= 200: break
    p = row.get("prompt", row.get("text", row.get("jailbreak_prompt", "")))
    if p and len(p) > 20: dan_prompts.append(p)

dan_missed_strict = []
for i, p in enumerate(dan_prompts):
    if not fw.is_malicious(p, mode="strict"):
        dan_missed_strict.append((i, p))

print(f"Missed {len(dan_missed_strict)}/200 at strict\n")
for idx, (i, p) in enumerate(dan_missed_strict):
    # Show first 300 chars to see the pattern
    print(f"  [{idx+1:2d}] {p[:300]}")
    print()

# --- ToxicChat ---
print("\n=== TOXICCHAT MISSED AT STRICT ===")
url2 = "https://huggingface.co/datasets/lmsys/toxic-chat/resolve/main/data/0124/toxic-chat_annotation_test.csv"
resp2 = requests.get(url2, timeout=15)
reader2 = csv.DictReader(io.StringIO(resp2.text))
tc_prompts = []
for row in reader2:
    if len(tc_prompts) >= 200: break
    p = row.get("user_input", "")
    if p and len(p) > 5 and str(row.get("toxicity", "0")).strip() == "1":
        tc_prompts.append(p)

tc_missed_strict = []
for i, p in enumerate(tc_prompts):
    if not fw.is_malicious(p, mode="strict"):
        tc_missed_strict.append((i, p))

print(f"Missed {len(tc_missed_strict)}/200 at strict\n")
for idx, (i, p) in enumerate(tc_missed_strict):
    print(f"  [{idx+1:2d}] {p[:300]}")
    print()
