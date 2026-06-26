"""
ToxicChat Gap Analysis — See exactly what's being missed
"""
import sys, os, json, csv, requests, io
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardian.guardrails.ai_firewall import AIPromptFirewall

fw = AIPromptFirewall()

# Fetch ToxicChat
url = "https://huggingface.co/datasets/lmsys/toxic-chat/resolve/main/data/0124/toxic-chat_annotation_test.csv"
resp = requests.get(url, timeout=15)
reader = csv.DictReader(io.StringIO(resp.text))

missed_strict = []
missed_balanced = []
blocked_balanced = []
total = 0

for row in reader:
    if total >= 200:
        break
    prompt = row.get("user_input", "")
    toxic = row.get("toxicity", "0")
    if not prompt or len(prompt) < 5 or str(toxic).strip() != "1":
        continue
    total += 1
    
    s = fw.is_malicious(prompt, mode="strict")
    b = fw.is_malicious(prompt, mode="balanced")
    
    if not s:
        missed_strict.append(prompt)
    if not b:
        missed_balanced.append(prompt)
    else:
        blocked_balanced.append(prompt)

print(f"Total toxic prompts tested: {total}")
print(f"Missed at strict:   {len(missed_strict)}/{total}")
print(f"Missed at balanced: {len(missed_balanced)}/{total}")

print(f"\n{'='*70}")
print(f"  ALL {len(missed_balanced)} PROMPTS MISSED AT BALANCED MODE")
print(f"{'='*70}")
for i, p in enumerate(missed_balanced):
    print(f"\n  [{i+1:3d}] {p[:200]}")

print(f"\n{'='*70}")
print(f"  SAMPLE BLOCKED AT BALANCED (first 10)")
print(f"{'='*70}")
for i, p in enumerate(blocked_balanced[:10]):
    print(f"\n  [B{i+1:2d}] {p[:200]}")
