"""
NEW UNSEEN DATA PROBE — finds schemas for datasets we haven't tested yet
Tries 10 new datasets and prints what columns are available.
"""
import sys, os, json, time, requests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

CANDIDATES = [
    # (dataset_id, config, split)
    ("jackhhao/jailbreak-classification",       "default", "test"),
    ("jackhhao/jailbreak-classification",       "default", "train"),
    ("rubend18/ChatGPT-Jailbreak-Prompts",      "default", "train"),
    ("deepset/prompt-injections",               "default", "train"),
    ("notrichardren/refuse-bench",              "default", "test"),
    ("lmsys/toxic-chat",                        "toxicchat0124", "train"),
    ("markusbayer/CyberSecEval",                "default", "test"),
    ("Ejafa/ye-pop",                            "default", "train"),
    ("jondurbin/airoboros-2.2",                 "default", "train"),
    ("TrustAIRLab/in-the-wild-jailbreak-prompts", "default", "train"),
    ("JailbreakV-28K/JailBreakV_28K",           "JailBreakV_28K", "test"),
    ("JailbreakV-28K/JailBreakV_28K",           "JailBreakV_28K", "train"),
    ("ehartford/unlocked-wizard",               "default", "train"),
    ("CaterpillarFarmer/jailbreak-prompts",     "default", "train"),
    ("sevdeawesome/jailbreak_study",            "default", "train"),
]

def probe(dataset, config, split):
    url = f"https://datasets-server.huggingface.co/rows?dataset={dataset}&config={config}&split={split}&offset=0&length=2"
    try:
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            data = r.json()
            rows = data.get("rows", [])
            if rows:
                cols = list(rows[0].get("row", {}).keys())
                return "OK", cols, rows
            return "EMPTY", [], []
        return f"HTTP {r.status_code}", [], []
    except Exception as e:
        return f"ERR: {e}", [], []

print("=" * 70)
print("  DATASET PROBE — finding usable unseen data sources")
print("=" * 70)

found = []
for ds, cfg, split in CANDIDATES:
    status, cols, rows = probe(ds, cfg, split)
    if status == "OK":
        # Show a sample value for each column
        sample = rows[0].get("row", {}) if rows else {}
        text_cols = [c for c in cols if isinstance(sample.get(c), str) and len(sample.get(c, "")) > 10]
        print(f"\n  ✅ {ds} [{cfg}/{split}]")
        print(f"     Columns: {cols}")
        print(f"     Text cols: {text_cols}")
        if text_cols:
            print(f"     Sample '{text_cols[0]}': {str(sample.get(text_cols[0], ''))[:100]}")
        found.append((ds, cfg, split, text_cols))
    else:
        print(f"  ❌ {ds} [{split}]: {status}")
    time.sleep(0.5)

print(f"\n{'='*70}")
print(f"  FOUND {len(found)} usable datasets")
for ds, cfg, split, cols in found:
    print(f"    {ds} — text cols: {cols}")
