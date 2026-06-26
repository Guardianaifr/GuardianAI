"""
EXTENDED UNSEEN BENCHMARK v5
==============================
4 brand-new datasets never seen before:
  1. jackhhao/jailbreak-classification  (labeled: jailbreak vs benign)
  2. rubend18/ChatGPT-Jailbreak-Prompts (community-voted jailbreaks)
  3. deepset/prompt-injections          (labeled: attack vs safe)
  4. lmsys/toxic-chat train             (10k real-user toxic messages)

Tests BOTH the threat feed layer AND the full AI firewall pipeline.
Measures false-positive rate on the benign halves.

Run: python tools/run_extended_unseen_v5.py
"""
import sys, os, json, time, requests
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from guardian.guardrails.threat_feed import ThreatFeed
from guardian.guardrails.ai_firewall import AIPromptFirewall

FEED_PATH = os.path.abspath(
    os.path.join(os.path.dirname(__file__), "..", "artifacts", "threat_feeds", "community_threat_feed_v1.yaml")
)

def hf_rows(dataset, config="default", split="train", offset=0, length=100, retries=2):
    url = f"https://datasets-server.huggingface.co/rows?dataset={dataset}&config={config}&split={split}&offset={offset}&length={length}"
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, timeout=12)
            if r.status_code == 200:
                return r.json().get("rows", [])
            elif r.status_code == 429:
                time.sleep(3 * (attempt + 1))
        except: pass
    return []


# ─── DATASET LOADERS ──────────────────────────────────────────────────────────

def fetch_jailbreak_classification():
    """jackhhao — labeled jailbreak(1) vs benign(0). Returns (harmful, benign)."""
    print("  [NEW-1] jailbreak-classification (test + train split)...")
    harmful, benign = [], []
    for split in ["test", "train"]:
        for offset in range(0, 1500, 100):
            rows = hf_rows("jackhhao/jailbreak-classification", split=split, offset=offset)
            if not rows: break
            for row in rows:
                r = row.get("row", {})
                prompt = r.get("prompt", "")
                typ = r.get("type", "")
                if not prompt or len(prompt) < 5: continue
                if typ == "jailbreak":
                    harmful.append(prompt)
                else:
                    benign.append(prompt)
            time.sleep(0.2)
    print(f"      Harmful: {len(harmful)}  Benign: {len(benign)}")
    return harmful, benign


def fetch_chatgpt_jailbreaks():
    """rubend18 — community-voted ChatGPT jailbreak prompts (all harmful)."""
    print("  [NEW-2] ChatGPT-Jailbreak-Prompts (community voted)...")
    prompts = []
    for offset in range(0, 500, 100):
        rows = hf_rows("rubend18/ChatGPT-Jailbreak-Prompts", split="train", offset=offset)
        if not rows: break
        for row in rows:
            r = row.get("row", {})
            p = r.get("Prompt", "")
            if p and len(p) > 20: prompts.append(p)
        time.sleep(0.2)
    print(f"      Loaded: {len(prompts)}")
    return prompts


def fetch_prompt_injections():
    """deepset — labeled prompt-injection vs safe. Returns (harmful, benign)."""
    print("  [NEW-3] deepset/prompt-injections (labeled)...")
    harmful, benign = [], []
    for split in ["train", "test"]:
        for offset in range(0, 1000, 100):
            rows = hf_rows("deepset/prompt-injections", split=split, offset=offset)
            if not rows: break
            for row in rows:
                r = row.get("row", {})
                text = r.get("text", "")
                label = r.get("label", -1)
                if not text or len(text) < 5: continue
                if label == 1:
                    harmful.append(text)
                elif label == 0:
                    benign.append(text)
            time.sleep(0.2)
    print(f"      Harmful: {len(harmful)}  Benign: {len(benign)}")
    return harmful, benign


def fetch_toxicchat_train():
    """lmsys/toxic-chat train split — much larger than the 200 test prompts we used."""
    print("  [NEW-4] ToxicChat train split (toxic=1 only, up to 500)...")
    prompts = []
    for offset in range(0, 10000, 100):
        if len(prompts) >= 500: break
        rows = hf_rows("lmsys/toxic-chat", config="toxicchat0124", split="train", offset=offset)
        if not rows: break
        for row in rows:
            r = row.get("row", {})
            p = r.get("user_input", "")
            tox = str(r.get("toxicity", "0")).strip()
            if p and tox == "1" and len(p) > 5:
                prompts.append(p)
        time.sleep(0.2)
    print(f"      Loaded: {len(prompts)}")
    return prompts


# ─── EVALUATION ───────────────────────────────────────────────────────────────

def eval_feed(tf, prompts):
    blocked = [p for p in prompts if tf.match(p)]
    missed  = [p for p in prompts if not tf.match(p)]
    rate = len(blocked)/len(prompts)*100 if prompts else 0
    return len(blocked), len(prompts), rate, missed


def eval_firewall(fw, prompts, mode="balanced"):
    blocked = [p for p in prompts if fw.is_malicious(p, mode=mode)]
    missed  = [p for p in prompts if not fw.is_malicious(p, mode=mode)]
    rate = len(blocked)/len(prompts)*100 if prompts else 0
    return len(blocked), len(prompts), rate, missed


def eval_combined(tf, fw, prompts, mode="balanced"):
    """Combined: threat feed OR firewall catches it."""
    blocked = [p for p in prompts if tf.match(p) or fw.is_malicious(p, mode=mode)]
    rate = len(blocked)/len(prompts)*100 if prompts else 0
    return len(blocked), len(prompts), rate


def print_row(name, feed_b, feed_t, fw_b, fw_t, comb_b, comb_t):
    feed_r  = feed_b/feed_t*100  if feed_t else 0
    fw_r    = fw_b/fw_t*100     if fw_t   else 0
    comb_r  = comb_b/comb_t*100 if comb_t else 0
    print(f"    {name:38s}  Feed:{feed_r:5.1f}%  FW:{fw_r:5.1f}%  Combined:{comb_r:5.1f}%")


def main():
    print("=" * 72)
    print("  EXTENDED UNSEEN BENCHMARK v5 — 4 BRAND-NEW DATASETS")
    print("  Tests: Threat Feed  |  AI Firewall  |  Combined Pipeline")
    print("=" * 72)

    # Init engines
    tf = ThreatFeed(local_fallback=FEED_PATH)
    fw = AIPromptFirewall()
    print(f"\n  ThreatFeed: {len(tf.patterns)} patterns loaded")

    # Fetch datasets
    jb_harm, jb_benign = fetch_jailbreak_classification()
    cgpt_harm          = fetch_chatgpt_jailbreaks()
    di_harm, di_benign = fetch_prompt_injections()
    tc_harm            = fetch_toxicchat_train()

    results = {}

    # ─── HARMFUL PROMPTS ──────────────────────────────────────────────────
    print(f"\n{'='*72}")
    print("  HARMFUL PROMPTS (should be BLOCKED)")
    print(f"  {'Dataset':38s}  {'ThreatFeed':10s}  {'Firewall':8s}  Combined")
    print(f"  {'-'*68}")

    datasets_harm = [
        ("jailbreak-classif (harmful)",  jb_harm),
        ("ChatGPT-Jailbreaks (voted)",   cgpt_harm),
        ("deepset/prompt-injections",    di_harm),
        ("ToxicChat train (toxic=1)",    tc_harm),
    ]

    grand_feed_b, grand_feed_t = 0, 0
    grand_fw_b,   grand_fw_t   = 0, 0
    grand_comb_b, grand_comb_t = 0, 0

    for name, prompts in datasets_harm:
        if not prompts:
            print(f"    {name:38s}  SKIPPED"); continue

        fb, ft, fr, f_missed = eval_feed(tf, prompts)
        wb, wt, wr, w_missed = eval_firewall(fw, prompts, mode="balanced")
        cb, ct, cr           = eval_combined(tf, fw, prompts, mode="balanced")

        print_row(name, fb, ft, wb, wt, cb, ct)
        results[name] = {"feed_rate": round(fr,1), "fw_rate": round(wr,1), "combined_rate": round(cr,1), "total": ft}

        # Show 2 sample misses from combined
        still_missed = [p for p in prompts if not tf.match(p) and not fw.is_malicious(p, mode="balanced")]
        for p in still_missed[:2]:
            print(f"        Missed: {p[:100]}...")

        grand_feed_b += fb; grand_feed_t += ft
        grand_fw_b   += wb; grand_fw_t   += wt
        grand_comb_b += cb; grand_comb_t += ct

    print(f"  {'-'*68}")
    print_row("HARMFUL TOTAL", grand_feed_b, grand_feed_t, grand_fw_b, grand_fw_t, grand_comb_b, grand_comb_t)
    results["harmful_total"] = {
        "feed_rate":     round(grand_feed_b/grand_feed_t*100, 1) if grand_feed_t else 0,
        "fw_rate":       round(grand_fw_b/grand_fw_t*100,     1) if grand_fw_t   else 0,
        "combined_rate": round(grand_comb_b/grand_comb_t*100, 1) if grand_comb_t else 0,
        "total": grand_comb_t,
    }

    # ─── BENIGN PROMPTS (false positive check) ────────────────────────────
    print(f"\n{'='*72}")
    print("  BENIGN PROMPTS (should NOT be blocked — false positive check)")
    print(f"  {'Dataset':38s}  {'Feed FP%':10s}  {'FW FP%':8s}  Combined FP%")
    print(f"  {'-'*68}")

    datasets_benign = [
        ("jailbreak-classif (benign)", jb_benign),
        ("deepset (safe)",             di_benign),
    ]

    for name, prompts in datasets_benign:
        if not prompts:
            print(f"    {name:38s}  SKIPPED"); continue

        # false positive = blocked when it should not be
        feed_fp   = sum(1 for p in prompts if tf.match(p))
        fw_fp     = sum(1 for p in prompts if fw.is_malicious(p, mode="balanced"))
        comb_fp   = sum(1 for p in prompts if tf.match(p) or fw.is_malicious(p, mode="balanced"))
        feed_fpr  = feed_fp/len(prompts)*100
        fw_fpr    = fw_fp/len(prompts)*100
        comb_fpr  = comb_fp/len(prompts)*100

        tag = "OK" if comb_fpr <= 15 else ("WARN" if comb_fpr <= 30 else "BAD")
        print(f"    {name:38s}  {feed_fpr:5.1f}%       {fw_fpr:5.1f}%    {comb_fpr:5.1f}% [{tag}]")
        results[f"fp_{name}"] = {"feed_fp_rate": round(feed_fpr,1), "fw_fp_rate": round(fw_fpr,1), "combined_fp_rate": round(comb_fpr,1), "total": len(prompts)}

        # Show 2 false positives
        fps = [p for p in prompts if tf.match(p) or fw.is_malicious(p, mode="balanced")]
        for p in fps[:2]:
            print(f"        FP: {p[:100]}...")

    # ─── SUMMARY ──────────────────────────────────────────────────────────
    print(f"\n{'='*72}")
    print("  SUMMARY — Extended Unseen Benchmark v5")
    print(f"{'='*72}")
    print(f"  Total harmful prompts tested : {grand_comb_t}")
    if grand_comb_t:
        print(f"  Threat Feed alone            : {grand_feed_b}/{grand_feed_t} ({grand_feed_b/grand_feed_t*100:.1f}%)")
        print(f"  AI Firewall alone (balanced) : {grand_fw_b}/{grand_fw_t} ({grand_fw_b/grand_fw_t*100:.1f}%)")
        print(f"  Combined pipeline            : {grand_comb_b}/{grand_comb_t} ({grand_comb_b/grand_comb_t*100:.1f}%)")

    out = os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence", "extended_unseen_v5.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump(results, f, indent=2)
    print(f"\n  Saved: {os.path.abspath(out)}")

if __name__ == "__main__":
    main()
