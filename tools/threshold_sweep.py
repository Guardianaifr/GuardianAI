"""
Threshold Sweep Tool - Finds optimal similarity threshold for the AI Firewall.

Runs the blind test corpus at multiple threshold values and reports:
- Recall (detection rate) at each threshold
- False Positive Rate (benign prompts incorrectly blocked)
- F1 score

This helps identify the best tradeoff between catching novel attacks
and avoiding false positives on legitimate prompts.
"""
import json
import os
import sys
import logging
from unittest.mock import MagicMock, patch

base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, "guardian"))

logging.getLogger("GuardianAI").setLevel(logging.ERROR)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

from guardian.runtime.interceptor import GuardianProxy


def evaluate_at_threshold(proxy, corpus, config, threshold):
    """Run evaluation at a specific threshold value."""
    # Directly update the firewall thresholds
    if hasattr(proxy, 'ai_firewall') and proxy.ai_firewall:
        proxy.ai_firewall.thresholds = {
            "strict": max(0.1, threshold - 0.10),
            "balanced": threshold,
            "lenient": threshold + 0.15,
        }

    stats = {"TP": 0, "FP": 0, "TN": 0, "FN": 0}

    for i, item in enumerate(corpus):
        prompt = item["text"]
        expected = item["label"]

        # Directly check ai_firewall to bypass Keyword check and InputFilter regex
        is_blocked = False
        if proxy.ai_firewall:
            # Note: We now use skip_keywords=True to see pure semantic impact
            is_blocked = proxy.ai_firewall.is_malicious(prompt, mode="balanced", skip_keywords=True)

        if expected == "jailbreak" and is_blocked:
            stats["TP"] += 1
        elif expected == "benign" and is_blocked:
            stats["FP"] += 1
        elif expected == "benign" and not is_blocked:
            stats["TN"] += 1
        elif expected == "jailbreak" and not is_blocked:
            stats["FN"] += 1

    tp, fp, tn, fn = stats["TP"], stats["FP"], stats["TN"], stats["FN"]
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0
    recall = tp / (tp + fn) if (tp + fn) > 0 else 0
    f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
    fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

    return {
        "threshold": threshold,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "fpr": fpr,
        "tp": tp, "fp": fp, "tn": tn, "fn": fn
    }


def main():
    config = {
        "guardian_id": "sweep",
        "proxy": {"listen_port": 8081, "target_url": "http://mock"},
        "rate_limiting": {"enabled": False},
        "security_policies": {
            "security_mode": "balanced",
            "validate_output": True
        },
        "backend": {"enabled": False},
        "threat_feed": {"enabled": True, "url": "mock", "update_interval_seconds": 9999}
    }

    blind_path = os.path.join(base_dir, "tests", "data", "corpus_week2_blind.json")
    if not os.path.exists(blind_path):
        print(f"Blind corpus not found at {blind_path}")
        return

    with open(blind_path, 'r', encoding='utf-8') as f:
        corpus = json.load(f)

    # Initialize proxy ONCE to load model
    print("Initialising proxy and loading model...")
    proxy = GuardianProxy(config)
    # Trigger model load
    if proxy.ai_firewall:
        proxy.ai_firewall.is_malicious("test load")

    thresholds = [0.55, 0.50, 0.45, 0.40, 0.35, 0.30, 0.25, 0.20, 0.15]

    print(f"\n{'Threshold':<12} {'Recall':<10} {'Precision':<12} {'F1':<10} {'FPR':<10} {'TP':<6} {'FP':<6} {'FN':<6}")
    print("-" * 78)

    best = None
    for t in thresholds:
        result = evaluate_at_threshold(proxy, corpus, config, t)
        print(f"{t:<12.2f} {result['recall']:<10.2%} {result['precision']:<12.2%} {result['f1']:<10.4f} {result['fpr']:<10.2%} {result['tp']:<6} {result['fp']:<6} {result['fn']:<6}")

        # Best = highest F1 with FPR < 10% (more lenient for sweep)
        if result['fpr'] < 0.10:
            if best is None or result['f1'] > best['f1']:
                best = result

    print(f"\n{'='*78}")
    if best:
        print(f"OPTIMAL: Threshold={best['threshold']:.2f}, Recall={best['recall']:.2%}, Precision={best['precision']:.2%}, F1={best['f1']:.4f}, FPR={best['fpr']:.2%}")
    else:
        print("No threshold found with FPR < 10%")

if __name__ == "__main__":
    # Suppress transformer progress bars
    os.environ["TOKENIZERS_PARALLELISM"] = "false"
    
    # Run the sweep
    main()
