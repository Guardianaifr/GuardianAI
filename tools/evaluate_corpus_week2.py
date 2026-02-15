
import json
import time
import os
import sys
import logging
from unittest.mock import MagicMock, patch

# Add parent directory to path to import guardian modules
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
sys.path.append(os.path.join(base_dir, "guardian"))

from guardian.runtime.interceptor import GuardianProxy

# Configure logging to suppress noise
logging.getLogger("GuardianAI").setLevel(logging.ERROR)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

def load_corpus(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

class SecurityEvaluator:
    def __init__(self, config):
        self.proxy = GuardianProxy(config)
        self.results = []
        self.stats = {
            "TP": 0, "FP": 0, "TN": 0, "FN": 0
        }

    def run(self, corpus):
        print(f"Evaluating {len(corpus)} requests...")
        
        # Mock downstream
        with patch('requests.request') as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"choices": [{"message": {"content": "Safe response"}}]}'
            mock_resp.raw.headers = {}
            mock_req.return_value = mock_resp
            
            with patch('requests.get') as mock_get:
                mock_get.return_value.status_code = 200

                for i, item in enumerate(corpus):
                    if i % 100 == 0:
                        print(f"Processing {i}/{len(corpus)}...")
                    
                    prompt = item["text"]
                    expected_label = item["label"] # "benign" or "jailbreak"
                    
                    with self.proxy.app.test_request_context(
                        '/v1/chat/completions',
                        method='POST',
                        json={"messages": [{"role": "user", "content": prompt}]},
                        headers={"X-Conversation-ID": f"eval-session-{i}"}
                    ):
                        response = self.proxy.proxy('v1/chat/completions')
                        is_blocked = response.status_code == 403
                        
                        actual_label = "jailbreak" if is_blocked else "benign"
                        
                        # Confusion Matrix Logic
                        if expected_label == "jailbreak" and is_blocked:
                            self.stats["TP"] += 1
                        elif expected_label == "benign" and is_blocked:
                            self.stats["FP"] += 1
                        elif expected_label == "benign" and not is_blocked:
                            self.stats["TN"] += 1
                        elif expected_label == "jailbreak" and not is_blocked:
                            self.stats["FN"] += 1
                        
                        self.results.append({
                            "prompt": prompt[:100],
                            "expected": expected_label,
                            "actual": actual_label,
                            "correct": expected_label == actual_label,
                            "category": item.get("category", "unknown")
                        })

    def generate_report(self, output_path):
        tp, fp, tn, fn = self.stats["TP"], self.stats["FP"], self.stats["TN"], self.stats["FN"]
        
        precision = tp / (tp + fp) if (tp + fp) > 0 else 0
        recall = tp / (tp + fn) if (tp + fn) > 0 else 0
        f1 = 2 * (precision * recall) / (precision + recall) if (precision + recall) > 0 else 0
        accuracy = (tp + tn) / (tp + tn + fp + fn)
        fpr = fp / (fp + tn) if (fp + tn) > 0 else 0

        report = []
        report.append("# 🎯 GuardianAI Security Evaluation (Week 2)")
        report.append(f"\n**Date**: {time.strftime('%Y-%m-%d')}")
        report.append(f"**Sample Size**: {len(self.results)} prompts (1000 benign, 500 jailbreak)")
        
        report.append("\n## 📊 Confusion Matrix")
        report.append("| | Predicted Jailbreak | Predicted Benign |")
        report.append("| :--- | :--- | :--- |")
        report.append(f"| **Actual Jailbreak** | TP: {tp} | FN: {fn} |")
        report.append(f"| **Actual Benign** | FP: {fp} | TN: {tn} |")
        
        report.append("\n## 📈 Core Metrics")
        report.append(f"- **Precision**: {precision:.2%}")
        report.append(f"- **Recall (Detection Rate)**: {recall:.2%}")
        report.append(f"- **F1-Score**: {f1:.4f}")
        report.append(f"- **Accuracy**: {accuracy:.2%}")
        report.append(f"- **False Positive Rate (FPR)**: {fpr:.2%}")
        
        report.append("\n## 🔍 Top Failure Samples")
        
        # Pull some False Negatives (Bypasses)
        fn_samples = [r for r in self.results if r["expected"] == "jailbreak" and r["actual"] == "benign"][:5]
        if fn_samples:
            report.append("\n### False Negatives (Missed Attacks)")
            for s in fn_samples:
                report.append(f"- [{s['category']}] {s['prompt']}...")
        
        # Pull some False Positives (Over-blocking)
        fp_samples = [r for r in self.results if r["expected"] == "benign" and r["actual"] == "jailbreak"][:5]
        if fp_samples:
            report.append("\n### False Positives (Incorrectly Blocked)")
            for s in fp_samples:
                report.append(f"- [{s['category']}] {s['prompt']}...")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report))
            
        with open("evaluation_results_week2.json", "w", encoding="utf-8") as f:
            json.dump({"stats": self.stats, "details": self.results}, f, indent=2)
        
        print(f"\nReport generated at {output_path}")
        print(f"Precision: {precision:.2%}, Recall: {recall:.2%}, F1: {f1:.4f}")

def main():
    config = {
        "guardian_id": "evaluator",
        "proxy": {"listen_port": 8081, "target_url": "http://mock"},
        "rate_limiting": {"enabled": False},
        "security_policies": {
            "security_mode": "balanced",
            "validate_output": True
        },
        "backend": {"enabled": False},
        "threat_feed": {"enabled": True, "url": "mock", "update_interval_seconds": 9999}
    }
    
    # Allow passing corpus path as argument
    if len(sys.argv) > 1:
        corpus_path = sys.argv[1]
    else:
        corpus_path = os.path.join(base_dir, "tests", "data", "corpus_week2.json")
        
    if not os.path.exists(corpus_path):
        print(f"Corpus not found at {corpus_path}")
        return
        
    eval_name = os.path.basename(corpus_path).replace(".json", "")
    report_path = f"evaluation_report_{eval_name}.md"
    
    evaluator = SecurityEvaluator(config)
    corpus = load_corpus(corpus_path)
    evaluator.run(corpus)
    evaluator.generate_report(report_path)

if __name__ == "__main__":
    main()
