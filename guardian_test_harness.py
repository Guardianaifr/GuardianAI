import requests
import json
import time
import argparse
import yaml
import os
from datetime import datetime

# Configuration
PROXY_URL = "http://localhost:8081/v1/chat/completions"
# Using the fixed credentials for now
AUTH = ("admin", "guardian_default")

class GuardianTestHarness:
    def __init__(self, vectors_path):
        self.vectors_path = vectors_path
        self.results = []
        self.vectors = self._load_vectors()

    def _load_vectors(self):
        with open(self.vectors_path, "r") as f:
            data = yaml.safe_load(f)
            return data.get("vectors", [])

    def run_suite(self):
        print(f"Starting GuardianAI Professional Audit Suite...")
        print(f"Loaded {len(self.vectors)} vectors from {self.vectors_path}")
        print("-" * 50)

        for i, vector in enumerate(self.vectors):
            prompt = vector.get("text")
            print(f"[{i+1}/{len(self.vectors)}] Testing: {prompt[:50]}...")
            
            start_time = time.time()
            try:
                # Simulate a chat completion request
                payload = {
                    "model": "gpt-4",
                    "messages": [{"role": "user", "content": prompt}]
                }
                
                # Note: We send to the proxy
                headers = {
                    "Content-Type": "application/json",
                    "X-Guardian-Token": "pt-guardian-789"
                }
                response = requests.post(PROXY_URL, json=payload, headers=headers, timeout=10)
                latency = (time.time() - start_time) * 1000
                
                status = "BLOCKED" if response.status_code == 403 else "ALLOWED"
                
                self.results.append({
                    "id": i + 1,
                    "prompt": prompt,
                    "status": status,
                    "status_code": response.status_code,
                    "latency_ms": round(latency, 2),
                    "response_preview": response.text[:100]
                })
                
                color = "[+]" if status == "BLOCKED" else "[-]"
                print(f"    Result: {color} {status} ({latency:.2f}ms)")
                
            except Exception as e:
                print(f"    [X] Error: {str(e)}")
                self.results.append({
                    "id": i + 1,
                    "prompt": prompt,
                    "status": "ERROR",
                    "error": str(e)
                })

    def generate_report(self, format="markdown"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        total = len(self.results)
        blocked = sum(1 for r in self.results if r.get("status") == "BLOCKED")
        allowed = sum(1 for r in self.results if r.get("status") == "ALLOWED")
        avg_latency = sum(r.get("latency_ms", 0) for r in self.results if "latency_ms" in r) / total if total > 0 else 0

        report_name = f"guardian_audit_{datetime.now().strftime('%Y%m%d_%H%M%S')}"

        if format == "json":
            output = {
                "audit_timestamp": timestamp,
                "summary": {
                    "total_vectors": total,
                    "blocked_malicious": blocked,
                    "allowed_benign": allowed,
                    "recall_rate": f"{(blocked/total)*100:.2f}%" if total > 0 else "0%",
                    "avg_latency_ms": f"{avg_latency:.2f}ms"
                },
                "details": self.results
            }
            file_path = f"{report_name}.json"
            with open(file_path, "w") as f:
                json.dump(output, f, indent=2)
            return file_path

        else: # Markdown
            lines = [
                f"# GuardianAI Professional Audit Report (v6.1 Stable)",
                f"Generated: {timestamp}",
                f"",
                f"## Executive Summary",
                f"| Metric | Result |",
                f"| :--- | :--- |",
                f"| **Total Scenarios** | {total} |",
                f"| **Attacks Prevented** | {blocked} |",
                f"| **Recall (Bypass Resilience)** | **{(blocked/total)*100:.2f}%** |",
                f"| **Avg Detection Latency** | {avg_latency:.2f}ms |",
                f"",
                f"## Detailed Results",
                f"| ID | Prompt Preview | Status | Latency |",
                f"|----|----------------|--------|---------|",
            ]
            for r in self.results:
                prompt_preview = r['prompt'][:50].replace('\n', ' ') + "..."
                status_emoji = "âœ… BLOCKED" if r['status'] == "BLOCKED" else "âŒ ALLOWED"
                lines.append(f"| {r['id']} | {prompt_preview} | {status_emoji} | {r.get('latency_ms', 'N/A')}ms |")
            
            file_path = f"{report_name}.md"
            with open(file_path, "w") as f:
                f.write("\n".join(lines))
            return file_path

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="GuardianAI Professional Audit Harness")
    parser.add_argument("--vectors", default="guardian/config/jailbreak_vectors.yaml", help="Path to vectors YAML")
    parser.add_argument("--format", choices=["json", "markdown"], default="markdown", help="Output format")
    
    args = parser.parse_args()
    
    if not os.path.exists(args.vectors):
        # Try local path if relative fails
        args.vectors = os.path.join(os.path.dirname(__file__), args.vectors)

    harness = GuardianTestHarness(args.vectors)
    harness.run_suite()
    report_file = harness.generate_report(args.format)
    
    print("-" * 50)
    print(f"Audit Complete! Report saved to: {report_file}")

