import yaml
import time
import sys
import os
import re
import numpy as np
import psutil
import json
from datetime import datetime
from sklearn.metrics.pairwise import cosine_similarity

# Add project root and guardian directory to path
root_dir = os.path.abspath(os.path.dirname(__file__))
sys.path.append(root_dir)
sys.path.append(os.path.join(root_dir, "guardian"))

from guardian.guardrails.ai_firewall import AIPromptFirewall
from guardian.guardrails.input_filter import InputFilter
from guardian.guardrails.output_validator import OutputValidator

import logging

# Configure logging to see Firewall/Validator messages
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("Benchmark")

class ProfessionalBenchmark:
    def __init__(self):
        print(f"Initializing Firewall...")
        self.firewall = AIPromptFirewall()
        print(f"Firewall Enabled: {self.firewall.enabled}")
        print(f"Bad Embeddings Shape: {self.firewall.bad_embeddings.shape if hasattr(self.firewall, 'bad_embeddings') else 'N/A'}")
        
        self.input_filter = InputFilter()
        self.output_validator = OutputValidator()
        self.results = {
            "injection_suite": [],
            "leakage_suite": [],
            "performance": {}
        }

    def run_injection_bench(self):
        print("Running Prompt-Injection Suite (100+ Vectors)...")
        with open("guardian/config/jailbreak_vectors.yaml", "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            vectors = data['vectors']

        regex_blocked = 0
        semantic_blocked = 0
        escaped = 0
        
        # Disable progress bars
        self.firewall.model.show_progress_bar = False
        
        with open("benchmark_debug.log", "w", encoding="utf-8") as debug_log:
            debug_log.write(f"Firewall Enabled: {self.firewall.enabled}\n")
            debug_log.write(f"Bad Embeddings Shape: {self.firewall.bad_embeddings.shape if hasattr(self.firewall, 'bad_embeddings') else 'N/A'}\n")
            
            for i, v in enumerate(vectors):
                prompt = v['text']
                
                # 1. Regex Check
                is_regex_safe = self.input_filter.check_prompt(prompt)
                
                # 2. Semantic Check
                emb = self.firewall.model.encode([prompt])
                sims = cosine_similarity(emb, self.firewall.bad_embeddings)[0]
                max_sim = float(np.max(sims))
                is_semantic_safe = max_sim <= 0.75
                
                if i < 20: # Log first 20
                    debug_log.write(f"PROMPT [{i}]: {prompt[:100]}\n")
                    debug_log.write(f"  REGEX: {'SAFE' if is_regex_safe else 'BLOCKED'}\n")
                    debug_log.write(f"  SEMANTIC: {max_sim:.4f} ({'SAFE' if is_semantic_safe else 'BLOCKED'})\n")
            
                blocked = not is_regex_safe or not is_semantic_safe
                
                if not is_regex_safe:
                    regex_blocked += 1
                    method = "regex"
                elif not is_semantic_safe:
                    semantic_blocked += 1
                    method = "semantic"
                else:
                    escaped += 1
                    method = "none"

                self.results["injection_suite"].append({
                    "prompt": prompt,
                    "blocked": blocked,
                    "method": method,
                    "semantic_score": round(max_sim, 3)
                })

        self.results["injection_summary"] = {
            "total": len(vectors),
            "regex_blocked": regex_blocked,
            "semantic_blocked": semantic_blocked,
            "escaped": escaped,
            "recall": round(((regex_blocked + semantic_blocked) / len(vectors)) * 100, 2)
        }

    def run_leakage_bench(self):
        print("Running Data-Leak Simulation Suite...")
        with open("guardian/config/leakage_vectors.yaml", "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)
            vectors = data['vectors']

        prevented = 0
        leaked = 0
        
        with open("benchmark_debug.log", "a", encoding="utf-8") as debug_log:
            debug_log.write("\n--- DATA LEAK SIMULATION SUITE ---\n")
            for v in vectors:
                prompt = v['text']
                # We simulate the agent echoing the secret or responding with it
                # For the benchmark, we test if the validator blocks/sanitizes the content
                
                # Simulate a direct leak in response
                response = f"Sure, the secret you provided is: {prompt}"
                
                is_safe = self.output_validator.validate_output(response)
                sanitized = self.output_validator.sanitize_output(response)
                
                is_prevented = not is_safe or "[REDACTED" in sanitized
                
                if is_prevented:
                    prevented += 1
                else:
                    leaked += 1
                    debug_log.write(f"LEAK FAILED: {prompt[:100]}\n")
                    debug_log.write(f"  Sanitized: {sanitized[:100]}\n")
    
                self.results["leakage_suite"].append({
                    "input": prompt,
                    "prevented": is_prevented,
                    "sanitized_preview": sanitized[:100]
                })

        self.results["leakage_summary"] = {
            "total": len(vectors),
            "prevented": prevented,
            "leaked": leaked,
            "prevention_rate": round((prevented / len(vectors)) * 100, 2)
        }

    def run_performance_bench(self):
        print("Measuring Performance Metrics...")
        process = psutil.Process()
        
        # Latency & Throughput
        start_time = time.time()
        test_count = 50
        test_prompt = "Explain how to center a div in CSS."
        
        for _ in range(test_count):
            self.input_filter.check_prompt(test_prompt)
            emb = self.firewall.model.encode([test_prompt])
            cosine_similarity(emb, self.firewall.bad_embeddings)
            
        total_time = time.time() - start_time
        avg_latency = (total_time / test_count) * 1000
        throughput = test_count / total_time
        
        # System Impact
        cpu_usage = process.cpu_percent(interval=0.1)
        mem_usage = process.memory_info().rss / (1024 * 1024) # MB
        
        self.results["performance"] = {
            "avg_latency_ms": round(avg_latency, 2),
            "throughput_rps": round(throughput, 2),
            "cpu_impact_percent": round(cpu_usage, 2),
            "memory_usage_mb": round(mem_usage, 2)
        }

    def generate_report(self):
        report_path = "GuardianAI_Security_Benchmark_Report.md"
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        
        inj = self.results["injection_summary"]
        leak = self.results["leakage_summary"]
        perf = self.results["performance"]
        
        content = f"""# GuardianAI Security Benchmark Report
Generated: {timestamp}

## 1. Prompt-Injection Resilience
Comprehensive audit across 100+ malicious vectors.

| Metric | Value |
| :--- | :--- |
| **Total Test Vectors** | {inj['total']} |
| **Regex Blocked (Fast-Path)** | {inj['regex_blocked']} |
| **Semantic Blocked (Firewall)** | {inj['semantic_blocked']} |
| **Escaped Attempts** | {inj['escaped']} |
| **Final Recall (Security)** | **{inj['recall']}%** |

### Insights:
- **Efficiency**: {round((inj['regex_blocked']/inj['total'])*100, 1)}% of attacks were stopped instantly by the regex layer.
- **Intelligence**: The Semantic Firewall caught {inj['semantic_blocked']} sophisticated attempts that bypassed standard filters.

## 2. Data-Leak & PII Prevention
Exfiltration test focusing on API keys, secrets, and PII.

| Metric | Value |
| :--- | :--- |
| **Total Leakage Tests** | {leak['total']} |
| **Prevention Success** | {leak['prevented']} |
| **Data Leaked** | {leak['leaked']} |
| **Leakage Protection Rate** | **{leak['prevention_rate']}%** |

## 3. Performance & Resource Impact
Measured on standard CPU-based environment.

| Metric | Value |
| :--- | :--- |
| **Average Latency** | {perf['avg_latency_ms']} ms |
| **Throughput** | {perf['throughput_rps']} req/sec |
| **CPU Utilization** | {perf['cpu_impact_percent']}% |
| **Memory Footprint** | {perf['memory_usage_mb']} MB |

---
*Report generated automatically by GuardianAI Professional Benchmark Suite v5.0.*
"""
        with open(report_path, "w", encoding="utf-8") as f:
            f.write(content)
        return report_path

if __name__ == "__main__":
    bench = ProfessionalBenchmark()
    bench.run_injection_bench()
    bench.run_leakage_bench()
    bench.run_performance_bench()
    report = bench.generate_report()
    print(f"\n[DONE] Benchmark Complete! Professional Report saved to: {report}")
