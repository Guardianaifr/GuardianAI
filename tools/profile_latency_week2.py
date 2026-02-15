
import json
import time
import statistics
import os
import sys
import logging
from unittest.mock import MagicMock, patch

# Add parent directory to path to import guardian modules
base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.append(base_dir)
# Add inner guardian directory as well for direct imports
sys.path.append(os.path.join(base_dir, "guardian"))

from guardian.runtime.interceptor import GuardianProxy

# Configure logging to suppress noise
logging.getLogger("GuardianAI").setLevel(logging.ERROR)
logging.getLogger("werkzeug").setLevel(logging.ERROR)

def load_corpus(path):
    with open(path, 'r', encoding='utf-8') as f:
        return json.load(f)

def calculate_percentiles(data):
    if not data:
        return {"p50": 0, "p95": 0, "p99": 0, "max": 0}
    sorted_data = sorted(data)
    n = len(sorted_data)
    return {
        "p50": sorted_data[int(n * 0.50)],
        "p95": sorted_data[int(n * 0.95)],
        "p99": sorted_data[int(n * 0.99)],
        "max": sorted_data[-1]
    }

class LatencyProfiler:
    def __init__(self, config):
        self.proxy = GuardianProxy(config)
        self.results = {
            "total_latency": [],
            "input_filter": [],
            "threat_feed": [],
            "ai_firewall": [],
            "output_validator": []
        }
        
        # Monkey patch _report_event to capture timings
        self.original_report = self.proxy._report_event
        self.proxy._report_event = self._capture_event

    def _capture_event(self, event_type, severity, details):
        # Capture timings from details
        timings = details.get("component_timings", {})
        if timings:
            if "input_filter_ms" in timings:
                self.results["input_filter"].append(timings["input_filter_ms"])
            if "threat_feed_ms" in timings:
                self.results["threat_feed"].append(timings["threat_feed_ms"])
            if "ai_firewall_ms" in timings:
                self.results["ai_firewall"].append(timings["ai_firewall_ms"])
            if "output_validator_ms" in timings:
                self.results["output_validator"].append(timings["output_validator_ms"])

    def run(self, corpus):
        print(f"Profiling {len(corpus)} requests...")
        
        # Mock downstream dependency to avoid network IO affecting latency measurement of PROXY components
        # We want to measure GuardianAI overhead, not specific downstream latency
        with patch('requests.request') as mock_req:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_resp.content = b'{"choices": [{"message": {"content": "Safe response"}}]}'
            mock_resp.raw.headers = {}
            mock_req.return_value = mock_resp
            
            # Also mock health check
            with patch('requests.get') as mock_get:
                mock_get.return_value.status_code = 200

                for i, item in enumerate(corpus):
                    if i % 100 == 0:
                        print(f"Processing {i}/{len(corpus)}...")
                    
                    prompt = item["text"]
                    # Use Flask test context
                    with self.proxy.app.test_request_context(
                        '/v1/chat/completions',
                        method='POST',
                        json={"messages": [{"role": "user", "content": prompt}]},
                        headers={"X-Conversation-ID": f"test-session-{i}"}
                    ):
                        start = time.perf_counter()
                        self.proxy.proxy('v1/chat/completions')
                        total_ms = (time.perf_counter() - start) * 1000
                        self.results["total_latency"].append(total_ms)

    def generate_report(self, output_path):
        report = []
        report.append("# 🚀 GuardianAI Latency Profile (Week 2)")
        report.append(f"\n**Date**: {time.strftime('%Y-%m-%d')}")
        report.append(f"**Sample Size**: {len(self.results['total_latency'])} requests")
        
        report.append("\n## 📊 Summary Metrics")
        stats = calculate_percentiles(self.results["total_latency"])
        report.append(f"- **p50 (Median)**: {stats['p50']:.2f}ms")
        report.append(f"- **p95**: {stats['p95']:.2f}ms")
        report.append(f"- **p99**: {stats['p99']:.2f}ms")
        report.append(f"- **Max**: {stats['max']:.2f}ms")
        
        report.append("\n## 🧩 Component Breakdown")
        
        components = ["input_filter", "threat_feed", "ai_firewall", "output_validator"]
        
        for comp in components:
            data = self.results.get(comp, [])
            if data:
                c_stats = calculate_percentiles(data)
                report.append(f"\n### {comp.replace('_', ' ').title()}")
                report.append(f"- Calls: {len(data)}")
                report.append(f"- p50: {c_stats['p50']:.4f}ms")
                report.append(f"- p95: {c_stats['p95']:.4f}ms")
                report.append(f"- p99: {c_stats['p99']:.4f}ms")
            else:
                 report.append(f"\n### {comp.replace('_', ' ').title()}")
                 report.append("- No data recorded (component likely skipped or disabled)")

        with open(output_path, "w", encoding="utf-8") as f:
            f.write("\n".join(report))
        
        print(f"\nReport generated at {output_path}")
        print("\n".join(report))

def main():
    config = {
        "guardian_id": "profiler",
        "proxy": {"listen_port": 8081, "target_url": "http://mock"},
        "rate_limiting": {"enabled": False}, # Disable RL to test raw throughput/latency
        "security_policies": {
            "security_mode": "balanced",
            "validate_output": True
        },
        "backend": {"enabled": False},
        "threat_feed": {"enabled": True, "url": "mock", "update_interval_seconds": 9999}
    }
    
    corpus_path = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "tests", "data", "corpus_week2.json")
    if not os.path.exists(corpus_path):
        print(f"Corpus not found at {corpus_path}")
        return
        
    profiler = LatencyProfiler(config)
    corpus = load_corpus(corpus_path)
    profiler.run(corpus)
    profiler.generate_report("latency_report_week2.md")

if __name__ == "__main__":
    main()
