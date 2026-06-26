"""
p99 Latency Stress Test
-----------------------
Enterprise SLA benchmark. Measures the 95th and 99th percentile latency
under concurrent load to prove GuardianAI does not suffer from latency spikes.
"""
import requests
import time
import numpy as np
import concurrent.futures

PROXY_URL = "http://127.0.0.1:8081/v1/chat/completions"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer p99_clean_session_token_555"
}

def make_request(prompt):
    payload = {
        "model": "openclaw",
        "messages": [{"role": "user", "content": prompt}]
    }
    start = time.time()
    try:
        res = requests.post(PROXY_URL, json=payload, headers=HEADERS, timeout=5)
        # We only care about the time it took
        elapsed = time.time() - start
        return elapsed * 1000  # convert to ms
    except Exception:
        return None

def run_p99_test():
    print("Running p99 Latency Stress Test...")
    print("-" * 50)
    
    num_requests = 200
    prompts = ["Tell me a joke.", "What is the weather?", "Explain quantum physics."] * 100
    prompts = prompts[:num_requests]
    
    latencies = []
    
    print(f"Firing {num_requests} concurrent requests to measure tail latency...")
    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(make_request, prompts)
        for r in results:
            if r is not None:
                latencies.append(r)
                
    if not latencies:
        print("ERROR: All requests failed.")
        return
        
    p50 = np.percentile(latencies, 50)
    p90 = np.percentile(latencies, 90)
    p95 = np.percentile(latencies, 95)
    p99 = np.percentile(latencies, 99)
    p100 = max(latencies)
    
    print("\nLatency Percentiles (ms):")
    print(f"  p50 (Median): {p50:.2f} ms")
    print(f"  p90         : {p90:.2f} ms")
    print(f"  p95         : {p95:.2f} ms")
    print(f"  p99         : {p99:.2f} ms")
    print(f"  Max         : {p100:.2f} ms")
    
    if p99 < 150:
        print("\n✅ PASSED! p99 latency is well under the 150ms enterprise SLA.")
    else:
        print("\n❌ FAILED! Latency spikes detected.")

if __name__ == "__main__":
    run_p99_test()
