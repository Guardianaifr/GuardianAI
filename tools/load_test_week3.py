
import concurrent.futures
import time
import requests
import json
import statistics
import sys
import os

# Configuration
TARGET_URL = "http://localhost:8081/v1/chat/completions"
# Using a simple prompt for load testing
PAYLOAD = {
    "messages": [{"role": "user", "content": "Hello, is this safe?"}],
    "model": "gpt-3.5-turbo"
}
HEADERS = {"Content-Type": "application/json"}

def send_request(request_id):
    start_time = time.perf_counter()
    try:
        response = requests.post(TARGET_URL, json=PAYLOAD, headers=HEADERS, timeout=10)
        latency = (time.perf_counter() - start_time) * 1000
        return {
            "id": request_id,
            "status": response.status_code,
            "latency": latency,
            "error": None
        }
    except Exception as e:
        latency = (time.perf_counter() - start_time) * 1000
        return {
            "id": request_id,
            "status": 0,
            "latency": latency,
            "error": str(e)
        }

def run_load_test(concurrent_users, total_requests):
    print(f"\n--- Starting Load Test: {concurrent_users} Concurrent Users ---")
    print(f"Target: {total_requests} Total Requests")
    
    results = []
    start_time = time.time()
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrent_users) as executor:
        # Submit all requests
        futures = [executor.submit(send_request, i) for i in range(total_requests)]
        
        # Wait for completion
        for future in concurrent.futures.as_completed(futures):
            results.append(future.result())
            
    total_duration = time.time() - start_time
    
    # Calculate Metrics
    latencies = [r["latency"] for r in results if r["error"] is None]
    errors = [r for r in results if r["error"] is not None]
    status_codes = {}
    for r in results:
        status_codes[r["status"]] = status_codes.get(r["status"], 0) + 1
        
    if not latencies:
        print("No successful requests.")
        return

    p50 = statistics.median(latencies)
    p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else max(latencies)
    p99 = statistics.quantiles(latencies, n=100)[98] if len(latencies) >= 100 else max(latencies)
    throughput = len(results) / total_duration
    
    print(f"Duration: {total_duration:.2f}s")
    print(f"Throughput: {throughput:.2f} req/sec")
    print(f"Latency (ms): p50={p50:.2f}, p95={p95:.2f}, p99={p99:.2f}")
    print(f"Status Codes: {status_codes}")
    print(f"Errors: {len(errors)}")
    
    return {
        "concurrent_users": concurrent_users,
        "throughput": throughput,
        "p95": p95,
        "errors": len(errors)
    }

if __name__ == "__main__":
    print("GuardianAI Load Test Tool (Week 3)")
    
    # Check if server is running
    try:
        requests.get("http://localhost:8081/health", timeout=2)
    except:
        print("❌ Error: GuardianAI proxy is not running on http://localhost:8081")
        print("Please start the proxy before running load tests.")
        sys.exit(1)

    scenarios = [
        (20, 100),   # Warmup
        (50, 500),   # Moderate Load
        (100, 1000)  # High Load
    ]
    
    report = []
    
    for users, reqs in scenarios:
        res = run_load_test(users, reqs)
        report.append(res)
        time.sleep(2) # Cooldown
        
    print("\n=== Load Test Summary ===")
    for r in report:
        if r:
            print(f"Users: {r['concurrent_users']} | TPS: {r['throughput']:.2f} | p95: {r['p95']:.2f}ms | Errors: {r['errors']}")
