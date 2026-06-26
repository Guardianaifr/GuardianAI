import subprocess
import time
import requests
import sys
import io
import os

# Ensure UTF-8 output on Windows
sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding='utf-8')

BASE = "http://127.0.0.1:8001"
PASS = True

def check(label, ok, detail=""):
    global PASS
    icon = "[OK]" if ok else "[FAIL]"
    print(f"  {icon} {label}", f"-- {detail}" if detail else "")
    if not ok:
        PASS = False

def main():
    print("=" * 60)
    print("  P2 LIVE END-TO-END FEATURE VERIFICATION")
    print("=" * 60)

    # 1. Start the server
    print("\n[1] Starting backend server and mock target...")
    server_process = subprocess.Popen(
        [sys.executable, "backend/main.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
        env={
            **os.environ,
            "GUARDIAN_BACKEND_PORT": "8001",
            "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
        }
    )
    
    mock_process = subprocess.Popen(
        [sys.executable, "mock_target.py"],
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True
    )
    
    # Start thread to log server output
    import threading
    def log_stream():
        for line in iter(server_process.stdout.readline, ''):
            print(f"[SERVER] {line.strip()}")
    
    t = threading.Thread(target=log_stream, daemon=True)
    t.start()
    
    # Wait for server and mock target to start
    time.sleep(5)
    
    # Check if server process is still running
    poll = server_process.poll()
    if poll is not None:
        print(f"[-] Server process died immediately with code {poll}!")
        sys.exit(1)
        
    poll_mock = mock_process.poll()
    if poll_mock is not None:
        print(f"[-] Mock target died immediately with code {poll_mock}!")
        sys.exit(1)
    
    try:
        # 2. Get billing plans
        print("\n[2] Testing Public Billing Plans Endpoint...")
        try:
            r = requests.get(f"{BASE}/api/v1/public/plans", timeout=5)
            check("Plans status 200", r.status_code == 200)
            data = r.json()
            check("Plan catalog is correct", "lifetime" in data.get("plans", {}))
        except Exception as e:
            check("Plans endpoint reachable", False, str(e))

        # 3. Authenticate and get JWT token (contains org_id)
        print("\n[3] Authenticating & Generating JWT...")
        token = ""
        try:
            r = requests.post(f"{BASE}/api/v1/auth/token", auth=("admin", "guardian_default"), timeout=5)
            check("Auth status 200", r.status_code == 200)
            token_data = r.json()
            token = token_data.get("access_token", "")
            check("Received token", bool(token))
            check("Role is admin", token_data.get("role") == "admin")
        except Exception as e:
            check("Auth endpoint reachable", False, str(e))

        headers = {"Authorization": f"Bearer {token}"} if token else {}

        # 4. Initiate checkout (simulated pricing page flow)
        print("\n[4] Testing Billing Checkout Endpoint...")
        try:
            payload = {
                "plan": "pro",
                "customer_email": "enterprise@test.com",
                "tenant_name": "Test Org",
                "payment_method": "card"
            }
            r = requests.post(f"{BASE}/api/v1/billing/checkout", json=payload, timeout=5)
            check("Checkout status 200", r.status_code == 200)
            checkout_data = r.json()
            check("Has checkout_url", "checkout_url" in checkout_data)
        except Exception as e:
            check("Checkout endpoint reachable", False, str(e))

        # 5. Create a scan job to test compliance mapping and remediation
        print("\n[5] Triggering Scan Job for Remediation & Compliance Mapping...")
        scan_id = ""
        findings = []
        try:
            r = requests.post(f"{BASE}/api/v1/scan-jobs", json={
                "target_url": "http://127.0.0.1:8080",
                "target_name": "MockTarget",
                "depth": "quick"
            }, timeout=10)
            job_id = r.json().get("job_id", "")
            
            # Poll scan job completion
            for _ in range(20):
                time.sleep(2)
                j = requests.get(f"{BASE}/api/v1/scan-jobs/{job_id}").json()
                if j.get("status") in ("completed", "failed"):
                    break
            
            result = j.get("result") or {}
            scan_id = result.get("scan_id", "")
            check("Scan job completed", j.get("status") == "completed", f"Status: {j.get('status')}")
            
            # Verify compliance mapping is returned in findings
            findings = result.get("findings", [])
            has_compliance = False
            for f in findings:
                if "compliance_mappings" in f and f["compliance_mappings"]:
                    has_compliance = True
                    break
            check("Findings contain compliance mappings", has_compliance)
        except Exception as e:
            check("Scan job run successfully", False, str(e))

        # 6. Verify Remediation Tracking
        print("\n[6] Testing Remediation Verification Endpoint...")
        if scan_id:
            try:
                # Let's find a vulnerable vector id
                vuln_vectors = [f["vector_id"] for f in findings if f["status"] == "vulnerable"]
                if vuln_vectors:
                    payload = {"scan_id": scan_id, "vector_ids": [vuln_vectors[0]]}
                    r = requests.post(f"{BASE}/api/v1/scan/verify", json=payload, headers=headers, timeout=5)
                    check("Verify remediation status 200", r.status_code == 200, str(r.status_code))
                    res_data = r.json()
                    check("Verify success", res_data.get("status") == "success")
                    check("Score recalculated", "new_score" in res_data)
                else:
                    check("No vulnerable vectors found to remediate", True)
            except Exception as e:
                check("Remediation endpoint test successful", False, str(e))
        else:
            check("Remediation verification bypassed (no scan_id)", False)

        # 7. Create continuous monitoring schedule with stream_mode
        print("\n[7] Testing Continuous Monitoring Schedule...")
        try:
            r = requests.post(f"{BASE}/api/v1/schedules", json={
                "target_url": "https://agentlove.fun",
                "target_name": "AgentLove",
                "interval_seconds": 60,
                "scan_mode": "quick",
                "stream_mode": True
            }, timeout=5)
            check("Create schedule status 200", r.status_code == 200)
            sched_data = r.json()
            sched_id = sched_data.get("schedule_id", "")
            check("Has schedule_id", bool(sched_id))
            
            # List schedules and verify stream_mode is preserved
            r_list = requests.get(f"{BASE}/api/v1/schedules", timeout=5)
            schedules = r_list.json().get("schedules", [])
            stream_mode_saved = any(s.get("schedule_id") == sched_id and s.get("stream_mode") is True for s in schedules)
            check("Stream mode saved successfully", stream_mode_saved)
            
            # Delete schedule
            if sched_id:
                requests.delete(f"{BASE}/api/v1/schedules/{sched_id}", timeout=5)
        except Exception as e:
            check("Schedules endpoint test successful", False, str(e))

    finally:
        print("\n[8] Stopping backend server and mock target...")
        server_process.terminate()
        mock_process.terminate()
        try:
            server_process.wait(timeout=5)
            mock_process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            server_process.kill()
            mock_process.kill()

    print("\n" + "=" * 60)
    print(f"  {'ALL ENTERPRISE P2 FEATURES VERIFIED WORKING (PASS)' if PASS else 'SOME VERIFICATION CHECKS FAILED (FAIL)'}")
    print("=" * 60)
    sys.exit(0 if PASS else 1)

if __name__ == "__main__":
    main()
