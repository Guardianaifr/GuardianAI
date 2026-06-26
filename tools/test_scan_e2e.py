"""Quick E2E test of the crypto audit scan pipeline."""
import requests
import time
import json

BASE = "http://localhost:8001"

# 1. Create async scan job
print("=== Creating scan job ===")
r = requests.post(f"{BASE}/api/v1/scan-jobs", json={
    "target_url": "https://agentlove.fun",
    "target_name": "AgentLove.fun",
    "depth": "quick",
}, timeout=10)
job = r.json()
job_id = job.get("job_id", "")
print(f"Job: {job_id}  Status: {job.get('status')}")

# 2. Poll until done
print("\n=== Polling ===")
for i in range(40):
    time.sleep(2)
    r2 = requests.get(f"{BASE}/api/v1/scan-jobs/{job_id}")
    j = r2.json()
    status = j.get("status")
    pct = j.get("progress_pct", 0)
    label = j.get("progress_label", "")
    print(f"  [{i:02d}] {status:10s} {pct:5.1f}%  {label}")

    if status in ("completed", "failed"):
        break

# 3. Show results
print("\n=== Results ===")
if status == "completed":
    result = j.get("result", {})
    print(f"Grade:      {result.get('grade')}")
    print(f"Score:      {result.get('score')}/100")
    print(f"Vulns:      {result.get('vulnerabilities_found')}")
    print(f"Protected:  {result.get('protected_count')}")
    print(f"Scan ID:    {result.get('scan_id')}")
    arts = result.get("artifacts", {})
    if arts:
        print(f"Report URL: {arts.get('report_url')}")
        if arts.get("badge_svg_url"):
            print(f"Badge URL:  {arts.get('badge_svg_url')}")
    # Show pillar scores
    for pname, pdata in result.get("pillar_scores", {}).items():
        print(f"  {pname[:35]:35s} {pdata['score']:5.1f}%  ({pdata['vulnerable']}/{pdata['total']} vuln)")
else:
    print(f"FAILED: {j.get('error')}")
