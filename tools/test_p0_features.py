"""Test all P0 features: Leaderboard API, Scan History/Trend, PDF endpoint."""
import requests
import json
import time

BASE = "http://localhost:8001"

print("=" * 60)
print("  P0 FEATURE VERIFICATION")
print("=" * 60)

# 1. Run a quick scan to populate data
print("\n[1] Running quick scan to populate data...")
r = requests.post(f"{BASE}/api/v1/scan-jobs", json={
    "target_url": "https://agentlove.fun",
    "target_name": "AgentLove.fun",
    "depth": "quick"
}, timeout=10)
job = r.json()
job_id = job.get("job_id", "")
print(f"    Job: {job_id}")

for i in range(30):
    time.sleep(2)
    r2 = requests.get(f"{BASE}/api/v1/scan-jobs/{job_id}")
    j = r2.json()
    if j["status"] in ("completed", "failed"):
        break

scan_id = ""
if j.get("result"):
    scan_id = j["result"].get("scan_id", "")
    print(f"    Scan complete: {j['result']['grade']} ({j['result']['score']}/100) ID={scan_id}")
else:
    print(f"    Scan failed: {j.get('error')}")

# 2. Test Leaderboard API
print("\n[2] Testing Leaderboard API...")
r = requests.get(f"{BASE}/api/v1/leaderboard?limit=10")
data = r.json()
print(f"    Status: {r.status_code}")
print(f"    Projects: {len(data.get('projects', []))}")
stats = data.get("stats", {})
print(f"    Stats: {stats.get('total_audited')} audited, avg={stats.get('avg_score')}, vectors={stats.get('total_vectors_tested')}")
if data.get("projects"):
    top = data["projects"][0]
    print(f"    #1: {top.get('target_name')} - {top.get('grade')} ({top.get('score')}/100)")

# 3. Test Scan History / Trend API
print("\n[3] Testing Scan History / Trend API...")
r = requests.get(f"{BASE}/api/v1/scan-history?target_url=https://agentlove.fun&limit=10")
data = r.json()
print(f"    Status: {r.status_code}")
print(f"    Scans found: {data.get('total')}")
trend = data.get("trend")
if trend:
    print(f"    Trend: {trend['direction']} ({'+' if trend['change']>0 else ''}{trend['change']})")
    print(f"    Current: {trend['current_score']} | Previous: {trend['previous_score']}")
    print(f"    Best: {trend['best_score']} | Worst: {trend['worst_score']} | Avg: {trend['avg_score']}")
else:
    print(f"    Trend: Not enough data yet (need 2+ scans for same target)")

# 4. Test PDF endpoint
print("\n[4] Testing PDF Export endpoint...")
if scan_id:
    r = requests.get(f"{BASE}/api/v1/scan/{scan_id}/pdf", allow_redirects=False)
    print(f"    Status: {r.status_code}")
    ct = r.headers.get("content-type", "")
    cd = r.headers.get("content-disposition", "")
    print(f"    Content-Type: {ct}")
    print(f"    Content-Disposition: {cd}")
    if "pdf" in ct:
        print(f"    PDF size: {len(r.content)} bytes")
    elif "html" in ct:
        print(f"    HTML fallback size: {len(r.content)} bytes (PDF gen requires Chrome/Edge)")
else:
    print("    SKIP: No scan_id available")

# 5. Test Leaderboard page
print("\n[5] Testing Leaderboard HTML page...")
r = requests.get(f"{BASE}/frontend/site/leaderboard.html")
print(f"    Status: {r.status_code}")
print(f"    Size: {len(r.content)} bytes")
has_leaderboard = "Audited Projects Leaderboard" in r.text
print(f"    Has leaderboard content: {has_leaderboard}")

# 6. Test Notification module loads
print("\n[6] Testing Notification module...")
r = requests.get(f"{BASE}/health")
print(f"    Backend healthy: {r.status_code == 200}")

print("\n" + "=" * 60)
print("  ALL P0 TESTS COMPLETE")
print("=" * 60)
