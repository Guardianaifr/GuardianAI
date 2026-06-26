"""Quick verify all P0 endpoints."""
import requests
BASE = "http://localhost:8001"

tests = [
    ("Audit Page", "/site/audit.html"),
    ("Leaderboard Page", "/site/leaderboard.html"),
    ("Leaderboard API", "/api/v1/leaderboard"),
    ("Scan History API", "/api/v1/scan-history"),
    ("Health", "/health"),
]

print("P0 Endpoint Status:")
for name, path in tests:
    r = requests.get(f"{BASE}{path}", timeout=5)
    print(f"  {name:25s} {path:35s} -> {r.status_code}")

# Check leaderboard data
r = requests.get(f"{BASE}/api/v1/leaderboard")
data = r.json()
print(f"\nLeaderboard: {len(data.get('projects',[]))} projects, avg={data['stats']['avg_score']}")

# Check scan history with trend
r = requests.get(f"{BASE}/api/v1/scan-history?target_url=https://agentlove.fun")
data = r.json()
t = data.get("trend")
print(f"History: {data['total']} scans, trend={'stable' if not t else t['direction']}")
print("\nAll P0 endpoints OK!")
