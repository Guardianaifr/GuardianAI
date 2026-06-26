import requests, time

BASE = "http://localhost:8001"

print("--- Testing P2 Continuous Monitoring API ---")
try:
    print("1. Creating Schedule...")
    r = requests.post(f"{BASE}/api/v1/schedules", json={
        "target_url": "https://agentlove.fun",
        "target_name": "AgentLove",
        "interval_seconds": 60,
        "scan_mode": "quick"
    })
    print(f"Status: {r.status_code}")
    data = r.json()
    print(data)
    sched_id = data.get("schedule_id")

    print("\n2. Listing Schedules...")
    r2 = requests.get(f"{BASE}/api/v1/schedules")
    print(f"Status: {r2.status_code}")
    print(r2.json())

    print(f"\n3. Waiting 5s for scheduler to start running...")
    time.sleep(5)

    print("\n4. Deleting Schedule...")
    r3 = requests.delete(f"{BASE}/api/v1/schedules/{sched_id}")
    print(f"Status: {r3.status_code}")
    print(r3.json())

    print("\n5. Getting History...")
    r4 = requests.get(f"{BASE}/api/v1/schedules/history")
    print(f"Status: {r4.status_code}")
    print(r4.json())

except Exception as e:
    print(f"Failed: {e}")
