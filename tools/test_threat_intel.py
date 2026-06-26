"""
Live test: BitcoinDepot threat intelligence + address screening API.
"""
import sys, io, os, subprocess, time, requests

sys.stdout = io.TextIOWrapper(sys.stdout.buffer, encoding="utf-8")
BASE = "http://127.0.0.1:8001"
PASS = True

def check(label, ok, detail=""):
    global PASS
    icon = "[OK]" if ok else "[FAIL]"
    print(f"  {icon} {label}", f"-- {detail}" if detail else "")
    if not ok: PASS = False

BTM_ADDRESSES = [
    "bc1qqt65qe94rm5kh7srhpp2u5cd5gtcc3peyesfmz",
    "bc1q9mppvhrrmdw9d05tvtvacgk87muvwstpxt59ce",
    "bc1q4ut9geva75wyeh78vx7tm4lehlkl77z6w5vksp",
    "bc1q5aes997chagmc6h8z4nlq0nk2waj8ff370hnlu",
]

def main():
    print("=" * 60)
    print("  THREAT INTELLIGENCE - LIVE API TEST")
    print("  BitcoinDepot BTM / March 2026")
    print("=" * 60)

    print("\n[0] Starting backend...")
    proc = subprocess.Popen(
        [sys.executable, "backend/main.py"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env={**os.environ, "GUARDIAN_BACKEND_PORT": "8001",
             "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}
    )
    import threading
    threading.Thread(target=lambda: [None for l in iter(proc.stdout.readline, "")], daemon=True).start()
    time.sleep(5)
    if proc.poll() is not None:
        print("[-] Server died!"); sys.exit(1)

    try:
        # 1. Stats
        print("\n[1] GET /api/v1/threat-intel/stats")
        r = requests.get(f"{BASE}/api/v1/threat-intel/stats", timeout=5)
        check("Status 200", r.status_code == 200)
        stats = r.json()
        check("Has incidents", stats.get("total_incidents", 0) >= 1)
        check("Has 19 addresses", stats.get("total_addresses_tracked", 0) == 19, str(stats.get("total_addresses_tracked")))
        check("Tracks 54+ BTC stolen", stats.get("total_stolen_btc", 0) >= 54)
        check("KuCoin flagged as exit", "KuCoin" in stats.get("exit_exchanges", []))
        print(f"     Stats: {stats}")

        # 2. List incidents
        print("\n[2] GET /api/v1/threat-intel/incidents")
        r = requests.get(f"{BASE}/api/v1/threat-intel/incidents", timeout=5)
        check("Status 200", r.status_code == 200)
        data = r.json()
        incidents = data.get("incidents", [])
        check("BTM incident present", any("BTM" in i.get("name", "") for i in incidents))
        btm = [i for i in incidents if "BTM" in i.get("name", "")][0]
        check("Entity is BitcoinDepot", "BitcoinDepot" in btm.get("entity", ""))
        check("Type is key_compromise", btm.get("incident_type") == "key_compromise")
        check("72h detection delay", btm.get("detection_delay_hours") == 72)

        # 3. Screen a known theft address
        print("\n[3] Screen known theft address")
        r = requests.post(f"{BASE}/api/v1/threat-intel/screen", json={
            "address": "bc1qqt65qe94rm5kh7srhpp2u5cd5gtcc3peyesfmz"
        }, timeout=5)
        check("Status 200", r.status_code == 200)
        result = r.json()
        check("FLAGGED", result.get("flagged") == True)
        check("Threat level CRITICAL", result.get("threat_level") == "critical")
        check("Role is theft_address", result.get("role") == "theft_address")
        check("Links to BTM incident", "BTM" in result.get("incident_name", ""))
        check("KuCoin destination", result.get("destination_exchange") == "KuCoin")
        check("NOT in commercial tools", result.get("in_commercial_tools") == False)
        print(f"     Result: {result}")

        # 4. Screen a clean address
        print("\n[4] Screen clean address")
        r = requests.post(f"{BASE}/api/v1/threat-intel/screen", json={
            "address": "bc1qcleanaddressnotinthefeedxxxxxxxxxxxxxxx"
        }, timeout=5)
        check("Status 200", r.status_code == 200)
        result = r.json()
        check("NOT flagged", result.get("flagged") == False)

        # 5. Batch screening
        print("\n[5] Batch screen (4 addresses)")
        r = requests.post(f"{BASE}/api/v1/threat-intel/screen/batch", json={
            "addresses": BTM_ADDRESSES + ["bc1qcleanaddressxxxxxxxxxxxxxxxxxxxxxx"]
        }, timeout=5)
        check("Status 200", r.status_code == 200)
        batch = r.json()
        check("5 total screened", batch.get("total_screened") == 5)
        check("4 flagged", batch.get("total_flagged") == 4, str(batch.get("total_flagged")))

        # 6. Get incident details
        print("\n[6] GET incident details")
        r = requests.get(f"{BASE}/api/v1/threat-intel/incidents/INC-BTM-2026-0320", timeout=5)
        check("Status 200", r.status_code == 200)
        inc = r.json()
        check("Has SEC filing URL", "sec.gov" in (inc.get("sec_filing_url") or ""))
        check("19 addresses in incident", len(inc.get("addresses", [])) == 19)
        check("Source is zachxbt", "zachxbt" in inc.get("source", ""))

    finally:
        proc.terminate()
        try: proc.wait(timeout=5)
        except: proc.kill()

    print("\n" + "=" * 60)
    print(f"  {'ALL THREAT INTEL TESTS PASSED' if PASS else 'SOME TESTS FAILED'}")
    print("=" * 60)
    sys.exit(0 if PASS else 1)

if __name__ == "__main__":
    main()
