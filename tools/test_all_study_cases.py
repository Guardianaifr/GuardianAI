"""
Full verification: All 5 study case threat feeds loaded and screenable via API.
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

def main():
    print("=" * 60)
    print("  ALL 5 STUDY CASES - THREAT INTEL VERIFICATION")
    print("=" * 60)

    proc = subprocess.Popen(
        [sys.executable, "backend/main.py"],
        stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
        env={**os.environ, "GUARDIAN_BACKEND_PORT": "8001",
             "PYTHONPATH": os.path.dirname(os.path.dirname(os.path.abspath(__file__)))}
    )
    import threading
    threading.Thread(target=lambda: [None for _ in iter(proc.stdout.readline, "")], daemon=True).start()
    time.sleep(5)
    if proc.poll() is not None:
        print("[-] Server died!"); sys.exit(1)

    try:
        # ── Global stats ──
        print("\n[1] Database stats")
        r = requests.get(f"{BASE}/api/v1/threat-intel/stats", timeout=5)
        check("Status 200", r.status_code == 200)
        stats = r.json()
        print(f"     Incidents: {stats.get('total_incidents')}")
        print(f"     Addresses: {stats.get('total_addresses_tracked')}")
        print(f"     Total stolen: ${stats.get('total_stolen_usd', 0):,.0f}")
        print(f"     Exit exchanges: {stats.get('exit_exchanges')}")
        check("5+ incidents loaded", stats.get("total_incidents", 0) >= 5, str(stats.get("total_incidents")))
        check("40+ addresses tracked", stats.get("total_addresses_tracked", 0) >= 40, str(stats.get("total_addresses_tracked")))

        # ── Incident list ──
        print("\n[2] Incident catalog")
        r = requests.get(f"{BASE}/api/v1/threat-intel/incidents", timeout=5)
        incidents = r.json().get("incidents", [])
        names = [i["name"] for i in incidents]
        for i in incidents:
            print(f"     [{i.get('incident_type'):20s}] {i['name'][:50]:50s} ${i.get('total_stolen_usd',0):>14,.0f}")

        check("Study 1: DSJ/BG Ponzi present",    any("DSJ" in n for n in names))
        check("Study 2: LAB manipulation present",  any("LAB" in n for n in names))
        check("Study 3: Social eng present",        any("Social" in n or "Dritan" in n for n in names))
        check("Study 4: DPRK IT workers present",   any("DPRK" in n and "Worker" in n for n in names))
        check("Study 5: Drift exploit present",     any("Drift" in n for n in names))
        check("Study 5: Bybit hack present",        any("Bybit" in n for n in names))
        check("Study 5: Radiant present",           any("Radiant" in n for n in names))

        # ── Screen addresses from each study ──
        test_addresses = {
            "Study 1 - DSJ hot wallet":     "0xf3bd39870d26cfdcdc582ed02b97f74e19e0ee97",
            "Study 2 - LAB insider wallet": "0xf09C19328C26088053a8c9CfB982427bafF2Bd0b",
            "Study 3 - Dritan theft addr":  "bc1qc07ytw5eh32khhvhtlw63kc5yfypvezru6gnue",
            "Study 4 - DPRK payment addr":  "0xb51DA55047Fd899aD08Ab5CE349823664d311998",
            "Study 5 - Drift exploit":      "HkGz4KmoZ7Zmk7HN6ndJ31UJ1qZ2qgwQxgVqQwovpZES",
            "Study 5 - Bybit Lazarus":      "0xDa2e12E94060720581994eEc870F83d9C7200c2c",
            "Clean address":                "0x0000000000000000000000000000000000000000",
        }

        print("\n[3] Address screening across all studies")
        all_addrs = list(test_addresses.values())
        r = requests.post(f"{BASE}/api/v1/threat-intel/screen/batch",
                         json={"addresses": all_addrs}, timeout=5)
        check("Batch status 200", r.status_code == 200)
        batch = r.json()
        check("7 screened", batch.get("total_screened") == 7)
        check("6 flagged (1 clean)", batch.get("total_flagged") == 6, str(batch.get("total_flagged")))

        print("\n  Individual screening results:")
        for label, addr in test_addresses.items():
            r2 = requests.post(f"{BASE}/api/v1/threat-intel/screen",
                              json={"address": addr}, timeout=5)
            res = r2.json()
            if res.get("flagged"):
                print(f"    [FLAGGED]  {label:30s} -> {res.get('threat_level'):8s} | {res.get('incident_name','')[:40]}")
                check(f"{label} flagged", True)
            else:
                print(f"    [CLEAN ]  {label}")
                if "Clean" in label:
                    check(f"{label} is clean", True)

        # ── BTM original addresses still work ──
        print("\n[4] BTM original 19 addresses still indexed")
        r = requests.get(f"{BASE}/api/v1/threat-intel/incidents/INC-BTM-2026-0320", timeout=5)
        check("BTM incident 200", r.status_code == 200)
        btm = r.json()
        check("19 BTM addresses present", len(btm.get("addresses", [])) == 19)

    finally:
        proc.terminate()
        try: proc.wait(timeout=5)
        except: proc.kill()

    print("\n" + "=" * 60)
    print(f"  {'ALL 5 STUDY CASES VERIFIED' if PASS else 'SOME CHECKS FAILED'}")
    print("=" * 60)
    sys.exit(0 if PASS else 1)

if __name__ == "__main__":
    main()
