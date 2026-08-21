import os
import requests
import sys

# Ensure pytest is not in sys.modules so the protection triggers
if 'pytest' in sys.modules:
    del sys.modules['pytest']

# Use backend.main so the monkeypatch is active
from backend.main import _safe_create_connection

def test_ssrf():
    print("--- Test 1: Literal IP (127.0.0.1) ---")
    try:
        resp = requests.get("http://127.0.0.1:9999", timeout=2)
        print("FAIL: Reached 127.0.0.1 without error!")
    except Exception as e:
        if "SSRF Protection" in str(e):
            print("SUCCESS: Blocked literal IP by SSRF filter.")
        else:
            print(f"FAIL: Blocked by something else: {type(e).__name__} - {e}")

    print("\n--- Test 2: Hostname resolving to private IP (localhost) ---")
    try:
        resp = requests.get("http://localhost:9999", timeout=2)
        print("FAIL: Reached localhost without error!")
    except Exception as e:
        if "SSRF Protection" in str(e):
            print("SUCCESS: Blocked hostname resolution by SSRF filter (addr_info block).")
        else:
            print(f"FAIL: Blocked by something else: {type(e).__name__} - {e}")

    print("\n--- Test 3: Allowlisted literal IP (127.0.0.1) ---")
    os.environ["GUARDIAN_SSRF_ALLOWLIST"] = "127.0.0.1"
    try:
        resp = requests.get("http://127.0.0.1:9999", timeout=2)
        print(f"SUCCESS: Reached allowlisted IP successfully! Status: {resp.status_code}")
    except Exception as e:
        print(f"FAIL: Expected to reach the server but got: {type(e).__name__} - {e}")

if __name__ == '__main__':
    test_ssrf()
