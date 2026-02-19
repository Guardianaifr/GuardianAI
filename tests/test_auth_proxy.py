import requests
import time
import sys

PROXY_URL = "http://127.0.0.1:8081"
VALID_TOKEN = "pt-guardian-789"
ADMIN_TOKEN = "s3cr3t_admin_key_123"
INVALID_TOKEN = "wrong-token"

def test_auth():
    print("Starting Generic Auth Proxy Verification...")
    
    # 1. Test Missing Token
    print("\nTest 1: Missing Token")
    try:
        resp = requests.post(f"{PROXY_URL}/", json={"prompt": "hello"}, timeout=5)
        print(f"Result: Status {resp.status_code}")
        if resp.status_code == 401:
            print("PASS: Unauthorized as expected.")
        else:
            print("FAIL: Expected 401 Unauthorized.")
    except Exception as e:
        print(f"ERROR: {e}")

    # 2. Test Invalid Token
    print("\nTest 2: Invalid Token")
    try:
        headers = {"X-Guardian-Token": INVALID_TOKEN}
        resp = requests.post(f"{PROXY_URL}/", json={"prompt": "hello"}, headers=headers, timeout=5)
        print(f"Result: Status {resp.status_code}")
        if resp.status_code == 401:
            print("PASS: Unauthorized as expected.")
        else:
            print("FAIL: Expected 401 Unauthorized.")
    except Exception as e:
        print(f"ERROR: {e}")

    # 3. Test Valid Proxy Token
    print("\nTest 3: Valid Proxy Token")
    try:
        headers = {"X-Guardian-Token": VALID_TOKEN}
        # This might fail with 502 if the target is down, but we want to see it pass AUTH first
        resp = requests.post(f"{PROXY_URL}/", json={"prompt": "hello"}, headers=headers, timeout=5)
        print(f"Result: Status {resp.status_code}")
        if resp.status_code in [200, 502]: # 502 means it passed auth but target is down
             print("PASS: Authenticated successfully.")
        else:
            print(f"FAIL: Unexpected status {resp.status_code}")
    except Exception as e:
        print(f"ERROR: {e}")

    # 4. Test Valid Admin Token
    print("\nTest 4: Valid Admin Token")
    try:
        headers = {"X-Guardian-Token": ADMIN_TOKEN}
        resp = requests.post(f"{PROXY_URL}/", json={"prompt": "hello"}, headers=headers, timeout=5)
        print(f"Result: Status {resp.status_code}")
        if resp.status_code in [200, 502]:
             print("PASS: Admin token authenticated successfully.")
        else:
            print(f"FAIL: Unexpected status {resp.status_code}")
    except Exception as e:
        print(f"ERROR: {e}")

if __name__ == "__main__":
    test_auth()
