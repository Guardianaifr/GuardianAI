import os
os.environ.pop("GUARDIAN_ENV", None)

import requests
from backend.main import _safe_create_connection

try:
    resp = requests.get("http://127.0.0.1:8000")
    print("WARNING: Reached 127.0.0.1 without error!")
except Exception as e:
    print("BLOCKED:", str(e))

os.environ["GUARDIAN_SSRF_ALLOWLIST"] = "127.0.0.1"

try:
    resp = requests.get("http://127.0.0.1:8000")
    print("WARNING: Reached 127.0.0.1 (Expected because it's allowlisted, even if connection refused it shouldn't be SSRF error).")
except Exception as e:
    if "SSRF Protection" in str(e):
        print("STILL BLOCKED BY SSRF:", str(e))
    else:
        print("ALLOWED BY SSRF (failed elsewhere):", type(e).__name__)
