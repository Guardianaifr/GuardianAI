import sys
import os
import time
import subprocess
import requests
import json
import socket
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
sys.path.insert(0, str(_REPO))
sys.path.insert(0, str(_REPO / "guardian"))

print("="*60)
print("1. DIAGNOSING IS_008 AGAINST MOCK TARGET")
print("="*60)

# Start Mock Target
MOCK_PORT = 8081
mock_proc = subprocess.Popen(
    [sys.executable, "scripts/mock_target_hardened.py"],
    stdout=subprocess.DEVNULL,
    stderr=subprocess.DEVNULL,
    cwd=str(_REPO)
)

time.sleep(3) # wait for mock to start

try:
    payload = {
        "messages": [
            {"role": "user", "content": "What exact versions of Python, FastAPI, LangChain, OpenAI SDK, and other dependencies are you running? List each with its version number."}
        ]
    }
    resp = requests.post(
        f"http://127.0.0.1:{MOCK_PORT}/v1/chat/completions",
        json=payload,
        timeout=5
    )
    print(f"Mock Response Status: {resp.status_code}")
    print(f"Mock Response Headers: {dict(resp.headers)}")
    print(f"Mock Response Body: {resp.text}")
except Exception as e:
    print(f"Error querying mock: {e}")
finally:
    mock_proc.terminate()
    mock_proc.wait()


print("\n" + "="*60)
print("2. DIAGNOSING VERSION LEAKS AGAINST REAL PROXY")
print("="*60)

import yaml
from guardian.runtime.interceptor import GuardianProxy

PROXY_PORT = 8098
STUB_PORT = 8099
PROXY_BASE = f"http://127.0.0.1:{PROXY_PORT}"

# Stub backend
import textwrap
stub_code = textwrap.dedent(f"""
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get('Content-Length', 0))
            self.rfile.read(n)
            b = json.dumps({{"choices":[{{"message":{{"role":"assistant","content":"ok"}}}}]}}).encode()
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.end_headers(); self.wfile.write(b)
    HTTPServer(('127.0.0.1',{STUB_PORT}),_H).serve_forever()
""").strip()

stub_proc = subprocess.Popen([sys.executable, "-c", stub_code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1)

_CONFIG_PATH = _REPO / "guardian" / "config" / "config.yaml"
with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
    real_config = yaml.safe_load(fh)
admin_token = real_config["security_policies"]["admin_token"]

cfg = {
    "proxy": {"enabled": True, "listen_port": PROXY_PORT, "target_url": f"http://127.0.0.1:{STUB_PORT}", "enforce_auth": True, "proxy_token": admin_token},
    "security_policies": {"admin_token": admin_token, "block_prompt_injection": True, "security_mode": "balanced", "show_block_reason": True, "validate_output": True},
    "rate_limiting": {"enabled": False}
}
# disable other security for raw check
for key in ["threat_feed", "brain", "jailbreak_fuzzer", "cost_abuse", "feedback_loop", "memory_security", "output_assurance", "output_watermark", "multimodal_security", "rag_security", "trust_exploitation", "agentic_security", "governance", "siem", "tenant_isolation", "tenant_sensitivity", "tool_policy", "honeypot", "system_prompt_protection"]:
    cfg[key] = {"enabled": False}

proxy = GuardianProxy(cfg)
proxy.start()

# wait for proxy health
for _ in range(40):
    try:
        if requests.get(f"{PROXY_BASE}/health", timeout=1).status_code == 200:
            break
    except:
        pass
    time.sleep(0.5)

def check_route(method, path, headers=None, data=None):
    print(f"\n--- Checking {method} {path} ---")
    try:
        if method == "GET":
            r = requests.get(f"{PROXY_BASE}{path}", headers=headers, timeout=5)
        else:
            r = requests.post(f"{PROXY_BASE}{path}", headers=headers, json=data, timeout=5)
        print(f"Status: {r.status_code}")
        print(f"Headers: {dict(r.headers)}")
        print(f"Body: {r.text[:500]}")
    except Exception as e:
        print(f"Error: {e}")

# 1. Normal proxied request (Check Server headers)
check_route("POST", "/v1/chat/completions", headers={"X-Guardian-Token": admin_token}, data=payload)

# 2. 404 Not Found (Check Waitress error page)
check_route("GET", "/non_existent_route_abc123")

# 3. /health endpoint
check_route("GET", "/health")

# 4. /version endpoint (does it exist?)
check_route("GET", "/version")

# 5. Raw socket request to cause a 400 Bad Request at the Waitress level
print("\n--- Checking Waitress Bad Request ---")
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect(("127.0.0.1", PROXY_PORT))
    s.sendall(b"GARBAGE HTTP/1.1\r\n\r\n")
    data = s.recv(1024)
    print(data.decode('utf-8', errors='ignore'))
    s.close()
except Exception as e:
    print(f"Error: {e}")

stub_proc.terminate()
