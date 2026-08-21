"""
IS_002 Real Proxy Verification — Manual Test Script
Sends malformed JSON payloads to the live GuardianProxy to verify that it
gracefully handles bad input (e.g. 400 Bad Request, 422, or 500) without
leaking Python stack traces or internal environment variables.
"""
import sys, os, time, subprocess, requests, yaml, textwrap
from pathlib import Path

_REPO = Path(__file__).resolve().parent.parent.parent
_GUARDIAN = _REPO / "guardian"
for p in [str(_REPO), str(_GUARDIAN)]:
    if p not in sys.path:
        sys.path.insert(0, p)

from runtime.interceptor import GuardianProxy

PROXY_PORT = 8094
STUB_PORT  = 8095
PROXY_BASE = f"http://127.0.0.1:{PROXY_PORT}"

stub_code = textwrap.dedent(f"""
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get('Content-Length', 0)); self.rfile.read(n)
            b = json.dumps({{"choices":[{{"message":{{"role":"assistant","content":"ok"}}}}]}}).encode()
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.end_headers(); self.wfile.write(b)
    HTTPServer(('127.0.0.1',{STUB_PORT}),_H).serve_forever()
""").strip()

stub_proc = subprocess.Popen([sys.executable, "-c", stub_code], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1)

_CONFIG_PATH = _GUARDIAN / "config" / "config.yaml"
with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
    real_config = yaml.safe_load(fh)
admin_token = real_config["security_policies"]["admin_token"]

cfg = {
    "proxy": {"enabled": True, "listen_port": PROXY_PORT, "target_url": f"http://127.0.0.1:{STUB_PORT}", "enforce_auth": True, "proxy_token": admin_token},
    "security_policies": {"admin_token": admin_token, "block_prompt_injection": True, "security_mode": "balanced", "show_block_reason": True, "validate_output": True},
    "rate_limiting": {"enabled": True, "requests_per_minute": 600}
}
for key in ["threat_feed", "brain", "jailbreak_fuzzer", "cost_abuse", "feedback_loop", "memory_security", "output_assurance", "output_watermark", "multimodal_security", "rag_security", "trust_exploitation", "agentic_security", "governance", "siem", "tenant_isolation", "tenant_sensitivity", "tool_policy", "honeypot", "system_prompt_protection"]:
    cfg[key] = {"enabled": False}

proxy = GuardianProxy(cfg)
proxy.start()

for _ in range(40):
    try:
        if requests.get(f"{PROXY_BASE}/health", timeout=2).status_code == 200:
            break
    except Exception:
        pass
    time.sleep(0.5)

print(f"GuardianProxy ready at {PROXY_BASE}")

# The three malformed payloads that IS_002 will use:
payloads = [
    {
        "name": "Missing Required Schema Fields",
        "body": '{"malformed": true, "role": "system", "injection": "test", "__proto__": {"admin": true}}'
    },
    {
        "name": "Syntactically Broken JSON",
        "body": 'not json at all {{{'
    },
    {
        "name": "Empty Body",
        "body": ''
    }
]

print("\n" + "=" * 70)
print("IS_002 REAL PROXY RAW RESPONSE DUMP")
print("=" * 70)

for p in payloads:
    print(f"\n--- Sub-check: {p['name']} ---")
    print(f"Payload Bytes: {repr(p['body'])}")
    
    # We send an authenticated request because we are testing error leakage, not auth bypass.
    # We want to see how the proxy handles the bad body.
    headers = {
        "Content-Type": "application/json",
        "X-Guardian-Token": admin_token
    }
    
    r = requests.post(f"{PROXY_BASE}/v1/chat/completions", data=p["body"], headers=headers, timeout=10)
    
    print(f"HTTP STATUS: {r.status_code}")
    print(f"RAW BODY:\n{r.text}")

print("\n" + "=" * 70)
stub_proc.terminate()
