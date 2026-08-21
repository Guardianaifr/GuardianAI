"""
/debug/info post-fix verification — confirms the auth gate is enforced.
"""
import sys, os, time, json, textwrap, subprocess

_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_GUARDIAN = os.path.join(_REPO, "guardian")
for p in [_REPO, _GUARDIAN]:
    if p not in sys.path:
        sys.path.insert(0, p)

import requests, yaml

PROXY_PORT = 8084
STUB_PORT  = 8085
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
        def do_GET(self):
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.end_headers(); self.wfile.write(b'{{"status":"ok"}}')
    HTTPServer(('127.0.0.1',{STUB_PORT}),_H).serve_forever()
""").strip()

stub_proc = subprocess.Popen([sys.executable, "-c", stub_code],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1)

_CONFIG_PATH = os.path.join(_GUARDIAN, "config", "config.yaml")
with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
    real_config = yaml.safe_load(fh)
admin_token = real_config["security_policies"]["admin_token"]

cfg = {
    "proxy": {"enabled": True, "listen_port": PROXY_PORT,
               "target_url": f"http://127.0.0.1:{STUB_PORT}",
               "enforce_auth": True, "proxy_token": admin_token},
    "security_policies": {"admin_token": admin_token,
                           "block_prompt_injection": True,
                           "leak_prevention_strategy": "redact",
                           "security_mode": "balanced",
                           "show_block_reason": True, "validate_output": True},
    "rate_limiting": {"enabled": True, "requests_per_minute": 600},
    "threat_feed": {"enabled": False}, "brain": {"enabled": False},
    "jailbreak_fuzzer": {"enabled": False}, "cost_abuse": {"enabled": False},
    "feedback_loop": {"enabled": False}, "memory_security": {"enabled": False},
    "output_assurance": {"enabled": False}, "output_watermark": {"enabled": False},
    "multimodal_security": {"enabled": False}, "rag_security": {"enabled": False},
    "trust_exploitation": {"enabled": False}, "agentic_security": {"enabled": False},
    "governance": {"enabled": False}, "siem": {"enabled": False},
    "tenant_isolation": {"enabled": False}, "tenant_sensitivity": {"enabled": False},
    "tool_policy": {"enabled": False}, "honeypot": {"enabled": False},
    "system_prompt_protection": {"enabled": False},
}

from runtime.interceptor import GuardianProxy
proxy = GuardianProxy(cfg)
proxy.start()

for _ in range(40):
    try:
        if requests.get(f"{PROXY_BASE}/health", timeout=2).status_code == 200:
            break
    except Exception:
        pass
    time.sleep(0.5)

print(f"Proxy ready at {PROXY_BASE}")

# Populate last_debug_info
requests.post(f"{PROXY_BASE}/v1/chat/completions",
              json={"messages":[{"role":"user","content":"hello"}],"model":"gpt-4","max_tokens":10},
              headers={"Content-Type":"application/json","X-Guardian-Token":admin_token,
                       "X-Custom-Secret":"MY_SECRET_VALUE"}, timeout=10)

print()
print("=" * 72)
print("CHECK 1: GET /debug/info — NO auth — must return 401")
print("=" * 72)
r1 = requests.get(f"{PROXY_BASE}/debug/info", timeout=5)
print(f"STATUS: {r1.status_code}")
print(f"BODY:   {r1.text}")
unauth_ok = r1.status_code == 401

print()
print("=" * 72)
print("CHECK 2: GET /debug/info — Authorization: Bearer <admin_token> — must return 200")
print("=" * 72)
r2 = requests.get(f"{PROXY_BASE}/debug/info",
                  headers={"Authorization": f"Bearer {admin_token}"}, timeout=5)
print(f"STATUS: {r2.status_code}")
print(f"BODY:   {r2.text[:400]}")
auth_ok = r2.status_code == 200

print()
print("=" * 72)
print("CHECK 3: GET /debug/info — wrong token — must return 401")
print("=" * 72)
r3 = requests.get(f"{PROXY_BASE}/debug/info",
                  headers={"Authorization": "Bearer wrongtoken"}, timeout=5)
print(f"STATUS: {r3.status_code}")
print(f"BODY:   {r3.text}")
wrong_ok = r3.status_code == 401

print()
print("=" * 72)
print("RESULT")
print("=" * 72)
print(f"  Unauthenticated blocked (401): {'PASS' if unauth_ok else 'FAIL'}")
print(f"  Authenticated allowed   (200): {'PASS' if auth_ok  else 'FAIL'}")
print(f"  Wrong token blocked     (401): {'PASS' if wrong_ok else 'FAIL'}")
all_pass = unauth_ok and auth_ok and wrong_ok
print(f"  Overall: {'ALL PASS — fix verified' if all_pass else 'FAILURES — fix incomplete'}")

stub_proc.terminate()
