"""
/debug/info route investigation — scratch script, not for CI.
Starts the real GuardianProxy in-process, sends a probe request through it
to populate last_debug_info, then reads /debug/info unauthenticated.
"""
import sys
import os
import time
import json

# Ensure guardian/ is importable
_REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
_GUARDIAN = os.path.join(_REPO, "guardian")
for p in [_REPO, _GUARDIAN]:
    if p not in sys.path:
        sys.path.insert(0, p)

import requests

PROXY_PORT = 8082
PROXY_BASE = f"http://127.0.0.1:{PROXY_PORT}"
STUB_PORT  = 8083

# ── Minimal stub backend ──────────────────────────────────────────────────────
import subprocess, textwrap

stub_code = textwrap.dedent(f"""
    import json
    from http.server import BaseHTTPRequestHandler, HTTPServer
    class _H(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_POST(self):
            n = int(self.headers.get('Content-Length', 0))
            self.rfile.read(n)
            body = json.dumps({{"id":"stub","object":"chat.completion",
                "choices":[{{"index":0,"message":{{"role":"assistant","content":"stub response"}},"finish_reason":"stop"}}]}})
            self.send_response(200)
            self.send_header('Content-Type','application/json')
            self.end_headers()
            self.wfile.write(body.encode())
        def do_GET(self):
            self.send_response(200); self.send_header('Content-Type','application/json')
            self.end_headers(); self.wfile.write(b'{{"status":"ok"}}')
    HTTPServer(('127.0.0.1',{STUB_PORT}),_H).serve_forever()
""").strip()

stub_proc = subprocess.Popen([sys.executable, "-c", stub_code],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
time.sleep(1)

# ── Start proxy in-process ────────────────────────────────────────────────────
import yaml
_CONFIG_PATH = os.path.join(_GUARDIAN, "config", "config.yaml")
with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
    real_config = yaml.safe_load(fh)

admin_token = real_config["security_policies"]["admin_token"]

cfg = {
    "proxy": {
        "enabled": True,
        "listen_port": PROXY_PORT,
        "target_url": f"http://127.0.0.1:{STUB_PORT}",
        "enforce_auth": True,
        "proxy_token": admin_token,
    },
    "security_policies": {
        "admin_token": admin_token,
        "block_prompt_injection": True,
        "leak_prevention_strategy": "redact",
        "security_mode": "balanced",
        "show_block_reason": True,
        "validate_output": True,
    },
    "rate_limiting": {"enabled": True, "requests_per_minute": 600},
    "threat_feed": {"enabled": False},
    "brain": {"enabled": False},
    "jailbreak_fuzzer": {"enabled": False},
    "cost_abuse": {"enabled": False},
    "feedback_loop": {"enabled": False},
    "memory_security": {"enabled": False},
    "output_assurance": {"enabled": False},
    "output_watermark": {"enabled": False},
    "multimodal_security": {"enabled": False},
    "rag_security": {"enabled": False},
    "trust_exploitation": {"enabled": False},
    "agentic_security": {"enabled": False},
    "governance": {"enabled": False},
    "siem": {"enabled": False},
    "tenant_isolation": {"enabled": False},
    "tenant_sensitivity": {"enabled": False},
    "tool_policy": {"enabled": False},
    "honeypot": {"enabled": False},
    "system_prompt_protection": {"enabled": False},
}

from runtime.interceptor import GuardianProxy
proxy = GuardianProxy(cfg)
proxy.start()

# Poll /health
for _ in range(40):
    try:
        r = requests.get(f"{PROXY_BASE}/health", timeout=2)
        if r.status_code == 200:
            break
    except Exception:
        pass
    time.sleep(0.5)
else:
    print("ERROR: proxy did not come up")
    stub_proc.terminate()
    sys.exit(1)

print(f"Proxy ready at {PROXY_BASE}")

# ─── Step 1: Read /debug/info BEFORE any request — what does it return cold? ──
print()
print("=" * 72)
print("STEP 1: GET /debug/info — NO auth header — BEFORE any proxied request")
print("=" * 72)
r_cold = requests.get(f"{PROXY_BASE}/debug/info", timeout=5)
print(f"STATUS: {r_cold.status_code}")
print(f"RESPONSE BODY (full):")
print(r_cold.text)

# ─── Step 2: Send an authenticated proxied request to populate last_debug_info ─
print()
print("=" * 72)
print("STEP 2: Send authenticated POST /v1/chat/completions to populate debug state")
print("  Headers sent include: X-Guardian-Token, X-Custom-Secret: MY_SECRET_VALUE")
print("=" * 72)
probe_headers = {
    "Content-Type": "application/json",
    "X-Guardian-Token": admin_token,
    "X-Custom-Secret": "MY_SECRET_VALUE",
    "Authorization": "Bearer FAKE_USER_JWT_TOKEN",
    "X-Api-Key": "sk-testkey-1234567890",
}
probe_payload = {
    "messages": [{"role": "user", "content": "hello world"}],
    "model": "gpt-4",
    "max_tokens": 10,
}
r_probe = requests.post(
    f"{PROXY_BASE}/v1/chat/completions",
    json=probe_payload,
    headers=probe_headers,
    timeout=15,
)
print(f"Probe response: HTTP {r_probe.status_code}")

# ─── Step 3: Read /debug/info unauthenticated AFTER the proxied request ────────
print()
print("=" * 72)
print("STEP 3: GET /debug/info — NO auth header — AFTER proxied request")
print("  Confirms whether client headers (tokens, secrets) appear in response")
print("=" * 72)
r_hot = requests.get(f"{PROXY_BASE}/debug/info", timeout=5)
print(f"STATUS: {r_hot.status_code}")
print(f"RESPONSE BODY (full, untruncated):")
print(r_hot.text)

# Pretty-print with label for each field
print()
print("─── Field-by-field breakdown ───────────────────────────────────────────")
try:
    data = r_hot.json()
    for k, v in data.items():
        print(f"  {k!r:30s}  =  {json.dumps(v, default=str)[:200]}")
except Exception as e:
    print(f"  (could not parse as JSON: {e})")

# ─── Step 4: Confirm there is NO auth check (try with admin token too) ─────────
print()
print("=" * 72)
print("STEP 4: GET /debug/info — WITH admin Bearer token (confirm open to everyone)")
print("=" * 72)
r_auth = requests.get(
    f"{PROXY_BASE}/debug/info",
    headers={"Authorization": f"Bearer {admin_token}"},
    timeout=5,
)
print(f"STATUS: {r_auth.status_code}")
print(f"Same content: {r_auth.text == r_hot.text}")

stub_proc.terminate()
print()
print("Done.")
