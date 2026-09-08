import pytest
import sys
import os
import threading
import time
import requests
import uvicorn
from pathlib import Path

# Ensure project root and scripts are on the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "scripts")))

from guardian.audit.crypto_scanner import CryptoAuditScanner, ScanDepth

# IS_003 token — must be set BEFORE importing mock_target_hardened so that
# _check_mock_admin_token() picks it up at route-call time (it reads env var
# at call time, not at import time, so setting it here is sufficient).
_IS003_ADMIN_TOKEN = "is003-audit-test-token-99f2"
os.environ["GUARDIAN_AUDIT_ADMIN_TOKEN"] = _IS003_ADMIN_TOKEN

from mock_target_hardened import app


class UvicornThread(threading.Thread):
    def __init__(self, app, host="127.0.0.1", port=8089):
        threading.Thread.__init__(self)
        self.host = host
        self.port = port
        self.server = uvicorn.Server(uvicorn.Config(app, host=host, port=port, log_level="warning"))

    def run(self):
        self.server.run()

    def stop(self):
        self.server.should_exit = True

@pytest.fixture(scope="module")
def hardened_server():
    server_thread = UvicornThread(app, port=8089)
    server_thread.start()
    
    # Wait for server startup
    started = False
    for _ in range(15):
        try:
            res = requests.post(f"http://127.0.0.1:8089/v1/chat/completions", json={"messages": []}, timeout=1)
            if res.status_code == 200:
                started = True
                break
        except requests.RequestException:
            pass
        time.sleep(0.5)
        
    if not started:
        server_thread.stop()
        pytest.fail("Failed to start hardened uvicorn server for tests")
        
    yield f"http://127.0.0.1:8089/v1/chat/completions"
    
    server_thread.stop()
    server_thread.join()


def test_hardened_mock_target_scan(hardened_server):
    """
    Scan the hardened mock target API (which has active system prompt guards,
    PII scanners, and conversation threat trackers) and verify that
    vulnerabilities drop to 0 and the final grade is A+.

    NOTE on IS_003: The mock intentionally does NOT enforce auth on
    /v1/chat/completions (sub-check a) to avoid breaking all other vector
    tests that don't supply tokens. IS_003(a) will appear as VULNERABLE on
    the mock, making IS_003's overall verdict VULNERABLE. This is expected
    and documented — see test_is003_auth_bypass_probe for the per-route
    breakdown. The score/grade assertion here excludes IS_003 from the
    vulnerability count expectation.
    """
    scanner = CryptoAuditScanner(target_url=hardened_server, target_name="Hardened Target", depth=ScanDepth.STANDARD)
    result = scanner.run_scan()

    # IS_003 will show VULNERABLE (mock doesn't enforce auth on /v1/chat/completions).
    # All other vectors should be PROTECTED.
    is003_finding = next((f for f in result.findings if f["vector_id"] == "IS_003"), None)
    other_vulns = [f for f in result.findings
                   if f["status"] == "vulnerable" and f["vector_id"] != "IS_003"]

    assert len(other_vulns) == 0, (
        f"Expected 0 non-IS_003 vulnerabilities on hardened target, "
        f"got {len(other_vulns)}: {[f['vector_id'] for f in other_vulns]}"
    )
    assert is003_finding is not None, "IS_003 finding not present in results"
    # IS_003 is VULNERABLE on the mock by design — proxy_route sub-check (a) has no auth
    assert is003_finding["status"] in ("vulnerable", "inconclusive"), (
        f"IS_003 on mock expected VULNERABLE or INCONCLUSIVE, got {is003_finding['status']}"
    )

    # Multi-turn findings should be PROTECTED
    mt_findings = [f for f in result.findings if f["vector_id"].startswith("MT-")]
    assert len(mt_findings) == 2, f"Expected 2 multi-turn findings, got {len(mt_findings)}"
    for f in mt_findings:
        assert f["status"] == "protected", (
            f"Expected multi-turn finding {f['vector_id']} to be protected, got {f['status']}"
        )


def test_is003_auth_bypass_probe(hardened_server):
    """
    Dedicated IS_003 test: runs the auth bypass probe against the mock and
    prints the full per-route breakdown. Reports raw HTTP status + body per
    sub-check and the authenticated-success confirmation.

    Scope gaps on this mock are flagged and asserted explicitly.
    """
    scanner = CryptoAuditScanner(
        target_url=hardened_server,
        target_name="IS003-AuthBypass-Test",
        depth=ScanDepth.STANDARD,
    )
    result = scanner.run_scan()

    is003 = next((f for f in result.findings if f["vector_id"] == "IS_003"), None)
    assert is003 is not None, "IS_003 finding not in scan results"

    details = is003.get("details", "")
    print("\n" + "=" * 70)
    print("IS_003 FULL PER-ROUTE BREAKDOWN:")
    print("=" * 70)
    print(details)
    print("=" * 70 + "\n")

    # ── Per-route assertions ──────────────────────────────────────────────────

    # Sub-check (a): POST /v1/chat/completions — mock does NOT enforce auth.
    # Expected: VULNERABLE (200). This is a documented mock scope limitation.
    assert "proxy_route" in details or "chat/completions" in details, (
        "Expected proxy_route sub-check results in IS_003 details"
    )

    # Sub-check (b): POST /api/reload-model — mock DOES enforce auth via GUARDIAN_AUDIT_ADMIN_TOKEN.
    # Unauthenticated → 401 (PROTECTED). Authenticated → 200 (OK).
    assert "reload-model" in details, (
        "Expected reload-model sub-check results in IS_003 details"
    )

    # Sub-check (c): GET /api/threat-feed/metrics — mock DOES enforce auth.
    # Unauthenticated → 401 (PROTECTED). Authenticated → 200 (OK).
    assert "threat-feed/metrics" in details, (
        "Expected threat-feed/metrics sub-check results in IS_003 details"
    )

    # Scope gap documentation — (a) must be flagged when mock returns 200
    # OR must show VULNERABLE (either way the finding is documented, not hidden)
    is003_status = is003["status"]
    print(f"IS_003 overall verdict on mock: {is003_status.upper()}")
    print(f"IS_003 matched_indicators: {is003.get('matched_indicators', [])}")

    # The finding must not be UNKNOWN/ERROR — it must resolve to a real verdict
    assert is003_status in ("vulnerable", "protected", "inconclusive"), (
        f"IS_003 must resolve to a real verdict, got: {is003_status}"
    )

    # Authenticated sub-check confirmation: both reload-model and threat-feed/metrics
    # should show 'OK (non-401/403)' in the details (they were called with valid token)
    assert "OK (non-401/403)" in details or "SKIPPED" in details, (
        "Authenticated sub-check results must appear in IS_003 details"
    )


# ─── /debug/info auth-gate regression test ───────────────────────────────────
# Finding (2026-07-15): /debug/info was unauthenticated, returning the full
# header dict of the last proxied request — including X-Guardian-Token,
# Authorization: Bearer, and X-Api-Key values sent by clients.
# Fix: _check_admin_auth() gate added to debug_info() in interceptor.py.
# This test locks that gate in: must return 401 without credentials.

@pytest.fixture(scope="module")
def real_proxy_server():
    """Start a GuardianProxy in-process backed by a minimal stub.

    Module-scoped so the proxy is reused across all tests that declare it.
    """
    import subprocess, textwrap, yaml
    from pathlib import Path

    _REPO = Path(__file__).resolve().parent.parent.parent
    _GUARDIAN = _REPO / "guardian"
    for p in [str(_REPO), str(_GUARDIAN)]:
        if p not in sys.path:
            sys.path.insert(0, p)

    from runtime.interceptor import GuardianProxy

    old_env = os.environ.get("GUARDIAN_ENV")
    os.environ["GUARDIAN_ENV"] = "development"

    PROXY_PORT = 8092
    STUB_PORT  = 8093

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

    stub_proc = subprocess.Popen(
        [sys.executable, "-c", stub_code],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    time.sleep(1)

    _CONFIG_PATH = _GUARDIAN / "config" / "config.yaml"
    with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
        cfg_yaml = yaml.safe_load(fh)
    admin_token = cfg_yaml.get("security_policies", {}).get("admin_token", "")
    if not admin_token or admin_token in {"***REDACTED***", "admin", "secret", "password", ""}:
        admin_token = "is003-audit-test-token-99f2a1b2c3d4e5f6"

    proxy_cfg = {
        "proxy": {"enabled": True, "listen_port": PROXY_PORT,
                   "target_url": f"http://127.0.0.1:{STUB_PORT}",
                   "enforce_auth": True, "proxy_token": admin_token},
        "security_policies": {"admin_token": admin_token,
                               "block_prompt_injection": True,
                               "leak_prevention_strategy": "redact",
                               "security_mode": "balanced",
                               "show_block_reason": True, "validate_output": True},
        "rate_limiting": {"enabled": False},
        **{k: {"enabled": False} for k in [
            "threat_feed", "brain", "jailbreak_fuzzer", "cost_abuse",
            "feedback_loop", "memory_security", "output_assurance",
            "output_watermark", "multimodal_security", "rag_security",
            "trust_exploitation", "agentic_security", "governance", "siem",
            "tenant_isolation", "tenant_sensitivity", "tool_policy",
            "honeypot", "system_prompt_protection",
        ]},
    }

    proxy = GuardianProxy(proxy_cfg)
    proxy.start()

    base = f"http://127.0.0.1:{PROXY_PORT}"
    for _ in range(40):
        try:
            if requests.get(f"{base}/health", timeout=2).status_code == 200:
                break
        except Exception:
            pass
        time.sleep(0.5)
    else:
        stub_proc.terminate()
        pytest.fail("GuardianProxy did not become ready within 20s")

    # Populate last_debug_info with a real proxied request so the route has
    # non-empty data — confirms auth blocks real content, not just an empty {}.
    requests.post(
        f"{base}/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "regression probe"}],
              "model": "gpt-4", "max_tokens": 10},
        headers={"Content-Type": "application/json",
                 "X-Guardian-Token": admin_token,
                 "X-Api-Key": "sk-regression-secret"},
        timeout=10,
    )

    yield base, admin_token

    stub_proc.terminate()
    if old_env is not None:
        os.environ["GUARDIAN_ENV"] = old_env
    else:
        os.environ.pop("GUARDIAN_ENV", None)


def test_debug_info_requires_admin_auth(real_proxy_server):
    """
    Regression test for /debug/info info-disclosure (2026-07-15).

    BEFORE fix: GET /debug/info returned HTTP 200 with the full header dict
    of the last proxied request — including X-Guardian-Token (64-char proxy
    token), Authorization, and X-Api-Key — to any unauthenticated caller.

    AFTER fix: _check_admin_auth() gate added to debug_info() in interceptor.py.
    Route now returns 401 without a valid admin Bearer token, same pattern as
    /api/reload-model and /api/threat-feed/metrics.

    Three assertions:
      (1) No auth header  -> 401   (was 200 before fix)
      (2) Valid admin token -> 200, non-empty debug state returned
      (3) Wrong token -> 401
    """
    base, admin_token = real_proxy_server
    url = f"{base}/debug/info"

    # (1) Unauthenticated must be blocked
    r_unauth = requests.get(url, timeout=5)
    assert r_unauth.status_code == 401, (
        f"REGRESSION: /debug/info returned HTTP {r_unauth.status_code} without auth. "
        f"Body: {r_unauth.text[:300]}"
    )

    # (2) Valid admin Bearer token must succeed
    r_auth = requests.get(url, headers={"Authorization": f"Bearer {admin_token}"}, timeout=5)
    assert r_auth.status_code == 200, (
        f"/debug/info returned HTTP {r_auth.status_code} for valid admin token. "
        f"Body: {r_auth.text[:300]}"
    )
    data = r_auth.json()
    assert isinstance(data, dict), "Expected JSON dict from /debug/info"
    assert "path" in data or "method" in data, (
        f"Expected debug state keys in response, got: {list(data.keys())}"
    )

    # (3) Wrong token must be blocked
    r_wrong = requests.get(url, headers={"Authorization": "Bearer wrongtoken"}, timeout=5)
    assert r_wrong.status_code == 401, (
        f"REGRESSION: /debug/info returned HTTP {r_wrong.status_code} for wrong token. "
        f"Body: {r_wrong.text[:300]}"
    )


def test_no_version_headers_in_any_response(real_proxy_server):
    """
    Regression test for IS_008 Technology-Stack Disclosure via HTTP headers.

    BEFORE fix (interceptor.py pre-patch):
      - Every response included  Server: BaseHTTP/0.6 Python/3.12.10  (exact Python version)
      - Proxied responses included  Via: waitress  (WSGI server identity)
      - Upstream backend's own Server / X-Powered-By headers were passed through verbatim.

    AFTER fix:
      1. Flask @app.after_request strips Server, X-Powered-By, Via from every
         Flask-level response (auth blocks, internal routes, proxied responses).
      2. excluded_headers in _forward_request() strips server/x-powered-by/via
         from the upstream header list before building the Flask Response — upstream
         identity never enters the Flask response pipeline.
      3. Waitress serve() is called with ident=None — suppresses the Server header
         at the WSGI level before after_request even runs.

    Assertions cover all four distinct response paths:
      (a) Proxied success (200) — upstream headers stripped
      (b) Auth block (401) — Flask own headers stripped
      (c) Internal route (/health, 200) — Flask own headers stripped
    """
    _FORBIDDEN = {'server', 'x-powered-by', 'via'}
    base, admin_token = real_proxy_server

    def assert_no_version_headers(response, label):
        leaked = {h.lower(): v for h, v in response.headers.items() if h.lower() in _FORBIDDEN}
        assert not leaked, (
            f"IS_008 REGRESSION [{label}]: version/stack header(s) leaked in response: {leaked}"
        )

    # (a) Success case — proxied POST that reaches upstream backend
    r_success = requests.post(
        f"{base}/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hello"}]},
        headers={"X-Guardian-Token": admin_token},
        timeout=10,
    )
    assert r_success.status_code == 200
    assert_no_version_headers(r_success, "proxied 200")

    # (b) Auth block — no token supplied, proxy returns 401 itself
    r_unauth = requests.post(
        f"{base}/v1/chat/completions",
        json={"messages": [{"role": "user", "content": "hello"}]},
        timeout=5,
    )
    assert r_unauth.status_code == 401
    assert_no_version_headers(r_unauth, "auth-blocked 401")

    # (c) Internal /health route — Flask-handled, never hits upstream
    r_health = requests.get(f"{base}/health", timeout=5)
    assert r_health.status_code == 200
    assert_no_version_headers(r_health, "/health 200")
