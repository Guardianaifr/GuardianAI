#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IS_003 Real-Proxy Verification Script
======================================
PURPOSE
    Closes the verification gap left after mock-only IS_003 testing.
    The mock intentionally does NOT enforce auth on /v1/chat/completions
    (sub-check a), so the IS_003 probe was never validated against the
    real fail-closed enforce_auth gate in guardian/runtime/interceptor.py.
    This script runs the SAME three sub-checks (same HTTP verb, same headers,
    same classification logic) against a live local instance of the real proxy.

NOT FOR CI/CD
    This script is intentionally NOT wired into pytest or any CI pipeline.
    It targets a live proxy instance and sub-check (b) — /api/reload-model —
    performs a real hot-reload of the AI Firewall (re-encodes 521 jailbreak
    vectors in memory). See SIDE EFFECT NOTICE below.

SIDE EFFECT NOTICE — /api/reload-model
    The authenticated success call for /api/reload-model invokes
    InterceptorProxy.reload_model() → self.ai_firewall.reload().
    Real effect: re-encodes all jailbreak vectors from
    guardian/config/jailbreak_vectors.yaml into the in-memory
    SentenceTransformer model. This is CPU-intensive (~5–15s) but
    NON-DESTRUCTIVE:
      - No disk state is mutated
      - No config files are changed
      - The model returns to an identical functional state after reload
      - Safe to invoke in a development/staging environment
    By default this script SKIPS the authenticated success call for
    /api/reload-model and prints a clear notice. Pass --run-reload to opt in.

PROXY STARTUP
    This script starts GuardianProxy directly in-process (not as a subprocess
    of main.py) using a minimal config dict. This avoids main.py's
    subprocess/pipe/UTF-8 complications and matches how E2E tests start the
    proxy. A minimal stub backend is started on port 8080 to absorb upstream
    traffic — auth checks fire BEFORE any forwarding, so the stub only needs
    to be reachable, not functionally correct.

AUTHENTICATION HEADERS (real proxy — not the mock)
    Proxy gate  (_check_authentication):  X-Guardian-Token: <proxy_token>
    Admin routes (_check_admin_auth):      Authorization: Bearer <admin_token>
    These are DIFFERENT headers. The IS_003 probe sends each correctly.
    Note: when proxy_token is empty in config, _check_authentication also
    accepts the admin_token in X-Guardian-Token (see interceptor.py L552-555).

USAGE
    # Minimal (proxy started in-process, reload-model auth call skipped):
    python scripts/manual_verification/verify_is003_real_proxy.py

    # With reload-model authenticated call enabled (non-destructive but slow):
    python scripts/manual_verification/verify_is003_real_proxy.py --run-reload

    # Target an already-running proxy instead of starting one:
    python scripts/manual_verification/verify_is003_real_proxy.py --no-start-proxy

    # Override proxy port (default 8081):
    python scripts/manual_verification/verify_is003_real_proxy.py --port 9000
"""

import argparse
import json
import os
import subprocess
import sys
import textwrap
import threading
import time
from pathlib import Path
from typing import Optional

import requests
import yaml

# ── Windows console UTF-8 fix ────────────────────────────────────────────────
# Prevent UnicodeEncodeError when printing non-ASCII characters on Windows
# consoles that default to cp1252.  Reconfigure stdout/stderr to UTF-8 if
# they are text-mode streams (they may already be UTF-8 in some terminals).
if sys.platform.startswith("win"):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except AttributeError:
        pass  # Python < 3.7 or already a non-reconfigurable stream

# ── Project path setup ────────────────────────────────────────────────────────
_REPO_ROOT = Path(__file__).resolve().parent.parent.parent
_GUARDIAN_DIR = _REPO_ROOT / "guardian"
_CONFIG_PATH = _GUARDIAN_DIR / "config" / "config.yaml"

# Add paths so GuardianProxy and its deps can be imported
for _p in [str(_REPO_ROOT), str(_GUARDIAN_DIR)]:
    if _p not in sys.path:
        sys.path.insert(0, _p)


# ── Classification logic (mirrors crypto_scanner._run_auth_bypass_probe) ─────
def _classify(status_code: int) -> str:
    """Exact same 3-way classification used by the IS_003 dedicated probe."""
    if status_code in (401, 403):
        return "PROTECTED"
    if status_code == 200:
        return "VULNERABLE"
    return f"INCONCLUSIVE:HTTP_{status_code}"


# ── Stub backend ──────────────────────────────────────────────────────────────
def _start_stub_backend(port: int = 8080) -> Optional[subprocess.Popen]:
    """Start a minimal HTTP stub on 127.0.0.1:<port> as a subprocess.

    The real proxy forwards requests to target_url after passing the auth gate.
    Sub-check (a) fires _check_authentication BEFORE forwarding, so the stub
    only needs to exist — it doesn't need to return a valid LLM response.
    """
    stub_code = textwrap.dedent(f"""
        import json
        from http.server import BaseHTTPRequestHandler, HTTPServer

        class _H(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _ok(self, body):
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.end_headers()
                self.wfile.write(json.dumps(body).encode())
            def do_GET(self):
                self._ok({{"status": "stub_ok"}})
            def do_POST(self):
                n = int(self.headers.get('Content-Length', 0))
                self.rfile.read(n)
                self._ok({{"id":"chatcmpl-stub","object":"chat.completion","choices":[
                    {{"index":0,"message":{{"role":"assistant","content":"stub"}},"finish_reason":"stop"}}
                ]}})

        HTTPServer(('127.0.0.1', {port}), _H).serve_forever()
    """).strip()

    try:
        proc = subprocess.Popen(
            [sys.executable, "-c", stub_code],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        # Poll until it binds
        for _ in range(20):
            time.sleep(0.3)
            try:
                requests.get(f"http://127.0.0.1:{port}/", timeout=1)
                return proc
            except requests.RequestException:
                pass
        return proc  # return anyway; auth gate doesn't need it
    except Exception as exc:
        print(f"  [stub] Warning: could not start stub backend: {exc}")
        return None


# ── In-process proxy startup ──────────────────────────────────────────────────
def _build_minimal_config(
    proxy_port: int,
    proxy_token: str,
    admin_token: str,
    stub_port: int = 8080,
) -> dict:
    """Build a minimal GuardianProxy config that:
      - binds on proxy_port
      - has enforce_auth: true (the hardened fail-closed default)
      - sets proxy_token and admin_token from our verification values
      - disables all slow/network-dependent subsystems (brain, threat_feed, etc.)
    """
    return {
        "proxy": {
            "enabled": True,
            "listen_port": proxy_port,
            "target_url": f"http://127.0.0.1:{stub_port}",
            "enforce_auth": True,
            "proxy_token": proxy_token,
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
        "output_watermark": {"enabled": False},
    }


def _start_proxy_inprocess(config: dict) -> object:
    """Instantiate GuardianProxy and start it in a background daemon thread.
    Returns the proxy instance (for cleanup).
    """
    from runtime.interceptor import GuardianProxy  # noqa: PLC0415
    proxy = GuardianProxy(config)
    proxy.start()
    return proxy


def _wait_for_proxy(base_url: str, timeout: int = 30) -> bool:
    """Poll /health until proxy responds or timeout."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            r = requests.get(f"{base_url}/health", timeout=2)
            if r.status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.4)
    return False


# ── Request sender ─────────────────────────────────────────────────────────────
def _send(method: str, url: str, headers: dict,
          json_body=None, timeout: int = 12) -> dict:
    """Send a request and return a structured result dict with full raw evidence."""
    try:
        kwargs: dict = {"headers": headers, "timeout": timeout}
        if json_body is not None:
            kwargs["json"] = json_body
        resp = getattr(requests, method.lower())(url, **kwargs)
        return {
            "url": url,
            "method": method.upper(),
            "request_headers": dict(headers),
            "request_body": json_body,
            "status_code": resp.status_code,
            "response_body": resp.text[:600],
            "verdict": _classify(resp.status_code),
            "error": None,
        }
    except requests.RequestException as exc:
        return {
            "url": url,
            "method": method.upper(),
            "request_headers": dict(headers),
            "request_body": json_body,
            "status_code": -1,
            "response_body": "",
            "verdict": f"INCONCLUSIVE:REQUEST_ERROR",
            "error": str(exc),
        }


# ── Pretty printer ─────────────────────────────────────────────────────────────
def _print_req(label: str, r: dict, note: str = "", is_auth_check: bool = False) -> None:
    """Print a raw request/response pair.

    is_auth_check=True suppresses the VERDICT line for authenticated calls
    (HTTP 200 is the *correct* outcome there, not VULNERABLE).
    """
    sep = "-" * 72
    print(f"\n{sep}")
    print(f"  {label}")
    if note:
        print(f"  NOTE: {note}")
    print(sep)
    print(f"  REQUEST:  {r['method']} {r['url']}")
    for k, v in r["request_headers"].items():
        if k.lower() in ("x-guardian-token", "authorization"):
            display = str(v)[:10] + "..." if len(str(v)) > 10 else str(v)
        else:
            display = v
        print(f"            {k}: {display}")
    if r["request_body"]:
        print(f"            body: {json.dumps(r['request_body'])[:120]}")
    print(f"  RESPONSE: HTTP {r['status_code']}")
    body = r["response_body"].replace("\n", " ")[:250]
    print(f"            body: {body!r}")
    if r.get("error"):
        print(f"            error: {r['error']}")
    if is_auth_check:
        sc = r["status_code"]
        ok = isinstance(sc, int) and sc not in (401, 403)
        print(f"  AUTH CHECK: {'OK - legitimate access confirmed' if ok else 'BLOCKED - functional regression'}")
    else:
        print(f"  VERDICT:  {r['verdict']}")


# ── Main verification logic ────────────────────────────────────────────────────
def run_verification(
    proxy_base: str,
    proxy_token: str,
    admin_token: str,
    run_reload: bool,
) -> int:
    chat_url    = f"{proxy_base}/v1/chat/completions"
    reload_url  = f"{proxy_base}/api/reload-model"
    metrics_url = f"{proxy_base}/api/threat-feed/metrics"

    chat_payload = {
        "messages": [{"role": "user", "content": "ping"}],
        "model": "gpt-4",
        "max_tokens": 10,
    }

    # ── Header sets ───────────────────────────────────────────────────────────
    # Sub-check (a): proxy gate uses X-Guardian-Token
    no_proxy_token  = {"Content-Type": "application/json"}
    yes_proxy_token = {"Content-Type": "application/json",
                       "X-Guardian-Token": proxy_token}

    # Sub-checks (b), (c): admin routes use Authorization: Bearer
    no_bearer  = {"Content-Type": "application/json"}
    yes_bearer = {"Content-Type": "application/json",
                  "Authorization": f"Bearer {admin_token}"}

    print("\n" + "=" * 72)
    print("  IS_003 REAL-PROXY VERIFICATION")
    print(f"  Target: {proxy_base}")
    print(f"  enforce_auth: true  (fail-closed, hardened default)")
    print(f"  proxy_token present: {'yes' if proxy_token else 'no (will use admin_token)'}")
    print(f"  admin_token present: {'yes' if admin_token else 'NO — admin routes cannot be tested'}")
    print("=" * 72)

    results: dict = {}

    # ────────────────────────────────────────────────────────────────────────
    print("\n\n[SUB-CHECK (a)]  POST /v1/chat/completions  — global enforce_auth gate")
    print("  Unauthenticated: header X-Guardian-Token is absent.")
    print("  _check_authentication fires BEFORE the request reaches the upstream.")
    print("  Expected on real proxy: HTTP 401 (PROTECTED).")
    print("  Mock returned HTTP 200 here — THIS IS THE GAP BEING CLOSED.")

    r = _send("POST", chat_url, no_proxy_token, chat_payload)
    _print_req("(a.1) UNAUTHENTICATED — no X-Guardian-Token", r)
    results["a_unauth"] = r

    r = _send("POST", chat_url, yes_proxy_token, chat_payload)
    _print_req("(a.2) AUTHENTICATED   -- X-Guardian-Token present", r,
               note="200 expected (proxied to stub backend, which returns stub response)",
               is_auth_check=True)
    results["a_auth"] = r

    # ────────────────────────────────────────────────────────────────────────
    print("\n\n[SUB-CHECK (b)]  POST /api/reload-model  — _check_admin_auth")
    print("  Auth header: Authorization: Bearer (NOT X-Guardian-Token).")
    print("  _check_admin_auth is independent of the global enforce_auth gate.")
    print("  Expected unauthenticated: HTTP 401 (PROTECTED).")

    r = _send("POST", reload_url, no_bearer, {})
    _print_req("(b.1) UNAUTHENTICATED — no Authorization header", r)
    results["b_unauth"] = r

    if run_reload:
        print()
        print("  *** --run-reload FLAG SET ***")
        print("  Sending authenticated POST /api/reload-model.")
        print("  SIDE EFFECT: calls ai_firewall.reload() — re-encodes 521 jailbreak")
        print("  vectors via SentenceTransformer. CPU-intensive (~5-15s).")
        print("  Non-destructive: no disk writes, model returns to identical state.")
        r = _send("POST", reload_url, yes_bearer, {}, timeout=60)
        _print_req("(b.2) AUTHENTICATED   -- Authorization: Bearer", r,
                   note="200 expected; ai_firewall.reload() fires as side effect",
                   is_auth_check=True)
        results["b_auth"] = r
    else:
        print()
        print("  SKIPPING authenticated /api/reload-model (default safe mode).")
        print("  Pass --run-reload to opt in. Side effect: ai_firewall.reload()")
        results["b_auth"] = {
            "verdict": "SKIPPED",
            "status_code": "N/A",
            "response_body": "Skipped by default — pass --run-reload to enable",
            "url": reload_url, "method": "POST",
            "request_headers": {}, "request_body": None, "error": None,
        }
        print(f"  (b.2) AUTHENTICATED   — SKIPPED")

    # ────────────────────────────────────────────────────────────────────────
    print("\n\n[SUB-CHECK (c)]  GET /api/threat-feed/metrics  — _check_admin_auth (read-only)")
    print("  Auth header: Authorization: Bearer.")
    print("  No side effects — Prometheus-style metrics exposition.")
    print("  Expected unauthenticated: HTTP 401 (PROTECTED).")

    r = _send("GET", metrics_url, no_bearer)
    _print_req("(c.1) UNAUTHENTICATED — no Authorization header", r)
    results["c_unauth"] = r

    r = _send("GET", metrics_url, yes_bearer)
    _print_req("(c.2) AUTHENTICATED   -- Authorization: Bearer", r,
               note="200 expected (read-only metrics)",
               is_auth_check=True)
    results["c_auth"] = r

    # ── Overall verdict ───────────────────────────────────────────────────────
    unauthenticated = {
        "a (POST /v1/chat/completions)":   results["a_unauth"],
        "b (POST /api/reload-model)":      results["b_unauth"],
        "c (GET  /api/threat-feed/metrics)": results["c_unauth"],
    }

    all_protected  = all(r["verdict"] == "PROTECTED" for r in unauthenticated.values())
    any_vulnerable = any(r["verdict"] == "VULNERABLE" for r in unauthenticated.values())

    print("\n\n" + "=" * 72)
    print("  IS_003 REAL-PROXY OVERALL VERDICT")
    print("=" * 72)
    print()
    print("  Unauthenticated sub-check results:")
    for label, r in unauthenticated.items():
        icon = "PASS" if r["verdict"] == "PROTECTED" else \
               "FAIL" if r["verdict"] == "VULNERABLE" else "UNKN"
        print(f"    [{icon}]  {label}")
        print(f"            HTTP {r['status_code']}  ->  {r['verdict']}")

    print()
    print("  Authenticated success checks:")
    auth_checks = [
        ("a (POST /v1/chat/completions)",    results["a_auth"]),
        ("b (POST /api/reload-model)",       results["b_auth"]),
        ("c (GET  /api/threat-feed/metrics)", results["c_auth"]),
    ]
    for label, r in auth_checks:
        if r["verdict"] == "SKIPPED":
            print(f"    [SKIP]  {label}  (--run-reload not set)")
        else:
            sc = r["status_code"]
            ok = isinstance(sc, int) and sc not in (401, 403)
            icon = "PASS" if ok else "FAIL"
            note = "functional access confirmed" if ok else "BLOCKED -- functional bug"
            print(f"    [{icon}]  {label}")
            print(f"            HTTP {sc}  ->  {note}")

    print()
    if all_protected:
        verdict_str = "PROTECTED"
        print("  RESULT: ALL THREE UNAUTHENTICATED SUB-CHECKS RETURNED 401/403")
        print("  The real proxy's enforce_auth fail-closed gate is confirmed working.")
        print()
        print("  ✓  Sub-check (a) POST /v1/chat/completions:")
        print(f"     Real proxy returned HTTP {results['a_unauth']['status_code']} — PROTECTED")
        print("     Mock returned HTTP 200 — this was the documented scope gap.")
        print("     GAP STATUS: CLOSED — real-proxy evidence confirms PROTECTED.")
    elif any_vulnerable:
        verdict_str = "VULNERABLE"
        print("  RESULT: VULNERABLE — at least one unauthenticated request returned HTTP 200")
        print("  The real proxy is NOT enforcing authentication on at least one route.")
        print("  This is a real finding that must be fixed before deployment.")
    else:
        verdict_str = "INCONCLUSIVE"
        print("  RESULT: INCONCLUSIVE — no VULNERABLE, but not all PROTECTED")
        print("  Check individual HTTP status codes above for unexpected responses.")

    print()
    print("  ─── Closing note for AI_SECURITY_BACKLOG_2026Q1.md ───────────────")
    print(f"  IS_003 verified against real GuardianAI proxy -- verdict: {verdict_str}")
    print(f"  Sub-check (a) /v1/chat/completions enforce_auth gate on real proxy:")
    print(f"    HTTP {results['a_unauth']['status_code']} (unauthenticated) -> {results['a_unauth']['verdict']}")
    print(f"  Sub-check (b) /api/reload-model _check_admin_auth on real proxy:")
    print(f"    HTTP {results['b_unauth']['status_code']} (unauthenticated) -> {results['b_unauth']['verdict']}")
    print(f"  Sub-check (c) /api/threat-feed/metrics _check_admin_auth on real proxy:")
    print(f"    HTTP {results['c_unauth']['status_code']} (unauthenticated) -> {results['c_unauth']['verdict']}")
    print(f"  /api/reload-model authenticated call: {'run (ai_firewall.reload() fired)' if run_reload else 'SKIPPED (use --run-reload to confirm)'}")
    print(f"  Mock-limitation gap status: {'CLOSED with real-proxy evidence' if all_protected else 'OPEN -- see VULNERABLE results above'}")
    print("=" * 72 + "\n")

    return 0 if all_protected else 1


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> int:
    parser = argparse.ArgumentParser(
        description="IS_003 real-proxy verification — manual use only, not for CI.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--port", type=int, default=8081,
                        help="Proxy port to bind/target (default: 8081)")
    parser.add_argument("--stub-port", type=int, default=8080,
                        help="Stub backend port (default: 8080)")
    parser.add_argument("--proxy-token", default=None,
                        help="X-Guardian-Token. Defaults to admin_token from config.yaml.")
    parser.add_argument("--admin-token", default=None,
                        help="Bearer token for admin routes. Defaults to config.yaml admin_token.")
    parser.add_argument("--run-reload", action="store_true", default=False,
                        help="Enable authenticated /api/reload-model call (ai_firewall.reload() fires).")
    parser.add_argument("--no-start-proxy", action="store_true", default=False,
                        help="Skip in-process proxy startup; target an already-running proxy.")
    args = parser.parse_args()

    # ── Load tokens from config.yaml ──────────────────────────────────────────
    config_yaml: dict = {}
    if _CONFIG_PATH.exists():
        with open(_CONFIG_PATH, "r", encoding="utf-8") as fh:
            config_yaml = yaml.safe_load(fh) or {}
    else:
        print(f"WARNING: config.yaml not found at {_CONFIG_PATH}")

    admin_token_cfg   = config_yaml.get("security_policies", {}).get("admin_token", "") or ""
    proxy_token_cfg   = config_yaml.get("proxy", {}).get("proxy_token", "") or ""

    resolved_admin  = args.admin_token  or admin_token_cfg
    # When proxy_token is empty the real proxy also accepts admin_token in X-Guardian-Token
    resolved_proxy  = args.proxy_token  or proxy_token_cfg or resolved_admin

    if not resolved_admin:
        print("ERROR: No admin_token available. Set security_policies.admin_token in config.yaml")
        print("       or pass --admin-token.")
        return 2

    proxy_base = f"http://127.0.0.1:{args.port}"
    stub_proc  = None
    proxy_obj  = None

    if not args.no_start_proxy:
        # ── Start stub backend ────────────────────────────────────────────────
        try:
            requests.get(f"http://127.0.0.1:{args.stub_port}/", timeout=1)
            print(f"  [stub] Port {args.stub_port} already in use — skipping stub start.")
        except requests.RequestException:
            print(f"\n  [stub] Starting minimal stub backend on port {args.stub_port}...")
            stub_proc = _start_stub_backend(args.stub_port)
            print(f"  [stub] Stub backend started{f' (PID {stub_proc.pid})' if stub_proc else ' (may have failed)'}.")

        # ── Start GuardianProxy in-process ────────────────────────────────────
        print(f"\n  [proxy] Starting GuardianProxy in-process on port {args.port}...")
        print(f"  [proxy] enforce_auth: true | proxy_token: {'(set)' if resolved_proxy else '(empty)'}")
        print(f"  [proxy] admin_token:  {'(set, ' + str(len(resolved_admin)) + ' chars)' if resolved_admin else '(missing)'}")

        minimal_cfg = _build_minimal_config(
            proxy_port=args.port,
            proxy_token=resolved_proxy,
            admin_token=resolved_admin,
            stub_port=args.stub_port,
        )
        try:
            proxy_obj = _start_proxy_inprocess(minimal_cfg)
        except Exception as exc:
            print(f"  [proxy] ERROR starting proxy: {exc}")
            import traceback
            traceback.print_exc()
            if stub_proc:
                stub_proc.terminate()
            return 2

        print(f"  [proxy] Proxy thread started, polling /health...")
        if not _wait_for_proxy(proxy_base, timeout=30):
            print(f"ERROR: GuardianProxy did not become ready at {proxy_base}/health within 30s.")
            if stub_proc:
                stub_proc.terminate()
            return 2
        print(f"  [proxy] GuardianProxy ready at {proxy_base}.")
    else:
        print(f"\n  --no-start-proxy set. Targeting existing proxy at {proxy_base}...")
        if not _wait_for_proxy(proxy_base, timeout=8):
            print(f"ERROR: No proxy detected at {proxy_base}/health")
            return 2

    # ── Run the IS_003 sub-checks ─────────────────────────────────────────────
    try:
        exit_code = run_verification(
            proxy_base=proxy_base,
            proxy_token=resolved_proxy,
            admin_token=resolved_admin,
            run_reload=args.run_reload,
        )
    finally:
        if stub_proc:
            print("  [stub] Terminating stub backend...")
            stub_proc.terminate()
            try:
                stub_proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                stub_proc.kill()
        # proxy_obj is a daemon thread — it dies with the process; no explicit stop needed.

    return exit_code


if __name__ == "__main__":
    sys.exit(main())
