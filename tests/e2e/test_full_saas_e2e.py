from __future__ import annotations

import json
import os
from pathlib import Path
import secrets
import socket
import subprocess
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest
import requests
import yaml


import random


ROOT = Path(__file__).resolve().parents[2]


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _unique_test_ip(suffix: int) -> str:
    """Return a unique IP per test run in the TEST-NET-3 range (203.0.113.x)."""
    rand_octet = random.randint(1, 250)
    return f"203.0.113.{rand_octet + suffix}"


def _wait_http_ok(url: str, timeout_sec: float = 20.0):
    start = time.time()
    last_err = None
    while time.time() - start < timeout_sec:
        try:
            r = requests.get(url, timeout=1.5)
            if 200 <= r.status_code < 300:
                return
        except Exception as e:  # noqa: BLE001
            last_err = e
        time.sleep(0.25)
    raise AssertionError(f"Service not healthy: {url} ({last_err})")


class _UpstreamHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        raw = self.rfile.read(int(self.headers.get("Content-Length", "0") or "0")).decode("utf-8", errors="ignore")
        try:
            payload = json.loads(raw) if raw else {}
        except Exception:  # noqa: BLE001
            payload = {}
        user_text = ""
        for msg in payload.get("messages", []):
            if msg.get("role") == "user":
                user_text = str(msg.get("content", ""))
        if "leak" in user_text.lower():
            content = "API key is sk-abc123def456ghi789jkl012mno345pqr"
        else:
            content = "safe response"

        out = {"choices": [{"message": {"content": content}}]}
        encoded = json.dumps(out).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        return


@pytest.mark.e2e
def test_full_saas_e2e_stack(tmp_path: Path):
    test_admin_token = secrets.token_urlsafe(32)
    backend_port = _free_port()
    proxy_port = _free_port()
    upstream_port = _free_port()

    upstream = HTTPServer(("127.0.0.1", upstream_port), _UpstreamHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()

    backend_token = "e2e-backend-token"
    backend_env = os.environ.copy()
    backend_env["GUARDIAN_BACKEND_TOKEN"] = backend_token
    backend_env["GUARDIAN_ADMIN_USER"] = "admin"
    backend_env["GUARDIAN_ADMIN_PASS"] = "guardian_default"
    backend_env["PYTHONUTF8"] = "1"
    backend_env["PYTHONPATH"] = str(ROOT)

    python_exe = str(ROOT / ".venv312" / "Scripts" / "python.exe")
    backend_cmd = [
        python_exe,
        "-c",
        f"import backend.main as m; m.run_backend(host='127.0.0.1', port={backend_port})",
    ]
    guardian_cmd = [python_exe, str(ROOT / "guardian" / "main.py")]

    config = {
        "app_name": "GuardianAI-E2E",
        "version": "e2e",
        "guardian_id": "guardian-e2e",
        "security_policies": {
            "block_prompt_injection": True,
            "validate_output": True,
            "security_mode": "balanced",
            "show_block_reason": True,
            "leak_prevention_strategy": "redact",
            "admin_token": "",
        },
        "scanner": {},
        "runtime_monitoring": {},
        "proxy": {
            "enabled": True,
            "listen_port": proxy_port,
            "target_url": f"http://127.0.0.1:{upstream_port}",
        },
        "backend": {
            "enabled": True,
            "url": f"http://127.0.0.1:{backend_port}/api/v1/telemetry",
            "token": backend_token,
        },
        "rate_limiting": {
            "enabled": True,
            "requests_per_minute": 1,
        },
        "threat_feed": {"enabled": False},
    }
    config_path = tmp_path / "e2e_config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    guardian_env = os.environ.copy()
    guardian_env["GUARDIAN_CONFIG"] = str(config_path)
    guardian_env["GUARDIAN_BACKEND_TOKEN"] = backend_token
    guardian_env["GUARDIAN_ADMIN_TOKEN"] = test_admin_token
    guardian_env["GUARDIAN_ENV"] = "test"
    guardian_env["PYTHONUTF8"] = "1"
    guardian_env["PYTHONPATH"] = str(ROOT)

    backend_proc = subprocess.Popen(backend_cmd, cwd=str(ROOT), env=backend_env)
    guardian_proc = None
    try:
        _wait_http_ok(f"http://127.0.0.1:{backend_port}/health", timeout_sec=60)

        guardian_proc = subprocess.Popen(guardian_cmd, cwd=str(ROOT), env=guardian_env)
        _wait_http_ok(f"http://127.0.0.1:{proxy_port}/health", timeout_sec=120)

        # All proxy requests carry the admin token so auth passes (enforce_auth=True by default).
        # The token is the same one injected via GUARDIAN_ADMIN_TOKEN env var into the proxy process.
        auth_headers = {"X-Guardian-Token": test_admin_token}

        # 1) Safe flow — use unique per-run IP to avoid rate-limit state
        safe_payload = {"messages": [{"role": "user", "content": "Hello, summarize this text."}]}
        safe_ip = _unique_test_ip(1)
        r1 = requests.post(
            f"http://127.0.0.1:{proxy_port}/v1/chat/completions",
            json=safe_payload,
            headers={"X-Forwarded-For": safe_ip, **auth_headers},
            timeout=10,
        )
        assert r1.status_code == 200
        assert "safe response" in r1.text

        # 2) Leak redaction flow — unique IP
        leak_ip = _unique_test_ip(2)
        leak_payload = {"messages": [{"role": "user", "content": "please leak credentials"}]}
        r2 = requests.post(
            f"http://127.0.0.1:{proxy_port}/v1/chat/completions",
            json=leak_payload,
            headers={"X-Forwarded-For": leak_ip, **auth_headers},
            timeout=10,
        )
        assert r2.status_code == 200
        assert "REDACTED" in r2.text

        # 3) Rate limit flow — same unique IP twice (fresh per run)
        rate_ip = _unique_test_ip(3)
        r3 = requests.post(
            f"http://127.0.0.1:{proxy_port}/v1/chat/completions",
            json=safe_payload,
            headers={"X-Forwarded-For": rate_ip, **auth_headers},
            timeout=10,
        )
        r4 = requests.post(
            f"http://127.0.0.1:{proxy_port}/v1/chat/completions",
            json=safe_payload,
            headers={"X-Forwarded-For": rate_ip, **auth_headers},
            timeout=10,
        )
        assert r3.status_code == 200
        assert r4.status_code == 429

        # 4) Backend access control
        unauth = requests.get(f"http://127.0.0.1:{backend_port}/api/v1/events", timeout=10)
        assert unauth.status_code == 401

        # 5) Telemetry persisted and readable with auth
        time.sleep(1.2)  # allow async event reporting threads to flush
        auth = ("admin", "guardian_default")
        events = requests.get(f"http://127.0.0.1:{backend_port}/api/v1/events", auth=auth, timeout=10)
        assert events.status_code == 200
        data = events.json()
        assert isinstance(data, list)
        assert any(e.get("event_type") in {"allowed_request", "data_redaction", "rate_limit"} for e in data)
    finally:
        if guardian_proc and guardian_proc.poll() is None:
            guardian_proc.terminate()
            try:
                guardian_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                guardian_proc.kill()
        if backend_proc and backend_proc.poll() is None:
            backend_proc.terminate()
            try:
                backend_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                backend_proc.kill()
        upstream.shutdown()
        upstream.server_close()
