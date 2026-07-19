import requests
import time
import sys
import os
import secrets
import socket
import subprocess
import threading
import json
from pathlib import Path
from http.server import BaseHTTPRequestHandler, HTTPServer
import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def _wait_http_ok(url: str, timeout_sec: float = 120.0):
    start = time.time()
    last_err = None
    while time.time() - start < timeout_sec:
        try:
            r = requests.get(url, timeout=1.5)
            if 200 <= r.status_code < 300:
                return
        except Exception as e:
            last_err = e
        time.sleep(0.25)
    raise AssertionError(f"Service not healthy: {url} ({last_err})")

class _UpstreamHandler(BaseHTTPRequestHandler):
    valid_token = ""
    admin_token = ""

    def do_POST(self):
        token = self.headers.get("X-Guardian-Token")
        if not token or token not in [self.valid_token, self.admin_token]:
            self.send_response(401)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"error": "Unauthorized"}).encode("utf-8"))
            return

        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(json.dumps({"choices": [{"message": {"content": "hello response"}}]}).encode("utf-8"))

    def do_GET(self):
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, *args):
        return

def test_auth(tmp_path: Path):
    proxy_port = _free_port()
    upstream_port = _free_port()
    
    valid_token = secrets.token_urlsafe(32)
    admin_token = secrets.token_urlsafe(32)
    invalid_token = "wrong-token"
    
    _UpstreamHandler.valid_token = valid_token
    _UpstreamHandler.admin_token = admin_token

    upstream = HTTPServer(("127.0.0.1", upstream_port), _UpstreamHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()

    config = {
        "app_name": "GuardianAI-Auth-Test",
        "version": "test",
        "guardian_id": "guardian-auth-test",
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
            "enforce_auth": True,
            "proxy_token": valid_token,
        },
        "backend": {
            "enabled": False,
        },
        "rate_limiting": {
            "enabled": False,
        },
        "threat_feed": {"enabled": False},
    }
    
    config_path = tmp_path / "auth_test_config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    python_exe = str(ROOT / ".venv312" / "Scripts" / "python.exe")
    guardian_cmd = [python_exe, str(ROOT / "guardian" / "main.py")]
    
    guardian_env = os.environ.copy()
    guardian_env["GUARDIAN_CONFIG"] = str(config_path)
    guardian_env["GUARDIAN_ADMIN_TOKEN"] = admin_token
    guardian_env["GUARDIAN_ENV"] = "test"
    guardian_env["PYTHONUTF8"] = "1"
    guardian_env["PYTHONUNBUFFERED"] = "1"
    guardian_env["PYTHONPATH"] = str(ROOT)

    stdout_path = tmp_path / "guardian_stdout.log"
    stderr_path = tmp_path / "guardian_stderr.log"

    out_f = open(stdout_path, "w", encoding="utf-8")
    err_f = open(stderr_path, "w", encoding="utf-8")
    guardian_proc = subprocess.Popen(guardian_cmd, cwd=str(ROOT), env=guardian_env, stdout=out_f, stderr=err_f)
    
    try:
        _wait_http_ok(f"http://127.0.0.1:{proxy_port}/health", timeout_sec=120)

        PROXY_URL = f"http://127.0.0.1:{proxy_port}"

        print("Starting Generic Auth Proxy Verification...")
        
        # 1. Test Missing Token
        print("\nTest 1: Missing Token")
        resp = requests.post(f"{PROXY_URL}/", json={"prompt": "hello"}, timeout=10)
        print(f"Result: Status {resp.status_code}")
        assert resp.status_code == 401

        # 2. Test Invalid Token
        print("\nTest 2: Invalid Token")
        headers = {"X-Guardian-Token": invalid_token}
        resp = requests.post(f"{PROXY_URL}/", json={"prompt": "hello"}, headers=headers, timeout=10)
        print(f"Result: Status {resp.status_code}")
        assert resp.status_code == 401

        # 3. Test Valid Proxy Token
        print("\nTest 3: Valid Proxy Token")
        headers = {"X-Guardian-Token": valid_token}
        resp = requests.post(f"{PROXY_URL}/", json={"prompt": "hello"}, headers=headers, timeout=10)
        print(f"Result: Status {resp.status_code}")
        assert resp.status_code in [200, 502]

        # 4. Test Valid Admin Token
        print("\nTest 4: Valid Admin Token")
        headers = {"X-Guardian-Token": admin_token}
        resp = requests.post(f"{PROXY_URL}/", json={"prompt": "hello"}, headers=headers, timeout=10)
        print(f"Result: Status {resp.status_code}")
        assert resp.status_code in [200, 502]

    finally:
        out_f.close()
        err_f.close()
        
        if guardian_proc and guardian_proc.poll() is None:
            guardian_proc.terminate()
            try:
                guardian_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                guardian_proc.kill()

        enc = sys.stdout.encoding or "utf-8"
        
        print("\n=== GUARDIAN SUBPROCESS STDOUT ===")
        stdout_text = stdout_path.read_text(encoding="utf-8", errors="ignore")
        for line in stdout_text.splitlines():
            safe_line = line.encode(enc, errors="replace").decode(enc)
            print(safe_line)
        
        print("\n=== GUARDIAN SUBPROCESS STDERR ===")
        stderr_text = stderr_path.read_text(encoding="utf-8", errors="ignore")
        for line in stderr_text.splitlines():
            safe_line = line.encode(enc, errors="replace").decode(enc)
            print(safe_line)
        
        upstream.shutdown()
        upstream.server_close()
