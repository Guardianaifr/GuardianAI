import os
import json
import secrets
import subprocess
import socket
import time
from pathlib import Path
import pytest
import yaml
import requests
import hmac

ROOT = Path(__file__).resolve().parents[2]

def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]

def _wait_http_ok(url: str, timeout_sec: float = 10.0):
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

def test_compliance_evidence_endpoint(tmp_path: Path):
    proxy_port = _free_port()
    admin_token = secrets.token_urlsafe(32)
    signing_key = secrets.token_urlsafe(32)

    config = {
        "app_name": "GuardianAI-Compliance-Test",
        "version": "test",
        "guardian_id": "test-compliance",
        "security_policies": {
            "admin_token": admin_token,
        },
        "proxy": {
            "enabled": True,
            "listen_port": proxy_port,
            "target_url": f"http://127.0.0.1:{_free_port()}",
            "enforce_auth": False,
        },
        "rate_limiting": {"enabled": False},
        "siem": {"enabled": False},
        "network_monitoring": False,
        "runtime_monitoring": False,
        "filesystem_sandbox": False,
        "purple_team_governance": {"enabled": False},
        "backend": {"enabled": False},
        "scanner": {},
        "runtime_monitoring": {},
        "threat_feed": {"enabled": False},
        "hardening": {"bypass_provenance_in_dev": True},
        "brain": {
            "db_path": ":memory:",
            "cyberops_intel": ":memory:",
        },
        "rate_limiting": {"enabled": False},
    }
    
    config_path = tmp_path / "compliance_test_config.yaml"
    config_path.write_text(yaml.safe_dump(config), encoding="utf-8")

    python_exe = str(ROOT / ".venv312" / "Scripts" / "python.exe")
    if not os.path.exists(python_exe):
        python_exe = sys.executable

    guardian_cmd = [python_exe, str(ROOT / "guardian" / "main.py")]
    
    guardian_env = os.environ.copy()
    guardian_env["GUARDIAN_CONFIG"] = str(config_path)
    guardian_env["GUARDIAN_ADMIN_TOKEN"] = admin_token
    guardian_env["GUARDIAN_EVIDENCE_SIGNING_KEY"] = signing_key
    guardian_env["GUARDIAN_ENV"] = "test"
    guardian_env["PYTHONPATH"] = str(ROOT)
    guardian_env["PYTHONUNBUFFERED"] = "1"

    stdout_path = tmp_path / "guardian_stdout.log"
    stderr_path = tmp_path / "guardian_stderr.log"

    out_f = open(stdout_path, "w", encoding="utf-8")
    err_f = open(stderr_path, "w", encoding="utf-8")
    guardian_proc = subprocess.Popen(guardian_cmd, cwd=str(ROOT), env=guardian_env, stdout=out_f, stderr=err_f)
    
    try:
        _wait_http_ok(f"http://127.0.0.1:{proxy_port}/health", timeout_sec=120)

        BASE_URL = f"http://127.0.0.1:{proxy_port}/api/compliance/evidence"

        # 1. Unauthenticated Request -> 401
        r_unauth = requests.get(BASE_URL)
        assert r_unauth.status_code == 401
        assert "Unauthorized" in r_unauth.text

        # 2. Authenticated Request -> 200 with Valid HMAC
        headers = {"Authorization": f"Bearer {admin_token}"}
        r_auth = requests.get(BASE_URL, headers=headers)
        assert r_auth.status_code == 200
        
        bundle = r_auth.json()
        assert "payload" in bundle
        assert "signature" in bundle

        # 3. Verify Signature
        from guardian.security.evidence_export import verify_evidence_payload_signature
        is_valid = verify_evidence_payload_signature(bundle["payload"], signing_key, bundle["signature"])
        assert is_valid, "Evidence payload signature verification failed"

    finally:
        out_f.close()
        err_f.close()
        if guardian_proc and guardian_proc.poll() is None:
            guardian_proc.terminate()
            try:
                guardian_proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                guardian_proc.kill()
                
        import sys
        enc = sys.stdout.encoding or "utf-8"
        print("\n=== GUARDIAN SUBPROCESS STDOUT ===")
        print(stdout_path.read_text(encoding="utf-8", errors="ignore"))
        print("\n=== GUARDIAN SUBPROCESS STDERR ===")
        print(stderr_path.read_text(encoding="utf-8", errors="ignore"))
