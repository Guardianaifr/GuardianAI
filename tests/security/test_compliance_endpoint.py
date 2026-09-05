import os
import json
import secrets
import subprocess
import socket
import time
import threading
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

    # 4. Start GuardianProxy in a background daemon thread
    os.environ["GUARDIAN_CONFIG"] = str(config_path)
    os.environ["GUARDIAN_ADMIN_TOKEN"] = admin_token
    os.environ["GUARDIAN_EVIDENCE_SIGNING_KEY"] = signing_key
    os.environ["GUARDIAN_ENV"] = "test"

    from guardian.runtime.interceptor import GuardianProxy
    proxy = GuardianProxy(config)
    proxy_thread = threading.Thread(target=proxy.start, daemon=True)
    proxy_thread.start()

    try:
        _wait_http_ok(f"http://127.0.0.1:{proxy_port}/health", timeout_sec=30)

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
        proxy.stop()
        os.environ.pop("GUARDIAN_CONFIG", None)
        os.environ.pop("GUARDIAN_ADMIN_TOKEN", None)
        os.environ.pop("GUARDIAN_EVIDENCE_SIGNING_KEY", None)
        os.environ.pop("GUARDIAN_ENV", None)

