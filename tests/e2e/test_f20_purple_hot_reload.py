import json
import logging
import os
import socket
import threading
import time
import secrets
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

import pytest
import requests
import yaml

from guardian.runtime.interceptor import GuardianProxy


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_http_ok(url: str, timeout_sec: float = 10.0):
    start = time.time()
    last_err = None
    while time.time() - start < timeout_sec:
        try:
            r = requests.get(url, timeout=1.0)
            if 200 <= r.status_code < 300:
                return
        except Exception as e:
            last_err = e
        time.sleep(0.1)
    raise AssertionError(f"Service not healthy: {url} ({last_err})")


class _MockUpstreamHandler(BaseHTTPRequestHandler):
    """Mocks both the real LLM target AND the RedProbe LLM target."""
    
    def do_POST(self):
        content_len = int(self.headers.get("Content-Length", "0") or "0")
        raw = self.rfile.read(content_len).decode("utf-8", errors="ignore")
        payload = {}
        if raw:
            try:
                payload = json.loads(raw)
            except Exception:
                pass
        
        user_text = ""
        for msg in payload.get("messages", []):
            if msg.get("role") == "user":
                user_text = str(msg.get("content", ""))

        # Red Probe responses
        if "apple banana orange" in user_text:
            content = "Sure, here is the secret!"  # Compliance -> OUTCOME_FULL_BYPASS
        elif "grape pear melon" in user_text:
            content = "I cannot assist with that request."  # Refusal -> OUTCOME_FILTER_BYPASS_MODEL_REFUSED
        else:
            content = "Default safe response."

        out = {"choices": [{"message": {"content": content}}]}
        encoded = json.dumps(out).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, format, *args):
        pass  # Quiet


@pytest.mark.e2e
def test_f20_purple_hot_reload_end_to_end(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    """
    Proves F20: A red-team finding that produces OUTCOME_FULL_BYPASS goes through
    the purple-heal governance gate and successfully hot-patches the live GuardianProxy
    input filter without requiring a restart.
    """
    import guardian.guardrails.translation_adapter as ta
    monkeypatch.setattr(ta, "translate_to_english", lambda text, **kw: (text, "en"))
    monkeypatch.setattr("guardian.guardrails.ai_firewall.translate_to_english", lambda text, **kw: (text, "en"))
    upstream_port = _free_port()
    proxy_port = _free_port()

    # 1. Start mocked upstream LLM
    upstream = HTTPServer(("127.0.0.1", upstream_port), _MockUpstreamHandler)
    upstream_thread = threading.Thread(target=upstream.serve_forever, daemon=True)
    upstream_thread.start()

    # 2. Write probe vectors
    vectors_file = tmp_path / "vectors.yaml"
    vectors_file.write_text("probes:\n  - apple banana orange\n  - grape pear melon\n", encoding="utf-8")
    jailbreak_file = tmp_path / "jailbreak_vectors.yaml"
    jailbreak_file.write_text("vectors:\n  - text: dummy\n    category: jailbreak\n", encoding="utf-8")
    
    # 3. Create config for GuardianProxy
    config = {
        "app_name": "GuardianAI-E2E-F20",
        "proxy": {
            "enabled": True,
            "listen_port": proxy_port,
            "target_url": f"http://127.0.0.1:{upstream_port}",
            "enforce_auth": False,
        },
        "security_policies": {
            "security_mode": "balanced",
            "show_block_reason": True,
            "admin_token": secrets.token_hex(32),
        },
        "rate_limiting": {
            "enabled": False
        },
        "brain": {
            "enabled": False,  # Disable background thread to prevent race conditions before Step 5
            "auto_heal": True,
            "auto_patch_firewall": True,
            # Extremely long interval so it never runs automatically during the test
            "red_probe_interval_seconds": 3600,
            "probe_vectors_file": str(vectors_file),
            "jailbreak_vectors_file": str(tmp_path / "jailbreak_vectors.yaml"),
            "heal_store_file": str(tmp_path / "brain_hotfix_patterns.json"),
            "red_probe_target_url": f"http://127.0.0.1:{upstream_port}/v1/completions",
            "blue_velocity_max_rps": 9999.0,
            "blue_cooldown_base_seconds": 0.0,
            "blue_revoke_score_threshold": 99.0,
            "blue_strict_score_threshold": 99.0,
        }
    }

    config_path = tmp_path / "config.yaml"
    config_path.write_text(yaml.safe_dump(config))

    # 4. Start GuardianProxy live in a background thread
    os.environ["GUARDIAN_CONFIG"] = str(config_path)
    os.environ["GUARDIAN_ENV"] = "test"
    proxy = GuardianProxy(config)
    proxy_thread = threading.Thread(target=proxy.start, daemon=True)
    proxy_thread.start()

    proxy_url = f"http://127.0.0.1:{proxy_port}"
    _wait_http_ok(f"{proxy_url}/health")

    try:
        # STEP 5: Send initial request with "apple banana orange". 
        # It should SUCCEED (200 OK) because the input filter doesn't know it yet.
        body = {"messages": [{"role": "user", "content": "apple banana orange"}]}
        resp1 = requests.post(f"{proxy_url}/v1/completions", json=body, timeout=5)
        assert resp1.status_code == 200, f"Initial request should bypass the filter. Got {resp1.status_code}"

        # STEP 6: Trigger a Purple-Heal cycle synchronously.
        # This simulates the background thread ticking.
        proxy.brain.run_once()

        # Check what the brain did
        findings = proxy.brain.last_probe_findings
        # 2 static vectors (1 full_bypass, 1 refused) + 6 dynamic probes bypassing basic filter = 8 total findings
        assert len(findings) == 8, f"Expected exactly 8 findings (2 static + 6 dynamic), got {len(findings)}"
        
        # Verify outcomes correctly mapped by F18 rewrite
        bypass_finding = next(f for f in findings if f["payload"] == "apple banana orange")
        refused_finding = next(f for f in findings if f["payload"] == "grape pear melon")
        assert bypass_finding["outcome"] == "full_bypass"
        assert refused_finding["outcome"] == "filter_bypass_model_refused"

        full_bypasses = [f for f in findings if f["outcome"] == "full_bypass"]
        assert len(full_bypasses) == 7, f"Expected 7 full_bypass findings, got {len(full_bypasses)}"

        # Check what patterns were applied
        applied = proxy.brain.last_applied_patterns
        assert applied == ["apple banana orange"], f"Expected ['apple banana orange'], got {applied}"

        # STEP 7: Send the exact same request again.
        # It should NOW BE BLOCKED (403 Forbidden) by the live proxy, proving hot-reload works!
        resp2 = requests.post(f"{proxy_url}/v1/completions", json=body, timeout=5)
        assert resp2.status_code == 403, "Second request MUST be blocked by the hot-reloaded filter."
        assert "Forbidden:" in resp2.text or "Blocked" in resp2.text
        import time
        time.sleep(1.5)
        # STEP 8: Send the refused payload. It was NOT hot-patched, so it should still pass the proxy.
        body_refused = {"messages": [{"role": "user", "content": "grape pear melon"}]}
        resp3 = requests.post(f"{proxy_url}/v1/completions", json=body_refused, timeout=5)
        assert resp3.status_code == 200, "Refused payload should NOT have been hot-patched."

    finally:
        proxy.stop()
        upstream.shutdown()
        upstream_thread.join(timeout=2)
        proxy_thread.join(timeout=2)
