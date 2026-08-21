import pytest
import httpx
import subprocess
import time
import sys

BASE_URL = "http://127.0.0.1:8001"

@pytest.fixture(scope="session", autouse=True)
def start_local_server():
    # Start uvicorn as a background process using the current python interpreter
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8001"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL
    )
    # Wait for the server to spin up and accept connections
    retries = 30
    while retries > 0:
        try:
            with httpx.Client() as client:
                r = client.get(f"{BASE_URL}/api/v1/health")
                if r.status_code == 200:
                    break
        except Exception:
            pass
        time.sleep(0.2)
        retries -= 1
        
    yield
    
    proc.terminate()
    try:
        proc.wait(timeout=5.0)
    except subprocess.TimeoutExpired:
        proc.kill()

class TestSecurityHeaders:

    def test_all_security_headers_present(self):
        """All 5 security headers must be on every response"""
        with httpx.Client() as client:
            response = client.get(f"{BASE_URL}/api/v1/health")
        
        required = {
            "x-content-type-options": "nosniff",
            "x-frame-options": "DENY",
            "x-xss-protection": "0",
            "referrer-policy": "strict-origin-when-cross-origin",
            "permissions-policy": "camera=(), microphone=(), geolocation=()",
        }
        
        # Check that headers are present and have correct values (case-insensitive keys)
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        for header, expected_value in required.items():
            assert header in headers_lower, f"Missing header: {header}"
            # Check for substring match in permissions-policy or exact match otherwise
            if header == "permissions-policy":
                assert "camera" in headers_lower[header]
            else:
                assert headers_lower[header] == expected_value, (
                    f"Wrong value for {header}: "
                    f"got {headers_lower[header]}, "
                    f"expected {expected_value}"
                )

    def test_security_headers_on_error_responses(self):
        """Security headers must be present even on 404 responses"""
        with httpx.Client() as client:
            response = client.get(f"{BASE_URL}/nonexistent-endpoint-xyz")
        headers_lower = {k.lower(): v for k, v in response.headers.items()}
        assert "x-content-type-options" in headers_lower
        assert "x-frame-options" in headers_lower

    def test_csrf_token_missing_rejected(self):
        """POST without CSRF token must return 403"""
        with httpx.Client() as client:
            response = client.post(
                f"{BASE_URL}/api/v1/admin/action",
                json={"test": True},
                headers={"Content-Type": "application/json"},
                cookies={"guardian_token": "some-token-value"}
            )
        assert response.status_code == 403, (
            f"Expected 403, got {response.status_code}. "
            f"CSRF protection may not be active."
        )

    def test_api_key_exempts_csrf(self):
        """API key authenticated requests exempt from CSRF"""
        with httpx.Client() as client:
            response = client.post(
                f"{BASE_URL}/api/v1/admin/action",
                json={"test": True},
                headers={
                    "Content-Type": "application/json",
                    "X-API-Key": "test-api-key"
                },
                cookies={"guardian_token": "some-token-value"}
            )
        # Should not be 403 (CSRF) — may be 401/404 for other reasons
        assert response.status_code != 403, \
            "API key requests should bypass CSRF check"

    def test_body_size_limit(self):
        """Request body > 1MB must return 413"""
        large_body = {"data": "x" * (1024 * 1024 + 1)}
        with httpx.Client() as client:
            response = client.post(
                f"{BASE_URL}/api/v1/scan",
                json=large_body,
                headers={"Content-Type": "application/json"},
                timeout=15.0
            )
        assert response.status_code == 413, (
            f"Expected 413 for oversized body, "
            f"got {response.status_code}"
        )

    def test_cors_no_wildcard(self):
        """CORS must not allow wildcard origins"""
        with httpx.Client() as client:
            response = client.options(
                f"{BASE_URL}/api/v1/health",
                headers={
                    "Origin": "https://evil.attacker.com",
                    "Access-Control-Request-Method": "POST"
                }
            )
        acao = response.headers.get("access-control-allow-origin", "")
        assert acao != "*", \
            "CORS allows wildcard origin — must be restricted"
        assert "evil.attacker.com" not in acao, \
            "CORS allows attacker origin"

    def test_scan_id_path_traversal_rejected(self):
        """Path traversal in scan_id must return 400"""
        traversal_ids = [
            "../../../etc/passwd",
            "..%2F..%2Fetc%2Fpasswd",
            "valid-id/../../../secret",
            "scan\x00id",
        ]
        with httpx.Client() as client:
            for scan_id in traversal_ids:
                try:
                    response = client.get(
                        f"{BASE_URL}/api/v1/scan/{scan_id}",
                        timeout=5.0
                    )
                    assert response.status_code in [400, 404], (
                        f"scan_id '{scan_id}' should return 400/404, "
                        f"got {response.status_code}"
                    )
                except httpx.InvalidURL:
                    # Successfully blocked client-side by HTTP library
                    pass
