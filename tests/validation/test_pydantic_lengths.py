import pytest
import subprocess
import time
import sys
import httpx
from pydantic import ValidationError
from backend.main import ScanRequest
import backend.main as backend_main

BASE_URL = "http://127.0.0.1:8002"
_TEST_ADMIN_PASS = "test-pydantic-pass-8271"

@pytest.fixture(scope="session", autouse=True)
def start_local_server():
    import os
    env = os.environ.copy()
    env["GUARDIAN_ADMIN_PASS"] = _TEST_ADMIN_PASS
    # Start uvicorn as a background process using the current python interpreter
    proc = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", "127.0.0.1", "--port", "8002"],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=env,
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

class TestPydanticLengths:

    def test_pydantic_validation_direct(self):
        """ScanRequest must reject target_url > 512 characters directly"""
        oversized = "http://" + "a" * 513
        with pytest.raises(ValidationError):
            ScanRequest(target_url=oversized, target_name="test", depth="standard")

    def test_pydantic_validation_via_api(self):
        """API must return 422 for ScanRequest with target_url > 512 characters"""
        oversized = "http://" + "a" * 513
        payload = {
            "target_url": oversized,
            "target_name": "test",
            "depth": "standard"
        }
        with httpx.Client() as client:
            response = client.post(
                f"{BASE_URL}/api/v1/scan-jobs",
                json=payload,
                headers={"Content-Type": "application/json"},
                auth=("admin", _TEST_ADMIN_PASS),
            )
        assert response.status_code == 422, (
            f"Expected 422 for oversized string parameter, "
            f"got {response.status_code}"
        )
