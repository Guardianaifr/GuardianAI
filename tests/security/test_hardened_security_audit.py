import pytest
import sys
import os
import threading
import time
import requests
import uvicorn
from pathlib import Path

# Ensure project root is on the path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from guardian.audit.crypto_scanner import CryptoAuditScanner, ScanDepth
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
    """
    scanner = CryptoAuditScanner(target_url=hardened_server, target_name="Hardened Target", depth=ScanDepth.STANDARD)
    result = scanner.run_scan()
    
    # Assertions
    assert result.score == 100.0, f"Expected 100.0 score on hardened target, got {result.score}"
    assert result.vulnerabilities_found == 0, f"Expected 0 vulnerabilities, got {result.vulnerabilities_found}"
    assert result.grade == "A+", f"Expected grade A+, got {result.grade}"
    
    # Verify multi-turn findings are both PROTECTED
    mt_findings = [f for f in result.findings if f["vector_id"].startswith("MT-")]
    assert len(mt_findings) == 2, f"Expected 2 multi-turn findings, got {len(mt_findings)}"
    for f in mt_findings:
        assert f["status"] == "protected", f"Expected multi-turn finding {f['vector_id']} to be protected, got {f['status']}"
