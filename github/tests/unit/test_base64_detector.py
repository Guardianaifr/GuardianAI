
import pytest
from guardrails.base64_detector import Base64Detector

class TestBase64Detector:
    def setup_method(self):
        self.detector = Base64Detector()

    def test_normal_text(self):
        # Normal text should NOT be flagged
        assert not self.detector.is_suspicious("Hello world this is a normal sentence.")
        assert not self.detector.is_suspicious("SELECT * FROM users WHERE id = 1")
        assert not self.detector.is_suspicious("A short string")

    def test_base64_payloads(self):
        # Actual malicious payloads (simulated high entropy)
        # Random bytes encoded in base64 often have high entropy
        import base64
        import os
        
        # High entropy payload (random bytes)
        payload = base64.b64encode(os.urandom(50)).decode('utf-8')
        assert self.detector.is_suspicious(payload)

    def test_low_entropy_base64(self):
        # Base64 of repeated chars (low entropy) -> Should likely pass or be edge case
        # AAAAAA... encoded is still AAAAA...
        import base64
        payload = base64.b64encode(b"A" * 50).decode('utf-8')
        # This might fail the "is_suspicious" check because entropy is low
        assert not self.detector.is_suspicious(payload) 

    def test_mixed_content(self):
        # Only checks exact matches of the pattern for now, as per implementation
        import base64
        assert not self.detector.is_suspicious("prefix " + base64.b64encode(b"foo").decode('utf-8'))
