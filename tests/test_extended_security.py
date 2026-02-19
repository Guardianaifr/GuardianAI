import sys
import os
import tempfile
# Ensure 'guardian' directory is in path (it's the package root in production)
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'guardian')))

from guardrails.base64_detector import Base64Detector
from guardrails.fast_path import FastPath
from guardrails.skill_scanner import SkillScanner
from utils.ssh_manager import SSHTunnelManager
# Mocking GuardianProxy dependencies to test logic without starting Flask
from runtime.interceptor import GuardianProxy
from unittest.mock import MagicMock, patch
import unittest

class TestExtendedSecurity(unittest.TestCase):

    def test_base64_detection(self):
        print("\n[TEST] Base64 Payload Detection")
        detector = Base64Detector()
        
        # 1. Plain text (Safe)
        self.assertFalse(detector.is_suspicious("Hello world"), "Plain text should not trigger")
        
        # 2. Base64 Encoded Malicious Payload
        # "exec(open('/etc/passwd').read())" -> ZXhlYyhvcGVuKCcvZXRjL3Bhc3N3ZCcpLnJlYWQoKSk=
        payload = "ZXhlYyhvcGVuKCcvZXRjL3Bhc3N3ZCcpLnJlYWQoKSk="
        # Base64Detector checks the *entire* token if matches regex ^[...]{20,}$
        # So we pass just the payload for this unit test.
        
        is_suspicious = detector.is_suspicious(payload)
        self.assertTrue(is_suspicious, "Base64 payload with high entropy should be detected")
        print("[OK] Base64 Detection verified.")

    def test_fast_path_caching(self):
        print("\n[TEST] Fast Path White-listing")
        fast_path = FastPath()
        
        # 1. Unknown prompt
        self.assertFalse(fast_path.is_known_safe("Random unknown prompt"), "Unknown prompt should return False")
        
        # 2. Known safe prompt
        self.assertTrue(fast_path.is_known_safe("hello?"), "Known safe prompt 'hello?' should return True")
        self.assertTrue(fast_path.is_known_safe("ping"), "Known safe prompt 'ping' should return True")
        print("[OK] Fast Path White-listing verified.")

    def test_skill_scanner(self):
        print("\n[TEST] Static Skill Scanner")
        config = {
            "scanner": {
                "blocked_imports": ["os", "subprocess"],
                "blocked_functions": ["eval", "exec"]
            }
        }
        scanner = SkillScanner(config)
        
        with tempfile.NamedTemporaryFile(mode='w', suffix='.py', delete=False) as f:
            f.write("import os\nprint(os.environ)")
            fname = f.name
            
        try:
            # Should detect 'os' import
            issues = scanner.scan_file(fname)
            self.assertTrue(any("illicit import 'os'" in i.lower() for i in issues), 
                            f"Should detect forbidden import 'os'. Found: {issues}")
            print("[OK] Skill Scanner verified (detected forbidden import).")
        finally:
            if os.path.exists(fname):
                os.remove(fname)

    @patch('subprocess.Popen')
    def test_ssh_tunnel_manager(self, mock_popen):
        print("\n[TEST] SSH Tunnel Manager")
        mock_proc = MagicMock()
        mock_proc.pid = 12345
        mock_proc.poll.return_value = None # Running
        mock_popen.return_value = mock_proc
        
        config = {
            "ssh_tunnels": {
                "enabled": True,
                "tunnels": [{
                    "name": "TestTunnel",
                    "remote_host": "example.com",
                    "remote_user": "user",
                    "remote_port": 8080,
                    "local_port": 9090
                }]
            }
        }
        
        manager = SSHTunnelManager(config)
        manager.start_all()
        
        # Verify subprocess call
        self.assertTrue(mock_popen.called)
        args, _ = mock_popen.call_args
        cmd = args[0]
        # cmd is a list like ['ssh', '-L', ...]
        self.assertIn("ssh", cmd)
        self.assertIn("9090:localhost:8080", "".join(cmd))
        
        print("[OK] SSH Tunnel Manager verified (mocked start).")


    def test_threat_feed_integration(self):
        print("\n[TEST] Threat Feed Integration")
        # 1. Setup Proxy with mocked ThreatFeed
        config = {"threat_feed": {"enabled": True, "url": "http://mock.feed"}, "security_policies": {}}
        
        # We need to mock ThreatFeed BEFORE GuardianProxy init to stop thread
        # Mock targets must match how they are imported in interceptor.py
        # interceptor.py imports them as: from guardrails.input_filter import ...
        # But we verify interceptor.py code:
        # from guardrails.input_filter import InputFilter
        # So we mock 'runtime.interceptor.InputFilter' etc because that's the name in the module we are testing?
        # NO, patch works on where the object is looked up.
        # We are importing GuardianProxy from runtime.interceptor.
        # So we patch 'runtime.interceptor.InputFilter'
        
        with patch('runtime.interceptor.InputFilter'), \
             patch('runtime.interceptor.OutputValidator'), \
             patch('runtime.interceptor.AIPromptFirewall'), \
             patch('runtime.interceptor.RateLimiter'), \
             patch('runtime.interceptor.ThreatFeed') as MockThreatFeed:
            
            # Setup MockThreatFeed instance
            mock_feed_instance = MockThreatFeed.return_value
            mock_feed_instance.patterns = [] # Start empty
            
            proxy = GuardianProxy(config)
            
            # 2. Inject a known threat pattern into the MOCK instance that Proxy holds
            # GuardianProxy assigns self.threat_feed = ThreatFeed(...) which returns mock_feed_instance
            proxy.threat_feed.patterns = [r"known_malicious_signature"]
            
            # 3. Test Blocked Prompt
            timings = {}
            resp = proxy._check_threat_feed("This contains a known_malicious_signature attack", 0, timings)
            
            self.assertIsNotNone(resp, "Should return a Response object (block) for matched threat")
            self.assertEqual(resp.status_code, 403)
            # Response data is bytes in Flask
            self.assertIn(b"Threat Feed", resp.data)
            
            # 4. Test Safe Prompt
            resp_safe = proxy._check_threat_feed("Safe prompt", 0, timings)
            self.assertIsNone(resp_safe, "Should return None (pass) for safe prompt")
            
            print("[OK] Threat Feed Logic verified.")

if __name__ == '__main__':
    unittest.main()
