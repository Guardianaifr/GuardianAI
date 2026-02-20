import unittest
from unittest.mock import patch, MagicMock, ANY
import sys
import os
import json
import socket

# Ensure 'guardian' and 'backend' are in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..')))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'backend')))

from backend import main as backend_main

class TestAuditLoggingInternal(unittest.TestCase):

    def setUp(self):
        self.sample_payload = {
            "action": "test_action",
            "user": "test_user",
            "timestamp": 1234567890.0,
            "details": {"foo": "bar"}
        }

    @patch('backend.main.requests.post')
    def test_forward_external_audit_log_http(self, mock_post):
        # Setup configuration
        with patch.object(backend_main, 'AUDIT_SINK_URL', 'http://mock-sink.com'), \
             patch.object(backend_main, 'AUDIT_SINK_TOKEN', 'mock-token'):
            
            mock_post.return_value.status_code = 200
            
            success = backend_main._forward_external_audit_log(self.sample_payload)
            
            self.assertTrue(success)
            mock_post.assert_called_with(
                'http://mock-sink.com',
                json=self.sample_payload,
                headers={'Content-Type': 'application/json', 'Authorization': 'Bearer mock-token'},
                timeout=ANY
            )

    @patch('socket.socket')
    def test_forward_syslog_audit_log(self, mock_socket_cls):
        # Setup configuration
        with patch.object(backend_main, 'AUDIT_SYSLOG_HOST', '127.0.0.1'), \
             patch.object(backend_main, 'AUDIT_SYSLOG_PORT', 514):
            
            mock_socket = MagicMock()
            mock_socket_cls.return_value = mock_socket
            
            success = backend_main._forward_syslog_audit_log(self.sample_payload)
            
            self.assertTrue(success)
            # Verify UDP send
            mock_socket.sendto.assert_called()
            # Decode the message sent to verification
            args, _ = mock_socket.sendto.call_args
            message_bytes = args[0]
            self.assertIn(b'guardian-backend:', message_bytes)
            self.assertIn(b'"action":"test_action"', message_bytes)

    @patch('backend.main.requests.post')
    def test_forward_splunk_audit_log(self, mock_post):
        # Setup configuration
        with patch.object(backend_main, 'AUDIT_SPLUNK_HEC_URL', 'http://splunk:8088'), \
             patch.object(backend_main, 'AUDIT_SPLUNK_HEC_TOKEN', 'splunk-token'):
            
            mock_post.return_value.status_code = 200
            
            success = backend_main._forward_splunk_audit_log(self.sample_payload)
            
            self.assertTrue(success)
            # Verify Splunk format
            call_args = mock_post.call_args
            self.assertEqual(call_args[0][0], 'http://splunk:8088')
            json_body = call_args[1]['json']
            self.assertEqual(json_body['event'], self.sample_payload)
            self.assertEqual(json_body['sourcetype'], '_json')
            self.assertIn('Authorization', call_args[1]['headers'])

    @patch('backend.main.requests.post')
    def test_forward_datadog_audit_log(self, mock_post):
        # Setup configuration
        with patch.object(backend_main, 'AUDIT_DATADOG_API_KEY', 'dd-key'):
            
            mock_post.return_value.status_code = 202
            
            success = backend_main._forward_datadog_audit_log(self.sample_payload)
            
            self.assertTrue(success)
            # Verify Datadog format
            call_args = mock_post.call_args
            self.assertIn('http', call_args[0][0]) # URL check
            json_body = call_args[1]['json']
            self.assertIsInstance(json_body, list)
            log_entry = json_body[0]
            self.assertIn('ddsource', log_entry)
            self.assertIn('message', log_entry)
            # Verify API Key header
            self.assertEqual(call_args[1]['headers']['DD-API-KEY'], 'dd-key')

if __name__ == '__main__':
    unittest.main()
