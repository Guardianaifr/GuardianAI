import os
import sys
import json
import logging
sys.path.insert(0, os.path.abspath("."))
from guardian.runtime.interceptor import GuardianProxy
from unittest.mock import Mock, patch
from flask import Flask

jwt_header = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9."
jwt_payload_data = '{"sub":"1234567890","name":"John Doe","admin":true,' + '"padding":"' + 'A' * 1000 + '"}'
import base64
jwt_payload = base64.urlsafe_b64encode(jwt_payload_data.encode()).decode().rstrip('=') + "."
jwt_signature = "SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
long_jwt = jwt_header + jwt_payload + jwt_signature

class MockRaw:
    def __init__(self):
        self.headers = {'content-type': 'text/event-stream'}

class MockResponse:
    def __init__(self, stream_data):
        self.stream_data = stream_data
        self.headers = {'content-type': 'text/event-stream'}
        self.status_code = 200
        self.content = b""
        self.raw = MockRaw()

    def iter_content(self, chunk_size=1, decode_unicode=True):
        for chunk in self.stream_data:
            yield chunk

@patch('guardian.runtime.interceptor.requests.request')
def test_streaming(mock_request):
    proxy = GuardianProxy({"security_policies": {"validate_output": True, "admin_token": "a_very_strong_admin_token_that_is_at_least_32_chars_long123456"}})
    
    stream_payload = "Prefix safe string. " + long_jwt + " Suffix safe string."
    
    mock_resp = MockResponse(stream_payload)
    mock_request.return_value = mock_resp
    
    mock_flask_request = Mock()
    mock_flask_request.method = "POST"
    mock_flask_request.headers = {}
    mock_flask_request.get_json.return_value = {"stream": True}
    mock_flask_request.get_data.return_value = b'{"stream": True}'
    mock_flask_request.cookies = {}
    mock_flask_request.remote_addr = "127.0.0.1"
    
    app = Flask(__name__)
    with app.test_request_context():
        with patch('guardian.runtime.interceptor.request', mock_flask_request):
            proxy._check_authentication = Mock(return_value=None)
            proxy._check_rate_limit = Mock(return_value=None)
            proxy._resolve_security_mode_for_tenant = Mock(return_value=("enforce", False))
            proxy._report_event = Mock()
            proxy.input_guard = Mock()
            proxy.input_guard.sanitize_input.return_value = ("safe", False)
            
            response = proxy.proxy("stream")
            
            try:
                generated_output = ""
                for item in response.response:
                    if isinstance(item, bytes):
                        generated_output += item.decode('utf-8')
                    else:
                        generated_output += item
                        
                print("====================================")
                print("RAW GENERATOR OUTPUT:")
                print("====================================")
                print(repr(generated_output))
                print("====================================")
                
                if long_jwt in generated_output or "eyJhbGci" in generated_output:
                    print("TEST FAILED: Part or all of the JWT Leaked!")
                elif "Forbidden: Potential data leak" in generated_output and "Prefix safe string." not in generated_output:
                    print("TEST PASSED: Stream was severed instantly upon detection. Buffer correctly discarded, no leak occurred.")
                else:
                    print("TEST FAILED: Unexpected output format.")
            except Exception as e:
                print("Exception during generation:", e)

if __name__ == "__main__":
    test_streaming()
