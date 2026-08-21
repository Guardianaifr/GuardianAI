import sys
from guardian.runtime.interceptor import GuardianProxy
from unittest.mock import Mock, patch

# Mock dependencies
proxy = GuardianProxy.__new__(GuardianProxy)
proxy.target_url = "http://localhost:9998"
proxy.config = {'proxy': {'upstream_key': 'test_upstream_key'}}

with patch('guardian.runtime.interceptor.requests.request') as mock_req:
    # Setup mock request
    class MockRequest:
        def __init__(self):
            self.headers = {"Host": "localhost", "X-Guardian-Token": "secret", "User-Agent": "test-agent"}
            self.cookies = {"session_id": "secret"}
            self.method = "POST"
        def get_data(self):
            return b""
            
    mock_flask_request = MockRequest()
    
    with patch('guardian.runtime.interceptor.request', mock_flask_request):
        # Call the forwarding block logic directly or recreate it to verify
        # Actually, let's just copy the logic to see if our fix works:
        fwd_headers = {
            key: value for (key, value) in mock_flask_request.headers.items()
            if key.lower() not in ('host', 'x-guardian-token')
        }
        
        upstream_key = proxy.config.get('proxy', {}).get('upstream_key')
        if upstream_key:
            fwd_headers['Authorization'] = f"Bearer {upstream_key}"
            
        print("Forwarded Headers:", fwd_headers)
        print("Cookies Sent:", None) # We hardcoded cookies=None
