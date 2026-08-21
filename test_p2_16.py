from guardian.runtime.interceptor import GuardianProxy
from flask import Flask, request, jsonify
import os
import json

# Setup mock proxy
proxy = GuardianProxy.__new__(GuardianProxy)
proxy.config = {'proxy': {}}
proxy.app = Flask(__name__)
proxy.last_debug_info = {}
proxy.admin_token = "admin123"

def check_admin_auth():
    return None
proxy._check_admin_auth = check_admin_auth

proxy._update_debug_info = lambda info: setattr(proxy, 'last_debug_info', info)

@proxy.app.route('/dummy', methods=['POST'])
def dummy():
    # Execute the redaction logic exactly as written in interceptor.py
    safe_headers = dict(request.headers)
    for sensitive_key in ['Authorization', 'X-Guardian-Token', 'x-api-key']:
        for header_key in list(safe_headers.keys()):
            if header_key.lower() == sensitive_key.lower():
                val = safe_headers[header_key]
                if val.lower().startswith('bearer '):
                    safe_headers[header_key] = val[:10] + '***' + val[-4:]
                else:
                    safe_headers[header_key] = '***REDACTED***'

    prompt = request.json.get("prompt", "")
    proxy._update_debug_info({
        "prompt_extracted": prompt[:100] + '...[REDACTED]' if prompt and len(prompt) > 100 else prompt,
        "headers": safe_headers
    })
    return jsonify({"status": "ok"})

proxy.app.add_url_rule('/debug', view_func=proxy.debug_info, methods=['GET'])

with proxy.app.test_client() as c:
    os.environ["GUARDIAN_ENV"] = "development"
    # Send request to trigger _update_debug_info
    c.post('/dummy', headers={
        "Authorization": "Bearer 1234567890abcdef1234567890",
        "X-Guardian-Token": "secret_token_123",
        "Safe-Header": "ok"
    }, json={"prompt": "A"*150})
    
    resp = c.get('/debug')
    print("DEVELOPMENT MODE OUTPUT:")
    print(json.dumps(resp.json, indent=2))
    
    # 2. Test production mode
    os.environ["GUARDIAN_ENV"] = "production"
    resp2 = c.get('/debug')
    print("\nPRODUCTION MODE OUTPUT:")
    print(f"Status: {resp2.status_code}")
    print(f"Body: {resp2.data.decode('utf-8')}")

