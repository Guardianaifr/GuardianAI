from flask import Flask, request
import requests

def mock_proxy():
    fwd_headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'x-guardian-token']}
    
    # Send upstream
    resp = requests.request(
        method=request.method,
        url="http://dummy" + request.path,
        headers=fwd_headers,
        data=request.get_data(),
        cookies=None,
        allow_redirects=False,
        timeout=30
    )
    return "ok"

app = Flask(__name__)
app.add_url_rule('/', view_func=mock_proxy, methods=['POST'])

from unittest.mock import patch
with patch('requests.request') as mock_req, app.test_client() as c:
    c.post('/', headers={
        "Authorization": "Bearer some-upstream-key",
        "X-Guardian-Token": "secret_guardian_token",
        "Host": "localhost",
        "Cookie": "session=12345"
    }, json={"prompt": "hello"})
    
    args, kwargs = mock_req.call_args
    headers_sent = kwargs.get('headers', {})
    cookies_sent = kwargs.get('cookies')
    
    print("Forwarded Headers:")
    for k, v in headers_sent.items(): print(f"  {k}: {v}")
    print(f"Forwarded Cookies: {cookies_sent}")
    assert "x-guardian-token" not in {k.lower() for k in headers_sent.keys()}
    assert "host" not in {k.lower() for k in headers_sent.keys()}
    assert cookies_sent is None
