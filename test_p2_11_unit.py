from unittest.mock import Mock
from guardian.runtime.interceptor import GuardianProxy

# Instantiate proxy without loading models by mocking out the heavy components
proxy = GuardianProxy({'proxy': {'target': 'http://localhost:9998'}})
proxy.tool_policy = Mock()
proxy.tool_policy.evaluate.return_value = Mock(action="allow")

# We want to test _handle_request directly
from flask import Flask, request
app = Flask(__name__)
app.add_url_rule('/<path:path>', view_func=proxy._handle_request, methods=['GET', 'POST'])

with app.test_client() as c:
    # Send a request with a guardian token and cookies
    resp = c.post(
        '/test_route', 
        headers={"X-Guardian-Token": "secret", "X-Other-Header": "value"},
        cookies={"my_cookie": "secret_cookie"},
        json={"prompt": "hello"}
    )
    print("Response JSON:")
    print(resp.json)
