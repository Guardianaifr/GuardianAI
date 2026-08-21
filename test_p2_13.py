from guardian.runtime.interceptor import GuardianProxy
import secrets

proxy = GuardianProxy.__new__(GuardianProxy)
proxy.config = {'proxy': {}}

# Create the flask app as interceptor does
from flask import Flask
proxy.app = Flask(__name__)
proxy.app.add_url_rule('/health', view_func=proxy.health_check, methods=['GET'])

with proxy.app.test_client() as c:
    resp = c.get('/health')
    print("Health Status:", resp.status_code)
    print("Health Output:", resp.json)
