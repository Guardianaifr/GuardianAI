import os
import sys

# Fake out huggingface so it doesn't download
os.environ['HF_HUB_OFFLINE'] = '1'

# We don't even need to run GuardianProxy fully, just test the health_check method
from guardian.runtime.interceptor import GuardianProxy
from flask import Flask
proxy = GuardianProxy.__new__(GuardianProxy)
proxy.app = Flask(__name__)
proxy.app.add_url_rule('/health', view_func=proxy.health_check, methods=['GET'])

with proxy.app.test_client() as c:
    resp = c.get('/health')
    print("Health Status:", resp.status_code)
    print("Health Output:", resp.json)
