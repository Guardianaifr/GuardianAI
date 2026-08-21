import os
import sys
from fastapi.testclient import TestClient

os.environ['GUARDIAN_ENV'] = 'development'
os.environ['GUARDIAN_JWT_SECRET'] = 'test-secret-123'
os.environ['GUARDIAN_USER_USER'] = 'my_test_user'
os.environ['GUARDIAN_USER_PASS'] = 'my_test_pass'
sys.path.insert(0, os.path.abspath("."))

from backend.main import app

client = TestClient(app)

res1 = client.get("/api/v1/auth/whoami")
print(f"Whoami without auth: {res1.status_code}")

res2 = client.get("/api/v1/auth/whoami", auth=("my_test_user", "my_test_pass"))
print(f"Whoami with valid basic auth: {res2.status_code}")
if res2.status_code == 200:
    print(res2.json())
