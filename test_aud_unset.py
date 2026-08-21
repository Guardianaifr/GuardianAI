import os
import sys
import time
sys.path.insert(0, os.path.abspath("."))
if "GUARDIAN_JWT_AUDIENCE" in os.environ:
    del os.environ["GUARDIAN_JWT_AUDIENCE"]

from backend.auth import _jwt_encode, _jwt_decode

secret = "super_secret_test_key_123"
future = int(time.time()) + 3600

# Token missing aud
missing_aud_payload = {"sub": "user1", "exp": future}
missing_aud_token = _jwt_encode(missing_aud_payload, secret)

try:
    decoded2 = _jwt_decode(missing_aud_token, secret)
    print("MISSING AUD TOKEN decoded successfully because AUDIENCE checking is NOT configured:", decoded2)
except ValueError as e:
    print("MISSING AUD TOKEN correctly rejected:", str(e))
