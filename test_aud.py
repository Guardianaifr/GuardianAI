import os
import sys
import time
sys.path.insert(0, os.path.abspath("."))
os.environ["GUARDIAN_JWT_AUDIENCE"] = "my_expected_aud"

from backend.auth import _jwt_encode, _jwt_decode

secret = "super_secret_test_key_123"
future = int(time.time()) + 3600

# 1. Correctly issued token with aud
valid_payload = {"sub": "user1", "aud": "my_expected_aud", "exp": future}
valid_token = _jwt_encode(valid_payload, secret)

try:
    decoded = _jwt_decode(valid_token, secret)
    print("VALID TOKEN decoded successfully:", decoded)
except Exception as e:
    print("VALID TOKEN FAILED:", str(e))

# 2. Token missing aud
missing_aud_payload = {"sub": "user1", "exp": future}
missing_aud_token = _jwt_encode(missing_aud_payload, secret)

try:
    decoded2 = _jwt_decode(missing_aud_token, secret)
    print("MISSING AUD TOKEN decoded successfully (VULNERABLE!)", decoded2)
except ValueError as e:
    print("MISSING AUD TOKEN correctly rejected:", str(e))
