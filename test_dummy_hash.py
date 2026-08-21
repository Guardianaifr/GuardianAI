import os
import sys
sys.path.insert(0, os.path.abspath("."))
from backend.auth import verify_password, hash_password

DUMMY_HASH = "$argon2id$v=19$m=65536,t=7,p=4$4/R9QOq4jO/5y2J9P0N1qQ$t/Z8Y3W8y9w2u3O3R4+w0w0Q2Q0V2Z4V2Z4V2Z4V2Z4"

try:
    print("Testing fake hash...")
    res = verify_password("anything", DUMMY_HASH)
    print("Result:", res)
except Exception as e:
    print("FAILED with Exception:", type(e).__name__, "-", str(e))

real_hash = hash_password("dummy")
print("Real hash generated:", real_hash)
try:
    print("Testing real hash...")
    res = verify_password("anything", real_hash)
    print("Result:", res)
except Exception as e:
    print("FAILED with Exception:", type(e).__name__, "-", str(e))
