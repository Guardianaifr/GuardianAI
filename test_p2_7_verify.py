import time
from backend.auth import verify_password, hash_password

DUMMY_HASH = "$argon2id$v=19$m=65536,t=7,p=4$KUGcP8geNdGLxEzipJtshQ$BiFNhl23xD9jhkM4YXPtzmfc1AR6XL1n6BV4zvcj5Ak"

print("1. Testing execution for exceptions:")
try:
    res = verify_password("anything", DUMMY_HASH)
    print(f"   verify_password('anything', DUMMY_HASH) -> {res}")
except Exception as e:
    print(f"   Exception thrown: {type(e).__name__} - {str(e)}")

print("\n2. Testing timing (10 iterations each):")
real_hash = hash_password("some_real_password")

t0 = time.time()
for _ in range(10):
    verify_password("anything", real_hash)
t_real = (time.time() - t0) / 10

t0 = time.time()
for _ in range(10):
    verify_password("anything", DUMMY_HASH)
t_dummy = (time.time() - t0) / 10

print(f"   Real hash avg  : {t_real:.5f} sec")
print(f"   Dummy hash avg : {t_dummy:.5f} sec")
print(f"   Difference     : {abs(t_real - t_dummy):.5f} sec")
