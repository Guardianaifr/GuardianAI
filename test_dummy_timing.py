import time
from backend.auth import verify_password, hash_password

fake = "$argon2id$v=19$m=65536,t=7,p=4$4/R9QOq4jO/5y2J9P0N1qQ$t/Z8Y3W8y9w2u3O3R4+w0w0Q2Q0V2Z4V2Z4V2Z4V2Z4"
real = hash_password("dummy")

t0 = time.time()
verify_password("dummy", fake)
t1 = time.time()
verify_password("dummy", real)
t2 = time.time()

print("Fake hash time:", t1 - t0)
print("Real hash time:", t2 - t1)
