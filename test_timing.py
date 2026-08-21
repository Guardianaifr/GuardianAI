import os
import sys
sys.path.insert(0, os.path.abspath("."))
import time
from backend.main import _validate_basic
from fastapi.security import HTTPBasicCredentials
from fastapi import HTTPException
import statistics

# Warm up
try:
    _validate_basic(HTTPBasicCredentials(username="admin", password="wrong-password"))
except HTTPException:
    pass

def measure_time(username):
    times = []
    for _ in range(20):
        t0 = time.time()
        try:
            _validate_basic(HTTPBasicCredentials(username=username, password="wrong-password"))
        except HTTPException:
            pass
        t1 = time.time()
        times.append(t1 - t0)
    return statistics.mean(times), statistics.stdev(times)

known_mean, known_std = measure_time("admin")
unknown_mean, unknown_std = measure_time("nonexistentuser")

print(f"Known user   : {known_mean:.5f} sec ± {known_std:.5f}")
print(f"Unknown user : {unknown_mean:.5f} sec ± {unknown_std:.5f}")
print("Difference   : {:.5f} sec".format(abs(known_mean - unknown_mean)))
