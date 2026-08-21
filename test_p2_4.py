import requests
import subprocess
import time
import os

env = os.environ.copy()
env['GUARDIAN_JWT_SECRET'] = 'test'
env['GUARDIAN_ADMIN_PASS'] = 'test'
env['PYTHONPATH'] = 'guardian'
p = subprocess.Popen(['python', 'backend/main.py'], env=env)
time.sleep(3)
try:
    print('PRE-FIX REQUEST:')
    r1 = requests.get('http://127.0.0.1:8000/api/v1/leaderboard')
    print(f'Status: {r1.status_code}')
    print(r1.text[:200])
finally:
    p.terminate()
