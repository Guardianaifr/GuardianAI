import requests
import threading
import time
import sys

URL = "http://localhost:8081/v1/chat/completions"
HEADERS = {
    "Content-Type": "application/json",
    "Authorization": "Bearer 5a98a95f112930867b69e20d1b7495edc51ef6f7931a9175"
}
DATA = {
    "model": "openclaw",
    "messages": [{"role": "user", "content": "Hello"}]
}

def send_request(i):
    try:
        start_time = time.time()
        response = requests.post(URL, json=DATA, headers=HEADERS, timeout=30)
        duration = (time.time() - start_time) * 1000
        
        status = response.status_code
        if status == 429:
            print(f"Request {i}: 🛑 BLOCKED (429 Rate Limit) - {int(duration)}ms")
        elif status == 200:
            print(f"Request {i}: ✅ ALLOWED (200 OK) - {int(duration)}ms")
        else:
            print(f"Request {i}: Status {status}")
            
    except Exception as e:
        print(f"Request {i}: ⚠️ FAILED ({e})")

print(f"\n🚀 Launching 70 asynchronous requests to {URL}...")
print("--------------------------------------------------")

threads = []
for i in range(1, 71):
    t = threading.Thread(target=send_request, args=(i,))
    threads.append(t)
    t.start()
    # A tiny sleep to stagger output so it's readable, but still fast enough to trigger limit
    time.sleep(0.05) 

for t in threads:
    t.join()

print("\n--------------------------------------------------")
print("DONE. Check Dashboard for spike!")
