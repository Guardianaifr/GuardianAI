import time
import json
import threading
from flask import Flask, request, Response
from guardian.runtime.interceptor import GuardianInterceptor

app = Flask(__name__)

# Fake upstream that streams two chunks
@app.route('/upstream', methods=['POST'])
def upstream():
    def generate():
        yield 'data: {"choices": [{"delta": {"content": "This is a sec"}}]}\n\n'
        time.sleep(0.5)
        yield 'data: {"choices": [{"delta": {"content": "ret password."}}]}\n\n'
    return Response(generate(), content_type='text/event-stream')

def run_server():
    app.run(port=5000)

t = threading.Thread(target=run_server, daemon=True)
t.start()
time.sleep(1)

interceptor = GuardianInterceptor({'proxy': {'target_url': 'http://127.0.0.1:5000/upstream'}, 'security_policies': {'validate_output': True, 'leak_prevention_strategy': 'block'}})
interceptor.app.config['TESTING'] = True

# F3 OutputValidator blocks "password" by default in F3 (if it triggers F3, wait F3 redacts by default)
# Let's add 'password' to some blocklist, or just test PII. Actually 'secret' might trigger it. Let's see.
# Actually, the user says F27 or PII. The output validator redacts. Wait, my code yields an error if detected is true.

with interceptor.app.test_client() as client:
    t0 = time.time()
    resp = client.post('/upstream', json={'stream': True, 'messages': [{'role': 'user', 'content': 'test'}]})
    chunks = []
    for chunk in resp.iter_encoded():
        t1 = time.time()
        print(f"[{t1-t0:.2f}s] Chunk: {chunk}")
        chunks.append(chunk)

print('Done')
