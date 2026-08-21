import time
from guardian.runtime.interceptor import GuardianProxy
from flask import Flask, Request

def mock_output_validator(text):
    if 'My_Super_Secret_Password' in text:
        return text, True
    return text, False

class MockProxy(GuardianProxy):
    def __init__(self):
        self.config = {'security_policies': {'validate_output': True}}
        class MockValidator:
            def sanitize_output(self, text):
                if 'My_Super_Secret_Password' in text:
                    return text, True
                return text, False
        self.output_validator = MockValidator()

# We can test the generator logic directly
proxy = MockProxy()

class MockResponse:
    def __init__(self):
        self.headers = {'content-type': 'text/event-stream'}
    
    def iter_content(self, chunk_size=1, decode_unicode=True):
        chunks = [
            "This is a safe prefix. ",
            "Here comes a long secret: ",
            "My_Super",
            "_Secret_Password",
            "_That_Is_Long_123",
            " And some safe suffix."
        ]
        for c in chunks:
            for char in c:
                yield char

resp = MockResponse()

def generate():
    window = ""
    margin = 50
    for chunk in resp.iter_content(chunk_size=1, decode_unicode=True):
        if chunk:
            window += chunk
            _, detected = proxy.output_validator.sanitize_output(window)
            if detected:
                yield 'data: {"error": "Forbidden: Potential data leak blocked by GuardianAI."}\\n\\n'
                return
            if len(window) > margin:
                yield window[:-margin]
                window = window[-margin:]
    if window:
        yield window

output = []
for out_chunk in generate():
    output.append(out_chunk)

print("Generated stream:", ''.join(output))

