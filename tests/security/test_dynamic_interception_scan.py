import json
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

import requests

from guardrails.output_validator import OutputValidator


class _LeakyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        payload = {
            "choices": [
                {
                    "message": {
                        "content": "API Key leaked: sk-abc123def456ghi789jkl012mno345pqr",
                    }
                }
            ]
        }
        encoded = json.dumps(payload).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(encoded)))
        self.end_headers()
        self.wfile.write(encoded)

    def log_message(self, *_args):
        return


def test_dynamic_response_scanning_via_interception():
    server = HTTPServer(("127.0.0.1", 0), _LeakyHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    validator = OutputValidator()
    try:
        url = f"http://127.0.0.1:{server.server_port}/v1/chat/completions"
        response = requests.get(url, timeout=5)
        assert response.status_code == 200
        body = response.text
        assert validator.validate_output(body) is False
        sanitized, entities = validator.sanitize_output(body)
        assert "REDACTED" in sanitized
        assert entities
    finally:
        server.shutdown()
        server.server_close()

