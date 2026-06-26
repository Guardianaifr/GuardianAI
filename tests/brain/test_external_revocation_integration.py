import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

from brain.orchestrator import CyberBrain


class _BypassFilter:
    def __init__(self):
        self.block_patterns = []

    def check_prompt(self, _prompt: str) -> bool:
        return True


def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


def test_external_revocation_mock_server(tmp_path):
    received = {}

    class _Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            body = self.rfile.read(length).decode("utf-8")
            received["path"] = self.path
            received["auth"] = self.headers.get("Authorization")
            received["json"] = json.loads(body)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"ok":true}')

        def log_message(self, _format, *_args):
            return

    port = _free_port()
    server = HTTPServer(("127.0.0.1", port), _Handler)
    t = threading.Thread(target=server.serve_forever, daemon=True)
    t.start()
    try:
        config = {
            "brain": {
                "enabled": True,
                "blue_escalation_threshold": 10,
                "blue_revoke_score_threshold": 0.2,
                "external_jwt_revocation": {
                    "enabled": True,
                    "url": f"http://127.0.0.1:{port}/revoke",
                    "token": "provider-token",
                    "timeout_seconds": 1,
                    "max_retries": 1,
                    "include_raw_jwt": False,
                },
            }
        }
        brain = CyberBrain(config, tmp_path, _BypassFilter())
        # JWT payload decodes to {"sub":"u1","jti":"j1"}.
        fake_jwt = "aaa.eyJzdWIiOiJ1MSIsImp0aSI6ImoxIn0.ccc"
        brain.bind_session_identity("jwt:test", fake_jwt)
        result = brain.analyze_request("jwt:test", "reverse shell", blocked=True)
        assert result["action"] == "revoke"
        assert received["path"] == "/revoke"
        assert received["auth"] == "Bearer provider-token"
        assert received["json"]["session_id"] == "jwt:test"
        assert received["json"]["jwt_sub"] == "u1"
        assert received["json"]["jwt_jti"] == "j1"
        assert "raw_jwt" not in received["json"]
    finally:
        server.shutdown()
