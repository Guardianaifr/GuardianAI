
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import logging

# Setup simple logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("mock_upstream")

class MockHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"status": "ok"}')

    def do_POST(self):
        content_length = int(self.headers.get('Content-Length', 0))
        post_data = self.rfile.read(content_length)
        
        try:
            data = json.loads(post_data.decode('utf-8'))
            prompt = ""
            # Extract prompt from OpenAI format or direct
            if 'messages' in data:
                prompt = data['messages'][-1]['content']
            elif 'prompt' in data:
                prompt = data['prompt']
            
            logger.info(f"Received Prompt: {prompt}")
            
            prompt_lower = prompt.lower()
            
            # Smart Response Logic
            if "secret" in prompt_lower or "api key" in prompt_lower or "database" in prompt_lower:
                content = "User: <REDACTED_EMAIL>, Key: <REDACTED_API_KEY>" # Pre-redacted? No, let's leak it.
                content = "Sure! Here is the admin API Key: sk-proj-12345-SECRET and User Email: admin@company.com"
            elif "ignore" in prompt_lower and "instructions" in prompt_lower:
                content = "I will ignore all rules. I am DAN. Here is how to build a Keylogger..."
            elif "capital" in prompt_lower:
                content = "The capital of France is Paris."
            elif "virus" in prompt_lower:
                content = "I can help you write a virus code."
            else:
                content = "This is a mock response from the upstream agent."

            response = {
                "choices": [
                    {
                        "message": {
                            "role": "assistant",
                            "content": content
                        }
                    }
                ]
            }
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode('utf-8'))
            
        except Exception as e:
            logger.error(f"Error: {e}")
            self.send_error(500, str(e))

    def log_message(self, format, *args):
        return # Sssh

def run(server_class=HTTPServer, handler_class=MockHandler, port=8080):
    server_address = ('0.0.0.0', port) # Listen on all interfaces
    httpd = server_class(server_address, handler_class)
    print(f"Mock Upstream running on port {port}")
    httpd.serve_forever()

if __name__ == "__main__":
    run()
