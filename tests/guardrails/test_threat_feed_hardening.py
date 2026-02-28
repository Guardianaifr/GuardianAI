import pytest
import time
import requests
import threading
from http.server import HTTPServer, BaseHTTPRequestHandler
from guardian.guardrails.threat_feed import ThreatFeed

class MockRedirectHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/redirect':
            self.send_response(301)
            self.send_header('Location', 'http://malicious.com/')
            self.end_headers()
        elif self.path == '/feed.yaml':
            self.send_response(200)
            self.send_header('Content-Type', 'text/yaml')
            self.end_headers()
            
            # Create a pathologically large and nested regex that stalls `re.compile`
            pathological = "(((((" * 100 + "a" + ")))))" * 100
            self.wfile.write(f'patterns:\n  - "safe"\n  - "{pathological}"'.encode('utf-8'))

def run_mock_server():
    server = HTTPServer(('127.0.0.1', 9091), MockRedirectHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return server

@pytest.fixture(scope="module")
def mock_server():
    server = run_mock_server()
    time.sleep(1) # give server time to start
    yield "http://127.0.0.1:9091"
    server.shutdown()

def test_https_enforcement():
    # Should reject HTTP
    tf = ThreatFeed(feed_url="http://insecure.com/feed.yaml")
    assert tf.feed_url is None

    # Should accept HTTPS
    tf = ThreatFeed(feed_url="https://secure.com/feed.yaml", update_interval=999)
    assert tf.feed_url == "https://secure.com/feed.yaml"

def test_ssrf_redirect_block(mock_server, caplog):
    # Pass 'mock' to bypass the HTTPS enforcement so we can test the local redirect server
    tf = ThreatFeed(feed_url="mock")
    tf.feed_url = f"{mock_server}/redirect"
    
    tf.fetch_latest()
    
    # Should catch the 301 and log an error
    assert "ThreatFeed rejected due to HTTP Redirect (301) to block SSRF vectors" in caplog.text

def test_redos_sandbox(mock_server, caplog):
    tf = ThreatFeed(feed_url="mock")
    tf.feed_url = f"{mock_server}/feed.yaml"
    
    tf.fetch_latest()
    
    # Safe pattern compiled
    assert "safe" in tf.patterns
    
    # ReDoS pattern timed out and rejected (or failed due to max repeated limit natively in Python)
    assert len(tf.patterns) == 1

