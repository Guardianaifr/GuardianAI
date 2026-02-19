import pytest
from unittest.mock import MagicMock, patch
import sys
from flask import Flask, Response, request
import json

# --- MOCKING STRATEGY ---
mock_requests = MagicMock()
mock_input_filter = MagicMock()
mock_output_validator = MagicMock()
mock_ai_firewall = MagicMock()
mock_fast_path = MagicMock()
mock_rate_limiter = MagicMock()
mock_threat_feed = MagicMock()

sys.modules['requests'] = mock_requests
sys.modules['guardrails.input_filter'] = mock_input_filter
sys.modules['guardrails.output_validator'] = mock_output_validator
sys.modules['guardrails.ai_firewall'] = mock_ai_firewall
sys.modules['guardrails.fast_path'] = mock_fast_path
sys.modules['guardrails.rate_limiter'] = mock_rate_limiter
sys.modules['guardrails.threat_feed'] = mock_threat_feed

from guardian.runtime.interceptor import GuardianProxy

@pytest.fixture
def mock_config():
    return {
        "guardian_id": "test-guardian",
        "proxy": {"listen_port": 8081, "target_url": "http://mock-target"},
        "rate_limiting": {"enabled": True, "requests_per_minute": 60},
        "security_policies": {"security_mode": "balanced", "show_block_reason": True},
        "threat_feed": {"enabled": False},
        "backend": {"enabled": False}
    }

@pytest.fixture
def proxy(mock_config):
    # Create the proxy instance
    # The imports in interceptor.py use our sys.modules mocks
    # But initialization creates instances of the clases from those mocks
    
    # We need to make sure the Classes return our mock instances
    mock_input_filter.InputFilter.return_value = MagicMock()
    mock_output_validator.OutputValidator.return_value = MagicMock()
    mock_ai_firewall.AIPromptFirewall.return_value = MagicMock()
    
    expected_rl_instance = MagicMock()
    expected_rl_instance.is_allowed.return_value = True
    expected_rl_instance.get_pressure.return_value = 0.0
    mock_rate_limiter.RateLimiter.return_value = expected_rl_instance
    
    mock_threat_feed.ThreatFeed.return_value = MagicMock()
    
    p = GuardianProxy(mock_config)
    
    # Double check assignments
    p.rate_limiter = expected_rl_instance
    
    return p

def test_extract_prompt_json_simple(proxy):
    data = {"prompt": "hello"}
    assert proxy._extract_prompt(data) == "hello"

def test_extract_prompt_json_input(proxy):
    data = {"input": "hello"}
    assert proxy._extract_prompt(data) == "hello"

def test_extract_prompt_openai_format(proxy):
    data = {
        "messages": [
            {"role": "system", "content": "you are a bot"},
            {"role": "user", "content": "hello world"}
        ]
    }
    assert proxy._extract_prompt(data) == "hello world"

def test_extract_prompt_empty(proxy):
    assert proxy._extract_prompt({}) is None
    assert proxy._extract_prompt(None) is None

def test_check_rate_limit_allowed(proxy):
    with proxy.app.test_request_context('/'):
        assert proxy._check_rate_limit() is None

def test_check_rate_limit_blocked(proxy):
    proxy.rate_limiter.is_allowed.return_value = False
    with proxy.app.test_request_context('/'):
        resp = proxy._check_rate_limit()
        assert resp is not None
        assert resp.status_code == 429

def test_check_keyword_filter_safe(proxy):
    proxy.input_filter.check_prompt.return_value = True
    assert proxy._check_keyword_filter("safe prompt", 0, {}) is None

def test_check_keyword_filter_blocked(proxy):
    proxy.input_filter.check_prompt.return_value = False
    with proxy.app.test_request_context('/'):
        resp = proxy._check_keyword_filter("bad prompt", 0, {})
        assert resp is not None
        assert resp.status_code == 403
        assert "Forbidden" in resp.get_data(as_text=True)

def test_check_ai_firewall_safe(proxy):
    proxy.ai_firewall.is_malicious.return_value = False
    with proxy.app.test_request_context('/', headers={'X-Conversation-ID': 'test-session'}):
        assert proxy._check_ai_firewall("hello", "balanced", 0, {}) is None

def test_check_ai_firewall_malicious(proxy):
    proxy.ai_firewall.is_malicious.return_value = True
    with proxy.app.test_request_context('/', headers={'X-Conversation-ID': 'test-session'}):
        resp = proxy._check_ai_firewall("attack", "balanced", 0, {})
        assert resp is not None
        assert resp.status_code == 403

def test_process_output_validation_safe(proxy):
    proxy.output_validator.validate_output.return_value = True
    proxy.output_validator.sanitize_output.return_value = ("safe content", [])
    assert proxy._process_output_validation("safe content", "/api", 0, {}) == "safe content"

def test_process_output_validation_leak_block(proxy):
    # Configure to block
    proxy.config['security_policies']['leak_prevention_strategy'] = 'block'
    proxy.output_validator.validate_output.return_value = False
    proxy.output_validator.sanitize_output.return_value = ("redacted", ["PII"])
    
    with pytest.raises(ValueError, match="Data leak blocked"):
        proxy._process_output_validation("secret info", "/api", 0, {})

def test_process_output_validation_leak_redact(proxy):
    # Configure to redact
    proxy.config['security_policies']['leak_prevention_strategy'] = 'redact'
    proxy.output_validator.validate_output.return_value = False # fail validation
    proxy.output_validator.sanitize_output.return_value = ("redacted info", ["PII"])
    
    result = proxy._process_output_validation("secret info", "/api", 0, {})
    assert result == "redacted info"
