import pytest
from unittest.mock import MagicMock, patch
import sys
from flask import Flask, Response, request
import json

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
    # We patch sys.modules only during the creation of GuardianProxy
    with patch('guardian.guardrails.input_filter.InputFilter') as MockIF, \
         patch('guardian.guardrails.output_validator.OutputValidator') as MockOV, \
         patch('guardian.guardrails.ai_firewall.AIPromptFirewall') as MockAF, \
         patch('guardian.guardrails.fast_path.FastPath') as MockFP, \
         patch('guardian.guardrails.rate_limiter.RateLimiter') as MockRL, \
         patch('guardian.guardrails.threat_feed.ThreatFeed') as MockTF, \
         patch('requests.post') as MockPost:

        # Configure instances
        mock_rl_instance = MockRL.return_value
        mock_rl_instance.is_allowed.return_value = True
        mock_rl_instance.get_pressure.return_value = 0.0

        p = GuardianProxy(mock_config)
        
        # Attach mocks to proxy for test access
        p.input_filter = MockIF.return_value
        p.output_validator = MockOV.return_value
        p.ai_firewall = MockAF.return_value
        p.rate_limiter = mock_rl_instance
        p.threat_feed = MockTF.return_value
        
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
