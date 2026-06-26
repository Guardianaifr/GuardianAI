"""
Tests for Universal Auth Proxy.

Covers backend definitions, request translation, model allowlisting,
header stripping, rate limiting, and proxy configuration.
"""
import pytest
import sys
import os
import time

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", "..", "guardian"))

from proxy.auth_proxy import (
    SUPPORTED_BACKENDS,
    LLMBackend,
    ProxyConfig,
    ProxyResult,
    translate_request,
    check_model_allowed,
    build_proxy_headers,
    TokenBucketRateLimiter,
)


# ---------------------------------------------------------------------------
# Test: Backend Definitions
# ---------------------------------------------------------------------------

class TestBackendDefinitions:
    def test_five_backends_defined(self):
        assert len(SUPPORTED_BACKENDS) == 5
        assert set(SUPPORTED_BACKENDS.keys()) == {"ollama", "localai", "vllm", "llamacpp", "openai"}

    def test_ollama_config(self):
        b = SUPPORTED_BACKENDS["ollama"]
        assert b.default_port == 11434
        assert b.api_format == "ollama"
        assert b.chat_path == "/api/chat"

    def test_vllm_config(self):
        b = SUPPORTED_BACKENDS["vllm"]
        assert b.default_port == 8000
        assert b.api_format == "openai"

    def test_openai_requires_auth(self):
        b = SUPPORTED_BACKENDS["openai"]
        assert b.auth_required is True

    def test_all_backends_have_health_path(self):
        for name, b in SUPPORTED_BACKENDS.items():
            assert b.health_path, f"{name} missing health_path"

    def test_all_backends_have_chat_path(self):
        for name, b in SUPPORTED_BACKENDS.items():
            assert b.chat_path, f"{name} missing chat_path"


# ---------------------------------------------------------------------------
# Test: Proxy Configuration
# ---------------------------------------------------------------------------

class TestProxyConfig:
    def test_default_config(self):
        cfg = ProxyConfig()
        assert cfg.backend_type == "ollama"
        assert "11434" in cfg.backend_url
        assert cfg.require_jwt is True

    def test_custom_backend_url(self):
        cfg = ProxyConfig(backend_url="http://gpu-server:8080")
        assert cfg.backend_url == "http://gpu-server:8080"

    def test_auto_url_from_type(self):
        cfg = ProxyConfig(backend_type="vllm")
        assert "8000" in cfg.backend_url

    def test_backend_property(self):
        cfg = ProxyConfig(backend_type="localai")
        assert cfg.backend.name == "LocalAI"

    def test_unknown_backend_defaults_openai(self):
        cfg = ProxyConfig(backend_type="unknown")
        assert cfg.backend.name == "OpenAI API"


# ---------------------------------------------------------------------------
# Test: Request Translation
# ---------------------------------------------------------------------------

class TestRequestTranslation:
    def test_openai_to_ollama(self):
        cfg = ProxyConfig(backend_type="ollama")
        path, body = translate_request(
            "/v1/chat/completions",
            {"model": "llama3", "messages": [{"role": "user", "content": "Hi"}], "temperature": 0.7},
            cfg,
        )
        assert path == "/api/chat"
        assert body["model"] == "llama3"
        assert body["messages"][0]["content"] == "Hi"
        assert body["options"]["temperature"] == 0.7

    def test_openai_passthrough_for_vllm(self):
        cfg = ProxyConfig(backend_type="vllm")
        path, body = translate_request(
            "/v1/chat/completions",
            {"model": "mistral", "messages": [{"role": "user", "content": "Hello"}]},
            cfg,
        )
        assert path == "/v1/chat/completions"
        assert body["model"] == "mistral"

    def test_health_path_mapping(self):
        cfg = ProxyConfig(backend_type="ollama")
        path, body = translate_request("/health", {}, cfg)
        assert path == "/"

    def test_models_path_mapping(self):
        cfg = ProxyConfig(backend_type="ollama")
        path, _ = translate_request("/v1/models", {}, cfg)
        assert path == "/api/tags"


# ---------------------------------------------------------------------------
# Test: Model Allowlisting
# ---------------------------------------------------------------------------

class TestModelAllowlist:
    def test_empty_allows_all(self):
        assert check_model_allowed("anything", []) is True

    def test_exact_match(self):
        assert check_model_allowed("llama3", ["llama3", "mistral"]) is True
        assert check_model_allowed("gpt-4", ["llama3", "mistral"]) is False

    def test_case_insensitive(self):
        assert check_model_allowed("Llama3", ["llama3"]) is True

    def test_glob_pattern(self):
        assert check_model_allowed("llama3:70b", ["llama*"]) is True
        assert check_model_allowed("llama3:7b-chat", ["llama*"]) is True
        assert check_model_allowed("mistral:7b", ["llama*"]) is False

    def test_multiple_patterns(self):
        allowed = ["llama*", "mistral*", "codellama*"]
        assert check_model_allowed("llama3", allowed) is True
        assert check_model_allowed("mistral:7b", allowed) is True
        assert check_model_allowed("gpt-4", allowed) is False


# ---------------------------------------------------------------------------
# Test: Header Handling
# ---------------------------------------------------------------------------

class TestHeaders:
    def test_strips_auth_for_local_backend(self):
        cfg = ProxyConfig(backend_type="ollama", strip_auth_header=True)
        headers = build_proxy_headers(
            {"Authorization": "Bearer jwt_token", "Content-Type": "application/json"},
            cfg,
        )
        assert "Authorization" not in headers
        assert headers["Content-Type"] == "application/json"

    def test_keeps_auth_for_openai(self):
        cfg = ProxyConfig(backend_type="openai", strip_auth_header=True)
        headers = build_proxy_headers(
            {"Authorization": "Bearer sk-xxx"},
            cfg,
        )
        assert "Authorization" in headers

    def test_strips_hop_by_hop(self):
        cfg = ProxyConfig(backend_type="vllm")
        headers = build_proxy_headers(
            {"Host": "example.com", "Connection": "keep-alive", "X-Custom": "value"},
            cfg,
        )
        assert "Host" not in headers
        assert "Connection" not in headers
        assert headers["X-Custom"] == "value"

    def test_adds_content_type_if_missing(self):
        cfg = ProxyConfig(backend_type="vllm")
        headers = build_proxy_headers({}, cfg)
        assert headers["Content-Type"] == "application/json"


# ---------------------------------------------------------------------------
# Test: Rate Limiter
# ---------------------------------------------------------------------------

class TestRateLimiter:
    def test_unlimited(self):
        rl = TokenBucketRateLimiter(rpm=0)
        for _ in range(1000):
            assert rl.is_allowed("user1") is True

    def test_limit_enforced(self):
        rl = TokenBucketRateLimiter(rpm=5)
        for _ in range(5):
            assert rl.is_allowed("user1") is True
        assert rl.is_allowed("user1") is False

    def test_per_user_isolation(self):
        rl = TokenBucketRateLimiter(rpm=3)
        for _ in range(3):
            rl.is_allowed("user_a")
        assert rl.is_allowed("user_a") is False
        assert rl.is_allowed("user_b") is True  # Different user

    def test_reset(self):
        rl = TokenBucketRateLimiter(rpm=2)
        rl.is_allowed("u1")
        rl.is_allowed("u1")
        assert rl.is_allowed("u1") is False
        rl.reset("u1")
        assert rl.is_allowed("u1") is True
