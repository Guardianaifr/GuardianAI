"""
Universal Auth Proxy Mode for GuardianAI.

Provides transparent authentication enforcement for local LLM inference
servers that lack built-in auth (Ollama, LocalAI, vLLM, llama.cpp, etc.).

How it works:
  1. Client sends request to GuardianAI proxy with JWT Bearer token
  2. Proxy validates token + RBAC permissions
  3. If authorized, proxy strips auth header and forwards to backend LLM
  4. LLM response flows back through GuardianAI guardrails
  5. Protected response returned to client

Supported backends:
  - Ollama (default port 11434)
  - LocalAI (default port 8080)
  - vLLM (default port 8000)
  - llama.cpp server (default port 8080)
  - Any OpenAI-compatible API
"""
from __future__ import annotations

import time
import re
import threading
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ---------------------------------------------------------------------------
# Backend Definitions
# ---------------------------------------------------------------------------

@dataclass
class LLMBackend:
    """Defines a local LLM backend that can be proxied."""
    name: str
    default_port: int
    health_path: str
    chat_path: str
    completions_path: str
    api_format: str  # "openai" | "ollama" | "custom"
    auth_required: bool = False  # Does the backend itself need auth?
    model_list_path: str = ""
    supports_streaming: bool = True


SUPPORTED_BACKENDS: Dict[str, LLMBackend] = {
    "ollama": LLMBackend(
        name="Ollama",
        default_port=11434,
        health_path="/",
        chat_path="/api/chat",
        completions_path="/api/generate",
        model_list_path="/api/tags",
        api_format="ollama",
    ),
    "localai": LLMBackend(
        name="LocalAI",
        default_port=8080,
        health_path="/readyz",
        chat_path="/v1/chat/completions",
        completions_path="/v1/completions",
        model_list_path="/v1/models",
        api_format="openai",
    ),
    "vllm": LLMBackend(
        name="vLLM",
        default_port=8000,
        health_path="/health",
        chat_path="/v1/chat/completions",
        completions_path="/v1/completions",
        model_list_path="/v1/models",
        api_format="openai",
    ),
    "llamacpp": LLMBackend(
        name="llama.cpp Server",
        default_port=8080,
        health_path="/health",
        chat_path="/v1/chat/completions",
        completions_path="/completion",
        model_list_path="/v1/models",
        api_format="openai",
    ),
    "openai": LLMBackend(
        name="OpenAI API",
        default_port=443,
        health_path="/v1/models",
        chat_path="/v1/chat/completions",
        completions_path="/v1/completions",
        model_list_path="/v1/models",
        api_format="openai",
        auth_required=True,
    ),
}


# ---------------------------------------------------------------------------
# Auth Proxy Configuration
# ---------------------------------------------------------------------------

@dataclass
class ProxyConfig:
    """Configuration for the auth proxy."""
    backend_type: str = "ollama"
    backend_url: str = ""
    guardian_port: int = 8000
    require_jwt: bool = True
    require_role: str = ""       # Min role required (empty = any authenticated)
    allowed_models: List[str] = field(default_factory=list)  # Empty = all
    rate_limit_rpm: int = 0      # Requests per minute (0 = unlimited)
    strip_auth_header: bool = True  # Remove JWT before forwarding to backend
    inject_system_prompt: str = ""  # Auto-inject system prompt for guardrails
    log_requests: bool = True

    def __post_init__(self):
        if not self.backend_url:
            backend = SUPPORTED_BACKENDS.get(self.backend_type)
            if backend:
                self.backend_url = f"http://localhost:{backend.default_port}"

    @property
    def backend(self) -> LLMBackend:
        return SUPPORTED_BACKENDS.get(self.backend_type, SUPPORTED_BACKENDS["openai"])


# ---------------------------------------------------------------------------
# Request/Response Translation
# ---------------------------------------------------------------------------

@dataclass
class ProxyResult:
    """Result of a proxy operation."""
    allowed: bool
    reason: str
    backend_type: str
    target_url: str
    request_path: str
    auth_user: str = ""
    auth_role: str = ""
    latency_ms: float = 0.0
    model: str = ""


def translate_request(
    path: str,
    body: Dict[str, Any],
    config: ProxyConfig,
) -> Tuple[str, Dict[str, Any]]:
    """Translate an incoming request to the backend's expected format.

    Args:
        path: Incoming request path.
        body: Incoming request body.
        config: Proxy configuration.

    Returns:
        Tuple of (backend_path, translated_body).
    """
    backend = config.backend

    # Map OpenAI-format paths to backend-specific paths
    path_mapping = {
        "/v1/chat/completions": backend.chat_path,
        "/v1/completions": backend.completions_path,
        "/v1/models": backend.model_list_path,
        "/health": backend.health_path,
    }
    target_path = path_mapping.get(path, path)

    # Translate body if backend format differs
    if backend.api_format == "ollama" and "/chat" in target_path:
        # Convert OpenAI format to Ollama format
        translated = {
            "model": body.get("model", "llama3"),
            "messages": body.get("messages", []),
            "stream": body.get("stream", False),
        }
        if "temperature" in body:
            translated["options"] = {"temperature": body["temperature"]}
        return target_path, translated

    # OpenAI-compatible backends: pass through
    return target_path, body


def check_model_allowed(
    model: str,
    allowed_models: List[str],
) -> bool:
    """Check if the requested model is in the allowlist.

    Args:
        model: Requested model name.
        allowed_models: List of allowed model patterns (glob-style).

    Returns:
        True if allowed (empty list = all allowed).
    """
    if not allowed_models:
        return True
    model_lower = model.lower()
    for pattern in allowed_models:
        pattern_lower = pattern.lower()
        if pattern_lower == model_lower:
            return True
        # Simple glob: "llama*" matches "llama3", "llama3:70b", etc.
        if pattern_lower.endswith("*") and model_lower.startswith(pattern_lower[:-1]):
            return True
    return False


def build_proxy_headers(
    original_headers: Dict[str, str],
    config: ProxyConfig,
) -> Dict[str, str]:
    """Build headers to forward to the backend.

    Strips JWT auth header if configured (since the local backend
    doesn't understand JWT tokens).
    """
    forwarded = {}
    for key, value in original_headers.items():
        key_lower = key.lower()
        # Skip hop-by-hop headers
        if key_lower in {"host", "connection", "transfer-encoding"}:
            continue
        # Strip auth header unless backend needs it
        if key_lower == "authorization" and config.strip_auth_header:
            if not config.backend.auth_required:
                continue
        forwarded[key] = value

    # Ensure content-type
    if "Content-Type" not in forwarded and "content-type" not in forwarded:
        forwarded["Content-Type"] = "application/json"

    return forwarded


# ---------------------------------------------------------------------------
# Rate Limiter (Token Bucket)
# ---------------------------------------------------------------------------

class TokenBucketRateLimiter:
    """Simple token bucket rate limiter for per-user rate limiting.

    Thread-safe via a class-level threading.Lock.
    """

    def __init__(self, rpm: int = 60):
        self.rpm = rpm
        self._buckets: Dict[str, List[float]] = {}
        self._lock = threading.Lock()

    def is_allowed(self, key: str) -> bool:
        """Check if a request from this key is allowed.

        Args:
            key: Rate limit key (e.g., user_id or tenant_id).

        Returns:
            True if under the rate limit.
        """
        if self.rpm <= 0:
            return True  # Unlimited

        now = time.time()
        window_start = now - 60  # 1-minute window

        with self._lock:
            if key not in self._buckets:
                self._buckets[key] = []

            # Prune old entries
            self._buckets[key] = [t for t in self._buckets[key] if t > window_start]

            if len(self._buckets[key]) >= self.rpm:
                return False

            self._buckets[key].append(now)
            return True

    def reset(self, key: str) -> None:
        """Reset the rate limit for a key."""
        with self._lock:
            self._buckets.pop(key, None)
