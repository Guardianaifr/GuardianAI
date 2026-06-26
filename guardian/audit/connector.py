"""
Target API Connector for GuardianAI Audit.

Handles connecting to any AI endpoint (OpenAI-compatible, raw HTTP, etc.),
sending prompts, and capturing responses with timing data.
"""

from __future__ import annotations

import json
import logging
import time
from typing import Any, Dict, Optional, Tuple

import requests

from guardian.audit.models import TargetConfig

logger = logging.getLogger("guardian.audit.connector")


class ConnectorError(Exception):
    """Raised when the target cannot be reached or returns unexpected errors."""


class TargetConnector:
    """
    Sends prompts to an AI API endpoint and captures responses.

    Supports:
      - OpenAI-compatible chat completions API
      - Raw HTTP POST with custom request/response mapping
    """

    def __init__(self, config: TargetConfig):
        self.config = config
        self._session = requests.Session()
        self._session.headers.update(self._build_auth_headers())
        self._last_request_time: float = 0.0

    def _build_auth_headers(self) -> Dict[str, str]:
        headers: Dict[str, str] = {"Content-Type": "application/json"}
        cfg = self.config

        if cfg.auth_type == "bearer" and cfg.api_key:
            headers[cfg.auth_header] = f"Bearer {cfg.api_key}"
        elif cfg.auth_type == "api-key-header" and cfg.api_key:
            headers[cfg.auth_header] = cfg.api_key
        elif cfg.auth_type == "basic" and cfg.api_key:
            import base64
            encoded = base64.b64encode(cfg.api_key.encode("utf-8")).decode("ascii")
            headers["Authorization"] = f"Basic {encoded}"
        # auth_type == "none" → no auth headers

        return headers

    def health_check(self) -> Tuple[bool, float, str]:
        """
        Verify the target endpoint is reachable with a simple prompt.
        Returns (is_healthy, latency_ms, message).
        """
        try:
            start = time.perf_counter()
            resp_text = self.send_prompt("Say 'OK' and nothing else.")
            elapsed = (time.perf_counter() - start) * 1000

            if resp_text and len(resp_text.strip()) > 0:
                return True, round(elapsed, 1), f"Target healthy — {elapsed:.0f}ms baseline latency"
            return False, round(elapsed, 1), "Target returned empty response"

        except Exception as exc:
            return False, 0.0, f"Health check failed: {exc}"

    def send_prompt(self, prompt: str) -> str:
        """
        Send a prompt to the target AI endpoint and return the response text.
        Automatically rate-limits requests.
        """
        self._enforce_rate_limit()

        cfg = self.config

        # Build the request body — OpenAI-compatible by default
        if cfg.request_template:
            body = json.loads(json.dumps(cfg.request_template))  # deep copy
            body = self._inject_prompt(body, prompt)
        else:
            body = {
                "model": cfg.model or "gpt-4o",
                "messages": [{"role": "user", "content": prompt}],
                "max_tokens": cfg.max_tokens,
                "temperature": cfg.temperature,
            }

        try:
            resp = self._session.post(
                cfg.endpoint_url,
                json=body,
                timeout=cfg.timeout_sec,
            )
        except requests.Timeout:
            raise ConnectorError(f"Request timed out after {cfg.timeout_sec}s")
        except requests.ConnectionError as exc:
            raise ConnectorError(f"Connection failed: {exc}")

        if resp.status_code == 429:
            raise ConnectorError("Rate limited by target — backing off")
        if resp.status_code == 401:
            raise ConnectorError("Authentication failed — check API key")
        if resp.status_code == 403:
            raise ConnectorError("Forbidden — insufficient permissions")

        if resp.status_code >= 400:
            raise ConnectorError(
                f"Target returned HTTP {resp.status_code}: {resp.text[:200]}"
            )

        return self._extract_response_text(resp.json())

    def send_prompt_timed(self, prompt: str) -> Tuple[str, float]:
        """
        Send a prompt and return (response_text, elapsed_ms).
        """
        start = time.perf_counter()
        try:
            text = self.send_prompt(prompt)
            elapsed = (time.perf_counter() - start) * 1000
            return text, round(elapsed, 2)
        except ConnectorError:
            elapsed = (time.perf_counter() - start) * 1000
            raise

    def _extract_response_text(self, response_json: Dict[str, Any]) -> str:
        """
        Extract the text content from an API response.
        Supports OpenAI format and common alternatives.
        """
        # OpenAI format: choices[0].message.content
        choices = response_json.get("choices")
        if choices and isinstance(choices, list) and len(choices) > 0:
            message = choices[0].get("message", {})
            content = message.get("content", "")
            if content:
                return content.strip()

            # Some APIs use choices[0].text
            text = choices[0].get("text", "")
            if text:
                return text.strip()

        # Anthropic format: content[0].text
        content_list = response_json.get("content")
        if content_list and isinstance(content_list, list):
            for block in content_list:
                if isinstance(block, dict) and block.get("type") == "text":
                    return block.get("text", "").strip()

        # Fallback — try common keys
        for key in ("response", "text", "output", "result", "answer", "generated_text"):
            val = response_json.get(key)
            if isinstance(val, str) and val.strip():
                return val.strip()

        # Last resort — dump the full response
        return json.dumps(response_json, indent=2)[:2000]

    def _inject_prompt(self, template: Dict[str, Any], prompt: str) -> Dict[str, Any]:
        """Replace {{PROMPT}} placeholder in a custom request template."""
        raw = json.dumps(template)
        raw = raw.replace("{{PROMPT}}", prompt.replace('"', '\\"'))
        return json.loads(raw)

    def _enforce_rate_limit(self) -> None:
        """Sleep if needed to respect the configured rate limit."""
        if self.config.rate_limit_rps <= 0:
            return
        min_interval = 1.0 / self.config.rate_limit_rps
        elapsed = time.time() - self._last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_time = time.time()

    def close(self) -> None:
        self._session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
