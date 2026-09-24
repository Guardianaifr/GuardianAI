"""
Shadow AI Detection Engine

Detects unsanctioned third-party AI API usage per tenant by inspecting
outbound HTTP requests for known AI provider endpoints, AI-specific
headers, and API key patterns.

Capabilities:
  - URL-based detection for 20+ AI providers (OpenAI, Anthropic, Cohere,
    Google AI, Azure OpenAI, AWS Bedrock, Replicate, HuggingFace, Mistral,
    Together AI, Perplexity, Groq, DeepSeek, AI21, Cerebras, etc.)
  - Header-based detection (x-anthropic-version, x-api-key patterns,
    authorization Bearer for AI services, x-goog-api-key)
  - AI endpoint fingerprinting via response patterns
  - Per-tenant alert generation and aggregation
  - Configurable allowlists for sanctioned AI services
"""

from __future__ import annotations

import re
import time
from collections import defaultdict
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple


class AlertSeverity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


@dataclass
class ShadowAIAlert:
    """An alert for detected shadow AI usage."""
    tenant_id: str
    provider: str
    detection_method: str
    severity: AlertSeverity
    url: str
    description: str
    timestamp: float = 0.0
    headers_matched: List[str] = field(default_factory=list)
    metadata: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tenant_id": self.tenant_id,
            "provider": self.provider,
            "detection_method": self.detection_method,
            "severity": self.severity.value,
            "url": self.url,
            "description": self.description,
            "timestamp": self.timestamp,
            "headers_matched": self.headers_matched,
            "metadata": self.metadata,
        }


# ── AI Provider Endpoint Patterns ────────────────────────────────────────────

@dataclass
class AIProviderPattern:
    """Pattern for detecting an AI provider in outbound requests."""
    name: str
    url_patterns: List[re.Pattern[str]]
    header_indicators: List[Tuple[str, re.Pattern[str]]]  # (header_name, value_pattern)
    severity: AlertSeverity = AlertSeverity.CRITICAL


# Compile all patterns once at module load
_PROVIDERS: List[AIProviderPattern] = [
    AIProviderPattern(
        name="OpenAI",
        url_patterns=[re.compile(r"api\.openai\.com", re.I)],
        header_indicators=[
            ("authorization", re.compile(r"Bearer\s+sk-[a-zA-Z0-9]{20,}", re.I)),
            ("openai-organization", re.compile(r"org-[a-zA-Z0-9]+", re.I)),
        ],
    ),
    AIProviderPattern(
        name="Azure OpenAI",
        url_patterns=[
            re.compile(r"[a-z0-9-]+\.openai\.azure\.com", re.I),
            re.compile(r"cognitiveservices\.azure\.com.*openai", re.I),
        ],
        header_indicators=[
            ("api-key", re.compile(r"[a-f0-9]{32}", re.I)),
        ],
    ),
    AIProviderPattern(
        name="Anthropic",
        url_patterns=[re.compile(r"api\.anthropic\.com", re.I)],
        header_indicators=[
            ("x-anthropic-version", re.compile(r"20\d{2}-\d{2}-\d{2}")),
            ("x-api-key", re.compile(r"sk-ant-[a-zA-Z0-9-]+", re.I)),
        ],
    ),
    AIProviderPattern(
        name="Google AI (Gemini)",
        url_patterns=[
            re.compile(r"generativelanguage\.googleapis\.com", re.I),
            re.compile(r"aiplatform\.googleapis\.com", re.I),
        ],
        header_indicators=[
            ("x-goog-api-key", re.compile(r".+", re.I)),
        ],
    ),
    AIProviderPattern(
        name="AWS Bedrock",
        url_patterns=[
            re.compile(r"bedrock-runtime\.[a-z0-9-]+\.amazonaws\.com", re.I),
            re.compile(r"bedrock\.[a-z0-9-]+\.amazonaws\.com", re.I),
        ],
        header_indicators=[],
    ),
    AIProviderPattern(
        name="Cohere",
        url_patterns=[re.compile(r"api\.cohere\.ai", re.I)],
        header_indicators=[
            ("authorization", re.compile(r"Bearer\s+[a-zA-Z0-9]{30,}", re.I)),
        ],
    ),
    AIProviderPattern(
        name="HuggingFace Inference",
        url_patterns=[
            re.compile(r"api-inference\.huggingface\.co", re.I),
            re.compile(r"router\.huggingface\.co", re.I),
            re.compile(r"huggingface\.co/api/models", re.I),
            re.compile(r"[a-z0-9-]+\.hf\.space", re.I),
        ],
        header_indicators=[
            ("authorization", re.compile(r"Bearer\s+hf_[a-zA-Z0-9]+", re.I)),
        ],
    ),
    AIProviderPattern(
        name="Replicate",
        url_patterns=[re.compile(r"api\.replicate\.com", re.I)],
        header_indicators=[
            ("authorization", re.compile(r"Token\s+r8_[a-zA-Z0-9]+", re.I)),
        ],
    ),
    AIProviderPattern(
        name="Mistral AI",
        url_patterns=[re.compile(r"api\.mistral\.ai", re.I)],
        header_indicators=[],
    ),
    AIProviderPattern(
        name="Together AI",
        url_patterns=[
            re.compile(r"api\.together\.(xyz|ai)", re.I),
        ],
        header_indicators=[],
    ),
    AIProviderPattern(
        name="Perplexity",
        url_patterns=[re.compile(r"api\.perplexity\.ai", re.I)],
        header_indicators=[],
    ),
    AIProviderPattern(
        name="Groq",
        url_patterns=[re.compile(r"api\.groq\.com", re.I)],
        header_indicators=[],
    ),
    AIProviderPattern(
        name="DeepSeek",
        url_patterns=[re.compile(r"api\.deepseek\.com", re.I)],
        header_indicators=[
            ("authorization", re.compile(r"Bearer\s+sk-[a-zA-Z0-9]{32,}", re.I)),
        ],
    ),
    AIProviderPattern(
        name="GitHub Models",
        url_patterns=[
            re.compile(r"models\.inference\.ai\.azure\.com", re.I),
            re.compile(r"models\.github\.ai", re.I),
        ],
        header_indicators=[],
    ),
    AIProviderPattern(
        name="OpenRouter",
        url_patterns=[re.compile(r"openrouter\.ai", re.I)],
        header_indicators=[
            ("authorization", re.compile(r"Bearer\s+sk-or-v1-[a-zA-Z0-9]+", re.I)),
        ],
    ),
    AIProviderPattern(
        name="AI21 Labs",
        url_patterns=[re.compile(r"api\.ai21\.com", re.I)],
        header_indicators=[],
    ),
    AIProviderPattern(
        name="Cerebras",
        url_patterns=[re.compile(r"api\.cerebras\.ai", re.I)],
        header_indicators=[],
    ),
    AIProviderPattern(
        name="Fireworks AI",
        url_patterns=[re.compile(r"api\.fireworks\.ai", re.I)],
        header_indicators=[],
    ),
    AIProviderPattern(
        name="Ollama (Remote)",
        url_patterns=[
            re.compile(r".*:11434/(api|v1)/", re.I),
            re.compile(r"ollama\.[a-z0-9-]+\.corp", re.I),
        ],
        header_indicators=[],
        severity=AlertSeverity.WARNING,
    ),
    AIProviderPattern(
        name="xAI (Grok)",
        url_patterns=[re.compile(r"api\.x\.ai", re.I)],
        header_indicators=[
            ("authorization", re.compile(r"Bearer\s+xai-[a-zA-Z0-9]+", re.I)),
        ],
    ),
    AIProviderPattern(
        name="GitHub Copilot",
        url_patterns=[
            re.compile(r"api\.githubcopilot\.com", re.I),
            re.compile(r"copilot-proxy\.githubusercontent\.com", re.I),
        ],
        header_indicators=[
            ("editor-version", re.compile(r".+", re.I)),
        ],
    ),
    AIProviderPattern(
        name="Local AI (vLLM / LM Studio)",
        url_patterns=[
            re.compile(r".*:8000/v1/", re.I),
            re.compile(r".*:1234/v1/", re.I),
            re.compile(r".*:5000/v1/", re.I),
        ],
        header_indicators=[],
        severity=AlertSeverity.WARNING,
    ),
]


class ShadowAIDetector:
    """
    Detects unsanctioned AI API usage per tenant.

    Inspects outbound HTTP request URLs and headers against a database of
    known AI provider patterns. Maintains per-tenant alert history and
    supports allowlisting of sanctioned services.
    """

    def __init__(
        self,
        *,
        allowed_providers: Optional[Set[str]] = None,
        providers: Optional[List[AIProviderPattern]] = None,
    ):
        self._providers = providers or _PROVIDERS
        self._allowed: Set[str] = allowed_providers or set()
        self._alerts: List[ShadowAIAlert] = []
        self._tenant_stats: Dict[str, Dict[str, int]] = defaultdict(
            lambda: defaultdict(int)
        )

    def allow_provider(self, provider_name: str) -> None:
        """Allowlist a provider for all tenants."""
        self._allowed.add(provider_name)

    def inspect_request(
        self,
        tenant_id: str,
        url: str,
        headers: Optional[Dict[str, str]] = None,
        timestamp: Optional[float] = None,
    ) -> List[ShadowAIAlert]:
        """
        Inspect an outbound HTTP request for shadow AI usage.

        Returns list of alerts (empty if request is clean or allowed).
        """
        ts = timestamp or time.time()
        headers = headers or {}
        norm_headers = {str(k).lower(): str(v) for k, v in headers.items() if v is not None}
        alerts: List[ShadowAIAlert] = []

        import urllib.parse
        urls_to_check = [str(url)]
        curr_url = str(url)
        for _ in range(5):
            try:
                nxt_url = urllib.parse.unquote(curr_url)
                if nxt_url == curr_url:
                    break
                if nxt_url not in urls_to_check:
                    urls_to_check.append(nxt_url)
                curr_url = nxt_url
            except Exception:
                break

        for provider in self._providers:
            if provider.name in self._allowed:
                continue

            matched_url = False
            matched_headers: List[str] = []

            # URL pattern matching
            for pattern in provider.url_patterns:
                if any(pattern.search(u) for u in urls_to_check):
                    matched_url = True
                    break

            # Header-based detection
            for header_name, value_pattern in provider.header_indicators:
                header_val = norm_headers.get(header_name.lower(), "")
                if header_val and value_pattern.search(header_val):
                    matched_headers.append(header_name)

            # Disambiguate generic OpenAI header matches when target URL belongs to another specific provider
            if not matched_url and matched_headers and provider.name == "OpenAI":
                other_url_match = any(
                    other.name != "OpenAI" and any(p.search(u) for u in urls_to_check for p in other.url_patterns)
                    for other in self._providers
                )
                if other_url_match:
                    continue

            if matched_url or matched_headers:
                detection_method = []
                if matched_url:
                    detection_method.append("url_match")
                if matched_headers:
                    detection_method.append("header_match")

                alert = ShadowAIAlert(
                    tenant_id=tenant_id,
                    provider=provider.name,
                    detection_method="+".join(detection_method),
                    severity=provider.severity,
                    url=url,
                    description=(
                        f"Tenant '{tenant_id}' made unsanctioned request to "
                        f"{provider.name} AI service."
                    ),
                    timestamp=ts,
                    headers_matched=matched_headers,
                )
                alerts.append(alert)

                # Track stats
                self._tenant_stats[tenant_id][provider.name] += 1

        self._alerts.extend(alerts)
        return alerts

    def get_alerts(
        self,
        tenant_id: Optional[str] = None,
        since: Optional[float] = None,
    ) -> List[ShadowAIAlert]:
        """Retrieve alerts, optionally filtered by tenant and/or time."""
        results = self._alerts
        if tenant_id:
            results = [a for a in results if a.tenant_id == tenant_id]
        if since:
            results = [a for a in results if a.timestamp >= since]
        return results

    def get_tenant_stats(self, tenant_id: str) -> Dict[str, int]:
        """Get per-provider hit counts for a tenant."""
        return dict(self._tenant_stats.get(tenant_id, {}))

    def get_summary(self) -> Dict[str, Any]:
        """Get a summary of all detected shadow AI usage."""
        return {
            "total_alerts": len(self._alerts),
            "tenants_affected": len(self._tenant_stats),
            "providers_detected": sorted(
                {a.provider for a in self._alerts}
            ),
            "per_tenant": {
                tid: dict(stats)
                for tid, stats in self._tenant_stats.items()
            },
        }
