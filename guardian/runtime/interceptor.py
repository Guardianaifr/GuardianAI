from flask import Flask, request, Response, has_request_context
import requests
import threading
import logging
import time
import re
import collections
import hashlib
import secrets
import json
import os
from pathlib import Path
from typing import Dict, Any, List, Optional
from guardrails.input_filter import InputFilter
from guardrails.output_validator import OutputValidator
from guardrails.ai_firewall import AIPromptFirewall
from guardrails.fast_path import FastPath
from guardrails.rate_limiter import RateLimiter
from guardrails.threat_feed import ThreatFeed
from guardrails.base64_detector import Base64Detector
from guardrails.tool_policy import ToolPolicyEngine
from guardrails.honeypot import HoneypotManager, AttackerProfiler, HoneypotAnalytics
from brain.orchestrator import CyberBrain
from security.cost_abuse import CostAbuseDetector
from security.tenant_isolation import TenantIsolationManager
from security.agentic_controls import AgenticSecurityManager
from security.rag_guard import RAGSecurityGuard
from security.multimodal_guard import MultimodalSecurityGuard
from security.tenant_sensitivity import TenantSensitivityManager
from security.feedback_loop import FeedbackLoopManager
from security.memory_guard import MemoryPoisoningGuard
from security.output_assurance import OutputAssuranceGuard
from security.output_watermark import OutputWatermarker
from guardrails.system_prompt_guard import SystemPromptGuard
from security.trust_exploitation import TrustExploitationGuard
from security.jailbreak_fuzzer import AutomatedJailbreakFuzzer
from backend.siem import SiemRouter, SiemConfig
"""
GuardianProxy - Core HTTP Interceptor and Security Router

This module implements the primary entry point for GuardianAI. It acts as a 
reverse proxy that intercepts LLM requests, applies multiple layers of 
security (Input Filter, AI Firewall, Rate Limiting), and validates 
downstream agent outputs for PII leaks.
"""
logger = logging.getLogger("GuardianAI")

class GuardianProxy:
    """
    The main GuardianAI proxy application.

    This class encapsulates the Flask application and orchestrates the
    various guardrail components to protect against prompt injection
    and data leakage.

    Attributes:
        app (Flask): The internal Flask application instance.
        input_filter (InputFilter): Keyword-based injection blocker.
        ai_firewall (AIPromptFirewall): Semantic similarity detector.
        output_validator (OutputValidator): PII detection and redaction engine.
        rate_limiter (RateLimiter): Per-IP request flow control.
        threat_feed (ThreatFeed): Community pattern synchronization service.
    """
    def __init__(self, config: Dict[str, Any]):
        """
        Initializes the GuardianProxy with global configuration and wires up
        all security guardrails.

        Args:
            config (dict): The global application configuration.
        """
        self.config = config
        proxy_config = config.get('proxy', {})
        self.port = proxy_config.get('listen_port', 8080)
        self.target_url = proxy_config.get('target_url', "http://localhost:18789")
        
        self.app = Flask(__name__)
        # ProxyFix: trust exactly `trusted_proxy_hops` upstream proxy hops.
        # Prevents X-Forwarded-For spoofing for rate-limit bypass / audit falsification.
        # (audit finding #4, eb180c04)
        from werkzeug.middleware.proxy_fix import ProxyFix
        _hops = int(config.get("proxy", {}).get("trusted_proxy_hops", 1))
        self.app.wsgi_app = ProxyFix(self.app.wsgi_app, x_for=_hops, x_proto=_hops, x_host=_hops)
        self.input_filter = InputFilter()
        self.output_validator = OutputValidator()
        self.ai_firewall = AIPromptFirewall()
        self.fast_path = FastPath()
        self.base64_detector = Base64Detector()
        self.tool_policy = ToolPolicyEngine(config.get("tool_policy", {}))
        self.honeypot = HoneypotManager(config.get("honeypot", {}))
        # FEAT-HONEY-PROFILE: TTP profiling and analytics for honeypot sessions
        self.attacker_profiler = AttackerProfiler()
        self.honeypot_analytics = HoneypotAnalytics()
        self.filesystem_sandbox = None

        
        # Rate Limiting
        rl_config = config.get('rate_limiting', {})
        redis_client = self._build_redis_client(rl_config)
        self.rate_limiter = RateLimiter(
            requests_per_minute=rl_config.get('requests_per_minute', 60),
            redis_client=redis_client,
            redis_prefix=rl_config.get('redis_prefix', 'guardian:ratelimit'),
        )
        
        # Threat Feed
        tf_config = config.get('threat_feed', {})
        cb_config = tf_config.get('circuit_breaker', {})
        self.threat_feed = ThreatFeed(
            feed_url=tf_config.get('url') if tf_config.get('enabled') else None,
            update_interval=tf_config.get('update_interval_seconds', 3600),
            additional_feeds=tf_config.get('additional_feeds', []),
            api_key=tf_config.get('api_key') or os.environ.get('GUARDIAN_THREAT_FEED_KEY', '') or None,
            hmac_secret=tf_config.get('hmac_secret') or os.environ.get('GUARDIAN_FEED_HMAC_SECRET', '') or None,
            circuit_breaker_max_failures=cb_config.get('max_failures', 3),
            circuit_breaker_cooldown=cb_config.get('cooldown_seconds', 300),
            live_apis_config=tf_config.get('live_apis', {}),
            default_ttl_days=tf_config.get('default_ttl_days'),
        )

        self.cost_abuse = CostAbuseDetector(config.get("cost_abuse", {}))
        self.tenant_isolation = TenantIsolationManager(
            config.get("tenant_isolation", {}),
            Path(__file__).resolve().parent.parent,
        )
        self.agentic_security = AgenticSecurityManager(
            config.get("agentic_security", {}),
            Path(__file__).resolve().parent.parent,
        )

        self.rag_security = RAGSecurityGuard(config.get("rag_security", {}))
        self.multimodal_security = MultimodalSecurityGuard(config.get("multimodal_security", {}))
        self.tenant_sensitivity = TenantSensitivityManager(config.get("tenant_sensitivity", {}))
        self.feedback_loop = FeedbackLoopManager(
            config.get("feedback_loop", {}),
            Path(__file__).resolve().parent.parent,
        )
        self.memory_security = MemoryPoisoningGuard(config.get("memory_security", {}))
        self.output_assurance = OutputAssuranceGuard(config.get("output_assurance", {}))
        self.output_watermarker = OutputWatermarker(config.get("output_watermark", {}))
        self.system_prompt_guard = SystemPromptGuard(config.get("system_prompt_protection", {}))
        self.trust_exploitation = TrustExploitationGuard(config.get("trust_exploitation", {}), Path(__file__).resolve().parent.parent)
        self.jailbreak_fuzzer = AutomatedJailbreakFuzzer(
            config.get("jailbreak_fuzzer", {}),
            Path(__file__).resolve().parent.parent,
            detector=lambda prompt: bool(self.input_filter.is_malicious(prompt) or self.ai_firewall.is_malicious(prompt, mode="strict") or self.threat_feed.match(prompt)),
            threat_feed=self.threat_feed,
        )
        self.brain = CyberBrain(config, Path(__file__).resolve().parent.parent, self.input_filter, self.ai_firewall, threat_feed=self.threat_feed)
        
        # Upstream LLM Health Cache
        self._last_health_check_time = 0.0
        self._last_health_check_status = 200

        # Admin token for authenticated endpoints — fail-closed: refuse to start if absent or weak.
        # (audit finding #7, eb180c04)
        _admin_token = config.get("security_policies", {}).get("admin_token", "")
        _KNOWN_WEAK = {"***REDACTED***", "admin", "secret", "password", ""}
        if not _admin_token or _admin_token in _KNOWN_WEAK:
            raise ValueError(
                "SECURITY: security_policies.admin_token is absent or set to a known-weak value. "
                "Set a strong random token (e.g. secrets.token_hex(32)) before starting GuardianProxy."
            )
        self.admin_token = _admin_token

        # SIEM Integration
        siem_cfg = config.get("siem", {})
        self.siem_config = SiemConfig(
            enabled=bool(siem_cfg.get("enabled", False)),
            out_path=str(siem_cfg.get("out_path", "artifacts/evidence/siem_alerts.log")),
            format=str(siem_cfg.get("format", "json")),
            transport=str(siem_cfg.get("transport", "file")),
            endpoint_url=str(siem_cfg.get("endpoint_url", "")),
            endpoint_auth_token=str(siem_cfg.get("endpoint_auth_token", "")),
        )
        self.siem_router = SiemRouter(self.siem_config)
        if self.siem_config.enabled:
            self.siem_router.start()

        # Multi-turn Context Buffer (per IP/Session)
        self.context_buffer = collections.defaultdict(lambda: collections.deque(maxlen=5))
        
        # Register routes
        self.app.add_url_rule('/health', view_func=self.health_check, methods=['GET'])
        self.app.add_url_rule('/api/reload-model', view_func=self.reload_model, methods=['POST'])
        # Threat Feed admin endpoints
        self.app.add_url_rule('/api/threat-feed/status', view_func=self.threat_feed_status, methods=['GET'])
        self.app.add_url_rule('/api/threat-feed/refresh', view_func=self.threat_feed_refresh, methods=['POST'])
        self.app.add_url_rule('/api/threat-feed/add-pattern', view_func=self.threat_feed_add_pattern, methods=['POST'])
        self.app.add_url_rule('/api/threat-feed/remove-pattern', view_func=self.threat_feed_remove_pattern, methods=['POST'])
        self.app.add_url_rule('/api/threat-feed/webhook', view_func=self.threat_feed_webhook, methods=['POST'])
        self.app.add_url_rule('/api/threat-feed/test', view_func=self.threat_feed_test, methods=['POST'])
        self.app.add_url_rule('/api/threat-feed/export', view_func=self.threat_feed_export, methods=['GET'])
        self.app.add_url_rule('/api/threat-feed/metrics', view_func=self.threat_feed_metrics, methods=['GET'])
        # Compliance evidence export (admin-only)
        self.app.add_url_rule('/api/compliance/evidence', view_func=self.compliance_evidence, methods=['GET'])
        # Honeypot TTP profile admin endpoints (admin-only)
        self.app.add_url_rule('/api/admin/honeypot/profiles', view_func=self.honeypot_profiles, methods=['GET'])
        self.app.add_url_rule('/api/admin/honeypot/analytics', view_func=self.honeypot_analytics_view, methods=['GET'])
        

        self.app.add_url_rule('/', defaults={'path': ''}, view_func=self.proxy, methods=['GET', 'POST', 'PUT', 'DELETE'])
        self.app.add_url_rule('/<path:path>', view_func=self.proxy, methods=['GET', 'POST', 'PUT', 'DELETE'])

        @self.app.after_request
        def _strip_version_headers(response):
            for header in ['Server', 'X-Powered-By', 'Via']:
                response.headers.pop(header, None)
            return response

        self._thread = None
        self.last_debug_info = {}
        self._input_filter_cache = collections.OrderedDict()
        self._input_filter_cache_size = 2000

    def _build_redis_client(self, rl_config: Dict[str, Any]):
        """Build optional Redis client for distributed rate limiting."""
        redis_url = rl_config.get("redis_url") or os.environ.get("GUARDIAN_REDIS_URL", "").strip()
        if not redis_url:
            return None
        try:
            import redis  # type: ignore

            client = redis.Redis.from_url(
                redis_url,
                socket_timeout=1,
                socket_connect_timeout=1,
                decode_responses=True,
            )
            client.ping()
            logger.info("Distributed rate limiting enabled via Redis.")
            return client
        except Exception as e:
            logger.warning(f"Redis unavailable for distributed rate limiting. Falling back to in-memory buckets. Error: {e}")
            return None

    def health_check(self):
        from guardian.guardrails.output_validator import PRESIDIO_AVAILABLE, DEGRADED_PII
        status = "ok"
        warnings = []
        if not PRESIDIO_AVAILABLE:
            warnings.append(f"PII detection degraded to regex-only: {DEGRADED_PII}")
        
        return {
            "status": "degraded" if warnings else "ok",
            "component": "guardian_proxy",
            "warnings": warnings
        }

    def reload_model(self):
        """Endpoint to hot-reload the AI model and jailbreak vectors."""
        logger.info("RELOAD REQUEST: Hot-reloading AI firewall...")
        try:
            self.ai_firewall.reload()
            return Response("Success: AI Firewall hot-reloaded.", status=200)
        except Exception as e:
            logger.error(f"Hot-reload failed: {e}")
            return Response(f"Error: {e}", status=500)

    # ──────────────────────────────────────────────────────────────────────────
    # Threat Feed Admin REST Endpoints
    # ──────────────────────────────────────────────────────────────────────────

    def _check_admin_auth(self) -> Optional[Response]:
        """Verify admin Bearer token. Returns error Response or None if valid."""
        from flask import request as flask_request
        auth = flask_request.headers.get("Authorization", "")
        if not auth.startswith("Bearer ") or auth[7:].strip() != self.admin_token:
            return Response(
                json.dumps({"error": "Unauthorized — provide admin Bearer token"}),
                status=401,
                mimetype="application/json",
            )
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # Compliance Evidence Admin Endpoint
    # ──────────────────────────────────────────────────────────────────────────

    def compliance_evidence(self):
        """GET /api/compliance/evidence — Build and return a signed compliance bundle.

        Admin-only (requires Authorization: Bearer <admin_token>).  Calls
        build_evidence_bundle() from security/evidence_export.py and returns
        the HMAC-signed JSON payload.

        Note: This endpoint produces an on-demand snapshot of system state.
        The separate per-event JSONL audit logs (purple governance decisions,
        trust exploitation review queue) are distinct streams and are NOT
        consolidated into this bundle.
        """
        auth_err = self._check_admin_auth()
        if auth_err:
            return auth_err
        try:
            from security.evidence_export import build_evidence_bundle, sign_evidence_payload, resolve_signing_key_material
            import sys
            import dataclasses
            from pathlib import Path
            bundle = build_evidence_bundle(root=Path(self.config.get("base_dir", ".")), python_exe=sys.executable)
            bundle_dict = dataclasses.asdict(bundle)
            
            key, key_id = resolve_signing_key_material()
            if not key:
                logger.error("[ComplianceEvidence] No signing key available for evidence export.")
                return Response(json.dumps({"error": "No signing key configured"}), status=500, mimetype="application/json")
                
            sig = sign_evidence_payload(bundle_dict, key)
            payload = {
                "payload": bundle_dict,
                "signature": sig,
                "key_id": key_id
            }
            
            return Response(
                json.dumps(payload, default=str),
                status=200,
                mimetype="application/json",
            )
        except Exception as e:
            logger.error(f"[ComplianceEvidence] Failed to build evidence bundle: {e}")
            return Response(
                json.dumps({"error": "Failed to generate evidence bundle", "detail": str(e)}),
                status=500,
                mimetype="application/json",
            )


    # ──────────────────────────────────────────────────────────────────────────
    # Honeypot TTP Admin Endpoints (FEAT-HONEY-PROFILE)
    # ──────────────────────────────────────────────────────────────────────────

    def honeypot_profiles(self):
        """GET /api/admin/honeypot/profiles — Return collected attacker TTP profiles.

        Admin-only (requires Authorization: Bearer <admin_token>). Returns all
        honeypot-session profiles harvested by AttackerProfiler, including prompts
        (capped at 50 per session), IPs, user-agents, and interaction counts.
        """
        auth_err = self._check_admin_auth()
        if auth_err:
            return auth_err
        sessions = self.attacker_profiler.get_all_sessions()
        profiles = {sid: self.attacker_profiler.get_profile(sid) for sid in sessions}
        return Response(
            json.dumps({
                "total_sessions": self.attacker_profiler.count(),
                "profiles": profiles,
            }, default=str),
            status=200,
            mimetype="application/json",
        )

    def honeypot_analytics_view(self):
        """GET /api/admin/honeypot/analytics — Return aggregate honeypot interaction metrics.

        Admin-only (requires Authorization: Bearer <admin_token>). Returns total
        interaction count, top attacking sessions, and top targeted paths.
        """
        auth_err = self._check_admin_auth()
        if auth_err:
            return auth_err
        return Response(
            json.dumps({
                "total_interactions": self.honeypot_analytics.total,
                "top_sessions": self.honeypot_analytics.top_sessions(n=20),
                "top_paths": self.honeypot_analytics.top_paths(n=20),
            }),
            status=200,
            mimetype="application/json",
        )


    def threat_feed_status(self):
        """GET /api/threat-feed/status — Returns full feed status and metrics."""
        auth_err = self._check_admin_auth()
        if auth_err:
            return auth_err
        status = self.threat_feed.status()
        return Response(json.dumps(status, default=str), status=200, mimetype="application/json")

    def threat_feed_refresh(self):
        """POST /api/threat-feed/refresh — Force immediate feed sync."""
        auth_err = self._check_admin_auth()
        if auth_err:
            return auth_err
        try:
            self.threat_feed.refresh_now()
            return Response(
                json.dumps({"status": "ok", "pattern_count": len(self.threat_feed.patterns)}),
                status=200,
                mimetype="application/json",
            )
        except Exception as e:
            return Response(json.dumps({"error": str(e)}), status=500, mimetype="application/json")

    def threat_feed_add_pattern(self):
        """POST /api/threat-feed/add-pattern — Hot-add a pattern at runtime.
        Body: {"pattern": "...", "severity": "high", "category": "...", "ttl_days": 7}
        """
        auth_err = self._check_admin_auth()
        if auth_err:
            return auth_err
        from flask import request as flask_request
        data = flask_request.get_json(force=True, silent=True) or {}
        pattern = data.get("pattern", "").strip()
        if not pattern:
            return Response(
                json.dumps({"error": "Missing 'pattern' field"}),
                status=400,
                mimetype="application/json",
            )
        added = self.threat_feed.add_pattern(
            pattern=pattern,
            severity=data.get("severity", "medium"),
            category=data.get("category", "admin"),
            source="admin_api",
            ttl_days=data.get("ttl_days"),
        )
        if added:
            return Response(
                json.dumps({"status": "added", "pattern": pattern, "pattern_count": len(self.threat_feed.patterns)}),
                status=201,
                mimetype="application/json",
            )
        return Response(
            json.dumps({"status": "rejected", "reason": "Duplicate or unsafe regex"}),
            status=409,
            mimetype="application/json",
        )

    def threat_feed_remove_pattern(self):
        """POST /api/threat-feed/remove-pattern — Remove a pattern.
        Body: {"pattern": "..."}
        """
        auth_err = self._check_admin_auth()
        if auth_err:
            return auth_err
        from flask import request as flask_request
        data = flask_request.get_json(force=True, silent=True) or {}
        pattern = data.get("pattern", "").strip()
        if not pattern:
            return Response(json.dumps({"error": "Missing 'pattern' field"}), status=400, mimetype="application/json")
        removed = self.threat_feed.remove_pattern(pattern)
        if removed:
            return Response(
                json.dumps({"status": "removed", "pattern": pattern}),
                status=200,
                mimetype="application/json",
            )
        return Response(
            json.dumps({"status": "not_found", "pattern": pattern}),
            status=404,
            mimetype="application/json",
        )

    def threat_feed_webhook(self):
        """POST /api/threat-feed/webhook — Accept patterns from external SIEM/SOAR.
        Body: {"patterns": [...], "source": "splunk", "ttl_days": 7}
        Optional header: X-Webhook-Signature: sha256=<hmac_hex> for verification.
        """
        auth_err = self._check_admin_auth()
        if auth_err:
            return auth_err
        from flask import request as flask_request
        data = flask_request.get_json(force=True, silent=True) or {}
        if not data.get("patterns"):
            return Response(
                json.dumps({"error": "Missing 'patterns' array"}),
                status=400,
                mimetype="application/json",
            )
        # Optional HMAC verification on webhook payload
        if self.threat_feed.hmac_secret:
            sig = flask_request.headers.get("X-Webhook-Signature", "")
            raw_body = flask_request.get_data(as_text=True)
            if not self.threat_feed._verify_hmac(raw_body, sig):
                return Response(
                    json.dumps({"error": "Webhook HMAC signature mismatch"}),
                    status=403,
                    mimetype="application/json",
                )
        result = self.threat_feed.ingest_webhook(data)
        return Response(json.dumps(result), status=200, mimetype="application/json")

    def threat_feed_test(self):
        """POST /api/threat-feed/test — Dry-run test a prompt against patterns.
        Body: {"prompt": "test text here"}
        Does NOT increment match counters or block — purely diagnostic.
        """
        auth_err = self._check_admin_auth()
        if auth_err:
            return auth_err
        from flask import request as flask_request
        data = flask_request.get_json(force=True, silent=True) or {}
        prompt = data.get("prompt", "").strip()
        if not prompt:
            return Response(
                json.dumps({"error": "Missing 'prompt' field"}),
                status=400,
                mimetype="application/json",
            )
        result = self.threat_feed.test_prompt(prompt)
        return Response(json.dumps(result, default=str), status=200, mimetype="application/json")

    def threat_feed_export(self):
        """GET /api/threat-feed/export — Export current feed as YAML for backup/compliance."""
        auth_err = self._check_admin_auth()
        if auth_err:
            return auth_err
        yaml_content = self.threat_feed.export_yaml()
        return Response(
            yaml_content,
            status=200,
            mimetype="text/yaml",
            headers={"Content-Disposition": "attachment; filename=threat_feed_export.yaml"},
        )

    def threat_feed_metrics(self):
        """GET /api/threat-feed/metrics — Prometheus text exposition format."""
        # Auth required by default (audit finding #6, eb180c04).
        # Set proxy.metrics_public: true to allow unauthenticated Prometheus scraping
        # ONLY if this endpoint is not reachable externally (e.g. behind a scrape-network firewall).
        if not self.config.get("proxy", {}).get("metrics_public", False):
            auth_err = self._check_admin_auth()
            if auth_err:
                return auth_err
        metrics = self.threat_feed.prometheus_metrics()
        return Response(metrics, status=200, mimetype="text/plain; version=0.0.4; charset=utf-8")

    # DEBUGGING STATE
    # DEBUGGING STATE


    def _update_debug_info(self, info: Dict):
        self.last_debug_info = info

    def debug_info(self):
        # P2-16: Feature-flag off in production
        if os.getenv("GUARDIAN_ENV") != "development":
            return Response("Forbidden: Debug route disabled in production.", status=403)

        """Admin-only debug endpoint.

        SECURITY: requires admin Bearer token (same gate as /api/reload-model and
        /api/threat-feed/metrics).  last_debug_info contains the full headers of the
        most recently proxied request, including X-Guardian-Token, Authorization, and
        any X-Api-Key values sent by clients — credential disclosure if left open.
        Confirmed live via _debug_info_probe.py (2026-07-15).
        """
        auth_err = self._check_admin_auth()
        if auth_err:
            return auth_err
        return Response(json.dumps(self.last_debug_info, default=str), mimetype='application/json')

    def start(self):
        """
        Starts the GuardianAI proxy server in a background daemon thread.
        This allows the main thread to remain responsive or monitor the proxy.
        """
        if self._thread is not None:
            return
        logger.info(f"Starting Interceptor Proxy on port {self.port} -> {self.target_url}")
        self.brain.start()
        self.jailbreak_fuzzer.start()
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()

    def stop(self):
        self.jailbreak_fuzzer.stop()
        self.brain.stop()

    def _run_server(self):
        """
        Internal method to run the Flask development server.
        """
        try:
            # Default to loopback — operators must explicitly set GUARDIAN_PROXY_HOST=0.0.0.0
            # to bind on all interfaces. (audit finding #3, eb180c04)
            host = os.environ.get("GUARDIAN_PROXY_HOST", "127.0.0.1").strip() or "127.0.0.1"
            logger.info(f"Proxy application starting on {host}:{self.port}...")
            # DEBUG ROUTE — admin-only (requires Authorization: Bearer <admin_token>).
            # See debug_info() docstring for why this must be gated.
            self.app.add_url_rule('/debug/info', view_func=self.debug_info, methods=['GET'])
            wsgi_server = os.environ.get("GUARDIAN_WSGI_SERVER", "waitress").strip().lower()
            if wsgi_server == "waitress":
                try:
                    from waitress import serve

                    threads = int(os.environ.get("GUARDIAN_WSGI_THREADS", "32").strip() or "32")
                    logger.info(f"Using waitress WSGI server (threads={threads}).")
                    serve(self.app, host=host, port=self.port, threads=threads, clear_untrusted_proxy_headers=False, ident=None)
                    return
                except Exception as e:
                    logger.warning(f"Waitress unavailable, falling back to Flask dev server. Error: {e}")

            # Fallback path for local debugging.
            import sys

            try:
                cli = sys.modules['flask.cli']
                cli.show_server_banner = lambda *x: None
            except (KeyError, AttributeError) as e:
                logger.debug(f"Could not disable Flask banner: {e}")
            logger.warning("Using Flask dev server fallback. Set GUARDIAN_WSGI_SERVER=waitress for production.")
            self.app.run(host=host, port=self.port, debug=False, use_reloader=False)
        except Exception as e:
            logger.error(f"FLASK CRASH: {e}")
            import traceback
            logger.error(traceback.format_exc())

    # ============================================================================
    # HELPER METHODS - Extracted from proxy() for better maintainability
    # ============================================================================
    
    def _check_rate_limit(self, start_time: Optional[float] = None, path: str = "") -> Optional[Response]:
        """Check if request should be rate limited.
        
        Returns:
            Response object if rate limited, None otherwise
        """
        if start_time is None:
            start_time = time.time()

        if not self.config.get('rate_limiting', {}).get('enabled'):
            return None
        
        client_ip = self._get_client_ip()
        if not self.rate_limiter.is_allowed(client_ip):
            logger.warning(f"Rate limit exceeded for {client_ip}")
            latency_ms = (time.time() - start_time) * 1000
            self._report_event("rate_limit", "HIGH", {
                "reason": "Rate limit exceeded.",
                "path": "rate_limit",
                "target_path": path,
                "ip": client_ip,
                "latency_ms": f"{latency_ms:.2f}ms",
            })
            return Response("Too Many Requests: Rate limit exceeded.", status=429)
        
        return None

    @staticmethod
    def _normalize_ip(addr: str) -> str:
        """Normalize IPv6 loopback and IPv4-mapped IPv6 addresses to IPv4.

        Handles the two cases identified in audit finding #4 (eb180c04):
          * ::1 / 0:0:0:0:0:0:0:1  (IPv6 loopback)  -> 127.0.0.1
          * ::ffff:a.b.c.d          (RFC 4291 mapped)  -> a.b.c.d

        All other addresses are returned unchanged.  No external library is
        required; re is already imported at module level.
        """
        if not addr or addr in ("unknown", ""):
            return addr
        # IPv6 loopback — short and full forms
        if addr in ("::1", "0:0:0:0:0:0:0:1"):
            return "127.0.0.1"
        # IPv4-mapped IPv6: ::ffff:a.b.c.d
        m = re.match(
            r"^::ffff:(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$",
            addr,
            re.IGNORECASE,
        )
        if m:
            return m.group(1)
        return addr

    def _get_client_ip(self) -> str:
        """Return client IP as resolved by ProxyFix WSGI middleware, normalised to IPv4.

        ProxyFix (applied in __init__) rewrites request.remote_addr to the
        correctly-trusted client address, honouring only the configured number
        of upstream proxy hops. Manual X-Forwarded-For parsing is removed to
        prevent header-injection spoofing (audit finding #4, eb180c04).

        The result is then passed through _normalize_ip so that IPv6 loopback
        (::1) and IPv4-mapped IPv6 (::ffff:x.x.x.x) are canonicalised to their
        IPv4 equivalents.  This closes the residual LoopbackNormalizer gap noted
        in eb180c04: without this step a dual-stack client could reach two
        separate rate-limit buckets (127.0.0.1 and ::1) and receive twice the
        allowed request budget.
        """
        return self._normalize_ip(request.remote_addr or "unknown")

    def _get_session_id(self) -> str:
        bearer_value = self._get_bearer_token()
        if bearer_value:
            token_hash = hashlib.sha256(bearer_value.encode("utf-8")).hexdigest()[:16]
            raw_session = f"jwt:{token_hash}"
        else:
            raw_session = request.headers.get("X-Conversation-ID") or self._get_client_ip()
        tenant_id, _err = self.tenant_isolation.resolve_tenant_id(dict(request.headers))
        return self.tenant_isolation.scope_session_id(tenant_id, str(raw_session))

    def _resolve_tenant(self, data: Dict[str, Any] | None = None) -> tuple[str, Optional[Response]]:
        headers = dict(request.headers) if has_request_context() else {}
        tenant_id, err = self.tenant_isolation.resolve_tenant_id(headers, data)
        if err:
            return "", Response(f"Bad Request: {err}", status=400)
        return tenant_id, None

    def _get_bearer_token(self) -> str | None:
        auth_header = request.headers.get("Authorization", "")
        if not auth_header.lower().startswith("bearer "):
            return None
        bearer_value = auth_header.split(" ", 1)[1].strip()
        return bearer_value or None
    
    def _extract_prompt(self, data: Dict) -> Optional[str]:
        """Extract prompt from request data (supports multiple formats).

        Handles:
        - Top-level 'prompt' / 'input' / 'content' fields
        - OpenAI messages array with plain string content
        - OpenAI / Anthropic multi-modal content-part arrays:
          [{"type": "text", "text": "..."}]  (vision / tool-use format)

        Previously only scanned the top-level string value of messages[].content,
        allowing injection payloads inside content-part lists to bypass all
        input filters. Fixed by audit finding #1 (eb180c04).

        Args:
            data: Request JSON data

        Returns:
            Extracted and concatenated prompt string, or None
        """
        if not data:
            return None

        # Try direct top-level prompt fields
        prompt = data.get('prompt') or data.get('input') or data.get('content')

        # Try OpenAI / Anthropic messages array
        if not prompt and 'messages' in data:
            messages = data.get('messages', [])
            parts: List[str] = []
            for msg in reversed(messages):
                if msg.get('role') != 'user':
                    continue
                content = msg.get('content', '')
                if isinstance(content, str):
                    parts.append(content)
                elif isinstance(content, list):
                    # Multi-modal content-part format (vision / tool-use):
                    # [{"type": "text", "text": "..."}, {"type": "image_url", ...}]
                    for part in content:
                        if isinstance(part, dict) and part.get('type') == 'text':
                            text = part.get('text', '')
                            if isinstance(text, str) and text:
                                parts.append(text)
                if parts:
                    break
            prompt = ' '.join(parts) if parts else None

        return prompt if isinstance(prompt, str) else None

    @staticmethod
    def _extract_system_prompt(data: Optional[Dict[str, Any]]) -> Optional[str]:
        """Extract system prompt from OpenAI-style messages array."""
        if not data or not isinstance(data, dict):
            return None
        messages = data.get("messages", [])
        if not isinstance(messages, list):
            return None
        for msg in messages:
            if isinstance(msg, dict) and msg.get("role") == "system":
                content = msg.get("content", "")
                if isinstance(content, str) and content.strip():
                    return content
        return None
    
    def _check_keyword_filter(self, prompt: str, start_time: float, timings: Dict[str, float], show_reason: bool = True) -> Optional[Response]:
        """Check prompt against keyword/regex patterns."""
        t_start = time.perf_counter()

        if prompt in self._input_filter_cache:
            is_blocked = self._input_filter_cache[prompt]
            self._input_filter_cache.move_to_end(prompt)
        else:
            is_blocked = self.input_filter.check_prompt(prompt) is False
            self._input_filter_cache[prompt] = is_blocked
            if len(self._input_filter_cache) > self._input_filter_cache_size:
                self._input_filter_cache.popitem(last=False)

        timings['input_filter_ms'] = (time.perf_counter() - t_start) * 1000

        if not is_blocked:
            return None  # Passed check
        
        path_taken = "fast_path_keyword"
        reason = "Prompt injection attempt detected (Pattern Match)."
        latency_ms = (time.time() - start_time) * 1000
        
        logger.warning(f"ATTACK PREVENTED: {reason} (Prompt: {prompt[:30]}...)")
        self._report_event("injection", "high", {
            "prompt_preview": prompt[:100],
            "reason": reason,
            "latency_ms": f"{latency_ms:.2f}ms",
            "component_timings": timings,
            "path": path_taken
        })
        
        msg = f"Forbidden: {reason}" if show_reason else "Forbidden: Attack Prevented by GuardianAI."
        return Response(msg, status=403)
    
    def _check_threat_feed(self, prompt: str, start_time: float, timings: Dict[str, float]) -> Optional[Response]:
        """Check prompt against community threat feed patterns (compiled, multi-source).
        
        Severity-aware decision logic:
        - critical / high: immediate block (403)
        - medium: block with pattern detail in evidence
        - low: audit-only log, no block (returns None)
        """
        t_start = time.perf_counter()

        match_result = self.threat_feed.match(prompt)
        if match_result and not isinstance(match_result, (dict, str)):
            match_result = None
            for pattern in getattr(self.threat_feed, "patterns", []) or []:
                try:
                    if re.search(pattern, prompt, re.IGNORECASE):
                        match_result = {
                            "pattern": pattern,
                            "severity": "medium",
                            "category": "unknown",
                            "source": "legacy",
                        }
                        break
                except re.error:
                    continue
        timings['threat_feed_ms'] = (time.perf_counter() - t_start) * 1000

        if match_result:
            # match_result is now a dict: {pattern, severity, category, source}
            pattern_str = match_result.get("pattern", "unknown")[:120] if isinstance(match_result, dict) else str(match_result)[:120]
            severity = match_result.get("severity", "medium") if isinstance(match_result, dict) else "medium"
            category = match_result.get("category", "unknown") if isinstance(match_result, dict) else "unknown"
            source = match_result.get("source", "unknown") if isinstance(match_result, dict) else "unknown"

            latency_ms = (time.time() - start_time) * 1000
            event_data = {
                "prompt_preview": prompt[:100],
                "matched_pattern": pattern_str,
                "severity": severity,
                "category": category,
                "source": source,
                "pattern_count": len(self.threat_feed.patterns),
                "latency_ms": f"{latency_ms:.2f}ms",
                "component_timings": timings,
                "path": "fast_path_threat_feed",
            }

            # Low severity: audit-only (log but don't block)
            if severity == "low":
                logger.info(f"THREAT FEED AUDIT: low-severity match (pattern={pattern_str[:60]}, prompt={prompt[:30]}...)")
                self._report_event("threat_feed_audit", "LOW", event_data)
                return None  # do NOT block

            # Medium / high / critical: block
            reason = f"Blocked by Community Threat Feed [{severity.upper()}]."
            logger.warning(f"ATTACK PREVENTED: {reason} (Prompt: {prompt[:30]}...)")
            self._report_event("threat_feed_match", severity.upper(), event_data)
            return Response(f"Forbidden: {reason}", status=403)

        return None

    
    def _check_ai_firewall(self, prompt: str, mode: str, start_time: float, timings: Dict[str, float], show_reason: bool = True) -> Optional[Response]:
        """Check prompt using AI semantic analysis."""
        t_start = time.perf_counter()
        path_taken = "ai_firewall"
        
        # Context tracking: Prefer X-Conversation-ID for NAT/VPN environments
        session_id = self._get_session_id()
        self.context_buffer[session_id].append(prompt)
        full_context = " ".join(self.context_buffer[session_id])

        # Adaptive Security: escalate only when the bucket is nearly exhausted.
        # `get_pressure()` returns remaining capacity from 0.0 (empty) to 1.0 (full).
        client_ip = self._get_client_ip()
        pressure = self.rate_limiter.get_pressure(client_ip)
        effective_capacity = getattr(self.rate_limiter, "_get_effective_capacity", lambda _ip: getattr(self.rate_limiter, "capacity", 0))(client_ip)
        if effective_capacity > 1 and pressure <= 0.2:
            logger.info(f"High pressure detected ({pressure:.2f}). Scaling up to STRICT mode for session: {session_id}")
            mode = "strict"
        mode = self.brain.recommend_mode(session_id, default_mode=mode)
        
        # Smart Adaptation: tighten only when the upstream explicitly looks unhealthy.
        # Some compatible upstreams do not expose `/health`, so 404/405/501 should not
        # be treated as a signal to harden into strict mode.
        now = time.time()
        status_code = 200
        if now - getattr(self, "_last_health_check_time", 0.0) < 5.0:
            status_code = getattr(self, "_last_health_check_status", 200)
        else:
            try:
                health_check = requests.get(f"{self.target_url}/health", timeout=1)
                status_code = int(getattr(health_check, "status_code", 0) or 0)
                self._last_health_check_time = now
                self._last_health_check_status = status_code
            except Exception as e:
                logger.debug(f"Health check failed: {e}")
                self._last_health_check_time = now
                self._last_health_check_status = 500  # Assume unhealthy status on error
                status_code = 500

        if 500 <= status_code < 600 and status_code != 501:
            logger.debug("Downstream agent unhealthy. Applying defensive Balanced+ posture.")
            if mode == "balanced":
                mode = "strict"

        is_malicious = self.ai_firewall.is_malicious(full_context, mode=mode)
        timings['ai_firewall_ms'] = (time.perf_counter() - t_start) * 1000

        if is_malicious:
            reason = f"AI Firewall detected malicious intent (Mode: {mode})."
            latency_ms = (time.time() - start_time) * 1000
            logger.warning(f"ATTACK PREVENTED: {reason} (Prompt: {prompt[:30]}...)")
            self._report_event("injection_ai", "HIGH", {
                "prompt_preview": prompt[:100],
                "reason": reason,
                "context_used": True,
                "latency_ms": f"{latency_ms:.2f}ms",
                "component_timings": timings,
                "path": path_taken
            })
            
            msg = f"Forbidden: {reason}" if show_reason else "Forbidden: Attack Prevented by GuardianAI Firewall."
            return Response(msg, status=403)
        
        return None

    def _should_defer_to_output_redaction(self, prompt: str) -> bool:
        strategy = str(
            self.config.get("security_policies", {}).get("leak_prevention_strategy", "block")
        ).strip().lower()
        if strategy != "redact":
            return False
        prompt_lower = (prompt or "").lower()
        if not prompt_lower:
            return False
        request_terms = ("leak", "reveal", "show", "print", "expose", "dump")
        secret_terms = ("credential", "credentials", "password", "secret", "token", "api key", "key")
        return any(term in prompt_lower for term in request_terms) and any(term in prompt_lower for term in secret_terms)
    
    def _extract_output_assurance_payload(
        self,
        parsed_json: Optional[Dict[str, Any]],
        message_content: str,
    ) -> Optional[Dict[str, Any]]:
        """Extract structured payload candidate for output-assurance checks."""
        if parsed_json and isinstance(parsed_json, dict):
            choices = parsed_json.get("choices", [])
            if choices and isinstance(choices, list):
                try:
                    msg_content = choices[0].get("message", {}).get("content", "")
                    if isinstance(msg_content, dict):
                        return msg_content
                    if isinstance(msg_content, str) and msg_content.strip():
                        parsed_msg = json.loads(msg_content)
                        if isinstance(parsed_msg, dict):
                            return parsed_msg
                except (json.JSONDecodeError, KeyError, IndexError, TypeError):
                    pass
            return parsed_json
        if isinstance(message_content, str) and message_content.strip():
            try:
                parsed = json.loads(message_content)
                if isinstance(parsed, dict):
                    return parsed
            except (json.JSONDecodeError, TypeError):
                pass
        return None

    def _is_trivially_safe_output(self, content: str) -> bool:
        text = (content or "").strip()
        return text.lower() in {"safe response", "ok", "success"}

    def _process_output_validation(
        self,
        raw_content: str,
        path: str,
        start_time: float,
        timings: Dict[str, float],
        tenant_id: Optional[str] = None,
    ) -> str:
        """Process output validation and PII redaction."""
        t_start = time.perf_counter()
        
        # Targeted validation for JSON responses (OpenAI format)
        content_to_check = raw_content
        parsed_json = None
        has_message_content = False
        try:
            out_data = json.loads(raw_content)
            if isinstance(out_data, dict):
                parsed_json = out_data
                # Extract the actual AI message content if present
                choices = out_data.get('choices', [])
                if choices and isinstance(choices, list):
                    msg_content = choices[0].get('message', {}).get('content', '')
                    if msg_content:
                        content_to_check = msg_content
                        has_message_content = True
        except (json.JSONDecodeError, KeyError, IndexError, TypeError) as e:
            logger.debug(f"Could not parse response JSON: {e}")

        assurance_payload = self._extract_output_assurance_payload(parsed_json, content_to_check)
        assurance_decision = self.output_assurance.evaluate(assurance_payload)
        if assurance_decision.action == "block":
            timings["output_assurance_ms"] = (time.perf_counter() - t_start) * 1000
            self._report_event(
                "output_assurance_block",
                assurance_decision.severity,
                {
                    "path": path,
                    "reason": assurance_decision.reason,
                    "details": assurance_decision.details,
                    "component_timings": timings,
                },
                tenant_id=tenant_id,
            )
            if self.output_assurance.enforcement_mode != "audit":
                raise ValueError(f"Output assurance blocked: {assurance_decision.reason}")
        else:
            timings["output_assurance_ms"] = (time.perf_counter() - t_start) * 1000

        if self._is_trivially_safe_output(content_to_check):
            timings['output_validator_ms'] = (time.perf_counter() - t_start) * 1000
            return raw_content

        # 1. Check for HARD block (Critical leaks)
        is_valid = self.output_validator.validate_output(content_to_check)
        
        if not is_valid:
            strategy = self.config.get('security_policies', {}).get('leak_prevention_strategy', 'block')
            
            if strategy == "block":
                logger.warning("DATA LEAK PREVENTED: Sensitive information detected in agent output. Blocking response.")
                sanitized_content, detected = self.output_validator.sanitize_output(content_to_check)
                timings['output_validator_ms'] = (time.perf_counter() - t_start) * 1000
                self._report_event("data_leak", "critical", {
                    "path": path,
                    "detected_entities": detected or ["UNKNOWN_PII"],
                    "redacted_count": len(detected) if detected else 1,
                    "prompt_preview": (sanitized_content[:75] + "...") if len(sanitized_content) > 75 else sanitized_content, # Always mask sensitive data even in admin logs
                    "component_timings": timings
                })
                raise ValueError("Data leak blocked")
            else:
                logger.warning("DATA LEAK DETECTED: Redacting sensitive information (Privacy Strategy: REDACT).")
                sanitized_content, detected = self.output_validator.sanitize_output(content_to_check)
                self._report_event("data_redaction", "INFO", {
                    "path": path,
                    "detected_entities": detected or ["UNKNOWN_PII"],
                    "redacted_count": len(detected) if detected else 1,
                    "prompt_preview": (sanitized_content[:75] + "...") if len(sanitized_content) > 75 else sanitized_content, # Always mask sensitive data
                     "component_timings": timings
                })
                timings['output_validator_ms'] = (time.perf_counter() - t_start) * 1000
                if parsed_json is not None and has_message_content:
                    parsed_json['choices'][0]['message']['content'] = sanitized_content
                    return json.dumps(parsed_json)
                return sanitized_content

        # Output is safe, so avoid a second sanitize pass for lower latency.
        timings['output_validator_ms'] = (time.perf_counter() - t_start) * 1000
        if is_valid:
            return raw_content

        # 2. Proactive sanitization on model text only (faster, fewer false positives)
        sanitized_content, detected = self.output_validator.sanitize_output(content_to_check)
        timings['output_validator_ms'] = (time.perf_counter() - t_start) * 1000
        
        if detected:
            self._report_event("redaction", "MEDIUM", {
                "path": path,
                "detected_entities": detected,
                "prompt_preview": (sanitized_content[:75] + "...") if len(sanitized_content) > 75 else sanitized_content, # Always mask sensitive data
                "component_timings": timings
            })
            if parsed_json is not None and has_message_content:
                parsed_json['choices'][0]['message']['content'] = sanitized_content
                return json.dumps(parsed_json)
            return sanitized_content
        
        return raw_content

    def _apply_output_watermark(self, content: str, path: str, timings: Dict[str, float], tenant_id: str) -> str:
        t_start = time.perf_counter()
        if not self.output_watermarker.can_apply():
            timings["output_watermark_ms"] = 0.0
            return content
        watermarked, decision = self.output_watermarker.apply(content)
        timings["output_watermark_ms"] = (time.perf_counter() - t_start) * 1000
        if decision.action == "allow":
            if decision.reason == "watermark_applied":
                self._report_event(
                    "output_watermark_applied",
                    "LOW",
                    {"path": path, "details": decision.details, "component_timings": timings},
                    tenant_id=tenant_id,
                )
            return watermarked
        self._report_event(
            "output_watermark_block",
            decision.severity,
            {"path": path, "reason": decision.reason, "details": decision.details, "component_timings": timings},
            tenant_id=tenant_id,
        )
        if self.output_watermarker.enforcement_mode != "audit":
            raise ValueError(f"Output watermark blocked: {decision.reason}")
        return content

    def _log_blocked_prompt(self, event_type: str, severity: str, prompt_preview: str, details: Dict[str, Any]) -> None:
        """Write a structured blocked-prompt record to the local logger.

        Provides a synchronous, local audit trail independent of the async
        backend/SIEM path. Blocked prompts are always recorded here even if
        the backend is unreachable. Called automatically from _report_event
        for HIGH/CRITICAL severity events that carry a prompt_preview field.
        (audit finding #8, eb180c04)
        """
        logger.warning(
            "BLOCKED_PROMPT event_type=%s severity=%s preview=%r details=%s",
            event_type,
            severity,
            prompt_preview[:80],
            json.dumps({k: v for k, v in details.items() if k != "prompt_preview"}, default=str),
        )

    def _report_event(self, event_type: str, severity: str, details: Dict[str, Any], tenant_id: Optional[str] = None):
        if not tenant_id:
            tenant_id = self.tenant_isolation.default_tenant_id
            if has_request_context():
                resolved_tenant, err = self.tenant_isolation.resolve_tenant_id(dict(request.headers))
                if not err and resolved_tenant:
                    tenant_id = resolved_tenant
        
        payload = {
            "guardian_id": self.config.get('guardian_id', 'unknown'),
            "tenant_id": tenant_id,
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "timestamp": time.time()
        }
        # Synchronous local structured log for high-severity blocked prompts.
        # Runs before async backend/SIEM dispatch to guarantee local record. (finding #8, eb180c04)
        if severity.upper() in {"CRITICAL", "HIGH"} and "prompt_preview" in details:
            self._log_blocked_prompt(event_type, severity, details.get("prompt_preview", ""), details)
        if getattr(self, "siem_config", None) and self.siem_config.enabled:
            from backend.siem import build_alert_document
            alert_doc = build_alert_document(
                guardian_id=self.config.get('guardian_id', 'unknown'),
                event_type=event_type,
                severity=severity,
                details=details,
                timestamp=payload["timestamp"],
            )
            self.siem_router.enqueue(alert_doc)
        else:
            self.tenant_isolation.write_evidence(
                tenant_id=tenant_id,
                event_type=event_type,
                severity=severity,
                details=details,
                timestamp=payload["timestamp"],
            )
        backend_config = self.config.get('backend', {})
        if not backend_config.get('enabled'):
            return
        backend_token = backend_config.get("token")
        if not backend_token:
            backend_token = os.environ.get("GUARDIAN_BACKEND_TOKEN", "").strip()
        service_id = backend_config.get("service_id") or os.environ.get("GUARDIAN_SERVICE_ID", "guardian-proxy").strip()
        service_token = backend_config.get("service_auth_token") or os.environ.get("GUARDIAN_SERVICE_AUTH_TOKEN", "").strip()
        headers = {}
        if backend_token:
            headers["Authorization"] = f"Bearer {backend_token}"
        if service_id and service_token:
            headers["X-Guardian-Service-Id"] = str(service_id)
            headers["X-Guardian-Service-Token"] = str(service_token)

        verify: bool | str = True
        if "tls_verify" in backend_config:
            verify = bool(backend_config.get("tls_verify"))
        ca_bundle = backend_config.get("ca_bundle")
        if ca_bundle:
            verify = str(ca_bundle)
        cert = None
        client_cert = backend_config.get("client_cert")
        client_key = backend_config.get("client_key")
        if client_cert and client_key:
            cert = (str(client_cert), str(client_key))
        elif client_cert:
            cert = str(client_cert)
        
        def send_report():
            try:
                requests.post(
                    backend_config.get('url'),
                    json=payload,
                    timeout=5,
                    headers=headers or None,
                    verify=verify,
                    cert=cert,
                )
            except Exception as e:
                logger.error(f"Failed to report event to backend: {e}")

        # Non-blocking background report
        threading.Thread(target=send_report, daemon=True).start()

    def _build_honeypot_response(
        self, session_id: str, path: str, prompt: str = "",
    ) -> Response:
        # FEAT-HONEY-PROFILE: record attacker TTP intelligence before building response
        client_ip = ""
        user_agent = ""
        try:
            from flask import request as _req
            client_ip = _req.remote_addr or ""
            user_agent = _req.headers.get("User-Agent", "")
        except Exception:
            pass
        if prompt or client_ip or user_agent:
            self.attacker_profiler.record_interaction(
                session_id, prompt, client_ip=client_ip, user_agent=user_agent
            )
        self.honeypot_analytics.record(session_id, path)
        body = self.honeypot.build_response(session_id, path)
        if body is None:
            return Response("Forbidden: Session limited by deception controls.", status=403)
        return Response(json.dumps(body), status=200, mimetype="application/json")

    def _enforce_tool_policy(self, data: Dict[str, Any] | None, path: str) -> Optional[Response]:
        headers = dict(request.headers)
        result = self.tool_policy.evaluate(data, headers=headers)
        if result.action == "allow":
            return None
        if result.action == "confirm":
            self._report_event("tool_policy_confirmation_required", "MEDIUM", {
                "path": path,
                "reason": result.reason,
                "tools": result.tools,
            })
            if self.tool_policy.enforcement_mode == "audit":
                return None
            return Response("Precondition Required: Sensitive tool requires explicit confirmation header.", status=428)
        if result.action == "block":
            self._report_event("tool_policy_block", "HIGH", {
                "path": path,
                "reason": result.reason,
                "tools": result.tools,
            })
            if self.tool_policy.enforcement_mode == "audit":
                return None
            return Response("Forbidden: Tool call blocked by Guardian tool policy.", status=403)
        return None




    # -- Filesystem Sandbox Enforcement ----------------------------------------
    # Operation-intent inference order:
    #   1. Explicit mode/operation/access arg in the tool-call arguments.
    #   2. Function-name heuristic: write-like names -> write; read-like -> read.
    #   3. Unknown intent -> default to "write" (stricter: false-block a benign
    #      read is far safer than false-pass on a malicious write).
    # The old double-check pattern (block only if BOTH read AND write deny) is
    # removed -- it silently passed write attempts on read-only-configured paths.
    _WRITE_NAME_TOKENS = frozenset({
        'write', 'create', 'append', 'delete', 'remove', 'move', 'copy',
        'rename', 'mkdir', 'rmdir', 'truncate', 'save', 'store', 'put',
        'upload', 'overwrite', 'patch', 'update',
    })
    _READ_NAME_TOKENS = frozenset({
        'read', 'get', 'fetch', 'list', 'stat', 'open', 'download', 'view',
        'show', 'cat', 'head', 'tail', 'grep', 'search', 'find', 'ls',
    })

    @staticmethod
    def _infer_operation(fn_name, args):
        # Infer "read" or "write" from explicit args first, then function name.
        for key in ('mode', 'operation', 'access', 'action', 'method'):
            val = args.get(key, '')
            if isinstance(val, str):
                val_lower = val.lower()
                if any(t in val_lower for t in GuardianProxy._WRITE_NAME_TOKENS):
                    return 'write'
                if any(t in val_lower for t in GuardianProxy._READ_NAME_TOKENS):
                    return 'read'
        name_lower = (fn_name or '').lower()
        for token in GuardianProxy._WRITE_NAME_TOKENS:
            if token in name_lower:
                return 'write'
        for token in GuardianProxy._READ_NAME_TOKENS:
            if token in name_lower:
                return 'read'
        return 'write'  # unknown -> conservative default

    def _enforce_filesystem_sandbox(self, data, path):
        # Block tool calls accessing paths outside the configured sandbox.
        # Infers read vs write intent; unknown defaults to write (stricter).
        if not hasattr(self, 'filesystem_sandbox') or self.filesystem_sandbox is None:
            return None
        if not isinstance(data, dict):
            return None

        _PATH_KEYS = ('path', 'file', 'filepath', 'filename',
                      'dir', 'directory', 'target')
        candidates = []  # list of (file_path, operation)

        def _extract(fn_name, raw_args):
            if isinstance(raw_args, str):
                try:
                    import json as _json
                    raw_args = _json.loads(raw_args)
                except Exception:
                    return
            if not isinstance(raw_args, dict):
                return
            operation = GuardianProxy._infer_operation(fn_name, raw_args)
            for key in _PATH_KEYS:
                val = raw_args.get(key)
                if isinstance(val, str) and val:
                    candidates.append((val, operation))

        # tool_calls array (OpenAI / Anthropic messages format).
        for msg in data.get('messages', []):
            if not isinstance(msg, dict):
                continue
            for call in msg.get('tool_calls', []):
                if not isinstance(call, dict):
                    continue
                fn = call.get('function')
                if isinstance(fn, dict):
                    _extract(fn.get('name', ''), fn.get('arguments'))

        # Legacy function_call field.
        fc = data.get('function_call')
        if isinstance(fc, dict):
            _extract(fc.get('name', ''), fc.get('arguments'))

        # Evaluate each (path, operation) pair against the sandbox.
        for file_path, operation in candidates:
            allowed, reason = self.filesystem_sandbox.check_access(file_path, operation)
            if not allowed:
                self._report_event('sandbox_block', 'HIGH', {
                    'path': path,
                    'file_path': file_path,
                    'operation': operation,
                    'reason': reason,
                })
                from flask import Response as _Resp
                return _Resp(
                    'Forbidden: Filesystem Sandbox blocked {} access to {}. Reason: {}'.format(
                        operation, file_path, reason),
                    status=403,
                )
        return None

    def _enforce_agentic_controls(
        self,
        data: Dict[str, Any] | None,
        path: str,
        tenant_id: str,
    ) -> Optional[Response]:
        headers = dict(request.headers)
        result = self.agentic_security.evaluate(headers, data=data)
        if result.action == "allow":
            return None
        self._report_event(
            "agentic_policy_block",
            result.severity,
            {
                "path": path,
                "reason": result.reason,
                "details": result.details,
            },
            tenant_id=tenant_id,
        )
        if self.agentic_security.enforcement_mode == "audit":
            return None
        return Response(f"Forbidden: Agentic policy blocked request ({result.reason}).", status=403)

    def _enforce_rag_controls(
        self,
        data: Dict[str, Any] | None,
        path: str,
        tenant_id: str,
    ) -> Optional[Response]:
        result = self.rag_security.evaluate(data)
        if result.action == "allow":
            return None
        self._report_event(
            "rag_policy_block",
            result.severity,
            {
                "path": path,
                "reason": result.reason,
                "details": result.details,
            },
            tenant_id=tenant_id,
        )
        if self.rag_security.enforcement_mode == "audit":
            return None
        return Response(f"Forbidden: RAG policy blocked request ({result.reason}).", status=403)

    def _enforce_multimodal_controls(
        self,
        data: Dict[str, Any] | None,
        path: str,
        tenant_id: str,
    ) -> Optional[Response]:
        result = self.multimodal_security.evaluate(data)
        if result.action == "allow":
            return None
        self._report_event(
            "multimodal_policy_block",
            result.severity,
            {
                "path": path,
                "reason": result.reason,
                "details": result.details,
            },
            tenant_id=tenant_id,
        )
        if self.multimodal_security.enforcement_mode == "audit":
            return None
        return Response(f"Forbidden: Multimodal policy blocked request ({result.reason}).", status=403)

    def _resolve_security_mode_for_tenant(
        self,
        tenant_id: str,
        mode: str,
        show_reason: bool,
    ) -> tuple[str, bool]:
        profile = self.tenant_sensitivity.resolve(tenant_id, mode, show_reason)
        return profile.security_mode, profile.show_block_reason

    def _is_feedback_allowlisted(self, tenant_id: str, prompt: str, event_family: str) -> bool:
        return self.feedback_loop.is_allowlisted(tenant_id, prompt, event_family)

    def _enforce_memory_controls(self, session_id: str, prompt: str, path: str, tenant_id: str) -> Optional[Response]:
        result = self.memory_security.evaluate_and_record(session_id, prompt)
        if result.action == "allow":
            return None
        self._report_event(
            "memory_policy_block",
            result.severity,
            {
                "path": path,
                "reason": result.reason,
                "details": result.details,
            },
            tenant_id=tenant_id,
        )
        if self.memory_security.enforcement_mode == "audit":
            return None
        return Response(f"Forbidden: Memory policy blocked request ({result.reason}).", status=403)

    def _decode_obfuscation(self, prompt: str) -> str:
        """Attempt to decode hex or base64 payloads to scan their true meaning."""
        import binascii
        import base64
        import urllib.parse
        
        decoded = prompt
        # Try URL Decode
        if "%" in decoded:
            decoded = urllib.parse.unquote(decoded)
        
        # Try Hex Decode (assuming pure hex string)
        hex_prompt = prompt.replace(" ", "").strip()
        if len(hex_prompt) > 10 and all(c in "0123456789abcdefABCDEF" for c in hex_prompt):
            try:
                decoded += " " + bytes.fromhex(hex_prompt).decode("utf-8")
            except Exception:
                pass
                
        # Try Base64 Decode
        try:
            if len(prompt) % 4 == 0 and len(prompt) > 16:
                b64_decoded = base64.b64decode(prompt).decode("utf-8")
                if len(b64_decoded) > 5 and b64_decoded.isprintable():
                    decoded += " " + b64_decoded
        except Exception:
            pass
            
        return decoded

    def _check_language_allowlist(self, prompt: str, session_id: str, path: str) -> Optional[Response]:
        """Detect language and block if it's not English (Enterprise 'Strict' feature)."""
        if not prompt or len(prompt.strip()) < 20:
            return None
        if self.fast_path.is_known_safe(prompt):
            return None
        # Language detection is only meaningful for word-separated natural
        # language. langdetect misclassifies JSON-syntax blobs and single
        # tokens (garbage-in, garbage-out), producing false-positive 403s for
        # the wrong reason before check_prompt() runs. The language allowlist
        # is a policy control, not a security boundary — text that cannot be
        # reliably classified is skipped here and still fully scanned by the
        # keyword/regex/ML guardrails below.
        letter_tokens = [t for t in prompt.split() if any(c.isalpha() for c in t)]
        natural_ratio = sum(c.isalpha() or c.isspace() for c in prompt) / max(len(prompt), 1)
        if len(letter_tokens) < 2 or natural_ratio < 0.7:
            return None
        try:
            from langdetect import detect
            lang = detect(prompt)
            if lang != 'en':
                self._report_event("language_block", "MEDIUM", {
                    "session_id": session_id,
                    "reason": f"Non-English language detected: {lang}",
                    "path": path,
                })
                return Response("Forbidden: Only English language is allowed under strict security policies.", status=403)
        except Exception as e:
            logger.warning(f"Language detection failed: {e}")
        return None

    def _check_cost_abuse_quarantine(self, session_id: str, path: str) -> Optional[Response]:
        """Check if session is currently quarantined due to cost abuse."""
        is_quarantined, remaining_seconds = self.cost_abuse.is_quarantined(session_id)
        if not is_quarantined:
            return None
        self._report_event("session_quarantined", "HIGH", {
            "session_id": session_id,
            "reason": "Session blocked by active cost-abuse quarantine.",
            "path": path,
            "remaining_seconds": remaining_seconds,
        })
        return Response("Forbidden: Session quarantined due to anomalous cost activity.", status=403)

    def _check_trust_exploitation(self, prompt: str, session_id: str, path: str, tenant_id: str, timings: Dict[str, float]) -> Optional[Response]:
        """Check prompt against human-agent trust exploitation controls (OWASP ASI09)."""
        t_start = time.perf_counter()
        decision = self.trust_exploitation.evaluate(prompt, session_id=session_id)
        timings['trust_exploitation_ms'] = (time.perf_counter() - t_start) * 1000
        
        if decision.action == "allow":
            return None
            
        self._report_event(
            f"trust_exploitation_{decision.action}",
            decision.severity,
            {
                "path": path,
                "reason": decision.reason,
                "confidence_score": decision.confidence_score,
                "deception_score": decision.deception_score,
                "details": decision.details,
                "component_timings": timings,
            },
            tenant_id=tenant_id,
        )
        
        if self.trust_exploitation.enforcement_mode == "audit":
            logger.info(f"Trust Exploitation Guard AUDIT: {decision.action} skipped in audit. Reason: {decision.reason}")
            return None
            
        return Response(f"Forbidden: Trust exploitation policy blocked request ({decision.reason}).", status=403)

    def _check_authentication(self, start_time: float, path: str) -> Optional[Response]:
        """Verify X-Guardian-Token for proxied requests.

        SECURITY: Defaults to True (fail-closed). Authentication is REQUIRED
        unless explicitly disabled via `proxy.enforce_auth: false` in config.
        Previously defaulted to False — a fail-open default on a security product.

        Returns Response(401) if unauthorized, None if authorized.
        """
        proxy_config = self.config.get('proxy', {})
        if not proxy_config.get('enforce_auth', True):
            return None

        request_token = request.headers.get("X-Guardian-Token")
        required_token = proxy_config.get('proxy_token')
        admin_token = self.config.get('security_policies', {}).get('admin_token')

        if request_token:
            if required_token and secrets.compare_digest(request_token, required_token):
                return None
            if admin_token and secrets.compare_digest(request_token, admin_token):
                return None

        latency_ms = (time.time() - start_time) * 1000
        client_ip = self._get_client_ip()
        logger.warning(f"UNAUTHORIZED ACCESS: Invalid or missing token from {client_ip} for /{path}")
        self._report_event("unauthorized_access", "MEDIUM", {
            "path": path,
            "ip": client_ip,
            "latency_ms": f"{latency_ms:.2f}ms",
            "reason": "Missing or invalid X-Guardian-Token",
        })
        return Response("Unauthorized: Valid X-Guardian-Token is required.", status=401)

    def proxy(self, path):
        start_time = time.time()
        timings = {}
        logger.info(f"DEBUG: Proxy received request for /{path}")

        # 1. Rate Limiting Check
        rl_resp = self._check_rate_limit(start_time, path)
        if rl_resp:
            return rl_resp

        # 1b. Authentication (fail-closed unless enforce_auth=false in config)
        auth_resp = self._check_authentication(start_time, path)
        if auth_resp:
            return auth_resp

        path_taken = "fast_path_allowlist"  # Default path

        # 2. Inspect input
        data = None
        prompt = None
        prompt_is_raw_body = False  # True when prompt came from raw fallback (JSON parse failed)
        raw_len = 0
        tenant_id = self.tenant_isolation.default_tenant_id
        
        try:
            # Attempt 1: Flask Built-in (Force ignore Content-Type)
            data = request.get_json(force=True, silent=True)
            
            # Attempt 2: Manual Fallback (If Flask returns None for valid JSON bytes)
            if data is None and request.method in ['POST', 'PUT']:
                raw_data = request.get_data()
                raw_len = len(raw_data) if raw_data else 0
                if raw_data:
                    import json
                    try:
                        data = json.loads(raw_data)
                    except (TypeError, json.JSONDecodeError):
                        try:
                            # Try decoding to string first
                            data = json.loads(raw_data.decode('utf-8', errors='ignore'))
                        except Exception:
                            pass
        except Exception as e:
            logger.error(f"DEBUG: content parsing error: {e}")

        if isinstance(data, dict) and data:
            # Structured controls require an object body. Valid-but-non-dict
            # JSON (string/array/number) previously crashed here with
            # AttributeError and must instead fall through to the raw-body
            # fallback below, where the full guardrail chain scans them.
            tenant_id, tenant_resp = self._resolve_tenant(data)
            if tenant_resp is not None:
                return tenant_resp
            multimodal_resp = self._enforce_multimodal_controls(data, path, tenant_id)
            if multimodal_resp is not None:
                return multimodal_resp
            rag_resp = self._enforce_rag_controls(data, path, tenant_id)
            if rag_resp is not None:
                return rag_resp
            agentic_resp = self._enforce_agentic_controls(data, path, tenant_id)
            if agentic_resp is not None:
                return agentic_resp
            prompt = self._extract_prompt(data)
            logger.debug(f"DEBUG: Extracted prompt: {str(prompt)[:50] if prompt else 'None'}")
            tool_policy_resp = self._enforce_tool_policy(data, path)
            if tool_policy_resp is not None:
                return tool_policy_resp
            fs_sandbox_resp = self._enforce_filesystem_sandbox(data, path)
            if fs_sandbox_resp is not None:
                return fs_sandbox_resp
        else:
            tenant_id, tenant_resp = self._resolve_tenant()
            if tenant_resp is not None:
                return tenant_resp
            agentic_resp = self._enforce_agentic_controls(None, path, tenant_id)
            if agentic_resp is not None:
                return agentic_resp

        if not prompt and request.method in ['POST', 'PUT']:
            raw_data = request.get_data()
            if raw_data:
                try:
                    decoded = raw_data.decode('utf-8')
                    if not any(c.isprintable() and not c.isspace() for c in decoded):
                        return Response("Bad Request: Uninspectable or empty body", status=400)
                    prompt = decoded
                except UnicodeDecodeError:
                    return Response("Bad Request: Uninspectable or empty body", status=400)
            else:
                return Response("Bad Request: Uninspectable or empty body", status=400)
            # Mark that this prompt was not extracted from structured JSON — language
            # detection on raw body bytes is unreliable (langdetect misclassifies JSON
            # syntax characters) and must not block before check_prompt() runs.
            prompt_is_raw_body = True

        # DEBUG INFO UPDATE
        # P2-16: Redact sensitive headers before storing in memory
        safe_headers = dict(request.headers)
        for sensitive_key in ['Authorization', 'X-Guardian-Token', 'x-api-key']:
            for header_key in list(safe_headers.keys()):
                if header_key.lower() == sensitive_key.lower():
                    val = safe_headers[header_key]
                    if val.lower().startswith('bearer '):
                        safe_headers[header_key] = val[:10] + '***' + val[-4:]
                    else:
                        safe_headers[header_key] = '***REDACTED***'

        self._update_debug_info({
            "path": path,
            "tenant_id": tenant_id,
            "method": request.method,
            "content_type": request.content_type,
            "raw_len": raw_len,
            "data_parsed": bool(data),
            "data_keys": list(data.keys()) if isinstance(data, dict) else str(type(data)),
            "prompt_extracted": prompt[:100] + '...[REDACTED]' if prompt and len(prompt) > 100 else prompt,
            "headers": safe_headers
        })

        if prompt:
            session_id = self._get_session_id()
            
            # 0.1 Decode obfuscations (Hex/Base64) to expose the true payload
            prompt = self._decode_obfuscation(prompt)
            
            quarantined_resp = self._check_cost_abuse_quarantine(session_id, path)
            if quarantined_resp is not None:
                return quarantined_resp
            memory_resp = self._enforce_memory_controls(session_id, prompt, path, tenant_id)
            if memory_resp is not None:
                self.brain.analyze_request(session_id, prompt, blocked=True)
                return memory_resp
            self.brain.bind_session_identity(session_id, self._get_bearer_token())
            pre_action = self.brain.session_action(session_id)
            if pre_action == "revoke" or self.brain.should_revoke_session(session_id):
                self.brain.enforce_revocation(session_id, reason="pre_request_gate")
                self._report_event("session_revoked", "HIGH", {
                    "session_id": session_id,
                    "reason": "Blue Team adaptive revoke threshold exceeded.",
                    "path": path,
                })
                return Response("Forbidden: Session revoked by adaptive security controls.", status=403)
            # FEAT-BLUE-ADVANCED: cooldown → 429 with Retry-After
            if pre_action == "cooldown":
                retry_after = self.brain.get_cooldown_seconds(session_id)
                self._report_event("session_cooldown", "MEDIUM", {
                    "session_id": session_id,
                    "retry_after_seconds": retry_after,
                    "path": path,
                })
                return Response(
                    "Too Many Requests: Session rate-limited by adaptive security controls.",
                    status=429,
                    headers={"Retry-After": str(max(1, retry_after))},
                )
            if pre_action == "honeypot":
                self._report_event("honeypot_engaged", "MEDIUM", {
                    "session_id": session_id,
                    "reason": "Blue Team adaptive honeypot threshold exceeded.",
                    "path": path,
                })
                resp = self._build_honeypot_response(session_id, path, prompt=prompt)
                if resp.status_code == 403:
                    self._report_event("honeypot_rate_limited", "MEDIUM", {
                        "session_id": session_id,
                        "path": path,
                    })
                return resp
            # 0.2 Check Language Allowlist after higher-priority adaptive controls.
            # Skip for raw-body prompts: langdetect on JSON syntax or malformed bytes
            # is unreliable and produces false-positive 403s before check_prompt() runs.
            # Raw prompts are fully inspected by keyword/regex filters below.
            if not prompt_is_raw_body:
                lang_resp = self._check_language_allowlist(prompt, session_id, path)
                if lang_resp is not None:
                    self.brain.analyze_request(session_id, prompt, blocked=True)
                    return lang_resp
            # 0.3 Trust Exploitation Guard (OWASP ASI09)
            te_resp = self._check_trust_exploitation(prompt, session_id, path, tenant_id, timings)
            if te_resp is not None:
                self.brain.analyze_request(session_id, prompt, blocked=True)
                return te_resp
            policies = self.config.get('security_policies', {})
            mode = policies.get('security_mode', 'balanced')
            show_reason = policies.get('show_block_reason', True)

            # 0. Admin Policy Bypass (Trusted Agent)
            admin_token = policies.get('admin_token')
            request_token = request.headers.get("X-Guardian-Token")
            mode, show_reason = self._resolve_security_mode_for_tenant(tenant_id, mode, show_reason)
            
            if request.headers.get("X-Guardian-Role") == "admin":
                if admin_token and secrets.compare_digest(request_token or "", admin_token):
                    logger.warning(f"âš ï¸  ADMIN BYPASS: Authorized request (Token Match) from {request.remote_addr}.")
                    path_taken = "admin_allowlist"
                    # Audit Log Event (Immutable Record)
                    self._report_event("admin_action", "critical", {
                        "action": "security_bypass",
                        "user": "admin",
                        "ip": request.remote_addr,
                        "prompt_preview": prompt[:50]
                    })
                else:
                    logger.warning(f"ADMIN FAIL: Invalid or missing token from {request.remote_addr}. ConfigTokenHash={hashlib.sha256(str(admin_token).encode()).hexdigest()[:8] if admin_token else 'None'}, ReqTokenHash={hashlib.sha256(str(request_token).encode()).hexdigest()[:8] if request_token else 'None'}")
                    # Fall through to normal checks (don't block, just treat as untrusted)
            
            if path_taken != "admin_allowlist":
                # 3. Fast Keyword/Regex Filter (Known Bad)
                if self._is_feedback_allowlisted(tenant_id, prompt, "injection"):
                    kw_resp = None
                else:
                    kw_resp = self._check_keyword_filter(prompt, start_time, timings, show_reason)
                if kw_resp:
                    self.brain.analyze_request(session_id, prompt, blocked=True)
                    return kw_resp
                
                # 3b. Base64 Obfuscation Check (Segment 4)
                if self.base64_detector.is_suspicious(prompt, entropy_threshold=5.0):
                    reason = "Obfuscated payload detected (Base64/High Entropy)."
                    logger.warning(f"ATTACK PREVENTED: {reason}")
                    self._report_event("obfuscation", "MEDIUM", {
                        "prompt_preview": "HIDDEN_BASE64_PAYLOAD",
                        "reason": reason,
                        "path": "base64_filter"
                    })
                    self.brain.analyze_request(session_id, prompt, blocked=True)
                    return Response(f"Forbidden: {reason}", status=403)
                
                # 4. Community Threat Feed Check (Dynamic)
                if self._is_feedback_allowlisted(tenant_id, prompt, "threat_feed_match"):
                    tf_resp = None
                else:
                    tf_resp = self._check_threat_feed(prompt, start_time, timings)
                if tf_resp:
                    self.brain.analyze_request(session_id, prompt, blocked=True)
                    return tf_resp
                
                # 5a. Fast-Path Blocklist (Known Malicious - High Speed Regex)
                if self.fast_path.is_known_malicious(prompt):
                    self.brain.analyze_request(session_id, prompt, blocked=True)
                    self._report_event("fast_path_block", "HIGH", {
                        "session_id": session_id,
                        "reason": "Prompt matched known malicious regex patterns.",
                        "path": path,
                    })
                    return Response("Forbidden: fast_path_keyword", status=403)

                # 5b. Fast-Path Allowlist (Known Safe - Optimization)
                if self.fast_path.is_known_safe(prompt):
                    path_taken = "fast_path_allowlist"
                
                # 6. AI Embedding Filter (Semantic Check + Context)
                else:
                    path_taken = "ai_firewall"
                    if self._is_feedback_allowlisted(tenant_id, prompt, "injection_ai"):
                        af_resp = None
                    else:
                        # NOTE: _should_defer_to_output_redaction() bypass REMOVED.
                        # Prompts matching leak/credential patterns are highest-risk inputs —
                        # they must face MORE scrutiny, not less. Output redaction still runs
                        # downstream via validate_output as an additional layer.
                        # (audit finding #5, eb180c04)
                        af_resp = self._check_ai_firewall(prompt, mode, start_time, timings, show_reason)
                    if af_resp:
                        self.brain.analyze_request(session_id, prompt, blocked=True)
                        return af_resp
                assessment = self.brain.analyze_request(session_id, prompt, blocked=False)
                action = assessment.get("action", "allow")
                if action == "revoke":
                    self.brain.enforce_revocation(session_id, reason="post_analysis_gate")
                    self._report_event("session_revoked", "HIGH", {
                        "session_id": session_id,
                        "reason": "Blue Team adaptive revoke threshold exceeded.",
                        "path": path,
                    })
                    return Response("Forbidden: Session revoked by adaptive security controls.", status=403)
                # FEAT-BLUE-ADVANCED: cooldown → 429 in post-analysis gate
                if action == "cooldown":
                    retry_after = self.brain.get_cooldown_seconds(session_id)
                    self._report_event("session_cooldown", "MEDIUM", {
                        "session_id": session_id,
                        "retry_after_seconds": retry_after,
                        "path": path,
                    })
                    return Response(
                        "Too Many Requests: Session rate-limited by adaptive security controls.",
                        status=429,
                        headers={"Retry-After": str(max(1, retry_after))},
                    )
                if action == "honeypot":
                    self._report_event("honeypot_engaged", "MEDIUM", {
                        "session_id": session_id,
                        "reason": "Blue Team adaptive honeypot threshold exceeded.",
                        "path": path,
                    })
                    resp = self._build_honeypot_response(session_id, path, prompt=prompt)
                    if resp.status_code == 403:
                        self._report_event("honeypot_rate_limited", "MEDIUM", {
                            "session_id": session_id,
                            "path": path,
                        })
                    return resp
        else:
            timings['input_process_ms'] = 0.0
            session_id = self._get_session_id()

        # Forward request
        target = f"{self.target_url}/{path}"
        logger.info(f"DEBUG: Forwarding to {target}")
        
        # Prepare headers
        # Strip Host, X-Guardian-Token (internal auth), and any other Guardian-specific headers
        fwd_headers = {
            key: value for (key, value) in request.headers 
            if key.lower() not in ('host', 'x-guardian-token')
        }
        
        # SECURITY FEATURE: Upstream Key Injection
        upstream_key = self.config.get('proxy', {}).get('upstream_key')
        if upstream_key:
            fwd_headers['Authorization'] = f"Bearer {upstream_key}"
            if "anthropic" in self.target_url:
                fwd_headers['x-api-key'] = upstream_key

        try:
            is_stream = data and data.get("stream") is True
            resp = requests.request(
                method=request.method,
                url=target,
                headers=fwd_headers,
                data=request.get_data(),
                # Cookies are stripped. Upstream LLM APIs (OpenAI, Anthropic) do not use cookies.
                # Forwarding them poses a risk of leaking unrelated client session credentials.
                cookies=None,
                allow_redirects=False,
                timeout=30,  # Prevent indefinite hangs (Increased for stability)
                stream=is_stream,
                proxies={"http": None, "https": None} # Bypass system proxies
            )
            
            if is_stream:
                def generate():
                    window = ""
                    # 500-byte margin to prevent prefix leaks of long sensitive patterns (P2-2 trade-off)
                    margin = 2048
                    for chunk in resp.iter_content(chunk_size=1, decode_unicode=True):
                        if chunk:
                            window += chunk
                            if self.config.get('security_policies', {}).get('validate_output'):
                                _, detected = self.output_validator.sanitize_output(window)
                                if detected:
                                    yield 'data: {"error": "Forbidden: Potential data leak blocked by GuardianAI."}\n\n'
                                    return
                            if len(window) > margin:
                                yield window[:-margin]
                                window = window[-margin:]
                    if window:
                        yield window
                
                from flask import stream_with_context
                return Response(stream_with_context(generate()), content_type=resp.headers.get('content-type', 'text/event-stream'))

            # Inspect output if enabled
            raw_content = resp.content.decode('utf-8', errors='ignore')
            content = raw_content
            
            was_redacted = False
            if self.config.get('security_policies', {}).get('validate_output'):
                try:
                    content = self._process_output_validation(raw_content, path, start_time, timings, tenant_id=tenant_id)
                    was_redacted = content != raw_content
                except ValueError as exc:
                    msg = str(exc)
                    if msg.startswith("Output assurance blocked:"):
                        return Response(
                            "Forbidden: Output assurance policy blocked unsafe or unverifiable model output.",
                            status=403,
                        )
                    # Blocked leak
                    return Response("Forbidden: Potential data leak blocked by GuardianAI.", status=403)

            # System Prompt Leakage Protection (OWASP LLM07)
            if self.system_prompt_guard.enabled:
                system_prompt = self._extract_system_prompt(data) if data else None
                leak_decision = self.system_prompt_guard.check_response(
                    response_text=content,
                    system_prompt=system_prompt,
                    user_prompt=prompt,
                )
                timings["system_prompt_leak_ms"] = leak_decision.score  # lightweight timing proxy
                if leak_decision.action == "block":
                    self._report_event(
                        "system_prompt_leak_blocked",
                        leak_decision.severity,
                        {
                            "path": path,
                            "reason": leak_decision.reason,
                            "score": leak_decision.score,
                            "details": leak_decision.details,
                            "component_timings": timings,
                        },
                        tenant_id=tenant_id,
                    )
                    if self.system_prompt_guard.enforcement_mode != "audit":
                        return Response(
                            "Forbidden: Potential system prompt leakage blocked by GuardianAI.",
                            status=403,
                        )

            try:
                content = self._apply_output_watermark(content, path, timings, tenant_id)
            except ValueError:
                return Response("Forbidden: Output watermark policy blocked response.", status=403)

            if self.cost_abuse.enabled:
                estimated_tokens, estimated_cost = self.cost_abuse.estimate_usage(prompt, raw_content)
                cost_decision = self.cost_abuse.register_usage(
                    session_id=session_id,
                    tokens=estimated_tokens,
                    cost_usd=estimated_cost,
                    tenant_id=tenant_id,
                )
                if cost_decision.action == "quarantine":
                    self._report_event("cost_abuse_detected", "HIGH", {
                        **cost_decision.metrics,
                        "reason": cost_decision.reason,
                        "target_path": path,
                    })
                    self._report_event("session_quarantined", "HIGH", {
                        "session_id": session_id,
                        "reason": "Quarantine activated from wallet-drain anomaly detection.",
                        "target_path": path,
                        "metrics": cost_decision.metrics,
                    })
                    return Response("Forbidden: Session quarantined due to anomalous cost activity.", status=403)
            
            # Report success telemetry (Analytics)
            if not was_redacted:
                latency_ms = (time.time() - start_time) * 1000
                self._report_event("allowed_request", "LOW", {
                    "path": path_taken,
                    "latency_ms": f"{latency_ms:.2f}ms",
                    "component_timings": timings,
                    "target_path": path
                })
            
            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection', 'server', 'x-powered-by', 'via']
            headers = [(name, value) for (name, value) in resp.raw.headers.items()
                       if name.lower() not in excluded_headers]
            
            return Response(content, resp.status_code, headers)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Proxy forwarding failed: {e}")
            return Response("Bad Gateway: Could not connect to OpenClaw Agent.", status=502)

if __name__ == "__main__":
    # Minimal config for standalone testing
    _debug_admin_token = os.environ.get("GUARDIAN_ADMIN_TOKEN", "")
    if not _debug_admin_token:
        raise SystemExit(
            "ERROR: Set GUARDIAN_ADMIN_TOKEN env var before running interceptor.py directly.\n"
            "  Example: $env:GUARDIAN_ADMIN_TOKEN = (python -c \"import secrets; print(secrets.token_hex(32))\")"
        )
    test_config = {
        "guardian_id": "test-guardian",
        "proxy": {
            "listen_port": 8081,
            "target_url": "http://localhost:8080"
        },
        "rate_limiting": {
            "enabled": True,
            "requests_per_minute": 60
        },
        "security_policies": {
            "security_mode": "balanced",
            "validate_output": True, # Required for PII Check
            "leak_prevention_strategy": "redact",
            "admin_token": _debug_admin_token,  # sourced from env — audit finding #7
        },
        "backend": {
            "enabled": True,
            "url": "http://127.0.0.1:8001/api/v1/telemetry"
        }
    }
    
    logging.basicConfig(level=logging.INFO)
    proxy = GuardianProxy(test_config)
    # Run in main thread for debugging
    proxy._run_server()


