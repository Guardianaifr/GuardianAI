from flask import Flask, request, Response
import requests
import threading
import logging
import time
import re
import collections
import json
from typing import Dict, Any, List, Optional
from guardrails.input_filter import InputFilter
from guardrails.output_validator import OutputValidator
from guardrails.ai_firewall import AIPromptFirewall
from guardrails.fast_path import FastPath
from guardrails.rate_limiter import RateLimiter
from guardrails.threat_feed import ThreatFeed
from guardrails.base64_detector import Base64Detector

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
        self.input_filter = InputFilter()
        self.output_validator = OutputValidator()
        self.ai_firewall = AIPromptFirewall()
        self.fast_path = FastPath()
        self.base64_detector = Base64Detector()
        
        # Rate Limiting
        rl_config = config.get('rate_limiting', {})
        self.rate_limiter = RateLimiter(requests_per_minute=rl_config.get('requests_per_minute', 60))
        
        # Threat Feed
        tf_config = config.get('threat_feed', {})
        self.threat_feed = ThreatFeed(
            feed_url=tf_config.get('url') if tf_config.get('enabled') else None,
            update_interval=tf_config.get('update_interval_seconds', 3600)
        )
        
        # Multi-turn Context Buffer (per IP/Session)
        self.context_buffer = collections.defaultdict(lambda: collections.deque(maxlen=5))
        
        # Register routes
        self.app.add_url_rule('/health', view_func=self.health_check, methods=['GET'])
        self.app.add_url_rule('/api/reload-model', view_func=self.reload_model, methods=['POST'])
        self.app.add_url_rule('/', defaults={'path': ''}, view_func=self.proxy, methods=['GET', 'POST', 'PUT', 'DELETE'])
        self.app.add_url_rule('/<path:path>', view_func=self.proxy, methods=['GET', 'POST', 'PUT', 'DELETE'])

        self._thread = None
        self.last_debug_info = {}
        self._input_filter_cache = collections.OrderedDict()
        self._input_filter_cache_size = 2000

    def health_check(self):
        return {"status": "ok", "component": "guardian_proxy"}

    def reload_model(self):
        """Endpoint to hot-reload the AI model and jailbreak vectors."""
        logger.info("RELOAD REQUEST: Hot-reloading AI firewall...")
        try:
            self.ai_firewall.reload()
            return Response("Success: AI Firewall hot-reloaded.", status=200)
        except Exception as e:
            logger.error(f"Hot-reload failed: {e}")
            return Response(f"Error: {e}", status=500)

    # DEBUGGING STATE
    # DEBUGGING STATE


    def _update_debug_info(self, info: Dict):
        self.last_debug_info = info

    def debug_info(self):
        return Response(json.dumps(self.last_debug_info, default=str), mimetype='application/json')

    def start(self):
        """
        Starts the GuardianAI proxy server in a background daemon thread.
        This allows the main thread to remain responsive or monitor the proxy.
        """
        if self._thread is not None:
            return
        logger.info(f"Starting Interceptor Proxy on port {self.port} -> {self.target_url}")
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()

    def _run_server(self):
        """
        Internal method to run the Flask development server.
        """
        # Disable Flask banner
        import sys
        try:
            cli = sys.modules['flask.cli']
            cli.show_server_banner = lambda *x: None
        except (KeyError, AttributeError) as e:
            # Flask CLI module not available or attribute missing
            logger.debug(f"Could not disable Flask banner: {e}")
        try:
            logger.info(f"Flask application starting on 127.0.0.1:{self.port}...")
            # DEBUG ROUTE
            self.app.add_url_rule('/debug/info', view_func=self.debug_info, methods=['GET'])
            self.app.run(host='127.0.0.1', port=self.port, debug=False, use_reloader=False)
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
        
        if not self.rate_limiter.is_allowed(request.remote_addr):
            logger.warning(f"Rate limit exceeded for {request.remote_addr}")
            latency_ms = (time.time() - start_time) * 1000
            self._report_event("rate_limit", "HIGH", {
                "reason": "Rate limit exceeded.",
                "path": "rate_limit",
                "target_path": path,
                "ip": request.remote_addr,
                "latency_ms": f"{latency_ms:.2f}ms",
            })
            return Response("Too Many Requests: Rate limit exceeded.", status=429)
        
        return None

    def _check_authentication(self, start_time: float, path: str) -> Optional[Response]:
        """Verify authentication for the proxy request.
        
        Returns:
            Response object if unauthorized, None if authorized.
        """
        proxy_config = self.config.get('proxy', {})
        if not proxy_config.get('enforce_auth', False):
            return None

        request_token = request.headers.get("X-Guardian-Token")
        required_token = proxy_config.get('proxy_token')
        admin_token = self.config.get('security_policies', {}).get('admin_token')

        # Allow if it matches either proxy token OR admin token
        if request_token and (request_token == required_token or (admin_token and request_token == admin_token)):
            return None

        # Auth failed
        latency_ms = (time.time() - start_time) * 1000
        logger.warning(f"🔐  UNAUTHORIZED ACCESS: Invalid or missing token from {request.remote_addr} for /{path}")
        
        self._report_event("unauthorized_access", "MEDIUM", {
            "path": path,
            "ip": request.remote_addr,
            "latency_ms": f"{latency_ms:.2f}ms",
            "reason": "Missing or invalid X-Guardian-Token"
        })
        
        return Response("Unauthorized: Valid X-Guardian-Token is required.", status=401)
    
    def _extract_prompt(self, data: Dict) -> Optional[str]:
        """Extract prompt from request data (supports multiple formats).
        
        Args:
            data: Request JSON data
            
        Returns:
            Extracted prompt string or None
        """
        if not data:
            return None
        
        # Try direct prompt fields
        prompt = data.get('prompt') or data.get('input') or data.get('content')
        
        # Try OpenAI messages format
        if not prompt and 'messages' in data:
            messages = data.get('messages', [])
            for msg in reversed(messages):
                if msg.get('role') == 'user':
                    prompt = msg.get('content', '')
                    break
        
        return prompt if isinstance(prompt, str) else None
    
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
        
        logger.warning(f"ðŸš«  ATTACK PREVENTED: {reason} (Prompt: {prompt[:30]}...)")
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
        """Check prompt against community threat feed patterns."""
        t_start = time.perf_counter()
        
        for pattern in self.threat_feed.patterns:
            if re.search(pattern, prompt, re.IGNORECASE):
                timings['threat_feed_ms'] = (time.perf_counter() - t_start) * 1000
                path_taken = "fast_path_threat_feed"
                reason = "Blocked by Community Threat Feed."
                latency_ms = (time.time() - start_time) * 1000
                
                logger.warning(f"ðŸš«  ATTACK PREVENTED: {reason} (Prompt: {prompt[:30]}...)")
                self._report_event("threat_feed_match", "HIGH", {
                    "prompt_preview": prompt[:100],
                    "reason": reason,
                    "latency_ms": f"{latency_ms:.2f}ms",
                    "component_timings": timings,
                    "path": path_taken
                })
                return Response(f"Forbidden: {reason}", status=403)
        
        timings['threat_feed_ms'] = (time.perf_counter() - t_start) * 1000
        return None
    
    def _check_ai_firewall(self, prompt: str, mode: str, start_time: float, timings: Dict[str, float], show_reason: bool = True) -> Optional[Response]:
        """Check prompt using AI semantic analysis."""
        t_start = time.perf_counter()
        path_taken = "ai_firewall"
        
        # Context tracking: Prefer X-Conversation-ID for NAT/VPN environments
        session_id = request.headers.get('X-Conversation-ID') or request.remote_addr
        self.context_buffer[session_id].append(prompt)
        full_context = " ".join(self.context_buffer[session_id])

        # Adaptive Security: If under high rate-limit pressure, force 'strict' mode
        pressure = self.rate_limiter.get_pressure(session_id)
        if pressure < 0.2:
            logger.info(f"High pressure detected ({pressure:.2f}). Scaling up to STRICT mode for session: {session_id}")
            mode = "strict"
        
        # Smart Adaptation: If downstream is unknown/unhealthy, slightly tighten security
        try:
            health_check = requests.get(f"{self.target_url}/health", timeout=1)
            if health_check.status_code != 200:
                logger.debug("Downstream agent unhealthy. Applying defensive Balanced+ posture.")
                if mode == "balanced":
                    mode = "strict"
        except requests.RequestException as e:
            logger.debug(f"Health check failed: {e}")

        is_malicious = self.ai_firewall.is_malicious(full_context, mode=mode)
        timings['ai_firewall_ms'] = (time.perf_counter() - t_start) * 1000

        if is_malicious:
            reason = f"AI Firewall detected malicious intent (Mode: {mode})."
            latency_ms = (time.time() - start_time) * 1000
            logger.warning(f"ðŸš«  ATTACK PREVENTED: {reason} (Prompt: {prompt[:30]}...)")
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
    
    def _process_output_validation(self, raw_content: str, path: str, start_time: float, timings: Dict[str, float]) -> str:
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

        # 1. Check for HARD block (Critical leaks)
        is_valid = self.output_validator.validate_output(content_to_check)
        
        if not is_valid:
            strategy = self.config.get('security_policies', {}).get('leak_prevention_strategy', 'block')
            
            if strategy == "block":
                logger.warning("ðŸš¨  DATA LEAK PREVENTED: Sensitive information detected in agent output. Blocking response.")
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
                logger.warning("ðŸ›¡ï¸  DATA LEAK DETECTED: Redacting sensitive information (Privacy Strategy: REDACT).")
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

    def _report_event(self, event_type: str, severity: str, details: Dict[str, Any]):
        backend_config = self.config.get('backend', {})
        if not backend_config.get('enabled'):
            return
        
        payload = {
            "guardian_id": self.config.get('guardian_id', 'unknown'),
            "event_type": event_type,
            "severity": severity,
            "details": details,
            "timestamp": time.time()
        }
        
        def send_report():
            try:
                requests.post(backend_config.get('url'), json=payload, timeout=5)
            except Exception as e:
                logger.error(f"Failed to report event to backend: {e}")

        # Non-blocking background report
        threading.Thread(target=send_report, daemon=True).start()

    def proxy(self, path):
        start_time = time.time()
        timings = {}
        logger.info(f"DEBUG: Proxy received request for /{path}")
        
        # 1. Rate Limiting Check
        rl_resp = self._check_rate_limit(start_time, path)
        if rl_resp:
            return rl_resp

        # 1b. Authentication Check (Milestone 1: Universal Auth Proxy)
        auth_resp = self._check_authentication(start_time, path)
        if auth_resp:
            return auth_resp

        path_taken = "fast_path_allowlist" # Default path

        # 2. Inspect input
        data = None
        prompt = None
        raw_len = 0
        
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

        if data:
            prompt = self._extract_prompt(data)
            logger.debug(f"DEBUG: Extracted prompt: {str(prompt)[:50] if prompt else 'None'}")

        # DEBUG INFO UPDATE
        self._update_debug_info({
            "path": path,
            "method": request.method,
            "content_type": request.content_type,
            "raw_len": raw_len,
            "data_parsed": bool(data),
            "data_keys": list(data.keys()) if isinstance(data, dict) else str(type(data)),
            "prompt_extracted": prompt,
            "headers": dict(request.headers)
        })

        if prompt:
            policies = self.config.get('security_policies', {})
            mode = policies.get('security_mode', 'balanced')
            show_reason = policies.get('show_block_reason', True)

            # 0. Admin Policy Bypass (Trusted Agent)
            admin_token = policies.get('admin_token')
            request_token = request.headers.get("X-Guardian-Token")
            
            if request.headers.get("X-Guardian-Role") == "admin":
                if admin_token and request_token == admin_token:
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
                    logger.warning(f"ðŸ›‘  ADMIN FAIL: Invalid or missing token from {request.remote_addr}. ConfigToken={admin_token}, ReqToken={request_token}")
                    # Fall through to normal checks (don't block, just treat as untrusted)
            
            if path_taken != "admin_allowlist":
                # 3. Fast Keyword/Regex Filter (Known Bad)
                kw_resp = self._check_keyword_filter(prompt, start_time, timings, show_reason)
                if kw_resp:
                    return kw_resp
                
                # 3b. Base64 Obfuscation Check (Segment 4)
                if self.base64_detector.is_suspicious(prompt, entropy_threshold=5.0):
                    reason = "Obfuscated payload detected (Base64/High Entropy)."
                    logger.warning(f"ðŸš«  ATTACK PREVENTED: {reason}")
                    self._report_event("obfuscation", "MEDIUM", {
                        "prompt_preview": "HIDDEN_BASE64_PAYLOAD",
                        "reason": reason,
                        "path": "base64_filter"
                    })
                    return Response(f"Forbidden: {reason}", status=403)
                
                # 4. Community Threat Feed Check (Dynamic)
                tf_resp = self._check_threat_feed(prompt, start_time, timings)
                if tf_resp:
                    return tf_resp
                
                # 5. Fast-Path Allowlist (Known Safe - Optimization)
                if self.fast_path.is_known_safe(prompt):
                    path_taken = "fast_path_allowlist"
                
                # 6. AI Embedding Filter (Semantic Check + Context)
                else:
                    path_taken = "ai_firewall"
                    af_resp = self._check_ai_firewall(prompt, mode, start_time, timings, show_reason)
                    if af_resp:
                        return af_resp
        else:
            timings['input_process_ms'] = 0.0

        # Forward request
        target = f"{self.target_url}/{path}"
        logger.info(f"DEBUG: Forwarding to {target}")
        
        # Prepare headers
        fwd_headers = {key: value for (key, value) in request.headers if key != 'Host'}
        
        # SECURITY FEATURE: Upstream Key Injection
        upstream_key = self.config.get('proxy', {}).get('upstream_key')
        if upstream_key:
            fwd_headers['Authorization'] = f"Bearer {upstream_key}"
            if "anthropic" in self.target_url:
                fwd_headers['x-api-key'] = upstream_key

        try:
            resp = requests.request(
                method=request.method,
                url=target,
                headers=fwd_headers,
                data=request.get_data(),
                cookies=request.cookies,
                allow_redirects=False,
                timeout=30,  # Prevent indefinite hangs (Increased for stability)
                proxies={"http": None, "https": None} # Bypass system proxies
            )
            
            # Inspect output if enabled
            raw_content = resp.content.decode('utf-8', errors='ignore')
            content = raw_content
            
            was_redacted = False
            if self.config.get('security_policies', {}).get('validate_output'):
                try:
                    content = self._process_output_validation(raw_content, path, start_time, timings)
                    was_redacted = content != raw_content
                except ValueError:
                    # Blocked leak
                    return Response("Forbidden: Potential data leak blocked by GuardianAI.", status=403)
            
            # Report success telemetry (Analytics)
            if not was_redacted:
                latency_ms = (time.time() - start_time) * 1000
                self._report_event("allowed_request", "LOW", {
                    "path": path_taken,
                    "latency_ms": f"{latency_ms:.2f}ms",
                    "component_timings": timings,
                    "target_path": path
                })
            
            excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection']
            headers = [(name, value) for (name, value) in resp.raw.headers.items()
                       if name.lower() not in excluded_headers]
            
            return Response(content, resp.status_code, headers)
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Proxy forwarding failed: {e}")
            return Response("Bad Gateway: Could not connect to OpenClaw Agent.", status=502)

if __name__ == "__main__":
    # Minimal config for standalone testing
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
            "leak_prevention_strategy": "redact"
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

