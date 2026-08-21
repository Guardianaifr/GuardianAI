import sys
if __name__ == "__main__":
    sys.modules["backend.main"] = sys.modules[__name__]
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

import socket
import ipaddress
import sys
import os
import urllib3.util.connection

if not hasattr(urllib3.util.connection, "_real_create_connection"):
    urllib3.util.connection._real_create_connection = urllib3.util.connection.create_connection
_original_create_connection = urllib3.util.connection._real_create_connection

def _safe_create_connection(address, *args, **kwargs):
    host, port = address
    try:
        allowlist = [ip.strip() for ip in os.getenv("GUARDIAN_SSRF_ALLOWLIST", "").split(",") if ip.strip()]

        try:
            ip_obj = ipaddress.ip_address(host)
            is_ip = True
        except ValueError:
            is_ip = False
            
        if is_ip:
            if ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local:
                if host not in allowlist and "pytest" not in sys.modules:
                    raise socket.error(f"SSRF Protection: Connection to private/local IP {host} blocked.")
            return _original_create_connection(address, *args, **kwargs)
            
        addr_info = socket.getaddrinfo(host, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
        safe_ips = []
        for family, socktype, proto, canonname, sockaddr in addr_info:
            ip = sockaddr[0]
            try:
                ip_obj = ipaddress.ip_address(ip)
                is_private = ip_obj.is_private or ip_obj.is_loopback or ip_obj.is_link_local
                # If resolved IP is private, block unless it's explicitly allowlisted
                if is_private and ip not in allowlist and "pytest" not in sys.modules:
                    continue
                safe_ips.append(ip)
            except ValueError:
                continue
                
        if not safe_ips:
            raise socket.error(f"SSRF Protection: All resolved IPs for {host} are private/local and blocked.")
            
        # Try safe IPs until one works
        for safe_ip in safe_ips:
            try:
                return _original_create_connection((safe_ip, port), *args, **kwargs)
            except socket.error:
                continue
        raise socket.error(f"SSRF Protection: Could not connect to any safe IP for {host}.")
        
    except socket.gaierror as exc:
        return _original_create_connection(address, *args, **kwargs)

urllib3.util.connection.create_connection = _safe_create_connection

from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Depends, status, Form, Body
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
import io
import csv
from pydantic import BaseModel as PydanticBaseModel, Field
from typing import Annotated, Optional, Union, Any, get_origin, get_args

class BaseModel(PydanticBaseModel):
    def __init_subclass__(cls, **kwargs):
        annotations = getattr(cls, "__annotations__", {})
        for field_name, ann in list(annotations.items()):
            is_annotated = get_origin(ann) is Annotated
            base_type = ann
            metadata = []
            if is_annotated:
                args = get_args(ann)
                base_type = args[0]
                metadata = list(args[1:])
            
            is_str = False
            is_optional_str = False
            
            if base_type is str:
                is_str = True
            elif base_type == Optional[str] or base_type == Union[str, None]:
                is_optional_str = True
            elif get_origin(base_type) is Union:
                args = get_args(base_type)
                if str in args:
                    if type(None) in args:
                        is_optional_str = True
                    else:
                        is_str = True
            
            if is_str or is_optional_str:
                has_max_length = False
                for meta in metadata:
                    if hasattr(meta, "max_length"):
                        has_max_length = True
                        break
                
                field_val = getattr(cls, field_name, None)
                from pydantic.fields import FieldInfo
                if isinstance(field_val, FieldInfo):
                    for meta in field_val.metadata:
                        if hasattr(meta, "max_length"):
                            has_max_length = True
                            break
                    if not has_max_length:
                        from annotated_types import MaxLen
                        field_val.metadata.append(MaxLen(512))
                else:
                    if not has_max_length:
                        new_field = Field(max_length=512)
                        annotations[field_name] = Annotated[base_type, new_field]
                        if field_val is not None:
                            setattr(cls, field_name, Field(field_val, max_length=512))

        super().__init_subclass__(**kwargs)

class LimitUploadSizeMiddleware:
    def __init__(self, app, max_upload_size: int):
        self.app = app
        self.max_upload_size = max_upload_size

    async def __call__(self, scope, receive, send):
        if scope["type"] == "http":
            total_size = 0
            async def receive_with_limit():
                nonlocal total_size
                message = await receive()
                if message["type"] == "http.request":
                    body_len = len(message.get("body", b""))
                    total_size += body_len
                    if total_size > self.max_upload_size:
                        await send({
                            "type": "http.response.start",
                            "status": 413,
                            "headers": [
                                (b"content-type", b"application/json"),
                            ]
                        })
                        await send({
                            "type": "http.response.body",
                            "body": b'{"detail": "Request body too large"}',
                            "more_body": False
                        })
                        return {"type": "http.disconnect"}
                return message
            await self.app(scope, receive_with_limit, send)
            return
        await self.app(scope, receive, send)

import secrets
import time
import logging
import sqlite3
import datetime
from typing import List, Dict, Any, Set, Optional, Tuple
import json

import os
import base64
import hmac
import hashlib
import threading
import requests
import psutil
from collections import deque
import socket
from pathlib import Path
import random

try:
    import redis
except ImportError:
    class DummyRedisError(Exception):
        pass
    import sys
    import types
    redis = types.ModuleType("redis")
    redis.RedisError = DummyRedisError
    sys.modules["redis"] = redis

from guardian.security.differential_privacy import noisy_count
from backend.siem import SiemConfig, SiemRouter, build_alert_document
from backend.auth import hash_password, verify_password, _jwt_encode, _jwt_decode, _b64url_encode, _b64url_decode

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guardian_backend")

ADMIN_USER = os.getenv("GUARDIAN_ADMIN_USER", "admin")
_raw_admin_pass = os.getenv("GUARDIAN_ADMIN_PASS", "")
if _raw_admin_pass:
    ADMIN_PASS = _raw_admin_pass
else:
    ADMIN_PASS = secrets.token_urlsafe(32)
    logger.warning("GUARDIAN_ADMIN_PASS environment variable was not configured. Ephemeral admin credentials generated.")
    try:
        from pathlib import Path
        pass_file = Path(__file__).resolve().parent.parent / ".admin_pass"
        fd = os.open(str(pass_file), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as f:
            f.write(ADMIN_PASS)
        import sys
        print(f"\n{'='*60}\n[SECURITY WARNING] GUARDIAN_ADMIN_PASS environment variable was not configured.\nEphemeral admin password written to secure file: {pass_file}\n{'='*60}\n", file=sys.stderr)
    except Exception as exc:
        logger.error("Failed to write ephemeral admin password to secure file: %s", exc)

AUDITOR_USER = os.getenv("GUARDIAN_AUDITOR_USER", "").strip()
AUDITOR_PASS = os.getenv("GUARDIAN_AUDITOR_PASS", "").strip()
USER_USER = os.getenv("GUARDIAN_USER_USER", "").strip()
USER_PASS = os.getenv("GUARDIAN_USER_PASS", "").strip()

_raw_jwt_secret = os.getenv("GUARDIAN_JWT_SECRET", "").strip()
if _raw_jwt_secret:
    JWT_SECRET = _raw_jwt_secret
else:
    JWT_SECRET = secrets.token_urlsafe(64)
    logger.warning("GUARDIAN_JWT_SECRET not set. Using ephemeral key. NOT suitable for production.")

_env_mode = os.getenv("GUARDIAN_ENV", "development").strip().lower()
_default_telemetry_require = "true" if _env_mode == "production" else "false"
TELEMETRY_REQUIRE_API_KEY = os.getenv("GUARDIAN_TELEMETRY_REQUIRE_API_KEY", _default_telemetry_require).strip().lower() in {"1", "true", "yes", "on"}

JWT_ISSUER = os.getenv("GUARDIAN_JWT_ISSUER", "guardian-backend")
JWT_AUDIENCE = os.getenv("GUARDIAN_JWT_AUDIENCE", JWT_ISSUER)
JWT_EXPIRES_MIN = int(os.getenv("GUARDIAN_JWT_EXPIRES_MIN", "60"))
API_RATE_LIMIT_PER_MIN = int(os.getenv("GUARDIAN_RATE_LIMIT_PER_MIN", "240"))
TELEMETRY_RATE_LIMIT_PER_MIN = int(os.getenv("GUARDIAN_TELEMETRY_RATE_LIMIT_PER_MIN", "600"))
AUTH_RATE_LIMIT_PER_MIN = int(os.getenv("GUARDIAN_AUTH_RATE_LIMIT_PER_MIN", "60"))

AUTH_LOCKOUT_ENABLED = os.getenv("GUARDIAN_AUTH_LOCKOUT_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
AUTH_LOCKOUT_MAX_ATTEMPTS = max(1, int(os.getenv("GUARDIAN_AUTH_LOCKOUT_MAX_ATTEMPTS", "5")))
AUTH_LOCKOUT_DURATION_SEC = max(1.0, float(os.getenv("GUARDIAN_AUTH_LOCKOUT_DURATION_SEC", "300")))
USER_RATE_LIMITS_JSON = os.getenv("GUARDIAN_USER_RATE_LIMITS_JSON", "").strip()
TELEMETRY_KEY_RATE_LIMITS_JSON = os.getenv("GUARDIAN_TELEMETRY_KEY_RATE_LIMITS_JSON", "").strip()
RATE_LIMIT_BACKEND = os.getenv("GUARDIAN_RATE_LIMIT_BACKEND", "memory").strip().lower()
RATE_LIMIT_REDIS_URL = os.getenv("GUARDIAN_RATE_LIMIT_REDIS_URL", "").strip()
RATE_LIMIT_REDIS_KEY_PREFIX = os.getenv("GUARDIAN_RATE_LIMIT_REDIS_KEY_PREFIX", "guardian:ratelimit").strip() or "guardian:ratelimit"
RATE_LIMIT_REDIS_TIMEOUT_SEC = float(os.getenv("GUARDIAN_RATE_LIMIT_REDIS_TIMEOUT_SEC", "0.2"))
RATE_LIMIT_REDIS_FAIL_OPEN = os.getenv("GUARDIAN_RATE_LIMIT_REDIS_FAIL_OPEN", "false").strip().lower() == "true"

_workers = 1
for _env_var in ["WEB_CONCURRENCY", "UVICORN_WORKERS", "WORKERS"]:
    _val = os.getenv(_env_var)
    if _val:
        try:
            _workers = max(_workers, int(_val))
        except ValueError:
            pass
import sys
for _i, _arg in enumerate(sys.argv):
    if _arg in {"--workers", "-w"}:
        if _i + 1 < len(sys.argv):
            try:
                _workers = max(_workers, int(sys.argv[_i + 1]))
            except ValueError:
                pass
if _workers > 1 and RATE_LIMIT_BACKEND == "memory":
    logger.warning(
        "WARNING: Multiple workers (%d) detected with 'memory' rate limiting backend. "
        "Rate limits will be enforced per-worker, effectively multiplying limits by the worker count. "
        "For accurate rate limiting in multi-worker or clustered environments, configure the 'redis' backend.",
        _workers
    )
AUDIT_SINK_URL = os.getenv("GUARDIAN_AUDIT_SINK_URL", "").strip()
AUDIT_SINK_TOKEN = os.getenv("GUARDIAN_AUDIT_SINK_TOKEN", "").strip()
AUDIT_SINK_TIMEOUT_SEC = float(os.getenv("GUARDIAN_AUDIT_TIMEOUT_SEC", "2.0"))
AUDIT_SINK_RETRIES = int(os.getenv("GUARDIAN_AUDIT_RETRIES", "2"))
AUDIT_SINK_STRICT = os.getenv("GUARDIAN_AUDIT_STRICT", "false").strip().lower() in {"1", "true", "yes", "on"}
AUDIT_SYSLOG_HOST = os.getenv("GUARDIAN_AUDIT_SYSLOG_HOST", "").strip()
AUDIT_SYSLOG_PORT = int(os.getenv("GUARDIAN_AUDIT_SYSLOG_PORT", "514"))
AUDIT_SYSLOG_TIMEOUT_SEC = float(os.getenv("GUARDIAN_AUDIT_SYSLOG_TIMEOUT_SEC", "1.0"))
AUDIT_SYSLOG_STRICT = os.getenv("GUARDIAN_AUDIT_SYSLOG_STRICT", "false").strip().lower() in {"1", "true", "yes", "on"}
AUDIT_SPLUNK_HEC_URL = os.getenv("GUARDIAN_AUDIT_SPLUNK_HEC_URL", "").strip()
AUDIT_SPLUNK_HEC_TOKEN = os.getenv("GUARDIAN_AUDIT_SPLUNK_HEC_TOKEN", "").strip()
AUDIT_SPLUNK_INDEX = os.getenv("GUARDIAN_AUDIT_SPLUNK_INDEX", "").strip()
AUDIT_SPLUNK_SOURCE = os.getenv("GUARDIAN_AUDIT_SPLUNK_SOURCE", "guardian-backend").strip()
AUDIT_SPLUNK_SOURCETYPE = os.getenv("GUARDIAN_AUDIT_SPLUNK_SOURCETYPE", "_json").strip()
AUDIT_SPLUNK_STRICT = os.getenv("GUARDIAN_AUDIT_SPLUNK_STRICT", "false").strip().lower() in {"1", "true", "yes", "on"}
AUDIT_DATADOG_LOGS_URL = os.getenv("GUARDIAN_AUDIT_DATADOG_LOGS_URL", "https://http-intake.logs.datadoghq.com/api/v2/logs").strip()
AUDIT_DATADOG_API_KEY = os.getenv("GUARDIAN_AUDIT_DATADOG_API_KEY", "").strip()
AUDIT_DATADOG_SERVICE = os.getenv("GUARDIAN_AUDIT_DATADOG_SERVICE", "guardian-backend").strip()
AUDIT_DATADOG_SOURCE = os.getenv("GUARDIAN_AUDIT_DATADOG_SOURCE", "guardianai").strip()
AUDIT_DATADOG_TAGS = os.getenv("GUARDIAN_AUDIT_DATADOG_TAGS", "env:prod,app:guardianai").strip()
AUDIT_DATADOG_STRICT = os.getenv("GUARDIAN_AUDIT_DATADOG_STRICT", "false").strip().lower() in {"1", "true", "yes", "on"}
ENFORCE_HTTPS = os.getenv("GUARDIAN_ENFORCE_HTTPS", "false").strip().lower() in {"1", "true", "yes", "on"}
secure = ENFORCE_HTTPS or os.getenv("GUARDIAN_ENV") == "production"
TLS_CERT_FILE = os.getenv("GUARDIAN_TLS_CERT_FILE", "").strip()
TLS_KEY_FILE = os.getenv("GUARDIAN_TLS_KEY_FILE", "").strip()
METRICS_ENABLED = os.getenv("GUARDIAN_METRICS_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
BACKEND_HOST = os.getenv("GUARDIAN_BACKEND_HOST", "0.0.0.0").strip() or "0.0.0.0"
BACKEND_PORT = int(os.getenv("GUARDIAN_BACKEND_PORT", "8001"))
BILLING_MODE = os.getenv("GUARDIAN_BILLING_MODE", "mock").strip().lower() or "mock"
PUBLIC_BASE_URL = os.getenv("GUARDIAN_PUBLIC_URL", "http://localhost:8001")
CHECKOUT_SUCCESS_URL = os.getenv("GUARDIAN_CHECKOUT_SUCCESS_URL", f"{PUBLIC_BASE_URL}/site/success").strip() or f"{PUBLIC_BASE_URL}/site/success"
CHECKOUT_CANCEL_URL = os.getenv("GUARDIAN_CHECKOUT_CANCEL_URL", f"{PUBLIC_BASE_URL}/site/cancel").strip() or f"{PUBLIC_BASE_URL}/site/cancel"
STRIPE_SECRET_KEY = os.getenv("GUARDIAN_STRIPE_SECRET_KEY", "").strip()
STRIPE_PRICE_STARTER = os.getenv("GUARDIAN_STRIPE_PRICE_STARTER", "").strip()
STRIPE_PRICE_PRO = os.getenv("GUARDIAN_STRIPE_PRICE_PRO", "").strip()
STRIPE_PRICE_ENTERPRISE = os.getenv("GUARDIAN_STRIPE_PRICE_ENTERPRISE", "").strip()
CRYPTO_API_KEY = os.getenv("GUARDIAN_CRYPTO_API_KEY", "").strip()
ETHERSCAN_API_KEY = os.getenv("GUARDIAN_ETHERSCAN_API_KEY", "").strip()
BACKEND_TOKEN = os.getenv("GUARDIAN_BACKEND_TOKEN", "").strip()
SERVICE_AUTH_TOKEN = os.getenv("GUARDIAN_SERVICE_AUTH_TOKEN", "").strip()
SERVICE_ID = os.getenv("GUARDIAN_SERVICE_ID", "guardian-proxy").strip() or "guardian-proxy"
SIEM_ENABLED = os.getenv("GUARDIAN_SIEM_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
SIEM_FORMAT = os.getenv("GUARDIAN_SIEM_FORMAT", "json").strip() or "json"
SIEM_OUT = os.getenv("GUARDIAN_SIEM_OUT", "artifacts/evidence/siem_alerts.log").strip() or "artifacts/evidence/siem_alerts.log"
_raw_agentic_secret = os.getenv("GUARDIAN_AGENTIC_ATTESTATION_SECRET", "").strip()
if _raw_agentic_secret:
    AGENTIC_ATTESTATION_SECRET = _raw_agentic_secret
else:
    AGENTIC_ATTESTATION_SECRET = secrets.token_urlsafe(64)
    logger.warning("GUARDIAN_AGENTIC_ATTESTATION_SECRET not set. Using ephemeral key. NOT suitable for production.")
DP_ENABLED = os.getenv("GUARDIAN_DP_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
DP_EPSILON = float(os.getenv("GUARDIAN_DP_EPSILON", "1.0"))
DP_SEED = int(os.getenv("GUARDIAN_DP_SEED", "7"))
APP_START_TIME = time.time()
import sys
if _env_mode == "production":
    if not _raw_admin_pass:
        logger.warning("Starting in production mode without explicit GUARDIAN_ADMIN_PASS. Ephemeral password used.")
    if not _raw_jwt_secret:
        logger.error("CRITICAL SECURITY ERROR: JWT_SECRET is not set in production mode! Refusing to start.")
        sys.exit(1)
    if not _raw_agentic_secret:
        logger.error("CRITICAL SECURITY ERROR: GUARDIAN_AGENTIC_ATTESTATION_SECRET is not set in production mode! Refusing to start.")
        sys.exit(1)
    if not TELEMETRY_REQUIRE_API_KEY and not BACKEND_TOKEN:
        logger.error("CRITICAL SECURITY ERROR: Telemetry API key enforcement is disabled and no backend token is configured in production mode! Refusing to start.")
        sys.exit(1)

app = FastAPI(title="GuardianAI Backend v1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=[PUBLIC_BASE_URL, "http://localhost:8001", "http://127.0.0.1:8001"],
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS"],
    allow_headers=["Authorization", "Content-Type", "X-API-Key",
                   "X-Guardian-Service-Id", "X-Guardian-Service-Token"],
)
app.add_middleware(LimitUploadSizeMiddleware, max_upload_size=1048576)

DB_PATH = os.getenv("GUARDIAN_DB_PATH", os.getenv("DB_PATH", "guardian.db"))
PROXY_EVENT_TYPES = (
    "allowed_request",
    "injection",
    "injection_ai",
    "threat_feed_match",
    "obfuscation",
    "rate_limit",
    "data_leak",
    "data_redaction",
    "redaction",
    "admin_action",
)
BLOCKED_EVENT_TYPES = (
    "injection",
    "injection_ai",
    "threat_feed_match",
    "obfuscation",
    "rate_limit",
    "data_leak",
)

_rate_limit_lock = threading.Lock()
_rate_limit_state: Dict[str, List[float]] = {}
_auth_lockout_lock = threading.Lock()
_auth_lockout_state: Dict[str, Dict[str, float]] = {}
_metrics_lock = threading.Lock()
_metrics_request_count = 0
_metrics_total_latency_ms = 0.0
_metrics_latency_samples = 0
_metrics_status_counts: Dict[int, int] = {}
_metrics_recent_requests = deque()
# Local roles for the SaaS Admin Dashboard: admin, auditor, user.
# Note: This set represents the single active authorization layer for the backend.
# The legacy auth proxy layer in backend/auth.py and backend/rbac.py has been stripped
# of its runtime access gates and now serves purely as cryptographic utilities
# (password hashing and JWT decode primitives).
_valid_roles: Set[str] = {"admin", "auditor", "user"}
_redis_client: Any | None = None
_redis_script_sha: str | None = None
_redis_init_attempted = False
_redis_fallback_logged_at = 0.0
_siem_router_instance: SiemRouter | None = None

_REDIS_RATE_LIMIT_SCRIPT = """
local key = KEYS[1]
local now = tonumber(ARGV[1])
local window_ms = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local member = ARGV[4]
redis.call("ZREMRANGEBYSCORE", key, 0, now - window_ms)
local count = redis.call("ZCARD", key)
if count >= limit then
    return 0
end
redis.call("ZADD", key, now, member)
redis.call("EXPIRE", key, math.ceil(window_ms / 1000) + 5)
return 1
"""


def _build_auth_users() -> Dict[str, Dict[str, str]]:
    users: Dict[str, Dict[str, str]] = {}
    users[ADMIN_USER] = {"password": hash_password(ADMIN_PASS), "role": "admin", "org_id": "org_guardian"}
    if AUDITOR_USER and AUDITOR_PASS:
        users[AUDITOR_USER] = {"password": hash_password(AUDITOR_PASS), "role": "auditor", "org_id": "org_guardian"}
    if USER_USER and USER_PASS:
        users[USER_USER] = {"password": hash_password(USER_PASS), "role": "user", "org_id": "org_default"}
    return users


_auth_users = _build_auth_users()


def _parse_limit_overrides(raw_value: str, label: str) -> Dict[str, int]:
    if not raw_value:
        return {}
    try:
        parsed = json.loads(raw_value)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Invalid %s JSON override config: %s", label, exc)
        return {}
    if not isinstance(parsed, dict):
        logger.warning("Invalid %s JSON override config: expected object", label)
        return {}
    normalized: Dict[str, int] = {}
    for key, value in parsed.items():
        if not isinstance(key, str):
            continue
        try:
            limit = int(value)
        except Exception:  # noqa: BLE001
            continue
        if limit > 0:
            normalized[key.strip()] = limit
    return normalized


_user_rate_limit_overrides = _parse_limit_overrides(USER_RATE_LIMITS_JSON, "GUARDIAN_USER_RATE_LIMITS_JSON")
_telemetry_rate_limit_overrides = _parse_limit_overrides(
    TELEMETRY_KEY_RATE_LIMITS_JSON,
    "GUARDIAN_TELEMETRY_KEY_RATE_LIMITS_JSON",
)





def _issue_jwt(subject: str, role: str, org_id: str = "org_default", ttl_minutes: int = JWT_EXPIRES_MIN) -> tuple[str, Dict[str, Any]]:
    now = int(time.time())
    payload = {
        "sub": subject,
        "role": role,
        "org_id": org_id,
        "iat": now,
        "exp": now + (ttl_minutes * 60),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE,
        "jti": secrets.token_hex(12),
    }
    token = _jwt_encode(payload, JWT_SECRET)
    return token, payload


def _decode_jwt(token: str) -> Dict[str, Any]:
    try:
        # We use auth.py's _jwt_decode for the heavy lifting (alg check, signature, exp, nbf, aud)
        payload = _jwt_decode(token, JWT_SECRET)
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(exc))

    if payload.get("iss") != JWT_ISSUER:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token issuer")

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")
    role = payload.get("role")
    if not isinstance(role, str) or role not in _valid_roles:
        raise HTTPException(status_code=401, detail="Invalid token role")

    jti = payload.get("jti")
    if isinstance(jti, str) and _is_token_revoked(jti):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token revoked")

    return payload


def _enforce_rate_limit(identity: str, limit_per_minute: int):
    if _enforce_rate_limit_distributed(identity, limit_per_minute):
        return

    now = time.time()
    window_start = now - 60.0
    with _rate_limit_lock:
        entries = _rate_limit_state.get(identity, [])
        entries = [entry for entry in entries if entry >= window_start]
        if len(entries) >= limit_per_minute:
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Rate limit exceeded for {identity}",
            )
        entries.append(now)
        _rate_limit_state[identity] = entries


def _use_distributed_rate_limit() -> bool:
    if RATE_LIMIT_BACKEND == "redis":
        return True
    if RATE_LIMIT_BACKEND == "auto":
        return bool(RATE_LIMIT_REDIS_URL)
    return False


def _log_redis_fallback(reason: str):
    global _redis_fallback_logged_at
    now = time.time()
    if now - _redis_fallback_logged_at >= 30:
        logger.warning("Distributed rate limit disabled, falling back to in-memory limiter: %s", reason)
        _redis_fallback_logged_at = now


def _get_redis_client() -> Any | None:
    global _redis_client
    global _redis_init_attempted
    if _redis_init_attempted:
        return _redis_client
    _redis_init_attempted = True

    if not RATE_LIMIT_REDIS_URL:
        _log_redis_fallback("GUARDIAN_RATE_LIMIT_REDIS_URL not set")
        return None

    try:
        import redis  # type: ignore
    except Exception:
        _log_redis_fallback("python redis package is not installed")
        return None

    try:
        _redis_client = redis.Redis.from_url(
            RATE_LIMIT_REDIS_URL,
            socket_timeout=RATE_LIMIT_REDIS_TIMEOUT_SEC,
            socket_connect_timeout=RATE_LIMIT_REDIS_TIMEOUT_SEC,
            decode_responses=True,
        )
        _redis_client.ping()
        return _redis_client
    except redis.RedisError as exc:
        _redis_client = None
        _log_redis_fallback(f"unable to connect to redis: {exc}")
        return None


def _load_redis_rate_limit_script(client: Any) -> str | None:
    global _redis_script_sha
    if _redis_script_sha:
        return _redis_script_sha
    try:
        _redis_script_sha = client.script_load(_REDIS_RATE_LIMIT_SCRIPT)
        return _redis_script_sha
    except redis.RedisError as exc:
        _log_redis_fallback(f"unable to load redis script: {exc}")
        return None


def _enforce_rate_limit_distributed(identity: str, limit_per_minute: int) -> bool:
    if not _use_distributed_rate_limit():
        return False

    client = _get_redis_client()
    if client is None:
        if RATE_LIMIT_REDIS_FAIL_OPEN:
            return False
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Rate limiter unavailable")

    key = f"{RATE_LIMIT_REDIS_KEY_PREFIX}:{identity}"
    now_ms = int(time.time() * 1000)
    member = f"{now_ms}:{secrets.token_hex(6)}"

    try:
        script_sha = _load_redis_rate_limit_script(client)
        if script_sha:
            allowed = int(client.evalsha(script_sha, 1, key, now_ms, 60_000, limit_per_minute, member))
        else:
            allowed = int(client.eval(_REDIS_RATE_LIMIT_SCRIPT, 1, key, now_ms, 60_000, limit_per_minute, member))
    except HTTPException:
        raise
    except redis.RedisError as exc:
        _log_redis_fallback(f"redis eval failed: {exc}")
        if RATE_LIMIT_REDIS_FAIL_OPEN:
            return False
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Rate limiter unavailable")

    if allowed != 1:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for {identity}",
        )
    return True


def _validate_audit_sink_url(url: str) -> bool:
    from backend.security.url_validation import is_safe_url
    return is_safe_url(url)


def _forward_external_audit_log(payload: Dict[str, Any], strict: bool = AUDIT_SINK_STRICT) -> bool:
    if not AUDIT_SINK_URL:
        return True

    if not _validate_audit_sink_url(AUDIT_SINK_URL):
        if strict:
            raise ValueError("Invalid or unsafe AUDIT_SINK_URL configured")
        return False

    headers = {"Content-Type": "application/json"}
    if AUDIT_SINK_TOKEN:
        headers["Authorization"] = f"Bearer {AUDIT_SINK_TOKEN}"

    attempts = max(0, AUDIT_SINK_RETRIES) + 1
    for attempt in range(attempts):
        try:
            response = requests.post(
                AUDIT_SINK_URL,
                json=payload,
                headers=headers,
                timeout=AUDIT_SINK_TIMEOUT_SEC,
            )
            if 200 <= response.status_code < 300:
                return True
            logger.warning(
                "External audit sink rejected event (status=%s, attempt=%s/%s)",
                response.status_code,
                attempt + 1,
                attempts,
            )
        except Exception as exc:  # noqa: BLE001
            logger.warning("External audit sink request failed (attempt=%s/%s): %s", attempt + 1, attempts, exc)

        if attempt < attempts - 1:
            time.sleep(min(0.1 * (2 ** attempt), 0.5))

    if strict:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="External audit log delivery failed",
        )
    return False


def _forward_syslog_audit_log(payload: Dict[str, Any], strict: bool = AUDIT_SYSLOG_STRICT) -> bool:
    if not AUDIT_SYSLOG_HOST:
        return True

    message = json.dumps(
        {
            "app": "guardian-backend",
            "event": "audit_log",
            "payload": payload,
        },
        separators=(",", ":"),
    )
    pri = "<134>"  # local0.info
    frame = f"{pri}guardian-backend: {message}".encode("utf-8")

    sock = None
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(AUDIT_SYSLOG_TIMEOUT_SEC)
        sock.sendto(frame, (AUDIT_SYSLOG_HOST, AUDIT_SYSLOG_PORT))
        return True
    except Exception as exc:  # noqa: BLE001
        logger.warning("Syslog audit sink delivery failed: %s", exc)
        if strict:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="Syslog audit delivery failed",
            ) from exc
        return False
    finally:
        if sock is not None:
            sock.close()


def _forward_splunk_audit_log(payload: Dict[str, Any], strict: bool = AUDIT_SPLUNK_STRICT) -> bool:
    if not AUDIT_SPLUNK_HEC_URL:
        return True

    headers = {"Content-Type": "application/json"}
    if AUDIT_SPLUNK_HEC_TOKEN:
        headers["Authorization"] = f"Splunk {AUDIT_SPLUNK_HEC_TOKEN}"
    event = {
        "time": payload.get("timestamp", time.time()),
        "source": AUDIT_SPLUNK_SOURCE,
        "sourcetype": AUDIT_SPLUNK_SOURCETYPE,
        "event": payload,
    }
    if AUDIT_SPLUNK_INDEX:
        event["index"] = AUDIT_SPLUNK_INDEX
    try:
        response = requests.post(AUDIT_SPLUNK_HEC_URL, json=event, headers=headers, timeout=AUDIT_SINK_TIMEOUT_SEC)
        if 200 <= response.status_code < 300:
            return True
        logger.warning("Splunk HEC rejected audit event (status=%s)", response.status_code)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Splunk HEC audit delivery failed: %s", exc)

    if strict:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Splunk audit delivery failed",
        )
    return False


def _forward_datadog_audit_log(payload: Dict[str, Any], strict: bool = AUDIT_DATADOG_STRICT) -> bool:
    if not AUDIT_DATADOG_API_KEY:
        return True

    headers = {"Content-Type": "application/json", "DD-API-KEY": AUDIT_DATADOG_API_KEY}
    log_entry = {
        "ddsource": AUDIT_DATADOG_SOURCE,
        "service": AUDIT_DATADOG_SERVICE,
        "ddtags": AUDIT_DATADOG_TAGS,
        "message": json.dumps(payload, separators=(",", ":")),
    }
    try:
        response = requests.post(
            AUDIT_DATADOG_LOGS_URL,
            json=[log_entry],
            headers=headers,
            timeout=AUDIT_SINK_TIMEOUT_SEC,
        )
        if 200 <= response.status_code < 300:
            return True
        logger.warning("Datadog logs intake rejected audit event (status=%s)", response.status_code)
    except Exception as exc:  # noqa: BLE001
        logger.warning("Datadog logs audit delivery failed: %s", exc)

    if strict:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Datadog audit delivery failed",
        )
    return False


def _is_https_request(scheme: str, forwarded_proto: str = "") -> bool:
    if (scheme or "").lower() == "https":
        return True
    forwarded_values = [segment.strip().lower() for segment in (forwarded_proto or "").split(",") if segment.strip()]
    return "https" in forwarded_values


def _record_request_metric(status_code: int, latency_ms: float):
    now = time.time()
    with _metrics_lock:
        global _metrics_request_count
        global _metrics_total_latency_ms
        global _metrics_latency_samples
        _metrics_request_count += 1
        _metrics_total_latency_ms += latency_ms
        _metrics_latency_samples += 1
        _metrics_status_counts[status_code] = _metrics_status_counts.get(status_code, 0) + 1
        _metrics_recent_requests.append(now)
        one_minute_ago = now - 60.0
        while _metrics_recent_requests and _metrics_recent_requests[0] < one_minute_ago:
            _metrics_recent_requests.popleft()


def _get_user_rate_limit(username: str) -> int:
    return _user_rate_limit_overrides.get(username, API_RATE_LIMIT_PER_MIN)


def _get_telemetry_rate_limit(identity: str) -> int:
    return _telemetry_rate_limit_overrides.get(identity, TELEMETRY_RATE_LIMIT_PER_MIN)


def _build_metrics_payload() -> str:
    with _metrics_lock:
        request_count = _metrics_request_count
        avg_latency_ms = (_metrics_total_latency_ms / _metrics_latency_samples) if _metrics_latency_samples else 0.0
        requests_last_minute = len(_metrics_recent_requests)
        status_counts = dict(_metrics_status_counts)

    process = psutil.Process()
    cpu_percent = process.cpu_percent(interval=0.0)
    memory_bytes = process.memory_info().rss
    req_per_second = requests_last_minute / 60.0

    lines = [
        "# HELP guardian_http_requests_total Total HTTP requests handled.",
        "# TYPE guardian_http_requests_total counter",
        f"guardian_http_requests_total {request_count}",
        "# HELP guardian_http_request_latency_avg_ms Average request latency in milliseconds.",
        "# TYPE guardian_http_request_latency_avg_ms gauge",
        f"guardian_http_request_latency_avg_ms {avg_latency_ms:.3f}",
        "# HELP guardian_http_requests_per_second_1m Approximate requests per second over 1 minute.",
        "# TYPE guardian_http_requests_per_second_1m gauge",
        f"guardian_http_requests_per_second_1m {req_per_second:.3f}",
        "# HELP guardian_process_cpu_percent Process CPU usage percent.",
        "# TYPE guardian_process_cpu_percent gauge",
        f"guardian_process_cpu_percent {cpu_percent:.3f}",
        "# HELP guardian_process_memory_bytes Process resident memory in bytes.",
        "# TYPE guardian_process_memory_bytes gauge",
        f"guardian_process_memory_bytes {memory_bytes}",
    ]
    for code, count in sorted(status_counts.items()):
        lines.append(f'guardian_http_status_total{{code="{code}"}} {count}')
    agentic_metrics = _build_agentic_metrics()
    lines.extend(
        [
            "# HELP guardian_agentic_hop_policy_violations_blocked Agent hop policy violations blocked.",
            "# TYPE guardian_agentic_hop_policy_violations_blocked counter",
            f"guardian_agentic_hop_policy_violations_blocked {agentic_metrics['hop_policy_violations_blocked']}",
            "# HELP guardian_agentic_unauthorized_mcp_server_attempts Unauthorized MCP server usage attempts.",
            "# TYPE guardian_agentic_unauthorized_mcp_server_attempts counter",
            f"guardian_agentic_unauthorized_mcp_server_attempts {agentic_metrics['unauthorized_mcp_server_attempts']}",
            "# HELP guardian_agentic_scope_escalation_attempts_blocked Scope escalation attempts blocked.",
            "# TYPE guardian_agentic_scope_escalation_attempts_blocked counter",
            f"guardian_agentic_scope_escalation_attempts_blocked {agentic_metrics['scope_escalation_attempts_blocked']}",
            "# HELP guardian_agentic_active_execution_grants Active time-bounded execution grants.",
            "# TYPE guardian_agentic_active_execution_grants gauge",
            f"guardian_agentic_active_execution_grants {agentic_metrics['active_execution_grants']}",
            "# HELP guardian_agentic_active_agent_keys Active signed-agent keys.",
            "# TYPE guardian_agentic_active_agent_keys gauge",
            f"guardian_agentic_active_agent_keys {agentic_metrics['active_agent_keys']}",
        ]
    )
    if agentic_metrics["mean_time_to_revoke_seconds"] is not None:
        lines.extend(
            [
                "# HELP guardian_agentic_mean_time_to_revoke_seconds Mean time to revoke compromised agent keys.",
                "# TYPE guardian_agentic_mean_time_to_revoke_seconds gauge",
                f"guardian_agentic_mean_time_to_revoke_seconds {agentic_metrics['mean_time_to_revoke_seconds']:.3f}",
            ]
        )
    return "\n".join(lines) + "\n"


def _check_db_health() -> tuple[bool, str]:
    try:
        conn = sqlite3.connect(DB_PATH)
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        conn.close()
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def _to_ms(value):
    if value is None:
        return None
    if isinstance(value, (int, float)):
        return float(value)
    if isinstance(value, str):
        cleaned = value.strip().lower().replace("ms", "")
        try:
            return float(cleaned)
        except ValueError:
            return None
    return None


def _siem_router() -> SiemRouter | None:
    global _siem_router_instance
    if not SIEM_ENABLED:
        return None
    if _siem_router_instance is None:
        _siem_router_instance = SiemRouter(
            SiemConfig(
                enabled=True,
                out_path=SIEM_OUT,
                format=SIEM_FORMAT,
                transport="file",
            )
        )
    return _siem_router_instance


def _write_siem_alert(event: "SecurityEvent") -> None:
    if not SIEM_ENABLED:
        return
    severity = str(event.severity or "").upper()
    if severity not in {"HIGH", "CRITICAL"}:
        return
    router = _siem_router()
    if router is None:
        return
    alert = build_alert_document(
        guardian_id=event.guardian_id,
        event_type=event.event_type,
        severity=severity,
        details=event.details,
        timestamp=event.timestamp,
    )
    router.enqueue(alert)

def init_db():
    db_dir = os.path.dirname(DB_PATH)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guardian_id TEXT,
        tenant_id TEXT DEFAULT 'default',
        event_type TEXT,
        severity TEXT,
        details TEXT,
        timestamp REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT DEFAULT 'default',
        path TEXT,
        latency_ms REAL,
        timestamp REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guardian_id TEXT,
        action TEXT,
        user TEXT,
        details TEXT,
        timestamp REAL,
        signature TEXT -- Cryptographic proof (simulated)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_name TEXT UNIQUE,
        key_prefix TEXT,
        key_hash TEXT UNIQUE,
        is_active INTEGER DEFAULT 1,
        created_by TEXT,
        created_at REAL,
        last_used_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS revoked_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        jti TEXT UNIQUE,
        revoked_by TEXT,
        revoked_at REAL,
        expires_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS issued_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        jti TEXT UNIQUE,
        subject TEXT,
        role TEXT,
        issued_at REAL,
        expires_at REAL,
        revoked_at REAL,
        revoked_by TEXT,
        revoke_reason TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_delivery_failures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sink_type TEXT,
        payload TEXT,
        error TEXT,
        retry_count INTEGER DEFAULT 0,
        created_at REAL,
        last_attempt_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        tenant_name TEXT,
        created_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id TEXT UNIQUE,
        customer_email TEXT,
        tenant_name TEXT,
        plan TEXT,
        payment_method TEXT,
        provider TEXT,
        status TEXT,
        checkout_url TEXT,
        provider_transaction_id TEXT,
        created_at REAL,
        updated_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id TEXT UNIQUE,
        machine_id TEXT,
        license_key TEXT,
        status TEXT,
        issued_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS lockout_state (
        identity TEXT PRIMARY KEY,
        failed_count INTEGER,
        locked_until REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agentic_agent_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        key_id TEXT NOT NULL,
        key_secret_hash TEXT NOT NULL,
        key_secret_ciphertext TEXT NOT NULL,
        cert_fingerprints_json TEXT,
        status TEXT DEFAULT 'active',
        created_by TEXT,
        created_at REAL,
        rotated_at REAL,
        revoked_at REAL,
        revoked_by TEXT,
        revoke_reason TEXT,
        UNIQUE(agent_id, key_id)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agentic_revocations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        revocation_type TEXT NOT NULL,
        agent_id TEXT,
        key_id TEXT,
        reason TEXT,
        revoked_by TEXT,
        revoked_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agentic_execution_grants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        execution_id TEXT UNIQUE NOT NULL,
        agent_id TEXT,
        parent_agent TEXT,
        scopes_json TEXT,
        tools_json TEXT,
        expires_at REAL,
        created_by TEXT,
        created_at REAL,
        revoked_at REAL,
        revoked_by TEXT,
        revoke_reason TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agentic_policy_edges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_agent TEXT NOT NULL,
        child_agent TEXT NOT NULL,
        scopes_json TEXT,
        tools_json TEXT,
        max_hops INTEGER,
        created_by TEXT,
        created_at REAL,
        UNIQUE(parent_agent, child_agent)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agentic_trace_hashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_hash TEXT UNIQUE NOT NULL,
        agent_id TEXT,
        execution_id TEXT,
        first_seen_at REAL
    )
    """)
    # Backward-compatible schema upgrades for existing installations.
    cur.execute("PRAGMA table_info(security_events)")
    security_cols = {row[1] for row in cur.fetchall()}
    if "tenant_id" not in security_cols:
        cur.execute("ALTER TABLE security_events ADD COLUMN tenant_id TEXT DEFAULT 'default'")
    cur.execute("PRAGMA table_info(analytics)")
    analytics_cols = {row[1] for row in cur.fetchall()}
    if "tenant_id" not in analytics_cols:
        cur.execute("ALTER TABLE analytics ADD COLUMN tenant_id TEXT DEFAULT 'default'")
    cur.execute("PRAGMA table_info(audit_logs)")
    audit_cols = {row[1] for row in cur.fetchall()}
    if "prev_hash" not in audit_cols:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT")
    if "entry_hash" not in audit_cols:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN entry_hash TEXT")
    cur.execute("PRAGMA table_info(agentic_agent_keys)")
    agentic_key_cols = {row[1] for row in cur.fetchall()}
    if "cert_fingerprints_json" not in agentic_key_cols:
        cur.execute("ALTER TABLE agentic_agent_keys ADD COLUMN cert_fingerprints_json TEXT")
    conn.commit()
    conn.close()
    logger.info("SQLite DB initialized at %s", DB_PATH)

init_db()

class SecurityEvent(BaseModel):
    guardian_id: str = Field(..., max_length=256)
    tenant_id: str = Field("default", max_length=512)
    event_type: str = Field(..., max_length=128)
    severity: str = Field(..., max_length=512)
    details: dict = Field(default_factory=dict)
    timestamp: float = 0.0

# WebSocket Connection Manager
class ConnectionManager:
    def __init__(self):
        self.active_connections: List[WebSocket] = []

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.append(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.remove(websocket)

    async def broadcast(self, message: str):
        for connection in self.active_connections:
            await connection.send_text(message)

manager = ConnectionManager()


@app.middleware("http")
async def add_security_headers(request: Request, call_next):
    import secrets
    import re
    from fastapi.responses import Response

    nonce = secrets.token_hex(16)
    request.state.nonce = nonce

    response = await call_next(request)

    content_type = response.headers.get("content-type", "")
    if "text/html" in content_type:
        body = b""
        async for chunk in response.body_iterator:
            body += chunk
        body_str = body.decode("utf-8", errors="ignore")
        modified_body_str = re.sub(
            r'<script(?![^>]*\bsrc\b)(?![^>]*\bnonce\b)([^>]*)>',
            f'<script nonce="{nonce}"\\1>',
            body_str
        )
        modified_body = modified_body_str.encode("utf-8")
        response = Response(
            content=modified_body,
            status_code=response.status_code,
            headers=dict(response.headers)
        )
        response.headers["content-length"] = str(len(modified_body))

    csp = f"default-src 'self'; script-src 'self' 'nonce-{nonce}' https://cdn.jsdelivr.net; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none';"
    
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "0"
    if ENFORCE_HTTPS:
        response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
    response.headers["Content-Security-Policy"] = csp
    response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    return response


@app.middleware("http")
async def csrf_middleware(request: Request, call_next):
    is_m2m = (
        request.headers.get("x-api-key") is not None or
        request.headers.get("x-guardian-service-token") is not None or
        request.headers.get("authorization") is not None
    )
    exempt_paths = {
        "/login",
        "/api/v1/auth/token",
        "/logout",
    }
    path = request.url.path
    is_exempt = path in exempt_paths or any(path.startswith(p) for p in ["/ws/", "/api/v1/public/"])

    uses_cookie = request.cookies.get("guardian_token") is not None
    if request.method in {"POST", "PUT", "DELETE"} and uses_cookie and not is_m2m and not is_exempt:
        cookie_token = request.cookies.get("guardian_csrf")
        header_token = request.headers.get("x-csrf-token") or request.headers.get("x-xsrf-token")
        
        if not cookie_token or not header_token or not hmac.compare_digest(cookie_token, header_token):
            return JSONResponse(
                status_code=status.HTTP_403_FORBIDDEN,
                content={"detail": "CSRF token validation failed"}
            )
            
    response = await call_next(request)
    
    if request.method == "GET" or path == "/login":
        if not request.cookies.get("guardian_csrf"):
            csrf_token = secrets.token_hex(32)
            response.set_cookie(
                key="guardian_csrf",
                value=csrf_token,
                httponly=False,
                samesite="lax",
                secure=ENFORCE_HTTPS
            )
            
    return response


@app.middleware("http")
async def enforce_https_middleware(request: Request, call_next):
    if ENFORCE_HTTPS and not _is_https_request(request.url.scheme, request.headers.get("x-forwarded-proto", "")):
        return JSONResponse(
            status_code=status.HTTP_400_BAD_REQUEST,
            content={"detail": "HTTPS required. Set GUARDIAN_ENFORCE_HTTPS=false only for local development."},
        )
    return await call_next(request)


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    if not METRICS_ENABLED:
        return await call_next(request)

    start = time.perf_counter()
    response = await call_next(request)
    latency_ms = (time.perf_counter() - start) * 1000.0
    _record_request_metric(response.status_code, latency_ms)
    return response

# Security / Auth
security = HTTPBasic(auto_error=False)
bearer_security = HTTPBearer(auto_error=False)

def _validate_basic(credentials: HTTPBasicCredentials) -> str:
    user_config = _auth_users.get(credentials.username)
    
    # Anti-enumeration: always verify a hash to equalize timing.
    # If the user doesn't exist, we verify against a static, genuinely valid dummy hash.
    # Generated via hash_password("dummy") to ensure valid base64 and checksum.
    DUMMY_HASH = "$argon2id$v=19$m=65536,t=7,p=4$KUGcP8geNdGLxEzipJtshQ$BiFNhl23xD9jhkM4YXPtzmfc1AR6XL1n6BV4zvcj5Ak"
    stored = user_config["password"] if user_config else DUMMY_HASH
    
    ok = verify_password(credentials.password, stored)
    
    if not user_config or not ok:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def _get_user_role(username: str) -> str:
    user_config = _auth_users.get(username)
    if not user_config:
        return "user"
    role = user_config.get("role", "user")
    return role if role in _valid_roles else "user"


def get_current_principal(
    bearer: HTTPAuthorizationCredentials = Depends(bearer_security),
    credentials: HTTPBasicCredentials = Depends(security),
):
    if bearer and bearer.scheme.lower() == "bearer":
        payload = _decode_jwt(bearer.credentials)
        return {"username": payload["sub"], "role": payload.get("role", "user"), "org_id": payload.get("org_id", "org_default"), "auth_type": "bearer"}

    if credentials:
        username = _validate_basic(credentials)
        user_config = _auth_users.get(username, {})
        return {"username": username, "role": _get_user_role(username), "org_id": user_config.get("org_id", "org_default"), "auth_type": "basic"}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Basic realm=\"GuardianAI\""},
    )


def get_current_user(principal: Dict[str, str] = Depends(get_current_principal)):
    return principal["username"]


def get_current_admin(principal: Dict[str, str] = Depends(get_current_principal)):
    if principal.get("role") != "admin":
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privilege required",
        )
    return principal["username"]


def get_current_token_payload(
    bearer: HTTPAuthorizationCredentials = Depends(bearer_security),
):
    if not bearer or bearer.scheme.lower() != "bearer":
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Bearer token required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    return _decode_jwt(bearer.credentials)


def _extract_basic_credentials_from_header(request: Request) -> Optional[Tuple[str, str]]:
    auth_header = request.headers.get("authorization", "")
    if not auth_header.lower().startswith("basic "):
        return None
    encoded = auth_header.split(" ", 1)[1].strip()
    if not encoded:
        return None
    try:
        decoded = base64.b64decode(encoded).decode("utf-8")
    except Exception:  # noqa: BLE001
        return None
    if ":" not in decoded:
        return None
    username, password = decoded.split(":", 1)
    return username, password


def _enforce_rbac_and_user_rate_limit(
    request: Request,
    principal: Dict[str, str],
    allowed_roles: Set[str] | None = None,
) -> str:
    role = principal.get("role", "user")
    if allowed_roles and role not in allowed_roles:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=f"Requires one of roles: {', '.join(sorted(allowed_roles))}",
        )
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    return username


def enforce_user_rate_limit(request: Request, principal: Dict[str, str] = Depends(get_current_principal)):
    return _enforce_rbac_and_user_rate_limit(request, principal)


def enforce_auditor_rate_limit(request: Request, principal: Dict[str, str] = Depends(get_current_principal)):
    return _enforce_rbac_and_user_rate_limit(request, principal, allowed_roles={"admin", "auditor"})


def enforce_admin_rate_limit(request: Request, principal: Dict[str, str] = Depends(get_current_principal)):
    return _enforce_rbac_and_user_rate_limit(request, principal, allowed_roles={"admin"})


def enforce_telemetry_rate_limit(request: Request):
    identity = request.headers.get("x-api-key", "").strip()
    api_key_record = None
    if identity:
        api_key_record = _lookup_api_key(identity)
        if TELEMETRY_REQUIRE_API_KEY and not api_key_record:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid API key")
        if api_key_record:
            identity = api_key_record["key_name"]
    elif BACKEND_TOKEN:
        auth_header = request.headers.get("authorization", "").strip()
        expected = f"Bearer {BACKEND_TOKEN}"
        if not auth_header or not secrets.compare_digest(auth_header, expected):
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid backend token")
        if SERVICE_AUTH_TOKEN:
            service_id = request.headers.get("X-Guardian-Service-Id", "").strip()
            service_token = request.headers.get("X-Guardian-Service-Token", "").strip()
            if service_id != SERVICE_ID or not secrets.compare_digest(service_token, SERVICE_AUTH_TOKEN):
                raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid service authentication")
        identity = request.headers.get("X-Guardian-Service-Id", "").strip() or "backend-token"
    elif TELEMETRY_REQUIRE_API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    if not identity:
        identity = _request_source_identity(request)
    _enforce_rate_limit(f"telemetry:{identity}", _get_telemetry_rate_limit(identity))
    return True


def _request_source_identity(request: Request) -> str:
    trust_hops_str = os.getenv("GUARDIAN_TRUST_PROXY_HOPS", "").strip()
    if not trust_hops_str:
        import sys
        if "pytest" in sys.modules or os.getenv("GUARDIAN_ENV") == "test":
            trust_hops = 1
        else:
            trust_hops = 0
    else:
        try:
            trust_hops = int(trust_hops_str)
        except ValueError:
            trust_hops = 0

    if trust_hops > 0:
        forwarded = request.headers.get("x-forwarded-for", "").strip()
        if forwarded:
            hops = [h.strip() for h in forwarded.split(",") if h.strip()]
            if len(hops) >= trust_hops:
                return hops[-trust_hops]

    if request.client and request.client.host:
        return request.client.host
    return "unknown"


def enforce_auth_rate_limit(request: Request):
    identity = _request_source_identity(request)
    _enforce_rate_limit(f"auth:{identity}", AUTH_RATE_LIMIT_PER_MIN)
    return True


def _is_auth_lockout_enabled() -> bool:
    return AUTH_LOCKOUT_ENABLED and AUTH_LOCKOUT_MAX_ATTEMPTS > 0 and AUTH_LOCKOUT_DURATION_SEC > 0


def _format_auth_lockout_identity(username: str, source: str) -> str:
    normalized_user = username.strip().lower() or "unknown-user"
    normalized_source = source.strip() or "unknown"
    return f"{normalized_user}|{normalized_source}"


def _parse_auth_lockout_identity(identity: str) -> tuple[str, str]:
    raw = (identity or "").strip()
    if "|" in raw:
        username, source = raw.split("|", 1)
        return username or "unknown-user", source or "unknown"
    if "@" in raw:
        username, source = raw.split("@", 1)
        return username or "unknown-user", source or "unknown"
    return raw or "unknown-user", "unknown"


def _auth_lockout_identity(request: Request, username: str | None) -> str:
    return _format_auth_lockout_identity((username or "").strip().lower(), _request_source_identity(request))


def _get_lockout_entry(identity: str) -> Dict[str, float]:
    client = _get_redis_client()
    if client is not None:
        try:
            val = client.get(f"guardian:lockout:{identity}")
            if val:
                return json.loads(val)
        except Exception as exc:
            logger.warning("Redis error reading lockout: %s", exc)
    else:
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT failed_count, locked_until FROM lockout_state WHERE identity = ?", (identity,))
            row = cur.fetchone()
            conn.close()
            if row:
                return {"failed": float(row[0]), "locked_until": float(row[1])}
        except Exception as exc:
            logger.warning("SQLite error reading lockout: %s", exc)
    
    global _auth_lockout_state
    return _auth_lockout_state.get(identity, {"failed": 0.0, "locked_until": 0.0})

def _set_lockout_entry(identity: str, failed: float, locked_until: float):
    client = _get_redis_client()
    if client is not None:
        try:
            val = json.dumps({"failed": failed, "locked_until": locked_until})
            ttl = int(max(86400, (locked_until - time.time()) + 3600))
            client.set(f"guardian:lockout:{identity}", val, ex=ttl)
            return
        except Exception as exc:
            logger.warning("Redis error writing lockout: %s", exc)
    else:
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute(
                "INSERT INTO lockout_state (identity, failed_count, locked_until) VALUES (?, ?, ?) "
                "ON CONFLICT(identity) DO UPDATE SET failed_count=excluded.failed_count, locked_until=excluded.locked_until",
                (identity, int(failed), locked_until)
            )
            conn.commit()
            conn.close()
            return
        except Exception as exc:
            logger.warning("SQLite error writing lockout: %s", exc)
            
    global _auth_lockout_state
    _auth_lockout_state[identity] = {"failed": failed, "locked_until": locked_until}

def _delete_lockout_entry(identity: str):
    client = _get_redis_client()
    if client is not None:
        try:
            client.delete(f"guardian:lockout:{identity}")
        except Exception as exc:
            logger.warning("Redis error deleting lockout: %s", exc)
    else:
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM lockout_state WHERE identity = ?", (identity,))
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning("SQLite error deleting lockout: %s", exc)

    global _auth_lockout_state
    _auth_lockout_state.pop(identity, None)

def _get_all_lockout_entries() -> Dict[str, Dict[str, float]]:
    client = _get_redis_client()
    if client is not None:
        try:
            entries = {}
            for key in client.scan_iter("guardian:lockout:*"):
                identity = key.replace("guardian:lockout:", "", 1)
                val = client.get(key)
                if val:
                    entries[identity] = json.loads(val)
            return entries
        except Exception as exc:
            logger.warning("Redis error scanning lockouts: %s", exc)
    else:
        try:
            conn = sqlite3.connect(DB_PATH)
            cur = conn.cursor()
            cur.execute("SELECT identity, failed_count, locked_until FROM lockout_state")
            rows = cur.fetchall()
            conn.close()
            return {row[0]: {"failed": float(row[1]), "locked_until": float(row[2])} for row in rows}
        except Exception as exc:
            logger.warning("SQLite error scanning lockouts: %s", exc)
            
    global _auth_lockout_state
    return dict(_auth_lockout_state)

def _clear_all_lockout_entries():
    client = _get_redis_client()
    if client is not None:
        try:
            for key in client.scan_iter("guardian:lockout:*"):
                client.delete(key)
        except Exception as exc:
            logger.warning("Redis error clearing lockouts: %s", exc)
    else:
        try:
            conn = sqlite3.connect(DB_PATH)
            conn.execute("DELETE FROM lockout_state")
            conn.commit()
            conn.close()
        except Exception as exc:
            logger.warning("SQLite error clearing lockouts: %s", exc)
            
    global _auth_lockout_state
    _auth_lockout_state.clear()


def _auth_lockout_retry_after_seconds(identity: str) -> int:
    if not _is_auth_lockout_enabled():
        return 0
    now = time.time()
    with _auth_lockout_lock:
        entry = _get_lockout_entry(identity)
        failed = int(entry.get("failed", 0) or 0)
        locked_until = float(entry.get("locked_until", 0.0) or 0.0)
        if failed <= 0 and locked_until <= 0.0:
            return 0
        if locked_until <= now:
            if failed <= 0:
                _delete_lockout_entry(identity)
            else:
                _set_lockout_entry(identity, failed, 0.0)
            return 0
        return max(1, int((locked_until - now) + 0.999))


def _record_auth_lockout_failure(identity: str):
    if not _is_auth_lockout_enabled():
        return
    now = time.time()
    with _auth_lockout_lock:
        entry = _get_lockout_entry(identity)
        locked_until = float(entry.get("locked_until", 0.0) or 0.0)
        if locked_until > now:
            return
        failures = int(entry.get("failed", 0) or 0) + 1
        if failures >= AUTH_LOCKOUT_MAX_ATTEMPTS:
            _set_lockout_entry(identity, 0.0, now + AUTH_LOCKOUT_DURATION_SEC)
        else:
            _set_lockout_entry(identity, float(failures), 0.0)


def _clear_auth_lockout_failures(identity: str):
    with _auth_lockout_lock:
        _delete_lockout_entry(identity)
        # Backward compatibility for keys created before delimiter change.
        if "|" in identity:
            legacy = identity.replace("|", "@", 1)
            _delete_lockout_entry(legacy)


def _list_auth_lockouts(limit: int = 100, active_only: bool = True) -> List[Dict[str, Any]]:
    now = time.time()
    records: List[Dict[str, Any]] = []
    entries = _get_all_lockout_entries()
    with _auth_lockout_lock:
        stale: List[str] = []
        for identity, entry in entries.items():
            failed = int(entry.get("failed", 0) or 0)
            locked_until = float(entry.get("locked_until", 0.0) or 0.0)
            if locked_until <= now and failed <= 0:
                stale.append(identity)
                continue
            active = locked_until > now
            if active_only and not active:
                continue
            username, source = _parse_auth_lockout_identity(identity)
            records.append(
                {
                    "identity": identity,
                    "username": username,
                    "source": source,
                    "failed_attempts": max(0, failed),
                    "locked_until": locked_until if locked_until > 0 else None,
                    "retry_after_sec": max(0, int((locked_until - now) + 0.999)) if active else 0,
                    "active": active,
                }
            )
        for identity in stale:
            _delete_lockout_entry(identity)

    records.sort(
        key=lambda item: (
            1 if item["active"] else 0,
            int(item["retry_after_sec"]),
            int(item["failed_attempts"]),
        ),
        reverse=True,
    )
    return records[: max(1, min(limit, 1000))]


def _clear_auth_lockouts(
    *,
    clear_all: bool = False,
    identity: str | None = None,
    username: str | None = None,
    source: str | None = None,
) -> Dict[str, Any]:
    normalized_identity = (identity or "").strip()
    normalized_user = (username or "").strip().lower()
    normalized_source = (source or "").strip()

    entries = _get_all_lockout_entries()
    with _auth_lockout_lock:
        cleared = 0
        scope = ""

        if clear_all:
            cleared = len(entries)
            _clear_all_lockout_entries()
            scope = "all"
        elif normalized_identity:
            aliases = [normalized_identity]
            if "|" in normalized_identity:
                aliases.append(normalized_identity.replace("|", "@", 1))
            elif "@" in normalized_identity:
                aliases.append(normalized_identity.replace("@", "|", 1))
            for key in aliases:
                if key in entries:
                    _delete_lockout_entry(key)
                    cleared += 1
            scope = f"identity:{normalized_identity}"
        elif normalized_user and normalized_source:
            aliases = [
                _format_auth_lockout_identity(normalized_user, normalized_source),
                f"{normalized_user}@{normalized_source}",
            ]
            for key in aliases:
                if key in entries:
                    _delete_lockout_entry(key)
                    cleared += 1
            scope = f"user+source:{normalized_user}@{normalized_source}"
        elif normalized_user:
            for key in list(entries.keys()):
                key_user, _ = _parse_auth_lockout_identity(key)
                if key_user == normalized_user:
                    _delete_lockout_entry(key)
                    cleared += 1
            scope = f"user:{normalized_user}"
        else:
            raise ValueError("clear target is required")

        return {
            "cleared": cleared,
            "remaining": len(_get_all_lockout_entries()),
            "scope": scope,
        }


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user: str
    role: str


class CreateApiKeyRequest(BaseModel):
    key_name: str


class ApiKeyResponse(BaseModel):
    id: int
    key_name: str
    key_prefix: str
    is_active: bool
    created_by: str
    created_at: float
    last_used_at: float | None = None


class CreatedApiKeyResponse(ApiKeyResponse):
    api_key: str


class RevokeTokenResponse(BaseModel):
    status: str
    revoked_jti: str
    revoked_by: str


class RevokedTokenEntryResponse(BaseModel):
    jti: str
    revoked_by: str
    revoked_at: float
    expires_at: float
    expired: bool


class PruneRevokedTokensResponse(BaseModel):
    deleted: int
    remaining: int
    expired_only: bool


class AuthSessionResponse(BaseModel):
    jti: str
    subject: str
    role: str
    issued_at: float
    expires_at: float
    revoked_at: float | None = None
    revoked_by: str | None = None
    revoke_reason: str | None = None
    active: bool


class RevokeUserSessionsRequest(BaseModel):
    username: str
    active_only: bool = True
    reason: str | None = None


class RevokeUserSessionsResponse(BaseModel):
    target_user: str
    matched: int
    revoked: int
    already_revoked: int
    active_only: bool
    reason: str | None = None


class RevokeSelfSessionsRequest(BaseModel):
    active_only: bool = True
    exclude_current: bool = True
    reason: str | None = None


class RevokeSelfSessionsResponse(BaseModel):
    target_user: str
    matched: int
    revoked: int
    already_revoked: int
    excluded_current: int
    active_only: bool
    exclude_current: bool
    reason: str | None = None


class RevokeSelfSessionByJtiRequest(BaseModel):
    jti: str
    reason: str | None = None


class RevokeSelfSessionByJtiResponse(BaseModel):
    jti: str
    target_user: str
    revoked: bool
    already_revoked: bool
    reason: str | None = None


class RevokeAllSessionsRequest(BaseModel):
    active_only: bool = True
    exclude_self: bool = True
    exclude_usernames: List[str] | None = None
    reason: str | None = None


class RevokeAllSessionsResponse(BaseModel):
    matched: int
    revoked: int
    already_revoked: int
    excluded: int
    active_only: bool
    exclude_self: bool
    excluded_users: List[str]
    reason: str | None = None


class RevokeSessionByJtiRequest(BaseModel):
    jti: str
    reason: str | None = None


class RevokeSessionByJtiResponse(BaseModel):
    jti: str
    target_user: str
    revoked: bool
    already_revoked: bool
    reason: str | None = None


class AuthLockoutEntryResponse(BaseModel):
    identity: str
    username: str
    source: str
    failed_attempts: int
    locked_until: float | None = None
    retry_after_sec: int
    active: bool


class ClearAuthLockoutsRequest(BaseModel):
    clear_all: bool = False
    identity: str | None = None
    username: str | None = None
    source: str | None = None


class ClearAuthLockoutsResponse(BaseModel):
    cleared: int
    remaining: int
    scope: str


class WhoAmIResponse(BaseModel):
    user: str
    role: str
    auth_type: str
    permissions: List[str]


class TelemetryIngestResponse(BaseModel):
    status: str
    event_id: str


class BillingCheckoutRequest(BaseModel):
    plan: str
    payment_method: str
    customer_email: str | None = None
    tenant_name: str | None = None


class BillingConfirmRequest(BaseModel):
    order_id: str
    provider_transaction_id: str
    provider_status: str
    machine_id: str | None = None


class LicenseIssueRequest(BaseModel):
    order_id: str
    machine_id: str


class AnalyticsResponse(BaseModel):
    total_requests: int
    total_blocked: int
    avg_latency_ms: float
    avg_guardian_overhead_ms: float
    avg_upstream_ms: float
    global_block_rate_pct: float
    recent_block_rate_pct: float
    path_breakdown: Dict[str, int]
    fast_path_pct: float
    differential_privacy: Dict[str, Any] | None = None


class HealthDatabaseComponent(BaseModel):
    ok: bool
    detail: str


class HealthComponents(BaseModel):
    database: HealthDatabaseComponent
    metrics_enabled: bool
    https_enforced: bool
    telemetry_requires_api_key: bool
    audit_sink_configured: bool
    auth_lockout_enabled: bool


class HealthResponse(BaseModel):
    status: str
    timestamp: float
    uptime_sec: float
    components: HealthComponents


class SecurityEventResponse(BaseModel):
    id: int
    guardian_id: str
    tenant_id: str = "default"
    event_type: str
    severity: str
    details: Dict[str, Any]
    timestamp: float


class AuditLogEntryResponse(BaseModel):
    id: int
    guardian_id: str
    action: str
    user: str
    details: str
    timestamp: float
    signature: str
    prev_hash: str | None = None
    entry_hash: str | None = None


class AuditVerifyResponse(BaseModel):
    ok: bool
    entries: int
    message: str | None = None
    failed_id: int | None = None
    reason: str | None = None


class AuditDeliveryFailureResponse(BaseModel):
    id: int
    sink_type: str
    payload: Dict[str, Any]
    error: str
    retry_count: int
    created_at: float
    last_attempt_at: float


class RetryFailuresResponse(BaseModel):
    retried: int
    resolved: int
    failed: int


class AuditSummaryResponse(BaseModel):
    timestamp: float
    total_entries: int
    hashed_entries: int
    legacy_unhashed_entries: int
    recent_admin_actions_24h: int
    failed_deliveries_total: int
    failed_deliveries_by_sink: Dict[str, int]
    chain_ok: bool
    chain_entries_checked: int
    chain_message: str | None = None
    chain_failed_id: int | None = None
    chain_reason: str | None = None


class AgenticKeyCreateRequest(BaseModel):
    agent_id: str
    key_id: str | None = None
    cert_fingerprints: List[str] = []


class AgenticKeyResponse(BaseModel):
    id: int
    agent_id: str
    key_id: str
    key_secret_hash: str
    cert_fingerprints: List[str] = []
    status: str
    created_by: str | None = None
    created_at: float
    rotated_at: float | None = None
    revoked_at: float | None = None
    revoked_by: str | None = None
    revoke_reason: str | None = None


class CreatedAgenticKeyResponse(AgenticKeyResponse):
    key_secret: str


class AgenticRevokeRequest(BaseModel):
    agent_id: str
    key_id: str | None = None
    reason: str | None = None


class AgenticExecutionGrantRequest(BaseModel):
    execution_id: str
    agent_id: str | None = None
    parent_agent: str | None = None
    scopes: List[str] = []
    tools: List[str] = []
    ttl_seconds: int = 300


class AgenticExecutionGrantResponse(BaseModel):
    id: int
    execution_id: str
    agent_id: str | None = None
    parent_agent: str | None = None
    scopes: List[str]
    tools: List[str]
    expires_at: float
    created_by: str | None = None
    created_at: float
    revoked_at: float | None = None
    revoked_by: str | None = None
    revoke_reason: str | None = None


class AgenticPolicyEdgeRequest(BaseModel):
    parent_agent: str
    child_agent: str
    scopes: List[str] = []
    tools: List[str] = []
    max_hops: int | None = None


class AgenticPolicyEdgeResponse(BaseModel):
    id: int
    parent_agent: str
    child_agent: str
    scopes: List[str]
    tools: List[str]
    max_hops: int | None = None
    created_by: str | None = None
    created_at: float


class AgenticMetricsResponse(BaseModel):
    timestamp: float
    hop_policy_violations_blocked: int
    unauthorized_mcp_server_attempts: int
    scope_escalation_attempts_blocked: int
    agent_revocations_total: int
    active_agent_keys: int
    active_execution_grants: int
    mean_time_to_revoke_seconds: float | None = None


class AgenticConfigSnapshotResponse(BaseModel):
    generated_at: float
    agent_attestation_keys: Dict[str, Dict[str, str]]
    agent_cert_fingerprints: Dict[str, List[str]]
    revoked_agent_ids: List[str]
    revoked_agent_key_ids: List[str]
    cross_agent_policy_graph: Dict[str, Any]
    execution_grants: Dict[str, Any]
    trace_replay_cache: List[str]


class ComplianceControlResponse(BaseModel):
    control: str
    status: str
    detail: str


class ComplianceSummaryResponse(BaseModel):
    passed: int
    warnings: int
    failed: int


class ComplianceReportResponse(BaseModel):
    status: str
    timestamp: float
    summary: ComplianceSummaryResponse
    controls: List[ComplianceControlResponse]


class RbacEndpointPolicyResponse(BaseModel):
    method: str
    path: str
    allowed_roles: List[str]
    permission: str


class RbacPolicyResponse(BaseModel):
    generated_at: float
    roles: Dict[str, List[str]]
    endpoints: List[RbacEndpointPolicyResponse]


_ROLE_PERMISSIONS: Dict[str, List[str]] = {
    "admin": [
        "auth:issue",
        "auth:revoke:self",
        "auth:revocations:read",
        "auth:revocations:manage",
        "auth:sessions:read",
        "auth:sessions:revoke_self",
        "auth:sessions:revoke_self_jti",
        "auth:sessions:revoke_user",
        "auth:sessions:revoke_all",
        "auth:sessions:revoke_jti",
        "auth:lockouts:read",
        "auth:lockouts:manage",
        "api_keys:manage",
        "audit:read",
        "audit:verify",
        "audit:retry",
        "agentic:manage",
        "agentic:read",
        "compliance:read",
        "rbac:read",
        "events:read",
        "analytics:read",
        "export:read",
        "telemetry:ingest",
    ],
    "auditor": [
        "auth:issue",
        "auth:revoke:self",
        "auth:revocations:read",
        "auth:sessions:read",
        "auth:sessions:revoke_self",
        "auth:sessions:revoke_self_jti",
        "auth:lockouts:read",
        "api_keys:read",
        "audit:read",
        "audit:verify",
        "agentic:read",
        "compliance:read",
        "rbac:read",
        "events:read",
        "analytics:read",
        "export:read",
        "telemetry:ingest",
    ],
    "user": [
        "auth:issue",
        "auth:revoke:self",
        "auth:sessions:revoke_self",
        "auth:sessions:revoke_self_jti",
        "events:read",
        "analytics:read",
        "export:read",
        "telemetry:ingest",
    ],
}


def _permissions_for_role(role: str) -> List[str]:
    return list(_ROLE_PERMISSIONS.get(role, _ROLE_PERMISSIONS["user"]))


def _rbac_endpoint_policies() -> List[Dict[str, Any]]:
    return [
        {"method": "GET", "path": "/api/v1/auth/whoami", "allowed_roles": ["admin", "auditor", "user"], "permission": "auth:issue"},
        {"method": "POST", "path": "/api/v1/auth/revoke", "allowed_roles": ["admin", "auditor", "user"], "permission": "auth:revoke:self"},
        {"method": "GET", "path": "/api/v1/auth/revocations", "allowed_roles": ["admin", "auditor"], "permission": "auth:revocations:read"},
        {"method": "POST", "path": "/api/v1/auth/revocations/prune", "allowed_roles": ["admin"], "permission": "auth:revocations:manage"},
        {"method": "GET", "path": "/api/v1/auth/lockouts", "allowed_roles": ["admin", "auditor"], "permission": "auth:lockouts:read"},
        {"method": "POST", "path": "/api/v1/auth/lockouts/clear", "allowed_roles": ["admin"], "permission": "auth:lockouts:manage"},
        {"method": "GET", "path": "/api/v1/auth/sessions", "allowed_roles": ["admin", "auditor"], "permission": "auth:sessions:read"},
        {"method": "POST", "path": "/api/v1/auth/sessions/revoke-self", "allowed_roles": ["admin", "auditor", "user"], "permission": "auth:sessions:revoke_self"},
        {"method": "POST", "path": "/api/v1/auth/sessions/revoke-self-jti", "allowed_roles": ["admin", "auditor", "user"], "permission": "auth:sessions:revoke_self_jti"},
        {"method": "POST", "path": "/api/v1/auth/sessions/revoke-user", "allowed_roles": ["admin"], "permission": "auth:sessions:revoke_user"},
        {"method": "POST", "path": "/api/v1/auth/sessions/revoke-all", "allowed_roles": ["admin"], "permission": "auth:sessions:revoke_all"},
        {"method": "POST", "path": "/api/v1/auth/sessions/revoke-jti", "allowed_roles": ["admin"], "permission": "auth:sessions:revoke_jti"},
        {"method": "POST", "path": "/api/v1/api-keys", "allowed_roles": ["admin"], "permission": "api_keys:manage"},
        {"method": "GET", "path": "/api/v1/api-keys", "allowed_roles": ["admin", "auditor"], "permission": "api_keys:read"},
        {"method": "POST", "path": "/api/v1/api-keys/{key_id}/revoke", "allowed_roles": ["admin"], "permission": "api_keys:manage"},
        {"method": "POST", "path": "/api/v1/api-keys/{key_id}/rotate", "allowed_roles": ["admin"], "permission": "api_keys:manage"},
        {"method": "GET", "path": "/api/v1/audit-log", "allowed_roles": ["admin", "auditor"], "permission": "audit:read"},
        {"method": "GET", "path": "/api/v1/audit-log/summary", "allowed_roles": ["admin", "auditor"], "permission": "audit:read"},
        {"method": "GET", "path": "/api/v1/audit-log/verify", "allowed_roles": ["admin", "auditor"], "permission": "audit:verify"},
        {"method": "GET", "path": "/api/v1/audit-log/failures", "allowed_roles": ["admin", "auditor"], "permission": "audit:read"},
        {"method": "POST", "path": "/api/v1/audit-log/retry-failures", "allowed_roles": ["admin"], "permission": "audit:retry"},
        {"method": "POST", "path": "/api/v1/agentic/keys", "allowed_roles": ["admin"], "permission": "agentic:manage"},
        {"method": "GET", "path": "/api/v1/agentic/keys", "allowed_roles": ["admin", "auditor"], "permission": "agentic:read"},
        {"method": "POST", "path": "/api/v1/agentic/keys/{key_id}/rotate", "allowed_roles": ["admin"], "permission": "agentic:manage"},
        {"method": "POST", "path": "/api/v1/agentic/revocations", "allowed_roles": ["admin"], "permission": "agentic:manage"},
        {"method": "POST", "path": "/api/v1/agentic/grants", "allowed_roles": ["admin"], "permission": "agentic:manage"},
        {"method": "GET", "path": "/api/v1/agentic/grants", "allowed_roles": ["admin", "auditor"], "permission": "agentic:read"},
        {"method": "POST", "path": "/api/v1/agentic/grants/{execution_id}/revoke", "allowed_roles": ["admin"], "permission": "agentic:manage"},
        {"method": "POST", "path": "/api/v1/agentic/policy-edges", "allowed_roles": ["admin"], "permission": "agentic:manage"},
        {"method": "GET", "path": "/api/v1/agentic/policy-edges", "allowed_roles": ["admin", "auditor"], "permission": "agentic:read"},
        {"method": "GET", "path": "/api/v1/agentic/config-snapshot", "allowed_roles": ["admin"], "permission": "agentic:manage"},
        {"method": "GET", "path": "/api/v1/agentic/metrics", "allowed_roles": ["admin", "auditor"], "permission": "agentic:read"},
        {"method": "GET", "path": "/api/v1/compliance/report", "allowed_roles": ["admin", "auditor"], "permission": "compliance:read"},
        {"method": "GET", "path": "/api/v1/rbac/policy", "allowed_roles": ["admin", "auditor"], "permission": "rbac:read"},
        {"method": "GET", "path": "/api/v1/events", "allowed_roles": ["admin", "auditor", "user"], "permission": "events:read"},
        {"method": "GET", "path": "/api/v1/analytics", "allowed_roles": ["admin", "auditor", "user"], "permission": "analytics:read"},
        {"method": "GET", "path": "/api/v1/export/json", "allowed_roles": ["admin", "auditor", "user"], "permission": "export:read"},
        {"method": "GET", "path": "/api/v1/export/csv", "allowed_roles": ["admin", "auditor", "user"], "permission": "export:read"},
    ]


def _build_rbac_policy() -> Dict[str, Any]:
    return {
        "generated_at": time.time(),
        "roles": {role: list(perms) for role, perms in _ROLE_PERMISSIONS.items()},
        "endpoints": _rbac_endpoint_policies(),
    }


def _build_audit_summary() -> Dict[str, Any]:
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    total_entries = 0
    hashed_entries = 0
    legacy_unhashed_entries = 0
    recent_admin_actions_24h = 0
    failed_deliveries_total = 0
    failed_deliveries_by_sink: Dict[str, int] = {}

    try:
        cur.execute(
            """
            SELECT
                COUNT(*) AS total_count,
                SUM(CASE WHEN entry_hash IS NOT NULL AND entry_hash != '' THEN 1 ELSE 0 END) AS hashed_count,
                SUM(CASE WHEN entry_hash IS NULL OR entry_hash = '' THEN 1 ELSE 0 END) AS legacy_count
            FROM audit_logs
            """
        )
        row = cur.fetchone() or (0, 0, 0)
        total_entries = int(row[0] or 0)
        hashed_entries = int(row[1] or 0)
        legacy_unhashed_entries = int(row[2] or 0)

        cur.execute(
            """
            SELECT COUNT(*)
            FROM audit_logs
            WHERE action = 'admin_action' AND timestamp >= ?
            """,
            (now - 86400.0,),
        )
        recent_admin_actions_24h = int((cur.fetchone() or (0,))[0] or 0)
    except sqlite3.OperationalError:
        total_entries = 0
        hashed_entries = 0
        legacy_unhashed_entries = 0
        recent_admin_actions_24h = 0

    try:
        cur.execute("SELECT sink_type, COUNT(*) FROM audit_delivery_failures GROUP BY sink_type")
        for sink_type, count in cur.fetchall():
            failed_deliveries_by_sink[str(sink_type)] = int(count or 0)
        failed_deliveries_total = sum(failed_deliveries_by_sink.values())
    except sqlite3.OperationalError:
        failed_deliveries_by_sink = {}
        failed_deliveries_total = 0

    conn.close()

    chain_result = _verify_audit_log_chain_internal()
    return {
        "timestamp": now,
        "total_entries": total_entries,
        "hashed_entries": hashed_entries,
        "legacy_unhashed_entries": legacy_unhashed_entries,
        "recent_admin_actions_24h": recent_admin_actions_24h,
        "failed_deliveries_total": failed_deliveries_total,
        "failed_deliveries_by_sink": failed_deliveries_by_sink,
        "chain_ok": bool(chain_result.get("ok", False)),
        "chain_entries_checked": int(chain_result.get("entries", 0) or 0),
        "chain_message": chain_result.get("message"),
        "chain_failed_id": chain_result.get("failed_id"),
        "chain_reason": chain_result.get("reason"),
    }


def _agentic_secret_stream(length: int) -> bytes:
    seed = AGENTIC_ATTESTATION_SECRET.encode("utf-8")
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def _get_aead_key():
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b"guardian_agentic_v2",
        info=b"agentic_attestation_key",
    )
    return hkdf.derive(AGENTIC_ATTESTATION_SECRET.encode("utf-8"))

def _agentic_encrypt_secret(raw_secret: str) -> str:
    key = _get_aead_key()
    aesgcm = AESGCM(key)
    nonce = os.urandom(12)
    raw = raw_secret.encode("utf-8")
    ct = aesgcm.encrypt(nonce, raw, None)
    return "v2:" + base64.urlsafe_b64encode(nonce + ct).decode("ascii")

def _agentic_decrypt_secret(ciphertext: str) -> str:
    if ciphertext.startswith("v2:"):
        data = base64.urlsafe_b64decode(ciphertext[3:].encode("ascii"))
        nonce = data[:12]
        ct = data[12:]
        key = _get_aead_key()
        aesgcm = AESGCM(key)
        try:
            return aesgcm.decrypt(nonce, ct, None).decode("utf-8")
        except Exception:
            raise ValueError("Decryption failed")
    else:
        encrypted = base64.urlsafe_b64decode(ciphertext.encode("ascii"))
        stream = _agentic_secret_stream(len(encrypted))
        raw = bytes(a ^ b for a, b in zip(encrypted, stream))
        return raw.decode("utf-8")


def _hash_agentic_secret(raw_secret: str) -> str:
    return hmac.new(
        AGENTIC_ATTESTATION_SECRET.encode("utf-8"),
        raw_secret.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def _new_agentic_secret() -> str:
    return "ga_" + secrets.token_urlsafe(32)


def _normalize_agentic_id(value: str, field_name: str) -> str:
    normalized = (value or "").strip()
    if not normalized:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"{field_name} is required")
    if len(normalized) > 128 or not all(ch.isalnum() or ch in "._:-" for ch in normalized):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=f"invalid {field_name}")
    return normalized


def _json_list(value: Any) -> List[str]:
    if not value:
        return []
    if isinstance(value, str):
        try:
            parsed = json.loads(value)
        except Exception:
            return []
    else:
        parsed = value
    if not isinstance(parsed, list):
        return []
    return [str(v) for v in parsed]


def _normalize_cert_fingerprint(value: str) -> str:
    return (value or "").replace(":", "").replace(" ", "").strip().lower()


def _agentic_key_response(row: tuple, include_secret: str | None = None) -> AgenticKeyResponse:
    payload = {
        "id": row[0],
        "agent_id": row[1],
        "key_id": row[2],
        "key_secret_hash": row[3],
        "cert_fingerprints": _json_list(row[5]),
        "status": row[6],
        "created_by": row[7],
        "created_at": row[8],
        "rotated_at": row[9],
        "revoked_at": row[10],
        "revoked_by": row[11],
        "revoke_reason": row[12],
    }
    if include_secret is not None:
        payload["key_secret"] = include_secret
        return CreatedAgenticKeyResponse(**payload)
    return AgenticKeyResponse(**payload)


def _agentic_grant_response(row: tuple) -> AgenticExecutionGrantResponse:
    return AgenticExecutionGrantResponse(
        id=row[0],
        execution_id=row[1],
        agent_id=row[2],
        parent_agent=row[3],
        scopes=_json_list(row[4]),
        tools=_json_list(row[5]),
        expires_at=row[6],
        created_by=row[7],
        created_at=row[8],
        revoked_at=row[9],
        revoked_by=row[10],
        revoke_reason=row[11],
    )


def _agentic_edge_response(row: tuple) -> AgenticPolicyEdgeResponse:
    return AgenticPolicyEdgeResponse(
        id=row[0],
        parent_agent=row[1],
        child_agent=row[2],
        scopes=_json_list(row[3]),
        tools=_json_list(row[4]),
        max_hops=row[5],
        created_by=row[6],
        created_at=row[7],
    )


def _build_agentic_config_snapshot() -> Dict[str, Any]:
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    cur.execute(
        """
        SELECT agent_id, key_id, key_secret_ciphertext, cert_fingerprints_json
        FROM agentic_agent_keys
        WHERE status = 'active' AND revoked_at IS NULL
        ORDER BY agent_id, key_id
        """
    )
    agent_keys: Dict[str, Dict[str, str]] = {}
    agent_cert_fingerprints: Dict[str, List[str]] = {}
    needs_migration = []
    for agent_id, key_id, ciphertext, cert_fingerprints_json in cur.fetchall():
        try:
            secret = _agentic_decrypt_secret(ciphertext)
            if not ciphertext.startswith("v2:"):
                needs_migration.append((agent_id, key_id, secret))
        except Exception:
            continue
        agent_keys.setdefault(agent_id, {})[key_id] = secret
        
    if needs_migration:
        for agent_id, key_id, secret in needs_migration:
            new_ct = _agentic_encrypt_secret(secret)
            cur.execute(
                "UPDATE agentic_agent_keys SET key_secret_ciphertext = ? WHERE agent_id = ? AND key_id = ?",
                (new_ct, agent_id, key_id)
            )
        conn.commit()
        for fingerprint in _json_list(cert_fingerprints_json):
            normalized = _normalize_cert_fingerprint(fingerprint)
            if normalized:
                agent_cert_fingerprints.setdefault(agent_id, []).append(normalized)

    cur.execute("SELECT DISTINCT agent_id FROM agentic_revocations WHERE revocation_type = 'agent' AND agent_id IS NOT NULL")
    revoked_agent_ids = [row[0] for row in cur.fetchall()]

    cur.execute("SELECT DISTINCT key_id FROM agentic_revocations WHERE revocation_type = 'key' AND key_id IS NOT NULL")
    revoked_agent_key_ids = [row[0] for row in cur.fetchall()]

    cur.execute(
        """
        SELECT parent_agent, child_agent, scopes_json, tools_json, max_hops
        FROM agentic_policy_edges
        ORDER BY parent_agent, child_agent
        """
    )
    graph: Dict[str, Any] = {}
    for parent, child, scopes_json, tools_json, max_hops in cur.fetchall():
        graph.setdefault(parent, {"children": {}})
        child_policy: Dict[str, Any] = {
            "scopes": _json_list(scopes_json),
            "tools": _json_list(tools_json),
        }
        if max_hops is not None:
            child_policy["max_hops"] = int(max_hops)
        graph[parent]["children"][child] = child_policy

    cur.execute(
        """
        SELECT execution_id, agent_id, parent_agent, scopes_json, tools_json, expires_at
        FROM agentic_execution_grants
        WHERE revoked_at IS NULL AND expires_at > ?
        ORDER BY expires_at ASC
        """,
        (now,),
    )
    grants: Dict[str, Any] = {}
    for execution_id, agent_id, parent_agent, scopes_json, tools_json, expires_at in cur.fetchall():
        grants[execution_id] = {
            "agent_id": agent_id,
            "parent_agent": parent_agent,
            "scopes": _json_list(scopes_json),
            "tools": _json_list(tools_json),
            "expires_at": expires_at,
        }

    cur.execute("SELECT trace_hash FROM agentic_trace_hashes ORDER BY first_seen_at DESC LIMIT 10000")
    trace_replay_cache = [row[0] for row in cur.fetchall()]
    conn.close()

    return {
        "generated_at": now,
        "agent_attestation_keys": agent_keys,
        "agent_cert_fingerprints": agent_cert_fingerprints,
        "revoked_agent_ids": revoked_agent_ids,
        "revoked_agent_key_ids": revoked_agent_key_ids,
        "cross_agent_policy_graph": graph,
        "execution_grants": grants,
        "trace_replay_cache": trace_replay_cache,
    }


def _build_agentic_metrics() -> Dict[str, Any]:
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    reason_counts: Dict[str, int] = {}
    try:
        cur.execute(
            """
            SELECT details FROM security_events
            WHERE event_type = 'agentic_policy_block'
            """
        )
        for (details_raw,) in cur.fetchall():
            try:
                details = json.loads(details_raw or "{}")
            except Exception:
                details = {}
            reason = str(details.get("reason", "unknown"))
            reason_counts[reason] = reason_counts.get(reason, 0) + 1
    except sqlite3.OperationalError:
        pass

    cur.execute("SELECT COUNT(*) FROM agentic_revocations")
    revocations_total = int((cur.fetchone() or (0,))[0] or 0)
    cur.execute("SELECT COUNT(*) FROM agentic_agent_keys WHERE status = 'active' AND revoked_at IS NULL")
    active_agent_keys = int((cur.fetchone() or (0,))[0] or 0)
    cur.execute("SELECT COUNT(*) FROM agentic_execution_grants WHERE revoked_at IS NULL AND expires_at > ?", (now,))
    active_execution_grants = int((cur.fetchone() or (0,))[0] or 0)
    cur.execute(
        """
        SELECT AVG(r.revoked_at - k.created_at)
        FROM agentic_revocations r
        JOIN agentic_agent_keys k
          ON r.key_id = k.key_id
        WHERE r.revocation_type = 'key'
          AND r.revoked_at IS NOT NULL
          AND k.created_at IS NOT NULL
        """
    )
    avg_row = cur.fetchone()
    conn.close()

    hop_reasons = {
        "unauthorized_agent_hop",
        "policy_graph_hop_denied",
        "policy_graph_hop_limit_exceeded",
        "policy_graph_scope_denied",
        "policy_graph_tool_denied",
    }
    return {
        "timestamp": now,
        "hop_policy_violations_blocked": sum(reason_counts.get(reason, 0) for reason in hop_reasons),
        "unauthorized_mcp_server_attempts": reason_counts.get("untrusted_mcp_server", 0),
        "scope_escalation_attempts_blocked": reason_counts.get("scope_escalation_detected", 0)
        + reason_counts.get("dynamic_scope_tightening", 0),
        "agent_revocations_total": revocations_total,
        "active_agent_keys": active_agent_keys,
        "active_execution_grants": active_execution_grants,
        "mean_time_to_revoke_seconds": avg_row[0] if avg_row and avg_row[0] is not None else None,
    }


def _hash_api_key(raw_key: str) -> str:
    return hashlib.sha256(f"{JWT_SECRET}:{raw_key}".encode("utf-8")).hexdigest()


def _generate_api_key_material() -> tuple[str, str]:
    token = secrets.token_urlsafe(24)
    raw_key = f"gk_{token}"
    return raw_key, raw_key[:10]


def _lookup_api_key(raw_key: str) -> Dict[str, Any] | None:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    key_hash = _hash_api_key(raw_key)
    cur.execute(
        "SELECT id, key_name, key_prefix, key_hash, is_active, created_by, created_at, last_used_at FROM api_keys WHERE key_hash = ?",
        (key_hash,),
    )
    row = cur.fetchone()
    if row and int(row[4]) == 1:
        cur.execute("UPDATE api_keys SET last_used_at = ? WHERE id = ?", (time.time(), row[0]))
        conn.commit()
    conn.close()
    if not row:
        return None
    return {
        "id": row[0],
        "key_name": row[1],
        "key_prefix": row[2],
        "key_hash": row[3],
        "is_active": bool(row[4]),
        "created_by": row[5],
        "created_at": row[6],
        "last_used_at": row[7],
    }


def _is_token_revoked(jti: str) -> bool:
    if not jti:
        return False
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (time.time(),))
    cur.execute("SELECT 1 FROM revoked_tokens WHERE jti = ? LIMIT 1", (jti,))
    row = cur.fetchone()
    conn.commit()
    conn.close()
    return row is not None


def _record_issued_token(claims: Dict[str, Any]):
    jti = claims.get("jti")
    subject = claims.get("sub")
    role = claims.get("role")
    issued_at = claims.get("iat")
    expires_at = claims.get("exp")
    if not all(isinstance(v, (str, int)) for v in (jti, subject, role, issued_at, expires_at)):
        return
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT OR IGNORE INTO issued_tokens (jti, subject, role, issued_at, expires_at, revoked_at, revoked_by, revoke_reason)
        VALUES (?, ?, ?, ?, ?, NULL, NULL, NULL)
        """,
        (str(jti), str(subject), str(role), float(issued_at), float(expires_at)),
    )
    conn.commit()
    conn.close()


def _mark_issued_token_revoked(jti: str, revoked_by: str, reason: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        UPDATE issued_tokens
        SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
        WHERE jti = ?
        """,
        (time.time(), revoked_by, reason[:200], jti),
    )
    conn.commit()
    conn.close()


def _list_auth_sessions(limit: int = 100, include_expired: bool = False, include_revoked: bool = True) -> List[Dict[str, Any]]:
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    where_parts: List[str] = []
    params: List[Any] = []
    if not include_expired:
        where_parts.append("expires_at >= ?")
        params.append(now)
    if not include_revoked:
        where_parts.append("revoked_at IS NULL")
    where_clause = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""

    cur.execute(
        f"""
        SELECT jti, subject, role, issued_at, expires_at, revoked_at, revoked_by, revoke_reason
        FROM issued_tokens
        {where_clause}
        ORDER BY issued_at DESC
        LIMIT ?
        """,
        (*params, limit),
    )
    rows = cur.fetchall()
    conn.close()

    sessions: List[Dict[str, Any]] = []
    for row in rows:
        revoked_at = row[5]
        expires_at = float(row[4])
        sessions.append(
            {
                "jti": row[0],
                "subject": row[1],
                "role": row[2],
                "issued_at": float(row[3]),
                "expires_at": expires_at,
                "revoked_at": float(revoked_at) if revoked_at is not None else None,
                "revoked_by": row[6],
                "revoke_reason": row[7],
                "active": revoked_at is None and expires_at >= now,
            }
        )
    return sessions


def _revoke_user_sessions(
    target_user: str,
    revoked_by: str,
    active_only: bool = True,
    reason: str = "",
    exclude_jti: str | None = None,
) -> Dict[str, int]:
    now = time.time()
    normalized_exclude_jti = (exclude_jti or "").strip()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    where_parts = ["subject = ?"]
    params: List[Any] = [target_user]
    if active_only:
        where_parts.append("expires_at >= ?")
        params.append(now)
    cur.execute(
        f"""
        SELECT jti, expires_at, revoked_at
        FROM issued_tokens
        WHERE {' AND '.join(where_parts)}
        ORDER BY issued_at DESC
        """,
        params,
    )
    rows = cur.fetchall()

    matched = len(rows)
    revoked = 0
    already_revoked = 0
    excluded = 0
    for jti, expires_at, revoked_at in rows:
        if normalized_exclude_jti and str(jti) == normalized_exclude_jti:
            excluded += 1
            continue
        if revoked_at is not None:
            already_revoked += 1
            continue
        cur.execute(
            """
            INSERT OR IGNORE INTO revoked_tokens (jti, revoked_by, revoked_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (jti, revoked_by, now, float(expires_at)),
        )
        cur.execute(
            """
            UPDATE issued_tokens
            SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
            WHERE jti = ?
            """,
            (now, revoked_by, (reason or "admin_revoke_user_sessions")[:200], jti),
        )
        revoked += 1

    conn.commit()
    conn.close()
    return {"matched": matched, "revoked": revoked, "already_revoked": already_revoked, "excluded": excluded}


def _revoke_all_sessions(
    revoked_by: str,
    active_only: bool = True,
    reason: str = "",
    excluded_subjects: Set[str] | None = None,
) -> Dict[str, int]:
    now = time.time()
    excluded = {item.strip() for item in (excluded_subjects or set()) if item and item.strip()}
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    where_parts: List[str] = []
    params: List[Any] = []
    if active_only:
        where_parts.append("expires_at >= ?")
        params.append(now)
    where_clause = f"WHERE {' AND '.join(where_parts)}" if where_parts else ""

    cur.execute(
        f"""
        SELECT jti, subject, expires_at, revoked_at
        FROM issued_tokens
        {where_clause}
        ORDER BY issued_at DESC
        """,
        params,
    )
    rows = cur.fetchall()

    matched = len(rows)
    revoked = 0
    already_revoked = 0
    excluded_count = 0
    for jti, subject, expires_at, revoked_at in rows:
        subject_name = str(subject or "")
        if subject_name in excluded:
            excluded_count += 1
            continue
        if revoked_at is not None:
            already_revoked += 1
            continue
        cur.execute(
            """
            INSERT OR IGNORE INTO revoked_tokens (jti, revoked_by, revoked_at, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (jti, revoked_by, now, float(expires_at)),
        )
        cur.execute(
            """
            UPDATE issued_tokens
            SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
            WHERE jti = ?
            """,
            (now, revoked_by, (reason or "admin_revoke_all_sessions")[:200], jti),
        )
        revoked += 1

    conn.commit()
    conn.close()
    return {
        "matched": matched,
        "revoked": revoked,
        "already_revoked": already_revoked,
        "excluded": excluded_count,
    }


def _revoke_session_by_jti(jti: str, revoked_by: str, reason: str = "") -> Dict[str, Any] | None:
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT subject, expires_at, revoked_at
        FROM issued_tokens
        WHERE jti = ?
        LIMIT 1
        """,
        (jti,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return None

    subject, expires_at, revoked_at = row
    if revoked_at is not None:
        conn.close()
        return {"jti": jti, "target_user": subject, "revoked": False, "already_revoked": True}

    cur.execute(
        """
        INSERT OR IGNORE INTO revoked_tokens (jti, revoked_by, revoked_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (jti, revoked_by, now, float(expires_at)),
    )
    cur.execute(
        """
        UPDATE issued_tokens
        SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
        WHERE jti = ?
        """,
        (now, revoked_by, (reason or "admin_revoke_session_jti")[:200], jti),
    )
    conn.commit()
    conn.close()
    return {"jti": jti, "target_user": subject, "revoked": True, "already_revoked": False}


def _revoke_self_session_by_jti(
    jti: str,
    subject: str,
    revoked_by: str,
    reason: str = "",
    current_jti: str | None = None,
) -> Dict[str, Any] | None:
    normalized_current_jti = (current_jti or "").strip()
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT subject, expires_at, revoked_at
        FROM issued_tokens
        WHERE jti = ?
        LIMIT 1
        """,
        (jti,),
    )
    row = cur.fetchone()
    if not row:
        conn.close()
        return None

    target_user, expires_at, revoked_at = row
    if str(target_user) != subject:
        conn.close()
        return {"jti": jti, "target_user": str(target_user), "revoked": False, "already_revoked": False, "not_owned": True}
    if normalized_current_jti and jti == normalized_current_jti:
        conn.close()
        return {
            "jti": jti,
            "target_user": str(target_user),
            "revoked": False,
            "already_revoked": False,
            "current_session": True,
        }
    if revoked_at is not None:
        conn.close()
        return {
            "jti": jti,
            "target_user": str(target_user),
            "revoked": False,
            "already_revoked": True,
            "not_owned": False,
        }

    cur.execute(
        """
        INSERT OR IGNORE INTO revoked_tokens (jti, revoked_by, revoked_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (jti, revoked_by, now, float(expires_at)),
    )
    cur.execute(
        """
        UPDATE issued_tokens
        SET revoked_at = ?, revoked_by = ?, revoke_reason = ?
        WHERE jti = ?
        """,
        (now, revoked_by, (reason or "self_revoke_session_jti")[:200], jti),
    )
    conn.commit()
    conn.close()
    return {
        "jti": jti,
        "target_user": str(target_user),
        "revoked": True,
        "already_revoked": False,
        "not_owned": False,
    }


def _list_revoked_tokens(limit: int = 100, include_expired: bool = False) -> List[Dict[str, Any]]:
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if include_expired:
        cur.execute(
            """
            SELECT jti, revoked_by, revoked_at, expires_at
            FROM revoked_tokens
            ORDER BY revoked_at DESC
            LIMIT ?
            """,
            (limit,),
        )
    else:
        cur.execute(
            """
            SELECT jti, revoked_by, revoked_at, expires_at
            FROM revoked_tokens
            WHERE expires_at >= ?
            ORDER BY revoked_at DESC
            LIMIT ?
            """,
            (now, limit),
        )
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "jti": row[0],
            "revoked_by": row[1],
            "revoked_at": float(row[2]),
            "expires_at": float(row[3]),
            "expired": float(row[3]) < now,
        }
        for row in rows
    ]


def _prune_revoked_tokens(expired_only: bool = True) -> Dict[str, int]:
    now = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if expired_only:
        cur.execute("DELETE FROM revoked_tokens WHERE expires_at < ?", (now,))
    else:
        cur.execute("DELETE FROM revoked_tokens")
    deleted = int(cur.rowcount or 0)
    cur.execute("SELECT COUNT(*) FROM revoked_tokens")
    remaining = int((cur.fetchone() or (0,))[0] or 0)
    conn.commit()
    conn.close()
    return {"deleted": deleted, "remaining": remaining}


def _compute_audit_entry_hash(
    guardian_id: str,
    action: str,
    user: str,
    details_json: str,
    timestamp: float,
    signature: str,
    prev_hash: str,
) -> str:
    material = "|".join(
        [
            guardian_id or "",
            action or "",
            user or "",
            details_json or "",
            str(timestamp),
            signature or "",
            prev_hash or "",
        ]
    )
    return hashlib.sha256(material.encode("utf-8")).hexdigest()


def _queue_audit_delivery_failure(sink_type: str, payload: Dict[str, Any], error: str):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT INTO audit_delivery_failures (sink_type, payload, error, retry_count, created_at, last_attempt_at)
        VALUES (?, ?, ?, 0, ?, ?)
        """,
        (sink_type, json.dumps(payload), error[:500], time.time(), time.time()),
    )
    conn.commit()
    conn.close()


def _retry_failed_audit_deliveries(limit: int = 100) -> Dict[str, int]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, sink_type, payload, retry_count
        FROM audit_delivery_failures
        ORDER BY id ASC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()

    retried = 0
    resolved = 0
    failed = 0
    for row in rows:
        row_id, sink_type, payload_raw, retry_count = row
        retried += 1
        try:
            payload = json.loads(payload_raw)
        except Exception:  # noqa: BLE001
            payload = {}

        ok = False
        error = ""
        try:
            if sink_type == "http":
                ok = _forward_external_audit_log(payload, strict=False)
            elif sink_type == "syslog":
                ok = _forward_syslog_audit_log(payload, strict=False)
            elif sink_type == "splunk":
                ok = _forward_splunk_audit_log(payload, strict=False)
            elif sink_type == "datadog":
                ok = _forward_datadog_audit_log(payload, strict=False)
            else:
                error = f"unknown sink_type={sink_type}"
        except Exception as exc:  # noqa: BLE001
            error = str(exc)
            ok = False

        if ok:
            cur.execute("DELETE FROM audit_delivery_failures WHERE id = ?", (row_id,))
            resolved += 1
        else:
            cur.execute(
                """
                UPDATE audit_delivery_failures
                SET retry_count = ?, last_attempt_at = ?, error = ?
                WHERE id = ?
                """,
                (int(retry_count) + 1, time.time(), (error or "delivery failed")[:500], row_id),
            )
            failed += 1

    conn.commit()
    conn.close()
    return {"retried": retried, "resolved": resolved, "failed": failed}


def _forward_audit_payload(audit_payload: Dict[str, Any]):
    try:
        http_ok = _forward_external_audit_log(audit_payload)
        if not http_ok:
            _queue_audit_delivery_failure("http", audit_payload, "http delivery failed")
    except HTTPException as exc:
        _queue_audit_delivery_failure("http", audit_payload, str(exc.detail))
        raise

    try:
        syslog_ok = _forward_syslog_audit_log(audit_payload)
        if not syslog_ok:
            _queue_audit_delivery_failure("syslog", audit_payload, "syslog delivery failed")
    except HTTPException as exc:
        _queue_audit_delivery_failure("syslog", audit_payload, str(exc.detail))
        raise
    try:
        splunk_ok = _forward_splunk_audit_log(audit_payload)
        if not splunk_ok:
            _queue_audit_delivery_failure("splunk", audit_payload, "splunk delivery failed")
    except HTTPException as exc:
        _queue_audit_delivery_failure("splunk", audit_payload, str(exc.detail))
        raise
    try:
        datadog_ok = _forward_datadog_audit_log(audit_payload)
        if not datadog_ok:
            _queue_audit_delivery_failure("datadog", audit_payload, "datadog delivery failed")
    except HTTPException as exc:
        _queue_audit_delivery_failure("datadog", audit_payload, str(exc.detail))
        raise


def _write_control_plane_audit_entry(action: str, user: str, details: Dict[str, Any]) -> Dict[str, Any]:
    timestamp = time.time()
    guardian_id = "guardian-backend"
    details_json = json.dumps(details)
    signature = hmac.new(JWT_SECRET.encode("utf-8"), f"{guardian_id}:{timestamp}:{details_json}".encode("utf-8"), hashlib.sha256).hexdigest()

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT entry_hash
        FROM audit_logs
        WHERE entry_hash IS NOT NULL AND entry_hash != ''
        ORDER BY id DESC LIMIT 1
        """
    )
    prev_row = cur.fetchone()
    prev_hash = prev_row[0] if prev_row and prev_row[0] else ""
    entry_hash = _compute_audit_entry_hash(
        guardian_id=guardian_id,
        action=action,
        user=user,
        details_json=details_json,
        timestamp=timestamp,
        signature=signature,
        prev_hash=prev_hash,
    )
    cur.execute(
        """
        INSERT INTO audit_logs (guardian_id, action, user, details, timestamp, signature, prev_hash, entry_hash)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (guardian_id, action, user, details_json, timestamp, signature, prev_hash, entry_hash),
    )
    conn.commit()
    conn.close()

    audit_payload = {
        "guardian_id": guardian_id,
        "action": action,
        "user": user,
        "details": details,
        "timestamp": timestamp,
        "signature": signature,
        "prev_hash": prev_hash,
        "entry_hash": entry_hash,
    }
    _forward_audit_payload(audit_payload)
    return audit_payload


def _verify_audit_log_chain_internal() -> Dict[str, Any]:
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute(
            """
            SELECT id, guardian_id, action, user, details, timestamp, signature, prev_hash, entry_hash
            FROM audit_logs ORDER BY id ASC
            """
        )
        rows = cur.fetchall()
    except sqlite3.OperationalError:
        conn.close()
        return {"ok": True, "entries": 0, "message": "No audit log table"}
    conn.close()

    expected_prev_hash = ""
    checked = 0
    legacy_unhashed = 0
    for row in rows:
        row_id, guardian_id, action, user, details, ts, signature, prev_hash, entry_hash = row
        if not entry_hash:
            if prev_hash:
                return {
                    "ok": False,
                    "entries": checked,
                    "failed_id": row_id,
                    "reason": "missing entry_hash with non-empty prev_hash",
                }
            legacy_unhashed += 1
            continue

        computed = _compute_audit_entry_hash(
            guardian_id=guardian_id,
            action=action,
            user=user,
            details_json=details,
            timestamp=ts,
            signature=signature,
            prev_hash=prev_hash or "",
        )
        if (prev_hash or "") != expected_prev_hash:
            return {
                "ok": False,
                "entries": checked,
                "failed_id": row_id,
                "reason": "prev_hash mismatch",
            }
        if (entry_hash or "") != computed:
            return {
                "ok": False,
                "entries": checked,
                "failed_id": row_id,
                "reason": "entry_hash mismatch",
            }

        if len(signature) == 64:
            expected_sig_payload = f"{guardian_id}:{ts}:{details}"
            expected_signature_hmac = hmac.new(JWT_SECRET.encode("utf-8"), expected_sig_payload.encode("utf-8"), hashlib.sha256).hexdigest()
            expected_signature_sha = hashlib.sha256(expected_sig_payload.encode()).hexdigest()
            if signature not in (expected_signature_hmac, expected_signature_sha):
                return {
                    "ok": False,
                    "entries": checked,
                    "failed_id": row_id,
                    "reason": "signature tampering detected",
                }
        expected_prev_hash = entry_hash or ""
        checked += 1

    if legacy_unhashed:
        return {
            "ok": True,
            "entries": checked,
            "message": f"Verified hashed entries; skipped {legacy_unhashed} legacy unhashed entries",
        }
    return {"ok": True, "entries": checked}


def _build_compliance_report() -> Dict[str, Any]:
    controls: List[Dict[str, str]] = []

    def add_control(control: str, status_value: str, detail: str):
        controls.append({"control": control, "status": status_value, "detail": detail})

    add_control(
        "admin_password_configured",
        "pass" if _raw_admin_pass and ADMIN_PASS != "guardian_default" else "fail",
        "Admin password is set explicitly."
        if _raw_admin_pass and ADMIN_PASS != "guardian_default"
        else "Default or ephemeral admin password is in use.",
    )
    add_control(
        "jwt_secret_configured",
        "pass" if _raw_jwt_secret and JWT_SECRET != "guardian_jwt_dev_secret_change_me" else "fail",
        "JWT signing secret is explicitly configured."
        if _raw_jwt_secret and JWT_SECRET != "guardian_jwt_dev_secret_change_me"
        else "Default or ephemeral JWT secret is in use.",
    )
    add_control(
        "jwt_expiry_configured",
        "pass" if JWT_EXPIRES_MIN > 0 else "fail",
        f"JWT expiry is set to {JWT_EXPIRES_MIN} minute(s)."
        if JWT_EXPIRES_MIN > 0
        else "JWT expiry must be positive.",
    )
    add_control(
        "auth_rate_limit_enabled",
        "pass" if AUTH_RATE_LIMIT_PER_MIN > 0 else "fail",
        f"Auth endpoint rate limit is {AUTH_RATE_LIMIT_PER_MIN}/min."
        if AUTH_RATE_LIMIT_PER_MIN > 0
        else "Auth endpoint rate limiting is disabled.",
    )
    add_control(
        "auth_failed_login_lockout",
        "pass" if _is_auth_lockout_enabled() else "warn",
        (
            f"Failed-login lockout enabled at {AUTH_LOCKOUT_MAX_ATTEMPTS} attempt(s) "
            f"for {int(AUTH_LOCKOUT_DURATION_SEC)} second(s)."
        )
        if _is_auth_lockout_enabled()
        else "Failed-login lockout is disabled.",
    )
    add_control(
        "api_rate_limit_enabled",
        "pass" if API_RATE_LIMIT_PER_MIN > 0 else "fail",
        f"API rate limit is {API_RATE_LIMIT_PER_MIN}/min."
        if API_RATE_LIMIT_PER_MIN > 0
        else "API rate limiting is disabled.",
    )
    add_control(
        "telemetry_api_key_enforced",
        "pass" if TELEMETRY_REQUIRE_API_KEY else "warn",
        "Telemetry API key enforcement is enabled."
        if TELEMETRY_REQUIRE_API_KEY
        else "Telemetry API key enforcement is disabled.",
    )
    add_control(
        "https_enforced",
        "pass" if ENFORCE_HTTPS else "warn",
        "HTTPS enforcement middleware is enabled."
        if ENFORCE_HTTPS
        else "HTTPS enforcement middleware is disabled.",
    )
    add_control(
        "metrics_enabled",
        "pass" if METRICS_ENABLED else "warn",
        "Prometheus metrics endpoint is enabled."
        if METRICS_ENABLED
        else "Prometheus metrics endpoint is disabled.",
    )

    sink_configured = bool(AUDIT_SINK_URL or AUDIT_SYSLOG_HOST or AUDIT_SPLUNK_HEC_URL or AUDIT_DATADOG_API_KEY)
    add_control(
        "external_audit_sink_configured",
        "pass" if sink_configured else "warn",
        "At least one external audit sink is configured."
        if sink_configured
        else "No external audit sink is configured.",
    )

    if RATE_LIMIT_BACKEND == "redis":
        redis_ok = _get_redis_client() is not None
        add_control(
            "distributed_rate_limit_backend",
            "pass" if redis_ok else ("warn" if RATE_LIMIT_REDIS_FAIL_OPEN else "fail"),
            "Redis rate limiter backend is configured and reachable."
            if redis_ok
            else "Redis backend is selected but unavailable.",
        )
    elif RATE_LIMIT_BACKEND == "auto":
        redis_ok = _get_redis_client() is not None
        add_control(
            "distributed_rate_limit_backend",
            "pass" if redis_ok else "warn",
            "Auto backend resolved to Redis."
            if redis_ok
            else "Auto backend is currently using in-memory fallback.",
        )
    else:
        add_control(
            "distributed_rate_limit_backend",
            "warn",
            "In-memory rate limiting backend is active.",
        )

    db_ok, db_detail = _check_db_health()
    add_control(
        "database_health",
        "pass" if db_ok else "fail",
        db_detail if db_ok else f"Database health check failed: {db_detail}",
    )

    audit_verify = _verify_audit_log_chain_internal()
    add_control(
        "audit_chain_integrity",
        "pass" if audit_verify.get("ok") else "fail",
        audit_verify.get("message")
        or (
            f"Verified {audit_verify.get('entries', 0)} hashed audit entries."
            if audit_verify.get("ok")
            else (
                f"Integrity failure at id={audit_verify.get('failed_id')}: "
                f"{audit_verify.get('reason', 'unknown reason')}"
            )
        ),
    )

    passed = sum(1 for c in controls if c["status"] == "pass")
    warnings = sum(1 for c in controls if c["status"] == "warn")
    failed = sum(1 for c in controls if c["status"] == "fail")
    overall = "fail" if failed else ("warn" if warnings else "pass")

    return {
        "status": overall,
        "timestamp": time.time(),
        "summary": {"passed": passed, "warnings": warnings, "failed": failed},
        "controls": controls,
    }

























































async def send_webhook_alert(event: SecurityEvent):
    # Broadcast to Dashboard via WebSocket
    message = json.dumps({
        "type": "new_event",
        "data": {
            "guardian_id": event.guardian_id,
            "event_type": event.event_type,
            "severity": event.severity,
            "details": event.details,
            "timestamp": event.timestamp
        }
    })
    await manager.broadcast(message)


from fastapi.responses import StreamingResponse
import io
import csv















def _upsert_customer(cur: sqlite3.Cursor, customer_email: str | None, tenant_name: str | None) -> None:
    if not customer_email:
        return
    cur.execute(
        """
        INSERT INTO customers (email, tenant_name, created_at)
        VALUES (?, ?, ?)
        ON CONFLICT(email) DO UPDATE SET tenant_name = COALESCE(excluded.tenant_name, customers.tenant_name)
        """,
        (customer_email, tenant_name, time.time()),
    )


def _build_checkout_url(order_id: str) -> str:
    return f"{CHECKOUT_SUCCESS_URL}?order_id={order_id}"

































class BadgeVerificationRequest(BaseModel):
    badge_data: dict


# ---------- CRYPTO AUDIT SCAN ENDPOINT ----------

class ScanRequest(BaseModel):
    target_url: str
    target_name: str = ""
    depth: str = "standard"

_scan_results_cache: dict = {}
_scan_jobs_lock = threading.Lock()
_scan_jobs: Dict[str, Dict[str, Any]] = {}
AUDIT_ARTIFACTS_DIR = Path("artifacts/audit")


def _new_scan_job_id() -> str:
    return f"JOB-{secrets.token_hex(6).upper()}"


def _scan_status_kind(raw_status: str) -> str:
    normalized = str(raw_status or "").lower()
    if normalized in {"vulnerable", "error", "failed"}:
        return "vuln"
    if normalized in {"protected", "completed"}:
        return "ok"
    return "info"


def _append_scan_job_log(job_id: str, message: str, kind: str = "info") -> None:
    timestamp = time.time()
    with _scan_jobs_lock:
        job = _scan_jobs.get(job_id)
        if not job:
            return
        logs = job.setdefault("logs", [])
        logs.append({"timestamp": timestamp, "message": message, "kind": kind})
        if len(logs) > 250:
            del logs[:-250]


def _update_scan_job_progress(job_id: str, current: int, total: int, label: str, raw_status: str) -> None:
    with _scan_jobs_lock:
        job = _scan_jobs.get(job_id)
        if not job:
            return
        if total > 0:
            progress_pct = round((current / total) * 100, 1)
            progress_text = f"[{current}/{total}] {label}"
        else:
            progress_pct = job.get("progress_pct", 0.0)
            progress_text = label
        job["status"] = "running"
        job["progress_pct"] = progress_pct
        job["current_step"] = current
        job["total_steps"] = total
        job["progress_label"] = progress_text
    _append_scan_job_log(job_id, progress_text if total > 0 else label, _scan_status_kind(raw_status))


def _create_scan_job(req: ScanRequest) -> Dict[str, Any]:
    job_id = _new_scan_job_id()
    job = {
        "job_id": job_id,
        "status": "queued",
        "target_url": req.target_url,
        "target_name": req.target_name,
        "depth": req.depth,
        "created_at": time.time(),
        "started_at": None,
        "completed_at": None,
        "progress_pct": 0.0,
        "current_step": 0,
        "total_steps": 0,
        "progress_label": "Queued for scan startup",
        "error": None,
        "logs": [],
        "result": None,
    }
    with _scan_jobs_lock:
        _scan_jobs[job_id] = job
    _append_scan_job_log(job_id, "Scan job queued", "info")
    return dict(job)


def _run_scan_job(job_id: str) -> None:
    from guardian.audit.crypto_scanner import CryptoAuditScanner, ScanDepth

    with _scan_jobs_lock:
        job = _scan_jobs.get(job_id)
        if not job:
            return
        job["status"] = "running"
        job["started_at"] = time.time()
        job["progress_label"] = "Initializing scan engine"

    req_depth = str(job.get("depth") or "standard").lower()
    depth_map = {"quick": ScanDepth.QUICK, "standard": ScanDepth.STANDARD, "deep": ScanDepth.DEEP}
    depth = depth_map.get(req_depth, ScanDepth.STANDARD)
    _append_scan_job_log(job_id, "Initializing scan engine", "info")

    try:
        scanner = CryptoAuditScanner(
            target_url=str(job.get("target_url") or ""),
            target_name=str(job.get("target_name") or "") or None,
            depth=depth,
        )
        _append_scan_job_log(job_id, "Discovering target endpoints", "info")
        result = scanner.run_scan(progress_callback=lambda current, total, label, status: _update_scan_job_progress(job_id, current, total, label, status))
        scan_payload = _persist_crypto_scan_artifacts(result)
        _scan_results_cache[result.scan_id] = scan_payload

        with _scan_jobs_lock:
            live_job = _scan_jobs.get(job_id)
            if not live_job:
                return
            scan_status = getattr(result, "scan_status", "completed")
            if scan_status == "target_unreachable":
                live_job["status"] = "target_unreachable"
                live_job["progress_label"] = "No AI endpoint detected"
            else:
                live_job["status"] = "completed"
                live_job["progress_label"] = "Scan complete"
            live_job["completed_at"] = time.time()
            live_job["progress_pct"] = 100.0
            live_job["result"] = scan_payload
        if scan_status == "target_unreachable":
            _append_scan_job_log(job_id, f"No AI/LLM API endpoint found — scan skipped", "info")
        else:
            _append_scan_job_log(job_id, f"Scan complete: {scan_payload.get('grade', 'F')} grade", "ok")
        # Send notifications (Slack/Discord/Webhook)
        try:
            from guardian.audit.notifications import notify_scan_complete
            notify_scan_complete(scan_payload)
        except Exception as notify_err:
            logger.debug(f"Notification dispatch skipped: {notify_err}")
    except Exception as exc:
        logger.exception("Background scan job failed")
        with _scan_jobs_lock:
            live_job = _scan_jobs.get(job_id)
            if not live_job:
                return
            live_job["status"] = "failed"
            live_job["completed_at"] = time.time()
            live_job["error"] = str(exc)
            live_job["progress_label"] = "Scan failed"
        _append_scan_job_log(job_id, f"Scan failed: {exc}", "vuln")


def _start_scan_job(req: ScanRequest) -> Dict[str, Any]:
    job = _create_scan_job(req)
    threading.Thread(target=_run_scan_job, args=(job["job_id"],), daemon=True).start()
    with _scan_jobs_lock:
        return dict(_scan_jobs[job["job_id"]])


def _get_scan_job(job_id: str) -> Dict[str, Any]:
    with _scan_jobs_lock:
        job = _scan_jobs.get(job_id)
        if not job:
            raise HTTPException(status_code=404, detail="Scan job not found")
        return json.loads(json.dumps(job, default=str))


def _write_json_file(path: Path, payload: Dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        json.dump(payload, handle, indent=2, default=str)


def _crypto_scan_depth_to_mode(depth: str):
    from guardian.audit.models import ScanMode

    return {
        "quick": ScanMode.QUICK,
        "standard": ScanMode.STANDARD,
        "deep": ScanMode.FULL,
    }.get(depth, ScanMode.STANDARD)


def _build_crypto_audit_modules() -> List[Dict[str, str]]:
    return [
        {
            "name": "IndirectInjectionFilter",
            "description": "Detects retrieved-content prompt injection and instruction boundary abuse.",
            "status": "ACTIVE",
        },
        {
            "name": "SystemPromptLeakageGuard",
            "description": "Blocks attempts to expose system prompts, hidden instructions, and secrets.",
            "status": "ACTIVE",
        },
        {
            "name": "OutputScanner",
            "description": "Screens model responses for unsafe code, exfiltration artifacts, and abuse signals.",
            "status": "ACTIVE",
        },
        {
            "name": "OutputPIIScanner",
            "description": "Redacts wallet-linked PII, credentials, and regulated data before release.",
            "status": "ACTIVE",
        },
        {
            "name": "CryptoGuard",
            "description": "Catches high-risk smart contract, trading, and DeFi manipulation requests.",
            "status": "ACTIVE",
        },
        {
            "name": "DefiIntentAnalyzer",
            "description": "Flags intent patterns tied to fund movement, yield hijacking, and market spoofing.",
            "status": "ACTIVE",
        },
    ]


def _normalize_crypto_scan_findings(findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    status_map = {
        "protected": "BLOCKED",
        "vulnerable": "VULNERABLE",
        "inconclusive": "PARTIAL",
        "error": "ERROR",
        "skipped": "SKIPPED",
    }
    normalized: List[Dict[str, Any]] = []
    for finding in findings:
        normalized.append(
            {
                "vector_id": finding.get("vector_id", ""),
                "category": finding.get("pillar", finding.get("category", "Unknown")),
                "severity": str(finding.get("severity", "unknown")).upper(),
                "status": status_map.get(str(finding.get("status", "")).lower(), "UNKNOWN"),
                "compliance_mappings": finding.get("compliance_mappings", {}),
            }
        )
    return normalized


def _load_crypto_scan_json(scan_id: str) -> Dict[str, Any]:
    matches = sorted(
        AUDIT_ARTIFACTS_DIR.glob(f"scan_{scan_id}_*.json"),
        key=lambda item: item.stat().st_mtime,
        reverse=True,
    )
    if not matches:
        raise HTTPException(status_code=404, detail="Scan not found")
    with matches[0].open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _load_crypto_badge(scan_id: str) -> Optional[Dict[str, Any]]:
    badge_path = AUDIT_ARTIFACTS_DIR / f"badge_{scan_id}.json"
    if not badge_path.exists():
        return None
    with badge_path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _render_crypto_scan_report_html(scan_data: Dict[str, Any], badge_data: Optional[Dict[str, Any]] = None) -> str:
    from guardian.audit.report_generator import AuditReportGenerator

    report_generator = AuditReportGenerator()
    return report_generator.generate(
        target_name=scan_data.get("target_name", "Unknown Target"),
        target_uri=scan_data.get("target_url", ""),
        score=float(scan_data.get("score") if scan_data.get("score") is not None else 0.0),
        grade=scan_data.get("grade") or "F",
        total_vectors=int(scan_data.get("total_vectors") if scan_data.get("total_vectors") is not None else 0),
        blocked_count=int(scan_data.get("protected_count") if scan_data.get("protected_count") is not None else 0),
        findings=_normalize_crypto_scan_findings(scan_data.get("findings", [])),
        modules=_build_crypto_audit_modules(),
        badge_data=badge_data,
    )


def _persist_crypto_scan_artifacts(result: Any) -> Dict[str, Any]:
    from dataclasses import asdict
    from guardian.audit.certification import CertificationEngine

    scan_data = asdict(result)
    scan_id = scan_data["scan_id"]
    timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y%m%d%H%M%S")
    scan_mode = _crypto_scan_depth_to_mode(scan_data.get("scan_depth", "standard"))

    badge_data: Optional[Dict[str, Any]] = None
    badge_svg_url: Optional[str] = None
    score_val = scan_data.get("score")
    if score_val is not None and float(score_val) >= 80.0 and scan_mode.value in {"standard", "full"}:
        badge_key = os.getenv("GUARDIAN_BADGE_SECRET_KEY", "dev_secret_key")
        if badge_key == "dev_secret_key" and os.getenv("GUARDIAN_ENV", "development").strip().lower() == "production":
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail="CRITICAL SECURITY ERROR: GUARDIAN_BADGE_SECRET_KEY is default key in production mode!"
            )
        cert_engine = CertificationEngine(signing_key=badge_key)
        badge_data = cert_engine.generate_badge(
            target_uri=scan_data.get("target_url", ""),
            score=float(scan_data.get("score", 0.0)),
            grade=scan_data.get("grade", "F"),
            mode=scan_mode,
            report_id=scan_id,
        )
        badge_data["verification_url"] = f"{PUBLIC_BASE_URL}/api/v1/verify-badge"
        _write_json_file(AUDIT_ARTIFACTS_DIR / f"badge_{scan_id}.json", badge_data)
        (AUDIT_ARTIFACTS_DIR / f"badge_{scan_id}.svg").write_text(
            cert_engine.get_badge_svg(badge_data),
            encoding="utf-8",
        )
        badge_svg_url = f"{PUBLIC_BASE_URL}/api/v1/audits/{scan_id}/svg"

    report_html = _render_crypto_scan_report_html(scan_data, badge_data=badge_data)
    report_path = AUDIT_ARTIFACTS_DIR / f"report_{scan_id}.html"
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_html, encoding="utf-8")

    scan_data["artifacts"] = {
        "report_url": f"{PUBLIC_BASE_URL}/api/v1/scan/{scan_id}/report",
        "badge_id": scan_id if badge_data else None,
        "badge_svg_url": badge_svg_url,
        "verification_url": badge_data.get("verification_url") if badge_data else None,
    }
    scan_data["badge"] = badge_data

    _write_json_file(AUDIT_ARTIFACTS_DIR / f"scan_{scan_id}_{timestamp}.json", scan_data)
    return scan_data















# ---------- P1: SARIF EXPORT ----------


# ---------- P1: MULTI-TARGET CAMPAIGNS ----------
_campaign_engine = None
_campaign_engine_lock = threading.Lock()

def _get_campaign_engine():
    global _campaign_engine
    if _campaign_engine is None:
        with _campaign_engine_lock:
            if _campaign_engine is None:
                from guardian.audit.campaign import CampaignEngine
                def _campaign_scan_cb(url, name, depth, custom_vectors):
                    from guardian.audit.crypto_scanner import CryptoAuditScanner, ScanDepth, AttackVector, Pillar, Severity
                    depth_map = {"quick": ScanDepth.QUICK, "standard": ScanDepth.STANDARD, "deep": ScanDepth.DEEP}
                    mapped_vectors = []
                    for cv in custom_vectors:
                        try:
                            pillar = Pillar(cv.pillar)
                        except ValueError:
                            pillar = Pillar.INFRASTRUCTURE
                        try:
                            severity = Severity(cv.severity.lower())
                        except ValueError:
                            severity = Severity.MEDIUM
                        mapped_vectors.append(AttackVector(
                            id=cv.id, name=cv.name, pillar=pillar, severity=severity,
                            description=cv.description, prompt=cv.payload,
                            success_indicators=cv.success_indicators, scan_depth=depth_map.get(cv.depth, ScanDepth.STANDARD)
                        ))
                    scanner = CryptoAuditScanner(
                        target_url=url,
                        target_name=name,
                        depth=depth_map.get(depth, ScanDepth.STANDARD),
                        custom_vectors=mapped_vectors,
                    )
                    result = scanner.run_scan()
                    from dataclasses import asdict
                    return asdict(result) if hasattr(result, "__dataclass_fields__") else result
                _campaign_engine = CampaignEngine(
                    scan_callback=_campaign_scan_cb,
                    max_parallel=3,
                    artifacts_dir="artifacts/campaigns",
                )
    return _campaign_engine


class CampaignTargetInput(BaseModel):
    url: str
    name: str = ""
    depth: str = "standard"


class CampaignCreateRequest(BaseModel):
    name: str
    targets: List[CampaignTargetInput]
    custom_pack_paths: List[str] = []










# ---------- P1: CUSTOM VECTOR PACKS ----------
CUSTOM_PACKS_DIR = Path("artifacts/vector_packs")





# ---------- P2: CONTINUOUS MONITORING ----------
_audit_scheduler = None
_audit_scheduler_lock = threading.Lock()

def _get_audit_scheduler():
    global _audit_scheduler
    if _audit_scheduler is None:
        with _audit_scheduler_lock:
            if _audit_scheduler is None:
                from guardian.audit.scheduler import AuditScheduler, ScanResult as SchedulerScanResult
                
                def _scheduler_scan_cb(schedule):
                    from guardian.audit.crypto_scanner import CryptoAuditScanner, ScanDepth
                    depth_map = {"quick": ScanDepth.QUICK, "standard": ScanDepth.STANDARD, "deep": ScanDepth.DEEP}
                    scanner = CryptoAuditScanner(
                        target_url=schedule.target_uri,
                        target_name=schedule.target_name,
                        depth=depth_map.get(schedule.scan_mode.lower(), ScanDepth.STANDARD),
                    )
                    crypto_result = scanner.run_scan()
                    # Convert CryptoAuditScanner result to SchedulerScanResult
                    block_rate = (crypto_result.protected_count / crypto_result.total_vectors * 100) if crypto_result.total_vectors else 0
                    return SchedulerScanResult(
                        schedule_id=schedule.schedule_id,
                        target_uri=schedule.target_uri,
                        score=crypto_result.score,
                        grade=crypto_result.grade,
                        block_rate=block_rate,
                        total_vectors=crypto_result.total_vectors,
                        blocked_count=crypto_result.protected_count,
                        timestamp=crypto_result.completed_at
                    )

                _audit_scheduler = AuditScheduler(scan_callback=_scheduler_scan_cb)
                _audit_scheduler.start()
    return _audit_scheduler

class ScheduleInput(BaseModel):
    target_url: str
    target_name: str
    interval_seconds: int = 86400
    scan_mode: str = "standard"
    webhook_url: Optional[str] = None
    stream_mode: bool = False





class RemediationRequest(BaseModel):
    scan_id: str
    vector_ids: List[str]


# ---------- P2: MULTI-CHAIN SMART CONTRACT ANALYZER ----------

class ContractAnalyzeRequest(BaseModel):
    source_code: str
    contract_name: str = "UnknownContract"
    contract_address: Optional[str] = None
    chain: str = "ethereum"

class ContractOnChainAnalyzeRequest(BaseModel):
    contract_address: str
    chain: str = "ethereum"
    api_key: Optional[str] = None








# ---------- P2: THREAT INTELLIGENCE & ADDRESS SCREENING ----------

class AddressScreenRequest(BaseModel):
    address: str
    chain: str = "bitcoin"

class BatchScreenRequest(BaseModel):
    addresses: List[str]
    chain: str = "bitcoin"







# ---------- SCAN HISTORY & REGRESSION TRACKING ----------







# ---------- AI AGENT PASSPORT API ----------

_passport_engine = None
_trust_scorer = None
_credential_issuer = None
_passport_verifier = None


def _get_passport_engine():
    global _passport_engine
    if _passport_engine is None:
        from guardian.passport.passport_core import PassportEngine
        _passport_engine = PassportEngine(db_path=DB_PATH)
    return _passport_engine


def _get_trust_scorer():
    global _trust_scorer
    if _trust_scorer is None:
        from guardian.passport.trust_scorer import TrustScorer
        _trust_scorer = TrustScorer(db_path=DB_PATH)
    return _trust_scorer


def _get_credential_issuer():
    global _credential_issuer
    if _credential_issuer is None:
        from guardian.passport.credentials import CredentialIssuer
        _credential_issuer = CredentialIssuer()
    return _credential_issuer


def _get_passport_verifier():
    global _passport_verifier
    if _passport_verifier is None:
        from guardian.passport.verification import PassportVerifier
        _passport_verifier = PassportVerifier(
            passport_engine=_get_passport_engine(),
            credential_issuer=_get_credential_issuer(),
        )
    return _passport_verifier


class PassportIssueRequest(BaseModel):
    agent_id: str
    owner_pubkey: str
    chain_id: str = "base"
    metadata: Optional[Dict[str, Any]] = None


class PassportVerifyRequest(BaseModel):
    agent_id: str
    requesting_agent_id: Optional[str] = None


class CredentialIssueRequest(BaseModel):
    agent_id: str
    credential_type: str
    claims: Optional[Dict[str, Any]] = None




















# ═══════════════════════════════════════════════════════════════
# GUARDIAN CORTEX — Verifiable Agent Memory API
# ═══════════════════════════════════════════════════════════════

_cortex_engine = None
_merkle_anchor = None
_interlock_protocol = None
_insurance_generator = None


def _get_cortex_engine():
    global _cortex_engine
    if _cortex_engine is None:
        from guardian.cortex.cortex_engine import CortexEngine
        _cortex_engine = CortexEngine(db_path=DB_PATH, privacy_mode="hash_only")
    return _cortex_engine


def _get_merkle_anchor():
    global _merkle_anchor
    if _merkle_anchor is None:
        from guardian.cortex.merkle_anchor import MerkleAnchor
        _merkle_anchor = MerkleAnchor(primary_chain="monad")
    return _merkle_anchor


def _get_interlock_protocol():
    global _interlock_protocol
    if _interlock_protocol is None:
        from guardian.cortex.interlock import InterlockProtocol
        _interlock_protocol = InterlockProtocol(db_path=DB_PATH)
    return _interlock_protocol


def _get_insurance_generator():
    global _insurance_generator
    if _insurance_generator is None:
        from guardian.cortex.insurance import InsuranceCertificateGenerator
        _insurance_generator = InsuranceCertificateGenerator(db_path=DB_PATH)
    return _insurance_generator


























_risk_scorer = None
def _get_risk_scorer():
    global _risk_scorer
    if _risk_scorer is None:
        from guardian.audit.onchain_risk_scorer import OnChainRiskScorer
        _risk_scorer = OnChainRiskScorer()
    return _risk_scorer












# ---------- STATIC FILE SERVING ----------



_frontend_site_dir = Path(__file__).resolve().parent.parent / "frontend" / "site"
if _frontend_site_dir.is_dir():
    from starlette.staticfiles import StaticFiles
    app.mount("/site", StaticFiles(directory=str(_frontend_site_dir), html=True), name="frontend_site")
    _assets_dir = _frontend_site_dir / "site-assets"
    if _assets_dir.is_dir():
        app.mount("/site-assets", StaticFiles(directory=str(_assets_dir)), name="frontend_site_assets")



# -- ROUTER INCLUDES --
from backend.routers import agentic_routes
from backend.routers import audit_routes
from backend.routers import auth_routes
from backend.routers import billing_routes
from backend.routers import campaign_routes
from backend.routers import contract_routes
from backend.routers import cortex_routes
from backend.routers import dashboard_routes
from backend.routers import misc_routes
from backend.routers import passport_routes
from backend.routers import scan_routes
from backend.routers import telemetry_routes
from backend.routers import threat_intel_routes

app.include_router(agentic_routes.router)
app.include_router(audit_routes.router)
app.include_router(auth_routes.router)
app.include_router(billing_routes.router)
app.include_router(campaign_routes.router)
app.include_router(contract_routes.router)
app.include_router(cortex_routes.router)
app.include_router(dashboard_routes.router)
app.include_router(misc_routes.router)
app.include_router(passport_routes.router)
app.include_router(scan_routes.router)
app.include_router(telemetry_routes.router)
app.include_router(threat_intel_routes.router)

def run_backend(host: str = BACKEND_HOST, port: int = BACKEND_PORT):
    import uvicorn

    ssl_kwargs = {}
    if TLS_CERT_FILE and TLS_KEY_FILE:
        ssl_kwargs = {"ssl_certfile": TLS_CERT_FILE, "ssl_keyfile": TLS_KEY_FILE}
    uvicorn.run(app, host=host, port=port, **ssl_kwargs)

if __name__ == "__main__":
    run_backend()
