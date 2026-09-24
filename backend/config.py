import json
import logging
import os
from pathlib import Path
import secrets
import sys
import time
from typing import Dict, List, Set

from backend.auth import hash_password

logger = logging.getLogger("guardian_backend.config")

# Credentials & Admin Config
ADMIN_USER = os.getenv("GUARDIAN_ADMIN_USER", "admin")
_raw_admin_pass = os.getenv("GUARDIAN_ADMIN_PASS", "")
if _raw_admin_pass:
    ADMIN_PASS = _raw_admin_pass
else:
    ADMIN_PASS = secrets.token_urlsafe(32)
    logger.warning("GUARDIAN_ADMIN_PASS environment variable was not configured. Ephemeral in-memory admin credentials generated.")

AUDITOR_USER = os.getenv("GUARDIAN_AUDITOR_USER", "").strip()
AUDITOR_PASS = os.getenv("GUARDIAN_AUDITOR_PASS", "").strip()
USER_USER = os.getenv("GUARDIAN_USER_USER", "").strip()
USER_PASS = os.getenv("GUARDIAN_USER_PASS", "").strip()

# JWT Config
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

# Rate Limiting & Lockout
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

# Multi-worker detection
_workers = 1
for _env_var in ["WEB_CONCURRENCY", "UVICORN_WORKERS", "WORKERS"]:
    _val = os.getenv(_env_var)
    if _val:
        try:
            _workers = max(_workers, int(_val))
        except ValueError:
            pass
for _i, _arg in enumerate(sys.argv):
    if _arg in {"--workers", "-w"}:
        if _i + 1 < len(sys.argv):
            try:
                _workers = max(_workers, int(sys.argv[_i + 1]))
            except ValueError:
                pass

# Audit & SIEM Config
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

# Security & Network
ENFORCE_HTTPS = os.getenv("GUARDIAN_ENFORCE_HTTPS", "false").strip().lower() in {"1", "true", "yes", "on"}
secure = ENFORCE_HTTPS or os.getenv("GUARDIAN_ENV") == "production"
TLS_CERT_FILE = os.getenv("GUARDIAN_TLS_CERT_FILE", "").strip()
TLS_KEY_FILE = os.getenv("GUARDIAN_TLS_KEY_FILE", "").strip()
METRICS_ENABLED = os.getenv("GUARDIAN_METRICS_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
BACKEND_HOST = os.getenv("GUARDIAN_BACKEND_HOST", "0.0.0.0").strip() or "0.0.0.0"
BACKEND_PORT = int(os.getenv("GUARDIAN_BACKEND_PORT", "8001"))

# Billing Config
BILLING_MODE = os.getenv("GUARDIAN_BILLING_MODE", "mock").strip().lower() or "mock"
PUBLIC_BASE_URL = os.getenv("GUARDIAN_PUBLIC_URL", "http://localhost:8001")
CHECKOUT_SUCCESS_URL = os.getenv("GUARDIAN_CHECKOUT_SUCCESS_URL", f"{PUBLIC_BASE_URL}/site/success").strip() or f"{PUBLIC_BASE_URL}/site/success"
CHECKOUT_CANCEL_URL = os.getenv("GUARDIAN_CHECKOUT_CANCEL_URL", f"{PUBLIC_BASE_URL}/site/cancel").strip() or f"{PUBLIC_BASE_URL}/site/cancel"
STRIPE_SECRET_KEY = os.getenv("GUARDIAN_STRIPE_SECRET_KEY", "").strip()
STRIPE_PRICE_STARTER = os.getenv("GUARDIAN_STRIPE_PRICE_STARTER", "").strip()
STRIPE_PRICE_PRO = os.getenv("GUARDIAN_STRIPE_PRICE_PRO", "").strip()
STRIPE_PRICE_ENTERPRISE = os.getenv("GUARDIAN_STRIPE_PRICE_ENTERPRISE", "").strip()

# Integrations & Secrets
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

# Database & Artifact Paths
DB_PATH = os.getenv("GUARDIAN_DB_PATH", os.getenv("DB_PATH", "guardian.db"))
CUSTOM_PACKS_DIR = Path("artifacts/vector_packs")
AUDIT_ARTIFACTS_DIR = Path("artifacts/audit")

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

_valid_roles: Set[str] = {"admin", "auditor", "user"}

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
