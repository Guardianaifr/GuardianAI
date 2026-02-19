from fastapi import FastAPI, HTTPException, Request, WebSocket, WebSocketDisconnect, Depends, status
from fastapi.responses import HTMLResponse, JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBasic, HTTPBasicCredentials, HTTPBearer, HTTPAuthorizationCredentials
from pydantic import BaseModel
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

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guardian_backend")

# Configuration (Env Vars -> Defaults)
ADMIN_USER = os.getenv("GUARDIAN_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("GUARDIAN_ADMIN_PASS", "guardian_default") # Simple default for local demo
AUDITOR_USER = os.getenv("GUARDIAN_AUDITOR_USER", "").strip()
AUDITOR_PASS = os.getenv("GUARDIAN_AUDITOR_PASS", "").strip()
USER_USER = os.getenv("GUARDIAN_USER_USER", "").strip()
USER_PASS = os.getenv("GUARDIAN_USER_PASS", "").strip()
JWT_SECRET = os.getenv("GUARDIAN_JWT_SECRET", "guardian_jwt_dev_secret_change_me")
JWT_ISSUER = os.getenv("GUARDIAN_JWT_ISSUER", "guardian-backend")
JWT_EXPIRES_MIN = int(os.getenv("GUARDIAN_JWT_EXPIRES_MIN", "60"))
API_RATE_LIMIT_PER_MIN = int(os.getenv("GUARDIAN_RATE_LIMIT_PER_MIN", "240"))
TELEMETRY_RATE_LIMIT_PER_MIN = int(os.getenv("GUARDIAN_TELEMETRY_RATE_LIMIT_PER_MIN", "600"))
AUTH_RATE_LIMIT_PER_MIN = int(os.getenv("GUARDIAN_AUTH_RATE_LIMIT_PER_MIN", "60"))
AUTH_LOCKOUT_ENABLED = os.getenv("GUARDIAN_AUTH_LOCKOUT_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
AUTH_LOCKOUT_MAX_ATTEMPTS = max(1, int(os.getenv("GUARDIAN_AUTH_LOCKOUT_MAX_ATTEMPTS", "5")))
AUTH_LOCKOUT_DURATION_SEC = max(1.0, float(os.getenv("GUARDIAN_AUTH_LOCKOUT_DURATION_SEC", "300")))
USER_RATE_LIMITS_JSON = os.getenv("GUARDIAN_USER_RATE_LIMITS_JSON", "").strip()
TELEMETRY_KEY_RATE_LIMITS_JSON = os.getenv("GUARDIAN_TELEMETRY_KEY_RATE_LIMITS_JSON", "").strip()
TELEMETRY_REQUIRE_API_KEY = os.getenv("GUARDIAN_TELEMETRY_REQUIRE_API_KEY", "false").strip().lower() in {"1", "true", "yes", "on"}
RATE_LIMIT_BACKEND = os.getenv("GUARDIAN_RATE_LIMIT_BACKEND", "memory").strip().lower()
RATE_LIMIT_REDIS_URL = os.getenv("GUARDIAN_RATE_LIMIT_REDIS_URL", "").strip()
RATE_LIMIT_REDIS_KEY_PREFIX = os.getenv("GUARDIAN_RATE_LIMIT_REDIS_KEY_PREFIX", "guardian:ratelimit").strip() or "guardian:ratelimit"
RATE_LIMIT_REDIS_TIMEOUT_SEC = float(os.getenv("GUARDIAN_RATE_LIMIT_REDIS_TIMEOUT_SEC", "0.2"))
RATE_LIMIT_REDIS_FAIL_OPEN = os.getenv("GUARDIAN_RATE_LIMIT_REDIS_FAIL_OPEN", "true").strip().lower() in {"1", "true", "yes", "on"}
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
TLS_CERT_FILE = os.getenv("GUARDIAN_TLS_CERT_FILE", "").strip()
TLS_KEY_FILE = os.getenv("GUARDIAN_TLS_KEY_FILE", "").strip()
METRICS_ENABLED = os.getenv("GUARDIAN_METRICS_ENABLED", "true").strip().lower() in {"1", "true", "yes", "on"}
APP_START_TIME = time.time()

if ADMIN_PASS == "guardian_default":
    logger.warning("USING DEFAULT PASSWORD! Set GUARDIAN_ADMIN_PASS environment variable for production.")
if JWT_SECRET == "guardian_jwt_dev_secret_change_me":
    logger.warning("USING DEFAULT JWT SECRET! Set GUARDIAN_JWT_SECRET environment variable for production.")

app = FastAPI(title="GuardianAI Backend v1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB_PATH = "guardian.db"
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
_valid_roles: Set[str] = {"admin", "auditor", "user"}
_redis_client: Any | None = None
_redis_script_sha: str | None = None
_redis_init_attempted = False
_redis_fallback_logged_at = 0.0

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
    users[ADMIN_USER] = {"password": ADMIN_PASS, "role": "admin"}
    if AUDITOR_USER and AUDITOR_PASS:
        users[AUDITOR_USER] = {"password": AUDITOR_PASS, "role": "auditor"}
    if USER_USER and USER_PASS:
        users[USER_USER] = {"password": USER_PASS, "role": "user"}
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


def _b64url_encode(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")


def _b64url_decode(raw: str) -> bytes:
    padding = "=" * (-len(raw) % 4)
    return base64.urlsafe_b64decode((raw + padding).encode("ascii"))


def _issue_jwt(subject: str, role: str, ttl_minutes: int = JWT_EXPIRES_MIN) -> tuple[str, Dict[str, Any]]:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "role": role,
        "iat": now,
        "exp": now + (ttl_minutes * 60),
        "iss": JWT_ISSUER,
        "jti": secrets.token_hex(12),
    }
    header_seg = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    token = f"{header_seg}.{payload_seg}.{_b64url_encode(signature)}"
    return token, payload


def _decode_jwt(token: str) -> Dict[str, Any]:
    try:
        header_seg, payload_seg, sig_seg = token.split(".")
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token format") from exc

    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    try:
        provided_sig = _b64url_decode(sig_seg)
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature") from exc

    if not hmac.compare_digest(expected_sig, provided_sig):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token signature")

    try:
        header = json.loads(_b64url_decode(header_seg).decode("utf-8"))
        payload = json.loads(_b64url_decode(payload_seg).decode("utf-8"))
    except Exception as exc:  # noqa: BLE001
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Malformed token payload") from exc

    if header.get("alg") != "HS256":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Unsupported token algorithm")
    if payload.get("iss") != JWT_ISSUER:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token issuer")

    now = int(time.time())
    exp = payload.get("exp")
    if not isinstance(exp, int) or exp < now:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Token expired")

    sub = payload.get("sub")
    if not isinstance(sub, str) or not sub:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token subject")
    role = payload.get("role")
    if not isinstance(role, str) or role not in _valid_roles:
        role = "admin" if sub == ADMIN_USER else "user"
        payload["role"] = role

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
    except Exception as exc:  # noqa: BLE001
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
    except Exception as exc:  # noqa: BLE001
        _log_redis_fallback(f"unable to load redis script: {exc}")
        return None


def _enforce_rate_limit_distributed(identity: str, limit_per_minute: int) -> bool:
    if not _use_distributed_rate_limit():
        return False

    client = _get_redis_client()
    if client is None:
        if RATE_LIMIT_REDIS_FAIL_OPEN:
            return False
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Rate limiter backend unavailable")

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
    except Exception as exc:  # noqa: BLE001
        _log_redis_fallback(f"redis eval failed: {exc}")
        if RATE_LIMIT_REDIS_FAIL_OPEN:
            return False
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Rate limiter backend unavailable")

    if allowed != 1:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=f"Rate limit exceeded for {identity}",
        )
    return True


def _forward_external_audit_log(payload: Dict[str, Any], strict: bool = AUDIT_SINK_STRICT) -> bool:
    if not AUDIT_SINK_URL:
        return True

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

def init_db():
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guardian_id TEXT,
        event_type TEXT,
        severity TEXT,
        details TEXT,
        timestamp REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
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
    # Backward-compatible schema upgrades for existing installations.
    cur.execute("PRAGMA table_info(audit_logs)")
    audit_cols = {row[1] for row in cur.fetchall()}
    if "prev_hash" not in audit_cols:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT")
    if "entry_hash" not in audit_cols:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN entry_hash TEXT")
    conn.commit()
    conn.close()
    logger.info(f"SQLite DB initialized at {DB_PATH}")

init_db()

class SecurityEvent(BaseModel):
    guardian_id: str
    event_type: str
    severity: str
    details: dict
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
    if not user_config:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    if not secrets.compare_digest(credentials.password, user_config["password"]):
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
        return {"username": payload["sub"], "role": payload.get("role", "user"), "auth_type": "bearer"}

    if credentials:
        username = _validate_basic(credentials)
        return {"username": username, "role": _get_user_role(username), "auth_type": "basic"}

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Basic realm=\"GuardianAI\", Bearer"},
    )


def get_current_user(principal: Dict[str, str] = Depends(get_current_principal)):
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
    elif TELEMETRY_REQUIRE_API_KEY:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Missing API key")

    if not identity:
        identity = request.headers.get("x-forwarded-for", "").strip() or request.client.host
    _enforce_rate_limit(f"telemetry:{identity}", _get_telemetry_rate_limit(identity))
    return True


def _request_source_identity(request: Request) -> str:
    forwarded = request.headers.get("x-forwarded-for", "").strip()
    if forwarded:
        first_hop = forwarded.split(",", 1)[0].strip()
        if first_hop:
            return first_hop
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


def _auth_lockout_retry_after_seconds(identity: str) -> int:
    if not _is_auth_lockout_enabled():
        return 0
    now = time.time()
    with _auth_lockout_lock:
        entry = _auth_lockout_state.get(identity)
        if not entry:
            return 0
        locked_until = float(entry.get("locked_until", 0.0) or 0.0)
        if locked_until <= now:
            failed = int(entry.get("failed", 0) or 0)
            if failed <= 0:
                _auth_lockout_state.pop(identity, None)
            else:
                entry["locked_until"] = 0.0
            return 0
        return max(1, int((locked_until - now) + 0.999))


def _record_auth_lockout_failure(identity: str):
    if not _is_auth_lockout_enabled():
        return
    now = time.time()
    with _auth_lockout_lock:
        entry = _auth_lockout_state.setdefault(identity, {"failed": 0.0, "locked_until": 0.0})
        locked_until = float(entry.get("locked_until", 0.0) or 0.0)
        if locked_until > now:
            return
        failures = int(entry.get("failed", 0) or 0) + 1
        if failures >= AUTH_LOCKOUT_MAX_ATTEMPTS:
            entry["failed"] = 0.0
            entry["locked_until"] = now + AUTH_LOCKOUT_DURATION_SEC
        else:
            entry["failed"] = float(failures)
            entry["locked_until"] = 0.0


def _clear_auth_lockout_failures(identity: str):
    with _auth_lockout_lock:
        _auth_lockout_state.pop(identity, None)
        # Backward compatibility for keys created before delimiter change.
        if "|" in identity:
            legacy = identity.replace("|", "@", 1)
            _auth_lockout_state.pop(legacy, None)


def _list_auth_lockouts(limit: int = 100, active_only: bool = True) -> List[Dict[str, Any]]:
    now = time.time()
    records: List[Dict[str, Any]] = []
    with _auth_lockout_lock:
        stale: List[str] = []
        for identity, entry in _auth_lockout_state.items():
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
            _auth_lockout_state.pop(identity, None)

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

    with _auth_lockout_lock:
        cleared = 0
        scope = ""

        if clear_all:
            cleared = len(_auth_lockout_state)
            _auth_lockout_state.clear()
            scope = "all"
        elif normalized_identity:
            aliases = [normalized_identity]
            if "|" in normalized_identity:
                aliases.append(normalized_identity.replace("|", "@", 1))
            elif "@" in normalized_identity:
                aliases.append(normalized_identity.replace("@", "|", 1))
            for key in aliases:
                if key in _auth_lockout_state:
                    _auth_lockout_state.pop(key, None)
                    cleared += 1
            scope = f"identity:{normalized_identity}"
        elif normalized_user and normalized_source:
            aliases = [
                _format_auth_lockout_identity(normalized_user, normalized_source),
                f"{normalized_user}@{normalized_source}",
            ]
            for key in aliases:
                if key in _auth_lockout_state:
                    _auth_lockout_state.pop(key, None)
                    cleared += 1
            scope = f"user+source:{normalized_user}@{normalized_source}"
        elif normalized_user:
            for key in list(_auth_lockout_state.keys()):
                key_user, _ = _parse_auth_lockout_identity(key)
                if key_user == normalized_user:
                    _auth_lockout_state.pop(key, None)
                    cleared += 1
            scope = f"user:{normalized_user}"
        else:
            raise ValueError("clear target is required")

        return {
            "cleared": cleared,
            "remaining": len(_auth_lockout_state),
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
    signature = hashlib.sha256(f"{guardian_id}:{timestamp}:{details_json}".encode()).hexdigest()

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
        "pass" if ADMIN_PASS != "guardian_default" else "fail",
        "Admin password is set to a non-default value."
        if ADMIN_PASS != "guardian_default"
        else "Default admin password is still configured.",
    )
    add_control(
        "jwt_secret_configured",
        "pass" if JWT_SECRET != "guardian_jwt_dev_secret_change_me" else "fail",
        "JWT signing secret is non-default."
        if JWT_SECRET != "guardian_jwt_dev_secret_change_me"
        else "Default JWT secret is configured.",
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


@app.post(
    "/api/v1/auth/token",
    response_model=TokenResponse,
    responses={
        200: {
            "description": "JWT issued successfully.",
            "content": {
                "application/json": {
                    "example": {
                        "access_token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...",
                        "token_type": "bearer",
                        "expires_in": 3600,
                        "user": "admin",
                        "role": "admin",
                    }
                }
            },
        },
        429: {
            "description": "Temporarily locked due to repeated failed credentials from the same source.",
            "content": {
                "application/json": {
                    "example": {
                        "detail": "Account temporarily locked due to repeated failed authentication attempts."
                    }
                }
            },
        },
    },
)
async def create_access_token(
    request: Request,
    credentials: HTTPBasicCredentials = Depends(HTTPBasic()),
    _: bool = Depends(enforce_auth_rate_limit),
):
    lockout_identity = _auth_lockout_identity(request, credentials.username)
    retry_after = _auth_lockout_retry_after_seconds(lockout_identity)
    if retry_after > 0:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Account temporarily locked due to repeated failed authentication attempts.",
            headers={"Retry-After": str(retry_after)},
        )

    try:
        username = _validate_basic(credentials)
    except HTTPException:
        _record_auth_lockout_failure(lockout_identity)
        raise

    _clear_auth_lockout_failures(lockout_identity)
    role = _get_user_role(username)
    token, claims = _issue_jwt(username, role=role)
    _record_issued_token(claims)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=JWT_EXPIRES_MIN * 60,
        user=username,
        role=role,
    )


@app.post(
    "/api/v1/auth/revoke",
    response_model=RevokeTokenResponse,
    responses={
        200: {
            "description": "Current bearer token revoked.",
            "content": {
                "application/json": {
                    "example": {
                        "status": "revoked",
                        "revoked_jti": "a1b2c3d4e5f6",
                        "revoked_by": "admin",
                    }
                }
            },
        }
    },
)
async def revoke_access_token(
    payload: Dict[str, Any] = Depends(get_current_token_payload),
    _: bool = Depends(enforce_auth_rate_limit),
):
    jti = payload.get("jti")
    exp = payload.get("exp")
    sub = payload.get("sub", "unknown")
    if not isinstance(jti, str) or not isinstance(exp, int):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token missing required claims")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        INSERT OR IGNORE INTO revoked_tokens (jti, revoked_by, revoked_at, expires_at)
        VALUES (?, ?, ?, ?)
        """,
        (jti, sub, time.time(), float(exp)),
    )
    conn.commit()
    conn.close()
    _mark_issued_token_revoked(jti, revoked_by=sub, reason="self_revoke")

    _write_control_plane_audit_entry(
        action="auth_revoke_token",
        user=sub,
        details={"revoked_jti": jti, "expires_at": exp},
    )

    return RevokeTokenResponse(status="revoked", revoked_jti=jti, revoked_by=sub)


@app.get(
    "/api/v1/auth/revocations",
    response_model=List[RevokedTokenEntryResponse],
    responses={
        200: {
            "description": "Lists revoked JWT entries for incident response.",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "jti": "a1b2c3d4e5f6",
                            "revoked_by": "admin",
                            "revoked_at": 1739835000.0,
                            "expires_at": 1739838600.0,
                            "expired": False,
                        }
                    ]
                }
            },
        }
    },
)
async def list_revoked_tokens(
    limit: int = 100,
    include_expired: bool = False,
    username: str = Depends(enforce_auditor_rate_limit),
):
    bounded_limit = max(1, min(limit, 1000))
    return _list_revoked_tokens(limit=bounded_limit, include_expired=include_expired)


@app.post(
    "/api/v1/auth/revocations/prune",
    response_model=PruneRevokedTokensResponse,
    responses={
        200: {
            "description": "Prunes revoked token entries.",
            "content": {
                "application/json": {
                    "example": {"deleted": 5, "remaining": 12, "expired_only": True}
                }
            },
        }
    },
)
async def prune_revoked_tokens(
    expired_only: bool = True,
    username: str = Depends(enforce_admin_rate_limit),
):
    result = _prune_revoked_tokens(expired_only=expired_only)
    _write_control_plane_audit_entry(
        action="auth_prune_revocations",
        user=username,
        details={
            "expired_only": expired_only,
            "deleted": result["deleted"],
            "remaining": result["remaining"],
        },
    )
    return PruneRevokedTokensResponse(
        deleted=result["deleted"],
        remaining=result["remaining"],
        expired_only=expired_only,
    )


@app.get(
    "/api/v1/auth/lockouts",
    response_model=List[AuthLockoutEntryResponse],
    responses={
        200: {
            "description": "Lists current failed-login lockout state.",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "identity": "user1|10.0.0.1",
                            "username": "user1",
                            "source": "10.0.0.1",
                            "failed_attempts": 0,
                            "locked_until": 1739835300.0,
                            "retry_after_sec": 240,
                            "active": True,
                        }
                    ]
                }
            },
        }
    },
)
async def list_auth_lockouts(
    limit: int = 100,
    active_only: bool = True,
    username: str = Depends(enforce_auditor_rate_limit),
):
    bounded_limit = max(1, min(limit, 1000))
    return _list_auth_lockouts(limit=bounded_limit, active_only=active_only)


@app.post(
    "/api/v1/auth/lockouts/clear",
    response_model=ClearAuthLockoutsResponse,
    responses={
        200: {
            "description": "Clears failed-login lockout entries by identity, user, or globally.",
            "content": {
                "application/json": {
                    "example": {"cleared": 1, "remaining": 0, "scope": "user+source:user1@10.0.0.1"}
                }
            },
        }
    },
)
async def clear_auth_lockouts(
    payload: ClearAuthLockoutsRequest,
    username: str = Depends(enforce_admin_rate_limit),
):
    has_identity = bool((payload.identity or "").strip())
    has_username = bool((payload.username or "").strip())
    has_source = bool((payload.source or "").strip())
    clear_all = bool(payload.clear_all)

    if not clear_all and not has_identity and not has_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Provide clear_all=true, identity, or username as clear target",
        )
    if has_source and not has_username:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="source requires username",
        )
    if has_identity and (has_username or has_source):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="identity cannot be combined with username/source",
        )

    try:
        result = _clear_auth_lockouts(
            clear_all=clear_all,
            identity=payload.identity,
            username=payload.username,
            source=payload.source,
        )
    except ValueError as exc:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)) from exc

    _write_control_plane_audit_entry(
        action="auth_clear_lockouts",
        user=username,
        details={
            "clear_all": clear_all,
            "identity": (payload.identity or "").strip(),
            "username": (payload.username or "").strip(),
            "source": (payload.source or "").strip(),
            "cleared": result["cleared"],
            "remaining": result["remaining"],
            "scope": result["scope"],
        },
    )
    return ClearAuthLockoutsResponse(
        cleared=result["cleared"],
        remaining=result["remaining"],
        scope=result["scope"],
    )


@app.get(
    "/api/v1/auth/sessions",
    response_model=List[AuthSessionResponse],
    responses={
        200: {
            "description": "Lists tracked JWT sessions.",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "jti": "a1b2c3d4e5f6",
                            "subject": "admin",
                            "role": "admin",
                            "issued_at": 1739835000.0,
                            "expires_at": 1739838600.0,
                            "revoked_at": None,
                            "revoked_by": None,
                            "revoke_reason": None,
                            "active": True,
                        }
                    ]
                }
            },
        }
    },
)
async def list_auth_sessions(
    limit: int = 100,
    include_expired: bool = False,
    include_revoked: bool = True,
    username: str = Depends(enforce_auditor_rate_limit),
):
    bounded_limit = max(1, min(limit, 1000))
    return _list_auth_sessions(limit=bounded_limit, include_expired=include_expired, include_revoked=include_revoked)


@app.post(
    "/api/v1/auth/sessions/revoke-self",
    response_model=RevokeSelfSessionsResponse,
    responses={
        200: {
            "description": "Revokes sessions for the current authenticated user, with optional current-session exclusion.",
            "content": {
                "application/json": {
                    "example": {
                        "target_user": "user1",
                        "matched": 3,
                        "revoked": 2,
                        "already_revoked": 0,
                        "excluded_current": 1,
                        "active_only": True,
                        "exclude_current": True,
                        "reason": "user_compromise_containment",
                    }
                }
            },
        }
    },
)
async def revoke_self_sessions(
    payload: RevokeSelfSessionsRequest,
    token_payload: Dict[str, Any] = Depends(get_current_token_payload),
    username: str = Depends(enforce_user_rate_limit),
):
    target_user = token_payload.get("sub")
    current_jti = token_payload.get("jti")
    if not isinstance(target_user, str) or not target_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token missing required subject claim")
    if payload.exclude_current and (not isinstance(current_jti, str) or not current_jti):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token missing required jti claim")

    result = _revoke_user_sessions(
        target_user=target_user,
        revoked_by=username,
        active_only=payload.active_only,
        reason=payload.reason or "",
        exclude_jti=current_jti if payload.exclude_current else None,
    )
    _write_control_plane_audit_entry(
        action="auth_revoke_self_sessions",
        user=username,
        details={
            "target_user": target_user,
            "matched": result["matched"],
            "revoked": result["revoked"],
            "already_revoked": result["already_revoked"],
            "excluded_current": result["excluded"],
            "active_only": payload.active_only,
            "exclude_current": payload.exclude_current,
            "reason": payload.reason or "",
        },
    )
    return RevokeSelfSessionsResponse(
        target_user=target_user,
        matched=result["matched"],
        revoked=result["revoked"],
        already_revoked=result["already_revoked"],
        excluded_current=result["excluded"],
        active_only=payload.active_only,
        exclude_current=payload.exclude_current,
        reason=payload.reason,
    )


@app.post(
    "/api/v1/auth/sessions/revoke-self-jti",
    response_model=RevokeSelfSessionByJtiResponse,
    responses={
        200: {
            "description": "Revokes one specific session JTI owned by current authenticated user.",
            "content": {
                "application/json": {
                    "example": {
                        "jti": "a1b2c3d4e5f6",
                        "target_user": "user1",
                        "revoked": True,
                        "already_revoked": False,
                        "reason": "suspicious_device_logout",
                    }
                }
            },
        }
    },
)
async def revoke_self_session_by_jti(
    payload: RevokeSelfSessionByJtiRequest,
    token_payload: Dict[str, Any] = Depends(get_current_token_payload),
    username: str = Depends(enforce_user_rate_limit),
):
    target_jti = payload.jti.strip()
    if not target_jti:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="jti is required")

    target_user = token_payload.get("sub")
    current_jti = token_payload.get("jti")
    if not isinstance(target_user, str) or not target_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token missing required subject claim")
    if not isinstance(current_jti, str) or not current_jti:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Token missing required jti claim")

    result = _revoke_self_session_by_jti(
        jti=target_jti,
        subject=target_user,
        revoked_by=username,
        reason=payload.reason or "",
        current_jti=current_jti,
    )
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session not found")
    if result.get("not_owned"):
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="session does not belong to current user")
    if result.get("current_session"):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Use /api/v1/auth/revoke for current session")

    _write_control_plane_audit_entry(
        action="auth_revoke_self_session_jti",
        user=username,
        details={
            "jti": target_jti,
            "target_user": result["target_user"],
            "revoked": result["revoked"],
            "already_revoked": result["already_revoked"],
            "reason": payload.reason or "",
        },
    )
    return RevokeSelfSessionByJtiResponse(
        jti=target_jti,
        target_user=result["target_user"],
        revoked=result["revoked"],
        already_revoked=result["already_revoked"],
        reason=payload.reason,
    )


@app.post(
    "/api/v1/auth/sessions/revoke-user",
    response_model=RevokeUserSessionsResponse,
    responses={
        200: {
            "description": "Revokes tracked sessions for a target user.",
            "content": {
                "application/json": {
                    "example": {
                        "target_user": "user1",
                        "matched": 3,
                        "revoked": 2,
                        "already_revoked": 1,
                        "active_only": True,
                        "reason": "incident_containment",
                    }
                }
            },
        }
    },
)
async def revoke_user_sessions(
    payload: RevokeUserSessionsRequest,
    username: str = Depends(enforce_admin_rate_limit),
):
    target_user = payload.username.strip()
    if not target_user:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="username is required")

    result = _revoke_user_sessions(
        target_user=target_user,
        revoked_by=username,
        active_only=payload.active_only,
        reason=payload.reason or "",
    )
    _write_control_plane_audit_entry(
        action="auth_revoke_user_sessions",
        user=username,
        details={
            "target_user": target_user,
            "matched": result["matched"],
            "revoked": result["revoked"],
            "already_revoked": result["already_revoked"],
            "active_only": payload.active_only,
            "reason": payload.reason or "",
        },
    )
    return RevokeUserSessionsResponse(
        target_user=target_user,
        matched=result["matched"],
        revoked=result["revoked"],
        already_revoked=result["already_revoked"],
        active_only=payload.active_only,
        reason=payload.reason,
    )


@app.post(
    "/api/v1/auth/sessions/revoke-all",
    response_model=RevokeAllSessionsResponse,
    responses={
        200: {
            "description": "Revokes tracked sessions globally with optional exclusions.",
            "content": {
                "application/json": {
                    "example": {
                        "matched": 12,
                        "revoked": 10,
                        "already_revoked": 1,
                        "excluded": 1,
                        "active_only": True,
                        "exclude_self": True,
                        "excluded_users": ["admin"],
                        "reason": "global_incident_containment",
                    }
                }
            },
        }
    },
)
async def revoke_all_sessions(
    payload: RevokeAllSessionsRequest,
    username: str = Depends(enforce_admin_rate_limit),
):
    excluded_users: Set[str] = set()
    if payload.exclude_usernames:
        excluded_users = {item.strip() for item in payload.exclude_usernames if item and item.strip()}
    if payload.exclude_self:
        excluded_users.add(username)

    result = _revoke_all_sessions(
        revoked_by=username,
        active_only=payload.active_only,
        reason=payload.reason or "",
        excluded_subjects=excluded_users,
    )
    sorted_excluded = sorted(excluded_users)
    _write_control_plane_audit_entry(
        action="auth_revoke_all_sessions",
        user=username,
        details={
            "matched": result["matched"],
            "revoked": result["revoked"],
            "already_revoked": result["already_revoked"],
            "excluded": result["excluded"],
            "active_only": payload.active_only,
            "exclude_self": payload.exclude_self,
            "excluded_users": sorted_excluded,
            "reason": payload.reason or "",
        },
    )
    return RevokeAllSessionsResponse(
        matched=result["matched"],
        revoked=result["revoked"],
        already_revoked=result["already_revoked"],
        excluded=result["excluded"],
        active_only=payload.active_only,
        exclude_self=payload.exclude_self,
        excluded_users=sorted_excluded,
        reason=payload.reason,
    )


@app.post(
    "/api/v1/auth/sessions/revoke-jti",
    response_model=RevokeSessionByJtiResponse,
    responses={
        200: {
            "description": "Revokes a single tracked session by JTI.",
            "content": {
                "application/json": {
                    "example": {
                        "jti": "a1b2c3d4e5f6",
                        "target_user": "user1",
                        "revoked": True,
                        "already_revoked": False,
                        "reason": "incident_containment",
                    }
                }
            },
        }
    },
)
async def revoke_session_by_jti(
    payload: RevokeSessionByJtiRequest,
    username: str = Depends(enforce_admin_rate_limit),
):
    jti = payload.jti.strip()
    if not jti:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="jti is required")

    result = _revoke_session_by_jti(jti=jti, revoked_by=username, reason=payload.reason or "")
    if result is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="session not found")

    _write_control_plane_audit_entry(
        action="auth_revoke_session_jti",
        user=username,
        details={
            "jti": jti,
            "target_user": result["target_user"],
            "revoked": result["revoked"],
            "already_revoked": result["already_revoked"],
            "reason": payload.reason or "",
        },
    )
    return RevokeSessionByJtiResponse(
        jti=jti,
        target_user=result["target_user"],
        revoked=result["revoked"],
        already_revoked=result["already_revoked"],
        reason=payload.reason,
    )


@app.get(
    "/api/v1/auth/whoami",
    response_model=WhoAmIResponse,
    responses={
        200: {
            "description": "Returns current authenticated principal and effective permissions.",
            "content": {
                "application/json": {
                    "example": {
                        "user": "admin",
                        "role": "admin",
                        "auth_type": "bearer",
                        "permissions": [
                            "auth:issue",
                            "auth:revoke:self",
                            "api_keys:manage",
                            "audit:read",
                            "audit:verify",
                            "audit:retry",
                            "compliance:read",
                            "events:read",
                            "analytics:read",
                            "export:read",
                            "telemetry:ingest",
                        ],
                    }
                }
            },
        }
    },
)
async def auth_whoami(
    request: Request,
    principal: Dict[str, str] = Depends(get_current_principal),
):
    _enforce_rbac_and_user_rate_limit(request, principal)
    role = principal.get("role", "user")
    return WhoAmIResponse(
        user=principal["username"],
        role=role,
        auth_type=principal.get("auth_type", "unknown"),
        permissions=_permissions_for_role(role),
    )


@app.post(
    "/api/v1/api-keys",
    response_model=CreatedApiKeyResponse,
    responses={
        200: {
            "description": "Managed API key created.",
            "content": {
                "application/json": {
                    "example": {
                        "id": 1,
                        "key_name": "telemetry_ingest",
                        "key_prefix": "gk_abc123",
                        "is_active": True,
                        "created_by": "admin",
                        "created_at": 1739835000.0,
                        "last_used_at": None,
                        "api_key": "gk_abc123_plaintext",
                    }
                }
            },
        }
    },
    openapi_extra={
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "default": {"summary": "Create key", "value": {"key_name": "telemetry_ingest"}}
                    }
                }
            }
        }
    },
)
async def create_api_key(payload: CreateApiKeyRequest, username: str = Depends(enforce_admin_rate_limit)):
    key_name = payload.key_name.strip()
    if not key_name:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="key_name is required")

    raw_key, key_prefix = _generate_api_key_material()
    key_hash = _hash_api_key(raw_key)
    created_at = time.time()
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    try:
        cur.execute(
            """
            INSERT INTO api_keys (key_name, key_prefix, key_hash, is_active, created_by, created_at, last_used_at)
            VALUES (?, ?, ?, 1, ?, ?, NULL)
            """,
            (key_name, key_prefix, key_hash, username, created_at),
        )
        key_id = cur.lastrowid
        conn.commit()
    except sqlite3.IntegrityError as exc:
        conn.close()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="key_name already exists") from exc
    conn.close()

    return CreatedApiKeyResponse(
        id=key_id,
        key_name=key_name,
        key_prefix=key_prefix,
        is_active=True,
        created_by=username,
        created_at=created_at,
        last_used_at=None,
        api_key=raw_key,
    )


@app.get(
    "/api/v1/api-keys",
    response_model=List[ApiKeyResponse],
    responses={
        200: {
            "description": "List API keys.",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "id": 2,
                            "key_name": "telemetry_ingest",
                            "key_prefix": "gk_abcd1234",
                            "is_active": True,
                            "created_by": "admin",
                            "created_at": 1739835000.0,
                            "last_used_at": 1739835100.0,
                        }
                    ]
                }
            },
        }
    },
)
async def list_api_keys(username: str = Depends(enforce_auditor_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        "SELECT id, key_name, key_prefix, is_active, created_by, created_at, last_used_at FROM api_keys ORDER BY created_at DESC"
    )
    rows = cur.fetchall()
    conn.close()
    return [
        ApiKeyResponse(
            id=row[0],
            key_name=row[1],
            key_prefix=row[2],
            is_active=bool(row[3]),
            created_by=row[4],
            created_at=row[5],
            last_used_at=row[6],
        )
        for row in rows
    ]


@app.post(
    "/api/v1/api-keys/{key_id}/revoke",
    response_model=ApiKeyResponse,
    responses={
        200: {
            "description": "API key revoked.",
            "content": {
                "application/json": {
                    "example": {
                        "id": 2,
                        "key_name": "telemetry_ingest",
                        "key_prefix": "gk_abcd1234",
                        "is_active": False,
                        "created_by": "admin",
                        "created_at": 1739835000.0,
                        "last_used_at": 1739835100.0,
                    }
                }
            },
        }
    },
)
async def revoke_api_key(key_id: int, username: str = Depends(enforce_admin_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("UPDATE api_keys SET is_active = 0 WHERE id = ?", (key_id,))
    if cur.rowcount == 0:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    conn.commit()
    cur.execute(
        "SELECT id, key_name, key_prefix, is_active, created_by, created_at, last_used_at FROM api_keys WHERE id = ?",
        (key_id,),
    )
    row = cur.fetchone()
    conn.close()
    return ApiKeyResponse(
        id=row[0],
        key_name=row[1],
        key_prefix=row[2],
        is_active=bool(row[3]),
        created_by=row[4],
        created_at=row[5],
        last_used_at=row[6],
    )


@app.post(
    "/api/v1/api-keys/{key_id}/rotate",
    response_model=CreatedApiKeyResponse,
    responses={
        200: {
            "description": "API key rotated.",
            "content": {
                "application/json": {
                    "example": {
                        "id": 2,
                        "key_name": "telemetry_ingest",
                        "key_prefix": "gk_efgh5678",
                        "is_active": True,
                        "created_by": "admin",
                        "created_at": 1739835000.0,
                        "last_used_at": 1739835100.0,
                        "api_key": "gk_efgh5678_plaintext",
                    }
                }
            },
        }
    },
)
async def rotate_api_key(key_id: int, username: str = Depends(enforce_admin_rate_limit)):
    raw_key, key_prefix = _generate_api_key_material()
    key_hash = _hash_api_key(raw_key)

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT key_name, created_by, created_at, last_used_at FROM api_keys WHERE id = ?", (key_id,))
    existing = cur.fetchone()
    if not existing:
        conn.close()
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")

    cur.execute(
        """
        UPDATE api_keys
        SET key_prefix = ?, key_hash = ?, is_active = 1
        WHERE id = ?
        """,
        (key_prefix, key_hash, key_id),
    )
    conn.commit()
    conn.close()

    return CreatedApiKeyResponse(
        id=key_id,
        key_name=existing[0],
        key_prefix=key_prefix,
        is_active=True,
        created_by=existing[1],
        created_at=existing[2],
        last_used_at=existing[3],
        api_key=raw_key,
    )

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

@app.post(
    "/api/v1/telemetry",
    response_model=TelemetryIngestResponse,
    openapi_extra={
        "requestBody": {
            "content": {
                "application/json": {
                    "examples": {
                        "admin_action": {
                            "summary": "Admin action audit event",
                            "value": {
                                "guardian_id": "guardian-01",
                                "event_type": "admin_action",
                                "severity": "high",
                                "details": {"action": "update_policy", "user": "admin"},
                            },
                        }
                    }
                }
            }
        }
    },
)
async def ingest_telemetry(event: SecurityEvent, _: bool = Depends(enforce_telemetry_rate_limit)):
    if event.timestamp == 0.0:
        event.timestamp = time.time()
        
    logger.info(f"Ingesting {event.event_type} from {event.guardian_id}")
    
    # Normalize severity
    event.severity = event.severity.upper()
    
    # 1. Persist to SQLite
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Insert new event
    cur.execute(
        "INSERT INTO security_events (guardian_id, event_type, severity, details, timestamp) VALUES (?, ?, ?, ?, ?)",
        (event.guardian_id, event.event_type, event.severity, json.dumps(event.details), event.timestamp)
    )

    audit_payload = None

    # 2. Immutable Audit Log (Critical Events)
    if event.event_type == "admin_action":
        import hashlib
        # Simulate cryptographic signing of the log entry
        details_json = json.dumps(event.details)
        payload = f"{event.guardian_id}:{event.timestamp}:{details_json}"
        signature = hashlib.sha256(payload.encode()).hexdigest()
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
            guardian_id=event.guardian_id,
            action=event.details.get("action", "unknown"),
            user=event.details.get("user", "unknown"),
            details_json=details_json,
            timestamp=event.timestamp,
            signature=signature,
            prev_hash=prev_hash,
        )
        audit_payload = {
            "guardian_id": event.guardian_id,
            "action": event.details.get("action", "unknown"),
            "user": event.details.get("user", "unknown"),
            "details": event.details,
            "timestamp": event.timestamp,
            "signature": signature,
            "prev_hash": prev_hash,
            "entry_hash": entry_hash,
        }
        
        cur.execute(
            """
            INSERT INTO audit_logs (guardian_id, action, user, details, timestamp, signature, prev_hash, entry_hash)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                event.guardian_id,
                event.details.get("action", "unknown"),
                event.details.get("user", "unknown"),
                details_json,
                event.timestamp,
                signature,
                prev_hash,
                entry_hash,
            ),
        )


    # Extract Analytics if present (Add to analytics table)
    if "latency_ms" in event.details and "path" in event.details:
        try:
            latency = float(event.details["latency_ms"].replace("ms", ""))
            path = event.details["path"]
            cur.execute(
                "INSERT INTO analytics (path, latency_ms, timestamp) VALUES (?, ?, ?)",
                (path, latency, event.timestamp)
            )
        except:
            pass
    
    # 2. Retention Policy: Auto-purge events older than the configured retention window
    retention_cutoff = time.time() - (30 * 24 * 60 * 60)
    cur.execute("DELETE FROM security_events WHERE timestamp < ?", (retention_cutoff,))
    
    conn.commit()
    conn.close()

    # 3. External Audit Sinks (best effort unless strict mode enabled)
    if audit_payload is not None:
        _forward_audit_payload(audit_payload)

    # 4. Fire Webhook Alert
    await send_webhook_alert(event)
    
    return {"status": "persisted", "event_id": event.guardian_id}

from fastapi.responses import StreamingResponse
import io
import csv

@app.get("/api/v1/export/json", response_model=List[SecurityEventResponse])
async def export_json(username: str = Depends(enforce_user_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_events ORDER BY timestamp DESC")
    rows = cur.fetchall()
    conn.close()
    
    data = [
        {
            "id": r[0], "guardian_id": r[1], "event_type": r[2], 
            "severity": r[3], "details": json.loads(r[4]), "timestamp": r[5]
        } for r in rows
    ]
    return data

@app.get(
    "/api/v1/analytics",
    response_model=AnalyticsResponse,
    responses={200: {"description": "Aggregated analytics and block-rate summary."}},
)
async def get_analytics(username: str = Depends(enforce_user_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    proxy_placeholders = ",".join("?" for _ in PROXY_EVENT_TYPES)
    blocked_set = set(BLOCKED_EVENT_TYPES)

    # Consistent ingress scope: only proxy pipeline events.
    cur.execute(
        f"SELECT event_type, details FROM security_events WHERE event_type IN ({proxy_placeholders})",
        PROXY_EVENT_TYPES,
    )
    rows = cur.fetchall()

    total_count = len(rows)
    total_blocked = 0
    paths = {}
    end_to_end_samples = []
    overhead_samples = []
    upstream_samples = []

    for event_type, details_raw in rows:
        et = (event_type or "").lower()
        if et in blocked_set:
            total_blocked += 1

        details = {}
        if details_raw:
            try:
                details = json.loads(details_raw)
            except Exception:  # noqa: BLE001
                details = {}

        path = details.get("path")
        if isinstance(path, str) and path:
            paths[path] = paths.get(path, 0) + 1

        total_ms = _to_ms(details.get("latency_ms"))
        if total_ms is not None:
            end_to_end_samples.append(total_ms)

        timings = details.get("component_timings")
        if isinstance(timings, dict):
            component_values = [_to_ms(v) for v in timings.values()]
            component_values = [v for v in component_values if v is not None]
            if component_values:
                guardian_overhead = sum(component_values)
                overhead_samples.append(guardian_overhead)
                if total_ms is not None:
                    upstream_samples.append(max(0.0, total_ms - guardian_overhead))

    # Recent block rate over last 25 ingress events
    cur.execute(
        f"SELECT event_type FROM security_events WHERE event_type IN ({proxy_placeholders}) ORDER BY timestamp DESC LIMIT 25",
        PROXY_EVENT_TYPES,
    )
    recent_rows = cur.fetchall()
    recent_total = len(recent_rows)
    recent_blocked = sum(1 for (evt_type,) in recent_rows if (evt_type or "").lower() in blocked_set)

    conn.close()

    avg_latency = (sum(end_to_end_samples) / len(end_to_end_samples)) if end_to_end_samples else 0.0
    avg_overhead = (sum(overhead_samples) / len(overhead_samples)) if overhead_samples else 0.0
    avg_upstream = (sum(upstream_samples) / len(upstream_samples)) if upstream_samples else avg_latency
    global_block_rate = (total_blocked / total_count * 100) if total_count else 0.0
    recent_block_rate = (recent_blocked / recent_total * 100) if recent_total else 0.0

    return {
        "total_requests": total_count or 0,
        "total_blocked": total_blocked or 0,
        "avg_latency_ms": round(avg_latency or 0, 2),
        "avg_guardian_overhead_ms": round(avg_overhead or 0, 2),
        "avg_upstream_ms": round(avg_upstream or 0, 2),
        "global_block_rate_pct": round(global_block_rate, 1),
        "recent_block_rate_pct": round(recent_block_rate, 1),
        "path_breakdown": paths,
        "fast_path_pct": round((sum(v for k,v in paths.items() if 'fast' in k) / total_count * 100) if total_count else 0, 1)
    }

@app.get("/api/v1/export/csv")
async def export_csv(username: str = Depends(enforce_user_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_events ORDER BY timestamp DESC")
    rows = cur.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "GuardianID", "EventType", "Severity", "Details", "Timestamp"])
    for r in rows:
        writer.writerow([r[0], r[1], r[2], r[3], r[4], datetime.datetime.fromtimestamp(r[5]).isoformat()])
    
    output.seek(0)
    return StreamingResponse(
        output, 
        media_type="text/csv", 
        headers={"Content-Disposition": "attachment; filename=guardian_audit_log.csv"}
    )

@app.get(
    "/health",
    response_model=HealthResponse,
    responses={
        200: {
            "description": "Readiness healthy.",
            "content": {
                "application/json": {
                    "example": {
                        "status": "healthy",
                        "timestamp": 1739835000.0,
                        "uptime_sec": 42.5,
                        "components": {
                            "database": {"ok": True, "detail": "ok"},
                            "metrics_enabled": True,
                            "https_enforced": True,
                            "telemetry_requires_api_key": False,
                            "audit_sink_configured": True,
                            "auth_lockout_enabled": True,
                        },
                    }
                }
            },
        },
        503: {
            "description": "One or more readiness dependencies are unhealthy.",
            "content": {
                "application/json": {
                    "example": {
                        "status": "unhealthy",
                        "timestamp": 1739835000.0,
                        "uptime_sec": 42.5,
                        "components": {
                            "database": {"ok": False, "detail": "unable to open database file"},
                            "metrics_enabled": True,
                            "https_enforced": True,
                            "telemetry_requires_api_key": True,
                            "audit_sink_configured": False,
                            "auth_lockout_enabled": True,
                        },
                    }
                }
            },
        }
    },
)
async def health_check():
    db_ok, db_message = _check_db_health()
    now = time.time()
    payload = {
        "status": "healthy" if db_ok else "unhealthy",
        "timestamp": now,
        "uptime_sec": round(now - APP_START_TIME, 3),
        "components": {
            "database": {"ok": db_ok, "detail": db_message},
            "metrics_enabled": METRICS_ENABLED,
            "https_enforced": ENFORCE_HTTPS,
            "telemetry_requires_api_key": TELEMETRY_REQUIRE_API_KEY,
            "audit_sink_configured": bool(
                AUDIT_SINK_URL or AUDIT_SYSLOG_HOST or AUDIT_SPLUNK_HEC_URL or AUDIT_DATADOG_API_KEY
            ),
            "auth_lockout_enabled": _is_auth_lockout_enabled(),
        },
    }
    if db_ok:
        return payload
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload)


@app.get(
    "/metrics",
    responses={
        200: {
            "description": "Prometheus exposition format.",
            "content": {
                "text/plain": {
                    "example": "guardian_requests_total 12\nguardian_requests_last_minute 3\n"
                }
            },
        },
        404: {"description": "Metrics disabled."},
    },
)
async def metrics():
    if not METRICS_ENABLED:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Metrics disabled")
    return HTMLResponse(content=_build_metrics_payload(), media_type="text/plain")

@app.get("/", response_class=HTMLResponse)
async def dashboard(
    request: Request,
    user: str | None = None,
    password: str | None = None,
):
    username: str | None = None

    # Primary path: standard Basic/Bearer header auth.
    auth_header = request.headers.get("authorization", "")
    if auth_header.lower().startswith("bearer "):
        token = auth_header.split(" ", 1)[1].strip()
        if token:
            try:
                payload = _decode_jwt(token)
                username = str(payload.get("sub", "")).strip() or None
            except Exception:  # noqa: BLE001
                username = None
    else:
        creds = _extract_basic_credentials_from_header(request)
        if creds:
            try:
                username = _validate_basic(HTTPBasicCredentials(username=creds[0], password=creds[1]))
            except Exception:  # noqa: BLE001
                username = None

    # Fallback path for browser demo UX when auth popup does not appear.
    if not username and user and password:
        try:
            username = _validate_basic(HTTPBasicCredentials(username=user, password=password))
        except Exception:  # noqa: BLE001
            username = None

    if not username:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Basic realm=\"GuardianAI\", Bearer"},
        )

    role = _get_user_role(username)
    _enforce_rbac_and_user_rate_limit(request, {"username": username, "role": role}, {"admin", "auditor", "user"})

    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT 30")
    events = cur.fetchall()
    conn.close()
    
    # Try to read config for mode visibility
    try:
        import yaml
        with open("../guardian/config/config.yaml", 'r') as f:
            config = yaml.safe_load(f)
            sec_mode = config.get('security_policies', {}).get('security_mode', 'Balanced')
            prev_strat = config.get('security_policies', {}).get('leak_prevention_strategy', 'Redact')
    except:
        sec_mode = "Balanced"
        prev_strat = "Redact"

    return f"""
    <html>
        <head>
            <title>GuardianAI // SOC TERMINAL</title>
            <script src="https://unpkg.com/lucide@latest"></script>
            <style>
                :root {{
                    --bg-color: #050505;
                    --card-bg: #0a0a0a;
                    --text-main: #00ff41;
                    --text-dim: #008F11;
                    --accent-red: #ff003c;
                    --accent-cyan: #00e5ff;
                    --accent-yellow: #fcee0a;
                    --border-color: #1a1a1a;
                }}
                body {{ 
                    font-family: 'Courier New', Courier, monospace; 
                    background-color: var(--bg-color); 
                    color: var(--text-main); 
                    margin: 0; 
                    padding: 20px; 
                    background-image: linear-gradient(rgba(18, 16, 16, 0) 50%, rgba(0, 0, 0, 0.25) 50%), linear-gradient(90deg, rgba(255, 0, 0, 0.06), rgba(0, 255, 0, 0.02), rgba(0, 0, 255, 0.06));
                    background-size: 100% 2px, 3px 100%;
                }}
                h1 {{ 
                    color: var(--accent-cyan); 
                    margin: 0; 
                    font-size: 1.5rem; 
                    text-transform: uppercase; 
                    letter-spacing: 2px;
                    text-shadow: 0 0 5px var(--accent-cyan);
                }}
                .container {{ max-width: 1200px; margin: auto; }}
                
                /* CRT Scanline Effect */
                .scanline {{
                    width: 100%;
                    height: 100px;
                    z-index: 10;
                    background: linear-gradient(0deg, rgba(0,0,0,0) 0%, rgba(255, 255, 255, 0.04) 50%, rgba(0,0,0,0) 100%);
                    opacity: 0.1;
                    position: absolute;
                    bottom: 100%;
                    animation: scanline 10s linear infinite;
                    pointer-events: none;
                }}
                @keyframes scanline {{
                    0% {{ bottom: 100%; }}
                    100% {{ bottom: -100%; }}
                }}

                .event-card {{ 
                    background: var(--card-bg); 
                    border: 1px solid var(--text-dim); 
                    padding: 15px; 
                    margin-bottom: 15px; 
                    border-left: 4px solid var(--accent-red); 
                    position: relative; 
                    box-shadow: 0 0 10px rgba(0, 255, 65, 0.05);
                }}
                .event-card:hover {{ 
                    box-shadow: 0 0 15px rgba(0, 255, 65, 0.2); 
                    border-color: var(--text-main);
                }}
                .event-card.low, .event-card.info {{ border-left-color: var(--text-main); }} 
                .event-card.medium {{ border-left-color: var(--accent-yellow); }}
                .event-card.high {{ border-left-color: var(--accent-red); }}
                .event-card.critical {{ border-left-color: var(--accent-red); animation: pulse-red 2s infinite; }}

                @keyframes pulse-red {{
                    0% {{ box-shadow: 0 0 0 0 rgba(255, 0, 60, 0.4); }}
                    70% {{ box-shadow: 0 0 0 10px rgba(255, 0, 60, 0); }}
                    100% {{ box-shadow: 0 0 0 0 rgba(255, 0, 60, 0); }}
                }}
                
                .header-flex {{ display: flex; justify-content: space-between; align-items: center; margin-bottom: 30px; border-bottom: 1px dashed var(--text-dim); padding-bottom: 15px; }}
                .severity {{ text-transform: uppercase; font-weight: 800; font-size: 0.75rem; letter-spacing: 0.1em; }}
                .timestamp {{ color: var(--text-dim); font-size: 0.85rem; }}
                .details {{ 
                    background: #000; 
                    padding: 15px; 
                    border: 1px dashed var(--text-dim); 
                    font-family: 'Courier New', monospace; 
                    margin-top: 15px; 
                    color: #ddd; 
                    font-size: 0.85rem; 
                    line-height: 1.5; 
                    overflow-x: auto; 
                }}
                .badge {{ 
                    background: #000; 
                    padding: 4px 12px; 
                    border: 1px solid var(--text-dim); 
                    font-size: 0.7rem; 
                    font-weight: 600; 
                    text-transform: uppercase; 
                    color: var(--text-main);
                }}
                .stat-card {{ 
                    background: var(--card-bg); 
                    border: 1px solid var(--text-dim); 
                    padding: 20px; 
                    text-align: center; 
                    position: relative;
                }}
                .stat-card:before {{
                    content: '';
                    position: absolute;
                    top: 0; left: 0; right: 0; bottom: 0;
                    border: 1px solid transparent;
                    border-bottom-color: var(--text-main);
                }}
                .footnote {{ font-size: 0.65rem; color: var(--text-dim); margin-top: 8px; text-transform: uppercase; }}
                
                .mode-banner {{ 
                    background: #000; 
                    border: 1px solid var(--text-dim); 
                    padding: 10px 20px; 
                    margin-bottom: 25px; 
                    display: flex; 
                    align-items: center; 
                    gap: 20px; 
                }}
                
                .toast {{ 
                    position: fixed; bottom: 20px; right: 20px; 
                    background: #000; color: var(--text-main); border: 1px solid var(--text-main);
                    padding: 12px 24px; font-weight: 600; display: none; 
                    box-shadow: 0 0 10px var(--text-main);
                    z-index: 1000; 
                }}

                .snippet-diff {{ display: grid; grid-template-columns: 1fr 1fr; gap: 10px; margin-top: 10px; font-size: 0.8rem; }}
                .snippet-box {{ 
                    background: #000; 
                    padding: 10px; 
                    border: 1px dashed var(--text-dim); 
                }}
                
                /* Timings */
                .timings-bar {{ display: flex; height: 4px; overflow: hidden; margin-top: 10px; background: #111; border: 1px solid #333; }}
                .timing-seg {{ height: 100%; }}
                .timing-legend {{ display: flex; gap: 10px; font-size: 0.7rem; color: var(--text-dim); margin-top: 4px; flex-wrap: wrap; }}
                .timing-dot {{ width: 6px; height: 6px; display: inline-block; margin-right: 4px; }}
            </style>
        </head>
        <body>
            <div class="scanline"></div>
            <div id="toast" class="toast"></div>
            <div class="container">
                <div class="header-flex">
                    <div style="display: flex; align-items: center; gap: 15px;">
                        <i data-lucide="shield-check" style="width: 32px; height: 32px; color: var(--text-main);"></i>
                        <div>
                            <h1>GUARDIAN.AI // SOC</h1>
                            <div style="font-size: 0.7rem; color: var(--text-dim); letter-spacing: 1px;">SYSTEM STATUS: ONLINE</div>
                        </div>
                    </div>
                    <div style="display: flex; gap: 10px;">
                        <button onclick="triggerExport('json')" class="badge" style="cursor:pointer; color: var(--accent-cyan); border-color: var(--accent-cyan);">[ EXPORT JSON ]</button>
                        <span class="badge" style="color: var(--accent-yellow); border-color: var(--accent-yellow);">V2.0 SECURE</span>
                    </div>
                </div>

                <!-- Security Warning (Hidden for Demo) -->
                <div style="background: rgba(255, 0, 60, 0.1); border: 1px solid var(--accent-red); padding: 10px; margin-bottom: 20px; text-align: center; color: var(--accent-red); font-weight: bold; font-size: 0.8rem; display: none;">
                    âš ï¸ WARNING: You are using default credentials. Set GUARDIAN_ADMIN_PASS environment variable immediately.
                </div>

                <div class="mode-banner">
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <i data-lucide="settings-2" style="width: 18px; height: 18px; color: var(--text-dim);"></i>
                        <span style="color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase;">Security Mode:</span>
                        <span class="badge" style="color: var(--accent-cyan); border-color: var(--accent-cyan);">{sec_mode.upper()}</span>
                    </div>
                    <div style="display: flex; align-items: center; gap: 8px;">
                        <i data-lucide="shield" style="width: 18px; height: 18px; color: var(--text-dim);"></i>
                        <span style="color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase;">Privacy Strategy:</span>
                        <span class="badge" style="color: var(--accent-yellow); border-color: var(--accent-yellow);">{prev_strat.upper()}</span>
                    </div>
                    <div style="margin-left: auto; display: flex; align-items: center; gap: 8px;">
                         <i data-lucide="bar-chart-2" style="width: 18px; height: 18px; color: var(--text-dim);"></i>
                         <span style="color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase;">BLOCK RATE (GLOBAL):</span>
                         <span id="block-rate" class="badge" style="color: var(--accent-red); border-color: var(--accent-red);">0%</span>
                         <span style="color: var(--text-dim); font-size: 0.8rem; text-transform: uppercase; margin-left: 10px;">RECENT(25):</span>
                         <span id="block-rate-recent" class="badge" style="color: var(--accent-yellow); border-color: var(--accent-yellow);">0%</span>
                    </div>
                </div>
                
                <div style="display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-bottom: 40px;">
                    <div class="stat-card">
                        <div style="font-size: 0.7rem; color: var(--text-dim); margin-bottom: 5px; text-transform: uppercase;">Total Ingress</div>
                        <div id="stat-total" style="font-size: 2rem; font-weight: 800; color: var(--text-main); text-shadow: 0 0 5px var(--text-main);">0</div>
                    </div>
                    <div class="stat-card">
                        <div style="font-size: 0.7rem; color: var(--text-dim); margin-bottom: 5px; text-transform: uppercase;">Upstream Latency</div>
                        <div id="stat-latency" style="font-size: 2rem; font-weight: 800; color: var(--accent-cyan); text-shadow: 0 0 5px var(--accent-cyan);">0ms</div>
                        <div class="footnote">MODEL + NETWORK TIME<br>(EXCLUDES GUARDIAN CHECKS)</div>
                    </div>
                    <div class="stat-card">
                        <div style="font-size: 0.7rem; color: var(--text-dim); margin-bottom: 5px; text-transform: uppercase;">Guardian Overhead</div>
                        <div id="stat-fastpath" style="font-size: 2rem; font-weight: 800; color: var(--accent-yellow); text-shadow: 0 0 5px var(--accent-yellow);">0</div>
                        <div class="footnote">FAST-PATH HITS: <span id="stat-fastpath-hits">0</span></div>
                    </div>
                    <div class="stat-card">
                        <div style="font-size: 0.7rem; color: var(--text-dim); margin-bottom: 5px; text-transform: uppercase;">Threats Blocked</div>
                        <div id="stat-blocked" style="font-size: 2rem; font-weight: 800; color: var(--accent-red); text-shadow: 0 0 5px var(--accent-red);">0</div>
                    </div>
                </div>

                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px; border-bottom: 1px dashed var(--text-dim); padding-bottom: 10px;">
                    <i data-lucide="file-lock" style="width: 20px; height: 20px; color: var(--accent-cyan);"></i>
                    <h2 style="font-size: 1.1rem; font-weight: 600; margin: 0; text-transform: uppercase; color: #fff;">Immutable Audit Log</h2>
                </div>
                <div id="audit-log" style="margin-bottom: 40px;"></div>

                <div style="display: flex; align-items: center; gap: 10px; margin-bottom: 20px; border-bottom: 1px dashed var(--text-dim); padding-bottom: 10px;">
                    <i data-lucide="activity" style="width: 20px; height: 20px; color: var(--accent-red);"></i>
                    <h2 style="font-size: 1.1rem; font-weight: 600; margin: 0; text-transform: uppercase; color: #fff;">Live Threat Telemetry</h2>
                </div>
                
                <div id="events"></div>
            </div>
            <script>
                // Auto-inject credentials for dashboard API calls (this is a local tool)
                const auth = 'Basic ' + btoa('{ADMIN_USER}:{ADMIN_PASS}');
                function showToast(msg) {{
                    const t = document.getElementById('toast');
                    t.innerText = msg;
                    t.style.display = 'block';
                    setTimeout(() => t.style.display = 'none', 3000);
                }}

                function triggerExport(type) {{
                    window.location.href = `/api/v1/export/${{type}}`;
                    showToast(`Exported events as guardianai_telemetry_${{new Date().toISOString().split('T')[0]}}.${{type}}`);
                }}

                function getIcon(entity) {{
                    const e = entity.toUpperCase();
                    if (e.includes('KEY') || e.includes('TOKEN') || e.includes('SECRET')) return 'lock';
                    if (e.includes('EMAIL')) return 'mail';
                    if (e.includes('PHONE')) return 'phone';
                    return 'alert-circle';
                }}
                
                function timeAgo(timestamp) {{
                    const seconds = Math.floor((new Date() - new Date(timestamp * 1000)) / 1000);
                    let interval = seconds / 60;
                    if (interval > 1) return Math.floor(interval) + "m ago";
                    return Math.floor(seconds) + "s ago";
                }}

                async function updateStats() {{
                    try {{
                        const res = await fetch('/api/v1/analytics', {{ headers: {{ 'Authorization': auth }} }});
                        const data = await res.json();
                        document.getElementById('stat-total').innerText = data.total_requests;
                        document.getElementById('stat-blocked').innerText = data.total_blocked;
                        document.getElementById('stat-latency').innerText = data.avg_upstream_ms + 'ms';
                        document.getElementById('stat-fastpath').innerText = data.avg_guardian_overhead_ms + 'ms';
                        document.getElementById('block-rate').innerText = data.global_block_rate_pct + '%';
                        document.getElementById('block-rate-recent').innerText = data.recent_block_rate_pct + '%';
                        
                        const fastHits = (data.path_breakdown.fast_path_keyword || 0) + 
                                         (data.path_breakdown.fast_path_threat_feed || 0) + 
                                         (data.path_breakdown.fast_path_allowlist || 0) +
                                         (data.path_breakdown.base64_filter || 0);
                        document.getElementById('stat-fastpath-hits').innerText = fastHits;
                    }} catch (e) {{ console.error("Analytics fetch failed", e); }}
                }}

                async function updateEvents() {{
                    try {{
                        const res = await fetch('/api/v1/events?limit=25', {{ headers: {{ 'Authorization': auth }} }});
                        const events = await res.json();
                        const eventsDiv = document.getElementById('events');
                        
                        eventsDiv.innerHTML = events.map(e => {{
                            const entities = e.details.detected_entities ? 
                                `<div style="margin-top:10px; display: flex; flex-wrap: wrap; gap: 8px; border-top: 1px dashed #333; padding-top: 10px;">${{e.details.detected_entities.map(ent => 
                                    `<span class="badge" style="color: var(--accent-red); border-color: var(--accent-red); display: flex; align-items: center; gap: 5px;">
                                        <i data-lucide="${{getIcon(ent)}}" style="width: 12px; height: 12px;"></i>
                                        ${{ent}}
                                    </span>`).join('')}}</div>` : '';

                            // Redaction Preview - Cyberpunk Style
                            const redactionPreview = e.details.original_snippet ? `
                                <details style="margin-top: 15px; border: 1px solid var(--text-dim); padding: 5px;">
                                    <summary style="cursor: pointer; font-size: 0.75rem; color: var(--text-dim); list-style: none; display: flex; align-items: center; gap: 8px;">
                                        <i data-lucide="crosshair" style="width: 14px; height: 14px;"></i>
                                        [ VIEW AUDIT LOG ]
                                    </summary>
                                    <div class="snippet-diff" style="padding: 10px; background: #000;">
                                        <div class="snippet-box">
                                            <div style="font-size: 0.65rem; color: var(--accent-red); margin-bottom: 4px; text-transform: uppercase;">>> THREAT DETECTED</div>
                                            <div style="color: var(--accent-red); word-break: break-all;">${{e.details.original_snippet}}</div>
                                        </div>
                                        <div class="snippet-box" style="border-left: 2px solid var(--text-main);">
                                            <div style="font-size: 0.65rem; color: var(--text-main); margin-bottom: 4px; text-transform: uppercase;">>> NEUTRALIZED</div>
                                            <div style="color: var(--text-main); font-weight: 600;">[REDACTED]</div>
                                        </div>
                                    </div>
                                </details>
                            ` : '';
                            
                            // Component Timings
                            let timingsHtml = '';
                            if (e.details.component_timings) {{
                                const times = e.details.component_timings;
                                const total = Object.values(times).reduce((a, b) => a + b, 0);
                                if (total > 0) {{
                                    const colors = ['var(--text-main)', 'var(--accent-cyan)', 'var(--accent-yellow)', 'var(--accent-red)'];
                                    timingsHtml = `
                                        <div style="margin-top: 12px;">
                                            <div class="timings-bar">
                                                ${{Object.entries(times).map(([k, v], i) => 
                                                    `<div class="timing-seg" style="width: ${{v/total*100}}%; background: ${{colors[i % colors.length]}}" title="${{k}}: ${{v.toFixed(1)}}ms"></div>`
                                                ).join('')}}
                                            </div>
                                            <div class="timing-legend">
                                                ${{Object.entries(times).map(([k, v], i) => 
                                                    `<span><i class="timing-dot" style="background:${{colors[i % colors.length]}}"></i>${{k.replace('_ms','').replace('_',' ')}}: ${{v.toFixed(1)}}ms</span>`
                                                ).join('')}}
                                                <span style="margin-left:auto; color: #666;">TOT: ${{total.toFixed(1)}}ms</span>
                                            </div>
                                        </div>
                                    `;
                                }}
                            }}

                            const severityMap = {{
                                'CRITICAL': {{ color: 'var(--accent-red)', icon: 'shield-alert' }},
                                'HIGH': {{ color: 'var(--accent-red)', icon: 'alert-triangle' }},
                                'INFO': {{ color: 'var(--text-main)', icon: 'check-circle' }}, 
                                'LOW': {{ color: 'var(--text-main)', icon: 'check-circle' }},
                                'MEDIUM': {{ color: 'var(--accent-yellow)', icon: 'alert-circle' }}
                            }};
                            
                            const sev = severityMap[e.severity.toUpperCase()] || {{ color: '#666', icon: 'activity' }};
                            
                            let friendlyTitle = e.event_type.toUpperCase().replace('_', ' ');

                            return `
                                <div class="event-card ${{e.severity.toLowerCase()}}" style="border-left-color: ${{sev.color}}">
                                    <div class="header-flex" style="margin-bottom: 5px; border-bottom: none;">
                                        <div style="display: flex; align-items: center; gap: 8px;">
                                            <i data-lucide="${{sev.icon}}" style="width: 16px; height: 16px; color: ${{sev.color}}"></i>
                                            <span class="severity" style="color: ${{sev.color}}">${{e.severity}}</span>
                                        </div>
                                        <span class="timestamp" title="${{new Date(e.timestamp * 1000).toLocaleString()}}">${{timeAgo(e.timestamp)}}</span>
                                    </div>
                                    <div style="font-weight: 800; font-size: 1.1rem; color: #fff; display: flex; align-items: center; gap: 10px; margin-bottom: 5px; letter-spacing: 1px;">
                                        ${{friendlyTitle}}
                                    </div>
                                    <div class="details">
                                        <div style="margin-bottom: 5px; color: #666; font-size: 0.75rem;">
                                            PATH: <span style="color: #ccc;">${{e.details.path || 'unknown'}}</span>
                                        </div>
                                        ${{e.details.reason ? `<div style="color: var(--accent-red); margin-bottom: 5px;">REASON: ${{e.details.reason}}</div>` : ''}}
                                        ${{e.details.prompt_preview ? `<div style="color: #aaa;">PROMPT: "${{e.details.prompt_preview}}..."</div>` : ''}}
                                        ${{redactionPreview}}
                                        ${{entities}}
                                        ${{timingsHtml}}
                                    </div>
                                </div>
                            `;
                        }}).join('');
                        lucide.createIcons();
                    }} catch (e) {{ console.error("Events fetch failed", e); }}
                }}

                setInterval(() => {{
                    updateStats();
                    updateEvents();
                }}, 3000);
                
                updateStats();
                updateEvents();
            </script>
        </body>
    </html>
    """

@app.get("/api/v1/events", response_model=List[SecurityEventResponse])
async def get_events(limit: int = 50, username: str = Depends(enforce_user_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT * FROM security_events ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    
    return [
        {
            "id": r[0],
            "guardian_id": r[1],
            "event_type": r[2],
            "severity": r[3],
            "details": json.loads(r[4]),
            "timestamp": r[5]
        } for r in rows
    ]

@app.get(
    "/api/v1/audit-log",
    response_model=List[AuditLogEntryResponse],
    responses={
        200: {
            "description": "Audit log entries in reverse timestamp order.",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "id": 42,
                            "guardian_id": "guardian-01",
                            "action": "admin_action",
                            "user": "admin",
                            "details": "{\"action\":\"update_policy\"}",
                            "timestamp": 1739835000.0,
                            "signature": "40a0adf4f5...",
                            "prev_hash": "eb2b9f...",
                            "entry_hash": "24d385...",
                        }
                    ]
                }
            },
        }
    },
)
async def get_audit_log(limit: int = 50, username: str = Depends(enforce_auditor_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Check if table exists (it might not if init_db ran on old schema)
    try:
        cur.execute("SELECT * FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
        rows = cur.fetchall()
    except sqlite3.OperationalError:
        return []
    conn.close()
    
    return [
        {
            "id": r[0],
            "guardian_id": r[1],
            "action": r[2],
            "user": r[3],
            "details": r[4],
            "timestamp": r[5],
            "signature": r[6],
            "prev_hash": r[7] if len(r) > 7 else None,
            "entry_hash": r[8] if len(r) > 8 else None,
        } for r in rows
    ]


@app.get(
    "/api/v1/audit-log/verify",
    response_model=AuditVerifyResponse,
    responses={
        200: {
            "description": "Hash-chain verification status.",
            "content": {
                "application/json": {"example": {"ok": True, "entries": 12, "failed_id": None, "reason": None}}
            },
        }
    },
)
async def verify_audit_log_chain(username: str = Depends(enforce_auditor_rate_limit)):
    return _verify_audit_log_chain_internal()


@app.get(
    "/api/v1/audit-log/summary",
    response_model=AuditSummaryResponse,
    responses={
        200: {
            "description": "Audit observability summary including chain and delivery-failure state.",
            "content": {
                "application/json": {
                    "example": {
                        "timestamp": 1739835000.0,
                        "total_entries": 24,
                        "hashed_entries": 20,
                        "legacy_unhashed_entries": 4,
                        "recent_admin_actions_24h": 3,
                        "failed_deliveries_total": 2,
                        "failed_deliveries_by_sink": {"http": 1, "syslog": 1},
                        "chain_ok": True,
                        "chain_entries_checked": 20,
                        "chain_message": "Verified hashed entries; skipped 4 legacy unhashed entries",
                        "chain_failed_id": None,
                        "chain_reason": None,
                    }
                }
            },
        }
    },
)
async def get_audit_summary(username: str = Depends(enforce_auditor_rate_limit)):
    return _build_audit_summary()


@app.get(
    "/api/v1/compliance/report",
    response_model=ComplianceReportResponse,
    responses={
        200: {
            "description": "Operational hardening and compliance posture snapshot.",
            "content": {
                "application/json": {
                    "example": {
                        "status": "warn",
                        "timestamp": 1739835000.0,
                        "summary": {"passed": 8, "warnings": 3, "failed": 1},
                        "controls": [
                            {
                                "control": "jwt_secret_configured",
                                "status": "pass",
                                "detail": "JWT signing secret is non-default.",
                            },
                            {
                                "control": "telemetry_api_key_enforced",
                                "status": "warn",
                                "detail": "Telemetry API key enforcement is disabled.",
                            },
                        ],
                    }
                }
            },
        }
    },
)
async def get_compliance_report(username: str = Depends(enforce_auditor_rate_limit)):
    return _build_compliance_report()


@app.get(
    "/api/v1/rbac/policy",
    response_model=RbacPolicyResponse,
    responses={
        200: {
            "description": "Role-permission catalog and endpoint access matrix.",
            "content": {
                "application/json": {
                    "example": {
                        "generated_at": 1739835000.0,
                        "roles": {
                            "admin": ["api_keys:manage", "audit:retry", "compliance:read", "rbac:read"],
                            "auditor": ["api_keys:read", "audit:read", "compliance:read", "rbac:read"],
                            "user": ["events:read", "analytics:read", "export:read"],
                        },
                        "endpoints": [
                            {
                                "method": "POST",
                                "path": "/api/v1/audit-log/retry-failures",
                                "allowed_roles": ["admin"],
                                "permission": "audit:retry",
                            },
                            {
                                "method": "GET",
                                "path": "/api/v1/compliance/report",
                                "allowed_roles": ["admin", "auditor"],
                                "permission": "compliance:read",
                            },
                        ],
                    }
                }
            },
        }
    },
)
async def get_rbac_policy(username: str = Depends(enforce_auditor_rate_limit)):
    return _build_rbac_policy()


@app.get(
    "/api/v1/audit-log/failures",
    response_model=List[AuditDeliveryFailureResponse],
    responses={
        200: {
            "description": "Queued failed audit deliveries.",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "id": 7,
                            "sink_type": "http",
                            "payload": {"guardian_id": "guardian-01", "action": "admin_action"},
                            "error": "HTTP 503 from sink",
                            "retry_count": 2,
                            "created_at": 1739835000.0,
                            "last_attempt_at": 1739835050.0,
                        }
                    ]
                }
            },
        }
    },
)
async def get_audit_delivery_failures(limit: int = 100, username: str = Depends(enforce_auditor_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute(
        """
        SELECT id, sink_type, payload, error, retry_count, created_at, last_attempt_at
        FROM audit_delivery_failures
        ORDER BY id DESC
        LIMIT ?
        """,
        (limit,),
    )
    rows = cur.fetchall()
    conn.close()
    return [
        {
            "id": row[0],
            "sink_type": row[1],
            "payload": json.loads(row[2]) if row[2] else {},
            "error": row[3],
            "retry_count": row[4],
            "created_at": row[5],
            "last_attempt_at": row[6],
        }
        for row in rows
    ]


@app.post(
    "/api/v1/audit-log/retry-failures",
    response_model=RetryFailuresResponse,
    responses={
        200: {
            "description": "Queued audit deliveries retried.",
            "content": {"application/json": {"example": {"retried": 10, "resolved": 9, "failed": 1}}},
        }
    },
)
async def retry_audit_delivery_failures(limit: int = 100, username: str = Depends(enforce_admin_rate_limit)):
    return _retry_failed_audit_deliveries(limit=limit)

@app.websocket("/ws/threats")
async def websocket_endpoint(websocket: WebSocket):
    await manager.connect(websocket)
    try:
        while True:
            # Just keep connection alive
            await websocket.receive_text()
    except WebSocketDisconnect:
        manager.disconnect(websocket)

if __name__ == "__main__":
    import uvicorn
    ssl_kwargs = {}
    if TLS_CERT_FILE and TLS_KEY_FILE:
        ssl_kwargs = {"ssl_certfile": TLS_CERT_FILE, "ssl_keyfile": TLS_KEY_FILE}
    uvicorn.run(app, host="127.0.0.1", port=8001, **ssl_kwargs)

