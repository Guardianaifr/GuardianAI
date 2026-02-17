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
from typing import List, Dict, Any
import json

import os
import base64
import hmac
import hashlib
import threading
import requests
import psutil
from collections import deque

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("guardian_backend")

# Configuration (Env Vars -> Defaults)
ADMIN_USER = os.getenv("GUARDIAN_ADMIN_USER", "admin")
ADMIN_PASS = os.getenv("GUARDIAN_ADMIN_PASS", "guardian_default") # Simple default for local demo
JWT_SECRET = os.getenv("GUARDIAN_JWT_SECRET", "guardian_jwt_dev_secret_change_me")
JWT_ISSUER = os.getenv("GUARDIAN_JWT_ISSUER", "guardian-backend")
JWT_EXPIRES_MIN = int(os.getenv("GUARDIAN_JWT_EXPIRES_MIN", "60"))
API_RATE_LIMIT_PER_MIN = int(os.getenv("GUARDIAN_RATE_LIMIT_PER_MIN", "240"))
TELEMETRY_RATE_LIMIT_PER_MIN = int(os.getenv("GUARDIAN_TELEMETRY_RATE_LIMIT_PER_MIN", "600"))
USER_RATE_LIMITS_JSON = os.getenv("GUARDIAN_USER_RATE_LIMITS_JSON", "").strip()
TELEMETRY_KEY_RATE_LIMITS_JSON = os.getenv("GUARDIAN_TELEMETRY_KEY_RATE_LIMITS_JSON", "").strip()
TELEMETRY_REQUIRE_API_KEY = os.getenv("GUARDIAN_TELEMETRY_REQUIRE_API_KEY", "false").strip().lower() in {"1", "true", "yes", "on"}
AUDIT_SINK_URL = os.getenv("GUARDIAN_AUDIT_SINK_URL", "").strip()
AUDIT_SINK_TOKEN = os.getenv("GUARDIAN_AUDIT_SINK_TOKEN", "").strip()
AUDIT_SINK_TIMEOUT_SEC = float(os.getenv("GUARDIAN_AUDIT_TIMEOUT_SEC", "2.0"))
AUDIT_SINK_RETRIES = int(os.getenv("GUARDIAN_AUDIT_RETRIES", "2"))
AUDIT_SINK_STRICT = os.getenv("GUARDIAN_AUDIT_STRICT", "false").strip().lower() in {"1", "true", "yes", "on"}
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
_metrics_lock = threading.Lock()
_metrics_request_count = 0
_metrics_total_latency_ms = 0.0
_metrics_latency_samples = 0
_metrics_status_counts: Dict[int, int] = {}
_metrics_recent_requests = deque()


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


def _issue_jwt(subject: str, ttl_minutes: int = JWT_EXPIRES_MIN) -> str:
    now = int(time.time())
    header = {"alg": "HS256", "typ": "JWT"}
    payload = {
        "sub": subject,
        "iat": now,
        "exp": now + (ttl_minutes * 60),
        "iss": JWT_ISSUER,
        "jti": secrets.token_hex(12),
    }
    header_seg = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    payload_seg = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{header_seg}.{payload_seg}".encode("ascii")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    return f"{header_seg}.{payload_seg}.{_b64url_encode(signature)}"


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

    return payload


def _enforce_rate_limit(identity: str, limit_per_minute: int):
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
    correct_username = secrets.compare_digest(credentials.username, ADMIN_USER)
    correct_password = secrets.compare_digest(credentials.password, ADMIN_PASS)
    if not (correct_username and correct_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
            headers={"WWW-Authenticate": "Basic"},
        )
    return credentials.username


def get_current_user(
    bearer: HTTPAuthorizationCredentials = Depends(bearer_security),
    credentials: HTTPBasicCredentials = Depends(security),
):
    if bearer and bearer.scheme.lower() == "bearer":
        payload = _decode_jwt(bearer.credentials)
        return payload["sub"]

    if credentials:
        return _validate_basic(credentials)

    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required",
        headers={"WWW-Authenticate": "Bearer"},
    )


def enforce_user_rate_limit(request: Request, username: str = Depends(get_current_user)):
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    return username


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


class TokenResponse(BaseModel):
    access_token: str
    token_type: str
    expires_in: int
    user: str


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


@app.post("/api/v1/auth/token", response_model=TokenResponse)
async def create_access_token(credentials: HTTPBasicCredentials = Depends(HTTPBasic())):
    username = _validate_basic(credentials)
    token = _issue_jwt(username)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=JWT_EXPIRES_MIN * 60,
        user=username,
    )


@app.post("/api/v1/api-keys", response_model=CreatedApiKeyResponse)
async def create_api_key(payload: CreateApiKeyRequest, username: str = Depends(enforce_user_rate_limit)):
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


@app.get("/api/v1/api-keys", response_model=List[ApiKeyResponse])
async def list_api_keys(username: str = Depends(enforce_user_rate_limit)):
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


@app.post("/api/v1/api-keys/{key_id}/revoke", response_model=ApiKeyResponse)
async def revoke_api_key(key_id: int, username: str = Depends(enforce_user_rate_limit)):
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


@app.post("/api/v1/api-keys/{key_id}/rotate", response_model=CreatedApiKeyResponse)
async def rotate_api_key(key_id: int, username: str = Depends(enforce_user_rate_limit)):
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

@app.post("/api/v1/telemetry")
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
        payload = f"{event.guardian_id}:{event.timestamp}:{json.dumps(event.details)}"
        signature = hashlib.sha256(payload.encode()).hexdigest()
        audit_payload = {
            "guardian_id": event.guardian_id,
            "action": event.details.get("action", "unknown"),
            "user": event.details.get("user", "unknown"),
            "details": event.details,
            "timestamp": event.timestamp,
            "signature": signature,
        }
        
        cur.execute(
            "INSERT INTO audit_logs (guardian_id, action, user, details, timestamp, signature) VALUES (?, ?, ?, ?, ?, ?)",
            (event.guardian_id, event.details.get("action", "unknown"), event.details.get("user", "unknown"), json.dumps(event.details), event.timestamp, signature)
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

    # 3. External Audit Sink (best effort unless strict mode enabled)
    if audit_payload is not None:
        _forward_external_audit_log(audit_payload)

    # 4. Fire Webhook Alert
    await send_webhook_alert(event)
    
    return {"status": "persisted", "event_id": event.guardian_id}

from fastapi.responses import StreamingResponse
import io
import csv

@app.get("/api/v1/export/json")
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

@app.get("/api/v1/analytics")
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

@app.get("/health")
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
            "audit_sink_configured": bool(AUDIT_SINK_URL),
        },
    }
    if db_ok:
        return payload
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload)


@app.get("/metrics")
async def metrics():
    if not METRICS_ENABLED:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Metrics disabled")
    return HTMLResponse(content=_build_metrics_payload(), media_type="text/plain")

@app.get("/", response_class=HTMLResponse)
async def dashboard(username: str = Depends(enforce_user_rate_limit)):
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

@app.get("/api/v1/events")
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

@app.get("/api/v1/audit-log")
async def get_audit_log(limit: int = 50, username: str = Depends(enforce_user_rate_limit)):
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
            "signature": r[6]
        } for r in rows
    ]

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

