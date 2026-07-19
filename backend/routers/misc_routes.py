from fastapi import APIRouter, Depends, HTTPException, status
from fastapi.responses import HTMLResponse, JSONResponse
from typing import List, Any
import hmac
import os
import random
import time
import json
import hashlib
import sqlite3

from backend.main import (
    # Private helpers
    _build_audit_summary,
    _build_compliance_report,
    _build_metrics_payload,
    _build_rbac_policy,
    _check_db_health,
    _compute_audit_entry_hash,
    _forward_audit_payload,
    _generate_api_key_material,
    _hash_api_key,
    _retry_failed_audit_deliveries,
    _to_ms,
    _verify_audit_log_chain_internal,
    _write_siem_alert,
    # Pydantic models
    AnalyticsResponse,
    ApiKeyResponse,
    AuditDeliveryFailureResponse,
    AuditLogEntryResponse,
    AuditSummaryResponse,
    AuditVerifyResponse,
    ComplianceReportResponse,
    CreateApiKeyRequest,
    CreatedApiKeyResponse,
    HealthResponse,
    RbacPolicyResponse,
    RetryFailuresResponse,
    TelemetryIngestResponse,
    # Constants
    APP_START_TIME,
    BLOCKED_EVENT_TYPES,
    DB_PATH,
    DP_ENABLED,
    DP_EPSILON,
    DP_SEED,
    JWT_SECRET,
    METRICS_ENABLED,
    PROXY_EVENT_TYPES,
    # Auth dependencies
    enforce_admin_rate_limit,
    enforce_auditor_rate_limit,
    enforce_telemetry_rate_limit,
    enforce_user_rate_limit,
    get_current_principal,
    _enforce_rate_limit,
    _get_user_rate_limit,
    # Other
    logger,
    noisy_count,
    send_webhook_alert,
    SecurityEvent,
)
from backend.security.authorization import can_access_tenant

router = APIRouter()

@router.post(
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


@router.get(
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


@router.post(
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


@router.post(
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


@router.post(
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
    if not event.tenant_id:
        event.tenant_id = "default"
        
    logger.info("Ingesting %s from %s", event.event_type, event.guardian_id)
    
    # Normalize severity
    event.severity = event.severity.upper()
    
    # 1. Persist to SQLite
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    
    # Insert new event
    cur.execute(
        "INSERT INTO security_events (guardian_id, tenant_id, event_type, severity, details, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
        (event.guardian_id, event.tenant_id, event.event_type, event.severity, json.dumps(event.details), event.timestamp)
    )

    audit_payload = None

    # 2. Immutable Audit Log (Critical Events)
    if event.event_type == "admin_action":
        import hashlib
        # Simulate cryptographic signing of the log entry
        details_json = json.dumps(event.details)
        payload = f"{event.guardian_id}:{event.timestamp}:{details_json}"
        signature = hmac.new(JWT_SECRET.encode("utf-8"), payload.encode("utf-8"), hashlib.sha256).hexdigest()
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
                "INSERT INTO analytics (tenant_id, path, latency_ms, timestamp) VALUES (?, ?, ?, ?)",
                (event.tenant_id, path, latency, event.timestamp)
            )
        except (ValueError, TypeError, KeyError, AttributeError) as exc:
            logger.debug("Analytics extraction skipped: %s", exc)
    
    # 2. Retention Policy: Auto-purge events older than the configured retention window
    retention_cutoff = time.time() - (30 * 24 * 60 * 60)
    cur.execute("DELETE FROM security_events WHERE timestamp < ?", (retention_cutoff,))
    
    conn.commit()
    conn.close()

    # 3. External Audit Sinks (best effort unless strict mode enabled)
    if audit_payload is not None:
        _forward_audit_payload(audit_payload)
    _write_siem_alert(event)

    # 4. Fire Webhook Alert
    await send_webhook_alert(event)
    
    return {"status": "persisted", "event_id": event.guardian_id}


@router.get(
    "/api/v1/analytics",
    response_model=AnalyticsResponse,
    responses={200: {"description": "Aggregated analytics and block-rate summary."}},
)
async def get_analytics(
    tenant_id: str | None = None,
    dp: bool = True,
    principal: dict = Depends(get_current_principal),
):
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    role = principal.get("role", "user")
    user_tenant = principal.get("org_id", "default")
    is_global = role == "admin" or (role == "auditor" and user_tenant == "org_guardian")

    if tenant_id:
        if not can_access_tenant(principal, tenant_id):
            raise HTTPException(status_code=403, detail="Forbidden: You do not have access to this tenant's data.")
    else:
        if not is_global:
            tenant_id = user_tenant

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()

    proxy_placeholders = ",".join("?" for _ in PROXY_EVENT_TYPES)
    blocked_set = set(BLOCKED_EVENT_TYPES)

    # Consistent ingress scope: only proxy pipeline events.
    query = f"SELECT event_type, details FROM security_events WHERE event_type IN ({proxy_placeholders})"
    params: list[Any] = list(PROXY_EVENT_TYPES)
    if tenant_id:
        query += " AND tenant_id = ?"
        params.append(tenant_id)
    cur.execute(query, params)
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
    recent_query = f"SELECT event_type FROM security_events WHERE event_type IN ({proxy_placeholders})"
    recent_params: list[Any] = list(PROXY_EVENT_TYPES)
    if tenant_id:
        recent_query += " AND tenant_id = ?"
        recent_params.append(tenant_id)
    recent_query += " ORDER BY timestamp DESC LIMIT 25"
    cur.execute(recent_query, recent_params)
    recent_rows = cur.fetchall()
    recent_total = len(recent_rows)
    recent_blocked = sum(1 for (evt_type,) in recent_rows if (evt_type or "").lower() in blocked_set)

    conn.close()

    avg_latency = (sum(end_to_end_samples) / len(end_to_end_samples)) if end_to_end_samples else 0.0
    avg_overhead = (sum(overhead_samples) / len(overhead_samples)) if overhead_samples else 0.0
    avg_upstream = (sum(upstream_samples) / len(upstream_samples)) if upstream_samples else avg_latency
    global_block_rate = (total_blocked / total_count * 100) if total_count else 0.0
    recent_block_rate = (recent_blocked / recent_total * 100) if recent_total else 0.0
    dp_meta = {"enabled": False}
    if DP_ENABLED and dp:
        rng = random.Random(DP_SEED)
        total_count = noisy_count(total_count, DP_EPSILON, rng)
        total_blocked = noisy_count(total_blocked, DP_EPSILON, rng)
        dp_meta = {
            "enabled": True,
            "mechanism": "laplace",
            "epsilon": DP_EPSILON,
        }

    return {
        "total_requests": total_count or 0,
        "total_blocked": total_blocked or 0,
        "avg_latency_ms": round(avg_latency or 0, 2),
        "avg_guardian_overhead_ms": round(avg_overhead or 0, 2),
        "avg_upstream_ms": round(avg_upstream or 0, 2),
        "global_block_rate_pct": round(global_block_rate, 1),
        "recent_block_rate_pct": round(recent_block_rate, 1),
        "path_breakdown": paths,
        "fast_path_pct": round((sum(v for k,v in paths.items() if 'fast' in k) / total_count * 100) if total_count else 0, 1),
        "differential_privacy": dp_meta,
    }


@router.get(
    "/health",
    response_model=HealthResponse,
    responses={
        200: {
            "description": "Service is healthy.",
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
            "description": "One or more dependencies are unhealthy.",
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
        },
    },
)
async def health_check():
    """Readiness / liveness health-check endpoint."""
    db_ok, db_message = _check_db_health()
    now = time.time()
    # Resolve optional config variables that may not exist in all deployment variants
    _https_enforced: bool = bool(os.getenv("GUARDIAN_ENFORCE_HTTPS", "false").lower() in {"1", "true", "yes", "on"})
    _env_mode = os.getenv("GUARDIAN_ENV", "development").strip().lower()
    _default_telemetry_require = "true" if _env_mode == "production" else "false"
    _telemetry_api_key: bool = bool(os.getenv("GUARDIAN_TELEMETRY_REQUIRE_API_KEY", _default_telemetry_require).lower() in {"1", "true", "yes", "on"})
    _audit_sink: bool = bool(
        os.getenv("GUARDIAN_AUDIT_SINK_URL")
        or os.getenv("GUARDIAN_AUDIT_SYSLOG_HOST")
        or os.getenv("GUARDIAN_AUDIT_SPLUNK_HEC_URL")
        or os.getenv("GUARDIAN_AUDIT_DATADOG_API_KEY")
    )
    _auth_lockout: bool = bool(os.getenv("GUARDIAN_AUTH_LOCKOUT_ENABLED", "true").lower() in {"1", "true", "yes", "on"})
    payload = {
        "status": "healthy" if db_ok else "unhealthy",
        "timestamp": now,
        "uptime_sec": round(now - APP_START_TIME, 3),
        "components": {
            "database": {"ok": db_ok, "detail": db_message},
            "metrics_enabled": METRICS_ENABLED,
            "https_enforced": _https_enforced,
            "telemetry_requires_api_key": _telemetry_api_key,
            "audit_sink_configured": _audit_sink,
            "auth_lockout_enabled": _auth_lockout,
        },
    }
    if db_ok:
        return payload
    return JSONResponse(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, content=payload)


@router.get(
    "/metrics",
    responses={
        200: {"description": "Prometheus exposition format.", "content": {"text/plain": {}}},
        404: {"description": "Metrics disabled."},
    },
)
async def metrics():
    """Expose Prometheus-style metrics when GUARDIAN_METRICS_ENABLED is true."""
    if not METRICS_ENABLED:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Metrics disabled")
    return HTMLResponse(content=_build_metrics_payload(), media_type="text/plain")


@router.get(
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
    limit = min(max(1, limit), 1000)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    # Check if table exists (it might not if init_db ran on old schema)
    try:
        cur.execute("SELECT id, guardian_id, action, user, details, timestamp, signature, prev_hash, entry_hash FROM audit_logs ORDER BY timestamp DESC LIMIT ?", (limit,))
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


@router.get(
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


@router.get(
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


@router.get(
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


@router.get(
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


@router.get(
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
    limit = min(max(1, limit), 1000)
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


@router.post(
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
    limit = min(max(1, limit), 1000)
    return _retry_failed_audit_deliveries(limit=limit)
