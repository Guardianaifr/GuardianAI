from typing import Any, Dict, List, Optional
from pydantic import Field
from backend.models.base import BaseModel


class SecurityEvent(BaseModel):
    guardian_id: str = Field(..., max_length=256)
    tenant_id: str = Field("default", max_length=512)
    event_type: str = Field(..., max_length=128)
    severity: str = Field(..., max_length=512)
    details: dict = Field(default_factory=dict)
    timestamp: float = 0.0


class SecurityEventResponse(BaseModel):
    id: int
    guardian_id: str
    tenant_id: str = "default"
    event_type: str
    severity: str
    details: Dict[str, Any]
    timestamp: float


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
    differential_privacy: Optional[Dict[str, Any]] = None


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


class AuditLogEntryResponse(BaseModel):
    id: int
    guardian_id: str
    action: str
    user: str
    details: str
    timestamp: float
    signature: str
    prev_hash: Optional[str] = None
    entry_hash: Optional[str] = None


class AuditVerifyResponse(BaseModel):
    ok: bool
    entries: int
    message: Optional[str] = None
    failed_id: Optional[int] = None
    reason: Optional[str] = None


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
    chain_message: Optional[str] = None
    chain_failed_id: Optional[int] = None
    chain_reason: Optional[str] = None


__all__ = [
    "SecurityEvent",
    "SecurityEventResponse",
    "TelemetryIngestResponse",
    "AnalyticsResponse",
    "HealthDatabaseComponent",
    "HealthComponents",
    "HealthResponse",
    "AuditLogEntryResponse",
    "AuditVerifyResponse",
    "AuditDeliveryFailureResponse",
    "RetryFailuresResponse",
    "AuditSummaryResponse",
]
