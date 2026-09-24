from typing import Any, Dict, List, Optional
from backend.models.base import BaseModel


class AgenticKeyCreateRequest(BaseModel):
    agent_id: str
    key_id: Optional[str] = None
    cert_fingerprints: List[str] = []


class AgenticKeyResponse(BaseModel):
    id: int
    agent_id: str
    key_id: str
    key_secret_hash: str
    cert_fingerprints: List[str] = []
    status: str
    created_by: Optional[str] = None
    created_at: float
    rotated_at: Optional[float] = None
    revoked_at: Optional[float] = None
    revoked_by: Optional[str] = None
    revoke_reason: Optional[str] = None


class CreatedAgenticKeyResponse(AgenticKeyResponse):
    key_secret: str


class AgenticRevokeRequest(BaseModel):
    agent_id: str
    key_id: Optional[str] = None
    reason: Optional[str] = None


class AgenticExecutionGrantRequest(BaseModel):
    execution_id: str
    agent_id: Optional[str] = None
    parent_agent: Optional[str] = None
    scopes: List[str] = []
    tools: List[str] = []
    ttl_seconds: int = 300


class AgenticExecutionGrantResponse(BaseModel):
    id: int
    execution_id: str
    agent_id: Optional[str] = None
    parent_agent: Optional[str] = None
    scopes: List[str]
    tools: List[str]
    expires_at: float
    created_by: Optional[str] = None
    created_at: float
    revoked_at: Optional[float] = None
    revoked_by: Optional[str] = None
    revoke_reason: Optional[str] = None


class AgenticPolicyEdgeRequest(BaseModel):
    parent_agent: str
    child_agent: str
    scopes: List[str] = []
    tools: List[str] = []
    max_hops: Optional[int] = None


class AgenticPolicyEdgeResponse(BaseModel):
    id: int
    parent_agent: str
    child_agent: str
    scopes: List[str]
    tools: List[str]
    max_hops: Optional[int] = None
    created_by: Optional[str] = None
    created_at: float


class AgenticMetricsResponse(BaseModel):
    timestamp: float
    hop_policy_violations_blocked: int
    unauthorized_mcp_server_attempts: int
    scope_escalation_attempts_blocked: int
    agent_revocations_total: int
    active_agent_keys: int
    active_execution_grants: int
    mean_time_to_revoke_seconds: Optional[float] = None


class AgenticConfigSnapshotResponse(BaseModel):
    generated_at: float
    agent_attestation_keys: Dict[str, Dict[str, str]]
    agent_cert_fingerprints: Dict[str, List[str]]
    revoked_agent_ids: List[str]
    revoked_agent_key_ids: List[str]
    cross_agent_policy_graph: Dict[str, Any]
    execution_grants: Dict[str, Any]
    trace_replay_cache: List[str]


__all__ = [
    "AgenticKeyCreateRequest",
    "AgenticKeyResponse",
    "CreatedAgenticKeyResponse",
    "AgenticRevokeRequest",
    "AgenticExecutionGrantRequest",
    "AgenticExecutionGrantResponse",
    "AgenticPolicyEdgeRequest",
    "AgenticPolicyEdgeResponse",
    "AgenticMetricsResponse",
    "AgenticConfigSnapshotResponse",
]
