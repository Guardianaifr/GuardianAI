from typing import Dict, List
from backend.models.base import BaseModel


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


__all__ = [
    "ComplianceControlResponse",
    "ComplianceSummaryResponse",
    "ComplianceReportResponse",
    "RbacEndpointPolicyResponse",
    "RbacPolicyResponse",
]
