from typing import Any, Dict, List, Optional
from backend.models.base import BaseModel


class BillingCheckoutRequest(BaseModel):
    plan: str
    payment_method: str
    customer_email: Optional[str] = None
    tenant_name: Optional[str] = None


class BillingConfirmRequest(BaseModel):
    order_id: str
    provider_transaction_id: str
    provider_status: str
    machine_id: Optional[str] = None


class BadgeVerificationRequest(BaseModel):
    badge_data: dict


class ScanRequest(BaseModel):
    target_url: str
    target_name: str = ""
    depth: str = "standard"


class CampaignTargetInput(BaseModel):
    url: str
    name: str = ""
    depth: str = "standard"


class CampaignCreateRequest(BaseModel):
    name: str
    targets: List[CampaignTargetInput]
    custom_pack_paths: List[str] = []


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


class ContractAnalyzeRequest(BaseModel):
    source_code: str
    contract_name: str = "UnknownContract"
    contract_address: Optional[str] = None
    chain: str = "ethereum"


class ContractOnChainAnalyzeRequest(BaseModel):
    contract_address: str
    chain: str = "ethereum"
    api_key: Optional[str] = None


class AddressScreenRequest(BaseModel):
    address: str
    chain: str = "bitcoin"


class BatchScreenRequest(BaseModel):
    addresses: List[str]
    chain: str = "bitcoin"


class PassportIssueRequest(BaseModel):
    agent_id: str
    owner_pubkey: str
    chain_id: str = "monad-testnet"
    metadata: Optional[Dict[str, Any]] = None


class PassportVerifyRequest(BaseModel):
    agent_id: str
    requesting_agent_id: Optional[str] = None


class CredentialIssueRequest(BaseModel):
    agent_id: str
    credential_type: str
    claims: Optional[Dict[str, Any]] = None


__all__ = [
    "BillingCheckoutRequest",
    "BillingConfirmRequest",
    "BadgeVerificationRequest",
    "ScanRequest",
    "CampaignTargetInput",
    "CampaignCreateRequest",
    "ScheduleInput",
    "RemediationRequest",
    "ContractAnalyzeRequest",
    "ContractOnChainAnalyzeRequest",
    "AddressScreenRequest",
    "BatchScreenRequest",
    "PassportIssueRequest",
    "PassportVerifyRequest",
    "CredentialIssueRequest",
]
