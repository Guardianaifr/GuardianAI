from typing import List, Optional
from backend.models.base import BaseModel


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
    last_used_at: Optional[float] = None


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
    revoked_at: Optional[float] = None
    revoked_by: Optional[str] = None
    revoke_reason: Optional[str] = None
    active: bool


class RevokeUserSessionsRequest(BaseModel):
    username: str
    active_only: bool = True
    reason: Optional[str] = None


class RevokeUserSessionsResponse(BaseModel):
    target_user: str
    matched: int
    revoked: int
    already_revoked: int
    active_only: bool
    reason: Optional[str] = None


class RevokeSelfSessionsRequest(BaseModel):
    active_only: bool = True
    exclude_current: bool = True
    reason: Optional[str] = None


class RevokeSelfSessionsResponse(BaseModel):
    target_user: str
    matched: int
    revoked: int
    already_revoked: int
    excluded_current: int
    active_only: bool
    exclude_current: bool
    reason: Optional[str] = None


class RevokeSelfSessionByJtiRequest(BaseModel):
    jti: str
    reason: Optional[str] = None


class RevokeSelfSessionByJtiResponse(BaseModel):
    jti: str
    target_user: str
    revoked: bool
    already_revoked: bool
    reason: Optional[str] = None


class RevokeAllSessionsRequest(BaseModel):
    active_only: bool = True
    exclude_self: bool = True
    exclude_usernames: Optional[List[str]] = None
    reason: Optional[str] = None


class RevokeAllSessionsResponse(BaseModel):
    matched: int
    revoked: int
    already_revoked: int
    excluded: int
    active_only: bool
    exclude_self: bool
    excluded_users: List[str]
    reason: Optional[str] = None


class RevokeSessionByJtiRequest(BaseModel):
    jti: str
    reason: Optional[str] = None


class RevokeSessionByJtiResponse(BaseModel):
    jti: str
    target_user: str
    revoked: bool
    already_revoked: bool
    reason: Optional[str] = None


class AuthLockoutEntryResponse(BaseModel):
    identity: str
    username: str
    source: str
    failed_attempts: int
    locked_until: Optional[float] = None
    retry_after_sec: int
    active: bool


class ClearAuthLockoutsRequest(BaseModel):
    clear_all: bool = False
    identity: Optional[str] = None
    username: Optional[str] = None
    source: Optional[str] = None


class ClearAuthLockoutsResponse(BaseModel):
    cleared: int
    remaining: int
    scope: str


class WhoAmIResponse(BaseModel):
    user: str
    role: str
    auth_type: str
    permissions: List[str]


__all__ = [
    "TokenResponse",
    "CreateApiKeyRequest",
    "ApiKeyResponse",
    "CreatedApiKeyResponse",
    "RevokeTokenResponse",
    "RevokedTokenEntryResponse",
    "PruneRevokedTokensResponse",
    "AuthSessionResponse",
    "RevokeUserSessionsRequest",
    "RevokeUserSessionsResponse",
    "RevokeSelfSessionsRequest",
    "RevokeSelfSessionsResponse",
    "RevokeSelfSessionByJtiRequest",
    "RevokeSelfSessionByJtiResponse",
    "RevokeAllSessionsRequest",
    "RevokeAllSessionsResponse",
    "RevokeSessionByJtiRequest",
    "RevokeSessionByJtiResponse",
    "AuthLockoutEntryResponse",
    "ClearAuthLockoutsRequest",
    "ClearAuthLockoutsResponse",
    "WhoAmIResponse",
]
