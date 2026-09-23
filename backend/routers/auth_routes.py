import os
import time
import sqlite3

from fastapi import APIRouter, Depends, HTTPException, status, Request, Form
from fastapi.responses import RedirectResponse
from typing import List, Dict, Any, Set

from backend.main import (
    # Security classes
    HTTPBasic,
    HTTPBasicCredentials,
    # Constants
    DB_PATH,
    ENFORCE_HTTPS,
    JWT_EXPIRES_MIN,
    # Dependency functions
    enforce_admin_rate_limit,
    enforce_auditor_rate_limit,
    enforce_auth_rate_limit,
    enforce_user_rate_limit,
    get_current_principal,
    get_current_token_payload,
    # Pydantic models
    AuthLockoutEntryResponse,
    AuthSessionResponse,
    ClearAuthLockoutsRequest,
    ClearAuthLockoutsResponse,
    PruneRevokedTokensResponse,
    RevokeAllSessionsRequest,
    RevokeAllSessionsResponse,
    RevokeSessionByJtiRequest,
    RevokeSessionByJtiResponse,
    RevokeSelfSessionByJtiRequest,
    RevokeSelfSessionByJtiResponse,
    RevokeSelfSessionsRequest,
    RevokeSelfSessionsResponse,
    RevokeTokenResponse,
    RevokeUserSessionsRequest,
    RevokeUserSessionsResponse,
    RevokedTokenEntryResponse,
    TokenResponse,
    WhoAmIResponse,
    # Private helpers
    _auth_lockout_identity,
    _auth_lockout_retry_after_seconds,
    _auth_users,
    _clear_auth_lockout_failures,
    _clear_auth_lockouts,
    _enforce_rbac_and_user_rate_limit,
    _get_user_role,
    _issue_jwt,
    _list_auth_lockouts,
    _list_auth_sessions,
    _list_revoked_tokens,
    _mark_issued_token_revoked,
    _permissions_for_role,
    _prune_revoked_tokens,
    _record_auth_lockout_failure,
    _record_issued_token,
    _revoke_all_sessions,
    _revoke_self_session_by_jti,
    _revoke_session_by_jti,
    _revoke_user_sessions,
    _validate_basic,
    _write_control_plane_audit_entry,
)

router = APIRouter()
secure = ENFORCE_HTTPS or os.getenv("GUARDIAN_ENV") == "production"

@router.post(
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
@router.post(
    "/api/v1/auth/login",
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
def create_access_token(
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
    user_config = _auth_users.get(username, {})
    org_id = user_config.get("org_id", "org_default")
    token, claims = _issue_jwt(username, role=role, org_id=org_id)
    _record_issued_token(claims)
    return TokenResponse(
        access_token=token,
        token_type="bearer",
        expires_in=JWT_EXPIRES_MIN * 60,
        user=username,
        role=role,
    )


@router.post(
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
def revoke_access_token(
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


@router.get(
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
def list_revoked_tokens(
    limit: int = 100,
    include_expired: bool = False,
    username: str = Depends(enforce_auditor_rate_limit),
):
    bounded_limit = max(1, min(limit, 1000))
    return _list_revoked_tokens(limit=bounded_limit, include_expired=include_expired)


@router.post(
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
def prune_revoked_tokens(
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


@router.get(
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
def list_auth_lockouts(
    limit: int = 100,
    active_only: bool = True,
    username: str = Depends(enforce_auditor_rate_limit),
):
    bounded_limit = max(1, min(limit, 1000))
    return _list_auth_lockouts(limit=bounded_limit, active_only=active_only)


@router.post(
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
def clear_auth_lockouts(
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


@router.get(
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
def list_auth_sessions(
    limit: int = 100,
    include_expired: bool = False,
    include_revoked: bool = True,
    username: str = Depends(enforce_auditor_rate_limit),
):
    bounded_limit = max(1, min(limit, 1000))
    return _list_auth_sessions(limit=bounded_limit, include_expired=include_expired, include_revoked=include_revoked)


@router.post(
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
def revoke_self_sessions(
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


@router.post(
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
def revoke_self_session_by_jti(
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


@router.post(
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
def revoke_user_sessions(
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


@router.post(
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
def revoke_all_sessions(
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


@router.post(
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
def revoke_session_by_jti(
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


@router.get(
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
def auth_whoami(
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


@router.post("/login")
def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
    _: bool = Depends(enforce_auth_rate_limit),
):
    lockout_identity = _auth_lockout_identity(request, username)
    retry_after = _auth_lockout_retry_after_seconds(lockout_identity)
    if retry_after > 0:
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    try:
        creds = HTTPBasicCredentials(username=username, password=password)
        validated_user = _validate_basic(creds)
    except HTTPException:
        _record_auth_lockout_failure(lockout_identity)
        return RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)

    _clear_auth_lockout_failures(lockout_identity)
    role = _get_user_role(validated_user)
    user_config = _auth_users.get(validated_user, {})
    org_id = user_config.get("org_id", "org_default")

    token, _ = _issue_jwt(validated_user, role, org_id)

    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.set_cookie(
        key="guardian_token",
        value=token,
        httponly=True,
        samesite="lax",
        secure=secure
    )
    return response


@router.get("/logout")
def logout():
    response = RedirectResponse(url="/", status_code=status.HTTP_303_SEE_OTHER)
    response.delete_cookie("guardian_token")
    return response
