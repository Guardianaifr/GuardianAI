from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional

from backend.main import (
    CredentialIssueRequest,
    PassportIssueRequest,
    PassportVerifyRequest,
    _get_credential_issuer,
    _get_passport_engine,
    _get_passport_verifier,
    _get_trust_scorer,
    get_current_principal,
    _enforce_rate_limit,
    _get_user_rate_limit,
)
from backend.security.authorization import can_access_agent

router = APIRouter()

@router.post("/api/v1/passport/issue", tags=["Agent Passport"])
async def issue_passport(req: PassportIssueRequest, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Issue a new Agent Passport (SBT identity) for an AI agent."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    tenant_id = principal.get("org_id", "default")

    engine = _get_passport_engine()
    existing = engine.get_passport(req.agent_id)
    if existing is not None:
        if not can_access_agent(principal, existing.tenant_id):
            raise HTTPException(
                status_code=403,
                detail="Forbidden: Passport for this agent is already owned by another tenant."
            )
        passport = existing
    else:
        passport = engine.issue_passport(
            agent_id=req.agent_id,
            owner_pubkey=req.owner_pubkey,
            chain_id=req.chain_id,
            metadata=req.metadata,
            tenant_id=tenant_id,
        )

    # Compute initial trust score (no Cortex data yet on first issue)
    scorer = _get_trust_scorer()
    result = scorer.compute_score(req.agent_id, cortex_events_count=0, last_anchor_tx="")
    engine.update_trust_score(req.agent_id, result.score, result.tier)

    # Refresh passport with updated score
    passport = engine.get_passport(req.agent_id)
    return {"passport": passport.to_dict(), "trust_score": result.to_dict()}


@router.get("/api/v1/passport/leaderboard", tags=["Agent Passport"])
async def get_passport_leaderboard(limit: int = 20, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Get the top agents by trust score."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    limit = min(max(1, limit), 100)
    engine = _get_passport_engine()
    leaders = engine.get_leaderboard(limit=limit)
    return {
        "leaderboard": [p.to_dict() for p in leaders],
        "total": len(leaders),
    }


@router.get("/api/v1/passport/public-key", tags=["Agent Passport"])
async def get_passport_public_key():
    """Get the issuer's public key for credential verification (public endpoint)."""
    issuer = _get_credential_issuer()
    return {
        "public_key_hex": issuer.get_public_key_hex(),
        "algorithm": "Ed25519",
        "issuer_did": f"did:guardian:issuer:{issuer.get_public_key_hex()[:32]}",
    }


@router.get("/api/v1/passport/{agent_id}", tags=["Agent Passport"])
async def get_passport(agent_id: str, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Get an agent's passport details including trust score."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))

    engine = _get_passport_engine()
    passport = engine.get_passport(agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail=f"No passport found for agent: {agent_id}")
        
    if not can_access_agent(principal, passport.tenant_id):
        raise HTTPException(status_code=403, detail="Forbidden: You do not have access to this agent's passport.")

    return {"passport": passport.to_dict()}


@router.get("/api/v1/passport/{agent_id}/score", tags=["Agent Passport"])
async def get_passport_score(agent_id: str, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Get an agent's current trust score with full breakdown."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))

    engine = _get_passport_engine()
    passport = engine.get_passport(agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail=f"No passport found for agent: {agent_id}")
        
    if not can_access_agent(principal, passport.tenant_id):
        raise HTTPException(status_code=403, detail="Forbidden: You do not have access to this agent's passport.")

    scorer = _get_trust_scorer()
    cortex_count = passport.cortex_events_count
    anchor_tx = passport.last_anchor_tx
    result = scorer.compute_score(
        agent_id,
        cortex_events_count=cortex_count,
        last_anchor_tx=anchor_tx,
    )

    # Update stored score
    engine.update_trust_score(agent_id, result.score, result.tier)

    return {"agent_id": agent_id, "trust_score": result.to_dict()}


@router.get("/api/v1/passport/{agent_id}/credentials", tags=["Agent Passport"])
async def get_passport_credentials(agent_id: str, principal: Dict[str, Any] = Depends(get_current_principal)):
    """List an agent's verifiable credentials."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))

    engine = _get_passport_engine()
    passport = engine.get_passport(agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail=f"No passport found for agent: {agent_id}")
        
    if not can_access_agent(principal, passport.tenant_id):
        raise HTTPException(status_code=403, detail="Forbidden: You do not have access to this agent's passport.")

    return {"agent_id": agent_id, "credentials": passport.credentials}


@router.post("/api/v1/passport/{agent_id}/credentials/issue", tags=["Agent Passport"])
async def issue_credential(agent_id: str, req: CredentialIssueRequest, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Issue a verifiable credential for an agent (admin only)."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privilege required")

    engine = _get_passport_engine()
    passport = engine.get_passport(agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail=f"No passport found for agent: {agent_id}")
        
    if not can_access_agent(principal, passport.tenant_id):
        raise HTTPException(status_code=403, detail="Forbidden: You do not have access to this agent's passport.")

    if not passport.is_active:
        raise HTTPException(status_code=404, detail=f"Passport for agent '{agent_id}' has been revoked")

    from guardian.passport.credentials import CredentialType
    valid_types = {ct.value for ct in CredentialType}
    if req.credential_type not in valid_types:
        raise HTTPException(
            status_code=400,
            detail=f"Invalid credential type. Must be one of: {', '.join(sorted(valid_types))}",
        )

    issuer = _get_credential_issuer()
    credential = issuer.issue_credential(
        agent_id=agent_id,
        credential_type=req.credential_type,
        claims=req.claims,
    )

    engine.add_credential(agent_id, credential.to_dict())
    return {"credential": credential.to_dict()}


@router.post("/api/v1/passport/verify", tags=["Agent Passport"])
async def verify_passport(req: PassportVerifyRequest, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Verify an agent's passport and trust status."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))

    verifier = _get_passport_verifier()

    if req.requesting_agent_id:
        result = verifier.cross_verify(req.requesting_agent_id, req.agent_id)
        return {"verification": result}
    else:
        result = verifier.verify_passport(req.agent_id)
        return {"verification": result.to_dict()}


@router.post("/api/v1/passport/{agent_id}/revoke", tags=["Agent Passport"])
async def revoke_passport(agent_id: str, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Revoke an agent's passport (admin only)."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privilege required")

    engine = _get_passport_engine()
    passport = engine.get_passport(agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail=f"No passport found for agent: {agent_id}")
        
    if not can_access_agent(principal, passport.tenant_id):
        raise HTTPException(status_code=403, detail="Forbidden: You do not have access to this agent's passport.")

    revoked = engine.revoke_passport(agent_id)
    if not revoked:
        raise HTTPException(status_code=404, detail=f"No active passport found for agent: {agent_id}")
    return {"revoked": True, "agent_id": agent_id}
