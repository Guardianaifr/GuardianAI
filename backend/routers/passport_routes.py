from fastapi import APIRouter, Depends, HTTPException, status, Request, WebSocket, WebSocketDisconnect, Form, Body
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, StreamingResponse
from pydantic import BaseModel
from typing import List, Dict, Any, Optional, Set
import time
import json
import base64
import hashlib
import sqlite3

# Import all shared dependencies from backend.main
import backend.main as backend_main
globals().update({k: v for k, v in backend_main.__dict__.items()})

router = APIRouter()

@router.post("/api/v1/passport/issue", tags=["Agent Passport"])
async def issue_passport(req: PassportIssueRequest, username: str = Depends(enforce_user_rate_limit)):
    """Issue a new Agent Passport (SBT identity) for an AI agent."""
    engine = _get_passport_engine()
    passport = engine.issue_passport(
        agent_id=req.agent_id,
        owner_pubkey=req.owner_pubkey,
        chain_id=req.chain_id,
        metadata=req.metadata,
    )
    # Compute initial trust score (no Cortex data yet on first issue)
    scorer = _get_trust_scorer()
    result = scorer.compute_score(req.agent_id, cortex_events_count=0, last_anchor_tx="")
    engine.update_trust_score(req.agent_id, result.score, result.tier)

    # Refresh passport with updated score
    passport = engine.get_passport(req.agent_id)
    return {"passport": passport.to_dict(), "trust_score": result.to_dict()}


@router.get("/api/v1/passport/leaderboard", tags=["Agent Passport"])
async def get_passport_leaderboard(limit: int = 20, username: str = Depends(enforce_user_rate_limit)):
    """Get the top agents by trust score."""
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
async def get_passport(agent_id: str, username: str = Depends(enforce_user_rate_limit)):
    """Get an agent's passport details including trust score."""
    engine = _get_passport_engine()
    passport = engine.get_passport(agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail=f"No passport found for agent: {agent_id}")
    return {"passport": passport.to_dict()}


@router.get("/api/v1/passport/{agent_id}/score", tags=["Agent Passport"])
async def get_passport_score(agent_id: str, username: str = Depends(enforce_user_rate_limit)):
    """Get an agent's current trust score with full breakdown."""
    scorer = _get_trust_scorer()
    # Pull Cortex stats from passport to include transparency bonus
    engine = _get_passport_engine()
    passport = engine.get_passport(agent_id)
    cortex_count = passport.cortex_events_count if passport else 0
    anchor_tx = passport.last_anchor_tx if passport else ""
    result = scorer.compute_score(
        agent_id,
        cortex_events_count=cortex_count,
        last_anchor_tx=anchor_tx,
    )

    # Update stored score
    engine.update_trust_score(agent_id, result.score, result.tier)

    return {"agent_id": agent_id, "trust_score": result.to_dict()}


@router.get("/api/v1/passport/{agent_id}/credentials", tags=["Agent Passport"])
async def get_passport_credentials(agent_id: str, username: str = Depends(enforce_user_rate_limit)):
    """List an agent's verifiable credentials."""
    engine = _get_passport_engine()
    passport = engine.get_passport(agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail=f"No passport found for agent: {agent_id}")
    return {"agent_id": agent_id, "credentials": passport.credentials}


@router.post("/api/v1/passport/{agent_id}/credentials/issue", tags=["Agent Passport"])
async def issue_credential(agent_id: str, req: CredentialIssueRequest, username: str = Depends(enforce_admin_rate_limit)):
    """Issue a verifiable credential for an agent (admin only)."""
    from guardian.passport.credentials import CredentialType

    engine = _get_passport_engine()
    passport = engine.get_passport(agent_id)
    if passport is None:
        raise HTTPException(status_code=404, detail=f"No passport found for agent: {agent_id}")
    if not passport.is_active:
        raise HTTPException(status_code=404, detail=f"Passport for agent '{agent_id}' has been revoked")

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
async def verify_passport(req: PassportVerifyRequest, username: str = Depends(enforce_user_rate_limit)):
    """Verify an agent's passport and trust status."""
    verifier = _get_passport_verifier()

    if req.requesting_agent_id:
        result = verifier.cross_verify(req.requesting_agent_id, req.agent_id)
        return {"verification": result}
    else:
        result = verifier.verify_passport(req.agent_id)
        return {"verification": result.to_dict()}


@router.post("/api/v1/passport/{agent_id}/revoke", tags=["Agent Passport"])
async def revoke_passport(agent_id: str, username: str = Depends(enforce_admin_rate_limit)):
    """Revoke an agent's passport (admin only)."""
    engine = _get_passport_engine()
    revoked = engine.revoke_passport(agent_id)
    if not revoked:
        raise HTTPException(status_code=404, detail=f"No active passport found for agent: {agent_id}")
    return {"revoked": True, "agent_id": agent_id}


