from fastapi import APIRouter, Depends, HTTPException, status, Request, Body
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
import time

from backend.main import (
    _get_cortex_engine,
    _get_insurance_generator,
    _get_interlock_protocol,
    _get_merkle_anchor,
    _get_passport_engine,
    _get_risk_scorer,
    get_current_principal,
    _enforce_rate_limit,
    _get_user_rate_limit,
    logger,
)
from backend.security.authorization import can_access_agent

router = APIRouter()

def check_agent_access(principal: Dict[str, Any], agent_id: str):
    role = principal.get("role", "user")
    user_tenant = principal.get("org_id", "default")
    is_global = role == "admin" or (role == "auditor" and user_tenant == "org_guardian")
    if is_global:
        return
        
    engine = _get_passport_engine()
    passport = engine.get_passport(agent_id)
    if passport is None:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: Agent must be registered with a passport for your tenant."
        )
    if not can_access_agent(principal, passport.tenant_id):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Forbidden: You do not have access to this agent's cortex events."
        )

@router.post("/api/v1/cortex/record", tags=["Guardian Cortex"])
def cortex_record_event(body: Dict[str, Any] = Body(...), principal: Dict[str, Any] = Depends(get_current_principal)):
    """Record a decision event in the agent's Cortex memory."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    agent_id = body.get("agent_id", "")
    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    check_agent_access(principal, agent_id)

    engine = _get_cortex_engine()
    event = engine.record_event(
        agent_id=agent_id,
        event_type=body.get("event_type", "decision"),
        action=body.get("action", ""),
        category=body.get("category", ""),
        input_text=body.get("input_text", ""),
        output_text=body.get("output_text", ""),
        reasoning=body.get("reasoning", ""),
        confidence=float(body.get("confidence", 0.0)),
        context=body.get("context", ""),
        parent_event_id=body.get("parent_event_id", ""),
        metadata=body.get("metadata"),
    )

    if event is None:
        raise HTTPException(status_code=403, detail="Cortex trial expired for this agent. Upgrade to continue recording.")

    return {"event": event.to_dict(), "trial": engine.check_trial(agent_id)}


@router.get("/api/v1/cortex/{agent_id}/events", tags=["Guardian Cortex"])
def cortex_get_events(agent_id: str, event_type: str = None, limit: int = 100, principal: Dict[str, Any] = Depends(get_current_principal)):
    """List Cortex events for an agent with optional filters."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    check_agent_access(principal, agent_id)

    engine = _get_cortex_engine()
    events = engine.get_events(agent_id=agent_id, event_type=event_type, limit=min(limit, 500))
    return {
        "agent_id": agent_id,
        "events": [e.to_dict() for e in events],
        "total": engine.get_event_count(agent_id),
        "trial": engine.check_trial(agent_id),
    }


@router.get("/api/v1/cortex/{agent_id}/replay", tags=["Guardian Cortex"])
def cortex_replay(agent_id: str, timestamp: float = None, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Time-travel replay — reconstruct agent state at a specific timestamp."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    check_agent_access(principal, agent_id)

    engine = _get_cortex_engine()
    ts = timestamp if timestamp else time.time()
    snapshot = engine.replay_at(agent_id=agent_id, timestamp=ts)
    return {"replay": snapshot}


@router.get("/api/v1/cortex/{agent_id}/chain/{event_id}", tags=["Guardian Cortex"])
def cortex_event_chain(agent_id: str, event_id: str, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Get the full decision chain for an event (parent traversal)."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    check_agent_access(principal, agent_id)

    engine = _get_cortex_engine()
    chain = engine.get_event_chain(event_id=event_id)
    return {
        "agent_id": agent_id,
        "event_id": event_id,
        "chain": [e.to_dict() for e in chain],
        "chain_length": len(chain),
    }


@router.post("/api/v1/cortex/anchor", tags=["Guardian Cortex"])
def cortex_anchor(body: Dict[str, Any] = Body(...), principal: Dict[str, Any] = Depends(get_current_principal)):
    """Trigger Merkle anchor — batch unanchored events and commit root on-chain."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privilege required")

    agent_id = body.get("agent_id", "")
    chain_id = body.get("chain_id", "monad")

    if not agent_id:
        raise HTTPException(status_code=400, detail="agent_id is required")

    check_agent_access(principal, agent_id)

    engine = _get_cortex_engine()
    anchor = _get_merkle_anchor()

    events = engine.get_unanchored_events(agent_id)
    if not events:
        return {"message": "No unanchored events to commit", "agent_id": agent_id}

    leaves = [e.merkle_leaf for e in events]
    tree, proofs = anchor.build_batch(leaves)

    result = anchor.anchor_to_chain(
        merkle_root=tree.root,
        event_count=len(events),
        agent_id=agent_id,
        chain_id=chain_id,
    )

    if result.success:
        event_ids = [e.event_id for e in events]
        engine.mark_events_anchored(agent_id, event_ids, result.tx_hash)
        engine.save_anchor(
            agent_id=agent_id,
            merkle_root=tree.root,
            event_count=len(events),
            period_start=events[0].timestamp,
            period_end=events[-1].timestamp,
            chain_id=chain_id,
            tx_hash=result.tx_hash,
        )
        try:
            _get_passport_engine().update_cortex_status(
                agent_id=agent_id,
                cortex_events_count=engine.get_event_count(agent_id),
                last_anchor_tx=result.tx_hash,
            )
        except Exception as exc:
            logger.warning("Failed to update passport Cortex status for %s: %s", agent_id, exc)

    anchor_data = result.to_dict()
    is_simulated = anchor_data.get("simulated", True)
    return {
        "anchor": anchor_data,
        "proofs_count": len(proofs),
        "simulated": is_simulated,
        "message": (
            "Merkle root committed (simulated — on-chain pending)"
            if is_simulated
            else "Merkle root anchored on-chain"
        ),
    }


@router.get("/api/v1/cortex/{agent_id}/anchors", tags=["Guardian Cortex"])
def cortex_get_anchors(agent_id: str, principal: Dict[str, Any] = Depends(get_current_principal)):
    """List all on-chain Merkle anchors for an agent."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    check_agent_access(principal, agent_id)

    engine = _get_cortex_engine()
    anchors = engine.get_anchors(agent_id)
    # Include anchor mode for transparency
    from guardian.cortex.merkle_anchor import MerkleAnchor
    anchor_instance = MerkleAnchor()
    return {
        "agent_id": agent_id,
        "anchors": anchors,
        "total": len(anchors),
        "anchor_mode": anchor_instance.mode,
    }


@router.get("/api/v1/cortex/chains", tags=["Guardian Cortex"])
def cortex_get_chains(principal: Dict[str, Any] = Depends(get_current_principal)):
    """Return supported chains with their deployment status (live vs simulated)."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    from guardian.cortex.merkle_anchor import MerkleAnchor
    anchor = MerkleAnchor()
    return {
        "anchor_mode": anchor.mode,
        "chains": anchor.get_supported_chains(),
    }


@router.post("/api/v1/cortex/verify", tags=["Guardian Cortex"])
def cortex_verify_proof(body: Dict[str, Any] = Body(...)):
    """Verify a Merkle inclusion proof (public endpoint, no auth required)."""
    from guardian.cortex.merkle_anchor import MerkleTree as MT

    leaf = body.get("leaf", "")
    proof = body.get("proof", [])
    root = body.get("root", "")

    if not all([leaf, proof, root]):
        raise HTTPException(status_code=400, detail="leaf, proof, and root are required")

    is_valid = MT.verify_proof(leaf, proof, root)
    return {"verified": is_valid, "leaf": leaf, "root": root}


@router.post("/api/v1/cortex/interlock", tags=["Guardian Cortex"])
def cortex_create_interlock(body: Dict[str, Any] = Body(...), principal: Dict[str, Any] = Depends(get_current_principal)):
    """Create a cross-agent interlock (mutual proof of interaction)."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    agent_a = body.get("agent_a_id", "")
    agent_b = body.get("agent_b_id", "")

    if not agent_a or not agent_b:
        raise HTTPException(status_code=400, detail="agent_a_id and agent_b_id are required")

    check_agent_access(principal, agent_a)
    check_agent_access(principal, agent_b)

    protocol = _get_interlock_protocol()
    proof = protocol.create_interlock(
        agent_a_id=agent_a,
        agent_b_id=agent_b,
        interaction_type=body.get("interaction_type", "request"),
        interaction_data=body.get("interaction_data"),
    )
    return {"interlock": proof.to_dict()}


@router.get("/api/v1/cortex/{agent_id}/insurance", tags=["Guardian Cortex"])
def cortex_insurance_certificate(agent_id: str, period_days: int = 30, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Generate an insurance evidence certificate for an agent."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privilege required")

    check_agent_access(principal, agent_id)

    generator = _get_insurance_generator()
    now = time.time()
    period_start = now - (period_days * 86400)

    # Try to get trust score from passport
    trust_score = 0.0
    trust_tier = "UNVERIFIED"
    try:
        pe = _get_passport_engine()
        passport = pe.get_passport(agent_id)
        if passport:
            trust_score = passport.trust_score
            trust_tier = passport.tier
    except Exception:
        pass

    cert = generator.generate_certificate(
        agent_id=agent_id,
        period_start=period_start,
        period_end=now,
        trust_score=trust_score,
        trust_tier=trust_tier,
    )
    return {"certificate": cert.to_dict()}


@router.get("/api/v1/cortex/{agent_id}/trial", tags=["Guardian Cortex"])
def cortex_trial_status(agent_id: str, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Get the 10-day free trial status for an agent's Cortex recording."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    check_agent_access(principal, agent_id)

    engine = _get_cortex_engine()
    trial = engine.check_trial(agent_id)
    if trial.get("never_started"):
        msg = "No Cortex trial started yet. POST /start-trial to begin your 10-day free period."
    elif trial.get("is_active"):
        days = round(trial.get("days_remaining", 0), 1)
        msg = f"Trial active — {days} day(s) remaining."
    else:
        msg = "Trial expired. Existing events are readable; new recordings require an upgrade."
    return {"agent_id": agent_id, "trial": trial, "message": msg}


@router.post("/api/v1/cortex/{agent_id}/start-trial", tags=["Guardian Cortex"])
def cortex_start_trial(agent_id: str, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Start or resume the 10-day free Cortex recording trial for an agent. Idempotent."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    check_agent_access(principal, agent_id)

    engine = _get_cortex_engine()
    engine.start_trial(agent_id)
    trial = engine.check_trial(agent_id)
    days = round(trial.get("days_remaining", 10), 1)
    return {
        "agent_id": agent_id,
        "trial": trial,
        "message": f"Trial active — {days} day(s) remaining.",
    }


@router.post("/api/v1/interlock/{interlock_id}/anchor", tags=["Guardian Cortex"])
def cortex_anchor_interlock(interlock_id: str, chain: Optional[str] = None, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Anchor a specific cross-agent interlock proof on-chain (admin only)."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privilege required")

    protocol = _get_interlock_protocol()
    res = protocol.anchor_interlock(interlock_id, chain_id=chain)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Failed to anchor interlock"))
    return res


@router.get("/api/v1/insurance/{agent_id}/certificates", tags=["Guardian Cortex"])
def cortex_list_insurance_certificates(agent_id: str, principal: Dict[str, Any] = Depends(get_current_principal)):
    """List generated insurance certificates for an agent, including on-chain details."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    check_agent_access(principal, agent_id)

    generator = _get_insurance_generator()
    certs = generator.get_certificates(agent_id)
    return {"agent_id": agent_id, "certificates": [c.to_dict() for c in certs]}


@router.post("/api/v1/insurance/{certificate_id}/anchor", tags=["Guardian Cortex"])
def cortex_anchor_insurance_certificate(certificate_id: str, chain: Optional[str] = None, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Anchor a generated insurance certificate on-chain (admin only)."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privilege required")

    # Access checking for insurance certificates is based on admin role, which has global access.
    generator = _get_insurance_generator()
    res = generator.anchor_certificate(certificate_id, chain_id=chain)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Failed to anchor certificate"))
    return res


@router.get("/api/v1/risk/{chain}/{address}/attest", tags=["Audit Scanner"])
def risk_attest_onchain(chain: str, address: str, api_key: Optional[str] = None, principal: Dict[str, Any] = Depends(get_current_principal)):
    """Score a contract and attest the score/grade on-chain (admin only)."""
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin privilege required")

    scorer = _get_risk_scorer()
    try:
        score_obj = scorer.score_contract(chain, address, api_key=api_key)
        attest_res = scorer.attest_to_chain(score_obj)
        return {
            "success": True,
            "score": score_obj.score,
            "grade": score_obj.grade,
            "attestation": attest_res
        }
    except Exception as e:
        logger.exception("On-chain risk attestation failed")
        raise HTTPException(status_code=400, detail="On-chain risk attestation failed")
