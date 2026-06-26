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

@router.post("/api/v1/threat-intel/screen", tags=["Threat Intelligence"])
def screen_address(req: AddressScreenRequest, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Screen a single address against GuardianAI's threat intelligence database."""
    from guardian.threat_intel.engine import get_threat_db
    from dataclasses import asdict
    db = get_threat_db()
    result = db.screen_address(req.address)
    return asdict(result)


@router.post("/api/v1/threat-intel/screen/batch", tags=["Threat Intelligence"])
def screen_batch(req: BatchScreenRequest, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Screen multiple addresses in one request."""
    from guardian.threat_intel.engine import get_threat_db
    from dataclasses import asdict
    db = get_threat_db()
    results = db.screen_batch(req.addresses)
    flagged = [r for r in results if r.flagged]
    return {
        "total_screened": len(results),
        "total_flagged": len(flagged),
        "results": [asdict(r) for r in results],
    }


@router.get("/api/v1/threat-intel/incidents", tags=["Threat Intelligence"])
def list_threat_incidents(principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """List all tracked security incidents in the threat database."""
    from guardian.threat_intel.engine import get_threat_db
    db = get_threat_db()
    return {
        "total_incidents": db.incident_count,
        "total_addresses": db.address_count,
        "incidents": db.list_incidents(),
    }


@router.get("/api/v1/threat-intel/incidents/{incident_id}", tags=["Threat Intelligence"])
def get_threat_incident(incident_id: str, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Get full details for a specific incident including all tracked addresses."""
    from guardian.threat_intel.engine import get_threat_db
    from dataclasses import asdict
    db = get_threat_db()
    incident = db.get_incident(incident_id)
    if not incident:
        raise HTTPException(status_code=404, detail="Incident not found")
    return asdict(incident)


@router.get("/api/v1/threat-intel/stats", tags=["Threat Intelligence"])
def threat_intel_stats(principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Return summary statistics for the threat intelligence database."""
    from guardian.threat_intel.engine import get_threat_db
    db = get_threat_db()
    incidents = db.list_incidents()
    total_btc = sum(i.get("total_stolen_btc", 0) for i in incidents)
    total_usd = sum(i.get("total_stolen_usd", 0) for i in incidents)
    exchanges = set()
    for i in incidents:
        exchanges.update(i.get("exit_exchanges", []))
    return {
        "total_incidents": db.incident_count,
        "total_addresses_tracked": db.address_count,
        "total_stolen_btc": round(total_btc, 4),
        "total_stolen_usd": round(total_usd, 2),
        "exit_exchanges": sorted(exchanges),
    }


@router.post("/api/v1/threat-intel/sync", tags=["Threat Intelligence"])
def sync_threat_intel_onchain(chain: Optional[str] = None, user=Depends(get_current_admin)):
    """Sync the threat intelligence high-risk address list to the on-chain registry (admin only)."""
    from guardian.security.trust_exploitation import TrustExploitationGuard
    guard = TrustExploitationGuard({"enabled": True})
    res = guard.sync_to_chain(chain_id=chain)
    if not res.get("success"):
        raise HTTPException(status_code=400, detail=res.get("error", "Failed to sync threat feed"))
    return res


