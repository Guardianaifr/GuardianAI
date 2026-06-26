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

@router.post("/api/v1/contract/analyze", tags=["Smart Contract Analyzer"])
def analyze_smart_contract(req: ContractAnalyzeRequest, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """
    Static analysis of a Solidity or Vyper smart contract source.
    Detects 15+ vulnerability classes: reentrancy, front-running, integer
    overflow, access control flaws, oracle manipulation, and more.
    Returns a scored, graded report with compliance mappings.
    """
    if not req.source_code or len(req.source_code.strip()) < 10:
        raise HTTPException(status_code=400, detail="source_code must be non-empty.")
    if len(req.source_code) > 500_000:
        raise HTTPException(status_code=413, detail="Source code exceeds 500 KB limit.")
    try:
        from guardian.audit.smart_contract_analyzer import SmartContractAnalyzer
        from dataclasses import asdict
        analyzer = SmartContractAnalyzer(
            source_code=req.source_code,
            contract_name=req.contract_name,
            contract_address=req.contract_address,
            chain=req.chain,
        )
        result = analyzer.analyze()
        return asdict(result)
    except Exception as exc:
        logger.exception("Smart contract analysis failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/api/v1/contract/analyze/onchain", tags=["Smart Contract Analyzer"])
def analyze_smart_contract_onchain(req: ContractOnChainAnalyzeRequest, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """
    Fetch verified on-chain source from explorer/Sourcify and run static analysis.
    Supports EVM chains (Ethereum, BSC, Monad, etc.).
    """
    if not req.contract_address or len(req.contract_address.strip()) < 10:
        raise HTTPException(status_code=400, detail="contract_address must be non-empty.")

    try:
        from guardian.audit.smart_contract_analyzer import SmartContractAnalyzer
        from dataclasses import asdict

        resolved_api_key = (req.api_key or ETHERSCAN_API_KEY or "").strip() or None
        analyzer = SmartContractAnalyzer.from_onchain(
            contract_address=req.contract_address,
            chain=req.chain,
            api_key=resolved_api_key,
        )
        result = analyzer.analyze()
        return asdict(result)
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:
        logger.exception("On-chain smart contract analysis failed: %s", exc)
        raise HTTPException(status_code=500, detail=str(exc))


@router.get("/api/v1/contract/chains", tags=["Smart Contract Analyzer"])
def list_supported_chains(principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Return the list of chains supported by the smart contract analyzer."""
    from guardian.audit.smart_contract_analyzer import Chain
    return {
        "chains": [
            {"id": c.value, "name": c.name.title()}
            for c in Chain
            if c != Chain.UNKNOWN
        ]
    }


@router.get("/api/v1/contract/rules", tags=["Smart Contract Analyzer"])
def list_contract_rules(principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Return all vulnerability rules used by the static analyzer."""
    from guardian.audit.smart_contract_analyzer import VULN_RULES
    return {
        "total": len(VULN_RULES),
        "rules": [
            {
                "id": r.id,
                "name": r.name,
                "category": r.category,
                "severity": r.severity.value,
                "language": r.language.value if r.language else "all",
                "description": r.description,
            }
            for r in VULN_RULES
        ],
    }


