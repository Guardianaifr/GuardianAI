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

@router.get("/api/v1/audits", tags=["Audits"])
def get_audits():
    audits = []
    audit_dir = AUDIT_ARTIFACTS_DIR
    if audit_dir.exists():
        for badge_file in audit_dir.glob("badge_*.json"):
            try:
                with open(badge_file, "r", encoding="utf-8") as f:
                    badge_data = json.load(f)
                    badge_id = badge_file.stem.replace("badge_", "")
                    payload = badge_data.get("payload", {})
                    audits.append({
                        "id": badge_id,
                        "target": payload.get("target", ""),
                        "score": payload.get("score", 0),
                        "grade": payload.get("grade", ""),
                        "mode": payload.get("scan_mode", ""),
                        "issued_at": payload.get("issued_at", "")
                    })
            except Exception:
                pass
        audits.sort(key=lambda x: x["issued_at"], reverse=True)
    return {"audits": audits}


@router.get("/api/v1/audits/{badge_id}/svg", tags=["Audits"])
def get_audit_badge_svg(badge_id: str):
    svg_path = AUDIT_ARTIFACTS_DIR / f"badge_{badge_id}.svg"
    if not svg_path.exists():
        raise HTTPException(status_code=404, detail="Badge not found")
    with open(svg_path, "r", encoding="utf-8") as f:
        svg_content = f.read()
    return HTMLResponse(content=svg_content, media_type="image/svg+xml")


@router.post("/api/v1/verify-badge", tags=["Audits"])
def verify_audit_badge(request: BadgeVerificationRequest):
    from guardian.audit.certification import CertificationEngine
    badge_key = os.getenv("GUARDIAN_BADGE_SECRET_KEY", "dev_secret_key")
    if badge_key == "dev_secret_key" and os.getenv("GUARDIAN_ENV", "development").strip().lower() == "production":
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="CRITICAL SECURITY ERROR: GUARDIAN_BADGE_SECRET_KEY is default key in production mode!"
        )
    cert_engine = CertificationEngine(signing_key=badge_key)
    
    is_valid = cert_engine.verify_badge(request.badge_data)
    
    if is_valid:
        return {"status": "valid", "message": "Badge signature is valid and authentic."}
    else:
        raise HTTPException(status_code=400, detail="Invalid badge signature. Badge may be forged or tampered with.")


