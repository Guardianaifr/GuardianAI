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

@router.get("/api/v1/export/json", response_model=List[SecurityEventResponse])
async def export_json(username: str = Depends(enforce_user_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, guardian_id, tenant_id, event_type, severity, details, timestamp FROM security_events ORDER BY timestamp DESC")
    rows = cur.fetchall()
    conn.close()
    
    data = [
        {
            "id": r[0], "guardian_id": r[1], "tenant_id": r[2], "event_type": r[3], 
            "severity": r[4], "details": json.loads(r[5]), "timestamp": r[6]
        } for r in rows
    ]
    return data


@router.get("/api/v1/export/csv")
async def export_csv(username: str = Depends(enforce_user_rate_limit)):
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    cur.execute("SELECT id, guardian_id, tenant_id, event_type, severity, details, timestamp FROM security_events ORDER BY timestamp DESC")
    rows = cur.fetchall()
    conn.close()
    
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["ID", "GuardianID", "TenantID", "EventType", "Severity", "Details", "Timestamp"])
    for r in rows:
        writer.writerow([r[0], r[1], r[2], r[3], r[4], r[5], datetime.datetime.fromtimestamp(r[6]).isoformat()])
    
    output.seek(0)
    return StreamingResponse(
        io.BytesIO(output.getvalue().encode("utf-8")),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=guardianai_events.csv"}
    )


@router.get("/api/v1/events", response_model=List[SecurityEventResponse])
async def get_events(tenant_id: str | None = None, limit: int = 50, username: str = Depends(enforce_user_rate_limit)):
    limit = min(max(1, limit), 1000)
    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    select_sql = """
        SELECT id, guardian_id, tenant_id, event_type, severity, details, timestamp
        FROM security_events
    """
    if tenant_id:
        cur.execute(
            select_sql + " WHERE tenant_id = ? ORDER BY timestamp DESC LIMIT ?",
            (tenant_id, limit),
        )
    else:
        cur.execute(select_sql + " ORDER BY timestamp DESC LIMIT ?", (limit,))
    rows = cur.fetchall()
    conn.close()
    
    return [
        {
            "id": r[0],
            "guardian_id": r[1],
            "tenant_id": r[2],
            "event_type": r[3],
            "severity": r[4],
            "details": json.loads(r[5]) if isinstance(r[5], str) and r[5] else {},
            "timestamp": r[6]
        } for r in rows
    ]


