from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import StreamingResponse
from typing import List, Dict, Any
import json
import sqlite3
import csv
import datetime
import io

from backend.main import (
    DB_PATH,
    SecurityEventResponse,
    get_current_principal,
    _enforce_rate_limit,
    _get_user_rate_limit,
)
from backend.security.authorization import can_access_tenant

router = APIRouter()

@router.get("/api/v1/export/json", response_model=List[SecurityEventResponse])
async def export_json(principal: Dict[str, Any] = Depends(get_current_principal)):
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    role = principal.get("role", "user")
    user_tenant = principal.get("org_id", "default")
    is_global = role == "admin" or (role == "auditor" and user_tenant == "org_guardian")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if is_global:
        cur.execute("SELECT id, guardian_id, tenant_id, event_type, severity, details, timestamp FROM security_events ORDER BY timestamp DESC")
    else:
        cur.execute("SELECT id, guardian_id, tenant_id, event_type, severity, details, timestamp FROM security_events WHERE tenant_id = ? ORDER BY timestamp DESC", (user_tenant,))
    rows = cur.fetchall()
    conn.close()
    
    data = [
        {
            "id": r[0], "guardian_id": r[1], "tenant_id": r[2], "event_type": r[3], 
            "severity": r[4], "details": json.loads(r[5]) if isinstance(r[5], str) and r[5] else {}, "timestamp": r[6]
        } for r in rows
    ]
    return data


@router.get("/api/v1/export/csv")
async def export_csv(principal: Dict[str, Any] = Depends(get_current_principal)):
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    role = principal.get("role", "user")
    user_tenant = principal.get("org_id", "default")
    is_global = role == "admin" or (role == "auditor" and user_tenant == "org_guardian")

    conn = sqlite3.connect(DB_PATH)
    cur = conn.cursor()
    if is_global:
        cur.execute("SELECT id, guardian_id, tenant_id, event_type, severity, details, timestamp FROM security_events ORDER BY timestamp DESC")
    else:
        cur.execute("SELECT id, guardian_id, tenant_id, event_type, severity, details, timestamp FROM security_events WHERE tenant_id = ? ORDER BY timestamp DESC", (user_tenant,))
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
async def get_events(tenant_id: str | None = None, limit: int = 50, principal: Dict[str, Any] = Depends(get_current_principal)):
    username = principal["username"]
    _enforce_rate_limit(f"user:{username}", _get_user_rate_limit(username))
    role = principal.get("role", "user")
    user_tenant = principal.get("org_id", "default")
    is_global = role == "admin" or (role == "auditor" and user_tenant == "org_guardian")

    if tenant_id:
        if not can_access_tenant(principal, tenant_id):
            raise HTTPException(status_code=403, detail="Forbidden: You do not have access to this tenant's data.")
    else:
        if not is_global:
            tenant_id = user_tenant

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
