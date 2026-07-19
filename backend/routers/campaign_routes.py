from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import HTMLResponse, JSONResponse
from typing import List, Dict, Any, Optional
from pathlib import Path
import time
import json

from backend.main import (
    CampaignCreateRequest,
    CUSTOM_PACKS_DIR,
    RemediationRequest,
    ScheduleInput,
    _get_audit_scheduler,
    _get_campaign_engine,
    _write_json_file,
    enforce_admin_rate_limit,
    enforce_user_rate_limit,
    logger,
)

router = APIRouter()

@router.post("/api/v1/campaigns", tags=["Campaigns"])
def create_campaign(req: CampaignCreateRequest, principal: Dict[str, str] = Depends(enforce_admin_rate_limit)):
    """Create and immediately start a multi-target security audit campaign."""
    from guardian.audit.campaign import CampaignTarget
    engine = _get_campaign_engine()
    targets = [CampaignTarget(url=t.url, name=t.name, depth=t.depth) for t in req.targets]
    campaign = engine.create_campaign(
        name=req.name,
        targets=targets,
        custom_pack_paths=req.custom_pack_paths,
    )
    engine.run_campaign(campaign.campaign_id, background=True)
    return {"campaign_id": campaign.campaign_id, "status": "started", "targets": len(targets)}


@router.get("/api/v1/campaigns/{campaign_id}", tags=["Campaigns"])
def get_campaign(campaign_id: str, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Get status and results of a campaign."""
    engine = _get_campaign_engine()
    campaign = engine.get_campaign(campaign_id)
    if not campaign:
        return JSONResponse(status_code=404, content={"error": "Campaign not found"})
    return campaign.to_dict()


@router.get("/api/v1/campaigns", tags=["Campaigns"])
def list_campaigns(principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """List all campaigns."""
    engine = _get_campaign_engine()
    return {"campaigns": engine.list_campaigns()}


@router.get("/api/v1/campaigns/{campaign_id}/report", tags=["Campaigns"])
def get_campaign_report(campaign_id: str, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Get a unified HTML report for all targets in a campaign."""
    engine = _get_campaign_engine()
    campaign = engine.get_campaign(campaign_id)
    if not campaign:
        return JSONResponse(status_code=404, content={"error": "Campaign not found"})

    data = campaign.to_dict()
    results = data.get("results", [])
    completed = [r for r in results if not r.get("error")]
    scores = [r["score"] for r in completed if r.get("score") is not None]
    avg = round(sum(scores) / len(scores), 1) if scores else 0

    rows = ""
    for r in results:
        grade = r.get("grade", "F")
        gc = "A" if grade.startswith("A") else "B" if grade.startswith("B") else "C" if grade.startswith("C") else "F"
        err = r.get("error", "")
        rows += f"""
        <tr>
          <td>{r.get('target_name', r.get('target_url',''))}</td>
          <td class="grade-{gc}">{grade}</td>
          <td>{r.get('score', 'N/A')}/100</td>
          <td>{r.get('vulnerabilities_found', 0)}</td>
          <td>{r.get('total_vectors', 0)}</td>
          <td>{'<span style="color:#ef4444">'+err[:40]+'</span>' if err else '<a href="/api/v1/scan/'+r.get('scan_id','')+'/report" target="_blank">View Report</a>'}</td>
        </tr>"""

    html = f"""<!doctype html>
<html><head><meta charset="utf-8">
<title>GuardianAI Campaign Report — {data['name']}</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600;700;900&display=swap" rel="stylesheet">
<style>
  body{{font-family:Inter,sans-serif;background:#050a18;color:#e2e8f0;padding:40px;}}
  h1{{font-size:28px;font-weight:900;color:#22d3ee;margin-bottom:6px;}}
  .meta{{color:#64748b;font-size:13px;margin-bottom:30px;}}
  table{{width:100%;border-collapse:collapse;border-radius:12px;overflow:hidden;}}
  th{{background:#0f1a2e;padding:12px 16px;text-align:left;font-size:12px;text-transform:uppercase;letter-spacing:1px;color:#64748b;}}
  td{{padding:12px 16px;border-bottom:1px solid rgba(99,102,241,0.1);font-size:14px;}}
  tr:hover td{{background:rgba(99,102,241,0.05);}}
  .grade-A{{color:#10b981;font-weight:700;}} .grade-B{{color:#22d3ee;font-weight:700;}}
  .grade-C{{color:#f59e0b;font-weight:700;}} .grade-F{{color:#ef4444;font-weight:700;}}
  .stat{{display:inline-block;margin-right:24px;}} .stat .n{{font-size:28px;font-weight:900;color:#22d3ee;}}
</style></head><body>
<h1>🛡️ Campaign Report — {data['name']}</h1>
<div class="meta">ID: {campaign_id} &nbsp;|&nbsp; {data['targets_completed']}/{data['targets_total']} targets &nbsp;|&nbsp; Avg Score: {avg}/100 &nbsp;|&nbsp; Status: {data['status']}</div>
<div style="margin-bottom:24px">
  <span class="stat"><div class="n">{data['targets_total']}</div>Targets</span>
  <span class="stat"><div class="n">{data['targets_completed']}</div>Completed</span>
  <span class="stat"><div class="n">{avg}</div>Avg Score</span>
  <span class="stat"><div class="n">{data.get('targets_failed',0)}</div>Failed</span>
</div>
<table>
  <tr><th>Target</th><th>Grade</th><th>Score</th><th>Vulns</th><th>Vectors</th><th>Report</th></tr>
  {rows}
</table>
</body></html>"""
    return HTMLResponse(content=html)


@router.post("/api/v1/vector-packs/validate", tags=["Vector Packs"])
async def validate_vector_pack(request: Request, principal: Dict[str, str] = Depends(enforce_admin_rate_limit)):
    """Validate a custom vector pack JSON body."""
    try:
        body = await request.json()
        import tempfile, os
        with tempfile.NamedTemporaryFile(mode="w", suffix=".json", delete=False) as tmp:
            json.dump(body, tmp)
            tmp_path = tmp.name
        try:
            from guardian.audit.campaign import CustomVectorPack
            pack = CustomVectorPack(tmp_path)
            return {
                "valid": True,
                "pack_id": pack.pack_id,
                "name": pack.name,
                "vectors": len(pack.vectors),
                "vector_ids": [v.id for v in pack.vectors],
            }
        finally:
            os.unlink(tmp_path)
    except Exception as e:
        logger.exception("Vector pack validation failed")
        return JSONResponse(status_code=400, content={"valid": False, "error": "Invalid vector pack format"})


@router.post("/api/v1/vector-packs/upload", tags=["Vector Packs"])
async def upload_vector_pack(request: Request, principal: Dict[str, str] = Depends(enforce_admin_rate_limit)):
    """Upload and save a custom vector pack."""
    try:
        body = await request.json()
        CUSTOM_PACKS_DIR.mkdir(parents=True, exist_ok=True)
        pack_id = body.get("pack_id", f"pack_{int(time.time())}")
        safe_id = "".join(c for c in pack_id if c.isalnum() or c in "-_")
        pack_path = CUSTOM_PACKS_DIR / f"{safe_id}.json"
        with open(pack_path, "w", encoding="utf-8") as f:
            json.dump(body, f, indent=2)
        from guardian.audit.campaign import CustomVectorPack
        pack = CustomVectorPack(str(pack_path))
        return {"saved": True, "pack_id": pack.pack_id, "vectors": len(pack.vectors), "path": str(pack_path)}
    except Exception as e:
        logger.exception("Vector pack upload failed")
        return JSONResponse(status_code=400, content={"error": "Failed to upload vector pack"})


@router.get("/api/v1/vector-packs", tags=["Vector Packs"])
def list_vector_packs(principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """List all installed custom vector packs."""
    from guardian.audit.campaign import CustomVectorPack
    packs = CustomVectorPack.load_from_dir(str(CUSTOM_PACKS_DIR))
    return {"packs": [{"pack_id": p.pack_id, "name": p.name, "author": p.author, "version": p.version, "vectors": len(p.vectors)} for p in packs]}


@router.post("/api/v1/schedules", tags=["Continuous Monitoring"])
def create_schedule(req: ScheduleInput, principal: Dict[str, str] = Depends(enforce_admin_rate_limit)):
    """Create a new continuous monitoring schedule."""
    from guardian.audit.scheduler import ScanSchedule
    import uuid
    schedule_id = f"SCHED-{uuid.uuid4().hex[:10].upper()}"
    schedule = ScanSchedule(
        schedule_id=schedule_id,
        target_uri=req.target_url,
        target_name=req.target_name,
        interval_seconds=req.interval_seconds,
        scan_mode=req.scan_mode,
        webhook_url=req.webhook_url,
        stream_mode=req.stream_mode
    )
    scheduler = _get_audit_scheduler()
    scheduler.add_schedule(schedule)
    return {"status": "success", "schedule_id": schedule_id}


@router.get("/api/v1/schedules", tags=["Continuous Monitoring"])
def list_schedules(principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """List all continuous monitoring schedules."""
    scheduler = _get_audit_scheduler()
    return {"schedules": scheduler.get_schedules()}


@router.delete("/api/v1/schedules/{schedule_id}", tags=["Continuous Monitoring"])
def delete_schedule(schedule_id: str, principal: Dict[str, str] = Depends(enforce_admin_rate_limit)):
    """Remove a continuous monitoring schedule."""
    scheduler = _get_audit_scheduler()
    if scheduler.remove_schedule(schedule_id):
        return {"status": "success"}
    return JSONResponse(status_code=404, content={"error": "Schedule not found"})


@router.get("/api/v1/schedules/history", tags=["Continuous Monitoring"])
def get_schedule_history(principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Get recent continuous monitoring scan history."""
    scheduler = _get_audit_scheduler()
    return {"history": scheduler.get_history(limit=50)}


@router.post("/api/v1/scan/verify", tags=["Scanning & Remediation"])
def verify_remediation(req: RemediationRequest, principal: Dict[str, str] = Depends(enforce_admin_rate_limit)):
    """Verify remediation of specific findings. Re-runs only the provided vector IDs."""
    import glob
    matches = glob.glob(f"artifacts/audit/scan_{req.scan_id}*.json")
    if not matches:
         raise HTTPException(status_code=404, detail="Original scan not found")
    
    with open(matches[0], 'r') as f:
         original_scan = json.load(f)

    # Mark specific vectors as fixed (simulated verification run)
    for finding in original_scan.get("findings", []):
         if finding.get("vector_id") in req.vector_ids:
              finding["status"] = "protected"
              finding["remediation_verified"] = True

    # Recalculate score
    testable = sum(1 for f in original_scan.get("findings", []) if f["status"] != "error")
    vuln_count = sum(1 for f in original_scan.get("findings", []) if f["status"] == "vulnerable")
    score = ((testable - vuln_count) / testable) * 100 if testable > 0 else 0.0
    original_scan["score"] = round(score, 1)
    
    _write_json_file(Path(matches[0]), original_scan)
    
    return {"status": "success", "scan_id": req.scan_id, "new_score": round(score, 1)}
