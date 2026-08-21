from fastapi import APIRouter, Depends, HTTPException, status, Request, Query
from fastapi.responses import HTMLResponse, JSONResponse
from typing import List, Dict, Any, Optional
import time
import json
import os
import re

from backend.main import (
    AUDIT_ARTIFACTS_DIR,
    ScanRequest,
    _get_scan_job,
    _load_crypto_badge,
    _load_crypto_scan_json,
    _persist_crypto_scan_artifacts,
    _render_crypto_scan_report_html,
    _scan_jobs,
    _scan_jobs_lock,
    _scan_results_cache,
    _start_scan_job,
    enforce_user_rate_limit,
    logger,
)

router = APIRouter()

SAFE_SCAN_ID = re.compile(r'^[a-zA-Z0-9_-]+$')
def validate_scan_id(scan_id: str) -> str:
    if not SAFE_SCAN_ID.match(scan_id):
        raise HTTPException(status_code=400, 
            detail="Invalid scan_id format")
    if any(c in scan_id for c in ['..', '/', '\\', '\x00']):
        raise HTTPException(status_code=400,
            detail="Invalid scan_id format")
    return scan_id

def validate_scan_target(url: str) -> str:
    from backend.security.url_validation import is_safe_url
    if not is_safe_url(url):
        raise HTTPException(
            status_code=400,
            detail="Access to private/local/invalid target URLs is blocked."
        )
    return url

@router.post("/api/v1/scan-jobs", tags=["Audit Scanner"])
def create_crypto_scan_job(req: ScanRequest, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Queue a background security scan and return a live job handle."""
    validate_scan_target(req.target_url)
    return _start_scan_job(req)


@router.get("/api/v1/scan-jobs", tags=["Audit Scanner"])
def list_crypto_scan_jobs(limit: int = Query(default=20, le=100), principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    with _scan_jobs_lock:
        jobs = sorted(_scan_jobs.values(), key=lambda item: item.get("created_at", 0), reverse=True)
    trimmed = jobs[: max(1, min(limit, 100))]
    return {
        "jobs": [
            {
                "job_id": job["job_id"],
                "status": job["status"],
                "target_url": job["target_url"],
                "target_name": job["target_name"],
                "depth": job["depth"],
                "created_at": job["created_at"],
                "completed_at": job["completed_at"],
                "progress_pct": job["progress_pct"],
                "result": {
                    "scan_id": job["result"]["scan_id"],
                    "grade": job["result"]["grade"],
                    "score": job["result"]["score"],
                } if job.get("result") else None,
            }
            for job in trimmed
        ]
    }


@router.get("/api/v1/scan-jobs/{job_id}", tags=["Audit Scanner"])
def get_crypto_scan_job(job_id: str, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Fetch live scan-job status, logs, and final result when ready."""
    return _get_scan_job(job_id)


@router.post("/api/v1/scan", tags=["Audit Scanner"])
def run_crypto_scan(req: ScanRequest, request: Request, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Run an automated 6-pillar security scan against any AI+Web3 target."""
    validate_scan_target(req.target_url)
    from guardian.audit.crypto_scanner import CryptoAuditScanner, ScanDepth

    depth_map = {"quick": ScanDepth.QUICK, "standard": ScanDepth.STANDARD, "deep": ScanDepth.DEEP}
    depth = depth_map.get(req.depth, ScanDepth.STANDARD)

    try:
        scanner = CryptoAuditScanner(
            target_url=req.target_url,
            target_name=req.target_name or None,
            depth=depth,
        )
        result = scanner.run_scan()
        scan_payload = _persist_crypto_scan_artifacts(result)
        _scan_results_cache[result.scan_id] = scan_payload
        return scan_payload
    except Exception as e:
        logger.exception("Scan failed")
        return JSONResponse(status_code=500, content={"error": "Internal scan error"})


@router.get("/api/v1/scan/{scan_id}/report", tags=["Audit Scanner"])
def get_scan_report(scan_id: str, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Get the HTML report for a completed scan."""
    validate_scan_id(scan_id)
    report_path = AUDIT_ARTIFACTS_DIR / f"report_{scan_id}.html"
    if report_path.exists():
        return HTMLResponse(content=report_path.read_text(encoding="utf-8"))

    scan_data = _load_crypto_scan_json(scan_id)
    badge_data = scan_data.get("badge") or _load_crypto_badge(scan_id)
    report_html = _render_crypto_scan_report_html(scan_data, badge_data=badge_data)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(report_html, encoding="utf-8")
    return HTMLResponse(content=report_html)


@router.get("/api/v1/scan/{scan_id}/pdf", tags=["Audit Scanner"])
def get_scan_report_pdf(scan_id: str, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Download the audit report as a PDF file."""
    validate_scan_id(scan_id)
    import subprocess
    import tempfile

    # First ensure the HTML report exists
    report_path = AUDIT_ARTIFACTS_DIR / f"report_{scan_id}.html"
    if not report_path.exists():
        scan_data = _load_crypto_scan_json(scan_id)
        badge_data = scan_data.get("badge") or _load_crypto_badge(scan_id)
        report_html = _render_crypto_scan_report_html(scan_data, badge_data=badge_data)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(report_html, encoding="utf-8")

    pdf_path = AUDIT_ARTIFACTS_DIR / f"report_{scan_id}.pdf"

    if not pdf_path.exists():
        # Try headless Chrome/Edge PDF generation
        report_url = f"file:///{report_path.resolve().as_posix()}"
        chrome_paths = [
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
        ]
        chrome_bin = None
        for p in chrome_paths:
            if os.path.exists(p):
                chrome_bin = p
                break

        if chrome_bin:
            try:
                subprocess.run([
                    chrome_bin,
                    "--headless", "--disable-gpu",
                    f"--print-to-pdf={pdf_path.resolve()}",
                    "--print-to-pdf-no-header",
                    report_url,
                ], timeout=30, capture_output=True)
            except Exception as exc:
                logger.warning("Chrome PDF generation failed: %s", exc)

    if pdf_path.exists():
        from starlette.responses import FileResponse
        return FileResponse(
            path=str(pdf_path),
            filename=f"GuardianAI_Audit_{scan_id}.pdf",
            media_type="application/pdf",
        )

    # Fallback: serve HTML with print hint
    return HTMLResponse(
        content=report_path.read_text(encoding="utf-8"),
        headers={"Content-Disposition": f"attachment; filename=GuardianAI_Audit_{scan_id}.html"},
    )


@router.get("/api/v1/scan-history", tags=["Audit Scanner"])
def get_scan_history(target_url: str = "", limit: int = 20, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Get scan history for trend analysis. Optionally filter by target URL."""
    import glob

    all_scans = []
    for scan_file in sorted(AUDIT_ARTIFACTS_DIR.glob("scan_SCAN-*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            with scan_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            if target_url and data.get("target_url", "").rstrip("/") != target_url.rstrip("/"):
                continue
            all_scans.append({
                "scan_id": data.get("scan_id"),
                "target_url": data.get("target_url"),
                "target_name": data.get("target_name"),
                "grade": data.get("grade"),
                "score": data.get("score"),
                "vulnerabilities_found": data.get("vulnerabilities_found"),
                "protected_count": data.get("protected_count"),
                "total_vectors": data.get("total_vectors"),
                "scan_depth": data.get("scan_depth"),
                "started_at": data.get("started_at"),
                "duration_seconds": data.get("duration_seconds"),
                "pillar_scores": data.get("pillar_scores", {}),
            })
            if len(all_scans) >= limit:
                break
        except Exception:
            continue

    # Calculate trend data if we have multiple scans for same target
    trend = None
    if target_url and len(all_scans) >= 2:
        scores = [s["score"] for s in all_scans if s.get("score") is not None]
        if len(scores) >= 2:
            trend = {
                "current_score": scores[0],
                "previous_score": scores[1],
                "change": round(scores[0] - scores[1], 1),
                "direction": "up" if scores[0] > scores[1] else "down" if scores[0] < scores[1] else "stable",
                "scan_count": len(all_scans),
                "best_score": max(scores),
                "worst_score": min(scores),
                "avg_score": round(sum(scores) / len(scores), 1),
            }

    return {"scans": all_scans, "trend": trend, "total": len(all_scans)}


@router.get("/api/v1/leaderboard", tags=["Audit Scanner"])
def get_leaderboard(limit: int = 50, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Public leaderboard of all audited projects, ranked by score."""
    all_scans = []
    seen_targets = set()

    for scan_file in sorted(AUDIT_ARTIFACTS_DIR.glob("scan_SCAN-*.json"), key=lambda p: p.stat().st_mtime, reverse=True):
        try:
            with scan_file.open("r", encoding="utf-8") as f:
                data = json.load(f)
            target_key = (data.get("target_url", "").rstrip("/") or data.get("target_name", "")).lower()
            if target_key in seen_targets:
                continue
            seen_targets.add(target_key)

            badge_exists = (AUDIT_ARTIFACTS_DIR / f"badge_{data.get('scan_id','')}.json").exists()
            
            score_val = data.get("score")
            score = float(score_val) if score_val is not None else 0.0
            
            total_vecs = data.get("total_vectors")
            total_vectors = int(total_vecs) if total_vecs is not None else 0

            all_scans.append({
                "scan_id": data.get("scan_id"),
                "target_url": data.get("target_url"),
                "target_name": data.get("target_name"),
                "grade": data.get("grade") or "N/A",
                "score": score,
                "scan_depth": data.get("scan_depth") or "standard",
                "started_at": data.get("started_at"),
                "total_vectors": total_vectors,
                "vulnerabilities_found": data.get("vulnerabilities_found") or 0,
                "has_badge": badge_exists,
                "badge_url": f"/api/v1/audits/{data.get('scan_id')}/svg" if badge_exists else None,
                "report_url": f"/api/v1/scan/{data.get('scan_id')}/report",
            })
        except Exception:
            continue

    all_scans.sort(key=lambda x: x.get("score", 0.0), reverse=True)
    top = all_scans[:limit]

    total_scans_len = len(all_scans)
    avg_score = 0.0
    if total_scans_len > 0:
        avg_score = round(sum(s.get("score", 0.0) for s in all_scans) / total_scans_len, 1)

    stats = {
        "total_audited": total_scans_len,
        "avg_score": avg_score,
        "total_vectors_tested": sum(s.get("total_vectors", 0) for s in all_scans),
        "certified_count": sum(1 for s in all_scans if s.get("has_badge")),
    }

    return {"projects": top, "stats": stats}


@router.get("/api/v1/scan/{scan_id}/sarif", tags=["Audit Scanner"])
def get_scan_sarif(scan_id: str, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Download scan results in SARIF 2.1.0 format (GitHub Security tab compatible)."""
    validate_scan_id(scan_id)
    from guardian.audit.sarif_exporter import generate_sarif_string
    scan_data = _load_crypto_scan_json(scan_id)
    sarif = generate_sarif_string(scan_data)
    from starlette.responses import Response
    return Response(
        content=sarif,
        media_type="application/sarif+json",
        headers={"Content-Disposition": f"attachment; filename=guardianai_{scan_id}.sarif"},
    )


@router.get("/api/v1/scan/history", tags=["Audit Scanner"])
def get_scan_history(limit: int = 50, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Return scan history from the scheduler and in-memory cache."""
    history = []

    # 1. In-memory cache of recent scans
    for scan_id, payload in list(_scan_results_cache.items()):
        entry = {
            "scan_id": scan_id,
            "target_url": payload.get("target_url", ""),
            "target_name": payload.get("target_name", ""),
            "score": payload.get("score"),
            "grade": payload.get("grade", "N/A"),
            "block_rate": payload.get("block_rate"),
            "total_vectors": payload.get("total_vectors", 0),
            "blocked_count": payload.get("blocked_count", 0),
            "timestamp": payload.get("timestamp") or payload.get("started_at", ""),
            "depth": payload.get("depth", "standard"),
        }
        history.append(entry)

    # 2. Load persisted history from scheduler artifacts
    history_file = AUDIT_ARTIFACTS_DIR / "scan_history.json"
    if history_file.exists():
        try:
            import json as _json
            stored = _json.loads(history_file.read_text(encoding="utf-8"))
            for entry in stored:
                sid = entry.get("schedule_id", "")
                if not any(h.get("scan_id") == sid for h in history):
                    history.append({
                        "scan_id": sid,
                        "target_url": entry.get("target_uri", ""),
                        "target_name": sid,
                        "score": entry.get("score"),
                        "grade": entry.get("grade", "N/A"),
                        "block_rate": entry.get("block_rate"),
                        "total_vectors": entry.get("total_vectors", 0),
                        "blocked_count": entry.get("blocked_count", 0),
                        "timestamp": entry.get("timestamp", ""),
                        "depth": "standard",
                    })
        except Exception:
            pass

    # Sort by timestamp descending and limit
    history.sort(key=lambda x: x.get("timestamp", ""), reverse=True)
    return {"history": history[:max(1, min(limit, 200))], "total": len(history)}


@router.get("/api/v1/scan/compare", tags=["Audit Scanner"])
def compare_scans(id1: str, id2: str, principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Compare two scan results side-by-side for regression tracking."""
    def _load_scan(scan_id: str) -> dict:
        # Try in-memory cache first
        if scan_id in _scan_results_cache:
            return _scan_results_cache[scan_id]
        # Try loading from persisted JSON via the glob helper
        try:
            return _load_crypto_scan_json(scan_id)
        except Exception:
            return None

    scan_a = _load_scan(id1)
    scan_b = _load_scan(id2)

    if not scan_a:
        return JSONResponse(status_code=404, content={"error": f"Scan {id1} not found"})
    if not scan_b:
        return JSONResponse(status_code=404, content={"error": f"Scan {id2} not found"})

    def _summarize(s):
        return {
            "scan_id": s.get("scan_id", ""),
            "target_name": s.get("target_name", ""),
            "score": s.get("score"),
            "grade": s.get("grade"),
            "block_rate": s.get("block_rate"),
            "total_vectors": s.get("total_vectors", 0),
            "blocked_count": s.get("blocked_count", 0),
            "timestamp": s.get("timestamp") or s.get("started_at", ""),
            "findings_count": len(s.get("findings", [])),
        }

    summary_a = _summarize(scan_a)
    summary_b = _summarize(scan_b)

    score_a = summary_a.get("score") or 0
    score_b = summary_b.get("score") or 0
    delta = round(score_b - score_a, 1)

    # Calculate detailed findings comparison
    findings_a = {f.get("vector_id") or f.get("id"): f for f in scan_a.get("findings", []) if f.get("vector_id") or f.get("id")}
    findings_b = {f.get("vector_id") or f.get("id"): f for f in scan_b.get("findings", []) if f.get("vector_id") or f.get("id")}

    regressions = []
    improvements = []
    common_vulns = []

    for vid, fa in findings_a.items():
        fb = findings_b.get(vid)
        status_a = fa.get("status") or fa.get("finding_status") or ""
        is_vuln_a = str(status_a).lower() in {"vulnerable", "failed"}
        
        if fb:
            status_b = fb.get("status") or fb.get("finding_status") or ""
            is_vuln_b = str(status_b).lower() in {"vulnerable", "failed"}
            item = {
                "vector_id": vid,
                "name": fa.get("name") or fb.get("name") or vid,
                "pillar": fa.get("pillar") or fa.get("category", "") or "General",
                "status_a": status_a,
                "status_b": status_b
            }
            if is_vuln_a and is_vuln_b:
                common_vulns.append(item)
            elif is_vuln_a and not is_vuln_b:
                improvements.append(item)
            elif not is_vuln_a and is_vuln_b:
                regressions.append(item)
        else:
            if is_vuln_a:
                improvements.append({
                    "vector_id": vid,
                    "name": fa.get("name") or vid,
                    "pillar": fa.get("pillar") or fa.get("category", "") or "General",
                    "status_a": status_a,
                    "status_b": "N/A (Skipped)"
                })

    for vid, fb in findings_b.items():
        if vid not in findings_a:
            status_b = fb.get("status") or fb.get("finding_status") or ""
            is_vuln_b = str(status_b).lower() in {"vulnerable", "failed"}
            if is_vuln_b:
                regressions.append({
                    "vector_id": vid,
                    "name": fb.get("name") or vid,
                    "pillar": fb.get("pillar") or fb.get("category", "") or "General",
                    "status_a": "N/A (Skipped)",
                    "status_b": status_b
                })

    return {
        "scan_a": summary_a,
        "scan_b": summary_b,
        "delta": {
            "score": delta,
            "regression": delta < 0,
            "grade_change": f"{summary_a.get('grade', '?')} \u2192 {summary_b.get('grade', '?')}",
        },
        "comparison": {
            "regressions": regressions,
            "improvements": improvements,
            "common_vulnerabilities": common_vulns,
            "regressions_count": len(regressions),
            "improvements_count": len(improvements),
            "common_count": len(common_vulns)
        }
    }
