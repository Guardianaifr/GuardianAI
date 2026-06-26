"""
Report Generator for GuardianAI Audit.

Exports audit results as JSON and formatted text reports.
PDF generation available when reportlab/weasyprint are installed.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

from guardian.audit.models import (
    AuditScan,
    AuditScore,
    CategoryScore,
    Finding,
    FindingStatus,
    Severity,
)

EVIDENCE_SIGNING_KEY = os.getenv("GUARDIAN_EVIDENCE_SIGNING_KEY", "guardian-audit-default-key")


def _sign_evidence(data: str) -> str:
    """HMAC-SHA256 seal for tamper-proof evidence."""
    return hmac.new(
        EVIDENCE_SIGNING_KEY.encode("utf-8"),
        data.encode("utf-8"),
        hashlib.sha256,
    ).hexdigest()


def finding_to_dict(f: Finding) -> Dict[str, Any]:
    return {
        "vector_id": f.vector_id,
        "vector_name": f.vector_name,
        "category": f.category.value,
        "severity": f.severity.value,
        "status": f.status.value,
        "confidence": f.confidence,
        "response_time_ms": f.response_time_ms,
        "evidence_notes": f.evidence_notes,
        "remediation": f.remediation,
        "request_prompt": f.request_prompt[:500],
        "response_excerpt": f.response_text[:500],
        "timestamp": f.timestamp,
    }


def score_to_dict(score: AuditScore) -> Dict[str, Any]:
    return {
        "overall_score": score.overall_score,
        "grade": score.grade.value,
        "total_vectors": score.total_vectors,
        "total_blocked": score.total_blocked,
        "total_passed": score.total_passed,
        "total_partial": score.total_partial,
        "total_errors": score.total_errors,
        "categories": [
            {
                "category": cs.category.value,
                "score_pct": cs.score_pct,
                "weight": cs.weight,
                "total": cs.total_vectors,
                "blocked": cs.blocked,
                "passed": cs.passed,
                "partial": cs.partial,
                "critical_count": len(cs.critical_findings),
            }
            for cs in score.category_scores
        ],
    }


def scan_to_dict(scan: AuditScan) -> Dict[str, Any]:
    """Convert a full audit scan to a serializable dictionary."""
    result: Dict[str, Any] = {
        "scan_id": scan.scan_id,
        "status": scan.status,
        "mode": scan.mode.value,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "duration_sec": scan.duration_sec,
    }

    if scan.target:
        result["target"] = {
            "endpoint": scan.target.endpoint_url,
            "model": scan.target.model,
        }

    if scan.score:
        result["score"] = score_to_dict(scan.score)

    # Separate findings by status
    vulnerabilities = [f for f in scan.findings if f.status == FindingStatus.PASSED]
    partial = [f for f in scan.findings if f.status == FindingStatus.PARTIAL]
    blocked = [f for f in scan.findings if f.status == FindingStatus.BLOCKED]

    result["vulnerabilities"] = [finding_to_dict(f) for f in vulnerabilities]
    result["partial_findings"] = [finding_to_dict(f) for f in partial]
    result["blocked_count"] = len(blocked)

    # Evidence signature
    evidence_payload = json.dumps(result, sort_keys=True, separators=(",", ":"))
    result["evidence_signature"] = _sign_evidence(evidence_payload)
    result["report_generated_at"] = time.time()

    return result


def export_json(scan: AuditScan, output_path: Path) -> Path:
    """Export the full audit report as a JSON file."""
    data = scan_to_dict(scan)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        json.dump(data, fh, indent=2, ensure_ascii=False)
    return output_path


def export_text(scan: AuditScan, output_path: Path) -> Path:
    """Export a human-readable text report."""
    lines: List[str] = []

    lines.append("=" * 70)
    lines.append("  GUARDIANAI AI SECURITY AUDIT REPORT")
    lines.append("=" * 70)
    lines.append("")

    if scan.target:
        lines.append(f"  Target:     {scan.target.endpoint_url}")
        lines.append(f"  Model:      {scan.target.model or 'N/A'}")
    lines.append(f"  Scan ID:    {scan.scan_id}")
    lines.append(f"  Mode:       {scan.mode.value}")
    lines.append(f"  Date:       {time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan.started_at))}")
    if scan.duration_sec:
        lines.append(f"  Duration:   {scan.duration_sec}s")
    lines.append("")

    if scan.score:
        s = scan.score
        lines.append("-" * 70)
        lines.append(f"  SECURITY SCORE:  {s.overall_score}/100  (Grade: {s.grade.value})")
        lines.append("-" * 70)
        lines.append("")
        lines.append(f"  Vectors Tested:  {s.total_vectors}")
        lines.append(f"  Blocked:         {s.total_blocked}")
        lines.append(f"  Vulnerabilities: {s.total_passed}")
        lines.append(f"  Partial:         {s.total_partial}")
        lines.append(f"  Errors:          {s.total_errors}")
        lines.append("")

        lines.append("-" * 70)
        lines.append("  CATEGORY BREAKDOWN")
        lines.append("-" * 70)
        for cs in sorted(scan.score.category_scores, key=lambda x: x.score_pct):
            bar_len = 25
            filled = int(bar_len * cs.score_pct / 100)
            bar = "#" * filled + "." * (bar_len - filled)
            flag = " !! WEAK" if cs.score_pct < 70 else ""
            lines.append(f"  {cs.category.value:<12} [{bar}] {cs.score_pct:5.1f}%{flag}")
        lines.append("")

    # Vulnerabilities detail
    vulns = [f for f in scan.findings if f.status == FindingStatus.PASSED]
    if vulns:
        lines.append("=" * 70)
        lines.append(f"  VULNERABILITIES FOUND ({len(vulns)})")
        lines.append("=" * 70)
        for i, v in enumerate(sorted(vulns, key=lambda x: x.severity.value), 1):
            lines.append("")
            lines.append(f"  [{v.severity.value}] #{i}: {v.vector_name}")
            lines.append(f"  Category:    {v.category.value}")
            lines.append(f"  Vector ID:   {v.vector_id}")
            lines.append(f"  Confidence:  {v.confidence:.0%}")
            lines.append(f"  Latency:     {v.response_time_ms:.0f}ms")
            if v.evidence_notes:
                lines.append(f"  Evidence:    {v.evidence_notes[:120]}")
            if v.remediation:
                lines.append(f"  Remediation: {v.remediation[:120]}")
            lines.append(f"  Response:    {v.response_text[:200]}...")
            lines.append("  " + "-" * 40)

    # Partial findings
    partials = [f for f in scan.findings if f.status == FindingStatus.PARTIAL]
    if partials:
        lines.append("")
        lines.append(f"  PARTIAL / AMBIGUOUS ({len(partials)})")
        lines.append("  " + "-" * 40)
        for p in partials:
            lines.append(f"  [{p.severity.value}] {p.vector_name} — {p.evidence_notes[:80]}")

    lines.append("")
    lines.append("=" * 70)

    # Evidence signature
    raw = "\n".join(lines)
    sig = _sign_evidence(raw)
    lines.append(f"  Evidence Signature: {sig}")
    lines.append("  This report is cryptographically sealed by GuardianAI.")
    lines.append("=" * 70)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines))
    return output_path
