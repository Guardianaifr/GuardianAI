"""
GuardianAI — Professional HTML Report Generator for Crypto Audit Scans.
Takes a ScanResult JSON and produces a branded, print-ready HTML report.
"""
import json
import os
import hashlib
import hmac
from datetime import datetime
from typing import Dict, Any


BADGE_SECRET = os.getenv("GUARDIAN_BADGE_SECRET_KEY", "guardianai_badge_secret_2026")


def _severity_color(sev: str) -> str:
    return {"critical": "#ef4444", "high": "#f59e0b", "medium": "#3b82f6", "low": "#10b981", "info": "#94a3b8"}.get(sev, "#94a3b8")


def _status_color(status: str) -> str:
    return {"vulnerable": "#ef4444", "protected": "#10b981", "inconclusive": "#94a3b8", "error": "#64748b", "skipped": "#3b82f6"}.get(status, "#94a3b8")


def _grade_color(grade: str) -> str:
    if grade == "N/A": return "#64748b"
    if grade.startswith("A"): return "#10b981"
    if grade.startswith("B"): return "#22d3ee"
    if grade.startswith("C"): return "#f59e0b"
    return "#ef4444"


def _generate_badge_signature(scan_id: str, grade: str, score: float) -> str:
    payload = f"{scan_id}:{grade}:{score}"
    return hmac.new(BADGE_SECRET.encode(), payload.encode(), hashlib.sha256).hexdigest()[:16]


def generate_scan_report_html(scan_data: Dict[str, Any]) -> str:
    """Generate a full professional HTML report from scan result data."""

    target_name = scan_data.get("target_name", "Unknown")
    target_url = scan_data.get("target_url", "")
    scan_id = scan_data.get("scan_id", "")
    grade = scan_data.get("grade", "F")
    score = scan_data.get("score")
    score_disp = f"{score}/100" if score is not None else "N/A"
    depth = scan_data.get("scan_depth", "standard")
    duration = scan_data.get("duration_seconds", 0)
    total = scan_data.get("total_vectors", 0)
    vulns = scan_data.get("vulnerabilities_found", 0)
    protected = scan_data.get("protected_count", 0)
    findings = scan_data.get("findings", [])
    pillar_scores = scan_data.get("pillar_scores", {})
    detected_tech = scan_data.get("detected_tech", {})
    started_at = scan_data.get("started_at", "")
    badge_sig = _generate_badge_signature(scan_id, grade, score or 0.0)
    gc = _grade_color(grade)

    scan_status = scan_data.get("scan_status", "completed")
    scan_notes = scan_data.get("scan_notes", "")
    unreachable_html = ""
    if scan_status == "target_unreachable":
        unreachable_html = f"""
        <div style="background:rgba(59,130,246,0.06);border:1px solid rgba(59,130,246,0.25);border-radius:12px;padding:24px;margin-bottom:20px;text-align:center">
            <h2 style="color:#22d3ee;font-size:18px;margin-bottom:8px">&#9888;&#65039; Scan Skipped: Target Unreachable</h2>
            <p style="color:var(--text);font-size:13px;line-height:1.6">{scan_notes}</p>
            <p style="color:var(--muted);font-size:11px;margin-top:12px">GuardianAI is designed to audit interactive AI/LLM API endpoints, not standard web applications. Please ensure you provide a valid API endpoint or that your AI agent is online.</p>
        </div>
        """

    # Build findings table rows
    findings_rows = ""
    for f in findings:
        sc = _status_color(f["status"])
        sevc = _severity_color(f["severity"])
        findings_rows += f"""<tr>
            <td style="font-family:'JetBrains Mono',monospace;font-weight:600">{f['vector_id']}</td>
            <td>{f['vector_name']}</td>
            <td style="max-width:180px;overflow:hidden;text-overflow:ellipsis;white-space:nowrap">{f['pillar']}</td>
            <td><span style="color:{sevc};font-weight:700;text-transform:uppercase;font-size:11px">{f['severity']}</span></td>
            <td><span style="color:{sc};font-weight:700;text-transform:uppercase;font-size:11px">{f['status']}</span></td>
        </tr>"""

    # Build pillar bars
    pillar_bars = ""
    for pname, pdata in pillar_scores.items():
        ps = pdata.get("score", 0)
        pc = "#10b981" if ps >= 80 else "#f59e0b" if ps >= 50 else "#ef4444"
        v = pdata.get("vulnerable", 0)
        t = pdata.get("total", 0)
        pillar_bars += f"""<div style="margin:10px 0">
            <div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:4px">
                <span style="font-weight:600">{pname}</span>
                <span style="color:{pc};font-weight:700">{ps}% ({v}/{t} vuln)</span>
            </div>
            <div style="width:100%;height:10px;background:rgba(255,255,255,0.05);border-radius:5px;overflow:hidden">
                <div style="width:{ps}%;height:100%;background:{pc};border-radius:5px;transition:width .5s"></div>
            </div>
        </div>"""

    # Build tech stack
    tech_html = ""
    if detected_tech:
        for k, v in detected_tech.items():
            tech_html += f'<span style="display:inline-block;background:rgba(99,102,241,0.12);color:#818cf8;padding:4px 12px;border-radius:6px;font-size:11px;font-weight:600;margin:3px">{k}: {v}</span>'

    # Critical findings summary
    critical_findings = [f for f in findings if f["status"] == "vulnerable" and f["severity"] in ("critical", "high")]
    critical_html = ""
    if critical_findings:
        for cf in critical_findings:
            critical_html += f"""<div style="background:rgba(239,68,68,0.06);border:1px solid rgba(239,68,68,0.2);border-radius:10px;padding:16px;margin:10px 0">
                <div style="display:flex;justify-content:space-between;align-items:center">
                    <span style="font-weight:700;font-size:14px">{cf['vector_name']}</span>
                    <span style="color:#ef4444;font-weight:700;font-size:11px;text-transform:uppercase">{cf['severity']}</span>
                </div>
                <p style="color:#94a3b8;font-size:12px;margin-top:6px">{cf['details']}</p>
                <div style="margin-top:8px;font-size:11px;color:#64748b">Pillar: {cf['pillar']} | Vector: {cf['vector_id']}</div>
            </div>"""
    else:
        critical_html = '<div style="text-align:center;padding:24px;color:#10b981;font-weight:600">&#10003; No critical or high-severity vulnerabilities detected</div>'

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Security Audit Report — {target_name} | GuardianAI</title>
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&family=JetBrains+Mono:wght@400;600&display=swap" rel="stylesheet">
    <style>
        :root {{ --bg:#0a0e1a; --card:rgba(15,23,42,0.7); --border:rgba(99,102,241,0.15); --text:#e2e8f0; --muted:#94a3b8; }}
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ font-family:'Inter',sans-serif; background:var(--bg); color:var(--text); line-height:1.7; padding:0; }}
        .container {{ max-width:900px; margin:0 auto; padding:40px 30px; }}
        .section {{ background:var(--card); border:1px solid var(--border); border-radius:12px; padding:28px; margin-bottom:20px; }}
        .section h2 {{ font-size:18px; font-weight:800; margin-bottom:16px; display:flex; align-items:center; gap:8px; }}
        table {{ width:100%; border-collapse:collapse; font-size:13px; }}
        th {{ text-align:left; padding:8px 12px; border-bottom:2px solid var(--border); color:var(--muted); font-size:10px; text-transform:uppercase; letter-spacing:1px; font-weight:700; }}
        td {{ padding:10px 12px; border-bottom:1px solid rgba(255,255,255,0.04); font-size:13px; }}
        @media print {{
            body {{ background:white; color:#1e293b; }}
            .section {{ border-color:#e2e8f0; background:#f8fafc; }}
            .no-print {{ display:none; }}
        }}
    </style>
</head>
<body>
<div class="container">

    {unreachable_html}

    <!-- HEADER -->
    <div style="text-align:center;padding:50px 30px;background:linear-gradient(135deg,rgba(99,102,241,0.06),rgba(16,185,129,0.04));border:1px solid var(--border);border-radius:16px;margin-bottom:30px;position:relative;overflow:hidden">
        <div style="position:absolute;top:0;left:0;right:0;height:4px;background:linear-gradient(90deg,{gc},{gc}80,{gc})"></div>
        <div style="font-size:12px;font-weight:700;letter-spacing:2px;color:{gc};margin-bottom:16px">GUARDIANAI SECURITY AUDIT REPORT</div>
        <div style="font-size:80px;font-weight:900;color:{gc};line-height:1">{grade}</div>
        <div style="font-size:20px;color:var(--muted);margin:8px 0;font-weight:600">Score: {score_disp}</div>
        <div style="font-size:16px;font-weight:700;margin-top:16px">{target_name}</div>
        <div style="font-size:13px;color:#64748b;margin-top:4px">{target_url}</div>
        <div style="display:flex;justify-content:center;gap:24px;margin-top:20px;flex-wrap:wrap;font-size:11px;color:#64748b">
            <span><strong style="color:var(--text)">Scan ID:</strong> {scan_id}</span>
            <span><strong style="color:var(--text)">Depth:</strong> {depth}</span>
            <span><strong style="color:var(--text)">Duration:</strong> {duration}s</span>
            <span><strong style="color:var(--text)">Date:</strong> {started_at[:10] if started_at else 'N/A'}</span>
        </div>
    </div>

    <!-- STATS -->
    <div style="display:grid;grid-template-columns:repeat(4,1fr);gap:12px;margin-bottom:20px">
        <div style="text-align:center;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px">
            <div style="font-size:28px;font-weight:900">{total}</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-top:4px">Vectors Tested</div>
        </div>
        <div style="text-align:center;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px">
            <div style="font-size:28px;font-weight:900;color:#ef4444">{vulns}</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-top:4px">Vulnerabilities</div>
        </div>
        <div style="text-align:center;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px">
            <div style="font-size:28px;font-weight:900;color:#10b981">{protected}</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-top:4px">Protected</div>
        </div>
        <div style="text-align:center;background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px">
            <div style="font-size:28px;font-weight:900;color:#22d3ee">{total - vulns - protected}</div>
            <div style="font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:1px;margin-top:4px">Inconclusive</div>
        </div>
    </div>

    <!-- CRITICAL FINDINGS -->
    <div class="section" style="border-color:rgba(239,68,68,0.25)">
        <h2>&#9888;&#65039; Critical & High-Severity Findings</h2>
        {critical_html}
    </div>

    <!-- PILLAR BREAKDOWN -->
    <div class="section">
        <h2>&#128202; 6-Pillar Security Breakdown</h2>
        {pillar_bars}
    </div>

    <!-- DETECTED TECH -->
    {"" if not tech_html else f'''<div class="section">
        <h2>&#128270; Detected Technology Stack</h2>
        <div style="margin-top:8px">{tech_html}</div>
    </div>'''}

    <!-- ALL FINDINGS -->
    <div class="section">
        <h2>&#128220; Detailed Findings ({total} vectors)</h2>
        <table>
            <tr><th>ID</th><th>Vector</th><th>Pillar</th><th>Severity</th><th>Status</th></tr>
            {findings_rows}
        </table>
    </div>

    <!-- BADGE -->
    <div class="section" style="text-align:center">
        <h2 style="justify-content:center">&#128737;&#65039; Audit Verification Badge</h2>
        <p style="color:var(--muted);font-size:13px;margin-bottom:16px">This badge is cryptographically signed and can be verified at <strong>guardianai.com/verify</strong></p>
        <div style="display:inline-block;background:rgba(0,0,0,0.3);border:2px solid {gc};border-radius:12px;padding:20px 40px;margin:8px">
            <div style="font-size:11px;color:var(--muted);letter-spacing:2px;text-transform:uppercase">Audited by GuardianAI</div>
            <div style="font-size:36px;font-weight:900;color:{gc};margin:4px 0">{grade}</div>
            <div style="font-size:11px;color:#64748b">{scan_id} &middot; {badge_sig}</div>
        </div>
    </div>

    <!-- REMEDIATION -->
    <div class="section" style="border-color:rgba(16,185,129,0.25)">
        <h2>&#9989; Recommended Next Steps</h2>
        <div style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);display:flex;gap:12px;align-items:flex-start">
            <div style="background:#6366f1;color:white;width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:12px;flex-shrink:0">1</div>
            <div><strong>Deploy GuardianAI SDK</strong> — Add the semantic firewall to scan all LLM inputs/outputs before they touch smart contracts. <code>pip install guardianai-sdk</code></div>
        </div>
        <div style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);display:flex;gap:12px;align-items:flex-start">
            <div style="background:#6366f1;color:white;width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:12px;flex-shrink:0">2</div>
            <div><strong>Isolate Agent Contexts</strong> — Ensure multi-agent outputs are sanitized before being passed to other agents in the chain.</div>
        </div>
        <div style="padding:10px 0;border-bottom:1px solid rgba(255,255,255,0.04);display:flex;gap:12px;align-items:flex-start">
            <div style="background:#6366f1;color:white;width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:12px;flex-shrink:0">3</div>
            <div><strong>Add Output Validation</strong> — Never parse raw LLM output to trigger financial transactions. Use strict schema validation.</div>
        </div>
        <div style="padding:10px 0;display:flex;gap:12px;align-items:flex-start">
            <div style="background:#6366f1;color:white;width:24px;height:24px;border-radius:50%;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:12px;flex-shrink:0">4</div>
            <div><strong>Schedule Recurring Scans</strong> — Set up continuous monitoring to catch regressions as your AI agents evolve.</div>
        </div>
    </div>

    <div style="text-align:center;padding:30px;color:#475569;font-size:11px;border-top:1px solid var(--border);margin-top:20px">
        <strong>GuardianAI Security Lab</strong> | Enterprise LLM Security for Web3<br>
        &copy; 2026 GuardianAI Platform. All rights reserved.
    </div>

</div>
</body>
</html>"""
    return html


def generate_report_from_json(json_path: str, output_dir: str = "artifacts/audit") -> str:
    """Load a scan JSON and produce the branded HTML report."""
    with open(json_path, "r", encoding="utf-8") as f:
        scan_data = json.load(f)

    html = generate_scan_report_html(scan_data)

    scan_id = scan_data.get("scan_id", "unknown")
    os.makedirs(output_dir, exist_ok=True)
    out_path = os.path.join(output_dir, f"report_{scan_id}.html")
    with open(out_path, "w", encoding="utf-8") as f:
        f.write(html)
    print(f"[+] Report generated: {out_path}")
    return out_path


if __name__ == "__main__":
    import sys
    if len(sys.argv) < 2:
        print("Usage: python scan_report_generator.py <scan_result.json>")
        sys.exit(1)
    generate_report_from_json(sys.argv[1])
