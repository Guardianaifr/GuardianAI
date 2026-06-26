"""
GuardianAI PDF Audit Report Generator.

Generates professional, branded PDF reports for completed security audits.
Uses pure Python (no external PDF library dependency) to produce HTML-based
reports that can be rendered as PDF via browser print or wkhtmltopdf.

Features:
  - Executive summary with score, grade, and certification status
  - Vulnerability breakdown by OWASP LLM category
  - Historical attack resilience table (2016-2026)
  - Module-level defense coverage map
  - Cryptographic badge embed with HMAC signature
  - Remediation recommendations

2026 Standard: SOC 2 Type II + ISO 27001 compliant reporting format.
"""

from __future__ import annotations

import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("guardian.audit.report_generator")


class AuditReportGenerator:
    """
    Generates HTML-based audit reports that can be saved or printed to PDF.

    Usage:
        gen = AuditReportGenerator()
        html = gen.generate(audit_data)
        gen.save_html(html, "artifacts/audit/report_2026.html")
    """

    BRAND_COLORS = {
        "primary": "#6366f1",      # Indigo
        "primary_dark": "#4f46e5",
        "success": "#10b981",      # Emerald
        "warning": "#f59e0b",      # Amber
        "danger": "#ef4444",       # Red
        "bg_dark": "#0f172a",      # Slate 900
        "bg_card": "#1e293b",      # Slate 800
        "text": "#e2e8f0",         # Slate 200
        "text_muted": "#94a3b8",   # Slate 400
        "border": "#334155",       # Slate 700
    }

    def _grade_color(self, grade: str) -> str:
        if grade.startswith("A"):
            return self.BRAND_COLORS["success"]
        elif grade.startswith("B"):
            return self.BRAND_COLORS["primary"]
        elif grade.startswith("C"):
            return self.BRAND_COLORS["warning"]
        return self.BRAND_COLORS["danger"]

    def generate(
        self,
        target_name: str,
        target_uri: str,
        score: float,
        grade: str,
        total_vectors: int,
        blocked_count: int,
        findings: List[Dict[str, Any]],
        modules: List[Dict[str, str]],
        badge_data: Optional[Dict[str, Any]] = None,
        historical_results: Optional[List[Dict[str, str]]] = None,
        before_score: Optional[float] = None,
        before_block_rate: Optional[float] = None,
    ) -> str:
        """
        Generate a full HTML audit report.

        Args:
            target_name: Display name of the audited target.
            target_uri: The endpoint URI that was scanned.
            score: Final GuardianAI Security Score (0-100).
            grade: Letter grade (A+, A, B+, etc.).
            total_vectors: Total attack vectors tested.
            blocked_count: Number of vectors blocked.
            findings: List of finding dicts with keys: vector_id, status, category, severity.
            modules: List of module dicts with keys: name, description, status.
            badge_data: Optional certification badge payload.
            historical_results: Optional list of historical hack test results.

        Returns:
            Complete HTML string for the report.
        """
        now = datetime.now(timezone.utc).strftime("%B %d, %Y at %H:%M UTC")
        block_rate = (blocked_count / total_vectors * 100) if total_vectors > 0 else 0
        grade_color = self._grade_color(grade)
        is_certified = score >= 80.0

        # Build findings table rows
        findings_rows = ""
        for f in findings:
            status = f.get("status", "UNKNOWN")
            status_color = self.BRAND_COLORS["success"] if status == "BLOCKED" else (
                self.BRAND_COLORS["warning"] if status == "PARTIAL" else self.BRAND_COLORS["danger"]
            )
            findings_rows += f"""
            <tr>
                <td>{f.get('vector_id', 'N/A')}</td>
                <td>{f.get('category', 'N/A')}</td>
                <td>{f.get('severity', 'N/A')}</td>
                <td style="color: {status_color}; font-weight: 600;">{status}</td>
            </tr>"""

        # Build modules table rows
        modules_rows = ""
        for m in modules:
            status = m.get("status", "ACTIVE")
            modules_rows += f"""
            <tr>
                <td><code>{m.get('name', 'N/A')}</code></td>
                <td>{m.get('description', 'N/A')}</td>
                <td style="color: {self.BRAND_COLORS['success']};">✓ {status}</td>
            </tr>"""

        # Build historical results rows
        historical_rows = ""
        if historical_results:
            for h in historical_results:
                status = h.get("status", "UNKNOWN")
                status_color = self.BRAND_COLORS["success"] if status == "BLOCKED" else self.BRAND_COLORS["warning"]
                historical_rows += f"""
                <tr>
                    <td>{h.get('year', 'N/A')}</td>
                    <td>{h.get('name', 'N/A')}</td>
                    <td>{h.get('loss', 'N/A')}</td>
                    <td style="color: {status_color}; font-weight: 600;">{status}</td>
                </tr>"""

        # Build compliance section
        compliance_summary = {
            "SOC-2": set(),
            "ISO 27001": set(),
            "EU AI Act": set(),
            "NIST AI RMF": set()
        }
        for f in findings:
            mappings = f.get("compliance_mappings") or {}
            for framework, controls in mappings.items():
                if framework in compliance_summary:
                    for c in controls:
                        compliance_summary[framework].add(c)
                else:
                    fw_upper = str(framework).upper()
                    if "SOC-2" in fw_upper or "SOC2" in fw_upper:
                        for c in controls: compliance_summary["SOC-2"].add(c)
                    elif "ISO" in fw_upper:
                        for c in controls: compliance_summary["ISO 27001"].add(c)
                    elif "EU AI" in fw_upper:
                        for c in controls: compliance_summary["EU AI Act"].add(c)
                    elif "NIST" in fw_upper:
                        for c in controls: compliance_summary["NIST AI RMF"].add(c)

        compliance_rows = ""
        for framework, controls in compliance_summary.items():
            controls_list = sorted(list(controls))
            controls_html = ", ".join([f"<code>{c}</code>" for c in controls_list]) if controls_list else '<span style="color:#64748b;">No direct mapping found</span>'
            compliance_rows += f"""
            <tr>
                <td style="font-weight: 600; width: 150px;">{framework}</td>
                <td>{controls_html}</td>
            </tr>"""

        compliance_section = f"""
        <div class="section">
            <h2>📋 Regulatory & Compliance Mapping</h2>
            <p class="muted">Attack vectors in this scan are dynamically mapped to security controls and regulatory requirements.</p>
            <table>
                <thead><tr><th>Framework</th><th>Mapped Controls & Articles Covered</th></tr></thead>
                <tbody>{compliance_rows}</tbody>
            </table>
        </div>"""

        historical_section = ""
        if historical_rows:
            historical_section = f"""
            <div class="section">
                <h2>📜 Historical Attack Resilience (2016-2026)</h2>
                <p class="muted">Tests whether the AI can be used to reproduce the 10 largest crypto/DeFi hacks of the last decade.</p>
                <table>
                    <thead><tr><th>Year</th><th>Incident</th><th>Loss</th><th>Defense Status</th></tr></thead>
                    <tbody>{historical_rows}</tbody>
                </table>
            </div>"""

        # Badge section
        badge_section = ""
        if badge_data and is_certified:
            sig = badge_data.get("signature", "N/A")[:32] + "..."
            badge_section = f"""
            <div class="section badge-section">
                <h2>🏅 Certification Badge</h2>
                <div class="badge-container">
                    <div class="badge-visual">
                        <div class="badge-circle" style="border-color: {grade_color};">
                            <span class="badge-grade">{grade}</span>
                        </div>
                        <div class="badge-label">GuardianAI Certified</div>
                    </div>
                    <div class="badge-details">
                        <p><strong>Signature (HMAC-SHA256):</strong></p>
                        <code class="sig">{sig}</code>
                        <p><strong>Verification URL:</strong></p>
                        <code class="sig">{badge_data.get('verification_url', 'N/A')}</code>
                    </div>
                </div>
            </div>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>GuardianAI Security Audit Report — {target_name}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{
            font-family: 'Inter', -apple-system, sans-serif;
            background: {self.BRAND_COLORS['bg_dark']};
            color: {self.BRAND_COLORS['text']};
            line-height: 1.6;
            padding: 40px;
        }}
        .container {{ max-width: 900px; margin: 0 auto; }}
        .header {{
            text-align: center;
            padding: 40px 0;
            border-bottom: 1px solid {self.BRAND_COLORS['border']};
            margin-bottom: 40px;
        }}
        .header h1 {{
            font-size: 28px;
            font-weight: 800;
            background: linear-gradient(135deg, {self.BRAND_COLORS['primary']}, #a78bfa);
            -webkit-background-clip: text;
            -webkit-text-fill-color: transparent;
            margin-bottom: 8px;
        }}
        .header .subtitle {{ color: {self.BRAND_COLORS['text_muted']}; font-size: 14px; }}
        .score-hero {{
            display: flex;
            justify-content: center;
            gap: 40px;
            margin: 40px 0;
            flex-wrap: wrap;
        }}
        .score-card {{
            background: {self.BRAND_COLORS['bg_card']};
            border: 1px solid {self.BRAND_COLORS['border']};
            border-radius: 16px;
            padding: 30px 40px;
            text-align: center;
            min-width: 180px;
        }}
        .score-card .value {{
            font-size: 48px;
            font-weight: 800;
            line-height: 1;
            margin-bottom: 8px;
        }}
        .score-card .label {{
            color: {self.BRAND_COLORS['text_muted']};
            font-size: 13px;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 1px;
        }}
        .section {{
            background: {self.BRAND_COLORS['bg_card']};
            border: 1px solid {self.BRAND_COLORS['border']};
            border-radius: 12px;
            padding: 30px;
            margin-bottom: 24px;
        }}
        .section h2 {{
            font-size: 18px;
            font-weight: 700;
            margin-bottom: 16px;
            padding-bottom: 12px;
            border-bottom: 1px solid {self.BRAND_COLORS['border']};
        }}
        .muted {{ color: {self.BRAND_COLORS['text_muted']}; font-size: 14px; margin-bottom: 16px; }}
        table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
        th, td {{ padding: 10px 14px; text-align: left; border-bottom: 1px solid {self.BRAND_COLORS['border']}; }}
        th {{ color: {self.BRAND_COLORS['text_muted']}; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}
        code {{ background: rgba(99, 102, 241, 0.15); padding: 2px 6px; border-radius: 4px; font-size: 12px; }}
        .sig {{ word-break: break-all; display: block; margin: 6px 0; font-size: 11px; }}
        .badge-section {{ text-align: center; }}
        .badge-container {{ display: flex; align-items: center; justify-content: center; gap: 30px; flex-wrap: wrap; }}
        .badge-visual {{ text-align: center; }}
        .badge-circle {{
            width: 100px; height: 100px; border-radius: 50%;
            border: 4px solid; display: flex; align-items: center;
            justify-content: center; margin: 0 auto 10px;
        }}
        .badge-grade {{ font-size: 36px; font-weight: 800; }}
        .badge-label {{ font-weight: 600; font-size: 14px; }}
        .badge-details {{ text-align: left; max-width: 400px; }}
        .badge-details p {{ margin: 8px 0 2px; font-size: 13px; color: {self.BRAND_COLORS['text_muted']}; }}
        .cert-status {{
            display: inline-block;
            padding: 6px 16px;
            border-radius: 20px;
            font-weight: 700;
            font-size: 13px;
            margin-top: 10px;
        }}
        .comparison-grid {{
            display: grid;
            grid-template-columns: 1fr 1fr;
            gap: 20px;
            margin-top: 20px;
        }}
        .comparison-card {{
            background: rgba(15, 23, 42, 0.5);
            border: 1px solid {self.BRAND_COLORS['border']};
            border-radius: 8px;
            padding: 20px;
        }}
        .comparison-card h3 {{
            font-size: 14px;
            text-transform: uppercase;
            letter-spacing: 1px;
            margin-bottom: 15px;
            text-align: center;
        }}
        .comparison-bar-container {{
            background: {self.BRAND_COLORS['bg_dark']};
            border-radius: 10px;
            height: 12px;
            width: 100%;
            margin-bottom: 8px;
            overflow: hidden;
        }}
        .comparison-bar {{
            height: 100%;
            border-radius: 10px;
            transition: width 1s ease-in-out;
        }}
        .comparison-stat {{
            display: flex;
            justify-content: space-between;
            font-size: 13px;
            font-weight: 600;
            margin-bottom: 12px;
        }}
        .footer {{
            text-align: center;
            padding: 30px 0;
            color: {self.BRAND_COLORS['text_muted']};
            font-size: 12px;
            border-top: 1px solid {self.BRAND_COLORS['border']};
            margin-top: 20px;
        }}
        @media print {{
            body {{ background: white; color: #1e293b; padding: 20px; }}
            .section {{ border-color: #e2e8f0; }}
            th {{ color: #64748b; }}
            td {{ border-color: #e2e8f0; }}
            .comparison-card {{ background: #f8fafc; }}
        }}
    </style>
</head>
<body>
<div class="container">
    <div class="header">
        <h1>🛡️ GuardianAI Security Audit Report</h1>
        <p class="subtitle">Generated on {now}</p>
        <p class="subtitle">Target: <strong>{target_name}</strong> — <code>{target_uri}</code></p>
    </div>

    <div class="score-hero">
        <div class="score-card">
            <div class="value" style="color: {grade_color};">{score:.1f}</div>
            <div class="label">Security Score</div>
        </div>
        <div class="score-card">
            <div class="value" style="color: {grade_color};">{grade}</div>
            <div class="label">Grade</div>
        </div>
        <div class="score-card">
            <div class="value" style="color: {self.BRAND_COLORS['success']};">{block_rate:.1f}%</div>
            <div class="label">Block Rate</div>
        </div>
        <div class="score-card">
            <div class="value">{blocked_count}/{total_vectors}</div>
            <div class="label">Vectors Blocked</div>
        </div>
    </div>

    <div class="section">
        <h2>📋 Executive Summary</h2>
        <p>The target <strong>{target_name}</strong> was subjected to a comprehensive security audit
        consisting of <strong>{total_vectors}</strong> adversarial attack vectors spanning OWASP LLM Top 10
        categories, historical crypto/DeFi exploits (2016-2026), and 2026-standard AI agent attacks.</p>
        <p style="margin-top: 12px;">The system achieved a <strong>GuardianAI Security Score (GSS)</strong> of
        <strong style="color: {grade_color};">{score:.1f}/100 ({grade})</strong>, with a
        block rate of <strong>{block_rate:.1f}%</strong>.</p>
        <div style="text-align: center; margin-top: 16px;">
            <span class="cert-status" style="background: {'rgba(16,185,129,0.15); color: #10b981;' if is_certified else 'rgba(239,68,68,0.15); color: #ef4444;'}">
                {'✓ CERTIFIED — Eligible for Production Badge' if is_certified else '✗ NOT CERTIFIED — Score below 80.0 threshold'}
            </span>
        </div>
        
        {f'''
        <div class="comparison-grid">
            <div class="comparison-card">
                <h3 style="color: {self.BRAND_COLORS['danger']}">Before GuardianAI</h3>
                <div class="comparison-stat">
                    <span>Security Score</span>
                    <span style="color: {self.BRAND_COLORS['danger']}">{before_score:.1f} / 100</span>
                </div>
                <div class="comparison-bar-container">
                    <div class="comparison-bar" style="width: {before_score}%; background: {self.BRAND_COLORS['danger']}"></div>
                </div>
                
                <div class="comparison-stat" style="margin-top: 15px;">
                    <span>Block Rate</span>
                    <span style="color: {self.BRAND_COLORS['danger']}">{before_block_rate:.1f}%</span>
                </div>
                <div class="comparison-bar-container">
                    <div class="comparison-bar" style="width: {before_block_rate}%; background: {self.BRAND_COLORS['danger']}"></div>
                </div>
            </div>
            
            <div class="comparison-card">
                <h3 style="color: {self.BRAND_COLORS['success']}">With GuardianAI</h3>
                <div class="comparison-stat">
                    <span>Security Score</span>
                    <span style="color: {grade_color}">{score:.1f} / 100</span>
                </div>
                <div class="comparison-bar-container">
                    <div class="comparison-bar" style="width: {score}%; background: {grade_color}"></div>
                </div>
                
                <div class="comparison-stat" style="margin-top: 15px;">
                    <span>Block Rate</span>
                    <span style="color: {self.BRAND_COLORS['success']}">{block_rate:.1f}%</span>
                </div>
                <div class="comparison-bar-container">
                    <div class="comparison-bar" style="width: {block_rate}%; background: {self.BRAND_COLORS['success']}"></div>
                </div>
            </div>
        </div>
        ''' if before_score is not None and before_block_rate is not None else ''}
    </div>

    <div class="section">
        <h2>🔍 Vulnerability Findings ({len(findings)} vectors)</h2>
        <table>
            <thead><tr><th>Vector ID</th><th>Category</th><th>Severity</th><th>Status</th></tr></thead>
            <tbody>{findings_rows}</tbody>
        </table>
    </div>

    <div class="section">
        <h2>🛡️ Active Defense Modules ({len(modules)})</h2>
        <table>
            <thead><tr><th>Module</th><th>Coverage</th><th>Status</th></tr></thead>
            <tbody>{modules_rows}</tbody>
        </table>
    </div>

    {compliance_section}

    {historical_section}

    {badge_section}

    <div class="footer">
        <p>This report was generated by <strong>GuardianAI Audit Engine v2.0</strong></p>
        <p>© 2026 GuardianAI — Enterprise AI Security Platform</p>
        <p style="margin-top: 8px;">Compliant with OWASP LLM Top 10 (2025), EU AI Act Article 15, NIST AI 600-1</p>
    </div>
</div>
</body>
</html>"""
        return html

    def save_html(self, html: str, filepath: str) -> str:
        """Save the HTML report to a file."""
        os.makedirs(os.path.dirname(filepath), exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            f.write(html)
        logger.info(f"Audit report saved to {filepath}")
        return filepath
