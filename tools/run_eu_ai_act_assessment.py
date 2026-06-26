#!/usr/bin/env python3
"""
CLI tool to run EU AI Act compliance assessment and generate full evidence bundle.

Usage:
    python tools/run_eu_ai_act_assessment.py
    python tools/run_eu_ai_act_assessment.py --output artifacts/evidence/eu_ai_act_report.json
    python tools/run_eu_ai_act_assessment.py --format markdown
"""
from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict
from pathlib import Path

# Add guardian to path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "guardian"))

from compliance.eu_ai_act import EUAIActAssessment


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Run EU AI Act compliance assessment for GuardianAI"
    )
    parser.add_argument(
        "--output", "-o",
        default=str(ROOT / "artifacts" / "evidence" / "eu_ai_act_report.json"),
        help="Output file path (default: artifacts/evidence/eu_ai_act_report.json)",
    )
    parser.add_argument(
        "--format", "-f",
        choices=["json", "markdown", "both"],
        default="both",
        help="Output format (default: both)",
    )
    parser.add_argument(
        "--system-name",
        default="GuardianAI",
        help="AI system name",
    )
    parser.add_argument(
        "--system-version",
        default="1.0",
        help="AI system version",
    )
    parser.add_argument(
        "--organization",
        default="",
        help="Deployer organization name",
    )
    args = parser.parse_args()

    config = {
        "enabled": True,
        "system_name": args.system_name,
        "system_version": args.system_version,
        "deployer_organization": args.organization,
    }

    print(f"🇪🇺 EU AI Act Compliance Assessment — {args.system_name} v{args.system_version}")
    print("=" * 70)

    engine = EUAIActAssessment(config=config, root_dir=ROOT)

    # Run risk classification
    risk = engine.classify_risk()
    print(f"\n📋 Risk Classification: {risk.risk_level.upper()}")
    print(f"   Category: {risk.annex_iii_category}")
    print(f"   Rationale: {risk.rationale}")

    # Run full assessment
    report = engine.assess_compliance()

    print(f"\n📊 Overall Score: {report.overall_score:.0%} ({report.overall_status})")
    print(f"\n📑 Article-by-Article Assessment:")
    print("-" * 70)

    for assessment in report.article_assessments:
        status_icon = {"compliant": "✅", "partial": "⚠️", "non_compliant": "❌"}.get(
            assessment["status"], "❓"
        )
        print(f"  {status_icon} {assessment['article_id'].upper()} — {assessment['article_title']}")
        print(f"     Score: {assessment['score']:.0%} | Status: {assessment['status']}")
        if assessment["findings"]:
            for finding in assessment["findings"]:
                print(f"     → {finding}")
        if assessment["recommendations"]:
            print(f"     Recommendations:")
            for rec in assessment["recommendations"][:3]:
                print(f"       • {rec}")
        print()

    # Generate conformity checklist summary
    checklist = report.conformity_checklist
    implemented = sum(1 for c in checklist if c["status"] == "implemented")
    partial = sum(1 for c in checklist if c["status"] == "partial")
    print(f"✅ Conformity Checklist: {implemented}/{len(checklist)} implemented, {partial} partial")

    # Generate QMS mapping summary
    qms = report.qms_mapping
    mapped = sum(1 for m in qms if m["status"] == "mapped")
    print(f"📐 ISO 42001 QMS Mapping: {mapped}/{len(qms)} clauses mapped")

    # Write outputs
    out_path = Path(args.output)
    out_path.parent.mkdir(parents=True, exist_ok=True)

    if args.format in ("json", "both"):
        report_dict = asdict(report)
        out_path.write_text(json.dumps(report_dict, indent=2, default=str), encoding="utf-8")
        print(f"\n💾 JSON report saved: {out_path}")

    if args.format in ("markdown", "both"):
        md_path = out_path.with_suffix(".md")
        md_content = _build_markdown_report(report)
        md_path.write_text(md_content, encoding="utf-8")
        print(f"💾 Markdown report saved: {md_path}")

    # Final verdict
    print(f"\n{'=' * 70}")
    if report.overall_status == "compliant":
        print("🟢 VERDICT: Compliant — System meets EU AI Act requirements")
    elif report.overall_status == "conditional":
        print("🟡 VERDICT: Conditional — Partial compliance, remediation needed")
    else:
        print("🔴 VERDICT: Non-compliant — Significant gaps require remediation")

    # Machine-readable summary for CI integration
    summary = {
        "overall_score": report.overall_score,
        "overall_status": report.overall_status,
        "risk_level": report.risk_classification.get("risk_level", "unknown"),
        "articles_compliant": sum(1 for a in report.article_assessments if a["status"] == "compliant"),
        "articles_partial": sum(1 for a in report.article_assessments if a["status"] == "partial"),
        "articles_non_compliant": sum(1 for a in report.article_assessments if a["status"] == "non_compliant"),
        "conformity_items_implemented": implemented,
        "qms_clauses_mapped": mapped,
    }
    print(json.dumps(summary))


def _build_markdown_report(report) -> str:
    """Build a markdown version of the compliance report."""
    lines = [
        f"# EU AI Act Compliance Report — {report.system_name}",
        f"",
        f"**Generated**: {report.generated_at_utc}",
        f"**System**: {report.system_name} v{report.system_version}",
        f"**Framework**: {report.framework}",
        f"**Overall Score**: {report.overall_score:.0%} ({report.overall_status})",
        f"",
        f"---",
        f"",
        f"## Risk Classification",
        f"",
        f"- **Risk Level**: {report.risk_classification.get('risk_level', 'unknown').upper()}",
        f"- **Category**: {report.risk_classification.get('annex_iii_category', 'N/A')}",
        f"- **Rationale**: {report.risk_classification.get('rationale', 'N/A')}",
        f"",
        f"---",
        f"",
        f"## Article Assessments",
        f"",
        f"| Article | Title | Score | Status |",
        f"|---------|-------|-------|--------|",
    ]

    for a in report.article_assessments:
        icon = {"compliant": "✅", "partial": "⚠️", "non_compliant": "❌"}.get(a["status"], "❓")
        lines.append(f"| {a['article_id'].upper()} | {a['article_title']} | {a['score']:.0%} | {icon} {a['status']} |")

    lines.extend([
        f"",
        f"---",
        f"",
        f"## Risk Management System (Art. 9)",
        f"",
        report.rms_document,
        f"",
        f"---",
        f"",
        f"## Transparency Report (Art. 13)",
        f"",
        report.transparency_report,
        f"",
        f"---",
        f"",
        f"## Conformity Checklist",
        f"",
        f"| ID | Requirement | Status | Evidence |",
        f"|----|-------------|--------|----------|",
    ])

    for item in report.conformity_checklist:
        evidence = ", ".join(item.get("evidence", []))
        icon = {"implemented": "✅", "partial": "⚠️", "not_implemented": "❌"}.get(item["status"], "❓")
        lines.append(f"| {item['id']} | {item['requirement'][:60]} | {icon} {item['status']} | {evidence} |")

    lines.extend([
        f"",
        f"---",
        f"",
        f"## ISO/IEC 42001 QMS Mapping",
        f"",
        f"| ISO Clause | EU AI Act | Guardian Control | Status |",
        f"|-----------|-----------|------------------|--------|",
    ])

    for m in report.qms_mapping:
        lines.append(f"| {m['iso_clause']} | {m['eu_ai_act_article']} | {m['guardian_control'][:50]} | ✅ {m['status']} |")

    return "\n".join(lines)


if __name__ == "__main__":
    main()
