#!/usr/bin/env python3
"""Analyze GuardianAI audit report failures in detail."""
import json, sys
sys.stdout.reconfigure(encoding="utf-8")
from pathlib import Path

reports = sorted(Path("artifacts/audit").glob("*.json"))
if not reports:
    print("No reports found")
    sys.exit(1)

latest = reports[-1]
print(f"Report: {latest.name}")

with open(latest) as f:
    data = json.load(f)

score = data.get("score", {})
print(f"\nOverall Score: {score.get('overall_score', 'N/A')}")
print(f"Grade: {score.get('grade', 'N/A')}")

# Analyze by category
cats = score.get("category_scores", [])
print(f"\n{'Category':<30} {'Score':>6} {'Blocked':>8} {'Vulns':>6} {'Partial':>8}")
print("-" * 65)
for c in sorted(cats, key=lambda x: x.get("score", 0)):
    print(f"{c['category']:<30} {c['score']:>5.1f}% {c['blocked']:>7} {c['passed']:>6} {c.get('partial', 0):>7}")

# Analyze vulnerabilities
vulns = [v for v in data.get("vulnerabilities", []) if v.get("status") in ("PASSED", "PARTIAL")]
sev_counts = {}
cat_vuln_counts = {}
for v in vulns:
    sev = v.get("severity", "UNKNOWN")
    cat = v.get("category", "UNKNOWN")
    sev_counts[sev] = sev_counts.get(sev, 0) + 1
    cat_vuln_counts[cat] = cat_vuln_counts.get(cat, 0) + 1

print(f"\nVulnerabilities by Severity:")
for s, c in sorted(sev_counts.items(), key=lambda x: -x[1]):
    print(f"  {s}: {c}")

print(f"\nVulnerabilities by Category:")
for s, c in sorted(cat_vuln_counts.items(), key=lambda x: -x[1]):
    print(f"  {s}: {c}")

# List all unique vulnerability details
print(f"\nAll {len(vulns)} Vulnerability Details:")
seen = set()
for v in vulns:
    key = v["vector_name"]
    if key in seen:
        continue
    seen.add(key)
    print(f"  [{v['severity']}] {v['category']}: {v['vector_name'][:70]}")
    evidence = v.get("evidence_notes", "")
    if evidence:
        print(f"         Evidence: {evidence[:100]}")
    response = v.get("response_text", "")
    if response:
        print(f"         Response: {response[:120]}")
    print()

print(f"\nUnique failing vectors: {len(seen)}")
print(f"Total failing instances: {len(vulns)}")
