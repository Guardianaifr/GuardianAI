"""
SARIF (Static Analysis Results Interchange Format) exporter for GuardianAI.

SARIF 2.1.0 is the industry standard format accepted by GitHub Security tab,
VS Code, Rider, and all major CI/CD security dashboards.
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

SEVERITY_MAP = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "none",
}

# OWASP LLM IDs → CWE mappings for SARIF taxonomy
OWASP_TO_CWE: Dict[str, str] = {
    "Prompt Injection & Jailbreak": "CWE-77",
    "Data Exfiltration & Privacy":  "CWE-200",
    "Smart Contract Manipulation":  "CWE-682",
    "Multi-Agent Exploitation":     "CWE-284",
    "Financial Logic Manipulation": "CWE-840",
    "Infrastructure & API Security": "CWE-306",
}


def _make_rule(vector_id: str, vector_name: str, pillar: str, severity: str, description: str) -> Dict:
    """Build a SARIF rule descriptor."""
    cwe = OWASP_TO_CWE.get(pillar, "CWE-0")
    sarif_level = SEVERITY_MAP.get(severity.lower(), "warning")
    return {
        "id": vector_id,
        "name": vector_name.replace(" ", ""),
        "shortDescription": {"text": vector_name},
        "fullDescription": {"text": description or vector_name},
        "helpUri": f"https://owasp.org/www-project-top-10-for-large-language-model-applications/",
        "properties": {
            "tags": ["security", "ai", "web3", pillar],
            "precision": "high",
            "problem.severity": sarif_level,
        },
        "defaultConfiguration": {"level": sarif_level},
        "relationships": [
            {
                "target": {
                    "id": cwe,
                    "toolComponent": {"name": "CWE", "guid": "FFC64C90-42B6-44CE-8BEB-F6B7DAE649E5"},
                },
                "kinds": ["superset"],
            }
        ],
    }


def generate_sarif(scan_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Convert a GuardianAI scan result dict into a SARIF 2.1.0 document.

    Args:
        scan_data: The JSON result from CryptoAuditScanner.to_dict()

    Returns:
        A SARIF-compliant Python dict ready for json.dumps()
    """
    target_url = scan_data.get("target_url", "unknown")
    target_name = scan_data.get("target_name", target_url)
    scan_id = scan_data.get("scan_id", "unknown")
    started_at = scan_data.get("started_at", datetime.now(timezone.utc).isoformat())

    findings = scan_data.get("findings", [])

    # Build rule index from unique vectors
    rules_seen: Dict[str, Dict] = {}
    results: List[Dict] = []

    for f in findings:
        status = f.get("status", "")
        # Only report findings that are actually vulnerable (attack succeeded)
        if status not in ("vulnerable", "passed"):
            continue

        vector_id = f.get("vector_id", "UNKNOWN")
        vector_name = f.get("vector_name", vector_id)
        pillar = f.get("pillar", "")
        severity = f.get("severity", "medium")
        details = f.get("details", "")
        remediation = f.get("remediation", "")

        # Build rule if not seen
        if vector_id not in rules_seen:
            rules_seen[vector_id] = _make_rule(vector_id, vector_name, pillar, severity, details)

        # Build result entry
        sarif_level = SEVERITY_MAP.get(severity.lower(), "warning")
        message_parts = [f"**{vector_name}** — {details or 'Attack vector succeeded.'}"]
        if remediation:
            message_parts.append(f"\n\n**Remediation:** {remediation}")

        result = {
            "ruleId": vector_id,
            "level": sarif_level,
            "message": {"text": " ".join(message_parts)},
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": target_url,
                            "uriBaseId": "%TARGETURI%",
                        }
                    },
                    "logicalLocations": [
                        {
                            "name": target_name,
                            "kind": "endpoint",
                        }
                    ],
                }
            ],
            "properties": {
                "pillar": pillar,
                "severity": severity,
                "vector_id": vector_id,
                "scan_id": scan_id,
                "confidence": f.get("confidence", 0.9),
                "attack_prompt": (f.get("attack_prompt", "") or "")[:500],
                "response_snippet": (f.get("response_snippet", "") or "")[:500],
            },
        }
        results.append(result)

    # If no vulnerable findings, produce one informational result
    if not results:
        results.append({
            "ruleId": "GUARDIAN-PASS",
            "level": "none",
            "message": {
                "text": f"No vulnerabilities detected. Score: {scan_data.get('score', 100)}/100 ({scan_data.get('grade', 'A+')})"
            },
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": target_url, "uriBaseId": "%TARGETURI%"}
                    }
                }
            ],
        })
        rules_seen["GUARDIAN-PASS"] = {
            "id": "GUARDIAN-PASS",
            "name": "GuardianAIScanPassed",
            "shortDescription": {"text": "GuardianAI Security Scan Passed"},
            "fullDescription": {"text": "All security vectors were blocked. No vulnerabilities detected."},
            "defaultConfiguration": {"level": "none"},
        }

    sarif_doc = {
        "$schema": SARIF_SCHEMA,
        "version": SARIF_VERSION,
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "GuardianAI",
                        "version": "1.0.0",
                        "informationUri": "https://guardianai.dev",
                        "organization": "GuardianAI Security Lab",
                        "shortDescription": {"text": "AI+Web3 Security Audit Platform — 6-Pillar, 49-Vector Scanner"},
                        "rules": list(rules_seen.values()),
                    }
                },
                "automationDetails": {
                    "id": f"guardianai/{scan_id}",
                    "description": {"text": f"GuardianAI security scan of {target_name}"},
                },
                "results": results,
                "artifacts": [
                    {
                        "location": {"uri": target_url, "uriBaseId": "%TARGETURI%"},
                        "description": {"text": f"Target API endpoint: {target_name}"},
                    }
                ],
                "invocations": [
                    {
                        "executionSuccessful": True,
                        "startTimeUtc": started_at,
                        "endTimeUtc": scan_data.get("completed_at", started_at),
                        "toolExecutionNotifications": [],
                        "properties": {
                            "scan_depth": scan_data.get("scan_depth", "standard"),
                            "total_vectors": scan_data.get("total_vectors", 0),
                            "score": scan_data.get("score", 0),
                            "grade": scan_data.get("grade", "F"),
                        },
                    }
                ],
                "properties": {
                    "guardianai": {
                        "score": scan_data.get("score"),
                        "grade": scan_data.get("grade"),
                        "scan_id": scan_id,
                        "target": target_url,
                        "pillar_scores": scan_data.get("pillar_scores", {}),
                    }
                },
            }
        ],
    }

    return sarif_doc


def generate_sarif_string(scan_data: Dict[str, Any], indent: int = 2) -> str:
    """Return the SARIF document as a formatted JSON string."""
    return json.dumps(generate_sarif(scan_data), indent=indent, ensure_ascii=False)
