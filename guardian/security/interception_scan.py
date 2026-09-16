"""Interception traffic scanning helpers (HAR format from Burp/ZAP-like tools)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import json

try:
    from guardian.guardrails.output_validator import OutputValidator
except ImportError:
    from guardrails.output_validator import OutputValidator


@dataclass
class InterceptionFinding:
    source: str
    location: str
    entities: list[str]
    preview: str
    scanner: str = "har_interception_scan"


def _extract_har_entries(data: dict) -> list[dict]:
    log = data.get("log", {})
    entries = log.get("entries", [])
    return entries if isinstance(entries, list) else []


def scan_har_for_leaks(har_path: Path) -> list[InterceptionFinding]:
    payload = json.loads(Path(har_path).read_text(encoding="utf-8"))
    entries = _extract_har_entries(payload)
    if not entries:
        return []

    findings: list[InterceptionFinding] = []
    validator = OutputValidator()

    for i, entry in enumerate(entries):
        req = entry.get("request", {}) or {}
        resp = entry.get("response", {}) or {}
        url = str(req.get("url") or f"entry_{i}")

        req_text = ""
        req_post = req.get("postData", {})
        if isinstance(req_post, dict):
            req_text = str(req_post.get("text", "") or "")
        if req_text and validator.validate_output(req_text) is False:
            _, entities = validator.sanitize_output(req_text)
            findings.append(
                InterceptionFinding(
                    source=url,
                    location="request.body",
                    entities=entities or ["possible_sensitive_data"],
                    preview=req_text[:180],
                )
            )

        resp_text = ""
        resp_content = resp.get("content", {})
        if isinstance(resp_content, dict):
            resp_text = str(resp_content.get("text", "") or "")
        if resp_text and validator.validate_output(resp_text) is False:
            _, entities = validator.sanitize_output(resp_text)
            findings.append(
                InterceptionFinding(
                    source=url,
                    location="response.body",
                    entities=entities or ["possible_sensitive_data"],
                    preview=resp_text[:180],
                )
            )

    return findings


def scan_har_directory(har_dir: Path) -> list[InterceptionFinding]:
    """Scan all .har files in a directory tree."""
    root = Path(har_dir)
    if not root.exists():
        return []
    findings: list[InterceptionFinding] = []
    for path in root.rglob("*.har"):
        findings.extend(scan_har_for_leaks(path))
    return findings
