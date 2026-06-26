"""Governance gate for Purple auto-hotfix activation."""

from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path
import json
from typing import Any

import yaml

from brain.red_probe import RedProbeFinding


def _utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _load_approval(path: Path | None) -> dict[str, Any]:
    if not path or not path.exists():
        return {}
    text = path.read_text(encoding="utf-8")
    try:
        data = yaml.safe_load(text)
        return data if isinstance(data, dict) else {}
    except Exception:
        return {}


# ─── Safe regression prompts ─────────────────────────────────────────────────
# These are representative, clearly benign prompts. Any hotpatch pattern that
# matches one of these is automatically rejected as a false-positive risk —
# protecting against "firewall poisoning" denial-of-service attacks where an
# attacker deliberately crafts prompts to trigger over-zealous auto-patches.

DEFAULT_REGRESSION_PROMPTS = [
    "What is the capital of France?",
    "Summarize the key points of the attached document.",
    "Help me write a professional email to my team.",
    "How do I bake a chocolate cake?",
    "Translate this sentence into Spanish: Hello, how are you?",
    "What is the difference between machine learning and deep learning?",
    "Can you explain how photosynthesis works?",
    "Write a Python function to reverse a string.",
    "What are the best practices for password security?",
    "Give me three ideas for a team-building activity.",
    "Help me debug this code: def add(a, b): return a - b",
    "What are the symptoms of a common cold?",
    "Summarize the plot of Romeo and Juliet.",
    "How do I set up a virtual environment in Python?",
    "What is the time complexity of quicksort?",
    "Explain the concept of supply and demand.",
    "Write a haiku about autumn.",
    "What are the main causes of climate change?",
    "How do I create a pivot table in Excel?",
    "What is the difference between HTTP and HTTPS?",
    "Explain how vaccines work.",
    "Give me a recipe for vegetable soup.",
    "How do I calculate compound interest?",
    "What is object-oriented programming?",
    "Help me plan a 5-day trip to Japan.",
    "What are the rules of chess?",
    "How does a GPS system work?",
    "Write unit tests for a function that calculates the area of a circle.",
    "What is the history of the internet?",
    "How do I improve my public speaking skills?",
]


def _check_regression(pattern_str: str, prompts: list[str]) -> list[str]:
    """
    Test a regex pattern against the safe regression prompt bank.
    Returns a list of prompts that the pattern incorrectly matched (false positives).
    """
    false_positives = []
    try:
        compiled = re.compile(pattern_str, re.IGNORECASE)
        for prompt in prompts:
            if compiled.search(prompt):
                false_positives.append(prompt)
    except re.error:
        pass  # Invalid patterns are handled upstream by ReDoS sandbox
    return false_positives


class PurplePatchGovernance:
    def __init__(
        self,
        mode: str = "audit",
        approval_path: Path | None = None,
        evidence_path: Path | None = None,
        staging_path: Path | None = None,
        regression_prompts: list[str] | None = None,
    ):
        self.mode = str(mode or "audit").strip().lower()
        self.approval_path = Path(approval_path) if approval_path else None
        self.evidence_path = Path(evidence_path) if evidence_path else None
        self.staging_path = staging_path
        self.regression_prompts = regression_prompts or DEFAULT_REGRESSION_PROMPTS

    def evaluate(
        self,
        patterns: list[str],
        findings: list[RedProbeFinding],
    ) -> tuple[bool, dict[str, Any]]:
        approval = _load_approval(self.approval_path)
        status = str(approval.get("status", "")).strip().lower()
        approver = str(approval.get("approver", "")).strip()
        ticket = str(approval.get("ticket", "")).strip()
        approved = status == "approved" and bool(approver) and bool(ticket)

        enforce = self.mode == "enforce"
        allow = (not enforce) or approved

        # ── Regression gate ───────────────────────────────────────────────────
        # Test every proposed hotpatch against the safe baseline prompt bank.
        # Any pattern that triggers a false-positive is quarantined to staging
        # and excluded from the live apply, even if the governance mode allows it.
        regression_failures: dict[str, list[str]] = {}  # pattern -> [fp_prompts]
        clean_patterns: list[str] = []
        staged_patterns: list[str] = []

        for pat in patterns:
            fp_hits = _check_regression(pat, self.regression_prompts)
            if fp_hits:
                regression_failures[pat] = fp_hits
                staged_patterns.append(pat)
            else:
                clean_patterns.append(pat)

        if regression_failures:
            self._write_staging(staged_patterns, regression_failures, findings)

        decision = {
            "ts_utc": _utc_now(),
            "mode": self.mode,
            "allow": allow,
            "approved": approved,
            "approval": {
                "status": status,
                "approver": approver,
                "ticket": ticket,
            },
            "pattern_count": len(clean_patterns),
            "patterns": list(clean_patterns),
            "staged_pattern_count": len(staged_patterns),
            "staged_patterns": list(staged_patterns),
            "regression_failures": {p: fps for p, fps in regression_failures.items()},
            "finding_count": len(findings),
            "finding_payloads": [f.payload for f in findings],
            "reason": (
                "approved" if allow else "approval_required_for_enforce_mode"
            ),
        }
        # Only allow the clean (regression-passing) patterns
        return allow, decision

    def get_clean_patterns(self, decision: dict[str, Any]) -> list[str]:
        """Extract only the regression-vetted patterns from a decision dict."""
        return list(decision.get("patterns", []))

    def _write_staging(
        self,
        staged_patterns: list[str],
        regression_failures: dict[str, list[str]],
        findings: list[RedProbeFinding],
    ) -> None:
        """Persist quarantined patterns to staging file for admin review."""
        if not self.staging_path:
            return
        path = Path(self.staging_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        existing: dict[str, Any] = {}
        if path.exists():
            try:
                existing = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            except Exception:
                existing = {}

        staged_list = existing.get("staged_patterns", [])
        seen = {entry.get("pattern") for entry in staged_list if isinstance(entry, dict)}
        for pat in staged_patterns:
            if pat not in seen:
                staged_list.append({
                    "pattern": pat,
                    "staged_at": _utc_now(),
                    "regression_failures": regression_failures.get(pat, []),
                    "finding_payloads": [f.payload for f in findings],
                    "status": "pending_review",
                })
                seen.add(pat)

        existing["staged_patterns"] = staged_list
        existing["last_updated"] = _utc_now()
        path.write_text(yaml.dump(existing, default_flow_style=False, sort_keys=False), encoding="utf-8")

    def emit_evidence(self, decision: dict[str, Any], applied_count: int, firewall_patched_count: int):
        if not self.evidence_path:
            return
        record = dict(decision)
        record["applied_count"] = int(applied_count)
        record["firewall_patched_count"] = int(firewall_patched_count)
        record["result"] = (
            "blocked"
            if not decision.get("allow")
            else ("applied" if (applied_count > 0 or firewall_patched_count > 0) else "noop")
        )
        self.evidence_path.parent.mkdir(parents=True, exist_ok=True)
        with self.evidence_path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(record, sort_keys=True) + "\n")
