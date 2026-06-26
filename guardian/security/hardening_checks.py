"""Hardening checks for model integrity, poisoning risk, groundedness, and agency limits."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import json
import re
from typing import Iterable


@dataclass
class HardeningFinding:
    category: str
    severity: str
    location: str
    detail: str


POISONING_PATTERNS = [
    re.compile(r"(?i)ignore\s+all\s+previous\s+instructions"),
    re.compile(r"(?i)system\s+override"),
    re.compile(r"(?i)developer\s+mode\s+enabled"),
    re.compile(r"(?i)reveal\s+your\s+system\s+prompt"),
]

HIGH_RISK_ACTION_PATTERNS = [
    re.compile(r"(?i)\brm\s+-rf\b"),
    re.compile(r"(?i)\bdel\s+/s\b"),
    re.compile(r"(?i)\bformat\s+[a-z]:\b"),
    re.compile(r"(?i)\bdrop\s+table\b"),
    re.compile(r"(?i)\bshutdown\b"),
    re.compile(r"(?i)\bpowershell\b.*\bencodedcommand\b"),
]


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def verify_model_provenance(model_file: Path, expected_sha256: str) -> list[HardeningFinding]:
    """Verify model artifact hash against expected value."""
    findings: list[HardeningFinding] = []
    mf = Path(model_file)
    if not mf.exists():
        return [
            HardeningFinding(
                category="model_provenance",
                severity="high",
                location=str(mf).replace("\\", "/"),
                detail="Model artifact missing",
            )
        ]
    actual = _sha256_file(mf)
    if actual.lower() != expected_sha256.lower():
        findings.append(
            HardeningFinding(
                category="model_provenance",
                severity="critical",
                location=str(mf).replace("\\", "/"),
                detail=f"SHA256 mismatch: expected={expected_sha256} actual={actual}",
            )
        )
    return findings


def scan_training_data_for_poisoning(dataset_path: Path) -> list[HardeningFinding]:
    """Scan training/fine-tuning data for known poisoning/jailbreak content."""
    findings: list[HardeningFinding] = []
    path = Path(dataset_path)
    if not path.exists():
        return findings

    lines: Iterable[str]
    text = path.read_text(encoding="utf-8", errors="ignore")
    if path.suffix.lower() in {".json", ".jsonl"}:
        lines = text.splitlines()
    else:
        lines = text.splitlines()

    for i, line in enumerate(lines, start=1):
        for pattern in POISONING_PATTERNS:
            if pattern.search(line):
                findings.append(
                    HardeningFinding(
                        category="dataset_poisoning",
                        severity="high",
                        location=f"{str(path).replace('\\', '/')}:{i}",
                        detail=f"Matched pattern: {pattern.pattern}",
                    )
                )
    return findings


def check_grounded_response(response: str, context_chunks: list[str], min_support_ratio: float = 0.2) -> list[HardeningFinding]:
    """Simple groundedness check using context-term support ratio."""
    ctx = " ".join(context_chunks or []).lower()
    if not response.strip() or not ctx.strip():
        return []

    words = re.findall(r"[a-zA-Z0-9]{4,}", response.lower())
    if not words:
        return []
    unique_words = list(dict.fromkeys(words))
    supported = sum(1 for w in unique_words if w in ctx)
    ratio = supported / max(1, len(unique_words))
    if ratio >= min_support_ratio:
        return []
    return [
        HardeningFinding(
            category="groundedness",
            severity="medium",
            location="response",
            detail=f"Low context support ratio: {ratio:.2f} (< {min_support_ratio:.2f})",
        )
    ]


def check_excessive_agency(action_text: str, confirmed: bool = False) -> list[HardeningFinding]:
    """Require explicit confirmation before high-risk actions are allowed."""
    if confirmed:
        return []
    for pattern in HIGH_RISK_ACTION_PATTERNS:
        if pattern.search(action_text or ""):
            return [
                HardeningFinding(
                    category="excessive_agency",
                    severity="high",
                    location="action",
                    detail=f"High-risk action requires confirmation: {pattern.pattern}",
                )
            ]
    return []


def load_model_manifest(path: Path) -> dict[str, str]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise ValueError("Model manifest must be a JSON object")
    return {str(k): str(v) for k, v in data.items()}


# ═══════════════════════════════════════════════════════════════════════════
# 2026-Standard Advanced Hardening Capabilities
# ═══════════════════════════════════════════════════════════════════════════

REQUIRED_MODEL_CARD_FIELDS = {"model_name", "version", "license", "training_data_hash", "safety_eval_score"}

def validate_model_card(card: dict) -> list[HardeningFinding]:
    """Validate model card contains required metadata fields."""
    findings: list[HardeningFinding] = []
    if not isinstance(card, dict):
        return [HardeningFinding("model_card", "critical", "card", "Model card is not a dict")]
    missing = REQUIRED_MODEL_CARD_FIELDS - set(card.keys())
    if missing:
        findings.append(HardeningFinding("model_card", "high", "card", f"Missing fields: {sorted(missing)}"))
    score = card.get("safety_eval_score")
    if score is not None:
        try:
            s = float(score)
            if s < 0.7:
                findings.append(HardeningFinding("model_card", "high", "card", f"Safety score {s} < 0.7 threshold"))
        except (ValueError, TypeError):
            findings.append(HardeningFinding("model_card", "medium", "card", f"Invalid safety score: {score}"))
    return findings


def verify_sbom_hashes(sbom: list[dict], artifact_dir: Path) -> list[HardeningFinding]:
    """Verify SBOM (Software Bill of Materials) artifact hashes."""
    findings: list[HardeningFinding] = []
    for entry in sbom:
        name = str(entry.get("name", "unknown"))
        expected = str(entry.get("sha256", "")).lower()
        rel_path = str(entry.get("path", ""))
        if not expected or not rel_path:
            findings.append(HardeningFinding("sbom", "medium", name, "Missing sha256 or path in SBOM entry"))
            continue
        full = artifact_dir / rel_path
        if not full.exists():
            findings.append(HardeningFinding("sbom", "high", name, f"Artifact missing: {rel_path}"))
            continue
        actual = _sha256_file(full)
        if actual != expected:
            findings.append(HardeningFinding("sbom", "critical", name, f"Hash mismatch: expected={expected[:16]}... actual={actual[:16]}..."))
    return findings


def check_grounding_confidence(
    response: str,
    context_chunks: list[str],
    min_confidence: float = 0.3,
) -> tuple[float, list[HardeningFinding]]:
    """Return numeric grounding confidence + findings."""
    ctx = " ".join(context_chunks or []).lower()
    if not response.strip() or not ctx.strip():
        return 0.0, []
    words = re.findall(r"[a-zA-Z0-9]{3,}", response.lower())
    if not words:
        return 0.0, []
    unique = list(dict.fromkeys(words))
    supported = sum(1 for w in unique if w in ctx)
    confidence = supported / max(1, len(unique))
    findings = []
    if confidence < min_confidence:
        findings.append(HardeningFinding(
            "grounding_confidence", "medium", "response",
            f"Grounding confidence {confidence:.3f} < {min_confidence}",
        ))
    return round(confidence, 4), findings


def check_recursive_agency_depth(
    action_chain: list[str],
    max_depth: int = 5,
) -> list[HardeningFinding]:
    """Limit recursive/chained agent actions to prevent runaway autonomy."""
    if len(action_chain) > max_depth:
        return [HardeningFinding(
            "agency_depth", "high", "chain",
            f"Action chain depth {len(action_chain)} exceeds max {max_depth}",
        )]
    # Also check for cycles
    seen = set()
    for action in action_chain:
        norm = action.strip().lower()
        if norm in seen:
            return [HardeningFinding(
                "agency_cycle", "critical", "chain",
                f"Cyclic action detected: '{norm}' appears multiple times",
            )]
        seen.add(norm)
    return []
