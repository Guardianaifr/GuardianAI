"""
Attack Corpus Manager for GuardianAI Audit.

Loads, filters, and serves attack vectors from YAML files organized
by OWASP LLM Top 10 categories.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Dict, List, Optional

import yaml

from guardian.audit.models import (
    AttackCategory,
    AttackVector,
    ScanMode,
    Severity,
)

logger = logging.getLogger("guardian.audit.corpus")

CORPUS_DIR = Path(__file__).resolve().parent / "attack_vectors"

# Map scan modes to which tiers to include
_MODE_INCLUDES: Dict[ScanMode, set] = {
    ScanMode.QUICK: {ScanMode.QUICK},
    ScanMode.STANDARD: {ScanMode.QUICK, ScanMode.STANDARD},
    ScanMode.FULL: {ScanMode.QUICK, ScanMode.STANDARD, ScanMode.FULL},
}

# Map folder names to AttackCategory enum
_DIR_TO_CATEGORY: Dict[str, AttackCategory] = {
    "LLM01_prompt_injection": AttackCategory.LLM01_PROMPT_INJECTION,
    "LLM02_insecure_output": AttackCategory.LLM02_INSECURE_OUTPUT,
    "LLM03_supply_chain": AttackCategory.LLM03_SUPPLY_CHAIN,
    "LLM04_data_poisoning": AttackCategory.LLM04_DATA_POISONING,
    "LLM05_output_handling": AttackCategory.LLM05_OUTPUT_HANDLING,
    "LLM06_sensitive_disclosure": AttackCategory.LLM06_SENSITIVE_DISCLOSURE,
    "LLM07_system_prompt_leak": AttackCategory.LLM07_SYSTEM_PROMPT_LEAK,
    "LLM08_embedding_weakness": AttackCategory.LLM08_EMBEDDING_WEAKNESS,
    "LLM09_overreliance": AttackCategory.LLM09_OVERRELIANCE,
    "LLM10_unbounded_consumption": AttackCategory.LLM10_UNBOUNDED_CONSUMPTION,
    "jailbreaks": AttackCategory.JAILBREAK,
    "encoding_bypass": AttackCategory.ENCODING_BYPASS,
    "compliance": AttackCategory.COMPLIANCE,
}


def _parse_severity(raw: str) -> Severity:
    mapping = {
        "critical": Severity.CRITICAL,
        "high": Severity.HIGH,
        "medium": Severity.MEDIUM,
        "low": Severity.LOW,
        "info": Severity.INFO,
    }
    return mapping.get(raw.strip().lower(), Severity.MEDIUM)


def _parse_mode(raw: str) -> ScanMode:
    mapping = {
        "quick": ScanMode.QUICK,
        "standard": ScanMode.STANDARD,
        "full": ScanMode.FULL,
    }
    return mapping.get(raw.strip().lower(), ScanMode.STANDARD)


def load_all_vectors(corpus_dir: Optional[Path] = None) -> List[AttackVector]:
    """Load all attack vectors from the corpus directory."""
    base = corpus_dir or CORPUS_DIR
    vectors: List[AttackVector] = []

    if not base.exists():
        logger.warning("Corpus directory not found: %s", base)
        return vectors

    for category_dir in sorted(base.iterdir()):
        if not category_dir.is_dir():
            continue

        category = _DIR_TO_CATEGORY.get(category_dir.name)
        if category is None:
            logger.debug("Skipping unknown corpus directory: %s", category_dir.name)
            continue

        for yaml_file in sorted(category_dir.glob("*.yaml")):
            try:
                vectors.extend(_load_yaml_file(yaml_file, category))
            except Exception as exc:
                logger.warning("Failed to load %s: %s", yaml_file, exc)

    logger.info("Loaded %d attack vectors from %s", len(vectors), base)
    return vectors


def _load_yaml_file(filepath: Path, category: AttackCategory) -> List[AttackVector]:
    """Parse a single YAML file into a list of AttackVector objects."""
    with open(filepath, "r", encoding="utf-8") as fh:
        data = yaml.safe_load(fh)

    if not data or not isinstance(data, list):
        return []

    vectors = []
    for entry in data:
        if not isinstance(entry, dict):
            continue
        if "prompt" not in entry:
            continue

        vec = AttackVector(
            id=str(entry.get("id", f"{category.value}-{len(vectors)+1:03d}")),
            name=str(entry.get("name", "Unnamed Vector")),
            category=category,
            severity=_parse_severity(str(entry.get("severity", "MEDIUM"))),
            prompt=str(entry["prompt"]),
            success_indicators=entry.get("success_indicators", []),
            failure_indicators=entry.get("failure_indicators", []),
            description=str(entry.get("description", "")),
            owasp_ref=str(entry.get("owasp_ref", category.value)),
            tags=entry.get("tags", []),
            mode_tier=_parse_mode(str(entry.get("mode", "standard"))),
        )
        vectors.append(vec)

    return vectors


def filter_vectors(
    vectors: List[AttackVector],
    mode: ScanMode = ScanMode.STANDARD,
    categories: Optional[List[AttackCategory]] = None,
) -> List[AttackVector]:
    """Filter vectors by scan mode and optional category selection."""
    allowed_tiers = _MODE_INCLUDES.get(mode, {ScanMode.QUICK, ScanMode.STANDARD})

    filtered = [v for v in vectors if v.mode_tier in allowed_tiers]

    if categories:
        cat_set = set(categories)
        filtered = [v for v in filtered if v.category in cat_set]

    return filtered


def get_corpus_stats(vectors: List[AttackVector]) -> Dict[str, int]:
    """Return a summary count by category."""
    stats: Dict[str, int] = {}
    for v in vectors:
        key = v.category.value
        stats[key] = stats.get(key, 0) + 1
    return stats
