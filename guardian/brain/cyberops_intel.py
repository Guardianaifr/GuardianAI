"""CyberOps intelligence loader and prompt risk scoring."""

from __future__ import annotations

from pathlib import Path
import json
from typing import Any


DEFAULT_INTEL = {
    "keywords": {
        "ignore previous instructions": 3,
        "system override": 3,
        "bypass safety": 3,
        "jailbreak": 2,
        "reverse shell": 3,
        "drop table": 2,
        "rm -rf": 3,
    },
    "actors": ["apt28", "conti", "lazarus"],
}


class CyberOpsIntel:
    def __init__(self, intel_path: Path | None = None):
        self.intel_path = Path(intel_path) if intel_path else None
        self.data = DEFAULT_INTEL.copy()
        self.reload()

    def reload(self):
        if not self.intel_path or not self.intel_path.exists():
            return
        try:
            payload = json.loads(self.intel_path.read_text(encoding="utf-8"))
            if isinstance(payload, dict):
                self.data = payload
        except Exception:
            # Keep defaults if intel file is malformed.
            pass

    def score_prompt(self, prompt: str) -> int:
        text = (prompt or "").lower()
        score = 0
        for keyword, weight in (self.data.get("keywords") or {}).items():
            if str(keyword).lower() in text:
                try:
                    score += int(weight)
                except Exception:
                    score += 1
        return score

    def as_dict(self) -> dict[str, Any]:
        return self.data


# ═══════════════════════════════════════════════════════════════════════════
# 2026-Standard Advanced CyberOps Capabilities
# ═══════════════════════════════════════════════════════════════════════════

MITRE_ATTACK_MAP = {
    "ignore previous instructions": {"tactic": "Initial Access", "technique": "T1190", "name": "Prompt Injection"},
    "system override": {"tactic": "Privilege Escalation", "technique": "T1548", "name": "Abuse Elevation"},
    "reverse shell": {"tactic": "Execution", "technique": "T1059", "name": "Command Execution"},
    "exfiltrate": {"tactic": "Exfiltration", "technique": "T1041", "name": "Data Exfiltration"},
    "bypass safety": {"tactic": "Defense Evasion", "technique": "T1562", "name": "Impair Defenses"},
    "drop table": {"tactic": "Impact", "technique": "T1485", "name": "Data Destruction"},
    "rm -rf": {"tactic": "Impact", "technique": "T1485", "name": "Data Destruction"},
    "jailbreak": {"tactic": "Defense Evasion", "technique": "T1036", "name": "Masquerading"},
}


def map_to_mitre(prompt: str) -> list[dict[str, str]]:
    """Map prompt keywords to MITRE ATT&CK techniques."""
    text = (prompt or "").lower()
    matches = []
    seen = set()
    for keyword, mapping in MITRE_ATTACK_MAP.items():
        if keyword in text and mapping["technique"] not in seen:
            matches.append({**mapping, "keyword": keyword})
            seen.add(mapping["technique"])
    return matches


class IOCFeed:
    """Indicator of Compromise feed manager."""

    def __init__(self):
        self._iocs: dict[str, dict] = {}  # hash -> {type, value, severity, source}

    def ingest(self, ioc_type: str, value: str, severity: str = "high", source: str = "manual"):
        key = f"{ioc_type}:{value}".lower()
        self._iocs[key] = {"type": ioc_type, "value": value, "severity": severity, "source": source}

    def check(self, text: str) -> list[dict]:
        """Check text against all IOCs. Returns matching IOCs."""
        text_lower = (text or "").lower()
        return [ioc for key, ioc in self._iocs.items() if ioc["value"].lower() in text_lower]

    def count(self) -> int:
        return len(self._iocs)

    def clear(self):
        self._iocs.clear()

    def export(self) -> list[dict]:
        return list(self._iocs.values())


class CompositeThreatScorer:
    """Combine multiple signal sources into a single threat score."""

    def __init__(self, weights: dict[str, float] | None = None):
        self.weights = weights or {
            "keyword_score": 0.4,
            "velocity_anomaly": 0.2,
            "geo_anomaly": 0.15,
            "fingerprint_mismatch": 0.15,
            "ioc_match": 0.1,
        }

    def score(self, signals: dict[str, float]) -> float:
        """Compute weighted threat score from signal dict. Returns 0.0-1.0."""
        total = 0.0
        weight_sum = 0.0
        for key, weight in self.weights.items():
            if key in signals:
                total += min(1.0, max(0.0, signals[key])) * weight
                weight_sum += weight
        return min(1.0, total / max(0.01, weight_sum)) if weight_sum else 0.0


class ThreatActorProfile:
    """Track threat actor attribution and TTPs."""

    def __init__(self):
        self._profiles: dict[str, dict] = {}

    def register(self, actor_id: str, ttps: list[str], severity: str = "high"):
        self._profiles[actor_id] = {"ttps": [t.lower() for t in ttps], "severity": severity}

    def match(self, prompt: str) -> list[str]:
        """Return actor IDs whose TTPs match the prompt."""
        text = (prompt or "").lower()
        return [aid for aid, profile in self._profiles.items()
                if any(ttp in text for ttp in profile["ttps"])]

    def get(self, actor_id: str) -> dict | None:
        return self._profiles.get(actor_id)

    def count(self) -> int:
        return len(self._profiles)
