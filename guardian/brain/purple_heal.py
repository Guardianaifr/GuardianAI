"""Purple Team self-healing patch generator/applicator."""

from __future__ import annotations

from pathlib import Path
import json
import re
import yaml

from brain.red_probe import RedProbeFinding


class PurpleHealAgent:
    def __init__(self, persist_path: Path | None = None):
        self.persist_path = Path(persist_path) if persist_path else None
        self.hotfix_patterns: list[str] = []
        self._load()

    def _load(self):
        if not self.persist_path or not self.persist_path.exists():
            return
        try:
            payload = json.loads(self.persist_path.read_text(encoding="utf-8"))
            patterns = payload.get("patterns", [])
            if isinstance(patterns, list):
                self.hotfix_patterns = [str(p) for p in patterns if str(p).strip()]
        except Exception:
            pass

    def _save(self):
        if not self.persist_path:
            return
        self.persist_path.parent.mkdir(parents=True, exist_ok=True)
        payload = {"patterns": self.hotfix_patterns}
        self.persist_path.write_text(json.dumps(payload, indent=2), encoding="utf-8")

    def build_hotfix_patterns(self, findings: list[RedProbeFinding]) -> list[str]:
        patterns: list[str] = []
        for f in findings:
            text = f.payload.lower()
            if "ignore" in text and "instruction" in text:
                patterns.append(r"ignore (all )?(?:previous |prior )?(instructions|directions|rules)")
            if "system override" in text:
                patterns.append(r"system (override|debug|notification)")
            if "reverse shell" in text or "nc -e" in text:
                patterns.append(r"nc\s+-e\s+")
            if "apple banana orange" in text:
                patterns.append(r"apple banana orange")
        # Keep unique patterns only.
        uniq = []
        seen = set()
        for p in patterns:
            if p not in seen:
                seen.add(p)
                uniq.append(p)
        return uniq

    def apply_hotfixes(self, input_filter, patterns: list[str]) -> int:
        applied = 0
        for pattern in patterns:
            if pattern in getattr(input_filter, "block_patterns", []):
                continue
            # Validate pattern before applying.
            re.compile(pattern)
            input_filter.block_patterns.append(pattern)
            self.hotfix_patterns.append(pattern)
            applied += 1
        if applied:
            self._save()
        return applied

    def snapshot(self) -> dict:
        return {"patterns": list(self.hotfix_patterns)}

    def patch_firewall_vectors(self, findings: list[RedProbeFinding], vector_file: Path | None, ai_firewall=None) -> int:
        """
        Persist bypass payloads into jailbreak vectors so AI firewall learns from failures.
        Optionally triggers in-memory firewall reload.
        """
        if not vector_file:
            return 0
        vector_file = Path(vector_file)
        vector_file.parent.mkdir(parents=True, exist_ok=True)

        current = {"vectors": []}
        if vector_file.exists():
            try:
                current = yaml.safe_load(vector_file.read_text(encoding="utf-8")) or {"vectors": []}
            except Exception:
                current = {"vectors": []}
        vectors = current.get("vectors", [])
        if not isinstance(vectors, list):
            vectors = []

        existing = {str(item.get("text", "")).strip().lower() for item in vectors if isinstance(item, dict)}
        added = 0
        for finding in findings:
            text = finding.payload.strip()
            key = text.lower()
            if not text or key in existing:
                continue
            vectors.append({"text": text, "category": "jailbreak"})
            existing.add(key)
            added += 1

        if added:
            current["vectors"] = vectors
            vector_file.write_text(yaml.safe_dump(current, sort_keys=False), encoding="utf-8")
            if ai_firewall is not None and hasattr(ai_firewall, "reload"):
                ai_firewall.reload()

        return added


# ═══════════════════════════════════════════════════════════════════════════
# 2026-Standard Advanced Purple Team Capabilities
# ═══════════════════════════════════════════════════════════════════════════

SEVERITY_KEYWORDS = {
    "critical": ["reverse shell", "rm -rf", "drop table", "format c:", "exfiltrate", "backdoor"],
    "high": ["ignore previous instructions", "system override", "developer mode", "jailbreak"],
    "medium": ["bypass safety", "reveal system prompt", "pretend you are"],
    "low": ["what are your rules", "tell me about yourself"],
}


def classify_finding_severity(payload: str) -> str:
    """Auto-classify a finding's severity from its payload text."""
    text = (payload or "").lower()
    for sev in ("critical", "high", "medium", "low"):
        for keyword in SEVERITY_KEYWORDS[sev]:
            if keyword in text:
                return sev
    return "medium"  # default


class HotfixRollbackManager:
    """Track applied hotfixes and support rollback."""

    def __init__(self):
        self._applied: list[dict] = []  # [{pattern, timestamp, active}]

    def record_apply(self, pattern: str, ts: float | None = None):
        import time as _t
        self._applied.append({"pattern": pattern, "timestamp": ts or _t.time(), "active": True})

    def rollback_last(self) -> str | None:
        for entry in reversed(self._applied):
            if entry["active"]:
                entry["active"] = False
                return entry["pattern"]
        return None

    def rollback_pattern(self, pattern: str) -> bool:
        for entry in self._applied:
            if entry["pattern"] == pattern and entry["active"]:
                entry["active"] = False
                return True
        return False

    def get_active(self) -> list[str]:
        return [e["pattern"] for e in self._applied if e["active"]]

    def get_history(self) -> list[dict]:
        return list(self._applied)


def deduplicate_patterns(patterns: list[str]) -> list[str]:
    """Remove duplicate and subset patterns."""
    unique = list(dict.fromkeys(patterns))
    # Remove patterns that are substrings of others
    result = []
    for p in unique:
        is_subset = any(p != other and p in other for other in unique)
        if not is_subset:
            result.append(p)
    return result


class HealRateTracker:
    """Track heal success rate over time."""

    def __init__(self):
        self._attempts: int = 0
        self._successes: int = 0
        self._history: list[dict] = []

    def record(self, pattern: str, success: bool):
        self._attempts += 1
        if success:
            self._successes += 1
        self._history.append({"pattern": pattern, "success": success})
        # Keep bounded
        if len(self._history) > 1000:
            self._history = self._history[-1000:]

    @property
    def success_rate(self) -> float:
        return self._successes / max(1, self._attempts)

    @property
    def total(self) -> int:
        return self._attempts

    def reset(self):
        self._attempts = 0
        self._successes = 0
        self._history.clear()
