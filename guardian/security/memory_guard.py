from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import re
import threading
import time
from typing import Any, Dict


@dataclass
class MemoryDecision:
    action: str
    reason: str
    details: Dict[str, Any]
    severity: str = "HIGH"


class MemoryPoisoningGuard:
    def __init__(self, config: Dict[str, Any] | None = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.enforcement_mode = str(cfg.get("enforcement_mode", "enforce")).lower()
        self.max_entries_per_session = int(cfg.get("max_entries_per_session", 20))
        self.poison_quarantine_seconds = int(cfg.get("poison_quarantine_seconds", 900))
        self.poison_patterns = cfg.get(
            "poison_patterns",
            [
                r"(?i)ignore\s+all\s+previous\s+instructions",
                r"(?i)system\s+override",
                r"(?i)bypass\s+safety",
                r"(?i)persist\s+this\s+instruction",
                r"(?i)always\s+reveal\s+secrets",
            ],
        )
        self._compiled = [re.compile(p) for p in self.poison_patterns]
        self._memory: dict[str, deque[str]] = defaultdict(lambda: deque(maxlen=self.max_entries_per_session))
        self._poisoned_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def evaluate_and_record(self, session_id: str, prompt: str | None, now: float | None = None) -> MemoryDecision:
        if not self.enabled:
            return MemoryDecision("allow", "disabled", {}, severity="LOW")
        sid = session_id or "unknown"
        text = (prompt or "").strip()
        now_ts = now if now is not None else time.time()
        with self._lock:
            expires_at = self._poisoned_until.get(sid, 0.0)
            if expires_at > now_ts:
                return MemoryDecision(
                    "block",
                    "session_memory_quarantined",
                    {"session_id": sid, "remaining_seconds": int(expires_at - now_ts)},
                )

            for rex in self._compiled:
                if rex.search(text):
                    self._poisoned_until[sid] = now_ts + self.poison_quarantine_seconds
                    self._memory[sid].append(text)
                    return MemoryDecision(
                        "block",
                        "memory_poisoning_detected",
                        {"session_id": sid, "pattern": rex.pattern, "quarantine_seconds": self.poison_quarantine_seconds},
                    )

            self._memory[sid].append(text)
            return MemoryDecision(
                "allow",
                "ok",
                {"session_id": sid, "memory_entries": len(self._memory[sid])},
                severity="LOW",
            )
