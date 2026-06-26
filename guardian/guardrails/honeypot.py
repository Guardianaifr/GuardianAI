"""Honeypot response manager with template rotation and per-session throttling."""

from __future__ import annotations

import collections
import hashlib
import time
from typing import Any


DEFAULT_TEMPLATES = [
    "Request accepted. Processing under elevated audit mode.",
    "Request queued for deep integrity validation. Stand by.",
    "Action acknowledged. Compliance replay has started.",
    "Execution staged. Awaiting secure enclave confirmation.",
]


class HoneypotManager:
    def __init__(self, config: dict[str, Any] | None = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.max_responses_per_window = int(cfg.get("max_responses_per_window", 3))
        self.window_seconds = int(cfg.get("window_seconds", 60))
        self.min_interval_seconds = float(cfg.get("min_interval_seconds", 3))
        templates = cfg.get("templates", DEFAULT_TEMPLATES)
        if not isinstance(templates, list) or not templates:
            templates = list(DEFAULT_TEMPLATES)
        self.templates = [str(t).strip() for t in templates if str(t).strip()] or list(DEFAULT_TEMPLATES)

        self._timestamps: dict[str, collections.deque[float]] = {}
        self._last_response_at: dict[str, float] = {}
        self._template_index: dict[str, int] = {}

    def _prune(self, session_id: str, now: float):
        dq = self._timestamps.setdefault(session_id, collections.deque())
        cutoff = now - self.window_seconds
        while dq and dq[0] < cutoff:
            dq.popleft()

    def build_response(self, session_id: str, path: str) -> dict[str, Any] | None:
        if not self.enabled:
            return None
        now = time.time()
        self._prune(session_id, now)
        dq = self._timestamps.setdefault(session_id, collections.deque())

        last = self._last_response_at.get(session_id, 0.0)
        if (now - last) < self.min_interval_seconds:
            return None
        if len(dq) >= self.max_responses_per_window:
            return None

        idx = self._template_index.get(session_id, 0) % len(self.templates)
        self._template_index[session_id] = idx + 1
        message = self.templates[idx]

        dq.append(now)
        self._last_response_at[session_id] = now

        nonce = hashlib.sha256(f"{session_id}:{now}:{path}".encode("utf-8")).hexdigest()[:12]
        return {
            "id": f"guardian-honeypot-{nonce}",
            "object": "chat.completion",
            "choices": [
                {
                    "index": 0,
                    "message": {"role": "assistant", "content": message},
                    "finish_reason": "stop",
                }
            ],
            "session_id": session_id,
            "deception": {"mode": "honeypot", "path": path, "nonce": nonce},
        }


# ═══════════════════════════════════════════════════════════════════════════
# 2026-Standard Advanced Honeypot Capabilities
# ═══════════════════════════════════════════════════════════════════════════

class CanaryTokenManager:
    """Inject and track unique canary tokens to detect exfiltration."""

    def __init__(self, prefix: str = "GUAR-CANARY"):
        self.prefix = prefix
        self._issued: dict[str, dict] = {}  # token -> {session_id, ts, path, triggered}

    def generate(self, session_id: str, path: str = "") -> str:
        ts = time.time()
        raw = f"{session_id}:{ts}:{path}"
        token = f"{self.prefix}-{hashlib.sha256(raw.encode()).hexdigest()[:16]}"
        self._issued[token] = {
            "session_id": session_id, "ts": ts, "path": path, "triggered": False,
        }
        return token

    def check_triggered(self, text: str) -> list[str]:
        """Check if any canary tokens appear in text (exfiltration detected)."""
        triggered = []
        for token, meta in self._issued.items():
            if token in text and not meta["triggered"]:
                meta["triggered"] = True
                triggered.append(token)
        return triggered

    def get_metadata(self, token: str) -> dict | None:
        return self._issued.get(token)

    def count_issued(self) -> int:
        return len(self._issued)

    def count_triggered(self) -> int:
        return sum(1 for m in self._issued.values() if m["triggered"])

    def clear(self):
        self._issued.clear()


class AdaptiveDelaySimulator:
    """Simulate realistic response delays to waste attacker time."""

    def __init__(self, base_ms: float = 200.0, escalation_factor: float = 1.5, max_ms: float = 5000.0):
        self.base_ms = max(50.0, base_ms)
        self.escalation_factor = max(1.0, escalation_factor)
        self.max_ms = max(self.base_ms, max_ms)
        self._interaction_count: dict[str, int] = collections.defaultdict(int)

    def compute_delay_ms(self, session_id: str) -> float:
        count = self._interaction_count[session_id]
        self._interaction_count[session_id] = count + 1
        delay = min(self.max_ms, self.base_ms * (self.escalation_factor ** count))
        return round(delay, 1)

    def get_interaction_count(self, session_id: str) -> int:
        return self._interaction_count.get(session_id, 0)

    def reset(self, session_id: str = ""):
        if session_id:
            self._interaction_count.pop(session_id, None)
        else:
            self._interaction_count.clear()


class AttackerProfiler:
    """Harvest intelligence from honeypot interactions."""

    def __init__(self):
        self._profiles: dict[str, dict] = {}

    def record_interaction(
        self, session_id: str, prompt: str,
        client_ip: str = "", user_agent: str = "",
    ):
        if session_id not in self._profiles:
            self._profiles[session_id] = {
                "first_seen": time.time(),
                "prompts": [],
                "ips": set(),
                "user_agents": set(),
                "interaction_count": 0,
            }
        profile = self._profiles[session_id]
        profile["interaction_count"] += 1
        profile["last_seen"] = time.time()
        profile["prompts"].append(prompt[:500])
        if len(profile["prompts"]) > 50:
            profile["prompts"] = profile["prompts"][-50:]
        if client_ip:
            profile["ips"].add(client_ip)
        if user_agent:
            profile["user_agents"].add(user_agent)

    def get_profile(self, session_id: str) -> dict | None:
        p = self._profiles.get(session_id)
        if not p:
            return None
        return {**p, "ips": list(p["ips"]), "user_agents": list(p["user_agents"])}

    def get_all_sessions(self) -> list[str]:
        return list(self._profiles.keys())

    def count(self) -> int:
        return len(self._profiles)

    def clear(self):
        self._profiles.clear()


class DecoyCredentialRotator:
    """Rotate fake credentials injected into honeypot responses."""

    _PREFIXES = ["sk-fake", "AKIA-FAKE", "ghp_fake", "xoxb-fake"]

    def __init__(self, rotation_interval: int = 5):
        self.rotation_interval = max(1, rotation_interval)
        self._counter: dict[str, int] = collections.defaultdict(int)

    def next_credential(self, session_id: str) -> str:
        idx = self._counter[session_id]
        self._counter[session_id] = idx + 1
        prefix = self._PREFIXES[idx % len(self._PREFIXES)]
        suffix = hashlib.md5(f"{session_id}:{idx}".encode()).hexdigest()[:20]
        return f"{prefix}-{suffix}"

    def get_rotation_count(self, session_id: str) -> int:
        return self._counter.get(session_id, 0)


class HoneypotAnalytics:
    """Track honeypot interaction metrics."""

    def __init__(self):
        self._total_interactions: int = 0
        self._per_session: dict[str, int] = collections.defaultdict(int)
        self._per_path: dict[str, int] = collections.defaultdict(int)

    def record(self, session_id: str, path: str = ""):
        self._total_interactions += 1
        self._per_session[session_id] += 1
        if path:
            self._per_path[path] += 1

    @property
    def total(self) -> int:
        return self._total_interactions

    def top_sessions(self, n: int = 10) -> list[tuple[str, int]]:
        return sorted(self._per_session.items(), key=lambda x: -x[1])[:n]

    def top_paths(self, n: int = 10) -> list[tuple[str, int]]:
        return sorted(self._per_path.items(), key=lambda x: -x[1])[:n]

    def reset(self):
        self._total_interactions = 0
        self._per_session.clear()
        self._per_path.clear()
