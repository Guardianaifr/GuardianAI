"""Cost-abuse anomaly detection and session quarantine controls."""

from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass
import json
import threading
import time
from typing import Any


@dataclass
class CostAbuseDecision:
    action: str
    reason: str
    metrics: dict[str, Any]


class CostAbuseDetector:
    def __init__(self, config: dict[str, Any] | None = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.window_seconds = int(cfg.get("window_seconds", 120))
        self.min_events = max(1, int(cfg.get("min_events", 3)))
        self.max_tokens_per_window = int(cfg.get("max_tokens_per_window", 12000))
        self.max_cost_usd_per_window = float(cfg.get("max_cost_usd_per_window", 0.60))
        self.spike_multiplier = float(cfg.get("spike_multiplier", 3.5))
        self.quarantine_seconds = int(cfg.get("quarantine_seconds", 900))
        self.cost_per_1k_tokens_usd = float(cfg.get("cost_per_1k_tokens_usd", 0.01))
        self.tenant_window_seconds = int(cfg.get("tenant_window_seconds", self.window_seconds))
        self.min_sessions_for_tenant_anomaly = max(2, int(cfg.get("min_sessions_for_tenant_anomaly", 3)))
        self.max_tokens_per_tenant_window = int(cfg.get("max_tokens_per_tenant_window", self.max_tokens_per_window * 5))
        self.max_cost_usd_per_tenant_window = float(
            cfg.get("max_cost_usd_per_tenant_window", self.max_cost_usd_per_window * 5.0)
        )
        self.min_tokens_per_session_for_slow_drain = int(cfg.get("min_tokens_per_session_for_slow_drain", 100))
        self.min_cost_per_session_for_slow_drain = float(cfg.get("min_cost_per_session_for_slow_drain", 0.001))
        
        self.max_tracked_sessions = int(cfg.get("max_tracked_sessions", 10000))
        self.max_tracked_tenants = int(cfg.get("max_tracked_tenants", 1000))

        self._events: dict[str, deque[tuple[float, int, float]]] = defaultdict(deque)
        self._tenant_events: dict[str, deque[tuple[float, str, int, float]]] = defaultdict(deque)
        self._quarantined_until: dict[str, float] = {}
        self._lock = threading.Lock()

    def _session_key(self, session_id: str | None) -> str:
        return session_id or "unknown"

    def _prune(self, session_id: str, now: float):
        bucket = self._events[session_id]
        cutoff = now - self.window_seconds
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

    def _prune_tenant(self, tenant_id: str, now: float):
        bucket = self._tenant_events[tenant_id]
        cutoff = now - self.tenant_window_seconds
        while bucket and bucket[0][0] < cutoff:
            bucket.popleft()

    def _enforce_capacity(self, now: float):
        if len(self._events) > self.max_tracked_sessions:
            candidates = []
            for sid, q in self._events.items():
                if self._quarantined_until.get(sid, 0.0) > now:
                    continue  # EXEMPT: never evict active quarantines
                last_ts = q[-1][0] if q else 0.0
                candidates.append((sid, last_ts))
            
            candidates.sort(key=lambda x: x[1])
            to_remove = len(self._events) - self.max_tracked_sessions
            for sid, _ in candidates[:to_remove]:
                self._events.pop(sid, None)
                self._quarantined_until.pop(sid, None)

        if len(self._tenant_events) > self.max_tracked_tenants:
            tenant_candidates = []
            for tid, q in self._tenant_events.items():
                last_ts = q[-1][0] if q else 0.0
                tenant_candidates.append((tid, last_ts))
            
            tenant_candidates.sort(key=lambda x: x[1])
            t_to_remove = len(self._tenant_events) - self.max_tracked_tenants
            for tid, _ in tenant_candidates[:t_to_remove]:
                self._tenant_events.pop(tid, None)

    def _parse_usage_tokens(self, response_text: str) -> int | None:
        if not response_text:
            return None
        try:
            payload = json.loads(response_text)
        except Exception:
            return None
        if not isinstance(payload, dict):
            return None
        usage = payload.get("usage")
        if isinstance(usage, dict):
            total = usage.get("total_tokens")
            if isinstance(total, int) and total > 0:
                return total
        return None

    def estimate_usage(self, prompt: str | None, response_text: str | None) -> tuple[int, float]:
        response_text = response_text or ""
        measured_tokens = self._parse_usage_tokens(response_text)
        if measured_tokens is None:
            approx_chars = len(prompt or "") + len(response_text)
            measured_tokens = max(1, int(approx_chars / 4))
        estimated_cost = (measured_tokens / 1000.0) * self.cost_per_1k_tokens_usd
        return measured_tokens, estimated_cost

    def is_quarantined(self, session_id: str | None, now: float | None = None) -> tuple[bool, int]:
        sid = self._session_key(session_id)
        now = now if now is not None else time.time()
        with self._lock:
            expires_at = self._quarantined_until.get(sid, 0.0)
            if expires_at <= now:
                self._quarantined_until.pop(sid, None)
                return False, 0
            return True, max(1, int(expires_at - now))

    def register_usage(
        self,
        session_id: str | None,
        tokens: int,
        cost_usd: float,
        tenant_id: str | None = None,
        now: float | None = None,
    ) -> CostAbuseDecision:
        sid = self._session_key(session_id)
        tid = (tenant_id or "default").strip() or "default"
        now = now if now is not None else time.time()
        tokens = max(0, int(tokens))
        cost_usd = max(0.0, float(cost_usd))

        with self._lock:
            expires_at = self._quarantined_until.get(sid, 0.0)
            if expires_at > now:
                return CostAbuseDecision(
                    action="quarantined",
                    reason="Session currently quarantined due to prior cost-abuse anomaly.",
                    metrics={
                        "session_id": sid,
                        "quarantine_remaining_seconds": int(expires_at - now),
                    },
                )

            self._prune(sid, now)
            prior_tokens = [entry[1] for entry in self._events[sid]]
            baseline_tokens = (sum(prior_tokens) / len(prior_tokens)) if prior_tokens else 0.0

            self._events[sid].append((now, tokens, cost_usd))
            self._prune(sid, now)
            self._tenant_events[tid].append((now, sid, tokens, cost_usd))
            self._prune_tenant(tid, now)
            
            # FEAT-TENANT-INMEM-HARDEN: Bounded capacity enforcement
            self._enforce_capacity(now)

            total_events = len(self._events[sid])
            total_tokens = sum(entry[1] for entry in self._events[sid])
            total_cost = sum(entry[2] for entry in self._events[sid])
            spike_ratio = (float(tokens) / baseline_tokens) if baseline_tokens > 0 else 1.0
            tenant_bucket = self._tenant_events[tid]
            tenant_tokens = sum(entry[2] for entry in ((t, s, tok, c) for t, s, tok, c in tenant_bucket))
            tenant_cost = sum(entry[3] for entry in tenant_bucket)
            tenant_sessions = {entry[1] for entry in tenant_bucket}
            tenant_active_sessions = len(tenant_sessions)

            # Session contribution in tenant window (used for slow-drain confidence).
            session_tokens_in_tenant_window = sum(entry[2] for entry in tenant_bucket if entry[1] == sid)
            session_cost_in_tenant_window = sum(entry[3] for entry in tenant_bucket if entry[1] == sid)

            exceeded = []
            if total_events >= self.min_events and total_tokens >= self.max_tokens_per_window:
                exceeded.append("tokens_per_window")
            if total_events >= self.min_events and total_cost >= self.max_cost_usd_per_window:
                exceeded.append("cost_per_window")
            if (
                total_events >= self.min_events
                and baseline_tokens > 0
                and spike_ratio >= self.spike_multiplier
            ):
                exceeded.append("token_spike")
            if (
                tenant_active_sessions >= self.min_sessions_for_tenant_anomaly
                and tenant_tokens >= self.max_tokens_per_tenant_window
                and session_tokens_in_tenant_window >= self.min_tokens_per_session_for_slow_drain
            ):
                exceeded.append("tenant_tokens_slow_drain")
            if (
                tenant_active_sessions >= self.min_sessions_for_tenant_anomaly
                and tenant_cost >= self.max_cost_usd_per_tenant_window
                and session_cost_in_tenant_window >= self.min_cost_per_session_for_slow_drain
            ):
                exceeded.append("tenant_cost_slow_drain")

            if exceeded:
                quarantine_until = now + self.quarantine_seconds
                self._quarantined_until[sid] = quarantine_until
                return CostAbuseDecision(
                    action="quarantine",
                    reason="Potential wallet-drain abuse detected. Session quarantined.",
                    metrics={
                        "session_id": sid,
                        "window_seconds": self.window_seconds,
                        "events_in_window": total_events,
                        "tokens_in_window": total_tokens,
                        "cost_usd_in_window": round(total_cost, 6),
                        "latest_tokens": tokens,
                        "spike_ratio": round(spike_ratio, 2),
                        "thresholds_exceeded": exceeded,
                        "tenant_id": tid,
                        "tenant_window_seconds": self.tenant_window_seconds,
                        "tenant_active_sessions": tenant_active_sessions,
                        "tenant_tokens_in_window": tenant_tokens,
                        "tenant_cost_usd_in_window": round(tenant_cost, 6),
                        "session_tokens_in_tenant_window": session_tokens_in_tenant_window,
                        "session_cost_in_tenant_window": round(session_cost_in_tenant_window, 6),
                        "quarantine_seconds": self.quarantine_seconds,
                    },
                )

            return CostAbuseDecision(
                action="allow",
                reason="No cost-abuse anomaly detected.",
                metrics={
                    "session_id": sid,
                    "window_seconds": self.window_seconds,
                    "events_in_window": total_events,
                    "tokens_in_window": total_tokens,
                    "cost_usd_in_window": round(total_cost, 6),
                    "latest_tokens": tokens,
                    "spike_ratio": round(spike_ratio, 2),
                    "tenant_id": tid,
                    "tenant_window_seconds": self.tenant_window_seconds,
                    "tenant_active_sessions": tenant_active_sessions,
                    "tenant_tokens_in_window": tenant_tokens,
                    "tenant_cost_usd_in_window": round(tenant_cost, 6),
                },
            )
