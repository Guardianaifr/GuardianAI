"""Blue Team adaptive behavior and session hardening."""

from __future__ import annotations

from dataclasses import dataclass
from collections import defaultdict
import time


@dataclass
class UserBehaviorProfile:
    request_count: int = 0
    blocked_count: int = 0
    risk_points: int = 0
    first_seen_ts: float = 0.0
    last_seen_ts: float = 0.0
    threat_score: float = 0.0


class BlueAdaptAgent:
    def __init__(
        self,
        escalation_threshold: int = 3,
        strict_score_threshold: float = 0.5,
        honeypot_score_threshold: float = 0.6,
        revoke_score_threshold: float = 0.8,
        profile_ttl_seconds: int = 3600,
        max_sessions: int = 5000,
        cleanup_interval_seconds: int = 60,
        # FEAT-BLUE-ADVANCED: velocity and cooldown params
        velocity_window_sec: float = 10.0,
        velocity_max_rps: float = 5.0,
        cooldown_base_seconds: float = 5.0,
        cooldown_max_seconds: float = 300.0,
        cooldown_multiplier: float = 2.0,
    ):
        self.escalation_threshold = escalation_threshold
        self.session_risk = defaultdict(int)
        self.profiles = defaultdict(UserBehaviorProfile)
        self.revoked_sessions = set()
        self.strict_score_threshold = strict_score_threshold
        self.honeypot_score_threshold = honeypot_score_threshold
        self.revoke_score_threshold = revoke_score_threshold
        self.profile_ttl_seconds = max(60, int(profile_ttl_seconds))
        self.max_sessions = max(100, int(max_sessions))
        self.cleanup_interval_seconds = max(5, int(cleanup_interval_seconds))
        self._last_cleanup_ts = 0.0
        # FEAT-BLUE-ADVANCED: velocity tracker and adaptive cooldown
        self._velocity = SessionVelocityTracker(
            window_sec=velocity_window_sec,
            max_rps=velocity_max_rps,
        )
        self._cooldown = AdaptiveCooldown(
            base_seconds=cooldown_base_seconds,
            max_seconds=cooldown_max_seconds,
            multiplier=cooldown_multiplier,
        )

    def _risk_to_threat_score(self, risk_points: int) -> float:
        # Normalized risk score in [0,1].
        return min(1.0, max(0.0, float(risk_points) / 10.0))

    def _session_key(self, session_id: str | None) -> str:
        return session_id or "unknown"

    def observe_prompt(self, session_id: str, prompt: str, blocked: bool, intel_score: int = 0):
        session_id = self._session_key(session_id)
        now = time.time()
        self._maybe_cleanup(now)
        risk_delta = max(0, int(intel_score))
        if blocked:
            risk_delta += 2
            # FEAT-BLUE-ADVANCED: record a cooldown violation on every blocked request
            self._cooldown.record_violation(session_id, now=now)
        # FEAT-BLUE-ADVANCED: bump risk score when session velocity is anomalous
        if self._velocity.record(session_id, ts=now):
            risk_delta += 1
        self.session_risk[session_id] += risk_delta
        profile = self.profiles[session_id]
        if profile.first_seen_ts == 0.0:
            profile.first_seen_ts = now
        profile.last_seen_ts = now
        profile.request_count += 1
        if blocked:
            profile.blocked_count += 1
        profile.risk_points = self.session_risk[session_id]
        profile.threat_score = self._risk_to_threat_score(profile.risk_points)
        if self.should_revoke_session(session_id):
            self.revoked_sessions.add(session_id)
        self._enforce_capacity()

    def analyze_request(self, session_id: str, prompt: str, blocked: bool, intel_score: int = 0) -> dict:
        self.observe_prompt(session_id, prompt, blocked=blocked, intel_score=intel_score)
        session_id = self._session_key(session_id)
        profile = self.profiles[session_id]
        return {
            "session_id": session_id,
            "threat_score": profile.threat_score,
            "risk_points": profile.risk_points,
            "action": self.get_action(session_id),
            "blocked_count": profile.blocked_count,
            "request_count": profile.request_count,
        }

    def recommend_mode(self, session_id: str, default_mode: str = "balanced") -> str:
        session_id = self._session_key(session_id)
        if self.session_risk.get(session_id, 0) >= self.escalation_threshold:
            return "strict"
        if self.profiles[session_id].threat_score >= self.strict_score_threshold:
            return "strict"
        return default_mode

    def should_revoke_session(self, session_id: str) -> bool:
        session_id = self._session_key(session_id)
        return (
            self.session_risk.get(session_id, 0) >= self.escalation_threshold * 2
            or self.profiles[session_id].threat_score >= self.revoke_score_threshold
        )

    def should_honeypot_session(self, session_id: str) -> bool:
        session_id = self._session_key(session_id)
        score = self.profiles[session_id].threat_score
        return score >= self.honeypot_score_threshold and not self.should_revoke_session(session_id)

    def is_revoked(self, session_id: str) -> bool:
        return self._session_key(session_id) in self.revoked_sessions

    def mark_revoked(self, session_id: str):
        self.revoked_sessions.add(self._session_key(session_id))

    def get_action(self, session_id: str) -> str:
        session_id = self._session_key(session_id)
        if self.is_revoked(session_id) or self.should_revoke_session(session_id):
            return "revoke"
        if self.should_honeypot_session(session_id):
            return "honeypot"
        # FEAT-BLUE-ADVANCED: cooldown (rate-limit) takes precedence over strict mode
        if self._cooldown.is_cooling_down(session_id):
            return "cooldown"
        if self.recommend_mode(session_id, default_mode="balanced") == "strict":
            return "strict"
        return "allow"

    def get_cooldown_seconds_remaining(self, session_id: str, now: float | None = None) -> int:
        """Return whole seconds remaining in the current cooldown window, or 0."""
        now = now if now is not None else time.time()
        sid = self._session_key(session_id)
        remaining = self._cooldown._cooldown_until.get(sid, 0.0) - now
        return max(0, int(remaining))

    def _maybe_cleanup(self, now: float | None = None):
        now = now if now is not None else time.time()
        if (now - self._last_cleanup_ts) < self.cleanup_interval_seconds:
            return
        self.cleanup_stale_sessions(now)
        self._last_cleanup_ts = now

    def cleanup_stale_sessions(self, now: float | None = None) -> int:
        now = now if now is not None else time.time()
        removed = 0
        expired = []
        for sid, profile in list(self.profiles.items()):
            last_seen = profile.last_seen_ts or profile.first_seen_ts or 0.0
            if last_seen and (now - last_seen) > self.profile_ttl_seconds:
                expired.append(sid)
        for sid in expired:
            self.profiles.pop(sid, None)
            self.session_risk.pop(sid, None)
            self.revoked_sessions.discard(sid)
            removed += 1
        return removed

    def _enforce_capacity(self):
        if len(self.profiles) <= self.max_sessions:
            return
        # Evict oldest sessions by last_seen_ts until within cap.
        candidates = sorted(
            self.profiles.items(),
            key=lambda kv: kv[1].last_seen_ts or kv[1].first_seen_ts or 0.0,
        )
        to_remove = len(self.profiles) - self.max_sessions
        for sid, _profile in candidates[:to_remove]:
            self.profiles.pop(sid, None)
            self.session_risk.pop(sid, None)
            self.revoked_sessions.discard(sid)


# ═══════════════════════════════════════════════════════════════════════════
# 2026-Standard Advanced Blue Team Capabilities
# ═══════════════════════════════════════════════════════════════════════════

class SessionVelocityTracker:
    """Detect burst-rate anomalies per session (requests-per-second)."""

    def __init__(self, window_sec: float = 10.0, max_rps: float = 5.0):
        self.window_sec = max(1.0, window_sec)
        self.max_rps = max(0.1, max_rps)
        self._timestamps: dict[str, list[float]] = defaultdict(list)

    def record(self, session_id: str, ts: float | None = None) -> bool:
        """Record a request. Returns True if velocity is anomalous."""
        ts = ts or time.time()
        bucket = self._timestamps[session_id]
        bucket.append(ts)
        cutoff = ts - self.window_sec
        self._timestamps[session_id] = [t for t in bucket if t >= cutoff]
        rps = len(self._timestamps[session_id]) / self.window_sec
        return rps > self.max_rps

    def get_rps(self, session_id: str) -> float:
        now = time.time()
        bucket = self._timestamps.get(session_id, [])
        cutoff = now - self.window_sec
        recent = [t for t in bucket if t >= cutoff]
        return len(recent) / self.window_sec

    def clear(self, session_id: str = ""):
        if session_id:
            self._timestamps.pop(session_id, None)
        else:
            self._timestamps.clear()


class GeoAnomalyDetector:
    """Detect impossible-travel or geo-hop anomalies."""

    def __init__(self, max_hops_per_hour: int = 3):
        self.max_hops = max(1, max_hops_per_hour)
        self._geo_log: dict[str, list[tuple[float, str]]] = defaultdict(list)

    def record(self, session_id: str, geo_label: str, ts: float | None = None) -> bool:
        """Record geo event. Returns True if anomalous hop detected."""
        ts = ts or time.time()
        self._geo_log[session_id].append((ts, geo_label))
        cutoff = ts - 3600.0
        self._geo_log[session_id] = [(t, g) for t, g in self._geo_log[session_id] if t >= cutoff]
        distinct = set(g for _, g in self._geo_log[session_id])
        return len(distinct) > self.max_hops

    def get_distinct_geos(self, session_id: str) -> set[str]:
        return set(g for _, g in self._geo_log.get(session_id, []))

    def clear(self):
        self._geo_log.clear()


class BehavioralFingerprint:
    """Track behavioral consistency for session integrity verification."""

    def __init__(self):
        self._fingerprints: dict[str, dict] = {}

    def register(self, session_id: str, user_agent: str = "", lang: str = "", tz_offset: int = 0):
        self._fingerprints[session_id] = {
            "user_agent": user_agent, "lang": lang, "tz_offset": tz_offset,
        }

    def check(self, session_id: str, user_agent: str = "", lang: str = "", tz_offset: int = 0) -> bool:
        """Returns True if fingerprint matches (consistent). False = suspicious."""
        stored = self._fingerprints.get(session_id)
        if not stored:
            return True  # first time
        mismatches = 0
        if stored["user_agent"] and user_agent and stored["user_agent"] != user_agent:
            mismatches += 1
        if stored["lang"] and lang and stored["lang"] != lang:
            mismatches += 1
        if stored["tz_offset"] != 0 and tz_offset != 0 and abs(stored["tz_offset"] - tz_offset) > 2:
            mismatches += 1
        return mismatches == 0

    def clear(self):
        self._fingerprints.clear()


class AdaptiveCooldown:
    """Exponential backoff cooldown for repeat offenders."""

    def __init__(self, base_seconds: float = 5.0, max_seconds: float = 300.0, multiplier: float = 2.0):
        self.base = max(1.0, base_seconds)
        self.maximum = max(self.base, max_seconds)
        self.multiplier = max(1.1, multiplier)
        self._violations: dict[str, int] = defaultdict(int)
        self._cooldown_until: dict[str, float] = {}

    def record_violation(self, session_id: str, now: float | None = None) -> float:
        """Record a violation. Returns cooldown duration in seconds."""
        now = now or time.time()
        self._violations[session_id] += 1
        duration = min(self.maximum, self.base * (self.multiplier ** (self._violations[session_id] - 1)))
        self._cooldown_until[session_id] = now + duration
        return duration

    def is_cooling_down(self, session_id: str, now: float | None = None) -> bool:
        now = now or time.time()
        return now < self._cooldown_until.get(session_id, 0.0)

    def get_violation_count(self, session_id: str) -> int:
        return self._violations.get(session_id, 0)

    def reset(self, session_id: str = ""):
        if session_id:
            self._violations.pop(session_id, None)
            self._cooldown_until.pop(session_id, None)
        else:
            self._violations.clear()
            self._cooldown_until.clear()
