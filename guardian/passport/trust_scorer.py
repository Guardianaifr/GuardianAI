"""
Trust Scorer — Computes dynamic trust scores for AI agents.

Aggregates security telemetry from the GuardianAI event database to produce
a weighted trust score (0–100) based on attack survival, PII compliance,
jailbreak resistance, hallucination-free rate, uptime, and incident recency.
"""

from __future__ import annotations

import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, Optional

from guardian.passport.passport_core import classify_tier

logger = logging.getLogger("guardian.passport.trust_scorer")

# ── Weight configuration ─────────────────────────────────────
WEIGHTS = {
    "attack_survival": 0.30,
    "pii_compliance": 0.20,
    "hallucination_free": 0.15,
    "jailbreak_resistance": 0.15,
    "uptime": 0.10,
    "incident_recency": 0.10,
}

# Event type classifications
ATTACK_EVENT_TYPES = {"injection", "injection_ai", "threat_feed_match", "obfuscation"}
PII_LEAK_TYPES = {"data_leak", "data_redaction", "redaction"}
JAILBREAK_TYPES = {"injection", "injection_ai"}
INCIDENT_TYPES = {"injection", "injection_ai", "data_leak", "threat_feed_match"}
ALLOWED_TYPES = {"allowed_request"}

# Time windows (seconds)
WINDOW_7D = 7 * 86400
WINDOW_30D = 30 * 86400
WINDOW_90D = 90 * 86400

# Decay: if no events in 30+ days, score decays
INACTIVITY_DECAY_THRESHOLD = WINDOW_30D
INACTIVITY_DECAY_RATE = 0.02  # 2% per day of inactivity


@dataclass
class TrustScoreResult:
    """Result of a trust score computation."""

    score: float
    tier: str
    breakdown: Dict[str, float] = field(default_factory=dict)
    event_summary: Dict[str, int] = field(default_factory=dict)
    windows: Dict[str, float] = field(default_factory=dict)
    computed_at: float = 0.0

    def to_dict(self) -> Dict:
        return asdict(self)


# ── Cortex Transparency Boost ────────────────────────────────
# Agents with verifiable Cortex event history earn a bonus.
# Cap at +5.0 points to prevent gaming.
CORTEX_BOOST_PER_EVENT = 0.005   # 0.5 points per 100 events
CORTEX_BOOST_MAX = 5.0           # Hard cap at +5.0

# Bonus for agents with at least one on-chain anchor (anchor_tx set)
CORTEX_ANCHOR_BONUS = 1.5


class TrustScorer:
    """
    Computes dynamic trust scores for AI agents based on security telemetry.

    Scoring breakdown (weights):
      - attack_survival   (30%): Ratio of attacks successfully blocked
      - pii_compliance    (20%): Clean request ratio, penalized by data leaks
      - hallucination_free(15%): Absence of hallucination-related events
      - jailbreak_resistance(15%): Ratio of jailbreak attempts blocked
      - uptime            (10%): Based on operational duration
      - incident_recency  (10%): Penalty for recent HIGH/CRITICAL incidents

    Transparency bonus (additive, up to +5 pts):
      - Agents with Cortex event history get a provable-transparency bonus.
      - Each 100 Cortex events adds 0.5 points (up to +5.0).
      - Agents with at least one on-chain Merkle anchor earn an extra +1.5.
    """

    def __init__(self, db_path: str = "guardian.db"):
        self.db_path = db_path

    def compute_score(
        self,
        agent_id: str,
        cortex_events_count: int = 0,
        last_anchor_tx: str = "",
    ) -> TrustScoreResult:
        """
        Compute the trust score for an agent based on security_events.

        Uses the guardian_id field to match events for this agent.
        Applies rolling time windows with more weight on recent data.

        Args:
            agent_id: The agent's unique identifier.
            cortex_events_count: Number of Cortex events recorded for this agent.
                                 Agents with more events earn a transparency bonus.
            last_anchor_tx: If set, the agent has at least one on-chain Merkle anchor,
                            granting an additional transparency bonus.
        """
        now = time.time()
        events = self._fetch_events(agent_id)

        if not events:
            return TrustScoreResult(
                score=0.0,
                tier="UNVERIFIED",
                breakdown={k: 0.0 for k in WEIGHTS},
                event_summary={"total": 0, "cortex_events": cortex_events_count},
                computed_at=now,
            )

        # Classify events
        total_events = len(events)
        attack_events = [e for e in events if e["event_type"] in ATTACK_EVENT_TYPES]
        pii_events = [e for e in events if e["event_type"] in PII_LEAK_TYPES]
        jailbreak_events = [e for e in events if e["event_type"] in JAILBREAK_TYPES]
        allowed_events = [e for e in events if e["event_type"] in ALLOWED_TYPES]
        incident_events = [
            e for e in events
            if e["event_type"] in INCIDENT_TYPES
            and e.get("severity", "").upper() in {"HIGH", "CRITICAL"}
        ]

        # Time-weighted scoring across windows
        scores_7d = self._compute_window_scores(events, now, WINDOW_7D)
        scores_30d = self._compute_window_scores(events, now, WINDOW_30D)
        scores_90d = self._compute_window_scores(events, now, WINDOW_90D)

        # Blend windows: 50% recent (7d), 30% medium (30d), 20% long (90d)
        breakdown = {}
        for metric in WEIGHTS:
            blended = (
                scores_7d.get(metric, 0.0) * 0.5
                + scores_30d.get(metric, 0.0) * 0.3
                + scores_90d.get(metric, 0.0) * 0.2
            )
            breakdown[metric] = round(blended, 2)

        # Compute weighted total
        raw_score = sum(breakdown[k] * WEIGHTS[k] for k in WEIGHTS)
        final_score = round(raw_score * 100, 1)

        # Apply inactivity decay
        latest_event_ts = max(e.get("timestamp", 0) for e in events)
        inactivity_days = (now - latest_event_ts) / 86400
        if inactivity_days > (INACTIVITY_DECAY_THRESHOLD / 86400):
            excess_days = inactivity_days - (INACTIVITY_DECAY_THRESHOLD / 86400)
            decay_factor = max(0.0, 1.0 - (INACTIVITY_DECAY_RATE * excess_days))
            final_score = round(final_score * decay_factor, 1)

        # ── Cortex Transparency Boost ──────────────────────────────
        # Reward agents with verifiable, recorded decision histories.
        transparency_bonus = 0.0
        if cortex_events_count > 0:
            transparency_bonus = min(
                CORTEX_BOOST_MAX,
                cortex_events_count * CORTEX_BOOST_PER_EVENT,
            )
        if last_anchor_tx:
            transparency_bonus = min(
                CORTEX_BOOST_MAX,
                transparency_bonus + CORTEX_ANCHOR_BONUS,
            )
        final_score = round(final_score + transparency_bonus, 1)
        logger.debug(
            "Cortex transparency boost for %s: +%.2f (events=%d, anchored=%s)",
            agent_id,
            transparency_bonus,
            cortex_events_count,
            bool(last_anchor_tx),
        )
        # ──────────────────────────────────────────────────────────

        final_score = max(0.0, min(100.0, final_score))
        tier = classify_tier(final_score)

        return TrustScoreResult(
            score=final_score,
            tier=tier,
            breakdown=breakdown,
            event_summary={
                "total": total_events,
                "attacks": len(attack_events),
                "pii_events": len(pii_events),
                "jailbreak_attempts": len(jailbreak_events),
                "allowed": len(allowed_events),
                "high_severity_incidents": len(incident_events),
                "cortex_events": cortex_events_count,
                "transparency_bonus": round(transparency_bonus, 2),
            },
            windows={"7d": scores_7d.get("_total", 0), "30d": scores_30d.get("_total", 0), "90d": scores_90d.get("_total", 0)},
            computed_at=now,
        )

    def _compute_window_scores(
        self, events: list, now: float, window_sec: int
    ) -> Dict[str, float]:
        """Compute sub-scores for events within a given time window."""
        cutoff = now - window_sec
        windowed = [e for e in events if e.get("timestamp", 0) >= cutoff]

        if not windowed:
            return {k: 0.5 for k in WEIGHTS}  # Neutral for empty windows

        total = len(windowed)
        attacks = [e for e in windowed if e["event_type"] in ATTACK_EVENT_TYPES]
        pii_leaks = [e for e in windowed if e["event_type"] in PII_LEAK_TYPES]
        jailbreaks = [e for e in windowed if e["event_type"] in JAILBREAK_TYPES]
        allowed = [e for e in windowed if e["event_type"] in ALLOWED_TYPES]
        incidents = [
            e for e in windowed
            if e.get("severity", "").upper() in {"HIGH", "CRITICAL"}
        ]

        scores: Dict[str, float] = {}

        # Attack survival: high ratio of blocks is good
        if attacks:
            blocked = len([a for a in attacks if a.get("severity", "").upper() in {"HIGH", "CRITICAL"}])
            scores["attack_survival"] = min(1.0, blocked / max(1, len(attacks)))
        else:
            scores["attack_survival"] = 1.0  # No attacks = perfect survival

        # PII compliance: fewer leaks is better
        if total > 0:
            leak_ratio = len(pii_leaks) / total
            scores["pii_compliance"] = max(0.0, 1.0 - (leak_ratio * 10))
        else:
            scores["pii_compliance"] = 1.0

        # Hallucination-free: no hallucination events
        hallucination_events = [
            e for e in windowed
            if "hallucin" in str(e.get("details", {})).lower()
        ]
        if total > 0:
            scores["hallucination_free"] = max(0.0, 1.0 - (len(hallucination_events) / total * 5))
        else:
            scores["hallucination_free"] = 1.0

        # Jailbreak resistance
        if jailbreaks:
            scores["jailbreak_resistance"] = 1.0  # All detected = all blocked by the firewall
        else:
            scores["jailbreak_resistance"] = 1.0  # No attempts = perfect

        # Uptime: based on event spread across the window
        first_ts = min(e.get("timestamp", now) for e in windowed)
        operational_span = now - first_ts
        expected_span = window_sec
        scores["uptime"] = min(1.0, operational_span / max(1, expected_span))

        # Incident recency: penalize recent HIGH/CRITICAL incidents
        if incidents:
            most_recent = max(i.get("timestamp", 0) for i in incidents)
            days_since = (now - most_recent) / 86400
            scores["incident_recency"] = min(1.0, days_since / 30)  # Full score after 30 days clean
        else:
            scores["incident_recency"] = 1.0

        scores["_total"] = total
        return scores

    def _fetch_events(self, agent_id: str) -> list:
        """Fetch all security events for an agent from the database."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT event_type, severity, details, timestamp
            FROM security_events
            WHERE guardian_id = ?
            ORDER BY timestamp DESC
            """,
            (agent_id,),
        )
        rows = cur.fetchall()
        conn.close()

        events = []
        for row in rows:
            details = {}
            if row[2]:
                try:
                    details = json.loads(row[2]) if isinstance(row[2], str) else row[2]
                except (json.JSONDecodeError, TypeError):
                    details = {}
            events.append({
                "event_type": row[0],
                "severity": row[1] or "",
                "details": details,
                "timestamp": row[3] or 0.0,
            })
        return events
