"""
Cortex Engine — Immutable decision recording and time-travel replay.

Records every AI agent decision as a CortexEvent with cryptographic hashes.
Privacy-first: only hashes are stored by default; full text is opt-in.
Includes a 10-day free trial; after expiry events are read-only.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
import uuid
from dataclasses import dataclass, field, asdict
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("guardian.cortex")

# ── Trial Configuration ────────────────────────────────────────
TRIAL_DURATION_DAYS = 10
TRIAL_DURATION_SECONDS = TRIAL_DURATION_DAYS * 86400


class EventType(str, Enum):
    """Types of events the Cortex records."""
    LLM_CALL = "llm_call"
    DECISION = "decision"
    TOOL_INVOCATION = "tool_invocation"
    MEMORY_ACCESS = "memory_access"
    CREDENTIAL_CHECK = "credential_check"
    POLICY_GATE = "policy_gate"
    INTERLOCK = "interlock"


class PrivacyMode(str, Enum):
    """Controls what is stored vs hashed."""
    HASH_ONLY = "hash_only"       # Default — maximum privacy
    FULL_TEXT = "full_text"        # Opt-in — stores raw content


@dataclass
class CortexEvent:
    """A single immutable decision record."""

    event_id: str
    agent_id: str
    timestamp: float
    event_type: str
    category: str = ""
    action: str = ""
    context_hash: str = ""
    input_hash: str = ""
    output_hash: str = ""
    reasoning_hash: str = ""
    reasoning_text: str = ""      # Empty in HASH_ONLY mode
    confidence: float = 0.0
    parent_event_id: str = ""
    merkle_leaf: str = ""
    metadata: Dict[str, Any] = field(default_factory=dict)
    anchored: bool = False
    anchor_tx: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        if not d.get("reasoning_text"):
            d.pop("reasoning_text", None)
        return d

    @classmethod
    def from_row(cls, row: tuple) -> "CortexEvent":
        """Construct from SQLite row."""
        return cls(
            event_id=row[0],
            agent_id=row[1],
            timestamp=float(row[2]),
            event_type=row[3],
            category=row[4] or "",
            action=row[5] or "",
            context_hash=row[6] or "",
            input_hash=row[7] or "",
            output_hash=row[8] or "",
            reasoning_hash=row[9] or "",
            reasoning_text=row[10] or "",
            confidence=float(row[11]) if row[11] else 0.0,
            parent_event_id=row[12] or "",
            merkle_leaf=row[13] or "",
            metadata=json.loads(row[14]) if row[14] else {},
            anchored=bool(row[15]) if len(row) > 15 else False,
            anchor_tx=row[16] or "" if len(row) > 16 else "",
        )


def _sha256(data: str) -> str:
    """SHA-256 hash of a string, returned as hex."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _compute_merkle_leaf(event: CortexEvent) -> str:
    """Compute the Merkle leaf hash for an event."""
    canonical = f"{event.event_id}:{event.agent_id}:{event.timestamp}:{event.event_type}:{event.input_hash}:{event.output_hash}:{event.reasoning_hash}"
    return _sha256(canonical)


class CortexEngine:
    """
    Records, stores, and replays AI agent decisions.

    Privacy-first: stores SHA-256 hashes of inputs/outputs/reasoning
    by default. Full text storage is opt-in per agent.

    Includes a 10-day free trial per agent. After trial expiry,
    recording stops but existing events remain readable.
    """

    def __init__(self, db_path: str = "guardian.db", privacy_mode: str = "hash_only"):
        self.db_path = db_path
        self.privacy_mode = PrivacyMode(privacy_mode)
        self._init_tables()

    def _init_tables(self) -> None:
        """Create Cortex tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        cur = conn.cursor()

        cur.execute("""
            CREATE TABLE IF NOT EXISTS cortex_events (
                event_id        TEXT PRIMARY KEY,
                agent_id        TEXT NOT NULL,
                timestamp       REAL NOT NULL,
                event_type      TEXT NOT NULL,
                category        TEXT DEFAULT '',
                action          TEXT DEFAULT '',
                context_hash    TEXT DEFAULT '',
                input_hash      TEXT DEFAULT '',
                output_hash     TEXT DEFAULT '',
                reasoning_hash  TEXT DEFAULT '',
                reasoning_text  TEXT DEFAULT '',
                confidence      REAL DEFAULT 0.0,
                parent_event_id TEXT DEFAULT '',
                merkle_leaf     TEXT DEFAULT '',
                metadata        TEXT DEFAULT '{}',
                anchored        INTEGER DEFAULT 0,
                anchor_tx       TEXT DEFAULT ''
            )
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_cortex_agent_ts
            ON cortex_events(agent_id, timestamp DESC)
        """)

        cur.execute("""
            CREATE INDEX IF NOT EXISTS idx_cortex_agent_type
            ON cortex_events(agent_id, event_type)
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS cortex_trials (
                agent_id    TEXT PRIMARY KEY,
                started_at  REAL NOT NULL,
                expires_at  REAL NOT NULL,
                is_active   INTEGER DEFAULT 1
            )
        """)

        cur.execute("""
            CREATE TABLE IF NOT EXISTS cortex_anchors (
                id            INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id      TEXT NOT NULL,
                merkle_root   TEXT NOT NULL,
                event_count   INTEGER NOT NULL,
                period_start  REAL NOT NULL,
                period_end    REAL NOT NULL,
                chain_id      TEXT DEFAULT 'monad',
                tx_hash       TEXT DEFAULT '',
                anchored_at   REAL NOT NULL,
                verified      INTEGER DEFAULT 0
            )
        """)

        conn.commit()
        conn.close()
        logger.info("Cortex tables initialized at %s", self.db_path)

    # ── Trial Management ──────────────────────────────────────

    def start_trial(self, agent_id: str) -> Dict[str, Any]:
        """Start a 10-day free trial for an agent. Idempotent."""
        now = time.time()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        cur.execute("SELECT started_at, expires_at, is_active FROM cortex_trials WHERE agent_id = ?", (agent_id,))
        row = cur.fetchone()
        if row:
            conn.close()
            return {
                "agent_id": agent_id,
                "started_at": row[0],
                "expires_at": row[1],
                "is_active": bool(row[2]),
                "days_remaining": max(0, (row[1] - now) / 86400),
                "already_existed": True,
            }

        expires_at = now + TRIAL_DURATION_SECONDS
        cur.execute(
            "INSERT INTO cortex_trials (agent_id, started_at, expires_at, is_active) VALUES (?, ?, ?, 1)",
            (agent_id, now, expires_at),
        )
        conn.commit()
        conn.close()
        logger.info("Cortex trial started for %s (expires in %d days)", agent_id, TRIAL_DURATION_DAYS)
        return {
            "agent_id": agent_id,
            "started_at": now,
            "expires_at": expires_at,
            "is_active": True,
            "days_remaining": TRIAL_DURATION_DAYS,
            "already_existed": False,
        }

    def check_trial(self, agent_id: str) -> Dict[str, Any]:
        """Check trial status. Auto-expires if past deadline."""
        now = time.time()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        cur.execute("SELECT started_at, expires_at, is_active FROM cortex_trials WHERE agent_id = ?", (agent_id,))
        row = cur.fetchone()
        if not row:
            conn.close()
            return {"agent_id": agent_id, "has_trial": False, "is_active": False}

        started_at, expires_at, is_active = row[0], row[1], bool(row[2])

        # Auto-expire
        if is_active and now > expires_at:
            cur.execute("UPDATE cortex_trials SET is_active = 0 WHERE agent_id = ?", (agent_id,))
            conn.commit()
            is_active = False
            logger.info("Cortex trial expired for %s", agent_id)

        conn.close()
        return {
            "agent_id": agent_id,
            "has_trial": True,
            "is_active": is_active,
            "started_at": started_at,
            "expires_at": expires_at,
            "days_remaining": max(0, (expires_at - now) / 86400) if is_active else 0,
            "expired": not is_active,
        }

    # ── Event Recording ───────────────────────────────────────

    def record_event(
        self,
        agent_id: str,
        event_type: str,
        action: str = "",
        category: str = "",
        input_text: str = "",
        output_text: str = "",
        reasoning: str = "",
        confidence: float = 0.0,
        context: str = "",
        parent_event_id: str = "",
        metadata: Optional[Dict] = None,
    ) -> Optional[CortexEvent]:
        """
        Record a decision event. Returns None if trial expired.

        Privacy: input_text, output_text, and reasoning are SHA-256
        hashed by default (HASH_ONLY mode). Full text is only stored
        when privacy_mode is FULL_TEXT.
        """
        # Check trial
        trial = self.check_trial(agent_id)
        if not trial.get("has_trial"):
            # Auto-start trial on first event
            self.start_trial(agent_id)
        elif not trial.get("is_active"):
            logger.warning("Cortex trial expired for %s — event not recorded", agent_id)
            return None

        now = time.time()
        event_id = str(uuid.uuid4())

        # Privacy-first hashing
        input_hash = _sha256(input_text) if input_text else ""
        output_hash = _sha256(output_text) if output_text else ""
        reasoning_hash = _sha256(reasoning) if reasoning else ""
        context_hash = _sha256(context) if context else ""

        # Only store full text in FULL_TEXT mode
        reasoning_text = reasoning if self.privacy_mode == PrivacyMode.FULL_TEXT else ""

        event = CortexEvent(
            event_id=event_id,
            agent_id=agent_id,
            timestamp=now,
            event_type=event_type,
            category=category,
            action=action,
            context_hash=context_hash,
            input_hash=input_hash,
            output_hash=output_hash,
            reasoning_hash=reasoning_hash,
            reasoning_text=reasoning_text,
            confidence=confidence,
            parent_event_id=parent_event_id,
            metadata=metadata or {},
        )

        # Compute merkle leaf
        event.merkle_leaf = _compute_merkle_leaf(event)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO cortex_events
                (event_id, agent_id, timestamp, event_type, category, action,
                 context_hash, input_hash, output_hash, reasoning_hash,
                 reasoning_text, confidence, parent_event_id, merkle_leaf,
                 metadata, anchored, anchor_tx)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, 0, '')
            """,
            (
                event.event_id, event.agent_id, event.timestamp,
                event.event_type, event.category, event.action,
                event.context_hash, event.input_hash, event.output_hash,
                event.reasoning_hash, event.reasoning_text, event.confidence,
                event.parent_event_id, event.merkle_leaf,
                json.dumps(event.metadata),
            ),
        )
        conn.commit()
        conn.close()
        return event

    # ── Event Retrieval ───────────────────────────────────────

    def get_events(
        self,
        agent_id: str,
        start: Optional[float] = None,
        end: Optional[float] = None,
        event_type: Optional[str] = None,
        limit: int = 100,
    ) -> List[CortexEvent]:
        """Retrieve events with optional time range and type filters."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()

        query = "SELECT * FROM cortex_events WHERE agent_id = ?"
        params: list = [agent_id]

        if start is not None:
            query += " AND timestamp >= ?"
            params.append(start)
        if end is not None:
            query += " AND timestamp <= ?"
            params.append(end)
        if event_type:
            query += " AND event_type = ?"
            params.append(event_type)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cur.execute(query, tuple(params))
        rows = cur.fetchall()
        conn.close()
        return [CortexEvent.from_row(r) for r in rows]

    def get_event(self, event_id: str) -> Optional[CortexEvent]:
        """Retrieve a single event by ID."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT * FROM cortex_events WHERE event_id = ?", (event_id,))
        row = cur.fetchone()
        conn.close()
        return CortexEvent.from_row(row) if row else None

    def get_event_chain(self, event_id: str, max_depth: int = 50) -> List[CortexEvent]:
        """
        Walk the parent chain from an event back to the root.
        Returns events in chronological order (oldest first).
        """
        chain: List[CortexEvent] = []
        current_id = event_id
        visited = set()

        for _ in range(max_depth):
            if not current_id or current_id in visited:
                break
            visited.add(current_id)

            event = self.get_event(current_id)
            if not event:
                break
            chain.append(event)
            current_id = event.parent_event_id

        chain.reverse()
        return chain

    def get_event_count(self, agent_id: str) -> int:
        """Get total event count for an agent."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) FROM cortex_events WHERE agent_id = ?", (agent_id,))
        count = cur.fetchone()[0]
        conn.close()
        return count

    # ── Time-Travel Replay ────────────────────────────────────

    def replay_at(self, agent_id: str, timestamp: float) -> Dict[str, Any]:
        """
        Reconstruct an agent's state at a specific point in time.

        Returns events up to that timestamp, the most recent decision,
        and summary statistics.
        """
        events = self.get_events(agent_id, end=timestamp, limit=500)

        if not events:
            return {
                "agent_id": agent_id,
                "snapshot_at": timestamp,
                "total_events": 0,
                "events": [],
                "last_decision": None,
                "event_type_counts": {},
            }

        type_counts: Dict[str, int] = {}
        last_decision = None
        for e in events:
            type_counts[e.event_type] = type_counts.get(e.event_type, 0) + 1
            if e.event_type == EventType.DECISION.value:
                if last_decision is None or e.timestamp > last_decision.timestamp:
                    last_decision = e

        # Recent events (last 20 before timestamp)
        recent = sorted(events, key=lambda e: e.timestamp, reverse=True)[:20]

        return {
            "agent_id": agent_id,
            "snapshot_at": timestamp,
            "total_events": len(events),
            "recent_events": [e.to_dict() for e in recent],
            "last_decision": last_decision.to_dict() if last_decision else None,
            "event_type_counts": type_counts,
        }

    # ── Anchor Management ─────────────────────────────────────

    def mark_events_anchored(
        self, agent_id: str, event_ids: List[str], tx_hash: str
    ) -> int:
        """Mark events as anchored on-chain."""
        if not event_ids:
            return 0
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        placeholders = ",".join("?" * len(event_ids))
        cur.execute(
            f"UPDATE cortex_events SET anchored = 1, anchor_tx = ? WHERE event_id IN ({placeholders})",
            [tx_hash] + event_ids,
        )
        updated = cur.rowcount
        conn.commit()
        conn.close()
        return updated

    def save_anchor(
        self,
        agent_id: str,
        merkle_root: str,
        event_count: int,
        period_start: float,
        period_end: float,
        chain_id: str = "monad",
        tx_hash: str = "",
    ) -> int:
        """Save an anchor record."""
        now = time.time()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO cortex_anchors
                (agent_id, merkle_root, event_count, period_start, period_end,
                 chain_id, tx_hash, anchored_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (agent_id, merkle_root, event_count, period_start, period_end,
             chain_id, tx_hash, now),
        )
        anchor_id = cur.lastrowid
        conn.commit()
        conn.close()
        return anchor_id

    def get_anchors(self, agent_id: str, limit: int = 50) -> List[Dict[str, Any]]:
        """Get anchor history for an agent."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT id, agent_id, merkle_root, event_count, period_start,
                   period_end, chain_id, tx_hash, anchored_at, verified
            FROM cortex_anchors WHERE agent_id = ?
            ORDER BY anchored_at DESC LIMIT ?
            """,
            (agent_id, limit),
        )
        rows = cur.fetchall()
        conn.close()
        return [
            {
                "id": r[0], "agent_id": r[1], "merkle_root": r[2],
                "event_count": r[3], "period_start": r[4], "period_end": r[5],
                "chain_id": r[6], "tx_hash": r[7], "anchored_at": r[8],
                "verified": bool(r[9]),
            }
            for r in rows
        ]

    def get_unanchored_events(self, agent_id: str, limit: int = 1000) -> List[CortexEvent]:
        """Get events that haven't been anchored on-chain yet."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT * FROM cortex_events
            WHERE agent_id = ? AND anchored = 0
            ORDER BY timestamp ASC LIMIT ?
            """,
            (agent_id, limit),
        )
        rows = cur.fetchall()
        conn.close()
        return [CortexEvent.from_row(r) for r in rows]
