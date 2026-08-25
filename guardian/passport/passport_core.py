"""
Passport Core — Agent identity issuance, storage, and lifecycle management.

Provides the AgentPassport data model and PassportEngine for CRUD operations
against the SQLite database.
"""

from __future__ import annotations

import hashlib
import json
import logging
import sqlite3
import time
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional

logger = logging.getLogger("guardian.passport")

# ── Tier thresholds ─────────────────────────────────────────
TIER_DIAMOND = 90.0
TIER_GOLD = 75.0
TIER_SILVER = 50.0

TIER_LABELS = {
    "DIAMOND": "🟢 DIAMOND",
    "GOLD": "🔵 GOLD",
    "SILVER": "🟡 SILVER",
    "UNVERIFIED": "🔴 UNVERIFIED",
}


def classify_tier(score: float) -> str:
    """Return tier string based on trust score."""
    if score >= TIER_DIAMOND:
        return "DIAMOND"
    if score >= TIER_GOLD:
        return "GOLD"
    if score >= TIER_SILVER:
        return "SILVER"
    return "UNVERIFIED"


@dataclass
class AgentPassport:
    """Portable, verifiable identity for an AI agent."""

    passport_id: str
    agent_id: str
    owner_pubkey: str
    chain_id: str = "base"
    trust_score: float = 0.0
    tier: str = "UNVERIFIED"
    credentials: List[Dict] = field(default_factory=list)
    metadata: Dict = field(default_factory=dict)
    issued_at: float = 0.0
    updated_at: float = 0.0
    is_active: bool = True
    cortex_events_count: int = 0
    last_anchor_tx: str = ""
    tenant_id: str = "default"

    def to_dict(self) -> Dict:
        return asdict(self)

    @classmethod
    def from_row(cls, row: tuple) -> "AgentPassport":
        """Construct from a SQLite row tuple."""
        return cls(
            passport_id=row[0],
            agent_id=row[1],
            owner_pubkey=row[2],
            chain_id=row[3] if row[3] else "base",
            trust_score=float(row[4]) if row[4] is not None else 0.0,
            tier=row[5] if row[5] else "UNVERIFIED",
            credentials=json.loads(row[6]) if row[6] else [],
            metadata=json.loads(row[7]) if row[7] else {},
            issued_at=float(row[8]) if row[8] is not None else 0.0,
            updated_at=float(row[9]) if row[9] is not None else 0.0,
            is_active=bool(row[10]) if row[10] is not None else True,
            cortex_events_count=int(row[11]) if len(row) > 11 and row[11] is not None else 0,
            last_anchor_tx=row[12] if len(row) > 12 and row[12] else "",
            tenant_id=row[13] if len(row) > 13 and row[13] else "default",
        )


def _generate_passport_id(agent_id: str, owner_pubkey: str, chain_id: str) -> str:
    """Deterministic passport ID from (agent_id, owner_pubkey, chain_id)."""
    raw = f"{agent_id}:{owner_pubkey}:{chain_id}".encode("utf-8")
    return hashlib.sha256(raw).hexdigest()


class PassportEngine:
    """
    Manages the lifecycle of AI Agent Passports.

    Handles issuance, retrieval, scoring updates, revocation, and
    leaderboard queries against the SQLite database.
    """

    def __init__(self, db_path: str = "guardian.db"):
        self.db_path = db_path
        self._init_passport_tables()

    # ── Schema ────────────────────────────────────────────────

    def _init_passport_tables(self) -> None:
        """Create passport tables if they don't exist."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA busy_timeout=5000")
        cur = conn.cursor()
        cur.execute("""
            CREATE TABLE IF NOT EXISTS agent_passports (
                passport_id   TEXT PRIMARY KEY,
                agent_id      TEXT UNIQUE NOT NULL,
                owner_pubkey  TEXT NOT NULL,
                chain_id      TEXT DEFAULT 'base',
                trust_score   REAL DEFAULT 0.0,
                tier          TEXT DEFAULT 'UNVERIFIED',
                credentials   TEXT DEFAULT '[]',
                metadata      TEXT DEFAULT '{}',
                issued_at     REAL,
                updated_at    REAL,
                is_active     INTEGER DEFAULT 1,
                cortex_events_count INTEGER DEFAULT 0,
                last_anchor_tx TEXT DEFAULT '',
                tenant_id     TEXT DEFAULT 'default'
            )
        """)
        existing_columns = {
            row[1] for row in cur.execute("PRAGMA table_info(agent_passports)").fetchall()
        }
        if "cortex_events_count" not in existing_columns:
            cur.execute("ALTER TABLE agent_passports ADD COLUMN cortex_events_count INTEGER DEFAULT 0")
        if "last_anchor_tx" not in existing_columns:
            cur.execute("ALTER TABLE agent_passports ADD COLUMN last_anchor_tx TEXT DEFAULT ''")
        if "tenant_id" not in existing_columns:
            try:
                cur.execute("SELECT agent_id FROM agent_passports")
                existing_passports = [r[0] for r in cur.fetchall()]
            except Exception:
                existing_passports = []
            cur.execute("ALTER TABLE agent_passports ADD COLUMN tenant_id TEXT DEFAULT 'default'")
            for agent in existing_passports:
                print(f"[PASSPORT MIGRATION AUDIT] Migrated passport {agent} to default tenant")
                logger.info("[PASSPORT MIGRATION AUDIT] Migrated passport %s to default tenant", agent)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS passport_credentials (
                id              INTEGER PRIMARY KEY AUTOINCREMENT,
                passport_id     TEXT NOT NULL,
                credential_type TEXT NOT NULL,
                credential_data TEXT NOT NULL,
                issued_at       REAL,
                expires_at      REAL,
                is_valid        INTEGER DEFAULT 1,
                FOREIGN KEY (passport_id) REFERENCES agent_passports(passport_id)
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS passport_score_history (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id    TEXT NOT NULL,
                score       REAL NOT NULL,
                tier        TEXT NOT NULL,
                breakdown   TEXT DEFAULT '{}',
                recorded_at REAL
            )
        """)
        conn.commit()
        conn.close()
        logger.info("Passport tables initialized at %s", self.db_path)

    # ── CRUD ──────────────────────────────────────────────────

    def issue_passport(
        self,
        agent_id: str,
        owner_pubkey: str,
        chain_id: str = "base",
        metadata: Optional[Dict] = None,
        tenant_id: str = "default",
    ) -> AgentPassport:
        """
        Issue a new passport for an AI agent.

        If the agent already has a passport, return the existing one.
        The passport_id is deterministically derived from the inputs.
        """
        existing = self.get_passport(agent_id)
        if existing is not None:
            return existing

        now = time.time()
        passport_id = _generate_passport_id(agent_id, owner_pubkey, chain_id)

        passport = AgentPassport(
            passport_id=passport_id,
            agent_id=agent_id,
            owner_pubkey=owner_pubkey,
            chain_id=chain_id,
            trust_score=0.0,
            tier="UNVERIFIED",
            credentials=[],
            metadata=metadata or {},
            issued_at=now,
            updated_at=now,
            is_active=True,
            tenant_id=tenant_id,
        )

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        try:
            cur.execute(
                """
                INSERT INTO agent_passports
                    (passport_id, agent_id, owner_pubkey, chain_id,
                     trust_score, tier, credentials, metadata,
                     issued_at, updated_at, is_active, tenant_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    passport.passport_id,
                    passport.agent_id,
                    passport.owner_pubkey,
                    passport.chain_id,
                    passport.trust_score,
                    passport.tier,
                    json.dumps(passport.credentials),
                    json.dumps(passport.metadata),
                    passport.issued_at,
                    passport.updated_at,
                    1,
                    passport.tenant_id,
                ),
            )
            conn.commit()
            logger.info("Passport issued for agent %s → %s", agent_id, passport_id[:16])
        except sqlite3.IntegrityError:
            conn.rollback()
            # Race condition — another thread issued first; retry lookup
            result = self.get_passport(agent_id)
            if result is None:
                raise RuntimeError(
                    f"Failed to issue or retrieve passport for {agent_id}"
                )
            return result
        finally:
            conn.close()

        # ERC-8004 identity registration (no-op unless GUARDIAN_ERC8004_ENABLED).
        # Deliberately swallow-all: identity registration must never break
        # passport issuance or affect traffic availability.
        try:
            from guardian.passport.erc8004_registrar import enqueue_registration

            enqueue_registration(self.db_path, agent_id, passport.passport_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("ERC-8004 registration hook skipped: %s", exc)

        return passport

    def get_passport(self, agent_id: str) -> Optional[AgentPassport]:
        """Retrieve a passport by agent_id."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT passport_id, agent_id, owner_pubkey, chain_id,
                   trust_score, tier, credentials, metadata,
                   issued_at, updated_at, is_active,
                   cortex_events_count, last_anchor_tx, tenant_id
            FROM agent_passports WHERE agent_id = ?
            """,
            (agent_id,),
        )
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None
        return AgentPassport.from_row(row)

    def get_passport_by_id(self, passport_id: str) -> Optional[AgentPassport]:
        """Retrieve a passport by passport_id."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT passport_id, agent_id, owner_pubkey, chain_id,
                   trust_score, tier, credentials, metadata,
                   issued_at, updated_at, is_active,
                   cortex_events_count, last_anchor_tx, tenant_id
            FROM agent_passports WHERE passport_id = ?
            """,
            (passport_id,),
        )
        row = cur.fetchone()
        conn.close()
        if row is None:
            return None
        return AgentPassport.from_row(row)

    def update_trust_score(self, agent_id: str, score: float, tier: Optional[str] = None) -> bool:
        """Update the trust score and tier for an agent's passport."""
        if tier is None:
            tier = classify_tier(score)
        now = time.time()

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE agent_passports
            SET trust_score = ?, tier = ?, updated_at = ?
            WHERE agent_id = ? AND is_active = 1
            """,
            (score, tier, now, agent_id),
        )
        updated = cur.rowcount > 0
        if updated:
            cur.execute(
                """
                INSERT INTO passport_score_history (agent_id, score, tier, recorded_at)
                VALUES (?, ?, ?, ?)
                """,
                (agent_id, score, tier, now),
            )
        conn.commit()
        conn.close()
        return updated

    # Anti-gaming constants for trust boosts
    _BOOST_COOLDOWN_SECONDS = 3600    # 1 hour between boosts
    _BOOST_CUMULATIVE_CAP = 10.0      # Max total boost from Cortex events
    _BOOST_MIN_EVENTS = 10            # Minimum events required per boost

    def update_cortex_status(
        self,
        agent_id: str,
        cortex_events_count: int,
        last_anchor_tx: str = "",
        trust_boost: float = 2.5,
    ) -> bool:
        """
        Persist Cortex transparency metadata and apply a small trust boost.

        The boost is intentionally capped and only applies to active passports.
        Anti-gaming protections:
          - 1-hour cooldown between boosts
          - Minimum 10 events required per boost application
          - Cumulative boost capped at 10.0 points total
        """
        now = time.time()
        passport = self.get_passport(agent_id)
        if passport is None or not passport.is_active:
            return False

        # Anti-gaming: check cooldown and minimum events
        actual_boost = 0.0
        if cortex_events_count >= self._BOOST_MIN_EVENTS:
            # Check last boost time from score history
            conn_check = sqlite3.connect(self.db_path)
            cur_check = conn_check.cursor()
            cur_check.execute(
                "SELECT recorded_at, breakdown FROM passport_score_history "
                "WHERE agent_id = ? ORDER BY recorded_at DESC LIMIT 1",
                (agent_id,),
            )
            last_row = cur_check.fetchone()
            conn_check.close()

            can_boost = True
            cumulative_boost = 0.0

            if last_row:
                last_time = float(last_row[0]) if last_row[0] else 0.0
                if (now - last_time) < self._BOOST_COOLDOWN_SECONDS:
                    can_boost = False
                    logger.debug("Cortex boost cooldown active for %s", agent_id)

                # Calculate cumulative boost from history
                try:
                    breakdown = json.loads(last_row[1]) if last_row[1] else {}
                    cumulative_boost = float(breakdown.get("cumulative_boost", 0.0))
                except (json.JSONDecodeError, TypeError, ValueError):
                    cumulative_boost = 0.0

            if can_boost and cumulative_boost < self._BOOST_CUMULATIVE_CAP:
                actual_boost = min(
                    trust_boost,
                    self._BOOST_CUMULATIVE_CAP - cumulative_boost,
                )
                cumulative_boost += actual_boost
            else:
                cumulative_boost = min(cumulative_boost, self._BOOST_CUMULATIVE_CAP)
        else:
            cumulative_boost = 0.0

        boosted_score = min(100.0, passport.trust_score + actual_boost)
        boosted_tier = classify_tier(boosted_score)

        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            UPDATE agent_passports
            SET cortex_events_count = ?,
                last_anchor_tx = COALESCE(NULLIF(?, ''), last_anchor_tx),
                trust_score = ?,
                tier = ?,
                updated_at = ?
            WHERE agent_id = ? AND is_active = 1
            """,
            (cortex_events_count, last_anchor_tx, boosted_score, boosted_tier, now, agent_id),
        )
        updated = cur.rowcount > 0
        if updated:
            cur.execute(
                """
                INSERT INTO passport_score_history (agent_id, score, tier, breakdown, recorded_at)
                VALUES (?, ?, ?, ?, ?)
                """,
                (
                    agent_id,
                    boosted_score,
                    boosted_tier,
                    json.dumps({
                        "source": "cortex_transparency",
                        "cortex_events_count": cortex_events_count,
                        "last_anchor_tx": last_anchor_tx,
                        "boost_applied": actual_boost,
                        "cumulative_boost": cumulative_boost,
                    }),
                    now,
                ),
            )
        conn.commit()
        conn.close()
        return updated

    def add_credential(self, agent_id: str, credential_data: Dict) -> bool:
        """Attach a verifiable credential to an agent's passport."""
        passport = self.get_passport(agent_id)
        if passport is None or not passport.is_active:
            return False

        now = time.time()
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO passport_credentials
                (passport_id, credential_type, credential_data, issued_at, expires_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                passport.passport_id,
                # W3C VC 'type' is a list; extract the GuardianAI type or stringify
                self._extract_credential_type(credential_data),
                json.dumps(credential_data),
                now,
                credential_data.get("expirationDate"),
            ),
        )
        # Also update the embedded credentials list
        passport.credentials.append(credential_data)
        cur.execute(
            "UPDATE agent_passports SET credentials = ?, updated_at = ? WHERE agent_id = ?",
            (json.dumps(passport.credentials), now, agent_id),
        )
        conn.commit()
        conn.close()
        return True

    @staticmethod
    def _extract_credential_type(credential_data: Dict) -> str:
        """Extract a string credential type from W3C VC data (type can be a list)."""
        raw_type = credential_data.get("type", "unknown")
        if isinstance(raw_type, list):
            # Find the GuardianAI-specific type, skip generic "VerifiableCredential"
            for t in raw_type:
                if t != "VerifiableCredential":
                    return str(t)
            return raw_type[0] if raw_type else "unknown"
        return str(raw_type)

    def revoke_passport(self, agent_id: str) -> bool:
        """Revoke an agent's passport. Returns False if not found or already revoked."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            "UPDATE agent_passports SET is_active = 0, updated_at = ? WHERE agent_id = ? AND is_active = 1",
            (time.time(), agent_id),
        )
        revoked = cur.rowcount > 0
        conn.commit()
        conn.close()
        if revoked:
            logger.info("Passport revoked for agent %s", agent_id)
        return revoked

    def list_passports(self, limit: int = 50, active_only: bool = True) -> List[AgentPassport]:
        """List passports, optionally filtering to active only."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        if active_only:
            cur.execute(
                """
                SELECT passport_id, agent_id, owner_pubkey, chain_id,
                       trust_score, tier, credentials, metadata,
                       issued_at, updated_at, is_active,
                       cortex_events_count, last_anchor_tx, tenant_id
                FROM agent_passports WHERE is_active = 1
                ORDER BY updated_at DESC LIMIT ?
                """,
                (limit,),
            )
        else:
            cur.execute(
                """
                SELECT passport_id, agent_id, owner_pubkey, chain_id,
                       trust_score, tier, credentials, metadata,
                       issued_at, updated_at, is_active,
                       cortex_events_count, last_anchor_tx, tenant_id
                FROM agent_passports ORDER BY updated_at DESC LIMIT ?
                """,
                (limit,),
            )
        rows = cur.fetchall()
        conn.close()
        return [AgentPassport.from_row(r) for r in rows]

    def get_leaderboard(self, limit: int = 20) -> List[AgentPassport]:
        """Return top agents by trust score (active only)."""
        conn = sqlite3.connect(self.db_path)
        cur = conn.cursor()
        cur.execute(
            """
            SELECT passport_id, agent_id, owner_pubkey, chain_id,
                   trust_score, tier, credentials, metadata,
                   issued_at, updated_at, is_active,
                   cortex_events_count, last_anchor_tx, tenant_id
            FROM agent_passports
            WHERE is_active = 1
            ORDER BY trust_score DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cur.fetchall()
        conn.close()
        return [AgentPassport.from_row(r) for r in rows]
