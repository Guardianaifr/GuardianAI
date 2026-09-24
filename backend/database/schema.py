import logging
import os
from pathlib import Path
import sqlite3
from typing import Optional, Tuple

logger = logging.getLogger("guardian_backend.database")


def get_default_db_path() -> str:
    return os.getenv("GUARDIAN_DB_PATH", os.getenv("DB_PATH", "guardian.db"))


def get_db_connection(db_path: Optional[str] = None, timeout: float = 10.0) -> sqlite3.Connection:
    target_db = db_path or get_default_db_path()
    db_dir = os.path.dirname(target_db)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(target_db, timeout=timeout)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    return conn


def init_db(db_path: Optional[str] = None) -> None:
    target_db = db_path or get_default_db_path()
    db_dir = os.path.dirname(target_db)
    if db_dir:
        os.makedirs(db_dir, exist_ok=True)
    conn = sqlite3.connect(target_db)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    cur = conn.cursor()
    cur.execute("""
    CREATE TABLE IF NOT EXISTS security_events (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guardian_id TEXT,
        tenant_id TEXT DEFAULT 'default',
        event_type TEXT,
        severity TEXT,
        details TEXT,
        timestamp REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS analytics (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        tenant_id TEXT DEFAULT 'default',
        path TEXT,
        latency_ms REAL,
        timestamp REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        guardian_id TEXT,
        action TEXT,
        user TEXT,
        details TEXT,
        timestamp REAL,
        signature TEXT -- Cryptographic proof (simulated)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS api_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        key_name TEXT UNIQUE,
        key_prefix TEXT,
        key_hash TEXT UNIQUE,
        is_active INTEGER DEFAULT 1,
        created_by TEXT,
        created_at REAL,
        last_used_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS revoked_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        jti TEXT UNIQUE,
        revoked_by TEXT,
        revoked_at REAL,
        expires_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS issued_tokens (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        jti TEXT UNIQUE,
        subject TEXT,
        role TEXT,
        issued_at REAL,
        expires_at REAL,
        revoked_at REAL,
        revoked_by TEXT,
        revoke_reason TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS audit_delivery_failures (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        sink_type TEXT,
        payload TEXT,
        error TEXT,
        retry_count INTEGER DEFAULT 0,
        created_at REAL,
        last_attempt_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS customers (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        email TEXT UNIQUE,
        tenant_name TEXT,
        created_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS orders (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id TEXT UNIQUE,
        customer_email TEXT,
        tenant_name TEXT,
        plan TEXT,
        payment_method TEXT,
        provider TEXT,
        status TEXT,
        checkout_url TEXT,
        provider_transaction_id TEXT,
        created_at REAL,
        updated_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS licenses (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        order_id TEXT UNIQUE,
        machine_id TEXT,
        license_key TEXT,
        status TEXT,
        issued_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS lockout_state (
        identity TEXT PRIMARY KEY,
        failed_count INTEGER,
        locked_until REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agentic_agent_keys (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        key_id TEXT NOT NULL,
        key_secret_hash TEXT NOT NULL,
        key_secret_ciphertext TEXT NOT NULL,
        cert_fingerprints_json TEXT,
        status TEXT DEFAULT 'active',
        created_by TEXT,
        created_at REAL,
        rotated_at REAL,
        revoked_at REAL,
        revoked_by TEXT,
        revoke_reason TEXT,
        UNIQUE(agent_id, key_id)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agentic_revocations (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        revocation_type TEXT NOT NULL,
        agent_id TEXT,
        key_id TEXT,
        reason TEXT,
        revoked_by TEXT,
        revoked_at REAL
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agentic_execution_grants (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        execution_id TEXT UNIQUE NOT NULL,
        agent_id TEXT,
        parent_agent TEXT,
        scopes_json TEXT,
        tools_json TEXT,
        expires_at REAL,
        created_by TEXT,
        created_at REAL,
        revoked_at REAL,
        revoked_by TEXT,
        revoke_reason TEXT
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agentic_policy_edges (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        parent_agent TEXT NOT NULL,
        child_agent TEXT NOT NULL,
        scopes_json TEXT,
        tools_json TEXT,
        max_hops INTEGER,
        created_by TEXT,
        created_at REAL,
        UNIQUE(parent_agent, child_agent)
    )
    """)
    cur.execute("""
    CREATE TABLE IF NOT EXISTS agentic_trace_hashes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        trace_hash TEXT UNIQUE NOT NULL,
        agent_id TEXT,
        execution_id TEXT,
        first_seen_at REAL
    )
    """)
    # Backward-compatible schema upgrades for existing installations.
    cur.execute("PRAGMA table_info(security_events)")
    security_cols = {row[1] for row in cur.fetchall()}
    if "tenant_id" not in security_cols:
        cur.execute("ALTER TABLE security_events ADD COLUMN tenant_id TEXT DEFAULT 'default'")
    cur.execute("PRAGMA table_info(analytics)")
    analytics_cols = {row[1] for row in cur.fetchall()}
    if "tenant_id" not in analytics_cols:
        cur.execute("ALTER TABLE analytics ADD COLUMN tenant_id TEXT DEFAULT 'default'")
    cur.execute("PRAGMA table_info(audit_logs)")
    audit_cols = {row[1] for row in cur.fetchall()}
    if "prev_hash" not in audit_cols:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN prev_hash TEXT")
    if "entry_hash" not in audit_cols:
        cur.execute("ALTER TABLE audit_logs ADD COLUMN entry_hash TEXT")
    cur.execute("PRAGMA table_info(agentic_agent_keys)")
    agentic_key_cols = {row[1] for row in cur.fetchall()}
    if "cert_fingerprints_json" not in agentic_key_cols:
        cur.execute("ALTER TABLE agentic_agent_keys ADD COLUMN cert_fingerprints_json TEXT")
    conn.commit()
    conn.close()
    logger.info("SQLite DB initialized at %s", target_db)


def check_db_health(db_path: Optional[str] = None) -> Tuple[bool, str]:
    target_db = db_path or get_default_db_path()
    try:
        conn = sqlite3.connect(target_db)
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        conn.close()
        return True, "ok"
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def run_migrations(db_path: Optional[str] = None) -> None:
    try:
        from alembic.config import Config
        from alembic import command
        target_db = db_path or get_default_db_path()
        ini_path = str(Path(__file__).resolve().parent.parent.parent / "alembic.ini")
        if os.path.exists(ini_path):
            alembic_cfg = Config(ini_path)
            alembic_cfg.set_main_option("sqlalchemy.url", f"sqlite:///{target_db}")
            command.upgrade(alembic_cfg, "head")
            logger.info("Alembic migrations applied up to head for %s", target_db)
    except Exception as exc:
        logger.warning("Alembic migration skipped or failed: %s", exc)


__all__ = ["init_db", "get_db_connection", "check_db_health", "get_default_db_path", "run_migrations"]
