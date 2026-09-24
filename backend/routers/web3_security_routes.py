from fastapi import APIRouter, Depends, HTTPException, status, Request
from fastapi.responses import JSONResponse
from typing import List, Dict, Any, Optional
import time
import json
import os
import sqlite3
import requests as http_requests

from backend.main import (
    enforce_user_rate_limit,
    logger,
    get_current_user
)

router = APIRouter()

# Absolute path — same derivation as rpc_relay.py so both processes share one DB
# backend/routers/web3_security_routes.py -> backend/routers -> backend -> repo root
DB_PATH = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
    "web3sec_blocked.db"
)

# Relay stats endpoint (relay runs on 127.0.0.1:8546 by default)
_RELAY_BASE_URL = os.environ.get("WEB3SEC_RELAY_URL", "http://127.0.0.1:8546")
_RELAY_STATS_URL = _RELAY_BASE_URL + "/stats"
_RELAY_RULES_URL = _RELAY_BASE_URL + "/rules"
_RELAY_WHITELIST_URL = _RELAY_BASE_URL + "/whitelist"

# Management token for relay mutating endpoints (audit P1-3).
# Must match the relay's management_token (sourced from the same env vars).
def _get_relay_mgmt_token() -> str:
    return (
        os.environ.get("GUARDIAN_ADMIN_TOKEN", "")
        or os.environ.get("GUARDIAN_ADMIN_BYPASS_TOKEN", "")
    )

_VALID_RULES = frozenset(
    ["reserve_manipulation", "infinite_approval", "role_change", "zero_slippage", "threat_address", "identity_check"]
)


def _db_conn():
    """Return a sqlite3 connection to the shared web3sec DB."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def _ensure_tables():
    """Create rules/whitelist tables if the relay hasn't started yet."""
    with sqlite3.connect(DB_PATH) as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS web3sec_rules (
                rule_name TEXT PRIMARY KEY,
                enabled INTEGER NOT NULL DEFAULT 1,
                updated_at REAL NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS web3sec_whitelist (
                address TEXT PRIMARY KEY,
                label TEXT,
                added_at REAL NOT NULL
            )
        ''')
        now = time.time()
        for rule in _VALID_RULES:
            conn.execute(
                "INSERT OR IGNORE INTO web3sec_rules (rule_name, enabled, updated_at) VALUES (?, 1, ?)",
                (rule, now)
            )
        conn.commit()

def _notify_relay(method: str, url: str, **kwargs):
    """Best-effort notification to running relay; silently ignored if relay is down.
    Sends management Bearer token for auth on mutating endpoints (audit P1-3)."""
    try:
        headers = kwargs.pop("headers", {})
        mgmt_token = _get_relay_mgmt_token()
        if mgmt_token:
            headers["Authorization"] = f"Bearer {mgmt_token}"
        http_requests.request(method, url, timeout=2, headers=headers, **kwargs)
    except (Exception, ValueError):
            pass  # Relay may not be running; DB is the source of truth

@router.get("/api/v1/web3/status", tags=["Web3 Security"])
def get_web3_status(principal: Dict[str, str] = Depends(enforce_user_rate_limit)):
    """Public endpoint to get relay status and live interception stats."""
    relay_stats = None
    relay_up = False
    try:
        resp = http_requests.get(_RELAY_STATS_URL, timeout=2)
        if resp.status_code == 200:
            relay_stats = resp.json()
            relay_up = True
    except (Exception, ValueError):
            pass

    # Count blocked txs from DB
    blocked_count = 0
    try:
        with sqlite3.connect(DB_PATH) as conn:
            row = conn.execute("SELECT COUNT(*) FROM blocked_transactions").fetchone()
            blocked_count = row[0] if row else 0
    except (Exception, ValueError):
            pass

    return {
        "status": "ok",
        "component": "web3sec_relay",
        "relay_up": relay_up,
        "relay_stats": relay_stats.get("stats") if relay_stats else None,
        "total_blocked_persisted": blocked_count,
    }

@router.get("/api/v1/web3/blocked", tags=["Web3 Security"])
def list_blocked_tx(limit: int = 50, principal: Dict[str, Any] = Depends(get_current_user)):
    """Admin endpoint to list blocked transactions."""
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    try:
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            cursor = conn.execute(
                "SELECT * FROM blocked_transactions ORDER BY timestamp DESC LIMIT ?",
                (limit,)
            )
            rows = cursor.fetchall()
            return {"blocked": [dict(r) for r in rows]}
    except sqlite3.OperationalError:
        return {"blocked": []}
    except Exception as e:
        logger.error(f"Error fetching blocked tx: {e}")
        raise HTTPException(status_code=500, detail="Internal error")

@router.get("/api/v1/web3/rules", tags=["Web3 Security"])
def get_rules(principal: Dict[str, Any] = Depends(get_current_user)):
    """Admin endpoint: return current detection rule settings from DB."""
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    try:
        _ensure_tables()
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT rule_name, enabled, updated_at FROM web3sec_rules").fetchall()
            rules = {row["rule_name"]: bool(row["enabled"]) for row in rows}
        return {"rules": rules}
    except Exception as e:
        logger.error(f"Error fetching rules: {e}")
        raise HTTPException(status_code=500, detail="Internal error")

@router.post("/api/v1/web3/rules", tags=["Web3 Security"])
def update_rules(rules: Dict[str, bool], principal: Dict[str, Any] = Depends(get_current_user)):
    """Admin endpoint: enable/disable detection rules. Persists to DB and syncs relay."""
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    unknown = set(rules.keys()) - _VALID_RULES
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown rules: {sorted(unknown)}")
    try:
        _ensure_tables()
        now = time.time()
        with sqlite3.connect(DB_PATH) as conn:
            for rule_name, enabled in rules.items():
                conn.execute(
                    "INSERT OR REPLACE INTO web3sec_rules (rule_name, enabled, updated_at) VALUES (?, ?, ?)",
                    (rule_name, 1 if enabled else 0, now)
                )
            conn.commit()
        # Best-effort relay sync (relay also reads DB on every tx, so this is just for immediacy)
        _notify_relay("POST", _RELAY_RULES_URL, json=rules)
        return {"status": "success", "updated": rules}
    except Exception as e:
        logger.error(f"Error updating rules: {e}")
        raise HTTPException(status_code=500, detail="Internal error")

@router.get("/api/v1/web3/whitelist", tags=["Web3 Security"])
def get_whitelist(principal: Dict[str, Any] = Depends(get_current_user)):
    """Admin endpoint: return current whitelisted addresses from DB."""
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    try:
        _ensure_tables()
        with sqlite3.connect(DB_PATH) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute("SELECT address, label, added_at FROM web3sec_whitelist ORDER BY added_at DESC").fetchall()
            return {"whitelist": [dict(r) for r in rows]}
    except Exception as e:
        logger.error(f"Error fetching whitelist: {e}")
        raise HTTPException(status_code=500, detail="Internal error")

@router.post("/api/v1/web3/whitelist", tags=["Web3 Security"])
def add_whitelist(payload: Dict[str, str], principal: Dict[str, Any] = Depends(get_current_user)):
    """Admin endpoint: add an address to the relay whitelist."""
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    address = payload.get("address", "").strip().lower()
    label = payload.get("label", "")
    if not address:
        raise HTTPException(status_code=400, detail="Address required")
    try:
        _ensure_tables()
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute(
                "INSERT OR REPLACE INTO web3sec_whitelist (address, label, added_at) VALUES (?, ?, ?)",
                (address, label, time.time())
            )
            conn.commit()
        _notify_relay("POST", _RELAY_WHITELIST_URL, json={"address": address, "label": label})
        return {"status": "success", "address": address}
    except Exception as e:
        logger.error(f"Error adding to whitelist: {e}")
        raise HTTPException(status_code=500, detail="Internal error")

@router.delete("/api/v1/web3/whitelist/{address}", tags=["Web3 Security"])
def remove_whitelist(address: str, principal: Dict[str, Any] = Depends(get_current_user)):
    """Admin endpoint: remove an address from the relay whitelist."""
    if principal.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Admin only")
    address = address.strip().lower()
    try:
        _ensure_tables()
        with sqlite3.connect(DB_PATH) as conn:
            conn.execute("DELETE FROM web3sec_whitelist WHERE address = ?", (address,))
            conn.commit()
        _notify_relay("DELETE", f"{_RELAY_WHITELIST_URL}/{address}")
        return {"status": "success", "address": address}
    except Exception as e:
        logger.error(f"Error removing from whitelist: {e}")
        raise HTTPException(status_code=500, detail="Internal error")

