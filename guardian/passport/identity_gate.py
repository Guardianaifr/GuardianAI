"""
Identity Gate — point-of-interaction enforcement for ERC-8004 / Guardian passports.

Closes the "registry exists, nobody checks it" gap: ERC-8004 registration
(erc8004_registrar.py) and the local passport engine (passport_core.py) are
both *discovery* primitives today — they answer "does this agent have an
identity" only if something bothers to ask. Nothing in the RPC relay or the
agentic control plane asked, before this module.

This is the single, shared, additive-only lookup layer both hot paths
consult:
  - guardian/web3sec/rpc_relay.py         (pre-flight, keyed by EVM `from` address)
  - guardian/security/agentic_controls.py (evaluate() gate, keyed by agent_id)

Design constraints:
  - Disabled by default. GUARDIAN_IDENTITY_GATE_ENABLED=false -> zero-cost
    pass-through, no DB or chain touch at all.
  - Fails OPEN on lookup errors by default. This is a DELIBERATE, NAMED
    EXCEPTION to GuardianAI's stated fail-closed philosophy (rpc_relay.py's
    own fail_mode="closed" default for calldata analysis) — identity lookups
    depend on infrastructure (SQLite locks, RPC endpoints) that is less
    reliable than the calldata analysis the relay already fails closed on,
    and this gate is new/unproven. Set GUARDIAN_IDENTITY_GATE_FAIL_CLOSED=true
    once it has burned in and you want lookup failures to block instead.
  - GUARDIAN_IDENTITY_GATE_MODE=shadow logs every decision the gate WOULD
    have made without ever actually returning allowed=False. Use this for
    burn-in before flipping to "enforce".
  - Cached with a short TTL so relay-path latency is ~0 after first lookup.
  - Never mutates state — read-only against agent_passports and (optionally)
    erc8004_registrations / the on-chain registry.

Env vars (all optional; gate is a no-op until GUARDIAN_IDENTITY_GATE_ENABLED=true):
  GUARDIAN_IDENTITY_GATE_ENABLED             default: false
  GUARDIAN_IDENTITY_GATE_MODE                default: enforce   (enforce|shadow)
  GUARDIAN_IDENTITY_GATE_MIN_TIER            default: UNVERIFIED (UNVERIFIED|SILVER|GOLD|DIAMOND)
  GUARDIAN_IDENTITY_GATE_UNREGISTERED_BLOCK  default: false
  GUARDIAN_IDENTITY_GATE_ONCHAIN_VERIFY      default: false
  GUARDIAN_IDENTITY_GATE_FAIL_CLOSED         default: false
  GUARDIAN_IDENTITY_GATE_CACHE_TTL           default: 60 (seconds)
  GUARDIAN_IDENTITY_GATE_CHAIN               default: base-sepolia (used only when ONCHAIN_VERIFY=true)
"""
from __future__ import annotations

import logging
import os
import re
import sqlite3
import threading
import time
from dataclasses import dataclass
from typing import Any, Dict, Optional

logger = logging.getLogger("guardian.passport.identity_gate")

_EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

_TIER_RANK = {"UNVERIFIED": 0, "SILVER": 1, "GOLD": 2, "DIAMOND": 3}


def _env_bool(name: str, default: bool) -> bool:
    val = os.environ.get(name)
    if val is None:
        return default
    return val.strip().lower() in ("1", "true", "yes", "on")


def _env_str(name: str, default: str) -> str:
    return os.environ.get(name, default)


def _env_int(name: str, default: int) -> int:
    try:
        return int(os.environ.get(name, str(default)))
    except (TypeError, ValueError):
        return default


@dataclass
class IdentityCheckResult:
    allowed: bool
    reason: str
    tier: str
    # "disabled" | "local_db" | "onchain" | "unregistered" | "error"
    source: str
    details: Optional[Dict[str, Any]] = None

    def as_details(self) -> Dict[str, Any]:
        d = dict(self.details or {})
        d.setdefault("identity_tier", self.tier)
        d.setdefault("identity_source", self.source)
        return d


class _CacheEntry:
    __slots__ = ("result", "expires_at")

    def __init__(self, result: IdentityCheckResult, expires_at: float):
        self.result = result
        self.expires_at = expires_at


class IdentityGate:
    """Shared point-of-interaction identity/tier check.

    Construct ONE instance per process (lazily, on first use) and share it
    between the RPC relay and the agentic control plane so the in-process
    cache actually helps both hot paths instead of being duplicated.
    """

    def __init__(self, passport_engine: Any, erc8004_db_path: Optional[str] = None):
        """
        passport_engine: a guardian.passport.passport_core.PassportEngine
            instance (or anything exposing get_passport() and
            get_passport_by_owner_address()).
        erc8004_db_path: path to the SQLite DB holding erc8004_registrations.
            Defaults to the passport engine's own db_path (same DB in
            practice — see erc8004_registrar.py module docstring).
        """
        self.passport_engine = passport_engine
        self.erc8004_db_path = erc8004_db_path or getattr(passport_engine, "db_path", None)

        self.enabled = _env_bool("GUARDIAN_IDENTITY_GATE_ENABLED", False)
        self.shadow_mode = _env_str("GUARDIAN_IDENTITY_GATE_MODE", "enforce").strip().lower() == "shadow"
        self.min_tier = _env_str("GUARDIAN_IDENTITY_GATE_MIN_TIER", "UNVERIFIED").strip().upper()
        self.block_unregistered = _env_bool("GUARDIAN_IDENTITY_GATE_UNREGISTERED_BLOCK", False)
        self.onchain_verify = _env_bool("GUARDIAN_IDENTITY_GATE_ONCHAIN_VERIFY", False)
        self.fail_closed = _env_bool("GUARDIAN_IDENTITY_GATE_FAIL_CLOSED", False)
        self.cache_ttl = _env_int("GUARDIAN_IDENTITY_GATE_CACHE_TTL", 60)

        if self.min_tier not in _TIER_RANK:
            logger.warning(
                "GUARDIAN_IDENTITY_GATE_MIN_TIER=%r is not a known tier, falling back to UNVERIFIED",
                self.min_tier,
            )
            self.min_tier = "UNVERIFIED"

        self._cache: Dict[str, _CacheEntry] = {}
        self._cache_lock = threading.Lock()

    # ── Public entry points ─────────────────────────────────────────

    def check_agent(self, agent_id: str) -> IdentityCheckResult:
        """Lookup keyed by Guardian agent_id. Used by agentic_controls.py."""
        if not self.enabled:
            return IdentityCheckResult(True, "disabled", "UNKNOWN", "disabled")
        if not agent_id:
            return self._unregistered_result("no_agent_id_provided")

        cache_key = f"agent:{agent_id}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            passport = self.passport_engine.get_passport(agent_id)
        except Exception as exc:  # noqa: BLE001
            logger.warning("IdentityGate DB lookup failed for agent_id=%s: %s", agent_id, exc)
            return self._error_result(str(exc))

        result = self._evaluate_passport(passport, lookup_key=agent_id)
        self._cache_set(cache_key, result)
        return result

    def check_address(self, address: str) -> IdentityCheckResult:
        """Lookup keyed by EVM wallet address (the tx `from`). Used by rpc_relay.py."""
        if not self.enabled:
            return IdentityCheckResult(True, "disabled", "UNKNOWN", "disabled")
        if not address:
            return self._unregistered_result("no_address_provided")

        normalized = address.strip()
        if not _EVM_ADDRESS_RE.match(normalized):
            # Malformed input isn't a DB/chain failure — treat as unregistered,
            # not an error, so it doesn't trip fail_closed for the wrong reason.
            return self._unregistered_result("malformed_address", details={"address": address})

        cache_key = f"addr:{normalized.lower()}"
        cached = self._cache_get(cache_key)
        if cached is not None:
            return cached

        try:
            passport = self._resolve_passport_by_address(normalized)
        except Exception as exc:  # noqa: BLE001
            logger.warning("IdentityGate DB lookup failed for address=%s: %s", normalized, exc)
            return self._error_result(str(exc))

        result = self._evaluate_passport(passport, lookup_key=normalized)
        self._cache_set(cache_key, result)
        return result

    # ── Resolution ───────────────────────────────────────────────────

    def _resolve_passport_by_address(self, address: str):
        """Prefer erc8004_registrations.owner_address (validated EVM address,
        set only after a confirmed register-then-transfer) over
        agent_passports.owner_pubkey (operator-supplied, not guaranteed to be
        a checksummed EVM address). Falls back to owner_pubkey so agents that
        never went through ERC-8004 registration are still resolvable.
        """
        agent_id = self._agent_id_for_confirmed_owner_address(address)
        if agent_id:
            passport = self.passport_engine.get_passport(agent_id)
            if passport is not None:
                return passport
        return self.passport_engine.get_passport_by_owner_address(address)

    def _agent_id_for_confirmed_owner_address(self, address: str) -> Optional[str]:
        if not self.erc8004_db_path:
            return None
        try:
            conn = sqlite3.connect(self.erc8004_db_path)
            try:
                cur = conn.cursor()
                # LEFT JOIN agent_passports so a wallet shared by an active
                # and a revoked/deleted registration resolves to the active
                # one first — mirrors the ORDER BY is_active DESC tiebreak in
                # get_passport_by_owner_address(). Without this, a wallet
                # holding two confirmed registrations (one revoked) could
                # resolve to the revoked agent purely because its
                # registration row was touched more recently, incorrectly
                # blocking the real active agent's real wallet. Requires
                # agent_passports and erc8004_registrations to live in the
                # same DB file (true by default — see erc8004_registrar's
                # default_db_path()); if they're ever split across files,
                # this join silently degrades to "no match" rather than
                # raising, since the whole call is wrapped below.
                cur.execute(
                    """
                    SELECT r.agent_id
                    FROM erc8004_registrations r
                    LEFT JOIN agent_passports p ON p.agent_id = r.agent_id
                    WHERE r.owner_address = ? COLLATE NOCASE AND r.status = 'confirmed'
                    ORDER BY COALESCE(p.is_active, 0) DESC, r.updated_at DESC
                    LIMIT 1
                    """,
                    (address,),
                )
                row = cur.fetchone()
                return row[0] if row else None
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001
            # erc8004_registrations (or agent_passports, for the join) may
            # not exist yet — that's normal, not a failure worth failing
            # closed over.
            logger.debug("IdentityGate: erc8004_registrations lookup skipped: %s", exc)
            return None

    def _evaluate_passport(self, passport: Any, lookup_key: str) -> IdentityCheckResult:
        if passport is None:
            return self._unregistered_result("no_passport", details={"lookup_key": lookup_key})

        if not getattr(passport, "is_active", True):
            return self._blocked("revoked_passport", passport, details={"lookup_key": lookup_key})

        tier = str(getattr(passport, "tier", "UNVERIFIED") or "UNVERIFIED").upper()
        if _TIER_RANK.get(tier, 0) < _TIER_RANK.get(self.min_tier, 0):
            return self._blocked(
                "below_minimum_tier", passport,
                details={"lookup_key": lookup_key, "required_tier": self.min_tier},
            )

        if self.onchain_verify:
            onchain_result = self._verify_onchain(passport)
            if onchain_result is not None:
                return onchain_result

        return IdentityCheckResult(
            True, "ok", tier, "local_db",
            details={"agent_id": getattr(passport, "agent_id", None)},
        )

    # ── On-chain (optional layer) ───────────────────────────────────

    def _verify_onchain(self, passport: Any) -> Optional[IdentityCheckResult]:
        """Confirm the registry actually knows this agent's token and that
        ownership is non-zero. Returns None (no override — fall through to
        the local-DB result) when on-chain verification can't run at all;
        that's an availability problem, handled by _chain_unavailable_result,
        not the same thing as a genuine on-chain block.
        """
        try:
            from guardian.passport.erc8004_registrar import (
                IDENTITY_REGISTRY_ABI,
                _resolve_chain_config,
            )
            from web3 import Web3
        except Exception as exc:  # noqa: BLE001
            logger.warning("IdentityGate on-chain verify unavailable (import): %s", exc)
            return self._chain_unavailable_result(passport)

        token_id = self._token_id_for(passport)
        if token_id is None:
            # A local passport exists but there's no confirmed on-chain
            # registration for it — a real signal, not a lookup error.
            return self._unregistered_result(
                "no_onchain_registration",
                details={"agent_id": getattr(passport, "agent_id", None)},
            )

        try:
            chain = _env_str("GUARDIAN_IDENTITY_GATE_CHAIN", "base-sepolia")
            cfg = _resolve_chain_config(chain)
            w3 = Web3(Web3.HTTPProvider(cfg["rpc_url"]))
            contract = w3.eth.contract(
                address=Web3.to_checksum_address(cfg["registry"]),
                abi=IDENTITY_REGISTRY_ABI,
            )
            owner = contract.functions.ownerOf(token_id).call()
        except Exception as exc:  # noqa: BLE001
            logger.warning("IdentityGate on-chain ownerOf(%s) failed: %s", token_id, exc)
            return self._chain_unavailable_result(passport)

        if not owner or int(owner, 16) == 0:
            return self._blocked("onchain_owner_zero", passport, details={"token_id": token_id})

        tier = str(getattr(passport, "tier", "UNVERIFIED") or "UNVERIFIED").upper()
        return IdentityCheckResult(
            True, "ok", tier, "onchain",
            details={"agent_id": getattr(passport, "agent_id", None), "token_id": token_id, "owner": owner},
        )

    def _token_id_for(self, passport: Any) -> Optional[int]:
        if not self.erc8004_db_path:
            return None
        agent_id = getattr(passport, "agent_id", None)
        if not agent_id:
            return None
        try:
            conn = sqlite3.connect(self.erc8004_db_path)
            try:
                cur = conn.cursor()
                cur.execute(
                    """
                    SELECT token_id FROM erc8004_registrations
                    WHERE agent_id = ? AND status = 'confirmed' AND token_id IS NOT NULL
                    ORDER BY updated_at DESC LIMIT 1
                    """,
                    (agent_id,),
                )
                row = cur.fetchone()
                return int(row[0]) if row and row[0] is not None else None
            finally:
                conn.close()
        except Exception as exc:  # noqa: BLE001
            logger.debug("IdentityGate: token_id lookup skipped: %s", exc)
            return None

    def _chain_unavailable_result(self, passport: Any) -> Optional[IdentityCheckResult]:
        if self.fail_closed:
            return self._blocked("onchain_verify_unavailable", passport, details={})
        # Fail-open for chain reads (default): fall through to local-DB result.
        return None

    # ── Result constructors (shadow-mode aware) ─────────────────────

    def _blocked(self, reason: str, passport: Any, details: Dict[str, Any]) -> IdentityCheckResult:
        tier = str(getattr(passport, "tier", "UNVERIFIED") or "UNVERIFIED").upper() if passport else "UNVERIFIED"
        if self.shadow_mode:
            logger.info("IdentityGate SHADOW would-block: reason=%s tier=%s details=%s", reason, tier, details)
            return IdentityCheckResult(True, reason, tier, "local_db", details=details)
        return IdentityCheckResult(False, reason, tier, "local_db", details=details)

    def _unregistered_result(self, reason: str, details: Optional[Dict[str, Any]] = None) -> IdentityCheckResult:
        if not self.block_unregistered:
            return IdentityCheckResult(True, reason, "UNKNOWN", "unregistered", details=details)
        if self.shadow_mode:
            logger.info("IdentityGate SHADOW would-block (unregistered): reason=%s details=%s", reason, details)
            return IdentityCheckResult(True, reason, "UNKNOWN", "unregistered", details=details)
        return IdentityCheckResult(False, reason, "UNKNOWN", "unregistered", details=details)

    def _error_result(self, error: str) -> IdentityCheckResult:
        if not self.fail_closed:
            return IdentityCheckResult(True, "lookup_error", "UNKNOWN", "error", details={"error": error})
        if self.shadow_mode:
            logger.info("IdentityGate SHADOW would-block (lookup_error): %s", error)
            return IdentityCheckResult(True, "lookup_error", "UNKNOWN", "error", details={"error": error})
        return IdentityCheckResult(False, "lookup_error", "UNKNOWN", "error", details={"error": error})

    # ── Cache ────────────────────────────────────────────────────────

    def _cache_get(self, key: str) -> Optional[IdentityCheckResult]:
        if self.cache_ttl <= 0:
            return None
        with self._cache_lock:
            entry = self._cache.get(key)
            if entry is None:
                return None
            if entry.expires_at < time.time():
                self._cache.pop(key, None)
                return None
            return entry.result

    def _cache_set(self, key: str, result: IdentityCheckResult) -> None:
        if self.cache_ttl <= 0:
            return
        with self._cache_lock:
            self._cache[key] = _CacheEntry(result, time.time() + self.cache_ttl)
            # Cheap bound so a long-running process doesn't grow unbounded.
            if len(self._cache) > 50000:
                self._cache.clear()
