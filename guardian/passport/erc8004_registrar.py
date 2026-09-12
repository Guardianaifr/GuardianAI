"""
ERC-8004 Identity Registration for GuardianAI-protected agents.

Registers agents on the *canonical* ERC-8004 Identity Registry (never a
GuardianAI-deployed copy) and links the resulting agentId back to the
agent's GuardianPassport via setMetadata(agentId, "guardianPassportId", <passport_id utf-8>).

Design constraints (per approved scope, 2026-08):
  - Additive only. Nothing in this module is active unless
    GUARDIAN_ERC8004_ENABLED=true.
  - Chain state must never affect proxy/traffic availability: every public
    entrypoint swallows chain errors into queue status.
  - Fail-closed on chain safety: before the first transaction on any chain,
    require non-empty bytecode at the canonical address (eth_getCode) so a
    missing deployment aborts instead of sending funds into the void.
  - Idempotent retries: a registration tx that was broadcast but whose
    receipt-wait timed out is RECOVERED on retry (receipt re-query), never
    blindly re-sent — a second mint would orphan the first agentId.
  - Single-writer claim: rows are claimed with a conditional UPDATE before
    processing, so concurrent workers/threads cannot double-send.

Known constraints (accepted, documented):
  - Ownership policy (SETTLED 2026-08): transient registrar custody. The base
    ERC-8004 contracts have NO caller-specified-owner register(); minting goes
    to msg.sender by design. Sequence is therefore register -> setMetadata ->
    transferFrom(registrar, client_owner, agentId). Transfer MUST come after
    setMetadata because only the current owner can write metadata. When no
    client owner address is supplied the identity remains custodial
    (status confirmed, owner_address NULL) — visible in get_status().
    Permanent-custody alternative precedent: Adapter8004 (adapter8004.xyz);
    revisit only if GuardianAI-as-permanent-custodian ever becomes the plan.
  - One worker process assumption: two backend instances sharing one DB are
    guarded by the conditional-claim UPDATE, but cross-instance ordering is
    not coordinated. Same architectural class as Feature 25 (F25).
  - The ABI subset below MUST be re-validated against the pinned audited
    release of github.com/erc-8004/erc-8004-contracts before any mainnet
    enablement; the registry is UUPS-upgradeable and Validation is unstable.
  - agentURI is mutable HTTPS. Acceptable for discovery-only v1.

Queue schema (same SQLite DB as the passport engine):
    erc8004_registrations(
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        agent_id TEXT NOT NULL,
        passport_id TEXT NOT NULL,
        chain TEXT NOT NULL,
        status TEXT NOT NULL,          -- pending|registering|metadata|confirmed|failed
        token_id INTEGER,              -- ERC-8004 agentId once known
        tx_hash TEXT,
        retries INTEGER DEFAULT 0,
        last_error TEXT,
        updated_at REAL,
        UNIQUE(agent_id, chain)
    )

Author: GuardianAI Team
License: MIT
"""
import json
import logging
import os
import re
import sqlite3
import threading
import time
from typing import Any, Callable, Dict, List, Optional

logger = logging.getLogger("GuardianAI.passport.erc8004")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

METADATA_KEY = "guardianPassportId"

REGISTRATION_FILE_TYPE = "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"

# Canonical singleton deployed deterministically (CREATE2 vanity tooling).
# Same address across chains; override only for local fork tests.
CANONICAL_IDENTITY_REGISTRY = "0x8004A169FB4a3325136EB29fA0ceB6D2e539a432"
MONAD_TESTNET_REGISTRY = "0xB98644392B035a4bA7207a6EcBfF0Ba82a57AfcE"

# Best-known defaults; every value overridable via env. Chain IDs for Monad
# are community-published — verify against official docs at enablement time.
# 'testnet' chains are exempt from the production-URI safety gate.
# Strictly targeting Monad Testnet only.
CHAIN_DEFAULTS: Dict[str, Dict[str, Any]] = {
    "monad-testnet": {
        "chain_id": 10143,
        "rpc_url": "https://testnet-rpc.monad.xyz",
        "registry": MONAD_TESTNET_REGISTRY,
        "testnet": True,
    },
}

STATUS_PENDING = "pending"
STATUS_REGISTERING = "registering"
STATUS_METADATA = "metadata"
STATUS_CONFIRMED = "confirmed"
STATUS_FAILED = "failed"

TRANSFER_EVENT_SIG = (
    "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"
)

# agent_id flows into an on-chain URI and a filesystem-adjacent path; keep it
# to a conservative charset. Passport agent_ids are operator-supplied.
_AGENT_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")

# Client ownership handoff target (register-then-transfer policy).
_EVM_ADDRESS_RE = re.compile(r"^0x[a-fA-F0-9]{40}$")

# Minimal ABI subset — validate against the pinned registry release before
# enabling any mainnet chain (see module docstring).
IDENTITY_REGISTRY_ABI = [
    {
        "inputs": [{"name": "agentURI", "type": "string"}],
        "name": "register",
        "outputs": [{"name": "", "type": "uint256"}],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "metadataKey", "type": "string"},
            {"name": "metadataValue", "type": "bytes"},
        ],
        "name": "setMetadata",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "agentId", "type": "uint256"},
            {"name": "metadataKey", "type": "string"},
        ],
        "name": "getMetadata",
        "outputs": [{"name": "", "type": "bytes"}],
        "stateMutability": "view",
        "type": "function",
    },
    {
        "inputs": [
            {"name": "from", "type": "address"},
            {"name": "to", "type": "address"},
            {"name": "tokenId", "type": "uint256"},
        ],
        "name": "transferFrom",
        "outputs": [],
        "stateMutability": "nonpayable",
        "type": "function",
    },
    {
        "inputs": [{"name": "tokenId", "type": "uint256"}],
        "name": "ownerOf",
        "outputs": [{"name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    },
]


def is_valid_owner_address(addr: str) -> bool:
    """Handoff target for register-then-transfer ownership policy."""
    return bool(addr) and bool(_EVM_ADDRESS_RE.match(addr))


def to_checksum_address(addr: str) -> str:
    """
    Normalize any valid-hex address to EIP-55 checksum form. web3.py refuses
    non-checksummed addresses at call time (transferFrom was the first
    casualty); normalizing at the boundary keeps lowercase user input working.
    Falls back to the input if web3 is unavailable (offline unit tests).
    """
    try:
        from web3 import Web3 as _Web3

        return _Web3.to_checksum_address(addr)
    except Exception:  # noqa: BLE001
        return addr


class RegistrarDisabled(Exception):
    """Feature flag off — callers should treat as a silent no-op."""


class RegistrarMisconfigured(Exception):
    """Enabled but unusable (missing key, unknown chain, empty bytecode)."""


class TxReceiptTimeout(RuntimeError):
    """Broadcast succeeded but the receipt wait timed out.

    Carries the broadcast tx hash so the failure handler can persist it —
    losing this hash would make recovery impossible and force a double mint.
    """

    def __init__(self, tx_hash_hex: str, cause: Exception):
        super().__init__(f"receipt wait timed out for {tx_hash_hex}: {cause}")
        self.tx_hash = tx_hash_hex


class _DailyWeiBudget:
    """
    Denial-of-Wallet guard (scope item GUARDIAN_ERC8004_DAILY_BUDGET_WEI).
    Accumulates ACTUAL spend from receipts and refuses new broadcasts once the
    UTC-day budget is exhausted. 0 disables the cap. In-process only — restart
    resets the accumulator, which is acceptable for a single-operator guard.
    """

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._day = ""
        self._spent_wei = 0

    def _today(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime())

    def _rollover(self) -> None:
        today = self._today()
        if today != self._day:
            self._day = today
            self._spent_wei = 0

    def check(self, limit_wei: int) -> None:
        if limit_wei <= 0:
            return
        with self._lock:
            self._rollover()
            if self._spent_wei >= limit_wei:
                raise RegistrarMisconfigured(
                    f"Daily on-chain spend budget exhausted "
                    f"({self._spent_wei} / {limit_wei} wei today)"
                )

    def accumulate(self, limit_wei: int, gas_used: int,
                   effective_gas_price: int) -> None:
        if limit_wei <= 0:
            return
        with self._lock:
            self._rollover()
            self._spent_wei += gas_used * effective_gas_price


_budget = _DailyWeiBudget()


def _env(name: str, default: str = "") -> str:
    return os.getenv(name, default).strip()


def _enabled() -> bool:
    return _env("GUARDIAN_ERC8004_ENABLED", "false").lower() in {"1", "true", "yes", "on"}


def is_enabled() -> bool:
    """Public feature-flag check for routers/tests."""
    return _enabled()


def is_valid_agent_id(agent_id: str) -> bool:
    """Conservative charset for a value that enters an on-chain URI."""
    return bool(agent_id) and bool(_AGENT_ID_RE.match(agent_id))


def _resolve_chain_config(chain: str) -> Dict[str, Any]:
    base = CHAIN_DEFAULTS.get(chain)
    if base is None:
        raise RegistrarMisconfigured(
            f"Unsupported chain '{chain}'. System strictly targets monad-testnet only."
        )
    cfg = dict(base)
    rpc_override = (
        _env(f"GUARDIAN_ERC8004_RPC_{chain.upper().replace('-', '_')}")
        or _env("GUARDIAN_UPSTREAM_RPC")
        or _env("MONAD_TESTNET_RPC")
        or _env("MONAD_RPC_URL")
    )
    if rpc_override:
        cfg["rpc_url"] = rpc_override
    # Per-chain registry override first (multi-chain deployments register on
    # differently-addressed instances), then the global override, then the
    # canonical CREATE2 address.
    chain_registry = _env(
        f"GUARDIAN_ERC8004_REGISTRY_{chain.upper().replace('-', '_')}"
    )
    registry_override = _env("GUARDIAN_ERC8004_IDENTITY_REGISTRY_OVERRIDE")
    cfg["registry"] = (
        chain_registry or registry_override or base.get("registry") or CANONICAL_IDENTITY_REGISTRY
    )
    return cfg


def encode_passport_link(passport_id: str) -> bytes:
    """Metadata value encoding — defined once, documented, never improvised."""
    return passport_id.encode("utf-8")


def build_registration_file(
    agent_id: str,
    chain: str,
    token_id: Optional[int],
    base_url: str,
) -> Dict[str, Any]:
    """Build the ERC-8004 registration JSON served at the agentURI endpoint."""
    cfg = _resolve_chain_config(chain)
    file_obj: Dict[str, Any] = {
        "type": REGISTRATION_FILE_TYPE,
        "name": agent_id,
        "description": (
            "AI agent protected by GuardianAI. Identity registered for "
            "discovery; security telemetry is produced by the GuardianAI "
            "control plane."
        ),
        "services": [],
        "x402Support": False,
        "active": True,
        "registrations": [],
    }
    if token_id is not None:
        file_obj["registrations"].append(
            {
                "agentId": token_id,
                "agentRegistry": f"eip155:{cfg['chain_id']}:{cfg['registry']}",
            }
        )
    # supportedTrust intentionally omitted until Reputation emission ships:
    # per spec, absence means discovery-only, which is exactly this step's claim.
    return file_obj


class ERC8004Registrar:
    """Chain-facing registration client. All chain errors become queue status."""

    def __init__(
        self,
        chain: str,
        db_path: str,
        w3_factory: Optional[Callable[[str], Any]] = None,
        account_factory: Optional[Callable[[str], Any]] = None,
    ):
        self.chain = chain
        self.db_path = db_path
        self.cfg = _resolve_chain_config(chain)
        # Per-chain ceiling first: some chains (e.g. Monad testnet) keep a
        # nominally high gasPrice while actual cost stays negligible.
        self.max_gas_gwei = float(_env(
            f"GUARDIAN_MAX_GAS_PRICE_GWEI_{chain.upper().replace('-', '_')}",
            _env("GUARDIAN_MAX_GAS_PRICE_GWEI", "100"),
        ))
        self.max_retries = int(_env("GUARDIAN_ERC8004_MAX_RETRIES", "5"))
        self._w3_factory = w3_factory or self._default_w3_factory
        self._account_factory = account_factory or self._default_account_factory
        self._w3_client = None
        self._account = None
        self._code_checked = False
        # Serializes send+update within this process; cross-process safety
        # comes from the conditional-claim UPDATE in process_pending().
        self._send_lock = threading.Lock()
        
        if is_enabled() and int(_env("GUARDIAN_ERC8004_DAILY_BUDGET_WEI", "0")) == 0:
            logger.warning("ERC-8004 enabled with zero daily budget — no spend cap enforced. Set GUARDIAN_ERC8004_DAILY_BUDGET_WEI to limit gas spend.")

    # -- injectable factories ------------------------------------------------

    @staticmethod
    def _default_w3_factory(rpc_url: str):
        from web3 import Web3

        return Web3(Web3.HTTPProvider(rpc_url))

    @staticmethod
    def _default_account_factory(private_key: str):
        from eth_account import Account

        return Account.from_key(private_key)

    # -- lazy resources ------------------------------------------------------

    def _w3(self):
        if self._w3_client is None:
            self._w3_client = self._w3_factory(self.cfg["rpc_url"])
        return self._w3_client

    @property
    def w3(self):
        return self._w3()

    def _key_account(self):
        if self._account is None:
            key = _env("GUARDIAN_ERC8004_REGISTRAR_KEY")
            if not key:
                raise RegistrarMisconfigured(
                    "GUARDIAN_ERC8004_REGISTRAR_KEY not set"
                )
            self._account = self._account_factory(key)
        return self._account

    def _contract(self):
        return self._w3().eth.contract(
            address=self.w3.to_checksum_address(self.cfg["registry"]),
            abi=IDENTITY_REGISTRY_ABI,
        )

    # -- safety gates --------------------------------------------------------

    def _verify_deployment(self) -> None:
        """Fail-closed gate: refuse to send unless bytecode exists at registry."""
        if self._code_checked:
            return
        code = self.w3.eth.get_code(self.cfg["registry"])
        if not code:
            raise RegistrarMisconfigured(
                f"No bytecode at canonical registry {self.cfg['registry']} on "
                f"{self.chain} — refusing to register (fail-closed)"
            )
        self._code_checked = True

    def _verify_uri_target(self) -> str:
        """
        The agentURI is PERMANENT on-chain state. A localhost/default
        PUBLIC_BASE_URL must never reach a mainnet registry (fail-closed);
        testnets are exempt so local rehearsal stays frictionless.
        """
        base_url = self._agent_uri_base()
        if not self.cfg.get("testnet"):
            lowered = base_url.lower()
            if ("localhost" in lowered or "127.0.0.1" in lowered
                    or not lowered.startswith("https://")):
                raise RegistrarMisconfigured(
                    f"GUARDIAN_PUBLIC_URL ({base_url}) is not a production "
                    f"https:// URL — refusing to bake it into {self.chain} "
                    "registry state (fail-closed). Set GUARDIAN_PUBLIC_URL to "
                    "the public https endpoint."
                )
        return base_url

    def _gas_price_wei(self) -> int:
        gas_price = self.w3.eth.gas_price
        gwei = gas_price / 1e9
        if gwei > self.max_gas_gwei:
            raise RegistrarMisconfigured(
                f"Gas price {gwei:.2f} gwei exceeds safety limit "
                f"{self.max_gas_gwei} gwei — aborting registration tx"
            )
        return int(gas_price)

    def _send(self, contract_fn) -> Dict[str, Any]:
        acct = self._key_account()
        # Chain-suffixed budget first: nominal gasPrice overstates real cost
        # on some chains (Monad testnet reports 100+ gwei at near-zero cost).
        budget_wei = int(_env(
            f"GUARDIAN_ERC8004_DAILY_BUDGET_WEI_{self.chain.upper().replace('-', '_')}",
            _env("GUARDIAN_ERC8004_DAILY_BUDGET_WEI", "0"),
        ))
        _budget.check(budget_wei)
        with self._send_lock:
            # web3.py transaction dicts use camelCase keys ("gasPrice",
            # "chainId") — snake_case raises "Unknown kwargs" on real web3.
            tx = contract_fn.build_transaction(
                {
                    "from": acct.address,
                    "nonce": self.w3.eth.get_transaction_count(acct.address),
                    "gasPrice": self._gas_price_wei(),
                    "chainId": self.cfg["chain_id"],
                }
            )
            signed = acct.sign_transaction(tx)
            tx_hash = self.w3.eth.send_raw_transaction(signed.raw_transaction)
            tx_hash_hex = tx_hash.hex()
            try:
                receipt = self.w3.eth.wait_for_transaction_receipt(
                    tx_hash, timeout=120
                )
            except Exception as exc:  # noqa: BLE001
                raise TxReceiptTimeout(tx_hash_hex, exc) from exc
        if receipt.status != 1:
            raise RuntimeError(f"Transaction reverted: {tx_hash_hex}")
        gas_used = int(getattr(receipt, "gasUsed", 0) or 0)
        eff_price = int(getattr(receipt, "effectiveGasPrice", 0) or 0)
        _budget.accumulate(budget_wei, gas_used, eff_price)
        return {"tx_hash": tx_hash_hex, "receipt": receipt}

    # -- queue ---------------------------------------------------------------

    def _ensure_table(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS erc8004_registrations (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                agent_id TEXT NOT NULL,
                passport_id TEXT NOT NULL,
                chain TEXT NOT NULL,
                status TEXT NOT NULL,
                token_id INTEGER,
                tx_hash TEXT,
                retries INTEGER DEFAULT 0,
                last_error TEXT,
                updated_at REAL,
                owner_address TEXT,
                UNIQUE(agent_id, chain)
            )
            """
        )
        # In-place migration for tables created before ownership handoff.
        cols = {row[1] for row in conn.execute(
            "PRAGMA table_info(erc8004_registrations)"
        ).fetchall()}
        required_cols = {
            "token_id": "INTEGER",
            "tx_hash": "TEXT",
            "retries": "INTEGER DEFAULT 0",
            "last_error": "TEXT",
            "updated_at": "REAL",
            "owner_address": "TEXT",
        }
        for col, col_type in required_cols.items():
            if col not in cols:
                conn.execute(f"ALTER TABLE erc8004_registrations ADD COLUMN {col} {col_type}")
        # In-place migration: ensure all rows point to monad-testnet (if there was any old test data)
        conn.execute(
            """
            UPDATE OR IGNORE erc8004_registrations
            SET chain = 'monad-testnet'
            WHERE chain IN ('legacy-chain', 'legacy-chain-2', 'ethereum')
              AND agent_id NOT IN (
                  SELECT agent_id FROM erc8004_registrations WHERE chain = 'monad-testnet'
              )
            """
        )
        conn.commit()

    def enqueue(
        self, agent_id: str, passport_id: str, reset_failed: bool = False,
        owner_address: Optional[str] = None,
    ) -> bool:
        """
        Queue a registration. Never raises on storage errors.

        reset_failed=True (admin re-register route): a previously FAILED row is
        reset to pending with retries cleared so the operator can force a fresh
        attempt. Confirmed/mid-flight rows are never touched.

        owner_address (register-then-transfer policy): EVM address that will
        receive the identity NFT after the metadata link is written. Absent =
        identity stays custodial with the registrar.
        """
        if not is_valid_agent_id(agent_id):
            logger.warning("ERC-8004 enqueue rejected invalid agent_id %r", agent_id)
            return False
        if owner_address is not None and not is_valid_owner_address(owner_address):
            logger.warning(
                "ERC-8004 enqueue rejected invalid owner_address %r", owner_address
            )
            return False
        try:
            conn = sqlite3.connect(self.db_path)
            try:
                self._ensure_table(conn)
                cur = conn.cursor()
                if reset_failed:
                    cur.execute(
                        """
                        UPDATE erc8004_registrations
                        SET status=?, retries=0, last_error=NULL, updated_at=?,
                            owner_address=?
                        WHERE agent_id=? AND chain=? AND status=?
                        """,
                        (STATUS_PENDING, time.time(), owner_address,
                         agent_id, self.chain, STATUS_FAILED),
                    )
                cur.execute(
                    """
                    INSERT OR IGNORE INTO erc8004_registrations
                        (agent_id, passport_id, chain, status, updated_at,
                         owner_address)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    (agent_id, passport_id, self.chain, STATUS_PENDING,
                     time.time(), owner_address),
                )
                conn.commit()
            finally:
                conn.close()
            return True
        except Exception as exc:  # noqa: BLE001 — queue failure must not break issuance
            logger.warning("ERC-8004 enqueue failed (non-fatal): %s", exc)
            return False

    def get_status(self, agent_id: str) -> List[Dict[str, Any]]:
        conn = sqlite3.connect(self.db_path)
        try:
            self._ensure_table(conn)
            rows = conn.execute(
                """
                SELECT agent_id, passport_id, chain, status, token_id,
                       tx_hash, retries, last_error, updated_at, owner_address
                FROM erc8004_registrations WHERE agent_id = ?
                """,
                (agent_id,),
            ).fetchall()
        finally:
            conn.close()
        keys = [
            "agent_id", "passport_id", "chain", "status", "token_id",
            "tx_hash", "retries", "last_error", "updated_at", "owner_address",
        ]
        return [dict(zip(keys, r)) for r in rows]

    # -- processing ----------------------------------------------------------

    def process_pending(self, limit: int = 10) -> int:
        """Advance up to `limit` claimed registrations one step each."""
        conn = sqlite3.connect(self.db_path)
        try:
            self._ensure_table(conn)
            rows = conn.execute(
                """
                SELECT id, agent_id, passport_id, chain, status, token_id,
                       tx_hash, retries, owner_address
                FROM erc8004_registrations
                WHERE (status IN (?, ?, ?)
                       OR (status = ? AND retries < ?))
                  AND retries <= ?
                ORDER BY updated_at ASC LIMIT ?
                """,
                (STATUS_PENDING, STATUS_REGISTERING, STATUS_METADATA,
                 STATUS_FAILED, self.max_retries, self.max_retries, limit),
            ).fetchall()
        finally:
            conn.close()

        processed = 0
        for row_id, agent_id, passport_id, chain, status, token_id, tx_hash, \
                retries, owner_address in rows:
            registrar = self if chain == self.chain else ERC8004Registrar(
                chain, self.db_path, self._w3_factory, self._account_factory
            )
            claimed_status = registrar._claim(row_id, status)
            if claimed_status is None:
                continue  # another worker claimed it between SELECT and UPDATE
            try:
                new_status, new_token, new_tx = registrar._advance(
                    claimed_status, agent_id, passport_id, token_id, tx_hash,
                    owner_address,
                )
                registrar._update_row(row_id, new_status, new_token, new_tx,
                                      error=None)
            except Exception as exc:  # noqa: BLE001 — failures become status
                # Preserve a hash broadcast this attempt (receipt-wait timeout):
                # without it the retry cannot recover and would double-mint.
                fallback_tx = getattr(exc, "tx_hash", None) or tx_hash
                registrar._update_row(row_id, STATUS_FAILED, None, fallback_tx,
                                      error=str(exc), increment_retry=retries)
            processed += 1
        return processed

    def _claim(self, row_id: int, expected_status: str) -> Optional[str]:
        """
        Atomically claim a row. Returns the status to process under, or None
        if another worker claimed it first. 'pending'/'failed' move to
        'registering'; mid-flight statuses are pinned to themselves so only
        one thread can hold them.
        """
        target = (
            STATUS_REGISTERING
            if expected_status in (STATUS_PENDING, STATUS_FAILED,
                                   STATUS_REGISTERING)
            else expected_status
        )
        conn = sqlite3.connect(self.db_path)
        try:
            cur = conn.execute(
                "UPDATE erc8004_registrations SET status=?, updated_at=? "
                "WHERE id=? AND status=?",
                (target, time.time(), row_id, expected_status),
            )
            conn.commit()
            return target if cur.rowcount == 1 else None
        finally:
            conn.close()

    def _advance(self, status, agent_id, passport_id, token_id, tx_hash=None,
                 owner_address=None):
        """
        One state-machine step. Idempotency rule: whenever a tx_hash exists we
        attempt RECEIPT RECOVERY instead of broadcasting again — a register tx
        that mined but whose wait timed out must never be re-sent (double mint).

        Ownership policy (register-then-transfer): when owner_address is set,
        the identity is handed to the client AFTER the metadata link is written
        — transfer must follow setMetadata because only the current owner can
        write metadata. On retry after a partial failure, setMetadata may run
        again; it is an idempotent overwrite, and transferFrom is re-attempted.
        """
        self._verify_deployment()
        contract = self._contract()

        if status == STATUS_METADATA:
            if token_id is None:
                raise RuntimeError(
                    "metadata step reached without a token_id — refusing to "
                    "write a link against an unknown agentId"
                )
            link = encode_passport_link(passport_id)
            result = self._send(
                contract.functions.setMetadata(int(token_id), METADATA_KEY, link)
            )
            logger.info(
                "ERC-8004 passport link written for %s (agentId=%s) tx=%s",
                agent_id, token_id, result["tx_hash"],
            )
            if owner_address:
                acct = self._key_account()
                # Idempotence guard: if a previous transfer attempt actually
                # mined (receipt-wait timeout), re-sending would revert and
                # burn retries on an already-successful handoff.
                try:
                    current = contract.functions.ownerOf(
                        int(token_id)
                    ).call()
                    already_owned = int(current, 16) == int(owner_address, 16)
                except Exception:  # noqa: BLE001 — view failure → attempt send
                    already_owned = False
                if already_owned:
                    logger.info(
                        "ERC-8004 agentId=%s already owned by %s — transfer "
                        "skipped", token_id, owner_address,
                    )
                else:
                    owner_checksummed = to_checksum_address(owner_address)
                    xfer = self._send(
                        contract.functions.transferFrom(
                            acct.address, owner_checksummed, int(token_id)
                        )
                    )
                    logger.info(
                        "ERC-8004 ownership transferred for %s (agentId=%s) "
                        "→ %s tx=%s",
                        agent_id, token_id, owner_address, xfer["tx_hash"],
                    )
            return STATUS_CONFIRMED, token_id, result["tx_hash"]

        # pending / failed / registering → ensure an agentId exists
        if token_id is not None:
            return STATUS_METADATA, token_id, tx_hash  # already minted
        if tx_hash:
            recovered = self._recover_mined_tx(tx_hash)
            if recovered is not None:
                logger.info(
                    "ERC-8004 recovered mined registration tx %s → agentId=%s",
                    tx_hash, recovered,
                )
                return STATUS_METADATA, recovered, tx_hash
            raise RuntimeError(
                f"previous registration tx {tx_hash} not yet mined — will "
                "retry recovery rather than double-mint"
            )
        uri = self._verify_uri_target() + f"/api/v1/erc8004/agents/{agent_id}.json"
        result = self._send(contract.functions.register(uri))
        token = self._token_from_receipt(
            result["receipt"], required_to=self._registrar_address()
        )
        logger.info(
            "ERC-8004 registered %s on %s → agentId=%s tx=%s",
            agent_id, self.chain, token, result["tx_hash"],
        )
        return STATUS_METADATA, token, result["tx_hash"]

    def _registrar_address(self) -> Optional[str]:
        """Registrar address if the key is available; None enables sig-only
        log matching so receipt recovery still works after key rotation."""
        try:
            return self._key_account().address
        except RegistrarMisconfigured:
            return None

    def _recover_mined_tx(self, tx_hash: str) -> Optional[int]:
        """Re-query a previously broadcast tx. Returns tokenId if it mined."""
        try:
            receipt = self.w3.eth.get_transaction_receipt(tx_hash)
        except Exception:  # noqa: BLE001 — not found / RPC hiccup → not mined yet
            return None
        if receipt is None or getattr(receipt, "status", 0) != 1:
            return None
        return self._token_from_receipt(
            receipt, required_to=self._registrar_address()
        )

    def _agent_uri_base(self) -> str:
        return _env("GUARDIAN_PUBLIC_URL", "http://localhost:8001").rstrip("/")

    def _agent_uri(self, agent_id: str) -> str:
        return f"{self._agent_uri_base()}/api/v1/erc8004/agents/{agent_id}.json"

    @staticmethod
    def _token_from_receipt(receipt, required_to: Optional[str] = None) -> int:
        """
        Recover the minted tokenId from a Transfer(address,address,uint256) log.
        Scans ALL logs (newest first) rather than trusting the last one, and —
        when `required_to` is given — requires the mint's `_to` to match the
        registrar address, so unrelated events cannot hijack the parse.
        """
        for log in reversed(getattr(receipt, "logs", []) or []):
            topics = log.get("topics") if isinstance(log, dict) else log["topics"]
            if not topics or len(topics) < 4:
                continue
            t0 = topics[0].hex()
            if not t0.startswith("0x"):
                t0 = "0x" + t0
            if t0.lower() != TRANSFER_EVENT_SIG:
                continue
            if required_to is not None:
                to_addr_int = int.from_bytes(bytes(topics[2]), "big")
                if to_addr_int != int(required_to, 16):
                    continue
            return int.from_bytes(bytes(topics[3]), "big")
        raise RuntimeError(
            "Could not recover tokenId from registration receipt — refusing to "
            "write a metadata link against an unknown agentId"
        )

    def _update_row(self, row_id, status, token_id, tx_hash, error=None,
                    increment_retry=None):
        conn = sqlite3.connect(self.db_path)
        try:
            retries = (increment_retry or 0) + (1 if error else 0)
            conn.execute(
                """
                UPDATE erc8004_registrations
                SET status=?, token_id=COALESCE(?, token_id), tx_hash=COALESCE(?, tx_hash),
                    retries=?, last_error=?, updated_at=?
                WHERE id=?
                """,
                (status, token_id, tx_hash, retries, error, time.time(), row_id),
            )
            conn.commit()
        finally:
            conn.close()


# ---------------------------------------------------------------------------
# Module-level convenience used by the issuance hook and routes
# ---------------------------------------------------------------------------

_worker_started = threading.Event()


def configured_chains() -> List[str]:
    raw = _env("GUARDIAN_ERC8004_CHAINS", "monad-testnet")
    chains = [c.strip() for c in raw.split(",") if c.strip()]
    valid = [c for c in chains if c == "monad-testnet"]
    if not valid and chains:
        logger.warning(
            "Non-Monad networks are no longer supported. "
            "Please configure GUARDIAN_ERC8004_CHAINS to use 'monad-testnet'. Ignoring: %s",
            chains,
        )
    return valid or ["monad-testnet"]


def chains_str_list() -> list:
    return configured_chains()


def default_db_path() -> str:
    return _env("GUARDIAN_DB_PATH", _env("DB_PATH", "guardian.db"))


def enqueue_registration(db_path: str, agent_id: str, passport_id: str,
                         owner_address: Optional[str] = None) -> bool:
    """Called from issue_passport. Silent no-op when disabled. Never raises."""
    if not _enabled():
        return False
    ok_any = False
    for chain in configured_chains():
        try:
            if ERC8004Registrar(chain, db_path).enqueue(
                agent_id, passport_id, owner_address=owner_address
            ):
                ok_any = True
        except RegistrarMisconfigured as exc:
            logger.warning("ERC-8004 enqueue skipped (%s): %s", chain, exc)
    ensure_worker(db_path)
    return ok_any


def ensure_worker(db_path: str) -> None:
    """Start the polling worker once per process, only when enabled."""
    if not _enabled():
        return
    if _worker_started.is_set():
        return
    interval = float(_env("GUARDIAN_ERC8004_POLL_SECONDS", "30"))

    def _loop():
        chains = configured_chains()
        registrars = []
        for chain in chains:
            try:
                registrars.append(ERC8004Registrar(chain, db_path))
            except Exception as exc:  # noqa: BLE001
                logger.warning("ERC-8004 worker skipping chain %s: %s", chain, exc)
        while True:
            for reg in registrars:
                try:
                    reg.process_pending()
                except Exception as exc:  # noqa: BLE001 — worker never dies
                    logger.warning("ERC-8004 worker cycle failed: %s", exc)
            time.sleep(interval)

    thread = threading.Thread(target=_loop, name="erc8004-registrar", daemon=True)
    thread.start()
    _worker_started.set()
    logger.info("ERC-8004 registration worker started (chains=%s)",
                ",".join(chains_str_list()))
