from flask import Flask, request, Response
import requests as http_requests
import threading
import logging
import json
import os
import secrets
import sqlite3
import time
from typing import Dict, Any, List, Optional

from web3 import Web3
from eth_account import Account
import rlp
from guardian.guardrails.rate_limiter import RateLimiter
from guardian.web3sec.simulation import SimulationEngine, SimulationResult
from guardian.web3sec.tx_analyzer import TransactionAnalyzer

logger = logging.getLogger("guardian.web3sec.rpc_relay")

# ── Raw Transaction Decoder ──────────────────────────────────────────────────

def decode_raw_transaction(raw_hex: str) -> Dict[str, Any]:
    """Decode a signed raw transaction into {from, to, data, value}.

    Handles legacy (type 0), EIP-2930 (type 1), EIP-1559 (type 2),
    EIP-4844 blob (type 3), and EIP-7702 set-code (type 4).
    Uses rlp.decode() for field extraction and Account.recover_transaction()
    for the `from` address.
    """
    normalized = raw_hex if raw_hex.startswith("0x") else "0x" + raw_hex
    raw_bytes = bytes.fromhex(normalized[2:])

    tx: Dict[str, Any] = {}
    tx["from"] = Account.recover_transaction(normalized)

    first_byte = raw_bytes[0]

    if first_byte in (1, 2, 3, 4):
        # Typed transaction: first byte is type, rest is RLP payload
        decoded = rlp.decode(raw_bytes[1:])
        if first_byte in (2, 3, 4):
            # EIP-1559 / 4844 / 7702 share the same base layout:
            #   [chainId, nonce, maxPriorityFee, maxFee, gas, to, value, data, accessList, ...]
            # Types 3 (4844) and 4 (7702) append extra fields after accessList
            # (blob fields / authorization list), but to/value/data stay at 5/6/7.
            tx["to"] = "0x" + decoded[5].hex() if decoded[5] else None
            tx["value"] = int.from_bytes(decoded[6], "big") if decoded[6] else 0
            tx["data"] = "0x" + decoded[7].hex() if decoded[7] else "0x"
        else:
            # EIP-2930: [chainId, nonce, gasPrice, gas, to, value, data, accessList, v, r, s]
            tx["to"] = "0x" + decoded[4].hex() if decoded[4] else None
            tx["value"] = int.from_bytes(decoded[5], "big") if decoded[5] else 0
            tx["data"] = "0x" + decoded[6].hex() if decoded[6] else "0x"
    elif first_byte >= 0xc0:
        # Legacy: entire payload is RLP [nonce, gasPrice, gas, to, value, data, v, r, s]
        decoded = rlp.decode(raw_bytes)
        tx["to"] = "0x" + decoded[3].hex() if decoded[3] else None
        tx["value"] = int.from_bytes(decoded[4], "big") if decoded[4] else 0
        tx["data"] = "0x" + decoded[5].hex() if decoded[5] else "0x"
    else:
        raise ValueError(f"Unknown transaction type byte: {first_byte:#x}")

    return tx


# ── RPC Relay ────────────────────────────────────────────────────────────────

class GuardianRPCRelay:
    """Web3 JSON-RPC proxy with pre-flight transaction simulation and analysis.

    Primary path: eth_sendRawTransaction (MetaMask/wallets send raw).
    Secondary path: eth_sendTransaction (direct RPC clients).
    All other methods: pass-through to upstream.
    """

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get("web3_security", {})
        self.port = self.config.get("listen_port", 8546)
        self.upstream_rpc = self.config.get("upstream_rpc", "https://testnet.monad.xyz/v1")
        self.fail_mode = self.config.get("fail_mode", "closed")
        self.enforce_simulation = self.config.get("enforce_simulation", True)

        # Management auth token — shared with the interceptor's admin_token.
        # main.py overrides config['security_policies']['admin_token'] from
        # GUARDIAN_ADMIN_TOKEN / GUARDIAN_ADMIN_BYPASS_TOKEN env before the
        # relay is constructed. We also check env directly for standalone runs.
        # When empty, mutating management endpoints fail-closed (403).
        self.management_token = (
            config.get("security_policies", {}).get("admin_token", "")
            or os.environ.get("GUARDIAN_ADMIN_TOKEN", "")
            or os.environ.get("GUARDIAN_ADMIN_BYPASS_TOKEN", "")
        )

        self.app = Flask(__name__)

        # Setup Web3 & Simulation
        self.w3 = Web3(Web3.HTTPProvider(self.upstream_rpc))
        self.sim_engine = SimulationEngine(self.w3)
        self.analyzer = TransactionAnalyzer(self.config)

        # Rate limiting
        self.rate_limiter = RateLimiter(requests_per_minute=600)

        # Stats counters (thread-safe via GIL for simple increments)
        self.stats = {"intercepted": 0, "blocked": 0, "passed": 0, "errors": 0}

        # SQLite persistence — absolute path so relay and backend read the same DB
        self.db_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
            "web3sec_blocked.db"
        )
        self._init_db()

        # Routes — RPC proxy
        self.app.add_url_rule('/health', view_func=self.health_check, methods=['GET'])
        self.app.add_url_rule('/stats', view_func=self.get_stats, methods=['GET'])
        self.app.add_url_rule('/', view_func=self.proxy, methods=['POST'])
        # Management routes (backend → relay sync)
        self.app.add_url_rule('/rules', view_func=self.get_rules, methods=['GET'])
        self.app.add_url_rule('/rules', view_func=self.post_rules, methods=['POST'], endpoint='post_rules')
        self.app.add_url_rule('/whitelist', view_func=self.get_whitelist, methods=['GET'])
        self.app.add_url_rule('/whitelist', view_func=self.post_whitelist, methods=['POST'], endpoint='post_whitelist')
        self.app.add_url_rule('/whitelist/<address>', view_func=self.delete_whitelist, methods=['DELETE'])

        self._thread = None


    def _init_db(self):
        with sqlite3.connect(self.db_path) as conn:
            conn.execute('''
                CREATE TABLE IF NOT EXISTS blocked_transactions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    timestamp REAL,
                    ip_address TEXT,
                    tx_from TEXT,
                    tx_to TEXT,
                    detector TEXT,
                    reason TEXT,
                    severity TEXT,
                    raw_payload TEXT
                )
            ''')
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
            # Seed default rules on first run (INSERT OR IGNORE skips if already present)
            now = __import__('time').time()
            for rule in ("reserve_manipulation", "infinite_approval", "role_change",
                         "zero_slippage", "threat_address"):
                conn.execute(
                    "INSERT OR IGNORE INTO web3sec_rules (rule_name, enabled, updated_at) VALUES (?, 1, ?)",
                    (rule, now)
                )
            conn.commit()

    def _log_blocked(self, ip: str, tx_from: str, tx_to: str, detector: str,
                     reason: str, severity: str, raw_payload: str):
        try:
            with sqlite3.connect(self.db_path) as conn:
                conn.execute('''
                    INSERT INTO blocked_transactions
                        (timestamp, ip_address, tx_from, tx_to, detector, reason, severity, raw_payload)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ''', (time.time(), ip, tx_from, tx_to, detector, reason, severity, raw_payload))
                conn.commit()
        except Exception as e:
            logger.error(f"Failed to persist blocked tx: {e}")

    def _load_rules_from_db(self) -> Dict[str, bool]:
        """Read detection rule enable/disable flags from the shared DB."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute("SELECT rule_name, enabled FROM web3sec_rules").fetchall()
                return {row[0]: bool(row[1]) for row in rows}
        except Exception as e:
            logger.warning(f"Could not load rules from DB, using defaults: {e}")
            return {}

    def _load_whitelist_from_db(self) -> List[str]:
        """Read whitelisted addresses (lowercased) from the shared DB."""
        try:
            with sqlite3.connect(self.db_path) as conn:
                rows = conn.execute("SELECT address FROM web3sec_whitelist").fetchall()
                return [row[0].lower() for row in rows]
        except Exception as e:
            logger.warning(f"Could not load whitelist from DB: {e}")
            return []

    def _check_management_auth(self) -> Optional[Response]:
        """Validate Authorization: Bearer <token> on mutating management endpoints.

        Fail-closed: when no management token is configured, all mutating
        management endpoints return 403. This prevents any local process from
        disabling detectors or whitelisting addresses without the shared
        admin token (audit P1-3, 2026-08-20).
        """
        if not self.management_token:
            return Response(
                json.dumps({"error": "Management auth not configured"}),
                status=403, mimetype="application/json"
            )
        auth = request.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return Response(
                json.dumps({"error": "Authorization required"}),
                status=401, mimetype="application/json"
            )
        token = auth[7:].strip()
        if not token or not secrets.compare_digest(token, self.management_token):
            return Response(
                json.dumps({"error": "Invalid management token"}),
                status=403, mimetype="application/json"
            )
        return None

    def health_check(self):
        return {"status": "ok", "component": "web3sec_rpc_relay", "port": self.port}

    def get_stats(self):
        return {
            "status": "ok",
            "component": "web3sec_rpc_relay",
            "upstream_rpc": self.upstream_rpc,
            "stats": dict(self.stats),
        }

    def get_rules(self):
        """Relay-side endpoint: return current rules from DB."""
        return Response(
            json.dumps({"rules": self._load_rules_from_db()}),
            status=200, mimetype="application/json"
        )

    def post_rules(self):
        """Relay-side endpoint: update rules in DB (called by backend).
        Requires Bearer management token (audit P1-3)."""
        auth_err = self._check_management_auth()
        if auth_err:
            return auth_err
        try:
            data = request.get_json(force=True)
            now = time.time()
            with sqlite3.connect(self.db_path) as conn:
                for rule_name, enabled in data.items():
                    conn.execute(
                        "INSERT OR REPLACE INTO web3sec_rules (rule_name, enabled, updated_at) VALUES (?, ?, ?)",
                        (rule_name, 1 if enabled else 0, now)
                    )
                conn.commit()
            return Response(json.dumps({"status": "ok"}), status=200, mimetype="application/json")
        except Exception as e:
            return Response(json.dumps({"error": str(e)}), status=500, mimetype="application/json")

    def get_whitelist(self):
        """Relay-side endpoint: return current whitelist from DB."""
        return Response(
            json.dumps({"whitelist": self._load_whitelist_from_db()}),
            status=200, mimetype="application/json"
        )

    def post_whitelist(self):
        """Relay-side endpoint: add address to whitelist (called by backend).
        Requires Bearer management token (audit P1-3)."""
        auth_err = self._check_management_auth()
        if auth_err:
            return auth_err
        try:
            data = request.get_json(force=True)
            address = data.get("address", "").lower().strip()
            label = data.get("label", "")
            if not address:
                return Response(json.dumps({"error": "address required"}), status=400, mimetype="application/json")
            with sqlite3.connect(self.db_path) as conn:
                conn.execute(
                    "INSERT OR REPLACE INTO web3sec_whitelist (address, label, added_at) VALUES (?, ?, ?)",
                    (address, label, time.time())
                )
                conn.commit()
            return Response(json.dumps({"status": "ok", "address": address}), status=200, mimetype="application/json")
        except Exception as e:
            return Response(json.dumps({"error": str(e)}), status=500, mimetype="application/json")

    def delete_whitelist(self, address: str):
        """Relay-side endpoint: remove address from whitelist (called by backend).
        Requires Bearer management token (audit P1-3)."""
        auth_err = self._check_management_auth()
        if auth_err:
            return auth_err
        try:
            address = address.lower().strip()
            with sqlite3.connect(self.db_path) as conn:
                conn.execute("DELETE FROM web3sec_whitelist WHERE address = ?", (address,))
                conn.commit()
            return Response(json.dumps({"status": "ok", "address": address}), status=200, mimetype="application/json")
        except Exception as e:
            return Response(json.dumps({"error": str(e)}), status=500, mimetype="application/json")


    def _make_json_rpc_error(self, code: int, message: str, req_id=None) -> Response:
        return Response(
            json.dumps({"jsonrpc": "2.0", "error": {"code": code, "message": message}, "id": req_id}),
            status=200, mimetype="application/json"
        )

    def _handle_single_rpc(self, req_data: dict, client_ip: str) -> Optional[Response]:
        """Process a single JSON-RPC request. Returns a Response if blocked,
        or None to signal pass-through to upstream."""
        method = req_data.get("method")
        req_id = req_data.get("id")
        params = req_data.get("params", [])

        if method not in ("eth_sendRawTransaction", "eth_sendTransaction"):
            return None  # pass-through

        self.stats["intercepted"] += 1

        # ── Decode transaction fields ────────────────────────────────
        tx: Dict[str, Any] = {}
        if method == "eth_sendRawTransaction" and params:
            try:
                tx = decode_raw_transaction(params[0])
            except Exception as e:
                logger.warning(f"Failed to decode raw tx: {e}")
                self.stats["errors"] += 1
                if self.fail_mode == "closed":
                    return self._make_json_rpc_error(-32000, f"Transaction decode failed: {e}", req_id)
                return None  # fail-open: can't analyze, forward as-is
        elif method == "eth_sendTransaction" and params:
            tx = dict(params[0])

        if not tx:
            # No transaction data to analyze (empty/missing params).
            # Fail-closed blocks; fail-open lets upstream reject the malformed request.
            if self.fail_mode == "closed":
                return self._make_json_rpc_error(-32000, "Empty or missing transaction parameters", req_id)
            return None

        # Whitelist check
        whitelist = self._load_whitelist_from_db()
        to_addr = (tx.get("to") or "").lower()
        from_addr = (tx.get("from") or "").lower()
        is_whitelisted = to_addr in whitelist or from_addr in whitelist

        # Apply live rule flags from DB
        live_rules = self._load_rules_from_db()

        # Run detectors FIRST (calldata-only, no simulation needed)
        dummy_sim = SimulationResult(success=True, gas_used=0, return_data="")
        analysis_res = self.analyzer.analyze_transaction(tx, dummy_sim, live_rules=live_rules)
        if analysis_res and analysis_res.blocked:
            if is_whitelisted:
                logger.warning(f"Whitelisted address {to_addr or from_addr} bypassed {analysis_res.detector_name}: {analysis_res.reason}")
            else:
                self.stats["blocked"] += 1
                self._log_blocked(client_ip, tx.get("from", ""), tx.get("to", ""),
                                  analysis_res.detector_name, analysis_res.reason,
                                  analysis_res.severity, json.dumps(req_data))
                return self._make_json_rpc_error(
                    -32000, f"Guardian Security Block: {analysis_res.reason}", req_id
                )

        # ── Simulate (optional, additional check) ────────────────────
        if self.enforce_simulation:
            sim_res = self.sim_engine.simulate_transaction(tx)
            if not sim_res.success:
                if self.fail_mode == "closed":
                    self.stats["blocked"] += 1
                    return self._make_json_rpc_error(
                        -32000, f"Simulation failed: {sim_res.revert_reason}", req_id
                    )
                else:
                    logger.warning(f"Simulation failed (fail_mode=open, forwarding): {sim_res.revert_reason}")

        self.stats["passed"] += 1
        return None  # pass-through

    def proxy(self):
        client_ip = request.remote_addr or "127.0.0.1"
        if not self.rate_limiter.is_allowed(client_ip):
            return Response(
                json.dumps({"jsonrpc": "2.0", "error": {"code": -32005, "message": "Rate limit exceeded"}, "id": None}),
                status=429, mimetype="application/json"
            )

        req_data = request.get_json(silent=True)
        if req_data is None:
            return Response(
                json.dumps({"jsonrpc": "2.0", "error": {"code": -32700, "message": "Parse error"}, "id": None}),
                status=400, mimetype="application/json"
            )

        # ── Handle JSON-RPC batch (array of requests) ────────────────
        if isinstance(req_data, list):
            for single_req in req_data:
                if isinstance(single_req, dict):
                    blocked = self._handle_single_rpc(single_req, client_ip)
                    if blocked is not None:
                        return blocked
        elif isinstance(req_data, dict):
            blocked = self._handle_single_rpc(req_data, client_ip)
            if blocked is not None:
                return blocked

        # ── Pass-through to upstream ─────────────────────────────────
        try:
            resp = http_requests.post(
                self.upstream_rpc, json=req_data,
                headers={"Content-Type": "application/json"}, timeout=10
            )
            return Response(resp.content, status=resp.status_code,
                            headers={"Content-Type": "application/json"})
        except Exception as e:
            req_id = req_data.get("id") if isinstance(req_data, dict) else None
            return Response(
                json.dumps({"jsonrpc": "2.0", "error": {"code": -32603, "message": f"Upstream error: {e}"}, "id": req_id}),
                status=502, mimetype="application/json"
            )

    def start(self):
        if self._thread is not None:
            return
        logger.info(f"Starting Web3 RPC Relay on port {self.port} -> {self.upstream_rpc}")
        self._thread = threading.Thread(target=self._run_server, daemon=True)
        self._thread.start()

    def _run_server(self):
        try:
            from waitress import serve
            serve(self.app, host="127.0.0.1", port=self.port, threads=8)
        except Exception as e:
            logger.error(f"Waitress crash: {e}")
            self.app.run(host="127.0.0.1", port=self.port, debug=False, use_reloader=False)
