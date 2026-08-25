"""
ERC-8004 identity registration — offline tests.

No network anywhere: web3 and eth_account are replaced by fakes injected
through the registrar's factory seams. Covers:
  - disabled-by-default behaviour (the "don't mess with my codebase" guarantee)
  - happy path pending -> registered -> metadata-linked -> confirmed
  - fail-closed abort when canonical registry has no bytecode
  - gas-price ceiling abort
  - chain errors becoming queue status with retry cap (never raised)
  - registration-file schema shape
"""
import sqlite3

import pytest

from guardian.passport import erc8004_registrar as reg


SIG_TRANSFER = "0xddf252ad1be2c89b69c2b068fc378daa952ba7f163c4a11628f55a4df523b3ef"


def _topic32(value: int) -> bytes:
    return value.to_bytes(32, "big")


class FakeFn:
    def __init__(self, state, name, args):
        self.state, self.name, self.args = state, name, args

    def build_transaction(self, params):
        # Mimic web3.py's strictness: camelCase tx keys only. This exists
        # because a real web3 rejected snake_case "gas_price" in the field.
        allowed = {"from", "nonce", "gasPrice", "chainId", "gas",
                   "maxFeePerGas", "maxPriorityFeePerGas"}
        unknown = set(params) - allowed
        if unknown:
            raise TypeError(f"Unknown kwargs: {sorted(unknown)}")
        self.state.setdefault("built", []).append((self.name, self.args, params))
        return {"from": params["from"], "gasPrice": params.get("gasPrice")}


class FakeContractFunctions:
    def __init__(self, state):
        self.state = state

    def register(self, uri):
        return FakeFn(self.state, "register", (uri,))

    def setMetadata(self, agent_id, key, value):
        return FakeFn(self.state, "setMetadata", (agent_id, key, value))

    def transferFrom(self, sender, recipient, token_id):
        return FakeFn(self.state, "transferFrom", (sender, recipient, token_id))

    def ownerOf(self, token_id):
        state = self.state

        class _View:
            def call(self):
                # Default: registrar still owns the token (pre-handoff).
                return state.get("token_owner", "0x" + "ab" * 20)

        return _View()


class FakeReceipt:
    def __init__(self, logs):
        self.status = 1
        self.logs = logs


class FakeW3:
    """Minimal web3 stand-in driven by a mutable scenario dict."""

    def __init__(self, state):
        self.state = state
        eth = type("Eth", (), {})()
        registry_addr = None

        eth.get_code = lambda addr: state.get("code", b"\x60\x80")
        eth.gas_price = state.get("gas_price", 1_000_000_000)
        eth.contract = lambda address, abi: self._make_contract(address)
        eth.get_transaction_count = lambda addr: state.get("nonce", 0)

        def send_raw_tx(raw):
            if state.get("fail_send"):
                raise RuntimeError(state.get("fail_send_msg", "rpc down"))
            state["nonce"] = state.get("nonce", 0) + 1
            state["sent_count"] = state.get("sent_count", 0) + 1
            h = bytes.fromhex("aa" * 31 + f"{state['nonce']:02x}")
            state.setdefault("sent_hashes", []).append(h.hex())
            return h

        def wait_for_receipt(tx_hash, timeout=None):
            if state.get("timeout_wait"):
                # Optional precision: fire only after N successful sends so a
                # scenario can target one specific tx in a multi-send step.
                threshold = state.get("timeout_after_sends")
                if threshold is None or state.get("sent_count", 0) > threshold:
                    raise RuntimeError("TimeExhausted: wait timed out")
            if state.get("revert"):
                r = FakeReceipt([])
                r.status = 0
                return r
            if state.get("receipt_override") is not None:
                return state["receipt_override"]
            mint_log = {
                "topics": [
                    bytes.fromhex(SIG_TRANSFER[2:]),
                    _topic32(0),
                    _topic32(int(FakeAccount.address, 16)),  # _to = registrar
                    _topic32(77),
                ]
            }
            return FakeReceipt([mint_log])

        def get_receipt(tx_hash):
            # Recovery path: mined receipts are surfaced only when the
            # scenario says the tx eventually landed.
            return state.get("recovered_receipt")

        eth.send_raw_transaction = send_raw_tx
        eth.wait_for_transaction_receipt = wait_for_receipt
        eth.get_transaction_receipt = get_receipt
        self.eth = eth

    @staticmethod
    def to_checksum_address(a):
        return a

    def _make_contract(self, address):
        outer = self
        c = type("C", (), {})()
        c.functions = FakeContractFunctions(outer.state)
        return c


class FakeAccount:
    address = "0x" + "ab" * 20  # valid hex — the registrar validates _to against it

    def __init__(self, key):
        pass

    def sign_transaction(self, tx):
        return type("Signed", (), {"raw_transaction": b"fakesig"})()


@pytest.fixture()
def env(tmp_path, monkeypatch):
    """Isolated env + DB; worker thread disabled for determinism."""
    db = str(tmp_path / "guardian.db")
    monkeypatch.setenv("GUARDIAN_ERC8004_ENABLED", "true")
    monkeypatch.setenv("GUARDIAN_ERC8004_CHAINS", "base-sepolia")
    monkeypatch.setenv("GUARDIAN_ERC8004_REGISTRAR_KEY", "0x" + "11" * 32)
    monkeypatch.setenv("GUARDIAN_PUBLIC_URL", "https://guard.example.com")
    monkeypatch.setattr(reg, "ensure_worker", lambda db_path: None)
    yield {"db": db}
    # nothing to tear down — all fakes are per-test


def make_registrar(db, state):
    return reg.ERC8004Registrar(
        "base-sepolia",
        db,
        w3_factory=lambda rpc: FakeW3(state),
        account_factory=lambda key: FakeAccount(key),
    )


# ── disabled-by-default guarantee ────────────────────────────────────────────

def test_disabled_by_default_is_silent_noop(env, monkeypatch):
    monkeypatch.delenv("GUARDIAN_ERC8004_ENABLED")
    assert reg.enqueue_registration(env["db"], "agent-1", "passport-1") is False
    conn = sqlite3.connect(env["db"])
    tables = conn.execute(
        "SELECT name FROM sqlite_master WHERE name='erc8004_registrations'"
    ).fetchall()
    conn.close()
    assert tables == []  # not even the table exists when disabled


def test_enqueue_disabled_returns_false(env, monkeypatch):
    monkeypatch.delenv("GUARDIAN_ERC8004_ENABLED")
    r = make_registrar(env["db"], {})
    assert r.enqueue("a", "p") is True  # queue write allowed even if flag off,
    # but the issuance-level helper gates on the flag:
    assert reg.enqueue_registration(env["db"], "a2", "p2") is False


# ── happy path ───────────────────────────────────────────────────────────────

def test_happy_path_pending_to_confirmed(env):
    state = {}
    r = make_registrar(env["db"], state)
    assert r.enqueue("agent-a", "passport-a") is True

    # Step 1: register() — tokenId recovered from Transfer log (77)
    assert r.process_pending() == 1
    rows = r.get_status("agent-a")
    assert rows[0]["status"] == reg.STATUS_METADATA
    assert rows[0]["token_id"] == 77

    # Step 2: setMetadata() links the passport id
    assert r.process_pending() == 1
    rows = r.get_status("agent-a")
    assert rows[0]["status"] == reg.STATUS_CONFIRMED

    # Verify both transactions were built with expected arguments
    names = [n for n, _, _ in state["built"]]
    assert names == ["register", "setMetadata"]
    reg_call = state["built"][0][1]
    meta_call = state["built"][1][1]
    assert reg_call[0].startswith(
        "https://guard.example.com/api/v1/erc8004/agents/agent-a.json"
    )
    assert meta_call[0] == 77
    assert meta_call[1] == reg.METADATA_KEY
    assert bytes(meta_call[2]) == b"passport-a"


def test_registration_file_schema_shape():
    f = reg.build_registration_file(
        agent_id="agent-a", chain="base-sepolia", token_id=77,
        base_url="https://x",
    )
    assert f["type"] == "https://eips.ethereum.org/EIPS/eip-8004#registration-v1"
    assert f["active"] is True
    assert f["registrations"] == [
        {
            "agentId": 77,
            "agentRegistry": "eip155:84532:" + reg.CANONICAL_IDENTITY_REGISTRY,
        }
    ]
    assert "supportedTrust" not in f  # discovery-only until Reputation ships


# ── failure modes become status, never exceptions ────────────────────────────

def test_fail_closed_on_missing_registry_bytecode(env):
    state = {"code": b""}  # e.g. chain where canonical registry isn't deployed
    r = make_registrar(env["db"], state)
    r.enqueue("agent-x", "passport-x")
    r.process_pending()  # must not raise
    rows = r.get_status("agent-x")
    assert rows[0]["status"] == reg.STATUS_FAILED
    assert "bytecode" in (rows[0]["last_error"] or "")
    assert rows[0]["tx_hash"] is None  # nothing was broadcast


def test_gas_price_ceiling_aborts(env):
    state = {"gas_price": 500 * 10**9}  # 500 gwei >> default 100 gwei cap
    r = make_registrar(env["db"], state)
    r.enqueue("agent-g", "passport-g")
    r.process_pending()
    rows = r.get_status("agent-g")
    assert rows[0]["status"] == reg.STATUS_FAILED
    assert "safety limit" in (rows[0]["last_error"] or "")


def test_chain_errors_retry_then_cap_and_never_raise(env, monkeypatch):
    monkeypatch.setenv("GUARDIAN_ERC8004_MAX_RETRIES", "2")
    state = {"fail_send": True, "fail_send_msg": "connection refused"}
    r = make_registrar(env["db"], state)
    r.enqueue("agent-y", "passport-y")

    for _ in range(3):
        r.process_pending()  # every cycle must be exception-free

    rows = r.get_status("agent-y")
    assert rows[0]["status"] == reg.STATUS_FAILED
    assert rows[0]["retries"] == 2  # attempts capped at MAX_RETRIES
    assert "connection refused" in (rows[0]["last_error"] or "")

    # Recovery: retries exhausted means manual re-register; assert it stays put.
    state["fail_send"] = False
    processed = r.process_pending()
    assert processed == 0


def test_manual_reregister_after_failure_resets_row(env, monkeypatch):
    monkeypatch.setenv("GUARDIAN_ERC8004_MAX_RETRIES", "1")
    state = {"fail_send": True}
    r = make_registrar(env["db"], state)
    r.enqueue("agent-z", "passport-z")
    r.process_pending(); r.process_pending()
    assert r.get_status("agent-z")[0]["status"] == reg.STATUS_FAILED

    # Admin route semantics: enqueue(reset_failed=True) revives the row
    state["fail_send"] = False
    r.enqueue("agent-z", "passport-z", reset_failed=True)
    r.process_pending()
    assert r.get_status("agent-z")[0]["status"] == reg.STATUS_METADATA


# ── misc ─────────────────────────────────────────────────────────────────────

def test_passport_link_encoding_round_trip():
    assert bytes(reg.encode_passport_link("pid-123")) == b"pid-123"


def test_unsupported_chain_is_misconfigured(env):
    import os
    os.environ["GUARDIAN_ERC8004_IDENTITY_REGISTRY_OVERRIDE"] = ""
    with pytest.raises(reg.RegistrarMisconfigured):
        reg.ERC8004Registrar("solana-mainnet", env["db"])
