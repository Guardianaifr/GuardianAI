"""
ERC-8004 registrar — HARD tests. Adversarial cases beyond the unit suite:

  H1  Concurrency hammer: N threads racing one row must yield exactly ONE
      register broadcast (conditional-claim guarantee).
  H2  Receipt-wait timeout -> failure stores tx hash -> retry RECOVERS the
      mined tx instead of double-minting.
  H3  Decoy/malformed logs cannot hijack tokenId parsing (address-bound scan).
  H4  Invalid/hostile agent_id values are rejected before touching storage.
  H5  reset_failed never touches CONFIRMED rows.
  H6  Route auth matrix via isolated FastAPI app (admin/user/unknown/disabled).
  H7  Public registration file: schema correct, passportId never exposed.
  H8  Multi-chain queue advances through per-chain delegation.
"""
import json
import threading

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from guardian.passport import erc8004_registrar as reg
from test_erc8004_registrar import (  # sibling module (rootdir on sys.path)
    FakeAccount,
    FakeReceipt,
    FakeW3,
    SIG_TRANSFER,
    _topic32,
)


def make(db, state, chain="base-sepolia"):
    return reg.ERC8004Registrar(
        chain, db,
        w3_factory=lambda rpc: FakeW3(state),
        account_factory=lambda k: FakeAccount(k),
    )


class FakePassport:
    def __init__(self, pid, tenant="default", active=True):
        self.passport_id, self.tenant_id, self.is_active = pid, tenant, active


@pytest.fixture()
def env(tmp_path, monkeypatch):
    db = str(tmp_path / "guardian.db")
    monkeypatch.setenv("GUARDIAN_ERC8004_ENABLED", "true")
    monkeypatch.setenv("GUARDIAN_ERC8004_CHAINS", "base-sepolia")
    monkeypatch.setenv("GUARDIAN_ERC8004_REGISTRAR_KEY", "0x" + "11" * 32)
    monkeypatch.setenv("GUARDIAN_PUBLIC_URL", "https://guard.example.com")
    monkeypatch.setattr(reg, "ensure_worker", lambda p: None)
    return db


# ── H1: concurrency hammer ───────────────────────────────────────────────────

def test_h1_concurrent_workers_single_broadcast(env):
    state = {}
    r = make(env, state)
    r.enqueue("hammer-agent", "passport-h")

    errors = []
    def worker():
        try:
            r.process_pending()
        except Exception as exc:  # sqlite locking under contention is allowed,
            errors.append(exc)     # but must NEVER produce a second broadcast

    threads = [threading.Thread(target=worker) for _ in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]

    registers = [b for b in state.get("built", []) if b[0] == "register"]
    assert len(registers) == 1, f"double broadcast! {len(registers)}"
    # Row remains consistent and completable afterwards.
    r.process_pending()
    rows = r.get_status("hammer-agent")
    assert rows[0]["token_id"] == 77


# ── H2: receipt-timeout recovery (the double-mint killer) ────────────────────

def test_h2_timeout_then_recovery_never_double_mints(env):
    state = {"timeout_wait": True}
    r = make(env, state)
    r.enqueue("timeout-agent", "passport-t")

    r.process_pending()  # broadcast OK, receipt wait times out
    rows = r.get_status("timeout-agent")
    assert rows[0]["status"] == reg.STATUS_FAILED
    assert rows[0]["tx_hash"], "broadcast hash MUST be preserved on timeout"

    # The tx actually landed on chain later — surface its receipt.
    state["timeout_wait"] = False
    state["recovered_receipt"] = FakeReceipt([{
        "topics": [
            bytes.fromhex(SIG_TRANSFER[2:]),
            _topic32(0),
            _topic32(int(FakeAccount.address, 16)),
            _topic32(77),
        ]
    }])
    broadcasts_before = len(state.get("sent_hashes", []))

    r.process_pending()  # must RECOVER, not re-send register
    assert len(state["sent_hashes"]) == broadcasts_before, "double mint!"
    rows = r.get_status("timeout-agent")
    assert rows[0]["status"] == reg.STATUS_METADATA
    assert rows[0]["token_id"] == 77

    r.process_pending()  # metadata step proceeds normally
    assert r.get_status("timeout-agent")[0]["status"] == reg.STATUS_CONFIRMED


def test_h2b_unmined_tx_keeps_failing_without_resend(env):
    state = {"timeout_wait": True}
    r = make(env, state)
    r.enqueue("pending-tx", "passport-p")
    r.process_pending()
    n_sent = len(state["sent_hashes"])

    r.process_pending()  # recovery attempt: tx still unmined
    assert len(state["sent_hashes"]) == n_sent, "re-sent an unmined tx!"
    rows = r.get_status("pending-tx")
    assert rows[0]["status"] == reg.STATUS_FAILED
    assert "not yet mined" in (rows[0]["last_error"] or "")


# ── H3: hostile receipt logs ────────────────────────────────────────────────

def test_h3_decoy_transfer_to_wrong_address_is_ignored(env):
    state = {"timeout_wait": True}
    r = make(env, state)
    r.enqueue("decoy-agent", "passport-d")
    r.process_pending()

    decoy = {
        "topics": [
            bytes.fromhex(SIG_TRANSFER[2:]),
            _topic32(0),
            _topic32(int("0x" + "de" * 20, 16)),  # NOT the registrar
            _topic32(666),                          # attacker-chosen token
        ]
    }
    mint = {
        "topics": [
            bytes.fromhex(SIG_TRANSFER[2:]),
            _topic32(0),
            _topic32(int(FakeAccount.address, 16)),
            _topic32(77),
        ]
    }
    # Decoy AFTER the mint too — reversed scan must still bind to registrar.
    state["recovered_receipt"] = FakeReceipt([mint, decoy])
    state["timeout_wait"] = False
    r.process_pending()
    assert r.get_status("decoy-agent")[0]["token_id"] == 77


def test_h3b_reverted_register_is_not_recoverable(env):
    state = {"revert": True}
    r = make(env, state)
    r.enqueue("revert-agent", "passport-r")
    r.process_pending()
    rows = r.get_status("revert-agent")
    assert rows[0]["status"] == reg.STATUS_FAILED
    assert "reverted" in (rows[0]["last_error"] or "")


# ── H4: hostile agent_id values ──────────────────────────────────────────────

@pytest.mark.parametrize("bad", [
    "", "has space", "../etc/passwd", "a/b", "a;b", "agent\u00e9",
    "x" * 129, "-leadingspecial", "quote'or'1'=1", "agent\x00null",
])
def test_h4_hostile_agent_ids_rejected(env, bad):
    r = make(env, {})
    assert r.enqueue(bad, "p") is False
    assert r.get_status(bad) == []
    # Storage untouched and functional afterwards:
    assert r.enqueue("good-agent", "p") is True
    assert len(r.get_status("good-agent")) == 1


def test_h4b_valid_agent_id_charset_accepted(env):
    r = make(env, {})
    for ok in ["agent-1", "Agent_2.v3", "org:agent:9", "A" * 128]:
        assert r.enqueue(ok, "p") is True, ok


# ── H5: reset_failed safety ──────────────────────────────────────────────────

def test_h5_reset_failed_never_touches_confirmed(env):
    r = make(env, {})
    r.enqueue("done-agent", "passport-done")
    r.process_pending(); r.process_pending()
    assert r.get_status("done-agent")[0]["status"] == reg.STATUS_CONFIRMED

    r.enqueue("done-agent", "passport-done", reset_failed=True)
    assert r.get_status("done-agent")[0]["status"] == reg.STATUS_CONFIRMED


# ── H6/H7: routes via isolated FastAPI app ──────────────────────────────────

@pytest.fixture()
def client(env, monkeypatch):
    import backend.main  # noqa: F401 — must fully initialize before router import
    from backend.routers import identity_registry_routes as irr

    calls = {"passports": {}}

    engine = type("E", (), {})()
    engine.get_passport = lambda aid: calls["passports"].get(aid)

    monkeypatch.setattr(irr, "_get_passport_engine", lambda: engine)
    monkeypatch.setattr(irr, "_get_user_rate_limit", lambda u: 100)
    monkeypatch.setattr(irr, "_enforce_rate_limit", lambda k, l: None)
    monkeypatch.setenv("GUARDIAN_DB_PATH", env)

    principal = {"username": "tester", "role": "user", "org_id": "default"}

    # Depends() binds the original callable at route-build time, so override
    # via the app's dependency_overrides rather than patching the module.
    from backend.main import get_current_principal as _real_principal

    principal_holder = {"value": dict(principal)}

    app = FastAPI()
    app.include_router(irr.router)
    app.dependency_overrides[_real_principal] = lambda: principal_holder["value"]
    tc = TestClient(app)

    yield tc, calls, principal_holder
    calls.clear()


def test_h6_route_auth_matrix(client, monkeypatch):
    tc, calls, holder = client
    calls["passports"]["agent-a"] = FakePassport("pid-a")

    # Disabled feature -> admin gets 400/skipped, public file 404
    monkeypatch.delenv("GUARDIAN_ERC8004_ENABLED")
    r = tc.post("/api/v1/erc8004/register", json={"agent_id": "agent-a"})
    assert r.status_code in (400, 403)
    assert tc.get("/api/v1/erc8004/agents/agent-a.json").status_code == 404
    monkeypatch.setenv("GUARDIAN_ERC8004_ENABLED", "true")

    # Non-admin cannot trigger on-chain writes -> 403, and existence is NOT
    # leaked (403 comes before any 404 for unknown agents).
    r = tc.post("/api/v1/erc8004/register", json={"agent_id": "agent-a"})
    assert r.status_code == 403
    r = tc.post("/api/v1/erc8004/register", json={"agent_id": "ghost"})
    assert r.status_code == 403

    # Admin succeeds (202); unknown agent now yields 404 for the admin.
    holder["value"]["role"] = "admin"
    r = tc.post("/api/v1/erc8004/register", json={"agent_id": "ghost"})
    assert r.status_code == 404
    r = tc.post("/api/v1/erc8004/register", json={"agent_id": "agent-a"})
    assert r.status_code == 202, r.text

    # Cross-tenant read denied (back to plain user in org 'default')
    holder["value"]["role"] = "user"
    calls["passports"]["other-org-agent"] = FakePassport("pid-o", tenant="corp")
    r = tc.get("/api/v1/erc8004/status/other-org-agent")
    assert r.status_code == 403

    # Same-tenant read allowed
    r = tc.get("/api/v1/erc8004/status/agent-a")
    assert r.status_code == 200


def test_h7_public_file_schema_and_privacy(client):
    tc, calls, holder = client
    holder["value"]["role"] = "admin"
    calls["passports"]["pub-agent"] = FakePassport("pid-secret-hash")

    r = tc.post("/api/v1/erc8004/register", json={"agent_id": "pub-agent"})
    assert r.status_code == 202
    r = tc.post("/api/v1/erc8004/register", json={"agent_id": "pub-agent"})
    assert r.status_code == 202

    file_resp = tc.get("/api/v1/erc8004/agents/pub-agent.json")
    assert file_resp.status_code == 200
    body = file_resp.json()
    assert body["type"] == reg.REGISTRATION_FILE_TYPE
    assert body["active"] is True
    assert "passportId" not in json.dumps(body), "passport id leaked publicly!"
    assert "supportedTrust" not in body  # discovery-only claim, honestly absent


# ── H8: multi-chain delegation ───────────────────────────────────────────────

def test_h8_queue_advances_multiple_chains(env, tmp_path, monkeypatch):
    monkeypatch.setenv("GUARDIAN_ERC8004_CHAINS", "base-sepolia,monad-testnet")
    r_main = make(env, {})
    states = {}

    orig_init = reg.ERC8004Registrar.__init__

    def tracking_init(self, chain, db_path, wf=None, af=None):
        orig_init(self, chain, db_path, wf, af)
        states[chain] = self.cfg

    reg.ERC8004Registrar.__init__ = tracking_init
    try:
        from guardian.passport.erc8004_registrar import enqueue_registration as eq
        monkeypatch.setattr(reg, "ensure_worker", lambda p: None)
        assert eq(env, "multi-agent", "passport-m") is True
        r_main.process_pending()  # should delegate monad row to its own client

        statuses = {row["chain"]: row["status"] for row in r_main.get_status("multi-agent")}
        assert statuses["base-sepolia"] == reg.STATUS_METADATA
        assert statuses["monad-testnet"] == reg.STATUS_METADATA
        assert states["monad-testnet"]["chain_id"] != states["base-sepolia"]["chain_id"]
    finally:
        reg.ERC8004Registrar.__init__ = orig_init


# ── H9: production-URI gate (audit v2) ───────────────────────────────────────

def test_h9_localhost_uri_blocked_on_mainnet_chain(env, monkeypatch):
    """Default localhost PUBLIC_BASE_URL must never be baked onto mainnet."""
    monkeypatch.setenv("GUARDIAN_ERC8004_CHAINS", "base")
    # env fixture sets GUARDIAN_PUBLIC_URL=https://guard.example.com; undo it.
    monkeypatch.delenv("GUARDIAN_PUBLIC_URL")
    state = {}
    r = make(env, state, chain="base")  # MAINNET chain
    r.enqueue("mainnet-agent", "p")
    r.process_pending()  # must not raise, must not broadcast

    assert state.get("built") is None, "broadcast attempted with localhost URI!"
    rows = r.get_status("mainnet-agent")
    assert rows[0]["status"] == reg.STATUS_FAILED
    assert "fail-closed" in (rows[0]["last_error"] or "")


def test_h9b_http_non_https_uri_also_blocked_on_mainnet(env, monkeypatch):
    monkeypatch.setenv("GUARDIAN_ERC8004_CHAINS", "base")
    monkeypatch.setenv("GUARDIAN_PUBLIC_URL", "http://guard.example.com")
    state = {}
    r = make(env, state, chain="base")
    r.enqueue("mainnet-agent2", "p")
    r.process_pending()
    assert state.get("built") is None


def test_h9c_testnets_remain_exempt_from_uri_gate(env):
    """Sepolia rehearsal must keep working with https URL (fixture default)."""
    state = {}
    r = make(env, state)
    r.enqueue("sepolia-agent", "p")
    r.process_pending()
    assert any(b[0] == "register" for b in state.get("built", []))


# ── H10: daily wei budget (audit v2 — promised control now real) ────────────

def test_h10_daily_budget_blocks_after_threshold(env, monkeypatch):
    monkeypatch.setenv("GUARDIAN_ERC8004_DAILY_BUDGET_WEI", "21000")

    mint_log = {
        "topics": [
            bytes.fromhex(SIG_TRANSFER[2:]),
            _topic32(0),
            _topic32(int(FakeAccount.address, 16)),
            _topic32(77),
        ]
    }

    class PricedReceipt(FakeReceipt):
        gasUsed = 21_000
        effectiveGasPrice = 1_000_000_000  # 21_000 gwei = 2.1e13 wei per tx

    state = {"receipt_override": PricedReceipt([mint_log])}
    r = make(env, state)

    # First tx passes check, then accumulates 2.1e13 wei >= limit.
    r.enqueue("budget-a", "p")
    r.process_pending()
    rows = r.get_status("budget-a")
    assert rows[0]["status"] == reg.STATUS_METADATA  # tx itself succeeded

    # Second registration must now be refused pre-broadcast.
    r.enqueue("budget-b", "p")
    r.process_pending()
    rows_b = r.get_status("budget-b")
    assert rows_b[0]["status"] == reg.STATUS_FAILED
    assert "budget exhausted" in (rows_b[0]["last_error"] or "")
    assert state["sent_count"] == 1  # second tx never broadcast


def test_h10b_budget_zero_disables_cap(env, monkeypatch):
    monkeypatch.setenv("GUARDIAN_ERC8004_DAILY_BUDGET_WEI", "0")
    state = {}
    r = make(env, state)
    for aid in ("nocap-a", "nocap-b"):
        r.enqueue(aid, "p"); r.process_pending()
        st = r.get_status(aid)[0]["status"]
        assert st in (reg.STATUS_METADATA, reg.STATUS_CONFIRMED), aid


# ── H11: keyless recovery (audit v2) ─────────────────────────────────────────

def test_h11_recovery_works_without_registrar_key(env, monkeypatch):
    """A rotated/absent key must not make a mined registration unrecoverable."""
    state = {"timeout_wait": True}
    r = make(env, state)
    r.enqueue("keyless", "p")
    r.process_pending()
    rows = r.get_status("keyless")
    assert rows[0]["tx_hash"], "precondition: hash preserved on timeout"

    # Simulate a NEW process after key rotation: fresh registrar instance,
    # no key configured anywhere. Recovery must still succeed via sig-only
    # log matching (no _to binding possible without the address).
    monkeypatch.delenv("GUARDIAN_ERC8004_REGISTRAR_KEY")
    state["timeout_wait"] = False
    state["recovered_receipt"] = FakeReceipt([{
        "topics": [
            bytes.fromhex(SIG_TRANSFER[2:]),
            _topic32(0),
            _topic32(0),  # mint recipient unknown to us now
            _topic32(88),
        ]
    }])
    r2 = reg.ERC8004Registrar(
        "base-sepolia", env,
        w3_factory=lambda rpc: FakeW3(state),
        account_factory=lambda k: (_ for _ in ()).throw(
            reg.RegistrarMisconfigured("key rotated away")),
    )
    r2.process_pending()
    rows = r2.get_status("keyless")
    assert rows[0]["status"] == reg.STATUS_METADATA
    assert rows[0]["token_id"] == 88


# ── H12–H14: register-then-transfer ownership policy (settled 2026-08) ──────

CLIENT_OWNER = "0x" + "cd" * 20


def test_h12_transfer_flow_hands_identity_to_client(env):
    """register → setMetadata → transferFrom → confirmed, in that order."""
    state = {}
    r = make(env, state)
    r.enqueue("owned-agent", "p-owned", owner_address=CLIENT_OWNER)

    r.process_pending()   # register
    r.process_pending()   # setMetadata + transferFrom in the same step
    rows = r.get_status("owned-agent")
    assert rows[0]["status"] == reg.STATUS_CONFIRMED
    assert rows[0]["owner_address"] == CLIENT_OWNER

    names = [b[0] for b in state["built"]]
    assert names == ["register", "setMetadata", "transferFrom"], names
    sender, recipient, token_id = state["built"][2][1]
    # Registrar normalizes to EIP-55 checksum form before sending.
    assert recipient.lower() == CLIENT_OWNER.lower()
    assert token_id == 77
    # Transfer happens only AFTER the metadata link is on-chain.
    assert names.index("setMetadata") < names.index("transferFrom")


def test_h13_no_owner_stays_custodial(env):
    """Absent owner_address keeps the pre-existing custodial behavior."""
    state = {}
    r = make(env, state)
    r.enqueue("custodial-agent", "p-c")
    r.process_pending(); r.process_pending()
    assert r.get_status("custodial-agent")[0]["status"] == reg.STATUS_CONFIRMED
    assert [b[0] for b in state["built"]] == ["register", "setMetadata"]
    assert r.get_status("custodial-agent")[0]["owner_address"] is None


def test_h14_invalid_owner_address_rejected(env):
    r = make(env, {})
    for bad in ["0x1234", "cd" * 20, "0x" + "zz" * 20, "0x" + "cd" * 19]:
        assert r.enqueue("o-agent", "p", owner_address=bad) is False, bad
    assert r.get_status("o-agent") == []
    # Valid address passes and is stored.
    assert r.enqueue("o-agent", "p", owner_address=CLIENT_OWNER) is True
    assert r.get_status("o-agent")[0]["owner_address"] == CLIENT_OWNER


def test_h14b_route_rejects_bad_owner_address(client):
    tc, calls, holder = client
    holder["value"]["role"] = "admin"
    calls["passports"]["route-owner"] = FakePassport("pid-ro")
    r = tc.post("/api/v1/erc8004/register",
                json={"agent_id": "route-owner", "owner_address": "0xbad"})
    assert r.status_code == 400
    assert "owner_address" in r.json()["detail"]


# ── H15/H16: transfer idempotence (audit v3) ────────────────────────────────

def test_h15_transfer_timeout_then_retry_does_not_revert_loop(env):
    """transferFrom mined but receipt timed out -> retry must SKIP the
    transfer (ownerOf shows client ownership), not revert-loop to failed."""
    state = {}
    r = make(env, state)
    r.enqueue("handoff-agent", "p-h", owner_address=CLIENT_OWNER)

    # Cycle 1: register OK.
    r.process_pending()
    # Cycle 2: setMetadata OK (send 2), transferFrom broadcast (send 3) but
    # its receipt wait times out — timeout fires only after send #2.
    state["timeout_wait"] = True
    state["timeout_after_sends"] = 2
    r.process_pending()
    rows = r.get_status("handoff-agent")
    assert rows[0]["status"] == reg.STATUS_FAILED

    # The transfer actually mined on chain.
    state["timeout_wait"] = False
    state["token_owner"] = CLIENT_OWNER

    # Retry cycles must complete WITHOUT a second transferFrom broadcast.
    for _ in range(3):
        r.process_pending()

    transfers = [b for b in state.get("built", []) if b[0] == "transferFrom"]
    assert len(transfers) == 1, "duplicate transferFrom attempted!"
    assert r.get_status("handoff-agent")[0]["status"] == reg.STATUS_CONFIRMED


def test_h16_ownerof_skip_when_client_already_owns(env):
    """Defensive skip path: ownerOf reporting client ownership on the first
    metadata pass means no transfer is ever broadcast."""
    state = {"token_owner": CLIENT_OWNER}
    r = make(env, state)
    r.enqueue("preowned-agent", "p-po", owner_address=CLIENT_OWNER)
    r.process_pending()  # register
    r.process_pending()  # metadata step sees client already owns → skip
    names = [b[0] for b in state["built"]]
    assert "transferFrom" not in names
    assert r.get_status("preowned-agent")[0]["status"] == reg.STATUS_CONFIRMED
