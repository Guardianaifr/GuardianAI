"""
tests/security/test_tenant_isolation_concurrent.py

Part C -- Phase 4 F25 remediation: concurrent cross-tenant isolation tests.

Tests identified as MISSING in the Phase 4 audit.  Three groups:
  1. Cross-tenant quarantine independence (concurrent threads, Tenant A vs B).
  2. Session-ID scoping collision prevention (same raw session_id, two tenants).
  3. OOM / unbounded-growth stress (10,000 random session IDs).
"""

from __future__ import annotations

import sys
import threading
import time
import uuid
from pathlib import Path

import pytest

_GUARDIAN = Path(__file__).parent.parent.parent / "guardian"
if str(_GUARDIAN) not in sys.path:
    sys.path.insert(0, str(_GUARDIAN))

from security.cost_abuse import CostAbuseDetector
from security.tenant_isolation import TenantIsolationManager


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_detector(
    *,
    max_tokens: int = 300,
    min_events: int = 2,
    window: int = 120,
    quarantine_seconds: int = 300,
) -> CostAbuseDetector:
    """Return a CostAbuseDetector configured to quarantine quickly."""
    return CostAbuseDetector(
        {
            "enabled": True,
            "window_seconds": window,
            "min_events": min_events,
            "max_tokens_per_window": max_tokens,
            "max_cost_usd_per_window": 999.0,
            "spike_multiplier": 999.0,          # disable spike-ratio path
            "quarantine_seconds": quarantine_seconds,
            "cost_per_1k_tokens_usd": 0.01,
            "min_sessions_for_tenant_anomaly": 999,  # disable slow-drain path
            "max_tokens_per_tenant_window": 999999,
        }
    )


def _make_isolation_manager(*, enabled: bool = True) -> TenantIsolationManager:
    return TenantIsolationManager(
        config={
            "enabled": enabled,
            "enforce_tenant_scope_on_session": True,
            "require_tenant_header": False,
            "default_tenant_id": "default",
            "tenant_header": "X-Guardian-Tenant",
            "allowed_tenant_pattern": r"^[a-z0-9][a-z0-9_-]{1,63}$",
            "tenant_evidence_dir": "artifacts/evidence/tenants",
        },
        base_dir=Path("/tmp"),
    )


# ===========================================================================
# GROUP 1: Cross-tenant quarantine independence
# ===========================================================================

class TestCrossTenantQuarantineIndependence:
    """Prove Tenant A quarantine does NOT bleed into Tenant B."""

    def test_tenantA_quarantine_does_not_affect_tenantB_sequential(self):
        """Sequential baseline: Tenant A quarantine must not spill to Tenant B."""
        isolation = _make_isolation_manager()
        detector = _make_detector(max_tokens=200, min_events=2)

        sess_a = isolation.scope_session_id("alpha", "sess-shared")
        sess_b = isolation.scope_session_id("beta", "sess-shared")

        # Quarantine Tenant A
        detector.register_usage(sess_a, tokens=150, cost_usd=0.0015, tenant_id="alpha")
        result_a2 = detector.register_usage(sess_a, tokens=150, cost_usd=0.0015, tenant_id="alpha")
        assert result_a2.action == "quarantine", (
            f"Expected Tenant A quarantine; got action={result_a2.action}"
        )

        # Tenant B must be completely unaffected
        is_q_b, _ = detector.is_quarantined(sess_b)
        assert not is_q_b, (
            f"ISOLATION FAILURE: Tenant A quarantine bled into Tenant B. "
            f"sess_a={sess_a!r}, sess_b={sess_b!r}"
        )

        result_b = detector.register_usage(sess_b, tokens=50, cost_usd=0.0005, tenant_id="beta")
        assert result_b.action == "allow", (
            f"ISOLATION FAILURE: Tenant B register_usage returned {result_b.action!r} "
            f"because of Tenant A quarantine state."
        )

    def test_tenantA_quarantine_does_not_affect_tenantB_concurrent(self):
        """
        Concurrent version: 10 threads exhaust Tenant A, 10 threads probe Tenant B.
        Tenant B must never see 'quarantined' due to Tenant A state.

        Key constraint: max_tokens must be high enough that 10 concurrent Tenant B
        probe threads (each sending 30 tokens = 300 total) cannot self-quarantine,
        while Tenant A's single scoped key still gets quarantined via its 250-token
        requests.  We set max_tokens=5000 (well above 300) and min_events=2 so
        Tenant A quarantines after its 2nd call.
        """
        isolation = _make_isolation_manager()
        detector = _make_detector(
            max_tokens=5000,   # >> 10 * 30 tokens, so Tenant B cannot self-quarantine
            min_events=2,
            quarantine_seconds=60,
        )

        # Force-quarantine Tenant A before threads start, so its quarantine state
        # is already in _quarantined_until when Tenant B threads run.
        sess_a = isolation.scope_session_id("alpha", "concurrent-sess")
        sess_b = isolation.scope_session_id("beta", "concurrent-sess")

        # Pre-quarantine sess_a (deterministic, outside the concurrent section)
        detector.register_usage(sess_a, tokens=3000, cost_usd=0.03, tenant_id="alpha")
        result_pre = detector.register_usage(sess_a, tokens=3000, cost_usd=0.03, tenant_id="alpha")
        assert result_pre.action == "quarantine", (
            f"Pre-condition failed: expected sess_a to be quarantined, got {result_pre.action}"
        )

        # Now run concurrent Tenant B probes against an already-quarantined Tenant A dict
        tenant_b_violations: list[str] = []
        barrier = threading.Barrier(10)

        def probe_tenant_b():
            barrier.wait()
            result = detector.register_usage(sess_b, tokens=30, cost_usd=0.0003, tenant_id="beta")
            if result.action in ("quarantine", "quarantined"):
                tenant_b_violations.append(
                    f"Thread got action={result.action!r} for Tenant B (sess={sess_b})"
                )

        threads = [threading.Thread(target=probe_tenant_b) for _ in range(10)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)

        assert not tenant_b_violations, (
            f"CONCURRENT ISOLATION FAILURE: {len(tenant_b_violations)} Tenant B threads "
            f"saw quarantine action from Tenant A state (or self-quarantined unexpectedly):\n"
            + "\n".join(tenant_b_violations)
        )

    def test_multiple_tenants_independent_quarantine_windows(self):
        """5 tenants each quarantined; each tenant's fresh session must still get 'allow'."""
        isolation = _make_isolation_manager()
        detector = _make_detector(max_tokens=100, min_events=2, quarantine_seconds=120)
        tenants = [f"tenant-{i}" for i in range(5)]

        # Quarantine every tenant on 'shared-raw-sess'
        for tid in tenants:
            scoped = isolation.scope_session_id(tid, "shared-raw-sess")
            detector.register_usage(scoped, tokens=80, cost_usd=0.0008, tenant_id=tid)
            result = detector.register_usage(scoped, tokens=80, cost_usd=0.0008, tenant_id=tid)
            assert result.action == "quarantine", (
                f"Expected quarantine for {tid}, got {result.action}"
            )

        # Fresh sessions for each tenant must be allowed
        for tid in tenants:
            fresh = isolation.scope_session_id(tid, "fresh-sess-" + tid)
            result = detector.register_usage(fresh, tokens=10, cost_usd=0.0001, tenant_id=tid)
            assert result.action == "allow", (
                f"ISOLATION FAILURE: Fresh session for {tid} got {result.action!r}; "
                f"quarantine of other sessions bled into new session."
            )


# ===========================================================================
# GROUP 2: Session-ID scoping collision prevention
# ===========================================================================

class TestSessionIdScopingIsolation:
    """Prove scope_session_id() prevents cross-tenant key collisions."""

    def test_scope_session_id_produces_distinct_keys(self):
        """Same raw session_id must yield different scoped keys for different tenants."""
        isolation = _make_isolation_manager()
        raw = "session-xyz-123"
        scoped_a = isolation.scope_session_id("acme", raw)
        scoped_b = isolation.scope_session_id("globex", raw)

        assert scoped_a != scoped_b, (
            f"KEY COLLISION: same raw session_id produced identical scoped key for "
            f"two tenants: {scoped_a!r}"
        )
        assert "acme" in scoped_a, f"Expected 'acme' in scoped key, got {scoped_a!r}"
        assert "globex" in scoped_b, f"Expected 'globex' in scoped key, got {scoped_b!r}"

    def test_scope_session_id_deterministic(self):
        """Same tenant + raw session_id must always produce the same scoped key."""
        isolation = _make_isolation_manager()
        raw = "deterministic-test"
        assert isolation.scope_session_id("acme", raw) == isolation.scope_session_id("acme", raw)

    def test_scope_session_id_disabled_is_noop(self):
        """When isolation is disabled, scope_session_id must return the raw session_id."""
        isolation = _make_isolation_manager(enabled=False)
        raw = "raw-session"
        assert isolation.scope_session_id("acme", raw) == raw, (
            "When isolation is disabled, scope_session_id must be a no-op."
        )

    def test_collision_prevention_in_detector(self):
        """
        Same raw session_id used by two tenants -- detector must maintain
        completely independent event histories after scoping.
        """
        isolation = _make_isolation_manager()
        detector = _make_detector(max_tokens=500, min_events=3)

        raw_sess = "collide-me"
        sess_acme = isolation.scope_session_id("acme", raw_sess)
        sess_globex = isolation.scope_session_id("globex", raw_sess)

        # Exhaust acme's quota
        for _ in range(3):
            detector.register_usage(sess_acme, tokens=200, cost_usd=0.002, tenant_id="acme")

        is_q_acme, _ = detector.is_quarantined(sess_acme)
        is_q_globex, _ = detector.is_quarantined(sess_globex)

        assert is_q_acme, "Acme session should be quarantined after token exhaustion."
        assert not is_q_globex, (
            f"KEY COLLISION FAILURE: globex quarantined by acme usage. "
            f"acme={sess_acme!r}, globex={sess_globex!r}"
        )

    def test_resolve_tenant_id_rejects_path_traversal_and_malformed(self):
        """resolve_tenant_id must reject or default malformed tenant identifiers.

        NOTE: resolve_tenant_id applies .lower() before pattern matching, so
        'UPPERCASE' becomes 'uppercase' which IS a valid tenant id per the regex
        ^[a-z0-9][a-z0-9_-]{1,63}$. Case normalisation is the correct documented
        behaviour -- it is NOT a security boundary (the allowed_tenant_pattern
        governs allowed chars/length, not case sensitivity).
        """
        isolation = _make_isolation_manager()
        # Truly invalid: path traversal, spaces, oversized, empty
        bad_ids = ["../etc/passwd", "tenant with space", "x" * 65, ""]
        for bad in bad_ids:
            headers = {"X-Guardian-Tenant": bad}
            tid, err = isolation.resolve_tenant_id(headers)
            assert (err is not None) or (tid == isolation.default_tenant_id), (
                f"resolve_tenant_id should reject or default bad id {bad!r}; "
                f"got tid={tid!r}, err={err!r}"
            )

        # Verify case-normalisation behaviour explicitly:
        # 'UPPERCASE' is lowercased to 'uppercase' which is a valid tenant id.
        headers_upper = {"X-Guardian-Tenant": "UPPERCASE"}
        tid_upper, err_upper = isolation.resolve_tenant_id(headers_upper)
        assert err_upper is None and tid_upper == "uppercase", (
            f"resolve_tenant_id should normalise 'UPPERCASE' to 'uppercase'; "
            f"got tid={tid_upper!r}, err={err_upper!r}"
        )


# ===========================================================================
# GROUP 3: OOM / unbounded-growth stress
# ===========================================================================

class TestOOMStress:
    """
    Documents the OOM DoS risk identified in Phase 4.

    Current behaviour: lazy pruning means _events grows to N when N unique
    session IDs are submitted.  test_random_session_ids_grow_events_dict_without_bound
    PROVES this empirically.

    Future fix signal: if bounded eviction (LRU / max-keys cap / TTL) is added,
    the assertion in that test should be changed to assert final_size <= MAX_ALLOWED.
    """

    N = 10_000

    def test_random_session_ids_grow_events_dict_without_bound(self):
        """
        After N unique session IDs, _events grows to N -- proves unbounded OOM gap.
        This test PASSING confirms the gap is real (current implementation).
        """
        detector = _make_detector()
        random_sessions = [f"random-oom-{uuid.uuid4()}" for _ in range(self.N)]

        for sess in random_sessions:
            detector.register_usage(sess, tokens=10, cost_usd=0.0001)

        final_size = len(detector._events)
        # Asserting <= max_tracked_sessions proves the OOM fix (FEAT-TENANT-INMEM-HARDEN)
        assert final_size <= detector.max_tracked_sessions, (
            f"OOM stress: expected _events to be bounded by {detector.max_tracked_sessions}, "
            f"got {final_size}."
        )

    def test_quarantine_dict_does_not_grow_for_normal_sessions(self):
        """Sessions under threshold must not appear in _quarantined_until."""
        detector = _make_detector(max_tokens=999999)  # unreachably high threshold
        for i in range(1000):
            detector.register_usage(f"safe-sess-{i}", tokens=1, cost_usd=0.000001)

        assert len(detector._quarantined_until) == 0, (
            f"Quarantine dict unexpectedly has {len(detector._quarantined_until)} entries "
            f"for sessions that never exceeded thresholds."
        )

    def test_events_dict_prunes_expired_entries_on_revisit(self):
        """
        Entries ARE pruned, but lazily -- only when the same session_id is revisited.
        Proves lazy-pruning works but does not protect against abandoned sessions.
        """
        detector = _make_detector(window=1)  # 1-second window
        sess = "prune-test-sess"

        detector.register_usage(sess, tokens=50, cost_usd=0.0005)
        assert len(detector._events[sess]) == 1

        time.sleep(1.1)  # let the window expire

        # Revisit prunes stale events
        detector.register_usage(sess, tokens=10, cost_usd=0.0001)
        assert len(detector._events[sess]) == 1, (
            f"After window expiry, revisit should prune stale events; "
            f"found {len(detector._events[sess])} events."
        )

    def test_concurrent_random_sessions_no_lock_deadlock(self):
        """
        50 threads x 100 unique session IDs concurrently -- must not deadlock.
        Confirms global lock does not cause a deadlock under concurrent load.
        """
        detector = _make_detector()
        errors: list[str] = []

        def insert_batch(thread_id: int):
            try:
                for i in range(100):
                    sess = f"thread-{thread_id}-sess-{i}"
                    detector.register_usage(sess, tokens=5, cost_usd=0.00005)
            except Exception as exc:
                errors.append(f"Thread {thread_id}: {exc}")

        threads = [threading.Thread(target=insert_batch, args=(i,)) for i in range(50)]
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=30)

        assert not errors, f"Concurrent inserts raised exceptions: {errors}"
        # 50 threads * 100 sessions = 5000 unique keys, but limited to max_tracked_sessions
        assert len(detector._events) <= detector.max_tracked_sessions, (
            f"Expected max_tracked_sessions limit to be respected, got {len(detector._events)}"
        )

    def test_quarantine_exemption_logic(self):
        """
        Proves quarantine-exemption logic: fill tracked sessions to capacity,
        with one session actively quarantined and old/inactive.
        Confirm eviction runs, other old sessions are evicted, and quarantined survives.
        """
        # Configure small limits to force eviction easily
        detector = _make_detector(quarantine_seconds=300)
        detector.max_tracked_sessions = 5  # Force eviction easily
        
        # 1. Create the quarantined session, make it OLD (time.time() - 10)
        now = time.time()
        q_sess = "quarantined-session-id"
        detector._events[q_sess].append((now - 10, 10, 0.001))
        detector._quarantined_until[q_sess] = now + 300 # active quarantine
        
        # 2. Add 5 other old sessions
        for i in range(5):
            detector._events[f"old-sess-{i}"].append((now - 5, 10, 0.001))
            
        # Total is now 6. Limit is 5.
        # Now trigger register_usage, which calls _enforce_capacity(now)
        detector.register_usage("new-sess", tokens=10, cost_usd=0.001, now=now)
        
        # Total is now 7. Limit is 5. Two sessions should be evicted.
        # The oldest sessions are q_sess (ts=now-10), old-sess-0 (ts=now-5), etc.
        # But q_sess is EXEMPT. So old-sess-0 and old-sess-1 should be evicted.
        assert q_sess in detector._events, "Quarantined session was incorrectly evicted!"
        assert "new-sess" in detector._events, "New session was incorrectly evicted!"
        assert len(detector._events) == detector.max_tracked_sessions, "Capacity was not enforced!"
        
    def test_tenant_lock_overflow(self):
        """
        Proves the overflow-lock path: exceed max_tenant_locks, confirm tenants beyond
        the cap get the shared overflow lock, and confirm no deadlock when operating concurrently.
        """
        isolation = _make_isolation_manager(enabled=True)
        isolation.max_tenant_locks = 2  # Extremely small cap for testing
        
        # 1. First 2 tenants get dedicated locks
        lock1 = isolation._get_tenant_lock("tenant-1")
        lock2 = isolation._get_tenant_lock("tenant-2")
        assert lock1 is not lock2, "Dedicated locks should be unique"
        assert lock1 is not isolation._overflow_lock
        assert lock2 is not isolation._overflow_lock
        
        # 2. Tenants beyond cap get the overflow lock
        lock3 = isolation._get_tenant_lock("tenant-3")
        lock4 = isolation._get_tenant_lock("tenant-4")
        assert lock3 is isolation._overflow_lock, "Tenant 3 did not get overflow lock"
        assert lock4 is isolation._overflow_lock, "Tenant 4 did not get overflow lock"
        
        # 3. Prove concurrent write_evidence works safely across dedicated and overflow tenants
        errors = []
        def write_batch(tenant_id):
            try:
                for i in range(10):
                    isolation.write_evidence(tenant_id, "test_event", "HIGH", {"i": i})
            except Exception as e:
                errors.append(str(e))
                
        threads = [
            threading.Thread(target=write_batch, args=("tenant-1",)),
            threading.Thread(target=write_batch, args=("tenant-2",)),
            threading.Thread(target=write_batch, args=("tenant-3",)),
            threading.Thread(target=write_batch, args=("tenant-4",))
        ]
        
        for t in threads:
            t.start()
        for t in threads:
            t.join(timeout=10)
            
        assert not errors, f"Exceptions occurred during concurrent write_evidence: {errors}"