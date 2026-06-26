"""
HEAVY UNSEEN DATA TEST — Features #10-11 Rate Limiting
=======================================================
Tests all 14 capabilities with hard unseen data:
  A. Core Token Bucket (in-memory)
  B. Redis Distributed Mode
  C. Per-IP Custom Limits
  D. Whitelist / Banlist
  E. Burst Detection
  F. Bucket Management (reset, cleanup, info)
  G. Audit Log
  H. Stats & Export
  I. Thread Safety / Concurrency
  J. Performance / Scale
"""
import sys, os, json, time, threading, logging
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, "guardian"))

# Suppress rate limiter log noise during heavy testing
logging.getLogger("GuardianAI.rate_limiter").setLevel(logging.CRITICAL)

from guardian.guardrails.rate_limiter import RateLimiter

RESULTS = {}

def run_test(name, fn):
    try:
        fn()
        RESULTS[name] = "PASS"
        print(f"  [PASS] {name}")
    except AssertionError as e:
        RESULTS[name] = f"FAIL: {e}"
        print(f"  [FAIL] {name}: {e}")
    except Exception as e:
        RESULTS[name] = f"ERROR: {type(e).__name__}: {e}"
        print(f"  [ERROR] {name}: {type(e).__name__}: {e}")


class FakeRedis:
    def __init__(self):
        self.store = {}
    def get(self, key):
        return self.store.get(key)
    def setex(self, key, _ttl, value):
        self.store[key] = value

class BrokenRedis:
    def get(self, _key):
        raise RuntimeError("redis down")
    def setex(self, _key, _ttl, _value):
        raise RuntimeError("redis down")


# ═══════════════════════════════════════════════════════════════════════════
# A. CORE TOKEN BUCKET (IN-MEMORY)
# ═══════════════════════════════════════════════════════════════════════════

def test_a1_blocks_after_capacity():
    rl = RateLimiter(requests_per_minute=3)
    assert rl.is_allowed("1.1.1.1") is True
    assert rl.is_allowed("1.1.1.1") is True
    assert rl.is_allowed("1.1.1.1") is True
    assert rl.is_allowed("1.1.1.1") is False

def test_a2_refill_over_time():
    now = [1000.0]
    rl = RateLimiter(requests_per_minute=60, time_fn=lambda: now[0])
    for _ in range(60):
        rl.is_allowed("2.2.2.2")
    assert rl.is_allowed("2.2.2.2") is False
    now[0] += 2.0  # 2 tokens refilled
    assert rl.is_allowed("2.2.2.2") is True
    assert rl.is_allowed("2.2.2.2") is True
    assert rl.is_allowed("2.2.2.2") is False

def test_a3_per_ip_isolation():
    rl = RateLimiter(requests_per_minute=1)
    assert rl.is_allowed("3.3.3.1") is True
    assert rl.is_allowed("3.3.3.1") is False
    # Different IP should still be allowed
    assert rl.is_allowed("3.3.3.2") is True

def test_a4_pressure():
    now = [2000.0]
    rl = RateLimiter(requests_per_minute=10, time_fn=lambda: now[0])
    assert rl.get_pressure("4.4.4.4") == 1.0  # Full bucket
    for _ in range(5):
        rl.is_allowed("4.4.4.4")
    pressure = rl.get_pressure("4.4.4.4")
    assert 0.3 < pressure < 0.7, f"Expected ~0.5, got {pressure}"

def test_a5_empty_ip_handling():
    rl = RateLimiter(requests_per_minute=5)
    assert rl.is_allowed("") is True  # Empty IP defaults to "unknown"
    assert rl.is_allowed(None or "") is True


# ═══════════════════════════════════════════════════════════════════════════
# B. REDIS DISTRIBUTED MODE
# ═══════════════════════════════════════════════════════════════════════════

def test_b1_redis_basic():
    now = [3000.0]
    redis = FakeRedis()
    rl = RateLimiter(requests_per_minute=2, redis_client=redis, time_fn=lambda: now[0])
    assert rl.is_allowed("5.5.5.5") is True
    assert rl.is_allowed("5.5.5.5") is True
    assert rl.is_allowed("5.5.5.5") is False

def test_b2_redis_refill():
    now = [4000.0]
    redis = FakeRedis()
    rl = RateLimiter(requests_per_minute=2, redis_client=redis, time_fn=lambda: now[0])
    rl.is_allowed("6.6.6.6")
    rl.is_allowed("6.6.6.6")
    assert rl.is_allowed("6.6.6.6") is False
    now[0] += 30.0  # 1 token refilled at 2/min
    assert rl.is_allowed("6.6.6.6") is True

def test_b3_redis_failover():
    rl = RateLimiter(requests_per_minute=1, redis_client=BrokenRedis())
    # Should fall back to in-memory
    assert rl.is_allowed("7.7.7.7") is True
    assert rl.is_allowed("7.7.7.7") is False

def test_b4_redis_pressure():
    now = [5000.0]
    redis = FakeRedis()
    rl = RateLimiter(requests_per_minute=10, redis_client=redis, time_fn=lambda: now[0])
    rl.is_allowed("8.8.8.8")
    pressure = rl.get_pressure("8.8.8.8")
    assert 0.8 < pressure <= 1.0


# ═══════════════════════════════════════════════════════════════════════════
# C. PER-IP CUSTOM LIMITS
# ═══════════════════════════════════════════════════════════════════════════

def test_c1_custom_limit():
    now = [6000.0]
    rl = RateLimiter(requests_per_minute=100, time_fn=lambda: now[0])
    rl.set_custom_limit("slow.client", 2)
    assert rl.is_allowed("slow.client") is True
    assert rl.is_allowed("slow.client") is True
    assert rl.is_allowed("slow.client") is False  # Custom limit of 2

def test_c2_remove_custom_limit():
    now = [7000.0]
    rl = RateLimiter(requests_per_minute=100, time_fn=lambda: now[0])
    rl.set_custom_limit("temp.client", 1)
    assert rl.is_allowed("temp.client") is True
    assert rl.is_allowed("temp.client") is False
    rl.remove_custom_limit("temp.client")
    # After removing, should use default (100 RPM)
    rl.reset("temp.client")
    for _ in range(50):
        assert rl.is_allowed("temp.client") is True

def test_c3_different_limits_per_ip():
    now = [8000.0]
    rl = RateLimiter(requests_per_minute=10, time_fn=lambda: now[0])
    rl.set_custom_limit("premium", 20)
    rl.set_custom_limit("basic", 5)
    
    for _ in range(5):
        assert rl.is_allowed("basic") is True
    assert rl.is_allowed("basic") is False  # basic is capped at 5
    
    for _ in range(15):
        assert rl.is_allowed("premium") is True  # premium still has headroom


# ═══════════════════════════════════════════════════════════════════════════
# D. WHITELIST / BANLIST
# ═══════════════════════════════════════════════════════════════════════════

def test_d1_whitelist():
    rl = RateLimiter(requests_per_minute=1)
    rl.add_whitelist("trusted.internal")
    # Whitelisted IP should never be blocked
    for _ in range(100):
        assert rl.is_allowed("trusted.internal") is True

def test_d2_banlist():
    rl = RateLimiter(requests_per_minute=1000)
    rl.ban("attacker.ip")
    # Banned IP should always be blocked
    assert rl.is_allowed("attacker.ip") is False
    assert rl.is_allowed("attacker.ip") is False

def test_d3_unban():
    rl = RateLimiter(requests_per_minute=10)
    rl.ban("temp.ban")
    assert rl.is_allowed("temp.ban") is False
    rl.unban("temp.ban")
    assert rl.is_allowed("temp.ban") is True

def test_d4_whitelist_remove():
    rl = RateLimiter(requests_per_minute=1)
    rl.add_whitelist("temp.trusted")
    assert rl.is_allowed("temp.trusted") is True
    rl.remove_whitelist("temp.trusted")
    assert rl.is_allowed("temp.trusted") is True  # First request still allowed
    assert rl.is_allowed("temp.trusted") is False  # But now rate limited

def test_d5_is_banned_whitelisted():
    rl = RateLimiter(requests_per_minute=10)
    assert rl.is_banned("nobody") is False
    rl.ban("bad.actor")
    assert rl.is_banned("bad.actor") is True
    assert rl.is_whitelisted("nobody") is False
    rl.add_whitelist("good.actor")
    assert rl.is_whitelisted("good.actor") is True


# ═══════════════════════════════════════════════════════════════════════════
# E. BURST DETECTION
# ═══════════════════════════════════════════════════════════════════════════

def test_e1_burst_detection():
    now = [10000.0]
    rl = RateLimiter(requests_per_minute=120, time_fn=lambda: now[0])
    # Rapid fire within burst window
    for _ in range(25):
        rl.is_allowed("burst.ip")
    assert rl.is_bursting("burst.ip") is True

def test_e2_no_burst_spread():
    now = [11000.0]
    rl = RateLimiter(requests_per_minute=120, time_fn=lambda: now[0])
    # Spread requests across time
    for i in range(10):
        now[0] += 2.0  # 2 seconds apart
        rl.is_allowed("slow.ip")
    assert rl.is_bursting("slow.ip") is False


# ═══════════════════════════════════════════════════════════════════════════
# F. BUCKET MANAGEMENT
# ═══════════════════════════════════════════════════════════════════════════

def test_f1_reset_bucket():
    rl = RateLimiter(requests_per_minute=2)
    rl.is_allowed("reset.ip")
    rl.is_allowed("reset.ip")
    assert rl.is_allowed("reset.ip") is False
    rl.reset("reset.ip")
    assert rl.is_allowed("reset.ip") is True  # Reset = fresh bucket

def test_f2_reset_all():
    rl = RateLimiter(requests_per_minute=1)
    rl.is_allowed("a.a.a.a")
    rl.is_allowed("b.b.b.b")
    count = rl.reset_all()
    assert count >= 2

def test_f3_bucket_info():
    now = [12000.0]
    rl = RateLimiter(requests_per_minute=10, time_fn=lambda: now[0])
    rl.is_allowed("info.ip")
    info = rl.get_bucket_info("info.ip")
    assert info["ip"] == "info.ip"
    assert "tokens" in info
    assert "capacity" in info
    assert "pressure" in info
    assert info["is_banned"] is False

def test_f4_get_all_buckets():
    rl = RateLimiter(requests_per_minute=10)
    for i in range(5):
        rl.is_allowed(f"multi.{i}")
    buckets = rl.get_all_buckets()
    assert len(buckets) >= 5

def test_f5_cleanup_stale():
    now = [13000.0]
    rl = RateLimiter(requests_per_minute=10, time_fn=lambda: now[0])
    rl.is_allowed("stale.ip")
    rl.is_allowed("fresh.ip")
    now[0] += 400  # 400 seconds later
    rl.is_allowed("fresh.ip")  # Touch fresh.ip
    cleaned = rl.cleanup_stale(max_age_seconds=300)
    assert cleaned >= 1  # stale.ip should be cleaned


# ═══════════════════════════════════════════════════════════════════════════
# G. AUDIT LOG
# ═══════════════════════════════════════════════════════════════════════════

def test_g1_blocked_log():
    rl = RateLimiter(requests_per_minute=1)
    rl.is_allowed("log.ip")
    rl.is_allowed("log.ip")  # Should be blocked
    log = rl.get_blocked_log()
    assert len(log) >= 1
    assert log[-1]["ip"] == "log.ip"
    assert log[-1]["reason"] == "rate_limited"

def test_g2_banned_log():
    rl = RateLimiter(requests_per_minute=100)
    rl.ban("banned.ip")
    rl.is_allowed("banned.ip")
    log = rl.get_blocked_log()
    assert any(e["reason"] == "banned" for e in log)


# ═══════════════════════════════════════════════════════════════════════════
# H. STATS & EXPORT
# ═══════════════════════════════════════════════════════════════════════════

def test_h1_stats():
    rl = RateLimiter(requests_per_minute=2)
    rl.is_allowed("stat.ip")
    rl.is_allowed("stat.ip")
    rl.is_allowed("stat.ip")  # blocked
    stats = rl.get_stats()
    assert stats["total_requests"] == 3
    assert stats["total_allowed"] == 2
    assert stats["total_blocked"] == 1
    assert "default_rpm" in stats
    assert "active_buckets" in stats
    assert "redis_enabled" in stats

def test_h2_export_config():
    rl = RateLimiter(requests_per_minute=30)
    rl.set_custom_limit("vip", 100)
    rl.add_whitelist("safe")
    rl.ban("evil")
    export = rl.export_config()
    assert export["default_rpm"] == 30
    assert "vip" in export["custom_limits"]
    assert "safe" in export["whitelist"]
    assert "evil" in export["banlist"]
    assert "burst_threshold" in export


# ═══════════════════════════════════════════════════════════════════════════
# I. THREAD SAFETY / CONCURRENCY
# ═══════════════════════════════════════════════════════════════════════════

def test_i1_concurrent_access():
    rl = RateLimiter(requests_per_minute=100)
    results = []
    errors = []

    def hammer(ip, n):
        try:
            for _ in range(n):
                rl.is_allowed(ip)
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=hammer, args=(f"thread.{i}", 50)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Thread errors: {errors}"
    stats = rl.get_stats()
    assert stats["total_requests"] == 500

def test_i2_concurrent_ban_whitelist():
    rl = RateLimiter(requests_per_minute=100)
    errors = []

    def ops():
        try:
            for i in range(50):
                rl.ban(f"ip.{i}")
                rl.add_whitelist(f"safe.{i}")
                rl.is_allowed(f"ip.{i}")
                rl.unban(f"ip.{i}")
        except Exception as e:
            errors.append(e)

    threads = [threading.Thread(target=ops) for _ in range(5)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert not errors


# ═══════════════════════════════════════════════════════════════════════════
# J. PERFORMANCE / SCALE
# ═══════════════════════════════════════════════════════════════════════════

def test_j1_perf_10000_requests():
    rl = RateLimiter(requests_per_minute=10000)
    start = time.perf_counter()
    for i in range(10000):
        rl.is_allowed(f"{i // 100}.{i % 100}.0.1")
    elapsed = (time.perf_counter() - start) * 1000
    print(f"      10K requests: {elapsed:.1f}ms ({elapsed/10:.1f}us/req)")
    assert elapsed < 2000, f"Too slow: {elapsed:.1f}ms"

def test_j2_perf_same_ip():
    rl = RateLimiter(requests_per_minute=100000)
    start = time.perf_counter()
    for _ in range(5000):
        rl.is_allowed("single.ip")
    elapsed = (time.perf_counter() - start) * 1000
    print(f"      5K same-IP: {elapsed:.1f}ms ({elapsed/5:.1f}us/req)")
    assert elapsed < 1000

def test_j3_concurrent_perf():
    rl = RateLimiter(requests_per_minute=100000)
    start = time.perf_counter()
    threads = []
    for i in range(10):
        t = threading.Thread(target=lambda ip: [rl.is_allowed(ip) for _ in range(1000)], args=(f"perf.{i}",))
        threads.append(t)
        t.start()
    for t in threads:
        t.join()
    elapsed = (time.perf_counter() - start) * 1000
    print(f"      10K concurrent (10 threads): {elapsed:.1f}ms")
    assert elapsed < 3000


# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 72)
    print("  HEAVY UNSEEN DATA TEST -- Features #10-11 Rate Limiting")
    print("=" * 72)

    print("\n  [A] Core Token Bucket")
    run_test("blocks_after_capacity", test_a1_blocks_after_capacity)
    run_test("refill_over_time", test_a2_refill_over_time)
    run_test("per_ip_isolation", test_a3_per_ip_isolation)
    run_test("pressure", test_a4_pressure)
    run_test("empty_ip", test_a5_empty_ip_handling)

    print("\n  [B] Redis Distributed")
    run_test("redis_basic", test_b1_redis_basic)
    run_test("redis_refill", test_b2_redis_refill)
    run_test("redis_failover", test_b3_redis_failover)
    run_test("redis_pressure", test_b4_redis_pressure)

    print("\n  [C] Per-IP Custom Limits")
    run_test("custom_limit", test_c1_custom_limit)
    run_test("remove_custom_limit", test_c2_remove_custom_limit)
    run_test("different_limits", test_c3_different_limits_per_ip)

    print("\n  [D] Whitelist / Banlist")
    run_test("whitelist", test_d1_whitelist)
    run_test("banlist", test_d2_banlist)
    run_test("unban", test_d3_unban)
    run_test("whitelist_remove", test_d4_whitelist_remove)
    run_test("is_banned_whitelisted", test_d5_is_banned_whitelisted)

    print("\n  [E] Burst Detection")
    run_test("burst_detection", test_e1_burst_detection)
    run_test("no_burst_spread", test_e2_no_burst_spread)

    print("\n  [F] Bucket Management")
    run_test("reset_bucket", test_f1_reset_bucket)
    run_test("reset_all", test_f2_reset_all)
    run_test("bucket_info", test_f3_bucket_info)
    run_test("get_all_buckets", test_f4_get_all_buckets)
    run_test("cleanup_stale", test_f5_cleanup_stale)

    print("\n  [G] Audit Log")
    run_test("blocked_log", test_g1_blocked_log)
    run_test("banned_log", test_g2_banned_log)

    print("\n  [H] Stats & Export")
    run_test("stats", test_h1_stats)
    run_test("export_config", test_h2_export_config)

    print("\n  [I] Thread Safety")
    run_test("concurrent_access", test_i1_concurrent_access)
    run_test("concurrent_ban_whitelist", test_i2_concurrent_ban_whitelist)

    print("\n  [J] Performance / Scale")
    run_test("perf_10k_requests", test_j1_perf_10000_requests)
    run_test("perf_same_ip", test_j2_perf_same_ip)
    run_test("concurrent_perf", test_j3_concurrent_perf)

    passed = sum(1 for v in RESULTS.values() if v == "PASS")
    total = len(RESULTS)
    failed = {k: v for k, v in RESULTS.items() if v != "PASS"}

    print(f"\n{'='*72}")
    print(f"  RESULT: {passed}/{total} tests passed")
    if failed:
        print(f"\n  FAILURES ({len(failed)}):")
        for k, v in failed.items(): print(f"    {k}: {v}")
    print(f"{'='*72}")

    out = os.path.join(_root, "artifacts", "evidence", "rate_limiter_heavy.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump({"passed": passed, "total": total, "results": RESULTS}, f, indent=2)
    print(f"\n  Saved: {os.path.abspath(out)}")
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
