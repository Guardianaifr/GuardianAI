"""
HEAVY UNSEEN DATA TEST — Feature #8 Network Monitor / DNS Sinkhole
====================================================================
Tests all 10 capabilities with hard unseen data:
  A. IP Blocklist (direct IPs + CIDR ranges)
  B. Domain Blocklist (exact + subdomain matching)
  C. DNS Sinkhole (resolution interception)
  D. Allowlist (private/loopback never blocked)
  E. Connection Scanning (mocked psutil connections)
  F. Runtime Hot-Add / Remove
  G. Rate-Limited Alerting
  H. Stats & Export
  I. Adversarial Evasion Resistance
  J. Performance / Scale
"""
import sys, os, json, time, ipaddress
from unittest.mock import patch, MagicMock
from collections import namedtuple

_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, "guardian"))

from guardian.runtime.network_monitor import NetworkMonitor

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


# ═══════════════════════════════════════════════════════════════════════════
# A. IP BLOCKLIST
# ═══════════════════════════════════════════════════════════════════════════

UNSEEN_BLOCKED_IPS = [
    # RFC 5737 TEST-NET ranges
    ("192.0.2.1", True),
    ("192.0.2.255", True),
    ("198.51.100.50", True),
    ("203.0.113.99", True),
    # "This" network
    ("0.0.0.1", True),
    ("0.255.255.255", True),
    # Normal public IPs — should NOT be blocked
    ("8.8.8.8", False),
    ("1.1.1.1", False),
    ("142.250.217.78", False),  # google.com
    ("151.101.1.140", False),   # reddit.com
    ("13.107.42.14", False),    # microsoft.com
]

def test_a1_ip_blocklist():
    nm = NetworkMonitor()
    wrong = []
    for ip, expected in UNSEEN_BLOCKED_IPS:
        blocked, _ = nm.is_ip_blocked(ip)
        if blocked != expected:
            wrong.append((ip, expected, blocked))
    assert not wrong, f"IP blocklist errors: {wrong}"

def test_a2_custom_ip_blocklist():
    nm = NetworkMonitor({"network_monitoring": {
        "blocked_ips": ["45.33.32.156", "93.184.216.34"],
        "blocked_cidrs": [],
    }})
    assert nm.is_ip_blocked("45.33.32.156")[0] is True
    assert nm.is_ip_blocked("93.184.216.34")[0] is True
    assert nm.is_ip_blocked("8.8.8.8")[0] is False

def test_a3_ipv6_handling():
    nm = NetworkMonitor()
    # :: and 0.0.0.0 should not be blocked (they're listen addresses)
    assert nm.is_ip_blocked("::")[0] is False
    assert nm.is_ip_blocked("0.0.0.0")[0] is False
    # Loopback IPv6 should be allowlisted
    assert nm.is_ip_blocked("::1")[0] is False


# ═══════════════════════════════════════════════════════════════════════════
# B. DOMAIN BLOCKLIST
# ═══════════════════════════════════════════════════════════════════════════

UNSEEN_DOMAINS = [
    # Should be blocked (exact + subdomain)
    ("ngrok.io", True),
    ("abc123.ngrok.io", True),
    ("tunnel.ngrok-free.app", True),
    ("evil.serveo.net", True),
    ("xxx.burpcollaborator.net", True),
    ("test.interact.sh", True),
    ("abc.oastify.com", True),
    ("test123.webhook.site", True),
    ("mybin.requestbin.net", True),
    ("tag.canarytokens.com", True),
    ("transfer.sh", True),
    ("file.io", True),
    ("0x0.st", True),
    ("pool.minexmr.com", True),
    ("deep.sub.moneroocean.stream", True),
    # Should NOT be blocked
    ("google.com", False),
    ("github.com", False),
    ("api.openai.com", False),
    ("pypi.org", False),
    ("stackoverflow.com", False),
    ("docs.python.org", False),
    ("aws.amazon.com", False),
]

def test_b1_domain_blocklist():
    nm = NetworkMonitor()
    wrong = []
    for domain, expected in UNSEEN_DOMAINS:
        blocked, _ = nm.is_domain_blocked(domain)
        if blocked != expected:
            wrong.append((domain, expected, blocked))
    assert not wrong, f"Domain blocklist errors: {wrong}"

def test_b2_subdomain_cascade():
    nm = NetworkMonitor()
    # Deep subdomain nesting
    assert nm.is_domain_blocked("a.b.c.d.ngrok.io")[0] is True
    assert nm.is_domain_blocked("a.b.c.d.google.com")[0] is False

def test_b3_case_insensitive():
    nm = NetworkMonitor()
    assert nm.is_domain_blocked("NGROK.IO")[0] is True
    assert nm.is_domain_blocked("NgRoK.Io")[0] is True
    assert nm.is_domain_blocked("WEBHOOK.SITE")[0] is True


# ═══════════════════════════════════════════════════════════════════════════
# C. DNS SINKHOLE
# ═══════════════════════════════════════════════════════════════════════════

def test_c1_sinkhole_blocked_domain():
    nm = NetworkMonitor()
    result = nm.resolve_with_sinkhole("evil.ngrok.io")
    assert result == "0.0.0.0", f"Sinkhole should return 0.0.0.0, got {result}"
    assert nm._stats["dns_sinkholed"] >= 1

def test_c2_sinkhole_safe_domain():
    nm = NetworkMonitor()
    result = nm.resolve_with_sinkhole("google.com")
    assert result != "0.0.0.0", "Safe domain should NOT be sinkholed"
    assert result != "", "Should resolve to real IP"

def test_c3_sinkhole_disabled():
    nm = NetworkMonitor({"network_monitoring": {"sinkhole_enabled": False}})
    result = nm.resolve_with_sinkhole("evil.ngrok.io")
    # Even with sinkhole disabled, it should still resolve normally
    # (the domain may or may not resolve, but shouldn't sinkhole)
    assert nm._stats["dns_sinkholed"] == 0

def test_c4_custom_sinkhole_address():
    nm = NetworkMonitor({"network_monitoring": {"sinkhole_address": "127.0.0.1"}})
    result = nm.resolve_with_sinkhole("evil.ngrok.io")
    assert result == "127.0.0.1"


# ═══════════════════════════════════════════════════════════════════════════
# D. ALLOWLIST
# ═══════════════════════════════════════════════════════════════════════════

PRIVATE_IPS = [
    "127.0.0.1", "127.0.0.100", "10.0.0.1", "10.255.255.255",
    "172.16.0.1", "172.31.255.255", "192.168.0.1", "192.168.255.255",
]

def test_d1_private_ips_never_blocked():
    nm = NetworkMonitor({"network_monitoring": {
        "blocked_cidrs": ["0.0.0.0/0"],  # Block everything
    }})
    for ip in PRIVATE_IPS:
        blocked, reason = nm.is_ip_blocked(ip)
        assert not blocked, f"Private IP {ip} was blocked! ({reason})"

def test_d2_domain_allowlist():
    nm = NetworkMonitor({"network_monitoring": {
        "blocked_domains": ["example.com"],
        "allowlist_domains": ["safe.example.com"],
    }})
    assert nm.is_domain_blocked("evil.example.com")[0] is True
    assert nm.is_domain_blocked("safe.example.com")[0] is False


# ═══════════════════════════════════════════════════════════════════════════
# E. CONNECTION SCANNING (mocked psutil)
# ═══════════════════════════════════════════════════════════════════════════

ConnInfo = namedtuple("ConnInfo", ["raddr", "status", "pid"])
AddrPair = namedtuple("AddrPair", ["ip", "port"])

def test_e1_scan_detects_blocked():
    nm = NetworkMonitor()
    mock_conns = [
        ConnInfo(raddr=AddrPair("192.0.2.50", 443), status="ESTABLISHED", pid=1234),
        ConnInfo(raddr=AddrPair("8.8.8.8", 53), status="ESTABLISHED", pid=5678),
        ConnInfo(raddr=AddrPair("198.51.100.10", 80), status="SYN_SENT", pid=9999),
        ConnInfo(raddr=None, status="LISTEN", pid=80),
    ]
    with patch("psutil.net_connections", return_value=mock_conns), \
         patch("psutil.Process") as mock_proc:
        mock_proc.return_value.name.return_value = "malware.exe"
        blocked = nm.scan_connections()
    
    assert len(blocked) == 2, f"Expected 2 blocked, got {len(blocked)}"
    blocked_ips = [b["remote_ip"] for b in blocked]
    assert "192.0.2.50" in blocked_ips
    assert "198.51.100.10" in blocked_ips
    assert "8.8.8.8" not in blocked_ips

def test_e2_scan_attributes_process():
    nm = NetworkMonitor()
    mock_conns = [
        ConnInfo(raddr=AddrPair("192.0.2.1", 4444), status="ESTABLISHED", pid=6666),
    ]
    with patch("psutil.net_connections", return_value=mock_conns), \
         patch("psutil.Process") as mock_proc:
        mock_proc.return_value.name.return_value = "reverse_shell.exe"
        blocked = nm.scan_connections()
    
    assert len(blocked) == 1
    assert blocked[0]["pid"] == 6666
    assert blocked[0]["process_name"] == "reverse_shell.exe"
    assert blocked[0]["remote_port"] == 4444

def test_e3_domain_preflight():
    nm = NetworkMonitor()
    result = nm.check_domain_connection("evil.ngrok.io", 443)
    assert result["blocked"] is True
    assert result["sinkhole_ip"] == "0.0.0.0"
    
    result2 = nm.check_domain_connection("api.github.com", 443)
    assert result2["blocked"] is False
    assert result2["sinkhole_ip"] is None


# ═══════════════════════════════════════════════════════════════════════════
# F. RUNTIME HOT-ADD / REMOVE
# ═══════════════════════════════════════════════════════════════════════════

def test_f1_hot_add_ip():
    nm = NetworkMonitor({"network_monitoring": {"blocked_ips": [], "blocked_cidrs": []}})
    assert nm.is_ip_blocked("45.33.32.156")[0] is False
    nm.add_blocked_ip("45.33.32.156")
    assert nm.is_ip_blocked("45.33.32.156")[0] is True

def test_f2_hot_add_cidr():
    nm = NetworkMonitor({"network_monitoring": {"blocked_cidrs": []}})
    assert nm.is_ip_blocked("100.64.0.50")[0] is False
    nm.add_blocked_cidr("100.64.0.0/10")
    assert nm.is_ip_blocked("100.64.0.50")[0] is True

def test_f3_hot_add_domain():
    nm = NetworkMonitor({"network_monitoring": {"blocked_domains": []}})
    assert nm.is_domain_blocked("evil-new.com")[0] is False
    nm.add_blocked_domain("evil-new.com")
    assert nm.is_domain_blocked("evil-new.com")[0] is True
    assert nm.is_domain_blocked("sub.evil-new.com")[0] is True

def test_f4_remove_domain():
    nm = NetworkMonitor()
    assert nm.is_domain_blocked("ngrok.io")[0] is True
    nm.remove_blocked_domain("ngrok.io")
    assert nm.is_domain_blocked("ngrok.io")[0] is False

def test_f5_remove_blocked_ip():
    nm = NetworkMonitor({"network_monitoring": {"blocked_ips": ["1.2.3.4"], "blocked_cidrs": []}})
    assert nm.is_ip_blocked("1.2.3.4")[0] is True
    assert nm.remove_blocked_ip("1.2.3.4") is True
    assert nm.is_ip_blocked("1.2.3.4")[0] is False
    assert nm.remove_blocked_ip("1.2.3.4") is False  # Already removed

def test_f6_remove_blocked_cidr():
    nm = NetworkMonitor({"network_monitoring": {"blocked_cidrs": ["100.64.0.0/16"]}})
    assert nm.is_ip_blocked("100.64.1.1")[0] is True
    assert nm.remove_blocked_cidr("100.64.0.0/16") is True
    assert nm.is_ip_blocked("100.64.1.1")[0] is False
    assert nm.remove_blocked_cidr("100.64.0.0/16") is False  # Already removed


# ═══════════════════════════════════════════════════════════════════════════
# G. RATE-LIMITED ALERTING
# ═══════════════════════════════════════════════════════════════════════════

def test_g1_alert_cooldown():
    nm = NetworkMonitor({"network_monitoring": {"alert_cooldown_seconds": 60}})
    entry = {"remote_ip": "192.0.2.1", "remote_port": 443, "pid": 1, "process_name": "test", "reason": "test", "status": "EST", "timestamp": time.time()}
    nm._emit_alert(entry)
    nm._emit_alert(entry)  # Should be suppressed
    nm._emit_alert(entry)  # Should be suppressed
    assert len(nm._blocked_log) == 1, f"Rate limiting failed: {len(nm._blocked_log)} alerts"


# ═══════════════════════════════════════════════════════════════════════════
# H. STATS & EXPORT
# ═══════════════════════════════════════════════════════════════════════════

def test_h1_stats():
    nm = NetworkMonitor()
    nm.is_ip_blocked("192.0.2.1")
    stats = nm.get_stats()
    assert "blocked_cidrs_count" in stats
    assert "blocked_domains_count" in stats
    assert stats["sinkhole_enabled"] is True

def test_h2_export():
    nm = NetworkMonitor()
    export = nm.export_blocklists()
    assert "blocked_cidrs" in export
    assert "blocked_domains" in export
    assert "blocked_ips" in export
    assert len(export["blocked_domains"]) > 0

def test_h3_is_ip_allowed():
    nm = NetworkMonitor()
    assert nm.is_ip_allowed("127.0.0.1") is True
    assert nm.is_ip_allowed("10.0.0.1") is True
    assert nm.is_ip_allowed("192.168.1.1") is True
    assert nm.is_ip_allowed("8.8.8.8") is False
    assert nm.is_ip_allowed("203.0.113.5") is False

def test_h4_get_blocked_log():
    nm = NetworkMonitor({"network_monitoring": {"alert_cooldown_seconds": 0}})
    entry = {"remote_ip": "192.0.2.99", "remote_port": 80, "pid": 42, "process_name": "test", "reason": "blocked", "status": "EST", "timestamp": time.time()}
    nm._emit_alert(entry)
    log = nm.get_blocked_log()
    assert len(log) >= 1
    assert log[-1]["remote_ip"] == "192.0.2.99"
    assert "pid" in log[-1]

def test_h5_start_stop():
    nm = NetworkMonitor()
    # Verify stop works without start (no error)
    nm.stop()
    assert nm._thread is None


# ═══════════════════════════════════════════════════════════════════════════
# I. ADVERSARIAL EVASION RESISTANCE
# ═══════════════════════════════════════════════════════════════════════════

EVASION_DOMAINS = [
    ("ngrok.io.", True),       # Trailing dot
    ("NGROK.IO", True),        # Uppercase
    (".ngrok.io", True),       # Leading dot
    ("sub.sub.sub.ngrok.io", True),  # Deep nesting
    ("ngrok.io.evil.com", False),    # Appended — NOT a subdomain of ngrok.io
]

def test_i1_domain_evasion():
    nm = NetworkMonitor()
    wrong = []
    for domain, expected in EVASION_DOMAINS:
        blocked, _ = nm.is_domain_blocked(domain)
        if blocked != expected:
            wrong.append((domain, expected, blocked))
    assert not wrong, f"Evasion failures: {wrong}"

def test_i2_ip_boundary():
    nm = NetworkMonitor()
    # Just outside TEST-NET-1 range
    assert nm.is_ip_blocked("192.0.1.255")[0] is False
    assert nm.is_ip_blocked("192.0.3.0")[0] is False
    # Just inside
    assert nm.is_ip_blocked("192.0.2.0")[0] is True
    assert nm.is_ip_blocked("192.0.2.255")[0] is True


# ═══════════════════════════════════════════════════════════════════════════
# J. PERFORMANCE / SCALE
# ═══════════════════════════════════════════════════════════════════════════

def test_j1_ip_check_performance():
    nm = NetworkMonitor()
    ips = [f"{i}.{j}.{k}.1" for i in range(1, 11) for j in range(1, 11) for k in range(1, 11)]
    start = time.perf_counter()
    for ip in ips:
        nm.is_ip_blocked(ip)
    elapsed = (time.perf_counter() - start) * 1000
    print(f"      IP check: {len(ips)} IPs in {elapsed:.1f}ms ({elapsed/len(ips)*1000:.1f}us/ip)")
    assert elapsed < 500, f"Too slow: {elapsed:.1f}ms for {len(ips)} IPs"

def test_j2_domain_check_performance():
    nm = NetworkMonitor()
    domains = [f"test{i}.example{j}.com" for i in range(100) for j in range(10)]
    start = time.perf_counter()
    for d in domains:
        nm.is_domain_blocked(d)
    elapsed = (time.perf_counter() - start) * 1000
    print(f"      Domain check: {len(domains)} domains in {elapsed:.1f}ms ({elapsed/len(domains)*1000:.1f}us/domain)")
    assert elapsed < 500, f"Too slow: {elapsed:.1f}ms"

def test_j3_scan_1000_connections():
    nm = NetworkMonitor()
    conns = []
    for i in range(1000):
        ip = f"{(i//256)+1}.{i%256}.0.1"
        conns.append(ConnInfo(raddr=AddrPair(ip, 443), status="ESTABLISHED", pid=i+1000))
    # Add 5 blocked ones
    for i in range(5):
        conns.append(ConnInfo(raddr=AddrPair(f"192.0.2.{i+1}", 4444), status="ESTABLISHED", pid=i))
    
    start = time.perf_counter()
    with patch("psutil.net_connections", return_value=conns), \
         patch("psutil.Process") as mock_proc:
        mock_proc.return_value.name.return_value = "test.exe"
        blocked = nm.scan_connections()
    elapsed = (time.perf_counter() - start) * 1000
    
    print(f"      Scan: {len(conns)} connections in {elapsed:.1f}ms, {len(blocked)} blocked")
    assert len(blocked) == 5
    assert elapsed < 1000


# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 72)
    print("  HEAVY UNSEEN DATA TEST — Feature #8 Network Monitor / DNS Sinkhole")
    print("=" * 72)

    print("\n  [A] IP Blocklist")
    run_test("ip_blocklist_unseen", test_a1_ip_blocklist)
    run_test("ip_blocklist_custom", test_a2_custom_ip_blocklist)
    run_test("ipv6_handling", test_a3_ipv6_handling)

    print("\n  [B] Domain Blocklist")
    run_test("domain_blocklist_unseen", test_b1_domain_blocklist)
    run_test("subdomain_cascade", test_b2_subdomain_cascade)
    run_test("case_insensitive", test_b3_case_insensitive)

    print("\n  [C] DNS Sinkhole")
    run_test("sinkhole_blocked", test_c1_sinkhole_blocked_domain)
    run_test("sinkhole_safe", test_c2_sinkhole_safe_domain)
    run_test("sinkhole_disabled", test_c3_sinkhole_disabled)
    run_test("sinkhole_custom_addr", test_c4_custom_sinkhole_address)

    print("\n  [D] Allowlist")
    run_test("private_ips_safe", test_d1_private_ips_never_blocked)
    run_test("domain_allowlist", test_d2_domain_allowlist)

    print("\n  [E] Connection Scanning")
    run_test("scan_blocked_conns", test_e1_scan_detects_blocked)
    run_test("scan_process_attr", test_e2_scan_attributes_process)
    run_test("domain_preflight", test_e3_domain_preflight)

    print("\n  [F] Runtime Hot-Add / Remove")
    run_test("hot_add_ip", test_f1_hot_add_ip)
    run_test("hot_add_cidr", test_f2_hot_add_cidr)
    run_test("hot_add_domain", test_f3_hot_add_domain)
    run_test("remove_domain", test_f4_remove_domain)
    run_test("remove_blocked_ip", test_f5_remove_blocked_ip)
    run_test("remove_blocked_cidr", test_f6_remove_blocked_cidr)

    print("\n  [G] Rate-Limited Alerting")
    run_test("alert_cooldown", test_g1_alert_cooldown)

    print("\n  [H] Stats & Export")
    run_test("stats_shape", test_h1_stats)
    run_test("export_blocklists", test_h2_export)
    run_test("is_ip_allowed", test_h3_is_ip_allowed)
    run_test("get_blocked_log", test_h4_get_blocked_log)
    run_test("start_stop", test_h5_start_stop)

    print("\n  [I] Adversarial Evasion")
    run_test("domain_evasion", test_i1_domain_evasion)
    run_test("ip_boundary", test_i2_ip_boundary)

    print("\n  [J] Performance / Scale")
    run_test("ip_perf_1000", test_j1_ip_check_performance)
    run_test("domain_perf_1000", test_j2_domain_check_performance)
    run_test("scan_1000_conns", test_j3_scan_1000_connections)

    passed = sum(1 for v in RESULTS.values() if v == "PASS")
    total = len(RESULTS)
    failed = {k: v for k, v in RESULTS.items() if v != "PASS"}

    print(f"\n{'='*72}")
    print(f"  RESULT: {passed}/{total} tests passed")
    if failed:
        print(f"\n  FAILURES ({len(failed)}):")
        for k, v in failed.items(): print(f"    {k}: {v}")
    print(f"{'='*72}")

    out = os.path.join(_root, "artifacts", "evidence", "network_monitor_heavy.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump({"passed": passed, "total": total, "results": RESULTS}, f, indent=2)
    print(f"\n  Saved: {os.path.abspath(out)}")
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
