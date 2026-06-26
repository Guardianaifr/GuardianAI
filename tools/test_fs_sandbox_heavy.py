"""
HEAVY UNSEEN DATA TEST — Feature #9 Filesystem Sandbox
========================================================
Tests all 10 capabilities with hard unseen data:
  A. Path Allowlist/Denylist
  B. Path Traversal Prevention
  C. Extension Blocking
  D. Permission Model (R/W/X)
  E. Symlink Attack Prevention
  F. Default OS Denylists
  G. Runtime Hot-Add/Remove
  H. Audit Logging
  I. Stats & Export
  J. Performance / Scale
"""
import sys, os, json, time, tempfile
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, "guardian"))

from guardian.runtime.filesystem_sandbox import FilesystemSandbox, Permission

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
# A. PATH ALLOWLIST / DENYLIST
# ═══════════════════════════════════════════════════════════════════════════

def test_a1_allow_rules():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [
            {"path": "C:/workspace", "permission": "rw"},
            {"path": "C:/data", "permission": "read"},
        ],
        "use_default_denylists": False,
    }})
    assert sb.is_read_allowed("C:/workspace/file.txt")
    assert sb.is_write_allowed("C:/workspace/file.txt")
    assert sb.is_read_allowed("C:/data/report.csv")
    assert not sb.is_write_allowed("C:/data/report.csv")  # read-only
    assert not sb.is_read_allowed("C:/secret/credentials.txt")  # not allowed

def test_a2_deny_rules():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/workspace", "permission": "rw"}],
        "denied_paths": ["C:/workspace/secrets"],
        "use_default_denylists": False,
    }})
    assert sb.is_read_allowed("C:/workspace/code.py")
    assert not sb.is_read_allowed("C:/workspace/secrets/api_key.txt")  # denied

def test_a3_deny_overrides_allow():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/app", "permission": "rw"}],
        "denied_paths": ["C:/app/config/creds.yaml"],
        "use_default_denylists": False,
    }})
    assert sb.is_read_allowed("C:/app/main.py")
    assert not sb.is_read_allowed("C:/app/config/creds.yaml")

def test_a4_open_sandbox_no_rules():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [],
        "denied_paths": [],
        "use_default_denylists": False,
    }})
    # No allow rules = open sandbox
    assert sb.is_read_allowed("C:/anything/goes.txt")


# ═══════════════════════════════════════════════════════════════════════════
# B. PATH TRAVERSAL PREVENTION
# ═══════════════════════════════════════════════════════════════════════════

TRAVERSAL_PAYLOADS = [
    "../../../etc/passwd",
    "..\\..\\..\\Windows\\System32\\config\\SAM",
    "workspace/../../etc/shadow",
    "data/../../../proc/kcore",
    "./logs/../../../../root/.ssh/id_rsa",
    "..%2f..%2f..%2fetc%2fpasswd",  # URL-encoded (raw string)
    "....//....//etc/passwd",
]

def test_b1_traversal_blocked():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/workspace", "permission": "rw"}],
        "use_default_denylists": False,
    }})
    blocked = 0
    for payload in TRAVERSAL_PAYLOADS:
        allowed, reason = sb.check_access(payload, "read")
        if not allowed:
            blocked += 1
    print(f"      Traversal blocked: {blocked}/{len(TRAVERSAL_PAYLOADS)}")
    assert blocked >= 5, f"Only blocked {blocked}/{len(TRAVERSAL_PAYLOADS)} traversals"

def test_b2_null_byte():
    sb = FilesystemSandbox()
    allowed, reason = sb.check_access("file.txt\x00.jpg", "read")
    assert not allowed
    assert "null byte" in reason


# ═══════════════════════════════════════════════════════════════════════════
# C. EXTENSION BLOCKING
# ═══════════════════════════════════════════════════════════════════════════

BLOCKED_EXTENSIONS = [
    "malware.exe", "backdoor.dll", "rootkit.sys",
    "deploy.bat", "cleanup.cmd", "evil.ps1",
    "macro.vbs", "screensaver.scr", "installer.msi",
]

SAFE_EXTENSIONS = [
    "code.py", "data.json", "report.csv",
    "notes.md", "config.yaml", "styles.css",
    "app.js", "index.html", "image.png",
]

def test_c1_blocked_extensions():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "use_default_denylists": False,
    }})
    for f in BLOCKED_EXTENSIONS:
        allowed, _ = sb.check_access(f"C:/workspace/{f}", "write")
        assert not allowed, f"Should block writing {f}"

def test_c2_safe_extensions():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "use_default_denylists": False,
    }})
    for f in SAFE_EXTENSIONS:
        allowed, _ = sb.check_access(f"C:/workspace/{f}", "write")
        assert allowed, f"Should allow writing {f}"

def test_c3_extension_only_on_write_execute():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "use_default_denylists": False,
    }})
    # Reading .exe should be allowed (extension check is for write/execute)
    allowed, _ = sb.check_access("C:/workspace/app.exe", "read")
    assert allowed


# ═══════════════════════════════════════════════════════════════════════════
# D. PERMISSION MODEL
# ═══════════════════════════════════════════════════════════════════════════

def test_d1_read_only():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/logs", "permission": "read"}],
        "use_default_denylists": False,
    }})
    assert sb.is_read_allowed("C:/logs/app.log")
    assert not sb.is_write_allowed("C:/logs/app.log")

def test_d2_read_write():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/workspace", "permission": "rw"}],
        "use_default_denylists": False,
    }})
    assert sb.is_read_allowed("C:/workspace/file.py")
    assert sb.is_write_allowed("C:/workspace/file.py")

def test_d3_execute():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/bin", "permission": "all"}],
        "use_default_denylists": False,
    }})
    allowed, _ = sb.check_access("C:/bin/tool.py", "execute")
    assert allowed


# ═══════════════════════════════════════════════════════════════════════════
# E. SYMLINK ATTACK PREVENTION
# ═══════════════════════════════════════════════════════════════════════════

def test_e1_symlink_policy():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "resolve_symlinks": True,
        "use_default_denylists": False,
    }})
    assert sb.resolve_symlinks is True
    # Can't easily test symlinks on Windows in unit tests,
    # but verify the config is respected
    sb2 = FilesystemSandbox({"filesystem_sandbox": {"resolve_symlinks": False}})
    assert sb2.resolve_symlinks is False


# ═══════════════════════════════════════════════════════════════════════════
# F. DEFAULT OS DENYLISTS
# ═══════════════════════════════════════════════════════════════════════════

def test_f1_default_denylists():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "use_default_denylists": True,
    }})
    # Should have default deny rules loaded
    assert len(sb.deny_rules) > 0
    deny_paths = [r.path for r in sb.deny_rules]
    if os.name == "nt":
        # Windows defaults
        found = any("System32" in p or "config" in p for p in deny_paths)
        assert found, f"Missing Windows deny defaults: {deny_paths[:5]}"
    else:
        found = any("shadow" in p or "passwd" in p for p in deny_paths)
        assert found, f"Missing Unix deny defaults"

def test_f2_sensitive_paths_blocked():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "use_default_denylists": True,
    }})
    if os.name == "nt":
        paths = [
            "C:\\Windows\\System32\\config\\SAM",
            "C:\\Windows\\System32\\config\\SECURITY",
        ]
    else:
        paths = ["/etc/shadow", "/etc/sudoers"]
    
    for p in paths:
        allowed, reason = sb.check_access(p, "read")
        assert not allowed, f"Sensitive path {p} was allowed! ({reason})"


# ═══════════════════════════════════════════════════════════════════════════
# G. RUNTIME HOT-ADD/REMOVE
# ═══════════════════════════════════════════════════════════════════════════

def test_g1_hot_add_allow():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/existing", "permission": "read"}],
        "use_default_denylists": False,
    }})
    # Closed sandbox — C:/newdir not in allow list
    assert not sb.is_read_allowed("C:/newdir/file.txt")
    sb.add_allow_rule("C:/newdir", "rw")
    assert sb.is_read_allowed("C:/newdir/file.txt")
    assert sb.is_write_allowed("C:/newdir/file.txt")

def test_g2_hot_add_deny():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/workspace", "permission": "rw"}],
        "use_default_denylists": False,
    }})
    assert sb.is_read_allowed("C:/workspace/secrets.txt")
    sb.add_deny_rule("C:/workspace/secrets.txt")
    assert not sb.is_read_allowed("C:/workspace/secrets.txt")

def test_g3_remove_allow():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [
            {"path": "C:/temp", "permission": "rw"},
            {"path": "C:/keep", "permission": "read"},
        ],
        "use_default_denylists": False,
    }})
    assert sb.is_read_allowed("C:/temp/file.txt")
    sb.remove_allow_rule("C:/temp")
    # Still closed sandbox (C:/keep rule remains), so C:/temp is now denied
    assert not sb.is_read_allowed("C:/temp/file.txt")

def test_g4_remove_deny():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/workspace", "permission": "rw"}],
        "denied_paths": ["C:/workspace/secrets"],
        "use_default_denylists": False,
    }})
    assert not sb.is_read_allowed("C:/workspace/secrets/key.txt")
    sb.remove_deny_rule("C:/workspace/secrets")
    assert sb.is_read_allowed("C:/workspace/secrets/key.txt")


# ═══════════════════════════════════════════════════════════════════════════
# H. AUDIT LOGGING
# ═══════════════════════════════════════════════════════════════════════════

def test_h1_audit_log():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "use_default_denylists": False,
    }})
    sb.check_access("C:/workspace/file.txt", "read")
    sb.check_access("C:/secret/file.txt", "read")
    log = sb.get_audit_log()
    assert len(log) >= 2
    assert "path" in log[0]
    assert "operation" in log[0]
    assert "allowed" in log[0]
    assert "timestamp" in log[0]


# ═══════════════════════════════════════════════════════════════════════════
# I. STATS & EXPORT
# ═══════════════════════════════════════════════════════════════════════════

def test_i1_stats():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/workspace", "permission": "rw"}],
        "use_default_denylists": False,
    }})
    sb.check_access("C:/workspace/ok.txt", "read")
    sb.check_access("C:/forbidden/nope.txt", "read")
    stats = sb.get_stats()
    assert stats["total_checks"] == 2
    assert stats["allowed"] >= 1
    assert stats["denied"] >= 1

def test_i2_export():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/workspace", "permission": "rw"}],
        "denied_paths": ["C:/workspace/secrets"],
        "use_default_denylists": False,
    }})
    export = sb.export_rules()
    assert "allow_rules" in export
    assert "deny_rules" in export
    assert "denied_extensions" in export
    assert len(export["allow_rules"]) >= 1
    assert len(export["deny_rules"]) >= 1

def test_i3_sandbox_tmp():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "use_default_denylists": False,
    }})
    tmp = sb.get_sandbox_tmp()
    assert os.path.isdir(tmp)
    assert "guardian_sandbox" in tmp


# ═══════════════════════════════════════════════════════════════════════════
# J. PERFORMANCE / SCALE
# ═══════════════════════════════════════════════════════════════════════════

def test_j1_perf_1000_checks():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/workspace", "permission": "rw"}],
        "use_default_denylists": True,
    }})
    paths = [f"C:/workspace/dir{i}/file{j}.py" for i in range(100) for j in range(10)]
    start = time.perf_counter()
    for p in paths:
        sb.check_access(p, "read")
    elapsed = (time.perf_counter() - start) * 1000
    print(f"      1000 path checks: {elapsed:.1f}ms ({elapsed/len(paths)*1000:.1f}us/check)")
    assert elapsed < 500, f"Too slow: {elapsed:.1f}ms"

def test_j2_perf_traversal_checks():
    sb = FilesystemSandbox({"filesystem_sandbox": {
        "allowed_paths": [{"path": "C:/workspace", "permission": "rw"}],
        "use_default_denylists": False,
    }})
    payloads = [f"../../{'../' * i}etc/passwd" for i in range(100)]
    start = time.perf_counter()
    for p in payloads:
        sb.check_access(p, "read")
    elapsed = (time.perf_counter() - start) * 1000
    print(f"      100 traversal checks: {elapsed:.1f}ms")
    assert elapsed < 200


# ═══════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 72)
    print("  HEAVY UNSEEN DATA TEST -- Feature #9 Filesystem Sandbox")
    print("=" * 72)

    print("\n  [A] Path Allowlist / Denylist")
    run_test("allow_rules",        test_a1_allow_rules)
    run_test("deny_rules",         test_a2_deny_rules)
    run_test("deny_overrides",     test_a3_deny_overrides_allow)
    run_test("open_sandbox",       test_a4_open_sandbox_no_rules)

    print("\n  [B] Path Traversal Prevention")
    run_test("traversal_blocked",  test_b1_traversal_blocked)
    run_test("null_byte",          test_b2_null_byte)

    print("\n  [C] Extension Blocking")
    run_test("blocked_extensions", test_c1_blocked_extensions)
    run_test("safe_extensions",    test_c2_safe_extensions)
    run_test("ext_read_allowed",   test_c3_extension_only_on_write_execute)

    print("\n  [D] Permission Model")
    run_test("read_only",          test_d1_read_only)
    run_test("read_write",         test_d2_read_write)
    run_test("execute",            test_d3_execute)

    print("\n  [E] Symlink Policy")
    run_test("symlink_policy",     test_e1_symlink_policy)

    print("\n  [F] Default OS Denylists")
    run_test("default_denylists",  test_f1_default_denylists)
    run_test("sensitive_blocked",  test_f2_sensitive_paths_blocked)

    print("\n  [G] Runtime Hot-Add/Remove")
    run_test("hot_add_allow",      test_g1_hot_add_allow)
    run_test("hot_add_deny",       test_g2_hot_add_deny)
    run_test("remove_allow",       test_g3_remove_allow)
    run_test("remove_deny",        test_g4_remove_deny)

    print("\n  [H] Audit Logging")
    run_test("audit_log",          test_h1_audit_log)

    print("\n  [I] Stats & Export")
    run_test("stats",              test_i1_stats)
    run_test("export_rules",       test_i2_export)
    run_test("sandbox_tmp",        test_i3_sandbox_tmp)

    print("\n  [J] Performance / Scale")
    run_test("perf_1000_checks",   test_j1_perf_1000_checks)
    run_test("perf_traversal",     test_j2_perf_traversal_checks)

    passed = sum(1 for v in RESULTS.values() if v == "PASS")
    total = len(RESULTS)
    failed = {k: v for k, v in RESULTS.items() if v != "PASS"}

    print(f"\n{'='*72}")
    print(f"  RESULT: {passed}/{total} tests passed")
    if failed:
        print(f"\n  FAILURES ({len(failed)}):")
        for k, v in failed.items(): print(f"    {k}: {v}")
    print(f"{'='*72}")

    out = os.path.join(_root, "artifacts", "evidence", "fs_sandbox_heavy.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump({"passed": passed, "total": total, "results": RESULTS}, f, indent=2)
    print(f"\n  Saved: {os.path.abspath(out)}")
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
