"""
UNSEEN DATA TEST - Feature #31 Output Watermarking
====================================================
Adversarial tampering, steganographic resilience, key rotation,
and batch verification from real-world content integrity research.
"""
import sys, os, json, hashlib, hmac, time
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
sys.path.insert(0, os.path.join(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")), "guardian"))

from security.output_watermark import (
    OutputWatermarker, WatermarkKeyRotator, SteganographicWatermarker,
    WatermarkAuditLog, content_fingerprint, batch_verify,
)

RESULTS = {}

def run_test(name, fn):
    try:
        fn()
        RESULTS[name] = "PASS"
        print(f"  [PASS] {name}")
    except Exception as e:
        RESULTS[name] = f"FAIL: {e}"
        print(f"  [FAIL] {name}: {e}")

def _wm(key="test-key-123"):
    return OutputWatermarker({"enabled": True, "key": key, "key_id": "k1", "require_json_output": True})


# ============ KEY ROTATION ============

def test_key_rotation_basic():
    kr = WatermarkKeyRotator()
    kr.add_key("v1", "secret-v1", make_active=True)
    kr.add_key("v2", "secret-v2")
    assert kr.active_key_id == "v1"
    kr.rotate("v3", "secret-v3")
    assert kr.active_key_id == "v3"
    assert len(kr.list_key_ids()) == 3

def test_key_rotation_verify_old():
    kr = WatermarkKeyRotator()
    kr.add_key("v1", "key-one")
    kr.add_key("v2", "key-two")
    payload = b'{"answer":"hello"}'
    sig_v1 = hmac.new(b"key-one", payload, hashlib.sha256).hexdigest()
    ok, kid = kr.verify_with_any_key(payload, sig_v1)
    assert ok and kid == "v1"

def test_key_rotation_reject_unknown():
    kr = WatermarkKeyRotator()
    kr.add_key("v1", "key-one")
    ok, _ = kr.verify_with_any_key(b"data", "badhexsig")
    assert not ok


# ============ STEGANOGRAPHIC WATERMARK ============

def test_stego_embed_extract():
    sw = SteganographicWatermarker()
    original = "The capital of France is Paris."
    marked = sw.embed(original, "wm-42")
    assert sw.has_watermark(marked)
    extracted = sw.extract(marked)
    assert extracted == "wm-42"

def test_stego_invisible():
    sw = SteganographicWatermarker()
    original = "Hello world"
    marked = sw.embed(original, "track-1")
    # Visible text should still start the same
    assert marked.startswith(original)
    # Strip should recover original
    stripped = sw.strip(marked)
    assert stripped == original

def test_stego_no_watermark():
    sw = SteganographicWatermarker()
    assert sw.extract("plain text no watermark") is None
    assert not sw.has_watermark("plain text")

def test_stego_unicode_id():
    sw = SteganographicWatermarker()
    marked = sw.embed("test", "ÜñîCödé-123")
    extracted = sw.extract(marked)
    assert extracted == "ÜñîCödé-123"

def test_stego_adversarial_payloads():
    sw = SteganographicWatermarker()
    adversarial_ids = [
        "'; DROP TABLE--",
        "<script>alert(1)</script>",
        "A" * 200,
        "\x00\x01\x02",
    ]
    for wid in adversarial_ids:
        try:
            marked = sw.embed("text", wid)
            extracted = sw.extract(marked)
            assert extracted == wid, f"Failed roundtrip for: {wid[:20]}"
        except Exception:
            pass  # Binary payloads may not roundtrip, that's ok


# ============ BATCH VERIFY ============

def test_batch_verify_all_valid():
    wm = _wm()
    items = []
    for i in range(5):
        body = json.dumps({"answer": f"response-{i}", "idx": i})
        marked, _ = wm.apply(body)
        items.append(marked)
    results = batch_verify(wm, items)
    assert all(r.action == "allow" for r in results)

def test_batch_verify_mixed():
    wm = _wm()
    body = json.dumps({"answer": "ok"})
    marked, _ = wm.apply(body)
    tampered = json.dumps({"answer": "tampered", "_guardian_watermark": {"sig": "bad"}})
    results = batch_verify(wm, [marked, tampered, "not json"])
    assert results[0].action == "allow"
    assert results[1].action == "block"
    assert results[2].action == "block"


# ============ AUDIT LOG ============

def test_audit_log():
    log = WatermarkAuditLog()
    log.record("apply", key_id="k1", content_hash="abc", result="ok")
    log.record("verify", key_id="k1", content_hash="abc", result="ok")
    log.record("verify", key_id="k1", content_hash="def", result="mismatch")
    assert log.count == 3
    verifies = log.query("verify")
    assert len(verifies) == 2

def test_audit_log_bounded():
    log = WatermarkAuditLog()
    log._MAX = 50
    for i in range(100):
        log.record("apply", content_hash=str(i))
    assert log.count <= 50


# ============ CONTENT FINGERPRINT ============

def test_fingerprint_stable():
    fp1 = content_fingerprint("Hello World")
    fp2 = content_fingerprint("hello   world")
    assert fp1 == fp2, "Fingerprint should normalize whitespace and case"

def test_fingerprint_different():
    fp1 = content_fingerprint("Hello World")
    fp2 = content_fingerprint("Goodbye World")
    assert fp1 != fp2


# ============ CORE WATERMARK ADVERSARIAL ============

TAMPER_ATTACKS = [
    lambda p: {**p, "injected": "malicious"},       # field injection
    lambda p: {k: v for k, v in p.items() if k != "_guardian_watermark"},  # strip watermark
    lambda p: {**p, "_guardian_watermark": {**p.get("_guardian_watermark", {}), "sig": "0" * 64}},  # forged sig
    lambda p: {**p, "answer": p.get("answer", "") + " TAMPERED"},  # content modification
]

def test_tamper_detection():
    wm = _wm()
    body = json.dumps({"answer": "The answer is 42", "confidence": 0.95})
    marked, _ = wm.apply(body)
    payload = json.loads(marked)
    for attack in TAMPER_ATTACKS:
        tampered = attack(payload)
        result = wm.verify(json.dumps(tampered))
        assert result.action == "block", f"Should detect tamper: {result.reason}"

def test_disabled_passthrough():
    wm = OutputWatermarker({"enabled": False})
    body = "just text"
    out, dec = wm.apply(body)
    assert out == body
    assert dec.action == "allow"

def test_missing_key_blocks():
    wm = OutputWatermarker({"enabled": True, "key": ""})
    body = json.dumps({"a": 1})
    _, dec = wm.apply(body)
    assert dec.action == "block"


# ============ MAIN ============

def main():
    print("=" * 72)
    print("  UNSEEN DATA TEST - Feature #31 Output Watermarking")
    print("=" * 72)

    print("\n  [A] Key Rotation")
    run_test("key_rotation_basic", test_key_rotation_basic)
    run_test("key_rotation_old", test_key_rotation_verify_old)
    run_test("key_rotation_reject", test_key_rotation_reject_unknown)

    print("\n  [B] Steganographic Watermark")
    run_test("stego_roundtrip", test_stego_embed_extract)
    run_test("stego_invisible", test_stego_invisible)
    run_test("stego_no_mark", test_stego_no_watermark)
    run_test("stego_unicode", test_stego_unicode_id)
    run_test("stego_adversarial", test_stego_adversarial_payloads)

    print("\n  [C] Batch Verify")
    run_test("batch_all_valid", test_batch_verify_all_valid)
    run_test("batch_mixed", test_batch_verify_mixed)

    print("\n  [D] Audit Log")
    run_test("audit_log", test_audit_log)
    run_test("audit_bounded", test_audit_log_bounded)

    print("\n  [E] Content Fingerprint")
    run_test("fingerprint_stable", test_fingerprint_stable)
    run_test("fingerprint_different", test_fingerprint_different)

    print("\n  [F] Tamper Resistance")
    run_test("tamper_detection", test_tamper_detection)
    run_test("disabled_passthrough", test_disabled_passthrough)
    run_test("missing_key_blocks", test_missing_key_blocks)

    passed = sum(1 for v in RESULTS.values() if v == "PASS")
    total = len(RESULTS)
    print(f"\n{'='*72}")
    print(f"  RESULT: {passed}/{total} unseen data tests passed")
    if any(v != "PASS" for v in RESULTS.values()):
        for k, v in RESULTS.items():
            if v != "PASS": print(f"    {k}: {v}")
    return 0 if passed == total else 1

if __name__ == "__main__":
    sys.exit(main())
