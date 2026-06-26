import json

from security.output_watermark import OutputWatermarker


def test_output_watermark_apply_and_verify_round_trip():
    wm = OutputWatermarker(
        {
            "enabled": True,
            "field_name": "_guardian_watermark",
            "key_id": "test-key",
            "key": "secret-123",
            "require_json_output": True,
        }
    )
    body = json.dumps({"answer": "ok", "citations": ["https://example.org"]})
    watermarked, decision = wm.apply(body)
    assert decision.action == "allow"
    assert decision.reason == "watermark_applied"
    verify = wm.verify(watermarked)
    assert verify.action == "allow"
    assert verify.reason == "watermark_verified"


def test_output_watermark_detects_tamper():
    wm = OutputWatermarker(
        {
            "enabled": True,
            "field_name": "_guardian_watermark",
            "key_id": "test-key",
            "key": "secret-123",
            "require_json_output": True,
        }
    )
    body = json.dumps({"answer": "ok", "confidence": 0.9})
    watermarked, _ = wm.apply(body)
    payload = json.loads(watermarked)
    payload["answer"] = "tampered"
    verify = wm.verify(json.dumps(payload))
    assert verify.action == "block"
    assert verify.reason == "watermark_signature_mismatch"


def test_output_watermark_blocks_non_json_when_required():
    wm = OutputWatermarker(
        {
            "enabled": True,
            "key": "secret-123",
            "require_json_output": True,
        }
    )
    _out, decision = wm.apply("plain text")
    assert decision.action == "block"
    assert decision.reason == "watermark_json_required"
