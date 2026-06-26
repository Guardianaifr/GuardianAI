from security.multimodal_guard import MultimodalSecurityGuard


def test_multimodal_guard_blocks_malware_scan_hit():
    guard = MultimodalSecurityGuard({"enabled": True})

    decision = guard.evaluate(
        {
            "attachments": [
                {
                    "filename": "invoice.pdf",
                    "content": "base64-data",
                    "malware_scan_result": {"status": "infected", "signature": "Eicar-Test-Signature"},
                }
            ]
        }
    )

    assert decision.action == "block"
    assert decision.reason == "malware_scan_detected_threat"


def test_multimodal_guard_blocks_missing_ocr_provenance_when_required():
    guard = MultimodalSecurityGuard(
        {
            "enabled": True,
            "require_text_provenance": True,
            "provenance_required_fields": ["source_id", "extractor", "extracted_at"],
        }
    )

    decision = guard.evaluate(
        {
            "images": [
                {
                    "ocr_text": "Quarterly chart says revenue is up.",
                    "source_id": "image-1",
                    "extractor": "tesseract",
                }
            ]
        }
    )

    assert decision.action == "block"
    assert decision.reason == "text_extraction_provenance_missing"


def test_multimodal_guard_allows_scanned_attachment_with_provenance():
    guard = MultimodalSecurityGuard(
        {
            "enabled": True,
            "require_text_provenance": True,
            "require_malware_scan": True,
        }
    )

    decision = guard.evaluate(
        {
            "attachments": [
                {
                    "filename": "report.pdf",
                    "content": "safe extracted text",
                    "source_id": "doc-1",
                    "extractor": "pdfminer",
                    "extracted_at": "2026-03-18T00:00:00Z",
                    "malware_scan_result": "clean",
                }
            ]
        }
    )

    assert decision.action == "allow"
    assert decision.reason == "ok"
