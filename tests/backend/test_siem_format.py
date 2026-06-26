import json

from backend.siem import SiemConfig, SiemRouter, build_alert_document, emit_alert, format_cef_line


def test_build_alert_document_maps_playbook():
    alert = build_alert_document(
        guardian_id="guardian-1",
        event_type="data_leak",
        severity="critical",
        details={"reason": "pii"},
        timestamp=1.0,
    )
    assert alert["playbook_id"] == "PB-DLP-001"
    assert alert["severity"] == "CRITICAL"


def test_cef_format_includes_required_fields():
    cfg = SiemConfig(enabled=True, format="cef")
    alert = build_alert_document(
        guardian_id="guardian-1",
        event_type="injection",
        severity="high",
        details={},
        timestamp=1.0,
    )
    line = format_cef_line(alert, cfg)
    assert line.startswith("CEF:0|GuardianAI|GuardianProxy|1.0|PB-LLM-001|")
    assert "suser=guardian-1" in line


def test_emit_alert_writes_line(tmp_path):
    cfg = SiemConfig(enabled=True, out_path=str(tmp_path / "siem.log"), format="json")
    alert = build_alert_document(
        guardian_id="guardian-1",
        event_type="rate_limit",
        severity="high",
        details={"path": "rate_limit"},
        timestamp=2.0,
    )
    emit_alert(alert, cfg)
    content = (tmp_path / "siem.log").read_text(encoding="utf-8").strip()
    assert "PB-AVAIL-001" in content


def test_siem_router_http_retries_then_dead_letter(tmp_path, monkeypatch):
    cfg = SiemConfig(
        enabled=True,
        transport="http",
        endpoint_url="https://siem.example/ingest",
        request_timeout_sec=0.2,
        max_retries=2,
        retry_backoff_sec=0.01,
        dead_letter_path=str(tmp_path / "dead_letter.jsonl"),
    )
    alert = build_alert_document(
        guardian_id="guardian-1",
        event_type="injection",
        severity="high",
        details={"reason": "pii"},
        timestamp=1.0,
    )

    calls = {"count": 0}

    def _fail_post(*_args, **_kwargs):
        calls["count"] += 1
        raise RuntimeError("network_down")

    monkeypatch.setattr("backend.siem.requests.post", _fail_post)

    router = SiemRouter(cfg)
    router._dispatch_with_retry(alert)

    assert calls["count"] == 2
    dlq = (tmp_path / "dead_letter.jsonl").read_text(encoding="utf-8").strip()
    assert dlq
    body = json.loads(dlq)
    assert body["attempts"] == 2
    assert body["alert"]["event_type"] == "injection"


def test_siem_router_both_mode_writes_file_and_http(tmp_path, monkeypatch):
    cfg = SiemConfig(
        enabled=True,
        transport="both",
        out_path=str(tmp_path / "siem.log"),
        endpoint_url="https://siem.example/ingest",
        endpoint_auth_token="Bearer token",
        request_timeout_sec=0.5,
        max_retries=1,
    )
    alert = build_alert_document(
        guardian_id="guardian-1",
        event_type="threat_feed_match",
        severity="high",
        details={"reason": "feed_match"},
        timestamp=1.0,
    )

    sent = {}

    class _Resp:
        status_code = 200

    def _ok_post(url, json=None, headers=None, timeout=None):
        sent["url"] = url
        sent["json"] = json
        sent["headers"] = headers
        sent["timeout"] = timeout
        return _Resp()

    monkeypatch.setattr("backend.siem.requests.post", _ok_post)

    router = SiemRouter(cfg)
    router.dispatch_once(alert)

    content = (tmp_path / "siem.log").read_text(encoding="utf-8").strip()
    assert "PB-LLM-002" in content
    assert sent["url"] == "https://siem.example/ingest"
    assert sent["headers"]["Authorization"] == "Bearer token"
