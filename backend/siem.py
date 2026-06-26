"""SIEM alert formatting and routing helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
import queue
import json
import threading
import time
from typing import Any

import requests


DEFAULT_PLAYBOOK_MAP = {
    "injection": "PB-LLM-001",
    "injection_ai": "PB-LLM-001",
    "threat_feed_match": "PB-LLM-002",
    "obfuscation": "PB-LLM-003",
    "data_leak": "PB-DLP-001",
    "rate_limit": "PB-AVAIL-001",
    "session_revoked": "PB-IDENT-002",
    "tool_policy_block": "PB-TOOL-001",
}


@dataclass
class SiemConfig:
    enabled: bool = False
    out_path: str = "artifacts/evidence/siem_alerts.log"
    format: str = "json"  # json | cef
    vendor: str = "GuardianAI"
    product: str = "GuardianProxy"
    version: str = "1.0"
    transport: str = "file"  # file | http | both
    endpoint_url: str = ""
    endpoint_auth_header: str = "Authorization"
    endpoint_auth_token: str = ""
    request_timeout_sec: float = 2.0
    max_retries: int = 3
    retry_backoff_sec: float = 0.25
    dead_letter_path: str = "artifacts/evidence/siem_dead_letter.jsonl"


def _utc_iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def build_alert_document(
    guardian_id: str,
    event_type: str,
    severity: str,
    details: dict[str, Any],
    timestamp: float,
    playbook_map: dict[str, str] | None = None,
) -> dict[str, Any]:
    mapping = playbook_map or DEFAULT_PLAYBOOK_MAP
    normalized_event = str(event_type or "unknown").lower()
    normalized_severity = str(severity or "LOW").upper()
    return {
        "ts_utc": _utc_iso(timestamp),
        "guardian_id": guardian_id,
        "event_type": normalized_event,
        "severity": normalized_severity,
        "playbook_id": mapping.get(normalized_event, "PB-GEN-001"),
        "details": details or {},
    }


def format_json_line(alert_doc: dict[str, Any]) -> str:
    return json.dumps(alert_doc, separators=(",", ":"), sort_keys=True)


def format_cef_line(alert_doc: dict[str, Any], cfg: SiemConfig) -> str:
    # CEF:Version|Device Vendor|Device Product|Device Version|Signature ID|Name|Severity|Extension
    signature_id = alert_doc.get("playbook_id", "PB-GEN-001")
    name = str(alert_doc.get("event_type", "guardian_event")).replace("|", "_")
    sev_map = {"LOW": 3, "MEDIUM": 5, "HIGH": 8, "CRITICAL": 10}
    sev = sev_map.get(str(alert_doc.get("severity", "LOW")).upper(), 3)
    extension = (
        f"rt={alert_doc.get('ts_utc')} "
        f"suser={alert_doc.get('guardian_id')} "
        f"cs1Label=playbook cs1={signature_id} "
        f"msg={name}"
    )
    return (
        f"CEF:0|{cfg.vendor}|{cfg.product}|{cfg.version}|"
        f"{signature_id}|{name}|{sev}|{extension}"
    )


def emit_alert(alert_doc: dict[str, Any], cfg: SiemConfig) -> str:
    fmt = str(cfg.format or "json").strip().lower()
    line = format_json_line(alert_doc) if fmt == "json" else format_cef_line(alert_doc, cfg)
    out = Path(cfg.out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    return line


class SiemRouter:
    """Async SIEM dispatcher with retries and dead-letter fallback."""

    def __init__(self, cfg: SiemConfig):
        self.cfg = cfg
        self._queue: queue.Queue[dict[str, Any] | None] = queue.Queue()
        self._started = False
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    def start(self) -> None:
        with self._lock:
            if self._started:
                return
            self._started = True
            self._thread = threading.Thread(target=self._run, daemon=True, name="siem-router")
            self._thread.start()

    def stop(self, timeout_sec: float = 2.0) -> None:
        with self._lock:
            if not self._started:
                return
            self._queue.put(None)
            self._started = False
        if self._thread:
            self._thread.join(timeout=timeout_sec)

    def enqueue(self, alert_doc: dict[str, Any]) -> None:
        # File-only routing is safe to dispatch inline and keeps unit tests deterministic.
        if str(self.cfg.transport or "file").strip().lower() == "file":
            self.dispatch_once(alert_doc)
            return
        if not self._started:
            self.start()
        self._queue.put(alert_doc)

    def _run(self) -> None:
        while True:
            item = self._queue.get()
            if item is None:
                return
            self._dispatch_with_retry(item)

    def _dispatch_with_retry(self, alert_doc: dict[str, Any]) -> None:
        attempts = max(1, int(self.cfg.max_retries))
        last_err: str | None = None
        for attempt in range(1, attempts + 1):
            try:
                self.dispatch_once(alert_doc)
                return
            except Exception as exc:  # noqa: BLE001
                last_err = str(exc)
                if attempt < attempts:
                    sleep_s = float(self.cfg.retry_backoff_sec) * (2 ** (attempt - 1))
                    time.sleep(sleep_s)
        self._write_dead_letter(alert_doc, last_err or "unknown_error", attempts)

    def dispatch_once(self, alert_doc: dict[str, Any]) -> None:
        transport = str(self.cfg.transport or "file").strip().lower()
        fmt = str(self.cfg.format or "json").strip().lower()
        line = format_json_line(alert_doc) if fmt == "json" else format_cef_line(alert_doc, self.cfg)

        if transport in {"file", "both"}:
            out = Path(self.cfg.out_path)
            out.parent.mkdir(parents=True, exist_ok=True)
            with out.open("a", encoding="utf-8") as handle:
                handle.write(line + "\n")

        if transport in {"http", "both"}:
            self._send_http(alert_doc, line)

    def _send_http(self, alert_doc: dict[str, Any], line: str) -> None:
        endpoint = (self.cfg.endpoint_url or "").strip()
        if not endpoint:
            raise RuntimeError("siem_endpoint_missing")
        headers: dict[str, str] = {"Content-Type": "application/json"}
        token = (self.cfg.endpoint_auth_token or "").strip()
        if token:
            headers[str(self.cfg.endpoint_auth_header or "Authorization")] = token
        payload = {"alert": alert_doc, "line": line, "format": self.cfg.format}
        resp = requests.post(
            endpoint,
            json=payload,
            headers=headers,
            timeout=float(self.cfg.request_timeout_sec),
        )
        if resp.status_code >= 300:
            raise RuntimeError(f"siem_http_status_{resp.status_code}")

    def _write_dead_letter(self, alert_doc: dict[str, Any], error: str, attempts: int) -> None:
        out = Path(self.cfg.dead_letter_path)
        out.parent.mkdir(parents=True, exist_ok=True)
        body = {
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "attempts": attempts,
            "error": error,
            "alert": alert_doc,
        }
        with out.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(body, separators=(",", ":"), sort_keys=True) + "\n")
