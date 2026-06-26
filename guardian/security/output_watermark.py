"""Output watermarking and verification helpers."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import copy
import hashlib
import hmac
import json
from typing import Any, Optional


@dataclass
class WatermarkDecision:
    action: str
    reason: str
    details: dict[str, Any]
    severity: str = "MEDIUM"


class OutputWatermarker:
    def __init__(self, config: Optional[dict[str, Any]] = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.enforcement_mode = str(cfg.get("enforcement_mode", "enforce")).lower()
        self.field_name = str(cfg.get("field_name", "_guardian_watermark"))
        self.algorithm = "HMAC-SHA256"
        self.key_id = str(cfg.get("key_id", "local-dev"))
        self.key = str(cfg.get("key", "")).encode("utf-8")
        self.require_json_output = bool(cfg.get("require_json_output", True))

    def can_apply(self) -> bool:
        return self.enabled

    def apply(self, raw_content: str) -> tuple[str, WatermarkDecision]:
        if not self.enabled:
            return raw_content, WatermarkDecision("allow", "disabled", {}, severity="LOW")
        if not self.key:
            return raw_content, WatermarkDecision("block", "missing_watermark_key", {})

        try:
            payload = json.loads(raw_content)
        except json.JSONDecodeError:
            if self.require_json_output:
                return raw_content, WatermarkDecision("block", "watermark_json_required", {})
            return raw_content, WatermarkDecision("allow", "non_json_skipped", {}, severity="LOW")

        if not isinstance(payload, dict):
            if self.require_json_output:
                return raw_content, WatermarkDecision("block", "watermark_dict_json_required", {})
            return raw_content, WatermarkDecision("allow", "non_dict_json_skipped", {}, severity="LOW")

        payload_without_mark = self._strip_watermark(payload)
        sig = self._sign_payload(payload_without_mark)
        watermark = {
            "alg": self.algorithm,
            "key_id": self.key_id,
            "ts_utc": datetime.now(timezone.utc).isoformat(),
            "sig": sig,
        }
        payload_with_mark = copy.deepcopy(payload_without_mark)
        payload_with_mark[self.field_name] = watermark
        return (
            json.dumps(payload_with_mark, separators=(",", ":"), sort_keys=True),
            WatermarkDecision("allow", "watermark_applied", {"field": self.field_name}, severity="LOW"),
        )

    def verify(self, raw_content: str) -> WatermarkDecision:
        if not self.key:
            return WatermarkDecision("block", "missing_watermark_key", {})
        try:
            payload = json.loads(raw_content)
        except json.JSONDecodeError:
            return WatermarkDecision("block", "invalid_json", {})
        if not isinstance(payload, dict):
            return WatermarkDecision("block", "invalid_json_structure", {})
        mark = payload.get(self.field_name)
        if not isinstance(mark, dict):
            return WatermarkDecision("block", "watermark_missing", {})
        sig = str(mark.get("sig", ""))
        if not sig:
            return WatermarkDecision("block", "watermark_signature_missing", {})

        payload_without_mark = self._strip_watermark(payload)
        expected = self._sign_payload(payload_without_mark)
        if not hmac.compare_digest(sig, expected):
            return WatermarkDecision("block", "watermark_signature_mismatch", {})
        return WatermarkDecision("allow", "watermark_verified", {"field": self.field_name}, severity="LOW")

    def _sign_payload(self, payload: dict[str, Any]) -> str:
        canonical = json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8")
        digest = hmac.new(self.key, canonical, hashlib.sha256).hexdigest()
        return digest

    def _strip_watermark(self, payload: dict[str, Any]) -> dict[str, Any]:
        out = copy.deepcopy(payload)
        out.pop(self.field_name, None)
        return out


# ═══════════════════════════════════════════════════════════════════════════
# 2026-Standard Advanced Watermark Capabilities
# ═══════════════════════════════════════════════════════════════════════════

class WatermarkKeyRotator:
    """Manage versioned signing keys with rotation support."""

    def __init__(self):
        self._keys: dict[str, bytes] = {}  # key_id -> key_bytes
        self._active_id: str = ""

    def add_key(self, key_id: str, key: str | bytes, make_active: bool = False):
        self._keys[key_id] = key.encode("utf-8") if isinstance(key, str) else key
        if make_active or not self._active_id:
            self._active_id = key_id

    def rotate(self, new_key_id: str, new_key: str | bytes):
        self.add_key(new_key_id, new_key, make_active=True)

    @property
    def active_key_id(self) -> str:
        return self._active_id

    @property
    def active_key(self) -> bytes:
        return self._keys.get(self._active_id, b"")

    def get_key(self, key_id: str) -> bytes | None:
        return self._keys.get(key_id)

    def list_key_ids(self) -> list[str]:
        return list(self._keys.keys())

    def verify_with_any_key(self, payload_canonical: bytes, signature: str) -> tuple[bool, str]:
        """Try all keys to verify a signature (supports old keys during rotation)."""
        for kid, key_bytes in self._keys.items():
            expected = hmac.new(key_bytes, payload_canonical, hashlib.sha256).hexdigest()
            if hmac.compare_digest(signature, expected):
                return True, kid
        return False, ""


class SteganographicWatermarker:
    """Embed invisible watermarks in text using zero-width characters."""

    _ZWC = {
        "0": "\u200b",  # zero-width space
        "1": "\u200c",  # zero-width non-joiner
    }
    _MARKER_START = "\u200d"  # zero-width joiner marks boundary
    _MARKER_END = "\ufeff"   # BOM as end marker

    def embed(self, text: str, watermark_id: str) -> str:
        binary = "".join(format(b, "08b") for b in watermark_id.encode("utf-8"))
        encoded = "".join(self._ZWC.get(bit, "") for bit in binary)
        return text + self._MARKER_START + encoded + self._MARKER_END

    def extract(self, text: str) -> str | None:
        start = text.find(self._MARKER_START)
        end = text.find(self._MARKER_END, start + 1 if start >= 0 else 0)
        if start < 0 or end < 0:
            return None
        encoded = text[start + 1:end]
        bits = ""
        for ch in encoded:
            if ch == self._ZWC["0"]:
                bits += "0"
            elif ch == self._ZWC["1"]:
                bits += "1"
        if len(bits) % 8 != 0:
            return None
        try:
            raw = bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
            return raw.decode("utf-8")
        except Exception:
            return None

    def strip(self, text: str) -> str:
        start = text.find(self._MARKER_START)
        if start < 0:
            return text
        end = text.find(self._MARKER_END, start)
        if end < 0:
            return text[:start]
        return text[:start] + text[end + 1:]

    def has_watermark(self, text: str) -> bool:
        return self._MARKER_START in text and self._MARKER_END in text


class WatermarkAuditLog:
    """Bounded audit log for watermark operations."""
    _MAX = 1000

    def __init__(self):
        self._log: list[dict] = []

    def record(self, action: str, key_id: str = "", content_hash: str = "", result: str = ""):
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "action": action,
            "key_id": key_id,
            "content_hash": content_hash,
            "result": result,
        }
        self._log.append(entry)
        if len(self._log) > self._MAX:
            self._log = self._log[-self._MAX:]

    def query(self, action: str = "", limit: int = 50) -> list[dict]:
        out = self._log if not action else [e for e in self._log if e["action"] == action]
        return out[-limit:]

    @property
    def count(self) -> int:
        return len(self._log)

    def clear(self):
        self._log.clear()


def content_fingerprint(content: str) -> str:
    """Generate a stable fingerprint for content deduplication."""
    normalized = " ".join(content.lower().split())
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()[:32]


def batch_verify(watermarker: OutputWatermarker, items: list[str]) -> list[WatermarkDecision]:
    """Verify a batch of watermarked outputs."""
    return [watermarker.verify(item) for item in items]
