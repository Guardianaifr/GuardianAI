from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class MultimodalDecision:
    action: str
    reason: str
    details: Dict[str, Any]
    severity: str = "HIGH"


class MultimodalSecurityGuard:
    """
    Validates image and audio inputs for hidden steganography or malicious content.
    NOTE: This component requires pre-extracted text from an upstream adapter (e.g. OCR or Whisper) 
    to evaluate the content. It does not natively parse binary audio or image files on its own.
    """
    def __init__(self, config: Dict[str, Any] | None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.enforcement_mode = str(cfg.get("enforcement_mode", "enforce")).lower()
        self.max_extracted_chars = int(cfg.get("max_extracted_chars", 200000))
        self.max_segments = int(cfg.get("max_segments", 256))
        self.disallowed_mime_types = set(cfg.get("disallowed_mime_types", []))
        self.detect_prompt_injection = bool(cfg.get("detect_prompt_injection", True))
        self.detect_data_exfil_intent = bool(cfg.get("detect_data_exfil_intent", True))
        self.require_text_provenance = bool(cfg.get("require_text_provenance", False))
        self.provenance_required_fields = [
            str(v) for v in (cfg.get("provenance_required_fields", ["source_id", "extractor", "extracted_at"]) or [])
        ]
        self.require_malware_scan = bool(cfg.get("require_malware_scan", False))
        self.block_on_malware_scan_error = bool(cfg.get("block_on_malware_scan_error", False))
        self._inj_re = re.compile(
            r"(?i)(ignore\s+all\s+previous\s+instructions|system\s+override|bypass\s+safety|developer\s+mode|jailbreak)"
        )
        self._exfil_re = re.compile(r"(?i)(reveal\s+secrets|dump\s+credentials|exfiltrate|leak\s+api\s+key)")

    def evaluate(self, data: Optional[Dict[str, Any]]) -> MultimodalDecision:
        if not self.enabled:
            return MultimodalDecision("allow", "disabled", {}, severity="LOW")
        if not data:
            return MultimodalDecision("allow", "no_payload", {}, severity="LOW")

        segments, mime_hits, provenance_gaps, malware_hits, malware_missing, malware_errors = self._collect_payload_signals(data)
        if mime_hits:
            return MultimodalDecision(
                "block",
                "disallowed_attachment_type",
                {"disallowed_mime_matches": sorted(mime_hits)},
            )

        if malware_hits:
            return MultimodalDecision(
                "block",
                "malware_scan_detected_threat",
                {"malware_matches": malware_hits},
            )

        if self.require_malware_scan and malware_missing:
            return MultimodalDecision(
                "block",
                "malware_scan_missing",
                {"attachment_count_without_scan": malware_missing},
            )

        if self.block_on_malware_scan_error and malware_errors:
            return MultimodalDecision(
                "block",
                "malware_scan_error",
                {"malware_scan_errors": malware_errors},
            )

        if self.require_text_provenance and provenance_gaps:
            return MultimodalDecision(
                "block",
                "text_extraction_provenance_missing",
                {"provenance_gaps": provenance_gaps[:10]},
            )

        if len(segments) > self.max_segments:
            return MultimodalDecision(
                "block",
                "multimodal_segment_limit_exceeded",
                {"segment_count": len(segments), "max_segments": self.max_segments},
            )

        total_chars = sum(len(s) for s in segments)
        if total_chars > self.max_extracted_chars:
            return MultimodalDecision(
                "block",
                "multimodal_text_budget_exceeded",
                {"total_chars": total_chars, "max_extracted_chars": self.max_extracted_chars},
            )

        if self.detect_prompt_injection:
            for idx, seg in enumerate(segments):
                if self._inj_re.search(seg):
                    return MultimodalDecision(
                        "block",
                        "multimodal_prompt_injection_detected",
                        {"segment_index": idx, "preview": seg[:120]},
                    )

        if self.detect_data_exfil_intent:
            for idx, seg in enumerate(segments):
                if self._exfil_re.search(seg):
                    return MultimodalDecision(
                        "block",
                        "multimodal_exfiltration_intent_detected",
                        {"segment_index": idx, "preview": seg[:120]},
                    )

        return MultimodalDecision(
            "allow",
            "ok",
            {"segment_count": len(segments), "total_chars": total_chars},
            severity="LOW",
        )

    def _collect_segments_and_mime(self, data: Dict[str, Any]) -> tuple[list[str], set[str]]:
        segments, mime_hits, _gaps, _hits, _missing, _errors = self._collect_payload_signals(data)
        return segments, mime_hits

    def _collect_payload_signals(
        self, data: Dict[str, Any]
    ) -> tuple[list[str], set[str], list[Dict[str, Any]], list[Dict[str, Any]], int, list[Dict[str, Any]]]:
        segments: list[str] = []
        mime_hits: set[str] = set()
        provenance_gaps: list[Dict[str, Any]] = []
        malware_hits: list[Dict[str, Any]] = []
        malware_errors: list[Dict[str, Any]] = []

        root_keys = (
            "ocr_text",
            "image_text",
            "document_text",
            "pdf_text",
            "transcript",
            "audio_transcript",
            "caption",
            "alt_text",
        )
        for key in root_keys:
            v = data.get(key)
            if isinstance(v, str):
                segments.append(v)
                if self.require_text_provenance:
                    provenance_gaps.append({"field": key, "missing": self.provenance_required_fields})

        malware_missing = self._walk(data, segments, mime_hits, provenance_gaps, malware_hits, malware_errors)
        return [s for s in segments if s], mime_hits, provenance_gaps, malware_hits, malware_missing, malware_errors

    def _walk(
        self,
        value: Any,
        segments: list[str],
        mime_hits: set[str],
        provenance_gaps: list[Dict[str, Any]],
        malware_hits: list[Dict[str, Any]],
        malware_errors: list[Dict[str, Any]],
    ) -> int:
        if value is None:
            return 0
        malware_missing = 0
        if isinstance(value, list):
            for item in value:
                malware_missing += self._walk(item, segments, mime_hits, provenance_gaps, malware_hits, malware_errors)
            return malware_missing
        if isinstance(value, dict):
            text_keys_seen: list[str] = []
            for key in ("ocr_text", "text", "content", "transcript", "caption", "document_text", "pdf_text"):
                v = value.get(key)
                if isinstance(v, str):
                    segments.append(v)
                    text_keys_seen.append(key)
            for key in ("mime_type", "content_type", "type"):
                v = value.get(key)
                if isinstance(v, str) and v in self.disallowed_mime_types:
                    mime_hits.add(v)
            if self.require_text_provenance and text_keys_seen:
                missing = [field for field in self.provenance_required_fields if not value.get(field)]
                if missing:
                    provenance_gaps.append(
                        {
                            "fields": text_keys_seen,
                            "missing": missing,
                            "source": value.get("source_id") or value.get("filename") or value.get("url"),
                        }
                    )
            has_attachment_signal = any(key in value for key in ("bytes", "content", "filename", "mime_type", "content_type"))
            if has_attachment_signal:
                malware_status = self._malware_status(value)
                if malware_status in {"infected", "malicious", "found", "positive"}:
                    malware_hits.append(
                        {
                            "source": value.get("source_id") or value.get("filename") or value.get("url"),
                            "status": malware_status,
                            "signature": value.get("malware_signature") or value.get("signature"),
                        }
                    )
                elif malware_status in {"error", "failed", "timeout"}:
                    malware_errors.append(
                        {
                            "source": value.get("source_id") or value.get("filename") or value.get("url"),
                            "status": malware_status,
                        }
                    )
                elif self.require_malware_scan and malware_status is None:
                    malware_missing += 1
            for nested in value.values():
                if isinstance(nested, (dict, list)):
                    malware_missing += self._walk(
                        nested,
                        segments,
                        mime_hits,
                        provenance_gaps,
                        malware_hits,
                        malware_errors,
                    )
        return malware_missing

    @staticmethod
    def _malware_status(value: Dict[str, Any]) -> str | None:
        if value.get("malware_detected") is True:
            return "infected"
        for key in ("malware_scan", "malware_scan_result", "clamav_result", "av_result"):
            raw = value.get(key)
            if isinstance(raw, str) and raw.strip():
                return raw.strip().lower()
            if isinstance(raw, dict):
                for status_key in ("status", "result", "verdict"):
                    status = raw.get(status_key)
                    if isinstance(status, str) and status.strip():
                        return status.strip().lower()
        return None
