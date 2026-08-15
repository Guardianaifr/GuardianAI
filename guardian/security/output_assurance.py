from __future__ import annotations

from dataclasses import dataclass
import re
from typing import Any, Dict, Optional


@dataclass
class OutputAssuranceDecision:
    action: str
    reason: str
    details: Dict[str, Any]
    severity: str = "HIGH"


class OutputAssuranceGuard:
    def __init__(self, config: Dict[str, Any] | None = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.enforcement_mode = str(cfg.get("enforcement_mode", "enforce")).lower()
        self.require_json_output = bool(cfg.get("require_json_output", False))
        self.required_json_fields = [str(v) for v in (cfg.get("required_json_fields", []) or [])]
        self.require_citations = bool(cfg.get("require_citations", False))
        self.min_citations = int(cfg.get("min_citations", 1))
        self.citations_field = str(cfg.get("citations_field", "citations"))
        self.alternate_citations_field = str(cfg.get("alternate_citations_field", "sources"))
        self.min_confidence = float(cfg.get("min_confidence", 0.0))
        self.block_on_low_confidence = bool(cfg.get("block_on_low_confidence", False))
        self.confidence_field = str(cfg.get("confidence_field", "confidence"))
        self.citation_url_regex = re.compile(str(cfg.get("citation_url_regex", r"^https?://.+")), re.IGNORECASE)
        self.high_stakes_abstain_enabled = bool(cfg.get("high_stakes_abstain_enabled", False))
        self.high_stakes_domains = {
            str(v).strip().lower() for v in (cfg.get("high_stakes_domains", ["medical", "legal", "financial"]) or [])
        }
        self.domain_field = str(cfg.get("domain_field", "domain"))
        self.citation_quality_field = str(cfg.get("citation_quality_field", "citation_quality"))
        self.min_citation_quality = float(cfg.get("min_citation_quality", 0.70))
        self.citation_conflict_field = str(cfg.get("citation_conflict_field", "citation_conflict"))
        self.abstain_field = str(cfg.get("abstain_field", "abstain"))
        self.abstain_reason_field = str(cfg.get("abstain_reason_field", "abstain_reason"))
        self._high_stakes_text_re = re.compile(
            r"(?i)\b(medical|diagnosis|treatment|prescription|legal|lawsuit|contract|financial|investment|tax|loan|insurance)\b"
        )
        # Refusal/declination language patterns used to validate abstain claims.
        # A broader set than the original 5 markers — covers all natural-language forms
        # a well-behaved model uses to decline answering in high-stakes domains.
        self._REFUSAL_RE = re.compile(
            r"(?i)\b("
            r"i cannot|i can'?t|i am unable|i'm unable|i am not able|i'm not able"
            r"|cannot (provide|assist|help|answer|give|offer|share|advise|recommend|support|disclose)"
            r"|unable to (provide|assist|help|answer|give|offer|share|advise|recommend|support|determine|verify|confirm)"
            r"|not (able|in a position) to (provide|assist|help|answer|give|offer|advise|recommend|support)"
            r"|i (don'?t|do not) (have|know|possess) (enough|sufficient|reliable|the)"
            r"|insufficient (evidence|information|data|sources|context)"
            r"|not enough (reliable|sufficient|credible|current)"
            r"|beyond (my|the) (capabilities|scope|knowledge|training)"
            r"|outside (my|the) (capabilities|scope|expertise|knowledge)"
            r"|i (must|should|need to) (decline|refuse|abstain|withhold)"
            r"|i (am declining|am refusing|decline to|refuse to)"
            r"|i'?m not (going to|able to|in a position to)"
            r"|i would (not|advise against|recommend against)"
            r"|this (is|falls) (outside|beyond)"
            r"|ethically (i cannot|i can'?t|unable)"
            r")",
            re.IGNORECASE,
        )

    def evaluate(self, parsed_json: Optional[Dict[str, Any]]) -> OutputAssuranceDecision:
        if not self.enabled:
            return OutputAssuranceDecision("allow", "disabled", {}, severity="LOW")

        if self.require_json_output and not parsed_json:
            return OutputAssuranceDecision("block", "json_output_required", {})

        if not parsed_json:
            return OutputAssuranceDecision("allow", "no_json_to_validate", {}, severity="LOW")

        missing = [field for field in self.required_json_fields if field not in parsed_json]
        if missing:
            return OutputAssuranceDecision("block", "required_fields_missing", {"missing_fields": missing})

        if self.require_citations:
            citations = parsed_json.get(self.citations_field)
            if citations is None:
                citations = parsed_json.get(self.alternate_citations_field)
            normalized = self._normalize_citations(citations)
            valid = [c for c in normalized if self.citation_url_regex.search(c)]
            if len(valid) < self.min_citations:
                return OutputAssuranceDecision(
                    "block",
                    "insufficient_citations",
                    {"required": self.min_citations, "found": len(valid)},
                )

        if self.block_on_low_confidence:
            raw_conf = parsed_json.get(self.confidence_field)
            conf = self._to_float(raw_conf)
            if conf is None:
                return OutputAssuranceDecision("block", "confidence_missing", {"field": self.confidence_field})
            if conf < self.min_confidence:
                return OutputAssuranceDecision(
                    "block",
                    "confidence_below_threshold",
                    {"min_confidence": self.min_confidence, "actual_confidence": conf},
                )

        if self.high_stakes_abstain_enabled and self._is_high_stakes(parsed_json):
            conflict = self._citation_confidence_conflict(parsed_json)
            if conflict and not self._is_abstain_payload(parsed_json):
                return OutputAssuranceDecision(
                    "block",
                    "high_stakes_confidence_citation_conflict",
                    conflict,
                )

        return OutputAssuranceDecision("allow", "ok", {}, severity="LOW")

    @staticmethod
    def _to_float(value: Any) -> float | None:
        if value is None:
            return None
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError:
                return None
        return None

    @staticmethod
    def _normalize_citations(value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value]
        if isinstance(value, list):
            out: list[str] = []
            for item in value:
                if isinstance(item, str):
                    out.append(item)
                elif isinstance(item, dict):
                    for key in ("url", "source", "link"):
                        if isinstance(item.get(key), str):
                            out.append(str(item.get(key)))
            return out
        return []

    def _is_high_stakes(self, parsed_json: Dict[str, Any]) -> bool:
        raw_domain = parsed_json.get(self.domain_field) or parsed_json.get("category") or parsed_json.get("domain")
        domains: list[str] = []
        if isinstance(raw_domain, str):
            domains.append(raw_domain)
        elif isinstance(raw_domain, list):
            domains.extend(str(v) for v in raw_domain)
        if any(domain.strip().lower() in self.high_stakes_domains for domain in domains):
            return True
        answer = parsed_json.get("answer") or parsed_json.get("content") or parsed_json.get("response")
        return isinstance(answer, str) and bool(self._high_stakes_text_re.search(answer))

    def _citation_confidence_conflict(self, parsed_json: Dict[str, Any]) -> Dict[str, Any] | None:
        conf = self._to_float(parsed_json.get(self.confidence_field))
        citation_quality = self._to_float(parsed_json.get(self.citation_quality_field))
        explicit_conflict = bool(parsed_json.get(self.citation_conflict_field))
        citations = parsed_json.get(self.citations_field)
        if citations is None:
            citations = parsed_json.get(self.alternate_citations_field)
        normalized = self._normalize_citations(citations)
        valid = [c for c in normalized if self.citation_url_regex.search(c)]

        reasons: list[str] = []
        if explicit_conflict:
            reasons.append("explicit_citation_conflict")
        if citation_quality is not None and citation_quality < self.min_citation_quality:
            reasons.append("citation_quality_below_threshold")
        if self.require_citations and len(valid) < self.min_citations:
            reasons.append("citation_count_below_threshold")

        high_confidence = conf is not None and conf >= self.min_confidence
        if high_confidence and reasons:
            return {
                "confidence": conf,
                "min_confidence": self.min_confidence,
                "citation_quality": citation_quality,
                "min_citation_quality": self.min_citation_quality,
                "valid_citations": len(valid),
                "required_citations": self.min_citations,
                "conflict_reasons": reasons,
            }
        return None

    def _is_abstain_payload(self, parsed_json: Dict[str, Any]) -> bool:
        """Return True only when the payload represents a *genuine* abstention.

        A genuine abstention requires that the answer content is consistent with
        refusing/declining — either:
          (a) the answer field is empty or near-empty (< 20 printable chars), OR
          (b) the answer text matches recognised refusal-language patterns.

        The ``abstain`` boolean flag and ``abstain_reason`` string are treated as
        *hints*, not as authoritative truth.  They are checked first to avoid
        spending regex time on payloads that clearly never intended to abstain,
        but a positive flag/reason ALONE is not sufficient — the answer content
        is always validated when the flag is present.

        This prevents the EVASION_FAKE_ABSTAIN attack where a jailbroken model
        (or adversarially crafted tool response) sets ``abstain=True`` alongside
        a clearly harmful answer in order to bypass the
        ``high_stakes_confidence_citation_conflict`` check.
        """
        flag_set = parsed_json.get(self.abstain_field) is True
        reason_set = isinstance(parsed_json.get(self.abstain_reason_field), str) and bool(
            str(parsed_json.get(self.abstain_reason_field)).strip()
        )

        answer = (
            parsed_json.get("answer")
            or parsed_json.get("content")
            or parsed_json.get("response")
        )

        # No flag, no reason hint — fall back purely to answer-text refusal detection.
        if not flag_set and not reason_set:
            if not isinstance(answer, str):
                return False
            return bool(self._REFUSAL_RE.search(answer))

        # Flag or reason is set — still must validate the answer content.
        # If the answer is absent or trivially short, that is consistent with abstention.
        if not isinstance(answer, str) or len(answer.strip()) < 20:
            return True

        # Answer has substantive length — require it to actually sound like a refusal.
        # If the answer contains non-refusal content, the abstain claim is REJECTED
        # and the high-stakes check will proceed (and likely block).
        return bool(self._REFUSAL_RE.search(answer))
