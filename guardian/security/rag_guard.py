from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Dict, Optional


@dataclass
class RAGDecision:
    action: str
    reason: str
    details: Dict[str, Any]
    severity: str = "HIGH"


class RAGSecurityGuard:
    def __init__(self, config: Dict[str, Any] | None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", True))
        self.enforcement_mode = str(cfg.get("enforcement_mode", "enforce")).lower()
        self.max_context_chars = int(cfg.get("max_context_chars", 50000))
        self.max_chunks = int(cfg.get("max_chunks", 64))
        self.detect_embedding_dump = bool(cfg.get("detect_embedding_dump", True))
        self.detect_indirect_prompt_injection = bool(cfg.get("detect_indirect_prompt_injection", True))
        self.max_single_chunk_chars = int(cfg.get("max_single_chunk_chars", 10000))
        self.enforce_trust_scoring = bool(cfg.get("enforce_trust_scoring", True))
        self.min_average_trust_score = float(cfg.get("min_average_trust_score", 0.55))
        self.min_chunk_trust_score = float(cfg.get("min_chunk_trust_score", 0.35))
        self.default_trust_score = float(cfg.get("default_trust_score", 0.70))
        self.detect_cross_source_contamination = bool(cfg.get("detect_cross_source_contamination", False))
        self.trusted_source_patterns = [
            re.compile(str(p), re.IGNORECASE) for p in (cfg.get("trusted_source_patterns", []) or [])
        ]
        self.untrusted_source_patterns = [
            re.compile(str(p), re.IGNORECASE) for p in (cfg.get("untrusted_source_patterns", []) or [])
        ]
        self._inj_re = re.compile(
            r"(?i)(?:\b(ignore|disregard|forget|bypass|reveal|drop)\s+(?:all\s+)?(?:previous\s+|prior\s+|above\s+|earlier\s+|the\s+|your\s+|everything\s+(?:above\s+)?)?(instructions|context|directives|rules|safety|secrets|database)\b|"
            r"\b(ignore|disregard|forget)\s+(?:all\s+)?(?:previous|prior|everything\s+above)\b|"
            r"\b(?:system\s+)?override(?:\s+(?:your\s+)?(?:instructions|context|directives|rules|safety))?\b)"
        )
        self._emb_re = re.compile(r"(?i)(embedding|vector)\s*[:=]\s*\[[^\]]{200,}\]")

    def evaluate(self, data: Optional[Dict[str, Any]]) -> RAGDecision:
        if not self.enabled:
            return RAGDecision("allow", "disabled", {}, severity="LOW")
        if not data:
            return RAGDecision("allow", "no_payload", {}, severity="LOW")

        records = self._collect_chunk_records(data)
        chunks = [record["content"] for record in records]
        if len(chunks) > self.max_chunks:
            return RAGDecision(
                "block",
                "context_chunk_count_exceeded",
                {"chunk_count": len(chunks), "max_chunks": self.max_chunks},
            )

        total_chars = sum(len(chunk) for chunk in chunks)
        if total_chars > self.max_context_chars:
            return RAGDecision(
                "block",
                "context_window_stuffing",
                {"total_chars": total_chars, "max_context_chars": self.max_context_chars},
            )

        oversized = [len(chunk) for chunk in chunks if len(chunk) > self.max_single_chunk_chars]
        if oversized:
            return RAGDecision(
                "block",
                "oversized_retrieval_chunk",
                {"max_single_chunk_chars": self.max_single_chunk_chars, "observed": max(oversized)},
            )

        if self.detect_indirect_prompt_injection:
            for idx, chunk in enumerate(chunks):
                if self._inj_re.search(chunk):
                    return RAGDecision(
                        "block",
                        "indirect_prompt_injection_in_retrieval",
                        {"chunk_index": idx, "preview": chunk[:120]},
                    )

        if self.detect_embedding_dump:
            for idx, chunk in enumerate(chunks):
                if self._emb_re.search(chunk):
                    return RAGDecision(
                        "block",
                        "embedding_dump_detected",
                        {"chunk_index": idx, "preview": chunk[:120]},
                    )

        if self.enforce_trust_scoring and records:
            scores = [self._trust_score(record) for record in records]
            low_score = min(scores)
            avg_score = sum(scores) / len(scores)
            if low_score < self.min_chunk_trust_score:
                idx = scores.index(low_score)
                return RAGDecision(
                    "block",
                    "retrieval_source_trust_below_threshold",
                    {
                        "chunk_index": idx,
                        "trust_score": low_score,
                        "min_chunk_trust_score": self.min_chunk_trust_score,
                        "source": records[idx].get("source"),
                    },
                )
            if avg_score < self.min_average_trust_score:
                return RAGDecision(
                    "block",
                    "retrieval_average_trust_below_threshold",
                    {
                        "average_trust_score": round(avg_score, 3),
                        "min_average_trust_score": self.min_average_trust_score,
                        "chunk_count": len(records),
                    },
                )

        if self.detect_cross_source_contamination:
            contamination = self._find_cross_source_contamination(records)
            if contamination:
                return RAGDecision("block", "cross_source_contamination_detected", contamination)

        return RAGDecision("allow", "ok", {"chunk_count": len(chunks), "total_chars": total_chars}, severity="LOW")

    def _collect_chunks(self, data: Dict[str, Any]) -> list[str]:
        return [record["content"] for record in self._collect_chunk_records(data)]

    def _collect_chunk_records(self, data: Dict[str, Any]) -> list[Dict[str, Any]]:
        records: list[Dict[str, Any]] = []
        direct_keys = ("context", "retrieved_context", "knowledge", "documents", "chunks", "retrieval_results")
        for key in direct_keys:
            if key not in data:
                continue
            self._collect_records_from_value(data.get(key), records)
        return [record for record in records if record.get("content")]

    def _collect_from_value(self, value: Any, out: list[str]) -> None:
        records: list[Dict[str, Any]] = []
        self._collect_records_from_value(value, records)
        out.extend(record["content"] for record in records if record.get("content"))

    def _collect_records_from_value(self, value: Any, out: list[Dict[str, Any]]) -> None:
        if value is None:
            return
        if isinstance(value, str):
            out.append({"content": value, "source": None, "metadata": {}})
            return
        if isinstance(value, dict):
            content_values: list[str] = []
            for k in ("content", "text", "chunk", "body", "snippet"):
                v = value.get(k)
                if isinstance(v, str):
                    content_values.append(v)
            if content_values:
                metadata = {k: v for k, v in value.items() if not isinstance(v, (dict, list))}
                source = self._source_from_metadata(value)
                for content in content_values:
                    out.append({"content": content, "source": source, "metadata": metadata})
            for nested in value.values():
                if isinstance(nested, (list, dict)):
                    self._collect_records_from_value(nested, out)
            return
        if isinstance(value, list):
            for item in value:
                self._collect_records_from_value(item, out)

    def _source_from_metadata(self, value: Dict[str, Any]) -> str | None:
        for key in ("source", "source_id", "url", "uri", "domain", "document_id"):
            raw = value.get(key)
            if isinstance(raw, str) and raw.strip():
                return raw.strip()
        metadata = value.get("metadata")
        if isinstance(metadata, dict):
            return self._source_from_metadata(metadata)
        return None

    def _trust_score(self, record: Dict[str, Any]) -> float:
        metadata = record.get("metadata") or {}
        for key in ("trust_score", "source_trust", "reputation", "confidence"):
            score = self._to_float(metadata.get(key))
            if score is not None:
                return max(0.0, min(1.0, score))
        source = str(record.get("source") or "")
        if source and any(pattern.search(source) for pattern in self.trusted_source_patterns):
            return 1.0
        if source and any(pattern.search(source) for pattern in self.untrusted_source_patterns):
            return 0.2
        return max(0.0, min(1.0, self.default_trust_score))

    def _find_cross_source_contamination(self, records: list[Dict[str, Any]]) -> Dict[str, Any] | None:
        by_claim: Dict[str, list[Dict[str, Any]]] = {}
        for record in records:
            metadata = record.get("metadata") or {}
            claim_id = metadata.get("claim_id") or metadata.get("fact_id") or metadata.get("entity_id")
            if isinstance(claim_id, str) and claim_id.strip():
                by_claim.setdefault(claim_id.strip(), []).append(record)

        for claim_id, claim_records in by_claim.items():
            sources = {str(record.get("source") or "unknown") for record in claim_records}
            normalized_contents = {self._normalize_claim(record.get("content", "")) for record in claim_records}
            scores = [self._trust_score(record) for record in claim_records]
            if len(sources) > 1 and len(normalized_contents) > 1 and min(scores) < self.default_trust_score:
                return {
                    "claim_id": claim_id,
                    "sources": sorted(sources),
                    "trust_scores": [round(score, 3) for score in scores],
                }
            for idx, record in enumerate(claim_records):
                if self._trust_score(record) < self.default_trust_score and self._inj_re.search(record.get("content", "")):
                    return {
                        "claim_id": claim_id,
                        "chunk_index": idx,
                        "source": record.get("source"),
                        "preview": record.get("content", "")[:120],
                    }
        return None

    @staticmethod
    def _normalize_claim(value: str) -> str:
        return re.sub(r"\s+", " ", value.strip().lower())

    @staticmethod
    def _to_float(value: Any) -> float | None:
        if isinstance(value, (int, float)):
            return float(value)
        if isinstance(value, str):
            try:
                return float(value.strip())
            except ValueError:
                return None
        return None
