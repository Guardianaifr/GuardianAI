from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
from pathlib import Path
import threading
import time
from typing import Any, Dict


@dataclass
class FeedbackEntry:
    tenant_id: str
    prompt_sha256: str
    event_family: str
    status: str
    expires_at: float
    created_at: float
    notes: str = ""


class FeedbackLoopManager:
    def __init__(self, config: Dict[str, Any] | None, root_dir: Path):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.allowlist_file = (root_dir / str(cfg.get("allowlist_file", "artifacts/evidence/fp_allowlist.jsonl"))).resolve()
        self.default_ttl_seconds = int(cfg.get("default_ttl_seconds", 7 * 24 * 60 * 60))
        self.max_entries = int(cfg.get("max_entries", 5000))
        self._cache: Dict[str, FeedbackEntry] = {}
        self._lock = threading.Lock()
        self._loaded = False

    @staticmethod
    def hash_prompt(prompt: str) -> str:
        return hashlib.sha256((prompt or "").encode("utf-8")).hexdigest()

    def is_allowlisted(self, tenant_id: str, prompt: str, event_family: str, now: float | None = None) -> bool:
        if not self.enabled:
            return False
        self._ensure_loaded()
        now_ts = now if now is not None else time.time()
        key = self._key(tenant_id, self.hash_prompt(prompt), event_family)
        entry = self._cache.get(key)
        if not entry:
            return False
        if entry.status != "approved":
            return False
        if entry.expires_at and entry.expires_at < now_ts:
            return False
        return True

    def add_approved_entry(
        self,
        tenant_id: str,
        prompt: str,
        event_family: str,
        notes: str = "",
        ttl_seconds: int | None = None,
    ) -> FeedbackEntry:
        now_ts = time.time()
        ttl = int(ttl_seconds) if ttl_seconds is not None else self.default_ttl_seconds
        entry = FeedbackEntry(
            tenant_id=tenant_id,
            prompt_sha256=self.hash_prompt(prompt),
            event_family=event_family,
            status="approved",
            expires_at=now_ts + max(0, ttl),
            created_at=now_ts,
            notes=notes,
        )
        self._write_entry(entry)
        with self._lock:
            self._cache[self._key(entry.tenant_id, entry.prompt_sha256, entry.event_family)] = entry
            self._trim_cache()
        return entry

    def _ensure_loaded(self) -> None:
        if self._loaded:
            return
        with self._lock:
            if self._loaded:
                return
            if self.allowlist_file.exists():
                for line in self.allowlist_file.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    try:
                        raw = json.loads(line)
                    except Exception:
                        continue
                    entry = FeedbackEntry(
                        tenant_id=str(raw.get("tenant_id", "default")),
                        prompt_sha256=str(raw.get("prompt_sha256", "")),
                        event_family=str(raw.get("event_family", "injection")),
                        status=str(raw.get("status", "approved")),
                        expires_at=float(raw.get("expires_at", 0)),
                        created_at=float(raw.get("created_at", 0)),
                        notes=str(raw.get("notes", "")),
                    )
                    self._cache[self._key(entry.tenant_id, entry.prompt_sha256, entry.event_family)] = entry
            self._trim_cache()
            self._loaded = True

    def _write_entry(self, entry: FeedbackEntry) -> None:
        self.allowlist_file.parent.mkdir(parents=True, exist_ok=True)
        body = {
            "tenant_id": entry.tenant_id,
            "prompt_sha256": entry.prompt_sha256,
            "event_family": entry.event_family,
            "status": entry.status,
            "expires_at": entry.expires_at,
            "created_at": entry.created_at,
            "notes": entry.notes,
        }
        with self.allowlist_file.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(body, separators=(",", ":"), sort_keys=True) + "\n")

    def _trim_cache(self) -> None:
        if len(self._cache) <= self.max_entries:
            return
        ordered = sorted(self._cache.values(), key=lambda v: v.created_at, reverse=True)
        self._cache = {
            self._key(entry.tenant_id, entry.prompt_sha256, entry.event_family): entry
            for entry in ordered[: self.max_entries]
        }

    @staticmethod
    def _key(tenant_id: str, prompt_sha256: str, event_family: str) -> str:
        return f"{tenant_id}|{event_family}|{prompt_sha256}"
