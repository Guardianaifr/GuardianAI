"""Tenant isolation helpers for session, telemetry, and evidence segregation."""

from __future__ import annotations

import json
from pathlib import Path
import re
import threading
import time
from typing import Any


class TenantIsolationManager:
    def __init__(self, config: dict[str, Any] | None, base_dir: Path):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.require_tenant_header = bool(cfg.get("require_tenant_header", False))
        self.tenant_header = str(cfg.get("tenant_header", "X-Guardian-Tenant"))
        self.default_tenant_id = str(cfg.get("default_tenant_id", "default"))
        self.enforce_tenant_scope_on_session = bool(cfg.get("enforce_tenant_scope_on_session", True))
        pattern = str(cfg.get("allowed_tenant_pattern", r"^[a-z0-9][a-z0-9_-]{1,63}$"))
        self.allowed_pattern = re.compile(pattern)
        evidence_dir = str(cfg.get("tenant_evidence_dir", "artifacts/evidence/tenants"))
        self.evidence_dir = self._resolve(base_dir, evidence_dir)
        self.max_tenant_locks = int(cfg.get("max_tenant_locks", 1000))
        self._tenant_locks: dict[str, threading.Lock] = {}
        self._meta_lock = threading.Lock()
        self._overflow_lock = threading.Lock()

    def _get_tenant_lock(self, tenant_id: str) -> threading.Lock:
        with self._meta_lock:
            if tenant_id in self._tenant_locks:
                return self._tenant_locks[tenant_id]
            if len(self._tenant_locks) < self.max_tenant_locks:
                lock = threading.Lock()
                self._tenant_locks[tenant_id] = lock
                return lock
            return self._overflow_lock

    def _resolve(self, base_dir: Path, maybe_relative: str | None) -> Path:
        path = Path(maybe_relative or "artifacts/evidence/tenants")
        if path.is_absolute():
            return path
        return base_dir / path

    def resolve_tenant_id(
        self,
        headers: dict[str, Any] | None,
        payload: dict[str, Any] | None = None,
    ) -> tuple[str, str | None]:
        if not self.enabled:
            return self.default_tenant_id, None

        headers = headers or {}
        payload = payload if isinstance(payload, dict) else {}
        raw_tenant = str(headers.get(self.tenant_header, "")).strip() or str(payload.get("tenant_id", "")).strip()

        if not raw_tenant:
            if self.require_tenant_header:
                return "", f"Missing required tenant header: {self.tenant_header}"
            return self.default_tenant_id, None

        candidate = raw_tenant.lower()
        if not self.allowed_pattern.match(candidate):
            return "", "Tenant identifier format is invalid."
        return candidate, None

    def scope_session_id(self, tenant_id: str, session_id: str) -> str:
        if not self.enabled or not self.enforce_tenant_scope_on_session:
            return session_id
        return f"tenant:{tenant_id}:{session_id}"

    def write_evidence(
        self,
        tenant_id: str,
        event_type: str,
        severity: str,
        details: dict[str, Any],
        timestamp: float | None = None,
    ):
        if not self.enabled:
            return
        ts = float(timestamp) if timestamp is not None else time.time()
        tenant_dir = self.evidence_dir / tenant_id
        tenant_dir.mkdir(parents=True, exist_ok=True)
        path = tenant_dir / "events.jsonl"
        record = {
            "tenant_id": tenant_id,
            "event_type": event_type,
            "severity": severity,
            "timestamp": ts,
            "details": details or {},
        }
        line = json.dumps(record, separators=(",", ":"), ensure_ascii=True)
        lock = self._get_tenant_lock(tenant_id)
        with lock:
            with path.open("a", encoding="utf-8") as fp:
                fp.write(line + "\n")
