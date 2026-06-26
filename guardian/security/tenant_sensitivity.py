from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict


@dataclass
class TenantSensitivity:
    tenant_id: str
    security_mode: str
    show_block_reason: bool


class TenantSensitivityManager:
    def __init__(self, config: Dict[str, Any] | None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.default_security_mode = str(cfg.get("default_security_mode", "balanced")).lower()
        self.default_show_block_reason = bool(cfg.get("default_show_block_reason", True))
        self.tenant_modes = cfg.get("tenant_modes", {}) or {}
        self._valid_modes = {"strict", "balanced", "lenient"}

    def resolve(self, tenant_id: str, fallback_mode: str, fallback_show_reason: bool) -> TenantSensitivity:
        if not self.enabled:
            return TenantSensitivity(tenant_id=tenant_id, security_mode=fallback_mode, show_block_reason=fallback_show_reason)

        tenant_cfg = self.tenant_modes.get(tenant_id, {})
        if not isinstance(tenant_cfg, dict):
            tenant_cfg = {}

        mode = str(tenant_cfg.get("security_mode", fallback_mode or self.default_security_mode)).lower()
        if mode not in self._valid_modes:
            mode = fallback_mode if fallback_mode in self._valid_modes else self.default_security_mode

        show_reason = tenant_cfg.get("show_block_reason", fallback_show_reason)
        return TenantSensitivity(tenant_id=tenant_id, security_mode=mode, show_block_reason=bool(show_reason))
