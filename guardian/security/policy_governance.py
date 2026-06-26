"""Policy governance checks for controlled, auditable security config changes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
import hashlib
import os
from typing import Any

import yaml


@dataclass
class GovernanceFinding:
    severity: str
    code: str
    detail: str


def _sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            digest.update(chunk)
    return digest.hexdigest()


def compute_config_integrity_hash(config_path: Path) -> str:
    """Compute stable config hash excluding governance.approval.config_sha256 field."""
    data = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return _sha256_file(config_path)
    gov = data.get("governance")
    if isinstance(gov, dict):
        approval = gov.get("approval")
        if isinstance(approval, dict) and "config_sha256" in approval:
            approval = dict(approval)
            approval["config_sha256"] = ""
            gov = dict(gov)
            gov["approval"] = approval
            data["governance"] = gov
    canonical = yaml.safe_dump(data, sort_keys=True).encode("utf-8")
    return hashlib.sha256(canonical).hexdigest()


def _get_path(data: dict[str, Any], path: str, default=None):
    current: Any = data
    for part in path.split("."):
        if not isinstance(current, dict) or part not in current:
            return default
        current = current[part]
    return current


def _is_high_risk_config(config: dict[str, Any], policy: dict[str, Any]) -> list[str]:
    risky: list[str] = []
    rules = policy.get("risk_rules", {})

    mode = str(_get_path(config, "security_policies.security_mode", "")).lower()
    lenient_values = [str(v).lower() for v in rules.get("lenient_modes", ["lenient"])]
    if mode in lenient_values:
        risky.append(f"security_mode={mode}")

    leak_strategy = str(_get_path(config, "security_policies.leak_prevention_strategy", "")).lower()
    risky_leak = [str(v).lower() for v in rules.get("risky_leak_strategies", ["redact"])]
    if leak_strategy in risky_leak:
        risky.append(f"leak_prevention_strategy={leak_strategy}")

    rpm = _get_path(config, "rate_limiting.requests_per_minute", 60)
    try:
        rpm_num = int(rpm)
    except Exception:  # noqa: BLE001
        rpm_num = 60
    max_rpm = int(rules.get("max_requests_per_minute_without_approval", 120))
    if rpm_num > max_rpm:
        risky.append(f"requests_per_minute={rpm_num}>{max_rpm}")

    backend_enabled = bool(_get_path(config, "backend.enabled", True))
    if not backend_enabled and bool(rules.get("backend_must_be_enabled", True)):
        risky.append("backend.enabled=false")

    return risky


def _load_policy(policy_path: Path) -> dict[str, Any]:
    if not policy_path.exists():
        return {}
    data = yaml.safe_load(policy_path.read_text(encoding="utf-8"))
    return data if isinstance(data, dict) else {}


def evaluate_policy_governance(
    config: dict[str, Any],
    config_path: Path,
    policy_path: Path,
) -> tuple[bool, list[GovernanceFinding]]:
    """Evaluate governance policy and return (allowed, findings)."""
    findings: list[GovernanceFinding] = []
    policy = _load_policy(policy_path)
    governance_cfg = config.get("governance", {}) if isinstance(config, dict) else {}
    enabled = bool(governance_cfg.get("enabled", False))
    if not enabled:
        return True, findings

    mode = str(governance_cfg.get("mode", policy.get("mode", "enforce"))).lower()
    risky = _is_high_risk_config(config, policy)

    approval = governance_cfg.get("approval", {}) if isinstance(governance_cfg, dict) else {}
    approved = str(approval.get("status", "")).lower() == "approved"
    approver = str(approval.get("approver", "")).strip()
    ticket = str(approval.get("ticket", "")).strip()
    declared_hash = str(approval.get("config_sha256", "")).strip().lower()

    if risky and not approved:
        findings.append(
            GovernanceFinding(
                severity="high",
                code="approval_required",
                detail=f"High-risk settings require approval: {', '.join(risky)}",
            )
        )

    if approved:
        if not approver or not ticket:
            findings.append(
                GovernanceFinding(
                    severity="high",
                    code="approval_metadata_missing",
                    detail="Approved configuration must include approver and ticket.",
                )
            )
        if declared_hash:
            actual_hash = compute_config_integrity_hash(config_path).lower() if config_path.exists() else ""
            if actual_hash and declared_hash != actual_hash:
                findings.append(
                    GovernanceFinding(
                        severity="critical",
                        code="config_integrity_mismatch",
                        detail="Approval hash does not match configuration file contents.",
                    )
                )
        else:
            findings.append(
                GovernanceFinding(
                    severity="high",
                    code="config_hash_missing",
                    detail="Approved configuration missing config_sha256 integrity pin.",
                )
            )

    if mode == "audit":
        return True, findings
    allowed = len(findings) == 0
    return allowed, findings


def evaluate_from_runtime_config(config: dict[str, Any], config_path: str, base_dir: str) -> tuple[bool, list[GovernanceFinding]]:
    governance = config.get("governance", {}) if isinstance(config, dict) else {}
    policy_file = governance.get("policy_file", "config/policy_control.yaml")
    if not os.path.isabs(str(policy_file)):
        policy_path = Path(base_dir) / str(policy_file)
    else:
        policy_path = Path(str(policy_file))
    return evaluate_policy_governance(config, Path(config_path), policy_path)


# ═══════════════════════════════════════════════════════════════════════════
# 2026-Standard Advanced Governance Capabilities
# ═══════════════════════════════════════════════════════════════════════════

class GovernanceEventBus:
    """Bounded in-memory event bus for governance audit events."""
    _MAX = 500

    def __init__(self):
        self._events: list[dict] = []

    def emit(self, event_type: str, detail: str, approver: str = "", severity: str = "info"):
        entry = {"event": event_type, "detail": detail, "approver": approver, "severity": severity}
        self._events.append(entry)
        if len(self._events) > self._MAX:
            self._events = self._events[-self._MAX:]

    def query(self, event_type: str = "", limit: int = 50) -> list[dict]:
        out = self._events if not event_type else [e for e in self._events if e["event"] == event_type]
        return out[-limit:]

    def clear(self):
        self._events.clear()

    @property
    def count(self) -> int:
        return len(self._events)


_governance_bus = GovernanceEventBus()


def get_governance_event_bus() -> GovernanceEventBus:
    return _governance_bus


def validate_multi_approver_quorum(
    approvers: list[str],
    required_quorum: int = 2,
    min_distinct_roles: int = 1,
    approver_roles: dict[str, str] | None = None,
) -> tuple[bool, list[GovernanceFinding]]:
    """Validate that a change has enough approvals from distinct roles."""
    findings: list[GovernanceFinding] = []
    unique = list(dict.fromkeys(a.strip() for a in approvers if a.strip()))
    if len(unique) < required_quorum:
        findings.append(GovernanceFinding(
            severity="high", code="quorum_not_met",
            detail=f"Need {required_quorum} approvers, got {len(unique)}: {unique}",
        ))
    if approver_roles and min_distinct_roles > 1:
        roles = set(approver_roles.get(a, "unknown") for a in unique)
        if len(roles) < min_distinct_roles:
            findings.append(GovernanceFinding(
                severity="high", code="insufficient_role_diversity",
                detail=f"Need {min_distinct_roles} distinct roles, got {len(roles)}: {roles}",
            ))
    return len(findings) == 0, findings


def validate_change_window(
    current_hour_utc: int,
    allowed_windows: list[tuple[int, int]] | None = None,
) -> tuple[bool, list[GovernanceFinding]]:
    """Enforce change-window policy (e.g., no deploys at 3am)."""
    if not allowed_windows:
        return True, []
    for start, end in allowed_windows:
        if start <= end:
            if start <= current_hour_utc < end:
                return True, []
        else:  # wraps midnight
            if current_hour_utc >= start or current_hour_utc < end:
                return True, []
    return False, [GovernanceFinding(
        severity="high", code="outside_change_window",
        detail=f"Current hour {current_hour_utc} UTC not in allowed windows {allowed_windows}",
    )]


def validate_policy_version_pin(
    declared_version: str,
    minimum_version: str = "1.0.0",
) -> tuple[bool, list[GovernanceFinding]]:
    """Ensure policy file version meets minimum."""
    def _parse(v: str) -> tuple[int, ...]:
        parts = []
        for p in v.strip().split("."):
            try:
                parts.append(int(p))
            except ValueError:
                parts.append(0)
        return tuple(parts)

    decl = _parse(declared_version)
    minimum = _parse(minimum_version)
    if decl < minimum:
        return False, [GovernanceFinding(
            severity="high", code="policy_version_too_old",
            detail=f"Policy version {declared_version} < minimum {minimum_version}",
        )]
    return True, []


def detect_config_drift(
    live_config: dict[str, Any],
    baseline_config: dict[str, Any],
    ignore_keys: set[str] | None = None,
) -> list[GovernanceFinding]:
    """Detect keys that differ between live and baseline configs."""
    ignore = ignore_keys or set()
    findings: list[GovernanceFinding] = []

    def _walk(live: Any, base: Any, path: str):
        if path in ignore:
            return
        if isinstance(live, dict) and isinstance(base, dict):
            all_keys = set(live.keys()) | set(base.keys())
            for k in sorted(all_keys):
                _walk(live.get(k), base.get(k), f"{path}.{k}" if path else k)
        elif live != base:
            findings.append(GovernanceFinding(
                severity="medium" if path.startswith("governance") else "high",
                code="config_drift",
                detail=f"Drift at '{path}': live={live!r} baseline={base!r}",
            ))

    _walk(live_config, baseline_config, "")
    return findings
