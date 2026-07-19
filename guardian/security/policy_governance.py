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
    """Compute stable config hash excluding governance.approval.config_sha256 and signature fields."""
    data = yaml.safe_load(Path(config_path).read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        return _sha256_file(config_path)
    gov = data.get("governance")
    if isinstance(gov, dict):
        approval = gov.get("approval")
        if isinstance(approval, dict):
            approval = dict(approval)
            if "config_sha256" in approval:
                approval["config_sha256"] = ""
            if "signature" in approval:
                approval["signature"] = ""
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
    db_path: Path | str = "guardian.db",
    public_key_b64: str | None = None,
    baseline_config_path: Path | None = None,
    require_signature: bool = True,
    ticket_ttl_seconds: int = 90 * 86400,
    require_baseline: bool = True,
) -> tuple[bool, list[GovernanceFinding]]:
    """Evaluate governance policy and return (allowed, findings)."""
    import base64
    import time
    import hmac
    import sqlite3
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.exceptions import InvalidSignature

    findings: list[GovernanceFinding] = []
    policy = _load_policy(policy_path)
    governance_cfg = config.get("governance", {}) if isinstance(config, dict) else {}
    enabled = bool(governance_cfg.get("enabled", False))
    if not enabled:
        return True, findings

    mode = str(governance_cfg.get("mode", policy.get("mode", "enforce"))).lower()

    # 1. Mandatory baseline checks & drift protection
    if mode == "enforce" and require_baseline:
        if not baseline_config_path or not Path(baseline_config_path).exists():
            findings.append(
                GovernanceFinding(
                    severity="critical",
                    code="baseline_missing",
                    detail="baseline_config_path is required but missing under governance enforcement"
                )
            )
            return False, findings

        # Load baseline config
        try:
            baseline_data = yaml.safe_load(Path(baseline_config_path).read_text(encoding="utf-8"))
        except Exception as exc:
            findings.append(
                GovernanceFinding(
                    severity="critical",
                    code="baseline_corrupted",
                    detail=f"Failed to parse baseline configuration: {exc}"
                )
            )
            return False, findings

        if not isinstance(baseline_data, dict):
            findings.append(
                GovernanceFinding(
                    severity="critical",
                    code="baseline_corrupted",
                    detail="Baseline configuration must be a JSON/YAML object"
                )
            )
            return False, findings

        if "version" not in baseline_data:
            findings.append(
                GovernanceFinding(
                    severity="critical",
                    code="baseline_version_missing",
                    detail="Baseline configuration missing required version field"
                )
            )
            return False, findings

        # Run cumulative drift detection
        drift_findings = detect_config_drift(config, baseline_data, ignore_keys={"governance"})
        if drift_findings:
            risky = [f.detail for f in drift_findings]
        else:
            risky = []
    else:
        # Fallback to single-turn risk rule scanner if not in strict enforcement or baseline is skipped
        risky = _is_high_risk_config(config, policy)

    approval = governance_cfg.get("approval", {}) if isinstance(governance_cfg, dict) else {}
    approved = str(approval.get("status", "")).lower() == "approved"
    approver = str(approval.get("approver", "")).strip()
    ticket = str(approval.get("ticket", "")).strip()
    declared_hash = str(approval.get("config_sha256", "")).strip().lower()
    signature_b64 = str(approval.get("signature", "")).strip()

    if risky and not approved:
        findings.append(
            GovernanceFinding(
                severity="high",
                code="approval_required",
                detail=f"Configuration changes require approval. Deviations: {', '.join(risky)}",
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
        if not declared_hash:
            findings.append(
                GovernanceFinding(
                    severity="high",
                    code="config_hash_missing",
                    detail="Approved configuration missing config_sha256 integrity pin.",
                )
            )
        else:
            actual_hash = compute_config_integrity_hash(config_path).lower() if config_path.exists() else ""
            if actual_hash and declared_hash != actual_hash:
                findings.append(
                    GovernanceFinding(
                        severity="critical",
                        code="config_integrity_mismatch",
                        detail="Approval hash does not match configuration file contents.",
                    )
                )

        # 2. Strict Ed25519 signature enforcement
        if require_signature:
            resolved_key = public_key_b64 or os.environ.get("GUARDIAN_GOVERNANCE_PUBLIC_KEY", "").strip()
            if not resolved_key:
                findings.append(
                    GovernanceFinding(
                        severity="critical",
                        code="public_key_missing",
                        detail="public key is required for signature verification but missing or invalid"
                    )
                )
            elif not signature_b64:
                findings.append(
                    GovernanceFinding(
                        severity="critical",
                        code="signature_missing",
                        detail="Approval signature is missing"
                    )
                )
            else:
                # Payload to verify is: approver + ":" + ticket + ":" + config_sha256
                payload = f"{approver}:{ticket}:{declared_hash}".encode("utf-8")
                try:
                    pubkey_bytes = base64.b64decode(resolved_key)
                    pubkey = ed25519.Ed25519PublicKey.from_public_bytes(pubkey_bytes)
                    sig_bytes = base64.b64decode(signature_b64)
                    pubkey.verify(sig_bytes, payload)
                except Exception as exc:
                    findings.append(
                        GovernanceFinding(
                            severity="critical",
                            code="invalid_approval_signature",
                            detail=f"Approval signature verification failed: {exc}"
                        )
                    )

        # 3. SQLite database ticket registry & replay prevention with expiration (TTL)
        if not findings and ticket and declared_hash:
            try:
                conn = sqlite3.connect(str(db_path))
                cursor = conn.cursor()
                cursor.execute(
                    """
                    CREATE TABLE IF NOT EXISTS consumed_tickets (
                        ticket_id TEXT PRIMARY KEY,
                        config_hash TEXT NOT NULL,
                        timestamp REAL NOT NULL
                    )
                    """
                )
                conn.commit()

                # Query the ticket
                cursor.execute("SELECT config_hash, timestamp FROM consumed_tickets WHERE ticket_id = ?", (ticket,))
                row = cursor.fetchone()

                current_time = time.time()
                if row:
                    stored_hash, timestamp = row

                    # Freshness (TTL) check gates before content-match
                    # Note: We enforce ticket expiration window to prevent rollback replay of historical tickets.
                    if current_time - timestamp > ticket_ttl_seconds:
                        findings.append(
                            GovernanceFinding(
                                severity="critical",
                                code="ticket_expired",
                                detail=f"Approval ticket '{ticket}' has expired"
                            )
                        )
                    elif stored_hash != declared_hash:
                        findings.append(
                            GovernanceFinding(
                                severity="critical",
                                code="ticket_replay_detected",
                                detail=f"Ticket replay detected: Ticket '{ticket}' has already been used for config hash '{stored_hash}'"
                            )
                        )
                else:
                    # Write to registry to consume the ticket
                    cursor.execute(
                        "INSERT INTO consumed_tickets (ticket_id, config_hash, timestamp) VALUES (?, ?, ?)",
                        (ticket, declared_hash, current_time)
                    )
                    conn.commit()
            except Exception as exc:
                findings.append(
                    GovernanceFinding(
                        severity="critical",
                        code="database_error",
                        detail=f"Governance ticket registry error: {exc}"
                    )
                )
            finally:
                if 'conn' in locals():
                    conn.close()

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

    db_path = governance.get("db_path", "guardian.db")
    if not os.path.isabs(str(db_path)):
        db_path = Path(base_dir) / str(db_path)

    baseline_file = governance.get("baseline_file")
    baseline_path = None
    if baseline_file:
        if not os.path.isabs(str(baseline_file)):
            baseline_path = Path(base_dir) / str(baseline_file)
        else:
            baseline_path = Path(str(baseline_file))

    public_key_b64 = governance.get("public_key")
    require_signature = bool(governance.get("require_signature", True))
    ticket_ttl = int(governance.get("ticket_ttl_seconds", 90 * 86400))
    require_baseline = bool(governance.get("require_baseline", True))

    return evaluate_policy_governance(
        config,
        Path(config_path),
        policy_path,
        db_path=db_path,
        public_key_b64=public_key_b64,
        baseline_config_path=baseline_path,
        require_signature=require_signature,
        ticket_ttl_seconds=ticket_ttl,
        require_baseline=require_baseline,
    )


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
