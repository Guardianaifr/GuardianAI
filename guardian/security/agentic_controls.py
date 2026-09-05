from __future__ import annotations

import json
import base64
import hashlib
import hmac
import re
import threading
import time
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Optional


@dataclass
class AgenticDecision:
    action: str
    reason: str
    details: Dict[str, Any]
    severity: str = "HIGH"


class AgenticSecurityManager:
    def __init__(self, config: Dict[str, Any] | None, root_dir: Path, identity_gate: "Any | None" = None):
        cfg = config or {}
        self.enabled = bool(cfg.get("enabled", False))
        self.enforcement_mode = str(cfg.get("enforcement_mode", "enforce")).lower()
        self.require_agent_id = bool(cfg.get("require_agent_id", True))
        self.require_execution_id = bool(cfg.get("require_execution_id", False))
        self.require_scope = bool(cfg.get("require_scope", False))
        # Identity Gate integration (point-of-interaction ERC-8004/passport
        # enforcement). Opt-in by design, deliberately separate from
        # GUARDIAN_IDENTITY_GATE_ENABLED: that env var controls whether the
        # gate does anything AT ALL (relay + here); this config key controls
        # whether THIS control plane additionally requires the check to pass.
        # If identity_gate is None (not wired by the caller) this is always a
        # no-op regardless of the flag, so a misconfigured deployment fails
        # open here rather than raising — see _identity_decision().
        self.require_agent_identity = bool(cfg.get("require_agent_identity", False))
        self.identity_gate = identity_gate
        self.agent_id_header = str(cfg.get("agent_id_header", "X-Guardian-Agent-Id"))
        self.parent_agent_header = str(cfg.get("parent_agent_header", "X-Guardian-Agent-Parent"))
        self.execution_id_header = str(cfg.get("execution_id_header", "X-Guardian-Exec-Id"))
        self.scope_header = str(cfg.get("scope_header", "X-Guardian-Agent-Scope"))
        self.parent_scope_header = str(cfg.get("parent_scope_header", "X-Guardian-Agent-Parent-Scope"))
        self.hop_header = str(cfg.get("hop_header", "X-Guardian-Agent-Hop"))
        self.max_hops = int(cfg.get("max_hops", 8))
        self.agent_id_pattern = re.compile(str(cfg.get("agent_id_pattern", r"^[A-Za-z0-9._:-]{2,128}$")))
        self.allowed_parent_child = cfg.get("allowed_parent_child", {}) or {}
        self.scope_tool_allowlist = cfg.get("scope_tool_allowlist", {}) or {}
        self.mcp_server_header = str(cfg.get("mcp_server_header", "X-Guardian-MCP-Server"))
        self.trusted_mcp_servers = set(str(v).strip() for v in (cfg.get("trusted_mcp_servers", []) or []) if str(v).strip())
        self.require_mcp_server_for_tools = bool(cfg.get("require_mcp_server_for_tools", False))
        self.mcp_server_tool_allowlist = cfg.get("mcp_server_tool_allowlist", {}) or {}
        self.enforce_scope_non_escalation = bool(cfg.get("enforce_scope_non_escalation", True))
        self.scope_hierarchy = cfg.get("scope_hierarchy", {"read_only": 0, "standard": 1, "privileged": 2}) or {}
        self.kill_switch_enabled = bool(cfg.get("kill_switch_enabled", True))
        kill_switch_path = str(cfg.get("kill_switch_file", "artifacts/control/agent_kill_switch.json"))
        self.kill_switch_file = (root_dir / kill_switch_path).resolve()
        self.revoked_agent_ids = set(str(v).strip() for v in (cfg.get("revoked_agent_ids", []) or []) if str(v).strip())
        self.require_agent_attestation = bool(cfg.get("require_agent_attestation", True))
        self.attestation_header = str(cfg.get("attestation_header", "X-Guardian-Agent-Attestation"))
        self.attestation_timestamp_header = str(
            cfg.get("attestation_timestamp_header", "X-Guardian-Agent-Attestation-Ts")
        )
        self.agent_key_id_header = str(cfg.get("agent_key_id_header", "X-Guardian-Agent-Key-Id"))
        self.agent_attestation_keys = cfg.get("agent_attestation_keys", {}) or {}
        self.revoked_agent_key_ids = set(
            str(v).strip() for v in (cfg.get("revoked_agent_key_ids", []) or []) if str(v).strip()
        )
        self.require_mtls = bool(cfg.get("require_mtls", False))
        self.mtls_verified_header = str(cfg.get("mtls_verified_header", "X-Guardian-mTLS-Verified"))
        self.mtls_fingerprint_header = str(cfg.get("mtls_fingerprint_header", "X-Guardian-mTLS-Fingerprint"))
        self.mtls_subject_header = str(cfg.get("mtls_subject_header", "X-Guardian-mTLS-Subject"))
        self.mtls_verified_value = str(cfg.get("mtls_verified_value", "SUCCESS"))
        self.agent_cert_fingerprints = cfg.get("agent_cert_fingerprints", {}) or {}
        control_plane_path = str(cfg.get("control_plane_file", "") or "").strip()
        self.control_plane_file = (root_dir / control_plane_path).resolve() if control_plane_path else None
        self.control_plane_reload_seconds = float(cfg.get("control_plane_reload_seconds", 5.0))
        self._control_plane_loaded_at = 0.0
        self._control_plane_mtime = 0.0
        self.attestation_max_age_seconds = int(cfg.get("attestation_max_age_seconds", 300))
        self.enforce_policy_graph = bool(cfg.get("enforce_policy_graph", True))
        self.cross_agent_policy_graph = cfg.get("cross_agent_policy_graph", {}) or {}
        self.require_execution_grant = bool(cfg.get("require_execution_grant", False))
        self.execution_grants = cfg.get("execution_grants", {}) or {}
        self.require_trace_hash = bool(cfg.get("require_trace_hash", False))
        self.trace_prev_hash_header = str(cfg.get("trace_prev_hash_header", "X-Guardian-Trace-Prev-Hash"))
        self.trace_hash_header = str(cfg.get("trace_hash_header", "X-Guardian-Trace-Hash"))
        self.trace_replay_cache_enabled = bool(cfg.get("trace_replay_cache_enabled", False))
        trace_cache_path = str(cfg.get("trace_replay_cache_file", "artifacts/control/agent_trace_hashes.json"))
        self.trace_replay_cache_file = (root_dir / trace_cache_path).resolve()
        self.risk_adaptive_enabled = bool(cfg.get("risk_adaptive_enabled", False))
        self.threat_score_header = str(cfg.get("threat_score_header", "X-Guardian-Threat-Score"))
        self.risk_scope_thresholds = cfg.get("risk_scope_thresholds", {}) or {}
        self.kill_switch_threat_score = self._optional_float(cfg.get("kill_switch_threat_score"))
        self.lateral_movement_detection_enabled = bool(cfg.get("lateral_movement_detection_enabled", False))
        self.chain_state_ttl_seconds = int(cfg.get("chain_state_ttl_seconds", 900))
        self.max_chain_agents = int(cfg.get("max_chain_agents", 8))
        self.max_scope_rank_drift = int(cfg.get("max_scope_rank_drift", 0))
        self.max_new_tools_per_chain = int(cfg.get("max_new_tools_per_chain", 3))
        self.chain_circuit_breaker_threshold = int(cfg.get("chain_circuit_breaker_threshold", 2))
        self.chain_circuit_breaker_write_kill_switch = bool(
            cfg.get("chain_circuit_breaker_write_kill_switch", True)
        )
        self.lateral_sensitive_tools = {
            str(v).strip()
            for v in (
                cfg.get(
                    "lateral_sensitive_tools",
                    [
                        "wire_transfer",
                        "delete_user",
                        "write_file",
                        "os_exec",
                        "shell",
                        "create_api_key",
                    ],
                )
                or []
            )
            if str(v).strip()
        }
        self._chain_state: Dict[str, Dict[str, Any]] = {}
        self._chain_circuit_breakers: set[str] = set()
        self._attestation_replay_cache: Dict[str, float] = {}
        self._attestation_replay_lock = threading.Lock()

    def evaluate(self, headers: Dict[str, Any], data: Optional[Dict[str, Any]] = None) -> AgenticDecision:
        if not self.enabled:
            return AgenticDecision("allow", "disabled", {})
        self._refresh_control_plane()

        agent_id = self._header(headers, self.agent_id_header)
        parent_id = self._header(headers, self.parent_agent_header)
        exec_id = self._header(headers, self.execution_id_header)
        scope = self._header(headers, self.scope_header)
        parent_scope = self._header(headers, self.parent_scope_header)
        mcp_server = self._header(headers, self.mcp_server_header)
        key_id = self._header(headers, self.agent_key_id_header)
        attestation = self._header(headers, self.attestation_header)
        attestation_ts = self._header(headers, self.attestation_timestamp_header)
        mtls_verified = self._header(headers, self.mtls_verified_header)
        mtls_fingerprint = self._normalize_fingerprint(self._header(headers, self.mtls_fingerprint_header))
        mtls_subject = self._header(headers, self.mtls_subject_header)
        trace_prev_hash = self._header(headers, self.trace_prev_hash_header)
        trace_hash = self._header(headers, self.trace_hash_header)
        threat_score = self._optional_float(self._header(headers, self.threat_score_header))
        hop_raw = self._header(headers, self.hop_header)
        hop_count = self._parse_hop(hop_raw)
        requested_tools = self._extract_tool_names(data or {})

        if exec_id and exec_id in self._chain_circuit_breakers:
            return AgenticDecision(
                "block",
                "execution_chain_circuit_breaker",
                {"execution_id": exec_id},
                severity="CRITICAL",
            )

        if self.require_agent_id and not agent_id:
            return AgenticDecision("block", "missing_agent_id", {"header": self.agent_id_header})
        if agent_id and not self.agent_id_pattern.match(agent_id):
            return AgenticDecision("block", "invalid_agent_id", {"agent_id": agent_id})
        
        mtls_decision = self._verify_mtls_binding(agent_id, mtls_verified, mtls_fingerprint, mtls_subject)
        if mtls_decision:
            return mtls_decision
            
        if self.require_agent_attestation:
            attestation_decision = self._verify_attestation(
                agent_id=agent_id,
                exec_id=exec_id,
                scope=scope,
                key_id=key_id,
                timestamp=attestation_ts,
                signature=attestation,
                data=data,
            )
            if attestation_decision:
                return attestation_decision

        else:
            if agent_id:
                revoked = (
                    agent_id in self.revoked_agent_ids
                    or (agent_id.startswith("0x") and any(r.lower() == agent_id.lower() for r in self.revoked_agent_ids))
                )
                if revoked:
                    return AgenticDecision("block", "revoked_agent_identity", {"agent_id": agent_id})
            if key_id and (
                key_id in self.revoked_agent_key_ids
                or any(r.lower() == key_id.lower() for r in self.revoked_agent_key_ids)
            ):
                return AgenticDecision("block", "revoked_agent_key", {"agent_id": agent_id, "key_id": key_id})

        if self.require_execution_id and not exec_id:
            return AgenticDecision("block", "missing_execution_id", {"header": self.execution_id_header})
        if self.require_scope and not scope:
            return AgenticDecision("block", "missing_scope", {"header": self.scope_header})

        if hop_count is not None and hop_count > self.max_hops:
            return AgenticDecision(
                "block",
                "hop_limit_exceeded",
                {"hop_count": hop_count, "max_hops": self.max_hops},
            )

        if parent_id and agent_id and self.allowed_parent_child:
            allowed = self.allowed_parent_child.get(parent_id, [])
            if allowed and agent_id not in allowed:
                return AgenticDecision(
                    "block",
                    "unauthorized_agent_hop",
                    {"parent_agent": parent_id, "child_agent": agent_id},
                )

        graph_decision = self._enforce_policy_graph(parent_id, agent_id, scope, requested_tools, hop_count)
        if graph_decision:
            return graph_decision

        grant_decision = self._enforce_execution_grant(exec_id, parent_id, agent_id, scope, requested_tools)
        if grant_decision:
            return grant_decision

        risk_decision = self._enforce_risk_adaptive_scope(threat_score, scope)
        if risk_decision:
            return risk_decision

        lateral_decision = self._enforce_lateral_movement_detection(
            exec_id=exec_id,
            parent_id=parent_id,
            agent_id=agent_id,
            scope=scope,
            requested_tools=requested_tools,
            hop_count=hop_count,
        )
        if lateral_decision:
            return lateral_decision

        if scope and data and self.scope_tool_allowlist:
            allowed_tools = self.scope_tool_allowlist.get(scope, [])
            if allowed_tools:
                denied = [name for name in requested_tools if name not in allowed_tools]
                if denied:
                    return AgenticDecision(
                        "block",
                        "scope_tool_violation",
                        {"scope": scope, "requested_tools": requested_tools, "denied_tools": denied},
                    )

        if self.require_mcp_server_for_tools and requested_tools and not mcp_server:
            return AgenticDecision(
                "block",
                "missing_mcp_server",
                {"header": self.mcp_server_header, "requested_tools": requested_tools},
            )

        if mcp_server and self.trusted_mcp_servers and mcp_server not in self.trusted_mcp_servers:
            return AgenticDecision(
                "block",
                "untrusted_mcp_server",
                {"mcp_server": mcp_server},
            )

        if mcp_server and requested_tools and self.mcp_server_tool_allowlist:
            allowed_for_server = self.mcp_server_tool_allowlist.get(mcp_server, [])
            if allowed_for_server:
                denied = [name for name in requested_tools if name not in allowed_for_server]
                if denied:
                    return AgenticDecision(
                        "block",
                        "mcp_tool_violation",
                        {"mcp_server": mcp_server, "requested_tools": requested_tools, "denied_tools": denied},
                    )

        if self.enforce_scope_non_escalation and scope and parent_scope:
            child_rank = self._scope_rank(scope)
            parent_rank = self._scope_rank(parent_scope)
            if child_rank > parent_rank:
                return AgenticDecision(
                    "block",
                    "scope_escalation_detected",
                    {"parent_scope": parent_scope, "requested_scope": scope},
                )

        trace_decision = self._verify_trace_hash(
            agent_id=agent_id,
            parent_id=parent_id,
            exec_id=exec_id,
            scope=scope,
            requested_tools=requested_tools,
            trace_prev_hash=trace_prev_hash,
            trace_hash=trace_hash,
        )
        if trace_decision:
            return trace_decision

        kill_switch = self._load_kill_switch()
        if self.kill_switch_enabled and kill_switch.get("global_pause", False):
            return AgenticDecision("block", "global_pause_enabled", {"kill_switch": "global_pause"})
        if self.kill_switch_enabled and agent_id and agent_id in set(kill_switch.get("blocked_agent_ids", [])):
            return AgenticDecision("block", "agent_kill_switch", {"agent_id": agent_id})
        if self.kill_switch_enabled and exec_id and exec_id in set(kill_switch.get("blocked_execution_ids", [])):
            return AgenticDecision("block", "execution_kill_switch", {"execution_id": exec_id})

        identity_decision, identity_details = self._enforce_identity_gate(agent_id)
        if identity_decision:
            return identity_decision

        allow_details = {
            "agent_id": agent_id,
            "parent_agent": parent_id,
            "execution_id": exec_id,
            "scope": scope,
            "mcp_server": mcp_server,
            "mtls_subject": mtls_subject,
            "mtls_fingerprint": mtls_fingerprint,
            "trace_hash": trace_hash,
            "threat_score": threat_score,
        }
        allow_details.update(identity_details)
        return AgenticDecision("allow", "ok", allow_details, severity="LOW")

    @staticmethod
    def _header(headers: Dict[str, Any], name: str) -> str:
        value = headers.get(name)
        if value is None:
            target = str(name).lower()
            for key, candidate in headers.items():
                if str(key).lower() == target:
                    value = candidate
                    break
        return str(value).strip() if value is not None else ""

    @staticmethod
    def _extract_tool_names(data: Dict[str, Any]) -> list[str]:
        names: list[str] = []
        for tool in data.get("tools", []) or []:
            if not isinstance(tool, dict):
                continue
            if tool.get("type") == "function":
                fn = tool.get("function", {})
                if isinstance(fn, dict) and fn.get("name"):
                    names.append(str(fn.get("name")))
        return names

    @staticmethod
    def _parse_hop(value: str) -> Optional[int]:
        if not value:
            return None
        try:
            hop = int(value)
            return hop if hop >= 0 else None
        except ValueError:
            return None

    @staticmethod
    def _normalize_fingerprint(value: str) -> str:
        return value.replace(":", "").replace(" ", "").strip().lower()

    @staticmethod
    def _optional_float(value: Any) -> Optional[float]:
        if value is None or value == "":
            return None
        try:
            return float(value)
        except (TypeError, ValueError):
            return None

    def _scope_rank(self, scope: str) -> int:
        raw = self.scope_hierarchy.get(scope, 0)
        try:
            return int(raw)
        except Exception:  # noqa: BLE001
            return 0

    def _verify_attestation(
        self,
        agent_id: str,
        exec_id: str,
        scope: str,
        key_id: str,
        timestamp: str,
        signature: str,
        data: Optional[Dict[str, Any]] = None,
    ) -> Optional[AgenticDecision]:
        if not signature:
            return AgenticDecision("block", "missing_agent_attestation", {"header": self.attestation_header})
        jwt_value = signature.removeprefix("Bearer ").strip()

        payload_hash = ""
        if data:
            payload_str = json.dumps(data, sort_keys=True, separators=(",", ":"))
            payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()

        if jwt_value.count(".") == 2:
            return self._verify_jwt_attestation(agent_id, exec_id, scope, key_id, jwt_value, payload_hash)
        if not timestamp:
            return AgenticDecision(
                "block",
                "missing_agent_attestation_timestamp",
                {"header": self.attestation_timestamp_header},
            )
        ts = self._parse_timestamp(timestamp)
        if ts is None:
            return AgenticDecision("block", "invalid_agent_attestation_timestamp", {"timestamp": timestamp})
        age = abs(time.time() - ts)
        if age > self.attestation_max_age_seconds:
            return AgenticDecision(
                "block",
                "stale_agent_attestation",
                {"age_seconds": int(age), "max_age_seconds": self.attestation_max_age_seconds},
            )
        secret, resolved_key_id = self._attestation_secret(agent_id, key_id)
        if not secret:
            return AgenticDecision(
                "block",
                "unknown_agent_attestation_key",
                {"agent_id": agent_id, "key_id": key_id},
            )
        material = self._attestation_material(agent_id, exec_id, scope, key_id, timestamp, payload_hash)
        expected = hmac.new(str(secret).encode("utf-8"), material.encode("utf-8"), hashlib.sha256).hexdigest()
        supplied = signature.removeprefix("sha256=").strip()
        if not hmac.compare_digest(expected, supplied):
            return AgenticDecision("block", "invalid_agent_attestation", {"agent_id": agent_id, "key_id": key_id})
        if resolved_key_id and (
            resolved_key_id in self.revoked_agent_key_ids
            or any(r.lower() == resolved_key_id.lower() for r in self.revoked_agent_key_ids)
        ):
            return AgenticDecision("block", "revoked_agent_key", {"agent_id": agent_id, "key_id": resolved_key_id})
        if agent_id:
            revoked = (
                agent_id in self.revoked_agent_ids
                or (agent_id.startswith("0x") and any(r.lower() == agent_id.lower() for r in self.revoked_agent_ids))
            )
            if revoked:
                return AgenticDecision("block", "revoked_agent_identity", {"agent_id": agent_id})

        now = time.time()
        with self._attestation_replay_lock:
            # Clean up old entries
            to_remove = [k for k, v in self._attestation_replay_cache.items() if now - v > self.attestation_max_age_seconds]
            for k in to_remove:
                self._attestation_replay_cache.pop(k, None)

            if supplied in self._attestation_replay_cache:
                return AgenticDecision("block", "attestation_replay_detected", {"signature": supplied})
            self._attestation_replay_cache[supplied] = ts

        return None

    def _enforce_lateral_movement_detection(
        self,
        exec_id: str,
        parent_id: str,
        agent_id: str,
        scope: str,
        requested_tools: list[str],
        hop_count: Optional[int],
    ) -> Optional[AgenticDecision]:
        if not self.lateral_movement_detection_enabled or not exec_id:
            return None
        self._prune_chain_state()

        now = time.time()
        state = self._chain_state.setdefault(
            exec_id,
            {
                "created_at": now,
                "last_seen": now,
                "agents": set(),
                "parent_by_agent": {},
                "edges": set(),
                "baseline_scope_rank": None,
                "max_scope_rank": None,
                "tools": set(),
                "violations": [],
            },
        )
        state["last_seen"] = now

        violations: list[Dict[str, Any]] = []
        agents: set[str] = state["agents"]
        if agent_id:
            agents.add(agent_id)
        if len(agents) > self.max_chain_agents:
            violations.append(
                {
                    "type": "chain_agent_fanout_exceeded",
                    "agent_count": len(agents),
                    "max_chain_agents": self.max_chain_agents,
                }
            )

        parent_by_agent: Dict[str, str] = state["parent_by_agent"]
        if agent_id and parent_id:
            previous_parent = parent_by_agent.get(agent_id)
            if previous_parent and previous_parent != parent_id:
                violations.append(
                    {
                        "type": "agent_parent_changed",
                        "agent_id": agent_id,
                        "previous_parent": previous_parent,
                        "new_parent": parent_id,
                    }
                )
            parent_by_agent.setdefault(agent_id, parent_id)
            state["edges"].add((parent_id, agent_id))

        scope_rank = self._scope_rank(scope) if scope else None
        if scope_rank is not None:
            if state["baseline_scope_rank"] is None:
                state["baseline_scope_rank"] = scope_rank
                state["max_scope_rank"] = scope_rank
            baseline_rank = int(state["baseline_scope_rank"])
            max_allowed = baseline_rank + self.max_scope_rank_drift
            if scope_rank > max_allowed:
                violations.append(
                    {
                        "type": "task_scope_drift",
                        "baseline_scope_rank": baseline_rank,
                        "requested_scope": scope,
                        "requested_scope_rank": scope_rank,
                        "max_allowed_scope_rank": max_allowed,
                    }
                )
            if state["max_scope_rank"] is None or scope_rank > int(state["max_scope_rank"]):
                state["max_scope_rank"] = scope_rank

        known_tools: set[str] = state["tools"]
        new_tools = [tool for tool in requested_tools if tool not in known_tools]
        sensitive_new_tools = [tool for tool in new_tools if tool in self.lateral_sensitive_tools]
        if len(known_tools) > 0 and len(new_tools) > self.max_new_tools_per_chain:
            violations.append(
                {
                    "type": "task_tool_drift",
                    "new_tools": new_tools,
                    "max_new_tools_per_chain": self.max_new_tools_per_chain,
                }
            )
        if len(known_tools) > 0 and sensitive_new_tools:
            violations.append(
                {
                    "type": "sensitive_tool_lateral_movement",
                    "new_sensitive_tools": sensitive_new_tools,
                }
            )
        known_tools.update(requested_tools)

        if not violations:
            return None

        state["violations"].extend(violations)
        violation_count = len(state["violations"])
        details = {
            "execution_id": exec_id,
            "agent_id": agent_id,
            "parent_agent": parent_id,
            "hop_count": hop_count,
            "violation_count": violation_count,
            "violations": violations,
        }
        if violation_count >= self.chain_circuit_breaker_threshold:
            self._trip_chain_circuit_breaker(exec_id)
            return AgenticDecision(
                "block",
                "chain_circuit_breaker_tripped",
                details,
                severity="CRITICAL",
            )
        return AgenticDecision(
            "block",
            "multi_agent_lateral_movement_detected",
            details,
            severity="HIGH",
        )

    def _verify_mtls_binding(
        self,
        agent_id: str,
        mtls_verified: str,
        mtls_fingerprint: str,
        mtls_subject: str,
    ) -> Optional[AgenticDecision]:
        if not self.require_mtls:
            return None
        if not mtls_verified or mtls_verified.lower() not in {
            self.mtls_verified_value.lower(),
            "true",
            "1",
            "verified",
            "success",
        }:
            return AgenticDecision(
                "block",
                "missing_mtls_verification",
                {"header": self.mtls_verified_header, "value": mtls_verified},
            )
        if not mtls_fingerprint:
            return AgenticDecision(
                "block",
                "missing_mtls_fingerprint",
                {"header": self.mtls_fingerprint_header, "subject": mtls_subject},
            )
        allowed = self.agent_cert_fingerprints.get(agent_id, []) if agent_id else []
        normalized_allowed = {self._normalize_fingerprint(str(v)) for v in allowed if str(v).strip()}
        if normalized_allowed and mtls_fingerprint not in normalized_allowed:
            return AgenticDecision(
                "block",
                "mtls_fingerprint_mismatch",
                {"agent_id": agent_id, "fingerprint": mtls_fingerprint, "subject": mtls_subject},
            )
        return None

    def _verify_jwt_attestation(
        self,
        agent_id: str,
        exec_id: str,
        scope: str,
        key_id: str,
        token: str,
        payload_hash: str = "",
    ) -> Optional[AgenticDecision]:
        try:
            header_b64, payload_b64, signature_b64 = token.split(".")
            header = json.loads(self._b64url_decode(header_b64).decode("utf-8"))
            payload = json.loads(self._b64url_decode(payload_b64).decode("utf-8"))
        except Exception:
            return AgenticDecision("block", "invalid_agent_attestation_jwt", {"agent_id": agent_id})
        if header.get("alg") != "HS256":
            return AgenticDecision(
                "block",
                "unsupported_agent_attestation_alg",
                {"alg": header.get("alg")},
            )
        token_agent_id = str(payload.get("agent_id") or payload.get("sub") or "")
        token_exec_id = str(payload.get("execution_id") or payload.get("exec_id") or "")
        token_scope = str(payload.get("scope") or "")
        token_key_id = str(payload.get("key_id") or header.get("kid") or key_id or "")
        token_payload_hash = str(payload.get("payload_hash") or "")

        if agent_id and token_agent_id:
            if agent_id.startswith("0x") and token_agent_id.startswith("0x"):
                if token_agent_id.lower() != agent_id.lower():
                    return AgenticDecision("block", "agent_attestation_subject_mismatch", {"agent_id": agent_id})
            elif token_agent_id != agent_id:
                return AgenticDecision("block", "agent_attestation_subject_mismatch", {"agent_id": agent_id})

        if exec_id and token_exec_id and token_exec_id != exec_id:
            return AgenticDecision("block", "agent_attestation_execution_mismatch", {"execution_id": exec_id})
        if scope and token_scope and token_scope != scope:
            return AgenticDecision("block", "agent_attestation_scope_mismatch", {"scope": scope})
        if payload_hash and token_payload_hash != payload_hash:
            return AgenticDecision("block", "agent_attestation_payload_mismatch", {})

        effective_agent_id = agent_id or token_agent_id
        secret, resolved_key_id = self._attestation_secret(effective_agent_id, token_key_id)
        if not secret:
            return AgenticDecision(
                "block",
                "unknown_agent_attestation_key",
                {"agent_id": effective_agent_id, "key_id": token_key_id},
            )

        signing_input = f"{header_b64}.{payload_b64}"
        expected = hmac.new(str(secret).encode("utf-8"), signing_input.encode("utf-8"), hashlib.sha256).digest()
        try:
            supplied = self._b64url_decode(signature_b64)
        except Exception:
            return AgenticDecision("block", "invalid_agent_attestation_jwt", {"agent_id": effective_agent_id})
        if not hmac.compare_digest(expected, supplied):
            return AgenticDecision(
                "block",
                "invalid_agent_attestation_jwt",
                {"agent_id": effective_agent_id, "key_id": token_key_id},
            )
        if resolved_key_id and (
            resolved_key_id in self.revoked_agent_key_ids
            or any(r.lower() == resolved_key_id.lower() for r in self.revoked_agent_key_ids)
        ):
            return AgenticDecision("block", "revoked_agent_key", {"agent_id": effective_agent_id, "key_id": resolved_key_id})
        if effective_agent_id:
            revoked = (
                effective_agent_id in self.revoked_agent_ids
                or (effective_agent_id.startswith("0x") and any(r.lower() == effective_agent_id.lower() for r in self.revoked_agent_ids))
            )
            if revoked:
                return AgenticDecision("block", "revoked_agent_identity", {"agent_id": effective_agent_id})
        now = time.time()
        exp = self._optional_float(payload.get("exp"))
        if exp is not None and now > exp:
            return AgenticDecision("block", "expired_agent_attestation_jwt", {"exp": exp})
        iat = self._optional_float(payload.get("iat"))
        if iat is None:
            return AgenticDecision("block", "missing_agent_attestation_iat", {})
        if abs(now - iat) > self.attestation_max_age_seconds:
            return AgenticDecision(
                "block",
                "stale_agent_attestation",
                {"age_seconds": int(abs(now - iat)), "max_age_seconds": self.attestation_max_age_seconds},
            )

        with self._attestation_replay_lock:
            # Clean up old entries
            to_remove = [k for k, v in self._attestation_replay_cache.items() if now - v > self.attestation_max_age_seconds]
            for k in to_remove:
                self._attestation_replay_cache.pop(k, None)

            if signature_b64 in self._attestation_replay_cache:
                return AgenticDecision("block", "attestation_replay_detected", {"signature": signature_b64})
            self._attestation_replay_cache[signature_b64] = iat if iat is not None else now

        return None

    def _attestation_secret(self, agent_id: str, key_id: str) -> tuple[str, str]:
        raw = self.agent_attestation_keys.get(agent_id)
        if raw is None and agent_id and agent_id.startswith("0x"):
            target = agent_id.lower()
            for k, v in self.agent_attestation_keys.items():
                if str(k).lower() == target:
                    raw = v
                    break
        if isinstance(raw, dict):
            if key_id and key_id in raw:
                return str(raw[key_id]), key_id
            if "default" in raw:
                return str(raw["default"]), "default"
            return "", ""
        return str(raw or ""), key_id

    @staticmethod
    def _attestation_material(agent_id: str, exec_id: str, scope: str, key_id: str, timestamp: str, payload_hash: str = "") -> str:
        return json.dumps(
            {
                "agent_id": agent_id,
                "execution_id": exec_id,
                "scope": scope,
                "key_id": key_id,
                "timestamp": timestamp,
                "payload_hash": payload_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )

    @staticmethod
    def _b64url_decode(value: str) -> bytes:
        padded = value + "=" * (-len(value) % 4)
        return base64.urlsafe_b64decode(padded.encode("ascii"))

    @staticmethod
    def _parse_timestamp(value: str) -> Optional[float]:
        try:
            return float(value)
        except (TypeError, ValueError):
            pass
        try:
            normalized = value.replace("Z", "+00:00")
            return datetime.fromisoformat(normalized).timestamp()
        except (TypeError, ValueError):
            return None

    def _enforce_policy_graph(
        self,
        parent_id: str,
        agent_id: str,
        scope: str,
        requested_tools: list[str],
        hop_count: Optional[int],
    ) -> Optional[AgenticDecision]:
        if not self.enforce_policy_graph or not parent_id or not agent_id:
            return None
        child_policy = self._child_policy(parent_id, agent_id)
        if child_policy is None:
            return AgenticDecision(
                "block",
                "policy_graph_hop_denied",
                {"parent_agent": parent_id, "child_agent": agent_id},
            )
        max_hops = child_policy.get("max_hops")
        if max_hops is not None and hop_count is not None and hop_count > int(max_hops):
            return AgenticDecision(
                "block",
                "policy_graph_hop_limit_exceeded",
                {"hop_count": hop_count, "max_hops": int(max_hops)},
            )
        allowed_scopes = child_policy.get("scopes") or child_policy.get("allowed_scopes") or []
        if scope and allowed_scopes and scope not in allowed_scopes:
            return AgenticDecision(
                "block",
                "policy_graph_scope_denied",
                {"scope": scope, "allowed_scopes": allowed_scopes},
            )
        allowed_tools = child_policy.get("tools") or child_policy.get("allowed_tools") or []
        if requested_tools and allowed_tools:
            denied = [name for name in requested_tools if name not in allowed_tools]
            if denied:
                return AgenticDecision(
                    "block",
                    "policy_graph_tool_denied",
                    {"requested_tools": requested_tools, "denied_tools": denied},
                )
        return None

    def _child_policy(self, parent_id: str, agent_id: str) -> Optional[Dict[str, Any]]:
        parent_policy = self.cross_agent_policy_graph.get(parent_id)
        if parent_policy is None:
            return None
        if isinstance(parent_policy, list):
            return {} if agent_id in parent_policy else None
        if not isinstance(parent_policy, dict):
            return None
        children = parent_policy.get("children", parent_policy)
        child_policy = children.get(agent_id) if isinstance(children, dict) else None
        if child_policy is True:
            return {}
        if isinstance(child_policy, list):
            return {"tools": child_policy}
        if isinstance(child_policy, dict):
            return child_policy
        return None

    def _enforce_execution_grant(
        self,
        exec_id: str,
        parent_id: str,
        agent_id: str,
        scope: str,
        requested_tools: list[str],
    ) -> Optional[AgenticDecision]:
        if not self.require_execution_grant:
            return None
        if not exec_id:
            return AgenticDecision("block", "missing_execution_grant", {"header": self.execution_id_header})
        grant = self.execution_grants.get(exec_id)
        if not isinstance(grant, dict):
            return AgenticDecision("block", "missing_execution_grant", {"execution_id": exec_id})
        expires_at = self._parse_timestamp(str(grant.get("expires_at", "")))
        if expires_at is not None and time.time() > expires_at:
            return AgenticDecision("block", "expired_execution_grant", {"execution_id": exec_id})
        if grant.get("agent_id") and grant.get("agent_id") != agent_id:
            return AgenticDecision("block", "execution_grant_agent_mismatch", {"execution_id": exec_id})
        if grant.get("parent_agent") and grant.get("parent_agent") != parent_id:
            return AgenticDecision("block", "execution_grant_parent_mismatch", {"execution_id": exec_id})
        allowed_scopes = grant.get("scopes") or grant.get("allowed_scopes") or []
        if scope and allowed_scopes and scope not in allowed_scopes:
            return AgenticDecision("block", "execution_grant_scope_denied", {"scope": scope})
        allowed_tools = grant.get("tools") or grant.get("allowed_tools") or []
        if requested_tools and allowed_tools:
            denied = [name for name in requested_tools if name not in allowed_tools]
            if denied:
                return AgenticDecision(
                    "block",
                    "execution_grant_tool_denied",
                    {"requested_tools": requested_tools, "denied_tools": denied},
                )
        return None

    def _enforce_risk_adaptive_scope(self, threat_score: Optional[float], scope: str) -> Optional[AgenticDecision]:
        if not self.risk_adaptive_enabled or threat_score is None:
            return None
        if self.kill_switch_threat_score is not None and threat_score >= self.kill_switch_threat_score:
            return AgenticDecision(
                "block",
                "risk_kill_switch",
                {"threat_score": threat_score, "threshold": self.kill_switch_threat_score},
                severity="CRITICAL",
            )
        max_scope = ""
        max_threshold = -1.0
        for raw_threshold, threshold_scope in self.risk_scope_thresholds.items():
            threshold = self._optional_float(raw_threshold)
            if threshold is not None and threat_score >= threshold and threshold > max_threshold:
                max_threshold = threshold
                max_scope = str(threshold_scope)
        if scope and max_scope and self._scope_rank(scope) > self._scope_rank(max_scope):
            return AgenticDecision(
                "block",
                "dynamic_scope_tightening",
                {"threat_score": threat_score, "requested_scope": scope, "max_scope": max_scope},
            )
        return None

    def _verify_trace_hash(
        self,
        agent_id: str,
        parent_id: str,
        exec_id: str,
        scope: str,
        requested_tools: list[str],
        trace_prev_hash: str,
        trace_hash: str,
    ) -> Optional[AgenticDecision]:
        if not self.require_trace_hash:
            return None
        if not trace_hash:
            return AgenticDecision("block", "missing_trace_hash", {"header": self.trace_hash_header})
        expected = self.compute_trace_hash(
            agent_id=agent_id,
            parent_id=parent_id,
            exec_id=exec_id,
            scope=scope,
            requested_tools=requested_tools,
            prev_hash=trace_prev_hash,
        )
        if not hmac.compare_digest(expected, trace_hash):
            return AgenticDecision(
                "block",
                "trace_hash_mismatch",
                {"expected": expected, "provided": trace_hash},
            )
        if self.trace_replay_cache_enabled:
            seen = self._load_trace_replay_cache()
            if trace_hash in seen:
                return AgenticDecision("block", "trace_replay_detected", {"trace_hash": trace_hash})
            seen.append(trace_hash)
            self._write_trace_replay_cache(seen)
        return None

    @staticmethod
    def compute_trace_hash(
        agent_id: str,
        parent_id: str,
        exec_id: str,
        scope: str,
        requested_tools: list[str],
        prev_hash: str = "",
    ) -> str:
        material = json.dumps(
            {
                "agent_id": agent_id,
                "parent_agent": parent_id,
                "execution_id": exec_id,
                "scope": scope,
                "tools": sorted(requested_tools),
                "prev_hash": prev_hash,
            },
            sort_keys=True,
            separators=(",", ":"),
        )
        return hashlib.sha256(material.encode("utf-8")).hexdigest()

    def _enforce_identity_gate(self, agent_id: str) -> tuple[Optional[AgenticDecision], Dict[str, Any]]:
        """Point-of-interaction identity/tier check via the shared IdentityGate.

        Returns (block_decision_or_None, extra_allow_details). The second
        element is merged into the final allow decision's details dict when
        this check doesn't block, so a downstream caller (dashboard, log
        line) can see the tier that was actually checked — not just that the
        request was allowed.

        Fails open by design when misconfigured: require_agent_identity=true
        with no identity_gate wired in is a caller wiring mistake, not a
        traffic-blocking event — it's logged and skipped rather than
        silently enforced against an agent_id with no gate to check it, and
        rather than raising and taking the control plane down.
        """
        should_enforce = self.require_agent_identity or (self.require_agent_attestation and self.identity_gate is not None)
        if not should_enforce:
            return None, {}
        if self.identity_gate is None:
            return AgenticDecision("block", "identity_gate_unavailable", {"agent_id": agent_id}), {"identity_verified": None, "identity_gate_note": "require_agent_identity set but no gate wired"}

        result = self.identity_gate.check_agent(agent_id)
        if not result.allowed or (self.require_agent_attestation and result.source == "unregistered"):
            return (
                AgenticDecision(
                    "block",
                    "unregistered_or_low_trust_agent",
                    {"agent_id": agent_id, "identity_reason": result.reason, **result.as_details()},
                ),
                {},
            )
        return None, {"erc8004_tier": result.tier, "identity_verified": result.source != "disabled"}

    def _load_trace_replay_cache(self) -> list[str]:
        if not self.trace_replay_cache_file.exists():
            return []
        try:
            data = json.loads(self.trace_replay_cache_file.read_text(encoding="utf-8"))
        except Exception:
            return []
        if isinstance(data, list):
            return [str(v) for v in data]
        return [str(v) for v in data.get("seen_hashes", [])] if isinstance(data, dict) else []

    def _prune_chain_state(self) -> None:
        if not self._chain_state:
            return
        now = time.time()
        expired = [
            exec_id
            for exec_id, state in self._chain_state.items()
            if now - float(state.get("last_seen", state.get("created_at", now))) > self.chain_state_ttl_seconds
        ]
        for exec_id in expired:
            self._chain_state.pop(exec_id, None)

    def _trip_chain_circuit_breaker(self, exec_id: str) -> None:
        if not exec_id:
            return
        self._chain_circuit_breakers.add(exec_id)
        if not self.chain_circuit_breaker_write_kill_switch or not self.kill_switch_enabled:
            return
        snapshot = self._load_kill_switch()
        blocked = {str(v) for v in snapshot.get("blocked_execution_ids", [])}
        if exec_id in blocked:
            return
        blocked.add(exec_id)
        snapshot["blocked_execution_ids"] = sorted(blocked)
        snapshot.setdefault("blocked_agent_ids", [])
        snapshot.setdefault("global_pause", False)
        try:
            self.kill_switch_file.parent.mkdir(parents=True, exist_ok=True)
            self.kill_switch_file.write_text(json.dumps(snapshot, indent=2, sort_keys=True), encoding="utf-8")
        except Exception:
            pass

    def _refresh_control_plane(self) -> None:
        if not self.control_plane_file:
            return
        now = time.time()
        if now - self._control_plane_loaded_at < self.control_plane_reload_seconds:
            return
        self._control_plane_loaded_at = now
        try:
            mtime = self.control_plane_file.stat().st_mtime
        except OSError:
            return
        if mtime <= self._control_plane_mtime:
            return
        try:
            snapshot = json.loads(self.control_plane_file.read_text(encoding="utf-8"))
        except Exception:
            return
        self._control_plane_mtime = mtime
        agent_keys = snapshot.get("agent_attestation_keys")
        if isinstance(agent_keys, dict):
            self.agent_attestation_keys = agent_keys
        revoked_agents = snapshot.get("revoked_agent_ids")
        if isinstance(revoked_agents, list):
            self.revoked_agent_ids = {str(v).strip() for v in revoked_agents if str(v).strip()}
        revoked_keys = snapshot.get("revoked_agent_key_ids")
        if isinstance(revoked_keys, list):
            self.revoked_agent_key_ids = {str(v).strip() for v in revoked_keys if str(v).strip()}
        cert_fingerprints = snapshot.get("agent_cert_fingerprints")
        if isinstance(cert_fingerprints, dict):
            self.agent_cert_fingerprints = cert_fingerprints
        graph = snapshot.get("cross_agent_policy_graph")
        if isinstance(graph, dict):
            self.cross_agent_policy_graph = graph
        grants = snapshot.get("execution_grants")
        if isinstance(grants, dict):
            self.execution_grants = grants
        trace_cache = snapshot.get("trace_replay_cache")
        if isinstance(trace_cache, list) and self.trace_replay_cache_enabled:
            self._write_trace_replay_cache([str(v) for v in trace_cache])

    def _write_trace_replay_cache(self, seen: list[str]) -> None:
        try:
            self.trace_replay_cache_file.parent.mkdir(parents=True, exist_ok=True)
            self.trace_replay_cache_file.write_text(
                json.dumps({"seen_hashes": seen[-10000:]}, indent=2, sort_keys=True),
                encoding="utf-8",
            )
        except Exception:
            pass

    def _load_kill_switch(self) -> Dict[str, Any]:
        if not self.kill_switch_enabled:
            return {}
        if not self.kill_switch_file.exists():
            return {"global_pause": False, "blocked_agent_ids": [], "blocked_execution_ids": []}
        try:
            return json.loads(self.kill_switch_file.read_text(encoding="utf-8"))
        except Exception:
            return {"global_pause": False, "blocked_agent_ids": [], "blocked_execution_ids": []}
