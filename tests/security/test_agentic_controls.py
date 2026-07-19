import json
import base64
import hashlib
import hmac
import os
import pytest
import sys
import tempfile
import time
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..")))

from guardian.security.agentic_controls import AgenticSecurityManager, AgenticDecision


class TestAgenticSecurityManager:
    """Standalone unit test suite for testing AgenticSecurityManager security decisions."""

    @pytest.fixture
    def root_dir(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            yield Path(tmpdir)

    def test_disabled(self, root_dir):
        manager = AgenticSecurityManager({"enabled": False}, root_dir)
        headers = {"X-Guardian-Agent-Id": "agent-a"}
        decision = manager.evaluate(headers)
        assert decision.action == "allow"
        assert decision.reason == "disabled"

    def test_require_agent_id(self, root_dir):
        manager = AgenticSecurityManager({"enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False, "require_agent_id": True}, root_dir)

        # Missing Agent ID
        decision = manager.evaluate({})
        assert decision.action == "block"
        assert decision.reason == "missing_agent_id"

        # Invalid Agent ID (invalid character '@')
        decision = manager.evaluate({"X-Guardian-Agent-Id": "agent@invalid"})
        assert decision.action == "block"
        assert decision.reason == "invalid_agent_id"

        # Valid Agent ID
        decision = manager.evaluate({"X-Guardian-Agent-Id": "agent-valid_123.abc:xyz"})
        assert decision.action == "allow"
        assert decision.reason == "ok"

    def test_require_execution_id(self, root_dir):
        manager = AgenticSecurityManager(
            {"enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False, "require_agent_id": False, "require_execution_id": True}, root_dir
        )

        # Missing Execution ID
        decision = manager.evaluate({})
        assert decision.action == "block"
        assert decision.reason == "missing_execution_id"

        # Valid Execution ID
        decision = manager.evaluate({"X-Guardian-Exec-Id": "exec-123"})
        assert decision.action == "allow"
        assert decision.reason == "ok"

    def test_require_scope(self, root_dir):
        manager = AgenticSecurityManager(
            {"enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False, "require_agent_id": False, "require_scope": True}, root_dir
        )

        # Missing Scope
        decision = manager.evaluate({})
        assert decision.action == "block"
        assert decision.reason == "missing_scope"

        # Valid Scope
        decision = manager.evaluate({"X-Guardian-Agent-Scope": "standard"})
        assert decision.action == "allow"
        assert decision.reason == "ok"

    def test_hop_limit(self, root_dir):
        manager = AgenticSecurityManager(
            {"enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False, "require_agent_id": False, "max_hops": 5}, root_dir
        )

        # Exceeds max hops
        decision = manager.evaluate({"X-Guardian-Agent-Hop": "6"})
        assert decision.action == "block"
        assert decision.reason == "hop_limit_exceeded"

        # Equals max hops
        decision = manager.evaluate({"X-Guardian-Agent-Hop": "5"})
        assert decision.action == "allow"

        # Less than max hops
        decision = manager.evaluate({"X-Guardian-Agent-Hop": "3"})
        assert decision.action == "allow"

        # Invalid hop integer (ignored, treats hop count as None)
        decision = manager.evaluate({"X-Guardian-Agent-Hop": "abc"})
        assert decision.action == "allow"

    def test_parent_child_routes(self, root_dir):
        config = {
            "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
            "require_agent_id": False,
            "allowed_parent_child": {
                "parent-a": ["child-a1", "child-a2"],
                "parent-b": ["child-b1"],
            },
        }
        manager = AgenticSecurityManager(config, root_dir)

        # Allowed hop parent-a -> child-a1
        headers = {
            "X-Guardian-Agent-Parent": "parent-a",
            "X-Guardian-Agent-Id": "child-a1",
        }
        decision = manager.evaluate(headers)
        assert decision.action == "allow"

        # Unauthorized hop parent-a -> child-b1
        headers = {
            "X-Guardian-Agent-Parent": "parent-a",
            "X-Guardian-Agent-Id": "child-b1",
        }
        decision = manager.evaluate(headers)
        assert decision.action == "block"
        assert decision.reason == "unauthorized_agent_hop"

    def test_scope_tool_allowlist(self, root_dir):
        config = {
            "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
            "require_agent_id": False,
            "scope_tool_allowlist": {
                "read_only": ["search_docs", "view_profile"],
                "privileged": ["wire_transfer"],
            },
        }
        manager = AgenticSecurityManager(config, root_dir)

        data = {
            "tools": [
                {"type": "function", "function": {"name": "search_docs"}},
                {"type": "function", "function": {"name": "view_profile"}},
            ]
        }

        # Allowed tools for read_only scope
        headers = {"X-Guardian-Agent-Scope": "read_only"}
        decision = manager.evaluate(headers, data)
        assert decision.action == "allow"

        # Denied tool (wire_transfer) for read_only scope
        data_violating = {
            "tools": [
                {"type": "function", "function": {"name": "search_docs"}},
                {"type": "function", "function": {"name": "wire_transfer"}},
            ]
        }
        decision = manager.evaluate(headers, data_violating)
        assert decision.action == "block"
        assert decision.reason == "scope_tool_violation"
        assert "wire_transfer" in decision.details["denied_tools"]

    def test_require_mcp_server_for_tools(self, root_dir):
        config = {
            "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
            "require_agent_id": False,
            "require_mcp_server_for_tools": True,
        }
        manager = AgenticSecurityManager(config, root_dir)
        data = {"tools": [{"type": "function", "function": {"name": "search_docs"}}]}

        # Blocked: requested tool but missing X-Guardian-MCP-Server header
        decision = manager.evaluate({}, data)
        assert decision.action == "block"
        assert decision.reason == "missing_mcp_server"

        # Allowed: provided X-Guardian-MCP-Server header
        decision = manager.evaluate({"X-Guardian-MCP-Server": "mcp://trusted-server"}, data)
        assert decision.action == "allow"

    def test_untrusted_mcp_server(self, root_dir):
        config = {
            "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
            "require_agent_id": False,
            "trusted_mcp_servers": ["mcp://trusted-a", "mcp://trusted-b"],
        }
        manager = AgenticSecurityManager(config, root_dir)

        # Untrusted server
        decision = manager.evaluate({"X-Guardian-MCP-Server": "mcp://untrusted"})
        assert decision.action == "block"
        assert decision.reason == "untrusted_mcp_server"

        # Trusted server
        decision = manager.evaluate({"X-Guardian-MCP-Server": "mcp://trusted-a"})
        assert decision.action == "allow"

    def test_mcp_server_tool_allowlist(self, root_dir):
        config = {
            "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
            "require_agent_id": False,
            "mcp_server_tool_allowlist": {
                "mcp://trusted-a": ["search_docs"],
            },
        }
        manager = AgenticSecurityManager(config, root_dir)
        data_allowed = {"tools": [{"type": "function", "function": {"name": "search_docs"}}]}
        data_denied = {"tools": [{"type": "function", "function": {"name": "wire_transfer"}}]}

        # Allowed
        decision = manager.evaluate({"X-Guardian-MCP-Server": "mcp://trusted-a"}, data_allowed)
        assert decision.action == "allow"

        # Denied tool violation
        decision = manager.evaluate({"X-Guardian-MCP-Server": "mcp://trusted-a"}, data_denied)
        assert decision.action == "block"
        assert decision.reason == "mcp_tool_violation"

    def test_scope_escalation(self, root_dir):
        config = {
            "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
            "require_agent_id": False,
            "enforce_scope_non_escalation": True,
            "scope_hierarchy": {"read_only": 0, "standard": 1, "privileged": 2},
        }
        manager = AgenticSecurityManager(config, root_dir)

        # Escalation: child scope 'privileged' is higher than parent scope 'read_only'
        headers_escalating = {
            "X-Guardian-Agent-Parent-Scope": "read_only",
            "X-Guardian-Agent-Scope": "privileged",
        }
        decision = manager.evaluate(headers_escalating)
        assert decision.action == "block"
        assert decision.reason == "scope_escalation_detected"

        # Non-escalating: child scope 'standard' is lower than parent scope 'privileged'
        headers_safe = {
            "X-Guardian-Agent-Parent-Scope": "privileged",
            "X-Guardian-Agent-Scope": "standard",
        }
        decision = manager.evaluate(headers_safe)
        assert decision.action == "allow"

    def test_kill_switches(self, root_dir):
        kill_file = root_dir / "agent_kill_switch.json"
        
        config = {
            "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
            "require_agent_id": False,
            "kill_switch_enabled": True,
            "kill_switch_file": str(kill_file.relative_to(root_dir)),
        }
        
        manager = AgenticSecurityManager(config, root_dir)

        # Scenario 1: Global Pause
        kill_file.write_text(
            json.dumps({"global_pause": True, "blocked_agent_ids": [], "blocked_execution_ids": []}),
            encoding="utf-8",
        )
        decision = manager.evaluate({})
        assert decision.action == "block"
        assert decision.reason == "global_pause_enabled"

        # Scenario 2: Blocked Agent ID
        kill_file.write_text(
            json.dumps({"global_pause": False, "blocked_agent_ids": ["blocked-agent"], "blocked_execution_ids": []}),
            encoding="utf-8",
        )
        decision = manager.evaluate({"X-Guardian-Agent-Id": "blocked-agent"})
        assert decision.action == "block"
        assert decision.reason == "agent_kill_switch"

        # Scenario 3: Blocked Execution ID
        kill_file.write_text(
            json.dumps({"global_pause": False, "blocked_agent_ids": [], "blocked_execution_ids": ["blocked-exec"]}),
            encoding="utf-8",
        )
        decision = manager.evaluate({"X-Guardian-Exec-Id": "blocked-exec"})
        assert decision.action == "block"
        assert decision.reason == "execution_kill_switch"

        # Scenario 4: Allowed
        decision = manager.evaluate({"X-Guardian-Agent-Id": "allowed-agent", "X-Guardian-Exec-Id": "allowed-exec"})
        assert decision.action == "allow"

    def test_agent_attestation_and_revocation(self, root_dir):
        ts = str(time.time())
        material = AgenticSecurityManager._attestation_material("agent-a", "exec-1", "standard", "key-1", ts)
        sig = hmac.new(b"secret-a", material.encode("utf-8"), hashlib.sha256).hexdigest()
        manager = AgenticSecurityManager(
            {
                "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
                "require_agent_attestation": True,
                "agent_attestation_keys": {"agent-a": {"key-1": "secret-a"}},
                "revoked_agent_ids": ["agent-revoked"],
                "revoked_agent_key_ids": ["key-revoked"],
            },
            root_dir,
        )

        headers = {
            "X-Guardian-Agent-Id": "agent-a",
            "X-Guardian-Exec-Id": "exec-1",
            "X-Guardian-Agent-Scope": "standard",
            "X-Guardian-Agent-Key-Id": "key-1",
            "X-Guardian-Agent-Attestation-Ts": ts,
            "X-Guardian-Agent-Attestation": f"sha256={sig}",
        }
        assert manager.evaluate(headers).action == "allow"

        bad_headers = dict(headers)
        bad_headers["X-Guardian-Agent-Attestation"] = "sha256=bad"
        decision = manager.evaluate(bad_headers)
        assert decision.action == "block"
        assert decision.reason == "invalid_agent_attestation"

        decision = manager.evaluate({"X-Guardian-Agent-Id": "agent-revoked"})
        assert decision.action == "block"
        assert decision.reason == "revoked_agent_identity"

        revoked_key_headers = dict(headers)
        revoked_key_headers["X-Guardian-Agent-Key-Id"] = "key-revoked"
        decision = manager.evaluate(revoked_key_headers)
        assert decision.action == "block"
        assert decision.reason == "revoked_agent_key"

    def test_jwt_agent_attestation(self, root_dir):
        def b64url(payload: bytes) -> str:
            return base64.urlsafe_b64encode(payload).decode("ascii").rstrip("=")

        header = {"alg": "HS256", "typ": "JWT", "kid": "key-1"}
        payload = {
            "sub": "agent-a",
            "execution_id": "exec-1",
            "scope": "standard",
            "key_id": "key-1",
            "iat": time.time(),
            "exp": time.time() + 60,
        }
        signing_input = (
            f"{b64url(json.dumps(header, separators=(',', ':'), sort_keys=True).encode('utf-8'))}."
            f"{b64url(json.dumps(payload, separators=(',', ':'), sort_keys=True).encode('utf-8'))}"
        )
        sig = hmac.new(b"secret-a", signing_input.encode("utf-8"), hashlib.sha256).digest()
        token = f"{signing_input}.{b64url(sig)}"
        manager = AgenticSecurityManager(
            {
                "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
                "require_agent_attestation": True,
                "agent_attestation_keys": {"agent-a": {"key-1": "secret-a"}},
            },
            root_dir,
        )

        headers = {
            "X-Guardian-Agent-Id": "agent-a",
            "X-Guardian-Exec-Id": "exec-1",
            "X-Guardian-Agent-Scope": "standard",
            "X-Guardian-Agent-Key-Id": "key-1",
            "X-Guardian-Agent-Attestation": f"Bearer {token}",
        }
        assert manager.evaluate(headers).action == "allow"

        bad_headers = dict(headers)
        bad_headers["X-Guardian-Agent-Scope"] = "privileged"
        decision = manager.evaluate(bad_headers)
        assert decision.action == "block"
        assert decision.reason == "agent_attestation_scope_mismatch"

    def test_mtls_fingerprint_binding(self, root_dir):
        manager = AgenticSecurityManager(
            {
                "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
                "require_agent_id": True,
                "require_mtls": True,
                "agent_cert_fingerprints": {
                    "agent-a": ["AA:BB:CC"],
                },
            },
            root_dir,
        )

        headers = {
            "X-Guardian-Agent-Id": "agent-a",
            "X-Guardian-mTLS-Verified": "SUCCESS",
            "X-Guardian-mTLS-Fingerprint": "aa bb cc",
            "X-Guardian-mTLS-Subject": "CN=agent-a",
        }
        assert manager.evaluate(headers).action == "allow"

        missing = manager.evaluate({"X-Guardian-Agent-Id": "agent-a"})
        assert missing.action == "block"
        assert missing.reason == "missing_mtls_verification"

        mismatch_headers = dict(headers)
        mismatch_headers["X-Guardian-mTLS-Fingerprint"] = "dd:ee:ff"
        mismatch = manager.evaluate(mismatch_headers)
        assert mismatch.action == "block"
        assert mismatch.reason == "mtls_fingerprint_mismatch"

    def test_cross_agent_policy_graph_is_deny_by_default(self, root_dir):
        manager = AgenticSecurityManager(
            {
                "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
                "require_agent_id": False,
                "enforce_policy_graph": True,
                "cross_agent_policy_graph": {
                    "parent-a": {
                        "children": {
                            "child-a": {
                                "scopes": ["read_only"],
                                "tools": ["search_docs"],
                                "max_hops": 2,
                            }
                        }
                    }
                },
            },
            root_dir,
        )
        payload = {"tools": [{"type": "function", "function": {"name": "search_docs"}}]}
        headers = {
            "X-Guardian-Agent-Parent": "parent-a",
            "X-Guardian-Agent-Id": "child-a",
            "X-Guardian-Agent-Scope": "read_only",
            "X-Guardian-Agent-Hop": "2",
        }
        assert manager.evaluate(headers, payload).action == "allow"

        denied_headers = dict(headers)
        denied_headers["X-Guardian-Agent-Id"] = "child-b"
        decision = manager.evaluate(denied_headers, payload)
        assert decision.action == "block"
        assert decision.reason == "policy_graph_hop_denied"

        denied_tool = {"tools": [{"type": "function", "function": {"name": "wire_transfer"}}]}
        decision = manager.evaluate(headers, denied_tool)
        assert decision.action == "block"
        assert decision.reason == "policy_graph_tool_denied"

    def test_time_bounded_execution_grants(self, root_dir):
        manager = AgenticSecurityManager(
            {
                "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
                "require_agent_id": False,
                "require_execution_grant": True,
                "execution_grants": {
                    "exec-allowed": {
                        "agent_id": "agent-a",
                        "parent_agent": "parent-a",
                        "scopes": ["read_only"],
                        "tools": ["search_docs"],
                        "expires_at": str(time.time() + 60),
                    },
                    "exec-expired": {
                        "agent_id": "agent-a",
                        "expires_at": str(time.time() - 60),
                    },
                },
            },
            root_dir,
        )
        payload = {"tools": [{"type": "function", "function": {"name": "search_docs"}}]}
        headers = {
            "X-Guardian-Agent-Parent": "parent-a",
            "X-Guardian-Agent-Id": "agent-a",
            "X-Guardian-Exec-Id": "exec-allowed",
            "X-Guardian-Agent-Scope": "read_only",
        }
        assert manager.evaluate(headers, payload).action == "allow"

        expired = dict(headers)
        expired["X-Guardian-Exec-Id"] = "exec-expired"
        decision = manager.evaluate(expired, payload)
        assert decision.action == "block"
        assert decision.reason == "expired_execution_grant"

    def test_trace_hash_integrity_and_replay_cache(self, root_dir):
        cache_file = root_dir / "trace_hashes.json"
        manager = AgenticSecurityManager(
            {
                "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
                "require_agent_id": False,
                "require_trace_hash": True,
                "trace_replay_cache_enabled": True,
                "trace_replay_cache_file": str(cache_file.relative_to(root_dir)),
            },
            root_dir,
        )
        payload = {"tools": [{"type": "function", "function": {"name": "search_docs"}}]}
        trace_hash = AgenticSecurityManager.compute_trace_hash(
            agent_id="agent-a",
            parent_id="parent-a",
            exec_id="exec-1",
            scope="read_only",
            requested_tools=["search_docs"],
            prev_hash="root",
        )
        headers = {
            "X-Guardian-Agent-Parent": "parent-a",
            "X-Guardian-Agent-Id": "agent-a",
            "X-Guardian-Exec-Id": "exec-1",
            "X-Guardian-Agent-Scope": "read_only",
            "X-Guardian-Trace-Prev-Hash": "root",
            "X-Guardian-Trace-Hash": trace_hash,
        }
        assert manager.evaluate(headers, payload).action == "allow"

        replay = manager.evaluate(headers, payload)
        assert replay.action == "block"
        assert replay.reason == "trace_replay_detected"

        bad_headers = dict(headers)
        bad_headers["X-Guardian-Trace-Hash"] = "bad"
        decision = manager.evaluate(bad_headers, payload)
        assert decision.action == "block"
        assert decision.reason == "trace_hash_mismatch"

    def test_risk_adaptive_scope_tightening_and_kill_switch(self, root_dir):
        manager = AgenticSecurityManager(
            {
                "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
                "require_agent_id": False,
                "risk_adaptive_enabled": True,
                "risk_scope_thresholds": {"0.70": "read_only"},
                "kill_switch_threat_score": 0.95,
                "scope_hierarchy": {"read_only": 0, "standard": 1, "privileged": 2},
            },
            root_dir,
        )
        decision = manager.evaluate(
            {"X-Guardian-Threat-Score": "0.80", "X-Guardian-Agent-Scope": "privileged"}
        )
        assert decision.action == "block"
        assert decision.reason == "dynamic_scope_tightening"

        decision = manager.evaluate(
            {"X-Guardian-Threat-Score": "0.96", "X-Guardian-Agent-Scope": "read_only"}
        )
        assert decision.action == "block"
        assert decision.reason == "risk_kill_switch"

    def test_lateral_movement_detects_task_scope_drift(self, root_dir):
        manager = AgenticSecurityManager(
            {
                "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
                "require_agent_id": False,
                "lateral_movement_detection_enabled": True,
                "max_scope_rank_drift": 0,
                "chain_circuit_breaker_threshold": 3,
                "scope_hierarchy": {"read_only": 0, "standard": 1, "privileged": 2},
            },
            root_dir,
        )

        first = manager.evaluate(
            {
                "X-Guardian-Exec-Id": "exec-lateral-1",
                "X-Guardian-Agent-Id": "agent-a",
                "X-Guardian-Agent-Scope": "read_only",
            }
        )
        assert first.action == "allow"

        drift = manager.evaluate(
            {
                "X-Guardian-Exec-Id": "exec-lateral-1",
                "X-Guardian-Agent-Id": "agent-a",
                "X-Guardian-Agent-Scope": "privileged",
            }
        )
        assert drift.action == "block"
        assert drift.reason == "multi_agent_lateral_movement_detected"
        assert drift.details["violations"][0]["type"] == "task_scope_drift"

    def test_lateral_movement_detects_agent_parent_change(self, root_dir):
        manager = AgenticSecurityManager(
            {
                "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
                "require_agent_id": False,
                "lateral_movement_detection_enabled": True,
                "chain_circuit_breaker_threshold": 3,
            },
            root_dir,
        )

        headers = {
            "X-Guardian-Exec-Id": "exec-lateral-2",
            "X-Guardian-Agent-Parent": "planner-a",
            "X-Guardian-Agent-Id": "worker-a",
            "X-Guardian-Agent-Scope": "read_only",
        }
        assert manager.evaluate(headers).action == "allow"

        hijacked = dict(headers)
        hijacked["X-Guardian-Agent-Parent"] = "unknown-parent"
        decision = manager.evaluate(hijacked)
        assert decision.action == "block"
        assert decision.reason == "multi_agent_lateral_movement_detected"
        assert decision.details["violations"][0]["type"] == "agent_parent_changed"

    def test_lateral_movement_trips_execution_circuit_breaker(self, root_dir):
        kill_file = root_dir / "agent_kill_switch.json"
        manager = AgenticSecurityManager(
            {
                "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
                "require_agent_id": False,
                "lateral_movement_detection_enabled": True,
                "chain_circuit_breaker_threshold": 2,
                "kill_switch_enabled": True,
                "kill_switch_file": str(kill_file.relative_to(root_dir)),
                "scope_hierarchy": {"read_only": 0, "standard": 1, "privileged": 2},
            },
            root_dir,
        )

        baseline_headers = {
            "X-Guardian-Exec-Id": "exec-lateral-breaker",
            "X-Guardian-Agent-Parent": "planner-a",
            "X-Guardian-Agent-Id": "worker-a",
            "X-Guardian-Agent-Scope": "read_only",
        }
        assert manager.evaluate(baseline_headers).action == "allow"

        drift_headers = dict(baseline_headers)
        drift_headers["X-Guardian-Agent-Scope"] = "privileged"
        first_violation = manager.evaluate(drift_headers)
        assert first_violation.action == "block"
        assert first_violation.reason == "multi_agent_lateral_movement_detected"

        second_drift = dict(drift_headers)
        second_drift["X-Guardian-Agent-Parent"] = "unknown-parent"
        breaker = manager.evaluate(second_drift)
        assert breaker.action == "block"
        assert breaker.reason == "chain_circuit_breaker_tripped"

        kill_snapshot = json.loads(kill_file.read_text(encoding="utf-8"))
        assert "exec-lateral-breaker" in kill_snapshot["blocked_execution_ids"]

        later = manager.evaluate(
            {
                "X-Guardian-Exec-Id": "exec-lateral-breaker",
                "X-Guardian-Agent-Id": "another-agent",
            }
        )
        assert later.action == "block"
        assert later.reason == "execution_chain_circuit_breaker"

    def test_control_plane_file_reload_updates_revocations_and_grants(self, root_dir):
        control_file = root_dir / "agentic_control_plane.json"
        control_file.write_text(
            json.dumps(
                {
                    "revoked_agent_ids": ["agent-revoked"],
                    "execution_grants": {
                        "exec-allowed": {
                            "agent_id": "agent-a",
                            "tools": ["search_docs"],
                            "expires_at": time.time() + 60,
                        }
                    },
                }
            ),
            encoding="utf-8",
        )
        manager = AgenticSecurityManager(
            {
                "enabled": True, "enforce_policy_graph": False, "enforce_scope_non_escalation": False,
                "require_agent_id": False,
                "require_execution_grant": True,
                "control_plane_file": str(control_file.relative_to(root_dir)),
                "control_plane_reload_seconds": 0,
            },
            root_dir,
        )

        payload = {"tools": [{"type": "function", "function": {"name": "search_docs"}}]}
        decision = manager.evaluate(
            {"X-Guardian-Agent-Id": "agent-a", "X-Guardian-Exec-Id": "exec-allowed"},
            payload,
        )
        assert decision.action == "allow"

        revoked = manager.evaluate({"X-Guardian-Agent-Id": "agent-revoked"})
        assert revoked.action == "block"
        assert revoked.reason == "revoked_agent_identity"
