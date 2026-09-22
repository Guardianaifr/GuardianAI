"""
Comprehensive tests for all Phase 5 remaining items:
  - Item 10: Credential Rotation + Anomaly Profiling
  - Item 11: Execution Sandbox with Resource Limits
  - Item 12: Cross-Agent Graph Drift Tracking
  - Item 14: Shadow AI Detection
  - Item 15: Deep Binary Model Scanner
  - Item 18: SIEM Mapping Packs + DLQ Replay
"""

import json
import os
import struct
import tempfile
import time

import pytest


# ══════════════════════════════════════════════════════════════════════════════
# Item 10: Non-Human Identity Credential Rotation & Anomaly Profiling
# ══════════════════════════════════════════════════════════════════════════════

from guardian.security.credential_rotation import (
    CredentialRotationPolicy,
    AgentBehaviorAnomalyProfiler,
)


class TestCredentialRotationPolicy:
    def test_issue_and_validate(self):
        policy = CredentialRotationPolicy(ttl_seconds=3600)
        policy.issue_credential("agent-1", "secret-abc")
        assert policy.is_valid("agent-1", "secret-abc") is True

    def test_wrong_secret_rejected(self):
        policy = CredentialRotationPolicy(ttl_seconds=3600)
        policy.issue_credential("agent-1", "correct")
        assert policy.is_valid("agent-1", "wrong") is False

    def test_unknown_agent_rejected(self):
        policy = CredentialRotationPolicy(ttl_seconds=3600)
        assert policy.is_valid("nonexistent", "any") is False

    def test_ttl_expiry(self):
        policy = CredentialRotationPolicy(ttl_seconds=1)
        policy.issue_credential("agent-1", "secret")
        assert policy.is_valid("agent-1", "secret") is True
        time.sleep(1.1)
        assert policy.is_valid("agent-1", "secret") is False

    def test_rotation_invalidates_old_secret(self):
        policy = CredentialRotationPolicy(ttl_seconds=3600)
        policy.issue_credential("agent-1", "old-secret")
        policy.rotate_credential("agent-1", "new-secret")
        assert policy.is_valid("agent-1", "new-secret") is True
        assert policy.is_valid("agent-1", "old-secret") is False

    def test_cron_rotation_trigger(self):
        policy = CredentialRotationPolicy(ttl_seconds=10)
        now = time.time()
        policy.issue_credential("agent-1", "s1")
        policy.issue_credential("agent-2", "s2")
        # Simulate time passing beyond TTL
        rotated = policy.trigger_cron_rotation(now + 15)
        assert "agent-1" in rotated
        assert "agent-2" in rotated

    def test_cron_no_rotation_before_expiry(self):
        policy = CredentialRotationPolicy(ttl_seconds=3600)
        now = time.time()
        policy.issue_credential("agent-1", "s1")
        rotated = policy.trigger_cron_rotation(now + 10)
        assert len(rotated) == 0


class TestAnomalyProfiler:
    def test_first_endpoint_not_anomalous(self):
        profiler = AgentBehaviorAnomalyProfiler()
        result = profiler.log_api_call("agent-1", "/api/v1/scan", 1.0)
        assert result["is_anomalous"] is False

    def test_new_endpoint_triggers_anomaly(self):
        profiler = AgentBehaviorAnomalyProfiler()
        profiler.log_api_call("agent-1", "/api/v1/scan", 1.0)
        result = profiler.log_api_call("agent-1", "/api/v1/admin", 2.0)
        assert result["is_anomalous"] is True
        assert any("endpoint" in a.lower() for a in result["anomalies"])

    def test_frequency_spike_detection(self):
        profiler = AgentBehaviorAnomalyProfiler(alpha=0.5, threshold=2.0)
        # Establish baseline: 1 call/second
        for i in range(5):
            profiler.log_api_call("agent-1", "/api/v1/scan", float(i))
        # Spike: call 100x faster
        result = profiler.log_api_call("agent-1", "/api/v1/scan", 4.01)
        assert result["is_anomalous"] is True
        assert any("frequency" in a.lower() for a in result["anomalies"])

    def test_normal_rate_not_anomalous(self):
        profiler = AgentBehaviorAnomalyProfiler()
        # Regular 1-second interval calls
        for i in range(10):
            result = profiler.log_api_call("agent-1", "/api/v1/scan", float(i))
        # The last call at a steady rate should not be anomalous (ignoring new-endpoint check)
        # After baseline, same endpoint, same rate → no anomaly
        result = profiler.log_api_call("agent-1", "/api/v1/scan", 10.0)
        assert result["is_anomalous"] is False


# ══════════════════════════════════════════════════════════════════════════════
# Item 11: Dynamic Code Execution Safety (Sandbox)
# ══════════════════════════════════════════════════════════════════════════════

from guardian.runtime.execution_sandbox import (
    ExecutionSandbox,
    ExecutionStatus,
    SandboxConfig,
)


class TestExecutionSandbox:
    def test_safe_code_succeeds(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute("print('hello world')")
        assert result.status == ExecutionStatus.SUCCESS
        assert "hello world" in result.stdout

    def test_math_computation(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute("import math\nprint(math.sqrt(144))")
        assert result.status == ExecutionStatus.SUCCESS
        assert "12" in result.stdout

    def test_blocked_os_import(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute("import os\nos.system('whoami')")
        assert result.status == ExecutionStatus.POLICY_VIOLATION
        assert any("os" in v for v in result.violations)

    def test_blocked_subprocess_import(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute("import subprocess\nsubprocess.run(['ls'])")
        assert result.status == ExecutionStatus.POLICY_VIOLATION
        assert any("subprocess" in v for v in result.violations)

    def test_blocked_eval_call(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute("eval('1+1')")
        assert result.status == ExecutionStatus.POLICY_VIOLATION
        assert any("eval" in v for v in result.violations)

    def test_blocked_exec_call(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute("exec('print(1)')")
        assert result.status == ExecutionStatus.POLICY_VIOLATION
        assert any("exec" in v for v in result.violations)

    def test_syntax_error_detected(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute("def (invalid syntax")
        assert result.status == ExecutionStatus.POLICY_VIOLATION
        assert any("syntax" in v.lower() for v in result.violations)

    def test_timeout_enforcement(self):
        sandbox = ExecutionSandbox(SandboxConfig(timeout_seconds=2))
        result = sandbox.execute("while True: pass")
        assert result.status == ExecutionStatus.TIMEOUT

    def test_runtime_error_captured(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute("x = 1 / 0")
        assert result.status == ExecutionStatus.ERROR
        assert "ZeroDivision" in result.stderr

    def test_result_to_dict(self):
        sandbox = ExecutionSandbox()
        result = sandbox.execute("print('test')")
        d = result.to_dict()
        assert "status" in d
        assert "stdout" in d
        assert "duration_ms" in d

    def test_config_defaults(self):
        config = SandboxConfig()
        assert config.timeout_seconds == 30
        assert config.memory_limit_mb == 256
        assert config.cpu_limit_seconds == 10


# ══════════════════════════════════════════════════════════════════════════════
# Item 12: Cross-Agent Graph Drift Tracking
# ══════════════════════════════════════════════════════════════════════════════

from guardian.security.agent_graph_tracking import (
    AgentGraphDriftTracker,
    DriftSeverity,
)


class TestAgentGraphDriftTracker:
    def test_baseline_edge_no_alert(self):
        tracker = AgentGraphDriftTracker(density_threshold=0.8)
        tracker.register_baseline_edge("A", "B")
        alerts = tracker.record_communication("A", "B")
        assert len(alerts) == 0

    def test_unexpected_edge_triggers_alert(self):
        tracker = AgentGraphDriftTracker()
        tracker.register_baseline_edge("A", "B")
        alerts = tracker.record_communication("A", "C")
        assert len(alerts) >= 1
        assert any(a.alert_type == "new_unexpected_edge" for a in alerts)

    def test_hub_formation_alert(self):
        tracker = AgentGraphDriftTracker(hub_degree_threshold=3)
        # Agent "hub" connects to many agents
        for i in range(5):
            tracker.record_communication("hub", f"target-{i}")
        alerts = tracker.get_alerts()
        assert any(a.alert_type == "hub_formation" for a in alerts)

    def test_density_drift_alert(self):
        tracker = AgentGraphDriftTracker(density_threshold=0.3)
        # Create a dense graph (3 nodes, all connected = density 1.0)
        for src in ["A", "B", "C"]:
            for tgt in ["A", "B", "C"]:
                if src != tgt:
                    tracker.record_communication(src, tgt)
        alerts = tracker.get_alerts()
        assert any(a.alert_type == "density_drift" for a in alerts)

    def test_cycle_detection(self):
        tracker = AgentGraphDriftTracker()
        tracker.record_communication("A", "B")
        tracker.record_communication("B", "C")
        alerts = tracker.record_communication("C", "A")  # creates cycle
        assert any(a.alert_type == "cycle_introduced" for a in alerts)

    def test_snapshot(self):
        tracker = AgentGraphDriftTracker()
        tracker.register_baseline_edge("A", "B")
        tracker.record_communication("A", "B")
        tracker.record_communication("A", "C")
        snap = tracker.get_current_snapshot()
        assert snap["node_count"] == 3
        assert snap["edge_count"] == 2
        assert ("A", "C") in snap["unexpected_edges"]

    def test_reset(self):
        tracker = AgentGraphDriftTracker()
        tracker.record_communication("A", "B")
        tracker.reset()
        snap = tracker.get_current_snapshot()
        assert snap["node_count"] == 0
        assert snap["edge_count"] == 0

    def test_alert_to_dict(self):
        tracker = AgentGraphDriftTracker()
        alerts = tracker.record_communication("X", "Y")
        for alert in alerts:
            d = alert.to_dict()
            assert "alert_type" in d
            assert "severity" in d


# ══════════════════════════════════════════════════════════════════════════════
# Item 14: Shadow AI Detection
# ══════════════════════════════════════════════════════════════════════════════

from guardian.security.shadow_ai import ShadowAIDetector, AlertSeverity


class TestShadowAIDetector:
    def test_detect_openai(self):
        detector = ShadowAIDetector()
        alerts = detector.inspect_request("tenant-1", "https://api.openai.com/v1/chat/completions")
        assert len(alerts) >= 1
        assert alerts[0].provider == "OpenAI"

    def test_detect_anthropic(self):
        detector = ShadowAIDetector()
        alerts = detector.inspect_request("tenant-1", "https://api.anthropic.com/v1/messages")
        assert len(alerts) >= 1
        assert alerts[0].provider == "Anthropic"

    def test_detect_azure_openai(self):
        detector = ShadowAIDetector()
        alerts = detector.inspect_request(
            "tenant-1", "https://myinstance.openai.azure.com/openai/deployments/gpt-4/completions"
        )
        assert len(alerts) >= 1
        assert alerts[0].provider == "Azure OpenAI"

    def test_detect_aws_bedrock(self):
        detector = ShadowAIDetector()
        alerts = detector.inspect_request(
            "tenant-1", "https://bedrock-runtime.us-east-1.amazonaws.com/model/invoke"
        )
        assert len(alerts) >= 1
        assert alerts[0].provider == "AWS Bedrock"

    def test_detect_cohere(self):
        detector = ShadowAIDetector()
        alerts = detector.inspect_request("tenant-1", "https://api.cohere.ai/v1/generate")
        assert len(alerts) >= 1
        assert alerts[0].provider == "Cohere"

    def test_detect_via_header(self):
        detector = ShadowAIDetector()
        alerts = detector.inspect_request(
            "tenant-1",
            "https://proxy.example.com/llm",
            headers={"x-anthropic-version": "2024-01-01"},
        )
        assert len(alerts) >= 1
        assert any("header" in a.detection_method for a in alerts)

    def test_clean_request_no_alert(self):
        detector = ShadowAIDetector()
        alerts = detector.inspect_request("tenant-1", "https://www.google.com/search?q=hello")
        assert len(alerts) == 0

    def test_allowlisted_provider_ignored(self):
        detector = ShadowAIDetector(allowed_providers={"OpenAI"})
        alerts = detector.inspect_request("tenant-1", "https://api.openai.com/v1/chat")
        assert len(alerts) == 0

    def test_allow_provider_dynamically(self):
        detector = ShadowAIDetector()
        detector.allow_provider("Anthropic")
        alerts = detector.inspect_request("tenant-1", "https://api.anthropic.com/v1/messages")
        assert len(alerts) == 0

    def test_tenant_stats(self):
        detector = ShadowAIDetector()
        detector.inspect_request("tenant-1", "https://api.openai.com/v1/chat")
        detector.inspect_request("tenant-1", "https://api.openai.com/v1/embeddings")
        stats = detector.get_tenant_stats("tenant-1")
        assert stats.get("OpenAI", 0) == 2

    def test_summary(self):
        detector = ShadowAIDetector()
        detector.inspect_request("t1", "https://api.openai.com/v1/chat")
        detector.inspect_request("t2", "https://api.anthropic.com/v1/messages")
        summary = detector.get_summary()
        assert summary["total_alerts"] == 2
        assert summary["tenants_affected"] == 2

    def test_alert_to_dict(self):
        detector = ShadowAIDetector()
        alerts = detector.inspect_request("t1", "https://api.openai.com/v1/chat")
        d = alerts[0].to_dict()
        assert d["tenant_id"] == "t1"
        assert d["provider"] == "OpenAI"

    def test_detect_groq(self):
        detector = ShadowAIDetector()
        alerts = detector.inspect_request("t1", "https://api.groq.com/openai/v1/chat")
        assert len(alerts) >= 1
        assert alerts[0].provider == "Groq"

    def test_detect_mistral(self):
        detector = ShadowAIDetector()
        alerts = detector.inspect_request("t1", "https://api.mistral.ai/v1/chat/completions")
        assert len(alerts) >= 1
        assert alerts[0].provider == "Mistral AI"


# ══════════════════════════════════════════════════════════════════════════════
# Item 15: Deep Binary Model Scanner
# ══════════════════════════════════════════════════════════════════════════════

from guardian.security.model_scanner import DeepBinaryScanner


class TestDeepBinaryScanner:
    def test_safe_pickle(self):
        """A minimal valid pickle with no dangerous opcodes."""
        scanner = DeepBinaryScanner()
        # pickle protocol 2: PROTO(2) + EMPTY_LIST + STOP
        safe_data = b"\x80\x02]q\x00."
        report = scanner.scan_bytes(safe_data, "pkl")
        assert report.is_safe is True

    def test_dangerous_reduce_opcode(self):
        scanner = DeepBinaryScanner()
        # Craft bytes with REDUCE opcode (0x52 = 'R')
        data = b"\x80\x02cos\nsystem\nq\x00X\x06\x00\x00\x00whoamiRq\x01."
        report = scanner.scan_bytes(data, "pkl")
        assert report.is_safe is False
        assert report.critical_count > 0
        assert any("REDUCE" in f.opcode for f in report.findings if f.opcode)

    def test_dangerous_global_opcode(self):
        scanner = DeepBinaryScanner()
        # GLOBAL opcode: 'c' followed by module\nname\n
        data = b"cos\nsystem\n."
        report = scanner.scan_bytes(data, "pkl")
        assert report.is_safe is False
        assert any("os.system" in str(f.metadata) for f in report.findings)

    def test_safe_safetensors(self):
        scanner = DeepBinaryScanner()
        # Minimal valid safetensors: 8-byte header size + JSON header + no tensors
        header = json.dumps({"__metadata__": {"format": "pt"}}).encode("utf-8")
        header_size = struct.pack("<Q", len(header))
        data = header_size + header
        report = scanner.scan_bytes(data, "safetensors")
        assert report.is_safe is True

    def test_safetensors_metadata_injection(self):
        scanner = DeepBinaryScanner()
        header = json.dumps({"__exec__": "malicious"}).encode("utf-8")
        header_size = struct.pack("<Q", len(header))
        data = header_size + header
        report = scanner.scan_bytes(data, "safetensors")
        assert report.is_safe is False
        assert any("metadata_injection" in f.category for f in report.findings)

    def test_safetensors_header_overflow(self):
        scanner = DeepBinaryScanner()
        # Header size larger than file
        header_size = struct.pack("<Q", 999999)
        data = header_size + b"short"
        report = scanner.scan_bytes(data, "safetensors")
        assert report.is_safe is False

    def test_safe_gguf(self):
        scanner = DeepBinaryScanner()
        # Minimal GGUF: magic + version 3 + padding
        data = b"GGUF" + struct.pack("<I", 3) + b"\x00" * 100
        report = scanner.scan_bytes(data, "gguf")
        assert report.is_safe is True

    def test_gguf_invalid_magic(self):
        scanner = DeepBinaryScanner()
        data = b"BADM" + b"\x00" * 100
        report = scanner.scan_bytes(data, "gguf")
        assert report.is_safe is False

    def test_gguf_malicious_metadata(self):
        scanner = DeepBinaryScanner()
        data = b"GGUF" + struct.pack("<I", 3) + b"\x00" * 20 + b"eval('exploit')" + b"\x00" * 50
        report = scanner.scan_bytes(data, "gguf")
        assert report.is_safe is False

    def test_onnx_safe(self):
        scanner = DeepBinaryScanner()
        # Simple ONNX-like protobuf data without suspicious patterns
        data = b"\x08\x07\x12\x0etensor_data_ok"
        report = scanner.scan_bytes(data, "onnx")
        assert report.is_safe is True

    def test_onnx_embedded_code(self):
        scanner = DeepBinaryScanner()
        data = b"\x08\x07\x12\x20some_data_exec('malicious')_end"
        report = scanner.scan_bytes(data, "onnx")
        assert report.is_safe is False

    def test_file_scan(self):
        scanner = DeepBinaryScanner()
        with tempfile.NamedTemporaryFile(suffix=".pkl", delete=False) as f:
            f.write(b"\x80\x02]q\x00.")  # safe pickle
            f.flush()
            report = scanner.scan_file(f.name)
        os.unlink(f.name)
        assert report.is_safe is True

    def test_file_not_found(self):
        scanner = DeepBinaryScanner()
        report = scanner.scan_file("/nonexistent/model.pkl")
        assert report.is_safe is False

    def test_unsupported_extension(self):
        scanner = DeepBinaryScanner()
        report = scanner.scan_file("model.xyz")
        assert report.is_safe is False

    def test_report_to_dict(self):
        scanner = DeepBinaryScanner()
        report = scanner.scan_bytes(b"\x80\x02].", "pkl")
        d = report.to_dict()
        assert "is_safe" in d
        assert "findings" in d
        assert "file_type" in d


# ══════════════════════════════════════════════════════════════════════════════
# Item 18: SIEM Mapping Packs + DLQ Replay Daemon
# ══════════════════════════════════════════════════════════════════════════════

from guardian.siem.mapping_packs import (
    MicrosoftSentinelMapper,
    ElasticECSMapper,
)
from guardian.siem.dlq_replay import DLQReplayDaemon, ReplayResult


class TestMicrosoftSentinelMapper:
    def test_basic_mapping(self):
        mapper = MicrosoftSentinelMapper()
        event = {
            "event_type": "prompt_injection",
            "severity": "high",
            "tenant_id": "tenant-1",
            "description": "Injection detected",
        }
        result = mapper.map_event(event)
        assert result.DeviceVendor == "GuardianAI"
        assert result.DeviceProduct == "AISecurityFirewall"
        assert result.LogSeverity == 8  # high = 8
        assert result.Activity == "prompt_injection"

    def test_severity_mapping(self):
        mapper = MicrosoftSentinelMapper()
        for sev, expected in [("info", 1), ("low", 3), ("medium", 5), ("high", 8), ("critical", 10)]:
            result = mapper.map_event({"severity": sev})
            assert result.LogSeverity == expected

    def test_to_dict(self):
        mapper = MicrosoftSentinelMapper()
        result = mapper.map_event({"event_type": "test"})
        d = result.to_dict()
        assert "TimeGenerated" in d
        assert "DeviceVendor" in d

    def test_detection_rules(self):
        rules = MicrosoftSentinelMapper.get_detection_rules()
        assert len(rules) >= 3
        assert any("Prompt Injection" in r["name"] for r in rules)
        assert any("Jailbreak" in r["name"] for r in rules)


class TestElasticECSMapper:
    def test_basic_mapping(self):
        mapper = ElasticECSMapper()
        event = {
            "event_type": "jailbreak",
            "severity": "critical",
            "tenant_id": "tenant-2",
        }
        result = mapper.map_event(event)
        d = result.to_dict()
        assert d["event"]["module"] == "guardianai"
        assert d["event"]["severity"] == 100  # critical = 100
        assert d["event"]["action"] == "jailbreak"

    def test_ecs_categories(self):
        mapper = ElasticECSMapper()
        result = mapper.map_event({"event_type": "prompt_injection"})
        d = result.to_dict()
        assert "intrusion_detection" in d["event"]["category"]

    def test_detection_rules(self):
        rules = ElasticECSMapper.get_detection_rules()
        assert len(rules) >= 3
        assert any("Jailbreak" in r["name"] for r in rules)


class TestDLQReplayDaemon:
    def test_add_and_replay_success(self):
        daemon = DLQReplayDaemon(
            delivery_fn=lambda e, t: True,
            max_retries=3,
            base_delay_seconds=10,
        )
        daemon.add_event({"test": 1}, "splunk", error="timeout", timestamp=100)
        # next_retry_ts = 100 + 10 = 110, so replay at t=200
        result = daemon.replay_cycle(current_time=200)
        assert result.succeeded == 1
        assert result.remaining == 0

    def test_replay_failure_with_retry(self):
        call_count = [0]

        def failing_delivery(event, target):
            call_count[0] += 1
            return False

        daemon = DLQReplayDaemon(
            delivery_fn=failing_delivery,
            max_retries=3,
            base_delay_seconds=10,
        )
        daemon.add_event({"test": 1}, "sentinel", error="fail", timestamp=0)

        # next_retry_ts = 0 + 10 = 10, replay at t=20
        result = daemon.replay_cycle(current_time=20)
        assert result.failed == 1
        assert result.remaining == 1

    def test_max_retries_drops_event(self):
        daemon = DLQReplayDaemon(
            delivery_fn=lambda e, t: False,
            max_retries=2,
            base_delay_seconds=1,
        )
        daemon.add_event({"test": 1}, "elastic", error="fail", timestamp=0)

        # Retry until dropped: attempt_count starts at 1 from add_event
        daemon.replay_cycle(current_time=100)   # attempt_count -> 2, scheduled retry
        result = daemon.replay_cycle(current_time=200)  # attempt_count -> 3 > max_retries=2 → drop
        assert result.dropped == 1
        assert daemon.queue_size == 0

    def test_exponential_backoff(self):
        daemon = DLQReplayDaemon(
            delivery_fn=lambda e, t: False,
            max_retries=5,
            base_delay_seconds=10.0,
            backoff_multiplier=2.0,
        )
        daemon.add_event({"test": 1}, "splunk", error="fail", timestamp=0)

        # next_retry_ts = 0 + 10 = 10
        # First replay at t=15 → fail, next_retry = 15 + 10*2^1 = 35
        daemon.replay_cycle(current_time=15)

        # At t=20, event should NOT be retried (before next_retry=35)
        result = daemon.replay_cycle(current_time=20)
        assert result.attempted == 0

        # At t=40, event should be retried
        result = daemon.replay_cycle(current_time=40)
        assert result.attempted == 1

    def test_queue_size_limit(self):
        daemon = DLQReplayDaemon(max_queue_size=3)
        for i in range(5):
            daemon.add_event({"id": i}, "splunk")
        assert daemon.queue_size == 3

    def test_stats(self):
        daemon = DLQReplayDaemon(
            delivery_fn=lambda e, t: True,
            base_delay_seconds=1,
        )
        daemon.add_event({"test": 1}, "splunk", timestamp=0)
        daemon.replay_cycle(current_time=100)
        stats = daemon.stats
        assert stats["total_succeeded"] == 1
        assert stats["total_replayed"] == 1

    def test_clear_queue(self):
        daemon = DLQReplayDaemon()
        daemon.add_event({"test": 1}, "splunk")
        daemon.add_event({"test": 2}, "splunk")
        dropped = daemon.clear()
        assert dropped == 2
        assert daemon.queue_size == 0

    def test_snapshot(self):
        daemon = DLQReplayDaemon()
        daemon.add_event({"test": 1}, "splunk", error="timeout")
        snapshot = daemon.get_queue_snapshot()
        assert len(snapshot) == 1
        assert snapshot[0]["target"] == "splunk"
