import pytest
import time
from guardian.security.credential_rotation import CredentialRotationPolicy, AgentBehaviorAnomalyProfiler

def test_credential_rotation_validity():
    policy = CredentialRotationPolicy(ttl_seconds=1)
    policy.issue_credential("agent_1", "secretA")
    
    assert policy.is_valid("agent_1", "secretA") is True
    assert policy.is_valid("agent_1", "wrong_secret") is False
    
    # Expiry
    time.sleep(1.1)
    assert policy.is_valid("agent_1", "secretA") is False

def test_credential_rotation_action():
    policy = CredentialRotationPolicy(ttl_seconds=3600)
    policy.issue_credential("agent_2", "old_secret")
    assert policy.is_valid("agent_2", "old_secret") is True
    
    policy.rotate_credential("agent_2", "new_secret")
    assert policy.is_valid("agent_2", "new_secret") is True
    assert policy.is_valid("agent_2", "old_secret") is False

def test_anomaly_profiler_new_endpoint():
    profiler = AgentBehaviorAnomalyProfiler()
    profiler.log_api_call("agent_1", "/api/v1/auth", 1.0)
    
    res = profiler.log_api_call("agent_1", "/api/v1/data", 2.0)
    assert res["is_anomalous"] is True
    assert "New unexpected endpoint accessed: /api/v1/data" in res["anomalies"]

def test_anomaly_profiler_frequency_spike():
    profiler = AgentBehaviorAnomalyProfiler(alpha=0.5, threshold=2.0)
    
    # Establish baseline
    for i in range(5):
        profiler.log_api_call("agent_2", "/api/v1/ping", i * 1.0)
        
    # Introduce spike (call immediately after)
    res = profiler.log_api_call("agent_2", "/api/v1/ping", 4.01)
    assert res["is_anomalous"] is True
    assert any("frequency spike" in a for a in res["anomalies"])
