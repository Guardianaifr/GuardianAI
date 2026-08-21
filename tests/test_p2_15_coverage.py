import pytest
from guardian.web3sec.rpc_relay import GuardianRPCRelay
from guardian.web3sec.tx_analyzer import TransactionAnalyzer, AnalysisResult
from flask import json, Response
import sqlite3
import os

@pytest.fixture
def relay_config(tmp_path):
    db_path = str(tmp_path / "test_guardian.db")
    return {
        "security_policies": {
            "admin_token": "test-admin-token"
        },
        "web3_security": {
            "listen_port": 8546,
            "upstream_rpc": "http://localhost",
            "fail_mode": "closed",
            "enforce_simulation": False
        }
    }, db_path

def test_rpc_relay_management_auth_closed(relay_config):
    cfg, db_path = relay_config
    cfg["security_policies"]["admin_token"] = ""
    relay = GuardianRPCRelay(cfg)
    relay.db_path = db_path
    relay.app.config['TESTING'] = True
    
    with relay.app.test_client() as client:
        resp = client.post('/whitelist', json={"address": "0x123", "label": "test"})
        assert resp.status_code == 403
        data = json.loads(resp.data)
        assert "Management auth not configured" in data["error"]

def test_rpc_relay_management_auth_valid(relay_config):
    cfg, db_path = relay_config
    relay = GuardianRPCRelay(cfg)
    relay.db_path = db_path
    relay._init_db()
    relay.app.config['TESTING'] = True
    
    with relay.app.test_client() as client:
        resp = client.post('/whitelist', json={"address": "0x123", "label": "test"})
        assert resp.status_code == 401
        data = json.loads(resp.data)
        assert "Authorization required" in data.get("error", "")
        
        resp = client.post('/whitelist', json={"address": "0x123", "label": "test"}, headers={"Authorization": "Bearer bad-token"})
        assert resp.status_code == 403
        data = json.loads(resp.data)
        assert "Invalid management token" in data.get("error", "")
        
        resp = client.post('/whitelist', json={"address": "0x123", "label": "test"}, headers={"Authorization": "Bearer test-admin-token"})
        assert resp.status_code == 200
        data = json.loads(resp.data)
        assert data["status"] == "ok"

def test_whitelist_ordering_per_request(relay_config):
    cfg, db_path = relay_config
    relay = GuardianRPCRelay(cfg)
    relay.db_path = db_path
    
    with sqlite3.connect(db_path) as conn:
        conn.execute("CREATE TABLE IF NOT EXISTS web3sec_whitelist (address TEXT PRIMARY KEY, label TEXT, added_at REAL)")
        conn.execute("INSERT INTO web3sec_whitelist (address, label, added_at) VALUES (?, ?, ?)", ("0xwhitelisted", "test", 123.0))
        conn.commit()
        
    class FakeAnalyzer:
        def analyze_transaction(self, tx, sim, live_rules=None):
            return AnalysisResult(blocked=True, detector_name="TestBlock", reason="Test block reason", severity="high")
            
    relay.analyzer = FakeAnalyzer()
    
    res1 = relay._handle_single_rpc({
        "jsonrpc": "2.0",
        "method": "eth_sendTransaction",
        "params": [{"to": "0xmalicious", "from": "0xabc", "data": "0x0", "value": "0x0"}],
        "id": 1
    }, "127.0.0.1")
    
    assert res1 is not None
    data = json.loads(res1.get_data())
    assert "error" in data
    assert "Test block reason" in data["error"]["message"]
    
    res2 = relay._handle_single_rpc({
        "jsonrpc": "2.0",
        "method": "eth_sendTransaction",
        "params": [{"to": "0xwhitelisted", "from": "0xabc", "data": "0x0", "value": "0x0"}],
        "id": 2
    }, "127.0.0.1")
    
    assert res2 is None

def test_fail_mode_config():
    cfg = {"web3_security": {"upstream_rpc": "http://localhost", "fail_mode": "open"}}
    relay = GuardianRPCRelay(cfg)
    assert relay.fail_mode == "open"
