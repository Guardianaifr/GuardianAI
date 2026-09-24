import pytest
from flask import Flask, Response
import json
import os
import sqlite3
from unittest.mock import patch, MagicMock

from guardian.web3sec.rpc_relay import GuardianRPCRelay, decode_raw_transaction
from guardian.web3sec.tx_analyzer import AnalysisResult
from guardian.web3sec.simulation import SimulationResult

@pytest.fixture
def relay():
    config = {
        "web3_security": {
            "listen_port": 8546,
            "upstream_rpc": "http://mock-rpc",
            "fail_mode": "closed",
            "enforce_simulation": True
        },
        "security_policies": {
            "admin_token": "test_token"
        }
    }
    with patch("guardian.web3sec.rpc_relay.Web3"):
        with patch("guardian.web3sec.rpc_relay.SimulationEngine") as sim_engine_mock:
            with patch("guardian.web3sec.rpc_relay.TransactionAnalyzer") as analyzer_mock:
                r = GuardianRPCRelay(config)
                # mock DB to be in-memory for testing
                import tempfile
                r.db_path = tempfile.mktemp(suffix=".db")
                r._init_db()
                r.analyzer = analyzer_mock.return_value
                r.sim_engine = sim_engine_mock.return_value
                r.require_attestation = False
                return r

def test_proxy_post(relay):
    req_data = {"method": "eth_sendTransaction", "id": 1, "params": [{"chainId": "0x279f", "to": "0x123", "from": "0x456"}]} # 10143
    relay.analyzer.analyze_transaction.return_value = AnalysisResult(blocked=False, reason="", detector_name="", severity="")
    relay.sim_engine.simulate_transaction.return_value = SimulationResult(success=True, revert_reason="", gas_used=0, return_data="")
    with patch("requests.post") as req_mock:
        req_mock.return_value.status_code = 200
        req_mock.return_value.content = b'{"result": "0x123"}'
        req_mock.return_value.headers = {"Content-Type": "application/json"}
        with patch.object(relay, '_load_rules_from_db', return_value={}):
            with patch.object(relay, '_load_whitelist_from_db', return_value=set()):
                with relay.app.test_client() as client:
                    resp = client.post('/', json=req_data)
                    assert resp.status_code == 200
                    assert json.loads(resp.data)["result"] == "0x123"

def test_proxy_post_blocked(relay):
    req_data = {"method": "eth_sendTransaction", "id": 1, "params": [{"chainId": "0x279f", "to": "0x123", "from": "0x456"}]}
    relay.analyzer.analyze_transaction.return_value = AnalysisResult(blocked=True, reason="malicious", detector_name="test", severity="HIGH")
    with patch.object(relay, '_load_rules_from_db', return_value={}):
        with patch.object(relay, '_load_whitelist_from_db', return_value=set()):
            with relay.app.test_client() as client:
                resp = client.post('/', json=req_data)
                assert resp.status_code == 200
                assert "Guardian Security Block" in json.loads(resp.data)["error"]["message"]


