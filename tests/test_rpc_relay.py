import pytest
import json
from guardian.web3sec.rpc_relay import GuardianRPCRelay
from guardian.web3sec.simulation import SimulationResult, SimulationEngine
from guardian.web3sec.tx_analyzer import TransactionAnalyzer, AnalysisResult
from unittest.mock import MagicMock, patch

@pytest.fixture
def relay_config():
    return {
        "web3_security": {
            "listen_port": 8546,
            "upstream_rpc": "https://testnet.monad.xyz/v1",
            "fail_mode": "closed",
            "enforce_simulation": True,
            "detection_rules": {
                "reserve_manipulation": True,
                "infinite_approval": True,
                "role_change": True,
                "zero_slippage": True,
                "threat_address": True
            },
            "threat_feed_addresses": ["0xbadguy"]
        }
    }

@pytest.fixture
def relay(relay_config):
    r = GuardianRPCRelay(relay_config)
    r.app.config['TESTING'] = True
    return r

def test_benign_request(relay):
    with relay.app.test_client() as client:
        with patch('requests.post') as mock_post:
            mock_post.return_value.status_code = 200
            mock_post.return_value.content = b'{"jsonrpc": "2.0", "result": "0x123", "id": 1}'
            
            resp = client.post('/', json={"jsonrpc": "2.0", "method": "eth_blockNumber", "params": [], "id": 1})
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert data["result"] == "0x123"

def test_infinite_approval_blocked(relay):
    with relay.app.test_client() as client:
        with patch.object(SimulationEngine, 'simulate_transaction') as mock_sim:
            mock_sim.return_value = SimulationResult(success=True, gas_used=21000, return_data="")
            
            resp = client.post('/', json={
                "jsonrpc": "2.0",
                "method": "eth_sendTransaction",
                "params": [{
                    "to": "0xtoken",
                    "data": "0x095ea7b30000000000000000000000000000000000000000ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff"
                }],
                "id": 2
            })
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert "error" in data
            assert "infinite approval" in data["error"]["message"].lower()

def test_threat_address_blocked(relay):
    with relay.app.test_client() as client:
        with patch.object(SimulationEngine, 'simulate_transaction') as mock_sim:
            mock_sim.return_value = SimulationResult(success=True, gas_used=21000, return_data="")
            
            resp = client.post('/', json={
                "jsonrpc": "2.0",
                "method": "eth_sendTransaction",
                "params": [{
                    "to": "0xbadguy",
                    "data": "0x"
                }],
                "id": 3
            })
            assert resp.status_code == 200
            data = json.loads(resp.data)
            assert "error" in data
            assert "threat feed" in data["error"]["message"].lower()

def test_fail_mode_closed(relay_config):
    relay_config["web3_security"]["fail_mode"] = "closed"
    relay = GuardianRPCRelay(relay_config)
    relay.app.config['TESTING'] = True
    
    with relay.app.test_client() as client:
        with patch.object(SimulationEngine, 'simulate_transaction') as mock_sim:
            mock_sim.return_value = SimulationResult(success=False, gas_used=0, return_data="", revert_reason="Out of gas")
            
            resp = client.post('/', json={
                "jsonrpc": "2.0",
                "method": "eth_sendTransaction",
                "params": [{"to": "0xtarget", "data": "0x"}],
                "id": 4
            })
            data = json.loads(resp.data)
            assert "error" in data
            assert "simulation failed" in data["error"]["message"].lower()

def test_fail_mode_open(relay_config):
    relay_config["web3_security"]["fail_mode"] = "open"
    relay = GuardianRPCRelay(relay_config)
    relay.app.config['TESTING'] = True
    
    with relay.app.test_client() as client:
        with patch.object(SimulationEngine, 'simulate_transaction') as mock_sim:
            mock_sim.return_value = SimulationResult(success=False, gas_used=0, return_data="", revert_reason="Out of gas")
            with patch('requests.post') as mock_post:
                mock_post.return_value.status_code = 200
                mock_post.return_value.content = b'{"jsonrpc": "2.0", "result": "0xtxhash", "id": 5}'
                
                resp = client.post('/', json={
                    "jsonrpc": "2.0",
                    "method": "eth_sendTransaction",
                    "params": [{"to": "0xtarget", "data": "0x"}],
                    "id": 5
                })
                data = json.loads(resp.data)
                assert "result" in data
