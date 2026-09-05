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


def test_base_network_rejected_monad_testnet_allowed(relay):
    """Base network (84532/8453) transactions are blocked; Monad Testnet (10143) is accepted."""
    with relay.app.test_client() as client:
        # Base Sepolia (84532) must be rejected
        resp = client.post('/', json={
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{"to": "0xtarget", "data": "0x", "chainId": 84532}],
            "id": 6
        })
        data = json.loads(resp.data)
        assert "error" in data
        assert "monad testnet" in data["error"]["message"].lower()

        # Base mainnet (8453 / 0x2105) must be rejected
        resp = client.post('/', json={
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{"to": "0xtarget", "data": "0x", "chainId": "0x2105"}],
            "id": 7
        })
        data = json.loads(resp.data)
        assert "error" in data
        assert "monad testnet" in data["error"]["message"].lower()

        # Monad Testnet (10143 / 0x279f) allowed to pass through
        with patch.object(SimulationEngine, 'simulate_transaction') as mock_sim:
            mock_sim.return_value = SimulationResult(success=True, gas_used=21000, return_data="")
            with patch('requests.post') as mock_post:
                mock_post.return_value.status_code = 200
                mock_post.return_value.content = b'{"jsonrpc": "2.0", "result": "0xmonadtx", "id": 8}'
                resp = client.post('/', json={
                    "jsonrpc": "2.0",
                    "method": "eth_sendTransaction",
                    "params": [{"to": "0xtarget", "data": "0x", "chainId": 10143}],
                    "id": 8
                })
                data = json.loads(resp.data)
                assert "result" in data
                assert data["result"] == "0xmonadtx"


def test_raw_transaction_base_rejected_monad_testnet_allowed(relay):
    """Raw transactions (eth_sendRawTransaction) targeting Base or missing EIP-155 are blocked; Monad Testnet raw tx is allowed."""
    from eth_account import Account

    acc = Account.create()

    # 1. Base Sepolia (84532) EIP-1559 raw tx -> rejected
    tx_base_sepolia = {
        "to": "0x0000000000000000000000000000000000000001",
        "value": 0,
        "gas": 21000,
        "maxFeePerGas": 10**9,
        "maxPriorityFeePerGas": 10**9,
        "nonce": 0,
        "chainId": 84532,
        "type": 2,
        "data": b"",
    }
    raw_base_sepolia = acc.sign_transaction(tx_base_sepolia).raw_transaction.hex()

    with relay.app.test_client() as client:
        resp = client.post('/', json={
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_base_sepolia],
            "id": 101
        })
        data = json.loads(resp.data)
        assert "error" in data
        assert "monad testnet" in data["error"]["message"].lower()

        # 2. Base Mainnet (8453) legacy EIP-155 raw tx -> rejected
        tx_base_mainnet = {
            "to": "0x0000000000000000000000000000000000000001",
            "value": 0,
            "gas": 21000,
            "gasPrice": 10**9,
            "nonce": 0,
            "chainId": 8453,
        }
        raw_base_mainnet = acc.sign_transaction(tx_base_mainnet).raw_transaction.hex()
        resp = client.post('/', json={
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_base_mainnet],
            "id": 102
        })
        data = json.loads(resp.data)
        assert "error" in data
        assert "monad testnet" in data["error"]["message"].lower()

        # 3. Pre-EIP-155 transaction (missing chainId) -> rejected
        tx_no_chain = {
            "to": "0x0000000000000000000000000000000000000001",
            "value": 0,
            "gas": 21000,
            "gasPrice": 10**9,
            "nonce": 0,
        }
        raw_no_chain = acc.sign_transaction(tx_no_chain).raw_transaction.hex()
        resp = client.post('/', json={
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_no_chain],
            "id": 103
        })
        data = json.loads(resp.data)
        assert "error" in data
        assert "missing eip-155" in data["error"]["message"].lower()

        # 4. Monad Testnet (10143) EIP-1559 raw tx -> allowed to pass to upstream
        tx_monad = {
            "to": "0x0000000000000000000000000000000000000001",
            "value": 0,
            "gas": 21000,
            "maxFeePerGas": 10**9,
            "maxPriorityFeePerGas": 10**9,
            "nonce": 0,
            "chainId": 10143,
            "type": 2,
            "data": b"",
        }
        raw_monad = acc.sign_transaction(tx_monad).raw_transaction.hex()
        with patch.object(SimulationEngine, 'simulate_transaction') as mock_sim:
            mock_sim.return_value = SimulationResult(success=True, gas_used=21000, return_data="")
            with patch('requests.post') as mock_post:
                mock_post.return_value.status_code = 200
                mock_post.return_value.content = b'{"jsonrpc": "2.0", "result": "0xmonadrawtx", "id": 104}'
                resp = client.post('/', json={
                    "jsonrpc": "2.0",
                    "method": "eth_sendRawTransaction",
                    "params": [raw_monad],
                    "id": 104
                })
                data = json.loads(resp.data)
                assert "result" in data
                assert data["result"] == "0xmonadrawtx"


def test_require_attestation_send_raw_transaction(relay_config):
    """When require_attestation is True, eth_sendRawTransaction requires valid attestation matching sender."""
    import time
    import hmac
    import hashlib
    from eth_account import Account
    from guardian.security.agentic_controls import AgenticSecurityManager

    acc = Account.create()
    sender = acc.address

    relay_config["web3_security"]["require_attestation"] = True
    relay = GuardianRPCRelay(relay_config)
    relay.app.config['TESTING'] = True

    secret = "secret-sender-key"
    relay.agentic_security.agent_attestation_keys = {sender: {"key-1": secret}}

    tx_monad = {
        "to": "0x0000000000000000000000000000000000000001",
        "value": 0,
        "gas": 21000,
        "maxFeePerGas": 10**9,
        "maxPriorityFeePerGas": 10**9,
        "nonce": 0,
        "chainId": 10143,
        "type": 2,
        "data": b"",
    }
    raw_tx = acc.sign_transaction(tx_monad).raw_transaction.hex()

    with relay.app.test_client() as client:
        # 1. Missing attestation -> blocked (-32000)
        resp = client.post('/', json={
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx],
            "id": 201
        })
        data = json.loads(resp.data)
        assert "error" in data
        assert "attestation block" in data["error"]["message"].lower()
        assert "missing_agent_attestation" in data["error"]["message"].lower()

        # 2. Invalid attestation signature -> blocked (-32000)
        ts = str(time.time())
        resp = client.post('/', json={
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx],
            "id": 202
        }, headers={
            "X-Guardian-Agent-Attestation": "sha256=invalid",
            "X-Guardian-Agent-Attestation-Ts": ts,
            "X-Guardian-Agent-Key-Id": "key-1",
        })
        data = json.loads(resp.data)
        assert "error" in data
        assert "attestation block" in data["error"]["message"].lower()
        assert "invalid_agent_attestation" in data["error"]["message"].lower()

        # 3. Mismatched X-Guardian-Agent-Id header -> blocked (-32000)
        resp = client.post('/', json={
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx],
            "id": 203
        }, headers={
            "X-Guardian-Agent-Id": "0x0000000000000000000000000000000000000099",
            "X-Guardian-Agent-Attestation": "sha256=abc",
            "X-Guardian-Agent-Attestation-Ts": ts,
        })
        data = json.loads(resp.data)
        assert "error" in data
        assert "mismatch" in data["error"]["message"].lower()

        # 4. Valid mock attestation matching decoded sender -> allowed through
        decoded_tx = {
            "from": sender,
            "to": "0x0000000000000000000000000000000000000001",
            "value": 0,
            "data": "0x",
            "chainId": 10143,
        }
        payload_str = json.dumps(decoded_tx, sort_keys=True, separators=(",", ":"))
        payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
        mat = AgenticSecurityManager._attestation_material(sender, "", "", "key-1", ts, payload_hash)
        valid_sig = hmac.new(secret.encode("utf-8"), mat.encode("utf-8"), hashlib.sha256).hexdigest()

        with patch.object(SimulationEngine, 'simulate_transaction') as mock_sim:
            mock_sim.return_value = SimulationResult(success=True, gas_used=21000, return_data="")
            with patch('requests.post') as mock_post:
                mock_post.return_value.status_code = 200
                mock_post.return_value.content = b'{"jsonrpc": "2.0", "result": "0xvalidraw", "id": 204}'
                resp = client.post('/', json={
                    "jsonrpc": "2.0",
                    "method": "eth_sendRawTransaction",
                    "params": [raw_tx],
                    "id": 204
                }, headers={
                    "X-Guardian-Agent-Attestation": f"sha256={valid_sig}",
                    "X-Guardian-Agent-Attestation-Ts": ts,
                    "X-Guardian-Agent-Key-Id": "key-1",
                })
                data = json.loads(resp.data)
                assert "result" in data
                assert data["result"] == "0xvalidraw"


def test_attestation_enforced_when_identity_gate_none_or_disabled(relay_config):
    """When require_attestation is True, attestation is enforced even if identity_gate is None or disabled."""
    relay_config["web3_security"]["require_attestation"] = True
    relay = GuardianRPCRelay(relay_config)
    relay.app.config['TESTING'] = True

    # Explicitly set identity_gate to None
    relay.identity_gate = None

    with relay.app.test_client() as client:
        resp = client.post('/', json={
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{"from": "0x1111111111111111111111111111111111111111", "to": "0xtarget", "data": "0x", "chainId": 10143}],
            "id": 301
        })
        data = json.loads(resp.data)
        assert "error" in data
        assert "attestation block" in data["error"]["message"].lower()
        assert "missing_agent_attestation" in data["error"]["message"].lower()


def test_attestation_fail_closed_when_agentic_security_unavailable(relay_config):
    """When require_attestation is True and agentic_security is None, fail closed."""
    relay_config["web3_security"]["require_attestation"] = True
    relay = GuardianRPCRelay(relay_config)
    relay.app.config['TESTING'] = True
    relay.agentic_security = None

    with relay.app.test_client() as client:
        resp = client.post('/', json={
            "jsonrpc": "2.0",
            "method": "eth_sendTransaction",
            "params": [{"from": "0x1111111111111111111111111111111111111111", "to": "0xtarget", "data": "0x", "chainId": 10143}],
            "id": 401
        })
        data = json.loads(resp.data)
        assert "error" in data
        assert "agenticsecuritymanager unavailable" in data["error"]["message"].lower()


def test_revoked_agent_blocked_on_raw_tx_even_without_identity_gate(relay_config):
    """When an agent identity is revoked, eth_sendRawTransaction is blocked even if identity_gate is None."""
    import time
    import hmac
    import hashlib
    from eth_account import Account
    from guardian.security.agentic_controls import AgenticSecurityManager

    acc = Account.create()
    sender = acc.address

    relay_config["web3_security"]["require_attestation"] = True
    relay = GuardianRPCRelay(relay_config)
    relay.app.config['TESTING'] = True
    relay.identity_gate = None

    secret = "secret-sender-key"
    relay.agentic_security.agent_attestation_keys = {sender: {"key-1": secret}}
    # Revoke sender in agentic_security
    relay.agentic_security.revoked_agent_ids = {sender.lower()}

    tx_monad = {
        "to": "0x0000000000000000000000000000000000000001",
        "value": 0,
        "gas": 21000,
        "maxFeePerGas": 10**9,
        "maxPriorityFeePerGas": 10**9,
        "nonce": 0,
        "chainId": 10143,
        "type": 2,
        "data": b"",
    }
    raw_tx = acc.sign_transaction(tx_monad).raw_transaction.hex()

    decoded_tx = {
        "from": sender,
        "to": "0x0000000000000000000000000000000000000001",
        "value": 0,
        "data": "0x",
        "chainId": 10143,
    }
    ts = str(time.time())
    payload_str = json.dumps(decoded_tx, sort_keys=True, separators=(",", ":"))
    payload_hash = hashlib.sha256(payload_str.encode("utf-8")).hexdigest()
    mat = AgenticSecurityManager._attestation_material(sender, "", "", "key-1", ts, payload_hash)
    valid_sig = hmac.new(secret.encode("utf-8"), mat.encode("utf-8"), hashlib.sha256).hexdigest()

    with relay.app.test_client() as client:
        resp = client.post('/', json={
            "jsonrpc": "2.0",
            "method": "eth_sendRawTransaction",
            "params": [raw_tx],
            "id": 501
        }, headers={
            "X-Guardian-Agent-Attestation": f"sha256={valid_sig}",
            "X-Guardian-Agent-Attestation-Ts": ts,
            "X-Guardian-Agent-Key-Id": "key-1",
        })
        data = json.loads(resp.data)
        assert "error" in data
        assert "revoked_agent_identity" in data["error"]["message"]


