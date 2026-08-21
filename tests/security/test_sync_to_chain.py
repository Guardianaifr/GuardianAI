import pytest
import os
import json
import redis
from unittest.mock import patch, MagicMock, PropertyMock
from guardian.security.trust_exploitation import TrustExploitationGuard, _REDIS_CONFIGURED, SyncAlreadyInProgressError

@pytest.fixture
def mock_w3_and_contract():
    with patch("web3.Web3") as mock_web3, \
         patch("eth_account.Account.from_key") as mock_account, \
         patch("json.load") as mock_json_load, \
         patch("builtins.open"):
        
        mock_w3_instance = MagicMock()
        mock_web3.return_value = mock_w3_instance
        
        mock_contract = MagicMock()
        mock_w3_instance.eth.contract.return_value = mock_contract
        
        mock_account_instance = MagicMock()
        mock_account_instance.address = "0xMockDeployer"
        mock_account.return_value = mock_account_instance
        
        # Proper primitive values for gas logic
        type(mock_w3_instance.eth).gas_price = PropertyMock(return_value=10000)
        mock_w3_instance.to_wei.side_effect = lambda val, unit: int(val * 1e9) if unit == "gwei" else val
        mock_w3_instance.to_checksum_address.side_effect = lambda addr: addr
        
        # Default mock returns
        mock_contract.functions.isMalicious.return_value.call.return_value = (False, "")
        mock_contract.functions.isMaliciousString.return_value.call.return_value = (False, "")
        mock_contract.functions.addAddressesBatch.return_value.estimate_gas.return_value = 100000
        mock_contract.functions.addStringAddressesBatch.return_value.estimate_gas.return_value = 100000
        mock_contract.functions.addAddressesBatch.return_value.build_transaction.return_value = {"tx": "mock"}
        mock_contract.functions.addStringAddressesBatch.return_value.build_transaction.return_value = {"tx": "mock"}
        
        mock_signed_tx = MagicMock()
        mock_signed_tx.raw_transaction = b"mock"
        mock_w3_instance.eth.account.sign_transaction.return_value = mock_signed_tx
        
        mock_tx_hash = MagicMock()
        mock_tx_hash.hex.return_value = "0xhash"
        mock_w3_instance.eth.send_raw_transaction.return_value = mock_tx_hash
        
        yield mock_w3_instance, mock_contract

@pytest.fixture
def setup_env():
    os.environ["GUARDIAN_ANCHOR_MODE"] = "live"
    os.environ["GUARDIAN_DEPLOYER_PRIVATE_KEY"] = "0xmock"
    os.environ["GUARDIAN_THREATFEED_CONTRACT_MONAD"] = "0xmockcontract"
    if "GUARDIAN_MAX_GAS_PRICE_GWEI" in os.environ:
        del os.environ["GUARDIAN_MAX_GAS_PRICE_GWEI"]
    yield
    del os.environ["GUARDIAN_ANCHOR_MODE"]
    del os.environ["GUARDIAN_DEPLOYER_PRIVATE_KEY"]
    del os.environ["GUARDIAN_THREATFEED_CONTRACT_MONAD"]
    if "GUARDIAN_MAX_GAS_PRICE_GWEI" in os.environ:
        del os.environ["GUARDIAN_MAX_GAS_PRICE_GWEI"]

@patch("guardian.onchain_safety.assert_timelock_owns_all")
def test_sync_to_chain_batching(mock_timelock, setup_env, mock_w3_and_contract):
    """Test full batch success with 55 addresses (should split into 50 and 5)."""
    mock_w3, mock_contract = mock_w3_and_contract
    
    guard = TrustExploitationGuard()
    # Create 55 valid EVM addresses
    guard.high_risk_addresses = [f"0x{'a' * 38}{i:02x}" for i in range(55)]
    
    with patch("guardian.security.trust_exploitation._REDIS_CONFIGURED", False):
        res = guard.sync_to_chain("monad")
        
    assert res["success"] is True
    assert len(res["succeeded"]) == 55
    assert len(res["failed"]) == 0
    assert len(res["not_attempted"]) == 0
    assert len(res["tx_hashes"]) == 2
    # Verify addAddressesBatch was called for 2 batches (estimate_gas + build_transaction)
    assert mock_contract.functions.addAddressesBatch.call_count == 4

@patch("guardian.onchain_safety.assert_timelock_owns_all")
def test_sync_to_chain_idempotency(mock_timelock, setup_env, mock_w3_and_contract):
    """Test that already registered addresses are skipped."""
    mock_w3, mock_contract = mock_w3_and_contract
    
    # Make the contract return True for isMalicious
    mock_contract.functions.isMalicious.return_value.call.return_value = (True, "Already registered")
    
    guard = TrustExploitationGuard()
    guard.high_risk_addresses = ["0x" + "a" * 40]
    
    with patch("guardian.security.trust_exploitation._REDIS_CONFIGURED", False):
        res = guard.sync_to_chain("monad")
        
    assert res["success"] is True
    assert len(res["succeeded"]) == 1
    assert len(res["failed"]) == 0
    assert len(res["not_attempted"]) == 0
    assert len(res["tx_hashes"]) == 0
    mock_contract.functions.addAddressesBatch.assert_not_called()

@patch("guardian.onchain_safety.assert_timelock_owns_all")
def test_sync_to_chain_gas_ceiling(mock_timelock, setup_env, mock_w3_and_contract):
    """Test that it blocks when gas price exceeds ceiling."""
    mock_w3, mock_contract = mock_w3_and_contract
    os.environ["GUARDIAN_MAX_GAS_PRICE_GWEI"] = "1"
    
    # Set current gas price to 2 Gwei (exceeds max 1 Gwei = 1000000000 Wei)
    type(mock_w3.eth).gas_price = PropertyMock(return_value=2000000000)
    
    guard = TrustExploitationGuard()
    guard.high_risk_addresses = ["0x" + "a" * 40]
    
    try:
        with patch("guardian.security.trust_exploitation._REDIS_CONFIGURED", False):
            res = guard.sync_to_chain("monad")
            
        assert res["success"] is False
        assert "exceeds maximum allowed" in res["error"]
        assert len(res["succeeded"]) == 0
        assert len(res["failed"]) == 0
        assert len(res["not_attempted"]) == 1
    finally:
        if "GUARDIAN_MAX_GAS_PRICE_GWEI" in os.environ:
            del os.environ["GUARDIAN_MAX_GAS_PRICE_GWEI"]

@patch("guardian.onchain_safety.assert_timelock_owns_all")
@patch("redis.Redis", create=True)
def test_sync_to_chain_redis_lock_unreachable(mock_redis, mock_timelock, setup_env, mock_w3_and_contract):
    """Test fail-closed if Redis is configured but unreachable."""
    from redis import RedisError
    mock_redis.from_url.side_effect = RedisError("Connection refused")
    
    guard = TrustExploitationGuard()
    guard.high_risk_addresses = ["0x" + "a" * 40]
    
    with patch("guardian.security.trust_exploitation._REDIS_CONFIGURED", True):
        res = guard.sync_to_chain("monad")
        
    assert res["success"] is False
    assert "unreachable" in res["error"]
    assert "Refusing to sync" in res["error"]

@patch("guardian.onchain_safety.assert_timelock_owns_all")
@patch("redis.Redis", create=True)
def test_sync_to_chain_redis_lock_held(mock_redis, mock_timelock, setup_env, mock_w3_and_contract):
    """Test fail-fast if Redis lock is already held by another pod."""
    mock_client = MagicMock()
    mock_redis.from_url.return_value = mock_client
    
    mock_lock = MagicMock()
    mock_lock.acquire.return_value = False  # Lock already held
    mock_client.lock.return_value = mock_lock
    
    guard = TrustExploitationGuard()
    guard.high_risk_addresses = ["0x" + "a" * 40]
    
    with patch("guardian.security.trust_exploitation._REDIS_CONFIGURED", True):
        res = guard.sync_to_chain("monad")
        
    assert res["success"] is False
    assert "already in progress" in res["error"]
    
@patch("guardian.onchain_safety.assert_timelock_owns_all")
def test_sync_to_chain_partial_failure(mock_timelock, setup_env, mock_w3_and_contract):
    """Test that partial failure returns the successful tx hashes before failing."""
    mock_w3, mock_contract = mock_w3_and_contract
    
    # Create 100 valid EVM addresses (2 batches of 50)
    guard = TrustExploitationGuard()
    guard.high_risk_addresses = [f"0x{'a' * 38}{i:02x}" for i in range(100)]
    
    # Make the second batch fail
    mock_contract.functions.addAddressesBatch.return_value.build_transaction.side_effect = [
        {"tx": "mock1"},  # Batch 1 succeeds
        Exception("Simulated out of gas")  # Batch 2 fails
    ]
    
    with patch("guardian.security.trust_exploitation._REDIS_CONFIGURED", False):
        res = guard.sync_to_chain("monad")
        
    assert res["success"] is False
    assert "Partial failure after 1 txs" in res["error"]
    assert len(res["succeeded"]) == 50
    assert len(res["failed"]) == 50
    assert len(res["not_attempted"]) == 0
    assert len(res["tx_hashes"]) == 1
    
    assert res["succeeded"][0] == guard.high_risk_addresses[0]
    assert res["failed"][0]["address"] == guard.high_risk_addresses[50]
    assert "Simulated out of gas" in res["failed"][0]["error"]
