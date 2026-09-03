"""Unit and live integration tests for Tenderly Transaction Simulation in GuardianAI."""
import os
import pytest
from web3 import Web3
from dotenv import load_dotenv
from guardian.web3sec.simulation import SimulationEngine, SimulationResult

def test_tenderly_simulation_live():
    load_dotenv()
    access_key = os.getenv("TENDERLY_ACCESS_KEY")
    if not access_key:
        pytest.skip("TENDERLY_ACCESS_KEY not configured in environment")

    w3 = Web3()
    engine = SimulationEngine(w3)

    # Benign transfer simulation on Monad Testnet
    tx = {
        "from": "0x1D4549B95dccAC8203393543187b25B3137D0bf6",
        "to": "0x1D4549B95dccAC8203393543187b25B3137D0bf6",
        "data": "0x",
        "value": 0,
        "gas": 100000,
    }

    result = engine.simulate_with_tenderly(tx, network_id="10143")
    assert result is not None
    assert isinstance(result, SimulationResult)
    assert result.success is True
    assert result.gas_used > 0
    assert result.tenderly_url is not None
    assert "dashboard.tenderly.co" in result.tenderly_url
    assert "simulator" in result.tenderly_url

def test_tenderly_fallback_when_unconfigured(monkeypatch):
    monkeypatch.delenv("TENDERLY_ACCESS_KEY", raising=False)
    w3 = Web3()
    engine = SimulationEngine(w3)

    tx = {"to": "0x1111111111111111111111111111111111111111", "data": "0x"}
    res = engine.simulate_with_tenderly(tx)
    assert res is None

