import threading
import time
from guardian.web3sec.tx_analyzer import TransactionAnalyzer, SimulationResult

def test_concurrency():
    analyzer = TransactionAnalyzer()
    
    # We will just test the method directly instead of running the whole backend.
    # We simulate what rpc_relay does.
    tx = {"to": "0x123", "from": "0x456"}
    dummy_sim = SimulationResult(success=True, gas_used=0, return_data="")
    
    # We pass live_rules locally.
    res1 = analyzer.analyze_transaction(tx, dummy_sim, live_rules={"reserve_manipulation": False})
    print(f"Result with rule disabled: {res1}")

test_concurrency()
