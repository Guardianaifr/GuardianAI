import threading
import time
from guardian.web3sec.tx_analyzer import TransactionAnalyzer, Detector, AnalysisResult, SimulationResult

class SlowDetector(Detector):
    name = "slow_detector"
    def analyze(self, tx, sim_result):
        time.sleep(0.5)
        return AnalysisResult(blocked=True, detector_name=self.name, reason="Blocked by slow_detector", severity="high")

analyzer = TransactionAnalyzer({})
analyzer.detectors = [SlowDetector()]

def test_thread(is_enabled, results, index):
    tx = {"to": "0x1", "from": "0x2"}
    sim = SimulationResult(success=True, gas_used=0, return_data="")
    live_rules = {"slow_detector": is_enabled}
    res = analyzer.analyze_transaction(tx, sim, live_rules=live_rules)
    results[index] = res.blocked if res else False

def run_concurrent_test():
    results = [None, None]
    
    t0 = threading.Thread(target=test_thread, args=(False, results, 0))
    t1 = threading.Thread(target=test_thread, args=(True, results, 1))
    
    t0.start()
    time.sleep(0.1)
    t1.start()
    
    t0.join()
    t1.join()
    
    print(f"Thread 0 (expected False): {results[0]}")
    print(f"Thread 1 (expected True): {results[1]}")
    print(f"Race condition fixed: {results[0] == False and results[1] == True}")

if __name__ == "__main__":
    run_concurrent_test()
