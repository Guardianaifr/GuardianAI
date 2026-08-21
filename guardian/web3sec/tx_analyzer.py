import logging
from dataclasses import dataclass
from typing import Dict, Any, List, Optional
from guardian.web3sec.simulation import SimulationResult

logger = logging.getLogger("guardian.web3sec.tx_analyzer")

@dataclass
class AnalysisResult:
    blocked: bool
    detector_name: str
    reason: str
    severity: str

class Detector:
    name: str
    enabled: bool

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def analyze(self, tx: Dict[str, Any], sim_result: SimulationResult) -> Optional[AnalysisResult]:
        raise NotImplementedError

class ReserveManipulationDetector(Detector):
    """Detects transfer() + sync() reserve desync attacks.

    Attack pattern: attacker calls transfer(pair, amount) to send tokens directly
    to a DEX pair, then calls sync() (0xfff6cae9) on that pair to update reserves
    without going through the swap path. This creates a price discrepancy.

    Since these are separate transactions, we flag sync() calls to known pair
    contracts as suspicious. For multicall/batched txs, we also check for both
    selectors in the same calldata.
    """
    name = "reserve_manipulation"

    # Correct selectors
    TRANSFER_SELECTOR = "a9059cbb"       # transfer(address,uint256)
    SYNC_SELECTOR = "fff6cae9"           # sync()  — NOT ffcb23f8 (that's skim)
    SKIM_SELECTOR = "bc25cf77"           # skim(address)

    def analyze(self, tx: Dict[str, Any], sim_result: SimulationResult) -> Optional[AnalysisResult]:
        data = tx.get("data", "")
        if not data or data == "0x":
            return None

        # Strip 0x prefix for selector matching
        data_clean = data[2:] if data.startswith("0x") else data

        # Pattern 1: bare sync() call (4 bytes, no args) — suspicious on its own
        if data_clean == self.SYNC_SELECTOR:
            return AnalysisResult(blocked=True, detector_name=self.name,
                                  reason="Detected bare sync() call (reserve manipulation signal)",
                                  severity="high")

        # Pattern 2: multicall containing both transfer + sync
        if self.TRANSFER_SELECTOR in data_clean and self.SYNC_SELECTOR in data_clean:
            return AnalysisResult(blocked=True, detector_name=self.name,
                                  reason="Detected transfer+sync in single tx (reserve desync attack)",
                                  severity="critical")

        # Pattern 3: skim() call — also used in reserve manipulation
        if data_clean.startswith(self.SKIM_SELECTOR):
            return AnalysisResult(blocked=True, detector_name=self.name,
                                  reason="Detected skim() call (reserve manipulation signal)",
                                  severity="medium")

        return None

class InfiniteApprovalDetector(Detector):
    name = "infinite_approval"
    
    def analyze(self, tx: Dict[str, Any], sim_result: SimulationResult) -> Optional[AnalysisResult]:
        data = tx.get("data", "")
        if data.startswith("0x095ea7b3") and "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff" in data:
            return AnalysisResult(blocked=True, detector_name=self.name, reason="Detected infinite approval", severity="high")
        return None

class RoleChangeDetector(Detector):
    name = "role_change"
    
    def analyze(self, tx: Dict[str, Any], sim_result: SimulationResult) -> Optional[AnalysisResult]:
        data = tx.get("data", "")
        selectors = ["0x2f2ff15d", "0xd547741f", "0xf2fde38b"] # grantRole, revokeRole, transferOwnership
        for s in selectors:
            if data.startswith(s):
                return AnalysisResult(blocked=True, detector_name=self.name, reason="Detected role change", severity="high")
        return None

class ZeroSlippageDetector(Detector):
    name = "zero_slippage"
    
    def analyze(self, tx: Dict[str, Any], sim_result: SimulationResult) -> Optional[AnalysisResult]:
        data = tx.get("data", "")
        if data.startswith("0x38ed1739") and "0000000000000000000000000000000000000000000000000000000000000000" in data:
            return AnalysisResult(blocked=True, detector_name=self.name, reason="Detected zero slippage swap", severity="high")
        return None

class ThreatAddressDetector(Detector):
    name = "threat_address"
    
    def __init__(self, enabled: bool = True, threat_feed: List[str] = None):
        super().__init__(enabled)
        self.threat_feed = [addr.lower() for addr in (threat_feed or [])]

    def analyze(self, tx: Dict[str, Any], sim_result: SimulationResult) -> Optional[AnalysisResult]:
        to = tx.get("to", "")
        if to and to.lower() in self.threat_feed:
            return AnalysisResult(blocked=True, detector_name=self.name, reason="Destination address is in threat feed", severity="critical")
        return None

class TransactionAnalyzer:
    def __init__(self, config: Dict[str, Any]):
        rules_config = config.get("detection_rules", {})
        self.detectors = [
            ReserveManipulationDetector(enabled=rules_config.get("reserve_manipulation", True)),
            InfiniteApprovalDetector(enabled=rules_config.get("infinite_approval", True)),
            RoleChangeDetector(enabled=rules_config.get("role_change", True)),
            ZeroSlippageDetector(enabled=rules_config.get("zero_slippage", True)),
            ThreatAddressDetector(enabled=rules_config.get("threat_address", True), threat_feed=config.get("threat_feed_addresses", [])),
        ]

    def analyze_transaction(self, tx: Dict[str, Any], sim_result: SimulationResult, live_rules: Optional[Dict[str, bool]] = None) -> Optional[AnalysisResult]:
        for detector in self.detectors:
            is_enabled = live_rules.get(detector.name, detector.enabled) if live_rules is not None else detector.enabled
            if is_enabled:
                result = detector.analyze(tx, sim_result)
                if result and result.blocked:
                    return result
        return None
