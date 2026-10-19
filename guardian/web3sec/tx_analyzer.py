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

def _word(data_clean: str, index: int) -> Optional[int]:
    """Calldata word `index` (after the 4-byte selector) as an int, or None if absent or not hex.
    A truncated word is zero-padded on the right, as CALLDATALOAD reads it."""
    start = 8 + 64 * index
    w = data_clean[start:start + 64]
    if not w:
        return None
    try:
        return int(w.ljust(64, "0"), 16)
    except ValueError:
        return None


class InfiniteApprovalDetector(Detector):
    """Flags approve / increaseAllowance with an amount in the top half of uint256 (>= 2**255), and
    Permit2 approve with an amount in the top half of uint160 (>= 2**159)."""
    name = "infinite_approval"

    ERC20_SELECTORS = ("095ea7b3", "39509351")  # approve, increaseAllowance
    PERMIT2_APPROVE = "87517c45"                # approve(token, spender, uint160 amount, uint48 expiration)

    def analyze(self, tx: Dict[str, Any], sim_result: SimulationResult) -> Optional[AnalysisResult]:
        data = str(tx.get("data", "") or "").lower()
        data_clean = data[2:] if data.startswith("0x") else data
        sel = data_clean[:8]
        amount = None
        threshold = 2 ** 255
        if sel in self.ERC20_SELECTORS:
            amount = _word(data_clean, 1)
        elif sel == self.PERMIT2_APPROVE:
            amount = _word(data_clean, 2)
            threshold = 2 ** 159
        if amount is not None and amount >= threshold:
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
    """swapExactTokensForTokens(amountIn, amountOutMin, ...) with amountOutMin == 0."""
    name = "zero_slippage"

    def analyze(self, tx: Dict[str, Any], sim_result: SimulationResult) -> Optional[AnalysisResult]:
        data = str(tx.get("data", "") or "").lower()
        data_clean = data[2:] if data.startswith("0x") else data
        if data_clean.startswith("38ed1739") and len(data_clean) >= 136 and _word(data_clean, 1) == 0:
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

    _SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}

    def analyze_transaction(self, tx: Dict[str, Any], sim_result: SimulationResult, live_rules: Optional[Dict[str, bool]] = None) -> Optional[AnalysisResult]:
        """Runs every enabled detector and returns the most severe block (first one wins a tie)."""
        worst: Optional[AnalysisResult] = None
        for detector in self.detectors:
            is_enabled = live_rules.get(detector.name, detector.enabled) if live_rules is not None else detector.enabled
            if not is_enabled:
                continue
            result = detector.analyze(tx, sim_result)
            if result and result.blocked:
                if worst is None or self._SEVERITY_RANK.get(result.severity, 0) > self._SEVERITY_RANK.get(worst.severity, 0):
                    worst = result
        return worst
