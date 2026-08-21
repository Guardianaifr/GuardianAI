import logging
from dataclasses import dataclass
from typing import Optional, Dict, Any
from web3 import Web3

logger = logging.getLogger("guardian.web3sec.simulation")

@dataclass
class SimulationResult:
    success: bool
    gas_used: int
    return_data: str
    revert_reason: Optional[str] = None
    trace: Optional[Dict[str, Any]] = None

class SimulationEngine:
    def __init__(self, w3: Web3):
        self.w3 = w3
        self._debug_trace_available = None

    def _check_debug_trace(self) -> bool:
        if self._debug_trace_available is not None:
            return self._debug_trace_available
        try:
            # Probe debug_traceCall
            self.w3.provider.make_request("debug_traceCall", [{"to": "0x0000000000000000000000000000000000000000", "data": "0x"}, "latest"])
            self._debug_trace_available = True
        except Exception as e:
            logger.warning(f"debug_traceCall unavailable: {e}")
            self._debug_trace_available = False
        return self._debug_trace_available

    def simulate_transaction(self, tx: Dict[str, Any]) -> SimulationResult:
        tx_params = {
            "from": tx.get("from"),
            "to": tx.get("to"),
            "data": tx.get("data", "0x"),
            "value": tx.get("value", 0),
        }
        
        # basic simulation
        try:
            return_data = self.w3.eth.call(tx_params).hex()
            gas_used = self.w3.eth.estimate_gas(tx_params)
            trace = None
            if self._check_debug_trace():
                try:
                    trace_resp = self.w3.provider.make_request("debug_traceCall", [tx_params, "latest"])
                    if "result" in trace_resp:
                        trace = trace_resp["result"]
                except Exception as e:
                    logger.debug(f"Trace failed: {e}")
            return SimulationResult(success=True, gas_used=gas_used, return_data=return_data, trace=trace)
        except Exception as e:
            return SimulationResult(success=False, gas_used=0, return_data="", revert_reason=str(e))
