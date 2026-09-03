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
    tenderly_url: Optional[str] = None

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

    def simulate_with_tenderly(
        self,
        tx: Dict[str, Any],
        network_id: str = "10143",
    ) -> Optional[SimulationResult]:
        """Performs full state-trace transaction simulation via Tenderly API."""
        import os, requests
        access_key = os.getenv("TENDERLY_ACCESS_KEY")
        account = os.getenv("TENDERLY_ACCOUNT_SLUG", "monad-86d12ef02b")
        project = os.getenv("TENDERLY_PROJECT_SLUG", "project")

        if not access_key:
            return None

        url = f"https://api.tenderly.co/api/v1/account/{account}/project/{project}/simulate"
        headers = {"X-Access-Key": access_key, "Content-Type": "application/json"}

        payload = {
            "network_id": str(network_id),
            "from": tx.get("from", "0x1D4549B95dccAC8203393543187b25B3137D0bf6"),
            "to": tx.get("to"),
            "input": tx.get("data", "0x"),
            "value": tx.get("value", 0),
            "gas": tx.get("gas", 300000),
            "save": True,
        }

        try:
            r = requests.post(url, headers=headers, json=payload, timeout=8.0)
            if r.status_code == 200:
                data = r.json()
                tx_info = data.get("transaction", {})
                sim_id = data.get("simulation", {}).get("id")
                trace_url = (
                    f"https://dashboard.tenderly.co/{account}/{project}/simulator/{sim_id}"
                    if sim_id else None
                )
                success = bool(tx_info.get("status"))
                gas_used = int(tx_info.get("gas_used", 0))
                error_msg = tx_info.get("error_message") if not success else None

                ct = tx_info.get("call_trace")
                return_data = "0x"
                if isinstance(ct, list) and len(ct) > 0 and isinstance(ct[0], dict):
                    return_data = str(ct[0].get("output") or "0x")
                elif isinstance(ct, dict):
                    return_data = str(ct.get("output") or "0x")

                return SimulationResult(
                    success=success,
                    gas_used=gas_used,
                    return_data=return_data,
                    revert_reason=error_msg,
                    trace={"call_trace": ct} if isinstance(ct, list) else ct,
                    tenderly_url=trace_url,
                )
        except Exception as e:
            logger.warning(f"Tenderly simulation failed: {e}")

        return None

    def simulate_transaction(self, tx: Dict[str, Any]) -> SimulationResult:
        # 1. Try Tenderly simulation if configured
        tenderly_res = self.simulate_with_tenderly(tx)
        if tenderly_res is not None:
            return tenderly_res

        # 2. Fallback to node eth_call simulation
        tx_params = {
            "from": tx.get("from"),
            "to": tx.get("to"),
            "data": tx.get("data", "0x"),
            "value": tx.get("value", 0),
        }
        
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

