import time
import logging
import requests
import threading
from typing import Dict, Any, List
from web3 import Web3

logger = logging.getLogger("guardian.web3sec.chain_monitor")


class ChainMonitor:
    """Polls on-chain events for explicitly watched contracts and posts alerts.

    IMPORTANT: watched_contracts must be non-empty. If empty, monitoring is
    disabled entirely to prevent chain-wide alert floods. Every Ownable
    deployment emits OwnershipTransferred at construction — querying the whole
    chain guarantees continuous noise. We scope all get_logs calls to the
    watched address list so we only pull events for contracts we care about.
    """

    # Event topic signatures
    _ROLE_GRANTED   = "0x2f8788117e7eff1d82e926ec794901d17c78024a50270940304540a733656f0d"
    _ROLE_REVOKED   = "0xf6391f5c32d9c69d2a47ea670b442974b53935d1edc7fd64eb21e047a839171b"
    _OWNERSHIP_XFER = "0x8be0079c531659141344cd1fd0a4f28419497f9722a3daafe3b4186f6b6457e0"
    # OwnershipTransferred(address(0), newOwner) fires at deployment — zero-padded
    _ZERO_ADDR_TOPIC = "0x0000000000000000000000000000000000000000000000000000000000000000"

    def __init__(self, config: Dict[str, Any]):
        self.config = config.get("web3_security", {})
        self.monitor_config = self.config.get("chain_monitor", {})
        self.enabled = self.monitor_config.get("enabled", False)
        self.rpc_url = self.config.get("upstream_rpc", "https://testnet.monad.xyz/v1")
        self.poll_interval = self.monitor_config.get("poll_interval_seconds", 2)
        self.watched_contracts = [addr.lower() for addr in self.monitor_config.get("watched_contracts", [])]
        self.alert_webhook = self.config.get("alert_webhook", "http://127.0.0.1:8001/api/v1/telemetry")
        self.w3 = Web3(Web3.HTTPProvider(self.rpc_url))
        self._thread = None
        self._running = False
        self.last_block = None

    def start(self):
        if not self.enabled or self._thread is not None:
            return
        if not self.watched_contracts:
            logger.warning(
                "ChainMonitor: watched_contracts is empty — monitoring disabled to prevent "
                "chain-wide alert flood. Add contract addresses to "
                "web3_security.chain_monitor.watched_contracts in config.yaml."
            )
            return
        logger.info(
            f"Starting Chain Monitor. Polling every {self.poll_interval}s "
            f"for {len(self.watched_contracts)} contract(s)"
        )
        self._running = True
        self._thread = threading.Thread(target=self._run_loop, daemon=True)
        self._thread.start()

    def stop(self):
        self._running = False

    def _run_loop(self):
        while self._running:
            try:
                latest_block = self.w3.eth.block_number
                if self.last_block is None:
                    self.last_block = latest_block - 1

                if latest_block > self.last_block:
                    self._process_range(self.last_block + 1, latest_block)
                    self.last_block = latest_block

            except Exception as e:
                logger.error(f"Chain monitor error: {e}")
            
            time.sleep(self.poll_interval)

    def _process_range(self, from_block: int, to_block: int):
        """Fetch logs ONLY for watched_contracts (address filter in the RPC call)
        so we never pull chain-wide events."""
        try:
            log_filter: Dict[str, Any] = {
                "fromBlock": from_block,
                "toBlock": to_block,
                "address": self.watched_contracts,   # scoped — not chain-wide
                "topics": [[
                    self._ROLE_GRANTED,
                    self._ROLE_REVOKED,
                    self._OWNERSHIP_XFER,
                ]],
            }
            logs = self.w3.eth.get_logs(log_filter)
        except Exception as e:
            logger.error(f"Failed to fetch logs for blocks {from_block}-{to_block}: {e}")
            return

        for log in logs:
            topics = log.get("topics", [])
            if not topics:
                continue

            sig = topics[0].hex() if isinstance(topics[0], bytes) else topics[0]
            addr = log.get("address", "").lower()
            tx_hash = log.get("transactionHash", b"")
            tx_hash_hex = tx_hash.hex() if isinstance(tx_hash, bytes) else tx_hash

            # Skip OwnershipTransferred where previousOwner == address(0):
            # that's a deployment event, not a live transfer — guaranteed noise.
            if sig == self._OWNERSHIP_XFER and len(topics) >= 2:
                prev_owner_topic = topics[1].hex() if isinstance(topics[1], bytes) else topics[1]
                if prev_owner_topic == self._ZERO_ADDR_TOPIC:
                    continue

            event_name = {
                self._ROLE_GRANTED:   "RoleGranted",
                self._ROLE_REVOKED:   "RoleRevoked",
                self._OWNERSHIP_XFER: "OwnershipTransferred",
            }.get(sig, "UnknownEvent")

            self._send_alert({
                "event_type": "chain_monitor_alert",
                "severity": "high",
                "details": {
                    "contract": addr,
                    "tx_hash": tx_hash_hex,
                    "event": event_name,
                    "block": log.get("blockNumber"),
                }
            })

    def _send_alert(self, payload: Dict[str, Any]):
        try:
            requests.post(self.alert_webhook, json=payload, timeout=5)
        except Exception as e:
            logger.error(f"Failed to send chain monitor alert: {e}")
