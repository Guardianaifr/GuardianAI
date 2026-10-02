"""On-chain scam-list lookups for the attestation relay.

Reads GuardianThreatFeedRegistry.isMalicious(address) on Monad and extracts every
address a transaction can move value to (target, ERC-20/721 recipients, spenders,
operators), so a payment to a listed wallet is refused even when the prompt looks polite
or is missing.
"""
from __future__ import annotations

import os
import threading
import time
from typing import Callable, Dict, List, Optional, Tuple

from eth_abi import decode, encode
from eth_utils import keccak
from web3 import Web3

DEFAULT_REGISTRY = "0x576CC248D8c406ac302b74e7BFd571E9F989f467"
_IS_MALICIOUS = keccak(text="isMalicious(address)")[:4]

# selector -> index of the address argument that receives value / rights
_RECIPIENT_ARG = {
    "0xa9059cbb": 0,  # transfer(address to, uint256)
    "0x095ea7b3": 0,  # approve(address spender, uint256)
    "0x39509351": 0,  # increaseAllowance(address spender, uint256)
    "0xa22cb465": 0,  # setApprovalForAll(address operator, bool)
    "0x23b872dd": 1,  # transferFrom(address from, address to, uint256)
    "0x42842e0e": 1,  # safeTransferFrom(address from, address to, uint256)
    "0xb88d4fde": 1,  # safeTransferFrom(address from, address to, uint256, bytes)
    "0xf242432a": 1,  # ERC-1155 safeTransferFrom(from, to, id, amount, data)
    "0x2eb2c2d6": 1,  # ERC-1155 safeBatchTransferFrom(from, to, ...)
}


def value_destinations(target: str, calldata_hex: str) -> List[str]:
    """Every address this call can send value or token rights to (lowercased, de-duplicated)."""
    out = [target.lower()]
    data = (calldata_hex or "0x").lower()
    sel = data[:10]
    idx = _RECIPIENT_ARG.get(sel)
    if idx is not None:
        word = data[10 + 64 * idx: 10 + 64 * (idx + 1)]
        if len(word) == 64:
            out.append("0x" + word[24:])
    return list(dict.fromkeys(out))


class ThreatFeedChecker:
    """Cached isMalicious() reads. Raises on RPC failure so callers can fail closed."""

    def __init__(self, rpc_url: str, registry: str = DEFAULT_REGISTRY, ttl_seconds: int = 60,
                 call: Optional[Callable[[str, str], bytes]] = None):
        self.registry = Web3.to_checksum_address(registry)
        self.ttl = ttl_seconds
        self._cache: Dict[str, Tuple[float, bool, str]] = {}
        self._lock = threading.Lock()
        if call is None:
            w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={"timeout": 5}))
            call = lambda to, data: bytes(w3.eth.call({"to": to, "data": data}))
        self._call = call

    @classmethod
    def from_env(cls, rpc_url: Optional[str] = None) -> Optional["ThreatFeedChecker"]:
        if os.environ.get("GUARDIAN_THREAT_FEED_CHECK", "true").strip().lower() == "false":
            return None
        rpc = (rpc_url or os.environ.get("GUARDIAN_UPSTREAM_RPC") or os.environ.get("MONAD_TESTNET_RPC")
               or os.environ.get("MONAD_RPC_URL") or "https://testnet-rpc.monad.xyz")
        reg = os.environ.get("GUARDIAN_THREAT_FEED_CONTRACT", DEFAULT_REGISTRY)
        return cls(rpc, reg)

    def is_malicious(self, address: str) -> Tuple[bool, str]:
        key = address.lower()
        now = time.time()
        with self._lock:
            hit = self._cache.get(key)
            if hit and now - hit[0] < self.ttl:
                return hit[1], hit[2]
        data = "0x" + (_IS_MALICIOUS + encode(["address"], [Web3.to_checksum_address(address)])).hex()
        flagged, reason = decode(["bool", "string"], self._call(self.registry, data))
        with self._lock:
            self._cache[key] = (now, bool(flagged), str(reason))
        return bool(flagged), str(reason)
