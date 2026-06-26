"""
Merkle Anchor — Cryptographic commitment of decision batches on-chain.

Builds Merkle trees from CortexEvent hashes, generates inclusion proofs,
and anchors roots to Monad (primary), Base (secondary), or Ethereum.

Phase 2: Real on-chain support via web3.py when GUARDIAN_DEPLOYER_PRIVATE_KEY
and contract addresses are configured. Falls back to simulation otherwise.
"""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("guardian.cortex.merkle")

# ── Chain Configuration ────────────────────────────────────────
# Monad is primary launch chain; Base is secondary.
CHAIN_CONFIGS: Dict[str, Dict[str, Any]] = {
    "monad": {
        "chain_id": 10143,
        "rpc_url": "https://testnet.monad.xyz/v1",
        "explorer": "https://monadscan.com/tx/",
        "name": "Monad",
        "priority": 1,
        "gas_estimate_gwei": 0.01,  # Extremely cheap on Monad
    },
    "base": {
        "chain_id": 8453,
        "rpc_url": "https://mainnet.base.org",
        "explorer": "https://basescan.org/tx/",
        "name": "Base",
        "priority": 2,
        "gas_estimate_gwei": 0.05,
    },
    "ethereum": {
        "chain_id": 1,
        "rpc_url": "https://eth.llamarpc.com",
        "explorer": "https://etherscan.io/tx/",
        "name": "Ethereum",
        "priority": 3,
        "gas_estimate_gwei": 30.0,
    },
}


def _sha256_bytes(data: bytes) -> bytes:
    """SHA-256 hash returning raw bytes."""
    return hashlib.sha256(data).digest()


def _sha256_hex(data: str) -> str:
    """SHA-256 hash returning hex string."""
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


def _hash_pair(left: bytes, right: bytes) -> bytes:
    """Hash two nodes together (sorted to ensure deterministic ordering)."""
    if left > right:
        left, right = right, left
    return _sha256_bytes(left + right)


@dataclass
class MerkleProof:
    """A proof of inclusion for a single leaf in the Merkle tree."""
    leaf: str
    root: str
    proof: List[str]
    leaf_index: int
    tree_size: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "leaf": self.leaf,
            "root": self.root,
            "proof": self.proof,
            "leaf_index": self.leaf_index,
            "tree_size": self.tree_size,
        }


class MerkleTree:
    """
    Build a Merkle tree from a list of hex-encoded leaf hashes.

    Supports:
    - Building from event merkle_leaf values
    - Generating inclusion proofs for any leaf
    - Verifying proofs against a known root
    """

    def __init__(self, leaves: List[str]):
        """
        Build the tree from a list of hex-encoded leaf hashes.

        Args:
            leaves: List of hex strings (e.g. SHA-256 hashes of events).
        """
        if not leaves:
            raise ValueError("Cannot build Merkle tree from empty leaf list")

        self._original_leaves = list(leaves)
        self._leaf_bytes = [bytes.fromhex(h) for h in leaves]

        # Pad to power of 2 by duplicating last leaf
        n = len(self._leaf_bytes)
        next_pow2 = 1
        while next_pow2 < n:
            next_pow2 *= 2
        while len(self._leaf_bytes) < next_pow2:
            self._leaf_bytes.append(self._leaf_bytes[-1])

        self._tree: List[List[bytes]] = []
        self._build()

    def _build(self) -> None:
        """Build the tree bottom-up."""
        level = list(self._leaf_bytes)
        self._tree.append(level)

        while len(level) > 1:
            next_level = []
            for i in range(0, len(level), 2):
                next_level.append(_hash_pair(level[i], level[i + 1]))
            self._tree.append(next_level)
            level = next_level

    @property
    def root(self) -> str:
        """The Merkle root as a hex string."""
        return self._tree[-1][0].hex()

    @property
    def leaf_count(self) -> int:
        """Original (non-padded) leaf count."""
        return len(self._original_leaves)

    def get_proof(self, leaf_index: int) -> MerkleProof:
        """
        Generate an inclusion proof for the leaf at the given index.

        Args:
            leaf_index: Index into the original leaves list.

        Returns:
            MerkleProof with sibling hashes from leaf to root.
        """
        if leaf_index < 0 or leaf_index >= len(self._original_leaves):
            raise IndexError(f"Leaf index {leaf_index} out of range [0, {len(self._original_leaves)})")

        proof: List[str] = []
        idx = leaf_index

        for level in self._tree[:-1]:  # All levels except root
            sibling_idx = idx ^ 1  # Flip last bit to get sibling
            if sibling_idx < len(level):
                proof.append(level[sibling_idx].hex())
            idx //= 2

        return MerkleProof(
            leaf=self._original_leaves[leaf_index],
            root=self.root,
            proof=proof,
            leaf_index=leaf_index,
            tree_size=len(self._original_leaves),
        )

    @staticmethod
    def verify_proof(leaf_hex: str, proof_hashes: List[str], root_hex: str) -> bool:
        """
        Verify a Merkle inclusion proof.

        Args:
            leaf_hex: The leaf hash (hex string).
            proof_hashes: Sibling hashes from leaf to root (hex strings).
            root_hex: The expected Merkle root (hex string).

        Returns:
            True if the proof is valid.
        """
        current = bytes.fromhex(leaf_hex)
        for sibling_hex in proof_hashes:
            sibling = bytes.fromhex(sibling_hex)
            current = _hash_pair(current, sibling)
        return current.hex() == root_hex


@dataclass
class AnchorResult:
    """Result of anchoring a Merkle root on-chain."""
    success: bool
    chain_id: str
    merkle_root: str
    event_count: int
    tx_hash: str = ""
    explorer_url: str = ""
    error: str = ""
    anchored_at: float = 0.0
    simulated: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "chain_id": self.chain_id,
            "merkle_root": self.merkle_root,
            "event_count": self.event_count,
            "tx_hash": self.tx_hash,
            "explorer_url": self.explorer_url,
            "error": self.error,
            "anchored_at": self.anchored_at,
            "simulated": self.simulated,
        }


class Web3ChainClient:
    """
    Thin wrapper around web3.py for submitting on-chain transactions.

    Only instantiated when GUARDIAN_DEPLOYER_PRIVATE_KEY is set and
    GUARDIAN_ANCHOR_MODE == 'live'. Otherwise MerkleAnchor uses simulated mode.
    """

    def __init__(self, chain_config: Dict[str, Any], chain_name: str):
        from web3 import Web3
        from eth_account import Account

        self.config = chain_config
        self.chain_name = chain_name
        self.w3 = Web3(Web3.HTTPProvider(chain_config["rpc_url"]))

        deployer_key = os.getenv("GUARDIAN_DEPLOYER_PRIVATE_KEY", "")
        if not deployer_key:
            raise EnvironmentError("GUARDIAN_DEPLOYER_PRIVATE_KEY not set")

        self.account = Account.from_key(deployer_key)
        self.max_gas_gwei = float(os.getenv("GUARDIAN_MAX_GAS_PRICE_GWEI", "100"))

        # Load contract ABI and address
        contract_addr = os.getenv(
            f"GUARDIAN_CORTEX_CONTRACT_{chain_name.upper()}", ""
        )
        if not contract_addr:
            raise EnvironmentError(
                f"GUARDIAN_CORTEX_CONTRACT_{chain_name.upper()} not set"
            )

        abi_path = Path(__file__).parent / "contracts" / "cortex_anchor_abi.json"
        if not abi_path.exists():
            raise FileNotFoundError(f"Contract ABI not found: {abi_path}")

        with open(abi_path, "r") as f:
            abi = json.load(f)

        self.contract = self.w3.eth.contract(
            address=self.w3.to_checksum_address(contract_addr),
            abi=abi,
        )
        logger.info(
            "Web3ChainClient initialized for %s (contract=%s, deployer=%s)",
            chain_name, contract_addr[:10] + "…", self.account.address[:10] + "…",
        )

    def commit_root(
        self,
        merkle_root: str,
        event_count: int,
        agent_id: str,
        period_start: int = 0,
        period_end: int = 0,
        max_retries: int = 3,
    ) -> Tuple[bool, str, str]:
        """
        Submit commitRoot() transaction to the CortexAnchor contract.

        Returns:
            (success, tx_hash, error_message)
        """
        from web3 import Web3

        # Gas price safety check
        gas_price = self.w3.eth.gas_price
        gas_price_gwei = gas_price / 1e9
        if gas_price_gwei > self.max_gas_gwei:
            return (
                False, "",
                f"Gas price {gas_price_gwei:.2f} gwei exceeds safety limit "
                f"{self.max_gas_gwei} gwei"
            )

        root_bytes = bytes.fromhex(merkle_root)
        agent_bytes = Web3.keccak(text=agent_id)

        last_error = ""
        for attempt in range(1, max_retries + 1):
            try:
                nonce = self.w3.eth.get_transaction_count(self.account.address)

                txn = self.contract.functions.commitRoot(
                    root_bytes,
                    event_count,
                    agent_bytes,
                    period_start,
                    period_end,
                ).build_transaction({
                    "from": self.account.address,
                    "nonce": nonce,
                    "gas": 200_000,
                    "gasPrice": gas_price,
                    "chainId": self.config["chain_id"],
                })

                signed = self.w3.eth.account.sign_transaction(
                    txn, self.account.key
                )
                tx_hash = self.w3.eth.send_raw_transaction(
                    signed.raw_transaction
                )

                # Wait for receipt with 60s timeout
                receipt = self.w3.eth.wait_for_transaction_receipt(
                    tx_hash, timeout=60
                )

                if receipt.status == 1:
                    return True, tx_hash.hex(), ""
                else:
                    last_error = f"Transaction reverted (receipt status=0)"

            except Exception as exc:
                last_error = f"Attempt {attempt}/{max_retries}: {exc}"
                logger.warning("Anchor tx attempt %d failed: %s", attempt, exc)
                if attempt < max_retries:
                    time.sleep(2 ** attempt)  # Exponential backoff

        return False, "", last_error


class MerkleAnchor:
    """
    Anchor Merkle roots to EVM chains.

    Primary chain: Monad (10,000 TPS, ~$0.0001/tx)
    Fallback:      Base → Ethereum

    Modes:
      - "live": Real on-chain transactions via web3.py (requires
        GUARDIAN_DEPLOYER_PRIVATE_KEY and GUARDIAN_CORTEX_CONTRACT_<CHAIN>)
      - "simulated" (default): Generates deterministic mock tx hashes.
        Safe for development and testing.
    """

    def __init__(self, primary_chain: str = "monad"):
        if primary_chain not in CHAIN_CONFIGS:
            raise ValueError(f"Unknown chain: {primary_chain}. Valid: {list(CHAIN_CONFIGS.keys())}")
        self.primary_chain = primary_chain
        self.chain_config = CHAIN_CONFIGS[primary_chain]

        # Determine anchoring mode
        self.mode = os.getenv("GUARDIAN_ANCHOR_MODE", "simulated").lower()
        self._web3_clients: Dict[str, Web3ChainClient] = {}

        if self.mode == "live":
            try:
                client = Web3ChainClient(self.chain_config, primary_chain)
                self._web3_clients[primary_chain] = client
                logger.info("MerkleAnchor: LIVE mode on %s", primary_chain)
            except Exception as exc:
                logger.warning(
                    "MerkleAnchor: Failed to init live mode for %s (%s). "
                    "Falling back to simulated.",
                    primary_chain, exc,
                )
                self.mode = "simulated"
        else:
            logger.info("MerkleAnchor: SIMULATED mode (set GUARDIAN_ANCHOR_MODE=live for on-chain)")

    def build_batch(
        self, event_leaves: List[str]
    ) -> Tuple[MerkleTree, List[MerkleProof]]:
        """
        Build a Merkle tree from event leaves and generate proofs for all.

        Args:
            event_leaves: List of merkle_leaf values from CortexEvents.

        Returns:
            Tuple of (MerkleTree, list of MerkleProof for each leaf).
        """
        tree = MerkleTree(event_leaves)
        proofs = [tree.get_proof(i) for i in range(len(event_leaves))]
        return tree, proofs

    def anchor_to_chain(
        self,
        merkle_root: str,
        event_count: int,
        agent_id: str = "",
        chain_id: Optional[str] = None,
    ) -> AnchorResult:
        """
        Anchor a Merkle root to the specified chain.

        In live mode: submits a real transaction to the CortexAnchor contract.
        In simulated mode: generates a deterministic mock tx hash.
        """
        chain = chain_id or self.primary_chain
        config = CHAIN_CONFIGS.get(chain)
        if not config:
            return AnchorResult(
                success=False, chain_id=chain, merkle_root=merkle_root,
                event_count=event_count, error=f"Unknown chain: {chain}",
            )

        now = time.time()

        # ── LIVE MODE: Real on-chain transaction ──
        if self.mode == "live" and chain in self._web3_clients:
            client = self._web3_clients[chain]
            success, tx_hash, error = client.commit_root(
                merkle_root=merkle_root,
                event_count=event_count,
                agent_id=agent_id,
            )

            if success:
                explorer_url = f"{config['explorer']}{tx_hash}"
                logger.info(
                    "Cortex anchor (LIVE) -> %s | root=%s | events=%d | tx=%s",
                    config["name"], merkle_root[:16] + "…", event_count,
                    tx_hash[:16] + "…",
                )
                return AnchorResult(
                    success=True,
                    chain_id=chain,
                    merkle_root=merkle_root,
                    event_count=event_count,
                    tx_hash=tx_hash,
                    explorer_url=explorer_url,
                    anchored_at=now,
                    simulated=False,
                )
            else:
                logger.error(
                    "Cortex anchor FAILED on %s: %s (falling back to simulated)",
                    config["name"], error,
                )
                # Fall through to simulated mode on failure

        # ── SIMULATED MODE ──
        tx_hash = _sha256_hex(f"{merkle_root}:{chain}:{now}:{agent_id}")
        explorer_url = f"{config['explorer']}{tx_hash}"

        logger.info(
            "Cortex anchor (SIMULATED) -> %s | root=%s | events=%d | tx=%s",
            config["name"], merkle_root[:16] + "…", event_count, tx_hash[:16] + "…",
        )

        return AnchorResult(
            success=True,
            chain_id=chain,
            merkle_root=merkle_root,
            event_count=event_count,
            tx_hash=tx_hash,
            explorer_url=explorer_url,
            anchored_at=now,
            simulated=True,
        )

    def get_supported_chains(self) -> List[Dict[str, Any]]:
        """Return all supported chains with their configs and deployment status."""
        return [
            {
                "chain_id_name": name,
                "deployed": name in self._web3_clients,
                "mode": "live" if name in self._web3_clients else "simulated",
                **{k: v for k, v in cfg.items() if k != "rpc_url"},
            }
            for name, cfg in CHAIN_CONFIGS.items()
        ]
