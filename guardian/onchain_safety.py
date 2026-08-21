"""
On-chain Safety Guard — GuardianAI Live Mode Pre-flight Check.

Enforces that GuardianTimelock owns all 5 live contracts before any
real on-chain transaction is permitted. Call assert_timelock_owns_all()
at the entry point of every live-mode code path.

Behaviour:
  - GUARDIAN_ANCHOR_MODE != "live"  → immediate no-op (zero cost).
  - GUARDIAN_ANCHOR_MODE == "live"  → calls owner() on each configured
    contract once per process (result cached under a lock). If ANY
    contract's owner is not the timelock address, raises
    OwnershipNotTransferredError listing every offending contract.

Environment variables read:
  GUARDIAN_ANCHOR_MODE          "live" | "simulated" (default)
  GUARDIAN_TIMELOCK_ADDRESS     Deployed GuardianTimelock address (required in live mode)
  GUARDIAN_DEPLOYER_PRIVATE_KEY Used only to label EOA violations in error messages
  GUARDIAN_CORTEX_CONTRACT_<CHAIN>
  GUARDIAN_INSURANCE_CONTRACT_<CHAIN>
  GUARDIAN_INTERLOCK_CONTRACT_<CHAIN>
  GUARDIAN_THREATFEED_CONTRACT_<CHAIN>
  GUARDIAN_RISK_CONTRACT_<CHAIN>
"""

from __future__ import annotations

import logging
import os
import threading
from typing import Any, Dict, List, Optional

logger = logging.getLogger("guardian.onchain_safety")

# ── Minimal ABI — only owner() is needed ────────────────────────────────────
_OWNER_ABI: List[Dict[str, Any]] = [
    {
        "inputs": [],
        "name": "owner",
        "outputs": [{"internalType": "address", "name": "", "type": "address"}],
        "stateMutability": "view",
        "type": "function",
    }
]

# Human-readable name → env var pattern (chain inserted at call time)
_CONTRACT_ENV_PATTERNS: Dict[str, str] = {
    "GuardianCortexAnchor":       "GUARDIAN_CORTEX_CONTRACT_{chain}",
    "GuardianInsuranceLedger":    "GUARDIAN_INSURANCE_CONTRACT_{chain}",
    "GuardianInterlockRegistry":  "GUARDIAN_INTERLOCK_CONTRACT_{chain}",
    "GuardianThreatFeedRegistry": "GUARDIAN_THREATFEED_CONTRACT_{chain}",
    "GuardianRiskAttestation":    "GUARDIAN_RISK_CONTRACT_{chain}",
}

_RPC_BY_CHAIN: Dict[str, str] = {
    "monad":    "https://testnet.monad.xyz/v1",
    "base":     "https://mainnet.base.org",
    "ethereum": "https://eth.llamarpc.com",
}

# ── Process-scoped cache ─────────────────────────────────────────────────────
_lock = threading.Lock()
_checked_chains: set = set()   # chains that have already passed the check


# ── Public exception ─────────────────────────────────────────────────────────

class OwnershipNotTransferredError(RuntimeError):
    """
    Raised when GUARDIAN_ANCHOR_MODE=live is set but one or more contracts
    still have an owner that is NOT the GuardianTimelock address.

    Attributes:
        violations: list of dicts with keys:
            contract, env_var, address, actual_owner,
            expected_timelock, is_deployer_eoa
    """

    def __init__(self, violations: List[Dict[str, Any]]) -> None:
        self.violations = violations

        lines = "\n".join(
            "  * {contract} (env: {env_var})\n"
            "      address   : {address}\n"
            "      owner now : {actual_owner}{eoa_tag}\n"
            "      expected  : {expected_timelock}".format(
                eoa_tag=" <- DEPLOYER EOA" if v.get("is_deployer_eoa") else "",
                **v,
            )
            for v in violations
        )

        super().__init__(
            "\n\n"
            + "=" * 72 + "\n"
            + "LIVE MODE BLOCKED -- Ownership not yet transferred to GuardianTimelock\n"
            + "=" * 72 + "\n"
            + lines + "\n\n"
            + "Run the transfer script before enabling live mode:\n"
            + "  TIMELOCK_ADDRESS=<addr> \\\n"
            + "  CORTEX_ANCHOR_ADDRESS=<addr> \\\n"
            + "  INSURANCE_LEDGER_ADDRESS=<addr> \\\n"
            + "  INTERLOCK_REGISTRY_ADDRESS=<addr> \\\n"
            + "  THREAT_FEED_REGISTRY_ADDRESS=<addr> \\\n"
            + "  RISK_ATTESTATION_ADDRESS=<addr> \\\n"
            + "  npx hardhat run contracts/scripts/transfer_ownership_to_timelock.js\n\n"
            + "Then set GUARDIAN_TIMELOCK_ADDRESS in your environment.\n"
            + "=" * 72 + "\n"
        )


# ── Public API ───────────────────────────────────────────────────────────────

def assert_timelock_owns_all(chain: str = "monad") -> None:
    """
    Verify that GuardianTimelock is the owner of all 5 live contracts on
    *chain* before permitting any on-chain write.

    This function is a no-op when GUARDIAN_ANCHOR_MODE != "live".
    The first successful check for a given chain is cached for the lifetime
    of the process; subsequent calls return instantly.

    Args:
        chain: chain identifier ("monad", "base", "ethereum").

    Raises:
        EnvironmentError:           GUARDIAN_TIMELOCK_ADDRESS not set in live mode.
        OwnershipNotTransferredError: one or more contracts still EOA-owned.
        RuntimeError:               owner() call failed (network / ABI issue).
    """
    mode = os.getenv("GUARDIAN_ANCHOR_MODE", "simulated").strip().lower()
    if mode != "live":
        return

    chain_key = chain.strip().lower()

    with _lock:
        if chain_key in _checked_chains:
            return
        _run_ownership_check(chain_key)
        _checked_chains.add(chain_key)


def _run_ownership_check(chain: str) -> None:
    """
    Internal: perform owner() RPC calls for every configured contract.
    Called under _lock with GUARDIAN_ANCHOR_MODE already confirmed == "live".
    """
    from web3 import Web3
    from eth_account import Account

    timelock_raw = os.getenv("GUARDIAN_TIMELOCK_ADDRESS", "").strip()
    if not timelock_raw:
        raise EnvironmentError(
            "GUARDIAN_TIMELOCK_ADDRESS must be set when GUARDIAN_ANCHOR_MODE=live. "
            "Deploy GuardianTimelock first and set this env var."
        )

    rpc_url = _RPC_BY_CHAIN.get(chain, _RPC_BY_CHAIN["monad"])
    w3 = Web3(Web3.HTTPProvider(rpc_url))

    timelock_cs = w3.to_checksum_address(timelock_raw)

    # Resolve deployer address for labelling only (not a blocker if missing)
    deployer_addr: Optional[str] = None
    deployer_key = os.getenv("GUARDIAN_DEPLOYER_PRIVATE_KEY", "").strip()
    if deployer_key:
        try:
            deployer_addr = Account.from_key(deployer_key).address
        except Exception:
            pass

    violations: List[Dict[str, Any]] = []

    for contract_name, env_pattern in _CONTRACT_ENV_PATTERNS.items():
        env_var = env_pattern.format(chain=chain.upper())
        contract_raw = os.getenv(env_var, "").strip()

        if not contract_raw:
            # Not yet deployed to this chain — ownership check irrelevant
            logger.debug(
                "Ownership check: %s skipped (%s not set)", contract_name, env_var
            )
            continue

        try:
            contract = w3.eth.contract(
                address=w3.to_checksum_address(contract_raw),
                abi=_OWNER_ABI,
            )
            actual_owner: str = contract.functions.owner().call()

        except Exception as exc:
            raise RuntimeError(
                f"Ownership check RPC failed for {contract_name} "
                f"at {contract_raw} on {chain}: {exc}"
            ) from exc

        if actual_owner.lower() == timelock_cs.lower():
            logger.info(
                "Ownership OK: %s → timelock (%s…)",
                contract_name,
                timelock_cs[:14],
            )
        else:
            is_eoa = bool(
                deployer_addr
                and actual_owner.lower() == deployer_addr.lower()
            )
            logger.error(
                "LIVE MODE BLOCKED: %s owner=%s%s expected=%s",
                contract_name,
                actual_owner[:14],
                " [DEPLOYER EOA]" if is_eoa else "",
                timelock_cs[:14],
            )
            violations.append(
                {
                    "contract":          contract_name,
                    "env_var":           env_var,
                    "address":           contract_raw,
                    "actual_owner":      actual_owner,
                    "expected_timelock": timelock_cs,
                    "is_deployer_eoa":   is_eoa,
                }
            )

    if violations:
        raise OwnershipNotTransferredError(violations)


# ── Test helper — never call in production code ──────────────────────────────

def _reset_cache_for_testing() -> None:
    """
    Clear the per-process ownership check cache.
    ONLY for use in unit tests — never call from production paths.
    """
    global _checked_chains
    with _lock:
        _checked_chains = set()
