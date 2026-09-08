"""GuardianAI Cryptographic Attestation Relayer Service.

Converts off-chain AI safety decisions into verified EIP-712 cryptographic
attestations consumed by GuardianPolicyGuard.sol on Monad.
"""
from __future__ import annotations

import logging
import os
import secrets
import time
from collections import defaultdict
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional, Set, Tuple, Union

from eth_account import Account
from eth_account.messages import encode_typed_data
from web3 import Web3

from guardian.guardrails.input_filter import InputFilter
from guardian.web3sec.tx_analyzer import TransactionAnalyzer, AnalysisResult
from guardian.web3sec.simulation import SimulationResult

logger = logging.getLogger("guardian.relayer.attestation_service")

# ── Minimal Inlined ABI Fragment for Call Wrapping ────────────────────────────
EXECUTE_WITH_ATTESTATION_ABI = [
    {
        "name": "executeWithAttestation",
        "type": "function",
        "stateMutability": "payable",
        "inputs": [
            {"name": "target", "type": "address"},
            {"name": "data", "type": "bytes"},
            {
                "name": "attestation",
                "type": "tuple",
                "components": [
                    {"name": "agentId", "type": "bytes32"},
                    {"name": "targetContract", "type": "address"},
                    {"name": "calldataHash", "type": "bytes32"},
                    {"name": "value", "type": "uint256"},
                    {"name": "riskScore", "type": "uint8"},
                    {"name": "nonce", "type": "uint256"},
                    {"name": "deadline", "type": "uint256"},
                ],
            },
            {"name": "signature", "type": "bytes"},
        ],
        "outputs": [{"name": "", "type": "bytes"}],
    }
]


@dataclass
class SafetyAttestation:
    agentId: str
    targetContract: str
    calldataHash: str
    value: int
    riskScore: int
    nonce: int
    deadline: int

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class AttestationResult:
    status: str  # "approved" or "blocked"
    risk_score: int
    reasons: List[str]
    attestation: Optional[SafetyAttestation]
    signature: Optional[str]
    policy_guard: str
    wrapped_calldata: Optional[str]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "status": self.status,
            "risk_score": self.risk_score,
            "reasons": self.reasons,
            "attestation": self.attestation.to_dict() if self.attestation else None,
            "signature": self.signature,
            "policy_guard": self.policy_guard,
            "verifying_contract": self.policy_guard,
            "wrapped_calldata": self.wrapped_calldata,
        }


@dataclass
class AgentPolicy:
    """Per-agent security policy defining allowed operations and spending limits.

    Attributes:
        allowed_selectors: Set of permitted 4-byte function selectors (e.g. {"0xa9059cbb", "0x095ea7b3"}).
                          If None, selector allowlisting is disabled (blocklist-only mode).
                          If set (even empty), only listed selectors are permitted.
        max_value_per_tx:  Maximum native value (in wei) allowed per single transaction.
                          None = no per-transaction limit.
        max_daily_outflow: Maximum cumulative native value (in wei) allowed per 24-hour rolling window.
                          None = no daily limit.
    """
    allowed_selectors: Optional[Set[str]] = None
    max_value_per_tx: Optional[int] = None
    max_daily_outflow: Optional[int] = None


class OutflowTracker:
    """Tracks cumulative agent outflows within a rolling 24-hour window.

    Uses a simple append-only log of (timestamp, value) pairs per agent,
    with lazy eviction of entries older than the window on each query.
    """

    WINDOW_SECONDS = 86400  # 24 hours

    def __init__(self) -> None:
        # agent_id -> list of (unix_timestamp, value_wei)
        self._ledger: Dict[str, List[Tuple[float, int]]] = defaultdict(list)

    def record(self, agent_id: str, value: int) -> None:
        """Record an approved outflow for an agent."""
        self._ledger[agent_id].append((time.time(), value))

    def cumulative(self, agent_id: str) -> int:
        """Return the total outflow for an agent within the rolling window."""
        now = time.time()
        cutoff = now - self.WINDOW_SECONDS
        entries = self._ledger.get(agent_id, [])
        # Lazy eviction: drop entries outside window
        active = [(ts, v) for ts, v in entries if ts >= cutoff]
        self._ledger[agent_id] = active
        return sum(v for _, v in active)

    def would_exceed(self, agent_id: str, proposed_value: int, cap: int) -> bool:
        """Check if adding proposed_value would exceed the agent's daily cap."""
        return self.cumulative(agent_id) + proposed_value > cap


class SafetyAttestationService:
    """Evaluates agent actions and issues EIP-712 cryptographic attestations for Monad."""

    EIP712_DOMAIN_TYPE = [
        {"name": "name", "type": "string"},
        {"name": "version", "type": "string"},
        {"name": "chainId", "type": "uint256"},
        {"name": "verifyingContract", "type": "address"},
    ]

    SAFETY_ATTESTATION_TYPE = [
        {"name": "agentId", "type": "bytes32"},
        {"name": "targetContract", "type": "address"},
        {"name": "calldataHash", "type": "bytes32"},
        {"name": "value", "type": "uint256"},
        {"name": "riskScore", "type": "uint8"},
        {"name": "nonce", "type": "uint256"},
        {"name": "deadline", "type": "uint256"},
    ]

    def __init__(
        self,
        private_key: Optional[str] = None,
        verifying_contract: Optional[str] = None,
        chain_id: Optional[int] = None,
        max_allowed_risk_score: int = 25,
        ttl_seconds: int = 300,
        tx_analyzer_config: Optional[Dict[str, Any]] = None,
        agent_policies: Optional[Dict[str, AgentPolicy]] = None,
    ):
        self._w3 = Web3()
        self.max_allowed_risk_score = max_allowed_risk_score
        self.ttl_seconds = ttl_seconds

        # Agent-specific security policies (allowlists + spending caps)
        self.agent_policies: Dict[str, AgentPolicy] = agent_policies or {}
        self.outflow_tracker = OutflowTracker()

        # 1. Signer Key Configuration (Audit M-01)
        raw_key = (
            private_key
            or os.environ.get("GUARDIAN_ATTESTATION_SIGNER_KEY")
            or os.environ.get("GUARDIAN_DEPLOYER_PRIVATE_KEY")
        )
        if not raw_key:
            # Ephemeral key fallback for testing/development
            logger.warning("No GUARDIAN_ATTESTATION_SIGNER_KEY set. Generating ephemeral key for testing.")
            self.account = Account.create()
        else:
            normalized_key = raw_key if raw_key.startswith("0x") else "0x" + raw_key
            self.account = Account.from_key(normalized_key)

        self.signer_address = self.account.address

        # 2. Verifying Contract Address (Audit L-02)
        raw_guard = (
            verifying_contract
            or os.environ.get("GUARDIAN_POLICY_GUARD_CONTRACT_MONAD")
            or "0x0000000000000000000000000000000000000000"
        )
        self.verifying_contract = Web3.to_checksum_address(raw_guard)

        # 3. Chain ID (Audit L-03)
        self.chain_id = int(
            chain_id
            or os.environ.get("MONAD_CHAIN_ID")
            or 10143
        )

        # 4. Security Subsystems
        self.input_filter = InputFilter()
        analyzer_cfg = tx_analyzer_config or {
            "detection_rules": {
                "reserve_manipulation": True,
                "infinite_approval": True,
                "role_change": True,
                "zero_slippage": True,
                "threat_address": True,
            },
            "threat_feed_addresses": [],
        }
        self.tx_analyzer = TransactionAnalyzer(analyzer_cfg)

        # 5. Pre-compiled contract encoder for call wrapping (Audit M-03)
        self._wrapper_contract = self._w3.eth.contract(abi=EXECUTE_WITH_ATTESTATION_ABI)

    def _normalize_agent_id(self, agent_id: Union[str, bytes]) -> str:
        """Normalizes agent ID to bytes32 hex string (Audit L-01)."""
        if isinstance(agent_id, bytes):
            return "0x" + agent_id.hex().rjust(64, "0")[:64]
        if isinstance(agent_id, str):
            if agent_id.startswith("0x") and len(agent_id) == 66:
                return agent_id.lower()
            h = Web3.keccak(text=agent_id).hex().lower()
            clean = h[2:] if h.startswith("0x") else h
            return "0x" + clean
        h = Web3.keccak(text=str(agent_id)).hex().lower()
        clean = h[2:] if h.startswith("0x") else h
        return "0x" + clean

    def _compute_risk_score(
        self,
        agent_id: str,
        prompt: Optional[str],
        target: Optional[str],
        calldata_hex: str,
        value: int,
    ) -> Tuple[int, List[str]]:
        """Composite safety evaluation mapping boolean/categorical outputs to a 0-100 score (Audit H-01)."""
        score = 0
        reasons: List[str] = []

        # Target address check
        if not target or target.lower() in ("0x", "0x0", "0x0000000000000000000000000000000000000000"):
            return 100, ["Invalid or zero target address"]

        if target.lower() == self.verifying_contract.lower() and self.verifying_contract != "0x0000000000000000000000000000000000000000":
            return 100, ["Self-call to GuardianPolicyGuard is prohibited"]

        # ── Agent Policy Enforcement ──────────────────────────────────────
        policy = self.agent_policies.get(agent_id)
        if policy:
            # 1. Function Selector Allowlist (zero-trust: deny-by-default)
            if policy.allowed_selectors is not None:
                selector = calldata_hex[:10].lower() if len(calldata_hex) >= 10 else "0x"
                if selector not in policy.allowed_selectors:
                    return 100, [
                        f"Function selector {selector} not in agent allowlist. "
                        f"Permitted: {sorted(policy.allowed_selectors)}"
                    ]

            # 2. Per-Transaction Spending Cap
            if policy.max_value_per_tx is not None and value > policy.max_value_per_tx:
                return 100, [
                    f"Transaction value {value} wei exceeds per-tx cap of "
                    f"{policy.max_value_per_tx} wei"
                ]

            # 3. Rolling 24h Outflow Cap
            if policy.max_daily_outflow is not None and value > 0:
                if self.outflow_tracker.would_exceed(agent_id, value, policy.max_daily_outflow):
                    current = self.outflow_tracker.cumulative(agent_id)
                    return 100, [
                        f"Transaction would push 24h outflow to {current + value} wei, "
                        f"exceeding daily cap of {policy.max_daily_outflow} wei"
                    ]

        # ── Standard Checks (blocklist layer) ─────────────────────────────

        # 4. Prompt Injection & Jailbreak Analysis
        if prompt and prompt.strip():
            try:
                is_safe = self.input_filter.check_prompt(prompt)
                if not is_safe:
                    score += 50
                    reasons.append("Prompt injection or adversarial pattern detected by InputFilter")
            except Exception as e:
                logger.error(f"Error checking prompt: {e}")
                score += 25
                reasons.append(f"Prompt check error: {e}")

        # 5. Transaction Analysis & Threat Feed
        tx_dict = {
            "to": target,
            "data": calldata_hex,
            "value": value,
        }
        dummy_sim = SimulationResult(success=True, gas_used=50000, return_data="")
        try:
            analysis: Optional[AnalysisResult] = self.tx_analyzer.analyze_transaction(tx_dict, dummy_sim)
            if analysis and analysis.blocked:
                if analysis.severity == "critical":
                    score += 50
                    reasons.append(f"Critical transaction security violation: {analysis.reason}")
                elif analysis.severity == "high":
                    score += 30
                    reasons.append(f"High-risk transaction violation: {analysis.reason}")
                else:
                    score += 15
                    reasons.append(f"Suspicious transaction violation: {analysis.reason}")
        except Exception as e:
            logger.error(f"Error analyzing transaction: {e}")

        clamped = min(100, max(0, score))
        return clamped, reasons

    def build_eip712_data(self, attestation: SafetyAttestation) -> Dict[str, Any]:
        """Constructs the exact EIP-712 structured payload dictionary."""
        raw_agent_id = (
            bytes.fromhex(attestation.agentId[2:])
            if attestation.agentId.startswith("0x")
            else bytes.fromhex(attestation.agentId)
        )
        raw_calldata_hash = (
            bytes.fromhex(attestation.calldataHash[2:])
            if attestation.calldataHash.startswith("0x")
            else bytes.fromhex(attestation.calldataHash)
        )
        return {
            "types": {
                "EIP712Domain": self.EIP712_DOMAIN_TYPE,
                "SafetyAttestation": self.SAFETY_ATTESTATION_TYPE,
            },
            "primaryType": "SafetyAttestation",
            "domain": {
                "name": "GuardianPolicyGuard",
                "version": "1",
                "chainId": self.chain_id,
                "verifyingContract": self.verifying_contract,
            },
            "message": {
                "agentId": raw_agent_id,
                "targetContract": attestation.targetContract,
                "calldataHash": raw_calldata_hash,
                "value": attestation.value,
                "riskScore": attestation.riskScore,
                "nonce": attestation.nonce,
                "deadline": attestation.deadline,
            },
        }

    def sign_attestation(self, attestation: SafetyAttestation) -> str:
        """Signs typed structured data using the relayer's private key."""
        eip712_dict = self.build_eip712_data(attestation)
        signable = encode_typed_data(full_message=eip712_dict)
        signed = self.account.sign_message(signable)
        return "0x" + signed.signature.hex()

    def verify_attestation_signature(
        self, attestation: SafetyAttestation, signature: str
    ) -> bool:
        """Verifies signature locally against the configured relayer signer address."""
        try:
            eip712_dict = self.build_eip712_data(attestation)
            signable = encode_typed_data(full_message=eip712_dict)
            recovered = Account.recover_message(signable, signature=signature)
            return recovered.lower() == self.signer_address.lower()
        except Exception as e:
            logger.warning(f"Signature verification failed: {e}")
            return False

    def wrap_for_policy_guard(
        self,
        target: str,
        data_hex: str,
        attestation: SafetyAttestation,
        signature: str,
    ) -> str:
        """Encodes calldata for calling GuardianPolicyGuard.executeWithAttestation(...) (Audit M-03)."""
        target_addr = Web3.to_checksum_address(target)
        raw_data = bytes.fromhex(data_hex[2:]) if data_hex.startswith("0x") else bytes.fromhex(data_hex)
        raw_sig = bytes.fromhex(signature[2:]) if signature.startswith("0x") else bytes.fromhex(signature)

        agent_hex = attestation.agentId[2:] if attestation.agentId.startswith("0x") else attestation.agentId
        agent_bytes32 = bytes.fromhex(agent_hex.rjust(64, "0")[:64])

        hash_hex = attestation.calldataHash[2:] if attestation.calldataHash.startswith("0x") else attestation.calldataHash
        calldata_hash_bytes32 = bytes.fromhex(hash_hex.rjust(64, "0")[:64])

        attestation_tuple = (
            agent_bytes32,
            Web3.to_checksum_address(attestation.targetContract),
            calldata_hash_bytes32,
            attestation.value,
            attestation.riskScore,
            attestation.nonce,
            attestation.deadline,
        )

        calldata = self._wrapper_contract.encode_abi(
            "executeWithAttestation",
            [target_addr, raw_data, attestation_tuple, raw_sig],
        )
        return calldata

    def evaluate_and_attest(
        self,
        agent_id: Union[str, bytes],
        target: str,
        data: Optional[Union[str, bytes]] = None,
        value: int = 0,
        prompt: Optional[str] = None,
        nonce: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
    ) -> AttestationResult:
        """Evaluates safety and signs an attestation if risk <= maxAllowedRiskScore."""
        # 1. Normalize calldata and hash
        if data is None or data == "" or data == "0x":
            calldata_hex = "0x"
            calldata_bytes = b""
        elif isinstance(data, str):
            calldata_hex = data if data.startswith("0x") else "0x" + data
            calldata_bytes = bytes.fromhex(calldata_hex[2:])
        else:
            calldata_bytes = bytes(data)
            calldata_hex = "0x" + calldata_bytes.hex()

        raw_ch = Web3.keccak(calldata_bytes).hex().lower()
        calldata_hash = raw_ch if raw_ch.startswith("0x") else "0x" + raw_ch

        # 2. Risk Evaluation (Audit H-01)
        agent_id_str = agent_id if isinstance(agent_id, str) else agent_id.hex()
        risk_score, reasons = self._compute_risk_score(agent_id_str, prompt, target, calldata_hex, value)

        # 3. Block if risk exceeds threshold
        if risk_score > self.max_allowed_risk_score:
            return AttestationResult(
                status="blocked",
                risk_score=risk_score,
                reasons=reasons,
                attestation=None,
                signature=None,
                policy_guard=self.verifying_contract,
                wrapped_calldata=None,
            )

        # 4. Construct Approved Attestation
        norm_agent_id = self._normalize_agent_id(agent_id)
        target_checksum = Web3.to_checksum_address(target)
        assigned_nonce = nonce if nonce is not None else secrets.randbelow(2**128)
        ttl = ttl_seconds if ttl_seconds is not None else self.ttl_seconds
        deadline = int(time.time()) + ttl

        attestation = SafetyAttestation(
            agentId=norm_agent_id,
            targetContract=target_checksum,
            calldataHash=calldata_hash,
            value=value,
            riskScore=risk_score,
            nonce=assigned_nonce,
            deadline=deadline,
        )

        # 5. Sign EIP-712 Attestation
        sig_hex = self.sign_attestation(attestation)

        # 6. Call Wrapping (Audit M-03)
        wrapped_calldata = self.wrap_for_policy_guard(
            target=target_checksum,
            data_hex=calldata_hex,
            attestation=attestation,
            signature=sig_hex,
        )

        # 7. Record approved outflow for daily cap tracking
        if value > 0:
            self.outflow_tracker.record(agent_id_str, value)

        return AttestationResult(
            status="approved",
            risk_score=risk_score,
            reasons=[],
            attestation=attestation,
            signature=sig_hex,
            policy_guard=self.verifying_contract,
            wrapped_calldata=wrapped_calldata,
        )