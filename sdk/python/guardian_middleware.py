"""
GuardianAI Agent Middleware — Pre-flight security & Policy Guard wrapper.

A drop-in cryptographic firewall for AI agents (LangChain, Web3.py, custom agents)
operating on Monad Testnet (Chain ID 10143) and EVM networks.

Intercepts agent transactions before broadcast, evaluates prompt intent and calldata
parameters via Guardian's EIP-712 Attestation pipeline, and wraps approved transactions
into GuardianPolicyGuard.executeWithAttestation(...).

Enforces strict FAIL-CLOSED policy: if attestation is rejected or the relayer is
unreachable, execution is halted immediately with GuardianSecurityBlockedError.
"""
from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional, Tuple, Union

logger = logging.getLogger("guardianai.middleware")

# Deployed GuardianPolicyGuard on Monad Testnet (Chain ID 10143)
DEFAULT_MONAD_POLICY_GUARD = "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60"
DEFAULT_MONAD_CHAIN_ID = 10143
POLICY_GUARD_SELECTOR = "0x3cb7461c"  # executeWithAttestation(address,bytes,(bytes32,address,bytes32,uint256,uint256,uint256,uint16),bytes)

KNOWN_SELECTORS: Dict[str, str] = {
    "0xa9059cbb": "transfer(address,uint256)",
    "0x095ea7b3": "approve(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "0x7ff36ab5": "swapExactETHForTokens(uint256,address[],address,uint256)",
    "0x18cbafe5": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
    "0xd0e30db0": "deposit()",
    "0x2e1a7d4d": "withdraw(uint256)",
    "0x3cb7461c": "executeWithAttestation(address,bytes,SafetyAttestation,bytes)",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class GuardianMiddlewareError(Exception):
    """Base exception for GuardianAI middleware errors."""
    pass


class GuardianSecurityBlockedError(GuardianMiddlewareError):
    """Raised when GuardianAI blocks an agent transaction due to security violations."""
    def __init__(self, message: str, risk_score: int, reasons: List[str], target: str, calldata: str):
        super().__init__(f"Transaction blocked by GuardianAI (Risk Score: {risk_score}): {', '.join(reasons)}")
        self.risk_score = risk_score
        self.reasons = reasons
        self.target = target
        self.calldata = calldata


class GuardianConnectionError(GuardianMiddlewareError):
    """Raised when the Guardian Attestation service cannot be reached (Fail-Closed)."""
    pass


# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

@dataclass
class DecodedCalldata:
    """Pre-flight decoded representation of an EVM transaction calldata."""
    selector: str
    function_name: str
    raw_data: str
    is_known: bool
    is_wrapped: bool
    recipient: Optional[str] = None
    amount: Optional[int] = None


@dataclass
class InterceptedTx:
    """The wrapped transaction ready for broadcast to the Monad RPC."""
    to: str
    data: str
    value: int
    risk_score: int
    status: str
    attestation: Dict[str, Any] = field(default_factory=dict)
    signature: Optional[str] = None
    original_target: str = ""
    original_data: str = ""
    decoded: Optional[DecodedCalldata] = None

    def to_tx_dict(self) -> Dict[str, Any]:
        """Format as an EVM transaction dict for web3 / eth_sendTransaction."""
        return {
            "to": self.to,
            "data": self.data,
            "value": hex(self.value) if isinstance(self.value, int) else self.value,
        }


# ---------------------------------------------------------------------------
# Core GuardianMiddleware Class
# ---------------------------------------------------------------------------

class GuardianMiddleware:
    """
    Client interceptor for AI agents.

    Intercepts transactions, validates them with Guardian's attestation service,
    and wraps them into `GuardianPolicyGuard.executeWithAttestation(...)`.
    """

    def __init__(
        self,
        relayer_url: str = "http://localhost:8000",
        policy_guard_address: str = DEFAULT_MONAD_POLICY_GUARD,
        chain_id: int = DEFAULT_MONAD_CHAIN_ID,
        fail_closed: bool = True,
        timeout_seconds: float = 5.0,
        local_attestation_service: Optional[Any] = None,
    ):
        self.relayer_url = relayer_url.rstrip("/")
        self.policy_guard_address = policy_guard_address.lower()
        self.chain_id = chain_id
        self.fail_closed = fail_closed
        self.timeout_seconds = timeout_seconds
        self.local_attestation_service = local_attestation_service

    @staticmethod
    def decode_calldata(data: Union[str, bytes]) -> DecodedCalldata:
        """Inspect and extract function selector and basic arguments from calldata."""
        if isinstance(data, bytes):
            hex_data = "0x" + data.hex()
        else:
            hex_data = data if data.startswith("0x") else "0x" + data

        if len(hex_data) < 10:
            return DecodedCalldata(
                selector="0x",
                function_name="native_transfer" if len(hex_data) <= 2 else "unknown_short",
                raw_data=hex_data,
                is_known=True if len(hex_data) <= 2 else False,
                is_wrapped=False,
            )

        selector = hex_data[:10].lower()
        fn_name = KNOWN_SELECTORS.get(selector, "unknown")
        is_known = selector in KNOWN_SELECTORS
        is_wrapped = (selector == POLICY_GUARD_SELECTOR)

        recipient: Optional[str] = None
        amount: Optional[int] = None

        # Extract ERC-20 transfer(address,uint256) or approve(address,uint256)
        if selector in ("0xa9059cbb", "0x095ea7b3") and len(hex_data) >= 74:
            try:
                addr_hex = hex_data[10:74]
                recipient = "0x" + addr_hex[-40:]
                if len(hex_data) >= 138:
                    amount = int(hex_data[74:138], 16)
            except Exception:
                pass

        return DecodedCalldata(
            selector=selector,
            function_name=fn_name,
            raw_data=hex_data,
            is_known=is_known,
            is_wrapped=is_wrapped,
            recipient=recipient,
            amount=amount,
        )

    def intercept_transaction(
        self,
        agent_id: str,
        target: str,
        data: Union[str, bytes] = "0x",
        value: int = 0,
        prompt: Optional[str] = None,
        nonce: Optional[int] = None,
        ttl_seconds: Optional[int] = None,
    ) -> InterceptedTx:
        """
        Intercepts an agent's proposed transaction.

        1. Decodes calldata and validates basic formats.
        2. Calls Guardian attestation service (or local service).
        3. Fails closed on any rejection, error, or network drop.
        4. Returns the wrapped transaction targeting GuardianPolicyGuard on Monad.
        """
        decoded = self.decode_calldata(data)
        raw_data = decoded.raw_data

        # SECURITY: Reject pre-wrapped calldata. Only this middleware is authorized
        # to produce executeWithAttestation calldata. If an agent tries to submit
        # already-wrapped calldata, it is either a bug or a bypass attempt.
        if decoded.is_wrapped:
            raise GuardianSecurityBlockedError(
                message="Pre-wrapped calldata rejected: only GuardianMiddleware may wrap transactions",
                risk_score=100,
                reasons=["pre_wrapped_calldata_bypass_attempt"],
                target=target,
                calldata=raw_data,
            )

        # 1. Evaluate and attest
        attestation_dict = self._request_attestation(
            agent_id=agent_id,
            target=target,
            data=raw_data,
            value=value,
            prompt=prompt,
            nonce=nonce,
            ttl_seconds=ttl_seconds,
        )

        status = attestation_dict.get("status", "rejected")
        risk_score = int(attestation_dict.get("risk_score", 100))
        reasons = attestation_dict.get("reasons", [])

        # 2. Strict Fail-Closed Check
        if status != "approved":
            logger.warning(
                f"[GuardianAI] Agent '{agent_id}' transaction to {target} BLOCKED. "
                f"Risk: {risk_score}, Reasons: {reasons}"
            )
            raise GuardianSecurityBlockedError(
                message="Transaction blocked by GuardianAI",
                risk_score=risk_score,
                reasons=reasons,
                target=target,
                calldata=raw_data,
            )

        # 3. Retrieve wrapped calldata and verifying contract
        wrapped_calldata = attestation_dict.get("wrapped_calldata")
        verifying_contract = attestation_dict.get("verifying_contract") or self.policy_guard_address

        if not wrapped_calldata or not wrapped_calldata.startswith(POLICY_GUARD_SELECTOR):
            raise GuardianMiddlewareError("Relayer returned approved status but missing valid wrapped calldata.")

        return InterceptedTx(
            to=verifying_contract,
            data=wrapped_calldata,
            value=value,  # Preserves native MON value
            risk_score=risk_score,
            status=status,
            attestation=attestation_dict.get("attestation", {}),
            signature=attestation_dict.get("signature"),
            original_target=target,
            original_data=raw_data,
            decoded=decoded,
        )

    def _request_attestation(
        self,
        agent_id: str,
        target: str,
        data: str,
        value: int,
        prompt: Optional[str],
        nonce: Optional[int],
        ttl_seconds: Optional[int],
    ) -> Dict[str, Any]:
        """Contact attestation service (local or remote HTTP)."""
        # Local fast-path (unit tests or co-located process)
        if self.local_attestation_service is not None:
            try:
                res = self.local_attestation_service.evaluate_and_attest(
                    agent_id=agent_id,
                    target=target,
                    data=data,
                    value=value,
                    prompt=prompt,
                    nonce=nonce,
                    ttl_seconds=ttl_seconds,
                )
                return res.to_dict()
            except Exception as e:
                if self.fail_closed:
                    raise GuardianConnectionError(f"Local attestation service failed: {e}") from e
                raise

        # Remote HTTP request to Guardian Relayer /api/v1/attest
        endpoint = f"{self.relayer_url}/api/v1/attest"
        payload = {
            "agent_id": agent_id,
            "target": target,
            "data": data,
            "value": value,
            "prompt": prompt or "",
        }
        if nonce is not None:
            payload["nonce"] = nonce
        if ttl_seconds is not None:
            payload["ttl_seconds"] = ttl_seconds

        req_body = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            endpoint,
            data=req_body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            with urllib.request.urlopen(req, timeout=self.timeout_seconds) as resp:
                resp_data = resp.read().decode("utf-8")
                return json.loads(resp_data)
        except urllib.error.HTTPError as e:
            try:
                err_body = e.read().decode("utf-8")
                err_json = json.loads(err_body)
                # If HTTP error contains attestation rejection payload, return it
                if "status" in err_json and "risk_score" in err_json:
                    return err_json
            except Exception:
                pass
            if self.fail_closed:
                raise GuardianConnectionError(f"Guardian attestation endpoint HTTP {e.code}: {e.reason}") from e
            raise GuardianMiddlewareError(f"HTTP Error {e.code}") from e
        except Exception as e:
            if self.fail_closed:
                raise GuardianConnectionError(f"Failed to connect to Guardian Attestation service at {endpoint}: {e}") from e
            raise


# ---------------------------------------------------------------------------
# LangChain Integration: Callbacks & Tool Wrappers
# ---------------------------------------------------------------------------

class GuardianLangChainCallback:
    """
    LangChain Callback Handler for agent security context binding.

    Captures agent reasoning and prompt context so transactions initiated
    by LangChain tools are screened against the original user prompt.
    """

    def __init__(self, middleware: GuardianMiddleware, agent_id: str):
        self.middleware = middleware
        self.agent_id = agent_id
        self.latest_prompt: Optional[str] = None
        self.last_action_context: Dict[str, Any] = {}

    def on_llm_start(self, serialized: Dict[str, Any], prompts: List[str], **kwargs: Any) -> None:
        """Capture the incoming prompt sent to the LLM."""
        if prompts:
            self.latest_prompt = prompts[0]

    def on_chain_start(self, serialized: Dict[str, Any], inputs: Dict[str, Any], **kwargs: Any) -> None:
        """Capture chain inputs."""
        if isinstance(inputs, dict):
            # Extract common input keys (input, query, prompt, question)
            for k in ("input", "query", "prompt", "question"):
                if k in inputs and isinstance(inputs[k], str):
                    self.latest_prompt = inputs[k]
                    break

    def on_tool_start(self, serialized: Dict[str, Any], input_str: str, **kwargs: Any) -> None:
        """Capture tool invocation string."""
        self.last_action_context = {"tool": serialized.get("name", "unknown"), "input": input_str}


class GuardianToolWrapper:
    """
    Decorator / Wrapper for Web3 LangChain Tools.

    Intercepts the tool's execution to validate transaction parameters
    and wrap calldata using GuardianPolicyGuard before dispatching.
    """

    def __init__(
        self,
        tool_func: Callable[..., Any],
        middleware: GuardianMiddleware,
        agent_id: str,
        callback: Optional[GuardianLangChainCallback] = None,
    ):
        self.tool_func = tool_func
        self.middleware = middleware
        self.agent_id = agent_id
        self.callback = callback

    def __call__(self, *args: Any, **kwargs: Any) -> Any:
        prompt = self.callback.latest_prompt if self.callback else None

        # Check if transaction params are in kwargs or positional args
        tx_dict: Optional[Dict[str, Any]] = None
        if kwargs and "to" in kwargs:
            tx_dict = kwargs
        elif args and isinstance(args[0], dict) and "to" in args[0]:
            tx_dict = args[0]

        if tx_dict is not None:
            target = tx_dict.get("to", "")
            data = tx_dict.get("data", "0x")
            value = int(tx_dict.get("value", 0))

            # Intercept and wrap
            wrapped = self.middleware.intercept_transaction(
                agent_id=self.agent_id,
                target=target,
                data=data,
                value=value,
                prompt=prompt,
            )

            # Replace with wrapped policy guard transaction
            tx_dict["to"] = wrapped.to
            tx_dict["data"] = wrapped.data
            tx_dict["value"] = wrapped.value

        return self.tool_func(*args, **kwargs)


# ---------------------------------------------------------------------------
# Web3.py Middleware Integration
# ---------------------------------------------------------------------------

def guardian_web3_middleware(
    middleware: GuardianMiddleware,
    agent_id: str,
    prompt_getter: Optional[Callable[[], Optional[str]]] = None,
) -> Callable[[Callable[[str, Any], Any], Any], Callable[[str, Any], Any]]:
    """
    Standard Web3.py middleware layer.

    Usage:
        from web3 import Web3
        from guardian_middleware import GuardianMiddleware, guardian_web3_middleware

        w3 = Web3(...)
        guard = GuardianMiddleware(relayer_url="http://localhost:8000")
        w3.middleware_onion.inject(guardian_web3_middleware(guard, agent_id="agent-01"), layer=0)
    """
    def middleware_factory(make_request: Callable[[str, Any], Any], web3: Any) -> Callable[[str, Any], Any]:
        def middleware_handler(method: str, params: Any) -> Any:
            # Intercept transaction sending methods
            if method in ("eth_sendTransaction", "eth_estimateGas") and params:
                tx_dict = params[0]
                if isinstance(tx_dict, dict) and "to" in tx_dict:
                    target = tx_dict.get("to", "")
                    data = tx_dict.get("data", "0x")
                    raw_val = tx_dict.get("value", 0)
                    value = int(raw_val, 16) if isinstance(raw_val, str) and raw_val.startswith("0x") else int(raw_val)
                    prompt = prompt_getter() if prompt_getter else None

                    # Wrap via Guardian Policy Guard
                    intercepted = middleware.intercept_transaction(
                        agent_id=agent_id,
                        target=target,
                        data=data,
                        value=value,
                        prompt=prompt,
                    )

                    # Mutate params to use Policy Guard
                    tx_dict["to"] = intercepted.to
                    tx_dict["data"] = intercepted.data

            return make_request(method, params)
        return middleware_handler
    return middleware_factory