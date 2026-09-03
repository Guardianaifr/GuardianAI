import {
  DEFAULT_MONAD_CHAIN_ID,
  DEFAULT_MONAD_POLICY_GUARD,
  POLICY_GUARD_SELECTOR,
} from "./types.ts";
import type {
  AttestationRequest,
  AttestationResponse,
  DecodedCalldata,
  GuardianConfig,
  RawTransaction,
  WrappedTransaction,
} from "./types.ts";

export const KNOWN_SELECTORS: Record<string, string> = {
  "0xa9059cbb": "transfer(address,uint256)",
  "0x095ea7b3": "approve(address,uint256)",
  "0x23b872dd": "transferFrom(address,address,uint256)",
  "0x38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
  "0x7ff36ab5": "swapExactETHForTokens(uint256,address[],address,uint256)",
  "0x18cbafe5": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
  "0xd0e30db0": "deposit()",
  "0x2e1a7d4d": "withdraw(uint256)",
  "0x3cb7461c": "executeWithAttestation(address,bytes,SafetyAttestation,bytes)",
};

export class GuardianSecurityError extends Error {
  public readonly riskScore: number;
  public readonly reasons: string[];
  public readonly target: string;
  public readonly calldata: string;

  constructor(message: string, riskScore: number, reasons: string[], target: string, calldata: string) {
    super(`${message} (Risk Score: ${riskScore}) [${reasons.join(", ")}]`);
    this.name = "GuardianSecurityError";
    this.riskScore = riskScore;
    this.reasons = reasons;
    this.target = target;
    this.calldata = calldata;
  }
}

export class GuardianConnectionError extends Error {
  constructor(message: string) {
    super(`Guardian Security Interceptor failed closed: ${message}`);
    this.name = "GuardianConnectionError";
  }
}

export class GuardianInterceptor {
  public readonly relayerUrl: string;
  public readonly policyGuardAddress: string;
  public readonly chainId: number;
  public readonly failClosed: boolean;
  public readonly timeoutMs: number;

  constructor(config: GuardianConfig = {}) {
    this.relayerUrl = (config.relayerUrl || "http://localhost:8000").replace(/\/$/, "");
    this.policyGuardAddress = (config.policyGuardAddress || DEFAULT_MONAD_POLICY_GUARD).toLowerCase();
    this.chainId = config.chainId || DEFAULT_MONAD_CHAIN_ID;
    this.failClosed = config.failClosed !== false; // Default true (FAIL-CLOSED)
    this.timeoutMs = config.timeoutMs || 5000;
  }

  public static decodeCalldata(data: string = "0x"): DecodedCalldata {
    const raw = data.startsWith("0x") ? data : "0x" + data;
    if (raw.length < 10) {
      return {
        selector: "0x",
        functionName: raw.length <= 2 ? "native_transfer" : "unknown_short",
        raw,
        isWrapped: false,
        isKnown: raw.length <= 2,
      };
    }

    const selector = raw.slice(0, 10).toLowerCase();
    const functionName = KNOWN_SELECTORS[selector] || "unknown";
    const isWrapped = selector === POLICY_GUARD_SELECTOR;
    const isKnown = selector in KNOWN_SELECTORS;

    let recipient: string | undefined;
    let amount: bigint | undefined;

    // ERC-20 transfer or approve argument extraction
    if ((selector === "0xa9059cbb" || selector === "0x095ea7b3") && raw.length >= 74) {
      try {
        recipient = "0x" + raw.slice(34, 74).toLowerCase();
        if (raw.length >= 138) {
          amount = BigInt("0x" + raw.slice(74, 138));
        }
      } catch {
        // Safe fallback on malformed calldata
      }
    }

    return {
      selector,
      functionName,
      raw,
      isWrapped,
      isKnown,
      recipient,
      amount,
    };
  }

  public async intercept(
    agentId: string,
    tx: RawTransaction,
    prompt?: string
  ): Promise<WrappedTransaction> {
    const decoded = GuardianInterceptor.decodeCalldata(tx.data);

    // SECURITY: Reject pre-wrapped calldata. Only this interceptor is authorized
    // to produce executeWithAttestation calldata. Accepting pre-wrapped input
    // would let a compromised agent bypass all security checks.
    if (decoded.isWrapped) {
      throw new GuardianSecurityError(
        "Pre-wrapped calldata rejected: only GuardianInterceptor may wrap transactions",
        100,
        ["pre_wrapped_calldata_bypass_attempt"],
        tx.to,
        decoded.raw
      );
    }

    const attestationRequest: AttestationRequest = {
      agent_id: agentId,
      target: tx.to,
      data: decoded.raw,
      value: tx.value ? tx.value.toString() : "0",
      prompt: prompt || "",
    };

    let response: AttestationResponse;
    try {
      response = await this.fetchAttestation(attestationRequest);
    } catch (err: any) {
      if (this.failClosed) {
        throw new GuardianConnectionError(
          `Unable to reach Guardian Attestation service (${err?.message || err}). Transaction blocked.`
        );
      }
      throw err;
    }

    // Fail-Closed on any non-approved state
    if (response.status !== "approved") {
      throw new GuardianSecurityError(
        `Transaction rejected by Guardian Policy Guard`,
        response.risk_score,
        response.reasons || ["unknown_violation"],
        tx.to,
        decoded.raw
      );
    }

    const verifyingContract = response.verifying_contract || this.policyGuardAddress;
    const wrappedCalldata = response.wrapped_calldata;

    if (!wrappedCalldata || !wrappedCalldata.startsWith(POLICY_GUARD_SELECTOR)) {
      throw new GuardianConnectionError("Approved attestation missing valid Policy Guard wrapped calldata.");
    }

    return {
      to: verifyingContract,
      data: wrappedCalldata,
      value: tx.value ?? 0n, // Value preservation (Audit Invariant 2)
      riskScore: response.risk_score,
      status: "approved",
      signature: response.signature,
      originalTarget: tx.to,
      originalData: decoded.raw,
      decoded,
    };
  }

  protected async fetchAttestation(req: AttestationRequest): Promise<AttestationResponse> {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), this.timeoutMs);

    try {
      const res = await fetch(`${this.relayerUrl}/api/v1/attest`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(req),
        signal: controller.signal,
      });

      const body = (await res.json()) as AttestationResponse;
      return body;
    } finally {
      clearTimeout(timer);
    }
  }
}

