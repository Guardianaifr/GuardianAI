/**
 * Type definitions for @guardianai/middleware
 *
 * Provides cryptographic attestation, pre-flight safety inspection,
 * and Policy Guard transaction wrapping for AI agents on Monad Testnet (10143).
 */

export const DEFAULT_MONAD_POLICY_GUARD = "0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101";
export const DEFAULT_MONAD_CHAIN_ID = 10143;
export const POLICY_GUARD_SELECTOR = "0x3cb7461c";

export interface GuardianConfig {
  relayerUrl?: string;
  policyGuardAddress?: string;
  chainId?: number;
  failClosed?: boolean;
  timeoutMs?: number;
}

export interface RawTransaction {
  to: string;
  data?: string;
  value?: bigint | string | number;
  from?: string;
  gas?: bigint | string | number;
}

export interface AttestationRequest {
  agent_id: string;
  target: string;
  data?: string;
  value?: number | string;
  prompt?: string;
  nonce?: number | string;
  ttl_seconds?: number;
}

export interface SafetyAttestationStruct {
  agentId: string;
  targetContract: string;
  calldataHash: string;
  value: number | string;
  nonce: number | string;
  deadline: number | string;
  riskScore: number;
}

export interface AttestationResponse {
  status: "approved" | "rejected";
  risk_score: number;
  reasons: string[];
  attestation?: SafetyAttestationStruct;
  signature?: string;
  verifying_contract?: string;
  wrapped_calldata?: string;
}

export interface DecodedCalldata {
  selector: string;
  functionName: string;
  raw: string;
  isWrapped: boolean;
  isKnown: boolean;
  recipient?: string;
  amount?: bigint;
}

export interface WrappedTransaction {
  to: string;
  data: string;
  value: bigint | string | number;
  riskScore: number;
  status: "approved";
  signature?: string;
  originalTarget: string;
  originalData: string;
  decoded: DecodedCalldata;
}

