/**
 * guardianViemClient.ts
 *
 * Creates a GuardianAI-secured Viem WalletClient from a Privy embedded wallet.
 *
 * Flow:
 *  1. Obtain the EIP-1193 provider from the Privy embedded wallet.
 *  2. Build a Viem WalletClient targeting Monad Testnet.
 *  3. Decorate it with withGuardianSecurity() so every sendTransaction call is
 *     pre-flighted through the GuardianPolicyGuard relayer.
 *
 * GuardianConfig fields used (all verified against packages/guardian-middleware/src/types.ts):
 *   relayerUrl        — URL of the off-chain relayer / attestation service
 *   policyGuardAddress — GuardianPolicyGuard contract on Monad Testnet
 *   chainId           — 10143 (Monad Testnet)
 *   failClosed        — if true, reject tx when relayer is unreachable
 *   timeoutMs         — optional HTTP timeout for relayer calls
 *
 * NOT included (do not exist in the type):
 *   gatewayUrl, strictMode
 */

import { createWalletClient, custom } from "viem";
import { withGuardianSecurity } from "@guardianai/middleware";
import type { GuardianViemOptions } from "@guardianai/middleware";
import { monadTestnet } from "./monadChain";

/** Verified deploy address on Monad Testnet (Chain ID 10143) */
const POLICY_GUARD_ADDRESS = "0x32fa262042dFB354f8064Ff369DcDe4BA4ec1101";

export interface CreateGuardedClientOptions {
  /** EIP-1193 provider from Privy embedded wallet (wallet.getEthereumProvider()) */
  provider: any;
  /** Agent ID string — used for per-agent nonce namespacing in GuardianPolicyGuard */
  agentId: string;
  /** Guardian relayer base URL. Defaults to http://localhost:8000 */
  relayerUrl?: string;
  /** Reject transactions when the relayer is unreachable. Defaults to true. */
  failClosed?: boolean;
  /** Optional: return current prompt text for richer attestation context */
  getPromptContext?: () => string | undefined;
  /** Optional: return runtime security state so the interceptor can halt if blocked */
  getSecurityState?: () => { isCompromised?: boolean; blocked?: boolean; reason?: string } | undefined;
}

/**
 * Build a GuardianAI-secured Viem WalletClient from a Privy embedded wallet.
 *
 * @example
 * const { wallet } = useEmbeddedWallet();
 * const provider = await wallet.getEthereumProvider();
 * const client = await createGuardedViemClient({ provider, agentId: "my-agent" });
 */
export async function createGuardedViemClient(opts: CreateGuardedClientOptions) {
  const {
    provider,
    agentId,
    relayerUrl = "http://localhost:8000",
    failClosed = true,
    getPromptContext,
    getSecurityState,
  } = opts;

  // Build a standard Viem WalletClient using the Privy EIP-1193 provider
  const baseClient = createWalletClient({
    chain: monadTestnet as any,
    transport: custom(provider),
  });

  // Correct GuardianConfig fields (no gatewayUrl / strictMode)
  const guardianOptions: GuardianViemOptions = {
    agentId,
    relayerUrl,
    policyGuardAddress: POLICY_GUARD_ADDRESS,
    chainId: monadTestnet.id,
    failClosed,
    getPromptContext,
    getSecurityState,
  };

  // Decorate with Guardian security middleware
  const securedClient = withGuardianSecurity(baseClient, guardianOptions);

  return securedClient;
}
