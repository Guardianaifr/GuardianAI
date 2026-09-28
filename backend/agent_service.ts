/**
 * agent_service.ts
 *
 * GuardianPrivyAgentRunner
 * ─────────────────────────
 * Creates a server-side Privy wallet for an AI agent and secures all
 * outbound transactions through the GuardianAI middleware.
 *
 * Dependencies (add to package.json as needed):
 *   @privy-io/node          — Server-side Privy SDK
 *   @privy-io/node/viem     — createViemAccount() helper
 *   viem                    — EVM client library
 *   @guardianai/middleware  — GuardianAI security middleware
 *
 * GuardianConfig fields (verified from packages/guardian-middleware/src/types.ts):
 *   relayerUrl, policyGuardAddress, chainId, failClosed, timeoutMs
 *   (no gatewayUrl, no strictMode — those fields do NOT exist)
 */

import { PrivyClient } from "@privy-io/node";
import { createViemAccount } from "@privy-io/node/viem";
import { createWalletClient, http } from "viem";
import { withGuardianSecurity } from "@guardianai/middleware";
import type { GuardianViemOptions } from "@guardianai/middleware";

/** Monad Testnet chain definition (mirrors dashboard/src/lib/monadChain.ts) */
const MONAD_TESTNET = {
  id: 10143,
  name: "Monad Testnet",
  nativeCurrency: { name: "Monad", symbol: "MON", decimals: 18 },
  rpcUrls: {
    default: { http: ["https://testnet-rpc.monad.xyz"] },
    public: { http: ["https://testnet-rpc.monad.xyz"] },
  },
  testnet: true,
} as const;

/** Verified GuardianPolicyGuard address on Monad Testnet */
const POLICY_GUARD_ADDRESS = "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60";

export interface AgentRunnerConfig {
  /** Privy App ID */
  privyAppId: string;
  /** Privy App Secret (server-side only — never expose to frontend) */
  privyAppSecret: string;
  /** Human-readable agent identifier for Guardian nonce namespacing */
  agentId: string;
  /** Optional: GuardianAI relayer URL. Defaults to http://localhost:8000 */
  relayerUrl?: string;
  /** Reject transactions if the relayer is unreachable. Defaults to true. */
  failClosed?: boolean;
  /** Optional HTTP timeout (ms) for the relayer. Defaults to 5 000. */
  timeoutMs?: number;
}

export class GuardianPrivyAgentRunner {
  private privy: PrivyClient;
  private config: Required<Pick<AgentRunnerConfig, "agentId" | "relayerUrl" | "failClosed" | "timeoutMs">>;

  constructor(config: AgentRunnerConfig) {
    // Initialise the Privy server-side SDK
    this.privy = new PrivyClient({ appId: config.privyAppId, appSecret: config.privyAppSecret });
    this.config = {
      agentId: config.agentId,
      relayerUrl: config.relayerUrl ?? "http://localhost:8000",
      failClosed: config.failClosed ?? true,
      timeoutMs: config.timeoutMs ?? 5_000,
    };
  }

  /**
   * Create a fresh Privy server wallet for the agent.
   *
   * Uses the correct @privy-io/node API:
   *   privy.wallets().create({ chain_type: 'ethereum' })
   *
   * Returns the wallet metadata (id, address) and the secured Viem WalletClient.
   */
  async createAgentWallet() {
    // Create a server-managed embedded wallet via Privy Node SDK
    const wallet = await this.privy.wallets().create({
      chain_type: "ethereum",
    });

    const securedClient = await this._buildSecuredClient(wallet.id, wallet.address);

    return {
      walletId: wallet.id,
      address: wallet.address,
      client: securedClient,
    };
  }

  /**
   * Re-hydrate an existing Privy server wallet for the agent by wallet ID.
   */
  async loadAgentWallet(walletId: string, address: string) {
    const securedClient = await this._buildSecuredClient(walletId, address);
    return { walletId, address, client: securedClient };
  }

  // ── Private helpers ────────────────────────────────────────────────────────

  private async _buildSecuredClient(walletId: string, address: string) {
    // createViemAccount() wraps a Privy server wallet as a Viem LocalAccount
    const account = await createViemAccount(this.privy, {
      walletId,
      address: address as `0x${string}`,
    });

    // Build a standard Viem WalletClient
    const baseClient = createWalletClient({
      account,
      chain: MONAD_TESTNET as any,
      transport: http(MONAD_TESTNET.rpcUrls.default.http[0]),
    });

    // Decorate with Guardian security middleware
    // Config fields are EXACTLY those in GuardianConfig (types.ts):
    //   relayerUrl, policyGuardAddress, chainId, failClosed, timeoutMs
    const guardianOptions: GuardianViemOptions = {
      agentId: this.config.agentId,
      relayerUrl: this.config.relayerUrl,
      policyGuardAddress: POLICY_GUARD_ADDRESS,
      chainId: MONAD_TESTNET.id,
      failClosed: this.config.failClosed,
      timeoutMs: this.config.timeoutMs,
    };

    return withGuardianSecurity(baseClient, guardianOptions);
  }
}
