/**
 * GuardianAI plugin for ElizaOS 1.x (@elizaos/core >= 1.7).
 *
 *   import { guardianPlugin } from "@guardianai/middleware/elizaos";
 *   plugins: [sqlPlugin, groqPlugin, bootstrapPlugin, guardianPlugin]
 *
 * Settings (character.settings / .env):
 *   GUARDIAN_AGENT_PRIVATE_KEY  agent key = the wallet's operator (pays gas only, holds no money)
 *   GUARDIAN_WALLET             guarded wallet address (from the GuardianAI console or the factory)
 *   GUARDIAN_OWNER              owner address (the human's wallet)
 *   GUARDIAN_AGENT_ID           optional; default console:<owner lowercase>
 *   GUARDIAN_RELAY_URL          optional; default the public GuardianAI relay
 *   MONAD_RPC_URL               optional; default https://testnet-rpc.monad.xyz
 *
 * What it adds:
 *   - GUARDED_PAYMENT action: the only way the agent moves money. Screens the request and the
 *     recent conversation for injected / poisoned instructions, asks GuardianAI to approve,
 *     then sends the approved call from the agent key. The wallet contract re-checks everything.
 *   - GUARDIAN_WALLET provider: tells the model which wallet it controls and its balance.
 */

import type { Action, ActionResult, HandlerCallback, IAgentRuntime, Memory, Plugin, Provider, State } from "@elizaos/core";
import { BaseError, createPublicClient, createWalletClient, decodeErrorResult, defineChain, formatEther, http, parseAbi, parseEther } from "viem";
import { privateKeyToAccount } from "viem/accounts";
import { detectInjection } from "./eliza.ts";
import { GuardedWalletClient } from "./guarded-wallet.ts";
import { GuardianConnectionError, GuardianSecurityError } from "./interceptor.ts";

export const monadTestnet = defineChain({
  id: 10143,
  name: "Monad Testnet",
  nativeCurrency: { name: "MON", symbol: "MON", decimals: 18 },
  rpcUrls: { default: { http: ["https://testnet-rpc.monad.xyz"] } },
  blockExplorers: { default: { name: "MonadScan", url: "https://testnet.monadscan.com" } },
});

/** GuardianAgentWallet custom errors, so refusals read e.g. FlaggedDestination(0x…) instead of "unknown reason". */
export const GUARDED_WALLET_ERRORS = parseAbi([
    "error AgentMismatch(bytes32 expected, bytes32 actual)",
    "error AttestationExpired(uint256 deadline, uint256 nowTs)",
    "error CallFailed()",
    "error CalldataHashMismatch()",
    "error ECDSAInvalidSignature()",
    "error ECDSAInvalidSignatureLength(uint256 length)",
    "error ECDSAInvalidSignatureS(bytes32 s)",
    "error EnforcedPause()",
    "error ExpectedPause()",
    "error FlaggedDestination(address account)",
    "error InvalidAttestationSignature()",
    "error InvalidRiskThreshold(uint8 value)",
    "error InvalidShortString()",
    "error InvalidTarget()",
    "error NonceAlreadyUsed(uint256 nonce)",
    "error NotOperator(address caller)",
    "error NotOperatorOrOwner(address caller)",
    "error OwnableInvalidOwner(address owner)",
    "error OwnableUnauthorizedAccount(address account)",
    "error PassportRevokedOrInactive(bytes32 agentId)",
    "error ReentrancyGuardReentrantCall()",
    "error RiskScoreExceedsThreshold(uint8 riskScore, uint8 maxAllowed)",
    "error StringTooLong(string str)",
    "error TargetMismatch(address expected, address actual)",
    "error ValueMismatch(uint256 expected, uint256 actual)",
    "error ZeroAddress()"
  ]);

/** Name + args of a guarded-wallet revert, from a viem error. */
export function revertReason(err: any): string {
  const data = (err instanceof BaseError ? (err.walk((e: any) => typeof e?.data === "string" || typeof e?.raw === "string") as any) : null);
  const raw: string | undefined = data?.raw ?? (typeof data?.data === "string" ? data.data : undefined) ?? err?.data;
  if (raw && raw.length >= 10) {
    try { const d = decodeErrorResult({ abi: GUARDED_WALLET_ERRORS, data: raw as `0x${string}` }); return `${d.errorName}(${(d.args || []).join(", ")})`; } catch {}
  }
  return err?.shortMessage || err?.message || String(err);
}

const ADDRESS_RE = /0x[0-9a-fA-F]{40}/g;
const AMOUNT_RE = /(\d+(?:\.\d+)?)\s*(?:MON\b)/i;
const HISTORY = 12;

function setting(runtime: IAgentRuntime, key: string): string | undefined {
  const v = runtime.getSetting(key);
  return v === null || v === undefined || v === "" ? undefined : String(v);
}

function context(runtime: IAgentRuntime) {
  const key = setting(runtime, "GUARDIAN_AGENT_PRIVATE_KEY");
  // External-signer mode (hosted agents): no key on the server. The agent decides and gets the approval;
  // the approved call goes back to whoever holds the agent key (e.g. the browser) to sign and send.
  const external = setting(runtime, "GUARDIAN_AGENT_ADDRESS");
  const wallet = setting(runtime, "GUARDIAN_WALLET");
  const owner = setting(runtime, "GUARDIAN_OWNER");
  if ((!key && !external) || !wallet || !owner) return null;
  const rpc = setting(runtime, "MONAD_RPC_URL") || monadTestnet.rpcUrls.default.http[0];
  const transport = http(rpc, { retryCount: 5, retryDelay: 400 });
  const account = key ? privateKeyToAccount(key as `0x${string}`) : null;
  return {
    agentAddress: (account ? account.address : external) as `0x${string}`,
    guard: new GuardedWalletClient({ wallet, owner, agentId: setting(runtime, "GUARDIAN_AGENT_ID"), relayerUrl: setting(runtime, "GUARDIAN_RELAY_URL") }),
    pub: createPublicClient({ chain: monadTestnet, transport }),
    signer: account ? createWalletClient({ account, chain: monadTestnet, transport }) : null,
  };
}

/** Destination + amount from the user's message. */
export function parsePayment(text: string): { to?: string; amountMon?: string } {
  const addrs = text.match(ADDRESS_RE) || [];
  const amt = text.match(AMOUNT_RE);
  return { to: addrs[0], amountMon: amt?.[1] };
}

/** Recent messages in this room, oldest first, excluding the current one. */
async function recentTexts(runtime: IAgentRuntime, message: Memory): Promise<string[]> {
  try {
    const mems = await runtime.getMemories({ tableName: "messages", roomId: message.roomId, count: HISTORY });
    return mems
      .filter((m) => m.id !== message.id && m.entityId !== runtime.agentId)
      .map((m) => String(m.content?.text || ""))
      .filter(Boolean)
      .reverse();
  } catch {
    return [];
  }
}

export interface GuardedPaymentOutcome {
  outcome: "paid" | "approved" | "blocked_locally" | "blocked_by_guardian" | "refused_on_chain" | "error";
  to?: string;
  amountMon?: string;
  riskScore?: number;
  reasons?: string[];
  hash?: string;
  status?: "success" | "reverted";
  /** External-signer mode: the GuardianAI-approved call for the agent key to send. */
  call?: { to: string; data: string; gas: string };
  message: string;
}

/** The guarded payment flow, usable from the action or directly from code. */
export async function guardedPayment(runtime: IAgentRuntime, message: Memory): Promise<GuardedPaymentOutcome> {
  const ctx = context(runtime);
  if (!ctx) return { outcome: "error", message: "GuardianAI plugin is not configured (GUARDIAN_AGENT_PRIVATE_KEY or GUARDIAN_AGENT_ADDRESS, GUARDIAN_WALLET, GUARDIAN_OWNER)." };
  const text = String(message.content?.text || "");
  const { to, amountMon } = parsePayment(text);
  if (!to || !amountMon) return { outcome: "error", message: "I need a destination address and an amount in MON (for example: pay 0.001 MON to 0x…)." };

  // Layer 1 — memory guard: the request AND the recent conversation (poisoned earlier messages).
  const history = await recentTexts(runtime, message);
  const hits = [...detectInjection(text).map((p) => `request: ${p}`), ...history.flatMap((h, i) => detectInjection(h).map((p) => `earlier message ${history.length - i} back: ${p}`))];
  if (hits.length) {
    return { outcome: "blocked_locally", to, amountMon, riskScore: 100, reasons: hits.slice(0, 4), message: `Blocked by GuardianAI memory guard before anything was sent: this conversation contains an injected instruction. No payment made.` };
  }

  // Layer 2 — GuardianAI relay approval (threat feed, policy, prompt screening).
  let approved;
  try {
    approved = await ctx.guard.approve({ to, value: parseEther(amountMon), prompt: [...history.slice(-4), text].join("\n") });
  } catch (err) {
    if (err instanceof GuardianSecurityError) return { outcome: "blocked_by_guardian", to, amountMon, riskScore: err.riskScore, reasons: err.reasons, message: `GuardianAI refused to approve this payment (risk ${err.riskScore}/100). No payment made.` };
    if (err instanceof GuardianConnectionError) return { outcome: "error", to, amountMon, message: `${err.message}` };
    throw err;
  }

  // Layer 3 — the guarded wallet contract re-checks on Monad. Dry-run first, then send.
  try {
    await ctx.pub.call({ account: ctx.agentAddress, to: approved.to as `0x${string}`, data: approved.data as `0x${string}` });
  } catch (err: any) {
    return { outcome: "refused_on_chain", to, amountMon, riskScore: approved.riskScore, reasons: [revertReason(err)], message: `The guarded wallet on Monad refused it: ${revertReason(err)}. No payment made.` };
  }
  const gas = await ctx.pub.estimateGas({ account: ctx.agentAddress, to: approved.to as `0x${string}`, data: approved.data as `0x${string}` });
  if (!ctx.signer) {
    return {
      outcome: "approved", to, amountMon, riskScore: approved.riskScore,
      call: { to: approved.to, data: approved.data, gas: ((gas * 110n) / 100n).toString() },
      message: `GuardianAI approved paying ${amountMon} MON to ${to} (risk ${approved.riskScore}/100). Sending it from your agent key…`,
    };
  }
  const hash = await ctx.signer.sendTransaction({ to: approved.to as `0x${string}`, data: approved.data as `0x${string}`, gas: (gas * 110n) / 100n });
  const rc = await ctx.pub.waitForTransactionReceipt({ hash, timeout: 120_000 });
  return {
    outcome: rc.status === "success" ? "paid" : "refused_on_chain",
    to, amountMon, riskScore: approved.riskScore, hash, status: rc.status,
    message: rc.status === "success"
      ? `Paid ${amountMon} MON to ${to}, approved by GuardianAI (risk ${approved.riskScore}/100). ${monadTestnet.blockExplorers.default.url}/tx/${hash}`
      : `Transaction reverted on Monad: ${monadTestnet.blockExplorers.default.url}/tx/${hash}`,
  };
}

export const guardedPaymentAction: Action = {
  name: "GUARDED_PAYMENT",
  similes: ["SEND_MON", "PAY", "TRANSFER", "SEND_PAYMENT", "SEND_TOKENS", "PAY_INVOICE"],
  description: "Send MON from the agent's GuardianAI-guarded wallet on Monad testnet. Use this for ANY request to pay, send or transfer funds. It needs a 0x address and an amount in MON.",
  validate: async (runtime: IAgentRuntime, message: Memory) => {
    if (!context(runtime)) return false;
    const t = String(message.content?.text || "");
    return /0x[0-9a-fA-F]{40}/.test(t) && /(pay|send|transfer|MON)/i.test(t);
  },
  handler: async (runtime: IAgentRuntime, message: Memory, _state?: State, _opts?: unknown, callback?: HandlerCallback): Promise<ActionResult> => {
    const r = await guardedPayment(runtime, message);
    const reasons = r.reasons?.length ? `\nReason: ${r.reasons.slice(0, 2).join("; ")}` : "";
    await callback?.({ text: r.message + reasons, actions: ["GUARDED_PAYMENT"], source: message.content?.source });
    return { success: r.outcome === "paid" || r.outcome === "approved", text: r.message, data: { ...r } as Record<string, unknown> };
  },
  examples: [
    [
      { name: "{{name1}}", content: { text: "Please pay 0.001 MON to 0x729BCCea35194c926Ff0BcA776B425012e88c23C for the invoice." } },
      { name: "{{name2}}", content: { text: "Sending it through GuardianAI.", actions: ["GUARDED_PAYMENT"] } },
    ],
  ],
};

export const guardianWalletProvider: Provider = {
  name: "GUARDIAN_WALLET",
  description: "The GuardianAI-guarded wallet this agent pays from",
  get: async (runtime: IAgentRuntime) => {
    const ctx = context(runtime);
    if (!ctx) return { text: "" };
    let balance = "unknown";
    try { balance = formatEther(await ctx.pub.getBalance({ address: ctx.guard.wallet as `0x${string}` })); } catch {}
    return {
      text: `You pay from a GuardianAI-guarded wallet ${ctx.guard.wallet} on Monad testnet (balance ${balance} MON). Every payment must go through the GUARDED_PAYMENT action; GuardianAI may refuse unsafe payments.`,
      values: { guardianWallet: ctx.guard.wallet, guardianBalance: balance },
    };
  },
};

export const guardianPlugin: Plugin = {
  name: "guardianai",
  description: "GuardianAI: guarded payments on Monad with prompt-injection and memory-poisoning protection",
  actions: [guardedPaymentAction],
  providers: [guardianWalletProvider],
};

export default guardianPlugin;
