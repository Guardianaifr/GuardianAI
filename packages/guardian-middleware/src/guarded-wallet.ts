/**
 * GuardianAgentWallet client — the path used by wallets created in the GuardianAI console
 * (https://aiguardian.dev/explorer/?view=console) and by GuardianAgentWalletFactory.
 *
 * The agent key never holds the money. It asks the GuardianAI relay to approve a payment;
 * the relay returns a signed `execute(...)` call for the guarded wallet; the agent key sends it.
 * The wallet contract re-checks the signature, nonce, passport, freeze state, risk limit and
 * (if enabled) the Chainlink-fed threat oracle before any money moves.
 *
 * Dependency-free: works with any signer (viem, ethers, Privy, ...).
 */

import { GuardianConnectionError, GuardianSecurityError } from "./interceptor.ts";

export const DEFAULT_GUARDIAN_RELAY = "https://guardian-relay-production.up.railway.app";
/** execute(address,uint256,bytes,(bytes32,address,bytes32,uint256,uint8,uint256,uint256),bytes) */
export const GUARDED_WALLET_EXECUTE_SELECTOR = "0x29e30039";

export interface GuardedWalletConfig {
  /** Guarded wallet contract address (holds the money). */
  wallet: string;
  /** Owner address (the human's wallet). Used to derive the default agent id. */
  owner: string;
  /** Agent id the wallet was created with. Default: `console:<owner lowercase>` (what the console uses). */
  agentId?: string;
  relayerUrl?: string;
  timeoutMs?: number;
  /** Injectable for tests. */
  fetchImpl?: typeof fetch;
}

export interface PaymentRequest {
  to: string;
  /** Amount in wei. */
  value: bigint | string | number;
  data?: string;
  /** What the agent was told / why it wants to pay. Screened by the relay for prompt injection. */
  prompt?: string;
}

export interface ApprovedCall {
  /** Send this transaction from the agent key. */
  to: string;
  data: string;
  value: 0n;
  riskScore: number;
  reasons: string[];
}

const isAddr = (a: string) => /^0x[0-9a-fA-F]{40}$/.test(a);
const word = (hex: string, i: number) => hex.slice(10 + i * 64, 10 + (i + 1) * 64);

/** Read target and value out of execute(...) calldata without an ABI library. */
export function decodeExecuteHead(data: string): { target: string; value: bigint } {
  if (!data.toLowerCase().startsWith(GUARDED_WALLET_EXECUTE_SELECTOR) || data.length < 10 + 64 * 2) {
    throw new GuardianConnectionError("Relay returned calldata that is not GuardianAgentWallet.execute(...)");
  }
  return { target: "0x" + word(data, 0).slice(24).toLowerCase(), value: BigInt("0x" + word(data, 1)) };
}

export class GuardedWalletClient {
  readonly wallet: string;
  readonly owner: string;
  readonly agentId: string;
  readonly relayerUrl: string;
  readonly timeoutMs: number;
  private readonly fetchImpl: typeof fetch;

  constructor(cfg: GuardedWalletConfig) {
    if (!isAddr(cfg.wallet)) throw new Error(`GuardedWalletClient: invalid wallet address ${cfg.wallet}`);
    if (!isAddr(cfg.owner)) throw new Error(`GuardedWalletClient: invalid owner address ${cfg.owner}`);
    this.wallet = cfg.wallet;
    this.owner = cfg.owner;
    this.agentId = cfg.agentId || `console:${cfg.owner.toLowerCase()}`;
    this.relayerUrl = (cfg.relayerUrl || DEFAULT_GUARDIAN_RELAY).replace(/\/$/, "");
    this.timeoutMs = cfg.timeoutMs ?? 20000;
    this.fetchImpl = cfg.fetchImpl || globalThis.fetch.bind(globalThis);
  }

  /**
   * Ask GuardianAI to approve a payment. Throws GuardianSecurityError if refused,
   * GuardianConnectionError if the relay can't be reached (fail-closed).
   */
  async approve(req: PaymentRequest): Promise<ApprovedCall> {
    if (!isAddr(req.to)) throw new GuardianSecurityError("Invalid destination address", 100, ["invalid_address"], String(req.to), req.data || "0x");
    const value = BigInt(req.value);
    const body: Record<string, string> = {
      agent_id: this.agentId,
      target: req.to,
      value: value.toString(),
      wallet: this.wallet,
      data: req.data || "0x",
    };
    if (req.prompt) body.prompt = req.prompt;

    const ctrl = new AbortController();
    const timer = setTimeout(() => ctrl.abort(), this.timeoutMs);
    let text: string;
    let status: number;
    try {
      const res = await this.fetchImpl(`${this.relayerUrl}/api/v1/attest`, {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify(body),
        signal: ctrl.signal,
      });
      status = res.status;
      text = await res.text();
    } catch (err: any) {
      throw new GuardianConnectionError(`relay unreachable (${err?.name === "AbortError" ? "timeout" : err?.message || err}). Payment blocked.`);
    } finally {
      clearTimeout(timer);
    }

    let d: any;
    try { d = JSON.parse(text); } catch { throw new GuardianConnectionError(`relay answered HTTP ${status} with non-JSON. Payment blocked.`); }
    if (status === 429) throw new GuardianConnectionError("relay rate limit reached. Payment blocked; try again in a minute.");
    if (d.status !== "approved") {
      throw new GuardianSecurityError("GuardianAI refused the payment", Number(d.risk_score ?? 100), Array.isArray(d.reasons) && d.reasons.length ? d.reasons : [d.error || d.status || "refused"], req.to, req.data || "0x");
    }
    // The nonce is a 128-bit integer: JSON.parse rounds it, so take the calldata from the raw text.
    const data = text.match(/"wrapped_calldata"\s*:\s*"(0x[0-9a-fA-F]*)"/)?.[1];
    if (!data) throw new GuardianConnectionError("approved response has no wrapped_calldata");
    const head = decodeExecuteHead(data);
    if (head.target !== req.to.toLowerCase() || head.value !== value) {
      throw new GuardianConnectionError(`relay approval does not match the request (target ${head.target}, value ${head.value})`);
    }
    return { to: this.wallet, data, value: 0n, riskScore: Number(d.risk_score ?? 0), reasons: d.reasons || [] };
  }
}
