/**
 * Viem Client Decorator for GuardianAI
 *
 * Automatically wraps transactions sent via Viem's WalletClient or PublicClient
 * through GuardianPolicyGuard on Monad Testnet.
 */

import { GuardianInterceptor, GuardianSecurityError } from "./interceptor.ts";
import type { GuardianConfig, RawTransaction, WrappedTransaction } from "./types.ts";

export interface GuardianViemOptions extends GuardianConfig {
  agentId: string;
  getPromptContext?: () => string | undefined;
  getSecurityState?: () => { isCompromised?: boolean; blocked?: boolean; reason?: string } | undefined;
}

/**
 * Decorates a Viem wallet client so all `sendTransaction` calls are pre-screened
 * and wrapped with EIP-712 attestations targeting GuardianPolicyGuard.
 */
export function withGuardianSecurity<TClient extends { sendTransaction?: (args: any) => Promise<any>; request?: (args: any) => Promise<any> }>(
  client: TClient,
  options: GuardianViemOptions
): TClient & { guardianInterceptor: GuardianInterceptor } {
  const defaultInterceptor = new GuardianInterceptor(options);
  const originalSendTransaction = client.sendTransaction ? client.sendTransaction.bind(client) : undefined;
  const originalRequest = client.request ? client.request.bind(client) : undefined;

  let result: any;

  const getInterceptor = (): GuardianInterceptor => {
    return (result && result.guardianInterceptor) || defaultInterceptor;
  };

  const decoratedSendTransaction = originalSendTransaction ? async (args: any): Promise<any> => {
    if (!args) {
      return originalSendTransaction(args);
    }

    const rawTx: RawTransaction = {
      to: args.to,
      data: args.data || "0x",
      value: args.value,
      gas: args.gas,
    };

    // Check runtime security barrier (halts unmonitored actions if state is compromised)
    if (options.getSecurityState) {
      const state = options.getSecurityState();
      if (state?.blocked || state?.isCompromised) {
        throw new GuardianSecurityError(
          `Transaction aborted before RPC dispatch: Agent security state is BLOCKED (${state.reason || "blocked by memory guard"})`,
          95,
          ["agent_security_state_blocked"],
          rawTx.to,
          rawTx.data || "0x"
        );
      }
    }

    const prompt = options.getPromptContext ? options.getPromptContext() : undefined;
    const interceptor = getInterceptor();

    // Pre-flight intercept & wrap (throws GuardianSecurityError if threat detected)
    const wrapped: WrappedTransaction = await interceptor.intercept(options.agentId, rawTx, prompt);

    // Replace target and data with Policy Guard envelope
    const securedArgs = {
      ...args,
      to: wrapped.to,
      data: wrapped.data,
      value: wrapped.value !== undefined ? wrapped.value : args.value,
    };

    return originalSendTransaction(securedArgs);
  } : undefined;

  const decoratedRequest = originalRequest ? async (args: any): Promise<any> => {
    if (!args) {
      return originalRequest(args);
    }

    if ((args.method === "eth_sendTransaction" || args.method === "eth_sendRawTransaction") && Array.isArray(args.params) && args.params[0] !== undefined) {
      const rawTx = args.params[0];

      // Check runtime security barrier (halts unmonitored actions if state is compromised)
      if (options.getSecurityState) {
        const state = options.getSecurityState();
        if (state?.blocked || state?.isCompromised) {
          throw new GuardianSecurityError(
            `Transaction aborted before RPC dispatch: Agent security state is BLOCKED (${state.reason || "blocked by memory guard"})`,
            95,
            ["agent_security_state_blocked"],
            typeof rawTx === "object" && rawTx !== null ? rawTx.to : undefined,
            typeof rawTx === "object" && rawTx !== null ? (rawTx.data || "0x") : String(rawTx)
          );
        }
      }

      // If eth_sendRawTransaction is dispatched, pre-signed raw bytes cannot be safely rewritten.
      // Halt direct raw transaction bypass to enforce Guardian pre-flight attestation invariants.
      if (args.method === "eth_sendRawTransaction") {
        throw new GuardianSecurityError(
          "Direct raw transaction dispatch rejected: transactions must be routed through GuardianInterceptor prior to signature",
          95,
          ["raw_transaction_bypass_attempt"],
          undefined,
          typeof rawTx === "string" ? rawTx : "0x"
        );
      }

      // Intercept and wrap eth_sendTransaction (JSON tx object)
      if (typeof rawTx === "object" && rawTx !== null) {
        const prompt = options.getPromptContext ? options.getPromptContext() : undefined;
        const txObj: RawTransaction = {
          to: rawTx.to,
          data: rawTx.data || "0x",
          value: rawTx.value,
          gas: rawTx.gas || rawTx.gasLimit,
        };

        const interceptor = getInterceptor();
        const wrapped = await interceptor.intercept(options.agentId, txObj, prompt);
        const securedTx = {
          ...rawTx,
          to: wrapped.to,
          data: wrapped.data,
          value: wrapped.value !== undefined
            ? (typeof wrapped.value === "bigint" ? "0x" + wrapped.value.toString(16) : wrapped.value)
            : rawTx.value,
        };
        return originalRequest({
          ...args,
          params: [securedTx, ...args.params.slice(1)],
        });
      }
    }
    return originalRequest(args);
  } : undefined;

  result = Object.assign(client, {
    guardianInterceptor: defaultInterceptor,
  });

  if (decoratedSendTransaction) {
    (result as any).sendTransaction = decoratedSendTransaction;
  }
  if (decoratedRequest) {
    (result as any).request = decoratedRequest;
  }

  return result as any;
}


