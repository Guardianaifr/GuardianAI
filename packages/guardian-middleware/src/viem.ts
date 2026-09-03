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
}

/**
 * Decorates a Viem wallet client so all `sendTransaction` calls are pre-screened
 * and wrapped with EIP-712 attestations targeting GuardianPolicyGuard.
 */
export function withGuardianSecurity<TClient extends { sendTransaction: (args: any) => Promise<any> }>(
  client: TClient,
  options: GuardianViemOptions
): TClient & { guardianInterceptor: GuardianInterceptor } {
  const interceptor = new GuardianInterceptor(options);
  const originalSendTransaction = client.sendTransaction.bind(client);

  const decoratedSendTransaction = async (args: any): Promise<any> => {
    const rawTx: RawTransaction = {
      to: args.to,
      data: args.data || "0x",
      value: args.value,
      gas: args.gas,
    };

    const prompt = options.getPromptContext ? options.getPromptContext() : undefined;

    // Pre-flight intercept & wrap
    const wrapped: WrappedTransaction = await interceptor.intercept(options.agentId, rawTx, prompt);

    // Replace target and data with Policy Guard envelope
    const securedArgs = {
      ...args,
      to: wrapped.to,
      data: wrapped.data,
      value: wrapped.value,
    };

    return originalSendTransaction(securedArgs);
  };

  return Object.assign(client, {
    sendTransaction: decoratedSendTransaction,
    guardianInterceptor: interceptor,
  });
}

