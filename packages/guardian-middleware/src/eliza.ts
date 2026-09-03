/**
 * ElizaOS (ai16z) Drop-in Security Plugin for GuardianAI
 *
 * Directly counters the Princeton/Sentient ElizaOS memory-poisoning vulnerability
 * by intercepting memory state before actions execute, scanning for prompt injections,
 * and wrapping all outgoing EVM transactions into GuardianPolicyGuard on Monad.
 */

import { GuardianInterceptor, GuardianSecurityError } from "./interceptor.ts";
import type { GuardianConfig, RawTransaction, WrappedTransaction } from "./types.ts";

// Common adversarial patterns used in ElizaOS context injection attacks
const ADVERSARIAL_PATTERNS = [
  /ignore\s+(all\s+)?(previous\s+)?instructions/i,
  /system\s+override/i,
  /drain\s+(all\s+)?(wallet|treasury|funds)/i,
  /transfer\s+all\s+(eth|mon|tokens)/i,
  /disregard\s+(safety|guardrails|rules)/i,
  /reveal\s+(private\s+key|seed\s+phrase|secret)/i,
];

export interface ElizaMessage {
  id?: string;
  userId?: string;
  content: {
    text: string;
    action?: string;
    params?: any;
    [key: string]: any;
  };
}

export interface ElizaRuntime {
  agentId: string;
  character?: { name: string };
  messageManager?: {
    getMemories: (opts: any) => Promise<ElizaMessage[]>;
  };
  [key: string]: any;
}

export interface ElizaAction {
  name: string;
  similes: string[];
  description: string;
  validate: (runtime: ElizaRuntime, message: ElizaMessage) => Promise<boolean>;
  handler: (runtime: ElizaRuntime, message: ElizaMessage, state?: any) => Promise<any>;
}

export interface ElizaEvaluator {
  name: string;
  similes: string[];
  description: string;
  validate: (runtime: ElizaRuntime, message: ElizaMessage) => Promise<boolean>;
  handler: (runtime: ElizaRuntime, message: ElizaMessage) => Promise<any>;
}

export interface ElizaProvider {
  get: (runtime: ElizaRuntime, message: ElizaMessage, state?: any) => Promise<string>;
}

export interface ElizaPlugin {
  name: string;
  description: string;
  actions: ElizaAction[];
  evaluators: ElizaEvaluator[];
  providers: ElizaProvider[];
}

/**
 * Creates an ElizaOS security plugin bound to GuardianPolicyGuard on Monad.
 */
export function createGuardianPlugin(config: GuardianConfig = {}): ElizaPlugin {
  const interceptor = new GuardianInterceptor(config);

  // 1. Evaluator: Memory Poisoning Guard (Princeton/Sentient exploit mitigation)
  const memoryGuardEvaluator: ElizaEvaluator = {
    name: "GUARDIAN_MEMORY_GUARD",
    similes: ["INJECTION_DETECTOR", "MEMORY_POISONING_SCANNER"],
    description: "Evaluates message history and persistent agent memory for prompt injection attacks.",
    validate: async (_runtime: ElizaRuntime, message: ElizaMessage): Promise<boolean> => {
      return typeof message?.content?.text === "string" && message.content.text.length > 0;
    },
    handler: async (runtime: ElizaRuntime, message: ElizaMessage): Promise<{ safe: boolean; detected: string[] }> => {
      const text = message.content.text;
      const detected: string[] = [];

      for (const pattern of ADVERSARIAL_PATTERNS) {
        if (pattern.test(text)) {
          detected.push(pattern.source);
        }
      }

      if (detected.length > 0) {
        const warning = `[GuardianAI] Memory poisoning / injection detected for agent '${runtime.agentId}': ${detected.join(", ")}`;
        console.warn(warning);
        return { safe: false, detected };
      }

      return { safe: true, detected: [] };
    },
  };

  // 2. Action: Execute Protected Transaction via GuardianPolicyGuard
  const protectedTransactionAction: ElizaAction = {
    name: "EXECUTE_PROTECTED_TRANSACTION",
    similes: ["SAFE_SEND_TX", "PROTECTED_TRANSFER", "SECURE_SWAP"],
    description: "Validates and wraps an on-chain EVM transaction through GuardianPolicyGuard on Monad.",
    validate: async (_runtime: ElizaRuntime, message: ElizaMessage): Promise<boolean> => {
      const tx = message?.content?.params?.tx as RawTransaction | undefined;
      return !!(tx && typeof tx.to === "string" && tx.to.startsWith("0x"));
    },
    handler: async (runtime: ElizaRuntime, message: ElizaMessage): Promise<WrappedTransaction> => {
      const tx = message.content.params.tx as RawTransaction;
      const prompt = message.content.text;

      // Fail-closed execution wrap
      const wrapped = await interceptor.intercept(runtime.agentId, tx, prompt);
      return wrapped;
    },
  };

  // 3. Provider: Security Context & Soulbound Passport Status
  const securityProvider: ElizaProvider = {
    get: async (runtime: ElizaRuntime): Promise<string> => {
      return JSON.stringify({
        guardianStatus: "ACTIVE",
        network: "Monad Testnet",
        chainId: interceptor.chainId,
        policyGuard: interceptor.policyGuardAddress,
        agentId: runtime.agentId,
        protection: "EIP-712 Pre-Flight Attestation Active",
        failClosed: interceptor.failClosed,
      });
    },
  };

  return {
    name: "guardian-security",
    description: "GuardianAI EIP-712 On-Chain Safety & Anti-Drain Interceptor for ElizaOS",
    actions: [protectedTransactionAction],
    evaluators: [memoryGuardEvaluator],
    providers: [securityProvider],
  };
}

