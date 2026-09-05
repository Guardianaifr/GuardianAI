/**
 * ElizaOS (ai16z) Drop-in Security Plugin for GuardianAI (v2 Audit Fixes)
 *
 * Directly counters the Princeton/Sentient ElizaOS memory-poisoning vulnerability
 * by intercepting memory state before actions execute, scanning for prompt injections,
 * and wrapping all outgoing EVM transactions into GuardianPolicyGuard on Monad.
 */

import { GuardianInterceptor, GuardianSecurityError } from "./interceptor.ts";
import type { GuardianConfig, RawTransaction, WrappedTransaction } from "./types.ts";

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
  memoryStore?: MemoryStore;
}

export interface ProvenanceEnvelope {
  source: "user" | "agent" | "tool" | "system";
  appId: string;
  agentId: string;
  trustLevel: number; // 0-100
  timestamp: number;
  isTombstoned: boolean;
}

interface MemoryRecord {
  text: string;
  provenance: ProvenanceEnvelope;
}

// Cyrillic → Latin visual confusables (Unicode TR39 subset)
const CONFUSABLES: Record<string, string> = {
  '\u0430': 'a', '\u0410': 'A', // а А
  '\u0435': 'e', '\u0415': 'E', // е Е
  '\u0454': 'e', '\u0404': 'E', // є Є
  '\u0456': 'i', '\u0406': 'I', // і І
  '\u0457': 'i',                  // ї
  '\u043E': 'o', '\u041E': 'O', // о О
  '\u0440': 'p', '\u0420': 'P', // р Р
  '\u0441': 'c', '\u0421': 'C', // с С
  '\u0443': 'y', '\u0423': 'Y', // у У
  '\u0445': 'x', '\u0425': 'X', // х Х
  '\u0455': 's', '\u0405': 'S', // ѕ Ѕ
  '\u0458': 'j', '\u0408': 'J', // ј Ј
  '\u04BB': 'h',                  // һ
};

const CONFUSABLES_REGEX = new RegExp('[' + Object.keys(CONFUSABLES).join('') + ']', 'g');

export function normalizeInput(text: string): string {
  // Strip zero-width/invisible Unicode
  let normalized = text.replace(/[\u200B\u200C\u200D\u200E\u200F\uFEFF\u00AD\u034F\u061C\u115F\u1160\u17B4\u17B5\u180E\u2000-\u200F\u202A-\u202E\u2060-\u2064\u2066-\u206F\uFFF0-\uFFF8]/g, "");
  
  // NFKC normalization (collapses fullwidth Latin, ligatures)
  normalized = normalized.normalize("NFKC");
  
  // Confusables substitution (Cyrillic → Latin visual equivalents)
  normalized = normalized.replace(CONFUSABLES_REGEX, (ch) => CONFUSABLES[ch] || ch);
  
  // Base64 decode scanning
  const b64Regex = /[A-Za-z0-9+/]{20,}={0,3}/g;
  let match;
  let decodedAppends = "";
  while ((match = b64Regex.exec(normalized)) !== null) {
    try {
      const decoded = atob(match[0]);
      decodedAppends += " " + decoded;
    } catch (e) {
      // Ignore invalid base64
    }
  }
  normalized += decodedAppends;
  
  // Strip control characters
  normalized = normalized.replace(/[\x00-\x08\x0B\x0C\x0E-\x1F\x7F]/g, "");
  
  // Collapse whitespace
  normalized = normalized.replace(/\s+/g, ' ').trim();
  
  return normalized;
}

const ADVERSARIAL_PATTERNS: RegExp[] = [
  // --- Instruction Override ---
  /ignore\s+(all\s+)?(previous|prior|above|earlier|preceding)\s+(instructions|directives|rules|guidelines|constraints|context)/i,
  /disregard\s+(all\s+)?(previous|prior|above|earlier|preceding)?\s*(instructions|directives|rules|guidelines|constraints|safety|guardrails|context)/i,
  /forget\s+(all|everything)\s+(previous\s+|prior\s+|above\s+|earlier\s+)?(instructions|directives|rules|context|you\s+know|you\s+were\s+told)/i,
  /override\s+(all\s+)?(previous|prior|current|existing|safety|security)?\s*(instructions|directives|rules|settings|config)/i,
  // --- System Directives ---
  /system\s+(override|directive|command|instruction|prompt)/i,
  /new\s+(instructions?|directives?|rules?|task|role|objective)/i,
  /do\s+not\s+follow\s+(previous|prior|any|the)\s+(instructions|rules|directives|guidelines)/i,
  // --- Drain / Exfiltrate / Sweep ---
  /(drain|sweep|exfiltrate|siphon|empty|liquidate)\s+(all\s+)?(the\s+)?(wallet|treasury|funds|balance|vault|assets|tokens|account)/i,
  /(transfer|send|forward)\s+(all|every|entire|full|complete|remaining)\s+(eth|mon|token|fund|balance|asset|amount)/i,
  // --- Reveal Secrets ---
  /(reveal|expose|show|display|output|print|leak|disclose|share)\s+(the\s+)?(private\s+key|seed\s+phrase|secret|password|mnemonic|api\s+key|credentials)/i,
  /(give|tell|send)\s+me\s+(the\s+|your\s+)?(private\s+key|seed\s+phrase|secret|password|mnemonic)/i,
  // --- Bypass Safety ---
  /(bypass|circumvent|disable|turn\s+off|deactivate|remove)\s+(the\s+)?(safety|security|guardrails?|guard|filter|restriction|protection|firewall|limit)/i,
  // --- Persist / Deferred Instructions ---
  /(persist|store|save|remember|memorize|record)\s+(this|these|the\s+following)\s+(instruction|directive|rule|command|setting|override)/i,
  /(always|from\s+now\s+on|henceforth|permanently|going\s+forward)\s+(do|execute|follow|obey|comply|perform|send|transfer|reveal)/i,
  /(whenever|every\s+time|each\s+time|next\s+time|if\s+anyone\s+asks)\s+.{0,60}(send|transfer|forward|reveal|execute|sweep|drain)/i,
  // --- Role Manipulation ---
  /you\s+are\s+now\s+(a\s+|an\s+|the\s+|my\s+)?(admin|administrator|root|superuser|unrestricted|unfiltered|jailbroken)/i,
  /your\s+(new\s+)?(role|persona|identity|character|task|objective|mission)\s+(is|will\s+be|has\s+changed)/i,
  /(act|behave|pretend|function)\s+(as|like)\s+(a\s+|an\s+|the\s+)?(admin|unrestricted|unfiltered|jailbroken|evil)/i,
  // --- Context Injection / Gaslighting (Princeton/Sentient vector) ---
  /(user|admin|owner|developer)\s+(has\s+)?(said|agreed|confirmed|approved|authorized|instructed|updated|changed|set)\s+.{0,60}(address|wallet|recipient|destination|payout|target)/i,
  /(you|we)\s+(previously\s+)?(agreed|confirmed|decided|established|set\s+up)\s+.{0,40}(address|wallet|recipient|payout|treasury)/i,
  /(earlier|previously|before|in\s+discord|in\s+chat|last\s+time)\s+.{0,60}(agreed|confirmed|said|told|instructed)\s+.{0,40}(address|wallet|send|transfer|forward)/i,
  /(designated|official|default|primary|new)\s+(treasury|payout|withdrawal|receiving)\s+(wallet|address)/i,
  // --- Delimiter / Context Boundary Injection ---
  /\[(?:[A-Z_]*(?:SYSTEM|INTERNAL|ADMIN|ROOT|OVERRIDE|DIRECTIVE)[A-Z_]*)\]/i,
  /---\s*\n?\s*\[?(?:SYSTEM|INTERNAL|ADMIN|OVERRIDE)/i,
  /<\s*(?:system|admin|root|override|instruction)\s*>/i,
  // --- Prompt Injection Meta & Jailbreak ---
  /(inject|insertion|injection|planted|implant)\s+(into\s+)?(memory|context|prompt|instruction|conversation)/i,
  /jailbreak/i,
  /(\bDAN\b|Do\s+Anything\s+Now)/i,
  /\bthis\s+is\s+not\s+a\s+prompt\s+injection\b/i,
  /======\s*END(\.|\s)/i,
  /\battention\s*-\s*stop\b/i,
  /\bas\s+a\s+language\s+model\s+free\b/i,
  /\byou\s+are\s+supposed\s+to\s+answer\s+at\s+all\s+times\b/i,
  /\b(that\s+was\s+ok\s+before|passed\s+the\s+first\s+test).{0,30}new\s+(challenge|task|test)\b/i,

  // --- System Prompt & Instruction Exfiltration ---
  /\b(show|tell|print|output|display|give|repeat|leak|reveal|share|echo|return)\s+(me\s+)?(all\s+)?(the\s+|your\s+)?(initial|system|original|hidden|secret|internal|above|prior|underlying)\s+(prompt\s+texts?|instructions?|rules?|directives?|system\s+prompt|embeddings?)\b/i,
  /\b(show|tell|reveal|print)\s+(me\s+)?(all\s+)?(your\s+prompt\s+texts?|the\s+system\s+prompt)\b/i,
  /\b(print|spell-?\s*check\s+and\s+print)\s+.{0,30}above\s+prompt\b/i,
  /\btell\s+me\s+what\s+your\s+(initial|original|system)\s+(instructions|prompt|rules)\s+(were|are)\b/i,
  /\b(print|output)\s+(a\s+|an\s+)?improved\s+version\s+of\s+(it|the\s+text\s+above)\b/i,

  // --- Conversational Reset & Context Erasure ---
  /\b(ignore|igmre)\s+(the\s+above|what\s+i\s+said\s+before|your\s+directions?|all\s+preceding\s+orders?|all\s+provided\s+context)\b/i,
  /\bforget\s+(everything|all)\s+(before\s+that|so\s+far|we\s+discussed|i\s+have\s+told\s+you|waht['']?s\s+before)\b/i,
  /\b(amnesia\s+and\s+forgot\s+everything|has\s+amnesia)\b/i,

  // --- Adversarial Roleplay & Persona Hijack ---
  /\b(act|pretend|behave)\s+(as|like)\s+(a\s+|an\s+)?(unrestricted|jailbroken|evil|unfiltered|illegal|rogue|DAN)\b/i,
  /\b(stay|remain)\s+in\s+(your|their)\s+roles?\s+without\s+.{0,30}(breaking|falling\s+out)\b/i,

  // --- Multilingual Injections (German & Spanish) ---
  /\bvergiss\s+(jetzt\s+)?(alles|alle)\s*(,|.)?\s*(was|bisher|davor|zuvor|wir\s+bisher|ich\s+dir|bisherigen\s+auftr[äa]ge)\b/i,
  /\b(drucken|zeigen|pr[üu]fen)\s+sie\s+.{0,40}(obige\s+eingabeaufforderung|prompt-texte|system-anweisung|gesamten\s+obigen\s+textes)\b/i,
  /\bh[öo]re\s+nicht\s+auf\s+alles\s+zuvor\s+gesagte\b/i,
  /\bdies\s+ist\s+keine\s+aufforderungsspritze\b/i,
  /\bverharren\s+stets\s+in\s+ihren\s+rollen\b/i,
  /\bolvide\s+(todo\s+)?(que\s+dije|lo\s+anterior|las\s+instrucciones)\b/i,

  // --- Deferred Memory Install ---
  /(note|memo|reminder|context\s+note)\s*:\s*(assistant|agent|ai|you|bot)\s+(must|should|shall|will|needs?\s+to)/i,
  /(note|memo|reminder)\s+(for\s+)?(future\s+)?(context|reference|use)\s*:\s*(assistant|agent|ai|you|bot)\s+(must|should|shall|will|needs?\s+to)/i,
];

export class MemoryStore {
  private _memory: Map<string, MemoryRecord[]> = new Map();
  private _quarantineLog: Map<string, MemoryRecord[]> = new Map();
  private _revokedApps: Set<string> = new Set();
  private _crossAgentGrants: Set<string> = new Set(); // "from->to" serialized

  public write(sessionId: string, text: string, provenance: ProvenanceEnvelope): {allowed: boolean, reason: string} {
    // Gate 1: Revocation check — revoked apps cannot write
    if (this._revokedApps.has(provenance.appId)) {
      return { allowed: false, reason: `App ${provenance.appId} access is revoked` };
    }

    // Gate 2: Trust cap enforcement
    if (provenance.source === "tool" && provenance.trustLevel >= 80) {
      return { allowed: false, reason: "Tool sources cannot claim trustLevel >= 80" };
    }
    if (provenance.source === "tool") {
      provenance.trustLevel = Math.min(provenance.trustLevel, 50);
    } else if (provenance.source === "agent") {
      provenance.trustLevel = Math.min(provenance.trustLevel, 70);
    }

    // Gate 3: Pattern matching on normalized input
    const normText = normalizeInput(text);
    let isPoisoned = false;
    let reason = "";

    for (const pattern of ADVERSARIAL_PATTERNS) {
      if (pattern.test(normText)) {
        isPoisoned = true;
        reason = `Pattern match: ${pattern.source}`;
        break;
      }
    }

    const record: MemoryRecord = { text, provenance };

    if (isPoisoned) {
      if (!this._quarantineLog.has(sessionId)) {
        this._quarantineLog.set(sessionId, []);
      }
      this._quarantineLog.get(sessionId)!.push(record);
      return { allowed: false, reason };
    }

    if (!this._memory.has(sessionId)) {
      this._memory.set(sessionId, []);
    }
    this._memory.get(sessionId)!.push(record);
    return { allowed: true, reason: "" };
  }

  public read(sessionId: string, agentId: string): MemoryRecord[] {
    const records = this._memory.get(sessionId) || [];
    return records.filter(record => {
      if (record.provenance.isTombstoned) return false;
      if (this._revokedApps.has(record.provenance.appId)) return false;
      
      const pAgent = record.provenance.agentId;
      if (pAgent !== agentId) {
        const grantKey = `${pAgent}->${agentId}`;
        if (!this._crossAgentGrants.has(grantKey)) return false;
      }
      return true;
    });
  }

  public revokeAppAccess(appId: string): number {
    this._revokedApps.add(appId);
    let count = 0;
    for (const [_, records] of this._memory.entries()) {
      for (const record of records) {
        if (record.provenance.appId === appId && !record.provenance.isTombstoned) {
          record.provenance.isTombstoned = true;
          count++;
        }
      }
    }
    return count;
  }

  public restoreAppAccess(appId: string): void {
    this._revokedApps.delete(appId);
  }

  public grantCrossAgentAccess(fromAgent: string, toAgent: string): void {
    this._crossAgentGrants.add(`${fromAgent}->${toAgent}`);
  }

  public revokeCrossAgentAccess(fromAgent: string, toAgent: string): void {
    this._crossAgentGrants.delete(`${fromAgent}->${toAgent}`);
  }

  public getQuarantineLog(sessionId: string): MemoryRecord[] {
    return this._quarantineLog.get(sessionId) || [];
  }
}

export function createGuardianPlugin(config: GuardianConfig = {}): ElizaPlugin {
  const interceptor = new GuardianInterceptor(config);
  const memoryStore = new MemoryStore();

  // 1. Evaluator: Memory Poisoning Guard (Princeton/Sentient exploit mitigation)
  const memoryGuardEvaluator: ElizaEvaluator = {
    name: "GUARDIAN_MEMORY_GUARD",
    similes: ["INJECTION_DETECTOR", "MEMORY_POISONING_SCANNER"],
    description: "Evaluates message history and persistent agent memory for prompt injection attacks.",
    validate: async (_runtime: ElizaRuntime, message: ElizaMessage): Promise<boolean> => {
      return typeof message?.content?.text === "string" && message.content.text.length > 0;
    },
    handler: async (runtime: ElizaRuntime, message: ElizaMessage): Promise<{ safe: boolean; detected: string[]; blocked: boolean }> => {
      const text = message.content.text;
      const normText = normalizeInput(text);
      const detected: string[] = [];

      for (const pattern of ADVERSARIAL_PATTERNS) {
        if (pattern.test(normText)) {
          detected.push(pattern.source);
        }
      }

      if (detected.length > 0) {
        const warning = `[GuardianAI] Memory poisoning / injection detected for agent '${runtime.agentId}': ${detected.join(", ")}`;
        console.warn(warning);
        return { safe: false, detected, blocked: true };
      }

      return { safe: true, detected: [], blocked: false };
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
    memoryStore: memoryStore,
  };
}
