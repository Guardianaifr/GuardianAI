/** Starts a real ElizaOS 1.x agent wired to a GuardianAI-guarded wallet. */
import { guardianPlugin, type GuardedPaymentOutcome } from "../../guardian-middleware/src/elizaos.ts";

export interface AgentConfig {
  wallet: string;
  owner: string;
  agentKey: string;
  groqKey: string;
  dataDir: string;
  relayUrl?: string;
  onPayment?: (r: GuardedPaymentOutcome) => void;
}

export async function startAgent(cfg: AgentConfig) {
  // Loaded lazily so LOG_LEVEL (set by the CLI) applies before ElizaOS creates its logger.
  const core: any = await import("@elizaos/core");
  const sqlMod: any = await import("@elizaos/plugin-sql");
  const groqPlugin = (await import("@elizaos/plugin-groq")).default;
  const bootstrapPlugin = (await import("@elizaos/plugin-bootstrap")).default;
  const sqlPlugin = sqlMod.default;

  if (cfg.onPayment) {
    const action: any = guardianPlugin.actions![0];
    const orig = action.__orig || action.handler;
    action.__orig = orig;
    action.handler = async (...args: any[]) => { const r = await orig(...args); cfg.onPayment!(r.data as GuardedPaymentOutcome); return r; };
  }

  const agentId = core.stringToUuid(`guardian-treasurer:${cfg.wallet.toLowerCase()}`);
  // plugin-sql 1.7 reads the agents table before migrating, so migrate first.
  const db = sqlMod.createDatabaseAdapter({ dataDir: cfg.dataDir }, agentId);
  await db.init();
  await db.runPluginMigrations([sqlPlugin], { verbose: false });

  const eliza = new core.ElizaOS();
  const [rt] = await eliza.addAgents([{
    databaseAdapter: db,
    character: {
      id: agentId,
      name: "Treasurer",
      plugins: [],
      bio: ["An autonomous treasury agent on Monad testnet. It pays invoices in MON from a GuardianAI-guarded wallet when asked."],
      system: "You are Treasurer. When someone asks you to pay, send or transfer MON to an address, use the GUARDED_PAYMENT action. Keep replies short and report results honestly.",
    },
    plugins: [sqlPlugin, groqPlugin, bootstrapPlugin, guardianPlugin],
    settings: {
      GROQ_API_KEY: cfg.groqKey,
      GROQ_SMALL_MODEL: process.env.GROQ_SMALL_MODEL || "openai/gpt-oss-20b",
      GROQ_LARGE_MODEL: process.env.GROQ_LARGE_MODEL || "openai/gpt-oss-120b",
      GUARDIAN_AGENT_PRIVATE_KEY: cfg.agentKey,
      GUARDIAN_WALLET: cfg.wallet,
      GUARDIAN_OWNER: cfg.owner,
      ...(cfg.relayUrl ? { GUARDIAN_RELAY_URL: cfg.relayUrl } : {}),
    },
  }], { returnRuntimes: true, autoStart: true });

  const user = core.stringToUuid("guardianai-eliza-user");
  const say = async (room: string, text: string) => {
    const res = await eliza.handleMessage(rt.agentId, { entityId: user, roomId: core.stringToUuid(room), content: { text, source: "cli" } });
    return (res.processing?.responseContent || {}) as { text?: string; actions?: string[] };
  };
  return { eliza, rt, user, say, stringToUuid: core.stringToUuid as (s: string) => string };
}
