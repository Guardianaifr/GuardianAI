/**
 * GuardianAI hosted Eliza: every agent created in the GuardianAI console gets an ElizaOS agent here.
 *
 * Non-custodial: this server never sees an agent key. The browser proves it holds the agent key by
 * signing a session message; the hosted agent thinks (LLM + GuardianAI memory guard + relay approval
 * + on-chain dry run) and returns the approved call; the browser's agent key sends it.
 *
 *   GET  /health
 *   POST /api/eliza/session   { owner, wallet, agent, ts, sig }      -> { token, expiresAt }
 *   POST /api/eliza/message   Bearer token, { text, conversation }   -> { reply, payment }
 */
if (!process.env.LOG_LEVEL) process.env.LOG_LEVEL = "fatal";

import http from "node:http";
import crypto from "node:crypto";
import { createPublicClient, http as viemHttp, keccak256, toBytes, verifyMessage, getAddress, isAddress } from "viem";
import { guardianPlugin, monadTestnet, type GuardedPaymentOutcome } from "../../guardian-middleware/src/elizaos.ts";
import { FailoverLlm, failoverPlugin, providersFromEnv } from "./llm.ts";

const PORT = Number(process.env.PORT || 8080);
const GROQ_API_KEY = process.env.GROQ_API_KEY || "";
const llm = new FailoverLlm(providersFromEnv());
const llmPlugin = failoverPlugin(llm);
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString("hex");
const ORIGINS = (process.env.CORS_ORIGINS || "https://aiguardian.dev,http://localhost:5173,http://localhost:4173").split(",").map((s) => s.trim());
const FACTORY = "0xAb3aE67587D946e63b3cfFb32C9e32d701B8Ef03";
const MAX_AGENTS = Number(process.env.MAX_AGENTS || 25);
const SESSION_MS = 2 * 60 * 60 * 1000;
const DATA_DIR = process.env.ELIZA_DATA_DIR || "/tmp/guardian-eliza-db";

export const sessionMessage = (wallet: string, agent: string, ts: number) =>
  `GuardianAI hosted Eliza session\nwallet: ${getAddress(wallet)}\nagent: ${getAddress(agent)}\ntime: ${ts}`;

const pub = createPublicClient({ chain: monadTestnet, transport: viemHttp(process.env.MONAD_RPC_URL || undefined, { retryCount: 6, retryDelay: 500 }) });
const factoryAbi = [{ type: "function", name: "walletOf", stateMutability: "view", inputs: [{ type: "address" }, { type: "bytes32" }], outputs: [{ type: "address" }] }] as const;
const walletAbi = [
  { type: "function", name: "operator", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
  { type: "function", name: "owner", stateMutability: "view", inputs: [], outputs: [{ type: "address" }] },
] as const;

/* ---------------- sessions (HMAC tokens, no server state) ---------------- */
const b64u = (b: Buffer | string) => Buffer.from(b).toString("base64url");
const mac = (s: string) => b64u(crypto.createHmac("sha256", SECRET).update(s).digest());
interface Session { wallet: string; owner: string; agent: string; exp: number }
function issue(s: Session) { const body = b64u(JSON.stringify(s)); return `${body}.${mac(body)}`; }
function check(token: string | undefined): Session | null {
  if (!token) return null;
  const [body, sig] = token.split(".");
  if (!body || !sig || sig.length !== mac(body).length || !crypto.timingSafeEqual(Buffer.from(sig), Buffer.from(mac(body)))) return null;
  try { const s = JSON.parse(Buffer.from(body, "base64url").toString()); return s.exp > Date.now() ? s : null; } catch { return null; }
}

/* ---------------- rate limits + one-at-a-time LLM queue (free Groq tier) ---------------- */
const hits = new Map<string, number[]>();
function limited(key: string, max: number, windowMs: number) {
  const now = Date.now();
  const arr = (hits.get(key) || []).filter((t) => now - t < windowMs);
  arr.push(now); hits.set(key, arr);
  return arr.length > max;
}
setInterval(() => { const now = Date.now(); for (const [k, v] of hits) if (!v.some((t) => now - t < 120_000)) hits.delete(k); }, 60_000).unref();
let chain: Promise<unknown> = Promise.resolve();
let queued = 0;
const MAX_QUEUE = Number(process.env.MAX_QUEUE || 8);
function enqueue<T>(job: () => Promise<T>): Promise<T> {
  if (queued >= MAX_QUEUE) return Promise.reject(Object.assign(new Error("The hosted agent is busy. Try again in a minute."), { status: 503 }));
  queued++;
  const p = chain.then(job, job);
  chain = p.catch(() => {}).finally(() => { queued--; });
  return p;
}

/* ---------------- ElizaOS: one shared database, one runtime per wallet ---------------- */
let core: any, sqlMod: any, groqPlugin: any, bootstrapPlugin: any, eliza: any;
let ready: Promise<void> | null = null;
function boot() {
  return (ready ??= (async () => {
    core = await import("@elizaos/core");
    sqlMod = await import("@elizaos/plugin-sql");
    groqPlugin = (await import("@elizaos/plugin-groq")).default;
    bootstrapPlugin = (await import("@elizaos/plugin-bootstrap")).default;
    eliza = new core.ElizaOS();
    // plugin-sql 1.7 reads the agents table before migrating: migrate once, up front.
    const db = sqlMod.createDatabaseAdapter({ dataDir: DATA_DIR }, core.stringToUuid("guardian-eliza-host"));
    await db.init();
    await db.runPluginMigrations([sqlMod.default], { verbose: false });
  })());
}

const runtimes = new Map<string, { rt: any; used: number; last?: GuardedPaymentOutcome }>();
async function runtimeFor(s: Session) {
  await boot();
  const key = `${s.wallet}:${s.agent}`.toLowerCase();
  const hit = runtimes.get(key);
  if (hit) { hit.used = Date.now(); return hit; }
  if (runtimes.size >= MAX_AGENTS) {
    const [oldKey, old] = [...runtimes.entries()].sort((a, b) => a[1].used - b[1].used)[0];
    runtimes.delete(oldKey);
    await eliza.stopAgents([old.rt.agentId]).catch(() => {});
    await eliza.deleteAgents?.([old.rt.agentId]).catch(() => {});
  }
  const agentId = core.stringToUuid(`hosted:${key}`);
  const db = sqlMod.createDatabaseAdapter({ dataDir: DATA_DIR }, agentId);
  await db.init();
  const entry: { rt: any; used: number; last?: GuardedPaymentOutcome } = { rt: null, used: Date.now() };
  // Each runtime gets its own copy of the plugin so payment results can't cross between users.
  const action: any = guardianPlugin.actions![0];
  const plugin = {
    ...guardianPlugin,
    actions: [{ ...action, handler: async (...a: any[]) => { const r = await action.handler(...a); entry.last = r.data as GuardedPaymentOutcome; return r; } }],
  };
  const [rt] = await eliza.addAgents([{
    databaseAdapter: db,
    character: {
      id: agentId,
      name: "Treasurer",
      plugins: [],
      bio: ["An autonomous treasury agent on Monad testnet that pays invoices in MON from a GuardianAI-guarded wallet."],
      system: "You are Treasurer. When someone asks you to pay, send or transfer MON to an address, use the GUARDED_PAYMENT action. Keep replies to one or two short sentences and report results honestly.",
    },
    // Groq first, OpenRouter if Groq is rate-limited or down (llm.ts). plugin-groq stays for its tokenizer.
    plugins: [sqlMod.default, ...(GROQ_API_KEY ? [groqPlugin] : []), llmPlugin, bootstrapPlugin, plugin],
    settings: {
      GROQ_API_KEY,
      GROQ_SMALL_MODEL: process.env.GROQ_SMALL_MODEL || "openai/gpt-oss-20b",
      GROQ_LARGE_MODEL: process.env.GROQ_LARGE_MODEL || "openai/gpt-oss-120b",
      GUARDIAN_AGENT_ADDRESS: s.agent,
      GUARDIAN_WALLET: s.wallet,
      GUARDIAN_OWNER: s.owner,
      ...(process.env.GUARDIAN_RELAY_URL ? { GUARDIAN_RELAY_URL: process.env.GUARDIAN_RELAY_URL } : {}),
    },
  }], { returnRuntimes: true, autoStart: true, skipMigrations: true });
  entry.rt = rt;
  runtimes.set(key, entry);
  return entry;
}

/* ---------------- HTTP ---------------- */
class HttpError extends Error { constructor(public status: number, msg: string) { super(msg); } }
const readJson = (req: http.IncomingMessage) => new Promise<any>((resolve, reject) => {
  let n = 0; const chunks: Buffer[] = [];
  req.on("data", (c) => { n += c.length; if (n > 8_000) { reject(new HttpError(413, "Request too large")); req.destroy(); } else chunks.push(c); });
  req.on("end", () => { try { resolve(JSON.parse(Buffer.concat(chunks).toString() || "{}")); } catch { reject(new HttpError(400, "Body must be JSON")); } });
  req.on("error", reject);
});
const clientIp = (req: http.IncomingMessage) => String(req.headers["x-forwarded-for"] || req.socket.remoteAddress || "").split(",")[0].trim();

async function session(body: any, ip: string) {
  if (limited(`s:${ip}`, 20, 60_000)) throw new HttpError(429, "Too many requests. Try again in a minute.");
  const { owner, wallet, agent, ts, sig } = body || {};
  if (![owner, wallet, agent].every((a) => typeof a === "string" && isAddress(a)) || typeof sig !== "string") throw new HttpError(400, "owner, wallet, agent and sig are required");
  if (typeof ts !== "number" || Math.abs(Date.now() - ts) > 5 * 60_000) throw new HttpError(400, "Session request is too old. Check your computer's clock.");
  const okSig = await verifyMessage({ address: getAddress(agent), message: sessionMessage(wallet, agent, ts), signature: sig as `0x${string}` }).catch(() => false);
  if (!okSig) throw new HttpError(401, "The session wasn't signed by this agent key.");
  const agentId = keccak256(toBytes(`console:${owner.toLowerCase()}`));
  const [w, op, own] = await Promise.all([
    pub.readContract({ address: FACTORY, abi: factoryAbi, functionName: "walletOf", args: [getAddress(owner), agentId] }),
    pub.readContract({ address: getAddress(wallet), abi: walletAbi, functionName: "operator" }),
    pub.readContract({ address: getAddress(wallet), abi: walletAbi, functionName: "owner" }),
  ]).catch(() => { throw new HttpError(502, "Couldn't read the wallet on Monad testnet. Try again."); });
  if (w.toLowerCase() !== wallet.toLowerCase() || own.toLowerCase() !== owner.toLowerCase()) throw new HttpError(403, "That wallet wasn't created in the GuardianAI console by this owner.");
  if (op.toLowerCase() !== agent.toLowerCase()) throw new HttpError(403, "This key is no longer the wallet's agent key.");
  const exp = Date.now() + SESSION_MS;
  return { token: issue({ wallet: getAddress(wallet), owner: getAddress(owner), agent: getAddress(agent), exp }), expiresAt: exp };
}

async function message(req: http.IncomingMessage, body: any) {
  const s = check(String(req.headers.authorization || "").replace(/^Bearer\s+/i, ""));
  if (!s) throw new HttpError(401, "Session expired. Reload the console.");
  const text = String(body?.text || "").trim().slice(0, 1000);
  if (!text) throw new HttpError(400, "Say something.");
  const conv = String(body?.conversation || "main").replace(/[^a-zA-Z0-9_-]/g, "").slice(0, 40) || "main";
  if (limited(`m:${s.wallet}`, 10, 60_000)) throw new HttpError(429, "Slow down a little: 10 messages a minute.");
  if (!llm.providers.length) throw new HttpError(503, "The hosted agent has no LLM key configured.");
  return enqueue(async () => {
    const e = await runtimeFor(s);
    e.last = undefined;
    const res = await eliza.handleMessage(e.rt.agentId, {
      entityId: core.stringToUuid(`owner:${s.owner.toLowerCase()}`),
      roomId: core.stringToUuid(`room:${s.wallet.toLowerCase()}:${conv}`),
      content: { text, source: "guardian-console" },
    });
    const reply = res.processing?.responseContent || {};
    const p = e.last as GuardedPaymentOutcome | undefined;
    return {
      reply: String(reply.text || ""),
      actions: reply.actions || [],
      payment: p ? { outcome: p.outcome, to: p.to, amountMon: p.amountMon, riskScore: p.riskScore, reasons: (p.reasons || []).slice(0, 2), message: p.message, call: p.call } : null,
    };
  });
}

const server = http.createServer(async (req, res) => {
  const origin = String(req.headers.origin || "");
  if (ORIGINS.includes(origin)) {
    res.setHeader("Access-Control-Allow-Origin", origin);
    res.setHeader("Vary", "Origin");
    res.setHeader("Access-Control-Allow-Headers", "content-type, authorization");
    res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  }
  const send = (status: number, data: unknown) => { res.writeHead(status, { "content-type": "application/json" }); res.end(JSON.stringify(data)); };
  try {
    const url = (req.url || "").split("?")[0];
    if (req.method === "OPTIONS") { res.writeHead(ORIGINS.includes(origin) ? 204 : 404); res.end(); return; }
    if (req.method === "GET" && url === "/health") return send(200, { ok: true, agents: runtimes.size, queued, llm: llm.providers.map((p) => p.name), served: llm.stats.served, failovers: llm.stats.failovers, lastProvider: llm.stats.last ?? null });
    if (req.method === "POST" && url === "/api/eliza/session") return send(200, await session(await readJson(req), clientIp(req)));
    if (req.method === "POST" && url === "/api/eliza/message") return send(200, await message(req, await readJson(req)));
    send(404, { error: "Not found" });
  } catch (err: any) {
    const status = err?.status || 500;
    if (status >= 500) console.error("[eliza-host]", err?.stack || err);
    send(status, { error: status >= 500 && !err?.status ? "The hosted agent hit an error. Try again." : err.message });
  }
});

if (process.env.ELIZA_HOST_NO_LISTEN !== "1") {
  server.listen(PORT, () => console.log(`[eliza-host] listening on ${PORT}; LLM ${llm.providers.map((p) => p.name).join(" → ") || "MISSING"}; origins ${ORIGINS.join(" ")}`));
  boot().catch((e) => console.error("[eliza-host] boot failed", e));
  for (const sig of ["SIGTERM", "SIGINT"] as const) process.on(sig, () => { server.close(); process.exit(0); });
}
export { server };
