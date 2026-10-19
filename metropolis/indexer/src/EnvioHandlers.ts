/**
 * Envio HyperIndex (v3) registrations for GuardianAI on Monad testnet.
 *
 * The state transitions live in EventHandlers.ts as pure functions (unit-tested without Envio).
 * Each registration here loads the entities an event touches into a small in-memory store,
 * runs the pure handler, and writes the touched entities back through the Envio context.
 */
import { indexer, createEffect, S } from "envio";
import * as H from "./EventHandlers";

type Ctx = any; // entity accessors are typed at each call site by Envio

const ENFORCEMENT_ID = "global";

async function loadGlobal(context: Ctx, db: H.MockDbStore) {
  db.globalStats = (await context.GlobalSecurityStats.get("global")) ?? H.createInMemoryDb().globalStats;
  db.globalStats = { ...db.globalStats! };
}
function saveGlobal(context: Ctx, db: H.MockDbStore) {
  if (db.globalStats) context.GlobalSecurityStats.set(db.globalStats);
}
async function loadEnforcement(context: Ctx, db: H.MockDbStore) {
  const s = await context.EnforcementStats.get(ENFORCEMENT_ID);
  db.enforcementStats = s ? { ...s } : H.emptyEnforcementStats();
}
function saveEnforcement(context: Ctx, db: H.MockDbStore) {
  if (db.enforcementStats) context.EnforcementStats.set(db.enforcementStats);
}
async function loadInto<T extends { id: string }>(entity: any, map: Map<string, T>, id: string) {
  const row = await entity.get(id);
  if (row) map.set(id, { ...row });
}
const lc = (v: any) => String(v ?? "").toLowerCase();

// Envio entities need every nullable field present (as undefined); the pure entities mark them optional.
const threat = (t: H.ThreatRecordEntity) => ({ ...t, removedAt: t.removedAt });
const passport = (p: H.PassportRecordEntity) => ({ ...p, revokedAt: p.revokedAt });
const wallet = (w: H.AgentWalletEntity) => ({ ...w, threatOracle: w.threatOracle });
const execution = (e: H.AgentWalletExecutionEntity) => ({ ...e, nonce: e.nonce, riskScore: e.riskScore });

// ── Existing protocol contracts ───────────────────────────────────────────────

indexer.onEvent({ contract: "GuardianPolicyGuard", event: "ActionExecutedWithAttestation" }, async ({ event, context }) => {
  const db = H.createInMemoryDb();
  await loadGlobal(context, db);
  const a = H.handleActionExecutedWithAttestation(event, db);
  context.AgentAction.set(a);
  saveGlobal(context, db);
});

indexer.onEvent({ contract: "GuardianThreatFeedRegistry", event: "AddressAdded" }, async ({ event, context }) => {
  const db = H.createInMemoryDb();
  await loadGlobal(context, db);
  await loadInto(context.ThreatRecord, db.threatRecords, lc(event.params.malicious));
  context.ThreatRecord.set(threat(H.handleAddressAdded(event, db)));
  saveGlobal(context, db);
});

indexer.onEvent({ contract: "GuardianThreatFeedRegistry", event: "AddressRemoved" }, async ({ event, context }) => {
  const db = H.createInMemoryDb();
  await loadGlobal(context, db);
  await loadInto(context.ThreatRecord, db.threatRecords, lc(event.params.malicious));
  const r = H.handleAddressRemoved(event, db);
  if (r) context.ThreatRecord.set(threat(r));
  saveGlobal(context, db);
});

indexer.onEvent({ contract: "GuardianThreatFeedRegistry", event: "StringAddressAdded" }, async ({ event, context }) => {
  const db = H.createInMemoryDb();
  await loadGlobal(context, db);
  await loadInto(context.ThreatRecord, db.threatRecords, H.cleanEntityId(H.cleanString(event.params.malicious, 1024)));
  context.ThreatRecord.set(threat(H.handleStringAddressAdded(event, db)));
  saveGlobal(context, db);
});

indexer.onEvent({ contract: "GuardianThreatFeedRegistry", event: "StringAddressRemoved" }, async ({ event, context }) => {
  const db = H.createInMemoryDb();
  await loadGlobal(context, db);
  await loadInto(context.ThreatRecord, db.threatRecords, H.cleanEntityId(H.cleanString(event.params.malicious, 1024)));
  const r = H.handleStringAddressRemoved(event, db);
  if (r) context.ThreatRecord.set(threat(r));
  saveGlobal(context, db);
});

indexer.onEvent({ contract: "GuardianPassportSBT", event: "ScoreUpdated" }, async ({ event, context }) => {
  const db = H.createInMemoryDb();
  await loadGlobal(context, db);
  await loadInto(context.PassportRecord, db.passportRecords, event.params.tokenId.toString());
  context.PassportRecord.set(passport(H.handleScoreUpdated(event, db)));
  saveGlobal(context, db);
});

// Passport issuance emits only Transfer + Locked (no agent hash, score or tier), so read the
// passport struct on-chain at the mint block. Cached, so re-syncs do not repeat the RPC call.
const PASSPORTS_SELECTOR = "0xcb22f5fd"; // passports(uint256)
const RPC_URL = (globalThis as any).process?.env?.ENVIO_MONAD_RPC_URL || "https://testnet-rpc.monad.xyz";
const ZERO_ADDRESS = "0x0000000000000000000000000000000000000000";

const readPassport = createEffect(
  {
    name: "readPassport",
    input: { contract: S.string, tokenId: S.string, blockNumber: S.number },
    output: { agentHash: S.string, tier: S.number, score: S.string },
    rateLimit: { calls: 10, per: "second" },
    cache: true,
  },
  async ({ input }) => {
    const data = PASSPORTS_SELECTOR + BigInt(input.tokenId).toString(16).padStart(64, "0");
    let lastError: unknown;
    for (let attempt = 0; attempt < 5; attempt++) {
      try {
        const res = await fetch(RPC_URL, {
          method: "POST",
          headers: { "content-type": "application/json" },
          body: JSON.stringify({
            jsonrpc: "2.0", id: 1, method: "eth_call",
            params: [{ to: input.contract, data }, "0x" + input.blockNumber.toString(16)],
          }),
        });
        const json: any = await res.json();
        if (json.error) throw new Error(`eth_call passports(${input.tokenId}): ${json.error.message}`);
        const out: string = String(json.result).slice(2);
        const word = (i: number) => out.slice(i * 64, (i + 1) * 64);
        return { agentHash: "0x" + word(0), tier: Number(BigInt("0x" + word(1))), score: BigInt("0x" + word(2)).toString() };
      } catch (e) {
        lastError = e;
        await new Promise((r) => setTimeout(r, 500 * (attempt + 1)));
      }
    }
    throw lastError;
  }
);

indexer.onEvent({ contract: "GuardianPassportSBT", event: "Transfer" }, async ({ event, context }) => {
  if (lc(event.params.from) !== ZERO_ADDRESS) return; // only mints; burns are covered by PassportRevoked
  const tokenId = event.params.tokenId.toString();
  const db = H.createInMemoryDb();
  await loadGlobal(context, db);
  await loadInto(context.PassportRecord, db.passportRecords, tokenId);
  const p = await context.effect(readPassport, { contract: event.srcAddress, tokenId, blockNumber: event.block.number });
  context.PassportRecord.set(passport(H.handlePassportMinted(event, { ...p, score: BigInt(p.score) }, db)));
  saveGlobal(context, db);
});

indexer.onEvent({ contract: "GuardianPassportSBT", event: "PassportRevoked" }, async ({ event, context }) => {
  const tokenId = event.params.tokenId.toString();
  const db = H.createInMemoryDb();
  await loadGlobal(context, db);
  await loadInto(context.PassportRecord, db.passportRecords, tokenId);
  let onchain: H.OnchainPassport | undefined;
  if (!db.passportRecords.has(tokenId)) {
    const p = await context.effect(readPassport, { tokenId, blockNumber: event.block.number - 1 });
    onchain = { ...p, score: BigInt(p.score) };
  }
  const r = H.handlePassportRevoked(event, db, onchain);
  if (r) context.PassportRecord.set(passport(r));
  saveGlobal(context, db);
});

indexer.onEvent({ contract: "GuardianCortexAnchor", event: "RootCommitted" }, async ({ event, context }) => {
  const db = H.createInMemoryDb();
  await loadGlobal(context, db);
  context.CortexCommitment.set(H.handleRootCommitted(event, db));
  saveGlobal(context, db);
});

indexer.onEvent({ contract: "GuardianRiskAttestation", event: "RiskAttested" }, async ({ event, context }) => {
  context.ContractRiskRecord.set(H.handleRiskAttested(event, H.createInMemoryDb()));
});

indexer.onEvent({ contract: "GuardianRiskAttestation", event: "AttestationUpdated" }, async ({ event, context }) => {
  context.ContractRiskRecord.set(H.handleAttestationUpdated(event, H.createInMemoryDb()));
});

// ── On-chain enforcement layer ────────────────────────────────────────────────

// Every wallet the factory creates is indexed from then on.
indexer.contractRegister({ contract: "GuardianAgentWalletFactory", event: "WalletCreated" }, async ({ event, context }) => {
  context.chain.GuardianAgentWallet.add(event.params.wallet);
});

indexer.onEvent({ contract: "GuardianAgentWalletFactory", event: "WalletCreated" }, async ({ event, context }) => {
  const db = H.createInMemoryDb();
  await loadEnforcement(context, db);
  await loadInto(context.AgentWallet, db.agentWallets!, lc(event.params.wallet));
  context.AgentWallet.set(wallet(H.handleWalletCreated(event, db)));
  saveEnforcement(context, db);
});

for (const [eventName, byOwner] of [["Executed", false], ["OwnerExecuted", true]] as const) {
  indexer.onEvent({ contract: "GuardianAgentWallet", event: eventName }, async ({ event, context }) => {
    const db = H.createInMemoryDb();
    await loadEnforcement(context, db);
    await loadInto(context.AgentWallet, db.agentWallets!, lc(event.srcAddress));
    const exec = byOwner ? H.handleWalletOwnerExecuted(event, db) : H.handleWalletExecuted(event, db);
    context.AgentWalletExecution.set(execution(exec));
    const w = db.agentWallets!.get(lc(event.srcAddress));
    if (w) context.AgentWallet.set(wallet(w));
    saveEnforcement(context, db);
  });
}

for (const [eventName, paused] of [["Paused", true], ["Unpaused", false]] as const) {
  indexer.onEvent({ contract: "GuardianAgentWallet", event: eventName }, async ({ event, context }) => {
    const db = H.createInMemoryDb();
    await loadInto(context.AgentWallet, db.agentWallets!, lc(event.srcAddress));
    const w = H.handleWalletPaused(event, db, paused);
    if (w) context.AgentWallet.set(wallet(w));
  });
}

indexer.onEvent({ contract: "GuardianAgentWallet", event: "ThreatOracleUpdated" }, async ({ event, context }) => {
  const db = H.createInMemoryDb();
  await loadInto(context.AgentWallet, db.agentWallets!, lc(event.srcAddress));
  const w = H.handleWalletThreatOracleUpdated(event, db);
  if (w) context.AgentWallet.set(wallet(w));
});

indexer.onEvent({ contract: "GuardianThreatOracle", event: "ThreatReportAccepted" }, async ({ event, context }) => {
  const db = H.createInMemoryDb();
  await loadEnforcement(context, db);
  context.ThreatOracleReport.set(H.handleThreatReportAccepted(event, db));
  saveEnforcement(context, db);
});

indexer.onEvent({ contract: "GuardianThreatOracle", event: "AddressFlagUpdated" }, async ({ event, context }) => {
  const db = H.createInMemoryDb();
  await loadEnforcement(context, db);
  await loadInto(context.ThreatOracleFlag, db.oracleFlags!, lc(event.params.account));
  context.ThreatOracleFlag.set(H.handleAddressFlagUpdated(event, db));
  saveEnforcement(context, db);
});
