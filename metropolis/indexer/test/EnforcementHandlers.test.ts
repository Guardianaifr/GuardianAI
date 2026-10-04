import assert from "assert";
import {
  createInMemoryDb,
  handleWalletCreated,
  handleWalletExecuted,
  handleWalletOwnerExecuted,
  handleWalletPaused,
  handleWalletThreatOracleUpdated,
  handleThreatReportAccepted,
  handleAddressFlagUpdated,
} from "../src/EventHandlers.ts";

const WALLET = "0xCCb137694f2910c8Ec4883d108c989648019D335";
const ev = (params: any, extra: any = {}) => ({
  params,
  srcAddress: WALLET,
  block: { timestamp: 1000 + (extra.logIndex ?? 0) },
  transaction: { hash: extra.hash ?? "0xtx", from: "0xfrom" },
  logIndex: extra.logIndex ?? 0,
});

let passed = 0;
const t = (name: string, fn: () => void) => { fn(); passed++; console.log(`  [+] PASS: ${name}`); };
console.log("Enforcement layer handlers (GuardianAgentWallet + CRE threat oracle)");

const db = createInMemoryDb();

t("WalletCreated registers a wallet once (idempotent on replay)", () => {
  const e = ev({ agentId: "0xAB", wallet: WALLET, owner: "0xOWNER", operator: "0xOP" }, { hash: "0xc1" });
  handleWalletCreated(e, db);
  handleWalletCreated(e, db);
  const w = db.agentWallets!.get(WALLET.toLowerCase())!;
  assert.equal(w.owner, "0xowner");
  assert.equal(w.operator, "0xop");
  assert.equal(w.paused, false);
  assert.equal(db.enforcementStats!.agentWallets, 1n);
});

t("Executed counts GuardianAI-approved calls; replayed log is not double counted", () => {
  const e = ev({ nonce: 7n, target: "0xT", value: 5n, riskScore: 10n, calldataHash: "0xH" }, { hash: "0xe1", logIndex: 1 });
  handleWalletExecuted(e, db);
  handleWalletExecuted(e, db);
  const x = db.walletExecutions!.get("0xe1-1")!;
  assert.equal(x.byOwner, false);
  assert.equal(x.nonce, 7n);
  assert.equal(x.riskScore, 10);
  assert.equal(db.agentWallets!.get(WALLET.toLowerCase())!.executedCount, 1n);
  assert.equal(db.enforcementStats!.guardianApprovedExecutions, 1n);
});

t("OwnerExecuted is tracked separately (human emergency path, no approval)", () => {
  handleWalletOwnerExecuted(ev({ target: "0xT", value: 0n, calldataHash: "0xH" }, { hash: "0xo1", logIndex: 2 }), db);
  const x = db.walletExecutions!.get("0xo1-2")!;
  assert.equal(x.byOwner, true);
  assert.equal(x.nonce, undefined);
  assert.equal(db.enforcementStats!.ownerExecutions, 1n);
  assert.equal(db.agentWallets!.get(WALLET.toLowerCase())!.ownerExecutedCount, 1n);
});

t("Paused / Unpaused and ThreatOracleUpdated update the wallet", () => {
  handleWalletPaused(ev({ account: "0xOP" }), db, true);
  assert.equal(db.agentWallets!.get(WALLET.toLowerCase())!.paused, true);
  handleWalletPaused(ev({ account: "0xOWNER" }), db, false);
  assert.equal(db.agentWallets!.get(WALLET.toLowerCase())!.paused, false);
  handleWalletThreatOracleUpdated(ev({ previousOracle: "0x0", newOracle: "0xORACLE" }), db);
  assert.equal(db.agentWallets!.get(WALLET.toLowerCase())!.threatOracle, "0xoracle");
});

t("ThreatReportAccepted stores DON report stats", () => {
  handleThreatReportAccepted(ev({ asOf: 99n, blocked: 3n, intercepted: 10n, passed: 7n, feedDigest: "0xD", changes: 2n }, { hash: "0xr1", logIndex: 3 }), db);
  const r = db.oracleReports!.get("0xr1-3")!;
  assert.equal(r.asOf, 99n);
  assert.equal(r.blocked, 3n);
  assert.equal(db.enforcementStats!.oracleReports, 1n);
});

t("AddressFlagUpdated keeps flaggedCount right through flag, re-flag and unflag", () => {
  handleAddressFlagUpdated(ev({ account: "0xBAD", flagged: true }), db);
  handleAddressFlagUpdated(ev({ account: "0xBAD", flagged: true }), db);
  assert.equal(db.enforcementStats!.oracleFlaggedCount, 1n);
  handleAddressFlagUpdated(ev({ account: "0xbad", flagged: false }), db);
  assert.equal(db.oracleFlags!.get("0xbad")!.flagged, false);
  assert.equal(db.enforcementStats!.oracleFlaggedCount, 0n);
  handleAddressFlagUpdated(ev({ account: "0xNEVER", flagged: false }), db);
  assert.equal(db.enforcementStats!.oracleFlaggedCount, 0n);
});

t("Execution from an unknown wallet is stored without crashing", () => {
  const e = { ...ev({ nonce: 1n, target: "0xT", value: 0n, riskScore: 0n, calldataHash: "0xH" }, { hash: "0xu", logIndex: 9 }), srcAddress: "0xUNKNOWN" };
  handleWalletExecuted(e, db);
  assert.equal(db.walletExecutions!.get("0xu-9")!.wallet, "0xunknown");
});

console.log(`ENFORCEMENT: ${passed} / 7 tests passed.`);
if (passed !== 7) process.exit(1);
