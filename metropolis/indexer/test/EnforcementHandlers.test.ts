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

const WALLET = "0x356EfbC397B104F90795E89F0b755aa5AE4967DD";
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

if (passed !== 7) process.exit(1);

// ── Passport issuance (Transfer mint + on-chain read) ─────────────────────────
import { handlePassportMinted, handlePassportRevoked } from "../src/EventHandlers.ts";
{
  const pdb = createInMemoryDb();
  const mint = { params: { from: "0x0000000000000000000000000000000000000000", to: "0xO", tokenId: 11n }, block: { timestamp: 2000, number: 5 }, transaction: { hash: "0xm", from: "0xf" }, logIndex: 2, srcAddress: "0xsbt" };
  const onchain = { agentHash: "0xb085", tier: 0, score: 1000n };
  t("Mint creates a passport record from the on-chain read", () => {
    const p = handlePassportMinted(mint, onchain, pdb);
    assert.equal(p.id, "11");
    assert.equal(p.agentHash, "0xb085");
    assert.equal(p.score, 1000n);
    assert.equal(p.tier, "UNVERIFIED");
    assert.equal(p.isRevoked, false);
    assert.equal(pdb.globalStats!.totalPassportsTracked, 1n);
  });
  t("Replayed mint is idempotent and does not double count", () => {
    handlePassportMinted(mint, { ...onchain, score: 1n }, pdb);
    assert.equal(pdb.passportRecords.get("11")!.score, 1000n);
    assert.equal(pdb.globalStats!.totalPassportsTracked, 1n);
  });
  t("Revoke marks an indexed passport revoked", () => {
    const rev = { params: { tokenId: 11n, agentHash: "0xb085", revokedAt: 3000n }, block: { timestamp: 3000, number: 9 }, transaction: { hash: "0xr", from: "0xf" }, logIndex: 1, srcAddress: "0xsbt" };
    const r = handlePassportRevoked(rev, pdb)!;
    assert.equal(r.isRevoked, true);
    assert.equal(r.revokedAt, 3000n);
  });
  t("Revoke of a passport minted before start block creates it revoked when on-chain data is given", () => {
    const rev = { params: { tokenId: 4n, agentHash: "0xaaaa", revokedAt: 4000n }, block: { timestamp: 4000, number: 10 }, transaction: { hash: "0xr2", from: "0xf" }, logIndex: 1, srcAddress: "0xsbt" };
    const r = handlePassportRevoked(rev, pdb, { agentHash: "0xaaaa", tier: 3, score: 9400n })!;
    assert.equal(r.id, "4");
    assert.equal(r.isRevoked, true);
    assert.equal(r.tier, "GOLD");
    assert.equal(pdb.globalStats!.totalPassportsTracked, 2n);
  });
  t("Revoke without a record or on-chain data stays a safe no-op", () => {
    const rev = { params: { tokenId: 99n, agentHash: "0x0", revokedAt: 1n }, block: { timestamp: 1, number: 1 }, transaction: { hash: "0xr3", from: "0xf" }, logIndex: 1, srcAddress: "0xsbt" };
    assert.equal(handlePassportRevoked(rev, pdb), undefined);
  });
}
console.log(`ENFORCEMENT: ${passed} / 12 tests passed.`);
