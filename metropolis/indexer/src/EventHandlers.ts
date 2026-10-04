/**
 * GuardianAI Envio HyperIndex Event Handlers for Monad Testnet (Chain ID 10143).
 *
 * Implements real-time indexing of agent policy executions, threat registries,
 * passport trust scores, cortex commitments, and contract risk attestations.
 */

export interface AgentActionEntity {
  id: string;
  agentId: string;
  target: string;
  riskScore: number;
  nonce: bigint;
  timestamp: bigint;
  txHash: string;
}

export interface ThreatRecordEntity {
  id: string;
  target: string;
  isStringAddress: boolean;
  reason: string;
  active: boolean;
  addedBy: string;
  addedAt: bigint;
  removedAt?: bigint;
}

export interface PassportRecordEntity {
  id: string;
  tokenId: bigint;
  agentHash: string;
  score: bigint;
  tier: string;
  tierNumber: number;
  isRevoked: boolean;
  revokedAt?: bigint;
  updatedAt: bigint;
}

export interface CortexCommitmentEntity {
  id: string;
  merkleRoot: string;
  agentHash: string;
  eventCount: bigint;
  periodStart: bigint;
  periodEnd: bigint;
  commitmentIndex: bigint;
  committedBy: string;
  timestamp: bigint;
}

export interface ContractRiskRecordEntity {
  id: string;
  contractAddress: string;
  chain: string;
  score: number;
  grade: string;
  signalsHash: string;
  updatedAt: bigint;
}

export interface GlobalSecurityStatsEntity {
  id: string;
  totalActionsExecuted: bigint;
  totalThreatsRegistered: bigint;
  activeThreatCount: bigint;
  totalPassportsTracked: bigint;
  totalCortexRootsAnchored: bigint;
  lastUpdated: bigint;
}

export interface AgentWalletEntity {
  id: string;
  agentId: string;
  owner: string;
  operator: string;
  threatOracle?: string;
  paused: boolean;
  executedCount: bigint;
  ownerExecutedCount: bigint;
  createdAt: bigint;
  createdTx: string;
}

export interface AgentWalletExecutionEntity {
  id: string;
  wallet: string;
  byOwner: boolean;
  nonce?: bigint;
  target: string;
  value: bigint;
  riskScore?: number;
  calldataHash: string;
  timestamp: bigint;
  txHash: string;
}

export interface ThreatOracleReportEntity {
  id: string;
  asOf: bigint;
  blocked: bigint;
  intercepted: bigint;
  passed: bigint;
  feedDigest: string;
  changes: bigint;
  timestamp: bigint;
  txHash: string;
}

export interface ThreatOracleFlagEntity {
  id: string;
  flagged: boolean;
  updatedAt: bigint;
  txHash: string;
}

export interface EnforcementStatsEntity {
  id: string;
  agentWallets: bigint;
  guardianApprovedExecutions: bigint;
  ownerExecutions: bigint;
  oracleReports: bigint;
  oracleFlaggedCount: bigint;
  lastUpdated: bigint;
}

export interface MockDbStore {
  agentActions: Map<string, AgentActionEntity>;
  threatRecords: Map<string, ThreatRecordEntity>;
  passportRecords: Map<string, PassportRecordEntity>;
  cortexCommitments: Map<string, CortexCommitmentEntity>;
  contractRiskRecords: Map<string, ContractRiskRecordEntity>;
  globalStats?: GlobalSecurityStatsEntity;
  agentWallets?: Map<string, AgentWalletEntity>;
  walletExecutions?: Map<string, AgentWalletExecutionEntity>;
  oracleReports?: Map<string, ThreatOracleReportEntity>;
  oracleFlags?: Map<string, ThreatOracleFlagEntity>;
  enforcementStats?: EnforcementStatsEntity;
}


export function cleanString(val: any, maxLength: number = 1024): string {
  if (typeof val !== 'string') return '';
  return val.replace(/\0/g, '').slice(0, maxLength);
}

export function cleanEntityId(val: any): string {
  if (typeof val !== 'string') return '';
  return val.replace(/\0/g, '').slice(0, 255);
}

export function createInMemoryDb(): MockDbStore {
  return {
    agentActions: new Map(),
    threatRecords: new Map(),
    passportRecords: new Map(),
    cortexCommitments: new Map(),
    contractRiskRecords: new Map(),
    agentWallets: new Map(),
    walletExecutions: new Map(),
    oracleReports: new Map(),
    oracleFlags: new Map(),
    enforcementStats: emptyEnforcementStats(),
    globalStats: {
      id: "global",
      totalActionsExecuted: 0n,
      totalThreatsRegistered: 0n,
      activeThreatCount: 0n,
      totalPassportsTracked: 0n,
      totalCortexRootsAnchored: 0n,
      lastUpdated: 0n,
    },
  };
}

export function mapTier(tierNumber: number): string {
  switch (tierNumber) {
    case 0:
      return "UNVERIFIED";
    case 1:
      return "BRONZE";
    case 2:
      return "SILVER";
    case 3:
      return "GOLD";
    case 4:
      return "DIAMOND";
    default:
      return "UNKNOWN";
  }
}

// ── Event Processing Core Handlers ───────────────────────────────────────────

export function handleActionExecutedWithAttestation(event: any, db: MockDbStore) {
  const entityId = cleanEntityId(`${event.transaction.hash}-${event.logIndex}`);
  const action: AgentActionEntity = {
    id: entityId,
    agentId: cleanString(event.params.agentId, 255),
    target: cleanString(event.params.target, 255),
    riskScore: Number(event.params.riskScore),
    nonce: BigInt(event.params.nonce),
    timestamp: BigInt(event.block.timestamp),
    txHash: event.transaction.hash,
  };
  const isNew = !db.agentActions.has(entityId);
  db.agentActions.set(entityId, action);

  if (db.globalStats) {
    if (isNew) db.globalStats.totalActionsExecuted += 1n;
    db.globalStats.lastUpdated = BigInt(event.block.timestamp);
  }
  return action;
}

export function handleAddressAdded(event: any, db: MockDbStore) {
  const target = cleanString(event.params.malicious, 255);
  const entityId = target.toLowerCase();
  const reason = cleanString(event.params.reason, 1024);
  const existing = db.threatRecords.get(entityId);
  const wasActive = existing?.active ?? false;
  const isNew = !existing;

  const threat: ThreatRecordEntity = {
    id: entityId,
    target: target,
    isStringAddress: false,
    reason: reason,
    active: true,
    addedBy: event.transaction.from,
    addedAt: BigInt(event.block.timestamp),
  };
  db.threatRecords.set(entityId, threat);

  if (db.globalStats) {
    if (isNew) db.globalStats.totalThreatsRegistered += 1n;
    if (!wasActive) db.globalStats.activeThreatCount += 1n;
    db.globalStats.lastUpdated = BigInt(event.block.timestamp);
  }
  return threat;
}

export function handleAddressRemoved(event: any, db: MockDbStore) {
  const target = cleanString(event.params.malicious, 255);
  const entityId = target.toLowerCase();
  const existing = db.threatRecords.get(entityId);
  let wasActive = false;
  if (existing && existing.active) {
    existing.active = false;
    existing.removedAt = BigInt(event.block.timestamp);
    wasActive = true;
  }

  if (db.globalStats && wasActive && db.globalStats.activeThreatCount > 0n) {
    db.globalStats.activeThreatCount -= 1n;
    db.globalStats.lastUpdated = BigInt(event.block.timestamp);
  }
  return existing;
}

export function handleStringAddressAdded(event: any, db: MockDbStore) {
  const target = cleanString(event.params.malicious, 1024);
  const entityId = cleanEntityId(target);
  const reason = cleanString(event.params.reason, 1024);
  const existing = db.threatRecords.get(entityId);
  const wasActive = existing?.active ?? false;
  const isNew = !existing;

  const threat: ThreatRecordEntity = {
    id: entityId,
    target: target,
    isStringAddress: true,
    reason: reason,
    active: true,
    addedBy: event.transaction.from,
    addedAt: BigInt(event.block.timestamp),
  };
  db.threatRecords.set(entityId, threat);

  if (db.globalStats) {
    if (isNew) db.globalStats.totalThreatsRegistered += 1n;
    if (!wasActive) db.globalStats.activeThreatCount += 1n;
    db.globalStats.lastUpdated = BigInt(event.block.timestamp);
  }
  return threat;
}

export function handleStringAddressRemoved(event: any, db: MockDbStore) {
  const entityId = cleanEntityId(cleanString(event.params.malicious, 1024));
  const existing = db.threatRecords.get(entityId);
  let wasActive = false;
  if (existing && existing.active) {
    existing.active = false;
    existing.removedAt = BigInt(event.block.timestamp);
    wasActive = true;
  }

  if (db.globalStats && wasActive && db.globalStats.activeThreatCount > 0n) {
    db.globalStats.activeThreatCount -= 1n;
    db.globalStats.lastUpdated = BigInt(event.block.timestamp);
  }
  return existing;
}

export function handleScoreUpdated(event: any, db: MockDbStore) {
  const entityId = cleanEntityId(event.params.tokenId.toString());
  const tierNum = Number(event.params.newTier);
  const isNew = !db.passportRecords.has(entityId);

  const passport: PassportRecordEntity = {
    id: entityId,
    tokenId: BigInt(event.params.tokenId),
    agentHash: cleanString(event.params.agentHash, 255),
    score: BigInt(event.params.newScore),
    tier: mapTier(tierNum),
    tierNumber: tierNum,
    isRevoked: false,
    updatedAt: BigInt(event.block.timestamp),
  };
  db.passportRecords.set(entityId, passport);

  if (db.globalStats) {
    if (isNew) {
      db.globalStats.totalPassportsTracked += 1n;
    }
    db.globalStats.lastUpdated = BigInt(event.block.timestamp);
  }
  return passport;
}

export function handlePassportRevoked(event: any, db: MockDbStore) {
  const entityId = cleanEntityId(event.params.tokenId.toString());
  const existing = db.passportRecords.get(entityId);
  if (existing) {
    existing.isRevoked = true;
    existing.revokedAt = BigInt(event.params.revokedAt);
  }
  return existing;
}

export function handleRootCommitted(event: any, db: MockDbStore) {
  const entityId = cleanEntityId(`${event.transaction.hash}-${event.logIndex}`);
  const isNew = !db.cortexCommitments.has(entityId);
  const commitment: CortexCommitmentEntity = {
    id: entityId,
    merkleRoot: cleanString(event.params.merkleRoot, 255),
    agentHash: cleanString(event.params.agentHash, 255),
    eventCount: BigInt(event.params.eventCount),
    periodStart: BigInt(event.params.periodStart),
    periodEnd: BigInt(event.params.periodEnd),
    commitmentIndex: BigInt(event.params.commitmentIndex),
    committedBy: event.transaction.from,
    timestamp: BigInt(event.block.timestamp),
  };
  db.cortexCommitments.set(entityId, commitment);

  if (db.globalStats) {
    if (isNew) db.globalStats.totalCortexRootsAnchored += 1n;
    db.globalStats.lastUpdated = BigInt(event.block.timestamp);
  }
  return commitment;
}

export function handleRiskAttested(event: any, db: MockDbStore) {
  const entityId = cleanEntityId(`${event.params.contractAddress.toLowerCase()}-${event.params.chain}`);
  const risk: ContractRiskRecordEntity = {
    id: entityId,
    contractAddress: cleanString(event.params.contractAddress, 255),
    chain: cleanString(event.params.chain, 255),
    score: Number(event.params.score),
    grade: cleanString(event.params.grade, 255),
    signalsHash: cleanString(event.params.signalsHash, 1024),
    updatedAt: BigInt(event.block.timestamp),
  };
  db.contractRiskRecords.set(entityId, risk);
  return risk;
}

export function handleAttestationUpdated(event: any, db: MockDbStore) {
  return handleRiskAttested(event, db);
}

// ── On-chain enforcement layer (GuardianAgentWallet + Chainlink CRE threat oracle) ──
// Pure functions over a small store interface so the same logic runs in Envio and in unit tests.

export function emptyEnforcementStats(): EnforcementStatsEntity {
  return {
    id: "global",
    agentWallets: 0n,
    guardianApprovedExecutions: 0n,
    ownerExecutions: 0n,
    oracleReports: 0n,
    oracleFlaggedCount: 0n,
    lastUpdated: 0n,
  };
}

function ensureStores(db: MockDbStore) {
  db.agentWallets ??= new Map();
  db.walletExecutions ??= new Map();
  db.oracleReports ??= new Map();
  db.oracleFlags ??= new Map();
  db.enforcementStats ??= emptyEnforcementStats();
  return db as Required<MockDbStore>;
}

const lc = (v: any) => cleanString(String(v ?? ""), 255).toLowerCase();

export function handleWalletCreated(event: any, db: MockDbStore) {
  const s = ensureStores(db);
  const id = lc(event.params.wallet);
  const isNew = !s.agentWallets.has(id);
  const wallet: AgentWalletEntity = {
    id,
    agentId: lc(event.params.agentId),
    owner: lc(event.params.owner),
    operator: lc(event.params.operator),
    threatOracle: undefined,
    paused: false,
    executedCount: s.agentWallets.get(id)?.executedCount ?? 0n,
    ownerExecutedCount: s.agentWallets.get(id)?.ownerExecutedCount ?? 0n,
    createdAt: BigInt(event.block.timestamp),
    createdTx: event.transaction.hash,
  };
  s.agentWallets.set(id, wallet);
  if (isNew) s.enforcementStats.agentWallets += 1n;
  s.enforcementStats.lastUpdated = BigInt(event.block.timestamp);
  return wallet;
}

function recordExecution(event: any, db: MockDbStore, byOwner: boolean) {
  const s = ensureStores(db);
  const id = cleanEntityId(`${event.transaction.hash}-${event.logIndex}`);
  const walletId = lc(event.srcAddress);
  const isNew = !s.walletExecutions.has(id);
  const exec: AgentWalletExecutionEntity = {
    id,
    wallet: walletId,
    byOwner,
    nonce: byOwner ? undefined : BigInt(event.params.nonce),
    target: lc(event.params.target),
    value: BigInt(event.params.value),
    riskScore: byOwner ? undefined : Number(event.params.riskScore),
    calldataHash: lc(event.params.calldataHash),
    timestamp: BigInt(event.block.timestamp),
    txHash: event.transaction.hash,
  };
  s.walletExecutions.set(id, exec);
  if (isNew) {
    const w = s.agentWallets.get(walletId);
    if (w) {
      if (byOwner) w.ownerExecutedCount += 1n; else w.executedCount += 1n;
    }
    if (byOwner) s.enforcementStats.ownerExecutions += 1n; else s.enforcementStats.guardianApprovedExecutions += 1n;
  }
  s.enforcementStats.lastUpdated = BigInt(event.block.timestamp);
  return exec;
}

export function handleWalletExecuted(event: any, db: MockDbStore) {
  return recordExecution(event, db, false);
}

export function handleWalletOwnerExecuted(event: any, db: MockDbStore) {
  return recordExecution(event, db, true);
}

export function handleWalletPaused(event: any, db: MockDbStore, paused: boolean) {
  const s = ensureStores(db);
  const w = s.agentWallets.get(lc(event.srcAddress));
  if (w) w.paused = paused;
  return w;
}

export function handleWalletThreatOracleUpdated(event: any, db: MockDbStore) {
  const s = ensureStores(db);
  const w = s.agentWallets.get(lc(event.srcAddress));
  if (w) w.threatOracle = lc(event.params.newOracle);
  return w;
}

export function handleThreatReportAccepted(event: any, db: MockDbStore) {
  const s = ensureStores(db);
  const id = cleanEntityId(`${event.transaction.hash}-${event.logIndex}`);
  const isNew = !s.oracleReports.has(id);
  const report: ThreatOracleReportEntity = {
    id,
    asOf: BigInt(event.params.asOf),
    blocked: BigInt(event.params.blocked),
    intercepted: BigInt(event.params.intercepted),
    passed: BigInt(event.params.passed),
    feedDigest: lc(event.params.feedDigest),
    changes: BigInt(event.params.changes),
    timestamp: BigInt(event.block.timestamp),
    txHash: event.transaction.hash,
  };
  s.oracleReports.set(id, report);
  if (isNew) s.enforcementStats.oracleReports += 1n;
  s.enforcementStats.lastUpdated = BigInt(event.block.timestamp);
  return report;
}

export function handleAddressFlagUpdated(event: any, db: MockDbStore) {
  const s = ensureStores(db);
  const id = lc(event.params.account);
  const was = s.oracleFlags.get(id)?.flagged ?? false;
  const now = Boolean(event.params.flagged);
  const flag: ThreatOracleFlagEntity = { id, flagged: now, updatedAt: BigInt(event.block.timestamp), txHash: event.transaction.hash };
  s.oracleFlags.set(id, flag);
  if (now && !was) s.enforcementStats.oracleFlaggedCount += 1n;
  if (!now && was && s.enforcementStats.oracleFlaggedCount > 0n) s.enforcementStats.oracleFlaggedCount -= 1n;
  s.enforcementStats.lastUpdated = BigInt(event.block.timestamp);
  return flag;
}
