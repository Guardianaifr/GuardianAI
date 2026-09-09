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

export interface MockDbStore {
  agentActions: Map<string, AgentActionEntity>;
  threatRecords: Map<string, ThreatRecordEntity>;
  passportRecords: Map<string, PassportRecordEntity>;
  cortexCommitments: Map<string, CortexCommitmentEntity>;
  contractRiskRecords: Map<string, ContractRiskRecordEntity>;
  globalStats?: GlobalSecurityStatsEntity;
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

// ── Optional Envio Framework Registration ───────────────────────────────────
try {
  const envioGenerated = require("generated");
  if (envioGenerated && envioGenerated.GuardianPolicyGuard) {
    const {
      GuardianPolicyGuard,
      GuardianThreatFeedRegistry,
      GuardianPassportSBT,
      GuardianCortexAnchor,
      GuardianRiskAttestation,
    } = envioGenerated;

    GuardianPolicyGuard.ActionExecutedWithAttestation.handler(async ({ event, context }: any) => {
      const entityId = `${event.transaction.hash}-${event.logIndex}`;
      context.AgentAction.set({
        id: entityId,
        agentId: event.params.agentId,
        target: event.params.target,
        riskScore: Number(event.params.riskScore),
        nonce: BigInt(event.params.nonce),
        timestamp: BigInt(event.block.timestamp),
        txHash: event.transaction.hash,
      });

      let stats = await context.GlobalSecurityStats.get("global");
      if (!stats) {
        stats = {
          id: "global",
          totalActionsExecuted: 0n,
          totalThreatsRegistered: 0n,
          activeThreatCount: 0n,
          totalPassportsTracked: 0n,
          totalCortexRootsAnchored: 0n,
          lastUpdated: 0n,
        };
      }
      stats.totalActionsExecuted += 1n;
      stats.lastUpdated = BigInt(event.block.timestamp);
      context.GlobalSecurityStats.set(stats);
    });

    GuardianThreatFeedRegistry.AddressAdded.handler(async ({ event, context }: any) => {
      const entityId = event.params.malicious.toLowerCase();
      context.ThreatRecord.set({
        id: entityId,
        target: event.params.malicious,
        isStringAddress: false,
        reason: event.params.reason,
        active: true,
        addedBy: event.transaction.from,
        addedAt: BigInt(event.block.timestamp),
      });

      let stats = await context.GlobalSecurityStats.get("global");
      if (stats) {
        stats.totalThreatsRegistered += 1n;
        stats.activeThreatCount += 1n;
        stats.lastUpdated = BigInt(event.block.timestamp);
        context.GlobalSecurityStats.set(stats);
      }
    });

    GuardianThreatFeedRegistry.AddressRemoved.handler(async ({ event, context }: any) => {
      const entityId = event.params.malicious.toLowerCase();
      const existing = await context.ThreatRecord.get(entityId);
      if (existing) {
        context.ThreatRecord.set({
          ...existing,
          active: false,
          removedAt: BigInt(event.block.timestamp),
        });
      }
      let stats = await context.GlobalSecurityStats.get("global");
      if (stats && stats.activeThreatCount > 0n) {
        stats.activeThreatCount -= 1n;
        stats.lastUpdated = BigInt(event.block.timestamp);
        context.GlobalSecurityStats.set(stats);
      }
    });

    GuardianPassportSBT.ScoreUpdated.handler(async ({ event, context }: any) => {
      const entityId = event.params.tokenId.toString();
      const tierNum = Number(event.params.newTier);
      context.PassportRecord.set({
        id: entityId,
        tokenId: BigInt(event.params.tokenId),
        agentHash: event.params.agentHash,
        score: BigInt(event.params.newScore),
        tier: mapTier(tierNum),
        tierNumber: tierNum,
        isRevoked: false,
        updatedAt: BigInt(event.block.timestamp),
      });
    });

    GuardianPassportSBT.PassportRevoked.handler(async ({ event, context }: any) => {
      const entityId = event.params.tokenId.toString();
      const existing = await context.PassportRecord.get(entityId);
      if (existing) {
        context.PassportRecord.set({
          ...existing,
          isRevoked: true,
          revokedAt: BigInt(event.params.revokedAt),
        });
      }
    });

    GuardianCortexAnchor.RootCommitted.handler(async ({ event, context }: any) => {
      const entityId = `${event.transaction.hash}-${event.logIndex}`;
      context.CortexCommitment.set({
        id: entityId,
        merkleRoot: event.params.merkleRoot,
        agentHash: event.params.agentHash,
        eventCount: BigInt(event.params.eventCount),
        periodStart: BigInt(event.params.periodStart),
        periodEnd: BigInt(event.params.periodEnd),
        commitmentIndex: BigInt(event.params.commitmentIndex),
        committedBy: event.transaction.from,
        timestamp: BigInt(event.block.timestamp),
      });

      let stats = await context.GlobalSecurityStats.get("global");
      if (stats) {
        stats.totalCortexRootsAnchored += 1n;
        stats.lastUpdated = BigInt(event.block.timestamp);
        context.GlobalSecurityStats.set(stats);
      }
    });

    GuardianRiskAttestation.RiskAttested.handler(async ({ event, context }: any) => {
      const entityId = `${event.params.contractAddress.toLowerCase()}-${event.params.chain}`;
      context.ContractRiskRecord.set({
        id: entityId,
        contractAddress: event.params.contractAddress,
        chain: event.params.chain,
        score: Number(event.params.score),
        grade: event.params.grade,
        signalsHash: event.params.signalsHash,
        updatedAt: BigInt(event.block.timestamp),
      });
    });

    GuardianRiskAttestation.AttestationUpdated.handler(async ({ event, context }: any) => {
      const entityId = `${event.params.contractAddress.toLowerCase()}-${event.params.chain}`;
      context.ContractRiskRecord.set({
        id: entityId,
        contractAddress: event.params.contractAddress,
        chain: event.params.chain,
        score: Number(event.params.score),
        grade: event.params.grade,
        signalsHash: event.params.signalsHash,
        updatedAt: BigInt(event.block.timestamp),
      });
    });
  }
} catch {
  // Running in standalone testing or non-Envio context
}