"use strict";
/**
 * GuardianAI Envio HyperIndex Event Handlers for Monad Testnet (Chain ID 10143).
 *
 * Implements real-time indexing of agent policy executions, threat registries,
 * passport trust scores, cortex commitments, and contract risk attestations.
 */
Object.defineProperty(exports, "__esModule", { value: true });
exports.createInMemoryDb = createInMemoryDb;
exports.mapTier = mapTier;
exports.handleActionExecutedWithAttestation = handleActionExecutedWithAttestation;
exports.handleAddressAdded = handleAddressAdded;
exports.handleAddressRemoved = handleAddressRemoved;
exports.handleStringAddressAdded = handleStringAddressAdded;
exports.handleStringAddressRemoved = handleStringAddressRemoved;
exports.handleScoreUpdated = handleScoreUpdated;
exports.handlePassportRevoked = handlePassportRevoked;
exports.handleRootCommitted = handleRootCommitted;
exports.handleRiskAttested = handleRiskAttested;
exports.handleAttestationUpdated = handleAttestationUpdated;
function createInMemoryDb() {
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
function mapTier(tierNumber) {
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
function handleActionExecutedWithAttestation(event, db) {
    const entityId = `${event.transaction.hash}-${event.logIndex}`;
    const action = {
        id: entityId,
        agentId: event.params.agentId,
        target: event.params.target,
        riskScore: Number(event.params.riskScore),
        nonce: BigInt(event.params.nonce),
        timestamp: BigInt(event.block.timestamp),
        txHash: event.transaction.hash,
    };
    db.agentActions.set(entityId, action);
    if (db.globalStats) {
        db.globalStats.totalActionsExecuted += 1n;
        db.globalStats.lastUpdated = BigInt(event.block.timestamp);
    }
    return action;
}
function handleAddressAdded(event, db) {
    const target = event.params.malicious;
    const entityId = target.toLowerCase();
    const threat = {
        id: entityId,
        target: target,
        isStringAddress: false,
        reason: event.params.reason,
        active: true,
        addedBy: event.transaction.from,
        addedAt: BigInt(event.block.timestamp),
    };
    db.threatRecords.set(entityId, threat);
    if (db.globalStats) {
        db.globalStats.totalThreatsRegistered += 1n;
        db.globalStats.activeThreatCount += 1n;
        db.globalStats.lastUpdated = BigInt(event.block.timestamp);
    }
    return threat;
}
function handleAddressRemoved(event, db) {
    const entityId = event.params.malicious.toLowerCase();
    const existing = db.threatRecords.get(entityId);
    if (existing) {
        existing.active = false;
        existing.removedAt = BigInt(event.block.timestamp);
    }
    if (db.globalStats && db.globalStats.activeThreatCount > 0n) {
        db.globalStats.activeThreatCount -= 1n;
        db.globalStats.lastUpdated = BigInt(event.block.timestamp);
    }
    return existing;
}
function handleStringAddressAdded(event, db) {
    const target = event.params.malicious;
    const entityId = target;
    const threat = {
        id: entityId,
        target: target,
        isStringAddress: true,
        reason: event.params.reason,
        active: true,
        addedBy: event.transaction.from,
        addedAt: BigInt(event.block.timestamp),
    };
    db.threatRecords.set(entityId, threat);
    if (db.globalStats) {
        db.globalStats.totalThreatsRegistered += 1n;
        db.globalStats.activeThreatCount += 1n;
        db.globalStats.lastUpdated = BigInt(event.block.timestamp);
    }
    return threat;
}
function handleStringAddressRemoved(event, db) {
    const entityId = event.params.malicious;
    const existing = db.threatRecords.get(entityId);
    if (existing) {
        existing.active = false;
        existing.removedAt = BigInt(event.block.timestamp);
    }
    if (db.globalStats && db.globalStats.activeThreatCount > 0n) {
        db.globalStats.activeThreatCount -= 1n;
        db.globalStats.lastUpdated = BigInt(event.block.timestamp);
    }
    return existing;
}
function handleScoreUpdated(event, db) {
    const entityId = event.params.tokenId.toString();
    const tierNum = Number(event.params.newTier);
    const isNew = !db.passportRecords.has(entityId);
    const passport = {
        id: entityId,
        tokenId: BigInt(event.params.tokenId),
        agentHash: event.params.agentHash,
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
function handlePassportRevoked(event, db) {
    const entityId = event.params.tokenId.toString();
    const existing = db.passportRecords.get(entityId);
    if (existing) {
        existing.isRevoked = true;
        existing.revokedAt = BigInt(event.params.revokedAt);
    }
    return existing;
}
function handleRootCommitted(event, db) {
    const entityId = `${event.transaction.hash}-${event.logIndex}`;
    const commitment = {
        id: entityId,
        merkleRoot: event.params.merkleRoot,
        agentHash: event.params.agentHash,
        eventCount: BigInt(event.params.eventCount),
        periodStart: BigInt(event.params.periodStart),
        periodEnd: BigInt(event.params.periodEnd),
        commitmentIndex: BigInt(event.params.commitmentIndex),
        committedBy: event.transaction.from,
        timestamp: BigInt(event.block.timestamp),
    };
    db.cortexCommitments.set(entityId, commitment);
    if (db.globalStats) {
        db.globalStats.totalCortexRootsAnchored += 1n;
        db.globalStats.lastUpdated = BigInt(event.block.timestamp);
    }
    return commitment;
}
function handleRiskAttested(event, db) {
    const entityId = `${event.params.contractAddress.toLowerCase()}-${event.params.chain}`;
    const risk = {
        id: entityId,
        contractAddress: event.params.contractAddress,
        chain: event.params.chain,
        score: Number(event.params.score),
        grade: event.params.grade,
        signalsHash: event.params.signalsHash,
        updatedAt: BigInt(event.block.timestamp),
    };
    db.contractRiskRecords.set(entityId, risk);
    return risk;
}
function handleAttestationUpdated(event, db) {
    return handleRiskAttested(event, db);
}
// ── Optional Envio Framework Registration ───────────────────────────────────
try {
    const envioGenerated = require("generated");
    if (envioGenerated && envioGenerated.GuardianPolicyGuard) {
        const { GuardianPolicyGuard, GuardianThreatFeedRegistry, GuardianPassportSBT, GuardianCortexAnchor, GuardianRiskAttestation, } = envioGenerated;
        GuardianPolicyGuard.ActionExecutedWithAttestation.handler(async ({ event, context }) => {
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
        GuardianThreatFeedRegistry.AddressAdded.handler(async ({ event, context }) => {
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
        GuardianThreatFeedRegistry.AddressRemoved.handler(async ({ event, context }) => {
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
        GuardianPassportSBT.ScoreUpdated.handler(async ({ event, context }) => {
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
        GuardianPassportSBT.PassportRevoked.handler(async ({ event, context }) => {
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
        GuardianCortexAnchor.RootCommitted.handler(async ({ event, context }) => {
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
        GuardianRiskAttestation.RiskAttested.handler(async ({ event, context }) => {
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
        GuardianRiskAttestation.AttestationUpdated.handler(async ({ event, context }) => {
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
}
catch {
    // Running in standalone testing or non-Envio context
}
