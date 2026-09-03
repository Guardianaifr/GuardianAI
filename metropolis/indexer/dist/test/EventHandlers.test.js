"use strict";
var __importDefault = (this && this.__importDefault) || function (mod) {
    return (mod && mod.__esModule) ? mod : { "default": mod };
};
Object.defineProperty(exports, "__esModule", { value: true });
const assert_1 = __importDefault(require("assert"));
const EventHandlers_1 = require("../src/EventHandlers");
console.log("================================================================");
console.log("Running Envio HyperIndex Standalone Unit Test Suite");
console.log("================================================================");
function runTestSuite() {
    const db = (0, EventHandlers_1.createInMemoryDb)();
    let passed = 0;
    // Test 1: ActionExecutedWithAttestation
    {
        console.log("[Test 1] Testing GuardianPolicyGuard.ActionExecutedWithAttestation...");
        const mockEvent = {
            transaction: { hash: "0xabc123", from: "0xagentOwner" },
            logIndex: 0,
            block: { timestamp: 1788410000 },
            params: {
                agentId: "0x1111111111111111111111111111111111111111111111111111111111111111",
                target: "0x2222222222222222222222222222222222222222",
                riskScore: 10,
                nonce: 101,
            },
        };
        const action = (0, EventHandlers_1.handleActionExecutedWithAttestation)(mockEvent, db);
        assert_1.default.strictEqual(action.id, "0xabc123-0");
        assert_1.default.strictEqual(action.agentId, mockEvent.params.agentId);
        assert_1.default.strictEqual(action.target, mockEvent.params.target);
        assert_1.default.strictEqual(action.riskScore, 10);
        assert_1.default.strictEqual(action.nonce, 101n);
        assert_1.default.strictEqual(action.timestamp, 1788410000n);
        assert_1.default.strictEqual(db.globalStats?.totalActionsExecuted, 1n);
        console.log("  [+] Passed: AgentAction indexed with deterministic ID and stats incremented.");
        passed++;
    }
    // Test 2: Threat Lifecycle (AddressAdded & AddressRemoved)
    {
        console.log("[Test 2] Testing GuardianThreatFeedRegistry EVM Address Lifecycle...");
        const addEvent = {
            transaction: { hash: "0xdef456", from: "0xthreatReporter" },
            logIndex: 1,
            block: { timestamp: 1788410050 },
            params: {
                malicious: "0x9999999999999999999999999999999999999999",
                reason: "Drainer contract identified",
            },
        };
        const threat = (0, EventHandlers_1.handleAddressAdded)(addEvent, db);
        assert_1.default.strictEqual(threat.id, "0x9999999999999999999999999999999999999999".toLowerCase());
        assert_1.default.strictEqual(threat.active, true);
        assert_1.default.strictEqual(threat.addedBy, "0xthreatReporter");
        assert_1.default.strictEqual(db.globalStats?.totalThreatsRegistered, 1n);
        assert_1.default.strictEqual(db.globalStats?.activeThreatCount, 1n);
        // Remove threat
        const removeEvent = {
            transaction: { hash: "0xdef457", from: "0xadmin" },
            logIndex: 0,
            block: { timestamp: 1788410100 },
            params: {
                malicious: "0x9999999999999999999999999999999999999999",
            },
        };
        const removed = (0, EventHandlers_1.handleAddressRemoved)(removeEvent, db);
        assert_1.default.strictEqual(removed?.active, false);
        assert_1.default.strictEqual(removed?.removedAt, 1788410100n);
        assert_1.default.strictEqual(db.globalStats?.activeThreatCount, 0n);
        console.log("  [+] Passed: Threat added and removed with active flag toggle and stats balance.");
        passed++;
    }
    // Test 3: String Address Threat Lifecycle
    {
        console.log("[Test 3] Testing Non-EVM String Address Threat Handling...");
        const addStringEvent = {
            transaction: { hash: "0xstr001", from: "0xstringReporter" },
            logIndex: 2,
            block: { timestamp: 1788410150 },
            params: {
                malicious: "solana:adversary_pubkey_12345",
                reason: "Cross-chain malicious agent",
            },
        };
        const strThreat = (0, EventHandlers_1.handleStringAddressAdded)(addStringEvent, db);
        assert_1.default.strictEqual(strThreat.isStringAddress, true);
        assert_1.default.strictEqual(strThreat.active, true);
        assert_1.default.strictEqual(strThreat.id, "solana:adversary_pubkey_12345");
        assert_1.default.strictEqual(db.globalStats?.activeThreatCount, 1n);
        const removeStringEvent = {
            transaction: { hash: "0xstr002", from: "0xadmin" },
            logIndex: 0,
            block: { timestamp: 1788410200 },
            params: {
                malicious: "solana:adversary_pubkey_12345",
            },
        };
        const strRemoved = (0, EventHandlers_1.handleStringAddressRemoved)(removeStringEvent, db);
        assert_1.default.strictEqual(strRemoved?.active, false);
        assert_1.default.strictEqual(db.globalStats?.activeThreatCount, 0n);
        console.log("  [+] Passed: Non-EVM string threat lifecycle fully verified.");
        passed++;
    }
    // Test 4: Passport Trust Score & Revocation
    {
        console.log("[Test 4] Testing GuardianPassportSBT ScoreUpdated & Revocation...");
        const scoreEvent = {
            transaction: { hash: "0xpass01", from: "0xverifier" },
            logIndex: 3,
            block: { timestamp: 1788410250 },
            params: {
                tokenId: 42,
                agentHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
                newScore: 8850,
                newTier: 3, // GOLD
            },
        };
        const passport = (0, EventHandlers_1.handleScoreUpdated)(scoreEvent, db);
        assert_1.default.strictEqual(passport.id, "42");
        assert_1.default.strictEqual(passport.score, 8850n);
        assert_1.default.strictEqual(passport.tier, "GOLD");
        assert_1.default.strictEqual(passport.tierNumber, 3);
        assert_1.default.strictEqual(passport.isRevoked, false);
        assert_1.default.strictEqual(db.globalStats?.totalPassportsTracked, 1n);
        // Revoke passport
        const revokeEvent = {
            transaction: { hash: "0xpass02", from: "0xadmin" },
            logIndex: 0,
            block: { timestamp: 1788410300 },
            params: {
                tokenId: 42,
                agentHash: "0x3333333333333333333333333333333333333333333333333333333333333333",
                revokedAt: 1788410300,
            },
        };
        const revoked = (0, EventHandlers_1.handlePassportRevoked)(revokeEvent, db);
        assert_1.default.strictEqual(revoked?.isRevoked, true);
        assert_1.default.strictEqual(revoked?.revokedAt, 1788410300n);
        console.log("  [+] Passed: Soulbound passport score updated to GOLD and successfully revoked.");
        passed++;
    }
    // Test 5: CortexAnchor 6-parameter RootCommitted
    {
        console.log("[Test 5] Testing GuardianCortexAnchor 6-Parameter RootCommitted...");
        const anchorEvent = {
            transaction: { hash: "0xcortex01", from: "0xcortexRelay" },
            logIndex: 1,
            block: { timestamp: 1788410350 },
            params: {
                merkleRoot: "0x4444444444444444444444444444444444444444444444444444444444444444",
                agentHash: "0x5555555555555555555555555555555555555555555555555555555555555555",
                eventCount: 500,
                periodStart: 1788400000,
                periodEnd: 1788410000,
                commitmentIndex: 12,
            },
        };
        const commitment = (0, EventHandlers_1.handleRootCommitted)(anchorEvent, db);
        assert_1.default.strictEqual(commitment.id, "0xcortex01-1");
        assert_1.default.strictEqual(commitment.merkleRoot, anchorEvent.params.merkleRoot);
        assert_1.default.strictEqual(commitment.agentHash, anchorEvent.params.agentHash);
        assert_1.default.strictEqual(commitment.eventCount, 500n);
        assert_1.default.strictEqual(commitment.periodStart, 1788400000n);
        assert_1.default.strictEqual(commitment.periodEnd, 1788410000n);
        assert_1.default.strictEqual(commitment.commitmentIndex, 12n);
        assert_1.default.strictEqual(commitment.committedBy, "0xcortexRelay");
        assert_1.default.strictEqual(db.globalStats?.totalCortexRootsAnchored, 1n);
        console.log("  [+] Passed: Full 6-parameter Cortex Anchor state commitment indexed accurately.");
        passed++;
    }
    // Test 6: RiskAttested & AttestationUpdated Upsert
    {
        console.log("[Test 6] Testing GuardianRiskAttestation RiskAttested & AttestationUpdated...");
        const attestEvent = {
            transaction: { hash: "0xrisk01", from: "0xauditor" },
            logIndex: 0,
            block: { timestamp: 1788410400 },
            params: {
                contractAddress: "0x6666666666666666666666666666666666666666",
                chain: "monad",
                score: 1500,
                grade: "A",
                signalsHash: "0x7777777777777777777777777777777777777777777777777777777777777777",
            },
        };
        const riskRecord = (0, EventHandlers_1.handleRiskAttested)(attestEvent, db);
        assert_1.default.strictEqual(riskRecord.id, "0x6666666666666666666666666666666666666666".toLowerCase() + "-monad");
        assert_1.default.strictEqual(riskRecord.score, 1500);
        assert_1.default.strictEqual(riskRecord.grade, "A");
        // Overwrite with update
        const updateEvent = {
            transaction: { hash: "0xrisk02", from: "0xauditor" },
            logIndex: 0,
            block: { timestamp: 1788410450 },
            params: {
                contractAddress: "0x6666666666666666666666666666666666666666",
                chain: "monad",
                score: 3000,
                grade: "B",
                signalsHash: "0x8888888888888888888888888888888888888888888888888888888888888888",
            },
        };
        const updatedRecord = (0, EventHandlers_1.handleAttestationUpdated)(updateEvent, db);
        assert_1.default.strictEqual(updatedRecord.id, riskRecord.id);
        assert_1.default.strictEqual(updatedRecord.score, 3000);
        assert_1.default.strictEqual(updatedRecord.grade, "B");
        assert_1.default.strictEqual(db.contractRiskRecords.size, 1);
        console.log("  [+] Passed: Risk attestation record created and updated with zero duplicate IDs.");
        passed++;
    }
    // Test 7: Tier Mapping Invariants
    {
        console.log("[Test 7] Testing Tier Classification Boundary Mapping...");
        assert_1.default.strictEqual((0, EventHandlers_1.mapTier)(0), "UNVERIFIED");
        assert_1.default.strictEqual((0, EventHandlers_1.mapTier)(1), "BRONZE");
        assert_1.default.strictEqual((0, EventHandlers_1.mapTier)(2), "SILVER");
        assert_1.default.strictEqual((0, EventHandlers_1.mapTier)(3), "GOLD");
        assert_1.default.strictEqual((0, EventHandlers_1.mapTier)(4), "DIAMOND");
        assert_1.default.strictEqual((0, EventHandlers_1.mapTier)(99), "UNKNOWN");
        console.log("  [+] Passed: All tier enum classifications match on-chain specification.");
        passed++;
    }
    console.log("================================================================");
    console.log(`Summary: ${passed} / 7 tests passed successfully (100% green).`);
    console.log("================================================================");
}
runTestSuite();
