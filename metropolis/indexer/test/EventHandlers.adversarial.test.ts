import assert from "assert";
import {
  createInMemoryDb,
  handleActionExecutedWithAttestation,
  handleAddressAdded,
  handleAddressRemoved,
  handleStringAddressAdded,
  handleStringAddressRemoved,
  handleScoreUpdated,
  handlePassportRevoked,
  handleRootCommitted,
  handleRiskAttested,
  handleAttestationUpdated,
  mapTier,
} from "../src/EventHandlers.ts";

console.log("================================================================");
console.log("Running Envio HyperIndex ADVERSARIAL Audit Test Suite");
console.log("================================================================");

// ── Helpers ──────────────────────────────────────────────────────────────────

const MAX_UINT256 = 2n ** 256n - 1n;
const ZERO_ADDR = "0x0000000000000000000000000000000000000000";
const ZERO_HASH = "0x0000000000000000000000000000000000000000000000000000000000000000";

function makeBaseEvent(overrides: any = {}): any {
  return {
    transaction: { hash: overrides.txHash ?? "0xadversarial", from: overrides.from ?? "0xattacker" },
    logIndex: overrides.logIndex ?? 0,
    block: { timestamp: overrides.timestamp ?? 1788500000 },
    params: overrides.params ?? {},
  };
}

function runAdversarialSuite() {
  let passed = 0;
  let failed = 0;
  const total = 30;

  function pass(msg: string) {
    console.log(`  [+] PASS: ${msg}`);
    passed++;
  }

  function fail(msg: string, err: any) {
    console.log(`  [-] FAIL: ${msg} — ${err}`);
    failed++;
  }

  // ════════════════════════════════════════════════════════════════════════════
  // CATEGORY A: Numeric Overflow & Boundary Attacks
  // ════════════════════════════════════════════════════════════════════════════

  // A1: Max uint256 riskScore → Number() loses precision but must not crash
  {
    console.log("[A1] Max uint256 riskScore — no crash, graceful precision loss...");
    try {
      const db = createInMemoryDb();
      const event = makeBaseEvent({
        txHash: "0xa1", params: {
          agentId: ZERO_HASH, target: ZERO_ADDR,
          riskScore: MAX_UINT256, nonce: 0,
        }
      });
      const action = handleActionExecutedWithAttestation(event, db);
      // Number(MAX_UINT256) is Infinity — handler must not throw
      assert.strictEqual(typeof action.riskScore, "number");
      assert.strictEqual(db.agentActions.size, 1);
      pass("Max uint256 riskScore handled without crash.");
    } catch (e) { fail("Max uint256 riskScore crashed handler", e); }
  }

  // A2: Max uint256 nonce
  {
    console.log("[A2] Max uint256 nonce — BigInt stores faithfully...");
    try {
      const db = createInMemoryDb();
      const event = makeBaseEvent({
        txHash: "0xa2", params: {
          agentId: ZERO_HASH, target: ZERO_ADDR,
          riskScore: 0, nonce: MAX_UINT256,
        }
      });
      const action = handleActionExecutedWithAttestation(event, db);
      assert.strictEqual(action.nonce, MAX_UINT256);
      pass("Max uint256 nonce stored faithfully as BigInt.");
    } catch (e) { fail("Max uint256 nonce failed", e); }
  }

  // A3: Max uint256 tokenId in passport
  {
    console.log("[A3] Max uint256 tokenId in passport ScoreUpdated...");
    try {
      const db = createInMemoryDb();
      const event = makeBaseEvent({
        txHash: "0xa3", params: {
          tokenId: MAX_UINT256, agentHash: ZERO_HASH,
          newScore: 9999, newTier: 4,
        }
      });
      const passport = handleScoreUpdated(event, db);
      assert.strictEqual(passport.tokenId, MAX_UINT256);
      assert.strictEqual(passport.id, MAX_UINT256.toString());
      pass("Max uint256 tokenId stored correctly.");
    } catch (e) { fail("Max uint256 tokenId failed", e); }
  }

  // A4: Zero values across all numeric fields
  {
    console.log("[A4] All-zero numeric fields — handler must not skip or crash...");
    try {
      const db = createInMemoryDb();
      const event = makeBaseEvent({
        txHash: "0xa4", params: {
          agentId: ZERO_HASH, target: ZERO_ADDR,
          riskScore: 0, nonce: 0,
        }
      });
      const action = handleActionExecutedWithAttestation(event, db);
      assert.strictEqual(action.riskScore, 0);
      assert.strictEqual(action.nonce, 0n);
      assert.strictEqual(action.timestamp, 1788500000n);
      pass("All-zero numeric fields handled cleanly.");
    } catch (e) { fail("All-zero numeric fields crashed", e); }
  }

  // A5: Negative tier number → must map to UNKNOWN
  {
    console.log("[A5] Negative tier number → UNKNOWN...");
    try {
      assert.strictEqual(mapTier(-1), "UNKNOWN");
      assert.strictEqual(mapTier(-999), "UNKNOWN");
      assert.strictEqual(mapTier(Number.MIN_SAFE_INTEGER), "UNKNOWN");
      pass("Negative tiers correctly map to UNKNOWN.");
    } catch (e) { fail("Negative tier mapping failed", e); }
  }

  // A6: Fractional / NaN tier numbers
  {
    console.log("[A6] Fractional and NaN tier inputs...");
    try {
      assert.strictEqual(mapTier(1.5), "UNKNOWN");
      assert.strictEqual(mapTier(NaN), "UNKNOWN");
      assert.strictEqual(mapTier(Infinity), "UNKNOWN");
      assert.strictEqual(mapTier(-Infinity), "UNKNOWN");
      pass("Fractional/NaN/Infinity tiers all map to UNKNOWN.");
    } catch (e) { fail("Fractional/NaN tier handling failed", e); }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // CATEGORY B: Malformed / Injection String Payloads
  // ════════════════════════════════════════════════════════════════════════════

  // B1: Empty string agentId
  {
    console.log("[B1] Empty string agentId — must index without crash...");
    try {
      const db = createInMemoryDb();
      const event = makeBaseEvent({
        txHash: "0xb1", params: {
          agentId: "", target: ZERO_ADDR,
          riskScore: 50, nonce: 1,
        }
      });
      const action = handleActionExecutedWithAttestation(event, db);
      assert.strictEqual(action.agentId, "");
      assert.strictEqual(db.agentActions.size, 1);
      pass("Empty string agentId indexed without crash.");
    } catch (e) { fail("Empty string agentId crashed", e); }
  }

  // B2: Null byte injection in reason field
  {
    console.log("[B2] Null byte injection in threat reason...");
    try {
      const db = createInMemoryDb();
      const event = makeBaseEvent({
        txHash: "0xb2", params: {
          malicious: "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA",
          reason: "legit\x00DROP TABLE threats;--",
        }
      });
      const threat = handleAddressAdded(event, db);
      assert.strictEqual(threat.reason.includes("\x00"), false);
      assert.strictEqual(threat.active, true);
      pass("Null byte in reason field stripped safely.");
    } catch (e) { fail("Null byte injection crashed", e); }
  }

  // B3: GraphQL special characters in string address
  {
    console.log("[B3] GraphQL/SQL injection in string address...");
    try {
      const db = createInMemoryDb();
      const maliciousAddr = '"; DROP TABLE ThreatRecord; --';
      const event = makeBaseEvent({
        txHash: "0xb3", params: {
          malicious: maliciousAddr,
          reason: "test",
        }
      });
      const threat = handleStringAddressAdded(event, db);
      assert.strictEqual(threat.target, maliciousAddr);
      assert.strictEqual(threat.id, maliciousAddr);
      assert.strictEqual(db.threatRecords.has(maliciousAddr), true);
      pass("GraphQL/SQL injection string stored safely as opaque data.");
    } catch (e) { fail("GraphQL injection string crashed", e); }
  }

  // B4: Unicode and emoji in metadata fields
  {
    console.log("[B4] Unicode/emoji in agentHash and reason...");
    try {
      const db = createInMemoryDb();
      const unicodeReason = "🔥 drainer 漢字 العربية\u200B\u200B";
      const event = makeBaseEvent({
        txHash: "0xb4", params: {
          malicious: "cosmos:🚀attacker🚀",
          reason: unicodeReason,
        }
      });
      const threat = handleStringAddressAdded(event, db);
      assert.strictEqual(threat.reason, unicodeReason);
      assert.strictEqual(threat.target, "cosmos:🚀attacker🚀");
      pass("Unicode/emoji fields stored faithfully.");
    } catch (e) { fail("Unicode/emoji handling crashed", e); }
  }

  // B5: Extremely long string address (10KB)
  {
    console.log("[B5] 10KB-long string address — no OOM or crash...");
    try {
      const db = createInMemoryDb();
      const longAddr = "A".repeat(10240);
      const event = makeBaseEvent({
        txHash: "0xb5", params: {
          malicious: longAddr,
          reason: "stress test",
        }
      });
      const threat = handleStringAddressAdded(event, db);
      assert.strictEqual(threat.target.length, 1024);
      assert.strictEqual(db.threatRecords.has(threat.id), true);
      pass("10KB string address safely truncated without OOM.");
    } catch (e) { fail("10KB string address crashed", e); }
  }

  // B6: txHash with special characters
  {
    console.log("[B6] Malformed txHash with special characters...");
    try {
      const db = createInMemoryDb();
      const event = makeBaseEvent({
        txHash: '<script>alert("xss")</script>',
        params: {
          agentId: ZERO_HASH, target: ZERO_ADDR,
          riskScore: 1, nonce: 1,
        }
      });
      const action = handleActionExecutedWithAttestation(event, db);
      assert.strictEqual(action.txHash, '<script>alert("xss")</script>');
      assert.strictEqual(action.id, '<script>alert("xss")</script>-0');
      pass("XSS-laden txHash stored as opaque string, no execution.");
    } catch (e) { fail("Malformed txHash crashed", e); }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // CATEGORY C: Duplicate / Replay / Ordering Attacks
  // ════════════════════════════════════════════════════════════════════════════

  // C1: Duplicate event with identical txHash+logIndex → must overwrite, not duplicate
  {
    console.log("[C1] Duplicate event replay — must overwrite, not create duplicates...");
    try {
      const db = createInMemoryDb();
      const event1 = makeBaseEvent({
        txHash: "0xc1", logIndex: 0, params: {
          agentId: ZERO_HASH, target: ZERO_ADDR,
          riskScore: 10, nonce: 1,
        }
      });
      const event2 = makeBaseEvent({
        txHash: "0xc1", logIndex: 0, params: {
          agentId: ZERO_HASH, target: ZERO_ADDR,
          riskScore: 99, nonce: 2,
        }
      });
      handleActionExecutedWithAttestation(event1, db);
      handleActionExecutedWithAttestation(event2, db);
      assert.strictEqual(db.agentActions.size, 1);
      const stored = db.agentActions.get("0xc1-0")!;
      assert.strictEqual(stored.riskScore, 99); // overwritten
      assert.strictEqual(db.globalStats?.totalActionsExecuted, 1n);
      pass("Duplicate event overwrites entity; stats double-count fixed.");
    } catch (e) { fail("Duplicate event replay handling failed", e); }
  }

  // C2: Remove a threat that was never added → must not underflow activeThreatCount
  {
    console.log("[C2] Remove non-existent threat — no underflow on activeThreatCount...");
    try {
      const db = createInMemoryDb();
      assert.strictEqual(db.globalStats?.activeThreatCount, 0n);
      const event = makeBaseEvent({
        txHash: "0xc2", params: {
          malicious: "0xNEVERADDED0000000000000000000000000000",
        }
      });
      const result = handleAddressRemoved(event, db);
      assert.strictEqual(result, undefined);
      assert.strictEqual(db.globalStats?.activeThreatCount, 0n); // must stay 0, not go to -1
      pass("Removing non-existent threat does not underflow counter.");
    } catch (e) { fail("Non-existent threat removal caused underflow", e); }
  }

  // C3: Revoke a passport that was never created
  {
    console.log("[C3] Revoke non-existent passport — graceful no-op...");
    try {
      const db = createInMemoryDb();
      const event = makeBaseEvent({
        txHash: "0xc3", params: {
          tokenId: 999999, agentHash: ZERO_HASH,
          revokedAt: 1788500000,
        }
      });
      const result = handlePassportRevoked(event, db);
      assert.strictEqual(result, undefined);
      assert.strictEqual(db.passportRecords.size, 0);
      pass("Revoking non-existent passport is a safe no-op.");
    } catch (e) { fail("Revoking non-existent passport crashed", e); }
  }

  // C4: Out-of-order timestamps — block timestamp goes backward
  {
    console.log("[C4] Out-of-order block timestamps (reorg simulation)...");
    try {
      const db = createInMemoryDb();
      // Event at timestamp 2000
      handleActionExecutedWithAttestation(makeBaseEvent({
        txHash: "0xc4a", timestamp: 2000, params: {
          agentId: ZERO_HASH, target: ZERO_ADDR, riskScore: 1, nonce: 1,
        }
      }), db);
      // Event at timestamp 1000 (earlier — simulating reorg)
      handleActionExecutedWithAttestation(makeBaseEvent({
        txHash: "0xc4b", timestamp: 1000, params: {
          agentId: ZERO_HASH, target: ZERO_ADDR, riskScore: 2, nonce: 2,
        }
      }), db);
      assert.strictEqual(db.agentActions.size, 2);
      // lastUpdated should reflect the most recent processed event (1000), not 2000
      // This documents that the handler does NOT enforce monotonic timestamps
      assert.strictEqual(db.globalStats?.lastUpdated, 1000n);
      pass("Out-of-order timestamps processed without crash. lastUpdated not monotonic (documented).");
    } catch (e) { fail("Out-of-order timestamps crashed", e); }
  }

  // C5: Double-remove same threat
  {
    console.log("[C5] Double-remove same threat — idempotent, no underflow...");
    try {
      const db = createInMemoryDb();
      handleAddressAdded(makeBaseEvent({
        txHash: "0xc5a", params: {
          malicious: "0xDOUBLERMV000000000000000000000000000000",
          reason: "test",
        }
      }), db);
      assert.strictEqual(db.globalStats?.activeThreatCount, 1n);
      handleAddressRemoved(makeBaseEvent({
        txHash: "0xc5b", params: {
          malicious: "0xDOUBLERMV000000000000000000000000000000",
        }
      }), db);
      assert.strictEqual(db.globalStats?.activeThreatCount, 0n);
      // Second remove — should stay at 0, not go negative
      handleAddressRemoved(makeBaseEvent({
        txHash: "0xc5c", params: {
          malicious: "0xDOUBLERMV000000000000000000000000000000",
        }
      }), db);
      assert.strictEqual(db.globalStats?.activeThreatCount, 0n);
      pass("Double-remove is idempotent, counter stays at 0.");
    } catch (e) { fail("Double-remove caused underflow", e); }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // CATEGORY D: State Corruption & Cross-Entity Isolation
  // ════════════════════════════════════════════════════════════════════════════

  // D1: Score update on same tokenId must not increment totalPassportsTracked twice
  {
    console.log("[D1] Repeated ScoreUpdated on same tokenId — no double-count...");
    try {
      const db = createInMemoryDb();
      const event1 = makeBaseEvent({
        txHash: "0xd1a", params: {
          tokenId: 42, agentHash: ZERO_HASH, newScore: 100, newTier: 1,
        }
      });
      const event2 = makeBaseEvent({
        txHash: "0xd1b", params: {
          tokenId: 42, agentHash: ZERO_HASH, newScore: 9000, newTier: 4,
        }
      });
      handleScoreUpdated(event1, db);
      handleScoreUpdated(event2, db);
      assert.strictEqual(db.passportRecords.size, 1);
      assert.strictEqual(db.globalStats?.totalPassportsTracked, 1n); // must NOT be 2
      const passport = db.passportRecords.get("42")!;
      assert.strictEqual(passport.score, 9000n);
      assert.strictEqual(passport.tier, "DIAMOND");
      pass("Repeated ScoreUpdated correctly deduplicates totalPassportsTracked.");
    } catch (e) { fail("Repeated ScoreUpdated double-counted passports", e); }
  }

  // D2: Threat add/remove must not affect passport or action stores
  {
    console.log("[D2] Cross-entity isolation — threat ops don't corrupt other stores...");
    try {
      const db = createInMemoryDb();
      handleScoreUpdated(makeBaseEvent({
        txHash: "0xd2a", params: {
          tokenId: 1, agentHash: ZERO_HASH, newScore: 500, newTier: 2,
        }
      }), db);
      handleActionExecutedWithAttestation(makeBaseEvent({
        txHash: "0xd2b", params: {
          agentId: ZERO_HASH, target: ZERO_ADDR, riskScore: 5, nonce: 1,
        }
      }), db);

      // Now add/remove a threat — other stores must be untouched
      handleAddressAdded(makeBaseEvent({
        txHash: "0xd2c", params: {
          malicious: "0xISOLATION00000000000000000000000000000",
          reason: "isolation test",
        }
      }), db);
      handleAddressRemoved(makeBaseEvent({
        txHash: "0xd2d", params: {
          malicious: "0xISOLATION00000000000000000000000000000",
        }
      }), db);

      assert.strictEqual(db.passportRecords.size, 1);
      assert.strictEqual(db.agentActions.size, 1);
      assert.strictEqual(db.passportRecords.get("1")!.score, 500n);
      assert.strictEqual(db.agentActions.get("0xd2b-0")!.riskScore, 5);
      pass("Cross-entity isolation verified — threat ops don't corrupt other stores.");
    } catch (e) { fail("Cross-entity isolation broken", e); }
  }

  // D3: globalStats undefined safety
  {
    console.log("[D3] Handlers with globalStats=undefined — no null dereference...");
    try {
      const db = createInMemoryDb();
      db.globalStats = undefined;

      handleActionExecutedWithAttestation(makeBaseEvent({
        txHash: "0xd3a", params: {
          agentId: ZERO_HASH, target: ZERO_ADDR, riskScore: 1, nonce: 1,
        }
      }), db);
      handleAddressAdded(makeBaseEvent({
        txHash: "0xd3b", params: {
          malicious: ZERO_ADDR, reason: "test",
        }
      }), db);
      handleAddressRemoved(makeBaseEvent({
        txHash: "0xd3c", params: { malicious: ZERO_ADDR }
      }), db);
      handleRootCommitted(makeBaseEvent({
        txHash: "0xd3d", params: {
          merkleRoot: ZERO_HASH, agentHash: ZERO_HASH,
          eventCount: 0, periodStart: 0, periodEnd: 0, commitmentIndex: 0,
        }
      }), db);

      assert.strictEqual(db.agentActions.size, 1);
      assert.strictEqual(db.threatRecords.size, 1);
      assert.strictEqual(db.cortexCommitments.size, 1);
      pass("All handlers survive globalStats=undefined without crash.");
    } catch (e) { fail("Null globalStats caused crash", e); }
  }

  // D4: Case sensitivity attack on EVM addresses
  {
    console.log("[D4] Case sensitivity — mixed-case EVM address collision...");
    try {
      const db = createInMemoryDb();
      const lowerAddr = "0xabcdef0000000000000000000000000000000000";
      const mixedAddr = "0xABCDEF0000000000000000000000000000000000";

      handleAddressAdded(makeBaseEvent({
        txHash: "0xd4a", params: { malicious: lowerAddr, reason: "lower" }
      }), db);
      handleAddressAdded(makeBaseEvent({
        txHash: "0xd4b", params: { malicious: mixedAddr, reason: "mixed" }
      }), db);

      // Both should normalize to the same entity ID via .toLowerCase()
      assert.strictEqual(db.threatRecords.size, 1);
      const entity = db.threatRecords.get(lowerAddr)!;
      assert.strictEqual(entity.reason, "mixed"); // second write overwrites
      pass("Mixed-case addresses correctly collapse to single entity via toLowerCase().");
    } catch (e) { fail("Case sensitivity attack created duplicate entities", e); }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // CATEGORY E: Batch Flood / Stress Tests
  // ════════════════════════════════════════════════════════════════════════════

  // E1: 1000 rapid-fire actions
  {
    console.log("[E1] Batch flood — 1000 ActionExecuted events...");
    try {
      const db = createInMemoryDb();
      for (let i = 0; i < 1000; i++) {
        handleActionExecutedWithAttestation(makeBaseEvent({
          txHash: `0xe1-${i}`, logIndex: i, params: {
            agentId: ZERO_HASH, target: ZERO_ADDR,
            riskScore: i, nonce: i,
          }
        }), db);
      }
      assert.strictEqual(db.agentActions.size, 1000);
      assert.strictEqual(db.globalStats?.totalActionsExecuted, 1000n);
      pass("1000 rapid-fire actions indexed correctly.");
    } catch (e) { fail("Batch flood of 1000 events failed", e); }
  }

  // E2: 500 threats added then all removed — counter must be exactly 0
  {
    console.log("[E2] 500 threats added then removed — counter balance...");
    try {
      const db = createInMemoryDb();
      for (let i = 0; i < 500; i++) {
        handleAddressAdded(makeBaseEvent({
          txHash: `0xe2-add-${i}`, params: {
            malicious: `0x${i.toString(16).padStart(40, '0')}`,
            reason: `threat-${i}`,
          }
        }), db);
      }
      assert.strictEqual(db.globalStats?.activeThreatCount, 500n);
      assert.strictEqual(db.globalStats?.totalThreatsRegistered, 500n);

      for (let i = 0; i < 500; i++) {
        handleAddressRemoved(makeBaseEvent({
          txHash: `0xe2-rm-${i}`, params: {
            malicious: `0x${i.toString(16).padStart(40, '0')}`,
          }
        }), db);
      }
      assert.strictEqual(db.globalStats?.activeThreatCount, 0n);
      assert.strictEqual(db.globalStats?.totalThreatsRegistered, 500n); // total never decreases
      pass("500 add/remove cycle — activeThreatCount returns to exactly 0.");
    } catch (e) { fail("500 threat add/remove cycle failed", e); }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // CATEGORY F: Risk Attestation Edge Cases
  // ════════════════════════════════════════════════════════════════════════════

  // F1: Same contract, different chains — separate entities
  {
    console.log("[F1] Same contract on different chains — separate entities...");
    try {
      const db = createInMemoryDb();
      const addr = "0xCONTRACT00000000000000000000000000000000";
      handleRiskAttested(makeBaseEvent({
        txHash: "0xf1a", params: {
          contractAddress: addr, chain: "monad",
          score: 100, grade: "A", signalsHash: ZERO_HASH,
        }
      }), db);
      handleRiskAttested(makeBaseEvent({
        txHash: "0xf1b", params: {
          contractAddress: addr, chain: "ethereum",
          score: 9000, grade: "F", signalsHash: ZERO_HASH,
        }
      }), db);
      assert.strictEqual(db.contractRiskRecords.size, 2);
      const monad = db.contractRiskRecords.get(`${addr.toLowerCase()}-monad`)!;
      const eth = db.contractRiskRecords.get(`${addr.toLowerCase()}-ethereum`)!;
      assert.strictEqual(monad.score, 100);
      assert.strictEqual(eth.score, 9000);
      pass("Same contract on different chains creates separate entities.");
    } catch (e) { fail("Multi-chain attestation entity collision", e); }
  }

  // F2: Empty chain string
  {
    console.log("[F2] Empty chain string in risk attestation...");
    try {
      const db = createInMemoryDb();
      handleRiskAttested(makeBaseEvent({
        txHash: "0xf2", params: {
          contractAddress: ZERO_ADDR, chain: "",
          score: 50, grade: "C", signalsHash: ZERO_HASH,
        }
      }), db);
      const entityId = `${ZERO_ADDR}-`;
      assert.strictEqual(db.contractRiskRecords.has(entityId), true);
      pass("Empty chain string produces valid entity ID.");
    } catch (e) { fail("Empty chain string crashed", e); }
  }

  // F3: AttestationUpdated overwrites RiskAttested
  {
    console.log("[F3] AttestationUpdated fully overwrites prior RiskAttested...");
    try {
      const db = createInMemoryDb();
      const addr = "0xUPDATE0000000000000000000000000000000000";
      handleRiskAttested(makeBaseEvent({
        txHash: "0xf3a", timestamp: 1000, params: {
          contractAddress: addr, chain: "monad",
          score: 100, grade: "A", signalsHash: "0xoriginal",
        }
      }), db);
      handleAttestationUpdated(makeBaseEvent({
        txHash: "0xf3b", timestamp: 2000, params: {
          contractAddress: addr, chain: "monad",
          score: 9999, grade: "F", signalsHash: "0xupdated",
        }
      }), db);
      assert.strictEqual(db.contractRiskRecords.size, 1);
      const record = db.contractRiskRecords.get(`${addr.toLowerCase()}-monad`)!;
      assert.strictEqual(record.score, 9999);
      assert.strictEqual(record.grade, "F");
      assert.strictEqual(record.signalsHash, "0xupdated");
      assert.strictEqual(record.updatedAt, 2000n);
      pass("AttestationUpdated fully overwrites prior record.");
    } catch (e) { fail("AttestationUpdated did not overwrite", e); }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // CATEGORY G: Cortex Anchor Edge Cases
  // ════════════════════════════════════════════════════════════════════════════

  // G1: periodEnd before periodStart (invalid time window)
  {
    console.log("[G1] Cortex periodEnd < periodStart — must index, not crash...");
    try {
      const db = createInMemoryDb();
      handleRootCommitted(makeBaseEvent({
        txHash: "0xg1", params: {
          merkleRoot: ZERO_HASH, agentHash: ZERO_HASH,
          eventCount: 100, periodStart: 2000, periodEnd: 1000,
          commitmentIndex: 0,
        }
      }), db);
      const commitment = db.cortexCommitments.get("0xg1-0")!;
      assert.strictEqual(commitment.periodStart, 2000n);
      assert.strictEqual(commitment.periodEnd, 1000n); // invalid but stored
      pass("Invalid period window indexed without crash (documented).");
    } catch (e) { fail("Invalid time window crashed handler", e); }
  }

  // G2: Zero eventCount
  {
    console.log("[G2] Cortex zero eventCount — edge boundary...");
    try {
      const db = createInMemoryDb();
      handleRootCommitted(makeBaseEvent({
        txHash: "0xg2", params: {
          merkleRoot: ZERO_HASH, agentHash: ZERO_HASH,
          eventCount: 0, periodStart: 0, periodEnd: 0,
          commitmentIndex: 0,
        }
      }), db);
      const commitment = db.cortexCommitments.get("0xg2-0")!;
      assert.strictEqual(commitment.eventCount, 0n);
      pass("Zero eventCount handled correctly.");
    } catch (e) { fail("Zero eventCount failed", e); }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // CATEGORY H: String Address vs EVM Address Namespace Collision
  // ════════════════════════════════════════════════════════════════════════════

  // H1: EVM address as string address — different entity stores
  {
    console.log("[H1] EVM-format address via StringAddressAdded — namespace isolation...");
    try {
      const db = createInMemoryDb();
      const addr = "0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

      // Add as EVM address (lowercase ID)
      handleAddressAdded(makeBaseEvent({
        txHash: "0xh1a", params: { malicious: addr, reason: "evm" }
      }), db);
      // Add same address as string (case-preserved ID)
      handleStringAddressAdded(makeBaseEvent({
        txHash: "0xh1b", params: { malicious: addr, reason: "string" }
      }), db);

      // EVM handler lowercases → "0xaaaa..."; String handler preserves case → "0xAAAA..."
      const evmEntity = db.threatRecords.get(addr.toLowerCase());
      const strEntity = db.threatRecords.get(addr);

      assert.ok(evmEntity, "EVM entity must exist with lowercase key");
      assert.ok(strEntity, "String entity must exist with original-case key");
      assert.strictEqual(evmEntity!.isStringAddress, false);
      assert.strictEqual(strEntity!.isStringAddress, true);
      // They are separate entities because lowercase differs from original
      assert.strictEqual(db.threatRecords.size, 2);
      pass("EVM and string address handlers create separate namespace entries.");
    } catch (e) { fail("EVM/string namespace collision detected", e); }
  }

  // ════════════════════════════════════════════════════════════════════════════
  // SUMMARY
  // ════════════════════════════════════════════════════════════════════════════

  console.log("================================================================");
  if (failed > 0) {
    console.log(`ADVERSARIAL AUDIT: ${passed} passed, ${failed} FAILED out of ${passed + failed} tests.`);
    process.exit(1);
  } else {
    console.log(`ADVERSARIAL AUDIT: ${passed} / ${passed} tests passed (100% green).`);
  }
  console.log("================================================================");
}

runAdversarialSuite();
