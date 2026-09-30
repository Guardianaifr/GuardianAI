import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

// REAL logic imported directly from shared dashboard modules:
import {
  createDelegationAdapters,
  validateDelegationResult,
  validateRevocationResult,
  resolveDelegationParams
} from '../dashboard/src/lib/delegationAdapter.js';

import {
  isBlockedEvent,
  isNonRequestEvent,
  calculateRiskScores,
  classifyActionOutcomes,
  getSafetyContinuumStatus,
  processTelemetryEvent,
  evaluatePassportQuery,
  calculateShareBlocked,
  getSimpleStatusIndicator
} from '../dashboard/src/lib/truthfulnessMetrics.js';

import { t, GLOSSARY } from '../dashboard/src/lib/glossary.js';

describe('Phase 1a Truthfulness Unit Tests (Real Shared Modules)', () => {

  describe('F5 & Item 4: Real Delegation and Revocation Enforcement & Explicit Params', () => {
    test('outside demo mode: addSigners throws when session-signer methods are missing', async () => {
      const emptySigners = {}; // No addSessionSigners, no addSigners
      const adapter = createDelegationAdapters(emptySigners, false);

      await assert.rejects(
        async () => { await adapter.addSigners({}); },
        { message: /Privy session signers are not configured or available/ }
      );
    });

    test('outside demo mode: removeSigners throws when session-signer methods are missing', async () => {
      const emptySigners = {};
      const adapter = createDelegationAdapters(emptySigners, false);

      await assert.rejects(
        async () => { await adapter.removeSigners({}); },
        { message: /Privy session signers are not configured or available/ }
      );
    });

    test('outside demo mode: caller rejects simulated:true even if an adapter returned it', () => {
      const simulatedRes = { success: true, simulated: true };

      assert.throws(
        () => validateDelegationResult(simulatedRes, false),
        { message: /Simulated delegation rejected: not in demo mode/ }
      );

      assert.throws(
        () => validateRevocationResult(simulatedRes, false),
        { message: /Simulated revocation rejected: not in demo mode/ }
      );
    });

    test('in demo mode: adapter returns simulated:true and caller activates persistent demo simulation state', async () => {
      const emptySigners = {};
      const adapter = createDelegationAdapters(emptySigners, true);

      const addRes = await adapter.addSigners({});
      assert.equal(addRes.simulated, true);

      const addValidation = validateDelegationResult(addRes, true);
      assert.equal(addValidation.isDemoSimulation, true);

      const removeRes = await adapter.removeSigners({});
      assert.equal(removeRes.simulated, true);

      const removeValidation = validateRevocationResult(removeRes, true);
      assert.equal(removeValidation.isDemoSimulation, true);
    });

    test('Item 4: outside demo mode, missing agent address or policy ID is invalid and never delegates to placeholder', () => {
      // Both missing outside demo mode
      const missingBoth = resolveDelegationParams("", "", false);
      assert.equal(missingBoth.isValid, false);
      assert.equal(missingBoth.agentAddress, "");
      assert.equal(missingBoth.policyId, "");

      // Missing agentAddress outside demo mode
      const missingAgent = resolveDelegationParams("", "pol_valid_01", false);
      assert.equal(missingAgent.isValid, false);

      // Missing policyId outside demo mode
      const missingPolicy = resolveDelegationParams("0x1234567890123456789012345678901234567890", "", false);
      assert.equal(missingPolicy.isValid, false);

      // Both present outside demo mode
      const validParams = resolveDelegationParams("0x1234567890123456789012345678901234567890", "pol_valid_01", false);
      assert.equal(validParams.isValid, true);
      assert.equal(validParams.agentAddress, "0x1234567890123456789012345678901234567890");
      assert.equal(validParams.policyId, "pol_valid_01");

      // In demo mode: permitted to use demo placeholders
      const demoParams = resolveDelegationParams("", "", true);
      assert.equal(demoParams.isValid, true);
      assert.equal(demoParams.agentAddress, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e");
      assert.equal(demoParams.policyId, "pol_guardian_monad_policyguard_01");
    });

    test('A.2.4: resolveDelegationParams validates with ethers.isAddress outside demo mode', () => {
      // Invalid Ethereum addresses outside demo mode:
      assert.equal(resolveDelegationParams("not-an-address", "pol_valid_01", false).isValid, false);
      assert.equal(resolveDelegationParams("0x123", "pol_valid_01", false).isValid, false);
      assert.equal(resolveDelegationParams("0xZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZZ", "pol_valid_01", false).isValid, false);
      assert.equal(resolveDelegationParams("", "pol_valid_01", false).isValid, false);

      // Valid Ethereum address outside demo mode:
      const valid = resolveDelegationParams("0x742d35Cc6634C0532925a3b844Bc454e4438f44e", "pol_valid_01", false);
      assert.equal(valid.isValid, true);
      assert.equal(valid.agentAddress, "0x742d35Cc6634C0532925a3b844Bc454e4438f44e");
    });
  });

  describe('F1/F16: Real Empty Data Renders Null/Neutral, Never Green or 14', () => {
    test('empty events render avgRiskScore and peakRiskScore as null (never 14, never green)', () => {
      const emptyEvents = [];
      const scores = calculateRiskScores(emptyEvents);

      assert.equal(scores.avgRiskScore, null, 'Average risk score must be null when empty');
      assert.equal(scores.peakRiskScore, null, 'Peak risk score must be null when empty');
    });

    test('events with only unknown severity render null risk scores', () => {
      const unknownEvents = [
        { severity: 'UNKNOWN', details: {} },
        { severity: 'UNKNOWN' }
      ];
      const scores = calculateRiskScores(unknownEvents);

      assert.equal(scores.avgRiskScore, null);
      assert.equal(scores.peakRiskScore, null);
    });
  });

  describe('F10 & Item 1: Real Outcome Classification — Explicit Status Required for Allowed', () => {
    test('unknown event types are counted in couldntVerifyCount and do not increment allowedCount', () => {
      const events = [
        { event_type: "UNKNOWN", severity: "WARN", details: { status: "UNKNOWN" } },
        { event_type: "UNRECOGNIZED_RPC", severity: "ERROR", details: {} },
        { event_type: "CORRUPTED_EVENT" }, // missing status and severity
      ];

      const outcomes = classifyActionOutcomes(events);

      assert.equal(outcomes.allowedCount, 0, "Unknown events must NEVER count as allowed");
      assert.equal(outcomes.couldntVerifyCount, 3, "All unknown/errored events must count as couldn't verify");
      assert.equal(outcomes.blockedCount, 0);
    });

    test('Item 1: bare INFO event without ALLOWED/EXECUTED/SUCCESS status goes to couldnt verify, NOT allowed', () => {
      const bareInfoEvents = [
        { event_type: "ON-CHAIN ACTION", severity: "INFO", isBlocked: false },
        { event_type: "TELEMETRY_LOG", severity: "INFO", isBlocked: false, details: {} },
        { event_type: "UNVERIFIED_CALL", severity: "INFO", isBlocked: false, details: { status: "PENDING" } }
      ];

      const outcomes = classifyActionOutcomes(bareInfoEvents);

      assert.equal(outcomes.allowedCount, 0, "severity INFO alone is NOT evidence of allowance");
      assert.equal(outcomes.couldntVerifyCount, 3, "Bare INFO events must count as couldn't verify");
      assert.equal(outcomes.blockedCount, 0);
    });

    test('Item 1: POLICY DEPLOYED is a non-request event and does NOT increment allowed or request counters', () => {
      const events = [
        {
          event_type: "POLICY DEPLOYED",
          severity: "INFO",
          isBlocked: false,
          details: { status: "ALLOWED", reason: "Policy deployed" }
        },
        {
          event_type: "POLICY_CREATED",
          severity: "INFO",
          isBlocked: false
        }
      ];

      assert.equal(isNonRequestEvent(events[0]), true);
      assert.equal(isNonRequestEvent(events[1]), true);

      const outcomes = classifyActionOutcomes(events);

      assert.equal(outcomes.totalRequests, 0, "Non-request events must be excluded from totalRequests");
      assert.equal(outcomes.allowedCount, 0, "POLICY DEPLOYED must not increment allowed");
      assert.equal(outcomes.couldntVerifyCount, 0);
      assert.equal(outcomes.blockedCount, 0);

      // Verify processTelemetryEvent also excludes non-request events from stats
      const stats = { requests: 10, blocked: 2 };
      const { nextStats } = processTelemetryEvent(events[0], stats, false);
      assert.equal(nextStats.requests, 10, "processTelemetryEvent must not increment requests for POLICY DEPLOYED");
    });

    test('allowedCount requires explicit status (ALLOWED/EXECUTED/SUCCESS)', () => {
      const events = [
        // Positively verified allowed:
        { event_type: "ON-CHAIN ACTION", severity: "INFO", isBlocked: false, details: { status: "EXECUTED" } },
        { event_type: "SWAP_EXECUTION", severity: "INFO", isBlocked: false, details: { status: "ALLOWED" } },
        { event_type: "BRIDGE_TRANSFER", severity: "INFO", isBlocked: false, details: { status: "SUCCESS" } },
        // Unverified event (isBlocked false, but no positive allowed status):
        { event_type: "CUSTOM_HOOK", severity: "WARN", isBlocked: false, details: { status: "PENDING" } },
        // Blocked event:
        { event_type: "INJECTION", severity: "CRITICAL", isBlocked: true },
      ];

      const outcomes = classifyActionOutcomes(events);

      assert.equal(outcomes.allowedCount, 3, "Only explicitly allowed/executed/success events count as allowed");
      assert.equal(outcomes.blockedCount, 1, "The blocked event must count as blocked");
      assert.equal(outcomes.couldntVerifyCount, 1, "The pending/unverified event must count as couldn't verify");
      assert.equal(outcomes.totalRequests, 5);
    });

    test('Item 1 Invariant: allowed + blocked + couldn\'t verify === totalRequests, with and without indexer stats present', () => {
      // 1. Without indexer stats (stats is null / empty)
      const mixedEvents = [
        { event_type: "ON-CHAIN ACTION", severity: "INFO", isBlocked: false, details: { status: "EXECUTED" } },
        { event_type: "INJECTION", severity: "CRITICAL", isBlocked: true },
        { event_type: "UNKNOWN", severity: "WARN", details: {} },
        { event_type: "UNVERIFIED", severity: "INFO", isBlocked: false }, // bare info -> couldn't verify
        { event_type: "POLICY DEPLOYED", severity: "INFO" }, // non-request -> excluded
        { event_type: "SWAP_EXECUTION", severity: "INFO", isBlocked: false, details: { status: "ALLOWED" } }
      ];

      const outcomesNoStats = classifyActionOutcomes(mixedEvents, null);
      assert.equal(
        outcomesNoStats.allowedCount + outcomesNoStats.blockedCount + outcomesNoStats.couldntVerifyCount,
        outcomesNoStats.totalRequests,
        "Invariant violation: allowed + blocked + couldn't verify must equal totalRequests (without indexer stats)"
      );
      assert.equal(outcomesNoStats.totalRequests, 5); // 6 events minus 1 non-request event
      assert.equal(outcomesNoStats.allowedCount, 2);
      assert.equal(outcomesNoStats.blockedCount, 1);
      assert.equal(outcomesNoStats.couldntVerifyCount, 2);

      // 2. With indexer stats present
      const indexerStats = { requests: 250, blocked: 45, allowed: 180 };
      const outcomesWithStats = classifyActionOutcomes(mixedEvents, indexerStats);
      assert.equal(
        outcomesWithStats.allowedCount + outcomesWithStats.blockedCount + outcomesWithStats.couldntVerifyCount,
        outcomesWithStats.totalRequests,
        "Invariant violation: allowed + blocked + couldn't verify must equal totalRequests (with indexer stats)"
      );
      assert.equal(outcomesWithStats.totalRequests, 250);
      assert.equal(outcomesWithStats.blockedCount, 45);
      assert.equal(outcomesWithStats.allowedCount, 180);
      assert.equal(outcomesWithStats.couldntVerifyCount, 25);

      // 3. With indexer stats having no explicit allowed count (only requests & blocked)
      const partialIndexerStats = { requests: 100, blocked: 15 };
      const outcomesPartial = classifyActionOutcomes([], partialIndexerStats);
      assert.equal(
        outcomesPartial.allowedCount + outcomesPartial.blockedCount + outcomesPartial.couldntVerifyCount,
        outcomesPartial.totalRequests,
        "Invariant violation: allowed + blocked + couldn't verify must equal totalRequests (partial indexer stats)"
      );
      assert.equal(outcomesPartial.totalRequests, 100);
      assert.equal(outcomesPartial.blockedCount, 15);
      assert.equal(outcomesPartial.allowedCount, 0);
      assert.equal(outcomesPartial.couldntVerifyCount, 85);

      // 4. Edge case: completely empty
      const outcomesEmpty = classifyActionOutcomes([], null);
      assert.equal(
        outcomesEmpty.allowedCount + outcomesEmpty.blockedCount + outcomesEmpty.couldntVerifyCount,
        outcomesEmpty.totalRequests
      );
      assert.equal(outcomesEmpty.totalRequests, 0);
    });
  });

  describe('Item 2: AgentsTab Passport Probe 3-State Evaluation', () => {
    test('when query returns true, status is active', async () => {
      const result = await evaluatePassportQuery(async () => true);

      assert.equal(result.state, "active");
      assert.equal(result.type, "success");
      assert.equal(result.title, "Passport active (read from Monad Testnet)");
      assert.equal(result.riskScore, 2);
    });

    test('when query returns false, status is revoked with inactive passport title', async () => {
      const result = await evaluatePassportQuery(async () => false);

      assert.equal(result.state, "revoked");
      assert.equal(result.type, "error");
      assert.equal(result.title, "No active passport for test ID revoked-agent-01");
      assert.equal(result.riskScore, null);
    });

    test('when query throws error, status is couldn\'t verify (network error) and NEVER revoked', async () => {
      const result = await evaluatePassportQuery(async () => {
        throw new Error("connection reset by peer");
      });

      assert.equal(result.state, "couldnt_verify");
      assert.notEqual(result.state, "revoked", "The catch block must NEVER set revoked on network/RPC error");
      assert.equal(result.type, "warning");
      assert.equal(result.title, "Couldn't verify (network error)");
      assert.equal(result.riskScore, null);
    });
  });

  describe('Fix 1: Probe Injected Events & Telemetry Stats Isolation', () => {
    test('outside demo mode: simulated probe events are tagged isSimulated and DO NOT mutate real stats', () => {
      const initialStats = { requests: 5, blocked: 2 };
      const probeEvent = {
        event_type: "MERA MEMORY TAMPER ATTEMPT",
        severity: "CRITICAL",
        isBlocked: true,
        isSimulated: true
      };

      const { nextStats, eventToRecord } = processTelemetryEvent(probeEvent, initialStats, false);

      assert.equal(eventToRecord.isSimulated, true, "Event must be flagged as isSimulated");
      assert.equal(nextStats.requests, 5, "Requests must NOT mutate from simulated probe outside demo mode");
      assert.equal(nextStats.blocked, 2, "Blocked must NOT mutate from simulated probe outside demo mode");
    });

    test('in demo mode: simulated probe events DO update demo stats', () => {
      const initialStats = { requests: 5, blocked: 2 };
      const probeEvent = {
        event_type: "MERA MEMORY TAMPER ATTEMPT",
        severity: "CRITICAL",
        isBlocked: true,
        isSimulated: true
      };

      const { nextStats, eventToRecord } = processTelemetryEvent(probeEvent, initialStats, true);

      assert.equal(eventToRecord.isSimulated, true);
      assert.equal(nextStats.blocked, 3, "In demo mode, stats are updated for simulation");
    });
  });

  describe('Fix 4: Fail-Closed Safety Continuum Status', () => {
    test('when couldntVerifyCount > 0, NEVER show green/clean state even if avgRiskScore is 0', () => {
      const status = getSafetyContinuumStatus(0, 1);

      assert.equal(status.isClean, false, "Must fail closed: isClean must be false when unverified events exist");
      assert.notEqual(status.tier, "clean", "Tier must not be clean");
      assert.equal(status.tier, "warning");
      assert.equal(status.statusLabel, "UNVERIFIED ACTIVITY (AMBER)");
      assert.equal(status.colorClass, "text-amber-400");
    });

    test('when couldntVerifyCount === 0 and avgRiskScore < 30, shows nominal green baseline', () => {
      const status = getSafetyContinuumStatus(15, 0);

      assert.equal(status.isClean, true);
      assert.equal(status.tier, "clean");
      assert.equal(status.statusLabel, "NOMINAL BASELINE");
      assert.equal(status.colorClass, "text-emerald-400");
    });

    test('when avgRiskScore is null, shows neutral Awaiting Activity state', () => {
      const status = getSafetyContinuumStatus(null, 0);

      assert.equal(status.isClean, false);
      assert.equal(status.tier, "none");
      assert.equal(status.statusLabel, "NO DATA YET");
      assert.equal(status.colorClass, "text-muted-foreground");
    });
  });

  describe('Item 7: DashboardTab Share Blocked Metric', () => {
    test('if totalRequests is 0, returns "--", not a fabricated percentage', () => {
      assert.equal(calculateShareBlocked(0, 0), "--");
      assert.equal(calculateShareBlocked(5, 0), "--");
      assert.equal(calculateShareBlocked(0, null), "--");
      assert.equal(calculateShareBlocked(0, -1), "--");
    });

    test('if totalRequests > 0, returns accurate formatted percentage', () => {
      assert.equal(calculateShareBlocked(3, 10), "30.0%");
      assert.equal(calculateShareBlocked(5, 20), "25.0%");
      assert.equal(calculateShareBlocked(0, 50), "0.0%");
      assert.equal(calculateShareBlocked(100, 100), "100.0%");
    });
  });

  describe('Part B.1: Glossary & Plain English Translation Function t()', () => {
    test('contains all Phase 0 audit terms in GLOSSARY dictionary', () => {
      const requiredTerms = [
        "TEE",
        "Enclave",
        "Attestation",
        "Session Signer",
        "MPC",
        "Monad",
        "RIP-7212",
        "Gas",
        "Policy Guard",
        "ERC-8004",
        "Soulbound",
        "EIP-712",
        "Merkle Root",
        "Precompile",
        "PRF",
        "RPC",
        "Mempool",
        "BFT consensus",
        "Smart contract",
        "Relayer",
        "Entropy",
        "Bips"
      ];

      for (const term of requiredTerms) {
        assert.ok(GLOSSARY[term], `GLOSSARY missing required audit term: ${term}`);
        assert.ok(GLOSSARY[term].simple, `GLOSSARY[${term}] missing simple translation`);
        assert.ok(GLOSSARY[term].advanced, `GLOSSARY[${term}] missing advanced definition`);
      }
    });

    test('t() returns plain English in Simple mode (isAdvanced=false)', () => {
      assert.equal(t("TEE", false), "Hardware-secured vault");
      assert.equal(t("Attestation", false), "Cryptographic proof of integrity");
      assert.equal(t("RIP-7212", false), "Hardware passkey accelerator");
      assert.equal(t("Gas", false), "Network fee");
      assert.equal(t("ERC-8004", false), "Agent digital ID");
      assert.equal(t("Session Signer", false), "Automated trading permission");
    });

    test('t() returns technical term in Advanced mode (isAdvanced=true)', () => {
      assert.equal(t("TEE", true), "Trusted Execution Environment (TEE)");
      assert.equal(t("Attestation", true), "Cryptographic Attestation");
      assert.equal(t("RIP-7212", true), "RIP-7212 Precompile");
      assert.equal(t("Gas", true), "Gas");
      assert.equal(t("ERC-8004", true), "ERC-8004 Trustless Agent Passport");
    });
  });

  describe('Part B.3: Simple Mode Fail-Closed Status Indicator', () => {
    test('empty / null risk score returns "No data yet" (neutral gray, not green)', () => {
      const status = getSimpleStatusIndicator(null, 0);
      assert.equal(status.statusLabel, "No data yet");
      assert.equal(status.isClean, false);
      assert.equal(status.colorClass, "text-muted-foreground");
    });

    test('when couldntVerifyCount > 0, returns "Couldn\'t verify" (never green)', () => {
      const status = getSimpleStatusIndicator(10, 2);
      assert.equal(status.statusLabel, "Couldn't verify");
      assert.equal(status.isClean, false);
      assert.equal(status.colorClass, "text-muted-foreground");
    });

    test('when avgRiskScore >= 30, returns "Attention needed" (yellow)', () => {
      const status = getSimpleStatusIndicator(45, 0);
      assert.equal(status.statusLabel, "Attention needed");
      assert.equal(status.isClean, false);
      assert.equal(status.colorClass, "text-amber-400");
    });

    test('when avgRiskScore < 30 and couldntVerifyCount === 0, returns "Protected" (green)', () => {
      const status = getSimpleStatusIndicator(12, 0);
      assert.equal(status.statusLabel, "Protected");
      assert.equal(status.isClean, true);
      assert.equal(status.colorClass, "text-emerald-400");
    });

    test('INVARIANT: NEVER returns "Protected" or green when unverified events exist', () => {
      for (let risk = 0; risk <= 100; risk += 10) {
        const status = getSimpleStatusIndicator(risk, 1);
        assert.notEqual(status.statusLabel, "Protected", `Risk ${risk} with 1 unverified must not be Protected`);
        assert.notEqual(status.colorClass, "text-emerald-400");
        assert.equal(status.isClean, false);
      }
    });
  });

});
