import { test, describe } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ethers } from '../dashboard/node_modules/ethers/lib.esm/index.js';

const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);

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
  getSimpleStatusIndicator
} from '../dashboard/src/lib/truthfulnessMetrics.js';

import { deriveSecurityStats } from '../dashboard/src/lib/statsModel.js';
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

    test('actionsExecuted requires explicit status (ALLOWED/EXECUTED/SUCCESS)', () => {
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

      assert.equal(outcomes.actionsExecuted, 3, "Only explicitly allowed/executed/success events count as actionsExecuted");
      assert.equal(outcomes.threatsRegistered, 1, "The blocked event must count as threatsRegistered");
      assert.equal(outcomes.couldntVerifyCount, 1, "The pending/unverified event must count as couldn't verify");
    });

    test('Part E Item 2: actionsExecuted and threatsRegistered are returned separately without summed totalRequests', () => {
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
      assert.equal(outcomesNoStats.actionsExecuted, 2);
      assert.equal(outcomesNoStats.threatsRegistered, 1);
      assert.equal(outcomesNoStats.couldntVerifyCount, 2);
      assert.equal(outcomesNoStats.totalRequests, 5);

      // 2. With indexer stats present
      const indexerStats = { actionsExecuted: 180, threatsRegistered: 45 };
      const outcomesWithStats = classifyActionOutcomes(mixedEvents, indexerStats);
      assert.equal(outcomesWithStats.actionsExecuted, 180);
      assert.equal(outcomesWithStats.threatsRegistered, 45);
      assert.equal(outcomesWithStats.couldntVerifyCount, 0);
      assert.equal(outcomesWithStats.totalRequests, undefined);

      // 3. Edge case: completely empty
      const outcomesEmpty = classifyActionOutcomes([], null);
      assert.equal(outcomesEmpty.actionsExecuted, 0);
      assert.equal(outcomesEmpty.threatsRegistered, 0);
      assert.equal(outcomesEmpty.couldntVerifyCount, 0);
    });

    test('B.1.1: allowed count does not depend on the length of actionsArr (independent of limit-25)', () => {
      // 50 events in actionsArr, but totalActionsExecuted is 350
      const actionsArr = Array.from({ length: 50 }, (_, i) => ({ id: `act-${i}`, details: { status: "ALLOWED" } }));
      const indexerStats = { actionsExecuted: 350, threatsRegistered: 50 };
      const outcomes = classifyActionOutcomes(actionsArr, indexerStats, false);
      assert.equal(outcomes.actionsExecuted, 350, "actionsExecuted must equal totalActionsExecuted, NOT actionsArr.length");
      assert.notEqual(outcomes.actionsExecuted, actionsArr.length);
      assert.equal(outcomes.threatsRegistered, 50);
      assert.equal(outcomes.couldntVerifyCount, 0);
    });

    test('B.1.1: failed fetch renders couldn\'t load data with null numbers', () => {
      const someStats = { actionsExecuted: 100, threatsRegistered: 20 };
      const outcomes = classifyActionOutcomes([], someStats, true); // fetchFailed = true
      assert.equal(outcomes.fetchFailed, true);
      assert.equal(outcomes.statusMessage, "Couldn't load data");
      assert.equal(outcomes.actionsExecuted, null, "When fetch fails, actionsExecuted must be null");
      assert.equal(outcomes.threatsRegistered, null, "When fetch fails, threatsRegistered must be null");
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
        if (!GLOSSARY[term].hideInSimple) {
          assert.ok(GLOSSARY[term].simple, `GLOSSARY[${term}] missing simple translation`);
        } else {
          assert.equal(GLOSSARY[term].simple, null, `GLOSSARY[${term}] must have simple: null for hidden term`);
        }
        assert.ok(GLOSSARY[term].advanced, `GLOSSARY[${term}] missing advanced definition`);
      }
    });

    test('t() returns plain English in Simple mode (isAdvanced=false)', () => {
      assert.equal(t("TEE", false), "Protected environment");
      assert.equal(t("Attestation", false), "Signed safety check");
      assert.equal(t("RIP-7212", false), "Passkey check");
      assert.equal(t("Gas", false), "Execution fee");
      assert.equal(t("ERC-8004", false), "Registered agent ID");
      assert.equal(t("Session Signer", false), "Delegated agent key");
    });

    test('t() returns technical term in Advanced mode (isAdvanced=true)', () => {
      assert.equal(t("TEE", true), "Trusted Execution Environment (TEE)");
      assert.equal(t("Attestation", true), "Cryptographic Attestation");
      assert.equal(t("RIP-7212", true), "RIP-7212 Precompile");
      assert.equal(t("Gas", true), "Gas");
      assert.equal(t("ERC-8004", true), "Soulbound agent passport (ERC-5192)");
    });
  });

  describe('Part B.3: Simple Mode Fail-Closed Status Indicator', () => {
    test('empty / null risk score returns "No data yet" (neutral gray, not green)', () => {
      const status = getSimpleStatusIndicator({ avgRiskScore: null, couldntVerifyCount: 0 });
      assert.equal(status.statusLabel, "No data yet");
      assert.equal(status.isClean, false);
      assert.equal(status.colorClass, "text-muted-foreground");
    });

    test('when couldntVerifyCount > 0, returns "Couldn\'t verify" (never green)', () => {
      const status = getSimpleStatusIndicator({ avgRiskScore: 10, couldntVerifyCount: 2 });
      assert.equal(status.statusLabel, "Couldn't verify");
      assert.equal(status.isClean, false);
      assert.equal(status.colorClass, "text-muted-foreground");
    });

    test('when avgRiskScore >= 30, returns "Attention needed" (amber)', () => {
      const status = getSimpleStatusIndicator({ avgRiskScore: 45, couldntVerifyCount: 0 });
      assert.equal(status.statusLabel, "Attention needed");
      assert.equal(status.isClean, false);
      assert.equal(status.colorClass, "text-amber-400");
    });

    test('B.1.2: one CRITICAL event among 50 low events produces amber (Attention needed)', () => {
      const lowEvents = Array.from({ length: 50 }, (_, i) => ({
        id: `evt-${i}`,
        severity: "LOW",
        details: { riskScore: 5 }
      }));
      const criticalEvent = {
        id: "evt-crit",
        severity: "CRITICAL",
        details: { riskScore: 95 }
      };
      const allEvents = [...lowEvents, criticalEvent];
      const avgRisk = (50 * 5 + 95) / 51; // ~6.76 (well below 30)
      const peakRisk = 95;

      const status = getSimpleStatusIndicator({ avgRiskScore: avgRisk, couldntVerifyCount: 0, peakRiskScore: peakRisk, events: allEvents });
      assert.equal(status.statusLabel, "Attention needed", "A single CRITICAL event must trigger Attention needed even with low average");
      assert.equal(status.tier, "attention");
      assert.equal(status.isClean, false);
      assert.equal(status.colorClass, "text-amber-400");
    });

    test('when avgRiskScore <= 25 and couldntVerifyCount === 0 with no high events, returns "No flagged on-chain actions" (green)', () => {
      const status = getSimpleStatusIndicator({ avgRiskScore: 12, couldntVerifyCount: 0, peakRiskScore: 15, events: [] });
      assert.equal(status.statusLabel, "No flagged on-chain actions");
      assert.equal(status.isClean, true);
      assert.equal(status.colorClass, "text-emerald-400");
    });

    test('CONTRACT BOUNDARY: peakRiskScore > 25 triggers Attention needed (amber) (GuardianPolicyGuard.sol:30, 48, 120)', () => {
      const status = getSimpleStatusIndicator({ avgRiskScore: 12, couldntVerifyCount: 0, peakRiskScore: 26, events: [] });
      assert.equal(status.statusLabel, "Attention needed");
      assert.equal(status.isClean, false);
      assert.equal(status.colorClass, "text-amber-400");
    });

    test('GLOBAL THREATS INFO-ONLY: global threatsRegistered alone does NOT trigger amber when recorded activity is nominal', () => {
      const statusThreats = getSimpleStatusIndicator({ avgRiskScore: 10, couldntVerifyCount: 0, peakRiskScore: 10, events: [] });
      assert.equal(statusThreats.statusLabel, "No flagged on-chain actions", "Global threatsRegistered is info-only and must not make clean session amber");
      assert.equal(statusThreats.isClean, true);
    });

    test('BLOCKED EVENT IN ACTIVITY: a blocked event (isBlocked: true) triggers Attention needed (amber) immediately', () => {
      const statusBlocked = getSimpleStatusIndicator({ avgRiskScore: 10, couldntVerifyCount: 0, peakRiskScore: 10, events: [{ isBlocked: true }] });
      assert.equal(statusBlocked.statusLabel, "Attention needed");
      assert.equal(statusBlocked.isClean, false);
      assert.equal(statusBlocked.colorClass, "text-amber-400");
    });

    test('INVARIANT: NEVER returns "No flagged on-chain actions" or green when unverified events exist', () => {
      for (let risk = 0; risk <= 100; risk += 10) {
        const status = getSimpleStatusIndicator({ avgRiskScore: risk, couldntVerifyCount: 1 });
        assert.notEqual(status.statusLabel, "No flagged on-chain actions", `Risk ${risk} with 1 unverified must not be clean`);
        assert.notEqual(status.colorClass, "text-emerald-400");
        assert.equal(status.isClean, false);
      }
    });

    test('INVARIANT: NEVER returns "Protected" anywhere', () => {
      for (let risk = 0; risk <= 100; risk += 5) {
        const status0 = getSimpleStatusIndicator({ avgRiskScore: risk, couldntVerifyCount: 0 });
        assert.notEqual(status0.statusLabel, "Protected", `Status label must never be Protected`);
        const status1 = getSimpleStatusIndicator({ avgRiskScore: risk, couldntVerifyCount: 2 });
        assert.notEqual(status1.statusLabel, "Protected", `Status label must never be Protected`);
      }
    });

    test('STRICT EVALUATION ORDER: 1. Elevated risk / blocked events trigger amber before couldntVerify', () => {
      // Case 1a: peakRiskScore > 25 triggers Attention needed even if couldntVerifyCount > 0
      const statusPeak = getSimpleStatusIndicator({ avgRiskScore: 10, couldntVerifyCount: 5, peakRiskScore: 26, events: [] });
      assert.equal(statusPeak.statusLabel, "Attention needed");
      assert.equal(statusPeak.tier, "attention");

      // Case 1b: HIGH event triggers Attention needed even if couldntVerifyCount > 0
      const statusHigh = getSimpleStatusIndicator({ avgRiskScore: 10, couldntVerifyCount: 5, peakRiskScore: 10, events: [{ severity: "HIGH" }] });
      assert.equal(statusHigh.statusLabel, "Attention needed");
      assert.equal(statusHigh.tier, "attention");

      // Case 1c: Blocked event triggers Attention needed even if couldntVerifyCount > 0
      const statusBlocked = getSimpleStatusIndicator({ avgRiskScore: 10, couldntVerifyCount: 5, peakRiskScore: 10, events: [{ isBlocked: true }] });
      assert.equal(statusBlocked.statusLabel, "Attention needed");
      assert.equal(statusBlocked.tier, "attention");
    });

    test('STRICT EVALUATION ORDER: 2. couldntVerify triggers second when 0 threats', () => {
      const status = getSimpleStatusIndicator({ avgRiskScore: 10, couldntVerifyCount: 4, peakRiskScore: 15, events: [] });
      assert.equal(status.statusLabel, "Couldn't verify");
      assert.equal(status.tier, "unverified");
      assert.equal(status.isClean, false);
    });

    test('STRICT EVALUATION ORDER: 3. No data triggers third when 0 threats and 0 unverified', () => {
      const status = getSimpleStatusIndicator({ avgRiskScore: null, couldntVerifyCount: 0, peakRiskScore: null, events: [] });
      assert.equal(status.statusLabel, "No data yet");
      assert.equal(status.tier, "none");
      assert.equal(status.isClean, false);
    });

    test('STRICT EVALUATION ORDER: 4. Nominal activity triggers green last', () => {
      const status = getSimpleStatusIndicator({ avgRiskScore: 15, couldntVerifyCount: 0, peakRiskScore: 20, events: [] });
      assert.equal(status.statusLabel, "No flagged on-chain actions");
      assert.equal(status.tier, "clean");
      assert.equal(status.isClean, true);
      assert.equal(status.colorClass, "text-emerald-400");
    });

    test('Part F Item 2: fetchFailed returns "Couldn\'t load data" (neutral gray, never "No data yet")', () => {
      const statusFailed = getSimpleStatusIndicator({
        fetchFailed: true,
        avgRiskScore: null,
        couldntVerifyCount: 0,
        events: []
      });
      assert.equal(statusFailed.statusLabel, "Couldn't load data");
      assert.equal(statusFailed.tier, "failed");
      assert.equal(statusFailed.isClean, false);
      assert.equal(statusFailed.colorClass, "text-muted-foreground");
    });

    test('Part F Item 1: target matches ACTIVE threatFeed record -> "Attention needed" + copy', () => {
      const threatFeed = [
        { address: "0xdead000000000000000000000000000000000001", reason: "Phishing drainer", active: true },
        { address: "0xdead000000000000000000000000000000000002", reason: "Malicious contract", active: false }
      ];
      const events = [
        {
          event_type: "ON-CHAIN ACTION",
          details: { target: "0xDEAD000000000000000000000000000000000001", riskScore: 5 },
          severity: "INFO",
          isBlocked: false
        }
      ];

      const status = getSimpleStatusIndicator({
        avgRiskScore: 5,
        peakRiskScore: 5,
        events,
        threatFeed,
        couldntVerifyCount: 0
      });

      assert.equal(status.statusLabel, "Attention needed");
      assert.equal(status.description, "An agent interacted with a listed address.");
      assert.equal(status.tier, "attention");
      assert.equal(status.isClean, false);
      assert.equal(status.colorClass, "text-amber-400");
    });

    test('Part F Item 1: target matches only REMOVED threatFeed record -> not amber (green)', () => {
      const threatFeed = [
        { address: "0xdead000000000000000000000000000000000002", reason: "Cleared address", active: false }
      ];
      const events = [
        {
          event_type: "ON-CHAIN ACTION",
          details: { target: "0xdead000000000000000000000000000000000002", riskScore: 5 },
          severity: "INFO",
          isBlocked: false
        }
      ];

      const status = getSimpleStatusIndicator({
        avgRiskScore: 5,
        peakRiskScore: 5,
        events,
        threatFeed,
        couldntVerifyCount: 0
      });

      assert.equal(status.statusLabel, "No flagged on-chain actions");
      assert.equal(status.tier, "clean");
      assert.equal(status.isClean, true);
    });

    test('Part F Item 1: 3 ThreatRecords (2 active, 1 removed), no match -> "No flagged on-chain actions"', () => {
      const threatFeed = [
        { address: "0x1111111111111111111111111111111111111111", reason: "Active 1", active: true },
        { address: "0x2222222222222222222222222222222222222222", reason: "Active 2", active: true },
        { address: "0x3333333333333333333333333333333333333333", reason: "Removed 1", active: false }
      ];
      const events = [
        {
          event_type: "ON-CHAIN ACTION",
          details: { target: "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60", riskScore: 5 },
          severity: "INFO",
          isBlocked: false
        }
      ];

      const status = getSimpleStatusIndicator({
        avgRiskScore: 5,
        peakRiskScore: 5,
        events,
        threatFeed,
        couldntVerifyCount: 0
      });

      assert.equal(status.statusLabel, "No flagged on-chain actions");
      assert.equal(status.tier, "clean");
      assert.equal(status.isClean, true);
      assert.equal(status.colorClass, "text-emerald-400");
    });
  });

  describe('Part B.2: Shared statsModel (deriveSecurityStats)', () => {
    test('keeps Actions executed and Threats registered strictly separate with no summed requests', () => {
      const raw = {
        totalActionsExecuted: 1250,
        totalThreatsRegistered: 48,
        activeThreatCount: 12,
        totalPassportsTracked: 85,
        totalCortexRootsAnchored: 6
      };
      const stats = deriveSecurityStats(raw, false);
      assert.equal(stats.status, "loaded");
      assert.equal(stats.actionsExecuted, 1250);
      assert.equal(stats.threatsRegistered, 48);
      assert.equal(stats.activeThreats, 12);
      assert.equal(stats.passportsTracked, 85);
      assert.equal(stats.cortexRootsAnchored, 6);
      assert.equal(stats.errorMessage, null);
      // No summed requests property exists
      assert.equal(stats.requests, undefined);
    });

    test('on fetch failure or null input, returns null numbers and errorMessage: "Couldn\'t load data"', () => {
      const failedStats = deriveSecurityStats(null, true);
      assert.equal(failedStats.status, "failed");
      assert.equal(failedStats.actionsExecuted, null);
      assert.equal(failedStats.threatsRegistered, null);
      assert.equal(failedStats.activeThreats, null);
      assert.equal(failedStats.passportsTracked, null);
      assert.equal(failedStats.errorMessage, "Couldn't load data");

      const emptyStats = deriveSecurityStats(null, false);
      assert.equal(emptyStats.status, "empty");
      assert.equal(emptyStats.actionsExecuted, null);
      assert.equal(emptyStats.threatsRegistered, null);
    });

    test('normalizes demo fallback stats cleanly', () => {
      const fallback = {
        actionsExecuted: 1380,
        threatsRegistered: 94,
        activeThreats: 17,
        passportsTracked: 340
      };
      const stats = deriveSecurityStats(fallback, false);
      assert.equal(stats.actionsExecuted, 1380);
      assert.equal(stats.threatsRegistered, 94);
      assert.equal(stats.activeThreats, 17);
      assert.equal(stats.passportsTracked, 340);
    });

    test('Part D Item 1: GraphQL response fixture with activeThreatCount parses non-null and equals source values', () => {
      const fixture = {
        GlobalSecurityStats: [{
          totalActionsExecuted: "350",
          totalThreatsRegistered: "12",
          activeThreatCount: "4",
          totalPassportsTracked: "7"
        }]
      };
      const rawStats = fixture.GlobalSecurityStats[0];
      const stats = deriveSecurityStats(rawStats);
      assert.notEqual(stats.actionsExecuted, null);
      assert.notEqual(stats.threatsRegistered, null);
      assert.notEqual(stats.activeThreats, null);
      assert.notEqual(stats.passportsTracked, null);
      assert.equal(stats.actionsExecuted, 350);
      assert.equal(stats.threatsRegistered, 12);
      assert.equal(stats.activeThreats, 4);
      assert.equal(stats.passportsTracked, 7);
    });
  });

  describe('Part B.2: classifyActionOutcomes Truthfulness & Invariants', () => {
    test('on fetch failure, returns null numbers and statusMessage "Couldn\'t load data"', () => {
      const outcomes = classifyActionOutcomes([], null, true);
      assert.equal(outcomes.fetchFailed, true);
      assert.equal(outcomes.actionsExecuted, null);
      assert.equal(outcomes.threatsRegistered, null);
      assert.equal(outcomes.couldntVerifyCount, null);
      assert.equal(outcomes.statusMessage, "Couldn't load data");
    });

    test('invariant: actionsExecuted and threatsRegistered are returned separately without summed totalRequests', () => {
      const stats = { actionsExecuted: 120, threatsRegistered: 30 };
      const outcomes = classifyActionOutcomes([], stats, false);
      assert.equal(outcomes.actionsExecuted, 120);
      assert.equal(outcomes.threatsRegistered, 30);
      assert.equal(outcomes.couldntVerifyCount, 0);
      assert.equal(outcomes.totalRequests, undefined);
    });
  });

  describe('Part B.2 Item 9: Glossary Hidden Terms in Simple Mode', () => {
    const hiddenTerms = [
      'precompile',
      'Merkle root',
      'PRF',
      'relayer',
      'entropy',
      'bips',
      'BFT consensus'
    ];

    test('in Simple mode (isAdvanced=false), returns null (hidden from users)', () => {
      for (const term of hiddenTerms) {
        assert.equal(
          t(term, false),
          null,
          `Term "${term}" must be hidden (null) in Simple mode`
        );
      }
    });

    test('in Advanced mode (isAdvanced=true), returns proper technical string', () => {
      for (const term of hiddenTerms) {
        const val = t(term, true);
        assert.ok(val, `Term "${term}" must not be empty in Advanced mode`);
        assert.equal(typeof val, 'string');
      }
    test('Part C Item 1: missing or NaN fields return null, not 0', () => {
      const raw = {
        totalActionsExecuted: "not-a-number",
        totalThreatsRegistered: null,
        activeThreatCount: undefined,
        totalPassportsTracked: NaN
      };
      const stats = deriveSecurityStats(raw, false);
      assert.strictEqual(stats.actionsExecuted, null);
      assert.strictEqual(stats.threatsRegistered, null);
      assert.strictEqual(stats.activeThreats, null);
      assert.strictEqual(stats.passportsTracked, null);
      assert.strictEqual(stats.cortexRootsAnchored, null);
    });
  });

  describe('Part C Item 1: Stale Polling & Failed Poll Preservation', () => {
    test('failed poll after success preserves last good stats and vectorData with stale label', () => {
      // Simulate state machine from App.jsx polling effect
      let lastGoodStats = null;
      let lastGoodVectorData = null;
      let lastUpdatedTime = null;
      let stats = null;
      let vectorData = null;
      let indexerStatus = "idle";

      // 1. Initial success:
      const initialRaw = { totalActionsExecuted: 100, totalThreatsRegistered: 5, activeThreatCount: 2, totalPassportsTracked: 10, totalCortexRootsAnchored: 1 };
      const derived = deriveSecurityStats(initialRaw, false);
      lastGoodStats = derived;
      lastGoodVectorData = {
        threatsRegistered: derived.threatsRegistered,
        activeThreats: derived.activeThreats,
        passportsTracked: derived.passportsTracked
      };
      lastUpdatedTime = "12:00:00 PM";
      stats = derived;
      vectorData = lastGoodVectorData;
      indexerStatus = "connected";

      assert.equal(stats.actionsExecuted, 100);
      assert.equal(stats.threatsRegistered, 5);

      // 2. Poll failure after success:
      if (lastGoodStats) {
        indexerStatus = "stale";
        const staleMsg = `Last updated ${lastUpdatedTime}. Couldn't refresh`;
        stats = {
          ...lastGoodStats,
          isStale: true,
          staleMessage: staleMsg
        };
        vectorData = {
          ...lastGoodVectorData,
          isStale: true,
          staleMessage: staleMsg
        };
      }

      assert.equal(indexerStatus, "stale");
      assert.equal(stats.isStale, true);
      assert.equal(stats.actionsExecuted, 100, "Last good actionsExecuted must be preserved");
      assert.equal(stats.threatsRegistered, 5, "Last good threatsRegistered must be preserved");
      assert.equal(vectorData.threatsRegistered, 5, "Last good vectorData must be preserved");
      assert.equal(stats.staleMessage, "Last updated 12:00:00 PM. Couldn't refresh");
      assert.equal(vectorData.staleMessage, "Last updated 12:00:00 PM. Couldn't refresh");
    });
  });

  describe('Part E Item 8: Sample hashes and addresses validation', () => {
    test('every sample hash matches /^0x[0-9a-f]{64}$/ and every sample address passes ethers.isAddress', () => {
      const sampleHashes = [
        "0x8c74e2d35cc6634c0532925a3b844bc454e4438f44e19d7b420f129ad4ec1101",
        "0x3a51f89c02d1847c25e8391a27e771c56b72d2459a721d7b328a9b1c73f01101"
      ];
      for (const hash of sampleHashes) {
        assert.ok(/^0x[0-9a-f]{64}$/.test(hash), `Hash "${hash}" does not match /^0x[0-9a-f]{64}$/`);
      }

      const sampleAddresses = [
        "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
        "0x1142f8c90Ab361B8c764b85994FCda30089eC890",
        "0x51b981E8fc89011424e650A1E704b1EC4dF7166e",
        "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60",
        "0xDA5f4E1cC2174A75dA63BD37606D2b7960862Cff",
        "0x9999120485f8064FF369dCDe4bA4eC1101f08E00",
        "0x0000000000000000000000000000000000000100"
      ];
      for (const addr of sampleAddresses) {
        assert.ok(ethers.isAddress(addr), `Address "${addr}" is not a valid Ethereum address according to ethers.isAddress`);
      }
    });
  });

  describe('Part F Item 6: Static verification of probe events in AgentsTab.jsx', () => {
    test('all onEmitTelemetryEvent calls in AgentsTab.jsx include isSimulated: true (expect 9)', () => {
      const agentsTabPath = path.resolve(__dirname, '../dashboard/src/components/AgentsTab.jsx');
      const content = fs.readFileSync(agentsTabPath, 'utf8');

      // Find all onEmitTelemetryEvent call blocks
      const regex = /onEmitTelemetryEvent\?\.\(\s*\{([\s\S]*?)\}\s*\)/g;
      let match;
      let callCount = 0;

      while ((match = regex.exec(content)) !== null) {
        callCount++;
        const callBody = match[1];
        const hasIsSimulatedTrue = /isSimulated:\s*true/.test(callBody);
        assert.ok(
          hasIsSimulatedTrue,
          `onEmitTelemetryEvent call #${callCount} is missing 'isSimulated: true': ${callBody.slice(0, 120)}`
        );
      }

      assert.equal(callCount, 9, `Expected exactly 9 onEmitTelemetryEvent calls in AgentsTab.jsx, found ${callCount}`);
    });
  });
});
});
