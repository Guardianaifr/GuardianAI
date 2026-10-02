/**
 * statsModel.js
 *
 * Truthful stats derivation module for GuardianAI.
 * Shared between App.jsx and tests.
 *
 * Definitions:
 * - actionsExecuted: totalActionsExecuted from Envio indexer (GuardianPolicyGuard ActionExecutedWithAttestation)
 * - threatsRegistered: totalThreatsRegistered from Envio indexer
 * - activeThreats: activeThreatCount from Envio indexer
 * - passportsTracked: totalPassportsTracked from Envio indexer
 * - cortexRootsAnchored: totalCortexRootsAnchored from Envio indexer
 *
 * Rules:
 * - "Actions executed" and "Threats registered" are kept as separate numbers.
 * - No summed total (no requests = allowed + blocked).
 * - Missing or NaN fields return null, not 0.
 * - On fetch failure or missing data, values are null and errorMessage is "Couldn't load data".
 */

function parseNullableNumber(val) {
  if (val === undefined || val === null || val === '') return null;
  const num = typeof val === 'number' ? val : Number(val);
  return isNaN(num) ? null : num;
}

export function deriveSecurityStats(rawStats = null, isFetchFailed = false) {
  if (isFetchFailed || !rawStats) {
    return {
      status: isFetchFailed ? "failed" : "empty",
      actionsExecuted: null,
      threatsRegistered: null,
      activeThreats: null,
      passportsTracked: null,
      cortexRootsAnchored: null,
      errorMessage: isFetchFailed ? "Couldn't load data" : null
    };
  }

  const actionsExecuted = parseNullableNumber(
    rawStats.totalActionsExecuted ?? rawStats.actionsExecuted ?? rawStats.allowed
  );

  const threatsRegistered = parseNullableNumber(
    rawStats.totalThreatsRegistered ?? rawStats.threatsRegistered ?? rawStats.blocked
  );

  const activeThreats = parseNullableNumber(
    rawStats.activeThreatCount ?? rawStats.activeThreats ?? rawStats.redacted
  );

  const passportsTracked = parseNullableNumber(
    rawStats.totalPassportsTracked ?? rawStats.passportsTracked ?? rawStats.admin
  );

  const cortexRootsAnchored = parseNullableNumber(
    rawStats.totalCortexRootsAnchored ?? rawStats.cortexRootsAnchored
  );

  return {
    status: "loaded",
    actionsExecuted,
    threatsRegistered,
    activeThreats,
    passportsTracked,
    cortexRootsAnchored,
    errorMessage: null
  };
}
