/**
 * Shared Truthfulness and Verification Metrics.
 * Enforces F10 (positive evidence for allowed actions) and F1/F16 (no default green/14 scores).
 * Imported directly by DashboardTab.jsx, App.jsx, and unit tests.
 */

export const BLOCKED_EVENT_TYPES = new Set([
  "injection",
  "injection_ai",
  "threat_feed_match",
  "threat registered",
  "threat_registered",
  "policy containment",
  "policy_containment",
  "policy violation",
  "policy_violation",
  "obfuscation",
  "rate_limit",
  "data_leak"
]);

export function isBlockedEvent(evt) {
  if (!evt) return false;
  if (evt.isBlocked === true || evt.blocked === true) return true;
  const type = (evt.event_type || "").toLowerCase().trim();
  return BLOCKED_EVENT_TYPES.has(type);
}

export const NON_REQUEST_EVENT_TYPES = new Set([
  "policy deployed",
  "policy_deployed",
  "policy created",
  "policy_created",
  "system_event",
  "system",
  "config",
  "indexer_status"
]);

export function isNonRequestEvent(evt) {
  if (!evt) return false;
  const type = (evt.event_type || "").toLowerCase().trim();
  return NON_REQUEST_EVENT_TYPES.has(type);
}

/**
 * Evaluates the 3 distinct states of the passport probe:
 * 1. active: query returns true
 * 2. revoked: query returns false
 * 3. couldnt_verify: query throws an error (network failure / RPC error)
 * The catch block NEVER assumes or sets revoked.
 */
export async function evaluatePassportQuery(queryFn) {
  try {
    const isActive = await queryFn();
    if (isActive === true) {
      return {
        state: "active",
        type: "success",
        title: "Passport active (read from Monad Testnet)",
        message: "Queried Monad registry GuardianPassportSBT.isPassportActive(). Status: Active.",
        riskScore: 2
      };
    } else {
      return {
        state: "revoked",
        type: "error",
        title: "No active passport for test ID revoked-agent-01",
        message: "Queried Monad registry GuardianPassportSBT.isPassportActive(revoked-agent-01). Status: Inactive / Not Found.",
        riskScore: null
      };
    }
  } catch (error) {
    return {
      state: "couldnt_verify",
      type: "warning",
      title: "Couldn't verify (network error)",
      message: `Failed to query Monad registry GuardianPassportSBT: ${error?.message || "network error"}. Status could not be determined.`,
      riskScore: null
    };
  }
}

/**
 * Calculate session average and peak risk scores.
 * Returns null if no valid events or numeric scores exist (never defaults to 14).
 */
export function calculateRiskScores(events = []) {
  const requestEvents = events.filter(e => !isNonRequestEvent(e));
  const recentEvents = requestEvents.slice(0, 20);
  const scores = recentEvents
    .filter(e => typeof e.details?.riskScore === 'number' || (e.severity && e.severity !== 'UNKNOWN'))
    .map(e => (typeof e.details?.riskScore === 'number' ? e.details.riskScore : (e.severity === 'CRITICAL' ? 95 : e.severity === 'HIGH' ? 70 : 15)));

  const avgRiskScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : null;
  const peakRiskScore = scores.length > 0 ? Math.max(...scores) : null;

  return { avgRiskScore, peakRiskScore };
}

/**
 * F10 Action Outcome Classification.
 * CRITICAL RULE: "Allowed" MUST require an explicit status (ALLOWED, EXECUTED, or SUCCESS).
 * severity: 'INFO' alone is NOT evidence. Non-request events are excluded from request counters.
 * 
 * In the stats path, returns actionsExecuted and threatsRegistered separately.
 * Never labels threatsRegistered as "blocked".
 */
export function classifyActionOutcomes(events = [], stats = null, fetchFailed = false) {
  const requestEvents = (events || []).filter(evt => !isNonRequestEvent(evt));

  // If fetch failed, return null numbers and signal error
  if (fetchFailed) {
    return {
      fetchFailed: true,
      actionsExecuted: null,
      threatsRegistered: null,
      couldntVerifyCount: null,
      statusMessage: "Couldn't load data"
    };
  }

  // Determine single source of truth:
  const hasIndexerStats = stats && (
    typeof stats.actionsExecuted === 'number' ||
    typeof stats.threatsRegistered === 'number' ||
    typeof stats.allowed === 'number' ||
    typeof stats.requests === 'number'
  );

  if (hasIndexerStats) {
    const rawActions = stats.actionsExecuted ?? stats.allowed;
    const rawThreats = stats.threatsRegistered ?? stats.blocked;
    const actionsExecuted = typeof rawActions === 'number' ? Math.max(0, rawActions) : null;
    const threatsRegistered = typeof rawThreats === 'number' ? Math.max(0, rawThreats) : null;

    return {
      actionsExecuted,
      threatsRegistered,
      allowedCount: actionsExecuted,
      blockedCount: threatsRegistered,
      couldntVerifyCount: 0,
      statusMessage: null
    };
  }

  // Otherwise, single source is requestEvents:
  const outcomeCounts = requestEvents.reduce((acc, evt) => {
    if (!evt || evt.severity === 'ERROR' || evt.details?.status === 'UNKNOWN' || evt.event_type?.toUpperCase() === 'UNKNOWN') {
      acc.unverified++;
    } else if (isBlockedEvent(evt)) {
      acc.blocked++;
    } else {
      const status = (evt.details?.status || "").toUpperCase();
      const hasExplicitAllowedStatus = status === 'ALLOWED' || status === 'EXECUTED' || status === 'SUCCESS';

      if (evt.isBlocked === false && hasExplicitAllowedStatus) {
        acc.allowed++;
      } else {
        // Anything lacking explicit positive evidence (including bare INFO) goes to unverified
        acc.unverified++;
      }
    }
    return acc;
  }, { allowed: 0, blocked: 0, unverified: 0 });

  return {
    actionsExecuted: outcomeCounts.allowed,
    threatsRegistered: outcomeCounts.blocked,
    allowedCount: outcomeCounts.allowed,
    blockedCount: outcomeCounts.blocked,
    couldntVerifyCount: outcomeCounts.unverified,
    totalRequests: requestEvents.length,
    statusMessage: null
  };
}

/**
 * Safety Continuum Status & Fail-Closed Logic.
 * If couldntVerifyCount > 0, NEVER show a green/clean state!
 */
export function getSafetyContinuumStatus(avgRiskScore, couldntVerifyCount = 0) {
  if (avgRiskScore === null) {
    return {
      text: "Awaiting Activity (No Data Yet)",
      statusLabel: "NO DATA YET",
      tier: "none",
      isClean: false,
      colorClass: "text-muted-foreground"
    };
  }

  // FAIL CLOSED RULE:
  // If there are unverified events, NEVER render clean/green state!
  if (couldntVerifyCount > 0) {
    return {
      text: "Elevated Monitoring (Amber)",
      statusLabel: "UNVERIFIED ACTIVITY (AMBER)",
      tier: "warning",
      isClean: false,
      colorClass: "text-amber-400"
    };
  }

  if (avgRiskScore < 30) {
    return {
      text: "Optimal Protection (Green)",
      statusLabel: "NOMINAL BASELINE",
      tier: "clean",
      isClean: true,
      colorClass: "text-emerald-400"
    };
  }

  if (avgRiskScore < 70) {
    return {
      text: "Elevated Monitoring (Amber)",
      statusLabel: "ELEVATED RISK",
      tier: "warning",
      isClean: false,
      colorClass: "text-amber-400"
    };
  }

  return {
    text: "Critical Rogue Tier (Red)",
    statusLabel: "CONTAINED ATTACK",
    tier: "rogue",
    isClean: false,
    colorClass: "text-red-500"
  };
}

/**
 * Probe Event Ingestion Logic.
 * Outside demo mode, simulated probe events must NEVER mutate real production stats.
 * Non-request events (POLICY DEPLOYED, etc.) do NOT increment request counters.
 */
export function processTelemetryEvent(eventData, currentStats = { requests: 0, blocked: 0 }, isDemoMode = false) {
  if (!eventData) return { nextStats: currentStats, eventToRecord: null };
  const isSimulated = eventData.isSimulated === true;
  const eventToRecord = {
    ...eventData,
    isSimulated,
    source: eventData.source || (isSimulated ? 'simulation_probe' : 'telemetry')
  };

  // Exclude non-request administrative events from request counters
  if (isNonRequestEvent(eventData)) {
    return { nextStats: currentStats, eventToRecord };
  }

  // Outside demo mode, simulated probe events must NOT mutate real stats!
  if (!isDemoMode && eventToRecord.isSimulated) {
    return { nextStats: currentStats, eventToRecord };
  }

  const nextStats = {
    ...currentStats,
    requests: eventData.isBlocked ? (currentStats.requests || 0) : (currentStats.requests || 0) + 1,
    blocked: eventData.isBlocked ? (currentStats.blocked || 0) + 1 : (currentStats.blocked || 0)
  };

  return { nextStats, eventToRecord };
}

/**
 * Simple Mode Status Indicator & Fail-Closed Logic.
 * Strict Evaluation Order:
 * 1. HIGH/CRITICAL event, peak risk > maxAllowedRiskScore, avg risk > maxAllowedRiskScore, or blockedCount > 0 -> "Attention needed" (amber)
 * 2. couldntVerifyCount > 0 -> "Couldn't verify" (neutral gray)
 * 3. avgRiskScore is null/empty -> "No data yet" (neutral gray)
 * 4. All nominal -> "No flagged on-chain actions" (green)
 * 
 * FAIL CLOSED INVARIANT: NEVER returns green when threats exist, unverified events exist, or data is empty.
 */
export function getSimpleStatusIndicator(options = {}) {
  // Support single options object
  const {
    avgRiskScore = null,
    peakRiskScore = null,
    events = [],
    threatFeed = [],
    fetchFailed = false,
    couldntVerifyCount = 0,
    blockedCount = 0,
    maxAllowedRiskScore = 25
  } = (typeof options === 'object' && options !== null && !Array.isArray(options)) ? options : {};

  // 0. Fetch failure returns "Couldn't load data" (neutral gray)
  if (fetchFailed) {
    return {
      statusLabel: "Couldn't load data",
      description: null,
      tier: "failed",
      isClean: false,
      colorClass: "text-muted-foreground",
      badgeClass: "bg-muted/40 border-border/70 text-muted-foreground",
      dotClass: "bg-muted-foreground"
    };
  }

  const effectiveThreshold = typeof maxAllowedRiskScore === 'number' ? maxAllowedRiskScore : 25;

  // 1. Check if any recorded AgentAction target matches an ACTIVE threatFeed record
  const activeThreatAddresses = new Set(
    (Array.isArray(threatFeed) ? threatFeed : [])
      .filter(t => t && t.active === true && typeof t.address === 'string')
      .map(t => t.address.toLowerCase())
  );

  const matchedActiveThreat = (Array.isArray(events) ? events : []).find(e => {
    const target = e?.details?.target || e?.target;
    return typeof target === 'string' && activeThreatAddresses.has(target.toLowerCase());
  });

  if (matchedActiveThreat) {
    return {
      statusLabel: "Attention needed",
      description: "An agent interacted with a listed address.",
      tier: "attention",
      isClean: false,
      colorClass: "text-amber-400",
      badgeClass: "bg-amber-950/60 border-amber-800 text-amber-300",
      dotClass: "bg-amber-400"
    };
  }

  // 2. Check for elevated threat / amber conditions:
  // Contract boundary: GuardianPolicyGuard.sol:30, 48, 120 (maxAllowedRiskScore = 25 default)
  // Amber = any HIGH/CRITICAL event, a blocked event in recorded activity, blockedCount > 0, or peak/avg > effectiveThreshold.
  const hasHighOrCritical = Array.isArray(events) && events.some(e => {
    const sev = (e?.severity || "").toUpperCase();
    const risk = typeof e?.risk_score === "number" ? e.risk_score : (typeof e?.details?.riskScore === "number" ? e.details.riskScore : null);
    return sev === "CRITICAL" || sev === "HIGH" || (typeof risk === "number" && risk > effectiveThreshold);
  });
  const hasBlockedEvent = (Array.isArray(events) && events.some(e => e?.isBlocked === true)) || (typeof blockedCount === 'number' && blockedCount > 0);
  const isElevated = (typeof avgRiskScore === "number" && avgRiskScore > effectiveThreshold) ||
                     (typeof peakRiskScore === "number" && peakRiskScore > effectiveThreshold) ||
                     hasHighOrCritical ||
                     hasBlockedEvent;

  if (isElevated) {
    return {
      statusLabel: "Attention needed",
      description: null,
      tier: "attention",
      isClean: false,
      colorClass: "text-amber-400",
      badgeClass: "bg-amber-950/60 border-amber-800 text-amber-300",
      dotClass: "bg-amber-400"
    };
  }

  // 3. Couldn't verify SECOND:
  if (couldntVerifyCount > 0) {
    return {
      statusLabel: "Couldn't verify",
      description: null,
      tier: "unverified",
      isClean: false,
      colorClass: "text-muted-foreground",
      badgeClass: "bg-muted/40 border-border/70 text-muted-foreground",
      dotClass: "bg-muted-foreground"
    };
  }

  // 4. No data THIRD:
  if (avgRiskScore === null || avgRiskScore === undefined) {
    return {
      statusLabel: "No data yet",
      description: null,
      tier: "none",
      isClean: false,
      colorClass: "text-muted-foreground",
      badgeClass: "bg-muted/40 border-border/70 text-muted-foreground",
      dotClass: "bg-muted-foreground"
    };
  }

  // 5. Green LAST:
  // Because on-chain executed actions are <= the contract threshold by construction
  return {
    statusLabel: "No flagged on-chain actions",
    description: null,
    tier: "clean",
    isClean: true,
    colorClass: "text-emerald-400",
    badgeClass: "bg-emerald-950/60 border-emerald-800 text-emerald-300",
    dotClass: "bg-emerald-400"
  };
}
