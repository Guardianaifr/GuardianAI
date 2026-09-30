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
 * Calculate the share of blocked requests.
 * If totalRequests is 0, returns "--" (never a fabricated percentage).
 */
export function calculateShareBlocked(blockedCount = 0, totalRequests = 0) {
  if (!totalRequests || totalRequests <= 0) {
    return "--";
  }
  const pct = Math.min(100, Math.max(0, (blockedCount / totalRequests) * 100));
  return `${pct.toFixed(1)}%`;
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
 * ALL COUNTS COME FROM ONE SOURCE (Single Source of Truth):
 * - If indexer stats with valid requests are supplied OR events array is empty, all counts derive from stats.
 * - Otherwise, all counts derive exclusively from the classified requestEvents array.
 * In all cases, the invariant holds: allowedCount + blockedCount + couldntVerifyCount === totalRequests.
 */
export function classifyActionOutcomes(events = [], stats = null) {
  const requestEvents = (events || []).filter(evt => !isNonRequestEvent(evt));

  // Determine single source of truth:
  const hasIndexerStats = stats && typeof stats.requests === 'number' && (stats.requests > 0 || requestEvents.length === 0);

  if (hasIndexerStats) {
    const totalRequests = Math.max(0, stats.requests || 0);
    const blockedCount = Math.min(totalRequests, Math.max(0, stats.blocked ?? 0));
    const allowedCount = Math.min(totalRequests - blockedCount, Math.max(0, stats.allowed ?? 0));
    const couldntVerifyCount = totalRequests - blockedCount - allowedCount;

    return {
      totalRequests,
      allowedCount,
      blockedCount,
      couldntVerifyCount
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

  const totalRequests = requestEvents.length;
  const allowedCount = outcomeCounts.allowed;
  const blockedCount = outcomeCounts.blocked;
  const couldntVerifyCount = outcomeCounts.unverified;

  return {
    totalRequests,
    allowedCount,
    blockedCount,
    couldntVerifyCount
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
  const eventToRecord = {
    ...eventData,
    isSimulated: Boolean(eventData.isSimulated || isDemoMode)
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
 * Simple Mode Status Indicator.
 * Returns ONLY one of four strictly permitted states:
 * 1. "No data yet" (neutral gray) when avgRiskScore is null / empty
 * 2. "Couldn't verify" (neutral gray) when couldntVerifyCount > 0
 * 3. "Attention needed" (yellow) when avgRiskScore >= 30
 * 4. "Protected" (green) when avgRiskScore < 30 and couldntVerifyCount === 0
 * 
 * FAIL CLOSED INVARIANT: NEVER returns "Protected" or green when couldntVerifyCount > 0 or in empty state.
 */
export function getSimpleStatusIndicator(avgRiskScore, couldntVerifyCount = 0) {
  if (avgRiskScore === null || avgRiskScore === undefined) {
    return {
      statusLabel: "No data yet",
      tier: "none",
      isClean: false,
      colorClass: "text-muted-foreground",
      badgeClass: "bg-muted/40 border-border/70 text-muted-foreground",
      dotClass: "bg-muted-foreground"
    };
  }

  if (couldntVerifyCount > 0) {
    return {
      statusLabel: "Couldn't verify",
      tier: "unverified",
      isClean: false,
      colorClass: "text-muted-foreground",
      badgeClass: "bg-muted/40 border-border/70 text-muted-foreground",
      dotClass: "bg-muted-foreground"
    };
  }

  if (avgRiskScore >= 30) {
    return {
      statusLabel: "Attention needed",
      tier: "attention",
      isClean: false,
      colorClass: "text-amber-400",
      badgeClass: "bg-amber-950/60 border-amber-800 text-amber-300",
      dotClass: "bg-amber-400"
    };
  }

  return {
    statusLabel: "Protected",
    tier: "protected",
    isClean: true,
    colorClass: "text-emerald-400",
    badgeClass: "bg-emerald-950/60 border-emerald-800 text-emerald-300",
    dotClass: "bg-emerald-400"
  };
}
