/**
 * Shared Delegation and Revocation Adapter Logic.
 * Used identically by AgentDelegationModal.tsx and unit tests.
 */

import { isAddress } from "ethers";

export function resolveDelegationParams(agentAddress, policyId, isDemoMode = false) {
  const cleanAgent = typeof agentAddress === "string" ? agentAddress.trim() : "";
  const cleanPolicy = typeof policyId === "string" ? policyId.trim() : "";

  if (isDemoMode) {
    return {
      agentAddress: cleanAgent || "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
      policyId: cleanPolicy || "pol_guardian_monad_policyguard_01",
      isValid: true,
      isPlaceholder: !cleanAgent || !cleanPolicy
    };
  }

  // Outside demo mode: require valid Ethereum address format via ethers.isAddress
  const isAddrValid = isAddress(cleanAgent);
  const isValid = isAddrValid && cleanPolicy.length > 0;
  return {
    agentAddress: cleanAgent,
    policyId: cleanPolicy,
    isValid,
    isPlaceholder: false
  };
}

export function createDelegationAdapters(sessionSigners, isDemoMode) {
  const addSigners = async (args) => {
    if (typeof sessionSigners?.addSessionSigners === "function") {
      return sessionSigners.addSessionSigners(args);
    }
    if (typeof sessionSigners?.addSigners === "function") {
      return sessionSigners.addSigners(args);
    }
    if (isDemoMode) {
      console.info("Privy session signers backend not active; simulating delegation for demo session.");
      return { success: true, simulated: true };
    }
    throw new Error("Privy session signers are not configured or available. Real signature delegation requires active session signers.");
  };

  const removeSigners = async (args) => {
    if (typeof sessionSigners?.removeSessionSigners === "function") {
      return sessionSigners.removeSessionSigners(args);
    }
    if (typeof sessionSigners?.removeSigners === "function") {
      return sessionSigners.removeSigners(args);
    }
    if (isDemoMode) {
      console.info("Privy session signers backend not active; simulating revocation for demo session.");
      return { success: true, simulated: true };
    }
    throw new Error("Privy session signers are not configured or available. Real signature revocation requires active session signers.");
  };

  return { addSigners, removeSigners };
}

export function validateDelegationResult(res, isDemoMode) {
  if (res?.simulated && !isDemoMode) {
    throw new Error("Simulated delegation rejected: not in demo mode.");
  }
  return {
    isDemoSimulation: Boolean(res?.simulated && isDemoMode)
  };
}

export function validateRevocationResult(res, isDemoMode) {
  if (res?.simulated && !isDemoMode) {
    throw new Error("Simulated revocation rejected: not in demo mode.");
  }
  return {
    isDemoSimulation: Boolean(res?.simulated && isDemoMode)
  };
}
