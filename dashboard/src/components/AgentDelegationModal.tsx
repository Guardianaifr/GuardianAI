/**
 * AgentDelegationModal.tsx
 *
 * Session-Signer delegation UI for GuardianAI.
 *
 * Uses the CORRECT @privy-io/react-auth APIs:
 *  - useSigners()        — hook that exposes addSigners() and removeSigners()
 *  - addSigners()        — grants a session signer (NOT the non-existent addSessionSigner)
 *  - removeSigners()     — revokes previously added signers
 *
 * The modal lets a supervisor wallet delegate transaction signing to an
 * AI agent address under a specific Privy Policy, and revoke that delegation.
 */

import React, { useState } from "react";
import { usePrivy, useSessionSigners } from "@privy-io/react-auth";
import { Shield, UserCheck, UserX, AlertTriangle, Loader2, X } from "lucide-react";
import {
  createDelegationAdapters,
  validateDelegationResult,
  validateRevocationResult,
  resolveDelegationParams
} from "@/lib/delegationAdapter";

interface AgentDelegationModalProps {
  /** The AI agent's Ethereum address that will be the session signer */
  agentAddress: string;
  /** The Privy Policy ID that restricts what the agent can sign */
  policyId: string;
  /** Callback to close the modal */
  onClose: () => void;
  /** Optional supervisor address fallback for demo mode */
  supervisorAddressOverride?: string;
  /** Explicit demo mode flag */
  isDemoMode?: boolean;
}

export const AgentDelegationModal: React.FC<AgentDelegationModalProps> = ({
  agentAddress,
  policyId,
  onClose,
  supervisorAddressOverride,
  isDemoMode = false,
}) => {
  const { user } = usePrivy();
  const sessionSigners = useSessionSigners();
  const [isDemoSimulation, setIsDemoSimulation] = useState(false);

  const { addSigners, removeSigners } = createDelegationAdapters(sessionSigners, isDemoMode);

  const [isDelegating, setIsDelegating] = useState(false);
  const [isRevoking, setIsRevoking] = useState(false);
  const [status, setStatus] = useState<"idle" | "delegated" | "revoked" | "error">("idle");
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const resolvedParams = resolveDelegationParams(agentAddress, policyId, isDemoMode);
  const displayAgentAddress = resolvedParams.agentAddress || "Not specified";
  const displayPolicyId = resolvedParams.policyId || "Not specified";
  const isMissingParams = !resolvedParams.isValid;

  // Supervisor wallet address from the authenticated Privy user or override
  const supervisorAddress =
    supervisorAddressOverride ??
    user?.wallet?.address ??
    user?.linkedAccounts?.find((a) => a.type === "wallet")?.address ??
    "Not connected";

  /**
   * Delegate signing authority to the AI agent.
   *
   * addSigners() is the correct method on the useSigners() hook.
   * Specification: addSigners({ address: supervisorAddress, signers: [{ signerId: displayAgentAddress, policyIds: [displayPolicyId] }] })
   * Gracefully falls back to array signature if object fails.
   */
  const handleDelegate = async () => {
    setIsDelegating(true);
    setErrorMessage(null);
    try {
      if (!resolvedParams.isValid) {
        throw new Error("Explicit agent address and policy ID are required outside demo mode. Cannot delegate to empty target.");
      }
      if (!supervisorAddress || supervisorAddress === "Not connected") {
        throw new Error("Please connect a supervisor wallet first.");
      }
      let res: any;
      try {
        // Primary: @privy-io/react-auth object specification
        res = await (addSigners as any)({
          address: supervisorAddress,
          signers: [
            {
              signerId: displayAgentAddress,
              policyIds: displayPolicyId ? [displayPolicyId] : [],
            },
          ],
        });
      } catch (primaryErr: any) {
        try {
          // Fallback: array signature format (legacy / alternate SDK variants)
          res = await (addSigners as any)([
            {
              address: displayAgentAddress,
              chainType: "ethereum",
              policyIds: displayPolicyId ? [displayPolicyId] : [],
            },
          ]);
        } catch {
          // If demo supervisor is active without live Privy login, simulate successful delegation only in demo mode
          if (supervisorAddressOverride && !user && isDemoMode) {
            console.info("Simulating successful delegation for demo supervisor session.");
            setIsDemoSimulation(true);
            setStatus("delegated");
            return;
          }
          // Preserve the primary error which reflects the standard SDK contract
          throw primaryErr;
        }
      }

      const validation = validateDelegationResult(res, isDemoMode);
      if (validation.isDemoSimulation) {
        setIsDemoSimulation(true);
      }
      setStatus("delegated");
    } catch (err: any) {
      setStatus("error");
      setErrorMessage(err?.message ?? "Delegation failed. Please try again.");
    } finally {
      setIsDelegating(false);
    }
  };

  /**
   * Revoke the AI agent's signing authority.
   *
   * Specification: removeSigners({ address: supervisorAddress })
   * Gracefully falls back to array signature if object fails.
   */
  const handleRevoke = async () => {
    setIsRevoking(true);
    setErrorMessage(null);
    try {
      if (!resolvedParams.isValid) {
        throw new Error("Explicit agent address and policy ID are required outside demo mode.");
      }
      if (!supervisorAddress || supervisorAddress === "Not connected") {
        throw new Error("Please connect a supervisor wallet first.");
      }
      let res: any;
      try {
        // Primary: @privy-io/react-auth object specification
        res = await (removeSigners as any)({
          address: supervisorAddress,
        });
      } catch (primaryErr: any) {
        try {
          // Fallback: array signature format
          res = await (removeSigners as any)([
            {
              address: displayAgentAddress,
              chainType: "ethereum",
            },
          ]);
        } catch {
          if (supervisorAddressOverride && !user && isDemoMode) {
            console.info("Simulating successful revocation for demo supervisor session.");
            setIsDemoSimulation(true);
            setStatus("revoked");
            return;
          }
          // Preserve the primary error which reflects the standard SDK contract
          throw primaryErr;
        }
      }

      const validation = validateRevocationResult(res, isDemoMode);
      if (validation.isDemoSimulation) {
        setIsDemoSimulation(true);
      }
      setStatus("revoked");
    } catch (err: any) {
      setStatus("error");
      setErrorMessage(err?.message ?? "Revocation failed. Please try again.");
    } finally {
      setIsRevoking(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm">
      <div className="relative w-full max-w-md rounded-2xl border border-purple-800/40 bg-[#0d0d14] p-6 shadow-xl shadow-purple-900/20">

        {/* Close button */}
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation();
            onClose();
          }}
          className="absolute right-4 top-4 rounded-lg p-1 text-gray-500 transition hover:bg-gray-800 hover:text-white"
          aria-label="Close"
        >
          <X className="h-5 w-5" />
        </button>

        {/* Header */}
        <div className="mb-6 flex items-center gap-3">
          <div className="flex h-10 w-10 items-center justify-center rounded-full bg-purple-900/40">
            <Shield className="h-5 w-5 text-[#836EF9]" />
          </div>
          <div>
            <h2 className="text-lg font-semibold text-white">Agent Delegation</h2>
            <p className="text-xs text-gray-400">
              Grant or revoke AI agent transaction signing rights
            </p>
          </div>
        </div>

        {/* Supervisor wallet */}
        <div className="mb-4 rounded-xl border border-gray-700/50 bg-gray-900/40 p-4">
          <p className="mb-1 text-xs font-medium text-gray-400">Supervisor Wallet</p>
          <p className="truncate font-mono text-sm text-white">{supervisorAddress}</p>
        </div>

        {/* Agent address */}
        <div className="mb-4 rounded-xl border border-gray-700/50 bg-gray-900/40 p-4">
          <p className="mb-1 text-xs font-medium text-gray-400">AI Agent Address</p>
          <p className="truncate font-mono text-sm text-[#836EF9]">{displayAgentAddress}</p>
        </div>

        {/* Policy */}
        <div className="mb-6 rounded-xl border border-gray-700/50 bg-gray-900/40 p-4">
          <p className="mb-1 text-xs font-medium text-gray-400">Privy Policy ID</p>
          <p className="truncate font-mono text-xs text-gray-300">{displayPolicyId}</p>
          <p className="mt-2 text-xs text-gray-500">
            Restricts agent to GuardianPolicyGuard on Monad Testnet (≤ 5 MON)
          </p>
        </div>

        {/* Status feedback */}
        {isDemoSimulation && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-amber-600/50 bg-amber-950/40 p-3 text-xs text-amber-200">
            <AlertTriangle className="h-4 w-4 shrink-0 text-amber-400" />
            <span>Demo mode: nothing was changed</span>
          </div>
        )}
        {status === "delegated" && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-green-700/40 bg-green-900/20 p-3">
            <UserCheck className="h-4 w-4 text-green-400" />
            <span className="text-sm text-green-300">Agent delegation active. Signing authority granted.</span>
          </div>
        )}
        {status === "revoked" && (
          <div className="mb-4 flex items-center gap-2 rounded-lg border border-amber-700/40 bg-amber-900/20 p-3">
            <UserX className="h-4 w-4 text-amber-400" />
            <span className="text-sm text-amber-300">Agent delegation revoked successfully.</span>
          </div>
        )}
        {status === "error" && errorMessage && (
          <div className="mb-4 flex items-start gap-2 rounded-lg border border-red-700/40 bg-red-900/20 p-3">
            <AlertTriangle className="mt-0.5 h-4 w-4 flex-shrink-0 text-red-400" />
            <span className="text-sm text-red-300">{errorMessage}</span>
          </div>
        )}

        {/* Inline explanation for missing explicit parameters outside demo mode */}
        {isMissingParams && (
          <div className="mb-4 flex items-start gap-2 rounded-lg border border-amber-600/50 bg-amber-950/40 p-3 text-xs text-amber-200">
            <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
            <span>
              Explicit AI Agent Address and Policy ID are required outside demo mode. Delegation and revocation are disabled to prevent actions against placeholder targets.
            </span>
          </div>
        )}

        {/* Action buttons */}
        <div className="flex gap-3">
          {/* Delegate button */}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              handleDelegate();
            }}
            disabled={isDelegating || isRevoking || status === "delegated" || isMissingParams}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl bg-[#836EF9] px-4 py-2.5 text-sm font-semibold text-white transition hover:bg-[#7560e0] disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isDelegating ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <UserCheck className="h-4 w-4" />
            )}
            {isDelegating ? "Delegating…" : "Delegate"}
          </button>

          {/* Revoke button */}
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation();
              handleRevoke();
            }}
            disabled={isDelegating || isRevoking || status !== "delegated" || isMissingParams}
            className="flex flex-1 items-center justify-center gap-2 rounded-xl border border-red-700/50 bg-red-900/20 px-4 py-2.5 text-sm font-semibold text-red-300 transition hover:bg-red-900/40 disabled:cursor-not-allowed disabled:opacity-50"
          >
            {isRevoking ? (
              <Loader2 className="h-4 w-4 animate-spin" />
            ) : (
              <UserX className="h-4 w-4" />
            )}
            {isRevoking ? "Revoking…" : "Revoke"}
          </button>
        </div>

        <p className="mt-4 text-center text-xs text-gray-600">
          Powered by Privy Session Signers · GuardianAI Policy Guard
        </p>
      </div>
    </div>
  );
};

export default AgentDelegationModal;
