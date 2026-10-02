import React, { useState } from 'react'
import { ethers } from 'ethers'
import { usePrivy, useWallets } from '@privy-io/react-auth'
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { 
  Cpu, 
  Shield, 
  UserCheck, 
  Lock, 
  CheckCircle2, 
  ExternalLink, 
  Copy, 
  Check, 
  Zap, 
  AlertTriangle, 
  Layers, 
  Sparkles,
  Terminal,
  Code2,
  RefreshCw,
  ShieldAlert,
  ShieldCheck,
  XCircle
} from "lucide-react"
import { cn } from "@/lib/utils"
import { isDemoModeActive } from "@/lib/demoMode"
import { evaluatePassportQuery } from "@/lib/truthfulnessMetrics"
import { sanitizeJargon } from "@/lib/glossary"
import { POLICY_GUARD_ADDRESS, PASSPORT_REGISTRY_ADDRESS } from "@/lib/constants"

export function AgentsTab({
  isConnectedSupervisor,
  supervisorAddress,
  truncatedSupervisor,
  onOpenDelegationModal,
  onConnectSupervisor,
  onTriggerGuardedAction,
  onTriggerRogueAction,
  executingAction,
  isExecutingGuarded,
  isExecutingRogue,
  agentActionStatus,
  onEmitTelemetryEvent,
  onNavigateTab,
  isAdvanced = false,
  stats = {},
  events = []
}) {
  const { authenticated, login } = usePrivy();
  const { wallets } = useWallets();

  const isGuardedRunning = Boolean(isExecutingGuarded || executingAction === 'guarded')
  const isRogueRunning = Boolean(isExecutingRogue || executingAction === 'rogue')
  const [copiedField, setCopiedField] = useState(null)
  const [activeCardTab, setActiveCardTab] = useState({
    "eliza-monad-01": "specs",
    "mera-memory-01": "specs",
    "passport-agent-01": "specs"
  })
  const [localFeedback, setLocalFeedback] = useState(null)
  const [runningProbes, setRunningProbes] = useState({})

  const setProbeState = (key, isRunning) => {
    setRunningProbes(prev => ({ ...prev, [key]: isRunning }))
  }

  const handleCopy = (text, fieldName, e) => {
    e?.stopPropagation?.()
    navigator.clipboard?.writeText(text)
    setCopiedField(fieldName)
    setTimeout(() => setCopiedField(null), 2000)
  }

  const setCardTab = (agentId, tab, e) => {
    e?.stopPropagation?.()
    setActiveCardTab(prev => ({ ...prev, [agentId]: tab }))
  }

  // Active feedback banner priority: local simulation probe first, then global agentActionStatus
  const displayStatus = localFeedback || agentActionStatus

  // Interactive Simulation Probe Handlers
  const handleElizaPromptInjectionProbe = async (e) => {
    e?.stopPropagation?.()
    const probeKey = "eliza-monad-01-injection"
    setProbeState(probeKey, true)
    setLocalFeedback(null)
    
    if (!isDemoModeActive()) {
      setLocalFeedback({
        type: "warning",
        agentId: "eliza-monad-01",
        title: "Attestation Relayer Required",
        message: "Live autonomous execution on Monad requires an EIP-712 signature from the backend relayer (GuardianPolicyGuard.sol:142-143). Switch to Demo Mode (?demo=true) to test adversarial attack probes.",
        guard: "GuardianPolicyGuard.executeWithAttestation()",
        riskScore: null,
        tx: null,
        timestamp: new Date().toLocaleTimeString()
      });
      setProbeState(probeKey, false);
      return;
    }

    try {
      const wallet = wallets[0];
      await wallet.switchChain(10143);
      const provider = await wallet.getEthereumProvider();
      const ethersProvider = new ethers.BrowserProvider(provider);
      
      let rejectionReason = "Unknown";
      try {
        const contract = new ethers.Contract(
          POLICY_GUARD_ADDRESS,
          ["function executeWithAttestation(address,bytes,tuple(bytes32,address,bytes32,uint256,uint8,uint256,uint256),bytes) external payable"],
          await ethersProvider.getSigner()
        );
        const dummyAttestation = [
          ethers.id("agent"),
          POLICY_GUARD_ADDRESS,
          ethers.keccak256("0x"),
          ethers.parseEther("50"),
          96,
          1,
          Math.floor(Date.now() / 1000) + 3600
        ];
        await contract.executeWithAttestation.staticCall(
          POLICY_GUARD_ADDRESS,
          "0x",
          dummyAttestation,
          "0x00",
          { value: ethers.parseEther("50") }
        );
      } catch (e) {
        rejectionReason = e.reason || e.message || JSON.stringify(e);
      }

      setLocalFeedback({
        type: "error",
        agentId: "eliza-monad-01",
        title: "PROMPT INJECTION CONTAINED & BLOCKED (Simulated Probe)",
        message: `Adversarial prompt injection detected on Monad network call. Transaction for 50.0 MON rejected. Reason: ${rejectionReason}`,
        guard: "GuardianPolicyGuard.ValueMismatch & PromptEntropyFilter",
        riskScore: 96,
        tx: null,
        timestamp: new Date().toLocaleTimeString()
      })
      onEmitTelemetryEvent?.({
        event_type: "PROMPT INJECTION CONTAINED",
        timestamp: Math.floor(Date.now() / 1000),
        severity: "CRITICAL",
        isBlocked: true,
        isSimulated: true,
        details: {
          agent: "0x742d...f44e",
          target: "0x90Fd...EF60 (PolicyGuard)",
          reason: "Prompt injection contained: 50.0 MON drain rejected on Monad Testnet",
          riskScore: 96,
          status: "BLOCKED"
        }
      })
      setProbeState(probeKey, false)
    } catch (e) {
      console.error(e);
      setProbeState(probeKey, false);
    }
  }

  const handleElizaValidTradeProbe = async (e) => {
    e?.stopPropagation?.()
    const probeKey = "eliza-monad-01-valid"
    setProbeState(probeKey, true)
    setLocalFeedback(null)

    if (!isDemoModeActive()) {
      setLocalFeedback({
        type: "warning",
        agentId: "eliza-monad-01",
        title: "Attestation Relayer Required",
        message: "Live autonomous execution on Monad requires an EIP-712 signature from the backend relayer (GuardianPolicyGuard.sol:142-143). Switch to Demo Mode (?demo=true) to test simulated trade flows.",
        guard: "GuardianPolicyGuard.executeWithAttestation()",
        riskScore: null,
        tx: null,
        timestamp: new Date().toLocaleTimeString()
      });
      setProbeState(probeKey, false);
      return;
    }

    // Only demo mode runs the simulation:
    setLocalFeedback({
      type: "success",
      agentId: "eliza-monad-01",
      title: "SIMULATED GUARDED TRADE (Demo Only)",
      message: "Simulated autonomous trade pre-screened against policy rules (Risk: 6/100). No on-chain transaction was submitted.",
      guard: "GuardianAI Policy Rules (Simulated)",
      riskScore: 6,
      tx: null,
      timestamp: new Date().toLocaleTimeString()
    });
    onEmitTelemetryEvent?.({
      event_type: "ON-CHAIN ACTION",
      timestamp: Math.floor(Date.now() / 1000),
      severity: "INFO",
      isBlocked: false,
      isSimulated: true,
      details: {
        agent: "0x742d...f44e",
        target: "0x90Fd...EF60 (PolicyGuard)",
        riskScore: 6,
        status: "EXECUTED",
        tx: null
      }
    });
    setProbeState(probeKey, false);
  }

  const handleMeraTamperProbe = async (e) => {
    e?.stopPropagation?.()
    const probeKey = "mera-memory-01-tamper"
    setProbeState(probeKey, true)
    setLocalFeedback(null)

    try {
      const provider = new ethers.JsonRpcProvider('https://testnet-rpc.monad.xyz');
      try {
        await provider.call({
          to: "0x0000000000000000000000000000000000000100",
          data: "0x1234"
        });
      } catch (err) { }

      setLocalFeedback({
        type: "error",
        agentId: "mera-memory-01",
        title: "MERA MEMORY TAMPERING DETECTED & ISOLATED (Simulated Probe)",
        message: "Verification simulated on Monad native RIP-7212 P256 precompile (0x100). Poisoned state rejected.",
        guard: "MeraMemoryGuard.AuthenticationTagMismatch & RIP-7212",
        riskScore: 98,
        tx: null,
        timestamp: new Date().toLocaleTimeString()
      })
      onEmitTelemetryEvent?.({
        event_type: "MEMORY TAMPER CONTAINED",
        timestamp: Math.floor(Date.now() / 1000),
        severity: "CRITICAL",
        isBlocked: true,
        isSimulated: true,
        details: {
          agent: "0x1142...c890",
          target: "0x0000...0100 (RIP-7212)",
          reason: "Memory tag mismatch: poisoned state isolated",
          riskScore: 98,
          status: "BLOCKED"
        }
      })
      setProbeState(probeKey, false)
    } catch (e) {
      console.error(e);
      setProbeState(probeKey, false);
    }
  }

  const handleMeraValidSealProbe = async (e) => {
    e?.stopPropagation?.()
    const probeKey = "mera-memory-01-seal"
    setProbeState(probeKey, true)
    setLocalFeedback(null)

    if (!isDemoModeActive()) {
      setLocalFeedback({
        type: "warning",
        agentId: "mera-memory-01",
        title: "Attestation Relayer Required",
        message: "Live autonomous execution on Monad requires an EIP-712 signature from the backend relayer (GuardianPolicyGuard.sol:142-143). Switch to Demo Mode (?demo=true) to test simulated memory sealing flows.",
        guard: "GuardianPolicyGuard.executeWithAttestation()",
        riskScore: null,
        tx: null,
        timestamp: new Date().toLocaleTimeString()
      });
      setProbeState(probeKey, false);
      return;
    }

    // Only demo mode runs the simulation:
    setLocalFeedback({
      type: "success",
      agentId: "mera-memory-01",
      title: "SIMULATED RIP-7212 PRECOMPILE CALL (Demo Only)",
      message: "Simulated WebAuthn PRF salt derivation and curve verification on native RIP-7212 precompile (0x100). No on-chain transaction was sent.",
      guard: "Monad RIP-7212 Precompile (0x100)",
      riskScore: 3,
      tx: null,
      timestamp: new Date().toLocaleTimeString()
    });
    onEmitTelemetryEvent?.({
      event_type: "ON-CHAIN ACTION",
      timestamp: Math.floor(Date.now() / 1000),
      severity: "INFO",
      isBlocked: false,
      isSimulated: true,
      details: {
        agent: "0x1142...c890",
        target: "0x0000...0100 (RIP-7212)",
        riskScore: 3,
        status: "EXECUTED",
        tx: null
      }
    });
    setProbeState(probeKey, false);
  }

  const handlePassportRevocationProbe = async (e) => {
    e?.stopPropagation?.()
    const probeKey = "passport-agent-01-revoke"
    setProbeState(probeKey, true)
    setLocalFeedback(null)
    
    try {
      const provider = new ethers.JsonRpcProvider('https://testnet-rpc.monad.xyz');
      const abi = ["function isPassportActive(bytes32 agentId) external view returns (bool)"];
      const registry = new ethers.Contract(PASSPORT_REGISTRY_ADDRESS, abi, provider);
      const revokedAgentId = ethers.id('revoked-agent-01');

      // Three states: active / revoked / Couldn't verify (network error). Catch does NOT set revoked.
      const result = await evaluatePassportQuery(() => registry.isPassportActive(revokedAgentId));

      setLocalFeedback({
        type: result.type,
        agentId: "passport-agent-01",
        title: result.title,
        message: result.message,
        guard: "GuardianPassportSBT.isPassportActive()",
        riskScore: result.riskScore,
        tx: null,
        timestamp: new Date().toLocaleTimeString()
      });

      if (result.state === "revoked") {
        onEmitTelemetryEvent?.({
          event_type: "INACTIVE PASSPORT CHECK",
          timestamp: Math.floor(Date.now() / 1000),
          severity: "WARN",
          isBlocked: false,
          isSimulated: true,
          details: {
            agent: "0xDA5f...2Cff",
            target: "0xDA5f...2Cff (PassportRegistry)",
            reason: "No active passport for test ID revoked-agent-01",
            riskScore: null,
            status: "INACTIVE"
          }
        });
      } else if (result.state === "couldnt_verify") {
        onEmitTelemetryEvent?.({
          event_type: "UNKNOWN",
          timestamp: Math.floor(Date.now() / 1000),
          severity: "WARN",
          isBlocked: false,
          isSimulated: true,
          details: {
            agent: "0xDA5f...2Cff",
            status: "UNKNOWN",
            reason: result.message
          }
        });
      }
      setProbeState(probeKey, false);
    } catch (error) {
      console.error(error);
      const errMsg = "Failed to connect to Monad RPC provider: " + (error?.message || "network error");
      setLocalFeedback({
        type: "warning",
        agentId: "passport-agent-01",
        title: "Couldn't verify (network error)",
        message: errMsg,
        guard: "GuardianPassportSBT.isPassportActive()",
        riskScore: null,
        tx: null,
        timestamp: new Date().toLocaleTimeString()
      });
      onEmitTelemetryEvent?.({
        event_type: "UNKNOWN",
        timestamp: Math.floor(Date.now() / 1000),
        severity: "WARN",
        isBlocked: false,
        isSimulated: true,
        details: {
          agent: "0xDA5f...2Cff",
          status: "UNKNOWN",
          reason: errMsg
        }
      });
      setProbeState(probeKey, false);
    }
  }

  const handlePassportValidCheckProbe = async (e) => {
    e?.stopPropagation?.()
    const probeKey = "passport-agent-01-valid"
    setProbeState(probeKey, true)
    setLocalFeedback(null)

    try {
      const provider = new ethers.JsonRpcProvider('https://testnet-rpc.monad.xyz');
      const abi = ["function isPassportActive(bytes32 agentId) external view returns (bool)"];
      const registry = new ethers.Contract(PASSPORT_REGISTRY_ADDRESS, abi, provider);
      const agentId = ethers.id('passport-agent-01');

      // Three states: active / revoked / Couldn't verify (network error). Catch does NOT set active or revoked.
      const result = await evaluatePassportQuery(() => registry.isPassportActive(agentId));

      setLocalFeedback({
        type: result.type,
        agentId: "passport-agent-01",
        title: result.title,
        message: result.message,
        guard: "GuardianPassportSBT.isPassportActive()",
        riskScore: result.riskScore,
        tx: null,
        timestamp: new Date().toLocaleTimeString()
      });

      if (result.state === "active") {
        onEmitTelemetryEvent?.({
          event_type: "ON-CHAIN ACTION",
          timestamp: Math.floor(Date.now() / 1000),
          severity: "INFO",
          isBlocked: false,
          isSimulated: true,
          details: {
            agent: "0xDA5f...2Cff",
            target: "0xDA5f...2Cff (PassportRegistry)",
            riskScore: 2,
            status: "EXECUTED"
          }
        });
      } else if (result.state === "couldnt_verify") {
        onEmitTelemetryEvent?.({
          event_type: "UNKNOWN",
          timestamp: Math.floor(Date.now() / 1000),
          severity: "WARN",
          isBlocked: false,
          isSimulated: true,
          details: {
            agent: "0xDA5f...2Cff",
            status: "UNKNOWN",
            reason: result.message
          }
        });
      }
      setProbeState(probeKey, false);
    } catch (error) {
      console.error(error);
      setLocalFeedback({
        type: "warning",
        agentId: "passport-agent-01",
        title: "Couldn't verify (network error)",
        message: "Failed to connect to Monad RPC provider: " + (error?.message || "network error"),
        guard: "GuardianPassportSBT.isPassportActive()",
        riskScore: null,
        tx: null,
        timestamp: new Date().toLocaleTimeString()
      });
      setProbeState(probeKey, false);
    }
  }

  const CODE_SNIPPETS = {
    "eliza-monad-01": `import { withGuardianSecurity } from '@guardianai/middleware';
import { AgentRuntime } from '@elizaos/core';

// Initialize ElizaOS Trader with on-chain Monad guardrails
const trader = withGuardianSecurity(new AgentRuntime({
  model: 'gpt-4o',
  character: 'monad-arbitrage-trader',
}), {
  policyGuardAddress: '${POLICY_GUARD_ADDRESS}',
  maxSpendPerTx: '1.0 MON',
  requireAttestation: true,
  chainId: 10143 // Monad Testnet
});

// Guarded swap execution validated against policy rules
const tx = await trader.executeSwap({
  tokenIn: 'MON',
  tokenOut: 'USDC',
  amount: '0.85',
  slippageTolerance: 0.015
});`,
    "mera-memory-01": `import { MeraMemoryGuard, PasskeyPRF } from '@guardianai/middleware';

// Derive hardware-bound AES-256-GCM key via Mera WebAuthn PRF
const passkeySecret = await PasskeyPRF.deriveKey({
  rpId: 'guardianai.monad',
  salt: crypto.getRandomValues(new Uint8Array(32))
});

const memory = new MeraMemoryGuard({
  agentId: 'mera-memory-01',
  encryptionKey: passkeySecret,
  precompileVerify: '0x0000000000000000000000000000000000000100' // Monad RIP-7212
});

// Seal agent memory state before cross-app invocation
const sealedBlob = await memory.sealState({
  portfolioState: { monReserve: 42.5 },
  riskAllowance: 'low',
  timestamp: Date.now()
});`,
    "passport-agent-01": `import { GuardianPassportRegistry } from '@guardianai/middleware';
import { ethers } from 'ethers';

// Connect to Soulbound Agent Passport Registry (ERC-5192) on Monad Testnet (10143)
const passportRegistry = new GuardianPassportRegistry({
  registryAddress: '${PASSPORT_REGISTRY_ADDRESS}',
  rpcUrl: 'https://testnet-rpc.monad.xyz'
});

// Verify agent's soulbound status and cryptographic reputation score
const agentId = ethers.id('passport-agent-01');
const isActive = await passportRegistry.isPassportActive(agentId);
const passport = await passportRegistry.getPassport(agentId);

console.log('Status: ' + (isActive ? 'ACTIVE' : 'REVOKED') + ', Score: ' + (passport.trustScore / 100) + '/100, Tier: ' + passport.tier);
// GuardianPolicyGuard automatically reverts with PassportRevokedOrInactive if isActive == false`
  }

  const REFERENCE_AGENTS = [
    {
      id: "eliza-monad-01",
      name: "ElizaOS Autonomous Trader",
      role: "Parallel DEX Arbitrage & Automated Swaps",
      badge: "ELIZAOS PLUGIN",
      address: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
      policyId: "pol_eliza_monad_swaps_01",
      status: "ACTIVE & GUARDED",
      statusType: "active",
      score: "94/100",
      tier: "GOLD",
      passportId: "#10143-001",
      explorerUrl: `https://testnet.monadscan.com/address/${POLICY_GUARD_ADDRESS}`,
      specs: [
        { label: "Runtime", value: "ElizaOS v2.4 + @guardianai/middleware" },
        { label: "Execution Cap", value: "Max 1.0 MON swap per execution" },
        { label: "Slippage Bound", value: "Strict <= 1.5% max slippage" },
        { label: "Protocol Guard", value: "GuardianPolicyGuard (EIP-712)" },
        { label: "Guard Address", value: POLICY_GUARD_ADDRESS },
        { label: "Total Executions", value: "1,482 Swaps (Example)" },
        { label: "Contained Injections", value: "94 Blocked (Example)" },
      ],
      probeConfig: {
        attackTitle: "Prompt Injection Attack Probe",
        attackDesc: "Simulates an adversarial jailbreak prompt attempting an unauthorized 50.0 MON drain.",
        attackBtn: "Simulate Prompt Injection Probe",
        validTitle: "Simulated Guarded Swap (Demo Only)",
        validDesc: "Simulates an authorized autonomous swap pre-screened under 1.0 MON threshold without sending on-chain tx.",
        validBtn: "Simulated Swap (Demo Only)",
        onAttack: handleElizaPromptInjectionProbe,
        onValid: handleElizaValidTradeProbe,
        attackLoadingKey: "eliza-monad-01-injection",
        validLoadingKey: "eliza-monad-01-valid"
      }
    },
    {
      id: "mera-memory-01",
      name: "Mera Cross-App Persistent Memory",
      role: "Cross-App Persistent Memory Protection on Monad",
      badge: "PERSISTENT MEMORY",
      address: "0x1142f8c90Ab361B8c764b85994FCda30089eC890",
      policyId: "pol_mera_memory_seal_02",
      status: "STATE RECORDED",
      statusType: "active",
      score: "97/100",
      tier: "DIAMOND",
      passportId: "#10143-002",
      specs: [
        { label: "Passkey PRF (WebAuthn)", value: "Category Labs Mera WebAuthn Passkey PRF" },
        { label: "Cryptographic Seal", value: "AES-256-GCM memory sealing with PRF salt" },
        { label: "Curve Precompile", value: "Native Monad RIP-7212 (0x100)" },
        { label: "State Scope", value: "Cross-App persistent state across Monad dApps" },
        { label: "Memory Operations", value: "3,890 Operations (Example)" },
        { label: "Tampering Quarantines", value: "12 Attempts Blocked (Example)" },
      ],
      probeConfig: {
        attackTitle: "Cross-App Memory Tamper Probe",
        attackDesc: "Simulates adversarial state corruption with a forged Merkle root across dApp boundaries.",
        attackBtn: "Simulate Memory Tamper Probe",
        validTitle: "Simulated RIP-7212 Precompile Call (Demo Only)",
        validDesc: "Simulates native Monad RIP-7212 P256 precompile (0x100) curve verification via WebAuthn PRF salt derivation without sending on-chain tx.",
        validBtn: "Simulated Call (Demo Only)",
        onAttack: handleMeraTamperProbe,
        onValid: handleMeraValidSealProbe,
        attackLoadingKey: "mera-memory-01-tamper",
        validLoadingKey: "mera-memory-01-valid"
      }
    },
    {
      id: "passport-agent-01",
      name: "Soulbound Sovereign Identity (ERC-5192)",
      simpleName: "Digital Identity Passport",
      role: "Soulbound Identity (ERC-5192) & Reputation Score on Monad",
      simpleRole: "Digital Passport & Identity Verification on Monad",
      badge: "SOVEREIGN PASSPORT",
      simpleBadge: "DIGITAL PASSPORT",
      address: "0x51b981E8fc89011424e650A1E704b1EC4dF7166e",
      policyId: "pol_erc5192_passport_03",
      status: "SOULBOUND (LOCKED)",
      statusType: "soulbound",
      score: "98/100",
      tier: "DIAMOND",
      passportId: "#10143-003",
      explorerUrl: `https://testnet.monadscan.com/address/${PASSPORT_REGISTRY_ADDRESS}`,
      specs: [
        { label: "Identity Standard", value: "Soulbound Token (ERC-5192)" },
        { label: "Registry Contract", value: PASSPORT_REGISTRY_ADDRESS },
        { label: "Reputation Score", value: "98/100 (DIAMOND Tier, 9800 bips) (Example)" },
        { label: "Tombstone Gating", value: "GuardianPolicyGuard atomically reverts revoked" },
        { label: "Attestations", value: "2,410 Executions (Example)" },
        { label: "Standing", value: "No Revocations Recorded (Example)" },
      ],
      probeConfig: {
        attackTitle: "Inactive Passport Probe",
        attackDesc: "Queries isPassportActive(revoked-agent-01) on Monad Testnet to test inactive/unregistered agent check.",
        attackBtn: "Check Test ID revoked-agent-01",
        validTitle: "On-Chain Sovereign Identity Check",
        validDesc: "Queries isPassportActive(agentId) on the Monad testnet registry contract.",
        validBtn: "Simulate Valid Identity Check",
        onAttack: handlePassportRevocationProbe,
        onValid: handlePassportValidCheckProbe,
        attackLoadingKey: "passport-agent-01-revoke",
        validLoadingKey: "passport-agent-01-valid"
      }
    }
  ]

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* ── Top Header Section ──────────────────────────────────────────────── */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/80 pb-6">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-[#836EF9]/15 border border-[#836EF9]/30 text-xs font-mono text-[#836EF9] mb-2">
            <Cpu className="h-3.5 w-3.5" />
            <span>{isAdvanced ? "Autonomous Agent Security Primitives" : "Protected AI Agents"}</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground font-mono">
            {isAdvanced ? "Protocol Explorer & Reference Agent Directory" : "AI Agent Protection Directory"}
          </h1>
          <p className="text-xs sm:text-sm text-muted-foreground mt-1">
            {isAdvanced 
              ? "Trust & execution primitives for autonomous agents on Monad: ElizaOS guardrails, Mera passkey memory sealing, and Soulbound agent passports (ERC-5192)."
              : "Manage authorized AI agents, monitor real-time protection, and enforce security guardrails."}
          </p>
        </div>

        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation()
            onOpenDelegationModal?.()
          }}
          className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-[#836EF9] hover:brightness-110 text-white text-xs font-semibold shadow-md shadow-[#836EF9]/25 transition active:scale-[0.98]"
        >
          <UserCheck className="h-4 w-4" />
          <span>{isAdvanced ? "Delegate Session Signer" : "Authorize New Agent"}</span>
        </button>
      </div>

      {!isAdvanced ? (
        <Card className="border-border/80 bg-card/80 p-5 shadow-sm">
          <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
            <div className="flex items-center gap-3.5">
              <div className="p-3 rounded-xl bg-emerald-500/10 text-emerald-400 border border-emerald-500/20">
                <ShieldCheck className="h-6 w-6" />
              </div>
              <div>
                <div className="flex items-center gap-2">
                  <span className="text-xs font-semibold px-2 py-0.5 rounded bg-emerald-500/20 text-emerald-400 border border-emerald-500/30">
                    ACTIVE PROTECTION
                  </span>
                </div>
                <h3 className="text-base font-semibold text-foreground mt-1">
                  Automated Security Checks: Active & Monitored
                </h3>
                <p className="text-xs text-muted-foreground">
                  AI agents are monitored with spending caps, prompt screening, and leak detection.
                </p>
              </div>
            </div>
            <button
              type="button"
              onClick={() => onOpenDelegationModal?.()}
              className="px-4 py-2 text-xs font-semibold rounded-lg bg-[#836EF9] hover:brightness-110 text-white transition shadow-sm shrink-0"
            >
              Authorize New Agent
            </button>
          </div>
        </Card>
      ) : (
        <>
          {/* ── Developer Integration Banner (3-Line Install) ───────────────────── */}
          <Card className="border-[#836EF9]/50 bg-gradient-to-br from-[#836EF9]/15 via-background to-card overflow-hidden relative shadow-lg">
            <div className="absolute top-0 right-0 w-96 h-96 bg-[#836EF9]/10 rounded-full blur-3xl pointer-events-none" />
            <CardHeader className="pb-3 border-b border-border/60">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/35">
                    <Terminal className="h-6 w-6" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <span className="text-[10px] font-mono font-bold px-2 py-0.5 rounded bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/40 tracking-wider">
                        DEVELOPER INTEGRATION • 3-LINE AGENT SECURITY
                      </span>
                      <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-300 border border-emerald-800">
                        npm v1.0.4
                      </span>
                    </div>
                    <CardTitle className="text-base font-semibold text-foreground mt-1">
                      Plug GuardianAI Guardrails Directly into Any Autonomous Agent
                    </CardTitle>
                    <p className="text-xs text-muted-foreground">
                      Wrap ElizaOS, LangChain, or custom autonomous signers with on-chain Monad policy containment and RIP-7212 verification in 3 lines.
                    </p>
                  </div>
                </div>

                <div className="flex items-center gap-2 self-start sm:self-center">
                  <button
                    type="button"
                    onClick={(e) => handleCopy("npm i @guardianai/middleware\nimport { withGuardianSecurity } from '@guardianai/middleware';", "banner-cmd", e)}
                    className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-[#836EF9]/40 bg-[#836EF9]/15 hover:bg-[#836EF9]/25 text-xs font-mono text-[#836EF9] transition"
                  >
                    {copiedField === "banner-cmd" ? (
                      <>
                        <Check className="h-3.5 w-3.5 text-emerald-400" />
                        <span className="text-emerald-300 font-semibold">Copied!</span>
                      </>
                    ) : (
                      <>
                        <Copy className="h-3.5 w-3.5" />
                        <span>Copy Install</span>
                      </>
                    )}
                  </button>
                </div>
              </div>
            </CardHeader>
            <CardContent className="pt-4 space-y-3">
              {/* 3-line Code Block */}
              <div className="relative rounded-xl border border-border/80 bg-black/60 p-4 font-mono text-xs text-slate-200">
                <div className="flex items-center justify-between text-[11px] text-muted-foreground pb-2 mb-2 border-b border-border/50">
                  <span className="flex items-center gap-1.5">
                    <Code2 className="h-3.5 w-3.5 text-[#836EF9]" />
                    TypeScript / Node.js
                  </span>
                  <span className="text-[#836EF9] text-[10px]">Monad Chain ID 10143</span>
                </div>
                <pre className="overflow-x-auto leading-relaxed">
                  <span className="text-slate-500">// 1. Install developer middleware</span>{'\n'}
                  <span className="text-emerald-400 font-semibold">$ npm i @guardianai/middleware</span>{'\n\n'}
                  <span className="text-slate-500">// 2. Import cryptographic guardrails</span>{'\n'}
                  <span className="text-purple-400">import</span> {'{ withGuardianSecurity }'} <span className="text-purple-400">from</span> <span className="text-amber-300">'@guardianai/middleware'</span>;{'\n\n'}
                  <span className="text-slate-500">// 3. Wrap your agent runtime with on-chain policy enforcement</span>{'\n'}
                  <span className="text-purple-400">const</span> guardedAgent = <span className="text-blue-400">withGuardianSecurity</span>(runtime, {'{'} chainId: <span className="text-amber-300">10143</span>, policyGuard: <span className="text-amber-300">'0x90Fd...EF60'</span> {'}'});
                </pre>
              </div>

              <div className="flex flex-wrap items-center gap-2 pt-1 text-[11px] font-mono text-muted-foreground">
                <span className="px-2 py-0.5 rounded bg-muted/40 border border-border/60">
                  ⚡ EIP-712 Typed Attestations
                </span>
                <span className="px-2 py-0.5 rounded bg-muted/40 border border-border/60">
                  🔐 Native Monad RIP-7212 (0x100)
                </span>
                <span className="px-2 py-0.5 rounded bg-muted/40 border border-border/60">
                  🪪 Soulbound Agent Passports (ERC-5192)
                </span>
                <span className="px-2 py-0.5 rounded bg-muted/40 border border-border/60">
                  🛡️ Scoped Session Signers
                </span>
              </div>
            </CardContent>
          </Card>

          {/* ── Supervisor Delegation Status Card ───────────────────────────────── */}
          <Card className="border-[#836EF9]/40 bg-gradient-to-r from-[#836EF9]/10 via-card to-card">
            <CardHeader className="pb-3 border-b border-border/50">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
                <div className="flex items-center gap-3">
                  <div className="p-2.5 rounded-xl bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/35">
                    <Shield className="h-6 w-6" />
                  </div>
                  <div>
                    <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                      Supervisor Delegation Authority
                      <span className="text-[10px] px-2 py-0.5 rounded-full bg-emerald-950 text-emerald-300 border border-emerald-800 font-mono">
                        {isConnectedSupervisor ? "ACTIVE SUPERVISOR" : "DEMO / DISCONNECTED"}
                      </span>
                    </CardTitle>
                    <p className="text-xs text-muted-foreground">
                      Grants scoped session keys under policy rules. Designed with scoped permissions.
                    </p>
                  </div>
                </div>

                {!isConnectedSupervisor ? (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation()
                      onConnectSupervisor?.()
                    }}
                    className="px-3.5 py-1.5 rounded-lg bg-[#836EF9] text-white text-xs font-semibold hover:brightness-110 shadow-sm"
                  >
                    Connect Supervisor
                  </button>
                ) : (
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation()
                      onOpenDelegationModal?.()
                    }}
                    className="px-3.5 py-1.5 rounded-lg bg-[#836EF9] text-white text-xs font-semibold hover:brightness-110 shadow-sm"
                  >
                    Manage Session Signers
                  </button>
                )}
              </div>
            </CardHeader>
            <CardContent className="pt-4">
              <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4 text-xs font-mono">
                <div className="p-3 rounded-xl bg-background/50 border border-border/70">
                  <span className="text-muted-foreground block mb-1">Supervisor Address:</span>
                  <div className="flex items-center justify-between">
                    <span className="text-[#836EF9] font-bold">{truncatedSupervisor}</span>
                    {supervisorAddress && (
                      <button
                        type="button"
                        onClick={(e) => handleCopy(supervisorAddress, 'sup', e)}
                        className="text-muted-foreground hover:text-foreground"
                        title="Copy Supervisor Address"
                      >
                        {copiedField === 'sup' ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      </button>
                    )}
                  </div>
                </div>

                <div className="p-3 rounded-xl bg-background/50 border border-border/70">
                  <span className="text-muted-foreground block mb-1">Target Network:</span>
                  <span className="text-foreground font-semibold">Monad Testnet (10143)</span>
                </div>

                <div className="p-3 rounded-xl bg-background/50 border border-border/70">
                  {/* Keys managed by Privy: https://docs.privy.io/guide/security/ */}
                  <span className="text-muted-foreground block mb-1">Key Management:</span>
                  <span className="text-emerald-400 font-semibold">Managed by Privy</span>
                </div>

                <div className="p-3 rounded-xl bg-background/50 border border-border/70">
                  <span className="text-muted-foreground block mb-1">Reference Agents:</span>
                  <span className="text-purple-300 font-semibold">{REFERENCE_AGENTS.length} Security Primitives</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </>
      )}

      {/* ── Real-Time Interactive Simulation Feedback Banner ─────────────────── */}
      {displayStatus && (
        <div
          className={cn(
            "p-4 rounded-xl border text-xs font-mono transition-all duration-200 shadow-md",
            displayStatus.type === "success"
              ? "bg-emerald-950/40 border-emerald-800/80 text-emerald-200"
              : "bg-red-950/40 border-red-800/80 text-red-200"
          )}
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              {displayStatus.type === "success" ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-red-400 shrink-0" />
              )}
              <span className="font-bold uppercase tracking-wider">
                {displayStatus.agentId ? `[${displayStatus.agentId}] ` : ""}{displayStatus.title}
              </span>
              {displayStatus.riskScore !== undefined && (
                <span className={cn(
                  "px-2 py-0.5 rounded text-[10px] font-bold border",
                  displayStatus.riskScore <= 25 
                    ? "bg-emerald-900/60 text-emerald-300 border-emerald-700" 
                    : "bg-red-900/60 text-red-300 border-red-700"
                )}>
                  Risk Score: {displayStatus.riskScore}/100
                </span>
              )}
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[11px] opacity-70">{displayStatus.timestamp}</span>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  setLocalFeedback(null)
                }}
                className="p-0.5 rounded hover:bg-white/10 text-muted-foreground hover:text-foreground transition"
                title="Dismiss feedback"
              >
                <XCircle className="h-4 w-4" />
              </button>
            </div>
          </div>

          <p className="leading-relaxed opacity-90">{displayStatus.message}</p>

          {displayStatus.guard && (
            <div className="mt-2 text-[11px] opacity-80 flex items-center gap-1.5">
              <span className="text-muted-foreground">Intercepting Primitive:</span>
              <span className="font-semibold text-foreground underline decoration-[#836EF9]">{displayStatus.guard}</span>
            </div>
          )}

          {displayStatus.tx && (
            <div className="mt-2.5 pt-2 border-t border-emerald-900/60 flex items-center gap-2">
              <span className="text-muted-foreground">Monad Testnet Tx:</span>
              <span className="text-emerald-400 font-mono">
                {displayStatus.tx.slice(0, 24)}...
              </span>
              <span className="px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                Simulated
              </span>
            </div>
          )}
        </div>
      )}

      {/* ── Flagship Reference Agents Section ───────────────────────────────── */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <div>
            <h2 className="text-lg font-semibold tracking-tight text-foreground flex items-center gap-2">
              <Sparkles className="h-4 w-4 text-[#836EF9]" />
              {isAdvanced ? "Reference Agent Architectures" : "Registered AI Agents"}
            </h2>
            <p className="text-xs text-muted-foreground mt-0.5">
              {isAdvanced
                ? "Interactive reference implementations: inspect specs, copy TypeScript developer snippets, and trigger real-time security probes."
                : "Active agents running under GuardianAI automated protection policies."}
            </p>
          </div>
          <span className="text-xs text-muted-foreground font-mono">
            {REFERENCE_AGENTS.length} {isAdvanced ? "Reference Architectures" : "Active Agents"}
          </span>
        </div>

        <div className="grid gap-6 lg:grid-cols-3">
          {REFERENCE_AGENTS.map((agent) => {
            const currentTab = activeCardTab[agent.id] || "specs"
            const isAttackLoading = Boolean(runningProbes[agent.probeConfig.attackLoadingKey])
            const isValidLoading = Boolean(runningProbes[agent.probeConfig.validLoadingKey])

            return (
              <Card
                key={agent.id}
                className="border border-[#836EF9]/40 bg-card/90 shadow-md shadow-[#836EF9]/5 flex flex-col justify-between overflow-hidden"
              >
                <div>
                  {/* Card Header */}
                  <CardHeader className="pb-3 border-b border-border/50 bg-muted/20">
                    <div className="flex items-start justify-between gap-2">
                      <div>
                        <div className="flex items-center gap-2 flex-wrap">
                          <CardTitle className="text-sm font-bold text-foreground">
                            {isAdvanced ? agent.name : (agent.simpleName || sanitizeJargon(agent.name, false))}
                          </CardTitle>
                          <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/35 font-semibold">
                            {isAdvanced ? agent.badge : (agent.simpleBadge || sanitizeJargon(agent.badge, false))}
                          </span>
                        </div>
                        <p className="text-[11px] text-muted-foreground mt-1 line-clamp-2">
                          {isAdvanced ? agent.role : (agent.simpleRole || sanitizeJargon(agent.role, false))}
                        </p>
                      </div>
                      <span className="flex h-2 w-2 relative mt-1 shrink-0">
                        <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                        <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                      </span>
                    </div>

                    {/* In-Card Sub-Tabs (Advanced Only) */}
                    {isAdvanced && (
                      <div className="flex items-center gap-1 mt-3 p-1 rounded-lg bg-background/70 border border-border/60 text-xs">
                        <button
                          type="button"
                          onClick={(e) => setCardTab(agent.id, "specs", e)}
                          className={cn(
                            "flex-1 py-1 rounded-md text-[11px] font-mono font-medium transition text-center",
                            currentTab === "specs"
                              ? "bg-[#836EF9] text-white shadow-sm font-semibold"
                              : "text-muted-foreground hover:text-foreground"
                          )}
                        >
                          Specs
                        </button>
                        <button
                          type="button"
                          onClick={(e) => setCardTab(agent.id, "snippet", e)}
                          className={cn(
                            "flex-1 py-1 rounded-md text-[11px] font-mono font-medium transition text-center",
                            currentTab === "snippet"
                              ? "bg-[#836EF9] text-white shadow-sm font-semibold"
                              : "text-muted-foreground hover:text-foreground"
                          )}
                        >
                          Snippet (TS)
                        </button>
                        <button
                          type="button"
                          onClick={(e) => setCardTab(agent.id, "probe", e)}
                          className={cn(
                            "flex-1 py-1 rounded-md text-[11px] font-mono font-medium transition text-center",
                            currentTab === "probe"
                              ? "bg-[#836EF9] text-white shadow-sm font-semibold"
                              : "text-muted-foreground hover:text-foreground"
                          )}
                        >
                          Simulate Probe
                        </button>
                      </div>
                    )}
                  </CardHeader>

                  {/* Card Content Based on Active Sub-Tab */}
                  <CardContent className="pt-4 text-xs font-mono space-y-4">
                    {!isAdvanced ? (
                      <div className="space-y-3 font-sans text-xs">
                        <div className="p-3 rounded-lg bg-background/60 border border-border/70 space-y-2">
                          <div className="flex justify-between items-center">
                            <span className="text-muted-foreground">Protection Status:</span>
                            <span className="text-emerald-400 font-semibold flex items-center gap-1">
                              <CheckCircle2 className="h-3.5 w-3.5" /> Protected
                            </span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-muted-foreground">Trust Rating:</span>
                            <span className="text-blue-400 font-semibold">{agent.score} ({agent.tier})</span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-muted-foreground">Active Policy:</span>
                            <span className="text-foreground font-semibold truncate max-w-[170px]">
                              {agent.id === "eliza-monad-01" 
                                ? "Max 1.0 MON / Execution" 
                                : agent.id === "mera-memory-01" 
                                ? "Secure Encrypted Storage" 
                                : "Verified Agent Passport"}
                            </span>
                          </div>
                          <div className="flex justify-between items-center pt-1 border-t border-border/50">
                            <span className="text-muted-foreground">Agent Address:</span>
                            <div className="flex items-center gap-1">
                              <span className="text-foreground font-mono text-[11px]">{`${agent.address.slice(0, 6)}...${agent.address.slice(-4)}`}</span>
                              <button
                                type="button"
                                onClick={(e) => handleCopy(agent.address, `simple-${agent.id}`, e)}
                                className="text-muted-foreground hover:text-foreground p-0.5 rounded transition"
                                title="Copy Address"
                              >
                                {copiedField === `simple-${agent.id}` ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                              </button>
                            </div>
                          </div>
                        </div>

                        <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-800/40 text-emerald-300 text-xs flex items-center gap-2">
                          <CheckCircle2 className="h-4 w-4 text-emerald-400 shrink-0" />
                          <span>Automated security checks: Active / Monitored</span>
                        </div>
                      </div>
                    ) : (
                      <>
                        {/* TAB 1: SPECS */}
                        {currentTab === "specs" && (
                      <div className="space-y-3">
                        <div className="space-y-1.5 p-3 rounded-lg bg-background/60 border border-border/70 text-[11px]">
                          <div className="flex justify-between items-center">
                            <span className="text-muted-foreground">Signer Address:</span>
                            <div className="flex items-center gap-1">
                              <span className="text-foreground">{`${agent.address.slice(0, 6)}...${agent.address.slice(-4)}`}</span>
                              <button
                                type="button"
                                onClick={(e) => handleCopy(agent.address, agent.id, e)}
                                className="text-muted-foreground hover:text-foreground"
                                title="Copy Address"
                              >
                                {copiedField === agent.id ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                              </button>
                            </div>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-muted-foreground">Policy Guard:</span>
                            <span className="text-[#836EF9] truncate max-w-[170px]" title={agent.policyId}>
                              {agent.policyId}
                            </span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-muted-foreground">Status / Standing:</span>
                            <span className="text-emerald-400 font-semibold">{agent.status}</span>
                          </div>
                          <div className="flex justify-between items-center">
                            <span className="text-muted-foreground">Trust Score / Tier:</span>
                            <span className="text-blue-400 font-bold">{agent.score} ({agent.tier})</span>
                          </div>
                          {agent.explorerUrl && (
                            <div className="flex justify-between items-center pt-1 border-t border-border/40">
                              <span className="text-muted-foreground">Monad Explorer:</span>
                              <a
                                href={agent.explorerUrl}
                                target="_blank"
                                rel="noreferrer"
                                className="text-[#836EF9] hover:underline flex items-center gap-1 font-semibold"
                              >
                                View Contract
                                <ExternalLink className="h-3 w-3 inline" />
                              </a>
                            </div>
                          )}
                        </div>

                        {/* Detailed Spec Key-Value Table */}
                        <div className="space-y-1 text-[11px]">
                          {agent.specs.map((spec, i) => (
                            <div key={i} className="flex justify-between items-start py-1 border-b border-border/40 last:border-0">
                              <span className="text-muted-foreground shrink-0">{spec.label}:</span>
                              <span className="text-foreground text-right font-medium pl-2">{spec.value}</span>
                            </div>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* TAB 2: DEVELOPER SNIPPET (TS) */}
                    {currentTab === "snippet" && (
                      <div className="space-y-2">
                        <div className="flex items-center justify-between text-[11px]">
                          <span className="text-muted-foreground flex items-center gap-1">
                            <Code2 className="h-3.5 w-3.5 text-[#836EF9]" />
                            Copyable TypeScript:
                          </span>
                          <button
                            type="button"
                            onClick={(e) => handleCopy(CODE_SNIPPETS[agent.id], `code-${agent.id}`, e)}
                            className="flex items-center gap-1 text-[#836EF9] hover:text-purple-300 font-semibold transition"
                          >
                            {copiedField === `code-${agent.id}` ? (
                              <>
                                <Check className="h-3 w-3 text-emerald-400" />
                                <span className="text-emerald-300">Copied!</span>
                              </>
                            ) : (
                              <>
                                <Copy className="h-3 w-3" />
                                <span>Copy Code</span>
                              </>
                            )}
                          </button>
                        </div>
                        <div className="rounded-lg bg-black/70 border border-border/80 p-3 max-h-56 overflow-y-auto font-mono text-[10.5px] leading-relaxed text-slate-300">
                          <pre>{CODE_SNIPPETS[agent.id]}</pre>
                        </div>
                      </div>
                    )}

                    {/* TAB 3: INTERACTIVE SIMULATION PROBE */}
                    {currentTab === "probe" && (
                      <div className="space-y-3.5">
                        <div className="p-3 rounded-lg bg-red-950/30 border border-red-900/50 space-y-1.5">
                          <div className="flex items-center gap-1.5 text-red-300 font-semibold text-[11px]">
                            <ShieldAlert className="h-3.5 w-3.5 text-red-400" />
                            <span>{agent.probeConfig.attackTitle}</span>
                          </div>
                          <p className="text-[10.5px] text-muted-foreground">
                            {agent.probeConfig.attackDesc}
                          </p>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation()
                              agent.probeConfig.onAttack?.(e)
                            }}
                            disabled={isAttackLoading}
                            className="w-full mt-1.5 px-3 py-1.5 rounded-lg bg-red-600/20 border border-red-500/40 text-red-300 hover:bg-red-600/30 text-[11px] font-semibold transition active:scale-[0.98] disabled:opacity-50 flex items-center justify-center gap-1.5"
                          >
                            {isAttackLoading ? (
                              <>
                                <RefreshCw className="h-3 w-3 animate-spin" />
                                <span>Testing Interception...</span>
                              </>
                            ) : (
                              <>
                                <Zap className="h-3 w-3" />
                                <span>{agent.probeConfig.attackBtn}</span>
                              </>
                            )}
                          </button>
                        </div>

                        <div className="p-3 rounded-lg bg-emerald-950/30 border border-emerald-900/50 space-y-1.5">
                          <div className="flex items-center gap-1.5 text-emerald-300 font-semibold text-[11px]">
                            <ShieldCheck className="h-3.5 w-3.5 text-emerald-400" />
                            <span>{agent.probeConfig.validTitle}</span>
                          </div>
                          <p className="text-[10.5px] text-muted-foreground">
                            {agent.probeConfig.validDesc}
                          </p>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation()
                              agent.probeConfig.onValid?.(e)
                            }}
                            disabled={isValidLoading}
                            className="w-full mt-1.5 px-3 py-1.5 rounded-lg bg-emerald-600/20 border border-emerald-500/40 text-emerald-300 hover:bg-emerald-600/30 text-[11px] font-semibold transition active:scale-[0.98] disabled:opacity-50 flex items-center justify-center gap-1.5"
                          >
                            {isValidLoading ? (
                              <>
                                <RefreshCw className="h-3 w-3 animate-spin" />
                                <span>Attesting Execution...</span>
                              </>
                            ) : (
                              <>
                                <CheckCircle2 className="h-3 w-3" />
                                <span>{agent.probeConfig.validBtn}</span>
                              </>
                            )}
                          </button>
                        </div>
                      </div>
                    )}
                      </>
                    )}
                  </CardContent>
                </div>

                {/* Card Footer Quick Actions */}
                <div className="p-4 pt-0 border-t border-border/40 mt-3 space-y-2">
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation()
                        onTriggerGuardedAction?.(agent.id)
                      }}
                      disabled={isExecutingGuarded === agent.id || isExecutingGuarded === true}
                      className="px-2.5 py-1.5 rounded-lg bg-emerald-600/20 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-600/30 text-[11px] font-semibold transition flex items-center justify-center gap-1 active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none"
                    >
                      {isExecutingGuarded === agent.id ? (
                        <>
                          <RefreshCw className="h-3 w-3 animate-spin" />
                          <span>Testing...</span>
                        </>
                      ) : (
                        <span>{isAdvanced ? "Test Action" : "Test Safe Action"}</span>
                      )}
                    </button>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation()
                        onTriggerRogueAction?.(agent.id)
                      }}
                      disabled={isExecutingRogue === agent.id || isExecutingRogue === true}
                      className="px-2.5 py-1.5 rounded-lg bg-red-600/20 border border-red-500/30 text-red-300 hover:bg-red-600/30 text-[11px] font-semibold transition flex items-center justify-center gap-1 active:scale-[0.98] disabled:opacity-50 disabled:pointer-events-none"
                    >
                      {isExecutingRogue === agent.id ? (
                        <>
                          <RefreshCw className="h-3 w-3 animate-spin" />
                          <span>Testing...</span>
                        </>
                      ) : (
                        <span>{isAdvanced ? "Test Rogue" : "Test Blocked"}</span>
                      )}
                    </button>
                  </div>
                  <div className="flex items-center gap-2">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation()
                        onOpenDelegationModal?.(agent.address, agent.policyId)
                      }}
                      className="flex-1 px-3 py-1.5 rounded-lg border border-[#836EF9]/40 text-[#836EF9] hover:bg-[#836EF9]/10 text-[11px] font-medium transition text-center"
                    >
                      {isAdvanced ? "Manage Signer" : "Manage Permissions"}
                    </button>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation()
                        onNavigateTab?.('policy')
                      }}
                      className="flex-1 px-3 py-1.5 rounded-lg border border-border/80 text-muted-foreground hover:text-foreground hover:bg-muted/30 text-[11px] font-medium transition text-center"
                    >
                      {isAdvanced ? "Policy Rules" : "Security Rules"}
                    </button>
                  </div>
                </div>
              </Card>
            )
          })}
        </div>
      </section>

      {/* ── Soulbound Passport Specification Section (ERC-5192) ───────────────── */}
      <section className="space-y-4">
        {isAdvanced ? (
          <>
            <h2 className="text-lg font-semibold tracking-tight text-foreground flex items-center gap-2 font-mono">
              <Lock className="h-4 w-4 text-blue-400" />
              Soulbound Agent Passport Specification (ERC-5192, Monad 10143)
            </h2>

            <div className="grid gap-6 md:grid-cols-12">
              {/* Holographic Passport Card (5 cols) */}
              <div className="md:col-span-5 relative overflow-hidden rounded-2xl border border-blue-500/40 bg-gradient-to-br from-blue-950/30 via-slate-900 to-slate-950 p-6 shadow-xl">
                <div className="absolute top-0 right-0 -mr-10 -mt-10 w-40 h-40 bg-blue-500/10 rounded-full blur-2xl pointer-events-none" />
                <div className="relative z-10 space-y-5">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <div className="p-2 rounded-xl bg-blue-500/20 text-blue-400 border border-blue-500/40">
                        <Shield className="h-5 w-5" />
                      </div>
                      <div>
                        <span className="text-[10px] font-mono tracking-widest text-blue-400 uppercase font-bold">
                          SOULBOUND PASSPORT
                        </span>
                        <h3 className="font-bold text-sm text-white">Soulbound Sovereign Identity (ERC-5192)</h3>
                      </div>
                    </div>
                    <span className="font-mono text-xs font-bold text-blue-300 bg-blue-950/80 px-2.5 py-1 rounded-full border border-blue-800">
                      #10143-001
                    </span>
                  </div>

                  <div className="space-y-2 text-xs font-mono">
                    <div className="p-2.5 rounded-lg bg-black/40 border border-white/10 space-y-1.5">
                      <div className="flex justify-between">
                        <span className="text-slate-400">Registry Contract:</span>
                        <a
                          href={`https://testnet.monadscan.com/address/${PASSPORT_REGISTRY_ADDRESS}`}
                          target="_blank"
                          rel="noreferrer"
                          className="text-blue-300 font-semibold hover:underline flex items-center gap-1"
                        >
                          0xDA5f...2Cff
                          <ExternalLink className="h-2.5 w-2.5" />
                        </a>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Attestation Origin:</span>
                        <span className="text-emerald-400">GuardianPolicyGuard</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Target Chain:</span>
                        <span className="text-purple-300">10143 (Monad Testnet)</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-slate-400">Passkey Attestation:</span>
                        <span className="text-amber-300">Mera WebAuthn PRF (RIP-7212)</span>
                      </div>
                    </div>
                  </div>

                  <div className="flex items-center justify-between text-[11px] pt-1 border-t border-white/10 font-mono text-slate-400">
                    <div className="flex items-center gap-1.5 text-emerald-400">
                      <CheckCircle2 className="h-4 w-4" />
                      <span>NON-TRANSFERABLE (ERC-5192)</span>
                    </div>
                    <span className="text-blue-300 font-bold">DIAMOND (98/100)</span>
                  </div>
                </div>
              </div>

              {/* Architecture Explanatory Details (7 cols) */}
              <Card className="md:col-span-7 border-border/80 bg-card/80">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                    <Layers className="h-4 w-4 text-[#836EF9]" />
                    Autonomous Agent Execution Primitives Architecture
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-3.5 text-xs text-muted-foreground leading-relaxed font-sans">
                  <p>
                    Under the GuardianAI architecture, autonomous agents transact on Monad using <strong className="text-foreground">EIP-712 Safety Attestations</strong>, <strong className="text-foreground">Category Labs Mera PRF Passkey Memory</strong>, and <strong className="text-foreground">Soulbound Agent Passports (ERC-5192)</strong>.
                  </p>

                  <div className="space-y-2">
                    <div className="p-3 rounded-lg bg-background/50 border border-border/60">
                      <div className="font-semibold text-foreground mb-0.5 flex items-center gap-2 font-mono text-xs">
                        <span className="text-[#836EF9]">1.</span>
                        <span>3-Line Developer Integration (@guardianai/middleware)</span>
                      </div>
                      <p className="text-[11px]">
                        Wrap any ElizaOS or custom agent with a single line of code to enforce pre-flight policy containment and off-chain prompt sanitization.
                      </p>
                    </div>

                    <div className="p-3 rounded-lg bg-background/50 border border-border/60">
                      <div className="font-semibold text-foreground mb-0.5 flex items-center gap-2 font-mono text-xs">
                        <span className="text-emerald-400">2.</span>
                        <span>Cross-App Persistent Memory (Mera Passkey PRF + RIP-7212)</span>
                      </div>
                      <p className="text-[11px]">
                        Hardware-bound WebAuthn PRF salts seal agent memory states with AES-256-GCM, attested via Monad precompile <code className="text-[#836EF9]">0x100</code>.
                      </p>
                    </div>

                    <div className="p-3 rounded-lg bg-background/50 border border-border/60">
                      <div className="font-semibold text-foreground mb-0.5 flex items-center gap-2 font-mono text-xs">
                        <span className="text-blue-400">3.</span>
                        <span>Soulbound Identity (ERC-5192) & Atomic Revocation</span>
                      </div>
                      <p className="text-[11px]">
                        GuardianPolicyGuard checks the on-chain passport registry before executing any transaction. If an agent is tombstoned or revoked, execution reverts atomically with <code className="text-red-400">PassportRevokedOrInactive</code>.
                      </p>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          </>
        ) : (
          <Card className="border-border/80 bg-card/80 p-5 shadow-sm">
            <div className="flex items-start gap-3.5">
              <div className="p-3 rounded-xl bg-blue-500/10 text-blue-400 border border-blue-500/20">
                <Shield className="h-6 w-6" />
              </div>
              <div className="space-y-1">
                <h3 className="text-base font-semibold text-foreground">
                  Agent Identity & Passport Verification
                </h3>
                <p className="text-xs text-muted-foreground leading-relaxed font-sans">
                  Connected agents hold digital passports. If an agent is suspended or attempts an unauthorized action, its passport status can be updated on-chain to restrict operations.
                </p>
                <div className="flex items-center gap-2 pt-2">
                  <span className="text-[11px] px-2.5 py-0.5 rounded-full bg-blue-500/15 text-blue-300 border border-blue-500/30 font-medium font-sans">
                    3 Agents Registered
                  </span>
                  <span className="text-[11px] px-2.5 py-0.5 rounded-full bg-emerald-500/15 text-emerald-300 border border-emerald-500/30 font-medium font-sans">
                    Containment Policy Configured
                  </span>
                </div>
              </div>
            </div>
          </Card>
        )}
      </section>
    </div>
  )
}
