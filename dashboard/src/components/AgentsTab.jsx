import React, { useState } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { 
  Cpu, 
  Shield, 
  UserCheck, 
  Lock, 
  Key, 
  CheckCircle2, 
  ExternalLink, 
  Copy, 
  Check, 
  Zap, 
  AlertTriangle,
  Clock,
  Sparkles,
  Layers
} from "lucide-react"
import { cn } from "@/lib/utils"

export function AgentsTab({
  isConnectedSupervisor,
  supervisorAddress,
  truncatedSupervisor,
  onOpenDelegationModal,
  onConnectSupervisor,
  onTriggerGuardedAction,
  onTriggerRogueAction,
  isExecutingAction,
  agentActionStatus,
  onNavigateTab
}) {
  const [copiedField, setCopiedField] = useState(null)

  const handleCopy = (text, fieldName) => {
    navigator.clipboard?.writeText(text)
    setCopiedField(fieldName)
    setTimeout(() => setCopiedField(null), 2000)
  }

  const AGENTS = [
    {
      id: "agent-01",
      name: "Guardian Autonomous Executor #01",
      address: "0x742d35Cc6634C0532925a3b844Bc454e4438f44e",
      role: "Primary On-Chain Transaction Worker",
      policyId: "pol_guardian_monad_policyguard_01",
      status: "ACTIVE & DELEGATED",
      statusType: "active",
      sessionExpiry: "23h 48m remaining",
      executions: 1482,
      blockedViolations: 94,
      passportId: "#10143-001",
      isPrimary: true
    },
    {
      id: "agent-02",
      name: "Monad High-Throughput Arb Agent",
      address: "0x1142F8C90aB361B8c764b85994fCdA30089eC890",
      role: "Parallel DEX Arbitrage & Liquidations",
      policyId: "pol_guardian_arb_fast_02",
      status: "ACTIVE & DELEGATED",
      statusType: "active",
      sessionExpiry: "18h 15m remaining",
      executions: 3890,
      blockedViolations: 12,
      passportId: "#10143-002",
      isPrimary: false
    },
    {
      id: "agent-03",
      name: "Tripwire Memory Guard Agent",
      address: "0x9812A61975e53beF6FeA28a1c93a0b5f10143891",
      role: "Category Labs MERA Enclave Tamper Monitor",
      policyId: "pol_guardian_tripwire_sentry_03",
      status: "PERMANENT ATTESTATION",
      statusType: "attested",
      sessionExpiry: "Permanent Hardware Attestation",
      executions: 540,
      blockedViolations: 43,
      passportId: "#10143-003",
      isPrimary: false
    }
  ]

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/80 pb-6">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-[#836EF9]/15 border border-[#836EF9]/30 text-xs font-mono text-[#836EF9] mb-2">
            <Cpu className="h-3.5 w-3.5" />
            <span>Autonomous Session Signers & ERC-8004 Passports</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground">
            Active AI Agent Directory & Delegation Center
          </h1>
          <p className="text-xs sm:text-sm text-muted-foreground mt-1">
            Supervise autonomous session signers, grant scoped authority, and inspect Soulbound identities.
          </p>
        </div>

        <button
          onClick={onOpenDelegationModal}
          className="flex items-center justify-center gap-2 px-4 py-2.5 rounded-xl bg-[#836EF9] hover:brightness-110 text-white text-xs font-semibold shadow-md shadow-[#836EF9]/25 transition active:scale-[0.98]"
        >
          <UserCheck className="h-4 w-4" />
          <span>Delegate to AI Agent</span>
        </button>
      </div>

      {/* Supervisor Delegation Status Card */}
      <Card className="border-[#836EF9]/40 bg-gradient-to-r from-[#836EF9]/15 via-card to-card">
        <CardHeader className="pb-3 border-b border-border/50">
          <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
            <div className="flex items-center gap-3">
              <div className="p-2.5 rounded-xl bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/30">
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
                  Grants scoped session keys under Privy Hardware TEE policies. Zero master key compromise risk.
                </p>
              </div>
            </div>

            {!isConnectedSupervisor ? (
              <button
                onClick={onConnectSupervisor}
                className="px-3.5 py-1.5 rounded-lg bg-[#836EF9] text-white text-xs font-semibold hover:brightness-110 shadow-sm"
              >
                Connect Supervisor
              </button>
            ) : (
              <button
                onClick={onOpenDelegationModal}
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
                    onClick={() => handleCopy(supervisorAddress, 'sup')}
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
              <span className="text-muted-foreground block mb-1">Hardware Isolation:</span>
              <span className="text-emerald-400 font-semibold">Privy TEE Enclave</span>
            </div>

            <div className="p-3 rounded-xl bg-background/50 border border-border/70">
              <span className="text-muted-foreground block mb-1">Authorized Agents:</span>
              <span className="text-purple-300 font-semibold">{AGENTS.length} Autonomous Agents</span>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Live Result Feedback Banner */}
      {agentActionStatus && (
        <div
          className={cn(
            "p-4 rounded-xl border text-xs font-mono transition-all duration-200 shadow-md",
            agentActionStatus.type === "success"
              ? "bg-emerald-950/40 border-emerald-800/80 text-emerald-200"
              : "bg-red-950/40 border-red-800/80 text-red-200"
          )}
        >
          <div className="flex items-center justify-between mb-2">
            <div className="flex items-center gap-2">
              {agentActionStatus.type === "success" ? (
                <CheckCircle2 className="h-4 w-4 text-emerald-400" />
              ) : (
                <AlertTriangle className="h-4 w-4 text-red-400" />
              )}
              <span className="font-bold uppercase tracking-wider">{agentActionStatus.title}</span>
            </div>
            <span className="text-[11px] opacity-70">{agentActionStatus.timestamp}</span>
          </div>
          <p className="leading-relaxed opacity-90">{agentActionStatus.message}</p>
          {agentActionStatus.tx && (
            <div className="mt-2.5 pt-2 border-t border-emerald-900/60 flex items-center gap-2">
              <span className="text-muted-foreground">Tx Hash:</span>
              <a 
                href={`https://testnet.monadscan.com/tx/${agentActionStatus.tx}`} 
                target="_blank" 
                rel="noreferrer"
                className="text-emerald-400 underline hover:text-emerald-300 flex items-center gap-1"
              >
                {agentActionStatus.tx.slice(0, 24)}...
                <ExternalLink className="h-3 w-3 inline" />
              </a>
            </div>
          )}
        </div>
      )}

      {/* Active AI Agent Directory */}
      <section className="space-y-4">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold tracking-tight text-foreground flex items-center gap-2">
            <Cpu className="h-4 w-4 text-[#836EF9]" />
            Registered Autonomous AI Agents
          </h2>
          <span className="text-xs text-muted-foreground font-mono">
            {AGENTS.length} Active Session Signers
          </span>
        </div>

        <div className="grid gap-4 lg:grid-cols-3">
          {AGENTS.map((agent) => (
            <Card
              key={agent.id}
              className={cn(
                "border transition-all duration-200 bg-card/80",
                agent.isPrimary
                  ? "border-[#836EF9]/50 shadow-md shadow-[#836EF9]/10"
                  : "border-border/80 hover:border-border"
              )}
            >
              <CardHeader className="pb-3 border-b border-border/50">
                <div className="flex items-start justify-between gap-2">
                  <div>
                    <div className="flex items-center gap-2">
                      <CardTitle className="text-sm font-semibold text-foreground">
                        {agent.name}
                      </CardTitle>
                      {agent.isPrimary && (
                        <span className="text-[10px] font-mono px-1.5 py-0.2 rounded bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/30">
                          PRIMARY
                        </span>
                      )}
                    </div>
                    <p className="text-[11px] text-muted-foreground mt-0.5">{agent.role}</p>
                  </div>
                  <span className="flex h-2 w-2 relative mt-1">
                    <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                    <span className="relative inline-flex rounded-full h-2 w-2 bg-emerald-500"></span>
                  </span>
                </div>
              </CardHeader>
              <CardContent className="space-y-4 pt-4 text-xs font-mono">
                {/* Address & Policy ID */}
                <div className="space-y-2 p-3 rounded-lg bg-background/60 border border-border/70 text-[11px]">
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Address:</span>
                    <div className="flex items-center gap-1">
                      <span className="text-foreground">{`${agent.address.slice(0, 6)}...${agent.address.slice(-4)}`}</span>
                      <button
                        onClick={() => handleCopy(agent.address, agent.id)}
                        className="text-muted-foreground hover:text-foreground"
                      >
                        {copiedField === agent.id ? <Check className="h-3 w-3 text-emerald-400" /> : <Copy className="h-3 w-3" />}
                      </button>
                    </div>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Bound Policy:</span>
                    <span className="text-[#836EF9] truncate max-w-[170px]" title={agent.policyId}>
                      {agent.policyId}
                    </span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">ERC-8004 NFT:</span>
                    <span className="text-blue-400 font-bold">{agent.passportId}</span>
                  </div>
                  <div className="flex justify-between items-center">
                    <span className="text-muted-foreground">Session Expiry:</span>
                    <span className="text-muted-foreground">{agent.sessionExpiry}</span>
                  </div>
                </div>

                {/* Performance & Execution Counters */}
                <div className="grid grid-cols-2 gap-2 text-center text-xs">
                  <div className="p-2 rounded-lg bg-muted/30 border border-border/60">
                    <span className="text-[10px] text-muted-foreground block">Executions</span>
                    <span className="font-bold text-foreground">{agent.executions.toLocaleString()}</span>
                  </div>
                  <div className="p-2 rounded-lg bg-muted/30 border border-border/60">
                    <span className="text-[10px] text-muted-foreground block">Rogue Contained</span>
                    <span className="font-bold text-red-400">{agent.blockedViolations}</span>
                  </div>
                </div>

                {/* Quick Action Buttons */}
                <div className="space-y-1.5 pt-1">
                  <div className="grid grid-cols-2 gap-2">
                    <button
                      onClick={onTriggerGuardedAction}
                      disabled={isExecutingAction}
                      className="px-2.5 py-1.5 rounded-lg bg-emerald-600/20 border border-emerald-500/30 text-emerald-300 hover:bg-emerald-600/30 text-[11px] font-semibold transition"
                    >
                      Test Action
                    </button>
                    <button
                      onClick={onTriggerRogueAction}
                      disabled={isExecutingAction}
                      className="px-2.5 py-1.5 rounded-lg bg-red-600/20 border border-red-500/30 text-red-300 hover:bg-red-600/30 text-[11px] font-semibold transition"
                    >
                      Test Rogue
                    </button>
                  </div>
                  <button
                    onClick={() => onOpenDelegationModal(agent.address, agent.policyId)}
                    className="w-full px-3 py-1.5 rounded-lg border border-[#836EF9]/40 text-[#836EF9] hover:bg-[#836EF9]/10 text-[11px] font-medium transition"
                  >
                    Manage Signer Rights
                  </button>
                  <button
                    onClick={() => onNavigateTab('policy')}
                    className="w-full px-3 py-1.5 rounded-lg border border-border/80 text-muted-foreground hover:text-foreground hover:bg-muted/30 text-[11px] font-medium transition"
                  >
                    Configure Policy Rules
                  </button>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>
      </section>

      {/* ERC-8004 Soulbound Passport Inspector Section */}
      <section className="space-y-4">
        <h2 className="text-lg font-semibold tracking-tight text-foreground flex items-center gap-2">
          <Lock className="h-4 w-4 text-blue-400" />
          ERC-8004 Soulbound Agent Passport Specification
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
                    <h3 className="font-bold text-sm text-white">ERC-8004 Verified Identity</h3>
                  </div>
                </div>
                <span className="font-mono text-xs font-bold text-blue-300 bg-blue-950/80 px-2.5 py-1 rounded-full border border-blue-800">
                  #10143-001
                </span>
              </div>

              <div className="space-y-2 text-xs font-mono">
                <div className="p-2.5 rounded-lg bg-black/40 border border-white/10 space-y-1.5">
                  <div className="flex justify-between">
                    <span className="text-slate-400">Agent Address:</span>
                    <span className="text-blue-300 font-semibold">0x742d...f44e</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Attestation Origin:</span>
                    <span className="text-emerald-400">GuardianPolicyGuard</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Chain ID:</span>
                    <span className="text-purple-300">10143 (Monad Testnet)</span>
                  </div>
                  <div className="flex justify-between">
                    <span className="text-slate-400">Enclave Attestation:</span>
                    <span className="text-amber-300">MERA Ed25519 PRF</span>
                  </div>
                </div>
              </div>

              <div className="flex items-center justify-between text-[11px] pt-1 border-t border-white/10 font-mono text-slate-400">
                <div className="flex items-center gap-1.5 text-emerald-400">
                  <CheckCircle2 className="h-4 w-4" />
                  <span>NON-TRANSFERABLE</span>
                </div>
                <span>Status: VERIFIED</span>
              </div>
            </div>
          </div>

          {/* Architecture Explanatory Details (7 cols) */}
          <Card className="md:col-span-7 border-border/80 bg-card/80">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                <Layers className="h-4 w-4 text-[#836EF9]" />
                Hardware-Isolated Session Signer Architecture
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3.5 text-xs text-muted-foreground leading-relaxed">
              <p>
                Under the GuardianAI architecture, the human supervisor delegates transaction authority using <strong className="text-foreground">Privy Session Signers</strong>. This allows the AI agent to sign transactions autonomously within predefined boundaries.
              </p>

              <div className="space-y-2">
                <div className="p-3 rounded-lg bg-background/50 border border-border/60">
                  <div className="font-semibold text-foreground mb-0.5 flex items-center gap-2">
                    <span className="text-[#836EF9] font-mono">1.</span>
                    <span>Zero Master Key Exposure</span>
                  </div>
                  <p className="text-[11px]">
                    The supervisor wallet never enters frontend local storage or disk. A scoped cryptographic session key is provisioned in the hardware TEE.
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-background/50 border border-border/60">
                  <div className="font-semibold text-foreground mb-0.5 flex items-center gap-2">
                    <span className="text-emerald-400 font-mono">2.</span>
                    <span>Dual Pre-Flight Containment</span>
                  </div>
                  <p className="text-[11px]">
                    Every transaction request is intercepted twice: off-chain by Privy Policy Engine, and on-chain by the Monad <span className="font-mono text-emerald-400">GuardianPolicyGuard</span> smart contract.
                  </p>
                </div>

                <div className="p-3 rounded-lg bg-background/50 border border-border/60">
                  <div className="font-semibold text-foreground mb-0.5 flex items-center gap-2">
                    <span className="text-blue-400 font-mono">3.</span>
                    <span>Instant Revocation</span>
                  </div>
                  <p className="text-[11px]">
                    Supervisors can revoke session signing rights instantly with a single click, immediately invalidating any subsequent agent transaction attempts.
                  </p>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </section>
    </div>
  )
}
