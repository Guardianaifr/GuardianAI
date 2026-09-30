import React from 'react'
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { 
  Shield, 
  Activity, 
  Lock, 
  AlertTriangle, 
  Zap, 
  CheckCircle2, 
  XCircle, 
  ArrowUpRight, 
  Cpu, 
  Sliders, 
  Terminal, 
  ExternalLink,
  Layers,
  Sparkles,
  ArrowLeft
} from "lucide-react"
import { cn } from "@/lib/utils"

export function HomeTab({
  stats,
  onTriggerGuardedAction,
  onTriggerRogueAction,
  executingAction,
  isExecutingGuarded,
  isExecutingRogue,
  agentActionStatus,
  defaultAgentAddress,
  defaultPolicyId,
  onOpenDelegationModal,
  onNavigateTab,
  indexerStatus,
  isAdvanced = false
}) {
  const isGuardedRunning = Boolean(isExecutingGuarded || executingAction === 'guarded')
  const isRogueRunning = Boolean(isExecutingRogue || executingAction === 'rogue')
  const estimatedPreventedLoss = stats.requests > 0 ? (stats.blocked * 10).toLocaleString() : "0"

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Hero / Platform Overview Banner */}
      <div className="relative overflow-hidden rounded-2xl border border-[#836EF9]/30 bg-gradient-to-br from-[#836EF9]/15 via-background to-background p-6 sm:p-8 shadow-lg">
        <div className="absolute top-0 right-0 -mt-8 -mr-8 w-64 h-64 bg-[#836EF9]/10 rounded-full blur-3xl pointer-events-none" />
        <div className="relative z-10 flex flex-col lg:flex-row items-start lg:items-center justify-between gap-6">
          <div className="max-w-2xl space-y-3">
            <div className="flex flex-wrap items-center gap-2">
              <div className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-[#836EF9]/20 border border-[#836EF9]/40 text-xs font-mono text-[#836EF9]">
                <Sparkles className="h-3.5 w-3.5 text-[#836EF9]" />
                <span>{isAdvanced ? "Autonomous Agent Security • Monad Parallel EVM" : "Autonomous Agent Security"}</span>
              </div>
              <a
                href="/"
                title="Return to aiguardian.dev main landing page"
                className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full bg-muted/60 hover:bg-muted border border-border/80 text-xs text-muted-foreground hover:text-foreground transition-all group"
              >
                <ArrowLeft className="h-3 w-3 text-[#836EF9] group-hover:-translate-x-0.5 transition-transform" />
                <span>aiguardian.dev (Main Site)</span>
              </a>
            </div>
            <h1 className="text-3xl sm:text-4xl font-extrabold tracking-tight text-foreground">
              Guardian<span className="text-[#836EF9]">AI</span> Platform
            </h1>
            <p className="text-sm sm:text-base text-muted-foreground leading-relaxed">
              {isAdvanced
                ? "Real-time policy enforcement, indirect prompt injection defense, and EIP-712 pre-flight containment for autonomous AI agents on Monad Testnet (Chain ID 10143)."
                : "Real-time safety rules, automated prompt injection defense, and transaction protection for autonomous AI agents."}
            </p>
          </div>

          {/* Quick Platform Status Pills */}
          <div className="flex flex-wrap lg:flex-col gap-2.5 w-full lg:w-auto">
            <div className="flex items-center justify-between gap-4 px-3.5 py-2 rounded-xl bg-card border border-border/80 text-xs font-mono">
              <span className="text-muted-foreground flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                {isAdvanced ? "Privy Policy Engine" : "Safety Firewall"}
              </span>
              <span className="font-semibold text-emerald-400">{isAdvanced ? "POLICY ENGINE" : "ACTIVE"}</span>
            </div>
            <div className="flex items-center justify-between gap-4 px-3.5 py-2 rounded-xl bg-card border border-border/80 text-xs font-mono">
              <span className="text-muted-foreground flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-blue-400 animate-pulse" />
                {isAdvanced ? "Monad Testnet RPC" : "Network Protection"}
              </span>
              <span className="font-semibold text-blue-400">{isAdvanced ? "10143 (ACTIVE)" : "PROTECTED"}</span>
            </div>
            <div className="flex items-center justify-between gap-4 px-3.5 py-2 rounded-xl bg-card border border-border/80 text-xs font-mono">
              <span className="text-muted-foreground flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-purple-400" />
                {isAdvanced ? "Containment Latency" : "Response Time"}
              </span>
              <span className="font-semibold text-purple-300">~2.4ms (Example)</span>
            </div>
          </div>
        </div>
      </div>

      {/* Key Security Stats Summary */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold tracking-tight text-foreground flex items-center gap-2">
            <Activity className="h-4 w-4 text-[#836EF9]" />
            {isAdvanced ? "Key Security Telemetry Summary" : "Security Activity Overview"}
          </h2>
          <span className="text-xs text-muted-foreground font-mono">
            {isAdvanced
              ? (indexerStatus === "connected" ? "Envio Realtime Feed" : "Live Web Stream Active")
              : "Live Protection Feed"}
          </span>
        </div>

        <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-5">
          <Card className="border-border/80 bg-card/60 backdrop-blur hover:border-[#836EF9]/50 transition-colors">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">{isAdvanced ? "Actions Indexed" : "Actions Monitored"}</CardTitle>
              <Activity className="h-4 w-4 text-[#836EF9]" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono text-foreground">{stats.requests.toLocaleString()}</div>
              <p className="text-[11px] text-muted-foreground mt-1">{isAdvanced ? "Monad on-chain executions" : "Autonomous agent actions"}</p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur hover:border-red-500/40 transition-colors">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Threats Intercepted</CardTitle>
              <Shield className="h-4 w-4 text-red-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono text-red-500">{stats.blocked.toLocaleString()}</div>
              <p className="text-[11px] text-muted-foreground mt-1">{isAdvanced ? "Injections & cap breaches" : "Injections & safety breaches"}</p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur hover:border-amber-500/40 transition-colors">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">{isAdvanced ? "Active Malicious Targets" : "Flagged Targets"}</CardTitle>
              <AlertTriangle className="h-4 w-4 text-amber-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono text-amber-500">{stats.redacted.toLocaleString()}</div>
              <p className="text-[11px] text-muted-foreground mt-1">{isAdvanced ? "Drainer contracts in registry" : "Malicious destinations blocked"}</p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur hover:border-blue-500/40 transition-colors">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">{isAdvanced ? "Soulbound Passports" : "Protected Agents"}</CardTitle>
              <Lock className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono text-blue-500">{stats.admin.toLocaleString()}</div>
              <p className="text-[11px] text-muted-foreground mt-1">{isAdvanced ? "ERC-8004 registered agents" : "Active monitored agents"}</p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur sm:col-span-2 lg:col-span-1 hover:border-emerald-500/40 transition-colors">
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Capital Preserved</CardTitle>
              <Zap className="h-4 w-4 text-emerald-400" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold font-mono text-emerald-400">~{estimatedPreventedLoss} MON</div>
              <p className="text-[11px] text-muted-foreground mt-1">{isAdvanced ? "Pre-flight saved off-chain" : "Saved from unauthorized transfer"}</p>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Quick Action Trigger Cards Section */}
      <section className="space-y-4">
        <div>
          <h2 className="text-lg font-semibold tracking-tight text-foreground flex items-center gap-2">
            <Zap className="h-4 w-4 text-amber-400" />
            {isAdvanced ? "Immediate Testing & Action Verification" : "Interactive Security Verification"}
          </h2>
          <p className="text-xs text-muted-foreground">
            {isAdvanced
              ? "Fire live pre-flight simulations to verify Privy Policy Engine enforcement vs. GuardianAI off-chain containment."
              : "Test how GuardianAI immediately allows safe transactions and blocks unauthorized actions before execution."}
          </p>
        </div>

        <div className="grid gap-4 md:grid-cols-2">
          {/* Guarded Action Trigger */}
          <Card className="border-emerald-900/40 bg-gradient-to-br from-emerald-950/20 via-card to-card hover:border-emerald-600/50 transition-all shadow-sm">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-emerald-900/40 text-emerald-400 border border-emerald-700/40">
                    <CheckCircle2 className="h-5 w-5" />
                  </div>
                  <div>
                    <CardTitle className="text-base font-semibold text-emerald-200">
                      {isAdvanced ? "Trigger Guarded Action" : "Test Approved Action"}
                    </CardTitle>
                    <p className="text-xs text-muted-foreground">
                      {isAdvanced ? "Within Scoped Policy Allowance" : "Within Approved Spending Limits"}
                    </p>
                  </div>
                </div>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-emerald-950 border border-emerald-800 text-emerald-300">
                  0.1 MON
                </span>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground leading-relaxed">
                {isAdvanced
                  ? <>Sends a transaction of 0.1 MON to the <span className="font-mono text-emerald-300">GuardianPolicyGuard</span> contract.</>
                  : "Executes a small, pre-approved action within safety limits."}
              </p>
              <div className="text-[11px] font-mono bg-background/60 p-2.5 rounded-lg border border-border/60 text-muted-foreground">
                <div className="flex justify-between items-center">
                  <span>Target:</span>
                  {isAdvanced ? (
                    <a
                      href="https://testnet.monadscan.com/address/0x90Fdc8E1e5C951701eCd84677038B38560CdEF60"
                      target="_blank"
                      rel="noreferrer"
                      className="text-foreground hover:text-emerald-400 hover:underline flex items-center gap-1 font-semibold"
                    >
                      0x90Fd...EF60 (Approved)
                      <ExternalLink className="h-2.5 w-2.5 inline" />
                    </a>
                  ) : (
                    <span className="text-emerald-400 font-semibold">Approved Security Contract</span>
                  )}
                </div>
                <div className="flex justify-between">
                  <span>Spend Cap:</span>
                  <span className="text-emerald-400">0.1 MON &le; 5.0 MON</span>
                </div>
              </div>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  onTriggerGuardedAction?.()
                }}
                disabled={isGuardedRunning}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-emerald-600 hover:bg-emerald-500 text-white text-xs font-semibold shadow-sm transition active:scale-[0.99] disabled:opacity-50"
              >
                {isGuardedRunning ? (
                  <span className="flex items-center gap-2">
                    <span className="h-3 w-3 border-2 border-white/60 border-t-white rounded-full animate-spin" />
                    Executing...
                  </span>
                ) : (
                  <>
                    <CheckCircle2 className="h-4 w-4" />
                    {isAdvanced ? "Trigger Guarded Action (0.1 MON)" : "Test Approved Action (0.1 MON)"}
                  </>
                )}
              </button>
            </CardContent>
          </Card>

          {/* Rogue Action Trigger */}
          <Card className="border-red-900/40 bg-gradient-to-br from-red-950/20 via-card to-card hover:border-red-600/50 transition-all shadow-sm">
            <CardHeader className="pb-3">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2.5">
                  <div className="p-2 rounded-lg bg-red-900/40 text-red-400 border border-red-700/40">
                    <XCircle className="h-5 w-5" />
                  </div>
                  <div>
                    <CardTitle className="text-base font-semibold text-red-200">
                      {isAdvanced ? "Test Rogue Action" : "Test Blocked Action"}
                    </CardTitle>
                    <p className="text-xs text-muted-foreground">
                      {isAdvanced ? "Violates Outflow & Target Allowlist" : "Simulates an attack exceeding spending limits"}
                    </p>
                  </div>
                </div>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded bg-red-950 border border-red-800 text-red-300">
                  10.0 MON
                </span>
              </div>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground leading-relaxed">
                {isAdvanced
                  ? "Simulates an autonomous agent attempting a 10 MON transfer to an unapproved recipient. Instantly intercepted off-chain by Privy Policy Engine before private keys sign. 0 gas burned."
                  : "Simulates an agent attempting an unauthorized 10 MON transfer. Instantly blocked before execution with zero fees burned."}
              </p>
              <div className="text-[11px] font-mono bg-background/60 p-2.5 rounded-lg border border-border/60 text-muted-foreground">
                <div className="flex justify-between">
                  <span>Target:</span>
                  <span className="text-red-400">{isAdvanced ? "0x9999...f08e (Unapproved EOA)" : "Unapproved Destination"}</span>
                </div>
                <div className="flex justify-between">
                  <span>Spend Cap:</span>
                  <span className="text-red-400">10.0 MON &gt; 5.0 MON Limit</span>
                </div>
              </div>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  onTriggerRogueAction?.()
                }}
                disabled={isRogueRunning}
                className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-red-700 hover:bg-red-600 text-white text-xs font-semibold shadow-sm transition active:scale-[0.99] disabled:opacity-50"
              >
                {isRogueRunning ? (
                  <span className="flex items-center gap-2">
                    <span className="h-3 w-3 border-2 border-white/60 border-t-white rounded-full animate-spin" />
                    Engaging Containment...
                  </span>
                ) : (
                  <>
                    <XCircle className="h-4 w-4" />
                    {isAdvanced ? "Test Rogue Action (10 MON Containment)" : "Test Blocked Action (10 MON)"}
                  </>
                )}
              </button>
            </CardContent>
          </Card>
        </div>

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
                <span className="font-bold uppercase tracking-wider">
                  {agentActionStatus.agentId ? `[${agentActionStatus.agentId}] ` : ""}{agentActionStatus.title}
                </span>
              </div>
              <span className="text-[11px] opacity-70">{agentActionStatus.timestamp}</span>
            </div>
            {isAdvanced && agentActionStatus.tx && (
              <div className="mt-2.5 pt-2 border-t border-emerald-900/60 flex items-center gap-2">
                <span className="text-muted-foreground">Tx Hash:</span>
                <span className="text-emerald-400 font-mono">
                  {agentActionStatus.tx.slice(0, 24)}...
                </span>
                <span className="px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                  Simulated
                </span>
              </div>
            )}
          </div>
        )}
      </section>

      {/* Beyond-Auth Architecture Card */}
      <Card className="border-[#836EF9]/40 bg-gradient-to-r from-[#836EF9]/10 via-card to-card">
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/30">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                {isAdvanced ? "Dual-Layer Beyond-Authentication Architecture" : "Three Layers of Agent Protection"}
                <span className="text-[10px] px-2 py-0.5 rounded-full bg-[#836EF9]/25 text-[#836EF9] font-normal border border-[#836EF9]/40 font-mono">
                  {isAdvanced ? "HARDWARE + MIDDLEWARE" : "AUTOMATED DEFENSE"}
                </span>
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5">
                {isAdvanced
                  ? "Autonomous agent session signing designed to protect keys with hardware enclaves"
                  : "How GuardianAI keeps your AI agents safe around the clock"}
              </p>
            </div>
          </div>
          {isAdvanced && defaultAgentAddress && (
            <div className="hidden sm:flex items-center gap-2">
              <span className="text-xs text-muted-foreground font-mono">Default Agent:</span>
              <span className="text-xs font-mono text-[#836EF9] bg-[#836EF9]/10 px-2 py-1 rounded border border-[#836EF9]/30">
                {`${defaultAgentAddress.slice(0, 6)}...${defaultAgentAddress.slice(-4)}`}
              </span>
            </div>
          )}
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-3 text-xs">
            <div className="p-3.5 rounded-xl border border-border/80 bg-background/50">
              <div className="font-semibold text-foreground mb-1 flex items-center justify-between">
                <span>{isAdvanced ? "Layer 1: Privy Policy Engine" : "Layer 1: Safety Firewall"}</span>
                <span className="text-[10px] text-emerald-400 font-mono">{isAdvanced ? "POLICY ENGINE" : "FIREWALL"}</span>
              </div>
              <p className="text-muted-foreground text-[11px] leading-relaxed">
                {isAdvanced
                  ? "Policy allowlist enforcing Chain 10143 (Monad), Target GuardianPolicyGuard, and Max Spend ≤ 5.0 MON before keys can sign."
                  : "Enforces spending caps and blocks unapproved recipients before any action can take place."}
              </p>
            </div>

            <div className="p-3.5 rounded-xl border border-border/80 bg-background/50">
              <div className="font-semibold text-foreground mb-1 flex items-center justify-between">
                <span>{isAdvanced ? "Layer 2: GuardianAI Middleware" : "Layer 2: Prompt Injection Shield"}</span>
                <span className="text-[10px] text-blue-400 font-mono">{isAdvanced ? "PRE-FLIGHT ATTEST" : "INSPECTION"}</span>
              </div>
              <p className="text-muted-foreground text-[11px] leading-relaxed">
                {isAdvanced
                  ? "EIP-712 runtime attestation, indirect prompt injection screening, and PolicyGuard calldata wrapping on Monad parallel blocks."
                  : "Analyzes agent prompts and input instructions in real time to prevent jailbreaks and malicious redirects."}
              </p>
            </div>

            <div className="p-3.5 rounded-xl border border-border/80 bg-background/50">
              <div className="font-semibold text-foreground mb-1 flex items-center justify-between">
                <span>{isAdvanced ? "Layer 3: Delegation State" : "Layer 3: Scoped Permissions"}</span>
                <span className="text-[10px] text-[#836EF9] font-mono">{isAdvanced ? "SESSION SIGNER" : "PERMISSIONS"}</span>
              </div>
              <p className="text-muted-foreground text-[11px] leading-relaxed">
                {isAdvanced
                  ? "Supervisor wallet delegates scoped session authority to AI agents. Keys are held within the hardware enclave."
                  : "You grant scoped authority to AI agents. Master keys are never exposed or directly accessible."}
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center justify-between gap-3 pt-1">
            <div className="text-xs text-muted-foreground">
              {isAdvanced ? "Want to delegate new session rights or update spend caps?" : "Explore our protected agent implementations and live security status:"}
            </div>
            <div className="flex items-center gap-2">
              {isAdvanced ? (
                <>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation()
                      onOpenDelegationModal?.(defaultAgentAddress, defaultPolicyId)
                    }}
                    className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg text-white bg-[#836EF9] hover:brightness-110 transition shadow-sm"
                  >
                    <Cpu className="h-3.5 w-3.5" />
                    Delegate Session Signer
                  </button>
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation()
                      onNavigateTab?.('policy')
                    }}
                    className="flex items-center gap-1.5 px-3 py-1.5 text-xs font-medium rounded-lg border border-border/80 text-foreground hover:bg-muted/40 transition"
                  >
                    <Sliders className="h-3.5 w-3.5 text-[#836EF9]" />
                    Guardrails
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation()
                    onNavigateTab?.('agents')
                  }}
                  className="flex items-center gap-1.5 px-3.5 py-1.5 text-xs font-semibold rounded-lg text-white bg-[#836EF9] hover:brightness-110 transition shadow-sm"
                >
                  <Cpu className="h-3.5 w-3.5" />
                  Explore Protected Agents
                </button>
              )}
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Quick Navigation Hub / Feature Cards */}
      <section className="space-y-3">
        <h2 className="text-lg font-semibold tracking-tight text-foreground flex items-center gap-2">
          <Layers className="h-4 w-4 text-[#836EF9]" />
          Platform Quick Access
        </h2>

        <div className={cn("grid gap-4 sm:grid-cols-2", isAdvanced ? "lg:grid-cols-4" : "lg:grid-cols-2")}>
          <div 
            role="button"
            tabIndex={0}
            onClick={(e) => {
              e.stopPropagation()
              onNavigateTab?.('dashboard')
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onNavigateTab?.('dashboard')
              }
            }}
            className="group cursor-pointer p-4 rounded-xl border border-border/80 bg-card hover:border-[#836EF9]/60 hover:bg-muted/20 transition-all focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="p-2 rounded-lg bg-[#836EF9]/15 text-[#836EF9]">
                <Activity className="h-5 w-5" />
              </div>
              <ArrowUpRight className="h-4 w-4 text-muted-foreground group-hover:text-[#836EF9] transition-colors" />
            </div>
            <h3 className="font-semibold text-sm text-foreground mb-1">{isAdvanced ? "Live Telemetry" : "Security Dashboard"}</h3>
            <p className="text-xs text-muted-foreground">
              {isAdvanced
                ? "Real-time threat stream, attack vector distribution, and Monad parallel throughput metrics."
                : "Live security status, intercepted threats, and automated protection metrics."}
            </p>
          </div>

          {isAdvanced && (
            <div 
              role="button"
              tabIndex={0}
              onClick={(e) => {
                e.stopPropagation()
                onNavigateTab?.('policy')
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  onNavigateTab?.('policy')
                }
              }}
              className="group cursor-pointer p-4 rounded-xl border border-border/80 bg-card hover:border-[#836EF9]/60 hover:bg-muted/20 transition-all focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
            >
              <div className="flex items-center justify-between mb-2">
                <div className="p-2 rounded-lg bg-emerald-500/15 text-emerald-400">
                  <Sliders className="h-5 w-5" />
                </div>
                <ArrowUpRight className="h-4 w-4 text-muted-foreground group-hover:text-emerald-400 transition-colors" />
              </div>
              <h3 className="font-semibold text-sm text-foreground mb-1">Guardrails</h3>
              <p className="text-xs text-muted-foreground">
                Configure spend caps, 24h outflow limits, time-locks, and target contract allowlists.
              </p>
            </div>
          )}

          <div 
            role="button"
            tabIndex={0}
            onClick={(e) => {
              e.stopPropagation()
              onNavigateTab?.('agents')
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                onNavigateTab?.('agents')
              }
            }}
            className="group cursor-pointer p-4 rounded-xl border border-border/80 bg-card hover:border-[#836EF9]/60 hover:bg-muted/20 transition-all focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
          >
            <div className="flex items-center justify-between mb-2">
              <div className="p-2 rounded-lg bg-blue-500/15 text-blue-400">
                <Cpu className="h-5 w-5" />
              </div>
              <ArrowUpRight className="h-4 w-4 text-muted-foreground group-hover:text-blue-400 transition-colors" />
            </div>
            <h3 className="font-semibold text-sm text-foreground mb-1">{isAdvanced ? "Agent Directory" : "Protected Agents"}</h3>
            <p className="text-xs text-muted-foreground">
              {isAdvanced
                ? "Manage active AI agents, ERC-8004 Soulbound Passports, and supervisor delegations."
                : "View protected AI agent architectures and their active security safeguards."}
            </p>
          </div>

          {isAdvanced && (
            <div 
              role="button"
              tabIndex={0}
              onClick={(e) => {
                e.stopPropagation()
                onNavigateTab?.('logs')
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  onNavigateTab?.('logs')
                }
              }}
              className="group cursor-pointer p-4 rounded-xl border border-border/80 bg-card hover:border-[#836EF9]/60 hover:bg-muted/20 transition-all focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
            >
              <div className="flex items-center justify-between mb-2">
                <div className="p-2 rounded-lg bg-amber-500/15 text-amber-400">
                  <Terminal className="h-5 w-5" />
                </div>
                <ArrowUpRight className="h-4 w-4 text-muted-foreground group-hover:text-amber-400 transition-colors" />
              </div>
              <h3 className="font-semibold text-sm text-foreground mb-1">Audit Logs</h3>
              <p className="text-xs text-muted-foreground">
                Filterable event audit table with severity badges, latency, and MonadScan explorer links.
              </p>
            </div>
          )}
        </div>
      </section>
    </div>
  )
}
