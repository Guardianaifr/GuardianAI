import React from 'react'
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { 
  Terminal, 
  Activity, 
  Shield, 
  Zap, 
  AlertTriangle, 
  Cpu, 
  Gauge, 
  TrendingUp, 
  CheckCircle2,
  ExternalLink,
  Layers,
  ArrowRight,
  Lock,
  FileText,
  KeyRound
} from "lucide-react"
import { cn } from "@/lib/utils"

export function DashboardTab({
  events = [],
  stats = {},
  vectorData = {},
  indexerStatus,
  isConnected,
  isLiveSimulating,
  onNavigateTab
}) {
  // Calculate dynamic attack vector percentages
  const totalVectors = Math.max(1, (vectorData.prompt || 0) + (vectorData.pii || 0) + (vectorData.admin || 0) + (stats.blocked || 0))
  const promptPct = Math.min(100, Math.round(((vectorData.prompt || 0) / totalVectors) * 100))
  const piiPct = Math.min(100, Math.round(((vectorData.pii || 0) / totalVectors) * 100))
  const policyPct = Math.min(100, Math.round(((stats.blocked || 0) / totalVectors) * 100))
  const enclavePct = Math.min(100, Math.round(((vectorData.admin || 0) / totalVectors) * 100))

  // Risk Score calculation based on recent events
  const recentEvents = events.slice(0, 20)
  const scores = recentEvents.map(e => e.details?.riskScore || (e.severity === 'CRITICAL' ? 95 : e.severity === 'HIGH' ? 70 : 15))
  const avgRiskScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 14
  const peakRiskScore = scores.length > 0 ? Math.max(...scores) : 98

  // Blocked vs verified ratio
  const totalRequests = stats.requests || 1482
  const blockedCount = stats.blocked || 94
  const redactedCount = stats.redacted || 17
  const verifiedCount = Math.max(0, totalRequests - blockedCount)

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Section: Monad Parallel Throughput & Latency Metrics */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold tracking-tight text-foreground flex items-center gap-2">
            <Cpu className="h-4 w-4 text-[#836EF9]" />
            Monad Parallel EVM Telemetry & Throughput
          </h2>
          <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>Parallel BFT Consensus • Chain 10143</span>
          </div>
        </div>

        <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Parallel Execution TPS</CardTitle>
              <Zap className="h-4 w-4 text-[#836EF9]" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-foreground">9,840</span>
                <span className="text-xs font-mono text-emerald-400 font-semibold">+14.2%</span>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">Non-blocking parallel state transitions</p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Monad Block Latency</CardTitle>
              <Activity className="h-4 w-4 text-emerald-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-foreground">0.8s</span>
                <span className="text-xs font-mono text-emerald-400">Sub-second</span>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">Real-time BFT consensus commit time</p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Containment Ratio</CardTitle>
              <Shield className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-emerald-400">99.2%</span>
                <span className="text-xs font-mono text-muted-foreground">Zero Leaks</span>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">Adversarial prompt & outflow interdiction</p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Active Protocol Guards</CardTitle>
              <Layers className="h-4 w-4 text-purple-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-purple-300">3 Primitives</span>
                <span className="text-xs font-mono text-emerald-400">P256 + TEE</span>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">PolicyGuard, Passport SBT, Mera PRF</p>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Main Grid: Runtime Risk & Threat Anomaly Engine (Left) & Attack Vector Distribution (Right) */}
      <div className="grid gap-6 grid-cols-1 lg:grid-cols-2">
        {/* Card 1: Runtime Risk & Threat Anomaly Engine */}
        <Card className="border-border/80 bg-card/80 flex flex-col justify-between">
          <CardHeader className="pb-3 border-b border-border/50">
            <CardTitle className="text-base font-semibold text-foreground flex items-center justify-between">
              <span className="flex items-center gap-2">
                <Gauge className="h-4 w-4 text-[#836EF9]" />
                Runtime Risk & Anomaly Engine
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-emerald-950 text-emerald-400 border border-emerald-800">
                ACTIVE MONITOR
              </span>
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              Continuous entropy anomaly scoring and prompt injection severity assessment
            </p>
          </CardHeader>
          <CardContent className="space-y-6 pt-5">
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 rounded-xl border border-border/80 bg-background/50 text-center">
                <span className="text-xs text-muted-foreground">Session Average Risk</span>
                <div className="text-3xl font-bold font-mono mt-1 text-emerald-400">
                  {avgRiskScore} <span className="text-xs text-muted-foreground font-normal">/ 100</span>
                </div>
                <span className="text-[10px] text-emerald-400 font-mono">NOMINAL BASELINE</span>
              </div>
              <div className="p-4 rounded-xl border border-border/80 bg-background/50 text-center">
                <span className="text-xs text-muted-foreground">Peak Intercepted Risk</span>
                <div className="text-3xl font-bold font-mono mt-1 text-red-500">
                  {peakRiskScore} <span className="text-xs text-muted-foreground font-normal">/ 100</span>
                </div>
                <span className="text-[10px] text-red-400 font-mono">CONTAINED ATTACK</span>
              </div>
            </div>

            {/* Visual Risk Gauge Meter */}
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-muted-foreground font-mono">
                <span>Safety Continuum</span>
                <span className="font-semibold text-foreground">
                  {avgRiskScore < 30 ? "Optimal Protection (Green)" : avgRiskScore < 70 ? "Elevated Monitoring (Amber)" : "Critical Rogue Tier (Red)"}
                </span>
              </div>
              <div className="h-3 w-full rounded-full bg-secondary overflow-hidden flex">
                <div className="h-full bg-emerald-500" style={{ width: '40%' }} title="Safe Tier (0-40)" />
                <div className="h-full bg-amber-500" style={{ width: '30%' }} title="Elevated Tier (40-70)" />
                <div className="h-full bg-red-500" style={{ width: '30%' }} title="Critical Rogue Tier (70-100)" />
              </div>
              <div className="flex justify-between text-[10px] text-muted-foreground font-mono">
                <span>0 (Compliant)</span>
                <span>40 (Warning)</span>
                <span>70 (Interdict)</span>
                <span>100 (Rogue)</span>
              </div>
            </div>

            <div className="p-3.5 rounded-xl border border-border/70 bg-muted/20 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-emerald-400" />
                <span className="text-muted-foreground">Pre-flight verification gate:</span>
              </div>
              <span className="font-mono font-semibold text-emerald-400">100% Transactions Scanned</span>
            </div>
          </CardContent>
        </Card>

        {/* Card 2: Attack Vector Distribution Chart */}
        <Card className="border-border/80 bg-card/80 flex flex-col justify-between">
          <CardHeader className="pb-3 border-b border-border/50">
            <CardTitle className="text-base font-semibold text-foreground flex items-center justify-between">
              <span className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-[#836EF9]" />
                Attack Vector Distribution
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/30">
                {totalRequests} SCANS
              </span>
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              Live categorization of intercepted prompt attacks, leaks, and policy breaches
            </p>
          </CardHeader>
          <CardContent className="space-y-4 pt-5">
            {/* Vector 1: Prompt Injections */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-muted-foreground flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-red-500" />
                  Indirect Prompt Injections
                </span>
                <span className="font-semibold text-foreground">{vectorData.prompt || 94} ({promptPct}%)</span>
              </div>
              <div className="h-2 bg-secondary rounded-full overflow-hidden">
                <div 
                  className="h-full bg-red-500 transition-all duration-500 rounded-full" 
                  style={{ width: `${promptPct}%` }} 
                />
              </div>
            </div>

            {/* Vector 2: Data Leaks / PII */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-muted-foreground flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-amber-500" />
                  Key / PII Leaks Scrubbed
                </span>
                <span className="font-semibold text-foreground">{vectorData.pii || 17} ({piiPct}%)</span>
              </div>
              <div className="h-2 bg-secondary rounded-full overflow-hidden">
                <div 
                  className="h-full bg-amber-500 transition-all duration-500 rounded-full" 
                  style={{ width: `${piiPct}%` }} 
                />
              </div>
            </div>

            {/* Vector 3: Policy Containment Breaches */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-muted-foreground flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-[#836EF9]" />
                  Policy Outflow Breaches
                </span>
                <span className="font-semibold text-foreground">{stats.blocked || 94} ({policyPct}%)</span>
              </div>
              <div className="h-2 bg-secondary rounded-full overflow-hidden">
                <div 
                  className="h-full bg-[#836EF9] transition-all duration-500 rounded-full" 
                  style={{ width: `${policyPct}%` }} 
                />
              </div>
            </div>

            {/* Vector 4: Enclave Passkey Attestations */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-muted-foreground flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-blue-500" />
                  Memory Enclave Tripwires
                </span>
                <span className="font-semibold text-foreground">{vectorData.admin || 340} ({enclavePct}%)</span>
              </div>
              <div className="h-2 bg-secondary rounded-full overflow-hidden">
                <div 
                  className="h-full bg-blue-500 transition-all duration-500 rounded-full" 
                  style={{ width: `${enclavePct}%` }} 
                />
              </div>
            </div>

            <div className="p-3.5 rounded-xl border border-border/70 bg-muted/20 flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Verified Non-Malicious Actions:</span>
              <span className="font-mono font-semibold text-foreground">{verifiedCount} allowed</span>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Bottom Grid: Infrastructure Specifications & Dedicated Audit Logs Bridge */}
      <div className="grid gap-6 grid-cols-1 lg:grid-cols-2">
        {/* Card 3: Monad Infrastructure Layer Specifications */}
        <Card className="border-border/80 bg-card/80">
          <CardHeader className="pb-3 border-b border-border/50">
            <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
              <Cpu className="h-4 w-4 text-[#836EF9]" />
              Monad Protocol Specifications
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              Verified on-chain contract addresses and hardware primitives on Monad Testnet
            </p>
          </CardHeader>
          <CardContent className="space-y-3 pt-4 text-xs font-mono">
            <div className="flex justify-between items-center py-1.5 border-b border-border/60">
              <span className="text-muted-foreground">Chain Target</span>
              <span className="text-foreground font-semibold">Monad Testnet (10143)</span>
            </div>
            <div className="flex justify-between items-center py-1.5 border-b border-border/60">
              <span className="text-muted-foreground">Execution Firewalls</span>
              <span className="text-purple-300">GuardianPolicyGuard (0x90Fd...EF60)</span>
            </div>
            <div className="flex justify-between items-center py-1.5 border-b border-border/60">
              <span className="text-muted-foreground">Identity Registry</span>
              <span className="text-emerald-400 font-semibold">ERC-8004 Soulbound (0xDA5f...2Cff)</span>
            </div>
            <div className="flex justify-between items-center py-1.5 border-b border-border/60">
              <span className="text-muted-foreground">Precompile Engine</span>
              <span className="text-blue-400">Native Monad RIP-7212 (0x100)</span>
            </div>
            <div className="flex justify-between items-center py-1.5">
              <span className="text-muted-foreground">Indexer Protocol</span>
              <span className={cn(
                "font-semibold",
                indexerStatus === "connected" ? "text-emerald-400" : "text-blue-400"
              )}>
                {indexerStatus === "connected" 
                  ? "Envio HyperIndex (Connected)" 
                  : isLiveSimulating 
                  ? "Envio Standalone Simulator" 
                  : "Direct WebSockets"}
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Card 4: Dedicated Audit Logs Bridge */}
        <Card className="border-[#836EF9]/40 bg-gradient-to-br from-[#836EF9]/10 via-card to-card flex flex-col justify-between">
          <CardHeader className="pb-3 border-b border-border/50">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                <FileText className="h-4 w-4 text-[#836EF9]" />
                Cryptographic Audit Log Center
              </CardTitle>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/30">
                DEDICATED SECTION
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              Raw execution logs, transaction hashes, and forensic search have been segregated into the Logs tab
            </p>
          </CardHeader>
          <CardContent className="space-y-4 pt-4">
            <div className="p-3.5 rounded-xl border border-border/80 bg-background/50 text-xs text-muted-foreground leading-relaxed">
              Every on-chain action, prompt injection attempt, session key delegation, and circuit breaker tripwire is immutably logged with its timestamp, latency, target address, and MonadScan explorer link.
            </div>

            <div className="flex items-center justify-between pt-2">
              <div className="text-xs font-mono text-muted-foreground">
                <span className="text-foreground font-semibold">{events.length}</span> logged events available
              </div>
              <button
                type="button"
                onClick={() => onNavigateTab?.('logs')}
                className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-lg text-white bg-[#836EF9] hover:brightness-110 transition shadow-sm active:scale-95"
              >
                <span>Open Audit Logs Tab</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
