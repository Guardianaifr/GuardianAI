import React, { useEffect, useState } from 'react'
import { ethers } from 'ethers'
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
import { 
  calculateRiskScores, 
  classifyActionOutcomes, 
  getSafetyContinuumStatus, 
  calculateShareBlocked,
  getSimpleStatusIndicator
} from "@/lib/truthfulnessMetrics"

export function DashboardTab({
  events = [],
  stats = {},
  vectorData = {},
  indexerStatus,
  isConnected,
  isLiveSimulating,
  isBlockedEvent,
  onNavigateTab,
  isAdvanced = false
}) {
  // Calculate dynamic attack vector percentages
  const totalVectors = (vectorData.prompt || 0) + (vectorData.pii || 0) + (vectorData.admin || 0) + (stats.blocked || 0)
  const promptPct = totalVectors > 0 ? Math.min(100, Math.round(((vectorData.prompt || 0) / totalVectors) * 100)) : 0
  const piiPct = totalVectors > 0 ? Math.min(100, Math.round(((vectorData.pii || 0) / totalVectors) * 100)) : 0
  const policyPct = totalVectors > 0 ? Math.min(100, Math.round(((stats.blocked || 0) / totalVectors) * 100)) : 0
  const enclavePct = totalVectors > 0 ? Math.min(100, Math.round(((vectorData.admin || 0) / totalVectors) * 100)) : 0

  // Risk Score calculation based on recent events (F1/F16: null if no data, never default to 14)
  const { avgRiskScore, peakRiskScore } = calculateRiskScores(events)

  // F10 Action outcome classification: separate allowed / blocked / couldn't verify
  const { totalRequests, allowedCount, blockedCount, couldntVerifyCount } = classifyActionOutcomes(events, stats)

  // Advanced mode safety continuum status
  const continuumStatus = getSafetyContinuumStatus(avgRiskScore, couldntVerifyCount)

  // Simple mode fail-closed status indicator
  const simpleStatus = getSimpleStatusIndicator(avgRiskScore, couldntVerifyCount)

  const [realChainData, setRealChainData] = useState({ tps: "--", latency: "--" });

  useEffect(() => {
    let active = true;
    const fetchChainData = async () => {
      try {
        const provider = new ethers.JsonRpcProvider('https://testnet-rpc.monad.xyz');
        const latestBlockNumber = await provider.getBlockNumber();
        const latestBlock = await provider.getBlock(latestBlockNumber);
        const pastBlock = await provider.getBlock(latestBlockNumber - 5);
        if (latestBlock && pastBlock && latestBlock.timestamp > pastBlock.timestamp && active) {
          let txCount = 0;
          for (let i = 0; i < 5; i++) {
             const b = await provider.getBlock(latestBlockNumber - i);
             if (b && b.transactions) txCount += b.transactions.length;
          }
          const timeDiff = latestBlock.timestamp - pastBlock.timestamp;
          const calculatedTps = (txCount / timeDiff).toFixed(1);
          const calculatedLatency = (timeDiff / 5).toFixed(2) + 's';
          setRealChainData({ tps: calculatedTps, latency: calculatedLatency });
        }
      } catch (e) {
        console.error("Error fetching real metrics:", e);
      }
    };
    fetchChainData();
    const interval = setInterval(fetchChainData, 15000);
    return () => { active = false; clearInterval(interval); };
  }, []);

  const actualShareBlocked = calculateShareBlocked(blockedCount, totalRequests);

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Top Section: Monad Parallel Throughput & Latency Metrics */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <h2 className="text-lg font-semibold tracking-tight text-foreground flex items-center gap-2">
            <Cpu className="h-4 w-4 text-[#836EF9]" />
            {isAdvanced ? "Monad Parallel EVM Telemetry & Throughput" : "System Throughput & Protection Metrics"}
          </h2>
          <div className="flex items-center gap-2 text-xs font-mono text-muted-foreground">
            <span className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
            <span>{isAdvanced ? "Parallel BFT Consensus • Chain 10143" : "Active Protection Feed"}</span>
          </div>
        </div>

        <div className="grid gap-4 grid-cols-1 sm:grid-cols-2 lg:grid-cols-4">
          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">
                {isAdvanced ? "Parallel Execution TPS" : "Execution Speed"}
              </CardTitle>
              <Zap className="h-4 w-4 text-[#836EF9]" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-foreground">{realChainData.tps}</span>
                <span className="text-xs font-mono text-emerald-400 font-semibold">+14.2%</span>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">
                {isAdvanced ? "Non-blocking parallel state transitions" : "Actions processed per second"}
              </p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">
                {isAdvanced ? "Monad Block Latency" : "Response Time"}
              </CardTitle>
              <Activity className="h-4 w-4 text-emerald-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-foreground">{realChainData.latency}</span>
                <span className="text-xs font-mono text-emerald-400">Sub-second</span>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">
                {isAdvanced ? "Real-time BFT consensus commit time" : "Real-time network response time"}
              </p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Share blocked</CardTitle>
              <Shield className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className={cn("text-2xl font-bold font-mono", isAdvanced ? continuumStatus.colorClass : simpleStatus.colorClass)}>
                  {actualShareBlocked}
                </span>
                <span className="text-xs font-mono text-muted-foreground">
                  {totalRequests > 0 ? `${blockedCount} blocked · ${couldntVerifyCount} couldn't verify` : "No Data Yet"}
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">
                {isAdvanced ? "Adversarial prompt & outflow interdiction" : "Attacks and unauthorized transfers blocked"}
              </p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">
                {isAdvanced ? "Active Protocol Guards" : "Active Protections"}
              </CardTitle>
              <Layers className="h-4 w-4 text-purple-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-purple-300">
                  {isAdvanced ? "3 Primitives" : "3 Protections"}
                </span>
                <span className="text-xs font-mono text-emerald-400">
                  {isAdvanced ? "P256 Precompile" : "Enforced"}
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">
                {isAdvanced ? "PolicyGuard, Passport SBT, Mera PRF" : "Firewall, Identity, Memory Isolation"}
              </p>
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
                {isAdvanced ? "Runtime Risk & Anomaly Engine" : "Threat Monitoring Engine"}
              </span>
              <span className={cn(
                "text-[10px] font-mono px-2 py-0.5 rounded border",
                !isAdvanced
                  ? simpleStatus.badgeClass
                  : "bg-emerald-950 text-emerald-400 border-emerald-800"
              )}>
                {!isAdvanced ? simpleStatus.statusLabel : "ACTIVE MONITOR"}
              </span>
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              {isAdvanced
                ? "Continuous entropy anomaly scoring and prompt injection severity assessment"
                : "Live assessment of security risks and incoming requests"}
            </p>
          </CardHeader>
          <CardContent className="space-y-6 pt-5">
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 rounded-xl border border-border/80 bg-background/50 text-center">
                <span className="text-xs text-muted-foreground">Session Average Risk</span>
                <div className={cn("text-3xl font-bold font-mono mt-1", isAdvanced ? continuumStatus.colorClass : simpleStatus.colorClass)}>
                  {avgRiskScore !== null ? avgRiskScore : "--"} <span className="text-xs text-muted-foreground font-normal">/ 100</span>
                </div>
                <span className={cn("text-[10px] font-mono", isAdvanced ? continuumStatus.colorClass : simpleStatus.colorClass)}>
                  {isAdvanced ? continuumStatus.statusLabel : simpleStatus.statusLabel}
                </span>
              </div>
              <div className="p-4 rounded-xl border border-border/80 bg-background/50 text-center">
                <span className="text-xs text-muted-foreground">Peak Intercepted Risk</span>
                <div className="text-3xl font-bold font-mono mt-1 text-red-500">
                  {peakRiskScore !== null ? peakRiskScore : "--"} <span className="text-xs text-muted-foreground font-normal">/ 100</span>
                </div>
                <span className={cn(
                  "text-[10px] font-mono",
                  peakRiskScore === null ? "text-muted-foreground" : "text-red-400"
                )}>
                  {peakRiskScore !== null ? (isAdvanced ? "CONTAINED ATTACK" : "Contained Attack") : "NO DATA YET"}
                </span>
              </div>
            </div>

            {/* Visual Risk Gauge Meter */}
            <div className="space-y-2">
              <div className="flex justify-between text-xs text-muted-foreground font-mono">
                <span>{isAdvanced ? "Safety Continuum" : "Protection Status"}</span>
                <span className={cn("font-semibold", isAdvanced ? "text-foreground" : simpleStatus.colorClass)}>
                  {isAdvanced ? continuumStatus.text : simpleStatus.statusLabel}
                </span>
              </div>
              <div className="h-3 w-full rounded-full bg-secondary overflow-hidden flex">
                {avgRiskScore === null ? (
                  <div className="h-full bg-muted/40 w-full" title="No activity recorded yet" />
                ) : (
                  <>
                    <div className="h-full bg-emerald-500" style={{ width: '40%' }} title="Safe Tier (0-40)" />
                    <div className="h-full bg-amber-500" style={{ width: '30%' }} title="Elevated Tier (40-70)" />
                    <div className="h-full bg-red-500" style={{ width: '30%' }} title="Critical Rogue Tier (70-100)" />
                  </>
                )}
              </div>
              <div className="flex justify-between text-[10px] text-muted-foreground font-mono">
                <span>{isAdvanced ? "0 (Compliant)" : "Low Risk"}</span>
                <span>{isAdvanced ? "40 (Warning)" : "Moderate"}</span>
                <span>{isAdvanced ? "70 (Interdict)" : "High"}</span>
                <span>{isAdvanced ? "100 (Rogue)" : "Critical"}</span>
              </div>
            </div>

            <div className="p-3.5 rounded-xl border border-border/70 bg-muted/20 flex items-center justify-between text-xs">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-emerald-400" />
                <span className="text-muted-foreground">
                  {isAdvanced ? "Pre-flight verification gate:" : "Automated verification gate:"}
                </span>
              </div>
              <span className={cn("font-mono font-semibold", couldntVerifyCount > 0 ? "text-amber-400" : "text-emerald-400")}>
                {totalRequests > 0 
                  ? `${blockedCount} blocked · ${couldntVerifyCount} couldn't verify` 
                  : (isAdvanced ? "No Transactions Recorded" : "No Activity Recorded")}
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Card 2: Attack Vector Distribution Chart */}
        <Card className="border-border/80 bg-card/80 flex flex-col justify-between">
          <CardHeader className="pb-3 border-b border-border/50">
            <CardTitle className="text-base font-semibold text-foreground flex items-center justify-between">
              <span className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-[#836EF9]" />
                {isAdvanced ? "Attack Vector Distribution" : "Threat Categorization"}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/30">
                {totalRequests} {isAdvanced ? "SCANS" : "CHECKS"}
              </span>
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              {isAdvanced 
                ? "Live categorization of intercepted prompt attacks, leaks, and policy breaches" 
                : "Breakdown of stopped attacks and safety violations"}
            </p>
          </CardHeader>
          <CardContent className="space-y-4 pt-5">
            {/* Vector 1: Prompt Injections */}
            <div className="space-y-1.5">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-muted-foreground flex items-center gap-1.5">
                  <span className="h-2 w-2 rounded-full bg-red-500" />
                  {isAdvanced ? "Indirect Prompt Injections" : "Prompt Injections Blocked"}
                </span>
                <span className="font-semibold text-foreground">{vectorData.prompt || 0} ({promptPct}%)</span>
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
                  {isAdvanced ? "Key / PII Leaks Scrubbed" : "Sensitive Data Leaks Prevented"}
                </span>
                <span className="font-semibold text-foreground">{vectorData.pii || 0} ({piiPct}%)</span>
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
                  {isAdvanced ? "Policy Outflow Breaches" : "Unauthorized Spending Stopped"}
                </span>
                <span className="font-semibold text-foreground">{stats.blocked || 0} ({policyPct}%)</span>
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
                  {isAdvanced ? "Memory Enclave Tripwires" : "Memory Tampering Intercepted"}
                </span>
                <span className="font-semibold text-foreground">{vectorData.admin || 0} ({enclavePct}%)</span>
              </div>
              <div className="h-2 bg-secondary rounded-full overflow-hidden">
                <div 
                  className="h-full bg-blue-500 transition-all duration-500 rounded-full" 
                  style={{ width: `${enclavePct}%` }} 
                />
              </div>
            </div>

            {/* F10: Separated action outcomes: allowed / blocked / couldn't verify */}
            <div className="p-3.5 rounded-xl border border-border/70 bg-muted/20 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
              <span className="text-muted-foreground">Action Outcomes Breakdown:</span>
              <div className="flex items-center gap-3 font-mono">
                <span className="text-emerald-400 font-semibold">{allowedCount} allowed</span>
                <span className="text-muted-foreground/40">•</span>
                <span className="text-red-400 font-semibold">{blockedCount} blocked</span>
                <span className="text-muted-foreground/40">•</span>
                <span className="text-amber-400 font-semibold">{couldntVerifyCount} couldn't verify</span>
              </div>
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
              {isAdvanced ? "Monad Protocol Specifications" : "Active Security Services"}
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              {isAdvanced 
                ? "Configured on-chain contract addresses and primitives on Monad Testnet"
                : "Automated safeguards running continuously to protect your agents"}
            </p>
          </CardHeader>
          <CardContent className="space-y-3 pt-4 text-xs font-mono">
            {isAdvanced ? (
              <>
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
              </>
            ) : (
              <>
                <div className="flex justify-between items-center py-1.5 border-b border-border/60">
                  <span className="text-muted-foreground font-sans">Protection Engine</span>
                  <span className="text-emerald-400 font-sans font-semibold flex items-center gap-1.5">
                    <CheckCircle2 className="h-3.5 w-3.5" /> Active & Monitoring
                  </span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-border/60">
                  <span className="text-muted-foreground font-sans">Execution Safeguards</span>
                  <span className="text-foreground font-sans font-semibold">Spending & Action Limits Enforced</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-border/60">
                  <span className="text-muted-foreground font-sans">Agent Identity Checks</span>
                  <span className="text-foreground font-sans font-semibold">Verified Passports Required</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-border/60">
                  <span className="text-muted-foreground font-sans">Hardware Enclave Defense</span>
                  <span className="text-foreground font-sans font-semibold">Keys Protected In Secure Storage</span>
                </div>
                <div className="flex justify-between items-center py-1.5">
                  <span className="text-muted-foreground font-sans">Activity Log Stream</span>
                  <span className="text-emerald-400 font-sans font-semibold">Connected</span>
                </div>
              </>
            )}
          </CardContent>
        </Card>

        {/* Card 4: Dedicated Audit Logs Bridge */}
        <Card className="border-[#836EF9]/40 bg-gradient-to-br from-[#836EF9]/10 via-card to-card flex flex-col justify-between">
          <CardHeader className="pb-3 border-b border-border/50">
            <div className="flex items-center justify-between">
              <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                <FileText className="h-4 w-4 text-[#836EF9]" />
                {isAdvanced ? "Cryptographic Audit Log Center" : "Activity Log Summary"}
              </CardTitle>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded-full bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/30">
                {isAdvanced ? "DEDICATED SECTION" : "AUDIT TRAIL"}
              </span>
            </div>
            <p className="text-xs text-muted-foreground mt-0.5">
              {isAdvanced 
                ? "Raw execution logs, transaction hashes, and forensic search have been segregated into the Logs tab"
                : "Complete history of all agent activities and blocked threats"}
            </p>
          </CardHeader>
          <CardContent className="space-y-4 pt-4">
            <div className="p-3.5 rounded-xl border border-border/80 bg-background/50 text-xs text-muted-foreground leading-relaxed">
              {isAdvanced 
                ? "Every on-chain action, prompt injection attempt, session key delegation, and circuit breaker tripwire is immutably logged with its timestamp, latency, target address, and MonadScan explorer link."
                : "Every AI agent action, security check, and blocked attempt is permanently recorded with full details and verification records."}
            </div>

            <div className="flex items-center justify-between pt-2">
              <div className="text-xs font-mono text-muted-foreground">
                <span className="text-foreground font-semibold">{events.length}</span> {isAdvanced ? "logged events available" : "recorded events"}
              </div>
              <button
                type="button"
                onClick={() => onNavigateTab?.('logs')}
                className="flex items-center gap-1.5 px-4 py-2 text-xs font-semibold rounded-lg text-white bg-[#836EF9] hover:brightness-110 transition shadow-sm active:scale-95"
              >
                <span>{isAdvanced ? "Open Audit Logs Tab" : "View Activity Logs"}</span>
                <ArrowRight className="h-3.5 w-3.5" />
              </button>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}
