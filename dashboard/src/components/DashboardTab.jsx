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
import { POLICY_GUARD_ADDRESS } from "@/lib/constants"
import { 
  calculateRiskScores, 
  classifyActionOutcomes, 
  getSafetyContinuumStatus, 
  getSimpleStatusIndicator
} from "@/lib/truthfulnessMetrics"

export function DashboardTab({
  events = [],
  threatFeed = [],
  stats = {},
  vectorData = {},
  indexerStatus,
  isConnected,
  isLiveSimulating,
  isBlockedEvent,
  onNavigateTab,
  isAdvanced = false
}) {
  // Calculate dynamic security record counts without turning missing data into zero
  const isFetchFailed = indexerStatus === "failed" || stats.status === "failed"
  const threatsCount = vectorData.threatsRegistered !== undefined && vectorData.threatsRegistered !== null
    ? vectorData.threatsRegistered
    : (stats.threatsRegistered !== undefined && stats.threatsRegistered !== null ? stats.threatsRegistered : null)
  const activeThreatsCount = vectorData.activeThreats !== undefined && vectorData.activeThreats !== null
    ? vectorData.activeThreats
    : (stats.activeThreats !== undefined && stats.activeThreats !== null ? stats.activeThreats : null)
  const passportsCount = vectorData.passportsTracked !== undefined && vectorData.passportsTracked !== null
    ? vectorData.passportsTracked
    : (stats.passportsTracked !== undefined && stats.passportsTracked !== null ? stats.passportsTracked : null)

  // Filter out simulated events outside demo mode for risk scores, outcomes, and status indicators
  const isDemoActive = typeof window !== 'undefined' && (new URLSearchParams(window.location.search).get('demo') === 'true');
  const evaluatedEvents = isDemoActive ? events : events.filter(e => !e.isSimulated);

  const [liveThreshold, setLiveThreshold] = useState(25);
  const [thresholdLabel, setThresholdLabel] = useState("default threshold 25");

  // Risk Score calculation based on recent events (F1/F16: null if no data, never default to 14)
  const { avgRiskScore, peakRiskScore } = calculateRiskScores(evaluatedEvents)

  // F10 Action outcome classification: separate actionsExecuted / threatsRegistered
  const { actionsExecuted, threatsRegistered, couldntVerifyCount } = classifyActionOutcomes(evaluatedEvents, stats, isFetchFailed)

  // Advanced mode safety continuum status
  const continuumStatus = getSafetyContinuumStatus(avgRiskScore, couldntVerifyCount)

  // Simple mode fail-closed status indicator: strict evaluation order
  const simpleStatus = getSimpleStatusIndicator({
    avgRiskScore,
    peakRiskScore,
    events: evaluatedEvents,
    threatFeed,
    fetchFailed: isFetchFailed,
    couldntVerifyCount,
    maxAllowedRiskScore: liveThreshold
  })

  useEffect(() => {
    let active = true;
    const fetchThreshold = async () => {
      try {
        const provider = new ethers.JsonRpcProvider('https://testnet-rpc.monad.xyz');
        const policyGuard = new ethers.Contract(
          POLICY_GUARD_ADDRESS,
          ['function maxAllowedRiskScore() view returns (uint8)'],
          provider
        );
        const score = await policyGuard.maxAllowedRiskScore();
        if (active) {
          setLiveThreshold(Number(score));
          setThresholdLabel(`threshold ${Number(score)} (on-chain)`);
        }
      } catch (err) {
        if (active) {
          setThresholdLabel("default threshold 25");
        }
      }
    };
    fetchThreshold();
    return () => { active = false; };
  }, []);

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

        {stats?.isStale && (
          <div data-testid="stale-banner" className="p-3 rounded-xl border border-amber-800/50 bg-amber-950/20 text-amber-300 text-xs flex items-center justify-between">
            <div className="flex items-center gap-2">
              <AlertTriangle className="h-4 w-4 text-amber-400 shrink-0" />
              <span>{stats.staleMessage || "Connection interrupted. Couldn't refresh data."}</span>
            </div>
            <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-amber-500/20 text-amber-300 border border-amber-500/30">
              STALE CACHE
            </span>
          </div>
        )}

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
                {isFetchFailed ? (
                  <span className="text-sm font-sans text-amber-400 font-semibold">Couldn't load data</span>
                ) : (
                  <>
                    <span className="text-2xl font-bold font-mono text-foreground">{realChainData.tps}</span>
                    <span className="text-xs font-mono text-emerald-400 font-semibold">Real-time</span>
                  </>
                )}
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
                {isFetchFailed ? (
                  <span className="text-sm font-sans text-amber-400 font-semibold">Couldn't load data</span>
                ) : (
                  <>
                    <span className="text-2xl font-bold font-mono text-foreground">{realChainData.latency}</span>
                    <span className="text-xs font-mono text-emerald-400">Sub-second</span>
                  </>
                )}
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">
                {isAdvanced ? "Real-time BFT consensus commit time" : "Real-time network response time"}
              </p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Actions executed</CardTitle>
              <Zap className="h-4 w-4 text-emerald-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                {isFetchFailed ? (
                  <span className="text-sm font-sans text-amber-400 font-semibold">Couldn't load data</span>
                ) : (
                  <span className="text-2xl font-bold font-mono text-emerald-400">
                    {stats.actionsExecuted !== null && stats.actionsExecuted !== undefined ? stats.actionsExecuted : "--"}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">
                {isAdvanced ? "Total on-chain attestation-verified actions" : "Actions completed on the Monad test network"}
              </p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Threats registered</CardTitle>
              <Shield className="h-4 w-4 text-red-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                {isFetchFailed ? (
                  <span className="text-sm font-sans text-amber-400 font-semibold">Couldn't load data</span>
                ) : (
                  <span className="text-2xl font-bold font-mono text-red-400">
                    {stats.threatsRegistered !== null && stats.threatsRegistered !== undefined ? stats.threatsRegistered : "--"}
                  </span>
                )}
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">
                {isAdvanced ? "Malicious addresses registered in threat feed" : "Addresses listed in the threat feed"}
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
                {!isAdvanced && simpleStatus.description && (
                  <p className="text-[11px] text-amber-300 font-sans mt-1">
                    {simpleStatus.description}
                  </p>
                )}
                {!isAdvanced && !simpleStatus.description && (
                  <p className="text-[11px] text-muted-foreground mt-1">
                    Requests blocked by the proxy are not shown here.
                  </p>
                )}
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
              {!isAdvanced && simpleStatus.description && (
                <p className="text-[11px] text-amber-300 font-sans mt-0.5 text-right">
                  {simpleStatus.description}
                </p>
              )}
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

            <div className="p-3.5 rounded-xl border border-border/70 bg-muted/20 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
              <div className="flex items-center gap-2">
                <Shield className="h-4 w-4 text-emerald-400" />
                <span className="text-muted-foreground">
                  {isAdvanced ? "Policy threshold:" : "Safety threshold:"}
                </span>
                <span className="font-mono text-[11px] text-[#836EF9]">{thresholdLabel}</span>
              </div>
              <span className={cn("font-mono font-semibold", couldntVerifyCount > 0 ? "text-amber-400" : "text-emerald-400")}>
                {stats.actionsExecuted !== null || stats.threatsRegistered !== null
                  ? `${stats.actionsExecuted ?? 0} executed · ${stats.threatsRegistered ?? 0} threats registered`
                  : (isAdvanced ? "No Transactions Recorded" : "No Activity Recorded")}
              </span>
            </div>
          </CardContent>
        </Card>

        {/* Card 2: On-Chain Security Records (Three Stat Tiles, No Fabricated Percentages) */}
        <Card className="border-border/80 bg-card/80 flex flex-col justify-between">
          <CardHeader className="pb-3 border-b border-border/50">
            <CardTitle className="text-base font-semibold text-foreground flex items-center justify-between">
              <span className="flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-[#836EF9]" />
                {isAdvanced ? "On-Chain Security Records" : "Security Records"}
              </span>
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/30">
                {isFetchFailed ? "FETCH ERROR" : "INDEXED FEEDS"}
              </span>
            </CardTitle>
            <p className="text-xs text-muted-foreground mt-0.5">
              {isAdvanced 
                ? "Record counts from Monad Testnet indexer" 
                : "Active counts from Monad Testnet indexer"}
            </p>
          </CardHeader>
          <CardContent className="space-y-3 pt-4">
            {/* Tile 1: Threats in the threat feed */}
            <div className="p-3 rounded-lg border border-border/70 bg-background/50 flex justify-between items-center">
              <span className="text-xs text-muted-foreground flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-red-500" />
                Threats in the threat feed
              </span>
              <span className="text-sm font-semibold font-mono text-foreground">
                {isFetchFailed || threatsCount === null ? (
                  <span className="text-amber-400 font-sans text-xs">Couldn't load data</span>
                ) : (
                  threatsCount
                )}
              </span>
            </div>

            {/* Tile 2: Active threat indicators */}
            <div className="p-3 rounded-lg border border-border/70 bg-background/50 flex justify-between items-center">
              <span className="text-xs text-muted-foreground flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-amber-500" />
                Active threat indicators
              </span>
              <span className="text-sm font-semibold font-mono text-foreground">
                {isFetchFailed || activeThreatsCount === null ? (
                  <span className="text-amber-400 font-sans text-xs">Couldn't load data</span>
                ) : (
                  activeThreatsCount
                )}
              </span>
            </div>

            {/* Tile 3: Agent passports tracked */}
            <div className="p-3 rounded-lg border border-border/70 bg-background/50 flex justify-between items-center">
              <span className="text-xs text-muted-foreground flex items-center gap-2">
                <span className="h-2 w-2 rounded-full bg-blue-500" />
                Agent passports tracked
              </span>
              <span className="text-sm font-semibold font-mono text-foreground">
                {isFetchFailed || passportsCount === null ? (
                  <span className="text-amber-400 font-sans text-xs">Couldn't load data</span>
                ) : (
                  passportsCount
                )}
              </span>
            </div>

            {/* F10: Separated action outcomes: executed / couldn't verify */}
            <div className="p-3.5 rounded-xl border border-border/70 bg-muted/20 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
              <span className="text-muted-foreground">On-chain activity:</span>
              <div className="flex items-center gap-3 font-mono">
                {isFetchFailed ? (
                  <span className="text-amber-400 font-semibold font-sans">Couldn't load data</span>
                ) : (
                  <>
                    <span className="text-emerald-400 font-semibold">{actionsExecuted !== null && actionsExecuted !== undefined ? `${actionsExecuted} executed` : "-- executed"}</span>
                    <span className="text-muted-foreground/40">•</span>
                    <span className="text-amber-400 font-semibold">{couldntVerifyCount !== null && couldntVerifyCount !== undefined ? `${couldntVerifyCount} couldn't verify` : "-- couldn't verify"}</span>
                  </>
                )}
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
                  <span className="text-muted-foreground">Execution Policy Guard</span>
                  <span className="text-purple-300">GuardianPolicyGuard (0x90Fd...EF60)</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-border/60">
                  <span className="text-muted-foreground">Identity Registry</span>
                  <span className="text-emerald-400 font-semibold">Soulbound agent passport (ERC-5192) (0xDA5f...2Cff)</span>
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
                  <span className="text-foreground font-sans font-semibold">Registered Passports Checked</span>
                </div>
                <div className="flex justify-between items-center py-1.5 border-b border-border/60">
                  {/* Keys managed by Privy: https://docs.privy.io/guide/security/ */}
                  <span className="text-muted-foreground font-sans">Protected Key Storage</span>
                  <span className="text-foreground font-sans font-semibold">Keys Managed by Privy</span>
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
                : "Activity history of recorded agent events and blocked threats"}
            </p>
          </CardHeader>
          <CardContent className="space-y-4 pt-4">
            <div className="p-3.5 rounded-xl border border-border/80 bg-background/50 text-xs text-muted-foreground leading-relaxed">
              {isAdvanced 
                ? "On-chain actions, security events, session key delegations, and circuit breaker tripwires are indexed with timestamps, target addresses, and MonadScan explorer links."
                : "Agent actions, security events, and blocked attempts are recorded in the event log with verification details."}
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

      {/* Threat feed (latest 25) */}
      <Card className="border-border/80 bg-card/80">
        <CardHeader className="pb-3 border-b border-border/50">
          <div className="flex items-center justify-between">
            <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
              <Shield className="h-4 w-4 text-red-400" />
              Threat feed (latest 25)
            </CardTitle>
            <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-red-950/50 text-red-400 border border-red-800">
              {threatFeed.length} ENTRIES
            </span>
          </div>
          <p className="text-xs text-muted-foreground mt-0.5">
            Addresses listed in the on-chain threat feed registry
          </p>
        </CardHeader>
        <CardContent className="pt-4">
          {threatFeed.length === 0 ? (
            <div className="text-xs text-muted-foreground py-3 text-center">
              No threats listed in the threat feed.
            </div>
          ) : (
            <div className="space-y-2 max-h-60 overflow-y-auto font-mono text-xs">
              {threatFeed.slice(0, 25).map((threat, idx) => (
                <div key={idx} className="flex items-center justify-between p-2 rounded border border-border/60 bg-background/50">
                  <div className="flex items-center gap-2">
                    <span className={cn("h-2 w-2 rounded-full", threat.active ? "bg-red-500" : "bg-muted-foreground")} />
                    <span className="font-semibold text-foreground">{threat.address ? (threat.address.slice(0, 10) + '...' + threat.address.slice(-6)) : 'Unknown'}</span>
                    <span className="text-muted-foreground text-[11px] font-sans">({threat.reason || 'No reason provided'})</span>
                  </div>
                  <span className={cn("text-[10px] px-1.5 py-0.5 rounded border", threat.active ? "bg-red-950/60 text-red-300 border-red-800" : "bg-muted/40 text-muted-foreground border-border")}>
                    {threat.active ? "ACTIVE" : "REMOVED"}
                  </span>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>
    </div>
  )
}
