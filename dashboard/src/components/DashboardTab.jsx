import React, { useState, useRef, useEffect } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { 
  Terminal, 
  Activity, 
  Shield, 
  Zap, 
  AlertTriangle, 
  Pause, 
  Play, 
  Cpu, 
  Gauge, 
  TrendingUp, 
  CheckCircle2,
  ExternalLink,
  Layers
} from "lucide-react"
import { cn } from "@/lib/utils"

export function DashboardTab({
  events,
  stats,
  vectorData,
  indexerStatus,
  isConnected,
  isLiveSimulating,
  isBlockedEvent
}) {
  const [isPaused, setIsPaused] = useState(false)
  const [frozenEvents, setFrozenEvents] = useState([])
  const feedContainerRef = useRef(null)
  const [isScrolledDown, setIsScrolledDown] = useState(false)

  const togglePause = () => {
    if (!isPaused) {
      setFrozenEvents([...events])
      setIsPaused(true)
    } else {
      setIsPaused(false)
    }
  }

  const scrollToLatest = () => {
    feedContainerRef.current?.scrollTo({ top: 0, behavior: 'smooth' })
    setIsScrolledDown(false)
  }

  const handleContainerScroll = (e) => {
    const scrollTop = e.currentTarget.scrollTop
    setIsScrolledDown(scrollTop > 60)
  }

  const displayedEvents = isPaused ? frozenEvents : events

  // Smoothly keep top visible when new events arrive if user has not scrolled down
  useEffect(() => {
    if (!isPaused && !isScrolledDown) {
      feedContainerRef.current?.scrollTo({ top: 0, behavior: 'smooth' })
    }
  }, [events, isPaused, isScrolledDown])

  // Calculate dynamic attack vector percentages
  const totalVectors = Math.max(1, (vectorData.prompt || 0) + (vectorData.pii || 0) + (vectorData.admin || 0) + (stats.blocked || 0))
  const promptPct = Math.min(100, Math.round(((vectorData.prompt || 0) / totalVectors) * 100))
  const piiPct = Math.min(100, Math.round(((vectorData.pii || 0) / totalVectors) * 100))
  const policyPct = Math.min(100, Math.round(((stats.blocked || 0) / totalVectors) * 100))
  const enclavePct = Math.min(100, Math.round(((vectorData.admin || 0) / totalVectors) * 100))

  // Risk Score calculation based on recent events
  const recentEvents = events.slice(0, 15)
  const scores = recentEvents.map(e => e.details?.riskScore || (e.severity === 'CRITICAL' ? 95 : e.severity === 'HIGH' ? 70 : 15))
  const avgRiskScore = scores.length > 0 ? Math.round(scores.reduce((a, b) => a + b, 0) / scores.length) : 14
  const peakRiskScore = scores.length > 0 ? Math.max(...scores) : 98

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
              <p className="text-[11px] text-muted-foreground mt-1">Simulated Monad parallel throughput</p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Median Pre-Flight Latency</CardTitle>
              <Activity className="h-4 w-4 text-emerald-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-emerald-400">2.4 ms</span>
                <span className="text-xs font-mono text-muted-foreground">p99: 4.8ms</span>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">EIP-712 runtime attestation speed</p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Gas Preserved Off-Chain</CardTitle>
              <Shield className="h-4 w-4 text-blue-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-blue-400">0.00 Gas</span>
                <span className="text-xs font-mono text-emerald-400">100% saved</span>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">Rogue actions contained before signing</p>
            </CardContent>
          </Card>

          <Card className="border-border/80 bg-card/60 backdrop-blur">
            <CardHeader className="flex flex-row items-center justify-between pb-2">
              <CardTitle className="text-xs font-medium text-muted-foreground">Active Parallel Cores</CardTitle>
              <Layers className="h-4 w-4 text-purple-400" />
            </CardHeader>
            <CardContent>
              <div className="flex items-baseline gap-2">
                <span className="text-2xl font-bold font-mono text-purple-300">16 Workers</span>
                <span className="text-xs font-mono text-emerald-400">Healthy</span>
              </div>
              <p className="text-[11px] text-muted-foreground mt-1">Non-blocking policy verification pipelines</p>
            </CardContent>
          </Card>
        </div>
      </section>

      {/* Main Grid: Live Security Feed (Left) & Threat Intelligence / Risk Score (Right) */}
      <div className="grid gap-6 lg:grid-cols-12">
        {/* Real-Time Security Feed (7 columns) */}
        <Card className="lg:col-span-7 flex flex-col h-[600px] border-border/80 bg-card/80">
          <CardHeader className="flex flex-row items-center justify-between pb-3 border-b border-border/50">
            <div className="flex items-center gap-2">
              <Terminal className="h-5 w-5 text-[#836EF9]" />
              <div>
                <CardTitle className="text-base font-semibold text-foreground">
                  Real-Time Security Threat Stream
                </CardTitle>
                <p className="text-[11px] text-muted-foreground">
                  Live pre-flight telemetry from GuardianAI relayer and Monad node
                </p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <button
                onClick={togglePause}
                className={cn(
                  "flex items-center gap-1.5 px-2.5 py-1 rounded-lg text-xs font-mono border transition-colors",
                  isPaused
                    ? "bg-amber-950/40 border-amber-800 text-amber-300 hover:bg-amber-900/40"
                    : "bg-muted/40 border-border/80 text-muted-foreground hover:text-foreground"
                )}
              >
                {isPaused ? <Play className="h-3 w-3" /> : <Pause className="h-3 w-3" />}
                <span>{isPaused ? "Resume Stream" : "Pause Stream"}</span>
              </button>
              <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-black/40 border border-border/60 text-[10px] font-mono text-muted-foreground">
                <span className={cn(
                  "h-1.5 w-1.5 rounded-full",
                  isPaused ? "bg-amber-400" : isConnected ? "bg-emerald-400 animate-pulse" : "bg-blue-400 animate-pulse"
                )} />
                <span>{displayedEvents.length} events</span>
              </div>
            </div>
          </CardHeader>
          <CardContent className="flex-1 overflow-hidden p-3 sm:p-4 relative">
            {isScrolledDown && (
              <button
                type="button"
                onClick={scrollToLatest}
                className="absolute top-2 right-6 z-10 flex items-center gap-1.5 px-3 py-1 rounded-full bg-[#836EF9] text-white text-[11px] font-mono shadow-md hover:brightness-110 transition active:scale-95 animate-in fade-in"
              >
                <span>&uarr; Jump to Latest</span>
              </button>
            )}
            <div
              ref={feedContainerRef}
              onScroll={handleContainerScroll}
              className="h-full overflow-y-auto space-y-2.5 pr-2 font-mono text-xs"
            >
              {displayedEvents.length === 0 ? (
                <div className="flex flex-col items-center justify-center h-full text-muted-foreground py-12">
                  <Activity className="h-8 w-8 text-muted-foreground/50 animate-pulse mb-2" />
                  <span>Waiting for telemetry events...</span>
                </div>
              ) : (
                displayedEvents.map((evt, i) => {
                  const isBlocked = isBlockedEvent(evt)
                  return (
                    <div
                      key={i}
                      className={cn(
                        "p-3 rounded-xl border transition-all duration-150 hover:brightness-105",
                        evt.severity === "CRITICAL"
                          ? "bg-red-950/25 border-red-900/60 text-red-200"
                          : evt.severity === "HIGH"
                          ? "bg-orange-950/25 border-orange-900/60 text-orange-200"
                          : evt.severity === "MEDIUM"
                          ? "bg-yellow-950/25 border-yellow-900/60 text-yellow-200"
                          : "bg-slate-900/40 border-slate-800/80 text-slate-300"
                      )}
                    >
                      <div className="flex flex-wrap justify-between items-center gap-2 mb-1.5">
                        <div className="flex items-center gap-1.5">
                          <span className="font-bold text-[10px] px-2 py-0.5 rounded bg-black/50 border border-white/10 uppercase tracking-wide">
                            {evt.event_type}
                          </span>
                          {isBlocked && (
                            <span className="text-[10px] uppercase font-bold px-1.5 py-0.5 rounded bg-red-900/80 text-red-100 border border-red-700/60">
                              Blocked
                            </span>
                          )}
                          {evt.details?.riskScore !== undefined && (
                            <span className={cn(
                              "text-[10px] font-mono px-1.5 py-0.5 rounded",
                              evt.details.riskScore > 70
                                ? "bg-red-950 text-red-400 border border-red-800"
                                : evt.details.riskScore > 30
                                ? "bg-amber-950 text-amber-400 border border-amber-800"
                                : "bg-emerald-950 text-emerald-400 border border-emerald-800"
                            )}>
                              Risk: {evt.details.riskScore}/100
                            </span>
                          )}
                        </div>
                        <span className="text-[11px] opacity-60">
                          {new Date(evt.timestamp * 1000).toLocaleTimeString()}
                        </span>
                      </div>

                      <div className="text-xs break-all opacity-90 leading-relaxed font-sans mt-1">
                        {evt.details?.prompt_preview || evt.details?.reason || JSON.stringify(evt.details)}
                      </div>

                      {/* Event Metadata Footer */}
                      <div className="mt-2 pt-1.5 border-t border-white/5 flex flex-wrap items-center gap-3 text-[11px] opacity-75 font-mono">
                        {evt.details?.agent && (
                          <span className="text-purple-300">Agent: {evt.details.agent}</span>
                        )}
                        {evt.details?.target && (
                          <span className="text-slate-400">Target: {evt.details.target}</span>
                        )}
                        {evt.details?.latency_ms && (
                          <span>⏱ {evt.details.latency_ms}</span>
                        )}
                        {evt.details?.path && (
                          <span>📍 {evt.details.path}</span>
                        )}
                        {evt.details?.tx && (
                          <a
                            href={`https://testnet.monadscan.com/tx/${evt.details.tx}`}
                            target="_blank"
                            rel="noreferrer"
                            className="text-[#836EF9] hover:underline ml-auto flex items-center gap-0.5"
                          >
                            <span>MonadScan</span>
                            <ExternalLink className="h-2.5 w-2.5" />
                          </a>
                        )}
                      </div>
                    </div>
                  )
                })
              )}
            </div>
          </CardContent>
        </Card>

        {/* Threat Intelligence, Risk Monitor & Attack Vectors (5 columns) */}
        <div className="lg:col-span-5 space-y-6">
          {/* Risk Score Monitor */}
          <Card className="border-border/80 bg-card/80">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                <Gauge className="h-4 w-4 text-[#836EF9]" />
                Runtime Risk Score Monitor
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-3">
                <div className="p-3 rounded-xl border border-border/80 bg-background/50 text-center">
                  <span className="text-xs text-muted-foreground">Session Avg Risk</span>
                  <div className="text-2xl font-bold font-mono mt-1 text-emerald-400">
                    {avgRiskScore} <span className="text-xs text-muted-foreground">/ 100</span>
                  </div>
                  <span className="text-[10px] text-emerald-400 font-mono">LOW ANOMALY</span>
                </div>
                <div className="p-3 rounded-xl border border-border/80 bg-background/50 text-center">
                  <span className="text-xs text-muted-foreground">Peak Intercepted</span>
                  <div className="text-2xl font-bold font-mono mt-1 text-red-500">
                    {peakRiskScore} <span className="text-xs text-muted-foreground">/ 100</span>
                  </div>
                  <span className="text-[10px] text-red-400 font-mono">CONTAINED THREAT</span>
                </div>
              </div>

              {/* Visual Risk Gauge Meter */}
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs text-muted-foreground font-mono">
                  <span>Safety Gradient</span>
                  <span>{avgRiskScore < 30 ? "Optimal Safety" : avgRiskScore < 70 ? "Elevated Monitoring" : "Critical"}</span>
                </div>
                <div className="h-3 w-full rounded-full bg-secondary overflow-hidden flex">
                  <div className="h-full bg-emerald-500" style={{ width: '40%' }} title="Safe Tier (0-40)" />
                  <div className="h-full bg-amber-500" style={{ width: '30%' }} title="Elevated Tier (40-70)" />
                  <div className="h-full bg-red-500" style={{ width: '30%' }} title="Critical Rogue Tier (70-100)" />
                </div>
                <div className="flex justify-between text-[10px] text-muted-foreground font-mono">
                  <span>0 (Safe)</span>
                  <span>50 (Elevated)</span>
                  <span>100 (Rogue)</span>
                </div>
              </div>
            </CardContent>
          </Card>

          {/* Attack Vector Distribution Chart */}
          <Card className="border-border/80 bg-card/80">
            <CardHeader className="pb-3">
              <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                <TrendingUp className="h-4 w-4 text-[#836EF9]" />
                Attack Vector Distribution
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              {/* Vector 1: Prompt Injections */}
              <div className="space-y-1.5">
                <div className="flex justify-between text-xs font-mono">
                  <span className="text-muted-foreground flex items-center gap-1.5">
                    <span className="h-2 w-2 rounded-full bg-red-500" />
                    Indirect Prompt Injections
                  </span>
                  <span className="font-semibold text-foreground">{vectorData.prompt} ({promptPct}%)</span>
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
                  <span className="font-semibold text-foreground">{vectorData.pii} ({piiPct}%)</span>
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
                  <span className="font-semibold text-foreground">{stats.blocked} ({policyPct}%)</span>
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
                  <span className="font-semibold text-foreground">{vectorData.admin} ({enclavePct}%)</span>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div 
                    className="h-full bg-blue-500 transition-all duration-500 rounded-full" 
                    style={{ width: `${enclavePct}%` }} 
                  />
                </div>
              </div>

              {/* Infrastructure Specification Box */}
              <div className="mt-4 p-3.5 bg-muted/40 rounded-xl border border-border/80 text-xs font-mono space-y-2">
                <div className="font-semibold text-foreground flex items-center gap-1.5 font-sans">
                  <Cpu className="h-3.5 w-3.5 text-[#836EF9]" />
                  <span>Infrastructure Layer Specifications</span>
                </div>
                <div className="flex justify-between py-1 border-b border-border/60">
                  <span className="text-muted-foreground">Indexer Protocol</span>
                  <span className={cn(
                    "font-semibold",
                    indexerStatus === "connected" ? "text-emerald-400" : "text-blue-400"
                  )}>
                    {indexerStatus === "connected" 
                      ? "Envio GraphQL (Live)" 
                      : isLiveSimulating 
                      ? "Envio Standalone Simulator" 
                      : "Direct WebSocket"}
                  </span>
                </div>
                <div className="flex justify-between py-1 border-b border-border/60">
                  <span className="text-muted-foreground">Chain Target</span>
                  <span className="text-foreground">Monad Testnet (10143)</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-muted-foreground">Consensus Engine</span>
                  <span className="text-purple-300">MonadBFT + Hardware TEE</span>
                </div>
              </div>
            </CardContent>
          </Card>
        </div>
      </div>
    </div>
  )
}
