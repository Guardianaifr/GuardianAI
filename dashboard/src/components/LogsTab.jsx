import React, { useState, useMemo } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { 
  Terminal, 
  Search, 
  Filter, 
  Download, 
  ExternalLink, 
  Check, 
  Copy, 
  RotateCcw, 
  Pause, 
  Play, 
  ShieldAlert, 
  CheckCircle2, 
  AlertTriangle 
} from "lucide-react"
import { cn } from "@/lib/utils"

const EVENT_TYPE_CATEGORIES = [
  { id: 'all', label: 'All Events' },
  { id: 'injections', label: 'Prompt Injections', match: ['injection', 'injection_ai'] },
  { id: 'outflow', label: 'Outflow Caps & Policy', match: ['policy containment', 'policy_containment', 'policy violation', 'policy_violation', 'policy deployed', 'policy_deployed', 'policy'] },
  { id: 'tamper', label: 'Tamper Protection', match: ['memory enclave', 'enclave', 'threat registered', 'threat_registered'] },
  { id: 'pii', label: 'PII & Data Leaks', match: ['data_leak', 'data leak', 'pii'] },
  { id: 'onchain', label: 'On-Chain Actions', match: ['on-chain action', 'action', 'execute'] },
  { id: 'ratelimit', label: 'Rate Limits', match: ['rate_limit', 'rate limit'] },
]

export function LogsTab({ events, isBlockedEvent, isAdvanced = false }) {
  const [searchTerm, setSearchTerm] = useState('')
  const [selectedCategory, setSelectedCategory] = useState('all')
  const [selectedSeverity, setSelectedSeverity] = useState('all')
  const [isPaused, setIsPaused] = useState(false)
  const [frozenEvents, setFrozenEvents] = useState([])
  const [copiedField, setCopiedField] = useState(null)

  const activeEventsList = isPaused ? frozenEvents : events

  const togglePause = () => {
    if (!isPaused) {
      setFrozenEvents([...events])
      setIsPaused(true)
    } else {
      setIsPaused(false)
    }
  }

  const handleCopy = (text, fieldId) => {
    navigator.clipboard?.writeText(text)
    setCopiedField(fieldId)
    setTimeout(() => setCopiedField(null), 2000)
  }

  // Filter events based on search, category, and severity
  const filteredEvents = useMemo(() => {
    return activeEventsList.filter((evt) => {
      // 1. Severity filter
      if (selectedSeverity !== 'all') {
        if ((evt.severity || '').toUpperCase() !== selectedSeverity) {
          return false
        }
      }

      // 2. Category filter
      if (selectedCategory !== 'all') {
        const catObj = EVENT_TYPE_CATEGORIES.find((c) => c.id === selectedCategory)
        if (catObj && catObj.match) {
          const typeLower = (evt.event_type || '').toLowerCase()
          const matched = catObj.match.some((pattern) => typeLower.includes(pattern))
          if (!matched) return false
        }
      }

      // 3. Search query filter
      if (searchTerm.trim()) {
        const query = searchTerm.toLowerCase()
        const textPayload = [
          evt.event_type,
          evt.severity,
          evt.details?.agent,
          evt.details?.target,
          evt.details?.reason,
          evt.details?.prompt_preview,
          evt.details?.tx,
          evt.details?.path
        ]
          .filter(Boolean)
          .join(' ')
          .toLowerCase()

        if (!textPayload.includes(query)) {
          return false
        }
      }

      return true
    })
  }, [activeEventsList, selectedSeverity, selectedCategory, searchTerm])

  const handleExportJSON = () => {
    const dataStr = "data:text/json;charset=utf-8," + encodeURIComponent(JSON.stringify(filteredEvents, null, 2))
    const downloadAnchor = document.createElement('a')
    downloadAnchor.setAttribute("href", dataStr)
    downloadAnchor.setAttribute("download", `guardianai_audit_logs_${Date.now()}.json`)
    document.body.appendChild(downloadAnchor)
    downloadAnchor.click()
    downloadAnchor.remove()
  }

  const handleResetFilters = () => {
    setSearchTerm('')
    setSelectedCategory('all')
    setSelectedSeverity('all')
  }

  return (
    <div className="space-y-6 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/80 pb-6">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-[#836EF9]/15 border border-[#836EF9]/30 text-xs font-mono text-[#836EF9] mb-2">
            <Terminal className="h-3.5 w-3.5" />
            <span>{isAdvanced ? "Monad Pre-Flight Security & Tamper Audit Log" : "Activity Stream"}</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground">
            {isAdvanced ? "Audit Trail & Event Explorer" : "Activity & Protection History"}
          </h1>
          <p className="text-xs sm:text-sm text-muted-foreground mt-1">
            {isAdvanced 
              ? "Filter, search, inspect, and export cryptographic pre-flight event telemetry."
              : "Review all agent actions, safety inspections, and blocked threats in plain English."}
          </p>
        </div>

        {/* Action Controls */}
        <div className="flex items-center gap-2.5">
          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              togglePause()
            }}
            className={cn(
              "flex items-center gap-1.5 px-3 py-2 rounded-xl text-xs font-mono border transition-colors",
              isPaused
                ? "bg-amber-950/40 border-amber-800 text-amber-300"
                : "bg-muted/40 border-border text-muted-foreground hover:text-foreground"
            )}
          >
            {isPaused ? <Play className="h-3.5 w-3.5" /> : <Pause className="h-3.5 w-3.5" />}
            <span>{isPaused ? "Resume Live" : "Pause Feed"}</span>
          </button>

          <button
            type="button"
            onClick={(e) => {
              e.stopPropagation()
              handleExportJSON()
            }}
            className="flex items-center gap-1.5 px-3.5 py-2 rounded-xl bg-[#836EF9] hover:brightness-110 text-white text-xs font-semibold shadow-sm transition active:scale-[0.98]"
          >
            <Download className="h-3.5 w-3.5" />
            <span>Export JSON</span>
          </button>
        </div>
      </div>

      {/* Filter and Search Bar Controls */}
      <Card className="border-border/80 bg-card/80">
        <CardContent className="p-4 space-y-3.5">
          <div className="flex flex-col md:flex-row gap-3">
            {/* Search Input */}
            <div className="relative flex-1">
              <Search className="absolute left-3 top-2.5 h-4 w-4 text-muted-foreground" />
              <input
                type="text"
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
                placeholder={isAdvanced ? "Search by agent address, target contract, tx hash, or anomaly reason..." : "Search activity log or protection reasons..."}
                className="w-full pl-9 pr-4 py-2 rounded-lg bg-background border border-border text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
              />
              {searchTerm && (
                <button
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation()
                    setSearchTerm('')
                  }}
                  className="absolute right-2.5 top-2 text-xs text-muted-foreground hover:text-foreground"
                >
                  &times;
                </button>
              )}
            </div>

            {/* Severity Filter Dropdown */}
            <div className="flex items-center gap-2">
              <span className="text-xs text-muted-foreground font-mono">Severity:</span>
              <select
                value={selectedSeverity}
                onChange={(e) => setSelectedSeverity(e.target.value)}
                className="px-3 py-2 rounded-lg bg-background border border-border text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
              >
                <option value="all">All Severities</option>
                <option value="CRITICAL">Critical</option>
                <option value="HIGH">High</option>
                <option value="MEDIUM">Medium</option>
                <option value="INFO">Info</option>
              </select>
            </div>

            {/* Reset Filters button */}
            {(searchTerm || selectedCategory !== 'all' || selectedSeverity !== 'all') && (
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  handleResetFilters()
                }}
                className="flex items-center gap-1 px-3 py-2 rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/40 text-xs transition"
              >
                <RotateCcw className="h-3 w-3" />
                <span>Reset</span>
              </button>
            )}
          </div>

          {/* Event Category Filter Pills */}
          <div className="flex flex-wrap gap-1.5 pt-1">
            {EVENT_TYPE_CATEGORIES.map((cat) => {
              const isSelected = selectedCategory === cat.id
              return (
                <button
                  key={cat.id}
                  type="button"
                  onClick={(e) => {
                    e.stopPropagation()
                    setSelectedCategory(cat.id)
                  }}
                  className={cn(
                    "px-3 py-1 rounded-lg text-xs font-mono transition-colors",
                    isSelected
                      ? "bg-[#836EF9] text-white font-semibold shadow-sm"
                      : "bg-muted/30 border border-border/60 text-muted-foreground hover:text-foreground hover:bg-muted/60"
                  )}
                >
                  {cat.label}
                </button>
              )
            })}
          </div>
        </CardContent>
      </Card>

      {/* Events Table */}
      <Card className="border-border/80 bg-card/80 overflow-hidden">
        <CardHeader className="py-3 px-4 border-b border-border/50 flex flex-row items-center justify-between">
          <div className="flex items-center gap-2">
            <span className="text-xs font-semibold text-foreground">
              Showing {filteredEvents.length} of {activeEventsList.length} Events
            </span>
            {isPaused && (
              <span className="text-[10px] font-mono px-2 py-0.5 rounded bg-amber-950 text-amber-300 border border-amber-800">
                STREAM PAUSED
              </span>
            )}
          </div>
          <span className="text-[11px] text-muted-foreground font-mono">
            Monad Testnet • 10143
          </span>
        </CardHeader>

        <div className="overflow-x-auto">
          <table className="w-full text-left text-xs font-mono">
            <thead className="bg-muted/30 border-b border-border text-muted-foreground uppercase text-[10px] tracking-wider">
              {isAdvanced ? (
                <tr>
                  <th className="py-3 px-4">Time</th>
                  <th className="py-3 px-3">Severity</th>
                  <th className="py-3 px-3">Type</th>
                  <th className="py-3 px-3">Agent / Target</th>
                  <th className="py-3 px-4">Telemetry Details / Calldata</th>
                  <th className="py-3 px-3">Latency</th>
                  <th className="py-3 px-3">Risk</th>
                  <th className="py-3 px-4 text-right">Explorer</th>
                </tr>
              ) : (
                <tr>
                  <th className="py-3 px-4 font-sans">Time</th>
                  <th className="py-3 px-3 font-sans">Status</th>
                  <th className="py-3 px-3 font-sans">Event Type</th>
                  <th className="py-3 px-4 font-sans">Activity Description</th>
                  <th className="py-3 px-4 text-right font-sans">Security Result</th>
                </tr>
              )}
            </thead>
            <tbody className="divide-y divide-border/60">
              {filteredEvents.length === 0 ? (
                <tr>
                  <td colSpan={isAdvanced ? 8 : 5} className="py-12 text-center text-muted-foreground">
                    <div className="flex flex-col items-center justify-center space-y-2">
                      <Filter className="h-6 w-6 text-muted-foreground/50" />
                      {events.length === 0 ? (
                        <>
                          <span className="font-semibold text-foreground">No telemetry events recorded yet</span>
                          <span className="text-xs text-muted-foreground">Awaiting live agent actions or security events.</span>
                        </>
                      ) : (
                        <>
                          <span>No matching events found for current filters.</span>
                          <button
                            type="button"
                            onClick={(e) => {
                              e.stopPropagation()
                              handleResetFilters()
                            }}
                            className="text-xs text-[#836EF9] underline hover:brightness-110"
                          >
                            Reset All Filters
                          </button>
                        </>
                      )}
                    </div>
                  </td>
                </tr>
              ) : !isAdvanced ? (
                filteredEvents.map((evt, idx) => {
                  const isBlocked = isBlockedEvent(evt)
                  const dateStr = new Date(evt.timestamp * 1000).toLocaleTimeString()
                  const statusDesc = evt.details?.reason || evt.details?.prompt_preview || "Nominal operation within authorized thresholds"
                  return (
                    <tr
                      key={idx}
                      className={cn(
                        "hover:bg-muted/30 transition-colors font-sans text-xs",
                        isBlocked ? "bg-red-950/10" : ""
                      )}
                    >
                      <td className="py-3 px-4 whitespace-nowrap text-muted-foreground font-mono text-[11px]">
                        {dateStr}
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap">
                        {isBlocked ? (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-red-950 text-red-400 border border-red-800 flex items-center gap-1 w-fit">
                            <ShieldAlert className="h-3 w-3" /> Blocked
                          </span>
                        ) : (
                          <span className="px-2 py-0.5 rounded text-[10px] font-bold uppercase bg-emerald-950 text-emerald-400 border border-emerald-800 flex items-center gap-1 w-fit">
                            <CheckCircle2 className="h-3 w-3" /> Allowed
                          </span>
                        )}
                      </td>
                      <td className="py-3 px-3 whitespace-nowrap font-medium text-foreground">
                        <div className="flex items-center gap-1.5">
                          <span>{evt.event_type}</span>
                          {evt.isSimulated && (
                            <span className="text-[9px] font-mono px-1.5 py-0.2 rounded bg-blue-950 text-blue-300 border border-blue-800 uppercase font-semibold">
                              Simulated
                            </span>
                          )}
                        </div>
                      </td>
                      <td className="py-3 px-4 text-xs text-muted-foreground leading-relaxed max-w-lg">
                        <div>{statusDesc}</div>
                        {evt.details?.tx && (
                          <div className="inline-flex items-center gap-1 mt-1 text-[11px] font-mono text-muted-foreground">
                            <span>Tx: {`${evt.details.tx.slice(0, 6)}...${evt.details.tx.slice(-4)}`}</span>
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation()
                                handleCopy(evt.details.tx, `simple_tx_${idx}`)
                              }}
                              className="text-muted-foreground hover:text-foreground p-0.5 rounded transition"
                              title="Copy Tx Hash"
                            >
                              {copiedField === `simple_tx_${idx}` ? <Check className="h-2.5 w-2.5 text-emerald-400" /> : <Copy className="h-2.5 w-2.5" />}
                            </button>
                          </div>
                        )}
                      </td>
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        <span className={cn(
                          "px-2 py-0.5 rounded text-[11px] font-semibold",
                          isBlocked ? "text-red-300 bg-red-950/40" : "text-emerald-300 bg-emerald-950/40"
                        )}>
                          {isBlocked ? "Threat Neutralized" : "Verified Safe"}
                        </span>
                      </td>
                    </tr>
                  )
                })
              ) : (
                filteredEvents.map((evt, idx) => {
                  const isBlocked = isBlockedEvent(evt)
                  const dateStr = new Date(evt.timestamp * 1000).toLocaleTimeString()
                  const agentAddr = evt.details?.agent
                  const targetAddr = evt.details?.target
                  const riskScore = evt.details?.riskScore
                  const txHash = evt.details?.tx

                  return (
                    <tr
                      key={idx}
                      className={cn(
                        "hover:bg-muted/30 transition-colors",
                        evt.severity === "CRITICAL" ? "bg-red-950/10" : ""
                      )}
                    >
                      {/* Timestamp */}
                      <td className="py-3 px-4 whitespace-nowrap text-muted-foreground text-[11px]">
                        {dateStr}
                      </td>

                      {/* Severity Badge */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <span
                          className={cn(
                            "px-2 py-0.5 rounded text-[10px] font-bold uppercase",
                            evt.severity === "CRITICAL"
                              ? "bg-red-950 text-red-400 border border-red-800"
                              : evt.severity === "HIGH"
                              ? "bg-orange-950 text-orange-400 border border-orange-800"
                              : evt.severity === "MEDIUM"
                              ? "bg-yellow-950 text-yellow-400 border border-yellow-800"
                              : "bg-slate-900 text-slate-300 border border-slate-700"
                          )}
                        >
                          {evt.severity}
                        </span>
                      </td>

                      {/* Event Type & Blocked pill */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        <div className="flex items-center gap-1.5">
                          <span className="font-semibold text-foreground text-[11px]">
                            {evt.event_type}
                          </span>
                          {evt.isSimulated && (
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-blue-950 text-blue-300 border border-blue-800 uppercase font-semibold">
                              Simulated
                            </span>
                          )}
                          {isBlocked && (
                            <span className="text-[9px] px-1.5 py-0.2 rounded bg-red-900/60 text-red-200 border border-red-700/50 uppercase font-bold">
                              Blocked
                            </span>
                          )}
                        </div>
                      </td>

                      {/* Agent / Target */}
                      <td className="py-3 px-3 whitespace-nowrap text-[11px]">
                        {agentAddr && (
                          <div className="flex items-center gap-1 text-purple-300">
                            <span>A: {agentAddr}</span>
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation()
                                handleCopy(agentAddr, `ag_${idx}`)
                              }}
                              className="text-muted-foreground hover:text-white"
                            >
                              {copiedField === `ag_${idx}` ? <Check className="h-2.5 w-2.5 text-emerald-400" /> : <Copy className="h-2.5 w-2.5" />}
                            </button>
                          </div>
                        )}
                        {targetAddr && (
                          <div className="flex items-center gap-1 text-slate-400">
                            <span>T: {targetAddr.length > 16 ? `${targetAddr.slice(0, 10)}...${targetAddr.slice(-4)}` : targetAddr}</span>
                            <button
                              type="button"
                              onClick={(e) => {
                                e.stopPropagation()
                                handleCopy(targetAddr, `tg_${idx}`)
                              }}
                              className="text-muted-foreground hover:text-white"
                            >
                              {copiedField === `tg_${idx}` ? <Check className="h-2.5 w-2.5 text-emerald-400" /> : <Copy className="h-2.5 w-2.5" />}
                            </button>
                          </div>
                        )}
                        {!agentAddr && !targetAddr && (
                          <span className="text-muted-foreground/40 font-mono">—</span>
                        )}
                      </td>

                      {/* Details / Calldata */}
                      <td className="py-3 px-4 max-w-md font-sans text-xs">
                        <div className="line-clamp-2 leading-relaxed text-foreground/90">
                          {evt.details?.reason || evt.details?.prompt_preview || JSON.stringify(evt.details)}
                        </div>
                        {evt.details?.path && (
                          <div className="text-[10px] text-muted-foreground font-mono mt-0.5">
                            Endpoint: {evt.details.path}
                          </div>
                        )}
                      </td>

                      {/* Latency */}
                      <td className="py-3 px-3 whitespace-nowrap text-muted-foreground text-[11px]">
                        {evt.details?.latency_ms || "—"}
                      </td>

                      {/* Risk Score */}
                      <td className="py-3 px-3 whitespace-nowrap">
                        {riskScore !== undefined ? (
                          <span
                            className={cn(
                              "px-1.5 py-0.5 rounded text-[10px] font-bold",
                              riskScore > 70
                                ? "text-red-400 bg-red-950/60 border border-red-800"
                                : riskScore > 30
                                ? "text-amber-400 bg-amber-950/60 border border-amber-800"
                                : "text-emerald-400 bg-emerald-950/60 border border-emerald-800"
                            )}
                          >
                            {riskScore}/100
                          </span>
                        ) : (
                          <span className="text-muted-foreground text-[10px]">—</span>
                        )}
                      </td>

                      {/* Monad Explorer Link */}
                      <td className="py-3 px-4 text-right whitespace-nowrap">
                        {evt.isSimulated ? (
                          <span className="px-1.5 py-0.5 text-[10px] font-semibold uppercase tracking-wider rounded bg-amber-500/20 text-amber-300 border border-amber-500/40">
                            Simulated
                          </span>
                        ) : txHash ? (
                          <a
                            href={`https://testnet.monadscan.com/tx/${txHash}`}
                            target="_blank"
                            rel="noreferrer"
                            className="inline-flex items-center gap-1 text-[#836EF9] hover:underline hover:brightness-125"
                          >
                            <span>MonadScan</span>
                            <ExternalLink className="h-3 w-3" />
                          </a>
                        ) : (
                          <span className="text-muted-foreground/40 text-[10px]">Off-Chain</span>
                        )}
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </Card>
    </div>
  )
}
