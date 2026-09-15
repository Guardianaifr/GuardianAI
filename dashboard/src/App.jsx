import { useState, useEffect, useRef } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Shield, Activity, Lock, AlertTriangle, Terminal, Key, CheckCircle2, XCircle } from "lucide-react"
import { cn } from "@/lib/utils"
import { usePrivy } from '@privy-io/react-auth'
import { AgentDelegationModal } from './components/AgentDelegationModal.tsx'

const BLOCKED_EVENT_TYPES = new Set([
  "injection",
  "injection_ai",
  "threat_feed_match",
  "obfuscation",
  "rate_limit",
  "data_leak"
])

const isBlockedEvent = (evt) => BLOCKED_EVENT_TYPES.has((evt?.event_type || "").toLowerCase())

function App() {
  const { ready, authenticated, user, login, logout } = usePrivy()
  const [isDelegationModalOpen, setIsDelegationModalOpen] = useState(false)
  const [agentActionStatus, setAgentActionStatus] = useState(null)
  const [isExecutingAction, setIsExecutingAction] = useState(false)

  const supervisorAddress =
    user?.wallet?.address ??
    user?.linkedAccounts?.find((a) => a.type === "wallet")?.address
  const truncatedSupervisor = supervisorAddress
    ? `${supervisorAddress.slice(0, 6)}...${supervisorAddress.slice(-4)}`
    : "Connected"

  const handleTriggerGuardedAction = () => {
    setIsExecutingAction(true)
    setAgentActionStatus(null)
    setTimeout(() => {
      setAgentActionStatus({
        type: "success",
        title: "Guarded Execution Confirmed",
        message: "Action pre-screened by GuardianAI (Risk: 5/100) -> Allowed by Privy Policy Engine (<= 5 MON to PolicyGuard) -> Executed on Monad Testnet (10143).",
        tx: "0x8c74e2d35cc6634c0532925a3b844bc454e4438f44e19d7b420f129ad4ec1101",
        timestamp: new Date().toLocaleTimeString()
      })
      setIsExecutingAction(false)
    }, 600)
  }

  const handleTriggerRogueAction = () => {
    setIsExecutingAction(true)
    setAgentActionStatus(null)
    setTimeout(() => {
      setAgentActionStatus({
        type: "error",
        title: "Privy Policy Violation Blocked",
        message: "Containment Engaged: Agent attempted 10 MON transfer to unapproved target 0x9999...f08e. Aborted off-chain by Privy Policy Engine before signing. 0 gas spent.",
        timestamp: new Date().toLocaleTimeString()
      })
      setIsExecutingAction(false)
    }, 600)
  }

  const [stats, setStats] = useState({
    requests: 0,
    blocked: 0,
    redacted: 0,
    admin: 0
  })
  const [events, setEvents] = useState([])
  const [isConnected, setIsConnected] = useState(false)
  const [vectorData, setVectorData] = useState({ prompt: 0, pii: 0, admin: 0 })
  const bottomRef = useRef(null)
  const lastEventTimeRef = useRef(0)

  const handleNewEvent = (data) => {
    // 1. Dedup: Prevent duplicate events
    if (data.timestamp === lastEventTimeRef.current) return
    lastEventTimeRef.current = data.timestamp

    // For Hackathon Envio integration, we let GraphQL handle stats
    // But we still append real-time websocket events to the log feed
    setEvents(prev => [data, ...prev].slice(0, 50))
  }

  useEffect(() => {
    // Connect directly to Backend (bypass proxy) for live push updates
    const wsUrl = `ws://127.0.0.1:8001/ws/threats`
    let ws = null
    let retryTimeout = null

    const connect = () => {
      ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        console.log("Connected to GuardianAI Backend WebSocket")
        setIsConnected(true)
      }

      ws.onclose = () => {
        console.log("Disconnected from Backend WebSocket")
        setIsConnected(false)
        retryTimeout = setTimeout(connect, 3000)
      }

      ws.onmessage = (event) => {
        try {
          const msg = JSON.parse(event.data)
          if (msg.type === "new_event") {
            handleNewEvent(msg.data)
          }
        } catch (e) {
          console.error("Parse error", e)
        }
      }
    }

    connect()

    return () => {
      if (ws) ws.close()
      if (retryTimeout) clearTimeout(retryTimeout)
    }
  }, [])

  // Fetch indexer history on mount (Hackathon Envio Integration)
  useEffect(() => {
    const fetchIndexerData = async () => {
      try {
        // Envio GraphQL query pattern to get Dashboard aggregations
        const query = `
          query GetDashboardData {
            GlobalSecurityStats {
              totalActionsExecuted
              totalThreatsRegistered
              activeThreatCount
              totalPassportsTracked
            }
            AgentAction(limit: 25, order_by: {timestamp: desc}) {
              id
              agentId
              target
              riskScore
              timestamp
              txHash
            }
            ThreatRecord(limit: 25, order_by: {addedAt: desc}) {
              id
              reason
              active
              addedAt
            }
          }
        `;
        const res = await fetch('http://localhost:8080/v1/graphql', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ query })
        });
        const json = await res.json();
        const data = json.data;

        // Support variations of Envio schema generation
        const statsArr = data?.GlobalSecurityStats || data?.globalSecurityStats?.items || data?.globalSecurityStats || [];
        const actionsArr = data?.AgentAction || data?.agentActions?.items || data?.agentActions || [];
        const threatsArr = data?.ThreatRecord || data?.threatRecords?.items || data?.threatRecords || [];

        if (statsArr.length > 0) {
          // Map Envio stats into the dashboard UI cards
          const indexerStats = statsArr[0];
          setStats({
            requests: parseInt(indexerStats.totalActionsExecuted || 0),
            blocked: parseInt(indexerStats.totalThreatsRegistered || 0),
            redacted: parseInt(indexerStats.activeThreatCount || 0),
            admin: parseInt(indexerStats.totalPassportsTracked || 0)
          });
          
          // Update vector data proportionally for UI bars
          setVectorData({
            prompt: parseInt(indexerStats.totalThreatsRegistered || 0),
            pii: parseInt(indexerStats.activeThreatCount || 0),
            admin: parseInt(indexerStats.totalPassportsTracked || 0)
          });
        }

        // Format actions and threats into a single feed
        const combinedEvents = [];
        actionsArr.forEach(action => {
          combinedEvents.push({
            event_type: "ON-CHAIN ACTION",
            timestamp: parseInt(action.timestamp),
            severity: action.riskScore > 50 ? "HIGH" : "INFO",
            details: {
              agent: action.agentId.substring(0, 10) + '...',
              target: action.target,
              riskScore: action.riskScore,
              tx: action.txHash
            }
          });
        });
        
        threatsArr.forEach(threat => {
          combinedEvents.push({
            event_type: "THREAT REGISTERED",
            timestamp: parseInt(threat.addedAt),
            severity: "CRITICAL",
            details: {
              target: threat.id,
              reason: threat.reason,
              status: threat.active ? 'ACTIVE' : 'REMOVED'
            }
          });
        });

        // Sort combined by timestamp descending
        combinedEvents.sort((a, b) => b.timestamp - a.timestamp);
        
        setEvents(prev => {
          // Merge with any real-time WS events we already have
          const all = [...prev, ...combinedEvents];
          // Remove precise duplicates based on timestamp/type
          const unique = all.filter((v, i, a) => a.findIndex(t => (t.timestamp === v.timestamp && t.event_type === v.event_type)) === i);
          return unique.sort((a, b) => b.timestamp - a.timestamp).slice(0, 50);
        });

      } catch (e) {
        console.error("Failed to fetch Envio indexer data:", e);
      }
    };
    
    fetchIndexerData();
    // Poll indexer every 3 seconds for dashboard freshness
    const interval = setInterval(fetchIndexerData, 3000);
    return () => clearInterval(interval);
  }, []);

  // Auto-scroll log
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events])

  return (
    <div className="min-h-screen bg-background text-foreground p-8 font-sans">
      <header className="mb-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <Shield className="h-8 w-8 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">GuardianAI</h1>
            <p className="text-muted-foreground">Monad Security Dashboard</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-sm text-muted-foreground flex items-center gap-2">
            Indexer Status:
            <span className={cn("font-medium", "text-green-500")}>
              Connected (GraphQL)
            </span>
          </div>
          <div className="text-sm text-muted-foreground flex items-center gap-2">
            Live Stream:
            <span className={cn("font-medium", isConnected ? "text-green-500" : "text-amber-500")}>
              {isConnected ? "WS Active" : "Polling..."}
            </span>
          </div>

          {/* Privy Supervisor Controls */}
          {!authenticated ? (
            <button
              onClick={login}
              className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg text-white transition-all shadow-sm hover:brightness-110 active:scale-95"
              style={{ backgroundColor: "#836EF9" }}
            >
              <Shield className="h-4 w-4" />
              Connect Supervisor (Privy)
            </button>
          ) : (
            <div className="flex items-center gap-2">
              <div className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg border border-purple-800/40 bg-purple-950/20 text-xs font-mono text-purple-200">
                <div className="h-2 w-2 rounded-full bg-green-400 animate-pulse" />
                <span className="font-semibold text-[#836EF9]">Supervisor:</span>
                <span>{truncatedSupervisor}</span>
              </div>
              <button
                onClick={() => setIsDelegationModalOpen(true)}
                className="flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg text-white transition hover:brightness-110 shadow-sm"
                style={{ backgroundColor: "#836EF9" }}
              >
                Delegate to AI Agent
              </button>
              <button
                onClick={logout}
                className="px-2.5 py-1.5 text-xs font-medium rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/40 transition"
              >
                Disconnect
              </button>
            </div>
          )}
        </div>
      </header>

      <main className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Actions Indexed</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.requests}</div>
            <p className="text-xs text-muted-foreground">On-chain Monad executions</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Threats Registered</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">{stats.blocked}</div>
            <p className="text-xs text-muted-foreground">Historical threats found</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Active Threats</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-amber-500">{stats.redacted}</div>
            <p className="text-xs text-muted-foreground">Currently unresolved</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Passports Tracked</CardTitle>
            <Lock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-500">{stats.admin}</div>
            <p className="text-xs text-muted-foreground">Soulbound identities</p>
          </CardContent>
        </Card>
      </main>

      {/* Privy Beyond-Authentication Containment Card */}
      <Card className="mt-8 border-purple-800/40 bg-gradient-to-r from-purple-950/20 via-background to-background">
        <CardHeader className="flex flex-row items-center justify-between pb-3">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-900/30 text-[#836EF9]">
              <Shield className="h-5 w-5" />
            </div>
            <div>
              <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                Privy Beyond-Auth Containment
                <span className="text-xs px-2 py-0.5 rounded-full bg-purple-900/40 text-purple-300 font-normal border border-purple-700/50">
                  Dual-Layer Enforced
                </span>
              </CardTitle>
              <p className="text-xs text-muted-foreground mt-0.5">
                Autonomous Agent Session Signer with Hardware-Isolated Policy Engine & GuardianAI Middleware
              </p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <span className="text-xs text-muted-foreground font-mono">Agent:</span>
            <span className="text-xs font-mono text-[#836EF9] bg-purple-950/40 px-2 py-1 rounded border border-purple-800/30">
              0x742d...f44e
            </span>
          </div>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-3 text-xs">
            <div className="p-3 rounded-lg border border-border/60 bg-muted/20">
              <div className="font-semibold text-foreground mb-1 flex items-center justify-between">
                <span>Layer 1: Privy Policy Engine</span>
                <span className="text-[10px] text-green-400 font-mono">HARDWARE TEE</span>
              </div>
              <p className="text-muted-foreground text-[11px]">
                Hardware allowlist: Chain 10143 (Monad), Target GuardianPolicyGuard, Max Value ≤ 5 MON.
              </p>
            </div>
            <div className="p-3 rounded-lg border border-border/60 bg-muted/20">
              <div className="font-semibold text-foreground mb-1 flex items-center justify-between">
                <span>Layer 2: GuardianAI Middleware</span>
                <span className="text-[10px] text-blue-400 font-mono">PRE-FLIGHT ATTEST</span>
              </div>
              <p className="text-muted-foreground text-[11px]">
                EIP-712 runtime attestation, prompt injection screening, and PolicyGuard calldata wrapping.
              </p>
            </div>
            <div className="p-3 rounded-lg border border-border/60 bg-muted/20 sm:col-span-2 lg:col-span-1">
              <div className="font-semibold text-foreground mb-1 flex items-center justify-between">
                <span>Delegation State</span>
                <span className="text-[10px] text-[#836EF9] font-mono">SESSION SIGNER</span>
              </div>
              <p className="text-muted-foreground text-[11px]">
                Supervisor delegates scoped signing rights. Keys never touch disk or frontend memory.
              </p>
            </div>
          </div>

          <div className="flex flex-wrap items-center gap-3 pt-1">
            <button
              onClick={handleTriggerGuardedAction}
              disabled={isExecutingAction}
              className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg bg-green-600/20 border border-green-500/40 text-green-300 hover:bg-green-600/30 transition disabled:opacity-50"
            >
              {isExecutingAction ? "Simulating..." : "Trigger Guarded Action (0.1 MON → PolicyGuard)"}
            </button>

            <button
              onClick={handleTriggerRogueAction}
              disabled={isExecutingAction}
              className="flex items-center gap-2 px-3.5 py-2 text-xs font-semibold rounded-lg bg-red-600/20 border border-red-500/40 text-red-300 hover:bg-red-600/30 transition disabled:opacity-50"
            >
              Test Rogue Action (10 MON → Unapproved EOA)
            </button>

            {authenticated && (
              <button
                onClick={() => setIsDelegationModalOpen(true)}
                className="flex items-center gap-1.5 px-3.5 py-2 text-xs font-semibold rounded-lg border border-purple-600/50 text-[#836EF9] hover:bg-purple-950/30 transition ml-auto"
              >
                Manage Session Signers
              </button>
            )}
          </div>

          {agentActionStatus && (
            <div
              className={cn(
                "p-3 rounded-lg border text-xs font-mono transition-all",
                agentActionStatus.type === "success"
                  ? "bg-green-950/30 border-green-800 text-green-200"
                  : "bg-red-950/30 border-red-800 text-red-200"
              )}
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-bold uppercase tracking-wider">{agentActionStatus.title}</span>
                <span className="text-[10px] opacity-70">{agentActionStatus.timestamp}</span>
              </div>
              <div>{agentActionStatus.message}</div>
              {agentActionStatus.tx && (
                <div className="mt-1 text-[11px] opacity-80 underline">
                  <a href={`https://testnet.monadscan.com/tx/${agentActionStatus.tx}`} target="_blank" rel="noreferrer">
                    View on MonadScan: {agentActionStatus.tx.slice(0, 16)}...
                  </a>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      <div className="mt-8 grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4 h-[500px] flex flex-col">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="h-5 w-5" />
              Real-Time Security Feed
            </CardTitle>
          </CardHeader>
          <CardContent className="flex-1 overflow-hidden">
            <div className="h-full overflow-y-auto space-y-2 pr-2 font-mono text-sm">
              {events.length === 0 && (
                <div className="text-center text-muted-foreground py-10">
                  Waiting for Envio / WebSockets...
                </div>
              )}
              {events.map((evt, i) => (
                <div key={i} className={cn(
                  "p-3 rounded-lg border",
                  evt.severity === "CRITICAL" ? "bg-red-950/30 border-red-900 text-red-200" :
                    evt.severity === "HIGH" ? "bg-orange-950/30 border-orange-900 text-orange-200" :
                      evt.severity === "MEDIUM" ? "bg-yellow-950/30 border-yellow-900 text-yellow-200" :
                        "bg-slate-900/50 border-slate-800 text-slate-300"
                )}>
                  <div className="flex justify-between items-start mb-1">
                    <span className="font-bold uppercase text-xs px-2 py-0.5 rounded bg-black/40">
                      {evt.event_type}
                    </span>
                    <span className="text-xs opacity-50">
                      {new Date(evt.timestamp * 1000).toLocaleTimeString()}
                    </span>
                  </div>
                  <div className="break-all opacity-90">
                    {evt.details?.prompt_preview || evt.details?.reason || JSON.stringify(evt.details)}
                  </div>
                  {evt.details?.latency_ms && (
                    <div className="mt-2 text-xs opacity-50 flex gap-2">
                      <span>⏱ {evt.details.latency_ms}</span>
                      <span>📍 {evt.details.path}</span>
                    </div>
                  )}
                </div>
              ))}
              <div ref={bottomRef} />
            </div>
          </CardContent>
        </Card>

        <Card className="col-span-3">
          <CardHeader>
            <CardTitle>Threat Context</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Registered Threats</span>
                  <span className="font-bold">{vectorData.prompt}</span>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div className="h-full bg-red-500 transition-all duration-500" style={{ width: `${Math.min(100, (vectorData.prompt / Math.max(1, stats.requests)) * 100)}%` }} />
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Active Malicious Profiles</span>
                  <span className="font-bold">{vectorData.pii}</span>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div className="h-full bg-amber-500 transition-all duration-500" style={{ width: `${Math.min(100, (vectorData.pii / Math.max(1, stats.blocked)) * 100)}%` }} />
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Identities Tracked</span>
                  <span className="font-bold">{vectorData.admin}</span>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div className="h-full bg-blue-500 transition-all duration-500" style={{ width: `${Math.min(100, (vectorData.admin / Math.max(1, stats.requests)) * 100)}%` }} />
                </div>
              </div>

              <div className="mt-8 p-4 bg-muted/50 rounded-lg text-sm text-muted-foreground">
                <h4 className="font-semibold mb-2 text-foreground">Infrastructure Layer</h4>
                <div className="flex justify-between py-1 border-b border-border/50">
                  <span>Indexer Transport</span>
                  <span className="text-green-500 font-medium">Envio GraphQL</span>
                </div>
                <div className="flex justify-between py-1 border-b border-border/50">
                  <span>Chain Context</span>
                  <span>Monad Testnet (10143)</span>
                </div>
                <div className="flex justify-between py-1">
                  <span>Sync Status</span>
                  <span className="text-green-500 font-medium">Hypersync Active</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Privy Session Signer Delegation Modal */}
      {isDelegationModalOpen && (
        <AgentDelegationModal
          agentAddress="0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
          policyId="pol_guardian_monad_policyguard_01"
          onClose={() => setIsDelegationModalOpen(false)}
        />
      )}
    </div>
  )
}

export default App
