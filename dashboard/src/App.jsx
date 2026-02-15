import { useState, useEffect, useRef } from 'react'
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { Shield, Activity, Lock, AlertTriangle, Terminal } from "lucide-react"
import { cn } from "@/lib/utils"

function App() {
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

  useEffect(() => {
    // Connect directly to Backend (bypass proxy)
    const wsUrl = `ws://127.0.0.1:8001/ws/threats`

    let ws = null
    let retryTimeout = null

    const connect = () => {
      ws = new WebSocket(wsUrl)

      ws.onopen = () => {
        console.log("Connected to GuardianAI Backend")
        setIsConnected(true)
      }

      ws.onclose = () => {
        console.log("Disconnected from Backend")
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

  const lastEventTimeRef = useRef(0)

  // Fetch history on mount
  useEffect(() => {
    const fetchHistory = async () => {
      try {
        const res = await fetch('http://127.0.0.1:8001/api/v1/events?limit=50')
        const data = await res.json()
        if (Array.isArray(data)) {
          // Process chronologically (Oldest -> Newest) to build stats
          const sorted = [...data].reverse()
          setEvents(data) // Events state keeps newest first (default API sort)

          // Rebuild stats
          const newStats = { requests: 0, blocked: 0, redacted: 0, admin: 0 }
          const newVector = { prompt: 0, pii: 0, admin: 0 }

          sorted.forEach(evt => {
            newStats.requests++
            if (evt.severity === "HIGH" || evt.severity === "CRITICAL") newStats.blocked++
            if (evt.severity === "HIGH" || evt.severity === "CRITICAL") newStats.blocked++

            // PII / Data Loss Events
            if (["pii_redaction", "data_redaction", "redaction", "data_leak"].includes(evt.event_type)) {
              newStats.redacted++
            }

            if (evt.event_type === "admin_action") newStats.admin++

            // Vectors
            if (["prompt_injection", "injection", "injection_ai", "threat_feed_match"].includes(evt.event_type) ||
              evt.details?.reason?.includes("Prompt injection")) {
              newVector.prompt++
            }

            if (["pii_redaction", "data_redaction", "redaction", "data_leak"].includes(evt.event_type)) {
              newVector.pii++
            }

            if (evt.event_type === "admin_action") newVector.admin++
          })

          setStats(newStats)
          setVectorData(newVector)

          // Sync dedup ref
          if (data.length > 0) {
            lastEventTimeRef.current = data[0].timestamp
          }
        }
      } catch (e) {
        console.error("Failed to fetch history:", e)
      }
    }
    fetchHistory()
  }, [])

  // Auto-scroll log
  useEffect(() => {
    bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
  }, [events])

  const handleNewEvent = (data) => {
    // 1. Dedup: Prevent duplicate events (common in dev mode / network retry)
    if (data.timestamp === lastEventTimeRef.current) return
    lastEventTimeRef.current = data.timestamp

    // Update Stats
    setStats(prev => {
      const newStats = { ...prev, requests: prev.requests + 1 }
      if (data.severity === "HIGH" || data.severity === "CRITICAL") newStats.blocked++

      // PII / Data Loss Events
      if (["pii_redaction", "data_redaction", "redaction", "data_leak"].includes(data.event_type)) {
        newStats.redacted++
      }

      if (data.event_type === "admin_action") newStats.admin++
      return newStats
    })

    // Update Attack Vectors
    setVectorData(prev => {
      const nu = { ...prev }

      // Prompt Injection / Jailbreak
      if (["prompt_injection", "injection", "injection_ai", "threat_feed_match"].includes(data.event_type) ||
        data.details?.reason?.includes("Prompt injection")) {
        nu.prompt++
      }

      // PII Leaks
      if (["pii_redaction", "data_redaction", "redaction", "data_leak"].includes(data.event_type)) {
        nu.pii++
      }

      if (data.event_type === "admin_action") nu.admin++
      return nu
    })

    // Add to Log (Limit 50)
    setEvents(prev => [data, ...prev].slice(0, 50))
  }

  return (
    <div className="min-h-screen bg-background text-foreground p-8 font-sans">
      <header className="mb-8 flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-primary/10 rounded-lg">
            <Shield className="h-8 w-8 text-primary" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">GuardianAI</h1>
            <p className="text-muted-foreground">Security Operations Center</p>
          </div>
        </div>
        <div className="flex items-center gap-4">
          <div className="text-sm text-muted-foreground flex items-center gap-2">
            Backend Status:
            <span className={cn("font-medium", isConnected ? "text-green-500" : "text-red-500")}>
              {isConnected ? "Connected" : "Disconnected"}
            </span>
          </div>
        </div>
      </header>

      <main className="grid gap-4 md:grid-cols-2 lg:grid-cols-4">
        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Total Requests</CardTitle>
            <Activity className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold">{stats.requests}</div>
            <p className="text-xs text-muted-foreground">Live traffic session</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Attacks Blocked</CardTitle>
            <Shield className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-red-500">{stats.blocked}</div>
            <p className="text-xs text-muted-foreground">High/Critical Severity</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">PII Redacted</CardTitle>
            <Lock className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-amber-500">{stats.redacted}</div>
            <p className="text-xs text-muted-foreground">Data leaks prevented</p>
          </CardContent>
        </Card>

        <Card>
          <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
            <CardTitle className="text-sm font-medium">Admin Actions</CardTitle>
            <AlertTriangle className="h-4 w-4 text-muted-foreground" />
          </CardHeader>
          <CardContent>
            <div className="text-2xl font-bold text-blue-500">{stats.admin}</div>
            <p className="text-xs text-muted-foreground">Policy changes</p>
          </CardContent>
        </Card>
      </main>

      <div className="mt-8 grid gap-4 md:grid-cols-2 lg:grid-cols-7">
        <Card className="col-span-4 h-[500px] flex flex-col">
          <CardHeader>
            <CardTitle className="flex items-center gap-2">
              <Terminal className="h-5 w-5" />
              Live Event Feed
            </CardTitle>
          </CardHeader>
          <CardContent className="flex-1 overflow-hidden">
            <div className="h-full overflow-y-auto space-y-2 pr-2 font-mono text-sm">
              {events.length === 0 && (
                <div className="text-center text-muted-foreground py-10">
                  Waiting for events...
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
            <CardTitle>Attack Vectors</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-4">
              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Prompt Injection</span>
                  <span className="font-bold">{vectorData.prompt}</span>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div className="h-full bg-red-500 transition-all duration-500" style={{ width: `${Math.min(100, (vectorData.prompt / Math.max(1, stats.blocked + stats.redacted + stats.admin)) * 100)}%` }} />
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>PII Leaks</span>
                  <span className="font-bold">{vectorData.pii}</span>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div className="h-full bg-amber-500 transition-all duration-500" style={{ width: `${Math.min(100, (vectorData.pii / Math.max(1, stats.blocked + stats.redacted + stats.admin)) * 100)}%` }} />
                </div>
              </div>

              <div className="space-y-2">
                <div className="flex justify-between text-sm">
                  <span>Admin Activity</span>
                  <span className="font-bold">{vectorData.admin}</span>
                </div>
                <div className="h-2 bg-secondary rounded-full overflow-hidden">
                  <div className="h-full bg-blue-500 transition-all duration-500" style={{ width: `${Math.min(100, (vectorData.admin / Math.max(1, stats.blocked + stats.redacted + stats.admin)) * 100)}%` }} />
                </div>
              </div>

              <div className="mt-8 p-4 bg-muted/50 rounded-lg text-sm text-muted-foreground">
                <h4 className="font-semibold mb-2 text-foreground">System Health</h4>
                <div className="flex justify-between py-1 border-b border-border/50">
                  <span>Backend Latency</span>
                  <span>&lt; 1ms</span>
                </div>
                <div className="flex justify-between py-1 border-b border-border/50">
                  <span>Database Size</span>
                  <span>120 KB</span>
                </div>
                <div className="flex justify-between py-1">
                  <span>Active Rules</span>
                  <span>12</span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>
    </div>
  )
}

export default App
