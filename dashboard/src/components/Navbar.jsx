import React from 'react'
import { 
  Shield, 
  Home, 
  Activity, 
  Sliders, 
  Cpu, 
  Terminal, 
  UserCheck, 
  LogOut,
  Radio,
  ArrowLeft
} from 'lucide-react'
import { cn } from '@/lib/utils'

const NAV_TABS = [
  { id: 'home', label: 'Home', shortLabel: 'Home', icon: Home },
  { id: 'dashboard', label: 'Dashboard', shortLabel: 'Dash', icon: Activity },
  { id: 'policy', label: 'Guardrails', shortLabel: 'Guardrails', icon: Sliders },
  { id: 'agents', label: 'Agents', shortLabel: 'Agents', icon: Cpu },
  { id: 'logs', label: 'Logs', shortLabel: 'Logs', icon: Terminal },
]

export function Navbar({
  activeTab,
  setActiveTab,
  indexerStatus,
  isConnected,
  isLiveSimulating,
  isConnectedSupervisor,
  supervisorAddress,
  truncatedSupervisor,
  ready,
  privyTimedOut,
  onConnectSupervisor,
  onDisconnectSupervisor,
  onOpenDelegationModal,
}) {
  return (
    <header className="sticky top-0 z-40 w-full border-b border-border/80 bg-background/90 backdrop-blur-md transition-all">
      <div className="flex h-16 items-center justify-between px-3 sm:px-6 lg:px-8 gap-2">
        {/* Brand / Logo & Back to Main Website */}
        <div className="flex items-center gap-2 sm:gap-3 shrink-0">
          <a
            href="/"
            title="Return to aiguardian.dev main website"
            className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg text-xs font-semibold text-muted-foreground hover:text-foreground bg-muted/40 hover:bg-muted/80 border border-border/80 hover:border-[#836EF9]/50 transition-all select-none group shrink-0"
          >
            <ArrowLeft className="h-3.5 w-3.5 text-[#836EF9] group-hover:-translate-x-0.5 transition-transform" />
            <span className="hidden sm:inline">Back to Website</span>
            <span className="sm:hidden">Main Site</span>
          </a>

          <div 
            role="button"
            tabIndex={0}
            onClick={(e) => {
              e.stopPropagation()
              setActiveTab('home')
            }}
            onKeyDown={(e) => {
              if (e.key === 'Enter' || e.key === ' ') {
                e.preventDefault()
                setActiveTab('home')
              }
            }}
            title="GuardianAI Dashboard Home"
            className="flex items-center gap-2 sm:gap-3 cursor-pointer group select-none focus:outline-none"
          >
            <div className="relative p-1.5 sm:p-2 rounded-xl bg-[#836EF9]/15 border border-[#836EF9]/30 text-[#836EF9] shadow-sm group-hover:scale-105 transition-transform">
              <Shield className="h-5 w-5 sm:h-6 sm:w-6 text-[#836EF9]" />
              <span className="absolute -top-1 -right-1 flex h-2.5 w-2.5">
                <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-emerald-400 opacity-75"></span>
                <span className="relative inline-flex rounded-full h-2.5 w-2.5 bg-emerald-500"></span>
              </span>
            </div>
            <div>
              <div className="flex items-center gap-1.5 sm:gap-2">
                <span className="text-lg sm:text-xl font-bold tracking-tight text-foreground font-mono">
                  Guardian<span className="text-[#836EF9]">AI</span>
                </span>
                <span 
                  className="hidden sm:inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-mono font-semibold bg-[#836EF9]/10 text-[#836EF9] border border-[#836EF9]/25 cursor-help"
                  title="Trust & Execution Primitives for Autonomous Agents (ERC-8004 + P256)"
                >
                  PROTOCOL EXPLORER • MONAD 10143
                </span>
              </div>
              <p 
                className="text-[11px] text-muted-foreground hidden lg:block"
                title="Trust & Execution Primitives for Autonomous Agents (ERC-8004 + P256)"
              >
                Trust & Execution Primitives for Autonomous Agents (ERC-8004 + P256)
              </p>
            </div>
          </div>
        </div>

        {/* Navigation Tabs */}
        <nav className="flex items-center gap-1 sm:gap-1.5 p-1 rounded-xl bg-muted/40 border border-border/60 overflow-x-auto max-w-[55vw] sm:max-w-none">
          {NAV_TABS.map((tab) => {
            const Icon = tab.icon
            const isActive = activeTab === tab.id
            return (
              <button
                key={tab.id}
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  setActiveTab(tab.id)
                }}
                title={tab.label}
                className={cn(
                  "flex items-center gap-1.5 sm:gap-2 px-2 sm:px-3 py-1.5 rounded-lg text-xs font-medium transition-all duration-150 select-none whitespace-nowrap",
                  isActive
                    ? "bg-[#836EF9] text-white shadow-sm shadow-[#836EF9]/30 font-semibold"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/60"
                )}
              >
                <Icon className={cn("h-4 w-4 shrink-0", isActive ? "text-white" : "text-muted-foreground")} />
                <span className="hidden md:inline">{tab.label}</span>
                <span className="hidden sm:inline md:hidden">{tab.shortLabel}</span>
              </button>
            )
          })}
        </nav>

        {/* Right Action / Status Controls */}
        <div className="flex items-center gap-2 sm:gap-3">
          {/* Telemetry Status Indicator */}
          <div className="hidden xl:flex items-center gap-2 px-2.5 py-1 rounded-lg border border-border/60 bg-muted/20 text-[11px] text-muted-foreground">
            <Radio className={cn(
              "h-3 w-3 animate-pulse",
              isConnected ? "text-emerald-400" : isLiveSimulating ? "text-blue-400" : "text-amber-400"
            )} />
            <span className="font-mono">
              {indexerStatus === "connected"
                ? "Envio Live"
                : isConnected
                ? "WS Active"
                : "Live Simulation"}
            </span>
          </div>

          {/* Supervisor Wallet Auth Controller */}
          {!isConnectedSupervisor ? (
            <button
              type="button"
              onClick={(e) => {
                e.stopPropagation()
                onConnectSupervisor?.()
              }}
              disabled={!ready && !privyTimedOut}
              className="flex items-center gap-2 px-3.5 py-1.5 text-xs font-semibold rounded-lg text-white transition-all shadow-sm hover:brightness-110 active:scale-95 disabled:opacity-50"
              style={{ backgroundColor: "#836EF9" }}
            >
              <UserCheck className="h-4 w-4" />
              <span className="hidden sm:inline">
                {ready
                  ? "Connect Supervisor"
                  : privyTimedOut
                  ? "Connect Demo Supervisor"
                  : "Initializing..."}
              </span>
              <span className="sm:hidden">Connect</span>
            </button>
          ) : (
            <div className="flex items-center gap-1.5 sm:gap-2">
              <div 
                title={supervisorAddress || ""}
                className="flex items-center gap-1.5 px-2.5 py-1.5 rounded-lg border border-[#836EF9]/40 bg-[#836EF9]/10 text-xs font-mono text-[#836EF9]"
              >
                <div className="h-2 w-2 rounded-full bg-emerald-400 animate-pulse" />
                <span className="font-semibold hidden sm:inline">Supervisor:</span>
                <span>{truncatedSupervisor}</span>
              </div>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  onOpenDelegationModal?.()
                }}
                className="hidden md:flex items-center gap-1 px-3 py-1.5 text-xs font-medium rounded-lg text-white transition hover:brightness-110 shadow-sm"
                style={{ backgroundColor: "#836EF9" }}
              >
                Delegate
              </button>
              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  onDisconnectSupervisor?.()
                }}
                title="Disconnect Supervisor"
                className="p-1.5 text-xs font-medium rounded-lg border border-border text-muted-foreground hover:text-foreground hover:bg-muted/40 transition"
              >
                <LogOut className="h-3.5 w-3.5" />
              </button>
            </div>
          )}
        </div>
      </div>
    </header>
  )
}
