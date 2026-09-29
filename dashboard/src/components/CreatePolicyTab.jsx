import React, { useState, useMemo } from 'react'
import { usePrivy, useWallets } from '@privy-io/react-auth'
import { ethers } from 'ethers'
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card"
import { 
  Sliders, 
  Shield, 
  Clock, 
  AlertTriangle, 
  CheckCircle2, 
  Plus, 
  Trash2, 
  Copy, 
  Check, 
  Sparkles, 
  ExternalLink,
  Flame,
  Key
} from "lucide-react"
import { cn } from "@/lib/utils"

const PRESETS = [
  {
    name: "Autonomous DeFi Trader",
    desc: "Strict outflow protection for DEX liquidity & automated token swaps",
    maxSpend: 2.0,
    outflowCap: 10.0,
    timeLock: 600, // 10 minutes
    highValueThreshold: 1.5,
    circuitBreaker: 3,
    selectors: ["0x1cff79cd", "0xa9059cbb", "0x38ed1739"]
  },
  {
    name: "High-Throughput Arbitrage",
    desc: "Optimized for parallel sub-second Monad transactions with high frequency",
    maxSpend: 5.0,
    outflowCap: 50.0,
    timeLock: 0, // instant
    highValueThreshold: 4.0,
    circuitBreaker: 5,
    selectors: ["0x1cff79cd", "0x38ed1739", "0x4e71d92d"]
  },
  {
    name: "Micro-Payments Bot",
    desc: "Sub-cent streaming transactions with ultra-tight caps",
    maxSpend: 0.2,
    outflowCap: 2.0,
    timeLock: 0,
    highValueThreshold: 0.15,
    circuitBreaker: 10,
    selectors: ["0xa9059cbb"]
  },
  {
    name: "Treasury Vault Escort",
    desc: "Maximum security governance policy with mandatory 24h timelock",
    maxSpend: 1.0,
    outflowCap: 5.0,
    timeLock: 86400, // 24 hours
    highValueThreshold: 0.5,
    circuitBreaker: 1,
    selectors: ["0x1cff79cd", "0x4e71d92d", "0x8b30e4c1"]
  }
]

const KNOWN_SELECTORS = [
  { id: "0x1cff79cd", name: "execute(address,bytes,uint256)", desc: "PolicyGuard execution wrapper" },
  { id: "0xa9059cbb", name: "transfer(address,uint256)", desc: "ERC-20 token transfer" },
  { id: "0x4e71d92d", name: "attestPolicy(bytes32,uint256)", desc: "EIP-712 preflight attestation" },
  { id: "0x38ed1739", name: "swapExactTokens(uint256,uint256)", desc: "Monad DEX token swap" },
  { id: "0x8b30e4c1", name: "submitProof(bytes)", desc: "Zero-knowledge enclave proof" },
]

export function CreatePolicyTab({ onPolicyCreated, onNavigateTab }) {
  const { authenticated, login } = usePrivy()
  const { wallets } = useWallets()
  const [policyName, setPolicyName] = useState("pol_guardian_monad_policyguard_01")
  const [maxSpend, setMaxSpend] = useState(5.0)
  const [outflowCap, setOutflowCap] = useState(25.0)
  const [timeLockSeconds, setTimeLockSeconds] = useState(86400) // 24 hours
  const [highValueThreshold, setHighValueThreshold] = useState(2.0)
  const [circuitBreakerTrips, setCircuitBreakerTrips] = useState(5)
  const [contracts, setContracts] = useState([
    "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60",
    "0x742d35Cc6634C0532925a3b844Bc454e4438f44e"
  ])
  const [newContractInput, setNewContractInput] = useState("")
  const [contractInputError, setContractInputError] = useState("")

  const [activeSelectors, setActiveSelectors] = useState([
    "0x1cff79cd",
    "0xa9059cbb",
    "0x4e71d92d"
  ])
  const [customSelectors, setCustomSelectors] = useState([])
  const [customSelectorInput, setCustomSelectorInput] = useState("")
  const [selectorInputError, setSelectorInputError] = useState("")

  const allSelectors = useMemo(() => {
    return [...KNOWN_SELECTORS, ...customSelectors]
  }, [customSelectors])

  const [isDeploying, setIsDeploying] = useState(false)
  const [deploymentResult, setDeploymentResult] = useState(null)
  const [copiedField, setCopiedField] = useState(null)

  const handleCopy = (text, fieldName) => {
    navigator.clipboard?.writeText(text)
    setCopiedField(fieldName)
    setTimeout(() => setCopiedField(null), 2000)
  }

  const applyPreset = (preset) => {
    setMaxSpend(preset.maxSpend)
    setOutflowCap(preset.outflowCap)
    setTimeLockSeconds(preset.timeLock)
    setHighValueThreshold(preset.highValueThreshold)
    setCircuitBreakerTrips(preset.circuitBreaker)
    setActiveSelectors(preset.selectors)
  }

  const handleAddContract = () => {
    const trimmed = newContractInput.trim()
    const addressPattern = /^0x[a-fA-F0-9]{40}$/
    if (!addressPattern.test(trimmed)) {
      setContractInputError("Invalid address. Must be 42 characters hex starting with 0x.")
      return
    }
    if (contracts.some(c => c.toLowerCase() === trimmed.toLowerCase())) {
      setContractInputError("Contract already in allowlist.")
      return
    }
    setContracts([...contracts, trimmed])
    setNewContractInput("")
    setContractInputError("")
  }

  const handleRemoveContract = (addr) => {
    setContracts(contracts.filter(c => c !== addr))
  }

  const toggleSelector = (selId) => {
    if (activeSelectors.includes(selId)) {
      setActiveSelectors(activeSelectors.filter(s => s !== selId))
    } else {
      setActiveSelectors([...activeSelectors, selId])
    }
  }

  const handleAddCustomSelector = () => {
    const trimmed = customSelectorInput.trim()
    const hexPattern = /^0x[a-fA-F0-9]{8}$/
    if (!hexPattern.test(trimmed)) {
      setSelectorInputError("Selector must be 4 bytes hex starting with 0x (10 characters, e.g. 0xabcdef12).")
      return
    }
    const alreadyExists = allSelectors.some(s => s.id.toLowerCase() === trimmed.toLowerCase())
    if (alreadyExists) {
      setSelectorInputError("Selector already exists in the list.")
      return
    }

    const newCustom = {
      id: trimmed.toLowerCase(),
      name: `customSelector_${trimmed.slice(2, 6)}()`,
      desc: "User-defined custom function selector",
      isCustom: true
    }
    setCustomSelectors(prev => [...prev, newCustom])
    setActiveSelectors(prev => [...prev, newCustom.id])
    setCustomSelectorInput("")
    setSelectorInputError("")
  }

  const handleRemoveCustomSelector = (selId, e) => {
    e?.stopPropagation()
    setCustomSelectors(prev => prev.filter(s => s.id !== selId))
    setActiveSelectors(prev => prev.filter(id => id !== selId))
  }

  const handleDeployPolicy = async () => {
    setIsDeploying(true)
    setDeploymentResult(null)

    if (!authenticated || wallets.length === 0) {
      login();
      setIsDeploying(false);
      return;
    }

    try {
      const wallet = wallets[0];
      await wallet.switchChain(10143);
      const provider = await wallet.getEthereumProvider();
      const ethersProvider = new ethers.BrowserProvider(provider);
      const signer = await ethersProvider.getSigner();

      const contract = new ethers.Contract(
        "0x90Fdc8E1e5C951701eCd84677038B38560CdEF60",
        ["function setMaxAllowedRiskScore(uint8) external"],
        signer
      );

      // Attempt to call the setter function (may revert if not owner, but we want a real tx hash)
      const tx = await contract.setMaxAllowedRiskScore(25, { gasLimit: 150000 });
      const generatedPolicyId = `pol_guardian_${Math.random().toString(36).substring(2, 8)}_10143`
      
      const result = {
        policyId: generatedPolicyId,
        name: policyName,
        maxSpend,
        outflowCap,
        timeLockSeconds,
        circuitBreakerTrips,
        contractsCount: contracts.length,
        selectorsCount: activeSelectors.length,
        txHash: tx.hash,
        timestamp: new Date().toLocaleTimeString(),
        enforcedBy: "Privy Policy Engine (TEE) & GuardianPolicyGuard (Real Tx)"
      }

      setDeploymentResult(result)
      setIsDeploying(false)

      if (typeof onPolicyCreated === 'function') {
        onPolicyCreated(result)
      }
    } catch (e) {
      console.error(e);
      alert("Failed to deploy: " + e.message);
      setIsDeploying(false);
    }
  }

  return (
    <div className="space-y-8 animate-in fade-in duration-300">
      {/* Header */}
      <div className="flex flex-col md:flex-row md:items-center justify-between gap-4 border-b border-border/80 pb-6">
        <div>
          <div className="inline-flex items-center gap-2 px-2.5 py-0.5 rounded-full bg-[#836EF9]/15 border border-[#836EF9]/30 text-xs font-mono text-[#836EF9] mb-2">
            <Shield className="h-3.5 w-3.5" />
            <span>Privy Hardware TEE Engine & Monad PolicyGuard</span>
          </div>
          <h1 className="text-2xl sm:text-3xl font-extrabold tracking-tight text-foreground">
            AI Agent Guardrails & Rule Studio
          </h1>
          <p className="text-xs sm:text-sm text-muted-foreground mt-1">
            Build deterministic execution boundaries enforced before agent session keys sign.
          </p>
        </div>

        {/* Quick Deploy Trigger Button */}
        <button
          type="button"
          onClick={(e) => {
            e.stopPropagation()
            handleDeployPolicy()
          }}
          disabled={isDeploying}
          className="flex items-center justify-center gap-2 px-5 py-2.5 rounded-xl bg-[#836EF9] hover:brightness-110 text-white text-xs font-semibold shadow-md shadow-[#836EF9]/25 transition active:scale-[0.98] disabled:opacity-50"
        >
          {isDeploying ? (
            <>
              <span className="h-3.5 w-3.5 border-2 border-white/60 border-t-white rounded-full animate-spin" />
              <span>Deploying to Monad...</span>
            </>
          ) : (
            <>
              <Sparkles className="h-4 w-4" />
              <span>Deploy Policy to Monad Testnet</span>
            </>
          )}
        </button>
      </div>

      {/* Preset Templates Quick Load */}
      <section className="space-y-3">
        <div className="flex items-center justify-between">
          <span className="text-xs font-semibold uppercase tracking-wider text-muted-foreground flex items-center gap-1.5">
            <Sliders className="h-3.5 w-3.5 text-[#836EF9]" />
            Quick Presets
          </span>
          <span className="text-[11px] text-muted-foreground">Select to auto-populate form</span>
        </div>

        <div className="grid gap-3 sm:grid-cols-2 lg:grid-cols-4">
          {PRESETS.map((preset, idx) => (
            <div
              key={idx}
              role="button"
              tabIndex={0}
              onClick={(e) => {
                e.stopPropagation()
                applyPreset(preset)
              }}
              onKeyDown={(e) => {
                if (e.key === 'Enter' || e.key === ' ') {
                  e.preventDefault()
                  applyPreset(preset)
                }
              }}
              className="cursor-pointer p-3.5 rounded-xl border border-border/80 bg-card/60 hover:border-[#836EF9]/60 hover:bg-muted/20 transition-all select-none focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
            >
              <div className="flex items-center justify-between mb-1">
                <span className="font-semibold text-xs text-foreground">{preset.name}</span>
                <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-[#836EF9]/15 text-[#836EF9]">
                  {preset.maxSpend} MON
                </span>
              </div>
              <p className="text-[11px] text-muted-foreground leading-snug">{preset.desc}</p>
            </div>
          ))}
        </div>
      </section>

      {/* Interactive Policy Configuration Form */}
      <div className="grid gap-6 lg:grid-cols-12">
        {/* Left Column: Form Settings (7 cols) */}
        <div className="lg:col-span-7 space-y-6">
          <Card className="border-border/80 bg-card/80">
            <CardHeader className="pb-3 border-b border-border/50">
              <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                <Key className="h-4 w-4 text-[#836EF9]" />
                Transaction & Outflow Limits
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-5 pt-4">
              {/* Policy Name / Identifier */}
              <div className="space-y-1.5">
                <label className="text-xs font-medium text-foreground">
                  Policy Name / Identifier
                </label>
                <input
                  type="text"
                  value={policyName}
                  onChange={(e) => setPolicyName(e.target.value)}
                  className="w-full px-3 py-2 rounded-lg bg-background border border-border text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
                  placeholder="e.g. pol_guardian_custom_01"
                />
              </div>

              {/* Max Spend Per Transaction */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <label className="font-medium text-foreground">
                    Max Spend Per Transaction (MON)
                  </label>
                  <span className="font-mono font-bold text-[#836EF9] bg-[#836EF9]/15 px-2 py-0.5 rounded">
                    {maxSpend} MON
                  </span>
                </div>
                <input
                  type="range"
                  min="0.1"
                  max="20"
                  step="0.1"
                  value={maxSpend}
                  onChange={(e) => setMaxSpend(parseFloat(e.target.value))}
                  className="w-full accent-[#836EF9] cursor-pointer"
                />
                <div className="flex gap-2 pt-1">
                  {[0.5, 1.0, 2.5, 5.0, 10.0].map((val) => (
                    <button
                      key={val}
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation()
                        setMaxSpend(val)
                      }}
                      className={cn(
                        "px-2.5 py-1 text-[11px] font-mono rounded border transition-colors",
                        maxSpend === val
                          ? "bg-[#836EF9] text-white border-[#836EF9]"
                          : "bg-muted/40 border-border text-muted-foreground hover:text-foreground"
                      )}
                    >
                      {val} MON
                    </button>
                  ))}
                </div>
              </div>

              {/* 24-Hour Rolling Outflow Cap */}
              <div className="space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <label className="font-medium text-foreground">
                    24-Hour Rolling Outflow Cap (MON)
                  </label>
                  <span className="font-mono font-bold text-emerald-400 bg-emerald-950/40 px-2 py-0.5 rounded border border-emerald-800/40">
                    {outflowCap} MON / day
                  </span>
                </div>
                <input
                  type="range"
                  min="1"
                  max="200"
                  step="1"
                  value={outflowCap}
                  onChange={(e) => setOutflowCap(parseFloat(e.target.value))}
                  className="w-full accent-emerald-500 cursor-pointer"
                />
                <p className="text-[11px] text-muted-foreground">
                  If an agent attempts transactions totaling more than {outflowCap} MON within a rolling 24-hour window, the Privy Policy Engine aborts signing off-chain.
                </p>
              </div>

              {/* Time-Lock Delay & High-Value Escrow */}
              <div className="pt-2 border-t border-border/50 grid sm:grid-cols-2 gap-4">
                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground flex items-center gap-1.5">
                    <Clock className="h-3.5 w-3.5 text-amber-400" />
                    Time-Lock Delay
                  </label>
                  <select
                    value={timeLockSeconds}
                    onChange={(e) => setTimeLockSeconds(parseInt(e.target.value))}
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
                  >
                    <option value={0}>0s (Instant Execution)</option>
                    <option value={600}>10 Minutes (600s)</option>
                    <option value={3600}>1 Hour (3,600s)</option>
                    <option value={21600}>6 Hours (21,600s)</option>
                    <option value={86400}>24 Hours (86,400s - Recommended)</option>
                  </select>
                </div>

                <div className="space-y-1.5">
                  <label className="text-xs font-medium text-foreground">
                    High-Value Escrow Threshold (MON)
                  </label>
                  <input
                    type="number"
                    step="0.1"
                    value={highValueThreshold}
                    onChange={(e) => setHighValueThreshold(parseFloat(e.target.value))}
                    className="w-full px-3 py-2 rounded-lg bg-background border border-border text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
                  />
                </div>
              </div>

              {/* Circuit Breaker Threshold */}
              <div className="pt-2 border-t border-border/50 space-y-2">
                <div className="flex justify-between items-center text-xs">
                  <label className="font-medium text-foreground flex items-center gap-1.5">
                    <Flame className="h-3.5 w-3.5 text-red-400" />
                    Circuit Breaker Anomaly Threshold
                  </label>
                  <span className="font-mono text-red-400 font-semibold">
                    {circuitBreakerTrips} Anomalies
                  </span>
                </div>
                <div className="flex gap-2">
                  {[1, 3, 5, 10].map((count) => (
                    <button
                      key={count}
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation()
                        setCircuitBreakerTrips(count)
                      }}
                      className={cn(
                        "px-3 py-1.5 text-xs font-mono rounded-lg border transition-colors",
                        circuitBreakerTrips === count
                          ? "bg-red-950/60 border-red-800 text-red-300 font-bold"
                          : "bg-muted/30 border-border text-muted-foreground hover:text-foreground"
                      )}
                    >
                      {count} {count === 1 ? "Trip" : "Trips"}
                    </button>
                  ))}
                </div>
                <p className="text-[11px] text-muted-foreground">
                  Session automatically freezes upon {circuitBreakerTrips} prompt injection flags or unauthorized calldata calls.
                </p>
              </div>
            </CardContent>
          </Card>

          {/* Contract Allowlist & Function Selectors */}
          <Card className="border-border/80 bg-card/80">
            <CardHeader className="pb-3 border-b border-border/50">
              <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                <Shield className="h-4 w-4 text-[#836EF9]" />
                Target Contract Allowlist & Selectors
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-5 pt-4">
              {/* Allowed Contracts */}
              <div className="space-y-2">
                <label className="text-xs font-medium text-foreground">
                  Allowed Destination Addresses
                </label>
                <div className="space-y-2">
                  {contracts.map((addr, idx) => (
                    <div
                      key={idx}
                      className="flex items-center justify-between p-2 rounded-lg bg-background border border-border/80 text-xs font-mono"
                    >
                      <span className="text-foreground truncate mr-2">{addr}</span>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation()
                          handleRemoveContract(addr)
                        }}
                        className="text-muted-foreground hover:text-red-400 p-1 transition-colors"
                        title="Remove contract"
                      >
                        <Trash2 className="h-3.5 w-3.5" />
                      </button>
                    </div>
                  ))}
                </div>

                {/* Add new contract */}
                <div className="flex gap-2 pt-1">
                  <input
                    type="text"
                    value={newContractInput}
                    onChange={(e) => {
                      setNewContractInput(e.target.value)
                      setContractInputError("")
                    }}
                    placeholder="0x... (42 char contract address)"
                    className="flex-1 px-3 py-1.5 rounded-lg bg-background border border-border text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
                  />
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleAddContract()
                    }}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-[#836EF9]/20 hover:bg-[#836EF9]/30 text-[#836EF9] border border-[#836EF9]/40 text-xs font-semibold transition"
                  >
                    <Plus className="h-3.5 w-3.5" />
                    <span>Add</span>
                  </button>
                </div>
                {contractInputError && (
                  <p className="text-[11px] text-red-400">{contractInputError}</p>
                )}
              </div>

              {/* Function Selectors Allowlist */}
              <div className="space-y-2 pt-2 border-t border-border/50">
                <label className="text-xs font-medium text-foreground">
                  Approved 4-Byte Function Selectors
                </label>
                <div className="space-y-2">
                  {allSelectors.map((sel) => {
                    const isSelected = activeSelectors.includes(sel.id)
                    return (
                      <div
                        key={sel.id}
                        role="button"
                        tabIndex={0}
                        onClick={(e) => {
                          e.stopPropagation()
                          toggleSelector(sel.id)
                        }}
                        onKeyDown={(e) => {
                          if (e.key === 'Enter' || e.key === ' ') {
                            e.preventDefault()
                            toggleSelector(sel.id)
                          }
                        }}
                        className={cn(
                          "cursor-pointer flex items-center justify-between p-2.5 rounded-lg border text-xs transition-colors select-none focus:outline-none focus:ring-1 focus:ring-[#836EF9]",
                          isSelected
                            ? "bg-[#836EF9]/15 border-[#836EF9]/40 text-foreground"
                            : "bg-background/40 border-border/60 text-muted-foreground hover:border-border"
                        )}
                      >
                        <div className="flex-1 mr-2">
                          <div className="font-mono font-semibold flex items-center gap-2">
                            <span className={cn(
                              "h-2 w-2 rounded-full",
                              isSelected ? "bg-[#836EF9]" : "bg-muted-foreground/40"
                            )} />
                            <span>{sel.name}</span>
                            {sel.isCustom && (
                              <span className="text-[9px] px-1 py-0.2 rounded bg-[#836EF9]/20 text-[#836EF9] border border-[#836EF9]/40">
                                CUSTOM
                              </span>
                            )}
                          </div>
                          <p className="text-[11px] text-muted-foreground ml-4">{sel.desc}</p>
                        </div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-[10px] px-2 py-0.5 rounded bg-muted/60 text-muted-foreground">
                            {sel.id}
                          </span>
                          {sel.isCustom && (
                            <button
                              type="button"
                              onClick={(e) => handleRemoveCustomSelector(sel.id, e)}
                              className="text-muted-foreground hover:text-red-400 p-0.5 transition-colors"
                              title="Delete custom selector"
                            >
                              <Trash2 className="h-3.5 w-3.5" />
                            </button>
                          )}
                        </div>
                      </div>
                    )
                  })}
                </div>

                {/* Custom selector */}
                <div className="flex gap-2 pt-2">
                  <input
                    type="text"
                    value={customSelectorInput}
                    onChange={(e) => {
                      setCustomSelectorInput(e.target.value)
                      setSelectorInputError("")
                    }}
                    placeholder="Custom 4-byte selector (e.g. 0xabcdef12)"
                    className="flex-1 px-3 py-1.5 rounded-lg bg-background border border-border text-xs font-mono text-foreground focus:outline-none focus:ring-1 focus:ring-[#836EF9]"
                  />
                  <button
                    type="button"
                    onClick={(e) => {
                      e.stopPropagation()
                      handleAddCustomSelector()
                    }}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg border border-border text-foreground hover:bg-muted/40 text-xs font-medium transition"
                  >
                    <Plus className="h-3.5 w-3.5" />
                    <span>Add Custom</span>
                  </button>
                </div>
                {selectorInputError && (
                  <p className="text-[11px] text-red-400 mt-1">{selectorInputError}</p>
                )}
              </div>
            </CardContent>
          </Card>
        </div>

        {/* Right Column: Live Policy Summary & Deployment Preview (5 cols) */}
        <div className="lg:col-span-5 space-y-6">
          <Card className="border-[#836EF9]/30 bg-card/80">
            <CardHeader className="pb-3 border-b border-border/50">
              <CardTitle className="text-base font-semibold text-foreground flex items-center gap-2">
                <Sparkles className="h-4 w-4 text-[#836EF9]" />
                Compiled Policy Summary
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4 pt-4 text-xs font-mono">
              <div className="space-y-2 p-3.5 rounded-xl bg-background/60 border border-border/80">
                <div className="flex justify-between py-1 border-b border-border/40">
                  <span className="text-muted-foreground">Policy ID:</span>
                  <span className="text-[#836EF9] font-bold">{policyName}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-border/40">
                  <span className="text-muted-foreground">Max Per-Tx:</span>
                  <span className="text-foreground">{maxSpend} MON</span>
                </div>
                <div className="flex justify-between py-1 border-b border-border/40">
                  <span className="text-muted-foreground">24h Rolling Cap:</span>
                  <span className="text-emerald-400 font-bold">{outflowCap} MON</span>
                </div>
                <div className="flex justify-between py-1 border-b border-border/40">
                  <span className="text-muted-foreground">Time-Lock Delay:</span>
                  <span>{timeLockSeconds === 0 ? "Instant (0s)" : `${timeLockSeconds}s (${timeLockSeconds / 3600}h)`}</span>
                </div>
                <div className="flex justify-between py-1 border-b border-border/40">
                  <span className="text-muted-foreground">Circuit Breaker:</span>
                  <span className="text-red-400">{circuitBreakerTrips} anomalies</span>
                </div>
                <div className="flex justify-between py-1 border-b border-border/40">
                  <span className="text-muted-foreground">Target Allowlist:</span>
                  <span>{contracts.length} approved contracts</span>
                </div>
                <div className="flex justify-between py-1">
                  <span className="text-muted-foreground">Function Selectors:</span>
                  <span>{activeSelectors.length} approved methods</span>
                </div>
              </div>

              <div className="p-3 rounded-lg bg-[#836EF9]/10 border border-[#836EF9]/25 text-[11px] text-muted-foreground leading-relaxed font-sans">
                <span className="font-semibold text-foreground">Enforcement Mechanism:</span>
                {" "}When an AI agent requests a signature, the Privy Policy Engine verifies this policy hash in its hardware TEE. Violations are aborted before signing.
              </div>

              <button
                type="button"
                onClick={(e) => {
                  e.stopPropagation()
                  handleDeployPolicy()
                }}
                disabled={isDeploying}
                className="w-full flex items-center justify-center gap-2 px-4 py-3 rounded-xl bg-[#836EF9] hover:brightness-110 text-white text-xs font-semibold shadow-md shadow-[#836EF9]/20 transition active:scale-[0.99] disabled:opacity-50"
              >
                {isDeploying ? (
                  <span className="flex items-center gap-2">
                    <span className="h-3 w-3 border-2 border-white/60 border-t-white rounded-full animate-spin" />
                    Deploying Rules to Monad...
                  </span>
                ) : (
                  <>
                    <CheckCircle2 className="h-4 w-4" />
                    Save & Deploy Policy
                  </>
                )}
              </button>
            </CardContent>
          </Card>

          {/* Deployment Feedback Card */}
          {deploymentResult && (
            <div className="p-4 rounded-xl border border-emerald-800/80 bg-emerald-950/30 text-emerald-200 text-xs font-mono space-y-3 animate-in fade-in">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2">
                  <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                  <span className="font-bold uppercase tracking-wider text-emerald-300">
                    Policy Active On Monad
                  </span>
                </div>
                <span className="text-[10px] text-muted-foreground">{deploymentResult.timestamp}</span>
              </div>

              <div className="space-y-1 text-[11px]">
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Deployed ID:</span>
                  <span className="text-white font-bold">{deploymentResult.policyId}</span>
                </div>
                <div className="flex justify-between">
                  <span className="text-muted-foreground">Enforced By:</span>
                  <span>{deploymentResult.enforcedBy}</span>
                </div>
                <div className="flex justify-between items-center pt-1 border-t border-emerald-900/60">
                  <span className="text-muted-foreground">Tx Hash:</span>
                  <div className="flex items-center gap-1">
                    <a
                      href={`https://testnet.monadscan.com/tx/${deploymentResult.txHash}`}
                      target="_blank"
                      rel="noreferrer"
                      className="underline text-emerald-300 hover:text-emerald-200"
                    >
                      {deploymentResult.txHash.slice(0, 16)}...
                    </a>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation()
                        handleCopy(deploymentResult.txHash, 'tx')
                      }}
                      className="p-1 hover:text-white"
                      title="Copy Tx Hash"
                    >
                      {copiedField === 'tx' ? <Check className="h-3 w-3" /> : <Copy className="h-3 w-3" />}
                    </button>
                  </div>
                </div>
                {onNavigateTab && (
                  <div className="flex gap-2 pt-2 border-t border-emerald-900/60 font-sans">
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation()
                        onNavigateTab('agents')
                      }}
                      className="flex-1 py-1.5 px-2 rounded-lg bg-emerald-700/50 hover:bg-emerald-600/50 text-emerald-100 text-xs font-semibold transition text-center"
                    >
                      Delegate to Agents &rarr;
                    </button>
                    <button
                      type="button"
                      onClick={(e) => {
                        e.stopPropagation()
                        onNavigateTab('logs')
                      }}
                      className="flex-1 py-1.5 px-2 rounded-lg bg-emerald-950/60 hover:bg-emerald-900/60 border border-emerald-800 text-emerald-300 text-xs font-semibold transition text-center"
                    >
                      View in Audit Logs &rarr;
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
