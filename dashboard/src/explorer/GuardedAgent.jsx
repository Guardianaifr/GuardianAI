/**
 * "Your guarded agent": the connected wallet creates and owns a GuardianAgentWallet.
 * Step 1 (create) and the owner controls (fund, scam protection, freeze, risk limit, rotate agent key, withdraw).
 */
import { useCallback, useEffect, useState } from 'react'
import { parseEther, ZeroAddress } from 'ethers'
import {
  ShieldCheck, Loader2, ExternalLink, KeyRound, Snowflake, Flame, ShieldAlert, Gauge, ArrowDownToLine, PlusCircle, RefreshCw, CheckCircle2, XCircle, AlertTriangle, Bot, User,
  IdCard, Fuel, Play, Ban, CircleDashed,
} from 'lucide-react'
import { useWallet } from './wallet.jsx'
import { CONTRACTS, addressUrl, txUrl, formatMon, getFirstScamAddress } from './chain.js'
import {
  readGuardedWallet, createGuardedWallet, ownerCall, fundWallet, loadAgentKey, saveAgentKey, newAgentKey, explainTxError, RISK_LEVELS,
  claimCard, runScenario, SCENARIOS, AGENT_GAS_WEI, PAY_BACK_WEI,
} from './guardedWallet.js'

const short = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : '')
const sameAddr = (a, b) => a && b && a.toLowerCase() === b.toLowerCase()

function Pill({ tone, children }) {
  const cls = tone === 'good' ? 'gx-good gx-good-t' : tone === 'bad' ? 'gx-bad gx-bad-t' : tone === 'warn' ? 'gx-warn' : 'gx-accent-soft'
  return <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold ${cls}`}>{children}</span>
}

function Fact({ label, children }) {
  return (
    <div className="gx-surface-2 rounded-xl p-4">
      <p className="gx-muted text-xs font-semibold">{label}</p>
      <div className="gx-t1 mt-1 text-sm">{children}</div>
    </div>
  )
}

function Shell({ children, action }) {
  return (
    <section className="gx-card p-5 sm:p-6" aria-labelledby="guarded-agent-title">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          <span className="gx-accent-soft grid h-10 w-10 place-items-center rounded-xl"><ShieldCheck className="h-5 w-5" aria-hidden="true" /></span>
          <div>
            <h2 id="guarded-agent-title" className="gx-t1 text-lg font-bold">Your guarded agent</h2>
            <p className="gx-muted text-sm">A wallet for your AI agent. It can spend, but only with GuardianAI’s approval, and you can freeze it any time.</p>
          </div>
        </div>
        {action}
      </div>
      <div className="mt-5">{children}</div>
    </section>
  )
}

function ActionButton({ busy, name, onClick, disabled, ghost, children }) {
  const loading = busy === name
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={!!busy || disabled}
      className={`${ghost ? 'gx-btn-ghost' : 'gx-btn'} gx-focus !min-h-[40px] !px-4 !py-2 text-sm disabled:opacity-50`}
    >
      {loading && <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" />}
      {children}
    </button>
  )
}

export default function GuardedAgent() {
  const w = useWallet()
  const [state, setState] = useState({ status: 'idle' })
  const [busy, setBusy] = useState(null)
  const [last, setLast] = useState(null) // { label, hash } | { error }
  const [amount, setAmount] = useState('0.05')
  const [agentKey, setAgentKey] = useState(null)
  const [scamAddress, setScamAddress] = useState(null)
  const [running, setRunning] = useState(null)
  const [results, setResults] = useState([])

  useEffect(() => {
    let alive = true
    getFirstScamAddress().then((a) => { if (alive) setScamAddress(a) }).catch(() => {})
    return () => { alive = false }
  }, [])

  const owner = w.status === 'connected' ? w.address : null

  const load = useCallback(async () => {
    if (!owner) return
    setState((s) => ({ ...s, status: s.data ? 'refreshing' : 'loading' }))
    try {
      const data = await readGuardedWallet(owner)
      setState({ status: 'done', data })
    } catch (err) {
      setState((s) => ({ ...s, status: 'error', message: err?.shortMessage || err?.message || 'Could not read the wallet.' }))
    }
  }, [owner])

  useEffect(() => {
    setState({ status: 'idle' })
    setLast(null)
    setAgentKey(owner ? loadAgentKey(owner) : null)
    if (owner) load()
  }, [owner, load])

  const run = async (name, label, fn) => {
    setBusy(name)
    setLast(null)
    try {
      const signer = await w.getSigner()
      const res = await fn(signer)
      setLast({ label, hash: res.hash })
      // Other panels (Agent ID cards) re-read the chain after a new card.
      if (name === 'claim') window.dispatchEvent(new Event('gx-cards-changed'))
      await load()
      return res
    } catch (err) {
      setLast({ error: explainTxError(err), hash: err?.hash })
      return null
    } finally {
      setBusy(null)
    }
  }

  if (!owner) {
    return (
      <Shell>
        <p className="gx-t2 text-sm">Connect a wallet above to create one. The Attack Lab and everything else on this page work without a wallet.</p>
      </Shell>
    )
  }

  if (!w.onMonad) {
    return (
      <Shell>
        <div className="gx-warn rounded-xl p-4 text-sm">
          <p className="flex items-center gap-1.5 font-semibold"><AlertTriangle className="h-4 w-4" aria-hidden="true" /> Your wallet is on another network</p>
          <p className="mt-1">Guarded wallets live on Monad testnet.</p>
          <button type="button" onClick={w.switchToMonad} className="gx-btn gx-focus mt-3 !min-h-[36px] !py-1.5 text-sm">Switch to Monad testnet</button>
        </div>
      </Shell>
    )
  }

  if (state.status === 'loading' || state.status === 'idle') {
    return <Shell><p className="gx-muted inline-flex items-center gap-2 text-sm"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> Looking for your guarded wallet on Monad…</p></Shell>
  }

  if (state.status === 'error' && !state.data) {
    return (
      <Shell>
        <div role="alert" className="gx-warn rounded-xl p-3 text-sm">
          <p className="font-semibold">Couldn’t reach Monad testnet.</p>
          <p className="opacity-90">{state.message}</p>
          <button type="button" onClick={load} className="gx-focus mt-1 rounded font-semibold underline-offset-2 hover:underline">Try again</button>
        </div>
      </Shell>
    )
  }

  const d = state.data
  const lastLine = last && (
    last.error
      ? <p role="alert" className="gx-bad-t mt-4 text-sm">{last.error}{last.hash && <> · <a className="gx-link" href={txUrl(last.hash)} target="_blank" rel="noreferrer">transaction</a></>}</p>
      : <p className="gx-good-t mt-4 inline-flex flex-wrap items-center gap-1 text-sm"><CheckCircle2 className="h-4 w-4" aria-hidden="true" /> {last.label} <a className="gx-link inline-flex items-center gap-1" href={txUrl(last.hash)} target="_blank" rel="noreferrer">View on MonadScan <ExternalLink className="h-3 w-3" aria-hidden="true" /></a></p>
  )

  /* ---------- Step 1: no wallet yet ---------- */
  if (!d.wallet) {
    const create = () => run('create', 'Guarded wallet created.', async (signer) => {
      const agent = agentKey || newAgentKey()
      if (!agentKey) { saveAgentKey(owner, agent); setAgentKey(agent) }
      return createGuardedWallet(signer, agent.address)
    })
    return (
      <Shell>
        <div className="grid grid-cols-1 gap-6 md:grid-cols-[1.2fr_1fr]">
          <div className="gx-t2 space-y-3 text-sm leading-relaxed">
            <p className="gx-t1 font-semibold">Two keys, like a real deployment:</p>
            <p className="flex gap-2"><User className="gx-accent mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" /><span><strong className="gx-t1">You (owner)</strong>: your connected wallet. You fund it, set its limits, freeze it and withdraw. No approval needed.</span></p>
            <p className="flex gap-2"><Bot className="gx-accent mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" /><span><strong className="gx-t1">Your agent</strong>: a new key made in this browser. It can only move money with a fresh GuardianAI approval for that exact payment. The chain refuses anything else.</span></p>
            <p className="gx-muted text-xs">One transaction on Monad testnet (gas only). The agent key is a demo key kept in this browser; you can replace it any time.</p>
          </div>
          <div className="gx-surface-2 flex flex-col justify-center gap-3 rounded-xl p-4">
            <ActionButton busy={busy} name="create" onClick={create}>Create guarded wallet</ActionButton>
            <a className="gx-link inline-flex items-center gap-1 text-xs" href={addressUrl(CONTRACTS.walletFactory.address)} target="_blank" rel="noreferrer">Uses GuardianAgentWalletFactory <ExternalLink className="h-3 w-3" aria-hidden="true" /></a>
          </div>
        </div>
        {lastLine}
      </Shell>
    )
  }

  /* ---------- Wallet exists: status + owner controls ---------- */
  const keyHere = agentKey && sameAddr(agentKey.address, d.operator)
  const balanceWei = d.balance
  const call = (name, label, fn, args) => run(name, label, (signer) => ownerCall(signer, d.wallet, fn, args))

  const rotate = () => run('rotate', 'Agent key replaced. The old key can no longer request anything.', async (signer) => {
    const next = newAgentKey()
    const res = await ownerCall(signer, d.wallet, 'setOperator', [next.address])
    saveAgentKey(owner, next)
    setAgentKey(next)
    return res
  })

  const fund = () => {
    let wei
    try { wei = parseEther(amount || '0') } catch { setLast({ error: 'Enter an amount like 0.05.' }); return }
    if (wei <= 0n) { setLast({ error: 'Enter an amount above 0.' }); return }
    run('fund', `Added ${amount} MON.`, (signer) => fundWallet(signer, d.wallet, wei))
  }

  return (
    <Shell
      action={<button type="button" onClick={load} disabled={state.status === 'refreshing'} className="gx-link gx-focus inline-flex items-center gap-1 rounded text-sm disabled:opacity-50"><RefreshCw className={`h-4 w-4 ${state.status === 'refreshing' ? 'animate-spin' : ''}`} aria-hidden="true" /> Refresh</button>}
    >
      <div className="grid grid-cols-1 gap-3 sm:grid-cols-2 lg:grid-cols-4">
        <Fact label="Agent wallet">
          <a className="gx-link inline-flex items-center gap-1 font-mono" href={addressUrl(d.wallet)} target="_blank" rel="noreferrer">{short(d.wallet)} <ExternalLink className="h-3 w-3" aria-hidden="true" /></a>
          <p className="gx-t1 mt-2 text-xl font-bold tabular-nums">{formatMon(balanceWei)} MON</p>
        </Fact>
        <Fact label="Status">
          {d.paused
            ? <Pill tone="bad"><Snowflake className="h-3.5 w-3.5" aria-hidden="true" /> Frozen: agent can’t pay</Pill>
            : <Pill tone="good"><CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" /> Active</Pill>}
          <p className="gx-muted mt-2 text-xs">Owner: {sameAddr(d.owner, owner) ? 'you' : short(d.owner)}</p>
        </Fact>
        <Fact label="Protection">
          <p className="flex items-center gap-1.5">{d.approvalsByGuardian ? <CheckCircle2 className="gx-good-t h-4 w-4" aria-hidden="true" /> : <XCircle className="gx-bad-t h-4 w-4" aria-hidden="true" />} Payments need GuardianAI’s approval</p>
          <p className="mt-1 flex items-center gap-1.5">{d.scamProtection ? <CheckCircle2 className="gx-good-t h-4 w-4" aria-hidden="true" /> : <XCircle className="gx-bad-t h-4 w-4" aria-hidden="true" />} Scam list checked on-chain</p>
          <p className="mt-1 flex items-center gap-1.5"><Gauge className="gx-accent h-4 w-4" aria-hidden="true" /> Risk limit {d.maxRisk}/100</p>
        </Fact>
        <Fact label="Agent">
          <p className="font-mono text-xs">{short(d.operator)}</p>
          <p className={`mt-1 text-xs ${keyHere ? 'gx-good-t' : 'gx-muted'}`}>{keyHere ? 'Key saved in this browser' : 'Key not in this browser'}</p>
          <p className="mt-2 text-xs">{d.hasPassport
            ? <Pill tone="good"><CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" /> Agent ID card active</Pill>
            : <Pill tone="warn">No Agent ID card yet</Pill>}</p>
        </Fact>
      </div>

      {!d.scamProtection && (
        <div className="gx-warn mt-4 flex flex-wrap items-center justify-between gap-3 rounded-xl p-4 text-sm">
          <p className="flex items-center gap-1.5"><ShieldAlert className="h-4 w-4 shrink-0" aria-hidden="true" /> Scam protection is off. Turn it on so the chain itself refuses payments to addresses on the Chainlink-fed scam list.</p>
          <ActionButton busy={busy} name="oracle" onClick={() => call('oracle', 'Scam protection on.', 'setThreatOracle', [CONTRACTS.threatOracle.address])}>Turn on scam protection</ActionButton>
        </div>
      )}

      <AgentReady d={d} keyHere={keyHere} busy={busy}
        onClaim={() => run('claim', 'Agent ID card issued to your agent.', (signer) => claimCard(signer))}
        onGas={() => run('gas', `Sent ${formatMon(AGENT_GAS_WEI)} MON to your agent for gas.`, (signer) => fundWallet(signer, d.operator, AGENT_GAS_WEI))}
      />

      <TryAgent
        ready={d.hasPassport && keyHere}
        canPay={balanceWei >= PAY_BACK_WEI}
        running={running}
        results={results}
        scamAddress={scamAddress}
        onRun={async (kind) => {
          setRunning(kind)
          try {
            const r = await runScenario(kind, { owner, wallet: d.wallet, agentKey, scamAddress })
            setResults((rs) => [{ ...r, at: Date.now() }, ...rs].slice(0, 12))
            if (r.outcome === 'paid') await load()
          } finally {
            setRunning(null)
          }
        }}
      />

      <h3 className="gx-t1 mt-6 text-base font-bold">You’re in control</h3>
      <p className="gx-muted text-sm">Owner actions go straight to your wallet contract. GuardianAI can’t block them, and your agent can’t do them.</p>

      <div className="mt-3 grid grid-cols-1 gap-3 md:grid-cols-2">
        <div className="gx-surface-2 rounded-xl p-4">
          <p className="gx-t1 flex items-center gap-1.5 font-semibold"><PlusCircle className="h-4 w-4" aria-hidden="true" /> Add funds</p>
          <div className="mt-2 flex flex-wrap items-center gap-2">
            <label className="sr-only" htmlFor="gx-fund-amount">Amount in MON</label>
            <span className="inline-flex items-center gap-2">
              <input id="gx-fund-amount" className="gx-input !w-24 rounded-lg border px-3 py-2 text-sm" inputMode="decimal" value={amount} onChange={(e) => setAmount(e.target.value.trim())} />
              <span className="gx-muted text-sm">MON</span>
            </span>
            <ActionButton busy={busy} name="fund" onClick={fund}>Send to agent wallet</ActionButton>
          </div>
        </div>

        <div className="gx-surface-2 rounded-xl p-4">
          <p className="gx-t1 flex items-center gap-1.5 font-semibold">{d.paused ? <Flame className="h-4 w-4" aria-hidden="true" /> : <Snowflake className="h-4 w-4" aria-hidden="true" />} Kill switch</p>
          <p className="gx-muted mt-1 text-xs">{d.paused ? 'While frozen, every agent payment is refused on-chain. You can still withdraw.' : 'Freeze stops every agent payment on-chain at once.'}</p>
          <div className="mt-2">
            {d.paused
              ? <ActionButton busy={busy} name="pause" onClick={() => call('pause', 'Wallet unfrozen.', 'unpause')}>Unfreeze agent</ActionButton>
              : <ActionButton busy={busy} name="pause" onClick={() => call('pause', 'Wallet frozen.', 'pause')}>Freeze agent</ActionButton>}
          </div>
        </div>

        <div className="gx-surface-2 rounded-xl p-4">
          <p className="gx-t1 flex items-center gap-1.5 font-semibold"><Gauge className="h-4 w-4" aria-hidden="true" /> Risk limit</p>
          <p className="gx-muted mt-1 text-xs">The highest GuardianAI risk score this wallet will accept. Checked on-chain for every payment.</p>
          <div className="mt-2 flex flex-wrap gap-2" role="group" aria-label="Risk limit">
            {RISK_LEVELS.map((r) => (
              d.maxRisk === r.value
                ? <span key={r.value} aria-current="true" title={r.hint} className="gx-good gx-good-t inline-flex min-h-[40px] items-center gap-1 rounded-xl px-4 text-sm font-semibold"><CheckCircle2 className="h-4 w-4" aria-hidden="true" /> {r.label} · {r.value}</span>
                : <span key={r.value} title={r.hint}><ActionButton busy={busy} name={`risk-${r.value}`} ghost
                    onClick={() => call(`risk-${r.value}`, `Risk limit set to ${r.value}.`, 'setMaxAllowedRiskScore', [r.value])}>
                    {r.label} · {r.value}
                  </ActionButton></span>
            ))}
          </div>
        </div>

        <div className="gx-surface-2 rounded-xl p-4">
          <p className="gx-t1 flex items-center gap-1.5 font-semibold"><KeyRound className="h-4 w-4" aria-hidden="true" /> Agent key leaked?</p>
          <p className="gx-muted mt-1 text-xs">Replace it with a new key. The old one stops working in the same block.</p>
          <div className="mt-2"><ActionButton busy={busy} name="rotate" ghost onClick={rotate}>Replace agent key</ActionButton></div>
        </div>

        <div className="gx-surface-2 rounded-xl p-4 md:col-span-2">
          <p className="gx-t1 flex items-center gap-1.5 font-semibold"><ArrowDownToLine className="h-4 w-4" aria-hidden="true" /> Withdraw</p>
          <p className="gx-muted mt-1 text-xs">Moves the whole balance back to your wallet. Works even while the agent is frozen.</p>
          <div className="mt-2">
            <ActionButton busy={busy} name="withdraw" ghost disabled={balanceWei === 0n}
              onClick={() => call('withdraw', `Withdrew ${formatMon(balanceWei)} MON.`, 'ownerExecute', [owner, balanceWei, '0x'])}>
              Withdraw {formatMon(balanceWei)} MON
            </ActionButton>
          </div>
        </div>
      </div>

      {lastLine}

      <p className="gx-muted mt-5 text-xs">
        Agent payments need an active Agent ID card and a GuardianAI approval for that exact payment.
        {!d.usesGuardianOracle && d.scamProtection && ' Scam list: a custom oracle, not GuardianAI’s.'}
        {d.operator === ZeroAddress && ' No agent key is set.'}
      </p>
    </Shell>
  )
}


/* ------------------------------------------------------------------ */
/* Get your agent ready: ID card + gas                                */
/* ------------------------------------------------------------------ */

function Check({ done, children, action }) {
  return (
    <li className="gx-surface-2 flex flex-wrap items-center justify-between gap-3 rounded-xl p-3">
      <span className="flex items-center gap-2 text-sm">
        {done ? <CheckCircle2 className="gx-good-t h-5 w-5 shrink-0" aria-hidden="true" /> : <CircleDashed className="gx-muted h-5 w-5 shrink-0" aria-hidden="true" />}
        <span className={done ? 'gx-t1' : 'gx-t2'}>{children}</span>
      </span>
      {!done && action}
    </li>
  )
}

function AgentReady({ d, keyHere, busy, onClaim, onGas }) {
  const gas = d.operatorBalance ?? 0n
  const enoughGas = gas >= AGENT_GAS_WEI / 5n
  return (
    <>
      <h3 className="gx-t1 mt-6 text-base font-bold">Get your agent ready</h3>
      <ul className="mt-3 space-y-2">
        <Check done={d.hasPassport} action={<ActionButton busy={busy} name="claim" onClick={onClaim}><IdCard className="h-4 w-4" aria-hidden="true" /> Get Agent ID card</ActionButton>}>
          {d.hasPassport ? 'Agent ID card active (entry level)' : 'Agent ID card: GuardianAI only approves payments for agents with a card. One per wallet, free.'}
        </Check>
        <Check done={enoughGas} action={<ActionButton busy={busy} name="gas" ghost onClick={onGas}><Fuel className="h-4 w-4" aria-hidden="true" /> Give your agent {formatMon(AGENT_GAS_WEI)} MON for gas</ActionButton>}>
          {enoughGas ? `Agent key has ${formatMon(gas)} MON for gas` : `Agent key has ${formatMon(gas)} MON. It pays its own gas when it sends a payment.`}
        </Check>
        <Check done={d.balance >= PAY_BACK_WEI}>
          {d.balance >= PAY_BACK_WEI ? 'Agent wallet has funds to spend' : 'Agent wallet is empty: add funds below so the agent has something to spend.'}
        </Check>
        {!keyHere && (
          <Check done={false}>The agent key isn’t in this browser. Use “Replace agent key” below to make a new one here.</Check>
        )}
      </ul>
    </>
  )
}

/* ------------------------------------------------------------------ */
/* Let your agent try                                                 */
/* ------------------------------------------------------------------ */

const OUTCOME = {
  paid: { tone: 'good', label: 'Paid', Icon: CheckCircle2 },
  blocked: { tone: 'bad', label: 'Blocked by GuardianAI', Icon: Ban },
  refused: { tone: 'bad', label: 'Refused by Monad', Icon: Ban },
  'would-pass': { tone: 'warn', label: 'Would go through', Icon: AlertTriangle },
  error: { tone: 'warn', label: 'Didn’t run', Icon: AlertTriangle },
}

function ResultRow({ r }) {
  const s = SCENARIOS.find((x) => x.kind === r.kind)
  const o = OUTCOME[r.outcome] || OUTCOME.error
  return (
    <li className="gx-surface-2 rounded-xl p-3 text-sm" aria-live="polite">
      <div className="flex flex-wrap items-center justify-between gap-2">
        <span className="gx-t1 font-semibold">{s?.title}</span>
        <Pill tone={o.tone}><o.Icon className="h-3.5 w-3.5" aria-hidden="true" /> {o.label}</Pill>
      </div>
      <p className="gx-t2 mt-1 break-words">{r.message}</p>
      <p className="gx-muted mt-1 flex min-w-0 flex-wrap gap-x-3 gap-y-1 text-xs">
        {r.riskScore !== null && r.riskScore !== undefined && <span>GuardianAI risk score {r.riskScore}/100</span>}
        {r.reasons?.length > 0 && <span className="min-w-0 break-all">{r.reasons.join(' · ')}</span>}
        {r.revert && <span className="font-mono">{r.revert}</span>}
        {r.hash && <a className="gx-link inline-flex items-center gap-1" href={txUrl(r.hash)} target="_blank" rel="noreferrer">Transaction on MonadScan <ExternalLink className="h-3 w-3" aria-hidden="true" /></a>}
      </p>
    </li>
  )
}

function TryAgent({ ready, canPay, running, results, scamAddress, onRun }) {
  return (
    <>
      <h3 className="gx-t1 mt-6 text-base font-bold">Let your agent try</h3>
      <p className="gx-muted text-sm">
        Each try asks GuardianAI first, then checks the call against Monad before anything is sent. Only “Pay you back” moves money.
      </p>
      {!ready && <p className="gx-warn mt-3 rounded-xl p-3 text-sm">Get the ID card first (and keep the agent key in this browser).</p>}
      <div className="mt-3 grid grid-cols-1 gap-2 sm:grid-cols-2 lg:grid-cols-3">
        {SCENARIOS.map((s) => {
          const disabled = !ready || !!running || (s.kind === 'payBack' && !canPay) || (s.kind === 'scamList' && !scamAddress)
          return (
            <button
              key={s.kind}
              type="button"
              disabled={disabled}
              onClick={() => onRun(s.kind)}
              className="gx-bd gx-focus flex items-start gap-2 rounded-xl border p-3 text-left text-sm transition hover:opacity-80 disabled:opacity-50"
            >
              {running === s.kind ? <Loader2 className="gx-accent mt-0.5 h-4 w-4 shrink-0 animate-spin" aria-hidden="true" /> : <Play className="gx-accent mt-0.5 h-4 w-4 shrink-0" aria-hidden="true" />}
              <span>
                <span className="gx-t1 block font-semibold">{s.title}</span>
                <span className="gx-muted block text-xs">Expected: {s.expect}</span>
              </span>
            </button>
          )
        })}
      </div>
      {results.length > 0 && <ul className="mt-3 space-y-2">{results.map((r) => <ResultRow key={r.at} r={r} />)}</ul>}
    </>
  )
}
