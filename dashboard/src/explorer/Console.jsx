import { useCallback, useEffect, useState } from 'react'
import {
  Wallet as WalletIcon, AlertTriangle, ExternalLink, RefreshCw, Loader2, IdCard, Ban, Settings2, Search, CheckCircle2, XCircle, Copy, Check,
} from 'lucide-react'
import './theme.css'
import { Header, Footer, useTheme } from './layout.jsx'
import { useWallet, WalletPicker } from './wallet.jsx'
import {
  CONTRACTS, TEAM_WALLET, addressUrl, getBalance, formatMon, listPassports, listScamWallets, readGuardSettings, checkAddress, ipfsToHttp, getBlockNumber, getFirstScamAddress,
} from './chain.js'

const short = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : '')
const sameAddr = (a, b) => a && b && a.toLowerCase() === b.toLowerCase()

function Panel(props) {
  const { title, subtitle, action, children } = props
  const IconC = props.iconC
  return (
    <section className="gx-card p-5 sm:p-6">
      <div className="flex flex-wrap items-start justify-between gap-3">
        <div className="flex items-center gap-3">
          {IconC && <span className="gx-accent-soft grid h-10 w-10 place-items-center rounded-xl"><IconC className="h-5 w-5" aria-hidden="true" /></span>}
          <div>
            <h2 className="gx-t1 text-lg font-bold">{title}</h2>
            {subtitle && <p className="gx-muted text-sm">{subtitle}</p>}
          </div>
        </div>
        {action}
      </div>
      <div className="mt-5">{children}</div>
    </section>
  )
}

function Pill({ tone, children }) {
  const cls = tone === 'good' ? 'gx-good gx-good-t' : tone === 'bad' ? 'gx-bad gx-bad-t' : tone === 'warn' ? 'gx-warn' : 'gx-accent-soft'
  return <span className={`inline-flex items-center gap-1 rounded-full px-2.5 py-0.5 text-xs font-semibold ${cls}`}>{children}</span>
}

function Loading({ label }) {
  return <p className="gx-muted inline-flex items-center gap-2 text-sm"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> {label}</p>
}

function ErrorLine({ message, onRetry }) {
  return (
    <div role="alert" className="gx-warn rounded-xl p-3 text-sm">
      <p className="font-semibold">Couldn’t reach Monad testnet.</p>
      <p className="opacity-90">{message}</p>
      {onRetry && <button type="button" onClick={onRetry} className="gx-focus mt-1 rounded font-semibold underline-offset-2 hover:underline">Try again</button>}
    </div>
  )
}

/* ------------------------------------------------------------------ */
/* Data loading                                                        */
/* ------------------------------------------------------------------ */

function useAsync(fn, deps) {
  const [state, setState] = useState({ status: 'loading' })
  // eslint-disable-next-line react-hooks/exhaustive-deps
  const run = useCallback(fn, deps)
  const reload = useCallback(async () => {
    setState((s) => ({ ...s, status: 'loading' }))
    try { setState({ status: 'done', data: await run() }) } catch (err) { setState({ status: 'error', message: err?.message || 'Unknown error' }) }
  }, [run])
  useEffect(() => {
    let alive = true
    run().then((data) => { if (alive) setState({ status: 'done', data }) })
      .catch((err) => { if (alive) setState({ status: 'error', message: err?.message || 'Unknown error' }) })
    return () => { alive = false }
  }, [run])
  return [state, reload]
}

/* ------------------------------------------------------------------ */
/* 1. Your wallet                                                      */
/* ------------------------------------------------------------------ */

function YourWallet() {
  const w = useWallet()
  const [copied, setCopied] = useState(false)
  const [bal, setBal] = useState({ status: 'idle' })

  useEffect(() => {
    if (w.status !== 'connected') return
    let alive = true
    getBalance(w.address)
      .then((wei) => { if (alive) setBal({ status: 'done', wei }) })
      .catch((err) => { if (alive) setBal({ status: 'error', message: err?.message }) })
    return () => { alive = false }
  }, [w.status, w.address])

  if (w.status !== 'connected') {
    return (
      <Panel iconC={WalletIcon} title="Connect your wallet" subtitle="See your wallet on Monad testnet and any GuardianAI agents it owns.">
        <div className="grid grid-cols-1 gap-6 md:grid-cols-[1fr_1fr]">
          <div className="gx-t2 space-y-2 text-sm leading-relaxed">
            <p>GuardianAI only reads your address. Nothing on this page asks you to sign a message or send a transaction.</p>
            <p>No wallet? Everything else on this page still works, and the <a href="./" className="gx-link">Attack Lab</a> needs no wallet at all.</p>
          </div>
          <div className="gx-surface-2 rounded-xl p-3">
            <WalletPicker />
            {w.error && <p role="alert" className="gx-bad-t mt-3 px-1 text-sm">{w.error}</p>}
          </div>
        </div>
      </Panel>
    )
  }

  const copy = async () => {
    try { await navigator.clipboard.writeText(w.address); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* ignore */ }
  }

  return (
    <Panel
      iconC={WalletIcon}
      title="Your wallet"
      subtitle={`Connected with ${w.wallet?.name}`}
      action={<button type="button" onClick={w.disconnect} className="gx-link gx-focus rounded text-sm">Disconnect</button>}
    >
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-3">
        <div className="gx-surface-2 rounded-xl p-4 sm:col-span-1">
          <p className="gx-muted text-xs font-semibold">Address</p>
          <p className="gx-t1 mt-1 font-mono text-sm">{short(w.address)}</p>
          <div className="mt-2 flex gap-3 text-xs">
            <button type="button" onClick={copy} className="gx-link gx-focus inline-flex items-center gap-1 rounded">{copied ? <Check className="h-3.5 w-3.5" aria-hidden="true" /> : <Copy className="h-3.5 w-3.5" aria-hidden="true" />}{copied ? 'Copied' : 'Copy'}</button>
            <a href={addressUrl(w.address)} target="_blank" rel="noreferrer" className="gx-link inline-flex items-center gap-1">MonadScan <ExternalLink className="h-3 w-3" aria-hidden="true" /></a>
          </div>
        </div>
        <div className="gx-surface-2 rounded-xl p-4">
          <p className="gx-muted text-xs font-semibold">Network</p>
          {w.onMonad
            ? <p className="mt-1"><Pill tone="good"><CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" /> Monad testnet</Pill></p>
            : (
              <>
                <p className="mt-1"><Pill tone="warn"><AlertTriangle className="h-3.5 w-3.5" aria-hidden="true" /> Not on Monad testnet</Pill></p>
                <button type="button" onClick={w.switchToMonad} className="gx-btn gx-focus mt-2 !min-h-[36px] !px-3 !py-1.5 text-sm">Switch network</button>
              </>
            )}
        </div>
        <div className="gx-surface-2 rounded-xl p-4">
          <p className="gx-muted text-xs font-semibold">Balance on Monad testnet</p>
          <p className="gx-t1 mt-1 text-xl font-bold tabular-nums">
            {bal.status === 'done' ? `${formatMon(bal.wei)} MON` : bal.status === 'error' ? '—' : <Loader2 className="h-5 w-5 animate-spin" aria-label="Loading" />}
          </p>
        </div>
      </div>
      {w.error && <p role="alert" className="gx-bad-t mt-3 text-sm">{w.error}</p>}
    </Panel>
  )
}

/* ------------------------------------------------------------------ */
/* 2. Agent ID cards (yours first)                                     */
/* ------------------------------------------------------------------ */

function AgentCard({ p, mine }) {
  return (
    <li className="gx-surface-2 rounded-xl p-4">
      <div className="flex items-start justify-between gap-3">
        <div className="min-w-0">
          <p className="gx-t1 font-bold">{p.name} <span className="gx-muted font-normal">#{p.tokenId}</span></p>
          <p className="mt-1 text-xs font-semibold" style={{ color: sameAddr(p.owner, TEAM_WALLET) ? 'var(--gx-muted)' : 'var(--gx-good-text)' }}>
            {sameAddr(p.owner, TEAM_WALLET) ? 'GuardianAI demo agent' : 'Built on GuardianAI · external team'}
          </p>
          <p className="gx-muted mt-0.5 break-all font-mono text-xs">{p.agentId.slice(0, 18)}…</p>
        </div>
        {p.revoked ? <Pill tone="bad"><XCircle className="h-3.5 w-3.5" aria-hidden="true" /> Revoked</Pill> : <Pill tone="good"><CheckCircle2 className="h-3.5 w-3.5" aria-hidden="true" /> Active</Pill>}
      </div>
      <dl className="mt-3 grid grid-cols-2 gap-2 text-sm">
        <div><dt className="gx-muted text-xs">Trust score</dt><dd className="gx-t1 font-semibold tabular-nums">{p.trustScore.toFixed(2)} / 100</dd></div>
        <div><dt className="gx-muted text-xs">Tier</dt><dd className="gx-t1 font-semibold">{p.tier}</dd></div>
        <div><dt className="gx-muted text-xs">Issued</dt><dd className="gx-t1">{p.issuedAt.toLocaleDateString()}</dd></div>
        <div><dt className="gx-muted text-xs">Owner</dt><dd className="gx-t1 font-mono text-xs">{mine ? 'You' : sameAddr(p.owner, TEAM_WALLET) ? `${short(p.owner)} (team)` : short(p.owner)}</dd></div>
      </dl>
      <div className="mt-3 flex flex-wrap gap-3 text-xs">
        <a href={`${addressUrl(CONTRACTS.passport.address)}`} target="_blank" rel="noreferrer" className="gx-link inline-flex items-center gap-1">Contract <ExternalLink className="h-3 w-3" aria-hidden="true" /></a>
        {p.metadataURI && <a href={ipfsToHttp(p.metadataURI)} target="_blank" rel="noreferrer" className="gx-link inline-flex items-center gap-1">Metadata <ExternalLink className="h-3 w-3" aria-hidden="true" /></a>}
      </div>
    </li>
  )
}

function Agents() {
  const w = useWallet()
  const [state, reload] = useAsync(() => listPassports(), [])
  const all = state.data || []
  const mine = w.status === 'connected' ? all.filter((p) => sameAddr(p.owner, w.address)) : []
  const others = all.filter((p) => !mine.includes(p))
  return (
    <Panel
      iconC={IdCard}
      title="Agent ID cards"
      subtitle="Every agent registered with GuardianAI. An agent needs an active card before the payment guard lets it pay."
      action={<button type="button" onClick={reload} disabled={state.status === 'loading'} className="gx-link gx-focus inline-flex items-center gap-1 rounded text-sm disabled:opacity-50"><RefreshCw className={`h-4 w-4 ${state.status === 'loading' ? 'animate-spin' : ''}`} aria-hidden="true" /> Refresh</button>}
    >
      {state.status === 'loading' && !state.data && <Loading label="Reading agent ID cards from Monad…" />}
      {state.status === 'error' && <ErrorLine message={state.message} onRetry={reload} />}
      {state.data && (
        <>
          {w.status === 'connected' && (
            <div className="mb-5">
              <p className="gx-t1 mb-2 text-sm font-semibold">Owned by your wallet</p>
              {mine.length
                ? <ul className="grid grid-cols-1 gap-3 md:grid-cols-3">{mine.map((p) => <AgentCard key={p.tokenId} p={p} mine />)}</ul>
                : <p className="gx-surface-2 gx-t2 rounded-xl p-4 text-sm">This wallet doesn’t own any agent ID cards yet. Cards are issued when an agent is registered with GuardianAI.</p>}
            </div>
          )}
          {others.length > 0 && (
            <>
              {w.status === 'connected' && <p className="gx-t1 mb-2 text-sm font-semibold">All other agents</p>}
              <ul className="grid grid-cols-1 gap-3 md:grid-cols-3">{others.map((p) => <AgentCard key={p.tokenId} p={p} />)}</ul>
            </>
          )}
          {all.length === 0 && <p className="gx-t2 text-sm">No agents are registered yet.</p>}
          {all.length > 0 && (
            <p className="gx-muted mt-4 text-sm">
              {all.filter((p) => !sameAddr(p.owner, TEAM_WALLET)).length} of {all.length} cards are held by wallets outside the GuardianAI team. Team wallet: <a href={addressUrl(TEAM_WALLET)} target="_blank" rel="noreferrer" className="gx-link font-mono">{short(TEAM_WALLET)}</a>.
            </p>
          )}
        </>
      )}
    </Panel>
  )
}

/* ------------------------------------------------------------------ */
/* 3. Check an address                                                 */
/* ------------------------------------------------------------------ */

function CheckAddress() {
  const [value, setValue] = useState('')
  const [state, setState] = useState({ status: 'idle' })
  const run = async (e, addr = value) => {
    e?.preventDefault()
    setState({ status: 'loading' })
    try { setState({ status: 'done', r: await checkAddress(addr) }) } catch (err) { setState({ status: 'error', message: err?.message }) }
  }
  const tryExample = async () => {
    try {
      const a = await getFirstScamAddress()
      if (a) { setValue(a); await run(null, a) }
    } catch (err) {
      setState({ status: 'error', message: err?.message })
    }
  }
  const r = state.r
  return (
    <Panel iconC={Search} title="Check an address before paying" subtitle="Looks the address up on GuardianAI’s scam list on Monad.">
      <form onSubmit={run} className="flex flex-col gap-2 sm:flex-row">
        <label htmlFor="console-addr" className="sr-only">Address</label>
        <input id="console-addr" value={value} onChange={(e) => setValue(e.target.value)} placeholder="0x…" spellCheck={false} autoComplete="off" className="gx-input min-h-[48px] flex-1 font-mono text-sm" />
        <button type="submit" disabled={!value.trim() || state.status === 'loading'} className="gx-btn gx-focus">
          {state.status === 'loading' && <Loader2 className="h-5 w-5 animate-spin" aria-hidden="true" />} Check
        </button>
      </form>
      <button type="button" onClick={tryExample} className="gx-link gx-focus mt-3 rounded text-sm">Try a known scam wallet</button>
      <div aria-live="polite" className="mt-4 empty:hidden">
        {state.status === 'error' && <p role="alert" className="gx-bad-t text-sm">{state.message}</p>}
        {state.status === 'done' && (
          <div className={`rounded-xl p-4 ${r.malicious ? 'gx-bad' : 'gx-good'}`}>
            <p className={`font-bold ${r.malicious ? 'gx-bad-t' : 'gx-good-t'}`}>{r.malicious ? 'Known scam wallet. GuardianAI blocks payments to it.' : 'Not on the scam list.'}</p>
            {r.malicious && r.reason && <p className="gx-t1 mt-1 text-sm">Listed as: {r.reason}</p>}
            {!r.malicious && <p className="gx-t1 mt-1 text-sm">That doesn’t prove it’s safe, but it isn’t a known scam.</p>}
            <p className="gx-muted mt-2 font-mono text-xs">isMalicious({short(r.address)}) → {r.proof.rawResult} · block #{r.block.toLocaleString()}</p>
          </div>
        )}
      </div>
    </Panel>
  )
}

/* ------------------------------------------------------------------ */
/* 4. Scam list + guard settings                                       */
/* ------------------------------------------------------------------ */

function ScamList() {
  const [state, reload] = useAsync(() => listScamWallets(), [])
  return (
    <Panel iconC={Ban} title="Scam wallet list" subtitle="Wallets GuardianAI refuses to let agents pay. Public, so any app can use it.">
      {state.status === 'loading' && !state.data && <Loading label="Reading the list…" />}
      {state.status === 'error' && <ErrorLine message={state.message} onRetry={reload} />}
      {state.data && (state.data.length === 0
        ? <p className="gx-t2 text-sm">The list is empty.</p>
        : (
          <ul className="space-y-2">
            {state.data.map((s) => (
              <li key={s.address} className="gx-surface-2 flex flex-col gap-1 rounded-xl p-3 sm:flex-row sm:items-center sm:justify-between">
                <span className="min-w-0">
                  <a href={addressUrl(s.address)} target="_blank" rel="noreferrer" className="gx-link break-all font-mono text-sm">{s.address}</a>
                  {s.reason && <span className="gx-t2 block text-sm">{s.reason}</span>}
                </span>
                <Pill tone="bad">Blocked</Pill>
              </li>
            ))}
          </ul>
        ))}
      <a href={addressUrl(CONTRACTS.threatFeed.address)} target="_blank" rel="noreferrer" className="gx-link mt-4 inline-flex items-center gap-1 text-xs">GuardianThreatFeedRegistry <ExternalLink className="h-3 w-3" aria-hidden="true" /></a>
    </Panel>
  )
}

function GuardSettings() {
  const [state, reload] = useAsync(async () => {
    const [settings, block] = await Promise.all([readGuardSettings(), getBlockNumber()])
    return { ...settings, block }
  }, [])
  const s = state.data
  const rows = s ? [
    ['Status', s.paused ? <Pill key="p" tone="warn">Paused</Pill> : <Pill key="a" tone="good">Active</Pill>],
    ['Highest risk allowed', `${s.maxRisk} / 100`],
    ['Approvals must be signed by', <a key="s" href={addressUrl(s.signer)} target="_blank" rel="noreferrer" className="gx-link font-mono">{short(s.signer)}</a>],
    ['Agent ID cards checked at', <a key="r" href={addressUrl(s.registry)} target="_blank" rel="noreferrer" className="gx-link font-mono">{sameAddr(s.registry, CONTRACTS.passport.address) ? 'GuardianPassportSBT' : short(s.registry)}</a>],
  ] : []
  return (
    <Panel
      iconC={Settings2}
      title="Payment guard settings"
      subtitle={s ? `Read live at block #${s.block.toLocaleString()}` : 'The rules every agent payment must pass on Monad.'}
      action={<button type="button" onClick={reload} disabled={state.status === 'loading'} className="gx-link gx-focus inline-flex items-center gap-1 rounded text-sm disabled:opacity-50"><RefreshCw className={`h-4 w-4 ${state.status === 'loading' ? 'animate-spin' : ''}`} aria-hidden="true" /> Refresh</button>}
    >
      {state.status === 'loading' && !s && <Loading label="Reading the payment guard…" />}
      {state.status === 'error' && <ErrorLine message={state.message} onRetry={reload} />}
      {s && (
        <dl className="divide-y" style={{ borderColor: 'var(--gx-border)' }}>
          {rows.map(([k, v]) => (
            <div key={k} className="gx-bd flex items-center justify-between gap-3 py-2.5 text-sm">
              <dt className="gx-t2">{k}</dt>
              <dd className="gx-t1 text-right font-semibold">{v}</dd>
            </div>
          ))}
        </dl>
      )}
      <a href={addressUrl(CONTRACTS.policyGuard.address)} target="_blank" rel="noreferrer" className="gx-link mt-4 inline-flex items-center gap-1 text-xs">GuardianPolicyGuard <ExternalLink className="h-3 w-3" aria-hidden="true" /></a>
    </Panel>
  )
}

/* ------------------------------------------------------------------ */

export default function Console() {
  const [theme, toggleTheme] = useTheme()
  return (
    <div className="gx min-h-screen antialiased" data-theme={theme}>
      <Header page="console" theme={theme} toggleTheme={toggleTheme} />
      <main className="mx-auto max-w-6xl px-4 pb-16 pt-10 sm:px-6">
        <p className="gx-accent text-sm font-semibold">Monad testnet · chain 10143</p>
        <h1 className="gx-t1 mt-2 text-3xl font-extrabold tracking-tight sm:text-4xl">Console</h1>
        <p className="gx-t2 mt-2 max-w-2xl text-lg">Your wallet, your agents, and GuardianAI’s live rules on Monad, all in one place.</p>
        <div className="mt-8 space-y-6">
          <YourWallet />
          <Agents />
          <div className="grid grid-cols-1 gap-6 lg:grid-cols-2">
            <CheckAddress />
            <GuardSettings />
          </div>
          <ScamList />
        </div>
      </main>
      <Footer />
    </div>
  )
}
