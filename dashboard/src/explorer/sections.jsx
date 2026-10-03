import { useCallback, useEffect, useState } from 'react'
import {
  Brain, Lock, Inbox, Shield, Bot, Landmark, Database, ExternalLink, RefreshCw, Loader2, CheckCircle2, AlertTriangle,
  Code2, Copy, Check, ArrowRight, Users, Coins, Flag,
} from 'lucide-react'
import { ALL_CONTRACTS, CONTRACTS, REAL_PAYMENT_TX, X402_FEE_TX, TEAM_WALLET, addressUrl, txUrl, checkDeployed, readLiveStats, listPassports } from './chain.js'
import { SPONSORS, REPO_PUBLIC, repoLink, FOUNDER, AUDIENCE, BUSINESS, NEXT } from './siteConfig.js'
import { Section, StatusPill } from './ui.jsx'

/* ------------------------------------------------------------------ */
/* Gate 1 is smart. Gate 2 is stubborn.                                */
/* ------------------------------------------------------------------ */

const GATE_1 = [
  'Flags common prompt-injection phrasing in emails, chats and web pages',
  'Decodes disguised text first: Base64, hex, ROT13, Braille, Morse, look-alike letters',
  'An AI model compares meaning with known attacks to catch some reworded tricks (not yet every language or disguise)',
  'Strips API keys, tokens and personal data from what the AI sends out',
  'Checks a transaction before it’s signed: unlimited approvals, NFT operator grants, and every recipient against the on-chain scam list',
  'Applies each agent’s limits before signing: per-payment and daily caps (1 MON and 5 MON by default), and an optional list of allowed recipients',
]

const GATE_2 = [
  { text: 'Runs a payment only with GuardianAI’s signature for that exact recipient, amount and data', c: CONTRACTS.policyGuard },
  { text: 'Refuses anything GuardianAI scored above the risk limit', c: CONTRACTS.policyGuard },
  { text: 'Requires an active agent ID card; revoke it and the agent stops', c: CONTRACTS.passport },
  { text: 'Each approval works once, tracked per agent', c: CONTRACTS.policyGuard },
  { text: 'Keeps a public list of known scam wallets', c: CONTRACTS.threatFeed },
  { text: 'The owner can pause every agent payment at once', c: CONTRACTS.policyGuard },
]

export function TwoGates() {
  return (
    <Section
      id="gates"
      eyebrow="Why two gates"
      title="Gate 1 is smart. Gate 2 is stubborn."
      intro="An AI firewall understands language, but a clever enough attacker might talk past it. A smart contract can’t be talked to at all, but it can’t read a message either. GuardianAI uses both, so an attack has to beat two very different defences."
      alt
    >
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-2">
        <div className="gx-card p-6 sm:p-8">
          <div className="flex items-center gap-3">
            <span className="gx-accent-soft grid h-11 w-11 place-items-center rounded-xl"><Brain className="h-6 w-6" aria-hidden="true" /></span>
            <div>
              <p className="gx-accent text-xs font-semibold uppercase tracking-wide">Gate 1 · off-chain · milliseconds</p>
              <h3 className="gx-t1 text-xl font-bold">Stops the trick</h3>
            </div>
          </div>
          <p className="gx-t2 mt-4 leading-relaxed">Sits in front of the AI. Every message is checked before the agent reads it, and every transaction before it’s sent.</p>
          <ul className="mt-5 space-y-3">
            {GATE_1.map((t) => (
              <li key={t} className="flex gap-3"><CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0" style={{ color: 'var(--gx-good-text)' }} aria-hidden="true" /><span className="gx-t1">{t}</span></li>
            ))}
          </ul>
          <p className="gx-muted mt-5 font-mono text-xs">guardian/runtime/interceptor.py · guardian/guardrails/ · guardian/web3sec/</p>
        </div>
        <div className="gx-card p-6 sm:p-8">
          <div className="flex items-center gap-3">
            <span className="gx-accent-soft grid h-11 w-11 place-items-center rounded-xl"><Lock className="h-6 w-6" aria-hidden="true" /></span>
            <div>
              <p className="gx-accent text-xs font-semibold uppercase tracking-wide">Gate 2 · on Monad · can’t be argued with</p>
              <h3 className="gx-t1 text-xl font-bold">Stops the money</h3>
            </div>
          </div>
          <p className="gx-t2 mt-4 leading-relaxed">Lives in smart contracts. Even an agent that was completely fooled, or taken over, can’t move funds without passing these rules.</p>
          <ul className="mt-5 space-y-3">
            {GATE_2.map((g) => (
              <li key={g.text} className="flex gap-3">
                <CheckCircle2 className="mt-0.5 h-5 w-5 shrink-0" style={{ color: 'var(--gx-good-text)' }} aria-hidden="true" />
                <span className="gx-t1">
                  {g.text}{' '}
                  <a href={addressUrl(g.c.address)} target="_blank" rel="noreferrer" className="gx-link whitespace-nowrap text-xs">{g.c.name} ↗</a>
                </span>
              </li>
            ))}
          </ul>
          <p className="gx-muted mt-5 font-mono text-xs">contracts/contracts/GuardianPolicyGuard.sol · GuardianPassportSBT.sol · GuardianThreatFeedRegistry.sol</p>
        </div>
      </div>
    </Section>
  )
}

/* ------------------------------------------------------------------ */
/* Architecture map with Monad features and sponsors in place          */
/* ------------------------------------------------------------------ */

const STOPS = [
  { key: 'in', icon: Inbox, title: 'Untrusted input', sub: 'Emails, chats, web pages, other agents' },
  { key: 'g1', icon: Shield, title: 'Gate 1', sub: 'Off-chain firewall' },
  { key: 'agent', icon: Bot, title: 'AI agent', sub: 'ElizaOS or any viem wallet', tags: [
    { sponsor: 'mera', label: 'Mera · passkey ID + sealed memory (local)' },
    { monad: 'ERC-8004 identity registry (testnet stand-in)' },
  ] },
  { key: 'g2', icon: Landmark, title: 'Gate 2', sub: 'PolicyGuard on Monad', tags: [
    { monad: 'Parallel-safe approvals: usedNonces[agentId][nonce]' },
    { monad: 'P-256 passkey verify helper via precompile 0x0100 (callable, not yet in the payment path)' },
  ] },
  { key: 'data', icon: Database, title: 'On-chain record', sub: 'Every decision is public', tags: [
    { sponsor: 'envio', label: 'Envio · indexes gate events (local)' },
    { sponsor: 'chainlink', label: 'Chainlink CRE · threat oracle (simulated)' },
  ] },
]

export function Architecture() {
  const [open, setOpen] = useState('mera')
  const sponsor = SPONSORS.find((s) => s.key === open)
  const link = sponsor ? repoLink(sponsor.path) : null
  return (
    <Section
      id="architecture"
      eyebrow="Architecture"
      title="Where everything fits"
      intro="One path from untrusted input to money. Monad features sit where they do the work, and each sponsor integration sits where it plugs in. Tap a sponsor to see what we built."
    >
      <ol className="grid grid-cols-1 gap-3 md:grid-cols-5" aria-label="GuardianAI architecture">
        {STOPS.map((s, i) => {
          const IconC = s.icon
          return (
            <li key={s.key} className="relative">
              <div className="gx-card h-full p-4">
                <div className="flex items-center gap-2">
                  <span className="gx-accent-soft grid h-9 w-9 place-items-center rounded-lg"><IconC className="h-5 w-5" aria-hidden="true" /></span>
                  <span className="gx-muted text-xs font-semibold tabular-nums">{i + 1}/{STOPS.length}</span>
                </div>
                <p className="gx-t1 mt-3 font-bold">{s.title}</p>
                <p className="gx-muted text-sm">{s.sub}</p>
                {s.tags && (
                  <div className="mt-3 flex flex-col gap-1.5">
                    {s.tags.map((t) => t.sponsor ? (
                      <button
                        key={t.label}
                        type="button"
                        onClick={() => setOpen(t.sponsor)}
                        aria-pressed={open === t.sponsor}
                        className="gx-focus rounded-lg px-2.5 py-1.5 text-left text-xs font-semibold transition"
                        style={{
                          background: open === t.sponsor ? 'var(--gx-accent)' : 'var(--gx-accent-soft)',
                          color: open === t.sponsor ? 'var(--gx-on-accent)' : 'var(--gx-accent-text)',
                        }}
                      >
                        {t.label}
                      </button>
                    ) : (
                      <span key={t.monad} className="gx-surface-2 gx-t2 rounded-lg px-2.5 py-1.5 text-xs">
                        <span className="font-semibold">Monad · </span>{t.monad}
                      </span>
                    ))}
                  </div>
                )}
              </div>
              {i < STOPS.length - 1 && (
                <ArrowRight className="gx-muted absolute -right-3 top-8 z-10 hidden h-5 w-5 md:block" aria-hidden="true" />
              )}
            </li>
          )
        })}
      </ol>

      {sponsor && (
        <div className="gx-card mt-5 grid grid-cols-1 gap-5 p-5 sm:p-6 lg:grid-cols-[1.4fr_1fr]" aria-live="polite">
          <div>
            <p className="gx-accent text-sm font-semibold">{sponsor.bounty}</p>
            <h3 className="gx-t1 mt-1 text-xl font-bold">{sponsor.name}: {sponsor.title}</h3>
            <p className="gx-t2 mt-2 leading-relaxed">{sponsor.body}</p>
            <div className="mt-4"><StatusPill kind={sponsor.statusKind}>{sponsor.status}</StatusPill></div>
          </div>
          <div className="min-w-0">
            <p className="gx-muted text-xs font-semibold">Run it yourself</p>
            <div className="gx-code mt-1.5 overflow-x-auto rounded-lg px-3 py-2 font-mono text-xs">{sponsor.howToRun}</div>
            <p className="gx-muted mt-2 font-mono text-xs">{sponsor.path}/</p>
            {link && (
              <a href={link} target="_blank" rel="noreferrer" className="gx-link mt-2 inline-flex items-center gap-1 text-sm">View the code <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" /></a>
            )}
          </div>
        </div>
      )}
    </Section>
  )
}

/* ------------------------------------------------------------------ */
/* Proof ledger: live values + every contract verified                  */
/* ------------------------------------------------------------------ */

const fetchAll = () => Promise.all([readLiveStats(), checkDeployed(ALL_CONTRACTS.map((c) => c.address))])

export function ProofLedger() {
  const [state, setState] = useState({ status: 'loading' })

  const load = useCallback(async () => {
    setState((s) => ({ ...s, status: 'loading' }))
    try {
      const [stats, sizes] = await fetchAll()
      setState({ status: 'done', stats, sizes })
    } catch (err) {
      setState({ status: 'error', message: err?.message || 'Unknown error' })
    }
  }, [])

  useEffect(() => {
    let alive = true
    fetchAll()
      .then(([stats, sizes]) => { if (alive) setState({ status: 'done', stats, sizes }) })
      .catch((err) => { if (alive) setState({ status: 'error', message: err?.message || 'Unknown error' }) })
    return () => { alive = false }
  }, [])

  const s = state.stats
  const live = {
    [CONTRACTS.policyGuard.address]: s && `${s.paused ? 'PAUSED' : 'active'} · risk limit ${s.maxRisk}/100`,
    [CONTRACTS.passport.address]: s && `${s.activePassports} active agent ID ${s.activePassports === 1 ? 'card' : 'cards'}`,
    [CONTRACTS.threatFeed.address]: s && `${s.scamAddresses} scam ${s.scamAddresses === 1 ? 'wallet' : 'wallets'} listed`,
  }
  const liveCount = state.sizes ? Object.values(state.sizes).filter((n) => n > 0).length : 0

  return (
    <Section
      id="proof"
      eyebrow="Proof"
      title="Don’t trust us. Check the chain."
      intro="This ledger is read from Monad testnet each time the page loads: every contract’s code, plus the live settings the demo above depends on. Each row links to MonadScan."
      alt
    >
      <div className="gx-card overflow-hidden">
        <div className="gx-bd flex flex-wrap items-center justify-between gap-2 border-b px-4 py-3 sm:px-5">
          <p className="gx-t1 font-mono text-sm" aria-live="polite">
            {state.status === 'loading' && <span className="inline-flex items-center gap-2"><Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> reading Monad testnet…</span>}
            {state.status === 'done' && <>Monad testnet · chain 10143 · block #{s.block.toLocaleString()} · <span style={{ color: 'var(--gx-good-text)' }}>{liveCount}/{ALL_CONTRACTS.length} contracts live</span></>}
            {state.status === 'error' && <span className="gx-bad-t">Couldn’t reach Monad testnet: {state.message}</span>}
          </p>
          <button type="button" onClick={load} disabled={state.status === 'loading'} className="gx-link gx-focus inline-flex items-center gap-1.5 rounded text-sm disabled:opacity-50">
            <RefreshCw className={`h-4 w-4 ${state.status === 'loading' ? 'animate-spin' : ''}`} aria-hidden="true" /> Re-check
          </button>
        </div>
        <ul>
          {ALL_CONTRACTS.map((c) => {
            const size = state.sizes?.[c.address]
            const ok = size > 0
            return (
              <li key={c.address} className="gx-bd grid grid-cols-[24px_1fr] gap-x-3 gap-y-1 border-b px-4 py-3.5 last:border-b-0 sm:grid-cols-[24px_minmax(0,1.2fr)_minmax(0,1fr)_auto] sm:items-center sm:px-5">
                <span className="pt-0.5 sm:pt-0">
                  {state.status === 'loading' && <Loader2 className="gx-muted h-5 w-5 animate-spin" aria-label="Checking" />}
                  {state.status === 'done' && ok && <CheckCircle2 className="h-5 w-5" style={{ color: 'var(--gx-good-text)' }} aria-label="Live" />}
                  {state.status === 'done' && !ok && <AlertTriangle className="h-5 w-5" style={{ color: 'var(--gx-bad-text)' }} aria-label="No code found" />}
                </span>
                <span className="min-w-0">
                  <span className="gx-t1 block font-semibold">{c.name}</span>
                  <span className="gx-t2 block text-sm">{c.role}</span>
                </span>
                <span className="gx-t1 col-start-2 font-mono text-xs sm:col-start-auto">
                  {state.status === 'done' ? (live[c.address] || (ok ? `deployed · ${size.toLocaleString()} bytes` : 'no code at this address')) : ''}
                </span>
                <a href={addressUrl(c.address)} target="_blank" rel="noreferrer" className="gx-link col-start-2 inline-flex items-center gap-1 font-mono text-xs sm:col-start-auto">
                  {c.address.slice(0, 8)}…{c.address.slice(-6)} <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
                </a>
              </li>
            )
          })}
        </ul>
      </div>
      <div className="gx-card mt-4 flex flex-wrap items-center justify-between gap-3 p-4 sm:px-5">
        <span className="min-w-0">
          <span className="gx-t1 block font-semibold">And one that got through</span>
          <span className="gx-t2 block text-sm">A real 1 USDC payment from the agent’s Privy wallet that passed every PolicyGuard check on Monad testnet (block #{REAL_PAYMENT_TX.block.toLocaleString()}).</span>
        </span>
        <a href={txUrl(REAL_PAYMENT_TX.hash)} target="_blank" rel="noreferrer" className="gx-link inline-flex items-center gap-1 font-mono text-xs">
          {REAL_PAYMENT_TX.hash.slice(0, 10)}…{REAL_PAYMENT_TX.hash.slice(-6)} <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
        </a>
      </div>
      <div className="gx-card mt-4 flex flex-wrap items-center justify-between gap-3 p-4 sm:px-5">
        <span className="min-w-0">
          <span className="gx-t1 block font-semibold">And one that paid for its approval</span>
          <span className="gx-t2 block text-sm">An agent paid $0.01 in USDC through x402 for one approved check, settled on Monad testnet (block #{X402_FEE_TX.block.toLocaleString()}). Blocked actions are not charged.</span>
        </span>
        <a href={txUrl(X402_FEE_TX.hash)} target="_blank" rel="noreferrer" className="gx-link inline-flex items-center gap-1 font-mono text-xs">
          {X402_FEE_TX.hash.slice(0, 10)}…{X402_FEE_TX.hash.slice(-6)} <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" />
        </a>
      </div>
      <p className="gx-muted mt-4 text-sm">
        Benchmarks and test results are on the <a href="/proof" className="gx-link">proof page</a>, each linked to the file it came from.
      </p>
    </Section>
  )
}

/* ------------------------------------------------------------------ */
/* Developers                                                          */
/* ------------------------------------------------------------------ */

const SNIPPETS = [
  {
    key: 'ethers',
    tab: 'Any app · no install',
    lang: 'JavaScript (ethers v6)',
    note: 'Works today. Reads GuardianAI’s public rules straight from Monad, no GuardianAI package or API key.',
    code: `import { JsonRpcProvider, Contract } from 'ethers'

const monad = new JsonRpcProvider('https://testnet-rpc.monad.xyz')
const scamList = new Contract('${CONTRACTS.threatFeed.address}',
  ['function isMalicious(address) view returns (bool, string)'], monad)
const passports = new Contract('${CONTRACTS.passport.address}',
  ['function isPassportActive(bytes32) view returns (bool)'], monad)

// Before your agent pays anyone
const [flagged, reason] = await scamList.isMalicious(recipient)
if (flagged) throw new Error(\`Blocked by GuardianAI: \${reason}\`)

// Before your agent trusts another agent
const trusted = await passports.isPassportActive(agentId)`,
  },
  {
    key: 'cast',
    tab: 'Terminal',
    lang: 'Shell (Foundry cast)',
    note: 'Ask the scam list about a wallet from your terminal. This one is listed, so it answers true and the reason.',
    code: `cast call ${CONTRACTS.threatFeed.address} \\
  "isMalicious(address)(bool,string)" \\
  0x535eA8d8eABA5D072f7DfCef98C32d8D1d8E1CBd \\
  --rpc-url https://testnet-rpc.monad.xyz`,
  },
  {
    key: 'middleware',
    tab: 'Full guard · middleware',
    lang: 'TypeScript',
    note: 'Routes every payment through PolicyGuard with a GuardianAI-signed approval. In the repo at packages/guardian-middleware, not on npm yet.',
    code: `import { withGuardianSecurity } from '@guardianai/middleware'

// Every sendTransaction is checked by GuardianAI before it is signed
const safeWallet = withGuardianSecurity(walletClient, {
  agentId: 'my-trading-agent',
  policyGuardAddress: '${CONTRACTS.policyGuard.address}',
})`,
  },
]

export function Developers() {
  const [active, setActive] = useState(SNIPPETS[0].key)
  const [copied, setCopied] = useState(false)
  const snip = SNIPPETS.find((x) => x.key === active)
  const copy = async () => {
    try {
      await navigator.clipboard.writeText(snip.code)
      setCopied(true)
      setTimeout(() => setCopied(false), 1800)
    } catch {
      setCopied(false)
    }
  }
  const links = [
    { href: '/docs', title: 'Docs', sub: 'API, SDK and setup' },
    ...(REPO_PUBLIC ? [{ href: repoLink(), title: 'Source on GitHub', sub: 'Contracts, firewall, Mera, Envio, Chainlink', external: true }] : []),
    { href: '?view=console', title: 'Console', sub: 'Connect a wallet, see your agents and the live registry' },
  ]
  return (
    <Section
      id="developers"
      eyebrow="For builders"
      title="Build on GuardianAI’s rules"
      intro="The scam list and agent ID cards are public contracts on Monad, so any wallet, agent or dApp can check them. Start with a read call; add the middleware when you want every payment enforced on-chain."
    >
      <div className="grid grid-cols-1 gap-6 lg:grid-cols-[1.4fr_1fr]">
        <div className="min-w-0">
          <div role="tablist" aria-label="Integration options" className="mb-3 flex flex-wrap gap-2">
            {SNIPPETS.map((x) => (
              <button
                key={x.key}
                type="button"
                role="tab"
                aria-selected={active === x.key}
                onClick={() => { setActive(x.key); setCopied(false) }}
                className="gx-focus rounded-lg px-3 py-1.5 text-sm font-semibold transition"
                style={{
                  background: active === x.key ? 'var(--gx-accent)' : 'var(--gx-accent-soft)',
                  color: active === x.key ? 'var(--gx-on-accent)' : 'var(--gx-accent-text)',
                }}
              >
                {x.tab}
              </button>
            ))}
          </div>
          <div className="gx-code min-w-0 overflow-hidden rounded-2xl" role="tabpanel">
            <div className="flex items-center justify-between border-b border-white/10 px-4 py-2.5">
              <span className="inline-flex items-center gap-2 text-sm opacity-70"><Code2 className="h-4 w-4" aria-hidden="true" /> {snip.lang}</span>
              <button type="button" onClick={copy} className="gx-focus inline-flex items-center gap-1.5 rounded text-sm font-medium opacity-80 hover:opacity-100">
                {copied ? <Check className="h-4 w-4" aria-hidden="true" /> : <Copy className="h-4 w-4" aria-hidden="true" />}
                {copied ? 'Copied' : 'Copy'}
              </button>
            </div>
            <pre className="overflow-x-auto p-4 text-sm leading-relaxed"><code>{snip.code}</code></pre>
          </div>
          <p className="gx-t2 mt-3 text-sm">{snip.note}</p>
        </div>
        <div className="space-y-3">
          {links.map((l) => (
            <a key={l.title} href={l.href} target={l.external ? '_blank' : undefined} rel={l.external ? 'noreferrer' : undefined} className="gx-card gx-focus flex items-center justify-between p-5 transition hover:opacity-90">
              <span>
                <span className="gx-t1 block font-semibold">{l.title}</span>
                <span className="gx-muted block text-sm">{l.sub}</span>
              </span>
              <ArrowRight className="gx-muted h-5 w-5" aria-hidden="true" />
            </a>
          ))}
        </div>
      </div>
    </Section>
  )
}

/* ------------------------------------------------------------------ */
/* Who it's for, how it makes money, what's next                       */
/* ------------------------------------------------------------------ */

const sameAddr = (a, b) => a && b && a.toLowerCase() === b.toLowerCase()

function Adoption() {
  const [state, setState] = useState({ status: 'loading' })
  useEffect(() => {
    let alive = true
    listPassports()
      .then((list) => { if (alive) setState({ status: 'done', total: list.length, external: list.filter((p) => !sameAddr(p.owner, TEAM_WALLET)) }) })
      .catch(() => { if (alive) setState({ status: 'error' }) })
    return () => { alive = false }
  }, [])
  if (state.status !== 'done') return null
  const n = state.external.length
  return (
    <div className="gx-card mt-5 flex flex-wrap items-center justify-between gap-3 p-5 sm:px-6">
      <span className="min-w-0">
        <span className="gx-t1 block font-semibold">
          {n > 0 ? `${n} agent${n === 1 ? '' : 's'} from outside teams registered on GuardianAI` : 'Building an agent on Monad? Be one of the first teams on GuardianAI.'}
        </span>
        <span className="gx-t2 block text-sm">
          Read live from GuardianPassportSBT: {state.total} agent ID {state.total === 1 ? 'card' : 'cards'} in total, {n} held by wallets outside the GuardianAI team.
        </span>
      </span>
      {FOUNDER.url && (
        <a href={FOUNDER.url} target="_blank" rel="noreferrer" className="gx-btn gx-focus">
          {n > 0 ? 'Register your agent' : 'Get an agent ID card'} <ArrowRight className="h-4 w-4" aria-hidden="true" />
        </a>
      )}
    </div>
  )
}

export function Readiness() {
  const who = FOUNDER.name ? `${FOUNDER.name}, ${FOUNDER.role.toLowerCase()}` : `a ${FOUNDER.role.toLowerCase()}`
  return (
    <Section
      id="readiness"
      eyebrow="Who it’s for"
      title="A safety layer other agents plug into"
      intro="GuardianAI isn’t an app on its own. It’s the firewall and the on-chain rules that agent builders, wallets and marketplaces put in front of their money."
      alt
    >
      <div className="grid grid-cols-1 gap-5 lg:grid-cols-3">
        <div className="gx-card p-6 lg:col-span-1">
          <div className="flex items-center gap-3">
            <span className="gx-accent-soft grid h-10 w-10 place-items-center rounded-xl"><Users className="h-5 w-5" aria-hidden="true" /></span>
            <h3 className="gx-t1 text-lg font-bold">Who uses it</h3>
          </div>
          <ul className="mt-4 space-y-4">
            {AUDIENCE.map((a) => (
              <li key={a.title}>
                <p className="gx-t1 font-semibold">{a.title}</p>
                <p className="gx-t2 mt-1 text-sm leading-relaxed">{a.body}</p>
              </li>
            ))}
          </ul>
        </div>
        <div className="gx-card p-6">
          <div className="flex items-center gap-3">
            <span className="gx-accent-soft grid h-10 w-10 place-items-center rounded-xl"><Coins className="h-5 w-5" aria-hidden="true" /></span>
            <h3 className="gx-t1 text-lg font-bold">How it makes money</h3>
          </div>
          <ul className="mt-4 space-y-3">
            {BUSINESS.map((b) => <li key={b} className="gx-t2 text-sm leading-relaxed">{b}</li>)}
          </ul>
        </div>
        <div className="gx-card p-6">
          <div className="flex items-center gap-3">
            <span className="gx-accent-soft grid h-10 w-10 place-items-center rounded-xl"><Flag className="h-5 w-5" aria-hidden="true" /></span>
            <h3 className="gx-t1 text-lg font-bold">After the hackathon</h3>
          </div>
          <ol className="mt-4 space-y-2.5">
            {NEXT.map((x, i) => (
              <li key={x} className="flex gap-3 text-sm">
                <span className="gx-accent-soft grid h-6 w-6 shrink-0 place-items-center rounded-full text-xs font-bold">{i + 1}</span>
                <span className="gx-t1 leading-relaxed">{x}</span>
              </li>
            ))}
          </ol>
        </div>
      </div>
      <Adoption />
      {(who || FOUNDER.handle) && (
        <p className="gx-muted mt-5 text-sm">
          Built by {who}{FOUNDER.handle && <> · <a href={FOUNDER.url} target="_blank" rel="noreferrer" className="gx-link">{FOUNDER.handle}</a></>}
        </p>
      )}
    </Section>
  )
}
