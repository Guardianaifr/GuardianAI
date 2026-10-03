import { useEffect, useState } from 'react'
import { ShieldX, CheckCircle2, Coins, ExternalLink, Loader2 } from 'lucide-react'
import { REAL_PAYMENT_TX, PRIVY_AGENT_WALLET, X402_FEE_TX, CONTRACTS, addressUrl, txUrl, checkAddress } from './chain.js'
import { Section, IconBadge } from './ui.jsx'

const SCAM_WALLET = '0x535eA8d8eABA5D072f7DfCef98C32d8D1d8E1CBd'
const short = (h) => `${h.slice(0, 10)}…${h.slice(-6)}`

function ProofLink({ href, children }) {
  return (
    <a href={href} target="_blank" rel="noreferrer" className="gx-link inline-flex items-center gap-1 font-mono text-xs break-all">
      {children} <ExternalLink className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
    </a>
  )
}

/** Live read of the scam list, so step 1's proof is checked on Monad when the page loads. */
function useScamCheck() {
  const [s, setS] = useState({ status: 'loading' })
  useEffect(() => {
    let alive = true
    checkAddress(SCAM_WALLET)
      .then((r) => alive && setS({ status: 'done', r }))
      .catch((e) => alive && setS({ status: 'error', message: e?.message || 'read failed' }))
    return () => { alive = false }
  }, [])
  return s
}

export function ThreeSteps() {
  const scam = useScamCheck()
  const steps = [
    {
      icon: ShieldX, tone: 'bad', label: 'Blocked',
      title: 'A polite invoice to a known drainer',
      body: 'The agent is asked to pay a wallet on GuardianAI’s scam list. GuardianAI checks every recipient against the list on Monad and refuses to sign, so no payment is ever sent.',
      proof: (
        <>
          <span className="gx-muted block text-xs">Live check on Monad, right now:</span>
          {scam.status === 'loading' && <span className="gx-t2 inline-flex items-center gap-1 text-xs"><Loader2 className="h-3.5 w-3.5 animate-spin" aria-hidden="true" /> reading the scam list…</span>}
          {scam.status === 'error' && <span className="gx-t2 text-xs">Couldn’t read Monad just now. The list is public, check it yourself: <ProofLink href={addressUrl(CONTRACTS.threatFeed.address)}>scam list contract</ProofLink></span>}
          {scam.status === 'done' && (
            <span className="gx-t2 block text-xs">
              <code className="font-mono">isMalicious({short(SCAM_WALLET)})</code> → <b>{String(scam.r.malicious)}</b>
              {scam.r.reason && <>, “{scam.r.reason}”</>} · block #{scam.r.block.toLocaleString()}
            </span>
          )}
          <ProofLink href={addressUrl(CONTRACTS.threatFeed.address)}>{short(CONTRACTS.threatFeed.address)} (scam list)</ProofLink>
        </>
      ),
    },
    {
      icon: CheckCircle2, tone: 'good', label: 'Approved',
      title: 'A normal payment goes through',
      body: 'The agent pays a vendor 1 USDC. GuardianAI approves that exact payment, the agent’s Privy wallet signs it (Privy’s policy only lets this wallet sign calls to PolicyGuard), and PolicyGuard checks the approval and the agent’s ID card before the USDC moves.',
      proof: (
        <>
          <span className="gx-muted block text-xs">1 USDC paid by the Privy wallet {short(PRIVY_AGENT_WALLET)} · block #{REAL_PAYMENT_TX.block.toLocaleString()}</span>
          <ProofLink href={txUrl(REAL_PAYMENT_TX.hash)}>{short(REAL_PAYMENT_TX.hash)}</ProofLink>
        </>
      ),
    },
    {
      icon: Coins, tone: 'accent', label: 'Paid',
      title: 'The agent pays for its approval',
      body: 'With x402, the agent pays $0.01 in USDC for the approval from its Privy wallet, with no account or API key. Only approvals are charged: the blocked scam payment cost nothing.',
      proof: (
        <>
          <span className="gx-muted block text-xs">USDC settlement via x402 · block #{X402_FEE_TX.block.toLocaleString()}</span>
          <ProofLink href={txUrl(X402_FEE_TX.hash)}>{short(X402_FEE_TX.hash)}</ProofLink>
        </>
      ),
    },
  ]

  return (
    <Section
      id="steps"
      eyebrow="Three real outcomes"
      title="Blocked, approved, paid."
      intro="What GuardianAI does with an agent’s payment, shown with real data from Monad testnet. Every link opens the public record."
    >
      <ol className="grid gap-4 md:grid-cols-3">
        {steps.map((s, i) => (
          <li key={s.label} className="gx-card flex min-w-0 flex-col p-5 sm:p-6">
            <div className="flex items-center gap-3">
              <IconBadge icon={s.icon} tone={s.tone} />
              <span className="gx-muted text-xs font-semibold uppercase tracking-wide">Step {i + 1} · {s.label}</span>
            </div>
            <h3 className="gx-t1 mt-4 text-lg font-bold">{s.title}</h3>
            <p className="gx-t2 mt-2 text-sm leading-relaxed">{s.body}</p>
            <div className="mt-auto flex flex-col gap-1.5 pt-4">{s.proof}</div>
          </li>
        ))}
      </ol>
    </Section>
  )
}
