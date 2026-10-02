import { useState } from 'react'
import { ShieldCheck, ShieldX, ChevronDown, ExternalLink, Loader2, RefreshCw } from 'lucide-react'
import { addressUrl } from './chain.js'

export function Section({ id, step, eyebrow, title, intro, alt = false, children }) {
  return (
    <section id={id} className={`scroll-mt-20 py-16 sm:py-24 ${alt ? 'gx-bg-alt' : ''}`}>
      <div className="mx-auto max-w-6xl px-4 sm:px-6">
        <div className="max-w-3xl">
          <div className="mb-3 flex items-center gap-3">
            {step && (
              <span className="grid h-7 w-7 place-items-center rounded-full text-sm font-bold" style={{ background: 'var(--gx-accent)', color: 'var(--gx-on-accent)' }}>
                {step}
              </span>
            )}
            <span className="gx-accent text-sm font-semibold uppercase tracking-wide">{eyebrow}</span>
          </div>
          <h2 className="gx-t1 text-2xl font-bold tracking-tight sm:text-4xl">{title}</h2>
          {intro && <p className="gx-t2 mt-4 text-base leading-relaxed sm:text-lg">{intro}</p>}
        </div>
        <div className="mt-10">{children}</div>
      </div>
    </section>
  )
}

export function Card({ className = '', children }) {
  return <div className={`gx-card p-5 sm:p-6 ${className}`}>{children}</div>
}

export function IconBadge(props) {
  const IconComponent = props.icon
  const tone = props.tone || 'accent'
  const cls = tone === 'bad' ? 'gx-bad-icon' : tone === 'good' ? 'gx-good-icon' : 'gx-accent-soft'
  return (
    <span className={`grid h-10 w-10 shrink-0 place-items-center rounded-xl ${cls}`}>
      <IconComponent className="h-5 w-5" aria-hidden="true" />
    </span>
  )
}

export function Verdict({ kind, title, children }) {
  const blocked = kind === 'blocked'
  const Icon = blocked ? ShieldX : ShieldCheck
  return (
    <div className={`rounded-2xl p-5 animate-[fadeIn_.25s_ease-out] ${blocked ? 'gx-bad' : 'gx-good'}`}>
      <div className="flex items-center gap-3">
        <span className={`grid h-9 w-9 shrink-0 place-items-center rounded-lg ${blocked ? 'gx-bad-icon' : 'gx-good-icon'}`}>
          <Icon className="h-5 w-5" aria-hidden="true" />
        </span>
        <p className={`text-lg font-bold leading-snug ${blocked ? 'gx-bad-t' : 'gx-good-t'}`}>{title}</p>
      </div>
      <div className="gx-t1 mt-3 space-y-2 leading-relaxed">{children}</div>
    </div>
  )
}

export function Proof({ children, label = 'technical proof' }) {
  const [open, setOpen] = useState(false)
  return (
    <div className="mt-3">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="gx-link gx-focus inline-flex items-center gap-1.5 rounded text-sm"
      >
        <ChevronDown className={`h-4 w-4 transition-transform ${open ? 'rotate-180' : ''}`} aria-hidden="true" />
        {open ? `Hide ${label}` : `Show ${label}`}
      </button>
      {open && (
        <dl className="gx-surface-2 gx-bd mt-3 grid gap-x-4 gap-y-2 rounded-xl border p-4 text-sm sm:grid-cols-[140px_1fr]">
          {children}
        </dl>
      )}
    </div>
  )
}

export function ProofRow({ label, children }) {
  return (
    <>
      <dt className="gx-muted">{label}</dt>
      <dd className="gx-t1 break-all font-mono">{children}</dd>
    </>
  )
}

export function ContractLink({ contract, short = true }) {
  return (
    <a href={addressUrl(contract.address)} target="_blank" rel="noreferrer" className="gx-link inline-flex items-center gap-1 break-all">
      {contract.name}{short ? ` (${contract.address.slice(0, 6)}…${contract.address.slice(-4)})` : ''}
      <ExternalLink className="h-3.5 w-3.5 shrink-0" aria-hidden="true" />
    </a>
  )
}

export function Button({ children, loading, className = '', type = 'button', ...props }) {
  return (
    <button type={type} {...props} disabled={loading || props.disabled} className={`gx-btn gx-focus ${className}`}>
      {loading && <Loader2 className="h-5 w-5 animate-spin" aria-hidden="true" />}
      {children}
    </button>
  )
}

export function NetworkError({ message, onRetry }) {
  return (
    <div role="alert" className="gx-warn rounded-xl p-4">
      <p className="font-semibold">We couldn’t reach the Monad testnet.</p>
      <p className="mt-1 text-sm opacity-90">{message}</p>
      {onRetry && (
        <button type="button" onClick={onRetry} className="gx-focus mt-3 inline-flex items-center gap-1.5 rounded text-sm font-semibold underline-offset-2 hover:underline">
          <RefreshCw className="h-4 w-4" aria-hidden="true" /> Try again
        </button>
      )}
    </div>
  )
}

export function StatusPill({ kind, children }) {
  const cls = kind === 'live' ? 'gx-good gx-good-t' : kind === 'simulated' ? 'gx-warn' : 'gx-accent-soft'
  return <span className={`inline-flex items-center rounded-full px-2.5 py-1 text-xs font-semibold ${cls}`}>{children}</span>
}
