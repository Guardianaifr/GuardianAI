/* eslint-disable react-refresh/only-export-components */
import { useEffect, useState } from 'react'
import { ShieldCheck, Sun, Moon, ArrowLeft } from 'lucide-react'
import { ConnectButton } from './wallet.jsx'

/* Theme: system preference first, then the visitor's choice (saved per browser). */
function readStoredTheme() {
  try {
    const t = window.localStorage.getItem('gx-theme')
    if (t === 'light' || t === 'dark') return t
  } catch {
    // storage blocked: fall back to system preference
  }
  try {
    return window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light'
  } catch {
    return 'light'
  }
}

export function useTheme() {
  const [theme, setTheme] = useState(readStoredTheme)
  useEffect(() => {
    try { window.localStorage.setItem('gx-theme', theme) } catch { /* ignore */ }
    document.documentElement.style.colorScheme = theme
    document.body.style.background = theme === 'dark' ? '#0b0d14' : '#ffffff'
  }, [theme])
  return [theme, () => setTheme((t) => (t === 'dark' ? 'light' : 'dark'))]
}

const HOME_NAV = [
  { href: '#lab', label: 'Attack Lab' },
  { href: '#gates', label: 'Two gates' },
  { href: '#architecture', label: 'Architecture' },
  { href: '#proof', label: 'Proof' },
  { href: '#developers', label: 'Build' },
  { href: '/mera/', label: 'Passkey' },
]

export function Header({ page, theme, toggleTheme }) {
  const nav = page === 'console'
    ? [{ href: './', label: 'Attack Lab' }, { href: '?view=console', label: 'Console', current: true }]
    : [...HOME_NAV, { href: '?view=console', label: 'Console' }]
  return (
    <header className="gx-bd sticky top-0 z-30 border-b backdrop-blur" style={{ background: 'color-mix(in srgb, var(--gx-bg) 88%, transparent)' }}>
      <div className="mx-auto flex h-16 max-w-6xl items-center justify-between gap-3 px-4 sm:px-6">
        <a href="./" className="gx-focus flex shrink-0 items-center gap-2.5 rounded-lg" aria-label="GuardianAI Explorer home">
          <span className="gx-accent-soft grid h-9 w-9 place-items-center rounded-xl"><ShieldCheck className="h-5 w-5" aria-hidden="true" /></span>
          <span className="gx-t1 hidden text-lg font-bold sm:inline">Guardian<span className="gx-accent">AI</span></span>
        </a>
        <nav className="gx-t2 hidden items-center gap-6 text-sm font-medium lg:flex" aria-label="Sections">
          {nav.map((n) => (
            <a key={n.href} href={n.href} aria-current={n.current ? 'page' : undefined} className={`gx-focus rounded hover:opacity-70 ${n.current ? 'gx-t1 font-semibold' : ''}`}>{n.label}</a>
          ))}
        </nav>
        <div className="flex items-center gap-2">
          {page !== 'console' && <a href="?view=console" className="gx-link gx-focus rounded px-1 text-sm lg:hidden">Console</a>}
          <button
            type="button"
            onClick={toggleTheme}
            className="gx-btn-ghost gx-focus !min-h-[40px] !px-2.5 !py-2"
            aria-label={theme === 'dark' ? 'Switch to light mode' : 'Switch to dark mode'}
          >
            {theme === 'dark' ? <Sun className="h-5 w-5" aria-hidden="true" /> : <Moon className="h-5 w-5" aria-hidden="true" />}
          </button>
          <ConnectButton />
        </div>
      </div>
    </header>
  )
}

export function Footer() {
  return (
    <footer className="gx-bd border-t">
      <div className="gx-muted mx-auto flex max-w-6xl flex-col gap-4 px-4 py-10 text-sm sm:flex-row sm:items-center sm:justify-between sm:px-6">
        <a href="/" className="gx-focus inline-flex items-center gap-1.5 rounded hover:opacity-70">
          <ArrowLeft className="h-4 w-4" aria-hidden="true" /> Back to aiguardian.dev
        </a>
        <p>Runs on Monad testnet. Test tokens only, no real money is used.</p>
      </div>
    </footer>
  )
}
