import { useEffect } from 'react'
import { Play } from 'lucide-react'
import './theme.css'
import { AttackLab } from './demos.jsx'
import { TwoGates, Architecture, ProofLedger, Developers, Readiness } from './sections.jsx'
import { VIDEO_URL } from './siteConfig.js'
import { Header, Footer, useTheme } from './layout.jsx'

function LabHero() {
  return (
    <section id="lab" className="relative scroll-mt-16 overflow-hidden">
      <div aria-hidden="true" className="pointer-events-none absolute -top-40 left-1/2 h-96 w-[56rem] max-w-full -translate-x-1/2 rounded-full blur-3xl" style={{ background: 'var(--gx-glow)' }} />
      <div className="relative mx-auto max-w-6xl px-4 pb-16 pt-10 sm:px-6 sm:pt-14">
        <div className="max-w-3xl">
          <p className="gx-accent text-sm font-semibold">Monad Metropolis · Track 04: Trust, Identity &amp; AI Infrastructure</p>
          <h1 className="gx-t1 mt-3 text-4xl font-extrabold leading-[1.05] tracking-tight sm:text-5xl lg:text-6xl">
            Try to rob an AI agent.
          </h1>
          <p className="gx-t2 mt-4 text-lg leading-relaxed sm:text-xl">
            This agent holds a wallet. GuardianAI guards it twice: once before the AI reads anything, and once on
            Monad before any money moves. Pick an attack and launch it. Every check below is real, and no wallet is needed.
          </p>
          {VIDEO_URL && (
            <a href={VIDEO_URL} target="_blank" rel="noreferrer" className="gx-link mt-4 inline-flex items-center gap-1.5">
              <Play className="h-4 w-4" aria-hidden="true" /> Or watch the 3-minute demo
            </a>
          )}
        </div>
        <div className="mt-8">
          <AttackLab />
        </div>
      </div>
    </section>
  )
}

export default function SimpleExplorer() {
  const [theme, toggleTheme] = useTheme()

  // Old links pointed at #home, #dashboard, #policy, #agents, #logs (and the first redesign's ids).
  useEffect(() => {
    const map = {
      home: null, dashboard: 'proof', logs: 'proof', agents: 'architecture', policy: 'gates',
      demo: 'lab', 'demo-chain': 'lab', how: 'gates', monad: 'architecture', sponsors: 'architecture', contracts: 'proof', live: 'proof',
    }
    const h = window.location.hash.replace('#', '').toLowerCase()
    if (h in map) {
      const target = map[h]
      history.replaceState(null, '', target ? `#${target}` : window.location.pathname + window.location.search)
      if (target) requestAnimationFrame(() => document.getElementById(target)?.scrollIntoView())
    }
  }, [])

  return (
    <div className="gx min-h-screen antialiased" data-theme={theme}>
      <a href="#lab" className="sr-only focus:not-sr-only focus:fixed focus:left-4 focus:top-4 focus:z-50 focus:rounded-lg focus:bg-white focus:px-4 focus:py-2 focus:text-black">
        Skip to the Attack Lab
      </a>
      <Header page="home" theme={theme} toggleTheme={toggleTheme} />
      <main>
        <LabHero />
        <TwoGates />
        <Architecture />
        <ProofLedger />
        <Developers />
        <Readiness />
      </main>
      <Footer />
    </div>
  )
}
