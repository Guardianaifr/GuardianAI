/**
 * wallet.jsx: connect any browser wallet (MetaMask, Rabby, OKX, Coinbase, …) and
 * put it on Monad testnet. Uses the EIP-6963 wallet discovery standard, falling
 * back to window.ethereum. No third-party app ID or backend needed.
 *
 * Read-only by design: we only ask for the address and the network. Nothing here
 * asks the user to sign a message or send a transaction.
 */
/* eslint-disable react-refresh/only-export-components */
import { createContext, useCallback, useContext, useEffect, useRef, useState } from 'react'
import { Wallet as WalletIcon, ChevronDown, Copy, Check, ExternalLink, LogOut, LayoutDashboard, AlertTriangle, Loader2 } from 'lucide-react'
import { addressUrl } from './chain.js'

export const MONAD_TESTNET = {
  chainId: '0x279f', // 10143
  chainName: 'Monad Testnet',
  nativeCurrency: { name: 'Monad', symbol: 'MON', decimals: 18 },
  rpcUrls: ['https://testnet-rpc.monad.xyz'],
  blockExplorerUrls: ['https://testnet.monadscan.com'],
}

const STORAGE_KEY = 'gx-wallet'
const WalletContext = createContext(null)

const short = (a) => (a ? `${a.slice(0, 6)}…${a.slice(-4)}` : '')

function friendlyError(err) {
  if (err?.code === 4001) return 'You cancelled the request in your wallet.'
  if (err?.code === -32002) return 'Your wallet already has a request open. Check the wallet window.'
  return err?.message || 'Something went wrong with the wallet.'
}

function useWalletDiscovery() {
  const [wallets, setWallets] = useState([])
  useEffect(() => {
    const found = new Map()
    const onAnnounce = (e) => {
      const { info, provider } = e.detail || {}
      if (!info?.uuid || !provider) return
      found.set(info.uuid, { id: info.rdns || info.uuid, name: info.name, icon: info.icon, provider })
      setWallets([...found.values()])
    }
    window.addEventListener('eip6963:announceProvider', onAnnounce)
    window.dispatchEvent(new Event('eip6963:requestProvider'))
    const fallback = setTimeout(() => {
      if (found.size === 0 && window.ethereum) {
        setWallets([{ id: 'injected', name: window.ethereum.isMetaMask ? 'MetaMask' : 'Browser wallet', icon: null, provider: window.ethereum }])
      }
    }, 400)
    return () => {
      window.removeEventListener('eip6963:announceProvider', onAnnounce)
      clearTimeout(fallback)
    }
  }, [])
  return wallets
}

export function WalletProvider({ children }) {
  const wallets = useWalletDiscovery()
  const [state, setState] = useState({ status: 'disconnected', address: null, chainId: null, wallet: null, error: null })
  const active = useRef(null)

  const detach = useCallback(() => {
    const p = active.current?.provider
    if (p?.removeListener && active.current?.handlers) {
      p.removeListener('accountsChanged', active.current.handlers.accounts)
      p.removeListener('chainChanged', active.current.handlers.chain)
    }
    active.current = null
  }, [])

  const attach = useCallback((wallet, address, chainId) => {
    detach()
    const handlers = {
      accounts: (accs) => {
        if (!accs?.length) {
          detach()
          setState({ status: 'disconnected', address: null, chainId: null, wallet: null, error: null })
          try { localStorage.removeItem(STORAGE_KEY) } catch { /* ignore */ }
        } else {
          setState((s) => ({ ...s, address: accs[0] }))
        }
      },
      chain: (cid) => setState((s) => ({ ...s, chainId: cid })),
    }
    wallet.provider.on?.('accountsChanged', handlers.accounts)
    wallet.provider.on?.('chainChanged', handlers.chain)
    active.current = { provider: wallet.provider, handlers }
    setState({ status: 'connected', address, chainId, wallet: { id: wallet.id, name: wallet.name, icon: wallet.icon }, error: null })
    try { localStorage.setItem(STORAGE_KEY, wallet.id) } catch { /* ignore */ }
  }, [detach])

  const connect = useCallback(async (wallet) => {
    setState((s) => ({ ...s, status: 'connecting', error: null }))
    try {
      const accounts = await wallet.provider.request({ method: 'eth_requestAccounts' })
      const chainId = await wallet.provider.request({ method: 'eth_chainId' })
      if (!accounts?.length) throw new Error('The wallet didn’t share an address.')
      attach(wallet, accounts[0], chainId)
    } catch (err) {
      setState((s) => ({ ...s, status: 'disconnected', error: friendlyError(err) }))
    }
  }, [attach])

  // Quietly restore a previous connection (eth_accounts never opens a popup).
  useEffect(() => {
    if (state.status !== 'disconnected' || !wallets.length) return
    let saved = null
    try { saved = localStorage.getItem(STORAGE_KEY) } catch { /* ignore */ }
    const w = saved && wallets.find((x) => x.id === saved)
    if (!w) return
    let alive = true
    Promise.all([w.provider.request({ method: 'eth_accounts' }), w.provider.request({ method: 'eth_chainId' })])
      .then(([accs, cid]) => { if (alive && accs?.length) attach(w, accs[0], cid) })
      .catch(() => {})
    return () => { alive = false }
  }, [wallets, state.status, attach])

  const disconnect = useCallback(async () => {
    const p = active.current?.provider
    try { await p?.request?.({ method: 'wallet_revokePermissions', params: [{ eth_accounts: {} }] }) } catch { /* not supported everywhere */ }
    detach()
    try { localStorage.removeItem(STORAGE_KEY) } catch { /* ignore */ }
    setState({ status: 'disconnected', address: null, chainId: null, wallet: null, error: null })
  }, [detach])

  const switchToMonad = useCallback(async () => {
    const p = active.current?.provider
    if (!p) return
    try {
      await p.request({ method: 'wallet_switchEthereumChain', params: [{ chainId: MONAD_TESTNET.chainId }] })
    } catch (err) {
      if (err?.code === 4902 || /unrecognized|not added|unknown chain/i.test(err?.message || '')) {
        try {
          await p.request({ method: 'wallet_addEthereumChain', params: [MONAD_TESTNET] })
        } catch (e2) {
          setState((s) => ({ ...s, error: friendlyError(e2) }))
        }
      } else {
        setState((s) => ({ ...s, error: friendlyError(err) }))
      }
    }
  }, [])

  const onMonad = state.chainId?.toLowerCase() === MONAD_TESTNET.chainId
  const value = { ...state, wallets, onMonad, connect, disconnect, switchToMonad, clearError: () => setState((s) => ({ ...s, error: null })) }
  return <WalletContext.Provider value={value}>{children}</WalletContext.Provider>
}

export function useWallet() {
  const ctx = useContext(WalletContext)
  if (!ctx) throw new Error('useWallet must be used inside <WalletProvider>')
  return ctx
}

/* ------------------------------------------------------------------ */
/* Wallet picker (shared by the header button and the console)         */
/* ------------------------------------------------------------------ */

export function WalletPicker({ onDone }) {
  const w = useWallet()
  if (!w.wallets.length) {
    return (
      <div className="p-1">
        <p className="gx-t1 font-semibold">No wallet found in this browser</p>
        <p className="gx-t2 mt-1 text-sm leading-relaxed">Install a browser wallet such as MetaMask or Rabby, then reload this page. You don’t need one to try the Attack Lab.</p>
        <a href="https://metamask.io/download/" target="_blank" rel="noreferrer" className="gx-link mt-3 inline-flex items-center gap-1 text-sm">Get MetaMask <ExternalLink className="h-3.5 w-3.5" aria-hidden="true" /></a>
      </div>
    )
  }
  return (
    <div>
      <p className="gx-muted px-1 pb-2 text-xs font-semibold uppercase tracking-wide">Choose a wallet</p>
      <ul className="space-y-1.5">
        {w.wallets.map((x) => (
          <li key={x.id}>
            <button
              type="button"
              onClick={async () => { await w.connect(x); onDone?.() }}
              disabled={w.status === 'connecting'}
              className="gx-focus gx-bd flex w-full items-center gap-3 rounded-xl border px-3 py-2.5 text-left transition hover:opacity-80 disabled:opacity-60"
            >
              {x.icon ? <img src={x.icon} alt="" className="h-7 w-7 rounded-md" /> : <WalletIcon className="gx-accent h-7 w-7" aria-hidden="true" />}
              <span className="gx-t1 flex-1 font-semibold">{x.name}</span>
              {w.status === 'connecting' && <Loader2 className="gx-muted h-4 w-4 animate-spin" aria-hidden="true" />}
            </button>
          </li>
        ))}
      </ul>
      <p className="gx-muted mt-3 px-1 text-xs leading-relaxed">Read-only. GuardianAI only sees your address; it never asks you to sign or send anything here.</p>
    </div>
  )
}

function Popover({ open, onClose, children }) {
  const ref = useRef(null)
  useEffect(() => {
    if (!open) return
    const onDown = (e) => { if (ref.current && !ref.current.contains(e.target)) onClose() }
    const onKey = (e) => { if (e.key === 'Escape') onClose() }
    document.addEventListener('mousedown', onDown)
    document.addEventListener('keydown', onKey)
    return () => { document.removeEventListener('mousedown', onDown); document.removeEventListener('keydown', onKey) }
  }, [open, onClose])
  if (!open) return null
  return (
    <div ref={ref} className="gx-card absolute right-0 top-full z-40 mt-2 w-[min(20rem,calc(100vw-2rem))] p-3" role="dialog">
      {children}
    </div>
  )
}

export function ConnectButton() {
  const w = useWallet()
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)
  const close = useCallback(() => setOpen(false), [])

  if (w.status !== 'connected') {
    return (
      <div className="relative">
        <button type="button" onClick={() => setOpen((v) => !v)} className="gx-btn gx-focus !min-h-[40px] !px-4 !py-2 text-sm" aria-expanded={open}>
          {w.status === 'connecting' ? <Loader2 className="h-4 w-4 animate-spin" aria-hidden="true" /> : <WalletIcon className="h-4 w-4" aria-hidden="true" />}
          <span>{w.status === 'connecting' ? 'Connecting…' : 'Connect wallet'}</span>
        </button>
        <Popover open={open} onClose={close}>
          <WalletPicker onDone={close} />
          {w.error && <p role="alert" className="gx-bad-t mt-3 px-1 text-sm">{w.error}</p>}
        </Popover>
      </div>
    )
  }

  const copy = async () => {
    try { await navigator.clipboard.writeText(w.address); setCopied(true); setTimeout(() => setCopied(false), 1500) } catch { /* ignore */ }
  }

  return (
    <div className="relative">
      <button
        type="button"
        onClick={() => setOpen((v) => !v)}
        aria-expanded={open}
        className="gx-btn-ghost gx-focus !min-h-[40px] !px-3 !py-2 text-sm"
      >
        <span className="h-2 w-2 rounded-full" style={{ background: w.onMonad ? 'var(--gx-good-text)' : 'var(--gx-warn-text)' }} aria-hidden="true" />
        <span className="font-mono">{short(w.address)}</span>
        <ChevronDown className="h-4 w-4 opacity-60" aria-hidden="true" />
      </button>
      <Popover open={open} onClose={close}>
        <p className="gx-muted px-1 text-xs">Connected with {w.wallet?.name}</p>
        <p className="gx-t1 mt-0.5 break-all px-1 font-mono text-sm">{w.address}</p>
        {!w.onMonad && (
          <div className="gx-warn mt-3 rounded-lg p-3 text-sm">
            <p className="flex items-center gap-1.5 font-semibold"><AlertTriangle className="h-4 w-4" aria-hidden="true" /> Wrong network</p>
            <button type="button" onClick={w.switchToMonad} className="gx-btn gx-focus mt-2 !min-h-[36px] w-full !py-1.5 text-sm">Switch to Monad testnet</button>
          </div>
        )}
        <div className="mt-3 space-y-0.5">
          <a href="?view=console" className="gx-t1 gx-focus flex items-center gap-2 rounded-lg px-2 py-2 text-sm hover:opacity-70"><LayoutDashboard className="h-4 w-4" aria-hidden="true" /> Open console</a>
          <button type="button" onClick={copy} className="gx-t1 gx-focus flex w-full items-center gap-2 rounded-lg px-2 py-2 text-left text-sm hover:opacity-70">
            {copied ? <Check className="h-4 w-4" aria-hidden="true" /> : <Copy className="h-4 w-4" aria-hidden="true" />} {copied ? 'Copied' : 'Copy address'}
          </button>
          <a href={addressUrl(w.address)} target="_blank" rel="noreferrer" className="gx-t1 gx-focus flex items-center gap-2 rounded-lg px-2 py-2 text-sm hover:opacity-70"><ExternalLink className="h-4 w-4" aria-hidden="true" /> View on MonadScan</a>
          <button type="button" onClick={() => { close(); w.disconnect() }} className="gx-bad-t gx-focus flex w-full items-center gap-2 rounded-lg px-2 py-2 text-left text-sm hover:opacity-70">
            <LogOut className="h-4 w-4" aria-hidden="true" /> Disconnect
          </button>
        </div>
        {w.error && <p role="alert" className="gx-bad-t mt-2 px-1 text-sm">{w.error}</p>}
      </Popover>
    </div>
  )
}
