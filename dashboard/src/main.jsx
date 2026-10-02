import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import SimpleExplorer from './explorer/SimpleExplorer.jsx'
import Console from './explorer/Console.jsx'
import { WalletProvider } from './explorer/wallet.jsx'
import { ErrorBoundary } from './components/ErrorBoundary.jsx'

// Two pages: the public Attack Lab (default) and the Console (?view=console).
// ?view=developer is the old console's address and now opens the new one.
const view = new URLSearchParams(window.location.search).get('view')
const isConsole = view === 'console' || view === 'developer'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ErrorBoundary>
      <WalletProvider>
        {isConsole ? <Console /> : <SimpleExplorer />}
      </WalletProvider>
    </ErrorBoundary>
  </StrictMode>,
)
