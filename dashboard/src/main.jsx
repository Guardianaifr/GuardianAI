import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import './index.css'
import App from './App.jsx'
import { PrivyConfigProvider } from './components/PrivyConfigProvider.tsx'
import { ErrorBoundary } from './components/ErrorBoundary.jsx'

createRoot(document.getElementById('root')).render(
  <StrictMode>
    <ErrorBoundary>
      <PrivyConfigProvider>
        <App />
      </PrivyConfigProvider>
    </ErrorBoundary>
  </StrictMode>,
)

