import App from './App.jsx'
import { PrivyConfigProvider } from './components/PrivyConfigProvider.tsx'

export default function DeveloperConsole() {
  return (
    <PrivyConfigProvider>
      <App />
    </PrivyConfigProvider>
  )
}
