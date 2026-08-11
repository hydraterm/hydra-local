import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { App } from './App'
import './styles.css'

async function startDashboard(): Promise<void> {
  // The mock host is a development convenience, not trusted application code. Keeping the import
  // behind Vite's compile-time DEV flag lets Rollup remove both devHost and its mock model from the
  // production dependency graph.
  if (import.meta.env.DEV) {
    const { installDevHost } = await import('./ipc/devHost')
    await installDevHost()
  }

  createRoot(document.getElementById('root')!).render(
    <StrictMode>
      <App />
    </StrictMode>,
  )
}

void startDashboard()
