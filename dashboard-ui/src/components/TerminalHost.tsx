import type { DashboardWindow } from '../types/model'

// The CENTER BODY. This is NOT a terminal — React never renders terminal
// content. It reserves the visual slot around the native Rust terminal surface.
// Rust/native host allocation remains the sole terminal geometry authority; this
// presentation component must not report browser-measured geometry over IPC.
type Props = {
  projectName: string
  window: DashboardWindow | null
}

export function TerminalHost({ projectName, window: win }: Props): JSX.Element {
  const livePanes = win?.tabs.filter((t) => !t.stashed) ?? []

  return (
    <div className="terminal-host" data-native-terminal-slot>
      <div className="terminal-host__inner">
        <div className="terminal-host__glyph" aria-hidden>
          ▤
        </div>
        <div className="terminal-host__label">Terminal</div>
        {win ? (
          <div className="terminal-host__detail">
            {projectName} · {win.name || win.window_id} · {livePanes.length} pane
            {livePanes.length === 1 ? '' : 's'}
          </div>
        ) : (
          <div className="terminal-host__detail">No window focused</div>
        )}
        <div className="terminal-host__note">
          Waiting for the native terminal surface.
        </div>
      </div>
    </div>
  )
}
