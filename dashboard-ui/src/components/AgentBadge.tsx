import type { AgentKind } from '../types/model'
import { AGENT_PROVIDERS } from '../model/agent-provider'

// Provider badges are deliberately code-native. Third-party marks are not bundled in the public
// source tree; each provider keeps a stable text/Unicode glyph, label, and color instead.
const AGENT = { ...AGENT_PROVIDERS, shell: AGENT_PROVIDERS.terminal } satisfies Record<
  AgentKind,
  { glyph: string; color: string; label: string }
>

type Props = {
  agent: AgentKind
  size?: number
  dim?: boolean
}

export function AgentBadge({ agent, size = 12, dim = false }: Props): JSX.Element {
  const a = AGENT[agent]
  return (
    <span
      className="agent-badge"
      data-agent={agent}
      title={a.label}
      style={{ color: a.color, fontSize: size, width: size, height: size, opacity: dim ? 0.5 : 1 }}
      aria-hidden
    >
      {a.glyph}
    </span>
  )
}
