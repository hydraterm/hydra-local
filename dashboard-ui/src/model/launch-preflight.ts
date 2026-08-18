import type { LaunchPreflightResult } from '../ipc/bridge'
import { AGENT_PROVIDERS, isRunnableAgentKind } from './agent-provider'

const PREFLIGHT_ERROR_MAX = 320

function boundedHostMessage(message: string | null): string {
  const fallback = 'That launch command is unavailable. Install the selected agent or choose another command.'
  const trimmed = message?.trim() || fallback
  if (trimmed.length <= PREFLIGHT_ERROR_MAX) return trimmed
  return `${trimmed.slice(0, PREFLIGHT_ERROR_MAX - 1)}…`
}

/** Map one stable native error code plus the closed selected-provider enum to fixed UI guidance.
 * Native message text is never parsed for provider identity, executable names, commands, or URLs. */
export function launchPreflightFailureMessage(
  result: LaunchPreflightResult,
  selectedAgent: string | null | undefined,
): string {
  if (result.code !== 'agent_executable_missing' || !isRunnableAgentKind(selectedAgent)) {
    return boundedHostMessage(result.message)
  }
  const provider = AGENT_PROVIDERS[selectedAgent]
  return (
    `${provider.label} is not available in your login shell. ` +
    `Hydra expected the \`${provider.command}\` executable. ` +
    `In Terminal, run \`command -v ${provider.command}\` to check that shell, ` +
    'or choose Terminal in Hydra for a plain shell.'
  )
}
