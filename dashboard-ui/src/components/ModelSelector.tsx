import { AGENT_PROVIDERS, type OverlayAgentKind } from '../model/agent-provider'
import type { ModelCatalog, ModelDeprecation } from '../types/model'

export interface ModelOption {
  value: string
  label: string
}

/** Return deprecation metadata only for the exact selected agent/model pair. */
export function modelDeprecation(
  agent: OverlayAgentKind,
  model: string,
  catalog: ModelCatalog | null | undefined,
): ModelDeprecation | null {
  return catalog?.deprecations?.[agent]?.[model] ?? null
}

/** Per-agent model options with catalog additions merged after the stable built-ins.
 * Ordering and de-duplication are unchanged; deprecation is display metadata only. */
export function agentModelOptions(
  agent: OverlayAgentKind,
  catalog: ModelCatalog | null | undefined,
): ModelOption[] {
  const mark = (value: string): ModelOption => ({
    value,
    label: modelDeprecation(agent, value, catalog) ? `${value} (deprecated)` : value,
  })
  const builtin = AGENT_PROVIDERS[agent].models.map(mark)
  const extra = catalog?.agents?.[agent] ?? []
  if (extra.length === 0) return builtin
  const seen = new Set(builtin.map((model) => model.value))
  const merged = [...builtin]
  for (const value of extra) {
    if (!seen.has(value)) {
      seen.add(value)
      merged.push(mark(value))
    }
  }
  return merged
}

export function modelDeprecationNoticeText(deprecation: ModelDeprecation): string {
  return deprecation.replacement
    ? `${deprecation.message} Suggested replacement: ${deprecation.replacement}.`
    : deprecation.message
}

export function ModelSelector({
  agent,
  catalog,
  value,
  ariaLabel,
  onValue,
}: {
  agent: OverlayAgentKind
  catalog: ModelCatalog | null | undefined
  value: string
  ariaLabel: string
  onValue: (value: string) => void
}): JSX.Element {
  const deprecation = modelDeprecation(agent, value, catalog)
  return (
    <>
      <select
        className="overlay-select"
        aria-label={ariaLabel}
        value={value}
        onInput={(event) => onValue(event.currentTarget.value)}
        onChange={(event) => onValue(event.currentTarget.value)}
      >
        {agentModelOptions(agent, catalog).map((model) => (
          <option key={model.value} value={model.value}>
            {model.label}
          </option>
        ))}
      </select>
      {deprecation && (
        <p className="overlay-model-deprecation" role="note" aria-live="polite">
          {modelDeprecationNoticeText(deprecation)}
        </p>
      )}
    </>
  )
}
