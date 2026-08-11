export type NewRunnableAgentKind = 'claude' | 'codex' | 'copilot' | 'antigravity' | 'kimi' | 'kiro' | 'opencode' | 'cursor' | 'amp' | 'devin' | 'factory'
export type LegacyRunnableAgentKind = 'gemini'
export type RunnableAgentKind = NewRunnableAgentKind | LegacyRunnableAgentKind
export type AgentKind = RunnableAgentKind | 'shell'
export type LaunchAgentKind = NewRunnableAgentKind | 'terminal'
export type OverlayAgentKind = RunnableAgentKind | 'terminal'
export type AgentResumeMode = 'continue' | 'resume' | 'none'

export type AgentProvider = {
  command: string
  commandArgs?: readonly string[]
  label: string
  glyph: string
  color: string
  dangerousFlag: string
  models: readonly string[]
  selectable: boolean
  legacy?: boolean
}

export const COPILOT_MODELS = [
  'default',
  'auto',
  'claude-sonnet-5',
  'claude-sonnet-4.6',
  'claude-sonnet-4.5',
  'claude-haiku-4.5',
  'claude-fable-5',
  'claude-opus-4.8',
  'claude-opus-4.8-fast',
  'claude-opus-4.7',
  'claude-opus-4.6',
  'claude-opus-4.5',
  'gpt-5.6-sol',
  'gpt-5.6-terra',
  'gpt-5.6-luna',
  'gpt-5.5',
  'gpt-5.4',
  'gpt-5.3-codex',
  'gpt-5.4-mini',
  'gpt-5-mini',
  'gemini-3.1-pro-preview',
  'gemini-3.5-flash',
  'kimi-k2.7-code',
] as const

export const ANTIGRAVITY_MODELS = [
  'default',
  'Gemini 3.5 Flash (Medium)',
  'Gemini 3.5 Flash (High)',
  'Gemini 3.5 Flash (Low)',
  'Gemini 3.1 Pro (Low)',
  'Gemini 3.1 Pro (High)',
  'Claude Sonnet 4.6 (Thinking)',
  'Claude Opus 4.6 (Thinking)',
  'GPT-OSS 120B (Medium)',
] as const

// Curated from Cursor Agent's account-aware `agent --list-models` output. The downloaded model
// catalog can add newer IDs without requiring a desktop release.
export const CURSOR_MODELS = [
  'default',
  'auto',
  'composer-2.5',
  'gpt-5.3-codex',
  'gpt-5.3-codex-high',
  'gpt-5.3-codex-xhigh',
  'claude-sonnet-5-high',
  'claude-opus-4-8-high',
  'gpt-5.6-sol-high',
  'gpt-5.5-high',
  'gpt-5.4-high',
  'gemini-3.1-pro',
  'kimi-k2.7-code',
  'glm-5.2-high',
] as const

export const DEVIN_MODELS = [
  'default', 'adaptive', 'opus', 'sonnet', 'swe', 'codex', 'gemini',
] as const

export const FACTORY_MODELS = ['default'] as const

export const AGENT_PROVIDERS: Record<OverlayAgentKind, AgentProvider> = {
  claude: {
    command: 'claude', label: 'Claude', glyph: '✳', color: '#d97757',
    dangerousFlag: '--dangerously-skip-permissions', selectable: true,
    models: ['default', 'best', 'fable', 'opus', 'sonnet', 'haiku', 'opus[1m]', 'sonnet[1m]'],
  },
  codex: {
    command: 'codex', label: 'Codex', glyph: '◆', color: '#10a37f',
    dangerousFlag: '--dangerously-bypass-approvals-and-sandbox', selectable: true,
    models: ['default', 'gpt-5.5', 'gpt-5.4-mini', 'gpt-5.3-codex-spark'],
  },
  copilot: {
    command: 'copilot', label: 'Copilot', glyph: '◉', color: '#58c8ff',
    dangerousFlag: '--yolo', selectable: true, models: COPILOT_MODELS,
  },
  antigravity: {
    command: 'agy', label: 'Antigravity', glyph: '⟡', color: '#8b5cf6',
    dangerousFlag: '--dangerously-skip-permissions', selectable: true, models: ANTIGRAVITY_MODELS,
  },
  kimi: {
    command: 'kimi', label: 'Kimi', glyph: '☾', color: '#f0b35b',
    dangerousFlag: '--yolo', selectable: true,
    models: ['default', 'kimi-code/kimi-for-coding', 'kimi-code/kimi-for-coding-highspeed', 'kimi-code/k3'],
  },
  kiro: {
    command: 'kiro-cli', commandArgs: ['chat'], label: 'Kiro', glyph: 'K', color: '#7c6cff',
    dangerousFlag: '--trust-all-tools', selectable: true,
    models: [
      'default', 'auto', 'claude-sonnet-4.5', 'claude-sonnet-4', 'claude-haiku-4.5',
      'deepseek-3.2', 'minimax-m2.5', 'minimax-m2.1', 'glm-5', 'qwen3-coder-next',
    ],
  },
  opencode: {
    command: 'opencode', label: 'OpenCode', glyph: '◇', color: '#a78bfa',
    dangerousFlag: '--auto', selectable: true,
    models: ['default', 'opencode/deepseek-v4-flash-free', 'opencode/hy3-free', 'opencode/big-pickle'],
  },
  cursor: {
    command: 'agent', label: 'Cursor', glyph: '⌁', color: '#38bdf8',
    dangerousFlag: '--yolo', selectable: true, models: CURSOR_MODELS,
  },
  amp: {
    command: 'amp', label: 'Amp', glyph: '▲', color: '#f59e0b',
    dangerousFlag: '--dangerously-allow-all', selectable: true, models: ['default'],
  },
  devin: {
    command: 'devin', label: 'Devin', glyph: 'D', color: '#34d399',
    dangerousFlag: '--permission-mode=dangerous', selectable: true, models: DEVIN_MODELS,
  },
  factory: {
    command: 'droid', label: 'Factory', glyph: 'F', color: '#a78bfa',
    dangerousFlag: '--auto=high', selectable: true, models: FACTORY_MODELS,
  },
  gemini: {
    command: 'gemini', label: 'Gemini', glyph: '✦', color: '#4f8cff', dangerousFlag: '--yolo',
    selectable: false, legacy: true,
    models: ['default', 'gemini-3.1-pro-preview', 'gemini-3-flash-preview', 'gemini-3.1-flash-lite', 'gemini-flash-latest'],
  },
  terminal: {
    command: '', label: 'Terminal', glyph: '›', color: '#9aa4b2', dangerousFlag: '',
    selectable: true, models: [],
  },
}

export const SELECTABLE_AGENT_OPTIONS = [
  'claude', 'codex', 'copilot', 'antigravity', 'kimi', 'kiro', 'opencode', 'cursor', 'amp', 'devin', 'factory', 'terminal',
] as const satisfies readonly LaunchAgentKind[]

export const SELECTABLE_RUNNABLE_AGENT_OPTIONS = SELECTABLE_AGENT_OPTIONS.filter(
  (agent): agent is NewRunnableAgentKind => agent !== 'terminal',
)

export const RUNNABLE_AGENT_OPTIONS = [
  'claude', 'codex', 'copilot', 'antigravity', 'kimi', 'kiro', 'opencode', 'cursor', 'amp', 'devin', 'factory', 'gemini',
] as const satisfies readonly RunnableAgentKind[]

// Amp and Factory are launchable and can ask their CLIs for the latest thread, but their provider-owned
// stores are intentionally not read until Hydra has qualified folder scoping and transcript privacy.
export const HISTORY_AGENT_OPTIONS = [
  'claude', 'codex', 'copilot', 'antigravity', 'kimi', 'kiro', 'opencode', 'cursor', 'devin', 'gemini',
] as const satisfies readonly RunnableAgentKind[]

export function isRunnableAgentKind(value: unknown): value is RunnableAgentKind {
  return RUNNABLE_AGENT_OPTIONS.some((agent) => agent === value)
}

export function supportsProviderHistory(agent: unknown): agent is RunnableAgentKind {
  return HISTORY_AGENT_OPTIONS.some((candidate) => candidate === agent)
}

export function defaultsFreshWithoutProviderHistory(agent: unknown): boolean {
  return isRunnableAgentKind(agent) && !supportsProviderHistory(agent)
}

export function resumeModeOptionsForAgent(
  agent: RunnableAgentKind,
): readonly (readonly [AgentResumeMode, string])[] {
  if (agent === 'amp') return [['continue', 'last'], ['none', 'fresh']]
  if (agent === 'factory') return [['continue', '--resume'], ['none', 'fresh']]
  return [['continue', '--continue'], ['resume', '--resume'], ['none', 'fresh']]
}

export function isOverlayAgentKind(value: unknown): value is OverlayAgentKind {
  return value === 'terminal' || isRunnableAgentKind(value)
}

export function isLegacyAgentKind(value: unknown): value is LegacyRunnableAgentKind {
  return value === 'gemini'
}

export function supportsPermanentHistoryDelete(
  agent: RunnableAgentKind,
  inUse = false,
): boolean {
  // Only providers whose complete on-disk ownership is proven may expose destructive deletion.
  // The other catalogs are SQLite-backed, provider-managed, or can duplicate one session across
  // multiple files; Remove remains available for those providers.
  return !inUse && (agent === 'codex' || agent === 'claude')
}

export type AgentLaunchOptions = {
  agent: RunnableAgentKind
  resumeMode?: AgentResumeMode
  sessionId?: string | null
  sessionFile?: string | null
  model?: string | null
  dangerous?: boolean
}

export function buildAgentLaunchArgv(options: AgentLaunchOptions): string[] {
  const { agent, resumeMode = 'none', sessionId, sessionFile, model, dangerous = false } = options
  const provider = AGENT_PROVIDERS[agent]
  const parts: string[] = [provider.command, ...(provider.commandArgs ?? [])]

  if (agent === 'codex') {
    if (resumeMode === 'resume' && sessionId) parts.push('resume', sessionId)
    else if (resumeMode !== 'none') parts.push('resume', '--last')
  } else if (agent === 'copilot') {
    if (resumeMode === 'resume' && sessionId) parts.push(`--resume=${sessionId}`)
    else if (resumeMode !== 'none') parts.push('--continue')
  } else if (agent === 'antigravity') {
    if (resumeMode === 'resume' && sessionId) parts.push('--conversation', sessionId)
    else if (resumeMode !== 'none') parts.push('--continue')
  } else if (agent === 'kimi') {
    if (resumeMode === 'resume' && sessionId) parts.push('--session', sessionId)
    else if (resumeMode !== 'none') parts.push('--continue')
  } else if (agent === 'kiro') {
    if (resumeMode === 'resume' && sessionId) parts.push('--resume-id', sessionId)
    else if (resumeMode !== 'none') parts.push('--resume')
  } else if (agent === 'cursor') {
    if (resumeMode === 'resume' && sessionId) parts.push('--resume', sessionId)
    else if (resumeMode !== 'none') parts.push('--continue')
  } else if (agent === 'amp') {
    if (resumeMode === 'resume' && sessionId) parts.push('threads', 'continue', sessionId)
    else if (resumeMode !== 'none') parts.push('last')
  } else if (agent === 'devin') {
    if (resumeMode === 'resume' && sessionId) parts.push('--resume', sessionId)
    else if (resumeMode !== 'none') parts.push('--continue')
  } else if (agent === 'factory') {
    if (resumeMode === 'resume' && sessionId) parts.push('--resume', sessionId)
    else if (resumeMode !== 'none') parts.push('--resume')
  } else if (agent === 'gemini') {
    if (resumeMode === 'resume' && sessionFile) parts.push('--session-file', sessionFile)
    else if (resumeMode !== 'none') parts.push('--resume', 'latest')
  } else if (agent === 'opencode') {
    if (resumeMode === 'resume' && sessionId) parts.push('--session', sessionId)
    else if (resumeMode !== 'none') parts.push('--continue')
  } else if (resumeMode === 'resume' && sessionId) {
    parts.push('--resume', sessionId)
  } else if (resumeMode !== 'none') {
    parts.push('--continue')
  }

  if (agent !== 'amp' && agent !== 'factory' && model && model !== 'default') parts.push('--model', model)
  if (dangerous && provider.dangerousFlag) parts.push(provider.dangerousFlag)
  return parts
}

export function quoteAgentLaunchArg(value: string): string {
  if (/^[A-Za-z0-9_@%+=:,./-]+$/.test(value)) return value
  // Shell-safe even if this display string ever crosses a shell boundary. Hydra's argv parser also
  // understands adjacent single-quoted/unquoted fragments, so embedded quotes round-trip as one argv. Its
  // grammar treats backslash as an escape inside quotes, so double it to preserve one literal backslash.
  return `'${value.replace(/\\/g, '\\\\').replace(/'/g, `'\\''`)}'`
}

export function formatAgentLaunchCommand(options: AgentLaunchOptions): string {
  return buildAgentLaunchArgv(options).map(quoteAgentLaunchArg).join(' ')
}
