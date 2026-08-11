import { describe, expect, it } from 'vitest'
import {
  AGENT_PROVIDERS,
  SELECTABLE_AGENT_OPTIONS,
  buildAgentLaunchArgv,
  defaultsFreshWithoutProviderHistory,
  formatAgentLaunchCommand,
  isRunnableAgentKind,
  quoteAgentLaunchArg,
  resumeModeOptionsForAgent,
  supportsPermanentHistoryDelete,
  supportsProviderHistory,
} from './agent-provider'

describe('desktop agent provider catalog', () => {
  it('offers Devin and Factory under stable product IDs, but not legacy Gemini for new sessions', () => {
    expect(SELECTABLE_AGENT_OPTIONS).toEqual([
      'claude', 'codex', 'copilot', 'antigravity', 'kimi', 'kiro', 'opencode', 'cursor', 'amp',
      'devin', 'factory', 'terminal',
    ])
    expect(SELECTABLE_AGENT_OPTIONS).not.toContain('gemini')
    expect(isRunnableAgentKind('gemini')).toBe(true)
    expect(isRunnableAgentKind('amp')).toBe(true)
    expect(isRunnableAgentKind('devin')).toBe(true)
    expect(isRunnableAgentKind('factory')).toBe(true)
    expect(supportsProviderHistory('amp')).toBe(false)
    expect(supportsProviderHistory('devin')).toBe(true)
    expect(supportsProviderHistory('factory')).toBe(false)
    expect(defaultsFreshWithoutProviderHistory('amp')).toBe(true)
    expect(defaultsFreshWithoutProviderHistory('factory')).toBe(true)
    expect(defaultsFreshWithoutProviderHistory('devin')).toBe(false)
    expect(resumeModeOptionsForAgent('amp')).toEqual([['continue', 'last'], ['none', 'fresh']])
    expect(resumeModeOptionsForAgent('factory')).toEqual([['continue', '--resume'], ['none', 'fresh']])
    expect(resumeModeOptionsForAgent('devin')).toEqual([
      ['continue', '--continue'], ['resume', '--resume'], ['none', 'fresh'],
    ])
    expect(supportsProviderHistory('claude')).toBe(true)
    expect(AGENT_PROVIDERS.gemini.legacy).toBe(true)
  })

  it('uses code-native glyphs and assigns no image to any provider', () => {
    for (const provider of Object.values(AGENT_PROVIDERS)) {
      expect(provider.glyph.length).toBeGreaterThan(0)
      expect(provider).not.toHaveProperty('icon')
    }
  })

  it('builds Copilot fresh, continue, exact resume, model, and --yolo argv', () => {
    expect(buildAgentLaunchArgv({ agent: 'copilot' })).toEqual(['copilot'])
    expect(buildAgentLaunchArgv({ agent: 'copilot', resumeMode: 'continue' })).toEqual([
      'copilot', '--continue',
    ])
    expect(buildAgentLaunchArgv({
      agent: 'copilot', resumeMode: 'resume', sessionId: 'session 42',
      model: 'claude-sonnet-5', dangerous: true,
    })).toEqual(['copilot', '--resume=session 42', '--model', 'claude-sonnet-5', '--yolo'])
  })

  it('uses agy and preserves Antigravity model values containing spaces as one quoted argv', () => {
    expect(buildAgentLaunchArgv({
      agent: 'antigravity', resumeMode: 'resume', sessionId: 'conv-7',
      model: 'Claude Sonnet 4.6 (Thinking)', dangerous: true,
    })).toEqual([
      'agy', '--conversation', 'conv-7', '--model', 'Claude Sonnet 4.6 (Thinking)',
      '--dangerously-skip-permissions',
    ])
    expect(formatAgentLaunchCommand({
      agent: 'antigravity', model: 'Claude Sonnet 4.6 (Thinking)',
    })).toBe("agy --model 'Claude Sonnet 4.6 (Thinking)'")
  })

  it('builds Kimi exact resume, continue, model, and --yolo argv', () => {
    expect(buildAgentLaunchArgv({ agent: 'kimi', resumeMode: 'continue' })).toEqual([
      'kimi', '--continue',
    ])
    expect(buildAgentLaunchArgv({
      agent: 'kimi', resumeMode: 'resume', sessionId: 'session_123',
      model: 'kimi-code/k3', dangerous: true,
    })).toEqual(['kimi', '--session', 'session_123', '--model', 'kimi-code/k3', '--yolo'])
  })

  it('builds Kiro chat fresh, continue, exact resume, model, and trust argv', () => {
    expect(buildAgentLaunchArgv({ agent: 'kiro' })).toEqual(['kiro-cli', 'chat'])
    expect(buildAgentLaunchArgv({ agent: 'kiro', resumeMode: 'continue' })).toEqual([
      'kiro-cli', 'chat', '--resume',
    ])
    expect(buildAgentLaunchArgv({
      agent: 'kiro', resumeMode: 'resume', sessionId: 'uuid-123',
      model: 'qwen3-coder-next', dangerous: true,
    })).toEqual([
      'kiro-cli', 'chat', '--resume-id', 'uuid-123', '--model', 'qwen3-coder-next',
      '--trust-all-tools',
    ])
  })

  it('builds Cursor fresh, continue, exact resume, model, and --yolo argv', () => {
    expect(buildAgentLaunchArgv({ agent: 'cursor' })).toEqual(['agent'])
    expect(buildAgentLaunchArgv({ agent: 'cursor', resumeMode: 'continue' })).toEqual([
      'agent', '--continue',
    ])
    expect(buildAgentLaunchArgv({
      agent: 'cursor', resumeMode: 'resume', sessionId: '123e4567-e89b-42d3-a456-426614174000',
      model: 'composer-2.5', dangerous: true,
    })).toEqual([
      'agent', '--resume', '123e4567-e89b-42d3-a456-426614174000', '--model', 'composer-2.5', '--yolo',
    ])
  })

  it('builds Amp fresh, latest, exact thread, and dangerous argv without exposing history', () => {
    expect(buildAgentLaunchArgv({ agent: 'amp' })).toEqual(['amp'])
    expect(buildAgentLaunchArgv({ agent: 'amp', resumeMode: 'continue' })).toEqual(['amp', 'last'])
    expect(buildAgentLaunchArgv({
      agent: 'amp', resumeMode: 'resume', sessionId: 'thread-id',
      model: 'must-not-be-forwarded', dangerous: true,
    })).toEqual([
      'amp', 'threads', 'continue', 'thread-id',
      '--dangerously-allow-all',
    ])
  })

  it('builds Devin fresh, latest, exact resume, model, and one-argv dangerous mode', () => {
    expect(buildAgentLaunchArgv({ agent: 'devin' })).toEqual(['devin'])
    expect(buildAgentLaunchArgv({ agent: 'devin', resumeMode: 'continue' })).toEqual([
      'devin', '--continue',
    ])
    expect(buildAgentLaunchArgv({
      agent: 'devin', resumeMode: 'resume', sessionId: 'synthetic-session',
      model: 'adaptive', dangerous: true,
    })).toEqual([
      'devin', '--resume', 'synthetic-session', '--model', 'adaptive',
      '--permission-mode=dangerous',
    ])
  })

  it('builds Factory fresh, latest, owned exact resume, and high autonomy without models', () => {
    expect(buildAgentLaunchArgv({ agent: 'factory' })).toEqual(['droid'])
    expect(buildAgentLaunchArgv({ agent: 'factory', resumeMode: 'continue' })).toEqual([
      'droid', '--resume',
    ])
    expect(buildAgentLaunchArgv({
      agent: 'factory', resumeMode: 'resume', sessionId: 'hydra-owned-id',
      model: 'must-not-be-forwarded', dangerous: true,
    })).toEqual(['droid', '--resume', 'hydra-owned-id', '--auto=high'])
  })

  it('shell-quotes hostile display values instead of interpolating them', () => {
    expect(quoteAgentLaunchArg('$(touch /tmp/pwned)')).toBe("'$(touch /tmp/pwned)'")
    expect(quoteAgentLaunchArg("it's `id`")).toBe("'it'\\''s `id`'")
    expect(quoteAgentLaunchArg('C:\\Hydra Sessions\\one')).toBe("'C:\\\\Hydra Sessions\\\\one'")
    expect(quoteAgentLaunchArg('model with spaces\\variant')).toBe("'model with spaces\\\\variant'")
  })

  it('does not expose unsafe permanent deletion for multi-file/SQLite providers', () => {
    expect(supportsPermanentHistoryDelete('copilot')).toBe(false)
    expect(supportsPermanentHistoryDelete('antigravity')).toBe(false)
    expect(supportsPermanentHistoryDelete('kimi')).toBe(false)
    expect(supportsPermanentHistoryDelete('kiro')).toBe(false)
    expect(supportsPermanentHistoryDelete('cursor')).toBe(false)
    expect(supportsPermanentHistoryDelete('amp')).toBe(false)
    expect(supportsPermanentHistoryDelete('devin')).toBe(false)
    expect(supportsPermanentHistoryDelete('factory')).toBe(false)
    expect(supportsPermanentHistoryDelete('claude')).toBe(true)
    expect(supportsPermanentHistoryDelete('codex')).toBe(true)
    expect(supportsPermanentHistoryDelete('claude', true)).toBe(false)
    expect(supportsPermanentHistoryDelete('codex', true)).toBe(false)
    expect(supportsPermanentHistoryDelete('gemini')).toBe(false)
    expect(supportsPermanentHistoryDelete('opencode')).toBe(false)
  })
})
