import { describe, expect, it } from 'vitest'
import { launchPreflightFailureMessage } from './launch-preflight'

describe('launch preflight guidance', () => {
  it('uses closed provider metadata for a known missing agent', () => {
    const message = launchPreflightFailureMessage(
      {
        ok: false,
        code: 'agent_executable_missing',
        message: 'Untrusted text claims the provider is something else.',
      },
      'claude',
    )
    expect(message).toContain('Claude')
    expect(message).toContain('`claude`')
    expect(message).toContain('`command -v claude`')
    expect(message).toContain('choose Terminal')
    expect(message).not.toContain('Untrusted text')
  })

  it('keeps custom-command failures on the bounded native message', () => {
    expect(
      launchPreflightFailureMessage(
        {
          ok: false,
          code: 'launch_executable_missing',
          message: 'The custom launch command is unavailable.',
        },
        'claude',
      ),
    ).toBe('The custom launch command is unavailable.')
  })

  it('fails an unknown code closed to the bounded native message', () => {
    const message = launchPreflightFailureMessage(
      { ok: false, code: 'future_error', message: 'A future bounded host message. ' + 'x'.repeat(400) },
      'claude',
    )
    expect(message).toContain('A future bounded host message.')
    expect(message.length).toBeLessThanOrEqual(320)
    expect(message.endsWith('…')).toBe(true)
    expect(message).not.toContain('command -v')
  })

  it('does not infer a provider for absent or unknown selections', () => {
    const result = {
      ok: false,
      code: 'agent_executable_missing',
      message: 'Choose a supported agent or Terminal.',
    }
    expect(launchPreflightFailureMessage(result, 'unknown')).toBe(result.message)
    expect(launchPreflightFailureMessage(result, null)).toBe(result.message)
  })
})
