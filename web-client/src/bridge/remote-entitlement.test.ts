import { describe, expect, it } from 'vitest'
import {
  RemoteEntitlementRequired,
  isRemoteEntitlementRequiredResponse,
  throwIfRemoteEntitlementRequired,
  isRemoteEntitlementRequired,
} from './remote-entitlement'
import { StableSetupRefusal, isStableSetupRefusal } from './setup-refusal-contract'

describe('remote entitlement response contract', () => {
  it('preserves the hosted nominal error while translating to the legacy local refusal state', () => {
    const error = new RemoteEntitlementRequired()
    expect(error.constructor).toBe(RemoteEntitlementRequired)
    expect(error).toBeInstanceOf(Error)
    expect(error).toBeInstanceOf(StableSetupRefusal)
    expect(error.name).toBe('RemoteEntitlementRequired')
    expect(error.message).toBe('remote_entitlement_required')
    expect(error.state).toBe('entitlement_required')
    expect(isRemoteEntitlementRequired(error)).toBe(true)
    expect(isStableSetupRefusal(error)).toBe(true)
    expect(isRemoteEntitlementRequired(new StableSetupRefusal())).toBe(false)
  })

  it('recognizes only the exact closed 402 response', () => {
    expect(isRemoteEntitlementRequiredResponse(402, { error: 'remote_entitlement_required' })).toBe(true)
    for (const [status, body] of [
      [503, { error: 'remote_entitlement_required' }],
      [402, { error: 'remote_entitlement_unavailable' }],
      [402, { error: 'remote_entitlement_required', detail: 'unexpected' }],
      [402, null],
    ] as const) expect(isRemoteEntitlementRequiredResponse(status, body)).toBe(false)
  })

  it('throws a typed stable-state signal only for that exact response', () => {
    expect(() => throwIfRemoteEntitlementRequired(402, { error: 'remote_entitlement_required' }))
      .toThrow(RemoteEntitlementRequired)
    expect(() => throwIfRemoteEntitlementRequired(503, { error: 'remote_entitlement_unavailable' }))
      .not.toThrow()
  })
})
