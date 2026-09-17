import { describe, it, expect } from 'vitest'
import {
  IcePathPolicy,
  iceServersFromRelay,
  modeFromCandidateType,
  stunServersFromRelay,
} from './relay-fallback'

describe('modeFromCandidateType', () => {
  it('maps candidate types to direct/relay', () => {
    expect(modeFromCandidateType('host')).toBe('direct')
    expect(modeFromCandidateType('srflx')).toBe('direct')
    expect(modeFromCandidateType('relay')).toBe('relay')
    expect(modeFromCandidateType(null)).toBe('unknown')
  })
})

describe('iceServersFromRelay', () => {
  it('maps cloud creds to a TURN RTCIceServer', () => {
    expect(
      iceServersFromRelay({ urls: ['turns:r:5349'], username: 'u', credential: 'p', expiresAtMs: 1 }),
    ).toEqual([{ urls: ['turns:r:5349'], username: 'u', credential: 'p' }])
  })

  it('appends OUR-HOST STUN (no credentials) when stunUrls are present — never a third party', () => {
    expect(
      iceServersFromRelay({
        urls: ['turns:r:5349'],
        username: 'u',
        credential: 'p',
        expiresAtMs: 1,
        stunUrls: ['stun:r:3478'],
      }),
    ).toEqual([
      { urls: ['turns:r:5349'], username: 'u', credential: 'p' },
      { urls: ['stun:r:3478'] }, // no username/credential on STUN
    ])
  })

  it('omits STUN when stunUrls is empty/absent (host + TURN only, no external STUN)', () => {
    const noStun = iceServersFromRelay({ urls: ['turns:r'], username: 'u', credential: 'p', expiresAtMs: 1, stunUrls: [] })
    expect(noStun).toEqual([{ urls: ['turns:r'], username: 'u', credential: 'p' }])
  })
})

describe('stunServersFromRelay', () => {
  it('returns our-host STUN servers (no creds) for the direct attempt', () => {
    expect(
      stunServersFromRelay({ urls: ['turns:r'], username: 'u', credential: 'p', expiresAtMs: 1, stunUrls: ['stun:r:3478'] }),
    ).toEqual([{ urls: ['stun:r:3478'] }])
  })

  it('returns [] when the cloud offered no STUN (host candidates only)', () => {
    expect(stunServersFromRelay({ urls: ['turns:r'], username: 'u', credential: 'p', expiresAtMs: 1 })).toEqual([])
  })
})

describe('IcePathPolicy — one ICE attempt', () => {
  it('classifies a selected server-reflexive pair as direct', () => {
    const p = new IcePathPolicy()
    p.onConnected(false, 'srflx')
    expect(p.connectionMode).toBe('direct')
    expect(p.isConnected).toBe(true)
  })

  it('classifies a selected relay pair as relay without a second attempt', () => {
    const p = new IcePathPolicy()
    p.onConnected(false, 'relay')
    expect(p.connectionMode).toBe('relay')
  })

  it('keeps forced-relay qualification honest when stats are unavailable', () => {
    const p = new IcePathPolicy()
    p.onConnected(true, null)
    expect(p.connectionMode).toBe('relay')
  })

  it('a failed attempt reports failed', () => {
    const p = new IcePathPolicy()
    p.onFailed()
    expect(p.connectionMode).toBe('failed')
  })

  it('a late failure callback after a successful connect does not rewrite the measured path', () => {
    const p = new IcePathPolicy()
    p.onConnected(false, 'host')
    p.onFailed()
    expect(p.connectionMode).toBe('direct')
  })
})
