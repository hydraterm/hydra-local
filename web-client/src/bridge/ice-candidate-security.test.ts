import { describe, it, expect } from 'vitest'
import { safeParseRemoteCandidate } from './ice-candidate-security'

describe('safeParseRemoteCandidate — signaling-boundary shape guard', () => {
  it('accepts a well-formed candidate init and keeps the known fields', () => {
    const raw = JSON.stringify({ candidate: 'candidate:1 1 udp 2122260223 192.168.1.2 54321 typ host', sdpMid: '0', sdpMLineIndex: 0, usernameFragment: 'abcd' })
    expect(safeParseRemoteCandidate(raw)).toEqual({
      candidate: 'candidate:1 1 udp 2122260223 192.168.1.2 54321 typ host',
      sdpMid: '0', sdpMLineIndex: 0, usernameFragment: 'abcd',
    })
  })

  it('allows the empty-string end-of-candidates sentinel', () => {
    expect(safeParseRemoteCandidate(JSON.stringify({ candidate: '', sdpMid: '0', sdpMLineIndex: 0 }))).toMatchObject({ candidate: '' })
  })

  it('STRIPS any unexpected fields the relay smuggled in (defense in depth)', () => {
    const raw = JSON.stringify({ candidate: 'candidate:x', sdpMid: '0', evil: 'rm -rf', __proto__: { polluted: true } })
    const out = safeParseRemoteCandidate(raw)!
    expect(out).toEqual({ candidate: 'candidate:x', sdpMid: '0' })
    expect('evil' in out).toBe(false)
  })

  it('rejects unparseable JSON / non-object / missing candidate', () => {
    expect(safeParseRemoteCandidate('not json')).toBeNull()
    expect(safeParseRemoteCandidate('[1,2,3]')).toBeNull() // array, not a candidate object
    expect(safeParseRemoteCandidate('"a string"')).toBeNull()
    expect(safeParseRemoteCandidate(JSON.stringify({ sdpMid: '0' }))).toBeNull() // no candidate field
    expect(safeParseRemoteCandidate(JSON.stringify({ candidate: 42 }))).toBeNull() // candidate not a string
  })

  it('rejects bad field types (sdpMid, sdpMLineIndex, usernameFragment)', () => {
    expect(safeParseRemoteCandidate(JSON.stringify({ candidate: 'c', sdpMid: 7 }))).toBeNull()
    expect(safeParseRemoteCandidate(JSON.stringify({ candidate: 'c', sdpMLineIndex: -1 }))).toBeNull()
    expect(safeParseRemoteCandidate(JSON.stringify({ candidate: 'c', sdpMLineIndex: 1.5 }))).toBeNull()
    expect(safeParseRemoteCandidate(JSON.stringify({ candidate: 'c', usernameFragment: 5 }))).toBeNull()
  })

  it('allows null for the optional fields (some stacks send null)', () => {
    expect(safeParseRemoteCandidate(JSON.stringify({ candidate: 'c', sdpMid: null, sdpMLineIndex: null }))).toEqual({ candidate: 'c', sdpMid: null, sdpMLineIndex: null })
  })
})
