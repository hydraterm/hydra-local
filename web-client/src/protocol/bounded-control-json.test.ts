import { describe, expect, it } from 'vitest'
import {
  MAX_BROWSER_CONTROL_JSON_ARRAY_ITEMS,
  MAX_BROWSER_CONTROL_JSON_BYTES,
  MAX_BROWSER_CONTROL_JSON_DEPTH,
  MAX_BROWSER_CONTROL_JSON_KEY_BYTES,
  MAX_BROWSER_CONTROL_JSON_MEMBERS,
  MAX_BROWSER_CONTROL_JSON_OBJECT_KEYS,
  MAX_BROWSER_CONTROL_JSON_STRING_BYTES,
  MAX_BROWSER_CONTROL_JSON_TOTAL_STRING_BYTES,
  controlJsonTextFitsByteLimit,
  parseBoundedControlJson,
} from './bounded-control-json'

describe('bounded browser control JSON', () => {
  it('admits a normal self-contained workspace update', () => {
    const parsed = parseBoundedControlJson(JSON.stringify({
      type: 'workspace_update',
      epoch: 7,
      sessions: ['s-1'],
      workspace_metadata: {
        projects: [{
          id: 'p-1',
          name: 'Project',
          root: '/workspace',
          windows: [{ id: 'w-1', panes: [{ id: 'pane-1', session_id: 's-1' }] }],
        }],
      },
    }))
    expect(parsed).toMatchObject({ ok: { type: 'workspace_update', epoch: 7 } })
  })

  it('rejects an over-budget text frame before parsing it', () => {
    const oversized = `{"type":"error","message":"${'x'.repeat(MAX_BROWSER_CONTROL_JSON_BYTES)}"}`
    expect(parseBoundedControlJson(oversized)).toEqual({ err: 'bytes' })
  })

  it('rejects independently oversized strings, arrays, and objects', () => {
    expect(parseBoundedControlJson(JSON.stringify({
      type: 'error',
      message: 'x'.repeat(MAX_BROWSER_CONTROL_JSON_STRING_BYTES + 1),
    }))).toEqual({ err: 'string_bytes' })

    expect(parseBoundedControlJson(JSON.stringify({
      type: 'sessions',
      ids: Array.from({ length: MAX_BROWSER_CONTROL_JSON_ARRAY_ITEMS + 1 }, () => 0),
    }))).toEqual({ err: 'array_items' })

    const tooManyKeys: Record<string, number> = { type: 1 }
    for (let i = 0; i < MAX_BROWSER_CONTROL_JSON_OBJECT_KEYS; i++) tooManyKeys[`k${i}`] = i
    expect(parseBoundedControlJson(JSON.stringify(tooManyKeys))).toEqual({ err: 'object_keys' })
  })

  it('admits exact per-container and aggregate-member boundaries, then refuses one more member', () => {
    const exactArray = Array.from({ length: MAX_BROWSER_CONTROL_JSON_ARRAY_ITEMS }, () => null)
    expect(parseBoundedControlJson(JSON.stringify({ exactArray }))).toHaveProperty('ok')

    const exactObject: Record<string, null> = {}
    for (let i = 0; i < MAX_BROWSER_CONTROL_JSON_OBJECT_KEYS; i++) exactObject[`k${i}`] = null
    expect(parseBoundedControlJson(JSON.stringify(exactObject))).toHaveProperty('ok')

    // The root contributes one member, the outer array contributes four, and the nested arrays contribute
    // the balance. Every individual array stays inside its own budget while the aggregate is exact / one over.
    const aggregate = (leafMembers: number) => ({
      groups: [
        Array.from({ length: MAX_BROWSER_CONTROL_JSON_ARRAY_ITEMS }, () => null),
        Array.from({ length: MAX_BROWSER_CONTROL_JSON_ARRAY_ITEMS }, () => null),
        Array.from({ length: MAX_BROWSER_CONTROL_JSON_ARRAY_ITEMS }, () => null),
        Array.from({ length: leafMembers }, () => null),
      ],
    })
    const exactLeaf = MAX_BROWSER_CONTROL_JSON_MEMBERS - 1 - 4 - 3 * MAX_BROWSER_CONTROL_JSON_ARRAY_ITEMS
    expect(parseBoundedControlJson(JSON.stringify(aggregate(exactLeaf)))).toHaveProperty('ok')
    expect(parseBoundedControlJson(JSON.stringify(aggregate(exactLeaf + 1)))).toEqual({ err: 'members' })
  })

  it('enforces exact individual, aggregate, and UTF-8 key string-byte boundaries', () => {
    expect(parseBoundedControlJson(JSON.stringify({
      a: 'x'.repeat(MAX_BROWSER_CONTROL_JSON_STRING_BYTES),
    }))).toHaveProperty('ok')

    // Object keys count toward the aggregate. Three values plus the one-byte key land exactly on the limit.
    const exactTotal = {
      a: [
        'x'.repeat(MAX_BROWSER_CONTROL_JSON_STRING_BYTES),
        'x'.repeat(MAX_BROWSER_CONTROL_JSON_STRING_BYTES),
        'x'.repeat(MAX_BROWSER_CONTROL_JSON_STRING_BYTES - 1),
      ],
    }
    expect(parseBoundedControlJson(JSON.stringify(exactTotal))).toHaveProperty('ok')
    exactTotal.a[2] += 'x'
    expect(parseBoundedControlJson(JSON.stringify(exactTotal))).toEqual({ err: 'total_string_bytes' })
    expect(MAX_BROWSER_CONTROL_JSON_TOTAL_STRING_BYTES).toBe(3 * MAX_BROWSER_CONTROL_JSON_STRING_BYTES)

    const exactUtf8Key = 'é'.repeat(MAX_BROWSER_CONTROL_JSON_KEY_BYTES / 2)
    expect(parseBoundedControlJson(JSON.stringify({ [exactUtf8Key]: null }))).toHaveProperty('ok')
    expect(parseBoundedControlJson(JSON.stringify({ [`${exactUtf8Key}é`]: null }))).toEqual({ err: 'key_bytes' })
  })

  it('counts UTF-8 bytes before parsing and rejects non-finite parsed numbers', () => {
    const prefix = '{"type":"x","padding":"'
    const suffix = '"}'
    const emoji = '💧' // four UTF-8 bytes, two UTF-16 code units
    const fixedBytes = new TextEncoder().encode(prefix + suffix + emoji).byteLength
    const exact = `${prefix}${'x'.repeat(MAX_BROWSER_CONTROL_JSON_BYTES - fixedBytes)}${emoji}${suffix}`
    expect(new TextEncoder().encode(exact)).toHaveLength(MAX_BROWSER_CONTROL_JSON_BYTES)
    expect(controlJsonTextFitsByteLimit(exact)).toBe(true)
    expect(controlJsonTextFitsByteLimit(`${exact}${emoji}`)).toBe(false)

    expect(parseBoundedControlJson('{"n":1.7976931348623157e308}')).toHaveProperty('ok')
    expect(parseBoundedControlJson('{"n":1e400}')).toEqual({ err: 'number' })
  })

  it('rejects excessive nesting with an iterative post-parse walk', () => {
    let nested: unknown = 'leaf'
    for (let i = 0; i < MAX_BROWSER_CONTROL_JSON_DEPTH; i++) nested = [nested]
    expect(parseBoundedControlJson(JSON.stringify({ type: 'nested', nested }))).toEqual({ err: 'depth' })
  })

  it('rejects malformed and non-object envelopes', () => {
    expect(parseBoundedControlJson('{')).toEqual({ err: 'syntax' })
    expect(parseBoundedControlJson('[]')).toEqual({ err: 'root' })
    expect(parseBoundedControlJson('null')).toEqual({ err: 'root' })
  })
})
