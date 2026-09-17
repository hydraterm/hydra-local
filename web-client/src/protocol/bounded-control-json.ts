/**
 * Independent browser admission for agent-originated control JSON.
 *
 * The enrolled desktop is trusted with terminal content, but a buggy or compromised agent must not be able to
 * hand an attached browser an unbounded JSON parse/walk. The byte ceiling matches the native peer's fixed
 * per-peer control-message budget; the post-parse budgets independently bound pathological structure inside
 * that envelope. Terminal payloads use the binary framing path and do not cross this decoder.
 */
export const MAX_BROWSER_CONTROL_JSON_BYTES = 8 * 1024 * 1024
export const MAX_BROWSER_CONTROL_JSON_DEPTH = 24
export const MAX_BROWSER_CONTROL_JSON_MEMBERS = 65_536
export const MAX_BROWSER_CONTROL_JSON_ARRAY_ITEMS = 16_384
export const MAX_BROWSER_CONTROL_JSON_OBJECT_KEYS = 256
export const MAX_BROWSER_CONTROL_JSON_STRING_BYTES = 2 * 1024 * 1024
export const MAX_BROWSER_CONTROL_JSON_TOTAL_STRING_BYTES = 6 * 1024 * 1024
export const MAX_BROWSER_CONTROL_JSON_KEY_BYTES = 128

export type ControlJsonLimit =
  | 'bytes'
  | 'syntax'
  | 'root'
  | 'depth'
  | 'members'
  | 'array_items'
  | 'object_keys'
  | 'key_bytes'
  | 'string_bytes'
  | 'total_string_bytes'
  | 'number'

export type BoundedControlJson =
  | { ok: Record<string, unknown> }
  | { err: ControlJsonLimit }

const encoder = new TextEncoder()

function boundedUtf8Bytes(value: string, maximum: number): number | null {
  // UTF-8 is never shorter than the UTF-16 code-unit count for JSON text. Avoid a second allocation when the
  // cheap lower bound already proves that the value is outside the contract.
  if (value.length > maximum) return null
  const bytes = encoder.encode(value).byteLength
  return bytes <= maximum ? bytes : null
}

/** Cheap transport-layer admission used before a DataChannel text frame reaches any product callback. */
export function controlJsonTextFitsByteLimit(json: string): boolean {
  return boundedUtf8Bytes(json, MAX_BROWSER_CONTROL_JSON_BYTES) !== null
}

/** Parse one text DataChannel control frame under independent byte and aggregate structure budgets. */
export function parseBoundedControlJson(json: string): BoundedControlJson {
  if (!controlJsonTextFitsByteLimit(json)) return { err: 'bytes' }

  let root: unknown
  try {
    root = JSON.parse(json)
  } catch {
    return { err: 'syntax' }
  }
  if (typeof root !== 'object' || root === null || Array.isArray(root)) return { err: 'root' }

  let members = 0
  let totalStringBytes = 0
  const pending: Array<{ value: unknown; depth: number }> = [{ value: root, depth: 1 }]

  while (pending.length > 0) {
    const current = pending.pop()!
    if (current.depth > MAX_BROWSER_CONTROL_JSON_DEPTH) return { err: 'depth' }

    if (typeof current.value === 'string') {
      const bytes = boundedUtf8Bytes(current.value, MAX_BROWSER_CONTROL_JSON_STRING_BYTES)
      if (bytes === null) return { err: 'string_bytes' }
      totalStringBytes += bytes
      if (totalStringBytes > MAX_BROWSER_CONTROL_JSON_TOTAL_STRING_BYTES) {
        return { err: 'total_string_bytes' }
      }
      continue
    }
    if (typeof current.value === 'number') {
      if (!Number.isFinite(current.value)) return { err: 'number' }
      continue
    }
    if (typeof current.value !== 'object' || current.value === null) continue

    if (Array.isArray(current.value)) {
      if (current.value.length > MAX_BROWSER_CONTROL_JSON_ARRAY_ITEMS) return { err: 'array_items' }
      members += current.value.length
      if (members > MAX_BROWSER_CONTROL_JSON_MEMBERS) return { err: 'members' }
      for (const value of current.value) pending.push({ value, depth: current.depth + 1 })
      continue
    }

    const object = current.value as Record<string, unknown>
    let ownKeys = 0
    // Do not materialize Object.entries/Object.keys here. The parsed object already owns the attacker-provided
    // properties; allocating a second unbounded key/value array before checking the 256-key budget would defeat
    // the purpose of the post-parse admission walk.
    for (const key in object) {
      if (!Object.prototype.hasOwnProperty.call(object, key)) continue
      ownKeys++
      if (ownKeys > MAX_BROWSER_CONTROL_JSON_OBJECT_KEYS) return { err: 'object_keys' }
      members++
      if (members > MAX_BROWSER_CONTROL_JSON_MEMBERS) return { err: 'members' }
      const keyBytes = boundedUtf8Bytes(key, MAX_BROWSER_CONTROL_JSON_KEY_BYTES)
      if (keyBytes === null) return { err: 'key_bytes' }
      totalStringBytes += keyBytes
      if (totalStringBytes > MAX_BROWSER_CONTROL_JSON_TOTAL_STRING_BYTES) {
        return { err: 'total_string_bytes' }
      }
      pending.push({ value: object[key], depth: current.depth + 1 })
    }
  }

  return { ok: root as Record<string, unknown> }
}
