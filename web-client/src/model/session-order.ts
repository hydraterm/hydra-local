// Pure manual session-ordering model (roadmap §2#5 persistent session organization — the "ordering" gap).
// Browser-local: a user-chosen order over the session ids, applied on top of the daemon's order. Content-blind
// (ids only). DOM-free, storage-free — a store + controller + UI wire on top of this is a later slice.
//
// The order is stored as a list of ids. `applySessionOrder` is robust to drift: ids in the saved order that
// no longer exist are dropped, and sessions the daemon reports that aren't in the saved order are appended in
// daemon order (so a brand-new session shows up at the end, never lost).

/** Reorder `sessions` by the saved `order`; unknown saved ids are dropped, new sessions appended in daemon order. */
export function applySessionOrder(sessions: readonly string[], order: readonly string[]): string[] {
  const present = new Set(sessions)
  const seen = new Set<string>()
  const out: string[] = []
  for (const id of order) {
    if (present.has(id) && !seen.has(id)) {
      out.push(id)
      seen.add(id)
    }
  }
  for (const id of sessions) {
    if (!seen.has(id)) {
      out.push(id)
      seen.add(id)
    }
  }
  return out
}

/** Move one session up (-1) or down (+1) within the current effective order. Returns the new id order. */
export function moveSession(sessions: readonly string[], order: readonly string[], sessionId: string, delta: -1 | 1): string[] {
  const effective = applySessionOrder(sessions, order)
  const from = effective.indexOf(sessionId)
  if (from === -1) return effective
  const to = from + delta
  if (to < 0 || to >= effective.length) return effective // already at an edge → no-op
  const next = [...effective]
  ;[next[from], next[to]] = [next[to], next[from]]
  return next
}

/** Clean a parsed order value into a de-duped list of non-empty string ids (for storage round-trips). */
export function cleanSessionOrder(input: unknown): string[] {
  if (!Array.isArray(input)) return []
  const out: string[] = []
  for (const v of input) {
    if (typeof v !== 'string') continue
    const id = v.trim()
    if (id && !out.includes(id)) out.push(id)
  }
  return out
}
