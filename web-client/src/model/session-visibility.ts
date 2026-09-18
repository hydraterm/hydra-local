// Pure browser-local session visibility model (roadmap §2#5 persistent session organization). This is the
// safe, non-destructive half of trash/delete: hidden ids are filtered from the browser list only; daemon
// sessions are never killed here.

export function cleanHiddenSessions(input: unknown): string[] {
  if (!Array.isArray(input)) return []
  const out: string[] = []
  for (const v of input) {
    if (typeof v !== 'string') continue
    const id = v.trim()
    if (id && !out.includes(id)) out.push(id)
  }
  return out
}

export function visibleSessions(sessions: readonly string[], hidden: readonly string[]): string[] {
  const hiddenSet = new Set(cleanHiddenSessions(hidden))
  return sessions.filter((id) => !hiddenSet.has(id))
}

export function hideSession(sessions: readonly string[], hidden: readonly string[], sessionId: string): string[] {
  const id = sessionId.trim()
  if (!id || !sessions.includes(id)) return cleanHiddenSessions(hidden)
  const current = cleanHiddenSessions(hidden)
  return current.includes(id) ? current : [...current, id]
}

export function unhideSession(hidden: readonly string[], sessionId: string): string[] {
  const id = sessionId.trim()
  if (!id) return cleanHiddenSessions(hidden)
  return cleanHiddenSessions(hidden).filter((x) => x !== id)
}
