// Inspector-only seam between the wire-inspector panel (?inspect=1) and the live RemoteSession.
// The panel mounts at app start — before any session exists — so it can't hold a session reference;
// instead the session registers a fetcher here and publishes results, and the panel subscribes.
// Content-blind: entries are rows of the desktop's db-write.jsonl ledger (who/op/kind/id/fields/ctx
// — names and opaque ids only, never values/tokens/terminal bytes).

/** One parsed db-write.jsonl row, as received (already content-blind at the source). */
export type DbWriteEntry = Record<string, unknown>

type Fetcher = (count: number) => void
type Listener = (entries: DbWriteEntry[]) => void

let fetcher: Fetcher | null = null
const listeners: Listener[] = []

/** The live session registers (and on teardown, clears) the way to request the desktop ledger. */
export function setDbWriteFetcher(f: Fetcher | null): void {
  fetcher = f
}

/** Panel → session: request the last `count` ledger rows. False = no live session to ask. */
export function requestDbWrites(count = 200): boolean {
  if (!fetcher) return false
  fetcher(count)
  return true
}

/** Session → panel: a db_write_trace_result arrived. */
export function publishDbWrites(entries: DbWriteEntry[]): void {
  for (const l of [...listeners]) l(entries)
}

/** Panel subscribes; returns an unsubscribe fn. */
export function onDbWrites(l: Listener): () => void {
  listeners.push(l)
  return () => {
    const i = listeners.indexOf(l)
    if (i >= 0) listeners.splice(i, 1)
  }
}
