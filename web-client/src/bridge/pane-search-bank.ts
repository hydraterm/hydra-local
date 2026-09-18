import type { GridSnapshot } from '../protocol/web-protocol.js'
import {
  TerminalSearch,
  type TerminalSearchMatch,
  type TerminalSearchOptions,
  type TerminalSearchStatus,
} from '../terminal/search.js'

const EMPTY_STATUS: TerminalSearchStatus = { query: '', count: 0, active: 0, label: '' }

/** Per-session search state for N-up panes. Keeps each pane's query, matches, and active match independent. */
export class PaneSearchBank {
  private readonly searches = new Map<string, TerminalSearch>()

  constructor(private readonly options: TerminalSearchOptions = {}) {}

  setGrid(sessionId: string, grid: GridSnapshot): TerminalSearch {
    const search = this.searchFor(sessionId)
    search.setGrid(grid)
    return search
  }

  setQuery(sessionId: string, query: string): TerminalSearch {
    const search = this.searchFor(sessionId)
    search.setQuery(query)
    return search
  }

  matches(sessionId: string): readonly TerminalSearchMatch[] {
    return this.searches.get(sessionId)?.matches() ?? []
  }

  active(sessionId: string): TerminalSearchMatch | null {
    return this.searches.get(sessionId)?.active() ?? null
  }

  next(sessionId: string): TerminalSearchMatch | null {
    return this.searches.get(sessionId)?.next() ?? null
  }

  prev(sessionId: string): TerminalSearchMatch | null {
    return this.searches.get(sessionId)?.prev() ?? null
  }

  status(sessionId: string): TerminalSearchStatus {
    return this.searches.get(sessionId)?.status() ?? EMPTY_STATUS
  }

  clear(sessionId: string): void {
    this.searches.delete(sessionId)
  }

  clearAll(): void {
    this.searches.clear()
  }

  has(sessionId: string): boolean {
    return this.searches.has(sessionId)
  }

  get size(): number {
    return this.searches.size
  }

  private searchFor(sessionId: string): TerminalSearch {
    const existing = this.searches.get(sessionId)
    if (existing) return existing
    const created = new TerminalSearch(this.options)
    this.searches.set(sessionId, created)
    return created
  }
}
