import type { GridSnapshot } from '../protocol/web-protocol.js'

export interface TerminalSearchMatch {
  readonly row: number
  readonly startCol: number
  readonly endCol: number
  readonly text: string
}

export interface TerminalSearchOptions {
  readonly caseSensitive?: boolean
  readonly maxMatches?: number
}

interface SearchableLine {
  readonly text: string
  readonly cols: readonly number[]
}

const DEFAULT_MAX_MATCHES = 200

/** Visible, searchable text for each grid row. Hidden cells are spaces; wide-cell spacers are skipped. */
export function visibleGridLines(grid: GridSnapshot): string[] {
  return searchableLines(grid).map((line) => line.text)
}

/** Pure terminal-search foundation over the current visible grid. No DOM, no clipboard, no terminal bytes. */
export function findInGrid(grid: GridSnapshot, query: string, options: TerminalSearchOptions = {}): TerminalSearchMatch[] {
  const needleRaw = query.trim()
  if (!needleRaw) return []

  const caseSensitive = options.caseSensitive ?? false
  const maxMatches = Math.max(0, options.maxMatches ?? DEFAULT_MAX_MATCHES)
  if (maxMatches === 0) return []

  const needle = caseSensitive ? needleRaw : needleRaw.toLocaleLowerCase()
  const matches: TerminalSearchMatch[] = []
  const lines = searchableLines(grid)
  for (let row = 0; row < lines.length && matches.length < maxMatches; row++) {
    const haystack = caseSensitive ? lines[row].text : lines[row].text.toLocaleLowerCase()
    let from = 0
    while (matches.length < maxMatches) {
      const at = haystack.indexOf(needle, from)
      if (at === -1) break
      const end = at + needleRaw.length
      matches.push({
        row,
        startCol: lines[row].cols[at] ?? at,
        endCol: (lines[row].cols[end - 1] ?? end - 1) + 1,
        text: lines[row].text.slice(at, end),
      })
      from = at + Math.max(needle.length, 1)
    }
  }
  return matches
}

function searchableLines(grid: GridSnapshot): SearchableLine[] {
  return grid.rows_cells.map((row) => {
    let text = ''
    const cols: number[] = []
    for (let col = 0; col < row.length; col++) {
      const cell = row[col]
      if (cell.width === 0) continue
      const visible = cell.hidden ? ' '.repeat(Math.max(1, cell.width)) : cell.text
      text += visible
      for (let i = 0; i < visible.length; i++) cols.push(col)
    }
    return { text, cols }
  })
}

/** A status line for a search box: "" (no query), "No matches", or "<active>/<count>" (1-based). */
export interface TerminalSearchStatus {
  readonly query: string
  readonly count: number
  /** 1-based index of the active match, or 0 when there are none. */
  readonly active: number
  readonly label: string
}

/**
 * Navigation layer over findInGrid: holds the query + options, recomputes matches when the query or grid
 * changes, and tracks the ACTIVE match with wrap-around next()/prev(). Pure + DOM-free — the renderer/UI reads
 * `matches()`/`active()`/`status()` to draw highlights and a "3/7" counter without re-implementing search.
 */
export class TerminalSearch {
  private query = ''
  private options: TerminalSearchOptions
  private grid: GridSnapshot | null = null
  private results: TerminalSearchMatch[] = []
  private activeIndex = 0

  constructor(options: TerminalSearchOptions = {}) {
    this.options = options
  }

  /** Point at the current grid snapshot (re-runs the search). Call on every fresh snapshot. */
  setGrid(grid: GridSnapshot): void {
    this.grid = grid
    this.recompute()
  }

  /** Set the query (re-runs the search, resets the active match to the first). */
  setQuery(query: string): void {
    if (query === this.query) return
    this.query = query
    this.recompute()
  }

  private recompute(): void {
    this.results = this.grid ? findInGrid(this.grid, this.query, this.options) : []
    this.activeIndex = 0
  }

  matches(): readonly TerminalSearchMatch[] {
    return this.results
  }

  /** The currently-focused match, or null when there are none. */
  active(): TerminalSearchMatch | null {
    return this.results[this.activeIndex] ?? null
  }

  /** Advance to the next match (wraps to the first). Returns the new active match. */
  next(): TerminalSearchMatch | null {
    if (this.results.length === 0) return null
    this.activeIndex = (this.activeIndex + 1) % this.results.length
    return this.active()
  }

  /** Go to the previous match (wraps to the last). Returns the new active match. */
  prev(): TerminalSearchMatch | null {
    if (this.results.length === 0) return null
    this.activeIndex = (this.activeIndex - 1 + this.results.length) % this.results.length
    return this.active()
  }

  status(): TerminalSearchStatus {
    const count = this.results.length
    const active = count === 0 ? 0 : this.activeIndex + 1
    const label = this.query.trim() === '' ? '' : count === 0 ? 'No matches' : `${active}/${count}`
    return { query: this.query, count, active, label }
  }
}
