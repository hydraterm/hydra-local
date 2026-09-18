import { describe, expect, it } from 'vitest'
import type { Cell, GridSnapshot } from '../protocol/web-protocol'
import { PaneSearchBank } from './pane-search-bank'

function cell(text: string, over: Partial<Cell> = {}): Cell {
  return {
    text,
    fg: { kind: 'named', name: 'foreground' },
    bg: { kind: 'named', name: 'background' },
    bold: false,
    italic: false,
    underline: 'none',
    inverse: false,
    strikeout: false,
    dim: false,
    hidden: false,
    width: 1,
    ...over,
  }
}

function grid(rows: Cell[][]): GridSnapshot {
  return {
    version: 2,
    generation: 'g',
    revision: 1,
    base_revision: 1,
    cols: rows[0]?.length ?? 0,
    rows: rows.length,
    rows_cells: rows,
    cursor_line: 0,
    cursor_col: 0,
    cursor_visible: true,
    cursor_shape: 'block',
    alt_screen: false,
    app_cursor: false,
    bracketed_paste: false,
    focus_reporting: false,
    mouse_report: false,
    mouse_drag: false,
    mouse_motion: false,
    mouse_sgr: false,
  }
}

function row(text: string): GridSnapshot {
  return grid([[...text].map((c) => cell(c))])
}

describe('PaneSearchBank', () => {
  it('keeps queries and matches independent per session', () => {
    const bank = new PaneSearchBank()

    bank.setGrid('s-a', row('alpha one alpha'))
    bank.setGrid('s-b', row('beta one beta'))
    bank.setQuery('s-a', 'alpha')
    bank.setQuery('s-b', 'beta')

    expect(bank.status('s-a')).toMatchObject({ query: 'alpha', count: 2, active: 1, label: '1/2' })
    expect(bank.status('s-b')).toMatchObject({ query: 'beta', count: 2, active: 1, label: '1/2' })
    expect(bank.matches('s-a').map((m) => m.text)).toEqual(['alpha', 'alpha'])
    expect(bank.matches('s-b').map((m) => m.text)).toEqual(['beta', 'beta'])
  })

  it('navigates each session without moving the other active match', () => {
    const bank = new PaneSearchBank()

    bank.setGrid('s-a', row('ok ok ok'))
    bank.setGrid('s-b', row('go go'))
    bank.setQuery('s-a', 'ok')
    bank.setQuery('s-b', 'go')

    bank.next('s-a')
    expect(bank.status('s-a').active).toBe(2)
    expect(bank.status('s-b').active).toBe(1)

    bank.prev('s-b')
    expect(bank.status('s-a').active).toBe(2)
    expect(bank.status('s-b').active).toBe(2)
  })

  it('updates one session grid without recomputing another session', () => {
    const bank = new PaneSearchBank()

    bank.setGrid('s-a', row('cat cat'))
    bank.setGrid('s-b', row('dog dog'))
    bank.setQuery('s-a', 'cat')
    bank.setQuery('s-b', 'dog')
    bank.setGrid('s-a', row('cat'))

    expect(bank.status('s-a')).toMatchObject({ count: 1, label: '1/1' })
    expect(bank.status('s-b')).toMatchObject({ count: 2, label: '1/2' })
  })

  it('allows a query before that session receives a grid', () => {
    const bank = new PaneSearchBank()

    bank.setQuery('s-late', 'ready')
    expect(bank.status('s-late')).toMatchObject({ query: 'ready', count: 0, label: 'No matches' })

    bank.setGrid('s-late', row('ready now'))
    expect(bank.status('s-late')).toMatchObject({ query: 'ready', count: 1, label: '1/1' })
  })

  it('clears individual sessions and all search state', () => {
    const bank = new PaneSearchBank()

    bank.setGrid('s-a', row('alpha'))
    bank.setGrid('s-b', row('beta'))
    expect(bank.size).toBe(2)
    expect(bank.has('s-a')).toBe(true)

    bank.clear('s-a')
    expect(bank.has('s-a')).toBe(false)
    expect(bank.size).toBe(1)
    expect(bank.status('s-a')).toMatchObject({ query: '', count: 0, label: '' })
    expect(bank.size).toBe(1)

    bank.clearAll()
    expect(bank.size).toBe(0)
  })
})
