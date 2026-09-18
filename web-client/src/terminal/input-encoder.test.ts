// Input encoder tests — mirror of the client.rs key/paste/focus encoding tests.

import { describe, expect, it } from 'vitest'
import {
  encodeFocus,
  encodeKey,
  encodeMouse,
  encodePaste,
  encodePasteChunks,
  MAX_PASTE_BYTES,
  sanitizePastePrefix,
  type KeyEvent,
  type TermModes,
} from './input-encoder'

const normal: TermModes = { app_cursor: false, bracketed_paste: false, focus_reporting: false }
const appCursor: TermModes = { ...normal, app_cursor: true }

function ev(partial: Partial<KeyEvent> & { key: string }): KeyEvent {
  return { ctrlKey: false, metaKey: false, altKey: false, shiftKey: false, ...partial }
}

describe('encodeKey', () => {
  it('suppresses PTY encoding when Super/Cmd is held', () => {
    expect(encodeKey(ev({ key: 'c', metaKey: true }), normal)).toBeNull()
    expect(encodeKey(ev({ key: 'v', metaKey: true }), normal)).toBeNull()
  })

  it('encodes ctrl chords A..Z and symbols', () => {
    expect(encodeKey(ev({ key: 'a', ctrlKey: true }), normal)).toBe('\x01') // Ctrl-A
    expect(encodeKey(ev({ key: 'c', ctrlKey: true }), normal)).toBe('\x03') // Ctrl-C
    expect(encodeKey(ev({ key: 'z', ctrlKey: true }), normal)).toBe('\x1a') // Ctrl-Z
    expect(encodeKey(ev({ key: ' ', ctrlKey: true }), normal)).toBe('\x00') // Ctrl-Space
    expect(encodeKey(ev({ key: '[', ctrlKey: true }), normal)).toBe('\x1b')
    expect(encodeKey(ev({ key: '\\', ctrlKey: true }), normal)).toBe('\x1c')
    expect(encodeKey(ev({ key: ']', ctrlKey: true }), normal)).toBe('\x1d')
  })

  it('encodes mode-independent named keys', () => {
    expect(encodeKey(ev({ key: 'Enter' }), normal)).toBe('\r')
    expect(encodeKey(ev({ key: 'Tab' }), normal)).toBe('\t')
    expect(encodeKey(ev({ key: 'Backspace' }), normal)).toBe('\x7f')
    expect(encodeKey(ev({ key: 'Escape' }), normal)).toBe('\x1b')
    expect(encodeKey(ev({ key: 'Delete' }), normal)).toBe('\x1b[3~')
    expect(encodeKey(ev({ key: 'PageUp' }), normal)).toBe('\x1b[5~')
  })

  it('encodes function keys F1–F12 (xterm sequences, mode-independent)', () => {
    // F1–F4: SS3
    expect(encodeKey(ev({ key: 'F1' }), normal)).toBe('\x1bOP')
    expect(encodeKey(ev({ key: 'F2' }), normal)).toBe('\x1bOQ')
    expect(encodeKey(ev({ key: 'F3' }), normal)).toBe('\x1bOR')
    expect(encodeKey(ev({ key: 'F4' }), normal)).toBe('\x1bOS')
    // F5–F12: CSI tilde codes
    expect(encodeKey(ev({ key: 'F5' }), normal)).toBe('\x1b[15~')
    expect(encodeKey(ev({ key: 'F6' }), normal)).toBe('\x1b[17~')
    expect(encodeKey(ev({ key: 'F7' }), normal)).toBe('\x1b[18~')
    expect(encodeKey(ev({ key: 'F8' }), normal)).toBe('\x1b[19~')
    expect(encodeKey(ev({ key: 'F9' }), normal)).toBe('\x1b[20~')
    expect(encodeKey(ev({ key: 'F10' }), normal)).toBe('\x1b[21~')
    expect(encodeKey(ev({ key: 'F11' }), normal)).toBe('\x1b[23~')
    expect(encodeKey(ev({ key: 'F12' }), normal)).toBe('\x1b[24~')
    // mode-independent: appCursor doesn't change F-keys
    expect(encodeKey(ev({ key: 'F1' }), appCursor)).toBe('\x1bOP')
  })

  it('encodes arrows/Home/End by cursor mode', () => {
    expect(encodeKey(ev({ key: 'ArrowUp' }), normal)).toBe('\x1b[A')
    expect(encodeKey(ev({ key: 'ArrowUp' }), appCursor)).toBe('\x1bOA')
    expect(encodeKey(ev({ key: 'ArrowLeft' }), normal)).toBe('\x1b[D')
    expect(encodeKey(ev({ key: 'ArrowLeft' }), appCursor)).toBe('\x1bOD')
    expect(encodeKey(ev({ key: 'Home' }), normal)).toBe('\x1b[H')
    expect(encodeKey(ev({ key: 'Home' }), appCursor)).toBe('\x1bOH')
    expect(encodeKey(ev({ key: 'End' }), appCursor)).toBe('\x1bOF')
  })

  it('sends a printable char as itself, incl. unicode', () => {
    expect(encodeKey(ev({ key: 'a' }), normal)).toBe('a')
    expect(encodeKey(ev({ key: 'A', shiftKey: true }), normal)).toBe('A')
    expect(encodeKey(ev({ key: '界' }), normal)).toBe('界')
  })

  it('ignores bare modifier keys', () => {
    expect(encodeKey(ev({ key: 'Shift', shiftKey: true }), normal)).toBeNull()
    expect(encodeKey(ev({ key: 'Control', ctrlKey: true }), normal)).toBeNull()
    expect(encodeKey(ev({ key: 'Alt', altKey: true }), normal)).toBeNull()
  })

  it('Alt-as-Meta: ESC + base printable', () => {
    expect(encodeKey(ev({ key: 'b', altKey: true }), normal)).toBe('\x1bb')
  })
})

describe('encodePaste', () => {
  it('passes raw text through in normal mode', () => {
    expect(encodePaste('hello\nworld', false)).toBe('hello\nworld')
  })

  it('wraps once in bracketed-paste mode', () => {
    expect(encodePaste('hi', true)).toBe('\x1b[200~hi\x1b[201~')
  })

  it('strips NUL bytes', () => {
    expect(encodePaste('a\0b\0c', false)).toBe('abc')
  })

  it('guards against paste injection (strips embedded markers to a fixpoint)', () => {
    // an embedded end-marker would prematurely close our wrapper
    expect(encodePaste('safe\x1b[201~evil', true)).toBe('\x1b[200~safeevil\x1b[201~')
    // nested marker that would reconstitute after one pass
    const nested = 'x\x1b[20\x1b[201~1~y'
    const out = encodePaste(nested, true)!
    // exactly one leading 200~ and one trailing 201~, none in the middle
    expect(out.startsWith('\x1b[200~')).toBe(true)
    expect(out.endsWith('\x1b[201~')).toBe(true)
    expect(out.slice(6, -6).includes('\x1b[201~')).toBe(false)
    expect(out.slice(6, -6).includes('\x1b[200~')).toBe(false)
  })

  it('returns null for empty / all-NUL paste', () => {
    expect(encodePaste('', false)).toBeNull()
    expect(encodePaste('\0\0', false)).toBeNull()
  })

  it('preserves unicode + newlines', () => {
    expect(encodePaste('café\n世界', false)).toBe('café\n世界')
  })

  it('bounds the complete bracketed paste including both markers on a UTF-8 boundary', () => {
    const out = encodePaste('界'.repeat(MAX_PASTE_BYTES), true)!
    const bytes = new TextEncoder().encode(out)
    expect(bytes.byteLength).toBeLessThanOrEqual(MAX_PASTE_BYTES)
    expect(out.startsWith('\x1b[200~')).toBe(true)
    expect(out.endsWith('\x1b[201~')).toBe(true)
    expect(out.slice(6, -6).endsWith('界')).toBe(true)
  })

  it('chunks a remote bracketed paste into balanced UTF-8-safe frames under one aggregate burst cap', () => {
    const maxFrame = 64 * 1024
    const raw = '界'.repeat(MAX_PASTE_BYTES)
    const chunks = encodePasteChunks(raw, true, maxFrame)
    const encoder = new TextEncoder()

    expect(chunks.length).toBeGreaterThan(1)
    expect(chunks.every((chunk) => (
      chunk.startsWith('\x1b[200~') && chunk.endsWith('\x1b[201~') &&
      encoder.encode(chunk).byteLength <= maxFrame
    ))).toBe(true)
    expect(chunks.reduce((total, chunk) => total + encoder.encode(chunk).byteLength, 0))
      .toBeLessThanOrEqual(MAX_PASTE_BYTES)
    const inner = chunks.map((chunk) => chunk.slice(6, -6)).join('')
    expect(raw.startsWith(inner)).toBe(true)
    expect(inner.endsWith('界')).toBe(true)
  })

  it('bounds source scanning even when a huge clipboard contains only stripped input', () => {
    const raw = '\0'.repeat(2_000_000)
    const bounded = sanitizePastePrefix(raw, true, 1024)

    expect(bounded).toEqual({ text: '', bytes: 0, truncated: true })
  })
})

describe('encodeFocus', () => {
  it('emits focus sequences only when focus reporting is on', () => {
    expect(encodeFocus(true, normal)).toBeNull()
    expect(encodeFocus(false, normal)).toBeNull()
    const fr: TermModes = { ...normal, focus_reporting: true }
    expect(encodeFocus(true, fr)).toBe('\x1b[I')
    expect(encodeFocus(false, fr)).toBe('\x1b[O')
  })
})

describe('input-encoder · encodeMouse (mirror of client.rs encode_mouse)', () => {
  const sgr: TermModes = { ...normal, mouse_report: true, mouse_sgr: true }
  const x10: TermModes = { ...normal, mouse_report: true } // legacy, no SGR
  const drag: TermModes = { ...sgr, mouse_drag: true }
  const anyMotion: TermModes = { ...sgr, mouse_motion: true }

  it('returns null when no mouse mode is on', () => {
    expect(encodeMouse({ kind: 'press', button: 0 }, 3, 4, normal)).toBeNull()
  })

  it('SGR press/release: 0-based cells become 1-based; press=M, release=m', () => {
    // col 3,row 4 → x=4,y=5; left button (0)
    expect(encodeMouse({ kind: 'press', button: 0 }, 3, 4, sgr)).toBe('\x1b[<0;4;5M')
    expect(encodeMouse({ kind: 'release', button: 0 }, 3, 4, sgr)).toBe('\x1b[<0;4;5m')
    // right button = 2
    expect(encodeMouse({ kind: 'press', button: 2 }, 0, 0, sgr)).toBe('\x1b[<2;1;1M')
  })

  it('SGR wheel up/down use codes 64/65', () => {
    expect(encodeMouse({ kind: 'wheelUp' }, 0, 0, sgr)).toBe('\x1b[<64;1;1M')
    expect(encodeMouse({ kind: 'wheelDown' }, 0, 0, sgr)).toBe('\x1b[<65;1;1M')
  })

  it('SGR modifier bits: shift=4, alt=8, ctrl=16', () => {
    expect(encodeMouse({ kind: 'press', button: 0 }, 0, 0, sgr, { ctrl: true })).toBe('\x1b[<16;1;1M')
    expect(encodeMouse({ kind: 'press', button: 0 }, 0, 0, sgr, { shift: true, alt: true })).toBe('\x1b[<12;1;1M')
  })

  it('motion only reports under drag (held) / any-motion (no button)', () => {
    // held-button move needs 1002 or 1003; base = button + 32
    expect(encodeMouse({ kind: 'move', heldButton: 0 }, 0, 0, drag)).toBe('\x1b[<32;1;1M')
    // no-button move needs 1003; base = 3 + 32 = 35
    expect(encodeMouse({ kind: 'move', heldButton: null }, 0, 0, drag)).toBeNull() // drag ≠ motion
    expect(encodeMouse({ kind: 'move', heldButton: null }, 0, 0, anyMotion)).toBe('\x1b[<35;1;1M')
  })

  it('legacy X10: \\x1b[M + (cb+32, x+32, y+32); release keeps low bits = 3', () => {
    // press left at col0,row0 → cb=0 → bytes 32,33,33
    expect(encodeMouse({ kind: 'press', button: 0 }, 0, 0, x10)).toBe(String.fromCharCode(0x1b, 0x5b, 0x4d, 32, 33, 33))
    // release → low 2 bits set to 3 → cb=3 → byte 35
    expect(encodeMouse({ kind: 'release', button: 0 }, 0, 0, x10)).toBe(String.fromCharCode(0x1b, 0x5b, 0x4d, 35, 33, 33))
  })

  it('legacy X10 returns null past the 95-cell ASCII cap (SGR has no cap)', () => {
    expect(encodeMouse({ kind: 'press', button: 0 }, 200, 0, x10)).toBeNull()
    expect(encodeMouse({ kind: 'press', button: 0 }, 200, 0, sgr)).toBe('\x1b[<0;201;1M') // SGR fine
  })
})
