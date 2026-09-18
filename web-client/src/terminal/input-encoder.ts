// Mode-aware input encoder — TS port of the key/paste/focus encoding in
// maestro-renderer/src/client.rs (encode_key / encode_named / ctrl_byte / encode_paste / encode_focus).
//
// The byte SEQUENCES are identical to the native renderer; only the INPUT differs: here we read a
// browser `KeyboardEvent` (event.key, modifier booleans) instead of winit's Key/Modifiers. The encoded
// string is the literal byte payload for a `Write { id, data }` request (the daemon forwards data's raw
// UTF-8 bytes to the PTY unchanged).
//
// Keep the sequences in lockstep with client.rs.

// The terminal modes that affect encoding — fed from the latest accepted GridSnapshot.
export interface TermModes {
  app_cursor: boolean
  bracketed_paste: boolean
  focus_reporting: boolean
  // Mouse reporting modes (DECSET 1000/1002/1003/1006). Optional so existing 3-field callers still type-check;
  // absent = off. Fed from the GridSnapshot's mouse_* flags.
  mouse_report?: boolean
  mouse_drag?: boolean // 1002: report motion while a button is held
  mouse_motion?: boolean // 1003: report all motion
  mouse_sgr?: boolean // 1006: SGR extended coordinates
}

/** A terminal mouse event to encode. Coordinates are 0-based cell col/row (converted to 1-based on the wire). */
export type MouseEvent2 =
  | { kind: 'press'; button: 0 | 1 | 2 } // left/middle/right
  | { kind: 'release'; button: 0 | 1 | 2 }
  | { kind: 'wheelUp' }
  | { kind: 'wheelDown' }
  | { kind: 'move'; heldButton: 0 | 1 | 2 | null }

// Minimal view of a browser keyboard event (so this is testable without a DOM).
export interface KeyEvent {
  key: string // KeyboardEvent.key, e.g. "a", "Enter", "ArrowUp", " "
  ctrlKey: boolean
  metaKey: boolean // Cmd on macOS / Windows key — treated as Super (suppress PTY encoding)
  altKey: boolean
  shiftKey: boolean
}

/** Hard cap on a single paste, mirror of client.rs MAX_PASTE_BYTES (1 MiB). */
export const MAX_PASTE_BYTES = 1024 * 1024

const ESC = ''
const BRACKETED_PASTE_START = '\x1b[200~'
const BRACKETED_PASTE_END = '\x1b[201~'
const BRACKETED_PASTE_WRAPPER_BYTES =
  new TextEncoder().encode(BRACKETED_PASTE_START + BRACKETED_PASTE_END).byteLength

// Map a browser KeyboardEvent to the bytes to send to the PTY, or null to send nothing.
// Order mirrors encode_key: Super suppression → Ctrl chords → named keys (mode-aware) → Alt-as-Meta →
// printable text.
export function encodeKey(ev: KeyEvent, modes: TermModes): string | null {
  // Command/Super suppresses PTY encoding entirely — app shortcuts (copy/paste/close) own those.
  if (ev.metaKey) return null

  // Ctrl chords.
  if (ev.ctrlKey) {
    const b = ctrlByte(ev.key)
    if (b !== null) return String.fromCharCode(b)
    if (ev.key === ' ' || ev.key === 'Spacebar') return '\x00'
  }

  // Named keys (arrows + Home/End are mode-dependent).
  const named = encodeNamed(ev.key, modes.app_cursor)
  if (named !== null) return named

  // Alt/Option-as-Meta: ESC + the printable base key (so Option-b → ESC b). In a browser, when Alt is
  // held, event.key is often the composed glyph; we only ESC-prefix a single non-control char.
  if (ev.altKey) {
    const c = singlePrintable(ev.key)
    if (c !== null) return ESC + c
  }

  // Printable text last. A single-character event.key IS the printable (already reflects Shift/AltGr).
  if (ev.key.length >= 1 && !isNamedKey(ev.key) && singlePrintableMulti(ev.key)) {
    return ev.key
  }
  return null
}

// Ctrl-A..Z = 0x01..0x1a; symbol chords [ \ ] ^ _ = 0x1b..0x1f. (Ctrl-Space handled by caller.)
function ctrlByte(key: string): number | null {
  if (key.length !== 1) return null
  const c = key
  if (c >= 'a' && c <= 'z') return c.charCodeAt(0) & 0x1f
  if (c >= 'A' && c <= 'Z') return c.toLowerCase().charCodeAt(0) & 0x1f
  switch (c) {
    case '[':
      return 0x1b
    case '\\':
      return 0x1c
    case ']':
      return 0x1d
    case '^':
      return 0x1e
    case '_':
      return 0x1f
    default:
      return null
  }
}

// Mode-aware named-key sequences. Arrows + Home/End switch normal `\x1b[_` vs application `\x1bO_`.
function encodeNamed(key: string, appCursor: boolean): string | null {
  switch (key) {
    case 'Enter':
      return '\r'
    case 'Tab':
      return '\t'
    case 'Backspace':
      return '\x7f'
    case 'Escape':
      return '\x1b'
    case 'ArrowUp':
      return appCursor ? '\x1bOA' : '\x1b[A'
    case 'ArrowDown':
      return appCursor ? '\x1bOB' : '\x1b[B'
    case 'ArrowRight':
      return appCursor ? '\x1bOC' : '\x1b[C'
    case 'ArrowLeft':
      return appCursor ? '\x1bOD' : '\x1b[D'
    case 'Home':
      return appCursor ? '\x1bOH' : '\x1b[H'
    case 'End':
      return appCursor ? '\x1bOF' : '\x1b[F'
    case 'Insert':
      return '\x1b[2~'
    case 'Delete':
      return '\x1b[3~'
    case 'PageUp':
      return '\x1b[5~'
    case 'PageDown':
      return '\x1b[6~'
    // Function keys (xterm). F1–F4 use SS3 (\x1bO…); F5–F12 use CSI tilde codes. Mode-independent.
    case 'F1':
      return '\x1bOP'
    case 'F2':
      return '\x1bOQ'
    case 'F3':
      return '\x1bOR'
    case 'F4':
      return '\x1bOS'
    case 'F5':
      return '\x1b[15~'
    case 'F6':
      return '\x1b[17~'
    case 'F7':
      return '\x1b[18~'
    case 'F8':
      return '\x1b[19~'
    case 'F9':
      return '\x1b[20~'
    case 'F10':
      return '\x1b[21~'
    case 'F11':
      return '\x1b[23~'
    case 'F12':
      return '\x1b[24~'
    default:
      return null
  }
}

const NAMED_KEYS = new Set([
  'Enter', 'Tab', 'Backspace', 'Escape', 'ArrowUp', 'ArrowDown', 'ArrowRight', 'ArrowLeft',
  'Home', 'End', 'Insert', 'Delete', 'PageUp', 'PageDown', 'Shift', 'Control', 'Alt', 'Meta',
  'CapsLock', 'F1', 'F2', 'F3', 'F4', 'F5', 'F6', 'F7', 'F8', 'F9', 'F10', 'F11', 'F12',
])
function isNamedKey(key: string): boolean {
  return NAMED_KEYS.has(key)
}

// Single non-control char (for Alt-as-Meta), else null.
function singlePrintable(s: string): string | null {
  if ([...s].length !== 1) return null
  const code = s.codePointAt(0)!
  if (code < 0x20 || code === 0x7f) return null
  return s
}
// Looser: any non-empty printable text (may be multi-codepoint for IME-composed glyphs).
function singlePrintableMulti(s: string): boolean {
  if (s.length === 0) return false
  // Reject if it's a single control char.
  if (s.length === 1) {
    const code = s.charCodeAt(0)
    if (code < 0x20 || code === 0x7f) return false
  }
  return true
}

// Build the bytes for a paste under current modes (mirror of encode_paste). Strips NUL; under
// bracketed-paste strips any embedded \x1b[200~/\x1b[201~ to a fixpoint (paste-injection guard) and
// wraps EXACTLY once; truncates to MAX_PASTE_BYTES on a UTF-8 boundary. Returns null to send nothing.
export function encodePaste(raw: string, bracketedPaste: boolean): string | null {
  // The agent's token bucket counts the complete TerminalInput payload, including bracket markers. Keeping the
  // content alone at 1 MiB would make the final marker exceed the burst allowance and risk leaving the PTY inside
  // bracketed-paste mode. The whole logical paste must fit the shared 1 MiB contract.
  const contentLimit = bracketedPaste
    ? MAX_PASTE_BYTES - BRACKETED_PASTE_WRAPPER_BYTES
    : MAX_PASTE_BYTES
  const cleaned = sanitizePastePrefix(raw, bracketedPaste, contentLimit).text
  if (cleaned.length === 0) return null
  return bracketedPaste ? `${BRACKETED_PASTE_START}${cleaned}${BRACKETED_PASTE_END}` : cleaned
}

/**
 * Prepare a remote paste as independently safe input operations. Every bracketed chunk has its own balanced
 * start/end pair and fits one agent input frame. The aggregate wire payload, including every repeated wrapper,
 * remains within the agent's 1 MiB burst allowance. This prevents a later rate refusal from stranding the PTY in
 * bracketed-paste mode while preserving the exact UTF-8 prefix and order of all admitted content.
 */
export function encodePasteChunks(raw: string, bracketedPaste: boolean, maxPayloadBytes: number): string[] {
  if (!Number.isSafeInteger(maxPayloadBytes) || maxPayloadBytes <= 0) {
    throw new RangeError('invalid paste chunk bound')
  }
  if (bracketedPaste && maxPayloadBytes <= BRACKETED_PASTE_WRAPPER_BYTES) {
    throw new RangeError('paste chunk bound cannot fit bracket markers')
  }
  const cleaned = sanitizePastePrefix(raw, bracketedPaste, MAX_PASTE_BYTES).text
  let offset = 0
  let aggregateBudget = MAX_PASTE_BYTES
  const out: string[] = []
  while (offset < cleaned.length) {
    const wrapperBytes = bracketedPaste ? BRACKETED_PASTE_WRAPPER_BYTES : 0
    if (aggregateBudget <= wrapperBytes) break
    const contentBudget = Math.min(maxPayloadBytes - wrapperBytes, aggregateBudget - wrapperBytes)
    const prefix = utf8Prefix(cleaned, offset, contentBudget)
    if (prefix.end === offset) break
    const content = cleaned.slice(offset, prefix.end)
    const payload = bracketedPaste
      ? `${BRACKETED_PASTE_START}${content}${BRACKETED_PASTE_END}`
      : content
    const payloadBytes = prefix.bytes + wrapperBytes
    if (payloadBytes > maxPayloadBytes || payloadBytes > aggregateBudget) break
    out.push(payload)
    aggregateBudget -= payloadBytes
    offset = prefix.end
  }
  return out
}

export interface SanitizedPastePrefix {
  readonly text: string
  readonly bytes: number
  /** True when the source/output work bound stopped scanning before the clipboard string ended. */
  readonly truncated: boolean
}

/**
 * Strip NUL and (in bracketed mode) embedded bracket markers while retaining only a bounded UTF-8 prefix.
 * The scan itself is capped at four source code units per admitted byte, so a huge clipboard made entirely of
 * stripped input cannot turn a small wire cap into an unbounded preprocessing allocation/CPU loop.
 *
 * `pending` retains the last five code units, which is enough to remove a six-byte marker even when removing one
 * marker joins two fragments into another. Committed output can therefore never contain either marker and no
 * repeated whole-string replace/fixpoint allocation is needed.
 */
export function sanitizePastePrefix(
  raw: string,
  bracketedPaste: boolean,
  maxBytes: number,
): SanitizedPastePrefix {
  if (!Number.isSafeInteger(maxBytes) || maxBytes < 0) throw new RangeError('invalid paste byte bound')
  const maxScannedCodeUnits = Math.min(raw.length, Math.max(64, maxBytes * 4))
  const markers = bracketedPaste ? [BRACKETED_PASTE_START, BRACKETED_PASTE_END] as const : []
  const chunks: string[] = []
  let committed = ''
  let pending = ''
  let bytes = 0
  let offset = 0

  const commit = (text: string): void => {
    committed += text
    if (committed.length >= 4096) {
      chunks.push(committed)
      committed = ''
    }
  }

  while (offset < maxScannedCodeUnits) {
    let skippedMarker = false
    for (const marker of markers) {
      if (raw.startsWith(marker, offset)) {
        offset += marker.length
        skippedMarker = true
        break
      }
    }
    if (skippedMarker) continue

    const codePoint = raw.codePointAt(offset)!
    const width = codePoint > 0xffff ? 2 : 1
    if (offset + width > maxScannedCodeUnits) break
    offset += width
    if (codePoint === 0) continue
    const charBytes = utf8CodePointBytes(codePoint)
    if (bytes + charBytes > maxBytes) {
      offset -= width
      break
    }
    const ch = String.fromCodePoint(codePoint)
    pending += ch
    bytes += charBytes

    if (bracketedPaste && (pending.endsWith(BRACKETED_PASTE_START) || pending.endsWith(BRACKETED_PASTE_END))) {
      pending = pending.slice(0, -BRACKETED_PASTE_START.length)
      bytes -= BRACKETED_PASTE_START.length
    }
    while (pending.length > BRACKETED_PASTE_START.length - 1) {
      const first = pending.codePointAt(0)!
      const firstWidth = first > 0xffff ? 2 : 1
      commit(pending.slice(0, firstWidth))
      pending = pending.slice(firstWidth)
    }
  }
  commit(pending)
  chunks.push(committed)
  return { text: chunks.join(''), bytes, truncated: offset < raw.length }
}

// Focus change (mirror of encode_focus): \x1b[I on focus-in / \x1b[O on focus-out, only when
// focus-reporting is on.
export function encodeFocus(focused: boolean, modes: TermModes): string | null {
  if (!modes.focus_reporting) return null
  return focused ? '\x1b[I' : '\x1b[O'
}

// Mouse reporting (TS port of client.rs encode_mouse). Emits an SGR (1006) or legacy X10 report to the PTY when a
// mouse mode is active, so TUIs (vim, tmux, htop, less -S) receive clicks/drags/wheel. col/row are 0-based cells.
// Returns null when no mouse mode is on, or (legacy path only) when coordinates exceed the 95-cell ASCII cap.
export function encodeMouse(
  event: MouseEvent2,
  col: number,
  row: number,
  modes: TermModes,
  mods: { shift?: boolean; alt?: boolean; ctrl?: boolean } = {},
): string | null {
  const report = !!modes.mouse_report
  const drag = !!modes.mouse_drag
  const motion = !!modes.mouse_motion
  const sgr = !!modes.mouse_sgr
  if (!report && !drag && !motion) return null

  // Resolve the base button code + whether this is a release (release only matters for the legacy/SGR final byte).
  let base: number
  let isRelease = false
  switch (event.kind) {
    case 'press':
      base = event.button
      break
    case 'release':
      base = event.button
      isRelease = true
      break
    case 'wheelUp':
      base = 64
      break
    case 'wheelDown':
      base = 65
      break
    case 'move': {
      // Motion is only reported under 1002 (button held) or 1003 (any motion).
      if (!drag && !motion) return null
      if (event.heldButton !== null) {
        base = event.heldButton + 32 // motion bit (32) + button
      } else {
        if (!motion) return null // no-button motion needs 1003
        base = 3 + 32 // 3 = "no button", + motion bit
      }
      break
    }
  }

  // Modifier bits: shift=4, alt(meta)=8, ctrl=16.
  const modBits = (mods.shift ? 4 : 0) + (mods.alt ? 8 : 0) + (mods.ctrl ? 16 : 0)
  const cb = base | modBits

  // Wire coordinates are 1-based.
  const x = Math.max(0, col) + 1
  const y = Math.max(0, row) + 1

  if (sgr) {
    // SGR (1006): \x1b[<cb;x;y then 'M' (press/motion/wheel) or 'm' (release).
    return `\x1b[<${cb};${x};${y}${isRelease ? 'm' : 'M'}`
  }
  // Legacy X10: \x1b[M + 3 bytes (cb+32, x+32, y+32). Release = button 3 (low 2 bits = 3), keep motion/mod bits.
  const cbLegacy = isRelease ? (cb & ~0b11) | 0b11 : cb
  const bb = 32 + cbLegacy
  const bx = 32 + x
  const by = 32 + y
  // Byte-safety: each value+32 must stay ASCII (≤127) or UTF-8 would split it into 2 bytes and corrupt the report.
  if (bb > 127 || bx > 127 || by > 127) return null
  return String.fromCharCode(0x1b, 0x5b, 0x4d, bb, bx, by)
}

/** Return the largest UTF-8-safe prefix starting at `start` without encoding the unbounded suffix. */
export function utf8Prefix(s: string, start: number, maxBytes: number): { end: number; bytes: number } {
  if (!Number.isSafeInteger(start) || start < 0 || start > s.length || !Number.isSafeInteger(maxBytes) || maxBytes < 0) {
    throw new RangeError('invalid UTF-8 prefix bound')
  }
  let end = start
  let bytes = 0
  while (end < s.length) {
    const codePoint = s.codePointAt(end)!
    const width = codePoint > 0xffff ? 2 : 1
    const nextBytes = utf8CodePointBytes(codePoint)
    if (bytes + nextBytes > maxBytes) break
    end += width
    bytes += nextBytes
  }
  return { end, bytes }
}

function utf8CodePointBytes(codePoint: number): number {
  if (codePoint <= 0x7f) return 1
  if (codePoint <= 0x7ff) return 2
  if (codePoint <= 0xffff) return 3
  return 4
}
