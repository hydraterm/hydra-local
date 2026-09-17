// CONTENT-BLIND guard (N1) — structural defense that rejects request bodies whose KEYS explicitly claim
// terminal/file/private-key semantics and VALUES containing obvious private-key material. Closed endpoint
// schemas exclude terminal-content fields, but this guard cannot infer the meaning of size-capped opaque
// signaling strings: an authorized peer could encode arbitrary text in one. This is defense in depth, not a
// claim that the control plane can make arbitrary user-controlled bytes semantically content-free.

/** Field-name patterns that must never appear in a control-plane request body. */
const FORBIDDEN_KEY_PATTERNS: RegExp[] = [
  /private[_-]?key/i,
  /secret[_-]?key/i,
  /priv[_-]?key/i,
  /\bprivkey\b/i,
  /pty/i,
  /terminal/i,
  /session[_-]?(output|bytes|stream|data)/i,
  /\bstdout\b/i,
  /\bstdin\b/i,
  /\bstderr\b/i,
  /\bfile[_-]?(content|bytes|data)\b/i,
  /\bgrid\b/i,
  /\bdamage\b/i,
  /scrollback/i,
  /keystroke/i,
  // S3a: a signaling request has no business carrying command/shell/env material.
  /\bcommand\b/i,
  /\bcmd\b/i,
  /\bargs\b/i,
  /\bcwd\b/i,
  /\benv\b/i,
]

/** Obvious private-key material in a VALUE (PEM blocks etc.). */
const FORBIDDEN_VALUE_PATTERNS: RegExp[] = [
  /-----BEGIN [A-Z ]*PRIVATE KEY-----/,
  /-----BEGIN OPENSSH PRIVATE KEY-----/,
]

export class ContentBlindViolation extends Error {
  constructor(public readonly reason: string) {
    super(`content-blind violation: ${reason}`)
    this.name = 'ContentBlindViolation'
  }
}

/**
 * Recursively reject terminal/private-key-shaped field names and obvious private-key values. Throws
 * ContentBlindViolation on the first hit. Depth/size-bounded so a hostile body can't exhaust us. Opaque
 * signaling values remain opaque and are governed by their endpoint-specific byte and lifetime limits.
 */
export function assertContentBlind(body: unknown, path = '$', depth = 0): void {
  if (depth > 12) throw new ContentBlindViolation(`nesting too deep at ${path}`)
  if (body === null || typeof body !== 'object') {
    if (typeof body === 'string') {
      for (const re of FORBIDDEN_VALUE_PATTERNS) {
        if (re.test(body)) throw new ContentBlindViolation(`private-key material in value at ${path}`)
      }
    }
    return
  }
  if (Array.isArray(body)) {
    if (body.length > 1000) throw new ContentBlindViolation(`oversized array at ${path}`)
    body.forEach((v, i) => assertContentBlind(v, `${path}[${i}]`, depth + 1))
    return
  }
  for (const [key, value] of Object.entries(body as Record<string, unknown>)) {
    for (const re of FORBIDDEN_KEY_PATTERNS) {
      if (re.test(key)) throw new ContentBlindViolation(`forbidden field "${key}" at ${path}`)
    }
    assertContentBlind(value, `${path}.${key}`, depth + 1)
  }
}

/**
 * Assert a string is plausibly PUBLIC key material (and definitely NOT a private key). We accept a
 * bounded base64/hex blob or an SSH/PEM PUBLIC key; we reject anything that looks private. The control
 * plane only ever stores public keys.
 */
export function assertPublicKeyMaterial(value: string): void {
  if (typeof value !== 'string' || value.length === 0 || value.length > 4096) {
    throw new ContentBlindViolation('public key missing or oversized')
  }
  for (const re of FORBIDDEN_VALUE_PATTERNS) {
    if (re.test(value)) throw new ContentBlindViolation('value is private-key material, not a public key')
  }
  if (/-----BEGIN [A-Z ]*PRIVATE/i.test(value)) {
    throw new ContentBlindViolation('value is a private key')
  }
  // Acceptable shapes: base64/hex blob, or an explicit public-key PEM/SSH form.
  const looksPublic =
    /^[A-Za-z0-9+/=_-]+$/.test(value) ||
    /-----BEGIN (PUBLIC KEY|CERTIFICATE)-----/.test(value) ||
    /^ssh-(ed25519|rsa) /.test(value)
  if (!looksPublic) {
    throw new ContentBlindViolation('value is not recognizable public-key material')
  }
}

/** Trim + length-cap a human label + drop control chars so it can't smuggle a payload. */
export function scrubLabel(raw: unknown): string {
  const s = typeof raw === 'string' ? raw : ''
  const printable = Array.from(s)
    .filter((ch) => {
      const c = ch.codePointAt(0) ?? 0
      return c >= 0x20 && c !== 0x7f // drop control chars + DEL
    })
    .join('')
  return printable.trim().slice(0, 64)
}
