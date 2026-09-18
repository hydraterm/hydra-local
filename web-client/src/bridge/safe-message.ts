// One shared content-blind redactor for any free-text error/status string that might carry secret material
// (tokens, cookies, signatures, keys, JWT-ish blobs, oversized SDP/ICE/frame chunks, named secret fields). It
// runs at the BOUNDARY where untrusted agent/cloud text would enter view.error or a diagnostics surface, so the
// raw text never lands in the observable view — not just in the render layer. Bounded to a safe length.
//
// Mirrors the logic previously duplicated in readiness.ts (safeStatusDetail) and diagnostics-view.ts
// (supportMessage); those can delegate to this so the redaction can't drift.

const MAX_LEN = 180

export function safeMessage(s: string): string {
  const redacted = s
    .replace(/\b(bearer)\s+[^\s,;]+/gi, '$1 [redacted]')
    .replace(/\b(token|secret|signature|private[_-]?key|cookie|password|reason)\s*[:=]\s*[^\s,;]+/gi, '$1=[redacted]')
    .split(/\s+/)
    .map((part) => {
      if (part.length > 120) return '[redacted]' // SDP/ICE/frame-sized blobs
      if (/^[A-Za-z0-9_-]{20,}\.[A-Za-z0-9_-]{20,}$/.test(part)) return '[redacted]' // JWT-ish
      if (/-----BEGIN/.test(part)) return '[redacted]' // PEM
      return part
    })
    .join(' ')
  return redacted.length > MAX_LEN ? `${redacted.slice(0, MAX_LEN - 3)}...` : redacted
}
