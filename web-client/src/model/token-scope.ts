// Client-side token-scope sanity check (defense in depth). The cloud mints a short-lived, device-scoped token
// for the auth{token} handshake; the AGENT is the authority that verifies the signature. This validator does
// NOT verify the signature — it only reads the (unverified) JWT payload to catch CLEAR contract violations
// before we present the token: an already-expired token, or one scoped to a DIFFERENT desktop than the one we
// asked for. It fails CLOSED on those (mirrors the SDP fail-closed guard), and fails OPEN on anything it can't
// confidently judge (opaque/non-JWT tokens, missing claims) — the agent still verifies, so we never block a
// token we merely can't introspect.
//
// Content-blind: it returns a stable reason CODE only, never the token bytes or any claim values.

export type TokenScopeResult = { ok: true } | { ok: false; reason: 'expired' | 'wrong-device' }

/** Decode a JWT payload (the middle segment) without verifying the signature. Returns null when the token is
 * not a parseable 3-part JWT or the payload isn't JSON — callers treat that as "can't judge" (fail open). */
function decodeJwtPayload(token: string): Record<string, unknown> | null {
  const parts = token.split('.')
  if (parts.length !== 3) return null
  try {
    // base64url → base64, then decode. atob is available in browsers; guard for non-DOM (tests/SSR).
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/')
    const json = typeof atob === 'function' ? atob(b64) : Buffer.from(b64, 'base64').toString('binary')
    const payload = JSON.parse(json)
    return payload && typeof payload === 'object' ? (payload as Record<string, unknown>) : null
  } catch {
    return null
  }
}

/**
 * Validate that a freshly-minted token is usable for the desktop we asked for, BEFORE presenting it:
 *  - not already expired (`exp`, seconds since epoch — the short-lived contract),
 *  - scoped to `expectedDeviceId` when the payload names a device (`aud` / `device_id` / `dev`).
 * Fails closed on a clear expiry/scope violation; otherwise (opaque token, missing claims) returns ok.
 * `nowMs` is injected for deterministic tests.
 */
export function validateTokenScope(token: string, expectedDeviceId: string, nowMs: number): TokenScopeResult {
  const payload = decodeJwtPayload(token)
  if (!payload) return { ok: true } // not a JWT we can introspect → let the agent verify (fail open)

  const exp = payload.exp
  if (typeof exp === 'number' && exp * 1000 <= nowMs) return { ok: false, reason: 'expired' }

  // A token may name its device scope under any of these claims; only reject when a NAMED scope CONFLICTS.
  const scoped = [payload.device_id, payload.dev, payload.aud].find((v) => typeof v === 'string') as
    | string
    | undefined
  if (scoped !== undefined && scoped !== expectedDeviceId) return { ok: false, reason: 'wrong-device' }

  return { ok: true }
}
