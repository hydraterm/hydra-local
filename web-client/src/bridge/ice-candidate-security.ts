// Signaling-boundary guard for PEER ICE candidates (defense in depth, mirrors the SDP fail-closed guard). The
// cloud relays the remote peer's ICE candidates as JSON strings; pollIce() hands them to
// RTCPeerConnection.addIceCandidate(). The cloud is content-blind and untrusted with payloads, so before the
// browser ICE stack sees a candidate we parse it ourselves and accept ONLY a well-formed candidate init,
// passing through nothing but the known RTCIceCandidateInit fields (candidate / sdpMid / sdpMLineIndex /
// usernameFragment). A malformed or unexpectedly-shaped entry is rejected (returns null); the owning transport
// decides whether that means a pre-open attempt must restart rather than silently accepting an incomplete set.
//
// Content-blind: it never logs/returns the candidate string itself — callers get a sanitized init or null.

export interface SafeIceCandidateInit {
  candidate: string
  sdpMid?: string | null
  sdpMLineIndex?: number | null
  usernameFragment?: string | null
}

/**
 * Parse + shape-validate a relayed peer ICE candidate (a JSON string). Returns a sanitized RTCIceCandidateInit
 * containing ONLY the recognized fields, or null when:
 *  - the JSON is unparseable / not an object,
 *  - `candidate` is missing or not a string (a candidate init must carry the SDP candidate line),
 *  - `sdpMid` / `usernameFragment` are present but not string|null,
 *  - `sdpMLineIndex` is present but not a non-negative integer | null.
 * An empty-string `candidate` is allowed (the end-of-candidates sentinel some stacks send).
 */
export function safeParseRemoteCandidate(raw: string): SafeIceCandidateInit | null {
  let obj: unknown
  try {
    obj = JSON.parse(raw)
  } catch {
    return null
  }
  if (!obj || typeof obj !== 'object') return null
  const c = obj as Record<string, unknown>

  if (typeof c.candidate !== 'string') return null

  if (c.sdpMid !== undefined && c.sdpMid !== null && typeof c.sdpMid !== 'string') return null
  if (
    c.sdpMLineIndex !== undefined &&
    c.sdpMLineIndex !== null &&
    (typeof c.sdpMLineIndex !== 'number' || !Number.isInteger(c.sdpMLineIndex) || c.sdpMLineIndex < 0)
  ) {
    return null
  }
  if (c.usernameFragment !== undefined && c.usernameFragment !== null && typeof c.usernameFragment !== 'string') return null

  // Build a fresh object with ONLY the known fields — strip anything else the relay smuggled in.
  const out: SafeIceCandidateInit = { candidate: c.candidate }
  if (c.sdpMid !== undefined) out.sdpMid = c.sdpMid as string | null
  if (c.sdpMLineIndex !== undefined) out.sdpMLineIndex = c.sdpMLineIndex as number | null
  if (c.usernameFragment !== undefined) out.usernameFragment = c.usernameFragment as string | null
  return out
}
