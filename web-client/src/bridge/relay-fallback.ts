// S3c — ICE path helpers and pure connection-mode policy. The normal browser attempt receives host,
// STUN, and TURN candidates together; ICE selects the best pair without a direct-timeout teardown or a
// second signaling session. This module has no DOM/WebRTC dependency.

import type { ConnectionMode } from './remote-transport.js'

export interface RelayCredentials {
  urls: string[]
  username: string
  credential: string
  expiresAtMs: number
  /** STUN URLs on our relay host (no credentials). Optional for back-compat with older cloud responses. */
  stunUrls?: string[]
}

/** Map cloud `/v1/relay/creds` credentials → RTCIceServer entries (TURN + our own STUN, no third party). */
export function iceServersFromRelay(creds: RelayCredentials): RTCIceServer[] {
  const servers: RTCIceServer[] = [{ urls: creds.urls, username: creds.username, credential: creds.credential }]
  if (creds.stunUrls && creds.stunUrls.length > 0) servers.push({ urls: creds.stunUrls })
  return servers
}

/** STUN-only ICE servers from our relay host for degraded responses that contain no TURN URL. Returns []
 * when the cloud offered no STUN — then the attempt uses host/mDNS candidates only. */
export function stunServersFromRelay(creds: RelayCredentials): RTCIceServer[] {
  return creds.stunUrls && creds.stunUrls.length > 0 ? [{ urls: creds.stunUrls }] : []
}

/** The selected ICE candidate type → connection mode. 'relay' = TURN; host/srflx/prflx = direct. */
export function modeFromCandidateType(type: string | undefined | null): ConnectionMode {
  if (type === 'relay') return 'relay'
  if (type === 'host' || type === 'srflx' || type === 'prflx') return 'direct'
  return 'unknown'
}

/** Connection-mode state, decoupled from WebRTC so selected-pair classification stays unit-testable. */
export class IcePathPolicy {
  private connected = false
  private mode: ConnectionMode = 'unknown'

  get connectionMode(): ConnectionMode {
    return this.mode
  }

  /** Record the selected path. Forced-relay qualification remains relay even if browser stats are unavailable. */
  onConnected(forcedRelay: boolean, candidateType?: string | null): void {
    this.connected = true
    this.mode = forcedRelay ? 'relay' : modeFromCandidateType(candidateType)
  }

  /** The single attempt failed before opening. */
  onFailed(): void {
    if (!this.connected) this.mode = 'failed'
  }

  get isConnected(): boolean {
    return this.connected
  }
}
