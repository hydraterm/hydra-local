import { WebrtcBridge, type WebrtcBridgeOptions } from '@hydraterm/remote-browser-core'
import type { SignalingPort } from '@hydraterm/remote-browser-core/signaling'
import type { BoundAuthorization } from '@hydraterm/remote-browser-core/transport'

// A consumer import/build example, not an account/agent composition. The caller remains responsible
// for enrolled device keys, passkey proof, current session-bound authority and authenticated signaling.
export function createTransport(signaling: SignalingPort, options: Omit<WebrtcBridgeOptions, 'signaling'>) {
  return new WebrtcBridge({ ...options, signaling })
}

export function currentAuthority(transport: WebrtcBridge): BoundAuthorization | null {
  return transport.currentAuthorization()
}
