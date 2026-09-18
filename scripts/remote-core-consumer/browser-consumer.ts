import { WebrtcBridge, type WebrtcBridgeOptions } from '@hydraterm/remote-browser-core'
import type { SignalingPort } from '@hydraterm/remote-browser-core/signaling'
import type { BoundAuthorization } from '@hydraterm/remote-browser-core/transport'
import { RemoteClientController, type RemoteClientDeps } from '@hydraterm/remote-browser-core/controller'
import { SignalingClient, type SignalingConfig } from '@hydraterm/remote-browser-core/signaling-http'
import { RemoteLayoutCloud, type RemoteLayoutCloudConfig } from '@hydraterm/remote-browser-core/layout'
export { GridRenderer } from '@hydraterm/remote-browser-core/grid'
export { encodeKey, encodePaste } from '@hydraterm/remote-browser-core/input'
export { SelectionController } from '@hydraterm/remote-browser-core/selection'
export { gridForViewport } from '@hydraterm/remote-browser-core/viewport'
export { AGENT_PROVIDERS } from '@hydraterm/remote-browser-core/providers'

// A consumer import/build example, not an account/agent composition. The caller remains responsible
// for enrolled device keys, passkey proof, current session-bound authority and authenticated signaling.
export function createTransport(signaling: SignalingPort, options: Omit<WebrtcBridgeOptions, 'signaling'>) {
  return new WebrtcBridge({ ...options, signaling })
}

export function currentAuthority(transport: WebrtcBridge): BoundAuthorization | null {
  return transport.currentAuthorization()
}

// The production arm requires enrollment preparation, not the legacy synthetic token-mint fallback.
export function createEngine(deps: Extract<RemoteClientDeps, { prepareConnection: unknown }>) {
  return new RemoteClientController(deps)
}

export function createHttpAdapters(signaling: SignalingConfig, layout: RemoteLayoutCloudConfig, fetchImpl?: typeof fetch) {
  return { signaling: new SignalingClient(signaling, fetchImpl), layout: new RemoteLayoutCloud(layout, fetchImpl) }
}
