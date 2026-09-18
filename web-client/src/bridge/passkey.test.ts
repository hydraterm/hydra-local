// Access Passkey (#11) — the web side. The load-bearing invariant is that certSignedBytes matches the agent's
// browser_cert.rs::cert_signed_bytes EXACTLY (the WebAuthn challenge is SHA-256 of these bytes; a mismatch
// makes every cert fail verification). Also verify the cert is embedded in the offer and low-level cancellation
// returns no cert while the production authorization wrapper fails closed.

import { describe, it, expect, vi, afterEach } from 'vitest'
import {
  authorizeBrowserWithPasskey,
  certSignedBytes,
  clearBrowserCertCache,
  createPasskeyRegistrationCredential,
  mintBrowserCert,
  passkeyReplacementAuthorizationChallenge,
  passkeySupported,
  provePasskeyRegistrationCredential,
  provePasskeyReplacementAuthorization,
} from './passkey'
import { WebrtcBridge } from './webrtc-bridge'
import { SignalingClient } from './signaling-client'

function memStorage(): Storage {
  const values = new Map<string, string>()
  return {
    get length() { return values.size },
    clear: () => values.clear(),
    getItem: (key: string) => values.get(key) ?? null,
    key: (index: number) => [...values.keys()][index] ?? null,
    removeItem: (key: string) => { values.delete(key) },
    setItem: (key: string, value: string) => { values.set(key, value) },
  }
}

describe('certSignedBytes — byte-for-byte parity with the agent', () => {
  it('produces the exact canonical string the Rust verifier hashes', () => {
    const bytes = certSignedBytes('BPUB', 'dev_desk', 'acct', 1234, 'nonce-x')
    const text = new TextDecoder().decode(bytes)
    // MUST equal browser_cert.rs cert_signed_bytes: "hydra-browser-cert-v1\n{pubkey}\n{desktop}\n{account}\n{expiry}\n{nonce}"
    expect(text).toBe('hydra-browser-cert-v1\nBPUB\ndev_desk\nacct\n1234\nnonce-x')
  })
})

describe('mintBrowserCert — low-level cancellation result', () => {
  afterEach(() => {
    clearBrowserCertCache()
    vi.unstubAllGlobals()
  })

  it('returns null when WebAuthn is unavailable so the production wrapper can refuse', async () => {
    vi.stubGlobal('window', {}) // no PublicKeyCredential
    expect(passkeySupported()).toBe(false)
    const cert = await mintBrowserCert({
      passkey: { spkiB64: 'x', alg: 'es256', rpId: 'hydraterms.com', credentialId: 'Y3JlZA' },
      browserPubkey: 'BPUB',
      desktopId: 'dev_desk',
      accountId: 'acct',
      nowMs: 1000,
    })
    expect(cert).toBeNull()
  })

  it('passes attempt cancellation into WebAuthn and brackets only the native interaction', async () => {
    const steps: string[] = []
    const get = vi.fn(async (options: CredentialRequestOptions) => {
      expect(options.signal).toBe(abort.signal)
      steps.push('get')
      return {
        response: {
          authenticatorData: new Uint8Array([1]).buffer,
          clientDataJSON: new Uint8Array([2]).buffer,
          signature: new Uint8Array([3]).buffer,
        },
      }
    })
    vi.stubGlobal('window', { PublicKeyCredential: class PublicKeyCredential {} })
    vi.stubGlobal('navigator', { credentials: { get } })
    const abort = new AbortController()

    const cert = await mintBrowserCert({
      passkey: { spkiB64: 'x', alg: 'es256', rpId: 'hydraterms.com', credentialId: 'Y3JlZA' },
      browserPubkey: 'BPUB',
      desktopId: 'dev_desk',
      accountId: 'acct',
      nowMs: 1_000,
      signal: abort.signal,
      onUserInteractionStart: () => steps.push('start'),
      onUserInteractionEnd: () => steps.push('end'),
    })

    expect(cert).not.toBeNull()
    expect(steps).toEqual(['start', 'get', 'end'])
  })
})

describe('authorizeBrowserWithPasskey — bounded in-page reuse', () => {
  afterEach(() => {
    clearBrowserCertCache()
    vi.unstubAllGlobals()
  })

  function installAuthenticator() {
    const get = vi.fn(async () => ({
      response: {
        authenticatorData: new Uint8Array([1, 2, 3]).buffer,
        clientDataJSON: new Uint8Array([4, 5, 6]).buffer,
        signature: new Uint8Array([7, 8, 9]).buffer,
      },
    }))
    vi.stubGlobal('window', { PublicKeyCredential: class PublicKeyCredential {} })
    vi.stubGlobal('navigator', { credentials: { get } })
    return get
  }

  const base = {
    passkey: { spkiB64: 'x', alg: 'es256' as const, rpId: 'hydraterms.com', credentialId: 'Y3JlZDE' },
    browserPubkey: 'BPUB',
    desktopId: 'dev_desk',
    accountId: 'acct',
  }

  it('reuses one valid certificate for the same account/desktop/browser/credential in this page', async () => {
    const get = installAuthenticator()
    const first = await authorizeBrowserWithPasskey({ ...base, nowMs: 1_000 })
    const second = await authorizeBrowserWithPasskey({ ...base, nowMs: 2_000 })

    expect(second).toEqual(first)
    expect(get).toHaveBeenCalledTimes(1)
  })

  it('coalesces concurrent authorization calls into one WebAuthn ceremony', async () => {
    const get = installAuthenticator()
    const [a, b] = await Promise.all([
      authorizeBrowserWithPasskey({ ...base, nowMs: 1_000 }),
      authorizeBrowserWithPasskey({ ...base, nowMs: 1_000 }),
    ])

    expect(a).toEqual(b)
    expect(get).toHaveBeenCalledTimes(1)
  })

  it('does not reuse a certificate after credential rotation or an account reset', async () => {
    const get = installAuthenticator()
    await authorizeBrowserWithPasskey({ ...base, nowMs: 1_000 })
    await authorizeBrowserWithPasskey({
      ...base,
      passkey: { ...base.passkey, credentialId: 'Y3JlZDI' },
      nowMs: 2_000,
    })
    clearBrowserCertCache()
    await authorizeBrowserWithPasskey({ ...base, nowMs: 3_000 })

    expect(get).toHaveBeenCalledTimes(3)
  })

  it('does not let an in-flight authorization repopulate caches after sign-out clearing', async () => {
    vi.stubGlobal('sessionStorage', memStorage())
    let resolveFirst!: (value: unknown) => void
    const firstResult = new Promise((resolve) => { resolveFirst = resolve })
    const response = {
      response: {
        authenticatorData: new Uint8Array([1, 2, 3]).buffer,
        clientDataJSON: new Uint8Array([4, 5, 6]).buffer,
        signature: new Uint8Array([7, 8, 9]).buffer,
      },
    }
    const get = vi.fn()
      .mockImplementationOnce(() => firstResult)
      .mockImplementationOnce(async () => response)
    vi.stubGlobal('window', { PublicKeyCredential: class PublicKeyCredential {} })
    vi.stubGlobal('navigator', { credentials: { get } })

    const pending = authorizeBrowserWithPasskey({ ...base, nowMs: 1_000 })
    await vi.waitFor(() => expect(get).toHaveBeenCalledTimes(1))
    clearBrowserCertCache()
    resolveFirst(response)
    await pending
    expect(sessionStorage.length).toBe(0)

    await authorizeBrowserWithPasskey({ ...base, nowMs: 2_000 })
    expect(get).toHaveBeenCalledTimes(2)
    expect(sessionStorage.length).toBe(1)
  })

  it('does not let a late authenticator result repopulate caches after its attempt is aborted', async () => {
    vi.stubGlobal('sessionStorage', memStorage())
    let resolveFirst!: (value: unknown) => void
    const firstResult = new Promise((resolve) => { resolveFirst = resolve })
    const response = {
      response: {
        authenticatorData: new Uint8Array([1, 2, 3]).buffer,
        clientDataJSON: new Uint8Array([4, 5, 6]).buffer,
        signature: new Uint8Array([7, 8, 9]).buffer,
      },
    }
    const get = vi.fn()
      .mockImplementationOnce(() => firstResult) // deliberately ignores AbortSignal
      .mockImplementationOnce(async () => response)
    vi.stubGlobal('window', { PublicKeyCredential: class PublicKeyCredential {} })
    vi.stubGlobal('navigator', { credentials: { get } })
    const abort = new AbortController()

    const pending = authorizeBrowserWithPasskey({ ...base, nowMs: 1_000, signal: abort.signal })
    await vi.waitFor(() => expect(get).toHaveBeenCalledTimes(1))
    abort.abort()
    resolveFirst(response)

    await expect(pending).rejects.toMatchObject({ name: 'AbortError' })
    expect(sessionStorage.length).toBe(0)
    await authorizeBrowserWithPasskey({ ...base, nowMs: 2_000 })
    expect(get).toHaveBeenCalledTimes(2)
    expect(sessionStorage.length).toBe(1)
  })

  it('hydrates a structurally valid, still-live certificate after a module refresh', async () => {
    vi.stubGlobal('sessionStorage', memStorage())
    const get = installAuthenticator()
    const firstModule = await import('./passkey')
    const first = await firstModule.authorizeBrowserWithPasskey({ ...base, nowMs: 1_000 })
    expect(sessionStorage.length).toBe(1)

    vi.resetModules() // model a page/module refresh: memory cache is gone, sessionStorage remains tab-scoped
    const refreshedModule = await import('./passkey')
    const hydrated = await refreshedModule.authorizeBrowserWithPasskey({ ...base, nowMs: 2_000 })

    expect(hydrated).toEqual(first)
    expect(get).toHaveBeenCalledTimes(1)
    refreshedModule.clearBrowserCertCache()
  })

  it('does not hydrate near-expiry, rotated-credential, or foreign-account entries', async () => {
    vi.stubGlobal('sessionStorage', memStorage())
    const get = installAuthenticator()
    const firstModule = await import('./passkey')
    const first = await firstModule.authorizeBrowserWithPasskey({ ...base, nowMs: 1_000 })
    vi.resetModules()
    const refreshedModule = await import('./passkey')

    await refreshedModule.authorizeBrowserWithPasskey({
      ...base,
      passkey: { ...base.passkey, credentialId: 'Y3JlZDI' },
      nowMs: 2_000,
    })
    await refreshedModule.authorizeBrowserWithPasskey({ ...base, browserPubkey: 'BPUB-ROTATED', nowMs: 2_000 })
    await refreshedModule.authorizeBrowserWithPasskey({ ...base, accountId: 'other-account', nowMs: 2_000 })
    await refreshedModule.authorizeBrowserWithPasskey({ ...base, nowMs: first.expiry_ms - 4_000 })

    expect(get).toHaveBeenCalledTimes(5)
    refreshedModule.clearBrowserCertCache()
  })

  it('ignores malformed session data and clear removes both memory and session caches', async () => {
    vi.stubGlobal('sessionStorage', memStorage())
    const get = installAuthenticator()
    const module = await import('./passkey')
    await module.authorizeBrowserWithPasskey({ ...base, nowMs: 1_000 })
    const storedKey = sessionStorage.key(0)!
    sessionStorage.setItem(storedKey, JSON.stringify({ account_id: base.accountId, expiry_ms: Number.MAX_VALUE }))

    vi.resetModules()
    const refreshedModule = await import('./passkey')
    await refreshedModule.authorizeBrowserWithPasskey({ ...base, nowMs: 2_000 })
    expect(get).toHaveBeenCalledTimes(2)
    expect(sessionStorage.length).toBe(1)

    refreshedModule.clearBrowserCertCache()
    expect(sessionStorage.length).toBe(0)
    await refreshedModule.authorizeBrowserWithPasskey({ ...base, nowMs: 3_000 })
    expect(get).toHaveBeenCalledTimes(3)
    refreshedModule.clearBrowserCertCache()
  })

  it('rejects oversized and implausibly far-future persisted certificates', async () => {
    vi.stubGlobal('sessionStorage', memStorage())
    const get = installAuthenticator()
    const firstModule = await import('./passkey')
    await firstModule.authorizeBrowserWithPasskey({ ...base, nowMs: 1_000 })
    const storedKey = sessionStorage.key(0)!
    const farFuture = JSON.parse(sessionStorage.getItem(storedKey)!)
    farFuture.expiry_ms = 9_999_999_999_999
    sessionStorage.setItem(storedKey, JSON.stringify(farFuture))

    vi.resetModules()
    const secondModule = await import('./passkey')
    await secondModule.authorizeBrowserWithPasskey({ ...base, nowMs: 2_000 })
    expect(get).toHaveBeenCalledTimes(2)

    sessionStorage.setItem(storedKey, 'x'.repeat(64 * 1024 + 1))
    vi.resetModules()
    const thirdModule = await import('./passkey')
    await thirdModule.authorizeBrowserWithPasskey({ ...base, nowMs: 3_000 })
    expect(get).toHaveBeenCalledTimes(3)
    thirdModule.clearBrowserCertCache()
  })
})

describe('createPasskeyRegistrationCredential — server-issued create ceremony', () => {
  afterEach(() => vi.unstubAllGlobals())

  it('decodes server options and serializes authenticator evidence without client-trusted key claims', async () => {
    let received: CredentialCreationOptions | undefined
    class FakePublicKeyCredential {
      id = 'credential-new'
      rawId = new Uint8Array([9, 10]).buffer
      type = 'public-key'
      authenticatorAttachment = 'platform'
      response = {
        clientDataJSON: new Uint8Array([11]).buffer,
        attestationObject: new Uint8Array([12, 13]).buffer,
        getTransports: () => ['internal', 'hybrid'],
      }
      getClientExtensionResults() { return { credProps: { rk: true } } }
    }
    vi.stubGlobal('PublicKeyCredential', FakePublicKeyCredential)
    vi.stubGlobal('navigator', {
      credentials: {
        create: vi.fn(async (options: CredentialCreationOptions) => {
          received = options
          return new FakePublicKeyCredential()
        }),
      },
    })

    const result = await createPasskeyRegistrationCredential({
      challenge: 'AQID',
      rp: { id: 'hydraterms.com', name: 'Hydra' },
      user: { id: 'BAUG', name: 'Hydra account', displayName: 'Hydra account' },
      pubKeyCredParams: [{ type: 'public-key', alg: -7 }, { type: 'public-key', alg: -8 }],
      excludeCredentials: [{ type: 'public-key', id: 'Bwg', transports: ['internal'] }],
      authenticatorSelection: { residentKey: 'preferred', userVerification: 'required' },
      attestation: 'none',
    })

    expect(Array.from(new Uint8Array(received!.publicKey!.challenge as ArrayBuffer))).toEqual([1, 2, 3])
    expect(Array.from(new Uint8Array(received!.publicKey!.user.id as ArrayBuffer))).toEqual([4, 5, 6])
    expect(Array.from(new Uint8Array(received!.publicKey!.excludeCredentials![0].id as ArrayBuffer))).toEqual([7, 8])
    expect(result).toEqual({
      id: 'credential-new',
      rawId: 'CQo',
      type: 'public-key',
      authenticatorAttachment: 'platform',
      response: { clientDataJSON: 'Cw', attestationObject: 'DA0', transports: ['internal', 'hybrid'] },
      clientExtensionResults: { credProps: { rk: true } },
    })
    expect(result).not.toHaveProperty('spkiB64')
    expect(result).not.toHaveProperty('alg')
    expect(result).not.toHaveProperty('rpId')
  })

  it('restricts the immediate get() proof to the newly-created credential and shares its AbortSignal', async () => {
    let received: CredentialRequestOptions | undefined
    const abort = new AbortController()
    class FakePublicKeyCredential {
      id = 'Y3JlZGVudGlhbC1uZXc'
      rawId = new TextEncoder().encode('credential-new').buffer
      type = 'public-key'
      authenticatorAttachment = 'platform'
      response = {
        clientDataJSON: new Uint8Array([1]).buffer,
        authenticatorData: new Uint8Array([2]).buffer,
        signature: new Uint8Array([3]).buffer,
        userHandle: null,
      }
      getClientExtensionResults() { return {} }
    }
    vi.stubGlobal('PublicKeyCredential', FakePublicKeyCredential)
    vi.stubGlobal('navigator', {
      credentials: {
        get: vi.fn(async (options: CredentialRequestOptions) => {
          received = options
          return new FakePublicKeyCredential()
        }),
      },
    })

    const proof = await provePasskeyRegistrationCredential('Y3JlZGVudGlhbC1uZXc', {
      challenge: 'AQID',
      rpId: 'hydraterms.com',
      timeout: 60_000,
      userVerification: 'required',
    }, abort.signal)
    expect(received?.signal).toBe(abort.signal)
    expect(received?.publicKey?.userVerification).toBe('required')
    expect(received?.publicKey?.allowCredentials).toHaveLength(1)
    expect(Array.from(new Uint8Array(received!.publicKey!.allowCredentials![0]!.id as ArrayBuffer)))
      .toEqual(Array.from(new TextEncoder().encode('credential-new')))
    expect(proof).toMatchObject({
      id: 'Y3JlZGVudGlhbC1uZXc',
      rawId: 'Y3JlZGVudGlhbC1uZXc',
      response: { clientDataJSON: 'AQ', authenticatorData: 'Ag', signature: 'Aw' },
    })
  })

  it('fails before WebAuthn when server authorization options target a different credential', async () => {
    const get = vi.fn()
    vi.stubGlobal('navigator', { credentials: { get } })

    await expect(provePasskeyRegistrationCredential('Y3VycmVudA', {
      challenge: 'AQID',
      rpId: 'hydraterms.com',
      userVerification: 'required',
      allowCredentials: [{ type: 'public-key', id: 'YXR0YWNrZXI' }],
    })).rejects.toThrow(/do not match the expected credential/)
    expect(get).not.toHaveBeenCalled()
  })

  it('derives the fixed replacement authorization domain identically to the cloud', async () => {
    await expect(passkeyReplacementAuthorizationChallenge('AQID'))
      .resolves.toBe('myLdjvrWLtfBC0_rN1SA8QFqv1Ke6buCHROTR7htwg8')
  })

  it.each(['browser certificate', 'unrelated random'] as const)(
    'rejects a substituted %s challenge before asking the current authenticator to sign',
    async (substitution) => {
      const get = vi.fn()
      vi.stubGlobal('navigator', { credentials: { get } })
      const challenge = substitution === 'browser certificate'
        ? Buffer.from(await crypto.subtle.digest(
          'SHA-256',
          certSignedBytes('attacker-browser-key', 'desktop', 'account', 1234, 'nonce') as BufferSource,
          )).toString('base64url')
        : 'ERIT'

      await expect(provePasskeyReplacementAuthorization(
        'Y3VycmVudA',
        {
          challenge,
          rpId: 'hydraterms.com',
          userVerification: 'required',
          allowCredentials: [{ type: 'public-key', id: 'Y3VycmVudA' }],
        },
        'AQID',
      )).rejects.toThrow(/not domain separated/)
      expect(get).not.toHaveBeenCalled()
    },
  )
})

// A fake peer/signaling to drive the bridge's offer construction and inspect the embedded cert.
function fakePeerFactory() {
  return (): RTCPeerConnection => {
    const pc: any = {
      createDataChannel: () => ({ binaryType: '', readyState: 'connecting', send: () => {}, close: () => {} }),
      createOffer: async () => ({ type: 'offer', sdp: 'v=0\r\na=fingerprint:sha-256 AA:BB\r\n' }),
      setLocalDescription: async () => {},
      setRemoteDescription: async () => {},
      addIceCandidate: async () => {},
      getStats: async () => new Map(),
      close: () => {},
      get currentRemoteDescription() { return null },
    }
    return pc as RTCPeerConnection
  }
}

describe('the bridge embeds hydra_browser_cert in the offer when provided', () => {
  it('includes the cert the browserCert() callback returns', async () => {
    let capturedOffer: string | undefined
    const signaling = new SignalingClient(
      { baseUrl: 'http://x', authToken: 'dev:a', deviceId: 'web_dev' },
      (async (_url: string, init: any) => {
        capturedOffer = JSON.parse(init.body).offer
        return new Response(JSON.stringify({ sessionId: 'sig_1' }), { status: 201 })
      }) as unknown as typeof fetch,
    )
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'dev_desk',
      directTimeoutMs: 100,
      peerFactory: fakePeerFactory(),
      browserCert: async () => ({ browser_pubkey: 'BPUB', desktop_id: 'dev_desk', assertion: { signature: 'sig' } }),
    })
    await bridge.connect()
    expect(capturedOffer).toBeDefined()
    const parsed = JSON.parse(capturedOffer!)
    expect(parsed.hydra_browser_cert).toEqual({ browser_pubkey: 'BPUB', desktop_id: 'dev_desk', assertion: { signature: 'sig' } })
    bridge.close()
  })

  it('omits hydra_browser_cert when the callback returns null (grace path)', async () => {
    let capturedOffer: string | undefined
    const signaling = new SignalingClient(
      { baseUrl: 'http://x', authToken: 'dev:a', deviceId: 'web_dev' },
      (async (_url: string, init: any) => {
        capturedOffer = JSON.parse(init.body).offer
        return new Response(JSON.stringify({ sessionId: 'sig_1' }), { status: 201 })
      }) as unknown as typeof fetch,
    )
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'dev_desk',
      directTimeoutMs: 100,
      peerFactory: fakePeerFactory(),
      browserCert: async () => null,
    })
    await bridge.connect()
    const parsed = JSON.parse(capturedOffer!)
    expect(parsed.hydra_browser_cert).toBeUndefined()
    bridge.close()
  })

  it('aborts before signaling when registered-passkey authorization is rejected', async () => {
    let signalingCalls = 0
    const signaling = new SignalingClient(
      { baseUrl: 'http://x', authToken: 'dev:a', deviceId: 'web_dev' },
      (async () => {
        signalingCalls++
        return new Response(JSON.stringify({ sessionId: 'must-not-open' }), { status: 201 })
      }) as unknown as typeof fetch,
    )
    const modes: string[] = []
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'dev_desk',
      directTimeoutMs: 100,
      peerFactory: fakePeerFactory(),
      onMode: (mode) => modes.push(mode),
      browserCert: async () => { throw new Error('user rejected passkey') },
    })
    await bridge.connect()
    expect(signalingCalls).toBe(0)
    expect(modes).toContain('failed')
    bridge.close()
  })

  it('close while passkey authorization is pending cannot revive signaling or token minting', async () => {
    let signalingCalls = 0
    let tokenMints = 0
    let releaseCert: (cert: Record<string, unknown>) => void = () => {}
    let markCertStarted: () => void = () => {}
    const certStarted = new Promise<void>((resolve) => { markCertStarted = resolve })
    const pendingCert = new Promise<Record<string, unknown>>((resolve) => { releaseCert = resolve })
    const signaling = new SignalingClient(
      { baseUrl: 'http://x', authToken: 'dev:a', deviceId: 'web_dev' },
      (async () => {
        signalingCalls++
        return new Response(JSON.stringify({ sessionId: 'must-not-open' }), { status: 201 })
      }) as unknown as typeof fetch,
    )
    const states: string[] = []
    const bridge = new WebrtcBridge({
      signaling,
      targetDeviceId: 'dev_desk',
      directTimeoutMs: 100,
      peerFactory: fakePeerFactory(),
      browserCert: async () => {
        markCertStarted()
        return pendingCert
      },
      mintToken: async () => {
        tokenMints++
        return 'must-not-mint'
      },
    })
    bridge.onState((state) => states.push(state))

    const connecting = bridge.connect()
    await certStarted
    bridge.close() // models controller retirement/sign-out while the native passkey UI is still open
    releaseCert({ browser_pubkey: 'BPUB' })
    await connecting
    await Promise.resolve()

    expect(signalingCalls).toBe(0)
    expect(tokenMints).toBe(0)
    expect(bridge.currentToken()).toBeNull()
    expect(states).toEqual(['connecting']) // no connected/offline/authorization_required revival after close
  })
})
