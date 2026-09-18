// S5 — browser device identity. The browser is a DEVICE (S2): it holds a keypair whose PUBLIC key is
// enrolled with the cloud; the PRIVATE key is NON-EXTRACTABLE (WebCrypto `CryptoKey` with
// extractable:false), persisted by HANDLE in IndexedDB — its raw bytes are NEVER exported, NEVER written
// to localStorage, NEVER logged.
//
// Per the S5 plan, full enrollment can be stubbed behind this interface while keeping the storage design
// correct. `WebCryptoDeviceIdentity` is the real (non-extractable) implementation; `StubDeviceIdentity`
// is a deterministic stand-in for tests/dev that still NEVER exposes private bytes.

export interface DeviceIdentity {
  /** Stable device id for this browser (minted on first use, persisted). */
  deviceId(): Promise<string>
  /** The PUBLIC key as base64 — the only key material that ever leaves the browser. */
  publicKeyB64(): Promise<string>
  /** The key algorithm tag the verifier needs ('ed25519' | 'p256'). */
  alg(): Promise<'ed25519' | 'p256'>
  /** Sign `message` with the NON-EXTRACTABLE private key → base64 signature. Proof of possession: the
   * private bytes never leave the browser; only this signature does. */
  sign(message: string): Promise<string>
}

const DB_NAME = 'hydra-device'
const STORE = 'identity'
const KEY_ID = 'device-key' // the non-extractable CryptoKeyPair handle
const DEVICE_ID_KEY = 'device-id'

// ---- real implementation: non-extractable WebCrypto key in IndexedDB ----

export class WebCryptoDeviceIdentity implements DeviceIdentity {
  private cached?: { id: string; pubB64: string; alg: 'ed25519' | 'p256'; pair: CryptoKeyPair }

  private async load(): Promise<{ id: string; pubB64: string; alg: 'ed25519' | 'p256'; pair: CryptoKeyPair }> {
    if (this.cached) return this.cached
    const db = await openDb()
    let stored = (await idbGet(db, KEY_ID)) as { pair: CryptoKeyPair; alg: 'ed25519' | 'p256' } | CryptoKeyPair | undefined
    let id = (await idbGet(db, DEVICE_ID_KEY)) as string | undefined
    let pair: CryptoKeyPair
    let alg: 'ed25519' | 'p256'
    if (!stored) {
      // Prefer Ed25519 (smaller sigs, native to more agents); fall back to ECDSA P-256 where unsupported.
      // extractable:false → the private key bytes can NEVER be exported/read.
      try {
        pair = (await crypto.subtle.generateKey({ name: 'Ed25519' }, false, ['sign', 'verify'])) as CryptoKeyPair
        alg = 'ed25519'
      } catch {
        pair = (await crypto.subtle.generateKey({ name: 'ECDSA', namedCurve: 'P-256' }, false, ['sign', 'verify'])) as CryptoKeyPair
        alg = 'p256'
      }
      await idbPut(db, KEY_ID, { pair, alg }) // stores the KEY HANDLE (+ alg tag), not raw bytes
    } else if ('pair' in stored) {
      pair = stored.pair
      alg = stored.alg
    } else {
      // Legacy record (bare CryptoKeyPair from before the alg tag) → it was P-256.
      pair = stored
      alg = 'p256'
    }
    // The public key IS exportable (it's public); export it as base64 SPKI.
    const spki = await crypto.subtle.exportKey('spki', pair.publicKey)
    const pubB64 = btoa(String.fromCharCode(...new Uint8Array(spki)))
    if (!id) {
      // device id = a random opaque id (not derived from the key, which we never expose).
      id = `web_${crypto.randomUUID()}`
      await idbPut(db, DEVICE_ID_KEY, id)
    }
    this.cached = { id, pubB64, alg, pair }
    return this.cached
  }

  async deviceId(): Promise<string> {
    return (await this.load()).id
  }
  async publicKeyB64(): Promise<string> {
    return (await this.load()).pubB64
  }
  async alg(): Promise<'ed25519' | 'p256'> {
    return (await this.load()).alg
  }
  async sign(message: string): Promise<string> {
    const { pair, alg } = await this.load()
    const data = new TextEncoder().encode(message)
    const params: AlgorithmIdentifier | EcdsaParams =
      alg === 'ed25519' ? { name: 'Ed25519' } : { name: 'ECDSA', hash: 'SHA-256' }
    const sig = await crypto.subtle.sign(params, pair.privateKey, data)
    return btoa(String.fromCharCode(...new Uint8Array(sig)))
  }
}

// ---- stub: deterministic, still never exposes a private key ----

export class StubDeviceIdentity implements DeviceIdentity {
  constructor(
    private readonly id = 'web_stub_device',
    private readonly pub = 'STUBPUBLICKEYbase64',
  ) {}
  async deviceId(): Promise<string> {
    return this.id
  }
  async publicKeyB64(): Promise<string> {
    return this.pub
  }
  async alg(): Promise<'ed25519' | 'p256'> {
    return 'p256'
  }
  async sign(message: string): Promise<string> {
    // NOT real crypto — a deterministic stand-in so dev/test paths that don't cryptographically verify
    // still get a stable "signature" shape. Production uses WebCryptoDeviceIdentity.
    return btoa(`stub-sig:${this.id}:${message}`)
  }
}

// ---- tiny IndexedDB helpers (handle storage only) ----

function openDb(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, 1)
    req.onupgradeneeded = () => req.result.createObjectStore(STORE)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}
function idbGet(db: IDBDatabase, key: string): Promise<unknown> {
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readonly').objectStore(STORE).get(key)
    req.onsuccess = () => resolve(req.result)
    req.onerror = () => reject(req.error)
  })
}
function idbPut(db: IDBDatabase, key: string, value: unknown): Promise<void> {
  return new Promise((resolve, reject) => {
    const req = db.transaction(STORE, 'readwrite').objectStore(STORE).put(value, key)
    req.onsuccess = () => resolve()
    req.onerror = () => reject(req.error)
  })
}
