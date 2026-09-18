// S5 — TS mirror of the S4 binary terminal frame (hydra-agent `remote_frame.rs`). The browser client and
// the Rust agent MUST agree byte-for-byte; the shared fixtures in terminal-frame.test.ts pin that.
//
// Wire layout (big-endian), header = 8 bytes:
//   version : u8    (FRAME_VERSION; reject anything else)
//   kind    : u8    (FrameKind; reject unknown)
//   channel : u16   (attach/channel id)
//   length  : u32   (payload byte length; reject > MAX_FRAME_PAYLOAD)
//   payload : [u8; length]
//
// Direction is enforced by the bridge, not the frame: terminal_input is client→agent, terminal_output is
// agent→client. This carries ONLY terminal bytes over the DTLS DataChannel — never to the cloud.

export const FRAME_VERSION = 1
export const MAX_FRAME_PAYLOAD = 8 * 1024 * 1024 // 8 MiB — must match remote_frame.rs (wide-grid frames are large)
export const MAX_INPUT_PAYLOAD = 64 * 1024 // 64 KiB — must match remote_frame.rs client→agent input cap
export const TERMINAL_GZIP_JSON_V1 = 'terminal_gzip_json_v1'
export const TERMINAL_GZIP_CODEC_VERSION = 1
export const TERMINAL_CODEC_CHUNK_BYTES = 16 * 1024
export const MAX_TERMINAL_CODEC_BYTES = 16 * 1024 * 1024
export const MAX_TERMINAL_CODEC_CHUNKS = 1024
export const MAX_TERMINAL_CODEC_EXPANSION = 512
export const TERMINAL_GZIP_MIN_DECODED_BYTES = 4 * 1024
const HEADER_LEN = 8
const TERMINAL_GZIP_CHUNK_HEADER_LEN = 14

export enum FrameKind {
  TerminalInput = 1,
  TerminalOutput = 2,
  /** ONE chunk of a large terminal_output: payload = [is_last:u8][bytes]. Reassembled per channel. */
  TerminalOutputChunk = 3,
  TerminalGzipJsonChunk = 4,
}

export interface TerminalFrame {
  kind: FrameKind
  channel: number
  payload: Uint8Array
  /** Local-only strict UTF-8 result produced by the negotiated codec. Avoids decoding a large Grid twice. */
  decodedText?: string
  /** Local-only, content-blind accounting attached after codec decoding. Never serialized. */
  transport?: TerminalFrameTransport
}

export interface TerminalFrameTransport {
  readonly rawWireBytes: number
  readonly encodedBytes: number
  readonly decodedBytes: number
  readonly chunkCount: number
  readonly compressed: boolean
  readonly transferMs: number
  readonly codecQueueMs: number
  readonly codecMs: number
}

export interface TerminalGzipChunk {
  readonly index: number
  readonly count: number
  readonly encodedLength: number
  readonly decodedLength: number
  readonly final: boolean
  readonly bytes: Uint8Array
}

export type TerminalGzipChunkError =
  | 'short'
  | 'bad_version'
  | 'bad_flags'
  | 'bad_count'
  | 'bad_index'
  | 'bad_finality'
  | 'empty_chunk'
  | 'encoded_too_large'
  | 'decoded_too_large'
  | 'below_threshold'
  | 'insufficient_savings'
  | 'expansion_too_large'
  | 'bad_chunk_length'

export type FrameError =
  | { kind: 'short' }
  | { kind: 'bad_version'; version: number }
  | { kind: 'bad_kind'; value: number }
  | { kind: 'too_large'; length: number }
  | { kind: 'trailing' }

function isKnownKind(v: number): v is FrameKind {
  return v === FrameKind.TerminalInput || v === FrameKind.TerminalOutput ||
    v === FrameKind.TerminalOutputChunk || v === FrameKind.TerminalGzipJsonChunk
}

/** Parse a gzip chunk's fixed metadata without allocating from any attacker-provided length. */
export function decodeTerminalGzipChunk(
  payload: Uint8Array,
): { ok: TerminalGzipChunk } | { err: TerminalGzipChunkError } {
  if (payload.byteLength < TERMINAL_GZIP_CHUNK_HEADER_LEN) return { err: 'short' }
  if (payload[0] !== TERMINAL_GZIP_CODEC_VERSION) return { err: 'bad_version' }
  const flags = payload[1]!
  if ((flags & ~1) !== 0) return { err: 'bad_flags' }
  const view = new DataView(payload.buffer, payload.byteOffset, payload.byteLength)
  const index = view.getUint16(2, false)
  const count = view.getUint16(4, false)
  if (count === 0 || count > MAX_TERMINAL_CODEC_CHUNKS) return { err: 'bad_count' }
  if (index >= count) return { err: 'bad_index' }
  const final = (flags & 1) === 1
  if (final !== (index + 1 === count)) return { err: 'bad_finality' }
  const encodedLength = view.getUint32(6, false)
  const decodedLength = view.getUint32(10, false)
  if (encodedLength === 0 || encodedLength > MAX_TERMINAL_CODEC_BYTES) return { err: 'encoded_too_large' }
  if (decodedLength > MAX_TERMINAL_CODEC_BYTES) return { err: 'decoded_too_large' }
  if (decodedLength < TERMINAL_GZIP_MIN_DECODED_BYTES) return { err: 'below_threshold' }
  if (encodedLength * 8 > decodedLength * 7) return { err: 'insufficient_savings' }
  if (decodedLength > encodedLength * MAX_TERMINAL_CODEC_EXPANSION) return { err: 'expansion_too_large' }
  const expectedCount = Math.ceil(encodedLength / TERMINAL_CODEC_CHUNK_BYTES)
  if (count !== expectedCount) return { err: 'bad_count' }
  const expectedLength = final
    ? encodedLength - index * TERMINAL_CODEC_CHUNK_BYTES
    : TERMINAL_CODEC_CHUNK_BYTES
  const bytes = payload.subarray(TERMINAL_GZIP_CHUNK_HEADER_LEN)
  if (bytes.byteLength === 0) return { err: 'empty_chunk' }
  if (bytes.byteLength !== expectedLength) return { err: 'bad_chunk_length' }
  return { ok: { index, count, encodedLength, decodedLength, final, bytes } }
}

/** Encode one canonical gzip chunk payload (primarily used by wire fixtures/tests; the browser receives these). */
export function encodeTerminalGzipChunkPayload(
  index: number,
  count: number,
  encodedLength: number,
  decodedLength: number,
  bytes: Uint8Array,
): Uint8Array {
  const payload = new Uint8Array(TERMINAL_GZIP_CHUNK_HEADER_LEN + bytes.byteLength)
  const view = new DataView(payload.buffer)
  payload[0] = TERMINAL_GZIP_CODEC_VERSION
  payload[1] = index + 1 === count ? 1 : 0
  view.setUint16(2, index, false)
  view.setUint16(4, count, false)
  view.setUint32(6, encodedLength, false)
  view.setUint32(10, decodedLength, false)
  payload.set(bytes, TERMINAL_GZIP_CHUNK_HEADER_LEN)
  const validated = decodeTerminalGzipChunk(payload)
  if ('err' in validated) throw new RangeError(`invalid terminal gzip chunk: ${validated.err}`)
  return payload
}

/** Encode one binary frame. Throws on an oversized payload (mirrors the Rust encode's TooLarge). */
export function encodeFrame(kind: FrameKind, channel: number, payload: Uint8Array): Uint8Array {
  if (payload.length > MAX_FRAME_PAYLOAD) {
    throw new RangeError(`frame payload too large: ${payload.length}`)
  }
  const out = new Uint8Array(HEADER_LEN + payload.length)
  const view = new DataView(out.buffer)
  out[0] = FRAME_VERSION
  out[1] = kind
  view.setUint16(2, channel & 0xffff, false) // big-endian
  view.setUint32(4, payload.length, false)
  out.set(payload, HEADER_LEN)
  return out
}

/** Encode client→agent terminal input as one or more frames that respect the agent's tighter input cap. */
export function encodeInputFrames(channel: number, payload: Uint8Array): Uint8Array[] {
  if (payload.length <= MAX_INPUT_PAYLOAD) {
    return [encodeFrame(FrameKind.TerminalInput, channel, payload)]
  }
  const out: Uint8Array[] = []
  for (let off = 0; off < payload.length; off += MAX_INPUT_PAYLOAD) {
    out.push(encodeFrame(FrameKind.TerminalInput, channel, payload.subarray(off, off + MAX_INPUT_PAYLOAD)))
  }
  return out
}

/** Parse exactly one binary frame (one DataChannel binary message = one frame). Returns a discriminated
 * result; never throws on malformed input — rejects unknown version/kind, oversized, short, or trailing. */
export function decodeFrame(buf: Uint8Array): { ok: TerminalFrame } | { err: FrameError } {
  if (buf.length < HEADER_LEN) return { err: { kind: 'short' } }
  const version = buf[0]!
  if (version !== FRAME_VERSION) return { err: { kind: 'bad_version', version } }
  const kindByte = buf[1]!
  if (!isKnownKind(kindByte)) return { err: { kind: 'bad_kind', value: kindByte } }
  const view = new DataView(buf.buffer, buf.byteOffset, buf.byteLength)
  const channel = view.getUint16(2, false)
  const length = view.getUint32(4, false)
  if (length > MAX_FRAME_PAYLOAD) return { err: { kind: 'too_large', length } }
  const end = HEADER_LEN + length
  if (buf.length < end) return { err: { kind: 'short' } }
  if (buf.length > end) return { err: { kind: 'trailing' } }
  return { ok: { kind: kindByte, channel, payload: buf.subarray(HEADER_LEN, end) } }
}
