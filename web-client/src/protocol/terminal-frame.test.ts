import { describe, it, expect } from 'vitest'
import {
  FRAME_VERSION,
  FrameKind,
  MAX_FRAME_PAYLOAD,
  MAX_INPUT_PAYLOAD,
  decodeFrame,
  encodeFrame,
  encodeInputFrames,
  decodeTerminalGzipChunk,
} from './terminal-frame'

// Shared cross-language fixtures: these exact (kind, channel, payloadHex) → frameHex pairs are also
// asserted by the Rust side (hydra-agent remote_frame cross-fixture test) so the wire form can't drift.
// frameHex = version(01) kind channel(be16) len(be32) payload.
export const SHARED_FRAME_FIXTURES = [
  { kind: FrameKind.TerminalInput, channel: 7, payloadHex: '68656c6c6f', frameHex: '0101000700000005' + '68656c6c6f' },
  { kind: FrameKind.TerminalOutput, channel: 0, payloadHex: '', frameHex: '0102000000000000' },
  { kind: FrameKind.TerminalOutput, channel: 258, payloadHex: '00010203', frameHex: '0102010200000004' + '00010203' },
  {
    kind: FrameKind.TerminalGzipJsonChunk,
    channel: 258,
    payloadHex: '01010000000100000008000010000001020304050607',
    frameHex: '010401020000001601010000000100000008000010000001020304050607',
  },
] as const

function hexToBytes(hex: string): Uint8Array {
  const out = new Uint8Array(hex.length / 2)
  for (let i = 0; i < out.length; i++) out[i] = parseInt(hex.slice(i * 2, i * 2 + 2), 16)
  return out
}
function bytesToHex(b: Uint8Array): string {
  return Array.from(b, (x) => x.toString(16).padStart(2, '0')).join('')
}

describe('terminal frame codec — shared fixtures (JS↔Rust)', () => {
  for (const f of SHARED_FRAME_FIXTURES) {
    it(`encodes kind=${f.kind} channel=${f.channel} to the canonical bytes`, () => {
      const bytes = encodeFrame(f.kind, f.channel, hexToBytes(f.payloadHex))
      expect(bytesToHex(bytes)).toBe(f.frameHex)
    })
    it(`decodes the canonical bytes back`, () => {
      const res = decodeFrame(hexToBytes(f.frameHex))
      expect('ok' in res).toBe(true)
      if ('ok' in res) {
        expect(res.ok.kind).toBe(f.kind)
        expect(res.ok.channel).toBe(f.channel)
        expect(bytesToHex(res.ok.payload)).toBe(f.payloadHex)
      }
    })
  }
})

describe('terminal frame codec — round trip + rejections', () => {
  it('round-trips arbitrary payload bytes', () => {
    const payload = new Uint8Array([0, 1, 2, 255, 128, 10, 13])
    const res = decodeFrame(encodeFrame(FrameKind.TerminalOutput, 12345, payload))
    expect('ok' in res).toBe(true)
    if ('ok' in res) {
      expect(res.ok.channel).toBe(12345)
      expect(Array.from(res.ok.payload)).toEqual(Array.from(payload))
    }
  })

  it('rejects an unknown version', () => {
    const bytes = encodeFrame(FrameKind.TerminalInput, 1, new Uint8Array([1]))
    bytes[0] = 99
    expect(decodeFrame(bytes)).toEqual({ err: { kind: 'bad_version', version: 99 } })
  })

  it('rejects an unknown kind', () => {
    const bytes = encodeFrame(FrameKind.TerminalInput, 1, new Uint8Array([1]))
    bytes[1] = 200
    expect(decodeFrame(bytes)).toEqual({ err: { kind: 'bad_kind', value: 200 } })
  })

  it('rejects an oversized declared length without reading it', () => {
    const bytes = new Uint8Array(8)
    bytes[0] = FRAME_VERSION
    bytes[1] = FrameKind.TerminalInput
    new DataView(bytes.buffer).setUint32(4, MAX_FRAME_PAYLOAD + 1, false)
    expect(decodeFrame(bytes)).toEqual({ err: { kind: 'too_large', length: MAX_FRAME_PAYLOAD + 1 } })
  })

  it('encode throws on an oversized payload', () => {
    expect(() => encodeFrame(FrameKind.TerminalOutput, 0, new Uint8Array(MAX_FRAME_PAYLOAD + 1))).toThrow()
  })

  it('encodes terminal input into frames capped at MAX_INPUT_PAYLOAD', () => {
    const payload = new Uint8Array(MAX_INPUT_PAYLOAD * 2 + 7)
    payload.fill(0x61)
    const frames = encodeInputFrames(9, payload)
    expect(frames).toHaveLength(3)
    const decoded = frames.map((frame) => decodeFrame(frame))
    for (const res of decoded) {
      expect('ok' in res).toBe(true)
      if ('ok' in res) {
        expect(res.ok.kind).toBe(FrameKind.TerminalInput)
        expect(res.ok.channel).toBe(9)
        expect(res.ok.payload.length).toBeLessThanOrEqual(MAX_INPUT_PAYLOAD)
      }
    }
    expect('ok' in decoded[0] && decoded[0].ok.payload.length).toBe(MAX_INPUT_PAYLOAD)
    expect('ok' in decoded[1] && decoded[1].ok.payload.length).toBe(MAX_INPUT_PAYLOAD)
    expect('ok' in decoded[2] && decoded[2].ok.payload.length).toBe(7)
  })

  it('rejects a short buffer', () => {
    expect(decodeFrame(new Uint8Array([1, 1, 0]))).toEqual({ err: { kind: 'short' } })
    const bytes = new Uint8Array([FRAME_VERSION, FrameKind.TerminalInput, 0, 0, 0, 0, 0, 4, 0x61, 0x62])
    expect(decodeFrame(bytes)).toEqual({ err: { kind: 'short' } })
  })

  it('rejects trailing bytes', () => {
    const bytes = encodeFrame(FrameKind.TerminalInput, 0, new Uint8Array([0x61, 0x62]))
    const withTrailing = new Uint8Array(bytes.length + 1)
    withTrailing.set(bytes)
    withTrailing[bytes.length] = 0xff
    expect(decodeFrame(withTrailing)).toEqual({ err: { kind: 'trailing' } })
  })

  it('parses the exact gzip metadata fixture and pins finality precedence', () => {
    const payload = hexToBytes('01010000000100000008000010000001020304050607')
    expect(decodeTerminalGzipChunk(payload)).toEqual({
      ok: {
        index: 0,
        count: 1,
        encodedLength: 8,
        decodedLength: 4096,
        final: true,
        bytes: payload.subarray(14),
      },
    })
    const notFinal = payload.slice()
    notFinal[1] = 0
    expect(decodeTerminalGzipChunk(notFinal)).toEqual({ err: 'bad_finality' })
  })

  it('rejects malformed gzip chunk metadata before allocation', () => {
    const valid = hexToBytes('01010000000100000008000010000001020304050607')
    for (const [offset, value, error] of [
      [0, 2, 'bad_version'],
      [1, 3, 'bad_flags'],
      [5, 0, 'bad_count'],
      [3, 1, 'bad_index'],
    ] as const) {
      const bytes = valid.slice()
      bytes[offset] = value
      expect(decodeTerminalGzipChunk(bytes)).toEqual({ err: error })
    }
    expect(decodeTerminalGzipChunk(valid.subarray(0, 13))).toEqual({ err: 'short' })
    expect(decodeTerminalGzipChunk(valid.subarray(0, valid.length - 1))).toEqual({ err: 'bad_chunk_length' })
  })
})
