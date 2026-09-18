//! S4 — the versioned BINARY frame for the terminal hot path over the WebRTC DataChannel.
//!
//! Terminal input/output is byte-heavy (the daemon's grid/damage/output frames); base64-in-JSON would
//! bloat it ~33% and add parse cost. So the hot path uses a tiny length-prefixed binary frame. The frame
//! is opaque on the wire to the cloud anyway (it travels ONLY over DTLS, peer↔peer) and never leaves the
//! peer. Control + terminal METADATA (attach/resize/detach/list) stay JSON; only `terminal_input` /
//! `terminal_output` payloads are framed here.
//!
//! Wire layout (big-endian), total header = 8 bytes:
//!   version : u8    (FRAME_VERSION; reject anything else)
//!   kind    : u8    (FrameKind; reject unknown)
//!   channel : u16   (attach/channel id — which attached session this frame is for)
//!   length  : u32   (payload byte length; reject > MAX_FRAME_PAYLOAD)
//!   payload : [u8; length]

pub const FRAME_VERSION: u8 = 1;
/// Hard cap on a single binary frame's payload (256 KiB). A larger daemon frame must be chunked upstream.
// NOTE: a full daemon Grid (every cell as JSON) can be multi-MB on a wide terminal, so the cap is
// generous. A proper fix is to chunk/compress Grid frames; until then this lets them through. Must match
// the TS terminal-frame.ts MAX_FRAME_PAYLOAD.
pub const MAX_FRAME_PAYLOAD: usize = 8 * 1024 * 1024;

/// Tighter cap on a single client→agent `terminal_input` frame (64 KiB). The 8 MiB MAX_FRAME_PAYLOAD is sized
/// for OUTPUT (multi-MB daemon Grid frames); INPUT is human keystrokes/paste — even a large paste is far under
/// this. The browser is UNTRUSTED, so the agent enforces this independently of any client-side limit: it stops
/// a malicious/buggy peer from shoving megabytes of input per frame into the PTY (amplification / DoS). A
/// legitimate huge paste is the browser's job to chunk into multiple input frames.
pub const MAX_INPUT_PAYLOAD: usize = 64 * 1024;

/// Additive per-attach terminal codec. The outer frame remains v1 so legacy peers continue to reject an unknown
/// kind rather than misparse it; the payload has its own versioned, fully-bounded envelope.
pub const TERMINAL_GZIP_JSON_V1: &str = "terminal_gzip_json_v1";
pub const TERMINAL_GZIP_CODEC_VERSION: u8 = 1;
pub const TERMINAL_CODEC_CHUNK_BYTES: usize = 16 * 1024;
pub const MAX_TERMINAL_CODEC_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_TERMINAL_CODEC_CHUNKS: usize = 1024;
pub const MAX_TERMINAL_CODEC_EXPANSION: usize = 512;
pub const TERMINAL_GZIP_MIN_DECODED_BYTES: usize = 4 * 1024;
const TERMINAL_GZIP_CHUNK_HEADER_LEN: usize = 14;

const HEADER_LEN: usize = 8;

/// The closed set of binary frame kinds. Direction is enforced by the bridge, not the frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FrameKind {
    /// client→agent: raw bytes for the PTY.
    TerminalInput = 1,
    /// agent→client: a daemon output frame, passed through opaquely.
    TerminalOutput = 2,
    /// agent→client: ONE CHUNK of a large terminal_output (the WebRTC DataChannel rejects multi-hundred-KB
    /// single messages, so big Grid frames are split). Payload = [is_last:u8][chunk bytes]. The client
    /// concatenates chunks per channel until is_last=1, then treats the joined buffer as a TerminalOutput.
    TerminalOutputChunk = 3,
    /// agent→client: one independently-gzipped complete daemon JSON event, split into explicitly indexed
    /// chunks. The payload is parsed by `decode_terminal_gzip_chunk`; legacy peers reject this unknown kind.
    TerminalGzipJsonChunk = 4,
}

impl FrameKind {
    fn from_u8(v: u8) -> Option<Self> {
        match v {
            1 => Some(FrameKind::TerminalInput),
            2 => Some(FrameKind::TerminalOutput),
            3 => Some(FrameKind::TerminalOutputChunk),
            4 => Some(FrameKind::TerminalGzipJsonChunk),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TerminalGzipChunk<'a> {
    pub index: u16,
    pub count: u16,
    pub encoded_len: u32,
    pub decoded_len: u32,
    pub final_chunk: bool,
    pub bytes: &'a [u8],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalGzipChunkError {
    Short,
    BadVersion(u8),
    BadFlags(u8),
    BadCount(u16),
    BadIndex { index: u16, count: u16 },
    BadFinality { index: u16, count: u16 },
    EmptyChunk,
    EncodedTooLarge(u32),
    DecodedTooLarge(u32),
    BelowCompressionThreshold(u32),
    InsufficientSavings { encoded: u32, decoded: u32 },
    ExpansionTooLarge { encoded: u32, decoded: u32 },
    BadChunkLength { actual: usize, expected: usize },
}

/// Encode the payload carried by `FrameKind::TerminalGzipJsonChunk`. Every non-final chunk is exactly 16 KiB;
/// the final chunk is the exact remainder. That makes length, count, index and finality independently checkable.
pub fn encode_terminal_gzip_chunk_payload(
    index: u16,
    count: u16,
    encoded_len: u32,
    decoded_len: u32,
    bytes: &[u8],
) -> Result<Vec<u8>, TerminalGzipChunkError> {
    let final_chunk = index.checked_add(1) == Some(count);
    let flags = u8::from(final_chunk);
    let mut payload = Vec::with_capacity(TERMINAL_GZIP_CHUNK_HEADER_LEN + bytes.len());
    payload.push(TERMINAL_GZIP_CODEC_VERSION);
    payload.push(flags);
    payload.extend_from_slice(&index.to_be_bytes());
    payload.extend_from_slice(&count.to_be_bytes());
    payload.extend_from_slice(&encoded_len.to_be_bytes());
    payload.extend_from_slice(&decoded_len.to_be_bytes());
    payload.extend_from_slice(bytes);
    decode_terminal_gzip_chunk(&payload)?;
    Ok(payload)
}

/// Parse and validate one gzip chunk without allocating from its declared lengths.
pub fn decode_terminal_gzip_chunk(
    payload: &[u8],
) -> Result<TerminalGzipChunk<'_>, TerminalGzipChunkError> {
    if payload.len() < TERMINAL_GZIP_CHUNK_HEADER_LEN {
        return Err(TerminalGzipChunkError::Short);
    }
    let version = payload[0];
    if version != TERMINAL_GZIP_CODEC_VERSION {
        return Err(TerminalGzipChunkError::BadVersion(version));
    }
    let flags = payload[1];
    if flags & !1 != 0 {
        return Err(TerminalGzipChunkError::BadFlags(flags));
    }
    let index = u16::from_be_bytes([payload[2], payload[3]]);
    let count = u16::from_be_bytes([payload[4], payload[5]]);
    if count == 0 || usize::from(count) > MAX_TERMINAL_CODEC_CHUNKS {
        return Err(TerminalGzipChunkError::BadCount(count));
    }
    if index >= count {
        return Err(TerminalGzipChunkError::BadIndex { index, count });
    }
    let final_chunk = flags & 1 == 1;
    if final_chunk != (index + 1 == count) {
        return Err(TerminalGzipChunkError::BadFinality { index, count });
    }
    let encoded_len = u32::from_be_bytes([payload[6], payload[7], payload[8], payload[9]]);
    let decoded_len = u32::from_be_bytes([payload[10], payload[11], payload[12], payload[13]]);
    if encoded_len == 0 || encoded_len as usize > MAX_TERMINAL_CODEC_BYTES {
        return Err(TerminalGzipChunkError::EncodedTooLarge(encoded_len));
    }
    if decoded_len as usize > MAX_TERMINAL_CODEC_BYTES {
        return Err(TerminalGzipChunkError::DecodedTooLarge(decoded_len));
    }
    if (decoded_len as usize) < TERMINAL_GZIP_MIN_DECODED_BYTES {
        return Err(TerminalGzipChunkError::BelowCompressionThreshold(
            decoded_len,
        ));
    }
    if (encoded_len as u64) * 8 > (decoded_len as u64) * 7 {
        return Err(TerminalGzipChunkError::InsufficientSavings {
            encoded: encoded_len,
            decoded: decoded_len,
        });
    }
    if (decoded_len as u64) > (encoded_len as u64) * (MAX_TERMINAL_CODEC_EXPANSION as u64) {
        return Err(TerminalGzipChunkError::ExpansionTooLarge {
            encoded: encoded_len,
            decoded: decoded_len,
        });
    }
    let expected_count = (encoded_len as usize).div_ceil(TERMINAL_CODEC_CHUNK_BYTES);
    if expected_count != usize::from(count) {
        return Err(TerminalGzipChunkError::BadCount(count));
    }
    let expected_chunk_len = if final_chunk {
        encoded_len as usize - usize::from(index) * TERMINAL_CODEC_CHUNK_BYTES
    } else {
        TERMINAL_CODEC_CHUNK_BYTES
    };
    let bytes = &payload[TERMINAL_GZIP_CHUNK_HEADER_LEN..];
    if bytes.is_empty() {
        return Err(TerminalGzipChunkError::EmptyChunk);
    }
    if bytes.len() != expected_chunk_len {
        return Err(TerminalGzipChunkError::BadChunkLength {
            actual: bytes.len(),
            expected: expected_chunk_len,
        });
    }
    Ok(TerminalGzipChunk {
        index,
        count,
        encoded_len,
        decoded_len,
        final_chunk,
        bytes,
    })
}

/// A parsed binary frame (borrows the payload from the input buffer).
#[derive(Debug, PartialEq, Eq)]
pub struct Frame<'a> {
    pub kind: FrameKind,
    pub channel: u16,
    pub payload: &'a [u8],
}

#[derive(Debug, PartialEq, Eq)]
pub enum FrameError {
    Short,           // fewer bytes than the header / declared length
    BadVersion(u8),  // unknown version
    BadKind(u8),     // unknown kind
    TooLarge(usize), // declared length > MAX_FRAME_PAYLOAD
    Trailing,        // extra bytes after the declared payload
}

/// Encode one binary frame. `payload` must be ≤ MAX_FRAME_PAYLOAD.
pub fn encode(kind: FrameKind, channel: u16, payload: &[u8]) -> Result<Vec<u8>, FrameError> {
    if payload.len() > MAX_FRAME_PAYLOAD {
        return Err(FrameError::TooLarge(payload.len()));
    }
    let mut out = Vec::with_capacity(HEADER_LEN + payload.len());
    out.push(FRAME_VERSION);
    out.push(kind as u8);
    out.extend_from_slice(&channel.to_be_bytes());
    out.extend_from_slice(&(payload.len() as u32).to_be_bytes());
    out.extend_from_slice(payload);
    Ok(out)
}

/// Parse exactly one binary frame from `buf` (one DataChannel binary message = one frame). Rejects an
/// unknown version/kind, an oversized declared length, a short buffer, or trailing bytes.
pub fn decode(buf: &[u8]) -> Result<Frame<'_>, FrameError> {
    if buf.len() < HEADER_LEN {
        return Err(FrameError::Short);
    }
    let version = buf[0];
    if version != FRAME_VERSION {
        return Err(FrameError::BadVersion(version));
    }
    let kind = FrameKind::from_u8(buf[1]).ok_or(FrameError::BadKind(buf[1]))?;
    let channel = u16::from_be_bytes([buf[2], buf[3]]);
    let len = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]) as usize;
    if len > MAX_FRAME_PAYLOAD {
        return Err(FrameError::TooLarge(len));
    }
    let end = HEADER_LEN + len;
    if buf.len() < end {
        return Err(FrameError::Short);
    }
    if buf.len() > end {
        return Err(FrameError::Trailing);
    }
    Ok(Frame {
        kind,
        channel,
        payload: &buf[HEADER_LEN..end],
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trips_input_and_output() {
        for kind in [FrameKind::TerminalInput, FrameKind::TerminalOutput] {
            let payload = b"hello \x00\x01\x02 world";
            let bytes = encode(kind, 7, payload).unwrap();
            let f = decode(&bytes).unwrap();
            assert_eq!(f.kind, kind);
            assert_eq!(f.channel, 7);
            assert_eq!(f.payload, payload);
        }
    }

    #[test]
    fn empty_payload_is_valid() {
        let bytes = encode(FrameKind::TerminalInput, 0, b"").unwrap();
        let f = decode(&bytes).unwrap();
        assert_eq!(f.payload, b"");
        assert_eq!(f.channel, 0);
    }

    #[test]
    fn unknown_version_rejected() {
        let mut bytes = encode(FrameKind::TerminalInput, 1, b"x").unwrap();
        bytes[0] = 99;
        assert_eq!(decode(&bytes), Err(FrameError::BadVersion(99)));
    }

    #[test]
    fn unknown_kind_rejected() {
        let mut bytes = encode(FrameKind::TerminalInput, 1, b"x").unwrap();
        bytes[1] = 200;
        assert_eq!(decode(&bytes), Err(FrameError::BadKind(200)));
    }

    #[test]
    fn oversized_declared_length_rejected_without_allocating() {
        // header claims a huge length but the buffer is small → TooLarge, not a giant read.
        let mut bytes = vec![FRAME_VERSION, FrameKind::TerminalInput as u8, 0, 0];
        bytes.extend_from_slice(&((MAX_FRAME_PAYLOAD as u32) + 1).to_be_bytes());
        assert_eq!(
            decode(&bytes),
            Err(FrameError::TooLarge(MAX_FRAME_PAYLOAD + 1))
        );
    }

    #[test]
    fn encode_rejects_oversized_payload() {
        let big = vec![0u8; MAX_FRAME_PAYLOAD + 1];
        assert_eq!(
            encode(FrameKind::TerminalOutput, 0, &big),
            Err(FrameError::TooLarge(big.len()))
        );
    }

    #[test]
    fn short_buffer_rejected() {
        assert_eq!(decode(&[1, 1, 0]), Err(FrameError::Short));
        // header says 4 bytes but only 2 follow
        let mut bytes = vec![
            FRAME_VERSION,
            FrameKind::TerminalInput as u8,
            0,
            0,
            0,
            0,
            0,
            4,
        ];
        bytes.extend_from_slice(b"ab");
        assert_eq!(decode(&bytes), Err(FrameError::Short));
    }

    #[test]
    fn trailing_bytes_rejected() {
        let mut bytes = encode(FrameKind::TerminalInput, 0, b"ab").unwrap();
        bytes.push(0xff);
        assert_eq!(decode(&bytes), Err(FrameError::Trailing));
    }

    /// Cross-language fixtures shared with the TS codec (web-client terminal-frame.test.ts
    /// SHARED_FRAME_FIXTURES). The exact (kind, channel, payload) → frame bytes MUST match so the browser
    /// client and the agent agree on the wire form. Keep these two lists in lockstep.
    #[test]
    fn shared_cross_language_fixtures() {
        fn hex(bytes: &[u8]) -> String {
            bytes.iter().map(|b| format!("{b:02x}")).collect()
        }
        let cases: &[(FrameKind, u16, &[u8], &str)] = &[
            (
                FrameKind::TerminalInput,
                7,
                b"hello",
                "010100070000000568656c6c6f",
            ),
            (FrameKind::TerminalOutput, 0, b"", "0102000000000000"),
            (
                FrameKind::TerminalOutput,
                258,
                &[0, 1, 2, 3],
                "010201020000000400010203",
            ),
            (
                FrameKind::TerminalGzipJsonChunk,
                258,
                &[
                    1, 1, 0, 0, 0, 1, 0, 0, 0, 8, 0, 0, 16, 0, 0, 1, 2, 3, 4, 5, 6, 7,
                ],
                "010401020000001601010000000100000008000010000001020304050607",
            ),
        ];
        for (kind, channel, payload, frame_hex) in cases {
            let bytes = encode(*kind, *channel, payload).unwrap();
            assert_eq!(
                hex(&bytes),
                *frame_hex,
                "encode fixture {kind:?} ch{channel}"
            );
            let f = decode(&bytes).unwrap();
            assert_eq!(f.kind, *kind);
            assert_eq!(f.channel, *channel);
            assert_eq!(f.payload, *payload);
        }
    }

    #[test]
    fn gzip_chunk_fixture_and_metadata_are_exact() {
        let bytes = [0, 1, 2, 3, 4, 5, 6, 7];
        let payload = encode_terminal_gzip_chunk_payload(0, 1, 8, 4096, &bytes).unwrap();
        let parsed = decode_terminal_gzip_chunk(&payload).unwrap();
        assert_eq!(parsed.index, 0);
        assert_eq!(parsed.count, 1);
        assert_eq!(parsed.encoded_len, 8);
        assert_eq!(parsed.decoded_len, 4096);
        assert!(parsed.final_chunk);
        assert_eq!(parsed.bytes, bytes);
    }

    #[test]
    fn gzip_chunk_rejects_metadata_and_finality_bombs_without_allocating() {
        let bytes = [0u8; 8];
        let valid = encode_terminal_gzip_chunk_payload(0, 1, 8, 4096, &bytes).unwrap();
        let mut bad = valid.clone();
        bad[0] = 2;
        assert_eq!(
            decode_terminal_gzip_chunk(&bad),
            Err(TerminalGzipChunkError::BadVersion(2))
        );
        let mut bad = valid.clone();
        bad[1] = 0;
        assert_eq!(
            decode_terminal_gzip_chunk(&bad),
            Err(TerminalGzipChunkError::BadFinality { index: 0, count: 1 })
        );
        let mut bad = valid.clone();
        bad[5] = 0;
        assert_eq!(
            decode_terminal_gzip_chunk(&bad),
            Err(TerminalGzipChunkError::BadCount(0))
        );
        let mut bad = valid.clone();
        bad[6..10].copy_from_slice(&((MAX_TERMINAL_CODEC_BYTES as u32) + 1).to_be_bytes());
        assert!(matches!(
            decode_terminal_gzip_chunk(&bad),
            Err(TerminalGzipChunkError::EncodedTooLarge(_))
        ));
        let mut bad = valid.clone();
        bad[10..14].copy_from_slice(&((MAX_TERMINAL_CODEC_BYTES as u32) + 1).to_be_bytes());
        assert!(matches!(
            decode_terminal_gzip_chunk(&bad),
            Err(TerminalGzipChunkError::DecodedTooLarge(_))
        ));
        let mut bad = valid.clone();
        bad[10..14].copy_from_slice(&4095u32.to_be_bytes());
        assert_eq!(
            decode_terminal_gzip_chunk(&bad),
            Err(TerminalGzipChunkError::BelowCompressionThreshold(4095))
        );
        let mut bad = valid;
        bad.pop();
        assert!(matches!(
            decode_terminal_gzip_chunk(&bad),
            Err(TerminalGzipChunkError::BadChunkLength { .. })
        ));
    }
}
