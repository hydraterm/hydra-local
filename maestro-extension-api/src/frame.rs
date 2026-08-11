use serde::de::DeserializeOwned;
use std::fmt;

/// Transport adapters must pass frames through the crate decoders, which enforce this limit before
/// serde sees an attacker-controlled string or vector.
pub const MAX_EXTENSION_FRAME_BYTES: usize = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum FrameDecodeError {
    Empty,
    TooLarge { got: usize, max: usize },
    InvalidJson { detail: String },
}

impl fmt::Display for FrameDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Empty => write!(f, "extension frame is empty"),
            Self::TooLarge { got, max } => {
                write!(f, "extension frame is {got} bytes; maximum is {max}")
            }
            Self::InvalidJson { detail } => write!(f, "invalid extension frame: {detail}"),
        }
    }
}

impl std::error::Error for FrameDecodeError {}

pub(crate) fn decode_bounded_json<T: DeserializeOwned>(
    bytes: &[u8],
) -> Result<T, FrameDecodeError> {
    if bytes.is_empty() {
        return Err(FrameDecodeError::Empty);
    }
    if bytes.len() > MAX_EXTENSION_FRAME_BYTES {
        return Err(FrameDecodeError::TooLarge {
            got: bytes.len(),
            max: MAX_EXTENSION_FRAME_BYTES,
        });
    }
    serde_json::from_slice(bytes).map_err(|error| FrameDecodeError::InvalidJson {
        detail: error.to_string(),
    })
}
