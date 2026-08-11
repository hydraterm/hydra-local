//! Versioned record envelope. Every persisted record is wrapped so a future format change is
//! DETECTABLE, never guessed: an unknown `schema` is rejected, and a `schema_version` newer
//! than this build understands is treated as read-only/unmigratable (surfaced, never silently
//! rewritten).

use serde::{de::DeserializeOwned, Deserialize, Serialize};

/// The envelope schema version this build writes and can read. A file stamped HIGHER than this
/// was written by a newer Maestro and must not be rewritten by us (we might drop fields we
/// don't model). A file stamped lower is readable (forward fields are additive); when
/// migrations exist they run on read, but none are currently registered.
pub const SCHEMA_VERSION: u32 = 1;

/// Identifies who wrote a record, for forensic/debug context. Format `maestro-shell/<ver>`.
fn written_by() -> String {
    format!("maestro-shell/{}", env!("CARGO_PKG_VERSION"))
}

/// A versioned wrapper around a typed record payload.
///
/// `schema` is the logical record kind (e.g. `"maestro.session"`); a reader that expects a
/// different kind rejects it rather than mis-deserializing. `schema_version` gates
/// forward-compat. `record` is the typed payload, kept generic so one envelope type serves
/// every record kind.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Envelope<T> {
    pub schema: String,
    pub schema_version: u32,
    pub written_by: String,
    pub written_at_ms: u64,
    pub record: T,
}

/// Why an envelope could not be accepted.
#[derive(Debug, PartialEq, Eq)]
pub enum EnvelopeError {
    /// The `schema` string did not match the kind the reader expected.
    SchemaMismatch { expected: String, got: String },
    /// The `schema_version` is newer than this build understands; the record is read-only and
    /// must not be rewritten.
    FutureVersion { ours: u32, got: u32 },
    /// The bytes did not parse as a valid envelope of the requested payload type.
    Malformed(String),
}

impl std::fmt::Display for EnvelopeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EnvelopeError::SchemaMismatch { expected, got } => {
                write!(f, "schema mismatch: expected {expected}, got {got}")
            }
            EnvelopeError::FutureVersion { ours, got } => write!(
                f,
                "record schema_version {got} is newer than supported {ours}; treating as read-only"
            ),
            EnvelopeError::Malformed(e) => write!(f, "malformed envelope: {e}"),
        }
    }
}

impl std::error::Error for EnvelopeError {}

impl<T> Envelope<T>
where
    T: Serialize,
{
    /// Wrap a record with the given logical `schema` kind, stamping the current build/version
    /// and `written_at_ms`.
    pub fn new(schema: impl Into<String>, written_at_ms: u64, record: T) -> Self {
        Envelope {
            schema: schema.into(),
            schema_version: SCHEMA_VERSION,
            written_by: written_by(),
            written_at_ms,
            record,
        }
    }

    /// Serialize to pretty JSON bytes (records are small and occasionally hand-inspected).
    pub fn to_json_bytes(&self) -> Result<Vec<u8>, EnvelopeError> {
        serde_json::to_vec_pretty(self).map_err(|e| EnvelopeError::Malformed(e.to_string()))
    }
}

impl<T> Envelope<T>
where
    T: DeserializeOwned,
{
    /// Parse bytes into an envelope and VALIDATE schema + version before yielding the payload.
    /// A schema mismatch or a future version is an error (not silently coerced), and unknown
    /// or future records are thereby kept out of the in-memory set by the caller.
    pub fn from_json_bytes(bytes: &[u8], expected_schema: &str) -> Result<Self, EnvelopeError> {
        let env: Envelope<T> =
            serde_json::from_slice(bytes).map_err(|e| EnvelopeError::Malformed(e.to_string()))?;
        if env.schema != expected_schema {
            return Err(EnvelopeError::SchemaMismatch {
                expected: expected_schema.to_string(),
                got: env.schema,
            });
        }
        if env.schema_version > SCHEMA_VERSION {
            return Err(EnvelopeError::FutureVersion {
                ours: SCHEMA_VERSION,
                got: env.schema_version,
            });
        }
        Ok(env)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    struct Demo {
        a: u32,
        b: String,
    }

    const KIND: &str = "maestro.demo";

    fn demo() -> Demo {
        Demo {
            a: 7,
            b: "hi".into(),
        }
    }

    #[test]
    fn envelope_round_trips() {
        let env = Envelope::new(KIND, 1234, demo());
        let bytes = env.to_json_bytes().unwrap();
        let back: Envelope<Demo> = Envelope::from_json_bytes(&bytes, KIND).unwrap();
        assert_eq!(back.record, demo());
        assert_eq!(back.schema, KIND);
        assert_eq!(back.schema_version, SCHEMA_VERSION);
        assert_eq!(back.written_at_ms, 1234);
        assert!(back.written_by.starts_with("maestro-shell/"));
    }

    #[test]
    fn unknown_schema_is_rejected() {
        let env = Envelope::new("maestro.something_else", 0, demo());
        let bytes = env.to_json_bytes().unwrap();
        let err = Envelope::<Demo>::from_json_bytes(&bytes, KIND).unwrap_err();
        assert_eq!(
            err,
            EnvelopeError::SchemaMismatch {
                expected: KIND.to_string(),
                got: "maestro.something_else".to_string(),
            }
        );
    }

    #[test]
    fn future_schema_version_is_rejected() {
        // Hand-craft an envelope stamped one version ahead of this build.
        let raw = format!(
            r#"{{"schema":"{KIND}","schema_version":{},"written_by":"maestro-shell/9.9.9","written_at_ms":0,"record":{{"a":1,"b":"x"}}}}"#,
            SCHEMA_VERSION + 1
        );
        let err = Envelope::<Demo>::from_json_bytes(raw.as_bytes(), KIND).unwrap_err();
        assert_eq!(
            err,
            EnvelopeError::FutureVersion {
                ours: SCHEMA_VERSION,
                got: SCHEMA_VERSION + 1,
            }
        );
    }

    #[test]
    fn malformed_bytes_are_rejected() {
        let err = Envelope::<Demo>::from_json_bytes(b"{not json", KIND).unwrap_err();
        assert!(matches!(err, EnvelopeError::Malformed(_)));
    }
}
