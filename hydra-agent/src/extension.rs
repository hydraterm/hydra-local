//! Bounded, two-phase stdin/stdout adapter for the public extension contract.
//!
//! The wire DTOs and their validation live in `maestro-extension-api`; this
//! private crate only supplies newline framing and executes the private remote
//! authority operations. Enrollment material is accepted only in the second
//! stdin frame. It never appears in argv, environment variables, responses, or
//! diagnostic text.

use maestro_extension_api::{
    decode_hello_frame, negotiate, Capability, ExtensionHello, KnownCapability,
    NegotiatedExtension, RemoteDesktopHostRequest, MAX_EXTENSION_FRAME_BYTES,
};
use serde::Serialize;
use std::fmt;
use std::io::{BufRead, Write};

/// State created only after the public host hello has been decoded and the
/// lifecycle capability has been negotiated. Holding this value is required to
/// decode a lifecycle request, so request decoding cannot accidentally bypass
/// phase one.
pub struct LifecycleExchange {
    negotiated: NegotiatedExtension,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExchangeError {
    EmptyFrame,
    FrameTooLarge,
    UnterminatedFrame,
    ReadFailed,
    WriteFailed,
    InvalidHello,
    UnsupportedProtocol,
    LifecycleNotNegotiated,
    InvalidRequest,
    TrailingInput,
    ResponseTooLarge,
}

impl fmt::Display for ExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Deliberately fixed diagnostic text. In particular, serde errors are
        // not surfaced because their context can contain enrollment material.
        formatter.write_str(match self {
            Self::EmptyFrame => "empty extension frame",
            Self::FrameTooLarge => "extension frame exceeds the size limit",
            Self::UnterminatedFrame => "extension frame is not newline terminated",
            Self::ReadFailed => "could not read extension frame",
            Self::WriteFailed => "could not write extension frame",
            Self::InvalidHello => "invalid extension hello",
            Self::UnsupportedProtocol => "extension protocol versions do not overlap",
            Self::LifecycleNotNegotiated => "remote desktop lifecycle was not negotiated",
            Self::InvalidRequest => "invalid remote desktop lifecycle request",
            Self::TrailingInput => "extension exchange contains trailing input",
            Self::ResponseTooLarge => "extension response exceeds the size limit",
        })
    }
}

impl std::error::Error for ExchangeError {}

/// The private extension implements lifecycle directly and proxies the typed, content-blind
/// viewport capability to the live peer's fixed same-user control socket.
pub fn extension_hello() -> ExtensionHello {
    ExtensionHello::host([
        Capability::remote_desktop_lifecycle_v1(),
        Capability::external_viewport_lease_v1(),
        Capability::filesystem_mode_migration_v1(),
        Capability::enrollment_failure_v1(),
    ])
    .expect("the built-in extension capabilities are valid")
}

pub fn decode_host_hello(frame: &[u8]) -> Result<ExtensionHello, ExchangeError> {
    decode_hello_frame(frame).map_err(|_| ExchangeError::InvalidHello)
}

impl LifecycleExchange {
    pub fn negotiate(host: &ExtensionHello) -> Result<Self, ExchangeError> {
        let extension = extension_hello();
        let negotiated =
            negotiate(host, &extension).map_err(|_| ExchangeError::UnsupportedProtocol)?;
        if !negotiated.supports(KnownCapability::RemoteDesktopLifecycleV1) {
            return Err(ExchangeError::LifecycleNotNegotiated);
        }
        Ok(Self { negotiated })
    }

    pub fn decode_request(&self, frame: &[u8]) -> Result<RemoteDesktopHostRequest, ExchangeError> {
        self.negotiated
            .decode_remote_desktop_host_frame(frame)
            .map_err(|_| ExchangeError::InvalidRequest)
    }

    pub fn supports_filesystem_mode_migration(&self) -> bool {
        self.negotiated
            .supports(KnownCapability::FilesystemModeMigrationV1)
    }

    pub fn supports_enrollment_failure(&self) -> bool {
        self.negotiated
            .supports(KnownCapability::EnrollmentFailureV1)
    }
}

/// Read one newline-delimited frame without allowing an attacker-controlled
/// line to grow the buffer beyond the public contract's maximum plus framing.
pub fn read_frame(reader: &mut impl BufRead) -> Result<Vec<u8>, ExchangeError> {
    let mut bytes = Vec::new();
    let mut bounded = std::io::Read::take(reader, (MAX_EXTENSION_FRAME_BYTES + 2) as u64);
    bounded
        .read_until(b'\n', &mut bytes)
        .map_err(|_| ExchangeError::ReadFailed)?;

    if bytes.last() != Some(&b'\n') {
        return if bytes.len() > MAX_EXTENSION_FRAME_BYTES {
            Err(ExchangeError::FrameTooLarge)
        } else {
            Err(ExchangeError::UnterminatedFrame)
        };
    }
    bytes.pop();
    if bytes.last() == Some(&b'\r') {
        bytes.pop();
    }
    if bytes.is_empty() {
        return Err(ExchangeError::EmptyFrame);
    }
    if bytes.len() > MAX_EXTENSION_FRAME_BYTES {
        return Err(ExchangeError::FrameTooLarge);
    }
    Ok(bytes)
}

/// Serialize one public DTO, enforce the same bound in the response direction,
/// terminate it with a newline, and flush so phase-one negotiation cannot
/// deadlock while the host waits for the extension hello.
pub fn write_frame(writer: &mut impl Write, value: &impl Serialize) -> Result<(), ExchangeError> {
    let bytes = serde_json::to_vec(value).map_err(|_| ExchangeError::WriteFailed)?;
    if bytes.len() > MAX_EXTENSION_FRAME_BYTES {
        return Err(ExchangeError::ResponseTooLarge);
    }
    writer
        .write_all(&bytes)
        .and_then(|_| writer.write_all(b"\n"))
        .and_then(|_| writer.flush())
        .map_err(|_| ExchangeError::WriteFailed)
}

/// Require the host to close stdin immediately after its one request. This is
/// checked before any lifecycle mutation, so a valid request followed by a
/// third frame (or even one trailing byte) cannot be smuggled through a
/// successful one-shot exchange.
pub fn require_eof(reader: &mut impl std::io::Read) -> Result<(), ExchangeError> {
    let mut byte = [0u8; 1];
    match reader.read(&mut byte) {
        Ok(0) => Ok(()),
        Ok(_) => Err(ExchangeError::TrailingInput),
        Err(_) => Err(ExchangeError::ReadFailed),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use maestro_extension_api::{
        EnrollmentCode, RemoteDesktopHostRequest, RemoteDesktopRequestId, CURRENT_PROTOCOL_VERSION,
        MAX_ENROLLMENT_CODE_BYTES,
    };
    use std::io::{BufReader, Cursor};

    fn hello_line(capabilities: &str) -> Vec<u8> {
        format!(
            "{{\"protocol\":{{\"min\":{CURRENT_PROTOCOL_VERSION},\"max\":{CURRENT_PROTOCOL_VERSION}}},\"capabilities\":[{capabilities}]}}\n"
        )
        .into_bytes()
    }

    #[test]
    fn newline_framing_is_bounded_for_both_exchange_phases() {
        let mut reader =
            BufReader::new(Cursor::new(hello_line(r#""remote_desktop_lifecycle_v1""#)));
        assert!(read_frame(&mut reader).is_ok());

        let mut oversized = vec![b'x'; MAX_EXTENSION_FRAME_BYTES + 1];
        oversized.push(b'\n');
        let mut reader = BufReader::new(Cursor::new(oversized));
        assert_eq!(read_frame(&mut reader), Err(ExchangeError::FrameTooLarge));

        let mut reader = BufReader::new(Cursor::new(b"{}"));
        assert_eq!(
            read_frame(&mut reader),
            Err(ExchangeError::UnterminatedFrame)
        );
    }

    #[test]
    fn lifecycle_request_cannot_decode_until_capability_negotiates() {
        let no_capability = decode_host_hello(
            &read_frame(&mut BufReader::new(Cursor::new(hello_line("")))).unwrap(),
        )
        .unwrap();
        assert!(matches!(
            LifecycleExchange::negotiate(&no_capability),
            Err(ExchangeError::LifecycleNotNegotiated)
        ));

        let lifecycle = decode_host_hello(
            &read_frame(&mut BufReader::new(Cursor::new(hello_line(
                r#""remote_desktop_lifecycle_v1""#,
            ))))
            .unwrap(),
        )
        .unwrap();
        let exchange = LifecycleExchange::negotiate(&lifecycle).unwrap();
        assert!(!exchange.supports_enrollment_failure());
        let request = exchange
            .decode_request(br#"{"type":"status","request_id":7}"#)
            .unwrap();
        assert_eq!(request.request_id().get(), 7);

        let current = LifecycleExchange::negotiate(&extension_hello()).unwrap();
        assert!(current.supports_enrollment_failure());
    }

    #[test]
    fn public_dto_enforces_secret_bound_and_unknown_fields() {
        let host = extension_hello();
        let exchange = LifecycleExchange::negotiate(&host).unwrap();
        let too_long = format!(
            r#"{{"type":"enroll","request_id":1,"code":"{}"}}"#,
            "X".repeat(MAX_ENROLLMENT_CODE_BYTES + 1)
        );
        assert_eq!(
            exchange.decode_request(too_long.as_bytes()).unwrap_err(),
            ExchangeError::InvalidRequest
        );
        assert_eq!(
            exchange
                .decode_request(
                    br#"{"type":"enroll","request_id":1,"code":"secret","cloud":"https://attacker.invalid"}"#,
                )
                .unwrap_err(),
            ExchangeError::InvalidRequest
        );
    }

    #[test]
    fn transport_errors_never_repeat_enrollment_material() {
        let host = extension_hello();
        let exchange = LifecycleExchange::negotiate(&host).unwrap();
        let secret = "TOP-SECRET-ENROLLMENT-CODE";
        let frame =
            format!(r#"{{"type":"enroll","request_id":1,"code":"{secret}","unknown":true}}"#);
        let error = exchange
            .decode_request(frame.as_bytes())
            .unwrap_err()
            .to_string();
        assert!(!error.contains(secret));
    }

    #[test]
    fn public_types_round_trip_through_private_framing_without_private_wire_dtos() {
        let request = RemoteDesktopHostRequest::Enroll {
            request_id: RemoteDesktopRequestId::new(11).unwrap(),
            code: EnrollmentCode::new("A2B3C4D5").unwrap(),
        };
        let mut output = Vec::new();
        write_frame(&mut output, &request).unwrap();
        let host = extension_hello();
        let decoded = LifecycleExchange::negotiate(&host)
            .unwrap()
            .decode_request(output.strip_suffix(b"\n").unwrap())
            .unwrap();
        assert_eq!(decoded.request_id().get(), 11);
    }

    #[test]
    fn request_must_be_followed_by_eof_not_a_third_frame() {
        let mut valid = Cursor::new(Vec::<u8>::new());
        assert_eq!(require_eof(&mut valid), Ok(()));

        let mut trailing = Cursor::new(b"{\"type\":\"status\"}\n".to_vec());
        assert_eq!(
            require_eof(&mut trailing),
            Err(ExchangeError::TrailingInput)
        );
    }
}
