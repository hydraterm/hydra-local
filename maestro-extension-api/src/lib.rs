//! Bounded local capability contract for optional desktop extensions.
//!
//! This crate is deliberately public-core-safe: it defines version negotiation and typed,
//! content-blind viewport lease messages, but owns no transport, cloud endpoint, authentication,
//! filesystem path, process command, PTY, renderer, or remote-product behavior.

mod frame;
mod negotiation;
mod remote_desktop;
mod viewport;

pub use frame::{FrameDecodeError, MAX_EXTENSION_FRAME_BYTES};

pub use negotiation::{
    decode_hello_frame, negotiate, Capability, ExtensionHello, ExtensionHelloError,
    KnownCapability, NegotiatedExtension, NegotiationError, ProtocolRange,
    CURRENT_PROTOCOL_VERSION, MAX_CAPABILITIES, MAX_CAPABILITY_NAME_BYTES,
};
pub use remote_desktop::{
    validate_remote_desktop_response, EnrollmentCode, FilesystemMode, FilesystemModeChange,
    FilesystemModeMigrationNotice, FilesystemModeMigrationNoticeId, FilesystemModeMigrationPhase,
    RemoteDesktopDecodeError, RemoteDesktopErrorCode, RemoteDesktopExchangeError,
    RemoteDesktopExtensionResponse, RemoteDesktopHostRequest, RemoteDesktopId,
    RemoteDesktopMessageError, RemoteDesktopRequestId, RemoteDesktopResponseError,
    RemoteDesktopStatus, RemoteDesktopViewport, RemoteDesktopViewportList,
    FILESYSTEM_MODE_MIGRATION_NOTICE_ID_BYTES, MAX_ENROLLMENT_CODE_BYTES,
    MAX_FILESYSTEM_MODE_CHANGES, MAX_FILESYSTEM_MODE_PATH_BYTES, MAX_REMOTE_DESKTOP_CONNECTIONS,
    MAX_REMOTE_DESKTOP_ERROR_BYTES, MAX_REMOTE_DESKTOP_ID_BYTES, MAX_REMOTE_DESKTOP_VIEWPORTS,
};
pub use viewport::{
    ExtensionToHost, ExternalViewportLease, HostToExtension, LeaseApplyOutcome, LeaseCursor,
    LeaseId, ReclaimRequestId, SessionKey, ViewportApplyError, ViewportDecodeError,
    ViewportGeometry, ViewportLeaseBook, ViewportMessageError, ViewportReclaimReason,
    MAX_ACTIVE_VIEWPORT_LEASES, MAX_LEASE_TTL_MS, MAX_OPAQUE_ID_BYTES, MAX_TERMINAL_DIMENSION,
    MAX_VIEWPORT_PIXEL_DIMENSION,
};
