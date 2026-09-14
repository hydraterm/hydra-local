//! `maestro-protocol` — the shared Maestro wire protocol boundary.
//!
//! This crate owns the *request-side*, daemon-runtime-INDEPENDENT wire types so the daemon,
//! the renderer, and the app shell can speak one protocol without a direct crate dependency on
//! the daemon's internals (its grid/session/revision modules). It has NO `tokio`, NO PTY, NO
//! `alacritty_terminal`, and no knowledge of how the daemon parses terminals — only the JSON
//! contract.
//!
//! This crate provides:
//! - The id newtypes the wire is keyed by (`SessionId`, `ChannelId`).
//! - The channel-bus payload (`ChannelEventKind`, `ChannelEvent`).
//! - Everything the UI/shell SENDS (`ClientRequest`) plus the framing cap (`MAX_LINE_BYTES`).
//! - The closed HTTP(S) terminal-link validator and shared wire caps used by both
//!   daemon and renderer mirrors.
//! - A LIGHTWEIGHT shell-side decoder ([`event`]) for the handful of daemon events the Phase 1
//!   app-shell client needs (`Grid` generation, `Sessions` ids, `SessionExited`, `Error`) that
//!   TOLERATES every other event (`Damage`/`Output`/`ScrollbackRows`/`ResyncRequired`/`Channel`)
//!   without failing a read loop.
//!
//! The full `DaemonEvent` enum, `GridSnapshot`, `DamageFrame`, `Cell`, `Revision`, and
//! `SessionGeneration` remain daemon-owned. The shell does
//! not need the heavy grid payload typed — it reads a `Grid` event's `generation` and ignores the
//! cells — so this crate stays free of daemon grid internals.
//!
//! The serde shapes here are byte-for-byte identical to the daemon's originals; the daemon's
//! existing `cross_wire_*` fixtures remain the regression net that proves no drift.

pub mod channel;
pub mod endpoint;
pub mod event;
pub mod ids;
pub mod request;
pub mod row_copy;
pub mod terminal_link;

pub use channel::{ChannelEvent, ChannelEventKind};
pub use endpoint::daemon_socket_filename;
pub use event::{
    ConditionalSessionStartOutcome, ConditionalSessionStartRefusal, GridInfo, SessionAttachRefusal,
    SessionListInfo, SessionStartOperationLifecycle, SessionStartOperationReserveOutcome,
    SessionStartOperationReserveRefusal, SessionStartOperationRetireOutcome,
    SessionStartOperationStatus, ShellEvent,
};
pub use ids::{ChannelId, SessionId};
pub use request::{
    AttachmentHandoff, AttachmentHandoffToken, ChildEnvironment, ClientRequest,
    ConditionalSessionStart, DaemonInstanceId, SessionStartOperationRetireExpectation,
    SessionStartOperationToken, SessionStartPrecondition, DAEMON_PROTOCOL_VERSION, MAX_LINE_BYTES,
    MAX_START_OPERATION_SESSION_ID_BYTES,
};
pub use terminal_link::{
    is_safe_terminal_http_url, MAX_TERMINAL_LINK_CELLS_PER_FRAME, MAX_TERMINAL_URL_BYTES,
};
