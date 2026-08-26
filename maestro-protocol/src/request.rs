//! Everything the UI/shell SENDS to the daemon, plus the shared framing cap.
//!
//! `ClientRequest` is internally tagged by `op` (snake_case). The serde shape is identical to the
//! daemon's original `protocol.rs` definition — same variant set, field names, and the
//! `want_raw_output` default — so a request built here parses byte-for-byte in the daemon's
//! `serde_json::from_str::<ClientRequest>`.

use crate::channel::ChannelEvent;
use crate::ids::{ChannelId, SessionId};
use serde::de::Error as _;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;
use std::str::FromStr;

/// Hard ceiling on the byte length of ONE newline-delimited wire line, in either direction. Bounds
/// deserialization memory: a peer cannot make us buffer an unbounded line before we even attempt to
/// parse it. A longer line is a framing violation and the connection/read is dropped, never grown
/// without limit. The daemon's request reader, the renderer's event reader, and the app-shell
/// client all enforce this same cap.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// App/daemon control-protocol generation. A client probes this before reusing a
/// retained daemon so it never silently pairs a new renderer with an obsolete
/// PTY owner. Additive terminal grid revisions have their own schema versions.
/// Version 2 added explicit exited-session restart authority and live-only session listings. The
/// additive headless child-environment field remains separately capability-gated by DaemonInfo.
/// Version 3 makes every existing-session terminal mutation generation-conditional: Write, Resize,
/// and Kill must carry the exact grid/process lifetime they intend to touch. A v3 client may attach
/// read-only to an older retained daemon, but must never fall back to an id-only mutation.
pub const DAEMON_PROTOCOL_VERSION: u32 = 3;

/// Fixed child environment authority for a headless StartSession. This deliberately is not a
/// general environment map: browser/caller input can never inject PATH, loader, or other process
/// variables through the daemon protocol. Absence retains the desktop/legacy daemon environment.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ChildEnvironment {
    pub home: String,
    pub shell: String,
}

/// serde default for `Attach.want_raw_output`: absence identifies a compatibility client, which
/// must keep receiving raw output.
fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Length, in lowercase hexadecimal characters, of one attachment handoff capability.
pub const ATTACHMENT_HANDOFF_TOKEN_HEX_LEN: usize = 32;

/// Length, in lowercase hexadecimal characters, of a daemon-instance or conditional-start
/// operation identity. Both are UUIDv4 values encoded without hyphens; keeping the wire values
/// fixed-width makes malformed identity authority fail at the shared protocol boundary.
pub const OPAQUE_UUID_V4_HEX_LEN: usize = 32;

/// Maximum UTF-8 byte length of a session id admitted into the daemon's process-lifetime start
/// operation ledger. The token itself is already fixed at [`OPAQUE_UUID_V4_HEX_LEN`]. Keeping the
/// bound in the shared contract lets every implementation reject an attacker-shaped identity
/// before retaining it indefinitely.
pub const MAX_START_OPERATION_SESSION_ID_BYTES: usize = 512;

fn is_simple_uuid_v4(value: &str) -> bool {
    value.len() == OPAQUE_UUID_V4_HEX_LEN
        && value
            .as_bytes()
            .iter()
            .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        && value.as_bytes()[12] == b'4'
        && matches!(value.as_bytes()[16], b'8' | b'9' | b'a' | b'b')
}

/// Opaque identity minted once when one daemon process creates its in-memory authority graph.
/// It complements kernel peer credentials on Linux and gives macOS/other Unix clients an exact
/// cross-connection daemon identity. Diagnostics redact the value so it cannot accidentally become
/// a public/loggable launch token.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct DaemonInstanceId(String);

impl DaemonInstanceId {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidDaemonInstanceId;

impl fmt::Display for InvalidDaemonInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .write_str("daemon instance id must be a lowercase UUIDv4 encoded as 32 hex characters")
    }
}

impl std::error::Error for InvalidDaemonInstanceId {}

impl FromStr for DaemonInstanceId {
    type Err = InvalidDaemonInstanceId;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        is_simple_uuid_v4(value)
            .then(|| Self(value.to_owned()))
            .ok_or(InvalidDaemonInstanceId)
    }
}

impl TryFrom<String> for DaemonInstanceId {
    type Error = InvalidDaemonInstanceId;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Serialize for DaemonInstanceId {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for DaemonInstanceId {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

impl fmt::Debug for DaemonInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DaemonInstanceId(<redacted>)")
    }
}

impl fmt::Display for DaemonInstanceId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-daemon-instance-id>")
    }
}

/// Idempotency identity for one generation-conditional `StartSession`. It is deliberately
/// distinct from an attachment handoff: it can prove that a daemon already applied the same spawn
/// request, but grants no Attach, Kill, or cancellation authority.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct SessionStartOperationToken(String);

impl SessionStartOperationToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidSessionStartOperationToken;

impl fmt::Display for InvalidSessionStartOperationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(
            "session start operation token must be a lowercase UUIDv4 encoded as 32 hex characters",
        )
    }
}

impl std::error::Error for InvalidSessionStartOperationToken {}

impl FromStr for SessionStartOperationToken {
    type Err = InvalidSessionStartOperationToken;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        is_simple_uuid_v4(value)
            .then(|| Self(value.to_owned()))
            .ok_or(InvalidSessionStartOperationToken)
    }
}

impl TryFrom<String> for SessionStartOperationToken {
    type Error = InvalidSessionStartOperationToken;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Serialize for SessionStartOperationToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for SessionStartOperationToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        String::deserialize(deserializer)?
            .parse()
            .map_err(D::Error::custom)
    }
}

impl fmt::Debug for SessionStartOperationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionStartOperationToken(<redacted>)")
    }
}

impl fmt::Display for SessionStartOperationToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-session-start-operation-token>")
    }
}

/// Daemon-map predicate checked atomically before a conditional session spawn is allowed.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum SessionStartPrecondition {
    /// The id must have no current daemon Session mapping.
    Absent {
        /// Optional durable predecessor generation that a fresh daemon no longer maps. A new
        /// generation is minted excluding it before child spawn, so recovery can never execute a
        /// replacement whose identity aliases retained durable A.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        excluded_generation: Option<String>,
    },
    /// The current mapping must be the exact exited generation and have no active/pending
    /// attachment ownership.
    ExitedGeneration { expected_generation: String },
}

/// Exact conditional-start authority carried by one additive `StartSession` request.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ConditionalSessionStart {
    pub operation_token: SessionStartOperationToken,
    pub precondition: SessionStartPrecondition,
}

/// Compare-and-set predicate for retiring one process-lifetime start operation. `Unapplied`
/// races safely with Start: either retirement removes the Reserved/Refused entry first, making a
/// delayed Start fail closed, or the caller learns the exact generation that Start published.
/// `Applied` retires only that exact generation.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SessionStartOperationRetireExpectation {
    Unapplied,
    Applied { generation: String },
}

/// Opaque one-shot authority used to transfer an exact daemon-session attachment between local
/// clients without creating an ownerless interval. The token is deliberately validated at the
/// shared protocol boundary and redacted from `Debug`/`Display`, so malformed or accidentally
/// logged caller input never becomes attachment authority or leaks into diagnostics. Callers must
/// generate a fresh cryptographically random value for every offer and never reuse a retired value.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct AttachmentHandoffToken(String);

impl AttachmentHandoffToken {
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A handoff token must be exactly 128 bits encoded as 32 lowercase hexadecimal characters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvalidAttachmentHandoffToken;

impl fmt::Display for InvalidAttachmentHandoffToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("attachment handoff token must be exactly 32 lowercase hex characters")
    }
}

impl std::error::Error for InvalidAttachmentHandoffToken {}

impl FromStr for AttachmentHandoffToken {
    type Err = InvalidAttachmentHandoffToken;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        if value.len() == ATTACHMENT_HANDOFF_TOKEN_HEX_LEN
            && value
                .as_bytes()
                .iter()
                .all(|byte| matches!(byte, b'0'..=b'9' | b'a'..=b'f'))
        {
            Ok(Self(value.to_owned()))
        } else {
            Err(InvalidAttachmentHandoffToken)
        }
    }
}

impl TryFrom<String> for AttachmentHandoffToken {
    type Error = InvalidAttachmentHandoffToken;

    fn try_from(value: String) -> Result<Self, Self::Error> {
        value.parse()
    }
}

impl Serialize for AttachmentHandoffToken {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.0)
    }
}

impl<'de> Deserialize<'de> for AttachmentHandoffToken {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let value = String::deserialize(deserializer)?;
        value.parse().map_err(D::Error::custom)
    }
}

impl fmt::Debug for AttachmentHandoffToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("AttachmentHandoffToken(<redacted>)")
    }
}

impl fmt::Display for AttachmentHandoffToken {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("<redacted-attachment-handoff-token>")
    }
}

/// Optional ownership transfer attached to one `Attach` request. An offer installs a bounded
/// pending token on the exact current daemon Session; an exact claim consumes it and installs this
/// connection's ordinary RAII attachment guard in the same daemon critical section.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum AttachmentHandoff {
    Offer { token: AttachmentHandoffToken },
    Claim { token: AttachmentHandoffToken },
}

impl AttachmentHandoff {
    pub fn token(&self) -> &AttachmentHandoffToken {
        match self {
            Self::Offer { token } | Self::Claim { token } => token,
        }
    }
}

/// Requests the UI sends to the daemon.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ClientRequest {
    /// Lightweight identity handshake. Safe on a dedicated probe connection and
    /// never mutates sessions; old daemons reject/close only that probe.
    DaemonInfo,
    /// Reserve one content-blind `(session id, operation token)` tuple in the daemon's bounded,
    /// process-lifetime ledger. A capable daemon accepts conditional Start only after this exact
    /// reservation; no command, cwd, environment, dimensions, or terminal data is retained here.
    ReserveStartOperation {
        id: SessionId,
        operation_token: SessionStartOperationToken,
    },
    /// Start a new agent session (spawn a PTY). If `id` already exists and is alive, this is a
    /// no-op reattach.
    StartSession {
        id: SessionId,
        cwd: String,
        command: String,
        args: Vec<String>,
        /// Explicit all-or-none child HOME/SHELL. Absent preserves the daemon's inherited
        /// environment and the exact legacy/desktop wire bytes.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        child_environment: Option<ChildEnvironment>,
        cols: u16,
        rows: u16,
        /// Explicit authority to replace an exited, retained same-id session with a new process.
        /// Missing/false is the safe attach-or-create behavior: a live same-id session is reused,
        /// while an exited same-id session keeps its final grid and exit latch and the request is
        /// refused. Skipped when false so attach/create requests remain decodable by retained older
        /// daemons; v2 clients nevertheless prohibit StartSession mutation against those daemons.
        #[serde(default, skip_serializing_if = "is_false")]
        restart_exited: bool,
        /// Exact daemon-map CAS + idempotency authority. New clients use this instead of the
        /// legacy restart bit; retained daemons safely ignore the additive field, but clients wait
        /// for a typed acknowledgement before sending Attach so ignored authority can never be
        /// mistaken for a successful start.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        conditional_start: Option<ConditionalSessionStart>,
    },
    /// Read-only recovery query for an ambiguous conditional start. It never spawns or replaces a
    /// process: the process-lifetime ledger reports the exact operation state even after its
    /// Session exits, is removed, or is replaced by a later same-id generation.
    LookupStartOperation {
        id: SessionId,
        operation_token: SessionStartOperationToken,
    },
    /// Retire one exact operation tuple. The exact CAS removes the bounded ledger entry; a delayed
    /// Start then sees Missing and refuses, while callers regain capacity only through this
    /// explicit barrier (never TTL/LRU eviction).
    RetireStartOperation {
        id: SessionId,
        operation_token: SessionStartOperationToken,
        expected: SessionStartOperationRetireExpectation,
    },
    /// Attach: restore from the grid snapshot then stream live output. At most one attachment per
    /// (client connection, session) — a repeat Attach replaces the previous forwarder rather than
    /// spawning a duplicate.
    ///
    /// `want_raw_output` selects the stream shape. It defaults to `true` when ABSENT so a
    /// compatibility client (which never sent the field) keeps receiving raw `Output { data }`
    /// exactly as before. A grid-aware renderer opts OUT explicitly with
    /// `want_raw_output: false`.
    /// - `true` (default / loggers / orchestrator / proxies): receive `Output { data }` in addition
    ///   to Grid/Damage/lifecycle/ResyncRequired.
    /// - `false` (grid-aware renderer): receive Grid, Damage, lifecycle, and ResyncRequired — but NOT raw
    ///   `Output { data }`. No raw PTY bytes reach the client, so there is no path to a second VT
    ///   parser.
    Attach {
        id: SessionId,
        #[serde(default = "default_true")]
        want_raw_output: bool,
        /// Optional daemon-atomic lifetime precondition. A capable daemon compares this with the
        /// current Session generation under the same map lock used to acquire the attachment guard;
        /// Missing or mismatch is refused before any Grid or foreign terminal bytes are exposed.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_session_generation: Option<String>,
        /// Optional connection-local generation chosen by a proxy/client that needs an exact
        /// output ownership boundary. A supporting daemon echoes it on this Attach's authoritative
        /// restore Grid and tags that Attach's live forwarder events. Older daemons ignore the
        /// additive field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_generation: Option<u64>,
        /// Optional exact-session attachment ownership handoff. Absent ordinary attaches preserve
        /// their legacy wire shape. The tagged enum makes offer/claim mutually exclusive.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        handoff: Option<AttachmentHandoff>,
    },
    /// Stop streaming a session to this client (the inverse of Attach). The session keeps running;
    /// only this client's forwarder ends.
    Detach { id: SessionId },
    /// Retire one exact pending handoff token. A token belongs only to the current Session object;
    /// the same id's replacement lifetime never inherits it.
    CancelAttachmentHandoff {
        id: SessionId,
        token: AttachmentHandoffToken,
        /// Bind cancellation to the daemon process that installed the token. A same-path
        /// replacement daemon must never acknowledge or consume authority minted by its predecessor.
        expected_daemon_instance: DaemonInstanceId,
    },
    /// Write raw bytes to one exact session lifetime's PTY (keystrokes / paste).
    Write {
        id: SessionId,
        expected_generation: String,
        data: String,
    },
    /// Resize one exact session lifetime's PTY.
    Resize {
        id: SessionId,
        expected_generation: String,
        cols: u16,
        rows: u16,
    },
    /// Request the authoritative grid snapshot for a session (the rendered screen the daemon
    /// holds), so a renderer can paint without re-parsing.
    Snapshot { id: SessionId },
    /// The live read-only scrollback request: a window of STRUCTURED historical rows — the rows
    /// that scrolled above the live screen, as the same `Cell` model as the grid. Read-only: the
    /// daemon never moves its own viewport to serve this, so live damage frames stay correct and
    /// multiple clients can scroll independently. The renderer asks for the exact window it needs to
    /// paint; the daemon clamps `count` server-side and replies with `ScrollbackRows`.
    Scrollback {
        id: SessionId,
        /// Topmost history line to fetch, as a NON-NEGATIVE distance ABOVE the top visible row.
        /// `1` = the row just above the screen; `0` = the top visible row itself (allowed, for
        /// overlap with the live snapshot).
        offset_from_top: u32,
        /// How many rows to return, walking DOWNWARD toward the screen. Clamped server-side.
        count: u16,
    },
    /// Kill one exact session lifetime's process and drop it.
    Kill {
        id: SessionId,
        expected_generation: String,
    },
    /// List live sessions (for reconciliation on UI start).
    ListSessions,

    /// Create or get a channel.
    OpenChannel { id: ChannelId },
    /// Subscribe a session to a channel (it will emit Output onto it and can receive
    /// Prompt/Control/ChatMsg from it).
    JoinChannel {
        channel: ChannelId,
        session: SessionId,
    },
    /// Publish an event onto a channel (e.g. a chat message or a prompt).
    Publish { event: ChannelEvent },
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sid(s: &str) -> SessionId {
        SessionId(s.to_string())
    }

    #[test]
    fn daemon_info_is_a_bare_non_mutating_probe() {
        assert_eq!(
            serde_json::to_string(&ClientRequest::DaemonInfo).unwrap(),
            r#"{"op":"daemon_info"}"#
        );
    }

    /// `StartSession` serializes to the exact `op`-tagged snake_case shape the daemon parses.
    /// Field order matches struct declaration order (serde_json preserves it), so this pins the
    /// canonical bytes.
    #[test]
    fn start_session_serializes_to_daemon_shape() {
        let req = ClientRequest::StartSession {
            id: sid("s1"),
            cwd: "/tmp/work".into(),
            command: "bash".into(),
            args: vec!["-l".into()],
            child_environment: None,
            cols: 80,
            rows: 24,
            restart_exited: false,
            conditional_start: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"op":"start_session","id":"s1","cwd":"/tmp/work","command":"bash","args":["-l"],"cols":80,"rows":24}"#
        );
    }

    #[test]
    fn child_environment_is_an_additive_typed_pair() {
        let legacy = r#"{"op":"start_session","id":"s1","cwd":"/tmp/work","command":"bash","args":[],"cols":80,"rows":24}"#;
        let decoded: ClientRequest = serde_json::from_str(legacy).unwrap();
        assert!(matches!(
            &decoded,
            ClientRequest::StartSession {
                child_environment: None,
                ..
            }
        ));
        assert_eq!(
            serde_json::to_string(&decoded).unwrap(),
            legacy,
            "an older desktop StartSession must retain its exact wire bytes"
        );

        let request = ClientRequest::StartSession {
            id: sid("s1"),
            cwd: "/srv/work".into(),
            command: "/bin/sh".into(),
            args: vec!["-l".into()],
            child_environment: Some(ChildEnvironment {
                home: "/home/user".into(),
                shell: "/bin/sh".into(),
            }),
            cols: 80,
            rows: 24,
            restart_exited: false,
            conditional_start: None,
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"op":"start_session","id":"s1","cwd":"/srv/work","command":"/bin/sh","args":["-l"],"child_environment":{"home":"/home/user","shell":"/bin/sh"},"cols":80,"rows":24}"#
        );

        for partial in [
            r#"{"op":"start_session","id":"s1","cwd":"/tmp","command":"/bin/sh","args":[],"child_environment":{"home":"/home/user"},"cols":80,"rows":24}"#,
            r#"{"op":"start_session","id":"s1","cwd":"/tmp","command":"/bin/sh","args":[],"child_environment":{"shell":"/bin/sh"},"cols":80,"rows":24}"#,
        ] {
            assert!(
                serde_json::from_str::<ClientRequest>(partial).is_err(),
                "a partial HOME/SHELL authority must fail closed"
            );
        }
    }

    #[test]
    fn explicit_exited_restart_serializes_authority_and_absent_defaults_safe() {
        let request = ClientRequest::StartSession {
            id: sid("s1"),
            cwd: "/tmp/work".into(),
            command: "bash".into(),
            args: vec![],
            child_environment: None,
            cols: 80,
            rows: 24,
            restart_exited: true,
            conditional_start: None,
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"op":"start_session","id":"s1","cwd":"/tmp/work","command":"bash","args":[],"cols":80,"rows":24,"restart_exited":true}"#
        );

        let decoded: ClientRequest = serde_json::from_str(
            r#"{"op":"start_session","id":"s1","cwd":"/tmp/work","command":"bash","args":[],"cols":80,"rows":24}"#,
        )
        .unwrap();
        assert!(matches!(
            decoded,
            ClientRequest::StartSession {
                restart_exited: false,
                ..
            }
        ));
    }

    /// `Attach { want_raw_output: false }` — the structured-only opt-out the renderer and the
    /// shell client sends — serializes with the explicit `false` field present.
    #[test]
    fn attach_false_serializes_with_explicit_flag() {
        let req = ClientRequest::Attach {
            id: sid("s1"),
            want_raw_output: false,
            expected_session_generation: None,
            output_generation: None,
            handoff: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"op":"attach","id":"s1","want_raw_output":false}"#);
    }

    #[test]
    fn attach_output_generation_is_additive_and_optional() {
        let req = ClientRequest::Attach {
            id: sid("s1"),
            want_raw_output: false,
            expected_session_generation: None,
            output_generation: Some(42),
            handoff: None,
        };
        assert_eq!(
            serde_json::to_string(&req).unwrap(),
            r#"{"op":"attach","id":"s1","want_raw_output":false,"output_generation":42}"#
        );
        let legacy: ClientRequest = serde_json::from_str(r#"{"op":"attach","id":"s1"}"#).unwrap();
        assert!(matches!(
            legacy,
            ClientRequest::Attach {
                output_generation: None,
                ..
            }
        ));
    }

    #[test]
    fn conditional_attach_generation_precondition_is_additive_and_exact() {
        let request = ClientRequest::Attach {
            id: sid("s1"),
            want_raw_output: false,
            expected_session_generation: Some("generation-a".into()),
            output_generation: Some(9),
            handoff: None,
        };
        let json = serde_json::to_string(&request).unwrap();
        assert_eq!(
            json,
            r#"{"op":"attach","id":"s1","want_raw_output":false,"expected_session_generation":"generation-a","output_generation":9}"#
        );
        assert!(matches!(
            serde_json::from_str::<ClientRequest>(&json).unwrap(),
            ClientRequest::Attach {
                id: SessionId(ref id),
                want_raw_output: false,
                expected_session_generation: Some(ref generation),
                output_generation: Some(9),
                handoff: None,
            } if id == "s1" && generation == "generation-a"
        ));
        assert!(matches!(
            serde_json::from_str::<ClientRequest>(r#"{"op":"attach","id":"s1"}"#).unwrap(),
            ClientRequest::Attach {
                expected_session_generation: None,
                ..
            }
        ));
    }

    #[test]
    fn attachment_handoff_is_additive_typed_and_cancel_is_exact() {
        let token: AttachmentHandoffToken = "0123456789abcdef0123456789abcdef".parse().unwrap();
        let daemon_instance: DaemonInstanceId = "22222222222242228222222222222222".parse().unwrap();
        let offer = ClientRequest::Attach {
            id: sid("s1"),
            want_raw_output: false,
            expected_session_generation: None,
            output_generation: None,
            handoff: Some(AttachmentHandoff::Offer {
                token: token.clone(),
            }),
        };
        assert_eq!(
            serde_json::to_string(&offer).unwrap(),
            r#"{"op":"attach","id":"s1","want_raw_output":false,"handoff":{"kind":"offer","token":"0123456789abcdef0123456789abcdef"}}"#
        );

        let claim: ClientRequest = serde_json::from_str(
            r#"{"op":"attach","id":"s1","want_raw_output":false,"handoff":{"kind":"claim","token":"0123456789abcdef0123456789abcdef"}}"#,
        )
        .unwrap();
        assert!(matches!(
            claim,
            ClientRequest::Attach {
                handoff: Some(AttachmentHandoff::Claim { token: claimed }),
                ..
            } if claimed == token
        ));

        assert_eq!(
            serde_json::to_string(&ClientRequest::CancelAttachmentHandoff {
                id: sid("s1"),
                token,
                expected_daemon_instance: daemon_instance,
            })
            .unwrap(),
            r#"{"op":"cancel_attachment_handoff","id":"s1","token":"0123456789abcdef0123456789abcdef","expected_daemon_instance":"22222222222242228222222222222222"}"#
        );
    }

    #[test]
    fn conditional_start_ledger_requests_are_typed_redacted_exact_authority() {
        let operation_token: SessionStartOperationToken =
            "11111111111141118111111111111111".parse().unwrap();
        let request = ClientRequest::StartSession {
            id: sid("s1"),
            cwd: "/tmp/work".into(),
            command: "bash".into(),
            args: vec![],
            child_environment: None,
            cols: 80,
            rows: 24,
            restart_exited: false,
            conditional_start: Some(ConditionalSessionStart {
                operation_token: operation_token.clone(),
                precondition: SessionStartPrecondition::ExitedGeneration {
                    expected_generation: "generation-a".into(),
                },
            }),
        };
        assert_eq!(
            serde_json::to_string(&request).unwrap(),
            r#"{"op":"start_session","id":"s1","cwd":"/tmp/work","command":"bash","args":[],"cols":80,"rows":24,"conditional_start":{"operation_token":"11111111111141118111111111111111","precondition":{"kind":"exited_generation","expected_generation":"generation-a"}}}"#
        );
        assert_eq!(
            serde_json::to_string(&ClientRequest::ReserveStartOperation {
                id: sid("s1"),
                operation_token: operation_token.clone(),
            })
            .unwrap(),
            r#"{"op":"reserve_start_operation","id":"s1","operation_token":"11111111111141118111111111111111"}"#
        );
        assert_eq!(
            serde_json::to_string(&ClientRequest::LookupStartOperation {
                id: sid("s1"),
                operation_token: operation_token.clone(),
            })
            .unwrap(),
            r#"{"op":"lookup_start_operation","id":"s1","operation_token":"11111111111141118111111111111111"}"#
        );
        assert_eq!(
            serde_json::to_string(&ClientRequest::RetireStartOperation {
                id: sid("s1"),
                operation_token: operation_token.clone(),
                expected: SessionStartOperationRetireExpectation::Applied {
                    generation: "generation-b".into(),
                },
            })
            .unwrap(),
            r#"{"op":"retire_start_operation","id":"s1","operation_token":"11111111111141118111111111111111","expected":{"state":"applied","generation":"generation-b"}}"#
        );
        assert!(!format!("{operation_token:?}").contains(operation_token.as_str()));
        assert!(!operation_token
            .to_string()
            .contains(operation_token.as_str()));
    }

    #[test]
    fn daemon_and_start_uuid_authority_rejects_non_v4_or_noncanonical_values() {
        for invalid in [
            "",
            "11111111111111111111111111111111",
            "11111111-1111-4111-8111-111111111111",
            "11111111111141117111111111111111",
            "1111111111114111811111111111111A",
        ] {
            assert!(invalid.parse::<DaemonInstanceId>().is_err(), "{invalid:?}");
            assert!(
                invalid.parse::<SessionStartOperationToken>().is_err(),
                "{invalid:?}"
            );
        }
        let instance: DaemonInstanceId = "22222222222242228222222222222222".parse().unwrap();
        assert!(!format!("{instance:?}").contains(instance.as_str()));
        assert!(!instance.to_string().contains(instance.as_str()));
    }

    #[test]
    fn attachment_handoff_token_validation_and_diagnostics_are_fail_closed() {
        for invalid in [
            "",
            "0123456789abcdef0123456789abcde",
            "0123456789abcdef0123456789abcdef0",
            "0123456789ABCDEF0123456789ABCDEF",
            "0123456789abcdef0123456789abcdeg",
        ] {
            assert!(
                invalid.parse::<AttachmentHandoffToken>().is_err(),
                "{invalid:?}"
            );
        }

        let secret = "fedcba9876543210fedcba9876543210";
        let token: AttachmentHandoffToken = secret.parse().unwrap();
        assert!(!format!("{token:?}").contains(secret));
        assert!(!token.to_string().contains(secret));

        let malformed = r#"{"op":"attach","id":"s1","handoff":{"kind":"offer","token":"FEDCBA9876543210FEDCBA9876543210"}}"#;
        assert!(serde_json::from_str::<ClientRequest>(malformed).is_err());
    }

    #[test]
    fn terminal_mutations_require_an_explicit_session_generation() {
        for legacy in [
            r#"{"op":"write","id":"s1","data":"x"}"#,
            r#"{"op":"resize","id":"s1","cols":80,"rows":24}"#,
            r#"{"op":"kill","id":"s1"}"#,
        ] {
            assert!(
                serde_json::from_str::<ClientRequest>(legacy).is_err(),
                "an id-only terminal mutation must fail closed: {legacy}"
            );
        }

        for conditional in [
            r#"{"op":"write","id":"s1","expected_generation":"gen-a","data":"x"}"#,
            r#"{"op":"resize","id":"s1","expected_generation":"gen-a","cols":80,"rows":24}"#,
            r#"{"op":"kill","id":"s1","expected_generation":"gen-a"}"#,
        ] {
            let request: ClientRequest = serde_json::from_str(conditional)
                .expect("generation-conditional terminal mutation must decode");
            assert_eq!(
                serde_json::to_string(&request).unwrap(),
                conditional,
                "the generation proof is mandatory wire authority"
            );
        }
    }

    /// `ListSessions` is a unit variant: a bare `{"op":"list_sessions"}`.
    #[test]
    fn list_sessions_serializes_to_bare_op() {
        let json = serde_json::to_string(&ClientRequest::ListSessions).unwrap();
        assert_eq!(json, r#"{"op":"list_sessions"}"#);
    }

    /// An attach line with NO `want_raw_output` field decodes with the flag defaulting to `true`,
    /// so a compatibility client keeps getting raw output. This is the daemon's exact
    /// contract, now owned by the shared crate.
    #[test]
    fn attach_defaults_want_raw_output_true_when_absent() {
        let req: ClientRequest = serde_json::from_str(r#"{"op":"attach","id":"s1"}"#).unwrap();
        match req {
            ClientRequest::Attach {
                want_raw_output, ..
            } => assert!(want_raw_output, "absent flag must default to true"),
            other => panic!("expected Attach, got {other:?}"),
        }
        // An explicit false still round-trips (the renderer / shell opt-out).
        let req: ClientRequest =
            serde_json::from_str(r#"{"op":"attach","id":"s1","want_raw_output":false}"#).unwrap();
        match req {
            ClientRequest::Attach {
                want_raw_output, ..
            } => assert!(!want_raw_output),
            other => panic!("expected Attach, got {other:?}"),
        }
    }

    /// The three shell-client requests round-trip through JSON unchanged (decode of what we encode).
    #[test]
    fn phase1_requests_round_trip() {
        let reqs = [
            ClientRequest::StartSession {
                id: sid("s1"),
                cwd: ".".into(),
                command: "sh".into(),
                args: vec![],
                child_environment: None,
                cols: 100,
                rows: 40,
                restart_exited: false,
                conditional_start: None,
            },
            ClientRequest::Attach {
                id: sid("s1"),
                want_raw_output: false,
                expected_session_generation: None,
                output_generation: None,
                handoff: None,
            },
            ClientRequest::ListSessions,
        ];
        for req in reqs {
            let json = serde_json::to_string(&req).unwrap();
            let back: ClientRequest = serde_json::from_str(&json).unwrap();
            assert_eq!(serde_json::to_string(&back).unwrap(), json);
        }
    }

    #[test]
    fn max_line_bytes_is_16_mib() {
        assert_eq!(MAX_LINE_BYTES, 16 * 1024 * 1024);
    }
}
