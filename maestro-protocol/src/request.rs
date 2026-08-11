//! Everything the UI/shell SENDS to the daemon, plus the shared framing cap.
//!
//! `ClientRequest` is internally tagged by `op` (snake_case). The serde shape is identical to the
//! daemon's original `protocol.rs` definition — same variant set, field names, and the
//! `want_raw_output` default — so a request built here parses byte-for-byte in the daemon's
//! `serde_json::from_str::<ClientRequest>`.

use crate::channel::ChannelEvent;
use crate::ids::{ChannelId, SessionId};
use serde::{Deserialize, Serialize};

/// Hard ceiling on the byte length of ONE newline-delimited wire line, in either direction. Bounds
/// deserialization memory: a peer cannot make us buffer an unbounded line before we even attempt to
/// parse it. A longer line is a framing violation and the connection/read is dropped, never grown
/// without limit. The daemon's request reader, the renderer's event reader, and the app-shell
/// client all enforce this same cap.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

/// App/daemon control-protocol generation. A client probes this before reusing a
/// retained daemon so it never silently pairs a new renderer with an obsolete
/// PTY owner. Additive terminal grid revisions have their own schema versions.
/// Version 2 adds explicit exited-session restart authority and live-only session listings. A v2
/// GUI may still attach to a retained v1 daemon, but must not send mutating StartSession requests to
/// it because v1 could reap unrelated exited snapshots as a side effect.
pub const DAEMON_PROTOCOL_VERSION: u32 = 2;

/// serde default for `Attach.want_raw_output`: absence identifies a compatibility client, which
/// must keep receiving raw output.
fn default_true() -> bool {
    true
}

fn is_false(value: &bool) -> bool {
    !*value
}

/// Requests the UI sends to the daemon.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ClientRequest {
    /// Lightweight identity handshake. Safe on a dedicated probe connection and
    /// never mutates sessions; old daemons reject/close only that probe.
    DaemonInfo,
    /// Start a new agent session (spawn a PTY). If `id` already exists and is alive, this is a
    /// no-op reattach.
    StartSession {
        id: SessionId,
        cwd: String,
        command: String,
        args: Vec<String>,
        cols: u16,
        rows: u16,
        /// Explicit authority to replace an exited, retained same-id session with a new process.
        /// Missing/false is the safe attach-or-create behavior: a live same-id session is reused,
        /// while an exited same-id session keeps its final grid and exit latch and the request is
        /// refused. Skipped when false so attach/create requests remain decodable by retained older
        /// daemons; v2 clients nevertheless prohibit StartSession mutation against those daemons.
        #[serde(default, skip_serializing_if = "is_false")]
        restart_exited: bool,
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
        /// Optional connection-local generation chosen by a proxy/client that needs an exact
        /// output ownership boundary. A supporting daemon echoes it on this Attach's authoritative
        /// restore Grid and tags that Attach's live forwarder events. Older daemons ignore the
        /// additive field.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_generation: Option<u64>,
    },
    /// Stop streaming a session to this client (the inverse of Attach). The session keeps running;
    /// only this client's forwarder ends.
    Detach { id: SessionId },
    /// Write raw bytes to a session's PTY (keystrokes / paste).
    Write { id: SessionId, data: String },
    /// Resize a session's PTY.
    Resize { id: SessionId, cols: u16, rows: u16 },
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
    /// Kill a session's process and drop it.
    Kill { id: SessionId },
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
            cols: 80,
            rows: 24,
            restart_exited: false,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(
            json,
            r#"{"op":"start_session","id":"s1","cwd":"/tmp/work","command":"bash","args":["-l"],"cols":80,"rows":24}"#
        );
    }

    #[test]
    fn explicit_exited_restart_serializes_authority_and_absent_defaults_safe() {
        let request = ClientRequest::StartSession {
            id: sid("s1"),
            cwd: "/tmp/work".into(),
            command: "bash".into(),
            args: vec![],
            cols: 80,
            rows: 24,
            restart_exited: true,
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
            output_generation: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"op":"attach","id":"s1","want_raw_output":false}"#);
    }

    #[test]
    fn attach_output_generation_is_additive_and_optional() {
        let req = ClientRequest::Attach {
            id: sid("s1"),
            want_raw_output: false,
            output_generation: Some(42),
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
                cols: 100,
                rows: 40,
                restart_exited: false,
            },
            ClientRequest::Attach {
                id: sid("s1"),
                want_raw_output: false,
                output_generation: None,
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
