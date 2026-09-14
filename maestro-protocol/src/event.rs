//! A LIGHTWEIGHT shell-side decoder for the few daemon events the app-shell client needs,
//! deliberately decoupled from the daemon's full `DaemonEvent`/`GridSnapshot`/`Cell` types.
//!
//! The app shell first proves mutation compatibility with `DaemonInfo`, reserves a content-blind
//! operation tuple, then drives one `StartSession -> Attach{want_raw_output:false} -> Grid` flow
//! plus `ListSessions`, and watches for end-of-session. Its lightweight mirror also carries the
//! typed operation-ledger acknowledgements needed for exact recovery and retirement.
//! - `DaemonInfo` — the read-only protocol/build identity used to keep retained older daemons
//!   attach-compatible while making session creation fail closed.
//! - `Grid`     — the attach/snapshot baseline. The shell flips `status=Live` and captures the
//!   grid's `generation` to detect a later daemon respawn. It does NOT paint, so it does NOT type
//!   the cells: only `generation` (and `revision`, opportunistically) are extracted, via a thin
//!   [`GridInfo`] over a borrowed JSON object — no `Cell`/`GridSnapshot` dependency.
//! - `Sessions` — the `ListSessions` reply; the live id set for reconciliation.
//! - `SessionExited` — end of session + exit code.
//! - `Error`    — a daemon error reply, surfaced rather than swallowed.
//!
//! Every OTHER daemon event (`Output`, `Damage`, `ScrollbackRows`, `ResyncRequired`, `Channel`,
//! and anything added later) decodes to [`ShellEvent::Other`] instead of failing — a structured
//! attach streams `Damage` continuously, and a shell read loop must skip those without erroring.
//! This is the same tolerance the renderer mirror gets from its `#[serde(other)]` arm, here scoped
//! to the shell's needs.

use crate::ids::SessionId;
use crate::request::{AttachmentHandoffToken, DaemonInstanceId, SessionStartOperationToken};
use serde::{Deserialize, Serialize};

/// Lightweight live-session identity from the daemon's additive `sessions` metadata. Older
/// retained daemons omit the vector entirely; newer daemons include a generation so reconciliation
/// can distinguish a fresh same-id PTY from an ended lifetime without decoding a full grid.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SessionListInfo {
    pub id: SessionId,
    #[serde(default)]
    pub generation: Option<String>,
}

/// Why a generation-conditional `StartSession` made no daemon-map mutation.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ConditionalSessionStartRefusal {
    AttachmentInUse,
    PreconditionFailed,
    SpawnFailed,
}

/// Why a content-blind start-operation reservation was refused without adding a ledger entry.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStartOperationReserveRefusal {
    InvalidSessionId,
    LedgerFull,
    TokenInUse,
    AlreadyTerminal,
}

/// Typed acknowledgement for `ReserveStartOperation`.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SessionStartOperationReserveOutcome {
    Reserved,
    AlreadyReserved,
    Refused {
        reason: SessionStartOperationReserveRefusal,
    },
}

/// Typed result of one conditional start operation. `AlreadyApplied` is returned only for the
/// same exact tuple retained as Applied in the process-lifetime ledger; it makes an ACK retry
/// idempotent without granting a second spawn, even after Session removal or replacement.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ConditionalSessionStartOutcome {
    Applied {
        generation: String,
    },
    AlreadyApplied {
        generation: String,
    },
    Refused {
        reason: ConditionalSessionStartRefusal,
    },
}

/// Read-only status for an ambiguous conditional-start operation. It never causes a spawn.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SessionStartOperationStatus {
    Unknown,
    Reserved,
    Refused,
    Applied {
        generation: String,
        lifecycle: SessionStartOperationLifecycle,
    },
}

/// Current lifecycle observation for the exact generation recorded by an Applied ledger entry.
/// The ledger keeps the generation after map removal/replacement; lifecycle is derived under the
/// same daemon mutex used for map mutations.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionStartOperationLifecycle {
    Live,
    Exited,
    Removed,
}

/// Typed result of the compare-and-set `RetireStartOperation` barrier.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum SessionStartOperationRetireOutcome {
    Retired,
    AlreadyRetired,
    Conflict {
        current: SessionStartOperationStatus,
    },
}

/// Typed refusal for a generation-conditional Attach. Both cases are decided before acquiring an
/// attachment guard or exposing a Grid, so the caller may safely distinguish absence from an ABA
/// same-id lifetime.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionAttachRefusal {
    Missing,
    GenerationMismatch,
}

/// The subset of daemon events a Phase 1 shell client acts on. Tagged by the same `ev` field the
/// daemon emits (snake_case); any unmodeled event lands in [`ShellEvent::Other`] so a read loop
/// tolerates the full event stream. `serde(other)` requires a unit/variant with no data, so the
/// heavy events are not decoded — exactly the point.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum ShellEvent {
    DaemonInfo {
        protocol_version: u32,
        build_version: String,
        /// Opaque per-daemon-process identity. Retained peers omit it; exact cross-connection
        /// mutation/handoff authority requires it.
        #[serde(default)]
        daemon_instance_id: Option<DaemonInstanceId>,
        /// Whether Attach restore grids echo and live forwarders tag the optional output generation.
        #[serde(default)]
        output_generation_echo: bool,
        /// Whether StartSession consumes the typed child_environment HOME/SHELL pair. Absent on
        /// retained daemons means false; headless mutation must remain closed.
        #[serde(default)]
        child_environment: bool,
        /// Whether Write/Resize/Kill require and atomically enforce an exact PTY generation.
        #[serde(default)]
        generation_conditional_mutations: bool,
        /// Whether conditional Kill also refuses an exact session lifetime while it has an active
        /// attachment guard or an unclaimed handoff token. Absent on retained daemons means false.
        #[serde(default)]
        attachment_aware_conditional_kill: bool,
        /// Whether StartSession accepts an atomic daemon-map precondition and returns an exact,
        /// token-correlated acknowledgement before Attach is admitted.
        #[serde(default)]
        generation_conditional_start: bool,
        /// Whether this daemon requires Reserve -> conditional Start and retains operation status
        /// without TTL/LRU eviction until an exact retirement barrier removes it.
        #[serde(default)]
        start_operation_ledger: bool,
        /// Whether Attach atomically enforces `expected_session_generation` before guard/Grid.
        #[serde(default)]
        generation_conditional_attach: bool,
    },
    SessionAttachRefused {
        id: SessionId,
        expected_generation: String,
        daemon_instance_id: DaemonInstanceId,
        reason: SessionAttachRefusal,
    },
    /// Exact acknowledgement for a conditional StartSession mutation.
    ConditionalSessionStart {
        id: SessionId,
        operation_token: SessionStartOperationToken,
        daemon_instance_id: DaemonInstanceId,
        outcome: ConditionalSessionStartOutcome,
    },
    /// Exact acknowledgement for `ReserveStartOperation`.
    StartOperationReserved {
        id: SessionId,
        operation_token: SessionStartOperationToken,
        daemon_instance_id: DaemonInstanceId,
        outcome: SessionStartOperationReserveOutcome,
    },
    /// Exact read-only answer to `LookupStartOperation`.
    StartOperationStatus {
        id: SessionId,
        operation_token: SessionStartOperationToken,
        daemon_instance_id: DaemonInstanceId,
        status: SessionStartOperationStatus,
    },
    /// Exact acknowledgement for the compare-and-set retirement barrier.
    StartOperationRetired {
        id: SessionId,
        operation_token: SessionStartOperationToken,
        daemon_instance_id: DaemonInstanceId,
        outcome: SessionStartOperationRetireOutcome,
    },
    /// Ordered acknowledgement that one exact cancellation request was processed by the daemon
    /// instance named in the request. Unknown/already-retired tokens are idempotent success.
    AttachmentHandoffCancelled {
        id: SessionId,
        token: AttachmentHandoffToken,
        daemon_instance_id: DaemonInstanceId,
    },
    /// Authoritative grid baseline (attach restore / `Snapshot` reply). Only the lightweight
    /// [`GridInfo`] is decoded — never the cell payload.
    Grid {
        id: SessionId,
        #[serde(default)]
        output_generation: Option<u64>,
        grid: GridInfo,
    },
    /// Reply to `ListSessions`: legacy live ids plus additive per-session identity metadata.
    Sessions {
        ids: Vec<SessionId>,
        #[serde(default)]
        sessions: Vec<SessionListInfo>,
    },
    /// A session's process exited.
    SessionExited { id: SessionId, code: Option<i32> },
    /// A daemon error reply not tied to a specific stream.
    Error { message: String },
    /// Any other daemon event (`output`, `damage`, `scrollback_rows`, `resync_required`,
    /// `channel`, or a future variant). Carries no data: tolerated and ignored by the shell.
    #[serde(other)]
    Other,
}

/// The slice of a daemon `GridSnapshot` the shell reads from a `Grid` event: enough to confirm a
/// live session and detect a respawn, with NO dependency on the daemon's `Cell`/`GridSnapshot`.
/// Extra snapshot fields (cells, cursor, modes, dimensions) are simply not captured — serde ignores
/// unknown fields by default — so this stays stable as the grid payload evolves.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct GridInfo {
    /// The grid lifetime id (a UUID string on the wire). A change across attaches means the daemon
    /// respawned a fresh grid; the shell treats that as a clean baseline.
    pub generation: String,
    /// The revision the snapshot is at. Opportunistic — handy for ordering, not required to flip
    /// status. Absent in a malformed/partial grid object decodes as `None`.
    #[serde(default)]
    pub revision: Option<u64>,
}

impl ShellEvent {
    /// Decode one newline-delimited daemon event line into a [`ShellEvent`]. A well-formed event
    /// the shell does not model returns [`ShellEvent::Other`] (not an error), so a read loop can
    /// `?`-propagate only genuinely malformed JSON.
    pub fn from_line(line: &str) -> Result<ShellEvent, serde_json::Error> {
        serde_json::from_str(line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_daemon_identity() {
        let line = r#"{"ev":"daemon_info","protocol_version":1,"build_version":"0.1.0"}"#;
        assert_eq!(
            ShellEvent::from_line(line).unwrap(),
            ShellEvent::DaemonInfo {
                protocol_version: 1,
                build_version: "0.1.0".into(),
                daemon_instance_id: None,
                output_generation_echo: false,
                child_environment: false,
                generation_conditional_mutations: false,
                attachment_aware_conditional_kill: false,
                generation_conditional_start: false,
                start_operation_ledger: false,
                generation_conditional_attach: false,
            }
        );
    }

    #[test]
    fn decodes_exact_conditional_start_lookup_and_cancel_acknowledgements() {
        let start = ShellEvent::from_line(
            r#"{"ev":"conditional_session_start","id":"s1","operation_token":"11111111111141118111111111111111","daemon_instance_id":"22222222222242228222222222222222","outcome":{"status":"applied","generation":"generation-b"}}"#,
        )
        .unwrap();
        assert!(matches!(
            start,
            ShellEvent::ConditionalSessionStart {
                id: SessionId(ref id),
                outcome: ConditionalSessionStartOutcome::Applied { ref generation },
                ..
            } if id == "s1" && generation == "generation-b"
        ));

        let reserved = ShellEvent::from_line(
            r#"{"ev":"start_operation_reserved","id":"s1","operation_token":"11111111111141118111111111111111","daemon_instance_id":"22222222222242228222222222222222","outcome":{"status":"already_reserved"}}"#,
        )
        .unwrap();
        assert!(matches!(
            reserved,
            ShellEvent::StartOperationReserved {
                outcome: SessionStartOperationReserveOutcome::AlreadyReserved,
                ..
            }
        ));

        let applied_lookup = ShellEvent::from_line(
            r#"{"ev":"start_operation_status","id":"s1","operation_token":"11111111111141118111111111111111","daemon_instance_id":"22222222222242228222222222222222","status":{"status":"applied","generation":"generation-b","lifecycle":"exited"}}"#,
        )
        .unwrap();
        assert!(matches!(
            applied_lookup,
            ShellEvent::StartOperationStatus {
                status: SessionStartOperationStatus::Applied {
                    ref generation,
                    lifecycle: SessionStartOperationLifecycle::Exited,
                },
                ..
            } if generation == "generation-b"
        ));

        let retired = ShellEvent::from_line(
            r#"{"ev":"start_operation_retired","id":"s1","operation_token":"11111111111141118111111111111111","daemon_instance_id":"22222222222242228222222222222222","outcome":{"status":"conflict","current":{"status":"reserved"}}}"#,
        )
        .unwrap();
        assert!(matches!(
            retired,
            ShellEvent::StartOperationRetired {
                outcome: SessionStartOperationRetireOutcome::Conflict {
                    current: SessionStartOperationStatus::Reserved,
                },
                ..
            }
        ));

        let lookup = ShellEvent::from_line(
            r#"{"ev":"start_operation_status","id":"s1","operation_token":"11111111111141118111111111111111","daemon_instance_id":"22222222222242228222222222222222","status":{"status":"unknown"}}"#,
        )
        .unwrap();
        assert!(matches!(
            lookup,
            ShellEvent::StartOperationStatus {
                status: SessionStartOperationStatus::Unknown,
                ..
            }
        ));

        let cancelled = ShellEvent::from_line(
            r#"{"ev":"attachment_handoff_cancelled","id":"s1","token":"0123456789abcdef0123456789abcdef","daemon_instance_id":"22222222222242228222222222222222"}"#,
        )
        .unwrap();
        assert!(matches!(
            cancelled,
            ShellEvent::AttachmentHandoffCancelled { id: SessionId(ref id), .. } if id == "s1"
        ));
    }

    #[test]
    fn decodes_generation_conditional_mutation_capability() {
        let line = r#"{"ev":"daemon_info","protocol_version":3,"build_version":"0.1.0","generation_conditional_mutations":true,"attachment_aware_conditional_kill":true}"#;
        assert!(matches!(
            ShellEvent::from_line(line).unwrap(),
            ShellEvent::DaemonInfo {
                protocol_version: 3,
                generation_conditional_mutations: true,
                attachment_aware_conditional_kill: true,
                ..
            }
        ));
    }

    #[test]
    fn decodes_exact_generation_conditional_attach_refusal() {
        let event = ShellEvent::from_line(
            r#"{"ev":"session_attach_refused","id":"s1","expected_generation":"generation-a","daemon_instance_id":"22222222222242228222222222222222","reason":"generation_mismatch"}"#,
        )
        .unwrap();
        assert!(matches!(
            event,
            ShellEvent::SessionAttachRefused {
                id: SessionId(ref id),
                ref expected_generation,
                ref daemon_instance_id,
                reason: SessionAttachRefusal::GenerationMismatch,
            } if id == "s1"
                && expected_generation == "generation-a"
                && daemon_instance_id.as_str() == "22222222222242228222222222222222"
        ));
    }

    /// The EXACT canonical `Grid` event the daemon emits (copied verbatim from the daemon's
    /// `CROSS_WIRE_GRID_JSON` fixture: a full `GridSnapshot` with cells, cursor, and all mode/mouse
    /// flags). The lightweight decoder must pull `generation` out of this real, heavy payload
    /// WITHOUT modeling cells — proving it stays decoupled from the daemon grid internals. If the
    /// daemon's grid shape drifts, this literal can be re-synced from that fixture; the decoder only
    /// depends on the stable `generation` field.
    const DAEMON_GRID_LINE: &str = r#"{"ev":"grid","id":"s1","grid":{"version":2,"generation":"11111111-1111-1111-1111-111111111111","revision":5,"base_revision":4,"cols":3,"rows":1,"rows_cells":[[{"text":"界","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":2},{"text":"","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":0},{"text":"x","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}]],"cursor_line":0,"cursor_col":2,"cursor_visible":true,"cursor_shape":"beam","alt_screen":true,"app_cursor":true,"bracketed_paste":true,"focus_reporting":true,"mouse_report":true,"mouse_drag":true,"mouse_motion":true,"mouse_sgr":true}}"#;

    #[test]
    fn row_copy_fields_do_not_change_shell_identity_decoding() {
        let mut value: serde_json::Value = serde_json::from_str(DAEMON_GRID_LINE).unwrap();
        value["grid"]["row_copy"] =
            serde_json::json!([{ "soft_wrap": true, "excluded_columns": [] }]);
        let ShellEvent::Grid { grid, .. } = ShellEvent::from_line(&value.to_string()).unwrap()
        else {
            panic!("grid")
        };
        assert_eq!(grid.generation, "11111111-1111-1111-1111-111111111111");
        assert_eq!(grid.revision, Some(5));
    }

    #[test]
    fn decodes_grid_generation_from_full_daemon_snapshot() {
        let ev = ShellEvent::from_line(DAEMON_GRID_LINE).unwrap();
        match ev {
            ShellEvent::Grid { id, grid, .. } => {
                assert_eq!(id, SessionId("s1".into()));
                assert_eq!(grid.generation, "11111111-1111-1111-1111-111111111111");
                assert_eq!(grid.revision, Some(5));
            }
            other => panic!("expected Grid, got {other:?}"),
        }
    }

    #[test]
    fn decodes_sessions_ids() {
        let line = r#"{"ev":"sessions","ids":["a","b","c"]}"#;
        match ShellEvent::from_line(line).unwrap() {
            ShellEvent::Sessions { ids, sessions } => {
                assert!(sessions.is_empty(), "legacy reply has no metadata");
                assert_eq!(
                    ids,
                    vec![
                        SessionId("a".into()),
                        SessionId("b".into()),
                        SessionId("c".into())
                    ]
                )
            }
            other => panic!("expected Sessions, got {other:?}"),
        }
    }

    #[test]
    fn decodes_additive_live_session_generation_metadata() {
        let line = r#"{"ev":"sessions","ids":["a"],"sessions":[{"id":"a","cwd":"/tmp","generation":"gen-a"}]}"#;
        match ShellEvent::from_line(line).unwrap() {
            ShellEvent::Sessions { ids, sessions } => {
                assert_eq!(ids, vec![SessionId("a".into())]);
                assert_eq!(
                    sessions,
                    vec![SessionListInfo {
                        id: SessionId("a".into()),
                        generation: Some("gen-a".into()),
                    }]
                );
            }
            other => panic!("expected Sessions, got {other:?}"),
        }
    }

    #[test]
    fn decodes_session_exited_with_and_without_code() {
        match ShellEvent::from_line(r#"{"ev":"session_exited","id":"s1","code":0}"#).unwrap() {
            ShellEvent::SessionExited { id, code } => {
                assert_eq!(id, SessionId("s1".into()));
                assert_eq!(code, Some(0));
            }
            other => panic!("expected SessionExited, got {other:?}"),
        }
        match ShellEvent::from_line(r#"{"ev":"session_exited","id":"s1","code":null}"#).unwrap() {
            ShellEvent::SessionExited { code, .. } => assert_eq!(code, None),
            other => panic!("expected SessionExited, got {other:?}"),
        }
    }

    #[test]
    fn decodes_error_message() {
        match ShellEvent::from_line(r#"{"ev":"error","message":"boom"}"#).unwrap() {
            ShellEvent::Error { message } => assert_eq!(message, "boom"),
            other => panic!("expected Error, got {other:?}"),
        }
    }

    /// Every event the shell does NOT act on must decode to `Other` (not error), so a structured
    /// attach — which streams `damage` continuously, plus `output`/`resync_required`/`channel`/
    /// `scrollback_rows` — never breaks a shell read loop. We feed representative lines for each.
    #[test]
    fn tolerates_unrelated_events_as_other() {
        let lines = [
            // damage (heavy, grid-coupled) — decoder must NOT try to parse its frame.
            r#"{"ev":"damage","frame":{"schema":1,"id":"s1","generation":"g","base_revision":4,"revision":5,"cols":10,"rows":4,"cursor":{"line":1,"col":2,"visible":true,"shape":"block"},"modes":{"alt_screen":false,"app_cursor":false,"bracketed_paste":false,"focus_reporting":false,"mouse_report":false,"mouse_drag":false,"mouse_motion":false,"mouse_sgr":false},"ops":[]}}"#,
            r#"{"ev":"output","id":"s1","generation":"g","revision":7,"data":"aGVsbG8="}"#,
            r#"{"ev":"resync_required","id":"s1"}"#,
            r#"{"ev":"scrollback_rows","id":"s1","generation":"g","revision":7,"history_len":5000,"offset_from_top":3,"rows":[]}"#,
            r#"{"ev":"channel","event":{"channel":"c1","from":null,"kind":"chat_msg","text":"hi","ts":1}}"#,
            // A hypothetical future event the shell has never seen still tolerated.
            r#"{"ev":"some_future_event","whatever":123}"#,
        ];
        for line in lines {
            assert_eq!(
                ShellEvent::from_line(line).unwrap(),
                ShellEvent::Other,
                "unrelated event must decode to Other, not fail: {line}"
            );
        }
    }

    /// Genuinely malformed JSON IS an error (so a read loop can distinguish "tolerable event" from
    /// "corrupt line"), unlike a well-formed-but-unmodeled event.
    #[test]
    fn malformed_json_is_an_error_not_other() {
        assert!(ShellEvent::from_line("{not json").is_err());
    }

    /// A `Grid` whose snapshot lacks `revision` still decodes (revision is optional); generation is
    /// the only required field.
    #[test]
    fn grid_without_revision_decodes_generation_only() {
        let line = r#"{"ev":"grid","id":"s1","grid":{"generation":"g-42"}}"#;
        match ShellEvent::from_line(line).unwrap() {
            ShellEvent::Grid { grid, .. } => {
                assert_eq!(grid.generation, "g-42");
                assert_eq!(grid.revision, None);
            }
            other => panic!("expected Grid, got {other:?}"),
        }
    }
}
