//! A LIGHTWEIGHT shell-side decoder for the few daemon events the app-shell client needs,
//! deliberately decoupled from the daemon's full `DaemonEvent`/`GridSnapshot`/`Cell` types.
//!
//! The app shell first proves mutation compatibility with `DaemonInfo`, then drives one
//! `StartSession -> Attach{want_raw_output:false} -> Grid` flow plus `ListSessions`, and watches
//! for end-of-session. To do that it only needs five events:
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
use serde::Deserialize;

/// Lightweight live-session identity from the daemon's additive `sessions` metadata. Older
/// retained daemons omit the vector entirely; newer daemons include a generation so reconciliation
/// can distinguish a fresh same-id PTY from an ended lifetime without decoding a full grid.
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct SessionListInfo {
    pub id: SessionId,
    #[serde(default)]
    pub generation: Option<String>,
}

/// The subset of daemon events a shell client acts on. Tagged by the same `ev` field the
/// daemon emits (snake_case); any unmodeled event lands in [`ShellEvent::Other`] so a read loop
/// tolerates the full event stream. `serde(other)` requires a unit/variant with no data, so the
/// heavy events are not decoded — exactly the point.
#[derive(Clone, Debug, Deserialize, PartialEq)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum ShellEvent {
    DaemonInfo {
        protocol_version: u32,
        build_version: String,
        /// Whether Attach restore grids echo and live forwarders tag the optional output generation.
        #[serde(default)]
        output_generation_echo: bool,
    },
    /// Authoritative grid baseline (attach restore / `Snapshot` reply). Only the lightweight
    /// [`GridInfo`] is decoded — never the cell payload.
    Grid { id: SessionId, grid: GridInfo },
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
                output_generation_echo: false,
            }
        );
    }

    /// The EXACT canonical `Grid` event the daemon emits (copied verbatim from the daemon's
    /// `CROSS_WIRE_GRID_JSON` fixture: a full `GridSnapshot` with cells, cursor, and all mode/mouse
    /// flags). The lightweight decoder must pull `generation` out of this real, heavy payload
    /// WITHOUT modeling cells — proving it stays decoupled from the daemon grid internals. If the
    /// daemon's grid shape drifts, this literal can be re-synced from that fixture; the decoder only
    /// depends on the stable `generation` field.
    const DAEMON_GRID_LINE: &str = r#"{"ev":"grid","id":"s1","grid":{"version":2,"generation":"11111111-1111-1111-1111-111111111111","revision":5,"base_revision":4,"cols":3,"rows":1,"rows_cells":[[{"text":"界","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":2},{"text":"","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":0},{"text":"x","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}]],"cursor_line":0,"cursor_col":2,"cursor_visible":true,"cursor_shape":"beam","alt_screen":true,"app_cursor":true,"bracketed_paste":true,"focus_reporting":true,"mouse_report":true,"mouse_drag":true,"mouse_motion":true,"mouse_sgr":true}}"#;

    #[test]
    fn decodes_grid_generation_from_full_daemon_snapshot() {
        let ev = ShellEvent::from_line(DAEMON_GRID_LINE).unwrap();
        match ev {
            ShellEvent::Grid { id, grid } => {
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
