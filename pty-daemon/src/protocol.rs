//! Wire protocol between the UI client and the daemon over a Unix domain
//! socket. Newline-delimited JSON: one `ClientRequest` or `DaemonEvent` per
//! line. The UI may attach/detach freely; the daemon and its PTYs live on.

use crate::grid::{Cell, CursorShape, GridSnapshot, MAX_SNAPSHOT_CELLS};
use crate::ids::SessionId;
use crate::revision::{Revision, SessionGeneration};
use serde::{Deserialize, Serialize};

// The request-side, runtime-independent wire types now live in the shared `maestro-protocol`
// crate and are re-exported here so the rest of the daemon keeps referring to them via
// `crate::protocol::{...}` unchanged. `MAX_LINE_BYTES` is the per-line framing cap (still enforced
// by the daemon's request reader, the renderer's event reader, and the app-shell client). The
// daemon still owns the event-side and grid-coupled types below (`DaemonEvent`, `DamageFrame`,
// etc.), which depend on `grid`/`revision` internals and therefore remain daemon-owned.
pub use maestro_protocol::{
    ChannelEvent, ChannelEventKind, ClientRequest, DAEMON_PROTOCOL_VERSION, MAX_LINE_BYTES,
};

/// Metadata for one live daemon session. Kept next to `ids` in the `Sessions` event so old clients can keep
/// reading just ids while richer clients show dashboard-quality labels.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SessionInfo {
    pub id: SessionId,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    /// Grid/process lifetime for this live session. Additive and optional so retained legacy
    /// clients keep decoding the event while newer clients can reconcile same-id restarts safely.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub generation: Option<String>,
}

/// Damage wire-schema version. Independent of `GridSnapshot::version`
/// (`SNAPSHOT_VERSION`): snapshots and damage evolve separately, and a consumer
/// that does not understand this schema treats a damage frame as malformed and
/// drops to resync rather than misapplying it.
///
/// This version is stamped on every generated damage frame.
pub const DAMAGE_SCHEMA: u32 = 1;

/// Hard cap on `DamageFrame::ops` length. A frame is attacker-shaped data; decoding
/// must not let a hostile/buggy sender force an unbounded allocation. A frame over
/// this is malformed -> resync. The daemon's generator also gives up on incremental
/// damage and ships a full snapshot if a diff would exceed it.
pub const MAX_DAMAGE_OPS: usize = 4096;

/// Practical cap on the total number of cells across all `RowSpan` ops in one frame.
/// A full-screen rewrite of any REALISTIC terminal (e.g. 1000x1000 = 1e6 cells) fits
/// comfortably; the theoretical grid max (2000x2000 = 4e6) is never legitimately sent
/// as a single damage frame (a resize that large is a full snapshot, not damage).
/// Anything above this is malformed -> resync. Decoupled from `MAX_DAMAGE_DIMENSION`
/// on purpose: dims bound the addressable grid; this bounds per-frame mutation volume.
pub const MAX_DAMAGE_CELLS: usize = 1_000_000;

/// Practical cap on the serialized byte length of a single damage frame's wire line.
/// This bounds deserialization allocation independently of cell/op counts (a single
/// `RowSpan` cell can carry a long `text` grapheme cluster). A frame's JSON over this
/// is rejected at the framing layer before a full parse is attempted. 8 MiB covers a
/// dense full-screen frame with rich styling and multi-codepoint cells with margin.
#[allow(dead_code)]
pub const MAX_DAMAGE_BYTES: usize = 8 * 1024 * 1024;

/// Largest grid dimension a damage frame may claim — mirrors `grid::MAX_DIMENSION`.
/// The daemon clamps real grids to this; a frame claiming more is malformed.
#[allow(dead_code)]
pub const MAX_DAMAGE_DIMENSION: u16 = 2000;

/// Hard cap on the number of historical rows returned by ONE `Scrollback` reply
/// (`DaemonEvent::ScrollbackRows`). For structured scrollback, the renderer asks for
/// the window it needs to paint (viewport height + a small prefetch margin), never the
/// whole 5000-line history, and the daemon clamps `count` to this. 256 rows is far more
/// than any realistic viewport and keeps each reply small.
///
/// This is the ROW cap. The reply must ALSO respect the per-line framing cap
/// (`MAX_LINE_BYTES`): rows × cols cells × worst-case cell bytes. Because a single grid
/// is never wider than `MAX_SNAPSHOT_CELLS` total cells anyway, the daemon additionally
/// clamps the returned cell volume to `MAX_SNAPSHOT_CELLS` (already proven
/// wire-shippable). The compile-time proof below pins both: 256 rows of cells, capped at
/// the snapshot cell budget, serialize within `MAX_LINE_BYTES`.
pub const MAX_SCROLLBACK_ROWS_PER_REQUEST: u16 = 256;

/// Conservative worst-case serialized byte cost of ONE scrollback `Cell`, identical to
/// the snapshot cell budget's per-cell figure (a maximal cell with 64-byte text, two
/// RGB colors, all attrs). Pessimistic on purpose — it only shrinks the guaranteed
/// reply. Kept in sync with `grid::WORST_CASE_CELL_BYTES` (private there; the proof
/// below would fail loudly if the snapshot budget shrank below what we assume).
#[allow(dead_code)]
const SCROLLBACK_WORST_CASE_CELL_BYTES: usize = 256;

/// Fixed per-line overhead for the `ScrollbackRows` envelope outside the cell array
/// (the `ev`/`id`/generation UUID/revision/history_len/offset_from_top/`rows` nesting).
/// 4 KiB is far more than the header ever needs.
#[allow(dead_code)]
const SCROLLBACK_HEADER_BYTES: usize = 4 * 1024;

// Compile-time proof: a `ScrollbackRows` reply is GUARANTEED to fit `MAX_LINE_BYTES`.
// The daemon clamps the returned cell volume to `MAX_SNAPSHOT_CELLS` (the same budget
// the live snapshot is held to, itself proven <= MAX_LINE_BYTES/2). So the worst-case
// reply is `MAX_SNAPSHOT_CELLS` cells plus the header, which we re-prove here against
// the full line cap with margin. If a future edit breaks this, the crate fails to
// compile rather than shipping an un-shippable reply size.
const _: () = {
    assert!(MAX_SCROLLBACK_ROWS_PER_REQUEST > 0);
    assert!(
        MAX_SNAPSHOT_CELLS * SCROLLBACK_WORST_CASE_CELL_BYTES + SCROLLBACK_HEADER_BYTES
            <= MAX_LINE_BYTES
    );
};

/// Why a damage frame failed structural validation. Carried for logging; the
/// renderer maps every variant to "drop to AwaitingResync and request exactly one
/// full snapshot" (the held grid is never mutated by an invalid frame).
#[derive(Debug, Clone, PartialEq, Eq)]
#[allow(dead_code)]
pub enum DamageInvalid {
    /// `schema` is not one we model.
    UnsupportedSchema { got: u32 },
    /// cols/rows are zero or exceed the maximum.
    BadDimensions { reason: &'static str },
    /// `ops.len()` exceeds `MAX_DAMAGE_OPS`.
    TooManyOps { got: usize },
    /// Total RowSpan cells exceed `MAX_DAMAGE_CELLS`.
    TooManyCells { got: usize },
    /// A RowSpan references a row >= rows, or its span runs past `cols`.
    RowSpanOutOfBounds { op: usize },
    /// A RowSpan carries zero cells — an empty span is a no-op and never a valid
    /// damage payload; the sender must omit it rather than ship an empty op.
    EmptyRowSpan { op: usize },
    /// A scroll region violates `top < bottom_exclusive <= rows`, `lines > 0`, or
    /// `lines <= region height`.
    BadScrollRegion { op: usize },
    /// `base_revision >= revision` — a damage frame must STRICTLY advance the
    /// revision (it represents at least one committed mutation). Equal or backwards
    /// is structurally impossible; treat as corrupt.
    BadRevisionOrder { base: u64, rev: u64 },
    /// The post-frame cursor position lies outside the frame's `cols`/`rows`.
    CursorOutOfBounds { line: usize, col: usize },
    /// A cell violates the width/text invariant: `width` must be 0 (wide spacer,
    /// empty text), 1 (normal), or 2 (wide lead); a width-0 cell must have empty
    /// text. `op` is the op index; for `ClearAll` it is the op carrying the cell.
    BadCell { op: usize },
}

/// Cursor state carried on a damage frame header. Absolute post-frame state (not a
/// delta), so applying a frame is idempotent w.r.t. the cursor. Mirrors the cursor
/// fields of `GridSnapshot`.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CursorState {
    pub line: usize,
    pub col: usize,
    pub visible: bool,
    pub shape: CursorShape,
}

/// Terminal mode flags carried on a damage frame header. Absolute post-frame state.
/// Mirrors the mode fields of `GridSnapshot` (SnapshotV2).
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ModeState {
    pub alt_screen: bool,
    pub app_cursor: bool,
    pub bracketed_paste: bool,
    pub focus_reporting: bool,
    /// Mouse click reporting (DECSET 1000). `#[serde(default)]` so a frame from an older
    /// daemon (no field) decodes as `false`, keeping the mirrored renderer protocol
    /// backward-compatible.
    #[serde(default)]
    pub mouse_report: bool,
    /// Mouse button-drag reporting (DECSET 1002).
    #[serde(default)]
    pub mouse_drag: bool,
    /// Mouse any-motion reporting (DECSET 1003).
    #[serde(default)]
    pub mouse_motion: bool,
    /// SGR extended mouse encoding (DECSET 1006).
    #[serde(default)]
    pub mouse_sgr: bool,
}

/// One structured change within a damage frame. NEVER carries raw PTY bytes — every
/// op is derived from the daemon's authoritative grid. Applied in order.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DamageOp {
    /// Replace `cells` into row `row` starting at column `start`:
    /// columns `[start, start + cells.len())` now hold these cells.
    RowSpan {
        row: u16,
        start: u16,
        cells: Vec<Cell>,
    },
    /// Clear the whole grid to `cell`. The blank cell is explicit because terminal
    /// erasure fills with the ACTIVE background color/attributes, not a fixed default.
    ClearAll { cell: Cell },
    /// Scroll the half-open region `[top, bottom_exclusive)` up by `lines` rows.
    /// OPTIONAL optimization (not emitted until equivalence-proven). Requires
    /// `top < bottom_exclusive`, `lines > 0`, `lines <= bottom_exclusive - top`.
    ScrollUp {
        top: u16,
        bottom_exclusive: u16,
        lines: u16,
    },
    /// Scroll the half-open region `[top, bottom_exclusive)` down by `lines` rows.
    /// Same constraints as `ScrollUp`.
    ScrollDown {
        top: u16,
        bottom_exclusive: u16,
        lines: u16,
    },
}

/// One atomic damage frame: the structured change from `base_revision` to
/// `revision` for one session's grid. The renderer applies ALL ops or NONE; it
/// applies the frame only when `generation` matches its baseline and
/// `base_revision` equals the revision it currently holds. Dimensions are carried
/// for validation and MUST equal the held grid's dims — a damage frame never
/// resizes (resize is a full snapshot).
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct DamageFrame {
    /// Damage wire-schema version (`DAMAGE_SCHEMA`).
    pub schema: u32,
    pub id: SessionId,
    pub generation: SessionGeneration,
    /// The revision this frame continues FROM (must equal the renderer's held rev).
    pub base_revision: Revision,
    /// The revision the grid is at AFTER applying this frame.
    pub revision: Revision,
    /// Grid width after this frame (== before; damage never resizes).
    pub cols: u16,
    /// Grid height after this frame.
    pub rows: u16,
    /// Absolute cursor state after the frame.
    pub cursor: CursorState,
    /// Absolute mode flags after the frame.
    pub modes: ModeState,
    /// Ordered structured changes.
    pub ops: Vec<DamageOp>,
}

impl DamageFrame {
    /// Pure structural validation: schema, dimensions, allocation limits, op
    /// bounds, scroll-region half-open constraints, and revision ordering. Does NOT
    /// touch any grid — it is the gate the renderer runs against a candidate frame
    /// before mutating a scratch grid. Returns the first violation found.
    ///
    /// NOTE: this validates SHAPE only. Continuity (does `base_revision` match what
    /// the renderer holds?) and generation matching are the renderer's state-machine
    /// concern, not pure frame validity.
    #[allow(dead_code)]
    pub fn validate(&self) -> Result<(), DamageInvalid> {
        if self.schema != DAMAGE_SCHEMA {
            return Err(DamageInvalid::UnsupportedSchema { got: self.schema });
        }
        if self.cols == 0 || self.rows == 0 {
            return Err(DamageInvalid::BadDimensions {
                reason: "zero cols or rows",
            });
        }
        if self.cols > MAX_DAMAGE_DIMENSION || self.rows > MAX_DAMAGE_DIMENSION {
            return Err(DamageInvalid::BadDimensions {
                reason: "cols or rows exceed maximum",
            });
        }
        // Strictly advancing: a damage frame is at least one committed mutation, so
        // `revision` must be > `base_revision`. Equal (no-op) or backwards is corrupt.
        if self.base_revision.0 >= self.revision.0 {
            return Err(DamageInvalid::BadRevisionOrder {
                base: self.base_revision.0,
                rev: self.revision.0,
            });
        }
        // Post-frame cursor must land on the addressable grid (col/line are 0-based).
        if self.cursor.col >= self.cols as usize || self.cursor.line >= self.rows as usize {
            return Err(DamageInvalid::CursorOutOfBounds {
                line: self.cursor.line,
                col: self.cursor.col,
            });
        }
        if self.ops.len() > MAX_DAMAGE_OPS {
            return Err(DamageInvalid::TooManyOps {
                got: self.ops.len(),
            });
        }

        let mut total_cells = 0usize;
        for (i, op) in self.ops.iter().enumerate() {
            match op {
                DamageOp::RowSpan { row, start, cells } => {
                    if cells.is_empty() {
                        return Err(DamageInvalid::EmptyRowSpan { op: i });
                    }
                    if (*row as usize) >= self.rows as usize {
                        return Err(DamageInvalid::RowSpanOutOfBounds { op: i });
                    }
                    let end = (*start as usize)
                        .checked_add(cells.len())
                        .ok_or(DamageInvalid::RowSpanOutOfBounds { op: i })?;
                    if end > self.cols as usize {
                        return Err(DamageInvalid::RowSpanOutOfBounds { op: i });
                    }
                    for c in cells {
                        if !cell_is_valid(c) {
                            return Err(DamageInvalid::BadCell { op: i });
                        }
                    }
                    total_cells = total_cells
                        .checked_add(cells.len())
                        .ok_or(DamageInvalid::TooManyCells { got: usize::MAX })?;
                    if total_cells > MAX_DAMAGE_CELLS {
                        return Err(DamageInvalid::TooManyCells { got: total_cells });
                    }
                }
                DamageOp::ClearAll { cell } => {
                    // The fill must be the CANONICAL blank cell: width 1 and text " "
                    // (the daemon's snapshot path normalizes an empty grid cell's glyph
                    // to a single space, never the empty string). Requiring exactly that
                    // representation prevents two encodings of "blank" from coexisting:
                    // a width-0 spacer fill, a wide lead (2), or empty/multi-char text
                    // would desync the renderer's wide-pair layout. Styling (fg/bg/attrs)
                    // is free — terminal erase fills with the ACTIVE background.
                    if !cell_is_valid(cell) || cell.width != 1 || cell.text != " " {
                        return Err(DamageInvalid::BadCell { op: i });
                    }
                }
                DamageOp::ScrollUp {
                    top,
                    bottom_exclusive,
                    lines,
                }
                | DamageOp::ScrollDown {
                    top,
                    bottom_exclusive,
                    lines,
                } => {
                    if !(top < bottom_exclusive
                        && (*bottom_exclusive as usize) <= self.rows as usize
                        && *lines > 0
                        && *lines <= bottom_exclusive - top)
                    {
                        return Err(DamageInvalid::BadScrollRegion { op: i });
                    }
                }
            }
        }
        Ok(())
    }
}

/// A cell is valid iff `width` is 0/1/2 and a wide spacer (`width == 0`) carries
/// empty text. Mirrors the grid's wire contract for `Cell`. Pure; shared by frame
/// validation on both the daemon and the renderer mirror.
#[allow(dead_code)]
fn cell_is_valid(cell: &Cell) -> bool {
    match cell.width {
        0 => cell.text.is_empty(),
        1 | 2 => true,
        _ => false,
    }
}

/// Events the daemon sends to attached UI clients.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum DaemonEvent {
    /// Reply to the non-mutating daemon identity handshake.
    DaemonInfo {
        protocol_version: u32,
        build_version: String,
        /// This daemon echoes an Attach request's optional `output_generation` on exactly that
        /// Attach's restore Grid and tags its live forwarder events, giving proxies exact ownership
        /// even if an aborted old forwarder races past a newer baseline.
        #[serde(default)]
        output_generation_echo: bool,
    },
    TerminalBell {
        id: SessionId,
    },
    TerminalTitle {
        id: SessionId,
        title: Option<String>,
    },
    /// OSC 52 store request. Capped by the daemon before crossing the wire; the
    /// renderer applies its own local clipboard policy.
    TerminalClipboardStore {
        id: SessionId,
        text: String,
    },
    /// Live PTY output for a session. `data` is **base64-encoded raw bytes**,
    /// not text: a multibyte UTF-8 character or ANSI escape can be split across
    /// PTY reads, so lossy String conversion here would corrupt the stream.
    /// The client decodes base64 and feeds the raw bytes to its VT parser.
    ///
    /// `generation` + `revision` place this chunk on the grid timeline. After
    /// applying a Grid snapshot, a client MUST drop any Output whose
    /// `revision <= snapshot.revision` (already folded in) and, if it ever sees a
    /// different `generation`, discard its screen and request a fresh Snapshot.
    Output {
        id: SessionId,
        generation: SessionGeneration,
        revision: Revision,
        data: String,
    },
    /// Authoritative rendered grid for a session. Sent as the restore payload
    /// on Attach (a clean screen, not replayed raw bytes) and in reply to
    /// Snapshot.
    Grid {
        id: SessionId,
        /// Present only on the authoritative restore Grid emitted by an Attach carrying an output
        /// generation. Resync and Snapshot grids omit it, so the echo is an unambiguous boundary.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_generation: Option<u64>,
        grid: GridSnapshot,
    },
    /// A window of STRUCTURED historical rows, emitted in reply to a
    /// `Scrollback` request. NOT a `Grid` and NOT folded into `SyncState` (the
    /// snapshot/damage state machine): it is a read-only view of rows that scrolled above
    /// the live screen, carrying structured `Cell`s (never raw bytes). The renderer paints
    /// these as renderer-owned view state while scrolled up; it does NOT fold them into the
    /// held live grid, and the live grid keeps advancing underneath independently.
    ScrollbackRows {
        id: SessionId,
        /// The grid lifetime these rows belong to. A renderer holding a different
        /// generation must discard and re-baseline (same rule as `Grid`/`Output`).
        generation: SessionGeneration,
        /// The revision the history buffer was at when these rows were read. Lets the
        /// renderer notice live output advanced history since the query (absolute
        /// offsets may have shifted) and re-query if it cares.
        revision: Revision,
        /// Total history rows available right now. The renderer clamps its own max
        /// scrollback and sizes a scrollbar from this.
        history_len: u32,
        /// The `offset_from_top` this window actually starts at (echoed; may be clamped
        /// down from the request if it exceeded `history_len`).
        offset_from_top: u32,
        /// Rows top-to-bottom, each exactly `cols` cells wide. SAME `Cell` model as
        /// `GridSnapshot::rows_cells` — never raw bytes.
        rows: Vec<Vec<Cell>>,
    },
    /// Structured incremental damage for a session's grid. Carries the
    /// `base_revision -> revision` change as structured ops (never raw bytes). The forwarder emits this LIVE after each
    /// PTY-advanced grid. The raw `Output` bridge is now opt-in (gated on the
    /// attacher's `want_raw_output`); a structured-only client lives off Damage alone.
    /// A geometry/generation change ships a full `Grid` (ResyncRequired + Grid), never a
    /// partial-resize frame.
    Damage {
        frame: DamageFrame,
    },
    /// A session ended (process exit).
    SessionExited {
        id: SessionId,
        code: Option<i32>,
    },
    /// This client's live stream lagged and dropped bytes, so its VT parser is
    /// now inconsistent. The client should request a fresh Snapshot and rebuild
    /// from the authoritative grid rather than trust its current screen.
    ResyncRequired {
        id: SessionId,
    },
    /// Snapshot reply to ListSessions.
    Sessions {
        ids: Vec<SessionId>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        sessions: Vec<SessionInfo>,
    },
    /// An event traversed a channel — fan-out to subscribed UI clients.
    Channel {
        event: ChannelEvent,
    },
    /// Generic error reply tied to no specific stream.
    Error {
        message: String,
    },
}

pub fn now_millis() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod damage_tests {
    use super::*;
    use crate::grid::{Color, NamedColor};

    #[test]
    fn daemon_info_event_has_stable_shape() {
        let event = DaemonEvent::DaemonInfo {
            protocol_version: DAEMON_PROTOCOL_VERSION,
            build_version: "0.1.0".into(),
            output_generation_echo: true,
        };
        assert_eq!(
            serde_json::to_string(&event).unwrap(),
            r#"{"ev":"daemon_info","protocol_version":2,"build_version":"0.1.0","output_generation_echo":true}"#
        );
    }

    fn cell(text: &str) -> Cell {
        Cell {
            text: text.into(),
            fg: Color::Named {
                name: NamedColor::Foreground,
            },
            bg: Color::Named {
                name: NamedColor::Background,
            },
            bold: false,
            italic: false,
            underline: Default::default(),
            inverse: false,
            strikeout: false,
            dim: false,
            hidden: false,
            width: 1,
        }
    }

    fn cursor() -> CursorState {
        CursorState {
            line: 0,
            col: 0,
            visible: true,
            shape: CursorShape::Block,
        }
    }

    fn modes() -> ModeState {
        ModeState {
            alt_screen: false,
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_report: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_sgr: false,
        }
    }

    fn frame(ops: Vec<DamageOp>) -> DamageFrame {
        DamageFrame {
            schema: DAMAGE_SCHEMA,
            id: SessionId("s1".into()),
            generation: SessionGeneration::new(),
            base_revision: Revision(4),
            revision: Revision(5),
            cols: 10,
            rows: 4,
            cursor: cursor(),
            modes: modes(),
            ops,
        }
    }

    #[test]
    fn damage_frame_round_trips_through_json() {
        let f = frame(vec![
            DamageOp::RowSpan {
                row: 1,
                start: 2,
                cells: vec![cell("a"), cell("b")],
            },
            DamageOp::ClearAll { cell: cell(" ") },
            DamageOp::ScrollUp {
                top: 0,
                bottom_exclusive: 4,
                lines: 1,
            },
            DamageOp::ScrollDown {
                top: 1,
                bottom_exclusive: 3,
                lines: 2,
            },
        ]);
        let json = serde_json::to_string(&f).unwrap();
        let back: DamageFrame = serde_json::from_str(&json).unwrap();
        assert_eq!(f, back);
    }

    /// Each mouse-mode bit must survive serialization through a `DamageFrame` and decode
    /// back unchanged. Tested ONE field at a time (the others held `false`) so a swapped,
    /// dropped, or aliased field is caught per-field rather than masked by an all-true
    /// frame — then a full all-true frame confirms they coexist. Mirrors the renderer's
    /// `mouse_modes_round_trip_through_damage_json` so the two serde shapes stay in lockstep.
    #[test]
    fn mouse_modes_round_trip_through_damage_json() {
        // (label, modes-with-exactly-this-bit-set, the JSON key that must read `true`).
        let only = |set: fn(&mut ModeState)| {
            let mut m = modes();
            set(&mut m);
            m
        };
        let cases: [(&str, ModeState); 4] = [
            ("mouse_report", only(|m| m.mouse_report = true)),
            ("mouse_drag", only(|m| m.mouse_drag = true)),
            ("mouse_motion", only(|m| m.mouse_motion = true)),
            ("mouse_sgr", only(|m| m.mouse_sgr = true)),
        ];
        for (key, m) in cases {
            let mut f = frame(vec![]);
            f.modes = m;
            let json = serde_json::to_string(&f).unwrap();
            assert!(
                json.contains(&format!("\"{key}\":true")),
                "the set bit serializes as {key}:true: {json}"
            );
            let back: DamageFrame = serde_json::from_str(&json).unwrap();
            assert_eq!(
                back.modes, m,
                "exactly the {key} bit survives the round-trip"
            );
        }

        // All four set together also round-trip (they coexist, no field clobbers another).
        let all = ModeState {
            mouse_report: true,
            mouse_drag: true,
            mouse_motion: true,
            mouse_sgr: true,
            ..modes()
        };
        let mut f = frame(vec![]);
        f.modes = all;
        let back: DamageFrame = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(back.modes, all);
    }

    #[test]
    fn damage_event_round_trips_with_ev_tag() {
        let ev = DaemonEvent::Damage {
            frame: frame(vec![]),
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(json.contains("\"ev\":\"damage\""), "tag present: {json}");
        let back: DaemonEvent = serde_json::from_str(&json).unwrap();
        match back {
            DaemonEvent::Damage { frame } => assert_eq!(frame.schema, DAMAGE_SCHEMA),
            other => panic!("expected Damage, got {other:?}"),
        }
    }

    #[test]
    fn op_tag_is_snake_case() {
        let json = serde_json::to_string(&DamageOp::RowSpan {
            row: 0,
            start: 0,
            cells: vec![],
        })
        .unwrap();
        assert!(json.contains("\"op\":\"row_span\""), "{json}");
        let json = serde_json::to_string(&DamageOp::ScrollDown {
            top: 0,
            bottom_exclusive: 1,
            lines: 1,
        })
        .unwrap();
        assert!(json.contains("\"op\":\"scroll_down\""), "{json}");
    }

    #[test]
    fn attach_want_raw_output_defaults_true() {
        // An old-style attach with no flag decodes with want_raw_output == true, so a
        // compatibility client keeps getting raw output.
        let req: ClientRequest = serde_json::from_str(r#"{"op":"attach","id":"s1"}"#).unwrap();
        match req {
            ClientRequest::Attach {
                want_raw_output, ..
            } => assert!(want_raw_output, "absent flag defaults to true"),
            other => panic!("expected Attach, got {other:?}"),
        }
        // An explicit false round-trips (a grid-aware renderer opting out).
        let req: ClientRequest =
            serde_json::from_str(r#"{"op":"attach","id":"s1","want_raw_output":false}"#).unwrap();
        match req {
            ClientRequest::Attach {
                want_raw_output, ..
            } => assert!(!want_raw_output),
            other => panic!("expected Attach, got {other:?}"),
        }
        // And an explicit true round-trips.
        let req: ClientRequest =
            serde_json::from_str(r#"{"op":"attach","id":"s1","want_raw_output":true}"#).unwrap();
        match req {
            ClientRequest::Attach {
                want_raw_output, ..
            } => assert!(want_raw_output),
            other => panic!("expected Attach, got {other:?}"),
        }
    }

    #[test]
    fn validate_accepts_well_formed_frame() {
        let f = frame(vec![DamageOp::RowSpan {
            row: 3,
            start: 0,
            cells: vec![cell("x"); 10],
        }]);
        assert_eq!(f.validate(), Ok(()));
    }

    #[test]
    fn validate_rejects_bad_schema() {
        let mut f = frame(vec![]);
        f.schema = 99;
        assert_eq!(
            f.validate(),
            Err(DamageInvalid::UnsupportedSchema { got: 99 })
        );
    }

    #[test]
    fn validate_rejects_zero_and_oversized_dims() {
        let mut f = frame(vec![]);
        f.rows = 0;
        assert!(matches!(
            f.validate(),
            Err(DamageInvalid::BadDimensions { .. })
        ));
        let mut f = frame(vec![]);
        f.cols = 2001;
        assert!(matches!(
            f.validate(),
            Err(DamageInvalid::BadDimensions { .. })
        ));
    }

    #[test]
    fn validate_rejects_rowspan_out_of_bounds() {
        // row past rows
        let f = frame(vec![DamageOp::RowSpan {
            row: 4,
            start: 0,
            cells: vec![cell("x")],
        }]);
        assert_eq!(
            f.validate(),
            Err(DamageInvalid::RowSpanOutOfBounds { op: 0 })
        );
        // span past cols
        let f = frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 8,
            cells: vec![cell("x"); 5],
        }]);
        assert_eq!(
            f.validate(),
            Err(DamageInvalid::RowSpanOutOfBounds { op: 0 })
        );
    }

    #[test]
    fn validate_rejects_too_many_ops() {
        let f = frame(vec![
            DamageOp::ClearAll { cell: cell(" ") };
            MAX_DAMAGE_OPS + 1
        ]);
        assert_eq!(
            f.validate(),
            Err(DamageInvalid::TooManyOps {
                got: MAX_DAMAGE_OPS + 1
            })
        );
    }

    #[test]
    fn validate_rejects_scroll_region_violations() {
        // top == bottom_exclusive (empty/inverted region)
        let f = frame(vec![DamageOp::ScrollUp {
            top: 2,
            bottom_exclusive: 2,
            lines: 1,
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadScrollRegion { op: 0 }));
        // lines == 0
        let f = frame(vec![DamageOp::ScrollDown {
            top: 0,
            bottom_exclusive: 4,
            lines: 0,
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadScrollRegion { op: 0 }));
        // lines > region height (4 > 4-0? no; use 5 > 4)
        let f = frame(vec![DamageOp::ScrollUp {
            top: 0,
            bottom_exclusive: 4,
            lines: 5,
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadScrollRegion { op: 0 }));
        // bottom_exclusive past rows
        let f = frame(vec![DamageOp::ScrollUp {
            top: 0,
            bottom_exclusive: 5,
            lines: 1,
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadScrollRegion { op: 0 }));
    }

    #[test]
    fn validate_rejects_backwards_revision() {
        let mut f = frame(vec![]);
        f.base_revision = Revision(9);
        f.revision = Revision(5);
        assert_eq!(
            f.validate(),
            Err(DamageInvalid::BadRevisionOrder { base: 9, rev: 5 })
        );
    }

    #[test]
    fn validate_rejects_non_advancing_revision() {
        // base == revision is a no-op frame: strictly advancing means it's rejected.
        let mut f = frame(vec![]);
        f.base_revision = Revision(5);
        f.revision = Revision(5);
        assert_eq!(
            f.validate(),
            Err(DamageInvalid::BadRevisionOrder { base: 5, rev: 5 })
        );
    }

    #[test]
    fn validate_rejects_empty_rowspan() {
        let f = frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 0,
            cells: vec![],
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::EmptyRowSpan { op: 0 }));
    }

    #[test]
    fn validate_rejects_cursor_out_of_bounds() {
        // frame() is 10 cols x 4 rows.
        let mut f = frame(vec![]);
        f.cursor.col = 10; // == cols, out of [0, cols)
        assert!(matches!(
            f.validate(),
            Err(DamageInvalid::CursorOutOfBounds { .. })
        ));
        let mut f = frame(vec![]);
        f.cursor.line = 4; // == rows
        assert!(matches!(
            f.validate(),
            Err(DamageInvalid::CursorOutOfBounds { .. })
        ));
    }

    #[test]
    fn validate_rejects_bad_cell_width() {
        // width 3 is not a valid cell width.
        let mut bad = cell("x");
        bad.width = 3;
        let f = frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 0,
            cells: vec![bad],
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadCell { op: 0 }));
        // width-0 spacer must carry empty text.
        let mut spacer = cell("x");
        spacer.width = 0;
        let f = frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 0,
            cells: vec![spacer],
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadCell { op: 0 }));
    }

    #[test]
    fn validate_rejects_clear_all_with_non_single_width_fill() {
        // ClearAll fill must be width 1; a wide-lead (2) fill is rejected.
        let mut wide = cell("W");
        wide.width = 2;
        let f = frame(vec![DamageOp::ClearAll { cell: wide }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadCell { op: 0 }));
    }

    #[test]
    fn validate_rejects_clear_all_with_non_canonical_blank_text() {
        // ClearAll fill must be the canonical blank: width 1 AND text " ". A width-1
        // cell carrying a glyph (not a space) is NOT a blank fill.
        let f = frame(vec![DamageOp::ClearAll { cell: cell("x") }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadCell { op: 0 }));
        // Empty text is also not the canonical blank (that's a width-0 spacer shape).
        let f = frame(vec![DamageOp::ClearAll { cell: cell("") }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadCell { op: 0 }));
        // The canonical blank (width 1, " ") is accepted.
        let f = frame(vec![DamageOp::ClearAll { cell: cell(" ") }]);
        assert_eq!(f.validate(), Ok(()));
    }

    #[test]
    fn cell_text_over_cap_is_rejected_during_deserialization() {
        use crate::grid::MAX_CELL_TEXT_BYTES;
        // Build a RowSpan cell whose `text` is one byte over the cap, then check that
        // the FRAME fails to deserialize (the custom visitor errors mid-parse, before
        // the whole frame is constructed).
        let long = "a".repeat(MAX_CELL_TEXT_BYTES + 1);
        let mut c = cell("a");
        c.text = long.into();
        let f = frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 0,
            cells: vec![c],
        }]);
        let json = serde_json::to_string(&f).unwrap();
        let err = serde_json::from_str::<DamageFrame>(&json).unwrap_err();
        assert!(
            err.to_string().contains("exceeds"),
            "expected cell-text cap error, got: {err}"
        );
        // Exactly at the cap deserializes fine.
        let mut c = cell("a");
        c.text = "a".repeat(MAX_CELL_TEXT_BYTES).into();
        let f = frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 0,
            cells: vec![c],
        }]);
        let json = serde_json::to_string(&f).unwrap();
        assert!(serde_json::from_str::<DamageFrame>(&json).is_ok());
    }

    /// The exact wire bytes the daemon emits for a representative damage event. This
    /// SAME literal is decoded by a renderer-side test (`wire.rs`:
    /// `cross_wire_damage_decodes_in_renderer_mirror`). Together the two prove
    /// daemon-serialized JSON deserializes identically in the renderer mirror.
    /// If the daemon's serde shape drifts, `cross_wire_daemon_emits_canonical_json`
    /// fails here and the renderer fixture must be updated in lockstep.
    pub(crate) const CROSS_WIRE_DAMAGE_JSON: &str = r#"{"ev":"damage","frame":{"schema":1,"id":"s1","generation":"11111111-1111-1111-1111-111111111111","base_revision":4,"revision":5,"cols":10,"rows":4,"cursor":{"line":1,"col":2,"visible":true,"shape":"block"},"modes":{"alt_screen":false,"app_cursor":true,"bracketed_paste":false,"focus_reporting":true,"mouse_report":false,"mouse_drag":false,"mouse_motion":false,"mouse_sgr":false},"ops":[{"op":"row_span","row":1,"start":2,"cells":[{"text":"a","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}]},{"op":"clear_all","cell":{"text":" ","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}}]}}"#;

    #[test]
    fn cross_wire_daemon_emits_canonical_json() {
        // Decode the canonical literal into the daemon's own types, re-serialize, and
        // assert it reproduces the literal byte-for-byte. This pins the daemon's wire
        // shape to the exact bytes the renderer test consumes.
        let ev: DaemonEvent = serde_json::from_str(CROSS_WIRE_DAMAGE_JSON).unwrap();
        let reser = serde_json::to_string(&ev).unwrap();
        assert_eq!(reser, CROSS_WIRE_DAMAGE_JSON);
        // And the decoded frame is structurally valid.
        match ev {
            DaemonEvent::Damage { frame } => assert_eq!(frame.validate(), Ok(())),
            other => panic!("expected Damage, got {other:?}"),
        }
    }

    // --- Scrollback protocol types -----------------------------------------

    #[test]
    fn scrollback_request_round_trips_through_json() {
        let req = ClientRequest::Scrollback {
            id: SessionId("s1".into()),
            offset_from_top: 42,
            count: 24,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(
            json.contains("\"op\":\"scrollback\""),
            "tag present: {json}"
        );
        let back: ClientRequest = serde_json::from_str(&json).unwrap();
        match back {
            ClientRequest::Scrollback {
                id,
                offset_from_top,
                count,
            } => {
                assert_eq!(id, SessionId("s1".into()));
                assert_eq!(offset_from_top, 42);
                assert_eq!(count, 24);
            }
            other => panic!("expected Scrollback, got {other:?}"),
        }
    }

    #[test]
    fn scrollback_rows_event_round_trips_with_ev_tag() {
        let ev = DaemonEvent::ScrollbackRows {
            id: SessionId("s1".into()),
            generation: SessionGeneration::new(),
            revision: Revision(99),
            history_len: 5000,
            offset_from_top: 10,
            rows: vec![vec![cell("a"), cell("b")], vec![cell("c"), cell("d")]],
        };
        let json = serde_json::to_string(&ev).unwrap();
        assert!(
            json.contains("\"ev\":\"scrollback_rows\""),
            "tag present: {json}"
        );
        let back: DaemonEvent = serde_json::from_str(&json).unwrap();
        match back {
            DaemonEvent::ScrollbackRows {
                id,
                revision,
                history_len,
                offset_from_top,
                rows,
                ..
            } => {
                assert_eq!(id, SessionId("s1".into()));
                assert_eq!(revision, Revision(99));
                assert_eq!(history_len, 5000);
                assert_eq!(offset_from_top, 10);
                assert_eq!(rows.len(), 2);
                assert_eq!(rows[0], vec![cell("a"), cell("b")]);
            }
            other => panic!("expected ScrollbackRows, got {other:?}"),
        }
    }

    /// `ScrollbackRows::rows` uses the EXACT same `Cell` shape as `GridSnapshot::rows_cells`:
    /// a cell serialized for a grid row deserializes byte-identically inside a scrollback
    /// reply. This pins the "same Cell model as the live grid" constraint at the type level.
    #[test]
    fn scrollback_rows_use_same_cell_shape_as_grid() {
        let c = cell("x");
        let grid_cell_json = serde_json::to_string(&c).unwrap();
        let ev = DaemonEvent::ScrollbackRows {
            id: SessionId("s1".into()),
            generation: SessionGeneration::new(),
            revision: Revision(1),
            history_len: 1,
            offset_from_top: 0,
            rows: vec![vec![c.clone()]],
        };
        let line = serde_json::to_string(&ev).unwrap();
        // The grid-cell JSON appears verbatim inside the scrollback reply (no alternate
        // encoding) — proving the row cells are the same wire type as a grid cell.
        assert!(
            line.contains(&grid_cell_json),
            "scrollback cell must serialize identically to a grid cell:\n cell={grid_cell_json}\n line={line}"
        );
        let back: DaemonEvent = serde_json::from_str(&line).unwrap();
        match back {
            DaemonEvent::ScrollbackRows { rows, .. } => assert_eq!(rows[0][0], c),
            other => panic!("expected ScrollbackRows, got {other:?}"),
        }
    }

    /// The cap constants are sized so even a MAXIMAL reply — the largest cell volume the
    /// daemon will ever ship (`MAX_SNAPSHOT_CELLS` worst-case cells) — stays within
    /// `MAX_LINE_BYTES`. The `const _` block in this module is the compile-time proof;
    /// this test pins the same arithmetic at runtime and documents the conservative
    /// per-cell sizing it relies on.
    #[test]
    #[allow(clippy::assertions_on_constants)]
    fn scrollback_reply_max_size_within_line_cap() {
        // Worst case: the full snapshot cell budget, each cell at the conservative
        // worst-case byte cost, plus the fixed header reserve. These are const inputs
        // (the same ones the `const _` proof in this module checks at compile time); we
        // assert them here too so the budget intent is visible at the test layer.
        let worst_case =
            MAX_SNAPSHOT_CELLS * SCROLLBACK_WORST_CASE_CELL_BYTES + SCROLLBACK_HEADER_BYTES;
        assert!(
            worst_case <= MAX_LINE_BYTES,
            "worst-case scrollback reply {worst_case} exceeds line cap {MAX_LINE_BYTES}"
        );
        // And the row cap is positive (a reply can carry at least one row).
        assert!(MAX_SCROLLBACK_ROWS_PER_REQUEST > 0);
    }

    /// The exact wire bytes the daemon emits for a representative `ScrollbackRows` event.
    /// This SAME literal is decoded by a renderer-side test
    /// (`wire.rs`: `cross_wire_scrollback_decodes_in_renderer_mirror`). Together they
    /// prove daemon-serialized JSON deserializes identically in the renderer mirror; if
    /// the daemon's serde shape drifts, `cross_wire_daemon_emits_canonical_scrollback`
    /// fails here and the renderer fixture must be updated in lockstep.
    pub(crate) const CROSS_WIRE_SCROLLBACK_JSON: &str = r#"{"ev":"scrollback_rows","id":"s1","generation":"11111111-1111-1111-1111-111111111111","revision":7,"history_len":5000,"offset_from_top":3,"rows":[[{"text":"a","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}]]}"#;

    /// The exact wire bytes the daemon emits for a representative `Grid` event — the
    /// attach/resync baseline payload and the largest, most field-heavy event on the wire.
    /// This SAME literal is decoded by a renderer-side test (`wire.rs`:
    /// `cross_wire_grid_decodes_in_renderer_mirror`). Together they prove daemon-serialized
    /// `GridSnapshot` JSON deserializes byte-identically in the renderer mirror; a silent
    /// drift in either `GridSnapshot` shape (renamed/added/reordered field) would make the
    /// renderer reject every Grid and the product would be dead-on-attach, with no other
    /// test catching it. If the daemon's serde shape drifts,
    /// `cross_wire_daemon_emits_canonical_grid` fails here and the renderer fixture must be
    /// updated in lockstep. The snapshot is deliberately small but covers a wide pair
    /// (width-2 lead + width-0 spacer) so the cell `width` field is exercised at both ends.
    /// It also sets the non-default cursor shape (`beam`) and ALL mode/mouse flags `true`,
    /// so a future rename/drop/reorder of any cursor, mode, or mouse field — e.g. the
    /// `mouse_report`/`mouse_drag`/`mouse_motion`/`mouse_sgr` set — fails one of the paired
    /// tests instead of silently decoding to a wrong (defaulted-`false`) value.
    pub(crate) const CROSS_WIRE_GRID_JSON: &str = r#"{"ev":"grid","id":"s1","grid":{"version":2,"generation":"11111111-1111-1111-1111-111111111111","revision":5,"base_revision":4,"cols":3,"rows":1,"rows_cells":[[{"text":"界","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":2},{"text":"","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":0},{"text":"x","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}]],"cursor_line":0,"cursor_col":2,"cursor_visible":true,"cursor_shape":"beam","alt_screen":true,"app_cursor":true,"bracketed_paste":true,"focus_reporting":true,"mouse_report":true,"mouse_drag":true,"mouse_motion":true,"mouse_sgr":true}}"#;

    #[test]
    fn cross_wire_daemon_emits_canonical_grid() {
        // Decode the canonical literal into the daemon's own types, re-serialize, and assert
        // it reproduces the literal byte-for-byte. Pins the daemon's GridSnapshot wire shape
        // to the exact bytes the renderer mirror test consumes.
        let ev: DaemonEvent = serde_json::from_str(CROSS_WIRE_GRID_JSON).unwrap();
        let reser = serde_json::to_string(&ev).unwrap();
        assert_eq!(reser, CROSS_WIRE_GRID_JSON);
        match ev {
            DaemonEvent::Grid { id, grid, .. } => {
                // Every GridSnapshot wire field survives the daemon's own round-trip.
                assert_eq!(id, SessionId("s1".into()));
                assert_eq!(grid.version, crate::grid::SNAPSHOT_VERSION);
                assert_eq!(grid.revision, Revision(5));
                assert_eq!(grid.base_revision, Revision(4));
                assert_eq!(grid.cols, 3);
                assert_eq!(grid.rows, 1);
                assert_eq!(grid.rows_cells.len(), 1);
                assert_eq!(grid.rows_cells[0].len(), 3);
                // Wide pair preserved across the wire: width-2 lead, width-0 spacer.
                assert_eq!(grid.rows_cells[0][0].width, 2);
                assert_eq!(grid.rows_cells[0][1].width, 0);
                assert_eq!(grid.cursor_line, 0);
                assert_eq!(grid.cursor_col, 2);
                assert!(grid.cursor_visible);
                // Non-default cursor shape must survive (guards CursorShape drift).
                assert_eq!(grid.cursor_shape, CursorShape::Beam);
                // All mode + mouse flags are `true`, so a dropped/renamed field that
                // defaulted to `false` would fail here.
                assert!(grid.alt_screen);
                assert!(grid.app_cursor);
                assert!(grid.bracketed_paste);
                assert!(grid.focus_reporting);
                assert!(grid.mouse_report);
                assert!(grid.mouse_drag);
                assert!(grid.mouse_motion);
                assert!(grid.mouse_sgr);
            }
            other => panic!("expected Grid, got {other:?}"),
        }
    }

    #[test]
    fn cross_wire_daemon_emits_canonical_scrollback() {
        // Decode the canonical literal into the daemon's own types, re-serialize, and
        // assert it reproduces the literal byte-for-byte. Pins the wire shape to the
        // exact bytes the renderer mirror test consumes.
        let ev: DaemonEvent = serde_json::from_str(CROSS_WIRE_SCROLLBACK_JSON).unwrap();
        let reser = serde_json::to_string(&ev).unwrap();
        assert_eq!(reser, CROSS_WIRE_SCROLLBACK_JSON);
        match ev {
            DaemonEvent::ScrollbackRows {
                history_len, rows, ..
            } => {
                assert_eq!(history_len, 5000);
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].len(), 1);
            }
            other => panic!("expected ScrollbackRows, got {other:?}"),
        }
    }
}
