//! Wire protocol mirror. These types are deserialization-only mirrors of the
//! daemon's `protocol`/`grid`/`revision` serde shapes. We deliberately keep our
//! own copy (rather than depending on the `pty-daemon` crate) so the renderer
//! has zero coupling to daemon internals: it only needs the JSON contract.
//!
//! IMPORTANT: this commit paints the authoritative `GridSnapshot` only. We never
//! decode the `Output.data` base64 bytes — re-parsing PTY bytes would be a second
//! VT parser, which the project forbids.

use serde::{Deserialize, Serialize};

/// A semantic palette slot. The renderer resolves each against its theme.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NamedColor {
    Black,
    Red,
    Green,
    Yellow,
    Blue,
    Magenta,
    Cyan,
    White,
    BrightBlack,
    BrightRed,
    BrightGreen,
    BrightYellow,
    BrightBlue,
    BrightMagenta,
    BrightCyan,
    BrightWhite,
    Foreground,
    Background,
    Cursor,
    DimBlack,
    DimRed,
    DimGreen,
    DimYellow,
    DimBlue,
    DimMagenta,
    DimCyan,
    DimWhite,
    BrightForeground,
    DimForeground,
}

/// A terminal color on the wire.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Color {
    Named { name: NamedColor },
    Indexed { index: u8 },
    Rgb { r: u8, g: u8, b: u8 },
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CursorShape {
    Block,
    Underline,
    Beam,
}

#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnderlineStyle {
    #[default]
    None,
    Single,
    Double,
    Curly,
    Dotted,
    Dashed,
}

/// Hard cap on the UTF-8 byte length of a single `Cell::text` (mirror of the daemon's
/// `grid::MAX_CELL_TEXT_BYTES`). Enforced DURING deserialization by a custom visitor so
/// an over-long cell text fails the parse early, not after the whole frame is built.
/// `MAX_LINE_BYTES` remains the hard pre-parse memory bound.
pub const MAX_CELL_TEXT_BYTES: usize = 64;

/// One cell of the authoritative grid. `width`: 1 = normal, 2 = wide lead,
/// 0 = wide spacer (skip drawing).
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct Cell {
    #[serde(deserialize_with = "deserialize_cell_text")]
    pub text: String,
    pub fg: Color,
    pub bg: Color,
    #[serde(default)]
    pub bold: bool,
    #[serde(default)]
    pub italic: bool,
    #[serde(default)]
    pub underline: UnderlineStyle,
    #[serde(default)]
    pub inverse: bool,
    #[serde(default)]
    pub strikeout: bool,
    #[serde(default)]
    pub dim: bool,
    #[serde(default)]
    pub hidden: bool,
    /// Bounded OSC 8 target supplied by the daemon.  Missing stays `None` for
    /// compatibility with older retained daemons; opening still re-validates the
    /// scheme/content at the renderer boundary.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "deserialize_cell_hyperlink"
    )]
    pub hyperlink: Option<String>,
    pub width: u8,
}

/// Deserialize `Cell::text`, rejecting any string longer than `MAX_CELL_TEXT_BYTES`
/// as it is read (mirror of the daemon's `grid::deserialize_cell_text`). Fails the
/// parse early rather than after the whole frame is constructed.
fn deserialize_cell_text<'de, D>(de: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, Visitor};
    use std::fmt;

    struct TextVisitor;
    impl Visitor<'_> for TextVisitor {
        type Value = String;
        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(f, "a cell text string up to {MAX_CELL_TEXT_BYTES} bytes")
        }
        fn visit_str<E: Error>(self, v: &str) -> Result<String, E> {
            if v.len() > MAX_CELL_TEXT_BYTES {
                return Err(E::custom(format!(
                    "cell text {} bytes exceeds {MAX_CELL_TEXT_BYTES}",
                    v.len()
                )));
            }
            Ok(v.to_owned())
        }
        fn visit_string<E: Error>(self, v: String) -> Result<String, E> {
            if v.len() > MAX_CELL_TEXT_BYTES {
                return Err(E::custom(format!(
                    "cell text {} bytes exceeds {MAX_CELL_TEXT_BYTES}",
                    v.len()
                )));
            }
            Ok(v)
        }
    }
    de.deserialize_str(TextVisitor)
}

fn deserialize_cell_hyperlink<'de, D>(de: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    use serde::de::{Error, Visitor};
    use std::fmt;

    struct OptionalHyperlinkVisitor;
    impl<'de> Visitor<'de> for OptionalHyperlinkVisitor {
        type Value = Option<String>;

        fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
            write!(
                f,
                "null or a terminal hyperlink up to {} bytes",
                maestro_protocol::MAX_TERMINAL_URL_BYTES
            )
        }

        fn visit_none<E: Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_unit<E: Error>(self) -> Result<Self::Value, E> {
            Ok(None)
        }

        fn visit_some<D2>(self, de: D2) -> Result<Self::Value, D2::Error>
        where
            D2: serde::Deserializer<'de>,
        {
            struct HyperlinkVisitor;
            impl Visitor<'_> for HyperlinkVisitor {
                type Value = String;

                fn expecting(&self, f: &mut fmt::Formatter) -> fmt::Result {
                    write!(
                        f,
                        "a terminal hyperlink up to {} bytes",
                        maestro_protocol::MAX_TERMINAL_URL_BYTES
                    )
                }

                fn visit_str<E: Error>(self, value: &str) -> Result<Self::Value, E> {
                    if value.len() > maestro_protocol::MAX_TERMINAL_URL_BYTES {
                        return Err(E::custom("terminal hyperlink exceeds byte cap"));
                    }
                    Ok(value.to_owned())
                }

                fn visit_string<E: Error>(self, value: String) -> Result<Self::Value, E> {
                    if value.len() > maestro_protocol::MAX_TERMINAL_URL_BYTES {
                        return Err(E::custom("terminal hyperlink exceeds byte cap"));
                    }
                    Ok(value)
                }
            }
            de.deserialize_str(HyperlinkVisitor).map(Some)
        }
    }

    de.deserialize_option(OptionalHyperlinkVisitor)
}

/// `SessionGeneration` serializes as a bare UUID string; we keep it as a String
/// since we only compare/display it, never mint UUIDs.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq, Hash)]
pub struct SessionGeneration(pub String);

/// `Revision` serializes as a bare u64.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq, PartialOrd, Ord, Default)]
pub struct Revision(pub u64);

/// One screen of the authoritative grid. We ignore unknown fields for forward
/// compatibility.
#[derive(Clone, Serialize, Deserialize, Debug)]
pub struct GridSnapshot {
    pub version: u32,
    pub generation: SessionGeneration,
    pub revision: Revision,
    /// Revision this snapshot continues from (see daemon `grid.rs`). The sync
    /// state machine uses it to tell a continuous fast-forward from a fresh
    /// baseline. `#[serde(default)]` keeps us tolerant of a snapshot that
    /// predates the field.
    #[serde(default)]
    pub base_revision: Revision,
    pub cols: usize,
    pub rows: usize,
    pub rows_cells: Vec<Vec<Cell>>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_copy: Option<Vec<maestro_protocol::row_copy::RowCopy>>,
    pub cursor_line: usize,
    pub cursor_col: usize,
    pub cursor_visible: bool,
    pub cursor_shape: CursorShape,
    pub alt_screen: bool,
    /// DECCKM application-cursor mode: arrows/Home/End emit `\x1bO_` not `\x1b[_`.
    /// REQUIRED in V2 (no serde default) — a missing field means a V1-shaped
    /// snapshot, which the sync gate rejects before any mode state is read.
    pub app_cursor: bool,
    /// Bracketed-paste mode: pasted text is wrapped in `\x1b[200~`/`\x1b[201~`.
    pub bracketed_paste: bool,
    /// Focus-reporting mode: focus changes emit `\x1b[I`/`\x1b[O`.
    pub focus_reporting: bool,
    /// Mouse click reporting (DECSET 1000). `#[serde(default)]`: an older daemon omits the
    /// field and it decodes as `false`. Unlike the V2 mode fields above, mouse modes are an
    /// additive, defaulted extension — their absence is "no mouse reporting", which is safe.
    #[serde(default)]
    pub mouse_report: bool,
    /// Mouse button-drag reporting (DECSET 1002): report motion while a button is held.
    #[serde(default)]
    pub mouse_drag: bool,
    /// Mouse any-motion reporting (DECSET 1003): report motion with no button held.
    #[serde(default)]
    pub mouse_motion: bool,
    /// SGR extended mouse encoding (DECSET 1006).
    #[serde(default)]
    pub mouse_sgr: bool,
}

/// Copy metadata may exclude only genuine blank width-one placeholder cells.
pub(crate) fn row_copy_cells_valid(
    rows: &[Vec<Cell>],
    metadata: Option<&[maestro_protocol::row_copy::RowCopy]>,
) -> bool {
    let cols = rows.first().map_or(0, Vec::len);
    rows.iter().all(|row| row.len() == cols)
        && maestro_protocol::row_copy::row_copy_valid(metadata, cols, rows.len())
        && metadata.is_none_or(|metadata| {
            metadata.iter().enumerate().all(|(index, row)| {
                row.excluded_columns.iter().all(|col| {
                    let cell = &rows[index][usize::from(*col)];
                    cell.width == 1 && cell.text == " "
                })
            })
        })
}

/// Renderer-side enforcement of the shared OSC 8 cell budget. The daemon applies
/// the same cap while producing snapshots, but every decoded or damage-mutated grid
/// is rechecked because the local socket payload is still untrusted input.
pub(crate) fn terminal_link_cells_within_cap(rows: &[Vec<Cell>]) -> bool {
    rows.iter()
        .flatten()
        .filter(|cell| cell.hyperlink.is_some())
        .take(maestro_protocol::MAX_TERMINAL_LINK_CELLS_PER_FRAME + 1)
        .count()
        <= maestro_protocol::MAX_TERMINAL_LINK_CELLS_PER_FRAME
}

/// `SessionId(pub String)` is a newtype tuple struct: serializes as a bare
/// string. We send `{"op":"attach","id":"<session>"}` directly. The renderer
/// attaches, pulls snapshots, writes input, and resizes the daemon.
/// `Write.data` carries the LITERAL byte sequence to feed the PTY — the daemon
/// forwards `data`'s raw UTF-8 bytes unchanged (see pty-daemon protocol.rs).
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum ClientRequest {
    /// Read-only daemon protocol/capability probe. The renderer sends this on a candidate socket
    /// before it admits any terminal mutation.
    DaemonInfo,
    /// `want_raw_output` (C3) opts the renderer OUT of raw `Output { data }`: with
    /// `false` the daemon streams Grid/Damage/lifecycle/resync only. As of C3.6 the
    /// native renderer sends `false` — it is structured-only (live updates via Damage,
    /// no second VT parse) and the Output->Snapshot bridge is retired. Default mirrors
    /// the daemon: an absent field decodes to `true` for compatibility.
    Attach {
        id: String,
        #[serde(default = "default_true")]
        want_raw_output: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        expected_session_generation: Option<String>,
        /// Connection-local causal fence for this exact Attach incarnation. Canonical daemons
        /// echo it on the Attach restore Grid and tag every event from that live forwarder. An
        /// older daemon ignores the additive field; the client permits that only for the initial
        /// connection incarnation and fails closed after any clear/rebind.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        output_generation: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        handoff: Option<maestro_shell::AttachmentHandoff>,
    },
    /// Retire one exact pending startup-to-renderer ownership handoff. This is the renderer mirror
    /// of `maestro_protocol::ClientRequest::CancelAttachmentHandoff`; the opaque token remains
    /// redacted by its own Debug/Display implementations.
    CancelAttachmentHandoff {
        id: String,
        token: maestro_shell::AttachmentHandoffToken,
        expected_daemon_instance: maestro_shell::DaemonInstanceId,
    },
    /// Stop streaming a session to this client (the inverse of Attach). The session
    /// keeps running; only this client's forwarder ends. Mirror of the daemon's
    /// existing `ClientRequest::Detach` — NOT a new wire message. Sent when the single
    /// renderer rebinds to a different session so the daemon stops forwarding the old
    /// one before the new Attach.
    Detach {
        id: String,
    },
    Snapshot {
        id: String,
    },
    Write {
        id: String,
        expected_generation: SessionGeneration,
        data: String,
    },
    Resize {
        id: String,
        expected_generation: SessionGeneration,
        cols: u16,
        rows: u16,
    },
    /// Request a window of STRUCTURED historical rows. Read-only; the
    /// daemon clamps `count` to `MAX_SCROLLBACK_ROWS_PER_REQUEST` and replies with a
    /// `ScrollbackRows` event. Mirror of the daemon's `ClientRequest::Scrollback`. Live
    /// The renderer sends this in response to wheel / PageUp/Down / Home/End
    /// and paints the reply as renderer-owned view state, separate from the live `Grid`.
    Scrollback {
        id: String,
        /// Topmost history line to fetch, as a non-negative distance ABOVE the top
        /// visible row (`1` = the row just above the screen; `0` = the top visible row).
        offset_from_top: u32,
        /// Rows to return, walking downward toward the screen. Server-clamped.
        count: u16,
    },
}

/// Hard cap on the number of historical rows in one `Scrollback` reply, mirror of the
/// daemon's `MAX_SCROLLBACK_ROWS_PER_REQUEST`. The renderer requests at most this many
/// rows per round-trip and paginates for more. Mirrors the daemon cap so the two cannot
/// drift.
#[allow(dead_code)]
pub const MAX_SCROLLBACK_ROWS_PER_REQUEST: u16 = 256;

/// Damage wire-schema version. Mirrors the daemon's `DAMAGE_SCHEMA`. An
/// unknown schema is treated as malformed damage -> resync, never misapplied.
pub const DAMAGE_SCHEMA: u32 = 1;

/// Caps mirroring the daemon's `MAX_DAMAGE_OPS` / `MAX_DAMAGE_CELLS`. A frame over
/// either is malformed -> resync; they bound allocation against a hostile sender.
/// `MAX_DAMAGE_CELLS` is the PRACTICAL per-frame mutation volume (1e6 cells), not the
/// theoretical grid max — mirror of the daemon value.
pub const MAX_DAMAGE_OPS: usize = 4096;
pub const MAX_DAMAGE_CELLS: usize = 1_000_000;

/// Practical per-frame serialized-byte cap (mirror of the daemon's `MAX_DAMAGE_BYTES`).
/// Enforced at the framing layer BEFORE a full typed parse of a damage line: a damage
/// event whose raw line exceeds this is rejected (drop to resync) without paying to
/// deserialize a 9 MiB payload's nested cells.
pub const MAX_DAMAGE_BYTES: usize = 9 * 1024 * 1024;

/// Why decoding a raw event line failed at the framing layer (before a full typed
/// parse). Distinct from `DamageInvalid` (post-decode structural validation).
#[derive(Debug, PartialEq, Eq)]
pub enum DecodeError {
    /// The raw line is not even a minimal `{"ev": "..."}` envelope (bad JSON / missing
    /// tag). With no trustworthy route this is a connection-terminal protocol failure.
    BadEnvelope,
    /// The event is a `damage` whose raw line exceeds `MAX_DAMAGE_BYTES`. Rejected at
    /// the framing layer WITHOUT a full parse of its nested cells. Route classification decides
    /// whether an exact current Damage can recover or the connection must fail closed.
    DamageTooLarge { bytes: usize },
    /// The line passed framing checks but full typed deserialization failed (malformed fields,
    /// over-long cell text, etc.). Deliberately carries no serde text: those diagnostics may quote
    /// terminal-controlled values and must never reach logs or a future derived `Debug` dump.
    BadPayload,
}

/// Minimal borrowed envelope: reads ONLY the `ev` tag, ignoring every other field
/// (the nested `frame`/`grid`/cells are never allocated). `serde(borrow)` keeps `ev`
/// a `&str` into the input line. This is the "lightweight bounded discriminator": we
/// learn the event kind with a cheap scan, apply the damage byte cap, and only THEN do
/// the full typed parse. Field ordering / whitespace are irrelevant — this is real
/// JSON parsing, not a substring match.
#[derive(Deserialize)]
struct EventEnvelope<'a> {
    #[serde(borrow)]
    ev: &'a str,
    #[serde(default, borrow)]
    id: Option<&'a str>,
    #[serde(default, borrow)]
    frame: Option<EventFrameEnvelope<'a>>,
    /// Present only on the restore Grid produced by an Attach carrying the matching request
    /// generation. Snapshot replies omit it.
    #[serde(default)]
    output_generation: Option<u64>,
    /// Present on events emitted by one Attach's live forwarder (Damage, notifications, exit,
    /// resync, and its follow-up Grid). It stays outside the typed event payload so old clients
    /// continue to ignore it.
    #[serde(default)]
    live_output_generation: Option<u64>,
}

#[derive(Deserialize)]
struct EventFrameEnvelope<'a> {
    #[serde(borrow)]
    id: &'a str,
}

/// Causal routing metadata extracted from the same bounded event line before its heavy payload is
/// decoded. These fields are additive on the daemon wire and intentionally remain outside
/// [`DaemonEvent`] so the existing event constructors and schema mirror stay compact.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct EventRouteMetadata {
    pub output_generation: Option<u64>,
    pub live_output_generation: Option<u64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EventRouteKind {
    Grid,
    Damage,
    ScrollbackRows,
    Other,
}

impl EventRouteKind {
    fn from_tag(tag: &str) -> Self {
        match tag {
            "grid" => Self::Grid,
            "damage" => Self::Damage,
            "scrollback_rows" => Self::ScrollbackRows,
            _ => Self::Other,
        }
    }
}

/// A payload/framing failure plus whatever bounded routing proof the lightweight envelope could
/// establish. A malformed old-generation line must not be allowed to resync the current viewport,
/// so callers inspect this metadata before mutating SyncState or admitting a Snapshot request.
#[derive(Debug)]
pub struct RoutedDecodeError {
    pub error: DecodeError,
    pub route: Option<EventRouteMetadata>,
    pub kind: Option<EventRouteKind>,
    pub session_id: Option<String>,
}

/// Decode one raw event line into a `DaemonEvent`, enforcing the damage byte cap
/// BEFORE full deserialization. Steps:
/// 1. Parse a minimal envelope to read `ev` without allocating nested cells.
/// 2. If `ev == "damage"` and the line is over `MAX_DAMAGE_BYTES`, reject as
///    `DamageTooLarge` — no second full parse of the oversized payload.
/// 3. Otherwise do the full typed parse (a second linear scan, which is acceptable;
///    ambiguous substring framing is not).
///
/// `line` is the already-trimmed, already-`MAX_LINE_BYTES`-bounded UTF-8 line.
#[cfg(test)]
pub fn decode_event(line: &str) -> Result<DaemonEvent, DecodeError> {
    decode_event_with_route(line)
        .map(|(event, _)| event)
        .map_err(|error| error.error)
}

/// Decode an event together with its connection-local Attach ownership proof. The discriminator
/// pass remains lightweight: it reads only the event tag and two optional integers, then the same
/// damage-size gate runs before full payload allocation.
pub fn decode_event_with_route(
    line: &str,
) -> Result<(DaemonEvent, EventRouteMetadata), RoutedDecodeError> {
    let env: EventEnvelope = serde_json::from_str(line).map_err(|_| RoutedDecodeError {
        error: DecodeError::BadEnvelope,
        route: None,
        kind: None,
        session_id: None,
    })?;
    let route = EventRouteMetadata {
        output_generation: env.output_generation,
        live_output_generation: env.live_output_generation,
    };
    let kind = EventRouteKind::from_tag(env.ev);
    // Match the typed route exactly: Damage authority lives only at `frame.id`; every other modeled
    // session event uses the top-level id. A conflicting attacker-supplied top-level Damage id must
    // never redirect a malformed old payload into the current binding's recovery path.
    let session_id = match kind {
        EventRouteKind::Damage => env.frame.as_ref().map(|frame| frame.id),
        _ => env.id,
    }
    .map(str::to_string);
    if env.ev == "damage" && line.len() > MAX_DAMAGE_BYTES {
        return Err(RoutedDecodeError {
            error: DecodeError::DamageTooLarge { bytes: line.len() },
            route: Some(route),
            kind: Some(kind),
            session_id,
        });
    }
    let event = serde_json::from_str(line).map_err(|_| RoutedDecodeError {
        error: DecodeError::BadPayload,
        route: Some(route),
        kind: Some(kind),
        session_id,
    })?;
    Ok((event, route))
}

/// Per-line framing ceiling for the event read loop, mirror of the daemon's
/// `MAX_LINE_BYTES`: a longer line is dropped rather than buffered without limit.
pub const MAX_LINE_BYTES: usize = 16 * 1024 * 1024;

const DAMAGE_MAX_DIMENSION: u16 = 2000;

/// Why a damage frame failed structural validation. Mirror of the daemon's
/// `DamageInvalid`; the renderer maps every variant to "drop to resync, request one
/// snapshot" (the held grid is never mutated by an invalid frame).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DamageInvalid {
    UnsupportedSchema { got: u32 },
    BadDimensions { reason: &'static str },
    TooManyOps { got: usize },
    TooManyCells { got: usize },
    TooManyHyperlinkCells { got: usize },
    RowSpanOutOfBounds { op: usize },
    EmptyRowSpan { op: usize },
    BadScrollRegion { op: usize },
    BadRevisionOrder { base: u64, rev: u64 },
    CursorOutOfBounds { line: usize, col: usize },
    BadCell { op: usize },
    BadRowCopy,
}

/// Absolute post-frame cursor state on a damage frame. Mirror of daemon `CursorState`.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct CursorState {
    pub line: usize,
    pub col: usize,
    pub visible: bool,
    pub shape: CursorShape,
}

/// Absolute post-frame mode flags on a damage frame. Mirror of daemon `ModeState`.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
pub struct ModeState {
    pub alt_screen: bool,
    pub app_cursor: bool,
    pub bracketed_paste: bool,
    pub focus_reporting: bool,
    #[serde(default)]
    pub mouse_report: bool,
    #[serde(default)]
    pub mouse_drag: bool,
    #[serde(default)]
    pub mouse_motion: bool,
    #[serde(default)]
    pub mouse_sgr: bool,
}

/// One structured change in a damage frame. Mirror of daemon `DamageOp`. Never
/// carries raw PTY bytes.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
#[serde(tag = "op", rename_all = "snake_case")]
pub enum DamageOp {
    RowSpan {
        row: u16,
        start: u16,
        cells: Vec<Cell>,
    },
    ClearAll {
        cell: Cell,
    },
    ScrollUp {
        top: u16,
        bottom_exclusive: u16,
        lines: u16,
    },
    ScrollDown {
        top: u16,
        bottom_exclusive: u16,
        lines: u16,
    },
}

/// One atomic damage frame. Mirror of daemon `DamageFrame`. The renderer applies this only when `generation`
/// matches its baseline and `base_revision` equals the revision it holds; that
/// continuity check is the sync state machine's job, not `validate`.
#[derive(Clone, Serialize, Deserialize, Debug, PartialEq)]
pub struct DamageFrame {
    pub schema: u32,
    pub id: String,
    pub generation: SessionGeneration,
    pub base_revision: Revision,
    pub revision: Revision,
    pub cols: u16,
    pub rows: u16,
    pub cursor: CursorState,
    pub modes: ModeState,
    pub ops: Vec<DamageOp>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub row_copy: Option<Vec<maestro_protocol::row_copy::RowCopy>>,
}

impl DamageFrame {
    /// Pure structural validation (shape only — not continuity). Mirrors the
    /// daemon's `DamageFrame::validate`: schema, dims, allocation caps, RowSpan
    /// bounds, half-open scroll constraints, revision ordering.
    pub fn validate(&self) -> Result<(), DamageInvalid> {
        if !maestro_protocol::row_copy::row_copy_valid(
            self.row_copy.as_deref(),
            self.cols as usize,
            self.rows as usize,
        ) {
            return Err(DamageInvalid::BadRowCopy);
        }
        if self.schema != DAMAGE_SCHEMA {
            return Err(DamageInvalid::UnsupportedSchema { got: self.schema });
        }
        if self.cols == 0 || self.rows == 0 {
            return Err(DamageInvalid::BadDimensions {
                reason: "zero cols or rows",
            });
        }
        if self.cols > DAMAGE_MAX_DIMENSION || self.rows > DAMAGE_MAX_DIMENSION {
            return Err(DamageInvalid::BadDimensions {
                reason: "cols or rows exceed maximum",
            });
        }
        // Strictly advancing revision: a damage frame is >= 1 mutation.
        if self.base_revision.0 >= self.revision.0 {
            return Err(DamageInvalid::BadRevisionOrder {
                base: self.base_revision.0,
                rev: self.revision.0,
            });
        }
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
        let mut hyperlink_cells = 0usize;
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
                    hyperlink_cells = hyperlink_cells
                        .checked_add(cells.iter().filter(|cell| cell.hyperlink.is_some()).count())
                        .ok_or(DamageInvalid::TooManyHyperlinkCells { got: usize::MAX })?;
                    if hyperlink_cells > maestro_protocol::MAX_TERMINAL_LINK_CELLS_PER_FRAME {
                        return Err(DamageInvalid::TooManyHyperlinkCells {
                            got: hyperlink_cells,
                        });
                    }
                    total_cells = total_cells
                        .checked_add(cells.len())
                        .ok_or(DamageInvalid::TooManyCells { got: usize::MAX })?;
                    if total_cells > MAX_DAMAGE_CELLS {
                        return Err(DamageInvalid::TooManyCells { got: total_cells });
                    }
                }
                DamageOp::ClearAll { cell } => {
                    // Canonical blank fill: width 1 and text " " (mirror of the daemon
                    // validation). Styling is free; the glyph and width are pinned so
                    // "blank" has exactly one representation.
                    if !cell_is_valid(cell) || cell.width != 1 || cell.text != " " {
                        return Err(DamageInvalid::BadCell { op: i });
                    }
                    if cell.hyperlink.is_some() {
                        let projected =
                            usize::from(self.cols).saturating_mul(usize::from(self.rows));
                        if projected > maestro_protocol::MAX_TERMINAL_LINK_CELLS_PER_FRAME {
                            return Err(DamageInvalid::TooManyHyperlinkCells { got: projected });
                        }
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

/// Mirror of the daemon's `cell_is_valid`: width 0/1/2; a width-0 spacer must have
/// empty text.
fn cell_is_valid(cell: &Cell) -> bool {
    match cell.width {
        0 => cell.text.is_empty(),
        1 | 2 => true,
        _ => false,
    }
}

/// serde default for `Attach.want_raw_output` — absence identifies a compatibility client which
/// keeps raw output (mirror of the daemon default).
fn default_true() -> bool {
    true
}

/// Renderer-local mirror of the protocol's typed generation-conditional Attach refusal. Keeping
/// this leaf wire module independent of the full protocol crate preserves the existing renderer
/// dependency boundary while decoding the exact same snake-case bytes.
#[derive(Clone, Copy, Serialize, Deserialize, Debug, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum SessionAttachRefusal {
    Missing,
    GenerationMismatch,
}

/// Events the daemon sends. We only model the variants this commit cares about;
/// `#[serde(other)]` swallows the rest (channel, sessions, output's siblings)
/// so an unknown `ev` never aborts the reader.
#[derive(Clone, Serialize, Deserialize, Debug)]
#[serde(tag = "ev", rename_all = "snake_case")]
pub enum DaemonEvent {
    DaemonInfo {
        protocol_version: u32,
        build_version: String,
        /// Opaque per-process identity required before a handoff Claim may cross this connection.
        #[serde(default)]
        daemon_instance_id: Option<maestro_shell::DaemonInstanceId>,
        #[serde(default)]
        output_generation_echo: bool,
        #[serde(default)]
        child_environment: bool,
        #[serde(default)]
        generation_conditional_mutations: bool,
        #[serde(default)]
        attachment_aware_conditional_kill: bool,
        #[serde(default)]
        generation_conditional_attach: bool,
    },
    SessionAttachRefused {
        id: String,
        expected_generation: String,
        daemon_instance_id: maestro_shell::DaemonInstanceId,
        reason: SessionAttachRefusal,
    },
    TerminalBell {
        id: String,
    },
    TerminalTitle {
        id: String,
        title: Option<String>,
    },
    TerminalClipboardStore {
        id: String,
        text: String,
    },
    /// THE thing we paint.
    Grid {
        id: String,
        grid: GridSnapshot,
    },
    /// One atomic structured-damage frame. After shape/continuity
    /// validation the frame is applied to the renderer's grid via `sync`, which is how
    /// the screen updates between full `Grid` snapshots. A frame that fails validation
    /// drops the renderer to resync rather than being applied.
    Damage {
        frame: DamageFrame,
    },
    /// A window of structured historical rows, mirroring the daemon's
    /// `DaemonEvent::ScrollbackRows`. It is not a `Grid` and is not part of the live-grid sync state
    /// machine: it carries rows that scrolled above the live screen as structured
    /// `Cell`s (never raw bytes), emitted in reply to a `Scrollback`
    /// request and painted as renderer-owned view state while scrolled up.
    ScrollbackRows {
        id: String,
        generation: SessionGeneration,
        revision: Revision,
        history_len: u32,
        offset_from_top: u32,
        rows: Vec<Vec<Cell>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        row_copy: Option<Vec<maestro_protocol::row_copy::RowCopy>>,
    },
    /// We IGNORE `data` (raw PTY bytes). `revision` is read only as a cheap
    /// "grid changed" signal to drive poll cadence.
    Output {
        id: String,
        #[serde(default)]
        generation: Option<SessionGeneration>,
        revision: Revision,
        #[allow(dead_code)]
        data: String,
    },
    ResyncRequired {
        id: String,
    },
    SessionExited {
        id: String,
        code: Option<i32>,
    },
    Error {
        message: String,
    },
    /// Any other event variant (sessions, channel, ...) we don't act on.
    #[serde(other)]
    Other,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A V1-shaped grid event: `version:1` and — crucially — NO `app_cursor`,
    /// `bracketed_paste`, or `focus_reporting` fields, exactly as the old daemon
    /// emitted. Everything else is a well-formed minimal grid so the ONLY thing
    /// that can make decode fail is the missing required V2 mode fields.
    fn v1_grid_json() -> &'static str {
        r#"{
            "ev": "grid",
            "id": "s1",
            "grid": {
                "version": 1,
                "generation": "11111111-1111-1111-1111-111111111111",
                "revision": 7,
                "cols": 1,
                "rows": 1,
                "rows_cells": [[{
                    "text": "x",
                    "fg": {"kind": "named", "name": "foreground"},
                    "bg": {"kind": "named", "name": "background"},
                    "width": 1
                }]],
                "cursor_line": 0,
                "cursor_col": 0,
                "cursor_visible": true,
                "cursor_shape": "block",
                "alt_screen": false
            }
        }"#
    }

    /// Wire-level proof: a genuine V1 payload — missing the three
    /// required mode fields — fails serde decoding outright. It can never become a
    /// `GridSnapshot`, so it never reaches `SyncState`/`on_grid`; the version gate
    /// there is a second line of defense, not the only one. This guards against a
    /// future `#[serde(default)]` slipping onto a mode field and silently admitting
    /// V1 snapshots with `false` mode flags (which would mis-encode arrows/paste).
    #[test]
    fn v1_grid_event_fails_wire_decode_before_sync() {
        let err = serde_json::from_str::<DaemonEvent>(v1_grid_json());
        assert!(
            err.is_err(),
            "V1 grid (no mode fields) must fail schema decode, got {err:?}"
        );
    }

    /// Control: the SAME JSON with the three mode fields added decodes cleanly,
    /// proving the V1 failure above is specifically the missing required fields
    /// and not some unrelated malformation in the fixture.
    #[test]
    fn v2_grid_event_with_mode_fields_decodes() {
        let v2 = v1_grid_json().replace(
            "\"alt_screen\": false",
            "\"alt_screen\": false, \"app_cursor\": true, \"bracketed_paste\": false, \"focus_reporting\": true",
        );
        let ev = serde_json::from_str::<DaemonEvent>(&v2).expect("V2 grid decodes");
        match ev {
            DaemonEvent::Grid { grid, .. } => {
                assert_eq!(grid.version, 1, "version field carried through verbatim");
                assert!(grid.app_cursor);
                assert!(!grid.bracketed_paste);
                assert!(grid.focus_reporting);
            }
            other => panic!("expected Grid, got {other:?}"),
        }
    }

    // --- Damage schema mirror tests ----------------------------------------
    // The renderer decodes/validates damage frames; these mirror the daemon's
    // `damage_tests` so the two definitions cannot silently drift. `Cell` has no
    // `PartialEq` here, so cell-bearing frames are checked by re-decoding fields
    // rather than whole-value equality.

    fn dmg_cell(text: &str) -> Cell {
        Cell {
            text: text.to_string(),
            fg: Color::Named {
                name: NamedColor::Foreground,
            },
            bg: Color::Named {
                name: NamedColor::Background,
            },
            bold: false,
            italic: false,
            underline: UnderlineStyle::None,
            inverse: false,
            strikeout: false,
            dim: false,
            hidden: false,
            hyperlink: None,
            width: 1,
        }
    }

    fn dmg_cursor() -> CursorState {
        CursorState {
            line: 0,
            col: 0,
            visible: true,
            shape: CursorShape::Block,
        }
    }

    fn dmg_modes() -> ModeState {
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

    fn dmg_frame(ops: Vec<DamageOp>) -> DamageFrame {
        DamageFrame {
            row_copy: None,
            schema: DAMAGE_SCHEMA,
            id: "s1".into(),
            generation: SessionGeneration("11111111-1111-1111-1111-111111111111".into()),
            base_revision: Revision(4),
            revision: Revision(5),
            cols: 10,
            rows: 4,
            cursor: dmg_cursor(),
            modes: dmg_modes(),
            ops,
        }
    }

    #[test]
    fn damage_frame_decodes_through_json() {
        let f = dmg_frame(vec![
            DamageOp::RowSpan {
                row: 1,
                start: 2,
                cells: vec![dmg_cell("a"), dmg_cell("b")],
            },
            DamageOp::ClearAll {
                cell: dmg_cell(" "),
            },
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
        assert_eq!(back.schema, DAMAGE_SCHEMA);
        assert_eq!(back.ops.len(), 4);
        assert_eq!(back.base_revision, Revision(4));
        assert_eq!(back.revision, Revision(5));
    }

    /// Renderer mirror of the daemon's `mouse_modes_round_trip_through_damage_json`: each
    /// mouse-mode bit must survive serde through a `DamageFrame`, tested one field at a time
    /// so a swapped/dropped field is caught per-field, then all four together. This proves a
    /// daemon damage frame that flips a mouse mode is decoded with that bit intact by the
    /// renderer mirror — i.e. mouse-mode toggles propagate through incremental Damage, not
    /// only a full resync. Keep this in lockstep with the daemon test.
    #[test]
    fn mouse_modes_round_trip_through_damage_json() {
        let only = |set: fn(&mut ModeState)| {
            let mut m = dmg_modes();
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
            let mut f = dmg_frame(vec![]);
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

        let all = ModeState {
            mouse_report: true,
            mouse_drag: true,
            mouse_motion: true,
            mouse_sgr: true,
            ..dmg_modes()
        };
        let mut f = dmg_frame(vec![]);
        f.modes = all;
        let back: DamageFrame = serde_json::from_str(&serde_json::to_string(&f).unwrap()).unwrap();
        assert_eq!(back.modes, all);
    }

    /// A damage event line emitted by a daemon with a mouse mode set decodes in the renderer
    /// mirror with that bit live — the cross-crate proof that incremental Damage carries
    /// mouse state. Built from the canonical cross-wire fixture with one `mouse_sgr` flipped
    /// to `true`, so it shares the exact field set the daemon emits.
    #[test]
    fn cross_wire_damage_with_mouse_mode_decodes_in_mirror() {
        let with_mouse =
            CROSS_WIRE_DAMAGE_JSON.replace("\"mouse_sgr\":false", "\"mouse_sgr\":true");
        assert_ne!(
            with_mouse, CROSS_WIRE_DAMAGE_JSON,
            "fixture must actually contain a mouse_sgr field to flip"
        );
        let ev: DaemonEvent = serde_json::from_str(&with_mouse).expect("decodes in mirror");
        match ev {
            DaemonEvent::Damage { frame } => {
                assert!(frame.modes.mouse_sgr, "mouse_sgr bit is live after decode");
                assert!(!frame.modes.mouse_report, "other mouse bits stay false");
                assert_eq!(frame.validate(), Ok(()), "still a structurally valid frame");
            }
            other => panic!("expected Damage, got {other:?}"),
        }
    }

    #[test]
    fn damage_event_decodes_with_ev_tag() {
        let ev = DaemonEvent::Damage {
            frame: dmg_frame(vec![]),
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
    fn damage_op_tag_is_snake_case() {
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
        // An absent flag defaults to true so compatibility clients keep raw output.
        let req: ClientRequest = serde_json::from_str(r#"{"op":"attach","id":"s1"}"#).unwrap();
        match req {
            ClientRequest::Attach {
                want_raw_output, ..
            } => assert!(want_raw_output, "absent flag defaults to true"),
            other => panic!("expected Attach, got {other:?}"),
        }
        // Explicit false (a grid-aware renderer opting out) round-trips.
        let req: ClientRequest =
            serde_json::from_str(r#"{"op":"attach","id":"s1","want_raw_output":false}"#).unwrap();
        match req {
            ClientRequest::Attach {
                want_raw_output, ..
            } => assert!(!want_raw_output),
            other => panic!("expected Attach, got {other:?}"),
        }
    }

    /// The native renderer is structured-only. The exact Attach request it sends
    /// (see `client::run`) MUST serialize with `want_raw_output:false`, so the daemon
    /// withholds raw Output and ships only Grid/Damage/Resync.
    #[test]
    fn renderer_attach_serializes_want_raw_output_false() {
        let req = ClientRequest::Attach {
            id: "s1".to_string(),
            want_raw_output: false,
            expected_session_generation: None,
            output_generation: Some(7),
            handoff: None,
        };
        let json = serde_json::to_string(&req).unwrap();
        assert!(json.contains("\"op\":\"attach\""), "{json}");
        assert!(json.contains("\"want_raw_output\":false"), "{json}");
        assert!(
            !json.contains("\"want_raw_output\":true"),
            "structured-only renderer must NOT opt into raw output: {json}"
        );
    }

    #[test]
    fn attachment_handoff_cancel_matches_canonical_request_shape() {
        let token: maestro_shell::AttachmentHandoffToken = "0123456789abcdef0123456789abcdef"
            .parse()
            .expect("valid handoff token");
        let expected_daemon_instance: maestro_shell::DaemonInstanceId =
            "22222222222242228222222222222222"
                .parse()
                .expect("valid daemon instance");
        let request = ClientRequest::CancelAttachmentHandoff {
            id: "s1".to_string(),
            token: token.clone(),
            expected_daemon_instance,
        };
        let json = serde_json::to_string(&request).expect("cancel serializes");
        assert_eq!(
            json,
            r#"{"op":"cancel_attachment_handoff","id":"s1","token":"0123456789abcdef0123456789abcdef","expected_daemon_instance":"22222222222242228222222222222222"}"#
        );
        assert_eq!(
            serde_json::from_str::<ClientRequest>(&json).expect("cancel round-trips"),
            request
        );
    }

    #[test]
    fn conditional_attach_refusal_decodes_with_exact_correlation_facts() {
        let event: DaemonEvent = serde_json::from_str(
            r#"{"ev":"session_attach_refused","id":"s1","expected_generation":"generation-a","daemon_instance_id":"22222222222242228222222222222222","reason":"missing"}"#,
        )
        .expect("conditional Attach refusal decodes");
        assert!(matches!(
            event,
            DaemonEvent::SessionAttachRefused {
                ref id,
                ref expected_generation,
                ref daemon_instance_id,
                reason: SessionAttachRefusal::Missing,
            } if id == "s1"
                && expected_generation == "generation-a"
                && daemon_instance_id.as_str() == "22222222222242228222222222222222"
        ));
    }

    /// The renderer mirrors the daemon's existing `Detach { id }` (NOT a new wire
    /// message): a session rebind detaches the old session first. It must serialize to
    /// the daemon's `{"op":"detach","id":...}` shape and round-trip back.
    #[test]
    fn detach_serializes_and_round_trips() {
        let req = ClientRequest::Detach {
            id: "s-old".to_string(),
        };
        let json = serde_json::to_string(&req).unwrap();
        assert_eq!(json, r#"{"op":"detach","id":"s-old"}"#);
        let back: ClientRequest = serde_json::from_str(&json).unwrap();
        match back {
            ClientRequest::Detach { id } => assert_eq!(id, "s-old"),
            other => panic!("expected Detach, got {other:?}"),
        }
    }

    #[test]
    fn damage_validate_accepts_well_formed_frame() {
        let f = dmg_frame(vec![DamageOp::RowSpan {
            row: 3,
            start: 0,
            cells: vec![dmg_cell("x"); 10],
        }]);
        assert_eq!(f.validate(), Ok(()));
    }

    #[test]
    fn damage_validate_rejects_bad_schema() {
        let mut f = dmg_frame(vec![]);
        f.schema = 99;
        assert_eq!(
            f.validate(),
            Err(DamageInvalid::UnsupportedSchema { got: 99 })
        );
    }

    #[test]
    fn damage_validate_rejects_zero_and_oversized_dims() {
        let mut f = dmg_frame(vec![]);
        f.rows = 0;
        assert!(matches!(
            f.validate(),
            Err(DamageInvalid::BadDimensions { .. })
        ));
        let mut f = dmg_frame(vec![]);
        f.cols = 2001;
        assert!(matches!(
            f.validate(),
            Err(DamageInvalid::BadDimensions { .. })
        ));
    }

    #[test]
    fn damage_validate_rejects_rowspan_out_of_bounds() {
        let f = dmg_frame(vec![DamageOp::RowSpan {
            row: 4,
            start: 0,
            cells: vec![dmg_cell("x")],
        }]);
        assert_eq!(
            f.validate(),
            Err(DamageInvalid::RowSpanOutOfBounds { op: 0 })
        );
        let f = dmg_frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 8,
            cells: vec![dmg_cell("x"); 5],
        }]);
        assert_eq!(
            f.validate(),
            Err(DamageInvalid::RowSpanOutOfBounds { op: 0 })
        );
    }

    #[test]
    fn damage_validate_rejects_too_many_ops() {
        let f = dmg_frame(vec![
            DamageOp::ClearAll {
                cell: dmg_cell(" ")
            };
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
    fn damage_validate_rejects_scroll_region_violations() {
        let f = dmg_frame(vec![DamageOp::ScrollUp {
            top: 2,
            bottom_exclusive: 2,
            lines: 1,
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadScrollRegion { op: 0 }));
        let f = dmg_frame(vec![DamageOp::ScrollDown {
            top: 0,
            bottom_exclusive: 4,
            lines: 0,
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadScrollRegion { op: 0 }));
        let f = dmg_frame(vec![DamageOp::ScrollUp {
            top: 0,
            bottom_exclusive: 4,
            lines: 5,
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadScrollRegion { op: 0 }));
        let f = dmg_frame(vec![DamageOp::ScrollUp {
            top: 0,
            bottom_exclusive: 5,
            lines: 1,
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadScrollRegion { op: 0 }));
    }

    #[test]
    fn damage_validate_rejects_backwards_revision() {
        let mut f = dmg_frame(vec![]);
        f.base_revision = Revision(9);
        f.revision = Revision(5);
        assert_eq!(
            f.validate(),
            Err(DamageInvalid::BadRevisionOrder { base: 9, rev: 5 })
        );
    }

    #[test]
    fn damage_validate_rejects_non_advancing_revision() {
        let mut f = dmg_frame(vec![]);
        f.base_revision = Revision(5);
        f.revision = Revision(5);
        assert_eq!(
            f.validate(),
            Err(DamageInvalid::BadRevisionOrder { base: 5, rev: 5 })
        );
    }

    #[test]
    fn damage_validate_rejects_empty_rowspan() {
        let f = dmg_frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 0,
            cells: vec![],
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::EmptyRowSpan { op: 0 }));
    }

    #[test]
    fn damage_validate_rejects_cursor_out_of_bounds() {
        let mut f = dmg_frame(vec![]);
        f.cursor.col = 10; // == cols
        assert!(matches!(
            f.validate(),
            Err(DamageInvalid::CursorOutOfBounds { .. })
        ));
        let mut f = dmg_frame(vec![]);
        f.cursor.line = 4; // == rows
        assert!(matches!(
            f.validate(),
            Err(DamageInvalid::CursorOutOfBounds { .. })
        ));
    }

    #[test]
    fn damage_validate_rejects_bad_cell() {
        let mut bad = dmg_cell("x");
        bad.width = 3;
        let f = dmg_frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 0,
            cells: vec![bad],
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadCell { op: 0 }));

        let mut spacer = dmg_cell("x");
        spacer.width = 0; // spacer must have empty text
        let f = dmg_frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 0,
            cells: vec![spacer],
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadCell { op: 0 }));

        let mut wide = dmg_cell("W");
        wide.width = 2; // ClearAll fill must be width 1
        let f = dmg_frame(vec![DamageOp::ClearAll { cell: wide }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadCell { op: 0 }));
    }

    #[test]
    fn hyperlink_field_round_trips_and_overlong_hostile_value_is_rejected() {
        let mut linked = dmg_cell("x");
        linked.hyperlink = Some("https://example.test/path".to_owned());
        let json = serde_json::to_string(&linked).unwrap();
        let decoded: Cell = serde_json::from_str(&json).unwrap();
        assert_eq!(decoded.hyperlink, linked.hyperlink);

        linked.hyperlink = Some("x".repeat(maestro_protocol::MAX_TERMINAL_URL_BYTES + 1));
        let json = serde_json::to_string(&linked).unwrap();
        assert!(serde_json::from_str::<Cell>(&json).is_err());
    }

    #[test]
    fn nested_grid_rejects_overlong_hyperlink_before_event_construction() {
        let hostile = CROSS_WIRE_GRID_JSON.replace(
            "https://grid.example.test/x",
            &"x".repeat(maestro_protocol::MAX_TERMINAL_URL_BYTES + 1),
        );
        assert!(serde_json::from_str::<DaemonEvent>(&hostile).is_err());
    }

    #[test]
    fn linked_clear_all_cannot_clone_beyond_the_frame_cell_budget() {
        let mut linked_blank = dmg_cell(" ");
        linked_blank.hyperlink = Some("https://clear.example.test".to_owned());
        let mut frame = dmg_frame(vec![DamageOp::ClearAll { cell: linked_blank }]);
        frame.cols = 17;
        frame.rows = 16;
        assert_eq!(
            frame.validate(),
            Err(DamageInvalid::TooManyHyperlinkCells { got: 272 })
        );
    }

    /// Byte-identical to the daemon's `CROSS_WIRE_DAMAGE_JSON` (protocol.rs). The
    /// daemon test proves it emits exactly these bytes; this test proves they decode
    /// in the renderer mirror and validate. Keep the two literals in lockstep.
    const CROSS_WIRE_DAMAGE_JSON: &str = r#"{"ev":"damage","frame":{"schema":1,"id":"s1","generation":"11111111-1111-1111-1111-111111111111","base_revision":4,"revision":5,"cols":10,"rows":4,"cursor":{"line":1,"col":2,"visible":true,"shape":"block"},"modes":{"alt_screen":false,"app_cursor":true,"bracketed_paste":false,"focus_reporting":true,"mouse_report":false,"mouse_drag":false,"mouse_motion":false,"mouse_sgr":false},"ops":[{"op":"row_span","row":1,"start":2,"cells":[{"text":"a","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"hyperlink":"https://damage.example.test/a","width":1}]},{"op":"clear_all","cell":{"text":" ","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":1}}]}}"#;

    #[test]
    fn cross_wire_damage_decodes_in_renderer_mirror() {
        let ev: DaemonEvent =
            serde_json::from_str(CROSS_WIRE_DAMAGE_JSON).expect("daemon JSON decodes in mirror");
        match ev {
            DaemonEvent::Damage { frame } => {
                assert_eq!(frame.schema, DAMAGE_SCHEMA);
                assert_eq!(frame.id, "s1");
                assert_eq!(frame.base_revision, Revision(4));
                assert_eq!(frame.revision, Revision(5));
                assert_eq!(frame.cols, 10);
                assert_eq!(frame.rows, 4);
                assert_eq!(frame.cursor.line, 1);
                assert_eq!(frame.cursor.col, 2);
                assert!(frame.modes.app_cursor);
                assert!(frame.modes.focus_reporting);
                assert_eq!(frame.ops.len(), 2);
                match &frame.ops[0] {
                    DamageOp::RowSpan { cells, .. } => assert_eq!(
                        cells[0].hyperlink.as_deref(),
                        Some("https://damage.example.test/a")
                    ),
                    other => panic!("expected RowSpan, got {other:?}"),
                }
                // The decoded daemon frame is structurally valid under the mirror's
                // identical validate().
                assert_eq!(frame.validate(), Ok(()));
            }
            other => panic!("expected Damage, got {other:?}"),
        }
    }

    #[test]
    fn clear_all_requires_canonical_blank_fill() {
        // width 1 but non-space text is not the canonical blank.
        let f = dmg_frame(vec![DamageOp::ClearAll {
            cell: dmg_cell("x"),
        }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadCell { op: 0 }));
        // empty text is not the canonical blank either.
        let f = dmg_frame(vec![DamageOp::ClearAll { cell: dmg_cell("") }]);
        assert_eq!(f.validate(), Err(DamageInvalid::BadCell { op: 0 }));
        // width 1, " " is accepted.
        let f = dmg_frame(vec![DamageOp::ClearAll {
            cell: dmg_cell(" "),
        }]);
        assert_eq!(f.validate(), Ok(()));
    }

    #[test]
    fn cell_text_over_cap_rejected_mid_parse() {
        // A RowSpan cell whose text is one byte over the cap fails to deserialize.
        let mut c = dmg_cell("a");
        c.text = "a".repeat(MAX_CELL_TEXT_BYTES + 1);
        let f = dmg_frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 0,
            cells: vec![c],
        }]);
        let json = serde_json::to_string(&f).unwrap();
        assert!(serde_json::from_str::<DamageFrame>(&json).is_err());
        // Exactly at the cap deserializes fine.
        let mut c = dmg_cell("a");
        c.text = "a".repeat(MAX_CELL_TEXT_BYTES);
        let f = dmg_frame(vec![DamageOp::RowSpan {
            row: 0,
            start: 0,
            cells: vec![c],
        }]);
        let json = serde_json::to_string(&f).unwrap();
        assert!(serde_json::from_str::<DamageFrame>(&json).is_ok());
    }

    /// Build a syntactically valid `damage` event line whose total byte length is
    /// EXACTLY `target`, padded via the `id` field (a plain quoted string: each added
    /// ASCII char grows the JSON by exactly one byte). The result is real, parseable
    /// JSON whose `ev` is "damage", so the discriminator path is exercised — not a
    /// substring hack. `target` must be large enough to hold the minimal line.
    fn damage_line_of_len(target: usize) -> String {
        // Measure the line with an empty id to learn the fixed overhead.
        let mut f = dmg_frame(vec![DamageOp::ClearAll {
            cell: dmg_cell(" "),
        }]);
        f.id = String::new();
        let base_len = serde_json::to_string(&DaemonEvent::Damage { frame: f })
            .unwrap()
            .len();
        assert!(
            target >= base_len,
            "target {target} below minimal {base_len}"
        );
        let id = "a".repeat(target - base_len);
        let mut f = dmg_frame(vec![DamageOp::ClearAll {
            cell: dmg_cell(" "),
        }]);
        f.id = id;
        let line = serde_json::to_string(&DaemonEvent::Damage { frame: f }).unwrap();
        assert_eq!(line.len(), target, "padding math off");
        line
    }

    #[test]
    fn decode_event_rejects_damage_over_byte_cap() {
        // One byte over MAX_DAMAGE_BYTES: rejected at the framing layer (DamageTooLarge)
        // WITHOUT a full typed parse.
        let line = damage_line_of_len(MAX_DAMAGE_BYTES + 1);
        assert!(line.len() > MAX_DAMAGE_BYTES);
        match decode_event(&line) {
            Err(DecodeError::DamageTooLarge { bytes }) => assert_eq!(bytes, line.len()),
            other => panic!("expected DamageTooLarge, got {other:?}"),
        }
    }

    #[test]
    fn decode_event_accepts_damage_at_byte_cap() {
        // Exactly at the cap: NOT rejected by the byte gate; full parse proceeds.
        let line = damage_line_of_len(MAX_DAMAGE_BYTES);
        assert_eq!(line.len(), MAX_DAMAGE_BYTES);
        match decode_event(&line) {
            Ok(DaemonEvent::Damage { .. }) => {}
            other => panic!("expected Ok(Damage) at the cap, got {other:?}"),
        }
    }

    #[test]
    fn decode_event_byte_cap_only_applies_to_damage() {
        // A non-damage event larger than MAX_DAMAGE_BYTES is NOT rejected by the damage
        // gate (only MAX_LINE_BYTES bounds it, enforced earlier in the read loop). Use a
        // large Output event.
        let big_data = "x".repeat(MAX_DAMAGE_BYTES + 10);
        let ev = DaemonEvent::Output {
            id: "s1".into(),
            generation: Some(SessionGeneration(
                "11111111-1111-1111-1111-111111111111".into(),
            )),
            revision: Revision(1),
            data: big_data,
        };
        let line = serde_json::to_string(&ev).unwrap();
        assert!(line.len() > MAX_DAMAGE_BYTES);
        // Not DamageTooLarge — it decodes as a normal (large) event.
        assert!(matches!(
            decode_event(&line),
            Ok(DaemonEvent::Output { .. })
        ));
    }

    #[test]
    fn decode_event_bad_envelope_is_reported() {
        assert!(matches!(
            decode_event("not json"),
            Err(DecodeError::BadEnvelope)
        ));
        // Valid JSON but missing the `ev` tag.
        assert!(matches!(
            decode_event(r#"{"foo":1}"#),
            Err(DecodeError::BadEnvelope)
        ));
    }

    // --- Scrollback protocol mirror tests ----------------------------------

    #[test]
    fn scrollback_request_round_trips_through_json() {
        let req = ClientRequest::Scrollback {
            id: "s1".into(),
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
                assert_eq!(id, "s1");
                assert_eq!(offset_from_top, 42);
                assert_eq!(count, 24);
            }
            other => panic!("expected Scrollback, got {other:?}"),
        }
    }

    #[test]
    fn scrollback_rows_event_round_trips_with_ev_tag() {
        let ev = DaemonEvent::ScrollbackRows {
            id: "s1".into(),
            row_copy: None,
            generation: SessionGeneration("11111111-1111-1111-1111-111111111111".into()),
            revision: Revision(99),
            history_len: 5000,
            offset_from_top: 10,
            rows: vec![vec![dmg_cell("a"), dmg_cell("b")]],
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
                assert_eq!(id, "s1");
                assert_eq!(revision, Revision(99));
                assert_eq!(history_len, 5000);
                assert_eq!(offset_from_top, 10);
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].len(), 2);
            }
            other => panic!("expected ScrollbackRows, got {other:?}"),
        }
    }

    /// `ScrollbackRows::rows` uses the SAME `Cell` shape as `GridSnapshot::rows_cells`:
    /// a cell serialized for a grid row appears verbatim inside a scrollback reply.
    #[test]
    fn scrollback_rows_use_same_cell_shape_as_grid() {
        let c = dmg_cell("x");
        let grid_cell_json = serde_json::to_string(&c).unwrap();
        let ev = DaemonEvent::ScrollbackRows {
            id: "s1".into(),
            row_copy: None,
            generation: SessionGeneration("11111111-1111-1111-1111-111111111111".into()),
            revision: Revision(1),
            history_len: 1,
            offset_from_top: 0,
            rows: vec![vec![c.clone()]],
        };
        let line = serde_json::to_string(&ev).unwrap();
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

    /// Byte-identical to the daemon's `CROSS_WIRE_SCROLLBACK_JSON` (protocol.rs). The
    /// daemon test proves it emits exactly these bytes; this test proves they decode in
    /// the renderer mirror. Keep the two literals in lockstep.
    const CROSS_WIRE_SCROLLBACK_JSON: &str = r#"{"ev":"scrollback_rows","id":"s1","generation":"11111111-1111-1111-1111-111111111111","revision":7,"history_len":5000,"offset_from_top":3,"rows":[[{"text":"a","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"hyperlink":"https://scrollback.example.test/a","width":1}]]}"#;

    #[test]
    fn cross_wire_scrollback_decodes_in_renderer_mirror() {
        let ev: DaemonEvent = serde_json::from_str(CROSS_WIRE_SCROLLBACK_JSON)
            .expect("daemon scrollback JSON decodes in mirror");
        match ev {
            DaemonEvent::ScrollbackRows {
                id,
                generation,
                revision,
                history_len,
                offset_from_top,
                rows,
                ..
            } => {
                assert_eq!(id, "s1");
                assert_eq!(
                    generation,
                    SessionGeneration("11111111-1111-1111-1111-111111111111".into())
                );
                assert_eq!(revision, Revision(7));
                assert_eq!(history_len, 5000);
                assert_eq!(offset_from_top, 3);
                assert_eq!(rows.len(), 1);
                assert_eq!(rows[0].len(), 1);
                assert_eq!(rows[0][0].text, "a");
                assert_eq!(
                    rows[0][0].hyperlink.as_deref(),
                    Some("https://scrollback.example.test/a")
                );
            }
            other => panic!("expected ScrollbackRows, got {other:?}"),
        }
    }

    /// Re-serializing the canonical literal reproduces it byte-for-byte in the renderer
    /// mirror — pinning the renderer's serde shape to the same bytes the daemon emits.
    #[test]
    fn cross_wire_scrollback_reserializes_canonically() {
        let ev: DaemonEvent = serde_json::from_str(CROSS_WIRE_SCROLLBACK_JSON).unwrap();
        let reser = serde_json::to_string(&ev).unwrap();
        assert_eq!(reser, CROSS_WIRE_SCROLLBACK_JSON);
    }

    /// Byte-identical to the daemon's `CROSS_WIRE_GRID_JSON` (protocol.rs). The daemon test
    /// proves it emits exactly these bytes; this test proves they decode in the renderer
    /// mirror. `Grid` is the attach/resync baseline payload — if the mirror's `GridSnapshot`
    /// shape ever drifts from the daemon's (renamed/added/reordered field), decoding here
    /// fails and the product would be dead-on-attach. Keep the two literals in lockstep.
    const CROSS_WIRE_GRID_JSON: &str = r#"{"ev":"grid","id":"s1","grid":{"version":2,"generation":"11111111-1111-1111-1111-111111111111","revision":5,"base_revision":4,"cols":3,"rows":1,"rows_cells":[[{"text":"界","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":2},{"text":"","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"width":0},{"text":"x","fg":{"kind":"named","name":"foreground"},"bg":{"kind":"named","name":"background"},"bold":false,"italic":false,"underline":"none","inverse":false,"strikeout":false,"dim":false,"hidden":false,"hyperlink":"https://grid.example.test/x","width":1}]],"cursor_line":0,"cursor_col":2,"cursor_visible":true,"cursor_shape":"beam","alt_screen":true,"app_cursor":true,"bracketed_paste":true,"focus_reporting":true,"mouse_report":true,"mouse_drag":true,"mouse_motion":true,"mouse_sgr":true}}"#;

    #[test]
    fn row_copy_cross_wire_addition_and_null_absence() {
        for (json, field, rows) in [
            (CROSS_WIRE_GRID_JSON, "grid", 1),
            (CROSS_WIRE_DAMAGE_JSON, "frame", 4),
            (CROSS_WIRE_SCROLLBACK_JSON, "", 1),
        ] {
            let mut value: serde_json::Value = serde_json::from_str(json).unwrap();
            let payload = if field.is_empty() {
                &mut value
            } else {
                &mut value[field]
            };
            payload["row_copy"] = serde_json::json!(vec![
                serde_json::json!({
                "starts_line": false, "soft_wrap": true, "excluded_columns": [] });
                rows
            ]);
            let decoded: DaemonEvent = serde_json::from_value(value.clone()).unwrap();
            assert_eq!(serde_json::to_value(decoded).unwrap(), value);
            let payload = if field.is_empty() {
                &mut value
            } else {
                &mut value[field]
            };
            payload["row_copy"] = serde_json::Value::Null;
            let decoded: DaemonEvent = serde_json::from_value(value).unwrap();
            assert_eq!(serde_json::to_string(&decoded).unwrap(), json);
        }
    }

    #[test]
    fn cross_wire_grid_decodes_in_renderer_mirror() {
        let ev: DaemonEvent =
            serde_json::from_str(CROSS_WIRE_GRID_JSON).expect("daemon grid JSON decodes in mirror");
        match ev {
            DaemonEvent::Grid { id, grid } => {
                // Every GridSnapshot wire field survives decode in the renderer mirror.
                assert_eq!(id, "s1");
                assert_eq!(grid.version, 2);
                assert_eq!(
                    grid.generation,
                    SessionGeneration("11111111-1111-1111-1111-111111111111".into())
                );
                assert_eq!(grid.revision, Revision(5));
                assert_eq!(grid.base_revision, Revision(4));
                assert_eq!(grid.cols, 3);
                assert_eq!(grid.rows, 1);
                assert_eq!(grid.rows_cells.len(), 1);
                assert_eq!(grid.rows_cells[0].len(), 3);
                // Wide pair survives the wire: width-2 lead followed by width-0 spacer.
                assert_eq!(grid.rows_cells[0][0].width, 2);
                assert_eq!(grid.rows_cells[0][1].width, 0);
                assert_eq!(
                    grid.rows_cells[0][2].hyperlink.as_deref(),
                    Some("https://grid.example.test/x")
                );
                assert_eq!(grid.cursor_line, 0);
                assert_eq!(grid.cursor_col, 2);
                assert!(grid.cursor_visible);
                // Non-default cursor shape must survive (guards CursorShape drift).
                assert_eq!(grid.cursor_shape, CursorShape::Beam);
                // All mode + mouse flags are `true` on the wire, so a renamed/dropped field
                // that fell back to its `#[serde(default)]` `false` would fail here. This is
                // the guard against silent daemon/renderer mouse-mode drift.
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

    /// Re-serializing the canonical Grid literal reproduces it byte-for-byte in the renderer
    /// mirror — pinning the mirror's `GridSnapshot` field order/shape to the daemon's bytes.
    /// (The mirror's `base_revision`/mouse fields are `#[serde(default)]`, but their
    /// declaration order still matches the daemon, so reserialize stays byte-identical.)
    #[test]
    fn cross_wire_grid_reserializes_canonically() {
        let ev: DaemonEvent = serde_json::from_str(CROSS_WIRE_GRID_JSON).unwrap();
        let reser = serde_json::to_string(&ev).unwrap();
        assert_eq!(reser, CROSS_WIRE_GRID_JSON);
    }
}
