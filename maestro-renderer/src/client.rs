//! Socket client. Runs on a background thread: connects to the daemon's Unix
//! socket, sends Attach, then reads newline-delimited JSON events. The latest
//! `GridSnapshot` is published into shared state for the UI thread to paint.
//!
//! The client is event-driven: after a validated state change it wakes
//! the OWNER event loop via the platform-neutral [`UserEventSender`] (the winit
//! proxy on macOS, the Tao/GTK proxy on Linux) instead of the UI thread polling
//! on a timer. The reader thread issues snapshot requests only for live output
//! (an Output revision advance) and resync — never on a periodic clock.

use crate::host_event::{HostKey, HostModifiers, HostNamedKey};
use crate::sync::{Action, DamageOutcome, SyncState};
use crate::wire::{
    decode_event, Cell, ClientRequest, CursorShape, DaemonEvent, DecodeError, GridSnapshot,
    Revision, SessionGeneration, MAX_LINE_BYTES,
};
use crate::{UserEvent, UserEventSender};
use std::collections::{BTreeMap, HashMap, VecDeque};
use std::io::{BufRead, BufReader, Read, Write};
use std::os::unix::net::UnixStream;
use std::sync::{Arc, Condvar, Mutex};
use std::time::Instant;

/// Hard cap on the outbound queue's buffered bytes. The daemon's socket can stall
/// (a busy daemon, a slow consumer); rather than let the UI thread block on a raw
/// `write_all` syscall under the paint path, requests are enqueued here and a
/// dedicated writer thread drains them in order. 1 MiB is generous for control
/// frames + a capped paste; reaching it means the daemon is badly wedged.
pub const OUTBOUND_CAP_BYTES: usize = 1024 * 1024;

/// A serialized, byte-bounded outbound queue draining to one writer thread.
///
/// ORDER: strict FIFO — the daemon's protocol is order-sensitive (Attach must
/// precede the Snapshots/Writes that depend on it), so requests are dequeued in
/// the exact order they were enqueued. A single writer thread owns the socket, so
/// no two writers can interleave bytes at the kernel.
///
/// OVERLOAD: when buffered bytes would exceed [`OUTBOUND_CAP_BYTES`] the producer
/// BLOCKS (backpressure) until the writer drains enough room — we do NOT silently
/// drop Write/Attach/Snapshot/Resize. NOTE that one producer is the winit UI
/// thread (Write/Resize), so a wedged daemon can momentarily stall the UI thread
/// here; the current overload policy deliberately blocks rather than dropping input —
/// see [`Shared::send_request`]. The one safety valve: a single oversized item (larger
/// than the whole cap, e.g. a giant paste) is still admitted once the queue is
/// otherwise empty, so a legitimate large request can never deadlock. Resize
/// floods don't reach here — the UI coalesces them upstream ([`ResizeCoalescer`])
/// so only the settled geometry is ever enqueued.
struct OutboundQueue {
    inner: Mutex<OutboundInner>,
    /// Signalled when the writer drains an item (room freed) or `closed` flips.
    space: Condvar,
    /// Signalled when an item is enqueued (work available) or `closed` flips.
    work: Condvar,
}

struct OutboundInner {
    queue: VecDeque<Vec<u8>>,
    bytes: usize,
    /// Set when the socket is gone; producers stop blocking and return.
    closed: bool,
}

impl OutboundQueue {
    fn new() -> Self {
        OutboundQueue {
            inner: Mutex::new(OutboundInner {
                queue: VecDeque::new(),
                bytes: 0,
                closed: false,
            }),
            space: Condvar::new(),
            work: Condvar::new(),
        }
    }

    /// Enqueue one already-framed line (JSON + '\n'), blocking if the queue is at
    /// capacity until room frees. Never drops. Returns `false` only if the queue
    /// was closed (socket gone) before the item could be admitted.
    fn enqueue(&self, line: Vec<u8>) -> bool {
        let len = line.len();
        let mut inner = self.inner.lock().unwrap();
        // Block while admitting would overflow the cap — UNLESS the queue is empty,
        // in which case we admit the item regardless of its size so an oversized
        // request (bigger than the whole cap) can still make progress.
        while !inner.closed && inner.bytes + len > OUTBOUND_CAP_BYTES && !inner.queue.is_empty() {
            inner = self.space.wait(inner).unwrap();
        }
        if inner.closed {
            return false;
        }
        inner.queue.push_back(line);
        inner.bytes += len;
        self.work.notify_one();
        true
    }

    /// Block until an item is available, then pop it (FIFO). Returns `None` when
    /// the queue is closed AND drained — the writer thread then exits.
    fn dequeue(&self) -> Option<Vec<u8>> {
        let mut inner = self.inner.lock().unwrap();
        loop {
            if let Some(item) = inner.queue.pop_front() {
                inner.bytes -= item.len();
                // Room freed — wake any producer blocked on the cap.
                self.space.notify_all();
                return Some(item);
            }
            if inner.closed {
                return None;
            }
            inner = self.work.wait(inner).unwrap();
        }
    }

    /// Mark closed and wake everyone so producers/writer unblock and exit.
    fn close(&self) {
        let mut inner = self.inner.lock().unwrap();
        inner.closed = true;
        self.space.notify_all();
        self.work.notify_all();
    }

    /// Number of frames currently queued (not yet drained by the writer). Test-only:
    /// lets a unit test assert that a code path enqueued exactly N requests without
    /// spinning up the writer thread / socket.
    #[cfg(test)]
    fn len(&self) -> usize {
        self.inner.lock().unwrap().queue.len()
    }

    /// Pop every queued line and parse each back into a [`ClientRequest`], FIFO. Test-only: lets a
    /// unit test assert the exact requests a `send_request`-driven code path enqueued.
    #[cfg(test)]
    fn drain_requests(&self) -> Vec<ClientRequest> {
        let mut inner = self.inner.lock().unwrap();
        let lines: Vec<Vec<u8>> = inner.queue.drain(..).collect();
        inner.bytes = 0;
        lines
            .iter()
            .map(|l| serde_json::from_slice(l).expect("framed line parses as ClientRequest"))
            .collect()
    }
}

/// Renderer-owned scrollback VIEW state. The daemon is stateless about
/// the viewport — it pins its live grid at the bottom and only answers read-only
/// `Scrollback` queries. This struct is the renderer's entire notion of "where the
/// user has scrolled to". Touched by BOTH threads: the UI thread writes `view_offset`
/// on wheel/key and reads `historical` in `draw`; the reader thread writes
/// `historical`/`history_len` when a `ScrollbackRows` reply arrives. Hence the Mutex.
#[derive(Default)]
pub struct ScrollbackState {
    /// How far the viewport is scrolled UP from the live bottom, in rows. `0` means
    /// "live" (paint `Shared.grid` exactly as before). `> 0` means paint `historical`.
    /// Normally clamped to the last-known `history_len`. An explicit upward gesture at
    /// that cached ceiling may move provisionally by at most one page so the daemon can
    /// report a newer depth after live output grows history.
    pub view_offset: u32,
    /// Total history length, IF known. `None` until the first `ScrollbackRows` reply —
    /// distinct from `Some(0)` ("there was no history at the last reply"). The
    /// distinction matters at bootstrap: the very first wheel/PageUp from the live
    /// bottom happens BEFORE any reply, so `history_len` is `None` and we must still send one
    /// provisional `Scrollback` request to learn the real length.
    pub history_len: Option<u32>,
    /// The synthetic snapshot built from the latest `ScrollbackRows` window, ready to
    /// paint through the SAME render path as a live grid. `None` until a reply arrives
    /// (or after returning to live, where it is cleared).
    pub historical: Option<Arc<GridSnapshot>>,
    /// The live grid generation the `historical` rows belong to. A `ScrollbackRows`
    /// for a different (older/newer) generation than the live grid is stale and ignored.
    pub historical_generation: Option<SessionGeneration>,
}

impl ScrollbackState {
    /// Are we currently showing history (vs. the live bottom)?
    pub fn is_scrolled(&self) -> bool {
        self.view_offset > 0
    }

    /// Snap back to the live bottom and drop the cached historical window.
    pub fn reset_to_live(&mut self) {
        self.view_offset = 0;
        self.historical = None;
        self.historical_generation = None;
    }
}

/// A primary/alternate screen transition invalidates any renderer-owned historical viewport.
/// Initial publication has no previous screen to invalidate; ordinary damage on the same screen
/// must preserve the user's current normal-screen history position.
fn reset_scrollback_for_screen_transition(
    previous_alt_screen: Option<bool>,
    next_alt_screen: bool,
    scrollback: &mut ScrollbackState,
) -> bool {
    if previous_alt_screen.is_some_and(|previous| previous != next_alt_screen) {
        scrollback.reset_to_live();
        true
    } else {
        false
    }
}

/// Clamp a desired view offset against the KNOWN history length, if any.
/// - `Some(n)`: clamp into `[0, n]` (the authoritative bound the daemon also enforces).
/// - `None` (length not yet known): clamp into `[0, provisional_cap]`. This lets the
///   first scroll-up from the bottom move to a provisional offset and fire one request
///   to learn the real length, without overshooting wildly. The reply re-clamps to the
///   true length (and snaps back to live if there is no history at all). A caller deliberately
///   re-probing a last-known ceiling passes `None` with a cap extending from its current offset.
pub fn clamp_view_offset(desired: i64, history_len: Option<u32>, provisional_cap: u32) -> u32 {
    let ceiling = match history_len {
        Some(n) => n as i64,
        None => provisional_cap as i64,
    };
    desired.clamp(0, ceiling) as u32
}

/// Build the overlay scroll indicator from the current view state. Returns `None` at the
/// live bottom (offset 0) so the overlay shows nothing extra. When scrolled we always show
/// the offset; the depth (`/N`) and percent are appended ONLY when the history length is
/// known and positive (`Some(n>0)`) — before the first reply (`None`) or with no history
/// (`Some(0)`) we cannot honestly compute a fraction, so we show the bare offset. Percent
/// is `round(offset / n * 100)` clamped to `[0, 100]` (offset is already clamped to `n` by
/// `clamp_view_offset`, so this is belt-and-suspenders). Pure, unit-tested.
pub fn scroll_indicator_label(view_offset: u32, history_len: Option<u32>) -> Option<String> {
    if view_offset == 0 {
        return None;
    }
    match history_len {
        Some(n) if n > 0 => {
            let pct = ((view_offset as f64 / n as f64) * 100.0).round() as i64;
            let pct = pct.clamp(0, 100);
            Some(format!("[scroll {view_offset}/{n} {pct}%]"))
        }
        _ => Some(format!("[scroll +{view_offset}]")),
    }
}

/// A user-initiated viewport movement. Positive deltas scroll UP into history; the
/// page/home/end variants are resolved against the visible row count and history length.
/// These are VIEW actions only — never PTY input (mouse reporting is out of scope).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollAction {
    /// Move by `rows` lines: positive = up into history, negative = down toward live.
    Lines(i64),
    /// One visible page up (into history).
    PageUp,
    /// One visible page down (toward live).
    PageDown,
    /// Jump to the oldest available history (top).
    Home,
    /// Jump to the live bottom.
    End,
}

/// Resolve a `ScrollAction` against the current offset into a new clamped offset.
/// `page` is the visible row count used for PageUp/PageDown. `history_len` is `None`
/// until the first reply; in that bootstrap case the offset is clamped to one page so a
/// first scroll-up can move (and fire a request) without overshooting. A cached length is
/// point-in-time metadata, so an upward gesture at that ceiling likewise gets one bounded
/// page to re-probe. Pure so it is unit-tested without a window. Alt-screen suppression and
/// request dispatch are handled by the caller; this only does the offset arithmetic.
pub fn next_view_offset(
    current: u32,
    history_len: Option<u32>,
    page: u32,
    action: ScrollAction,
) -> u32 {
    let cur = current as i64;
    let page_i = page.max(1) as i64;
    // `history_len` is authoritative for the reply that supplied it, but it is not an
    // eternal ceiling: live output can add history afterwards.  In particular, caching
    // `Some(0)` must not make a pane permanently unscrollable.  When the user explicitly
    // scrolls UP while already at the last-known ceiling, allow one bounded page of
    // provisional movement so the normal Scrollback request re-probes the daemon.  The
    // reply immediately clamps/echoes the real current depth.  Downward movement keeps
    // using the known bound and can never probe away from the live bottom.
    let moves_up = match action {
        ScrollAction::Lines(delta) => delta > 0,
        ScrollAction::PageUp | ScrollAction::Home => true,
        ScrollAction::PageDown | ScrollAction::End => false,
    };
    let probes_above_cached_ceiling = moves_up && history_len.is_some_and(|known| current >= known);
    let effective_history_len = if probes_above_cached_ceiling {
        None
    } else {
        history_len
    };
    let desired = match action {
        ScrollAction::Lines(d) => cur + d,
        ScrollAction::PageUp => cur + page_i,
        ScrollAction::PageDown => cur - page_i,
        // Home jumps to the oldest line; when length is unknown, clamping pins it to the
        // provisional cap so we move up and learn the real length from the reply.
        ScrollAction::Home => effective_history_len.map(|n| n as i64).unwrap_or(i64::MAX),
        ScrollAction::End => 0,
    };
    // If a previously-known ceiling became stale while already scrolled, the provisional
    // cap must extend FROM the current offset rather than snap back to the first page.
    let provisional_cap = current.saturating_add(page.max(1));
    clamp_view_offset(desired, effective_history_len, provisional_cap)
}

/// Pixels of trackpad/precision scroll that equal one line step. macOS delivers a
/// stream of small `PixelDelta` events (often 1–10px each) during a normal scroll;
/// converting each one independently and rounding loses every sub-threshold event,
/// so a gentle scroll never moves at all. We instead accumulate pixels and emit whole
/// line steps as the total crosses each multiple, retaining the remainder.
pub const WHEEL_PIXELS_PER_LINE: f64 = 16.0;

/// Accumulates fractional wheel/trackpad scroll into whole line steps without losing
/// sub-line motion between events. `add_lines` (mouse wheels, already in line units)
/// and `add_pixels` (trackpads, in pixels) both feed the same residue, so a slow
/// trackpad scroll eventually crosses a line boundary instead of rounding to zero on
/// every event. Pure and window-free so it is unit-testable.
///
/// Sign convention matches `ScrollAction::Lines`: positive = up into history (which is
/// winit's "positive y reveals content above"), negative = down toward live.
#[derive(Debug, Default, Clone)]
pub struct WheelAccumulator {
    residue: f64,
}

impl WheelAccumulator {
    /// Feed a `LineDelta` y (already in line units). Returns the whole line steps to
    /// apply now (sign = direction), carrying any fraction forward.
    pub fn add_lines(&mut self, lines: f64) -> i64 {
        self.residue += lines;
        self.take_whole()
    }

    /// Feed a `PixelDelta` y (in pixels). Returns the whole line steps to apply now,
    /// carrying the sub-line remainder forward so consecutive small events accumulate.
    pub fn add_pixels(&mut self, pixels: f64) -> i64 {
        self.residue += pixels / WHEEL_PIXELS_PER_LINE;
        self.take_whole()
    }

    /// Extract the integer part of the residue toward zero, leaving the fraction.
    fn take_whole(&mut self) -> i64 {
        let whole = self.residue.trunc();
        self.residue -= whole;
        whole as i64
    }
}

/// Maximum number of terminal or renderer line steps one host wheel event may produce.
/// Precision trackpads can occasionally deliver a large momentum delta; bounding it keeps
/// alternate-screen key fallback and normal scrollback work proportional per event while the
/// remaining gesture events continue to arrive normally.
pub const MAX_WHEEL_STEPS_PER_EVENT: i64 = 16;

/// One resolved wheel action after fractional deltas have accumulated into whole lines.
///
/// This is the single policy boundary for wheel routing:
///
/// - negotiated terminal mouse reporting wins;
/// - an alternate-screen application without mouse reporting receives conventional Up/Down
///   cursor-key input;
/// - a normal-screen pane moves the renderer-owned scrollback viewport;
/// - a sub-line gesture that has not accumulated to one line is a no-op.
///
/// The route carries an already bounded step count so no platform adapter or caller can drift on
/// direction or caps.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WheelRoute {
    NoOp,
    MouseReport { event: MouseEvent, steps: u8 },
    AlternateScroll { key: HostNamedKey, steps: u8 },
    RendererScroll(ScrollAction),
}

/// Resolve whole wheel lines into exactly one bounded route. Positive lines mean scrolling up;
/// negative lines mean scrolling down. Mouse reporting takes precedence even on the alternate
/// screen, matching xterm-compatible applications that explicitly opted into wheel reports.
pub fn wheel_route(lines: i64, alt_screen: bool, mouse_reporting: bool) -> WheelRoute {
    let lines = lines.clamp(-MAX_WHEEL_STEPS_PER_EVENT, MAX_WHEEL_STEPS_PER_EVENT);
    if lines == 0 {
        return WheelRoute::NoOp;
    }
    let steps = lines.unsigned_abs() as u8;
    if mouse_reporting {
        return WheelRoute::MouseReport {
            event: if lines > 0 {
                MouseEvent::WheelUp
            } else {
                MouseEvent::WheelDown
            },
            steps,
        };
    }
    if alt_screen {
        return WheelRoute::AlternateScroll {
            key: if lines > 0 {
                HostNamedKey::ArrowUp
            } else {
                HostNamedKey::ArrowDown
            },
            steps,
        };
    }
    WheelRoute::RendererScroll(ScrollAction::Lines(lines))
}

/// The four navigation keys that may drive renderer scrollback. The caller maps a
/// winit `NamedKey` to this so the policy below is pure and unit-testable without a
/// window or a winit key event.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ScrollKey {
    PageUp,
    PageDown,
    Home,
    End,
}

/// Decide whether a navigation key is consumed as a renderer-scrollback VIEW action,
/// or `None` if it must pass through to the PTY. This is the single source of truth
/// for the PageUp/PageDown/Home/End policy:
///
/// - **alt-screen (TUI):** always `None`. Full-screen apps own paging; the renderer
///   must never intercept these keys, so they reach the PTY unmodified.
/// - **normal + scrolled up:** all four control the scrollback viewport.
/// - **normal + live bottom:** only PageUp enters scrollback (there is history above);
///   PageDown/Home/End have nothing to scroll into and belong to the shell/pager, so
///   they pass to the PTY.
/// - any modifier held (Ctrl/Alt/Super/Shift): `None` — modified chords are out of
///   scope and belong to the application.
///
/// `modified` is true if any of Ctrl/Alt/Super/Shift is held.
pub fn scroll_key_action_for(
    key: ScrollKey,
    alt_screen: bool,
    scrolled: bool,
    modified: bool,
) -> Option<ScrollAction> {
    if alt_screen || modified {
        return None;
    }
    match key {
        ScrollKey::PageUp => Some(ScrollAction::PageUp),
        ScrollKey::PageDown if scrolled => Some(ScrollAction::PageDown),
        ScrollKey::Home if scrolled => Some(ScrollAction::Home),
        ScrollKey::End if scrolled => Some(ScrollAction::End),
        // At the live bottom, PageDown/Home/End have nothing to scroll into -> PTY.
        ScrollKey::PageDown | ScrollKey::Home | ScrollKey::End => None,
    }
}

/// Build a SYNTHETIC `GridSnapshot` from a `ScrollbackRows` window so historical rows
/// flow through the exact same `render()` path as a live grid. The rows already use the
/// identical `Cell` shape; we only wrap them with grid geometry and a hidden cursor
/// (history has no live cursor). This snapshot is NEVER fed to `SyncState` — it is a
/// display artifact, not part of the authoritative generation/revision timeline. We carry
/// the source `generation`/`revision` purely so the overlay can show them and so a stale
/// window (wrong generation) can be rejected by the caller before this is built.
fn scrollback_snapshot(
    generation: SessionGeneration,
    revision: Revision,
    rows: Vec<Vec<Cell>>,
) -> GridSnapshot {
    let row_count = rows.len();
    let cols = rows.first().map(|r| r.len()).unwrap_or(0);
    GridSnapshot {
        version: crate::sync::SUPPORTED_VERSION,
        generation,
        revision,
        base_revision: revision,
        cols,
        rows: row_count,
        rows_cells: rows,
        // History is read-only: no cursor is drawn while scrolled up.
        cursor_line: 0,
        cursor_col: 0,
        cursor_visible: false,
        cursor_shape: CursorShape::Block,
        // A scrollback window is, by construction, primary-screen history — never the
        // alternate screen (alt-screen disables scrollback). Input modes are irrelevant
        // to painting and never read from a historical snapshot.
        alt_screen: false,
        app_cursor: false,
        bracketed_paste: false,
        focus_reporting: false,
        // Historical rows are read-only: mouse reporting is never active over a scrollback
        // view (the live grid owns input modes); a click in history is local selection only.
        mouse_report: false,
        mouse_drag: false,
        mouse_motion: false,
        mouse_sgr: false,
    }
}

/// Accept-or-reject a `ScrollbackRows` reply and fold it into `Shared.scrollback`.
/// Pure of any event loop so it is unit-testable. Returns `true` if the renderer should
/// repaint (the caller wakes the UI). Reject rules, in order:
///
/// - wrong session id -> ignore (false);
/// - generation no longer matches the live grid (re-baselined since we asked), or no
///   live grid yet -> stale, ignore (false);
/// - user has already returned to the live bottom -> record `history_len` only and do
///   NOT resurrect a historical view; still repaint so the overlay's history is fresh.
///
/// On accept we echo the daemon's actually-served offset (it may have clamped ours).
#[allow(clippy::too_many_arguments)]
fn apply_scrollback_rows(
    shared: &Arc<Shared>,
    session_id: &str,
    id: &str,
    generation: SessionGeneration,
    revision: Revision,
    history_len: u32,
    offset_from_top: u32,
    rows: Vec<Vec<Cell>>,
) -> bool {
    if id != session_id {
        return false;
    }
    let live_generation = shared
        .grid
        .lock()
        .unwrap()
        .as_ref()
        .map(|g| g.generation.clone());
    let mut sb = shared.scrollback.lock().unwrap();
    apply_scrollback_payload(
        live_generation,
        &mut sb,
        generation,
        revision,
        history_len,
        offset_from_top,
        rows,
    )
}

fn apply_scrollback_payload(
    live_generation: Option<SessionGeneration>,
    sb: &mut ScrollbackState,
    generation: SessionGeneration,
    revision: Revision,
    history_len: u32,
    offset_from_top: u32,
    rows: Vec<Vec<Cell>>,
) -> bool {
    if live_generation.as_ref() != Some(&generation) {
        return false;
    }
    let snap = Arc::new(scrollback_snapshot(generation.clone(), revision, rows));
    // We now KNOW the history length (distinct from the `None` bootstrap state).
    sb.history_len = Some(history_len);
    // No history at all (the bootstrap request found an empty scrollback): snap back to
    // the live bottom so a provisional offset can't strand us in scrolled mode.
    if history_len == 0 {
        sb.reset_to_live();
        return true;
    }
    if sb.is_scrolled() {
        // Echo the daemon's actually-served offset, re-clamped to the now-known length.
        sb.view_offset = clamp_view_offset(offset_from_top as i64, Some(history_len), history_len);
        sb.historical = Some(snap);
        sb.historical_generation = Some(generation);
    }
    true
}

/// The renderer's CURRENT active session, shared between the UI thread (which
/// rebinds it on a tab switch) and the reader thread (which filters every event
/// against it). `epoch` bumps on each rebind so the reader can detect a switch and
/// rebuild its `SyncState` for the new id, even though it captured the original id
/// in a thread-local. The id is the single source of truth for "whose events do we
/// honor"; the reader copies it into its `SyncState` and its own filter on each bump.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct ActiveSession {
    pub id: String,
    pub epoch: u64,
}

/// The renderer's cache of the ONE inactive split-pane sibling session, kept entirely
/// separate from the active session ([`Shared::active`]/[`Shared::grid`]). The sibling is attached
/// and cached without receiving input; this passive store is filled by
/// [`Shared::sync_sibling_session`] and updated by its reader path.
///
/// Uniform per-session store. Every non-active session id — the rendered
/// split sibling AND every extra non-active pane of a three-or-more-pane layout — gets one
/// `PaneStore` keyed by its session id in [`Shared::stores`]. This replaces the two formerly
/// separate stores (`SiblingSession` and the `PaneCaches` map): both are now the SAME shape
/// with the SAME capabilities, distinguished only by the [`PaneStore::kind`] tag so the
/// sibling-binding ops and the multi-pane membership reconcile each touch only their own
/// entries.
///
/// `epoch` increments every time this id is (re)bound (sibling rebind / pane re-add) so a late
/// grid/exit stamped with a stale epoch is dropped instead of overwriting the current binding.
/// `scrollback` is carried for uniformity and owns the viewport state for this session.
#[derive(Default)]
pub struct PaneStore {
    /// Whether this entry is the rendered split sibling or one of the extra cached panes. Lets
    /// `set_sibling_session`/`clear_sibling_session` and `set_pane_sessions`/`clear_pane_sessions`
    /// operate on disjoint subsets of the one map without clobbering each other's entries.
    pub kind: PaneKind,
    /// Bumped whenever this id is (re)bound, so a frame stamped with a stale epoch is dropped.
    pub epoch: u64,
    /// The session's latest accepted grid, or `None` until its first frame (or after a rebind).
    pub grid: Option<Arc<GridSnapshot>>,
    /// `Some(code)` once this session's process exits; `None` while it is live.
    pub exited: Option<Option<i32>>,
    /// Renderer-owned scrollback view state, read by the uniform pane paint path.
    pub scrollback: ScrollbackState,
}

/// Which class of session a [`PaneStore`] entry represents in the unified [`Shared::stores`]
/// map. The two binding surfaces (the single rendered sibling vs. the N-pane membership set)
/// each manage only entries of their own kind, so collapsing them into one map cannot let a
/// pane reconcile evict the sibling (or vice versa).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PaneKind {
    /// One of the extra non-active panes (membership-managed via `set_pane_sessions`).
    #[default]
    Pane,
    /// The single rendered split sibling (bound via `set_sibling_session`).
    Sibling,
}

/// Snapshot of the rendered sibling, returned by [`Shared::sibling_snapshot`]. Mirrors the
/// fields the UI/reader read from the sibling entry of the unified store. `id` is the currently
/// bound sibling id (the [`Shared::sibling_id`] pointer), or `None` when there is no split.
#[derive(Clone, Default)]
pub struct SiblingSession {
    /// The session id currently bound to the inactive pane, or `None` when there is no split.
    pub id: Option<String>,
    /// The sibling entry's rebind epoch (0 when unbound).
    pub epoch: u64,
    /// The sibling's latest accepted grid, or `None` until its first frame (or after a rebind).
    pub grid: Option<Arc<GridSnapshot>>,
    /// `Some(code)` once the sibling session process exits; `None` while it is live.
    pub exited: Option<Option<i32>>,
}

/// A pane's painting snapshot read from the cache: its latest `(grid, exited)` — `grid` is `None`
/// until baselined; `exited` is `Some(code)` once the session exited. Returned by
/// [`Shared::pane_snapshot`] for the render path to paint a cached pane or a pending/exited
/// placeholder.
#[cfg(test)]
pub type PaneSnapshot = (Option<Arc<GridSnapshot>>, Option<Option<i32>>);

/// Uniform per-pane paint resolution, the single source the draw path reads for every
/// visible pane — the primary/focused session AND every other pane — so painting has no privileged
/// "the active grid" special case. Every field is OWNED (the `live`/`historical` grids are `Arc`
/// clones, a refcount bump only), captured under ONE short lock and returned, so the caller holds NO
/// mutex across shaping/GPU submission (see the lock-lifetime contract in `draw`) and the
/// guard-across-statements hazard that blocked moving the active scrollback is gone.
///
/// `live` is the pane's latest accepted live grid (`None` until its first frame). `exited` is
/// `Some(code)` once its process exited. The remaining fields are the pane's OWN scrollback view
/// (`PaneStore::scrollback` for a non-primary pane; the primary's dedicated [`Shared::scrollback`]
/// for the primary), so paint reads the scrollback of the pane being drawn: `scrolled_offset > 0`
/// means paint `historical` (a cut window already fetched for THIS pane) and show the scroll label;
/// `0` means paint `live`.
#[derive(Clone, Default)]
pub struct PanePaint {
    /// The pane's latest accepted LIVE grid, or `None` until its first frame.
    pub live: Option<Arc<GridSnapshot>>,
    /// `Some(code)` once this pane's process exited; `None` while live.
    pub exited: Option<Option<i32>>,
    /// The pane's scrollback offset from the live bottom (0 = live). Drives the paint-source choice.
    pub scrolled_offset: u32,
    /// Known history length for this pane (for the scroll-indicator fraction), if a reply has landed.
    pub history_len: Option<u32>,
    /// The pane's cached historical window to paint while `scrolled_offset > 0`, or `None`.
    pub historical: Option<Arc<GridSnapshot>>,
}

impl PanePaint {
    /// The grid to actually paint for this pane: the historical window while scrolled up (and a cut
    /// has arrived), else the live grid. The same choice is applied uniformly per pane.
    pub fn paint_grid(&self) -> Option<Arc<GridSnapshot>> {
        if self.scrolled_offset > 0 {
            self.historical.clone().or_else(|| self.live.clone())
        } else {
            self.live.clone()
        }
    }

    /// The scroll-indicator label for this pane, or `None` at the live bottom. Pure projection of the
    /// owned offset/length so the caller needs no scrollback lock.
    pub fn scroll_label(&self) -> Option<String> {
        scroll_indicator_label(self.scrolled_offset, self.history_len)
    }
}

/// Shared, lock-protected view the UI thread paints from.
#[derive(Default)]
pub struct Shared {
    /// The session the renderer is CURRENTLY bound to (id + rebind epoch). Written by
    /// the UI thread on a tab switch ([`Shared::set_active_session`]), read by the
    /// reader thread before each event so it rebinds its `SyncState` to a new id and
    /// rejects late frames from the old one. `None`-equivalent is the empty default
    /// (epoch 0, empty id) only for the demo/stress paths that never connect.
    pub active: Mutex<ActiveSession>,
    /// The most recent grid snapshot (None until the first Grid event), stored
    /// behind an `Arc` so the UI thread can clone-and-release under a short lock
    /// and then shape/submit to the GPU without holding the mutex —
    /// the reader thread is never blocked by a slow frame.
    pub grid: Mutex<Option<Arc<GridSnapshot>>>,
    /// Latest revision seen from any Output/Grid event + when we saw it. Retained
    /// for diagnostics/overlay; it does not drive a poll cadence because the renderer is event-driven.
    pub last_revision: Mutex<Option<(Revision, Instant)>>,
    /// Set when the session process exits; carries the exit code.
    pub exited: Mutex<Option<Option<i32>>>,
    /// Renderer-owned scrollback view state. Read by the UI paint path, written
    /// by both the UI (wheel/key) and the reader (ScrollbackRows reply).
    pub scrollback: Mutex<ScrollbackState>,
    /// The bounded outbound queue. ALL requests — the reader thread's
    /// Attach/Snapshot AND the UI thread's Write/Resize — are framed and pushed
    /// here; one dedicated writer thread (spawned in `spawn`) drains them to the
    /// socket in strict order. `None` until the socket connects (and after it
    /// closes); a request enqueued while `None` is a no-op (e.g. the demo scene).
    outbound: Mutex<Option<Arc<OutboundQueue>>>,
    /// Unified per-session store. One map holds a [`PaneStore`] for every non-active
    /// session id: the single rendered split sibling (`kind == Sibling`) AND every extra
    /// non-active pane of a three-or-more-pane layout (`kind == Pane`). Replaces the two
    /// formerly separate stores (`sibling: Mutex<SiblingSession>` + `panes: Mutex<PaneCaches>`)
    /// with one uniform keyed store. Wholly independent of `active`/`grid`/`exited`/`scrollback`
    /// (which remain the live active-session paint path): writing this never disturbs
    /// the active session, and active-session frames never touch it. The reader's former Sibling
    /// and Pane routes both collapse into one keyed lookup of this map.
    pub stores: Mutex<BTreeMap<String, PaneStore>>,
    /// Which id in [`Self::stores`] is the rendered split sibling, or `None` when there is no
    /// split. The pointer half of the sibling binding; the bound entry's grid/exit live in the
    /// map under this id.
    pub sibling_id: Mutex<Option<String>>,
    /// SINGLE monotonic counter for the rendered sibling, preserving the pre-unification
    /// `SiblingSession::epoch` semantics: it bumps on EVERY sibling bind AND clear (even across a
    /// rebind to a brand-new id, where the old map entry is gone), so a late frame from any prior
    /// sibling binding is always rejected by a strictly-greater epoch. Stamped onto the bound
    /// entry's `epoch` so the existing per-entry epoch gate keeps working.
    pub sibling_epoch: Mutex<u64>,
    /// Membership generation for the multi-pane (`kind == Pane`) set, bumped on every membership
    /// change so the reader rebuilds its per-pane `SyncState` map. Independent of the sibling
    /// pointer (which has no generation — it is a single slot).
    pub pane_generation: Mutex<u64>,
}

impl Shared {
    /// Frame `req` as one `json + '\n'` line and push it onto the outbound queue
    /// for the writer thread.
    ///
    /// BLOCKING BEHAVIOR — read this before calling from the UI thread.
    /// This is NOT fully nonblocking. Under normal load the enqueue returns
    /// immediately, but if the queue has reached its byte cap
    /// ([`OUTBOUND_CAP_BYTES`]) — i.e. the daemon's socket is wedged and the
    /// writer thread cannot drain — [`OutboundQueue::enqueue`] BLOCKS the caller
    /// until room frees. The winit UI thread calls this for Write/Resize, so a
    /// wedged daemon CAN momentarily stall the UI thread here.
    ///
    /// The current overload policy deliberately blocks: backpressure is
    /// preferable to silently dropping terminal input (a dropped keystroke or the
    /// final Resize is a correctness bug; a brief stall is a responsiveness bug).
    /// The cap is 1 MiB of control frames + a capped paste, so reaching it means
    /// the daemon is badly wedged, not normal slowness. A future change should make
    /// the UI-thread path nonblocking with an explicit "outbound saturated" state
    /// surfaced to the UI (e.g. an overlay) rather than blocking; until then this
    /// honestly blocks instead of dropping.
    ///
    /// Locking: takes only the short `outbound` lock to clone the queue handle,
    /// then releases it before (possibly) blocking on the queue's own lock — so it
    /// is a leaf w.r.t. `grid`/`exited`. Safe to call from any thread.
    pub fn send_request(&self, req: &ClientRequest) {
        let line = match serde_json::to_string(req) {
            Ok(mut line) => {
                line.push('\n');
                line.into_bytes()
            }
            Err(e) => {
                eprintln!("maestro-renderer: serialize failed: {e}");
                return;
            }
        };
        let queue = self.outbound.lock().unwrap().clone();
        if let Some(q) = queue {
            if !q.enqueue(line) {
                eprintln!("maestro-renderer: outbound queue closed; request dropped");
            }
        }
    }

    /// Read the current active session (id + epoch) under a short lock.
    pub fn active_snapshot(&self) -> ActiveSession {
        self.active.lock().unwrap().clone()
    }

    /// Publish one accepted active-session grid and clear a historical viewport when the terminal
    /// switches between the primary and alternate screens. Grid and scrollback remain separately
    /// locked and are never held across each other; the draw path independently refuses history
    /// over an alternate grid, so the short publication/reset interval cannot paint stale history.
    pub fn publish_primary_grid(&self, grid: Arc<GridSnapshot>) {
        let next_alt_screen = grid.alt_screen;
        let previous_alt_screen = {
            let mut held = self.grid.lock().unwrap();
            let previous_alt_screen = held.as_ref().map(|previous| previous.alt_screen);
            *held = Some(grid);
            previous_alt_screen
        };
        reset_scrollback_for_screen_transition(
            previous_alt_screen,
            next_alt_screen,
            &mut self.scrollback.lock().unwrap(),
        );
    }

    /// Initialize the active session to `id` at epoch 0 — the attach the reader does
    /// at spawn. Called ONCE before the reader thread starts so the first
    /// `sync_active_session` is a no-op (the reader's local epoch already matches).
    fn init_active_session(&self, id: &str) {
        let mut active = self.active.lock().unwrap();
        active.id = id.to_string();
        active.epoch = 0;
    }

    /// Rebind the renderer to `new_id`, bumping the epoch so the reader thread rebuilds
    /// its `SyncState` and rejects late frames from the old session. Returns the bumped
    /// epoch. Called from the UI thread on a real tab switch (see
    /// [`crate::App::attach_session`]); the reader notices the epoch change on its next
    /// event and rebases. A no-op-detecting caller must compare ids BEFORE calling this
    /// (this always bumps the epoch).
    pub fn set_active_session(&self, new_id: &str) -> u64 {
        let mut active = self.active.lock().unwrap();
        active.id = new_id.to_string();
        active.epoch += 1;
        active.epoch
    }

    /// Snapshot the rendered sibling (id + epoch + grid + exit) from the unified store under a
    /// short lock. Shim over [`Self::stores`]: reads the [`Self::sibling_id`] pointer, then the
    /// matching `kind == Sibling` entry. Returns the empty default when there is no split.
    pub fn sibling_snapshot(&self) -> SiblingSession {
        let id = self.sibling_id.lock().unwrap().clone();
        let stores = self.stores.lock().unwrap();
        match id {
            Some(id) => match stores.get(&id) {
                Some(entry) if entry.kind == PaneKind::Sibling => SiblingSession {
                    id: Some(id),
                    epoch: entry.epoch,
                    grid: entry.grid.clone(),
                    exited: entry.exited,
                },
                // Pointer set but entry missing/wrong-kind (shouldn't happen): report the id with
                // an empty payload so callers see the binding but no stale grid.
                _ => SiblingSession {
                    id: Some(id),
                    epoch: 0,
                    grid: None,
                    exited: None,
                },
            },
            None => SiblingSession::default(),
        }
    }

    /// Bind the sibling slot of the unified store to `new_id`, bumping its epoch and clearing the
    /// cached grid/exit so a fresh sibling starts empty. Returns the bumped epoch. Idempotent on a
    /// same-id call is the CALLER's job to avoid (this always bumps, dropping any late frame from
    /// the previous binding). Never touches the active session.
    ///
    /// Shim: moves the [`Self::sibling_id`] pointer to `new_id` and (re)installs a fresh
    /// `kind == Sibling` entry. The PRIOR sibling entry (if a different id) is removed so the map
    /// never accumulates orphaned sibling slots.
    #[allow(dead_code)]
    pub fn set_sibling_session(&self, new_id: &str) -> u64 {
        let mut sibling_id = self.sibling_id.lock().unwrap();
        let mut sibling_epoch = self.sibling_epoch.lock().unwrap();
        let mut stores = self.stores.lock().unwrap();
        // Drop the previous sibling entry when rebinding to a different id so only one
        // `kind == Sibling` entry ever exists. (A same-id rebind reuses the slot below.)
        if let Some(prev) = sibling_id.as_deref() {
            if prev != new_id {
                if let Some(e) = stores.get(prev) {
                    if e.kind == PaneKind::Sibling {
                        stores.remove(prev);
                    }
                }
            }
        }
        // Bump the single monotonic counter and stamp it (matches old `SiblingSession::epoch`).
        *sibling_epoch += 1;
        let entry = stores.entry(new_id.to_string()).or_default();
        entry.kind = PaneKind::Sibling;
        entry.epoch = *sibling_epoch;
        entry.grid = None;
        entry.exited = None;
        entry.scrollback.reset_to_live();
        *sibling_id = Some(new_id.to_string());
        *sibling_epoch
    }

    /// Drop the sibling binding entirely (no split → no sibling to cache), bumping the epoch so any
    /// in-flight old-sibling grid is rejected, and removing its entry. Never touches the active
    /// session. Shim: clears the [`Self::sibling_id`] pointer and removes the `kind == Sibling`
    /// entry from the unified store.
    pub fn clear_sibling_session(&self) {
        let mut sibling_id = self.sibling_id.lock().unwrap();
        let mut sibling_epoch = self.sibling_epoch.lock().unwrap();
        let mut stores = self.stores.lock().unwrap();
        let Some(id) = sibling_id.take() else {
            return;
        };
        // Bump the monotonic counter on unbind too, so a late frame from the just-cleared sibling
        // (or any later rebind of the same id) is rejected by a strictly-greater epoch.
        *sibling_epoch += 1;
        if let Some(e) = stores.get(&id) {
            if e.kind == PaneKind::Sibling {
                stores.remove(&id);
            }
        }
    }

    /// Apply a sibling grid IF it belongs to the currently-bound sibling at `for_epoch`.
    /// A grid whose `for_id`/`for_epoch` does not match the live binding is a late frame
    /// from a previous sibling and is dropped (returns `false`). Never touches the active
    /// grid. Returns `true` when the sibling cache was updated. Shim over the unified store
    /// (the `kind == Sibling` entry under `for_id`).
    pub fn apply_sibling_grid(
        &self,
        for_id: &str,
        for_epoch: u64,
        grid: Arc<GridSnapshot>,
    ) -> bool {
        let sibling_id = self.sibling_id.lock().unwrap();
        if sibling_id.as_deref() != Some(for_id) {
            return false;
        }
        let mut stores = self.stores.lock().unwrap();
        match stores.get_mut(for_id) {
            Some(entry) if entry.kind == PaneKind::Sibling && entry.epoch == for_epoch => {
                reset_scrollback_for_screen_transition(
                    entry.grid.as_ref().map(|previous| previous.alt_screen),
                    grid.alt_screen,
                    &mut entry.scrollback,
                );
                entry.grid = Some(grid);
                true
            }
            _ => false,
        }
    }

    /// Record the sibling session's exit IF it belongs to the currently-bound sibling at
    /// `for_epoch`. An exit for a previous sibling is dropped (returns `false`). Never touches
    /// the active session. Returns `true` when recorded. Shim over the unified store.
    pub fn apply_sibling_exit(&self, for_id: &str, for_epoch: u64, code: Option<i32>) -> bool {
        let sibling_id = self.sibling_id.lock().unwrap();
        if sibling_id.as_deref() != Some(for_id) {
            return false;
        }
        let mut stores = self.stores.lock().unwrap();
        match stores.get_mut(for_id) {
            Some(entry) if entry.kind == PaneKind::Sibling && entry.epoch == for_epoch => {
                entry.exited = Some(code);
                true
            }
            _ => false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_sibling_scrollback(
        &self,
        for_id: &str,
        for_epoch: u64,
        generation: SessionGeneration,
        revision: Revision,
        history_len: u32,
        offset_from_top: u32,
        rows: Vec<Vec<Cell>>,
    ) -> bool {
        let sibling_id = self.sibling_id.lock().unwrap();
        if sibling_id.as_deref() != Some(for_id) {
            return false;
        }
        let mut stores = self.stores.lock().unwrap();
        match stores.get_mut(for_id) {
            Some(entry) if entry.kind == PaneKind::Sibling && entry.epoch == for_epoch => {
                let live_generation = entry.grid.as_ref().map(|g| g.generation.clone());
                apply_scrollback_payload(
                    live_generation,
                    &mut entry.scrollback,
                    generation,
                    revision,
                    history_len,
                    offset_from_top,
                    rows,
                )
            }
            _ => false,
        }
    }

    /// The current generation of the multi-pane membership (bumped on every membership change).
    /// The reader compares this to its local generation to know when to rebuild its per-pane
    /// `SyncState` set.
    pub fn pane_generation(&self) -> u64 {
        *self.pane_generation.lock().unwrap()
    }

    /// The `kind == Pane` session ids currently bound in the unified store, in sorted order
    /// (`BTreeMap` iteration order). The sibling entry is excluded.
    pub fn pane_ids(&self) -> Vec<String> {
        self.stores
            .lock()
            .unwrap()
            .iter()
            .filter(|(_, e)| e.kind == PaneKind::Pane)
            .map(|(id, _)| id.clone())
            .collect()
    }

    /// Reconcile the multi-pane (`kind == Pane`) membership to exactly `ids` (the visible
    /// non-active pane session ids). Removes pane entries no longer present and inserts fresh
    /// (empty) entries for new ids, bumping each new id's `epoch` so a late frame from a prior
    /// binding of the same id is dropped. Bumps `generation` (and returns the new value) ONLY when
    /// membership actually changed. NEVER touches the active session or the rendered sibling entry
    /// (the `kind == Sibling` filter keeps the reconcile disjoint from the sibling slot).
    pub fn set_pane_sessions(&self, ids: &[&str]) -> u64 {
        let mut generation = self.pane_generation.lock().unwrap();
        let mut stores = self.stores.lock().unwrap();
        let wanted: std::collections::HashSet<&str> = ids.iter().copied().collect();
        // Remove only PANE entries no longer wanted; the sibling slot is untouched.
        let before: Vec<String> = stores
            .iter()
            .filter(|(id, e)| e.kind == PaneKind::Pane && !wanted.contains(id.as_str()))
            .map(|(id, _)| id.clone())
            .collect();
        let removed = before.len();
        for id in &before {
            stores.remove(id);
        }
        let mut added = 0u64;
        for id in ids {
            let is_pane_member = stores
                .get(*id)
                .map(|e| e.kind == PaneKind::Pane)
                .unwrap_or(false);
            if !is_pane_member {
                let epoch = generation.wrapping_add(1).wrapping_add(added);
                let entry = stores.entry((*id).to_string()).or_default();
                entry.kind = PaneKind::Pane;
                entry.epoch = epoch;
                entry.grid = None;
                entry.exited = None;
                entry.scrollback.reset_to_live();
                added += 1;
            }
        }
        if removed > 0 || added > 0 {
            *generation += 1;
        }
        *generation
    }

    /// Drop ALL multi-pane (`kind == Pane`) entries (e.g. the layout collapsed back to two panes
    /// or no split), bumping `generation` so the reader drops every per-pane `SyncState`. No-op
    /// when there are no pane entries. Never touches the active session or the rendered sibling.
    pub fn clear_pane_sessions(&self) {
        let mut generation = self.pane_generation.lock().unwrap();
        let mut stores = self.stores.lock().unwrap();
        let panes: Vec<String> = stores
            .iter()
            .filter(|(_, e)| e.kind == PaneKind::Pane)
            .map(|(id, _)| id.clone())
            .collect();
        if panes.is_empty() {
            return;
        }
        for id in &panes {
            stores.remove(id);
        }
        *generation += 1;
    }

    /// The epoch currently bound to pane `id` in the unified store, or `None` when `id` is not a
    /// `kind == Pane` member. The reader stamps each frame it ingests with this so
    /// [`Self::apply_pane_grid`]/[`Self::apply_pane_exit`] can reject a frame whose id was removed
    /// and re-added since.
    pub fn pane_epoch(&self, id: &str) -> Option<u64> {
        self.stores
            .lock()
            .unwrap()
            .get(id)
            .filter(|e| e.kind == PaneKind::Pane)
            .map(|e| e.epoch)
    }

    /// Snapshot pane `id`'s cached `(grid, exited)` for painting, or `None` when `id` is not a
    /// `kind == Pane` member. `grid` is the last cached structured snapshot (`None` until its
    /// first baseline); `exited` is `Some(code)` once the pane's process exited.
    #[cfg(test)]
    pub fn pane_snapshot(&self, id: &str) -> Option<PaneSnapshot> {
        self.stores
            .lock()
            .unwrap()
            .get(id)
            .filter(|e| e.kind == PaneKind::Pane)
            .map(|e| (e.grid.clone(), e.exited))
    }

    /// Uniform per-pane paint resolution: the single source `draw` reads for every visible
    /// pane, primary or not. `primary_id` is [`Self::active`]'s id (the pane the dedicated
    /// `grid`/`exited`/`scrollback` fields back); any other id resolves from its [`Self::stores`]
    /// entry. All grid `Arc`s + scrollback values are CLONED under short locks and returned OWNED, so
    /// the caller holds no mutex across shaping/GPU submission — this is also how the
    /// active-session scrollback finally moves into the symmetric path without the
    /// guard-across-statements hazard: we snapshot, then drop the guard.
    ///
    /// For the primary pane the live grid/exit come from the dedicated fields and the scrollback view
    /// from [`Self::scrollback`] (the same paint source used by the active path). For a
    /// non-primary pane they come from its `PaneStore` (sibling OR extra pane — same shape), including
    /// that pane's OWN `scrollback`, so paint reads the scrollback of the pane being drawn. A non-primary
    /// pane with no scrollback reply yet simply reports offset 0 and paints live — the symmetric
    /// "live until you scroll" state. Returns the empty default for an unknown id (paints nothing).
    pub fn pane_paint(&self, id: &str, primary_id: &str) -> PanePaint {
        if id == primary_id {
            // Primary: snapshot the dedicated fields under short, sequential locks and release each
            // before the next so we never hold two at once and never hold any past return.
            let live = self.grid.lock().unwrap().clone();
            let exited = *self.exited.lock().unwrap();
            let (scrolled_offset, history_len, historical) = {
                let sb = self.scrollback.lock().unwrap();
                (sb.view_offset, sb.history_len, sb.historical.clone())
            };
            return PanePaint {
                live,
                exited,
                scrolled_offset,
                history_len,
                historical,
            };
        }
        // Non-primary: one short lock over the store yields this pane's live grid, exit, and its OWN
        // scrollback view, all cloned out before the guard drops.
        let stores = self.stores.lock().unwrap();
        match stores.get(id) {
            Some(entry) => PanePaint {
                live: entry.grid.clone(),
                exited: entry.exited,
                scrolled_offset: entry.scrollback.view_offset,
                history_len: entry.scrollback.history_len,
                historical: entry.scrollback.historical.clone(),
            },
            None => PanePaint::default(),
        }
    }

    /// Run `f` against pane `id`'s OWN scrollback view under a short lock and return its result, then
    /// release. The primary pane uses the dedicated [`Self::scrollback`]; any other id uses its
    /// `PaneStore::scrollback` (the wheel acts on the FOCUSED pane's scrollback, whichever pane that is).
    /// An unknown non-primary id runs `f` against a throwaway default (a no-op edit, default reads) so a
    /// stale focus never panics. The guard never escapes `f`, so the caller holds no scrollback lock
    /// across a redraw or request.
    pub fn with_pane_scrollback<R>(
        &self,
        id: &str,
        primary_id: &str,
        f: impl FnOnce(&mut ScrollbackState) -> R,
    ) -> R {
        if id == primary_id {
            let mut sb = self.scrollback.lock().unwrap();
            return f(&mut sb);
        }
        let mut stores = self.stores.lock().unwrap();
        match stores.get_mut(id) {
            Some(entry) => f(&mut entry.scrollback),
            None => f(&mut ScrollbackState::default()),
        }
    }

    /// Apply a grid to pane `id` IF it is still a `kind == Pane` member at `for_epoch`. A frame for
    /// a removed pane (no entry) or a stale epoch (the id was re-added) is dropped (`false`). Never
    /// touches the active or sibling grid. Returns `true` when the pane cache was updated.
    pub fn apply_pane_grid(&self, id: &str, for_epoch: u64, grid: Arc<GridSnapshot>) -> bool {
        let mut stores = self.stores.lock().unwrap();
        match stores.get_mut(id) {
            Some(entry) if entry.kind == PaneKind::Pane && entry.epoch == for_epoch => {
                reset_scrollback_for_screen_transition(
                    entry.grid.as_ref().map(|previous| previous.alt_screen),
                    grid.alt_screen,
                    &mut entry.scrollback,
                );
                entry.grid = Some(grid);
                true
            }
            _ => false,
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_pane_scrollback(
        &self,
        id: &str,
        for_epoch: u64,
        generation: SessionGeneration,
        revision: Revision,
        history_len: u32,
        offset_from_top: u32,
        rows: Vec<Vec<Cell>>,
    ) -> bool {
        let mut stores = self.stores.lock().unwrap();
        match stores.get_mut(id) {
            Some(entry) if entry.kind == PaneKind::Pane && entry.epoch == for_epoch => {
                let live_generation = entry.grid.as_ref().map(|g| g.generation.clone());
                apply_scrollback_payload(
                    live_generation,
                    &mut entry.scrollback,
                    generation,
                    revision,
                    history_len,
                    offset_from_top,
                    rows,
                )
            }
            _ => false,
        }
    }

    /// Record pane `id`'s exit IF it is still a `kind == Pane` member at `for_epoch`. A late exit
    /// for a removed or replaced pane is dropped (`false`). Returns `true` when recorded.
    pub fn apply_pane_exit(&self, id: &str, for_epoch: u64, code: Option<i32>) -> bool {
        let mut stores = self.stores.lock().unwrap();
        match stores.get_mut(id) {
            Some(entry) if entry.kind == PaneKind::Pane && entry.epoch == for_epoch => {
                entry.exited = Some(code);
                true
            }
            _ => false,
        }
    }

    /// Install a fresh, drainable outbound queue and hand back a handle to it, so a
    /// unit test can run `send_request`-driven code and then inspect what got enqueued
    /// without a socket or writer thread. Test-only.
    #[cfg(test)]
    fn with_test_queue() -> (Arc<Shared>, Arc<OutboundQueue>) {
        let shared = Arc::new(Shared::default());
        let queue = Arc::new(OutboundQueue::new());
        *shared.outbound.lock().unwrap() = Some(Arc::clone(&queue));
        (shared, queue)
    }

    /// Crate-level test seam for App tests: install a fresh queue without exposing the private
    /// queue type across the module boundary. Production builds have no such accessor.
    #[cfg(test)]
    pub(crate) fn with_test_outbound() -> Arc<Shared> {
        Self::with_test_queue().0
    }

    /// Drain and decode all requests currently queued by App. Returns empty if a test did not
    /// install the queue. Keeps the production outbound internals private.
    #[cfg(test)]
    pub(crate) fn drain_test_requests(&self) -> Vec<ClientRequest> {
        self.outbound
            .lock()
            .unwrap()
            .as_ref()
            .map(|queue| queue.drain_requests())
            .unwrap_or_default()
    }

    /// Clone one pane (`kind == Pane`) entry's `(epoch, grid, exited)` by id for assertions, or
    /// `None` when not a pane member. Test-only.
    #[cfg(test)]
    fn pane_entry(&self, id: &str) -> Option<PaneEntryView> {
        self.stores
            .lock()
            .unwrap()
            .get(id)
            .filter(|e| e.kind == PaneKind::Pane)
            .map(|e| PaneEntryView {
                grid: e.grid.clone(),
                exited: e.exited,
            })
    }
}

/// Test-only flattened view of a pane entry's assertion-relevant fields, so existing tests keep
/// reading `.grid`/`.exited` after the backing store unification. (Epoch is asserted via
/// [`Shared::pane_epoch`].)
#[cfg(test)]
#[derive(Clone)]
struct PaneEntryView {
    grid: Option<Arc<GridSnapshot>>,
    exited: Option<Option<i32>>,
}

/// The ordered outbound requests a single-session renderer must enqueue to rebind
/// from `old_id` to `new_id`. Pure so the FIFO ordering is unit-tested without a
/// socket. The order is load-bearing — the daemon's protocol is order-sensitive:
///
/// 1. `Detach { old_id }` — stop the daemon forwarding the old session first, so no
///    further old-session frames are produced after we rebase.
/// 2. `Attach { new_id, want_raw_output: false }` — structured-only attach; the daemon
///    installs the live notification/damage forwarder before any geometry mutation.
/// 3. `Resize { new_id, cols, rows }` — ONLY when `dims` is supplied (window geometry
///    is known), followed by `Snapshot { new_id }`. Resize advances the grid revision and
///    Snapshot supplies a deterministic final-size baseline even when the PTY is otherwise idle.
///    Keeping Attach first also prevents a bell/title/OSC notification generated by SIGWINCH
///    from falling into a pre-subscription gap.
///
/// A same-session switch is the caller's responsibility to short-circuit BEFORE
/// calling this (see [`crate::App::attach_session`]); this helper always assumes a
/// real change and never emits a no-op.
pub fn plan_attach_switch(
    old_id: &str,
    new_id: &str,
    dims: Option<(u16, u16)>,
) -> Vec<ClientRequest> {
    let mut plan = vec![
        ClientRequest::Detach {
            id: old_id.to_string(),
        },
        ClientRequest::Attach {
            id: new_id.to_string(),
            want_raw_output: false,
        },
    ];
    if let Some((cols, rows)) = dims {
        plan.push(ClientRequest::Resize {
            id: new_id.to_string(),
            cols,
            rows,
        });
        plan.push(ClientRequest::Snapshot {
            id: new_id.to_string(),
        });
    }
    plan
}

/// The ordered outbound requests to bind the inactive pane's sibling session, given the
/// previously-bound sibling (`old_id`, `None` when there was no split) and the new one
/// (`new_id`). Pure so the FIFO ordering is unit-tested without a socket. It NEVER
/// detaches the active session — only the prior SIBLING — so attaching/replacing the
/// inactive pane can never disrupt the active pane:
///
/// 1. `Detach { old_id }` — ONLY when there was a different prior sibling, so the daemon
///    stops forwarding the old sibling before we rebind. Skipped when `old_id` is `None`
///    (first sibling) or equals `new_id` (same sibling — the caller should have
///    short-circuited, but we still never emit a redundant detach+reattach of it).
/// 2. `Attach { new_id, want_raw_output: false }` — structured-only attach of the new
///    sibling; the daemon replies with its authoritative baseline `Grid`.
/// 3. `Resize { new_id, cols, rows }` — ONLY when `dims` (the inactive pane size) is
///    supplied, so the sibling adopts the inactive-pane geometry. Sent AFTER Attach.
///
/// A same-sibling rebind (`old_id == Some(new_id)`) yields ONLY the optional Resize: no
/// detach, no reattach — so a pane-size change for the unchanged sibling just resizes it.
#[allow(dead_code)]
pub fn plan_sibling_attach(
    old_id: Option<&str>,
    new_id: &str,
    dims: Option<(u16, u16)>,
) -> Vec<ClientRequest> {
    let same_sibling = old_id == Some(new_id);
    let mut plan = Vec::new();
    if let Some(old) = old_id {
        if !same_sibling {
            plan.push(ClientRequest::Detach {
                id: old.to_string(),
            });
        }
    }
    if !same_sibling {
        plan.push(ClientRequest::Attach {
            id: new_id.to_string(),
            want_raw_output: false,
        });
    }
    if let Some((cols, rows)) = dims {
        plan.push(ClientRequest::Resize {
            id: new_id.to_string(),
            cols,
            rows,
        });
    }
    plan
}

/// Reset the renderer's per-session published state so NO stale row from the old
/// session can paint as the new one. Clears the live grid, the exit overlay, and the
/// scrollback view. Pure of the event loop / socket so a unit test can drive it on a
/// `Shared` and assert grid/exit/scrollback are cleared. Called by the reader thread
/// on a session rebind (the UI thread already cleared its own selection/view state in
/// [`crate::App::attach_session`]; this clears the reader-owned shared fields).
pub fn reset_session_state(shared: &Shared) {
    *shared.grid.lock().unwrap() = None;
    *shared.exited.lock().unwrap() = None;
    *shared.last_revision.lock().unwrap() = None;
    // This is an IDENTITY rebind, not an ordinary viewport reset.  `history_len` belongs
    // to the old PTY just as much as its grid does; retaining it can clamp the new session
    // to another pane's stale depth (including a permanent `Some(0)` fixed point).
    *shared.scrollback.lock().unwrap() = ScrollbackState::default();
}

/// If the UI thread switched the active session since the reader last checked
/// (`shared.active.epoch` advanced past `local_epoch`), rebind the reader's
/// thread-local `session_id` and `SyncState` to the new id and reset the shared
/// published state. A no-op when the epoch is unchanged (the common per-event path).
/// Returns `true` if a rebind happened (test hook).
///
/// This is the reader-side half of a tab switch: the UI thread bumps the epoch and
/// enqueues Detach/Attach/optional-Resize+Snapshot; the reader, on its next event, adopts the new id so
/// (a) a fresh `SyncState` AwaitingBaseline accepts the new session's first Grid, and
/// (b) any late frame from the OLD session is rejected as `WrongSession`.
fn sync_active_session(
    shared: &Shared,
    session_id: &mut String,
    sync: &mut SyncState,
    local_epoch: &mut u64,
) -> bool {
    let active = shared.active_snapshot();
    if active.epoch == *local_epoch {
        return false;
    }
    *local_epoch = active.epoch;
    *session_id = active.id.clone();
    *sync = SyncState::new(active.id);
    reset_session_state(shared);
    true
}

/// Reader-side half of binding the inactive split-pane SIBLING. The UI thread fills
/// `shared.sibling` (id + epoch) from the split frame; the reader, on its next event,
/// adopts that binding so a fresh sibling `SyncState` (AwaitingBaseline) accepts the
/// sibling's first Grid and any late frame from a PREVIOUS sibling is rejected.
///
/// Mirrors [`sync_active_session`] but for the sibling, and is wholly independent of it:
/// it reads only `shared.sibling`, never touches the active session, and on unbind
/// (no split → `id == None`) drops the sibling `SyncState` so no frames are ingested.
/// The sibling grid/exit cache is owned by `Shared` (cleared on bind/unbind there); this
/// only manages the reader-local id/sync/epoch. Returns `true` if the binding changed.
fn sync_sibling_session(
    shared: &Shared,
    sibling_id: &mut Option<String>,
    sibling_sync: &mut Option<SyncState>,
    local_epoch: &mut u64,
) -> bool {
    let sib = shared.sibling_snapshot();
    if sib.epoch == *local_epoch {
        return false;
    }
    *local_epoch = sib.epoch;
    match sib.id {
        Some(id) => {
            *sibling_sync = Some(SyncState::new(id.clone()));
            *sibling_id = Some(id);
        }
        None => {
            *sibling_id = None;
            *sibling_sync = None;
        }
    }
    true
}

/// Reader-side membership reconcile for the MULTI-PANE cache (the N-pane generalization of
/// [`sync_sibling_session`]). The UI thread reconciles `shared.panes` from the non-active panes
/// of [`compute_split_layout`](crate::compute_split_layout); on a generation bump the reader
/// rebuilds `pane_syncs` so each currently-bound pane has a fresh `SyncState` (AwaitingBaseline)
/// and a removed pane's `SyncState` is dropped — so a late frame from a removed/replaced pane is
/// never ingested. The per-pane grid/exit cache itself lives in `Shared` (membership + epoch
/// gated there); this only maintains the reader-local sync map and generation. Socket attachment
/// lifecycle belongs exclusively to the UI-side pane-role reconcile: emitting Attach/Detach here
/// as well races a pane-to-primary promotion and can detach the newly-active session's one daemon
/// forwarder. Returns `true` when the membership changed.
fn sync_pane_sessions(
    shared: &Shared,
    pane_syncs: &mut HashMap<String, SyncState>,
    local_generation: &mut u64,
) -> bool {
    let generation = shared.pane_generation();
    if generation == *local_generation {
        return false;
    }
    *local_generation = generation;
    let ids = shared.pane_ids();
    // Reader-local only: the UI-side pane-role reconcile owns the corresponding daemon Detach.
    // Keeping socket lifecycle out of this asynchronously-running reader prevents a stale removed
    // `Pane` role from detaching the same session after it has already become the active role.
    pane_syncs.retain(|id, _| ids.iter().any(|i| i == id));
    // Add a fresh sync for each newly bound pane. The UI already sent the structured-only Attach
    // after publishing this membership, so the fresh SyncState is ready before that baseline is
    // decoded. Sending another Attach here would only replace the same daemon forwarder.
    for id in ids {
        if !pane_syncs.contains_key(&id) {
            pane_syncs.insert(id.clone(), SyncState::new(id.clone()));
        }
    }
    true
}

/// Ingest a frame for one of the extra non-active panes into the multi-pane cache. The N-pane
/// analogue of [`handle_sibling_event`]: it ONLY maintains the cache (no render, no input). The
/// pane's `SyncState` gates every Grid/Damage, and the resulting grid is published via
/// [`Shared::apply_pane_grid`] (membership + epoch gated, so a frame for a removed/replaced pane
/// is dropped). Scrollback rows update the pane's own renderer-owned viewport state; raw Output
/// stays ignored on structured-only attaches. The UI is woken only on an accepted grid, exit, or
/// scrollback update.
fn handle_pane_event(
    shared: &Arc<Shared>,
    sync: &mut SyncState,
    proxy: &dyn UserEventSender,
    pane_id: &str,
    ev: DaemonEvent,
) {
    let Some(epoch) = shared.pane_epoch(pane_id) else {
        return; // pane removed since routing was decided; drop the frame.
    };
    match ev {
        DaemonEvent::Grid { id, grid } => match sync.on_grid(&id, &grid) {
            Ok(outcome) => {
                if outcome.repaint && shared.apply_pane_grid(pane_id, epoch, Arc::new(grid)) {
                    wake(proxy);
                }
                if outcome.request_snapshot {
                    shared.send_request(&ClientRequest::Snapshot { id: pane_id.into() });
                }
            }
            Err(reason) => eprintln!("maestro-renderer: rejected pane snapshot: {reason:?}"),
        },
        DaemonEvent::Damage { frame } => {
            if frame.id.as_str() != pane_id {
                return;
            }
            let held = {
                let stores = shared.stores.lock().unwrap();
                match stores.get(pane_id) {
                    Some(entry) if entry.kind == PaneKind::Pane && entry.epoch == epoch => {
                        entry.grid.clone()
                    }
                    _ => return,
                }
            };
            let Some(held) = held else {
                if sync.on_resync_required(pane_id).is_ok() {
                    shared.send_request(&ClientRequest::Snapshot { id: pane_id.into() });
                }
                return;
            };
            match sync.on_damage(&frame.id, &frame, &held) {
                DamageOutcome::Applied(grid) => {
                    if shared.apply_pane_grid(pane_id, epoch, Arc::from(grid)) {
                        wake(proxy);
                    }
                }
                DamageOutcome::Ignore => {}
                DamageOutcome::Resync { reason } => {
                    eprintln!(
                        "maestro-renderer: pane damage not applicable ({reason:?}); resyncing"
                    );
                    if sync.on_resync_required(pane_id).is_ok() {
                        shared.send_request(&ClientRequest::Snapshot { id: pane_id.into() });
                    }
                }
            }
        }
        DaemonEvent::ResyncRequired { id } => {
            if let Err(reason) = sync.on_resync_required(&id) {
                eprintln!("maestro-renderer: ignored pane resync: {reason:?}");
            }
        }
        DaemonEvent::SessionExited { id, code } => {
            if let Ok(Action::Exited) = sync.on_session_exited(&id) {
                if shared.apply_pane_exit(pane_id, epoch, code) {
                    notify_session_exit(proxy, pane_id, code, sync.accepted_generation());
                }
            }
        }
        DaemonEvent::ScrollbackRows {
            generation,
            revision,
            history_len,
            offset_from_top,
            rows,
            ..
        } => {
            if shared.apply_pane_scrollback(
                pane_id,
                epoch,
                generation,
                revision,
                history_len,
                offset_from_top,
                rows,
            ) {
                wake(proxy);
            }
        }
        DaemonEvent::TerminalBell { id } if id == pane_id => {
            let _ = proxy.send(UserEvent::TerminalBell);
        }
        DaemonEvent::TerminalTitle { id, title } if id == pane_id => {
            let _ = proxy.send(UserEvent::TerminalTitle { title });
        }
        DaemonEvent::TerminalClipboardStore { id, text } if id == pane_id => {
            let _ = proxy.send(UserEvent::TerminalClipboardStore { text });
        }
        DaemonEvent::TerminalBell { .. }
        | DaemonEvent::TerminalTitle { .. }
        | DaemonEvent::TerminalClipboardStore { .. }
        | DaemonEvent::Output { .. }
        | DaemonEvent::Error { .. }
        | DaemonEvent::Other => {}
    }
}

/// Spawn the reader thread. Returns the shared state. The reader validates every
/// event, publishes accepted snapshots, and wakes the OWNER event loop via `proxy`
/// (the platform-neutral [`UserEventSender`]) only after a validated state change. It also owns a
/// write handle so it can request a fresh snapshot when
/// live output advances the revision or a resync is needed.
pub fn spawn(
    socket_path: String,
    session_id: String,
    proxy: Box<dyn UserEventSender>,
) -> Arc<Shared> {
    let shared = Arc::new(Shared::default());

    let stream = match UnixStream::connect(&socket_path) {
        Ok(s) => s,
        Err(e) => {
            eprintln!("maestro-renderer: failed to connect to {socket_path}: {e}");
            // Return empty shared state; the window will show nothing.
            return shared;
        }
    };

    // The dedicated writer's own socket handle. One thread owns it and drains the
    // bounded outbound queue in strict FIFO order — no other thread touches the
    // write half, so bytes can never interleave at the kernel.
    let mut write_half = match stream.try_clone() {
        Ok(s) => s,
        Err(e) => {
            eprintln!("maestro-renderer: failed to clone stream: {e}");
            return shared;
        }
    };

    // Publish the queue so producers (reader + UI) can enqueue, then start the
    // writer thread that drains it.
    let outbound = Arc::new(OutboundQueue::new());
    *shared.outbound.lock().unwrap() = Some(Arc::clone(&outbound));
    {
        let outbound = Arc::clone(&outbound);
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            while let Some(line) = outbound.dequeue() {
                if let Err(e) = write_half.write_all(&line) {
                    eprintln!("maestro-renderer: write failed: {e}");
                    break;
                }
            }
            // Socket write side is dead: close the queue so any blocked producer
            // unblocks, and clear it from Shared so later requests are no-ops.
            outbound.close();
            *shared.outbound.lock().unwrap() = None;
        });
    }

    // Attach only. Attach already guarantees an authoritative baseline Grid (the
    // daemon replays the restore grid on the attach path), so we do NOT send a
    // redundant Snapshot here — the first Grid event will baseline us. This is the
    // FIRST item enqueued, so strict FIFO guarantees it reaches the daemon before
    // any Snapshot/Write/Resize that depends on the attach.
    // With `want_raw_output: false`, this renderer is structured-only. The daemon
    // ships the baseline Grid plus live `Damage` frames (and ResyncRequired+Grid for
    // resize/generation/lag recovery) — never raw `Output`. Damage is the normal live
    // update path; raw bytes are never re-parsed here (no second VT parser). If an
    // Output ever arrives anyway it is debug-ignored, NOT turned into a Snapshot
    // request (see the Output arm of `handle_event`).
    shared.send_request(&ClientRequest::Attach {
        id: session_id.clone(),
        want_raw_output: false,
    });

    // Seed the shared active session BEFORE the reader starts so its local epoch (0)
    // already matches — the first `sync_active_session` is a no-op. A later tab switch
    // bumps the epoch via `set_active_session` and the reader rebases on its next event.
    shared.init_active_session(&session_id);

    // Reader thread: parse events, validate, publish accepted snapshots, wake the
    // UI on validated change. The SyncState is owned solely by this thread (sole
    // writer of `shared.grid`), so it needs no lock of its own. `session_id`/`sync`
    // are REBOUND in-place when the UI thread switches the active session (a tab
    // switch): `sync_active_session` rebuilds the `SyncState` for the new id and
    // resets the shared grid/exit/scrollback so stale old-session rows can't paint.
    {
        let shared = Arc::clone(&shared);
        std::thread::spawn(move || {
            let mut reader = BufReader::new(stream);
            let mut session_id = session_id;
            let mut sync = SyncState::new(session_id.clone());
            let mut epoch: u64 = 0;
            // Reader-local sibling binding, independent of the active session above. The
            // UI thread fills `shared.sibling` from the split frame; `sync_sibling_session`
            // adopts it here so sibling frames are ingested into the sibling cache. `None`
            // until/unless there is a split with a resolved inactive session.
            let mut sibling_id: Option<String> = None;
            let mut sibling_sync: Option<SyncState> = None;
            let mut sibling_epoch: u64 = 0;
            // Reader-local multi-pane cache binding (the extra non-active panes beyond the
            // rendered sibling). One `SyncState` per bound pane id, rebuilt on a membership
            // generation bump by `sync_pane_sessions`. Empty for the two-pane case.
            let mut pane_syncs: HashMap<String, SyncState> = HashMap::new();
            let mut pane_generation: u64 = 0;
            let mut line_buf: Vec<u8> = Vec::new();
            loop {
                // Rebase to the active session if the UI switched it since the last
                // event. Done at the TOP of the loop so the first frame after a switch
                // is already filtered against the new id and a late old-session frame
                // is rejected by the fresh `SyncState`/filter.
                sync_active_session(&shared, &mut session_id, &mut sync, &mut epoch);
                sync_sibling_session(
                    &shared,
                    &mut sibling_id,
                    &mut sibling_sync,
                    &mut sibling_epoch,
                );
                sync_pane_sessions(&shared, &mut pane_syncs, &mut pane_generation);
                line_buf.clear();
                // Bounded framing: cap one line at MAX_LINE_BYTES + 1 so a peer can't
                // make us buffer an unbounded line before parsing. An oversized,
                // unterminated line is a framing violation — stop reading.
                let n = match (&mut reader)
                    .take((MAX_LINE_BYTES + 1) as u64)
                    .read_until(b'\n', &mut line_buf)
                {
                    Ok(n) => n,
                    Err(_) => break,
                };
                if n == 0 {
                    break; // EOF
                }
                let terminated = line_buf.last() == Some(&b'\n');
                if !terminated && line_buf.len() > MAX_LINE_BYTES {
                    eprintln!(
                        "maestro-renderer: event line exceeds {MAX_LINE_BYTES} bytes; closing"
                    );
                    break;
                }
                let line = match std::str::from_utf8(&line_buf) {
                    Ok(s) => s.trim(),
                    Err(_) => {
                        eprintln!("maestro-renderer: event line is not valid UTF-8");
                        continue;
                    }
                };
                if line.is_empty() {
                    continue;
                }
                // Rebase AGAIN here, after the blocking `read_until` returned. The
                // top-of-loop rebase ran BEFORE we blocked; if the UI switched the active
                // session while we were parked in `read_until`, the line we just read
                // belongs to (or arrived during) the old binding. Re-checking the epoch now
                // — before decode/handle — guarantees the just-read frame is filtered
                // against the NEW active session: a late old-session frame is rejected, and
                // the new session's baseline `Grid` is accepted into the fresh `SyncState`
                // instead of being wrongly rejected as `WrongSession`.
                sync_active_session(&shared, &mut session_id, &mut sync, &mut epoch);
                sync_sibling_session(
                    &shared,
                    &mut sibling_id,
                    &mut sibling_sync,
                    &mut sibling_epoch,
                );
                sync_pane_sessions(&shared, &mut pane_syncs, &mut pane_generation);
                // Decode via the bounded discriminator: it reads the `ev` tag from a
                // minimal envelope and enforces MAX_DAMAGE_BYTES BEFORE fully parsing a
                // damage payload's nested cells.
                let mut ev = match decode_event(line) {
                    Ok(ev) => ev,
                    Err(err) => {
                        // A line we can't decode is a frame we've lost on the wire. On the
                        // structured-only path the dropped frame may have been a Damage
                        // mutation, so merely logging would leave the screen permanently
                        // stale. Every decode failure therefore drops to resync to pull a
                        // fresh authoritative grid — see `decode_error_requires_resync`.
                        eprintln!("maestro-renderer: {}", describe_decode_error(&err));
                        if decode_error_requires_resync(&err)
                            && sync.on_resync_required(&session_id).is_ok()
                        {
                            shared.send_request(&ClientRequest::Snapshot {
                                id: session_id.clone(),
                            });
                        }
                        continue;
                    }
                };
                // Compatibility for retained daemons started by an older Hydra build: alternate-
                // screen shrink could serialize a lone wide lead/spacer at a viewport boundary.
                // Repair ONLY those two provably malformed boundary cells. Interior corruption
                // remains untouched and is rejected by SyncState's strict wide-layout gate.
                if let DaemonEvent::Grid { grid, .. } = &mut ev {
                    let repaired = normalize_legacy_snapshot_wide_boundaries(grid);
                    if cfg!(debug_assertions) && repaired > 0 {
                        eprintln!(
                            "maestro-renderer: normalized {repaired} legacy wide boundary cell(s)"
                        );
                    }
                }

                // Dispatch by the event's session id. A frame for the active session takes the
                // existing active path; a frame for the rendered sibling takes the sibling path;
                // a frame for one of the EXTRA non-active panes takes the multi-pane cache path;
                // anything else is ignored/rejected exactly as `handle_event`'s own id filters
                // would. The route is resolved BEFORE consuming `ev` so the id borrow does not
                // outlive the move into the handler. Active wins over sibling wins over pane, so a
                // pane id can never shadow the live active/sibling path.
                enum Route {
                    Active,
                    Sibling,
                    Pane(String),
                }
                let route = match event_session_id(&ev) {
                    Some(id) if id == session_id.as_str() => Route::Active,
                    Some(id) if sibling_id.as_deref() == Some(id) => Route::Sibling,
                    Some(id) if pane_syncs.contains_key(id) => Route::Pane(id.to_string()),
                    _ => Route::Active,
                };
                match route {
                    Route::Sibling => {
                        if let (Some(s_sync), Some(s_id)) =
                            (sibling_sync.as_mut(), sibling_id.as_deref())
                        {
                            handle_sibling_event(
                                &shared,
                                s_sync,
                                proxy.as_ref(),
                                s_id,
                                sibling_epoch,
                                ev,
                            );
                        }
                    }
                    Route::Pane(id) => {
                        if let Some(p_sync) = pane_syncs.get_mut(&id) {
                            handle_pane_event(&shared, p_sync, proxy.as_ref(), &id, ev);
                        }
                    }
                    Route::Active => {
                        handle_event(&shared, &mut sync, proxy.as_ref(), &session_id, ev);
                    }
                }
            }
        });
    }

    shared
}

/// Wake the owner event loop to repaint. A closed event loop (window gone) is not
/// an error here — the reader simply stops mattering once the UI has exited.
fn wake(proxy: &dyn UserEventSender) {
    let _ = proxy.send(UserEvent::Redraw);
}

/// Deliver one accepted daemon exit to the owner loop. Unlike an ordinary repaint wake, this
/// preserves the session id, exit code, and the generation proven by the last accepted grid so
/// app/domain state can perform a guarded targeted update. `None` is deliberately forwarded when
/// the daemon exits before any baseline; the durable layer must not guess a generation.
fn notify_session_exit(
    proxy: &dyn UserEventSender,
    session_id: &str,
    code: Option<i32>,
    observed_generation: Option<&str>,
) {
    let _ = proxy.send(UserEvent::SessionExited {
        session_id: session_id.to_string(),
        code,
        observed_generation: observed_generation.map(str::to_string),
    });
}

/// Decide what (if anything) a raw `Output` event should trigger on the
/// structured-only renderer path. The renderer attached `want_raw_output: false`, so
/// the daemon should not send Output at all; if one arrives anyway it is a stray
/// (a daemon that ignored our opt-out, or an in-flight frame from before the opt-out
/// took effect). The structured-only contract is: NEVER resurrect the Output->Snapshot
/// bridge — Damage drives live updates. So this always returns `None`. Extracted as a
/// pure fn purely so the "no Snapshot request on Output" invariant is unit-testable
/// without standing up a winit event loop.
/// Should an undecodable event line drive a resync? On the structured-only path a
/// line we can't parse is a frame lost on the wire; if it was a Damage mutation,
/// skipping it silently would leave the screen stale forever. So EVERY decode error
/// (bad envelope, bad payload, oversized damage) requests one fresh authoritative
/// snapshot. Pulled out as a pure predicate so the policy is unit-testable without a
/// socket. The cost of an over-eager resync is one extra Snapshot; the cost of NOT
/// resyncing on a dropped Damage frame is permanent visual staleness — so we resync.
fn decode_error_requires_resync(err: &DecodeError) -> bool {
    match err {
        DecodeError::DamageTooLarge { .. }
        | DecodeError::BadEnvelope
        | DecodeError::BadPayload { .. } => true,
    }
}

/// Narrow compatibility repair for a retained daemon from before wide-boundary normalization.
/// A width-0 cell in the first column and a width-2 cell in the last column can never form a valid
/// in-row pair, so replacing just those cells with styled blanks is unambiguous. All visual style
/// fields are preserved; only text/width change. We deliberately do not repair interior layout so
/// malformed or hostile snapshots still fail the strict [`SyncState`] validation gate.
fn normalize_legacy_snapshot_wide_boundaries(grid: &mut GridSnapshot) -> usize {
    let mut repaired = 0;
    for row in &mut grid.rows_cells {
        if row.is_empty() {
            continue;
        }
        if row[0].width == 0 {
            row[0].text = " ".to_string();
            row[0].width = 1;
            repaired += 1;
        }
        let last = row.len() - 1;
        if row[last].width == 2 {
            row[last].text = " ".to_string();
            row[last].width = 1;
            repaired += 1;
        }
    }
    repaired
}

/// Human-readable log line for a decode failure. Separated from the resync decision so
/// the message wording can't drift from the policy.
fn describe_decode_error(err: &DecodeError) -> String {
    match err {
        DecodeError::DamageTooLarge { bytes } => {
            format!("damage frame {bytes} bytes exceeds cap; resyncing")
        }
        DecodeError::BadEnvelope => "event line is not a valid envelope; resyncing".to_string(),
        DecodeError::BadPayload { message } => {
            format!("bad event JSON ({message}); resyncing")
        }
    }
}

fn on_structured_output(revision: Revision) -> Option<ClientRequest> {
    #[cfg(debug_assertions)]
    eprintln!(
        "maestro-renderer: unexpected Output (rev {}) on a structured-only attach; ignoring",
        revision.0
    );
    let _ = revision;
    None
}

fn handle_event(
    shared: &Arc<Shared>,
    sync: &mut SyncState,
    proxy: &dyn UserEventSender,
    session_id: &str,
    ev: DaemonEvent,
) {
    match ev {
        DaemonEvent::Grid { id, grid } => {
            // Gate every snapshot through the sync state machine. A wrong-session,
            // unsupported-version, invalid-dimension, invalid-wide-layout, retired-,
            // or stale-revision frame must never reach the paint path. On rejection we
            // keep showing the last accepted grid and DO NOT wake — an invalid frame is
            // not a state change worth a repaint: wake only after validation.
            //
            // A single Grid can require BOTH actions: paint the accepted grid AND
            // request one more snapshot when live output has already run past it
            // (trailing output the daemon hasn't shipped us yet). We honor both.
            match sync.on_grid(&id, &grid) {
                Ok(outcome) => {
                    if outcome.repaint {
                        let rev = grid.revision;
                        *shared.last_revision.lock().unwrap() = Some((rev, Instant::now()));
                        shared.publish_primary_grid(Arc::new(grid));
                        wake(proxy);
                    }
                    if outcome.request_snapshot {
                        shared.send_request(&ClientRequest::Snapshot {
                            id: session_id.into(),
                        });
                    }
                }
                Err(reason) => eprintln!("maestro-renderer: rejected snapshot: {reason:?}"),
            }
        }
        // This renderer attaches `want_raw_output: false`, so the daemon does
        // NOT send raw Output — live updates arrive as structured `Damage`. The old
        // Output->Snapshot bridge is gone. An Output event here is unexpected (a daemon
        // that ignored our opt-out, or a stale frame); debug-ignore it. Crucially we do
        // NOT request a Snapshot — doing so would resurrect the polling bridge and
        // defeat the structured-only path. Damage drives all live updates; Snapshots
        // are reserved for attach and resync/resize/generation recovery.
        DaemonEvent::Output { revision, .. } => {
            // Delegate the decision to a pure helper so the "never request a Snapshot"
            // invariant is unit-testable without an event loop. It returns the request
            // (if any) the Output should trigger — structured-only, that is always None.
            if let Some(req) = on_structured_output(revision) {
                shared.send_request(&req);
            }
        }
        DaemonEvent::ResyncRequired { id } => {
            // After lag our view is stale. The daemon GUARANTEES ResyncRequired is
            // followed by a fresh authoritative Grid, so we do NOT request one
            // ourselves — we just move to AwaitingResync and wait for that baseline.
            if let Err(reason) = sync.on_resync_required(&id) {
                eprintln!("maestro-renderer: ignored resync: {reason:?}");
            } else {
                *shared.last_revision.lock().unwrap() = Some((Revision(u64::MAX), Instant::now()));
            }
        }
        DaemonEvent::SessionExited { id, code } => {
            if let Ok(Action::Exited) = sync.on_session_exited(&id) {
                *shared.exited.lock().unwrap() = Some(code);
                notify_session_exit(proxy, session_id, code, sync.accepted_generation());
            }
        }
        DaemonEvent::Damage { frame } => {
            // Apply the structured frame against the grid we currently hold,
            // SCRATCH-FIRST. `on_damage` validates the frame and applies its ops onto
            // a CLONE of the held grid; only a fully-applied frame yields a new grid to
            // commit. The held grid is never mutated by an invalid/partial frame.
            //
            // Wrong-session frames are ignored OUTRIGHT — before we read the held grid
            // or contemplate a resync. An unrelated session's frame is not a sync
            // failure of ours; resyncing here (e.g. via the no-baseline path below)
            // would pull a needless snapshot for OUR session over a foreign frame.
            if frame.id.as_str() != session_id {
                return;
            }
            // Clone the held Arc under a short lock so we don't hold `grid` across the
            // apply. (The reader thread is the sole writer of `shared.grid`, so the
            // value can't change underneath us between this read and the commit below.)
            let held = shared.grid.lock().unwrap().clone();
            let Some(held) = held else {
                // No baseline yet — a damage frame (for OUR session) before the first
                // Grid can't be applied. Resync once to pull an authoritative baseline.
                if sync.on_resync_required(session_id).is_ok() {
                    shared.send_request(&ClientRequest::Snapshot {
                        id: session_id.into(),
                    });
                }
                return;
            };
            match sync.on_damage(&frame.id, &frame, &held) {
                DamageOutcome::Applied(grid) => {
                    let rev = grid.revision;
                    *shared.last_revision.lock().unwrap() = Some((rev, Instant::now()));
                    shared.publish_primary_grid(Arc::from(grid));
                    wake(proxy);
                }
                DamageOutcome::Ignore => {
                    // Duplicate/stale frame — keep the current screen, no resync.
                }
                DamageOutcome::Resync { reason } => {
                    eprintln!("maestro-renderer: damage not applicable ({reason:?}); resyncing");
                    if sync.on_resync_required(session_id).is_ok() {
                        shared.send_request(&ClientRequest::Snapshot {
                            id: session_id.into(),
                        });
                    }
                }
            }
        }
        DaemonEvent::Error { message } => {
            eprintln!("maestro-renderer: daemon error: {message}");
        }
        // Scrollback reply. A read-only historical window — NOT a Grid, so it never
        // enters `SyncState` (no generation/revision continuity gating, no damage path).
        // We turn it into a synthetic snapshot for the paint path and stash it in the
        // renderer-owned `ScrollbackState`. Rejected outright if it is for another session
        // or a generation that no longer matches the live grid (stale after a resync).
        DaemonEvent::ScrollbackRows {
            id,
            generation,
            revision,
            history_len,
            offset_from_top,
            rows,
        } => {
            // The accept/reject + state-update decision is pure (no proxy/event loop), so
            // it is unit-tested directly. We only translate its result into a wake here.
            if apply_scrollback_rows(
                shared,
                session_id,
                &id,
                generation,
                revision,
                history_len,
                offset_from_top,
                rows,
            ) {
                wake(proxy);
            }
        }
        DaemonEvent::TerminalBell { id } if id == session_id => {
            let _ = proxy.send(UserEvent::TerminalBell);
        }
        DaemonEvent::TerminalTitle { id, title } if id == session_id => {
            let _ = proxy.send(UserEvent::TerminalTitle { title });
        }
        DaemonEvent::TerminalClipboardStore { id, text } if id == session_id => {
            let _ = proxy.send(UserEvent::TerminalClipboardStore { text });
        }
        DaemonEvent::TerminalBell { .. }
        | DaemonEvent::TerminalTitle { .. }
        | DaemonEvent::TerminalClipboardStore { .. } => {}
        DaemonEvent::Other => {}
    }
}

/// The session id a daemon event is addressed to, used to route a frame to the active
/// session vs the attached sibling. `None` for events that carry no id (`Error`,
/// `Other`) — those fall through to the active path, which already ignores them.
fn event_session_id(ev: &DaemonEvent) -> Option<&str> {
    match ev {
        DaemonEvent::Grid { id, .. }
        | DaemonEvent::Output { id, .. }
        | DaemonEvent::ResyncRequired { id }
        | DaemonEvent::SessionExited { id, .. }
        | DaemonEvent::ScrollbackRows { id, .. }
        | DaemonEvent::TerminalBell { id }
        | DaemonEvent::TerminalTitle { id, .. }
        | DaemonEvent::TerminalClipboardStore { id, .. } => Some(id.as_str()),
        DaemonEvent::Damage { frame } => Some(frame.id.as_str()),
        DaemonEvent::Error { .. } | DaemonEvent::Other => None,
    }
}

/// Ingest a frame for the attached SIBLING session into the sibling cache. This is the
/// sibling analogue of [`handle_event`]'s active path, but it ONLY maintains the cache —
/// the sibling is not rendered yet (the inactive pane keeps its placeholder), receives no
/// input, and never drives the active session's `SyncState`/grid.
///
/// Gating mirrors the active path: every Grid/Damage goes through the sibling `SyncState`,
/// and the resulting grid is published via [`Shared::apply_sibling_grid`] (id+epoch gated
/// so a late frame from a previous sibling is dropped). Scrollback rows update the sibling's
/// own renderer-owned viewport state; raw Output stays ignored on structured-only attaches.
/// The UI is woken only on an accepted sibling grid, exit, or scrollback update.
fn handle_sibling_event(
    shared: &Arc<Shared>,
    sync: &mut SyncState,
    proxy: &dyn UserEventSender,
    sibling_id: &str,
    sibling_epoch: u64,
    ev: DaemonEvent,
) {
    match ev {
        DaemonEvent::Grid { id, grid } => match sync.on_grid(&id, &grid) {
            Ok(outcome) => {
                if outcome.repaint
                    && shared.apply_sibling_grid(sibling_id, sibling_epoch, Arc::new(grid))
                {
                    wake(proxy);
                }
                if outcome.request_snapshot {
                    shared.send_request(&ClientRequest::Snapshot {
                        id: sibling_id.into(),
                    });
                }
            }
            Err(reason) => eprintln!("maestro-renderer: rejected sibling snapshot: {reason:?}"),
        },
        DaemonEvent::Damage { frame } => {
            // A damage frame can only apply against a baseline. The sibling's held grid
            // lives in the cache (not `shared.grid`); read it under the same id+epoch.
            if frame.id.as_str() != sibling_id {
                return;
            }
            let held = {
                let bound = shared.sibling_id.lock().unwrap();
                if bound.as_deref() != Some(sibling_id) {
                    return;
                }
                let stores = shared.stores.lock().unwrap();
                match stores.get(sibling_id) {
                    Some(entry)
                        if entry.kind == PaneKind::Sibling && entry.epoch == sibling_epoch =>
                    {
                        entry.grid.clone()
                    }
                    _ => return,
                }
            };
            let Some(held) = held else {
                // No sibling baseline yet — request one snapshot to seed the cache.
                if sync.on_resync_required(sibling_id).is_ok() {
                    shared.send_request(&ClientRequest::Snapshot {
                        id: sibling_id.into(),
                    });
                }
                return;
            };
            match sync.on_damage(&frame.id, &frame, &held) {
                DamageOutcome::Applied(grid) => {
                    if shared.apply_sibling_grid(sibling_id, sibling_epoch, Arc::from(grid)) {
                        wake(proxy);
                    }
                }
                DamageOutcome::Ignore => {}
                DamageOutcome::Resync { reason } => {
                    eprintln!(
                        "maestro-renderer: sibling damage not applicable ({reason:?}); resyncing"
                    );
                    if sync.on_resync_required(sibling_id).is_ok() {
                        shared.send_request(&ClientRequest::Snapshot {
                            id: sibling_id.into(),
                        });
                    }
                }
            }
        }
        DaemonEvent::ResyncRequired { id } => {
            if let Err(reason) = sync.on_resync_required(&id) {
                eprintln!("maestro-renderer: ignored sibling resync: {reason:?}");
            }
        }
        DaemonEvent::SessionExited { id, code } => {
            if let Ok(Action::Exited) = sync.on_session_exited(&id) {
                if shared.apply_sibling_exit(sibling_id, sibling_epoch, code) {
                    notify_session_exit(proxy, sibling_id, code, sync.accepted_generation());
                }
            }
        }
        DaemonEvent::ScrollbackRows {
            generation,
            revision,
            history_len,
            offset_from_top,
            rows,
            ..
        } => {
            if shared.apply_sibling_scrollback(
                sibling_id,
                sibling_epoch,
                generation,
                revision,
                history_len,
                offset_from_top,
                rows,
            ) {
                wake(proxy);
            }
        }
        DaemonEvent::TerminalBell { .. }
        | DaemonEvent::TerminalTitle { .. }
        | DaemonEvent::TerminalClipboardStore { .. }
        | DaemonEvent::Output { .. }
        | DaemonEvent::Error { .. }
        | DaemonEvent::Other => {}
    }
}

// ============================================================================
// Input encoding (pure, unit-testable). These functions PRODUCE bytes for
// the PTY; they do not parse output, so the "no second VT parser" rule does not
// apply here. Correct encoding depends on the terminal's current input modes,
// which the daemon owns and ships on every SnapshotV2.
// ============================================================================

/// The terminal input modes the encoder needs, mirrored from the latest accepted
/// `GridSnapshot`. The UI thread refreshes this whenever a grid is accepted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct TermModes {
    /// DECCKM: arrows/Home/End emit `\x1bO_` instead of `\x1b[_`.
    pub app_cursor: bool,
    /// Pasted text must be wrapped in `\x1b[200~`/`\x1b[201~`.
    pub bracketed_paste: bool,
    /// Window focus changes emit `\x1b[I` (in) / `\x1b[O` (out).
    pub focus_reporting: bool,
    /// Mouse modes (click/drag/motion/SGR) the app has enabled.
    pub mouse: MouseModes,
}

/// The mouse-reporting modes the terminal app has requested, mirrored from the daemon
/// snapshot. Drives whether a click/drag/wheel is encoded as a PTY mouse report (so TUIs
/// like vim, htop, tmux receive mouse input) instead of being consumed as local selection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct MouseModes {
    /// DECSET 1000: report button press/release.
    pub report: bool,
    /// DECSET 1002: also report motion while a button is held (button-drag tracking).
    pub drag: bool,
    /// DECSET 1003: report motion even with no button held (any-motion tracking).
    pub motion: bool,
    /// DECSET 1006: SGR encoding (`\x1b[<b;x;yM`/`m`) instead of legacy X10 byte-triple.
    pub sgr: bool,
}

impl MouseModes {
    /// Is ANY button-event reporting active? When false, mouse events are local-only
    /// (selection/scroll) and never sent to the PTY.
    pub fn any(&self) -> bool {
        self.report || self.drag || self.motion
    }
}

impl TermModes {
    pub fn from_snapshot(g: &GridSnapshot) -> Self {
        TermModes {
            app_cursor: g.app_cursor,
            bracketed_paste: g.bracketed_paste,
            focus_reporting: g.focus_reporting,
            mouse: MouseModes {
                report: g.mouse_report,
                drag: g.mouse_drag,
                motion: g.mouse_motion,
                sgr: g.mouse_sgr,
            },
        }
    }
}

/// Abstracts clipboard access so the platform surface (arboard) is isolated and
/// tests can inject a fake. `read_text` returns `None` when the clipboard is
/// empty, holds non-text, or the read errors (errors are non-fatal — log+None).
#[cfg(any(not(target_os = "linux"), test))]
pub trait Clipboard {
    fn read_text(&mut self) -> Option<String>;
    /// Write text to the clipboard. Returns `true` on success; errors are
    /// non-fatal (log + `false`) so a copy never crashes the renderer.
    fn write_text(&mut self, text: String) -> bool;
}

/// macOS clipboard backed by `arboard`. Linux deliberately does not compile this
/// backend: arboard's text-only Unix configuration is X11-only, while the Linux
/// DashboardHost uses GTK's native asynchronous Wayland/X11 clipboard service.
#[cfg(not(target_os = "linux"))]
pub struct SystemClipboard {
    inner: Option<arboard::Clipboard>,
}

#[cfg(not(target_os = "linux"))]
impl SystemClipboard {
    pub fn new() -> Self {
        let inner = match arboard::Clipboard::new() {
            Ok(c) => Some(c),
            Err(e) => {
                eprintln!("maestro-renderer: clipboard unavailable: {e}");
                None
            }
        };
        SystemClipboard { inner }
    }
}

#[cfg(not(target_os = "linux"))]
impl Default for SystemClipboard {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(not(target_os = "linux"))]
impl Clipboard for SystemClipboard {
    fn read_text(&mut self) -> Option<String> {
        let cb = self.inner.as_mut()?;
        match cb.get_text() {
            Ok(t) => Some(t),
            Err(e) => {
                eprintln!("maestro-renderer: clipboard read failed: {e}");
                None
            }
        }
    }

    fn write_text(&mut self, text: String) -> bool {
        let Some(cb) = self.inner.as_mut() else {
            return false;
        };
        match cb.set_text(text) {
            Ok(()) => true,
            Err(e) => {
                eprintln!("maestro-renderer: clipboard write failed: {e}");
                false
            }
        }
    }
}

/// Encode a key press into the bytes to send to the PTY, honoring the terminal's
/// current modes. Returns `None` when nothing should be sent (e.g. a Command/Super
/// shortcut, or a key with no PTY meaning). Call only on `ElementState::Pressed`.
///
/// `text` is the OS-composed text for the event (reflects Shift/AltGr, and on macOS
/// the Option-composed glyph). `base_text` is the key WITHOUT modifiers applied —
/// on macOS this is what recovers `b` from Option-b (whose `text` is the glyph `∫`).
/// It comes from winit's `key_without_modifiers()`; when unavailable, pass `None`.
///
/// Order matters: platform-shortcut suppression comes first — when Super/Command is
/// held we never leak printable input into the PTY, so Cmd-C/V/W behave as app
/// shortcuts. Then Ctrl chords, then mode-aware named keys, then Alt/Option-as-Meta
/// (ESC prefix), then plain printable text.
pub fn encode_key(
    key: &HostKey,
    text: Option<&str>,
    base_text: Option<&str>,
    mods: &HostModifiers,
    modes: TermModes,
) -> Option<String> {
    // Command/Super suppresses PTY encoding entirely. Application shortcut
    // handling (copy/paste/close) precedes the terminal.
    if mods.super_key {
        return None;
    }

    // Ctrl chords: control characters from letters and a handful of symbols.
    if mods.control {
        if let HostKey::Character(s) = key {
            if let Some(b) = ctrl_byte(s.as_str()) {
                return Some((b as char).to_string());
            }
        }
        if let HostKey::Named(HostNamedKey::Space) = key {
            return Some("\u{0}".to_string());
        }
    }

    // Named keys. Arrows + Home/End are mode-dependent (DECCKM); the rest are not.
    if let HostKey::Named(named) = key {
        if let Some(seq) = encode_named(*named, modes.app_cursor, mods) {
            return Some(seq);
        }
    }

    // Alt/Option-as-Meta: emit ESC + the base printable so Option-b -> ESC b for
    // readline word-motion etc. We use `base_text` (the key with NO modifiers)
    // rather than `text`, because on macOS `text` is the Option-composed glyph
    // (Option-b -> `∫`) — sending that would defeat the purpose. We DELIBERATELY
    // do not guess a base from the composed glyph: if `base_text` is absent or not
    // a single printable char, the Alt branch falls through (the OS text path may
    // still emit the glyph, matching prior behavior). Super and Ctrl are handled
    // above, so this only fires for Alt without those; Alt+named keys (arrows, etc.)
    // already returned from `encode_named` and never reach here.
    if mods.alt {
        if let Some(c) = single_printable(base_text) {
            let mut out = String::with_capacity(1 + c.len_utf8());
            out.push('\u{1b}');
            out.push(c);
            return Some(out);
        }
    }

    // Printable text last. The OS-provided `text` already reflects Shift/AltGr.
    if let Some(s) = text {
        if !s.is_empty() {
            return Some(s.to_string());
        }
    }

    None
}

/// Return the single character of `s` if it is exactly one non-control character,
/// else `None`. Used to gate Alt-as-Meta: we only ESC-prefix a real printable base
/// key, never a multi-char string or a control char.
fn single_printable(s: Option<&str>) -> Option<char> {
    let s = s?;
    let mut chars = s.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return None; // more than one char: not a simple printable key
    }
    if c.is_control() {
        return None;
    }
    Some(c)
}

/// Map a single-character `Key::Character` to its Ctrl control byte, or `None`
/// if it is not a recognized Ctrl chord. Ctrl-A..Z = 0x01..0x1a; the symbol
/// chords cover `[ \ ] ^ _` (0x1b..0x1f); Ctrl-Space (0x00) is handled by caller.
fn ctrl_byte(s: &str) -> Option<u8> {
    let mut chars = s.chars();
    let c = chars.next()?;
    if chars.next().is_some() {
        return None; // multi-char string is not a Ctrl chord
    }
    match c {
        'a'..='z' => Some((c as u8) & 0x1f),
        'A'..='Z' => Some((c.to_ascii_lowercase() as u8) & 0x1f),
        ' ' => Some(0x00),
        '[' => Some(0x1b),
        '\\' => Some(0x1c),
        ']' => Some(0x1d),
        '^' => Some(0x1e),
        '_' => Some(0x1f),
        _ => None,
    }
}

/// Xterm's modifier parameter: 1 + Shift + 2*Alt + 4*Ctrl.
fn xterm_modifier(mods: &HostModifiers) -> u8 {
    1 + u8::from(mods.shift) + 2 * u8::from(mods.alt) + 4 * u8::from(mods.control)
}

/// Encode terminal named keys using the xterm-256color contract advertised to
/// child processes. This includes the function keys used heavily by htop/mc and
/// modifier-aware CSI sequences used by editors and shells.
fn encode_named(named: HostNamedKey, app_cursor: bool, mods: &HostModifiers) -> Option<String> {
    let modifier = xterm_modifier(mods);
    let modified = modifier != 1;
    let literal = |s: &'static str| Some(s.to_string());

    match named {
        HostNamedKey::Enter => literal("\r"),
        HostNamedKey::Tab if mods.shift && !mods.alt && !mods.control => literal("\x1b[Z"),
        HostNamedKey::Tab => literal("\t"),
        HostNamedKey::Backspace => literal("\x7f"),
        HostNamedKey::Escape => literal("\x1b"),
        HostNamedKey::ArrowUp => {
            if modified {
                Some(format!("\x1b[1;{modifier}A"))
            } else if app_cursor {
                literal("\x1bOA")
            } else {
                literal("\x1b[A")
            }
        }
        HostNamedKey::ArrowDown => {
            if modified {
                Some(format!("\x1b[1;{modifier}B"))
            } else if app_cursor {
                literal("\x1bOB")
            } else {
                literal("\x1b[B")
            }
        }
        HostNamedKey::ArrowRight => {
            if modified {
                Some(format!("\x1b[1;{modifier}C"))
            } else if app_cursor {
                literal("\x1bOC")
            } else {
                literal("\x1b[C")
            }
        }
        HostNamedKey::ArrowLeft => {
            if modified {
                Some(format!("\x1b[1;{modifier}D"))
            } else if app_cursor {
                literal("\x1bOD")
            } else {
                literal("\x1b[D")
            }
        }
        HostNamedKey::Home => {
            if modified {
                Some(format!("\x1b[1;{modifier}H"))
            } else if app_cursor {
                literal("\x1bOH")
            } else {
                literal("\x1b[H")
            }
        }
        HostNamedKey::End => {
            if modified {
                Some(format!("\x1b[1;{modifier}F"))
            } else if app_cursor {
                literal("\x1bOF")
            } else {
                literal("\x1b[F")
            }
        }
        HostNamedKey::Insert => Some(if modified {
            format!("\x1b[2;{modifier}~")
        } else {
            "\x1b[2~".to_string()
        }),
        HostNamedKey::Delete => Some(if modified {
            format!("\x1b[3;{modifier}~")
        } else {
            "\x1b[3~".to_string()
        }),
        HostNamedKey::PageUp => Some(if modified {
            format!("\x1b[5;{modifier}~")
        } else {
            "\x1b[5~".to_string()
        }),
        HostNamedKey::PageDown => Some(if modified {
            format!("\x1b[6;{modifier}~")
        } else {
            "\x1b[6~".to_string()
        }),
        HostNamedKey::F1 | HostNamedKey::F2 | HostNamedKey::F3 | HostNamedKey::F4 => {
            let final_byte = match named {
                HostNamedKey::F1 => 'P',
                HostNamedKey::F2 => 'Q',
                HostNamedKey::F3 => 'R',
                _ => 'S',
            };
            Some(if modified {
                format!("\x1b[1;{modifier}{final_byte}")
            } else {
                format!("\x1bO{final_byte}")
            })
        }
        HostNamedKey::F5
        | HostNamedKey::F6
        | HostNamedKey::F7
        | HostNamedKey::F8
        | HostNamedKey::F9
        | HostNamedKey::F10
        | HostNamedKey::F11
        | HostNamedKey::F12 => {
            let code = match named {
                HostNamedKey::F5 => 15,
                HostNamedKey::F6 => 17,
                HostNamedKey::F7 => 18,
                HostNamedKey::F8 => 19,
                HostNamedKey::F9 => 20,
                HostNamedKey::F10 => 21,
                HostNamedKey::F11 => 23,
                _ => 24,
            };
            Some(if modified {
                format!("\x1b[{code};{modifier}~")
            } else {
                format!("\x1b[{code}~")
            })
        }
        _ => None,
    }
}

/// Hard cap on the bytes we will forward from a single paste. A hostile or
/// runaway clipboard must not be able to shove an unbounded write at the PTY in
/// one frame; the payload is truncated (on a UTF-8 char boundary) to this many
/// bytes after sanitizing. 1 MiB matches the outbound queue's per-frame budget.
pub const MAX_PASTE_BYTES: usize = 1024 * 1024;

/// Build the bytes for a paste of `raw` clipboard text under the current modes.
/// Returns `None` (send nothing) when the text is empty after sanitizing.
///
/// Sanitizing, in order:
/// - NUL bytes are stripped (terminals reject them).
/// - In `bracketed_paste` mode the clipboard could itself contain the literal
///   bracketed-paste markers `\x1b[200~`/`\x1b[201~`. A clipboard-supplied
///   `\x1b[201~` would prematurely close OUR wrapper, letting everything after
///   it be interpreted as keystrokes/commands rather than pasted data — a
///   classic paste-injection. We therefore strip any embedded `\x1b[200~` and
///   `\x1b[201~` so the wrapper we add is the ONLY pair the terminal sees.
///   Stripping runs to a FIXPOINT: a single non-overlapping `str::replace`
///   pass is not idempotent, so a nested payload like `\x1b[201\x1b[201~~`
///   would reconstitute a live `\x1b[201~` after one pass. We loop until no
///   marker remains.
/// - The result is truncated to `MAX_PASTE_BYTES` on a char boundary.
///
/// All other Unicode and newlines are preserved. Under `bracketed_paste` the
/// final result is wrapped EXACTLY once with `\x1b[200~` … `\x1b[201~`. The
/// caller emits this as ONE atomic `Write`.
pub fn encode_paste(raw: &str, bracketed_paste: bool) -> Option<String> {
    let mut cleaned: String = raw.chars().filter(|&c| c != '\0').collect();
    if bracketed_paste {
        loop {
            let stripped = cleaned.replace("\x1b[200~", "").replace("\x1b[201~", "");
            if stripped.len() == cleaned.len() {
                cleaned = stripped;
                break;
            }
            cleaned = stripped;
        }
    }
    if cleaned.len() > MAX_PASTE_BYTES {
        let mut end = MAX_PASTE_BYTES;
        while end > 0 && !cleaned.is_char_boundary(end) {
            end -= 1;
        }
        cleaned.truncate(end);
    }
    if cleaned.is_empty() {
        return None;
    }
    if bracketed_paste {
        Some(format!("\x1b[200~{cleaned}\x1b[201~"))
    } else {
        Some(cleaned)
    }
}

/// Read the clipboard once and produce the single paste payload to write, or
/// `None` if there is nothing to send (empty/unavailable clipboard). Errors are
/// already swallowed by the `Clipboard` impl. Never simulates paste as key events.
#[cfg(any(not(target_os = "linux"), test))]
pub fn paste_payload(clipboard: &mut dyn Clipboard, modes: TermModes) -> Option<String> {
    let raw = clipboard.read_text()?;
    encode_paste(&raw, modes.bracketed_paste)
}

/// Focus change encoding: `\x1b[I` on focus-in, `\x1b[O` on focus-out, but
/// ONLY when focus-reporting mode is enabled; otherwise send nothing.
pub fn encode_focus(focused: bool, modes: TermModes) -> Option<String> {
    if !modes.focus_reporting {
        return None;
    }
    Some(if focused { "\x1b[I" } else { "\x1b[O" }.to_string())
}

/// Direction of a command-palette overlay selection move. The overlay is a foreground modal: while
/// visible, unmodified Up/Down arrows move the highlighted action row and every key is consumed so
/// none reaches the PTY, scrollback, or copy/paste shortcuts (the consume policy lives in the caller;
/// this enum only names the two navigation directions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CommandPaletteNavKey {
    Up,
    Down,
}

/// Compute the next selected LINE index for command-palette overlay navigation, or `None` when the
/// selection would not change (so the caller can skip the redraw). Pure so it is unit-testable without
/// a window or GPU.
///
/// `lines` are the composed overlay lines; only `selectable` lines (action rows) are navigable —
/// title/query header and the empty-state line are skipped. The returned `usize` is an index INTO
/// `lines` (not into the action-row sub-sequence), so the caller can flip `selected` flags directly.
///
/// Behavior:
/// - With no selectable lines: always `None` (keys are still consumed by the caller, but nothing moves).
/// - `Down` advances to the next selectable line, wrapping the last selectable line to the first.
/// - `Up` retreats to the previous selectable line, wrapping the first selectable line to the last.
/// - When no line is currently `selected` (missing selection) but selectable lines exist, `Down`
///   selects the FIRST selectable line and `Up` selects the LAST.
/// - When the move lands on the line that is already selected (e.g. a single selectable line, which
///   wraps onto itself), returns `None` — no change, no redraw.
pub fn command_palette_nav(
    lines: &[crate::RendererCommandPaletteOverlayLine],
    key: CommandPaletteNavKey,
) -> Option<usize> {
    let selectable: Vec<usize> = lines
        .iter()
        .enumerate()
        .filter(|(_, l)| l.selectable)
        .map(|(i, _)| i)
        .collect();
    if selectable.is_empty() {
        return None;
    }

    // Position of the currently-selected line within `selectable` (if any selectable line is
    // selected). A `selected` flag on a non-selectable line is ignored by construction.
    let current = lines
        .iter()
        .position(|l| l.selectable && l.selected)
        .and_then(|line_idx| selectable.iter().position(|&i| i == line_idx));

    let next_pos = match (current, key) {
        // Missing selection: Down -> first selectable, Up -> last selectable.
        (None, CommandPaletteNavKey::Down) => 0,
        (None, CommandPaletteNavKey::Up) => selectable.len() - 1,
        (Some(pos), CommandPaletteNavKey::Down) => (pos + 1) % selectable.len(),
        (Some(pos), CommandPaletteNavKey::Up) => (pos + selectable.len() - 1) % selectable.len(),
    };

    let next_line = selectable[next_pos];
    // No-op move (single selectable wrapping onto itself, or already there): report no change.
    if current == Some(next_pos) {
        return None;
    }
    Some(next_line)
}

/// Pure key policy for the command-palette overlay's modal Escape: return `true` only when an
/// UNMODIFIED `Escape` should dismiss the overlay. Modified `Escape` (any of Ctrl/Alt/Super/Shift held)
/// is swallowed by the modal but must NOT dismiss, so this returns `false` for it. The caller still
/// consumes the key regardless of this result — this helper only decides the dismiss action, mirroring
/// `command_palette_nav`'s split of policy (here) from consumption (the caller). Pure so it is
/// unit-testable without a window.
pub fn command_palette_escape_dismisses(is_escape: bool, any_modifier_held: bool) -> bool {
    is_escape && !any_modifier_held
}

/// Which mouse button a report concerns. The numeric values are the low 2 bits of the
/// xterm button byte: left=0, middle=1, right=2. Wheel up/down are encoded separately
/// (bit 6 set, codes 64/65) and have no `MouseButton`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseButton {
    Left,
    Middle,
    Right,
}

impl MouseButton {
    fn code(self) -> u8 {
        match self {
            MouseButton::Left => 0,
            MouseButton::Middle => 1,
            MouseButton::Right => 2,
        }
    }
}

/// A normalized mouse interaction to (maybe) report to the PTY. The renderer maps winit
/// events to these; `encode_mouse` turns them into the xterm wire sequence under the
/// active mouse modes. `Move` carries the button held during a drag (`None` if no button).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MouseEvent {
    Press(MouseButton),
    Release(MouseButton),
    /// Pointer motion to a new cell. `held` is the button down during the motion, if any.
    Move {
        held: Option<MouseButton>,
    },
    WheelUp,
    WheelDown,
}

/// Encode a mouse event into the bytes to send to the PTY, honoring the active mouse modes
/// and modifier keys. Returns `None` when nothing should be reported:
///
/// - no button-event mode active (`!modes.mouse.any()`),
/// - a bare `Move` while only click-reporting (1000) is on (motion requires 1002/1003),
/// - a no-button `Move` while only button-drag (1002) is on (1002 reports motion only
///   while a button is held; any-motion needs 1003),
/// - legacy (non-SGR) coordinates/buttons whose `value + 32` would exceed 127 — see below.
///
/// WIRE BYTE-SAFETY: `Write.data` is a JSON String carried as UTF-8, and the daemon writes
/// `data.into_bytes()` (the UTF-8 encoding) to the PTY. SGR (1006) reports are pure ASCII,
/// so they always round-trip as single bytes. Legacy X10 reports use raw bytes `value + 32`;
/// any byte ≥ 128 would be re-encoded by UTF-8 into TWO bytes and corrupt the report. We
/// therefore only emit a legacy report when every byte stays ≤ 127 (cells 1..=95); beyond
/// that, or when the app has not negotiated SGR, we drop the report rather than send garbage.
/// Essentially all modern TUIs negotiate SGR (1006), so this limit is rarely hit in practice.
///
/// `col`/`row` are 0-based cell coordinates; the wire format is 1-based. `shift`/`alt`/
/// `ctrl` set the xterm modifier bits (4/8/16). Pure and unit-tested.
pub fn encode_mouse(
    event: MouseEvent,
    col: usize,
    row: usize,
    modes: TermModes,
    shift: bool,
    alt: bool,
    ctrl: bool,
) -> Option<String> {
    let m = modes.mouse;
    if !m.any() {
        return None;
    }

    // Resolve the base button code and whether this is a release (only meaningful for the
    // legacy/X10 path, where release is button 3 / `m` in SGR).
    let (base, is_release) = match event {
        MouseEvent::Press(b) => (b.code(), false),
        MouseEvent::Release(b) => (b.code(), true),
        MouseEvent::WheelUp => (64, false),
        MouseEvent::WheelDown => (65, false),
        MouseEvent::Move { held } => {
            // Motion is only reported under 1002 (button held) or 1003 (any motion).
            if !m.drag && !m.motion {
                return None;
            }
            match held {
                // Button held: 1002 (drag) or 1003 (motion) both report it. The motion
                // flag (bit 5 = 32) is added; the low 2 bits identify the button.
                Some(b) => (b.code() + 32, false),
                // No-button motion requires any-motion mode (1003). 3 = "no button".
                None => {
                    if !m.motion {
                        return None;
                    }
                    (3 + 32, false)
                }
            }
        }
    };

    // Modifier bits: shift=4, alt(meta)=8, ctrl=16.
    let mods = (shift as u8) * 4 + (alt as u8) * 8 + (ctrl as u8) * 16;
    let cb = base | mods;

    // Wire coordinates are 1-based.
    let x = col.saturating_add(1);
    let y = row.saturating_add(1);

    if m.sgr {
        // SGR (1006): `\x1b[<cb;x;y` then `M` (press/motion/wheel) or `m` (release).
        let final_byte = if is_release { 'm' } else { 'M' };
        Some(format!("\x1b[<{cb};{x};{y}{final_byte}"))
    } else {
        // Legacy X10: `\x1b[M` + 3 bytes (cb+32, x+32, y+32). Release is button 3 (low 2
        // bits = 3), keeping the motion/modifier bits.
        let cb_legacy = if is_release { (cb & !0b11) | 0b11 } else { cb };
        // Byte-safety: each `value + 32` must stay ASCII (≤ 127) or UTF-8 would split it
        // into two bytes on the wire and corrupt the report. That caps cells at 95.
        let bb = 32usize + cb_legacy as usize;
        let bx = 32usize + x;
        let by = 32usize + y;
        if bb > 127 || bx > 127 || by > 127 {
            return None;
        }
        let bytes = [0x1b, b'[', b'M', bb as u8, bx as u8, by as u8];
        Some(bytes.iter().map(|&b| b as char).collect())
    }
}

/// Upper bound on a dimension we will claim. Mirrors the daemon's `MAX_DIMENSION`
/// (pty-daemon grid.rs): the daemon clamps anyway, but the renderer must not claim
/// a geometry the daemon will silently reduce, or our painted grid and the PTY
/// would disagree on size.
pub const MAX_DIMENSION: u16 = 2000;

/// Legacy convenience wrapper for computing daemon `(cols, rows)` from physical window and cell
/// dimensions while reserving one chrome row. New runtime paths whose visible chrome is dynamic use
/// [`compute_dims_with_chrome_rows`] directly so daemon geometry matches the rows actually painted.
/// Result is clamped to `[1, MAX_DIMENSION]` so neither dimension is ever 0 (a 1px window) nor
/// exceeds the daemon's cap.
#[cfg_attr(not(test), allow(dead_code))]
pub fn compute_dims(phys_w: f32, phys_h: f32, cell_phys_w: f32, cell_phys_h: f32) -> (u16, u16) {
    // Preserve this helper's historical one-row contract for legacy callers and focused tests.
    compute_dims_with_chrome_rows(phys_w, phys_h, cell_phys_w, cell_phys_h, 1)
}

/// Like [`compute_dims`], but reserves `chrome_rows` cell rows of height for renderer
/// chrome instead of hardcoding a single row. `compute_dims` delegates here with
/// `chrome_rows = 1` to preserve that wrapper's legacy contract. Each reserved chrome row removes
/// one cell row of terminal height WHEN the window is tall enough; the terminal still
/// keeps at least one row regardless. All math is in physical space (matching
/// `render()` and `compute_dims`); the result is clamped to `[1, MAX_DIMENSION]`.
///
/// This is a PURE geometry helper: it reserves only the row count supplied by the caller and does
/// not itself decide which chrome is visible or draw any chrome.
pub fn compute_dims_with_chrome_rows(
    phys_w: f32,
    phys_h: f32,
    cell_phys_w: f32,
    cell_phys_h: f32,
    chrome_rows: u16,
) -> (u16, u16) {
    // Degenerate cell metrics (renderer not ready) -> minimum viable grid.
    if cell_phys_w <= 0.0 || cell_phys_h <= 0.0 {
        return (1, 1);
    }
    let chrome_h = cell_phys_h * chrome_rows as f32;
    let terminal_h = (phys_h - chrome_h).max(cell_phys_h);
    let rows = (terminal_h / cell_phys_h).floor();
    let cols = (phys_w / cell_phys_w).floor();
    let clamp = |v: f32| -> u16 {
        if v < 1.0 {
            1
        } else if v > MAX_DIMENSION as f32 {
            MAX_DIMENSION
        } else {
            v as u16
        }
    };
    (clamp(cols), clamp(rows))
}

/// A grid cell coordinate (column, row), 0-based. Produced by hit-testing a
/// pixel position against the painted grid.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct CellPos {
    pub col: usize,
    pub row: usize,
}

/// Map a physical pixel position to the grid cell it falls in, clamped to the grid bounds
/// `[0, cols) x [0, rows)`. Callers that paint chrome outside those bounds must intercept that band
/// before calling this helper; otherwise any pixel below/right of the grid clamps to its last cell.
///
/// `cell_phys_w/h` are the physical cell metrics (logical * scale_factor). A
/// click left/above the grid clamps to `(0, 0)`; right/below clamps to the last
/// cell. Degenerate metrics or an empty grid yield `None`.
pub fn pixel_to_cell(
    x: f32,
    y: f32,
    cell_phys_w: f32,
    cell_phys_h: f32,
    cols: usize,
    rows: usize,
) -> Option<CellPos> {
    if cell_phys_w <= 0.0 || cell_phys_h <= 0.0 || cols == 0 || rows == 0 {
        return None;
    }
    let cx = (x.max(0.0) / cell_phys_w).floor() as usize;
    let cy = (y.max(0.0) / cell_phys_h).floor() as usize;
    Some(CellPos {
        col: cx.min(cols - 1),
        row: cy.min(rows - 1),
    })
}

/// Map a physical pixel position to a grid cell when the painted grid is translated DOWN by
/// `top_offset` physical pixels (the reserved top tab-bar row) and RIGHT by `left_offset` physical
/// pixels (the reserved left dock column). A pixel inside the top band (`y < top_offset`) or the left
/// dock (`x < left_offset`) belongs to renderer chrome, NOT the grid, so this returns `None` there
/// instead of clamping to row/col 0 — that lets the caller consume the click as chrome rather than
/// leaking it into selection or PTY mouse reporting. Inside the grid, both offsets are removed and
/// [`pixel_to_cell`] maps the remainder, so the first grid cell just past the chrome is (0,0). With
/// both offsets `== 0.0` this is exactly [`pixel_to_cell`].
#[allow(clippy::too_many_arguments)]
pub fn pixel_to_cell_with_top_offset(
    x: f32,
    y: f32,
    left_offset: f32,
    top_offset: f32,
    cell_phys_w: f32,
    cell_phys_h: f32,
    cols: usize,
    rows: usize,
) -> Option<CellPos> {
    if top_offset > 0.0 && y < top_offset {
        return None;
    }
    if left_offset > 0.0 && x < left_offset {
        return None;
    }
    pixel_to_cell(
        x - left_offset.max(0.0),
        y - top_offset.max(0.0),
        cell_phys_w,
        cell_phys_h,
        cols,
        rows,
    )
}

/// Extract the text covered by the selection `[anchor, focus]` (inclusive, order
/// independent) from the painted grid, row by row. Rows are joined with `'\n'`.
/// Per line, trailing blank cells are trimmed. Wide-spacer cells (`width == 0`)
/// are skipped — the lead cell already carries the glyph. Wide/combining glyphs
/// are preserved as-is (`Cell::text` holds the full grapheme).
///
/// The selection is row-major and contiguous: the first row starts at the
/// anchor column and runs to the row end; intermediate rows are full width; the
/// last row runs from the start to the focus column. A single-row selection runs
/// from the lower to the higher column on that row.
pub fn extract_selection(rows_cells: &[Vec<Cell>], anchor: CellPos, focus: CellPos) -> String {
    if rows_cells.is_empty() {
        return String::new();
    }
    let (start, end) = if (anchor.row, anchor.col) <= (focus.row, focus.col) {
        (anchor, focus)
    } else {
        (focus, anchor)
    };
    let last_row = rows_cells.len() - 1;
    let r0 = start.row.min(last_row);
    let r1 = end.row.min(last_row);

    let mut lines: Vec<String> = Vec::with_capacity(r1 - r0 + 1);
    for (r, row) in rows_cells.iter().enumerate().take(r1 + 1).skip(r0) {
        let ncols = row.len();
        if ncols == 0 {
            lines.push(String::new());
            continue;
        }
        let col_start = if r == r0 { start.col } else { 0 };
        let col_end = if r == r1 { end.col } else { ncols - 1 };
        let col_start = col_start.min(ncols - 1);
        let col_end = col_end.min(ncols - 1);

        let mut line = String::new();
        for cell in row.iter().take(col_end + 1).skip(col_start) {
            if cell.width == 0 {
                continue;
            }
            line.push_str(&cell.text);
        }
        lines.push(line.trim_end().to_string());
    }
    lines.join("\n")
}

/// Latest-wins resize throttle. A burst of distinct geometries during a drag
/// collapses to at most one send per `min_interval`, and the settled geometry is
/// always flushed by a trailing call. Time is injected (`now`) so the policy is
/// pure and unit-testable without a real clock or window.
#[derive(Debug, Default)]
pub struct ResizeCoalescer {
    pending: Option<(u16, u16)>,
    last_sent: Option<(u16, u16)>,
    last_sent_at: Option<std::time::Instant>,
}

impl ResizeCoalescer {
    /// Record a freshly computed target geometry. Dedups against the last sent
    /// size (no-op if unchanged) and overwrites any earlier pending value
    /// (latest-wins). Returns the geometry to send NOW if the interval allows,
    /// else `None` (it stays pending for a trailing `flush`).
    pub fn record(
        &mut self,
        dims: (u16, u16),
        now: std::time::Instant,
        min_interval: std::time::Duration,
    ) -> Option<(u16, u16)> {
        if Some(dims) == self.last_sent {
            self.pending = None;
            return None;
        }
        self.pending = Some(dims);
        self.flush(now, min_interval)
    }

    /// Send the pending geometry if `min_interval` has elapsed since the last send.
    /// Returns the geometry to send (the LATEST pending, not intermediates), or
    /// `None` if nothing is due. Call from the idle path for the trailing send.
    pub fn flush(
        &mut self,
        now: std::time::Instant,
        min_interval: std::time::Duration,
    ) -> Option<(u16, u16)> {
        let dims = self.pending?;
        let due = self
            .last_sent_at
            .map(|t| now.duration_since(t) >= min_interval)
            .unwrap_or(true);
        if !due {
            return None;
        }
        if Some(dims) == self.last_sent {
            self.pending = None;
            return None;
        }
        self.last_sent = Some(dims);
        self.last_sent_at = Some(now);
        self.pending = None;
        Some(dims)
    }

    /// Forget the last-sent geometry so the next `record` of the SAME window size is not deduped away.
    /// Used when the SPLIT geometry changes without a window resize (a tab split toggles, or the active
    /// pane switches sides): the window dims are unchanged but the active session must be re-sized to its
    /// new pane region. Leaves any pending value and the last-sent timestamp intact (the throttle still
    /// applies), so this only defeats the value-equality dedup, not the rate limit.
    pub fn invalidate_last_sent(&mut self) {
        self.last_sent = None;
    }

    /// Whether a geometry is still waiting for a trailing flush.
    pub fn has_pending(&self) -> bool {
        self.pending.is_some()
    }

    /// When the last send happened (drives the trailing-flush wake time).
    pub fn last_sent_at(&self) -> Option<std::time::Instant> {
        self.last_sent_at
    }
}

#[cfg(test)]
mod input_tests {
    use super::*;
    use std::time::{Duration, Instant};

    /// On the structured-only path a stray `Output` event must be ignored and
    /// must NOT enqueue a Snapshot request (which would resurrect the polling bridge).
    /// We drive the exact decision the Output arm makes and assert it produces no
    /// request, then confirm the outbound queue stays empty even if we route the
    /// (None) result through `send_request`'s call site.
    #[test]
    fn unexpected_output_requests_nothing_and_enqueues_nothing() {
        let (shared, queue) = Shared::with_test_queue();

        // The pure decision: a stray Output yields no follow-up request.
        assert!(
            on_structured_output(Revision(123)).is_none(),
            "structured-only Output must not trigger any request"
        );

        // Mirror the production call site: only enqueue if the helper returned Some.
        if let Some(req) = on_structured_output(Revision(123)) {
            shared.send_request(&req);
        }
        assert_eq!(
            queue.len(),
            0,
            "no request must be enqueued for an unexpected Output"
        );

        // Sanity: the queue DOES enqueue when something is actually sent — proves the
        // empty assertion above is meaningful, not a dead queue.
        shared.send_request(&ClientRequest::Snapshot {
            id: "s1".to_string(),
        });
        assert_eq!(queue.len(), 1, "a real request enqueues exactly one frame");
    }

    /// Build a command-palette overlay line for nav tests.
    fn cp_line(
        text: &str,
        selectable: bool,
        selected: bool,
    ) -> crate::RendererCommandPaletteOverlayLine {
        crate::RendererCommandPaletteOverlayLine {
            text: text.to_string(),
            selectable,
            selected,
            // Nav operates purely on the `selectable` flag; a placeholder index keeps selectable lines
            // realistic (every selectable action line carries `Some(_)`) without affecting nav results.
            action_index: if selectable { Some(0) } else { None },
        }
    }

    /// Title + two action rows; the first action row is selected.
    fn cp_lines_two_actions_first_selected() -> Vec<crate::RendererCommandPaletteOverlayLine> {
        vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, true),
            cp_line("New Workspace", true, false),
        ]
    }

    #[test]
    fn command_palette_nav_down_moves_first_action_to_second() {
        let lines = cp_lines_two_actions_first_selected();
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Down),
            Some(2)
        );
    }

    #[test]
    fn command_palette_nav_up_moves_second_action_to_first() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, false),
            cp_line("New Workspace", true, true),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Up),
            Some(1)
        );
    }

    #[test]
    fn command_palette_nav_down_wraps_last_action_to_first() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, false),
            cp_line("New Workspace", true, true),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Down),
            Some(1)
        );
    }

    #[test]
    fn command_palette_nav_up_wraps_first_action_to_last() {
        let lines = cp_lines_two_actions_first_selected();
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Up),
            Some(2)
        );
    }

    #[test]
    fn command_palette_nav_missing_selection_down_selects_first_action() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, false),
            cp_line("New Workspace", true, false),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Down),
            Some(1)
        );
    }

    #[test]
    fn command_palette_nav_missing_selection_up_selects_last_action() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, false),
            cp_line("New Workspace", true, false),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Up),
            Some(2)
        );
    }

    #[test]
    fn command_palette_nav_no_selectable_rows_reports_no_change() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("(no commands)", false, false),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Down),
            None
        );
        assert_eq!(command_palette_nav(&lines, CommandPaletteNavKey::Up), None);
    }

    #[test]
    fn command_palette_nav_single_selectable_row_reports_no_change() {
        let lines = vec![
            cp_line("Commands", false, false),
            cp_line("Open Project", true, true),
        ];
        assert_eq!(
            command_palette_nav(&lines, CommandPaletteNavKey::Down),
            None
        );
        assert_eq!(command_palette_nav(&lines, CommandPaletteNavKey::Up), None);
    }

    #[test]
    fn command_palette_unmodified_escape_dismisses() {
        // Unmodified Escape (no modifier held) is the dismiss trigger.
        assert!(command_palette_escape_dismisses(true, false));
    }

    #[test]
    fn command_palette_modified_escape_does_not_dismiss() {
        // Any modifier held (Ctrl/Alt/Super/Shift collapses to `true` at the call site) -> no dismiss.
        assert!(!command_palette_escape_dismisses(true, true));
    }

    #[test]
    fn command_palette_non_escape_key_does_not_dismiss() {
        // A non-Escape key never dismisses, regardless of modifiers.
        assert!(!command_palette_escape_dismisses(false, false));
        assert!(!command_palette_escape_dismisses(false, true));
    }

    /// Build a `HostModifiers` from bool flags for tests.
    fn host_mods(control: bool, alt: bool, shift: bool, super_key: bool) -> HostModifiers {
        HostModifiers {
            control,
            alt,
            shift,
            super_key,
        }
    }

    fn no_mods() -> HostModifiers {
        HostModifiers::default()
    }

    fn modes(app_cursor: bool, bracketed: bool, focus: bool) -> TermModes {
        TermModes {
            app_cursor,
            bracketed_paste: bracketed,
            focus_reporting: focus,
            mouse: MouseModes::default(),
        }
    }

    /// Build `TermModes` carrying only the given mouse modes (other modes off).
    fn mouse_modes(report: bool, drag: bool, motion: bool, sgr: bool) -> TermModes {
        TermModes {
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse: MouseModes {
                report,
                drag,
                motion,
                sgr,
            },
        }
    }

    struct FakeClipboard(Option<String>);
    impl Clipboard for FakeClipboard {
        fn read_text(&mut self) -> Option<String> {
            self.0.clone()
        }
        fn write_text(&mut self, text: String) -> bool {
            self.0 = Some(text);
            true
        }
    }

    #[test]
    fn super_key_suppresses_printable_input() {
        // Cmd-C / Cmd-V etc. must never leak into the PTY.
        let m = host_mods(false, false, false, true);
        let out = encode_key(
            &HostKey::Character("c".to_string()),
            Some("c"),
            Some("c"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(out, None, "Super-held printable must not encode");
    }

    #[test]
    fn unicode_text_round_trips_as_utf8() {
        let out = encode_key(
            &HostKey::Character("é".to_string()),
            Some("é"),
            Some("é"),
            &no_mods(),
            modes(false, false, false),
        );
        assert_eq!(out.as_deref(), Some("é"));
        assert_eq!(out.unwrap().as_bytes(), "é".as_bytes());
    }

    #[test]
    fn ctrl_letter_chords() {
        let m = host_mods(true, false, false, false);
        let c = encode_key(
            &HostKey::Character("c".to_string()),
            Some("c"),
            Some("c"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(c.as_deref(), Some("\u{3}"), "Ctrl-C = 0x03");
        let a = encode_key(
            &HostKey::Character("a".to_string()),
            Some("a"),
            Some("a"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(a.as_deref(), Some("\u{1}"), "Ctrl-A = 0x01");
    }

    #[test]
    fn ctrl_space_is_nul() {
        let m = host_mods(true, false, false, false);
        let out = encode_key(
            &HostKey::Named(HostNamedKey::Space),
            None,
            None,
            &m,
            modes(false, false, false),
        );
        assert_eq!(out.as_deref(), Some("\u{0}"));
    }

    #[test]
    fn arrows_respect_application_cursor_mode() {
        // Normal mode -> CSI sequences.
        let up = encode_key(
            &HostKey::Named(HostNamedKey::ArrowUp),
            None,
            None,
            &no_mods(),
            modes(false, false, false),
        );
        assert_eq!(up.as_deref(), Some("\x1b[A"));
        // Application cursor mode -> SS3 sequences.
        let up_app = encode_key(
            &HostKey::Named(HostNamedKey::ArrowUp),
            None,
            None,
            &no_mods(),
            modes(true, false, false),
        );
        assert_eq!(up_app.as_deref(), Some("\x1bOA"));
        // Home/End follow the same rule.
        let home = encode_key(
            &HostKey::Named(HostNamedKey::Home),
            None,
            None,
            &no_mods(),
            modes(false, false, false),
        );
        assert_eq!(home.as_deref(), Some("\x1b[H"));
        let home_app = encode_key(
            &HostKey::Named(HostNamedKey::Home),
            None,
            None,
            &no_mods(),
            modes(true, false, false),
        );
        assert_eq!(home_app.as_deref(), Some("\x1bOH"));
    }

    #[test]
    fn mode_independent_named_keys() {
        for (key, want) in [
            (HostNamedKey::Enter, "\r"),
            (HostNamedKey::Tab, "\t"),
            (HostNamedKey::Backspace, "\x7f"),
            (HostNamedKey::Escape, "\x1b"),
            (HostNamedKey::Delete, "\x1b[3~"),
            (HostNamedKey::PageUp, "\x1b[5~"),
        ] {
            let out = encode_key(
                &HostKey::Named(key),
                None,
                None,
                &no_mods(),
                modes(true, false, false),
            );
            assert_eq!(
                out.as_deref(),
                Some(want),
                "{key:?} should be mode-independent"
            );
        }
    }

    #[test]
    fn function_keys_match_xterm_sequences() {
        for (key, want) in [
            (HostNamedKey::F1, "\x1bOP"),
            (HostNamedKey::F2, "\x1bOQ"),
            (HostNamedKey::F3, "\x1bOR"),
            (HostNamedKey::F4, "\x1bOS"),
            (HostNamedKey::F5, "\x1b[15~"),
            (HostNamedKey::F10, "\x1b[21~"),
            (HostNamedKey::F12, "\x1b[24~"),
        ] {
            let out = encode_key(
                &HostKey::Named(key),
                None,
                None,
                &no_mods(),
                modes(false, false, false),
            );
            assert_eq!(out.as_deref(), Some(want), "{key:?}");
        }
    }

    #[test]
    fn modified_navigation_and_function_keys_match_xterm() {
        let ctrl = host_mods(true, false, false, false);
        let ctrl_up = encode_key(
            &HostKey::Named(HostNamedKey::ArrowUp),
            None,
            None,
            &ctrl,
            modes(true, false, false),
        );
        assert_eq!(ctrl_up.as_deref(), Some("\x1b[1;5A"));

        let shift = host_mods(false, false, true, false);
        let shift_tab = encode_key(
            &HostKey::Named(HostNamedKey::Tab),
            None,
            None,
            &shift,
            modes(false, false, false),
        );
        assert_eq!(shift_tab.as_deref(), Some("\x1b[Z"));

        let alt = host_mods(false, true, false, false);
        let alt_f5 = encode_key(
            &HostKey::Named(HostNamedKey::F5),
            None,
            None,
            &alt,
            modes(false, false, false),
        );
        assert_eq!(alt_f5.as_deref(), Some("\x1b[15;3~"));
    }

    /// Table-driven coverage of the xterm named-key contract (keyboard spec):
    /// F1–F12, Tab / Shift-Tab, Insert / Delete, and the plain/Shift/Alt/Ctrl
    /// modifier matrix on the arrows + Home/End. Every expected sequence is the
    /// literal output of the current encoder — no invented values.
    #[test]
    fn named_key_xterm_contract_table() {
        // --- Function keys, unmodified (SS3 for F1–F4, CSI ~ for F5–F12). ---
        for (named, want) in [
            (HostNamedKey::F1, "\x1bOP"),
            (HostNamedKey::F2, "\x1bOQ"),
            (HostNamedKey::F3, "\x1bOR"),
            (HostNamedKey::F4, "\x1bOS"),
            (HostNamedKey::F5, "\x1b[15~"),
            (HostNamedKey::F6, "\x1b[17~"),
            (HostNamedKey::F7, "\x1b[18~"),
            (HostNamedKey::F8, "\x1b[19~"),
            (HostNamedKey::F9, "\x1b[20~"),
            (HostNamedKey::F10, "\x1b[21~"),
            (HostNamedKey::F11, "\x1b[23~"),
            (HostNamedKey::F12, "\x1b[24~"),
        ] {
            let out = encode_named(named, false, &no_mods());
            assert_eq!(out.as_deref(), Some(want), "unmodified {named:?}");
        }

        // --- Tab and Shift-Tab (back-tab). ---
        assert_eq!(
            encode_named(HostNamedKey::Tab, false, &no_mods()).as_deref(),
            Some("\t"),
            "Tab -> \\t"
        );
        assert_eq!(
            encode_named(
                HostNamedKey::Tab,
                false,
                &host_mods(false, false, true, false)
            )
            .as_deref(),
            Some("\x1b[Z"),
            "Shift-Tab -> CSI Z"
        );

        // --- Insert / Delete (CSI 2 ~ / CSI 3 ~), mode-independent. ---
        assert_eq!(
            encode_named(HostNamedKey::Insert, false, &no_mods()).as_deref(),
            Some("\x1b[2~"),
            "Insert"
        );
        assert_eq!(
            encode_named(HostNamedKey::Delete, false, &no_mods()).as_deref(),
            Some("\x1b[3~"),
            "Delete"
        );

        // --- Modifier matrix on arrows + Home/End (app_cursor off). ---
        // Rows: (mods, xterm modifier param). plain=1, Shift=2, Alt=3, Ctrl=5.
        let plain = no_mods();
        let shift = host_mods(false, false, true, false);
        let alt = host_mods(false, true, false, false);
        let ctrl = host_mods(true, false, false, false);
        // (named, final byte)
        for (named, fin) in [
            (HostNamedKey::ArrowUp, 'A'),
            (HostNamedKey::ArrowDown, 'B'),
            (HostNamedKey::ArrowRight, 'C'),
            (HostNamedKey::ArrowLeft, 'D'),
            (HostNamedKey::Home, 'H'),
            (HostNamedKey::End, 'F'),
        ] {
            // Plain: bare CSI <final>.
            assert_eq!(
                encode_named(named, false, &plain).as_deref(),
                Some(format!("\x1b[{fin}").as_str()),
                "plain {named:?}"
            );
            // Modified: CSI 1 ; <param> <final>.
            for (m, param) in [(&shift, 2u8), (&alt, 3), (&ctrl, 5)] {
                assert_eq!(
                    encode_named(named, false, m).as_deref(),
                    Some(format!("\x1b[1;{param}{fin}").as_str()),
                    "modified {named:?} param {param}"
                );
            }
        }

        // --- Same matrix routed through encode_key (named keys are not swallowed
        //     by the Ctrl/Alt printable branches). ---
        assert_eq!(
            encode_key(
                &HostKey::Named(HostNamedKey::ArrowLeft),
                None,
                None,
                &ctrl,
                modes(false, false, false),
            )
            .as_deref(),
            Some("\x1b[1;5D"),
            "Ctrl-Left via encode_key"
        );
        assert_eq!(
            encode_key(
                &HostKey::Named(HostNamedKey::Home),
                None,
                None,
                &alt,
                modes(false, false, false),
            )
            .as_deref(),
            Some("\x1b[1;3H"),
            "Alt-Home via encode_key"
        );
    }

    #[test]
    fn alt_letter_emits_esc_prefix() {
        // macOS Option-b: `text`/logical_key carry the composed glyph `∫`, but the
        // base key (key_without_modifiers) is `b`. We must emit ESC + b, NOT `∫`.
        let m = host_mods(false, true, false, false);
        let b = encode_key(
            &HostKey::Character("∫".to_string()),
            Some("∫"),
            Some("b"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(b.as_deref(), Some("\x1bb"), "Alt-b -> ESC b");

        // Option-f: composed glyph is `ƒ`, base is `f`.
        let f = encode_key(
            &HostKey::Character("ƒ".to_string()),
            Some("ƒ"),
            Some("f"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(f.as_deref(), Some("\x1bf"), "Alt-f -> ESC f");
    }

    #[test]
    fn alt_unicode_base_emits_esc_plus_that_char() {
        // Decision: when the BASE key itself is a (single) non-ASCII printable, we
        // ESC-prefix that exact character. Meta-encoding is defined as ESC + the
        // intended key, and the intended key here is the base char, not ASCII-only.
        let m = host_mods(false, true, false, false);
        let out = encode_key(
            &HostKey::Character("é".to_string()),
            Some("é"),
            Some("é"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(out.as_deref(), Some("\x1bé"));
        assert_eq!(out.unwrap().as_bytes(), "\x1bé".as_bytes());
    }

    #[test]
    fn alt_without_base_text_does_not_guess() {
        // If winit gives us only the composed glyph and NO base text, we must NOT
        // guess a letter back from `∫`. The Alt branch falls through; the OS `text`
        // path emits the glyph as-is (prior behavior), never a fabricated ESC b.
        let m = host_mods(false, true, false, false);
        let out = encode_key(
            &HostKey::Character("∫".to_string()),
            Some("∫"),
            None,
            &m,
            modes(false, false, false),
        );
        assert_eq!(
            out.as_deref(),
            Some("∫"),
            "no base -> emit glyph, do not guess"
        );
    }

    #[test]
    fn ctrl_takes_precedence_over_alt() {
        // Ctrl-C must stay 0x03 even if Alt is also (spuriously) reported; it must
        // NOT become ESC + c. Ctrl chords are resolved before the Alt branch.
        let m = host_mods(true, true, false, false);
        let out = encode_key(
            &HostKey::Character("c".to_string()),
            Some("c"),
            Some("c"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(out.as_deref(), Some("\u{3}"), "Ctrl wins: 0x03, not ESC c");
    }

    #[test]
    fn super_takes_precedence_over_alt() {
        // Cmd held (even with Alt) still suppresses PTY input entirely.
        let m = host_mods(false, true, false, true);
        let out = encode_key(
            &HostKey::Character("∫".to_string()),
            Some("∫"),
            Some("b"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(out, None, "Super suppresses, even with Alt");
    }

    #[test]
    fn plain_text_unchanged_without_alt() {
        // No Alt: a normal letter is emitted verbatim, never ESC-prefixed.
        let out = encode_key(
            &HostKey::Character("b".to_string()),
            Some("b"),
            Some("b"),
            &no_mods(),
            modes(false, false, false),
        );
        assert_eq!(out.as_deref(), Some("b"));
    }

    #[test]
    fn paste_normal_mode_is_raw() {
        let out = encode_paste("hello\nworld", false);
        assert_eq!(out.as_deref(), Some("hello\nworld"), "normal paste is raw");
    }

    #[test]
    fn paste_bracketed_wraps_exactly_once() {
        let out = encode_paste("hi", true).unwrap();
        assert_eq!(out, "\x1b[200~hi\x1b[201~");
        // Exactly one wrapping: the markers appear once each.
        assert_eq!(out.matches("\x1b[200~").count(), 1);
        assert_eq!(out.matches("\x1b[201~").count(), 1);
    }

    #[test]
    fn paste_strips_nul_preserves_unicode_and_newlines() {
        let out = encode_paste("a\0b\nça\0", false).unwrap();
        assert_eq!(out, "ab\nça", "NUL stripped; Unicode + newline preserved");
    }

    #[test]
    fn paste_empty_or_all_nul_sends_nothing() {
        assert_eq!(encode_paste("", false), None);
        assert_eq!(
            encode_paste("\0\0", true),
            None,
            "all-NUL collapses to empty -> None"
        );
    }

    #[test]
    fn paste_bracketed_strips_embedded_terminator_injection() {
        // A hostile clipboard embeds a literal ESC[201~ to escape our wrapper.
        // After sanitizing, only the single wrapper we add may remain.
        let out = encode_paste("rm -rf /\x1b[201~malicious", true).unwrap();
        assert_eq!(
            out, "\x1b[200~rm -rf /malicious\x1b[201~",
            "embedded terminator stripped; one wrapper only"
        );
        assert_eq!(
            out.matches("\x1b[201~").count(),
            1,
            "exactly one terminator"
        );
        assert_eq!(
            out.matches("\x1b[200~").count(),
            1,
            "exactly one introducer"
        );
    }

    #[test]
    fn paste_bracketed_strips_embedded_introducer_injection() {
        let out = encode_paste("a\x1b[200~b", true).unwrap();
        assert_eq!(out, "\x1b[200~ab\x1b[201~");
        assert_eq!(out.matches("\x1b[200~").count(), 1);
    }

    #[test]
    fn paste_bracketed_strips_nested_reconstituting_terminator() {
        // A single non-overlapping replace pass is not idempotent: removing the
        // inner ESC[201~ from ESC[201<ESC[201~>~ leaves a fresh live ESC[201~.
        // The fixpoint loop must keep stripping until none remains, so the only
        // terminator the terminal sees is the one wrapper we add.
        let out = encode_paste("before\x1b[201\x1b[201~~after", true).unwrap();
        assert!(
            out.starts_with("\x1b[200~") && out.ends_with("\x1b[201~"),
            "wrapped exactly by our markers"
        );
        let inner = &out["\x1b[200~".len()..out.len() - "\x1b[201~".len()];
        assert!(
            !inner.contains("\x1b[201~"),
            "no terminator survives inside the wrapper after fixpoint strip"
        );
        assert_eq!(
            out.matches("\x1b[201~").count(),
            1,
            "exactly one terminator overall"
        );
    }

    #[test]
    fn paste_bracketed_strips_nested_reconstituting_introducer() {
        // Same reconstitution trick for the introducer ESC[200~.
        let out = encode_paste("x\x1b[200\x1b[200~~y", true).unwrap();
        assert_eq!(
            out.matches("\x1b[200~").count(),
            1,
            "only our single introducer remains"
        );
        let inner = &out["\x1b[200~".len()..out.len() - "\x1b[201~".len()];
        assert!(
            !inner.contains("\x1b[200~"),
            "no introducer survives inside the wrapper after fixpoint strip"
        );
    }

    #[test]
    fn paste_normal_mode_does_not_strip_markers() {
        // Outside bracketed mode there is no wrapper to protect, so leave the
        // bytes verbatim — stripping would corrupt legitimate content.
        let out = encode_paste("x\x1b[201~y", false).unwrap();
        assert_eq!(out, "x\x1b[201~y");
    }

    #[test]
    fn paste_caps_oversized_payload_on_char_boundary() {
        // Multi-byte chars so truncation must land on a boundary, never split.
        let big = "é".repeat(MAX_PASTE_BYTES); // 2 bytes each -> 2x the cap
        let out = encode_paste(&big, false).unwrap();
        assert!(out.len() <= MAX_PASTE_BYTES, "truncated to the cap");
        assert!(out.chars().all(|c| c == 'é'), "no split/replacement chars");
    }

    #[test]
    fn paste_payload_reads_clipboard_once_and_wraps() {
        let mut cb = FakeClipboard(Some("x".into()));
        let out = paste_payload(&mut cb, modes(false, true, false));
        assert_eq!(out.as_deref(), Some("\x1b[200~x\x1b[201~"));
    }

    #[test]
    fn paste_payload_unavailable_clipboard_sends_nothing() {
        let mut cb = FakeClipboard(None);
        assert_eq!(paste_payload(&mut cb, modes(false, true, false)), None);
    }

    #[test]
    fn focus_only_when_reporting_enabled() {
        // Disabled: nothing on either transition.
        assert_eq!(encode_focus(true, modes(false, false, false)), None);
        assert_eq!(encode_focus(false, modes(false, false, false)), None);
        // Enabled: in/out sequences.
        assert_eq!(
            encode_focus(true, modes(false, false, true)).as_deref(),
            Some("\x1b[I")
        );
        assert_eq!(
            encode_focus(false, modes(false, false, true)).as_deref(),
            Some("\x1b[O")
        );
    }

    #[test]
    fn tiny_window_clamps_to_one_by_one() {
        // A 1px window with sane cell metrics must never claim a 0 dimension.
        let (cols, rows) = compute_dims(1.0, 1.0, 9.0, 20.0);
        assert_eq!((cols, rows), (1, 1));
    }

    #[test]
    fn degenerate_cell_metrics_clamp_to_one_by_one() {
        // Renderer not ready (zero cell size) -> minimum viable grid, not a divide.
        assert_eq!(compute_dims(800.0, 600.0, 0.0, 0.0), (1, 1));
    }

    #[test]
    fn fractional_dpi_computes_consistent_integers() {
        // Logical cell 9x20 at scale 1.5 -> physical cell 13.5x30. An 1080x720
        // physical window: cols = floor(1080/13.5)=80; rows = floor((720-30)/30)=23.
        let scale = 1.5_f32;
        let (cw, ch) = (9.0 * scale, 20.0 * scale);
        let (cols, rows) = compute_dims(1080.0, 720.0, cw, ch);
        assert_eq!((cols, rows), (80, 23));
    }

    #[test]
    fn dims_clamp_to_max_dimension() {
        // An absurdly large window must not claim past the daemon's cap.
        let (cols, rows) = compute_dims(1_000_000.0, 1_000_000.0, 1.0, 1.0);
        assert_eq!(cols, MAX_DIMENSION);
        assert_eq!(rows, MAX_DIMENSION);
    }

    #[test]
    fn overlay_row_is_reserved() {
        // With an exact integer number of cells, the overlay steals exactly one row.
        // cell 10x10, window 100x100 phys: cols=10; rows=floor((100-10)/10)=9.
        let (cols, rows) = compute_dims(100.0, 100.0, 10.0, 10.0);
        assert_eq!((cols, rows), (10, 9));
    }

    #[test]
    fn compute_dims_one_row_matches_chrome_rows_one() {
        // The public one-row path must equal the generalized helper with chrome_rows = 1.
        for (w, h, cw, ch) in [
            (100.0, 100.0, 10.0, 10.0),
            (800.0, 600.0, 9.0, 20.0),
            (1080.0, 720.0, 8.5, 17.0),
        ] {
            assert_eq!(
                compute_dims(w, h, cw, ch),
                compute_dims_with_chrome_rows(w, h, cw, ch, 1),
            );
        }
    }

    #[test]
    fn more_chrome_rows_reserve_more_terminal_rows() {
        // cell 10x10, window 100x100: 1 row -> 9 terminal rows; 3 rows -> 7 terminal rows.
        let (_, rows1) = compute_dims_with_chrome_rows(100.0, 100.0, 10.0, 10.0, 1);
        let (_, rows3) = compute_dims_with_chrome_rows(100.0, 100.0, 10.0, 10.0, 3);
        assert_eq!(rows1, 9);
        assert_eq!(rows3, 7);
        assert!(rows3 < rows1);
    }

    #[test]
    fn chrome_rows_still_clamp_to_at_least_one_row() {
        // A tiny window with several reserved chrome rows still leaves at least one terminal row.
        let (cols, rows) = compute_dims_with_chrome_rows(10.0, 10.0, 10.0, 10.0, 5);
        assert!(cols >= 1);
        assert_eq!(rows, 1, "terminal must keep at least one row");
    }

    #[test]
    fn chrome_rows_clamp_to_max_dimension() {
        // Huge window: rows clamp to MAX_DIMENSION regardless of chrome rows reserved.
        let (cols, rows) = compute_dims_with_chrome_rows(1_000_000.0, 1_000_000.0, 1.0, 1.0, 4);
        assert_eq!(cols, MAX_DIMENSION);
        assert_eq!(rows, MAX_DIMENSION);
    }

    #[test]
    fn chrome_rows_bad_dimensions_are_degenerate() {
        // Non-positive cell metrics produce the (1, 1) degenerate result for any chrome_rows.
        assert_eq!(
            compute_dims_with_chrome_rows(800.0, 600.0, 0.0, 0.0, 2),
            (1, 1)
        );
    }

    #[test]
    fn resize_burst_coalesces_to_latest() {
        let mut c = ResizeCoalescer::default();
        let t0 = Instant::now();
        let interval = Duration::from_millis(33);
        // First geometry sends immediately (no prior send).
        assert_eq!(c.record((80, 24), t0, interval), Some((80, 24)));
        // A burst of intermediates within the interval: none send; latest pends.
        assert_eq!(
            c.record((81, 24), t0 + Duration::from_millis(5), interval),
            None
        );
        assert_eq!(
            c.record((82, 25), t0 + Duration::from_millis(10), interval),
            None
        );
        assert_eq!(
            c.record((83, 26), t0 + Duration::from_millis(15), interval),
            None
        );
        assert!(
            c.has_pending(),
            "latest geometry waits for the trailing flush"
        );
        // After the interval elapses, the trailing flush sends only the LATEST.
        assert_eq!(
            c.flush(t0 + Duration::from_millis(40), interval),
            Some((83, 26))
        );
        assert!(!c.has_pending());
    }

    #[test]
    fn resize_trailing_send_flushes_settled_geometry() {
        let mut c = ResizeCoalescer::default();
        let t0 = Instant::now();
        let interval = Duration::from_millis(33);
        assert_eq!(c.record((80, 24), t0, interval), Some((80, 24)));
        // Drag settles at (90, 30) just after the first send; under interval -> pends.
        assert_eq!(
            c.record((90, 30), t0 + Duration::from_millis(2), interval),
            None
        );
        // Even much later, exactly one trailing send delivers the settled size.
        assert_eq!(
            c.flush(t0 + Duration::from_secs(1), interval),
            Some((90, 30))
        );
        // A second flush with nothing new is a no-op.
        assert_eq!(c.flush(t0 + Duration::from_secs(2), interval), None);
    }

    #[test]
    fn resize_dedups_unchanged_geometry() {
        let mut c = ResizeCoalescer::default();
        let t0 = Instant::now();
        let interval = Duration::from_millis(33);
        assert_eq!(c.record((80, 24), t0, interval), Some((80, 24)));
        // Re-recording the same size well after the interval sends NOTHING.
        assert_eq!(
            c.record((80, 24), t0 + Duration::from_secs(1), interval),
            None
        );
        assert!(!c.has_pending());
    }

    #[test]
    fn resize_invalidate_last_sent_re_emits_same_window_size() {
        // When the split geometry changes at the SAME window size, the renderer invalidates the last-sent
        // value so the active session is re-sized to its new pane region. After invalidate, re-recording
        // the same window dims sends again (instead of being deduped to None).
        let mut c = ResizeCoalescer::default();
        let t0 = Instant::now();
        let interval = Duration::from_millis(33);
        assert_eq!(c.record((80, 24), t0, interval), Some((80, 24)));
        // Without invalidation the same size would dedup to None (see resize_dedups_unchanged_geometry).
        c.invalidate_last_sent();
        assert_eq!(
            c.record((80, 24), t0 + Duration::from_secs(1), interval),
            Some((80, 24)),
            "after invalidate, the same window size re-emits so the active pane resizes"
        );
        // The rate limit still applies: a same-size record within the interval pends rather than sending.
        c.invalidate_last_sent();
        assert_eq!(
            c.record(
                (80, 24),
                t0 + Duration::from_secs(1) + Duration::from_millis(5),
                interval
            ),
            None
        );
        assert!(c.has_pending());
    }

    // ---- Outbound queue ----

    #[test]
    fn outbound_preserves_strict_fifo_order() {
        let q = OutboundQueue::new();
        for i in 0..5u8 {
            assert!(q.enqueue(vec![i]));
        }
        for i in 0..5u8 {
            assert_eq!(q.dequeue(), Some(vec![i]), "FIFO order must be preserved");
        }
    }

    #[test]
    fn outbound_backpressures_then_admits_after_drain() {
        // A queue at capacity must BLOCK a further enqueue (never drop), and
        // admit it once the writer drains room. We drive the drain from another
        // thread so the blocked producer can make progress.
        let q = Arc::new(OutboundQueue::new());
        // Fill to just under the cap with one big item, plus one more that fits.
        let big = vec![0u8; OUTBOUND_CAP_BYTES - 1];
        assert!(q.enqueue(big));
        assert!(q.enqueue(vec![1u8])); // now exactly at cap

        // This enqueue cannot fit (cap exceeded, queue non-empty) -> it blocks.
        let producer = {
            let q = Arc::clone(&q);
            std::thread::spawn(move || q.enqueue(vec![2u8, 3u8]))
        };

        // Drain the two items; each pop frees room and notifies the producer.
        assert_eq!(q.dequeue().map(|v| v.len()), Some(OUTBOUND_CAP_BYTES - 1));
        assert_eq!(q.dequeue(), Some(vec![1u8]));

        // The producer's item is admitted (never dropped) and dequeues in order.
        assert!(
            producer.join().unwrap(),
            "blocked enqueue must eventually admit"
        );
        assert_eq!(q.dequeue(), Some(vec![2u8, 3u8]));
    }

    #[test]
    fn outbound_admits_oversized_item_into_empty_queue() {
        // A single item larger than the whole cap must still go through (otherwise
        // a legitimate large paste could deadlock forever).
        let q = OutboundQueue::new();
        let huge = vec![7u8; OUTBOUND_CAP_BYTES + 4096];
        assert!(
            q.enqueue(huge.clone()),
            "oversized item must be admitted, not dropped"
        );
        assert_eq!(q.dequeue(), Some(huge));
    }

    #[test]
    fn outbound_close_unblocks_and_drains_remaining() {
        let q = Arc::new(OutboundQueue::new());
        assert!(q.enqueue(vec![1u8]));
        assert!(q.enqueue(vec![2u8]));
        // Close: a producer blocked on a full queue would now return false, and the
        // writer's dequeue drains what's buffered, THEN returns None to exit.
        q.close();
        assert_eq!(
            q.dequeue(),
            Some(vec![1u8]),
            "buffered items drain after close"
        );
        assert_eq!(q.dequeue(), Some(vec![2u8]));
        assert_eq!(q.dequeue(), None, "closed + drained -> writer exits");
        // Enqueue after close is refused (not silently buffered into a dead queue).
        assert!(!q.enqueue(vec![3u8]));
    }

    // ---- Selection hit-test + extraction + copy/interrupt ----

    fn sel_cell(text: &str, width: u8) -> Cell {
        Cell {
            text: text.to_string(),
            fg: crate::wire::Color::Named {
                name: crate::wire::NamedColor::Foreground,
            },
            bg: crate::wire::Color::Named {
                name: crate::wire::NamedColor::Background,
            },
            bold: false,
            italic: false,
            underline: Default::default(),
            inverse: false,
            strikeout: false,
            dim: false,
            hidden: false,
            width,
        }
    }

    /// Build a row from a string, padding with blank cells to `cols`.
    fn sel_row(text: &str, cols: usize) -> Vec<Cell> {
        let mut r: Vec<Cell> = text.chars().map(|c| sel_cell(&c.to_string(), 1)).collect();
        while r.len() < cols {
            r.push(sel_cell(" ", 1));
        }
        r.truncate(cols);
        r
    }

    #[test]
    fn pixel_to_cell_maps_and_clamps() {
        // 10x20 px cells, 8 cols x 4 rows.
        assert_eq!(
            pixel_to_cell(0.0, 0.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 0, row: 0 })
        );
        assert_eq!(
            pixel_to_cell(25.0, 41.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 2, row: 2 })
        );
        // Far beyond the grid clamps to the last cell, never out of bounds.
        assert_eq!(
            pixel_to_cell(9999.0, 9999.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 7, row: 3 })
        );
        // Negative-ish (left/above) clamps to origin.
        assert_eq!(
            pixel_to_cell(-5.0, -5.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 0, row: 0 })
        );
    }

    #[test]
    fn pixel_to_cell_rejects_degenerate() {
        assert_eq!(pixel_to_cell(5.0, 5.0, 0.0, 20.0, 8, 4), None);
        assert_eq!(pixel_to_cell(5.0, 5.0, 10.0, 20.0, 0, 4), None);
        assert_eq!(pixel_to_cell(5.0, 5.0, 10.0, 20.0, 8, 0), None);
    }

    #[test]
    fn top_offset_zero_equals_plain_pixel_to_cell() {
        // With no left/top chrome offsets the translated helper is exactly pixel_to_cell.
        for (x, y) in [(0.0, 0.0), (25.0, 41.0), (9999.0, 9999.0), (-5.0, -5.0)] {
            assert_eq!(
                pixel_to_cell_with_top_offset(x, y, 0.0, 0.0, 10.0, 20.0, 8, 4),
                pixel_to_cell(x, y, 10.0, 20.0, 8, 4),
            );
        }
    }

    #[test]
    fn top_offset_first_row_below_bar_is_row_zero() {
        // 20px top band, 10x20 cells. A pixel exactly at the band bottom maps to grid row 0;
        // one cell-row lower maps to row 1.
        assert_eq!(
            pixel_to_cell_with_top_offset(5.0, 20.0, 0.0, 20.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 0, row: 0 })
        );
        assert_eq!(
            pixel_to_cell_with_top_offset(5.0, 40.0, 0.0, 20.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 0, row: 1 })
        );
    }

    #[test]
    fn top_offset_inside_band_returns_none() {
        // A pixel inside the reserved top band is renderer chrome, NOT a grid cell: None,
        // never clamped to grid row 0 (which would leak the click into selection/PTY reporting).
        assert_eq!(
            pixel_to_cell_with_top_offset(5.0, 0.0, 0.0, 20.0, 10.0, 20.0, 8, 4),
            None
        );
        assert_eq!(
            pixel_to_cell_with_top_offset(5.0, 19.9, 0.0, 20.0, 10.0, 20.0, 8, 4),
            None
        );
    }

    #[test]
    fn left_offset_first_col_past_dock_is_col_zero() {
        // 30px left dock, 10x20 cells. A pixel exactly at the dock's right edge maps to grid col 0;
        // one cell-col further right maps to col 1. (top_offset 0 so y maps straight.)
        assert_eq!(
            pixel_to_cell_with_top_offset(30.0, 5.0, 30.0, 0.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 0, row: 0 })
        );
        assert_eq!(
            pixel_to_cell_with_top_offset(40.0, 5.0, 30.0, 0.0, 10.0, 20.0, 8, 4),
            Some(CellPos { col: 1, row: 0 })
        );
    }

    #[test]
    fn left_offset_inside_dock_returns_none() {
        // A pixel inside the reserved left dock is renderer chrome, NOT a grid cell: None, never
        // clamped to grid col 0 (which would leak the click into selection/PTY reporting).
        assert_eq!(
            pixel_to_cell_with_top_offset(0.0, 5.0, 30.0, 0.0, 10.0, 20.0, 8, 4),
            None
        );
        assert_eq!(
            pixel_to_cell_with_top_offset(29.9, 5.0, 30.0, 0.0, 10.0, 20.0, 8, 4),
            None
        );
    }

    #[test]
    fn extract_single_row_selection() {
        let grid = vec![sel_row("hello world", 11)];
        // cols 0..=4 = "hello".
        let out = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 4, row: 0 },
        );
        assert_eq!(out, "hello");
    }

    #[test]
    fn extract_selection_order_independent() {
        let grid = vec![sel_row("hello world", 11)];
        let a = extract_selection(
            &grid,
            CellPos { col: 4, row: 0 },
            CellPos { col: 0, row: 0 },
        );
        assert_eq!(a, "hello", "reversed anchor/focus yields same text");
    }

    #[test]
    fn extract_multi_row_joins_with_newline_and_trims() {
        // Row 0 trailing blanks, row 1 short. Multi-row: row0 from col2 to end,
        // row1 from start to col2.
        let grid = vec![sel_row("ab    ", 6), sel_row("xyz", 6)];
        let out = extract_selection(
            &grid,
            CellPos { col: 2, row: 0 },
            CellPos { col: 2, row: 1 },
        );
        // Row0 col2.. is all blanks -> trimmed to ""; row1 col0..=2 = "xyz".
        assert_eq!(out, "\nxyz");
    }

    #[test]
    fn extract_skips_wide_spacers_keeps_wide_lead() {
        // A wide glyph occupies a lead cell (width 2) + a spacer (width 0).
        let mut row = vec![sel_cell("a", 1), sel_cell("世", 2), sel_cell("", 0)];
        row.push(sel_cell("b", 1));
        let grid = vec![row];
        let out = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 3, row: 0 },
        );
        assert_eq!(
            out, "a世b",
            "spacer skipped, wide lead glyph preserved once"
        );
    }

    #[test]
    fn extract_clamps_out_of_range_coords() {
        let grid = vec![sel_row("abc", 3)];
        // Focus row/col beyond bounds clamps to the grid.
        let out = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 99, row: 99 },
        );
        assert_eq!(out, "abc");
    }

    #[test]
    fn extract_empty_grid_is_empty() {
        let grid: Vec<Vec<Cell>> = Vec::new();
        let out = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 0, row: 0 },
        );
        assert_eq!(out, "");
    }

    #[test]
    fn copy_writes_extracted_selection_to_clipboard() {
        // Simulate the copy flow: extract from the painted grid, write to clipboard.
        let grid = vec![sel_row("copy me", 7)];
        let text = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 3, row: 0 },
        );
        let mut cb = FakeClipboard(None);
        assert!(cb.write_text(text));
        assert_eq!(cb.read_text().as_deref(), Some("copy"));
    }

    #[test]
    fn empty_selection_text_not_written() {
        // An all-blank selection extracts to "" — the copy path must not write it.
        let grid = vec![sel_row("       ", 7)];
        let text = extract_selection(
            &grid,
            CellPos { col: 0, row: 0 },
            CellPos { col: 6, row: 0 },
        );
        assert_eq!(text, "");
        // Caller guards on is_empty(); clipboard stays untouched.
        let mut cb = FakeClipboard(Some("prev".into()));
        if !text.is_empty() {
            cb.write_text(text);
        }
        assert_eq!(cb.read_text().as_deref(), Some("prev"));
    }

    #[test]
    fn ctrl_c_still_emits_interrupt_not_copy() {
        // Ctrl-C (no Super, no Shift) must encode the 0x03 interrupt — it is NOT the
        // copy chord (Cmd-C / Ctrl-Shift-C), which is intercepted before encoding.
        let m = host_mods(true, false, false, false);
        let out = encode_key(
            &HostKey::Character("c".to_string()),
            Some("c"),
            Some("c"),
            &m,
            modes(false, false, false),
        );
        assert_eq!(out, Some("\u{03}".to_string()), "Ctrl-C -> 0x03");
    }

    // ---- mouse reporting (TUI) ----

    #[test]
    fn mouse_no_report_when_no_mode_active() {
        // With no mouse mode negotiated, every event encodes to nothing.
        let off = mouse_modes(false, false, false, false);
        for ev in [
            MouseEvent::Press(MouseButton::Left),
            MouseEvent::Release(MouseButton::Left),
            MouseEvent::Move { held: None },
            MouseEvent::WheelUp,
        ] {
            assert_eq!(encode_mouse(ev, 0, 0, off, false, false, false), None);
        }
    }

    #[test]
    fn mouse_sgr_press_and_release_left() {
        // SGR (1006), click reporting (1000). Left press at cell (0,0) -> 1-based (1,1),
        // button 0, `M`. Release -> same coords, `m`.
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                0,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<0;1;1M".to_string())
        );
        assert_eq!(
            encode_mouse(
                MouseEvent::Release(MouseButton::Left),
                0,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<0;1;1m".to_string())
        );
    }

    #[test]
    fn mouse_sgr_right_and_middle_button_codes() {
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Middle),
                4,
                2,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<1;5;3M".to_string())
        );
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Right),
                4,
                2,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<2;5;3M".to_string())
        );
    }

    #[test]
    fn mouse_sgr_modifier_bits() {
        // shift=4, alt=8, ctrl=16 added to the button code. Left(0) + all three = 28.
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                0,
                0,
                m,
                true,
                true,
                true
            ),
            Some("\x1b[<28;1;1M".to_string())
        );
    }

    #[test]
    fn mouse_sgr_wheel_up_down() {
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(MouseEvent::WheelUp, 0, 0, m, false, false, false),
            Some("\x1b[<64;1;1M".to_string())
        );
        assert_eq!(
            encode_mouse(MouseEvent::WheelDown, 0, 0, m, false, false, false),
            Some("\x1b[<65;1;1M".to_string())
        );
    }

    #[test]
    fn mouse_click_mode_does_not_report_motion() {
        // Click-only (1000) reports press/release but never motion (needs 1002/1003).
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Move {
                    held: Some(MouseButton::Left)
                },
                1,
                1,
                m,
                false,
                false,
                false
            ),
            None
        );
        assert_eq!(
            encode_mouse(
                MouseEvent::Move { held: None },
                1,
                1,
                m,
                false,
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn mouse_drag_mode_reports_held_motion_only() {
        // Button-drag (1002): motion WITH a button held is reported (button + motion bit
        // 32); no-button motion is not.
        let m = mouse_modes(true, true, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Move {
                    held: Some(MouseButton::Left)
                },
                2,
                3,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<32;3;4M".to_string())
        );
        assert_eq!(
            encode_mouse(
                MouseEvent::Move { held: None },
                2,
                3,
                m,
                false,
                false,
                false
            ),
            None
        );
    }

    #[test]
    fn mouse_any_motion_reports_no_button_move() {
        // Any-motion (1003): no-button motion reports button 3 + motion bit 32 = 35.
        let m = mouse_modes(true, true, true, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Move { held: None },
                0,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<35;1;1M".to_string())
        );
    }

    #[test]
    fn mouse_legacy_x10_byte_triple() {
        // Legacy (no SGR): `\x1b[M` + (cb+32, x+32, y+32). Left press at (0,0) ->
        // bytes 32, 33, 33 = space, '!', '!'.
        let m = mouse_modes(true, false, false, false);
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                0,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[M\x20\x21\x21".to_string())
        );
    }

    #[test]
    fn mouse_legacy_release_is_button_three() {
        // Legacy release uses button 3 (low 2 bits): cb = 3, byte = 35 = '#'.
        let m = mouse_modes(true, false, false, false);
        assert_eq!(
            encode_mouse(
                MouseEvent::Release(MouseButton::Left),
                0,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[M\x23\x21\x21".to_string())
        );
    }

    #[test]
    fn mouse_legacy_drops_coords_beyond_ascii_safe_range() {
        // Cells past 95 would push a byte >= 128, which UTF-8 would split into two wire
        // bytes and corrupt the report — so legacy mode drops them.
        let m = mouse_modes(true, false, false, false);
        // col 95 -> x=96 -> byte 128: dropped.
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                95,
                0,
                m,
                false,
                false,
                false
            ),
            None
        );
        // col 94 -> x=95 -> byte 127: still emitted (boundary).
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                94,
                0,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[M\x20\x7f\x21".to_string())
        );
    }

    #[test]
    fn mouse_sgr_handles_large_coords() {
        // SGR is ASCII decimal, so it has no 223/95-cell ceiling — large coords are fine.
        let m = mouse_modes(true, false, false, true);
        assert_eq!(
            encode_mouse(
                MouseEvent::Press(MouseButton::Left),
                499,
                199,
                m,
                false,
                false,
                false
            ),
            Some("\x1b[<0;500;200M".to_string())
        );
    }

    #[test]
    fn mouse_legacy_sequences_are_single_byte_ascii() {
        // Every byte of a legacy report must be < 128 so it round-trips as ONE byte
        // through the UTF-8 Write channel (the daemon does `data.into_bytes()`).
        let m = mouse_modes(true, true, false, false);
        let s = encode_mouse(
            MouseEvent::Move {
                held: Some(MouseButton::Right),
            },
            94,
            94,
            m,
            true,
            true,
            true,
        )
        .expect("boundary coords still encode");
        assert!(s.is_ascii(), "legacy report must be ASCII, got {s:?}");
        assert_eq!(s.len(), s.chars().count(), "one byte per char");
    }
}

#[cfg(test)]
mod scrollback_view_tests {
    use super::*;

    // --- fixtures -----------------------------------------------------------

    fn color() -> crate::wire::Color {
        crate::wire::Color::Named {
            name: crate::wire::NamedColor::Foreground,
        }
    }

    fn cell(text: &str) -> Cell {
        Cell {
            text: text.to_string(),
            fg: color(),
            bg: color(),
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

    fn row(text: &str, cols: usize) -> Vec<Cell> {
        let mut r: Vec<Cell> = text.chars().map(|c| cell(&c.to_string())).collect();
        while r.len() < cols {
            r.push(cell(" "));
        }
        r.truncate(cols);
        r
    }

    fn live_grid(gen: &str, cols: usize, rows: usize, alt: bool) -> GridSnapshot {
        let rows_cells: Vec<Vec<Cell>> =
            (0..rows).map(|i| row(&format!("live{i}"), cols)).collect();
        GridSnapshot {
            version: crate::sync::SUPPORTED_VERSION,
            generation: SessionGeneration(gen.to_string()),
            revision: Revision(100),
            base_revision: Revision(100),
            cols,
            rows,
            rows_cells,
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
            alt_screen: alt,
            app_cursor: false,
            bracketed_paste: false,
            focus_reporting: false,
            mouse_report: false,
            mouse_drag: false,
            mouse_motion: false,
            mouse_sgr: false,
        }
    }

    /// A `Shared` whose live grid is set to `gen`, with an installed test queue so
    /// any `send_request` is observable. Returns the shared state.
    fn shared_with_live(gen: &str, cols: usize, rows: usize) -> Arc<Shared> {
        let (shared, _q) = Shared::with_test_queue();
        *shared.grid.lock().unwrap() = Some(Arc::new(live_grid(gen, cols, rows, false)));
        shared
    }

    fn hist_rows(cols: usize, rows: usize) -> Vec<Vec<Cell>> {
        (0..rows).map(|i| row(&format!("hist{i}"), cols)).collect()
    }

    // --- 1: view_offset clamps to [0, history_len] --------------------------

    #[test]
    fn view_offset_clamps_to_zero_history_len_range() {
        // Known length: below zero clamps to 0; above history clamps to history_len.
        assert_eq!(clamp_view_offset(-5, Some(40), 6), 0);
        assert_eq!(clamp_view_offset(0, Some(40), 6), 0);
        assert_eq!(clamp_view_offset(40, Some(40), 6), 40);
        assert_eq!(clamp_view_offset(999, Some(40), 6), 40);
        // Below the cached ceiling, next_view_offset still clamps to the known range.
        assert_eq!(
            next_view_offset(0, Some(40), 6, ScrollAction::Lines(-10)),
            0
        );
        assert_eq!(
            next_view_offset(38, Some(40), 6, ScrollAction::Lines(10)),
            40
        );
    }

    // --- 2: wheel up moves up into history (would send a request) ------------

    #[test]
    fn wheel_up_moves_offset_into_history() {
        // From the live bottom, scrolling up by 3 lines lands at offset 3 (history is
        // deep enough), which is the offset the renderer would request from the daemon.
        let new = next_view_offset(0, Some(100), 6, ScrollAction::Lines(3));
        assert_eq!(new, 3, "wheel up enters scrollback at the moved-to offset");
        assert!(new > 0, "a positive offset triggers a Scrollback request");
    }

    // --- 3: wheel down toward zero returns to live --------------------------

    #[test]
    fn wheel_down_to_zero_returns_to_live() {
        // Scrolled up at 2; a downward wheel of 5 clamps to 0 = live bottom.
        let new = next_view_offset(2, Some(100), 6, ScrollAction::Lines(-5));
        assert_eq!(new, 0, "wheel down past bottom returns to live (offset 0)");
    }

    // --- 4: PageUp/PageDown/Home/End adjust offset --------------------------

    #[test]
    fn page_and_home_end_adjust_offset() {
        let page = 6;
        let h = Some(100);
        // PageUp from bottom moves up one page.
        assert_eq!(next_view_offset(0, h, page, ScrollAction::PageUp), 6);
        // PageDown from 6 returns to live.
        assert_eq!(next_view_offset(6, h, page, ScrollAction::PageDown), 0);
        // PageDown cannot go negative.
        assert_eq!(next_view_offset(3, h, page, ScrollAction::PageDown), 0);
        // Home jumps to the oldest history.
        assert_eq!(next_view_offset(6, h, page, ScrollAction::Home), 100);
        // End jumps to the live bottom.
        assert_eq!(next_view_offset(50, h, page, ScrollAction::End), 0);
    }

    // --- 4a: selection invalidation predicate on scroll --------------------
    // `apply_scroll` clears the selection iff the viewport actually moves, i.e.
    // `next_view_offset(...) != cur`. The no-op early-return (offset unchanged)
    // runs BEFORE either clear site, so an unchanged viewport keeps the
    // selection. These tests pin that decision without needing a window.

    #[test]
    fn scroll_that_moves_viewport_changes_offset_and_clears() {
        let page = 6;
        let h = Some(100);
        // A moving wheel scroll up: offset changes -> selection cleared.
        let cur = 0;
        let next = next_view_offset(cur, h, page, ScrollAction::Lines(3));
        assert_ne!(next, cur, "moving scroll changes the offset -> clear");
        // PageUp from the bottom also moves.
        assert_ne!(next_view_offset(0, h, page, ScrollAction::PageUp), 0);
        // End from a scrolled position returns to live (still a change).
        assert_ne!(next_view_offset(50, h, page, ScrollAction::End), 50);
    }

    #[test]
    fn downward_no_op_keeps_selection_but_upward_at_cached_ceiling_reprobes() {
        let page = 6;
        let h = Some(40);
        // At the live bottom, scrolling DOWN / PageDown / End is a no-op.
        assert_eq!(next_view_offset(0, h, page, ScrollAction::Lines(-5)), 0);
        assert_eq!(next_view_offset(0, h, page, ScrollAction::PageDown), 0);
        assert_eq!(next_view_offset(0, h, page, ScrollAction::End), 0);
        // The cached upper bound is only a point-in-time daemon reply. An explicit upward
        // gesture at it moves provisionally (bounded to one page) so a fresh Scrollback
        // request can discover history produced since that reply.
        assert_eq!(next_view_offset(40, h, page, ScrollAction::PageUp), 46);
        assert_eq!(next_view_offset(40, h, page, ScrollAction::Home), 46);
        assert_eq!(next_view_offset(40, h, page, ScrollAction::Lines(10)), 46);
    }

    // --- 4b: PageUp/PageDown/Home/End consume policy (TUI-aware) ------------

    #[test]
    fn alt_screen_passes_all_nav_keys_to_pty() {
        // On the alternate screen every nav key returns None (-> PTY), regardless of
        // scrolled state (which is forced live on alt-screen anyway).
        for key in [
            ScrollKey::PageUp,
            ScrollKey::PageDown,
            ScrollKey::Home,
            ScrollKey::End,
        ] {
            assert_eq!(
                scroll_key_action_for(key, true, false, false),
                None,
                "{key:?} must reach the PTY on alt-screen"
            );
        }
    }

    #[test]
    fn live_bottom_only_pageup_enters_scrollback() {
        // Normal screen, at the live bottom (not scrolled): PageUp enters scrollback;
        // PageDown/Home/End have nothing above to scroll into -> PTY.
        assert_eq!(
            scroll_key_action_for(ScrollKey::PageUp, false, false, false),
            Some(ScrollAction::PageUp)
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::PageDown, false, false, false),
            None,
            "PageDown at the live bottom belongs to the PTY (pager)"
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::Home, false, false, false),
            None
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::End, false, false, false),
            None
        );
    }

    #[test]
    fn scrolled_up_all_nav_keys_control_scrollback() {
        // Normal screen, already scrolled up: all four drive the renderer viewport.
        assert_eq!(
            scroll_key_action_for(ScrollKey::PageUp, false, true, false),
            Some(ScrollAction::PageUp)
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::PageDown, false, true, false),
            Some(ScrollAction::PageDown)
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::Home, false, true, false),
            Some(ScrollAction::Home)
        );
        assert_eq!(
            scroll_key_action_for(ScrollKey::End, false, true, false),
            Some(ScrollAction::End)
        );
    }

    #[test]
    fn modified_nav_keys_pass_to_pty() {
        // Any modifier held -> the chord belongs to the application, even PageUp and
        // even when scrolled. Alt-screen is irrelevant here.
        for &scrolled in &[false, true] {
            for key in [
                ScrollKey::PageUp,
                ScrollKey::PageDown,
                ScrollKey::Home,
                ScrollKey::End,
            ] {
                assert_eq!(
                    scroll_key_action_for(key, false, scrolled, true),
                    None,
                    "modified {key:?} (scrolled={scrolled}) must reach the PTY"
                );
            }
        }
    }

    // --- 1a: scroll indicator label math/clamping ---------------------------

    #[test]
    fn scroll_indicator_hidden_at_live_bottom() {
        // Offset 0 = live; no indicator regardless of known length.
        assert_eq!(scroll_indicator_label(0, None), None);
        assert_eq!(scroll_indicator_label(0, Some(0)), None);
        assert_eq!(scroll_indicator_label(0, Some(100)), None);
    }

    #[test]
    fn scroll_indicator_known_length_shows_depth_and_percent() {
        assert_eq!(
            scroll_indicator_label(8, Some(100)).as_deref(),
            Some("[scroll 8/100 8%]")
        );
        // Percent rounds.
        assert_eq!(
            scroll_indicator_label(1, Some(3)).as_deref(),
            Some("[scroll 1/3 33%]")
        );
        // At the very top, percent is 100.
        assert_eq!(
            scroll_indicator_label(100, Some(100)).as_deref(),
            Some("[scroll 100/100 100%]")
        );
    }

    #[test]
    fn scroll_indicator_unknown_or_empty_shows_bare_offset() {
        // Before the first reply (None) we cannot honestly compute a fraction.
        assert_eq!(
            scroll_indicator_label(6, None).as_deref(),
            Some("[scroll +6]")
        );
        // Some(0) = daemon says no history; show the bare provisional offset.
        assert_eq!(
            scroll_indicator_label(3, Some(0)).as_deref(),
            Some("[scroll +3]")
        );
    }

    #[test]
    fn scroll_indicator_percent_clamps_to_100() {
        // Defensive: even if offset somehow exceeds the length, percent never exceeds 100.
        assert_eq!(
            scroll_indicator_label(150, Some(100)).as_deref(),
            Some("[scroll 150/100 100%]")
        );
    }

    // --- 1b: bootstrap — unknown history_len permits a provisional first move ---

    #[test]
    fn unknown_history_len_permits_provisional_first_scroll() {
        // history_len == None means "not yet known" (distinct from Some(0) = no history).
        // The very first wheel/PageUp from the live bottom must move so a request fires.
        let page = 6;
        // Wheel up by 3 from bottom with unknown length: moves to 3 (within one page).
        assert_eq!(next_view_offset(0, None, page, ScrollAction::Lines(3)), 3);
        // PageUp from bottom with unknown length: clamps to one provisional page.
        assert_eq!(next_view_offset(0, None, page, ScrollAction::PageUp), 6);
        // Home with unknown length: pin to the provisional cap, not 0 (so we move + ask).
        assert_eq!(next_view_offset(0, None, page, ScrollAction::Home), 6);
        // A big wheel-up does not overshoot past the provisional one-page cap.
        assert_eq!(next_view_offset(0, None, page, ScrollAction::Lines(999)), 6);
        // Down/End still return to live even when length is unknown.
        assert_eq!(next_view_offset(4, None, page, ScrollAction::End), 0);
    }

    #[test]
    fn known_empty_history_does_not_permanently_lock_future_scrolls() {
        // A daemon reply of zero is true only at that instant. Later shell output can create
        // history, so the next explicit upward gesture must issue a bounded fresh probe instead
        // of remaining forever at Step::NoMove.
        let page = 8;
        assert_eq!(
            next_view_offset(0, Some(0), page, ScrollAction::Lines(1)),
            1
        );
        assert_eq!(next_view_offset(0, Some(0), page, ScrollAction::PageUp), 8);
        assert_eq!(next_view_offset(0, Some(0), page, ScrollAction::Home), 8);
        // The opposite direction remains pinned to the live bottom.
        assert_eq!(
            next_view_offset(0, Some(0), page, ScrollAction::Lines(-1)),
            0
        );
    }

    #[test]
    fn cached_positive_ceiling_reprobe_extends_from_current_without_jump_back() {
        // If a scrolled pane learned depth 100 and live output later grew it, probe one
        // additional page from 100. Never reuse the initial page as an absolute cap.
        assert_eq!(
            next_view_offset(100, Some(100), 12, ScrollAction::PageUp),
            112
        );
        assert_eq!(
            next_view_offset(100, Some(100), 12, ScrollAction::Lines(99)),
            112
        );
    }

    // --- 5: alt-screen forces scrollback off --------------------------------

    #[test]
    fn alt_screen_forces_view_off() {
        // The alt-screen gate in App::apply_scroll/draw resets to live. We assert the
        // state transition it performs: a scrolled state with a cached window snaps back
        // to the live bottom and drops the historical snapshot.
        let mut sb = ScrollbackState {
            view_offset: 7,
            history_len: Some(100),
            historical: Some(Arc::new(scrollback_snapshot(
                SessionGeneration("g".into()),
                Revision(1),
                hist_rows(40, 6),
            ))),
            historical_generation: Some(SessionGeneration("g".into())),
        };
        assert!(sb.is_scrolled());
        sb.reset_to_live();
        assert_eq!(sb.view_offset, 0, "alt-screen reset clears the offset");
        assert!(
            sb.historical.is_none(),
            "alt-screen reset drops history window"
        );
        assert!(!sb.is_scrolled());
    }

    // --- 6: resize forces scrollback off ------------------------------------

    #[test]
    fn resize_forces_view_off() {
        // Resize uses the same reset path; from any scrolled state we return to live.
        let mut sb = ScrollbackState {
            view_offset: 12,
            history_len: Some(100),
            historical: Some(Arc::new(scrollback_snapshot(
                SessionGeneration("g".into()),
                Revision(1),
                hist_rows(40, 6),
            ))),
            historical_generation: None,
        };
        sb.reset_to_live();
        assert_eq!(sb.view_offset, 0);
        assert!(sb.historical.is_none());
        assert!(sb.historical_generation.is_none());
    }

    // --- 7: ScrollbackRows for wrong session / generation ignored -----------

    #[test]
    fn scrollback_rows_wrong_session_ignored() {
        let shared = shared_with_live("gen-a", 40, 6);
        // Scroll up so a valid reply WOULD be adopted.
        shared.scrollback.lock().unwrap().view_offset = 5;

        let woke = apply_scrollback_rows(
            &shared,
            "my-session",
            "OTHER-session",
            SessionGeneration("gen-a".into()),
            Revision(50),
            100,
            5,
            hist_rows(40, 6),
        );
        assert!(!woke, "wrong-session reply does not repaint");
        let sb = shared.scrollback.lock().unwrap();
        assert!(sb.historical.is_none(), "wrong-session reply not adopted");
        assert_eq!(
            sb.history_len, None,
            "wrong-session reply leaves history_len unknown (untouched)"
        );
    }

    #[test]
    fn scrollback_rows_stale_generation_ignored() {
        let shared = shared_with_live("gen-a", 40, 6);
        shared.scrollback.lock().unwrap().view_offset = 5;

        // Live grid is gen-a; this reply is for gen-b (session was re-baselined).
        let woke = apply_scrollback_rows(
            &shared,
            "my-session",
            "my-session",
            SessionGeneration("gen-b".into()),
            Revision(50),
            100,
            5,
            hist_rows(40, 6),
        );
        assert!(!woke, "stale-generation reply does not repaint");
        assert!(
            shared.scrollback.lock().unwrap().historical.is_none(),
            "stale-generation reply not adopted"
        );
    }

    // --- 8: ScrollbackRows while offset>0 becomes the painted window --------

    #[test]
    fn scrollback_rows_while_scrolled_becomes_historical_window() {
        let shared = shared_with_live("gen-a", 40, 6);
        shared.scrollback.lock().unwrap().view_offset = 10;

        let woke = apply_scrollback_rows(
            &shared,
            "my-session",
            "my-session",
            SessionGeneration("gen-a".into()),
            Revision(50),
            100,
            10,
            hist_rows(40, 6),
        );
        assert!(woke, "a valid reply triggers a repaint");
        let sb = shared.scrollback.lock().unwrap();
        assert_eq!(sb.history_len, Some(100));
        assert_eq!(sb.view_offset, 10, "echoes the served offset");
        let snap = sb.historical.as_ref().expect("historical window adopted");
        assert_eq!(snap.rows, 6);
        assert_eq!(snap.cols, 40);
        assert_eq!(
            snap.rows_cells[0][0].text, "h",
            "painted rows are the history rows"
        );
        assert!(
            !snap.cursor_visible,
            "history snapshot draws no live cursor"
        );
    }

    /// A late reply that arrives AFTER the user returned to the live bottom must not
    /// resurrect a historical view (offset stays 0, no window), but may refresh
    /// history_len.
    #[test]
    fn scrollback_rows_after_return_to_live_does_not_resurrect() {
        let shared = shared_with_live("gen-a", 40, 6);
        // view_offset == 0 (live).
        let woke = apply_scrollback_rows(
            &shared,
            "my-session",
            "my-session",
            SessionGeneration("gen-a".into()),
            Revision(50),
            100,
            5,
            hist_rows(40, 6),
        );
        assert!(woke);
        let sb = shared.scrollback.lock().unwrap();
        assert_eq!(sb.view_offset, 0, "stays at the live bottom");
        assert!(sb.historical.is_none(), "no historical window resurrected");
        assert_eq!(sb.history_len, Some(100), "history_len still refreshed");
    }

    // --- bootstrap: first scroll from bottom with UNKNOWN history dispatches -

    /// The very first wheel/PageUp from the live bottom happens before any reply, so
    /// `history_len` is `None`. The renderer must still move to a provisional offset and
    /// dispatch one `Scrollback` request to learn the real length. We assert the exact
    /// offset-resolution + request the `App::apply_scroll` flow performs, without a window.
    #[test]
    fn first_scroll_with_unknown_history_dispatches_request() {
        let (shared, queue) = Shared::with_test_queue();
        *shared.grid.lock().unwrap() = Some(Arc::new(live_grid("gen-a", 40, 6, false)));
        // Fresh state: at the live bottom, history length not yet known.
        {
            let sb = shared.scrollback.lock().unwrap();
            assert_eq!(sb.view_offset, 0);
            assert_eq!(sb.history_len, None, "length unknown at bootstrap");
        }

        // Mirror App::apply_scroll's core: resolve the new offset (rows=6 = one page),
        // see it move off zero, store it, and enqueue a Scrollback for it.
        let page = 6u32;
        let new_offset = next_view_offset(0, None, page, ScrollAction::PageUp);
        assert!(
            new_offset > 0,
            "first PageUp moves even with unknown history"
        );
        shared.scrollback.lock().unwrap().view_offset = new_offset;
        shared.send_request(&ClientRequest::Scrollback {
            id: "my-session".to_string(),
            offset_from_top: new_offset,
            count: page as u16,
        });

        assert_eq!(
            queue.len(),
            1,
            "first scroll-up dispatches exactly one Scrollback request"
        );
    }

    /// If the bootstrap request comes back with `history_len = 0` (no scrollback exists),
    /// the provisional offset must NOT strand us in scrolled mode: we snap back to live.
    #[test]
    fn no_history_reply_returns_to_live() {
        let shared = shared_with_live("gen-a", 40, 6);
        // We provisionally scrolled up (offset 6) before knowing the length.
        shared.scrollback.lock().unwrap().view_offset = 6;

        let woke = apply_scrollback_rows(
            &shared,
            "my-session",
            "my-session",
            SessionGeneration("gen-a".into()),
            Revision(50),
            0, // the daemon reports: there is no history
            0,
            vec![], // no rows
        );
        assert!(woke, "a reply still repaints");
        let sb = shared.scrollback.lock().unwrap();
        assert_eq!(sb.history_len, Some(0), "length now known to be zero");
        assert_eq!(sb.view_offset, 0, "no-history reply snaps back to live");
        assert!(!sb.is_scrolled(), "not stuck in scrolled mode");
        assert!(sb.historical.is_none(), "no historical window adopted");
    }

    // --- 9: live updates while scrolled don't move the historical viewport ---

    #[test]
    fn live_update_while_scrolled_keeps_historical_viewport() {
        let shared = shared_with_live("gen-a", 40, 6);
        // Adopt a historical window at offset 10.
        shared.scrollback.lock().unwrap().view_offset = 10;
        apply_scrollback_rows(
            &shared,
            "my-session",
            "my-session",
            SessionGeneration("gen-a".into()),
            Revision(50),
            100,
            10,
            hist_rows(40, 6),
        );
        let painted_before = shared
            .scrollback
            .lock()
            .unwrap()
            .historical
            .clone()
            .unwrap();

        // Simulate live Damage: the reader updates shared.grid (same generation, newer
        // content). This is exactly what handle_event does for a Damage frame.
        let mut newer = live_grid("gen-a", 40, 6, false);
        newer.revision = Revision(200);
        newer.rows_cells = (0..6).map(|i| row(&format!("NEW{i}"), 40)).collect();
        *shared.grid.lock().unwrap() = Some(Arc::new(newer));

        // The historical viewport the UI paints from is unchanged: scrollback view state
        // is independent of the live grid mutation.
        let sb = shared.scrollback.lock().unwrap();
        assert_eq!(sb.view_offset, 10, "live update does not move the viewport");
        assert!(
            Arc::ptr_eq(sb.historical.as_ref().unwrap(), &painted_before),
            "the historical window the UI paints is the same Arc, untouched by live damage"
        );
    }

    // --- 10: returning to the bottom paints the current live grid -----------

    #[test]
    fn returning_to_bottom_paints_live_grid() {
        let shared = shared_with_live("gen-a", 40, 6);
        // Scrolled up with a cached window.
        {
            let mut sb = shared.scrollback.lock().unwrap();
            sb.view_offset = 8;
            sb.historical = Some(Arc::new(scrollback_snapshot(
                SessionGeneration("gen-a".into()),
                Revision(1),
                hist_rows(40, 6),
            )));
            sb.historical_generation = Some(SessionGeneration("gen-a".into()));
        }
        // Returning to the bottom: offset reaches 0, reset_to_live drops the window so
        // draw() falls through to the live grid.
        let new = next_view_offset(8, Some(100), 6, ScrollAction::End);
        assert_eq!(new, 0);
        {
            let mut sb = shared.scrollback.lock().unwrap();
            sb.reset_to_live();
            assert!(!sb.is_scrolled(), "back at the live bottom");
            assert!(sb.historical.is_none(), "draw paints the live grid now");
        }
        // The live grid is still present and current — that is what draw() will paint.
        assert!(shared.grid.lock().unwrap().is_some());
    }

    // --- WheelAccumulator: sub-line trackpad/wheel delta accumulation ---

    #[test]
    fn wheel_pixels_below_one_line_accumulate_then_step() {
        // A gentle macOS trackpad delivers a stream of small (<16px) PixelDelta events.
        // Each alone rounds to nothing, but together they must cross a line boundary.
        let mut w = WheelAccumulator::default();
        assert_eq!(w.add_pixels(5.0), 0, "5px < one line, no step yet");
        assert_eq!(w.add_pixels(5.0), 0, "10px accumulated, still < 16");
        assert_eq!(w.add_pixels(5.0), 0, "15px accumulated, still < 16");
        assert_eq!(
            w.add_pixels(5.0),
            1,
            "20px crosses one line: emit 1 step up"
        );
    }

    #[test]
    fn wheel_pixel_remainder_carries_forward() {
        // After emitting a whole step the fractional remainder must persist so the next
        // small event builds on it rather than restarting from zero.
        let mut w = WheelAccumulator::default();
        assert_eq!(
            w.add_pixels(20.0),
            1,
            "20px -> 1 step, 4px remainder retained"
        );
        // 12px + 4px carried = 16px = exactly one more line.
        assert_eq!(
            w.add_pixels(12.0),
            1,
            "carried remainder completes the next line"
        );
    }

    #[test]
    fn wheel_negative_pixels_step_toward_live() {
        // Negative y = scroll down toward live; sign must pass through to ScrollAction.
        let mut w = WheelAccumulator::default();
        assert_eq!(w.add_pixels(-20.0), -1, "down past one line -> -1 step");
    }

    #[test]
    fn wheel_line_delta_passes_whole_lines() {
        // Classic wheels deliver LineDelta already in line units.
        let mut w = WheelAccumulator::default();
        assert_eq!(w.add_lines(3.0), 3, "whole lines pass straight through");
        assert_eq!(w.add_lines(-1.0), -1, "negative line delta toward live");
    }

    #[test]
    fn wheel_line_delta_fraction_accumulates_with_pixels() {
        // LineDelta and PixelDelta feed the same residue, so a fractional line plus a
        // few pixels can complete a step together.
        let mut w = WheelAccumulator::default();
        assert_eq!(w.add_lines(0.5), 0, "half a line is not yet a step");
        // 0.5 line residue + 8px (=0.5 line) = 1.0 line.
        assert_eq!(
            w.add_pixels(8.0),
            1,
            "fractional line + pixels complete a step"
        );
    }

    #[test]
    fn wheel_sign_matches_scroll_action_up_into_history() {
        // Positive accumulated delta maps to ScrollAction::Lines positive = up into
        // history; negative = down toward live. Lock that mapping in.
        let mut w = WheelAccumulator::default();
        let up = w.add_pixels(32.0);
        assert!(up > 0, "positive delta is up into history");
        let mut w2 = WheelAccumulator::default();
        let down = w2.add_pixels(-32.0);
        assert!(down < 0, "negative delta is down toward live");
    }

    #[test]
    fn wheel_route_mouse_reporting_precedes_alternate_fallback() {
        assert_eq!(
            wheel_route(3, true, true),
            WheelRoute::MouseReport {
                event: MouseEvent::WheelUp,
                steps: 3,
            }
        );
        assert_eq!(
            wheel_route(-2, true, true),
            WheelRoute::MouseReport {
                event: MouseEvent::WheelDown,
                steps: 2,
            }
        );
    }

    #[test]
    fn wheel_route_alt_screen_without_mouse_uses_cursor_keys() {
        assert_eq!(
            wheel_route(4, true, false),
            WheelRoute::AlternateScroll {
                key: HostNamedKey::ArrowUp,
                steps: 4,
            }
        );
        assert_eq!(
            wheel_route(-5, true, false),
            WheelRoute::AlternateScroll {
                key: HostNamedKey::ArrowDown,
                steps: 5,
            }
        );
    }

    #[test]
    fn wheel_route_normal_screen_uses_bounded_renderer_scrollback() {
        assert_eq!(
            wheel_route(3, false, false),
            WheelRoute::RendererScroll(ScrollAction::Lines(3))
        );
        assert_eq!(
            wheel_route(i64::MAX, false, false),
            WheelRoute::RendererScroll(ScrollAction::Lines(MAX_WHEEL_STEPS_PER_EVENT))
        );
        assert_eq!(
            wheel_route(i64::MIN, false, false),
            WheelRoute::RendererScroll(ScrollAction::Lines(-MAX_WHEEL_STEPS_PER_EVENT))
        );
        assert_eq!(wheel_route(0, true, true), WheelRoute::NoOp);
    }

    #[test]
    fn alternate_scroll_keys_honor_application_cursor_mode() {
        let plain = encode_key(
            &HostKey::Named(HostNamedKey::ArrowUp),
            None,
            None,
            &HostModifiers::default(),
            TermModes::default(),
        );
        assert_eq!(plain.as_deref(), Some("\x1b[A"));

        let application = encode_key(
            &HostKey::Named(HostNamedKey::ArrowUp),
            None,
            None,
            &HostModifiers::default(),
            TermModes {
                app_cursor: true,
                ..TermModes::default()
            },
        );
        assert_eq!(application.as_deref(), Some("\x1bOA"));
    }
}

#[cfg(test)]
mod decode_error_tests {
    use super::*;

    #[test]
    fn every_decode_error_requires_resync() {
        // A dropped frame may have been a Damage mutation; the structured-only renderer
        // cannot just log and stay stale. All three decode failures must resync.
        assert!(decode_error_requires_resync(&DecodeError::BadEnvelope));
        assert!(decode_error_requires_resync(&DecodeError::BadPayload {
            message: "trailing comma".to_string(),
        }));
        assert!(decode_error_requires_resync(&DecodeError::DamageTooLarge {
            bytes: 999_999,
        }));
    }

    #[test]
    fn malformed_damage_line_decodes_to_resync_decision() {
        // End-to-end through the real decoder: a damage event with a structurally
        // broken payload fails to decode, and that failure is classified as needing a
        // resync (not a silent skip). This guards the BadPayload path specifically.
        let line =
            r#"{"ev":"damage","id":"s1","base_revision":1,"revision":2,"ops":[{"bogus":true}]}"#;
        let err = decode_event(line).expect_err("malformed damage payload must not decode");
        assert!(
            decode_error_requires_resync(&err),
            "a malformed damage frame must trigger resync, got {err:?}"
        );
    }
}

// ============================================================================
// Session-rebind tests (the single-renderer tab-switch primitive). These cover
// the pure switch-plan ordering, the reader-side `SyncState` rebind, and that a
// late old-session frame is rejected while the new session's baseline is accepted
// into a fresh `SyncState`. No window / event loop / socket is needed.
// ============================================================================
#[cfg(test)]
mod rebind_tests {
    use super::*;
    use crate::sync::{Reject, SyncPhase};

    struct SinkSender;

    impl UserEventSender for SinkSender {
        fn send(&self, _event: UserEvent) -> Result<(), UserEvent> {
            Ok(())
        }

        fn clone_sender(&self) -> Box<dyn UserEventSender> {
            Box::new(SinkSender)
        }
    }

    fn color() -> crate::wire::Color {
        crate::wire::Color::Named {
            name: crate::wire::NamedColor::Foreground,
        }
    }

    fn cell() -> Cell {
        Cell {
            text: "x".to_string(),
            fg: color(),
            bg: color(),
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

    fn grid(gen: &str, rev: u64) -> GridSnapshot {
        GridSnapshot {
            version: crate::sync::SUPPORTED_VERSION,
            generation: SessionGeneration(gen.to_string()),
            revision: Revision(rev),
            base_revision: Revision(rev),
            cols: 2,
            rows: 1,
            rows_cells: vec![vec![cell(), cell()]],
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
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

    fn damage(id: &str, gen: &str, base: u64, rev: u64) -> crate::wire::DamageFrame {
        use crate::wire::{CursorState, DamageOp, ModeState};
        let mut blank = cell();
        blank.text = " ".to_string();
        crate::wire::DamageFrame {
            schema: crate::wire::DAMAGE_SCHEMA,
            id: id.to_string(),
            generation: SessionGeneration(gen.to_string()),
            base_revision: Revision(base),
            revision: Revision(rev),
            cols: 2,
            rows: 1,
            cursor: CursorState {
                line: 0,
                col: 1,
                visible: true,
                shape: CursorShape::Block,
            },
            modes: ModeState {
                alt_screen: false,
                app_cursor: false,
                bracketed_paste: false,
                focus_reporting: false,
                mouse_report: false,
                mouse_drag: false,
                mouse_motion: false,
                mouse_sgr: false,
            },
            ops: vec![DamageOp::ClearAll { cell: blank }],
        }
    }

    // --- pure switch-plan ordering ------------------------------------------

    #[test]
    fn switch_plan_with_dims_is_detach_attach_resize_snapshot_in_order() {
        let plan = plan_attach_switch("old", "new", Some((120, 40)));
        assert_eq!(plan.len(), 4);
        match &plan[0] {
            ClientRequest::Detach { id } => assert_eq!(id, "old"),
            other => panic!("first request must be Detach{{old}}, got {other:?}"),
        }
        match &plan[1] {
            ClientRequest::Attach {
                id,
                want_raw_output,
            } => {
                assert_eq!(id, "new");
                assert!(!want_raw_output, "switch attach must be structured-only");
            }
            other => panic!("second request must be Attach{{new}}, got {other:?}"),
        }
        match &plan[2] {
            ClientRequest::Resize { id, cols, rows } => {
                assert_eq!(id, "new");
                assert_eq!((*cols, *rows), (120, 40));
            }
            other => panic!("third request must be Resize{{new}}, got {other:?}"),
        }
        match &plan[3] {
            ClientRequest::Snapshot { id } => assert_eq!(id, "new"),
            other => panic!("fourth request must be Snapshot{{new}}, got {other:?}"),
        }
    }

    #[test]
    fn switch_plan_without_dims_omits_resize() {
        let plan = plan_attach_switch("old", "new", None);
        assert_eq!(plan.len(), 2, "no geometry -> no Resize");
        assert!(matches!(&plan[0], ClientRequest::Detach { id } if id == "old"));
        assert!(
            matches!(&plan[1], ClientRequest::Attach { id, want_raw_output } if id == "new" && !*want_raw_output)
        );
    }

    #[test]
    fn legacy_snapshot_boundary_orphans_are_repaired_before_strict_sync_validation() {
        let mut snap = grid("g", 1);
        snap.rows_cells[0][0].text.clear();
        snap.rows_cells[0][0].width = 0;
        snap.rows_cells[0][1].text = "中".to_string();
        snap.rows_cells[0][1].width = 2;

        assert_eq!(
            SyncState::new("sid").on_grid("sid", &snap),
            Err(Reject::InvalidWideLayout { row: 0, col: 0 }),
            "the unmodified legacy snapshot demonstrates the retained-daemon failure"
        );
        assert_eq!(normalize_legacy_snapshot_wide_boundaries(&mut snap), 2);
        assert_eq!(
            (
                snap.rows_cells[0][0].text.as_str(),
                snap.rows_cells[0][0].width
            ),
            (" ", 1)
        );
        assert_eq!(
            (
                snap.rows_cells[0][1].text.as_str(),
                snap.rows_cells[0][1].width
            ),
            (" ", 1)
        );
        assert!(
            SyncState::new("sid").on_grid("sid", &snap).is_ok(),
            "the narrow boundary repair must restore a valid authoritative baseline"
        );
    }

    #[test]
    fn legacy_snapshot_compatibility_leaves_valid_wide_pairs_byte_for_byte_unchanged() {
        let mut snap = grid("g", 1);
        snap.rows_cells[0][0].text = "中".to_string();
        snap.rows_cells[0][0].width = 2;
        snap.rows_cells[0][1].text.clear();
        snap.rows_cells[0][1].width = 0;
        let before = snap.rows_cells.clone();

        assert_eq!(normalize_legacy_snapshot_wide_boundaries(&mut snap), 0);
        assert_eq!(snap.rows_cells, before);
        assert!(SyncState::new("sid").on_grid("sid", &snap).is_ok());
    }

    #[test]
    fn legacy_snapshot_compatibility_does_not_hide_interior_wide_corruption() {
        let mut snap = grid("g", 1);
        snap.cols = 3;
        snap.rows_cells[0].push(cell());
        snap.rows_cells[0][1].text = "中".to_string();
        snap.rows_cells[0][1].width = 2;

        assert_eq!(normalize_legacy_snapshot_wide_boundaries(&mut snap), 0);
        assert_eq!(
            SyncState::new("sid").on_grid("sid", &snap),
            Err(Reject::InvalidWideLayout { row: 0, col: 1 })
        );
    }

    // --- active-session state + reader rebind --------------------------------

    #[test]
    fn set_active_session_bumps_epoch_and_swaps_id() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-old");
        let before = shared.active_snapshot();
        assert_eq!(
            before,
            ActiveSession {
                id: "s-old".into(),
                epoch: 0
            }
        );

        let epoch = shared.set_active_session("s-new");
        assert_eq!(epoch, 1);
        assert_eq!(
            shared.active_snapshot(),
            ActiveSession {
                id: "s-new".into(),
                epoch: 1
            }
        );
    }

    #[test]
    fn sync_active_session_rebinds_reader_id_and_sync_and_resets_state() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-old");

        // The reader's thread-locals, as in `spawn`.
        let mut session_id = "s-old".to_string();
        let mut sync = SyncState::new(session_id.clone());
        let mut epoch = 0u64;

        // Bring the old session to Synchronized and seed shared state that a switch
        // must clear so stale rows can't paint as the new session.
        sync.on_grid("s-old", &grid("gen-old", 100)).unwrap();
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-old", 100)));
        *shared.exited.lock().unwrap() = Some(Some(0));
        shared.scrollback.lock().unwrap().view_offset = 5;

        // No switch yet: a sync is a no-op.
        assert!(!sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut epoch
        ));

        // The UI thread switches.
        shared.set_active_session("s-new");
        assert!(sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut epoch
        ));

        // Reader thread-locals now follow the new session.
        assert_eq!(session_id, "s-new");
        assert_eq!(epoch, 1);
        assert_eq!(sync.phase(), SyncPhase::AwaitingBaseline);

        // Shared published state was reset (no stale old-session rows survive).
        assert!(shared.grid.lock().unwrap().is_none());
        assert!(shared.exited.lock().unwrap().is_none());
        assert!(shared.last_revision.lock().unwrap().is_none());
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);
    }

    #[test]
    fn old_session_frame_rejected_and_new_session_baseline_accepted_after_switch() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-old");
        let mut session_id = "s-old".to_string();
        let mut sync = SyncState::new(session_id.clone());
        let mut epoch = 0u64;
        sync.on_grid("s-old", &grid("gen-old", 100)).unwrap();

        // Switch to the new session; the reader rebases on its next event.
        shared.set_active_session("s-new");
        sync_active_session(&shared, &mut session_id, &mut sync, &mut epoch);

        // A LATE frame still tagged with the old session id is rejected — it cannot
        // repaint over the new session.
        let stale = sync.on_grid("s-old", &grid("gen-old", 101));
        assert_eq!(stale, Err(Reject::WrongSession));

        // The new session's baseline is accepted into the fresh `SyncState`.
        let outcome = sync
            .on_grid("s-new", &grid("gen-new", 1))
            .expect("new-session baseline must be accepted");
        assert!(outcome.repaint, "the new baseline must paint");
        assert_eq!(sync.phase(), SyncPhase::Synchronized);
    }

    #[test]
    fn pane_to_active_promotion_reader_reconcile_cannot_detach_or_freeze_new_primary() {
        let (shared, queue) = Shared::with_test_queue();
        shared.init_active_session("C");

        // SetTabStrip arrives before AttachSession: while C is still primary, the just-created D is
        // temporarily a non-primary pane member. The UI owns its Attach; reader adoption is local.
        shared.set_pane_sessions(&["A", "B", "D"]);
        let mut pane_syncs = HashMap::new();
        let mut pane_generation = 0;
        assert!(sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut pane_generation
        ));
        assert!(pane_syncs.contains_key("D"));
        assert!(queue.drain_requests().is_empty());

        // AttachSession promotes D. The next role reconcile demotes C into the cache and removes D's
        // old Pane role. Before the fix, this reader path emitted Detach(D), cancelling the active
        // daemon forwarder and leaving D frozen at its initial blank baseline.
        shared.set_active_session("D");
        shared.set_pane_sessions(&["A", "B", "C"]);
        let mut active_id = "C".to_string();
        let mut active_sync = SyncState::new("C");
        let mut active_epoch = 0;
        assert!(sync_active_session(
            &shared,
            &mut active_id,
            &mut active_sync,
            &mut active_epoch
        ));
        assert!(sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut pane_generation
        ));
        assert_eq!(active_id, "D");
        assert!(!pane_syncs.contains_key("D"));
        assert!(pane_syncs.contains_key("C"));
        assert!(
            queue.drain_requests().is_empty(),
            "reader role transition must never emit the fatal Detach(D)"
        );

        // With the active subscription left alive, both its baseline and subsequent structured
        // damage continue through the dedicated primary grid.
        handle_event(
            &shared,
            &mut active_sync,
            &SinkSender,
            "D",
            DaemonEvent::Grid {
                id: "D".to_string(),
                grid: grid("gen-D", 1),
            },
        );
        handle_event(
            &shared,
            &mut active_sync,
            &SinkSender,
            "D",
            DaemonEvent::Damage {
                frame: damage("D", "gen-D", 1, 2),
            },
        );
        assert_eq!(
            shared
                .grid
                .lock()
                .unwrap()
                .as_ref()
                .map(|grid| grid.revision),
            Some(Revision(2)),
            "promoted D remains live after its old Pane role is removed"
        );
    }

    #[test]
    fn reset_session_state_clears_grid_exit_revision_scrollback() {
        let shared = Arc::new(Shared::default());
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("g", 1)));
        *shared.exited.lock().unwrap() = Some(Some(7));
        *shared.last_revision.lock().unwrap() = Some((Revision(9), Instant::now()));
        {
            let mut scrollback = shared.scrollback.lock().unwrap();
            scrollback.view_offset = 3;
            scrollback.history_len = Some(42);
            scrollback.historical_generation = Some(SessionGeneration("old-session".into()));
        }

        reset_session_state(&shared);

        assert!(shared.grid.lock().unwrap().is_none());
        assert!(shared.exited.lock().unwrap().is_none());
        assert!(shared.last_revision.lock().unwrap().is_none());
        let scrollback = shared.scrollback.lock().unwrap();
        assert_eq!(scrollback.view_offset, 0);
        assert_eq!(
            scrollback.history_len, None,
            "a new session must not inherit the old PTY's cached history ceiling"
        );
        assert!(scrollback.historical.is_none());
        assert!(scrollback.historical_generation.is_none());
    }

    // Reader-switch race: the reader rebases at the TOP of the loop, then
    // blocks in `read_until`. If the UI switches the active session WHILE the reader is
    // blocked, the just-read frame must be filtered against the NEW session. The reader
    // therefore rebases AGAIN after the read, before decode/handle. This test reproduces
    // the window: top-of-loop rebase runs first (no switch yet), then the UI switches
    // mid-block, then the new session's baseline arrives. Without the post-read rebase the
    // baseline would be wrongly rejected as `WrongSession`; with it, the baseline is
    // accepted.
    #[test]
    fn reader_rebases_after_blocked_read_then_accepts_new_baseline() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-old");
        let mut session_id = "s-old".to_string();
        let mut sync = SyncState::new(session_id.clone());
        let mut epoch = 0u64;
        sync.on_grid("s-old", &grid("gen-old", 100)).unwrap();

        // Top-of-loop rebase: no switch yet, so it is a no-op and we stay on s-old.
        assert!(!sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut epoch
        ));
        assert_eq!(session_id, "s-old");

        // The reader is now "blocked in read_until". The UI switches the active session.
        shared.set_active_session("s-new");

        // A new-session baseline `Grid` is delivered. WITHOUT the post-read rebase the
        // reader is still bound to s-old, so the new baseline would be rejected:
        assert_eq!(
            sync.on_grid("s-new", &grid("gen-new", 1)),
            Err(Reject::WrongSession),
            "control: pre-rebase the new baseline is rejected as wrong-session"
        );

        // The post-read rebase (the fix) runs before decode/handle of the just-read line.
        assert!(sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut epoch
        ));
        assert_eq!(session_id, "s-new");
        assert_eq!(sync.phase(), SyncPhase::AwaitingBaseline);

        // Now the SAME just-read new-session baseline is accepted into the fresh state.
        let outcome = sync
            .on_grid("s-new", &grid("gen-new", 1))
            .expect("post-rebase the new baseline must be accepted");
        assert!(outcome.repaint);
        assert_eq!(sync.phase(), SyncPhase::Synchronized);
    }

    // UI-switch race: `App::attach_session` must clear the SHARED
    // published state immediately on the UI thread, before its `request_redraw`, so the
    // window cannot repaint stale old-session rows in the gap before the reader thread
    // wakes and rebases. This test mirrors the UI-thread mutation order from
    // `App::attach_session` (reset_session_state + set_active_session) and asserts the
    // shared state is already clear WITHOUT the reader having run `sync_active_session`.
    #[test]
    fn ui_switch_clears_shared_state_before_reader_runs() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-old");

        // Seed shared published state as if s-old were live and Synchronized.
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-old", 100)));
        *shared.exited.lock().unwrap() = Some(Some(0));
        *shared.last_revision.lock().unwrap() = Some((Revision(100), Instant::now()));
        shared.scrollback.lock().unwrap().view_offset = 5;

        // UI-thread switch path (matches `App::attach_session`): clear shared state
        // immediately, THEN bump the epoch. The reader has NOT run yet.
        reset_session_state(&shared);
        shared.set_active_session("s-new");

        // Shared state is already clear — a redraw in this gap paints nothing stale.
        assert!(shared.grid.lock().unwrap().is_none());
        assert!(shared.exited.lock().unwrap().is_none());
        assert!(shared.last_revision.lock().unwrap().is_none());
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);

        // The reader's later rebase is idempotent: it observes the epoch, rebinds, and
        // resetting again leaves the shared state clear (no panic, still empty).
        let mut session_id = "s-old".to_string();
        let mut sync = SyncState::new(session_id.clone());
        let mut epoch = 0u64;
        assert!(sync_active_session(
            &shared,
            &mut session_id,
            &mut sync,
            &mut epoch
        ));
        assert_eq!(session_id, "s-new");
        assert!(shared.grid.lock().unwrap().is_none());
        assert!(shared.exited.lock().unwrap().is_none());
    }

    // --- inactive-pane sibling session cache (attach + cache only) -----------

    #[test]
    fn sibling_attach_plan_attaches_and_resizes_without_detaching_active() {
        // First sibling (no prior sibling): Attach(new) then Resize(new) — and crucially NO
        // Detach of anything, so the active session is never disturbed by binding the sibling.
        let plan = plan_sibling_attach(None, "sib-1", Some((40, 12)));
        assert_eq!(plan.len(), 2);
        assert!(
            matches!(&plan[0], ClientRequest::Attach { id, want_raw_output } if id == "sib-1" && !*want_raw_output)
        );
        assert!(
            matches!(&plan[1], ClientRequest::Resize { id, cols, rows } if id == "sib-1" && (*cols, *rows) == (40, 12))
        );
        assert!(
            !plan
                .iter()
                .any(|r| matches!(r, ClientRequest::Detach { .. })),
            "binding the first sibling must never detach (the active session stays attached)"
        );
    }

    #[test]
    fn sibling_replace_detaches_only_the_old_sibling_then_attaches_new() {
        // Replacing the sibling detaches the OLD SIBLING only (never the active session),
        // then attaches+resizes the new sibling.
        let plan = plan_sibling_attach(Some("sib-old"), "sib-new", Some((30, 10)));
        assert_eq!(plan.len(), 3);
        assert!(matches!(&plan[0], ClientRequest::Detach { id } if id == "sib-old"));
        assert!(
            matches!(&plan[1], ClientRequest::Attach { id, want_raw_output } if id == "sib-new" && !*want_raw_output)
        );
        assert!(
            matches!(&plan[2], ClientRequest::Resize { id, cols, rows } if id == "sib-new" && (*cols, *rows) == (30, 10))
        );
    }

    #[test]
    fn same_sibling_replan_resizes_only_no_detach_or_reattach() {
        // A same-sibling draw with a new pane size resizes the bound sibling and does NOT
        // detach/reattach it.
        let plan = plan_sibling_attach(Some("sib-1"), "sib-1", Some((50, 14)));
        assert_eq!(plan.len(), 1);
        assert!(
            matches!(&plan[0], ClientRequest::Resize { id, cols, rows } if id == "sib-1" && (*cols, *rows) == (50, 14))
        );
    }

    #[test]
    fn changing_inactive_session_replaces_cache_and_ignores_late_old_sibling_frame() {
        let shared = Arc::new(Shared::default());
        // Bind sibling A, cache a grid for it.
        let epoch_a = shared.set_sibling_session("sib-a");
        assert!(shared.apply_sibling_grid("sib-a", epoch_a, Arc::new(grid("gen-a", 1))));
        assert!(shared.sibling_snapshot().grid.is_some());

        // Inactive pane changes to sibling B: cache is replaced (cleared) and epoch bumps.
        let epoch_b = shared.set_sibling_session("sib-b");
        assert_ne!(epoch_a, epoch_b);
        let snap = shared.sibling_snapshot();
        assert_eq!(snap.id.as_deref(), Some("sib-b"));
        assert!(
            snap.grid.is_none(),
            "rebinding must clear the prior sibling grid"
        );

        // A late frame from the OLD sibling (its id AND its stale epoch) is dropped.
        assert!(!shared.apply_sibling_grid("sib-a", epoch_a, Arc::new(grid("gen-a", 2))));
        assert!(shared.sibling_snapshot().grid.is_none());

        // A frame for the current sibling at the current epoch is accepted.
        assert!(shared.apply_sibling_grid("sib-b", epoch_b, Arc::new(grid("gen-b", 1))));
        assert!(shared.sibling_snapshot().grid.is_some());
    }

    #[test]
    fn active_and_sibling_grids_update_independent_caches() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-active");
        let epoch = shared.set_sibling_session("s-sibling");

        // An active-session grid lands in `shared.grid` and must NOT touch the sibling cache.
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-active", 1)));
        assert!(shared.grid.lock().unwrap().is_some());
        assert!(
            shared.sibling_snapshot().grid.is_none(),
            "an active-session frame must never populate the sibling cache"
        );

        // A sibling grid lands in the sibling cache and must NOT touch the active grid's revision.
        let before_active = shared.grid.lock().unwrap().clone();
        assert!(shared.apply_sibling_grid("s-sibling", epoch, Arc::new(grid("gen-sib", 7))));
        assert!(shared.sibling_snapshot().grid.is_some());
        let after_active = shared.grid.lock().unwrap().clone();
        assert!(
            Arc::ptr_eq(&before_active.unwrap(), &after_active.unwrap()),
            "a sibling frame must leave the active grid Arc untouched"
        );
    }

    #[test]
    fn clearing_sibling_does_not_disrupt_active_session() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-active");
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-active", 1)));
        *shared.exited.lock().unwrap() = Some(None);
        let active_before = shared.active_snapshot();

        // Bind then clear the sibling (split torn down): sibling cache empties, epoch bumps,
        // but the active session id/epoch/grid/exit are all untouched.
        shared.set_sibling_session("s-sibling");
        shared.clear_sibling_session();
        let snap = shared.sibling_snapshot();
        assert!(snap.id.is_none());
        assert!(snap.grid.is_none());

        assert_eq!(shared.active_snapshot(), active_before);
        assert!(shared.grid.lock().unwrap().is_some());
        assert_eq!(*shared.exited.lock().unwrap(), Some(None));
    }

    // --- sibling frame ingest (reader teaches the sibling cache) --------------
    //
    // `handle_sibling_event` needs a live `EventLoopProxy`, which can't be built without
    // an event loop in a unit test — so (like the active path) these exercise the exact
    // composable pieces the handler runs: `event_session_id` routing, `sync_sibling_session`
    // rebind, the sibling `SyncState` gate, and `apply_sibling_grid`/`apply_sibling_exit`.

    /// A `ClearAll` damage frame over the 2-col x 1-row shape `grid()` produces,
    /// advancing `base` -> `rev` for `gen`. Sized/shaped to apply cleanly onto a
    /// `grid(gen, base)` baseline so `on_damage` yields `Applied`.
    fn damage_frame(id: &str, gen: &str, base: u64, rev: u64) -> crate::wire::DamageFrame {
        use crate::wire::{CursorState, DamageOp, ModeState};
        crate::wire::DamageFrame {
            schema: crate::wire::DAMAGE_SCHEMA,
            id: id.to_string(),
            generation: SessionGeneration(gen.to_string()),
            base_revision: Revision(base),
            revision: Revision(rev),
            cols: 2,
            rows: 1,
            cursor: CursorState {
                line: 0,
                col: 0,
                visible: true,
                shape: CursorShape::Block,
            },
            modes: ModeState {
                alt_screen: false,
                app_cursor: false,
                bracketed_paste: false,
                focus_reporting: false,
                mouse_report: false,
                mouse_drag: false,
                mouse_motion: false,
                mouse_sgr: false,
            },
            ops: vec![DamageOp::ClearAll {
                cell: Cell {
                    text: " ".to_string(),
                    width: 1,
                    ..cell()
                },
            }],
        }
    }

    #[test]
    fn sibling_grid_baseline_populates_sibling_cache_and_leaves_active_untouched() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-active");
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-active", 1)));
        let active_before = shared.grid.lock().unwrap().clone();

        let epoch = shared.set_sibling_session("s-sib");
        let mut sync = SyncState::new("s-sib".to_string());

        // A sibling baseline Grid: gate through the sibling SyncState, then publish.
        let snap = grid("gen-sib", 5);
        let outcome = sync.on_grid("s-sib", &snap).expect("baseline accepted");
        assert!(outcome.repaint);
        assert!(shared.apply_sibling_grid("s-sib", epoch, Arc::new(snap)));

        // Sibling cache is populated; the active grid Arc is byte-for-byte untouched.
        assert!(shared.sibling_snapshot().grid.is_some());
        let after = shared.grid.lock().unwrap().clone();
        assert!(Arc::ptr_eq(&active_before.unwrap(), &after.unwrap()));
    }

    #[test]
    fn primary_screen_transition_resets_only_stale_scrollback_view() {
        let shared = Arc::new(Shared::default());
        shared.publish_primary_grid(Arc::new(grid("gen-active", 1)));
        shared.scrollback.lock().unwrap().view_offset = 7;

        // Ordinary primary-screen damage preserves the user's historical position.
        shared.publish_primary_grid(Arc::new(grid("gen-active", 2)));
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 7);

        // Entering alternate screen invalidates that renderer-owned historical viewport.
        let mut alt = grid("gen-active", 3);
        alt.alt_screen = true;
        shared.publish_primary_grid(Arc::new(alt));
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);

        // Defensive symmetry: a stale offset cannot survive the transition back either.
        shared.scrollback.lock().unwrap().view_offset = 5;
        shared.publish_primary_grid(Arc::new(grid("gen-active", 4)));
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);
    }

    #[test]
    fn sibling_screen_transition_resets_its_own_scrollback_only() {
        let shared = Arc::new(Shared::default());
        let epoch = shared.set_sibling_session("s-sib");
        assert!(shared.apply_sibling_grid("s-sib", epoch, Arc::new(grid("gen-sib", 1))));
        shared.with_pane_scrollback("s-sib", "s-active", |sb| sb.view_offset = 9);
        shared.scrollback.lock().unwrap().view_offset = 4;

        let mut alt = grid("gen-sib", 2);
        alt.alt_screen = true;
        assert!(shared.apply_sibling_grid("s-sib", epoch, Arc::new(alt)));

        assert_eq!(
            shared.with_pane_scrollback("s-sib", "s-active", |sb| sb.view_offset),
            0,
            "sibling transition clears the sibling viewport"
        );
        assert_eq!(
            shared.scrollback.lock().unwrap().view_offset,
            4,
            "sibling transition never clears the primary viewport"
        );
    }

    #[test]
    fn extra_pane_screen_transition_resets_that_pane_only() {
        let shared = Arc::new(Shared::default());
        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        let epoch_b = shared.pane_epoch("pane-b").unwrap();
        let epoch_c = shared.pane_epoch("pane-c").unwrap();
        assert!(shared.apply_pane_grid("pane-b", epoch_b, Arc::new(grid("gen-b", 1))));
        assert!(shared.apply_pane_grid("pane-c", epoch_c, Arc::new(grid("gen-c", 1))));
        shared.with_pane_scrollback("pane-b", "primary", |sb| sb.view_offset = 6);
        shared.with_pane_scrollback("pane-c", "primary", |sb| sb.view_offset = 8);

        let mut alt = grid("gen-b", 2);
        alt.alt_screen = true;
        assert!(shared.apply_pane_grid("pane-b", epoch_b, Arc::new(alt)));

        assert_eq!(
            shared.with_pane_scrollback("pane-b", "primary", |sb| sb.view_offset),
            0
        );
        assert_eq!(
            shared.with_pane_scrollback("pane-c", "primary", |sb| sb.view_offset),
            8,
            "another pane's transition cannot leak into this pane"
        );
    }

    #[test]
    fn sibling_damage_updates_cache_only_after_sibling_baseline() {
        let shared = Arc::new(Shared::default());
        let epoch = shared.set_sibling_session("s-sib");
        let mut sync = SyncState::new("s-sib".to_string());

        // BEFORE baseline: the sibling cache holds no grid. `handle_sibling_event`'s
        // damage arm reads the cached grid and short-circuits when it is `None`, so a
        // pre-baseline damage frame can never produce a cached grid.
        assert!(shared.sibling_snapshot().grid.is_none());

        // Seed a baseline Grid into the cache (the only way `grid` becomes `Some`).
        let base = grid("gen-sib", 5);
        sync.on_grid("s-sib", &base).expect("baseline accepted");
        assert!(shared.apply_sibling_grid("s-sib", epoch, Arc::new(base)));
        let held = shared.sibling_snapshot().grid.clone().unwrap();

        // AFTER baseline: a damage frame applies onto the cached grid and advances it.
        let frame = damage_frame("s-sib", "gen-sib", 5, 6);
        match sync.on_damage(&frame.id, &frame, &held) {
            DamageOutcome::Applied(g) => {
                assert!(shared.apply_sibling_grid("s-sib", epoch, Arc::from(g)));
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        assert_eq!(
            shared.sibling_snapshot().grid.unwrap().revision,
            Revision(6)
        );
    }

    #[test]
    fn late_old_sibling_frame_ignored_after_sibling_epoch_changes() {
        let shared = Arc::new(Shared::default());
        let epoch_a = shared.set_sibling_session("sib-a");

        // The inactive pane changes to sibling B (epoch bumps, cache cleared).
        let epoch_b = shared.set_sibling_session("sib-b");
        assert_ne!(epoch_a, epoch_b);

        // A late Grid from the OLD sibling routes by id, but `apply_sibling_grid` drops it:
        // both its id (sib-a) and its stale epoch fail the live binding gate.
        assert!(!shared.apply_sibling_grid("sib-a", epoch_a, Arc::new(grid("gen-a", 9))));
        assert!(shared.sibling_snapshot().grid.is_none());

        // The current sibling's frame at the current epoch is accepted.
        assert!(shared.apply_sibling_grid("sib-b", epoch_b, Arc::new(grid("gen-b", 1))));
        assert!(shared.sibling_snapshot().grid.is_some());
    }

    #[test]
    fn sibling_session_exited_updates_exit_state() {
        let shared = Arc::new(Shared::default());
        let epoch = shared.set_sibling_session("s-sib");
        let mut sync = SyncState::new("s-sib".to_string());
        // A baseline so the SyncState is past AwaitingBaseline before the exit.
        sync.on_grid("s-sib", &grid("gen-sib", 1)).unwrap();

        assert!(matches!(
            sync.on_session_exited("s-sib"),
            Ok(Action::Exited)
        ));
        assert!(shared.apply_sibling_exit("s-sib", epoch, Some(0)));

        let snap = shared.sibling_snapshot();
        assert_eq!(snap.exited, Some(Some(0)));
        // The active session's exit state is untouched.
        assert!(shared.exited.lock().unwrap().is_none());
    }

    #[test]
    fn late_old_sibling_exit_ignored_after_epoch_change() {
        let shared = Arc::new(Shared::default());
        let epoch_a = shared.set_sibling_session("sib-a");
        shared.set_sibling_session("sib-b"); // rebind: epoch bumps, exit cleared
        assert!(!shared.apply_sibling_exit("sib-a", epoch_a, Some(1)));
        assert!(shared.sibling_snapshot().exited.is_none());
    }

    #[test]
    fn event_session_id_routes_frames_to_active_vs_sibling() {
        // Frames carry the id used for routing; Error/Other carry none.
        assert_eq!(
            event_session_id(&DaemonEvent::Grid {
                id: "x".into(),
                grid: grid("g", 1)
            }),
            Some("x")
        );
        assert_eq!(
            event_session_id(&DaemonEvent::Damage {
                frame: damage_frame("y", "g", 1, 2)
            }),
            Some("y")
        );
        assert_eq!(
            event_session_id(&DaemonEvent::SessionExited {
                id: "z".into(),
                code: None
            }),
            Some("z")
        );
        assert_eq!(
            event_session_id(&DaemonEvent::Error {
                message: "boom".into()
            }),
            None
        );
        assert_eq!(event_session_id(&DaemonEvent::Other), None);
    }

    #[test]
    fn sync_sibling_session_rebinds_on_epoch_change_and_drops_on_unbind() {
        let shared = Arc::new(Shared::default());
        let mut sib_id: Option<String> = None;
        let mut sib_sync: Option<SyncState> = None;
        let mut local_epoch = 0u64;

        // No sibling yet (epoch 0 default): no rebind.
        assert!(!sync_sibling_session(
            &shared,
            &mut sib_id,
            &mut sib_sync,
            &mut local_epoch
        ));
        assert!(sib_sync.is_none());

        // UI binds a sibling: the reader adopts it (fresh SyncState, AwaitingBaseline).
        shared.set_sibling_session("s-sib");
        assert!(sync_sibling_session(
            &shared,
            &mut sib_id,
            &mut sib_sync,
            &mut local_epoch
        ));
        assert_eq!(sib_id.as_deref(), Some("s-sib"));
        assert!(sib_sync.is_some());

        // Unbind (split torn down): the reader drops the sibling SyncState so no frames ingest.
        shared.clear_sibling_session();
        assert!(sync_sibling_session(
            &shared,
            &mut sib_id,
            &mut sib_sync,
            &mut local_epoch
        ));
        assert!(sib_id.is_none());
        assert!(sib_sync.is_none());
    }

    // --- multi-pane session cache (N non-active panes; attach + cache only) ---

    #[test]
    fn three_pane_membership_binds_a_cache_entry_per_non_active_pane() {
        let shared = Arc::new(Shared::default());
        // A 3-pane layout's two non-active panes are bound as cache members; the generation bumps.
        let gen = shared.set_pane_sessions(&["pane-b", "pane-c"]);
        assert!(gen > 0);
        let mut ids = shared.pane_ids();
        ids.sort();
        assert_eq!(ids, vec!["pane-b".to_string(), "pane-c".to_string()]);
        assert!(shared.pane_entry("pane-b").is_some());
        assert!(shared.pane_entry("pane-c").is_some());

        // Each member caches a grid INDEPENDENTLY, gated by its own epoch.
        let eb = shared.pane_epoch("pane-b").unwrap();
        let ec = shared.pane_epoch("pane-c").unwrap();
        assert!(shared.apply_pane_grid("pane-b", eb, Arc::new(grid("gen-b", 1))));
        assert!(shared.apply_pane_grid("pane-c", ec, Arc::new(grid("gen-c", 1))));
        assert!(shared.pane_entry("pane-b").unwrap().grid.is_some());
        assert!(shared.pane_entry("pane-c").unwrap().grid.is_some());

        // A frame for an id that was never a member is dropped (no entry to write).
        assert!(!shared.apply_pane_grid("pane-x", 1, Arc::new(grid("gen-x", 1))));
    }

    #[test]
    fn removing_a_pane_clears_only_its_cache_entry() {
        let shared = Arc::new(Shared::default());
        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        let eb = shared.pane_epoch("pane-b").unwrap();
        let ec = shared.pane_epoch("pane-c").unwrap();
        shared.apply_pane_grid("pane-b", eb, Arc::new(grid("gen-b", 1)));
        shared.apply_pane_grid("pane-c", ec, Arc::new(grid("gen-c", 1)));

        // Remove only pane-c (layout collapsed it). pane-b's entry + grid survive untouched;
        // pane-c's entry is gone and its epoch lookup returns None.
        shared.set_pane_sessions(&["pane-b"]);
        assert!(shared.pane_entry("pane-b").unwrap().grid.is_some());
        assert!(shared.pane_entry("pane-c").is_none());
        assert!(shared.pane_epoch("pane-c").is_none());
        // pane-b keeps the SAME epoch (it was never re-bound), so its in-flight frames still apply.
        assert_eq!(shared.pane_epoch("pane-b"), Some(eb));
        assert!(shared.apply_pane_grid("pane-b", eb, Arc::new(grid("gen-b", 2))));
        assert_eq!(
            shared.pane_entry("pane-b").unwrap().grid.unwrap().revision,
            Revision(2)
        );
    }

    #[test]
    fn late_frame_from_removed_or_replaced_pane_is_dropped() {
        let shared = Arc::new(Shared::default());
        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        let ec_old = shared.pane_epoch("pane-c").unwrap();

        // Remove pane-c, then later re-add it (a pane replaced by a fresh session reusing the slot):
        // its epoch is bumped, so a frame stamped with the OLD epoch is dropped, while a frame at the
        // NEW epoch is accepted.
        shared.set_pane_sessions(&["pane-b"]);
        assert!(!shared.apply_pane_grid("pane-c", ec_old, Arc::new(grid("gen-c", 9))));

        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        let ec_new = shared.pane_epoch("pane-c").unwrap();
        assert_ne!(ec_old, ec_new);
        assert!(!shared.apply_pane_grid("pane-c", ec_old, Arc::new(grid("gen-c", 10))));
        assert!(shared.apply_pane_grid("pane-c", ec_new, Arc::new(grid("gen-c", 11))));

        // A late EXIT from the stale epoch is likewise dropped; the live epoch is recorded.
        assert!(!shared.apply_pane_exit("pane-c", ec_old, Some(1)));
        assert!(shared.apply_pane_exit("pane-c", ec_new, Some(0)));
        assert_eq!(shared.pane_entry("pane-c").unwrap().exited, Some(Some(0)));
    }

    #[test]
    fn unchanged_membership_does_not_bump_generation_and_clear_empties_cache() {
        let shared = Arc::new(Shared::default());
        let g1 = shared.set_pane_sessions(&["pane-b", "pane-c"]);
        // Re-binding the SAME set is a no-op: the generation does not move.
        let g2 = shared.set_pane_sessions(&["pane-c", "pane-b"]);
        assert_eq!(g1, g2);
        // clear_pane_sessions empties the cache and bumps the generation.
        shared.clear_pane_sessions();
        assert!(shared.pane_ids().is_empty());
        assert!(shared.pane_generation() > g2);
    }

    #[test]
    fn pane_cache_is_independent_of_active_and_sibling_caches() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-active");
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-active", 1)));
        shared.set_sibling_session("s-sib");
        shared.set_pane_sessions(&["pane-b"]);

        // A pane frame never touches the active grid nor the rendered sibling.
        let eb = shared.pane_epoch("pane-b").unwrap();
        assert!(shared.apply_pane_grid("pane-b", eb, Arc::new(grid("gen-b", 1))));
        assert!(shared.grid.lock().unwrap().is_some());
        assert!(shared.sibling_snapshot().grid.is_none());
        assert!(shared.pane_entry("pane-b").unwrap().grid.is_some());
    }

    #[test]
    fn sibling_scrollback_rows_update_sibling_view_state() {
        let shared = Arc::new(Shared::default());
        let epoch = shared.set_sibling_session("s-sib");
        assert!(shared.apply_sibling_grid("s-sib", epoch, Arc::new(grid("gen-sib", 1))));
        shared.with_pane_scrollback("s-sib", "s-active", |sb| {
            sb.view_offset = 3;
        });

        assert!(shared.apply_sibling_scrollback(
            "s-sib",
            epoch,
            SessionGeneration("gen-sib".to_string()),
            Revision(2),
            20,
            3,
            vec![vec![cell(), cell()]],
        ));
        let paint = shared.pane_paint("s-sib", "s-active");
        assert_eq!(paint.scrolled_offset, 3);
        assert!(paint.historical.is_some());
    }

    #[test]
    fn extra_pane_scrollback_rows_update_that_pane_only() {
        let shared = Arc::new(Shared::default());
        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        let eb = shared.pane_epoch("pane-b").unwrap();
        let ec = shared.pane_epoch("pane-c").unwrap();
        assert!(shared.apply_pane_grid("pane-b", eb, Arc::new(grid("gen-b", 1))));
        assert!(shared.apply_pane_grid("pane-c", ec, Arc::new(grid("gen-c", 1))));
        shared.with_pane_scrollback("pane-b", "s-active", |sb| {
            sb.view_offset = 4;
        });

        assert!(shared.apply_pane_scrollback(
            "pane-b",
            eb,
            SessionGeneration("gen-b".to_string()),
            Revision(2),
            30,
            4,
            vec![vec![cell(), cell()]],
        ));
        let pane_b = shared.pane_paint("pane-b", "s-active");
        let pane_c = shared.pane_paint("pane-c", "s-active");
        assert_eq!(pane_b.scrolled_offset, 4);
        assert!(pane_b.historical.is_some());
        assert_eq!(pane_c.scrolled_offset, 0);
        assert!(pane_c.historical.is_none());
    }

    #[test]
    fn sync_pane_sessions_rebuilds_only_reader_state_on_generation_change() {
        let (shared, queue) = Shared::with_test_queue();
        let mut pane_syncs: HashMap<String, SyncState> = HashMap::new();
        let mut local_generation = 0u64;

        // No panes yet: no rebuild.
        assert!(!sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut local_generation
        ));
        assert!(pane_syncs.is_empty());

        // Bind two panes: the reader gains a fresh SyncState per id. The UI-side role reconcile is
        // the sole owner of daemon Attach/Detach, so this asynchronous reader emits no wire request.
        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        assert!(sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut local_generation
        ));
        assert!(pane_syncs.contains_key("pane-b"));
        assert!(pane_syncs.contains_key("pane-c"));
        assert!(
            queue.drain_requests().is_empty(),
            "reader membership adoption must not duplicate UI-owned Attach"
        );

        // Re-reconcile with the SAME membership: the generation is unchanged so this is a no-op
        // (no rebuild, no new Attach — only NEW ids attach).
        shared.set_pane_sessions(&["pane-b", "pane-c"]);
        assert!(!sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut local_generation
        ));
        assert_eq!(
            queue.drain_requests().len(),
            0,
            "an unchanged pane membership re-attaches nothing"
        );

        // Remove pane-c: its reader-local SyncState is dropped, but no Detach is emitted here. This
        // is load-bearing for Pane -> Active promotion: a late reader reconcile must not cancel the
        // newly-active role's one daemon forwarder.
        shared.set_pane_sessions(&["pane-b"]);
        assert!(sync_pane_sessions(
            &shared,
            &mut pane_syncs,
            &mut local_generation
        ));
        assert!(pane_syncs.contains_key("pane-b"));
        assert!(!pane_syncs.contains_key("pane-c"));
        assert!(
            queue.drain_requests().is_empty(),
            "reader membership removal must not duplicate UI-owned Detach"
        );
    }

    // --- uniform per-pane paint resolution -----------------------------------

    #[test]
    fn pane_paint_resolves_primary_from_dedicated_fields() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("primary");
        *shared.grid.lock().unwrap() = Some(Arc::new(grid("gen-p", 7)));
        *shared.exited.lock().unwrap() = Some(Some(3));
        {
            let mut sb = shared.scrollback.lock().unwrap();
            sb.view_offset = 4;
            sb.history_len = Some(20);
            sb.historical = Some(Arc::new(grid("gen-p", 5)));
        }

        let pp = shared.pane_paint("primary", "primary");
        assert_eq!(pp.live.as_ref().unwrap().revision.0, 7, "primary live grid");
        assert_eq!(pp.exited, Some(Some(3)), "primary exit");
        assert_eq!(pp.scrolled_offset, 4, "primary's own scrollback offset");
        assert_eq!(pp.history_len, Some(20));
        // Scrolled up with a cut present -> paints the historical window, not live.
        assert_eq!(pp.paint_grid().unwrap().revision.0, 5);
        assert!(pp.scroll_label().is_some());
    }

    #[test]
    fn pane_paint_resolves_non_primary_from_its_own_store_entry() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("primary");
        // A non-primary (extra) pane with its OWN grid + scrollback view.
        shared.set_pane_sessions(&["pane-x"]);
        let epoch = shared.pane_epoch("pane-x").unwrap();
        assert!(shared.apply_pane_grid("pane-x", epoch, Arc::new(grid("gen-x", 11))));
        shared.with_pane_scrollback("pane-x", "primary", |sb| {
            sb.view_offset = 2;
            sb.history_len = Some(9);
            sb.historical = Some(Arc::new(grid("gen-x", 8)));
        });

        let pp = shared.pane_paint("pane-x", "primary");
        assert_eq!(pp.live.as_ref().unwrap().revision.0, 11, "pane's live grid");
        assert_eq!(pp.scrolled_offset, 2, "pane's OWN scrollback offset");
        assert_eq!(
            pp.paint_grid().unwrap().revision.0,
            8,
            "paints pane's history"
        );

        // The primary's dedicated scrollback is UNTOUCHED by the pane's edit (per-pane isolation).
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);

        // An unknown id resolves to the empty default (paints nothing).
        let empty = shared.pane_paint("ghost", "primary");
        assert!(empty.live.is_none() && empty.paint_grid().is_none());
    }

    #[test]
    fn pane_paint_resolves_sibling_store_even_when_not_a_pane_member() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("primary");
        let epoch = shared.set_sibling_session("sibling-x");
        assert!(shared.apply_sibling_grid("sibling-x", epoch, Arc::new(grid("gen-sibling", 17))));

        assert!(
            shared.pane_snapshot("sibling-x").is_none(),
            "pane_snapshot intentionally excludes the sibling store"
        );
        let pp = shared.pane_paint("sibling-x", "primary");
        assert_eq!(
            pp.live.as_ref().unwrap().revision.0,
            17,
            "uniform paint must still resolve sibling grids"
        );
        assert!(pp.paint_grid().is_some());
    }

    #[test]
    fn with_pane_scrollback_routes_to_focused_pane_not_always_primary() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("primary");
        shared.set_pane_sessions(&["pane-y"]);

        // Editing the focused NON-primary pane writes the store entry, leaving the primary at live.
        shared.with_pane_scrollback("pane-y", "primary", |sb| sb.view_offset = 6);
        assert_eq!(
            shared.with_pane_scrollback("pane-y", "primary", |sb| sb.view_offset),
            6
        );
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 0);

        // Editing with the primary as focus writes the dedicated field.
        shared.with_pane_scrollback("primary", "primary", |sb| sb.view_offset = 3);
        assert_eq!(shared.scrollback.lock().unwrap().view_offset, 3);

        // An unknown focused id edits a throwaway default and never panics.
        let read = shared.with_pane_scrollback("ghost", "primary", |sb| {
            sb.view_offset = 99;
            sb.view_offset
        });
        assert_eq!(read, 99, "edit applies to the throwaway only");
    }
}

// ============================================================================
// UserEventSender wake-path tests — possible now that the reader handlers take
// the platform-neutral sender instead of a live winit `EventLoopProxy` (which
// could not be built in a unit test). These prove the delivery contract the
// owner loops (winit on macOS, Tao/GTK on Linux) rely on: every VALIDATED
// state change requests its UserEvent once, in event order; rejected/foreign
// frames wake nothing; and a sender whose loop has already shut down is
// harmless — shared state still updates, nothing panics, nothing retries.
// Linux's sender may coalesce payloadless Redraw requests after this producer
// boundary while one redraw is already pending; typed/non-redraw events remain
// exact FIFO.
// ============================================================================
#[cfg(test)]
mod user_event_sender_tests {
    use super::*;

    // --- test senders -------------------------------------------------------

    /// Records every event in send order — the "live owner loop" double.
    #[derive(Clone)]
    struct RecordingSender(Arc<Mutex<Vec<UserEvent>>>);

    impl UserEventSender for RecordingSender {
        fn send(&self, event: UserEvent) -> Result<(), UserEvent> {
            self.0.lock().unwrap().push(event);
            Ok(())
        }
        fn clone_sender(&self) -> Box<dyn UserEventSender> {
            Box::new(self.clone())
        }
    }

    /// Always refuses — the "owner loop already shut down" double.
    struct ClosedSender;

    impl UserEventSender for ClosedSender {
        fn send(&self, event: UserEvent) -> Result<(), UserEvent> {
            Err(event)
        }
        fn clone_sender(&self) -> Box<dyn UserEventSender> {
            Box::new(ClosedSender)
        }
    }

    /// Compact comparable form of a recorded event (`UserEvent` derives no `PartialEq`).
    fn tag(ev: &UserEvent) -> String {
        match ev {
            UserEvent::Redraw => "redraw".to_string(),
            UserEvent::SessionExited {
                session_id,
                code,
                observed_generation,
            } => format!(
                "exit:{session_id}:{code:?}:{}",
                observed_generation.as_deref().unwrap_or("<none>")
            ),
            UserEvent::TerminalBell => "bell".to_string(),
            UserEvent::TerminalTitle { title } => {
                format!("title:{}", title.clone().unwrap_or_default())
            }
            UserEvent::TerminalClipboardStore { text } => format!("clipboard:{text}"),
            other => format!("other:{other:?}"),
        }
    }

    fn tags(log: &Arc<Mutex<Vec<UserEvent>>>) -> Vec<String> {
        log.lock().unwrap().iter().map(tag).collect()
    }

    // --- fixtures (the same shapes the sibling-ingest tests use) -------------

    fn color() -> crate::wire::Color {
        crate::wire::Color::Named {
            name: crate::wire::NamedColor::Foreground,
        }
    }

    fn cell() -> Cell {
        Cell {
            text: "x".to_string(),
            fg: color(),
            bg: color(),
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

    fn grid(gen: &str, rev: u64) -> GridSnapshot {
        GridSnapshot {
            version: crate::sync::SUPPORTED_VERSION,
            generation: SessionGeneration(gen.to_string()),
            revision: Revision(rev),
            base_revision: Revision(rev),
            cols: 2,
            rows: 1,
            rows_cells: vec![vec![cell(), cell()]],
            cursor_line: 0,
            cursor_col: 0,
            cursor_visible: true,
            cursor_shape: CursorShape::Block,
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

    /// A `ClearAll` damage frame over the 2-col x 1-row shape `grid()` produces,
    /// advancing `base` -> `rev` for `gen`, sized to apply cleanly onto a
    /// `grid(gen, base)` baseline so `on_damage` yields `Applied`.
    fn damage_frame(id: &str, gen: &str, base: u64, rev: u64) -> crate::wire::DamageFrame {
        use crate::wire::{CursorState, DamageOp, ModeState};
        crate::wire::DamageFrame {
            schema: crate::wire::DAMAGE_SCHEMA,
            id: id.to_string(),
            generation: SessionGeneration(gen.to_string()),
            base_revision: Revision(base),
            revision: Revision(rev),
            cols: 2,
            rows: 1,
            cursor: CursorState {
                line: 0,
                col: 0,
                visible: true,
                shape: CursorShape::Block,
            },
            modes: ModeState {
                alt_screen: false,
                app_cursor: false,
                bracketed_paste: false,
                focus_reporting: false,
                mouse_report: false,
                mouse_drag: false,
                mouse_motion: false,
                mouse_sgr: false,
            },
            ops: vec![DamageOp::ClearAll {
                cell: Cell {
                    text: " ".to_string(),
                    width: 1,
                    ..cell()
                },
            }],
        }
    }

    // --- delivery order + exactly-once ---------------------------------------

    #[test]
    fn validated_changes_deliver_user_events_once_and_in_order() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a".to_string());
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());
        let id = || "s-a".to_string();

        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: id(),
                grid: grid("gen", 1),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalBell { id: id() },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalTitle {
                id: id(),
                title: Some("t".to_string()),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Damage {
                frame: damage_frame("s-a", "gen", 1, 2),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalClipboardStore {
                id: id(),
                text: "x".to_string(),
            },
        );

        assert_eq!(
            tags(&log),
            vec!["redraw", "bell", "title:t", "redraw", "clipboard:x"],
            "the producer requests one event per validated change, in event order"
        );
    }

    #[test]
    fn active_exit_delivers_identity_code_and_generation_exactly_once() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a".to_string());
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());

        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-a".to_string(),
                grid: grid("gen-a", 1),
            },
        );
        log.lock().unwrap().clear();

        for _ in 0..2 {
            handle_event(
                &shared,
                &mut sync,
                &sender,
                "s-a",
                DaemonEvent::SessionExited {
                    id: "s-a".to_string(),
                    code: Some(7),
                },
            );
        }

        assert_eq!(tags(&log), vec!["exit:s-a:Some(7):gen-a"]);
        assert_eq!(*shared.exited.lock().unwrap(), Some(Some(7)));
    }

    #[test]
    fn sibling_and_extra_pane_exits_preserve_their_accepted_generations() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active");
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());

        let sibling_epoch = shared.set_sibling_session("sibling");
        let mut sibling_sync = SyncState::new("sibling");
        handle_sibling_event(
            &shared,
            &mut sibling_sync,
            &sender,
            "sibling",
            sibling_epoch,
            DaemonEvent::Grid {
                id: "sibling".to_string(),
                grid: grid("gen-sibling", 1),
            },
        );

        shared.set_pane_sessions(&["pane"]);
        let mut pane_sync = SyncState::new("pane");
        handle_pane_event(
            &shared,
            &mut pane_sync,
            &sender,
            "pane",
            DaemonEvent::Grid {
                id: "pane".to_string(),
                grid: grid("gen-pane", 1),
            },
        );
        log.lock().unwrap().clear();

        handle_sibling_event(
            &shared,
            &mut sibling_sync,
            &sender,
            "sibling",
            sibling_epoch,
            DaemonEvent::SessionExited {
                id: "sibling".to_string(),
                code: Some(0),
            },
        );
        handle_pane_event(
            &shared,
            &mut pane_sync,
            &sender,
            "pane",
            DaemonEvent::SessionExited {
                id: "pane".to_string(),
                code: None,
            },
        );

        assert_eq!(
            tags(&log),
            vec![
                "exit:sibling:Some(0):gen-sibling",
                "exit:pane:None:gen-pane"
            ]
        );
        assert_eq!(shared.sibling_snapshot().exited, Some(Some(0)));
        assert_eq!(shared.pane_snapshot("pane").unwrap().1, Some(None));
    }

    #[test]
    fn stale_pane_epoch_drops_exit_without_notifying_owner() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("active");
        shared.set_pane_sessions(&["pane"]);
        let stale_epoch = shared.pane_epoch("pane").unwrap();
        let mut stale_sync = SyncState::new("pane");
        stale_sync.on_grid("pane", &grid("stale-gen", 1)).unwrap();

        shared.clear_pane_sessions();
        shared.set_pane_sessions(&["pane"]);
        assert_ne!(shared.pane_epoch("pane"), Some(stale_epoch));

        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());
        // Call the lower-level accepted-exit path with the stale epoch to model an in-flight frame
        // from the replaced binding. The cache gate refuses it, so no lifecycle event escapes.
        if let Ok(Action::Exited) = stale_sync.on_session_exited("pane") {
            if shared.apply_pane_exit("pane", stale_epoch, Some(1)) {
                notify_session_exit(&sender, "pane", Some(1), stale_sync.accepted_generation());
            }
        }
        assert!(tags(&log).is_empty());
        assert_eq!(shared.pane_snapshot("pane").unwrap().1, None);
    }

    #[test]
    fn rejected_and_foreign_frames_never_wake() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a".to_string());
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());

        // A foreign session's grid is rejected by the SyncState gate; its bell/title/
        // clipboard fall through the id guards; a foreign damage frame short-circuits.
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-b".to_string(),
                grid: grid("gen", 1),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalBell {
                id: "s-b".to_string(),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalTitle {
                id: "s-b".to_string(),
                title: Some("t".to_string()),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Damage {
                frame: damage_frame("s-b", "gen", 1, 2),
            },
        );

        assert!(
            tags(&log).is_empty(),
            "no wake without a validated state change (exactly-once also means never-spurious)"
        );
    }

    #[test]
    fn sibling_ingest_wakes_through_the_neutral_sender() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-active");
        let epoch = shared.set_sibling_session("s-sib");
        let mut sync = SyncState::new("s-sib".to_string());
        let log = Arc::new(Mutex::new(Vec::new()));
        let sender = RecordingSender(log.clone());

        handle_sibling_event(
            &shared,
            &mut sync,
            &sender,
            "s-sib",
            epoch,
            DaemonEvent::Grid {
                id: "s-sib".to_string(),
                grid: grid("gen-sib", 5),
            },
        );

        assert_eq!(tags(&log), vec!["redraw"]);
        assert!(
            shared.sibling_snapshot().grid.is_some(),
            "the accepted sibling grid is cached before the wake"
        );
    }

    // --- closed owner loop is harmless ---------------------------------------

    #[test]
    fn sends_after_owner_loop_closure_are_harmless_and_state_still_updates() {
        let shared = Arc::new(Shared::default());
        shared.init_active_session("s-a");
        let mut sync = SyncState::new("s-a".to_string());
        let sender = ClosedSender;

        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Grid {
                id: "s-a".to_string(),
                grid: grid("gen", 1),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::Damage {
                frame: damage_frame("s-a", "gen", 1, 2),
            },
        );
        handle_event(
            &shared,
            &mut sync,
            &sender,
            "s-a",
            DaemonEvent::TerminalBell {
                id: "s-a".to_string(),
            },
        );

        // Every wake failed (loop gone) — no panic, and the validated state was still
        // published: teardown is nonfatal for the reader.
        let published = shared.grid.lock().unwrap().clone().expect("grid published");
        assert_eq!(published.revision, Revision(2));
    }

    // --- clone fan-out shares one ordered stream ------------------------------

    #[test]
    fn clone_sender_fans_out_into_one_ordered_stream() {
        let log = Arc::new(Mutex::new(Vec::new()));
        let a: Box<dyn UserEventSender> = Box::new(RecordingSender(log.clone()));
        let b = a.clone_sender();

        let _ = a.send(UserEvent::Redraw);
        let _ = b.send(UserEvent::TerminalBell);
        let _ = a.send(UserEvent::TerminalClipboardStore {
            text: "x".to_string(),
        });

        assert_eq!(
            tags(&log),
            vec!["redraw", "bell", "clipboard:x"],
            "clones (client reader + command bridge) feed the same ordered stream"
        );
    }
}
