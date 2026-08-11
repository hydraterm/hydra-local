//! Renderer synchronization state machine. The renderer trusts the daemon's grid,
//! but a malformed, stale, cross-generation, or wrong-session snapshot must never
//! reach the GPU path — painting one would show a corrupt, rewound, or foreign
//! screen. This module is the single gate every daemon event passes through.
//!
//! It is bound to one expected `session_id`; events naming any other session are
//! ignored. It models four explicit states:
//!
//! - **AwaitingBaseline** — attached, no accepted grid yet. The first valid Grid
//!   for the current generation moves us to Synchronized.
//! - **Synchronized** — we hold a `(generation, revision)` baseline and paint it.
//! - **AwaitingResync** — the daemon signalled a lag (ResyncRequired); the daemon
//!   guarantees a fresh Grid follows, so we wait for it (no request of our own).
//! - **Exited** — the session ended; we stop accepting grids.
//!
//! Rejections:
//! - **unsupported versions** — a wire `version` we don't model;
//! - **invalid dimensions / wide-cell layouts** — structurally corrupt grids;
//! - **wrong session** — an event for a different session id;
//! - **retired generation** — a delayed frame from a generation we already left
//!   (a respawn minted a newer one); it must not replace the current screen;
//! - **stale revisions** — same generation, a revision strictly older than ours.
//!
//! A same-generation duplicate (same revision we already hold) is NOT a rejection:
//! it returns a `GridOutcome` with no repaint, but may still re-request a snapshot
//! if live output has run ahead (see [`GridOutcome`]).
//!
//! A NEW generation we have not retired is adopted as a fresh baseline (the daemon
//! rebuilt the grid; generations are independent lifetimes, not revision-comparable).

use crate::wire::{
    DamageFrame, DamageInvalid, DamageOp, GridSnapshot, Revision, SessionGeneration,
};
use std::collections::HashSet;

/// Wire schema version this renderer understands. Mirrors the daemon's
/// `SNAPSHOT_VERSION`; bump in lockstep when the snapshot shape changes. The
/// daemon and renderer MUST share the same major version — `on_grid` rejects any
/// mismatch with `Reject::UnsupportedVersion` BEFORE reading mode state, so a V1
/// snapshot is never interpreted with false app_cursor/bracketed_paste defaults.
/// v2 = SnapshotV2 (adds terminal input modes).
pub const SUPPORTED_VERSION: u32 = 2;

/// Upper bound on a single grid dimension, mirroring the daemon's `MAX_DIMENSION`.
/// A snapshot exceeding it is treated as corrupt rather than allocated against.
const MAX_DIMENSION: usize = 2000;

/// Why an event was refused. Carried for logging; on any rejection the renderer
/// keeps painting the last accepted grid and waits for a valid frame.
#[derive(Debug, PartialEq, Eq)]
pub enum Reject {
    /// Event named a session other than the one we're bound to.
    WrongSession,
    /// `version` is not one we model.
    UnsupportedVersion { got: u32 },
    /// cols/rows are zero, oversized, or `rows_cells` doesn't match them.
    InvalidDimensions { reason: &'static str },
    /// Wide-cell (width 2/0) invariants are violated at `col` of `row`.
    InvalidWideLayout { row: usize, col: usize },
    /// A frame from a generation we already retired (a newer one supersedes it).
    RetiredGeneration,
    /// Same generation, but the revision is older than the one we hold.
    StaleRevision { got: u64, have: u64 },
    /// The session has exited; we no longer accept grids.
    SessionEnded,
    /// A damage frame failed structural validation (`DamageFrame::validate`), or
    /// its declared geometry / a RowSpan span did not fit the held grid, or an
    /// op was otherwise unapplicable. Carries the structural reason when one
    /// exists; geometry/apply mismatches use `DamageNotApplicable`.
    DamageInvalid { reason: DamageInvalid },
    /// A damage frame decoded and structurally validated, but could not be applied
    /// against the held grid: its `cols`/`rows` disagree with the held grid, no
    /// baseline grid is held yet, or a RowSpan ran past the held row. The held grid
    /// is left untouched and the caller resyncs.
    DamageNotApplicable { reason: &'static str },
    /// The damage frame's `base_revision` does not equal the revision we hold — a
    /// gap (frames were lost) or a fork. We cannot apply it incrementally; resync.
    DamageRevisionGap { base: u64, have: u64 },
}

/// Explicit lifecycle of the renderer's sync with the daemon.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyncPhase {
    /// Attached, awaiting the first authoritative baseline grid.
    AwaitingBaseline,
    /// Holding a baseline; painting it.
    Synchronized,
    /// Lag signalled; awaiting the daemon's guaranteed follow-up baseline grid.
    AwaitingResync,
    /// Session ended.
    Exited,
}

/// What the caller should do after the state machine processed an Output,
/// ResyncRequired, or SessionExited event. (Grid replies use [`GridOutcome`],
/// because a single Grid can require BOTH a repaint and a follow-up request.)
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// Nothing to do (ignored/rejected event, or a duplicate).
    None,
    /// Live output advanced the grid; the caller should request ONE snapshot if
    /// it has none in flight (the state machine has already recorded that a
    /// request is now outstanding). This was the raw-output compatibility bridge; the structured-only
    /// renderer does not use it in the production loop, so
    /// the variant — like `on_output` — survives only under `#[cfg(test)]`.
    #[cfg(test)]
    RequestSnapshot,
    /// The session exited — repaint to show the end-of-session overlay.
    Exited,
}

/// The result of accepting a Grid. A Grid can require two independent caller
/// actions at once, so this is a pair of flags rather than a single enum: the
/// accepted grid must be painted (`repaint`), AND — if live output has already
/// advanced past this grid's revision (`highest_seen` is ahead) — one more
/// snapshot must be requested to fetch that trailing output (`request_snapshot`).
/// Collapsing these into one value would silently drop whichever action lost.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct GridOutcome {
    /// Paint the just-accepted grid.
    pub repaint: bool,
    /// Issue exactly one snapshot request: the accepted grid is older than the
    /// highest output revision we've observed, so trailing output is unfetched.
    /// When set, `request_in_flight` is kept/raised so the caller need not toggle it.
    pub request_snapshot: bool,
}

/// The result of processing a structured damage frame. Unlike a Grid, a
/// damage frame is applied against the grid the renderer already holds, so the
/// outcome tells the caller exactly one of three things to do:
///
/// - [`Applied`](DamageOutcome::Applied) — the frame validated and APPLIED cleanly
///   to a scratch copy of the held grid; the caller commits the returned snapshot
///   into shared state and wakes the UI exactly once. The held grid is replaced
///   atomically (the scratch was only built off to the side).
/// - [`Ignore`](DamageOutcome::Ignore) — a duplicate or stale frame (its target
///   revision is one we already hold or have passed). Nothing to do: do NOT repaint
///   and do NOT resync. Dropping a stale frame is correct, not an error.
/// - [`Resync`](DamageOutcome::Resync) — the frame could not be applied
///   incrementally (malformed, wrong generation, revision gap, geometry mismatch,
///   out-of-bounds op, or no baseline held). The held grid is UNTOUCHED; the caller
///   moves to AwaitingResync and requests exactly ONE snapshot. `reason` is carried
///   for logging.
#[derive(Debug)]
pub enum DamageOutcome {
    /// Commit this freshly-built grid and wake the UI once.
    Applied(Box<GridSnapshot>),
    /// Duplicate/stale frame — ignore silently (no repaint, no resync).
    Ignore,
    /// Drop to resync; request exactly one snapshot. The held grid is unchanged.
    Resync { reason: Reject },
}

/// The renderer's view, bound to one session. Tracks the current generation +
/// revision baseline, the set of retired generations, the explicit phase, and
/// whether a coalescing snapshot request is in flight.
pub struct SyncState {
    /// The only session whose events we honor.
    session_id: String,
    phase: SyncPhase,
    /// Current grid lifetime + revision baseline (None until first accepted grid).
    current: Option<(SessionGeneration, Revision)>,
    /// Generations we have moved past. A delayed frame from any of these must not
    /// replace the current screen.
    retired: HashSet<SessionGeneration>,
    /// At most one snapshot request may be outstanding (coalescing, item 2). While
    /// true, further Output events do NOT issue another request; we instead record
    /// the highest revision seen so the caller knows the screen still moved.
    request_in_flight: bool,
    /// Highest (generation, revision) observed from any Output while a request was
    /// in flight — so a burst collapses to one request that still reflects the
    /// newest position once the in-flight grid lands.
    highest_seen: Option<(SessionGeneration, Revision)>,
}

impl SyncState {
    /// Bind a fresh state machine to `session_id`, starting in AwaitingBaseline.
    pub fn new(session_id: impl Into<String>) -> Self {
        SyncState {
            session_id: session_id.into(),
            phase: SyncPhase::AwaitingBaseline,
            current: None,
            retired: HashSet::new(),
            request_in_flight: false,
            highest_seen: None,
        }
    }

    #[cfg(test)]
    pub fn phase(&self) -> SyncPhase {
        self.phase
    }

    /// Whether a snapshot request is currently outstanding. `on_output` sets this
    /// itself when it returns `RequestSnapshot`, so the renderer never toggles it
    /// manually; it exists for the state-machine's own coalescing and for tests.
    #[cfg(test)]
    pub fn request_in_flight(&self) -> bool {
        self.request_in_flight
    }

    /// Validate and apply a Grid snapshot for session `id`. On `Ok(GridOutcome)`
    /// the state has advanced and the caller paints and/or re-requests per the
    /// returned flags; on `Err` the snapshot is rejected and the state is unchanged.
    ///
    /// A Grid is a reply to an outstanding request (or the attach baseline / resync
    /// follow-up). Normally it clears the in-flight flag — BUT if live output has
    /// already advanced past this grid's revision (`highest_seen` is ahead), the
    /// reply is stale-on-arrival: we keep the request pending and tell the caller to
    /// issue one more snapshot so trailing output is not lost. The pending state is
    /// only cleared once an accepted Grid finally covers the highest observed revision.
    pub fn on_grid(&mut self, id: &str, snap: &GridSnapshot) -> Result<GridOutcome, Reject> {
        if id != self.session_id {
            return Err(Reject::WrongSession);
        }
        if self.phase == SyncPhase::Exited {
            return Err(Reject::SessionEnded);
        }
        if snap.version != SUPPORTED_VERSION {
            return Err(Reject::UnsupportedVersion { got: snap.version });
        }
        validate_dimensions(snap)?;
        validate_wide_layout(snap)?;

        let gen = &snap.generation;
        let rev = snap.revision;

        // A frame from a generation we already retired must never repaint.
        if self.retired.contains(gen) {
            return Err(Reject::RetiredGeneration);
        }

        match &self.current {
            Some((cur_gen, cur_rev)) if cur_gen == gen => {
                // Same generation: enforce monotonic, non-rewinding revisions.
                if rev.0 < cur_rev.0 {
                    return Err(Reject::StaleRevision {
                        got: rev.0,
                        have: cur_rev.0,
                    });
                }
                if rev.0 == cur_rev.0 {
                    // Duplicate of the current baseline: nothing new to paint. But a
                    // duplicate reply does NOT prove trailing output was fetched, so
                    // we still settle pending state against `highest_seen` — if output
                    // ran ahead, re-request rather than dropping it.
                    let request_snapshot = self.settle_pending_after_grid(gen, rev);
                    return Ok(GridOutcome {
                        repaint: false,
                        request_snapshot,
                    });
                }
            }
            Some((cur_gen, _)) => {
                // A DIFFERENT, non-retired generation: the daemon rebuilt the grid
                // (respawn). Retire the one we were on so its delayed frames can
                // never come back and overwrite this new screen.
                self.retired.insert(cur_gen.clone());
            }
            None => {}
        }

        self.current = Some((gen.clone(), rev));
        self.phase = SyncPhase::Synchronized;
        // Decide whether trailing output still needs fetching (keeps or clears the
        // in-flight flag accordingly).
        let request_snapshot = self.settle_pending_after_grid(gen, rev);
        Ok(GridOutcome {
            repaint: true,
            request_snapshot,
        })
    }

    /// Validate and apply a structured damage frame for session `id` against the
    /// grid the renderer currently holds (`held`). Returns a [`DamageOutcome`] the
    /// caller acts on; the held grid is NEVER mutated here — on success a fresh
    /// snapshot is returned for the caller to commit, on any failure the held grid
    /// stays put and the caller resyncs.
    ///
    /// SCRATCH-FIRST: ops are applied to a CLONE of `held`. The clone is only
    /// returned (for the caller to commit) once the WHOLE frame validates and every
    /// op applies in bounds. A partially-applied frame is never observable: if any
    /// op fails after an earlier one succeeded, we discard the scratch and resync,
    /// so the held grid is untouched.
    ///
    /// Order of checks (each a distinct failure mode, all -> resync EXCEPT a
    /// duplicate/stale frame which is ignored):
    /// 1. wrong session / exited -> resync-class reject (no grid to apply onto).
    /// 2. structural `validate()` (schema, dims, caps, RowSpan/scroll bounds,
    ///    revision ordering, cursor bounds) -> resync.
    /// 3. no baseline held / generation mismatch -> resync (can't apply onto nothing
    ///    or onto a different lifetime).
    /// 4. `frame.revision <= held.revision` -> IGNORE (duplicate/stale; not an error).
    /// 5. `frame.base_revision != held.revision` -> resync (a gap; frames were lost).
    /// 6. `frame.cols/rows != held.cols/rows` -> resync (geometry moved; only a fresh
    ///    snapshot can re-baseline — damage never resizes).
    /// 7. apply ops to the scratch in frame order; any out-of-bounds RowSpan or an
    ///    out-of-region ScrollUp/ScrollDown -> resync (held grid untouched).
    /// 8. the resulting scratch must still satisfy the wide-cell layout contract
    ///    (a RowSpan could leave a dangling wide lead/spacer) -> resync if not.
    ///
    /// On success the scratch carries the frame's absolute post-frame cursor/modes
    /// and `revision`/`base_revision`; an empty-ops frame still advances those.
    pub fn on_damage(
        &mut self,
        id: &str,
        frame: &DamageFrame,
        held: &GridSnapshot,
    ) -> DamageOutcome {
        // Wrong session: not OUR frame at all. This is not a sync failure of the
        // session we're bound to — ignore it silently. Resyncing here would pull a
        // needless snapshot for our session over an unrelated session's frame.
        if id != self.session_id {
            return DamageOutcome::Ignore;
        }
        if self.phase == SyncPhase::Exited {
            return DamageOutcome::Resync {
                reason: Reject::SessionEnded,
            };
        }
        // A frame from a generation we already retired (a newer one superseded it) is
        // a stale straggler, not a continuity break — ignore it, do NOT resync.
        if self.retired.contains(&frame.generation) {
            return DamageOutcome::Ignore;
        }
        // Structural shape (schema/dims/caps/op-bounds/revision-order/cursor-bounds).
        if let Err(reason) = frame.validate() {
            return DamageOutcome::Resync {
                reason: Reject::DamageInvalid { reason },
            };
        }

        // We need a baseline to apply incrementally onto.
        let Some((cur_gen, cur_rev)) = &self.current else {
            return DamageOutcome::Resync {
                reason: Reject::DamageNotApplicable {
                    reason: "no baseline grid held",
                },
            };
        };
        // Damage applies only onto the CURRENT generation's grid. A DIFFERENT,
        // non-retired generation means the daemon rebuilt the grid (a respawn we
        // haven't baselined yet); we can't apply incrementally onto it, so resync to
        // pull that generation's fresh snapshot. (A RETIRED generation was already
        // ignored above — only a live, un-baselined generation reaches here.)
        if &frame.generation != cur_gen {
            return DamageOutcome::Resync {
                reason: Reject::DamageNotApplicable {
                    reason: "generation mismatch",
                },
            };
        }

        // Duplicate/stale: the frame targets a revision we already hold or passed.
        // This is benign — ignore it, do NOT resync.
        if frame.revision.0 <= cur_rev.0 {
            return DamageOutcome::Ignore;
        }
        // Continuity: the frame must build on EXACTLY the revision we hold. A gap
        // means lost frames; only a fresh snapshot can re-baseline.
        if frame.base_revision.0 != cur_rev.0 {
            return DamageOutcome::Resync {
                reason: Reject::DamageRevisionGap {
                    base: frame.base_revision.0,
                    have: cur_rev.0,
                },
            };
        }
        // Damage never resizes: a geometry change must arrive as a fresh snapshot.
        if frame.cols as usize != held.cols || frame.rows as usize != held.rows {
            return DamageOutcome::Resync {
                reason: Reject::DamageNotApplicable {
                    reason: "frame geometry disagrees with held grid",
                },
            };
        }

        // SCRATCH: clone the held grid and apply onto the copy. Nothing the caller
        // can observe is touched until the whole frame succeeds.
        let mut scratch = held.clone();
        if let Err(reason) = apply_ops(&mut scratch, &frame.ops) {
            return DamageOutcome::Resync {
                reason: Reject::DamageNotApplicable { reason },
            };
        }

        // Carry the frame's absolute post-frame state onto the scratch. Empty-ops
        // frames reach here too, so a cursor/mode-only advance still lands.
        scratch.revision = frame.revision;
        scratch.base_revision = frame.base_revision;
        scratch.cursor_line = frame.cursor.line;
        scratch.cursor_col = frame.cursor.col;
        scratch.cursor_visible = frame.cursor.visible;
        scratch.cursor_shape = frame.cursor.shape;
        scratch.alt_screen = frame.modes.alt_screen;
        scratch.app_cursor = frame.modes.app_cursor;
        scratch.bracketed_paste = frame.modes.bracketed_paste;
        scratch.focus_reporting = frame.modes.focus_reporting;
        scratch.mouse_report = frame.modes.mouse_report;
        scratch.mouse_drag = frame.modes.mouse_drag;
        scratch.mouse_motion = frame.modes.mouse_motion;
        scratch.mouse_sgr = frame.modes.mouse_sgr;

        // The post-apply grid must still be paintable: a RowSpan could have left a
        // dangling wide lead/spacer at a span boundary. Validate before committing.
        if let Err(reason) = validate_wide_layout(&scratch) {
            return DamageOutcome::Resync { reason };
        }

        // Advance our baseline to the frame's revision; the caller commits `scratch`.
        self.current = Some((cur_gen.clone(), frame.revision));
        self.phase = SyncPhase::Synchronized;
        // A pushed damage frame caught us up; a coalesced snapshot request (if any)
        // is settled against the new revision exactly as a Grid would be.
        let gen = frame.generation.clone();
        self.settle_pending_after_grid(&gen, frame.revision);
        DamageOutcome::Applied(Box::new(scratch))
    }

    /// After accepting (or de-duplicating) a Grid at `(gen, rev)`, reconcile the
    /// coalescing bookkeeping. If the highest output we've observed for THIS
    /// generation is strictly ahead of `rev`, trailing output is unfetched: keep
    /// `request_in_flight` raised and return `true` so the caller pulls one more
    /// snapshot. Otherwise the grid has caught up — clear the pending state and
    /// return `false`. (A `highest_seen` from a different generation is moot once we
    /// hold `gen`, so it is cleared.)
    fn settle_pending_after_grid(&mut self, gen: &SessionGeneration, rev: Revision) -> bool {
        let trailing = matches!(
            &self.highest_seen,
            Some((hg, hr)) if hg == gen && hr.0 > rev.0
        );
        if trailing {
            self.request_in_flight = true;
            true
        } else {
            self.request_in_flight = false;
            self.highest_seen = None;
            false
        }
    }

    /// Process an Output event (a revision advance carrying no grid). We validate
    /// its session, generation, and revision (item 5) before acting. If it is a
    /// genuine forward advance of the current generation, we ask the caller to
    /// pull ONE snapshot — but only if none is in flight (coalescing, item 2);
    /// otherwise we just record the highest position seen.
    ///
    /// The native renderer does not drive this path: it attaches
    /// `want_raw_output: false` and lives off structured `Damage`, so the
    /// Output->Snapshot bridge is retired from the production event loop. The method
    /// (and its coalescing contract) is kept under `#[cfg(test)]` to document and lock
    /// the behavior a raw-output client would still rely on.
    #[cfg(test)]
    pub fn on_output(
        &mut self,
        id: &str,
        generation: Option<&SessionGeneration>,
        revision: Revision,
    ) -> Result<Action, Reject> {
        if id != self.session_id {
            return Err(Reject::WrongSession);
        }
        if self.phase == SyncPhase::Exited {
            return Err(Reject::SessionEnded);
        }

        // If the Output names a generation, validate it against what we know.
        if let Some(gen) = generation {
            if self.retired.contains(gen) {
                return Err(Reject::RetiredGeneration);
            }
            if let Some((cur_gen, cur_rev)) = &self.current {
                if cur_gen == gen && revision.0 <= cur_rev.0 {
                    // Not a forward advance of the current screen — nothing to pull.
                    return Err(Reject::StaleRevision {
                        got: revision.0,
                        have: cur_rev.0,
                    });
                }
            }
        }

        // Remember the highest position so a coalesced burst still reflects the
        // newest revision once the in-flight grid lands.
        self.note_highest(generation, revision);

        if self.request_in_flight {
            // Coalesce: a request is already outstanding; do not issue another.
            return Ok(Action::None);
        }
        self.request_in_flight = true;
        Ok(Action::RequestSnapshot)
    }

    /// The daemon signalled a lag. It GUARANTEES a fresh Grid follows, so we move
    /// to AwaitingResync and DO NOT request a snapshot ourselves (item 3). Any
    /// in-flight request is now moot — the daemon's baseline supersedes it.
    pub fn on_resync_required(&mut self, id: &str) -> Result<Action, Reject> {
        if id != self.session_id {
            return Err(Reject::WrongSession);
        }
        if self.phase == SyncPhase::Exited {
            return Err(Reject::SessionEnded);
        }
        self.phase = SyncPhase::AwaitingResync;
        // The guaranteed follow-up Grid will clear this; drop our own bookkeeping
        // so we accept that baseline rather than coalescing against a stale request.
        self.request_in_flight = false;
        self.highest_seen = None;
        Ok(Action::None)
    }

    /// The session ended. We move to Exited and stop accepting grids.
    pub fn on_session_exited(&mut self, id: &str) -> Result<Action, Reject> {
        if id != self.session_id {
            return Err(Reject::WrongSession);
        }
        if self.phase == SyncPhase::Exited {
            return Ok(Action::None);
        }
        self.phase = SyncPhase::Exited;
        Ok(Action::Exited)
    }

    /// Generation of the most recent accepted authoritative grid, if this binding has one.
    ///
    /// `SessionExited` itself carries no generation on the daemon wire. The renderer therefore
    /// forwards the generation it actually observed through the same [`SyncState`] that accepted
    /// the grid. A caller must treat `None` conservatively: an exit before any baseline cannot
    /// safely be attributed to a durable session generation.
    pub fn accepted_generation(&self) -> Option<&str> {
        self.current
            .as_ref()
            .map(|(generation, _)| generation.0.as_str())
    }

    #[cfg(test)]
    fn note_highest(&mut self, generation: Option<&SessionGeneration>, revision: Revision) {
        // We can only meaningfully order revisions within a known generation; use
        // the Output's generation if present, else the current one.
        let gen = generation
            .cloned()
            .or_else(|| self.current.as_ref().map(|(g, _)| g.clone()));
        let Some(gen) = gen else { return };
        match &self.highest_seen {
            Some((hg, hr)) if *hg == gen && hr.0 >= revision.0 => {}
            _ => self.highest_seen = Some((gen, revision)),
        }
    }

    /// The currently-accepted `(generation, revision)`, if any grid is held.
    #[cfg(test)]
    pub fn accepted(&self) -> Option<(&str, u64)> {
        self.current.as_ref().map(|(g, r)| (g.0.as_str(), r.0))
    }
}

/// Reject zero/oversized dimensions and any `rows_cells` shape that disagrees with
/// the declared `cols`/`rows`. The renderer indexes cells by row/col assuming this
/// holds, so a mismatch would panic or paint garbage.
fn validate_dimensions(snap: &GridSnapshot) -> Result<(), Reject> {
    if snap.cols == 0 || snap.rows == 0 {
        return Err(Reject::InvalidDimensions {
            reason: "zero cols or rows",
        });
    }
    if snap.cols > MAX_DIMENSION || snap.rows > MAX_DIMENSION {
        return Err(Reject::InvalidDimensions {
            reason: "cols or rows exceed maximum",
        });
    }
    if snap.rows_cells.len() != snap.rows {
        return Err(Reject::InvalidDimensions {
            reason: "rows_cells length != rows",
        });
    }
    if snap.rows_cells.iter().any(|r| r.len() != snap.cols) {
        return Err(Reject::InvalidDimensions {
            reason: "a row's cell count != cols",
        });
    }
    Ok(())
}

/// Apply a damage frame's ops onto `grid` (a SCRATCH copy — callers never pass the
/// held grid). `validate()` has already bounded the ops structurally; this re-checks
/// every index against the ACTUAL scratch dimensions before writing so a frame whose
/// declared `cols`/`rows` somehow disagree with the grid can never write past a row.
/// Returns the first failure reason; on `Err` the scratch is partially mutated but
/// the caller DISCARDS it (the held grid is a separate value), so no partial state
/// is ever observable.
///
/// Applies RowSpan + ClearAll + ScrollUp/ScrollDown. The scroll application mirrors
/// the daemon's `apply_scroll` exactly (forward copy for up, reverse for down, every
/// index re-checked against the actual scratch height) — a parity-fixture test pins the
/// two implementations together so they cannot drift. Ops are applied in the frame's
/// order (scroll first, then the exposed/leftover RowSpans), exactly as the daemon
/// self-verified before shipping.
fn apply_ops(grid: &mut GridSnapshot, ops: &[DamageOp]) -> Result<(), &'static str> {
    for op in ops {
        match op {
            DamageOp::ClearAll { cell } => {
                for row in grid.rows_cells.iter_mut() {
                    for c in row.iter_mut() {
                        *c = cell.clone();
                    }
                }
            }
            DamageOp::RowSpan { row, start, cells } => {
                let row_idx = *row as usize;
                let start = *start as usize;
                let dst_row = grid
                    .rows_cells
                    .get_mut(row_idx)
                    .ok_or("RowSpan row past held grid")?;
                let end = start
                    .checked_add(cells.len())
                    .ok_or("RowSpan span overflows")?;
                if end > dst_row.len() {
                    return Err("RowSpan span past held row width");
                }
                dst_row[start..end].clone_from_slice(cells);
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
                let up = matches!(op, DamageOp::ScrollUp { .. });
                apply_scroll_op(
                    &mut grid.rows_cells,
                    *top as usize,
                    *bottom_exclusive as usize,
                    *lines as usize,
                    up,
                )?;
            }
        }
    }
    Ok(())
}

/// Move a half-open row region `[top, bottom_exclusive)` by `lines` (up or down) within
/// `rows_cells`. Mirrors `pty-daemon`'s `apply_scroll`: forward copy for up so each
/// destination reads a not-yet-overwritten source; reverse for down. Re-validates the
/// region against the ACTUAL height (the frame is scratch; a frame whose declared rows
/// disagree with the held grid can never write past a row). Vacated rows are NOT cleared
/// here — the frame's following RowSpans repaint them.
fn apply_scroll_op(
    rows_cells: &mut [Vec<crate::wire::Cell>],
    top: usize,
    bottom_exclusive: usize,
    lines: usize,
    up: bool,
) -> Result<(), &'static str> {
    if !(top < bottom_exclusive && bottom_exclusive <= rows_cells.len() && lines > 0)
        || lines > bottom_exclusive - top
    {
        return Err("scroll region out of bounds");
    }
    if up {
        for i in top..(bottom_exclusive - lines) {
            rows_cells[i] = rows_cells[i + lines].clone();
        }
    } else {
        for i in (top + lines..bottom_exclusive).rev() {
            rows_cells[i] = rows_cells[i - lines].clone();
        }
    }
    Ok(())
}

/// Enforce the wide-cell contract row by row: a width-2 lead must be immediately
/// followed by a width-0 spacer and must not sit in the last column; a width-0
/// spacer must be immediately preceded by a width-2 lead. Any other width is
/// treated as a normal (1-wide) cell and needs no neighbor checks.
fn validate_wide_layout(snap: &GridSnapshot) -> Result<(), Reject> {
    for (row_idx, row) in snap.rows_cells.iter().enumerate() {
        let mut col = 0;
        while col < row.len() {
            match row[col].width {
                2 => {
                    let spacer = row.get(col + 1);
                    if spacer.map(|c| c.width) != Some(0) {
                        return Err(Reject::InvalidWideLayout { row: row_idx, col });
                    }
                    col += 2;
                }
                0 => {
                    return Err(Reject::InvalidWideLayout { row: row_idx, col });
                }
                _ => col += 1,
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::{
        Cell, Color, CursorShape, CursorState, DamageFrame, DamageOp, ModeState, NamedColor,
        Revision, SessionGeneration,
    };

    const SESSION: &str = "sess-1";

    fn fg() -> Color {
        Color::Named {
            name: NamedColor::Foreground,
        }
    }

    fn cell(width: u8, text: &str) -> Cell {
        Cell {
            text: text.to_string(),
            fg: fg(),
            bg: fg(),
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

    /// A canonical blank cell (width 1, text " ") — the only valid ClearAll fill.
    fn blank() -> Cell {
        cell(1, " ")
    }

    fn snap(gen: &str, rev: u64, rows_cells: Vec<Vec<Cell>>) -> GridSnapshot {
        let rows = rows_cells.len();
        let cols = rows_cells.first().map(|r| r.len()).unwrap_or(0);
        GridSnapshot {
            version: SUPPORTED_VERSION,
            generation: SessionGeneration(gen.to_string()),
            revision: Revision(rev),
            base_revision: Revision(rev),
            cols,
            rows,
            rows_cells,
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

    fn plain_row(cols: usize) -> Vec<Cell> {
        (0..cols).map(|_| cell(1, " ")).collect()
    }

    fn st() -> SyncState {
        SyncState::new(SESSION)
    }

    /// A plain repaint with no trailing-output request (the common Grid outcome).
    fn repaint() -> Result<GridOutcome, Reject> {
        Ok(GridOutcome {
            repaint: true,
            request_snapshot: false,
        })
    }

    /// Repaint AND request one more snapshot (the grid is behind observed output).
    fn repaint_and_request() -> Result<GridOutcome, Reject> {
        Ok(GridOutcome {
            repaint: true,
            request_snapshot: true,
        })
    }

    #[test]
    fn baseline_then_synchronized() {
        let mut s = st();
        assert_eq!(s.phase(), SyncPhase::AwaitingBaseline);
        let g = snap("gen-a", 5, vec![plain_row(3), plain_row(3)]);
        assert_eq!(s.on_grid(SESSION, &g), repaint());
        assert_eq!(s.phase(), SyncPhase::Synchronized);
        assert_eq!(s.accepted(), Some(("gen-a", 5)));
    }

    #[test]
    fn rejects_unsupported_version() {
        let mut s = st();
        let mut g = snap("gen-a", 1, vec![plain_row(2)]);
        g.version = 999;
        assert_eq!(
            s.on_grid(SESSION, &g),
            Err(Reject::UnsupportedVersion { got: 999 })
        );
        assert_eq!(s.accepted(), None);
    }

    /// A V1-version snapshot must be rejected as UnsupportedVersion BEFORE any
    /// mode state is read — never silently accepted with app_cursor=false. V1
    /// carried no terminal-mode fields, so accepting it would mis-encode arrows
    /// and paste. The version gate fires first, so the (false) mode fields a
    /// deserialized V1 would carry are never consulted.
    #[test]
    fn rejects_v1_snapshot_before_reading_modes() {
        let mut s = st();
        // A snapshot that is otherwise valid but tagged with the previous major
        // version. Its mode flags happen to be false here; the point is they are
        // never inspected because the version gate rejects first.
        let mut g = snap("gen-a", 1, vec![plain_row(2)]);
        g.version = 1;
        assert_eq!(
            s.on_grid(SESSION, &g),
            Err(Reject::UnsupportedVersion { got: 1 }),
            "V1 must be rejected, not accepted with false mode defaults"
        );
        assert_eq!(
            s.accepted(),
            None,
            "no baseline established from a V1 snapshot"
        );
        assert_eq!(s.phase(), SyncPhase::AwaitingBaseline);
    }

    #[test]
    fn rejects_wrong_session_events() {
        let mut s = st();
        let g = snap("gen-a", 1, vec![plain_row(2)]);
        assert_eq!(s.on_grid("other", &g), Err(Reject::WrongSession));
        assert_eq!(
            s.on_output("other", None, Revision(9)),
            Err(Reject::WrongSession)
        );
        assert_eq!(s.on_resync_required("other"), Err(Reject::WrongSession));
        assert_eq!(s.on_session_exited("other"), Err(Reject::WrongSession));
        // Nothing leaked into our state.
        assert_eq!(s.phase(), SyncPhase::AwaitingBaseline);
        assert_eq!(s.accepted(), None);
    }

    #[test]
    fn rejects_stale_revision_same_generation() {
        let mut s = st();
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 10, vec![plain_row(2)])),
            repaint()
        );
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 9, vec![plain_row(2)])),
            Err(Reject::StaleRevision { got: 9, have: 10 })
        );
        // Newer is fine.
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 11, vec![plain_row(2)])),
            repaint()
        );
    }

    #[test]
    fn ignores_duplicate_revision_without_repaint() {
        let mut s = st();
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 10, vec![plain_row(2)])),
            repaint()
        );
        // Same gen + same revision, with no output ahead: a benign duplicate —
        // neither repaint nor request.
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 10, vec![plain_row(2)])),
            Ok(GridOutcome {
                repaint: false,
                request_snapshot: false,
            })
        );
        assert_eq!(s.accepted(), Some(("gen-a", 10)));
    }

    #[test]
    fn accepts_forward_revision_gap_as_resync_baseline() {
        let mut s = st();
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 10, vec![plain_row(2)])),
            repaint()
        );
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 5000, vec![plain_row(2)])),
            repaint()
        );
        assert_eq!(s.accepted(), Some(("gen-a", 5000)));
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 4999, vec![plain_row(2)])),
            Err(Reject::StaleRevision {
                got: 4999,
                have: 5000
            })
        );
    }

    #[test]
    fn new_generation_adopted_and_old_retired() {
        let mut s = st();
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 100, vec![plain_row(2)])),
            repaint()
        );
        // New generation with a LOWER revision is still accepted.
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-b", 1, vec![plain_row(2)])),
            repaint()
        );
        assert_eq!(s.accepted(), Some(("gen-b", 1)));
        // A DELAYED frame from the retired gen-a must never replace gen-b.
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 9999, vec![plain_row(2)])),
            Err(Reject::RetiredGeneration)
        );
        assert_eq!(s.accepted(), Some(("gen-b", 1)));
    }

    #[test]
    fn output_burst_coalesces_to_one_request_in_flight() {
        let mut s = st();
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 10, vec![plain_row(2)])),
            repaint()
        );
        // First output past the baseline asks for one snapshot.
        assert_eq!(
            s.on_output(
                SESSION,
                Some(&SessionGeneration("gen-a".into())),
                Revision(11)
            ),
            Ok(Action::RequestSnapshot)
        );
        assert!(s.request_in_flight());
        // A burst while one is in flight must NOT issue more requests.
        assert_eq!(
            s.on_output(
                SESSION,
                Some(&SessionGeneration("gen-a".into())),
                Revision(12)
            ),
            Ok(Action::None)
        );
        assert_eq!(
            s.on_output(
                SESSION,
                Some(&SessionGeneration("gen-a".into())),
                Revision(20)
            ),
            Ok(Action::None)
        );
        // The grid reply clears the in-flight flag, re-enabling a future request.
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 20, vec![plain_row(2)])),
            repaint()
        );
        assert!(!s.request_in_flight());
        assert_eq!(
            s.on_output(
                SESSION,
                Some(&SessionGeneration("gen-a".into())),
                Revision(21)
            ),
            Ok(Action::RequestSnapshot)
        );
    }

    /// Trailing-output regression: when the Grid that lands is BEHIND the highest
    /// output we've observed, coalescing must not drop the gap. The grid repaints
    /// AND re-requests, keeping the request in flight, until a grid finally covers
    /// the highest observed revision.
    #[test]
    fn grid_behind_highest_seen_repaints_and_re_requests() {
        let mut s = st();
        let gen = SessionGeneration("gen-a".into());
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 10, vec![plain_row(2)])),
            repaint()
        );
        // output 11 -> RequestSnapshot
        assert_eq!(
            s.on_output(SESSION, Some(&gen), Revision(11)),
            Ok(Action::RequestSnapshot)
        );
        assert!(s.request_in_flight());
        // output 20 -> coalesced (no second request), but highest_seen advances to 20.
        assert_eq!(
            s.on_output(SESSION, Some(&gen), Revision(20)),
            Ok(Action::None)
        );
        assert!(s.request_in_flight());
        // grid 11 -> the reply is behind the observed output (20): repaint the
        // accepted grid AND request again; the request stays in flight.
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 11, vec![plain_row(2)])),
            repaint_and_request()
        );
        assert!(s.request_in_flight());
        assert_eq!(s.accepted(), Some(("gen-a", 11)));
        // grid 20 -> now caught up to the highest observed revision: repaint, and
        // NO further request — the pending state clears.
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 20, vec![plain_row(2)])),
            repaint()
        );
        assert!(!s.request_in_flight());
        assert_eq!(s.accepted(), Some(("gen-a", 20)));
    }

    #[test]
    fn resync_required_awaits_grid_without_extra_request() {
        let mut s = st();
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 10, vec![plain_row(2)])),
            repaint()
        );
        // Put a request in flight, then a lag arrives.
        assert_eq!(
            s.on_output(
                SESSION,
                Some(&SessionGeneration("gen-a".into())),
                Revision(11)
            ),
            Ok(Action::RequestSnapshot)
        );
        // ResyncRequired must NOT request a snapshot; the daemon guarantees a Grid.
        assert_eq!(s.on_resync_required(SESSION), Ok(Action::None));
        assert_eq!(s.phase(), SyncPhase::AwaitingResync);
        assert!(!s.request_in_flight());
        // The guaranteed follow-up Grid re-baselines and returns to Synchronized.
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 30, vec![plain_row(2)])),
            repaint()
        );
        assert_eq!(s.phase(), SyncPhase::Synchronized);
        assert_eq!(s.accepted(), Some(("gen-a", 30)));
    }

    #[test]
    fn exit_stops_accepting_grids() {
        let mut s = st();
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 10, vec![plain_row(2)])),
            repaint()
        );
        assert_eq!(s.on_session_exited(SESSION), Ok(Action::Exited));
        assert_eq!(s.accepted_generation(), Some("gen-a"));
        assert_eq!(s.phase(), SyncPhase::Exited);
        assert_eq!(
            s.on_session_exited(SESSION),
            Ok(Action::None),
            "a duplicate exit is accepted as an idempotent no-op"
        );
        // Post-exit grids and outputs are refused.
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 11, vec![plain_row(2)])),
            Err(Reject::SessionEnded)
        );
        assert_eq!(
            s.on_output(SESSION, None, Revision(12)),
            Err(Reject::SessionEnded)
        );
    }

    #[test]
    fn rejects_zero_dimensions() {
        let mut s = st();
        let g = snap("gen-a", 1, vec![]);
        assert!(matches!(
            s.on_grid(SESSION, &g),
            Err(Reject::InvalidDimensions { .. })
        ));
    }

    #[test]
    fn rejects_ragged_rows() {
        let mut s = st();
        let g = snap("gen-a", 1, vec![plain_row(3), plain_row(2)]);
        assert!(matches!(
            s.on_grid(SESSION, &g),
            Err(Reject::InvalidDimensions { .. })
        ));
    }

    #[test]
    fn accepts_valid_wide_pair() {
        let mut s = st();
        let row = vec![cell(2, "界"), cell(0, ""), cell(1, "x")];
        assert_eq!(s.on_grid(SESSION, &snap("gen-a", 1, vec![row])), repaint());
    }

    #[test]
    fn rejects_lead_without_spacer() {
        let mut s = st();
        let row = vec![cell(2, "界"), cell(1, "x")];
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 1, vec![row])),
            Err(Reject::InvalidWideLayout { row: 0, col: 0 })
        );
    }

    #[test]
    fn rejects_lead_in_last_column() {
        let mut s = st();
        let row = vec![cell(1, "x"), cell(2, "界")];
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 1, vec![row])),
            Err(Reject::InvalidWideLayout { row: 0, col: 1 })
        );
    }

    #[test]
    fn rejects_bare_spacer() {
        let mut s = st();
        let row = vec![cell(0, ""), cell(1, "x")];
        assert_eq!(
            s.on_grid(SESSION, &snap("gen-a", 1, vec![row])),
            Err(Reject::InvalidWideLayout { row: 0, col: 0 })
        );
    }

    // ---- damage application -------------------------------------------------

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

    /// A damage frame for `gen` advancing `base` -> `rev` over a `cols`x`rows` grid.
    fn dmg(
        gen: &str,
        base: u64,
        rev: u64,
        cols: u16,
        rows: u16,
        ops: Vec<DamageOp>,
    ) -> DamageFrame {
        DamageFrame {
            schema: crate::wire::DAMAGE_SCHEMA,
            id: SESSION.to_string(),
            generation: SessionGeneration(gen.to_string()),
            base_revision: Revision(base),
            revision: Revision(rev),
            cols,
            rows,
            cursor: dmg_cursor(),
            modes: dmg_modes(),
            ops,
        }
    }

    /// A 2-row x 3-col grid of canonical blanks, established as the held baseline.
    fn baseline(s: &mut SyncState, gen: &str, rev: u64) -> GridSnapshot {
        let g = snap(gen, rev, vec![plain_row(3), plain_row(3)]);
        assert_eq!(s.on_grid(SESSION, &g), repaint());
        g
    }

    /// Drive a Grid through `on_grid` so the held snapshot and the sync baseline
    /// agree, returning the snapshot the caller "holds".
    fn rows_text(g: &GridSnapshot) -> Vec<String> {
        g.rows_cells
            .iter()
            .map(|r| r.iter().map(|c| c.text.clone()).collect())
            .collect()
    }

    #[test]
    fn damage_rowspan_applies_and_matches_expected() {
        let mut s = st();
        let held = baseline(&mut s, "gen-a", 10);
        // Overwrite cols [1,3) of row 0 with "a","b".
        let frame = dmg(
            "gen-a",
            10,
            11,
            3,
            2,
            vec![DamageOp::RowSpan {
                row: 0,
                start: 1,
                cells: vec![cell(1, "a"), cell(1, "b")],
            }],
        );
        match s.on_damage(SESSION, &frame, &held) {
            DamageOutcome::Applied(g) => {
                assert_eq!(rows_text(&g), vec![" ab".to_string(), "   ".to_string()]);
                assert_eq!(g.revision, Revision(11));
                // base_revision carries the frame's base (the rev it built on), not
                // the new revision.
                assert_eq!(g.base_revision, Revision(10));
                assert_eq!(s.accepted(), Some(("gen-a", 11)));
            }
            other => panic!("expected Applied, got {other:?}"),
        }
    }

    #[test]
    fn damage_clear_all_applies_and_matches_expected() {
        let mut s = st();
        // Hold a grid with some non-blank content first.
        let g = snap(
            "gen-a",
            10,
            vec![
                vec![cell(1, "x"), cell(1, "y"), cell(1, "z")],
                vec![cell(1, "1"), cell(1, "2"), cell(1, "3")],
            ],
        );
        assert_eq!(s.on_grid(SESSION, &g), repaint());
        let frame = dmg(
            "gen-a",
            10,
            11,
            3,
            2,
            vec![DamageOp::ClearAll { cell: blank() }],
        );
        match s.on_damage(SESSION, &frame, &g) {
            DamageOutcome::Applied(out) => {
                assert!(
                    out.rows_cells.iter().flatten().all(|c| *c == blank()),
                    "every cell becomes the canonical blank fill"
                );
                assert_eq!(out.revision, Revision(11));
            }
            other => panic!("expected Applied, got {other:?}"),
        }
    }

    #[test]
    fn damage_invalid_frame_leaves_grid_and_resyncs() {
        let mut s = st();
        let held = baseline(&mut s, "gen-a", 10);
        // Schema mismatch makes validate() fail -> resync, held grid untouched.
        let mut frame = dmg(
            "gen-a",
            10,
            11,
            3,
            2,
            vec![DamageOp::RowSpan {
                row: 0,
                start: 0,
                cells: vec![cell(1, "a")],
            }],
        );
        frame.schema = 99;
        match s.on_damage(SESSION, &frame, &held) {
            DamageOutcome::Resync {
                reason: Reject::DamageInvalid { .. },
            } => {}
            other => panic!("expected Resync(DamageInvalid), got {other:?}"),
        }
        // Baseline revision unchanged: the invalid frame never advanced us.
        assert_eq!(s.accepted(), Some(("gen-a", 10)));
    }

    #[test]
    fn damage_revision_gap_resyncs() {
        let mut s = st();
        let held = baseline(&mut s, "gen-a", 10);
        // base_revision 12 != held revision 10 -> a gap. (revision 13 > 10 so it's
        // forward, not a duplicate.)
        let frame = dmg("gen-a", 12, 13, 3, 2, vec![]);
        match s.on_damage(SESSION, &frame, &held) {
            DamageOutcome::Resync {
                reason: Reject::DamageRevisionGap { base: 12, have: 10 },
            } => {}
            other => panic!("expected Resync(DamageRevisionGap), got {other:?}"),
        }
        assert_eq!(s.accepted(), Some(("gen-a", 10)));
    }

    #[test]
    fn damage_stale_or_duplicate_frame_is_ignored() {
        let mut s = st();
        let held = baseline(&mut s, "gen-a", 10);
        // A frame whose target revision == the one we already hold: duplicate.
        let dup = dmg("gen-a", 9, 10, 3, 2, vec![]);
        assert!(matches!(
            s.on_damage(SESSION, &dup, &held),
            DamageOutcome::Ignore
        ));
        // A frame targeting an older revision: stale.
        let stale = dmg("gen-a", 8, 9, 3, 2, vec![]);
        assert!(matches!(
            s.on_damage(SESSION, &stale, &held),
            DamageOutcome::Ignore
        ));
        // Neither moved us off the baseline, and neither requested a resync.
        assert_eq!(s.accepted(), Some(("gen-a", 10)));
    }

    #[test]
    fn damage_empty_ops_advances_cursor_and_modes() {
        let mut s = st();
        let held = baseline(&mut s, "gen-a", 10);
        let mut frame = dmg("gen-a", 10, 11, 3, 2, vec![]);
        frame.cursor = CursorState {
            line: 1,
            col: 2,
            visible: false,
            shape: CursorShape::Beam,
        };
        frame.modes = ModeState {
            alt_screen: true,
            app_cursor: true,
            bracketed_paste: true,
            focus_reporting: true,
            mouse_report: true,
            mouse_drag: true,
            mouse_motion: true,
            mouse_sgr: true,
        };
        match s.on_damage(SESSION, &frame, &held) {
            DamageOutcome::Applied(g) => {
                // Grid content is unchanged (no ops) but cursor/modes/revision advance.
                assert_eq!(rows_text(&g), rows_text(&held));
                assert_eq!(g.revision, Revision(11));
                assert_eq!(g.cursor_line, 1);
                assert_eq!(g.cursor_col, 2);
                assert!(!g.cursor_visible);
                assert_eq!(g.cursor_shape, CursorShape::Beam);
                assert!(g.alt_screen && g.app_cursor && g.bracketed_paste && g.focus_reporting);
                assert!(g.mouse_report && g.mouse_drag && g.mouse_motion && g.mouse_sgr);
                assert_eq!(s.accepted(), Some(("gen-a", 11)));
            }
            other => panic!("expected Applied, got {other:?}"),
        }
    }

    #[test]
    fn damage_partial_bad_op_does_not_mutate_held() {
        let mut s = st();
        let held = baseline(&mut s, "gen-a", 10);
        let before = rows_text(&held);
        // First op is a valid RowSpan; the second runs past the row width. `validate`
        // bounds ops against the FRAME's declared cols, so to slip past validate and
        // fail only at apply, we make the frame's declared geometry larger than the
        // held grid: validate passes (in-bounds for cols=5), apply fails (held is 3).
        let frame = dmg(
            "gen-a",
            10,
            11,
            5,
            2,
            vec![
                DamageOp::RowSpan {
                    row: 0,
                    start: 0,
                    cells: vec![cell(1, "a")],
                },
                DamageOp::RowSpan {
                    row: 1,
                    start: 0,
                    cells: vec![cell(1, "x"); 5], // fits cols=5 but not the held 3-wide row
                },
            ],
        );
        // cols mismatch (5 vs held 3) is caught BEFORE apply -> resync, held untouched.
        match s.on_damage(SESSION, &frame, &held) {
            DamageOutcome::Resync {
                reason: Reject::DamageNotApplicable { .. },
            } => {}
            other => panic!("expected Resync(DamageNotApplicable), got {other:?}"),
        }
        // The held grid the caller passed is a separate value; our state never advanced.
        assert_eq!(rows_text(&held), before);
        assert_eq!(s.accepted(), Some(("gen-a", 10)));
    }

    /// A damage frame for a DIFFERENT session is ignored outright — never resynced,
    /// never applied, and our state is left exactly as it was. (Resyncing would pull
    /// a needless snapshot for our session over an unrelated session's frame.)
    #[test]
    fn damage_wrong_session_is_ignored_no_state_change() {
        let mut s = st();
        let held = baseline(&mut s, "gen-a", 10);
        // A perfectly valid, forward frame — but addressed to a different session.
        let frame = dmg(
            "gen-a",
            10,
            11,
            3,
            2,
            vec![DamageOp::ClearAll { cell: blank() }],
        );
        assert!(matches!(
            s.on_damage("some-other-session", &frame, &held),
            DamageOutcome::Ignore
        ));
        // Baseline untouched: not advanced, not retired, not resynced.
        assert_eq!(s.accepted(), Some(("gen-a", 10)));
        assert_eq!(s.phase(), SyncPhase::Synchronized);
    }

    /// Wrong-session BEFORE any baseline: still Ignore, and crucially it does NOT
    /// move us out of AwaitingBaseline (the client path keys off this to avoid
    /// requesting a snapshot for OUR session over a foreign frame).
    #[test]
    fn damage_wrong_session_before_baseline_does_not_resync() {
        let mut s = st();
        // No baseline yet (AwaitingBaseline). `held` is a throwaway grid the state
        // machine must never consult on the wrong-session path.
        let held = snap("gen-a", 1, vec![plain_row(3), plain_row(3)]);
        let frame = dmg("gen-a", 1, 2, 3, 2, vec![]);
        assert!(matches!(
            s.on_damage("other", &frame, &held),
            DamageOutcome::Ignore
        ));
        // We stayed in AwaitingBaseline — no phase change, no accepted grid.
        assert_eq!(s.phase(), SyncPhase::AwaitingBaseline);
        assert_eq!(s.accepted(), None);
    }

    /// A frame whose generation we already RETIRED (a newer one superseded it) is a
    /// stale straggler — ignored, not resynced, and our state is unchanged.
    #[test]
    fn damage_retired_generation_is_ignored_no_state_change() {
        let mut s = st();
        // gen-a then gen-b: gen-a is retired when gen-b lands.
        baseline(&mut s, "gen-a", 10);
        let held_b = snap("gen-b", 1, vec![plain_row(3), plain_row(3)]);
        assert_eq!(s.on_grid(SESSION, &held_b), repaint());
        let frame = dmg(
            "gen-a",
            1,
            2,
            3,
            2,
            vec![DamageOp::ClearAll { cell: blank() }],
        );
        assert!(matches!(
            s.on_damage(SESSION, &frame, &held_b),
            DamageOutcome::Ignore
        ));
        // gen-b baseline untouched.
        assert_eq!(s.accepted(), Some(("gen-b", 1)));
        assert_eq!(s.phase(), SyncPhase::Synchronized);
    }

    /// A DIFFERENT but NOT-retired generation still resyncs: the daemon rebuilt the
    /// grid (a respawn) and we haven't baselined that generation yet, so only a fresh
    /// snapshot can re-baseline — damage can't be applied incrementally onto it.
    #[test]
    fn damage_different_non_retired_generation_resyncs() {
        let mut s = st();
        let held = baseline(&mut s, "gen-a", 10);
        // gen-c was never seen, so it is not retired; held is still gen-a.
        let frame = dmg(
            "gen-c",
            10,
            11,
            3,
            2,
            vec![DamageOp::ClearAll { cell: blank() }],
        );
        match s.on_damage(SESSION, &frame, &held) {
            DamageOutcome::Resync {
                reason: Reject::DamageNotApplicable { .. },
            } => {}
            other => panic!("expected Resync(DamageNotApplicable), got {other:?}"),
        }
        assert_eq!(s.accepted(), Some(("gen-a", 10)));
    }

    /// Cross-check: a baseline grid plus a sequence of
    /// renderer-applied damage frames reconstructs EXACTLY the daemon's final grid,
    /// for both RowSpan and ClearAll. This is the renderer half of the daemon's
    /// `baseline + damage == final snapshot` equivalence property.
    #[test]
    fn damage_baseline_plus_frames_equals_final_grid() {
        let mut s = st();
        let held = baseline(&mut s, "gen-a", 10);

        // Frame 1: RowSpan on row 1 writing "hi" at col 0.
        let f1 = dmg(
            "gen-a",
            10,
            11,
            3,
            2,
            vec![DamageOp::RowSpan {
                row: 1,
                start: 0,
                cells: vec![cell(1, "h"), cell(1, "i")],
            }],
        );
        let g1 = match s.on_damage(SESSION, &f1, &held) {
            DamageOutcome::Applied(g) => *g,
            other => panic!("frame 1 expected Applied, got {other:?}"),
        };
        assert_eq!(rows_text(&g1), vec!["   ".to_string(), "hi ".to_string()]);

        // Frame 2: ClearAll wipes everything back to blanks.
        let f2 = dmg(
            "gen-a",
            11,
            12,
            3,
            2,
            vec![DamageOp::ClearAll { cell: blank() }],
        );
        let g2 = match s.on_damage(SESSION, &f2, &g1) {
            DamageOutcome::Applied(g) => *g,
            other => panic!("frame 2 expected Applied, got {other:?}"),
        };

        // The final reconstructed grid equals a fresh all-blank snapshot at rev 12.
        let expected = snap("gen-a", 12, vec![plain_row(3), plain_row(3)]);
        assert_eq!(rows_text(&g2), rows_text(&expected));
        assert_eq!(g2.revision, Revision(12));
        assert_eq!(s.accepted(), Some(("gen-a", 12)));
    }

    // ---- scroll application (parity with pty-daemon::grid) ------------------

    /// Byte-for-byte mirror of `pty-daemon/src/grid.rs::apply_scroll_up_parity_fixture`.
    /// A ScrollUp by 1 over [0,3) moves rows 1,2 to 0,1 and leaves row 2 unchanged (the
    /// vacated row is repainted by a following RowSpan, NOT cleared by the scroll).
    #[test]
    fn apply_scroll_up_parity_fixture() {
        let mut rows = vec![vec![cell(1, "A")], vec![cell(1, "B")], vec![cell(1, "C")]];
        apply_scroll_op(&mut rows, 0, 3, 1, true).unwrap();
        assert_eq!(rows[0][0].text, "B");
        assert_eq!(rows[1][0].text, "C");
        assert_eq!(rows[2][0].text, "C", "vacated row left as-is (not cleared)");
    }

    /// Mirror of `pty-daemon`'s `apply_scroll_down_parity_fixture`.
    #[test]
    fn apply_scroll_down_parity_fixture() {
        let mut rows = vec![vec![cell(1, "A")], vec![cell(1, "B")], vec![cell(1, "C")]];
        apply_scroll_op(&mut rows, 0, 3, 1, false).unwrap();
        assert_eq!(rows[0][0].text, "A", "vacated top row left as-is");
        assert_eq!(rows[1][0].text, "A");
        assert_eq!(rows[2][0].text, "B");
    }

    #[test]
    fn apply_scroll_rejects_out_of_bounds() {
        let mut rows = vec![vec![cell(1, "A")], vec![cell(1, "B")]];
        assert!(apply_scroll_op(&mut rows, 0, 2, 3, true).is_err());
        assert!(apply_scroll_op(&mut rows, 0, 5, 1, true).is_err());
        assert!(apply_scroll_op(&mut rows, 0, 2, 0, true).is_err());
    }

    /// A scroll frame applies over the held grid: ScrollUp by 1 then a RowSpan repaints
    /// the exposed bottom row — the same op order the daemon ships.
    #[test]
    fn damage_scroll_up_applies_and_matches_expected() {
        let mut s = st();
        let held = snap(
            "gen-a",
            10,
            vec![
                vec![cell(1, "a"), cell(1, "a"), cell(1, "a")],
                vec![cell(1, "b"), cell(1, "b"), cell(1, "b")],
                vec![cell(1, "c"), cell(1, "c"), cell(1, "c")],
            ],
        );
        assert_eq!(s.on_grid(SESSION, &held), repaint());
        // Scroll up by 1 (rows b,c rise to 0,1), then repaint the exposed row 2 with "d"s.
        let frame = dmg(
            "gen-a",
            10,
            11,
            3,
            3,
            vec![
                DamageOp::ScrollUp {
                    top: 0,
                    bottom_exclusive: 3,
                    lines: 1,
                },
                DamageOp::RowSpan {
                    row: 2,
                    start: 0,
                    cells: vec![cell(1, "d"), cell(1, "d"), cell(1, "d")],
                },
            ],
        );
        match s.on_damage(SESSION, &frame, &held) {
            DamageOutcome::Applied(g) => {
                assert_eq!(
                    rows_text(&g),
                    vec!["bbb".to_string(), "ccc".to_string(), "ddd".to_string()]
                );
                assert_eq!(g.revision, Revision(11));
            }
            other => panic!("expected Applied, got {other:?}"),
        }
        assert_eq!(s.accepted(), Some(("gen-a", 11)));
    }

    /// A scroll op whose region is in-bounds for the FRAME's declared geometry but past
    /// the held grid's actual height fails at apply -> resync, held grid untouched.
    #[test]
    fn damage_scroll_bad_region_resyncs_held_untouched() {
        let mut s = st();
        let held = baseline(&mut s, "gen-a", 10); // 3 cols x 2 rows of blanks
        let before = rows_text(&held);
        // Frame declares rows=5 (passes validate's bound: bottom_exclusive 5 <= rows 5),
        // but the held grid is only 2 rows tall, so apply_scroll_op rejects the region.
        let frame = dmg(
            "gen-a",
            10,
            11,
            3,
            5,
            vec![DamageOp::ScrollUp {
                top: 0,
                bottom_exclusive: 5,
                lines: 1,
            }],
        );
        match s.on_damage(SESSION, &frame, &held) {
            DamageOutcome::Resync {
                reason: Reject::DamageNotApplicable { .. },
            } => {}
            other => panic!("expected Resync(DamageNotApplicable), got {other:?}"),
        }
        assert_eq!(rows_text(&held), before);
        assert_eq!(s.accepted(), Some(("gen-a", 10)));
    }

    /// A frame whose first op (scroll) is valid but second op (RowSpan) runs past the held
    /// row width leaves the held grid untouched (scratch-first) and resyncs.
    #[test]
    fn damage_scroll_then_bad_rowspan_leaves_held_untouched() {
        let mut s = st();
        let held = snap(
            "gen-a",
            10,
            vec![
                vec![cell(1, "a"), cell(1, "a"), cell(1, "a")],
                vec![cell(1, "b"), cell(1, "b"), cell(1, "b")],
                vec![cell(1, "c"), cell(1, "c"), cell(1, "c")],
            ],
        );
        assert_eq!(s.on_grid(SESSION, &held), repaint());
        let before = rows_text(&held);
        // Frame declares cols=5 (RowSpan of 5 cells fits validate) but the held rows are
        // only 3 wide, so the RowSpan apply fails AFTER the scroll already mutated scratch.
        let frame = dmg(
            "gen-a",
            10,
            11,
            5,
            3,
            vec![
                DamageOp::ScrollUp {
                    top: 0,
                    bottom_exclusive: 3,
                    lines: 1,
                },
                DamageOp::RowSpan {
                    row: 2,
                    start: 0,
                    cells: vec![cell(1, "d"); 5],
                },
            ],
        );
        // cols mismatch (5 vs held 3) is caught before apply -> resync, held untouched.
        match s.on_damage(SESSION, &frame, &held) {
            DamageOutcome::Resync {
                reason: Reject::DamageNotApplicable { .. },
            } => {}
            other => panic!("expected Resync(DamageNotApplicable), got {other:?}"),
        }
        assert_eq!(rows_text(&held), before);
        assert_eq!(s.accepted(), Some(("gen-a", 10)));
    }

    /// A frame whose RowSpan is individually valid and applies in bounds, but leaves the
    /// grid with a DANGLING wide lead (it overwrote the spacer half of a wide pair with a
    /// normal cell, so a width-2 lead is no longer followed by a width-0 spacer). Each cell
    /// passes `validate` and the span fits, so the ONLY thing that can catch this is the
    /// post-apply `validate_wide_layout(&scratch)` gate. It must resync and leave the held
    /// grid untouched — a dangling wide lead would mis-paint the renderer's wide-pair layout
    /// (a half-drawn glyph or an off-by-one row). Pins that the post-apply layout re-check
    /// is load-bearing on the damage path, not only on the snapshot path.
    #[test]
    fn damage_rowspan_dangling_wide_lead_resyncs_held_untouched() {
        let mut s = st();
        // Held baseline carries a valid wide pair at cols [0,1] plus a normal cell at col 2.
        let held = snap(
            "gen-a",
            10,
            vec![vec![cell(2, "界"), cell(0, ""), cell(1, "x")]],
        );
        assert_eq!(s.on_grid(SESSION, &held), repaint());
        let before = rows_text(&held);
        // Overwrite ONLY the spacer (col 1) with a normal cell. The lead at col 0 is left
        // intact, so post-apply the grid holds [lead(2), normal(1), normal(1)] — a dangling
        // wide lead. The RowSpan cell is width 1 (valid) and the span [1,2) fits cols 3, so
        // `validate` and `apply_ops` both succeed; only `validate_wide_layout` can reject it.
        let frame = dmg(
            "gen-a",
            10,
            11,
            3,
            1,
            vec![DamageOp::RowSpan {
                row: 0,
                start: 1,
                cells: vec![cell(1, "y")],
            }],
        );
        match s.on_damage(SESSION, &frame, &held) {
            DamageOutcome::Resync {
                reason: Reject::InvalidWideLayout { row: 0, col: 0 },
            } => {}
            other => panic!("expected Resync(InvalidWideLayout {{row:0,col:0}}), got {other:?}"),
        }
        // Held grid untouched and the baseline never advanced past rev 10.
        assert_eq!(rows_text(&held), before);
        assert_eq!(s.accepted(), Some(("gen-a", 10)));
        assert_eq!(s.phase(), SyncPhase::Synchronized);
    }
}
