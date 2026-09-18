//! Winsize-owner state. One shared PTY = one winsize; a full-screen app (Claude Code, vim) queries the size
//! and redraws for it, so a grid sized for the desktop looks wrong on a differently-shaped remote. This
//! decides WHO sizes each PTY.
//!
//! PER-PANE, PRESENCE-DRIVEN (the model the user asked for): the pane the remote is ACTIVELY VIEWING owns
//! that pane's size while a remote is connected; every OTHER pane stays local. A browser-created pane also
//! gets a bounded, connection-scoped lease from immediately before its first durable publication until its
//! first viewed attach. When the remote switches panes, the previous pane drops back to local (and the desktop
//! auto-refits it). No connected remote → everything is local. There is no manual step for the common case —
//! ownership follows presence, not permanent creation provenance.
//!
//! How the agent knows the viewed pane: attach/resize messages carry an explicit `viewed` signal. Geometry for
//! background panes remains legal but cannot move presence. Only a successful viewed structured attach or viewed
//! resize feeds `note_remote_viewing(connection_id, session_id)`; switching panes therefore moves ownership
//! automatically.
//!
//! Manual override (kept as an escape hatch on both ends): `set_remote_selected(true)` forces remote to own
//! (the legacy global "Sized: Remote" toggle); `false` forces local immediately. The presence-driven set is
//! used when no manual override is active.
//!
//! GRACE: when serving drops to 0 we DON'T flip to Local immediately — a flaky drop often reconnects within
//! seconds. We wait `GRACE` (10s); if serving is still 0, remote ownership ends; a reconnect within the
//! window keeps it. Choosing Local explicitly flips immediately.
//!
//! Pure + time-injectable (`now_ms` passed in) so the rules + grace are unit-testable without WebRTC.

use std::time::Duration;

/// How long serving may stay at 0 before remote ownership ends (tolerates flaky reconnects).
pub const GRACE: Duration = Duration::from_secs(10);
/// Hard ceiling for the request-scoped ownership bridge between a remote creation's first durable
/// publication/StartSession and the browser's successful viewed attach. This covers the browser's bounded
/// creation, inventory, and attach watchdog chain without turning birth provenance into permanent ownership.
pub const CREATION_LEASE: Duration = Duration::from_secs(45);

/// Process-local authority identity. This value never crosses the private viewport adapter; it
/// exists only to make an exact public lease stale whenever a different authenticated claim takes
/// ownership without changing the pane's visible geometry.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct AuthorityGeneration(u64);

impl AuthorityGeneration {
    #[cfg(test)]
    pub(crate) const fn for_test(value: u64) -> Self {
        Self(value)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct CreationLease {
    connection_id: String,
    session_id: String,
    geometry: maestro_extension_api::ViewportGeometry,
    expires_at_ms: u64,
    authority_generation: AuthorityGeneration,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct PendingViewedAttachAuthority {
    connection_id: String,
    session_id: String,
    authority_generation: AuthorityGeneration,
    cols: u16,
    rows: u16,
    reclaimed_before_reservation: bool,
}

/// Exact, process-local authority captured for one viewed structured Attach. The token carries a
/// weak reference so abandoned daemon output cannot keep the shared owner alive. Its fields are
/// intentionally private: only [`WinsizeOwner`] may decide whether the same connection/session/
/// authority generation is still current at the exact Grid queue boundary.
#[derive(Clone, Debug)]
pub struct DeferredResizeAuthority {
    owner: std::sync::Weak<std::sync::Mutex<WinsizeOwner>>,
    connection_id: String,
    session_id: String,
    authority_generation: AuthorityGeneration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AuthorityGenerationExhausted;

impl DeferredResizeAuthority {
    /// Reserve a unique pending viewed claim without publishing remote ownership. A successful
    /// exact Grid later consumes this token; a local reclaim, another viewer, or an override
    /// invalidates it first.
    pub(crate) fn reserve(
        owner: &std::sync::Arc<std::sync::Mutex<WinsizeOwner>>,
        connection_id: &str,
        session_id: &str,
        cols: u16,
        rows: u16,
    ) -> Result<Option<Self>, AuthorityGenerationExhausted> {
        let mut state = owner.lock().unwrap_or_else(|error| error.into_inner());
        let Some(authority_generation) =
            state.reserve_viewed_attach_authority(connection_id, session_id, cols, rows)?
        else {
            return Ok(None);
        };
        Ok(Some(Self {
            owner: std::sync::Arc::downgrade(owner),
            connection_id: connection_id.to_string(),
            session_id: session_id.to_string(),
            authority_generation,
        }))
    }

    pub fn cancel(&self) {
        let Some(owner) = self.owner.upgrade() else {
            return;
        };
        owner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .cancel_viewed_attach_authority(self);
    }

    /// Run the conditional Resize publication while holding the exact owner claim, then publish
    /// viewed ownership only if queuing succeeded. This makes queue-before-reclaim and
    /// reclaim-before-queue two deterministic orders without holding an owner lock during Attach.
    pub fn publish_resize_if_current(&self, publish: impl FnOnce() -> bool) -> bool {
        let Some(owner) = self.owner.upgrade() else {
            return false;
        };
        let published = owner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .publish_viewed_attach_resize(self, publish);
        published
    }

    pub fn update_geometry_if_current(&self, cols: u16, rows: u16) -> bool {
        let Some(owner) = self.owner.upgrade() else {
            return false;
        };
        let updated = owner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .update_pending_viewed_attach_geometry(self, cols, rows);
        updated
    }
}

/// One content-blind in-memory ownership fact exposed only to the private viewport control
/// adapter. `None` means the authenticated remote is currently connected; a finite deadline is
/// used for reconnect grace and creation leases. The public host receives a shorter bounded TTL.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RemoteOwnedViewport {
    pub(crate) session_id: String,
    pub(crate) geometry: maestro_extension_api::ViewportGeometry,
    pub(crate) valid_until_ms: Option<u64>,
    pub(crate) authority_generation: AuthorityGeneration,
}

fn viewport_geometry(cols: u16, rows: u16) -> maestro_extension_api::ViewportGeometry {
    // The authenticated remote bridge rejects dimensions outside this range. Clamp again here so
    // future internal callers cannot turn malformed geometry into a process panic.
    let cols = cols.clamp(1, maestro_extension_api::MAX_TERMINAL_DIMENSION);
    let rows = rows.clamp(1, maestro_extension_api::MAX_TERMINAL_DIMENSION);
    // The browser protocol currently carries cells, not physical pixels. Use a conservative,
    // deterministic cell-derived projection until that protocol gains pixel dimensions; ownership
    // decisions never depend on these estimates and zero-sized surfaces remain impossible.
    maestro_extension_api::ViewportGeometry::new(
        cols,
        rows,
        u32::from(cols).saturating_mul(8),
        u32::from(rows).saturating_mul(16),
    )
    .expect("bounded nonzero terminal dimensions form valid viewport geometry")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    Local,
    Remote,
}

impl Owner {
    pub fn as_str(self) -> &'static str {
        match self {
            Owner::Local => "local",
            Owner::Remote => "remote",
        }
    }
}

/// The owner state machine. Feed it `remoteSelected` changes and `serving` counts (with a monotonic `now_ms`); read
/// `effective(now_ms)`. No interior clock — the caller supplies time, so tests are deterministic.
#[derive(Debug)]
pub struct WinsizeOwner {
    /// MANUAL override: `Some(true)` forces remote to own (legacy "Sized: Remote"), `Some(false)` forces
    /// local immediately, `None` = no override → use the presence-driven set. Kept as an escape hatch.
    remote_selected: Option<bool>,
    /// The session id the remote is ACTIVELY VIEWING (fed only from successful `viewed` resize/attach). This
    /// pane is the presence-driven remote-owned one; None when the remote isn't viewing a specific pane.
    viewed_session: Option<String>,
    /// Connection that most recently established the viewed-session claim. The typed public projection remains
    /// content-blind; this identity exists solely so another connection can reserve its own
    /// create-to-first-attach lease even while the same session is already viewed elsewhere.
    viewed_connection_id: Option<String>,
    /// Opaque process-local generation for the current viewed claim. A connection or pane handoff
    /// advances it even when geometry is byte-identical, invalidating delayed exact reclaims.
    viewed_authority_generation: Option<AuthorityGeneration>,
    /// Last successful viewed resize/structured-attach geometry. It is content-blind and never
    /// persisted; the typed extension snapshot projects it with a bounded lease TTL.
    viewed_geometry: Option<maestro_extension_api::ViewportGeometry>,
    /// Short-lived, connection-scoped ownership for sessions being created/revived from a remote viewport.
    /// It closes the gap before the first viewed attach can take normal presence ownership; it is never persisted
    /// into SessionRecord/TabRecord and therefore cannot pin later local/remote sizing.
    creation_leases: Vec<CreationLease>,
    /// At most one delayed viewed Attach may claim the peer's single active viewport. A newer
    /// viewed Attach supersedes the older token before either can mutate geometry.
    pending_viewed_attach: Option<PendingViewedAttachAuthority>,
    /// Monotonic allocator shared by viewed and creation claims for this private process.
    next_authority_generation: Option<u64>,
    /// Exact local reclaims. Repeated resize events from the same still-viewing remote cannot undo
    /// a user's local-size click; a new authenticated viewing claim (different pane/connection) or
    /// explicit remote selection may establish a fresh lease.
    local_reclaimed_sessions: std::collections::HashSet<String>,
    /// Last observed connected-peer count.
    serving: usize,
    /// When serving most recently BECAME 0 (ms). `None` while serving > 0. Drives the grace window.
    zero_since_ms: Option<u64>,
    /// A serialized eager publication failed after mutating in-memory authority. The periodic publisher must
    /// retry even when its last successful snapshot happens to equal the current in-memory state (for example,
    /// reserve wrote Remote, rollback returned memory to Local, but the rollback write failed).
    publication_dirty: bool,
    /// Last complete two-file snapshot published by the serialized writer. Keeping this with the authority state
    /// lets the periodic expiry poll observe eager publications too; a process sleep past lease expiry cannot
    /// compare against an older poll-local cache and leave the eager session set stranded on disk.
    published_effective: Option<Owner>,
    published_sessions: Option<Vec<String>>,
}

impl Default for WinsizeOwner {
    fn default() -> Self {
        Self {
            remote_selected: None,
            viewed_session: None,
            viewed_connection_id: None,
            viewed_authority_generation: None,
            viewed_geometry: None,
            creation_leases: Vec::new(),
            pending_viewed_attach: None,
            next_authority_generation: Some(1),
            local_reclaimed_sessions: std::collections::HashSet::new(),
            serving: 0,
            zero_since_ms: Some(0), // start "at zero" so a fresh agent is Local until a remote connects
            publication_dirty: false,
            published_effective: None,
            published_sessions: None,
        }
    }
}

impl WinsizeOwner {
    pub fn new() -> Self {
        Self::default()
    }

    #[cfg(test)]
    pub(crate) fn has_pending_viewed_attach_for_test(&self) -> bool {
        self.pending_viewed_attach.is_some()
    }

    #[cfg(test)]
    pub(crate) fn set_next_authority_generation_for_test(&mut self, next: Option<u64>) {
        self.next_authority_generation = next;
    }

    fn issue_authority_generation(
        &mut self,
    ) -> Result<AuthorityGeneration, AuthorityGenerationExhausted> {
        let generation = self
            .next_authority_generation
            .ok_or(AuthorityGenerationExhausted)?;
        self.next_authority_generation = generation.checked_add(1);
        Ok(AuthorityGeneration(generation))
    }

    fn invalidate_pending_viewed_attach(&mut self) {
        if let Some(pending) = self.pending_viewed_attach.take() {
            if pending.reclaimed_before_reservation {
                self.local_reclaimed_sessions.insert(pending.session_id);
            }
        }
    }

    fn reserve_viewed_attach_authority(
        &mut self,
        connection_id: &str,
        session_id: &str,
        cols: u16,
        rows: u16,
    ) -> Result<Option<AuthorityGeneration>, AuthorityGenerationExhausted> {
        // Allocate first so an exhausted process cannot invalidate an existing pending claim or
        // consume a local-reclaim fact before the bridge returns its correlated refusal.
        let authority_generation = self.issue_authority_generation()?;
        // A second viewed Attach is a newer claim. Restore any local-reclaim fact temporarily
        // hidden by the superseded reservation before deciding whether the new claim is admissible.
        self.invalidate_pending_viewed_attach();
        if self.remote_selected == Some(false)
            || !self.remote_resize_allowed(connection_id, session_id, true)
        {
            return Ok(None);
        }
        let reclaimed_before_reservation = self.local_reclaimed_sessions.remove(session_id);
        self.pending_viewed_attach = Some(PendingViewedAttachAuthority {
            connection_id: connection_id.to_string(),
            session_id: session_id.to_string(),
            authority_generation,
            cols,
            rows,
            reclaimed_before_reservation,
        });
        Ok(Some(authority_generation))
    }

    fn pending_viewed_attach_matches(&self, token: &DeferredResizeAuthority) -> bool {
        self.pending_viewed_attach.as_ref().is_some_and(|pending| {
            pending.connection_id == token.connection_id
                && pending.session_id == token.session_id
                && pending.authority_generation == token.authority_generation
        })
    }

    fn update_pending_viewed_attach_geometry(
        &mut self,
        token: &DeferredResizeAuthority,
        cols: u16,
        rows: u16,
    ) -> bool {
        if !self.pending_viewed_attach_matches(token) {
            return false;
        }
        let pending = self
            .pending_viewed_attach
            .as_mut()
            .expect("exact pending viewed authority disappeared while owner lock was held");
        pending.cols = cols;
        pending.rows = rows;
        true
    }

    fn cancel_viewed_attach_authority(&mut self, token: &DeferredResizeAuthority) {
        if self.pending_viewed_attach_matches(token) {
            self.invalidate_pending_viewed_attach();
        }
    }

    fn publish_viewed_attach_resize(
        &mut self,
        token: &DeferredResizeAuthority,
        publish: impl FnOnce() -> bool,
    ) -> bool {
        if !self.pending_viewed_attach_matches(token) {
            return false;
        }
        // Recheck the live admission rule at the exact Grid/queue boundary. A reclaim after
        // reservation reinserts the session; a handoff/override removes or replaces the token.
        if self.remote_selected == Some(false)
            || self.local_reclaimed_sessions.contains(&token.session_id)
            || !self.remote_resize_allowed(&token.connection_id, &token.session_id, true)
        {
            self.invalidate_pending_viewed_attach();
            return false;
        }
        if !publish() {
            self.invalidate_pending_viewed_attach();
            return false;
        }

        let pending = self
            .pending_viewed_attach
            .take()
            .expect("exact pending viewed authority disappeared while owner lock was held");
        self.creation_leases.retain(|lease| {
            lease.connection_id != pending.connection_id || lease.session_id != pending.session_id
        });
        self.viewed_session = Some(pending.session_id.clone());
        self.viewed_connection_id = Some(pending.connection_id);
        self.viewed_authority_generation = Some(pending.authority_generation);
        self.viewed_geometry = Some(viewport_geometry(pending.cols, pending.rows));
        self.local_reclaimed_sessions.remove(&pending.session_id);
        true
    }

    fn refresh_live_authority_generations(&mut self, now_ms: u64) {
        let refresh_viewed = self
            .viewed_session
            .as_ref()
            .is_some_and(|session| !self.local_reclaimed_sessions.contains(session));
        if refresh_viewed {
            self.viewed_authority_generation = self.issue_authority_generation().ok();
        }
        for index in 0..self.creation_leases.len() {
            let refresh = self.creation_leases[index].expires_at_ms > now_ms
                && !self
                    .local_reclaimed_sessions
                    .contains(&self.creation_leases[index].session_id);
            if refresh {
                let Some(generation) = self.issue_authority_generation().ok() else {
                    // No authority value may be reused. Clear every lease that could otherwise
                    // reappear under a stale token after reconnect.
                    self.creation_leases.clear();
                    return;
                };
                self.creation_leases[index].authority_generation = generation;
            }
        }
    }

    /// The manual override, if any (`Some(true)`=force remote, `Some(false)`=force local, `None`=presence).
    pub fn remote_selected(&self) -> Option<bool> {
        self.remote_selected
    }

    /// Apply a manual override. `Some(true)` = force remote (legacy toggle), `Some(false)` = force local,
    /// `None` = clear the override and return to presence-driven ownership. Returns whether it changed.
    pub fn set_remote_selected(&mut self, selected: Option<bool>) -> bool {
        let previous = self.remote_selected;
        let selected_changed = self.remote_selected != selected;
        if selected_changed {
            self.invalidate_pending_viewed_attach();
        }
        let viewed_was_reclaimed = self
            .viewed_session
            .as_ref()
            .is_some_and(|session| self.local_reclaimed_sessions.contains(session));
        let reexposes_viewed = self.viewed_session.is_some()
            && ((previous == Some(false) && selected != Some(false) && !viewed_was_reclaimed)
                || (selected == Some(true) && viewed_was_reclaimed));
        self.remote_selected = selected;
        // An explicit Local choice is authoritative now, not after a lease timeout. Clearing the override later
        // must not resurrect a creation that the user already handed back to the desktop.
        let leases_cleared = if selected == Some(false) {
            let had_leases = !self.creation_leases.is_empty();
            self.creation_leases.clear();
            had_leases
        } else {
            false
        };
        let reclaims_cleared = if selected == Some(true) {
            let had_reclaims = !self.local_reclaimed_sessions.is_empty();
            self.local_reclaimed_sessions.clear();
            had_reclaims
        } else {
            false
        };
        if reexposes_viewed {
            self.viewed_authority_generation = self.issue_authority_generation().ok();
        }
        selected_changed || leases_cleared || reclaims_cleared
    }

    /// PRESENCE: the remote is now actively viewing `session_id` (fed from a successful browser operation whose
    /// explicit `viewed` flag is true). This becomes the remote-owned pane; the previous pane drops to local.
    /// Returns whether the viewed session changed.
    pub fn note_remote_viewing(&mut self, connection_id: &str, session_id: &str) -> bool {
        self.note_remote_viewing_with_geometry(connection_id, session_id, 80, 24)
    }

    /// Geometry-aware form used by the authenticated terminal bridge after a successful remote
    /// resize. A same-claim repeat does not clear a local reclaim; a genuinely new connection or
    /// pane transition does, creating a new ownership generation.
    pub fn note_remote_viewing_with_geometry(
        &mut self,
        connection_id: &str,
        session_id: &str,
        cols: u16,
        rows: u16,
    ) -> bool {
        // Any successful explicit viewing operation is newer than a still-pending Attach Grid.
        self.invalidate_pending_viewed_attach();
        // A successful viewed attach/resize is the permanent-for-this-presence authority. Consume only this
        // connection's request-scoped lease: another browser can legitimately still be crossing its own
        // create/replay → first-attach boundary for the same durable session.
        let before = self.creation_leases.len();
        self.creation_leases
            .retain(|lease| lease.connection_id != connection_id || lease.session_id != session_id);
        let lease_changed = self.creation_leases.len() != before;
        let viewed_changed = self.viewed_session.as_deref() != Some(session_id)
            || self.viewed_connection_id.as_deref() != Some(connection_id);
        let geometry = viewport_geometry(cols, rows);
        let geometry_changed = self.viewed_geometry != Some(geometry);
        if viewed_changed {
            let Ok(authority_generation) = self.issue_authority_generation() else {
                // The Resize may already have reached the daemon, but exhausted local identity
                // cannot publish or revive remote winsize ownership.
                self.viewed_authority_generation = None;
                return lease_changed || geometry_changed;
            };
            self.viewed_session = Some(session_id.to_string());
            self.viewed_connection_id = Some(connection_id.to_string());
            self.viewed_authority_generation = Some(authority_generation);
            self.local_reclaimed_sessions.remove(session_id);
        }
        self.viewed_geometry = Some(geometry);
        viewed_changed || lease_changed || geometry_changed
    }

    /// Reserve remote ownership while a browser-originated session is crossing the durable-create → first-view
    /// boundary. Returns true only when this call inserted a NEW lease; an existing exact lease is deliberately
    /// not renewed, so replay cannot extend authority indefinitely.
    pub fn note_remote_creation(
        &mut self,
        connection_id: &str,
        session_id: &str,
        now_ms: u64,
    ) -> bool {
        self.creation_leases
            .retain(|lease| lease.expires_at_ms > now_ms);
        if self.remote_selected == Some(false)
            || (self.viewed_session.as_deref() == Some(session_id)
                && self.viewed_connection_id.as_deref() == Some(connection_id))
            || self
                .creation_leases
                .iter()
                .any(|lease| lease.connection_id == connection_id && lease.session_id == session_id)
        {
            return false;
        }
        let Ok(authority_generation) = self.issue_authority_generation() else {
            return false;
        };
        self.creation_leases.push(CreationLease {
            connection_id: connection_id.to_string(),
            session_id: session_id.to_string(),
            geometry: viewport_geometry(80, 24),
            expires_at_ms: now_ms.saturating_add(CREATION_LEASE.as_millis() as u64),
            authority_generation,
        });
        self.local_reclaimed_sessions.remove(session_id);
        true
    }

    /// Roll back one lease inserted by an operation that failed after reserving its session id.
    pub fn clear_remote_creation(&mut self, connection_id: &str, session_id: &str) -> bool {
        let before = self.creation_leases.len();
        self.creation_leases
            .retain(|lease| lease.connection_id != connection_id || lease.session_id != session_id);
        self.creation_leases.len() != before
    }

    /// Release only one connection's in-flight creations when its control owner is torn down. Other connected
    /// browsers retain their own bounded leases.
    pub fn clear_remote_creations_for_connection(&mut self, connection_id: &str) -> bool {
        let before = self.creation_leases.len();
        self.creation_leases
            .retain(|lease| lease.connection_id != connection_id);
        self.creation_leases.len() != before
    }

    /// The remote stopped viewing any pane (e.g. detached everything). Clears the presence-owned pane.
    pub fn clear_remote_viewing(&mut self) -> bool {
        self.invalidate_pending_viewed_attach();
        if self.viewed_session.is_none() {
            return false;
        }
        self.viewed_session = None;
        self.viewed_connection_id = None;
        self.viewed_authority_generation = None;
        self.viewed_geometry = None;
        true
    }

    /// Whether this authenticated remote resize may mutate the shared PTY. A local reclaim blocks
    /// only repeats from the exact connection/session that was viewing when the reclaim occurred;
    /// a new authenticated viewing transition may establish a new lease.
    pub fn remote_resize_allowed(
        &self,
        connection_id: &str,
        session_id: &str,
        viewed: bool,
    ) -> bool {
        !self.local_reclaimed_sessions.contains(session_id)
            || (viewed
                && (self.viewed_session.as_deref() != Some(session_id)
                    || self.viewed_connection_id.as_deref() != Some(connection_id)))
    }

    /// Reclaim one currently remote-owned viewport for local sizing. This is called only after the
    /// private adapter validates the exact session, lease id, epoch and per-lease cursor.
    pub(crate) fn reclaim_viewport(&mut self, session_id: &str) -> bool {
        if self
            .pending_viewed_attach
            .as_ref()
            .is_some_and(|pending| pending.session_id == session_id)
        {
            self.invalidate_pending_viewed_attach();
        }
        let inserted = self.local_reclaimed_sessions.insert(session_id.to_string());
        let before = self.creation_leases.len();
        self.creation_leases
            .retain(|lease| lease.session_id != session_id);
        inserted || self.creation_leases.len() != before
    }

    /// Update the connected-peer count. When it transitions 0→N we clear the zero-timer; N→0 we stamp `now_ms` to
    /// start the grace window. Idempotent for unchanged counts.
    pub fn set_serving(&mut self, serving: usize, now_ms: u64) {
        let was_zero = self.serving == 0;
        let is_zero = serving == 0;
        let reappearing_after_expired_grace =
            was_zero && !is_zero && self.past_grace(now_ms) && self.remote_selected != Some(false);
        if reappearing_after_expired_grace {
            // The adapter may not have observed the temporary empty state. Rotate every still-live
            // claim before it can reappear so a pre-disconnect cached reclaim cannot remain exact.
            self.refresh_live_authority_generations(now_ms);
        }
        self.serving = serving;
        match (was_zero, is_zero) {
            (_, true) if self.zero_since_ms.is_none() => self.zero_since_ms = Some(now_ms), // just dropped to 0
            (_, false) => self.zero_since_ms = None, // a remote is present
            _ => {}                                  // still 0: keep the stamp
        }
    }

    /// True once serving has been 0 for at least GRACE (so we should treat remote as gone).
    fn past_grace(&self, now_ms: u64) -> bool {
        match self.zero_since_ms {
            Some(since) => now_ms.saturating_sub(since) >= GRACE.as_millis() as u64,
            None => false, // serving > 0 → not in grace
        }
    }

    /// Is a remote effectively present (connected, or within the reconnect grace)?
    fn remote_present(&self, now_ms: u64) -> bool {
        self.serving > 0 || !self.past_grace(now_ms)
    }

    /// The set of session ids the REMOTE currently owns the size for (per-pane, presence-driven plus bounded
    /// in-flight creations). Empty when no remote is present. Rules:
    /// - Manual override `Some(false)` → empty (forced local everywhere), immediate.
    /// - Manual override `Some(true)` → the viewed pane (if any) — the legacy global toggle now scopes to the
    ///   pane the remote is looking at, so it can't strand OTHER panes yielded.
    /// - No override (`None`, the default) → the viewed pane plus unexpired connection-scoped creation leases
    ///   while a remote is present. Switching/attach consumes the relevant lease into viewed ownership;
    ///   disconnect cleanup or expiry removes unconsumed leases.
    pub(crate) fn remote_owned_viewports(&self, now_ms: u64) -> Vec<RemoteOwnedViewport> {
        if self.remote_selected == Some(false) {
            return Vec::new();
        }
        if !self.remote_present(now_ms) {
            return Vec::new();
        }
        let presence_deadline = if self.serving > 0 {
            None
        } else {
            self.zero_since_ms
                .map(|since| since.saturating_add(GRACE.as_millis() as u64))
        };
        let mut owned = std::collections::BTreeMap::<
            String,
            (
                maestro_extension_api::ViewportGeometry,
                Option<u64>,
                AuthorityGeneration,
            ),
        >::new();
        if let (Some(id), Some(geometry), Some(authority_generation)) = (
            &self.viewed_session,
            self.viewed_geometry,
            self.viewed_authority_generation,
        ) {
            if !self.local_reclaimed_sessions.contains(id) {
                owned.insert(
                    id.clone(),
                    (geometry, presence_deadline, authority_generation),
                );
            }
        }
        for lease in self
            .creation_leases
            .iter()
            .filter(|lease| lease.expires_at_ms > now_ms)
        {
            if self.local_reclaimed_sessions.contains(&lease.session_id) {
                continue;
            }
            let lease_deadline = match presence_deadline {
                Some(deadline) => Some(deadline.min(lease.expires_at_ms)),
                None => Some(lease.expires_at_ms),
            };
            owned
                .entry(lease.session_id.clone())
                .and_modify(|(_, existing_deadline, authority_generation)| {
                    *existing_deadline = match (*existing_deadline, lease_deadline) {
                        (None, _) | (_, None) => None,
                        (Some(left), Some(right)) => Some(left.max(right)),
                    };
                    *authority_generation = (*authority_generation).max(lease.authority_generation);
                })
                .or_insert((lease.geometry, lease_deadline, lease.authority_generation));
        }
        owned
            .into_iter()
            .map(
                |(session_id, (geometry, valid_until_ms, authority_generation))| {
                    RemoteOwnedViewport {
                        session_id,
                        geometry,
                        valid_until_ms,
                        authority_generation,
                    }
                },
            )
            .collect()
    }

    pub fn remote_owned_sessions(&self, now_ms: u64) -> Vec<String> {
        self.remote_owned_viewports(now_ms)
            .into_iter()
            .map(|viewport| viewport.session_id)
            .collect()
    }

    /// Back-compat single-word owner: Remote iff the remote owns ANY pane right now, else Local. Kept so the
    /// legacy `winsize-owner` file + any global reader still work while the per-session file drives per-pane.
    ///
    /// One special case beyond the per-pane set: a MANUAL force-remote (`Some(true)`) while a remote is present
    /// reports Remote globally even before the browser has told us WHICH pane it's viewing — this preserves the
    /// legacy "Sized: Remote" toggle's meaning (remote owns) for the global reader. The per-pane
    /// `remote_owned_sessions` stays precise (empty until a viewed pane is known), so no OTHER pane is stranded.
    pub fn effective(&self, now_ms: u64) -> Owner {
        if !self.remote_owned_sessions(now_ms).is_empty() {
            return Owner::Remote;
        }
        if self.remote_selected == Some(true) && self.remote_present(now_ms) {
            return Owner::Remote;
        }
        Owner::Local
    }

    pub(crate) fn publication_needed(&self, now_ms: u64) -> bool {
        let sessions = self.remote_owned_sessions(now_ms);
        self.publication_dirty
            || self.published_effective != Some(self.effective(now_ms))
            || self.published_sessions.as_ref() != Some(&sessions)
    }
}

fn owner_publication_lock() -> &'static std::sync::Mutex<()> {
    static LOCK: std::sync::OnceLock<std::sync::Mutex<()>> = std::sync::OnceLock::new();
    LOCK.get_or_init(|| std::sync::Mutex::new(()))
}

fn mutate_and_publish_owner<R>(
    dir: &std::path::Path,
    owner: &std::sync::Arc<std::sync::Mutex<WinsizeOwner>>,
    now_ms: u64,
    force_publish: bool,
    mutate: impl FnOnce(&mut WinsizeOwner) -> (R, bool),
) -> (R, std::io::Result<(Owner, Vec<String>)>) {
    // One writer order for the background expiry poll, create reserve/rollback, connection teardown, and
    // explicit owner changes. Keep the in-memory guard through both atomic renames so a later state cannot be
    // published first and then overwritten by this older snapshot.
    let _publication = owner_publication_lock()
        .lock()
        .unwrap_or_else(|error| error.into_inner());
    let mut state = owner.lock().unwrap_or_else(|error| error.into_inner());
    let (result, changed) = mutate(&mut state);
    let sessions = state.remote_owned_sessions(now_ms);
    let effective = state.effective(now_ms);
    let snapshot_changed = state.published_effective != Some(effective)
        || state.published_sessions.as_ref() != Some(&sessions);
    if !force_publish && !changed && !state.publication_dirty && !snapshot_changed {
        return (result, Ok((effective, sessions)));
    }
    // Set this before either write. A partial write or any later failure must be retried by the periodic
    // publisher even if the mutation was subsequently rolled back to its previous in-memory snapshot.
    state.publication_dirty = true;
    let published = write_remote_owned_sessions(dir, &sessions)
        .and_then(|()| write_effective_owner(dir, effective))
        .map(|()| {
            state.publication_dirty = false;
            state.published_effective = Some(effective);
            state.published_sessions = Some(sessions.clone());
            (effective, sessions)
        });
    (result, published)
}

/// Publish the latest state through the same serialized writer used by eager creation leases.
pub fn publish_owner_state(
    dir: &std::path::Path,
    owner: &std::sync::Arc<std::sync::Mutex<WinsizeOwner>>,
    now_ms: u64,
) -> std::io::Result<(Owner, Vec<String>)> {
    mutate_and_publish_owner(dir, owner, now_ms, true, |_| ((), false)).1
}

/// Connection-scoped publisher injected only into a live authenticated remote daemon facade. It reserves a
/// session before the first observable record/layout write, and writes the per-pane suppression file immediately.
#[derive(Clone)]
pub(crate) struct RemoteCreationLeasePublisher {
    owner: std::sync::Arc<std::sync::Mutex<WinsizeOwner>>,
    agent_dir: std::path::PathBuf,
    connection_id: String,
}

impl RemoteCreationLeasePublisher {
    pub(crate) fn new(
        owner: std::sync::Arc<std::sync::Mutex<WinsizeOwner>>,
        agent_dir: std::path::PathBuf,
        connection_id: String,
    ) -> Self {
        Self {
            owner,
            agent_dir,
            connection_id,
        }
    }

    pub(crate) fn reserve(
        &self,
        session_id: &str,
        now_ms: u64,
    ) -> std::io::Result<RemoteCreationLeaseGuard> {
        let (inserted, published) =
            mutate_and_publish_owner(&self.agent_dir, &self.owner, now_ms, false, |owner| {
                let inserted = owner.note_remote_creation(&self.connection_id, session_id, now_ms);
                (inserted, inserted)
            });
        if let Err(error) = published {
            if inserted {
                // Fail closed: if the desktop suppression file could not be published, undo the in-memory
                // authority before refusing the creation. Best-effort republish restores the prior snapshot.
                let _ = mutate_and_publish_owner(
                    &self.agent_dir,
                    &self.owner,
                    now_ms,
                    false,
                    |owner| {
                        let changed = owner.clear_remote_creation(&self.connection_id, session_id);
                        ((), changed)
                    },
                );
            }
            return Err(error);
        }
        Ok(RemoteCreationLeaseGuard {
            publisher: inserted.then_some(self.clone()),
            session_id: session_id.to_string(),
            committed: false,
        })
    }

    pub(crate) fn clear_connection(&self, now_ms: u64) -> std::io::Result<()> {
        let (_, published) =
            mutate_and_publish_owner(&self.agent_dir, &self.owner, now_ms, false, |owner| {
                let changed = owner.clear_remote_creations_for_connection(&self.connection_id);
                ((), changed)
            });
        published.map(|_| ())
    }

    fn rollback(&self, session_id: &str, now_ms: u64) {
        let _ = mutate_and_publish_owner(&self.agent_dir, &self.owner, now_ms, false, |owner| {
            let changed = owner.clear_remote_creation(&self.connection_id, session_id);
            ((), changed)
        });
    }
}

/// RAII rollback for a lease reserved before a multi-write desktop mutation. Only the success path commits it;
/// every `?`, validation failure, and explicit rollback releases the temporary ownership immediately.
pub(crate) struct RemoteCreationLeaseGuard {
    publisher: Option<RemoteCreationLeasePublisher>,
    session_id: String,
    committed: bool,
}

impl RemoteCreationLeaseGuard {
    pub(crate) fn noop() -> Self {
        Self {
            publisher: None,
            session_id: String::new(),
            committed: false,
        }
    }

    pub(crate) fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for RemoteCreationLeaseGuard {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        if let Some(publisher) = &self.publisher {
            publisher.rollback(&self.session_id, unix_now_ms());
        }
    }
}

fn unix_now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis() as u64)
        .unwrap_or(0)
}

fn owner_temp_path(dir: &std::path::Path, name: &str) -> std::path::PathBuf {
    static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    dir.join(format!(
        ".{}.{}.{}.tmp",
        name,
        std::process::id(),
        NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    ))
}

/// The filename (under the agent dir) that the desktop reads for the current effective winsize owner. Content
/// is exactly "local" or "remote" (a single opaque word — content-blind). Phase 2c reads this to decide whether
/// the desktop should yield sizing the shared PTY. The agent WRITES it whenever the effective owner changes.
pub const OWNER_FILE_NAME: &str = "winsize-owner";

/// The SEPARATE file the DESKTOP writes to REQUEST an owner (its topbar toggle). Kept distinct from
/// OWNER_FILE_NAME so the agent never reads back its OWN effective-owner output as a "desktop request" — that
/// self-adoption created a feedback loop where a persisted "remote" latched remote_selected ON on the next
/// launch with NO remote connected (the "resize button stuck on after reopen" bug). The agent reads ONLY this
/// file for the desktop's intent; it writes ONLY OWNER_FILE_NAME.
pub const OWNER_REQUEST_FILE_NAME: &str = "winsize-owner-request";

/// The PER-PANE owner file: a newline-separated list of the session ids the REMOTE currently owns the size
/// for. The desktop reads this to suppress local resize for ONLY those panes and auto-refit the rest. Empty
/// file (or absent) → no pane is remote-owned (all local). The agent writes this whenever the set changes;
/// the single-word OWNER_FILE_NAME stays as a back-compat "any remote owner" summary. Content-blind: session
/// ids only (opaque uuids), never terminal data.
pub const OWNER_SESSIONS_FILE_NAME: &str = "winsize-owner-sessions";

/// Atomically write the set of remote-owned session ids (one per line) to `<dir>/winsize-owner-sessions`.
/// Temp-file + rename so a reader never sees a half-written list. Best-effort.
pub fn write_remote_owned_sessions(
    dir: &std::path::Path,
    sessions: &[String],
) -> std::io::Result<()> {
    let final_path = dir.join(OWNER_SESSIONS_FILE_NAME);
    let tmp_path = owner_temp_path(dir, OWNER_SESSIONS_FILE_NAME);
    let body = sessions.join("\n");
    std::fs::write(&tmp_path, body.as_bytes())?;
    match std::fs::rename(&tmp_path, &final_path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path);
            Err(e)
        }
    }
}

/// Read the set of remote-owned session ids from `<dir>/winsize-owner-sessions`. Missing/empty → empty vec.
/// Content-blind: opaque session ids only.
pub fn read_remote_owned_sessions(dir: &std::path::Path) -> Vec<String> {
    match std::fs::read_to_string(dir.join(OWNER_SESSIONS_FILE_NAME)) {
        Ok(s) => s
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty())
            .map(str::to_string)
            .collect(),
        Err(_) => Vec::new(),
    }
}

/// Atomically write the effective owner ("local"/"remote") to `<dir>/winsize-owner` so a separate process (the
/// desktop) can read it. Temp-file + rename so a reader never sees a half-written value. Best-effort: returns the
/// IO error to the caller for logging, but the caller treats a failure as non-fatal (the owner is still tracked
/// in memory; the file just lags).
pub fn write_effective_owner(dir: &std::path::Path, owner: Owner) -> std::io::Result<()> {
    let final_path = dir.join(OWNER_FILE_NAME);
    // Unique temp name in the SAME dir so concurrent eager/background writers cannot share a temp inode and
    // the final rename stays atomic on one filesystem.
    let tmp_path = owner_temp_path(dir, OWNER_FILE_NAME);
    std::fs::write(&tmp_path, owner.as_str().as_bytes())?;
    match std::fs::rename(&tmp_path, &final_path) {
        Ok(()) => Ok(()),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp_path); // don't leak the temp on failure
            Err(e)
        }
    }
}

/// Read + CONSUME the desktop's requested owner from `<dir>/winsize-owner-request` (the desktop's topbar
/// toggle). Distinct from OWNER_FILE_NAME so the agent never adopts its own effective output. The request is
/// TRANSIENT: we delete it after reading so a stale value can't latch `remote_selected` on the next launch
/// (the "stuck on after reopen" bug). Unknown/missing → None.
pub fn read_requested_owner(dir: &std::path::Path) -> std::io::Result<Option<Owner>> {
    let path = dir.join(OWNER_REQUEST_FILE_NAME);
    match std::fs::read_to_string(&path) {
        Ok(s) => {
            let owner = match s.trim() {
                "remote" => Some(Owner::Remote),
                "local" => Some(Owner::Local),
                _ => None,
            };
            let _ = std::fs::remove_file(&path); // consume: one-shot request, never persists across launches
            Ok(owner)
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

/// Force the effective-owner file to "local" on agent startup, so a stale "remote" left on disk from a prior
/// run (a crash, or a previous remote that owned the size) never makes the desktop suppress local resize when
/// NO remote is connected. Called once before the peer loop begins. Best-effort.
pub fn reset_owner_file_to_local(dir: &std::path::Path) {
    let _ = write_effective_owner(dir, Owner::Local);
    // clear the per-pane remote-owned set too — no remote is viewing anything at startup.
    let _ = write_remote_owned_sessions(dir, &[]);
    // also clear any leftover request so it can't re-latch remote on the first tick
    let _ = std::fs::remove_file(dir.join(OWNER_REQUEST_FILE_NAME));
}

/// Initialize both effective owner files from the in-memory state and record that exact successful snapshot.
/// This is the production startup path; unlike the legacy fire-and-forget reset helper, it lets later no-op
/// connection cleanup prove there is nothing new to publish.
pub fn initialize_owner_publication(
    dir: &std::path::Path,
    owner: &std::sync::Arc<std::sync::Mutex<WinsizeOwner>>,
    now_ms: u64,
) -> std::io::Result<()> {
    match std::fs::remove_file(dir.join(OWNER_REQUEST_FILE_NAME)) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error),
    }
    publish_owner_state(dir, owner, now_ms).map(|_| ())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_effective_owner_writes_atomically_and_reads_back() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-winsize-owner-{}-{}",
            std::process::id(),
            123
        ));
        std::fs::create_dir_all(&dir).unwrap();
        write_effective_owner(&dir, Owner::Remote).unwrap();
        let got = std::fs::read_to_string(dir.join(OWNER_FILE_NAME)).unwrap();
        assert_eq!(got, "remote");
        write_effective_owner(&dir, Owner::Local).unwrap();
        let got = std::fs::read_to_string(dir.join(OWNER_FILE_NAME)).unwrap();
        assert_eq!(got, "local");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn read_requested_owner_reads_the_request_file_and_consumes_it() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-winsize-owner-read-{}-{}",
            std::process::id(),
            456
        ));
        std::fs::create_dir_all(&dir).unwrap();
        assert_eq!(read_requested_owner(&dir).unwrap(), None);
        // requests are read from the REQUEST file (not the agent's own effective-owner output)
        std::fs::write(dir.join(OWNER_REQUEST_FILE_NAME), "remote\n").unwrap();
        assert_eq!(read_requested_owner(&dir).unwrap(), Some(Owner::Remote));
        // and CONSUMED — a second read is None (so a stale request can't re-latch on the next launch)
        assert_eq!(read_requested_owner(&dir).unwrap(), None);
        assert!(!dir.join(OWNER_REQUEST_FILE_NAME).exists());
        std::fs::write(dir.join(OWNER_REQUEST_FILE_NAME), "local").unwrap();
        assert_eq!(read_requested_owner(&dir).unwrap(), Some(Owner::Local));
        std::fs::write(dir.join(OWNER_REQUEST_FILE_NAME), "browser").unwrap();
        assert_eq!(read_requested_owner(&dir).unwrap(), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_does_not_adopt_its_own_effective_output_as_a_request() {
        // THE FEEDBACK-LOOP BUG: the agent writes "remote" to the effective file; on the next tick/launch it
        // must NOT read that back as a desktop "request" (which latched remote_selected ON with no remote).
        // Since requests now come from a SEPARATE file, the effective output is invisible to read_requested_owner.
        let dir = std::env::temp_dir().join(format!("hydra-winsize-loop-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_effective_owner(&dir, Owner::Remote).unwrap(); // agent's own output
        assert_eq!(read_requested_owner(&dir).unwrap(), None); // NOT adopted as a request
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reset_owner_file_to_local_clears_stale_remote() {
        let dir = std::env::temp_dir().join(format!("hydra-winsize-reset-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        write_effective_owner(&dir, Owner::Remote).unwrap();
        std::fs::write(dir.join(OWNER_REQUEST_FILE_NAME), "remote").unwrap();
        reset_owner_file_to_local(&dir);
        assert_eq!(
            std::fs::read_to_string(dir.join(OWNER_FILE_NAME)).unwrap(),
            "local"
        );
        assert!(!dir.join(OWNER_REQUEST_FILE_NAME).exists()); // stale request cleared
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn production_initialization_records_the_published_local_snapshot() {
        let dir =
            std::env::temp_dir().join(format!("hydra-winsize-initialize-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join(OWNER_REQUEST_FILE_NAME), "remote").unwrap();
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));

        initialize_owner_publication(&dir, &owner, 100_000).unwrap();

        assert!(!dir.join(OWNER_REQUEST_FILE_NAME).exists());
        assert_eq!(
            std::fs::read_to_string(dir.join(OWNER_FILE_NAME)).unwrap(),
            "local"
        );
        assert!(read_remote_owned_sessions(&dir).is_empty());
        assert!(!owner.lock().unwrap().publication_needed(100_000));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_is_local_until_a_remote_views_a_pane() {
        let w = WinsizeOwner::new();
        assert_eq!(w.effective(0), Owner::Local);
        assert!(w.remote_owned_sessions(0).is_empty()); // nothing connected, nothing viewed
    }

    #[test]
    fn presence_the_viewed_pane_is_remote_owned_while_connected() {
        let mut w = WinsizeOwner::new();
        w.set_serving(1, 0); // remote connects
        w.note_remote_viewing("conn-1", "sig_a"); // and views pane A
        assert_eq!(w.remote_owned_sessions(0), vec!["sig_a".to_string()]);
        assert_eq!(w.effective(0), Owner::Remote); // some pane is remote-owned
    }

    #[test]
    fn switching_panes_moves_ownership_to_the_new_pane() {
        let mut w = WinsizeOwner::new();
        w.set_serving(1, 0);
        w.note_remote_viewing("conn-1", "sig_a");
        assert_eq!(w.remote_owned_sessions(0), vec!["sig_a".to_string()]);
        // remote switches to pane B → A drops to local, B becomes remote-owned
        assert!(w.note_remote_viewing("conn-1", "sig_b"));
        assert_eq!(w.remote_owned_sessions(0), vec!["sig_b".to_string()]);
        assert!(!w.remote_owned_sessions(0).contains(&"sig_a".to_string()));
    }

    #[test]
    fn creation_lease_bridges_birth_until_viewed_attach() {
        let mut w = WinsizeOwner::new();
        w.set_serving(1, 0);
        w.note_remote_viewing("conn-1", "sig_a");
        assert!(w.note_remote_creation("conn-1", "sig_b", 1_000));
        assert_eq!(
            w.remote_owned_sessions(1_000),
            vec!["sig_a".to_string(), "sig_b".to_string()]
        );

        // Successful viewed attach consumes the temporary lease and moves normal presence ownership.
        assert!(w.note_remote_viewing("conn-1", "sig_b"));
        assert_eq!(w.remote_owned_sessions(1_001), vec!["sig_b".to_string()]);
    }

    #[test]
    fn viewed_attach_consumes_only_its_connections_same_session_lease() {
        let mut w = WinsizeOwner::new();
        w.set_serving(2, 0);
        assert!(w.note_remote_creation("conn-1", "sig-shared", 1_000));
        assert!(w.note_remote_creation("conn-2", "sig-shared", 1_000));

        assert!(w.note_remote_viewing("conn-1", "sig-shared"));
        assert!(w
            .creation_leases
            .iter()
            .any(|lease| { lease.connection_id == "conn-2" && lease.session_id == "sig-shared" }));

        // Conn-1 can move away without exposing sig-shared to a local resize while conn-2 still awaits attach.
        assert!(w.note_remote_viewing("conn-1", "sig-other"));
        assert_eq!(
            w.remote_owned_sessions(1_001),
            vec!["sig-other".to_string(), "sig-shared".to_string()]
        );
        assert!(w.note_remote_viewing("conn-2", "sig-shared"));
        assert_eq!(
            w.remote_owned_sessions(1_002),
            vec!["sig-shared".to_string()]
        );
    }

    #[test]
    fn another_connection_can_lease_a_session_already_viewed_elsewhere() {
        let mut w = WinsizeOwner::new();
        w.set_serving(2, 0);
        assert!(w.note_remote_viewing("conn-1", "sig-shared"));
        assert!(!w.note_remote_creation("conn-1", "sig-shared", 1_000));
        assert!(w.note_remote_creation("conn-2", "sig-shared", 1_000));

        assert!(w.note_remote_viewing("conn-1", "sig-other"));
        assert_eq!(
            w.remote_owned_sessions(1_001),
            vec!["sig-other".to_string(), "sig-shared".to_string()]
        );
        assert!(w.note_remote_viewing("conn-2", "sig-shared"));
        assert_eq!(
            w.remote_owned_sessions(1_002),
            vec!["sig-shared".to_string()]
        );
    }

    #[test]
    fn creation_lease_is_not_renewed_and_expires_at_its_original_deadline() {
        let mut w = WinsizeOwner::new();
        w.set_serving(1, 0);
        assert!(w.note_remote_creation("conn-1", "sig_b", 1_000));
        assert!(!w.note_remote_creation("conn-1", "sig_b", 20_000));
        let deadline = 1_000 + CREATION_LEASE.as_millis() as u64;
        assert_eq!(
            w.remote_owned_sessions(deadline - 1),
            vec!["sig_b".to_string()]
        );
        assert!(w.remote_owned_sessions(deadline).is_empty());
    }

    #[test]
    fn connection_cleanup_releases_only_that_connections_creation_leases() {
        let mut w = WinsizeOwner::new();
        w.set_serving(2, 0);
        assert!(w.note_remote_creation("conn-1", "sig_a", 1_000));
        assert!(w.note_remote_creation("conn-2", "sig_b", 1_000));
        assert!(w.clear_remote_creations_for_connection("conn-1"));
        assert_eq!(w.remote_owned_sessions(1_001), vec!["sig_b".to_string()]);
        assert!(!w.clear_remote_creations_for_connection("conn-1"));
    }

    #[test]
    fn explicit_local_clears_creation_leases_instead_of_hiding_them() {
        let mut w = WinsizeOwner::new();
        w.set_serving(1, 0);
        assert!(w.note_remote_creation("conn-1", "sig_a", 1_000));
        assert!(w.set_remote_selected(Some(false)));
        assert!(w.remote_owned_sessions(1_001).is_empty());
        assert!(w.set_remote_selected(None));
        assert!(w.remote_owned_sessions(1_002).is_empty());
    }

    #[test]
    fn creation_lease_rollback_removes_only_the_exact_connection_and_session() {
        let mut w = WinsizeOwner::new();
        w.set_serving(2, 0);
        assert!(w.note_remote_creation("conn-1", "sig-a", 1_000));
        assert!(w.note_remote_creation("conn-1", "sig-b", 1_000));
        assert!(w.note_remote_creation("conn-2", "sig-a", 1_000));
        assert!(w.clear_remote_creation("conn-1", "sig-a"));
        assert_eq!(
            w.remote_owned_sessions(1_001),
            vec!["sig-a".to_string(), "sig-b".to_string()]
        );
    }

    #[test]
    fn publisher_reserves_before_create_and_drop_rolls_back_both_files() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-winsize-creation-publisher-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let publisher =
            RemoteCreationLeasePublisher::new(owner.clone(), dir.clone(), "conn-1".into());

        {
            let _uncommitted = publisher.reserve("sig-new", 1_000).unwrap();
            assert_eq!(
                read_remote_owned_sessions(&dir),
                vec!["sig-new".to_string()]
            );
            assert_eq!(
                std::fs::read_to_string(dir.join(OWNER_FILE_NAME)).unwrap(),
                "remote"
            );
        }

        assert!(read_remote_owned_sessions(&dir).is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.join(OWNER_FILE_NAME)).unwrap(),
            "local"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn committed_publisher_lease_survives_guard_then_connection_cleanup() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-winsize-creation-commit-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let publisher =
            RemoteCreationLeasePublisher::new(owner.clone(), dir.clone(), "conn-1".into());

        publisher.reserve("sig-new", 1_000).unwrap().commit();
        assert_eq!(
            read_remote_owned_sessions(&dir),
            vec!["sig-new".to_string()]
        );
        publisher.clear_connection(1_001).unwrap();
        assert!(read_remote_owned_sessions(&dir).is_empty());
        assert_eq!(
            std::fs::read_to_string(dir.join(OWNER_FILE_NAME)).unwrap(),
            "local"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_rollback_publication_stays_dirty_until_periodic_retry_succeeds() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-winsize-creation-dirty-retry-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let publisher =
            RemoteCreationLeasePublisher::new(owner.clone(), dir.clone(), "conn-1".into());

        // Missing parent makes both the eager reserve and its best-effort rollback publication fail. Memory is
        // rolled back to Local, but the dirty bit must force a later publisher retry rather than trusting a
        // potentially stale last-success cache.
        assert!(publisher.reserve("sig-new", 1_000).is_err());
        assert!(owner.lock().unwrap().publication_dirty);
        assert!(owner
            .lock()
            .unwrap()
            .remote_owned_sessions(1_001)
            .is_empty());

        std::fs::create_dir_all(&dir).unwrap();
        let (effective, sessions) = publish_owner_state(&dir, &owner, 1_002).unwrap();
        assert_eq!(effective, Owner::Local);
        assert!(sessions.is_empty());
        assert!(!owner.lock().unwrap().publication_dirty);
        assert_eq!(
            std::fs::read_to_string(dir.join(OWNER_FILE_NAME)).unwrap(),
            "local"
        );
        assert!(read_remote_owned_sessions(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn eager_publication_snapshot_cannot_hide_expiry_after_a_long_sleep() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-winsize-creation-expiry-snapshot-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let publisher =
            RemoteCreationLeasePublisher::new(owner.clone(), dir.clone(), "conn-1".into());

        publisher.reserve("sig-new", 1_000).unwrap().commit();
        assert!(!owner.lock().unwrap().publication_needed(1_001));
        assert_eq!(
            read_remote_owned_sessions(&dir),
            vec!["sig-new".to_string()]
        );

        // No intervening poll: jump directly past the hard deadline as if the runtime was suspended.
        let deadline = 1_000 + CREATION_LEASE.as_millis() as u64;
        assert!(owner.lock().unwrap().publication_needed(deadline));
        publish_owner_state(&dir, &owner, deadline).unwrap();
        assert!(read_remote_owned_sessions(&dir).is_empty());
        assert!(!owner.lock().unwrap().publication_needed(deadline));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_remote_means_everything_local() {
        let mut w = WinsizeOwner::new();
        w.set_serving(1, 0);
        w.note_remote_viewing("conn-1", "sig_a");
        assert!(!w.remote_owned_sessions(0).is_empty());
        // remote drops and grace expires → no pane is remote-owned
        w.set_serving(0, 1_000);
        assert!(w.remote_owned_sessions(1_000 + 10_000).is_empty());
        assert_eq!(w.effective(1_000 + 10_000), Owner::Local);
    }

    #[test]
    fn manual_force_local_is_immediate_even_while_a_remote_views() {
        let mut w = WinsizeOwner::new();
        w.set_serving(1, 0);
        w.note_remote_viewing("conn-1", "sig_a");
        assert!(!w.remote_owned_sessions(0).is_empty());
        w.set_remote_selected(Some(false)); // manual: force local everywhere
        assert!(w.remote_owned_sessions(0).is_empty());
        assert_eq!(w.effective(0), Owner::Local);
    }

    #[test]
    fn drop_keeps_the_viewed_pane_remote_during_grace_then_falls_back() {
        let mut w = WinsizeOwner::new();
        w.set_serving(1, 0);
        w.note_remote_viewing("conn-1", "sig_a");
        assert_eq!(w.effective(0), Owner::Remote);
        w.set_serving(0, 1_000); // drop
        assert_eq!(w.effective(1_000), Owner::Remote); // within grace → still remote-owned
        assert_eq!(w.effective(1_000 + 9_999), Owner::Remote);
        assert_eq!(w.effective(1_000 + 10_000), Owner::Local); // grace elapsed → local
        assert!(w.remote_owned_sessions(1_000 + 10_000).is_empty());
    }

    #[test]
    fn reconnect_within_grace_keeps_the_viewed_pane_remote() {
        let mut w = WinsizeOwner::new();
        w.set_serving(1, 0);
        w.note_remote_viewing("conn-1", "sig_a");
        w.set_serving(0, 1_000); // drop
        assert_eq!(w.effective(5_000), Owner::Remote); // mid-grace
        w.set_serving(1, 5_000); // reconnect
        assert_eq!(w.remote_owned_sessions(20_000), vec!["sig_a".to_string()]);
    }

    #[test]
    fn note_and_clear_report_change() {
        let mut w = WinsizeOwner::new();
        assert!(w.note_remote_viewing("conn-1", "sig_a"));
        assert!(!w.note_remote_viewing("conn-1", "sig_a")); // same → no change
        assert!(w.note_remote_viewing("conn-1", "sig_b"));
        assert!(w.clear_remote_viewing());
        assert!(!w.clear_remote_viewing()); // already cleared
    }

    #[test]
    fn exact_local_reclaim_blocks_same_claim_until_a_new_authenticated_viewer_claims() {
        let mut w = WinsizeOwner::new();
        w.set_serving(2, 0);
        w.note_remote_viewing_with_geometry("conn-1", "sig_a", 100, 30);
        assert_eq!(w.remote_owned_sessions(0), vec!["sig_a"]);

        assert!(w.reclaim_viewport("sig_a"));
        assert!(w.remote_owned_sessions(0).is_empty());
        assert!(!w.remote_resize_allowed("conn-1", "sig_a", true));
        assert!(!w.remote_resize_allowed("conn-1", "sig_a", false));
        w.note_remote_viewing_with_geometry("conn-1", "sig_a", 120, 40);
        assert!(
            w.remote_owned_sessions(0).is_empty(),
            "same-claim resize cannot undo the local reclaim",
        );

        assert!(w.remote_resize_allowed("conn-2", "sig_a", true));
        w.note_remote_viewing_with_geometry("conn-2", "sig_a", 120, 40);
        assert_eq!(
            w.remote_owned_sessions(0),
            vec!["sig_a"],
            "a new authenticated viewing transition creates a fresh remote claim",
        );
    }

    #[test]
    fn authority_generation_advances_for_handoffs_creations_and_reexposure() {
        let mut owner = WinsizeOwner::new();
        owner.set_serving(2, 0);
        assert!(owner.note_remote_viewing_with_geometry("conn-a", "sig-a", 100, 30));
        let viewed_a = owner.remote_owned_viewports(0)[0].authority_generation;

        assert!(!owner.note_remote_viewing_with_geometry("conn-a", "sig-a", 100, 30));
        assert_eq!(
            owner.remote_owned_viewports(0)[0].authority_generation,
            viewed_a,
            "an exact same-claim repeat is not a new authority generation",
        );

        assert!(owner.note_remote_viewing_with_geometry("conn-b", "sig-a", 100, 30));
        let viewed_b = owner.remote_owned_viewports(0)[0].authority_generation;
        assert!(viewed_b > viewed_a);

        assert!(owner.note_remote_creation("conn-c", "sig-a", 1_000));
        let with_creation = owner.remote_owned_viewports(1_000)[0].authority_generation;
        assert!(with_creation > viewed_b);

        assert!(owner.set_remote_selected(Some(false)));
        assert!(owner.remote_owned_viewports(1_001).is_empty());
        assert!(owner.set_remote_selected(None));
        let reexposed = owner.remote_owned_viewports(1_001)[0].authority_generation;
        assert!(reexposed > with_creation);

        assert!(owner.reclaim_viewport("sig-a"));
        assert!(owner.remote_owned_viewports(1_002).is_empty());
        assert!(owner.set_remote_selected(Some(true)));
        let reclaimed_then_reexposed = owner.remote_owned_viewports(1_002)[0].authority_generation;
        assert!(reclaimed_then_reexposed > reexposed);

        owner.set_serving(0, 2_000);
        owner.set_serving(1, 2_000 + GRACE.as_millis() as u64);
        let post_grace_reconnect = owner.remote_owned_viewports(12_000)[0].authority_generation;
        assert!(post_grace_reconnect > reclaimed_then_reexposed);
    }

    #[test]
    fn set_remote_selected_reports_change() {
        let mut w = WinsizeOwner::new();
        assert!(w.set_remote_selected(Some(true)));
        assert!(!w.set_remote_selected(Some(true))); // no change
        assert!(w.set_remote_selected(Some(false)));
        assert!(w.set_remote_selected(None)); // clear override
    }

    #[test]
    fn remote_owned_sessions_file_round_trips() {
        let dir =
            std::env::temp_dir().join(format!("hydra-winsize-sessions-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        assert!(read_remote_owned_sessions(&dir).is_empty()); // absent → empty
        write_remote_owned_sessions(&dir, &["sig_a".into(), "sig_b".into()]).unwrap();
        assert_eq!(
            read_remote_owned_sessions(&dir),
            vec!["sig_a".to_string(), "sig_b".to_string()]
        );
        write_remote_owned_sessions(&dir, &[]).unwrap(); // empty set → no remote-owned panes
        assert!(read_remote_owned_sessions(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }
}
