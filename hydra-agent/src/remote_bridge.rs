//! S4 — the terminal bridge. Sits behind the AUTHENTICATED control channel (S3b) and carries PTY/session
//! bytes between the remote client and the local daemon, after the token gate passes.
//!
//! Responsibilities:
//!   - accept the terminal METADATA messages (session_list / attach_session / resize / detach) — JSON —
//!     only when the connection is authenticated (a valid token was accepted).
//!   - enforce the session-access POLICY (token scope + ownership hook) before list/attach.
//!   - translate to the EXISTING daemon protocol via a `SessionBackend` (real = daemon_bridge; fake in
//!     tests) and stream daemon output frames back as `terminal_output` BINARY frames.
//!   - bound everything: cap concurrent attaches, drop per-attach state on detach, and **close ALL live
//!     attaches when the device is revoked**.
//!
//! Content-blindness: terminal bytes flow ONLY here (peer↔agent↔daemon over DTLS + the local unix socket);
//! they are NEVER sent to the cloud and NEVER logged (only sizes/counts may be logged).

use std::collections::HashMap;

use crate::remote_frame::{encode, FrameKind, MAX_INPUT_PAYLOAD};
use crate::remote_policy::{can_attach, can_list, visible_sessions, AccessDenied, SessionPolicy};
use crate::remote_token::TokenClaims;

fn is_false(value: &bool) -> bool {
    !*value
}

/// Prototype cap on concurrent attaches per connection. Small + independent cleanup per attach.
pub const MAX_ATTACHES: usize = 8;

/// Select one free non-zero wire channel and advance the cursor. Every possible id is inspected at most once,
/// so a corrupt/full registry fails in bounded time instead of overwriting a live attachment after `u16` wraps.
fn take_available_channel(
    next_channel: &mut u16,
    mut is_live: impl FnMut(u16) -> bool,
) -> Option<u16> {
    let start = (*next_channel).max(1);
    let mut candidate = start;
    for _ in 0..u16::MAX {
        let following = candidate.checked_add(1).unwrap_or(1);
        if !is_live(candidate) {
            *next_channel = following;
            return Some(candidate);
        }
        candidate = following;
    }
    None
}

fn valid_terminal_dimensions(cols: u16, rows: u16) -> bool {
    cols > 0
        && rows > 0
        && cols <= maestro_extension_api::MAX_TERMINAL_DIMENSION
        && rows <= maestro_extension_api::MAX_TERMINAL_DIMENSION
}

fn now_ms() -> u64 {
    use std::time::{SystemTime, UNIX_EPOCH};
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis() as u64)
        .unwrap_or(0)
}

fn default_true() -> bool {
    true
}

/// Terminal METADATA messages (JSON) the bridge accepts post-auth. `terminal_input`/`terminal_output`
/// travel as BINARY frames (remote_frame), not here.
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TerminalMsg {
    SessionList {
        request_id: String,
    },
    AttachSession {
        request_id: String,
        session_id: String,
        cols: u16,
        rows: u16,
        /// RAW renderer mode (xterm.js): attach with want_raw_output:true so the daemon streams raw PTY
        /// bytes. Absent/false → structured Grid+Damage (canvas renderer). The client picks per attach.
        #[serde(default)]
        raw: bool,
        /// True only for the pane the browser is actively viewing. Older clients omit it and remain
        /// background/attach-only, so an auto-attached sibling can never steal winsize ownership.
        #[serde(default)]
        viewed: bool,
    },
    Resize {
        session_id: String,
        cols: u16,
        rows: u16,
        /// Whether this resize belongs to the pane the browser is actively viewing. Legacy clients omitted
        /// this field while every resize implicitly meant the active pane, so absence must remain true.
        #[serde(default = "default_true")]
        viewed: bool,
    },
    Scrollback {
        session_id: String,
        offset_from_top: u32,
        count: u16,
    },
    Detach {
        session_id: String,
    },
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct SessionMetadata {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct WorkspacePaneMetadata {
    pub id: String,
    pub session_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub stashed: bool,
    /// The pane's session working directory (`SessionRecord.cwd_resolved`), surfaced so the browser can default a
    /// split's folder picker to the source window's folder (mirrors the local desktop split dialog). `None` when the
    /// session record has no resolved cwd. Content-blind (a directory path, not terminal content).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct WorkspaceWindowMetadata {
    pub id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub focused: bool,
    #[serde(default, skip_serializing_if = "is_false")]
    pub stashed: bool,
    pub panes: Vec<WorkspacePaneMetadata>,
}

/// A project's persisted defaultLaunchFlags, surfaced so the browser Edit Project form can PREFILL them. This is
/// config metadata already shown in the desktop ProjectForm — NOT live terminal content (content-blind).
#[derive(Debug, Clone, Default, serde::Serialize, PartialEq, Eq)]
pub struct WorkspaceLaunchDefaults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resume_mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dangerous: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_command: Option<String>,
}

/// A project's pinned directory (name + path), surfaced for Edit Project prefill. Content-blind (labels/paths).
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct WorkspaceDirectory {
    pub name: String,
    pub path: String,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct WorkspaceProjectMetadata {
    pub id: String,
    pub name: String,
    pub root: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icon: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accent_color: Option<String>,
    #[serde(default, skip_serializing_if = "is_false")]
    pub selected: bool,
    /// Persisted launch defaults (for Edit Project prefill); omitted when none set.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub launch_defaults: Option<WorkspaceLaunchDefaults>,
    /// Pinned directories (for Edit Project prefill); omitted when empty.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub directories: Vec<WorkspaceDirectory>,
    /// SYSTEM project (the built-in "Terminal"): the browser pins it + refuses delete. Omitted when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub system: bool,
    /// User hid this project from the dashboard. Omitted when false.
    #[serde(default, skip_serializing_if = "is_false")]
    pub hidden: bool,
    pub windows: Vec<WorkspaceWindowMetadata>,
}

#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct WorkspaceMetadata {
    pub projects: Vec<WorkspaceProjectMetadata>,
}

/// JSON replies the bridge emits (alongside binary `terminal_output`).
#[derive(Debug, serde::Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum TerminalReply {
    SessionListResult {
        request_id: String,
        sessions: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        session_metadata: Vec<SessionMetadata>,
        #[serde(skip_serializing_if = "Option::is_none")]
        workspace_metadata: Option<WorkspaceMetadata>,
    },
    AttachOk {
        request_id: String,
        session_id: String,
        channel: u16,
        #[serde(skip_serializing_if = "Option::is_none")]
        terminal_encoding: Option<String>,
    },
    /// UNSOLICITED live-sync push: the desktop's workspace changed while attached. `epoch` is the connection's
    /// monotonic push counter (for the ack in Slice 4). Carries the SAME triple a `session_list` reply carries —
    /// sessions + session_metadata + workspace_metadata — so the push is SELF-SUFFICIENT: a pane created on the
    /// desktop is clickable/attachable from the pushed state alone (metadata-only pushes left the new session
    /// missing from the browser's live list, so tree clicks silently no-op'd until a manual refresh). Only sent
    /// to connections allowed to list (never for a forbidden one).
    WorkspaceUpdate {
        epoch: u64,
        sessions: Vec<String>,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        session_metadata: Vec<SessionMetadata>,
        #[serde(skip_serializing_if = "Option::is_none")]
        workspace_metadata: Option<WorkspaceMetadata>,
    },
    Error {
        code: String,
        message: String,
        /// Present for request/reply operations that can be retried independently. Older clients ignore these
        /// fields; generic asynchronous errors omit them.
        #[serde(skip_serializing_if = "Option::is_none")]
        request_id: Option<String>,
        #[serde(skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
}

/// What the bridge sends out: either a JSON reply or a BINARY frame (already encoded).
#[derive(Debug, PartialEq, Eq)]
pub enum Outbound {
    Json(TerminalReply),
    Binary(Vec<u8>),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ResizeAdmission {
    /// The exact generation-conditional Resize was queued now.
    Queued,
    /// The current Attach route is still pending; geometry was updated under its exact authority
    /// token and will be queued only after the exact Grid.
    Deferred,
}

/// The local session layer the bridge drives. The REAL impl wraps `daemon_bridge` (ClientRequest/events);
/// the test impl is a fake. Kept minimal + synchronous-result for testability; the real async wiring
/// lives in the wiring layer.
pub trait SessionBackend {
    /// Live session ids (daemon `ListSessions` → `Sessions`).
    fn list_sessions(&self) -> Vec<String>;
    /// Optional live session metadata. Default empty keeps fake/old backends id-only.
    fn session_metadata(&self) -> Vec<SessionMetadata> {
        Vec::new()
    }
    /// Optional desktop dashboard hierarchy. Default `None` keeps old backends compatible.
    fn workspace_metadata(&self) -> Option<WorkspaceMetadata> {
        None
    }
    /// Attach to a session at the given size. `raw` selects want_raw_output (true → raw PTY bytes for
    /// xterm.js; false → structured Grid+Damage). Err on failure.
    fn attach(&mut self, session_id: &str, cols: u16, rows: u16, raw: bool) -> Result<(), String>;
    /// Attach with a connection-local output generation. Backends without an asynchronous output queue can use the
    /// default; the daemon backend overrides this so an echoed baseline and tagged live events establish exact
    /// ownership across detach/reattach.
    fn attach_with_output_generation(
        &mut self,
        session_id: &str,
        cols: u16,
        rows: u16,
        raw: bool,
        _output_generation: u64,
        deferred_resize_authority: Option<crate::winsize_owner::DeferredResizeAuthority>,
    ) -> Result<(), String> {
        if let Some(authority) = deferred_resize_authority {
            authority.cancel();
            return Err("backend cannot defer viewed attach geometry".into());
        }
        self.attach(session_id, cols, rows, raw)
    }
    /// Forward raw input bytes to the PTY (daemon `Input`).
    fn input(&mut self, session_id: &str, bytes: &[u8]) -> Result<(), String>;
    /// Resize the PTY (daemon `Resize`).
    fn resize(&mut self, session_id: &str, cols: u16, rows: u16) -> Result<(), String>;
    fn resize_with_admission(
        &mut self,
        session_id: &str,
        cols: u16,
        rows: u16,
    ) -> Result<ResizeAdmission, String> {
        self.resize(session_id, cols, rows)
            .map(|()| ResizeAdmission::Queued)
    }
    /// Request scrollback history (daemon `Scrollback`); the daemon replies with a `ScrollbackRows` event
    /// that flows back as a normal `terminal_output` frame. View-only: never touches the live grid.
    fn scrollback(
        &mut self,
        session_id: &str,
        offset_from_top: u32,
        count: u16,
    ) -> Result<(), String>;
    /// Detach (daemon `Detach`); release the forwarder.
    fn detach(&mut self, session_id: &str);
}

/// One live attach's state. Independent cleanup: dropping this entry detaches its session. The channel id is the
/// `attaches` map KEY, so it isn't duplicated here.
struct Attachment {
    session_id: String,
    terminal_encoding: TerminalEncoding,
    /// Connection-local generation, never sent to the browser/cloud. The local daemon may echo it solely for
    /// routing; delayed work must still match this exact attachment before it may use the DataChannel target.
    generation: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TerminalEncoding {
    Legacy,
    GzipJsonV1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TerminalOutputTarget {
    pub(crate) channel: u16,
    pub(crate) encoding: TerminalEncoding,
    pub(crate) generation: u64,
}

/// The terminal bridge for ONE authenticated connection.
pub struct TerminalBridge<B: SessionBackend, P: SessionPolicy> {
    backend: B,
    policy: P,
    claims: TokenClaims,
    /// channel id → attachment. Bounded by MAX_ATTACHES.
    attaches: HashMap<u16, Attachment>,
    next_channel: u16,
    next_attachment_generation: Option<u64>,
    /// Set when the device is revoked — every subsequent call refuses, and `revoke()` already closed all.
    revoked: bool,
    /// Per-connection input backpressure (byte token-bucket). Bounds a FLOOD of at-cap input frames; the
    /// per-frame size cap (MAX_INPUT_PAYLOAD) is enforced separately.
    input_rate: crate::input_rate::InputRateLimiter,
    /// WINSIZE (#25): the shared per-peer owner. `new` installs a bridge-private owner so the public
    /// default path can never acknowledge a viewed structured Attach while silently discarding its
    /// dimensions; production replaces it with the peer-shared owner below.
    winsize_owner: std::sync::Arc<std::sync::Mutex<crate::winsize_owner::WinsizeOwner>>,
    /// Authenticated control-connection identity. Creation leases are connection-scoped, so only the browser
    /// that successfully attaches may consume its own create-to-first-view bridge.
    winsize_connection_id: String,
    /// Exact per-connection viewed pane, sourced only from a successful operation carrying `viewed:true`.
    /// The remote sender reads this content-blind id at chunk boundaries so foreground output can overtake
    /// other panes without changing ordering within this pane. Raw attaches track viewing here even though
    /// their winsize claim intentionally waits for the post-subscription resize.
    viewed_session: Option<String>,
    browser_terminal_gzip: bool,
}

impl<B: SessionBackend, P: SessionPolicy> TerminalBridge<B, P> {
    /// Build a bridge for an AUTHENTICATED connection (the control channel already verified the token).
    pub fn new(backend: B, policy: P, claims: TokenClaims) -> Self {
        let private_connection_id = claims
            .signal_session_id
            .clone()
            .unwrap_or_else(|| claims.device_id.clone());
        TerminalBridge {
            backend,
            policy,
            claims,
            attaches: HashMap::new(),
            next_channel: 1,
            next_attachment_generation: Some(1),
            revoked: false,
            input_rate: crate::input_rate::InputRateLimiter::default(),
            winsize_owner: std::sync::Arc::new(std::sync::Mutex::new(
                crate::winsize_owner::WinsizeOwner::new(),
            )),
            winsize_connection_id: private_connection_id,
            viewed_session: None,
            browser_terminal_gzip: false,
        }
    }

    /// WINSIZE (#25): attach the shared per-peer owner so browser resizes/attaches drive per-pane presence.
    pub fn with_winsize_owner(
        mut self,
        owner: std::sync::Arc<std::sync::Mutex<crate::winsize_owner::WinsizeOwner>>,
        connection_id: impl Into<String>,
    ) -> Self {
        self.winsize_owner = owner;
        self.winsize_connection_id = connection_id.into();
        self
    }

    pub fn with_terminal_gzip(mut self, supported: bool) -> Self {
        self.browser_terminal_gzip = supported;
        self
    }

    /// Tell the owner which pane the remote is actively viewing (browser resizes/attaches only its focused pane).
    fn note_remote_viewing(&mut self, session_id: &str, cols: u16, rows: u16) {
        if self.viewed_session.as_deref() != Some(session_id) {
            self.viewed_session = Some(session_id.to_string());
        }
        let mut owner = self
            .winsize_owner
            .lock()
            .unwrap_or_else(|error| error.into_inner());
        owner.note_remote_viewing_with_geometry(
            &self.winsize_connection_id,
            session_id,
            cols,
            rows,
        );
    }

    fn remote_resize_allowed(&self, session_id: &str, viewed: bool) -> bool {
        self.winsize_owner
            .lock()
            .unwrap_or_else(|error| error.into_inner())
            .remote_resize_allowed(&self.winsize_connection_id, session_id, viewed)
    }

    fn err(code: &str, msg: &str) -> Outbound {
        Outbound::Json(TerminalReply::Error {
            code: code.into(),
            message: msg.into(),
            request_id: None,
            session_id: None,
        })
    }

    fn attach_err(code: &str, msg: &str, request_id: &str, session_id: &str) -> Outbound {
        Outbound::Json(TerminalReply::Error {
            code: code.into(),
            message: msg.into(),
            request_id: Some(request_id.into()),
            session_id: Some(session_id.into()),
        })
    }

    fn channel_for(&self, session_id: &str) -> Option<u16> {
        self.attaches
            .iter()
            .find(|(_, a)| a.session_id == session_id)
            .map(|(c, _)| *c)
    }

    /// Compute the (visible sessions, filtered session metadata, filtered workspace metadata) EXACTLY as a
    /// `session_list` reply would carry them for THIS connection's claims. Factored so the live-sync PUSH path sends
    /// byte-identical, identically-redacted data as the reply — the security invariant (a push can never leak content
    /// a reply wouldn't). Both the SessionList handler and the push poll call this.
    pub fn current_session_list_reply(
        &self,
    ) -> (Vec<String>, Vec<SessionMetadata>, Option<WorkspaceMetadata>) {
        let all = self.backend.list_sessions();
        let sessions = visible_sessions(&self.claims, &self.policy, all.iter().map(|s| s.as_str()));
        let visible = std::collections::HashSet::<String>::from_iter(sessions.iter().cloned());
        let session_metadata = self
            .backend
            .session_metadata()
            .into_iter()
            .filter(|m| visible.contains(&m.id))
            .collect();
        let workspace_metadata =
            filter_workspace_metadata(self.backend.workspace_metadata(), &visible);
        (sessions, session_metadata, workspace_metadata)
    }

    /// The live-sync push payload for THIS connection, with the forbidden-vs-empty distinction made EXPLICIT (Codex):
    /// - `None` → the connection is NOT allowed to list → NEVER push (no `workspace_update` at all).
    /// - `Some(inner)` → allowed; `inner` is EXACTLY the `workspace_metadata` field a `session_list` reply would carry
    ///   (`Some(meta)` when there's a workspace, `None` when the desktop reports none). So the browser treats a pushed
    ///   `workspace_metadata` identically to the reply's — same null/omitted semantics. Byte-diffed by the watcher.
    pub fn workspace_push_payload(
        &self,
    ) -> Option<(Vec<String>, Vec<SessionMetadata>, Option<WorkspaceMetadata>)> {
        if can_list(&self.claims, &self.policy).is_err() {
            return None; // forbidden → never push
        }
        // The FULL session_list reply triple — the push must be self-sufficient (see WorkspaceUpdate).
        // Including `sessions` in the payload also means the byte-diff fires on session-only changes
        // (e.g. a bare created/exited PTY), which metadata-only diffs missed.
        Some(self.current_session_list_reply())
    }

    /// Handle one terminal METADATA message. Returns the replies/frames to send.
    pub fn handle(&mut self, msg: TerminalMsg) -> Vec<Outbound> {
        self.handle_with_terminal_encoding(msg, None)
    }

    /// Live-wire variant for the additive attach codec field. Keeping the field outside `TerminalMsg` preserves
    /// the byte/source-compatible legacy bridge API used by older embedders while the wire parser validates the
    /// optional value on the one attach operation that owns it.
    pub fn handle_with_terminal_encoding(
        &mut self,
        msg: TerminalMsg,
        terminal_encoding: Option<&str>,
    ) -> Vec<Outbound> {
        if self.revoked {
            return vec![Self::err("revoked", "device revoked")];
        }
        match msg {
            TerminalMsg::SessionList { request_id } => {
                if can_list(&self.claims, &self.policy).is_err() {
                    return vec![Self::err("forbidden", "not allowed to list sessions")];
                }
                let (sessions, session_metadata, workspace_metadata) =
                    self.current_session_list_reply();
                vec![Outbound::Json(TerminalReply::SessionListResult {
                    request_id,
                    sessions,
                    session_metadata,
                    workspace_metadata,
                })]
            }
            TerminalMsg::AttachSession {
                request_id,
                session_id,
                cols,
                rows,
                raw,
                viewed,
            } => {
                if !valid_terminal_dimensions(cols, rows) {
                    return vec![Self::attach_err(
                        "invalid_dimensions",
                        "terminal dimensions are invalid",
                        &request_id,
                        &session_id,
                    )];
                }
                let selected_encoding = match terminal_encoding {
                    None => TerminalEncoding::Legacy,
                    Some(crate::remote_frame::TERMINAL_GZIP_JSON_V1)
                        if self.browser_terminal_gzip =>
                    {
                        TerminalEncoding::GzipJsonV1
                    }
                    Some(_) => {
                        return vec![Self::attach_err(
                            "unsupported_encoding",
                            "terminal encoding was not negotiated",
                            &request_id,
                            &session_id,
                        )]
                    }
                };
                if let Err(e) = can_attach(&self.claims, &self.policy, &session_id) {
                    let reason = match e {
                        AccessDenied::SessionScopeMismatch => "session_scope",
                        AccessDenied::PolicyDenied => "forbidden",
                    };
                    return vec![Self::attach_err(
                        reason,
                        "attach not allowed",
                        &request_id,
                        &session_id,
                    )];
                }
                if self.channel_for(&session_id).is_some() {
                    return vec![Self::attach_err(
                        "already_attached",
                        "session already attached",
                        &request_id,
                        &session_id,
                    )];
                }
                if self.attaches.len() >= MAX_ATTACHES {
                    return vec![Self::attach_err(
                        "too_many_attaches",
                        "attach limit reached",
                        &request_id,
                        &session_id,
                    )];
                }
                let Some(generation) = self.next_attachment_generation else {
                    return vec![Self::attach_err(
                        "attachment_generation_exhausted",
                        "terminal attachment identity space exhausted",
                        &request_id,
                        &session_id,
                    )];
                };
                let Some(channel) = take_available_channel(&mut self.next_channel, |candidate| {
                    self.attaches.contains_key(&candidate)
                }) else {
                    return vec![Self::attach_err(
                        "channel_exhausted",
                        "no terminal channel is available",
                        &request_id,
                        &session_id,
                    )];
                };
                // Only a viewed structured Attach may carry deferred geometry. Its process-local
                // token is reserved before the Attach line can be queued, then revalidated at the
                // exact Grid/conditional-Resize queue boundary. Raw and background attaches remain
                // read-only until an explicit gated Resize.
                let deferred_resize_authority = if viewed && !raw {
                    match crate::winsize_owner::DeferredResizeAuthority::reserve(
                        &self.winsize_owner,
                        &self.winsize_connection_id,
                        &session_id,
                        cols,
                        rows,
                    ) {
                        Ok(authority) => authority,
                        Err(crate::winsize_owner::AuthorityGenerationExhausted) => {
                            return vec![Self::attach_err(
                                "winsize_authority_exhausted",
                                "terminal winsize authority identity space exhausted",
                                &request_id,
                                &session_id,
                            )]
                        }
                    }
                } else {
                    None
                };
                if let Err(e) = self.backend.attach_with_output_generation(
                    &session_id,
                    cols,
                    rows,
                    raw,
                    generation,
                    deferred_resize_authority.clone(),
                ) {
                    if let Some(authority) = deferred_resize_authority {
                        authority.cancel();
                    }
                    return vec![Self::attach_err(
                        "attach_failed",
                        &e,
                        &request_id,
                        &session_id,
                    )];
                }
                if viewed {
                    // A viewed attach claims output priority immediately. Winsize ownership remains
                    // unpublished until its exact Grid queues the token-bound conditional Resize.
                    self.viewed_session = Some(session_id.clone());
                }
                self.next_attachment_generation = generation.checked_add(1);
                match self.attaches.entry(channel) {
                    std::collections::hash_map::Entry::Vacant(slot) => {
                        slot.insert(Attachment {
                            session_id: session_id.clone(),
                            terminal_encoding: selected_encoding,
                            generation,
                        });
                    }
                    std::collections::hash_map::Entry::Occupied(_) => {
                        // Defensive backstop: the allocator and registry share `&mut self`, so this cannot
                        // ordinarily race. Preserve the old route and undo the new daemon attachment if an
                        // internal invariant is ever violated.
                        self.backend.detach(&session_id);
                        return vec![Self::attach_err(
                            "channel_exhausted",
                            "no terminal channel is available",
                            &request_id,
                            &session_id,
                        )];
                    }
                }
                vec![Outbound::Json(TerminalReply::AttachOk {
                    request_id,
                    session_id,
                    channel,
                    terminal_encoding: (selected_encoding == TerminalEncoding::GzipJsonV1)
                        .then(|| crate::remote_frame::TERMINAL_GZIP_JSON_V1.to_string()),
                })]
            }
            TerminalMsg::Resize {
                session_id,
                cols,
                rows,
                viewed,
            } => {
                if !valid_terminal_dimensions(cols, rows) {
                    return vec![Self::err(
                        "invalid_dimensions",
                        "terminal dimensions are invalid",
                    )];
                }
                if self.channel_for(&session_id).is_none() {
                    return vec![Self::err("not_attached", "resize before attach")];
                }
                let resize_allowed = self.remote_resize_allowed(&session_id, viewed);
                let admission = if resize_allowed {
                    match self.backend.resize_with_admission(&session_id, cols, rows) {
                        Ok(admission) => Some(admission),
                        Err(e) => return vec![Self::err("resize_failed", &e)],
                    }
                } else {
                    None
                };
                // Geometry for background panes is legitimate but must not steal per-pane remote presence.
                // Publish viewing only after a mutation was actually queued. A Pending-route update
                // remains owned by its exact Attach token until Grid-time publication succeeds.
                if viewed && admission == Some(ResizeAdmission::Queued) {
                    self.note_remote_viewing(&session_id, cols, rows);
                }
                vec![]
            }
            TerminalMsg::Scrollback {
                session_id,
                offset_from_top,
                count,
            } => {
                // view-only history read; gated by the same attach scope as resize. The daemon's
                // ScrollbackRows reply rides back as a normal terminal_output frame.
                if self.channel_for(&session_id).is_none() {
                    return vec![Self::err("not_attached", "scrollback before attach")];
                }
                if let Err(e) = self.backend.scrollback(&session_id, offset_from_top, count) {
                    return vec![Self::err("scrollback_failed", &e)];
                }
                vec![]
            }
            TerminalMsg::Detach { session_id } => {
                match self.channel_for(&session_id) {
                    Some(channel) => {
                        self.attaches.remove(&channel);
                        self.backend.detach(&session_id); // independent per-attach cleanup
                        if self.viewed_session.as_deref() == Some(session_id.as_str()) {
                            self.viewed_session = None;
                        }
                        vec![]
                    }
                    None => vec![Self::err("not_attached", "detach without attach")],
                }
            }
        }
    }

    /// Handle an inbound BINARY `terminal_input` frame for `channel`. Forwards bytes to the PTY. Returns an
    /// error Outbound on a bad channel; otherwise nothing (input is one-way).
    pub fn handle_input(&mut self, channel: u16, bytes: &[u8]) -> Vec<Outbound> {
        self.handle_input_at(channel, bytes, now_ms())
    }

    /// Time-injected variant (for deterministic rate-limit tests; the live WebRTC path passes the real clock).
    /// Enforces, in order: revoke → per-frame size cap → per-connection input RATE → attach → forward to PTY.
    pub fn handle_input_at(&mut self, channel: u16, bytes: &[u8], now_ms: u64) -> Vec<Outbound> {
        if self.revoked {
            return vec![Self::err("revoked", "device revoked")];
        }
        // The browser is untrusted: independently cap a single input frame so a malicious/buggy peer can't shove
        // megabytes into the PTY per frame (amplification / DoS). Reject BEFORE touching the daemon backend — the
        // over-large bytes never reach the PTY. Content-blind (a code, never the payload).
        if bytes.len() > MAX_INPUT_PAYLOAD {
            return vec![Self::err(
                "input_too_large",
                "terminal input frame exceeds the size cap",
            )];
        }
        // Per-connection backpressure: bound a FLOOD of at-cap frames. Over-budget input is DROPPED before the
        // daemon (a slow throttle, content-blind) — legitimate typing/paste stays well within the bucket.
        if !self.input_rate.allow(bytes.len() as u64, now_ms) {
            return vec![Self::err(
                "input_rate_limited",
                "terminal input rate limit exceeded",
            )];
        }
        match self.attaches.get(&channel) {
            Some(a) => {
                let session_id = a.session_id.clone();
                if let Err(e) = self.backend.input(&session_id, bytes) {
                    return vec![Self::err("input_failed", &e)];
                }
                vec![]
            }
            None => vec![Self::err("not_attached", "input for unknown channel")],
        }
    }

    /// Encode a daemon output frame for a session into a `terminal_output` BINARY frame (agent→client).
    /// Returns None if the session isn't attached (nothing to send). Never logs the bytes.
    pub fn output_frame(&self, session_id: &str, daemon_frame: &[u8]) -> Option<Outbound> {
        let channel = self.channel_for(session_id)?;
        encode(FrameKind::TerminalOutput, channel, daemon_frame)
            .ok()
            .map(Outbound::Binary)
    }

    pub fn output_target(&self, session_id: &str) -> Option<(u16, TerminalEncoding)> {
        self.exact_output_target(session_id)
            .map(|target| (target.channel, target.encoding))
    }

    pub(crate) fn exact_output_target(&self, session_id: &str) -> Option<TerminalOutputTarget> {
        self.attaches.iter().find_map(|(channel, attachment)| {
            (attachment.session_id == session_id).then_some(TerminalOutputTarget {
                channel: *channel,
                encoding: attachment.terminal_encoding,
                generation: attachment.generation,
            })
        })
    }

    /// The pane explicitly identified as viewed by this authenticated connection. This is an opaque session id,
    /// never terminal content, and is intentionally connection-local rather than inferred from global desktop state.
    pub(crate) fn viewed_session(&self) -> Option<&str> {
        self.viewed_session.as_deref()
    }

    /// REVOKE: close ALL live attaches for this device (independent cleanup each) and refuse further use.
    /// The caller also tears down the DataChannel/peer; this releases the daemon forwarders.
    pub fn revoke(&mut self) {
        for (_, a) in self.attaches.drain() {
            self.backend.detach(&a.session_id);
        }
        self.viewed_session = None;
        self.revoked = true;
    }

    pub fn is_revoked(&self) -> bool {
        self.revoked
    }

    pub fn attach_count(&self) -> usize {
        self.attaches.len()
    }
}

fn filter_workspace_metadata(
    metadata: Option<WorkspaceMetadata>,
    visible_sessions: &std::collections::HashSet<String>,
) -> Option<WorkspaceMetadata> {
    let metadata = metadata?;
    // Surface the desktop's OPEN projects/windows even when their sessions aren't currently live/visible to this
    // device — the local dashboard shows idle projects in the sidebar, and the browser mirrors that (an open project
    // the user can navigate + launch into). We must NOT leak an ATTACHABLE session that policy hides, so a pane whose
    // session isn't visible is redacted to an EMPTY session_id (kept as a placeholder pane so the project/window
    // still shows, but non-live + non-attachable in the browser). Only truly-empty projects are dropped.
    let projects: Vec<WorkspaceProjectMetadata> = metadata
        .projects
        .into_iter()
        .filter_map(|project| {
            let windows: Vec<WorkspaceWindowMetadata> = project
                .windows
                .into_iter()
                .map(|window| {
                    let panes: Vec<WorkspacePaneMetadata> = window
                        .panes
                        .into_iter()
                        .map(|pane| {
                            if visible_sessions.contains(&pane.session_id) {
                                pane
                            } else {
                                // Redact the hidden session id → the pane shows (so the project/window appears) but
                                // can't be attached; the browser derives it as non-live (session not in `sessions`).
                                WorkspacePaneMetadata {
                                    session_id: String::new(),
                                    ..pane
                                }
                            }
                        })
                        .collect();
                    WorkspaceWindowMetadata { panes, ..window }
                })
                .collect();
            // Keep every project that has at least one window (idle projects still show, matching local + the
            // dashboard backend's intent). A project with zero windows is genuinely empty → drop.
            if windows.is_empty() {
                None
            } else {
                Some(WorkspaceProjectMetadata { windows, ..project })
            }
        })
        .collect();
    if projects.is_empty() {
        None
    } else {
        Some(WorkspaceMetadata { projects })
    }
}

/// Closing the bridge detaches everything (connection close / peer close). Independent cleanup per attach.
impl<B: SessionBackend, P: SessionPolicy> Drop for TerminalBridge<B, P> {
    fn drop(&mut self) {
        for (_, a) in self.attaches.drain() {
            self.backend.detach(&a.session_id);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_policy::SameAsLocalPolicy;
    use std::cell::RefCell;
    use std::rc::Rc;

    /// A fake session backend that records what the bridge did (no real PTY).
    #[derive(Debug, Clone, PartialEq, Eq)]
    enum BackendOperation {
        Resize {
            session_id: String,
            cols: u16,
            rows: u16,
        },
        Attach {
            session_id: String,
            cols: u16,
            rows: u16,
            raw: bool,
        },
    }

    #[derive(Default)]
    struct FakeState {
        sessions: Vec<String>,
        metadata: Vec<SessionMetadata>,
        workspace_metadata: Option<WorkspaceMetadata>,
        attached: Vec<String>,
        attached_raw: Vec<(String, bool)>,
        attach_deferred_sizes: Vec<(String, Option<(u16, u16)>)>,
        detached: Vec<String>,
        inputs: Vec<(String, Vec<u8>)>,
        resizes: Vec<(String, u16, u16)>,
        scrollbacks: Vec<(String, u32, u16)>,
        operations: Vec<BackendOperation>,
        fail_attach: bool,
        fail_resize: bool,
    }
    #[derive(Clone)]
    struct FakeBackend(Rc<RefCell<FakeState>>);
    impl SessionBackend for FakeBackend {
        fn list_sessions(&self) -> Vec<String> {
            self.0.borrow().sessions.clone()
        }
        fn session_metadata(&self) -> Vec<SessionMetadata> {
            self.0.borrow().metadata.clone()
        }
        fn workspace_metadata(&self) -> Option<WorkspaceMetadata> {
            self.0.borrow().workspace_metadata.clone()
        }
        fn attach(
            &mut self,
            session_id: &str,
            cols: u16,
            rows: u16,
            raw: bool,
        ) -> Result<(), String> {
            let mut state = self.0.borrow_mut();
            state.operations.push(BackendOperation::Attach {
                session_id: session_id.to_string(),
                cols,
                rows,
                raw,
            });
            if state.fail_attach {
                return Err("boom".into());
            }
            state.attached.push(session_id.to_string());
            state.attached_raw.push((session_id.to_string(), raw));
            Ok(())
        }
        fn attach_with_output_generation(
            &mut self,
            session_id: &str,
            cols: u16,
            rows: u16,
            raw: bool,
            _output_generation: u64,
            deferred_resize_authority: Option<crate::winsize_owner::DeferredResizeAuthority>,
        ) -> Result<(), String> {
            self.attach(session_id, cols, rows, raw)?;
            self.0.borrow_mut().attach_deferred_sizes.push((
                session_id.to_string(),
                deferred_resize_authority.map(|_| (cols, rows)),
            ));
            Ok(())
        }
        fn input(&mut self, session_id: &str, bytes: &[u8]) -> Result<(), String> {
            self.0
                .borrow_mut()
                .inputs
                .push((session_id.to_string(), bytes.to_vec()));
            Ok(())
        }
        fn resize(&mut self, session_id: &str, cols: u16, rows: u16) -> Result<(), String> {
            let mut state = self.0.borrow_mut();
            state.operations.push(BackendOperation::Resize {
                session_id: session_id.to_string(),
                cols,
                rows,
            });
            if state.fail_resize {
                return Err("boom".into());
            }
            state.resizes.push((session_id.to_string(), cols, rows));
            Ok(())
        }
        fn scrollback(
            &mut self,
            session_id: &str,
            offset_from_top: u32,
            count: u16,
        ) -> Result<(), String> {
            self.0
                .borrow_mut()
                .scrollbacks
                .push((session_id.to_string(), offset_from_top, count));
            Ok(())
        }
        fn detach(&mut self, session_id: &str) {
            self.0.borrow_mut().detached.push(session_id.to_string());
        }
    }

    fn claims(session: Option<&str>) -> TokenClaims {
        TokenClaims {
            account_id: "acct".into(),
            device_id: "dev_a".into(),
            session_id: session.map(|s| s.into()),
            signal_session_id: None,
            target_device_id: None,
            browser_pubkey: None,
            browser_pubkey_alg: None,
            refresh_parent_sha256: None,
            iat_ms: 0,
            exp_ms: 1_000_000,
        }
    }

    fn setup(
        sessions: &[&str],
        token_session: Option<&str>,
    ) -> (
        Rc<RefCell<FakeState>>,
        TerminalBridge<FakeBackend, SameAsLocalPolicy>,
    ) {
        let state = Rc::new(RefCell::new(FakeState {
            sessions: sessions.iter().map(|s| s.to_string()).collect(),
            ..Default::default()
        }));
        let bridge = TerminalBridge::new(
            FakeBackend(state.clone()),
            SameAsLocalPolicy,
            claims(token_session),
        );
        (state, bridge)
    }

    fn assert_correlated_attach_error(
        replies: &[Outbound],
        expected_code: &str,
        expected_request: &str,
        expected_session: &str,
    ) {
        match replies {
            [Outbound::Json(TerminalReply::Error {
                code,
                request_id,
                session_id,
                ..
            })] => {
                assert_eq!(code, expected_code);
                assert_eq!(request_id.as_deref(), Some(expected_request));
                assert_eq!(session_id.as_deref(), Some(expected_session));
            }
            other => panic!("expected one correlated attach error, got {other:?}"),
        }
    }

    #[test]
    fn default_backend_refuses_viewed_attach_without_dropping_geometry() {
        #[derive(Clone)]
        struct DefaultAttachBackend(Rc<RefCell<usize>>);

        impl SessionBackend for DefaultAttachBackend {
            fn list_sessions(&self) -> Vec<String> {
                vec!["s1".into()]
            }

            fn attach(
                &mut self,
                _session_id: &str,
                _cols: u16,
                _rows: u16,
                _raw: bool,
            ) -> Result<(), String> {
                *self.0.borrow_mut() += 1;
                Ok(())
            }

            fn input(&mut self, _session_id: &str, _bytes: &[u8]) -> Result<(), String> {
                Ok(())
            }

            fn resize(&mut self, _session_id: &str, _cols: u16, _rows: u16) -> Result<(), String> {
                Ok(())
            }

            fn scrollback(
                &mut self,
                _session_id: &str,
                _offset_from_top: u32,
                _count: u16,
            ) -> Result<(), String> {
                Ok(())
            }

            fn detach(&mut self, _session_id: &str) {}
        }

        let attach_calls = Rc::new(RefCell::new(0));
        let mut bridge = TerminalBridge::new(
            DefaultAttachBackend(attach_calls.clone()),
            SameAsLocalPolicy,
            claims(None),
        );
        let private_owner = bridge.winsize_owner.clone();

        let refused = bridge.handle(TerminalMsg::AttachSession {
            request_id: "default-hook".into(),
            session_id: "s1".into(),
            cols: 132,
            rows: 43,
            raw: false,
            viewed: true,
        });

        assert_correlated_attach_error(&refused, "attach_failed", "default-hook", "s1");
        assert_eq!(*attach_calls.borrow(), 0);
        assert_eq!(bridge.attach_count(), 0);
        assert_eq!(bridge.viewed_session(), None);
        assert!(!private_owner
            .lock()
            .unwrap()
            .has_pending_viewed_attach_for_test());
    }

    #[test]
    fn every_attach_rejection_carries_request_and_session_correlation() {
        struct DenyAll;
        impl SessionPolicy for DenyAll {
            fn may_list(&self, _: &str, _: &str) -> bool {
                false
            }
            fn may_attach(&self, _: &str, _: &str, _: &str) -> bool {
                false
            }
        }

        let (_state, mut scoped) = setup(&["s1", "s2"], Some("s1"));
        let scope = scoped.handle(TerminalMsg::AttachSession {
            request_id: "req-scope".into(),
            session_id: "s2".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert_correlated_attach_error(&scope, "session_scope", "req-scope", "s2");

        let denied_state = Rc::new(RefCell::new(FakeState::default()));
        let mut denied = TerminalBridge::new(FakeBackend(denied_state), DenyAll, claims(None));
        let forbidden = denied.handle(TerminalMsg::AttachSession {
            request_id: "req-forbidden".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert_correlated_attach_error(&forbidden, "forbidden", "req-forbidden", "s1");

        let (_state, mut duplicate) = setup(&["s1"], None);
        duplicate.handle(TerminalMsg::AttachSession {
            request_id: "req-first".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        let already = duplicate.handle(TerminalMsg::AttachSession {
            request_id: "req-again".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert_correlated_attach_error(&already, "already_attached", "req-again", "s1");

        let names: Vec<String> = (0..=MAX_ATTACHES).map(|i| format!("s{i}")).collect();
        let refs: Vec<&str> = names.iter().map(String::as_str).collect();
        let (_state, mut full) = setup(&refs, None);
        for i in 0..MAX_ATTACHES {
            full.handle(TerminalMsg::AttachSession {
                request_id: format!("req-{i}"),
                session_id: format!("s{i}"),
                cols: 80,
                rows: 24,
                raw: false,
                viewed: false,
            });
        }
        let capped = full.handle(TerminalMsg::AttachSession {
            request_id: "req-cap".into(),
            session_id: format!("s{MAX_ATTACHES}"),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert_correlated_attach_error(
            &capped,
            "too_many_attaches",
            "req-cap",
            &format!("s{MAX_ATTACHES}"),
        );

        let (failed_state, mut failed) = setup(&["s1"], None);
        failed_state.borrow_mut().fail_attach = true;
        let backend = failed.handle(TerminalMsg::AttachSession {
            request_id: "req-failed".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert_correlated_attach_error(&backend, "attach_failed", "req-failed", "s1");
    }

    #[test]
    fn generic_errors_omit_attach_correlation_fields() {
        let json = serde_json::to_value(TerminalReply::Error {
            code: "not_attached".into(),
            message: "detach without attach".into(),
            request_id: None,
            session_id: None,
        })
        .expect("serialize error");
        assert!(json.get("request_id").is_none());
        assert!(json.get("session_id").is_none());
    }

    #[test]
    fn legacy_attach_omits_encoding_and_keeps_the_legacy_output_target() {
        let (_state, mut bridge) = setup(&["s1"], None);
        let replies = bridge.handle(TerminalMsg::AttachSession {
            request_id: "legacy".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        let Outbound::Json(reply @ TerminalReply::AttachOk { channel, .. }) = &replies[0] else {
            panic!("expected attach_ok");
        };
        assert_eq!(
            bridge.output_target("s1"),
            Some((*channel, TerminalEncoding::Legacy))
        );
        let json = serde_json::to_value(reply).expect("serialize attach_ok");
        assert!(json.get("terminal_encoding").is_none());
    }

    #[test]
    fn invalid_dimensions_are_rejected_before_backend_or_ownership_mutation() {
        for (cols, rows) in [
            (0, 24),
            (80, 0),
            (maestro_extension_api::MAX_TERMINAL_DIMENSION + 1, 24),
            (80, maestro_extension_api::MAX_TERMINAL_DIMENSION + 1),
        ] {
            let (state, mut bridge) = setup(&["s1"], None);
            let replies = bridge.handle(TerminalMsg::AttachSession {
                request_id: "invalid-attach".into(),
                session_id: "s1".into(),
                cols,
                rows,
                raw: false,
                viewed: true,
            });

            assert_correlated_attach_error(&replies, "invalid_dimensions", "invalid-attach", "s1");
            assert!(state.borrow().operations.is_empty());
        }

        let (state, mut bridge) = setup(&["s1"], None);
        assert!(matches!(
            bridge
                .handle(TerminalMsg::AttachSession {
                    request_id: "valid-attach".into(),
                    session_id: "s1".into(),
                    cols: 80,
                    rows: 24,
                    raw: false,
                    viewed: false,
                })
                .as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { .. })]
        ));
        state.borrow_mut().operations.clear();

        for (cols, rows) in [
            (0, 24),
            (80, 0),
            (maestro_extension_api::MAX_TERMINAL_DIMENSION + 1, 24),
            (80, maestro_extension_api::MAX_TERMINAL_DIMENSION + 1),
        ] {
            let replies = bridge.handle(TerminalMsg::Resize {
                session_id: "s1".into(),
                cols,
                rows,
                viewed: true,
            });
            assert!(matches!(
                replies.as_slice(),
                [Outbound::Json(TerminalReply::Error { code, .. })]
                    if code == "invalid_dimensions"
            ));
            assert!(state.borrow().operations.is_empty());
        }
    }

    #[test]
    fn exact_negotiated_attach_confirms_gzip_before_selecting_its_output_target() {
        let (_state, mut bridge) = setup(&["s1"], None);
        bridge = bridge.with_terminal_gzip(true);
        let replies = bridge.handle_with_terminal_encoding(
            TerminalMsg::AttachSession {
                request_id: "gzip".into(),
                session_id: "s1".into(),
                cols: 80,
                rows: 24,
                raw: false,
                viewed: false,
            },
            Some(crate::remote_frame::TERMINAL_GZIP_JSON_V1),
        );
        let Outbound::Json(reply @ TerminalReply::AttachOk { channel, .. }) = &replies[0] else {
            panic!("expected attach_ok");
        };
        assert_eq!(
            bridge.output_target("s1"),
            Some((*channel, TerminalEncoding::GzipJsonV1))
        );
        assert_eq!(
            serde_json::to_value(reply).expect("serialize attach_ok")["terminal_encoding"],
            crate::remote_frame::TERMINAL_GZIP_JSON_V1
        );
    }

    #[test]
    fn detach_and_reattach_never_reuses_the_output_target_generation() {
        let (_state, mut bridge) = setup(&["s1"], None);
        bridge.handle(TerminalMsg::AttachSession {
            request_id: "first".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        let first = bridge
            .exact_output_target("s1")
            .expect("first output target");

        assert!(bridge
            .handle(TerminalMsg::Detach {
                session_id: "s1".into(),
            })
            .is_empty());
        assert_eq!(bridge.output_target("s1"), None);
        bridge.handle(TerminalMsg::AttachSession {
            request_id: "second".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        let second = bridge
            .exact_output_target("s1")
            .expect("second output target");

        assert_ne!(first, second);
        assert_eq!(second.generation, first.generation + 1);
    }

    #[test]
    fn attachment_generation_max_is_unique_and_then_exhausts_without_side_effects() {
        use crate::winsize_owner::WinsizeOwner;

        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let (state, mut bridge) = setup(&["s-max", "s-refused"], None);
        bridge = bridge.with_winsize_owner(owner.clone(), "connection");
        bridge.next_attachment_generation = Some(u64::MAX);

        let max = bridge.handle(TerminalMsg::AttachSession {
            request_id: "max".into(),
            session_id: "s-max".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert!(matches!(
            max.as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { .. })]
        ));
        assert_eq!(
            bridge.exact_output_target("s-max").unwrap().generation,
            u64::MAX
        );
        assert_eq!(bridge.next_attachment_generation, None);

        let refused = bridge.handle(TerminalMsg::AttachSession {
            request_id: "refused".into(),
            session_id: "s-refused".into(),
            cols: 132,
            rows: 43,
            raw: false,
            viewed: true,
        });
        assert_correlated_attach_error(
            &refused,
            "attachment_generation_exhausted",
            "refused",
            "s-refused",
        );
        assert_eq!(state.borrow().attached, vec!["s-max".to_string()]);
        assert_eq!(
            state.borrow().attach_deferred_sizes,
            vec![("s-max".into(), None)]
        );
        assert_eq!(bridge.attach_count(), 1);
        assert!(!owner.lock().unwrap().has_pending_viewed_attach_for_test());
        assert!(owner.lock().unwrap().remote_owned_sessions(0).is_empty());
    }

    #[test]
    fn winsize_authority_max_is_unique_then_exhaustion_refuses_before_backend() {
        use crate::winsize_owner::WinsizeOwner;

        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        {
            let mut state = owner.lock().unwrap();
            state.set_serving(1, 0);
            state.set_next_authority_generation_for_test(Some(u64::MAX));
        }
        let (backend, mut bridge) = setup(&["s-max", "s-refused"], None);
        bridge = bridge.with_winsize_owner(owner.clone(), "connection");

        let max = bridge.handle(TerminalMsg::AttachSession {
            request_id: "max".into(),
            session_id: "s-max".into(),
            cols: 132,
            rows: 43,
            raw: false,
            viewed: true,
        });
        assert!(matches!(
            max.as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { .. })]
        ));
        assert_eq!(
            backend.borrow().attach_deferred_sizes,
            [("s-max".into(), Some((132, 43)))]
        );
        assert!(owner.lock().unwrap().has_pending_viewed_attach_for_test());

        let refused = bridge.handle(TerminalMsg::AttachSession {
            request_id: "refused".into(),
            session_id: "s-refused".into(),
            cols: 100,
            rows: 30,
            raw: false,
            viewed: true,
        });
        assert_correlated_attach_error(
            &refused,
            "winsize_authority_exhausted",
            "refused",
            "s-refused",
        );
        assert_eq!(backend.borrow().attached, ["s-max"]);
        assert_eq!(bridge.attach_count(), 1);
        assert!(
            owner.lock().unwrap().has_pending_viewed_attach_for_test(),
            "exhaustion must not invalidate the last unique pending authority"
        );
    }

    #[test]
    fn channel_wrap_skips_every_live_route_without_overwriting_it() {
        let (_state, mut bridge) = setup(&["s1", "s2", "s3"], None);
        let first = bridge.handle(TerminalMsg::AttachSession {
            request_id: "first".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert!(matches!(
            first.as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { channel: 1, .. })]
        ));

        bridge.next_channel = u16::MAX;
        let last = bridge.handle(TerminalMsg::AttachSession {
            request_id: "last".into(),
            session_id: "s2".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert!(matches!(
            last.as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { channel, .. })] if *channel == u16::MAX
        ));

        let wrapped = bridge.handle(TerminalMsg::AttachSession {
            request_id: "wrapped".into(),
            session_id: "s3".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert!(matches!(
            wrapped.as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { channel: 2, .. })]
        ));
        assert_eq!(bridge.output_target("s1").map(|target| target.0), Some(1));
        assert_eq!(
            bridge.output_target("s2").map(|target| target.0),
            Some(u16::MAX)
        );
        assert_eq!(bridge.output_target("s3").map(|target| target.0), Some(2));
        assert_eq!(bridge.attach_count(), 3);
    }

    #[test]
    fn channel_allocator_exhaustion_is_bounded_and_never_returns_a_live_id() {
        let mut next = 41;
        let mut inspections = 0usize;
        let result = take_available_channel(&mut next, |_candidate| {
            inspections += 1;
            true
        });
        assert_eq!(result, None);
        assert_eq!(inspections, usize::from(u16::MAX));
        assert_eq!(next, 41, "exhaustion leaves the retry cursor stable");
    }

    #[test]
    fn unproved_or_non_exact_encoding_is_rejected_before_the_daemon_is_touched() {
        for (hello_support, requested) in [
            (false, crate::remote_frame::TERMINAL_GZIP_JSON_V1),
            (true, "terminal_gzip_json_v1_extra"),
            (true, ""),
        ] {
            let (state, mut bridge) = setup(&["s1"], None);
            bridge = bridge.with_terminal_gzip(hello_support);
            let replies = bridge.handle_with_terminal_encoding(
                TerminalMsg::AttachSession {
                    request_id: "bad-encoding".into(),
                    session_id: "s1".into(),
                    cols: 80,
                    rows: 24,
                    raw: false,
                    viewed: false,
                },
                Some(requested),
            );
            assert_correlated_attach_error(&replies, "unsupported_encoding", "bad-encoding", "s1");
            assert!(state.borrow().operations.is_empty());
            assert_eq!(bridge.attach_count(), 0);
        }
    }

    #[test]
    fn list_then_attach_then_input_reaches_fake_pty() {
        let (state, mut b) = setup(&["s1", "s2"], None);
        // list
        let r = b.handle(TerminalMsg::SessionList {
            request_id: "q".into(),
        });
        assert_eq!(
            r,
            vec![Outbound::Json(TerminalReply::SessionListResult {
                request_id: "q".into(),
                sessions: vec!["s1".into(), "s2".into()],
                session_metadata: vec![],
                workspace_metadata: None,
            })]
        );
        // attach
        let r = b.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        let channel = match &r[0] {
            Outbound::Json(TerminalReply::AttachOk { channel, .. }) => *channel,
            other => panic!("expected attach_ok, got {other:?}"),
        };
        assert_eq!(state.borrow().attached, vec!["s1"]);
        // input reaches the fake PTY
        let r = b.handle_input(channel, b"ls\n");
        assert!(r.is_empty());
        assert_eq!(
            state.borrow().inputs,
            vec![("s1".to_string(), b"ls\n".to_vec())]
        );
    }

    #[test]
    fn viewed_resize_moves_presence_but_background_geometry_does_not() {
        use crate::winsize_owner::WinsizeOwner;
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0); // a remote is connected
        let (_state, mut b) = setup(&["s1", "s2"], None);
        b = b.with_winsize_owner(owner.clone(), "test-connection");

        // Attach both panes (the browser attaches every visible pane).
        for id in ["s1", "s2"] {
            b.handle(TerminalMsg::AttachSession {
                request_id: "a".into(),
                session_id: id.into(),
                cols: 80,
                rows: 24,
                raw: false,
                viewed: false,
            });
        }
        // No resize yet → no pane is remote-owned (presence needs a VIEWED pane).
        assert!(owner.lock().unwrap().remote_owned_sessions(0).is_empty());

        // Active s1 claims remote presence.
        b.handle(TerminalMsg::Resize {
            session_id: "s1".into(),
            cols: 100,
            rows: 30,
            viewed: true,
        });
        assert_eq!(
            owner.lock().unwrap().remote_owned_sessions(0),
            vec!["s1".to_string()]
        );
        assert_eq!(b.viewed_session(), Some("s1"));

        // Background s2 still gets its exact geometry, but cannot steal presence from active s1.
        b.handle(TerminalMsg::Resize {
            session_id: "s2".into(),
            cols: 90,
            rows: 28,
            viewed: false,
        });
        assert_eq!(
            owner.lock().unwrap().remote_owned_sessions(0),
            vec!["s1".to_string()]
        );
        assert_eq!(b.viewed_session(), Some("s1"));

        // A real focus switch reasserts s2 explicitly and moves presence exactly once.
        b.handle(TerminalMsg::Resize {
            session_id: "s2".into(),
            cols: 90,
            rows: 28,
            viewed: true,
        });
        assert_eq!(
            owner.lock().unwrap().remote_owned_sessions(0),
            vec!["s2".to_string()]
        );
        assert_eq!(b.viewed_session(), Some("s2"));
    }

    #[test]
    fn locally_reclaimed_viewport_ignores_repeated_remote_resize_without_touching_pty() {
        use crate::winsize_owner::WinsizeOwner;
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let (state, mut bridge) = setup(&["s1"], None);
        bridge = bridge.with_winsize_owner(owner.clone(), "test-connection");
        bridge.handle(TerminalMsg::AttachSession {
            request_id: "attach".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        bridge.handle(TerminalMsg::Resize {
            session_id: "s1".into(),
            cols: 100,
            rows: 30,
            viewed: true,
        });
        assert_eq!(state.borrow().resizes.len(), 1);
        assert!(owner.lock().unwrap().reclaim_viewport("s1"));

        let replies = bridge.handle(TerminalMsg::Resize {
            session_id: "s1".into(),
            cols: 140,
            rows: 50,
            viewed: true,
        });

        assert!(replies.is_empty());
        assert_eq!(
            state.borrow().resizes,
            vec![("s1".to_string(), 100, 30)],
            "same-claim remote repeats are acknowledged without mutating the locally owned PTY",
        );
        assert!(owner.lock().unwrap().remote_owned_sessions(0).is_empty());
    }

    #[test]
    fn legacy_resize_defaults_to_viewed_true() {
        let msg = serde_json::from_str::<TerminalMsg>(
            r#"{"type":"resize","session_id":"s1","cols":80,"rows":24}"#,
        )
        .expect("an older resize message must retain active-pane semantics");
        assert!(matches!(msg, TerminalMsg::Resize { viewed: true, .. }));
    }

    #[test]
    fn failed_viewed_resize_does_not_move_presence() {
        use crate::winsize_owner::WinsizeOwner;
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let (state, mut b) = setup(&["s1", "s2"], None);
        b = b.with_winsize_owner(owner.clone(), "test-connection");
        for id in ["s1", "s2"] {
            b.handle(TerminalMsg::AttachSession {
                request_id: id.into(),
                session_id: id.into(),
                cols: 80,
                rows: 24,
                raw: false,
                viewed: false,
            });
        }
        b.handle(TerminalMsg::Resize {
            session_id: "s1".into(),
            cols: 100,
            rows: 30,
            viewed: true,
        });
        state.borrow_mut().fail_resize = true;

        let replies = b.handle(TerminalMsg::Resize {
            session_id: "s2".into(),
            cols: 90,
            rows: 28,
            viewed: true,
        });

        assert!(matches!(
            replies.as_slice(),
            [Outbound::Json(TerminalReply::Error { code, .. })] if code == "resize_failed"
        ));
        assert_eq!(
            owner.lock().unwrap().remote_owned_sessions(0),
            vec!["s1".to_string()]
        );
    }

    #[test]
    fn viewed_structured_attach_waits_for_explicit_resize_before_winsize_ownership() {
        use crate::winsize_owner::{Owner, WinsizeOwner};
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let (state, mut bridge) = setup(&["s-viewed"], None);
        bridge = bridge.with_winsize_owner(owner.clone(), "test-connection");

        let replies = bridge.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s-viewed".into(),
            cols: 132,
            rows: 43,
            raw: false,
            viewed: true,
        });

        assert!(matches!(
            replies.as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { .. })]
        ));
        assert_eq!(
            state.borrow().operations,
            vec![BackendOperation::Attach {
                session_id: "s-viewed".into(),
                cols: 132,
                rows: 43,
                raw: false,
            }],
            "the bridge must not emit an id-only Resize before the Attach baseline"
        );
        assert_eq!(
            state.borrow().attach_deferred_sizes,
            vec![("s-viewed".into(), Some((132, 43)))],
            "viewed structured Attach must capture exact deferred winsize authority"
        );
        assert!(owner.lock().unwrap().remote_owned_sessions(0).is_empty());
        assert_eq!(owner.lock().unwrap().effective(0), Owner::Local);

        assert!(bridge
            .handle(TerminalMsg::Resize {
                session_id: "s-viewed".into(),
                cols: 132,
                rows: 43,
                viewed: true,
            })
            .is_empty());
        assert_eq!(
            owner.lock().unwrap().remote_owned_sessions(0),
            vec!["s-viewed".to_string()]
        );
        assert_eq!(owner.lock().unwrap().effective(0), Owner::Remote);
    }

    #[test]
    fn local_reclaim_during_pending_attach_leaves_no_deferred_resize_authority() {
        use crate::winsize_owner::WinsizeOwner;
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let (state, mut bridge) = setup(&["s-pending"], None);
        bridge = bridge.with_winsize_owner(owner.clone(), "test-connection");

        let replies = bridge.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s-pending".into(),
            cols: 132,
            rows: 43,
            raw: false,
            viewed: true,
        });
        assert!(matches!(
            replies.as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { .. })]
        ));
        assert!(owner.lock().unwrap().reclaim_viewport("s-pending"));
        assert_eq!(
            state.borrow().attach_deferred_sizes,
            vec![("s-pending".into(), Some((132, 43)))],
            "Attach captured the token that the newer local reclaim invalidated"
        );
        assert!(owner.lock().unwrap().remote_owned_sessions(0).is_empty());
    }

    #[test]
    fn first_viewed_resize_consumes_only_the_bridges_connection_creation_lease() {
        use crate::winsize_owner::WinsizeOwner;
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        {
            let mut state = owner.lock().unwrap();
            state.set_serving(2, 0);
            assert!(state.note_remote_creation("bridge-connection", "s-shared", 1_000));
            assert!(state.note_remote_creation("other-connection", "s-shared", 1_000));
        }
        let (_state, mut bridge) = setup(&["s-shared"], None);
        bridge = bridge.with_winsize_owner(owner.clone(), "bridge-connection");

        let replies = bridge.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s-shared".into(),
            cols: 132,
            rows: 43,
            raw: false,
            viewed: true,
        });

        assert!(matches!(
            replies.as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { .. })]
        ));
        assert!(bridge
            .handle(TerminalMsg::Resize {
                session_id: "s-shared".into(),
                cols: 132,
                rows: 43,
                viewed: true,
            })
            .is_empty());
        let mut state = owner.lock().unwrap();
        // Moving this bridge away must still leave the same session protected for the other connection.
        assert!(state.note_remote_viewing("bridge-connection", "s-other"));
        assert_eq!(
            state.remote_owned_sessions(1_001),
            vec!["s-other".to_string(), "s-shared".to_string()]
        );
    }

    #[test]
    fn legacy_attach_without_viewed_is_background_attach_only() {
        use crate::winsize_owner::{Owner, WinsizeOwner};
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let (state, mut bridge) = setup(&["s-background"], None);
        bridge = bridge.with_winsize_owner(owner.clone(), "test-connection");
        let msg = serde_json::from_str::<TerminalMsg>(
            r#"{"type":"attach_session","request_id":"a","session_id":"s-background","cols":80,"rows":24,"raw":false}"#,
        )
        .expect("an older attach message must default viewed to false");

        let replies = bridge.handle(msg);

        assert!(matches!(
            replies.as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { .. })]
        ));
        assert_eq!(
            state.borrow().operations,
            vec![BackendOperation::Attach {
                session_id: "s-background".into(),
                cols: 80,
                rows: 24,
                raw: false,
            }]
        );
        assert_eq!(
            state.borrow().attach_deferred_sizes,
            vec![("s-background".into(), None)],
            "a background attach must not retain a future geometry mutation"
        );
        assert!(owner.lock().unwrap().remote_owned_sessions(0).is_empty());
        assert_eq!(owner.lock().unwrap().effective(0), Owner::Local);
    }

    #[test]
    fn viewed_raw_attach_remains_attach_only() {
        use crate::winsize_owner::WinsizeOwner;
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let (state, mut bridge) = setup(&["s-raw"], None);
        bridge = bridge.with_winsize_owner(owner.clone(), "test-connection");

        let replies = bridge.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s-raw".into(),
            cols: 132,
            rows: 43,
            raw: true,
            viewed: true,
        });

        assert!(matches!(
            replies.as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { .. })]
        ));
        assert_eq!(
            state.borrow().operations,
            vec![BackendOperation::Attach {
                session_id: "s-raw".into(),
                cols: 132,
                rows: 43,
                raw: true,
            }]
        );
        assert_eq!(
            state.borrow().attach_deferred_sizes,
            vec![("s-raw".into(), None)],
            "a raw attach must await an explicit winsize-gated Resize"
        );
        assert!(
            owner.lock().unwrap().remote_owned_sessions(0).is_empty(),
            "raw attach waits for its post-subscription resize before claiming winsize"
        );
        assert_eq!(
            bridge.viewed_session(),
            Some("s-raw"),
            "the explicit viewed signal is immediately authoritative for output priority"
        );
    }

    #[test]
    fn viewed_output_priority_changes_only_after_success_and_clears_on_detach() {
        let (state, mut bridge) = setup(&["s1", "s2"], None);
        for (session_id, viewed) in [("s1", true), ("s2", false)] {
            bridge.handle(TerminalMsg::AttachSession {
                request_id: session_id.into(),
                session_id: session_id.into(),
                cols: 80,
                rows: 24,
                raw: true,
                viewed,
            });
        }
        assert_eq!(bridge.viewed_session(), Some("s1"));

        state.borrow_mut().fail_resize = true;
        bridge.handle(TerminalMsg::Resize {
            session_id: "s2".into(),
            cols: 90,
            rows: 30,
            viewed: true,
        });
        assert_eq!(
            bridge.viewed_session(),
            Some("s1"),
            "a failed viewed mutation cannot promote its pane"
        );

        state.borrow_mut().fail_resize = false;
        bridge.handle(TerminalMsg::Resize {
            session_id: "s2".into(),
            cols: 90,
            rows: 30,
            viewed: true,
        });
        assert_eq!(bridge.viewed_session(), Some("s2"));
        bridge.handle(TerminalMsg::Detach {
            session_id: "s2".into(),
        });
        assert_eq!(bridge.viewed_session(), None);
    }

    #[test]
    fn viewed_structured_attach_never_calls_prebaseline_resize() {
        use crate::winsize_owner::{Owner, WinsizeOwner};
        let owner = std::sync::Arc::new(std::sync::Mutex::new(WinsizeOwner::new()));
        owner.lock().unwrap().set_serving(1, 0);
        let (state, mut bridge) = setup(&["s-failed"], None);
        state.borrow_mut().fail_resize = true;
        bridge = bridge.with_winsize_owner(owner.clone(), "test-connection");

        let replies = bridge.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s-failed".into(),
            cols: 132,
            rows: 43,
            raw: false,
            viewed: true,
        });

        assert!(matches!(
            replies.as_slice(),
            [Outbound::Json(TerminalReply::AttachOk { .. })]
        ));
        assert_eq!(
            state.borrow().operations,
            vec![BackendOperation::Attach {
                session_id: "s-failed".into(),
                cols: 132,
                rows: 43,
                raw: false,
            }]
        );
        assert_eq!(bridge.attach_count(), 1);
        assert!(owner.lock().unwrap().remote_owned_sessions(0).is_empty());
        assert_eq!(owner.lock().unwrap().effective(0), Owner::Local);
        assert!(matches!(
            bridge
                .handle(TerminalMsg::Resize {
                    session_id: "s-failed".into(),
                    cols: 132,
                    rows: 43,
                    viewed: true,
                })
                .as_slice(),
            [Outbound::Json(TerminalReply::Error { code, .. })] if code == "resize_failed"
        ));
        assert!(owner.lock().unwrap().remote_owned_sessions(0).is_empty());
    }

    #[test]
    fn a_failing_backend_attach_yields_attach_failed_not_attach_ok() {
        // HONEST attach (remote-triggered creations): when the backend cannot deliver the attach (e.g. the
        // daemon leg is dead), the browser must get an ERROR reply — never a false attach_ok it would sit
        // on forever waiting for output.
        let (state, mut b) = setup(&["s1"], None);
        state.borrow_mut().fail_attach = true;
        let r = b.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert!(
            matches!(&r[0], Outbound::Json(TerminalReply::Error { code, .. }) if code == "attach_failed"),
            "expected attach_failed error, got {r:?}"
        );
        assert!(
            !r.iter()
                .any(|o| matches!(o, Outbound::Json(TerminalReply::AttachOk { .. }))),
            "a failed attach must not also send attach_ok"
        );
        // no attachment was registered: input on any channel is refused, nothing reaches the backend.
        assert_eq!(b.attach_count(), 0);
        let r = b.handle_input(1, b"ls\n");
        assert!(
            matches!(&r[0], Outbound::Json(TerminalReply::Error { code, .. }) if code == "not_attached")
        );
        assert!(state.borrow().inputs.is_empty());
    }

    #[test]
    fn oversize_terminal_input_is_refused_and_never_reaches_the_backend() {
        let (state, mut b) = setup(&["s1"], None);
        let r = b.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        let channel = match &r[0] {
            Outbound::Json(TerminalReply::AttachOk { channel, .. }) => *channel,
            other => panic!("expected attach_ok, got {other:?}"),
        };

        // exactly at the cap is allowed (boundary)…
        let at_cap = vec![b'x'; MAX_INPUT_PAYLOAD];
        assert!(b.handle_input(channel, &at_cap).is_empty());
        // …one byte over is refused with a content-blind error and is DROPPED before the daemon.
        let over = vec![b'x'; MAX_INPUT_PAYLOAD + 1];
        let r = b.handle_input(channel, &over);
        assert!(
            matches!(&r[0], Outbound::Json(TerminalReply::Error { code, .. }) if code == "input_too_large"),
            "expected input_too_large, got {r:?}"
        );
        // the backend saw ONLY the at-cap input, never the oversize one (no megabytes reach the PTY).
        let inputs = &state.borrow().inputs;
        assert_eq!(inputs.len(), 1, "oversize input must not reach the backend");
        assert_eq!(inputs[0].1.len(), MAX_INPUT_PAYLOAD);
        // the refusal carries no payload bytes (content-blind).
        if let Outbound::Json(TerminalReply::Error { message, .. }) = &r[0] {
            assert!(!message.contains("xxxx"), "error must not echo the payload");
        }
    }

    #[test]
    fn an_input_flood_is_rate_limited_and_excess_never_reaches_the_backend() {
        use crate::input_rate::DEFAULT_CAPACITY;
        let (state, mut b) = setup(&["s1"], None);
        let r = b.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        let channel = match &r[0] {
            Outbound::Json(TerminalReply::AttachOk { channel, .. }) => *channel,
            other => panic!("expected attach_ok, got {other:?}"),
        };

        // blast at-cap (64 KiB) frames at the SAME instant (now_ms=0): only the burst capacity worth get through.
        let frame = vec![b'x'; MAX_INPUT_PAYLOAD];
        let mut accepted = 0usize;
        let mut limited = 0usize;
        for _ in 0..64 {
            let out = b.handle_input_at(channel, &frame, 0);
            if out.is_empty() {
                accepted += 1;
            } else if matches!(&out[0], Outbound::Json(TerminalReply::Error { code, .. }) if code == "input_rate_limited")
            {
                limited += 1;
            } else {
                panic!("unexpected reply {out:?}");
            }
        }
        let expect_accepted = (DEFAULT_CAPACITY as usize) / MAX_INPUT_PAYLOAD; // 1 MiB / 64 KiB = 16
        assert_eq!(
            accepted, expect_accepted,
            "only the burst budget is accepted instantaneously"
        );
        assert_eq!(limited, 64 - expect_accepted, "the rest is rate-limited");
        // the backend received ONLY the accepted frames — the throttled flood never reached the daemon.
        assert_eq!(state.borrow().inputs.len(), expect_accepted);

        // after time passes, the bucket refills and input flows again (legitimate sustained typing isn't broken).
        assert!(b.handle_input_at(channel, b"ls\n", 1000).is_empty());
        assert_eq!(state.borrow().inputs.len(), expect_accepted + 1);
    }

    #[test]
    fn fake_output_reaches_client_as_binary_frame() {
        let (_s, mut b) = setup(&["s1"], None);
        b.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        let daemon_frame = br#"{"op":"grid","id":"s1"}"#;
        let out = b
            .output_frame("s1", daemon_frame)
            .expect("attached → frame");
        match out {
            Outbound::Binary(bytes) => {
                let f = crate::remote_frame::decode(&bytes).unwrap();
                assert_eq!(f.kind, FrameKind::TerminalOutput);
                assert_eq!(f.payload, daemon_frame);
            }
            other => panic!("expected binary, got {other:?}"),
        }
        // un-attached session → no frame
        assert!(b.output_frame("s2", daemon_frame).is_none());
    }

    #[test]
    fn resize_reaches_session() {
        let (state, mut b) = setup(&["s1"], None);
        b.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        b.handle(TerminalMsg::Resize {
            session_id: "s1".into(),
            cols: 120,
            rows: 40,
            viewed: true,
        });
        assert_eq!(state.borrow().resizes, vec![("s1".to_string(), 120, 40)]);
    }

    #[test]
    fn attach_raw_flag_reaches_the_backend() {
        // raw:true ⇒ backend attaches in raw mode (want_raw_output:true → xterm.js); default false ⇒ grid.
        let (state, mut b) = setup(&["s1", "s2"], None);
        b.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: true,
            viewed: false,
        });
        b.handle(TerminalMsg::AttachSession {
            request_id: "b".into(),
            session_id: "s2".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert_eq!(
            state.borrow().attached_raw,
            vec![("s1".to_string(), true), ("s2".to_string(), false)]
        );
    }

    #[test]
    fn scrollback_reaches_session_after_attach() {
        let (state, mut b) = setup(&["s1"], None);
        b.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        let out = b.handle(TerminalMsg::Scrollback {
            session_id: "s1".into(),
            offset_from_top: 100,
            count: 24,
        });
        assert!(
            out.is_empty(),
            "scrollback request emits no JSON reply (rows come back as terminal_output)"
        );
        assert_eq!(
            state.borrow().scrollbacks,
            vec![("s1".to_string(), 100, 24)]
        );
    }

    #[test]
    fn scrollback_before_attach_is_refused() {
        let (state, mut b) = setup(&["s1"], None);
        let out = b.handle(TerminalMsg::Scrollback {
            session_id: "s1".into(),
            offset_from_top: 10,
            count: 5,
        });
        assert!(
            matches!(out.as_slice(), [Outbound::Json(TerminalReply::Error { code, .. })] if code == "not_attached")
        );
        assert!(
            state.borrow().scrollbacks.is_empty(),
            "no daemon call before attach"
        );
    }

    #[test]
    fn session_scoped_token_only_attaches_its_session_and_lists_only_it() {
        let (state, mut b) = setup(&["s1", "s2"], Some("s1"));
        // list shows only the bound session
        let r = b.handle(TerminalMsg::SessionList {
            request_id: "q".into(),
        });
        assert_eq!(
            r,
            vec![Outbound::Json(TerminalReply::SessionListResult {
                request_id: "q".into(),
                sessions: vec!["s1".into()],
                session_metadata: vec![],
                workspace_metadata: None,
            })]
        );
        // attach to the bound one ok
        assert!(matches!(
            b.handle(TerminalMsg::AttachSession {
                request_id: "a".into(),
                session_id: "s1".into(),
                cols: 80,
                rows: 24,
                raw: false,
                viewed: false
            })[0],
            Outbound::Json(TerminalReply::AttachOk { .. })
        ));
        // attach to another → refused (session_scope)
        let r = b.handle(TerminalMsg::AttachSession {
            request_id: "b".into(),
            session_id: "s2".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert!(
            matches!(&r[0], Outbound::Json(TerminalReply::Error { code, .. }) if code == "session_scope")
        );
        // HARDENING: the scope denial must happen BEFORE any backend interaction — the daemon was never asked
        // to attach s2 (no resource use, no timing/state oracle for an out-of-scope session). Only s1 reached it.
        assert_eq!(
            state.borrow().attached,
            vec!["s1"],
            "out-of-scope s2 must NOT reach the backend"
        );
        assert_eq!(b.attach_count(), 1, "only the bound session is attached");
    }

    #[test]
    fn session_metadata_is_filtered_to_visible_sessions() {
        let (state, mut b) = setup(&["s1", "s2"], Some("s1"));
        state.borrow_mut().metadata = vec![
            SessionMetadata {
                id: "s1".into(),
                cwd: Some("/Users/test/api".into()),
            },
            SessionMetadata {
                id: "s2".into(),
                cwd: Some("/Users/test/secret".into()),
            },
        ];

        let r = b.handle(TerminalMsg::SessionList {
            request_id: "q".into(),
        });

        assert_eq!(
            r,
            vec![Outbound::Json(TerminalReply::SessionListResult {
                request_id: "q".into(),
                sessions: vec!["s1".into()],
                session_metadata: vec![SessionMetadata {
                    id: "s1".into(),
                    cwd: Some("/Users/test/api".into())
                }],
                workspace_metadata: None,
            })]
        );
    }

    #[test]
    fn workspace_metadata_redacts_hidden_sessions_but_keeps_the_open_project() {
        let (state, mut b) = setup(&["s1", "s2"], Some("s1"));
        state.borrow_mut().workspace_metadata = Some(WorkspaceMetadata {
            projects: vec![WorkspaceProjectMetadata {
                id: "proj".into(),
                name: "Project".into(),
                root: "/Users/test/project".into(),
                icon: Some("◆".into()),
                accent_color: Some("#34d399".into()),
                selected: true,
                system: false,
                hidden: false,
                launch_defaults: None,
                directories: vec![],
                windows: vec![WorkspaceWindowMetadata {
                    id: "win".into(),
                    name: Some("Main".into()),
                    focused: true,
                    stashed: false,
                    panes: vec![
                        WorkspacePaneMetadata {
                            id: "pane-1".into(),
                            session_id: "s1".into(),
                            name: Some("Visible".into()),
                            stashed: false,
                            cwd: Some("/Users/test/project".into()),
                        },
                        WorkspacePaneMetadata {
                            id: "pane-2".into(),
                            session_id: "s2".into(),
                            name: Some("Hidden".into()),
                            stashed: false,
                            cwd: Some("/Users/test/project".into()),
                        },
                    ],
                }],
            }],
        });

        let r = b.handle(TerminalMsg::SessionList {
            request_id: "q".into(),
        });

        assert_eq!(
            r,
            vec![Outbound::Json(TerminalReply::SessionListResult {
                request_id: "q".into(),
                sessions: vec!["s1".into()],
                session_metadata: vec![],
                workspace_metadata: Some(WorkspaceMetadata {
                    projects: vec![WorkspaceProjectMetadata {
                        id: "proj".into(),
                        name: "Project".into(),
                        root: "/Users/test/project".into(),
                        icon: Some("◆".into()),
                        accent_color: Some("#34d399".into()),
                        selected: true,
                        system: false,
                        hidden: false,
                        launch_defaults: None,
                        directories: vec![],
                        windows: vec![WorkspaceWindowMetadata {
                            id: "win".into(),
                            name: Some("Main".into()),
                            focused: true,
                            stashed: false,
                            panes: vec![
                                // visible pane kept as-is
                                WorkspacePaneMetadata {
                                    id: "pane-1".into(),
                                    session_id: "s1".into(),
                                    name: Some("Visible".into()),
                                    stashed: false,
                                    cwd: Some("/Users/test/project".into()),
                                },
                                // hidden session REDACTED (empty session_id) but the pane is kept so the open
                                // project/window still appears in the browser (idle, non-attachable). The cwd is
                                // preserved through redaction (`..pane`) — it's a folder path, not attachable state.
                                WorkspacePaneMetadata {
                                    id: "pane-2".into(),
                                    session_id: String::new(),
                                    name: Some("Hidden".into()),
                                    stashed: false,
                                    cwd: Some("/Users/test/project".into()),
                                },
                            ],
                        }],
                    }],
                }),
            })]
        );
    }

    /// SECURITY INVARIANT (non-negotiable): the live-sync PUSH payload must be byte-identical to what a session_list
    /// REPLY would carry for the same connection — same redaction, same shape. If these ever diverge, the push could
    /// leak a hidden/stale session the reply wouldn't. Guards the factored `current_workspace_reply_metadata()`.
    #[test]
    fn push_metadata_is_byte_identical_to_the_session_list_reply() {
        let (state, mut b) = setup(&["s1", "s2"], Some("s1"));
        state.borrow_mut().workspace_metadata = Some(WorkspaceMetadata {
            projects: vec![WorkspaceProjectMetadata {
                id: "proj".into(),
                name: "Project".into(),
                root: "/Users/test/project".into(),
                icon: None,
                accent_color: None,
                selected: true,
                system: false,
                hidden: false,
                launch_defaults: None,
                directories: vec![],
                windows: vec![WorkspaceWindowMetadata {
                    id: "win".into(),
                    name: Some("Main".into()),
                    focused: true,
                    stashed: false,
                    panes: vec![
                        WorkspacePaneMetadata {
                            id: "pane-1".into(),
                            session_id: "s1".into(),
                            name: Some("Visible".into()),
                            stashed: false,
                            cwd: None,
                        },
                        WorkspacePaneMetadata {
                            id: "pane-2".into(),
                            session_id: "s2".into(),
                            name: Some("Hidden".into()),
                            stashed: false,
                            cwd: None,
                        },
                    ],
                }],
            }],
        });

        // The reply path.
        let reply = b.handle(TerminalMsg::SessionList {
            request_id: "q".into(),
        });
        let (reply_sessions, reply_session_meta, reply_meta) = match &reply[0] {
            Outbound::Json(TerminalReply::SessionListResult {
                sessions,
                session_metadata,
                workspace_metadata,
                ..
            }) => (
                sessions.clone(),
                session_metadata.clone(),
                workspace_metadata.clone(),
            ),
            other => panic!("expected SessionListResult, got {other:?}"),
        };
        // The push path (factored helper). Allowed connection → Some(triple); the triple IS the reply's
        // (sessions, session_metadata, workspace_metadata) — the push must be SELF-SUFFICIENT (a pane
        // created on the desktop is attachable from the pushed state alone) with redaction parity.
        let payload = b.workspace_push_payload();
        assert!(
            payload.is_some(),
            "an allowed connection must be pushable (Some), not forbidden (None)"
        );
        let (push_sessions, push_session_meta, push_meta) = payload.unwrap();

        // Byte-identical after deterministic serialization — the security guarantee, now for all three.
        assert_eq!(
            serde_json::to_string(&(&push_sessions, &push_session_meta, &push_meta)).unwrap(),
            serde_json::to_string(&(&reply_sessions, &reply_session_meta, &reply_meta)).unwrap(),
            "push payload must equal the session_list reply triple (redaction parity)"
        );
        // And it's non-empty (the hidden session redacted, the project kept) — not trivially equal via both-None.
        assert!(
            push_meta.is_some(),
            "push metadata should be present for an allowed connection"
        );
    }

    /// The forbidden-vs-empty distinction (Codex): a connection NOT allowed to list must yield `None` (never push),
    /// distinct from an allowed connection with no workspace (`Some(None)` — push an omitted-metadata update).
    #[test]
    fn workspace_push_payload_distinguishes_forbidden_from_empty() {
        // Allowed connection, backend reports NO workspace → Some(None): pushable, metadata omitted.
        let (_s, b_allowed) = setup(&["s1"], Some("s1"));
        let payload = b_allowed.workspace_push_payload();
        assert!(
            payload.is_some(),
            "allowed + no workspace → pushable (metadata omitted)"
        );
        let (sessions, _session_meta, meta) = payload.unwrap();
        assert_eq!(meta, None, "no workspace → omitted metadata in the push");
        assert!(
            !sessions.is_empty(),
            "the push still carries the live session list"
        );
    }

    #[test]
    fn attach_cap_is_enforced() {
        let names: Vec<String> = (0..MAX_ATTACHES + 1).map(|i| format!("s{i}")).collect();
        let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
        let (_s, mut b) = setup(&refs, None);
        for i in 0..MAX_ATTACHES {
            let r = b.handle(TerminalMsg::AttachSession {
                request_id: "a".into(),
                session_id: format!("s{i}"),
                cols: 80,
                rows: 24,
                raw: false,
                viewed: false,
            });
            assert!(matches!(
                r[0],
                Outbound::Json(TerminalReply::AttachOk { .. })
            ));
        }
        assert_eq!(b.attach_count(), MAX_ATTACHES);
        let r = b.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: format!("s{MAX_ATTACHES}"),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        assert!(
            matches!(&r[0], Outbound::Json(TerminalReply::Error { code, .. }) if code == "too_many_attaches")
        );
    }

    #[test]
    fn detach_cleans_up_one_attach_independently() {
        let (state, mut b) = setup(&["s1", "s2"], None);
        b.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        b.handle(TerminalMsg::AttachSession {
            request_id: "b".into(),
            session_id: "s2".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        b.handle(TerminalMsg::Detach {
            session_id: "s1".into(),
        });
        assert_eq!(state.borrow().detached, vec!["s1"]);
        assert_eq!(b.attach_count(), 1); // s2 still attached
                                         // input still works for s2; s1's channel is gone
        let r = b.handle(TerminalMsg::Resize {
            session_id: "s1".into(),
            cols: 1,
            rows: 1,
            viewed: true,
        });
        assert!(
            matches!(&r[0], Outbound::Json(TerminalReply::Error { code, .. }) if code == "not_attached")
        );
    }

    #[test]
    fn revoke_closes_all_live_attaches_and_refuses_further() {
        let (state, mut b) = setup(&["s1", "s2"], None);
        b.handle(TerminalMsg::AttachSession {
            request_id: "a".into(),
            session_id: "s1".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        b.handle(TerminalMsg::AttachSession {
            request_id: "b".into(),
            session_id: "s2".into(),
            cols: 80,
            rows: 24,
            raw: false,
            viewed: false,
        });
        b.revoke();
        // all detached
        let mut detached = state.borrow().detached.clone();
        detached.sort();
        assert_eq!(detached, vec!["s1", "s2"]);
        assert_eq!(
            state.borrow().sessions,
            vec!["s1", "s2"],
            "revocation releases only this remote attachment; retained daemon PTYs stay live",
        );
        assert_eq!(b.attach_count(), 0);
        assert!(b.is_revoked());
        // further terminal ops refused
        assert!(
            matches!(&b.handle(TerminalMsg::SessionList { request_id: "q".into() })[0], Outbound::Json(TerminalReply::Error { code, .. }) if code == "revoked")
        );
        assert!(
            matches!(&b.handle_input(1, b"x")[0], Outbound::Json(TerminalReply::Error { code, .. }) if code == "revoked")
        );
    }

    #[test]
    fn input_for_unknown_channel_refused() {
        let (_s, mut b) = setup(&["s1"], None);
        let r = b.handle_input(999, b"x");
        assert!(
            matches!(&r[0], Outbound::Json(TerminalReply::Error { code, .. }) if code == "not_attached")
        );
    }

    #[test]
    fn drop_detaches_everything() {
        let state = Rc::new(RefCell::new(FakeState {
            sessions: vec!["s1".into()],
            ..Default::default()
        }));
        {
            let mut b =
                TerminalBridge::new(FakeBackend(state.clone()), SameAsLocalPolicy, claims(None));
            b.handle(TerminalMsg::AttachSession {
                request_id: "a".into(),
                session_id: "s1".into(),
                cols: 80,
                rows: 24,
                raw: false,
                viewed: false,
            });
        } // dropped here
        assert_eq!(state.borrow().detached, vec!["s1"]);
        assert_eq!(
            state.borrow().sessions,
            vec!["s1"],
            "transport teardown must detach, never kill the retained local PTY",
        );
    }
}
