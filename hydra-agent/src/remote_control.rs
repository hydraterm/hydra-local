//! S3b — CONTROL-ONLY DataChannel protocol + the agent-side channel state machine.
//!
//! This carries NO terminal data: no PTY bytes, no keystrokes, no terminal output, no files. The message
//! set is a CLOSED allowlist; anything else (unknown type, or a field that looks like terminal data) is
//! rejected. The agent side enforces the auth boundary: a channel is UNAUTHENTICATED until a valid Hydra
//! token is accepted (`auth` → `auth_ok`); privileged messages (`list_request`) are refused until then —
//! "connected over WebRTC is NOT authorization". A revoke flips the channel back to refusing.
//!
//! Pure + transport-agnostic: `ControlChannel::handle(line)` takes one inbound message and returns the
//! reply (or None). The WebRTC wiring (separate module) just pumps bytes in/out of this.

use crate::remote_token::{verify_token, TokenClaims, TokenError};
use ed25519_dalek::VerifyingKey;
use maestro_local_services::agent_history::normalize_provider_session_id;
#[cfg(not(test))]
use maestro_shell::desktop_access;
use maestro_shell::desktop_access::{DesktopAccessStatus, FULL_DISK_ACCESS_REQUIRED_CODE};
use sha2::{Digest, Sha256};
use std::collections::VecDeque;
use std::path::{Path, PathBuf};

pub const PROTOCOL_VERSION: u32 = 1;
pub const CAPABILITY_VIEWED_RESIZE_V1: &str = "viewed_resize_v1";
pub const CAPABILITY_TERMINAL_GZIP_JSON_V1: &str = crate::remote_frame::TERMINAL_GZIP_JSON_V1;
pub const CAPABILITY_CREATION_REPLAY_V1: &str = "creation_request_replay_v1";
pub const CAPABILITY_DESKTOP_ACCESS_STATUS_V1: &str = "desktop_access_status_v1";
pub const CAPABILITY_AUTHORIZATION_REFRESH_V1: &str = "authorization_refresh_v1";
const MAX_MSG_BYTES: usize = 8 * 1024;
const MAX_CAPABILITIES: usize = 16;
const MAX_CAPABILITY_BYTES: usize = 64;
const MAX_CREATION_REQUEST_ID_BYTES: usize = 128;
const CREATION_REPLAY_MAX_ENTRIES: usize = 64;
const CREATION_REPLAY_TTL_MS: u64 = 120_000;
const FULL_DISK_ACCESS_REQUIRED_MESSAGE: &str =
    "Full Disk Access is required on the desktop before using this folder";
const RECORDLESS_CREATION_HELD_CODE: &str = "recordless_creation_held";
const RECORDLESS_CREATION_HELD_MESSAGE: &str =
    "record-less remote session creation is held in this release";
const INVALID_PROVIDER_SESSION_ID_CODE: &str = "invalid_session_id";
const INVALID_PROVIDER_SESSION_ID_MESSAGE: &str = "provider session id is invalid";

trait DesktopAccessPolicy: Send {
    fn current_status(&self) -> DesktopAccessStatus;
    fn path_requires_full_disk_access(&self, path: &Path) -> bool;
}

#[cfg(not(test))]
struct SystemDesktopAccessPolicy;

#[cfg(not(test))]
impl DesktopAccessPolicy for SystemDesktopAccessPolicy {
    fn current_status(&self) -> DesktopAccessStatus {
        desktop_access::current_status()
    }

    fn path_requires_full_disk_access(&self, path: &Path) -> bool {
        desktop_access::path_requires_full_disk_access(path)
    }
}

#[cfg(test)]
struct UnitTestDesktopAccessPolicy;

#[cfg(test)]
impl DesktopAccessPolicy for UnitTestDesktopAccessPolicy {
    fn current_status(&self) -> DesktopAccessStatus {
        DesktopAccessStatus::NotApplicable
    }

    fn path_requires_full_disk_access(&self, _path: &Path) -> bool {
        false
    }
}

fn default_desktop_access_policy() -> Box<dyn DesktopAccessPolicy> {
    #[cfg(test)]
    {
        Box::new(UnitTestDesktopAccessPolicy)
    }
    #[cfg(not(test))]
    {
        Box::new(SystemDesktopAccessPolicy)
    }
}

fn public_agent_build_git(value: &str) -> Option<String> {
    ((7..=40).contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)))
    .then(|| value.to_string())
}

/// Field names that must NEVER appear in a control message (terminal/secret-shaped). Mirrors the cloud
/// content-blind guard — a control channel has no business carrying these.
const FORBIDDEN_FIELDS: &[&str] = &[
    "pty",
    "stdout",
    "stderr",
    "scrollback",
    "keystroke",
    "keystrokes",
    "command",
    "cmd",
    "args",
    "env",
    "data",
    "bytes",
    "file",
    "grid",
    "damage",
    "output",
    "private_key",
    "privatekey",
    "privkey",
];

/// Inbound control messages the agent accepts (CLOSED set — there is no byte-stream message type).
#[derive(Debug, serde::Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum InboundMsg {
    Hello {
        protocol_version: u32,
        device_id: String,
        role: String,
        #[serde(default)]
        capabilities: Vec<String>,
    },
    Auth {
        token: String,
        /// Optional browser-minted correlation id for the connection trace (conn-trace.jsonl). Defaults empty when
        /// an older client doesn't send it; the agent still traces, just uncorrelated.
        #[serde(default)]
        trace_id: String,
    },
    /// Same-DataChannel successor authorization. It is never valid as initial auth: the signed successor must
    /// hash-link to this channel's exact current token and preserve every immutable binding.
    AuthRefresh {
        token: String,
    },
    Ping {
        nonce: String,
    },
    /// Privileged placeholder — proves the auth gate. Returns an EMPTY stub in S3b (no real session data).
    ListRequest {
        request_id: String,
    },
    /// Browser asks the agent to create a new local terminal session on demand. Still NO command/argv/env;
    /// optional launch metadata lets the browser match desktop project context.
    CreateSession {
        request_id: String,
        #[serde(default)]
        label: Option<String>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        agent: Option<String>,
        #[serde(default)]
        launch_flags: Option<serde_json::Value>,
        /// Optional exact initial viewport geometry. Only a complete, non-zero pair is honored;
        /// older browsers and missing/unpaired/zero requests keep the legacy 80×24 launch.
        #[serde(default)]
        cols: Option<u16>,
        #[serde(default)]
        rows: Option<u16>,
    },
    /// Gap-doc Step 2 (session picker): browser asks for the PRIOR agent sessions for an (agent, cwd) — mirrors
    /// the desktop `agent:listSessions`. Reply is METADATA ONLY (no conversation text) to stay content-blind;
    /// a session PREVIEW (which carries message content) is a separate, explicit op to be added later.
    ListAgentSessions {
        request_id: String,
        agent: String,
        #[serde(default)]
        cwd: Option<String>,
        /// When true, list the REMOVED (hidden) sessions for this folder+agent instead of the visible ones — powers
        /// the browser "Removed sessions" section (parity with the local dashboard's hidden-session view). The reply
        /// still comes back as AgentSessionsResult; the browser keys it by the request_id it sent.
        #[serde(default)]
        include_hidden: bool,
    },
    /// New-project "Choose working directory…" (screens/local/newproject.jpg): the local app opens a NATIVE folder
    /// dialog (rfd::FileDialog on the desktop) — which a REMOTE browser can't use (it would pop on the desktop, not
    /// the browser device). Browser-safe equivalent: the browser asks the desktop to LIST the subdirectories of
    /// `path` (None → the desktop home dir) so the user can navigate + pick a folder. Content-blind: folder
    /// names/paths only — never file contents, never listed as a session/transcript.
    ListDirectories {
        request_id: String,
        #[serde(default)]
        path: Option<String>,
    },
    /// Gap-doc Step 2 (session picker — PREVIEW): browser asks for the first `max_lines` of a prior agent
    /// session's transcript (the SessionPicker's 👁 preview) — mirrors the desktop `agent:previewSession`.
    /// DELIBERATE content exception: unlike list_agent_sessions (metadata only), this reply carries conversation
    /// text by design, so it is a SEPARATE explicit op, auth-gated, returning role+text lines (the gap doc's
    /// SessionPreviewLine). Still no PTY/keystroke/command on the wire — only the prior transcript text the user
    /// asked to preview.
    PreviewAgentSession {
        request_id: String,
        agent: String,
        #[serde(default)]
        cwd: Option<String>,
        session_id: String,
        #[serde(default)]
        max_lines: Option<usize>,
    },
    /// Gap-doc §4.4 (SessionPicker manage): browser asks the desktop to RENAME / HIDE (trash) / DELETE a prior
    /// agent session — mirrors the desktop `set_folder_session_name` / `hide_folder_session` /
    /// `delete_folder_session`. `action` ∈ rename|hide|delete; `name` carries the new label for rename (empty =
    /// clear); `cwd` is required for delete (resolves the file from the folder listing). Content-blind (ids/label
    /// only; never transcript). Desktop-authoritative — the browser re-lists after.
    ManageAgentSession {
        request_id: String,
        action: String,
        agent: String,
        session_id: String,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        name: Option<String>,
    },
    /// Gap-doc Step 3 (real split): browser asks the desktop to create a NEW pane by splitting `from_pane_id`
    /// in `window_id`, in `dir` (right|down). The desktop generates the tab/session ids, creates the session,
    /// and persists the pane under the project/window via WindowLayoutService::split_tab — so the split is
    /// DESKTOP-AUTHORITATIVE (mirrors back through workspace metadata), not a browser-local empty pane.
    /// Launch context (agent/launch_flags) is resolved on the desktop; still NO command/argv/env on the wire.
    SplitPane {
        request_id: String,
        window_id: String,
        from_pane_id: String,
        dir: String, // "right" (h) | "down" (v)
        #[serde(default)]
        agent: Option<String>,
        #[serde(default)]
        launch_flags: Option<serde_json::Value>,
        /// Optional working directory for the NEW pane. Absent → inherit the split source pane's cwd
        /// (the local-desktop split contract). A path, not terminal content — same posture as
        /// `create_session.cwd` / `new_window.cwd`.
        #[serde(default)]
        cwd: Option<String>,
        /// Optional display name for the NEW pane (the split dialog's "Pane name"). Metadata only (a
        /// TabRecord title, like `rename`'s name) — never a command and never terminal content.
        #[serde(default)]
        pane_name: Option<String>,
        #[serde(default)]
        cols: Option<u16>,
        #[serde(default)]
        rows: Option<u16>,
    },
    /// Remote single-pane create: browser asks the desktop to create a NEW pane record/session under
    /// `window_id` but WITHOUT changing the desktop window's split geometry. The source pane supplies
    /// inherited cwd/launch context. Remote owns visual layout; desktop owns existence.
    NewPane {
        request_id: String,
        window_id: String,
        from_pane_id: String,
        #[serde(default)]
        agent: Option<String>,
        #[serde(default)]
        launch_flags: Option<serde_json::Value>,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        pane_name: Option<String>,
        #[serde(default)]
        cols: Option<u16>,
        #[serde(default)]
        rows: Option<u16>,
    },
    /// Gap-doc Step 3b (revive a stashed pane): browser asks the desktop to bring `pane_id` (a stashed tab) in
    /// `window_id` back live — mirrors the desktop `WindowLayoutService::revive_pane`. Desktop-authoritative
    /// (reflects back via workspace metadata). No command/argv/env on the wire.
    RevivePane {
        request_id: String,
        window_id: String,
        pane_id: String,
        #[serde(default)]
        cols: Option<u16>,
        #[serde(default)]
        rows: Option<u16>,
    },
    /// Virtual remote viewport: start the durable session behind `pane_id` in the daemon so the browser can attach
    /// it, without mutating the desktop window layout/stash state.
    StartPaneSession {
        request_id: String,
        window_id: String,
        pane_id: String,
        #[serde(default)]
        cols: Option<u16>,
        #[serde(default)]
        rows: Option<u16>,
    },
    /// Gap-doc pane management (Close/stash — inverse of revive): browser asks the desktop to STASH a live pane
    /// `pane_id` in `window_id` (the desktop's Pane "Close(stash)") — mirrors `WindowLayoutService::stash_pane`.
    /// Desktop-authoritative (reflects via workspace metadata; the pane becomes a stashed row, revivable). No
    /// command/argv/env on the wire.
    StashPane {
        request_id: String,
        window_id: String,
        pane_id: String,
    },
    /// Gap-doc pane management (Remove from shelf): browser asks the desktop to REMOVE a pane record `pane_id` in
    /// `window_id` from the shelf/layout — mirrors `WindowLayoutService::close_pane`, which drops only the
    /// layout/shelf record and does NOT kill the daemon session. Desktop-authoritative (reflects via workspace
    /// metadata; the pane row disappears). No command/argv/env on the wire.
    RemovePane {
        request_id: String,
        window_id: String,
        pane_id: String,
    },
    /// Gap-doc pane/window management (Rename): browser asks the desktop to rename a PANE (`pane_id` set) or a
    /// WINDOW (`pane_id` omitted) in `window_id` — mirrors `WindowLayoutService::rename_tab` / `rename_window`.
    /// (Project rename is already covered by `project_update`'s name field.) Desktop-authoritative (reflects via
    /// workspace metadata). No command/argv/env on the wire.
    Rename {
        request_id: String,
        window_id: String,
        #[serde(default)]
        pane_id: Option<String>,
        name: String,
    },
    /// Browser window-tab click: focus/switch the REAL desktop window identified by `window_id`. This is a
    /// runtime focus intent, not a browser-local selection and not a LAN bridge. The eventual desktop-backed
    /// impl must call into the same live runtime path as `maestro-app`'s React `focusWindow` intent.
    FocusWindow {
        request_id: String,
        window_id: String,
    },
    /// Gap-doc window management (Close/Remove window): browser asks the desktop to CLOSE/remove `window_id` —
    /// mirrors `WindowLayoutService::delete` (the Window menu's "Remove from shelf"). DESTRUCTIVE: the desktop
    /// tears down the window's layout + its panes' sessions. Desktop-authoritative (reflects via workspace
    /// metadata). No command/argv/env on the wire.
    CloseWindow {
        request_id: String,
        window_id: String,
    },
    /// Gap-doc Step 4 (new window): browser asks the desktop to open a NEW named window under `project_id` with
    /// a first pane — mirrors the desktop createWindow path (write project/window records, create_empty layout,
    /// open_tab the first session). Desktop-authoritative (reflects via workspace metadata). Launch context
    /// (cwd/agent/launch_flags) resolved on the desktop; NO command/argv/env on the wire.
    NewWindow {
        request_id: String,
        project_id: String,
        name: String,
        #[serde(default)]
        cwd: Option<String>,
        #[serde(default)]
        agent: Option<String>,
        #[serde(default)]
        launch_flags: Option<serde_json::Value>,
        #[serde(default)]
        cols: Option<u16>,
        #[serde(default)]
        rows: Option<u16>,
    },
    /// Gap-doc Step 5 (project create): browser asks the desktop to create a new project — mirrors the desktop
    /// `ProjectService::create(name, root, NewProject{icon, accent_color, default agent})`. Desktop-authoritative.
    /// `root` is a directory path (sanitized on the desktop); NO command/argv/env on the wire.
    ProjectCreate {
        request_id: String,
        name: String,
        root: String,
        #[serde(default)]
        icon: Option<String>,
        #[serde(default)]
        accent_color: Option<String>,
        #[serde(default)]
        agent: Option<String>,
        #[serde(default)]
        resume_mode: Option<String>,
        /// New Project resume TARGET (dialog-parity item 5): the prior session the seeded first pane should
        /// resume (paired with resume_mode "resume"). An opaque provider session id — the desktop resolves
        /// any file path locally (Gemini); nothing but the id crosses the wire.
        #[serde(default)]
        resume_session_id: Option<String>,
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        dangerous: Option<bool>,
        /// A project DEFAULT custom launch command (ProjectForm's custom_command). This is persisted PROJECT
        /// CONFIG, NOT a live command executed from the wire — the desktop still resolves/launches server-side;
        /// the browser never drives argv/env. Stored into the project's launch_defaults. Empty string = clear.
        #[serde(default)]
        custom_command: Option<String>,
        /// The project's pinned extra DIRECTORIES (ProjectForm directories). None = unchanged; Some([]) = clear
        /// all; Some(list) = replace. Each is a {name, path} pair (ids minted on the desktop). Path strings only.
        #[serde(default)]
        directories: Option<Vec<ProjectDirectoryWire>>,
        #[serde(default)]
        cols: Option<u16>,
        #[serde(default)]
        rows: Option<u16>,
    },
    /// Gap-doc Step 5 (project edit): browser asks the desktop to update an existing project's editable fields
    /// (name/root/icon/accent/default agent) — mirrors `ProjectService::update`. Only present fields change.
    ProjectUpdate {
        request_id: String,
        project_id: String,
        #[serde(default)]
        name: Option<String>,
        #[serde(default)]
        root: Option<String>,
        #[serde(default)]
        icon: Option<String>,
        #[serde(default)]
        accent_color: Option<String>,
        #[serde(default)]
        agent: Option<String>,
        #[serde(default)]
        resume_mode: Option<String>,
        /// Accepted for wire symmetry with ProjectCreate; project UPDATE performs no seeding, so it is ignored.
        #[serde(default)]
        resume_session_id: Option<String>,
        #[serde(default)]
        model: Option<String>,
        #[serde(default)]
        dangerous: Option<bool>,
        #[serde(default)]
        custom_command: Option<String>,
        #[serde(default)]
        directories: Option<Vec<ProjectDirectoryWire>>,
    },
    /// Gap-doc project management (Delete project): browser asks the desktop to DELETE `project_id` — mirrors the
    /// desktop Project menu's "Delete project…" through the release-before-cascade project lifecycle. DESTRUCTIVE:
    /// releases unshared live sessions before removing the project record. Desktop-authoritative (reflects via
    /// workspace metadata). No command/argv/env on the wire.
    DeleteProject {
        request_id: String,
        project_id: String,
    },
    /// Winsize-owner Phase 2b: the browser's "Sized: Local/Remote" toggle. `selected` = does the user want the
    /// REMOTE (browser) to own the shared PTY's size? The agent records it on the shared `WinsizeOwner`, recomputes
    /// the effective owner (serving>0 && selected, with grace), and broadcasts `WinsizeOwnerChanged`. Content-blind:
    /// a single bool crosses the wire. No request_id — the reply is a broadcast owner_changed, not a request/response.
    SetWinsizeOwner {
        selected: bool,
    },
    Bye,
}

/// Content-blind metadata for one prior agent session (gap-doc SessionPicker row). Mirrors the desktop
/// `AgentHistorySession` MINUS the message text: id + agent + timestamps + an optional exact count — NO `first_message`,
/// no preview content, so listing prior sessions never leaks conversation data over the remote wire.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct AgentSessionMeta {
    pub id: String,
    pub agent: String,
    pub modified_at_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_count: Option<usize>,
    pub in_use: bool,
    /// The user-chosen short name for this session (desktop `custom_name`), so the browser can show the SAME label
    /// as local instead of the raw id. Content-blind: a name the USER typed, never derived from conversation text
    /// (we deliberately do NOT send `title`, which can be derived from the first message).
    #[serde(skip_serializing_if = "Option::is_none")]
    pub custom_name: Option<String>,
}

/// One subdirectory in the browser folder-picker (list_directories). Content-blind: a folder name + its absolute
/// path — no files, no contents.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct DirectoryEntry {
    pub name: String,
    pub path: String,
}

/// One line of a prior session's transcript (gap-doc SessionPreviewLine). This is the DELIBERATE content
/// exception: `text` is conversation content the user explicitly asked to preview (see PreviewAgentSession).
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
pub struct PreviewLine {
    pub role: String,
    pub text: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitPaneDir {
    Right,
    Down,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPaneRequest {
    pub window_id: String,
    pub from_pane_id: String,
    pub dir: SplitPaneDir,
    pub agent: Option<String>,
    pub launch_flags: Option<serde_json::Value>,
    /// Working directory for the new pane; `None` → inherit the source pane's cwd.
    pub cwd: Option<String>,
    /// Display name for the new pane's tab; `None` → derive from the agent (the pre-existing titles).
    pub pane_name: Option<String>,
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SplitPaneCreated {
    pub session_id: String,
    pub tab_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SplitPaneCreateError {
    DaemonUnavailable,
    WindowNotFound,
    PaneNotFound,
    PaneLimit,
    InvalidDirection,
    Internal,
}

impl SplitPaneCreateError {
    pub fn code(&self) -> &'static str {
        match self {
            SplitPaneCreateError::DaemonUnavailable => "daemon_unavailable",
            SplitPaneCreateError::WindowNotFound => "window_not_found",
            SplitPaneCreateError::PaneNotFound => "pane_not_found",
            SplitPaneCreateError::PaneLimit => "pane_limit",
            SplitPaneCreateError::InvalidDirection => "invalid_direction",
            SplitPaneCreateError::Internal => "internal",
        }
    }
}

pub trait PaneSplitter {
    fn split_pane(
        &mut self,
        request: SplitPaneRequest,
    ) -> Result<SplitPaneCreated, SplitPaneCreateError>;
    fn split_pane_with_initial_size(
        &mut self,
        request: SplitPaneRequest,
        _initial_size: crate::session_creator::InitialTerminalSize,
    ) -> Result<SplitPaneCreated, SplitPaneCreateError> {
        self.split_pane(request)
    }

    fn new_pane(
        &mut self,
        request: SplitPaneRequest,
    ) -> Result<SplitPaneCreated, SplitPaneCreateError>;
    fn new_pane_with_initial_size(
        &mut self,
        request: SplitPaneRequest,
        _initial_size: crate::session_creator::InitialTerminalSize,
    ) -> Result<SplitPaneCreated, SplitPaneCreateError> {
        self.new_pane(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevivePaneRequest {
    pub window_id: String,
    pub pane_id: String,
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RevivePaneCreated {
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RevivePaneError {
    WindowNotFound,
    PaneNotFound,
    GloballyLastVisible,
    Internal,
}

impl RevivePaneError {
    pub fn code(&self) -> &'static str {
        match self {
            RevivePaneError::WindowNotFound => "window_not_found",
            RevivePaneError::PaneNotFound => "pane_not_found",
            RevivePaneError::GloballyLastVisible => "last_visible_window",
            RevivePaneError::Internal => "internal",
        }
    }
}

/// Inject the desktop revive op (WindowLayoutService::revive_pane). Same pattern as PaneSplitter so the daemon/
/// shell IO stays out of this pure parser and is fakeable in tests.
pub trait PaneReviver {
    fn revive_pane(
        &mut self,
        request: RevivePaneRequest,
    ) -> Result<RevivePaneCreated, RevivePaneError>;
    fn revive_pane_with_initial_size(
        &mut self,
        request: RevivePaneRequest,
        _initial_size: crate::session_creator::InitialTerminalSize,
    ) -> Result<RevivePaneCreated, RevivePaneError> {
        self.revive_pane(request)
    }
}

/// Inject a virtual-viewport starter: start a pane's recorded daemon session without changing desktop layout.
pub trait PaneSessionStarter {
    fn start_pane_session(
        &mut self,
        request: RevivePaneRequest,
    ) -> Result<RevivePaneCreated, RevivePaneError>;
    fn start_pane_session_with_initial_size(
        &mut self,
        request: RevivePaneRequest,
        _initial_size: crate::session_creator::InitialTerminalSize,
    ) -> Result<RevivePaneCreated, RevivePaneError> {
        self.start_pane_session(request)
    }
}

/// One pane stash (Close/stash) request — same shape as revive (window_id + pane_id + now), the inverse op.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StashPaneRequest {
    pub window_id: String,
    pub pane_id: String,
    pub now_ms: u64,
}

/// Inject the desktop stash op (WindowLayoutService::stash_pane). Reuses RevivePaneError (WindowNotFound /
/// PaneNotFound / Internal) since the failure modes match. Same injectable pattern as the other service seams.
pub trait PaneStasher {
    fn stash_pane(&mut self, request: StashPaneRequest) -> Result<(), RevivePaneError>;
}

/// One pane REMOVE (Remove from shelf) request — same shape as stash (window_id + pane_id + now). Maps to
/// WindowLayoutService::close_pane, which drops only the layout/shelf record (the daemon session is not killed).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemovePaneRequest {
    pub window_id: String,
    pub pane_id: String,
    pub now_ms: u64,
}

/// Inject the desktop remove op (WindowLayoutService::close_pane). Reuses RevivePaneError (WindowNotFound /
/// PaneNotFound / Internal). Same injectable pattern as the other service seams.
pub trait PaneRemover {
    fn remove_pane(&mut self, request: RemovePaneRequest) -> Result<(), RevivePaneError>;
}

/// One rename request — a PANE (`pane_id` set, via rename_tab) or a WINDOW (`pane_id` None, via rename_window).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RenameRequest {
    pub window_id: String,
    /// Some = rename that pane (tab); None = rename the window itself.
    pub pane_id: Option<String>,
    pub name: String,
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenameError {
    InvalidName,
    WindowNotFound,
    PaneNotFound,
    Internal,
}

impl RenameError {
    pub fn code(&self) -> &'static str {
        match self {
            RenameError::InvalidName => "invalid_name",
            RenameError::WindowNotFound => "window_not_found",
            RenameError::PaneNotFound => "pane_not_found",
            RenameError::Internal => "internal",
        }
    }
}

/// Inject the desktop rename ops (WindowLayoutService::rename_tab / rename_window). Same injectable pattern as
/// the other service seams. (Project rename rides project_update's name field, so it isn't here.)
pub trait Renamer {
    fn rename(&mut self, request: RenameRequest) -> Result<(), RenameError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FocusWindowError {
    WindowNotFound,
    Internal,
}

impl FocusWindowError {
    pub fn code(&self) -> &'static str {
        match self {
            FocusWindowError::WindowNotFound => "window_not_found",
            FocusWindowError::Internal => "internal",
        }
    }
}

/// Inject the live desktop focus op. This must switch the actual desktop renderer/runtime window, not merely
/// mutate dashboard records; until that hook is available the channel returns `not_implemented`.
pub trait WindowFocuser {
    fn focus_window(&mut self, window_id: String, now_ms: u64) -> Result<(), FocusWindowError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CloseWindowError {
    WindowNotFound,
    GloballyLastVisible,
    Internal,
}

impl CloseWindowError {
    pub fn code(&self) -> &'static str {
        match self {
            CloseWindowError::WindowNotFound => "window_not_found",
            CloseWindowError::GloballyLastVisible => "last_visible_window",
            CloseWindowError::Internal => "internal",
        }
    }

    fn message(&self) -> &'static str {
        match self {
            CloseWindowError::GloballyLastVisible => {
                "the globally last visible window must remain open"
            }
            CloseWindowError::WindowNotFound | CloseWindowError::Internal => {
                "could not close window"
            }
        }
    }
}

/// Inject the desktop close-window op (WindowLayoutService::delete + session teardown). `now_ms` lets the impl
/// timestamp any related record writes. Same injectable pattern as the other service seams.
pub trait WindowCloser {
    fn close_window(&mut self, window_id: String, now_ms: u64) -> Result<(), CloseWindowError>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWindowRequest {
    pub project_id: String,
    pub name: String,
    pub cwd: Option<String>,
    pub agent: Option<String>,
    pub launch_flags: Option<serde_json::Value>,
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewWindowCreated {
    pub window_id: String,
    pub session_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NewWindowError {
    ProjectNotFound,
    DaemonUnavailable,
    Internal,
}

impl NewWindowError {
    pub fn code(&self) -> &'static str {
        match self {
            NewWindowError::ProjectNotFound => "project_not_found",
            NewWindowError::DaemonUnavailable => "daemon_unavailable",
            NewWindowError::Internal => "internal",
        }
    }
}

/// Inject the desktop new-window op (the createWindow sequence: project/window records + create_empty + open_tab).
/// Same pattern as PaneSplitter/PaneReviver so the daemon/shell IO stays out of this pure parser and is fakeable.
pub trait WindowOpener {
    fn new_window(&mut self, request: NewWindowRequest)
        -> Result<NewWindowCreated, NewWindowError>;
    fn new_window_with_initial_size(
        &mut self,
        request: NewWindowRequest,
        _initial_size: crate::session_creator::InitialTerminalSize,
    ) -> Result<NewWindowCreated, NewWindowError> {
        self.new_window(request)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionPreviewRequest {
    pub agent: String,
    pub cwd: Option<String>,
    pub session_id: String,
    pub max_lines: usize,
}

/// Inject the desktop session-preview reader
/// (`maestro_local_services::agent_history::preview_folder_session`). Returns the
/// prior transcript's first lines — the DELIBERATE content path. Same injectable pattern as the other seams.
pub trait SessionPreviewer {
    fn preview(&mut self, request: SessionPreviewRequest) -> Vec<PreviewLine>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionManageAction {
    Rename {
        name: Option<String>,
    },
    Hide,
    /// Bring a ⊘-removed (hidden) session back to the visible list — desktop `unhide_folder_session`.
    Unhide {
        cwd: Option<String>,
    },
    Delete {
        cwd: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionManageRequest {
    pub agent: String,
    pub session_id: String,
    pub action: SessionManageAction,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SessionManageError {
    NotFound,
    Internal,
}

impl SessionManageError {
    pub fn code(&self) -> &'static str {
        match self {
            SessionManageError::NotFound => "not_found",
            SessionManageError::Internal => "internal",
        }
    }
}

/// Inject the desktop SessionPicker manage ops (set_folder_session_name / hide_folder_session /
/// delete_folder_session). Content-blind (ids/label only). Same injectable pattern as the other seams.
pub trait SessionManager {
    fn manage(&mut self, request: SessionManageRequest) -> Result<(), SessionManageError>;
}

/// One pinned project directory from the wire (ProjectForm directories row). `name` is the display label, `path`
/// an absolute directory; the desktop mints the stable `id`. Content-blind: paths/labels only.
#[derive(Debug, Clone, PartialEq, Eq, serde::Deserialize)]
pub struct ProjectDirectoryWire {
    pub name: String,
    pub path: String,
}

/// One project create OR update request (the optional fields distinguish them: update names a project_id, only
/// present fields change). The reviver/splitter pattern: content-blind, launch resolved on the desktop.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectEditRequest {
    /// Some(id) = update an existing project; None = create a new one.
    pub project_id: Option<String>,
    pub name: Option<String>,
    pub root: Option<String>,
    pub icon: Option<String>,
    pub accent_color: Option<String>,
    pub agent: Option<String>,
    /// Default launch resume policy for the project — DESKTOP vocabulary "none"|"resume"|"continue"
    /// (legacy browsers sent "new"; the sanitizer maps it to "none"). Part of the desktop ProjectForm's
    /// defaultLaunchFlags. None = leave the desktop default.
    pub resume_mode: Option<String>,
    /// New Project resume TARGET (item 5): the prior session id the seeded first pane should resume when
    /// resume_mode is "resume". Create-only (update performs no seeding). Sanitized id-like; never a path.
    pub resume_session_id: Option<String>,
    /// Default per-agent model id for the project (free-form, sanitized) — part of defaultLaunchFlags. None =
    /// leave the desktop default.
    pub model: Option<String>,
    /// Whether new sessions in the project default to the agent's dangerous skip-permissions flag — part of
    /// defaultLaunchFlags. None = leave the desktop default.
    pub dangerous: Option<bool>,
    /// A project DEFAULT custom launch command (persisted config; not a wire-executed command). None = unchanged;
    /// Some("") = clear it; Some(cmd) = set it. Sanitized (control chars stripped, bounded).
    pub custom_command: Option<String>,
    /// Pinned extra directories. None = unchanged; Some([]) = clear all; Some(list) = replace. Sanitized.
    pub directories: Option<Vec<ProjectDirectoryWire>>,
    pub now_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProjectEdited {
    pub project_id: String,
    /// The seeded FIRST pane's session id — Some only on project CREATE (create_project seeds an initial
    /// window+pane; the browser auto-attaches it). None on update/delete (nothing is seeded there).
    pub session_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProjectEditError {
    InvalidName,
    InvalidRoot,
    ProjectNotFound,
    GloballyLastVisible,
    DaemonUnavailable,
    Internal,
}

impl ProjectEditError {
    pub fn code(&self) -> &'static str {
        match self {
            ProjectEditError::InvalidName => "invalid_name",
            ProjectEditError::InvalidRoot => "invalid_root",
            ProjectEditError::ProjectNotFound => "project_not_found",
            ProjectEditError::GloballyLastVisible => "last_visible_window",
            ProjectEditError::DaemonUnavailable => "daemon_unavailable",
            ProjectEditError::Internal => "internal",
        }
    }
}

/// Inject the desktop project create/edit op (ProjectService::create / update). Same pattern as the other
/// service seams so the shell IO stays out of this pure parser and is fakeable in tests.
pub trait ProjectEditor {
    fn create_project(
        &mut self,
        request: ProjectEditRequest,
    ) -> Result<ProjectEdited, ProjectEditError>;
    fn create_project_with_initial_size(
        &mut self,
        request: ProjectEditRequest,
        _initial_size: crate::session_creator::InitialTerminalSize,
    ) -> Result<ProjectEdited, ProjectEditError> {
        self.create_project(request)
    }
    fn update_project(
        &mut self,
        request: ProjectEditRequest,
    ) -> Result<ProjectEdited, ProjectEditError>;
    /// Release unshared project sessions and then delete the project record. Returns the deleted project_id on
    /// success; ProjectNotFound when it didn't exist.
    fn delete_project(
        &mut self,
        project_id: String,
        now_ms: u64,
    ) -> Result<ProjectEdited, ProjectEditError>;
}

trait AgentSessionLister: Send {
    fn list(
        &mut self,
        agent: &str,
        cwd: Option<String>,
        include_hidden: bool,
    ) -> Vec<AgentSessionMeta>;
}

struct SystemAgentSessionLister;

impl AgentSessionLister for SystemAgentSessionLister {
    fn list(
        &mut self,
        agent: &str,
        cwd: Option<String>,
        include_hidden: bool,
    ) -> Vec<AgentSessionMeta> {
        if include_hidden {
            list_hidden_agent_sessions_metadata(agent, cwd)
        } else {
            list_agent_sessions_metadata(agent, cwd)
        }
    }
}

trait DirectoryLister: Send {
    fn list(&mut self, path: Option<&str>) -> DirectoryListing;
}

struct SystemDirectoryLister;

impl DirectoryLister for SystemDirectoryLister {
    fn list(&mut self, path: Option<&str>) -> DirectoryListing {
        list_child_directories(path)
    }
}

/// Outbound replies. Bounded; no secrets, no terminal data.
#[derive(Debug, Clone, serde::Serialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum OutboundMsg {
    Hello {
        protocol_version: u32,
        device_id: String,
        role: String,
        /// Additive, allowlisted behavior flags. Older browser clients ignore this field; keeping the protocol
        /// version unchanged preserves compatibility while newer clients can avoid sending messages that an older
        /// agent would interpret with legacy semantics.
        capabilities: Vec<String>,
    },
    AuthOk {
        account_id: String,
        device_id: String,
        /// Additive QA cohort label sent only after successful authorization. Omitted for dirty/unknown/malformed
        /// local builds; browsers independently revalidate it and legacy clients ignore the field.
        #[serde(skip_serializing_if = "Option::is_none")]
        agent_build_git: Option<String>,
    },
    AuthRefused {
        reason: String,
    }, // missing | invalid | revoked | wrong_device
    AuthRefreshOk {
        expires_at_ms: u64,
    },
    AuthRefreshRefused {
        reason: String,
    },
    Pong {
        nonce: String,
    },
    ListResult {
        request_id: String,
        items: Vec<String>,
    }, // empty in S3b
    /// Reply to a successful `create_session` (Slice E) — the new local session id; the browser then
    /// attaches with the existing attach path. F1: echoes back the optional `label` so the UI can show a
    /// readable name (omitted from the wire when absent). No terminal payload.
    SessionCreated {
        request_id: String,
        session_id: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        label: Option<String>,
    },
    /// Reply to a refused/failed `create_session`. `code` ∈ unauthenticated|revoked|unsupported_provider|
    /// recordless_creation_held|daemon_unavailable|limit_reached|internal; `message` is a short
    /// non-sensitive reason.
    SessionCreateError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to `list_agent_sessions` — the prior sessions' content-blind metadata (newest first). Empty when
    /// none / unsupported. No conversation text (see AgentSessionMeta).
    AgentSessionsResult {
        request_id: String,
        sessions: Vec<AgentSessionMeta>,
    },
    /// Typed refusal for a history list that could not safely inspect a protected desktop folder. Older clients
    /// ignore this additive message; newer clients can show the same Full Disk Access recovery as the desktop.
    AgentSessionsError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to `list_directories` (the browser folder-picker). `path` is the resolved absolute directory that was
    /// listed; `parent` is its parent (None at filesystem root) so the browser can offer "up". `entries` are the
    /// immediate SUBDIRECTORIES (name + absolute path), sorted by name. Content-blind: directory names/paths only,
    /// no files, no contents.
    DirectoriesResult {
        request_id: String,
        path: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        parent: Option<String>,
        entries: Vec<DirectoryEntry>,
    },
    /// Typed refusal for `list_directories`. Never echoes the requested path.
    DirectoriesError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to `preview_agent_session` — the prior transcript's first lines (role+text). DELIBERATELY carries
    /// conversation content (the user asked to preview it). Empty when the session is gone / unsupported.
    AgentSessionPreview {
        request_id: String,
        lines: Vec<PreviewLine>,
    },
    /// Reply to a refused/failed `preview_agent_session`. `code` ∈ unauthenticated|revoked|invalid_session_id|
    /// not_implemented|internal; `message` is a short non-sensitive reason.
    AgentSessionPreviewError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to a successful `manage_agent_session` (rename/hide/delete). The browser re-lists prior sessions to
    /// reflect the change. No terminal payload.
    AgentSessionManaged {
        request_id: String,
    },
    /// Reply to a refused/failed `manage_agent_session`. `code` ∈ unauthenticated|revoked|invalid_session_id|
    /// not_implemented|invalid_action|not_found|internal; `message` is a short non-sensitive reason.
    AgentSessionManageError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to a successful `split_pane` — the new pane's session id (+ tab id). The browser then refreshes
    /// workspace metadata to see the persisted Project→Window→Pane layout. No terminal payload.
    SplitPaneOk {
        request_id: String,
        session_id: String,
        tab_id: String,
    },
    /// Reply to a refused/failed `split_pane` / `new_pane`. `code` ∈ unauthenticated|revoked|
    /// unsupported_provider|not_implemented|window_not_found|pane_limit|internal; `message` is a short
    /// non-sensitive reason.
    SplitPaneError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to a successful `revive_pane` — the revived pane's session id. The browser refreshes workspace
    /// metadata to see the pane back live. No terminal payload.
    RevivePaneOk {
        request_id: String,
        session_id: String,
    },
    /// Reply to a refused/failed `revive_pane`. `code` ∈ unauthenticated|revoked|not_implemented|
    /// window_not_found|pane_not_found|internal; `message` is a short non-sensitive reason.
    RevivePaneError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to `start_pane_session` — the pane's durable session is now daemon-live and attachable.
    StartPaneSessionOk {
        request_id: String,
        session_id: String,
    },
    /// Reply to a refused/failed `start_pane_session`.
    StartPaneSessionError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to a successful `stash_pane` — the pane was stashed. The browser refreshes workspace metadata to
    /// see it become a stashed row. No terminal payload.
    StashPaneOk {
        request_id: String,
    },
    /// Reply to a refused/failed `stash_pane`. `code` ∈ unauthenticated|revoked|not_implemented|
    /// window_not_found|pane_not_found|internal; `message` is a short non-sensitive reason.
    StashPaneError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to a successful `remove_pane` — the pane record was removed from the shelf/layout. The browser
    /// refreshes workspace metadata to see the row disappear. No terminal payload.
    RemovePaneOk {
        request_id: String,
    },
    /// Reply to a refused/failed `remove_pane`. `code` ∈ unauthenticated|revoked|not_implemented|
    /// window_not_found|pane_not_found|last_visible_window|internal; `message` is a short
    /// non-sensitive reason.
    RemovePaneError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to a successful `rename` (pane or window). The browser refreshes workspace metadata to see the new
    /// name. No terminal payload.
    RenameOk {
        request_id: String,
    },
    /// Reply to a refused/failed `rename`. `code` ∈ unauthenticated|revoked|not_implemented|invalid_name|
    /// window_not_found|pane_not_found|internal; `message` is a short non-sensitive reason.
    RenameError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to a successful `focus_window` — the desktop runtime focused/switched that real window.
    FocusWindowOk {
        request_id: String,
    },
    /// Reply to a refused/failed `focus_window`. `code` ∈ unauthenticated|revoked|not_implemented|
    /// window_not_found|internal; `message` is a short non-sensitive reason.
    FocusWindowError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to a successful `close_window` — the window was removed. The browser refreshes workspace metadata
    /// to see it gone. No terminal payload.
    CloseWindowOk {
        request_id: String,
    },
    /// Reply to a refused/failed `close_window`. `code` ∈ unauthenticated|revoked|not_implemented|
    /// window_not_found|last_visible_window|internal; `message` is a short non-sensitive reason.
    CloseWindowError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to a successful `new_window` — the new window id + its first pane's session id. The browser
    /// refreshes workspace metadata to see the new Project→Window. No terminal payload.
    NewWindowOk {
        request_id: String,
        window_id: String,
        session_id: String,
    },
    /// Reply to a refused/failed `new_window`. `code` ∈ unauthenticated|revoked|unsupported_provider|
    /// not_implemented|project_not_found|daemon_unavailable|internal; `message` is a short non-sensitive reason.
    NewWindowError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Reply to a successful `project_create` / `project_update` — the project id. The browser refreshes
    /// workspace metadata to see the new/updated project. On CREATE, `session_id` carries the seeded first
    /// pane's session id so the browser can auto-attach it; omitted from the wire on update/delete (old
    /// browsers never see the key — backward compatible). No terminal payload.
    ProjectEditOk {
        request_id: String,
        project_id: String,
        #[serde(skip_serializing_if = "Option::is_none")]
        session_id: Option<String>,
    },
    /// Reply to a refused/failed project create/update/delete. `code` ∈ unauthenticated|revoked|
    /// unsupported_provider|not_implemented|invalid_name|invalid_root|project_not_found|
    /// last_visible_window|daemon_unavailable|internal; `message` is a short non-sensitive reason.
    ProjectEditError {
        request_id: String,
        code: String,
        message: String,
    },
    /// Additive, bounded desktop permission snapshot. It is emitted only on an authenticated connection:
    /// once immediately after auth and again only when this connection observes a changed status.
    DesktopAccessStatus {
        platform: String,
        full_disk_access: String,
    },
    /// Winsize-owner Phase 2b broadcast: the agent's CURRENT effective owner of the shared PTY size ("local" or
    /// "remote"). Sent right after auth (so a fresh browser learns the current owner) and whenever the effective
    /// owner changes (toggle, or serving→0 after grace). Content-blind: one opaque word. The browser reflects it
    /// into its resize gate (Phase 2b web); the desktop reads the file mirror (Phase 2c).
    WinsizeOwnerChanged {
        owner: String, // "local" | "remote"
    },
    Error {
        code: String,
        message: String,
    },
    Bye,
}

impl InboundMsg {
    /// Central authorization boundary for a token restricted to one daemon session. Terminal attach/input/list
    /// have their own exact-session gate in `remote_bridge`; every control RPC that can read or mutate broader
    /// session, history, filesystem, pane, window, or project state is decided here before any backend is called.
    /// Keeping this match exhaustive makes a future RPC fail compilation until its scope policy is explicit.
    fn session_scope_refusal(&self, allowed_session_id: &str) -> Option<OutboundMsg> {
        const CODE: &str = "session_scope";
        const MESSAGE: &str = "this token is restricted to another session";
        match self {
            InboundMsg::Hello { .. }
            | InboundMsg::Auth { .. }
            | InboundMsg::AuthRefresh { .. }
            | InboundMsg::Ping { .. }
            | InboundMsg::Bye => None,
            InboundMsg::PreviewAgentSession {
                request_id,
                session_id,
                ..
            } => {
                (session_id != allowed_session_id).then(|| OutboundMsg::AgentSessionPreviewError {
                    request_id: request_id.clone(),
                    code: CODE.into(),
                    message: MESSAGE.into(),
                })
            }
            InboundMsg::ManageAgentSession {
                request_id,
                session_id,
                ..
            } => (session_id != allowed_session_id).then(|| OutboundMsg::AgentSessionManageError {
                request_id: request_id.clone(),
                code: CODE.into(),
                message: MESSAGE.into(),
            }),
            InboundMsg::CreateSession { request_id, .. } => Some(OutboundMsg::SessionCreateError {
                request_id: request_id.clone(),
                code: CODE.into(),
                message: MESSAGE.into(),
            }),
            InboundMsg::ListAgentSessions { request_id, .. } => {
                Some(OutboundMsg::AgentSessionsError {
                    request_id: request_id.clone(),
                    code: CODE.into(),
                    message: MESSAGE.into(),
                })
            }
            InboundMsg::ListDirectories { request_id, .. } => Some(OutboundMsg::DirectoriesError {
                request_id: request_id.clone(),
                code: CODE.into(),
                message: MESSAGE.into(),
            }),
            InboundMsg::SplitPane { request_id, .. } | InboundMsg::NewPane { request_id, .. } => {
                Some(OutboundMsg::SplitPaneError {
                    request_id: request_id.clone(),
                    code: CODE.into(),
                    message: MESSAGE.into(),
                })
            }
            InboundMsg::RevivePane { request_id, .. } => Some(OutboundMsg::RevivePaneError {
                request_id: request_id.clone(),
                code: CODE.into(),
                message: MESSAGE.into(),
            }),
            InboundMsg::StartPaneSession { request_id, .. } => {
                Some(OutboundMsg::StartPaneSessionError {
                    request_id: request_id.clone(),
                    code: CODE.into(),
                    message: MESSAGE.into(),
                })
            }
            InboundMsg::StashPane { request_id, .. } => Some(OutboundMsg::StashPaneError {
                request_id: request_id.clone(),
                code: CODE.into(),
                message: MESSAGE.into(),
            }),
            InboundMsg::RemovePane { request_id, .. } => Some(OutboundMsg::RemovePaneError {
                request_id: request_id.clone(),
                code: CODE.into(),
                message: MESSAGE.into(),
            }),
            InboundMsg::Rename { request_id, .. } => Some(OutboundMsg::RenameError {
                request_id: request_id.clone(),
                code: CODE.into(),
                message: MESSAGE.into(),
            }),
            InboundMsg::FocusWindow { request_id, .. } => Some(OutboundMsg::FocusWindowError {
                request_id: request_id.clone(),
                code: CODE.into(),
                message: MESSAGE.into(),
            }),
            InboundMsg::CloseWindow { request_id, .. } => Some(OutboundMsg::CloseWindowError {
                request_id: request_id.clone(),
                code: CODE.into(),
                message: MESSAGE.into(),
            }),
            InboundMsg::NewWindow { request_id, .. } => Some(OutboundMsg::NewWindowError {
                request_id: request_id.clone(),
                code: CODE.into(),
                message: MESSAGE.into(),
            }),
            InboundMsg::ProjectCreate { request_id, .. }
            | InboundMsg::ProjectUpdate { request_id, .. }
            | InboundMsg::DeleteProject { request_id, .. } => Some(OutboundMsg::ProjectEditError {
                request_id: request_id.clone(),
                code: CODE.into(),
                message: MESSAGE.into(),
            }),
            InboundMsg::ListRequest { .. } | InboundMsg::SetWinsizeOwner { .. } => {
                Some(OutboundMsg::Error {
                    code: CODE.into(),
                    message: MESSAGE.into(),
                })
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CreationRequestKind {
    CreateSession,
    SplitPane,
    NewPane,
    RevivePane,
    StartPaneSession,
    NewWindow,
    ProjectCreate,
}

#[derive(Debug, Clone)]
struct CompletedCreation {
    request_id: String,
    kind: CreationRequestKind,
    request_digest: [u8; 32],
    reply: OutboundMsg,
    completed_at_ms: u64,
}

#[derive(Debug, Default)]
struct CreationReplayCache {
    completed: VecDeque<CompletedCreation>,
}

enum CreationReplayDecision {
    Execute,
    Reply(OutboundMsg),
}

impl CreationReplayCache {
    fn clear(&mut self) {
        self.completed.clear();
    }

    fn prune_expired(&mut self, now_ms: u64) {
        self.completed
            .retain(|entry| now_ms.saturating_sub(entry.completed_at_ms) < CREATION_REPLAY_TTL_MS);
    }

    fn lookup_or_admit(
        &mut self,
        kind: CreationRequestKind,
        request_id: &str,
        request_digest: [u8; 32],
        now_ms: u64,
    ) -> CreationReplayDecision {
        self.prune_expired(now_ms);
        if let Some(entry) = self
            .completed
            .iter()
            .find(|entry| entry.request_id == request_id)
        {
            if entry.kind == kind && entry.request_digest == request_digest {
                return CreationReplayDecision::Reply(entry.reply.clone());
            }
            return CreationReplayDecision::Reply(creation_error_reply(
                kind,
                request_id.to_string(),
                "request_id_conflict",
                "request id was already used for a different creation request",
            ));
        }
        if self.completed.len() >= CREATION_REPLAY_MAX_ENTRIES {
            // Never evict an unexpired result: doing so would let a later duplicate execute twice.
            return CreationReplayDecision::Reply(creation_error_reply(
                kind,
                request_id.to_string(),
                "request_cache_full",
                "too many recent creation requests; wait and try again",
            ));
        }
        CreationReplayDecision::Execute
    }

    fn complete(
        &mut self,
        kind: CreationRequestKind,
        request_id: String,
        request_digest: [u8; 32],
        reply: OutboundMsg,
        now_ms: u64,
    ) {
        self.completed.push_back(CompletedCreation {
            request_id,
            kind,
            request_digest,
            reply,
            completed_at_ms: now_ms,
        });
    }
}

fn creation_error_reply(
    kind: CreationRequestKind,
    request_id: String,
    code: &str,
    message: &str,
) -> OutboundMsg {
    match kind {
        CreationRequestKind::CreateSession => OutboundMsg::SessionCreateError {
            request_id,
            code: code.into(),
            message: message.into(),
        },
        CreationRequestKind::SplitPane | CreationRequestKind::NewPane => {
            OutboundMsg::SplitPaneError {
                request_id,
                code: code.into(),
                message: message.into(),
            }
        }
        CreationRequestKind::RevivePane => OutboundMsg::RevivePaneError {
            request_id,
            code: code.into(),
            message: message.into(),
        },
        CreationRequestKind::StartPaneSession => OutboundMsg::StartPaneSessionError {
            request_id,
            code: code.into(),
            message: message.into(),
        },
        CreationRequestKind::NewWindow => OutboundMsg::NewWindowError {
            request_id,
            code: code.into(),
            message: message.into(),
        },
        CreationRequestKind::ProjectCreate => OutboundMsg::ProjectEditError {
            request_id,
            code: code.into(),
            message: message.into(),
        },
    }
}

/// The browser's per-connection proof of possession, captured from the OFFER (device id it claims, the
/// offer's DTLS fingerprint it bound to, and the signature). Verified at Auth against the browser public
/// key embedded in the token.
#[derive(Debug, Clone)]
struct OfferProof {
    device_id: String,
    fingerprint: String,
    sig_b64: String,
}

/// Minimal, non-secret authority state shared with the WebRTC binary-input gate. The gate must not
/// depend on the control loop making progress: that loop can be awaiting a bounded physical
/// DataChannel send while binary callbacks continue to run independently.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg(feature = "webrtc")]
pub(crate) struct AuthenticatedAuthoritySnapshot {
    pub(crate) account_id: String,
    /// The initial authority epoch remains fixed across in-band token successors so an account
    /// revoke-before cutoff cannot be bypassed by refreshing to a newer token iat.
    pub(crate) revocation_iat_ms: u64,
    /// The earliest live deadline: current signed-token expiry, additionally bounded by the
    /// passkey certificate when that certificate is part of this connection's authority.
    pub(crate) expires_at_ms: u64,
}

/// The agent's per-connection control channel. Holds auth state + the peer's expected device id (from the
/// signaling session) and the cloud pubkey for offline token verification.
pub struct ControlChannel<R: Fn(&str, &str, u64) -> bool> {
    /// The cloud's token-verification public key (owned — 32 bytes; lets the channel be `'static` so it
    /// can move into a spawned task that pumps a live DataChannel).
    cloud_pubkey: VerifyingKey,
    /// The device id this connection is FOR (from the signaling session) — a token must match it.
    peer_device_id: String,
    /// Optional WebRTC signaling-session id this control channel was created from. New tokens may bind to
    /// it; old tokens without the claim remain accepted during the migration.
    expected_signal_session_id: Option<String>,
    /// Account id loaded from this desktop's local enrollment snapshot. Production channels set this and reject
    /// any correctly signed cloud token for a different account before accepting browser or certificate authority.
    expected_account_id: Option<String>,
    /// Enrolled production channels require a pinned passkey as well as a token-embedded browser key and matching
    /// offer PoP. Pre-passkey records fail closed and require explicit re-enrollment.
    require_browser_proof: bool,
    /// The browser's per-connection offer proof-of-possession, captured from the OFFER at connection setup:
    /// `(device_id, sdp_fingerprint, signature_b64)`. At Auth we verify this signature against the browser
    /// public key embedded in the token — proving the connecting browser holds its device private key.
    /// None when the offer carried no proof. Enrolled production channels set `require_browser_proof` and refuse
    /// this state; explicit non-enrolled development callers may retain the generic no-proof path.
    offer_proof: Option<OfferProof>,
    /// ACCESS PASSKEY (#11): the browser certificate presented in the OFFER (WebAuthn-passkey-signed, binds
    /// the browser key to this desktop+account). None when the offer carried no cert.
    browser_cert: Option<crate::browser_cert::BrowserCert>,
    /// The account's passkey PUBLIC key this desktop pinned at enrollment (from device.json). None when no
    /// passkey was ever registered. Enrolled production channels refuse NONE; when SOME, a valid cert is
    /// MANDATORY (fail-closed) — the cloud cannot downgrade by omitting the cert or the browser_pubkey. See
    /// `allow_legacy_browsers`.
    passkey: Option<crate::browser_cert::PasskeyPublicKey>,
    /// LOCAL migration escape hatch (default false). When a passkey is pinned, a browser WITHOUT a valid cert
    /// is refused UNLESS this is true — and this is set only from LOCAL desktop config (env/flag), NEVER from a
    /// cloud-supplied field. This is the one and only way legacy (pre-passkey) browsers keep working during a
    /// migration window; a compromised cloud can't turn it on. Flip it off (the default) to fail closed.
    allow_legacy_browsers: bool,
    /// WebAuthn cert policy: the allowed origins + max cert TTL. Set alongside the passkey context.
    cert_policy: crate::browser_cert::CertPolicy,
    /// This desktop's own device id — the cert must name it as `desktop_id`. Defaults to peer_device_id's
    /// counterpart is NOT correct; set explicitly by the live wiring. Empty → cert desktop-binding can't be
    /// checked, so a cert is only trusted once this is set.
    this_desktop_id: String,
    /// Live revocation check (account_id, device_id) -> revoked?.
    revoked: R,
    /// The verified token claims once authenticated (None = unauthenticated). Carries the token SCOPE
    /// (account/device/optional session) the S4 terminal bridge enforces. Not secret — claims only.
    authed_claims: Option<TokenClaims>,
    /// Hash of the exact accepted wire token. The next successor must name this as refresh_parent_sha256.
    authed_token_sha256: Option<[u8; 32]>,
    /// Issued-at time of the INITIAL authority on this DataChannel. Successors advance their own iat for strict
    /// ordering, but live account revoke-before checks must keep comparing against the authority epoch that opened
    /// the channel; otherwise a post-revoke successor iat could make an already-revoked channel look fresh.
    authed_revocation_iat_ms: Option<u64>,
    /// Exact additive capabilities proposed by this browser for this concrete DataChannel lifetime. Bounded and
    /// reset with the channel object; near matches never become protocol authority.
    browser_terminal_gzip: bool,
    /// Capability-gated, per-control-connection replay protection for desktop-authoritative creations.
    /// Legacy browsers reused fixed request ids for distinct actions, so this must stay disabled unless the
    /// browser explicitly offers `creation_request_replay_v1`.
    browser_creation_replay: bool,
    /// Exact per-DataChannel negotiation for the additive desktop permission status/error vocabulary. An agent
    /// advertises support, but it never emits unsolicited status frames to a legacy browser that did not select it.
    browser_desktop_access_status: bool,
    browser_authorization_refresh: bool,
    creation_replay: CreationReplayCache,
    /// Browser-minted correlation id (from the auth message) for the connection trace. Empty = uncorrelated.
    trace_id: String,
    /// Record-less daemon session creator retained only as a unit-test seam while production promotion is
    /// held. Production leaves this `None`, so raw `create_session` fails before daemon or durable-store IO;
    /// desktop-backed `new_pane` / `split_pane` use their separate prepared topology seam below.
    session_creator: Option<Box<dyn crate::session_creator::SessionCreator + Send>>,
    /// Desktop-backed split service. Separate from `session_creator` because a real split must persist the
    /// Project→Window→Pane layout through WindowLayoutService, not just start a daemon session.
    pane_splitter: Option<Box<dyn PaneSplitter + Send>>,
    pane_reviver: Option<Box<dyn PaneReviver + Send>>,
    pane_session_starter: Option<Box<dyn PaneSessionStarter + Send>>,
    pane_stasher: Option<Box<dyn PaneStasher + Send>>,
    pane_remover: Option<Box<dyn PaneRemover + Send>>,
    renamer: Option<Box<dyn Renamer + Send>>,
    window_focuser: Option<Box<dyn WindowFocuser + Send>>,
    window_closer: Option<Box<dyn WindowCloser + Send>>,
    window_opener: Option<Box<dyn WindowOpener + Send>>,
    session_previewer: Option<Box<dyn SessionPreviewer + Send>>,
    session_manager: Option<Box<dyn SessionManager + Send>>,
    project_editor: Option<Box<dyn ProjectEditor + Send>>,
    /// Platform permission classifier. Production delegates to maestro-shell's non-canonicalizing macOS
    /// classifier; tests inject exact status/path outcomes to prove refusal happens before any IO seam.
    desktop_access: Box<dyn DesktopAccessPolicy>,
    agent_session_lister: Box<dyn AgentSessionLister>,
    directory_lister: Box<dyn DirectoryLister>,
    /// Winsize-owner Phase 2b: the SHARED owner state machine (one per remote-peer, across all sessions). Set by
    /// the live wiring (serve_control) so a `set_winsize_owner` from THIS connection updates the same state the
    /// serving counter feeds. None in unit tests that don't exercise the toggle → SetWinsizeOwner is a no-op reply.
    winsize_owner: Option<std::sync::Arc<std::sync::Mutex<crate::winsize_owner::WinsizeOwner>>>,
}

impl<R: Fn(&str, &str, u64) -> bool> ControlChannel<R> {
    pub fn new(cloud_pubkey: VerifyingKey, peer_device_id: String, revoked: R) -> Self {
        ControlChannel {
            cloud_pubkey,
            peer_device_id,
            expected_signal_session_id: None,
            expected_account_id: None,
            require_browser_proof: false,
            offer_proof: None,
            browser_cert: None,
            passkey: None,
            allow_legacy_browsers: false,
            cert_policy: crate::browser_cert::CertPolicy {
                allowed_origins: Vec::new(),
                max_ttl_ms: 60 * 60 * 1000, // 1h default; overridden via set_passkey_context
            },
            this_desktop_id: String::new(),
            revoked,
            authed_claims: None,
            authed_token_sha256: None,
            authed_revocation_iat_ms: None,
            browser_terminal_gzip: false,
            browser_creation_replay: false,
            browser_desktop_access_status: false,
            browser_authorization_refresh: false,
            creation_replay: CreationReplayCache::default(),
            trace_id: String::new(),
            session_creator: None,
            pane_splitter: None,
            pane_reviver: None,
            pane_session_starter: None,
            pane_stasher: None,
            pane_remover: None,
            renamer: None,
            window_focuser: None,
            window_closer: None,
            window_opener: None,
            session_previewer: None,
            session_manager: None,
            project_editor: None,
            desktop_access: default_desktop_access_policy(),
            agent_session_lister: Box::new(SystemAgentSessionLister),
            directory_lister: Box::new(SystemDirectoryLister),
            winsize_owner: None,
        }
    }

    pub fn set_expected_signal_session_id(&mut self, session_id: impl Into<String>) {
        self.expected_signal_session_id = Some(session_id.into());
    }

    /// Mark this as an enrolled production desktop channel. The local account becomes an independent token
    /// binding, and browser key proof becomes mandatory regardless of passkey/certificate migration state.
    pub fn set_enrollment_context(&mut self, account_id: impl Into<String>) {
        self.expected_account_id = Some(account_id.into());
        self.require_browser_proof = true;
    }

    /// Record the browser's per-connection offer proof-of-possession, extracted from the OFFER at setup.
    /// Verified at Auth against the browser public key in the token.
    pub fn set_offer_proof(&mut self, device_id: String, fingerprint: String, sig_b64: String) {
        self.offer_proof = Some(OfferProof {
            device_id,
            fingerprint,
            sig_b64,
        });
    }

    /// ACCESS PASSKEY (#11): record the browser certificate presented in the OFFER (if any). Verified at Auth
    /// against the pinned passkey.
    pub fn set_browser_cert(&mut self, cert: crate::browser_cert::BrowserCert) {
        self.browser_cert = Some(cert);
    }

    /// Pin the account passkey PUBLIC key (from device.json) + this desktop's own id, so the Auth handler can
    /// verify a browser certificate binds the connecting browser to THIS desktop/account, signed by the user's
    /// passkey. When a passkey is pinned, a valid cert is MANDATORY unless `allow_legacy_browsers` (an internal
    /// compatibility input, hard-coded off by shipping composition) is true. An enrolled channel with no passkey
    /// always fails closed regardless of that compatibility input.
    pub fn set_passkey_context(
        &mut self,
        passkey: Option<crate::browser_cert::PasskeyPublicKey>,
        this_desktop_id: impl Into<String>,
        allow_legacy_browsers: bool,
        cert_policy: crate::browser_cert::CertPolicy,
    ) {
        self.passkey = passkey;
        self.this_desktop_id = this_desktop_id.into();
        self.allow_legacy_browsers = allow_legacy_browsers;
        self.cert_policy = cert_policy;
    }

    /// Unit-test seam for the held record-less create implementation. Production has no setter, so a future
    /// caller cannot accidentally promote raw `create_session` without deliberately removing this gate.
    #[cfg(test)]
    pub fn set_session_creator(
        &mut self,
        creator: Box<dyn crate::session_creator::SessionCreator + Send>,
    ) {
        self.session_creator = Some(creator);
    }

    /// Inject the desktop-backed pane splitter (live wiring), enabling real persisted split_pane.
    pub fn set_pane_splitter(&mut self, splitter: Box<dyn PaneSplitter + Send>) {
        self.pane_splitter = Some(splitter);
    }

    /// Inject the desktop-backed pane reviver (live wiring), enabling real revive_pane.
    pub fn set_pane_reviver(&mut self, reviver: Box<dyn PaneReviver + Send>) {
        self.pane_reviver = Some(reviver);
    }

    /// Inject the virtual-viewport pane session starter, enabling browser viewing without desktop revive.
    pub fn set_pane_session_starter(&mut self, starter: Box<dyn PaneSessionStarter + Send>) {
        self.pane_session_starter = Some(starter);
    }

    /// Inject the desktop-backed pane stasher (live wiring), enabling real stash_pane.
    pub fn set_pane_stasher(&mut self, stasher: Box<dyn PaneStasher + Send>) {
        self.pane_stasher = Some(stasher);
    }

    /// Inject the desktop-backed pane remover (live wiring), enabling real remove_pane.
    pub fn set_pane_remover(&mut self, remover: Box<dyn PaneRemover + Send>) {
        self.pane_remover = Some(remover);
    }

    /// Inject the desktop-backed renamer (live wiring), enabling real pane/window rename.
    pub fn set_renamer(&mut self, renamer: Box<dyn Renamer + Send>) {
        self.renamer = Some(renamer);
    }

    /// Inject the live desktop window focuser, enabling browser window-tab clicks to switch the real desktop.
    pub fn set_window_focuser(&mut self, focuser: Box<dyn WindowFocuser + Send>) {
        self.window_focuser = Some(focuser);
    }

    /// Inject the desktop-backed window closer (live wiring), enabling real close_window.
    pub fn set_window_closer(&mut self, closer: Box<dyn WindowCloser + Send>) {
        self.window_closer = Some(closer);
    }

    /// Inject the desktop-backed window opener (live wiring), enabling real new_window.
    pub fn set_window_opener(&mut self, opener: Box<dyn WindowOpener + Send>) {
        self.window_opener = Some(opener);
    }

    /// Inject the desktop-backed session previewer (live wiring), enabling real preview_agent_session.
    pub fn set_session_previewer(&mut self, previewer: Box<dyn SessionPreviewer + Send>) {
        self.session_previewer = Some(previewer);
    }

    /// Inject the desktop-backed session manager (live wiring), enabling rename/hide/delete of prior sessions.
    pub fn set_session_manager(&mut self, manager: Box<dyn SessionManager + Send>) {
        self.session_manager = Some(manager);
    }

    /// Inject the desktop-backed project editor (live wiring), enabling real project_create/update.
    pub fn set_project_editor(&mut self, editor: Box<dyn ProjectEditor + Send>) {
        self.project_editor = Some(editor);
    }

    #[cfg(test)]
    fn set_desktop_access_policy(&mut self, policy: Box<dyn DesktopAccessPolicy>) {
        self.desktop_access = policy;
    }

    #[cfg(test)]
    fn set_agent_session_lister(&mut self, lister: Box<dyn AgentSessionLister>) {
        self.agent_session_lister = lister;
    }

    #[cfg(test)]
    fn set_directory_lister(&mut self, lister: Box<dyn DirectoryLister>) {
        self.directory_lister = lister;
    }

    pub fn desktop_access_status(&self) -> DesktopAccessStatus {
        self.desktop_access.current_status()
    }

    pub fn desktop_access_status_message(&self) -> OutboundMsg {
        desktop_access_status_message(self.desktop_access_status())
    }

    /// Capture one live permission result and derive its wire message from that exact value.
    ///
    /// The caller must use this pair for change detection and delivery together; probing once for
    /// the comparison and again for serialization can race a System Settings change.
    pub fn desktop_access_status_snapshot(&self) -> (DesktopAccessStatus, OutboundMsg) {
        let status = self.desktop_access_status();
        (status, desktop_access_status_message(status))
    }

    /// Return true only when a macOS access state that cannot authorize protected IO is paired with either a
    /// classifier-positive path or an operation whose inherited path is not knowable before its backend runs.
    /// Granted and non-macOS status never consult the path classifier, preserving existing Linux behavior.
    fn desktop_access_refuses<'a>(
        &self,
        paths: impl IntoIterator<Item = &'a str>,
        inherited_or_unknown_path: bool,
    ) -> bool {
        match self.desktop_access.current_status() {
            DesktopAccessStatus::Granted | DesktopAccessStatus::NotApplicable => false,
            DesktopAccessStatus::Required | DesktopAccessStatus::Unknown => {
                inherited_or_unknown_path
                    || paths.into_iter().any(|path| {
                        self.desktop_access
                            .path_requires_full_disk_access(Path::new(path))
                    })
            }
        }
    }

    /// Inject the SHARED winsize-owner state (Phase 2b live wiring). Once set, a `set_winsize_owner` from this
    /// connection updates the same state the serving counter feeds, so the effective owner reflects both.
    pub fn set_winsize_owner(
        &mut self,
        owner: std::sync::Arc<std::sync::Mutex<crate::winsize_owner::WinsizeOwner>>,
    ) {
        self.winsize_owner = Some(owner);
    }

    fn with_creation_replay(
        &mut self,
        kind: CreationRequestKind,
        request_id: String,
        raw_request: &str,
        now_ms: u64,
        execute: impl FnOnce(&mut Self, String) -> OutboundMsg,
    ) -> OutboundMsg {
        if !self.browser_creation_replay {
            return execute(self, request_id);
        }
        if request_id.is_empty() || request_id.len() > MAX_CREATION_REQUEST_ID_BYTES {
            return creation_error_reply(
                kind,
                request_id,
                "bad_request_id",
                "request id must be between 1 and 128 bytes",
            );
        }
        let request_digest: [u8; 32] = Sha256::digest(raw_request.as_bytes()).into();
        match self
            .creation_replay
            .lookup_or_admit(kind, &request_id, request_digest, now_ms)
        {
            CreationReplayDecision::Reply(reply) => reply,
            CreationReplayDecision::Execute => {
                let reply = execute(self, request_id.clone());
                self.creation_replay.complete(
                    kind,
                    request_id,
                    request_digest,
                    reply.clone(),
                    now_ms,
                );
                reply
            }
        }
    }

    /// The current effective winsize owner as a wire word ("local"/"remote"), for the post-auth snapshot the peer
    /// loop sends a freshly-connected browser. Local when no shared state is wired (unit/test paths).
    pub fn effective_winsize_owner(&self, now_ms: u64) -> &'static str {
        match &self.winsize_owner {
            Some(o) => o
                .lock()
                .map(|g| g.effective(now_ms).as_str())
                .unwrap_or("local"),
            None => "local",
        }
    }

    pub fn is_authenticated(&self) -> bool {
        self.authed_claims.is_some()
    }

    /// The browser-supplied connection-trace correlation id (from the auth message), or "" if none. Used by the
    /// remote_peer loop to tag its structured conn-trace events so they correlate with the browser's.
    pub fn trace_id(&self) -> &str {
        &self.trace_id
    }

    pub fn browser_supports_terminal_gzip(&self) -> bool {
        self.browser_terminal_gzip
    }

    pub fn browser_supports_desktop_access_status(&self) -> bool {
        self.browser_desktop_access_status
    }

    pub fn browser_supports_authorization_refresh(&self) -> bool {
        self.browser_authorization_refresh
    }

    fn clear_authenticated_authority(&mut self) {
        self.authed_claims = None;
        self.authed_token_sha256 = None;
        self.authed_revocation_iat_ms = None;
        self.creation_replay.clear();
    }

    fn live_authority_revoked(&self, claims: &TokenClaims) -> bool {
        let Some(initial_iat_ms) = self.authed_revocation_iat_ms else {
            return true;
        };
        (self.revoked)(&claims.account_id, &self.peer_device_id, initial_iat_ms)
    }

    /// Drop the authenticated session if the token has EXPIRED. Token expiry must be enforced on EVERY
    /// privileged operation and mirrored into the independent transport authority watchdog, not just checked at
    /// connect — otherwise an open DataChannel stays privileged forever past `exp_ms`. Idempotent.
    pub fn drop_if_expired(&mut self, now_ms: u64) {
        if let Some(claims) = &self.authed_claims {
            let cert_expired = self.passkey.is_some()
                && self
                    .browser_cert
                    .as_ref()
                    .is_some_and(|cert| now_ms >= cert.expiry_ms);
            if now_ms >= claims.exp_ms || cert_expired {
                self.clear_authenticated_authority();
            }
        }
    }

    /// The verified claims if authenticated AND still valid (re-checks BOTH revocation and expiry). Used by
    /// the S4 wiring to route terminal messages to the bridge with the right token scope. Returns None if
    /// unauthenticated, revoked, or expired (each of which also drops the channel's auth). Pass the current
    /// time so expiry is re-evaluated live.
    pub fn authenticated_claims_at(&mut self, now_ms: u64) -> Option<&TokenClaims> {
        self.drop_if_expired(now_ms);
        self.authenticated_claims()
    }

    /// Capture the exact live authority needed by an independent transport callback. This reuses
    /// the control channel's expiry/revocation checks, but the returned value is deliberately
    /// sufficient for the callback to repeat those checks later without borrowing this state
    /// machine or waiting for its select loop.
    #[cfg(feature = "webrtc")]
    pub(crate) fn authenticated_authority_snapshot_at(
        &mut self,
        now_ms: u64,
    ) -> Option<AuthenticatedAuthoritySnapshot> {
        let (account_id, claims_expiry_ms) = {
            let claims = self.authenticated_claims_at(now_ms)?;
            (claims.account_id.clone(), claims.exp_ms)
        };
        let revocation_iat_ms = self.authed_revocation_iat_ms?;
        let mut expires_at_ms = claims_expiry_ms;
        if self.passkey.is_some() {
            if let Some(cert) = self.browser_cert.as_ref() {
                expires_at_ms = expires_at_ms.min(cert.expiry_ms);
            }
        }
        Some(AuthenticatedAuthoritySnapshot {
            account_id,
            revocation_iat_ms,
            expires_at_ms,
        })
    }

    /// The verified claims if authenticated AND still non-revoked (re-checks revocation only). Prefer
    /// `authenticated_claims_at` where the current time is available so expiry is enforced too.
    pub fn authenticated_claims(&mut self) -> Option<&TokenClaims> {
        let revoked = self
            .authed_claims
            .as_ref()
            .is_some_and(|claims| self.live_authority_revoked(claims));
        if revoked {
            // Compare account revoke-before with the initial channel epoch, not a successor's newer iat. Device
            // revocation remains live through the same callback.
            self.clear_authenticated_authority();
            return None;
        }
        self.authed_claims.as_ref()
    }

    /// The auth gate shared by every PRIVILEGED op: `None` = authed, proceed; `Some(code)` = refuse with that
    /// code. Distinguishes a never-authed channel ("unauthenticated") from one whose device was revoked
    /// mid-session ("revoked") — by re-checking revocation (authenticated_claims) against the prior auth state.
    fn privileged_refusal(&mut self) -> Option<&'static str> {
        let was_authed = self.is_authenticated();
        if self.authenticated_claims().is_none() {
            Some(if was_authed {
                "revoked"
            } else {
                "unauthenticated"
            })
        } else {
            None
        }
    }

    /// Handle one inbound message LINE (a JSON object). `now_ms` for token expiry. Returns the reply.
    /// A revoke between messages is caught here: any privileged message re-checks revocation, and an
    /// already-authed channel is dropped to unauthenticated if its device got revoked.
    pub fn handle(&mut self, line: &str, now_ms: u64) -> Option<OutboundMsg> {
        if line.len() > MAX_MSG_BYTES {
            return Some(OutboundMsg::Error {
                code: "too_large".into(),
                message: "message too large".into(),
            });
        }
        // Content-blind: reject any terminal/secret-shaped field name before parsing into our enum.
        if let Some(bad) = forbidden_field_in(line) {
            return Some(OutboundMsg::Error {
                code: "forbidden_field".into(),
                message: format!("field {bad:?} not allowed on the control channel"),
            });
        }
        let msg: InboundMsg = match serde_json::from_str(line) {
            Ok(m) => m,
            Err(_) => {
                return Some(OutboundMsg::Error {
                    code: "bad_message".into(),
                    message: "unknown or malformed message".into(),
                })
            }
        };

        // Live re-authorization on EVERY message: drop auth if the token EXPIRED (now_ms >= exp_ms) or the
        // device was revoked since connect. Expiry alone was previously checked only at connect, so an open
        // channel outlived its token indefinitely.
        self.drop_if_expired(now_ms);
        let revoked = self
            .authed_claims
            .as_ref()
            .is_some_and(|claims| self.live_authority_revoked(claims));
        if revoked {
            self.clear_authenticated_authority();
        }

        if let Some(scoped_session_id) = self
            .authed_claims
            .as_ref()
            .and_then(|claims| claims.session_id.as_deref())
        {
            if let Some(refusal) = msg.session_scope_refusal(scoped_session_id) {
                return Some(refusal);
            }
        }

        match msg {
            InboundMsg::Hello {
                protocol_version,
                capabilities,
                ..
            } => {
                if protocol_version != PROTOCOL_VERSION {
                    return Some(OutboundMsg::Error {
                        code: "version".into(),
                        message: "unsupported protocol version".into(),
                    });
                }
                if capabilities.len() > MAX_CAPABILITIES
                    || capabilities
                        .iter()
                        .any(|capability| capability.len() > MAX_CAPABILITY_BYTES)
                {
                    self.browser_terminal_gzip = false;
                    self.browser_creation_replay = false;
                    self.browser_desktop_access_status = false;
                    self.browser_authorization_refresh = false;
                    self.creation_replay.clear();
                    return Some(OutboundMsg::Error {
                        code: "bad_capabilities".into(),
                        message: "capability list exceeds bounds".into(),
                    });
                }
                self.browser_terminal_gzip = capabilities
                    .iter()
                    .any(|capability| capability == CAPABILITY_TERMINAL_GZIP_JSON_V1);
                let browser_creation_replay = capabilities
                    .iter()
                    .any(|capability| capability == CAPABILITY_CREATION_REPLAY_V1);
                if self.browser_creation_replay != browser_creation_replay {
                    self.creation_replay.clear();
                }
                self.browser_creation_replay = browser_creation_replay;
                self.browser_desktop_access_status = capabilities
                    .iter()
                    .any(|capability| capability == CAPABILITY_DESKTOP_ACCESS_STATUS_V1);
                self.browser_authorization_refresh = capabilities
                    .iter()
                    .any(|capability| capability == CAPABILITY_AUTHORIZATION_REFRESH_V1);
                Some(OutboundMsg::Hello {
                    protocol_version: PROTOCOL_VERSION,
                    device_id: self.peer_device_id.clone(),
                    role: "agent".into(),
                    capabilities: vec![
                        CAPABILITY_VIEWED_RESIZE_V1.into(),
                        CAPABILITY_TERMINAL_GZIP_JSON_V1.into(),
                        CAPABILITY_CREATION_REPLAY_V1.into(),
                        CAPABILITY_DESKTOP_ACCESS_STATUS_V1.into(),
                        CAPABILITY_AUTHORIZATION_REFRESH_V1.into(),
                    ],
                })
            }
            InboundMsg::Ping { nonce } => Some(OutboundMsg::Pong { nonce }), // allowed pre-auth
            InboundMsg::Bye => Some(OutboundMsg::Bye),
            InboundMsg::SetWinsizeOwner { selected } => {
                // PRIVILEGED — connected ≠ authorized. Only an authed browser may drive who owns the shared PTY size.
                if let Some(_code) = self.privileged_refusal() {
                    return Some(OutboundMsg::AuthRefused {
                        reason: "missing".into(),
                    });
                }
                // Record the toggle on the SHARED owner (serving-fed), then broadcast the recomputed effective owner.
                // When no shared state is wired (unit path), fall back to the pure rule so the reply is still coherent.
                let owner = match &self.winsize_owner {
                    Some(o) => {
                        let effective = {
                            let mut g = o.lock().unwrap_or_else(|e| e.into_inner());
                            // Browser's explicit toggle is a MANUAL override (Some), which pins the owner
                            // regardless of per-pane presence until cleared. (#25 keeps the buttons as an escape hatch.)
                            g.set_remote_selected(Some(selected));
                            g.effective(now_ms)
                        };
                        effective.as_str()
                    }
                    None => {
                        // No shared state: effective owner is just `selected` (Remote iff selected) — good enough for
                        // the unit test that exercises parse+dispatch without the serving-fed Arc.
                        if selected {
                            "remote"
                        } else {
                            "local"
                        }
                    }
                };
                Some(OutboundMsg::WinsizeOwnerChanged {
                    owner: owner.into(),
                })
            }
            InboundMsg::Auth { token, trace_id } => {
                // Ordinary auth is a one-shot lifecycle transition. Successors use AuthRefresh so a duplicate
                // Auth can never emit another AuthOk and make the browser re-run session hydration.
                if self.authed_claims.is_some() {
                    return Some(OutboundMsg::AuthRefused {
                        reason: "refresh_required".into(),
                    });
                }
                match verify_token(
                    &token,
                    &self.cloud_pubkey,
                    now_ms,
                    &self.peer_device_id,
                    &self.revoked,
                ) {
                    Ok(claims) => {
                        if claims.refresh_parent_sha256.is_some() {
                            return Some(OutboundMsg::AuthRefused {
                                reason: "refresh_required".into(),
                            });
                        }
                        // Signal-session binding, FAIL-CLOSED: if this control channel was created for a specific
                        // signaling session, the token MUST carry a matching `signal_session_id`. Previously the
                        // check only fired when the claim was present, so a token that OMITTED it bypassed the
                        // binding (a token minted for signaling session A could be replayed onto session B). We now
                        // reject a missing OR mismatched claim when a session is expected.
                        if let Some(expected) = &self.expected_signal_session_id {
                            match claims.signal_session_id.as_deref() {
                                Some(got) if got == expected => {} // bound correctly
                                _ => {
                                    return Some(OutboundMsg::AuthRefused {
                                        reason: "wrong_signal_session".into(),
                                    });
                                }
                            }
                        }
                        if self
                            .expected_account_id
                            .as_deref()
                            .is_some_and(|expected| claims.account_id.as_str() != expected)
                        {
                            return Some(OutboundMsg::AuthRefused {
                                reason: "wrong_account".into(),
                            });
                        }
                        // Target binding is enforced independently of the signaling-row lifetime. Production WebRTC
                        // peers always configure this desktop id; empty exists only in target-less unit/local contexts.
                        if !self.this_desktop_id.is_empty() {
                            match claims.target_device_id.as_deref() {
                                Some(got) if got == self.this_desktop_id => {}
                                _ => {
                                    return Some(OutboundMsg::AuthRefused {
                                        reason: "wrong_target".into(),
                                    });
                                }
                            }
                        }
                        // PRE-PASSKEY ENROLLMENT, FAIL-CLOSED: a historical device.json remains readable for
                        // explicit removal/re-enrollment, but an enrolled channel may never turn its missing local
                        // anchor into remote authority. This defense lives below composition so an alternate caller
                        // cannot bypass the early supervisor/remote-peer startup check.
                        if self.require_browser_proof && self.passkey.is_none() {
                            return Some(OutboundMsg::AuthRefused {
                                reason: "passkey_reenrollment_required".into(),
                            });
                        }
                        // BROWSER PROOF OF POSSESSION, FAIL-CLOSED: an enrolled production desktop requires a
                        // browser key in every token. The OFFER must carry a valid proof that the connecting browser
                        // signed its fingerprint with that key. Local certificate migration may relax only the
                        // passkey-cert requirement below; it never makes a keyless cloud token sufficient.
                        if self.require_browser_proof && claims.browser_pubkey.is_none() {
                            return Some(OutboundMsg::AuthRefused {
                                reason: "browser_proof_required".into(),
                            });
                        }
                        if let Some(pubkey) = claims.browser_pubkey.as_deref() {
                            let alg = claims.browser_pubkey_alg.as_deref().unwrap_or("ed25519");
                            let ok = match &self.offer_proof {
                                Some(p) => {
                                    // The proof's device id must be the token's device; verify the signature over
                                    // the offer's fingerprint against the token-embedded browser public key.
                                    p.device_id == claims.device_id
                                        && crate::browser_pop::verify_offer_proof(
                                            pubkey,
                                            alg,
                                            &claims.device_id,
                                            &p.fingerprint,
                                            &p.sig_b64,
                                        )
                                }
                                None => false, // token requires a proof but the offer carried none
                            };
                            if !ok {
                                return Some(OutboundMsg::AuthRefused {
                                    reason: "bad_browser_proof".into(),
                                });
                            }
                        }
                        // ACCESS PASSKEY (#11), FAIL-CLOSED: if this desktop pinned an account passkey, a valid
                        // browser certificate is MANDATORY — the cert proves the USER (not the cloud) authorized
                        // this browser key for this desktop/account. Crucially, the REQUIREMENT is driven by the
                        // LOCALLY-pinned passkey, NOT by any cloud-supplied field: a compromised cloud cannot
                        // downgrade by omitting the cert OR the browser_pubkey. The only escape is the LOCAL
                        // `allow_legacy_browsers` flag (desktop config), used during a migration window; the cloud
                        // can't set it. An enrolled channel with no pinned passkey was already refused above.
                        if let Some(passkey) = self.passkey.as_ref() {
                            if !self.allow_legacy_browsers {
                                // The cloud must have named a browser key (verified via PoP above) AND the offer
                                // must carry a cert. A missing browser_pubkey here means the token itself omitted
                                // it — refuse rather than trust a cloud that stripped the browser identity.
                                let Some(pubkey) = claims.browser_pubkey.as_deref() else {
                                    tracing::warn!(
                                        "passkey pinned but token has no browser_pubkey → refuse"
                                    );
                                    return Some(OutboundMsg::AuthRefused {
                                        reason: "browser_cert_required".into(),
                                    });
                                };
                                let Some(cert) = self.browser_cert.as_ref() else {
                                    tracing::warn!(
                                        "passkey pinned but offer carried no browser cert → refuse"
                                    );
                                    return Some(OutboundMsg::AuthRefused {
                                        reason: "browser_cert_required".into(),
                                    });
                                };
                                if let Err(e) = crate::browser_cert::verify_browser_cert(
                                    cert,
                                    passkey,
                                    pubkey,
                                    &self.this_desktop_id,
                                    &claims.account_id,
                                    now_ms,
                                    &self.cert_policy,
                                ) {
                                    tracing::warn!("browser cert rejected: {e:?}");
                                    return Some(OutboundMsg::AuthRefused {
                                        reason: "bad_browser_cert".into(),
                                    });
                                }
                                tracing::debug!("browser cert OK (passkey-authorized browser)");
                            } else if let (Some(pubkey), Some(cert)) =
                                (claims.browser_pubkey.as_deref(), self.browser_cert.as_ref())
                            {
                                // LOCAL migration mode ON: still VERIFY a cert if one was presented (a valid cert
                                // is always good), but a missing cert is tolerated for legacy browsers. Only the
                                // local operator can enable this; the cloud cannot.
                                if let Err(e) = crate::browser_cert::verify_browser_cert(
                                    cert,
                                    passkey,
                                    pubkey,
                                    &self.this_desktop_id,
                                    &claims.account_id,
                                    now_ms,
                                    &self.cert_policy,
                                ) {
                                    tracing::warn!("browser cert rejected (migration mode): {e:?}");
                                    return Some(OutboundMsg::AuthRefused {
                                        reason: "bad_browser_cert".into(),
                                    });
                                }
                            } else {
                                tracing::info!(
                                "browser connected WITHOUT a passkey cert (LOCAL migration mode enabled)"
                            );
                            }
                        }
                        let reply = OutboundMsg::AuthOk {
                            account_id: claims.account_id.clone(),
                            device_id: claims.device_id.clone(),
                            agent_build_git: public_agent_build_git(crate::build_git()),
                        };
                        // Initial authentication starts this channel's authority epoch. Never carry mutation
                        // replay state into it; in-band successors deliberately use the separate branch below.
                        self.creation_replay.clear();
                        self.authed_revocation_iat_ms = Some(claims.iat_ms);
                        self.authed_claims = Some(claims);
                        self.authed_token_sha256 = Some(Sha256::digest(token.as_bytes()).into());
                        // Capture the browser's correlation id so the peer loop can tag its trace events with it.
                        self.trace_id = sanitize_id_like(trace_id);
                        Some(reply)
                    }
                    Err(e) => Some(OutboundMsg::AuthRefused {
                        reason: refusal_reason(e).into(),
                    }),
                }
            }
            InboundMsg::AuthRefresh { token } => {
                if !self.browser_authorization_refresh {
                    return Some(OutboundMsg::AuthRefreshRefused {
                        reason: "unsupported".into(),
                    });
                }
                let Some(previous) = self.authed_claims.clone() else {
                    return Some(OutboundMsg::AuthRefreshRefused {
                        reason: "missing".into(),
                    });
                };
                let Some(previous_hash) = self.authed_token_sha256 else {
                    return Some(OutboundMsg::AuthRefreshRefused {
                        reason: "missing".into(),
                    });
                };
                let Some(initial_revocation_iat_ms) = self.authed_revocation_iat_ms else {
                    return Some(OutboundMsg::AuthRefreshRefused {
                        reason: "missing".into(),
                    });
                };
                let claims = match verify_token(
                    &token,
                    &self.cloud_pubkey,
                    now_ms,
                    &self.peer_device_id,
                    &self.revoked,
                ) {
                    Ok(claims) => claims,
                    Err(e) => {
                        return Some(OutboundMsg::AuthRefreshRefused {
                            reason: refusal_reason(e).into(),
                        })
                    }
                };
                let expected_parent = previous_hash
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect::<String>();
                let immutable_match = claims.account_id == previous.account_id
                    && claims.device_id == previous.device_id
                    && claims.session_id == previous.session_id
                    && claims.signal_session_id == previous.signal_session_id
                    && claims.target_device_id == previous.target_device_id
                    && claims.browser_pubkey == previous.browser_pubkey
                    && claims.browser_pubkey_alg == previous.browser_pubkey_alg;
                if claims.refresh_parent_sha256.as_deref() != Some(expected_parent.as_str())
                    || !immutable_match
                    || claims.iat_ms <= previous.iat_ms
                    || claims.exp_ms <= previous.exp_ms
                {
                    return Some(OutboundMsg::AuthRefreshRefused {
                        reason: "stale_continuity".into(),
                    });
                }
                if self
                    .expected_account_id
                    .as_deref()
                    .is_some_and(|expected| claims.account_id.as_str() != expected)
                {
                    return Some(OutboundMsg::AuthRefreshRefused {
                        reason: "wrong_account".into(),
                    });
                }
                if self.require_browser_proof && claims.browser_pubkey.is_none() {
                    return Some(OutboundMsg::AuthRefreshRefused {
                        reason: "browser_proof_required".into(),
                    });
                }
                if self.expected_signal_session_id.as_deref() != claims.signal_session_id.as_deref()
                    || (!self.this_desktop_id.is_empty()
                        && claims.target_device_id.as_deref()
                            != Some(self.this_desktop_id.as_str()))
                {
                    return Some(OutboundMsg::AuthRefreshRefused {
                        reason: "wrong_binding".into(),
                    });
                }
                // Recheck the original channel authority epoch immediately before admitting the successor. The
                // successor's newer iat orders the token chain; it must never reset account revoke-before history.
                if (self.revoked)(
                    &claims.account_id,
                    &self.peer_device_id,
                    initial_revocation_iat_ms,
                ) {
                    return Some(OutboundMsg::AuthRefreshRefused {
                        reason: "revoked".into(),
                    });
                }
                // Re-evaluate the already-present user-held certificate at the refresh instant. No background
                // WebAuthn authority is invented; once this certificate expires the channel must reconnect and
                // obtain another user-authorized certificate.
                if let Some(passkey) = self.passkey.as_ref() {
                    if !self.allow_legacy_browsers || self.browser_cert.is_some() {
                        let (Some(pubkey), Some(cert)) =
                            (claims.browser_pubkey.as_deref(), self.browser_cert.as_ref())
                        else {
                            return Some(OutboundMsg::AuthRefreshRefused {
                                reason: "browser_cert_required".into(),
                            });
                        };
                        if crate::browser_cert::verify_browser_cert(
                            cert,
                            passkey,
                            pubkey,
                            &self.this_desktop_id,
                            &claims.account_id,
                            now_ms,
                            &self.cert_policy,
                        )
                        .is_err()
                        {
                            return Some(OutboundMsg::AuthRefreshRefused {
                                reason: "bad_browser_cert".into(),
                            });
                        }
                    }
                }
                let expires_at_ms = claims.exp_ms;
                self.authed_token_sha256 = Some(Sha256::digest(token.as_bytes()).into());
                self.authed_claims = Some(claims);
                // Preserve TerminalBridge, attachments, winsize ownership and mutation replay state: immutable
                // authority did not change, only its short-lived expiry advanced.
                Some(OutboundMsg::AuthRefreshOk { expires_at_ms })
            }
            InboundMsg::ListRequest { request_id } => {
                // PRIVILEGED — connected ≠ authorized. Require a still-valid auth.
                if !self.is_authenticated() {
                    return Some(OutboundMsg::AuthRefused {
                        reason: "missing".into(),
                    });
                }
                // S3b stub: no real session data — proves the gate, returns empty.
                Some(OutboundMsg::ListResult {
                    request_id,
                    items: vec![],
                })
            }
            InboundMsg::ListAgentSessions {
                request_id,
                agent,
                cwd,
                include_hidden,
            } => {
                // PRIVILEGED — same auth gate as ListRequest.
                if !self.is_authenticated() {
                    return Some(OutboundMsg::AuthRefused {
                        reason: "missing".into(),
                    });
                }
                let cwd = sanitize_cwd(cwd);
                if self.desktop_access_refuses(cwd.iter().map(String::as_str), false) {
                    return Some(OutboundMsg::AgentSessionsError {
                        request_id,
                        code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                        message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                    });
                }
                let sessions = match sanitize_history_agent(agent) {
                    Some(agent) => filter_agent_sessions_for_wire(
                        &agent,
                        self.agent_session_lister.list(&agent, cwd, include_hidden),
                    ),
                    None => Vec::new(),
                };
                Some(OutboundMsg::AgentSessionsResult {
                    request_id,
                    sessions,
                })
            }
            InboundMsg::ListDirectories { request_id, path } => {
                // PRIVILEGED — same auth gate as the other list ops. Content-blind: subdirectory names/paths only.
                if !self.is_authenticated() {
                    return Some(OutboundMsg::AuthRefused {
                        reason: "missing".into(),
                    });
                }
                let path = sanitize_cwd(path);
                let access_path = path
                    .clone()
                    .unwrap_or_else(|| default_history_cwd().to_string_lossy().into_owned());
                if self.desktop_access_refuses(std::iter::once(access_path.as_str()), false) {
                    return Some(OutboundMsg::DirectoriesError {
                        request_id,
                        code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                        message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                    });
                }
                let listing = self.directory_lister.list(path.as_deref());
                Some(OutboundMsg::DirectoriesResult {
                    request_id,
                    path: listing.path,
                    parent: listing.parent,
                    entries: listing.entries,
                })
            }
            InboundMsg::PreviewAgentSession {
                request_id,
                agent,
                cwd,
                session_id,
                max_lines,
            } => {
                // PRIVILEGED — same auth gate. Carries transcript text by design (the user asked to preview it).
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::AgentSessionPreviewError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before previewing a session".into(),
                    });
                }
                let cwd = sanitize_cwd(cwd);
                if self.desktop_access_refuses(cwd.iter().map(String::as_str), false) {
                    return Some(OutboundMsg::AgentSessionPreviewError {
                        request_id,
                        code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                        message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                    });
                }
                let Some(agent) = sanitize_history_agent(agent) else {
                    // unknown agent → empty preview (mirrors the list handler's defensive empty)
                    return Some(OutboundMsg::AgentSessionPreview {
                        request_id,
                        lines: Vec::new(),
                    });
                };
                let Some(session_id) = exact_provider_session_id(&agent, session_id) else {
                    return Some(OutboundMsg::AgentSessionPreviewError {
                        request_id,
                        code: INVALID_PROVIDER_SESSION_ID_CODE.into(),
                        message: INVALID_PROVIDER_SESSION_ID_MESSAGE.into(),
                    });
                };
                match self.session_previewer.as_mut() {
                    Some(previewer) => {
                        let lines = previewer.preview(SessionPreviewRequest {
                            agent,
                            cwd,
                            session_id,
                            max_lines: max_lines.unwrap_or(40).clamp(1, 200), // bound the transcript slice
                        });
                        Some(OutboundMsg::AgentSessionPreview { request_id, lines })
                    }
                    None => Some(OutboundMsg::AgentSessionPreviewError {
                        request_id,
                        code: "not_implemented".into(),
                        message: "desktop-backed session preview not ready".into(),
                    }),
                }
            }
            InboundMsg::ManageAgentSession {
                request_id,
                action,
                agent,
                session_id,
                cwd,
                name,
            } => {
                // PRIVILEGED — same auth gate. Content-blind (ids/label only).
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::AgentSessionManageError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before managing a session".into(),
                    });
                }
                let cwd = sanitize_cwd(cwd);
                if self.desktop_access_refuses(cwd.iter().map(String::as_str), false) {
                    return Some(OutboundMsg::AgentSessionManageError {
                        request_id,
                        code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                        message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                    });
                }
                let action = match action.as_str() {
                    "rename" => SessionManageAction::Rename {
                        name: sanitize_label(name),
                    },
                    "hide" => SessionManageAction::Hide,
                    "unhide" => SessionManageAction::Unhide { cwd },
                    "delete" => SessionManageAction::Delete { cwd },
                    _ => {
                        return Some(OutboundMsg::AgentSessionManageError {
                            request_id,
                            code: "invalid_action".into(),
                            message: "action must be rename, hide, unhide, or delete".into(),
                        });
                    }
                };
                let Some(agent) = sanitize_history_agent(agent) else {
                    return Some(OutboundMsg::AgentSessionManageError {
                        request_id,
                        code: SessionManageError::NotFound.code().into(),
                        message: "unknown agent".into(),
                    });
                };
                let Some(session_id) = exact_provider_session_id(&agent, session_id) else {
                    return Some(OutboundMsg::AgentSessionManageError {
                        request_id,
                        code: INVALID_PROVIDER_SESSION_ID_CODE.into(),
                        message: INVALID_PROVIDER_SESSION_ID_MESSAGE.into(),
                    });
                };
                match self.session_manager.as_mut() {
                    Some(manager) => match manager.manage(SessionManageRequest {
                        agent,
                        session_id,
                        action,
                    }) {
                        Ok(()) => Some(OutboundMsg::AgentSessionManaged { request_id }),
                        Err(e) => Some(OutboundMsg::AgentSessionManageError {
                            request_id,
                            code: e.code().into(),
                            message: "could not manage session".into(),
                        }),
                    },
                    None => Some(OutboundMsg::AgentSessionManageError {
                        request_id,
                        code: "not_implemented".into(),
                        message: "desktop-backed session manage not ready".into(),
                    }),
                }
            }
            InboundMsg::SplitPane {
                request_id,
                window_id,
                from_pane_id,
                dir,
                agent,
                launch_flags,
                cwd,
                pane_name,
                cols,
                rows,
            } => {
                // PRIVILEGED — same auth/revoke gate as create_session.
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::SplitPaneError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before splitting a pane".into(),
                    });
                }
                let cwd = cwd
                    .map(|cwd| cwd.trim().to_string())
                    .filter(|cwd| !cwd.is_empty());
                let explicit_resume_file = resume_file_from_launch_flags(&launch_flags);
                let access_paths = cwd
                    .iter()
                    .map(String::as_str)
                    .chain(explicit_resume_file.iter().map(String::as_str));
                if self.desktop_access_refuses(access_paths, cwd.is_none()) {
                    return Some(OutboundMsg::SplitPaneError {
                        request_id,
                        code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                        message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                    });
                }
                Some(self.with_creation_replay(
                    CreationRequestKind::SplitPane,
                    request_id,
                    line,
                    now_ms,
                    move |this, request_id| {
                        let dir = match sanitize_split_dir(&dir) {
                            Some(dir) => dir,
                            None => {
                                return OutboundMsg::SplitPaneError {
                                    request_id,
                                    code: SplitPaneCreateError::InvalidDirection.code().into(),
                                    message: "split direction must be right or down".into(),
                                };
                            }
                        };
                        let agent = match validate_optional_agent(agent, sanitize_split_agent) {
                            Ok(agent) => agent,
                            Err(error) => {
                                return OutboundMsg::SplitPaneError {
                                    request_id,
                                    code: error.code().into(),
                                    message: error.message().into(),
                                };
                            }
                        };
                        match this.pane_splitter.as_mut() {
                            Some(splitter) => match splitter.split_pane_with_initial_size(
                                SplitPaneRequest {
                                    window_id: sanitize_id_like(window_id),
                                    from_pane_id: sanitize_id_like(from_pane_id),
                                    dir,
                                    // Split allows "terminal" (plain-bash pane; the splitter records Shell + OptOut)
                                    // on top of the three launch agents — plain sanitize_agent would drop it and
                                    // silently turn the user's Terminal choice into "inherit the sibling".
                                    agent,
                                    launch_flags,
                                    cwd,
                                    pane_name: sanitize_pane_name(pane_name),
                                    now_ms,
                                },
                                crate::session_creator::InitialTerminalSize::from_optional_pair(
                                    cols, rows,
                                ),
                            ) {
                                Ok(created) => OutboundMsg::SplitPaneOk {
                                    request_id,
                                    session_id: created.session_id,
                                    tab_id: created.tab_id,
                                },
                                Err(e) => OutboundMsg::SplitPaneError {
                                    request_id,
                                    code: e.code().into(),
                                    message: "could not split pane".into(),
                                },
                            },
                            None => OutboundMsg::SplitPaneError {
                                request_id,
                                code: "not_implemented".into(),
                                message: "desktop-backed split not ready".into(),
                            },
                        }
                    },
                ))
            }
            InboundMsg::NewPane {
                request_id,
                window_id,
                from_pane_id,
                agent,
                launch_flags,
                cwd,
                pane_name,
                cols,
                rows,
            } => {
                // PRIVILEGED — same auth/revoke gate as split_pane.
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::SplitPaneError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before creating a pane".into(),
                    });
                }
                let cwd = cwd
                    .map(|cwd| cwd.trim().to_string())
                    .filter(|cwd| !cwd.is_empty());
                let explicit_resume_file = resume_file_from_launch_flags(&launch_flags);
                let access_paths = cwd
                    .iter()
                    .map(String::as_str)
                    .chain(explicit_resume_file.iter().map(String::as_str));
                if self.desktop_access_refuses(access_paths, cwd.is_none()) {
                    return Some(OutboundMsg::SplitPaneError {
                        request_id,
                        code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                        message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                    });
                }
                Some(self.with_creation_replay(
                    CreationRequestKind::NewPane,
                    request_id,
                    line,
                    now_ms,
                    move |this, request_id| {
                        let agent = match validate_optional_agent(agent, sanitize_split_agent) {
                            Ok(agent) => agent,
                            Err(error) => {
                                return OutboundMsg::SplitPaneError {
                                    request_id,
                                    code: error.code().into(),
                                    message: error.message().into(),
                                };
                            }
                        };
                        match this.pane_splitter.as_mut() {
                            Some(splitter) => match splitter.new_pane_with_initial_size(
                                SplitPaneRequest {
                                    window_id: sanitize_id_like(window_id),
                                    from_pane_id: sanitize_id_like(from_pane_id),
                                    dir: SplitPaneDir::Right,
                                    agent,
                                    launch_flags,
                                    cwd,
                                    pane_name: sanitize_pane_name(pane_name),
                                    now_ms,
                                },
                                crate::session_creator::InitialTerminalSize::from_optional_pair(
                                    cols, rows,
                                ),
                            ) {
                                Ok(created) => OutboundMsg::SplitPaneOk {
                                    request_id,
                                    session_id: created.session_id,
                                    tab_id: created.tab_id,
                                },
                                Err(e) => OutboundMsg::SplitPaneError {
                                    request_id,
                                    code: e.code().into(),
                                    message: "could not create pane".into(),
                                },
                            },
                            None => OutboundMsg::SplitPaneError {
                                request_id,
                                code: "not_implemented".into(),
                                message: "desktop-backed pane create not ready".into(),
                            },
                        }
                    },
                ))
            }
            InboundMsg::RevivePane {
                request_id,
                window_id,
                pane_id,
                cols,
                rows,
            } => {
                // PRIVILEGED — same auth/revoke gate as split_pane.
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::RevivePaneError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before reviving a pane".into(),
                    });
                }
                if self.desktop_access_refuses(std::iter::empty(), true) {
                    return Some(OutboundMsg::RevivePaneError {
                        request_id,
                        code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                        message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                    });
                }
                // Browser layout remains separate, but a desktop-stashed pane must be revived on the desktop so the
                // local renderer can paint it and stream fresh frames to the browser.
                Some(self.with_creation_replay(
                    CreationRequestKind::RevivePane,
                    request_id,
                    line,
                    now_ms,
                    move |this, request_id| match this.pane_reviver.as_mut() {
                        Some(reviver) => match reviver.revive_pane_with_initial_size(
                            RevivePaneRequest {
                                window_id: sanitize_id_like(window_id),
                                pane_id: sanitize_id_like(pane_id),
                                now_ms,
                            },
                            crate::session_creator::InitialTerminalSize::from_optional_pair(
                                cols, rows,
                            ),
                        ) {
                            Ok(created) => OutboundMsg::RevivePaneOk {
                                request_id,
                                session_id: created.session_id,
                            },
                            Err(e) => OutboundMsg::RevivePaneError {
                                request_id,
                                code: e.code().into(),
                                message: "could not restore pane".into(),
                            },
                        },
                        None => OutboundMsg::RevivePaneError {
                            request_id,
                            code: "not_implemented".into(),
                            message: "desktop-backed pane revive not ready".into(),
                        },
                    },
                ))
            }
            InboundMsg::StartPaneSession {
                request_id,
                window_id,
                pane_id,
                cols,
                rows,
            } => {
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::StartPaneSessionError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before starting a pane session".into(),
                    });
                }
                if self.desktop_access_refuses(std::iter::empty(), true) {
                    return Some(OutboundMsg::StartPaneSessionError {
                        request_id,
                        code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                        message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                    });
                }
                Some(self.with_creation_replay(
                    CreationRequestKind::StartPaneSession,
                    request_id,
                    line,
                    now_ms,
                    move |this, request_id| match this.pane_session_starter.as_mut() {
                        Some(starter) => match starter.start_pane_session_with_initial_size(
                            RevivePaneRequest {
                                window_id: sanitize_id_like(window_id),
                                pane_id: sanitize_id_like(pane_id),
                                now_ms,
                            },
                            crate::session_creator::InitialTerminalSize::from_optional_pair(
                                cols, rows,
                            ),
                        ) {
                            Ok(created) => {
                                eprintln!(
                                    "remote start_pane_session ok sid={}",
                                    created.session_id
                                );
                                OutboundMsg::StartPaneSessionOk {
                                    request_id,
                                    session_id: created.session_id,
                                }
                            }
                            Err(e) => {
                                eprintln!("remote start_pane_session error code={}", e.code());
                                OutboundMsg::StartPaneSessionError {
                                    request_id,
                                    code: e.code().into(),
                                    message: "could not start pane session".into(),
                                }
                            }
                        },
                        None => OutboundMsg::StartPaneSessionError {
                            request_id,
                            code: "not_implemented".into(),
                            message: "pane session start not ready".into(),
                        },
                    },
                ))
            }
            InboundMsg::StashPane {
                request_id,
                window_id,
                pane_id,
            } => {
                // PRIVILEGED — same auth/revoke gate as revive.
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::StashPaneError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before stashing a pane".into(),
                    });
                }
                // SEPARATE LAYOUTS: stash is REMOTE-ONLY. Never flip the desktop pane's stashed flag (that turned open
                // local panes gray/yellow). The browser stashes in its OWN layout; the desktop is untouched.
                let _ = (&window_id, &pane_id);
                Some(OutboundMsg::StashPaneError {
                    request_id,
                    code: "not_applied".into(),
                    message: "stash is remote-only; the desktop layout is not modified".into(),
                })
            }
            InboundMsg::RemovePane {
                request_id,
                window_id,
                pane_id,
            } => {
                // PRIVILEGED — same auth/revoke gate as stash/revive.
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::RemovePaneError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before removing a pane".into(),
                    });
                }
                // EXISTENCE MODEL: unlike stash/revive (per-surface ARRANGEMENT, remote-only by design),
                // "Remove from shelf" is a DESTRUCTIVE EXISTENCE deletion — the pane record ceases to exist
                // everywhere, exactly like close_window/delete_project, which the remote IS allowed to
                // command. Refusing it here made remote Remove-from-shelf a no-op (the desktop record
                // survived and every metadata refresh resurrected the pane in the browser). Route it to the
                // desktop remover (WindowLayoutService::close_pane — drops the layout/shelf record only;
                // the daemon session is not killed).
                match self.pane_remover.as_mut() {
                    Some(remover) => match remover.remove_pane(RemovePaneRequest {
                        window_id: sanitize_id_like(window_id),
                        pane_id: sanitize_id_like(pane_id),
                        now_ms,
                    }) {
                        Ok(()) => Some(OutboundMsg::RemovePaneOk { request_id }),
                        Err(e) => {
                            let message = if e == RevivePaneError::GloballyLastVisible {
                                "the globally last visible window must remain open"
                            } else {
                                "could not remove the pane"
                            };
                            Some(OutboundMsg::RemovePaneError {
                                request_id,
                                code: e.code().into(),
                                message: message.into(),
                            })
                        }
                    },
                    None => Some(OutboundMsg::RemovePaneError {
                        request_id,
                        code: "not_implemented".into(),
                        message: "desktop-backed remove not ready".into(),
                    }),
                }
            }
            InboundMsg::Rename {
                request_id,
                window_id,
                pane_id,
                name,
            } => {
                // PRIVILEGED — same auth/revoke gate as the other ops.
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::RenameError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before renaming".into(),
                    });
                }
                // A rename with no usable name is rejected here (don't ask the desktop to set an empty title).
                let Some(name) = sanitize_label(Some(name)) else {
                    return Some(OutboundMsg::RenameError {
                        request_id,
                        code: RenameError::InvalidName.code().into(),
                        message: "name must be non-empty".into(),
                    });
                };
                match self.renamer.as_mut() {
                    Some(renamer) => match renamer.rename(RenameRequest {
                        window_id: sanitize_id_like(window_id),
                        pane_id: pane_id.map(sanitize_id_like),
                        name,
                        now_ms,
                    }) {
                        Ok(()) => Some(OutboundMsg::RenameOk { request_id }),
                        Err(e) => Some(OutboundMsg::RenameError {
                            request_id,
                            code: e.code().into(),
                            message: "could not rename".into(),
                        }),
                    },
                    None => Some(OutboundMsg::RenameError {
                        request_id,
                        code: "not_implemented".into(),
                        message: "desktop-backed rename not ready".into(),
                    }),
                }
            }
            InboundMsg::FocusWindow {
                request_id,
                window_id,
            } => {
                // PRIVILEGED — this switches the user's real desktop window, so it uses the same auth/revoke
                // boundary as split/revive/rename/close. The payload is only a window id.
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::FocusWindowError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before focusing a window".into(),
                    });
                }
                match self.window_focuser.as_mut() {
                    Some(focuser) => {
                        match focuser.focus_window(sanitize_id_like(window_id), now_ms) {
                            Ok(()) => Some(OutboundMsg::FocusWindowOk { request_id }),
                            Err(e) => Some(OutboundMsg::FocusWindowError {
                                request_id,
                                code: e.code().into(),
                                message: "could not focus window".into(),
                            }),
                        }
                    }
                    None => Some(OutboundMsg::FocusWindowError {
                        request_id,
                        code: "not_implemented".into(),
                        message: "live desktop focus hook not ready".into(),
                    }),
                }
            }
            InboundMsg::CloseWindow {
                request_id,
                window_id,
            } => {
                // PRIVILEGED — same auth/revoke gate as the other ops. DESTRUCTIVE (tears down the window) so the
                // browser side should confirm; the wire stays a plain authed request.
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::CloseWindowError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before closing a window".into(),
                    });
                }
                match self.window_closer.as_mut() {
                    Some(closer) => {
                        match closer.close_window(sanitize_id_like(window_id), now_ms) {
                            Ok(()) => Some(OutboundMsg::CloseWindowOk { request_id }),
                            Err(e) => Some(OutboundMsg::CloseWindowError {
                                request_id,
                                code: e.code().into(),
                                message: e.message().into(),
                            }),
                        }
                    }
                    None => Some(OutboundMsg::CloseWindowError {
                        request_id,
                        code: "not_implemented".into(),
                        message: "desktop-backed close window not ready".into(),
                    }),
                }
            }
            InboundMsg::NewWindow {
                request_id,
                project_id,
                name,
                cwd,
                agent,
                launch_flags,
                cols,
                rows,
            } => {
                // PRIVILEGED — same auth/revoke gate as split/revive.
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::NewWindowError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before creating a window".into(),
                    });
                }
                let cwd = sanitize_cwd(cwd);
                let explicit_resume_file = resume_file_from_launch_flags(&launch_flags);
                let access_paths = cwd
                    .iter()
                    .map(String::as_str)
                    .chain(explicit_resume_file.iter().map(String::as_str));
                if self.desktop_access_refuses(access_paths, cwd.is_none()) {
                    return Some(OutboundMsg::NewWindowError {
                        request_id,
                        code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                        message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                    });
                }
                Some(self.with_creation_replay(
                    CreationRequestKind::NewWindow,
                    request_id,
                    line,
                    now_ms,
                    move |this, request_id| {
                        let agent = match validate_optional_agent(agent, sanitize_split_agent) {
                            Ok(agent) => agent,
                            Err(error) => {
                                return OutboundMsg::NewWindowError {
                                    request_id,
                                    code: error.code().into(),
                                    message: error.message().into(),
                                };
                            }
                        };
                        match this.window_opener.as_mut() {
                            Some(opener) => match opener.new_window_with_initial_size(
                                NewWindowRequest {
                                    project_id: sanitize_id_like(project_id),
                                    name: sanitize_label(Some(name)).unwrap_or_default(),
                                    cwd,
                                    // New-window allows "terminal" (plain-bash first pane; the opener records
                                    // Shell + OptOut) exactly like split — plain sanitize_agent would drop it and
                                    // silently turn the user's Terminal choice into "project default agent".
                                    agent,
                                    launch_flags,
                                    now_ms,
                                },
                                crate::session_creator::InitialTerminalSize::from_optional_pair(
                                    cols, rows,
                                ),
                            ) {
                                Ok(created) => OutboundMsg::NewWindowOk {
                                    request_id,
                                    window_id: created.window_id,
                                    session_id: created.session_id,
                                },
                                Err(e) => OutboundMsg::NewWindowError {
                                    request_id,
                                    code: e.code().into(),
                                    message: "could not create window".into(),
                                },
                            },
                            None => OutboundMsg::NewWindowError {
                                request_id,
                                code: "not_implemented".into(),
                                message: "desktop-backed new window not ready".into(),
                            },
                        }
                    },
                ))
            }
            InboundMsg::ProjectCreate {
                request_id,
                name,
                root,
                icon,
                accent_color,
                agent,
                resume_mode,
                resume_session_id,
                model,
                dangerous,
                custom_command,
                directories,
                cols,
                rows,
            } => {
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::ProjectEditError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before editing projects".into(),
                    });
                }
                let root = sanitize_cwd(Some(root));
                let directories = sanitize_directories(directories);
                let protected_paths = root.iter().map(String::as_str).chain(
                    directories
                        .iter()
                        .flatten()
                        .map(|directory| directory.path.as_str()),
                );
                if self.desktop_access_refuses(protected_paths, false) {
                    return Some(OutboundMsg::ProjectEditError {
                        request_id,
                        code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                        message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                    });
                }
                Some(self.with_creation_replay(
                    CreationRequestKind::ProjectCreate,
                    request_id,
                    line,
                    now_ms,
                    move |this, request_id| {
                        // Project launch defaults use the same provider vocabulary as the desktop picker,
                        // including the explicit `terminal` sentinel. An absent provider keeps the legacy
                        // default; an explicit unknown one must not be persisted as that default by accident.
                        let agent = match validate_optional_agent(agent, sanitize_split_agent) {
                            Ok(agent) => agent,
                            Err(error) => {
                                return OutboundMsg::ProjectEditError {
                                    request_id,
                                    code: error.code().into(),
                                    message: error.message().into(),
                                };
                            }
                        };
                        let resume_session_id =
                            sanitize_resume_session_id(agent.as_deref(), resume_session_id);
                        let req = ProjectEditRequest {
                            project_id: None,
                            name: sanitize_label(Some(name)),
                            root,
                            icon: sanitize_label(icon),
                            accent_color: sanitize_accent_color(accent_color),
                            agent,
                            resume_mode: sanitize_resume_mode(resume_mode),
                            resume_session_id,
                            model: sanitize_model(model),
                            dangerous,
                            custom_command: sanitize_custom_command(custom_command),
                            directories,
                            now_ms,
                        };
                        match this.project_editor.as_mut() {
                            Some(editor) => match editor.create_project_with_initial_size(
                                req,
                                crate::session_creator::InitialTerminalSize::from_optional_pair(
                                    cols, rows,
                                ),
                            ) {
                                Ok(edited) => OutboundMsg::ProjectEditOk {
                                    request_id,
                                    project_id: edited.project_id,
                                    session_id: edited.session_id,
                                },
                                Err(e) => OutboundMsg::ProjectEditError {
                                    request_id,
                                    code: e.code().into(),
                                    message: "could not edit project".into(),
                                },
                            },
                            None => OutboundMsg::ProjectEditError {
                                request_id,
                                code: "not_implemented".into(),
                                message: "desktop-backed project create not ready".into(),
                            },
                        }
                    },
                ))
            }
            InboundMsg::ProjectUpdate {
                request_id,
                project_id,
                name,
                root,
                icon,
                accent_color,
                agent,
                resume_mode,
                resume_session_id,
                model,
                dangerous,
                custom_command,
                directories,
            } => {
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::ProjectEditError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before editing projects".into(),
                    });
                }
                let root = sanitize_cwd(root);
                let directories = sanitize_directories(directories);
                let protected_paths = root.iter().map(String::as_str).chain(
                    directories
                        .iter()
                        .flatten()
                        .map(|directory| directory.path.as_str()),
                );
                if self.desktop_access_refuses(protected_paths, false) {
                    return Some(OutboundMsg::ProjectEditError {
                        request_id,
                        code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                        message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                    });
                }
                let agent = match validate_optional_agent(agent, sanitize_split_agent) {
                    Ok(agent) => agent,
                    Err(error) => {
                        return Some(OutboundMsg::ProjectEditError {
                            request_id,
                            code: error.code().into(),
                            message: error.message().into(),
                        });
                    }
                };
                let resume_session_id =
                    sanitize_resume_session_id(agent.as_deref(), resume_session_id);
                let req = ProjectEditRequest {
                    project_id: Some(sanitize_id_like(project_id)),
                    name: name.and_then(|n| sanitize_label(Some(n))),
                    root,
                    icon: icon.and_then(|i| sanitize_label(Some(i))),
                    accent_color: sanitize_accent_color(accent_color),
                    agent,
                    resume_mode: sanitize_resume_mode(resume_mode),
                    resume_session_id,
                    model: sanitize_model(model),
                    dangerous,
                    custom_command: sanitize_custom_command(custom_command),
                    directories,
                    now_ms,
                };
                match self.project_editor.as_mut() {
                    Some(editor) => project_edit_reply(request_id, editor.update_project(req)),
                    None => Some(OutboundMsg::ProjectEditError {
                        request_id,
                        code: "not_implemented".into(),
                        message: "desktop-backed project update not ready".into(),
                    }),
                }
            }
            InboundMsg::DeleteProject {
                request_id,
                project_id,
            } => {
                // PRIVILEGED — same auth/revoke gate as the other project ops. DESTRUCTIVE (removes the project
                // record) so the browser side should confirm; the wire stays a plain authed request.
                if let Some(code) = self.privileged_refusal() {
                    return Some(OutboundMsg::ProjectEditError {
                        request_id,
                        code: code.into(),
                        message: "authenticate before editing projects".into(),
                    });
                }
                match self.project_editor.as_mut() {
                    Some(editor) => project_edit_reply(
                        request_id,
                        editor.delete_project(sanitize_id_like(project_id), now_ms),
                    ),
                    None => Some(OutboundMsg::ProjectEditError {
                        request_id,
                        code: "not_implemented".into(),
                        message: "desktop-backed project delete not ready".into(),
                    }),
                }
            }
            InboundMsg::CreateSession {
                request_id,
                label,
                cwd,
                agent,
                launch_flags,
                cols,
                rows,
            } => {
                // PRIVILEGED — connected ≠ authorized. Distinguish unauth from revoked: was the channel
                // authed, and is it STILL authed after the revoke re-check?
                let was_authed = self.is_authenticated();
                if self.authenticated_claims().is_none() {
                    let (code, message) = if was_authed {
                        (
                            "revoked",
                            "this device was revoked — re-enroll to reconnect",
                        )
                    } else {
                        (
                            "unauthenticated",
                            "sign in / authenticate before creating a session",
                        )
                    };
                    return Some(OutboundMsg::SessionCreateError {
                        request_id,
                        code: code.into(),
                        message: message.into(),
                    });
                }
                let cwd = sanitize_cwd(cwd);
                Some(self.with_creation_replay(
                    CreationRequestKind::CreateSession,
                    request_id,
                    line,
                    now_ms,
                    move |this, request_id| {
                        // RELEASE HOLD: raw create_session has no durable product record that can retain the
                        // exact daemon instance + operation token after a pre-Grid
                        // ConditionalStartPossiblyApplied result. Production therefore leaves the creator seam
                        // absent and refuses here before permission inspection, daemon IO, or durable writes.
                        // Desktop-backed new_pane/split_pane are separate prepared-topology operations.
                        if this.session_creator.is_none() {
                            return OutboundMsg::SessionCreateError {
                                request_id,
                                code: RECORDLESS_CREATION_HELD_CODE.into(),
                                message: RECORDLESS_CREATION_HELD_MESSAGE.into(),
                            };
                        }
                        let access_cwd = cwd.clone().unwrap_or_else(|| {
                            default_history_cwd().to_string_lossy().into_owned()
                        });
                        let explicit_resume_file = resume_file_from_launch_flags(&launch_flags);
                        let access_paths = std::iter::once(access_cwd.as_str())
                            .chain(explicit_resume_file.iter().map(String::as_str));
                        if this.desktop_access_refuses(access_paths, false) {
                            return OutboundMsg::SessionCreateError {
                                request_id,
                                code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                                message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                            };
                        }
                        // F1: sanitize the optional label (user metadata shown in the UI) — strip control chars,
                        // trim, cap length; an empty result becomes None. Never logged as terminal payload.
                        let label = sanitize_label(label);
                        // Content-blind model NAME from launch_flags — appended as ["--model", <name>] to the
                        // built launch's argv (resume, or a fresh explicit-agent launch).
                        let model = model_from_launch_flags(&launch_flags);
                        let dangerous = dangerous_from_launch_flags(&launch_flags);
                        // Preserve the intentional legacy shell path only when the provider is absent, or when the
                        // browser explicitly selected the known `terminal` sentinel. An explicit unknown/future
                        // provider is a typed refusal: it must never look like a successful bare-shell creation.
                        let agent = match validate_optional_agent(agent, sanitize_split_agent) {
                            Ok(agent) => agent,
                            Err(error) => {
                                return OutboundMsg::SessionCreateError {
                                    request_id,
                                    code: error.code().into(),
                                    message: error.message().into(),
                                };
                            }
                        };
                        let fresh_agent =
                            agent.clone().filter(|agent| agent.as_str() != "terminal");
                        let mut resume = resume_descriptor_from_launch_flags(agent, launch_flags);
                        // Current Gemini UUIDs resume directly. Legacy history rows may still need a local
                        // session-file import path, which remains off the content-blind browser wire.
                        if let Some(descriptor) = resume.as_mut() {
                            resolve_gemini_resume_file(descriptor, cwd.as_deref());
                        }
                        // authenticated → create via the injected daemon seam (id-gen + collision + start_session).
                        match this.session_creator.as_mut() {
                            Some(creator) => {
                                match crate::session_creator::create_session_with_initial_size(
                                    creator.as_mut(),
                                    &crate::session_creator::CreateSessionRequest {
                                        cwd,
                                        resume,
                                        model,
                                        dangerous,
                                        agent: fresh_agent,
                                    },
                                    crate::session_creator::InitialTerminalSize::from_optional_pair(
                                        cols, rows,
                                    ),
                                ) {
                                    Ok(session_id) => OutboundMsg::SessionCreated {
                                        request_id,
                                        session_id,
                                        label,
                                    },
                                    Err(e) => OutboundMsg::SessionCreateError {
                                        request_id,
                                        code: e.code().into(),
                                        message: "could not create a session".into(),
                                    },
                                }
                            }
                            None => OutboundMsg::SessionCreateError {
                                request_id,
                                code: RECORDLESS_CREATION_HELD_CODE.into(),
                                message: RECORDLESS_CREATION_HELD_MESSAGE.into(),
                            },
                        }
                    },
                ))
            }
        }
    }
}

fn desktop_access_status_message(status: DesktopAccessStatus) -> OutboundMsg {
    let full_disk_access = match status {
        DesktopAccessStatus::Granted => "granted",
        DesktopAccessStatus::Required => "required",
        DesktopAccessStatus::Unknown => "unknown",
        DesktopAccessStatus::NotApplicable => "not_applicable",
    };
    OutboundMsg::DesktopAccessStatus {
        platform: desktop_access_platform().to_string(),
        full_disk_access: full_disk_access.to_string(),
    }
}

fn desktop_access_platform() -> &'static str {
    if cfg!(target_os = "macos") {
        "macos"
    } else if cfg!(target_os = "linux") {
        "linux"
    } else {
        "other"
    }
}

/// F1: sanitize a user-supplied session label — strip control chars, collapse to a trimmed string, cap at
/// 64 chars. Returns None for absent/blank labels so the UI falls back to the session id. (Mirrors the
/// cloud-side `scrubLabel` contract; labels are metadata, never terminal payload.)
fn sanitize_label(label: Option<String>) -> Option<String> {
    let cleaned: String = label?
        .chars()
        .filter(|c| !c.is_control())
        .take(64)
        .collect();
    let trimmed = cleaned.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed.to_string())
    }
}

/// Accept only an absolute, bounded, single-line path as launch metadata. Invalid/blank cwd falls back to
/// the desktop agent's default home rather than failing session creation.
fn sanitize_cwd(cwd: Option<String>) -> Option<String> {
    let cleaned: String = cwd?.chars().filter(|c| !c.is_control()).take(512).collect();
    let trimmed = cleaned.trim();
    if trimmed.starts_with('/') && !trimmed.is_empty() {
        Some(trimmed.to_string())
    } else {
        None
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AgentValidationError {
    UnsupportedProvider,
}

impl AgentValidationError {
    fn code(self) -> &'static str {
        match self {
            AgentValidationError::UnsupportedProvider => "unsupported_provider",
        }
    }

    fn message(self) -> &'static str {
        match self {
            AgentValidationError::UnsupportedProvider => "unsupported agent provider",
        }
    }
}

/// Validate an OPTIONAL provider without collapsing two semantically different inputs:
///
/// - `None` is the intentional legacy/default path (bare terminal or inherited project provider).
/// - `Some(unknown)` is an explicit request and must fail closed instead of becoming `None`.
///
/// The supplied sanitizer selects the operation's vocabulary: provider-only, or provider + the known
/// `terminal` sentinel. The untrusted raw value is never echoed in a response or log.
fn validate_optional_agent(
    agent: Option<String>,
    sanitizer: fn(String) -> Option<String>,
) -> Result<Option<String>, AgentValidationError> {
    match agent {
        None => Ok(None),
        Some(agent) => sanitizer(agent)
            .map(Some)
            .ok_or(AgentValidationError::UnsupportedProvider),
    }
}

fn sanitize_agent(agent: String) -> Option<String> {
    match agent.as_str() {
        "claude" | "codex" | "copilot" | "antigravity" | "kimi" | "kiro" | "cursor" | "amp"
        | "devin" | "factory" | "gemini" | "opencode" => Some(agent),
        _ => None,
    }
}

/// History access is a narrower capability than launch access. Amp and Factory are launchable, but their
/// provider stores have not been qualified, so forged list/preview/manage requests must stop at this boundary.
fn sanitize_history_agent(agent: String) -> Option<String> {
    match agent.as_str() {
        "claude" | "codex" | "copilot" | "antigravity" | "kimi" | "kiro" | "cursor" | "gemini"
        | "opencode" | "devin" => Some(agent),
        _ => None,
    }
}

/// Provider session identities are authority-bearing selectors, not display text. Accept only values that the
/// provider-specific normalizer leaves byte-for-byte unchanged; trimming, control stripping, truncation, or UUID
/// canonicalization could otherwise alias a different provider session.
fn exact_provider_session_id(agent: &str, candidate: String) -> Option<String> {
    let normalized = normalize_provider_session_id(agent, &candidate)?;
    (normalized == candidate).then_some(normalized)
}

/// Provider stores and injected listers are untrusted input. Keep malformed or cross-provider rows off the wire
/// even if a lower history layer regresses, applying the same exact non-aliasing contract as preview/manage.
fn filter_agent_sessions_for_wire(
    requested_agent: &str,
    sessions: Vec<AgentSessionMeta>,
) -> Vec<AgentSessionMeta> {
    sessions
        .into_iter()
        .filter(|session| {
            session.agent == requested_agent
                && normalize_provider_session_id(requested_agent, &session.id).as_deref()
                    == Some(session.id.as_str())
        })
        .collect()
}

/// User-facing launch pickers additionally allow "terminal" — a deliberate plain-bash pane/project default,
/// mirroring the local dialogs' Terminal choice. Kept separate from [`sanitize_agent`] because resume/history
/// operations accept only runnable providers.
fn sanitize_split_agent(agent: String) -> Option<String> {
    if agent.as_str() == "terminal" {
        return Some(agent);
    }
    sanitize_agent(agent)
}

/// Optional pane display name (the split dialog's "Pane name") — strip control chars, trim, cap at 80.
/// Blank/absent → None (the splitter falls back to the agent-derived title). Metadata only, like
/// [`sanitize_label`]; never terminal payload.
fn sanitize_pane_name(name: Option<String>) -> Option<String> {
    let cleaned: String = name?.chars().filter(|c| !c.is_control()).take(80).collect();
    let trimmed = cleaned.trim();
    (!trimmed.is_empty()).then(|| trimmed.to_string())
}

/// Content-blind model NAME from the browser's `launch_flags` (`{"model": "..."}`, same field the desktop
/// dialogs use). Model labels are provider-owned (Antigravity currently uses spaces and parentheses), so the
/// safe boundary is: trimmed, non-empty, bounded, and free of control characters. The value remains one
/// discrete argv member; the login-shell adapter must quote it rather than interpreting its punctuation.
pub(crate) fn model_from_launch_flags(launch_flags: &Option<serde_json::Value>) -> Option<String> {
    let obj = launch_flags.as_ref()?.as_object()?;
    let raw = obj.get("model").and_then(|value| value.as_str())?;
    sanitize_model_name(raw)
}

fn resume_file_from_launch_flags(launch_flags: &Option<serde_json::Value>) -> Option<String> {
    let object = launch_flags.as_ref()?.as_object()?;
    object
        .get("resumeSessionFile")
        .or_else(|| object.get("resume_session_file"))
        .and_then(serde_json::Value::as_str)
        .and_then(|path| sanitize_cwd(Some(path.to_string())))
}

/// The browser's checkbox is a boolean capability request, never a raw flag. The provider registry on the
/// desktop chooses the exact allowlisted argv later (notably Copilot is `--yolo`, never an inferred alias).
pub(crate) fn dangerous_from_launch_flags(launch_flags: &Option<serde_json::Value>) -> bool {
    let Some(obj) = launch_flags.as_ref().and_then(serde_json::Value::as_object) else {
        return false;
    };
    obj.get("dangerouslySkipPermissions")
        .or_else(|| obj.get("dangerous_skip_permissions"))
        .or_else(|| obj.get("dangerous"))
        .and_then(serde_json::Value::as_bool)
        .unwrap_or(false)
}

/// The argv-safe model-NAME check itself, factored out of [`model_from_launch_flags`] so plain-field
/// callers (project-create seeding carries `model` as a top-level field, not inside launch_flags) apply the
/// exact same rule before putting the name on a start line.
pub(crate) fn sanitize_model_name(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().count() > 96 || trimmed.chars().any(char::is_control) {
        return None;
    }
    Some(trimmed.to_string())
}

fn sanitize_split_dir(dir: &str) -> Option<SplitPaneDir> {
    match dir {
        "right" | "h" | "horizontal" => Some(SplitPaneDir::Right),
        "down" | "v" | "vertical" => Some(SplitPaneDir::Down),
        _ => None,
    }
}

fn sanitize_id_like(id: String) -> String {
    id.chars()
        .filter(|c| !c.is_control())
        .take(128)
        .collect::<String>()
        .trim()
        .to_string()
}

fn sanitize_opaque_resume_target(value: &str) -> Option<String> {
    let value = value.trim();
    (!value.is_empty()
        && !value.starts_with('-')
        && value.chars().count() <= 256
        && !value.chars().any(char::is_control))
    .then(|| value.to_string())
}

fn sanitize_resume_session_id(agent: Option<&str>, value: Option<String>) -> Option<String> {
    if matches!(agent, Some("amp" | "devin" | "factory")) {
        return value.as_deref().and_then(sanitize_opaque_resume_target);
    }
    value
        .map(sanitize_id_like)
        .filter(|value| !value.is_empty())
}

/// Accept only a `#RRGGBB` / `#RGB` hex color for a project accent — anything else is dropped (the desktop then
/// keeps/falls back to its own default). Content-blind + bounded.
fn sanitize_accent_color(c: Option<String>) -> Option<String> {
    let c = c?;
    let t = c.trim();
    let is_hex = t.starts_with('#')
        && (t.len() == 4 || t.len() == 7)
        && t[1..].chars().all(|ch| ch.is_ascii_hexdigit());
    is_hex.then(|| t.to_string())
}

/// Accept only the DESKTOP's resume-policy values ("none" | "resume" | "continue" — see maestro-shell
/// ProjectLaunchDefaults); anything else is dropped (the desktop then keeps its default). Legacy browsers used
/// "new" for the fresh policy — mapped to "none" so old clients (and replayed old messages) stay compatible.
/// Closed allowlist — content-blind.
fn sanitize_resume_mode(m: Option<String>) -> Option<String> {
    let m = m?;
    if m == "new" {
        return Some("none".to_string());
    }
    matches!(m.as_str(), "none" | "resume" | "continue").then_some(m)
}

/// A per-agent model id is free-form (e.g. "claude-opus-4-8") — strip control chars, trim, cap length; an empty
/// result becomes None (the desktop keeps its default). Bounded + content-blind.
fn sanitize_model(m: Option<String>) -> Option<String> {
    let m = m?;
    let t: String = m.chars().filter(|c| !c.is_control()).take(96).collect();
    let t = t.trim();
    (!t.is_empty()).then(|| t.to_string())
}

/// A project's DEFAULT custom launch command — strip control chars (no newlines/escapes that could change argv
/// interpretation), trim, cap length. Unlike model, EMPTY is PRESERVED as Some("") so the browser can CLEAR a
/// previously-set command (None still means "unchanged"). This is persisted project config, never executed from
/// the wire.
fn sanitize_custom_command(c: Option<String>) -> Option<String> {
    let c = c?;
    let t: String = c.chars().filter(|ch| !ch.is_control()).take(512).collect();
    Some(t.trim().to_string())
}

pub(crate) fn resume_descriptor_from_launch_flags(
    agent: Option<String>,
    launch_flags: Option<serde_json::Value>,
) -> Option<crate::resume_launch::ResumeDescriptor> {
    let agent = agent.and_then(sanitize_agent)?;
    let agent = crate::resume_launch::ResumeAgent::parse(&agent)?;
    let flags = launch_flags?;
    let obj = flags.as_object()?;
    let resume_mode = obj
        .get("resumeMode")
        .or_else(|| obj.get("resume_mode"))
        .and_then(|value| value.as_str())?;
    if resume_mode != "resume" {
        return None;
    }
    let raw_session_id = obj
        .get("resumeSessionId")
        .or_else(|| obj.get("resume_session_id"))
        .and_then(|value| value.as_str());
    // Most provider ids use Hydra's historical 128-character metadata sanitizer. Amp, Devin, and Factory accept
    // opaque targets up to 256 characters; preserve valid values exactly and reject invalid ones rather than
    // silently launching a truncated or control-stripped identifier.
    let session_id = if matches!(
        agent,
        crate::resume_launch::ResumeAgent::Amp
            | crate::resume_launch::ResumeAgent::Devin
            | crate::resume_launch::ResumeAgent::Factory
    ) {
        raw_session_id.and_then(sanitize_opaque_resume_target)
    } else {
        raw_session_id
            .map(|value| sanitize_id_like(value.to_string()))
            .filter(|value| !value.is_empty())
    };
    let session_file = obj
        .get("resumeSessionFile")
        .or_else(|| obj.get("resume_session_file"))
        .and_then(|value| value.as_str())
        .and_then(|value| sanitize_cwd(Some(value.to_string())));
    Some(crate::resume_launch::ResumeDescriptor {
        agent,
        session_id,
        session_file,
    })
}

/// Pure legacy resolver: find a local Gemini session file among desktop history rows. Exact canonical
/// UUIDs use `--resume <uuid>` and do not rely on this path. A legacy non-UUID history row may still be
/// imported by file; that path stays off the content-blind browser wire.
fn gemini_session_file_for_id(
    sessions: &[maestro_local_services::agent_history::AgentHistorySession],
    session_id: &str,
) -> Option<String> {
    sessions
        .iter()
        .find(|s| s.agent == "gemini" && s.id == session_id)
        .map(|s| s.file_path.clone())
        .filter(|path| !path.trim().is_empty())
}

/// For a legacy Gemini non-UUID descriptor with no file, resolve the local history file so the builder can
/// produce `gemini --session-file <path>`. Exact UUID descriptors remain UUID-only. On no legacy match, the
/// descriptor stays unchanged and the builder fails closed instead of selecting `latest`.
pub(crate) fn resolve_gemini_resume_file(
    descriptor: &mut crate::resume_launch::ResumeDescriptor,
    cwd: Option<&str>,
) {
    if descriptor.agent != crate::resume_launch::ResumeAgent::Gemini
        || descriptor.session_file.is_some()
    {
        return;
    }
    let Some(session_id) = descriptor.session_id.as_deref() else {
        return;
    };
    if uuid::Uuid::parse_str(session_id)
        .ok()
        .is_some_and(|id| id.hyphenated().to_string() == session_id)
    {
        return;
    }
    let Ok(paths) = maestro_shell::paths::AppPaths::production() else {
        return;
    };
    let cwd_path = cwd.map(PathBuf::from).unwrap_or_else(default_history_cwd);
    let sessions =
        maestro_local_services::agent_history::list_folder_sessions(&paths, "gemini", &cwd_path);
    descriptor.session_file = gemini_session_file_for_id(&sessions, session_id);
}

/// Sanitize the pinned-directories list. None stays None (unchanged); Some(list) → bounded (≤32) entries with
/// control chars stripped, name/path trimmed+capped, and any entry whose PATH is empty dropped. So Some([]) (or a
/// list of only-empty entries) becomes Some([]) = clear-all. Content-blind (labels/paths only).
fn sanitize_directories(
    dirs: Option<Vec<ProjectDirectoryWire>>,
) -> Option<Vec<ProjectDirectoryWire>> {
    let dirs = dirs?;
    let clean = |s: &str, cap: usize| -> String {
        s.chars()
            .filter(|c| !c.is_control())
            .take(cap)
            .collect::<String>()
            .trim()
            .to_string()
    };
    Some(
        dirs.into_iter()
            .take(32)
            .map(|d| ProjectDirectoryWire {
                name: clean(&d.name, 96),
                path: clean(&d.path, 512),
            })
            .filter(|d| !d.path.is_empty())
            .collect(),
    )
}

/// Map a desktop project create/update result into the wire reply.
fn project_edit_reply(
    request_id: String,
    result: Result<ProjectEdited, ProjectEditError>,
) -> Option<OutboundMsg> {
    Some(match result {
        Ok(edited) => OutboundMsg::ProjectEditOk {
            request_id,
            project_id: edited.project_id,
            // Some only on CREATE (the backend seeds an initial window+pane there) — the browser
            // auto-attaches it. skip_serializing_if keeps the key off the wire otherwise.
            session_id: edited.session_id,
        },
        Err(e) => OutboundMsg::ProjectEditError {
            request_id,
            code: e.code().into(),
            message: match e {
                ProjectEditError::DaemonUnavailable => {
                    "terminal service unavailable; project was not changed"
                }
                ProjectEditError::GloballyLastVisible => "keep one window open globally",
                _ => "could not edit project",
            }
            .into(),
        },
    })
}

fn list_agent_sessions_metadata(agent: &str, cwd: Option<String>) -> Vec<AgentSessionMeta> {
    let Ok(paths) = maestro_shell::paths::AppPaths::production() else {
        return Vec::new();
    };
    let cwd_path = cwd.map(PathBuf::from).unwrap_or_else(default_history_cwd);
    maestro_local_services::agent_history::list_folder_sessions(&paths, agent, &cwd_path)
        .into_iter()
        .map(agent_history_session_to_meta)
        .collect()
}

/// The REMOVED (hidden) sessions for a folder+agent — powers the browser "Removed sessions" section. Content-blind
/// (same metadata as the visible list; ⊘-removed sessions keep their file, so they can be brought back via unhide).
fn list_hidden_agent_sessions_metadata(agent: &str, cwd: Option<String>) -> Vec<AgentSessionMeta> {
    let Ok(paths) = maestro_shell::paths::AppPaths::production() else {
        return Vec::new();
    };
    let cwd_path = cwd.map(PathBuf::from).unwrap_or_else(default_history_cwd);
    maestro_local_services::agent_history::list_hidden_folder_sessions(&paths, agent, &cwd_path)
        .into_iter()
        .map(agent_history_session_to_meta)
        .collect()
}

fn agent_history_session_to_meta(
    session: maestro_local_services::agent_history::AgentHistorySession,
) -> AgentSessionMeta {
    AgentSessionMeta {
        id: session.id,
        agent: session.agent,
        modified_at_ms: session.modified_at_ms,
        message_count: session.message_count,
        in_use: session.in_use,
        custom_name: session.custom_name,
    }
}

fn default_history_cwd() -> PathBuf {
    dirs::home_dir().unwrap_or_else(|| PathBuf::from("/"))
}

/// A resolved directory listing for the browser folder-picker: the listed dir, its parent (for "up"), and its
/// immediate subdirectories. Content-blind (names/paths only).
struct DirectoryListing {
    path: String,
    parent: Option<String>,
    entries: Vec<crate::remote_control::DirectoryEntry>,
}

/// List the immediate SUBDIRECTORIES of `path` (None → the desktop home dir) for the browser folder-picker. Only
/// directories are returned (no files), hidden ones (dotfiles) skipped, sorted by name. Content-blind: names +
/// absolute paths, nothing else. Unreadable/nonexistent dir → an empty entry list (still reports the resolved path
/// + parent so the browser can navigate up). No symlink following beyond what read_dir + is_dir already do.
fn list_child_directories(path: Option<&str>) -> DirectoryListing {
    let base = path
        .map(str::trim)
        .filter(|p| !p.is_empty())
        .map(PathBuf::from)
        .unwrap_or_else(default_history_cwd);
    let parent = base.parent().map(|p| p.to_string_lossy().into_owned());
    let mut entries: Vec<crate::remote_control::DirectoryEntry> = std::fs::read_dir(&base)
        .map(|rd| {
            rd.filter_map(|e| e.ok())
                .filter(|e| e.file_type().map(|t| t.is_dir()).unwrap_or(false))
                .filter_map(|e| {
                    let name = e.file_name().to_string_lossy().into_owned();
                    if name.starts_with('.') {
                        return None; // skip hidden/dotfiles
                    }
                    Some(crate::remote_control::DirectoryEntry {
                        name,
                        path: e.path().to_string_lossy().into_owned(),
                    })
                })
                .collect()
        })
        .unwrap_or_default();
    entries.sort_by(|a, b| a.name.cmp(&b.name));
    DirectoryListing {
        path: base.to_string_lossy().into_owned(),
        parent,
        entries,
    }
}

fn refusal_reason(e: TokenError) -> &'static str {
    match e {
        TokenError::Malformed | TokenError::BadSignature => "invalid",
        TokenError::Expired => "invalid",
        TokenError::Revoked => "revoked",
        TokenError::WrongDevice => "wrong_device",
    }
}

/// Scan the raw JSON text for a forbidden field NAME (defense in depth, like the cloud guard). Looks for
/// `"<name>"` used as a key. Cheap + conservative.
fn forbidden_field_in(line: &str) -> Option<&'static str> {
    let lower = line.to_lowercase();
    for &f in FORBIDDEN_FIELDS {
        // match as a JSON key: "field"
        let needle = format!("\"{f}\"");
        if lower.contains(&needle) {
            return Some(f);
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::remote_token::{sign_token, TokenClaims};
    use base64::Engine as _;
    use ed25519_dalek::SigningKey;

    fn keys() -> (SigningKey, VerifyingKey) {
        let mut seed = [3u8; 32];
        use rand::RngCore;
        rand::thread_rng().fill_bytes(&mut seed);
        let sk = SigningKey::from_bytes(&seed);
        let vk = sk.verifying_key();
        (sk, vk)
    }
    fn token(sk: &SigningKey, dev: &str, now: u64) -> String {
        sign_token(
            &TokenClaims {
                account_id: "acct".into(),
                device_id: dev.into(),
                session_id: None,
                signal_session_id: None,
                target_device_id: None,
                browser_pubkey: None,
                browser_pubkey_alg: None,
                refresh_parent_sha256: None,
                iat_ms: now,
                exp_ms: now + 60_000,
            },
            sk,
        )
    }
    fn session_scoped_token(sk: &SigningKey, dev: &str, session_id: &str, now: u64) -> String {
        sign_token(
            &TokenClaims {
                account_id: "acct".into(),
                device_id: dev.into(),
                session_id: Some(session_id.into()),
                signal_session_id: None,
                target_device_id: None,
                browser_pubkey: None,
                browser_pubkey_alg: None,
                refresh_parent_sha256: None,
                iat_ms: now,
                exp_ms: now + 60_000,
            },
            sk,
        )
    }
    fn signal_bound_token(sk: &SigningKey, dev: &str, signal_session_id: &str, now: u64) -> String {
        sign_token(
            &TokenClaims {
                account_id: "acct".into(),
                device_id: dev.into(),
                session_id: None,
                signal_session_id: Some(signal_session_id.into()),
                target_device_id: None,
                browser_pubkey: None,
                browser_pubkey_alg: None,
                refresh_parent_sha256: None,
                iat_ms: now,
                exp_ms: now + 60_000,
            },
            sk,
        )
    }
    const NOPE: fn(&str, &str, u64) -> bool = |_, _, _| false;

    struct FakeDesktopAccessPolicy {
        status: DesktopAccessStatus,
        protected: bool,
        classifications: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl DesktopAccessPolicy for FakeDesktopAccessPolicy {
        fn current_status(&self) -> DesktopAccessStatus {
            self.status
        }

        fn path_requires_full_disk_access(&self, _path: &Path) -> bool {
            self.classifications
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            self.protected
        }
    }

    fn set_access<R: Fn(&str, &str, u64) -> bool>(
        channel: &mut ControlChannel<R>,
        status: DesktopAccessStatus,
        protected: bool,
    ) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        let classifications = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        channel.set_desktop_access_policy(Box::new(FakeDesktopAccessPolicy {
            status,
            protected,
            classifications: classifications.clone(),
        }));
        classifications
    }

    fn offer_creation_replay<R: Fn(&str, &str, u64) -> bool>(ch: &mut ControlChannel<R>) {
        assert!(matches!(
            ch.handle(
                r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client","capabilities":["creation_request_replay_v1"]}"#,
                1,
            ),
            Some(OutboundMsg::Hello { .. })
        ));
    }

    fn authenticate<R: Fn(&str, &str, u64) -> bool>(
        ch: &mut ControlChannel<R>,
        sk: &SigningKey,
        now_ms: u64,
    ) {
        let tok = token(sk, "dev_a", now_ms.saturating_sub(500));
        assert!(matches!(
            ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), now_ms),
            Some(OutboundMsg::AuthOk { .. })
        ));
    }

    #[test]
    fn public_agent_build_git_is_strict_and_bounded() {
        assert_eq!(
            public_agent_build_git("0123456"),
            Some("0123456".to_string())
        );
        assert_eq!(
            public_agent_build_git("0123456789abcdef0123456789abcdef01234567"),
            Some("0123456789abcdef0123456789abcdef01234567".to_string())
        );
        for invalid in [
            "",
            "012345",
            "0123456789abcdef0123456789abcdef012345678",
            "0123456-dirty",
            "ABCDEF0",
            "unknown",
            "token=secret",
        ] {
            assert_eq!(public_agent_build_git(invalid), None, "{invalid}");
        }
    }

    #[test]
    fn agent_build_is_additive_only_to_authenticated_auth_ok() {
        let auth = OutboundMsg::AuthOk {
            account_id: "acct".into(),
            device_id: "browser".into(),
            agent_build_git: Some("0123456".into()),
        };
        assert_eq!(
            serde_json::to_value(auth).unwrap(),
            serde_json::json!({
                "type": "auth_ok",
                "account_id": "acct",
                "device_id": "browser",
                "agent_build_git": "0123456",
            })
        );

        let unknown = OutboundMsg::AuthOk {
            account_id: "acct".into(),
            device_id: "browser".into(),
            agent_build_git: None,
        };
        assert!(serde_json::to_value(unknown)
            .unwrap()
            .get("agent_build_git")
            .is_none());
    }

    #[test]
    fn hello_and_ping_work_pre_auth() {
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let h = ch.handle(
            r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client"}"#,
            1,
        );
        assert_eq!(
            h,
            Some(OutboundMsg::Hello {
                protocol_version: PROTOCOL_VERSION,
                device_id: "dev_a".into(),
                role: "agent".into(),
                capabilities: vec![
                    CAPABILITY_VIEWED_RESIZE_V1.into(),
                    CAPABILITY_TERMINAL_GZIP_JSON_V1.into(),
                    CAPABILITY_CREATION_REPLAY_V1.into(),
                    CAPABILITY_DESKTOP_ACCESS_STATUS_V1.into(),
                    CAPABILITY_AUTHORIZATION_REFRESH_V1.into(),
                ],
            })
        );
        let p = ch.handle(r#"{"type":"ping","nonce":"n1"}"#, 1);
        assert_eq!(p, Some(OutboundMsg::Pong { nonce: "n1".into() }));
        assert!(!ch.is_authenticated());
    }

    #[test]
    fn hello_serializes_additive_capabilities_without_version_bump() {
        let hello = OutboundMsg::Hello {
            protocol_version: PROTOCOL_VERSION,
            device_id: "dev_a".into(),
            role: "agent".into(),
            capabilities: vec![
                CAPABILITY_VIEWED_RESIZE_V1.into(),
                CAPABILITY_TERMINAL_GZIP_JSON_V1.into(),
                CAPABILITY_CREATION_REPLAY_V1.into(),
                CAPABILITY_DESKTOP_ACCESS_STATUS_V1.into(),
                CAPABILITY_AUTHORIZATION_REFRESH_V1.into(),
            ],
        };
        assert_eq!(
            serde_json::to_value(hello).unwrap(),
            serde_json::json!({
                "type": "hello",
                "protocol_version": 1,
                "device_id": "dev_a",
                "role": "agent",
                "capabilities": [
                    "viewed_resize_v1",
                    "terminal_gzip_json_v1",
                    "creation_request_replay_v1",
                    "desktop_access_status_v1",
                    "authorization_refresh_v1"
                ],
            })
        );
    }

    #[test]
    fn desktop_access_status_is_exact_bounded_and_capability_negotiated() {
        let (_sk, vk) = keys();
        let mut channel = ControlChannel::new(vk, "dev_a".into(), NOPE);
        set_access(&mut channel, DesktopAccessStatus::Required, true);

        assert!(!channel.browser_supports_desktop_access_status());
        channel.handle(
            r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client","capabilities":["desktop_access_status_v1_extra"]}"#,
            1,
        );
        assert!(!channel.browser_supports_desktop_access_status());
        channel.handle(
            r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client","capabilities":["desktop_access_status_v1"]}"#,
            2,
        );
        assert!(channel.browser_supports_desktop_access_status());
        assert_eq!(
            serde_json::to_value(channel.desktop_access_status_message()).unwrap(),
            serde_json::json!({
                "type": "desktop_access_status",
                "platform": desktop_access_platform(),
                "full_disk_access": "required",
            })
        );

        channel.handle(
            r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client"}"#,
            3,
        );
        assert!(
            !channel.browser_supports_desktop_access_status(),
            "a new legacy hello resets the per-channel negotiation"
        );
    }

    #[test]
    fn desktop_access_snapshot_probes_once_and_serializes_that_exact_result() {
        struct ChangingPolicy {
            calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
        }
        impl DesktopAccessPolicy for ChangingPolicy {
            fn current_status(&self) -> DesktopAccessStatus {
                if self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst) == 0 {
                    DesktopAccessStatus::Required
                } else {
                    DesktopAccessStatus::Granted
                }
            }

            fn path_requires_full_disk_access(&self, _path: &Path) -> bool {
                true
            }
        }

        let (_sk, vk) = keys();
        let mut channel = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        channel.set_desktop_access_policy(Box::new(ChangingPolicy {
            calls: calls.clone(),
        }));

        let (status, message) = channel.desktop_access_status_snapshot();
        assert_eq!(status, DesktopAccessStatus::Required);
        assert_eq!(
            serde_json::to_value(message).unwrap()["full_disk_access"],
            "required"
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn desktop_access_list_errors_use_exact_additive_types_without_paths() {
        for (message, expected_type) in [
            (
                OutboundMsg::AgentSessionsError {
                    request_id: "history".into(),
                    code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                    message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                },
                "agent_sessions_error",
            ),
            (
                OutboundMsg::DirectoriesError {
                    request_id: "directories".into(),
                    code: FULL_DISK_ACCESS_REQUIRED_CODE.into(),
                    message: FULL_DISK_ACCESS_REQUIRED_MESSAGE.into(),
                },
                "directories_error",
            ),
        ] {
            let value = serde_json::to_value(message).unwrap();
            assert_eq!(value["type"], expected_type);
            assert_eq!(value["code"], FULL_DISK_ACCESS_REQUIRED_CODE);
            assert!(value.get("path").is_none());
        }
    }

    #[test]
    fn terminal_gzip_is_selected_only_by_the_exact_bounded_browser_offer() {
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        assert!(!ch.browser_supports_terminal_gzip());

        let legacy = ch.handle(
            r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client"}"#,
            1,
        );
        assert!(matches!(legacy, Some(OutboundMsg::Hello { .. })));
        assert!(!ch.browser_supports_terminal_gzip());

        let near_match = ch.handle(
            r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client","capabilities":["terminal_gzip_json_v1_extra","unknown"]}"#,
            2,
        );
        assert!(matches!(near_match, Some(OutboundMsg::Hello { .. })));
        assert!(!ch.browser_supports_terminal_gzip());

        let exact = ch.handle(
            r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client","capabilities":["terminal_gzip_json_v1"]}"#,
            3,
        );
        assert!(matches!(exact, Some(OutboundMsg::Hello { .. })));
        assert!(ch.browser_supports_terminal_gzip());
    }

    #[test]
    fn oversized_capability_lists_and_entries_fail_closed() {
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let exact = format!(
            r#"{{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client","capabilities":["{CAPABILITY_TERMINAL_GZIP_JSON_V1}","{CAPABILITY_DESKTOP_ACCESS_STATUS_V1}"]}}"#
        );
        ch.handle(&exact, 1);
        assert!(ch.browser_supports_terminal_gzip());
        assert!(ch.browser_supports_desktop_access_status());

        let too_many = serde_json::json!({
            "type": "hello",
            "protocol_version": 1,
            "device_id": "dev_a",
            "role": "client",
            "capabilities": vec!["x"; MAX_CAPABILITIES + 1],
        });
        assert!(matches!(
            ch.handle(&too_many.to_string(), 2),
            Some(OutboundMsg::Error { code, .. }) if code == "bad_capabilities"
        ));
        assert!(!ch.browser_supports_terminal_gzip());
        assert!(!ch.browser_supports_desktop_access_status());

        let too_long = serde_json::json!({
            "type": "hello",
            "protocol_version": 1,
            "device_id": "dev_a",
            "role": "client",
            "capabilities": ["x".repeat(MAX_CAPABILITY_BYTES + 1)],
        });
        assert!(matches!(
            ch.handle(&too_long.to_string(), 3),
            Some(OutboundMsg::Error { code, .. }) if code == "bad_capabilities"
        ));
        assert!(!ch.browser_supports_terminal_gzip());
    }

    #[test]
    fn privileged_request_refused_before_auth() {
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let r = ch.handle(r#"{"type":"list_request","request_id":"r1"}"#, 1);
        assert_eq!(
            r,
            Some(OutboundMsg::AuthRefused {
                reason: "missing".into()
            })
        );
    }

    #[test]
    fn create_session_is_refused_before_auth() {
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let r = ch.handle(r#"{"type":"create_session","request_id":"c1"}"#, 1);
        assert_eq!(
            r,
            Some(OutboundMsg::SessionCreateError {
                request_id: "c1".into(),
                code: "unauthenticated".into(),
                message: "sign in / authenticate before creating a session".into(),
            })
        );
    }

    #[test]
    fn recordless_create_is_held_after_auth_without_a_test_creator() {
        // Production deliberately has no record-less creator injection. The typed HOLD is honest and
        // terminal: it must not masquerade as a transient daemon outage that invites blind retries.
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(r#"{"type":"create_session","request_id":"c2"}"#, 1600);
        match r {
            Some(OutboundMsg::SessionCreateError {
                request_id, code, ..
            }) => {
                assert_eq!(request_id, "c2");
                assert_eq!(code, RECORDLESS_CREATION_HELD_CODE);
            }
            other => panic!("expected SessionCreateError, got {other:?}"),
        }
    }

    /// A fake SessionCreator for the channel tests: records start_session, never touches a real socket.
    struct FakeCreator {
        started: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        launches: std::sync::Arc<std::sync::Mutex<Vec<Option<crate::resume_launch::ResumeLaunch>>>>,
    }
    impl crate::session_creator::SessionCreator for FakeCreator {
        fn known_sessions(&self) -> Vec<String> {
            vec![]
        }
        fn start_session(
            &mut self,
            session_id: &str,
            _home: &str,
        ) -> Result<(), crate::session_creator::CreateSessionError> {
            self.started.lock().unwrap().push(session_id.to_string());
            Ok(())
        }
        fn start_session_with_launch(
            &mut self,
            session_id: &str,
            _home: &str,
            launch: Option<&crate::resume_launch::ResumeLaunch>,
        ) -> Result<(), crate::session_creator::CreateSessionError> {
            self.started.lock().unwrap().push(session_id.to_string());
            self.launches.lock().unwrap().push(launch.cloned());
            Ok(())
        }
        fn home(&self) -> String {
            "/Users/test/home".into()
        }
    }

    struct SizingFakeCreator {
        sizes: std::sync::Arc<std::sync::Mutex<Vec<crate::session_creator::InitialTerminalSize>>>,
    }
    impl crate::session_creator::SessionCreator for SizingFakeCreator {
        fn known_sessions(&self) -> Vec<String> {
            vec![]
        }
        fn start_session(
            &mut self,
            _session_id: &str,
            _home: &str,
        ) -> Result<(), crate::session_creator::CreateSessionError> {
            Ok(())
        }
        fn start_session_with_launch_and_size(
            &mut self,
            _session_id: &str,
            _home: &str,
            _launch: Option<&crate::resume_launch::ResumeLaunch>,
            initial_size: crate::session_creator::InitialTerminalSize,
        ) -> Result<(), crate::session_creator::CreateSessionError> {
            self.sizes.lock().unwrap().push(initial_size);
            Ok(())
        }
        fn home(&self) -> String {
            "/Users/test/home".into()
        }
    }

    #[test]
    fn create_session_threads_only_a_complete_valid_initial_size_pair() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let sizes = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(SizingFakeCreator {
            sizes: sizes.clone(),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        for request in [
            r#"{"type":"create_session","request_id":"exact","cols":132,"rows":43}"#,
            r#"{"type":"create_session","request_id":"legacy"}"#,
            r#"{"type":"create_session","request_id":"unpaired","cols":120}"#,
            r#"{"type":"create_session","request_id":"zero","cols":120,"rows":0}"#,
            r#"{"type":"create_session","request_id":"cols-low","cols":1,"rows":43}"#,
            r#"{"type":"create_session","request_id":"cols-high","cols":251,"rows":43}"#,
            r#"{"type":"create_session","request_id":"rows-high","cols":120,"rows":101}"#,
        ] {
            assert!(matches!(
                ch.handle(request, 1600),
                Some(OutboundMsg::SessionCreated { .. })
            ));
        }

        let sizes = sizes.lock().unwrap();
        assert_eq!(sizes[0].cols(), 132);
        assert_eq!(sizes[0].rows(), 43);
        assert_eq!(
            &sizes[1..],
            &[
                crate::session_creator::InitialTerminalSize::default(),
                crate::session_creator::InitialTerminalSize::default(),
                crate::session_creator::InitialTerminalSize::default(),
                crate::session_creator::InitialTerminalSize::default(),
                crate::session_creator::InitialTerminalSize::default(),
                crate::session_creator::InitialTerminalSize::default(),
            ]
        );
    }

    #[derive(Clone)]
    struct SizingRemoteOperations {
        calls: std::sync::Arc<
            std::sync::Mutex<Vec<(&'static str, crate::session_creator::InitialTerminalSize)>>,
        >,
    }
    impl SizingRemoteOperations {
        fn record(
            &self,
            operation: &'static str,
            initial_size: crate::session_creator::InitialTerminalSize,
        ) {
            self.calls.lock().unwrap().push((operation, initial_size));
        }
    }
    impl PaneSplitter for SizingRemoteOperations {
        fn split_pane(
            &mut self,
            _request: SplitPaneRequest,
        ) -> Result<SplitPaneCreated, SplitPaneCreateError> {
            unreachable!("size-aware handler must be used")
        }
        fn split_pane_with_initial_size(
            &mut self,
            _request: SplitPaneRequest,
            initial_size: crate::session_creator::InitialTerminalSize,
        ) -> Result<SplitPaneCreated, SplitPaneCreateError> {
            self.record("split_pane", initial_size);
            Ok(SplitPaneCreated {
                session_id: "s-split".into(),
                tab_id: "p-split".into(),
            })
        }
        fn new_pane(
            &mut self,
            _request: SplitPaneRequest,
        ) -> Result<SplitPaneCreated, SplitPaneCreateError> {
            unreachable!("size-aware handler must be used")
        }
        fn new_pane_with_initial_size(
            &mut self,
            _request: SplitPaneRequest,
            initial_size: crate::session_creator::InitialTerminalSize,
        ) -> Result<SplitPaneCreated, SplitPaneCreateError> {
            self.record("new_pane", initial_size);
            Ok(SplitPaneCreated {
                session_id: "s-new-pane".into(),
                tab_id: "p-new".into(),
            })
        }
    }
    impl PaneReviver for SizingRemoteOperations {
        fn revive_pane(
            &mut self,
            _request: RevivePaneRequest,
        ) -> Result<RevivePaneCreated, RevivePaneError> {
            unreachable!("size-aware handler must be used")
        }
        fn revive_pane_with_initial_size(
            &mut self,
            _request: RevivePaneRequest,
            initial_size: crate::session_creator::InitialTerminalSize,
        ) -> Result<RevivePaneCreated, RevivePaneError> {
            self.record("revive_pane", initial_size);
            Ok(RevivePaneCreated {
                session_id: "s-revive".into(),
            })
        }
    }
    impl PaneSessionStarter for SizingRemoteOperations {
        fn start_pane_session(
            &mut self,
            _request: RevivePaneRequest,
        ) -> Result<RevivePaneCreated, RevivePaneError> {
            unreachable!("size-aware handler must be used")
        }
        fn start_pane_session_with_initial_size(
            &mut self,
            _request: RevivePaneRequest,
            initial_size: crate::session_creator::InitialTerminalSize,
        ) -> Result<RevivePaneCreated, RevivePaneError> {
            self.record("start_pane_session", initial_size);
            Ok(RevivePaneCreated {
                session_id: "s-start".into(),
            })
        }
    }
    impl WindowOpener for SizingRemoteOperations {
        fn new_window(
            &mut self,
            _request: NewWindowRequest,
        ) -> Result<NewWindowCreated, NewWindowError> {
            unreachable!("size-aware handler must be used")
        }
        fn new_window_with_initial_size(
            &mut self,
            _request: NewWindowRequest,
            initial_size: crate::session_creator::InitialTerminalSize,
        ) -> Result<NewWindowCreated, NewWindowError> {
            self.record("new_window", initial_size);
            Ok(NewWindowCreated {
                window_id: "w-new".into(),
                session_id: "s-window".into(),
            })
        }
    }
    impl ProjectEditor for SizingRemoteOperations {
        fn create_project(
            &mut self,
            _request: ProjectEditRequest,
        ) -> Result<ProjectEdited, ProjectEditError> {
            unreachable!("size-aware handler must be used")
        }
        fn create_project_with_initial_size(
            &mut self,
            _request: ProjectEditRequest,
            initial_size: crate::session_creator::InitialTerminalSize,
        ) -> Result<ProjectEdited, ProjectEditError> {
            self.record("project_create", initial_size);
            Ok(ProjectEdited {
                project_id: "p-new".into(),
                session_id: Some("s-project".into()),
            })
        }
        fn update_project(
            &mut self,
            _request: ProjectEditRequest,
        ) -> Result<ProjectEdited, ProjectEditError> {
            unreachable!()
        }
        fn delete_project(
            &mut self,
            _project_id: String,
            _now_ms: u64,
        ) -> Result<ProjectEdited, ProjectEditError> {
            unreachable!()
        }
    }

    #[test]
    fn every_remote_pty_creation_threads_its_exact_initial_size() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let ops = SizingRemoteOperations {
            calls: calls.clone(),
        };
        ch.set_pane_splitter(Box::new(ops.clone()));
        ch.set_pane_reviver(Box::new(ops.clone()));
        ch.set_pane_session_starter(Box::new(ops.clone()));
        ch.set_window_opener(Box::new(ops.clone()));
        ch.set_project_editor(Box::new(ops));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        for request in [
            r#"{"type":"split_pane","request_id":"sp","window_id":"w","from_pane_id":"p","dir":"right","cols":101,"rows":31}"#,
            r#"{"type":"new_pane","request_id":"np","window_id":"w","from_pane_id":"p","cols":102,"rows":32}"#,
            r#"{"type":"revive_pane","request_id":"rp","window_id":"w","pane_id":"p","cols":103,"rows":33}"#,
            r#"{"type":"start_pane_session","request_id":"ss","window_id":"w","pane_id":"p","cols":104,"rows":34}"#,
            r#"{"type":"new_window","request_id":"nw","project_id":"p","name":"W","cols":105,"rows":35}"#,
            r#"{"type":"project_create","request_id":"pc","name":"P","root":"/tmp","cols":106,"rows":36}"#,
        ] {
            assert!(ch.handle(request, 1600).is_some());
        }
        for request in [
            r#"{"type":"split_pane","request_id":"sp-old","window_id":"w","from_pane_id":"p","dir":"right"}"#,
            r#"{"type":"new_pane","request_id":"np-old","window_id":"w","from_pane_id":"p","cols":120}"#,
            r#"{"type":"revive_pane","request_id":"rp-old","window_id":"w","pane_id":"p","rows":40}"#,
            r#"{"type":"start_pane_session","request_id":"ss-old","window_id":"w","pane_id":"p","cols":0,"rows":40}"#,
            r#"{"type":"new_window","request_id":"nw-old","project_id":"p","name":"W","cols":120,"rows":0}"#,
            r#"{"type":"project_create","request_id":"pc-old","name":"P","root":"/tmp"}"#,
        ] {
            assert!(ch.handle(request, 1601).is_some());
        }

        let calls = calls.lock().unwrap();
        let observed = calls
            .iter()
            .map(|(operation, size)| (*operation, size.cols(), size.rows()))
            .collect::<Vec<_>>();
        assert_eq!(
            observed,
            vec![
                ("split_pane", 101, 31),
                ("new_pane", 102, 32),
                ("revive_pane", 103, 33),
                ("start_pane_session", 104, 34),
                ("new_window", 105, 35),
                ("project_create", 106, 36),
                ("split_pane", 80, 24),
                ("new_pane", 80, 24),
                ("revive_pane", 80, 24),
                ("start_pane_session", 80, 24),
                ("new_window", 80, 24),
                ("project_create", 80, 24),
            ]
        );
    }

    #[test]
    fn negotiated_creation_replay_executes_all_seven_operations_once() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        offer_creation_replay(&mut ch);

        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches,
        }));
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let ops = SizingRemoteOperations {
            calls: calls.clone(),
        };
        ch.set_pane_splitter(Box::new(ops.clone()));
        ch.set_pane_reviver(Box::new(ops.clone()));
        ch.set_pane_session_starter(Box::new(ops.clone()));
        ch.set_window_opener(Box::new(ops.clone()));
        ch.set_project_editor(Box::new(ops));
        authenticate(&mut ch, &sk, 1_500);

        for request in [
            r#"{"type":"create_session","request_id":"create-once","cols":100,"rows":30}"#,
            r#"{"type":"split_pane","request_id":"split-once","window_id":"w","from_pane_id":"p","dir":"right","cols":101,"rows":31}"#,
            r#"{"type":"new_pane","request_id":"pane-once","window_id":"w","from_pane_id":"p","cols":102,"rows":32}"#,
            r#"{"type":"revive_pane","request_id":"revive-once","window_id":"w","pane_id":"p","cols":103,"rows":33}"#,
            r#"{"type":"start_pane_session","request_id":"start-once","window_id":"w","pane_id":"p","cols":104,"rows":34}"#,
            r#"{"type":"new_window","request_id":"window-once","project_id":"p","name":"W","cols":105,"rows":35}"#,
            r#"{"type":"project_create","request_id":"project-once","name":"P","root":"/tmp","cols":106,"rows":36}"#,
        ] {
            let first = ch.handle(request, 1_600);
            let replay = ch.handle(request, 1_601);
            assert_eq!(replay, first, "duplicate must replay: {request}");
        }

        assert_eq!(started.lock().unwrap().len(), 1);
        assert_eq!(
            calls
                .lock()
                .unwrap()
                .iter()
                .map(|(operation, _)| *operation)
                .collect::<Vec<_>>(),
            vec![
                "split_pane",
                "new_pane",
                "revive_pane",
                "start_pane_session",
                "new_window",
                "project_create",
            ]
        );
    }

    #[test]
    fn capable_exact_frame_create_replay_returns_cached_session_id_without_reexecution() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        offer_creation_replay(&mut ch);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
        }));
        authenticate(&mut ch, &sk, 1_500);

        let request =
            r#"{"type":"create_session","request_id":"retire-eof-delivery","cols":100,"rows":30}"#;
        let first = ch.handle(request, 1_600).unwrap();
        let first_session_id = match &first {
            OutboundMsg::SessionCreated {
                request_id,
                session_id,
                ..
            } => {
                assert_eq!(request_id, "retire-eof-delivery");
                session_id.clone()
            }
            other => panic!("expected first SessionCreated, got {other:?}"),
        };
        let replay = ch.handle(request, 1_601).unwrap();

        assert_eq!(replay, first);
        assert!(matches!(
            replay,
            OutboundMsg::SessionCreated {
                ref session_id,
                ..
            } if session_id == &first_session_id
        ));
        assert_eq!(
            started.lock().unwrap().as_slice(),
            &[first_session_id],
            "byte-identical capable replay must not invoke the creator again"
        );
    }

    #[test]
    fn creation_replay_is_capability_gated_for_legacy_fixed_ids() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches,
        }));
        authenticate(&mut ch, &sk, 1_500);

        let request = r#"{"type":"create_session","request_id":"create"}"#;
        let first = ch.handle(request, 1_600);
        let second = ch.handle(request, 1_601);

        assert_ne!(first, second, "legacy fixed id remains a fresh action");
        assert_eq!(started.lock().unwrap().len(), 2);
    }

    #[test]
    fn creation_replay_rejects_kind_and_payload_collisions_without_side_effects() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        offer_creation_replay(&mut ch);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches,
        }));
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let ops = SizingRemoteOperations {
            calls: calls.clone(),
        };
        ch.set_window_opener(Box::new(ops));
        authenticate(&mut ch, &sk, 1_500);

        let original = r#"{"type":"create_session","request_id":"same","cols":100,"rows":30}"#;
        assert!(matches!(
            ch.handle(original, 1_600),
            Some(OutboundMsg::SessionCreated { .. })
        ));
        assert!(matches!(
            ch.handle(
                r#"{"type":"create_session","request_id":"same","cols":101,"rows":30}"#,
                1_601,
            ),
            Some(OutboundMsg::SessionCreateError { code, .. })
                if code == "request_id_conflict"
        ));
        assert!(matches!(
            ch.handle(
                r#"{"type":"new_window","request_id":"same","project_id":"p","name":"W","cols":100,"rows":30}"#,
                1_602,
            ),
            Some(OutboundMsg::NewWindowError { code, .. })
                if code == "request_id_conflict"
        ));
        assert_eq!(started.lock().unwrap().len(), 1);
        assert!(calls.lock().unwrap().is_empty());
    }

    struct CountingFailCreator {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl crate::session_creator::SessionCreator for CountingFailCreator {
        fn known_sessions(&self) -> Vec<String> {
            vec![]
        }

        fn start_session(
            &mut self,
            _session_id: &str,
            _home: &str,
        ) -> Result<(), crate::session_creator::CreateSessionError> {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Err(crate::session_creator::CreateSessionError::DaemonUnavailable)
        }

        fn home(&self) -> String {
            "/Users/test/home".into()
        }
    }

    #[test]
    fn creation_replay_caches_operation_errors() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        offer_creation_replay(&mut ch);
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        ch.set_session_creator(Box::new(CountingFailCreator {
            calls: calls.clone(),
        }));
        authenticate(&mut ch, &sk, 1_500);

        let request = r#"{"type":"create_session","request_id":"fails-once"}"#;
        let first = ch.handle(request, 1_600);
        let replay = ch.handle(request, 1_601);

        assert_eq!(replay, first);
        assert!(matches!(
            first,
            Some(OutboundMsg::SessionCreateError { code, .. })
                if code == "daemon_unavailable"
        ));
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 1);
    }

    #[test]
    fn duplicate_auth_is_refused_without_restarting_the_authority_epoch() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        offer_creation_replay(&mut ch);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches,
        }));
        let request = r#"{"type":"create_session","request_id":"auth-epoch"}"#;

        assert!(matches!(
            ch.handle(request, 1_000),
            Some(OutboundMsg::SessionCreateError { code, .. }) if code == "unauthenticated"
        ));
        authenticate(&mut ch, &sk, 1_500);
        assert!(matches!(
            ch.handle(request, 1_600),
            Some(OutboundMsg::SessionCreated { .. })
        ));
        let duplicate = token(&sk, "dev_a", 1_700);
        assert!(matches!(
            ch.handle(&format!(r#"{{"type":"auth","token":"{duplicate}"}}"#), 1_700),
            Some(OutboundMsg::AuthRefused { reason }) if reason == "refresh_required"
        ));
        assert!(matches!(
            ch.handle(request, 1_800),
            Some(OutboundMsg::SessionCreated { .. })
        ));
        assert_eq!(started.lock().unwrap().len(), 1);
    }

    #[test]
    fn revoked_or_expired_auth_never_replays_a_cached_success() {
        let (sk, vk) = keys();
        let revoked = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let revoked_for_channel = revoked.clone();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), move |_, _, _| {
            revoked_for_channel.load(std::sync::atomic::Ordering::SeqCst)
        });
        offer_creation_replay(&mut ch);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches,
        }));
        authenticate(&mut ch, &sk, 1_500);
        let request = r#"{"type":"create_session","request_id":"revoke"}"#;
        assert!(matches!(
            ch.handle(request, 1_600),
            Some(OutboundMsg::SessionCreated { .. })
        ));

        revoked.store(true, std::sync::atomic::Ordering::SeqCst);
        assert!(matches!(
            ch.handle(request, 1_700),
            Some(OutboundMsg::SessionCreateError { code, .. })
                if code == "revoked" || code == "unauthenticated"
        ));
        assert_eq!(started.lock().unwrap().len(), 1);

        let (_sk2, vk2) = keys();
        let mut expiring = ControlChannel::new(vk2, "dev_a".into(), NOPE);
        offer_creation_replay(&mut expiring);
        // No cached success can survive expiry; the exact request is refused once the token lapses.
        expiring.authed_claims = Some(TokenClaims {
            account_id: "acct".into(),
            device_id: "dev_a".into(),
            session_id: None,
            signal_session_id: None,
            target_device_id: None,
            browser_pubkey: None,
            browser_pubkey_alg: None,
            refresh_parent_sha256: None,
            iat_ms: 1,
            exp_ms: 2,
        });
        expiring.creation_replay.complete(
            CreationRequestKind::CreateSession,
            "expired".into(),
            Sha256::digest(br#"{"type":"create_session","request_id":"expired"}"#).into(),
            OutboundMsg::SessionCreated {
                request_id: "expired".into(),
                session_id: "must-not-replay".into(),
                label: None,
            },
            1,
        );
        assert!(matches!(
            expiring.handle(
                r#"{"type":"create_session","request_id":"expired"}"#,
                2,
            ),
            Some(OutboundMsg::SessionCreateError { code, .. }) if code == "unauthenticated"
        ));
    }

    #[test]
    fn creation_replay_cache_is_bounded_without_evicting_live_results_and_expires() {
        let mut cache = CreationReplayCache::default();
        for index in 0..CREATION_REPLAY_MAX_ENTRIES {
            let request_id = format!("r-{index}");
            let digest: [u8; 32] = Sha256::digest(request_id.as_bytes()).into();
            assert!(matches!(
                cache.lookup_or_admit(CreationRequestKind::CreateSession, &request_id, digest, 1,),
                CreationReplayDecision::Execute
            ));
            cache.complete(
                CreationRequestKind::CreateSession,
                request_id.clone(),
                digest,
                OutboundMsg::SessionCreated {
                    request_id,
                    session_id: format!("s-{index}"),
                    label: None,
                },
                1,
            );
        }

        let overflow_digest: [u8; 32] = Sha256::digest(b"overflow").into();
        assert!(matches!(
            cache.lookup_or_admit(
                CreationRequestKind::CreateSession,
                "overflow",
                overflow_digest,
                2,
            ),
            CreationReplayDecision::Reply(OutboundMsg::SessionCreateError {
                code,
                ..
            }) if code == "request_cache_full"
        ));
        let oldest_digest: [u8; 32] = Sha256::digest(b"r-0").into();
        assert!(matches!(
            cache.lookup_or_admit(
                CreationRequestKind::CreateSession,
                "r-0",
                oldest_digest,
                2,
            ),
            CreationReplayDecision::Reply(OutboundMsg::SessionCreated {
                session_id,
                ..
            }) if session_id == "s-0"
        ));
        assert!(matches!(
            cache.lookup_or_admit(
                CreationRequestKind::CreateSession,
                "overflow",
                overflow_digest,
                CREATION_REPLAY_TTL_MS + 2,
            ),
            CreationReplayDecision::Execute
        ));
        assert!(cache.completed.is_empty());
    }

    #[test]
    fn negotiated_creation_replay_bounds_request_ids_before_mutation() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        offer_creation_replay(&mut ch);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches,
        }));
        authenticate(&mut ch, &sk, 1_500);

        let request = serde_json::json!({
            "type": "create_session",
            "request_id": "x".repeat(MAX_CREATION_REQUEST_ID_BYTES + 1),
        })
        .to_string();
        assert!(matches!(
            ch.handle(&request, 1_600),
            Some(OutboundMsg::SessionCreateError { code, .. }) if code == "bad_request_id"
        ));
        assert!(started.lock().unwrap().is_empty());
    }

    struct FakeSplitter {
        calls: std::sync::Arc<std::sync::Mutex<Vec<SplitPaneRequest>>>,
        result: Result<SplitPaneCreated, SplitPaneCreateError>,
    }
    impl PaneSplitter for FakeSplitter {
        fn split_pane(
            &mut self,
            request: SplitPaneRequest,
        ) -> Result<SplitPaneCreated, SplitPaneCreateError> {
            self.calls.lock().unwrap().push(request);
            self.result.clone()
        }

        fn new_pane(
            &mut self,
            request: SplitPaneRequest,
        ) -> Result<SplitPaneCreated, SplitPaneCreateError> {
            self.calls.lock().unwrap().push(request);
            self.result.clone()
        }
    }

    #[test]
    fn recordless_create_hold_keeps_desktop_backed_new_pane_available() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_pane_splitter(Box::new(FakeSplitter {
            calls: calls.clone(),
            result: Ok(SplitPaneCreated {
                session_id: "s-durable".into(),
                tab_id: "pane-durable".into(),
            }),
        }));
        authenticate(&mut ch, &sk, 1_500);

        assert!(matches!(
            ch.handle(
                r#"{"type":"create_session","request_id":"recordless"}"#,
                1_600,
            ),
            Some(OutboundMsg::SessionCreateError { code, .. })
                if code == RECORDLESS_CREATION_HELD_CODE
        ));
        assert!(
            calls.lock().unwrap().is_empty(),
            "held record-less create must not reach a durable pane mutation seam"
        );

        assert_eq!(
            ch.handle(
                r#"{"type":"new_pane","request_id":"durable","window_id":"w1","from_pane_id":"p1"}"#,
                1_601,
            ),
            Some(OutboundMsg::SplitPaneOk {
                request_id: "durable".into(),
                session_id: "s-durable".into(),
                tab_id: "pane-durable".into(),
            })
        );
        assert_eq!(calls.lock().unwrap().len(), 1);
    }

    #[test]
    fn create_session_authed_with_creator_replies_session_created() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches: launches.clone(),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(r#"{"type":"create_session","request_id":"c3"}"#, 1600);
        match r {
            Some(OutboundMsg::SessionCreated {
                request_id,
                session_id,
                label,
            }) => {
                assert_eq!(request_id, "c3");
                assert!(session_id.starts_with("s-"));
                // F1: no label sent → None (old-client behavior unchanged)
                assert_eq!(label, None);
                // the daemon got exactly one start_session, for the returned id
                assert_eq!(started.lock().unwrap().as_slice(), &[session_id]);
                assert_eq!(launches.lock().unwrap().as_slice(), &[None]);
            }
            other => panic!("expected SessionCreated, got {other:?}"),
        }
    }

    #[test]
    fn create_session_threads_codex_resume_launch_to_creator() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches: launches.clone(),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"create_session","request_id":"c-resume","agent":"codex","launch_flags":{"resumeMode":"resume","resumeSessionId":"50000000-0000-4000-8000-000000000003","model":"gpt-5.2-codex"}}"#,
            1600,
        );
        match r {
            Some(OutboundMsg::SessionCreated { session_id, .. }) => {
                assert!(session_id.starts_with("s-"));
                assert_eq!(started.lock().unwrap().as_slice(), &[session_id]);
                // Tier-1 model support: the launch_flags model rides the resume argv as a discrete pair.
                assert_eq!(
                    launches.lock().unwrap().as_slice(),
                    &[Some(crate::resume_launch::ResumeLaunch {
                        command: "codex".into(),
                        args: vec![
                            "resume".into(),
                            "50000000-0000-4000-8000-000000000003".into(),
                            "--model".into(),
                            "gpt-5.2-codex".into()
                        ],
                    })]
                );
            }
            other => panic!("expected SessionCreated, got {other:?}"),
        }
    }

    #[test]
    fn create_session_falls_back_to_fresh_when_resume_flags_do_not_build_launch() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches: launches.clone(),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"create_session","request_id":"c-fallback","agent":"gemini","launch_flags":{"resumeMode":"resume","resumeSessionId":"gemini-id-only"}}"#,
            1600,
        );
        match r {
            Some(OutboundMsg::SessionCreated { session_id, .. }) => {
                assert!(session_id.starts_with("s-"));
                assert_eq!(started.lock().unwrap().as_slice(), &[session_id]);
                // The unresolvable resume target falls back to FRESH — but fresh with the EXPLICIT agent
                // the browser picked and a separate Hydra-owned identity, not a bare shell or latest alias.
                let launches = launches.lock().unwrap();
                let launch = launches[0].as_ref().expect("fresh Gemini launch");
                assert_eq!(launch.command, "gemini");
                assert_eq!(launch.args.len(), 2);
                assert_eq!(launch.args[0], "--session-id");
                assert_eq!(
                    uuid::Uuid::parse_str(&launch.args[1])
                        .unwrap()
                        .hyphenated()
                        .to_string(),
                    launch.args[1]
                );
            }
            other => panic!("expected SessionCreated, got {other:?}"),
        }
    }

    #[test]
    fn create_session_echoes_a_sanitized_label_f1() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches,
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        // a label with surrounding whitespace + a control char → sanitized to the trimmed visible text.
        let r = ch.handle(
            "{\"type\":\"create_session\",\"request_id\":\"c5\",\"label\":\"  build\\u0007 logs  \"}",
            1600,
        );
        match r {
            Some(OutboundMsg::SessionCreated { label, .. }) => {
                assert_eq!(label.as_deref(), Some("build logs"));
            }
            other => panic!("expected SessionCreated, got {other:?}"),
        }
    }

    #[test]
    fn sanitize_label_rules_f1() {
        assert_eq!(sanitize_label(None), None);
        assert_eq!(sanitize_label(Some("   ".into())), None); // blank → None (falls back to id)
        assert_eq!(sanitize_label(Some("  hi  ".into())).as_deref(), Some("hi"));
        // control chars stripped
        assert_eq!(
            sanitize_label(Some("a\u{0}b".into())).as_deref(),
            Some("ab")
        );
        // capped at 64 chars
        assert_eq!(sanitize_label(Some("x".repeat(100))).unwrap().len(), 64);
    }

    #[test]
    fn create_session_unauth_does_not_call_the_creator() {
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches,
        }));
        let r = ch.handle(r#"{"type":"create_session","request_id":"c4"}"#, 1);
        assert!(
            matches!(r, Some(OutboundMsg::SessionCreateError { code, .. }) if code == "unauthenticated")
        );
        assert!(started.lock().unwrap().is_empty()); // gate blocked the daemon op
    }

    #[test]
    fn authenticated_claims_gate_terminal_routing() {
        // S4: terminal messages are only routed when authenticated_claims() yields Some. Pre-auth = None
        // (so the wiring refuses terminal attach); post-auth = the verified claims (token scope).
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        assert!(
            ch.authenticated_claims().is_none(),
            "unauthenticated → no terminal routing"
        );
        let tok = session_scoped_token(&sk, "dev_a", "sig", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let claims = ch.authenticated_claims().expect("authed → claims");
        assert_eq!(claims.device_id, "dev_a");
        assert_eq!(claims.session_id.as_deref(), Some("sig")); // token's scope flows to the bridge
    }

    #[test]
    fn session_scoped_token_cannot_reach_broader_control_state() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = session_scoped_token(&sk, "dev_a", "session_allowed", 1000);
        assert!(matches!(
            ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500),
            Some(OutboundMsg::AuthOk { .. })
        ));

        let denied = [
            r#"{"type":"list_request","request_id":"list"}"#,
            r#"{"type":"create_session","request_id":"create"}"#,
            r#"{"type":"list_agent_sessions","request_id":"history","agent":"claude"}"#,
            r#"{"type":"list_directories","request_id":"dirs"}"#,
            r#"{"type":"preview_agent_session","request_id":"preview","agent":"claude","session_id":"session_other"}"#,
            r#"{"type":"manage_agent_session","request_id":"manage","action":"delete","agent":"claude","session_id":"session_other"}"#,
            r#"{"type":"split_pane","request_id":"split","window_id":"w","from_pane_id":"p","dir":"right"}"#,
            r#"{"type":"new_pane","request_id":"pane","window_id":"w","from_pane_id":"p"}"#,
            r#"{"type":"revive_pane","request_id":"revive","window_id":"w","pane_id":"p"}"#,
            r#"{"type":"start_pane_session","request_id":"start","window_id":"w","pane_id":"p"}"#,
            r#"{"type":"stash_pane","request_id":"stash","window_id":"w","pane_id":"p"}"#,
            r#"{"type":"remove_pane","request_id":"remove","window_id":"w","pane_id":"p"}"#,
            r#"{"type":"rename","request_id":"rename","window_id":"w","name":"n"}"#,
            r#"{"type":"focus_window","request_id":"focus","window_id":"w"}"#,
            r#"{"type":"close_window","request_id":"close","window_id":"w"}"#,
            r#"{"type":"new_window","request_id":"window","project_id":"p","name":"n"}"#,
            r#"{"type":"project_create","request_id":"project-create","name":"n","root":"/tmp"}"#,
            r#"{"type":"project_update","request_id":"project-update","project_id":"p"}"#,
            r#"{"type":"delete_project","request_id":"project-delete","project_id":"p"}"#,
            r#"{"type":"set_winsize_owner","selected":true}"#,
        ];
        for message in denied {
            let reply = ch.handle(message, 1600).expect("scoped refusal reply");
            let wire = serde_json::to_value(reply).unwrap();
            assert_eq!(
                wire.get("code").and_then(|value| value.as_str()),
                Some("session_scope"),
                "unexpected scoped reply for {message}: {wire}"
            );
        }
    }

    #[test]
    fn session_scoped_history_rpc_allows_only_the_exact_session_id() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = session_scoped_token(&sk, "dev_a", "session_allowed", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        let preview = ch
            .handle(
                r#"{"type":"preview_agent_session","request_id":"preview","agent":"claude","session_id":"session_allowed"}"#,
                1600,
            )
            .unwrap();
        assert!(matches!(
            preview,
            OutboundMsg::AgentSessionPreviewError { code, .. } if code == "not_implemented"
        ));
        let manage = ch
            .handle(
                r#"{"type":"manage_agent_session","request_id":"manage","action":"hide","agent":"claude","session_id":"session_allowed"}"#,
                1600,
            )
            .unwrap();
        assert!(matches!(
            manage,
            OutboundMsg::AgentSessionManageError { code, .. } if code == "not_implemented"
        ));
    }

    #[test]
    fn revoke_drops_authenticated_claims() {
        let (sk, vk) = keys();
        use std::cell::Cell;
        let revoked = Cell::new(false);
        let mut ch = ControlChannel::new(vk, "dev_a".into(), |_a: &str, _d: &str, _i: u64| {
            revoked.get()
        });
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert!(ch.authenticated_claims().is_some());
        revoked.set(true);
        assert!(
            ch.authenticated_claims().is_none(),
            "revoke drops terminal routing"
        );
    }

    #[test]
    fn live_revocation_delivery_closes_an_authenticated_channel() {
        // INTEGRATION of the live-revocation-delivery path with the control channel: the `revoked` closure
        // that the peer composes reads a shared RevocationState fed by the cloud poll. When a later poll
        // marks THIS peer's browser id revoked, the channel de-auths on its next check. The live WebRTC path's
        // independent <=2s authority watchdog also closes binary input without waiting for control-loop progress.
        use crate::revocation::RevocationState;
        let (sk, vk) = keys();
        let state = RevocationState::new();
        let closure = {
            let state = state.clone();
            move |_a: &str, browser: &str, iat: u64| state.is_revoked(browser, iat)
        };
        let mut ch = ControlChannel::new(vk, "dev_a".into(), closure);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert!(
            ch.authenticated_claims().is_some(),
            "authed before revoke poll"
        );
        // a cloud poll lands marking dev_a (this peer) revoked
        state.update(
            false,
            std::collections::HashSet::from(["dev_a".to_string()]),
            0,
        );
        assert!(
            ch.authenticated_claims().is_none(),
            "live revocation delivery de-auths the channel mid-session"
        );
    }

    #[test]
    fn deletion_revocation_and_outage_expiry_use_the_route_agnostic_post_ice_gate() {
        // ICE selects Direct or Relay before this common authenticated control channel. Both labels therefore
        // exercise one structural post-ICE gate, not physical route qualification. TURN cannot become an
        // authorization bypass here, and the production token lifetime is ten minutes.
        use crate::revocation::RevocationState;
        let (sk, vk) = keys();
        for route in ["direct", "relay"] {
            let state = RevocationState::new();
            state.update(false, std::collections::HashSet::new(), 0);
            let closure = {
                let state = state.clone();
                move |_account: &str, browser: &str, iat: u64| state.is_revoked(browser, iat)
            };
            let mut outage_channel = ControlChannel::new(vk, "dev_a".into(), closure);
            let claims = TokenClaims {
                account_id: "acct".into(),
                device_id: "dev_a".into(),
                session_id: Some("sig".into()),
                signal_session_id: None,
                target_device_id: Some("dev_desk".into()),
                browser_pubkey: None,
                browser_pubkey_alg: None,
                refresh_parent_sha256: None,
                iat_ms: 1_000,
                exp_ms: 601_000,
            };
            let token = sign_token(&claims, &sk);
            assert!(
                matches!(
                    outage_channel
                        .handle(&format!(r#"{{"type":"auth","token":"{token}"}}"#), 1_000),
                    Some(OutboundMsg::AuthOk { .. })
                ),
                "{route} authenticated before the simulated API outage"
            );
            // No successful poll lands during the outage. Existing authority remains usable before expiry,
            // then fails closed at the exact token deadline; remote_peer's binary gate enforces the same deadline
            // synchronously while its watchdog retires the transport independently.
            assert!(
                outage_channel.authenticated_claims_at(600_999).is_some(),
                "{route}"
            );
            assert!(
                outage_channel.authenticated_claims_at(601_000).is_none(),
                "{route}"
            );

            let deleted = RevocationState::new();
            let deleted_closure = {
                let deleted = deleted.clone();
                move |_account: &str, browser: &str, iat: u64| deleted.is_revoked(browser, iat)
            };
            let mut deleted_channel = ControlChannel::new(vk, "dev_a".into(), deleted_closure);
            let token = sign_token(&claims, &sk);
            assert!(
                matches!(
                    deleted_channel
                        .handle(&format!(r#"{{"type":"auth","token":"{token}"}}"#), 1_000),
                    Some(OutboundMsg::AuthOk { .. })
                ),
                "{route}"
            );
            // Account deletion removes the desktop row; either a successful self-revoked snapshot or the exact
            // unknown_device terminal denial makes the shared state self-revoked (the latter is covered in
            // revocation.rs). The common route closes on its next auth check.
            deleted.update(true, std::collections::HashSet::new(), 1_000);
            assert!(
                deleted_channel.authenticated_claims_at(1_001).is_none(),
                "{route}"
            );
        }
    }

    #[test]
    fn valid_token_authenticates_then_privileged_works() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        match a {
            Some(OutboundMsg::AuthOk {
                agent_build_git, ..
            }) => assert_eq!(agent_build_git, public_agent_build_git(crate::build_git())),
            other => panic!("expected auth_ok, got {other:?}"),
        }
        assert!(ch.is_authenticated());
        let r = ch.handle(r#"{"type":"list_request","request_id":"r1"}"#, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::ListResult {
                request_id: "r1".into(),
                items: vec![]
            })
        );
    }

    #[test]
    fn signal_session_bound_token_must_match_this_signaling_session() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_expected_signal_session_id("sig_expected");
        let tok = signal_bound_token(&sk, "dev_a", "sig_other", 1000);
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert_eq!(
            a,
            Some(OutboundMsg::AuthRefused {
                reason: "wrong_signal_session".into()
            })
        );
        assert!(!ch.is_authenticated());
    }

    #[test]
    fn signal_session_bound_token_authenticates_when_it_matches() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_expected_signal_session_id("sig_expected");
        let tok = signal_bound_token(&sk, "dev_a", "sig_expected", 1000);
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert!(matches!(a, Some(OutboundMsg::AuthOk { .. })));
        assert!(ch.is_authenticated());
    }

    // CROSS-COMPONENT integration test (assessment ask): reproduce the CLOUD's exact hand-built claimsJson
    // (signed-token.ts `claimsJson`, fixed key order) carrying a signal_session_id, sign it with the cloud
    // key, and drive the agent's REAL Auth handler with the expected signaling session set. This exercises
    // the actual cloud token format + actual signaling id + actual agent authentication logic together —
    // catching any drift between the cloud's byte layout and the agent's deserializer/binding check that
    // per-component mocks would miss. Matches the two-stage handshake: session exists → token bound to it.
    fn cloud_signal_bound_token(
        cloud_sk: &SigningKey,
        account: &str,
        dev: &str,
        signal_session_id: &str,
        now: u64,
    ) -> String {
        use ed25519_dalek::Signer;
        // EXACTLY signed-token.ts claimsJson field order for a browser token WITH signal_session_id (no
        // session_id, no browser_pubkey in this case): account_id, device_id, signal_session_id, iat_ms, exp_ms.
        let cloud_json = format!(
            r#"{{"account_id":{account:?},"device_id":{dev:?},"signal_session_id":{sid:?},"iat_ms":{now},"exp_ms":{exp}}}"#,
            sid = signal_session_id,
            exp = now + 60_000,
        );
        // base64URL no-pad — the exact encoding signed-token.ts uses and remote_token::verify_token expects.
        let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        let claims_b64 = b64.encode(cloud_json.as_bytes());
        let sig = cloud_sk.sign(claims_b64.as_bytes());
        format!("{claims_b64}.{}", b64.encode(sig.to_bytes()))
    }

    #[test]
    fn cloud_exact_signal_bound_token_authenticates_against_the_matching_session() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_expected_signal_session_id("sig_live_42");
        let tok = cloud_signal_bound_token(&sk, "acct", "dev_a", "sig_live_42", 1000);
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert!(matches!(a, Some(OutboundMsg::AuthOk { .. })), "got {a:?}");
        assert!(ch.is_authenticated());
    }

    #[test]
    fn cloud_exact_signal_bound_token_is_refused_against_a_different_session() {
        // The exact release-blocker scenario: a token minted for signaling session A presented to a channel
        // answering session B → refused. (Before the two-stage fix, the browser minted a token with NO/other
        // signal_session_id and the agent would have rejected the production handshake.)
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_expected_signal_session_id("sig_live_42");
        let tok = cloud_signal_bound_token(&sk, "acct", "dev_a", "sig_DIFFERENT", 1000);
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert_eq!(
            a,
            Some(OutboundMsg::AuthRefused {
                reason: "wrong_signal_session".into()
            })
        );
        assert!(!ch.is_authenticated());
    }

    #[test]
    fn signal_session_binding_is_fail_closed_when_the_token_omits_the_claim() {
        // A signaling session is expected, but the token carries NO signal_session_id → REFUSE (previously
        // this fell open and authenticated, letting a token be replayed onto a different signaling session).
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_expected_signal_session_id("sig_expected");
        let tok = token(&sk, "dev_a", 1000); // token() sets signal_session_id: None
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert_eq!(
            a,
            Some(OutboundMsg::AuthRefused {
                reason: "wrong_signal_session".into()
            })
        );
        assert!(!ch.is_authenticated());
    }

    fn continuity_claims(parent_token: Option<&str>, iat_ms: u64, exp_ms: u64) -> TokenClaims {
        TokenClaims {
            account_id: "acct".into(),
            device_id: "dev_a".into(),
            session_id: None,
            signal_session_id: Some("sig_continuity".into()),
            target_device_id: Some("dev_desk".into()),
            browser_pubkey: None,
            browser_pubkey_alg: None,
            refresh_parent_sha256: parent_token.map(|token| {
                Sha256::digest(token.as_bytes())
                    .iter()
                    .map(|byte| format!("{byte:02x}"))
                    .collect()
            }),
            iat_ms,
            exp_ms,
        }
    }

    type ContinuityTestChannel = ControlChannel<fn(&str, &str, u64) -> bool>;

    fn continuity_channel(sk: &SigningKey, vk: VerifyingKey) -> (ContinuityTestChannel, String) {
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_expected_signal_session_id("sig_continuity");
        ch.set_passkey_context(None, "dev_desk", false, test_cert_policy());
        assert!(matches!(
            ch.handle(
                r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client","capabilities":["authorization_refresh_v1","creation_request_replay_v1"]}"#,
                900,
            ),
            Some(OutboundMsg::Hello { .. })
        ));
        let initial = sign_token(&continuity_claims(None, 1_000, 11_000), sk);
        assert!(matches!(
            ch.handle(&format!(r#"{{"type":"auth","token":"{initial}"}}"#), 1_500),
            Some(OutboundMsg::AuthOk { .. })
        ));
        (ch, initial)
    }

    #[test]
    fn initial_auth_requires_the_exact_target_and_never_accepts_an_unbound_token() {
        let (sk, vk) = keys();
        for target in [None, Some("dev_other")] {
            let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
            ch.set_expected_signal_session_id("sig_continuity");
            ch.set_passkey_context(None, "dev_desk", false, test_cert_policy());
            let mut claims = continuity_claims(None, 1_000, 11_000);
            claims.target_device_id = target.map(str::to_string);
            let token = sign_token(&claims, &sk);
            assert!(matches!(
                ch.handle(&format!(r#"{{"type":"auth","token":"{token}"}}"#), 1_500),
                Some(OutboundMsg::AuthRefused { reason }) if reason == "wrong_target"
            ));
        }
    }

    #[test]
    fn same_channel_refresh_preserves_bridge_epoch_and_rejects_siblings_or_mutated_bindings() {
        let (sk, vk) = keys();
        let (mut ch, initial) = continuity_channel(&sk, vk);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
        }));
        let request = r#"{"type":"create_session","request_id":"continuity-replay"}"#;
        assert!(matches!(
            ch.handle(request, 1_600),
            Some(OutboundMsg::SessionCreated { .. })
        ));

        let successor = sign_token(&continuity_claims(Some(&initial), 2_000, 12_000), &sk);
        assert_eq!(
            ch.handle(
                &format!(r#"{{"type":"auth_refresh","token":"{successor}"}}"#),
                2_100
            ),
            Some(OutboundMsg::AuthRefreshOk {
                expires_at_ms: 12_000
            })
        );
        // Exact mutation replay remains cached across a pure expiry advance.
        assert!(matches!(
            ch.handle(request, 2_200),
            Some(OutboundMsg::SessionCreated { .. })
        ));
        assert_eq!(started.lock().unwrap().len(), 1);

        let sibling = sign_token(&continuity_claims(Some(&initial), 2_001, 12_001), &sk);
        assert!(matches!(
            ch.handle(&format!(r#"{{"type":"auth_refresh","token":"{sibling}"}}"#), 2_300),
            Some(OutboundMsg::AuthRefreshRefused { reason }) if reason == "stale_continuity"
        ));

        for mutation in 0..6 {
            let (mut candidate_channel, predecessor) = continuity_channel(&sk, vk);
            let mut claims = continuity_claims(Some(&predecessor), 2_000, 12_000);
            match mutation {
                0 => claims.account_id = "other".into(),
                1 => claims.session_id = Some("other_session".into()),
                2 => claims.signal_session_id = Some("other_signal".into()),
                3 => claims.target_device_id = Some("other_desktop".into()),
                4 => claims.browser_pubkey = Some("other_key".into()),
                _ => claims.device_id = "other_browser".into(),
            }
            let candidate = sign_token(&claims, &sk);
            assert!(matches!(
                candidate_channel.handle(
                    &format!(r#"{{"type":"auth_refresh","token":"{candidate}"}}"#),
                    2_100,
                ),
                Some(OutboundMsg::AuthRefreshRefused { .. })
            ));
        }
    }

    #[test]
    fn successor_iat_never_advances_the_live_account_revocation_epoch() {
        let (sk, vk) = keys();
        let revoke_before = std::sync::Arc::new(std::sync::atomic::AtomicU64::new(0));
        let observed_revoke_before = revoke_before.clone();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), move |_, _, authority_iat_ms| {
            let cutoff = observed_revoke_before.load(std::sync::atomic::Ordering::SeqCst);
            cutoff != 0 && authority_iat_ms <= cutoff
        });
        ch.set_expected_signal_session_id("sig_continuity");
        ch.set_passkey_context(None, "dev_desk", false, test_cert_policy());
        assert!(matches!(
            ch.handle(
                r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client","capabilities":["authorization_refresh_v1"]}"#,
                900,
            ),
            Some(OutboundMsg::Hello { .. })
        ));
        let initial = sign_token(&continuity_claims(None, 1_000, 11_000), &sk);
        assert!(matches!(
            ch.handle(&format!(r#"{{"type":"auth","token":"{initial}"}}"#), 1_100),
            Some(OutboundMsg::AuthOk { .. })
        ));
        let successor = sign_token(&continuity_claims(Some(&initial), 2_000, 12_000), &sk);
        assert!(matches!(
            ch.handle(
                &format!(r#"{{"type":"auth_refresh","token":"{successor}"}}"#),
                2_100,
            ),
            Some(OutboundMsg::AuthRefreshOk { .. })
        ));
        assert_eq!(ch.authed_revocation_iat_ms, Some(1_000));
        assert!(ch.authenticated_claims_at(2_100).is_some());
        #[cfg(feature = "webrtc")]
        assert_eq!(
            ch.authenticated_authority_snapshot_at(2_100),
            Some(AuthenticatedAuthoritySnapshot {
                account_id: "acct".to_string(),
                revocation_iat_ms: 1_000,
                expires_at_ms: 12_000,
            })
        );

        // Account revocation happened after the initial authority but before its successor. Comparing the live
        // channel against successor iat=2000 would miss it; the preserved initial epoch=1000 must retire it.
        revoke_before.store(1_500, std::sync::atomic::Ordering::SeqCst);
        assert!(ch.authenticated_claims_at(2_101).is_none());
        assert!(ch.authed_token_sha256.is_none());
        assert!(ch.authed_revocation_iat_ms.is_none());
    }

    #[test]
    fn missed_refresh_after_token_expiry_drops_authority() {
        let (sk, vk) = keys();
        let (mut ch, initial) = continuity_channel(&sk, vk);
        let late = sign_token(&continuity_claims(Some(&initial), 12_000, 22_000), &sk);
        assert!(matches!(
            ch.handle(&format!(r#"{{"type":"auth_refresh","token":"{late}"}}"#), 11_000),
            Some(OutboundMsg::AuthRefreshRefused { reason }) if reason == "missing"
        ));
        assert!(!ch.is_authenticated());
    }

    // ---- browser proof-of-possession (#5) ----
    // Build a real browser Ed25519 key, its SPKI base64, and a token embedding browser_pubkey.
    fn browser_key_and_token(
        cloud_sk: &SigningKey,
        dev: &str,
        now: u64,
    ) -> (ed25519_dalek::SigningKey, String, String) {
        use ed25519_dalek::SigningKey as EdSk;
        use rand::rngs::OsRng;
        let bsk = EdSk::generate(&mut OsRng);
        let mut spki = vec![
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        spki.extend_from_slice(bsk.verifying_key().as_bytes());
        let pub_b64 = base64::engine::general_purpose::STANDARD.encode(&spki);
        let tok = sign_token(
            &TokenClaims {
                account_id: "acct".into(),
                device_id: dev.into(),
                session_id: None,
                signal_session_id: None,
                target_device_id: Some("dev_desk".into()),
                browser_pubkey: Some(pub_b64.clone()),
                browser_pubkey_alg: Some("ed25519".into()),
                refresh_parent_sha256: None,
                iat_ms: now,
                exp_ms: now + 60_000,
            },
            cloud_sk,
        );
        (bsk, pub_b64, tok)
    }

    #[test]
    fn enrolled_desktop_refuses_a_signed_token_for_another_account() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_enrollment_context("acct_local");
        let tok = token(&sk, "dev_a", 1000);
        assert_eq!(
            ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500),
            Some(OutboundMsg::AuthRefused {
                reason: "wrong_account".into(),
            })
        );
        assert!(!ch.is_authenticated());
    }

    #[test]
    fn enrolled_desktop_without_a_pinned_passkey_requires_explicit_reenrollment() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_enrollment_context("acct");
        ch.set_passkey_context(None, "dev_desk", true, test_cert_policy());
        let (_browser_key, _browser_public, tok) = browser_key_and_token(&sk, "dev_a", 1000);
        assert_eq!(
            ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500),
            Some(OutboundMsg::AuthRefused {
                reason: "passkey_reenrollment_required".into(),
            })
        );
        assert!(!ch.is_authenticated());
    }

    #[test]
    fn enrolled_desktop_without_passkey_refuses_even_a_valid_browser_offer_proof() {
        use ed25519_dalek::Signer;
        let (sk, vk) = keys();
        let (bsk, _pub, tok) = browser_key_and_token(&sk, "dev_a", 1000);
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_enrollment_context("acct");
        // The browser signed the offer challenge for THIS device + fingerprint.
        let fp = "aa:bb:cc";
        let challenge = crate::browser_pop::offer_challenge("dev_a", fp);
        let sig = base64::engine::general_purpose::STANDARD
            .encode(bsk.sign(challenge.as_bytes()).to_bytes());
        ch.set_offer_proof("dev_a".into(), fp.into(), sig);
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert_eq!(
            a,
            Some(OutboundMsg::AuthRefused {
                reason: "passkey_reenrollment_required".into(),
            })
        );
        assert!(!ch.is_authenticated());
    }

    #[test]
    fn browser_pop_token_is_refused_without_an_offer_proof() {
        let (sk, vk) = keys();
        let (_bsk, _pub, tok) = browser_key_and_token(&sk, "dev_a", 1000);
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        // No set_offer_proof → the token requires a proof but the offer carried none → REFUSE.
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert_eq!(
            a,
            Some(OutboundMsg::AuthRefused {
                reason: "bad_browser_proof".into()
            })
        );
        assert!(!ch.is_authenticated());
    }

    #[test]
    fn browser_pop_token_is_refused_with_a_wrong_key_proof() {
        use ed25519_dalek::Signer;
        use rand::rngs::OsRng;
        let (sk, vk) = keys();
        let (_bsk, _pub, tok) = browser_key_and_token(&sk, "dev_a", 1000);
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        // Sign the challenge with a DIFFERENT key than the token's browser_pubkey → possession NOT proven.
        let attacker = ed25519_dalek::SigningKey::generate(&mut OsRng);
        let fp = "aa:bb:cc";
        let challenge = crate::browser_pop::offer_challenge("dev_a", fp);
        let sig = base64::engine::general_purpose::STANDARD
            .encode(attacker.sign(challenge.as_bytes()).to_bytes());
        ch.set_offer_proof("dev_a".into(), fp.into(), sig);
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert_eq!(
            a,
            Some(OutboundMsg::AuthRefused {
                reason: "bad_browser_proof".into()
            })
        );
    }

    // Test cert policy: our app origin + a max TTL covering the helper's 60s cert.
    fn test_cert_policy() -> crate::browser_cert::CertPolicy {
        crate::browser_cert::CertPolicy {
            allowed_origins: vec!["https://app.hydraterms.com".to_string()],
            max_ttl_ms: 120_000,
        }
    }

    // ---- Access Passkey (#11) cross-component: token(+valid PoP) → cert verified against a pinned passkey.
    // Build a browser Ed25519 identity (for the token + offer PoP) AND an ES256 passkey that signs a cert
    // over the browser's pubkey, mirroring the full browser→agent handshake. Returns the pieces the Auth
    // handler needs. `desktop_id`/`account` bind the cert; `now` is the auth time.
    #[allow(clippy::type_complexity)]
    fn browser_with_passkey_cert(
        cloud_sk: &SigningKey,
        dev: &str,
        account: &str,
        desktop_id: &str,
        now: u64,
    ) -> (
        String,                                // token (browser_pubkey embedded)
        String,                                // fingerprint
        String, // offer-proof sig (browser key over the offer challenge)
        crate::browser_cert::PasskeyPublicKey, // the pinned passkey
        crate::browser_cert::BrowserCert, // the browser cert (or a tamperable copy)
    ) {
        use ed25519_dalek::Signer as _;
        use p256::ecdsa::{DerSignature, SigningKey as P256Sk};
        use p256::pkcs8::EncodePublicKey as _;
        use rand::rngs::OsRng;
        use sha2::{Digest, Sha256};
        let b64 = base64::engine::general_purpose::STANDARD;
        let url = base64::engine::general_purpose::URL_SAFE_NO_PAD;
        // Browser device key (Ed25519) → token browser_pubkey + offer PoP.
        let (bsk, browser_pub_b64, tok) = browser_key_and_token(cloud_sk, dev, now);
        let fp = "aa:bb:cc";
        let challenge = crate::browser_pop::offer_challenge(dev, fp);
        let offer_sig = b64.encode(bsk.sign(challenge.as_bytes()).to_bytes());
        // Passkey (ES256) signs the cert over the browser pubkey + desktop + account.
        let psk = P256Sk::random(&mut OsRng);
        let pvk = *psk.verifying_key();
        let passkey = crate::browser_cert::PasskeyPublicKey {
            spki_b64: b64.encode(pvk.to_public_key_der().unwrap().as_bytes()),
            alg: "es256".into(),
            rp_id: "hydraterms.com".into(),
        };
        let expiry = now + 60_000;
        let nonce = "n1";
        let signed = crate::browser_cert::cert_signed_bytes(
            &browser_pub_b64,
            desktop_id,
            account,
            expiry,
            nonce,
        );
        let cert_challenge = url.encode(Sha256::digest(&signed));
        let client_data = format!(
            r#"{{"type":"webauthn.get","challenge":"{cert_challenge}","origin":"https://app.hydraterms.com","crossOrigin":false}}"#
        );
        let mut auth_data = Sha256::digest(b"hydraterms.com").to_vec();
        auth_data.push(0x05); // UP + UV
        auth_data.extend_from_slice(&[0, 0, 0, 1]);
        let mut to_sign = auth_data.clone();
        to_sign.extend_from_slice(Sha256::digest(client_data.as_bytes()).as_slice());
        let der: DerSignature = psk.sign(&to_sign);
        let cert = crate::browser_cert::BrowserCert {
            browser_pubkey: browser_pub_b64,
            desktop_id: desktop_id.into(),
            account_id: account.into(),
            expiry_ms: expiry,
            nonce: nonce.into(),
            assertion: crate::browser_cert::WebauthnAssertion {
                authenticator_data: url.encode(&auth_data),
                client_data_json: url.encode(client_data.as_bytes()),
                signature: url.encode(der.as_bytes()),
            },
        };
        (tok, fp.into(), offer_sig, passkey, cert)
    }

    #[test]
    fn passkey_cert_authenticates_when_valid() {
        let (sk, vk) = keys();
        let (_short_tok, fp, offer_sig, passkey, cert) =
            browser_with_passkey_cert(&sk, "dev_a", "acct", "dev_desk", 1000);
        // Token authority intentionally extends beyond the cert so this proves the independent certificate
        // boundary, not ordinary token expiry.
        let tok = sign_token(
            &TokenClaims {
                account_id: "acct".into(),
                device_id: "dev_a".into(),
                session_id: None,
                signal_session_id: None,
                target_device_id: Some("dev_desk".into()),
                browser_pubkey: Some(cert.browser_pubkey.clone()),
                browser_pubkey_alg: Some("ed25519".into()),
                refresh_parent_sha256: None,
                iat_ms: 1_000,
                exp_ms: 121_000,
            },
            &sk,
        );
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_enrollment_context("acct");
        assert!(matches!(
            ch.handle(
                r#"{"type":"hello","protocol_version":1,"device_id":"dev_a","role":"client","capabilities":["authorization_refresh_v1"]}"#,
                900,
            ),
            Some(OutboundMsg::Hello { .. })
        ));
        ch.set_offer_proof("dev_a".into(), fp, offer_sig);
        ch.set_passkey_context(Some(passkey), "dev_desk", false, test_cert_policy());
        ch.set_browser_cert(cert.clone());
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert!(matches!(a, Some(OutboundMsg::AuthOk { .. })), "got {a:?}");
        assert!(ch.is_authenticated());
        assert!(ch.authenticated_claims_at(60_999).is_some());
        #[cfg(feature = "webrtc")]
        assert_eq!(
            ch.authenticated_authority_snapshot_at(60_999),
            Some(AuthenticatedAuthoritySnapshot {
                account_id: "acct".to_string(),
                revocation_iat_ms: 1_000,
                expires_at_ms: 61_000,
            })
        );
        let successor = sign_token(
            &TokenClaims {
                account_id: "acct".into(),
                device_id: "dev_a".into(),
                session_id: None,
                signal_session_id: None,
                target_device_id: Some("dev_desk".into()),
                browser_pubkey: Some(cert.browser_pubkey.clone()),
                browser_pubkey_alg: Some("ed25519".into()),
                refresh_parent_sha256: Some(
                    Sha256::digest(tok.as_bytes())
                        .iter()
                        .map(|byte| format!("{byte:02x}"))
                        .collect(),
                ),
                iat_ms: 60_000,
                exp_ms: 130_000,
            },
            &sk,
        );
        assert_eq!(
            ch.handle(
                &format!(r#"{{"type":"auth_refresh","token":"{successor}"}}"#),
                60_999,
            ),
            Some(OutboundMsg::AuthRefreshOk {
                expires_at_ms: 130_000,
            })
        );
        // The certificate's independent absolute deadline still retires the newly refreshed token.
        assert!(ch.authenticated_claims_at(61_000).is_none());
    }

    #[test]
    fn passkey_pinned_but_a_tampered_cert_is_refused() {
        let (sk, vk) = keys();
        let (tok, fp, offer_sig, passkey, mut cert) =
            browser_with_passkey_cert(&sk, "dev_a", "acct", "dev_desk", 1000);
        // Attacker extends the cert expiry after signing → the challenge no longer matches → refuse.
        cert.expiry_ms = 9_999_999;
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_offer_proof("dev_a".into(), fp, offer_sig);
        ch.set_passkey_context(Some(passkey), "dev_desk", false, test_cert_policy());
        ch.set_browser_cert(cert);
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert_eq!(
            a,
            Some(OutboundMsg::AuthRefused {
                reason: "bad_browser_cert".into()
            })
        );
    }

    #[test]
    fn passkey_pinned_and_no_cert_is_refused_fail_closed() {
        // THE RELEASE-BLOCKER FIX: a pinned passkey makes a cert MANDATORY. A browser (or a compromised cloud
        // relaying the offer) that omits the cert is REFUSED — the cloud cannot downgrade by omitting fields.
        let (sk, vk) = keys();
        let (tok, fp, offer_sig, passkey, _cert) =
            browser_with_passkey_cert(&sk, "dev_a", "acct", "dev_desk", 1000);
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_offer_proof("dev_a".into(), fp, offer_sig);
        ch.set_passkey_context(Some(passkey), "dev_desk", false, test_cert_policy()); // NOT allowing legacy
                                                                                      // no set_browser_cert → missing cert
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert_eq!(
            a,
            Some(OutboundMsg::AuthRefused {
                reason: "browser_cert_required".into()
            })
        );
        assert!(!ch.is_authenticated());
    }

    #[test]
    fn passkey_pinned_but_token_omits_browser_pubkey_is_refused() {
        // A compromised cloud could also strip browser_pubkey from the token to skip PoP+cert. With a passkey
        // pinned, that too is refused (the requirement is driven by the LOCAL passkey, not cloud fields).
        let (sk, vk) = keys();
        let (_bsk, _pub, _tok_with_pub) = browser_key_and_token(&sk, "dev_a", 1000);
        let (_t, _fp, _sig, passkey, _cert) =
            browser_with_passkey_cert(&sk, "dev_a", "acct", "dev_desk", 1000);
        // A target-bound token WITHOUT browser_pubkey. Target binding succeeds first; the locally pinned passkey
        // must still refuse the attempted key/certificate downgrade.
        let plain = sign_token(
            &TokenClaims {
                account_id: "acct".into(),
                device_id: "dev_a".into(),
                session_id: Some("sig".into()),
                signal_session_id: None,
                target_device_id: Some("dev_desk".into()),
                browser_pubkey: None,
                browser_pubkey_alg: None,
                refresh_parent_sha256: None,
                iat_ms: 1_000,
                exp_ms: 61_000,
            },
            &sk,
        );
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_passkey_context(Some(passkey), "dev_desk", false, test_cert_policy());
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{plain}"}}"#), 1500);
        assert_eq!(
            a,
            Some(OutboundMsg::AuthRefused {
                reason: "browser_cert_required".into()
            })
        );
    }

    #[test]
    fn internal_compatibility_parameter_allows_a_browser_without_a_cert() {
        // The control primitive retains an explicit compatibility parameter for old enrolled records. The
        // shipping private composition hard-codes it off; there is no environment, flag, or public-extension
        // request that can turn it on.
        let (sk, vk) = keys();
        let (tok, fp, offer_sig, passkey, _cert) =
            browser_with_passkey_cert(&sk, "dev_a", "acct", "dev_desk", 1000);
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_offer_proof("dev_a".into(), fp, offer_sig);
        ch.set_passkey_context(Some(passkey), "dev_desk", true, test_cert_policy()); // LOCAL migration mode ON
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert!(matches!(a, Some(OutboundMsg::AuthOk { .. })), "got {a:?}");
    }

    #[test]
    fn token_expiry_is_enforced_live_not_just_at_connect() {
        // Authenticate with a token that expires at exp_ms = now+60_000.
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000); // exp_ms = 61_000
        assert!(matches!(
            ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1000),
            Some(OutboundMsg::AuthOk { .. })
        ));
        assert!(ch.is_authenticated());
        // A privileged message BEFORE expiry still works.
        assert!(ch.authenticated_claims_at(60_000).is_some());
        // At/after exp_ms the session is dropped on the next op AND on the idle-tick path.
        assert!(ch.authenticated_claims_at(61_000).is_none());
        assert!(!ch.is_authenticated());
    }

    #[test]
    fn handle_drops_expired_auth_before_privileged_ops() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000); // exp_ms = 61_000
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1000);
        assert!(ch.is_authenticated());
        // A message processed at now=61_000 must find the channel de-authed (drop_if_expired in handle()).
        ch.handle(r#"{"type":"ping","nonce":"n"}"#, 61_000);
        assert!(!ch.is_authenticated());
    }

    #[test]
    fn list_agent_sessions_requires_auth_then_returns_content_blind_result() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        // before auth → refused (privileged, same gate as list_request).
        let pre = ch.handle(
            r#"{"type":"list_agent_sessions","request_id":"a1","agent":"codex","cwd":"/Users/test/api"}"#,
            1500,
        );
        assert!(matches!(pre, Some(OutboundMsg::AuthRefused { .. })));
        // after auth → an AgentSessionsResult; the row count depends on local desktop history.
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"list_agent_sessions","request_id":"a2","agent":"codex","cwd":"/Users/test/api"}"#,
            1500,
        );
        match r {
            Some(OutboundMsg::AgentSessionsResult {
                request_id,
                sessions,
            }) => {
                assert_eq!(request_id, "a2");
                for session in sessions {
                    assert_eq!(session.agent, "codex");
                }
            }
            other => panic!("expected AgentSessionsResult, got {other:?}"),
        }
    }

    #[test]
    fn agent_history_mapping_is_metadata_only() {
        let meta = agent_history_session_to_meta(
            maestro_local_services::agent_history::AgentHistorySession {
                id: "sess-1".into(),
                agent: "codex".into(),
                title: "not on wire".into(),
                first_message: "SECRET MESSAGE TEXT".into(),
                modified_at_ms: 1234,
                message_count: Some(7),
                folder_index: 2,
                file_path: "/Users/test/.codex/secret.jsonl".into(),
                in_use: true,
                custom_name: Some("private label".into()),
            },
        );
        assert_eq!(
            meta,
            AgentSessionMeta {
                id: "sess-1".into(),
                agent: "codex".into(),
                modified_at_ms: 1234,
                message_count: Some(7),
                in_use: true,
                // custom_name IS mapped through: it's the USER's chosen label, not conversation content, so the
                // browser can show the same name as local. (title/first_message/file_path are still NOT sent.)
                custom_name: Some("private label".into()),
            }
        );
        let mut unknown_count = meta.clone();
        unknown_count.message_count = None;
        let unknown_wire = serde_json::to_string(&unknown_count).unwrap();
        assert!(
            !unknown_wire.contains("message_count"),
            "a bounded metadata scan must not misrepresent an unknown count as zero"
        );
        let wire = serde_json::to_string(&OutboundMsg::AgentSessionsResult {
            request_id: "a3".into(),
            sessions: vec![meta],
        })
        .unwrap();
        // Conversation/derived content must NEVER be on the wire.
        assert!(!wire.contains("SECRET MESSAGE TEXT"));
        assert!(!wire.contains("file_path"));
        assert!(!wire.contains("/Users/test/.codex/secret.jsonl"));
        assert!(!wire.contains("first_message"));
        assert!(!wire.contains("not on wire")); // the derived `title` is NOT sent
                                                // The user-chosen custom_name IS sent (safe metadata) — that's the point of item 4.
        assert!(wire.contains("private label"));
    }

    #[test]
    fn gemini_session_file_resolver_matches_by_id_stays_off_wire() {
        let row = |id: &str, agent: &str, file: &str| {
            maestro_local_services::agent_history::AgentHistorySession {
                id: id.into(),
                agent: agent.into(),
                title: String::new(),
                first_message: String::new(),
                modified_at_ms: 0,
                message_count: Some(0),
                folder_index: 0,
                file_path: file.into(),
                in_use: false,
                custom_name: None,
            }
        };
        let sessions = vec![
            row("g-1", "gemini", "/Users/test/.gemini/g-1.json"),
            row("g-2", "gemini", "/Users/test/.gemini/g-2.json"),
            // a same-id row for a DIFFERENT agent must not be matched.
            row("g-2", "codex", "/Users/test/.codex/g-2.jsonl"),
            // an empty file_path must not resolve (would produce a broken --session-file).
            row("g-empty", "gemini", "   "),
        ];
        assert_eq!(
            gemini_session_file_for_id(&sessions, "g-2").as_deref(),
            Some("/Users/test/.gemini/g-2.json")
        );
        assert_eq!(
            gemini_session_file_for_id(&sessions, "g-1").as_deref(),
            Some("/Users/test/.gemini/g-1.json")
        );
        assert_eq!(gemini_session_file_for_id(&sessions, "g-empty"), None);
        assert_eq!(gemini_session_file_for_id(&sessions, "missing"), None);

        // The resolved descriptor then builds the correct Gemini resume launch — content-blind (id in, file used
        // only to build local argv).
        let mut descriptor = crate::resume_launch::ResumeDescriptor {
            agent: crate::resume_launch::ResumeAgent::Gemini,
            session_id: Some("g-2".into()),
            session_file: gemini_session_file_for_id(&sessions, "g-2"),
        };
        assert!(descriptor.session_file.is_some());
        let launch = crate::resume_launch::build_resume_launch(&descriptor).unwrap();
        assert_eq!(launch.command, "gemini");
        assert_eq!(
            launch.args,
            vec![
                "--session-file".to_string(),
                "/Users/test/.gemini/g-2.json".to_string()
            ]
        );
        // Unresolved id (no match) leaves file None → build returns None → caller starts fresh, not a broken resume.
        descriptor.session_file = gemini_session_file_for_id(&sessions, "missing");
        assert_eq!(crate::resume_launch::build_resume_launch(&descriptor), None);
    }

    #[test]
    fn list_agent_sessions_rejects_unknown_agents_with_empty_metadata() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"list_agent_sessions","request_id":"a4","agent":"unknown","cwd":"/Users/test/api"}"#,
            1500,
        );
        assert_eq!(
            r,
            Some(OutboundMsg::AgentSessionsResult {
                request_id: "a4".into(),
                sessions: vec![]
            })
        );
    }

    struct FixedAgentSessionLister {
        sessions: Vec<AgentSessionMeta>,
    }

    impl AgentSessionLister for FixedAgentSessionLister {
        fn list(
            &mut self,
            _agent: &str,
            _cwd: Option<String>,
            _include_hidden: bool,
        ) -> Vec<AgentSessionMeta> {
            self.sessions.clone()
        }
    }

    #[test]
    fn list_agent_sessions_drops_malformed_and_cross_provider_ids_before_wire() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let meta = |id: String, agent: &str| AgentSessionMeta {
            id,
            agent: agent.into(),
            modified_at_ms: 1,
            message_count: None,
            in_use: false,
            custom_name: None,
        };
        ch.set_agent_session_lister(Box::new(FixedAgentSessionLister {
            sessions: vec![
                meta("valid-session".into(), "codex"),
                meta("x".repeat(257), "codex"),
                meta("control\ncharacter".into(), "codex"),
                meta("valid-but-wrong-provider".into(), "claude"),
            ],
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        assert_eq!(
            ch.handle(
                r#"{"type":"list_agent_sessions","request_id":"safe-list","agent":"codex"}"#,
                1500,
            ),
            Some(OutboundMsg::AgentSessionsResult {
                request_id: "safe-list".into(),
                sessions: vec![meta("valid-session".into(), "codex")],
            })
        );
    }

    #[test]
    fn list_child_directories_returns_only_subdirs_content_blind() {
        // The browser folder-picker: list a dir's SUBDIRECTORIES (names + paths), no files, no dotfiles, sorted,
        // with the parent for "up". Content-blind.
        let dir = std::env::temp_dir().join(format!("hydra-dirlist-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("beta")).unwrap();
        std::fs::create_dir_all(dir.join("alpha")).unwrap();
        std::fs::create_dir_all(dir.join(".hidden")).unwrap();
        std::fs::write(dir.join("a-file.txt"), b"x").unwrap();

        let listing = list_child_directories(Some(dir.to_string_lossy().as_ref()));
        // sorted subdirs only; file + dotfile excluded.
        assert_eq!(
            listing
                .entries
                .iter()
                .map(|e| e.name.as_str())
                .collect::<Vec<_>>(),
            vec!["alpha", "beta"]
        );
        assert!(listing.entries.iter().all(|e| e.path.ends_with(&e.name)));
        assert_eq!(listing.path, dir.to_string_lossy());
        assert!(listing.parent.is_some()); // a temp subdir always has a parent for "up"
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn list_directories_requires_auth() {
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        // No auth → refused, no directory listing leaked.
        let r = ch.handle(r#"{"type":"list_directories","request_id":"d1"}"#, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::AuthRefused {
                reason: "missing".into()
            })
        );
    }

    #[test]
    fn authed_list_directories_returns_a_directories_result_end_to_end() {
        // End-to-end proof through ControlChannel::handle (the exact path a live browser request takes): an
        // AUTHED list_directories yields a directories_result, NOT bad_message. If the user's agent replied
        // bad_message instead, it is a STALE binary that predates this handler — not a code bug.
        let dir = std::env::temp_dir().join(format!("hydra-listdirs-e2e-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("alpha")).unwrap();
        std::fs::create_dir_all(dir.join("beta")).unwrap();
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let msg = format!(
            r#"{{"type":"list_directories","request_id":"d2","path":"{}"}}"#,
            dir.to_string_lossy()
        );
        match ch.handle(&msg, 1500) {
            Some(OutboundMsg::DirectoriesResult {
                request_id,
                path,
                entries,
                ..
            }) => {
                assert_eq!(request_id, "d2");
                assert_eq!(path, dir.to_string_lossy());
                assert_eq!(
                    entries.iter().map(|e| e.name.as_str()).collect::<Vec<_>>(),
                    vec!["alpha", "beta"]
                );
            }
            other => panic!(
                "expected DirectoriesResult, got {other:?} — a stale agent would give bad_message"
            ),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    struct FakePreviewer {
        calls: std::sync::Arc<std::sync::Mutex<Vec<SessionPreviewRequest>>>,
        lines: Vec<PreviewLine>,
    }
    impl SessionPreviewer for FakePreviewer {
        fn preview(&mut self, request: SessionPreviewRequest) -> Vec<PreviewLine> {
            self.calls.lock().unwrap().push(request);
            self.lines.clone()
        }
    }

    #[test]
    fn preview_agent_session_requires_auth_then_returns_transcript_lines() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let msg = r#"{"type":"preview_agent_session","request_id":"pv1","agent":"claude","cwd":"/Users/test/app","session_id":"abc","max_lines":5}"#;
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_previewer(Box::new(FakePreviewer {
            calls: calls.clone(),
            lines: vec![PreviewLine {
                role: "user".into(),
                text: "hello".into(),
            }],
        }));
        // before auth → refused (privileged), previewer not called.
        assert!(
            matches!(ch.handle(msg, 1500), Some(OutboundMsg::AgentSessionPreviewError { code, .. }) if code == "unauthenticated")
        );
        assert!(calls.lock().unwrap().is_empty());
        // after auth → calls the previewer (sanitized) and returns the transcript lines.
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(msg, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::AgentSessionPreview {
                request_id: "pv1".into(),
                lines: vec![PreviewLine {
                    role: "user".into(),
                    text: "hello".into()
                }],
            })
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].agent, "claude");
        assert_eq!(calls[0].session_id, "abc");
        assert_eq!(calls[0].max_lines, 5);
    }

    #[test]
    fn preview_agent_session_clamps_max_lines_and_defaults() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_previewer(Box::new(FakePreviewer {
            calls: calls.clone(),
            lines: vec![],
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        // no max_lines → default 40; a huge value → clamped to 200.
        ch.handle(r#"{"type":"preview_agent_session","request_id":"pv2","agent":"codex","session_id":"s"}"#, 1500);
        ch.handle(r#"{"type":"preview_agent_session","request_id":"pv3","agent":"codex","session_id":"s","max_lines":99999}"#, 1500);
        let calls = calls.lock().unwrap();
        assert_eq!(calls[0].max_lines, 40);
        assert_eq!(calls[1].max_lines, 200);
    }

    #[test]
    fn preview_agent_session_without_previewer_is_not_implemented() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(r#"{"type":"preview_agent_session","request_id":"pv4","agent":"claude","session_id":"s"}"#, 1500);
        assert!(
            matches!(r, Some(OutboundMsg::AgentSessionPreviewError { code, .. }) if code == "not_implemented")
        );
    }

    struct FakeManager {
        calls: std::sync::Arc<std::sync::Mutex<Vec<SessionManageRequest>>>,
        result: Result<(), SessionManageError>,
    }
    impl SessionManager for FakeManager {
        fn manage(&mut self, request: SessionManageRequest) -> Result<(), SessionManageError> {
            self.calls.lock().unwrap().push(request);
            self.result.clone()
        }
    }

    #[test]
    fn preview_and_manage_require_exact_provider_session_ids_without_aliasing() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let preview_calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let manage_calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_previewer(Box::new(FakePreviewer {
            calls: preview_calls.clone(),
            lines: vec![],
        }));
        ch.set_session_manager(Box::new(FakeManager {
            calls: manage_calls.clone(),
            result: Ok(()),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        let max_opaque = "x".repeat(256);
        let canonical_uuid = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";
        for (agent, session_id) in [("claude", max_opaque.as_str()), ("copilot", canonical_uuid)] {
            let preview = serde_json::json!({
                "type": "preview_agent_session",
                "request_id": format!("preview-{agent}"),
                "agent": agent,
                "session_id": session_id,
            })
            .to_string();
            assert!(matches!(
                ch.handle(&preview, 1500),
                Some(OutboundMsg::AgentSessionPreview { .. })
            ));
            let manage = serde_json::json!({
                "type": "manage_agent_session",
                "request_id": format!("manage-{agent}"),
                "action": "hide",
                "agent": agent,
                "session_id": session_id,
            })
            .to_string();
            assert!(matches!(
                ch.handle(&manage, 1500),
                Some(OutboundMsg::AgentSessionManaged { .. })
            ));
        }
        assert_eq!(preview_calls.lock().unwrap()[0].session_id, max_opaque);
        assert_eq!(preview_calls.lock().unwrap()[1].session_id, canonical_uuid);
        assert_eq!(manage_calls.lock().unwrap()[0].session_id, max_opaque);
        assert_eq!(manage_calls.lock().unwrap()[1].session_id, canonical_uuid);

        let invalid = [
            ("claude", "y".repeat(257)),
            ("claude", "control\ncharacter".into()),
            ("copilot", "not-a-uuid".into()),
            ("copilot", canonical_uuid.to_ascii_uppercase()),
        ];
        for (index, (agent, session_id)) in invalid.into_iter().enumerate() {
            let preview = serde_json::json!({
                "type": "preview_agent_session",
                "request_id": format!("bad-preview-{index}"),
                "agent": agent,
                "session_id": session_id,
            })
            .to_string();
            assert!(matches!(
                ch.handle(&preview, 1500),
                Some(OutboundMsg::AgentSessionPreviewError { code, .. })
                    if code == INVALID_PROVIDER_SESSION_ID_CODE
            ));
            let manage = serde_json::json!({
                "type": "manage_agent_session",
                "request_id": format!("bad-manage-{index}"),
                "action": "hide",
                "agent": agent,
                "session_id": session_id,
            })
            .to_string();
            assert!(matches!(
                ch.handle(&manage, 1500),
                Some(OutboundMsg::AgentSessionManageError { code, .. })
                    if code == INVALID_PROVIDER_SESSION_ID_CODE
            ));
        }
        assert_eq!(preview_calls.lock().unwrap().len(), 2);
        assert_eq!(manage_calls.lock().unwrap().len(), 2);
    }

    #[test]
    fn manage_agent_session_requires_auth_then_dispatches_rename_hide_delete() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_manager(Box::new(FakeManager {
            calls: calls.clone(),
            result: Ok(()),
        }));
        let rename = r#"{"type":"manage_agent_session","request_id":"m1","action":"rename","agent":"claude","session_id":"s1","name":"Build notes"}"#;
        // before auth → refused, manager not called.
        assert!(
            matches!(ch.handle(rename, 1500), Some(OutboundMsg::AgentSessionManageError { code, .. }) if code == "unauthenticated")
        );
        assert!(calls.lock().unwrap().is_empty());
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        // rename → carries the sanitized name.
        assert_eq!(
            ch.handle(rename, 1500),
            Some(OutboundMsg::AgentSessionManaged {
                request_id: "m1".into()
            })
        );
        // hide.
        ch.handle(r#"{"type":"manage_agent_session","request_id":"m2","action":"hide","agent":"claude","session_id":"s1"}"#, 1500);
        // delete → carries the cwd.
        ch.handle(r#"{"type":"manage_agent_session","request_id":"m3","action":"delete","agent":"claude","session_id":"s1","cwd":"/Users/test/app"}"#, 1500);
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 3);
        assert_eq!(
            calls[0].action,
            SessionManageAction::Rename {
                name: Some("Build notes".into())
            }
        );
        assert_eq!(calls[1].action, SessionManageAction::Hide);
        assert_eq!(
            calls[2].action,
            SessionManageAction::Delete {
                cwd: Some("/Users/test/app".into())
            }
        );
    }

    #[test]
    fn manage_agent_session_rejects_bad_action_and_handles_no_manager() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        // unknown action → invalid_action (before needing a manager).
        let bad = ch.handle(r#"{"type":"manage_agent_session","request_id":"m4","action":"nuke","agent":"claude","session_id":"s"}"#, 1500);
        assert!(
            matches!(bad, Some(OutboundMsg::AgentSessionManageError { code, .. }) if code == "invalid_action")
        );
        // valid action but no manager injected → not_implemented.
        let none = ch.handle(r#"{"type":"manage_agent_session","request_id":"m5","action":"hide","agent":"claude","session_id":"s"}"#, 1500);
        assert!(
            matches!(none, Some(OutboundMsg::AgentSessionManageError { code, .. }) if code == "not_implemented")
        );
    }

    #[test]
    fn unqualified_provider_launch_access_does_not_grant_history_preview_or_manage_access() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let preview_calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let manage_calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_previewer(Box::new(FakePreviewer {
            calls: preview_calls.clone(),
            lines: vec![PreviewLine {
                role: "user".into(),
                text: "must not surface".into(),
            }],
        }));
        ch.set_session_manager(Box::new(FakeManager {
            calls: manage_calls.clone(),
            result: Ok(()),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        assert_eq!(
            ch.handle(
                r#"{"type":"list_agent_sessions","request_id":"amp-list","agent":"amp"}"#,
                1500,
            ),
            Some(OutboundMsg::AgentSessionsResult {
                request_id: "amp-list".into(),
                sessions: vec![],
            })
        );
        assert_eq!(
            ch.handle(
                r#"{"type":"preview_agent_session","request_id":"amp-preview","agent":"amp","session_id":"thread-id"}"#,
                1500,
            ),
            Some(OutboundMsg::AgentSessionPreview {
                request_id: "amp-preview".into(),
                lines: vec![],
            })
        );
        assert!(matches!(
            ch.handle(
                r#"{"type":"manage_agent_session","request_id":"amp-manage","action":"hide","agent":"amp","session_id":"thread-id"}"#,
                1500,
            ),
            Some(OutboundMsg::AgentSessionManageError { code, .. }) if code == "not_found"
        ));
        assert!(preview_calls.lock().unwrap().is_empty());
        assert!(manage_calls.lock().unwrap().is_empty());

        assert_eq!(sanitize_history_agent("factory".into()), None);
        assert_eq!(sanitize_history_agent("amp".into()), None);
        assert_eq!(
            sanitize_history_agent("devin".into()).as_deref(),
            Some("devin")
        );
    }

    #[test]
    fn split_pane_requires_auth_then_calls_the_desktop_splitter() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let msg = r#"{"type":"split_pane","request_id":"s1","window_id":"w1","from_pane_id":"t1","dir":"right"}"#;
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_pane_splitter(Box::new(FakeSplitter {
            calls: calls.clone(),
            result: Ok(SplitPaneCreated {
                session_id: "s-new".into(),
                tab_id: "pane-new".into(),
            }),
        }));
        // before auth → refused (privileged) and does not call the splitter.
        assert!(matches!(
            ch.handle(msg, 1500),
            Some(OutboundMsg::SplitPaneError { code, .. }) if code == "unauthenticated"
        ));
        assert!(calls.lock().unwrap().is_empty());
        // after auth → calls the injected desktop splitter and returns its ids.
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(msg, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::SplitPaneOk {
                request_id: "s1".into(),
                session_id: "s-new".into(),
                tab_id: "pane-new".into(),
            })
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].window_id, "w1");
        assert_eq!(calls[0].from_pane_id, "t1");
        assert_eq!(calls[0].dir, SplitPaneDir::Right);
        assert_eq!(calls[0].now_ms, 1500);
    }

    #[test]
    fn new_pane_requires_auth_then_calls_the_desktop_pane_creator() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let msg = r#"{"type":"new_pane","request_id":"np1","window_id":"w1","from_pane_id":"t1","agent":"codex","cwd":" /tmp/review ","pane_name":"  Review  ","launch_flags":{"model":"gpt-5.2-codex"}}"#;
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_pane_splitter(Box::new(FakeSplitter {
            calls: calls.clone(),
            result: Ok(SplitPaneCreated {
                session_id: "s-new".into(),
                tab_id: "pane-new".into(),
            }),
        }));
        assert!(matches!(
            ch.handle(msg, 1500),
            Some(OutboundMsg::SplitPaneError { code, .. }) if code == "unauthenticated"
        ));
        assert!(calls.lock().unwrap().is_empty());

        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(msg, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::SplitPaneOk {
                request_id: "np1".into(),
                session_id: "s-new".into(),
                tab_id: "pane-new".into(),
            })
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].window_id, "w1");
        assert_eq!(calls[0].from_pane_id, "t1");
        assert_eq!(calls[0].dir, SplitPaneDir::Right);
        assert_eq!(calls[0].agent.as_deref(), Some("codex"));
        assert_eq!(calls[0].cwd.as_deref(), Some("/tmp/review"));
        assert_eq!(calls[0].pane_name.as_deref(), Some("Review"));
        assert_eq!(
            calls[0].launch_flags,
            Some(serde_json::json!({ "model": "gpt-5.2-codex" }))
        );
        assert_eq!(calls[0].now_ms, 1500);
    }

    struct FakeReviver {
        calls: std::sync::Arc<std::sync::Mutex<Vec<RevivePaneRequest>>>,
        result: Result<RevivePaneCreated, RevivePaneError>,
    }
    impl PaneReviver for FakeReviver {
        fn revive_pane(
            &mut self,
            request: RevivePaneRequest,
        ) -> Result<RevivePaneCreated, RevivePaneError> {
            self.calls.lock().unwrap().push(request);
            self.result.clone()
        }
    }

    #[test]
    fn revive_pane_requires_auth_then_calls_the_desktop_reviver() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let msg =
            r#"{"type":"revive_pane","request_id":"r1","window_id":"w1","pane_id":"t-stashed"}"#;
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_pane_reviver(Box::new(FakeReviver {
            calls: calls.clone(),
            result: Ok(RevivePaneCreated {
                session_id: "s-revived".into(),
            }),
        }));
        // before auth → refused (privileged), reviver not called.
        assert!(matches!(
            ch.handle(msg, 1500),
            Some(OutboundMsg::RevivePaneError { code, .. }) if code == "unauthenticated"
        ));
        assert!(calls.lock().unwrap().is_empty());
        // after auth → revive dispatches to the desktop so local can paint the stashed pane for remote.
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert_eq!(
            ch.handle(msg, 1500),
            Some(OutboundMsg::RevivePaneOk {
                request_id: "r1".into(),
                session_id: "s-revived".into()
            })
        );
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            &[RevivePaneRequest {
                window_id: "w1".into(),
                pane_id: "t-stashed".into(),
                now_ms: 1500,
            }]
        );
    }

    #[test]
    fn revive_pane_without_reviver_returns_not_implemented() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"revive_pane","request_id":"r2","window_id":"w","pane_id":"p"}"#,
            1500,
        );
        assert!(
            matches!(r, Some(OutboundMsg::RevivePaneError { code, .. }) if code == "not_implemented")
        );
    }

    struct FakeStasher {
        calls: std::sync::Arc<std::sync::Mutex<Vec<StashPaneRequest>>>,
        result: Result<(), RevivePaneError>,
    }
    impl PaneStasher for FakeStasher {
        fn stash_pane(&mut self, request: StashPaneRequest) -> Result<(), RevivePaneError> {
            self.calls.lock().unwrap().push(request);
            self.result.clone()
        }
    }

    #[test]
    fn stash_pane_requires_auth_then_calls_the_desktop_stasher() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let msg = r#"{"type":"stash_pane","request_id":"sp1","window_id":"w1","pane_id":"t-live"}"#;
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_pane_stasher(Box::new(FakeStasher {
            calls: calls.clone(),
            result: Ok(()),
        }));
        // before auth → refused, stasher not called.
        assert!(
            matches!(ch.handle(msg, 1500), Some(OutboundMsg::StashPaneError { code, .. }) if code == "unauthenticated")
        );
        assert!(calls.lock().unwrap().is_empty());
        // after auth → SEPARATE LAYOUTS: stash is remote-only, refused with not_applied, desktop stasher NEVER called.
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(msg, 1500);
        assert!(
            matches!(r, Some(OutboundMsg::StashPaneError { code, .. }) if code == "not_applied")
        );
        assert!(
            calls.lock().unwrap().is_empty(),
            "desktop layout must NOT be mutated by a remote stash"
        );
    }

    #[test]
    fn stash_pane_is_remote_only_never_mutates_desktop() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"stash_pane","request_id":"sp2","window_id":"w","pane_id":"p"}"#,
            1500,
        );
        assert!(
            matches!(r, Some(OutboundMsg::StashPaneError { code, .. }) if code == "not_applied")
        );
    }

    struct FakeRemover {
        calls: std::sync::Arc<std::sync::Mutex<Vec<RemovePaneRequest>>>,
        result: Result<(), RevivePaneError>,
    }
    impl PaneRemover for FakeRemover {
        fn remove_pane(&mut self, request: RemovePaneRequest) -> Result<(), RevivePaneError> {
            self.calls.lock().unwrap().push(request);
            self.result.clone()
        }
    }

    #[test]
    fn remove_pane_requires_auth_then_calls_the_desktop_remover() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let msg =
            r#"{"type":"remove_pane","request_id":"rp1","window_id":"w1","pane_id":"t-stashed"}"#;
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_pane_remover(Box::new(FakeRemover {
            calls: calls.clone(),
            result: Ok(()),
        }));
        // before auth → refused, remover not called.
        assert!(
            matches!(ch.handle(msg, 1500), Some(OutboundMsg::RemovePaneError { code, .. }) if code == "unauthenticated")
        );
        assert!(calls.lock().unwrap().is_empty());
        // after auth → EXISTENCE MODEL: remove-from-shelf is a DESTRUCTIVE existence deletion the remote IS
        // allowed to command (like close_window/delete_project) — routed to the desktop remover, unlike
        // stash/revive which stay remote-only. (Refusing it made remote Remove-from-shelf a no-op.)
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(msg, 1500);
        assert!(
            matches!(r, Some(OutboundMsg::RemovePaneOk { ref request_id }) if request_id == "rp1"),
            "expected RemovePaneOk, got {r:?}"
        );
        let calls = calls.lock().unwrap();
        assert_eq!(
            calls.len(),
            1,
            "the desktop remover must be called exactly once"
        );
        assert_eq!(calls[0].window_id, "w1");
        assert_eq!(calls[0].pane_id, "t-stashed");
    }

    #[test]
    fn remove_pane_maps_remover_errors_and_missing_remover_to_error_codes() {
        let (sk, vk) = keys();
        // No remover wired → not_implemented (never a silent OK).
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"remove_pane","request_id":"rp2","window_id":"w","pane_id":"p"}"#,
            1500,
        );
        assert!(
            matches!(r, Some(OutboundMsg::RemovePaneError { code, .. }) if code == "not_implemented")
        );
        // Remover error → its wire code (pane_not_found), not a success.
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_pane_remover(Box::new(FakeRemover {
            calls: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            result: Err(RevivePaneError::PaneNotFound),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"remove_pane","request_id":"rp3","window_id":"w","pane_id":"p"}"#,
            1500,
        );
        assert!(
            matches!(r, Some(OutboundMsg::RemovePaneError { code, .. }) if code == "pane_not_found")
        );

        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_pane_remover(Box::new(FakeRemover {
            calls: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            result: Err(RevivePaneError::GloballyLastVisible),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert!(matches!(
            ch.handle(
                r#"{"type":"remove_pane","request_id":"rp-last","window_id":"w","pane_id":"p"}"#,
                1500,
            ),
            Some(OutboundMsg::RemovePaneError { request_id, code, message })
                if request_id == "rp-last"
                    && code == "last_visible_window"
                    && message.contains("globally last visible")
        ));
    }

    struct FakeRenamer {
        calls: std::sync::Arc<std::sync::Mutex<Vec<RenameRequest>>>,
        result: Result<(), RenameError>,
    }
    impl Renamer for FakeRenamer {
        fn rename(&mut self, request: RenameRequest) -> Result<(), RenameError> {
            self.calls.lock().unwrap().push(request);
            self.result.clone()
        }
    }

    #[test]
    fn rename_requires_auth_then_calls_the_renamer_for_pane_and_window() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_renamer(Box::new(FakeRenamer {
            calls: calls.clone(),
            result: Ok(()),
        }));
        let pane_msg =
            r#"{"type":"rename","request_id":"rn1","window_id":"w1","pane_id":"t1","name":"Logs"}"#;
        // before auth → refused, renamer not called.
        assert!(
            matches!(ch.handle(pane_msg, 1500), Some(OutboundMsg::RenameError { code, .. }) if code == "unauthenticated")
        );
        assert!(calls.lock().unwrap().is_empty());
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        // pane rename → pane_id is Some.
        assert_eq!(
            ch.handle(pane_msg, 1500),
            Some(OutboundMsg::RenameOk {
                request_id: "rn1".into()
            })
        );
        // window rename → pane_id omitted → None.
        let win_msg = r#"{"type":"rename","request_id":"rn2","window_id":"w1","name":"Backend"}"#;
        assert_eq!(
            ch.handle(win_msg, 1500),
            Some(OutboundMsg::RenameOk {
                request_id: "rn2".into()
            })
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].pane_id.as_deref(), Some("t1"));
        assert_eq!(calls[0].name, "Logs");
        assert_eq!(calls[1].pane_id, None);
        assert_eq!(calls[1].name, "Backend");
    }

    #[test]
    fn rename_rejects_empty_name_before_calling_the_renamer() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_renamer(Box::new(FakeRenamer {
            calls: calls.clone(),
            result: Ok(()),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"rename","request_id":"rn3","window_id":"w","name":"   "}"#,
            1500,
        );
        assert!(matches!(r, Some(OutboundMsg::RenameError { code, .. }) if code == "invalid_name"));
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn rename_without_injected_renamer_is_not_implemented() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"rename","request_id":"rn4","window_id":"w","name":"X"}"#,
            1500,
        );
        assert!(
            matches!(r, Some(OutboundMsg::RenameError { code, .. }) if code == "not_implemented")
        );
    }

    struct FakeFocuser {
        calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        result: Result<(), FocusWindowError>,
    }

    impl WindowFocuser for FakeFocuser {
        fn focus_window(
            &mut self,
            window_id: String,
            _now_ms: u64,
        ) -> Result<(), FocusWindowError> {
            self.calls.lock().unwrap().push(window_id);
            self.result.clone()
        }
    }

    #[test]
    fn focus_window_requires_auth_then_calls_the_live_focuser() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let msg = r#"{"type":"focus_window","request_id":"fw1","window_id":"w1"}"#;
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_window_focuser(Box::new(FakeFocuser {
            calls: calls.clone(),
            result: Ok(()),
        }));
        assert!(
            matches!(ch.handle(msg, 1500), Some(OutboundMsg::FocusWindowError { code, .. }) if code == "unauthenticated")
        );
        assert!(calls.lock().unwrap().is_empty());

        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(msg, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::FocusWindowOk {
                request_id: "fw1".into()
            })
        );
        assert_eq!(calls.lock().unwrap().as_slice(), ["w1"]);
    }

    #[test]
    fn focus_window_without_injected_focuser_is_not_implemented() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"focus_window","request_id":"fw2","window_id":"w"}"#,
            1500,
        );
        assert!(
            matches!(r, Some(OutboundMsg::FocusWindowError { code, .. }) if code == "not_implemented")
        );
    }

    struct FakeCloser {
        calls: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        result: Result<(), CloseWindowError>,
    }
    impl WindowCloser for FakeCloser {
        fn close_window(
            &mut self,
            window_id: String,
            _now_ms: u64,
        ) -> Result<(), CloseWindowError> {
            self.calls.lock().unwrap().push(window_id);
            self.result.clone()
        }
    }

    #[test]
    fn close_window_requires_auth_then_calls_the_desktop_closer() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let msg = r#"{"type":"close_window","request_id":"cw1","window_id":"w1"}"#;
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_window_closer(Box::new(FakeCloser {
            calls: calls.clone(),
            result: Ok(()),
        }));
        // before auth → refused, closer not called.
        assert!(
            matches!(ch.handle(msg, 1500), Some(OutboundMsg::CloseWindowError { code, .. }) if code == "unauthenticated")
        );
        assert!(calls.lock().unwrap().is_empty());
        // after auth → calls the desktop closer and acks.
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(msg, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::CloseWindowOk {
                request_id: "cw1".into()
            })
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0], "w1");
    }

    #[test]
    fn close_window_surfaces_the_global_last_visible_refusal() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_window_closer(Box::new(FakeCloser {
            calls: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            result: Err(CloseWindowError::GloballyLastVisible),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        assert!(matches!(
            ch.handle(
                r#"{"type":"close_window","request_id":"cw-last","window_id":"w-last"}"#,
                1500,
            ),
            Some(OutboundMsg::CloseWindowError { request_id, code, message })
                if request_id == "cw-last"
                    && code == "last_visible_window"
                    && message.contains("globally last visible")
        ));
    }

    #[test]
    fn close_window_without_injected_closer_is_not_implemented() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"close_window","request_id":"cw2","window_id":"w"}"#,
            1500,
        );
        assert!(
            matches!(r, Some(OutboundMsg::CloseWindowError { code, .. }) if code == "not_implemented")
        );
    }

    struct FakeOpener {
        calls: std::sync::Arc<std::sync::Mutex<Vec<NewWindowRequest>>>,
        result: Result<NewWindowCreated, NewWindowError>,
    }
    impl WindowOpener for FakeOpener {
        fn new_window(
            &mut self,
            request: NewWindowRequest,
        ) -> Result<NewWindowCreated, NewWindowError> {
            self.calls.lock().unwrap().push(request);
            self.result.clone()
        }
    }

    #[test]
    fn new_window_requires_auth_then_calls_the_desktop_opener() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let msg = r#"{"type":"new_window","request_id":"n1","project_id":"p1","name":"experiment","agent":"codex"}"#;
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_window_opener(Box::new(FakeOpener {
            calls: calls.clone(),
            result: Ok(NewWindowCreated {
                window_id: "w-new".into(),
                session_id: "s-new".into(),
            }),
        }));
        // before auth → refused (privileged), opener not called.
        assert!(matches!(
            ch.handle(msg, 1500),
            Some(OutboundMsg::NewWindowError { code, .. }) if code == "unauthenticated"
        ));
        assert!(calls.lock().unwrap().is_empty());
        // after auth → calls the injected desktop opener and returns its ids.
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(msg, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::NewWindowOk {
                request_id: "n1".into(),
                window_id: "w-new".into(),
                session_id: "s-new".into(),
            })
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].project_id, "p1");
        assert_eq!(calls[0].name, "experiment");
        assert_eq!(calls[0].agent.as_deref(), Some("codex"));
    }

    #[test]
    fn new_window_keeps_terminal_agent_and_threads_launch_flags() {
        // Tier-1: "terminal" must survive the new_window dispatch (plain sanitize_agent dropped it, turning
        // the user's Terminal pick into "project default agent"), and launch_flags (resume/model) must reach
        // the opener verbatim so it can build the launch like split_pane does.
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_window_opener(Box::new(FakeOpener {
            calls: calls.clone(),
            result: Ok(NewWindowCreated {
                window_id: "w-new".into(),
                session_id: "s-new".into(),
            }),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        ch.handle(
            r#"{"type":"new_window","request_id":"n-t","project_id":"p1","name":"term","agent":"terminal"}"#,
            1500,
        );
        ch.handle(
            r#"{"type":"new_window","request_id":"n-f","project_id":"p1","name":"resumed","agent":"codex","launch_flags":{"resumeMode":"resume","resumeSessionId":"cdx-1","model":"gpt-5.2-codex"}}"#,
            1500,
        );
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 2);
        assert_eq!(calls[0].agent.as_deref(), Some("terminal"));
        assert_eq!(
            calls[1].launch_flags,
            Some(serde_json::json!({
                "resumeMode": "resume",
                "resumeSessionId": "cdx-1",
                "model": "gpt-5.2-codex",
            }))
        );
    }

    #[test]
    fn new_window_without_injected_opener_is_not_implemented() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"new_window","request_id":"n2","project_id":"p","name":"x"}"#,
            1500,
        );
        assert!(
            matches!(r, Some(OutboundMsg::NewWindowError { code, .. }) if code == "not_implemented")
        );
    }

    struct FakeProjectEditor {
        creates: std::sync::Arc<std::sync::Mutex<Vec<ProjectEditRequest>>>,
        updates: std::sync::Arc<std::sync::Mutex<Vec<ProjectEditRequest>>>,
        deletes: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
        result: Result<ProjectEdited, ProjectEditError>,
    }
    impl ProjectEditor for FakeProjectEditor {
        fn create_project(
            &mut self,
            request: ProjectEditRequest,
        ) -> Result<ProjectEdited, ProjectEditError> {
            self.creates.lock().unwrap().push(request);
            self.result.clone()
        }
        fn update_project(
            &mut self,
            request: ProjectEditRequest,
        ) -> Result<ProjectEdited, ProjectEditError> {
            self.updates.lock().unwrap().push(request);
            self.result.clone()
        }
        fn delete_project(
            &mut self,
            project_id: String,
            _now_ms: u64,
        ) -> Result<ProjectEdited, ProjectEditError> {
            self.deletes.lock().unwrap().push(project_id);
            self.result.clone()
        }
    }

    #[test]
    fn project_delete_daemon_failure_is_a_visible_non_sensitive_error() {
        assert_eq!(
            project_edit_reply("delete-1".into(), Err(ProjectEditError::DaemonUnavailable)),
            Some(OutboundMsg::ProjectEditError {
                request_id: "delete-1".into(),
                code: "daemon_unavailable".into(),
                message: "terminal service unavailable; project was not changed".into(),
            })
        );
    }

    #[test]
    fn project_delete_global_last_refusal_is_a_visible_non_sensitive_error() {
        assert_eq!(
            project_edit_reply(
                "delete-last".into(),
                Err(ProjectEditError::GloballyLastVisible),
            ),
            Some(OutboundMsg::ProjectEditError {
                request_id: "delete-last".into(),
                code: "last_visible_window".into(),
                message: "keep one window open globally".into(),
            })
        );
    }

    #[test]
    fn project_create_requires_auth_then_calls_the_editor_with_sanitized_fields() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let msg = r##"{"type":"project_create","request_id":"p1","name":"Capacity","root":"/Users/test/cap","icon":"◆","accent_color":"#fbbf24","agent":"codex","resume_mode":"resume","resume_session_id":" sess-42 ","model":"claude-opus-4-8","dangerous":true,"custom_command":"claude --foo","directories":[{"name":"api","path":"/Users/test/api"},{"name":"","path":""}]}"##;
        let creates = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_project_editor(Box::new(FakeProjectEditor {
            creates: creates.clone(),
            updates: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            deletes: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            result: Ok(ProjectEdited {
                project_id: "proj-new".into(),
                session_id: Some("proj-new-pane-1".into()),
            }),
        }));
        // before auth → refused, editor not called.
        assert!(
            matches!(ch.handle(msg, 1500), Some(OutboundMsg::ProjectEditError { code, .. }) if code == "unauthenticated")
        );
        assert!(creates.lock().unwrap().is_empty());
        // after auth → calls create with sanitized fields, returns the id.
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(msg, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::ProjectEditOk {
                request_id: "p1".into(),
                project_id: "proj-new".into(),
                session_id: Some("proj-new-pane-1".into())
            })
        );
        let c = creates.lock().unwrap();
        assert_eq!(c.len(), 1);
        assert_eq!(c[0].project_id, None); // create, not update
        assert_eq!(c[0].name.as_deref(), Some("Capacity"));
        assert_eq!(c[0].accent_color.as_deref(), Some("#fbbf24")); // valid hex kept
        assert_eq!(c[0].agent.as_deref(), Some("codex"));
        assert_eq!(c[0].resume_mode.as_deref(), Some("resume")); // valid resume policy threaded through
        assert_eq!(c[0].resume_session_id.as_deref(), Some("sess-42")); // resume TARGET threaded (id-sanitized)
        assert_eq!(c[0].model.as_deref(), Some("claude-opus-4-8")); // model threaded through (sanitized)
        assert_eq!(c[0].dangerous, Some(true)); // dangerous-skip-permissions bool threaded through
        assert_eq!(c[0].custom_command.as_deref(), Some("claude --foo")); // custom command (project config) threaded
                                                                          // directories: the empty-path entry is dropped; the valid one is kept (sanitized name/path).
        let dirs = c[0].directories.as_ref().unwrap();
        assert_eq!(dirs.len(), 1);
        assert_eq!(dirs[0].name, "api");
        assert_eq!(dirs[0].path, "/Users/test/api");
    }

    #[test]
    fn project_create_preserves_a_valid_long_non_ascii_amp_thread_target() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let creates = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_project_editor(Box::new(FakeProjectEditor {
            creates: creates.clone(),
            updates: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            deletes: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            result: Ok(ProjectEdited {
                project_id: "proj-amp".into(),
                session_id: None,
            }),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        let target = "é".repeat(200); // 200 Unicode scalars, 400 UTF-8 bytes: valid and must not be truncated.
        let msg = serde_json::json!({
            "type": "project_create",
            "request_id": "p-amp",
            "name": "Amp",
            "root": "/work/amp",
            "agent": "amp",
            "resume_mode": "resume",
            "resume_session_id": target.clone(),
        })
        .to_string();
        assert!(matches!(
            ch.handle(&msg, 1500),
            Some(OutboundMsg::ProjectEditOk { request_id, .. }) if request_id == "p-amp"
        ));
        let calls = creates.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].agent.as_deref(), Some("amp"));
        assert_eq!(calls[0].resume_session_id.as_deref(), Some(target.as_str()));
    }

    #[test]
    fn project_create_maps_legacy_resume_mode_new_to_desktop_none() {
        // Item 4 (dialog parity): the browser vocabulary is now the desktop's continue|resume|none. Old
        // browsers sent "new" for the fresh policy — it must arrive at the editor as "none", and junk must
        // still be dropped by the closed allowlist.
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let creates = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_project_editor(Box::new(FakeProjectEditor {
            creates: creates.clone(),
            updates: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            deletes: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            result: Ok(ProjectEdited {
                project_id: "proj-old".into(),
                session_id: None,
            }),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        ch.handle(r#"{"type":"project_create","request_id":"p8","name":"Old","root":"/tmp/old","resume_mode":"new"}"#, 1500);
        ch.handle(r#"{"type":"project_create","request_id":"p9","name":"Junk","root":"/tmp/junk","resume_mode":"; rm -rf /"}"#, 1500);
        let c = creates.lock().unwrap();
        assert_eq!(c.len(), 2);
        assert_eq!(c[0].resume_mode.as_deref(), Some("none")); // legacy "new" → desktop "none"
        assert_eq!(c[1].resume_mode, None); // non-vocabulary value dropped
    }

    #[test]
    fn project_update_routes_to_update_and_drops_a_bad_accent() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let updates = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_project_editor(Box::new(FakeProjectEditor {
            creates: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            updates: updates.clone(),
            deletes: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            result: Ok(ProjectEdited {
                project_id: "proj-x".into(),
                session_id: None,
            }),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(r#"{"type":"project_update","request_id":"p2","project_id":"proj-x","name":"Renamed","accent_color":"not-a-color"}"#, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::ProjectEditOk {
                request_id: "p2".into(),
                project_id: "proj-x".into(),
                session_id: None
            })
        );
        let u = updates.lock().unwrap();
        assert_eq!(u.len(), 1);
        assert_eq!(u[0].project_id.as_deref(), Some("proj-x"));
        assert_eq!(u[0].name.as_deref(), Some("Renamed"));
        assert_eq!(u[0].accent_color, None); // invalid accent dropped (desktop keeps its own)
    }

    #[test]
    fn project_create_reply_wire_carries_seed_session_id_and_update_omits_it() {
        // Item C (auto-attach after project create): the project_create reply surfaces the seeded first
        // pane's session id ON THE WIRE so the browser can attach it immediately; project_update seeds
        // nothing, so its reply must omit the key entirely (skip_serializing_if — old browsers see no
        // new field, backward compatible).
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_project_editor(Box::new(FakeProjectEditor {
            creates: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            updates: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            deletes: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            result: Ok(ProjectEdited {
                project_id: "proj-seeded".into(),
                session_id: Some("proj-seeded-pane-1".into()),
            }),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch
            .handle(
                r#"{"type":"project_create","request_id":"pc","name":"Seeded","root":"/tmp/seeded"}"#,
                1500,
            )
            .unwrap();
        let wire = serde_json::to_string(&r).unwrap();
        assert!(
            wire.contains(r#""session_id":"proj-seeded-pane-1""#),
            "create reply must carry the seeded session id on the wire, got {wire}"
        );

        // Update path: the backend returns session_id: None (no seeding) → the key is absent on the wire.
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_project_editor(Box::new(FakeProjectEditor {
            creates: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            updates: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            deletes: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            result: Ok(ProjectEdited {
                project_id: "proj-seeded".into(),
                session_id: None,
            }),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch
            .handle(
                r#"{"type":"project_update","request_id":"pu","project_id":"proj-seeded","name":"Renamed"}"#,
                1500,
            )
            .unwrap();
        let wire = serde_json::to_string(&r).unwrap();
        assert!(
            !wire.contains("session_id"),
            "update reply must omit the session_id key, got {wire}"
        );
    }

    #[test]
    fn project_create_without_editor_is_not_implemented() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"project_create","request_id":"p3","name":"X","root":"/r"}"#,
            1500,
        );
        assert!(
            matches!(r, Some(OutboundMsg::ProjectEditError { code, .. }) if code == "not_implemented")
        );
    }

    #[test]
    fn delete_project_requires_auth_then_calls_the_editor() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let msg = r#"{"type":"delete_project","request_id":"d1","project_id":"proj-x"}"#;
        let deletes = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_project_editor(Box::new(FakeProjectEditor {
            creates: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            updates: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            deletes: deletes.clone(),
            result: Ok(ProjectEdited {
                project_id: "proj-x".into(),
                session_id: None,
            }),
        }));
        // before auth → refused, editor not called.
        assert!(
            matches!(ch.handle(msg, 1500), Some(OutboundMsg::ProjectEditError { code, .. }) if code == "unauthenticated")
        );
        assert!(deletes.lock().unwrap().is_empty());
        // after auth → calls delete and acks with the project id.
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(msg, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::ProjectEditOk {
                request_id: "d1".into(),
                project_id: "proj-x".into(),
                session_id: None
            })
        );
        assert_eq!(deletes.lock().unwrap().as_slice(), &["proj-x".to_string()]);
    }

    #[test]
    fn delete_project_without_editor_is_not_implemented() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"delete_project","request_id":"d2","project_id":"p"}"#,
            1500,
        );
        assert!(
            matches!(r, Some(OutboundMsg::ProjectEditError { code, .. }) if code == "not_implemented")
        );
    }

    #[test]
    fn split_pane_rejects_bad_direction_before_calling_the_splitter() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_pane_splitter(Box::new(FakeSplitter {
            calls: calls.clone(),
            result: Ok(SplitPaneCreated {
                session_id: "s-new".into(),
                tab_id: "pane-new".into(),
            }),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"split_pane","request_id":"s2","window_id":"w1","from_pane_id":"t1","dir":"left"}"#,
            1500,
        );
        assert_eq!(
            r,
            Some(OutboundMsg::SplitPaneError {
                request_id: "s2".into(),
                code: "invalid_direction".into(),
                message: "split direction must be right or down".into(),
            })
        );
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn split_pane_threads_pane_name_and_model_launch_flags_to_the_splitter() {
        // Tier-1: the split dialog's pane name + launch_flags (with the model) must survive dispatch into
        // the SplitPaneRequest — pane_name sanitized (trimmed), launch_flags passed through verbatim so the
        // splitter can build the resume/model launch.
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_pane_splitter(Box::new(FakeSplitter {
            calls: calls.clone(),
            result: Ok(SplitPaneCreated {
                session_id: "s-new".into(),
                tab_id: "pane-new".into(),
            }),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"split_pane","request_id":"s9","window_id":"w1","from_pane_id":"t1","dir":"right","agent":"codex","pane_name":"  Build pane  ","launch_flags":{"resumeMode":"resume","resumeSessionId":"cdx-1","model":"gpt-5.2-codex"}}"#,
            1500,
        );
        assert!(matches!(r, Some(OutboundMsg::SplitPaneOk { .. })));
        let calls = calls.lock().unwrap();
        assert_eq!(calls.len(), 1);
        assert_eq!(calls[0].agent.as_deref(), Some("codex"));
        assert_eq!(calls[0].pane_name.as_deref(), Some("Build pane"));
        assert_eq!(
            calls[0].launch_flags,
            Some(serde_json::json!({
                "resumeMode": "resume",
                "resumeSessionId": "cdx-1",
                "model": "gpt-5.2-codex",
            }))
        );
        // and the model reader extracts the validated name from those flags
        assert_eq!(
            model_from_launch_flags(&calls[0].launch_flags).as_deref(),
            Some("gpt-5.2-codex")
        );
    }

    #[test]
    fn model_from_launch_flags_is_a_bounded_single_argv_value() {
        let flags = |v: serde_json::Value| Some(v);
        // valid names pass, trimmed
        assert_eq!(
            model_from_launch_flags(&flags(serde_json::json!({"model": " claude-opus-4-8 "})))
                .as_deref(),
            Some("claude-opus-4-8")
        );
        assert_eq!(
            model_from_launch_flags(&flags(serde_json::json!({"model": "provider:model_1.5"})))
                .as_deref(),
            Some("provider:model_1.5")
        );
        assert_eq!(
            model_from_launch_flags(&flags(serde_json::json!({
                "model": " Gemini 3.5 Flash (High) / preview "
            })))
            .as_deref(),
            Some("Gemini 3.5 Flash (High) / preview")
        );
        // absent / empty / non-string / no flags → None
        assert_eq!(model_from_launch_flags(&None), None);
        assert_eq!(model_from_launch_flags(&flags(serde_json::json!({}))), None);
        assert_eq!(
            model_from_launch_flags(&flags(serde_json::json!({"model": "  "}))),
            None
        );
        assert_eq!(
            model_from_launch_flags(&flags(serde_json::json!({"model": 7}))),
            None
        );
        // Shell punctuation is safe because this remains one argv member and the shell adapter quotes it.
        assert_eq!(
            model_from_launch_flags(&flags(serde_json::json!({"model": "opus; rm -rf /"}))),
            Some("opus; rm -rf /".into())
        );
        // Controls / oversized values are rejected wholesale (never partially cleaned into an argv).
        assert_eq!(
            model_from_launch_flags(&flags(serde_json::json!({"model": "bad\nmodel"}))),
            None
        );
        assert_eq!(
            model_from_launch_flags(&flags(serde_json::json!({"model": "x".repeat(97)}))),
            None
        );
    }

    #[test]
    fn amp_exact_thread_targets_are_preserved_not_cleaned_or_truncated() {
        let descriptor = |target: &str| {
            resume_descriptor_from_launch_flags(
                Some("amp".into()),
                Some(serde_json::json!({
                    "resumeMode": "resume",
                    "resumeSessionId": target,
                })),
            )
        };

        for target in ["x".repeat(129), "y".repeat(256), "é".repeat(256)] {
            let parsed = descriptor(&target).expect("AMP descriptor");
            assert_eq!(parsed.session_id.as_deref(), Some(target.as_str()));
            assert_eq!(
                crate::resume_launch::build_resume_launch(&parsed)
                    .expect("valid AMP target")
                    .args,
                vec!["threads", "continue", target.as_str()],
            );
        }

        for target in ["z".repeat(257), "bad\nthread".into(), "--help".into()] {
            let parsed = descriptor(&target).expect("AMP descriptor remains typed");
            assert_eq!(parsed.session_id, None, "target={target:?}");
            assert_eq!(crate::resume_launch::build_resume_launch(&parsed), None);
        }
    }

    #[test]
    fn devin_and_factory_exact_targets_are_preserved_or_rejected_not_cleaned() {
        for agent in ["devin", "factory"] {
            let descriptor = |target: &str| {
                resume_descriptor_from_launch_flags(
                    Some(agent.into()),
                    Some(serde_json::json!({
                        "resumeMode": "resume",
                        "resumeSessionId": target,
                    })),
                )
                .expect("typed descriptor")
            };
            for target in ["x".repeat(129), "é".repeat(256)] {
                let parsed = descriptor(&target);
                assert_eq!(parsed.session_id.as_deref(), Some(target.as_str()));
            }
            for target in ["x".repeat(257), "bad\nid".into(), "--latest".into()] {
                assert_eq!(
                    descriptor(&target).session_id,
                    None,
                    "agent={agent} id={target:?}"
                );
            }
        }
    }

    #[test]
    fn dangerous_launch_flag_is_boolean_only_and_supports_wire_aliases() {
        for key in [
            "dangerouslySkipPermissions",
            "dangerous_skip_permissions",
            "dangerous",
        ] {
            let mut object = serde_json::Map::new();
            object.insert(key.to_string(), serde_json::Value::Bool(true));
            assert!(dangerous_from_launch_flags(&Some(
                serde_json::Value::Object(object)
            )));
        }
        assert!(!dangerous_from_launch_flags(&None));
        assert!(!dangerous_from_launch_flags(&Some(serde_json::json!({
            "dangerouslySkipPermissions": "true"
        }))));
    }

    #[test]
    fn agent_allowlists_include_new_providers_and_keep_legacy_gemini() {
        for agent in [
            "claude",
            "codex",
            "copilot",
            "antigravity",
            "kimi",
            "kiro",
            "cursor",
            "amp",
            "devin",
            "factory",
            "gemini",
            "opencode",
        ] {
            assert_eq!(sanitize_agent(agent.into()).as_deref(), Some(agent));
        }
        assert_eq!(sanitize_agent("agy".into()), None);
        assert_eq!(sanitize_agent("bash".into()), None);
        assert_eq!(
            sanitize_split_agent("terminal".into()).as_deref(),
            Some("terminal")
        );
        assert_eq!(
            validate_optional_agent(None, sanitize_agent),
            Ok(None),
            "an absent provider keeps the intentional legacy/default path"
        );
        assert_eq!(
            validate_optional_agent(Some("future-provider".into()), sanitize_agent),
            Err(AgentValidationError::UnsupportedProvider),
            "an explicit unknown provider must not collapse to absence"
        );
    }

    #[test]
    fn create_session_rejects_unknown_provider_without_starting_a_shell() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches: launches.clone(),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        assert_eq!(
            ch.handle(
                r#"{"type":"create_session","request_id":"unknown-create","agent":"future-provider"}"#,
                1600,
            ),
            Some(OutboundMsg::SessionCreateError {
                request_id: "unknown-create".into(),
                code: "unsupported_provider".into(),
                message: "unsupported agent provider".into(),
            })
        );
        assert!(started.lock().unwrap().is_empty());
        assert!(launches.lock().unwrap().is_empty());
    }

    #[test]
    fn create_session_keeps_explicit_terminal_as_the_known_shell_choice() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let started = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let launches = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_session_creator(Box::new(FakeCreator {
            started: started.clone(),
            launches: launches.clone(),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        assert!(matches!(
            ch.handle(
                r#"{"type":"create_session","request_id":"terminal-create","agent":"terminal"}"#,
                1600,
            ),
            Some(OutboundMsg::SessionCreated { request_id, .. }) if request_id == "terminal-create"
        ));
        assert_eq!(started.lock().unwrap().len(), 1);
        assert_eq!(launches.lock().unwrap().as_slice(), &[None]);
    }

    #[test]
    fn pane_requests_reject_unknown_provider_without_calling_the_splitter() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_pane_splitter(Box::new(FakeSplitter {
            calls: calls.clone(),
            result: Ok(SplitPaneCreated {
                session_id: "must-not-exist".into(),
                tab_id: "must-not-exist".into(),
            }),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        for (request_id, message) in [
            (
                "unknown-split",
                r#"{"type":"split_pane","request_id":"unknown-split","window_id":"w1","from_pane_id":"p1","dir":"right","agent":"future-provider"}"#,
            ),
            (
                "unknown-pane",
                r#"{"type":"new_pane","request_id":"unknown-pane","window_id":"w1","from_pane_id":"p1","agent":"future-provider"}"#,
            ),
        ] {
            assert_eq!(
                ch.handle(message, 1600),
                Some(OutboundMsg::SplitPaneError {
                    request_id: request_id.into(),
                    code: "unsupported_provider".into(),
                    message: "unsupported agent provider".into(),
                })
            );
        }
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn new_window_rejects_unknown_provider_without_calling_the_opener() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let calls = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_window_opener(Box::new(FakeOpener {
            calls: calls.clone(),
            result: Ok(NewWindowCreated {
                window_id: "must-not-exist".into(),
                session_id: "must-not-exist".into(),
            }),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        assert_eq!(
            ch.handle(
                r#"{"type":"new_window","request_id":"unknown-window","project_id":"p1","name":"Window","agent":"future-provider"}"#,
                1600,
            ),
            Some(OutboundMsg::NewWindowError {
                request_id: "unknown-window".into(),
                code: "unsupported_provider".into(),
                message: "unsupported agent provider".into(),
            })
        );
        assert!(calls.lock().unwrap().is_empty());
    }

    #[test]
    fn project_requests_reject_unknown_provider_without_calling_the_editor() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let creates = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        let updates = std::sync::Arc::new(std::sync::Mutex::new(vec![]));
        ch.set_project_editor(Box::new(FakeProjectEditor {
            creates: creates.clone(),
            updates: updates.clone(),
            deletes: std::sync::Arc::new(std::sync::Mutex::new(vec![])),
            result: Ok(ProjectEdited {
                project_id: "must-not-exist".into(),
                session_id: Some("must-not-exist".into()),
            }),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);

        for (request_id, message) in [
            (
                "unknown-project-create",
                r#"{"type":"project_create","request_id":"unknown-project-create","name":"Project","root":"/tmp/project","agent":"future-provider"}"#,
            ),
            (
                "unknown-project-update",
                r#"{"type":"project_update","request_id":"unknown-project-update","project_id":"p1","agent":"future-provider"}"#,
            ),
        ] {
            assert_eq!(
                ch.handle(message, 1600),
                Some(OutboundMsg::ProjectEditError {
                    request_id: request_id.into(),
                    code: "unsupported_provider".into(),
                    message: "unsupported agent provider".into(),
                })
            );
        }
        assert!(creates.lock().unwrap().is_empty());
        assert!(updates.lock().unwrap().is_empty());
    }

    #[test]
    fn split_pane_maps_pane_limit_from_the_splitter() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        ch.set_pane_splitter(Box::new(FakeSplitter {
            calls: Default::default(),
            result: Err(SplitPaneCreateError::PaneLimit),
        }));
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        let r = ch.handle(
            r#"{"type":"split_pane","request_id":"s3","window_id":"w1","from_pane_id":"t1","dir":"down"}"#,
            1500,
        );
        assert_eq!(
            r,
            Some(OutboundMsg::SplitPaneError {
                request_id: "s3".into(),
                code: "pane_limit".into(),
                message: "could not split pane".into(),
            })
        );
    }

    #[test]
    fn wrong_device_token_refused() {
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let tok = token(&sk, "dev_OTHER", 1000); // token for a different device
        let a = ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert_eq!(
            a,
            Some(OutboundMsg::AuthRefused {
                reason: "wrong_device".into()
            })
        );
        assert!(!ch.is_authenticated());
    }

    #[test]
    fn revoke_after_auth_blocks_next_privileged_request() {
        let (sk, vk) = keys();
        // revocation flips on after we set the flag
        use std::cell::Cell;
        let revoked = Cell::new(false);
        let check = |_a: &str, _d: &str, _i: u64| revoked.get();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), check);
        let tok = token(&sk, "dev_a", 1000);
        assert!(matches!(
            ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500),
            Some(OutboundMsg::AuthOk { .. })
        ));
        // device gets revoked
        revoked.set(true);
        let r = ch.handle(r#"{"type":"list_request","request_id":"r2"}"#, 1500);
        assert_eq!(
            r,
            Some(OutboundMsg::AuthRefused {
                reason: "missing".into()
            })
        );
        assert!(
            !ch.is_authenticated(),
            "revoke drops the channel to unauthenticated"
        );
    }

    #[test]
    fn terminal_shaped_messages_are_rejected() {
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        for bad in [
            r#"{"type":"hello","protocol_version":1,"device_id":"d","role":"c","stdout":"leak"}"#,
            r#"{"type":"data","bytes":"AAAA"}"#,
            r#"{"type":"ping","nonce":"n","keystroke":"a"}"#,
            r#"{"type":"write","pty":"x"}"#,
        ] {
            let r = ch.handle(bad, 1);
            match r {
                Some(OutboundMsg::Error { code, .. }) => {
                    assert!(
                        code == "forbidden_field" || code == "bad_message",
                        "got {code}"
                    );
                }
                other => panic!("expected Error, got {other:?}"),
            }
        }
    }

    #[test]
    fn unknown_message_type_is_rejected() {
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let r = ch.handle(r#"{"type":"start_terminal","id":"x"}"#, 1);
        assert!(matches!(r, Some(OutboundMsg::Error { .. })));
    }

    #[test]
    fn oversized_message_is_rejected() {
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let big = format!(r#"{{"type":"ping","nonce":"{}"}}"#, "x".repeat(9000));
        assert!(
            matches!(ch.handle(&big, 1), Some(OutboundMsg::Error { code, .. }) if code == "too_large")
        );
    }

    #[derive(Clone)]
    struct CountingProtectedOperations {
        calls: std::sync::Arc<std::sync::atomic::AtomicUsize>,
    }

    impl CountingProtectedOperations {
        fn touched(&self) {
            self.calls.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
        }
    }

    impl crate::session_creator::SessionCreator for CountingProtectedOperations {
        fn known_sessions(&self) -> Vec<String> {
            Vec::new()
        }

        fn start_session(
            &mut self,
            _session_id: &str,
            _home: &str,
        ) -> Result<(), crate::session_creator::CreateSessionError> {
            self.touched();
            Ok(())
        }

        fn home(&self) -> String {
            "/Users/test/home".into()
        }
    }

    impl PaneSplitter for CountingProtectedOperations {
        fn split_pane(
            &mut self,
            _request: SplitPaneRequest,
        ) -> Result<SplitPaneCreated, SplitPaneCreateError> {
            self.touched();
            Ok(SplitPaneCreated {
                session_id: "split-session".into(),
                tab_id: "split-pane".into(),
            })
        }

        fn new_pane(
            &mut self,
            request: SplitPaneRequest,
        ) -> Result<SplitPaneCreated, SplitPaneCreateError> {
            self.split_pane(request)
        }
    }

    impl PaneReviver for CountingProtectedOperations {
        fn revive_pane(
            &mut self,
            _request: RevivePaneRequest,
        ) -> Result<RevivePaneCreated, RevivePaneError> {
            self.touched();
            Ok(RevivePaneCreated {
                session_id: "revived-session".into(),
            })
        }
    }

    impl PaneSessionStarter for CountingProtectedOperations {
        fn start_pane_session(
            &mut self,
            _request: RevivePaneRequest,
        ) -> Result<RevivePaneCreated, RevivePaneError> {
            self.touched();
            Ok(RevivePaneCreated {
                session_id: "started-session".into(),
            })
        }
    }

    impl WindowOpener for CountingProtectedOperations {
        fn new_window(
            &mut self,
            _request: NewWindowRequest,
        ) -> Result<NewWindowCreated, NewWindowError> {
            self.touched();
            Ok(NewWindowCreated {
                window_id: "new-window".into(),
                session_id: "new-session".into(),
            })
        }
    }

    impl SessionPreviewer for CountingProtectedOperations {
        fn preview(&mut self, _request: SessionPreviewRequest) -> Vec<PreviewLine> {
            self.touched();
            Vec::new()
        }
    }

    impl SessionManager for CountingProtectedOperations {
        fn manage(&mut self, _request: SessionManageRequest) -> Result<(), SessionManageError> {
            self.touched();
            Ok(())
        }
    }

    impl ProjectEditor for CountingProtectedOperations {
        fn create_project(
            &mut self,
            _request: ProjectEditRequest,
        ) -> Result<ProjectEdited, ProjectEditError> {
            self.touched();
            Ok(ProjectEdited {
                project_id: "project".into(),
                session_id: Some("project-session".into()),
            })
        }

        fn update_project(
            &mut self,
            _request: ProjectEditRequest,
        ) -> Result<ProjectEdited, ProjectEditError> {
            self.touched();
            Ok(ProjectEdited {
                project_id: "project".into(),
                session_id: None,
            })
        }

        fn delete_project(
            &mut self,
            _project_id: String,
            _now_ms: u64,
        ) -> Result<ProjectEdited, ProjectEditError> {
            unreachable!("not part of the protected-path operation matrix")
        }
    }

    impl AgentSessionLister for CountingProtectedOperations {
        fn list(
            &mut self,
            _agent: &str,
            _cwd: Option<String>,
            _include_hidden: bool,
        ) -> Vec<AgentSessionMeta> {
            self.touched();
            Vec::new()
        }
    }

    impl DirectoryLister for CountingProtectedOperations {
        fn list(&mut self, _path: Option<&str>) -> DirectoryListing {
            self.touched();
            DirectoryListing {
                path: "/".into(),
                parent: None,
                entries: Vec::new(),
            }
        }
    }

    fn install_counting_protected_operations<R: Fn(&str, &str, u64) -> bool>(
        channel: &mut ControlChannel<R>,
    ) -> std::sync::Arc<std::sync::atomic::AtomicUsize> {
        let calls = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let operations = CountingProtectedOperations {
            calls: calls.clone(),
        };
        channel.set_session_creator(Box::new(operations.clone()));
        channel.set_pane_splitter(Box::new(operations.clone()));
        channel.set_pane_reviver(Box::new(operations.clone()));
        channel.set_pane_session_starter(Box::new(operations.clone()));
        channel.set_window_opener(Box::new(operations.clone()));
        channel.set_project_editor(Box::new(operations.clone()));
        channel.set_session_previewer(Box::new(operations.clone()));
        channel.set_session_manager(Box::new(operations.clone()));
        channel.set_agent_session_lister(Box::new(operations.clone()));
        channel.set_directory_lister(Box::new(operations));
        calls
    }

    fn protected_operation_error_code(message: &OutboundMsg) -> Option<&str> {
        match message {
            OutboundMsg::SessionCreateError { code, .. }
            | OutboundMsg::SplitPaneError { code, .. }
            | OutboundMsg::RevivePaneError { code, .. }
            | OutboundMsg::StartPaneSessionError { code, .. }
            | OutboundMsg::NewWindowError { code, .. }
            | OutboundMsg::ProjectEditError { code, .. }
            | OutboundMsg::AgentSessionsError { code, .. }
            | OutboundMsg::DirectoriesError { code, .. }
            | OutboundMsg::AgentSessionPreviewError { code, .. }
            | OutboundMsg::AgentSessionManageError { code, .. } => Some(code),
            _ => None,
        }
    }

    #[test]
    fn required_desktop_access_rejects_every_protected_operation_before_backend_touch() {
        let (sk, vk) = keys();
        let mut channel = ControlChannel::new(vk, "dev_a".into(), NOPE);
        set_access(&mut channel, DesktopAccessStatus::Required, true);
        let calls = install_counting_protected_operations(&mut channel);
        authenticate(&mut channel, &sk, 1_500);
        let protected = "/Users/test/Desktop/private";
        let requests = [
            serde_json::json!({
                "type": "create_session",
                "request_id": "create",
                "cwd": protected,
            }),
            serde_json::json!({
                "type": "split_pane",
                "request_id": "split",
                "window_id": "window",
                "from_pane_id": "pane",
                "dir": "right",
                "cwd": protected,
            }),
            serde_json::json!({
                "type": "new_pane",
                "request_id": "new-pane",
                "window_id": "window",
                "from_pane_id": "pane",
                "cwd": protected,
            }),
            serde_json::json!({
                "type": "revive_pane",
                "request_id": "revive",
                "window_id": "window",
                "pane_id": "pane",
            }),
            serde_json::json!({
                "type": "start_pane_session",
                "request_id": "start",
                "window_id": "window",
                "pane_id": "pane",
            }),
            serde_json::json!({
                "type": "new_window",
                "request_id": "window",
                "project_id": "project",
                "name": "Window",
                "cwd": protected,
            }),
            serde_json::json!({
                "type": "project_create",
                "request_id": "project-create",
                "name": "Project",
                "root": protected,
            }),
            serde_json::json!({
                "type": "project_update",
                "request_id": "project-update",
                "project_id": "project",
                "root": protected,
            }),
            serde_json::json!({
                "type": "list_directories",
                "request_id": "directories",
                "path": protected,
            }),
            serde_json::json!({
                "type": "list_agent_sessions",
                "request_id": "history-list",
                "agent": "claude",
                "cwd": protected,
            }),
            serde_json::json!({
                "type": "preview_agent_session",
                "request_id": "history-preview",
                "agent": "claude",
                "cwd": protected,
                "session_id": "session",
            }),
            serde_json::json!({
                "type": "manage_agent_session",
                "request_id": "history-manage",
                "action": "delete",
                "agent": "claude",
                "cwd": protected,
                "session_id": "session",
            }),
        ];

        for request in requests {
            let reply = channel
                .handle(&request.to_string(), 1_600)
                .expect("protected operation must receive a typed refusal");
            assert_eq!(
                protected_operation_error_code(&reply),
                Some(FULL_DISK_ACCESS_REQUIRED_CODE),
                "{request}"
            );
            let encoded = serde_json::to_string(&reply).unwrap();
            assert!(
                !encoded.contains(protected),
                "browser-facing errors must never echo a raw path"
            );
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::SeqCst),
                0,
                "backend was touched by {request}"
            );
        }
    }

    fn create_session_access_outcome(
        status: DesktopAccessStatus,
        protected: bool,
    ) -> (OutboundMsg, usize, usize) {
        let (sk, vk) = keys();
        let mut channel = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let classifications = set_access(&mut channel, status, protected);
        let calls = install_counting_protected_operations(&mut channel);
        authenticate(&mut channel, &sk, 1_500);
        let reply = channel
            .handle(
                r#"{"type":"create_session","request_id":"create","cwd":"/Users/test/Desktop/private"}"#,
                1_600,
            )
            .unwrap();
        (
            reply,
            calls.load(std::sync::atomic::Ordering::SeqCst),
            classifications.load(std::sync::atomic::Ordering::SeqCst),
        )
    }

    #[test]
    fn granted_linux_and_unprotected_paths_preserve_existing_behavior() {
        for status in [
            DesktopAccessStatus::Granted,
            DesktopAccessStatus::NotApplicable,
        ] {
            let (reply, calls, classifications) = create_session_access_outcome(status, true);
            assert!(matches!(reply, OutboundMsg::SessionCreated { .. }));
            assert_eq!(calls, 1);
            assert_eq!(
                classifications, 0,
                "authorized/non-macOS status bypasses the classifier"
            );
        }

        let (reply, calls, classifications) =
            create_session_access_outcome(DesktopAccessStatus::Required, false);
        assert!(matches!(reply, OutboundMsg::SessionCreated { .. }));
        assert_eq!(calls, 1);
        assert_eq!(classifications, 1);
    }

    #[test]
    fn unknown_or_symlink_classification_fails_closed_before_backend_touch() {
        let (reply, calls, classifications) =
            create_session_access_outcome(DesktopAccessStatus::Unknown, true);
        assert_eq!(
            protected_operation_error_code(&reply),
            Some(FULL_DISK_ACCESS_REQUIRED_CODE)
        );
        assert_eq!(calls, 0);
        assert_eq!(
            classifications, 1,
            "agent honors the shared classifier's symlink/uncertainty verdict"
        );

        let (sk, vk) = keys();
        let mut channel = ControlChannel::new(vk, "dev_a".into(), NOPE);
        set_access(&mut channel, DesktopAccessStatus::Unknown, false);
        let calls = install_counting_protected_operations(&mut channel);
        authenticate(&mut channel, &sk, 1_500);
        let reply = channel
            .handle(
                r#"{"type":"revive_pane","request_id":"revive","window_id":"window","pane_id":"pane"}"#,
                1_600,
            )
            .unwrap();
        assert_eq!(
            protected_operation_error_code(&reply),
            Some(FULL_DISK_ACCESS_REQUIRED_CODE)
        );
        assert_eq!(calls.load(std::sync::atomic::Ordering::SeqCst), 0);
    }

    #[test]
    fn set_winsize_owner_refused_before_auth() {
        // PRIVILEGED — an unauthenticated browser cannot drive who sizes the shared PTY.
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let r = ch.handle(r#"{"type":"set_winsize_owner","selected":true}"#, 1);
        assert_eq!(
            r,
            Some(OutboundMsg::AuthRefused {
                reason: "missing".into()
            })
        );
    }

    #[test]
    fn set_winsize_owner_parses_and_dispatches_against_shared_state() {
        // Wire the SHARED owner in, authenticate, then toggle Remote → effective owner becomes remote (a peer is
        // serving) and the broadcast reflects it. Then toggle Local → immediate local.
        let (sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        let owner = std::sync::Arc::new(std::sync::Mutex::new(
            crate::winsize_owner::WinsizeOwner::new(),
        ));
        // A peer is connected so `remote_selected=true` can win.
        owner.lock().unwrap().set_serving(1, 0);
        ch.set_winsize_owner(owner.clone());
        let tok = token(&sk, "dev_a", 1000);
        ch.handle(&format!(r#"{{"type":"auth","token":"{tok}"}}"#), 1500);
        assert!(ch.is_authenticated());

        let r = ch.handle(r#"{"type":"set_winsize_owner","selected":true}"#, 1600);
        assert_eq!(
            r,
            Some(OutboundMsg::WinsizeOwnerChanged {
                owner: "remote".into()
            })
        );
        // The shared state recorded the toggle as a MANUAL override (Some(true)).
        assert_eq!(owner.lock().unwrap().remote_selected(), Some(true));

        // Selecting Local flips immediately (no grace).
        let r = ch.handle(r#"{"type":"set_winsize_owner","selected":false}"#, 1700);
        assert_eq!(
            r,
            Some(OutboundMsg::WinsizeOwnerChanged {
                owner: "local".into()
            })
        );
        assert_eq!(owner.lock().unwrap().remote_selected(), Some(false));
    }

    #[test]
    fn effective_winsize_owner_snapshot_reflects_shared_state() {
        // The post-auth snapshot helper reads the shared effective owner (used to greet a fresh browser).
        let (_sk, vk) = keys();
        let mut ch = ControlChannel::new(vk, "dev_a".into(), NOPE);
        assert_eq!(ch.effective_winsize_owner(0), "local"); // no shared state → local
        let owner = std::sync::Arc::new(std::sync::Mutex::new(
            crate::winsize_owner::WinsizeOwner::new(),
        ));
        {
            let mut g = owner.lock().unwrap();
            g.set_serving(1, 0);
            g.set_remote_selected(Some(true));
        }
        ch.set_winsize_owner(owner);
        assert_eq!(ch.effective_winsize_owner(0), "remote");
    }
}
