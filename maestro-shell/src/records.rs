//! Durable record types the app shell persists. These are PRODUCT metadata, never seen by
//! the daemon (which is keyed only by an opaque `SessionId(String)` it treats as
//! client-assigned) or the renderer. Every type here is plain serializable data — no IO, no
//! process/socket/git coupling.
//!
//! IDs are plain `String`s holding a UUIDv4. The shell mints `session_id` and hands the SAME
//! string to the daemon as its `SessionId`, which is why this stays a string and not a
//! shell-private newtype: it must round-trip onto the wire unchanged.

use serde::{Deserialize, Serialize};

/// Top-level user-facing grouping ("sample-app", "side-experiment").
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Project {
    pub project_id: String,
    pub name: String,
    /// Canonical directory the project is about (often a git repo root).
    pub root: String,
    pub default_workspace_policy: super::policy::WorkspacePolicy,
    pub created_at_ms: u64,
    pub last_active_at_ms: u64,
    /// Optional short display glyph (an emoji or 1–2 chars) used by the dashboard/sidebar to brand
    /// the project. `None` means "no icon"; the UI falls back to a neutral default. Defaulted on
    /// deserialize so records written before this field still load.
    #[serde(default)]
    pub icon: Option<String>,
    /// Optional accent color as a `#rrggbb` hex string, used for a light active-project tint in the
    /// dashboard/sidebar chrome. `None` means "no accent"; the UI uses its neutral chrome color.
    /// Defaulted on deserialize for backward compatibility.
    #[serde(default)]
    pub accent_color: Option<String>,
    /// Default launch settings (agent/model/resume/etc.) a new window or pane inherits unless it
    /// overrides them. `None` means "no project default" → fall back to the app's built-in default.
    /// Defaulted on deserialize so records written before this field still load.
    #[serde(default)]
    pub launch_defaults: Option<ProjectLaunchDefaults>,
    /// Extra named folders the project pins for quick selection on window creation. Empty when
    /// none. Defaulted on deserialize.
    #[serde(default)]
    pub directories: Vec<ProjectDirectory>,
    /// Preferred dashboard order for windows owned by this project. Window records remain independent;
    /// this list only controls presentation order and tolerates stale ids.
    #[serde(default)]
    pub window_order: Vec<String>,
    /// SYSTEM project marker. `true` for the built-in default "Terminal" project (auto-created on empty open):
    /// it can be renamed + hidden but NEVER deleted. `false` (default) for ordinary user projects. Defaulted on
    /// deserialize so pre-existing records load.
    #[serde(default)]
    pub system: bool,
    /// User HID this project from the dashboard/sidebar (still exists on disk + can be brought back). Distinct from
    /// deletion. Applies to any project; the system project uses it as the only way to "get it out of the way".
    /// Defaulted on deserialize.
    #[serde(default)]
    pub hidden: bool,
}

/// Default launch settings a project hands to new windows/panes
/// (agent/model/resume/dangerous/custom). All fields are optional so a partial
/// form submission round-trips; the app fills gaps from its built-in default at launch time.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectLaunchDefaults {
    /// Allowlisted provider identity to launch. `None` → app default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub agent: Option<String>,
    /// Per-agent model identifier; "default" / `None` lets the CLI pick.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub model: Option<String>,
    /// Resume policy: "continue" | "resume" | "none". `None` → app default.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub resume_mode: Option<String>,
    /// Whether to pass the agent's dangerous skip-permissions flag.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dangerous_skip_permissions: Option<bool>,
    /// If set, a fully custom launch command that overrides everything else.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub custom_command: Option<String>,
}

/// A named folder a project pins for quick selection on window creation. `id` is a stable
/// client-minted key and `path` is an absolute directory.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProjectDirectory {
    pub id: String,
    pub name: String,
    pub path: String,
}

/// Explicit user consent for repo-affecting workspace operations. A `Worktree` or
/// `RepoWrite` session may not be spawned until the matching consent flag is set. This type only
/// stores the consent record. Default is "no consent granted".
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceConsent {
    /// User has consented to `git worktree add/remove`, which mutates the source repo's git
    /// administrative state (e.g. `<root>/.git/worktrees/...`). A deliberate operation, not
    /// invisible metadata — hence an explicit flag.
    pub worktree_create: bool,
    /// User has consented to direct writes into the live checkout (`RepoWrite`).
    pub repo_write: bool,
    /// Unix millis the consent was granted; `None` while ungranted.
    pub granted_at_ms: Option<u64>,
}

/// Isolation contract for the sessions in a workspace. Many workspaces may share one project
/// (e.g. several isolated worktrees of the same repo). `policy` selects how `cwd` is resolved
/// (see `policy::resolved_cwd`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Workspace {
    pub workspace_id: String,
    pub project_id: String,
    /// Repo/dir governed (usually the project root).
    pub root: String,
    pub policy: super::policy::WorkspacePolicy,
    pub consent: WorkspaceConsent,
}

/// Durable, app-owned marker that Maestro prepared a git worktree for a session. Written
/// best-effort at `prepare_worktree` (creation OR idempotent reuse) and surfaced read-only in
/// `worktree-list`. It is provenance only — it NEVER affects cleanup eligibility or destructive
/// behavior; a present-and-matching marker is informational ("Maestro made this directory"),
/// not authorization to remove anything.
///
/// All path fields are canonicalized at write time so later comparison against a canonical
/// listing is exact: `repo_root` is the canonicalized workspace root, `target_path` the
/// canonicalized prepared worktree path, and `branch` the deterministic
/// `maestro/<workspace_id>/<session_id>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorktreeProvenance {
    pub workspace_id: String,
    pub session_id: String,
    pub repo_root: String,
    pub target_path: String,
    pub branch: String,
    pub created_at_ms: u64,
}

/// Whether a session is a plain terminal or agent-backed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionKind {
    Shell,
    Agent,
}

/// Reconciled liveness of a session vs. the daemon's `ListSessions`. `Unknown` is the
/// freshly-written state before the first reconcile/attach.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionStatus {
    Live,
    Exited,
    Unknown,
}

/// How a session is launched, kept SECRET-AWARE. Raw argv is not stored by default because it
/// may carry secrets (`--api-key=...`); see `redact` for the ad-hoc path. A `KnownSafe` spec
/// names a launch recipe whose secrets are re-resolved at launch time, never persisted.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "tier", rename_all = "snake_case")]
pub enum LaunchSpec {
    /// A named, parameterized recipe with NO embedded secrets. Secrets are resolved from the
    /// environment/keychain at launch, never written here. Safe to persist and one-click
    /// restart.
    KnownSafe {
        launch_spec_id: String,
        /// Non-secret parameters only.
        params: Vec<String>,
    },
    /// An ad-hoc command line whose secret-shaped tokens have been conservatively redacted.
    /// `restart_requires_user` is always true for this tier: the shell MUST prompt for the
    /// redacted values before re-spawning — it never silently replays them.
    AdHocRedacted {
        argv: Vec<String>,
        redacted: bool,
        restart_requires_user: bool,
    },
    /// The launch was not retained at all. Restart requires the user to re-enter the command.
    OptOut,
}

/// The durable, shell-side description of a session — distinct from the daemon's in-memory
/// runtime Session. It is what lets the shell re-find or recreate a daemon session by purpose.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    /// The SAME opaque id the shell sends to the daemon as `SessionId`.
    pub session_id: String,
    pub workspace_id: String,
    pub kind: SessionKind,
    pub launch: LaunchSpec,
    /// Actual cwd handed to `StartSession` (computed from the workspace policy).
    pub cwd_resolved: String,
    /// FK to an `AgentTask`, when this session serves one.
    pub agent_task_id: Option<String>,
    pub created_at_ms: u64,
    pub last_attached_at_ms: u64,
    /// Last `SessionGeneration` the shell saw, as a string; lets a reattach detect the daemon
    /// respawned a fresh grid. Stored as a string to avoid coupling to the daemon's uuid type.
    pub last_known_generation: Option<String>,
    pub status: SessionStatus,
}

/// AgentTask lifecycle, distinct from process exit. The daemon only knows a PTY is alive or
/// exited; `WaitingOnUser`/`Blocked` are shell-derived (from agent output conventions or the
/// future channel bus), never protocol facts.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgentTaskState {
    Draft,
    Running,
    WaitingOnUser,
    Blocked,
    Succeeded,
    Failed,
    Cancelled,
}

/// The purpose an agent session serves — a task object, so tabs are tasks, not raw terminals.
/// A task may outlive a single session (a restart is a new `session_id`, same task).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentTask {
    pub agent_task_id: String,
    pub project_id: String,
    pub goal: String,
    pub state: AgentTaskState,
    pub current_session_id: Option<String>,
    /// Prior sessions for this task (restarts/retries), oldest first.
    pub session_history: Vec<String>,
    pub created_at_ms: u64,
    pub updated_at_ms: u64,
    pub result_summary: Option<String>,
}

/// What a tab is signalling. Sticky: a transient signal the user never saw stays flagged
/// until seen (`unseen`), which is the value over raw "is it printing right now".
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Attention {
    None,
    Activity,
    NeedsInput,
    Error,
    Done,
}

/// Where an attention signal came from, for per-source weighting in the UX
/// (process activity < agent transition < explicit user mark/error).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AttentionSource {
    Process,
    Agent,
    User,
}

/// Per-tab attention/status. Mostly runtime-derived; only a coarse `unseen`/`since` roll-up is
/// persisted (inside `WindowLayout`) so "you have unread tabs" survives a restart.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttentionState {
    pub attention: Attention,
    /// Output/transition occurred while the tab was unfocused.
    pub unseen: bool,
    /// Unix millis the current attention level was entered (sorting/aging).
    pub since_ms: u64,
    pub source: AttentionSource,
}

impl Default for AttentionState {
    fn default() -> Self {
        AttentionState {
            attention: Attention::None,
            unseen: false,
            since_ms: 0,
            source: AttentionSource::Process,
        }
    }
}

/// Which way a tab was split off from its source tab. Stored only as layout metadata; the
/// renderer will later use it to place the two panes side-by-side (`Right`) or stacked (`Down`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SplitAxis {
    /// New pane sits to the RIGHT of the source (a vertical divider).
    Right,
    /// New pane sits BELOW the source (a horizontal divider).
    Down,
}

/// Records that a tab was created by splitting an existing tab: which tab it split from and
/// along which axis. Layout-only metadata — no live pane geometry is stored yet.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SplitFrom {
    /// The `tab_id` this tab was split off from (must be a tab in the same window at split time).
    pub tab_id: String,
    /// Direction of the split relative to the source tab.
    pub axis: SplitAxis,
    /// The persisted divider position: the first/parent side's share of the split axis, in PER-MILLE
    /// (`0..=1000`, so `500` == an even split). Stored as an integer so the record stays `Eq`/`Hash`
    /// and serializes deterministically (an `f32` would forfeit both). `#[serde(default)]` → `None`
    /// for older records and freshly-created splits, which the renderer reads as an even split.
    #[serde(default)]
    pub ratio_per_mille: Option<u16>,
}

/// A pane's rectangle within the window, in per-mille of the unit square: `[x, y, w, h]`, each
/// `0..=1000`
/// (so `[0,0,500,1000]` is the left half). Stored as integers so [`TabRecord`] keeps its `Eq`/`Hash`
/// derives and serializes deterministically (an `f32` rect would forfeit both). This is the AUTHORITATIVE
/// pane geometry — an exact tiling description that, unlike [`SplitFrom`], cannot be ambiguous about
/// nesting. The renderer scales it by the grid and paints it directly.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaneRect {
    pub x: u16,
    pub y: u16,
    pub w: u16,
    pub h: u16,
}

impl PaneRect {
    /// Build from a unit rect `[x, y, w, h]` in `[0,1]`, rounding each coordinate to per-mille.
    pub fn from_unit(rect: [f32; 4]) -> Self {
        let q = |v: f32| (v * 1000.0).round().clamp(0.0, 1000.0) as u16;
        PaneRect {
            x: q(rect[0]),
            y: q(rect[1]),
            w: q(rect[2]),
            h: q(rect[3]),
        }
    }
    /// Back to a unit rect `[x, y, w, h]` in `[0,1]`.
    pub fn to_unit(self) -> [f32; 4] {
        [
            self.x as f32 / 1000.0,
            self.y as f32 / 1000.0,
            self.w as f32 / 1000.0,
            self.h as f32 / 1000.0,
        ]
    }
}

/// live attach handle, scroll offset, and focus are runtime-only and not stored here).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TabRecord {
    pub tab_id: String,
    pub session_id: String,
    /// Order within the window.
    pub index: u32,
    pub title: String,
    pub pinned: bool,
    /// Coarse persisted attention roll-up (so unread state survives a restart).
    pub attention: AttentionState,
    /// Set when this tab was created by splitting an existing tab. `#[serde(default)]` so older
    /// records written before split support still deserialize (to `None`).
    ///
    /// LEGACY/transitional: geometry now lives in [`TabRecord::pane_rect`] (an exact tiling). `split_from`
    /// is retained for back-compat and focus-chain navigation while the rect model is wired everywhere.
    #[serde(default)]
    pub split_from: Option<SplitFrom>,
    /// The AUTHORITATIVE geometry of this LIVE pane: its rectangle within the window as a [`PaneRect`].
    /// `None` for a stashed pane (no live geometry) or an old record (the renderer then falls back to the
    /// `split_from` chain). When present, the renderer paints this rect directly — no layout guessing.
    #[serde(default)]
    pub pane_rect: Option<PaneRect>,
    /// The split provenance this pane had when it was stashed. `split_from` is cleared while the pane
    /// is hidden so the live renderer never points at a stashed parent, but revive can use this to
    /// place the pane back into a sensible location instead of reviving every stashed pane as a root.
    #[serde(default)]
    pub stashed_from: Option<SplitFrom>,
    /// Whether this tab is STASHED: kept in the layout as a dormant/revivable row instead of being
    /// hard-removed. A stashed tab is hidden from the live pane layout but still surfaced in the
    /// dashboard as a dim revive candidate; its session record is preserved so it can be relaunched.
    /// `#[serde(default)]` so records written before stash support still deserialize (to `false`).
    #[serde(default)]
    pub stashed: bool,
}

/// Persisted window → ordered tabs layout. One per window; the shell restores open tabs from
/// this on start.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WindowLayout {
    pub window_id: String,
    /// Optional user-facing window name. Kept separate from pane/tab titles so renaming a window
    /// never accidentally renames its first pane.
    #[serde(default)]
    pub name: Option<String>,
    pub tabs: Vec<TabRecord>,
}

/// One tab inside a saved [`LayoutPreset`]. Captures the LAYOUT POSITION of a tab — its order,
/// title, pin state, and split provenance — deliberately WITHOUT binding to a live session. The
/// safety model requires keeping running-session identity separate from layout position so restoring a
/// preset never relabels or restarts the wrong pane; therefore a preset records only a best-effort
/// `session_id` HINT (the session that occupied this slot at capture time), which revive treats as
/// optional: if that session is gone, the slot is restored as a fresh launch in the same position.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutPresetTab {
    /// Order within the preset (mirrors `TabRecord.index`).
    pub index: u32,
    pub title: String,
    pub pinned: bool,
    /// Split provenance relative to another tab in THIS preset. `split_from.tab_id` holds the
    /// CAPTURE-TIME tab id of the source slot (copied verbatim from the live layout); restore maps it
    /// to a slot via that slot's `source_tab_id`, then to the freshly-minted tab id. Reuses the same
    /// shape as the live model so capture is a 1:1 copy.
    #[serde(default)]
    pub split_from: Option<SplitFrom>,
    /// Best-effort pointer to the session that occupied this slot at capture time. `None` (or a
    /// session that no longer exists at restore time) means "launch fresh here". Never used to
    /// relabel a different running pane.
    #[serde(default)]
    pub session_id: Option<String>,
    /// The capture-time `tab_id` of the live tab this slot was copied from. Restore never reuses this
    /// id (it mints fresh ones); it exists ONLY so a sibling slot's `split_from.tab_id` can be matched
    /// back to its source slot, then resolved to that slot's newly-minted tab id. `#[serde(default)]`
    /// (empty) for presets written before split-restore support; a slot with an empty `source_tab_id`
    /// can never be a split source, which is the safe fallback (the dependent slot launches unsplit).
    #[serde(default)]
    pub source_tab_id: String,
}

/// A named, reopenable window arrangement: the ordered tab/pane topology captured from a window so
/// the user can rebuild a working layout without hand-placing tabs and splits. This is native Rust
/// state (not tmux persistence): the preset DESCRIBES a dormant arrangement; revive starts or
/// reattaches sessions through the app-owned daemon/session model in slot order.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LayoutPreset {
    pub preset_id: String,
    /// User-facing name (e.g. "Backend + logs"). Not unique by construction; the id is the key.
    pub name: String,
    /// The project this preset belongs to, if any. `None` is an unassigned/global preset.
    #[serde(default)]
    pub project_id: Option<String>,
    pub created_at_ms: u64,
    /// Ordered tab/pane slots. Empty is a legal (if useless) preset; restore is a no-op.
    pub tabs: Vec<LayoutPresetTab>,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Project launch-default persistence requires that existing project records — written
    // before launch_defaults / directories / window_order existed — still load safely with sane defaults. This
    // pins that: a legacy JSON with only the original fields deserializes with the new fields defaulted.
    #[test]
    fn legacy_project_json_without_launch_defaults_loads_with_safe_defaults() {
        let legacy = r#"{
            "project_id": "proj-legacy",
            "name": "Legacy",
            "root": "/Users/test/legacy",
            "default_workspace_policy": "scratch_cwd",
            "created_at_ms": 1,
            "last_active_at_ms": 2
        }"#;
        let project: Project =
            serde_json::from_str(legacy).expect("legacy project must deserialize");
        assert_eq!(project.project_id, "proj-legacy");
        assert_eq!(project.launch_defaults, None);
        assert!(project.directories.is_empty());
        assert!(project.window_order.is_empty());
        assert_eq!(project.icon, None);
        assert_eq!(project.accent_color, None);
    }

    // And a full record with launch defaults + directories round-trips through JSON unchanged, so the persisted
    // shape the browser/desktop both read stays stable.
    #[test]
    fn project_with_launch_defaults_and_directories_round_trips() {
        let project = Project {
            project_id: "proj-full".into(),
            name: "Full".into(),
            root: "/Users/test/full".into(),
            default_workspace_policy: super::super::policy::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 2,
            icon: Some("◆".into()),
            accent_color: Some("#34d399".into()),
            launch_defaults: Some(ProjectLaunchDefaults {
                agent: Some("codex".into()),
                model: Some("opus".into()),
                resume_mode: Some("resume".into()),
                dangerous_skip_permissions: Some(true),
                custom_command: None,
            }),
            directories: vec![ProjectDirectory {
                id: "dir-0".into(),
                name: "docs".into(),
                path: "/Users/test/full/docs".into(),
            }],
            window_order: vec!["win-1".into()],
            system: false,
            hidden: false,
        };
        let json = serde_json::to_string(&project).unwrap();
        let back: Project = serde_json::from_str(&json).unwrap();
        assert_eq!(project, back);
    }
}
