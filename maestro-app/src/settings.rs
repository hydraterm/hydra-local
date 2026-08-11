//! Settings model + storage for `maestro-app settings show` / `settings set`.
//!
//! This module owns the serde DTOs and the pure construction helper for the app's *effective*
//! settings, plus the narrow persisted-override path. `settings show` reports the policy the app
//! already enforces elsewhere (foreground chrome defaults, workspace consent policy, local safety
//! policy, and the current appearance), so this is a single source of truth for *reporting* those
//! defaults — not a new place where they are decided. The persisted appearance overrides are
//! `appearance.font_size_px` and `appearance.theme`; everything else is a reporting constant.
//!
//! Storage is local-only: a single versioned JSON file at `<base>/settings/settings.json`. There is
//! no daemon connection, no process spawn, no renderer/window, and no shared record store. The
//! settings dir is created `0700` and the file written `0600` (Unix) via temp-file + atomic rename.
//!
//! Keep all field names snake_case and every value deterministic so the JSON is stable across runs.
//! New fields must be backward-additive and covered by tests.

use serde::{Deserialize, Serialize};
use std::io;
use std::path::{Path, PathBuf};

/// The on-disk settings schema version. A file with a different `schema_version` is treated as
/// foreign: `settings show` ignores it and reports defaults (with a `settings_warning`), and
/// `settings set` refuses to overwrite it.
pub const SETTINGS_SCHEMA_VERSION: u32 = 1;

/// Inclusive accepted range for the persisted `appearance.font_size_px` override.
pub const MIN_FONT_SIZE_PX: u32 = 10;
pub const MAX_FONT_SIZE_PX: u32 = 32;

/// The settings subdirectory name under the resolved app-support base.
const SETTINGS_DIR_NAME: &str = "settings";
/// The settings file name within the settings subdirectory.
const SETTINGS_FILE_NAME: &str = "settings.json";

/// Supported persisted theme identifiers. `built_in_dark` is the default; `high_contrast_dark` is the
/// only settable alternative. These are storage/reporting identifiers only — no renderer
/// color wiring is read or written here.
pub const THEME_BUILT_IN_DARK: &str = "built_in_dark";
pub const THEME_HIGH_CONTRAST_DARK: &str = "high_contrast_dark";
pub const SUPPORTED_THEMES: &[&str] = &[THEME_BUILT_IN_DARK, THEME_HIGH_CONTRAST_DARK];

/// Supported persisted `workspace.default_policy` identifiers. These mirror the stable wire strings of
/// `maestro_shell::WorkspacePolicy` (`scratch_cwd` / `worktree` / `repo_write`); `scratch_cwd` is the
/// built-in default. Storage/reporting identifiers only — no daemon/launch policy resolution is read or
/// written here.
pub const WORKSPACE_POLICY_SCRATCH_CWD: &str = "scratch_cwd";
pub const WORKSPACE_POLICY_WORKTREE: &str = "worktree";
pub const WORKSPACE_POLICY_REPO_WRITE: &str = "repo_write";
pub const SUPPORTED_WORKSPACE_POLICIES: &[&str] = &[
    WORKSPACE_POLICY_SCRATCH_CWD,
    WORKSPACE_POLICY_WORKTREE,
    WORKSPACE_POLICY_REPO_WRITE,
];

/// The stable identifier for the built-in (default) theme reported by `settings show`. Aliased to
/// [`THEME_BUILT_IN_DARK`]; appearance theme is now persistable via `settings set appearance.theme`.
pub const BUILT_IN_THEME: &str = THEME_BUILT_IN_DARK;

/// The built-in font size (in px) reported by `settings show` when no override is persisted.
pub const DEFAULT_FONT_SIZE_PX: u32 = 16;

/// Default foreground chrome policy, mirroring [`crate::resolve_attach_tab_chrome`]'s defaults: the
/// top tab bar and dashboard status suffix default ON for foreground/no-run; the dashboard panel and
/// picker overlay remain explicit opt-ins (default OFF).
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ChromeDefaults {
    pub top_tab_bar_default: bool,
    pub dashboard_status_default: bool,
    pub dashboard_panel_default: bool,
    pub picker_overlay_default: bool,
}

/// Default workspace policy: foreground launches default to a scratch checkout of the current
/// directory, and both worktree creation and repo-write access require explicit consent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct WorkspaceDefaults {
    pub default_policy: String,
    pub worktree_requires_consent: bool,
    pub repo_write_requires_consent: bool,
}

/// Local safety policy booleans the app enforces: a private per-dev socket by default, a required
/// confirmation before any destructive worktree cleanup, and explicit consent before repo writes.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SafetyDefaults {
    pub private_dev_socket_by_default: bool,
    pub destructive_worktree_cleanup_requires_confirm: bool,
    pub repo_write_requires_explicit_consent: bool,
}

/// Current non-configurable appearance defaults. Reported for completeness; no renderer theme/font
/// wiring is read or written here.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct AppearanceDefaults {
    pub theme: String,
    pub font_size_px: u32,
}

/// Reported shell defaults. `default_argv` is the persisted `shell.default_argv` override (a non-empty
/// command argv) or `None` when unset — `None` means the app keeps its built-in `$SHELL`/`sh` fallback.
/// It is intentionally optional so `settings show` distinguishes a configured shell argv from the
/// environment fallback; the effective `$SHELL` value is never echoed here as a default.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ShellDefaults {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_argv: Option<Vec<String>>,
}

impl ShellDefaults {
    /// The built-in shell defaults: no configured argv (the `$SHELL`/`sh` fallback applies).
    pub fn built_in() -> Self {
        Self { default_argv: None }
    }
}

/// The full effective-settings report printed by `settings show`. `source` is `"defaults"` when no
/// persisted override applies and `"defaults+overrides"` when a schema-version-1 `settings.json`
/// supplied at least one override. `base_dir` echoes the resolved app-support base path;
/// `settings_path` is the resolved settings file path (whether or not it exists). `settings_warning`
/// is set only when a present file was unreadable or carried a foreign schema version, in which case
/// defaults are reported instead.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct EffectiveSettings {
    pub source: String,
    pub base_dir: String,
    pub settings_path: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub settings_warning: Option<String>,
    pub chrome: ChromeDefaults,
    pub workspace: WorkspaceDefaults,
    pub safety: SafetyDefaults,
    pub appearance: AppearanceDefaults,
    pub shell: ShellDefaults,
}

impl ChromeDefaults {
    /// The built-in foreground chrome defaults.
    pub fn built_in() -> Self {
        Self {
            top_tab_bar_default: true,
            dashboard_status_default: true,
            dashboard_panel_default: false,
            picker_overlay_default: false,
        }
    }
}

impl WorkspaceDefaults {
    /// The built-in workspace policy defaults.
    pub fn built_in() -> Self {
        Self {
            default_policy: "scratch_cwd".to_string(),
            worktree_requires_consent: true,
            repo_write_requires_consent: true,
        }
    }
}

impl SafetyDefaults {
    /// The built-in local safety policy defaults.
    pub fn built_in() -> Self {
        Self {
            private_dev_socket_by_default: true,
            destructive_worktree_cleanup_requires_confirm: true,
            repo_write_requires_explicit_consent: true,
        }
    }
}

impl AppearanceDefaults {
    /// The built-in (non-configurable) appearance defaults.
    pub fn built_in() -> Self {
        Self {
            theme: BUILT_IN_THEME.to_string(),
            font_size_px: DEFAULT_FONT_SIZE_PX,
        }
    }
}

/// Per-line character cap for the settings panel projection. Bounds any user-controlled string
/// content (paths, warning text, shell argv members) so a single panel line stays terminal-friendly
/// and cannot grow without limit. When a line is truncated it ends with an ASCII `...` marker.
pub const SETTINGS_PANEL_LINE_MAX: usize = 120;

/// A single structured row of the settings-panel projection. PURE metadata describing one visible
/// panel line: a stable `id` and `category` (never user-controlled, always ASCII), a user-facing
/// `label`, the sanitized/bounded display `value`, and editability metadata. `setting_key` is
/// `Some(<existing CLI settings key>)` ONLY when the row maps to a setting that is already
/// settable/resettable through the `settings set`/`settings reset` CLI; report-only rows (source,
/// paths, warnings, workspace policy, safety policy) carry `None`. `editable` is the derived
/// invariant `setting_key.is_some()`: a row is editable iff it names a real settings key. This is
/// metadata only — it adds NO mutation authority; `settings set/reset/show` stay the sole write path.
///
/// Rows are stable and ordered 1:1 with [`SettingsPanelLines::lines`] (row `i` describes line `i`),
/// so a future renderer can select a row and know exactly which visible line it represents. Every
/// string field is ASCII-only, control-char-sanitized, and length-bounded via the same panel safety
/// policy as the visible lines.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SettingsPanelRow {
    pub id: &'static str,
    pub category: &'static str,
    pub label: &'static str,
    pub value: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub setting_key: Option<&'static str>,
    pub editable: bool,
}

impl SettingsPanelRow {
    /// A report-only row: no settings key, not editable.
    fn report(
        id: &'static str,
        category: &'static str,
        label: &'static str,
        value: String,
    ) -> Self {
        Self {
            id,
            category,
            label,
            value,
            setting_key: None,
            editable: false,
        }
    }

    /// A row mapped to an existing CLI settings key; always editable.
    fn editable(
        id: &'static str,
        category: &'static str,
        label: &'static str,
        value: String,
        setting_key: &'static str,
    ) -> Self {
        Self {
            id,
            category,
            label,
            value,
            setting_key: Some(setting_key),
            editable: true,
        }
    }
}

/// A compact, display-ready projection of [`EffectiveSettings`] for a future native settings pane.
/// PURE and read-only: built entirely from an already-resolved `EffectiveSettings` value with no I/O.
/// Every field is ASCII-only, control-char-sanitized, and length-bounded so it is directly safe to
/// render as fixed panel rows. `lines` is a stable, ordered list of `category: value` rows;
/// `line_count` mirrors `lines.len()` for chrome that wants the count without walking the vector.
/// `rows` is a backward-additive structured mirror of `lines` (same order, one row per line) carrying
/// stable id/category/label/value plus `setting_key`/`editable` metadata for a future interactive UI;
/// it is metadata only and grants no mutation authority.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SettingsPanelLines {
    pub title: &'static str,
    pub summary: String,
    pub lines: Vec<String>,
    pub line_count: usize,
    pub rows: Vec<SettingsPanelRow>,
}

/// Strip control characters (anything `is_control()`, including tabs/newlines/CR) and collapse any
/// resulting whitespace runs to single spaces, then force ASCII by replacing every non-ASCII char
/// with `?`. The result can never contain a newline, so it can never split one panel line into two.
fn panel_line_sanitize(s: &str) -> String {
    let cleaned: String = s
        .chars()
        .map(|c| {
            if c.is_control() {
                ' '
            } else if c.is_ascii() {
                c
            } else {
                '?'
            }
        })
        .collect();
    cleaned.split_whitespace().collect::<Vec<_>>().join(" ")
}

/// Deterministically truncate `s` to at most `max` characters (counting `char`s). When truncated the
/// result is exactly `max` chars total ending in an ASCII `...` marker; `max < 4` collapses to a bare
/// `...`/prefix so the marker still fits. `max == 0` yields an empty string.
fn panel_line_truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        return s.to_string();
    }
    if max == 0 {
        return String::new();
    }
    if max <= 3 {
        return ".".repeat(max);
    }
    let keep = max - 3;
    let mut out: String = s.chars().take(keep).collect();
    out.push_str("...");
    out
}

/// Sanitize then bound a display string to one safe panel cell.
fn panel_field(s: &str) -> String {
    panel_line_truncate(&panel_line_sanitize(s), SETTINGS_PANEL_LINE_MAX)
}

/// Render a `default_argv` override as a compact, single-line, ASCII summary (e.g.
/// `["/bin/zsh", "-l"]`), each member sanitized; the whole rendering is then bounded.
fn panel_shell_argv(argv: &[String]) -> String {
    let members: Vec<String> = argv
        .iter()
        .map(|m| format!("\"{}\"", panel_line_sanitize(m)))
        .collect();
    panel_line_truncate(
        &format!("[{}]", members.join(", ")),
        SETTINGS_PANEL_LINE_MAX,
    )
}

/// Build the compact, deterministic [`SettingsPanelLines`] projection from an already-resolved
/// [`EffectiveSettings`]. PURE: no I/O, no daemon, no file reads — it only reshapes the value normal
/// `settings show` already prints. Categories appear in a STABLE order: source/path state (plus a
/// warning line only when `settings_warning` is present), appearance, chrome defaults, shell
/// (explicit fallback line when no argv is configured), workspace defaults, and safety defaults.
/// All user-controlled strings are sanitized (control chars removed, forced ASCII) and bounded.
pub fn build_settings_panel_lines(settings: &EffectiveSettings) -> SettingsPanelLines {
    let mut lines: Vec<String> = Vec::new();
    let mut rows: Vec<SettingsPanelRow> = Vec::new();

    // Each emit pairs one visible `lines` entry with its structured row so the two vectors stay
    // index-aligned (row `i` describes line `i`). `prefix` is the literal `category:`-style line
    // label and `value` is the already-sanitized/bounded display value; the visible line is exactly
    // `"{prefix}: {value}"`, byte-identical to the prior projection.
    let mut emit = |prefix: &str, value: String, row: SettingsPanelRow| {
        lines.push(format!("{prefix}: {value}"));
        rows.push(row);
    };

    // Source / path state (report-only).
    let source = panel_field(&settings.source);
    emit(
        "source",
        source.clone(),
        SettingsPanelRow::report("source", "source", "Source", source),
    );
    let base_dir = panel_field(&settings.base_dir);
    emit(
        "base_dir",
        base_dir.clone(),
        SettingsPanelRow::report("base_dir", "source", "Base dir", base_dir),
    );
    let settings_path = panel_field(&settings.settings_path);
    emit(
        "settings_path",
        settings_path.clone(),
        SettingsPanelRow::report("settings_path", "source", "Settings path", settings_path),
    );
    if let Some(warning) = &settings.settings_warning {
        let warning = panel_field(warning);
        emit(
            "warning",
            warning.clone(),
            SettingsPanelRow::report("warning", "source", "Warning", warning),
        );
    }

    // Appearance (editable).
    let theme = panel_field(&settings.appearance.theme);
    emit(
        "theme",
        theme.clone(),
        SettingsPanelRow::editable("theme", "appearance", "Theme", theme, "appearance.theme"),
    );
    let font_size_px = settings.appearance.font_size_px.to_string();
    emit(
        "font_size_px",
        font_size_px.clone(),
        SettingsPanelRow::editable(
            "font_size_px",
            "appearance",
            "Font size (px)",
            font_size_px,
            "appearance.font_size_px",
        ),
    );

    // Chrome defaults (editable).
    let top_tab_bar = settings.chrome.top_tab_bar_default.to_string();
    emit(
        "chrome.top_tab_bar",
        top_tab_bar.clone(),
        SettingsPanelRow::editable(
            "chrome.top_tab_bar",
            "chrome",
            "Top tab bar",
            top_tab_bar,
            "chrome.top_tab_bar_default",
        ),
    );
    let dashboard_status = settings.chrome.dashboard_status_default.to_string();
    emit(
        "chrome.dashboard_status",
        dashboard_status.clone(),
        SettingsPanelRow::editable(
            "chrome.dashboard_status",
            "chrome",
            "Dashboard status",
            dashboard_status,
            "chrome.dashboard_status_default",
        ),
    );
    let dashboard_panel = settings.chrome.dashboard_panel_default.to_string();
    emit(
        "chrome.dashboard_panel",
        dashboard_panel.clone(),
        SettingsPanelRow::editable(
            "chrome.dashboard_panel",
            "chrome",
            "Dashboard panel",
            dashboard_panel,
            "chrome.dashboard_panel_default",
        ),
    );
    let picker_overlay = settings.chrome.picker_overlay_default.to_string();
    emit(
        "chrome.picker_overlay",
        picker_overlay.clone(),
        SettingsPanelRow::editable(
            "chrome.picker_overlay",
            "chrome",
            "Picker overlay",
            picker_overlay,
            "chrome.picker_overlay_default",
        ),
    );

    // Shell (editable). The fallback line is reported when no argv is configured; the row is still
    // editable because `shell.default_argv` is a settable key (its value is just unset here).
    let shell_argv = match &settings.shell.default_argv {
        Some(argv) if !argv.is_empty() => panel_shell_argv(argv),
        _ => "(unset; $SHELL/sh fallback)".to_string(),
    };
    emit(
        "shell.default_argv",
        shell_argv.clone(),
        SettingsPanelRow::editable(
            "shell.default_argv",
            "shell",
            "Shell argv",
            shell_argv,
            "shell.default_argv",
        ),
    );

    // Workspace defaults (settable: policy + the two consent toggles).
    let workspace_policy = panel_field(&settings.workspace.default_policy);
    emit(
        "workspace.default_policy",
        workspace_policy.clone(),
        SettingsPanelRow::editable(
            "workspace.default_policy",
            "workspace",
            "Default policy",
            workspace_policy,
            "workspace.default_policy",
        ),
    );
    let worktree_consent = settings.workspace.worktree_requires_consent.to_string();
    emit(
        "workspace.worktree_requires_consent",
        worktree_consent.clone(),
        SettingsPanelRow::editable(
            "workspace.worktree_requires_consent",
            "workspace",
            "Worktree requires consent",
            worktree_consent,
            "workspace.worktree_requires_consent",
        ),
    );
    let repo_write_consent = settings.workspace.repo_write_requires_consent.to_string();
    emit(
        "workspace.repo_write_requires_consent",
        repo_write_consent.clone(),
        SettingsPanelRow::editable(
            "workspace.repo_write_requires_consent",
            "workspace",
            "Repo write requires consent",
            repo_write_consent,
            "workspace.repo_write_requires_consent",
        ),
    );

    // Safety defaults (report-only).
    let private_socket = settings.safety.private_dev_socket_by_default.to_string();
    emit(
        "safety.private_dev_socket_by_default",
        private_socket.clone(),
        SettingsPanelRow::report(
            "safety.private_dev_socket_by_default",
            "safety",
            "Private dev socket by default",
            private_socket,
        ),
    );
    let destructive_confirm = settings
        .safety
        .destructive_worktree_cleanup_requires_confirm
        .to_string();
    emit(
        "safety.destructive_worktree_cleanup_requires_confirm",
        destructive_confirm.clone(),
        SettingsPanelRow::report(
            "safety.destructive_worktree_cleanup_requires_confirm",
            "safety",
            "Destructive worktree cleanup requires confirm",
            destructive_confirm,
        ),
    );
    let repo_write_consent_safety = settings
        .safety
        .repo_write_requires_explicit_consent
        .to_string();
    emit(
        "safety.repo_write_requires_explicit_consent",
        repo_write_consent_safety.clone(),
        SettingsPanelRow::report(
            "safety.repo_write_requires_explicit_consent",
            "safety",
            "Repo write requires explicit consent",
            repo_write_consent_safety,
        ),
    );

    let summary = format!(
        "source={} theme={} font_size_px={} shell_argv={}",
        panel_field(&settings.source),
        panel_field(&settings.appearance.theme),
        settings.appearance.font_size_px,
        if settings
            .shell
            .default_argv
            .as_ref()
            .is_some_and(|a| !a.is_empty())
        {
            "set"
        } else {
            "unset"
        }
    );

    let line_count = lines.len();
    debug_assert_eq!(
        lines.len(),
        rows.len(),
        "settings panel lines and rows must stay index-aligned"
    );
    SettingsPanelLines {
        title: "Settings",
        summary,
        lines,
        line_count,
        rows,
    }
}

/// Structured failure envelope for the `settings` command, mirroring the other command failures
/// (`ok:false`, `command:"settings"`, `error_kind`, `message`). The only emitted `error_kind`
/// is `bad_usage` (a parse error); the command itself is infallible once parsed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct SettingsFailure {
    pub ok: bool,
    pub command: &'static str,
    pub error_kind: String,
    pub message: String,
}

impl SettingsFailure {
    pub fn new(error_kind: impl Into<String>, message: impl Into<String>) -> Self {
        SettingsFailure {
            ok: false,
            command: "settings",
            error_kind: error_kind.into(),
            message: message.into(),
        }
    }
}

/// The persisted on-disk settings file. `schema_version` (kept at `1`) gates whether the file is
/// honored. Pretty-printed snake_case JSON. `chrome` is `#[serde(default)]` so older schema-version-1
/// files that carried only `appearance` still deserialize (a missing `chrome` reports the built-in
/// chrome defaults). New writes always include both `appearance` and `chrome`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedSettings {
    pub schema_version: u32,
    pub appearance: PersistedAppearance,
    #[serde(default)]
    pub chrome: PersistedChrome,
    #[serde(default)]
    pub shell: PersistedShell,
    #[serde(default)]
    pub workspace: PersistedWorkspace,
}

/// The persisted shell overrides. `default_argv` is `Option<Vec<String>>` so an absent key keeps the
/// built-in `$SHELL`/`sh` fallback and only an explicitly-set non-empty argv overrides it. This is a
/// schema-version-1 backward-additive field (`#[serde(default)]`): older files without a `shell`
/// section still deserialize and report no override.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedShell {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_argv: Option<Vec<String>>,
}

/// The persisted appearance overrides. `theme` is `#[serde(default)]` so older schema-version-1 files
/// that carried only `font_size_px` still deserialize (a missing `theme` reports the default theme).
/// New writes always include both fields.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedAppearance {
    pub font_size_px: u32,
    #[serde(default = "default_persisted_theme")]
    pub theme: String,
}

/// The persisted foreground-chrome overrides. Each field is `Option<bool>` so an absent key reports
/// the built-in default and only an explicitly-set value overrides it. All four chrome defaults now
/// have explicit CLI enable/disable controls and are configurable here. Note `picker_overlay_default`
/// only affects the foreground in-process renderer: it never makes `--no-run-renderer` or a detached
/// renderer resolve the picker overlay true (see [`crate::resolve_attach_tab_chrome`]).
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedChrome {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_tab_bar_default: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashboard_status_default: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub dashboard_panel_default: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub picker_overlay_default: Option<bool>,
}

/// The persisted workspace-policy overrides. Each field is `Option` so an absent key reports the
/// built-in default and only an explicitly-set value overrides it. `default_policy` is a validated
/// policy id (`scratch_cwd` / `worktree` / `repo_write`). The two consent fields are persistable
/// `Option<bool>` toggles. This is a schema-version-1 backward-additive section (`#[serde(default)]`):
/// older files without a `workspace` section still deserialize and report the built-in defaults. Note
/// the `safety.*` policy keys remain report-only constants and are deliberately NOT persistable here:
/// the destructive/consent safety guards cannot be relaxed through the settings file.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct PersistedWorkspace {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_policy: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub worktree_requires_consent: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub repo_write_requires_consent: Option<bool>,
}

/// The default persisted theme used when a settings file omits `appearance.theme` (older font-size-only
/// files). Kept equal to [`BUILT_IN_THEME`].
fn default_persisted_theme() -> String {
    BUILT_IN_THEME.to_string()
}

/// A current-schema [`PersistedSettings`] holding the built-in appearance values and no chrome
/// overrides. Used as the starting point for the read-modify-write set/reset paths when no settings
/// file exists yet, so a single-field change records that field while leaving every sibling at its
/// default.
fn default_persisted() -> PersistedSettings {
    PersistedSettings {
        schema_version: SETTINGS_SCHEMA_VERSION,
        appearance: PersistedAppearance {
            font_size_px: DEFAULT_FONT_SIZE_PX,
            theme: BUILT_IN_THEME.to_string(),
        },
        chrome: PersistedChrome::default(),
        shell: PersistedShell::default(),
        workspace: PersistedWorkspace::default(),
    }
}

/// Whether a persisted-settings value is entirely at the built-in defaults: appearance equals the
/// built-in font/theme AND no chrome override is recorded. When true after a reset, the settings file
/// is deleted rather than rewritten so an all-default state leaves no file behind.
fn persisted_is_all_default(p: &PersistedSettings) -> bool {
    p.appearance.font_size_px == DEFAULT_FONT_SIZE_PX
        && p.appearance.theme == BUILT_IN_THEME
        && p.chrome.top_tab_bar_default.is_none()
        && p.chrome.dashboard_status_default.is_none()
        && p.chrome.dashboard_panel_default.is_none()
        && p.chrome.picker_overlay_default.is_none()
        && p.shell.default_argv.is_none()
        && p.workspace.default_policy.is_none()
        && p.workspace.worktree_requires_consent.is_none()
        && p.workspace.repo_write_requires_consent.is_none()
}

/// Validate a candidate `appearance.font_size_px` value. Accepts the inclusive
/// [`MIN_FONT_SIZE_PX`]..=[`MAX_FONT_SIZE_PX`] range; returns a human-readable reason otherwise. The
/// CLI parser is the primary gate (it rejects bad usage before dispatch), but this keeps the
/// invariant local to the storage model so it cannot drift.
pub fn validate_font_size_px(value: u32) -> Result<u32, String> {
    if (MIN_FONT_SIZE_PX..=MAX_FONT_SIZE_PX).contains(&value) {
        Ok(value)
    } else {
        Err(format!(
            "font_size_px must be in {MIN_FONT_SIZE_PX}..={MAX_FONT_SIZE_PX} (got {value})"
        ))
    }
}

/// Validate a candidate `appearance.theme` value against [`SUPPORTED_THEMES`]. Returns the owned theme
/// identifier on success or a human-readable reason listing the accepted identifiers otherwise.
pub fn validate_theme(value: &str) -> Result<String, String> {
    if SUPPORTED_THEMES.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(format!(
            "theme must be one of [{}] (got {value:?})",
            SUPPORTED_THEMES.join(", ")
        ))
    }
}

/// Validate a candidate `workspace.default_policy` value against [`SUPPORTED_WORKSPACE_POLICIES`].
/// Returns the owned policy id on success or a human-readable reason listing the accepted identifiers
/// otherwise. The CLI parser is the primary gate, but this keeps the invariant local to the storage
/// model so it cannot drift.
pub fn validate_workspace_policy(value: &str) -> Result<String, String> {
    if SUPPORTED_WORKSPACE_POLICIES.contains(&value) {
        Ok(value.to_string())
    } else {
        Err(format!(
            "workspace.default_policy must be one of [{}] (got {value:?})",
            SUPPORTED_WORKSPACE_POLICIES.join(", ")
        ))
    }
}

/// Validate a candidate `shell.default_argv` value supplied as a JSON-array string (for example
/// `["/bin/zsh","-l"]`). Returns the owned argv on success or a deterministic human-readable reason
/// otherwise. Rejections (all surfaced as `bad_usage` by the caller):
/// - malformed JSON;
/// - any non-array JSON (objects, scalars, `null`);
/// - an empty array;
/// - any non-string element (numbers, booleans, nulls, nested arrays/objects);
/// - a first element that is empty after trimming whitespace (an empty command name).
///
/// Element strings other than the first are preserved verbatim (arguments may legitimately be empty
/// or whitespace). Only the command name (first element) must be non-empty after trim.
pub fn validate_shell_default_argv(raw: &str) -> Result<Vec<String>, String> {
    let value: serde_json::Value = serde_json::from_str(raw)
        .map_err(|err| format!("shell.default_argv must be a JSON array of strings: {err}"))?;
    let serde_json::Value::Array(items) = value else {
        return Err(
            "shell.default_argv must be a JSON array (for example [\"/bin/zsh\",\"-l\"])"
                .to_string(),
        );
    };
    if items.is_empty() {
        return Err("shell.default_argv must be a non-empty array".to_string());
    }
    let mut argv = Vec::with_capacity(items.len());
    for (index, item) in items.iter().enumerate() {
        let serde_json::Value::String(s) = item else {
            return Err(format!(
                "shell.default_argv element {index} must be a string (got {item})"
            ));
        };
        argv.push(s.clone());
    }
    if argv[0].trim().is_empty() {
        return Err(
            "shell.default_argv command name (first element) must be non-empty".to_string(),
        );
    }
    Ok(argv)
}

/// Resolve the settings directory (`<base>/settings`) for a resolved app-support base.
pub fn settings_dir(base: &Path) -> PathBuf {
    base.join(SETTINGS_DIR_NAME)
}

/// Resolve the settings file path (`<base>/settings/settings.json`) for a resolved app-support base.
pub fn settings_file_path(base: &Path) -> PathBuf {
    settings_dir(base).join(SETTINGS_FILE_NAME)
}

/// Outcome of attempting to load the persisted settings file.
enum LoadedSettings {
    /// No file present — report pure defaults.
    Absent,
    /// A current-schema file was read and parsed.
    Honored(PersistedSettings),
    /// A file was present but unreadable or carried a foreign schema version; report defaults plus
    /// this warning. The file is never rewritten by `show`.
    Warn(String),
}

/// Read and classify the persisted settings file. Never rewrites; a foreign/unreadable file yields a
/// warning and defaults so `show` stays non-destructive.
fn load_persisted(path: &Path) -> LoadedSettings {
    let raw = match std::fs::read_to_string(path) {
        Ok(raw) => raw,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return LoadedSettings::Absent,
        Err(err) => {
            return LoadedSettings::Warn(format!("settings file unreadable: {err}"));
        }
    };
    match serde_json::from_str::<PersistedSettings>(&raw) {
        Ok(persisted) if persisted.schema_version == SETTINGS_SCHEMA_VERSION => {
            LoadedSettings::Honored(persisted)
        }
        Ok(persisted) => LoadedSettings::Warn(format!(
            "settings file schema_version {} is not supported (expected {SETTINGS_SCHEMA_VERSION}); reporting defaults",
            persisted.schema_version
        )),
        Err(err) => LoadedSettings::Warn(format!("settings file malformed: {err}")),
    }
}

/// Build the effective settings report for the supplied resolved `base`, merging any persisted
/// schema-version-1 `appearance` and `chrome` overrides over the built-in defaults. Reads at most the
/// single settings file; it connects to no daemon, reads no records, and never writes. A
/// foreign/unreadable file is ignored (defaults reported) with a `settings_warning`. `source` is
/// `"defaults+overrides"` whenever a current-schema file was honored, even if every field happens to
/// equal its default.
pub fn effective_settings(base: impl AsRef<Path>) -> EffectiveSettings {
    let base = base.as_ref();
    let path = settings_file_path(base);
    let mut appearance = AppearanceDefaults::built_in();
    let mut chrome = ChromeDefaults::built_in();
    let mut shell = ShellDefaults::built_in();
    let mut workspace = WorkspaceDefaults::built_in();
    let (source, warning) = match load_persisted(&path) {
        LoadedSettings::Absent => ("defaults".to_string(), None),
        LoadedSettings::Honored(persisted) => {
            appearance.font_size_px = persisted.appearance.font_size_px;
            appearance.theme = persisted.appearance.theme;
            if let Some(v) = persisted.chrome.top_tab_bar_default {
                chrome.top_tab_bar_default = v;
            }
            if let Some(v) = persisted.chrome.dashboard_status_default {
                chrome.dashboard_status_default = v;
            }
            if let Some(v) = persisted.chrome.dashboard_panel_default {
                chrome.dashboard_panel_default = v;
            }
            if let Some(v) = persisted.chrome.picker_overlay_default {
                chrome.picker_overlay_default = v;
            }
            shell.default_argv = persisted.shell.default_argv;
            if let Some(v) = persisted.workspace.default_policy {
                workspace.default_policy = v;
            }
            if let Some(v) = persisted.workspace.worktree_requires_consent {
                workspace.worktree_requires_consent = v;
            }
            if let Some(v) = persisted.workspace.repo_write_requires_consent {
                workspace.repo_write_requires_consent = v;
            }
            ("defaults+overrides".to_string(), None)
        }
        LoadedSettings::Warn(message) => ("defaults".to_string(), Some(message)),
    };
    EffectiveSettings {
        source,
        base_dir: base.to_string_lossy().to_string(),
        settings_path: path.to_string_lossy().to_string(),
        settings_warning: warning,
        chrome,
        workspace,
        safety: SafetyDefaults::built_in(),
        appearance,
        shell,
    }
}

/// The configured shell default argv resolved from the effective settings, or `None` when no override
/// is persisted. A thin accessor so callers (launch / foreground attach-tab default-shell) read the
/// override through one seam rather than reaching into the `shell` field.
pub fn settings_shell_default_argv(settings: &EffectiveSettings) -> Option<&[String]> {
    settings.shell.default_argv.as_deref()
}

/// The launch-time renderer glyph point size resolved from the effective settings. The renderer never
/// reads settings itself; the app passes this into `RendererLaunch.font_size_px` and reports it on the
/// launch/attach-tab success JSON. Currently a direct read of `appearance.font_size_px`.
pub fn renderer_font_size_px(settings: &EffectiveSettings) -> u32 {
    settings.appearance.font_size_px
}

/// The launch-time renderer theme id resolved from the effective settings. The renderer never reads
/// settings itself; the app passes this into `RendererLaunch.theme` (via `RendererTheme::parse`) and
/// the detached `--theme` argv, and reports it on the launch/attach-tab success JSON. A direct read
/// of `appearance.theme` (`built_in_dark` by default).
pub fn renderer_theme_id(settings: &EffectiveSettings) -> &str {
    &settings.appearance.theme
}

/// The deterministic success value printed by `settings set`. `changed` is `false` when the file
/// already held the requested value. `settings` is the full effective report after the write. `value`
/// is a `serde_json::Value` so font-size serializes as a JSON number (`18`) and theme as a JSON string
/// (`"high_contrast_dark"`) — the serialized shape for font-size is unchanged from when it was a `u32`.
#[derive(Clone, Debug, PartialEq, Serialize)]
pub struct SettingsSetSuccess {
    pub ok: bool,
    pub command: &'static str,
    pub action: &'static str,
    pub key: &'static str,
    pub value: serde_json::Value,
    pub changed: bool,
    pub base_dir: String,
    pub settings_path: String,
    pub settings: EffectiveSettings,
}

/// Persist `appearance.font_size_px` under the resolved `base`, then return a deterministic success
/// value. Local-only: creates `<base>/settings` (`0700` on Unix), writes `settings.json` (`0600` on
/// Unix) atomically via a temp file + rename, and re-reads the effective settings for the response.
///
/// Refuses (via [`SettingsFailure`]) when the value is out of range or when a present file carries a
/// foreign/unreadable schema (so `set` never silently clobbers a forward-version file). `changed` is
/// `false` when the persisted value already equals `value`.
pub fn set_font_size_px(base: &Path, value: u32) -> Result<SettingsSetSuccess, SettingsFailure> {
    validate_font_size_px(value).map_err(|reason| SettingsFailure::new("bad_usage", reason))?;

    let path = settings_file_path(base);
    // Guard against clobbering a foreign/unreadable file. An absent file or an honored
    // current-schema file is fine to (re)write. Preserve every existing sibling override (theme +
    // chrome) so unchanged fields are carried through the write per the full-state invariant.
    let (changed, mut next) = match load_persisted(&path) {
        LoadedSettings::Absent => (true, default_persisted()),
        LoadedSettings::Honored(existing) => (existing.appearance.font_size_px != value, existing),
        LoadedSettings::Warn(message) => {
            return Err(SettingsFailure::new(
                "settings_conflict",
                format!("refusing to overwrite settings: {message}"),
            ));
        }
    };

    if changed {
        next.appearance.font_size_px = value;
        write_settings_atomic(base, &next).map_err(|err| SettingsFailure::new("io_error", err))?;
    }

    let settings = effective_settings(base);
    Ok(SettingsSetSuccess {
        ok: true,
        command: "settings",
        action: "set",
        key: "appearance.font_size_px",
        value: serde_json::json!(value),
        changed,
        base_dir: base.to_string_lossy().to_string(),
        settings_path: path.to_string_lossy().to_string(),
        settings,
    })
}

/// Persist `appearance.theme` under the resolved `base`, then return a deterministic success value.
/// Mirrors [`set_font_size_px`]: validates the theme against [`SUPPORTED_THEMES`], creates
/// `<base>/settings` (`0700` on Unix), writes `settings.json` (`0600` on Unix) atomically, and re-reads
/// the effective settings for the response. Preserves any existing persisted `font_size_px` override
/// (or the default) so both appearance fields are written. Refuses to overwrite a foreign/unreadable
/// file. `changed` is `false` when the persisted theme already equals `theme`.
pub fn set_theme(base: &Path, theme: &str) -> Result<SettingsSetSuccess, SettingsFailure> {
    let theme =
        validate_theme(theme).map_err(|reason| SettingsFailure::new("bad_usage", reason))?;

    let path = settings_file_path(base);
    let (changed, mut next) = match load_persisted(&path) {
        LoadedSettings::Absent => (true, default_persisted()),
        LoadedSettings::Honored(existing) => (existing.appearance.theme != theme, existing),
        LoadedSettings::Warn(message) => {
            return Err(SettingsFailure::new(
                "settings_conflict",
                format!("refusing to overwrite settings: {message}"),
            ));
        }
    };

    if changed {
        next.appearance.theme = theme.clone();
        write_settings_atomic(base, &next).map_err(|err| SettingsFailure::new("io_error", err))?;
    }

    let settings = effective_settings(base);
    Ok(SettingsSetSuccess {
        ok: true,
        command: "settings",
        action: "set",
        key: "appearance.theme",
        value: serde_json::json!(theme),
        changed,
        base_dir: base.to_string_lossy().to_string(),
        settings_path: path.to_string_lossy().to_string(),
        settings,
    })
}

/// Which configurable chrome default a `settings set chrome.*` write targets. All four chrome defaults
/// now have explicit CLI enable/disable controls (`--top-tab-bar`/`--no-top-tab-bar`,
/// `--dashboard-status`/`--no-dashboard-status`, `--dashboard-panel`/`--no-dashboard-panel`,
/// `--picker-overlay`/`--no-picker-overlay`) and are configurable. The `PickerOverlay` default only
/// affects the foreground in-process renderer (`--no-run-renderer`/detached never resolve it true).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChromeDefaultKey {
    TopTabBar,
    DashboardStatus,
    DashboardPanel,
    PickerOverlay,
}

impl ChromeDefaultKey {
    /// The fully-qualified settings key string reported in the `set` success.
    fn key(self) -> &'static str {
        match self {
            ChromeDefaultKey::TopTabBar => "chrome.top_tab_bar_default",
            ChromeDefaultKey::DashboardStatus => "chrome.dashboard_status_default",
            ChromeDefaultKey::DashboardPanel => "chrome.dashboard_panel_default",
            ChromeDefaultKey::PickerOverlay => "chrome.picker_overlay_default",
        }
    }

    /// The existing override value on a persisted file (`None` when not set).
    fn current(self, chrome: &PersistedChrome) -> Option<bool> {
        match self {
            ChromeDefaultKey::TopTabBar => chrome.top_tab_bar_default,
            ChromeDefaultKey::DashboardStatus => chrome.dashboard_status_default,
            ChromeDefaultKey::DashboardPanel => chrome.dashboard_panel_default,
            ChromeDefaultKey::PickerOverlay => chrome.picker_overlay_default,
        }
    }

    /// Apply `value` as the override on a persisted file.
    fn apply(self, chrome: &mut PersistedChrome, value: bool) {
        match self {
            ChromeDefaultKey::TopTabBar => chrome.top_tab_bar_default = Some(value),
            ChromeDefaultKey::DashboardStatus => chrome.dashboard_status_default = Some(value),
            ChromeDefaultKey::DashboardPanel => chrome.dashboard_panel_default = Some(value),
            ChromeDefaultKey::PickerOverlay => chrome.picker_overlay_default = Some(value),
        }
    }
}

/// Persist a configurable `chrome.*_default` override under the resolved `base`, then return a
/// deterministic success value. Mirrors [`set_font_size_px`]/[`set_theme`]: a read-modify-write that
/// preserves every sibling override, creates `<base>/settings` (`0700` on Unix), writes `settings.json`
/// (`0600` on Unix) atomically, and re-reads the effective settings for the response. Refuses to
/// overwrite a foreign/unreadable file. `changed` is `false` when the persisted override already equals
/// `value` (an explicit `Some(value)`; an absent override differs from any explicit value, so setting a
/// chrome default to its built-in value still records it explicitly).
pub fn set_chrome_default(
    base: &Path,
    key: ChromeDefaultKey,
    value: bool,
) -> Result<SettingsSetSuccess, SettingsFailure> {
    let path = settings_file_path(base);
    let (changed, mut next) = match load_persisted(&path) {
        LoadedSettings::Absent => (true, default_persisted()),
        LoadedSettings::Honored(existing) => {
            (key.current(&existing.chrome) != Some(value), existing)
        }
        LoadedSettings::Warn(message) => {
            return Err(SettingsFailure::new(
                "settings_conflict",
                format!("refusing to overwrite settings: {message}"),
            ));
        }
    };

    if changed {
        key.apply(&mut next.chrome, value);
        write_settings_atomic(base, &next).map_err(|err| SettingsFailure::new("io_error", err))?;
    }

    let settings = effective_settings(base);
    Ok(SettingsSetSuccess {
        ok: true,
        command: "settings",
        action: "set",
        key: key.key(),
        value: serde_json::json!(value),
        changed,
        base_dir: base.to_string_lossy().to_string(),
        settings_path: path.to_string_lossy().to_string(),
        settings,
    })
}

/// The two persistable boolean `workspace.*` consent keys. `workspace.default_policy` is a validated
/// string and is handled separately by [`set_workspace_default_policy`]. The `safety.*` consent keys
/// are intentionally NOT represented here: they stay report-only constants so the destructive/consent
/// safety guards cannot be relaxed through the settings file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WorkspaceConsentKey {
    WorktreeRequiresConsent,
    RepoWriteRequiresConsent,
}

impl WorkspaceConsentKey {
    /// The fully-qualified settings key string reported in the `set` success.
    fn key(self) -> &'static str {
        match self {
            WorkspaceConsentKey::WorktreeRequiresConsent => "workspace.worktree_requires_consent",
            WorkspaceConsentKey::RepoWriteRequiresConsent => {
                "workspace.repo_write_requires_consent"
            }
        }
    }

    /// The existing override value on a persisted file (`None` when not set).
    fn current(self, workspace: &PersistedWorkspace) -> Option<bool> {
        match self {
            WorkspaceConsentKey::WorktreeRequiresConsent => workspace.worktree_requires_consent,
            WorkspaceConsentKey::RepoWriteRequiresConsent => workspace.repo_write_requires_consent,
        }
    }

    /// Apply `value` as the override on a persisted file.
    fn apply(self, workspace: &mut PersistedWorkspace, value: bool) {
        match self {
            WorkspaceConsentKey::WorktreeRequiresConsent => {
                workspace.worktree_requires_consent = Some(value)
            }
            WorkspaceConsentKey::RepoWriteRequiresConsent => {
                workspace.repo_write_requires_consent = Some(value)
            }
        }
    }
}

/// Persist a boolean `workspace.*_requires_consent` override under the resolved `base`, then return a
/// deterministic success value. Mirrors [`set_chrome_default`]: a read-modify-write that preserves every
/// sibling override, creates `<base>/settings` (`0700` on Unix), writes `settings.json` (`0600` on Unix)
/// atomically, and re-reads the effective settings for the response. Refuses to overwrite a
/// foreign/unreadable file. `changed` is `false` when the persisted override already equals `value`.
pub fn set_workspace_consent(
    base: &Path,
    key: WorkspaceConsentKey,
    value: bool,
) -> Result<SettingsSetSuccess, SettingsFailure> {
    let path = settings_file_path(base);
    let (changed, mut next) = match load_persisted(&path) {
        LoadedSettings::Absent => (true, default_persisted()),
        LoadedSettings::Honored(existing) => {
            (key.current(&existing.workspace) != Some(value), existing)
        }
        LoadedSettings::Warn(message) => {
            return Err(SettingsFailure::new(
                "settings_conflict",
                format!("refusing to overwrite settings: {message}"),
            ));
        }
    };

    if changed {
        key.apply(&mut next.workspace, value);
        write_settings_atomic(base, &next).map_err(|err| SettingsFailure::new("io_error", err))?;
    }

    let settings = effective_settings(base);
    Ok(SettingsSetSuccess {
        ok: true,
        command: "settings",
        action: "set",
        key: key.key(),
        value: serde_json::json!(value),
        changed,
        base_dir: base.to_string_lossy().to_string(),
        settings_path: path.to_string_lossy().to_string(),
        settings,
    })
}

/// Persist a `workspace.default_policy` override under the resolved `base`, then return a deterministic
/// success value. Mirrors [`set_theme`]: re-validates `policy` via [`validate_workspace_policy`]
/// (defense in depth — the CLI parser already validated), preserves every sibling override, creates
/// `<base>/settings` (`0700` on Unix), writes `settings.json` (`0600` on Unix) atomically, and re-reads
/// the effective settings for the response. Refuses to overwrite a foreign/unreadable file. `changed`
/// is `false` when the persisted override already equals the requested policy.
pub fn set_workspace_default_policy(
    base: &Path,
    policy: &str,
) -> Result<SettingsSetSuccess, SettingsFailure> {
    let policy = validate_workspace_policy(policy).map_err(|reason| {
        SettingsFailure::new("bad_usage", format!("invalid workspace policy: {reason}"))
    })?;
    let path = settings_file_path(base);
    let (changed, mut next) = match load_persisted(&path) {
        LoadedSettings::Absent => (true, default_persisted()),
        LoadedSettings::Honored(existing) => (
            existing.workspace.default_policy.as_deref() != Some(policy.as_str()),
            existing,
        ),
        LoadedSettings::Warn(message) => {
            return Err(SettingsFailure::new(
                "settings_conflict",
                format!("refusing to overwrite settings: {message}"),
            ));
        }
    };

    if changed {
        next.workspace.default_policy = Some(policy.clone());
        write_settings_atomic(base, &next).map_err(|err| SettingsFailure::new("io_error", err))?;
    }

    let settings = effective_settings(base);
    Ok(SettingsSetSuccess {
        ok: true,
        command: "settings",
        action: "set",
        key: "workspace.default_policy",
        value: serde_json::json!(policy),
        changed,
        base_dir: base.to_string_lossy().to_string(),
        settings_path: path.to_string_lossy().to_string(),
        settings,
    })
}

/// Persist a `shell.default_argv` override under the resolved `base`, then return a deterministic
/// success value. Mirrors [`set_font_size_px`]/[`set_theme`]: re-validates `argv` via
/// [`validate_shell_default_argv`] (defense in depth — the CLI parser already validated), creates
/// `<base>/settings` (`0700` on Unix), writes `settings.json` (`0600` on Unix) atomically, and re-reads
/// the effective settings for the response. Preserves every sibling override. Refuses to overwrite a
/// foreign/unreadable file. `changed` is `false` when the persisted argv already equals the requested
/// argv. The reported `value` is the JSON array of argv strings.
pub fn set_shell_default_argv(
    base: &Path,
    argv: &[String],
) -> Result<SettingsSetSuccess, SettingsFailure> {
    let argv = validate_shell_default_argv(&serde_json::json!(argv).to_string())
        .map_err(|reason| SettingsFailure::new("bad_usage", reason))?;

    let path = settings_file_path(base);
    let (changed, mut next) = match load_persisted(&path) {
        LoadedSettings::Absent => (true, default_persisted()),
        LoadedSettings::Honored(existing) => (
            existing.shell.default_argv.as_deref() != Some(argv.as_slice()),
            existing,
        ),
        LoadedSettings::Warn(message) => {
            return Err(SettingsFailure::new(
                "settings_conflict",
                format!("refusing to overwrite settings: {message}"),
            ));
        }
    };

    if changed {
        next.shell.default_argv = Some(argv.clone());
        write_settings_atomic(base, &next).map_err(|err| SettingsFailure::new("io_error", err))?;
    }

    let settings = effective_settings(base);
    Ok(SettingsSetSuccess {
        ok: true,
        command: "settings",
        action: "set",
        key: "shell.default_argv",
        value: serde_json::json!(argv),
        changed,
        base_dir: base.to_string_lossy().to_string(),
        settings_path: path.to_string_lossy().to_string(),
        settings,
    })
}

/// Which override a `settings reset` clears back to its built-in default. Covers the two appearance
/// overrides, the three configurable chrome defaults, and the shell default argv.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SettingsResetTarget {
    FontSizePx,
    Theme,
    TopTabBarDefault,
    DashboardStatusDefault,
    DashboardPanelDefault,
    PickerOverlayDefault,
    ShellDefaultArgv,
    WorkspaceDefaultPolicy,
    WorkspaceWorktreeRequiresConsent,
    WorkspaceRepoWriteRequiresConsent,
}

/// Reset one override under the resolved `base` back to its built-in default, preserving every
/// non-default sibling override. Local-only and mirrors [`set_font_size_px`]/[`set_theme`] output
/// (`action:"reset"`).
///
/// Behavior:
/// - No settings file: succeeds with `changed:false` and reports pure defaults (no file is created).
/// - Honored file: clear the target field (appearance back to its default, chrome override back to
///   `None`) while preserving every sibling. If the result is entirely at defaults (both appearance
///   fields default AND no chrome override recorded), delete `settings.json` (best-effort; a delete
///   error is `io_error`); otherwise rewrite the file atomically. `changed` is `false` when the target
///   already held its default.
/// - Foreign/unreadable file: refuses with `settings_conflict` (never overwrites or deletes it).
pub fn reset_appearance_setting(
    base: &Path,
    target: SettingsResetTarget,
) -> Result<SettingsSetSuccess, SettingsFailure> {
    let path = settings_file_path(base);

    let changed = match load_persisted(&path) {
        LoadedSettings::Absent => false,
        LoadedSettings::Honored(mut next) => {
            let changed = match target {
                SettingsResetTarget::FontSizePx => {
                    let was_default = next.appearance.font_size_px == DEFAULT_FONT_SIZE_PX;
                    next.appearance.font_size_px = DEFAULT_FONT_SIZE_PX;
                    !was_default
                }
                SettingsResetTarget::Theme => {
                    let was_default = next.appearance.theme == BUILT_IN_THEME;
                    next.appearance.theme = BUILT_IN_THEME.to_string();
                    !was_default
                }
                SettingsResetTarget::TopTabBarDefault => {
                    let was_default = next.chrome.top_tab_bar_default.is_none();
                    next.chrome.top_tab_bar_default = None;
                    !was_default
                }
                SettingsResetTarget::DashboardStatusDefault => {
                    let was_default = next.chrome.dashboard_status_default.is_none();
                    next.chrome.dashboard_status_default = None;
                    !was_default
                }
                SettingsResetTarget::DashboardPanelDefault => {
                    let was_default = next.chrome.dashboard_panel_default.is_none();
                    next.chrome.dashboard_panel_default = None;
                    !was_default
                }
                SettingsResetTarget::PickerOverlayDefault => {
                    let was_default = next.chrome.picker_overlay_default.is_none();
                    next.chrome.picker_overlay_default = None;
                    !was_default
                }
                SettingsResetTarget::ShellDefaultArgv => {
                    let was_default = next.shell.default_argv.is_none();
                    next.shell.default_argv = None;
                    !was_default
                }
                SettingsResetTarget::WorkspaceDefaultPolicy => {
                    let was_default = next.workspace.default_policy.is_none();
                    next.workspace.default_policy = None;
                    !was_default
                }
                SettingsResetTarget::WorkspaceWorktreeRequiresConsent => {
                    let was_default = next.workspace.worktree_requires_consent.is_none();
                    next.workspace.worktree_requires_consent = None;
                    !was_default
                }
                SettingsResetTarget::WorkspaceRepoWriteRequiresConsent => {
                    let was_default = next.workspace.repo_write_requires_consent.is_none();
                    next.workspace.repo_write_requires_consent = None;
                    !was_default
                }
            };

            if persisted_is_all_default(&next) {
                remove_settings_file(&path).map_err(|err| SettingsFailure::new("io_error", err))?;
            } else if changed {
                write_settings_atomic(base, &next)
                    .map_err(|err| SettingsFailure::new("io_error", err))?;
            }
            changed
        }
        LoadedSettings::Warn(message) => {
            return Err(SettingsFailure::new(
                "settings_conflict",
                format!("refusing to reset settings: {message}"),
            ));
        }
    };

    let (key, value) = match target {
        SettingsResetTarget::FontSizePx => (
            "appearance.font_size_px",
            serde_json::json!(DEFAULT_FONT_SIZE_PX),
        ),
        SettingsResetTarget::Theme => ("appearance.theme", serde_json::json!(BUILT_IN_THEME)),
        SettingsResetTarget::TopTabBarDefault => (
            "chrome.top_tab_bar_default",
            serde_json::json!(ChromeDefaults::built_in().top_tab_bar_default),
        ),
        SettingsResetTarget::DashboardStatusDefault => (
            "chrome.dashboard_status_default",
            serde_json::json!(ChromeDefaults::built_in().dashboard_status_default),
        ),
        SettingsResetTarget::DashboardPanelDefault => (
            "chrome.dashboard_panel_default",
            serde_json::json!(ChromeDefaults::built_in().dashboard_panel_default),
        ),
        SettingsResetTarget::PickerOverlayDefault => (
            "chrome.picker_overlay_default",
            serde_json::json!(ChromeDefaults::built_in().picker_overlay_default),
        ),
        SettingsResetTarget::ShellDefaultArgv => ("shell.default_argv", serde_json::Value::Null),
        SettingsResetTarget::WorkspaceDefaultPolicy => (
            "workspace.default_policy",
            serde_json::json!(WorkspaceDefaults::built_in().default_policy),
        ),
        SettingsResetTarget::WorkspaceWorktreeRequiresConsent => (
            "workspace.worktree_requires_consent",
            serde_json::json!(WorkspaceDefaults::built_in().worktree_requires_consent),
        ),
        SettingsResetTarget::WorkspaceRepoWriteRequiresConsent => (
            "workspace.repo_write_requires_consent",
            serde_json::json!(WorkspaceDefaults::built_in().repo_write_requires_consent),
        ),
    };

    let settings = effective_settings(base);
    Ok(SettingsSetSuccess {
        ok: true,
        command: "settings",
        action: "reset",
        key,
        value,
        changed,
        base_dir: base.to_string_lossy().to_string(),
        settings_path: path.to_string_lossy().to_string(),
        settings,
    })
}

/// Reset ALL persisted local settings back to built-in defaults under the resolved `base` by removing
/// the honored schema-v1 settings file. Local-only and mirrors the per-key reset output shape
/// (`action:"reset"`), but identifies the target as every setting via `key:"*"` and `value: null`.
///
/// Behavior:
/// - No settings file: succeeds with `changed:false` (nothing to remove; no file is created).
/// - Honored current-schema file: delete it and report `changed:true`. The containing settings
///   directory and any unrelated sibling files are left untouched.
/// - Foreign/unreadable file: refuses with `settings_conflict` and never removes it — the same
///   deterministic guard the per-key reset and `set` paths use, so reset-all never destroys a file it
///   cannot prove it owns.
///
/// The reported `settings` always reflect the post-reset state: built-in defaults for appearance,
/// chrome, and shell.
pub fn reset_all_settings(base: &Path) -> Result<SettingsSetSuccess, SettingsFailure> {
    let path = settings_file_path(base);

    let changed = match load_persisted(&path) {
        LoadedSettings::Absent => false,
        LoadedSettings::Honored(_) => {
            remove_settings_file(&path).map_err(|err| SettingsFailure::new("io_error", err))?;
            true
        }
        LoadedSettings::Warn(message) => {
            return Err(SettingsFailure::new(
                "settings_conflict",
                format!("refusing to reset settings: {message}"),
            ));
        }
    };

    let settings = effective_settings(base);
    Ok(SettingsSetSuccess {
        ok: true,
        command: "settings",
        action: "reset",
        key: "*",
        value: serde_json::Value::Null,
        changed,
        base_dir: base.to_string_lossy().to_string(),
        settings_path: path.to_string_lossy().to_string(),
        settings,
    })
}

/// Remove the settings file. A missing file is not an error (a no-op reset leaves nothing to delete);
/// any other error is surfaced. The containing settings directory is intentionally left in place.
fn remove_settings_file(path: &Path) -> Result<(), String> {
    match std::fs::remove_file(path) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(format!("remove settings file: {err}")),
    }
}

/// Atomically write the settings file: ensure `<base>/settings` exists (`0700` on Unix), write a
/// uniquely-named temp file in that dir, set it `0600` (Unix), then rename it over the destination.
/// Rename within the same directory is atomic on POSIX, so readers never observe a partial file.
fn write_settings_atomic(base: &Path, settings: &PersistedSettings) -> Result<(), String> {
    let dir = settings_dir(base);
    create_dir_private(&dir).map_err(|err| format!("create settings dir: {err}"))?;

    let mut body =
        serde_json::to_string_pretty(settings).map_err(|err| format!("serialize: {err}"))?;
    body.push('\n');

    let tmp = dir.join(format!("settings.json.tmp.{}", std::process::id()));
    write_file_private(&tmp, body.as_bytes()).map_err(|err| {
        let _ = std::fs::remove_file(&tmp);
        format!("write temp settings: {err}")
    })?;

    let dest = settings_file_path(base);
    std::fs::rename(&tmp, &dest).map_err(|err| {
        let _ = std::fs::remove_file(&tmp);
        format!("rename settings into place: {err}")
    })
}

/// Create a directory (and parents) with `0700` mode on Unix. On non-Unix the mode is the platform
/// default. Idempotent: succeeds if the directory already exists.
fn create_dir_private(dir: &Path) -> io::Result<()> {
    std::fs::create_dir_all(dir)?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700))?;
    }
    Ok(())
}

/// Write a file with `0600` mode on Unix (default mode elsewhere), truncating any existing content.
fn write_file_private(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::io::Write;
    #[cfg(unix)]
    let mut file = {
        use std::os::unix::fs::OpenOptionsExt;
        std::fs::OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?
    };
    #[cfg(not(unix))]
    let mut file = std::fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A unique scratch base dir under the OS temp dir; removed on drop.
    struct TempBase {
        path: PathBuf,
    }

    impl TempBase {
        fn new(tag: &str) -> Self {
            let path = std::env::temp_dir().join(format!(
                "maestro-settings-test-{}-{}-{:?}",
                tag,
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .unwrap()
                    .as_nanos()
            ));
            std::fs::create_dir_all(&path).expect("create temp base");
            TempBase { path }
        }
    }

    impl Drop for TempBase {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.path);
        }
    }

    #[test]
    fn effective_settings_reports_deterministic_defaults_and_echoes_base() {
        let tmp = TempBase::new("defaults");
        let s = effective_settings(&tmp.path);

        assert_eq!(s.source, "defaults");
        assert_eq!(s.base_dir, tmp.path.to_string_lossy());
        assert_eq!(
            s.settings_path,
            settings_file_path(&tmp.path).to_string_lossy()
        );
        assert!(s.settings_warning.is_none());

        assert!(s.chrome.top_tab_bar_default);
        assert!(s.chrome.dashboard_status_default);
        assert!(!s.chrome.dashboard_panel_default);
        assert!(!s.chrome.picker_overlay_default);

        assert_eq!(s.workspace.default_policy, "scratch_cwd");
        assert!(s.workspace.worktree_requires_consent);
        assert!(s.workspace.repo_write_requires_consent);

        assert!(s.safety.private_dev_socket_by_default);
        assert!(s.safety.destructive_worktree_cleanup_requires_confirm);
        assert!(s.safety.repo_write_requires_explicit_consent);

        assert_eq!(s.appearance.theme, "built_in_dark");
        assert_eq!(s.appearance.font_size_px, 16);
    }

    #[test]
    fn effective_settings_policy_is_independent_of_base() {
        let a = TempBase::new("indep-a");
        let b = TempBase::new("indep-b");
        let sa = effective_settings(&a.path);
        let sb = effective_settings(&b.path);
        // Only base_dir/settings_path differ; every policy field is identical across calls.
        assert_ne!(sa.base_dir, sb.base_dir);
        assert_eq!(sa.chrome, sb.chrome);
        assert_eq!(sa.workspace, sb.workspace);
        assert_eq!(sa.safety, sb.safety);
        assert_eq!(sa.appearance, sb.appearance);
    }

    #[test]
    fn no_file_keeps_default_font_size() {
        let tmp = TempBase::new("no-file");
        let s = effective_settings(&tmp.path);
        assert_eq!(s.source, "defaults");
        assert_eq!(s.appearance.font_size_px, DEFAULT_FONT_SIZE_PX);
        assert!(!settings_file_path(&tmp.path).exists());
    }

    #[test]
    fn set_creates_file_and_merges_override() {
        let tmp = TempBase::new("set-merge");
        let res = set_font_size_px(&tmp.path, 18).expect("set succeeds");
        assert!(res.ok);
        assert!(res.changed);
        assert_eq!(res.value, serde_json::json!(18));
        assert_eq!(res.key, "appearance.font_size_px");

        let file = settings_file_path(&tmp.path);
        assert!(file.exists(), "settings/settings.json should exist");

        // Effective settings now report the override and keep all other defaults unchanged.
        let s = effective_settings(&tmp.path);
        assert_eq!(s.source, "defaults+overrides");
        assert_eq!(s.appearance.font_size_px, 18);
        assert_eq!(s.appearance.theme, "built_in_dark");
        assert_eq!(s.chrome, ChromeDefaults::built_in());
        assert_eq!(s.workspace, WorkspaceDefaults::built_in());
        assert_eq!(s.safety, SafetyDefaults::built_in());
    }

    #[test]
    fn set_same_value_reports_unchanged() {
        let tmp = TempBase::new("set-same");
        let first = set_font_size_px(&tmp.path, 20).expect("first set");
        assert!(first.changed);
        let second = set_font_size_px(&tmp.path, 20).expect("second set");
        assert!(!second.changed);
        assert_eq!(second.value, serde_json::json!(20));
        assert_eq!(second.settings.appearance.font_size_px, 20);
    }

    #[test]
    fn set_rejects_out_of_range_font_size() {
        let tmp = TempBase::new("set-range");
        let too_small = set_font_size_px(&tmp.path, 9).expect_err("9 rejected");
        assert_eq!(too_small.error_kind, "bad_usage");
        let too_big = set_font_size_px(&tmp.path, 33).expect_err("33 rejected");
        assert_eq!(too_big.error_kind, "bad_usage");
        // A rejected set never creates the file.
        assert!(!settings_file_path(&tmp.path).exists());
    }

    #[test]
    fn validate_font_size_px_enforces_inclusive_range() {
        assert!(validate_font_size_px(10).is_ok());
        assert!(validate_font_size_px(32).is_ok());
        assert!(validate_font_size_px(16).is_ok());
        assert!(validate_font_size_px(9).is_err());
        assert!(validate_font_size_px(33).is_err());
    }

    #[test]
    fn foreign_schema_is_ignored_by_show_and_not_overwritten_by_set() {
        let tmp = TempBase::new("foreign");
        let dir = settings_dir(&tmp.path);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            settings_file_path(&tmp.path),
            r#"{"schema_version":99,"appearance":{"font_size_px":18}}"#,
        )
        .unwrap();

        // show ignores it: defaults + warning, file untouched.
        let s = effective_settings(&tmp.path);
        assert_eq!(s.source, "defaults");
        assert_eq!(s.appearance.font_size_px, DEFAULT_FONT_SIZE_PX);
        assert!(s.settings_warning.is_some());

        // set refuses to clobber it.
        let err = set_font_size_px(&tmp.path, 16).expect_err("foreign file blocks set");
        assert_eq!(err.error_kind, "settings_conflict");
    }

    #[cfg(unix)]
    #[test]
    fn set_writes_private_dir_and_file_modes() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempBase::new("modes");
        set_font_size_px(&tmp.path, 14).expect("set");

        let dir_mode = std::fs::metadata(settings_dir(&tmp.path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        let file_mode = std::fs::metadata(settings_file_path(&tmp.path))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(dir_mode, 0o700, "settings dir should be 0700");
        assert_eq!(file_mode, 0o600, "settings file should be 0600");
    }

    #[test]
    fn effective_settings_serializes_to_stable_snake_case_json() {
        let tmp = TempBase::new("json");
        let s = effective_settings(&tmp.path);
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&s).expect("serialize")).expect("parse");

        assert_eq!(v["source"], serde_json::json!("defaults"));
        assert_eq!(v["base_dir"], serde_json::json!(tmp.path.to_string_lossy()));
        assert_eq!(v["chrome"]["top_tab_bar_default"], serde_json::json!(true));
        assert_eq!(
            v["chrome"]["dashboard_status_default"],
            serde_json::json!(true)
        );
        assert_eq!(
            v["chrome"]["dashboard_panel_default"],
            serde_json::json!(false)
        );
        assert_eq!(
            v["chrome"]["picker_overlay_default"],
            serde_json::json!(false)
        );
        assert_eq!(
            v["workspace"]["default_policy"],
            serde_json::json!("scratch_cwd")
        );
        assert_eq!(
            v["workspace"]["worktree_requires_consent"],
            serde_json::json!(true)
        );
        assert_eq!(
            v["workspace"]["repo_write_requires_consent"],
            serde_json::json!(true)
        );
        assert_eq!(
            v["safety"]["private_dev_socket_by_default"],
            serde_json::json!(true)
        );
        assert_eq!(
            v["safety"]["destructive_worktree_cleanup_requires_confirm"],
            serde_json::json!(true)
        );
        assert_eq!(
            v["safety"]["repo_write_requires_explicit_consent"],
            serde_json::json!(true)
        );
        assert_eq!(v["appearance"]["theme"], serde_json::json!("built_in_dark"));
        assert_eq!(v["appearance"]["font_size_px"], serde_json::json!(16));
    }

    #[test]
    fn validate_theme_accepts_supported_and_rejects_unknown() {
        assert_eq!(validate_theme("built_in_dark").unwrap(), "built_in_dark");
        assert_eq!(
            validate_theme("high_contrast_dark").unwrap(),
            "high_contrast_dark"
        );
        assert!(validate_theme("solarized").is_err());
        assert!(validate_theme("").is_err());
        assert!(validate_theme("BUILT_IN_DARK").is_err());
    }

    #[test]
    fn old_font_size_only_file_loads_with_default_theme() {
        let tmp = TempBase::new("old-font-only");
        let dir = settings_dir(&tmp.path);
        std::fs::create_dir_all(&dir).unwrap();
        // A schema-version-1 file written before `theme` existed: only `font_size_px`.
        std::fs::write(
            settings_file_path(&tmp.path),
            r#"{"schema_version":1,"appearance":{"font_size_px":22}}"#,
        )
        .unwrap();

        let s = effective_settings(&tmp.path);
        assert_eq!(s.source, "defaults+overrides");
        assert_eq!(s.appearance.font_size_px, 22);
        assert_eq!(s.appearance.theme, "built_in_dark");
        assert!(s.settings_warning.is_none());
    }

    #[test]
    fn set_theme_persists_and_reports_override() {
        let tmp = TempBase::new("set-theme");
        let res = set_theme(&tmp.path, "high_contrast_dark").expect("set theme succeeds");
        assert!(res.ok);
        assert!(res.changed);
        assert_eq!(res.value, serde_json::json!("high_contrast_dark"));
        assert_eq!(res.key, "appearance.theme");

        let s = effective_settings(&tmp.path);
        assert_eq!(s.source, "defaults+overrides");
        assert_eq!(s.appearance.theme, "high_contrast_dark");
        // The unchanged font size carries the default.
        assert_eq!(s.appearance.font_size_px, DEFAULT_FONT_SIZE_PX);
    }

    #[test]
    fn set_theme_rejects_unknown_theme() {
        let tmp = TempBase::new("set-theme-bad");
        let err = set_theme(&tmp.path, "neon").expect_err("unknown theme rejected");
        assert_eq!(err.error_kind, "bad_usage");
        assert!(!settings_file_path(&tmp.path).exists());
    }

    #[test]
    fn set_theme_preserves_existing_font_size_override() {
        let tmp = TempBase::new("theme-preserves-font");
        set_font_size_px(&tmp.path, 24).expect("set font size");
        set_theme(&tmp.path, "high_contrast_dark").expect("set theme");

        let s = effective_settings(&tmp.path);
        assert_eq!(s.appearance.font_size_px, 24);
        assert_eq!(s.appearance.theme, "high_contrast_dark");
    }

    #[test]
    fn set_font_size_preserves_existing_theme_override() {
        let tmp = TempBase::new("font-preserves-theme");
        set_theme(&tmp.path, "high_contrast_dark").expect("set theme");
        set_font_size_px(&tmp.path, 28).expect("set font size");

        let s = effective_settings(&tmp.path);
        assert_eq!(s.appearance.theme, "high_contrast_dark");
        assert_eq!(s.appearance.font_size_px, 28);
    }

    #[test]
    fn set_theme_same_value_reports_unchanged() {
        let tmp = TempBase::new("theme-same");
        let first = set_theme(&tmp.path, "high_contrast_dark").expect("first");
        assert!(first.changed);
        let second = set_theme(&tmp.path, "high_contrast_dark").expect("second");
        assert!(!second.changed);
    }

    #[test]
    fn set_theme_refuses_foreign_file() {
        let tmp = TempBase::new("theme-foreign");
        let dir = settings_dir(&tmp.path);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            settings_file_path(&tmp.path),
            r#"{"schema_version":99,"appearance":{"font_size_px":18}}"#,
        )
        .unwrap();
        let err = set_theme(&tmp.path, "high_contrast_dark").expect_err("foreign blocks set");
        assert_eq!(err.error_kind, "settings_conflict");
    }

    #[test]
    fn reset_with_no_file_is_noop_and_reports_defaults() {
        let tmp = TempBase::new("reset-no-file");
        let res = reset_appearance_setting(&tmp.path, SettingsResetTarget::FontSizePx)
            .expect("reset succeeds");
        assert!(res.ok);
        assert!(!res.changed, "no-op reset reports changed:false");
        assert_eq!(res.action, "reset");
        assert_eq!(res.key, "appearance.font_size_px");
        assert_eq!(res.value, serde_json::json!(DEFAULT_FONT_SIZE_PX));
        // No file was created; effective settings are pure defaults.
        assert!(!settings_file_path(&tmp.path).exists());
        assert_eq!(res.settings.source, "defaults");
        assert_eq!(res.settings.appearance.font_size_px, DEFAULT_FONT_SIZE_PX);
        assert_eq!(res.settings.appearance.theme, BUILT_IN_THEME);
    }

    #[test]
    fn reset_font_size_preserves_non_default_theme() {
        let tmp = TempBase::new("reset-font-keeps-theme");
        set_font_size_px(&tmp.path, 18).expect("set font size");
        set_theme(&tmp.path, "high_contrast_dark").expect("set theme");

        let res = reset_appearance_setting(&tmp.path, SettingsResetTarget::FontSizePx)
            .expect("reset succeeds");
        assert!(res.changed);
        assert_eq!(res.value, serde_json::json!(DEFAULT_FONT_SIZE_PX));

        // File remains (theme is still non-default); font is back to default, theme preserved.
        assert!(settings_file_path(&tmp.path).exists());
        let s = effective_settings(&tmp.path);
        assert_eq!(s.source, "defaults+overrides");
        assert_eq!(s.appearance.font_size_px, DEFAULT_FONT_SIZE_PX);
        assert_eq!(s.appearance.theme, "high_contrast_dark");
    }

    #[test]
    fn reset_theme_preserves_non_default_font_size() {
        let tmp = TempBase::new("reset-theme-keeps-font");
        set_font_size_px(&tmp.path, 18).expect("set font size");
        set_theme(&tmp.path, "high_contrast_dark").expect("set theme");

        let res = reset_appearance_setting(&tmp.path, SettingsResetTarget::Theme)
            .expect("reset succeeds");
        assert!(res.changed);
        assert_eq!(res.key, "appearance.theme");
        assert_eq!(res.value, serde_json::json!(BUILT_IN_THEME));

        // File remains (font is still non-default); theme is back to default, font preserved.
        assert!(settings_file_path(&tmp.path).exists());
        let s = effective_settings(&tmp.path);
        assert_eq!(s.source, "defaults+overrides");
        assert_eq!(s.appearance.font_size_px, 18);
        assert_eq!(s.appearance.theme, BUILT_IN_THEME);
    }

    #[test]
    fn reset_last_override_deletes_file_and_reports_defaults() {
        let tmp = TempBase::new("reset-last-override");
        // Only a font-size override; theme already default.
        set_font_size_px(&tmp.path, 18).expect("set font size");
        assert!(settings_file_path(&tmp.path).exists());

        let res = reset_appearance_setting(&tmp.path, SettingsResetTarget::FontSizePx)
            .expect("reset succeeds");
        assert!(res.changed);
        // Both fields are now defaults, so the file is removed (not rewritten all-default).
        assert!(!settings_file_path(&tmp.path).exists());
        assert_eq!(res.settings.source, "defaults");
        assert_eq!(res.settings.appearance.font_size_px, DEFAULT_FONT_SIZE_PX);
        assert_eq!(res.settings.appearance.theme, BUILT_IN_THEME);
        // The containing settings dir is intentionally left in place.
        assert!(settings_dir(&tmp.path).exists());
    }

    #[test]
    fn reset_refuses_foreign_file() {
        let tmp = TempBase::new("reset-foreign");
        let dir = settings_dir(&tmp.path);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            settings_file_path(&tmp.path),
            r#"{"schema_version":99,"appearance":{"font_size_px":18}}"#,
        )
        .unwrap();

        let err = reset_appearance_setting(&tmp.path, SettingsResetTarget::FontSizePx)
            .expect_err("foreign file blocks reset");
        assert_eq!(err.error_kind, "settings_conflict");
        // The foreign file is left untouched.
        assert!(settings_file_path(&tmp.path).exists());
    }

    #[test]
    fn settings_reset_all_removes_honored_file_and_reports_changed() {
        let tmp = TempBase::new("reset-all-honored");
        set_font_size_px(&tmp.path, 18).expect("set font size");
        assert!(settings_file_path(&tmp.path).exists());

        let res = reset_all_settings(&tmp.path).expect("reset-all succeeds");
        assert!(res.ok);
        assert!(res.changed);
        assert_eq!(res.action, "reset");
        assert_eq!(res.key, "*");
        assert_eq!(res.value, serde_json::Value::Null);
        // The honored file is removed; the containing dir is left in place.
        assert!(!settings_file_path(&tmp.path).exists());
        assert!(settings_dir(&tmp.path).exists());
        assert_eq!(res.settings.source, "defaults");
    }

    #[test]
    fn settings_reset_all_on_absent_file_reports_unchanged() {
        let tmp = TempBase::new("reset-all-absent");
        assert!(!settings_file_path(&tmp.path).exists());

        let res = reset_all_settings(&tmp.path).expect("reset-all succeeds");
        assert!(res.ok);
        assert!(!res.changed);
        assert_eq!(res.key, "*");
        assert!(!settings_file_path(&tmp.path).exists());
        assert_eq!(res.settings.source, "defaults");
    }

    #[test]
    fn settings_reset_all_restores_all_built_in_defaults() {
        let tmp = TempBase::new("reset-all-multi");
        // Override across appearance, chrome, and shell.
        set_font_size_px(&tmp.path, 22).expect("set font size");
        set_theme(&tmp.path, "high_contrast_dark").expect("set theme");
        set_chrome_default(&tmp.path, ChromeDefaultKey::TopTabBar, false).expect("set chrome");
        set_shell_default_argv(&tmp.path, &["/bin/zsh".to_string(), "-l".to_string()])
            .expect("set shell");

        let res = reset_all_settings(&tmp.path).expect("reset-all succeeds");
        assert!(res.changed);

        // Every reported family is back to its built-in default.
        let s = res.settings;
        assert_eq!(s.source, "defaults");
        assert_eq!(s.appearance, AppearanceDefaults::built_in());
        assert_eq!(s.chrome, ChromeDefaults::built_in());
        assert_eq!(s.shell, ShellDefaults::built_in());
        assert!(!settings_file_path(&tmp.path).exists());
    }

    #[test]
    fn settings_reset_all_preserves_unrelated_sibling_files_and_dirs() {
        let tmp = TempBase::new("reset-all-siblings");
        set_font_size_px(&tmp.path, 18).expect("set font size");
        let dir = settings_dir(&tmp.path);
        let sibling_file = dir.join("unrelated.txt");
        let sibling_dir = dir.join("subdir");
        std::fs::write(&sibling_file, b"keep me").unwrap();
        std::fs::create_dir_all(&sibling_dir).unwrap();

        let res = reset_all_settings(&tmp.path).expect("reset-all succeeds");
        assert!(res.changed);
        assert!(!settings_file_path(&tmp.path).exists());
        // Only the settings file is removed; unrelated siblings survive.
        assert!(sibling_file.exists());
        assert!(sibling_dir.exists());
    }

    #[test]
    fn settings_reset_all_refuses_foreign_file() {
        let tmp = TempBase::new("reset-all-foreign");
        let dir = settings_dir(&tmp.path);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            settings_file_path(&tmp.path),
            r#"{"schema_version":99,"appearance":{"font_size_px":18}}"#,
        )
        .unwrap();

        let err = reset_all_settings(&tmp.path).expect_err("foreign file blocks reset-all");
        assert_eq!(err.error_kind, "settings_conflict");
        // The foreign file is left untouched.
        assert!(settings_file_path(&tmp.path).exists());
    }

    #[test]
    fn set_chrome_top_tab_bar_default_persists_and_merges() {
        let tmp = TempBase::new("set-chrome-top");
        let res = set_chrome_default(&tmp.path, ChromeDefaultKey::TopTabBar, false)
            .expect("set succeeds");
        assert!(res.ok);
        assert!(res.changed);
        assert_eq!(res.key, "chrome.top_tab_bar_default");
        assert_eq!(res.value, serde_json::json!(false));
        assert!(settings_file_path(&tmp.path).exists());

        let s = effective_settings(&tmp.path);
        assert_eq!(s.source, "defaults+overrides");
        assert!(!s.chrome.top_tab_bar_default);
        // The other chrome defaults stay at their built-in values.
        assert!(s.chrome.dashboard_status_default);
        assert!(!s.chrome.dashboard_panel_default);
        assert!(!s.chrome.picker_overlay_default);
        // Appearance is untouched.
        assert_eq!(s.appearance.font_size_px, DEFAULT_FONT_SIZE_PX);
        assert_eq!(s.appearance.theme, BUILT_IN_THEME);
    }

    #[test]
    fn set_chrome_dashboard_status_default_persists() {
        let tmp = TempBase::new("set-chrome-status");
        set_chrome_default(&tmp.path, ChromeDefaultKey::DashboardStatus, false).expect("set");
        let s = effective_settings(&tmp.path);
        assert!(!s.chrome.dashboard_status_default);
        assert!(s.chrome.top_tab_bar_default);
    }

    #[test]
    fn set_chrome_dashboard_panel_default_persists_and_resets() {
        let tmp = TempBase::new("set-chrome-panel");
        // Built-in default is OFF; pin it ON.
        let res =
            set_chrome_default(&tmp.path, ChromeDefaultKey::DashboardPanel, true).expect("set");
        assert!(res.changed);
        assert_eq!(res.key, "chrome.dashboard_panel_default");
        assert_eq!(res.value, serde_json::json!(true));
        let s = effective_settings(&tmp.path);
        assert!(s.chrome.dashboard_panel_default);
        // Siblings stay at their defaults.
        assert!(s.chrome.top_tab_bar_default);
        assert!(s.chrome.dashboard_status_default);

        // Reset clears only this override; it is the last one, so the file is removed.
        let reset = reset_appearance_setting(&tmp.path, SettingsResetTarget::DashboardPanelDefault)
            .expect("reset succeeds");
        assert!(reset.changed);
        assert_eq!(reset.key, "chrome.dashboard_panel_default");
        assert_eq!(reset.value, serde_json::json!(false));
        assert!(!settings_file_path(&tmp.path).exists());
        assert!(!reset.settings.chrome.dashboard_panel_default);
    }

    #[test]
    fn set_chrome_default_same_value_reports_unchanged() {
        let tmp = TempBase::new("set-chrome-same");
        let first =
            set_chrome_default(&tmp.path, ChromeDefaultKey::TopTabBar, false).expect("first");
        assert!(first.changed);
        let second =
            set_chrome_default(&tmp.path, ChromeDefaultKey::TopTabBar, false).expect("second");
        assert!(!second.changed);
    }

    #[test]
    fn set_chrome_default_preserves_appearance_overrides() {
        let tmp = TempBase::new("chrome-preserves-appearance");
        set_font_size_px(&tmp.path, 24).expect("set font");
        set_theme(&tmp.path, "high_contrast_dark").expect("set theme");
        set_chrome_default(&tmp.path, ChromeDefaultKey::TopTabBar, false).expect("set chrome");

        let s = effective_settings(&tmp.path);
        assert_eq!(s.appearance.font_size_px, 24);
        assert_eq!(s.appearance.theme, "high_contrast_dark");
        assert!(!s.chrome.top_tab_bar_default);
    }

    #[test]
    fn reset_chrome_default_preserves_other_overrides() {
        let tmp = TempBase::new("reset-chrome-keeps");
        set_chrome_default(&tmp.path, ChromeDefaultKey::TopTabBar, false).expect("set top");
        set_chrome_default(&tmp.path, ChromeDefaultKey::DashboardStatus, false)
            .expect("set status");

        let res = reset_appearance_setting(&tmp.path, SettingsResetTarget::TopTabBarDefault)
            .expect("reset succeeds");
        assert!(res.changed);
        assert_eq!(res.key, "chrome.top_tab_bar_default");
        assert_eq!(res.value, serde_json::json!(true));

        // File remains (status override is still non-default); top-bar back to default.
        assert!(settings_file_path(&tmp.path).exists());
        let s = effective_settings(&tmp.path);
        assert!(s.chrome.top_tab_bar_default);
        assert!(!s.chrome.dashboard_status_default);
    }

    #[test]
    fn reset_last_chrome_override_deletes_file() {
        let tmp = TempBase::new("reset-chrome-last");
        set_chrome_default(&tmp.path, ChromeDefaultKey::DashboardStatus, false).expect("set");
        assert!(settings_file_path(&tmp.path).exists());

        let res = reset_appearance_setting(&tmp.path, SettingsResetTarget::DashboardStatusDefault)
            .expect("reset succeeds");
        assert!(res.changed);
        // Every override is now default, so the file is removed.
        assert!(!settings_file_path(&tmp.path).exists());
        assert_eq!(res.settings.source, "defaults");
        assert!(res.settings.chrome.dashboard_status_default);
    }

    // ---- workspace.* ------------------------------------------------------------------------

    #[test]
    fn workspace_defaults_when_no_file() {
        let tmp = TempBase::new("workspace-defaults");
        let s = effective_settings(&tmp.path);
        assert_eq!(s.source, "defaults");
        assert_eq!(s.workspace.default_policy, "scratch_cwd");
        assert!(s.workspace.worktree_requires_consent);
        assert!(s.workspace.repo_write_requires_consent);
    }

    #[test]
    fn validate_workspace_policy_accepts_supported() {
        for p in SUPPORTED_WORKSPACE_POLICIES {
            assert_eq!(validate_workspace_policy(p).expect("accepted"), *p);
        }
    }

    #[test]
    fn validate_workspace_policy_rejects_unknown() {
        validate_workspace_policy("yolo").expect_err("unknown policy rejected");
        validate_workspace_policy("").expect_err("empty policy rejected");
    }

    #[test]
    fn set_workspace_default_policy_persists_and_reports_override() {
        let tmp = TempBase::new("set-ws-policy");
        let res = set_workspace_default_policy(&tmp.path, "worktree").expect("set policy");
        assert!(res.ok);
        assert!(res.changed);
        assert_eq!(res.key, "workspace.default_policy");
        assert_eq!(res.value, serde_json::json!("worktree"));

        let s = effective_settings(&tmp.path);
        assert_eq!(s.source, "defaults+overrides");
        assert_eq!(s.workspace.default_policy, "worktree");
        // Consents keep their built-in defaults.
        assert!(s.workspace.worktree_requires_consent);
        assert!(s.workspace.repo_write_requires_consent);
    }

    #[test]
    fn set_workspace_default_policy_rejects_unknown_policy() {
        let tmp = TempBase::new("set-ws-policy-bad");
        let err =
            set_workspace_default_policy(&tmp.path, "nope").expect_err("unknown policy rejected");
        assert_eq!(err.error_kind, "bad_usage");
        assert!(!settings_file_path(&tmp.path).exists());
    }

    #[test]
    fn set_workspace_default_policy_same_value_reports_unchanged() {
        let tmp = TempBase::new("set-ws-policy-same");
        let first = set_workspace_default_policy(&tmp.path, "repo_write").expect("first");
        assert!(first.changed);
        let second = set_workspace_default_policy(&tmp.path, "repo_write").expect("second");
        assert!(!second.changed);
    }

    #[test]
    fn set_workspace_default_policy_refuses_foreign_file() {
        let tmp = TempBase::new("ws-policy-foreign");
        std::fs::create_dir_all(settings_dir(&tmp.path)).unwrap();
        std::fs::write(
            settings_file_path(&tmp.path),
            r#"{"schema_version":99,"workspace":{"default_policy":"worktree"}}"#,
        )
        .unwrap();
        let err =
            set_workspace_default_policy(&tmp.path, "repo_write").expect_err("foreign blocks set");
        assert_eq!(err.error_kind, "settings_conflict");
    }

    #[test]
    fn set_workspace_consent_persists_and_reports_override() {
        let tmp = TempBase::new("set-ws-consent");
        let res = set_workspace_consent(
            &tmp.path,
            WorkspaceConsentKey::WorktreeRequiresConsent,
            false,
        )
        .expect("set consent");
        assert!(res.ok);
        assert!(res.changed);
        assert_eq!(res.key, "workspace.worktree_requires_consent");
        assert_eq!(res.value, serde_json::json!(false));

        let s = effective_settings(&tmp.path);
        assert!(!s.workspace.worktree_requires_consent);
        // Other consent + policy keep defaults.
        assert!(s.workspace.repo_write_requires_consent);
        assert_eq!(s.workspace.default_policy, "scratch_cwd");
    }

    #[test]
    fn set_workspace_consent_same_value_reports_unchanged() {
        let tmp = TempBase::new("set-ws-consent-same");
        let first = set_workspace_consent(
            &tmp.path,
            WorkspaceConsentKey::RepoWriteRequiresConsent,
            false,
        )
        .expect("first");
        assert!(first.changed);
        let second = set_workspace_consent(
            &tmp.path,
            WorkspaceConsentKey::RepoWriteRequiresConsent,
            false,
        )
        .expect("second");
        assert!(!second.changed);
    }

    #[test]
    fn workspace_overrides_are_independent() {
        let tmp = TempBase::new("ws-independent");
        set_workspace_default_policy(&tmp.path, "worktree").expect("policy");
        set_workspace_consent(
            &tmp.path,
            WorkspaceConsentKey::WorktreeRequiresConsent,
            false,
        )
        .expect("worktree consent");
        set_workspace_consent(
            &tmp.path,
            WorkspaceConsentKey::RepoWriteRequiresConsent,
            false,
        )
        .expect("repo consent");

        let s = effective_settings(&tmp.path);
        assert_eq!(s.workspace.default_policy, "worktree");
        assert!(!s.workspace.worktree_requires_consent);
        assert!(!s.workspace.repo_write_requires_consent);
    }

    #[test]
    fn workspace_overrides_preserve_appearance_overrides() {
        let tmp = TempBase::new("ws-preserves-appearance");
        set_font_size_px(&tmp.path, 24).expect("set font");
        set_theme(&tmp.path, "high_contrast_dark").expect("set theme");
        set_workspace_default_policy(&tmp.path, "worktree").expect("set policy");

        let s = effective_settings(&tmp.path);
        assert_eq!(s.appearance.font_size_px, 24);
        assert_eq!(s.appearance.theme, "high_contrast_dark");
        assert_eq!(s.workspace.default_policy, "worktree");
    }

    #[test]
    fn reset_workspace_policy_preserves_other_overrides() {
        let tmp = TempBase::new("reset-ws-policy-keeps");
        set_workspace_default_policy(&tmp.path, "worktree").expect("set policy");
        set_workspace_consent(
            &tmp.path,
            WorkspaceConsentKey::WorktreeRequiresConsent,
            false,
        )
        .expect("set consent");

        let res = reset_appearance_setting(&tmp.path, SettingsResetTarget::WorkspaceDefaultPolicy)
            .expect("reset succeeds");
        assert!(res.changed);
        assert_eq!(res.key, "workspace.default_policy");
        assert_eq!(res.value, serde_json::json!("scratch_cwd"));

        // File remains (consent override still non-default); policy back to default.
        assert!(settings_file_path(&tmp.path).exists());
        let s = effective_settings(&tmp.path);
        assert_eq!(s.workspace.default_policy, "scratch_cwd");
        assert!(!s.workspace.worktree_requires_consent);
    }

    #[test]
    fn reset_last_workspace_override_deletes_file() {
        let tmp = TempBase::new("reset-ws-last");
        set_workspace_consent(
            &tmp.path,
            WorkspaceConsentKey::RepoWriteRequiresConsent,
            false,
        )
        .expect("set");
        assert!(settings_file_path(&tmp.path).exists());

        let res = reset_appearance_setting(
            &tmp.path,
            SettingsResetTarget::WorkspaceRepoWriteRequiresConsent,
        )
        .expect("reset succeeds");
        assert!(res.changed);
        assert!(!settings_file_path(&tmp.path).exists());
        assert_eq!(res.settings.source, "defaults");
        assert!(res.settings.workspace.repo_write_requires_consent);
    }

    #[test]
    fn workspace_section_absent_deserializes_to_defaults() {
        let tmp = TempBase::new("ws-backward-compat");
        std::fs::create_dir_all(settings_dir(&tmp.path)).unwrap();
        // A file written before workspace settings existed has no `workspace` section.
        std::fs::write(
            settings_file_path(&tmp.path),
            r#"{"schema_version":1,"appearance":{"font_size_px":20}}"#,
        )
        .unwrap();

        let s = effective_settings(&tmp.path);
        assert_eq!(s.appearance.font_size_px, 20);
        assert_eq!(s.workspace.default_policy, "scratch_cwd");
        assert!(s.workspace.worktree_requires_consent);
        assert!(s.workspace.repo_write_requires_consent);
    }

    #[test]
    fn persisted_is_all_default_false_with_workspace_override() {
        let mut p = default_persisted();
        assert!(persisted_is_all_default(&p));
        p.workspace.default_policy = Some("worktree".to_string());
        assert!(!persisted_is_all_default(&p));
    }

    // ---- shell.default_argv -----------------------------------------------------------------

    #[test]
    fn shell_default_argv_absent_by_default() {
        let tmp = TempBase::new("shell-default-absent");
        let s = effective_settings(&tmp.path);
        assert!(s.shell.default_argv.is_none());
        assert!(settings_shell_default_argv(&s).is_none());
    }

    #[test]
    fn set_shell_default_argv_persists_and_show_reports_it() {
        let tmp = TempBase::new("shell-default-set");
        let argv = vec!["/bin/zsh".to_string(), "-l".to_string()];
        let res = set_shell_default_argv(&tmp.path, &argv).expect("set");
        assert!(res.changed);
        assert_eq!(res.key, "shell.default_argv");
        assert_eq!(res.value, serde_json::json!(["/bin/zsh", "-l"]));

        let s = effective_settings(&tmp.path);
        assert_eq!(s.source, "defaults+overrides");
        assert_eq!(s.shell.default_argv.as_deref(), Some(argv.as_slice()));
        assert_eq!(settings_shell_default_argv(&s), Some(argv.as_slice()));
    }

    #[test]
    fn set_shell_default_argv_same_value_reports_unchanged() {
        let tmp = TempBase::new("shell-default-same");
        let argv = vec!["/bin/zsh".to_string()];
        let first = set_shell_default_argv(&tmp.path, &argv).expect("first");
        assert!(first.changed);
        let second = set_shell_default_argv(&tmp.path, &argv).expect("second");
        assert!(!second.changed);
    }

    #[test]
    fn set_shell_default_argv_preserves_existing_appearance_override() {
        let tmp = TempBase::new("shell-default-preserves");
        set_theme(&tmp.path, "high_contrast_dark").expect("set theme");
        set_shell_default_argv(&tmp.path, &["/bin/bash".to_string()]).expect("set argv");

        let s = effective_settings(&tmp.path);
        assert_eq!(s.appearance.theme, "high_contrast_dark");
        assert_eq!(
            s.shell.default_argv.as_deref(),
            Some(["/bin/bash".to_string()].as_slice())
        );
    }

    #[test]
    fn reset_shell_default_argv_preserves_other_overrides() {
        let tmp = TempBase::new("shell-default-reset-keeps");
        set_theme(&tmp.path, "high_contrast_dark").expect("set theme");
        set_shell_default_argv(&tmp.path, &["/bin/bash".to_string()]).expect("set argv");

        let res = reset_appearance_setting(&tmp.path, SettingsResetTarget::ShellDefaultArgv)
            .expect("reset succeeds");
        assert!(res.changed);
        assert_eq!(res.key, "shell.default_argv");
        assert_eq!(res.value, serde_json::Value::Null);

        // File remains (theme still non-default); argv cleared, theme preserved.
        assert!(settings_file_path(&tmp.path).exists());
        let s = effective_settings(&tmp.path);
        assert!(s.shell.default_argv.is_none());
        assert_eq!(s.appearance.theme, "high_contrast_dark");
    }

    #[test]
    fn reset_last_shell_default_argv_override_deletes_file() {
        let tmp = TempBase::new("shell-default-reset-last");
        set_shell_default_argv(&tmp.path, &["/bin/bash".to_string()]).expect("set argv");
        assert!(settings_file_path(&tmp.path).exists());

        let res = reset_appearance_setting(&tmp.path, SettingsResetTarget::ShellDefaultArgv)
            .expect("reset succeeds");
        assert!(res.changed);
        // The only override is gone, so the file is removed.
        assert!(!settings_file_path(&tmp.path).exists());
        assert_eq!(res.settings.source, "defaults");
        assert!(res.settings.shell.default_argv.is_none());
    }

    #[test]
    fn set_shell_default_argv_refuses_foreign_file() {
        let tmp = TempBase::new("shell-default-foreign");
        let dir = settings_dir(&tmp.path);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(
            settings_file_path(&tmp.path),
            r#"{"schema_version":99,"appearance":{"font_size_px":18}}"#,
        )
        .unwrap();
        let err = set_shell_default_argv(&tmp.path, &["/bin/bash".to_string()])
            .expect_err("foreign blocks set");
        assert_eq!(err.error_kind, "settings_conflict");
    }

    #[test]
    fn validate_shell_default_argv_accepts_valid_array() {
        let argv = validate_shell_default_argv(r#"["/bin/zsh","-l"]"#).expect("valid");
        assert_eq!(argv, vec!["/bin/zsh".to_string(), "-l".to_string()]);
    }

    #[test]
    fn validate_shell_default_argv_rejects_malformed_json() {
        assert!(validate_shell_default_argv("not json").is_err());
        assert!(validate_shell_default_argv(r#"["/bin/zsh""#).is_err());
    }

    #[test]
    fn validate_shell_default_argv_rejects_non_array() {
        assert!(validate_shell_default_argv(r#"{"cmd":"zsh"}"#).is_err());
        assert!(validate_shell_default_argv(r#""zsh""#).is_err());
        assert!(validate_shell_default_argv("42").is_err());
        assert!(validate_shell_default_argv("null").is_err());
    }

    #[test]
    fn validate_shell_default_argv_rejects_empty_array() {
        assert!(validate_shell_default_argv("[]").is_err());
    }

    #[test]
    fn validate_shell_default_argv_rejects_non_string_member() {
        assert!(validate_shell_default_argv(r#"["/bin/zsh",1]"#).is_err());
        assert!(validate_shell_default_argv(r#"["/bin/zsh",["-l"]]"#).is_err());
        assert!(validate_shell_default_argv(r#"["/bin/zsh",null]"#).is_err());
    }

    #[test]
    fn validate_shell_default_argv_rejects_empty_command_name() {
        assert!(validate_shell_default_argv(r#"[""]"#).is_err());
        assert!(validate_shell_default_argv(r#"["   ","-l"]"#).is_err());
    }

    #[test]
    fn validate_shell_default_argv_allows_empty_later_args() {
        // Only the first element (command name) must be non-empty after trim.
        let argv = validate_shell_default_argv(r#"["/bin/zsh",""]"#).expect("valid");
        assert_eq!(argv, vec!["/bin/zsh".to_string(), String::new()]);
    }

    fn sample_settings() -> EffectiveSettings {
        EffectiveSettings {
            source: "defaults".to_string(),
            base_dir: "/tmp/base".to_string(),
            settings_path: "/tmp/base/settings.json".to_string(),
            settings_warning: None,
            chrome: ChromeDefaults::built_in(),
            workspace: WorkspaceDefaults::built_in(),
            safety: SafetyDefaults::built_in(),
            appearance: AppearanceDefaults::built_in(),
            shell: ShellDefaults { default_argv: None },
        }
    }

    #[test]
    fn settings_panel_default_build_is_deterministic_and_stable() {
        let panel = build_settings_panel_lines(&sample_settings());

        assert_eq!(panel.title, "Settings");
        assert_eq!(panel.line_count, panel.lines.len());
        assert_eq!(
            panel.summary,
            "source=defaults theme=built_in_dark font_size_px=16 shell_argv=unset"
        );

        // Stable category order with the source/path block first, no warning line by default.
        assert_eq!(panel.lines[0], "source: defaults");
        assert_eq!(panel.lines[1], "base_dir: /tmp/base");
        assert_eq!(panel.lines[2], "settings_path: /tmp/base/settings.json");
        assert_eq!(panel.lines[3], "theme: built_in_dark");
        assert_eq!(panel.lines[4], "font_size_px: 16");
        assert_eq!(panel.lines[5], "chrome.top_tab_bar: true");
        assert_eq!(panel.lines[6], "chrome.dashboard_status: true");
        assert_eq!(panel.lines[7], "chrome.dashboard_panel: false");
        assert_eq!(panel.lines[8], "chrome.picker_overlay: false");
        assert_eq!(
            panel.lines[9],
            "shell.default_argv: (unset; $SHELL/sh fallback)"
        );
        assert_eq!(panel.lines[10], "workspace.default_policy: scratch_cwd");
        assert_eq!(panel.lines[11], "workspace.worktree_requires_consent: true");
        assert_eq!(
            panel.lines[12],
            "workspace.repo_write_requires_consent: true"
        );
        assert_eq!(
            panel.lines[13],
            "safety.private_dev_socket_by_default: true"
        );
        assert_eq!(
            panel.lines[14],
            "safety.destructive_worktree_cleanup_requires_confirm: true"
        );
        assert_eq!(
            panel.lines[15],
            "safety.repo_write_requires_explicit_consent: true"
        );

        // Every line is ASCII and single-row.
        for line in &panel.lines {
            assert!(line.is_ascii());
            assert!(!line.contains('\n'));
        }

        // Determinism: building twice yields the same projection.
        assert_eq!(build_settings_panel_lines(&sample_settings()), panel);
    }

    #[test]
    fn settings_panel_reflects_overridden_appearance_chrome_and_shell() {
        let mut s = sample_settings();
        s.source = "settings.json".to_string();
        s.appearance.theme = "high_contrast_dark".to_string();
        s.appearance.font_size_px = 22;
        s.chrome.top_tab_bar_default = false;
        s.chrome.picker_overlay_default = true;
        s.shell.default_argv = Some(vec!["/bin/zsh".to_string(), "-l".to_string()]);

        let panel = build_settings_panel_lines(&s);

        assert!(panel
            .lines
            .contains(&"theme: high_contrast_dark".to_string()));
        assert!(panel.lines.contains(&"font_size_px: 22".to_string()));
        assert!(panel
            .lines
            .contains(&"chrome.top_tab_bar: false".to_string()));
        assert!(panel
            .lines
            .contains(&"chrome.picker_overlay: true".to_string()));
        assert!(panel
            .lines
            .contains(&r#"shell.default_argv: ["/bin/zsh", "-l"]"#.to_string()));
        assert_eq!(
            panel.summary,
            "source=settings.json theme=high_contrast_dark font_size_px=22 shell_argv=set"
        );
    }

    #[test]
    fn settings_panel_renders_empty_argv_override_as_unset_fallback() {
        let mut s = sample_settings();
        s.shell.default_argv = Some(Vec::new());

        let panel = build_settings_panel_lines(&s);

        assert!(panel
            .lines
            .contains(&"shell.default_argv: (unset; $SHELL/sh fallback)".to_string()));
        assert!(panel.summary.ends_with("shell_argv=unset"));
    }

    #[test]
    fn settings_panel_includes_and_sanitizes_warning() {
        let mut s = sample_settings();
        s.settings_warning = Some("bad\tfile\nsecond line".to_string());

        let panel = build_settings_panel_lines(&s);

        // Warning appears right after the source/path block.
        assert_eq!(panel.lines[3], "warning: bad file second line");
        for line in &panel.lines {
            assert!(line.is_ascii());
            assert!(!line.contains('\n'));
        }
    }

    #[test]
    fn settings_panel_truncates_overlong_warning() {
        let mut s = sample_settings();
        s.settings_warning = Some("x".repeat(500));

        let panel = build_settings_panel_lines(&s);
        let warning_value = panel.lines[3].strip_prefix("warning: ").unwrap();

        assert_eq!(warning_value.chars().count(), SETTINGS_PANEL_LINE_MAX);
        assert!(warning_value.ends_with("..."));
    }

    #[test]
    fn settings_panel_control_chars_cannot_create_extra_lines() {
        let mut s = sample_settings();
        s.base_dir = "a\nb\rc\x07d".to_string();
        s.settings_warning = Some("line1\nline2\nline3".to_string());
        s.shell.default_argv = Some(vec!["cmd\ninjected".to_string()]);

        let panel = build_settings_panel_lines(&s);

        // No control chars survive; no panel line carries a newline.
        for line in &panel.lines {
            assert!(line.is_ascii());
            assert!(!line.chars().any(|c| c.is_control()));
        }
        // The total newline count across the whole projection is zero.
        let joined = panel.lines.join("\n");
        assert_eq!(joined.matches('\n').count(), panel.lines.len() - 1);
        assert_eq!(panel.lines[1], "base_dir: a b c d");
    }

    #[test]
    fn settings_panel_forces_non_ascii_to_placeholder() {
        let mut s = sample_settings();
        s.appearance.theme = "thème-é".to_string();

        let panel = build_settings_panel_lines(&s);

        assert!(panel.lines.contains(&"theme: th?me-?".to_string()));
        for line in &panel.lines {
            assert!(line.is_ascii());
        }
    }

    #[test]
    fn settings_panel_serializes_to_expected_json_shape() {
        let panel = build_settings_panel_lines(&sample_settings());
        let json = serde_json::to_string(&panel).expect("serialize");

        assert!(json.contains("\"title\":\"Settings\""));
        assert!(json.contains("\"summary\":"));
        assert!(json.contains("\"lines\":["));
        assert!(json.contains("\"line_count\":"));
        // Backward-additive structured rows.
        assert!(json.contains("\"rows\":["));
        assert!(json.contains("\"setting_key\":\"appearance.theme\""));
        assert!(json.contains("\"editable\":true"));
        assert!(json.contains("\"editable\":false"));
    }

    /// The exact set of `setting_key` values the row model is allowed to expose, matching the
    /// existing `settings set`/`settings reset` CLI keys.
    const EXPECTED_EDITABLE_KEYS: &[&str] = &[
        "appearance.theme",
        "appearance.font_size_px",
        "chrome.top_tab_bar_default",
        "chrome.dashboard_status_default",
        "chrome.dashboard_panel_default",
        "chrome.picker_overlay_default",
        "shell.default_argv",
        "workspace.default_policy",
        "workspace.worktree_requires_consent",
        "workspace.repo_write_requires_consent",
    ];

    #[test]
    fn settings_panel_rows_mirror_lines_one_to_one() {
        let panel = build_settings_panel_lines(&sample_settings());

        // One row per visible line, in the same order; line_count tracks lines, not rows here.
        assert_eq!(panel.rows.len(), panel.lines.len());
        assert_eq!(panel.line_count, panel.lines.len());

        // Each row's value is the suffix of its paired visible line ("{id-ish}: {value}").
        for (row, line) in panel.rows.iter().zip(panel.lines.iter()) {
            let suffix = format!(": {}", row.value);
            assert!(
                line.ends_with(&suffix),
                "row {:?} value {:?} not the tail of line {:?}",
                row.id,
                row.value,
                line
            );
        }
    }

    #[test]
    fn settings_panel_rows_have_stable_first_source_rows() {
        let panel = build_settings_panel_lines(&sample_settings());

        assert_eq!(panel.rows[0].id, "source");
        assert_eq!(panel.rows[0].category, "source");
        assert_eq!(panel.rows[0].value, "defaults");
        assert_eq!(panel.rows[0].setting_key, None);
        assert!(!panel.rows[0].editable);

        assert_eq!(panel.rows[1].id, "base_dir");
        assert_eq!(panel.rows[1].value, "/tmp/base");
        assert!(!panel.rows[1].editable);

        assert_eq!(panel.rows[2].id, "settings_path");
        assert_eq!(panel.rows[2].value, "/tmp/base/settings.json");
        assert!(!panel.rows[2].editable);
    }

    #[test]
    fn settings_panel_editable_rows_carry_exact_setting_keys() {
        let panel = build_settings_panel_lines(&sample_settings());

        let editable_keys: Vec<&str> = panel
            .rows
            .iter()
            .filter(|r| r.editable)
            .map(|r| r.setting_key.expect("editable row has a key"))
            .collect();

        assert_eq!(editable_keys, EXPECTED_EDITABLE_KEYS);
    }

    #[test]
    fn settings_panel_report_only_rows_are_non_editable_with_no_key() {
        let mut s = sample_settings();
        s.settings_warning = Some("oops".to_string());
        let panel = build_settings_panel_lines(&s);

        let report_ids = [
            "source",
            "base_dir",
            "settings_path",
            "warning",
            "safety.private_dev_socket_by_default",
            "safety.destructive_worktree_cleanup_requires_confirm",
            "safety.repo_write_requires_explicit_consent",
        ];
        for id in report_ids {
            let row = panel.rows.iter().find(|r| r.id == id).expect("row present");
            assert_eq!(row.setting_key, None, "{id} must have no setting_key");
            assert!(!row.editable, "{id} must not be editable");
        }
    }

    #[test]
    fn settings_panel_row_editable_iff_has_setting_key() {
        let mut s = sample_settings();
        s.settings_warning = Some("warn".to_string());
        s.shell.default_argv = Some(vec!["/bin/zsh".to_string(), "-l".to_string()]);
        let panel = build_settings_panel_lines(&s);

        for row in &panel.rows {
            assert_eq!(
                row.editable,
                row.setting_key.is_some(),
                "row {:?} violates editable<=>setting_key invariant",
                row.id
            );
        }
    }

    #[test]
    fn settings_panel_shell_argv_row_stays_editable_when_unset() {
        // The fallback line is report-style text, but `shell.default_argv` is a settable key, so
        // its row must remain editable with the real key even when no argv is configured.
        let panel = build_settings_panel_lines(&sample_settings());
        let row = panel
            .rows
            .iter()
            .find(|r| r.id == "shell.default_argv")
            .expect("shell row present");
        assert_eq!(row.value, "(unset; $SHELL/sh fallback)");
        assert_eq!(row.setting_key, Some("shell.default_argv"));
        assert!(row.editable);
    }

    #[test]
    fn settings_panel_rows_are_sanitized_and_bounded() {
        let mut s = sample_settings();
        s.base_dir = "a\nb\rc\x07d".to_string();
        s.appearance.theme = "thème-é".to_string();
        s.settings_warning = Some("w".repeat(500));
        let panel = build_settings_panel_lines(&s);

        for row in &panel.rows {
            assert!(row.value.is_ascii(), "row {:?} value not ASCII", row.id);
            assert!(
                !row.value.chars().any(|c| c.is_control()),
                "row {:?} value has control chars",
                row.id
            );
            assert!(
                row.value.chars().count() <= SETTINGS_PANEL_LINE_MAX,
                "row {:?} value exceeds bound",
                row.id
            );
        }

        // Control chars collapse to spaces; non-ASCII becomes '?'; overlong is truncated.
        let base = panel.rows.iter().find(|r| r.id == "base_dir").unwrap();
        assert_eq!(base.value, "a b c d");
        let theme = panel.rows.iter().find(|r| r.id == "theme").unwrap();
        assert_eq!(theme.value, "th?me-?");
        let warning = panel.rows.iter().find(|r| r.id == "warning").unwrap();
        assert_eq!(warning.value.chars().count(), SETTINGS_PANEL_LINE_MAX);
        assert!(warning.value.ends_with("..."));
    }
}
