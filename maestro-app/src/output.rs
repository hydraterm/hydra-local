//! Output-surface helpers for the maestro-app harness: the user-visible window title and overlay
//! status labels, plus the structured launch/attach/window JSON output DTOs printed to stdout/stderr.
//! Pure formatting and plain serializable envelopes — nothing here starts a daemon/session, touches
//! the store, or talks to the renderer.

use serde::Serialize;

use crate::{
    CommandPalette, DashboardPanelLines, SettingsPanelLines, TabStripModel, WindowTabJson,
    WindowViewTabJson, TITLE_MAX_LEN,
};

/// The default foreground window title for a session: `Hydra - <session-id>`. Pure.
pub fn default_window_title(session_id: &str) -> String {
    format!("Hydra - {session_id}")
}

/// Validate a user-supplied `--title`: non-empty, no control characters, and bounded length
/// ([`TITLE_MAX_LEN`] characters). Returns a human-readable reason on rejection. Pure.
pub fn validate_window_title(title: &str) -> Result<(), String> {
    if title.is_empty() {
        return Err("--title must not be empty".to_string());
    }
    if title.chars().any(|c| c.is_control()) {
        return Err("--title must not contain control characters".to_string());
    }
    let len = title.chars().count();
    if len > TITLE_MAX_LEN {
        return Err(format!(
            "--title is too long ({len} characters; limit is {TITLE_MAX_LEN})"
        ));
    }
    Ok(())
}

/// The effective foreground window title: the validated explicit `--title` if given, else the
/// default `Hydra - <session-id>`. Pure; assumes any explicit title already passed
/// [`validate_window_title`] at parse time.
pub fn effective_window_title(explicit: Option<&str>, session_id: &str) -> String {
    match explicit {
        Some(t) => t.to_string(),
        None => default_window_title(session_id),
    }
}

/// The app-owned status label shown in the renderer's bottom overlay: `Hydra · <session-id>`.
/// Pure. Distinct from the native window title (which uses an ASCII hyphen); the overlay strip
/// uses a middot to read as a compact identity. This label has no user override.
pub fn status_label(session_id: &str) -> String {
    format!("Hydra · {session_id}")
}

/// The effective foreground window title for `attach-tab`: an explicit validated `--title` if given,
/// else the tab's persisted title (`Hydra - <tab title>`) when non-empty, else the session id
/// (`Hydra - <session-id>`). Pure; assumes any explicit title already passed
/// [`validate_window_title`] at parse time. The tab title falls back to the session id when blank so
/// a tab with an empty persisted title never yields a bare `Hydra - ` window name.
pub fn attach_tab_window_title(
    explicit: Option<&str>,
    tab_title: Option<&str>,
    session_id: &str,
) -> String {
    if let Some(t) = explicit {
        return t.to_string();
    }
    match tab_title {
        Some(t) if !t.trim().is_empty() => format!("Hydra - {t}"),
        _ => format!("Hydra - {session_id}"),
    }
}

/// The app-owned status label shown in the renderer's bottom overlay for `attach-tab`:
/// `Hydra · <window-id>/<tab-id> · <session-id>`. Pure. This is a compact identity that ties the
/// visible surface back to the persisted layout coordinate it was opened from. There is no user
/// override for this label.
pub fn attach_tab_status_label(window_id: &str, tab_id: &str, session_id: &str) -> String {
    format!("Hydra · {window_id}/{tab_id} · {session_id}")
}

/// The success JSON printed to stdout on a completed launch. The original contract fields
/// (`ok`, `command`, `socket_path`, `session_id`, `status`, `generation`, `renderer_started`,
/// `renderer_command`) are preserved; the lifecycle fields (`daemon_started`, `daemon_kept`,
/// `renderer_detached`, `renderer_exit_status`) make the lifecycle policy explicit on the wire.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LaunchSuccess {
    pub ok: bool,
    pub command: &'static str,
    pub socket_path: String,
    pub session_id: String,
    /// "live" | "exited" | "unknown".
    pub status: String,
    /// Last known generation string, or null.
    pub generation: Option<String>,
    /// The effective foreground window title (`Hydra - <session-id>` or an explicit `--title`).
    /// Reported in all modes; in `--no-run-renderer` it is accepted and reported but has no GUI.
    pub window_title: String,
    /// The app-owned overlay status label (`Hydra · <session-id>`). Reported in all modes; in
    /// `--no-run-renderer` it is computed and reported but has no GUI overlay.
    pub status_label: String,
    pub renderer_started: bool,
    pub renderer_command: Vec<String>,
    /// True if THIS process spawned the daemon (false if it reused an already-running one).
    pub daemon_started: bool,
    /// True if the daemon is left running after the app finishes (always true for a reused daemon).
    pub daemon_kept: bool,
    /// True if the renderer was launched fire-and-forget (not waited on).
    pub renderer_detached: bool,
    /// The renderer's exit status as a string (e.g. "exit 0" / "signal 15"), or null when the
    /// renderer was not launched or was detached (not awaited).
    pub renderer_exit_status: Option<String>,
    /// The opt-in child-process log directory (`--log-dir`), or null when not provided. When set,
    /// spawned daemon and detached renderer stdout/stderr were captured to deterministic files under
    /// this path (see [`child_log_path`]); the in-process foreground renderer is not a child process
    /// and is not captured here.
    pub log_dir: Option<String>,
    /// True when `--record-window` recorded this launched session into a window layout. False (the
    /// default) for a normal launch. Backward-compatible: existing consumers that ignore this field
    /// see the same shape they always did.
    pub window_recorded: bool,
    /// The window id the session was recorded under, or null when not recorded.
    pub window_id: Option<String>,
    /// The tab id the session was recorded under, or null when not recorded.
    pub tab_id: Option<String>,
    /// The renderer glyph point size resolved from the persisted `appearance.font_size_px` setting.
    /// Reported in ALL modes (including `--no-run-renderer`), so settings consumption is testable
    /// without a GUI. The in-process foreground renderer is launched with this size; in
    /// `--detach-renderer` the detached child still uses the historical renderer default while this
    /// field reports the effective app setting. Backward-additive — defaults to the built-in size.
    pub renderer_font_size_px: u32,
    /// The renderer theme id resolved from the persisted `appearance.theme` setting (`built_in_dark`
    /// by default). Reported in ALL modes (including `--no-run-renderer`), so settings consumption is
    /// testable without a GUI. The in-process foreground renderer is launched with this theme and the
    /// detached child inherits it via `--theme`. Backward-additive — defaults to the built-in theme.
    pub renderer_theme: String,
    /// True when the resolved chrome opted the foreground launch window into drawing the native top
    /// tab bar (`--top-tab-bar`, or the foreground default-on policy unless `--no-top-tab-bar`).
    /// Reported so the parse/JSON can be inspected (including with `--no-run-renderer`). Detached mode
    /// resolves this to `false`. Backward-additive — defaults to `false`.
    pub top_tab_bar: bool,
    /// True when `--new-tab-default-shell` opted this launch into the explicit dev/test new-tab
    /// policy that lets the `+` action spawn a default shell tab. Reported so the parsed launch path
    /// can be verified with `--no-run-renderer`. Backward-additive — defaults to `false`.
    pub new_tab_default_shell: bool,
    /// The read-only file preview opened by `--file-preview <path>`, or null when the flag was
    /// absent. Reported in ALL modes (including `--no-run-renderer`), so the requested path and its
    /// bounded read status are inspectable without opening a GUI. Backward-additive — `null` keeps
    /// every existing launch output shape unchanged. Default `None`.
    pub file_preview: Option<FilePreviewReport>,
}

/// The launch-time, read-only file-preview report stamped onto [`LaunchSuccess`] when
/// `--file-preview <path>` was given. It carries the requested path and the bounded reader's
/// truncation flags, so `--no-run-renderer` consumers can prove the file was read (and how it was
/// bounded) without a GUI. It deliberately does NOT echo the file body — only the metadata.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct FilePreviewReport {
    /// The display path exactly as supplied to `--file-preview`.
    pub path: String,
    /// The number of bounded body lines the reader produced.
    pub line_count: usize,
    /// True when the file was larger than the read cap so only a byte-prefix was previewed.
    pub truncated_bytes: bool,
    /// True when more lines existed than the line cap and the tail was dropped.
    pub truncated_lines: bool,
    /// True when at least one line exceeded the width cap and was cut.
    pub truncated_line_width: bool,
}

impl LaunchSuccess {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        socket_path: String,
        session_id: String,
        status: String,
        generation: Option<String>,
        window_title: String,
        status_label: String,
        renderer_started: bool,
        renderer_command: Vec<String>,
        daemon_started: bool,
        daemon_kept: bool,
        renderer_detached: bool,
        renderer_exit_status: Option<String>,
        log_dir: Option<String>,
    ) -> Self {
        LaunchSuccess {
            ok: true,
            command: "launch",
            socket_path,
            session_id,
            status,
            generation,
            window_title,
            status_label,
            renderer_started,
            renderer_command,
            daemon_started,
            daemon_kept,
            renderer_detached,
            renderer_exit_status,
            log_dir,
            window_recorded: false,
            window_id: None,
            tab_id: None,
            renderer_font_size_px: crate::settings::DEFAULT_FONT_SIZE_PX,
            renderer_theme: crate::settings::BUILT_IN_THEME.to_string(),
            top_tab_bar: false,
            new_tab_default_shell: false,
            file_preview: None,
        }
    }

    /// Stamp the read-only file-preview report onto the success value. `main.rs` calls this after the
    /// bounded reader produced a preview for `--file-preview <path>`, so the requested path and its
    /// truncation status are reported in every mode (including `--no-run-renderer`).
    pub fn with_file_preview(mut self, file_preview: FilePreviewReport) -> Self {
        self.file_preview = Some(file_preview);
        self
    }

    /// Stamp the resolved top-tab-bar chrome and the explicit new-tab-default-shell policy presence
    /// onto the success value. `main.rs` calls this with the resolved `chrome.top_tab_bar` and whether
    /// `--new-tab-default-shell` was given, so the parsed launch chrome/new-tab path is inspectable in
    /// the success JSON (including under `--no-run-renderer`).
    pub fn with_chrome(mut self, top_tab_bar: bool, new_tab_default_shell: bool) -> Self {
        self.top_tab_bar = top_tab_bar;
        self.new_tab_default_shell = new_tab_default_shell;
        self
    }

    /// Stamp the backward-compatible window-recording fields onto the success value. `main.rs` calls
    /// this after a successful `--record-window` recording with the persisted window/tab ids.
    pub fn with_window_record(mut self, window_id: String, tab_id: String) -> Self {
        self.window_recorded = true;
        self.window_id = Some(window_id);
        self.tab_id = Some(tab_id);
        self
    }

    /// Stamp the renderer font size resolved from persisted settings. `main.rs` calls this with
    /// [`crate::settings::renderer_font_size_px`] of the effective settings for the launch base.
    pub fn with_renderer_font_size_px(mut self, font_size_px: u32) -> Self {
        self.renderer_font_size_px = font_size_px;
        self
    }

    /// Stamp the renderer theme id resolved from persisted settings. `main.rs` calls this with
    /// [`crate::settings::renderer_theme_id`] of the effective settings for the launch base.
    pub fn with_renderer_theme(mut self, theme: impl Into<String>) -> Self {
        self.renderer_theme = theme.into();
        self
    }
}

/// The failure JSON printed to stderr on any error. Field set matches the contract (`ok:false`,
/// `error_kind`, `message`); `command` is included for symmetry with the success shape.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct LaunchFailure {
    pub ok: bool,
    pub command: &'static str,
    pub error_kind: String,
    pub message: String,
}

impl LaunchFailure {
    pub fn new(error_kind: impl Into<String>, message: impl Into<String>) -> Self {
        LaunchFailure {
            ok: false,
            command: "launch",
            error_kind: error_kind.into(),
            message: message.into(),
        }
    }
}

/// The success JSON printed to stdout by `maestro-app attach-tab`: exactly one structured value
/// describing which persisted window/tab was opened, the session it resolved to, and the renderer/
/// daemon lifecycle outcome. A dedicated DTO (not [`LaunchSuccess`]) so the window/tab coordinate is
/// unambiguous and `command: "attach-tab"` reads honestly.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AttachTabSuccess {
    pub ok: bool,
    pub command: &'static str,
    pub base: String,
    pub window_id: String,
    pub tab_id: String,
    /// The session id resolved from the selected tab in the persisted layout.
    pub session_id: String,
    pub socket_path: String,
    /// The effective foreground window title (see [`attach_tab_window_title`]).
    pub window_title: String,
    /// The app-owned overlay status label (see [`attach_tab_status_label`]).
    pub status_label: String,
    pub renderer_started: bool,
    pub renderer_command: Vec<String>,
    /// True if THIS process spawned the daemon (false if it reused an already-running one).
    pub daemon_started: bool,
    /// True if the daemon is left running after the app finishes (always true for a reused daemon).
    pub daemon_kept: bool,
    /// True if the renderer was launched fire-and-forget (`--detach-renderer`).
    pub renderer_detached: bool,
    /// The renderer's exit status as a string, or null when not launched or detached (not awaited).
    pub renderer_exit_status: Option<String>,
    /// The opt-in child-process log directory (`--log-dir`), or null when not provided.
    pub log_dir: Option<String>,
    /// The full persisted-window tab-strip model (every tab, index-ordered, selected tab marked
    /// active). Carried so future Rust-native chrome and tests consume the same shape the GUI will
    /// render. Nothing draws it yet.
    pub tab_strip: TabStripModel,
    /// True if `--top-tab-bar` opted the foreground renderer into drawing the native top tab bar.
    /// Reported so the parse/JSON can be inspected (including with `--no-run-renderer`). Default
    /// `false`.
    pub top_tab_bar: bool,
    /// The computed read-only dashboard panel lines when `--dashboard-panel` opted the foreground
    /// renderer into drawing top chrome, else null. Reported so `--no-run-renderer` can prove the
    /// panel was computed without opening a GUI. Default `None`.
    pub dashboard_panel: Option<DashboardPanelLines>,
    /// The computed read-only settings panel lines when `--settings-panel` opted the foreground
    /// renderer into drawing the in-app settings surface, else null. Reported so `--no-run-renderer`
    /// can prove the panel was computed without opening a GUI. Carries the same DTO shape produced by
    /// `settings show --panel-lines`. Mutually exclusive with `dashboard_panel` (the parser rejects the
    /// explicit combination). Default `None`.
    pub settings_panel: Option<SettingsPanelLines>,
    /// The renderer glyph point size resolved from the persisted `appearance.font_size_px` setting.
    /// Reported in ALL modes (including `--no-run-renderer`); the in-process foreground renderer is
    /// launched with this size while a `--detach-renderer` child stays on the historical renderer
    /// default. Backward-additive — defaults to the built-in size.
    pub renderer_font_size_px: u32,
    /// The renderer theme id resolved from the persisted `appearance.theme` setting (`built_in_dark`
    /// by default). Reported in ALL modes (including `--no-run-renderer`); the in-process foreground
    /// renderer is launched with this theme and a `--detach-renderer` child inherits it via `--theme`.
    /// Backward-additive — defaults to the built-in theme.
    pub renderer_theme: String,
    /// The computed command-palette catalog/query/preview DTO when `--command-palette` opted the
    /// foreground renderer into showing the static, display-only command-palette overlay, else null.
    /// Carries the same shape produced by `command-palette --list ... --preview` (always with the
    /// preview model attached). Reported in ALL modes so `--no-run-renderer` can prove the palette was
    /// computed without opening a GUI. Backward-additive — `null` when the flag is absent keeps every
    /// existing attach-tab output byte-identical. Default `None`.
    pub command_palette: Option<CommandPalette>,
    /// The metadata (path + line count + truncation flags, never the file body) of the read-only file
    /// preview requested via `--file-preview <path>`, else null. Reported in ALL modes so
    /// `--no-run-renderer` can prove the bounded file was read without opening a GUI; the foreground
    /// in-process renderer additionally paints the bounded body via one `SetFilePreview` command.
    /// Backward-additive — `null` when the flag is absent keeps every existing attach-tab output
    /// byte-identical. Default `None`.
    pub file_preview: Option<FilePreviewReport>,
}

impl AttachTabSuccess {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        base: String,
        window_id: String,
        tab_id: String,
        session_id: String,
        socket_path: String,
        window_title: String,
        status_label: String,
        renderer_started: bool,
        renderer_command: Vec<String>,
        daemon_started: bool,
        daemon_kept: bool,
        renderer_detached: bool,
        renderer_exit_status: Option<String>,
        log_dir: Option<String>,
        tab_strip: TabStripModel,
        top_tab_bar: bool,
        dashboard_panel: Option<DashboardPanelLines>,
        settings_panel: Option<SettingsPanelLines>,
    ) -> Self {
        AttachTabSuccess {
            ok: true,
            command: "attach-tab",
            base,
            window_id,
            tab_id,
            session_id,
            socket_path,
            window_title,
            status_label,
            renderer_started,
            renderer_command,
            daemon_started,
            daemon_kept,
            renderer_detached,
            renderer_exit_status,
            log_dir,
            tab_strip,
            top_tab_bar,
            dashboard_panel,
            settings_panel,
            renderer_font_size_px: crate::settings::DEFAULT_FONT_SIZE_PX,
            renderer_theme: crate::settings::BUILT_IN_THEME.to_string(),
            command_palette: None,
            file_preview: None,
        }
    }

    /// Stamp the renderer font size resolved from persisted settings for the attach-tab base.
    pub fn with_renderer_font_size_px(mut self, font_size_px: u32) -> Self {
        self.renderer_font_size_px = font_size_px;
        self
    }

    /// Stamp the renderer theme id resolved from persisted settings for the attach-tab base.
    pub fn with_renderer_theme(mut self, theme: impl Into<String>) -> Self {
        self.renderer_theme = theme.into();
        self
    }

    /// Stamp the computed command-palette catalog/query/preview DTO when `--command-palette` was
    /// requested. `None` keeps the field `null` and every existing attach-tab output byte-identical.
    pub fn with_command_palette(mut self, command_palette: Option<CommandPalette>) -> Self {
        self.command_palette = command_palette;
        self
    }

    /// Stamp the read-only file-preview metadata when `--file-preview <path>` was requested. `None`
    /// keeps the field `null` and every existing attach-tab output byte-identical. Carries metadata
    /// only (path + line count + truncation flags), never the file body.
    pub fn with_file_preview(mut self, file_preview: FilePreviewReport) -> Self {
        self.file_preview = Some(file_preview);
        self
    }
}

/// The failure JSON printed to stderr by `maestro-app attach-tab`. Mirrors [`LaunchFailure`]'s shape
/// but stamps `command: "attach-tab"`. `error_kind` values include `bad_usage`, `window_failed`,
/// `tab_selection_failed`, `tab_session_not_live`, `binary_not_found`, `daemon_failed`, and
/// `renderer_failed`.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AttachTabFailure {
    pub ok: bool,
    pub command: &'static str,
    pub error_kind: String,
    pub message: String,
}

impl AttachTabFailure {
    pub fn new(error_kind: impl Into<String>, message: impl Into<String>) -> Self {
        AttachTabFailure {
            ok: false,
            command: "attach-tab",
            error_kind: error_kind.into(),
            message: message.into(),
        }
    }
}

/// The success JSON for the layout-returning window subcommands (`create`/`show`/`open-tab`): one
/// structured value with the resolved `base`, the `window_id`, and the ordered `tabs`. `command`
/// distinguishes which subcommand produced it.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct WindowLayoutSuccess {
    pub ok: bool,
    pub command: &'static str,
    pub base: String,
    pub window_id: String,
    pub tabs: Vec<WindowTabJson>,
}

impl WindowLayoutSuccess {
    pub fn new(
        command: &'static str,
        base: String,
        window_id: String,
        tabs: Vec<WindowTabJson>,
    ) -> Self {
        WindowLayoutSuccess {
            ok: true,
            command,
            base,
            window_id,
            tabs,
        }
    }
}

/// The success JSON for `window view`: the resolved `base`, the `window_id`, and the projected
/// `tabs` joined with the agent-task reconcile report.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct WindowViewSuccess {
    pub ok: bool,
    pub command: &'static str,
    pub base: String,
    pub window_id: String,
    pub tabs: Vec<WindowViewTabJson>,
}

impl WindowViewSuccess {
    pub fn new(base: String, window_id: String, tabs: Vec<WindowViewTabJson>) -> Self {
        WindowViewSuccess {
            ok: true,
            command: "window view",
            base,
            window_id,
            tabs,
        }
    }
}

/// The failure JSON printed to stderr by any `window` subcommand. Mirrors the other failure shapes
/// (`ok:false`, `command`, `error_kind`, `message`) and stamps the originating subcommand. Typical
/// `error_kind`s: `bad_usage` (parse/usage error) and `window_failed` (service/store failure).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct WindowFailure {
    pub ok: bool,
    pub command: &'static str,
    pub error_kind: String,
    pub message: String,
}

impl WindowFailure {
    pub fn new(
        command: &'static str,
        error_kind: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        WindowFailure {
            ok: false,
            command,
            error_kind: error_kind.into(),
            message: message.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::build_tab_strip_model;
    use crate::AttentionJson;
    use crate::SplitFromJson;
    use crate::DEFAULT_SESSION_ID;

    fn s(v: &str) -> String {
        v.to_string()
    }

    fn attention(state: &str, unseen: bool) -> AttentionJson {
        AttentionJson {
            attention: s(state),
            unseen,
            since_ms: 0,
            source: s("process"),
        }
    }

    fn strip_tab(tab_id: &str, index: u32, attention: AttentionJson) -> WindowTabJson {
        WindowTabJson {
            tab_id: s(tab_id),
            session_id: format!("sess-{tab_id}"),
            index,
            title: format!("Title {tab_id}"),
            pinned: false,
            attention,
            split_from: None,
            pane_rect: None,
        }
    }

    #[test]
    fn attach_tab_success_serializes_tab_strip_without_losing_fields() {
        let tabs = vec![strip_tab("t0", 0, attention("none", false))];
        let strip = build_tab_strip_model("w1", &tabs, Some("t0")).unwrap();
        let success = AttachTabSuccess::new(
            s("/base"),
            s("w1"),
            s("t0"),
            s("sess-t0"),
            s("/run/sock"),
            s("Hydra - Title t0"),
            s("Hydra · w1/t0 · sess-t0"),
            false,
            vec![],
            false,
            true,
            false,
            None,
            None,
            strip,
            false,
            None,
            None,
        );
        let v: serde_json::Value = serde_json::to_value(&success).unwrap();

        // Existing top-level fields preserved.
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["command"], serde_json::json!("attach-tab"));
        assert_eq!(v["window_id"], serde_json::json!("w1"));
        assert_eq!(v["tab_id"], serde_json::json!("t0"));
        assert_eq!(v["session_id"], serde_json::json!("sess-t0"));
        assert_eq!(v["renderer_started"], serde_json::json!(false));
        assert_eq!(v["daemon_kept"], serde_json::json!(true));
        assert_eq!(v["log_dir"], serde_json::Value::Null);

        // New tab_strip field carries the model with the selected tab active.
        assert_eq!(v["tab_strip"]["window_id"], serde_json::json!("w1"));
        assert_eq!(v["tab_strip"]["active_tab_id"], serde_json::json!("t0"));
        let strip_tabs = v["tab_strip"]["tabs"].as_array().unwrap();
        assert_eq!(strip_tabs.len(), 1);
        assert_eq!(strip_tabs[0]["tab_id"], serde_json::json!("t0"));
        assert_eq!(strip_tabs[0]["active"], serde_json::json!(true));

        // Default top_tab_bar is reported as false.
        assert_eq!(v["top_tab_bar"], serde_json::json!(false));

        // Backward-additive panel fields default to null when neither flag was given.
        assert_eq!(v["dashboard_panel"], serde_json::Value::Null);
        assert_eq!(v["settings_panel"], serde_json::Value::Null);
        // The file-preview report is null until `--file-preview` is given.
        assert_eq!(v["file_preview"], serde_json::Value::Null);
    }

    #[test]
    fn attach_tab_success_file_preview_null_by_default_and_stamped_when_present() {
        let tabs = vec![strip_tab("t0", 0, attention("none", false))];
        let strip = build_tab_strip_model("w1", &tabs, Some("t0")).unwrap();
        let base = AttachTabSuccess::new(
            s("/base"),
            s("w1"),
            s("t0"),
            s("sess-t0"),
            s("/run/sock"),
            s("Hydra - Title t0"),
            s("Hydra · w1/t0 · sess-t0"),
            false,
            vec![],
            false,
            true,
            false,
            None,
            None,
            strip,
            false,
            None,
            None,
        );
        // Absent flag: the field serializes as JSON null, keeping the historical output shape.
        let v: serde_json::Value = serde_json::to_value(&base).unwrap();
        assert_eq!(v["file_preview"], serde_json::Value::Null);

        // Stamped: the report carries path + truncation metadata (and NOT the file body).
        let stamped = base.with_file_preview(FilePreviewReport {
            path: s("/tmp/notes.txt"),
            line_count: 3,
            truncated_bytes: true,
            truncated_lines: false,
            truncated_line_width: false,
        });
        let v: serde_json::Value = serde_json::to_value(&stamped).unwrap();
        assert_eq!(
            v["file_preview"]["path"],
            serde_json::json!("/tmp/notes.txt")
        );
        assert_eq!(v["file_preview"]["line_count"], serde_json::json!(3));
        assert_eq!(
            v["file_preview"]["truncated_bytes"],
            serde_json::json!(true)
        );
        assert_eq!(
            v["file_preview"]["truncated_lines"],
            serde_json::json!(false)
        );
        // The report never echoes the file body.
        assert!(v["file_preview"].get("lines").is_none());
    }

    fn argv(items: &[&str]) -> Vec<String> {
        items.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn window_failure_stamps_subcommand_and_kind() {
        let f = WindowFailure::new("window open-tab", "window_failed", "tab already exists");
        let v: serde_json::Value = serde_json::to_value(&f).unwrap();
        assert_eq!(v["ok"], serde_json::json!(false));
        assert_eq!(v["command"], serde_json::json!("window open-tab"));
        assert_eq!(v["error_kind"], serde_json::json!("window_failed"));
        assert_eq!(v["message"], serde_json::json!("tab already exists"));
    }

    #[test]
    fn success_json_has_contract_fields() {
        let ok = LaunchSuccess::new(
            s("/tmp/d.sock"),
            s("sid"),
            s("live"),
            Some(s("gen-1")),
            s("Hydra - sid"),
            s("Hydra · sid"),
            true,
            argv(&["/bin/maestro-renderer", "/tmp/d.sock", "sid"]),
            true,
            false,
            false,
            Some(s("exit 0")),
            None,
        );
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["command"], serde_json::json!("launch"));
        assert_eq!(v["socket_path"], serde_json::json!("/tmp/d.sock"));
        assert_eq!(v["session_id"], serde_json::json!("sid"));
        assert_eq!(v["status"], serde_json::json!("live"));
        assert_eq!(v["generation"], serde_json::json!("gen-1"));
        assert_eq!(v["window_title"], serde_json::json!("Hydra - sid"));
        assert_eq!(v["status_label"], serde_json::json!("Hydra · sid"));
        assert_eq!(v["renderer_started"], serde_json::json!(true));
        assert_eq!(
            v["renderer_command"][0],
            serde_json::json!("/bin/maestro-renderer")
        );
        // Lifecycle fields are present and explicit.
        assert_eq!(v["daemon_started"], serde_json::json!(true));
        assert_eq!(v["daemon_kept"], serde_json::json!(false));
        assert_eq!(v["renderer_detached"], serde_json::json!(false));
        assert_eq!(v["renderer_exit_status"], serde_json::json!("exit 0"));
    }

    #[test]
    fn success_json_file_preview_null_by_default_and_stamped_when_present() {
        let base = LaunchSuccess::new(
            s("/tmp/d.sock"),
            s("sid"),
            s("live"),
            None,
            s("Hydra - sid"),
            s("Hydra · sid"),
            true,
            vec![],
            true,
            false,
            false,
            None,
            None,
        );
        // Absent flag: the field serializes as JSON null, keeping the historical output shape.
        let v: serde_json::Value = serde_json::to_value(&base).unwrap();
        assert_eq!(v["file_preview"], serde_json::Value::Null);

        // Stamped: the report carries the path + truncation metadata (and NOT the file body).
        let stamped = base.with_file_preview(FilePreviewReport {
            path: s("/tmp/notes.txt"),
            line_count: 3,
            truncated_bytes: true,
            truncated_lines: false,
            truncated_line_width: false,
        });
        let v: serde_json::Value = serde_json::to_value(&stamped).unwrap();
        assert_eq!(
            v["file_preview"]["path"],
            serde_json::json!("/tmp/notes.txt")
        );
        assert_eq!(v["file_preview"]["line_count"], serde_json::json!(3));
        assert_eq!(
            v["file_preview"]["truncated_bytes"],
            serde_json::json!(true)
        );
        assert_eq!(
            v["file_preview"]["truncated_lines"],
            serde_json::json!(false)
        );
        // The report never echoes the file body.
        assert!(v["file_preview"].get("lines").is_none());
    }

    #[test]
    fn success_json_generation_serializes_null_when_absent() {
        let ok = LaunchSuccess::new(
            s("/s"),
            s("sid"),
            s("unknown"),
            None,
            s("Hydra - sid"),
            s("Hydra · sid"),
            false,
            vec![],
            false,
            true,
            false,
            None,
            None,
        );
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["generation"], serde_json::Value::Null);
        // renderer_exit_status is null when the renderer was not awaited.
        assert_eq!(v["renderer_exit_status"], serde_json::Value::Null);
        // log_dir serializes as null when not provided.
        assert_eq!(v["log_dir"], serde_json::Value::Null);
    }

    #[test]
    fn success_json_includes_log_dir_when_present() {
        let ok = LaunchSuccess::new(
            s("/s"),
            s("sid"),
            s("live"),
            None,
            s("Hydra - sid"),
            s("Hydra · sid"),
            false,
            vec![],
            true,
            false,
            false,
            None,
            Some(s("/tmp/logs")),
        );
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["log_dir"], serde_json::json!("/tmp/logs"));
    }

    #[test]
    fn success_json_log_dir_serializes_null_when_absent() {
        let ok = LaunchSuccess::new(
            s("/s"),
            s("sid"),
            s("live"),
            None,
            s("Hydra - sid"),
            s("Hydra · sid"),
            false,
            vec![],
            true,
            false,
            false,
            None,
            None,
        );
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["log_dir"], serde_json::Value::Null);
    }

    #[test]
    fn failure_json_has_contract_fields() {
        let f = LaunchFailure::new("binary_not_found", "no pty-daemon");
        let v: serde_json::Value = serde_json::to_value(&f).unwrap();
        assert_eq!(v["ok"], serde_json::json!(false));
        assert_eq!(v["error_kind"], serde_json::json!("binary_not_found"));
        assert_eq!(v["message"], serde_json::json!("no pty-daemon"));
    }

    #[test]
    fn launch_success_serializes_window_record_fields_for_both_cases() {
        // Unrecorded: window_recorded=false and the ids serialize as null.
        let plain = LaunchSuccess::new(
            s("/s"),
            s("sid"),
            s("live"),
            None,
            s("Hydra - sid"),
            s("Hydra · sid"),
            false,
            vec![],
            false,
            true,
            false,
            None,
            None,
        );
        let v: serde_json::Value = serde_json::to_value(&plain).unwrap();
        assert_eq!(v["window_recorded"], serde_json::json!(false));
        assert_eq!(v["window_id"], serde_json::json!(null));
        assert_eq!(v["tab_id"], serde_json::json!(null));

        // Recorded: window_recorded=true and the ids are present.
        let recorded = plain.with_window_record(s("main"), s("sid"));
        let v: serde_json::Value = serde_json::to_value(&recorded).unwrap();
        assert_eq!(v["window_recorded"], serde_json::json!(true));
        assert_eq!(v["window_id"], serde_json::json!("main"));
        assert_eq!(v["tab_id"], serde_json::json!("sid"));
    }

    #[test]
    fn launch_success_serializes_chrome_and_new_tab_policy() {
        // Default (no chrome stamped): both fields serialize false.
        let plain = LaunchSuccess::new(
            s("/s"),
            s("sid"),
            s("live"),
            None,
            s("Hydra - sid"),
            s("Hydra · sid"),
            false,
            vec![],
            false,
            true,
            false,
            None,
            None,
        );
        let v: serde_json::Value = serde_json::to_value(&plain).unwrap();
        assert_eq!(v["top_tab_bar"], serde_json::json!(false));
        assert_eq!(v["new_tab_default_shell"], serde_json::json!(false));

        // The resolved launch chrome / new-tab policy from the headline path: both true, so a
        // `--no-run-renderer` consumer can verify the parsed launch path from the JSON alone.
        let chrome = plain.with_chrome(true, true);
        let v: serde_json::Value = serde_json::to_value(&chrome).unwrap();
        assert_eq!(v["top_tab_bar"], serde_json::json!(true));
        assert_eq!(v["new_tab_default_shell"], serde_json::json!(true));
    }

    #[test]
    fn default_title_from_default_session_id() {
        assert_eq!(
            default_window_title(DEFAULT_SESSION_ID),
            "Hydra - maestro-app-dev"
        );
        // The effective title with no `--title` and the default session id matches the visible spec.
        assert_eq!(
            effective_window_title(None, DEFAULT_SESSION_ID),
            "Hydra - maestro-app-dev"
        );
    }

    #[test]
    fn validate_window_title_accepts_unicode_and_spaces() {
        assert!(validate_window_title("Maestro — café ✦").is_ok());
    }

    #[test]
    fn default_status_label_from_default_session_id() {
        assert_eq!(status_label(DEFAULT_SESSION_ID), "Hydra · maestro-app-dev");
    }

    #[test]
    fn success_json_includes_status_label() {
        let ok = LaunchSuccess::new(
            s("/s"),
            s("sid"),
            s("live"),
            None,
            s("Hydra - sid"),
            s("Hydra · sid"),
            false,
            vec![],
            false,
            true,
            false,
            None,
            None,
        );
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["status_label"], serde_json::json!("Hydra · sid"));
    }

    #[test]
    fn attach_tab_window_title_prefers_explicit_then_tab_then_session() {
        assert_eq!(
            attach_tab_window_title(Some("Explicit"), Some("Tabby"), "sess-1"),
            "Explicit"
        );
        assert_eq!(
            attach_tab_window_title(None, Some("Tabby"), "sess-1"),
            "Hydra - Tabby"
        );
        assert_eq!(
            attach_tab_window_title(None, Some("   "), "sess-1"),
            "Hydra - sess-1"
        );
        assert_eq!(
            attach_tab_window_title(None, None, "sess-1"),
            "Hydra - sess-1"
        );
    }

    #[test]
    fn attach_tab_status_label_is_compact_triple() {
        assert_eq!(
            attach_tab_status_label("w1", "t1", "sess-1"),
            "Hydra · w1/t1 · sess-1"
        );
    }

    // ---- window JSON DTOs -------------------------------------------------------------------

    fn attention_json_fixture() -> AttentionJson {
        AttentionJson {
            attention: s("none"),
            unseen: false,
            since_ms: 0,
            source: s("process"),
        }
    }

    #[test]
    fn window_mutation_success_uses_ordered_tabs_and_attention_object() {
        // A mutation command reuses WindowLayoutSuccess; prove the shape is stable here (main shapes
        // the same DTO from the persisted layout). This guards the wire contract independently of IO.
        let ok = WindowLayoutSuccess::new(
            "window rename-tab",
            s("/base"),
            s("w1"),
            vec![WindowTabJson {
                tab_id: s("t1"),
                session_id: s("s1"),
                index: 0,
                title: s("Renamed"),
                pinned: false,
                attention: attention_json_fixture(),
                split_from: None,
                pane_rect: None,
            }],
        );
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["command"], serde_json::json!("window rename-tab"));
        assert_eq!(v["tabs"][0]["title"], serde_json::json!("Renamed"));
        assert_eq!(v["tabs"][0]["index"], serde_json::json!(0));
        assert_eq!(
            v["tabs"][0]["attention"]["attention"],
            serde_json::json!("none")
        );
    }

    #[test]
    fn window_layout_success_has_ordered_tabs_and_attention_object() {
        let ok = WindowLayoutSuccess::new(
            "window show",
            s("/resolved/base"),
            s("w1"),
            vec![
                WindowTabJson {
                    tab_id: s("t0"),
                    session_id: s("s0"),
                    index: 0,
                    title: s("Zero"),
                    pinned: false,
                    attention: attention_json_fixture(),
                    split_from: None,
                    pane_rect: None,
                },
                WindowTabJson {
                    tab_id: s("t1"),
                    session_id: s("s1"),
                    index: 1,
                    title: s("One"),
                    pinned: true,
                    attention: attention_json_fixture(),
                    split_from: None,
                    pane_rect: None,
                },
            ],
        );
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["command"], serde_json::json!("window show"));
        assert_eq!(v["base"], serde_json::json!("/resolved/base"));
        assert_eq!(v["window_id"], serde_json::json!("w1"));
        // Tabs preserve insertion (index) order.
        assert_eq!(v["tabs"][0]["tab_id"], serde_json::json!("t0"));
        assert_eq!(v["tabs"][0]["index"], serde_json::json!(0));
        assert_eq!(v["tabs"][1]["tab_id"], serde_json::json!("t1"));
        assert_eq!(v["tabs"][1]["index"], serde_json::json!(1));
        // Each tab carries the nested attention object with snake_case strings.
        assert_eq!(
            v["tabs"][0]["attention"]["attention"],
            serde_json::json!("none")
        );
        assert_eq!(
            v["tabs"][0]["attention"]["source"],
            serde_json::json!("process")
        );
        assert_eq!(
            v["tabs"][0]["attention"]["unseen"],
            serde_json::json!(false)
        );
        assert_eq!(v["tabs"][0]["attention"]["since_ms"], serde_json::json!(0));
    }

    #[test]
    fn window_view_success_has_joined_task_session_fields() {
        let ok = WindowViewSuccess::new(
            s("/resolved/base"),
            s("w1"),
            vec![WindowViewTabJson {
                tab_id: s("t0"),
                session_id: s("s0"),
                index: 0,
                title: s("Zero"),
                pinned: false,
                attention: attention_json_fixture(),
                session_status: Some(s("live")),
                agent_task_id: Some(s("task-1")),
                agent_task_state: Some(s("running")),
                needs_attention: true,
                session_record_missing: false,
                split_from: Some(SplitFromJson {
                    tab_id: s("src"),
                    axis: s("right"),
                    ratio_per_mille: None,
                }),
                pane_rect: None,
                stashed: false,
            }],
        );
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        assert_eq!(v["command"], serde_json::json!("window view"));
        assert_eq!(v["window_id"], serde_json::json!("w1"));
        let tab = &v["tabs"][0];
        assert_eq!(tab["session_status"], serde_json::json!("live"));
        assert_eq!(tab["agent_task_id"], serde_json::json!("task-1"));
        assert_eq!(tab["agent_task_state"], serde_json::json!("running"));
        assert_eq!(tab["needs_attention"], serde_json::json!(true));
        assert_eq!(tab["session_record_missing"], serde_json::json!(false));
        assert_eq!(tab["split_from"]["tab_id"], serde_json::json!("src"));
        assert_eq!(tab["split_from"]["axis"], serde_json::json!("right"));
    }

    #[test]
    fn window_view_success_nulls_unjoined_fields() {
        let ok = WindowViewSuccess::new(
            s("/resolved/base"),
            s("w1"),
            vec![WindowViewTabJson {
                tab_id: s("t0"),
                session_id: s("s0"),
                index: 0,
                title: s("Zero"),
                pinned: false,
                attention: attention_json_fixture(),
                session_status: None,
                agent_task_id: None,
                agent_task_state: None,
                needs_attention: false,
                session_record_missing: false,
                split_from: None,
                pane_rect: None,
                stashed: false,
            }],
        );
        let v: serde_json::Value = serde_json::to_value(&ok).unwrap();
        let tab = &v["tabs"][0];
        assert_eq!(tab["session_status"], serde_json::Value::Null);
        assert_eq!(tab["agent_task_id"], serde_json::Value::Null);
        assert_eq!(tab["agent_task_state"], serde_json::Value::Null);
        // `split_from` is skipped entirely when absent, so the key is not present.
        assert!(tab.get("split_from").is_none());
    }
}
