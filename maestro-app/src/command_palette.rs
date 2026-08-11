//! Headless, read-only command-palette action catalog.
//!
//! This module owns the deterministic action catalog that a FUTURE interactive command palette will
//! display. It is strictly a data surface: [`build_command_palette`] returns a pure [`CommandPalette`]
//! DTO describing the app's currently-known actions. It connects to no daemon, opens no socket/
//! renderer/terminal, mutates no records, writes no settings, and touches no filesystem — the only
//! input is the already-resolved `base` directory string used for display context.
//!
//! Each [`PaletteAction`] carries a stable dotted `id`, a short `title`, a `category` drawn from a
//! small fixed set, a one-line `description`, and an `argv` showing the equivalent command shape with
//! `<window-id>`/`<tab-id>` placeholders where a runtime id would be required. The catalog order is
//! fixed and covered by tests so a future palette can rely on a stable presentation.

use serde::Serialize;

/// A single command-palette action: a stable, displayable description of one app command.
///
/// `id` is a stable dotted identifier (e.g. `settings.show_panel`) a palette can key on. `argv` lists
/// the equivalent CLI tokens, using `<window-id>`/`<tab-id>` placeholders where a real runtime id
/// would be substituted — the catalog never inspects records or daemon state to fill them in.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct PaletteAction {
    pub id: &'static str,
    pub title: &'static str,
    pub category: &'static str,
    pub description: &'static str,
    pub argv: Vec<&'static str>,
}

/// The read-only command-palette catalog DTO printed by `command-palette --list`.
///
/// `base` echoes the resolved/supplied base directory used for display context; `action_count`
/// always equals `actions.len()` (asserted in tests). `command` is the stable `"command-palette"`
/// label so the JSON self-identifies like the other headless commands.
///
/// `query`/`query_terms` are backward-additive metadata present ONLY when a `--query` filter was
/// applied (both are skipped from the JSON when absent), so unfiltered output is byte-compatible
/// with the pre-filter shape. `query` is the normalized query string and `query_terms` are the
/// normalized whitespace-separated terms used for matching.
///
/// `preview` is backward-additive metadata present ONLY when `--preview` was requested (skipped from
/// the JSON when absent), so output without `--preview` is byte-compatible with the prior shape. It is
/// a compact, display-ready projection of `actions` (after any query filter) that a future palette UI
/// can render directly without reimplementing row formatting.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommandPalette {
    pub ok: bool,
    pub command: &'static str,
    pub base: String,
    pub action_count: usize,
    pub actions: Vec<PaletteAction>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query_terms: Option<Vec<String>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preview: Option<CommandPalettePreview>,
}

/// Maximum `char` length of any single preview-row display field. Mirrors the settings-panel cap
/// spirit: every preview field is sanitized then bounded to this length so a row stays terminal-
/// friendly and cannot grow without limit. Truncated fields end with an ASCII `...` marker.
pub const PALETTE_PREVIEW_FIELD_MAX: usize = 120;

/// A compact, display-ready projection of the filtered/unfiltered action list for a future palette UI.
///
/// PURE and read-only: built entirely from the already-built `actions` (no I/O, no records/daemon
/// inspection). `title` is the stable `"Command Palette"` label; `query` echoes the normalized query
/// when one was supplied and is absent/null otherwise; `row_count` mirrors `rows.len()`. Every row
/// field is ASCII-only, single-line, sanitized, and length-bounded so it is directly safe to render.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommandPalettePreview {
    pub title: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub query: Option<String>,
    pub row_count: usize,
    pub rows: Vec<CommandPalettePreviewRow>,
}

/// A single display-ready preview row derived from one [`PaletteAction`].
///
/// All fields are sanitized + bounded copies of the action's display data: `id` (stable dotted
/// identifier), `label` (from the action `title`), `category`, `summary` (from `description`), and
/// `command` (a single-line display string derived from `argv`, placeholders preserved). No field can
/// contain a newline, so a row can never split into two.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommandPalettePreviewRow {
    pub id: String,
    pub label: String,
    pub category: String,
    pub summary: String,
    pub command: String,
}

/// Build the deterministic command-palette catalog for the supplied resolved `base` directory.
///
/// Pure and side-effect-free: it allocates the fixed action list, stamps `base`, and sets
/// `action_count` from the list length. The action order here IS the catalog order a palette will
/// present, and is pinned by tests.
pub fn build_command_palette(base: impl Into<String>) -> CommandPalette {
    let actions = catalog_actions();
    CommandPalette {
        ok: true,
        command: "command-palette",
        base: base.into(),
        action_count: actions.len(),
        actions,
        query: None,
        query_terms: None,
        preview: None,
    }
}

/// Normalize a raw `--query` value: trim leading/trailing ASCII whitespace and collapse every
/// internal run of ASCII whitespace to a single space. Returns the normalized string (which may be
/// empty only if the caller passed all-whitespace — the CLI parser already rejects that case).
pub fn normalize_palette_query(raw: &str) -> String {
    raw.split_ascii_whitespace().collect::<Vec<_>>().join(" ")
}

/// Split a normalized query into its lowercased whitespace-separated match terms. An action matches
/// the query only when EVERY returned term appears in at least one of its searchable fields.
pub fn palette_query_terms(normalized: &str) -> Vec<String> {
    normalized
        .split_ascii_whitespace()
        .map(|t| t.to_ascii_lowercase())
        .collect()
}

/// True when `action` matches `terms`: every term must appear (case-insensitively, as a substring)
/// in at least one of the action's searchable fields — `id`, `title`, `category`, `description`, or
/// any `argv` token.
fn action_matches_terms(action: &PaletteAction, terms: &[String]) -> bool {
    let mut haystacks: Vec<String> = vec![
        action.id.to_ascii_lowercase(),
        action.title.to_ascii_lowercase(),
        action.category.to_ascii_lowercase(),
        action.description.to_ascii_lowercase(),
    ];
    haystacks.extend(action.argv.iter().map(|t| t.to_ascii_lowercase()));
    terms
        .iter()
        .all(|term| haystacks.iter().any(|h| h.contains(term.as_str())))
}

/// Build the command-palette catalog filtered by the (raw) `--query` value.
///
/// Pure and side-effect-free: it filters ONLY the fixed catalog (no records/settings/daemon
/// inspection). The query is normalized (trim + collapse ASCII whitespace) and split into terms;
/// an action is kept only when every term matches at least one of its searchable fields, preserving
/// the original catalog order. The returned DTO carries the normalized `query` and `query_terms`
/// metadata so the JSON self-describes the applied filter; `action_count` equals the kept count
/// (0 with an empty `actions` array when nothing matches).
pub fn build_command_palette_filtered(base: impl Into<String>, query: &str) -> CommandPalette {
    let normalized = normalize_palette_query(query);
    let terms = palette_query_terms(&normalized);
    let actions: Vec<PaletteAction> = catalog_actions()
        .into_iter()
        .filter(|action| action_matches_terms(action, &terms))
        .collect();
    CommandPalette {
        ok: true,
        command: "command-palette",
        base: base.into(),
        action_count: actions.len(),
        actions,
        query: Some(normalized),
        query_terms: Some(terms),
        preview: None,
    }
}

/// Sanitize a display string for a single preview row field. Replaces every control char (including
/// tabs/newlines/CR) with a space, forces ASCII by mapping every non-ASCII char to `?`, then collapses
/// whitespace runs to single spaces. The result can never contain a newline, so a field can never
/// split one row into two. Mirrors the settings-panel sanitize spirit.
pub fn sanitize_palette_preview_text(s: &str) -> String {
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

/// Deterministically truncate `s` to at most `max` `char`s. When truncated the result is exactly
/// `max` chars ending in an ASCII `...` marker; `max <= 3` collapses to a bare run of `.` so the
/// marker still fits, and `max == 0` yields an empty string. Mirrors the settings-panel truncate.
fn truncate_palette_preview_text(s: &str, max: usize) -> String {
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

/// Sanitize then bound a display string to one safe preview field.
fn palette_preview_field(s: &str) -> String {
    truncate_palette_preview_text(&sanitize_palette_preview_text(s), PALETTE_PREVIEW_FIELD_MAX)
}

/// Build a single-line display `command` string from an action's `argv`, preserving placeholders such
/// as `<window-id>` as-is. Tokens are joined with single spaces, then sanitized + bounded like any
/// other preview field (so the join itself can never introduce a newline or unbounded growth).
pub fn palette_command_string(argv: &[&str]) -> String {
    palette_preview_field(&argv.join(" "))
}

/// Build the compact, display-ready preview model from an already-built action list (after any query
/// filter). PURE and read-only: derives rows ONLY from the supplied `actions`, preserving their order;
/// every row field is sanitized + bounded. `query` is echoed as-is (the caller passes the normalized
/// query when one was supplied, or `None`). `row_count` always equals `rows.len()`.
pub fn build_command_palette_preview(
    actions: &[PaletteAction],
    query: Option<String>,
) -> CommandPalettePreview {
    let rows: Vec<CommandPalettePreviewRow> = actions
        .iter()
        .map(|action| CommandPalettePreviewRow {
            id: palette_preview_field(action.id),
            label: palette_preview_field(action.title),
            category: palette_preview_field(action.category),
            summary: palette_preview_field(action.description),
            command: palette_command_string(&action.argv),
        })
        .collect();
    CommandPalettePreview {
        title: "Command Palette",
        query,
        row_count: rows.len(),
        rows,
    }
}

/// Attach a [`CommandPalettePreview`] to an already-built [`CommandPalette`], deriving the preview from
/// the palette's own (filtered/unfiltered) `actions` and reusing its normalized `query` (so the
/// preview echoes the same normalized query the filter recorded, or `None` when unfiltered). Pure: it
/// only reads the palette's existing fields and sets `preview`.
pub fn with_command_palette_preview(mut palette: CommandPalette) -> CommandPalette {
    let preview = build_command_palette_preview(&palette.actions, palette.query.clone());
    palette.preview = Some(preview);
    palette
}

/// The read-only action-detail DTO printed by `command-palette --describe <action-id>`.
///
/// Resolves EXACTLY one [`PaletteAction`] by stable `id` from the same fixed catalog as `--list`,
/// then attaches a non-executing [`CommandPaletteExecutionPlan`]. `base` echoes the resolved/supplied
/// base directory for display context; `command` is the stable `"command-palette"` label. This DTO is
/// pure: it inspects no records/settings/windows/tabs/worktrees/daemon state and executes nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommandPaletteActionDetail {
    pub ok: bool,
    pub command: &'static str,
    pub base: String,
    pub action: PaletteAction,
    pub execution: CommandPaletteExecutionPlan,
}

/// A non-executing description of how the selected action's command WOULD run, derived ONLY from the
/// action's `argv`. It deliberately does NOT run the command: `execution_supported` is always `false`
/// because this API intentionally does not implement execution.
///
/// `argv` lists the action's tokens verbatim (placeholders preserved). `command` is a single-line
/// display string built from `argv` via the same sanitizer/bounding as the preview command field.
/// `placeholders` is the stable-ordered, de-duplicated list of `<...>` placeholder tokens in `argv`;
/// `requires_context` is true when any placeholder is present (a runtime id would be required first);
/// `can_execute_now` is the negation of `requires_context` (true only when nothing must be filled in,
/// but execution is still not actually performed). `note` is a short, stable detail-only string.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct CommandPaletteExecutionPlan {
    pub argv: Vec<&'static str>,
    pub command: String,
    pub requires_context: bool,
    pub placeholders: Vec<String>,
    pub can_execute_now: bool,
    pub execution_supported: bool,
    pub note: &'static str,
}

/// Short, stable note stamped on every execution plan: this is a read-only detail view, never a run.
const PALETTE_EXECUTION_NOTE: &str =
    "Detail only: this describes the action's command without executing it.";

/// True when `token` is a placeholder of the form `<...>`: it starts with `<`, ends with `>`, and has
/// at least one inner char. Used to decide whether an action needs runtime context before it could run.
fn is_palette_placeholder(token: &str) -> bool {
    token.len() >= 3 && token.starts_with('<') && token.ends_with('>')
}

/// Extract the stable-ordered, de-duplicated list of `<...>` placeholder tokens from an action's
/// `argv`, preserving first-seen order. Pure: a token is copied verbatim (never rewritten).
pub fn palette_placeholders(argv: &[&str]) -> Vec<String> {
    let mut seen: Vec<String> = Vec::new();
    for token in argv {
        if is_palette_placeholder(token) && !seen.iter().any(|s| s == token) {
            seen.push((*token).to_string());
        }
    }
    seen
}

/// Build the non-executing execution plan for one resolved action, deriving every field from its
/// `argv`. Pure and side-effect-free: it never runs or mutates anything.
pub fn build_command_palette_execution_plan(action: &PaletteAction) -> CommandPaletteExecutionPlan {
    let placeholders = palette_placeholders(&action.argv);
    let requires_context = !placeholders.is_empty();
    CommandPaletteExecutionPlan {
        argv: action.argv.clone(),
        command: palette_command_string(&action.argv),
        requires_context,
        placeholders,
        can_execute_now: !requires_context,
        execution_supported: false,
        note: PALETTE_EXECUTION_NOTE,
    }
}

/// Look up exactly one catalog action by its stable `id`. Returns `None` for an unknown id; there is
/// NO fuzzy matching, aliasing, query filtering, or dynamic/record-derived lookup — only the fixed
/// catalog is consulted.
pub fn find_palette_action(action_id: &str) -> Option<PaletteAction> {
    catalog_actions()
        .into_iter()
        .find(|action| action.id == action_id)
}

/// Build the action-detail DTO for the resolved `base` and the requested stable `action_id`.
///
/// Pure and side-effect-free: resolves the action against the fixed catalog ONLY and attaches a
/// non-executing execution plan. Returns `None` when `action_id` is unknown (the caller maps that to a
/// stamped failure JSON + non-zero exit); never inspects records/settings/daemon/filesystem state and
/// never executes the action.
pub fn build_command_palette_action_detail(
    base: impl Into<String>,
    action_id: &str,
) -> Option<CommandPaletteActionDetail> {
    let action = find_palette_action(action_id)?;
    let execution = build_command_palette_execution_plan(&action);
    Some(CommandPaletteActionDetail {
        ok: true,
        command: "command-palette",
        base: base.into(),
        action,
        execution,
    })
}

/// The fixed, ordered action catalog. Order is load-bearing (tested) so a future palette UI has a
/// stable presentation; add new actions at a deliberate position rather than reordering existing ones.
fn catalog_actions() -> Vec<PaletteAction> {
    vec![
        PaletteAction {
            id: "command_palette.list",
            title: "List command palette",
            category: "launcher",
            description: "Print the read-only command-palette action catalog as JSON.",
            argv: vec!["command-palette", "--list"],
        },
        PaletteAction {
            id: "settings.show",
            title: "Show settings",
            category: "settings",
            description: "Print the effective app settings as JSON.",
            argv: vec!["settings", "show"],
        },
        PaletteAction {
            id: "settings.show_panel",
            title: "Show settings panel",
            category: "settings",
            description: "Print the compact settings panel lines projection.",
            argv: vec!["settings", "show", "--panel-lines"],
        },
        PaletteAction {
            id: "attach.settings_panel",
            title: "Attach tab with settings panel",
            category: "window",
            description: "Open a window tab in the renderer with the read-only settings panel above the grid.",
            argv: vec![
                "attach-tab",
                "--window-id",
                "<window-id>",
                "--tab-id",
                "<tab-id>",
                "--settings-panel",
            ],
        },
        PaletteAction {
            id: "dashboard.show",
            title: "Show dashboard",
            category: "dashboard",
            description: "Print the read-only local records snapshot (the dashboard model) as JSON.",
            argv: vec!["dashboard"],
        },
        PaletteAction {
            id: "dashboard.active_tasks",
            title: "Show active tasks",
            category: "dashboard",
            description: "Print the dashboard's active agent-task projection as JSON.",
            argv: vec!["dashboard", "--active-tasks"],
        },
        PaletteAction {
            id: "window.view",
            title: "View window",
            category: "window",
            description: "Print a window's persisted tab layout and session view as JSON.",
            argv: vec!["window", "view", "--window-id", "<window-id>"],
        },
        PaletteAction {
            id: "agent.mark_waiting",
            title: "Mark agent waiting on user",
            category: "agent",
            description: "Mark a running agent task as waiting-on-user via a trusted-local assertion.",
            argv: vec![
                "agent-mark",
                "--agent-task-id",
                "<agent-task-id>",
                "--waiting-on-user",
                "--reason",
                "<reason>",
            ],
        },
        PaletteAction {
            id: "agent.mark_blocked",
            title: "Mark agent blocked",
            category: "agent",
            description: "Mark a running agent task as blocked via a trusted-local assertion.",
            argv: vec![
                "agent-mark",
                "--agent-task-id",
                "<agent-task-id>",
                "--blocked",
                "--reason",
                "<reason>",
            ],
        },
        PaletteAction {
            id: "agent.finish",
            title: "Finish agent task",
            category: "agent",
            description: "Record a terminal outcome (succeeded/failed/cancelled) for an agent task.",
            argv: vec![
                "agent-finish",
                "--agent-task-id",
                "<agent-task-id>",
                "--succeeded",
            ],
        },
        PaletteAction {
            id: "worktree.list",
            title: "List worktrees",
            category: "workspace",
            description: "Print the read-only worktree-checkout inventory for a workspace as JSON.",
            argv: vec!["worktree-list", "--workspace-id", "<workspace-id>"],
        },
    ]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn command_palette_action_count_matches_len() {
        let palette = build_command_palette("/tmp/base");
        assert_eq!(palette.action_count, palette.actions.len());
    }

    #[test]
    fn command_palette_echoes_base_and_labels() {
        let palette = build_command_palette("/tmp/some-base");
        assert!(palette.ok);
        assert_eq!(palette.command, "command-palette");
        assert_eq!(palette.base, "/tmp/some-base");
    }

    #[test]
    fn command_palette_order_is_deterministic() {
        let ids: Vec<&str> = build_command_palette("/x")
            .actions
            .iter()
            .map(|a| a.id)
            .collect();
        assert_eq!(
            ids,
            vec![
                "command_palette.list",
                "settings.show",
                "settings.show_panel",
                "attach.settings_panel",
                "dashboard.show",
                "dashboard.active_tasks",
                "window.view",
                "agent.mark_waiting",
                "agent.mark_blocked",
                "agent.finish",
                "worktree.list",
            ]
        );
    }

    #[test]
    fn command_palette_includes_required_ids() {
        let ids: Vec<&str> = build_command_palette("/x")
            .actions
            .iter()
            .map(|a| a.id)
            .collect();
        for required in [
            "command_palette.list",
            "settings.show_panel",
            "attach.settings_panel",
        ] {
            assert!(
                ids.contains(&required),
                "missing required action id {required}"
            );
        }
    }

    #[test]
    fn command_palette_categories_are_known() {
        let known = [
            "session",
            "window",
            "settings",
            "agent",
            "workspace",
            "dashboard",
            "launcher",
        ];
        for action in build_command_palette("/x").actions {
            assert!(
                known.contains(&action.category),
                "action {} has unknown category {}",
                action.id,
                action.category
            );
        }
    }

    #[test]
    fn attach_settings_panel_uses_id_placeholders() {
        let palette = build_command_palette("/x");
        let action = palette
            .actions
            .iter()
            .find(|a| a.id == "attach.settings_panel")
            .expect("attach.settings_panel present");
        assert!(action.argv.contains(&"<window-id>"));
        assert!(action.argv.contains(&"<tab-id>"));
    }

    #[test]
    fn unfiltered_catalog_has_no_query_metadata() {
        let palette = build_command_palette("/x");
        assert!(palette.query.is_none());
        assert!(palette.query_terms.is_none());
    }

    #[test]
    fn normalize_palette_query_trims_and_collapses_whitespace() {
        assert_eq!(
            normalize_palette_query("  settings   show \t panel  "),
            "settings show panel"
        );
        assert_eq!(normalize_palette_query("settings"), "settings");
        assert_eq!(normalize_palette_query("   "), "");
    }

    #[test]
    fn palette_query_terms_lowercases_and_splits() {
        assert_eq!(
            palette_query_terms("Settings Show"),
            vec!["settings".to_string(), "show".to_string()]
        );
    }

    #[test]
    fn filtered_matching_is_case_insensitive() {
        let palette = build_command_palette_filtered("/x", "SETTINGS");
        assert!(!palette.actions.is_empty());
        assert!(palette.actions.iter().all(|a| a.category == "settings"
            || a.id.contains("settings")
            || a.argv.contains(&"--settings-panel")));
    }

    #[test]
    fn filtered_requires_all_terms_to_match() {
        // "settings" matches several actions; "panel" further narrows; both must hold.
        let palette = build_command_palette_filtered("/x", "settings panel");
        let ids: Vec<&str> = palette.actions.iter().map(|a| a.id).collect();
        assert!(ids.contains(&"settings.show_panel"));
        assert!(ids.contains(&"attach.settings_panel"));
        // "settings.show" lacks "panel" in any field, so it is excluded.
        assert!(!ids.contains(&"settings.show"));
    }

    #[test]
    fn filtered_matches_each_searchable_field() {
        // id substring
        assert!(build_command_palette_filtered("/x", "worktree.list")
            .actions
            .iter()
            .any(|a| a.id == "worktree.list"));
        // title word
        assert!(build_command_palette_filtered("/x", "dashboard")
            .actions
            .iter()
            .any(|a| a.id == "dashboard.show"));
        // category: the three "agent"-category actions all match (substring may match other fields
        // too, so we assert the agent ids are present rather than category-exclusivity).
        let agent_ids: Vec<&str> = build_command_palette_filtered("/x", "agent")
            .actions
            .iter()
            .map(|a| a.id)
            .collect();
        for id in ["agent.mark_waiting", "agent.mark_blocked", "agent.finish"] {
            assert!(agent_ids.contains(&id), "agent query missing {id}");
        }
        // description word ("inventory" only appears in worktree.list description)
        assert_eq!(
            build_command_palette_filtered("/x", "inventory")
                .actions
                .iter()
                .map(|a| a.id)
                .collect::<Vec<_>>(),
            vec!["worktree.list"]
        );
        // argv token ("--active-tasks" only appears in dashboard.active_tasks argv)
        assert_eq!(
            build_command_palette_filtered("/x", "--active-tasks")
                .actions
                .iter()
                .map(|a| a.id)
                .collect::<Vec<_>>(),
            vec!["dashboard.active_tasks"]
        );
    }

    #[test]
    fn filtered_preserves_catalog_order() {
        let palette = build_command_palette_filtered("/x", "settings");
        let ids: Vec<&str> = palette.actions.iter().map(|a| a.id).collect();
        // settings.show precedes settings.show_panel precedes attach.settings_panel in the catalog.
        let pos = |id: &str| ids.iter().position(|i| *i == id);
        assert!(pos("settings.show") < pos("settings.show_panel"));
        assert!(pos("settings.show_panel") < pos("attach.settings_panel"));
    }

    #[test]
    fn filtered_no_match_returns_empty_success() {
        let palette = build_command_palette_filtered("/x", "zzz-no-such-action");
        assert!(palette.ok);
        assert!(palette.actions.is_empty());
        assert_eq!(palette.action_count, 0);
        assert_eq!(palette.query.as_deref(), Some("zzz-no-such-action"));
    }

    #[test]
    fn filtered_action_count_matches_len() {
        let palette = build_command_palette_filtered("/x", "settings");
        assert_eq!(palette.action_count, palette.actions.len());
        let none = build_command_palette_filtered("/x", "no-match-xyz");
        assert_eq!(none.action_count, none.actions.len());
    }

    #[test]
    fn filtered_query_metadata_is_normalized() {
        let palette = build_command_palette_filtered("/x", "  Settings   Show ");
        assert_eq!(palette.query.as_deref(), Some("Settings Show"));
        assert_eq!(
            palette.query_terms.as_deref(),
            Some(["settings".to_string(), "show".to_string()].as_slice())
        );
    }

    #[test]
    fn unpreviewed_unfiltered_catalog_has_no_preview_metadata() {
        let palette = build_command_palette("/x");
        assert!(palette.preview.is_none());
    }

    #[test]
    fn unpreviewed_filtered_catalog_has_no_preview_metadata() {
        let palette = build_command_palette_filtered("/x", "settings");
        assert!(palette.preview.is_none());
    }

    #[test]
    fn previewed_catalog_includes_title_count_and_rows() {
        let palette = with_command_palette_preview(build_command_palette("/x"));
        let preview = palette.preview.expect("preview present");
        assert_eq!(preview.title, "Command Palette");
        assert_eq!(preview.row_count, preview.rows.len());
        assert_eq!(preview.row_count, palette.actions.len());
        assert!(!preview.rows.is_empty());
    }

    #[test]
    fn preview_rows_preserve_filtered_catalog_order() {
        let palette =
            with_command_palette_preview(build_command_palette_filtered("/x", "settings"));
        let preview = palette.preview.expect("preview present");
        let row_ids: Vec<&str> = preview.rows.iter().map(|r| r.id.as_str()).collect();
        let action_ids: Vec<&str> = palette.actions.iter().map(|a| a.id).collect();
        assert_eq!(row_ids, action_ids);
        // settings.show precedes settings.show_panel precedes attach.settings_panel.
        let pos = |id: &str| row_ids.iter().position(|i| *i == id);
        assert!(pos("settings.show") < pos("settings.show_panel"));
        assert!(pos("settings.show_panel") < pos("attach.settings_panel"));
    }

    #[test]
    fn preview_query_metadata_absent_without_query_and_normalized_with_query() {
        let unfiltered = with_command_palette_preview(build_command_palette("/x"));
        assert!(unfiltered.preview.expect("preview present").query.is_none());

        let filtered = with_command_palette_preview(build_command_palette_filtered(
            "/x",
            "  Settings   Show ",
        ));
        assert_eq!(
            filtered.preview.expect("preview present").query.as_deref(),
            Some("Settings Show")
        );
    }

    #[test]
    fn preview_no_match_returns_empty_rows() {
        let palette =
            with_command_palette_preview(build_command_palette_filtered("/x", "zzz-no-such"));
        let preview = palette.preview.expect("preview present");
        assert!(preview.rows.is_empty());
        assert_eq!(preview.row_count, 0);
        assert_eq!(preview.query.as_deref(), Some("zzz-no-such"));
    }

    #[test]
    fn preview_row_fields_are_deterministic_and_complete() {
        let palette =
            with_command_palette_preview(build_command_palette_filtered("/x", "worktree.list"));
        let preview = palette.preview.expect("preview present");
        let row = preview
            .rows
            .iter()
            .find(|r| r.id == "worktree.list")
            .expect("worktree.list row present");
        assert_eq!(row.label, "List worktrees");
        assert_eq!(row.category, "workspace");
        assert_eq!(
            row.summary,
            "Print the read-only worktree-checkout inventory for a workspace as JSON."
        );
        assert_eq!(row.command, "worktree-list --workspace-id <workspace-id>");
    }

    #[test]
    fn preview_command_string_preserves_placeholders() {
        let palette =
            with_command_palette_preview(build_command_palette_filtered("/x", "attach.settings"));
        let preview = palette.preview.expect("preview present");
        let row = preview
            .rows
            .iter()
            .find(|r| r.id == "attach.settings_panel")
            .expect("attach.settings_panel row present");
        assert!(row.command.contains("<window-id>"));
        assert!(row.command.contains("<tab-id>"));
        assert_eq!(
            row.command,
            "attach-tab --window-id <window-id> --tab-id <tab-id> --settings-panel"
        );
    }

    #[test]
    fn preview_sanitize_strips_control_and_non_ascii_and_collapses_whitespace() {
        // Control chars (incl. newline/tab/CR) become spaces; runs collapse; non-ASCII -> '?'.
        assert_eq!(sanitize_palette_preview_text("a\nb\tc\r  d"), "a b c d");
        assert_eq!(sanitize_palette_preview_text("café—ok"), "caf??ok");
        assert!(!sanitize_palette_preview_text("x\ny").contains('\n'));
    }

    #[test]
    fn preview_command_string_sanitizes_and_joins() {
        assert_eq!(
            palette_command_string(&["attach-tab", "--reason", "<reason>"]),
            "attach-tab --reason <reason>"
        );
        // a token carrying a newline cannot split the single-line command field
        assert!(!palette_command_string(&["a\nb", "c"]).contains('\n'));
    }

    #[test]
    fn preview_truncates_overlong_fields() {
        let long = "x".repeat(PALETTE_PREVIEW_FIELD_MAX + 50);
        let action = PaletteAction {
            id: "test.long",
            title: "t",
            category: "c",
            description: "d",
            argv: vec!["a"],
        };
        // build a row directly with a forced-long argv to exercise the command truncation
        let long_argv: Vec<&str> = vec![long.as_str()];
        let cmd = palette_command_string(&long_argv);
        assert_eq!(cmd.chars().count(), PALETTE_PREVIEW_FIELD_MAX);
        assert!(cmd.ends_with("..."));
        // a normal action's fields are well under the cap and unchanged
        let rows = build_command_palette_preview(std::slice::from_ref(&action), None).rows;
        assert_eq!(rows[0].id, "test.long");
        assert_eq!(rows[0].command, "a");
    }

    #[test]
    fn preview_sanitizes_row_fields_from_action() {
        // An action whose display strings carry control/non-ASCII chars must yield clean, single-line
        // rows (proving the builder sanitizes every field, not just the command).
        let action = PaletteAction {
            id: "weird.id",
            title: "line\none\ttwo",
            category: "caf\u{e9}",
            description: "a\rb",
            argv: vec!["cmd", "weird\narg"],
        };
        let preview = build_command_palette_preview(std::slice::from_ref(&action), None);
        let row = &preview.rows[0];
        assert_eq!(row.label, "line one two");
        assert_eq!(row.category, "caf?");
        assert_eq!(row.summary, "a b");
        assert!(!row.command.contains('\n'));
        for field in [
            &row.id,
            &row.label,
            &row.category,
            &row.summary,
            &row.command,
        ] {
            assert!(!field.contains('\n'));
        }
    }

    #[test]
    fn preview_row_count_matches_len_and_action_count_matches_len() {
        let palette =
            with_command_palette_preview(build_command_palette_filtered("/x", "settings"));
        assert_eq!(palette.action_count, palette.actions.len());
        let preview = palette.preview.expect("preview present");
        assert_eq!(preview.row_count, preview.rows.len());
    }

    #[test]
    fn describe_resolves_known_id_with_action_and_plan() {
        let detail =
            build_command_palette_action_detail("/tmp/base", "settings.show").expect("known id");
        assert!(detail.ok);
        assert_eq!(detail.command, "command-palette");
        assert_eq!(detail.base, "/tmp/base");
        assert_eq!(detail.action.id, "settings.show");
        assert_eq!(detail.action.title, "Show settings");
        assert_eq!(detail.execution.argv, vec!["settings", "show"]);
        assert_eq!(detail.execution.command, "settings show");
    }

    #[test]
    fn describe_unknown_id_returns_none() {
        assert!(build_command_palette_action_detail("/x", "no.such.action").is_none());
        // an id that exists as a substring of a real id must still not resolve (exact match only)
        assert!(build_command_palette_action_detail("/x", "settings").is_none());
    }

    #[test]
    fn describe_every_catalog_id_resolves_to_itself() {
        for action in build_command_palette("/x").actions {
            let detail =
                build_command_palette_action_detail("/x", action.id).expect("catalog id resolves");
            assert_eq!(detail.action, action);
        }
    }

    #[test]
    fn find_palette_action_exact_match_only() {
        assert!(find_palette_action("worktree.list").is_some());
        assert!(find_palette_action("worktree").is_none());
        assert!(find_palette_action("").is_none());
    }

    #[test]
    fn is_palette_placeholder_recognizes_angle_tokens() {
        assert!(is_palette_placeholder("<window-id>"));
        assert!(is_palette_placeholder("<x>"));
        assert!(!is_palette_placeholder("<>"));
        assert!(!is_palette_placeholder("window-id"));
        assert!(!is_palette_placeholder("--window-id"));
        assert!(!is_palette_placeholder("<window-id"));
        assert!(!is_palette_placeholder("window-id>"));
    }

    #[test]
    fn placeholders_are_ordered_and_deduplicated() {
        let argv = [
            "agent-mark",
            "--agent-task-id",
            "<agent-task-id>",
            "--reason",
            "<reason>",
            "--again",
            "<agent-task-id>",
        ];
        assert_eq!(
            palette_placeholders(&argv),
            vec!["<agent-task-id>".to_string(), "<reason>".to_string()]
        );
    }

    #[test]
    fn placeholders_empty_when_no_angle_tokens() {
        assert!(palette_placeholders(&["settings", "show"]).is_empty());
    }

    #[test]
    fn execution_plan_with_placeholders_requires_context_and_cannot_execute_now() {
        let detail =
            build_command_palette_action_detail("/x", "attach.settings_panel").expect("known id");
        let plan = &detail.execution;
        assert!(plan.requires_context);
        assert!(!plan.can_execute_now);
        assert!(!plan.execution_supported);
        assert_eq!(
            plan.placeholders,
            vec!["<window-id>".to_string(), "<tab-id>".to_string()]
        );
        // argv tokens (and the command display string) preserve placeholders verbatim.
        assert!(plan.argv.contains(&"<window-id>"));
        assert!(plan.argv.contains(&"<tab-id>"));
        assert!(plan.command.contains("<window-id>"));
        assert!(plan.command.contains("<tab-id>"));
        assert_eq!(
            plan.command,
            "attach-tab --window-id <window-id> --tab-id <tab-id> --settings-panel"
        );
    }

    #[test]
    fn execution_plan_without_placeholders_can_execute_now_but_unsupported() {
        let detail =
            build_command_palette_action_detail("/x", "dashboard.active_tasks").expect("known id");
        let plan = &detail.execution;
        assert!(!plan.requires_context);
        assert!(plan.can_execute_now);
        // execution is intentionally never implemented, even for no-placeholder actions.
        assert!(!plan.execution_supported);
        assert!(plan.placeholders.is_empty());
        assert_eq!(plan.command, "dashboard --active-tasks");
    }

    #[test]
    fn execution_plan_note_is_stable_detail_only() {
        let detail =
            build_command_palette_action_detail("/x", "command_palette.list").expect("known id");
        assert_eq!(detail.execution.note, PALETTE_EXECUTION_NOTE);
        assert!(detail
            .execution
            .note
            .to_ascii_lowercase()
            .contains("without executing"));
    }
}
