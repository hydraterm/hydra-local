//! Agent-domain DTOs, wire envelopes, and pure helpers for `maestro-app`.
//!
//! This module holds the PURE, unit-testable agent surface. It contains:
//!
//! - the `agent-mark` / `agent-finish` bound constants and intent/argument DTOs;
//! - the `agent-start` / `agent-resume` argument DTOs;
//! - the success/failure JSON envelopes (`AgentSuccess`, `AgentFailure`, `AgentMarkSuccess`,
//!   `AgentFinishSuccess`);
//! - the pure window-record resolvers ([`resolve_agent_window_record`],
//!   [`resolve_agent_resume_window_record`]) and the wire-string helper
//!   [`agent_task_state_wire_str`].
//!
//! These items read no global state and perform no process IO. The argument PARSERS
//! (`parse_agent_start`/`parse_agent_resume`/`parse_agent_mark`/`parse_agent_finish`) deliberately
//! remain in `lib.rs`; the crate root re-exports this module's public items for
//! `maestro_app::<Item>` callers.

use std::path::PathBuf;

use serde::Serialize;

use crate::{WindowRecordParams, DEFAULT_WINDOW_ID};

/// Maximum length (in characters) of an `agent-mark --reason`. A conservative bound so a caller
/// cannot persist an unbounded blob into the task record's transition reason echo.
pub const AGENT_MARK_REASON_MAX_LEN: usize = 512;

/// Maximum length (in characters) of an `agent-finish --summary`. A conservative bound so a caller
/// cannot persist an unbounded blob into the task record's `result_summary`.
pub const AGENT_FINISH_SUMMARY_MAX_LEN: usize = 2048;

/// The explicit terminal intent of an `agent-finish` invocation: exactly one of succeeded, failed,
/// or cancelled.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentFinishIntent {
    Succeeded,
    Failed,
    Cancelled,
}

/// Parsed `agent-finish` arguments:
/// `agent-finish --agent-task-id <id> (--succeeded | --failed | --cancelled) [--summary <text>]
/// [--base <dir>]`.
///
/// `agent_task_id`/`intent` are `Option` here (a pure record of what the user typed); the parser
/// enforces presence, singleton-ness, and exactly-one-intent, so a fully-parsed value always has
/// them set. `summary` is genuinely optional: absent or empty-after-trim is stored as `None`.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentFinishArgs {
    pub agent_task_id: Option<String>,
    pub intent: Option<AgentFinishIntent>,
    pub summary: Option<String>,
    pub base: Option<PathBuf>,
}

/// The explicit intent of an `agent-mark` invocation: exactly one of waiting-on-user or blocked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AgentMarkIntent {
    WaitingOnUser,
    Blocked,
}

/// Parsed `agent-mark` arguments:
/// `agent-mark --agent-task-id <id> (--waiting-on-user | --blocked) --reason <text> [--base <dir>]`.
///
/// `agent_task_id`/`intent`/`reason` are `Option` here (a pure record of what the user typed); the
/// parser enforces presence, singleton-ness, exactly-one-intent, and a non-empty bounded reason, so
/// a fully-parsed value always has them set.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentMarkArgs {
    pub agent_task_id: Option<String>,
    pub intent: Option<AgentMarkIntent>,
    pub reason: Option<String>,
    pub base: Option<PathBuf>,
}

/// Parsed `agent-start` arguments. The required identity/goal fields are `Option` here because this
/// is a pure record of what the user typed; `main` enforces presence at run time (so parsing stays
/// a single, uniform pass and the missing-field error is reported consistently). Optional knobs
/// mirror `launch`'s socket/base/daemon/log-dir/keep-daemon policy.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentStartArgs {
    pub agent_task_id: Option<String>,
    pub project_id: Option<String>,
    pub goal: Option<String>,
    pub session_id: Option<String>,
    pub workspace_id: Option<String>,
    pub cwd: Option<PathBuf>,
    pub base: Option<PathBuf>,
    pub socket: Option<PathBuf>,
    pub daemon_bin: Option<PathBuf>,
    pub log_dir: Option<PathBuf>,
    /// `--cols` / `--rows`; `None` means use [`crate::DEFAULT_COLS`] / [`crate::DEFAULT_ROWS`].
    pub cols: Option<u16>,
    pub rows: Option<u16>,
    /// Accepted for symmetry with `launch`; a successful agent start keeps a spawned daemon alive
    /// regardless (the task PTY must survive), so this flag only documents intent.
    pub keep_daemon: bool,
    /// `--record-window`: opt into recording this agent task into the app-owned window/tab layout
    /// records. Default `agent-start` behavior is unchanged unless this is present. The four
    /// `--window-id`/`--tab-id`/`--tab-title`/`--tab-pinned` flags are only valid alongside this.
    pub record_window: bool,
    /// `--window-id <id>`: explicit window id for recording. Only valid with `--record-window`;
    /// defaults to `"main"` when omitted.
    pub record_window_id: Option<String>,
    /// `--tab-id <id>`: explicit tab id for recording. Only valid with `--record-window`; defaults
    /// to the `agent_task_id` when omitted (task-oriented tab identity).
    pub record_tab_id: Option<String>,
    /// `--tab-title <text>`: explicit tab title for recording. Only valid with `--record-window`;
    /// defaults to the task `goal` when omitted.
    pub record_tab_title: Option<String>,
    /// `--tab-pinned <true|false>`: explicit pinned flag for recording. Only valid with
    /// `--record-window`; defaults to `false` when omitted.
    pub record_tab_pinned: Option<bool>,
    /// Everything after `--`: the agent command/argv. Required to be non-empty.
    pub agent_argv: Vec<String>,
}

/// Parsed `agent-resume` arguments. Same shape as [`AgentStartArgs`] minus `--project-id`/`--goal`
/// (the task already exists, so resume neither creates nor re-describes it).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct AgentResumeArgs {
    pub agent_task_id: Option<String>,
    pub session_id: Option<String>,
    pub workspace_id: Option<String>,
    pub cwd: Option<PathBuf>,
    pub base: Option<PathBuf>,
    pub socket: Option<PathBuf>,
    pub daemon_bin: Option<PathBuf>,
    pub log_dir: Option<PathBuf>,
    pub cols: Option<u16>,
    pub rows: Option<u16>,
    pub keep_daemon: bool,
    /// `--record-window`: opt into recording/retargeting this resumed task's tab in the app-owned
    /// window/tab layout. Default `agent-resume` behavior is unchanged unless this is present. The
    /// four `--window-id`/`--tab-id`/`--tab-title`/`--tab-pinned` flags are only valid alongside it.
    pub record_window: bool,
    /// `--window-id <id>`: explicit window id for recording. Only valid with `--record-window`;
    /// defaults to `"main"` when omitted.
    pub record_window_id: Option<String>,
    /// `--tab-id <id>`: explicit tab id for recording. Only valid with `--record-window`; defaults
    /// to the `agent_task_id` when omitted (task-oriented tab identity).
    pub record_tab_id: Option<String>,
    /// `--tab-title <text>`: explicit tab title for recording. Only valid with `--record-window`;
    /// defaults to the existing task `goal` when omitted. Only used when a tab is newly opened.
    pub record_tab_title: Option<String>,
    /// `--tab-pinned <true|false>`: explicit pinned flag for recording. Only valid with
    /// `--record-window`; defaults to `false` when omitted. Only used when a tab is newly opened.
    pub record_tab_pinned: Option<bool>,
    pub agent_argv: Vec<String>,
}

/// Resolve the effective window-record parameters from the parsed `agent-start` flags, the
/// `agent_task_id`, the first live `session_id`, and the task `goal`, applying the documented
/// agent-oriented defaults. Pure so the defaulting is unit-testable without any store IO. Returns
/// `None` when `--record-window` was not given.
///
/// Unlike [`crate::resolve_window_record`] (launch), the agent defaults are TASK-oriented: the tab id
/// defaults to the durable `agent_task_id` (not the session id), and the title defaults to the task
/// `goal`. The `session_id` always points the tab at the first live session.
pub fn resolve_agent_window_record(
    args: &AgentStartArgs,
    agent_task_id: &str,
    goal: &str,
) -> Option<WindowRecordParams> {
    if !args.record_window {
        return None;
    }
    let window_id = args
        .record_window_id
        .clone()
        .unwrap_or_else(|| DEFAULT_WINDOW_ID.to_string());
    let tab_id = args
        .record_tab_id
        .clone()
        .unwrap_or_else(|| agent_task_id.to_string());
    let tab_title = args
        .record_tab_title
        .clone()
        .unwrap_or_else(|| goal.to_string());
    let tab_pinned = args.record_tab_pinned.unwrap_or(false);
    Some(WindowRecordParams {
        window_id,
        tab_id,
        tab_title,
        tab_pinned,
    })
}

/// Resolve the effective window-record parameters from the parsed `agent-resume` flags, the
/// `agent_task_id`, and the existing task `goal`, applying the same TASK-oriented defaults as
/// [`resolve_agent_window_record`]. Pure so the defaulting is unit-testable without store IO.
/// Returns `None` when `--record-window` was not given.
///
/// The resolved `tab_title`/`tab_pinned` are only consumed when resume opens a brand-new tab; an
/// already-present tab keeps its own title/pinned/attention during retargeting (the retarget moves
/// only `session_id`).
pub fn resolve_agent_resume_window_record(
    args: &AgentResumeArgs,
    agent_task_id: &str,
    goal: &str,
) -> Option<WindowRecordParams> {
    if !args.record_window {
        return None;
    }
    let window_id = args
        .record_window_id
        .clone()
        .unwrap_or_else(|| DEFAULT_WINDOW_ID.to_string());
    let tab_id = args
        .record_tab_id
        .clone()
        .unwrap_or_else(|| agent_task_id.to_string());
    let tab_title = args
        .record_tab_title
        .clone()
        .unwrap_or_else(|| goal.to_string());
    let tab_pinned = args.record_tab_pinned.unwrap_or(false);
    Some(WindowRecordParams {
        window_id,
        tab_id,
        tab_title,
        tab_pinned,
    })
}

/// The wire-stable snake_case string for a [`maestro_shell::AgentTaskState`], matching its serde
/// repr and the strings `maestro-app/src/main.rs` already emits (`draft`/`running`/… ). Pure.
pub fn agent_task_state_wire_str(state: maestro_shell::AgentTaskState) -> &'static str {
    match state {
        maestro_shell::AgentTaskState::Draft => "draft",
        maestro_shell::AgentTaskState::Running => "running",
        maestro_shell::AgentTaskState::WaitingOnUser => "waiting_on_user",
        maestro_shell::AgentTaskState::Blocked => "blocked",
        maestro_shell::AgentTaskState::Succeeded => "succeeded",
        maestro_shell::AgentTaskState::Failed => "failed",
        maestro_shell::AgentTaskState::Cancelled => "cancelled",
    }
}

/// The success JSON printed to stdout by `maestro-app agent-start` / `agent-resume`: exactly one
/// structured value describing the started/resumed agent task and its live session. `command`
/// distinguishes the two (`"agent-start"` | `"agent-resume"`). All fields are primitives derived
/// from `maestro-shell`'s `StartAgentTaskOutcome` (task state, session status/generation) plus the
/// daemon lifecycle decision, so this stays a plain serde DTO with no `maestro-shell` dependency.
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AgentSuccess {
    pub ok: bool,
    pub command: &'static str,
    pub socket_path: String,
    pub agent_task_id: String,
    /// The agent task state after the operation, e.g. "running".
    pub agent_task_state: String,
    pub session_id: String,
    /// The live session status, e.g. "live".
    pub session_status: String,
    /// Last known generation string for the session, or null.
    pub generation: Option<String>,
    /// True if THIS command spawned the daemon (false if it reused an already-running one).
    pub daemon_started: bool,
    /// True if the daemon is left running after this command returns. Always true on success when a
    /// daemon was spawned (the task PTY must survive); always true for a reused daemon.
    pub daemon_kept: bool,
    /// The opt-in `--log-dir` for a spawned daemon's captured stdout/stderr, or null.
    pub log_dir: Option<String>,
    /// True when this agent task was recorded into a window/tab layout (`--record-window`).
    /// Backward-compatible: defaults to false for normal `agent-start`/`agent-resume`.
    pub window_recorded: bool,
    /// The window id the task was recorded under, or null when not recorded.
    pub window_id: Option<String>,
    /// The tab id the task was recorded under, or null when not recorded.
    pub tab_id: Option<String>,
}

impl AgentSuccess {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        command: &'static str,
        socket_path: String,
        agent_task_id: String,
        agent_task_state: String,
        session_id: String,
        session_status: String,
        generation: Option<String>,
        daemon_started: bool,
        daemon_kept: bool,
        log_dir: Option<String>,
    ) -> Self {
        AgentSuccess {
            ok: true,
            command,
            socket_path,
            agent_task_id,
            agent_task_state,
            session_id,
            session_status,
            generation,
            daemon_started,
            daemon_kept,
            log_dir,
            window_recorded: false,
            window_id: None,
            tab_id: None,
        }
    }

    /// Stamp the backward-compatible window-recording fields onto the success value. `main.rs` calls
    /// this after a successful `agent-start --record-window` recording with the persisted ids.
    pub fn with_window_record(mut self, window_id: String, tab_id: String) -> Self {
        self.window_recorded = true;
        self.window_id = Some(window_id);
        self.tab_id = Some(tab_id);
        self
    }
}

/// The failure JSON printed to stderr by `maestro-app agent-start` / `agent-resume`. Mirrors the
/// other failure shapes (`ok:false`, `command`, `error_kind`, `message`) and stamps the originating
/// command. Typical `error_kind`s: `bad_usage` (parse/usage error) and `agent_task_failed`
/// (cwd/daemon/runtime failure).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AgentFailure {
    pub ok: bool,
    pub command: &'static str,
    pub error_kind: String,
    pub message: String,
}

impl AgentFailure {
    pub fn new(
        command: &'static str,
        error_kind: impl Into<String>,
        message: impl Into<String>,
    ) -> Self {
        AgentFailure {
            ok: false,
            command,
            error_kind: error_kind.into(),
            message: message.into(),
        }
    }
}

/// Success JSON for `agent-mark`. Reports the durable outcome of a state assertion. `changed` is
/// `true` when the classifier produced a transition that was persisted; on `NoChange` it is `false`,
/// `state` is the unchanged durable state, and `updated_at_ms` is the record's untouched value. The
/// failure shape reuses [`AgentFailure`] (stamped `command: "agent-mark"`).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AgentMarkSuccess {
    pub ok: bool,
    pub command: &'static str,
    pub base: String,
    pub agent_task_id: String,
    /// The wire string for the task's durable state after the operation (`running`,
    /// `waiting_on_user`, `blocked`, …).
    pub state: String,
    pub changed: bool,
    /// The caller-supplied reason (echoed for both transitions and `NoChange`).
    pub reason: String,
    pub updated_at_ms: u64,
}

/// Success JSON for `agent-finish`. Reports the durable terminal outcome of an explicit transition.
/// `state` is the wire string for the terminal state (`succeeded`/`failed`/`cancelled`), `summary`
/// echoes the stored result summary (JSON null when none), and `updated_at_ms` is the record's
/// post-transition stamp. The failure shape reuses [`AgentFailure`] (stamped `command:
/// "agent-finish"`).
#[derive(Clone, Debug, Serialize, PartialEq, Eq)]
pub struct AgentFinishSuccess {
    pub ok: bool,
    pub command: &'static str,
    pub base: String,
    pub agent_task_id: String,
    /// The wire string for the task's durable terminal state (`succeeded`/`failed`/`cancelled`).
    pub state: String,
    /// The stored result summary (serialized as JSON null when absent).
    pub summary: Option<String>,
    pub updated_at_ms: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn s(v: &str) -> String {
        v.to_string()
    }

    // Pure resolver tests for `resolve_agent_window_record` / `resolve_agent_resume_window_record`.
    // These construct `AgentStartArgs` / `AgentResumeArgs` directly rather than going through the
    // `agent-start` / `agent-resume` parsers; the parser-error tests for the same flags stay in
    // `lib.rs`.

    #[test]
    fn resolve_agent_window_record_defaults_window_tab_id_title_and_pinned() {
        // Agent defaults are TASK-oriented: window "main", tab id = agent task id, title = goal,
        // pinned false. The session id only feeds the tab's session pointer (set in main.rs), not the
        // tab id.
        let a = AgentStartArgs {
            record_window: true,
            agent_task_id: Some(s("task-7")),
            ..Default::default()
        };
        assert!(a.record_window);
        assert_eq!(a.record_window_id, None);
        assert_eq!(a.record_tab_id, None);
        assert_eq!(a.record_tab_title, None);
        assert_eq!(a.record_tab_pinned, None);
        let p = resolve_agent_window_record(&a, "task-7", "do the thing").expect("record params");
        assert_eq!(p.window_id, "main");
        assert_eq!(p.tab_id, "task-7");
        assert_eq!(p.tab_title, "do the thing");
        assert!(!p.tab_pinned);
    }

    #[test]
    fn resolve_agent_window_record_tab_title_defaults_to_goal() {
        let a = AgentStartArgs {
            record_window: true,
            ..Default::default()
        };
        let p = resolve_agent_window_record(&a, "task-x", "Ship the feature").expect("params");
        assert_eq!(p.tab_id, "task-x");
        assert_eq!(p.tab_title, "Ship the feature");
    }

    #[test]
    fn resolve_agent_window_record_uses_explicit_ids_title_and_pinned() {
        let a = AgentStartArgs {
            record_window: true,
            record_window_id: Some(s("w-2")),
            record_tab_id: Some(s("t-2")),
            record_tab_title: Some(s("Build")),
            record_tab_pinned: Some(true),
            ..Default::default()
        };
        let p = resolve_agent_window_record(&a, "task-9", "ignored goal").expect("params");
        assert_eq!(p.window_id, "w-2");
        assert_eq!(p.tab_id, "t-2");
        assert_eq!(p.tab_title, "Build");
        assert!(p.tab_pinned);
    }

    #[test]
    fn resolve_agent_window_record_tab_pinned_false_resolves_unpinned() {
        let a = AgentStartArgs {
            record_window: true,
            record_tab_pinned: Some(false),
            ..Default::default()
        };
        assert_eq!(a.record_tab_pinned, Some(false));
        let p = resolve_agent_window_record(&a, "task-1", "g").expect("params");
        assert!(!p.tab_pinned);
    }

    #[test]
    fn resolve_agent_window_record_is_none_without_flag() {
        let a = AgentStartArgs {
            agent_task_id: Some(s("task-1")),
            ..Default::default()
        };
        assert!(resolve_agent_window_record(&a, "task-1", "g").is_none());
    }

    #[test]
    fn resolve_agent_resume_window_record_defaults_window_tab_id_title_and_pinned() {
        // Resume defaults match agent-start: window "main", tab id = agent task id, title = goal,
        // pinned false. The new live session id feeds the tab's session pointer (set in main.rs).
        let a = AgentResumeArgs {
            record_window: true,
            agent_task_id: Some(s("task-7")),
            ..Default::default()
        };
        assert!(a.record_window);
        assert_eq!(a.record_window_id, None);
        assert_eq!(a.record_tab_id, None);
        assert_eq!(a.record_tab_title, None);
        assert_eq!(a.record_tab_pinned, None);
        let p = resolve_agent_resume_window_record(&a, "task-7", "do the thing")
            .expect("record params");
        assert_eq!(p.window_id, "main");
        assert_eq!(p.tab_id, "task-7");
        assert_eq!(p.tab_title, "do the thing");
        assert!(!p.tab_pinned);
    }

    #[test]
    fn resolve_agent_resume_window_record_tab_title_defaults_to_goal() {
        let a = AgentResumeArgs {
            record_window: true,
            ..Default::default()
        };
        let p =
            resolve_agent_resume_window_record(&a, "task-x", "Ship the feature").expect("params");
        assert_eq!(p.tab_id, "task-x");
        assert_eq!(p.tab_title, "Ship the feature");
    }

    #[test]
    fn resolve_agent_resume_window_record_uses_explicit_ids_title_and_pinned() {
        let a = AgentResumeArgs {
            record_window: true,
            record_window_id: Some(s("w-2")),
            record_tab_id: Some(s("t-2")),
            record_tab_title: Some(s("Build")),
            record_tab_pinned: Some(true),
            ..Default::default()
        };
        let p = resolve_agent_resume_window_record(&a, "task-9", "ignored goal").expect("params");
        assert_eq!(p.window_id, "w-2");
        assert_eq!(p.tab_id, "t-2");
        assert_eq!(p.tab_title, "Build");
        assert!(p.tab_pinned);
    }

    #[test]
    fn resolve_agent_resume_window_record_tab_pinned_false_resolves_unpinned() {
        let a = AgentResumeArgs {
            record_window: true,
            record_tab_pinned: Some(false),
            ..Default::default()
        };
        assert_eq!(a.record_tab_pinned, Some(false));
        let p = resolve_agent_resume_window_record(&a, "task-1", "g").expect("params");
        assert!(!p.tab_pinned);
    }

    #[test]
    fn resolve_agent_resume_window_record_is_none_without_flag() {
        let a = AgentResumeArgs {
            agent_task_id: Some(s("task-1")),
            ..Default::default()
        };
        assert!(resolve_agent_resume_window_record(&a, "task-1", "g").is_none());
    }

    #[test]
    fn agent_success_serializes_window_record_fields_for_both_cases() {
        let plain = AgentSuccess::new(
            "agent-start",
            s("/s"),
            s("task-1"),
            s("running"),
            s("sess-1"),
            s("live"),
            None,
            true,
            true,
            None,
        );
        let v: serde_json::Value = serde_json::to_value(&plain).unwrap();
        assert_eq!(v["window_recorded"], serde_json::json!(false));
        assert_eq!(v["window_id"], serde_json::json!(null));
        assert_eq!(v["tab_id"], serde_json::json!(null));

        let recorded = plain.with_window_record(s("main"), s("task-1"));
        let v: serde_json::Value = serde_json::to_value(&recorded).unwrap();
        assert_eq!(v["window_recorded"], serde_json::json!(true));
        assert_eq!(v["window_id"], serde_json::json!("main"));
        assert_eq!(v["tab_id"], serde_json::json!("task-1"));
    }

    #[test]
    fn agent_failure_stamps_command_and_kind() {
        let v = serde_json::to_value(AgentFailure::new(
            "agent-resume",
            "agent_task_failed",
            "boom",
        ))
        .unwrap();
        assert_eq!(v["ok"], serde_json::json!(false));
        assert_eq!(v["command"], serde_json::json!("agent-resume"));
        assert_eq!(v["error_kind"], serde_json::json!("agent_task_failed"));
        assert_eq!(v["message"], serde_json::json!("boom"));
    }

    #[test]
    fn agent_success_serializes_stable_fields() {
        let v = serde_json::to_value(AgentSuccess::new(
            "agent-start",
            "/tmp/x.sock".into(),
            "t-1".into(),
            "running".into(),
            "s-1".into(),
            "live".into(),
            Some("gen-7".into()),
            true,
            true,
            None,
        ))
        .unwrap();
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["command"], serde_json::json!("agent-start"));
        assert_eq!(v["socket_path"], serde_json::json!("/tmp/x.sock"));
        assert_eq!(v["agent_task_id"], serde_json::json!("t-1"));
        assert_eq!(v["agent_task_state"], serde_json::json!("running"));
        assert_eq!(v["session_id"], serde_json::json!("s-1"));
        assert_eq!(v["session_status"], serde_json::json!("live"));
        assert_eq!(v["generation"], serde_json::json!("gen-7"));
        assert_eq!(v["daemon_started"], serde_json::json!(true));
        assert_eq!(v["daemon_kept"], serde_json::json!(true));
        assert_eq!(v["log_dir"], serde_json::Value::Null);
    }

    #[test]
    fn agent_mark_success_serializes_expected_shape() {
        let success = AgentMarkSuccess {
            ok: true,
            command: "agent-mark",
            base: "/base".to_string(),
            agent_task_id: "task-1".to_string(),
            state: "waiting_on_user".to_string(),
            changed: true,
            reason: "waiting for approval".to_string(),
            updated_at_ms: 123,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&success).unwrap()).unwrap();
        assert_eq!(v["command"], serde_json::json!("agent-mark"));
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["base"], serde_json::json!("/base"));
        assert_eq!(v["agent_task_id"], serde_json::json!("task-1"));
        assert_eq!(v["state"], serde_json::json!("waiting_on_user"));
        assert_eq!(v["changed"], serde_json::json!(true));
        assert_eq!(v["reason"], serde_json::json!("waiting for approval"));
        assert_eq!(v["updated_at_ms"], serde_json::json!(123));
    }

    #[test]
    fn agent_finish_success_serializes_expected_shape() {
        let success = AgentFinishSuccess {
            ok: true,
            command: "agent-finish",
            base: "/base".to_string(),
            agent_task_id: "task-1".to_string(),
            state: "failed".to_string(),
            summary: Some("tests failed".to_string()),
            updated_at_ms: 123,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&success).unwrap()).unwrap();
        assert_eq!(v["command"], serde_json::json!("agent-finish"));
        assert_eq!(v["ok"], serde_json::json!(true));
        assert_eq!(v["base"], serde_json::json!("/base"));
        assert_eq!(v["agent_task_id"], serde_json::json!("task-1"));
        assert_eq!(v["state"], serde_json::json!("failed"));
        assert_eq!(v["summary"], serde_json::json!("tests failed"));
        assert_eq!(v["updated_at_ms"], serde_json::json!(123));
    }

    #[test]
    fn agent_finish_success_absent_summary_serializes_null() {
        let success = AgentFinishSuccess {
            ok: true,
            command: "agent-finish",
            base: "/base".to_string(),
            agent_task_id: "task-1".to_string(),
            state: "succeeded".to_string(),
            summary: None,
            updated_at_ms: 7,
        };
        let v: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&success).unwrap()).unwrap();
        assert!(v["summary"].is_null());
    }
}
