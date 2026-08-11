//! Per-`RecordKind` row mapping between the JSON record model and the relational SQLite schema.
//!
//! The store's public seam (`store::write_record`/`load_one`/`load_all`) is generic over `T: Serialize`, keyed by
//! `RecordKind`. To keep those signatures — and thus every service + the ~188 call-sites — unchanged, we bridge the
//! generic `T` to typed SQL columns via `serde_json::Value`: serialize `T` to a Value, read the FK-bearing scalar
//! fields into columns, and store leaf sub-structs (attention, pane_rect, launch defaults, …) as JSON `TEXT`. Loading
//! reverses it: SELECT the row, rebuild the same JSON Value, and `serde_json::from_value` back into `T`.
//!
//! `WindowLayout` is special: its `tabs: Vec<TabRecord>` unwraps into the `tabs` table (one row per pane, `ON DELETE
//! CASCADE` from `windows`). Writing a layout replaces the whole tab set (matches the old "write the whole layout"
//! semantics: closed panes vanish, stashed panes persist with `stashed=1`).

use rusqlite::{Connection, OptionalExtension};
use serde_json::Value;

use crate::paths::RecordKind;

/// A row-mapping failure: a JSON column that won't parse, or a Value missing an expected field. Surfaced to the store
/// so a bad row is skipped + reported (the SQLite analog of the old file quarantine) rather than crashing a load.
#[derive(Debug)]
pub enum MapError {
    Sqlite(rusqlite::Error),
    /// The record's JSON shape didn't match what this kind's mapping expects (missing/typed-wrong field, or a JSON
    /// column that failed to deserialize).
    Shape(String),
}

impl std::fmt::Display for MapError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MapError::Sqlite(e) => write!(f, "sqlite: {e}"),
            MapError::Shape(s) => write!(f, "record shape: {s}"),
        }
    }
}
impl From<rusqlite::Error> for MapError {
    fn from(e: rusqlite::Error) -> Self {
        MapError::Sqlite(e)
    }
}

fn shape(msg: impl Into<String>) -> MapError {
    MapError::Shape(msg.into())
}

/// Read a required string field from a serialized record Value.
fn s<'a>(v: &'a Value, key: &str) -> Result<&'a str, MapError> {
    v.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| shape(format!("missing string field `{key}`")))
}
/// Read an optional string field (absent or null → None).
fn os(v: &Value, key: &str) -> Option<String> {
    v.get(key).and_then(Value::as_str).map(str::to_string)
}
/// Read a required integer (u64-ish) field.
fn i(v: &Value, key: &str) -> Result<i64, MapError> {
    v.get(key)
        .and_then(Value::as_i64)
        .ok_or_else(|| shape(format!("missing integer field `{key}`")))
}
/// Read a boolean field (absent → default false).
fn b(v: &Value, key: &str) -> bool {
    v.get(key).and_then(Value::as_bool).unwrap_or(false)
}
/// Serialize a sub-value (object/array) to a JSON string for a TEXT column; null/absent → None.
fn sub(v: &Value, key: &str) -> Option<String> {
    match v.get(key) {
        None | Some(Value::Null) => None,
        Some(other) => Some(other.to_string()),
    }
}
/// Like `sub` but required, defaulting to `default` (e.g. "[]") when absent/null.
fn sub_or(v: &Value, key: &str, default: &str) -> String {
    sub(v, key).unwrap_or_else(|| default.to_string())
}
/// Parse a JSON TEXT column back to a Value; None column → `Value::Null`.
fn parse_col(col: Option<String>) -> Result<Value, MapError> {
    match col {
        None => Ok(Value::Null),
        Some(text) => {
            serde_json::from_str(&text).map_err(|e| shape(format!("bad json column: {e}")))
        }
    }
}

/// UPSERT a record (already serialized to `record`) for `kind`/`id`. For most kinds this is one INSERT OR REPLACE; for
/// WindowLayout it also replaces the tab rows. `window_project` supplies the owning project id for a window when known
/// (windows carry no project_id in the JSON model; the caller passes it for cascade — None leaves it NULL/unassigned).
pub fn upsert(
    conn: &Connection,
    kind: RecordKind,
    id: &str,
    record: &Value,
) -> Result<(), MapError> {
    match kind {
        RecordKind::Project => {
            // ON CONFLICT DO UPDATE (in-place), NOT INSERT OR REPLACE — REPLACE is a DELETE+INSERT that would
            // CASCADE-DELETE the project's workspaces/windows/tasks/presets on every ordinary update (e.g. touch).
            conn.execute(
                "INSERT INTO projects (project_id, name, root, default_workspace_policy, created_at_ms, \
                 last_active_at_ms, icon, accent_color, launch_defaults_json, directories_json, window_order_json, \
                 system, hidden) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11,?12,?13) \
                 ON CONFLICT(project_id) DO UPDATE SET name=excluded.name, root=excluded.root, \
                 default_workspace_policy=excluded.default_workspace_policy, created_at_ms=excluded.created_at_ms, \
                 last_active_at_ms=excluded.last_active_at_ms, icon=excluded.icon, accent_color=excluded.accent_color, \
                 launch_defaults_json=excluded.launch_defaults_json, directories_json=excluded.directories_json, \
                 window_order_json=excluded.window_order_json, system=excluded.system, hidden=excluded.hidden",
                rusqlite::params![
                    id,
                    s(record, "name")?,
                    s(record, "root")?,
                    policy_str(record, "default_workspace_policy")?,
                    i(record, "created_at_ms")?,
                    i(record, "last_active_at_ms")?,
                    os(record, "icon"),
                    os(record, "accent_color"),
                    sub(record, "launch_defaults"),
                    sub_or(record, "directories", "[]"),
                    sub_or(record, "window_order", "[]"),
                    b(record, "system"),
                    b(record, "hidden"),
                ],
            )?;
        }
        RecordKind::Workspace => {
            // In-place update (not REPLACE) so re-saving a workspace doesn't cascade-delete its sessions.
            conn.execute(
                "INSERT INTO workspaces (workspace_id, project_id, root, policy, consent_json) VALUES (?1,?2,?3,?4,?5) \
                 ON CONFLICT(workspace_id) DO UPDATE SET project_id=excluded.project_id, root=excluded.root, \
                 policy=excluded.policy, consent_json=excluded.consent_json",
                rusqlite::params![
                    id,
                    s(record, "project_id")?,
                    s(record, "root")?,
                    policy_str(record, "policy")?,
                    sub_or(record, "consent", "null"),
                ],
            )?;
        }
        RecordKind::AgentTask => {
            // UPSERT via ON CONFLICT DO UPDATE (a true in-place update), NOT INSERT OR REPLACE — the latter is a
            // DELETE+INSERT that would fire `sessions.agent_task_id ON DELETE SET NULL` and orphan a live session's
            // back-reference every time a task transitions (e.g. mark_running).
            conn.execute(
                "INSERT INTO agent_tasks (agent_task_id, project_id, goal, state, current_session_id, \
                 session_history_json, created_at_ms, updated_at_ms, result_summary) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9) \
                 ON CONFLICT(agent_task_id) DO UPDATE SET project_id=excluded.project_id, goal=excluded.goal, \
                 state=excluded.state, current_session_id=excluded.current_session_id, \
                 session_history_json=excluded.session_history_json, created_at_ms=excluded.created_at_ms, \
                 updated_at_ms=excluded.updated_at_ms, result_summary=excluded.result_summary",
                rusqlite::params![
                    id,
                    s(record, "project_id")?,
                    s(record, "goal").unwrap_or(""),
                    state_str(record, "state")?,
                    os(record, "current_session_id"),
                    sub_or(record, "session_history", "[]"),
                    i(record, "created_at_ms")?,
                    i(record, "updated_at_ms").unwrap_or(0),
                    os(record, "result_summary"),
                ],
            )?;
        }
        RecordKind::Session => {
            conn.execute(
                "INSERT OR REPLACE INTO sessions (session_id, workspace_id, kind, launch_json, cwd_resolved, \
                 agent_task_id, created_at_ms, last_attached_at_ms, last_known_generation, status) \
                 VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10)",
                rusqlite::params![
                    id,
                    s(record, "workspace_id")?,
                    kind_str(record, "kind")?,
                    sub_or(record, "launch", "null"),
                    s(record, "cwd_resolved").unwrap_or(""),
                    os(record, "agent_task_id"),
                    i(record, "created_at_ms")?,
                    i(record, "last_attached_at_ms").unwrap_or(0),
                    os(record, "last_known_generation"),
                    status_str(record, "status")?,
                ],
            )?;
        }
        RecordKind::WindowLayout => {
            // Replace the whole layout in a transaction: upsert the window row, then drop + re-insert its tabs.
            let project_id: Option<&str> = record.get("project_id").and_then(Value::as_str);
            conn.execute(
                "INSERT INTO windows (window_id, project_id, name) VALUES (?1,?2,?3) \
                 ON CONFLICT(window_id) DO UPDATE SET name=excluded.name, \
                 project_id=COALESCE(excluded.project_id, windows.project_id)",
                rusqlite::params![id, project_id, os(record, "name")],
            )?;
            conn.execute("DELETE FROM tabs WHERE window_id = ?1", [id])?;
            if let Some(tabs) = record.get("tabs").and_then(Value::as_array) {
                for tab in tabs {
                    conn.execute(
                        "INSERT INTO tabs (tab_id, window_id, session_id, idx, title, pinned, stashed, attention_json, \
                         pane_rect_json, split_from_json, stashed_from_json) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
                        rusqlite::params![
                            s(tab, "tab_id")?,
                            id,
                            os(tab, "session_id"),
                            i(tab, "index").unwrap_or(0),
                            s(tab, "title").unwrap_or(""),
                            b(tab, "pinned"),
                            b(tab, "stashed"),
                            sub_or(tab, "attention", "null"),
                            sub(tab, "pane_rect"),
                            sub(tab, "split_from"),
                            sub(tab, "stashed_from"),
                        ],
                    )?;
                }
            }
        }
        RecordKind::LayoutPreset => {
            conn.execute(
                "INSERT OR REPLACE INTO layout_presets (preset_id, project_id, name, created_at_ms, tabs_json) \
                 VALUES (?1,?2,?3,?4,?5)",
                rusqlite::params![
                    id,
                    os(record, "project_id"),
                    s(record, "name").unwrap_or(""),
                    i(record, "created_at_ms").unwrap_or(0),
                    sub_or(record, "tabs", "[]"),
                ],
            )?;
        }
        RecordKind::WorktreeProvenance => {
            conn.execute(
                "INSERT OR REPLACE INTO worktree_provenance (session_id, workspace_id, repo_root, target_path, branch, \
                 created_at_ms) VALUES (?1,?2,?3,?4,?5,?6)",
                rusqlite::params![
                    id,
                    s(record, "workspace_id").unwrap_or(""),
                    s(record, "repo_root").unwrap_or(""),
                    s(record, "target_path").unwrap_or(""),
                    s(record, "branch").unwrap_or(""),
                    i(record, "created_at_ms").unwrap_or(0),
                ],
            )?;
        }
        RecordKind::DaemonEndpoint => {
            conn.execute(
                "INSERT OR REPLACE INTO daemon_endpoint (id, record_json) VALUES (?1,?2)",
                rusqlite::params![id, record.to_string()],
            )?;
        }
    }
    Ok(())
}

/// Stamp a window's owning `project_id` (the FK the cascade needs). WindowLayout carries no project_id in the record
/// model, so the app sets it here from the ownership signal (window_order). No-op if the window row doesn't exist yet.
pub fn set_window_project(
    conn: &Connection,
    window_id: &str,
    project_id: &str,
) -> Result<(), MapError> {
    conn.execute(
        "UPDATE windows SET project_id = ?2 WHERE window_id = ?1",
        rusqlite::params![window_id, project_id],
    )?;
    Ok(())
}

/// Delete a record by id. FK `ON DELETE CASCADE` removes children (a project's workspaces/sessions/windows/tabs/tasks/
/// presets; a window's tabs). Returns whether a row was actually removed (idempotent bool for the callers).
pub fn delete(conn: &Connection, kind: RecordKind, id: &str) -> Result<bool, MapError> {
    let (table_name, pk) = table(kind);
    let n = conn.execute(&format!("DELETE FROM {table_name} WHERE {pk} = ?1"), [id])?;
    Ok(n > 0)
}

/// Load ONE record by id, rebuilt as a JSON Value (the caller `from_value`s it into T). None = not present.
pub fn load_one(conn: &Connection, kind: RecordKind, id: &str) -> Result<Option<Value>, MapError> {
    match kind {
        RecordKind::WindowLayout => load_window(conn, id),
        _ => {
            let sql = single_select(kind);
            let row = conn
                .query_row(&sql, [id], |r| Ok(row_columns(r)))
                .optional()?;
            match row {
                None => Ok(None),
                Some(cols) => Ok(Some(row_to_value(kind, cols?)?)),
            }
        }
    }
}

/// Load ALL records of a kind as JSON Values.
pub fn load_all(conn: &Connection, kind: RecordKind) -> Result<Vec<Value>, MapError> {
    if kind == RecordKind::WindowLayout {
        let ids: Vec<String> = {
            let mut stmt = conn.prepare("SELECT window_id FROM windows")?;
            let rows = stmt.query_map([], |r| r.get::<_, String>(0))?;
            rows.collect::<Result<_, _>>()?
        };
        let mut out = Vec::new();
        for id in ids {
            if let Some(v) = load_window(conn, &id)? {
                out.push(v);
            }
        }
        return Ok(out);
    }
    let sql = all_select(kind);
    let mut stmt = conn.prepare(&sql)?;
    let rows: Vec<_> = stmt
        .query_map([], |r| Ok(row_columns(r)))?
        .collect::<Result<_, _>>()?;
    let mut out = Vec::with_capacity(rows.len());
    for cols in rows {
        out.push(row_to_value(kind, cols?)?);
    }
    Ok(out)
}

// ---- window (multi-table) load ----

fn load_window(conn: &Connection, id: &str) -> Result<Option<Value>, MapError> {
    let win: Option<(Option<String>, Option<String>)> = conn
        .query_row(
            "SELECT project_id, name FROM windows WHERE window_id = ?1",
            [id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let (project_id, name) = match win {
        None => return Ok(None),
        Some(w) => w,
    };
    let mut stmt = conn.prepare(
        "SELECT tab_id, session_id, idx, title, pinned, stashed, attention_json, pane_rect_json, split_from_json, \
         stashed_from_json FROM tabs WHERE window_id = ?1 ORDER BY idx",
    )?;
    let tabs: Vec<Value> = stmt
        .query_map([id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, Option<String>>(1)?,
                r.get::<_, i64>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, bool>(4)?,
                r.get::<_, bool>(5)?,
                r.get::<_, Option<String>>(6)?,
                r.get::<_, Option<String>>(7)?,
                r.get::<_, Option<String>>(8)?,
                r.get::<_, Option<String>>(9)?,
            ))
        })?
        .collect::<Result<Vec<_>, _>>()?
        .into_iter()
        .map(
            |(tab_id, session_id, idx, title, pinned, stashed, att, rect, split, sfrom)| {
                Ok(serde_json::json!({
                    "tab_id": tab_id,
                    "session_id": session_id,
                    "index": idx,
                    "title": title,
                    "pinned": pinned,
                    "stashed": stashed,
                    "attention": parse_col(att)?,
                    "pane_rect": parse_col(rect)?,
                    "split_from": parse_col(split)?,
                    "stashed_from": parse_col(sfrom)?,
                }))
            },
        )
        .collect::<Result<Vec<_>, MapError>>()?;
    Ok(Some(serde_json::json!({
        "window_id": id,
        "project_id": project_id,
        "name": name,
        "tabs": tabs,
    })))
}

// ---- generic single-table column plumbing ----

/// The columns of a fetched row, as (name, value) — we grab everything so row_to_value can rebuild the Value.
type Row = Result<Vec<(String, Value)>, MapError>;

fn row_columns(r: &rusqlite::Row) -> Row {
    let mut cols = Vec::new();
    let stmt = r.as_ref();
    for idx in 0..stmt.column_count() {
        let name = stmt.column_name(idx).unwrap_or("").to_string();
        // Fetch as the broadest type; ints/reals/text/null all map to a serde Value.
        let val: Value = match r.get_ref(idx)? {
            rusqlite::types::ValueRef::Null => Value::Null,
            rusqlite::types::ValueRef::Integer(n) => Value::from(n),
            rusqlite::types::ValueRef::Real(f) => Value::from(f),
            rusqlite::types::ValueRef::Text(t) => {
                Value::from(String::from_utf8_lossy(t).into_owned())
            }
            rusqlite::types::ValueRef::Blob(_) => Value::Null,
        };
        cols.push((name, val));
    }
    Ok(cols)
}

/// Fetch a scalar column by name from the row column list.
fn col<'a>(cols: &'a [(String, Value)], name: &str) -> &'a Value {
    cols.iter()
        .find(|(n, _)| n == name)
        .map(|(_, v)| v)
        .unwrap_or(&Value::Null)
}
/// A JSON TEXT column → its parsed Value (Null column → Null).
fn jcol(cols: &[(String, Value)], name: &str) -> Result<Value, MapError> {
    match col(cols, name) {
        Value::Null => Ok(Value::Null),
        Value::String(t) => {
            serde_json::from_str(t).map_err(|e| shape(format!("bad json column `{name}`: {e}")))
        }
        other => Ok(other.clone()),
    }
}
/// A boolean stored as INTEGER 0/1.
fn bcol(cols: &[(String, Value)], name: &str) -> Value {
    Value::from(col(cols, name).as_i64().unwrap_or(0) != 0)
}

fn row_to_value(kind: RecordKind, cols: Vec<(String, Value)>) -> Result<Value, MapError> {
    let v = match kind {
        RecordKind::Project => serde_json::json!({
            "project_id": col(&cols, "project_id"),
            "name": col(&cols, "name"),
            "root": col(&cols, "root"),
            "default_workspace_policy": jcol(&cols, "default_workspace_policy")?,
            "created_at_ms": col(&cols, "created_at_ms"),
            "last_active_at_ms": col(&cols, "last_active_at_ms"),
            "icon": col(&cols, "icon"),
            "accent_color": col(&cols, "accent_color"),
            "launch_defaults": jcol(&cols, "launch_defaults_json")?,
            "directories": jcol(&cols, "directories_json")?,
            "window_order": jcol(&cols, "window_order_json")?,
            "system": bcol(&cols, "system"),
            "hidden": bcol(&cols, "hidden"),
        }),
        RecordKind::Workspace => serde_json::json!({
            "workspace_id": col(&cols, "workspace_id"),
            "project_id": col(&cols, "project_id"),
            "root": col(&cols, "root"),
            "policy": jcol(&cols, "policy")?,
            "consent": jcol(&cols, "consent_json")?,
        }),
        RecordKind::AgentTask => serde_json::json!({
            "agent_task_id": col(&cols, "agent_task_id"),
            "project_id": col(&cols, "project_id"),
            "goal": col(&cols, "goal"),
            "state": jcol(&cols, "state")?,
            "current_session_id": col(&cols, "current_session_id"),
            "session_history": jcol(&cols, "session_history_json")?,
            "created_at_ms": col(&cols, "created_at_ms"),
            "updated_at_ms": col(&cols, "updated_at_ms"),
            "result_summary": col(&cols, "result_summary"),
        }),
        RecordKind::Session => serde_json::json!({
            "session_id": col(&cols, "session_id"),
            "workspace_id": col(&cols, "workspace_id"),
            "kind": jcol(&cols, "kind")?,
            "launch": jcol(&cols, "launch_json")?,
            "cwd_resolved": col(&cols, "cwd_resolved"),
            "agent_task_id": col(&cols, "agent_task_id"),
            "created_at_ms": col(&cols, "created_at_ms"),
            "last_attached_at_ms": col(&cols, "last_attached_at_ms"),
            "last_known_generation": col(&cols, "last_known_generation"),
            "status": jcol(&cols, "status")?,
        }),
        RecordKind::LayoutPreset => serde_json::json!({
            "preset_id": col(&cols, "preset_id"),
            "project_id": col(&cols, "project_id"),
            "name": col(&cols, "name"),
            "created_at_ms": col(&cols, "created_at_ms"),
            "tabs": jcol(&cols, "tabs_json")?,
        }),
        RecordKind::WorktreeProvenance => serde_json::json!({
            "workspace_id": col(&cols, "workspace_id"),
            "session_id": col(&cols, "session_id"),
            "repo_root": col(&cols, "repo_root"),
            "target_path": col(&cols, "target_path"),
            "branch": col(&cols, "branch"),
            "created_at_ms": col(&cols, "created_at_ms"),
        }),
        RecordKind::DaemonEndpoint => jcol(&cols, "record_json")?,
        RecordKind::WindowLayout => unreachable!("windows load via load_window"),
    };
    Ok(v)
}

// ---- per-kind SELECT sql + enum-as-string helpers ----

fn table(kind: RecordKind) -> (&'static str, &'static str) {
    match kind {
        RecordKind::Project => ("projects", "project_id"),
        RecordKind::Workspace => ("workspaces", "workspace_id"),
        RecordKind::AgentTask => ("agent_tasks", "agent_task_id"),
        RecordKind::Session => ("sessions", "session_id"),
        RecordKind::LayoutPreset => ("layout_presets", "preset_id"),
        RecordKind::WorktreeProvenance => ("worktree_provenance", "session_id"),
        RecordKind::DaemonEndpoint => ("daemon_endpoint", "id"),
        RecordKind::WindowLayout => ("windows", "window_id"),
    }
}
fn single_select(kind: RecordKind) -> String {
    let (t, pk) = table(kind);
    format!("SELECT * FROM {t} WHERE {pk} = ?1")
}
fn all_select(kind: RecordKind) -> String {
    let (t, _) = table(kind);
    format!("SELECT * FROM {t}")
}

/// Enum/tag fields serialize either as a bare string ("scratch_cwd") or a tagged object. Store the RAW serialized form
/// (string or JSON) so it round-trips exactly; on load `jcol` re-parses. These helpers return the TEXT to store.
fn policy_str(v: &Value, key: &str) -> Result<String, MapError> {
    raw_tag(v, key)
}
fn state_str(v: &Value, key: &str) -> Result<String, MapError> {
    raw_tag(v, key)
}
fn kind_str(v: &Value, key: &str) -> Result<String, MapError> {
    raw_tag(v, key)
}
fn status_str(v: &Value, key: &str) -> Result<String, MapError> {
    raw_tag(v, key)
}
/// Serialize a tag field to the TEXT we store: a bare string stays a JSON string ("\"x\""), an object stays JSON — so
/// the load-side `jcol` parse rebuilds the exact same Value either way.
fn raw_tag(v: &Value, key: &str) -> Result<String, MapError> {
    match v.get(key) {
        None | Some(Value::Null) => Err(shape(format!("missing tag field `{key}`"))),
        Some(other) => Ok(other.to_string()),
    }
}
