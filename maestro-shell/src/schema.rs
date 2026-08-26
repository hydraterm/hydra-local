//! The relational schema and ordered migrations for the local SQLite store.
//!
//! Version 1 is the initial relational schema. Later schema changes are appended to
//! [`MIGRATIONS`] as one-step transitions; opening the database applies the ordered chain under an
//! immediate transaction. A database stamped by a newer build is rejected before any schema DDL.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};

const INITIAL_SCHEMA_VERSION: i64 = 1;

/// One append-only schema transition.
struct Migration {
    from: i64,
    to: i64,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[
    Migration {
        from: 1,
        to: 2,
        sql: V2_DDL,
    },
    Migration {
        from: 2,
        to: 3,
        sql: V3_DDL,
    },
];

/// A schema cannot be initialized or upgraded safely.
#[derive(Debug)]
pub enum SchemaError {
    Sqlite(rusqlite::Error),
    FutureVersion { db: i64, ours: i64 },
    MissingVersion,
    InvalidVersion { value: String },
    MigrationGap { from: i64, target: i64 },
    InvalidMigration { from: i64, to: i64 },
    IntegrityCheck { check: &'static str, detail: String },
}

impl std::fmt::Display for SchemaError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SchemaError::Sqlite(error) => write!(f, "sqlite error: {error}"),
            SchemaError::FutureVersion { db, ours } => write!(
                f,
                "local database schema v{db} was written by a newer Maestro (this build supports v{ours}); left untouched"
            ),
            SchemaError::MissingVersion => {
                write!(f, "local database has data but no schema version; left untouched")
            }
            SchemaError::InvalidVersion { value } => write!(
                f,
                "local database has invalid schema version {value:?}; left untouched"
            ),
            SchemaError::MigrationGap { from, target } => write!(
                f,
                "no ordered local database migration from schema v{from} toward v{target}"
            ),
            SchemaError::InvalidMigration { from, to } => write!(
                f,
                "invalid local database migration v{from} -> v{to}; transitions must advance exactly one version"
            ),
            SchemaError::IntegrityCheck { check, detail } => {
                write!(f, "local database {check} failed after upgrade: {detail}")
            }
        }
    }
}

impl std::error::Error for SchemaError {}

impl From<rusqlite::Error> for SchemaError {
    fn from(error: rusqlite::Error) -> Self {
        SchemaError::Sqlite(error)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SchemaState {
    Fresh,
    Version(i64),
}

/// Initialize or migrate the schema to this binary's version.
///
/// The first inspection deliberately happens before `BEGIN IMMEDIATE`: malformed and future
/// databases return without schema mutation. The second inspection happens after the write lock is
/// acquired, so concurrent local-writer opens cannot both apply the same transition.
pub fn ensure_schema(conn: &mut Connection) -> Result<(), SchemaError> {
    ensure_schema_to(conn, crate::db::DB_SCHEMA_VERSION, MIGRATIONS)
}

/// Read-only compatibility preflight used before the shared database is opened for writes.
///
/// `true` means the caller must acquire the process-wide schema lease exclusively and call
/// [`ensure_schema`]. `false` means the database is already at this binary's exact version and may
/// be opened while retaining a shared lease. Future and malformed versions fail before a
/// read-write SQLite connection is created.
pub(crate) fn schema_requires_write(conn: &Connection) -> Result<bool, SchemaError> {
    let state = inspect_schema(conn)?;
    validate_state(state, crate::db::DB_SCHEMA_VERSION)?;
    Ok(match state {
        SchemaState::Fresh => true,
        SchemaState::Version(version) => version < crate::db::DB_SCHEMA_VERSION,
    })
}

fn ensure_schema_to(
    conn: &mut Connection,
    target: i64,
    migrations: &[Migration],
) -> Result<(), SchemaError> {
    validate_state(inspect_schema(conn)?, target)?;

    let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
    let state = inspect_schema(&tx)?;
    validate_state(state, target)?;

    let mut version = match state {
        SchemaState::Fresh => {
            tx.execute_batch(V1_DDL)?;
            tx.execute(
                "INSERT INTO schema_meta (id, version) VALUES (1, ?1)",
                [INITIAL_SCHEMA_VERSION],
            )?;
            INITIAL_SCHEMA_VERSION
        }
        SchemaState::Version(version) => version,
    };

    let changed = state == SchemaState::Fresh || version < target;
    while version < target {
        let migration = migrations
            .iter()
            .find(|migration| migration.from == version)
            .ok_or(SchemaError::MigrationGap {
                from: version,
                target,
            })?;
        if migration.to != migration.from + 1 || migration.to > target {
            return Err(SchemaError::InvalidMigration {
                from: migration.from,
                to: migration.to,
            });
        }

        tx.execute_batch(migration.sql)?;
        let updated = tx.execute(
            "UPDATE schema_meta SET version = ?1 WHERE id = 1 AND version = ?2",
            [migration.to, migration.from],
        )?;
        if updated != 1 {
            return Err(SchemaError::MigrationGap {
                from: version,
                target,
            });
        }
        version = migration.to;
    }

    if changed {
        validate_integrity(&tx)?;
    }
    tx.commit()?;
    Ok(())
}

fn validate_state(state: SchemaState, target: i64) -> Result<(), SchemaError> {
    if let SchemaState::Version(version) = state {
        if version > target {
            return Err(SchemaError::FutureVersion {
                db: version,
                ours: target,
            });
        }
    }
    Ok(())
}

/// Distinguish a truly empty database from an existing database whose version metadata is absent or
/// malformed. We never guess the version of a non-empty database.
fn inspect_schema(conn: &Connection) -> Result<SchemaState, SchemaError> {
    let meta_exists: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = 'schema_meta')",
        [],
        |row| row.get(0),
    )?;

    if !meta_exists {
        let application_objects: i64 = conn.query_row(
            "SELECT COUNT(*) FROM sqlite_schema WHERE name NOT LIKE 'sqlite_%'",
            [],
            |row| row.get(0),
        )?;
        return if application_objects == 0 {
            Ok(SchemaState::Fresh)
        } else {
            Err(SchemaError::MissingVersion)
        };
    }

    let row: Option<(String, String)> = conn
        .query_row(
            "SELECT typeof(version), CAST(version AS TEXT) FROM schema_meta WHERE id = 1",
            [],
            |row| Ok((row.get(0)?, row.get(1)?)),
        )
        .optional()
        .map_err(|error| match error {
            rusqlite::Error::SqliteFailure(_, Some(message))
                if message.contains("no such column") =>
            {
                SchemaError::InvalidVersion { value: message }
            }
            other => SchemaError::Sqlite(other),
        })?;

    let Some((kind, value)) = row else {
        return Err(SchemaError::MissingVersion);
    };
    let row_count: i64 =
        conn.query_row("SELECT COUNT(*) FROM schema_meta", [], |row| row.get(0))?;
    if row_count != 1 {
        return Err(SchemaError::InvalidVersion {
            value: format!("{row_count} schema_meta rows"),
        });
    }
    if kind != "integer" {
        return Err(SchemaError::InvalidVersion { value });
    }
    let version = value
        .parse::<i64>()
        .map_err(|_| SchemaError::InvalidVersion {
            value: value.clone(),
        })?;
    if version < INITIAL_SCHEMA_VERSION {
        return Err(SchemaError::InvalidVersion { value });
    }
    Ok(SchemaState::Version(version))
}

fn validate_integrity(tx: &Transaction<'_>) -> Result<(), SchemaError> {
    let quick_check: String = tx.query_row("PRAGMA quick_check", [], |row| row.get(0))?;
    if quick_check != "ok" {
        return Err(SchemaError::IntegrityCheck {
            check: "quick_check",
            detail: quick_check,
        });
    }

    let mut statement = tx.prepare("PRAGMA foreign_key_check")?;
    let mut rows = statement.query([])?;
    if let Some(row) = rows.next()? {
        let table: String = row.get(0)?;
        let row_id: Option<i64> = row.get(1)?;
        let parent: String = row.get(2)?;
        return Err(SchemaError::IntegrityCheck {
            check: "foreign_key_check",
            detail: format!("table={table} rowid={row_id:?} parent={parent}"),
        });
    }
    Ok(())
}

/// Version 1's full schema. Foreign-key columns declare `ON DELETE CASCADE` (or `SET NULL` where
/// the child should outlive its parent link).
const V1_DDL: &str = r#"
CREATE TABLE schema_meta (
    id      INTEGER PRIMARY KEY CHECK (id = 1),
    version INTEGER NOT NULL
);

CREATE TABLE projects (
    project_id               TEXT PRIMARY KEY,
    name                     TEXT NOT NULL,
    root                     TEXT NOT NULL,
    default_workspace_policy TEXT NOT NULL,
    created_at_ms            INTEGER NOT NULL,
    last_active_at_ms        INTEGER NOT NULL,
    icon                     TEXT,
    accent_color             TEXT,
    launch_defaults_json     TEXT,
    directories_json         TEXT NOT NULL DEFAULT '[]',
    window_order_json        TEXT NOT NULL DEFAULT '[]',
    system                   INTEGER NOT NULL DEFAULT 0,
    hidden                   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE workspaces (
    workspace_id TEXT PRIMARY KEY,
    project_id   TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    root         TEXT NOT NULL,
    policy       TEXT NOT NULL,
    consent_json TEXT NOT NULL
);
CREATE INDEX idx_workspaces_project ON workspaces(project_id);

CREATE TABLE agent_tasks (
    agent_task_id        TEXT PRIMARY KEY,
    project_id           TEXT NOT NULL REFERENCES projects(project_id) ON DELETE CASCADE,
    goal                 TEXT NOT NULL,
    state                TEXT NOT NULL,
    current_session_id   TEXT,
    session_history_json TEXT NOT NULL DEFAULT '[]',
    created_at_ms        INTEGER NOT NULL,
    updated_at_ms        INTEGER NOT NULL,
    result_summary       TEXT
);
CREATE INDEX idx_agent_tasks_project ON agent_tasks(project_id);

CREATE TABLE sessions (
    session_id            TEXT PRIMARY KEY,
    workspace_id          TEXT NOT NULL REFERENCES workspaces(workspace_id) ON DELETE CASCADE,
    kind                  TEXT NOT NULL,
    launch_json           TEXT NOT NULL,
    cwd_resolved          TEXT NOT NULL,
    agent_task_id         TEXT REFERENCES agent_tasks(agent_task_id) ON DELETE SET NULL,
    created_at_ms         INTEGER NOT NULL,
    last_attached_at_ms   INTEGER NOT NULL,
    last_known_generation TEXT,
    status                TEXT NOT NULL
);
CREATE INDEX idx_sessions_workspace ON sessions(workspace_id);

CREATE TABLE windows (
    window_id  TEXT PRIMARY KEY,
    project_id TEXT REFERENCES projects(project_id) ON DELETE CASCADE,
    name       TEXT
);
CREATE INDEX idx_windows_project ON windows(project_id);

-- tab_id is unique WITHIN a window, not globally.
CREATE TABLE tabs (
    window_id         TEXT NOT NULL REFERENCES windows(window_id) ON DELETE CASCADE,
    tab_id            TEXT NOT NULL,
    session_id        TEXT,
    idx               INTEGER NOT NULL,
    title             TEXT NOT NULL,
    pinned            INTEGER NOT NULL DEFAULT 0,
    stashed           INTEGER NOT NULL DEFAULT 0,
    attention_json    TEXT NOT NULL,
    pane_rect_json    TEXT,
    split_from_json   TEXT,
    stashed_from_json TEXT,
    PRIMARY KEY (window_id, tab_id)
);
CREATE INDEX idx_tabs_window ON tabs(window_id);

CREATE TABLE layout_presets (
    preset_id     TEXT PRIMARY KEY,
    project_id    TEXT REFERENCES projects(project_id) ON DELETE CASCADE,
    name          TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    tabs_json     TEXT NOT NULL DEFAULT '[]'
);
CREATE INDEX idx_layout_presets_project ON layout_presets(project_id);

CREATE TABLE worktree_provenance (
    session_id    TEXT PRIMARY KEY,
    workspace_id  TEXT NOT NULL,
    repo_root     TEXT NOT NULL,
    target_path   TEXT NOT NULL,
    branch        TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL
);

CREATE TABLE daemon_endpoint (
    id          TEXT PRIMARY KEY,
    record_json TEXT NOT NULL
);

CREATE TABLE session_names (
    key         TEXT PRIMARY KEY,
    custom_name TEXT,
    hidden      INTEGER NOT NULL DEFAULT 0
);
"#;

/// Version 2 adds a content-blind, forward-only journal for generation-fenced PTY release.
///
/// Operations carry only scheduling and short-lived lease metadata. Targets retain the exact PTY
/// identity needed to make a crash-safe release decision; they never contain terminal output,
/// commands, cwd values, or user-authored diagnostics.
const V2_DDL: &str = r#"
CREATE TABLE session_release_operations (
    operation_id  TEXT PRIMARY KEY
                  CHECK (typeof(operation_id) = 'text' AND length(operation_id) = 36),
    created_at_ms INTEGER NOT NULL
                  CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    lease_token   TEXT
                  CHECK (lease_token IS NULL OR
                         (typeof(lease_token) = 'text' AND length(lease_token) = 36)),
    lease_until_ms INTEGER
                  CHECK (lease_until_ms IS NULL OR
                         (typeof(lease_until_ms) = 'integer' AND lease_until_ms >= 0)),
    CHECK ((lease_token IS NULL AND lease_until_ms IS NULL) OR
           (lease_token IS NOT NULL AND lease_until_ms IS NOT NULL))
);
CREATE INDEX idx_session_release_operations_claim
    ON session_release_operations(lease_until_ms, created_at_ms, operation_id);

CREATE TABLE pending_session_releases (
    operation_id       TEXT NOT NULL
                       REFERENCES session_release_operations(operation_id) ON DELETE CASCADE,
    session_id         TEXT NOT NULL
                       CHECK (typeof(session_id) = 'text' AND
                              length(session_id) BETWEEN 1 AND 128),
    expected_generation TEXT NOT NULL
                       CHECK (typeof(expected_generation) = 'text' AND
                              length(expected_generation) BETWEEN 1 AND 128),
    row_expectation    TEXT NOT NULL
                       CHECK (typeof(row_expectation) = 'text' AND
                              row_expectation IN ('matching_row_is_proof', 'row_must_be_absent')),
    created_at_ms      INTEGER NOT NULL
                       CHECK (typeof(created_at_ms) = 'integer' AND created_at_ms >= 0),
    PRIMARY KEY (operation_id, session_id)
);
CREATE INDEX idx_pending_session_releases_session
    ON pending_session_releases(session_id);

CREATE TRIGGER trg_pending_session_releases_operation_cap
BEFORE INSERT ON pending_session_releases
WHEN (SELECT COUNT(*)
      FROM pending_session_releases
      WHERE operation_id = NEW.operation_id) >= 4096
BEGIN
    SELECT RAISE(ABORT, 'session release operation exceeds 4096 pending rows');
END;

CREATE TRIGGER trg_pending_session_releases_operation_move_cap
BEFORE UPDATE OF operation_id ON pending_session_releases
WHEN NEW.operation_id <> OLD.operation_id AND
     (SELECT COUNT(*)
      FROM pending_session_releases
      WHERE operation_id = NEW.operation_id) >= 4096
BEGIN
    SELECT RAISE(ABORT, 'session release operation exceeds 4096 pending rows');
END;

CREATE TRIGGER trg_pending_session_releases_global_cap
BEFORE INSERT ON pending_session_releases
WHEN (SELECT COUNT(*) FROM pending_session_releases) >= 16384
BEGIN
    SELECT RAISE(ABORT, 'session release journal exceeds 16384 pending rows');
END;
"#;

/// Version 3 adds the crash-recoverable authority journal for one prepared AgentTask Start.
///
/// The row contains no command, argv, cwd, environment, task goal/result, terminal bytes, or
/// renderer state. Exact record fingerprints bind the persisted A graph, while the already-safe
/// publication LaunchSpec is the only successor payload that cannot be derived from A after a
/// provider A -> B transition. The operation token and daemon identity are opaque control data and
/// are never rendered by product diagnostics.
const V3_DDL: &str = r#"
CREATE TABLE pending_agent_task_starts (
    session_id          TEXT PRIMARY KEY
                        REFERENCES sessions(session_id) ON DELETE RESTRICT
                        CHECK (typeof(session_id) = 'text' AND
                               length(session_id) BETWEEN 1 AND 128),
    agent_task_id       TEXT NOT NULL UNIQUE
                        REFERENCES agent_tasks(agent_task_id) ON DELETE RESTRICT
                        CHECK (typeof(agent_task_id) = 'text' AND
                               length(agent_task_id) BETWEEN 1 AND 128),
    project_id          TEXT NOT NULL
                        REFERENCES projects(project_id) ON DELETE RESTRICT
                        CHECK (typeof(project_id) = 'text' AND
                               length(project_id) BETWEEN 1 AND 128),
    workspace_id        TEXT NOT NULL
                        REFERENCES workspaces(workspace_id) ON DELETE RESTRICT
                        CHECK (typeof(workspace_id) = 'text' AND
                               length(workspace_id) BETWEEN 1 AND 128),
    operation_token     TEXT NOT NULL UNIQUE
                        CHECK (typeof(operation_token) = 'text' AND
                               length(operation_token) = 32 AND
                               operation_token NOT GLOB '*[^0-9a-f]*' AND
                               substr(operation_token, 13, 1) = '4' AND
                               substr(operation_token, 17, 1) IN ('8', '9', 'a', 'b')),
    binding_state       TEXT NOT NULL DEFAULT 'unbound'
                        CHECK (typeof(binding_state) = 'text' AND
                               binding_state IN ('unbound', 'bound')),
    daemon_instance_id  TEXT
                        CHECK (daemon_instance_id IS NULL OR
                               (typeof(daemon_instance_id) = 'text' AND
                                length(daemon_instance_id) = 32 AND
                                daemon_instance_id NOT GLOB '*[^0-9a-f]*' AND
                                substr(daemon_instance_id, 13, 1) = '4' AND
                                substr(daemon_instance_id, 17, 1) IN ('8', '9', 'a', 'b'))),
    server_pid          INTEGER
                        CHECK (server_pid IS NULL OR
                               (typeof(server_pid) = 'integer' AND
                                server_pid BETWEEN 1 AND 4294967295)),
    socket_path         TEXT
                        CHECK (socket_path IS NULL OR
                               (typeof(socket_path) = 'text' AND
                                length(socket_path) BETWEEN 1 AND 4096 AND
                                instr(socket_path, char(0)) = 0)),
    session_a_sha256    BLOB NOT NULL
                        CHECK (typeof(session_a_sha256) = 'blob' AND
                               length(session_a_sha256) = 32),
    task_a_sha256       BLOB NOT NULL
                        CHECK (typeof(task_a_sha256) = 'blob' AND
                               length(task_a_sha256) = 32),
    project_sha256      BLOB NOT NULL
                        CHECK (typeof(project_sha256) = 'blob' AND
                               length(project_sha256) = 32),
    workspace_sha256    BLOB NOT NULL
                        CHECK (typeof(workspace_sha256) = 'blob' AND
                               length(workspace_sha256) = 32),
    publication_launch_json TEXT NOT NULL
                        CHECK (typeof(publication_launch_json) = 'text' AND
                               length(publication_launch_json) BETWEEN 2 AND 65536 AND
                               json_valid(publication_launch_json) = 1),
    publication_now_ms  INTEGER NOT NULL
                        CHECK (typeof(publication_now_ms) = 'integer' AND
                               publication_now_ms >= 0),
    disposition         TEXT NOT NULL DEFAULT 'finalize'
                        CHECK (typeof(disposition) = 'text' AND
                               disposition IN ('finalize', 'release')),
    applied_generation  TEXT
                        CHECK (applied_generation IS NULL OR
                               (typeof(applied_generation) = 'text' AND
                                length(applied_generation) BETWEEN 1 AND 128)),
    applied_state       TEXT
                        CHECK (applied_state IS NULL OR
                               (typeof(applied_state) = 'text' AND
                                applied_state IN ('live', 'exited', 'removed'))),
    created_at_ms       INTEGER NOT NULL
                        CHECK (typeof(created_at_ms) = 'integer' AND
                               created_at_ms >= 0),
    lease_token         TEXT
                        CHECK (lease_token IS NULL OR
                               (typeof(lease_token) = 'text' AND
                                length(lease_token) = 36)),
    lease_until_ms      INTEGER
                        CHECK (lease_until_ms IS NULL OR
                               (typeof(lease_until_ms) = 'integer' AND
                                lease_until_ms >= 0)),
    CHECK ((lease_token IS NULL AND lease_until_ms IS NULL) OR
           (lease_token IS NOT NULL AND lease_until_ms IS NOT NULL)),
    CHECK ((binding_state = 'unbound' AND daemon_instance_id IS NULL AND
            server_pid IS NULL AND socket_path IS NULL) OR
           (binding_state = 'bound' AND daemon_instance_id IS NOT NULL AND
            socket_path IS NOT NULL)),
    CHECK ((applied_generation IS NULL AND applied_state IS NULL) OR
           (applied_generation IS NOT NULL AND applied_state IS NOT NULL)),
    CHECK (binding_state = 'bound' OR applied_generation IS NULL),
    CHECK (disposition = 'finalize' OR applied_generation IS NOT NULL)
);
CREATE INDEX idx_pending_agent_task_starts_claim
    ON pending_agent_task_starts(lease_until_ms, created_at_ms, session_id);

CREATE TRIGGER trg_pending_agent_task_starts_cap
BEFORE INSERT ON pending_agent_task_starts
WHEN (SELECT COUNT(*) FROM pending_agent_task_starts) >= 4096
BEGIN
    SELECT RAISE(ABORT, 'agent task start journal exceeds 4096 rows');
END;

CREATE TRIGGER trg_pending_agent_task_starts_relational_bind
BEFORE INSERT ON pending_agent_task_starts
WHEN NOT EXISTS (
    SELECT 1 FROM sessions s
    JOIN workspaces w ON w.workspace_id = s.workspace_id
    JOIN agent_tasks t ON t.agent_task_id = s.agent_task_id
    WHERE s.session_id = NEW.session_id
      AND s.workspace_id = NEW.workspace_id
      AND s.agent_task_id = NEW.agent_task_id
      AND w.project_id = NEW.project_id
      AND t.project_id = NEW.project_id
)
BEGIN
    SELECT RAISE(ABORT, 'agent task start journal graph identity mismatch');
END;

CREATE TRIGGER trg_pending_agent_task_starts_immutable_core
BEFORE UPDATE OF session_id, agent_task_id, project_id, workspace_id, operation_token,
                 session_a_sha256, task_a_sha256, project_sha256, workspace_sha256,
                 publication_launch_json, publication_now_ms, created_at_ms
ON pending_agent_task_starts
BEGIN
    SELECT RAISE(ABORT, 'agent task start journal authority is immutable');
END;

CREATE TRIGGER trg_pending_agent_task_starts_bind_once
BEFORE UPDATE OF binding_state, daemon_instance_id, server_pid, socket_path
ON pending_agent_task_starts
WHEN NOT (OLD.binding_state = 'unbound' AND NEW.binding_state = 'bound' AND
          OLD.daemon_instance_id IS NULL AND NEW.daemon_instance_id IS NOT NULL AND
          OLD.server_pid IS NULL AND NEW.socket_path IS NOT NULL AND
          OLD.socket_path IS NULL)
BEGIN
    SELECT RAISE(ABORT, 'agent task start journal peer binding is one-way');
END;

CREATE TRIGGER trg_pending_agent_task_starts_applied_monotone
BEFORE UPDATE OF applied_generation, applied_state
ON pending_agent_task_starts
WHEN NOT (
    (OLD.applied_generation IS NULL AND OLD.applied_state IS NULL AND
     ((NEW.applied_generation IS NULL AND NEW.applied_state IS NULL) OR
      (NEW.applied_generation IS NOT NULL AND NEW.applied_state IS NOT NULL))) OR
    (OLD.applied_generation IS NOT NULL AND
     NEW.applied_generation IS OLD.applied_generation AND
     (NEW.applied_state IS OLD.applied_state OR
      (OLD.applied_state = 'live' AND NEW.applied_state IN ('exited', 'removed')) OR
      (OLD.applied_state = 'exited' AND NEW.applied_state = 'removed')))
)
BEGIN
    SELECT RAISE(ABORT, 'agent task start journal applied state is reverse or generation-changing');
END;

CREATE TRIGGER trg_pending_agent_task_starts_disposition_monotone
BEFORE UPDATE OF disposition ON pending_agent_task_starts
WHEN NOT (NEW.disposition = OLD.disposition OR
          (OLD.disposition = 'finalize' AND NEW.disposition = 'release'))
BEGIN
    SELECT RAISE(ABORT, 'agent task start journal disposition is forward-only');
END;
"#;

#[cfg(test)]
mod tests {
    use super::*;

    const OPERATION_A: &str = "00000000-0000-4000-8000-000000000001";
    const OPERATION_B: &str = "00000000-0000-4000-8000-000000000002";
    const OPERATION_C: &str = "00000000-0000-4000-8000-000000000003";
    const OPERATION_D: &str = "00000000-0000-4000-8000-000000000004";
    const OPERATION_E: &str = "00000000-0000-4000-8000-000000000005";
    const LEASE_A: &str = "10000000-0000-4000-8000-000000000001";
    const START_TOKEN_A: &str = "00000000000040008000000000000001";
    const START_TOKEN_B: &str = "00000000000040008000000000000002";
    const START_TOKEN_C: &str = "00000000000040008000000000000003";
    const DAEMON_INSTANCE_A: &str = "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaa";
    const GENERATION_A: &str = "generation-a";
    const GENERATION_B: &str = "generation-b";

    fn version(conn: &Connection) -> i64 {
        conn.query_row("SELECT version FROM schema_meta WHERE id = 1", [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    fn initialize_v1(conn: &mut Connection) {
        ensure_schema_to(conn, 1, &[]).unwrap();
        assert_eq!(version(conn), 1);
    }

    fn initialize_v2(conn: &mut Connection) {
        ensure_schema_to(conn, 2, MIGRATIONS).unwrap();
        assert_eq!(version(conn), 2);
    }

    fn insert_agent_task_start_graph(conn: &Connection, suffix: &str) {
        let project_id = format!("project-{suffix}");
        let workspace_id = format!("workspace-{suffix}");
        let task_id = format!("task-{suffix}");
        let session_id = format!("session-{suffix}");
        conn.execute(
            "INSERT INTO projects \
             (project_id, name, root, default_workspace_policy, created_at_ms, last_active_at_ms) \
             VALUES (?1, 'Project', '/root', 'scratch_cwd', 1, 1)",
            [&project_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workspaces (workspace_id, project_id, root, policy, consent_json) \
             VALUES (?1, ?2, '/root', 'scratch_cwd', '{}')",
            rusqlite::params![workspace_id, project_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO agent_tasks \
             (agent_task_id, project_id, goal, state, current_session_id, \
              session_history_json, created_at_ms, updated_at_ms) \
             VALUES (?1, ?2, 'goal', 'Draft', ?3, '[]', 1, 1)",
            rusqlite::params![task_id, project_id, session_id],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO sessions \
             (session_id, workspace_id, kind, launch_json, cwd_resolved, agent_task_id, \
              created_at_ms, last_attached_at_ms, last_known_generation, status) \
             VALUES (?1, ?2, 'shell', '{}', '/root', ?3, 1, 1, NULL, 'Unknown')",
            rusqlite::params![session_id, workspace_id, task_id],
        )
        .unwrap();
    }

    #[allow(clippy::too_many_arguments)]
    fn insert_pending_agent_task_start_with_state(
        conn: &Connection,
        suffix: &str,
        operation_token: &str,
        binding_state: &str,
        daemon_instance_id: Option<&str>,
        server_pid: Option<i64>,
        socket_path: Option<&str>,
        disposition: &str,
        applied_generation: Option<&str>,
        applied_state: Option<&str>,
        lease_token: Option<&str>,
        lease_until_ms: Option<i64>,
    ) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO pending_agent_task_starts \
             (session_id, agent_task_id, project_id, workspace_id, operation_token, \
              binding_state, daemon_instance_id, server_pid, socket_path, session_a_sha256, \
              task_a_sha256, project_sha256, workspace_sha256, publication_launch_json, \
              publication_now_ms, disposition, applied_generation, applied_state, created_at_ms, \
              lease_token, lease_until_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, zeroblob(32), zeroblob(32), \
                     zeroblob(32), zeroblob(32), '{}', 1, ?10, ?11, ?12, 1, ?13, ?14)",
            rusqlite::params![
                format!("session-{suffix}"),
                format!("task-{suffix}"),
                format!("project-{suffix}"),
                format!("workspace-{suffix}"),
                operation_token,
                binding_state,
                daemon_instance_id,
                server_pid,
                socket_path,
                disposition,
                applied_generation,
                applied_state,
                lease_token,
                lease_until_ms,
            ],
        )
    }

    fn insert_unbound_agent_task_start(conn: &Connection, suffix: &str, operation_token: &str) {
        insert_agent_task_start_graph(conn, suffix);
        insert_pending_agent_task_start_with_state(
            conn,
            suffix,
            operation_token,
            "unbound",
            None,
            None,
            None,
            "finalize",
            None,
            None,
            None,
            None,
        )
        .unwrap();
    }

    fn bind_agent_task_start(conn: &Connection, suffix: &str) {
        conn.execute(
            "UPDATE pending_agent_task_starts \
             SET binding_state = 'bound', daemon_instance_id = ?1, server_pid = 7, \
                 socket_path = '/tmp/pty.sock' \
             WHERE session_id = ?2",
            rusqlite::params![DAEMON_INSTANCE_A, format!("session-{suffix}")],
        )
        .unwrap();
    }

    fn set_agent_task_start_applied(
        conn: &Connection,
        suffix: &str,
        generation: &str,
        state: &str,
    ) -> rusqlite::Result<usize> {
        conn.execute(
            "UPDATE pending_agent_task_starts \
             SET applied_generation = ?1, applied_state = ?2 \
             WHERE session_id = ?3",
            rusqlite::params![generation, state, format!("session-{suffix}")],
        )
    }

    fn start_token(value: usize) -> String {
        format!("00000000000040008000{value:012x}")
    }

    fn table_exists(conn: &Connection, table: &str) -> bool {
        conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE type = 'table' AND name = ?1)",
            [table],
            |row| row.get(0),
        )
        .unwrap()
    }

    fn table_column_names(conn: &Connection, table: &str) -> Vec<String> {
        let mut statement = conn
            .prepare(&format!("PRAGMA table_info({table})"))
            .unwrap();
        statement
            .query_map([], |row| row.get(1))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn index_column_names(conn: &Connection, index: &str) -> Vec<String> {
        let mut statement = conn
            .prepare(&format!("PRAGMA index_info({index})"))
            .unwrap();
        statement
            .query_map([], |row| row.get(2))
            .unwrap()
            .collect::<Result<Vec<_>, _>>()
            .unwrap()
    }

    fn insert_operation(conn: &Connection, operation_id: &str) {
        conn.execute(
            "INSERT INTO session_release_operations \
             (operation_id, created_at_ms, lease_token, lease_until_ms) \
             VALUES (?1, 1, NULL, NULL)",
            [operation_id],
        )
        .unwrap();
    }

    fn insert_pending_rows(conn: &mut Connection, operation_id: &str, count: usize) {
        let tx = conn.transaction().unwrap();
        {
            let mut statement = tx
                .prepare(
                    "INSERT INTO pending_session_releases \
                     (operation_id, session_id, expected_generation, row_expectation, created_at_ms) \
                     VALUES (?1, ?2, ?3, 'row_must_be_absent', ?4)",
                )
                .unwrap();
            for value in 0..count {
                statement
                    .execute(rusqlite::params![
                        operation_id,
                        format!("session-{value}"),
                        format!("generation-{value}"),
                        value as i64,
                    ])
                    .unwrap();
            }
        }
        tx.commit().unwrap();
    }

    #[test]
    fn fresh_schema_is_transactional_and_stamped_v3() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();
        assert_eq!(version(&conn), crate::db::DB_SCHEMA_VERSION);
        assert!(table_exists(&conn, "session_release_operations"));
        assert!(table_exists(&conn, "pending_session_releases"));
        assert!(table_exists(&conn, "pending_agent_task_starts"));
        assert_eq!(
            conn.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
    }

    #[test]
    fn reopening_current_schema_is_idempotent() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO projects (project_id, name, root, default_workspace_policy, created_at_ms, last_active_at_ms) \
             VALUES ('keep','Keep','/r','scratch_cwd',1,1)",
            [],
        )
        .unwrap();
        ensure_schema(&mut conn).unwrap();
        let count: i64 = conn
            .query_row(
                "SELECT COUNT(*) FROM projects WHERE project_id='keep'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(count, 1);
        assert_eq!(version(&conn), crate::db::DB_SCHEMA_VERSION);
    }

    #[test]
    fn v1_database_migrates_through_v3_without_rewriting_existing_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        initialize_v1(&mut conn);
        conn.execute(
            "INSERT INTO projects (project_id, name, root, default_workspace_policy, created_at_ms, last_active_at_ms) \
             VALUES ('keep','Keep','/r','scratch_cwd',1,1)",
            [],
        )
        .unwrap();
        assert!(!table_exists(&conn, "session_release_operations"));

        ensure_schema(&mut conn).unwrap();

        assert_eq!(version(&conn), crate::db::DB_SCHEMA_VERSION);
        assert_eq!(
            conn.query_row(
                "SELECT name FROM projects WHERE project_id = 'keep'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "Keep"
        );
        assert!(table_exists(&conn, "session_release_operations"));
        assert!(table_exists(&conn, "pending_session_releases"));
        assert!(table_exists(&conn, "pending_agent_task_starts"));
    }

    #[test]
    fn v2_database_migrates_to_v3_without_rewriting_existing_rows() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        initialize_v2(&mut conn);
        conn.execute(
            "INSERT INTO projects \
             (project_id, name, root, default_workspace_policy, created_at_ms, last_active_at_ms) \
             VALUES ('keep', 'Keep', '/r', 'scratch_cwd', 1, 1)",
            [],
        )
        .unwrap();
        insert_operation(&conn, OPERATION_A);
        conn.execute(
            "INSERT INTO pending_session_releases \
             (operation_id, session_id, expected_generation, row_expectation, created_at_ms) \
             VALUES (?1, 'retained-session', 'retained-generation', 'row_must_be_absent', 1)",
            [OPERATION_A],
        )
        .unwrap();
        assert!(!table_exists(&conn, "pending_agent_task_starts"));

        ensure_schema(&mut conn).unwrap();

        assert_eq!(version(&conn), crate::db::DB_SCHEMA_VERSION);
        assert_eq!(
            conn.query_row(
                "SELECT name FROM projects WHERE project_id = 'keep'",
                [],
                |row| { row.get::<_, String>(0) }
            )
            .unwrap(),
            "Keep"
        );
        assert_eq!(
            conn.query_row(
                "SELECT expected_generation FROM pending_session_releases \
                 WHERE operation_id = ?1 AND session_id = 'retained-session'",
                [OPERATION_A],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            "retained-generation"
        );
        assert!(table_exists(&conn, "pending_agent_task_starts"));
    }

    #[test]
    fn future_schema_is_rejected_without_applying_known_migrations() {
        let mut conn = Connection::open_in_memory().unwrap();
        initialize_v1(&mut conn);
        conn.execute_batch(
            "CREATE TABLE future_private_state (value TEXT NOT NULL); \
             INSERT INTO future_private_state VALUES ('untouched'); \
             UPDATE schema_meta SET version = 4 WHERE id = 1;",
        )
        .unwrap();

        assert!(matches!(
            ensure_schema(&mut conn),
            Err(SchemaError::FutureVersion { db: 4, ours: 3 })
        ));
        assert_eq!(version(&conn), 4);
        assert!(!table_exists(&conn, "session_release_operations"));
        assert!(!table_exists(&conn, "pending_agent_task_starts"));
        assert_eq!(
            conn.query_row("SELECT value FROM future_private_state", [], |row| {
                row.get::<_, String>(0)
            })
            .unwrap(),
            "untouched"
        );
    }

    #[test]
    fn release_journal_schema_is_content_blind_and_indexed_for_claims() {
        let mut conn = Connection::open_in_memory().unwrap();
        ensure_schema(&mut conn).unwrap();

        assert_eq!(
            table_column_names(&conn, "session_release_operations"),
            [
                "operation_id",
                "created_at_ms",
                "lease_token",
                "lease_until_ms",
            ]
        );
        assert_eq!(
            table_column_names(&conn, "pending_session_releases"),
            [
                "operation_id",
                "session_id",
                "expected_generation",
                "row_expectation",
                "created_at_ms",
            ]
        );
        assert_eq!(
            index_column_names(&conn, "idx_session_release_operations_claim"),
            ["lease_until_ms", "created_at_ms", "operation_id"]
        );
        assert_eq!(
            index_column_names(&conn, "idx_pending_session_releases_session"),
            ["session_id"]
        );
    }

    #[test]
    fn release_journal_checks_reject_malformed_control_metadata() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();

        assert!(conn
            .execute(
                "INSERT INTO session_release_operations \
                 (operation_id, created_at_ms) VALUES ('too-short', 0)",
                [],
            )
            .is_err());
        assert!(conn
            .execute(
                "INSERT INTO session_release_operations \
                 (operation_id, created_at_ms) VALUES (zeroblob(36), 0)",
                [],
            )
            .is_err());
        assert!(conn
            .execute(
                "INSERT INTO session_release_operations \
                 (operation_id, created_at_ms) VALUES (?1, -1)",
                [OPERATION_A],
            )
            .is_err());

        insert_operation(&conn, OPERATION_A);
        assert!(conn
            .execute(
                "UPDATE session_release_operations \
                 SET lease_token = ?1, lease_until_ms = NULL WHERE operation_id = ?2",
                [LEASE_A, OPERATION_A],
            )
            .is_err());
        assert!(conn
            .execute(
                "UPDATE session_release_operations \
                 SET lease_token = 'too-short', lease_until_ms = 2 WHERE operation_id = ?1",
                [OPERATION_A],
            )
            .is_err());
        assert!(conn
            .execute(
                "UPDATE session_release_operations \
                 SET lease_token = ?1, lease_until_ms = -1 WHERE operation_id = ?2",
                [LEASE_A, OPERATION_A],
            )
            .is_err());
        conn.execute(
            "UPDATE session_release_operations \
             SET lease_token = ?1, lease_until_ms = 2 WHERE operation_id = ?2",
            [LEASE_A, OPERATION_A],
        )
        .unwrap();

        for invalid_insert in [
            "INSERT INTO pending_session_releases VALUES \
             ('00000000-0000-4000-8000-000000000001', '', 'generation', \
              'row_must_be_absent', 1)",
            "INSERT INTO pending_session_releases VALUES \
             ('00000000-0000-4000-8000-000000000001', 'session', '', \
              'row_must_be_absent', 1)",
            "INSERT INTO pending_session_releases VALUES \
             ('00000000-0000-4000-8000-000000000001', 'session', 'generation', \
              'unknown_policy', 1)",
            "INSERT INTO pending_session_releases VALUES \
             ('00000000-0000-4000-8000-000000000001', 'session', 'generation', \
              'row_must_be_absent', -1)",
        ] {
            assert!(
                conn.execute(invalid_insert, []).is_err(),
                "{invalid_insert}"
            );
        }

        let max_session_id = "s".repeat(128);
        let max_generation = "g".repeat(128);
        conn.execute(
            "INSERT INTO pending_session_releases \
             (operation_id, session_id, expected_generation, row_expectation, created_at_ms) \
             VALUES (?1, ?2, ?3, 'matching_row_is_proof', 1)",
            rusqlite::params![OPERATION_A, max_session_id, max_generation],
        )
        .unwrap();
        assert!(conn
            .execute(
                "INSERT INTO pending_session_releases \
                 (operation_id, session_id, expected_generation, row_expectation, created_at_ms) \
                 VALUES (?1, ?2, 'generation', 'row_must_be_absent', 1)",
                rusqlite::params![OPERATION_A, "s".repeat(129)],
            )
            .is_err());
        assert!(conn
            .execute(
                "INSERT INTO pending_session_releases \
                 (operation_id, session_id, expected_generation, row_expectation, created_at_ms) \
                 VALUES (?1, 'another-session', ?2, 'row_must_be_absent', 1)",
                rusqlite::params![OPERATION_A, "g".repeat(129)],
            )
            .is_err());
    }

    #[test]
    fn release_journal_fk_cascades_and_rejects_orphan_targets() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();

        assert!(conn
            .execute(
                "INSERT INTO pending_session_releases \
                 (operation_id, session_id, expected_generation, row_expectation, created_at_ms) \
                 VALUES (?1, 'session', 'generation', 'row_must_be_absent', 1)",
                [OPERATION_A],
            )
            .is_err());

        insert_operation(&conn, OPERATION_A);
        conn.execute(
            "INSERT INTO pending_session_releases \
             (operation_id, session_id, expected_generation, row_expectation, created_at_ms) \
             VALUES (?1, 'session', 'generation', 'row_must_be_absent', 1)",
            [OPERATION_A],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM session_release_operations WHERE operation_id = ?1",
            [OPERATION_A],
        )
        .unwrap();
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM pending_session_releases", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            0
        );
    }

    #[test]
    fn release_journal_hard_caps_bound_each_operation_and_the_database() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();
        for operation_id in [
            OPERATION_A,
            OPERATION_B,
            OPERATION_C,
            OPERATION_D,
            OPERATION_E,
        ] {
            insert_operation(&conn, operation_id);
        }

        insert_pending_rows(&mut conn, OPERATION_A, 4096);
        assert!(conn
            .execute(
                "INSERT INTO pending_session_releases \
                 (operation_id, session_id, expected_generation, row_expectation, created_at_ms) \
                 VALUES (?1, 'overflow', 'generation', 'row_must_be_absent', 1)",
                [OPERATION_A],
            )
            .is_err());
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM pending_session_releases WHERE operation_id = ?1",
                [OPERATION_A],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            4096
        );

        conn.execute(
            "INSERT INTO pending_session_releases \
             (operation_id, session_id, expected_generation, row_expectation, created_at_ms) \
             VALUES (?1, 'move-overflow', 'generation', 'row_must_be_absent', 1)",
            [OPERATION_B],
        )
        .unwrap();
        assert!(conn
            .execute(
                "UPDATE pending_session_releases SET operation_id = ?1 \
                 WHERE operation_id = ?2 AND session_id = 'move-overflow'",
                [OPERATION_A, OPERATION_B],
            )
            .is_err());
        assert_eq!(
            conn.query_row(
                "SELECT operation_id FROM pending_session_releases \
                 WHERE session_id = 'move-overflow'",
                [],
                |row| row.get::<_, String>(0),
            )
            .unwrap(),
            OPERATION_B
        );
        conn.execute(
            "DELETE FROM pending_session_releases \
             WHERE operation_id = ?1 AND session_id = 'move-overflow'",
            [OPERATION_B],
        )
        .unwrap();

        for operation_id in [OPERATION_B, OPERATION_C, OPERATION_D] {
            insert_pending_rows(&mut conn, operation_id, 4096);
        }
        assert_eq!(
            conn.query_row("SELECT COUNT(*) FROM pending_session_releases", [], |row| {
                row.get::<_, i64>(0)
            })
            .unwrap(),
            16384
        );
        assert!(conn
            .execute(
                "INSERT INTO pending_session_releases \
                 (operation_id, session_id, expected_generation, row_expectation, created_at_ms) \
                 VALUES (?1, 'global-overflow', 'generation', 'row_must_be_absent', 1)",
                [OPERATION_E],
            )
            .is_err());
    }

    #[test]
    fn agent_task_start_journal_schema_is_content_blind_and_indexed_for_claims() {
        let mut conn = Connection::open_in_memory().unwrap();
        ensure_schema(&mut conn).unwrap();

        assert_eq!(
            table_column_names(&conn, "pending_agent_task_starts"),
            [
                "session_id",
                "agent_task_id",
                "project_id",
                "workspace_id",
                "operation_token",
                "binding_state",
                "daemon_instance_id",
                "server_pid",
                "socket_path",
                "session_a_sha256",
                "task_a_sha256",
                "project_sha256",
                "workspace_sha256",
                "publication_launch_json",
                "publication_now_ms",
                "disposition",
                "applied_generation",
                "applied_state",
                "created_at_ms",
                "lease_token",
                "lease_until_ms",
            ]
        );
        assert_eq!(
            index_column_names(&conn, "idx_pending_agent_task_starts_claim"),
            ["lease_until_ms", "created_at_ms", "session_id"]
        );
        for forbidden in [
            "command",
            "argv",
            "cwd",
            "environment",
            "goal",
            "result",
            "terminal",
            "output",
            "diagnostic",
        ] {
            assert!(
                !table_column_names(&conn, "pending_agent_task_starts")
                    .iter()
                    .any(|column| column.contains(forbidden)),
                "journal schema exposed content-bearing column fragment {forbidden:?}"
            );
        }
    }

    #[test]
    fn agent_task_start_journal_checks_enforce_binding_application_and_lease_matrix() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();

        let invalid = [
            (
                "unbound-peer",
                "unbound",
                Some(DAEMON_INSTANCE_A),
                None,
                None,
                "finalize",
                None,
                None,
                None,
                None,
            ),
            (
                "bound-no-daemon",
                "bound",
                None,
                Some(7),
                Some("/tmp/pty.sock"),
                "finalize",
                None,
                None,
                None,
                None,
            ),
            (
                "bound-no-socket",
                "bound",
                Some(DAEMON_INSTANCE_A),
                Some(7),
                None,
                "finalize",
                None,
                None,
                None,
                None,
            ),
            (
                "unbound-applied",
                "unbound",
                None,
                None,
                None,
                "finalize",
                Some(GENERATION_A),
                Some("live"),
                None,
                None,
            ),
            (
                "generation-without-state",
                "bound",
                Some(DAEMON_INSTANCE_A),
                Some(7),
                Some("/tmp/pty.sock"),
                "finalize",
                Some(GENERATION_A),
                None,
                None,
                None,
            ),
            (
                "state-without-generation",
                "bound",
                Some(DAEMON_INSTANCE_A),
                Some(7),
                Some("/tmp/pty.sock"),
                "finalize",
                None,
                Some("live"),
                None,
                None,
            ),
            (
                "release-without-application",
                "bound",
                Some(DAEMON_INSTANCE_A),
                Some(7),
                Some("/tmp/pty.sock"),
                "release",
                None,
                None,
                None,
                None,
            ),
            (
                "lease-token-only",
                "unbound",
                None,
                None,
                None,
                "finalize",
                None,
                None,
                Some(LEASE_A),
                None,
            ),
            (
                "lease-time-only",
                "unbound",
                None,
                None,
                None,
                "finalize",
                None,
                None,
                None,
                Some(10),
            ),
            (
                "invalid-state",
                "bound",
                Some(DAEMON_INSTANCE_A),
                Some(7),
                Some("/tmp/pty.sock"),
                "finalize",
                Some(GENERATION_A),
                Some("unknown"),
                None,
                None,
            ),
            (
                "invalid-pid",
                "bound",
                Some(DAEMON_INSTANCE_A),
                Some(0),
                Some("/tmp/pty.sock"),
                "finalize",
                None,
                None,
                None,
                None,
            ),
            (
                "nul-socket",
                "bound",
                Some(DAEMON_INSTANCE_A),
                Some(7),
                Some("/tmp/pty\0.sock"),
                "finalize",
                None,
                None,
                None,
                None,
            ),
        ];

        for (index, case) in invalid.into_iter().enumerate() {
            let (
                suffix,
                binding_state,
                daemon_instance_id,
                server_pid,
                socket_path,
                disposition,
                applied_generation,
                applied_state,
                lease_token,
                lease_until_ms,
            ) = case;
            insert_agent_task_start_graph(&conn, suffix);
            assert!(
                insert_pending_agent_task_start_with_state(
                    &conn,
                    suffix,
                    &start_token(index + 100),
                    binding_state,
                    daemon_instance_id,
                    server_pid,
                    socket_path,
                    disposition,
                    applied_generation,
                    applied_state,
                    lease_token,
                    lease_until_ms,
                )
                .is_err(),
                "invalid CHECK matrix case {suffix:?} was accepted"
            );
        }

        insert_agent_task_start_graph(&conn, "short-token");
        assert!(insert_pending_agent_task_start_with_state(
            &conn,
            "short-token",
            "too-short",
            "unbound",
            None,
            None,
            None,
            "finalize",
            None,
            None,
            None,
            None,
        )
        .is_err());

        insert_agent_task_start_graph(&conn, "valid-bound");
        insert_pending_agent_task_start_with_state(
            &conn,
            "valid-bound",
            START_TOKEN_A,
            "bound",
            Some(DAEMON_INSTANCE_A),
            None,
            Some("/tmp/pty.sock"),
            "release",
            Some(GENERATION_A),
            Some("removed"),
            Some(LEASE_A),
            Some(10),
        )
        .unwrap();
    }

    #[test]
    fn agent_task_start_journal_checks_reject_malformed_typed_control_fields() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();

        insert_agent_task_start_graph(&conn, "blob-token");
        assert!(conn
            .execute(
                "INSERT INTO pending_agent_task_starts \
                 (session_id, agent_task_id, project_id, workspace_id, operation_token, \
                  session_a_sha256, task_a_sha256, project_sha256, workspace_sha256, \
                  publication_launch_json, publication_now_ms, created_at_ms) \
                 VALUES ('session-blob-token', 'task-blob-token', 'project-blob-token', \
                         'workspace-blob-token', zeroblob(32), zeroblob(32), zeroblob(32), \
                         zeroblob(32), zeroblob(32), '{}', 1, 1)",
                [],
            )
            .is_err());

        insert_agent_task_start_graph(&conn, "short-hash");
        assert!(conn
            .execute(
                "INSERT INTO pending_agent_task_starts \
                 (session_id, agent_task_id, project_id, workspace_id, operation_token, \
                  session_a_sha256, task_a_sha256, project_sha256, workspace_sha256, \
                  publication_launch_json, publication_now_ms, created_at_ms) \
                 VALUES ('session-short-hash', 'task-short-hash', 'project-short-hash', \
                         'workspace-short-hash', ?1, zeroblob(31), zeroblob(32), zeroblob(32), \
                         zeroblob(32), '{}', 1, 1)",
                [START_TOKEN_B],
            )
            .is_err());

        insert_agent_task_start_graph(&conn, "text-hash");
        assert!(conn
            .execute(
                "INSERT INTO pending_agent_task_starts \
                 (session_id, agent_task_id, project_id, workspace_id, operation_token, \
                  session_a_sha256, task_a_sha256, project_sha256, workspace_sha256, \
                  publication_launch_json, publication_now_ms, created_at_ms) \
                 VALUES ('session-text-hash', 'task-text-hash', 'project-text-hash', \
                         'workspace-text-hash', ?1, hex(zeroblob(16)), zeroblob(32), zeroblob(32), \
                         zeroblob(32), '{}', 1, 1)",
                [START_TOKEN_C],
            )
            .is_err());

        insert_agent_task_start_graph(&conn, "bad-launch");
        assert!(conn
            .execute(
                "INSERT INTO pending_agent_task_starts \
                 (session_id, agent_task_id, project_id, workspace_id, operation_token, \
                  session_a_sha256, task_a_sha256, project_sha256, workspace_sha256, \
                  publication_launch_json, publication_now_ms, created_at_ms) \
                 VALUES ('session-bad-launch', 'task-bad-launch', 'project-bad-launch', \
                         'workspace-bad-launch', ?1, zeroblob(32), zeroblob(32), zeroblob(32), \
                         zeroblob(32), 'x', 1, 1)",
                [start_token(4)],
            )
            .is_err());

        insert_agent_task_start_graph(&conn, "negative-time");
        assert!(conn
            .execute(
                "INSERT INTO pending_agent_task_starts \
                 (session_id, agent_task_id, project_id, workspace_id, operation_token, \
                  session_a_sha256, task_a_sha256, project_sha256, workspace_sha256, \
                  publication_launch_json, publication_now_ms, created_at_ms) \
                 VALUES ('session-negative-time', 'task-negative-time', 'project-negative-time', \
                         'workspace-negative-time', ?1, zeroblob(32), zeroblob(32), zeroblob(32), \
                         zeroblob(32), '{}', -1, 1)",
                [start_token(5)],
            )
            .is_err());
    }

    #[test]
    fn agent_task_start_journal_uuid_control_ids_match_protocol_parser() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();

        assert!(START_TOKEN_A
            .parse::<maestro_protocol::SessionStartOperationToken>()
            .is_ok());
        assert!(DAEMON_INSTANCE_A
            .parse::<maestro_protocol::DaemonInstanceId>()
            .is_ok());

        for (index, (suffix, invalid)) in [
            ("operation-nonhex", "0000000000004000800000000000000g"),
            ("operation-uppercase", "0000000000004000800000000000000A"),
            (
                "operation-wrong-version",
                "00000000000050008000000000000001",
            ),
            (
                "operation-wrong-variant",
                "00000000000040007000000000000001",
            ),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(invalid
                .parse::<maestro_protocol::SessionStartOperationToken>()
                .is_err());
            insert_agent_task_start_graph(&conn, suffix);
            assert!(
                insert_pending_agent_task_start_with_state(
                    &conn, suffix, invalid, "unbound", None, None, None, "finalize", None, None,
                    None, None,
                )
                .is_err(),
                "operation token case {index} passed the database CHECK"
            );
        }

        for (index, (suffix, invalid)) in [
            ("daemon-nonhex", "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaag"),
            ("daemon-uppercase", "aaaaaaaaaaaa4aaa8aaaaaaaaaaaaaaA"),
            ("daemon-wrong-version", "aaaaaaaaaaaa5aaa8aaaaaaaaaaaaaaa"),
            ("daemon-wrong-variant", "aaaaaaaaaaaa4aaa7aaaaaaaaaaaaaaa"),
        ]
        .into_iter()
        .enumerate()
        {
            assert!(invalid
                .parse::<maestro_protocol::DaemonInstanceId>()
                .is_err());
            insert_agent_task_start_graph(&conn, suffix);
            assert!(
                insert_pending_agent_task_start_with_state(
                    &conn,
                    suffix,
                    &start_token(index + 600),
                    "bound",
                    Some(invalid),
                    Some(7),
                    Some("/tmp/pty.sock"),
                    "finalize",
                    None,
                    None,
                    None,
                    None,
                )
                .is_err(),
                "daemon instance case {index} passed the database CHECK"
            );
        }
    }

    #[test]
    fn agent_task_start_journal_rejects_malformed_publication_json() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();
        insert_agent_task_start_graph(&conn, "malformed-json");

        assert!(conn
            .execute(
                "INSERT INTO pending_agent_task_starts \
                 (session_id, agent_task_id, project_id, workspace_id, operation_token, \
                  session_a_sha256, task_a_sha256, project_sha256, workspace_sha256, \
                  publication_launch_json, publication_now_ms, created_at_ms) \
                 VALUES ('session-malformed-json', 'task-malformed-json', \
                         'project-malformed-json', 'workspace-malformed-json', ?1, \
                         zeroblob(32), zeroblob(32), zeroblob(32), zeroblob(32), \
                         '{broken', 1, 1)",
                [start_token(700)],
            )
            .is_err());
    }

    #[test]
    fn agent_task_start_journal_restricts_parent_deletes_and_rejects_graph_mismatch() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();
        insert_unbound_agent_task_start(&conn, "restrict", START_TOKEN_A);

        for delete in [
            "DELETE FROM sessions WHERE session_id = 'session-restrict'",
            "DELETE FROM agent_tasks WHERE agent_task_id = 'task-restrict'",
            "DELETE FROM workspaces WHERE workspace_id = 'workspace-restrict'",
            "DELETE FROM projects WHERE project_id = 'project-restrict'",
        ] {
            assert!(
                conn.execute(delete, []).is_err(),
                "{delete} bypassed RESTRICT"
            );
        }

        insert_agent_task_start_graph(&conn, "other");
        assert!(conn
            .execute(
                "INSERT INTO pending_agent_task_starts \
                 (session_id, agent_task_id, project_id, workspace_id, operation_token, \
                  session_a_sha256, task_a_sha256, project_sha256, workspace_sha256, \
                  publication_launch_json, publication_now_ms, created_at_ms) \
                 VALUES ('session-other', 'task-other', 'project-restrict', 'workspace-other', ?1, \
                         zeroblob(32), zeroblob(32), zeroblob(32), zeroblob(32), '{}', 1, 1)",
                [START_TOKEN_B],
            )
            .is_err());

        conn.execute(
            "DELETE FROM pending_agent_task_starts WHERE session_id = 'session-restrict'",
            [],
        )
        .unwrap();
        conn.execute(
            "DELETE FROM projects WHERE project_id = 'project-restrict'",
            [],
        )
        .unwrap();
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM sessions WHERE session_id = 'session-restrict'",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            0
        );
    }

    #[test]
    fn agent_task_start_journal_applied_state_is_same_generation_and_forward_only() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();

        insert_unbound_agent_task_start(&conn, "lifecycle", START_TOKEN_A);
        bind_agent_task_start(&conn, "lifecycle");
        set_agent_task_start_applied(&conn, "lifecycle", GENERATION_A, "live").unwrap();
        set_agent_task_start_applied(&conn, "lifecycle", GENERATION_A, "live").unwrap();
        assert!(set_agent_task_start_applied(&conn, "lifecycle", GENERATION_B, "live").is_err());
        assert!(conn
            .execute(
                "UPDATE pending_agent_task_starts \
                 SET applied_generation = NULL, applied_state = NULL \
                 WHERE session_id = 'session-lifecycle'",
                [],
            )
            .is_err());
        set_agent_task_start_applied(&conn, "lifecycle", GENERATION_A, "exited").unwrap();
        assert!(set_agent_task_start_applied(&conn, "lifecycle", GENERATION_A, "live").is_err());
        set_agent_task_start_applied(&conn, "lifecycle", GENERATION_A, "removed").unwrap();
        set_agent_task_start_applied(&conn, "lifecycle", GENERATION_A, "removed").unwrap();
        assert!(set_agent_task_start_applied(&conn, "lifecycle", GENERATION_A, "exited").is_err());
        assert!(set_agent_task_start_applied(&conn, "lifecycle", GENERATION_B, "removed").is_err());

        insert_unbound_agent_task_start(&conn, "direct-exited", START_TOKEN_B);
        bind_agent_task_start(&conn, "direct-exited");
        set_agent_task_start_applied(&conn, "direct-exited", GENERATION_A, "exited").unwrap();

        insert_unbound_agent_task_start(&conn, "direct-removed", START_TOKEN_C);
        bind_agent_task_start(&conn, "direct-removed");
        set_agent_task_start_applied(&conn, "direct-removed", GENERATION_A, "removed").unwrap();

        insert_unbound_agent_task_start(&conn, "live-removed", &start_token(4));
        bind_agent_task_start(&conn, "live-removed");
        set_agent_task_start_applied(&conn, "live-removed", GENERATION_A, "live").unwrap();
        set_agent_task_start_applied(&conn, "live-removed", GENERATION_A, "removed").unwrap();
    }

    #[test]
    fn agent_task_start_journal_binding_disposition_and_core_are_forward_only() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();
        insert_unbound_agent_task_start(&conn, "authority", START_TOKEN_A);

        assert!(conn
            .execute(
                "UPDATE pending_agent_task_starts SET disposition = 'release' \
                 WHERE session_id = 'session-authority'",
                [],
            )
            .is_err());
        bind_agent_task_start(&conn, "authority");
        assert!(conn
            .execute(
                "UPDATE pending_agent_task_starts SET socket_path = '/tmp/other.sock' \
                 WHERE session_id = 'session-authority'",
                [],
            )
            .is_err());
        assert!(conn
            .execute(
                "UPDATE pending_agent_task_starts \
                 SET binding_state = 'unbound', daemon_instance_id = NULL, server_pid = NULL, \
                     socket_path = NULL \
                 WHERE session_id = 'session-authority'",
                [],
            )
            .is_err());
        assert!(conn
            .execute(
                "UPDATE pending_agent_task_starts SET operation_token = operation_token \
                 WHERE session_id = 'session-authority'",
                [],
            )
            .is_err());

        set_agent_task_start_applied(&conn, "authority", GENERATION_A, "live").unwrap();
        conn.execute(
            "UPDATE pending_agent_task_starts SET disposition = 'release' \
             WHERE session_id = 'session-authority'",
            [],
        )
        .unwrap();
        conn.execute(
            "UPDATE pending_agent_task_starts SET disposition = 'release' \
             WHERE session_id = 'session-authority'",
            [],
        )
        .unwrap();
        assert!(conn
            .execute(
                "UPDATE pending_agent_task_starts SET disposition = 'finalize' \
                 WHERE session_id = 'session-authority'",
                [],
            )
            .is_err());
    }

    #[test]
    fn agent_task_start_journal_hard_cap_is_global() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();

        let tx = conn.transaction().unwrap();
        for value in 0..4096 {
            let suffix = format!("cap-{value}");
            insert_agent_task_start_graph(&tx, &suffix);
            insert_pending_agent_task_start_with_state(
                &tx,
                &suffix,
                &start_token(value),
                "unbound",
                None,
                None,
                None,
                "finalize",
                None,
                None,
                None,
                None,
            )
            .unwrap();
        }
        tx.commit().unwrap();

        insert_agent_task_start_graph(&conn, "cap-overflow");
        assert!(insert_pending_agent_task_start_with_state(
            &conn,
            "cap-overflow",
            &start_token(4096),
            "unbound",
            None,
            None,
            None,
            "finalize",
            None,
            None,
            None,
            None,
        )
        .is_err());
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM pending_agent_task_starts",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap(),
            4096
        );
    }

    #[test]
    fn nonempty_database_without_version_is_rejected() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.execute_batch("CREATE TABLE legacy_data (value TEXT);")
            .unwrap();
        assert!(matches!(
            ensure_schema(&mut conn),
            Err(SchemaError::MissingVersion)
        ));
        let meta_exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='schema_meta')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!meta_exists);
    }

    #[test]
    fn missing_or_invalid_version_row_is_rejected() {
        let mut missing = Connection::open_in_memory().unwrap();
        missing
            .execute_batch(
                "CREATE TABLE schema_meta (id INTEGER PRIMARY KEY, version INTEGER NOT NULL);",
            )
            .unwrap();
        assert!(matches!(
            ensure_schema(&mut missing),
            Err(SchemaError::MissingVersion)
        ));

        let mut invalid = Connection::open_in_memory().unwrap();
        invalid
            .execute_batch(
                "CREATE TABLE schema_meta (id INTEGER PRIMARY KEY, version); \
                 INSERT INTO schema_meta VALUES (1, 'one');",
            )
            .unwrap();
        assert!(matches!(
            ensure_schema(&mut invalid),
            Err(SchemaError::InvalidVersion { .. })
        ));
    }

    #[test]
    fn failed_migration_rolls_back_ddl_and_version() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        initialize_v1(&mut conn);

        let failing = [Migration {
            from: 1,
            to: 2,
            sql: "CREATE TABLE should_rollback (id INTEGER); INSERT INTO table_that_does_not_exist VALUES (1);",
        }];
        assert!(matches!(
            ensure_schema_to(&mut conn, 2, &failing),
            Err(SchemaError::Sqlite(_))
        ));
        assert_eq!(version(&conn), 1);
        let exists: bool = conn
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM sqlite_schema WHERE name='should_rollback')",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert!(!exists);
    }

    #[test]
    fn v2_migration_conflict_rolls_back_partial_journal_ddl() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        initialize_v1(&mut conn);
        conn.execute_batch("CREATE TABLE pending_session_releases (conflict TEXT);")
            .unwrap();

        assert!(matches!(
            ensure_schema(&mut conn),
            Err(SchemaError::Sqlite(_))
        ));
        assert_eq!(version(&conn), 1);
        assert!(!table_exists(&conn, "session_release_operations"));
        assert_eq!(
            table_column_names(&conn, "pending_session_releases"),
            ["conflict"]
        );
    }

    #[test]
    fn v3_migration_conflict_rolls_back_ddl_and_preserves_v2() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        initialize_v2(&mut conn);
        insert_operation(&conn, OPERATION_A);
        conn.execute_batch("CREATE TABLE pending_agent_task_starts (conflict TEXT);")
            .unwrap();

        assert!(matches!(
            ensure_schema(&mut conn),
            Err(SchemaError::Sqlite(_))
        ));
        assert_eq!(version(&conn), 2);
        assert_eq!(
            table_column_names(&conn, "pending_agent_task_starts"),
            ["conflict"]
        );
        assert_eq!(
            conn.query_row(
                "SELECT COUNT(*) FROM session_release_operations",
                [],
                |row| { row.get::<_, i64>(0) }
            )
            .unwrap(),
            1
        );
    }

    #[test]
    fn impossible_migration_gap_is_rejected_without_version_change() {
        let mut conn = Connection::open_in_memory().unwrap();
        initialize_v1(&mut conn);
        assert!(matches!(
            ensure_schema_to(&mut conn, 2, &[]),
            Err(SchemaError::MigrationGap { from: 1, target: 2 })
        ));
        assert_eq!(version(&conn), 1);
    }

    #[test]
    fn cascade_delete_removes_children() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();
        conn.execute(
            "INSERT INTO projects (project_id, name, root, default_workspace_policy, created_at_ms, last_active_at_ms) \
             VALUES ('p1','P','/r','scratch_cwd',1,1)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO workspaces (workspace_id, project_id, root, policy, consent_json) \
             VALUES ('w1','p1','/r','scratch_cwd','{}')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO windows (window_id, project_id, name) VALUES ('win1','p1','Window 1')",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO tabs (tab_id, window_id, idx, title, attention_json) \
             VALUES ('t1','win1',0,'Pane 1','{}')",
            [],
        )
        .unwrap();
        conn.execute("DELETE FROM projects WHERE project_id = 'p1'", [])
            .unwrap();
        for table in ["workspaces", "windows", "tabs"] {
            let count: i64 = conn
                .query_row(&format!("SELECT COUNT(*) FROM {table}"), [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(count, 0, "{table} rows should have cascaded away");
        }
    }
}
