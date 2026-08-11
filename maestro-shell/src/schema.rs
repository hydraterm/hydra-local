//! The relational schema and ordered migrations for the local SQLite store.
//!
//! Version 1 is the initial relational schema. Future schema changes must be appended to
//! [`MIGRATIONS`] as one-step transitions; opening the database applies the ordered chain under an
//! immediate transaction. A database stamped by a newer build is rejected before any schema DDL.

use rusqlite::{Connection, OptionalExtension, Transaction, TransactionBehavior};

const INITIAL_SCHEMA_VERSION: i64 = 1;

/// One append-only schema transition. There are no transitions yet: version 1 is still current.
struct Migration {
    from: i64,
    to: i64,
    sql: &'static str,
}

const MIGRATIONS: &[Migration] = &[];

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

#[cfg(test)]
mod tests {
    use super::*;

    fn version(conn: &Connection) -> i64 {
        conn.query_row("SELECT version FROM schema_meta WHERE id = 1", [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    #[test]
    fn fresh_schema_is_transactional_and_stamped_v1() {
        let mut conn = Connection::open_in_memory().unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        ensure_schema(&mut conn).unwrap();
        assert_eq!(version(&conn), crate::db::DB_SCHEMA_VERSION);
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
        assert_eq!(version(&conn), 1);
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
        ensure_schema(&mut conn).unwrap();

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
    fn impossible_migration_gap_is_rejected_without_version_change() {
        let mut conn = Connection::open_in_memory().unwrap();
        ensure_schema(&mut conn).unwrap();
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
