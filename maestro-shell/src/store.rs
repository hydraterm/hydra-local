//! The shell metadata store: the generic seam (`write_record`/`load_one`/`load_all`) over `RecordKind`, now backed by an
//! embedded SQLite DB (`<base>/maestro.db`) instead of per-record JSON files. The signatures are unchanged so every
//! service + call-site is backend-agnostic; the JSON↔row mapping lives in `store_sqlite`, connection + PRAGMAs in `db`.
//!
//! Guarantees preserved:
//! - Writes are atomic + durable via SQLite transactions + WAL (`synchronous=NORMAL`); a reader never sees a partial
//!   record. Deletes cascade (FK `ON DELETE CASCADE`) so closed projects/windows/panes leave no orphans.
//! - A row that fails to deserialize into its record type is surfaced as `Quarantined` (skipped from the loaded set),
//!   the SQLite analog of the old corrupt-file quarantine.
//! - An id is VALIDATED before any query (traversal/illegal ids refused) — input hygiene, preserved from the file era.
//!
//! The `#![allow(dead_code)]` covers the legacy file readers kept only for the one-shot JSON→SQLite migrator.

// The file-based readers below (legacy_read_one/quarantine/ensure_dir/…) are retained for the one-shot JSON→SQLite
// migrator (migrate.rs), which reads the LEGACY on-disk records before they're retired. They are dead on the main path
// (now SQLite), hence the module-scoped allow until the legacy JSON migration surface is retired.
#![allow(dead_code)]

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use serde::{de::DeserializeOwned, Serialize};

use crate::envelope::{Envelope, EnvelopeError};
use crate::ids::IdError;
use crate::paths::{AppPaths, RecordKind};

/// Mode for record files: owner read/write only.
#[cfg(unix)]
const FILE_MODE: u32 = 0o600;
/// Mode for Maestro directories: owner-only.
#[cfg(unix)]
const DIR_MODE: u32 = 0o700;

/// Errors from the store. Distinguish "couldn't even do IO" from "the bytes were bad" so the
/// caller can quarantine the latter and surface the former.
#[derive(Debug)]
pub enum StoreError {
    Io(io::Error),
    Envelope(EnvelopeError),
    /// A supplied id was unsafe for use in a path (traversal/illegal char/etc.). The operation
    /// is refused before any query is built.
    Id(IdError),
    /// Opening/pragma-ing the SQLite DB failed, or the DB was written by a newer build (FutureVersion).
    Db(String),
    /// A record failed to map to/from its relational row.
    Map(String),
}

impl std::fmt::Display for StoreError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            StoreError::Io(e) => write!(f, "store io error: {e}"),
            StoreError::Envelope(e) => write!(f, "store envelope error: {e}"),
            StoreError::Id(e) => write!(f, "store id error: {e}"),
            StoreError::Db(e) => write!(f, "store db error: {e}"),
            StoreError::Map(e) => write!(f, "store map error: {e}"),
        }
    }
}

impl std::error::Error for StoreError {}

impl StoreError {
    fn from_db(e: crate::db::DbError) -> Self {
        StoreError::Db(e.to_string())
    }
    fn from_map(e: crate::store_sqlite::MapError) -> Self {
        StoreError::Map(e.to_string())
    }
    fn from_json(e: serde_json::Error) -> Self {
        StoreError::Map(format!("serialize record: {e}"))
    }
}

impl From<io::Error> for StoreError {
    fn from(e: io::Error) -> Self {
        StoreError::Io(e)
    }
}

impl From<IdError> for StoreError {
    fn from(e: IdError) -> Self {
        StoreError::Id(e)
    }
}

/// What happened to one record file while loading a directory. The caller logs/surfaces this;
/// only `Loaded` contributes to the returned set.
#[derive(Debug)]
pub enum LoadOutcome<T> {
    /// A valid record was read.
    Loaded(T),
    /// A file failed validation (malformed JSON, schema mismatch, wrong type) and was
    /// quarantined to `moved_to`. `reason` explains why. The original bytes are preserved, not
    /// deleted.
    Quarantined {
        original: PathBuf,
        moved_to: PathBuf,
        reason: String,
    },
    /// A syntactically valid record stamped a schema version NEWER than this build understands.
    /// Such a record is read-only/unmigratable: it is LEFT IN PLACE at `path` (never quarantined
    /// or rewritten), not loaded, and surfaced here so the caller can tell the user a newer
    /// Maestro wrote it. Dropping our model's view and rewriting could lose fields we do not yet
    /// model.
    FutureVersion { path: PathBuf, ours: u32, got: u32 },
}

/// Create a directory (and parents) with `0700` where supported.
fn ensure_dir(dir: &Path) -> io::Result<()> {
    fs::create_dir_all(dir)?;
    set_dir_mode(dir)
}

#[cfg(unix)]
fn set_dir_mode(dir: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    // Best-effort: a filesystem that ignores mode bits returns Ok with no effect; a hard error
    // (e.g. not owner) is surfaced.
    fs::set_permissions(dir, fs::Permissions::from_mode(DIR_MODE))
}

#[cfg(not(unix))]
fn set_dir_mode(_dir: &Path) -> io::Result<()> {
    Ok(())
}

#[cfg(unix)]
fn set_file_mode(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(FILE_MODE))
}

#[cfg(not(unix))]
fn set_file_mode(_path: &Path) -> io::Result<()> {
    Ok(())
}

/// Best-effort fsync of a directory so a rename within it is durable across a crash. A failure
/// here (some filesystems reject opening a dir for sync) is non-fatal: the rename already
/// happened, we only lose the crash-durability guarantee, so we swallow the error.
fn fsync_dir(dir: &Path) {
    if let Ok(f) = fs::File::open(dir) {
        let _ = f.sync_all();
    }
}

/// Atomically write `record` for `kind`/`id` through the SQLite store.
///
/// The id is validated before any query is built. The typed record is serialized into the
/// kind-specific SQLite row shape and committed through the configured WAL transaction path; no
/// per-record JSON file or rename participates in this current write path.
///
/// `Project` is a full-row upsert that includes the ownership-bearing `window_order`. Ordinary
/// production updates of an existing project must therefore use [`crate::ProjectService`], whose
/// writer transaction loads fresh and cannot replay a stale order. Direct Project writes remain a
/// migration/bootstrap/test-fixture compatibility seam only.
pub fn write_record<T>(
    paths: &AppPaths,
    kind: RecordKind,
    id: &str,
    _written_at_ms: u64,
    record: &T,
) -> Result<(), StoreError>
where
    T: Serialize,
{
    // Validate the id up front (input hygiene: reject a traversing/illegal id before it reaches any query). Path-safety
    // no longer matters — ids are query parameters, not path components — but the invariant + its tests stay.
    let _ = paths.record_path(kind, id)?;

    // Serialize to a JSON Value, then map the typed columns + JSON sub-columns per kind (store_sqlite). A single-row
    // upsert is atomic on its own. WindowLayout spans the windows + tabs tables, so its complete replacement receives
    // an explicit writer fence and commits as one unit before any diagnostic trace is emitted.
    let value = serde_json::to_value(record).map_err(StoreError::from_json)?;
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let mut conn = arc.lock().unwrap();
    match kind {
        RecordKind::WindowLayout => {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| StoreError::Db(error.to_string()))?;
            crate::store_sqlite::upsert(&tx, kind, id, &value).map_err(StoreError::from_map)?;
            crate::db::bump_window_mutation_epoch(&tx).map_err(StoreError::from_db)?;
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
        }
        RecordKind::Project => {
            // This compatibility upsert remains unconditional, but a project-order change is an
            // ownership mutation and must still participate in the global window generation.
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let empty_order = serde_json::Value::Array(Vec::new());
            let previous = crate::store_sqlite::load_one(&tx, kind, id)
                .map_err(StoreError::from_map)?
                .and_then(|project| project.get("window_order").cloned())
                .unwrap_or_else(|| empty_order.clone());
            let next = value.get("window_order").cloned().unwrap_or(empty_order);
            crate::store_sqlite::upsert(&tx, kind, id, &value).map_err(StoreError::from_map)?;
            if previous != next {
                crate::db::bump_window_mutation_epoch(&tx).map_err(StoreError::from_db)?;
            }
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
        }
        _ => {
            crate::store_sqlite::upsert(&conn, kind, id, &value).map_err(StoreError::from_map)?;
        }
    }
    // Bounded write diagnostics: record the mutation (kind + local id + top-level field NAMES) so both writers
    // (desktop app + agent) leave an attributable, ordered forensic trail. For WindowLayout this is necessarily after
    // COMMIT; a mapping or commit failure rolls the transaction back and returns without a false-success trace.
    let fields: Vec<String> = value
        .as_object()
        .map(|o| o.keys().cloned().collect())
        .unwrap_or_default();
    crate::write_trace::trace_write(
        paths.base(),
        &format!("{kind:?}"),
        id,
        &fields,
        _written_at_ms,
    );
    Ok(())
}

/// Read and validate ONE record file.
///
/// - Valid record -> `Loaded`.
/// - Future schema version -> `FutureVersion`, LEFT IN PLACE (read-only/unmigratable; never
///   quarantined or rewritten, since rewriting could drop fields a newer build added).
/// - Malformed JSON / schema mismatch / wrong type -> `Quarantined` (moved to `corrupt/`,
///   preserved, excluded from loaded data).
fn read_one<T>(
    paths: &AppPaths,
    kind: RecordKind,
    file: &Path,
) -> Result<LoadOutcome<T>, StoreError>
where
    T: DeserializeOwned,
{
    let bytes = match fs::read(file) {
        Ok(b) => b,
        Err(e) => return Err(StoreError::Io(e)),
    };
    match Envelope::<T>::from_json_bytes(&bytes, kind.schema()) {
        Ok(env) => Ok(LoadOutcome::Loaded(env.record)),
        // A future-version record is intact and trustworthy bytes from a NEWER build; leave it
        // exactly where it is and surface the version gap. Do not quarantine it like corruption.
        Err(EnvelopeError::FutureVersion { ours, got }) => Ok(LoadOutcome::FutureVersion {
            path: file.to_path_buf(),
            ours,
            got,
        }),
        Err(e) => {
            let moved_to = quarantine(paths, file)?;
            Ok(LoadOutcome::Quarantined {
                original: file.to_path_buf(),
                moved_to,
                reason: e.to_string(),
            })
        }
    }
}

/// Move a bad record into the quarantine dir as `corrupt/<name>.<ms>.bad`. Never deletes the
/// data; a human (or a later GC) can inspect it.
fn quarantine(paths: &AppPaths, file: &Path) -> Result<PathBuf, StoreError> {
    let qdir = paths.corrupt_dir();
    ensure_dir(&qdir)?;
    let name = file
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "record".to_string());
    let ms = now_ms_monotonicish();
    let dest = qdir.join(format!("{name}.{ms}.bad"));
    fs::rename(file, &dest)?;
    Ok(dest)
}

/// A timestamp suffix for quarantine filenames. Uses wall-clock millis; collisions across the
/// same millisecond are avoided by including the pid.
fn now_ms_monotonicish() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_millis())
        .unwrap_or(0);
    format!("{ms}.{}", std::process::id())
}

/// Load every record of `kind` from its directory. Valid records come back as `Loaded`;
/// corrupt files are quarantined and reported as `Quarantined` (and excluded from any data the
/// caller keeps). A missing directory yields an empty vec (nothing persisted yet).
pub fn load_all<T>(paths: &AppPaths, kind: RecordKind) -> Result<Vec<LoadOutcome<T>>, StoreError>
where
    T: DeserializeOwned,
{
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let conn = arc.lock().unwrap();
    let values = crate::store_sqlite::load_all(&conn, kind).map_err(StoreError::from_map)?;
    Ok(values.into_iter().map(value_to_outcome::<T>).collect())
}

/// Load the `agent:session_id → custom_name` map (only rows that actually have a name). Replaces the JSON sidecar.
pub fn load_session_names(
    paths: &AppPaths,
) -> Result<std::collections::BTreeMap<String, String>, StoreError> {
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let conn = arc.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT key, custom_name FROM session_names WHERE custom_name IS NOT NULL")
        .map_err(|e| StoreError::Db(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| Ok((r.get::<_, String>(0)?, r.get::<_, String>(1)?)))
        .map_err(|e| StoreError::Db(e.to_string()))?;
    let mut map = std::collections::BTreeMap::new();
    for row in rows {
        let (k, v) = row.map_err(|e| StoreError::Db(e.to_string()))?;
        map.insert(k, v);
    }
    Ok(map)
}

/// Load the set of hidden session keys (`agent:session_id`). Replaces the hiddenSessions JSON sidecar.
pub fn load_hidden_sessions(
    paths: &AppPaths,
) -> Result<std::collections::BTreeSet<String>, StoreError> {
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let conn = arc.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT key FROM session_names WHERE hidden = 1")
        .map_err(|e| StoreError::Db(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| r.get::<_, String>(0))
        .map_err(|e| StoreError::Db(e.to_string()))?;
    let mut set = std::collections::BTreeSet::new();
    for row in rows {
        set.insert(row.map_err(|e| StoreError::Db(e.to_string()))?);
    }
    Ok(set)
}

/// Replace the ENTIRE set of custom names with `names` (agent:session_id → name), preserving hidden flags. Used by the
/// whole-map writer that mirrors the old JSON sidecar semantics.
pub fn replace_session_names(
    paths: &AppPaths,
    names: &std::collections::BTreeMap<String, String>,
) -> Result<(), StoreError> {
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let mut conn = arc.lock().unwrap();
    let tx = conn
        .transaction()
        .map_err(|e| StoreError::Db(e.to_string()))?;
    tx.execute("UPDATE session_names SET custom_name = NULL", [])
        .map_err(|e| StoreError::Db(e.to_string()))?;
    for (key, name) in names {
        tx.execute(
            "INSERT INTO session_names (key, custom_name) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET custom_name = excluded.custom_name",
            rusqlite::params![key, name],
        )
        .map_err(|e| StoreError::Db(e.to_string()))?;
    }
    tx.execute(
        "DELETE FROM session_names WHERE custom_name IS NULL AND hidden = 0",
        [],
    )
    .map_err(|e| StoreError::Db(e.to_string()))?;
    tx.commit().map_err(|e| StoreError::Db(e.to_string()))?;
    Ok(())
}

/// Replace the ENTIRE set of hidden session keys with `hidden`, preserving custom names.
pub fn replace_hidden_sessions(
    paths: &AppPaths,
    hidden: &std::collections::BTreeSet<String>,
) -> Result<(), StoreError> {
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let mut conn = arc.lock().unwrap();
    let tx = conn
        .transaction()
        .map_err(|e| StoreError::Db(e.to_string()))?;
    tx.execute("UPDATE session_names SET hidden = 0", [])
        .map_err(|e| StoreError::Db(e.to_string()))?;
    for key in hidden {
        tx.execute(
            "INSERT INTO session_names (key, hidden) VALUES (?1, 1) \
             ON CONFLICT(key) DO UPDATE SET hidden = 1",
            [key],
        )
        .map_err(|e| StoreError::Db(e.to_string()))?;
    }
    tx.execute(
        "DELETE FROM session_names WHERE custom_name IS NULL AND hidden = 0",
        [],
    )
    .map_err(|e| StoreError::Db(e.to_string()))?;
    tx.commit().map_err(|e| StoreError::Db(e.to_string()))?;
    Ok(())
}

/// Set (or clear, with `None`) a session's custom name. Upserts the row; a cleared name + not-hidden row is pruned.
pub fn set_session_name(paths: &AppPaths, key: &str, name: Option<&str>) -> Result<(), StoreError> {
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let conn = arc.lock().unwrap();
    conn.execute(
        "INSERT INTO session_names (key, custom_name) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET custom_name = excluded.custom_name",
        rusqlite::params![key, name],
    )
    .map_err(|e| StoreError::Db(e.to_string()))?;
    conn.execute(
        "DELETE FROM session_names WHERE key = ?1 AND custom_name IS NULL AND hidden = 0",
        [key],
    )
    .map_err(|e| StoreError::Db(e.to_string()))?;
    Ok(())
}

/// Set (or clear) a session's hidden flag. Upserts; a not-hidden row with no name is pruned.
pub fn set_session_hidden(paths: &AppPaths, key: &str, hidden: bool) -> Result<(), StoreError> {
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let conn = arc.lock().unwrap();
    conn.execute(
        "INSERT INTO session_names (key, hidden) VALUES (?1, ?2) \
         ON CONFLICT(key) DO UPDATE SET hidden = excluded.hidden",
        rusqlite::params![key, hidden as i64],
    )
    .map_err(|e| StoreError::Db(e.to_string()))?;
    conn.execute(
        "DELETE FROM session_names WHERE key = ?1 AND custom_name IS NULL AND hidden = 0",
        [key],
    )
    .map_err(|e| StoreError::Db(e.to_string()))?;
    Ok(())
}

/// Unconditionally stamp a window's owning project id.
///
/// Compatibility seam for migration/bootstrap fixtures and tests only. Ordinary production flows
/// must use [`crate::WindowLayoutService::ensure_project_assignment`] (NULL-or-same) or
/// [`crate::WindowLayoutService::assign_project_and_order_if_unchanged`] (exact snapshot), which
/// update the FK and project order together and cannot retarget a concurrent foreign owner.
pub fn set_window_project(
    paths: &AppPaths,
    window_id: &str,
    project_id: &str,
) -> Result<(), StoreError> {
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let mut conn = arc.lock().unwrap();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| StoreError::Db(error.to_string()))?;
    let changed = crate::store_sqlite::set_window_project(&tx, window_id, project_id)
        .map_err(StoreError::from_map)?;
    if changed {
        crate::db::bump_window_mutation_epoch(&tx).map_err(StoreError::from_db)?;
    }
    tx.commit()
        .map_err(|error| StoreError::Db(error.to_string()))?;
    let result = Ok(());
    // DB-write log net: the ownership stamp bypasses write_record (it is a raw column update), so trace it
    // here — otherwise "who linked this window to this project" is invisible in the forensic trail. Content-
    // blind: kind + window id + the one field NAME; wall clock (no caller timestamp on this path).
    if changed {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        crate::write_trace::trace_write(
            paths.base(),
            "WindowOwner",
            window_id,
            &["project_id".into()],
            ts,
        );
    }
    result
}

/// All `(window_id, project_id)` ownership stamps from the `windows` table (`None` = unstamped). Used by the
/// ownership repair to find windows whose FK owner is missing while the dashboard can still derive one.
pub fn window_project_owners(
    paths: &AppPaths,
) -> Result<Vec<(String, Option<String>)>, StoreError> {
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let conn = arc.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT window_id, project_id FROM windows ORDER BY window_id")
        .map_err(|e| StoreError::Db(e.to_string()))?;
    let rows = stmt
        .query_map([], |r| {
            Ok((r.get::<_, String>(0)?, r.get::<_, Option<String>>(1)?))
        })
        .map_err(|e| StoreError::Db(e.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| StoreError::Db(e.to_string()))?;
    Ok(rows)
}

/// Current window IDs in insertion order, solely for appending presentation metadata. Ordinary
/// record updates retain rowid; deletion/recreation does not make this an incarnation authority.
/// The connection guard is released before the caller can write its separate settings file.
pub fn window_ids_in_creation_order(paths: &AppPaths) -> Result<Vec<String>, StoreError> {
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let conn = arc.lock().unwrap();
    let mut stmt = conn
        .prepare("SELECT window_id FROM windows ORDER BY rowid")
        .map_err(|error| StoreError::Db(error.to_string()))?;
    let rows = stmt
        .query_map([], |row| row.get(0))
        .map_err(|error| StoreError::Db(error.to_string()))?
        .collect::<Result<Vec<_>, _>>()
        .map_err(|error| StoreError::Db(error.to_string()))?;
    Ok(rows)
}

/// Delete a record by id. FK `ON DELETE CASCADE` removes its children (deleting a project cascades to its workspaces,
/// sessions, windows, tabs, agent_tasks, and project-scoped presets; deleting a window cascades to its tabs). Returns
/// whether a row was removed (idempotent — a missing id is `Ok(false)`). Replaces the old `fs::remove_file`.
///
/// Project, Workspace, and Session ids participate in the durable ownership namespace used by a
/// prepared WindowLayout restore. Their actual deletion therefore advances the global window
/// epoch once in the same transaction, including when an FK cascade removes descendants. Ordinary
/// metadata updates and creation remain epoch-quiet; a same-id recreation necessarily crosses the
/// preceding deletion fence.
pub fn delete_record(paths: &AppPaths, kind: RecordKind, id: &str) -> Result<bool, StoreError> {
    let _ = paths.record_path(kind, id)?; // id hygiene, preserved
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let mut conn = arc.lock().unwrap();
    let result = match kind {
        RecordKind::WindowLayout
        | RecordKind::Project
        | RecordKind::Workspace
        | RecordKind::Session => {
            let tx = conn
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .map_err(|error| StoreError::Db(error.to_string()))?;
            let removed =
                crate::store_sqlite::delete(&tx, kind, id).map_err(StoreError::from_map)?;
            if removed {
                crate::db::bump_window_mutation_epoch(&tx).map_err(StoreError::from_db)?;
            }
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            Ok(removed)
        }
        _ => crate::store_sqlite::delete(&conn, kind, id).map_err(StoreError::from_map),
    };
    // DB-write log net: trace deletes too (the 'who deleted this window' evidence). Only on an actual removal.
    if matches!(result, Ok(true)) {
        let ts = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_millis() as u64)
            .unwrap_or(0);
        crate::write_trace::trace_delete(paths.base(), &format!("{kind:?}"), id, ts);
    }
    result
}

/// Deserialize a loaded row Value into `T`. A row whose JSON sub-columns don't fit `T` is surfaced as `Quarantined`
/// (skipped from the loaded set, like the old corrupt-file quarantine) rather than failing the whole load. There is no
/// file to move, so `original`/`moved_to` are best-effort markers.
fn value_to_outcome<T: DeserializeOwned>(value: serde_json::Value) -> LoadOutcome<T> {
    match serde_json::from_value::<T>(value) {
        Ok(record) => LoadOutcome::Loaded(record),
        Err(e) => LoadOutcome::Quarantined {
            original: PathBuf::new(),
            moved_to: PathBuf::new(),
            reason: format!("row failed to deserialize: {e}"),
        },
    }
}

/// Read one record by id, validating its envelope. The `id` is VALIDATED first (a traversing
/// id is refused with `StoreError::Id`, never turned into a path). `Ok(None)` means "not
/// present"; otherwise the `LoadOutcome` lets the caller see Loaded / Quarantined / FutureVersion.
pub fn load_one<T>(
    paths: &AppPaths,
    kind: RecordKind,
    id: &str,
) -> Result<Option<LoadOutcome<T>>, StoreError>
where
    T: DeserializeOwned,
{
    // Validate the id first (a traversing id is refused, preserving the old invariant + its tests).
    let _ = paths.record_path(kind, id)?;
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let conn = arc.lock().unwrap();
    match crate::store_sqlite::load_one(&conn, kind, id).map_err(StoreError::from_map)? {
        None => Ok(None),
        Some(value) => Ok(Some(value_to_outcome::<T>(value))),
    }
}

/// Compare one complete Session A and its complete Workspace W inside ONE SQLite read snapshot.
///
/// Generation-conditional Attach/Start callers use this immediately before their first daemon
/// frame. Two independent `load_one` calls are not authority: another process could change A and W
/// between them and make bytes that never coexisted look like the reviewed pair. A DEFERRED
/// transaction fixes the snapshot on the Session read and keeps the Workspace comparison on that
/// same database version. A caller-owned outer transaction remains authoritative and is reused.
pub(crate) fn session_workspace_rows_match_in_snapshot(
    paths: &AppPaths,
    expected_session: &crate::records::SessionRecord,
    expected_workspace: &crate::records::Workspace,
) -> Result<bool, StoreError> {
    let _ = paths.record_path(RecordKind::Session, &expected_session.session_id)?;
    let _ = paths.record_path(RecordKind::Workspace, &expected_workspace.workspace_id)?;
    if expected_session.workspace_id != expected_workspace.workspace_id {
        return Ok(false);
    }

    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let mut conn = arc.lock().unwrap();
    let compare = |conn: &rusqlite::Connection| -> Result<bool, StoreError> {
        let session =
            crate::store_sqlite::load_one(conn, RecordKind::Session, &expected_session.session_id)
                .map_err(StoreError::from_map)?
                .map(value_to_outcome::<crate::records::SessionRecord>);

        // Deterministic cross-connection race seam. Production has no hook; tests can commit a
        // complete A/W replacement here and prove the following Workspace read remains on the
        // snapshot established by the Session SELECT above.
        #[cfg(test)]
        crate::store_sqlite::run_window_layout_test_hook(
            "after-exact-session-before-workspace",
            &expected_session.session_id,
        );

        let workspace = crate::store_sqlite::load_one(
            conn,
            RecordKind::Workspace,
            &expected_workspace.workspace_id,
        )
        .map_err(StoreError::from_map)?
        .map(value_to_outcome::<crate::records::Workspace>);
        Ok(
            matches!(session, Some(LoadOutcome::Loaded(current)) if current == *expected_session)
                && matches!(workspace, Some(LoadOutcome::Loaded(current)) if current == *expected_workspace),
        )
    };

    if conn.is_autocommit() {
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Deferred)
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let matches = compare(&tx)?;
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        Ok(matches)
    } else {
        compare(&conn)
    }
}

/// Result of the narrow insert-only Session creation seam used by remote pane allocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CreateSessionRecordOutcome {
    Created,
    AlreadyExists,
}

/// Result of atomically establishing one exact Workspace (if absent) and one new Session. A
/// concurrent/non-identical Workspace or any same-id Session returns `Conflict`; neither requested
/// row is written in that case.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum CreateWorkspaceSessionOutcome {
    Created { workspace_created: bool },
    Conflict,
}

pub(crate) fn create_workspace_and_session_if_absent(
    paths: &AppPaths,
    workspace: &crate::records::Workspace,
    session: &crate::records::SessionRecord,
    written_at_ms: u64,
) -> Result<CreateWorkspaceSessionOutcome, StoreError> {
    let workspace_id = workspace.workspace_id.as_str();
    let session_id = session.session_id.as_str();
    if session.workspace_id != workspace.workspace_id {
        return Err(StoreError::Db(
            "new Session workspace id does not match exact Workspace authority".into(),
        ));
    }
    let _ = paths.record_path(RecordKind::Workspace, workspace_id)?;
    let _ = paths.record_path(RecordKind::Session, session_id)?;
    let workspace_value = serde_json::to_value(workspace).map_err(StoreError::from_json)?;
    let session_value = serde_json::to_value(session).map_err(StoreError::from_json)?;
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let mut conn = arc.lock().unwrap();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| StoreError::Db(error.to_string()))?;

    let workspace_created =
        match crate::store_sqlite::load_one(&tx, RecordKind::Workspace, workspace_id)
            .map_err(StoreError::from_map)?
        {
            Some(current) if current == workspace_value => false,
            Some(_) => return Ok(CreateWorkspaceSessionOutcome::Conflict),
            None => {
                crate::store_sqlite::upsert(
                    &tx,
                    RecordKind::Workspace,
                    workspace_id,
                    &workspace_value,
                )
                .map_err(StoreError::from_map)?;
                true
            }
        };

    if crate::store_sqlite::load_one(&tx, RecordKind::Session, session_id)
        .map_err(StoreError::from_map)?
        .is_some()
    {
        return Ok(CreateWorkspaceSessionOutcome::Conflict);
    }
    crate::store_sqlite::upsert(&tx, RecordKind::Session, session_id, &session_value)
        .map_err(StoreError::from_map)?;
    tx.commit()
        .map_err(|error| StoreError::Db(error.to_string()))?;

    if workspace_created {
        let fields = workspace_value
            .as_object()
            .map(|object| object.keys().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        crate::write_trace::trace_write(
            paths.base(),
            "Workspace",
            workspace_id,
            &fields,
            written_at_ms,
        );
    }
    let fields = session_value
        .as_object()
        .map(|object| object.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    crate::write_trace::trace_write(paths.base(), "Session", session_id, &fields, written_at_ms);
    Ok(CreateWorkspaceSessionOutcome::Created { workspace_created })
}

/// Insert one exact Session identity iff that id is absent at the `BEGIN IMMEDIATE` writer
/// snapshot. Unlike [`write_record`], this never adopts or overwrites an existing durable Session.
/// Session creation is intentionally quiet on the global window epoch; a later identity deletion
/// is the ABA fence. Only a committed insert emits a trace.
pub fn create_session_record_if_absent(
    paths: &AppPaths,
    record: &crate::records::SessionRecord,
    written_at_ms: u64,
) -> Result<CreateSessionRecordOutcome, StoreError> {
    let id = record.session_id.as_str();
    let _ = paths.record_path(RecordKind::Session, id)?;
    let value = serde_json::to_value(record).map_err(StoreError::from_json)?;
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let mut conn = arc.lock().unwrap();
    #[cfg(test)]
    crate::store_sqlite::run_window_layout_test_hook("before-create-session-transaction", id);
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| StoreError::Db(error.to_string()))?;
    if crate::store_sqlite::load_one(&tx, RecordKind::Session, id)
        .map_err(StoreError::from_map)?
        .is_some()
    {
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        return Ok(CreateSessionRecordOutcome::AlreadyExists);
    }
    crate::store_sqlite::upsert(&tx, RecordKind::Session, id, &value)
        .map_err(StoreError::from_map)?;
    tx.commit()
        .map_err(|error| StoreError::Db(error.to_string()))?;

    let fields = value
        .as_object()
        .map(|object| object.keys().cloned().collect::<Vec<_>>())
        .unwrap_or_default();
    crate::write_trace::trace_write(paths.base(), "Session", id, &fields, written_at_ms);
    Ok(CreateSessionRecordOutcome::Created)
}

/// Store-internal result for an atomic, generation-guarded session exit update. Kept separate from
/// the public SessionService result so the generic store boundary does not expose domain APIs.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConditionalSessionExit {
    MarkedExited,
    AlreadyExited,
    Missing,
    GenerationMismatch,
    Quarantined,
}

/// Result of one optimistic session-reconciliation transaction. `Stale` means another writer
/// changed status or generation after the caller's snapshot; the current record is returned and is
/// never overwritten. This keeps background reconciliation from clobbering a concurrent restart.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum ConditionalSessionReconcile {
    Updated(crate::records::SessionRecord),
    Unchanged(crate::records::SessionRecord),
    Stale(crate::records::SessionRecord),
    Missing,
    Quarantined,
}

/// Result of publishing one Grid-proven Session lifetime back into the durable graph while the
/// daemon connection that supplied the Grid still owns an attachment guard for that exact
/// lifetime.  The write is conditional on the complete pre-attach Session row: a concurrent
/// destructive transaction wins by deleting or changing that row, and this path never recreates
/// it from stale launch state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ConditionalSessionAttachFinalize {
    /// The exact expected row was updated and every older journal target for the adopted lifetime
    /// was consumed in the same transaction.  The count is diagnostic only.
    Finalized { consumed_release_targets: usize },
    /// The Session identity was deleted after the caller established its pre-attach snapshot.
    Missing,
    /// Another writer changed the Session row.  Its replacement bytes remain untouched.
    Changed,
    /// The transaction-local row could not be decoded as this build's SessionRecord.
    Quarantined,
}

/// Atomically publish a Grid-proven Session row and retire stale release intents for the exact
/// adopted PTY lifetime.
///
/// The daemon attachment is held by the caller across this transaction.  Therefore a drainer that
/// reached its daemon CAS first either removed the lifetime (and no Grid could have been returned)
/// or is refused by the attachment fence; a drainer that reaches SQLite first holds the same
/// `BEGIN IMMEDIATE` fence and this writer waits for its verdict.  Once the exact `expected` row is
/// revalidated, the Session update and journal retirement commit together.  A destructive delete
/// committed after this transaction inserts a fresh journal target and remains authoritative.
pub(crate) fn finalize_session_attach_if_unchanged(
    paths: &AppPaths,
    expected: &crate::records::SessionRecord,
    replacement: &crate::records::SessionRecord,
    expected_generation: &str,
    written_at_ms: u64,
) -> Result<ConditionalSessionAttachFinalize, StoreError> {
    finalize_session_attach_if_unchanged_with_workspace(
        paths,
        expected,
        replacement,
        None,
        expected_generation,
        written_at_ms,
    )
}

pub(crate) fn finalize_session_attach_if_unchanged_with_workspace(
    paths: &AppPaths,
    expected: &crate::records::SessionRecord,
    replacement: &crate::records::SessionRecord,
    expected_workspace: Option<&crate::records::Workspace>,
    expected_generation: &str,
    written_at_ms: u64,
) -> Result<ConditionalSessionAttachFinalize, StoreError> {
    finalize_session_attach_if_unchanged_with_workspace_and_guard(
        paths,
        expected,
        replacement,
        expected_workspace,
        expected_generation,
        written_at_ms,
        |_| Ok(true),
    )
}

/// Graph-aware form of [`finalize_session_attach_if_unchanged_with_workspace`].  `guard` runs
/// inside the same `BEGIN IMMEDIATE` transaction after exact Session+Workspace revalidation and
/// before the Session upsert/release-receipt retirement.  This is intentionally crate-private:
/// only opaque domain authorities may add publication predicates; callers cannot pass a stale
/// preflight boolean and reopen the check→write race.
pub(crate) fn finalize_session_attach_if_unchanged_with_workspace_and_guard(
    paths: &AppPaths,
    expected: &crate::records::SessionRecord,
    replacement: &crate::records::SessionRecord,
    expected_workspace: Option<&crate::records::Workspace>,
    expected_generation: &str,
    written_at_ms: u64,
    guard: impl FnOnce(&rusqlite::Transaction<'_>) -> Result<bool, StoreError>,
) -> Result<ConditionalSessionAttachFinalize, StoreError> {
    use crate::records::SessionRecord;

    let id = expected.session_id.as_str();
    let _ = paths.record_path(RecordKind::Session, id)?;
    if replacement.session_id != expected.session_id
        || replacement.last_known_generation.as_deref() != Some(expected_generation)
        || expected_workspace
            .is_some_and(|workspace| workspace.workspace_id != expected.workspace_id)
        || expected_generation.is_empty()
        || expected_generation.len() > 128
    {
        return Err(StoreError::Db(
            "invalid generation-bound Session attach finalization".into(),
        ));
    }
    let replacement_value = serde_json::to_value(replacement).map_err(StoreError::from_json)?;
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let mut conn = arc.lock().unwrap();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| StoreError::Db(error.to_string()))?;

    let raw = crate::store_sqlite::load_one(&tx, RecordKind::Session, id)
        .map_err(StoreError::from_map)?;
    let Some(raw) = raw else {
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        return Ok(ConditionalSessionAttachFinalize::Missing);
    };
    let current = match serde_json::from_value::<SessionRecord>(raw) {
        Ok(record) => record,
        Err(_) => {
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            return Ok(ConditionalSessionAttachFinalize::Quarantined);
        }
    };
    if current != *expected {
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        return Ok(ConditionalSessionAttachFinalize::Changed);
    }
    if let Some(expected_workspace) = expected_workspace {
        let workspace_raw = crate::store_sqlite::load_one(
            &tx,
            RecordKind::Workspace,
            &expected_workspace.workspace_id,
        )
        .map_err(StoreError::from_map)?;
        let workspace_matches = workspace_raw
            .and_then(|raw| serde_json::from_value::<crate::records::Workspace>(raw).ok())
            .is_some_and(|current| current == *expected_workspace);
        if !workspace_matches {
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            return Ok(ConditionalSessionAttachFinalize::Changed);
        }
    }
    if !guard(&tx)? {
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        return Ok(ConditionalSessionAttachFinalize::Changed);
    }

    crate::store_sqlite::upsert(&tx, RecordKind::Session, id, &replacement_value)
        .map_err(StoreError::from_map)?;

    // Re-adoption changes the meaning of every operation that still contains this exact
    // lifetime. In particular, a mixed operation `[adopted A, still-pending B]` must not retain
    // its initiator lease: that stale receipt could otherwise mint compensation for, or cancel,
    // sibling B after A has already become durable again. Invalidate every affected operation
    // before deleting A, and rotate the survivors behind existing work. A stale owned receipt or
    // forward claim then fails its exact-token check without entering the daemon CAS; any sibling
    // targets remain available only through a fresh forward claim.
    let affected_operations = {
        let mut statement = tx
            .prepare(
                "SELECT DISTINCT operation_id FROM pending_session_releases \
                 WHERE session_id = ?1 AND expected_generation = ?2 \
                 ORDER BY operation_id",
            )
            .map_err(|error| StoreError::Db(error.to_string()))?;
        let rows = statement
            .query_map(rusqlite::params![id, expected_generation], |row| row.get(0))
            .map_err(|error| StoreError::Db(error.to_string()))?;
        rows.collect::<Result<Vec<String>, _>>()
            .map_err(|error| StoreError::Db(error.to_string()))?
    };
    let written_at = i64::try_from(written_at_ms)
        .map_err(|_| StoreError::Db("session attach timestamp exceeds SQLite range".into()))?;
    let mut rotated_at: i64 = tx
        .query_row(
            "SELECT COALESCE(MAX(created_at_ms), ?1) FROM session_release_operations",
            [written_at],
            |row| row.get(0),
        )
        .map_err(|error| StoreError::Db(error.to_string()))?;
    rotated_at = rotated_at.max(written_at);
    for operation_id in &affected_operations {
        rotated_at = rotated_at
            .checked_add(1)
            .ok_or_else(|| StoreError::Db("session release schedule overflow".into()))?;
        tx.execute(
            "UPDATE session_release_operations \
             SET lease_token = NULL, lease_until_ms = NULL, created_at_ms = ?2 \
             WHERE operation_id = ?1",
            rusqlite::params![operation_id, rotated_at],
        )
        .map_err(|error| StoreError::Db(error.to_string()))?;
    }
    let consumed = tx
        .execute(
            "DELETE FROM pending_session_releases \
             WHERE session_id = ?1 AND expected_generation = ?2",
            rusqlite::params![id, expected_generation],
        )
        .map_err(|error| StoreError::Db(error.to_string()))?;
    // Removing the final target cascades no direction back to its operation, so prune only now-
    // empty operation rows. Operations with unrelated remaining targets keep the freshly rotated,
    // unleased forward-only schedule established above.
    tx.execute(
        "DELETE FROM session_release_operations \
         WHERE NOT EXISTS (SELECT 1 FROM pending_session_releases pending \
                           WHERE pending.operation_id = session_release_operations.operation_id)",
        [],
    )
    .map_err(|error| StoreError::Db(error.to_string()))?;
    tx.commit()
        .map_err(|error| StoreError::Db(error.to_string()))?;

    let fields: Vec<String> = replacement_value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    crate::write_trace::trace_write(paths.base(), "Session", id, &fields, written_at_ms);
    Ok(ConditionalSessionAttachFinalize::Finalized {
        consumed_release_targets: consumed,
    })
}

/// Atomically reconcile status/generation iff the persisted record still matches the caller's
/// snapshot. The mutation is applied to the freshly loaded transaction-local record, not to the
/// caller's stale copy, so concurrent changes to unrelated fields are preserved as well.
pub(crate) fn reconcile_session_if_unchanged(
    paths: &AppPaths,
    id: &str,
    expected_status: crate::records::SessionStatus,
    expected_generation: Option<&str>,
    desired_status: crate::records::SessionStatus,
    desired_generation: Option<&str>,
    written_at_ms: u64,
) -> Result<ConditionalSessionReconcile, StoreError> {
    use crate::records::SessionRecord;

    let _ = paths.record_path(RecordKind::Session, id)?;
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let mut conn = arc.lock().unwrap();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| StoreError::Db(error.to_string()))?;

    let raw = crate::store_sqlite::load_one(&tx, RecordKind::Session, id)
        .map_err(StoreError::from_map)?;
    let Some(raw) = raw else {
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        return Ok(ConditionalSessionReconcile::Missing);
    };
    let mut current = match serde_json::from_value::<SessionRecord>(raw) {
        Ok(record) => record,
        Err(_) => {
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            return Ok(ConditionalSessionReconcile::Quarantined);
        }
    };

    if current.status != expected_status
        || current.last_known_generation.as_deref() != expected_generation
    {
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        return Ok(ConditionalSessionReconcile::Stale(current));
    }
    if current.status == desired_status
        && current.last_known_generation.as_deref() == desired_generation
    {
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        return Ok(ConditionalSessionReconcile::Unchanged(current));
    }

    current.status = desired_status;
    current.last_known_generation = desired_generation.map(str::to_string);
    let value = serde_json::to_value(&current).map_err(StoreError::from_json)?;
    crate::store_sqlite::upsert(&tx, RecordKind::Session, id, &value)
        .map_err(StoreError::from_map)?;
    tx.commit()
        .map_err(|error| StoreError::Db(error.to_string()))?;

    let fields: Vec<String> = value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    crate::write_trace::trace_write(paths.base(), "Session", id, &fields, written_at_ms);
    Ok(ConditionalSessionReconcile::Updated(current))
}

/// Atomically mark one session record Exited iff its currently persisted generation matches.
///
/// The read, generation comparison, and write share one `IMMEDIATE` SQLite transaction. This is
/// stronger than composing `load_one` + `write_record`: Hydra has two local writer processes, and a
/// same-id restart could otherwise publish a new generation between those calls and then be
/// overwritten by a delayed exit from the old process lifetime.
pub(crate) fn mark_session_exited_if_generation(
    paths: &AppPaths,
    id: &str,
    observed_generation: &str,
    written_at_ms: u64,
) -> Result<ConditionalSessionExit, StoreError> {
    use crate::records::{SessionRecord, SessionStatus};

    let _ = paths.record_path(RecordKind::Session, id)?;
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let mut conn = arc.lock().unwrap();
    let tx = conn
        .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
        .map_err(|error| StoreError::Db(error.to_string()))?;

    let raw = crate::store_sqlite::load_one(&tx, RecordKind::Session, id)
        .map_err(StoreError::from_map)?;
    let Some(raw) = raw else {
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        return Ok(ConditionalSessionExit::Missing);
    };
    let mut record = match serde_json::from_value::<SessionRecord>(raw) {
        Ok(record) => record,
        Err(_) => {
            tx.commit()
                .map_err(|error| StoreError::Db(error.to_string()))?;
            return Ok(ConditionalSessionExit::Quarantined);
        }
    };
    if record.last_known_generation.as_deref() != Some(observed_generation) {
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        return Ok(ConditionalSessionExit::GenerationMismatch);
    }
    if record.status == SessionStatus::Exited {
        tx.commit()
            .map_err(|error| StoreError::Db(error.to_string()))?;
        return Ok(ConditionalSessionExit::AlreadyExited);
    }

    record.status = SessionStatus::Exited;
    let value = serde_json::to_value(&record).map_err(StoreError::from_json)?;
    crate::store_sqlite::upsert(&tx, RecordKind::Session, id, &value)
        .map_err(StoreError::from_map)?;
    tx.commit()
        .map_err(|error| StoreError::Db(error.to_string()))?;

    let fields: Vec<String> = value
        .as_object()
        .map(|object| object.keys().cloned().collect())
        .unwrap_or_default();
    crate::write_trace::trace_write(paths.base(), "Session", id, &fields, written_at_ms);
    Ok(ConditionalSessionExit::MarkedExited)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::WorkspacePolicy;
    use crate::records::{
        AttentionState, LaunchSpec, Project, SessionKind, SessionRecord, SessionStatus, TabRecord,
        WindowLayout, Workspace, WorkspaceConsent,
    };
    use tempfile::TempDir;

    fn paths_in(tmp: &TempDir) -> AppPaths {
        AppPaths::with_base(tmp.path().join("Maestro"))
    }

    fn project(id: &str, name: &str) -> Project {
        Project {
            project_id: id.into(),
            name: name.into(),
            root: "/home/u/repo".into(),
            default_workspace_policy: WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order: Vec::new(),
            system: false,
            hidden: false,
        }
    }

    fn child_identity_graph_with_suffix(
        suffix: &str,
    ) -> (TempDir, AppPaths, Workspace, SessionRecord) {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let id = |base: &str| {
            if suffix.is_empty() {
                base.to_string()
            } else {
                format!("{base}-{suffix}")
            }
        };
        let project = project(&id("child-identity-project"), "Child identity project");
        let workspace = Workspace {
            workspace_id: id("child-identity-workspace"),
            project_id: project.project_id.clone(),
            root: "/home/u/repo".into(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        };
        let session = SessionRecord {
            session_id: id("child-identity-session"),
            workspace_id: workspace.workspace_id.clone(),
            kind: SessionKind::Shell,
            launch: LaunchSpec::OptOut,
            cwd_resolved: workspace.root.clone(),
            agent_task_id: None,
            created_at_ms: 41,
            last_attached_at_ms: 41,
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        write_record(
            &paths,
            RecordKind::Project,
            &project.project_id,
            41,
            &project,
        )
        .unwrap();
        write_record(
            &paths,
            RecordKind::Workspace,
            &workspace.workspace_id,
            41,
            &workspace,
        )
        .unwrap();
        write_record(
            &paths,
            RecordKind::Session,
            &session.session_id,
            41,
            &session,
        )
        .unwrap();
        (tmp, paths, workspace, session)
    }

    fn child_identity_graph() -> (TempDir, AppPaths, Workspace, SessionRecord) {
        child_identity_graph_with_suffix("")
    }

    fn window_layout(window_id: &str, tabs: &[(&str, &str)]) -> WindowLayout {
        WindowLayout {
            window_id: window_id.into(),
            name: Some(format!("layout-{window_id}")),
            tabs: tabs
                .iter()
                .enumerate()
                .map(|(index, (tab_id, session_id))| TabRecord {
                    tab_id: (*tab_id).into(),
                    session_id: (*session_id).into(),
                    index: index as u32,
                    title: format!("tab-{tab_id}"),
                    pinned: false,
                    attention: AttentionState::default(),
                    split_from: None,
                    pane_rect: None,
                    stashed_from: None,
                    stashed: false,
                })
                .collect(),
        }
    }

    fn loaded_window_from_conn(conn: &rusqlite::Connection, window_id: &str) -> WindowLayout {
        serde_json::from_value(
            crate::store_sqlite::load_one(conn, RecordKind::WindowLayout, window_id)
                .unwrap()
                .unwrap(),
        )
        .unwrap()
    }

    fn open_test_writer(paths: &AppPaths) -> rusqlite::Connection {
        let conn = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        conn.pragma_update(None, "foreign_keys", "ON").unwrap();
        conn.pragma_update(None, "busy_timeout", 5000).unwrap();
        conn
    }

    fn window_epoch(paths: &AppPaths) -> u32 {
        let connection = crate::db::conn_for(paths.base()).unwrap();
        let guard = connection.lock().unwrap();
        crate::db::window_mutation_epoch(&guard).unwrap()
    }

    fn replace_windows_atomically(conn: &mut rusqlite::Connection, layouts: &[WindowLayout]) {
        let tx = conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        for layout in layouts {
            let value = serde_json::to_value(layout).unwrap();
            crate::store_sqlite::upsert(&tx, RecordKind::WindowLayout, &layout.window_id, &value)
                .unwrap();
        }
        tx.commit().unwrap();
    }

    fn session_trace_count(session_id: &str) -> usize {
        crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "Session" && event.id == session_id)
            .count()
    }

    #[test]
    fn session_insert_if_absent_creates_exact_row_without_advancing_window_epoch() {
        let (_tmp, paths, workspace, existing) = child_identity_graph();
        let mut expected = existing;
        expected.session_id = "insert-only-fresh-session".into();
        expected.workspace_id = workspace.workspace_id;
        expected.cwd_resolved = "/home/u/fresh".into();
        expected.created_at_ms = 101;
        expected.last_attached_at_ms = 102;

        let epoch_before = window_epoch(&paths);
        let traces_before = session_trace_count(&expected.session_id);
        let outcome = create_session_record_if_absent(&paths, &expected, 103).unwrap();

        assert_eq!(outcome, CreateSessionRecordOutcome::Created);
        let loaded =
            load_one::<SessionRecord>(&paths, RecordKind::Session, &expected.session_id).unwrap();
        assert!(matches!(loaded, Some(LoadOutcome::Loaded(ref row)) if row == &expected));
        assert_eq!(window_epoch(&paths), epoch_before);
        assert_eq!(session_trace_count(&expected.session_id), traces_before + 1);
    }

    #[test]
    fn session_insert_if_absent_never_overwrites_an_existing_identity() {
        let (_tmp, paths, _workspace, existing) =
            child_identity_graph_with_suffix("insert-if-absent-existing");
        let mut refused = existing.clone();
        refused.cwd_resolved = "/home/u/must-not-replace".into();
        refused.created_at_ms = 999;
        refused.status = SessionStatus::Live;

        let epoch_before = window_epoch(&paths);
        let traces_before = session_trace_count(&existing.session_id);
        let outcome = create_session_record_if_absent(&paths, &refused, 1000).unwrap();

        assert_eq!(outcome, CreateSessionRecordOutcome::AlreadyExists);
        let loaded =
            load_one::<SessionRecord>(&paths, RecordKind::Session, &existing.session_id).unwrap();
        assert!(matches!(loaded, Some(LoadOutcome::Loaded(ref row)) if row == &existing));
        assert_eq!(window_epoch(&paths), epoch_before);
        assert_eq!(session_trace_count(&existing.session_id), traces_before);
    }

    #[test]
    fn grid_proven_attach_finalizes_row_and_retires_only_the_adopted_lifetime() {
        let (_tmp, paths, _workspace, mut expected) = child_identity_graph();
        expected.last_known_generation = Some("generation-adopted".into());
        write_record(
            &paths,
            RecordKind::Session,
            &expected.session_id,
            49,
            &expected,
        )
        .unwrap();
        let adopted = crate::session_release::SessionReleaseTarget::new_recovered(
            expected.session_id.clone(),
            "generation-adopted",
            crate::session_release::SessionRowPolicy::MatchingRowIsProof,
        )
        .unwrap();
        let unrelated = crate::session_release::SessionReleaseTarget::new_recovered(
            "unrelated-session",
            "generation-unrelated",
            crate::session_release::SessionRowPolicy::RowMustBeAbsent,
        )
        .unwrap();
        let unrelated_two = crate::session_release::SessionReleaseTarget::new_recovered(
            "unrelated-session-two",
            "generation-unrelated-two",
            crate::session_release::SessionRowPolicy::RowMustBeAbsent,
        )
        .unwrap();
        let service = crate::session_release::SessionReleaseService::new(&paths);
        let stale_receipt_one = service
            .enqueue_recovered(&[adopted.clone(), unrelated], 50)
            .unwrap()
            .expect("one leased operation");
        let receipt_two = {
            let connection = crate::db::conn_for(paths.base()).unwrap();
            let mut guard = connection.lock().unwrap();
            let tx = guard
                .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
                .unwrap();
            let receipt =
                crate::session_release::insert_pending_releases(&tx, &[adopted, unrelated_two], 51)
                    .unwrap()
                    .expect("second destructive-style leased operation");
            tx.commit().unwrap();
            receipt
        };
        let compensation_two = match service.attempt_owned(
            receipt_two,
            |_| Ok::<(), &'static str>(()),
            |_| crate::session_release::CasPublication::NotPublished("offline"),
        ) {
            crate::session_release::ReleaseOperationOutcome::UnpublishedFailure {
                compensation,
                ..
            } => compensation,
            other => panic!("expected zero-publication result, got {other:?}"),
        };
        service
            .release_unpublished_for_retry(compensation_two)
            .unwrap();
        let stale_claim_two = service
            .claim_next()
            .unwrap()
            .expect("second operation becomes a forward claim");

        let mut replacement = expected.clone();
        replacement.status = SessionStatus::Live;
        replacement.last_attached_at_ms = 51;
        let outcome = finalize_session_attach_if_unchanged(
            &paths,
            &expected,
            &replacement,
            "generation-adopted",
            51,
        )
        .unwrap();
        assert_eq!(
            outcome,
            ConditionalSessionAttachFinalize::Finalized {
                consumed_release_targets: 2
            }
        );
        assert!(matches!(
            load_one::<SessionRecord>(&paths, RecordKind::Session, &expected.session_id).unwrap(),
            Some(LoadOutcome::Loaded(ref row)) if row == &replacement
        ));

        {
            let connection = crate::db::conn_for(paths.base()).unwrap();
            let guard = connection.lock().unwrap();
            let adopted_pending: i64 = guard
                .query_row(
                    "SELECT COUNT(*) FROM pending_session_releases \
                     WHERE session_id = ?1 AND expected_generation = ?2",
                    rusqlite::params![expected.session_id, "generation-adopted"],
                    |row| row.get(0),
                )
                .unwrap();
            let unrelated_pending: i64 = guard
                .query_row(
                    "SELECT COUNT(*) FROM pending_session_releases \
                     WHERE session_id LIKE 'unrelated-session%'",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            let invalidated_leases: i64 = guard
                .query_row(
                    "SELECT COUNT(*) FROM session_release_operations \
                     WHERE lease_token IS NULL AND lease_until_ms IS NULL",
                    [],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(adopted_pending, 0);
            assert_eq!(unrelated_pending, 2);
            assert_eq!(
                invalidated_leases, 2,
                "every affected operation loses its lease"
            );
        }

        let cas_calls = std::cell::Cell::new(0usize);
        let stale_owned = service.attempt_owned(
            stale_receipt_one,
            |_| Ok::<(), ()>(()),
            |_| {
                cas_calls.set(cas_calls.get() + 1);
                crate::session_release::CasPublication::Confirmed
            },
        );
        assert!(matches!(
            stale_owned,
            crate::session_release::ReleaseOperationOutcome::ForwardOnly {
                confirmed: 0,
                retained: 0,
                possibly_published: 0,
                ..
            }
        ));
        let stale_claimed = service.attempt_claimed(
            stale_claim_two,
            |_| Ok::<(), ()>(()),
            |_| {
                cas_calls.set(cas_calls.get() + 1);
                crate::session_release::CasPublication::Confirmed
            },
        );
        assert!(matches!(
            stale_claimed,
            crate::session_release::ReleaseOperationOutcome::ForwardOnly {
                confirmed: 0,
                retained: 0,
                possibly_published: 0,
                ..
            }
        ));
        assert_eq!(
            cas_calls.get(),
            0,
            "stale owned and forward claims never cross the CAS fence"
        );

        let mut freshly_claimed = std::collections::BTreeSet::new();
        for _ in 0..2 {
            let claim = service.claim_next().unwrap().expect("rotated sibling work");
            let outcome = service.attempt_claimed(
                claim,
                |_| Ok::<(), ()>(()),
                |target| {
                    freshly_claimed.insert(target.session_id().to_string());
                    crate::session_release::CasPublication::Confirmed
                },
            );
            assert!(matches!(
                outcome,
                crate::session_release::ReleaseOperationOutcome::Complete {
                    confirmed: 1,
                    retained: 0
                }
            ));
        }
        assert_eq!(
            freshly_claimed,
            std::collections::BTreeSet::from([
                "unrelated-session".to_string(),
                "unrelated-session-two".to_string(),
            ])
        );
        assert!(service.claim_next().unwrap().is_none());
    }

    #[test]
    fn concurrent_session_change_or_delete_wins_over_attach_finalization() {
        for delete in [false, true] {
            let (_tmp, paths, _workspace, expected) = child_identity_graph();
            let target = crate::session_release::SessionReleaseTarget::new_recovered(
                expected.session_id.clone(),
                "generation-stale",
                crate::session_release::SessionRowPolicy::MatchingRowIsProof,
            )
            .unwrap();
            crate::session_release::SessionReleaseService::new(&paths)
                .enqueue_recovered(&[target], 60)
                .unwrap()
                .expect("one leased operation");

            if delete {
                assert!(delete_record(&paths, RecordKind::Session, &expected.session_id).unwrap());
            } else {
                let mut concurrent = expected.clone();
                concurrent.status = SessionStatus::Exited;
                concurrent.last_attached_at_ms = 61;
                write_record(
                    &paths,
                    RecordKind::Session,
                    &concurrent.session_id,
                    61,
                    &concurrent,
                )
                .unwrap();
            }

            let mut stale_replacement = expected.clone();
            stale_replacement.status = SessionStatus::Live;
            stale_replacement.last_known_generation = Some("generation-stale".into());
            stale_replacement.last_attached_at_ms = 62;
            let outcome = finalize_session_attach_if_unchanged(
                &paths,
                &expected,
                &stale_replacement,
                "generation-stale",
                62,
            )
            .unwrap();
            assert_eq!(
                outcome,
                if delete {
                    ConditionalSessionAttachFinalize::Missing
                } else {
                    ConditionalSessionAttachFinalize::Changed
                }
            );
            let connection = crate::db::conn_for(paths.base()).unwrap();
            let pending: i64 = connection
                .lock()
                .unwrap()
                .query_row("SELECT COUNT(*) FROM pending_session_releases", [], |row| {
                    row.get(0)
                })
                .unwrap();
            assert_eq!(
                pending, 1,
                "stale finalization cannot erase release authority"
            );
        }
    }

    #[test]
    fn concurrent_session_insert_wins_without_being_overwritten() {
        use std::sync::{mpsc, Arc, Mutex};
        use std::time::Duration;

        let (_tmp, paths, workspace, seed) = child_identity_graph();
        let mut requested = seed.clone();
        requested.session_id = "insert-only-race-session".into();
        requested.workspace_id = workspace.workspace_id;
        requested.cwd_resolved = "/home/u/requested".into();
        requested.created_at_ms = 201;
        requested.last_attached_at_ms = 201;
        let mut concurrent = requested.clone();
        concurrent.cwd_resolved = "/home/u/concurrent-winner".into();
        concurrent.created_at_ms = 202;
        concurrent.last_attached_at_ms = 202;

        let epoch_before = window_epoch(&paths);
        let traces_before = session_trace_count(&requested.session_id);
        let (paused_tx, paused_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let _hook =
            crate::store_sqlite::install_window_layout_test_hook(requested.session_id.clone(), {
                let release_rx = Arc::clone(&release_rx);
                move |stage, _| {
                    if stage == "before-create-session-transaction" {
                        paused_tx.send(()).unwrap();
                        release_rx
                            .lock()
                            .unwrap()
                            .recv_timeout(Duration::from_secs(5))
                            .expect("test releases insert-only Session writer");
                    }
                }
            });

        let writer_paths = paths.clone();
        let writer_requested = requested.clone();
        let writer = std::thread::spawn(move || {
            create_session_record_if_absent(&writer_paths, &writer_requested, 203)
        });
        paused_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("insert-only Session writer pauses before BEGIN IMMEDIATE");

        let competitor = open_test_writer(&paths);
        crate::store_sqlite::upsert(
            &competitor,
            RecordKind::Session,
            &concurrent.session_id,
            &serde_json::to_value(&concurrent).unwrap(),
        )
        .unwrap();
        release_tx.send(()).unwrap();
        let outcome = writer.join().unwrap().unwrap();

        assert_eq!(outcome, CreateSessionRecordOutcome::AlreadyExists);
        let loaded =
            load_one::<SessionRecord>(&paths, RecordKind::Session, &concurrent.session_id).unwrap();
        assert!(matches!(loaded, Some(LoadOutcome::Loaded(ref row)) if row == &concurrent));
        assert_eq!(window_epoch(&paths), epoch_before);
        assert_eq!(session_trace_count(&concurrent.session_id), traces_before);
    }

    #[test]
    fn window_layout_second_insert_failure_rolls_back_without_trace() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let window_id = "atomic-second-insert-rollback-window";
        let prior = window_layout(
            window_id,
            &[("prior-a", "session-a"), ("prior-b", "session-b")],
        );
        write_record(&paths, RecordKind::WindowLayout, window_id, 100, &prior).unwrap();

        let traces_before = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "WindowLayout" && event.id == window_id)
            .collect::<Vec<_>>();
        assert_eq!(traces_before.len(), 1);

        let mut duplicate = window_layout(
            window_id,
            &[
                ("duplicate-tab", "session-c"),
                ("duplicate-tab", "session-d"),
            ],
        );
        duplicate.name = Some("failed-replacement".into());
        let failed = write_record(&paths, RecordKind::WindowLayout, window_id, 200, &duplicate);
        assert!(matches!(failed, Err(StoreError::Map(_))));

        let loaded: Option<LoadOutcome<WindowLayout>> =
            load_one(&paths, RecordKind::WindowLayout, window_id).unwrap();
        assert!(matches!(loaded, Some(LoadOutcome::Loaded(ref layout)) if layout == &prior));
        let traces_after = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "WindowLayout" && event.id == window_id)
            .collect::<Vec<_>>();
        assert_eq!(
            traces_after, traces_before,
            "failed write must not emit a trace"
        );
    }

    #[test]
    fn separate_reader_sees_complete_window_layout_before_and_after_commit() {
        use std::sync::{mpsc, Arc, Mutex};
        use std::time::Duration;

        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let window_id = "atomic-reader-snapshot-window";
        let mut prior = window_layout(
            window_id,
            &[("prior-a", "session-a"), ("prior-b", "session-b")],
        );
        prior.name = Some("prior-layout".into());
        let mut replacement = window_layout(
            window_id,
            &[("next-c", "session-c"), ("next-d", "session-d")],
        );
        replacement.name = Some("replacement-layout".into());
        write_record(&paths, RecordKind::WindowLayout, window_id, 100, &prior).unwrap();

        let reader = rusqlite::Connection::open_with_flags(
            crate::db::db_path(paths.base()),
            rusqlite::OpenFlags::SQLITE_OPEN_READ_ONLY | rusqlite::OpenFlags::SQLITE_OPEN_NO_MUTEX,
        )
        .unwrap();
        let (paused_tx, paused_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let release_rx = Arc::new(Mutex::new(release_rx));
        let _hook = crate::store_sqlite::install_window_layout_test_hook(window_id, {
            let release_rx = Arc::clone(&release_rx);
            move |stage, _| {
                if stage == "after-delete-before-inserts" {
                    paused_tx.send(()).unwrap();
                    release_rx
                        .lock()
                        .unwrap()
                        .recv_timeout(Duration::from_secs(5))
                        .expect("test releases paused window-layout writer");
                }
            }
        });

        let writer_paths = paths.clone();
        let writer_layout = replacement.clone();
        let writer = std::thread::spawn(move || {
            write_record(
                &writer_paths,
                RecordKind::WindowLayout,
                window_id,
                200,
                &writer_layout,
            )
        });
        paused_rx
            .recv_timeout(Duration::from_secs(5))
            .expect("writer pauses after DELETE and before INSERTs");
        let during_write = loaded_window_from_conn(&reader, window_id);
        release_tx.send(()).unwrap();
        let write_result = writer.join().unwrap();
        let after_commit = loaded_window_from_conn(&reader, window_id);

        assert_eq!(during_write, prior);
        write_result.unwrap();
        assert_eq!(after_commit, replacement);
    }

    #[test]
    fn window_layout_load_one_uses_one_multi_table_snapshot() {
        use std::sync::{Arc, Mutex};

        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let window_id = "coherent-load-one-window";
        let mut prior = window_layout(window_id, &[("prior-a", "session-a")]);
        prior.name = Some("prior-name".into());
        let mut replacement = window_layout(window_id, &[("next-b", "session-b")]);
        replacement.name = Some("replacement-name".into());
        write_record(&paths, RecordKind::WindowLayout, window_id, 100, &prior).unwrap();

        let writer = Arc::new(Mutex::new(open_test_writer(&paths)));
        let _hook = crate::store_sqlite::install_window_layout_test_hook(window_id, {
            let writer = Arc::clone(&writer);
            let replacement = replacement.clone();
            move |stage, _| {
                if stage == "after-window-before-tabs" {
                    replace_windows_atomically(
                        &mut writer.lock().unwrap(),
                        std::slice::from_ref(&replacement),
                    );
                }
            }
        });

        let reader = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        let observed = loaded_window_from_conn(&reader, window_id);
        assert!(
            observed == prior || observed == replacement,
            "one logical layout load must not mix the old window row with new tab rows: {observed:?}"
        );
        assert_eq!(loaded_window_from_conn(&reader, window_id), replacement);
    }

    #[test]
    fn window_layout_load_all_uses_one_snapshot_for_the_whole_scan() {
        use std::sync::{Arc, Mutex};

        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let mut prior_a = window_layout("coherent-all-a", &[("prior-a", "session-a")]);
        prior_a.name = Some("prior-a".into());
        let mut prior_b = window_layout("coherent-all-b", &[("prior-b", "session-b")]);
        prior_b.name = Some("prior-b".into());
        let mut next_a = window_layout("coherent-all-a", &[("next-a", "session-next-a")]);
        next_a.name = Some("next-a".into());
        let mut next_b = window_layout("coherent-all-b", &[("next-b", "session-next-b")]);
        next_b.name = Some("next-b".into());
        write_record(
            &paths,
            RecordKind::WindowLayout,
            &prior_a.window_id,
            100,
            &prior_a,
        )
        .unwrap();
        write_record(
            &paths,
            RecordKind::WindowLayout,
            &prior_b.window_id,
            100,
            &prior_b,
        )
        .unwrap();

        let writer = Arc::new(Mutex::new(open_test_writer(&paths)));
        let _hook = crate::store_sqlite::install_window_layout_test_hook("coherent-all-a", {
            let writer = Arc::clone(&writer);
            let next_a = next_a.clone();
            let next_b = next_b.clone();
            move |stage, _| {
                if stage == "after-load-window" {
                    replace_windows_atomically(
                        &mut writer.lock().unwrap(),
                        &[next_a.clone(), next_b.clone()],
                    );
                }
            }
        });

        let reader = rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
        let observed = crate::store_sqlite::load_all(&reader, RecordKind::WindowLayout)
            .unwrap()
            .into_iter()
            .map(|value| serde_json::from_value::<WindowLayout>(value).unwrap())
            .collect::<Vec<_>>();
        assert!(
            observed == vec![prior_a.clone(), prior_b.clone()]
                || observed == vec![next_a.clone(), next_b.clone()],
            "one load_all scan must return one committed cohort: {observed:?}"
        );
        let after = crate::store_sqlite::load_all(&reader, RecordKind::WindowLayout)
            .unwrap()
            .into_iter()
            .map(|value| serde_json::from_value::<WindowLayout>(value).unwrap())
            .collect::<Vec<_>>();
        assert_eq!(after, vec![next_a, next_b]);
    }

    #[test]
    fn window_layout_snapshot_reads_reuse_an_outer_transaction() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let layout = window_layout("outer-snapshot-window", &[("tab-a", "session-a")]);
        write_record(
            &paths,
            RecordKind::WindowLayout,
            &layout.window_id,
            100,
            &layout,
        )
        .unwrap();

        let mut conn = open_test_writer(&paths);
        let tx = conn.transaction().unwrap();
        let one = crate::store_sqlite::load_one(&tx, RecordKind::WindowLayout, &layout.window_id)
            .unwrap()
            .unwrap();
        assert_eq!(serde_json::from_value::<WindowLayout>(one).unwrap(), layout);
        let all = crate::store_sqlite::load_all(&tx, RecordKind::WindowLayout).unwrap();
        assert_eq!(all.len(), 1);
        tx.commit().unwrap();
    }

    #[test]
    fn write_then_load_round_trips() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        write_record(
            &paths,
            RecordKind::Project,
            "p1",
            10,
            &project("p1", "Alpha"),
        )
        .unwrap();

        let one: Option<LoadOutcome<Project>> =
            load_one(&paths, RecordKind::Project, "p1").unwrap();
        match one {
            Some(LoadOutcome::Loaded(p)) => assert_eq!(p, project("p1", "Alpha")),
            other => panic!("expected Loaded, got {other:?}"),
        }
    }

    #[test]
    fn project_without_icon_or_accent_deserializes_to_none() {
        // A project record written before the icon/accent_color fields existed must still load:
        // both fields default to None rather than failing deserialization.
        let legacy = r#"{
            "project_id": "p1",
            "name": "Alpha",
            "root": "/home/u/repo",
            "default_workspace_policy": "scratch_cwd",
            "created_at_ms": 1,
            "last_active_at_ms": 1
        }"#;
        let p: Project = serde_json::from_str(legacy).expect("legacy project loads");
        assert_eq!(p.icon, None);
        assert_eq!(p.accent_color, None);
    }

    #[test]
    fn project_icon_and_accent_round_trip() {
        let mut p = project("p1", "Alpha");
        p.icon = Some("🚀".to_string());
        p.accent_color = Some("#4f8cff".to_string());
        let json = serde_json::to_string(&p).unwrap();
        let back: Project = serde_json::from_str(&json).unwrap();
        assert_eq!(back, p);
    }

    #[test]
    fn tab_record_without_stashed_deserializes_to_false() {
        // A tab record written before the `stashed` field existed must still load: the flag
        // defaults to false (a live, non-stashed tab) rather than failing deserialization.
        let legacy = r#"{
            "tab_id": "t1",
            "session_id": "s1",
            "index": 0,
            "title": "First",
            "pinned": false,
            "attention": {
                "attention": "none",
                "unseen": false,
                "since_ms": 0,
                "source": "process"
            }
        }"#;
        let t: TabRecord = serde_json::from_str(legacy).expect("legacy tab record loads");
        assert!(!t.stashed);
        assert_eq!(t.split_from, None);
    }

    #[cfg(unix)]
    #[test]
    fn db_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        write_record(&paths, RecordKind::Project, "p1", 0, &project("p1", "x")).unwrap();
        // The single DB file carries the secrets-bearing records; it must be owner-only (0600).
        let mode = fs::metadata(crate::db::db_path(paths.base()))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600, "the maestro.db file must be 0600");
    }

    #[test]
    fn second_write_replaces_the_row_in_place() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        write_record(
            &paths,
            RecordKind::Project,
            "p1",
            1,
            &project("p1", "First"),
        )
        .unwrap();
        write_record(
            &paths,
            RecordKind::Project,
            "p1",
            2,
            &project("p1", "Second"),
        )
        .unwrap();

        // The second write replaced the first (same PK), not appended a sibling.
        let one: Option<LoadOutcome<Project>> =
            load_one(&paths, RecordKind::Project, "p1").unwrap();
        match one {
            Some(LoadOutcome::Loaded(p)) => assert_eq!(p.name, "Second"),
            other => panic!("expected Loaded Second, got {other:?}"),
        }
        // Exactly one row remains.
        let all: Vec<LoadOutcome<Project>> = load_all(&paths, RecordKind::Project).unwrap();
        assert_eq!(all.len(), 1);
    }

    #[test]
    fn generic_project_compatibility_writes_bump_only_for_window_order_changes() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let mut record = project("compat-project-epoch", "Before");
        write_record(&paths, RecordKind::Project, &record.project_id, 1, &record).unwrap();
        let initial_epoch = window_epoch(&paths);

        record.name = "Metadata only".into();
        write_record(&paths, RecordKind::Project, &record.project_id, 2, &record).unwrap();
        assert_eq!(window_epoch(&paths), initial_epoch);

        record.window_order.push("legacy-null-owner".into());
        write_record(&paths, RecordKind::Project, &record.project_id, 3, &record).unwrap();
        assert_eq!(window_epoch(&paths), initial_epoch + 1);

        assert!(delete_record(&paths, RecordKind::Project, &record.project_id).unwrap());
        assert_eq!(window_epoch(&paths), initial_epoch + 2);
    }

    #[test]
    fn generic_project_order_epoch_exhaustion_rolls_back_the_full_row_without_trace() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let mut record = project("compat-project-max", "Before");
        write_record(&paths, RecordKind::Project, &record.project_id, 1, &record).unwrap();
        {
            let connection = crate::db::conn_for(paths.base()).unwrap();
            connection
                .lock()
                .unwrap()
                .pragma_update(None, "user_version", i32::MAX)
                .unwrap();
        }
        let traces_before = crate::write_trace::recent()
            .into_iter()
            .filter(|event| event.kind == "Project" && event.id == record.project_id)
            .count();
        let before = record.clone();
        record.name = "Must roll back".into();
        record.window_order.push("new-owner".into());

        let error =
            write_record(&paths, RecordKind::Project, &record.project_id, 2, &record).unwrap_err();
        assert!(matches!(
            error,
            StoreError::Db(ref detail)
                if detail.contains("epoch") && detail.contains("exhausted")
        ));
        let loaded = load_one::<Project>(&paths, RecordKind::Project, &record.project_id)
            .unwrap()
            .unwrap();
        assert!(matches!(loaded, LoadOutcome::Loaded(project) if project == before));
        assert_eq!(window_epoch(&paths), i32::MAX as u32);
        assert_eq!(
            crate::write_trace::recent()
                .into_iter()
                .filter(|event| event.kind == "Project" && event.id == record.project_id)
                .count(),
            traces_before
        );
    }

    #[test]
    fn generic_child_identity_deletes_bump_once_and_missing_deletes_are_quiet() {
        let (_tmp, paths, _workspace, session) = child_identity_graph();
        let epoch_before_session_delete = window_epoch(&paths);
        assert!(delete_record(&paths, RecordKind::Session, &session.session_id).unwrap());
        assert_eq!(window_epoch(&paths), epoch_before_session_delete + 1);
        assert!(!delete_record(&paths, RecordKind::Session, &session.session_id).unwrap());
        assert_eq!(window_epoch(&paths), epoch_before_session_delete + 1);

        let (_tmp, paths, workspace, session) = child_identity_graph();
        let epoch_before_workspace_delete = window_epoch(&paths);
        assert!(delete_record(&paths, RecordKind::Workspace, &workspace.workspace_id,).unwrap());
        assert_eq!(
            window_epoch(&paths),
            epoch_before_workspace_delete + 1,
            "one workspace deletion must fence its cascaded session exactly once"
        );
        assert!(
            load_one::<SessionRecord>(&paths, RecordKind::Session, &session.session_id)
                .unwrap()
                .is_none()
        );
        assert!(!delete_record(&paths, RecordKind::Workspace, &workspace.workspace_id,).unwrap());
        assert_eq!(window_epoch(&paths), epoch_before_workspace_delete + 1);
    }

    #[test]
    fn child_identity_delete_epoch_exhaustion_rolls_back_rows_and_trace() {
        for kind in [RecordKind::Session, RecordKind::Workspace] {
            let suffix = match kind {
                RecordKind::Session => "epoch-exhaustion-session",
                RecordKind::Workspace => "epoch-exhaustion-workspace",
                _ => unreachable!(),
            };
            let (_tmp, paths, workspace, session) = child_identity_graph_with_suffix(suffix);
            let (id, trace_kind) = match kind {
                RecordKind::Session => (session.session_id.as_str(), "Session"),
                RecordKind::Workspace => (workspace.workspace_id.as_str(), "Workspace"),
                _ => unreachable!(),
            };
            let traces_before = crate::write_trace::recent()
                .into_iter()
                .filter(|event| event.kind == trace_kind && event.id == id)
                .count();
            {
                let connection = crate::db::conn_for(paths.base()).unwrap();
                connection
                    .lock()
                    .unwrap()
                    .pragma_update(None, "user_version", i32::MAX)
                    .unwrap();
            }

            let error = delete_record(&paths, kind, id).unwrap_err();
            assert!(matches!(
                error,
                StoreError::Db(ref detail)
                    if detail.contains("epoch") && detail.contains("exhausted")
            ));
            assert_eq!(window_epoch(&paths), i32::MAX as u32);
            assert!(load_one::<serde_json::Value>(&paths, kind, id)
                .unwrap()
                .is_some());
            if kind == RecordKind::Workspace {
                assert!(load_one::<SessionRecord>(
                    &paths,
                    RecordKind::Session,
                    &session.session_id,
                )
                .unwrap()
                .is_some());
            }
            assert_eq!(
                crate::write_trace::recent()
                    .into_iter()
                    .filter(|event| event.kind == trace_kind && event.id == id)
                    .count(),
                traces_before
            );
        }
    }

    #[test]
    fn row_that_wont_deserialize_is_quarantined_and_excluded() {
        // A row whose stored shape can't be deserialized into the requested type is surfaced as Quarantined (skipped
        // from the loaded set) — the SQLite analog of the old corrupt-file quarantine. We write a Project row, then
        // load the projects table AS AgentTasks (incompatible shape → each row fails from_value).
        use crate::records::AgentTask;
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        write_record(
            &paths,
            RecordKind::Project,
            "good",
            0,
            &project("good", "Good"),
        )
        .unwrap();

        // Sanity: as Project it loads fine.
        let good: Vec<LoadOutcome<Project>> = load_all(&paths, RecordKind::Project).unwrap();
        assert_eq!(
            good.iter()
                .filter(|o| matches!(o, LoadOutcome::Loaded(_)))
                .count(),
            1
        );

        // As AgentTask the same row's shape doesn't fit → Quarantined, not Loaded.
        let mismatched: Vec<LoadOutcome<AgentTask>> =
            load_all(&paths, RecordKind::Project).unwrap();
        assert_eq!(mismatched.len(), 1);
        assert!(
            matches!(mismatched[0], LoadOutcome::Quarantined { .. }),
            "a row that won't deserialize must be Quarantined, got {:?}",
            mismatched[0]
        );
    }

    #[test]
    fn future_version_db_is_refused_on_open() {
        // The per-record FutureVersion became a DB-level guard: a DB stamped with a schema version NEWER than this
        // build refuses to open (never silently mutated). Set schema_meta.version above ours, drop the cached
        // connection, and assert the next store call errors.
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        write_record(&paths, RecordKind::Project, "p1", 0, &project("p1", "x")).unwrap();
        {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let conn = arc.lock().unwrap();
            conn.execute(
                "UPDATE schema_meta SET version = ?1 WHERE id = 1",
                [crate::db::DB_SCHEMA_VERSION + 1],
            )
            .unwrap();
        }
        crate::db::forget_cached(paths.base());
        let reopened: Result<Vec<LoadOutcome<Project>>, _> = load_all(&paths, RecordKind::Project);
        assert!(
            matches!(reopened, Err(StoreError::Db(_))),
            "a future-version DB must be refused, got {reopened:?}"
        );
    }

    #[test]
    fn write_record_rejects_traversing_id() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        for bad in ["../escape", "a/b", "..", "/abs", "a/../b"] {
            let r = write_record(&paths, RecordKind::Project, bad, 0, &project("x", "X"));
            assert!(
                matches!(r, Err(StoreError::Id(_))),
                "write with id {bad:?} must be refused, got {r:?}"
            );
        }
        // Nothing escaped: the only thing that could exist is the (empty or absent) records dir;
        // assert no file was created above the base.
        let escaped = tmp.path().join("escape");
        assert!(!escaped.exists(), "no file may be written outside the base");
    }

    #[test]
    fn load_one_rejects_traversing_id() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        for bad in ["../etc/passwd", "a/b", "..", "/abs"] {
            let r: Result<Option<LoadOutcome<Project>>, _> =
                load_one(&paths, RecordKind::Project, bad);
            assert!(
                matches!(r, Err(StoreError::Id(_))),
                "load_one with id {bad:?} must be refused, got {r:?}"
            );
        }
    }

    #[test]
    fn missing_dir_loads_empty() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let outcomes: Vec<LoadOutcome<Project>> = load_all(&paths, RecordKind::AgentTask).unwrap();
        assert!(outcomes.is_empty());
    }
}
