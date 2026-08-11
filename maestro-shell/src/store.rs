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

    // Serialize to a JSON Value, then map the typed columns + JSON sub-columns per kind (store_sqlite). A single
    // INSERT OR REPLACE (or, for a window layout, a whole-layout transaction) is atomic + durable via WAL.
    let value = serde_json::to_value(record).map_err(StoreError::from_json)?;
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let conn = arc.lock().unwrap();
    let result = crate::store_sqlite::upsert(&conn, kind, id, &value).map_err(StoreError::from_map);
    // DB-write log net: record the mutation (content-blind — kind + id + top-level field NAMES) so both writers
    // (desktop app + agent) leave an attributable, ordered forensic trail. Only on a successful write.
    if result.is_ok() {
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
    }
    result
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

/// Stamp a window's owning project id (the FK column the cascade uses). WindowLayout has no project_id in its record
/// model; the app calls this from its ownership signal (window_order) so `windows.project_id → projects` is set.
pub fn set_window_project(
    paths: &AppPaths,
    window_id: &str,
    project_id: &str,
) -> Result<(), StoreError> {
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let conn = arc.lock().unwrap();
    let result = crate::store_sqlite::set_window_project(&conn, window_id, project_id)
        .map_err(StoreError::from_map);
    // DB-write log net: the ownership stamp bypasses write_record (it is a raw column update), so trace it
    // here — otherwise "who linked this window to this project" is invisible in the forensic trail. Content-
    // blind: kind + window id + the one field NAME; wall clock (no caller timestamp on this path).
    if result.is_ok() {
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

/// Delete a record by id. FK `ON DELETE CASCADE` removes its children (deleting a project cascades to its workspaces,
/// sessions, windows, tabs, agent_tasks, and project-scoped presets; deleting a window cascades to its tabs). Returns
/// whether a row was removed (idempotent — a missing id is `Ok(false)`). Replaces the old `fs::remove_file`.
pub fn delete_record(paths: &AppPaths, kind: RecordKind, id: &str) -> Result<bool, StoreError> {
    let _ = paths.record_path(kind, id)?; // id hygiene, preserved
    let arc = crate::db::conn_for(paths.base()).map_err(StoreError::from_db)?;
    let conn = arc.lock().unwrap();
    let result = crate::store_sqlite::delete(&conn, kind, id).map_err(StoreError::from_map);
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
    use crate::records::{Project, TabRecord};
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
