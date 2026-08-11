//! Fail-closed migration of the legacy per-record JSON store into SQLite.
//!
//! The legacy JSON remains authoritative until every record parses, the complete import commits,
//! every imported row can be read back, and a durable completion marker is published. Merely
//! finding `maestro.db` is never evidence that import completed: opening SQLite can create that
//! file before the import transaction begins. App and agent first-run attempts serialize through a
//! process-shared advisory lock. A crash before the marker simply retries the idempotent UPSERTs;
//! a crash after the marker retries archiving any still-active JSON files. Archives are moved, never
//! deleted.

use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use rusqlite::TransactionBehavior;
use serde_json::Value;

use crate::envelope::Envelope;
use crate::paths::{AppPaths, RecordKind};

const MIGRATION_LOCK: &str = ".legacy-json-import.lock";
// Version 1 markers were introduced after the best-effort importer had already shipped. That
// implementation could move records it skipped into `legacy-json*`, while the v1 marker path only
// looked for active JSON. Consequently a v1 marker is evidence that SQLite was checked, but is not
// evidence that recovery archives were reconciled. Preserve it, but never use it as authority.
const LEGACY_COMPLETION_MARKER: &str = ".legacy-json-import-v1.complete";
const LEGACY_COMPLETION_MARKER_BODY: &[u8] = b"hydra-legacy-json-import-v1\n";
const COMPLETION_MARKER: &str = ".legacy-json-import-v2.complete";
const COMPLETION_MARKER_BODY: &[u8] = b"hydra-legacy-json-import-v2\n";
const LEGACY_SIDECAR_COMPLETION_MARKER: &str = ".legacy-session-sidecars-v1.complete";
const LEGACY_SIDECAR_COMPLETION_MARKER_BODY: &[u8] = b"hydra-legacy-session-sidecars-v1\n";
const SIDECAR_COMPLETION_MARKER: &str = ".legacy-session-sidecars-v2.complete";
const SIDECAR_COMPLETION_MARKER_BODY: &[u8] = b"hydra-legacy-session-sidecars-v2\n";
const SIDECAR_PENDING_SNAPSHOT: &str = ".legacy-session-sidecars-v2.pending";
const SIDECAR_PENDING_HEADER: &[u8] = b"hydra-legacy-session-sidecars-v2-pending-v1\0";
// Session-name and hidden-session sidecars contain small dashboard metadata. A larger legacy file
// is not credible migration input and must fail closed before allocating its full body.
const LEGACY_SESSION_SIDECAR_MAX_BYTES: u64 = 4 * 1024 * 1024;
// The previous importer could leave one archived file per generation for each sidecar kind. Bound
// both dimensions before parsing: no kind may contribute more than 64 generations, and the two
// kinds share one 16 MiB raw-byte budget for the entire reconciliation attempt.
const LEGACY_SESSION_SIDECAR_ARCHIVE_MAX_GENERATIONS_PER_KIND: usize = 64;
const LEGACY_SESSION_SIDECAR_ARCHIVE_MAX_TOTAL_BYTES: u64 = 16 * 1024 * 1024;
const LEGACY_SESSION_SIDECAR_PENDING_MAX_BYTES: u64 =
    SIDECAR_PENDING_HEADER.len() as u64 + 2 * (1 + 8 + LEGACY_SESSION_SIDECAR_MAX_BYTES);
const INDEPENDENT_RECONCILIATION_NOTICE: &str = ".legacy-independent-data-reconciliation-required";
const INDEPENDENT_RECONCILIATION_NOTICE_BODY: &[u8] = b"hydra-independent-legacy-data-reconciliation-required-v1\nArchived independently owned daemon JSON remains under legacy-json*/daemon. It was not restored or certified by the record migration. Remote access remains fail-closed until explicitly reconfigured by its owner.\n";
const LEGACY_BACKUP_PREFIX: &str = "legacy-json";

#[cfg(not(test))]
fn migration_failpoint(_stage: &str) -> Result<(), String> {
    Ok(())
}

#[cfg(test)]
thread_local! {
    static ACTIVE_MIGRATION_FAILPOINT: std::cell::RefCell<Option<&'static str>> =
        const { std::cell::RefCell::new(None) };
}

#[cfg(test)]
fn migration_failpoint(stage: &str) -> Result<(), String> {
    ACTIVE_MIGRATION_FAILPOINT.with(|active| {
        if active.borrow().as_ref().copied() == Some(stage) {
            Err(format!("injected migration failure at {stage}"))
        } else {
            Ok(())
        }
    })
}

#[cfg(not(test))]
fn run_migration_test_hook(_stage: &str, _base: &Path) {}

#[cfg(test)]
type MigrationTestHook = std::sync::Arc<dyn Fn(&str, &Path) + Send + Sync>;

#[cfg(test)]
static MIGRATION_TEST_HOOK: std::sync::OnceLock<std::sync::Mutex<Option<MigrationTestHook>>> =
    std::sync::OnceLock::new();
#[cfg(test)]
static MIGRATION_TEST_HOOK_SERIAL: std::sync::OnceLock<std::sync::Mutex<()>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn run_migration_test_hook(stage: &str, base: &Path) {
    let hook = MIGRATION_TEST_HOOK
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap()
        .clone();
    if let Some(hook) = hook {
        hook(stage, base);
    }
}

/// The record dirs that hold migratable records, in FK-safe insert order (parents before children).
const MIGRATION_ORDER: &[RecordKind] = &[
    RecordKind::Project,
    RecordKind::Workspace,
    RecordKind::AgentTask,
    RecordKind::Session,
    RecordKind::WindowLayout,
    RecordKind::LayoutPreset,
    RecordKind::WorktreeProvenance,
    RecordKind::DaemonEndpoint,
];

/// Outcome of a migration run (for logging).
#[derive(Debug, Default)]
pub struct MigrationReport {
    pub migrated: usize,
    /// Kept for source compatibility with existing logging. A fail-closed import never skips a
    /// legacy record, so successful migrations always report zero.
    pub skipped: usize,
    pub already_done: bool,
}

#[derive(Debug)]
struct LegacyRecord {
    kind: RecordKind,
    id: String,
    path: PathBuf,
    bytes: Vec<u8>,
    /// Canonical serialization of the exact typed durable record, before migration-only fields
    /// such as a window's derived project owner are added.
    canonical: Value,
    /// Value handed to the relational mapper. Normally equal to `canonical`.
    value: Value,
}

#[derive(Debug)]
struct ArchivedSidecar<T> {
    path: PathBuf,
    bytes: Vec<u8>,
    value: T,
}

#[derive(Debug, Default)]
struct ArchivedSidecarBudget {
    raw_bytes: u64,
}

#[derive(Debug)]
struct ArchivedIndependentFile {
    path: PathBuf,
    bytes: Vec<u8>,
}

/// Process-shared serialization for every supported local-store writer. Hydra's desktop targets are
/// Unix (macOS and Linux), where `flock` releases automatically on process death.
struct MigrationLock {
    file: File,
}

impl MigrationLock {
    fn acquire(base: &Path) -> Result<Self, String> {
        match path_is_directory_no_follow(base) {
            Ok(true) => {}
            Ok(false) => {
                fs::create_dir_all(base)
                    .map_err(|e| format!("create migration base {}: {e}", base.display()))?;
                if !path_is_directory_no_follow(base)
                    .map_err(|e| format!("verify created migration base {}: {e}", base.display()))?
                {
                    return Err(format!(
                        "created migration base disappeared: {}",
                        base.display()
                    ));
                }
            }
            Err(error) => {
                return Err(format!(
                    "migration base must be a real directory {}: {error}",
                    base.display()
                ))
            }
        }
        let path = base.join(MIGRATION_LOCK);
        let file = open_owner_only(&path, false)
            .map_err(|e| format!("open migration lock {}: {e}", path.display()))?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::PermissionsExt;
            file.set_permissions(fs::Permissions::from_mode(0o600))
                .map_err(|e| format!("secure migration lock {}: {e}", path.display()))?;
            // SAFETY: `file` remains owned by this guard until Drop, and LOCK_EX blocks rather than
            // allowing the app and agent to race first-run import.
            loop {
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                    break;
                }
                let error = std::io::Error::last_os_error();
                if error.kind() != std::io::ErrorKind::Interrupted {
                    return Err(format!("lock legacy migration {}: {error}", path.display()));
                }
            }
        }
        #[cfg(not(unix))]
        {
            return Err("legacy migration locking is unsupported on this platform".to_string());
        }
        Ok(Self { file })
    }
}

impl Drop for MigrationLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            // SAFETY: the descriptor is still live and exclusively owned by this guard.
            let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
        }
    }
}

/// Import legacy JSON if necessary. A parse, read, map, commit, verification, or archive failure is
/// returned to the caller; callers must not continue into SQLite authority after such an error.
pub fn migrate_json_to_sqlite(paths: &AppPaths) -> Result<MigrationReport, String> {
    // Authority publication is part of the same critical section as source selection and
    // promotion. Otherwise a successful importer can release the filesystem lock, a second
    // importer can fail, and the first importer can then incorrectly publish READY over that
    // newer failure.
    run_migration_test_hook("before-migration-lock", paths.base());
    let _lock = MigrationLock::acquire(paths.base())?;
    migrate_json_to_sqlite_locked(paths)
}

/// Resolve record authority while the caller owns [`MigrationLock`]. Sidecar migration uses this
/// form so its fresh-vs-existing database decision and the record promotion are one indivisible
/// critical section rather than two lock acquisitions with a race between them.
fn migrate_json_to_sqlite_locked(paths: &AppPaths) -> Result<MigrationReport, String> {
    crate::db::mark_authority_blocked(paths.base());
    let report = migrate_json_to_sqlite_inner(paths)?;
    run_migration_test_hook("before-authority-ready", paths.base());
    crate::db::mark_authority_ready(paths.base());
    Ok(report)
}

fn migrate_json_to_sqlite_inner(paths: &AppPaths) -> Result<MigrationReport, String> {
    let base = paths.base();
    if validate_named_marker(
        base,
        INDEPENDENT_RECONCILIATION_NOTICE,
        INDEPENDENT_RECONCILIATION_NOTICE_BODY,
        "independent legacy-data reconciliation notice",
    )? {
        ensure_owner_only_notice(&base.join(INDEPENDENT_RECONCILIATION_NOTICE))?;
    }
    let marker_exists = validate_completion_marker(base)?;
    let legacy_marker_exists = validate_named_marker(
        base,
        LEGACY_COMPLETION_MARKER,
        LEGACY_COMPLETION_MARKER_BODY,
        "legacy v1 import",
    )?;
    let database_path = crate::db::db_path(base);
    let database_exists = path_is_regular_file_no_follow(&database_path).map_err(|error| {
        format!(
            "SQLite authority must be a regular file {}: {error}",
            database_path.display()
        )
    })?;

    // A marker asserts that the complete database was durably promoted. It is never permission to
    // recreate that database from whatever subset of JSON happened to remain after a partial
    // archive. Hoist this guard before inspecting active files so marker+missing-DB always fails.
    if (marker_exists || legacy_marker_exists) && !database_exists {
        return Err(format!(
            "legacy import marker exists but {} is missing; refusing partial recovery",
            crate::db::DB_FILENAME
        ));
    }

    let active = collect_active_record_paths(paths)?;
    if marker_exists {
        let arc = completed_database_connection(base)?;
        let conn = arc
            .lock()
            .map_err(|_| "completed migration database lock was poisoned".to_string())?;
        ensure_database_integrity(&conn, "completed legacy database")?;
        if active.is_empty() {
            return Ok(MigrationReport {
                already_done: true,
                ..Default::default()
            });
        }

        // Active JSON after completion can be the exact snapshot left by a crash before archive,
        // or a divergent write from an older binary. Those cases are intentionally distinguished:
        // exact snapshots may be retired; divergent content must never overwrite newer SQLite.
        let records = parse_legacy_records(active)?;
        set_full_durability(&conn)?;
        verify_records_equal_database(&conn, &records)?;
        checkpoint_fully(&conn)?;
        verify_source_snapshot(&records)?;
        verify_active_record_set_unchanged(paths, &records)?;
        archive_imported_active_record_files(paths, &records)?;
        restore_normal_durability(&conn)?;
        return Ok(MigrationReport {
            already_done: true,
            ..Default::default()
        });
    }

    // Before publishing the v2 marker, examine every record in every archive generation. The
    // previously shipped importer moved entire directories after committing, including corrupt,
    // future-version, and relationally rejected records. Selecting only the newest value per id
    // would therefore hide an older skipped record behind a later generation.
    let archive_roots_exist = !legacy_backup_roots(base)?.is_empty();
    let archived_records = parse_recovery_archive_records(paths)?;
    let archived_independent_files = inspect_archived_shared_daemon_authority(paths)?;

    if legacy_marker_exists {
        if active.is_empty() && archived_records.is_empty() && !archive_roots_exist {
            return Err(
                "legacy v1 import marker exists, but no active JSON or legacy-json* recovery archive remains to reconcile; refusing to promote an unproven completion marker"
                    .to_string(),
            );
        }
        let active_records = parse_legacy_records(active)?;
        let arc = completed_database_connection(base)?;
        let conn = arc
            .lock()
            .map_err(|_| "legacy v1 migration database lock was poisoned".to_string())?;
        ensure_database_integrity(&conn, "legacy v1 completed database")?;
        // The v1 path did prove active sources against SQLite; retain that non-overwrite behavior
        // while adding the archive reconciliation it lacked.
        verify_records_equal_database(&conn, &active_records)?;
        verify_archived_records_visible(&conn, &archived_records)?;
        set_full_durability(&conn)?;
        checkpoint_fully(&conn)?;
        verify_source_snapshot(&active_records)?;
        verify_source_snapshot(&archived_records)?;
        verify_archived_independent_files(&archived_independent_files)?;
        verify_active_record_set_unchanged(paths, &active_records)?;
        write_completion_marker(base)?;
        archive_imported_active_record_files(paths, &active_records)?;
        restore_normal_durability(&conn)?;
        return Ok(MigrationReport {
            already_done: true,
            ..Default::default()
        });
    }

    // Archives remain recovery sources when SQLite is missing. With an existing DB they are
    // reconciliation evidence, not overwrite authority: the DB may have evolved legitimately for
    // months after the archive was made. Active JSON is still authoritative until it is promoted.
    // With no DB, newer archives override older ones and active JSON overrides all.
    let source_paths = if database_exists {
        active
    } else {
        collect_recovery_and_active_record_paths(paths)?
    };

    if source_paths.is_empty() {
        if database_exists {
            let arc = completed_database_connection(base)?;
            let conn = arc
                .lock()
                .map_err(|_| "completed migration database lock was poisoned".to_string())?;
            ensure_database_integrity(&conn, "completed legacy database")?;
            if archived_records.is_empty() && !archive_roots_exist {
                if legacy_marker_exists {
                    return Err(
                        "legacy v1 import marker exists, but no active JSON or legacy-json* recovery archive remains to reconcile; refusing to promote an unproven completion marker"
                            .to_string(),
                    );
                }
                // A native SQLite store with no legacy evidence needs no import marker. Repeating
                // this read-only integrity preflight on the next process start is preferable to
                // certifying legacy completeness from database existence alone.
                return Ok(MigrationReport {
                    already_done: true,
                    ..Default::default()
                });
            }
            verify_archived_records_visible(&conn, &archived_records)?;
            set_full_durability(&conn)?;
            checkpoint_fully(&conn)?;
            verify_source_snapshot(&archived_records)?;
            verify_archived_independent_files(&archived_independent_files)?;
            write_completion_marker(base)?;
            restore_normal_durability(&conn)?;
            return Ok(MigrationReport {
                already_done: true,
                ..Default::default()
            });
        }
        return Ok(MigrationReport::default());
    }

    // Parse and type-check every selected record before opening SQLite. One unreadable,
    // future-version, corrupt, id-mismatched, or wrong-schema file blocks the complete import and
    // remains exactly where it was.
    let mut records = parse_legacy_records(source_paths)?;

    let projects = records
        .iter()
        .filter(|record| record.kind == RecordKind::Project)
        .map(|record| (record.id.clone(), record.value.clone()))
        .collect::<Vec<_>>();
    let window_owner = window_owner_map(Some(&projects))?;

    let arc = crate::db::conn_for_migration(base).map_err(|e| e.to_string())?;
    let mut conn = arc
        .lock()
        .map_err(|_| "legacy migration database lock was poisoned".to_string())?;
    if database_exists {
        preflight_active_record_non_overwrite(&conn, &records)?;
        preflight_archived_record_visibility(&conn, &archived_records, &records)?;
    }
    set_full_durability(&conn)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| format!("begin legacy import: {e}"))?;
    for record in &mut records {
        if record.kind == RecordKind::WindowLayout {
            if let Some(project_id) = window_owner.get(record.id.as_str()) {
                if let Value::Object(map) = &mut record.value {
                    map.insert("project_id".into(), Value::from(project_id.clone()));
                }
            }
        }
        crate::store_sqlite::upsert(&tx, record.kind, &record.id, &record.value).map_err(|e| {
            format!(
                "import legacy {:?} {} from {}: {e}",
                record.kind,
                record.id,
                record.path.display()
            )
        })?;
    }
    // Catch mapping/readback and FK failures while rollback is still possible. Re-check the exact
    // source snapshot before commit as well, so a cooperating/ordinary concurrent writer cannot
    // make us knowingly commit bytes different from the selected authority.
    verify_imported_records(&tx, &records)?;
    verify_source_snapshot(&records)?;
    verify_active_record_set_unchanged(paths, &records)?;
    migration_failpoint("before-sqlite-commit")?;
    tx.commit()
        .map_err(|e| format!("commit legacy import: {e}"))?;
    migration_failpoint("after-sqlite-commit")?;

    verify_imported_records(&conn, &records)?;
    verify_archived_records_visible(&conn, &archived_records)?;
    checkpoint_fully(&conn)?;
    migration_failpoint("after-sqlite-checkpoint")?;

    // The legacy snapshot must still be byte-for-byte the one just imported. If an older process
    // wrote during the import, fail before publishing the marker so the next launch retries it.
    verify_source_snapshot(&records)?;
    verify_source_snapshot(&archived_records)?;
    verify_archived_independent_files(&archived_independent_files)?;
    verify_active_record_set_unchanged(paths, &records)?;
    migration_failpoint("after-source-snapshot")?;
    write_completion_marker(base)?;
    migration_failpoint("after-completion-marker")?;

    // Only active JSON files are archived; recovery archives remain untouched. Moving individual
    // files avoids moving live daemon sockets/pid files that share `<base>/daemon`.
    archive_imported_active_record_files(paths, &records)?;
    restore_normal_durability(&conn)?;
    Ok(MigrationReport {
        migrated: records.len(),
        ..Default::default()
    })
}

/// An existing, unmarked SQLite database is not permission to replay stale JSON over a row that
/// may have evolved after a previous app version opened the database. Identical rows are valid
/// crash residue (commit/checkpoint succeeded before marker publication). A missing row can be
/// imported only when the whole database has no durable state; otherwise it may represent a later
/// deletion and blocks. Any collision must be byte-for-byte equivalent at the typed boundary.
fn preflight_active_record_non_overwrite(
    conn: &rusqlite::Connection,
    records: &[LegacyRecord],
) -> Result<(), String> {
    let database_has_durable_state = sqlite_has_any_durable_state(conn)?;
    for record in records {
        let Some(current) = load_and_validate_visible_record(conn, record)? else {
            if database_has_durable_state {
                return Err(format!(
                    "unmarked SQLite is non-empty but active legacy {:?} {} from {} is absent; it may have been deleted after SQLite became authoritative, so automatic resurrection is blocked and the source remains active",
                    record.kind,
                    record.id,
                    record.path.display()
                ));
            }
            continue;
        };
        if current != record.canonical {
            return Err(format!(
                "unmarked SQLite {:?} {} diverges from active legacy JSON {}; refusing to overwrite either authority and leaving the source active",
                record.kind,
                record.id,
                record.path.display()
            ));
        }
    }
    Ok(())
}

fn sqlite_has_any_durable_state(conn: &rusqlite::Connection) -> Result<bool, String> {
    for kind in MIGRATION_ORDER {
        if !crate::store_sqlite::load_all(conn, *kind)
            .map_err(|error| format!("inspect unmarked SQLite {kind:?} rows: {error}"))?
            .is_empty()
        {
            return Ok(true);
        }
    }
    let sidecar_rows: bool = conn
        .query_row("SELECT EXISTS(SELECT 1 FROM session_names)", [], |row| {
            row.get(0)
        })
        .map_err(|error| format!("inspect unmarked SQLite sidecar rows: {error}"))?;
    Ok(sidecar_rows)
}

fn parse_legacy_records(
    source_paths: Vec<(RecordKind, String, PathBuf)>,
) -> Result<Vec<LegacyRecord>, String> {
    let mut records = Vec::with_capacity(source_paths.len());
    for (kind, id, path) in source_paths {
        let bytes = read_regular_file_no_follow(&path)
            .map_err(|e| format!("read legacy record {}: {e}", path.display()))?;
        let env = Envelope::<Value>::from_json_bytes(&bytes, kind.schema())
            .map_err(|e| format!("parse legacy record {}: {e}", path.display()))?;
        let canonical = canonical_typed_record(kind, &id, &env.record, false).map_err(|error| {
            format!(
                "validate legacy {:?} {} from {}: {error}",
                kind,
                id,
                path.display()
            )
        })?;
        records.push(LegacyRecord {
            kind,
            id,
            path,
            bytes,
            value: canonical.clone(),
            canonical,
        });
    }
    Ok(records)
}

fn parse_recovery_archive_records(paths: &AppPaths) -> Result<Vec<LegacyRecord>, String> {
    let source_paths = collect_all_archive_record_paths(paths)?;
    parse_legacy_records(source_paths).map_err(|error| {
        format!(
            "previous-stable legacy archive reconciliation is blocked: {error}; no completion marker was written and every recovery archive was preserved"
        )
    })
}

/// Before mutating an existing database, prove that an archive-only identity is already visible or
/// is part of the still-active snapshot that this transaction will import. A missing archive row is
/// ambiguous: it may have been intentionally deleted later, or it may be one of the rows the
/// best-effort importer silently skipped. We do not guess or resurrect it automatically.
fn preflight_archived_record_visibility(
    conn: &rusqlite::Connection,
    archived: &[LegacyRecord],
    pending: &[LegacyRecord],
) -> Result<(), String> {
    for record in archived {
        if load_and_validate_visible_record(conn, record)?.is_none()
            && !pending
                .iter()
                .any(|candidate| candidate.kind == record.kind && candidate.id == record.id)
        {
            return Err(unresolved_archived_record_error(record));
        }
    }
    Ok(())
}

fn verify_archived_records_visible(
    conn: &rusqlite::Connection,
    archived: &[LegacyRecord],
) -> Result<(), String> {
    for record in archived {
        if load_and_validate_visible_record(conn, record)?.is_none() {
            return Err(unresolved_archived_record_error(record));
        }
    }
    Ok(())
}

fn load_and_validate_visible_record(
    conn: &rusqlite::Connection,
    record: &LegacyRecord,
) -> Result<Option<Value>, String> {
    let Some(loaded) =
        crate::store_sqlite::load_one(conn, record.kind, &record.id).map_err(|e| {
            format!(
                "inspect SQLite while reconciling previous-stable {:?} {} from {}: {e}",
                record.kind,
                record.id,
                record.path.display()
            )
        })?
    else {
        return Ok(None);
    };
    let canonical =
        canonical_typed_record(record.kind, &record.id, &loaded, true).map_err(|error| {
            format!(
                "validate SQLite while reconciling previous-stable {:?} {} from {}: {error}",
                record.kind,
                record.id,
                record.path.display()
            )
        })?;
    Ok(Some(canonical))
}

fn unresolved_archived_record_error(record: &LegacyRecord) -> String {
    format!(
        "previous-stable legacy archive {} contains {:?} {} that is absent from SQLite; it may have been skipped by the old best-effort importer, so automatic reconciliation is blocked, the archive is preserved, and no completion marker was written",
        record.path.display(),
        record.kind,
        record.id
    )
}

fn reject_unknown_top_level_fields(value: &Value, allowed: &[&str]) -> Result<(), String> {
    let object = value
        .as_object()
        .ok_or_else(|| "record must be a JSON object".to_string())?;
    if let Some(field) = object
        .keys()
        .find(|field| !allowed.contains(&field.as_str()))
    {
        return Err(format!("unknown top-level field {field:?}"));
    }
    Ok(())
}

/// Serde's durable structs intentionally default fields added by newer releases, but most of them
/// do not use `deny_unknown_fields`. Compare every input object recursively with the canonical
/// typed serialization so an ignored field cannot disappear silently at any nesting depth. The
/// only canonical omissions are known `Option::None` fields explicitly configured with
/// `skip_serializing_if`; a JSON null for one of those remains a valid spelling.
fn reject_unknown_durable_fields(
    input: &Value,
    canonical: &Value,
    path: &str,
) -> Result<(), String> {
    match (input, canonical) {
        (Value::Object(input), Value::Object(canonical)) => {
            for (field, value) in input {
                let child_path = format!("{path}/{}", json_pointer_escape(field));
                if let Some(canonical_value) = canonical.get(field) {
                    reject_unknown_durable_fields(value, canonical_value, &child_path)?;
                } else if !(value.is_null() && known_skipped_none_field(path, field)) {
                    return Err(format!("unknown durable field {child_path:?}"));
                }
            }
        }
        (Value::Array(input), Value::Array(canonical)) => {
            for (index, value) in input.iter().enumerate() {
                let Some(canonical_value) = canonical.get(index) else {
                    return Err(format!(
                        "typed canonical value lost array element {path}/{index}"
                    ));
                };
                reject_unknown_durable_fields(value, canonical_value, &format!("{path}/{index}"))?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn known_skipped_none_field(path: &str, field: &str) -> bool {
    (path == "$/launch_defaults"
        && matches!(
            field,
            "agent" | "model" | "resume_mode" | "dangerous_skip_permissions" | "custom_command"
        ))
        || (path == "$" && field == "daemon_pid")
}

fn json_pointer_escape(field: &str) -> String {
    field.replace('~', "~0").replace('/', "~1")
}

/// Deserialize through the exact durable type, enforce filename/embedded identity agreement, and
/// serialize back to one canonical value. This catches permissive mapper behavior (for example a
/// non-array `WindowLayout.tabs` becoming an empty window) before SQLite is opened.
fn canonical_typed_record(
    kind: RecordKind,
    id: &str,
    value: &Value,
    loaded_from_sqlite: bool,
) -> Result<Value, String> {
    let mut value = value.clone();
    if loaded_from_sqlite && kind == RecordKind::WindowLayout {
        // `project_id` is a relational ownership edge derived during migration, not part of the
        // durable WindowLayout JSON model.
        if let Value::Object(object) = &mut value {
            object.remove("project_id");
        }
    }

    macro_rules! typed {
        ($ty:ty, $identity:ident, $allowed:expr) => {{
            reject_unknown_top_level_fields(&value, $allowed)?;
            let record: $ty = serde_json::from_value(value.clone())
                .map_err(|error| format!("typed record decode failed: {error}"))?;
            if record.$identity != id {
                return Err(format!(
                    "embedded id {:?} does not match filename id {id:?}",
                    record.$identity
                ));
            }
            let canonical = serde_json::to_value(record)
                .map_err(|error| format!("canonical record encode failed: {error}"))?;
            reject_unknown_durable_fields(&value, &canonical, "$")?;
            Ok(canonical)
        }};
    }

    match kind {
        RecordKind::Project => typed!(
            crate::records::Project,
            project_id,
            &[
                "project_id",
                "name",
                "root",
                "default_workspace_policy",
                "created_at_ms",
                "last_active_at_ms",
                "icon",
                "accent_color",
                "launch_defaults",
                "directories",
                "window_order",
                "system",
                "hidden",
            ]
        ),
        RecordKind::Workspace => typed!(
            crate::records::Workspace,
            workspace_id,
            &["workspace_id", "project_id", "root", "policy", "consent"]
        ),
        RecordKind::Session => typed!(
            crate::records::SessionRecord,
            session_id,
            &[
                "session_id",
                "workspace_id",
                "kind",
                "launch",
                "cwd_resolved",
                "agent_task_id",
                "created_at_ms",
                "last_attached_at_ms",
                "last_known_generation",
                "status",
            ]
        ),
        RecordKind::AgentTask => typed!(
            crate::records::AgentTask,
            agent_task_id,
            &[
                "agent_task_id",
                "project_id",
                "goal",
                "state",
                "current_session_id",
                "session_history",
                "created_at_ms",
                "updated_at_ms",
                "result_summary",
            ]
        ),
        RecordKind::WindowLayout => typed!(
            crate::records::WindowLayout,
            window_id,
            &["window_id", "name", "tabs"]
        ),
        RecordKind::LayoutPreset => typed!(
            crate::records::LayoutPreset,
            preset_id,
            &["preset_id", "name", "project_id", "created_at_ms", "tabs"]
        ),
        RecordKind::WorktreeProvenance => typed!(
            crate::records::WorktreeProvenance,
            session_id,
            &[
                "workspace_id",
                "session_id",
                "repo_root",
                "target_path",
                "branch",
                "created_at_ms",
            ]
        ),
        RecordKind::DaemonEndpoint => {
            reject_unknown_top_level_fields(
                &value,
                &["socket_path", "daemon_pid", "updated_at_ms"],
            )?;
            if id != crate::daemon_endpoint::ENDPOINT_ID {
                return Err(format!(
                    "daemon endpoint filename id {id:?} is not the singleton id {:?}",
                    crate::daemon_endpoint::ENDPOINT_ID
                ));
            }
            let record: crate::daemon_endpoint::DaemonEndpoint =
                serde_json::from_value(value.clone())
                    .map_err(|error| format!("typed record decode failed: {error}"))?;
            let canonical = serde_json::to_value(record)
                .map_err(|error| format!("canonical record encode failed: {error}"))?;
            reject_unknown_durable_fields(&value, &canonical, "$")?;
            Ok(canonical)
        }
    }
}

/// Import the legacy dashboard custom-name/hidden-session sidecars. Both files are parsed before
/// SQLite mutation; each committed map is read back before either source file is renamed.
pub fn migrate_session_sidecars(paths: &AppPaths) -> Result<(), String> {
    run_migration_test_hook("before-migration-lock", paths.base());
    let _lock = MigrationLock::acquire(paths.base())?;
    let database_existed_before = path_is_regular_file_no_follow(&crate::db::db_path(paths.base()))
        .map_err(|error| {
            format!(
                "inspect SQLite authority before legacy sidecar migration {}: {error}",
                crate::db::db_path(paths.base()).display()
            )
        })?;
    // Sidecars must never create an empty SQLite store beside authoritative record JSON. Resolve
    // the main records while retaining this same lock so database provenance cannot race.
    migrate_json_to_sqlite_locked(paths)?;
    let marker_exists = validate_named_marker(
        paths.base(),
        SIDECAR_COMPLETION_MARKER,
        SIDECAR_COMPLETION_MARKER_BODY,
        "legacy session-sidecar import",
    )?;
    let legacy_marker_exists = validate_named_marker(
        paths.base(),
        LEGACY_SIDECAR_COMPLETION_MARKER,
        LEGACY_SIDECAR_COMPLETION_MARKER_BODY,
        "legacy v1 session-sidecar import",
    )?;
    let sidecar_database_exists = path_is_regular_file_no_follow(&crate::db::db_path(paths.base()))
        .map_err(|error| {
            format!(
                "SQLite sidecar authority must be a regular file {}: {error}",
                crate::db::db_path(paths.base()).display()
            )
        })?;
    if (marker_exists || legacy_marker_exists) && !sidecar_database_exists {
        return Err(format!(
            "legacy session-sidecar marker exists but {} is missing",
            crate::db::DB_FILENAME
        ));
    }
    let dashboard = paths.base().join("dashboard");
    path_is_directory_no_follow(&dashboard).map_err(|error| {
        format!(
            "legacy dashboard sidecar directory must not be a symlink {}: {error}",
            dashboard.display()
        )
    })?;
    let names_path = dashboard.join("sessionNames.json");
    let hidden_path = dashboard.join("hiddenSessions.json");

    let names = read_optional_sidecar::<BTreeMap<String, String>>(&names_path)?;
    let hidden = read_optional_sidecar::<BTreeSet<String>>(&hidden_path)?;

    // Opening SQLite can create a schema-only database before the sidecar transaction commits.
    // Persist the exact raw source pair first so a restart can distinguish that interrupted fresh
    // import from stale sidecars discovered beside a genuinely pre-existing SQLite authority.
    let pending_snapshot = encode_sidecar_pending_snapshot(&names, &hidden)?;
    run_migration_test_hook("after-sidecar-initial-snapshot", paths.base());
    // Revalidate immediately after the snapshot boundary. Besides closing the testable TOCTOU
    // window, this prevents a grown/replaced source from causing a pending marker or transaction.
    verify_optional_sidecar_sources(&names_path, &names, &hidden_path, &hidden)?;
    let mut pending_matches = false;
    if let Some(existing) = read_sidecar_pending_snapshot(paths.base())? {
        if !marker_exists && existing != pending_snapshot {
            return Err(
                "legacy session-sidecar pending snapshot differs from the active source pair; automatic reconciliation is blocked and both states were preserved"
                    .to_string(),
            );
        }
        pending_matches = existing == pending_snapshot;
    } else if !marker_exists && !database_existed_before && (names.is_some() || hidden.is_some()) {
        write_sidecar_pending_snapshot(paths.base(), &pending_snapshot)?;
        pending_matches = true;
        migration_failpoint("after-sidecar-pending-snapshot")?;
    }

    let arc = crate::db::conn_for_migration(paths.base()).map_err(|e| e.to_string())?;
    let mut conn = arc
        .lock()
        .map_err(|_| "sidecar migration database lock was poisoned".to_string())?;

    if marker_exists {
        ensure_database_integrity(&conn, "completed session-sidecar database")?;
        if names.is_none() && hidden.is_none() {
            retire_sidecar_pending_snapshot(paths.base())?;
            return Ok(());
        }
        let current_names = load_session_names_from(&conn)?;
        let current_hidden = load_hidden_sessions_from(&conn)?;
        if let Some((_, legacy)) = &names {
            for (key, value) in legacy {
                if current_names.get(key) != Some(value) {
                    return Err(format!(
                        "legacy session-name sidecar diverged after completed import at key {key:?}; left untouched"
                    ));
                }
            }
        }
        if let Some((_, legacy)) = &hidden {
            if !legacy.is_subset(&current_hidden) {
                return Err(
                    "legacy hidden-session sidecar diverged after completed import; left untouched"
                        .to_string(),
                );
            }
        }
        set_full_durability(&conn)?;
        checkpoint_fully(&conn)?;
        verify_optional_sidecar_sources(&names_path, &names, &hidden_path, &hidden)?;
        if let Some((bytes, _)) = &names {
            archive_sidecar(&names_path, bytes)?;
        }
        if let Some((bytes, _)) = &hidden {
            archive_sidecar(&hidden_path, bytes)?;
        }
        restore_normal_durability(&conn)?;
        retire_sidecar_pending_snapshot(paths.base())?;
        return Ok(());
    }

    // A v1 marker did not inspect files renamed by the previous best-effort importer. Before the
    // v2 marker can be published, parse every `.json.migrated*` generation and prove that each
    // archived identity is visible in SQLite (or in the active sidecar about to be merged).
    let mut archived_sidecar_budget = ArchivedSidecarBudget::default();
    let archived_names = read_archived_sidecars::<BTreeMap<String, String>>(
        &dashboard,
        "sessionNames.json.migrated",
        "session-name",
        &mut archived_sidecar_budget,
    )?;
    let archived_hidden = read_archived_sidecars::<BTreeSet<String>>(
        &dashboard,
        "hiddenSessions.json.migrated",
        "hidden-session",
        &mut archived_sidecar_budget,
    )?;

    if legacy_marker_exists {
        if names.is_none()
            && hidden.is_none()
            && archived_names.is_empty()
            && archived_hidden.is_empty()
        {
            return Err(
                "legacy v1 session-sidecar marker exists, but no active or .json.migrated* sidecar remains to reconcile; refusing to promote an unproven completion marker"
                    .to_string(),
            );
        }
        let current_names = load_session_names_from(&conn)?;
        let current_hidden = load_hidden_sessions_from(&conn)?;
        if let Some((_, legacy)) = &names {
            for (key, value) in legacy {
                if current_names.get(key) != Some(value) {
                    return Err(format!(
                        "legacy session-name sidecar diverged after v1 completion at key {key:?}; left untouched"
                    ));
                }
            }
        }
        if let Some((_, legacy)) = &hidden {
            if !legacy.is_subset(&current_hidden) {
                return Err(
                    "legacy hidden-session sidecar diverged after v1 completion; left untouched"
                        .to_string(),
                );
            }
        }
        verify_archived_name_visibility(&current_names, &archived_names)?;
        verify_archived_hidden_visibility(&current_hidden, &archived_hidden)?;
        set_full_durability(&conn)?;
        checkpoint_fully(&conn)?;
        verify_optional_sidecar_sources(&names_path, &names, &hidden_path, &hidden)?;
        verify_archived_sidecar_sources(&archived_names)?;
        verify_archived_sidecar_sources(&archived_hidden)?;
        write_named_marker(
            paths.base(),
            SIDECAR_COMPLETION_MARKER,
            SIDECAR_COMPLETION_MARKER_BODY,
            "legacy session-sidecar import",
        )?;
        if let Some((bytes, _)) = &names {
            archive_sidecar(&names_path, bytes)?;
        }
        if let Some((bytes, _)) = &hidden {
            archive_sidecar(&hidden_path, bytes)?;
        }
        restore_normal_durability(&conn)?;
        retire_sidecar_pending_snapshot(paths.base())?;
        return Ok(());
    }

    let mut expected_names = load_session_names_from(&conn)?;
    let mut expected_hidden = load_hidden_sessions_from(&conn)?;
    preflight_archived_name_visibility(&expected_names, names.as_ref(), &archived_names)?;
    preflight_archived_hidden_visibility(&expected_hidden, hidden.as_ref(), &archived_hidden)?;
    // If SQLite already existed when this operation began, a missing sidecar key is ambiguous: it
    // can mean the old best-effort importer skipped it, but it can equally mean the user deleted a
    // custom name or explicitly unhid a session later. Never resurrect that stale state. A truly
    // fresh migration (no database at entry) may seed the new database from its sidecars. The only
    // restart exception is an exact pending snapshot beside an otherwise empty schema database,
    // which proves that this process created the competing file before its sidecar commit.
    let interrupted_fresh_import =
        database_existed_before && pending_matches && !sqlite_has_any_durable_state(&conn)?;
    if database_existed_before && !interrupted_fresh_import {
        preflight_active_sidecars_do_not_resurrect(
            &expected_names,
            &expected_hidden,
            names.as_ref(),
            hidden.as_ref(),
        )?;
    }
    if let Some((_, legacy)) = &names {
        for (key, value) in legacy {
            if let Some(existing) = expected_names.get(key) {
                if existing != value {
                    return Err(format!(
                        "legacy session-name sidecar conflicts with newer SQLite value at key {key:?}; left untouched"
                    ));
                }
            } else {
                expected_names.insert(key.clone(), value.clone());
            }
        }
    }
    if let Some((_, legacy)) = &hidden {
        expected_hidden.extend(legacy.iter().cloned());
    }

    set_full_durability(&conn)?;
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|e| format!("begin session sidecar import: {e}"))?;
    if let Some((_, parsed)) = &names {
        merge_session_names_in(&tx, parsed)?;
    }
    if let Some((_, parsed)) = &hidden {
        merge_hidden_sessions_in(&tx, parsed)?;
    }
    if load_session_names_from(&tx)? != expected_names {
        return Err("session-name sidecar transaction verification failed".into());
    }
    if load_hidden_sessions_from(&tx)? != expected_hidden {
        return Err("hidden-session sidecar transaction verification failed".into());
    }
    verify_optional_sidecar_sources(&names_path, &names, &hidden_path, &hidden)?;
    migration_failpoint("before-sidecar-sqlite-commit")?;
    tx.commit()
        .map_err(|e| format!("commit session sidecar import: {e}"))?;
    migration_failpoint("after-sidecar-sqlite-commit")?;

    if load_session_names_from(&conn)? != expected_names {
        return Err("session-name sidecar verification did not match committed rows".into());
    }
    if load_hidden_sessions_from(&conn)? != expected_hidden {
        return Err("hidden-session sidecar verification did not match committed rows".into());
    }
    verify_archived_name_visibility(&expected_names, &archived_names)?;
    verify_archived_hidden_visibility(&expected_hidden, &archived_hidden)?;
    checkpoint_fully(&conn)?;
    migration_failpoint("after-sidecar-sqlite-checkpoint")?;
    verify_optional_sidecar_sources(&names_path, &names, &hidden_path, &hidden)?;
    verify_archived_sidecar_sources(&archived_names)?;
    verify_archived_sidecar_sources(&archived_hidden)?;
    migration_failpoint("after-sidecar-source-snapshot")?;
    write_named_marker(
        paths.base(),
        SIDECAR_COMPLETION_MARKER,
        SIDECAR_COMPLETION_MARKER_BODY,
        "legacy session-sidecar import",
    )?;
    migration_failpoint("after-sidecar-completion-marker")?;
    if let Some((bytes, _)) = &names {
        archive_sidecar(&names_path, bytes)?;
    }
    if let Some((bytes, _)) = &hidden {
        archive_sidecar(&hidden_path, bytes)?;
    }
    restore_normal_durability(&conn)?;
    retire_sidecar_pending_snapshot(paths.base())?;
    Ok(())
}

fn encode_sidecar_pending_snapshot<T, U>(
    names: &Option<(Vec<u8>, T)>,
    hidden: &Option<(Vec<u8>, U)>,
) -> Result<Vec<u8>, String> {
    let mut encoded = Vec::with_capacity(
        SIDECAR_PENDING_HEADER.len()
            + names.as_ref().map(|(bytes, _)| bytes.len()).unwrap_or(0)
            + hidden.as_ref().map(|(bytes, _)| bytes.len()).unwrap_or(0)
            + 18,
    );
    encoded.extend_from_slice(SIDECAR_PENDING_HEADER);
    append_pending_snapshot_part(
        &mut encoded,
        names.as_ref().map(|(bytes, _)| bytes.as_slice()),
    )?;
    append_pending_snapshot_part(
        &mut encoded,
        hidden.as_ref().map(|(bytes, _)| bytes.as_slice()),
    )?;
    Ok(encoded)
}

fn append_pending_snapshot_part(encoded: &mut Vec<u8>, bytes: Option<&[u8]>) -> Result<(), String> {
    let Some(bytes) = bytes else {
        encoded.push(0);
        return Ok(());
    };
    let length = u64::try_from(bytes.len())
        .map_err(|_| "legacy sidecar is too large to snapshot safely".to_string())?;
    encoded.push(1);
    encoded.extend_from_slice(&length.to_be_bytes());
    encoded.extend_from_slice(bytes);
    Ok(())
}

fn validate_sidecar_pending_snapshot(bytes: &[u8]) -> Result<(), String> {
    if !bytes.starts_with(SIDECAR_PENDING_HEADER) {
        return Err("legacy session-sidecar pending snapshot has an invalid header".to_string());
    }
    let mut cursor = SIDECAR_PENDING_HEADER.len();
    for label in ["session-name", "hidden-session"] {
        let tag = *bytes.get(cursor).ok_or_else(|| {
            format!("legacy session-sidecar pending snapshot truncates the {label} presence tag")
        })?;
        cursor += 1;
        match tag {
            0 => {}
            1 => {
                let length_end = cursor.checked_add(8).ok_or_else(|| {
                    "legacy session-sidecar pending snapshot length overflow".to_string()
                })?;
                let length_bytes: [u8; 8] = bytes
                    .get(cursor..length_end)
                    .ok_or_else(|| {
                        format!(
                            "legacy session-sidecar pending snapshot truncates the {label} length"
                        )
                    })?
                    .try_into()
                    .expect("eight-byte slice");
                cursor = length_end;
                let length = usize::try_from(u64::from_be_bytes(length_bytes)).map_err(|_| {
                    format!(
                        "legacy session-sidecar pending snapshot {label} length exceeds this platform"
                    )
                })?;
                cursor = cursor.checked_add(length).ok_or_else(|| {
                    "legacy session-sidecar pending snapshot payload overflow".to_string()
                })?;
                if cursor > bytes.len() {
                    return Err(format!(
                        "legacy session-sidecar pending snapshot truncates the {label} payload"
                    ));
                }
            }
            other => {
                let message = format!(
                    "legacy session-sidecar pending snapshot has invalid {label} presence tag {other}"
                );
                return Err(message);
            }
        }
    }
    if cursor != bytes.len() {
        return Err(
            "legacy session-sidecar pending snapshot has unexpected trailing bytes".to_string(),
        );
    }
    Ok(())
}

fn read_sidecar_pending_snapshot(base: &Path) -> Result<Option<Vec<u8>>, String> {
    let path = base.join(SIDECAR_PENDING_SNAPSHOT);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "inspect legacy session-sidecar pending snapshot {}: {error}",
                path.display()
            ))
        }
    };
    if !metadata.file_type().is_file() {
        return Err(format!(
            "legacy session-sidecar pending snapshot {} is not a regular file; refusing to follow or replace it",
            path.display()
        ));
    }
    let bytes =
        read_regular_file_no_follow_bounded(&path, LEGACY_SESSION_SIDECAR_PENDING_MAX_BYTES)
            .map_err(|error| {
                format!(
                    "read legacy session-sidecar pending snapshot {}: {error}",
                    path.display()
                )
            })?;
    validate_sidecar_pending_snapshot(&bytes).map_err(|error| {
        format!(
            "{error} at {}; refusing to guess migration state",
            path.display()
        )
    })?;
    Ok(Some(bytes))
}

fn write_sidecar_pending_snapshot(base: &Path, snapshot: &[u8]) -> Result<(), String> {
    if let Some(existing) = read_sidecar_pending_snapshot(base)? {
        if existing == snapshot {
            return Ok(());
        }
        return Err(
            "legacy session-sidecar pending snapshot differs from the selected source pair; refusing to replace either state"
                .to_string(),
        );
    }
    write_named_marker(
        base,
        SIDECAR_PENDING_SNAPSHOT,
        snapshot,
        "legacy session-sidecar pending snapshot",
    )
}

fn retire_sidecar_pending_snapshot(base: &Path) -> Result<(), String> {
    let Some(expected) = read_sidecar_pending_snapshot(base)? else {
        return Ok(());
    };
    let path = base.join(SIDECAR_PENDING_SNAPSHOT);
    let identity = regular_file_identity(&path)?;
    let actual = read_regular_file_no_follow_bounded(
        &path,
        u64::try_from(expected.len()).unwrap_or(u64::MAX),
    )
    .map_err(|error| {
        format!(
            "re-read legacy session-sidecar pending snapshot before retirement {}: {error}",
            path.display()
        )
    })?;
    if actual != expected || regular_file_identity(&path)? != identity {
        return Err(format!(
            "legacy session-sidecar pending snapshot {} changed before retirement; it was preserved",
            path.display()
        ));
    }
    fs::remove_file(&path).map_err(|error| {
        format!(
            "retire completed legacy session-sidecar pending snapshot {}: {error}",
            path.display()
        )
    })?;
    sync_dir(base)?;
    Ok(())
}

fn preflight_active_sidecars_do_not_resurrect(
    current_names: &BTreeMap<String, String>,
    current_hidden: &BTreeSet<String>,
    active_names: Option<&(Vec<u8>, BTreeMap<String, String>)>,
    active_hidden: Option<&(Vec<u8>, BTreeSet<String>)>,
) -> Result<(), String> {
    if let Some((_, names)) = active_names {
        for key in names.keys() {
            if !current_names.contains_key(key) {
                return Err(format!(
                    "active legacy session-name sidecar contains missing SQLite key {key:?}; the name may have been deleted after SQLite became authoritative, so automatic resurrection is blocked and the sidecar is preserved"
                ));
            }
        }
    }
    if let Some((_, hidden)) = active_hidden {
        for key in hidden {
            if !current_hidden.contains(key) {
                return Err(format!(
                    "active legacy hidden-session sidecar contains missing SQLite key {key:?}; the session may have been unhidden after SQLite became authoritative, so automatic resurrection is blocked and the sidecar is preserved"
                ));
            }
        }
    }
    Ok(())
}

fn merge_session_names_in(
    conn: &rusqlite::Connection,
    names: &BTreeMap<String, String>,
) -> Result<(), String> {
    for (key, name) in names {
        conn.execute(
            "INSERT INTO session_names (key, custom_name) VALUES (?1, ?2) \
             ON CONFLICT(key) DO UPDATE SET custom_name = excluded.custom_name",
            rusqlite::params![key, name],
        )
        .map_err(|e| format!("import session name {key}: {e}"))?;
    }
    Ok(())
}

fn merge_hidden_sessions_in(
    conn: &rusqlite::Connection,
    hidden: &BTreeSet<String>,
) -> Result<(), String> {
    for key in hidden {
        conn.execute(
            "INSERT INTO session_names (key, hidden) VALUES (?1, 1) \
             ON CONFLICT(key) DO UPDATE SET hidden = 1",
            [key],
        )
        .map_err(|e| format!("import hidden session {key}: {e}"))?;
    }
    Ok(())
}

fn verify_optional_sidecar_sources<T, U>(
    names_path: &Path,
    names: &Option<(Vec<u8>, T)>,
    hidden_path: &Path,
    hidden: &Option<(Vec<u8>, U)>,
) -> Result<(), String> {
    if let Some((bytes, _)) = names {
        verify_file_unchanged(names_path, bytes)?;
    } else if names_path.exists() {
        return Err(format!(
            "legacy sidecar {} appeared during import; retry required",
            names_path.display()
        ));
    }
    if let Some((bytes, _)) = hidden {
        verify_file_unchanged(hidden_path, bytes)?;
    } else if hidden_path.exists() {
        return Err(format!(
            "legacy sidecar {} appeared during import; retry required",
            hidden_path.display()
        ));
    }
    Ok(())
}

fn load_session_names_from(
    conn: &rusqlite::Connection,
) -> Result<BTreeMap<String, String>, String> {
    let mut stmt = conn
        .prepare("SELECT key, custom_name FROM session_names WHERE custom_name IS NOT NULL")
        .map_err(|e| format!("verify session names: {e}"))?;
    let rows = stmt
        .query_map([], |row| {
            Ok((row.get::<_, String>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(|e| format!("verify session names: {e}"))?;
    let mut out = BTreeMap::new();
    for row in rows {
        let (key, name) = row.map_err(|e| format!("verify session names: {e}"))?;
        out.insert(key, name);
    }
    Ok(out)
}

fn load_hidden_sessions_from(conn: &rusqlite::Connection) -> Result<BTreeSet<String>, String> {
    let mut stmt = conn
        .prepare("SELECT key FROM session_names WHERE hidden = 1")
        .map_err(|e| format!("verify hidden sessions: {e}"))?;
    let rows = stmt
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(|e| format!("verify hidden sessions: {e}"))?;
    let mut out = BTreeSet::new();
    for row in rows {
        out.insert(row.map_err(|e| format!("verify hidden sessions: {e}"))?);
    }
    Ok(out)
}

fn read_optional_sidecar<T>(path: &Path) -> Result<Option<(Vec<u8>, T)>, String>
where
    T: serde::de::DeserializeOwned,
{
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => {
            return Err(format!(
                "inspect legacy sidecar {}: {error}",
                path.display()
            ))
        }
    };
    if !metadata.file_type().is_file() {
        return Err(format!(
            "legacy sidecar is not a regular file: {}",
            path.display()
        ));
    }
    let bytes = read_regular_file_no_follow_bounded(path, LEGACY_SESSION_SIDECAR_MAX_BYTES)
        .map_err(|error| format!("read legacy sidecar {}: {error}", path.display()))?;
    let parsed = serde_json::from_slice(&bytes)
        .map_err(|e| format!("parse legacy sidecar {}: {e}", path.display()))?;
    Ok(Some((bytes, parsed)))
}

fn read_archived_sidecars<T>(
    dashboard: &Path,
    filename_prefix: &str,
    label: &str,
    budget: &mut ArchivedSidecarBudget,
) -> Result<Vec<ArchivedSidecar<T>>, String>
where
    T: serde::de::DeserializeOwned,
{
    match path_is_directory_no_follow(dashboard) {
        Ok(false) => return Ok(Vec::new()),
        Ok(true) => {}
        Err(error) => {
            return Err(format!(
                "inspect previous-stable {label} sidecar directory {}: {error}",
                dashboard.display()
            ))
        }
    }
    let entries = match fs::read_dir(dashboard) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => {
            return Err(format!(
                "inspect previous-stable {label} sidecar directory {}: {error}",
                dashboard.display()
            ))
        }
    };
    let mut paths = Vec::new();
    for entry in entries {
        let entry = entry.map_err(|error| {
            format!(
                "inspect previous-stable {label} sidecar directory {}: {error}",
                dashboard.display()
            )
        })?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if !name.starts_with(filename_prefix) {
            continue;
        }
        if paths.len() >= LEGACY_SESSION_SIDECAR_ARCHIVE_MAX_GENERATIONS_PER_KIND {
            return Err(format!(
                "previous-stable {label} sidecars exceed the {LEGACY_SESSION_SIDECAR_ARCHIVE_MAX_GENERATIONS_PER_KIND}-generation limit; no completion marker was written and every sidecar was preserved",
            ));
        }
        let path = entry.path();
        if !entry
            .file_type()
            .map_err(|error| {
                format!(
                    "inspect previous-stable {label} sidecar {}: {error}",
                    path.display()
                )
            })?
            .is_file()
        {
            return Err(format!(
                "previous-stable {label} sidecar is not a regular file: {}; no completion marker was written",
                path.display()
            ));
        }
        paths.push(path);
    }
    paths.sort();

    let mut out = Vec::with_capacity(paths.len());
    for path in paths {
        let metadata = fs::symlink_metadata(&path).map_err(|error| {
            format!(
                "inspect previous-stable {label} sidecar {} before budget accounting: {error}; no completion marker was written and every sidecar was preserved",
                path.display()
            )
        })?;
        if !metadata.file_type().is_file() {
            return Err(format!(
                "previous-stable {label} sidecar is not a regular file: {}; no completion marker was written",
                path.display()
            ));
        }
        let prospective_total = budget.raw_bytes.checked_add(metadata.len()).ok_or_else(|| {
            "previous-stable session sidecars exceed the aggregate raw-byte budget; no completion marker was written and every sidecar was preserved"
                .to_string()
        })?;
        if prospective_total > LEGACY_SESSION_SIDECAR_ARCHIVE_MAX_TOTAL_BYTES {
            return Err(format!(
                "previous-stable session sidecars exceed the {LEGACY_SESSION_SIDECAR_ARCHIVE_MAX_TOTAL_BYTES}-byte aggregate raw-byte budget; no completion marker was written and every sidecar was preserved",
            ));
        }
        let remaining_budget =
            LEGACY_SESSION_SIDECAR_ARCHIVE_MAX_TOTAL_BYTES.saturating_sub(budget.raw_bytes);
        let read_limit = LEGACY_SESSION_SIDECAR_MAX_BYTES.min(remaining_budget);
        let bytes = read_regular_file_no_follow_bounded(&path, read_limit).map_err(|error| {
            format!(
                "read previous-stable {label} sidecar {}: {error}; no completion marker was written and the sidecar was preserved",
                path.display()
            )
        })?;
        let actual_total = budget
            .raw_bytes
            .checked_add(u64::try_from(bytes.len()).unwrap_or(u64::MAX))
            .ok_or_else(|| {
                "previous-stable session sidecars exceed the aggregate raw-byte budget; no completion marker was written and every sidecar was preserved"
                    .to_string()
        })?;
        if actual_total > LEGACY_SESSION_SIDECAR_ARCHIVE_MAX_TOTAL_BYTES {
            return Err(format!(
                "previous-stable session sidecars exceed the {LEGACY_SESSION_SIDECAR_ARCHIVE_MAX_TOTAL_BYTES}-byte aggregate raw-byte budget; no completion marker was written and every sidecar was preserved",
            ));
        }
        let value = serde_json::from_slice(&bytes).map_err(|error| {
            format!(
                "parse previous-stable {label} sidecar {}: {error}; the old importer may have renamed it despite failure, so reconciliation is blocked, the sidecar is preserved, and no completion marker was written",
                path.display()
            )
        })?;
        budget.raw_bytes = actual_total;
        out.push(ArchivedSidecar { path, bytes, value });
    }
    Ok(out)
}

fn preflight_archived_name_visibility(
    current: &BTreeMap<String, String>,
    active: Option<&(Vec<u8>, BTreeMap<String, String>)>,
    archived: &[ArchivedSidecar<BTreeMap<String, String>>],
) -> Result<(), String> {
    for sidecar in archived {
        for key in sidecar.value.keys() {
            if !current.contains_key(key)
                && !active
                    .map(|(_, values)| values.contains_key(key))
                    .unwrap_or(false)
            {
                return Err(unresolved_archived_sidecar_error(
                    "session-name",
                    &sidecar.path,
                    key,
                ));
            }
        }
    }
    Ok(())
}

fn preflight_archived_hidden_visibility(
    current: &BTreeSet<String>,
    active: Option<&(Vec<u8>, BTreeSet<String>)>,
    archived: &[ArchivedSidecar<BTreeSet<String>>],
) -> Result<(), String> {
    for sidecar in archived {
        for key in &sidecar.value {
            if !current.contains(key)
                && !active
                    .map(|(_, values)| values.contains(key))
                    .unwrap_or(false)
            {
                return Err(unresolved_archived_sidecar_error(
                    "hidden-session",
                    &sidecar.path,
                    key,
                ));
            }
        }
    }
    Ok(())
}

fn verify_archived_name_visibility(
    current: &BTreeMap<String, String>,
    archived: &[ArchivedSidecar<BTreeMap<String, String>>],
) -> Result<(), String> {
    for sidecar in archived {
        for key in sidecar.value.keys() {
            if !current.contains_key(key) {
                return Err(unresolved_archived_sidecar_error(
                    "session-name",
                    &sidecar.path,
                    key,
                ));
            }
        }
    }
    Ok(())
}

fn verify_archived_hidden_visibility(
    current: &BTreeSet<String>,
    archived: &[ArchivedSidecar<BTreeSet<String>>],
) -> Result<(), String> {
    for sidecar in archived {
        for key in &sidecar.value {
            if !current.contains(key) {
                return Err(unresolved_archived_sidecar_error(
                    "hidden-session",
                    &sidecar.path,
                    key,
                ));
            }
        }
    }
    Ok(())
}

fn unresolved_archived_sidecar_error(label: &str, path: &Path, key: &str) -> String {
    format!(
        "previous-stable {label} sidecar {} contains key {key:?} that is absent from SQLite; the old best-effort write may have failed, so automatic reconciliation is blocked, the sidecar is preserved, and no completion marker was written",
        path.display()
    )
}

fn verify_archived_sidecar_sources<T>(sources: &[ArchivedSidecar<T>]) -> Result<(), String> {
    for source in sources {
        verify_file_unchanged(&source.path, &source.bytes)?;
    }
    Ok(())
}

fn archive_sidecar(path: &Path, expected: &[u8]) -> Result<(), String> {
    verify_file_unchanged(path, expected)?;
    let mut destination = path.with_extension("json.migrated");
    for index in 1.. {
        verify_file_unchanged(path, expected)?;
        match fs::hard_link(path, &destination) {
            Ok(()) => {
                finish_linked_archive(path, &destination, expected, "legacy sidecar")?;
                return Ok(());
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => {
                return Err(format!(
                    "archive legacy sidecar {} to {} without replacing existing data: {error}",
                    path.display(),
                    destination.display()
                ))
            }
        }
        destination = path.with_extension(format!("json.migrated-{index}"));
    }
    unreachable!()
}

fn finish_linked_archive(
    source: &Path,
    destination: &Path,
    expected: &[u8],
    label: &str,
) -> Result<(), String> {
    let archived = read_regular_file_no_follow_bounded(
        destination,
        u64::try_from(expected.len()).unwrap_or(u64::MAX),
    )
    .map_err(|error| {
        format!(
            "verify linked {label} archive {}: {error}; source was preserved",
            destination.display()
        )
    })?;
    if archived != expected {
        return Err(format!(
            "linked {label} archive {} differs from source snapshot; both paths were preserved",
            destination.display()
        ));
    }
    if regular_file_identity(source)? != regular_file_identity(destination)? {
        return Err(format!(
            "linked {label} archive {} no longer identifies the selected source {}; both paths were preserved",
            destination.display(),
            source.display()
        ));
    }
    // Make the new durable name reach disk before retiring the active name. A crash or injected
    // failure between these operations leaves two hard links to the same exact bytes, which is a
    // safe, retryable state.
    sync_parent(destination)?;
    migration_failpoint("after-archive-link")?;
    verify_file_unchanged(source, expected)?;
    if regular_file_identity(source)? != regular_file_identity(destination)? {
        return Err(format!(
            "{label} source identity changed before retirement {}; both paths were preserved",
            source.display()
        ));
    }
    fs::remove_file(source).map_err(|error| {
        format!(
            "retire linked {label} source {} after creating {}: {error}",
            source.display(),
            destination.display()
        )
    })?;
    sync_parent(source)?;
    migration_failpoint("after-archive-unlink")?;
    Ok(())
}

#[cfg(unix)]
fn regular_file_identity(path: &Path) -> Result<(u64, u64), String> {
    use std::os::unix::fs::MetadataExt;

    let mut options = OpenOptions::new();
    options.read(true);
    use std::os::unix::fs::OpenOptionsExt;
    options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .map_err(|error| format!("open regular file identity {}: {error}", path.display()))?;
    let metadata = file
        .metadata()
        .map_err(|error| format!("inspect regular file identity {}: {error}", path.display()))?;
    if !metadata.file_type().is_file() {
        return Err(format!("path is not a regular file: {}", path.display()));
    }
    Ok((metadata.dev(), metadata.ino()))
}

#[cfg(not(unix))]
fn regular_file_identity(_path: &Path) -> Result<(u64, u64), String> {
    Err("legacy archival identity checks are unsupported on this platform".to_string())
}

fn verify_imported_records(
    conn: &rusqlite::Connection,
    records: &[LegacyRecord],
) -> Result<(), String> {
    for record in records {
        let loaded = crate::store_sqlite::load_one(conn, record.kind, &record.id).map_err(|e| {
            format!(
                "verify imported {:?} {} from {}: {e}",
                record.kind,
                record.id,
                record.path.display()
            )
        })?;
        let loaded = loaded.ok_or_else(|| {
            format!(
                "verify imported {:?} {} from {}: row missing after commit",
                record.kind,
                record.id,
                record.path.display()
            )
        })?;
        let canonical =
            canonical_typed_record(record.kind, &record.id, &loaded, true).map_err(|error| {
                format!(
                    "verify imported {:?} {} from {}: {error}",
                    record.kind,
                    record.id,
                    record.path.display()
                )
            })?;
        if canonical != record.canonical {
            return Err(format!(
                "verify imported {:?} {} from {}: canonical readback differs from source",
                record.kind,
                record.id,
                record.path.display()
            ));
        }
    }
    let foreign_key_errors: i64 = conn
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|e| format!("verify imported foreign keys: {e}"))?;
    if foreign_key_errors != 0 {
        return Err(format!(
            "verify imported foreign keys: {foreign_key_errors} violation(s)"
        ));
    }
    let quick_check: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|e| format!("verify imported database: {e}"))?;
    if quick_check != "ok" {
        return Err(format!("verify imported database: {quick_check}"));
    }
    Ok(())
}

fn verify_records_equal_database(
    conn: &rusqlite::Connection,
    records: &[LegacyRecord],
) -> Result<(), String> {
    verify_imported_records(conn, records).map_err(|error| {
        format!("post-completion legacy JSON diverges from SQLite; refusing overwrite: {error}")
    })
}

fn verify_source_snapshot(records: &[LegacyRecord]) -> Result<(), String> {
    for record in records {
        verify_file_unchanged(&record.path, &record.bytes)?;
    }
    Ok(())
}

fn verify_active_record_set_unchanged(
    paths: &AppPaths,
    records: &[LegacyRecord],
) -> Result<(), String> {
    let actual = collect_active_record_paths(paths)?;
    let expected = records
        .iter()
        .filter(|record| record.path.parent() == Some(paths.record_dir(record.kind).as_path()))
        .map(|record| (record.kind, record.id.clone(), record.path.clone()))
        .collect::<Vec<_>>();
    if actual != expected {
        return Err(
            "the active legacy record set changed during import; retry required".to_string(),
        );
    }
    Ok(())
}

fn verify_file_unchanged(path: &Path, expected: &[u8]) -> Result<(), String> {
    let actual = read_regular_file_no_follow_bounded(
        path,
        u64::try_from(expected.len()).unwrap_or(u64::MAX),
    )
    .map_err(|e| {
        format!(
            "re-read legacy source {} before archive: {e}",
            path.display()
        )
    })?;
    if actual != expected {
        return Err(format!(
            "legacy source {} changed during import; retry required",
            path.display()
        ));
    }
    Ok(())
}

fn completed_database_connection(
    base: &Path,
) -> Result<std::sync::Arc<std::sync::Mutex<rusqlite::Connection>>, String> {
    if !path_is_regular_file_no_follow(&crate::db::db_path(base)).map_err(|error| {
        format!(
            "inspect completed SQLite authority {}: {error}",
            crate::db::db_path(base).display()
        )
    })? {
        return Err(format!(
            "legacy import marker exists but {} is missing; refusing empty-store startup",
            crate::db::DB_FILENAME
        ));
    }
    crate::db::conn_for_migration(base).map_err(|e| e.to_string())
}

fn ensure_database_integrity(conn: &rusqlite::Connection, context: &str) -> Result<(), String> {
    let check: String = conn
        .query_row("PRAGMA quick_check", [], |row| row.get(0))
        .map_err(|e| format!("check {context}: {e}"))?;
    if check != "ok" {
        return Err(format!("check {context}: {check}"));
    }
    let foreign_key_errors: i64 = conn
        .query_row("SELECT COUNT(*) FROM pragma_foreign_key_check", [], |row| {
            row.get(0)
        })
        .map_err(|e| format!("check {context} foreign keys: {e}"))?;
    if foreign_key_errors != 0 {
        return Err(format!(
            "check {context} foreign keys: {foreign_key_errors} violation(s)"
        ));
    }
    Ok(())
}

/// Promotion is exceptional and may retire the only legacy source. Temporarily elevate the cached
/// WAL connection from the normal runtime policy to FULL so the commit record itself is synced
/// before a completion marker or rename can become durable.
fn set_full_durability(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.pragma_update(None, "synchronous", "FULL")
        .map_err(|e| format!("enable FULL durability for local-data promotion: {e}"))
}

fn restore_normal_durability(conn: &rusqlite::Connection) -> Result<(), String> {
    conn.pragma_update(None, "synchronous", "NORMAL")
        .map_err(|e| format!("restore NORMAL durability after local-data promotion: {e}"))
}

/// `wal_checkpoint(FULL)` can return successfully with `busy != 0`; that is not sufficient for
/// source retirement. Require every frame present at the checkpoint to have reached the database.
fn checkpoint_fully(conn: &rusqlite::Connection) -> Result<(), String> {
    let (busy, log_frames, checkpointed): (i64, i64, i64) = conn
        .query_row("PRAGMA wal_checkpoint(FULL)", [], |row| {
            Ok((row.get(0)?, row.get(1)?, row.get(2)?))
        })
        .map_err(|e| format!("checkpoint promoted local database: {e}"))?;
    if busy != 0 || checkpointed != log_frames {
        return Err(format!(
            "checkpoint promoted local database was incomplete (busy={busy}, log_frames={log_frames}, checkpointed={checkpointed}); legacy sources left active"
        ));
    }
    ensure_database_integrity(conn, "checkpointed local database")
}

fn validate_completion_marker(base: &Path) -> Result<bool, String> {
    validate_named_marker(
        base,
        COMPLETION_MARKER,
        COMPLETION_MARKER_BODY,
        "legacy import",
    )
}

fn validate_named_marker(
    base: &Path,
    name: &str,
    expected_body: &[u8],
    label: &str,
) -> Result<bool, String> {
    let path = base.join(name);
    let metadata = match fs::symlink_metadata(&path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
        Err(error) => {
            return Err(format!(
                "inspect {label} marker {}: {error}",
                path.display()
            ))
        }
    };
    if !metadata.file_type().is_file() {
        return Err(format!(
            "{label} marker {} is not a regular file; refusing to follow or replace it",
            path.display()
        ));
    }
    match read_regular_file_no_follow_bounded(
        &path,
        u64::try_from(expected_body.len()).unwrap_or(u64::MAX),
    ) {
        Ok(bytes) if bytes == expected_body => Ok(true),
        Ok(_) => Err(format!(
            "{label} marker {} is invalid; refusing to guess migration state",
            path.display()
        )),
        Err(error) => Err(format!(
            "{label} marker {} is invalid: {error}; refusing to guess migration state",
            path.display()
        )),
    }
}

fn read_regular_file_no_follow(path: &Path) -> std::io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is not a regular file",
        ));
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(bytes)
}

fn read_regular_file_no_follow_bounded(path: &Path, max_bytes: u64) -> std::io::Result<Vec<u8>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options.open(path)?;
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is not a regular file",
        ));
    }
    if metadata.len() > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file exceeds its byte limit",
        ));
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take(max_bytes.saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > max_bytes {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "file grew beyond its byte limit while being read",
        ));
    }
    Ok(bytes)
}

fn path_is_regular_file_no_follow(path: &Path) -> std::io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_file() => Ok(true),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is not a regular file",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn path_is_directory_no_follow(path: &Path) -> std::io::Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_dir() => Ok(true),
        Ok(_) => Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is not a directory",
        )),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

fn write_completion_marker(base: &Path) -> Result<(), String> {
    write_named_marker(
        base,
        COMPLETION_MARKER,
        COMPLETION_MARKER_BODY,
        "legacy import",
    )
}

fn write_named_marker(base: &Path, name: &str, body: &[u8], label: &str) -> Result<(), String> {
    if validate_named_marker(base, name, body, label)? {
        return Ok(());
    }
    static NEXT_TEMP: AtomicU64 = AtomicU64::new(0);
    let (temp, mut file) = loop {
        let serial = NEXT_TEMP.fetch_add(1, Ordering::Relaxed);
        let candidate = base.join(format!(".{name}.tmp.{}.{}", std::process::id(), serial));
        match open_owner_only(&candidate, true) {
            Ok(file) => break (candidate, file),
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => {
                return Err(format!(
                    "create {label} marker temp {}: {error}",
                    candidate.display()
                ))
            }
        }
    };
    file.write_all(body)
        .map_err(|e| format!("write {label} marker temp {}: {e}", temp.display()))?;
    file.sync_all()
        .map_err(|e| format!("sync {label} marker temp {}: {e}", temp.display()))?;
    let marker = base.join(name);
    match fs::hard_link(&temp, &marker) {
        Ok(()) => {}
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let validation = validate_named_marker(base, name, body, label);
            let cleanup = fs::remove_file(&temp).map_err(|remove_error| {
                format!(
                    "remove unused {label} marker temp {} after collision: {remove_error}",
                    temp.display()
                )
            });
            match (validation, cleanup) {
                (Ok(true), Ok(())) => return Ok(()),
                (Ok(false), Ok(())) => {
                    return Err(format!(
                        "{label} marker disappeared during no-clobber publication; retry required"
                    ))
                }
                (Err(validation_error), Ok(())) => return Err(validation_error),
                (_, Err(cleanup_error)) => return Err(cleanup_error),
            }
        }
        Err(error) => {
            return Err(format!(
                "publish {label} marker {} to {} without replacing existing state: {error}",
                temp.display(),
                marker.display()
            ))
        }
    }
    sync_dir(base)?;
    fs::remove_file(&temp).map_err(|e| {
        format!(
            "remove published {label} marker temp {}: {e}",
            temp.display()
        )
    })?;
    sync_dir(base)?;
    Ok(())
}

fn open_owner_only(path: &Path, create_new: bool) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    if create_new {
        options.create_new(true);
    } else {
        options.create(true);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // O_NONBLOCK prevents a hostile/stale FIFO at the lock path from hanging startup before
        // the descriptor can be classified. It has no behavioral effect on ordinary files.
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
        options.mode(0o600);
    }
    let file = options.open(path)?;
    if !file.metadata()?.file_type().is_file() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "path is not a regular file",
        ));
    }
    Ok(file)
}

fn sync_parent(path: &Path) -> Result<(), String> {
    if let Some(parent) = path.parent() {
        sync_dir(parent)?;
    }
    Ok(())
}

fn sync_dir(path: &Path) -> Result<(), String> {
    #[cfg(unix)]
    {
        let mut options = OpenOptions::new();
        options.read(true);
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_DIRECTORY);
        options
            .open(path)
            .and_then(|dir| dir.sync_all())
            .map_err(|e| format!("sync directory {}: {e}", path.display()))?;
    }
    Ok(())
}

fn collect_active_record_paths(
    paths: &AppPaths,
) -> Result<Vec<(RecordKind, String, PathBuf)>, String> {
    collect_record_paths_from_roots(paths, &[], true)
}

fn collect_recovery_and_active_record_paths(
    paths: &AppPaths,
) -> Result<Vec<(RecordKind, String, PathBuf)>, String> {
    let roots = legacy_backup_roots(paths.base())?;
    collect_record_paths_from_roots(paths, &roots, true)
}

/// Return every archived record rather than the newest path for each id. The previous-stable
/// importer could skip one generation and a later recovery attempt could contain a valid record
/// with the same id; reconciliation must still inspect the skipped bytes.
fn collect_all_archive_record_paths(
    paths: &AppPaths,
) -> Result<Vec<(RecordKind, String, PathBuf)>, String> {
    let roots = legacy_backup_roots(paths.base())?;
    let mut out = Vec::new();
    for kind in MIGRATION_ORDER {
        for root in &roots {
            let mut records = BTreeMap::new();
            collect_json_files(&root.join(kind.dir_name()), *kind, &mut records)?;
            out.extend(records.into_iter().map(|(id, path)| (*kind, id, path)));
        }
    }
    Ok(out)
}

/// The old importer renamed the entire shared `daemon/` directory, even though only
/// `endpoint.json` belonged to its record set. Never silently certify an independently owned JSON
/// file that it made invisible. `remote_access.json` is security-sensitive, so we require a current
/// owner-managed replacement rather than restoring an old `enabled=true` flag automatically.
fn inspect_archived_shared_daemon_authority(
    paths: &AppPaths,
) -> Result<Vec<ArchivedIndependentFile>, String> {
    let mut archived = Vec::new();
    for root in legacy_backup_roots(paths.base())? {
        let daemon = root.join(RecordKind::DaemonEndpoint.dir_name());
        match path_is_directory_no_follow(&daemon) {
            Ok(false) => continue,
            Ok(true) => {}
            Err(error) => {
                return Err(format!(
                    "inspect previous-stable shared daemon archive {}: {error}",
                    daemon.display()
                ))
            }
        }
        let entries = match fs::read_dir(&daemon) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => {
                return Err(format!(
                    "inspect previous-stable shared daemon archive {}: {error}",
                    daemon.display()
                ))
            }
        };
        for entry in entries {
            let entry = entry.map_err(|error| {
                format!(
                    "inspect previous-stable shared daemon archive {}: {error}",
                    daemon.display()
                )
            })?;
            let path = entry.path();
            if path.extension().and_then(|extension| extension.to_str()) != Some("json") {
                continue;
            }
            let name = path.file_name().and_then(|name| name.to_str());
            if name == Some("endpoint.json") {
                continue;
            }
            if !entry
                .file_type()
                .map_err(|error| {
                    format!(
                        "inspect previous-stable independent daemon archive {}: {error}",
                        path.display()
                    )
                })?
                .is_file()
            {
                return Err(format!(
                    "previous-stable independent daemon archive is not a regular file: {}; automatic reconciliation is blocked",
                    path.display()
                ));
            }
            let bytes = read_regular_file_no_follow(&path).map_err(|error| {
                format!(
                    "read previous-stable independent daemon archive {}: {error}; no completion marker was written",
                    path.display()
                )
            })?;
            archived.push(ArchivedIndependentFile { path, bytes });
        }
    }
    archived.sort_by(|left, right| left.path.cmp(&right.path));
    let mut unresolved = false;
    let mut checked_active = BTreeSet::new();
    for file in &archived {
        let Some(name) = file.path.file_name() else {
            unresolved = true;
            continue;
        };
        let active = paths.daemon_dir().join(name);
        if !checked_active.insert(active.clone()) {
            continue;
        }
        match fs::symlink_metadata(&active) {
            Ok(metadata) if metadata.file_type().is_file() => {
                // Prove a current owner-managed authority is readable, but do not interpret or
                // overwrite an independently versioned contract.
                read_regular_file_no_follow(&active).map_err(|error| {
                    format!(
                        "read current independent daemon authority {}: {error}; archived bytes were preserved and no completion marker was written",
                        active.display()
                    )
                })?;
            }
            Ok(_) => {
                return Err(format!(
                    "current independent daemon authority is not a regular file: {}; archived bytes were preserved and no completion marker was written",
                    active.display()
                ));
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => unresolved = true,
            Err(error) => {
                return Err(format!(
                    "inspect current independent daemon authority {}: {error}; archived bytes were preserved and no completion marker was written",
                    active.display()
                ));
            }
        }
    }
    if unresolved {
        write_named_marker(
            paths.base(),
            INDEPENDENT_RECONCILIATION_NOTICE,
            INDEPENDENT_RECONCILIATION_NOTICE_BODY,
            "independent legacy-data reconciliation notice",
        )?;
        ensure_owner_only_notice(&paths.base().join(INDEPENDENT_RECONCILIATION_NOTICE))?;
        eprintln!(
            "local data migration: archived independently owned daemon JSON was preserved but has no current owner-managed authority; remote access remains fail-closed and must be explicitly reconfigured"
        );
    }
    Ok(archived)
}

fn verify_archived_independent_files(files: &[ArchivedIndependentFile]) -> Result<(), String> {
    for file in files {
        verify_file_unchanged(&file.path, &file.bytes)?;
    }
    Ok(())
}

fn ensure_owner_only_notice(path: &Path) -> Result<(), String> {
    let mut options = OpenOptions::new();
    options.read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|error| format!("open independent reconciliation notice: {error}"))?;
    if !file
        .metadata()
        .map_err(|error| format!("inspect independent reconciliation notice: {error}"))?
        .file_type()
        .is_file()
    {
        return Err("independent reconciliation notice is not a regular file".to_string());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .map_err(|error| format!("secure independent reconciliation notice: {error}"))?;
    }
    file.sync_all()
        .map_err(|error| format!("sync independent reconciliation notice: {error}"))?;
    sync_parent(path)
}

fn collect_record_paths_from_roots(
    paths: &AppPaths,
    archive_roots: &[PathBuf],
    include_active: bool,
) -> Result<Vec<(RecordKind, String, PathBuf)>, String> {
    let mut selected: Vec<(RecordKind, BTreeMap<String, PathBuf>)> = MIGRATION_ORDER
        .iter()
        .copied()
        .map(|kind| (kind, BTreeMap::new()))
        .collect();
    for root in archive_roots {
        for (kind, records) in &mut selected {
            collect_json_files(&root.join(kind.dir_name()), *kind, records)?;
        }
    }
    if include_active {
        for (kind, records) in &mut selected {
            collect_json_files(&paths.record_dir(*kind), *kind, records)?;
        }
    }
    Ok(selected
        .into_iter()
        .flat_map(|(kind, records)| records.into_iter().map(move |(id, path)| (kind, id, path)))
        .collect())
}

fn collect_json_files(
    dir: &Path,
    kind: RecordKind,
    out: &mut BTreeMap<String, PathBuf>,
) -> Result<(), String> {
    match path_is_directory_no_follow(dir) {
        Ok(false) => return Ok(()),
        Ok(true) => {}
        Err(error) => {
            return Err(format!(
                "legacy {:?} directory is not a real directory: {}: {error}",
                kind,
                dir.display()
            ))
        }
    }
    let entries = match fs::read_dir(dir) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(format!("read legacy directory {}: {error}", dir.display())),
    };
    for entry in entries {
        let entry = entry.map_err(|e| format!("read legacy directory {}: {e}", dir.display()))?;
        let path = entry.path();
        let file_type = entry
            .file_type()
            .map_err(|e| format!("inspect legacy path {}: {e}", path.display()))?;
        if path.extension().and_then(|ext| ext.to_str()) != Some("json") {
            continue;
        }
        if !file_type.is_file() {
            return Err(format!(
                "legacy {:?} JSON path is not a regular file: {}",
                kind,
                path.display()
            ));
        }
        let id = path
            .file_stem()
            .and_then(|stem| stem.to_str())
            .ok_or_else(|| {
                format!(
                    "legacy {:?} filename is not valid UTF-8: {}",
                    kind,
                    path.display()
                )
            })?;
        // `daemon/` is a shared app-support directory, not an exclusive record-kind
        // directory.  Only `endpoint.json` belongs to the SQLite-backed
        // `DaemonEndpoint` kind; files such as `remote_access.json` have their own
        // independently versioned ownership protocol and must remain byte-for-byte in
        // place.  Treating every JSON file in this one directory as an endpoint would
        // make an enabled remote installation fail migration (or, with a permissive
        // mapper, archive unrelated authority).
        if kind == RecordKind::DaemonEndpoint && id != crate::daemon_endpoint::ENDPOINT_ID {
            continue;
        }
        crate::ids::validate_id(id).map_err(|e| {
            format!(
                "legacy {:?} id from {} is invalid: {e}",
                kind,
                path.display()
            )
        })?;
        out.insert(id.to_string(), path);
    }
    Ok(())
}

fn legacy_backup_roots(base: &Path) -> Result<Vec<PathBuf>, String> {
    let entries = match fs::read_dir(base) {
        Ok(entries) => entries,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(format!("read migration base {}: {error}", base.display())),
    };
    let mut roots = BTreeMap::<u64, PathBuf>::new();
    for entry in entries {
        let entry = entry.map_err(|e| format!("read migration base {}: {e}", base.display()))?;
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let generation = if name == LEGACY_BACKUP_PREFIX {
            Some(0_u64)
        } else {
            name.strip_prefix("legacy-json-")
                .and_then(|suffix| suffix.parse::<u64>().ok())
        };
        if let Some(generation) = generation {
            if !entry
                .file_type()
                .map_err(|e| format!("inspect migration backup {}: {e}", entry.path().display()))?
                .is_dir()
            {
                return Err(format!(
                    "legacy archive generation is not a real directory: {}",
                    entry.path().display()
                ));
            }
            if let Some(previous) = roots.insert(generation, entry.path()) {
                return Err(format!(
                    "ambiguous legacy archive generation {generation}: {} and {}",
                    previous.display(),
                    roots[&generation].display()
                ));
            }
        }
    }
    Ok(roots.into_values().collect())
}

fn archive_imported_active_record_files(
    paths: &AppPaths,
    records: &[LegacyRecord],
) -> Result<(), String> {
    let active = records
        .iter()
        .filter(|record| record.path.parent() == Some(paths.record_dir(record.kind).as_path()))
        .collect::<Vec<_>>();
    if active.is_empty() {
        return Ok(());
    }
    let backup_root = unique_backup_dir(paths.base())?;
    fs::create_dir(&backup_root)
        .map_err(|e| format!("create legacy archive {}: {e}", backup_root.display()))?;
    // Persist the new generation before moving any source into it.
    sync_dir(paths.base())?;
    for record in active {
        // A legacy writer can predate this migration lock. Re-check immediately before moving so
        // a post-marker change remains active for the marker+active retry path.
        verify_file_unchanged(&record.path, &record.bytes)?;
        let destination_dir = backup_root.join(record.kind.dir_name());
        match fs::create_dir(&destination_dir) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                if !path_is_directory_no_follow(&destination_dir).map_err(|inspect_error| {
                    format!(
                        "inspect legacy archive {} after collision: {inspect_error}",
                        destination_dir.display()
                    )
                })? {
                    return Err(format!(
                        "legacy archive directory disappeared after collision: {}",
                        destination_dir.display()
                    ));
                }
            }
            Err(error) => {
                return Err(format!(
                    "create legacy archive {}: {error}",
                    destination_dir.display()
                ))
            }
        }
        // `destination_dir` is a directory entry in `backup_root`; syncing only the child does not
        // make that parent entry durable.
        sync_dir(&backup_root)?;
        let name = record
            .path
            .file_name()
            .ok_or_else(|| format!("legacy source has no filename: {}", record.path.display()))?;
        let destination = destination_dir.join(name);
        fs::hard_link(&record.path, &destination).map_err(|error| {
            format!(
                "archive legacy record {} to {} without replacing existing data: {error}",
                record.path.display(),
                destination.display()
            )
        })?;
        finish_linked_archive(&record.path, &destination, &record.bytes, "legacy record")?;
        sync_dir(&destination_dir)?;
    }
    sync_dir(&backup_root)?;
    sync_dir(paths.base())?;
    Ok(())
}

/// Invert every project's `window_order` into a window_id → project_id map. Two different
/// projects claiming one window is corrupted durable ownership, not an ordering tie to resolve.
fn window_owner_map(
    projects: Option<&Vec<(String, Value)>>,
) -> Result<HashMap<String, String>, String> {
    let mut map = HashMap::new();
    let Some(projects) = projects else {
        return Ok(map);
    };
    for (project_id, value) in projects {
        if let Some(order) = value.get("window_order").and_then(Value::as_array) {
            for window in order {
                if let Some(window_id) = window.as_str() {
                    if let Some(existing) = map.get(window_id) {
                        if existing != project_id {
                            return Err(format!(
                                "legacy window {window_id:?} has duplicate project ownership: {existing:?} and {project_id:?}; automatic migration is blocked"
                            ));
                        }
                    } else {
                        map.insert(window_id.to_string(), project_id.clone());
                    }
                }
            }
        }
    }
    Ok(map)
}

fn unique_backup_dir(base: &Path) -> Result<PathBuf, String> {
    let first = base.join(LEGACY_BACKUP_PREFIX);
    if !first.exists() {
        return Ok(first);
    }

    // Never reuse a numeric gap. Recovery processes generations in numeric order, so putting a
    // newer snapshot into a missing lower suffix would let an older higher suffix overwrite it.
    let mut maximum = 0_u64;
    let entries = fs::read_dir(base)
        .map_err(|error| format!("read migration base {}: {error}", base.display()))?;
    for entry in entries {
        let entry =
            entry.map_err(|error| format!("read migration base {}: {error}", base.display()))?;
        if !entry
            .file_type()
            .map_err(|error| {
                format!(
                    "inspect migration backup {}: {error}",
                    entry.path().display()
                )
            })?
            .is_dir()
        {
            continue;
        }
        let Some(name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        if let Some(suffix) = name.strip_prefix("legacy-json-") {
            if let Ok(generation) = suffix.parse::<u64>() {
                maximum = maximum.max(generation);
            }
        }
    }
    let next = maximum
        .checked_add(1)
        .ok_or_else(|| "legacy archive generation overflow".to_string())?;
    let candidate = base.join(format!("{LEGACY_BACKUP_PREFIX}-{next}"));
    if candidate.exists() {
        return Err(format!(
            "next legacy archive generation already exists: {}",
            candidate.display()
        ));
    }
    Ok(candidate)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{Project, Workspace, WorkspaceConsent};
    use tempfile::TempDir;

    struct MigrationFailpointGuard;

    impl MigrationFailpointGuard {
        fn install(stage: &'static str) -> Self {
            ACTIVE_MIGRATION_FAILPOINT.with(|active| {
                assert!(active.borrow().is_none(), "nested migration failpoint");
                *active.borrow_mut() = Some(stage);
            });
            Self
        }
    }

    impl Drop for MigrationFailpointGuard {
        fn drop(&mut self) {
            ACTIVE_MIGRATION_FAILPOINT.with(|active| *active.borrow_mut() = None);
        }
    }

    struct MigrationTestHookGuard {
        _serial: std::sync::MutexGuard<'static, ()>,
    }

    impl MigrationTestHookGuard {
        fn install(hook: MigrationTestHook) -> Self {
            let serial = MIGRATION_TEST_HOOK_SERIAL
                .get_or_init(|| std::sync::Mutex::new(()))
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let mut slot = MIGRATION_TEST_HOOK
                .get_or_init(|| std::sync::Mutex::new(None))
                .lock()
                .unwrap();
            assert!(slot.is_none(), "nested migration test hook");
            *slot = Some(hook);
            drop(slot);
            Self { _serial: serial }
        }
    }

    impl Drop for MigrationTestHookGuard {
        fn drop(&mut self) {
            *MIGRATION_TEST_HOOK
                .get_or_init(|| std::sync::Mutex::new(None))
                .lock()
                .unwrap() = None;
        }
    }

    fn base_paths(tmp: &TempDir) -> AppPaths {
        AppPaths::with_base(tmp.path().join("Maestro"))
    }

    fn write_legacy<T: serde::Serialize>(paths: &AppPaths, kind: RecordKind, id: &str, record: &T) {
        let dir = paths.record_dir(kind);
        fs::create_dir_all(&dir).unwrap();
        let env = Envelope::new(kind.schema(), 1, record);
        fs::write(
            paths.record_path(kind, id).unwrap(),
            env.to_json_bytes().unwrap(),
        )
        .unwrap();
    }

    fn write_legacy_value(paths: &AppPaths, kind: RecordKind, id: &str, record: Value) -> PathBuf {
        let dir = paths.record_dir(kind);
        fs::create_dir_all(&dir).unwrap();
        let path = paths.record_path(kind, id).unwrap();
        let env = Envelope::new(kind.schema(), 1, record);
        fs::write(&path, env.to_json_bytes().unwrap()).unwrap();
        path
    }

    fn legacy_snapshot_survives(paths: &AppPaths, filename: &str, expected: &[u8]) -> bool {
        let mut candidates = Vec::new();
        for kind in MIGRATION_ORDER {
            candidates.push(paths.record_dir(*kind).join(filename));
        }
        for root in legacy_backup_roots(paths.base()).unwrap_or_default() {
            for kind in MIGRATION_ORDER {
                candidates.push(root.join(kind.dir_name()).join(filename));
            }
        }
        candidates
            .into_iter()
            .any(|path| read_regular_file_no_follow(&path).ok().as_deref() == Some(expected))
    }

    fn sidecar_snapshot_survives(dashboard: &Path, prefix: &str, expected: &[u8]) -> bool {
        fs::read_dir(dashboard)
            .into_iter()
            .flatten()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_name().to_string_lossy().starts_with(prefix))
            .any(|entry| {
                read_regular_file_no_follow(&entry.path()).ok().as_deref() == Some(expected)
            })
    }

    fn project(id: &str, window_order: Vec<String>) -> Project {
        Project {
            project_id: id.into(),
            name: id.into(),
            root: "/r".into(),
            default_workspace_policy: crate::policy::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: None,
            directories: Vec::new(),
            window_order,
            system: false,
            hidden: false,
        }
    }

    fn workspace() -> Workspace {
        Workspace {
            workspace_id: "ws1".into(),
            project_id: "p1".into(),
            root: "/r".into(),
            policy: crate::policy::WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        }
    }

    fn write_previous_stable_archive<T: serde::Serialize>(
        paths: &AppPaths,
        kind: RecordKind,
        id: &str,
        record: &T,
    ) -> PathBuf {
        let dir = paths
            .base()
            .join(LEGACY_BACKUP_PREFIX)
            .join(kind.dir_name());
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join(format!("{id}.json"));
        let env = Envelope::new(kind.schema(), 1, record);
        fs::write(&path, env.to_json_bytes().unwrap()).unwrap();
        path
    }

    #[test]
    fn migrates_json_then_archives_and_marks_completion() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        write_legacy(&paths, RecordKind::Project, "p1", &project("p1", vec![]));
        write_legacy(&paths, RecordKind::Workspace, "ws1", &workspace());

        let report = migrate_json_to_sqlite(&paths).unwrap();
        assert_eq!(report.migrated, 2);
        assert!(!report.already_done);
        assert_eq!(
            crate::store::load_all::<Project>(&paths, RecordKind::Project)
                .unwrap()
                .len(),
            1
        );
        assert!(paths.base().join(COMPLETION_MARKER).exists());
        assert!(!paths
            .record_path(RecordKind::Project, "p1")
            .unwrap()
            .exists());
        assert!(paths
            .base()
            .join("legacy-json")
            .join("projects")
            .join("p1.json")
            .exists());
        let arc = crate::db::conn_for_migration(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        let synchronous: i64 = conn
            .pragma_query_value(None, "synchronous", |row| row.get(0))
            .unwrap();
        assert_eq!(synchronous, 1, "runtime policy must be restored to NORMAL");
        let (busy, log, checkpointed): (i64, i64, i64) = conn
            .query_row("PRAGMA wal_checkpoint(PASSIVE)", [], |row| {
                Ok((row.get(0)?, row.get(1)?, row.get(2)?))
            })
            .unwrap();
        assert_eq!(busy, 0);
        assert_eq!(
            checkpointed, log,
            "promotion must leave no uncheckpointed frame"
        );
        drop(conn);

        let again = migrate_json_to_sqlite(&paths).unwrap();
        assert!(again.already_done);
        assert_eq!(again.migrated, 0);
    }

    #[test]
    fn unrelated_json_in_shared_daemon_directory_is_never_imported_or_archived() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let remote_access = paths.daemon_dir().join("remote_access.json");
        fs::create_dir_all(paths.daemon_dir()).unwrap();
        let bytes =
            br#"{"schema":"maestro.remote_access","schema_version":1,"record":{"enabled":true}}"#;
        fs::write(&remote_access, bytes).unwrap();
        write_legacy(
            &paths,
            RecordKind::DaemonEndpoint,
            crate::daemon_endpoint::ENDPOINT_ID,
            &crate::daemon_endpoint::DaemonEndpoint::new("/tmp/hydra.sock", Some(42), 7),
        );

        let report = migrate_json_to_sqlite(&paths).unwrap();

        assert_eq!(report.migrated, 1);
        assert_eq!(fs::read(&remote_access).unwrap(), bytes);
        assert!(paths
            .base()
            .join(LEGACY_BACKUP_PREFIX)
            .join("daemon")
            .join("endpoint.json")
            .exists());
        assert!(!paths
            .base()
            .join(LEGACY_BACKUP_PREFIX)
            .join("daemon")
            .join("remote_access.json")
            .exists());
    }

    #[test]
    fn previous_stable_archived_remote_access_stays_closed_and_leaves_durable_notice() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::write_record(
            &paths,
            RecordKind::Project,
            "native",
            1,
            &project("native", vec![]),
        )
        .unwrap();
        let archived = paths
            .base()
            .join(LEGACY_BACKUP_PREFIX)
            .join("daemon")
            .join("remote_access.json");
        fs::create_dir_all(archived.parent().unwrap()).unwrap();
        let bytes =
            br#"{"schema":"maestro.remote_access","schema_version":1,"record":{"enabled":true}}"#;
        fs::write(&archived, bytes).unwrap();

        let report = migrate_json_to_sqlite(&paths).unwrap();

        assert!(report.already_done);
        assert_eq!(fs::read(&archived).unwrap(), bytes);
        assert!(paths.base().join(COMPLETION_MARKER).exists());
        let active = paths.daemon_dir().join("remote_access.json");
        assert!(
            !active.exists(),
            "migration must never reopen remote access"
        );
        let notice = paths.base().join(INDEPENDENT_RECONCILIATION_NOTICE);
        assert_eq!(
            fs::read(&notice).unwrap(),
            INDEPENDENT_RECONCILIATION_NOTICE_BODY
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&notice).unwrap().permissions().mode() & 0o777,
                0o600
            );
        }

        let again = migrate_json_to_sqlite(&paths).unwrap();
        assert!(again.already_done);
        assert_eq!(fs::read(&archived).unwrap(), bytes);
        assert_eq!(
            fs::read(&notice).unwrap(),
            INDEPENDENT_RECONCILIATION_NOTICE_BODY
        );
        assert!(!active.exists());
    }

    #[test]
    fn archived_remote_access_is_reconciled_only_when_current_owner_state_exists() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::write_record(
            &paths,
            RecordKind::Project,
            "native",
            1,
            &project("native", vec![]),
        )
        .unwrap();
        let archived = paths
            .base()
            .join(LEGACY_BACKUP_PREFIX)
            .join("daemon")
            .join("remote_access.json");
        fs::create_dir_all(archived.parent().unwrap()).unwrap();
        let archived_bytes = br#"{"record":{"enabled":true}}"#;
        fs::write(&archived, archived_bytes).unwrap();
        let active = paths.daemon_dir().join("remote_access.json");
        fs::create_dir_all(active.parent().unwrap()).unwrap();
        let active_bytes =
            br#"{"record":{"enabled":false,"desired_enabled":false,"reconcile_epoch":7}}"#;
        fs::write(&active, active_bytes).unwrap();

        let report = migrate_json_to_sqlite(&paths).unwrap();

        assert!(report.already_done);
        assert!(paths.base().join(COMPLETION_MARKER).exists());
        assert_eq!(fs::read(&archived).unwrap(), archived_bytes);
        assert_eq!(fs::read(&active).unwrap(), active_bytes);
        assert!(!paths
            .base()
            .join(INDEPENDENT_RECONCILIATION_NOTICE)
            .exists());
    }

    #[cfg(unix)]
    #[test]
    fn independent_reconciliation_notice_never_follows_a_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::write_record(
            &paths,
            RecordKind::Project,
            "native",
            1,
            &project("native", vec![]),
        )
        .unwrap();
        let archived = paths
            .base()
            .join(LEGACY_BACKUP_PREFIX)
            .join("daemon")
            .join("remote_access.json");
        fs::create_dir_all(archived.parent().unwrap()).unwrap();
        fs::write(&archived, br#"{"record":{"enabled":true}}"#).unwrap();
        let victim = tmp.path().join("victim");
        fs::write(&victim, b"do not replace").unwrap();
        symlink(
            &victim,
            paths.base().join(INDEPENDENT_RECONCILIATION_NOTICE),
        )
        .unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("refusing to follow or replace"));
        assert_eq!(fs::read(&victim).unwrap(), b"do not replace");
        assert_eq!(
            fs::read(&archived).unwrap(),
            br#"{"record":{"enabled":true}}"#
        );
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
    }

    #[cfg(unix)]
    #[test]
    fn migration_lock_never_follows_a_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.base()).unwrap();
        let victim = tmp.path().join("victim-lock-target");
        fs::write(&victim, b"never lock or alter me").unwrap();
        symlink(&victim, paths.base().join(MIGRATION_LOCK)).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("open migration lock"));
        assert_eq!(fs::read(&victim).unwrap(), b"never lock or alter me");
        assert!(!crate::db::db_path(paths.base()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn migration_lock_rejects_a_fifo_without_blocking() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt;

        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.base()).unwrap();
        let lock = paths.base().join(MIGRATION_LOCK);
        let lock_c = CString::new(lock.as_os_str().as_bytes()).unwrap();
        // SAFETY: `lock_c` is a live NUL-terminated path for this call.
        assert_eq!(unsafe { libc::mkfifo(lock_c.as_ptr(), 0o600) }, 0);

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("open migration lock"));
        assert!(!crate::db::db_path(paths.base()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn migration_base_never_follows_a_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let real_base = tmp.path().join("real-base");
        fs::create_dir(&real_base).unwrap();
        let linked_base = tmp.path().join("linked-base");
        symlink(&real_base, &linked_base).unwrap();
        let paths = AppPaths::with_base(&linked_base);

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("migration base must be a real directory"));
        assert!(fs::read_dir(&real_base).unwrap().next().is_none());
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_authority_never_follows_a_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.base()).unwrap();
        let victim = tmp.path().join("external.db");
        let victim_bytes = b"not a database and never opened";
        fs::write(&victim, victim_bytes).unwrap();
        symlink(&victim, crate::db::db_path(paths.base())).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("SQLite authority must be a regular file"));
        assert_eq!(fs::read(&victim).unwrap(), victim_bytes);
    }

    #[cfg(unix)]
    #[test]
    fn legacy_archive_generation_never_follows_a_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.base()).unwrap();
        let external = tmp.path().join("external-archive");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("preserve"), b"preserve").unwrap();
        symlink(&external, paths.base().join(LEGACY_BACKUP_PREFIX)).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("not a real directory"));
        assert_eq!(fs::read(external.join("preserve")).unwrap(), b"preserve");
        assert!(!crate::db::db_path(paths.base()).exists());
    }

    #[cfg(unix)]
    #[test]
    fn active_record_reader_never_follows_a_file_or_parent_symlink() {
        use std::os::unix::fs::symlink;

        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.record_dir(RecordKind::Project)).unwrap();
        let victim = tmp.path().join("victim.json");
        let victim_bytes =
            Envelope::new(RecordKind::Project.schema(), 1, project("victim", vec![]))
                .to_json_bytes()
                .unwrap();
        fs::write(&victim, &victim_bytes).unwrap();
        symlink(
            &victim,
            paths.record_dir(RecordKind::Project).join("victim.json"),
        )
        .unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();
        assert!(error.contains("not a regular file"));
        assert_eq!(fs::read(&victim).unwrap(), victim_bytes);
        assert!(!crate::db::db_path(paths.base()).exists());

        let tmp_parent = TempDir::new().unwrap();
        let parent_paths = base_paths(&tmp_parent);
        fs::create_dir_all(parent_paths.base()).unwrap();
        let external = tmp_parent.path().join("external-projects");
        fs::create_dir(&external).unwrap();
        fs::write(external.join("p1.json"), b"do not read through parent").unwrap();
        symlink(&external, parent_paths.record_dir(RecordKind::Project)).unwrap();

        let error = migrate_json_to_sqlite(&parent_paths).unwrap_err();
        assert!(error.contains("not a real directory"));
        assert_eq!(
            fs::read(external.join("p1.json")).unwrap(),
            b"do not read through parent"
        );
        assert!(!crate::db::db_path(parent_paths.base()).exists());
    }

    #[test]
    fn existing_database_file_does_not_suppress_pending_legacy_import() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let _ = crate::db::conn_for(paths.base()).unwrap();
        assert!(crate::db::db_path(paths.base()).exists());
        write_legacy(&paths, RecordKind::Project, "p1", &project("p1", vec![]));

        let report = migrate_json_to_sqlite(&paths).unwrap();
        assert_eq!(report.migrated, 1);
        assert_eq!(
            crate::store::load_all::<Project>(&paths, RecordKind::Project)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn unmarked_sqlite_divergence_never_overwrites_active_or_database_authority() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let mut current = project("p1", vec![]);
        current.name = "newer SQLite".into();
        crate::store::write_record(&paths, RecordKind::Project, "p1", 1, &current).unwrap();
        assert!(!paths.base().join(COMPLETION_MARKER).exists());

        let mut stale = current.clone();
        stale.name = "stale active JSON".into();
        write_legacy(&paths, RecordKind::Project, "p1", &stale);
        let source = paths.record_path(RecordKind::Project, "p1").unwrap();
        let source_bytes = fs::read(&source).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("diverges from active legacy JSON"));
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
        let arc = crate::db::conn_for_migration(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        let loaded: Project = serde_json::from_value(
            crate::store_sqlite::load_one(&conn, RecordKind::Project, "p1")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.name, "newer SQLite");
    }

    #[test]
    fn unmarked_nonempty_sqlite_never_resurrects_a_missing_active_record() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::write_record(
            &paths,
            RecordKind::Project,
            "current",
            1,
            &project("current", vec![]),
        )
        .unwrap();
        write_legacy(
            &paths,
            RecordKind::Project,
            "deleted",
            &project("deleted", vec![]),
        );
        let source = paths.record_path(RecordKind::Project, "deleted").unwrap();
        let source_bytes = fs::read(&source).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("may have been deleted"));
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
        let arc = crate::db::conn_for_migration(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        assert!(
            crate::store_sqlite::load_one(&conn, RecordKind::Project, "deleted")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn unmarked_identical_sqlite_row_is_safe_crash_residue() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let record = project("p1", vec![]);
        crate::store::write_record(&paths, RecordKind::Project, "p1", 1, &record).unwrap();
        write_legacy(&paths, RecordKind::Project, "p1", &record);
        let source = paths.record_path(RecordKind::Project, "p1").unwrap();
        let bytes = fs::read(&source).unwrap();

        let report = migrate_json_to_sqlite(&paths).unwrap();

        assert_eq!(report.migrated, 1);
        assert!(paths.base().join(COMPLETION_MARKER).exists());
        assert!(!source.exists());
        assert!(legacy_snapshot_survives(&paths, "p1.json", &bytes));
    }

    #[test]
    fn corrupt_record_fails_closed_without_db_marker_or_archive() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.record_dir(RecordKind::Project)).unwrap();
        let source = paths.record_path(RecordKind::Project, "p1").unwrap();
        fs::write(&source, b"not json").unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();
        assert!(error.contains("parse legacy record"));
        assert!(source.exists(), "legacy authority must remain active");
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
        assert!(!crate::db::db_path(paths.base()).exists());
        assert!(!paths.base().join("legacy-json").exists());
    }

    #[test]
    fn future_version_record_fails_closed_and_remains_authoritative() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.record_dir(RecordKind::Project)).unwrap();
        let source = paths.record_path(RecordKind::Project, "p1").unwrap();
        let raw = serde_json::json!({
            "schema": RecordKind::Project.schema(),
            "schema_version": crate::envelope::SCHEMA_VERSION + 1,
            "written_by": "future",
            "written_at_ms": 1,
            "record": project("p1", vec![]),
        })
        .to_string();
        fs::write(&source, &raw).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();
        assert!(error.contains("newer than supported"));
        assert_eq!(fs::read_to_string(&source).unwrap(), raw);
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
        assert!(!crate::db::db_path(paths.base()).exists());
    }

    #[test]
    fn map_failure_rolls_back_all_rows_and_keeps_sources_active() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        write_legacy(
            &paths,
            RecordKind::Project,
            "good",
            &project("good", vec![]),
        );
        write_legacy(
            &paths,
            RecordKind::Project,
            "bad",
            &serde_json::json!({"project_id":"bad"}),
        );

        let error = migrate_json_to_sqlite(&paths).unwrap_err();
        assert!(error.contains("validate legacy Project bad"));
        assert!(paths
            .record_path(RecordKind::Project, "good")
            .unwrap()
            .exists());
        assert!(paths
            .record_path(RecordKind::Project, "bad")
            .unwrap()
            .exists());
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
        assert!(!crate::db::db_path(paths.base()).exists());
    }

    #[test]
    fn archive_without_database_is_recovered() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let archived = paths.base().join("legacy-json").join("projects");
        fs::create_dir_all(&archived).unwrap();
        let env = Envelope::new(RecordKind::Project.schema(), 1, project("p1", vec![]));
        fs::write(archived.join("p1.json"), env.to_json_bytes().unwrap()).unwrap();

        let report = migrate_json_to_sqlite(&paths).unwrap();
        assert_eq!(report.migrated, 1);
        assert!(paths.base().join(COMPLETION_MARKER).exists());
        assert!(
            archived.join("p1.json").exists(),
            "old archive is never deleted"
        );
    }

    #[test]
    fn pre_marker_archive_never_overwrites_newer_existing_database_state() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let archived = paths.base().join("legacy-json").join("projects");
        fs::create_dir_all(&archived).unwrap();
        let old = project("p1", vec![]);
        let env = Envelope::new(RecordKind::Project.schema(), 1, old);
        fs::write(archived.join("p1.json"), env.to_json_bytes().unwrap()).unwrap();

        let mut current = project("p1", vec![]);
        current.name = "newer sqlite name".into();
        crate::store::write_record(&paths, RecordKind::Project, "p1", 2, &current).unwrap();

        let report = migrate_json_to_sqlite(&paths).unwrap();
        assert!(report.already_done);
        let loaded = crate::store::load_one::<Project>(&paths, RecordKind::Project, "p1")
            .unwrap()
            .unwrap();
        let crate::store::LoadOutcome::Loaded(loaded) = loaded else {
            panic!("project must remain readable")
        };
        assert_eq!(loaded.name, "newer sqlite name");
        assert!(archived.join("p1.json").exists());
        assert!(paths.base().join(COMPLETION_MARKER).exists());
    }

    #[test]
    fn previous_stable_corrupt_skipped_archive_is_never_certified_by_v1_marker() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::write_record(
            &paths,
            RecordKind::Project,
            "imported",
            1,
            &project("imported", vec![]),
        )
        .unwrap();
        let imported_path = write_previous_stable_archive(
            &paths,
            RecordKind::Project,
            "imported",
            &project("imported", vec![]),
        );
        let corrupt_path = paths
            .base()
            .join(LEGACY_BACKUP_PREFIX)
            .join("projects")
            .join("skipped.json");
        let corrupt_bytes = b"previous stable could not parse these bytes";
        fs::write(&corrupt_path, corrupt_bytes).unwrap();
        fs::write(
            paths.base().join(LEGACY_COMPLETION_MARKER),
            LEGACY_COMPLETION_MARKER_BODY,
        )
        .unwrap();
        let imported_bytes = fs::read(&imported_path).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("previous-stable legacy archive reconciliation is blocked"));
        assert!(error.contains("skipped.json"));
        assert_eq!(fs::read(&imported_path).unwrap(), imported_bytes);
        assert_eq!(fs::read(&corrupt_path).unwrap(), corrupt_bytes);
        assert!(paths.base().join(LEGACY_COMPLETION_MARKER).exists());
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
        let arc = crate::db::conn_for_migration(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        assert!(
            crate::store_sqlite::load_one(&conn, RecordKind::Project, "imported")
                .unwrap()
                .is_some()
        );
    }

    #[test]
    fn previous_stable_future_archive_is_preserved_and_blocks_completion() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::write_record(
            &paths,
            RecordKind::Project,
            "current",
            1,
            &project("current", vec![]),
        )
        .unwrap();
        let dir = paths.base().join(LEGACY_BACKUP_PREFIX).join("projects");
        fs::create_dir_all(&dir).unwrap();
        let source = dir.join("future.json");
        let bytes = serde_json::to_vec(&serde_json::json!({
            "schema": RecordKind::Project.schema(),
            "schema_version": crate::envelope::SCHEMA_VERSION + 1,
            "written_by": "previous-stable-fixture",
            "written_at_ms": 1,
            "record": project("future", vec![]),
        }))
        .unwrap();
        fs::write(&source, &bytes).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("newer than supported"));
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
    }

    #[test]
    fn previous_stable_fk_skipped_archive_requires_operator_reconciliation() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::write_record(&paths, RecordKind::Project, "p1", 1, &project("p1", vec![]))
            .unwrap();
        write_previous_stable_archive(&paths, RecordKind::Project, "p1", &project("p1", vec![]));
        let orphan = Workspace {
            workspace_id: "orphan".into(),
            project_id: "missing-parent".into(),
            root: "/preserve-me".into(),
            policy: crate::policy::WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        };
        let source =
            write_previous_stable_archive(&paths, RecordKind::Workspace, "orphan", &orphan);
        let bytes = fs::read(&source).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("absent from SQLite"));
        assert!(error.contains("orphan.json"));
        assert!(error.contains("automatic reconciliation is blocked"));
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
        let arc = crate::db::conn_for_migration(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        assert!(
            crate::store_sqlite::load_one(&conn, RecordKind::Workspace, "orphan")
                .unwrap()
                .is_none()
        );
    }

    #[test]
    fn existing_database_without_legacy_evidence_is_not_given_an_import_marker() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::write_record(
            &paths,
            RecordKind::Project,
            "native",
            1,
            &project("native", vec![]),
        )
        .unwrap();
        fs::write(
            paths.base().join(INDEPENDENT_RECONCILIATION_NOTICE),
            INDEPENDENT_RECONCILIATION_NOTICE_BODY,
        )
        .unwrap();

        let report = migrate_json_to_sqlite(&paths).unwrap();

        assert!(report.already_done);
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(paths.base().join(INDEPENDENT_RECONCILIATION_NOTICE))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn marker_without_database_fails_closed() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.base()).unwrap();
        fs::write(paths.base().join(COMPLETION_MARKER), COMPLETION_MARKER_BODY).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();
        assert!(error.contains("marker exists"));
        assert!(!crate::db::db_path(paths.base()).exists());
    }

    #[test]
    fn invalid_completion_marker_is_never_replaced_or_used() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.base()).unwrap();
        let marker = paths.base().join(COMPLETION_MARKER);
        let invalid = b"foreign or truncated marker bytes";
        fs::write(&marker, invalid).unwrap();
        write_legacy(&paths, RecordKind::Project, "p1", &project("p1", vec![]));
        let source = paths.record_path(RecordKind::Project, "p1").unwrap();
        let source_bytes = fs::read(&source).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("marker") && error.contains("invalid"));
        assert_eq!(fs::read(&marker).unwrap(), invalid);
        assert_eq!(fs::read(&source).unwrap(), source_bytes);
        assert!(!crate::db::db_path(paths.base()).exists());
    }

    #[test]
    fn marker_with_missing_database_never_recovers_only_active_subset() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.base()).unwrap();
        fs::write(paths.base().join(COMPLETION_MARKER), COMPLETION_MARKER_BODY).unwrap();
        write_legacy(
            &paths,
            RecordKind::Project,
            "active",
            &project("active", vec![]),
        );
        let archive = paths.base().join("legacy-json").join("projects");
        fs::create_dir_all(&archive).unwrap();
        let archived = Envelope::new(RecordKind::Project.schema(), 1, project("archived", vec![]));
        fs::write(
            archive.join("archived.json"),
            archived.to_json_bytes().unwrap(),
        )
        .unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();
        assert!(error.contains("refusing partial recovery"));
        assert!(!crate::db::db_path(paths.base()).exists());
        assert!(paths
            .record_path(RecordKind::Project, "active")
            .unwrap()
            .exists());
        assert!(archive.join("archived.json").exists());
    }

    #[test]
    fn typed_validation_rejects_non_array_window_tabs_before_opening_database() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.record_dir(RecordKind::WindowLayout)).unwrap();
        let source = paths
            .record_path(RecordKind::WindowLayout, "window-1")
            .unwrap();
        let envelope = Envelope::new(
            RecordKind::WindowLayout.schema(),
            1,
            serde_json::json!({
                "window_id": "window-1",
                "name": "Unsafe",
                "tabs": "not-an-array"
            }),
        );
        fs::write(&source, envelope.to_json_bytes().unwrap()).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();
        assert!(error.contains("typed record decode failed"));
        assert!(source.exists());
        assert!(!crate::db::db_path(paths.base()).exists());
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
    }

    #[test]
    fn typed_validation_rejects_nested_unknown_project_fields() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let mut value = serde_json::to_value(project("p1", vec![])).unwrap();
        value["launch_defaults"] = serde_json::json!({
            "agent": "claude",
            "model": null,
            "resume_mode": null,
            "dangerous_skip_permissions": false,
            "custom_command": null,
            "future_privileged_flag": true
        });
        value["directories"] = serde_json::json!([{
            "id": "dir-1",
            "name": "Repo",
            "path": "/r",
            "future_mount_authority": "ignored-by-serde"
        }]);
        let source = write_legacy_value(&paths, RecordKind::Project, "p1", value);
        let bytes = fs::read(&source).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("unknown durable field"));
        assert!(
            error.contains("future_privileged_flag") || error.contains("future_mount_authority")
        );
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(!crate::db::db_path(paths.base()).exists());
    }

    #[test]
    fn typed_validation_rejects_nested_unknown_window_tab_fields() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let value = serde_json::json!({
            "window_id": "window-1",
            "name": "Unsafe",
            "tabs": [{
                "tab_id": "tab-1",
                "session_id": "session-1",
                "index": 0,
                "title": "Shell",
                "pinned": false,
                "attention": {
                    "attention": "none",
                    "unseen": false,
                    "since_ms": 0,
                    "source": "process",
                    "future_attention_authority": true
                },
                "split_from": {
                    "tab_id": "tab-parent",
                    "axis": "right",
                    "ratio_per_mille": 500,
                    "future_split_field": "ignored"
                },
                "pane_rect": null,
                "stashed_from": null,
                "stashed": false
            }]
        });
        let source = write_legacy_value(&paths, RecordKind::WindowLayout, "window-1", value);
        let bytes = fs::read(&source).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("unknown durable field"));
        assert!(
            error.contains("future_attention_authority") || error.contains("future_split_field")
        );
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(!crate::db::db_path(paths.base()).exists());
    }

    #[test]
    fn typed_validation_accepts_explicit_null_for_known_skipped_option_fields() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let mut value = serde_json::to_value(project("p1", vec![])).unwrap();
        value["launch_defaults"] = serde_json::json!({
            "agent": null,
            "model": null,
            "resume_mode": null,
            "dangerous_skip_permissions": null,
            "custom_command": null
        });
        write_legacy_value(&paths, RecordKind::Project, "p1", value);

        migrate_json_to_sqlite(&paths).unwrap();

        assert!(paths.base().join(COMPLETION_MARKER).exists());
    }

    #[test]
    fn typed_validation_rejects_filename_and_embedded_id_mismatch() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        write_legacy(
            &paths,
            RecordKind::Project,
            "filename-id",
            &project("embedded-id", vec![]),
        );

        let error = migrate_json_to_sqlite(&paths).unwrap_err();
        assert!(error.contains("embedded id"));
        assert!(!crate::db::db_path(paths.base()).exists());
        assert!(paths
            .record_path(RecordKind::Project, "filename-id")
            .unwrap()
            .exists());
    }

    #[test]
    fn duplicate_window_ownership_blocks_before_database_creation() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        write_legacy(
            &paths,
            RecordKind::Project,
            "p1",
            &project("p1", vec!["window-1".into()]),
        );
        write_legacy(
            &paths,
            RecordKind::Project,
            "p2",
            &project("p2", vec!["window-1".into()]),
        );
        let first = paths.record_path(RecordKind::Project, "p1").unwrap();
        let second = paths.record_path(RecordKind::Project, "p2").unwrap();
        let first_bytes = fs::read(&first).unwrap();
        let second_bytes = fs::read(&second).unwrap();

        let error = migrate_json_to_sqlite(&paths).unwrap_err();

        assert!(error.contains("duplicate project ownership"));
        assert_eq!(fs::read(&first).unwrap(), first_bytes);
        assert_eq!(fs::read(&second).unwrap(), second_bytes);
        assert!(!crate::db::db_path(paths.base()).exists());
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
    }

    #[test]
    fn post_marker_divergent_json_never_overwrites_newer_sqlite() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let mut current = project("p1", vec![]);
        current.name = "SQLite current".into();
        write_legacy(&paths, RecordKind::Project, "p1", &current);
        migrate_json_to_sqlite(&paths).unwrap();

        let mut stale = current.clone();
        stale.name = "stale legacy writer".into();
        write_legacy(&paths, RecordKind::Project, "p1", &stale);
        let error = migrate_json_to_sqlite(&paths).unwrap_err();
        assert!(error.contains("diverges from SQLite"));
        assert!(paths
            .record_path(RecordKind::Project, "p1")
            .unwrap()
            .exists());
        let arc = crate::db::conn_for_migration(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        let loaded: Project = serde_json::from_value(
            crate::store_sqlite::load_one(&conn, RecordKind::Project, "p1")
                .unwrap()
                .unwrap(),
        )
        .unwrap();
        assert_eq!(loaded.name, "SQLite current");
    }

    #[test]
    fn first_store_open_runs_legacy_authority_gate() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        write_legacy(&paths, RecordKind::Project, "p1", &project("p1", vec![]));

        let loaded = crate::store::load_all::<Project>(&paths, RecordKind::Project).unwrap();
        assert_eq!(loaded.len(), 1);
        assert!(paths.base().join(COMPLETION_MARKER).exists());
        assert!(!paths
            .record_path(RecordKind::Project, "p1")
            .unwrap()
            .exists());
    }

    #[test]
    fn marker_with_identical_active_json_archives_without_reimporting() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        write_legacy(&paths, RecordKind::Project, "p1", &project("p1", vec![]));
        migrate_json_to_sqlite(&paths).unwrap();
        let archived = paths
            .base()
            .join("legacy-json")
            .join("projects")
            .join("p1.json");
        fs::create_dir_all(paths.record_dir(RecordKind::Project)).unwrap();
        fs::copy(
            archived,
            paths.record_path(RecordKind::Project, "p1").unwrap(),
        )
        .unwrap();

        let report = migrate_json_to_sqlite(&paths).unwrap();
        assert_eq!(report.migrated, 0);
        assert!(report.already_done);
        assert!(!paths
            .record_path(RecordKind::Project, "p1")
            .unwrap()
            .exists());
        assert_eq!(
            crate::store::load_all::<Project>(&paths, RecordKind::Project)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn concurrent_first_run_serializes_to_one_import_and_one_completed_result() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        write_legacy(&paths, RecordKind::Project, "p1", &project("p1", vec![]));
        let paths = std::sync::Arc::new(paths);
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut threads = Vec::new();
        for _ in 0..2 {
            let paths = std::sync::Arc::clone(&paths);
            let barrier = std::sync::Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                migrate_json_to_sqlite(&paths).unwrap()
            }));
        }
        barrier.wait();
        let reports = threads
            .into_iter()
            .map(|thread| thread.join().unwrap())
            .collect::<Vec<_>>();
        assert_eq!(
            reports.iter().filter(|report| report.migrated == 1).count(),
            1
        );
        assert_eq!(
            reports.iter().filter(|report| report.already_done).count(),
            1
        );
        assert_eq!(
            crate::store::load_all::<Project>(&paths, RecordKind::Project)
                .unwrap()
                .len(),
            1
        );
    }

    #[test]
    fn migration_lock_subprocess_probe() {
        let Some(base) = std::env::var_os("HYDRA_MIGRATION_LOCK_PROBE_BASE") else {
            return;
        };
        let base = PathBuf::from(base);
        fs::write(base.join("child-started"), b"started").unwrap();
        let _lock = MigrationLock::acquire(&base).unwrap();
        fs::write(base.join("child-acquired"), b"acquired").unwrap();
    }

    #[test]
    fn migration_lock_serializes_across_processes() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("cross-process-base");
        fs::create_dir_all(&base).unwrap();
        let parent_lock = MigrationLock::acquire(&base).unwrap();
        let mut child = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("migrate::tests::migration_lock_subprocess_probe")
            .arg("--nocapture")
            .env("HYDRA_MIGRATION_LOCK_PROBE_BASE", &base)
            .spawn()
            .unwrap();

        for _ in 0..500 {
            if base.join("child-started").exists() {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert!(base.join("child-started").exists());
        assert!(!base.join("child-acquired").exists());
        assert!(child.try_wait().unwrap().is_none(), "child bypassed flock");

        drop(parent_lock);
        let status = child.wait().unwrap();
        assert!(status.success());
        assert_eq!(fs::read(base.join("child-acquired")).unwrap(), b"acquired");
    }

    #[test]
    fn crash_restart_failpoints_preserve_exact_bytes_and_converge() {
        for stage in [
            "before-sqlite-commit",
            "after-sqlite-commit",
            "after-sqlite-checkpoint",
            "after-source-snapshot",
            "after-completion-marker",
            "after-archive-link",
            "after-archive-unlink",
        ] {
            let tmp = TempDir::new().unwrap();
            let paths = base_paths(&tmp);
            write_legacy(&paths, RecordKind::Project, "p1", &project("p1", vec![]));
            let source = paths.record_path(RecordKind::Project, "p1").unwrap();
            let bytes = fs::read(&source).unwrap();

            let error = {
                let _failpoint = MigrationFailpointGuard::install(stage);
                migrate_json_to_sqlite(&paths).unwrap_err()
            };

            assert!(
                error.contains(&format!("injected migration failure at {stage}")),
                "unexpected {stage} error: {error}"
            );
            assert!(
                legacy_snapshot_survives(&paths, "p1.json", &bytes),
                "{stage} lost the selected legacy bytes"
            );

            let retry = migrate_json_to_sqlite(&paths).unwrap();
            assert!(
                retry.migrated == 1 || retry.already_done,
                "{stage} did not converge on restart"
            );
            assert!(paths.base().join(COMPLETION_MARKER).exists());
            assert!(!source.exists());
            assert!(legacy_snapshot_survives(&paths, "p1.json", &bytes));
            let arc = crate::db::conn_for_migration(paths.base()).unwrap();
            let conn = arc.lock().unwrap();
            let loaded: Project = serde_json::from_value(
                crate::store_sqlite::load_one(&conn, RecordKind::Project, "p1")
                    .unwrap()
                    .unwrap(),
            )
            .unwrap();
            assert_eq!(loaded, project("p1", vec![]));
        }
    }

    #[test]
    fn authority_publication_stays_ordered_with_success_then_failure() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let base = paths.base().to_path_buf();
        let initial = project("p1", vec![]);
        write_legacy(&paths, RecordKind::Project, "p1", &initial);

        let success_waiting = std::sync::Arc::new(std::sync::Barrier::new(2));
        let release_success = std::sync::Arc::new(std::sync::Barrier::new(2));
        let failure_at_lock = std::sync::Arc::new(std::sync::Barrier::new(2));
        let allow_failure_lock = std::sync::Arc::new(std::sync::Barrier::new(2));
        let success_hook_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let failure_hook_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _hook = MigrationTestHookGuard::install({
            let expected_base = base.clone();
            let success_waiting = std::sync::Arc::clone(&success_waiting);
            let release_success = std::sync::Arc::clone(&release_success);
            let failure_at_lock = std::sync::Arc::clone(&failure_at_lock);
            let allow_failure_lock = std::sync::Arc::clone(&allow_failure_lock);
            let success_hook_fired = std::sync::Arc::clone(&success_hook_fired);
            let failure_hook_fired = std::sync::Arc::clone(&failure_hook_fired);
            std::sync::Arc::new(move |stage, observed_base| {
                if stage == "before-authority-ready"
                    && observed_base == expected_base
                    && !success_hook_fired.swap(true, Ordering::SeqCst)
                {
                    success_waiting.wait();
                    release_success.wait();
                } else if stage == "before-migration-lock"
                    && observed_base == expected_base
                    && success_hook_fired.load(Ordering::SeqCst)
                    && !failure_hook_fired.swap(true, Ordering::SeqCst)
                {
                    failure_at_lock.wait();
                    allow_failure_lock.wait();
                }
            })
        });

        let success_base = base.clone();
        let success = std::thread::spawn(move || crate::db::conn_for(&success_base));
        success_waiting.wait();

        let mut divergent = initial.clone();
        divergent.name = "late stale writer".into();
        write_legacy(&paths, RecordKind::Project, "p1", &divergent);

        let failure_base = base.clone();
        let failure = std::thread::spawn(move || crate::db::conn_for(&failure_base));
        failure_at_lock.wait();
        allow_failure_lock.wait();
        release_success.wait();

        assert!(success.join().unwrap().is_ok());
        let error = failure.join().unwrap().unwrap_err();
        assert!(error.to_string().contains("diverges from SQLite"));

        // The later failure must leave authority blocked. If the earlier success had published
        // READY after releasing the migration lock, this call would return the cached connection
        // and silently bypass the divergent active source.
        let error = crate::db::conn_for(paths.base()).unwrap_err();
        assert!(error.to_string().contains("diverges from SQLite"));
    }

    #[test]
    fn newly_appeared_active_record_blocks_completion_marker() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        write_legacy(&paths, RecordKind::Project, "p1", &project("p1", vec![]));
        let path = paths.record_path(RecordKind::Project, "p1").unwrap();
        let bytes = fs::read(&path).unwrap();
        let value = Envelope::<Value>::from_json_bytes(&bytes, RecordKind::Project.schema())
            .unwrap()
            .record;
        let canonical = canonical_typed_record(RecordKind::Project, "p1", &value, false).unwrap();
        let snapshot = vec![LegacyRecord {
            kind: RecordKind::Project,
            id: "p1".into(),
            path,
            bytes,
            value: canonical.clone(),
            canonical,
        }];
        write_legacy(&paths, RecordKind::Project, "p2", &project("p2", vec![]));

        let error = verify_active_record_set_unchanged(&paths, &snapshot).unwrap_err();
        assert!(error.contains("changed during import"));
        assert!(!paths.base().join(COMPLETION_MARKER).exists());
    }

    #[test]
    fn valid_session_sidecars_commit_verify_then_rename() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let names = BTreeMap::from([("codex:s1".to_string(), "Focus".to_string())]);
        let hidden = BTreeSet::from(["claude:s2".to_string()]);
        fs::write(
            dashboard.join("sessionNames.json"),
            serde_json::to_vec(&names).unwrap(),
        )
        .unwrap();
        fs::write(
            dashboard.join("hiddenSessions.json"),
            serde_json::to_vec(&hidden).unwrap(),
        )
        .unwrap();

        migrate_session_sidecars(&paths).unwrap();
        assert_eq!(crate::store::load_session_names(&paths).unwrap(), names);
        assert_eq!(crate::store::load_hidden_sessions(&paths).unwrap(), hidden);
        assert!(!dashboard.join("sessionNames.json").exists());
        assert!(!dashboard.join("hiddenSessions.json").exists());
        assert!(dashboard.join("sessionNames.json.migrated").exists());
        assert!(dashboard.join("hiddenSessions.json.migrated").exists());
        assert!(paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
        assert!(!paths.base().join(SIDECAR_PENDING_SNAPSHOT).exists());
    }

    #[test]
    #[cfg(unix)]
    fn bounded_session_sidecar_reader_rejects_oversized_files_and_symlinks() {
        let tmp = TempDir::new().unwrap();
        let oversized = tmp.path().join("oversized.json");
        fs::write(
            &oversized,
            vec![b'x'; LEGACY_SESSION_SIDECAR_MAX_BYTES as usize + 1],
        )
        .unwrap();
        let error =
            read_regular_file_no_follow_bounded(&oversized, LEGACY_SESSION_SIDECAR_MAX_BYTES)
                .unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::InvalidData);

        let target = tmp.path().join("target.json");
        fs::write(&target, b"{}").unwrap();
        let link = tmp.path().join("linked.json");
        std::os::unix::fs::symlink(&target, &link).unwrap();
        assert!(
            read_regular_file_no_follow_bounded(&link, LEGACY_SESSION_SIDECAR_MAX_BYTES,).is_err()
        );
    }

    #[test]
    fn sidecar_growth_after_initial_snapshot_fails_before_marker_or_archive() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json");
        fs::write(
            &source,
            serde_json::to_vec(&BTreeMap::from([(
                "codex:s1".to_string(),
                "Original".to_string(),
            )]))
            .unwrap(),
        )
        .unwrap();
        let hook_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _hook = MigrationTestHookGuard::install({
            let expected_base = paths.base().to_path_buf();
            let source = source.clone();
            let hook_fired = std::sync::Arc::clone(&hook_fired);
            std::sync::Arc::new(move |stage, observed_base| {
                if stage == "after-sidecar-initial-snapshot"
                    && observed_base == expected_base
                    && !hook_fired.swap(true, Ordering::SeqCst)
                {
                    let file = fs::File::create(&source).unwrap();
                    file.set_len(LEGACY_SESSION_SIDECAR_MAX_BYTES + 1).unwrap();
                }
            })
        });

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(hook_fired.load(Ordering::SeqCst));
        assert!(error.contains("re-read legacy source"));
        assert_eq!(
            fs::metadata(&source).unwrap().len(),
            LEGACY_SESSION_SIDECAR_MAX_BYTES + 1
        );
        assert!(!dashboard.join("sessionNames.json.migrated").exists());
        assert!(!paths.base().join(SIDECAR_PENDING_SNAPSHOT).exists());
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
    }

    #[test]
    fn oversized_sidecar_pending_snapshot_is_preserved_and_rejected() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.base()).unwrap();
        let pending = paths.base().join(SIDECAR_PENDING_SNAPSHOT);
        let file = fs::File::create(&pending).unwrap();
        file.set_len(LEGACY_SESSION_SIDECAR_PENDING_MAX_BYTES + 1)
            .unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("pending snapshot"));
        assert_eq!(
            fs::metadata(&pending).unwrap().len(),
            LEGACY_SESSION_SIDECAR_PENDING_MAX_BYTES + 1
        );
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
    }

    #[test]
    fn oversized_sidecar_completion_marker_is_preserved_and_rejected() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        fs::create_dir_all(paths.base()).unwrap();
        let marker = paths.base().join(SIDECAR_COMPLETION_MARKER);
        let file = fs::File::create(&marker).unwrap();
        file.set_len(SIDECAR_COMPLETION_MARKER_BODY.len() as u64 + 1)
            .unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("legacy session-sidecar import marker"));
        assert_eq!(
            fs::metadata(&marker).unwrap().len(),
            SIDECAR_COMPLETION_MARKER_BODY.len() as u64 + 1
        );
    }

    #[test]
    fn existing_empty_database_without_pending_provenance_never_seeds_active_sidecars() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let arc = crate::db::conn_for_migration(paths.base()).unwrap();
        drop(arc.lock().unwrap());
        assert!(crate::db::db_path(paths.base()).exists());

        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json");
        let bytes = serde_json::to_vec(&BTreeMap::from([(
            "codex:stale".to_string(),
            "Must not resurrect".to_string(),
        )]))
        .unwrap();
        fs::write(&source, &bytes).unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("automatic resurrection is blocked"));
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(!paths.base().join(SIDECAR_PENDING_SNAPSHOT).exists());
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
        assert!(crate::store::load_session_names(&paths).unwrap().is_empty());
    }

    #[test]
    fn sidecar_crash_restart_failpoints_preserve_exact_bytes_and_converge() {
        for stage in [
            "after-sidecar-pending-snapshot",
            "before-sidecar-sqlite-commit",
            "after-sidecar-sqlite-commit",
            "after-sidecar-sqlite-checkpoint",
            "after-sidecar-source-snapshot",
            "after-sidecar-completion-marker",
            "after-archive-link",
            "after-archive-unlink",
        ] {
            let tmp = TempDir::new().unwrap();
            let paths = base_paths(&tmp);
            let dashboard = paths.base().join("dashboard");
            fs::create_dir_all(&dashboard).unwrap();
            let names_path = dashboard.join("sessionNames.json");
            let hidden_path = dashboard.join("hiddenSessions.json");
            let names = BTreeMap::from([("codex:crash".to_string(), "Exact".to_string())]);
            let hidden = BTreeSet::from(["claude:crash".to_string()]);
            let names_bytes = serde_json::to_vec(&names).unwrap();
            let hidden_bytes = serde_json::to_vec(&hidden).unwrap();
            fs::write(&names_path, &names_bytes).unwrap();
            fs::write(&hidden_path, &hidden_bytes).unwrap();

            let error = {
                let _failpoint = MigrationFailpointGuard::install(stage);
                migrate_session_sidecars(&paths).unwrap_err()
            };

            assert!(
                error.contains(&format!("injected migration failure at {stage}")),
                "unexpected {stage} error: {error}"
            );
            assert!(
                sidecar_snapshot_survives(&dashboard, "sessionNames.json", &names_bytes),
                "{stage} lost the selected session-name bytes"
            );
            assert!(
                sidecar_snapshot_survives(&dashboard, "hiddenSessions.json", &hidden_bytes),
                "{stage} lost the selected hidden-session bytes"
            );

            migrate_session_sidecars(&paths)
                .unwrap_or_else(|error| panic!("{stage} did not converge on retry: {error}"));

            assert_eq!(crate::store::load_session_names(&paths).unwrap(), names);
            assert_eq!(crate::store::load_hidden_sessions(&paths).unwrap(), hidden);
            assert!(paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
            assert!(!paths.base().join(SIDECAR_PENDING_SNAPSHOT).exists());
            assert!(!names_path.exists());
            assert!(!hidden_path.exists());
            assert!(
                sidecar_snapshot_survives(&dashboard, "sessionNames.json", &names_bytes),
                "{stage} did not retain the exact session-name archive"
            );
            assert!(
                sidecar_snapshot_survives(&dashboard, "hiddenSessions.json", &hidden_bytes),
                "{stage} did not retain the exact hidden-session archive"
            );
        }
    }

    #[test]
    fn changed_sidecar_after_pending_snapshot_blocks_and_preserves_both_snapshots() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json");
        let original_names = BTreeMap::from([("codex:s1".to_string(), "Original".to_string())]);
        let original_bytes = serde_json::to_vec(&original_names).unwrap();
        fs::write(&source, &original_bytes).unwrap();

        {
            let _failpoint = MigrationFailpointGuard::install("after-sidecar-pending-snapshot");
            migrate_session_sidecars(&paths).unwrap_err();
        }
        let original_pending = encode_sidecar_pending_snapshot(
            &Some((original_bytes.clone(), original_names)),
            &None::<(Vec<u8>, BTreeSet<String>)>,
        )
        .unwrap();
        let pending_path = paths.base().join(SIDECAR_PENDING_SNAPSHOT);
        assert_eq!(fs::read(&pending_path).unwrap(), original_pending);

        let changed_bytes = serde_json::to_vec(&BTreeMap::from([(
            "codex:s1".to_string(),
            "Changed".to_string(),
        )]))
        .unwrap();
        fs::write(&source, &changed_bytes).unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("pending snapshot differs"));
        assert_eq!(fs::read(&source).unwrap(), changed_bytes);
        assert_eq!(fs::read(&pending_path).unwrap(), original_pending);
        assert!(!crate::db::db_path(paths.base()).exists());
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
    }

    #[test]
    fn ambiguous_sidecar_first_import_preserves_sqlite_only_names_and_blocks() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::replace_session_names(
            &paths,
            &BTreeMap::from([("codex:new".to_string(), "New SQLite".to_string())]),
        )
        .unwrap();
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json");
        let bytes = serde_json::to_vec(&BTreeMap::from([(
            "codex:legacy".to_string(),
            "Legacy".to_string(),
        )]))
        .unwrap();
        fs::write(&source, &bytes).unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("automatic resurrection is blocked"));
        assert_eq!(
            crate::store::load_session_names(&paths).unwrap(),
            BTreeMap::from([("codex:new".to_string(), "New SQLite".to_string())])
        );
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
    }

    #[test]
    fn sidecar_conflict_fails_closed_without_renaming_or_overwriting() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::replace_session_names(
            &paths,
            &BTreeMap::from([("codex:s1".to_string(), "New SQLite".to_string())]),
        )
        .unwrap();
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json");
        fs::write(
            &source,
            serde_json::to_vec(&BTreeMap::from([(
                "codex:s1".to_string(),
                "Stale legacy".to_string(),
            )]))
            .unwrap(),
        )
        .unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();
        assert!(error.contains("conflicts with newer SQLite"));
        assert!(source.exists());
        assert!(!dashboard.join("sessionNames.json.migrated").exists());
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
        assert_eq!(
            crate::store::load_session_names(&paths).unwrap()["codex:s1"],
            "New SQLite"
        );
    }

    #[test]
    fn active_sidecar_missing_from_existing_sqlite_never_resurrects_a_name() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::replace_session_names(
            &paths,
            &BTreeMap::from([("codex:current".into(), "Current".into())]),
        )
        .unwrap();
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json");
        let bytes = serde_json::to_vec(&BTreeMap::from([(
            "codex:missing".to_string(),
            "Stale".to_string(),
        )]))
        .unwrap();
        fs::write(&source, &bytes).unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("automatic resurrection is blocked"));
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
        assert_eq!(
            crate::store::load_session_names(&paths).unwrap(),
            BTreeMap::from([("codex:current".into(), "Current".into())])
        );
    }

    #[test]
    fn active_sidecar_cannot_restore_a_name_deleted_from_existing_sqlite() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let key = "codex:deleted".to_string();
        crate::store::replace_session_names(
            &paths,
            &BTreeMap::from([(key.clone(), "Old name".into())]),
        )
        .unwrap();
        crate::store::replace_session_names(&paths, &BTreeMap::new()).unwrap();
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json");
        let bytes = serde_json::to_vec(&BTreeMap::from([(key, "Old name".to_string())])).unwrap();
        fs::write(&source, &bytes).unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("may have been deleted"));
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(crate::store::load_session_names(&paths).unwrap().is_empty());
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
    }

    #[test]
    fn active_sidecar_cannot_rehide_a_session_unhidden_in_existing_sqlite() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let key = "claude:unhidden".to_string();
        crate::store::replace_hidden_sessions(&paths, &BTreeSet::from([key.clone()])).unwrap();
        crate::store::replace_hidden_sessions(&paths, &BTreeSet::new()).unwrap();
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("hiddenSessions.json");
        let bytes = serde_json::to_vec(&BTreeSet::from([key])).unwrap();
        fs::write(&source, &bytes).unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("may have been unhidden"));
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(crate::store::load_hidden_sessions(&paths)
            .unwrap()
            .is_empty());
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
    }

    #[test]
    fn active_sidecar_identical_to_existing_sqlite_is_safe_crash_residue() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let names = BTreeMap::from([("codex:same".to_string(), "Same".to_string())]);
        crate::store::replace_session_names(&paths, &names).unwrap();
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json");
        fs::write(&source, serde_json::to_vec(&names).unwrap()).unwrap();

        migrate_session_sidecars(&paths).unwrap();

        assert_eq!(crate::store::load_session_names(&paths).unwrap(), names);
        assert!(!source.exists());
        assert!(dashboard.join("sessionNames.json.migrated").exists());
        assert!(paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
    }

    #[test]
    fn sidecar_database_provenance_is_decided_inside_the_migration_lock() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json");
        let bytes = serde_json::to_vec(&BTreeMap::from([(
            "codex:stale".to_string(),
            "Must not resurrect".to_string(),
        )]))
        .unwrap();
        fs::write(&source, &bytes).unwrap();

        let parent_lock = MigrationLock::acquire(paths.base()).unwrap();
        let sidecar_waiting = std::sync::Arc::new(std::sync::Barrier::new(2));
        let hook_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let _hook = MigrationTestHookGuard::install({
            let expected_base = paths.base().to_path_buf();
            let sidecar_waiting = std::sync::Arc::clone(&sidecar_waiting);
            let hook_fired = std::sync::Arc::clone(&hook_fired);
            std::sync::Arc::new(move |stage, observed_base| {
                if stage == "before-migration-lock"
                    && observed_base == expected_base
                    && !hook_fired.swap(true, Ordering::SeqCst)
                {
                    sidecar_waiting.wait();
                }
            })
        });
        let sidecar_paths = paths.clone();
        let sidecar = std::thread::spawn(move || migrate_session_sidecars(&sidecar_paths));
        sidecar_waiting.wait();

        // Simulate the other owner creating meaningful SQLite state before releasing the same
        // process-shared migration lock. The waiting sidecar must observe EXISTING, not the stale
        // pre-lock absence.
        let arc = crate::db::conn_for_migration(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        merge_session_names_in(
            &conn,
            &BTreeMap::from([("codex:current".to_string(), "Current".to_string())]),
        )
        .unwrap();
        drop(conn);
        drop(parent_lock);

        let error = sidecar.join().unwrap().unwrap_err();
        assert!(error.contains("automatic resurrection is blocked"));
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert_eq!(
            crate::store::load_session_names(&paths).unwrap(),
            BTreeMap::from([("codex:current".to_string(), "Current".to_string())])
        );
    }

    #[test]
    fn completed_sidecar_marker_rejects_divergent_recreated_source() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json");
        fs::write(
            &source,
            serde_json::to_vec(&BTreeMap::from([(
                "codex:s1".to_string(),
                "Initial".to_string(),
            )]))
            .unwrap(),
        )
        .unwrap();
        migrate_session_sidecars(&paths).unwrap();
        fs::write(
            &source,
            serde_json::to_vec(&BTreeMap::from([(
                "codex:s1".to_string(),
                "Divergent".to_string(),
            )]))
            .unwrap(),
        )
        .unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();
        assert!(error.contains("diverged after completed import"));
        assert!(source.exists());
        assert_eq!(
            crate::store::load_session_names(&paths).unwrap()["codex:s1"],
            "Initial"
        );
    }

    #[test]
    fn archive_generation_never_reuses_a_numeric_gap() {
        let tmp = TempDir::new().unwrap();
        let base = tmp.path();
        fs::create_dir(base.join("legacy-json")).unwrap();
        fs::create_dir(base.join("legacy-json-2")).unwrap();
        assert_eq!(unique_backup_dir(base).unwrap(), base.join("legacy-json-3"));
    }

    #[test]
    fn sidecar_archive_collision_never_clobbers_existing_generation() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let names = BTreeMap::from([("codex:s1".to_string(), "Focus".to_string())]);
        let bytes = serde_json::to_vec(&names).unwrap();
        let existing = dashboard.join("sessionNames.json.migrated");
        fs::write(&existing, &bytes).unwrap();
        let active = dashboard.join("sessionNames.json");
        fs::write(&active, &bytes).unwrap();

        migrate_session_sidecars(&paths).unwrap();

        assert_eq!(fs::read(&existing).unwrap(), bytes);
        assert_eq!(
            fs::read(dashboard.join("sessionNames.json.migrated-1")).unwrap(),
            bytes
        );
        assert!(!active.exists());
    }

    #[test]
    fn malformed_sidecar_is_not_renamed_or_partially_imported() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let names_path = dashboard.join("sessionNames.json");
        let hidden_path = dashboard.join("hiddenSessions.json");
        fs::write(&names_path, br#"{"codex:s1":"Focus"}"#).unwrap();
        fs::write(&hidden_path, b"not json").unwrap();

        assert!(migrate_session_sidecars(&paths).is_err());
        assert!(names_path.exists());
        assert!(hidden_path.exists());
        assert!(!dashboard.join("sessionNames.json.migrated").exists());
        assert!(
            !crate::db::db_path(paths.base()).exists(),
            "parse must finish before SQLite is opened"
        );
    }

    #[test]
    fn previous_stable_parse_failed_migrated_sidecar_is_preserved_and_not_certified() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::replace_session_names(
            &paths,
            &BTreeMap::from([("codex:current".into(), "Current".into())]),
        )
        .unwrap();
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json.migrated");
        let bytes = b"not valid JSON from the previous stable importer";
        fs::write(&source, bytes).unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("parse previous-stable session-name sidecar"));
        assert!(error.contains("old importer may have renamed it despite failure"));
        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
    }

    #[test]
    fn excessive_archived_sidecar_generations_fail_closed_without_source_mutation() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let bytes = br#"{}"#;
        let sources = (0..=LEGACY_SESSION_SIDECAR_ARCHIVE_MAX_GENERATIONS_PER_KIND)
            .map(|generation| {
                let path = dashboard.join(format!("sessionNames.json.migrated-{generation}"));
                fs::write(&path, bytes).unwrap();
                path
            })
            .collect::<Vec<_>>();

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("generation limit"));
        assert!(error.contains("every sidecar was preserved"));
        for source in &sources {
            assert_eq!(fs::read(source).unwrap(), bytes);
        }
        assert_eq!(
            fs::read_dir(&dashboard).unwrap().count(),
            sources.len(),
            "failure must neither rename nor add sidecar files"
        );
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
        assert!(!paths.base().join(SIDECAR_PENDING_SNAPSHOT).exists());
    }

    #[test]
    fn archived_sidecars_share_one_aggregate_raw_byte_budget() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let payload = "x".repeat(3 * 1024 * 1024);
        let names_bytes = serde_json::to_vec(&BTreeMap::from([(
            "codex:large".to_string(),
            payload.clone(),
        )]))
        .unwrap();
        let hidden_bytes =
            serde_json::to_vec(&BTreeSet::from([format!("claude:{payload}")])).unwrap();
        assert!(names_bytes.len() as u64 <= LEGACY_SESSION_SIDECAR_MAX_BYTES);
        assert!(hidden_bytes.len() as u64 <= LEGACY_SESSION_SIDECAR_MAX_BYTES);
        let mut sources = Vec::new();
        for generation in 0..3 {
            let path = dashboard.join(format!("sessionNames.json.migrated-{generation}"));
            fs::write(&path, &names_bytes).unwrap();
            sources.push((path, names_bytes.as_slice()));
        }
        for generation in 0..3 {
            let path = dashboard.join(format!("hiddenSessions.json.migrated-{generation}"));
            fs::write(&path, &hidden_bytes).unwrap();
            sources.push((path, hidden_bytes.as_slice()));
        }

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("aggregate raw-byte budget"));
        assert!(error.contains("every sidecar was preserved"));
        for (source, expected) in &sources {
            assert_eq!(fs::read(source).unwrap(), *expected);
        }
        assert_eq!(
            fs::read_dir(&dashboard).unwrap().count(),
            sources.len(),
            "failure must neither rename nor add sidecar files"
        );
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
        assert!(!paths.base().join(SIDECAR_PENDING_SNAPSHOT).exists());
    }

    #[test]
    fn previous_stable_sqlite_failed_migrated_sidecars_require_reconciliation() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        // Create the current SQLite authority without either archived key. The old sidecar code
        // ignored replace errors and renamed each source anyway; these files are its on-disk result.
        crate::store::replace_session_names(
            &paths,
            &BTreeMap::from([("codex:current".into(), "Current".into())]),
        )
        .unwrap();
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let names_path = dashboard.join("sessionNames.json.migrated");
        let hidden_path = dashboard.join("hiddenSessions.json.migrated-1");
        let names_bytes = serde_json::to_vec(&BTreeMap::from([(
            "codex:write-failed".to_string(),
            "Preserve me".to_string(),
        )]))
        .unwrap();
        let hidden_bytes =
            serde_json::to_vec(&BTreeSet::from(["claude:write-failed".to_string()])).unwrap();
        fs::write(&names_path, &names_bytes).unwrap();
        fs::write(&hidden_path, &hidden_bytes).unwrap();

        let error = migrate_session_sidecars(&paths).unwrap_err();

        assert!(error.contains("absent from SQLite"));
        assert!(error.contains("old best-effort write may have failed"));
        assert_eq!(fs::read(&names_path).unwrap(), names_bytes);
        assert_eq!(fs::read(&hidden_path).unwrap(), hidden_bytes);
        assert!(!paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
        assert_eq!(
            crate::store::load_session_names(&paths).unwrap(),
            BTreeMap::from([("codex:current".into(), "Current".into())])
        );
        assert!(crate::store::load_hidden_sessions(&paths)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn previous_stable_migrated_name_keeps_newer_sqlite_value() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        crate::store::replace_session_names(
            &paths,
            &BTreeMap::from([("codex:same-key".into(), "SQLite value".into())]),
        )
        .unwrap();
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let source = dashboard.join("sessionNames.json.migrated");
        let bytes = serde_json::to_vec(&BTreeMap::from([(
            "codex:same-key".to_string(),
            "Archived value".to_string(),
        )]))
        .unwrap();
        fs::write(&source, &bytes).unwrap();

        migrate_session_sidecars(&paths).unwrap();

        assert_eq!(fs::read(&source).unwrap(), bytes);
        assert!(paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
        assert_eq!(
            crate::store::load_session_names(&paths).unwrap()["codex:same-key"],
            "SQLite value"
        );
    }

    #[test]
    fn previous_stable_migrated_sidecars_are_certified_only_when_keys_are_visible() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let names = BTreeMap::from([("codex:legacy".to_string(), "Renamed later".to_string())]);
        let hidden = BTreeSet::from(["claude:hidden".to_string()]);
        crate::store::replace_session_names(&paths, &names).unwrap();
        crate::store::replace_hidden_sessions(&paths, &hidden).unwrap();
        let dashboard = paths.base().join("dashboard");
        fs::create_dir_all(&dashboard).unwrap();
        let archived_names = dashboard.join("sessionNames.json.migrated");
        let archived_hidden = dashboard.join("hiddenSessions.json.migrated");
        let names_bytes = serde_json::to_vec(&names).unwrap();
        let hidden_bytes = serde_json::to_vec(&hidden).unwrap();
        fs::write(&archived_names, &names_bytes).unwrap();
        fs::write(&archived_hidden, &hidden_bytes).unwrap();

        migrate_session_sidecars(&paths).unwrap();

        assert!(paths.base().join(SIDECAR_COMPLETION_MARKER).exists());
        assert_eq!(fs::read(&archived_names).unwrap(), names_bytes);
        assert_eq!(fs::read(&archived_hidden).unwrap(), hidden_bytes);
    }

    #[test]
    fn no_legacy_and_no_db_is_a_noop() {
        let tmp = TempDir::new().unwrap();
        let paths = base_paths(&tmp);
        let report = migrate_json_to_sqlite(&paths).unwrap();
        assert_eq!(report.migrated, 0);
        assert!(!report.already_done);
        assert!(!crate::db::db_path(paths.base()).exists());
    }
}
