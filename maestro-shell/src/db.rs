//! Embedded SQLite connection management for the local record store.
//!
//! One DB file per app-support base (`<base>/maestro.db`). The store's free functions take `&AppPaths`, so rather than
//! thread a connection handle through ~188 call-sites we lazily open + CACHE one connection per base behind a mutex.
//! EVERY connection is opened through [`open_conn`], which sets the PRAGMAs that make the file safe for multiple local
//! writer processes:
//! - `journal_mode=WAL` — one writer concurrent with readers across processes.
//! - `foreign_keys=ON` — MUST be per-connection; miss it and ON DELETE CASCADE silently does nothing.
//! - `busy_timeout=5000` — the loser of a write race blocks-and-retries instead of erroring SQLITE_BUSY.
//! - `synchronous=NORMAL` — crash-safe with WAL, without fsync-per-write latency.

use rusqlite::{Connection, OpenFlags};
use std::collections::{HashMap, HashSet};
use std::ffi::OsStr;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, OnceLock};

/// The single-file DB name under the app-support base.
pub const DB_FILENAME: &str = "maestro.db";

/// The DB schema version this binary understands. Bumped when the relational schema changes; a DB stamped HIGHER than
/// this was written by a newer build → we refuse to mutate it (the DB-level analog of the old per-record FutureVersion).
pub const DB_SCHEMA_VERSION: i64 = 1;

/// Every schema-aware process keeps a shared lock on this file for as long as it has a cached
/// connection. A binary that needs to initialize or migrate the schema must first acquire the same
/// lock exclusively. This prevents an older schema-aware writer from continuing through a cached
/// connection while a newer binary changes the schema underneath it.
const SCHEMA_LEASE_FILENAME: &str = ".maestro-schema.lock";

/// SQLite may leave these siblings while a connection is active or after an interrupted start.
/// They carry database pages and therefore receive the same owner/type/link/mode checks as the
/// main database before SQLite is allowed to inspect them.
const DB_SIDECAR_FILENAMES: [&str; 3] = ["maestro.db-wal", "maestro.db-shm", "maestro.db-journal"];

/// Process-wide cache of one connection per base dir. `Arc<Mutex<Connection>>` so concurrent callers in THIS process
/// serialize on the same handle (rusqlite Connection is not Sync); cross-PROCESS safety is WAL + busy_timeout.
static CONNS: OnceLock<Mutex<HashMap<PathBuf, Arc<Mutex<Connection>>>>> = OnceLock::new();

/// The file descriptors that own the process-lifetime shared schema leases for [`CONNS`]. Kept in
/// a parallel map so the public connection type and its many callers remain unchanged.
static SCHEMA_LEASES: OnceLock<Mutex<HashMap<PathBuf, File>>> = OnceLock::new();

/// Bases whose legacy JSON authority has been resolved successfully in this process. Raw
/// connections opened by the migrator are deliberately not enough to set this bit: a failed import
/// must not let a later store call continue through the cached SQLite connection.
static AUTHORITY_READY: OnceLock<Mutex<HashSet<PathBuf>>> = OnceLock::new();

/// Errors from opening/pragma-ing/migrating the DB.
#[derive(Debug)]
pub enum DbError {
    /// The underlying sqlite call failed.
    Sqlite(rusqlite::Error),
    /// The DB was stamped with a schema version NEWER than this binary supports — left untouched (never downgraded).
    FutureVersion { db: i64, ours: i64 },
    /// The existing database cannot be upgraded safely because its schema metadata or migration chain is invalid.
    Schema(crate::schema::SchemaError),
    /// Another still-running Hydra binary holds the old schema generation open. The installer or
    /// user must stop/restart it before this binary is allowed to migrate.
    SchemaLeaseBusy,
    /// Legacy JSON/sidecar authority could not be promoted safely. SQLite remains unavailable to
    /// ordinary callers in this process even if the failed attempt happened to create the DB file.
    Authority(String),
    /// Could not create the base directory for the DB file.
    Io(std::io::Error),
}

impl std::fmt::Display for DbError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            DbError::Sqlite(e) => write!(f, "sqlite error: {e}"),
            DbError::FutureVersion { db, ours } => write!(
                f,
                "local database schema v{db} was written by a newer Maestro (this build supports v{ours}); left untouched"
            ),
            DbError::Schema(error) => write!(f, "schema error: {error}"),
            DbError::SchemaLeaseBusy => write!(
                f,
                "local database schema upgrade is blocked by another running Hydra process; restart all Hydra app and agent processes, then retry"
            ),
            DbError::Authority(error) => write!(f, "local data authority is unresolved: {error}"),
            DbError::Io(e) => write!(f, "db io error: {e}"),
        }
    }
}

impl std::error::Error for DbError {}

impl From<rusqlite::Error> for DbError {
    fn from(e: rusqlite::Error) -> Self {
        DbError::Sqlite(e)
    }
}

impl From<crate::schema::SchemaError> for DbError {
    fn from(error: crate::schema::SchemaError) -> Self {
        match error {
            crate::schema::SchemaError::FutureVersion { db, ours } => {
                DbError::FutureVersion { db, ours }
            }
            other => DbError::Schema(other),
        }
    }
}

/// The DB path under a base dir.
pub fn db_path(base: &Path) -> PathBuf {
    base.join(DB_FILENAME)
}

/// Return the cached connection for `base`, opening (and creating + migrating the schema of) the DB on first use.
/// Subsequent calls for the same base return the same handle. The returned guard serializes in-process writes.
pub fn conn_for(base: &Path) -> Result<Arc<Mutex<Connection>>, DbError> {
    if !authority_ready(base) {
        let paths = crate::paths::AppPaths::with_base(base);
        crate::migrate::migrate_json_to_sqlite(&paths).map_err(DbError::Authority)?;
    }
    conn_for_migration(base)
}

/// The raw connection path used only by the legacy migrator after it has taken the migration lock
/// and selected/validated its complete source set. It deliberately bypasses the authority gate to
/// avoid recursion back into `migrate_json_to_sqlite`.
pub(crate) fn conn_for_migration(base: &Path) -> Result<Arc<Mutex<Connection>>, DbError> {
    let map = CONNS.get_or_init(|| Mutex::new(HashMap::new()));
    let mut guard = map.lock().unwrap();
    #[cfg(test)]
    prune_deleted_test_bases(&mut guard);
    if let Some(existing) = guard.get(base).cloned() {
        return Ok(existing);
    }
    // Keep this lock through opening so two threads in one process cannot both attempt to upgrade
    // the flock from shared to exclusive. Cross-process initialization is serialized by the lease.
    let (conn, lease) = open_conn(base)?;
    let arc = Arc::new(Mutex::new(conn));
    SCHEMA_LEASES
        .get_or_init(|| Mutex::new(HashMap::new()))
        .lock()
        .unwrap()
        .insert(base.to_path_buf(), lease);
    guard.insert(base.to_path_buf(), Arc::clone(&arc));
    Ok(arc)
}

/// Unit tests create hundreds of distinct temporary app-support bases in one process. The
/// production cache intentionally keeps its one real base open for the process lifetime, but that
/// policy would otherwise retain every deleted test database and schema-lease descriptor until the
/// test binary exits. Reclaim only bases that have disappeared and whose connection has no owner
/// outside the cache. Keeping the lease while an external `Arc` exists preserves the same schema
/// generation invariant that production relies on.
#[cfg(test)]
fn prune_deleted_test_bases(conns: &mut HashMap<PathBuf, Arc<Mutex<Connection>>>) {
    let stale = conns
        .iter()
        .filter(|(base, conn)| !base.exists() && Arc::strong_count(conn) == 1)
        .map(|(base, _)| base.clone())
        .collect::<Vec<_>>();

    if stale.is_empty() {
        return;
    }

    // Close SQLite before releasing its matching schema lease.
    for base in &stale {
        conns.remove(base);
    }
    if let Some(leases) = SCHEMA_LEASES.get() {
        let mut leases = leases.lock().unwrap();
        for base in &stale {
            leases.remove(base);
        }
    }
    if let Some(ready) = AUTHORITY_READY.get() {
        let mut ready = ready.lock().unwrap();
        for base in &stale {
            ready.remove(base);
        }
    }
}

pub(crate) fn mark_authority_ready(base: &Path) {
    AUTHORITY_READY
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap()
        .insert(base.to_path_buf());
}

pub(crate) fn mark_authority_blocked(base: &Path) {
    if let Some(ready) = AUTHORITY_READY.get() {
        ready.lock().unwrap().remove(base);
    }
}

fn authority_ready(base: &Path) -> bool {
    AUTHORITY_READY
        .get_or_init(|| Mutex::new(HashSet::new()))
        .lock()
        .unwrap()
        .contains(base)
}

/// Open a connection to `<base>/maestro.db`, set the safety PRAGMAs, ensure the schema exists, and enforce the
/// future-version guard. This is the ONE opener both binaries (app + agent) go through.
fn open_conn(base: &Path) -> Result<(Connection, File), DbError> {
    let (secured_base, database_exists) = secure_database_boundary(base)?;
    let path = db_path(base);

    // Preserve the future-schema no-write contract. Existing DB bytes are inspected before a
    // schema lease is created. The only permitted change before this verdict is tightening the
    // owner-controlled base/DB/sidecar metadata to the security invariant; no DB byte, lock, or
    // schema state is created or mutated for a future-version database.
    if database_exists {
        inspect_database_for_write(&path)?;
    }

    let lease = open_schema_lease(&secured_base)?;
    lock_schema_shared(&lease)?;

    // Pre-create through the verified base descriptor so SQLite can never follow a link at its
    // authority path. The `0700` base makes the later pathname open safe from other UIDs; same-UID
    // replacement is the product's explicit local trust boundary. Scope this descriptor so it is
    // closed before the following read-only SQLite inspection can acquire process-owned locks.
    {
        let database_file = secured_base
            .open_owner_file(OsStr::new(DB_FILENAME), false)
            .map_err(|error| DbError::Io(io_context("pre-create SQLite database", error)))?;
        drop(database_file);
    }

    // Do not raw-open the database or any SQLite sidecar after this point. POSIX record locks are
    // process-owned: closing an unrelated descriptor for an inode releases every SQLite lock this
    // process holds on that inode, bypassing SQLite's deferred-close protection.

    // Existing databases are inspected through a read-only connection first. A future-version or
    // malformed database therefore returns before a read-write connection, persistent PRAGMA, or
    // schema DDL is attempted. A hot journal that would require recovery also fails read-only rather
    // than being replayed by this older binary.
    let mut needs_write = inspect_database_for_write(&path)?;

    let mut have_exclusive = false;
    if needs_write {
        unlock_schema(&lease)?;
        match acquire_schema_exclusive_after_upgrade(&lease) {
            Ok(()) => have_exclusive = true,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                // A concurrent initializer may be the blocker. Rejoin it as a shared reader, then
                // re-inspect: success means it completed our exact schema; an older process still
                // holding the previous generation leaves `needs_write=true` and we fail closed.
                lock_schema_shared(&lease)?;
                needs_write = inspect_database_for_write(&path)?;
                if needs_write {
                    return Err(DbError::SchemaLeaseBusy);
                }
            }
            Err(error) => return Err(DbError::Io(error)),
        }
    }

    let mut conn = Connection::open(&path)?;
    // These PRAGMAs are connection-local. Compatibility was established before this read-write
    // open, and the retained shared/exclusive schema lease prevents a cooperating process from
    // changing the generation for the lifetime of the cached connection.
    conn.pragma_update(None, "foreign_keys", "ON")?;
    conn.pragma_update(None, "busy_timeout", 5000)?;
    if needs_write {
        debug_assert!(have_exclusive);
        crate::schema::ensure_schema(&mut conn)?;
    }
    // Persistent/runtime tuning is applied only after the schema has been accepted. BEGIN IMMEDIATE in
    // ensure_schema serializes concurrent local-writer initialization and migration.
    conn.pragma_update(None, "journal_mode", "WAL")?;
    conn.pragma_update(None, "synchronous", "NORMAL")?;
    if have_exclusive {
        // Downgrade atomically: no other migrator can slip between schema commit and our retained
        // process-lifetime shared lease.
        lock_schema_shared(&lease)?;
    }
    Ok((conn, lease))
}

fn open_schema_lease(
    secured_base: &crate::local_store_security::SecureAppSupport,
) -> Result<File, DbError> {
    secured_base
        .open_owner_file(OsStr::new(SCHEMA_LEASE_FILENAME), false)
        .map_err(|error| DbError::Io(io_context("open schema lease", error)))
}

fn inspect_database_for_write(path: &Path) -> Result<bool, DbError> {
    let readonly = Connection::open_with_flags(
        path,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )?;
    crate::schema::schema_requires_write(&readonly).map_err(DbError::from)
}

fn secure_database_boundary(
    base: &Path,
) -> Result<(crate::local_store_security::SecureAppSupport, bool), DbError> {
    let secured_base = crate::local_store_security::SecureAppSupport::open(base)
        .map_err(|error| DbError::Io(io_context("secure app-support base", error)))?;
    let database_exists = secured_base
        .secure_existing_file(OsStr::new(DB_FILENAME))
        .map_err(|error| DbError::Io(io_context("secure SQLite database", error)))?;
    secure_database_sidecars(&secured_base)?;
    Ok((secured_base, database_exists))
}

fn secure_database_sidecars(
    secured_base: &crate::local_store_security::SecureAppSupport,
) -> Result<(), DbError> {
    for name in DB_SIDECAR_FILENAMES {
        secured_base
            .secure_existing_file(OsStr::new(name))
            .map_err(|error| DbError::Io(io_context("secure SQLite sidecar", error)))?;
    }
    Ok(())
}

fn io_context(context: &str, error: std::io::Error) -> std::io::Error {
    std::io::Error::new(error.kind(), format!("{context}: {error}"))
}

/// Permission/type/version preflight used by the legacy migrator before it creates its lock.
/// A future-version database therefore receives safe metadata tightening only and no auxiliary
/// file creation. Ordinary open repeats the verdict while holding the schema lease.
pub(crate) fn preflight_existing_database(base: &Path) -> Result<(), DbError> {
    // A failed legacy import can leave its connection cached while authority remains blocked, and
    // the next attempt enters this preflight again. Never raw-open/close SQLite inodes in that
    // state: on Unix, doing so would release every POSIX lock this process's cached connection owns.
    // Hold the same map mutex used by `conn_for_migration` across the uncached preflight so a new
    // cached connection cannot appear between this check and the descriptor-based boundary walk.
    let connections = CONNS.get_or_init(|| Mutex::new(HashMap::new()));
    let cached = connections.lock().unwrap();
    if cached.contains_key(base) {
        return Ok(());
    }
    let (_secured_base, database_exists) = secure_database_boundary(base)?;
    if database_exists {
        inspect_database_for_write(&db_path(base))?;
    }
    Ok(())
}

#[cfg(unix)]
fn flock(file: &File, operation: libc::c_int) -> std::io::Result<()> {
    use std::os::fd::AsRawFd;
    loop {
        // SAFETY: `file` remains open for at least the duration of this call. Successful shared
        // locks remain owned by the process-lifetime `SCHEMA_LEASES` descriptor.
        if unsafe { libc::flock(file.as_raw_fd(), operation) } == 0 {
            return Ok(());
        }
        let error = std::io::Error::last_os_error();
        if error.kind() != std::io::ErrorKind::Interrupted {
            return Err(error);
        }
    }
}

#[cfg(unix)]
fn lock_schema_shared(file: &File) -> Result<(), DbError> {
    flock(file, libc::LOCK_SH).map_err(DbError::Io)
}

#[cfg(unix)]
fn try_lock_schema_exclusive(file: &File) -> std::io::Result<()> {
    flock(file, libc::LOCK_EX | libc::LOCK_NB)
}

#[cfg(unix)]
fn acquire_schema_exclusive_after_upgrade(file: &File) -> std::io::Result<()> {
    // Two fresh processes can both observe an empty DB while holding shared leases, then both drop
    // them to upgrade. Give that short handoff enough attempts for one contender to win. If a
    // long-lived older process is the blocker, the bounded loop ends and the caller re-enters shared
    // mode to distinguish "another migrator finished" from a genuine stale-generation lease.
    for attempt in 0..20 {
        match try_lock_schema_exclusive(file) {
            Ok(()) => return Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                if attempt + 1 < 20 {
                    std::thread::sleep(std::time::Duration::from_millis(5));
                } else {
                    return Err(error);
                }
            }
            Err(error) => return Err(error),
        }
    }
    unreachable!()
}

#[cfg(unix)]
fn unlock_schema(file: &File) -> Result<(), DbError> {
    flock(file, libc::LOCK_UN).map_err(DbError::Io)
}

#[cfg(not(unix))]
fn lock_schema_shared(_file: &File) -> Result<(), DbError> {
    Err(DbError::Io(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "schema leases require Unix flock",
    )))
}

#[cfg(not(unix))]
fn try_lock_schema_exclusive(_file: &File) -> std::io::Result<()> {
    Err(std::io::Error::new(
        std::io::ErrorKind::Unsupported,
        "schema leases require Unix flock",
    ))
}

#[cfg(not(unix))]
fn acquire_schema_exclusive_after_upgrade(file: &File) -> std::io::Result<()> {
    try_lock_schema_exclusive(file)
}

#[cfg(not(unix))]
fn unlock_schema(_file: &File) -> Result<(), DbError> {
    Ok(())
}

/// SQLite's `PRAGMA data_version` for this connection: a value that CHANGES whenever the database file was committed
/// by a DIFFERENT connection (in this or another process) since this connection last read it. It does NOT change for
/// this connection's OWN writes. This makes it a free, cheap change epoch for another local process to detect that
/// the desktop app wrote something without scanning the store.
///
/// CRITICAL: the value is CONNECTION-LOCAL. It is only meaningful when read repeatedly on the SAME long-lived
/// connection (the cached [`conn_for`] handle). A fresh connection always reads the current value with no baseline, so
/// polling a per-call connection would never observe a delta. Callers MUST poll the cached connection for their base.
pub fn data_version(conn: &Connection) -> Result<i64, DbError> {
    // `PRAGMA data_version` returns a single row/column; pragma_query_value reads it directly.
    let v: i64 = conn.pragma_query_value(None, "data_version", |r| r.get(0))?;
    Ok(v)
}

/// [`data_version`] read on the process's CACHED connection for `base` — the long-lived handle the
/// baseline rule above requires, without the caller naming rusqlite types. `None` when the store
/// can't be opened (dev/no DB) or the lock is poisoned; callers treat that as "no signal" and fall
/// back to their slow cadence.
pub fn data_version_for(base: &Path) -> Option<i64> {
    let conn = conn_for(base).ok()?;
    let guard = conn.lock().ok()?;
    data_version(&guard).ok()
}

/// TEST-ONLY: drop the cached connection for a base so a temp DB can be reopened fresh (tests reuse temp dirs).
#[cfg(test)]
pub fn forget_cached(base: &Path) {
    if let Some(map) = CONNS.get() {
        map.lock().unwrap().remove(base);
    }
    if let Some(map) = SCHEMA_LEASES.get() {
        map.lock().unwrap().remove(base);
    }
    if let Some(ready) = AUTHORITY_READY.get() {
        ready.lock().unwrap().remove(base);
    }
}

#[cfg(test)]
mod data_version_tests {
    use super::*;
    use std::sync::{Arc, Barrier};
    use tempfile::TempDir;

    #[cfg(unix)]
    fn mode(path: &Path) -> u32 {
        use std::os::unix::fs::PermissionsExt;
        std::fs::metadata(path).unwrap().permissions().mode() & 0o777
    }

    #[cfg(unix)]
    const SQLITE_DMS_LOCK_OFFSET: libc::off_t = 128;

    #[cfg(unix)]
    fn sqlite_dms_lock(lock_type: libc::c_short) -> libc::flock {
        // SQLite's Unix VFS reserves bytes 120..127 for WAL locks and byte 128 for the dead-man
        // switch (UNIX_SHM_BASE + SQLITE_SHM_NLOCK). A live WAL mapping retains a shared lock here;
        // a newcomer may take it exclusively and truncate the SHM file only when no holder exists.
        // SAFETY: every field used by F_GETLK/F_SETLK is initialized immediately below.
        let mut lock: libc::flock = unsafe { std::mem::zeroed() };
        lock.l_type = lock_type;
        lock.l_whence = libc::SEEK_SET as libc::c_short;
        lock.l_start = SQLITE_DMS_LOCK_OFFSET;
        lock.l_len = 1;
        lock
    }

    #[cfg(unix)]
    fn conflicting_dms_lock(file: &File) -> std::io::Result<libc::c_short> {
        use std::os::fd::AsRawFd;

        let mut lock = sqlite_dms_lock(libc::F_WRLCK as libc::c_short);
        loop {
            // SAFETY: `lock` is a valid writable flock and `file` remains open for this call.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_GETLK, &mut lock) } == 0 {
                return Ok(lock.l_type);
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    #[cfg(unix)]
    fn set_dms_lock(file: &File, lock_type: libc::c_short) -> std::io::Result<()> {
        use std::os::fd::AsRawFd;

        let lock = sqlite_dms_lock(lock_type);
        loop {
            // SAFETY: `lock` is a valid flock and `file` remains open for this call.
            if unsafe { libc::fcntl(file.as_raw_fd(), libc::F_SETLK, &lock) } == 0 {
                return Ok(());
            }
            let error = std::io::Error::last_os_error();
            if error.kind() != std::io::ErrorKind::Interrupted {
                return Err(error);
            }
        }
    }

    #[cfg(unix)]
    fn assert_dms_exclusive_truncate_is_blocked(base: &Path) {
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("db::data_version_tests::sqlite_dms_exclusive_truncate_probe")
            .arg("--nocapture")
            .env("HYDRA_SQLITE_DMS_PROBE_BASE", base)
            .status()
            .unwrap();
        assert!(status.success(), "SQLite DMS contender was not blocked");
    }

    #[cfg(unix)]
    #[test]
    fn sqlite_dms_exclusive_truncate_probe() {
        let Some(base) = std::env::var_os("HYDRA_SQLITE_DMS_PROBE_BASE") else {
            return;
        };
        let shm = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(Path::new(&base).join("maestro.db-shm"))
            .unwrap();
        let length_before = shm.metadata().unwrap().len();
        assert!(
            length_before >= 32 * 1024,
            "live SQLite SHM must contain its first complete 32 KiB region"
        );

        assert_eq!(
            conflicting_dms_lock(&shm).unwrap(),
            libc::F_RDLCK as libc::c_short,
            "a live SQLite WAL mapping must retain a shared DMS lock"
        );

        match set_dms_lock(&shm, libc::F_WRLCK as libc::c_short) {
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(libc::EACCES) | Some(libc::EAGAIN)
                ) => {}
            Err(error) => panic!("unexpected SQLite DMS lock error: {error}"),
            Ok(()) => {
                shm.set_len(0).unwrap();
                set_dms_lock(&shm, libc::F_UNLCK as libc::c_short).unwrap();
                panic!("exclusive SQLite DMS lock allowed SHM truncation beside a live mapping");
            }
        }
        assert_eq!(
            shm.metadata().unwrap().len(),
            length_before,
            "blocked DMS contender must not truncate SQLite SHM"
        );
    }

    #[test]
    fn future_version_is_rejected_without_changing_database_bytes() {
        let dir = TempDir::new().unwrap();
        let path = db_path(dir.path());
        {
            let raw = Connection::open(&path).unwrap();
            raw.execute_batch(
                "CREATE TABLE schema_meta (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL);",
            )
            .unwrap();
            raw.execute(
                "INSERT INTO schema_meta (id, version) VALUES (1, ?1)",
                [DB_SCHEMA_VERSION + 1],
            )
            .unwrap();
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o755)).unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        }
        let before = std::fs::read(&path).unwrap();

        assert!(matches!(
            open_conn(dir.path()),
            Err(DbError::FutureVersion {
                db,
                ours: DB_SCHEMA_VERSION
            }) if db == DB_SCHEMA_VERSION + 1
        ));

        let after = std::fs::read(&path).unwrap();
        assert_eq!(after, before, "future-version DB bytes must be untouched");
        assert!(
            !dir.path().join(SCHEMA_LEASE_FILENAME).exists(),
            "future-version rejection must not create a schema lease"
        );
        for name in DB_SIDECAR_FILENAMES {
            assert!(
                !dir.path().join(name).exists(),
                "future-version rejection must not create {name}"
            );
        }
        #[cfg(unix)]
        {
            assert_eq!(mode(dir.path()), 0o700);
            assert_eq!(mode(&path), 0o600);
        }
        let raw = Connection::open(&path).unwrap();
        let tables: i64 = raw
            .query_row(
                "SELECT COUNT(*) FROM sqlite_schema WHERE type='table' AND name != 'schema_meta'",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(tables, 0, "no v1 DDL may run before the future guard");
    }

    #[cfg(unix)]
    #[test]
    fn future_version_authority_gate_creates_no_migration_or_schema_lock() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let base = dir.path().join("Maestro");
        std::fs::create_dir(&base).unwrap();
        let path = db_path(&base);
        {
            let raw = Connection::open(&path).unwrap();
            raw.execute_batch(
                "CREATE TABLE schema_meta (id INTEGER PRIMARY KEY CHECK (id = 1), version INTEGER NOT NULL);",
            )
            .unwrap();
            raw.execute(
                "INSERT INTO schema_meta (id, version) VALUES (1, ?1)",
                [DB_SCHEMA_VERSION + 1],
            )
            .unwrap();
        }
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).unwrap();
        let before = std::fs::read(&path).unwrap();

        assert!(conn_for(&base).is_err());

        assert_eq!(std::fs::read(&path).unwrap(), before);
        assert!(!base.join(SCHEMA_LEASE_FILENAME).exists());
        assert!(!base
            .join(crate::migrate::MIGRATION_LOCK_FOR_SECURITY_TESTS)
            .exists());
        for name in DB_SIDECAR_FILENAMES {
            assert!(
                !base.join(name).exists(),
                "future-version authority gate must not create {name}"
            );
        }
        assert_eq!(mode(&base), 0o700);
        assert_eq!(mode(&path), 0o600);
    }

    #[test]
    fn concurrent_first_opens_serialize_schema_initialization() {
        let dir = TempDir::new().unwrap();
        let base = Arc::new(dir.path().to_path_buf());
        let barrier = Arc::new(Barrier::new(3));
        let mut threads = Vec::new();

        for _ in 0..2 {
            let base = Arc::clone(&base);
            let barrier = Arc::clone(&barrier);
            threads.push(std::thread::spawn(move || {
                barrier.wait();
                let (conn, _lease) = open_conn(&base).expect("concurrent open");
                conn.query_row("SELECT version FROM schema_meta WHERE id=1", [], |row| {
                    row.get::<_, i64>(0)
                })
                .expect("schema version")
            }));
        }

        barrier.wait();
        for thread in threads {
            assert_eq!(thread.join().unwrap(), DB_SCHEMA_VERSION);
        }

        let (conn, _lease) = open_conn(&base).unwrap();
        let meta_rows: i64 = conn
            .query_row("SELECT COUNT(*) FROM schema_meta", [], |row| row.get(0))
            .unwrap();
        assert_eq!(meta_rows, 1);
        assert_eq!(
            conn.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
    }

    #[cfg(unix)]
    #[test]
    fn cached_connection_holds_shared_schema_lease_until_released() {
        let dir = TempDir::new().unwrap();
        let base = dir.path();
        let cached = conn_for_migration(base).unwrap();
        let secured = crate::local_store_security::SecureAppSupport::open(base).unwrap();
        let contender = open_schema_lease(&secured).unwrap();
        let error = acquire_schema_exclusive_after_upgrade(&contender).unwrap_err();
        assert_eq!(error.kind(), std::io::ErrorKind::WouldBlock);

        drop(cached);
        forget_cached(base);
        acquire_schema_exclusive_after_upgrade(&contender).unwrap();
        unlock_schema(&contender).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn deleted_test_bases_release_connections_and_leases_without_evicting_live_owners() {
        let first = TempDir::new().unwrap();
        let first_base = first.path().to_path_buf();
        let externally_owned = conn_for_migration(&first_base).unwrap();
        drop(first);

        // A deleted base with a live caller must keep both its connection and schema lease.
        let trigger = TempDir::new().unwrap();
        let trigger_conn = conn_for_migration(trigger.path()).unwrap();
        assert!(
            CONNS
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .contains_key(&first_base),
            "a caller-owned connection must not be evicted"
        );
        assert!(
            SCHEMA_LEASES
                .get()
                .unwrap()
                .lock()
                .unwrap()
                .contains_key(&first_base),
            "a caller-owned connection must retain its schema lease"
        );

        drop(externally_owned);
        drop(trigger_conn);
        drop(trigger);

        // The next open reclaims every prior base that is both deleted and cache-only. Repeating
        // this models the full unit binary, where hundreds of TempDirs previously accumulated four
        // or more descriptors apiece until Linux's ordinary 1024-descriptor limit was exhausted.
        let mut retired = vec![first_base];
        for _ in 0..128 {
            let dir = TempDir::new().unwrap();
            let base = dir.path().to_path_buf();
            drop(conn_for_migration(&base).unwrap());
            drop(dir);
            retired.push(base);
        }
        let final_trigger = TempDir::new().unwrap();
        let _final_conn = conn_for_migration(final_trigger.path()).unwrap();

        let conns = CONNS.get().unwrap().lock().unwrap();
        let leases = SCHEMA_LEASES.get().unwrap().lock().unwrap();
        for base in retired {
            assert!(!conns.contains_key(&base), "stale connection was retained");
            assert!(
                !leases.contains_key(&base),
                "stale schema lease was retained"
            );
        }
    }

    #[cfg(unix)]
    #[test]
    fn blocked_authority_retry_preserves_cached_sqlite_dms_lock() {
        let dir = TempDir::new().unwrap();
        let base = dir.path().join("Maestro");
        let cached = conn_for(&base).unwrap();
        {
            let conn = cached.lock().unwrap();
            conn.execute(
                "INSERT INTO projects (project_id, name, root, default_workspace_policy, created_at_ms, last_active_at_ms) \
                 VALUES ('p-retry','Retry','/tmp','scratch_cwd',1,1)",
                [],
            )
            .unwrap();
            conn.execute_batch("BEGIN DEFERRED").unwrap();
            assert_eq!(
                conn.query_row("SELECT COUNT(*) FROM projects", [], |row| row
                    .get::<_, i64>(0))
                    .unwrap(),
                1
            );
        }

        assert_dms_exclusive_truncate_is_blocked(&base);

        // This is the exact in-process state left when migration fails after opening SQLite:
        // authority is blocked, but `CONNS` still owns the live WAL connection. A public retry
        // repeats preflight before it reuses that cached connection.
        mark_authority_blocked(&base);
        preflight_existing_database(&base).unwrap();
        preflight_existing_database(&base).unwrap();
        let report =
            crate::migrate::migrate_json_to_sqlite(&crate::paths::AppPaths::with_base(&base))
                .unwrap();
        assert!(report.already_done);

        assert_dms_exclusive_truncate_is_blocked(&base);

        cached.lock().unwrap().execute_batch("ROLLBACK").unwrap();
        forget_cached(&base);
        drop(cached);
    }

    /// data_version on a stable connection: unchanged with no other-connection writes, STRICTLY increases after a
    /// commit by a SEPARATE connection to the same DB file. This pins the connection-local semantics the agent poll
    /// relies on (a write by the desktop app's connection is observed by the agent's cached connection).
    #[test]
    fn data_version_moves_on_other_connection_commit_and_is_stable_otherwise() {
        let dir = std::env::temp_dir().join(format!("hydra-dvtest-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        // Reader = the "agent" connection (stable, long-lived); Writer = the "desktop app" connection.
        let (reader, _reader_lease) = open_conn(&dir).expect("open reader");
        let (writer, _writer_lease) = open_conn(&dir).expect("open writer");

        let v0 = data_version(&reader).expect("v0");
        // Stable: reading again with no intervening write does not change it.
        assert_eq!(
            data_version(&reader).expect("v0b"),
            v0,
            "unchanged without a write"
        );

        // Writer (a DIFFERENT connection) commits a row.
        writer
            .execute(
                "INSERT INTO projects (project_id, name, root, default_workspace_policy, created_at_ms, last_active_at_ms) \
                 VALUES ('p1','P1','/tmp','scratch_cwd',1,1)",
                [],
            )
            .expect("insert");

        let v1 = data_version(&reader).expect("v1");
        assert!(
            v1 > v0,
            "data_version must increase after another connection commits (v0={v0} v1={v1})"
        );
        // And stabilize again after the change is observed.
        assert_eq!(
            data_version(&reader).expect("v1b"),
            v1,
            "stable after observing the change"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn restart_repairs_permissive_database_and_lock_metadata() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let base = dir.path().join("Maestro");
        let (conn, lease) = open_conn(&base).unwrap();
        conn.execute(
            "INSERT INTO projects (project_id, name, root, default_workspace_policy, created_at_ms, last_active_at_ms) \
             VALUES ('p-restart','Restart','/tmp','scratch_cwd',1,1)",
            [],
        )
        .unwrap();
        drop(conn);
        drop(lease);

        let db = db_path(&base);
        let schema_lock = base.join(SCHEMA_LEASE_FILENAME);
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o755)).unwrap();
        std::fs::set_permissions(&db, std::fs::Permissions::from_mode(0o644)).unwrap();
        std::fs::set_permissions(&schema_lock, std::fs::Permissions::from_mode(0o666)).unwrap();

        let (reopened, _lease) = open_conn(&base).unwrap();
        assert_eq!(
            reopened
                .query_row(
                    "SELECT COUNT(*) FROM projects WHERE project_id='p-restart'",
                    [],
                    |row| row.get::<_, i64>(0),
                )
                .unwrap(),
            1
        );
        assert_eq!(mode(&base), 0o700);
        assert_eq!(mode(&db), 0o600);
        assert_eq!(mode(&schema_lock), 0o600);
    }

    #[cfg(unix)]
    #[test]
    fn existing_permissive_sqlite_sidecars_are_repaired() {
        use std::os::unix::fs::PermissionsExt;

        let dir = TempDir::new().unwrap();
        let base = dir.path().join("Maestro");
        let _secured = crate::local_store_security::SecureAppSupport::open(&base).unwrap();
        for name in [
            DB_FILENAME,
            "maestro.db-wal",
            "maestro.db-shm",
            "maestro.db-journal",
        ] {
            let path = base.join(name);
            std::fs::write(&path, b"").unwrap();
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o666)).unwrap();
        }

        let (_secured, database_exists) = secure_database_boundary(&base).unwrap();
        assert!(database_exists);

        for name in [
            DB_FILENAME,
            "maestro.db-wal",
            "maestro.db-shm",
            "maestro.db-journal",
        ] {
            assert_eq!(mode(&base.join(name)), 0o600, "wrong mode for {name}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn schema_lease_refuses_symlink_and_hardlink_without_touching_target() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = TempDir::new().unwrap();
        let base = dir.path().join("Maestro");
        let (conn, lease) = open_conn(&base).unwrap();
        drop(conn);
        drop(lease);
        let schema_lock = base.join(SCHEMA_LEASE_FILENAME);
        std::fs::remove_file(&schema_lock).unwrap();
        let victim = base.join("victim");
        std::fs::write(&victim, b"preserve").unwrap();
        std::fs::set_permissions(&victim, std::fs::Permissions::from_mode(0o644)).unwrap();

        symlink(&victim, &schema_lock).unwrap();
        assert!(matches!(open_conn(&base), Err(DbError::Io(_))));
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve");
        assert_eq!(mode(&victim), 0o644);

        std::fs::remove_file(&schema_lock).unwrap();
        std::fs::hard_link(&victim, &schema_lock).unwrap();
        assert!(matches!(open_conn(&base), Err(DbError::Io(_))));
        assert_eq!(std::fs::read(&victim).unwrap(), b"preserve");
        assert_eq!(mode(&victim), 0o644);
    }

    #[cfg(unix)]
    #[test]
    fn permissive_umask_two_process_wal_probe() {
        let Some(base) = std::env::var_os("HYDRA_STORE_SECURITY_PROBE_BASE") else {
            return;
        };
        let control =
            PathBuf::from(std::env::var_os("HYDRA_STORE_SECURITY_PROBE_CONTROL").unwrap());
        let id = std::env::var("HYDRA_STORE_SECURITY_PROBE_ID").unwrap();
        // SAFETY: umask is process-global, but this probe runs as its own exact-test subprocess.
        unsafe { libc::umask(0) };
        let arc = conn_for(Path::new(&base)).unwrap();
        let conn = arc.lock().unwrap();
        conn.execute(
            "INSERT INTO projects (project_id, name, root, default_workspace_policy, created_at_ms, last_active_at_ms) \
             VALUES (?1,?1,'/tmp','scratch_cwd',1,1)",
            [&id],
        )
        .unwrap();
        conn.execute_batch("BEGIN DEFERRED").unwrap();
        let _: i64 = conn
            .query_row("SELECT COUNT(*) FROM projects", [], |row| row.get(0))
            .unwrap();
        std::fs::write(control.join(format!("ready-{id}")), b"ready").unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
        while !control.join(format!("release-{id}")).exists() {
            assert!(
                std::time::Instant::now() < deadline,
                "parent never released probe"
            );
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        assert_eq!(
            conn.query_row("PRAGMA quick_check", [], |row| row.get::<_, String>(0))
                .unwrap(),
            "ok"
        );
        conn.execute_batch("ROLLBACK").unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn permissive_umask_and_two_process_wal_remain_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let base = tmp.path().join("Maestro");
        std::fs::create_dir(&base).unwrap();
        std::fs::set_permissions(&base, std::fs::Permissions::from_mode(0o777)).unwrap();
        let control = tmp.path().join("control");
        std::fs::create_dir(&control).unwrap();
        let executable = std::env::current_exe().unwrap();
        let spawn_probe = |id: &str| {
            std::process::Command::new(&executable)
                .arg("--exact")
                .arg("db::data_version_tests::permissive_umask_two_process_wal_probe")
                .arg("--nocapture")
                .env("HYDRA_STORE_SECURITY_PROBE_BASE", &base)
                .env("HYDRA_STORE_SECURITY_PROBE_CONTROL", &control)
                .env("HYDRA_STORE_SECURITY_PROBE_ID", id)
                .spawn()
                .unwrap()
        };
        let wait_until_ready = |id: &str| {
            let deadline = std::time::Instant::now() + std::time::Duration::from_secs(15);
            while !control.join(format!("ready-{id}")).exists() {
                assert!(
                    std::time::Instant::now() < deadline,
                    "child probe {id} did not become ready"
                );
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
        };

        // Start the second process only after the first has created and mapped the WAL sidecars.
        // This pins the existing-SHM path that used to lose its DMS lock when `open_conn` performed
        // a late descriptor-based sidecar recheck.
        let mut first = spawn_probe("p-one");
        wait_until_ready("p-one");
        let mut second = spawn_probe("p-two");
        wait_until_ready("p-two");

        assert_eq!(mode(&base), 0o700);
        for name in [
            DB_FILENAME,
            "maestro.db-wal",
            "maestro.db-shm",
            SCHEMA_LEASE_FILENAME,
            crate::migrate::MIGRATION_LOCK_FOR_SECURITY_TESTS,
        ] {
            let path = base.join(name);
            assert!(
                path.exists(),
                "active two-process store did not create {name}"
            );
            assert_eq!(mode(&path), 0o600, "wrong active mode for {name}");
        }

        // Once the first holder exits, the second holder alone must retain the shared DMS lock. A
        // third opener must not acquire the exclusive lock that authorizes SHM truncation.
        std::fs::write(control.join("release-p-one"), b"release").unwrap();
        assert!(first.wait().unwrap().success());
        assert_dms_exclusive_truncate_is_blocked(&base);

        std::fs::write(control.join("release-p-two"), b"release").unwrap();
        assert!(second.wait().unwrap().success());
        let raw = Connection::open(db_path(&base)).unwrap();
        assert_eq!(
            raw.query_row(
                "SELECT COUNT(*) FROM projects WHERE project_id IN ('p-one','p-two')",
                [],
                |row| row.get::<_, i64>(0),
            )
            .unwrap(),
            2
        );
    }
}
