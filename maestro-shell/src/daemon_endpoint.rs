//! Daemon ENDPOINT discovery — resolving WHICH Unix socket the shell should hand to
//! [`DaemonClient`](crate::daemon_client::DaemonClient), for an ALREADY-RUNNING daemon.
//!
//! This is a small, pure foundation step. It does NOT spawn, supervise, probe, kill, or even
//! connect to a daemon: it only computes a `PathBuf`. The actual connect remains the caller's job
//! via `DaemonClient`. There is no socket IO, no PTY, no git, no scratch/worktree creation here.
//!
//! Resolution precedence (first match wins):
//! 1. an EXPLICIT caller-supplied socket path (e.g. a CLI flag) — always wins;
//! 2. otherwise a stored, valid [`DaemonEndpoint`] record at `<app-support>/daemon/endpoint.json`;
//! 3. otherwise the shared fresh-install default: the first non-empty `XDG_RUNTIME_DIR` or
//!    `TMPDIR`, then `/tmp`, joined with the per-user daemon socket filename.
//!
//! The endpoint record is persisted through the SAME envelope/store path as every other record
//! (atomic write, `0700` dir / `0600` file, corrupt-quarantine, future-version-left-in-place), via
//! the singleton [`RecordKind::DaemonEndpoint`] at `daemon/endpoint.json`. It is NOT a parallel
//! ad-hoc persistence system with weaker permissions.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

use crate::paths::{AppPaths, RecordKind};
use crate::store::{self, LoadOutcome, StoreError};

/// The fixed singleton id for the endpoint record. It maps to exactly `daemon/endpoint.json` and
/// passes `validate_id` (so it can never path-traverse out of the `daemon` directory).
pub const ENDPOINT_ID: &str = "endpoint";

/// A durable pointer to a running daemon's Unix socket. Persisted as the singleton
/// `maestro.daemon_endpoint` record so a later run can reattach to the same daemon without
/// re-deriving the default path (and without probing it here).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DaemonEndpoint {
    /// Absolute path of the daemon's listening Unix socket.
    pub socket_path: String,
    /// The daemon's pid, if known when the record was written. Advisory only — this module never
    /// signals or probes it; a stale pid does not invalidate the record.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub daemon_pid: Option<u32>,
    /// Unix millis the record was written, for staleness/debug context.
    pub updated_at_ms: u64,
}

impl DaemonEndpoint {
    /// A new endpoint record for `socket_path` (and optional pid), stamped `updated_at_ms`.
    pub fn new(
        socket_path: impl Into<String>,
        daemon_pid: Option<u32>,
        updated_at_ms: u64,
    ) -> Self {
        DaemonEndpoint {
            socket_path: socket_path.into(),
            daemon_pid,
            updated_at_ms,
        }
    }
}

/// An environment lookup, injectable so default-path resolution is testable WITHOUT mutating the
/// real process environment globally. Returns the value of `key`, or `None` if unset.
///
/// An EMPTY value is treated by [`default_socket_path`] as "absent" (the next source is tried), so
/// a caller that wires this to `std::env::var_os` does not need to special-case empty strings.
pub trait EnvLookup {
    fn get(&self, key: &str) -> Option<String>;
}

/// The production [`EnvLookup`]: reads the real process environment.
#[derive(Clone, Copy, Debug, Default)]
pub struct ProcessEnv;

impl EnvLookup for ProcessEnv {
    fn get(&self, key: &str) -> Option<String> {
        std::env::var_os(key).map(|v| v.to_string_lossy().into_owned())
    }
}

// A closure can be used directly as an `EnvLookup` (handy in tests).
impl<F> EnvLookup for F
where
    F: Fn(&str) -> Option<String>,
{
    fn get(&self, key: &str) -> Option<String> {
        (self)(key)
    }
}

/// Compute the daemon's DEFAULT socket path using the same non-empty runtime-directory precedence
/// and per-user filename as the daemon and installed launchers.
///
/// An env var that is unset OR empty is skipped (treated as absent), so a stray empty
/// `XDG_RUNTIME_DIR`/`TMPDIR` falls through to the next source rather than producing a socket at
/// the filesystem root.
pub fn default_socket_path(env: &impl EnvLookup) -> PathBuf {
    // SAFETY: geteuid has no preconditions and does not dereference memory.
    default_socket_path_for_uid(env, unsafe { libc::geteuid() })
}

/// Testable form of [`default_socket_path`] with an injected effective uid.
pub fn default_socket_path_for_uid(env: &impl EnvLookup, effective_uid: u32) -> PathBuf {
    let base =
        first_non_empty(env, &["XDG_RUNTIME_DIR", "TMPDIR"]).unwrap_or_else(|| "/tmp".into());
    PathBuf::from(base).join(maestro_protocol::daemon_socket_filename(effective_uid))
}

/// First env var in `keys` whose value is present AND non-empty.
fn first_non_empty(env: &impl EnvLookup, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| match env.get(k) {
        Some(v) if !v.is_empty() => Some(v),
        _ => None,
    })
}

/// Load the stored singleton endpoint record, if present and currently readable.
///
/// Returns `Ok(None)` when no record exists, when it is corrupt (it is quarantined by the store,
/// consistent with every other record), or when it is a future-version record (left in place,
/// never rewritten). In all of those "can't use it" cases the caller falls back to the default
/// path. Only a true IO/id error surfaces as `Err`.
pub fn load_endpoint(paths: &AppPaths) -> Result<Option<DaemonEndpoint>, StoreError> {
    match store::load_one::<DaemonEndpoint>(paths, RecordKind::DaemonEndpoint, ENDPOINT_ID)? {
        Some(LoadOutcome::Loaded(ep)) => Ok(Some(ep)),
        // Corrupt -> already quarantined by the store; future-version -> left in place untouched.
        // Either way it is unusable for resolution, so behave as "no usable record".
        Some(LoadOutcome::Quarantined { .. }) | Some(LoadOutcome::FutureVersion { .. }) | None => {
            Ok(None)
        }
    }
}

/// Persist (atomically) the singleton endpoint record at `<app-support>/daemon/endpoint.json`,
/// reusing the shared store (0700 dir / 0600 file / atomic temp+rename). This module does NOT open
/// the socket — writing a record is pure persistence.
pub fn store_endpoint(
    paths: &AppPaths,
    endpoint: &DaemonEndpoint,
    written_at_ms: u64,
) -> Result<(), StoreError> {
    store::write_record(
        paths,
        RecordKind::DaemonEndpoint,
        ENDPOINT_ID,
        written_at_ms,
        endpoint,
    )
}

/// Resolve the socket path to hand to `DaemonClient`, WITHOUT opening it.
///
/// Precedence: an `explicit` path wins; else a stored, valid endpoint record; else the daemon
/// default ([`default_socket_path`]). This performs no socket IO, no probing, and creates no
/// directories — a missing endpoint record simply falls through to the default. A genuine
/// IO/id error reading the record surfaces as `Err`.
pub fn resolve_socket_path(
    paths: &AppPaths,
    explicit: Option<PathBuf>,
    env: &impl EnvLookup,
) -> Result<PathBuf, StoreError> {
    if let Some(p) = explicit {
        return Ok(p);
    }
    if let Some(ep) = load_endpoint(paths)? {
        return Ok(PathBuf::from(ep.socket_path));
    }
    Ok(default_socket_path(env))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use std::fs;
    use tempfile::TempDir;

    /// A map-backed env lookup so tests never read/mutate the real process environment.
    struct MapEnv(HashMap<String, String>);

    impl MapEnv {
        fn new(pairs: &[(&str, &str)]) -> Self {
            MapEnv(
                pairs
                    .iter()
                    .map(|(k, v)| (k.to_string(), v.to_string()))
                    .collect(),
            )
        }
    }

    impl EnvLookup for MapEnv {
        fn get(&self, key: &str) -> Option<String> {
            self.0.get(key).cloned()
        }
    }

    fn paths_in(tmp: &TempDir) -> AppPaths {
        AppPaths::with_base(tmp.path().join("Maestro"))
    }

    #[test]
    fn default_uses_xdg_runtime_dir_first() {
        let env = MapEnv::new(&[
            ("XDG_RUNTIME_DIR", "/run/user/1000"),
            ("TMPDIR", "/var/tmp"),
        ]);
        assert_eq!(
            default_socket_path_for_uid(&env, 1000),
            PathBuf::from("/run/user/1000").join("hydra-maestro-1000.sock")
        );
    }

    #[test]
    fn default_falls_back_to_tmpdir_when_xdg_absent_or_empty() {
        // Absent.
        let env = MapEnv::new(&[("TMPDIR", "/var/tmp")]);
        assert_eq!(
            default_socket_path_for_uid(&env, 1000),
            PathBuf::from("/var/tmp").join("hydra-maestro-1000.sock")
        );
        // Present but EMPTY -> treated as absent.
        let env = MapEnv::new(&[("XDG_RUNTIME_DIR", ""), ("TMPDIR", "/var/tmp")]);
        assert_eq!(
            default_socket_path_for_uid(&env, 1000),
            PathBuf::from("/var/tmp").join("hydra-maestro-1000.sock")
        );
    }

    #[test]
    fn default_falls_back_to_tmp_when_both_absent_or_empty() {
        let env = MapEnv::new(&[]);
        assert_eq!(
            default_socket_path_for_uid(&env, 1000),
            PathBuf::from("/tmp").join("hydra-maestro-1000.sock")
        );
        // Both present but EMPTY -> /tmp.
        let env = MapEnv::new(&[("XDG_RUNTIME_DIR", ""), ("TMPDIR", "")]);
        assert_eq!(
            default_socket_path_for_uid(&env, 1000),
            PathBuf::from("/tmp").join("hydra-maestro-1000.sock")
        );
    }

    #[test]
    fn explicit_overrides_stored_record_and_default() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        // A stored record exists, AND a default would resolve — but explicit must win over both.
        store_endpoint(
            &paths,
            &DaemonEndpoint::new("/from/record.sock", None, 1),
            1,
        )
        .unwrap();
        let env = MapEnv::new(&[("XDG_RUNTIME_DIR", "/run/user/1000")]);

        let resolved =
            resolve_socket_path(&paths, Some(PathBuf::from("/explicit/cli.sock")), &env).unwrap();
        assert_eq!(resolved, PathBuf::from("/explicit/cli.sock"));
    }

    #[test]
    fn arbitrary_stored_endpoint_survives_default_rename_and_beats_fresh_default() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let env = MapEnv::new(&[("XDG_RUNTIME_DIR", "/run/user/1000")]);
        let fresh_default = default_socket_path(&env);
        let retained_path = PathBuf::from("/run/user/1000/pre-update-retained.sock");
        assert_ne!(retained_path, fresh_default);
        store_endpoint(
            &paths,
            &DaemonEndpoint::new(retained_path.to_string_lossy(), Some(4321), 7),
            7,
        )
        .unwrap();

        let resolved = resolve_socket_path(&paths, None, &env).unwrap();
        assert_eq!(resolved, retained_path);
    }

    #[test]
    fn default_used_when_no_explicit_and_no_record() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let env = MapEnv::new(&[("XDG_RUNTIME_DIR", "/run/user/1000")]);

        let resolved = resolve_socket_path(&paths, None, &env).unwrap();
        assert_eq!(
            resolved,
            PathBuf::from("/run/user/1000").join(maestro_protocol::daemon_socket_filename(
                // SAFETY: geteuid has no preconditions and does not dereference memory.
                unsafe { libc::geteuid() },
            ))
        );
    }

    #[test]
    fn endpoint_record_round_trips_through_store() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let ep = DaemonEndpoint::new("/run/user/1000/legacy.sock", Some(99), 123);
        store_endpoint(&paths, &ep, 123).unwrap();

        // The record round-trips through the store: what we stored is exactly what loads back.
        let back = load_endpoint(&paths).unwrap();
        assert_eq!(back, Some(ep));
    }

    // NOTE: the old `endpoint_record_round_trips_through_store` also asserted the record landed at a per-record file
    // `<base>/daemon/endpoint.json`, and `endpoint_dir_is_0700_and_file_is_0600` asserted that file/dir's Unix perms.
    // The SQLite store keeps the endpoint as a row in the single `maestro.db` file, not a per-record JSON file, so
    // those file-location/permission assertions no longer apply. The one owner-only-permissions invariant that remains
    // is the DB file being 0600, tested in store::db_file_is_0600. The round-trip intent is preserved above.

    #[test]
    fn future_version_legacy_endpoint_blocks_sqlite_authority_and_is_byte_preserved() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        // Hand-write a future-version envelope at the singleton path.
        let dir = paths.daemon_dir();
        fs::create_dir_all(&dir).unwrap();
        let raw = r#"{"schema":"maestro.daemon_endpoint","schema_version":9999,"written_by":"maestro-shell/9.9.9","written_at_ms":0,"record":{"socket_path":"/future.sock","updated_at_ms":0}}"#;
        let path = dir.join("endpoint.json");
        fs::write(&path, raw).unwrap();

        // A future legacy record means the JSON→SQLite authority transition is unresolved. Falling
        // back through a newly-created empty DB would hide that durable record, so both entrypoints
        // now fail closed instead.
        let load_error = load_endpoint(&paths).unwrap_err().to_string();
        assert!(load_error.contains("local data authority is unresolved"));
        let env = MapEnv::new(&[("XDG_RUNTIME_DIR", "/run/user/1000")]);
        let resolve_error = resolve_socket_path(&paths, None, &env)
            .unwrap_err()
            .to_string();
        assert!(resolve_error.contains("local data authority is unresolved"));

        // The future-version record was NOT rewritten or quarantined.
        assert!(path.exists());
        assert_eq!(fs::read_to_string(&path).unwrap(), raw);
        assert!(
            !paths.corrupt_dir().exists()
                || fs::read_dir(paths.corrupt_dir()).unwrap().next().is_none(),
            "future-version endpoint must not be quarantined"
        );
        assert!(!crate::db::db_path(paths.base()).exists());
    }

    // NOTE: the old `corrupt_endpoint_is_quarantined_consistently` test hand-wrote invalid JSON to a per-record file
    // `<base>/daemon/endpoint.json` and asserted `load_endpoint` moved it into `corrupt/` as a `.bad` file. The SQLite
    // store has no per-record files to move: a row that won't deserialize surfaces as Quarantined (which `load_endpoint`
    // maps to "no usable record", falling back to the default), with no file quarantine. That behavior is now covered by
    // store::row_that_wont_deserialize_is_quarantined_and_excluded. The test was removed because its file-move mechanism
    // is gone.

    #[test]
    fn endpoint_id_cannot_be_path_traversed() {
        // The fixed singleton id is path-safe: it resolves UNDER the daemon dir and never escapes.
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let p = paths
            .record_path(RecordKind::DaemonEndpoint, ENDPOINT_ID)
            .unwrap();
        assert!(p.starts_with(paths.daemon_dir()));
        assert_eq!(p, paths.daemon_dir().join("endpoint.json"));
    }

    #[test]
    fn resolver_creates_no_scratch_or_worktree_and_opens_no_socket() {
        let tmp = TempDir::new().unwrap();
        let paths = paths_in(&tmp);
        let env = MapEnv::new(&[("TMPDIR", "/var/tmp")]);

        // Pure resolution with no record present.
        let resolved = default_socket_path_for_uid(&env, 1000);
        assert_eq!(
            resolved,
            PathBuf::from("/var/tmp").join("hydra-maestro-1000.sock")
        );

        // No scratch / worktree / corrupt dirs were created by resolution, and the (advisory)
        // resolved socket path was NOT opened/created.
        assert!(!paths.scratch_base().exists());
        assert!(!paths.worktree_base().exists());
        assert!(!paths.corrupt_dir().exists());
        assert!(
            !resolved.exists(),
            "resolver must not open/create the socket"
        );
    }
}
