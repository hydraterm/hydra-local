//! One-shot foreground focus requests for optional extensions.
//!
//! An extension cannot switch a live renderer window directly because the foreground `maestro-app`
//! owns `RendererTabRuntime`. This tiny file-backed signal is intentionally only a request: the
//! running app consumes it on its existing idle refresh tick and performs the real live focus
//! through the same path as local React chrome.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde::{Deserialize, Serialize};

use crate::ids::validate_id;
use crate::paths::AppPaths;

const FOCUS_REQUEST_DIR: &str = "remote_control";
const FOCUS_REQUEST_FILE: &str = "focus_window.json";
pub const MAX_FOCUS_REQUEST_BYTES: usize = 4 * 1024;
pub const MAX_FOCUS_REQUEST_AGE_MS: u64 = 30_000;
pub const MAX_FOCUS_REQUEST_FUTURE_SKEW_MS: u64 = 5_000;

const PRIVATE_DIR_MODE: u32 = 0o700;
const PRIVATE_FILE_MODE: u32 = 0o600;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FocusWindowRequest {
    pub window_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tab_id: Option<String>,
    pub requested_at_ms: u64,
}

fn request_dir(paths: &AppPaths) -> PathBuf {
    paths.base().join(FOCUS_REQUEST_DIR)
}

#[cfg(test)]
fn request_path(paths: &AppPaths) -> PathBuf {
    request_dir(paths).join(FOCUS_REQUEST_FILE)
}

fn wall_clock_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis().min(u128::from(u64::MAX)) as u64)
        .unwrap_or(0)
}

fn invalid_input(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message.into())
}

fn invalid_data(message: impl Into<String>) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message.into())
}

/// An owner-only directory held open while a one-shot signal is claimed or published. Unix
/// operations are relative to this descriptor, so replacing the path after validation cannot
/// redirect a read, rename, or unlink into another directory.
struct PrivateRequestDir {
    #[cfg(not(unix))]
    path: PathBuf,
    directory: File,
}

impl PrivateRequestDir {
    fn open(path: &Path, create: bool) -> io::Result<Self> {
        if create {
            fs::create_dir_all(path)?;
        }
        let path_metadata = fs::symlink_metadata(path)?;
        if path_metadata.file_type().is_symlink() || !path_metadata.file_type().is_dir() {
            return Err(invalid_data(
                "focus request directory is not a real directory",
            ));
        }

        #[cfg(unix)]
        {
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};

            if path_metadata.uid() != unsafe { libc::geteuid() } {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "focus request directory is not owned by the current user",
                ));
            }
            if create {
                fs::set_permissions(path, fs::Permissions::from_mode(PRIVATE_DIR_MODE))?;
            } else if path_metadata.mode() & 0o077 != 0 {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "focus request directory is accessible by another user",
                ));
            }

            let mut options = OpenOptions::new();
            options.read(true).custom_flags(
                libc::O_NOFOLLOW | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NONBLOCK,
            );
            let directory = options.open(path)?;
            let opened = directory.metadata()?;
            if !opened.file_type().is_dir()
                || opened.uid() != unsafe { libc::geteuid() }
                || opened.mode() & 0o077 != 0
                || opened.dev() != path_metadata.dev()
                || opened.ino() != path_metadata.ino()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "focus request directory changed or is not private",
                ));
            }
            Ok(Self { directory })
        }

        #[cfg(not(unix))]
        {
            let directory = File::open(path)?;
            Ok(Self {
                path: path.to_path_buf(),
                directory,
            })
        }
    }

    fn unique_name(&self, suffix: &str) -> String {
        format!(
            ".{FOCUS_REQUEST_FILE}.{}.{}.{}",
            std::process::id(),
            uuid::Uuid::new_v4(),
            suffix
        )
    }

    #[cfg(unix)]
    fn c_name(name: &str) -> io::Result<std::ffi::CString> {
        std::ffi::CString::new(name).map_err(|_| invalid_input("shared-file name contains NUL"))
    }

    fn create_private(&self, name: &str) -> io::Result<File> {
        #[cfg(unix)]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            use std::os::unix::fs::PermissionsExt;
            let name = Self::c_name(name)?;
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_NOFOLLOW
                        | libc::O_CLOEXEC
                        | libc::O_NONBLOCK,
                    PRIVATE_FILE_MODE,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let file = unsafe { File::from_raw_fd(fd) };
            file.set_permissions(fs::Permissions::from_mode(PRIVATE_FILE_MODE))?;
            validate_private_regular_file(&file, MAX_FOCUS_REQUEST_BYTES as u64)?;
            Ok(file)
        }

        #[cfg(not(unix))]
        {
            OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(self.path.join(name))
        }
    }

    fn open_bounded(&self, name: &str) -> io::Result<(File, u64)> {
        #[cfg(unix)]
        {
            use std::os::fd::{AsRawFd, FromRawFd};
            let name = Self::c_name(name)?;
            let fd = unsafe {
                libc::openat(
                    self.directory.as_raw_fd(),
                    name.as_ptr(),
                    libc::O_RDONLY | libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK,
                )
            };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let file = unsafe { File::from_raw_fd(fd) };
            let len = validate_private_regular_file(&file, MAX_FOCUS_REQUEST_BYTES as u64)?;
            Ok((file, len))
        }

        #[cfg(not(unix))]
        {
            let file = OpenOptions::new().read(true).open(self.path.join(name))?;
            let len = validate_private_regular_file(&file, MAX_FOCUS_REQUEST_BYTES as u64)?;
            Ok((file, len))
        }
    }

    fn rename(&self, from: &str, to: &str) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let from = Self::c_name(from)?;
            let to = Self::c_name(to)?;
            let result = unsafe {
                libc::renameat(
                    self.directory.as_raw_fd(),
                    from.as_ptr(),
                    self.directory.as_raw_fd(),
                    to.as_ptr(),
                )
            };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        #[cfg(not(unix))]
        {
            fs::rename(self.path.join(from), self.path.join(to))
        }
    }

    fn unlink(&self, name: &str) -> io::Result<()> {
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd;
            let name = Self::c_name(name)?;
            let result = unsafe { libc::unlinkat(self.directory.as_raw_fd(), name.as_ptr(), 0) };
            if result != 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        #[cfg(not(unix))]
        {
            fs::remove_file(self.path.join(name))
        }
    }

    fn sync(&self) -> io::Result<()> {
        self.directory.sync_all()
    }
}

fn validate_private_regular_file(file: &File, max_bytes: u64) -> io::Result<u64> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(invalid_data("focus request is not a regular file"));
    }
    if metadata.len() > max_bytes {
        return Err(invalid_data(format!(
            "focus request exceeds {max_bytes} bytes"
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() }
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 1
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "focus request must be owner-only and singly linked",
            ));
        }
    }
    Ok(metadata.len())
}

fn validate_window_id(window_id: &str) -> io::Result<()> {
    validate_id(window_id)
        .map(|_| ())
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidInput, e.to_string()))
}

/// Queue a foreground window-focus request for the running desktop app to consume.
pub fn write_focus_window_request(
    paths: &AppPaths,
    window_id: &str,
    requested_at_ms: u64,
) -> io::Result<()> {
    write_focus_request_at(paths, window_id, None, requested_at_ms, wall_clock_ms())
}

/// Queue a foreground pane-focus request for the running desktop app to consume.
pub fn write_focus_pane_request(
    paths: &AppPaths,
    window_id: &str,
    tab_id: &str,
    requested_at_ms: u64,
) -> io::Result<()> {
    write_focus_request_at(
        paths,
        window_id,
        Some(tab_id),
        requested_at_ms,
        wall_clock_ms(),
    )
}

fn write_focus_request_at(
    paths: &AppPaths,
    window_id: &str,
    tab_id: Option<&str>,
    requested_at_ms: u64,
    now_ms: u64,
) -> io::Result<()> {
    validate_window_id(window_id)?;
    if let Some(tab_id) = tab_id {
        validate_window_id(tab_id)?;
    }
    if !validate_freshness(requested_at_ms, now_ms)? {
        return Err(invalid_input("focus request timestamp is stale"));
    }
    let request = FocusWindowRequest {
        window_id: window_id.to_string(),
        tab_id: tab_id.map(str::to_string),
        requested_at_ms,
    };
    let bytes = serde_json::to_vec_pretty(&request)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e.to_string()))?;
    if bytes.len() > MAX_FOCUS_REQUEST_BYTES {
        return Err(invalid_data(format!(
            "focus request exceeds {MAX_FOCUS_REQUEST_BYTES} bytes"
        )));
    }

    let dir = PrivateRequestDir::open(&request_dir(paths), true)?;
    let temp_name = dir.unique_name("tmp");
    let result = (|| {
        let mut file = dir.create_private(&temp_name)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        dir.rename(&temp_name, FOCUS_REQUEST_FILE)?;
        dir.sync()
    })();
    if result.is_err() {
        let _ = dir.unlink(&temp_name);
    }
    result
}

/// Read and delete a queued foreground focus request, if one exists.
pub fn take_focus_window_request(paths: &AppPaths) -> io::Result<Option<FocusWindowRequest>> {
    take_focus_window_request_at(paths, wall_clock_ms())
}

fn take_focus_window_request_at(
    paths: &AppPaths,
    now_ms: u64,
) -> io::Result<Option<FocusWindowRequest>> {
    let dir = match PrivateRequestDir::open(&request_dir(paths), false) {
        Ok(dir) => dir,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    // Rename first to atomically claim exactly one generation. A concurrent writer may publish the
    // next request immediately, while this reader consumes an unpredictable private name.
    let claimed_name = dir.unique_name("claimed");
    match dir.rename(FOCUS_REQUEST_FILE, &claimed_name) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    }

    let result = (|| {
        let (mut file, len) = dir.open_bounded(&claimed_name)?;
        let capacity = usize::try_from(len).unwrap_or(MAX_FOCUS_REQUEST_BYTES);
        let mut bytes = Vec::with_capacity(capacity);
        std::io::Read::by_ref(&mut file)
            .take((MAX_FOCUS_REQUEST_BYTES + 1) as u64)
            .read_to_end(&mut bytes)?;
        if bytes.len() > MAX_FOCUS_REQUEST_BYTES {
            return Err(invalid_data(format!(
                "focus request exceeds {MAX_FOCUS_REQUEST_BYTES} bytes"
            )));
        }
        let request: FocusWindowRequest =
            serde_json::from_slice(&bytes).map_err(|error| invalid_data(error.to_string()))?;
        validate_window_id(&request.window_id)?;
        if let Some(tab_id) = request.tab_id.as_deref() {
            validate_window_id(tab_id)?;
        }
        if !validate_freshness(request.requested_at_ms, now_ms)? {
            return Ok(None);
        }
        Ok(Some(request))
    })();

    // A claimed entry is always one-shot, including malformed/stale entries. This prevents one bad
    // owner-only signal from causing an error on every desktop refresh tick.
    match dir.unlink(&claimed_name) {
        Ok(()) => {}
        Err(error) if error.kind() == io::ErrorKind::NotFound => {}
        Err(error) if result.is_ok() => return Err(error),
        Err(_) => {}
    }
    let _ = dir.sync();
    result
}

/// Returns `Ok(true)` when fresh, `Ok(false)` when safely stale, and an error for a timestamp too
/// far in the future. Saturating arithmetic keeps clock-edge inputs deterministic.
fn validate_freshness(requested_at_ms: u64, now_ms: u64) -> io::Result<bool> {
    if requested_at_ms > now_ms.saturating_add(MAX_FOCUS_REQUEST_FUTURE_SKEW_MS) {
        return Err(invalid_data(
            "focus request timestamp is too far in the future",
        ));
    }
    Ok(now_ms.saturating_sub(requested_at_ms) <= MAX_FOCUS_REQUEST_AGE_MS)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn now() -> u64 {
        1_000_000
    }

    fn prepare_request_dir(paths: &AppPaths) -> PathBuf {
        let dir = request_dir(paths);
        fs::create_dir_all(&dir).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(PRIVATE_DIR_MODE)).unwrap();
        }
        dir
    }

    fn write_raw_request(paths: &AppPaths, bytes: &[u8]) {
        let dir = prepare_request_dir(paths);
        fs::write(dir.join(FOCUS_REQUEST_FILE), bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(
                dir.join(FOCUS_REQUEST_FILE),
                fs::Permissions::from_mode(PRIVATE_FILE_MODE),
            )
            .unwrap();
        }
    }

    #[test]
    fn write_then_take_focus_window_request_is_one_shot() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_base(dir.path());

        write_focus_request_at(&paths, "window-1", None, now(), now()).unwrap();

        assert_eq!(
            take_focus_window_request_at(&paths, now()).unwrap(),
            Some(FocusWindowRequest {
                window_id: "window-1".to_string(),
                tab_id: None,
                requested_at_ms: now(),
            })
        );
        assert_eq!(take_focus_window_request_at(&paths, now()).unwrap(), None);
    }

    #[test]
    fn write_focus_window_request_rejects_unsafe_window_id() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_base(dir.path());

        let err = write_focus_window_request(&paths, "../window", 42).unwrap_err();

        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
    }

    #[test]
    fn write_then_take_focus_pane_request_is_one_shot() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_base(dir.path());

        write_focus_request_at(&paths, "window-1", Some("pane-2"), now(), now()).unwrap();

        assert_eq!(
            take_focus_window_request_at(&paths, now()).unwrap(),
            Some(FocusWindowRequest {
                window_id: "window-1".to_string(),
                tab_id: Some("pane-2".to_string()),
                requested_at_ms: now(),
            })
        );
        assert_eq!(take_focus_window_request_at(&paths, now()).unwrap(), None);
    }

    #[test]
    fn stale_and_future_requests_fail_closed_and_are_consumed_once() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_base(dir.path());

        write_focus_request_at(&paths, "window-1", None, now(), now()).unwrap();
        assert_eq!(
            take_focus_window_request_at(&paths, now() + MAX_FOCUS_REQUEST_AGE_MS + 1).unwrap(),
            None
        );
        assert_eq!(take_focus_window_request_at(&paths, now()).unwrap(), None);

        assert!(write_focus_request_at(
            &paths,
            "window-1",
            None,
            now() + MAX_FOCUS_REQUEST_FUTURE_SKEW_MS + 1,
            now(),
        )
        .is_err());

        write_raw_request(
            &paths,
            format!(
                r#"{{"window_id":"window-1","requested_at_ms":{}}}"#,
                now() + MAX_FOCUS_REQUEST_FUTURE_SKEW_MS + 1
            )
            .as_bytes(),
        );
        assert!(take_focus_window_request_at(&paths, now()).is_err());
        assert_eq!(take_focus_window_request_at(&paths, now()).unwrap(), None);
    }

    #[test]
    fn malformed_unknown_and_oversized_requests_are_bounded_and_one_shot() {
        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_base(dir.path());

        for bytes in [
            b"{not json".to_vec(),
            format!(
                r#"{{"window_id":"window-1","requested_at_ms":{},"command":"sh"}}"#,
                now()
            )
            .into_bytes(),
        ] {
            write_raw_request(&paths, &bytes);
            assert!(take_focus_window_request_at(&paths, now()).is_err());
            assert_eq!(take_focus_window_request_at(&paths, now()).unwrap(), None);
        }

        let request_dir = prepare_request_dir(&paths);
        let path = request_dir.join(FOCUS_REQUEST_FILE);
        let oversized = File::create(&path).unwrap();
        oversized
            .set_len(MAX_FOCUS_REQUEST_BYTES as u64 + 1)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&path, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        }
        assert!(take_focus_window_request_at(&paths, now()).is_err());
        assert_eq!(take_focus_window_request_at(&paths, now()).unwrap(), None);
    }

    #[cfg(unix)]
    #[test]
    fn symlink_fifo_hardlink_and_broad_mode_requests_never_surface_or_block() {
        use std::os::unix::fs::{symlink, PermissionsExt};
        use std::time::{Duration, Instant};

        let dir = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_base(dir.path());
        let request_dir = prepare_request_dir(&paths);
        let request_path = request_path(&paths);
        let valid = format!(r#"{{"window_id":"window-1","requested_at_ms":{}}}"#, now());

        let external = dir.path().join("external.json");
        fs::write(&external, &valid).unwrap();
        symlink(&external, &request_path).unwrap();
        assert!(take_focus_window_request_at(&paths, now()).is_err());
        assert_eq!(fs::read_to_string(&external).unwrap(), valid);

        let fifo = request_path.clone();
        let fifo_c = std::ffi::CString::new(fifo.as_os_str().as_encoded_bytes()).unwrap();
        assert_eq!(
            unsafe { libc::mkfifo(fifo_c.as_ptr(), PRIVATE_FILE_MODE as libc::mode_t) },
            0
        );
        let started = Instant::now();
        assert!(take_focus_window_request_at(&paths, now()).is_err());
        assert!(started.elapsed() < Duration::from_secs(2));

        fs::write(&external, &valid).unwrap();
        fs::set_permissions(&external, fs::Permissions::from_mode(PRIVATE_FILE_MODE)).unwrap();
        fs::hard_link(&external, &request_path).unwrap();
        assert!(take_focus_window_request_at(&paths, now()).is_err());
        assert_eq!(fs::read_to_string(&external).unwrap(), valid);

        fs::write(&request_path, &valid).unwrap();
        fs::set_permissions(&request_path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(take_focus_window_request_at(&paths, now()).is_err());
        assert!(!request_path.exists());
        assert!(request_dir.is_dir());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_request_directory_is_never_followed() {
        use std::os::unix::fs::{symlink, PermissionsExt};

        let dir = tempfile::tempdir().unwrap();
        let external = dir.path().join("external");
        fs::create_dir(&external).unwrap();
        fs::set_permissions(&external, fs::Permissions::from_mode(PRIVATE_DIR_MODE)).unwrap();
        let base = dir.path().join("base");
        fs::create_dir(&base).unwrap();
        symlink(&external, base.join(FOCUS_REQUEST_DIR)).unwrap();
        let paths = AppPaths::with_base(base);

        assert!(write_focus_request_at(&paths, "window-1", None, now(), now()).is_err());
        assert!(!external.join(FOCUS_REQUEST_FILE).exists());
    }
}
