//! Coordinate the existing settings mutators, never the lock-free atomic reader.

use super::{create_dir_private, settings_dir, SettingsFailure};
use std::path::Path;
#[cfg(not(any(unix, windows)))]
use std::sync::{Mutex, MutexGuard};

// Other unsupported targets retain thread-only serialization; Windows and Unix coordinate
// separate GUI processes using a handle-owned lock on the same persistent sibling file.
// Recovering this state-free mutex's poison is safe: settings are reloaded after acquisition.
#[cfg(not(any(unix, windows)))]
static SETTINGS_WRITER: Mutex<()> = Mutex::new(());

pub(super) struct SettingsWriteGuard {
    #[cfg(unix)]
    file: std::fs::File,
    #[cfg(windows)]
    _file: maestro_shell::WindowsFileLock,
    #[cfg(not(any(unix, windows)))]
    _thread: MutexGuard<'static, ()>,
}

impl SettingsWriteGuard {
    pub(super) fn acquire(base: &Path) -> Result<Self, SettingsFailure> {
        #[cfg(not(any(unix, windows)))]
        let thread = SETTINGS_WRITER
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = settings_dir(base);
        let error =
            |error| SettingsFailure::new("io_error", format!("lock settings writer: {error}"));
        create_dir_private(&dir).map_err(error)?;
        #[cfg(windows)]
        let file = maestro_shell::WindowsFileLock::open_owner_exclusive(
            &std::path::absolute(&dir).map_err(error)?,
            std::ffi::OsStr::new(".settings-writer.lock"),
        )
        .map_err(error)?;
        #[cfg(unix)]
        let file = {
            use std::os::fd::AsRawFd;
            use std::os::unix::fs::{MetadataExt, OpenOptionsExt};

            // Each acquisition opens its own file description: flock serializes same-base threads
            // as well as processes, without blocking an unrelated profile behind a global mutex.
            // The separate lock inode must survive settings.json replacement and reset-all.
            let file = std::fs::OpenOptions::new()
                .read(true)
                .write(true)
                .create(true)
                .truncate(false)
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
                .open(dir.join(".settings-writer.lock"))
                .map_err(error)?;
            let metadata = file.metadata().map_err(error)?;
            // SAFETY: geteuid has no pointer arguments or preconditions.
            if !metadata.is_file()
                || metadata.nlink() != 1
                || metadata.uid() != unsafe { libc::geteuid() }
            {
                return Err(error(std::io::Error::new(
                    std::io::ErrorKind::InvalidData,
                    "settings lock is not an owner-local single-link regular file",
                )));
            }
            loop {
                // SAFETY: the descriptor is owned and remains open throughout the lock lifetime.
                if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } == 0 {
                    break;
                }
                let failure = std::io::Error::last_os_error();
                if failure.kind() != std::io::ErrorKind::Interrupted {
                    return Err(error(failure));
                }
            }
            file
        };
        Ok(Self {
            #[cfg(unix)]
            file,
            #[cfg(windows)]
            _file: file,
            #[cfg(not(any(unix, windows)))]
            _thread: thread,
        })
    }
}

#[cfg(unix)]
impl Drop for SettingsWriteGuard {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: Drop still owns this descriptor. Closing it also releases the OS lock if the
        // explicit unlock is interrupted. This descriptor is never cloned or shared with a waiter.
        let _ = unsafe { libc::flock(self.file.as_raw_fd(), libc::LOCK_UN) };
    }
}
