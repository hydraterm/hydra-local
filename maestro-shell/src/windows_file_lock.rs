//! Handle-owned Windows coordination locks for the existing schema and migration lock files.
//! These locks never replace SQLite's own byte-range/WAL locks or introduce a new database.

use std::fs::File;
use std::io;
use std::os::windows::io::{AsRawHandle, FromRawHandle};
use std::sync::{Mutex, MutexGuard};
use windows_sys::Win32::Foundation::{
    SetHandleInformation, ERROR_LOCK_VIOLATION, GENERIC_READ, GENERIC_WRITE, HANDLE_FLAG_INHERIT,
    INVALID_HANDLE_VALUE,
};
use windows_sys::Win32::Storage::FileSystem::{
    LockFileEx, ReOpenFile, UnlockFileEx, FILE_FLAG_OPEN_REPARSE_POINT, FILE_SHARE_READ,
    FILE_SHARE_WRITE, LOCKFILE_EXCLUSIVE_LOCK, LOCKFILE_FAIL_IMMEDIATELY,
};
use windows_sys::Win32::System::IO::OVERLAPPED;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Mode {
    Unlocked,
    Shared,
    Exclusive,
    /// A downgrade acquired SH while retaining EX but has not yet released EX. An unlock failure
    /// must never pretend that the conversion completed or discard the retained shared claim.
    SharedAndExclusive,
}

#[derive(Debug)]
pub(crate) struct WindowsFileLock {
    file: File,
    mode: Mutex<Mode>,
}

impl WindowsFileLock {
    /// Consume a file obtained from SecureAppSupport::open_owner_file. ReOpenFile addresses that
    /// exact kernel object, not a fresh pathname; omit delete sharing to pin its authority name.
    /// Reopen without FILE_FLAG_OVERLAPPED so no locking operation can outlive its stack context.
    pub(crate) fn from_owner_file(file: File) -> io::Result<Self> {
        // SAFETY: file stays open across the synchronous object-bound reopen. No FILE_ATTRIBUTE_*
        // flags belong here: ReOpenFile changes handle flags, not the existing file's attributes.
        let handle = unsafe {
            ReOpenFile(
                file.as_raw_handle(),
                GENERIC_READ | GENERIC_WRITE,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                FILE_FLAG_OPEN_REPARSE_POINT,
            )
        };
        if handle == INVALID_HANDLE_VALUE {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: successful ReOpenFile transfers one newly owned handle into File.
        let pinned = unsafe { File::from_raw_handle(handle) };
        if unsafe { SetHandleInformation(pinned.as_raw_handle(), HANDLE_FLAG_INHERIT, 0) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            file: pinned,
            mode: Mutex::new(Mode::Unlocked),
        })
    }

    fn state(&self) -> io::Result<MutexGuard<'_, Mode>> {
        self.mode
            .lock()
            .map_err(|_| io::Error::other("Windows file lease state is poisoned"))
    }

    pub(crate) fn lock_shared(&self) -> io::Result<()> {
        let mut mode = self.state()?;
        match *mode {
            Mode::Shared => Ok(()),
            Mode::Unlocked => {
                lock_raw(&self.file, false, false)?;
                *mode = Mode::Shared;
                Ok(())
            }
            Mode::Exclusive => {
                // Windows explicitly permits SH overlapping EX on the same handle. The first
                // matching unlock releases EX, leaving SH continuously held. This is not a
                // Unix-flock assumption and must never become unlock-EX then acquire-SH.
                lock_raw(&self.file, false, false)?;
                *mode = Mode::SharedAndExclusive;
                unlock_raw(&self.file)?;
                *mode = Mode::Shared;
                Ok(())
            }
            Mode::SharedAndExclusive => Err(io::Error::other(
                "Windows file lease downgrade did not complete",
            )),
        }
    }

    pub(crate) fn lock_exclusive(&self) -> io::Result<()> {
        self.exclusive(false)
    }

    pub(crate) fn try_lock_exclusive(&self) -> io::Result<()> {
        self.exclusive(true)
    }

    fn exclusive(&self, nonblocking: bool) -> io::Result<()> {
        let mut mode = self.state()?;
        match *mode {
            Mode::Exclusive => Ok(()),
            Mode::Unlocked => {
                lock_raw(&self.file, true, nonblocking)?;
                *mode = Mode::Exclusive;
                Ok(())
            }
            // The shared database opener already releases SH, tries its bounded upgrade, then
            // re-inspects under SH on contention. Do not invent a second implicit upgrade flow.
            Mode::Shared | Mode::SharedAndExclusive => Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "release the Windows shared lease before requesting an exclusive upgrade",
            )),
        }
    }

    pub(crate) fn unlock(&self) -> io::Result<()> {
        let mut mode = self.state()?;
        release_held(&self.file, &mut mode)
    }
}

impl Drop for WindowsFileLock {
    fn drop(&mut self) {
        // Drop has exclusive Rust ownership, including after a poisoned mutex. Explicit release
        // is best-effort; closing this exact non-inherited handle is the OS cleanup backstop.
        let mode = self
            .mode
            .get_mut()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let _ = release_held(&self.file, mode);
    }
}

fn release_held(file: &File, mode: &mut Mode) -> io::Result<()> {
    if *mode == Mode::SharedAndExclusive {
        unlock_raw(file)?;
        *mode = Mode::Shared;
    }
    if *mode != Mode::Unlocked {
        unlock_raw(file)?;
        *mode = Mode::Unlocked;
    }
    Ok(())
}

fn lock_raw(file: &File, exclusive: bool, nonblocking: bool) -> io::Result<()> {
    let flags = if exclusive {
        LOCKFILE_EXCLUSIVE_LOCK
    } else {
        0
    } | if nonblocking {
        LOCKFILE_FAIL_IMMEDIATELY
    } else {
        0
    };
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: the constructor makes a synchronous file handle and methods serialize access.
    // The zeroed context denotes byte 0, length 1 (legal beyond EOF), with no borrowed pending I/O.
    if unsafe { LockFileEx(file.as_raw_handle(), flags, 0, 1, 0, &mut overlapped) } == 0 {
        let error = io::Error::last_os_error();
        return if error.raw_os_error() == Some(ERROR_LOCK_VIOLATION as i32) {
            Err(io::Error::new(io::ErrorKind::WouldBlock, error))
        } else {
            Err(error)
        };
    }
    Ok(())
}

fn unlock_raw(file: &File) -> io::Result<()> {
    let mut overlapped = OVERLAPPED::default();
    // SAFETY: same synchronous, retained handle and exact offset/length as lock_raw. A double
    // layer is released separately, in the EX-then-SH order specified by LockFileEx.
    if unsafe { UnlockFileEx(file.as_raw_handle(), 0, 1, 0, &mut overlapped) } == 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::local_store_security::SecureAppSupport;
    use std::ffi::OsStr;
    use std::io::{BufRead, BufReader, Read, Write};
    use std::path::Path;
    use std::process::{Child, Command, Stdio};
    use std::sync::mpsc;
    use std::time::{Duration, Instant};

    const TEST_LOCK: &str = ".maestro-schema.lock";
    const CHILD_BASE: &str = "HYDRA_WINDOWS_LEASE_CHILD_BASE";
    const CHILD_MODE: &str = "HYDRA_WINDOWS_LEASE_CHILD_MODE";

    fn lease(base: &SecureAppSupport) -> WindowsFileLock {
        WindowsFileLock::from_owner_file(
            base.open_owner_file(OsStr::new(TEST_LOCK), false).unwrap(),
        )
        .unwrap()
    }

    fn would_block(result: io::Result<()>) {
        assert_eq!(result.unwrap_err().kind(), io::ErrorKind::WouldBlock);
    }

    #[test]
    fn shared_readers_exclude_writer_until_every_lease_is_released() {
        let temp = tempfile::tempdir().unwrap();
        let base = SecureAppSupport::open(temp.path()).unwrap();
        let first = lease(&base);
        let second = lease(&base);
        let writer = lease(&base);
        first.lock_shared().unwrap();
        first.lock_shared().unwrap(); // Idempotence must not accidentally acquire SH twice.
        second.lock_shared().unwrap();
        would_block(writer.try_lock_exclusive());
        drop(first);
        would_block(writer.try_lock_exclusive());
        second.unlock().unwrap();
        second.unlock().unwrap();
        writer.try_lock_exclusive().unwrap();
    }

    #[test]
    fn exclusive_to_shared_downgrade_retains_a_reader_after_exclusive_unlock() {
        let temp = tempfile::tempdir().unwrap();
        let base = SecureAppSupport::open(temp.path()).unwrap();
        let owner = lease(&base);
        let reader = lease(&base);
        let writer = lease(&base);
        owner.lock_exclusive().unwrap();
        would_block(writer.try_lock_exclusive());
        owner.lock_shared().unwrap();
        assert_eq!(*owner.state().unwrap(), Mode::Shared);
        reader.lock_shared().unwrap();
        would_block(writer.try_lock_exclusive());
        drop(reader);
        would_block(writer.try_lock_exclusive());
        drop(owner);
        writer.try_lock_exclusive().unwrap();
    }

    #[test]
    fn native_overlap_keeps_shared_lock_through_the_first_unlock() {
        let temp = tempfile::tempdir().unwrap();
        let base = SecureAppSupport::open(temp.path()).unwrap();
        let owner = lease(&base);
        let contender = lease(&base);
        owner.lock_exclusive().unwrap();
        // Exercise the documented Windows primitive independently of the wrapper transition:
        // same-handle SH is permitted over EX; the first unlock removes only EX.
        {
            let mut mode = owner.state().unwrap();
            lock_raw(&owner.file, false, false).unwrap();
            *mode = Mode::SharedAndExclusive;
            would_block(contender.try_lock_exclusive());
            unlock_raw(&owner.file).unwrap();
            *mode = Mode::Shared;
        }
        would_block(contender.try_lock_exclusive());
        owner.unlock().unwrap();
        contender.try_lock_exclusive().unwrap();
    }

    #[test]
    fn implicit_upgrade_is_refused_without_losing_the_current_reader() {
        let temp = tempfile::tempdir().unwrap();
        let base = SecureAppSupport::open(temp.path()).unwrap();
        let owner = lease(&base);
        let contender = lease(&base);
        owner.lock_shared().unwrap();
        assert_eq!(
            owner.try_lock_exclusive().unwrap_err().kind(),
            io::ErrorKind::InvalidInput
        );
        would_block(contender.try_lock_exclusive());
        owner.unlock().unwrap();
        owner.try_lock_exclusive().unwrap();
    }

    #[test]
    fn lock_handle_pins_authority_name_and_is_not_inherited() {
        use windows_sys::Win32::Foundation::GetHandleInformation;
        let temp = tempfile::tempdir().unwrap();
        let base = SecureAppSupport::open(temp.path()).unwrap();
        let owner = lease(&base);
        owner.lock_exclusive().unwrap();
        let mut flags = 0;
        assert_ne!(
            unsafe { GetHandleInformation(owner.file.as_raw_handle(), &mut flags) },
            0
        );
        assert_eq!(flags & HANDLE_FLAG_INHERIT, 0);
        let renamed = temp.path().join("moved.lock");
        assert!(std::fs::rename(temp.path().join(TEST_LOCK), &renamed).is_err());
        drop(owner);
        std::fs::rename(temp.path().join(TEST_LOCK), renamed).unwrap();
    }

    #[test]
    fn blocking_exclusive_waiter_proceeds_after_the_last_reader_drops() {
        let temp = tempfile::tempdir().unwrap();
        let base = SecureAppSupport::open(temp.path()).unwrap();
        let owner = lease(&base);
        let waiter = lease(&base);
        owner.lock_shared().unwrap();
        let (entered, ready) = mpsc::channel();
        let (acquired, completed) = mpsc::channel();
        let thread = std::thread::spawn(move || {
            entered.send(()).unwrap();
            waiter.lock_exclusive().unwrap();
            acquired.send(()).unwrap();
        });
        ready.recv_timeout(Duration::from_secs(2)).unwrap();
        assert!(completed.recv_timeout(Duration::from_millis(50)).is_err());
        drop(owner);
        completed.recv_timeout(Duration::from_secs(2)).unwrap();
        thread.join().unwrap();
    }

    struct ProbeChild {
        process: Child,
        output: Option<std::thread::JoinHandle<()>>,
    }

    impl Drop for ProbeChild {
        fn drop(&mut self) {
            let _ = self.process.kill();
            let _ = self.process.wait();
            if let Some(output) = self.output.take() {
                let _ = output.join();
            }
        }
    }

    fn locked_child(base: &Path, mode: &str) -> ProbeChild {
        let process = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "windows_file_lock::tests::lease_child_probe",
                "--nocapture",
            ])
            .env(CHILD_BASE, base)
            .env(CHILD_MODE, mode)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let mut child = ProbeChild {
            process,
            output: None,
        };
        let stdout = child.process.stdout.take().unwrap();
        let (send, ready) = mpsc::channel();
        child.output = Some(std::thread::spawn(move || {
            for line in BufReader::new(stdout.take(4096)).lines() {
                let Ok(line) = line else {
                    break;
                };
                if line.ends_with("hydra-lease-ready") {
                    let _ = send.send(());
                }
            }
        }));
        ready
            .recv_timeout(Duration::from_secs(10))
            .expect("native lease child did not acquire its lock");
        child
    }

    #[test]
    fn lease_child_probe() {
        let Some(path) = std::env::var_os(CHILD_BASE) else {
            return;
        };
        let base = SecureAppSupport::open(Path::new(&path)).unwrap();
        let owner = lease(&base);
        match std::env::var(CHILD_MODE).unwrap().as_str() {
            "shared" => owner.lock_shared().unwrap(),
            "exclusive" => owner.lock_exclusive().unwrap(),
            _ => panic!("unknown native lease probe mode"),
        }
        println!("hydra-lease-ready");
        std::io::stdout().flush().unwrap();
        let mut exit_byte = [0];
        let _ = std::io::stdin().read(&mut exit_byte);
        // Normal EOF returns through the guard; forced process exit must rely on OS cleanup.
    }

    #[test]
    fn exact_child_process_death_releases_shared_and_exclusive_leases() {
        for mode in ["shared", "exclusive"] {
            let temp = tempfile::tempdir().unwrap();
            let base = SecureAppSupport::open(temp.path()).unwrap();
            let contender = lease(&base);
            let mut child = locked_child(temp.path(), mode);
            would_block(contender.try_lock_exclusive());
            child.process.kill().unwrap();
            child.process.wait().unwrap();
            let deadline = Instant::now() + Duration::from_secs(2);
            loop {
                match contender.try_lock_exclusive() {
                    Ok(()) => break,
                    Err(error)
                        if error.kind() == io::ErrorKind::WouldBlock
                            && Instant::now() < deadline =>
                    {
                        std::thread::sleep(Duration::from_millis(5));
                    }
                    Err(_) => panic!("native lease was not released after exact child death"),
                }
            }
        }
    }
}
