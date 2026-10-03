//! Explicit startup recovery. Never unlink a retained socket or signal an unverified owner.
//! The confirmation authorizes ending live programs, not deleting any durable user data.

use std::io;
use std::os::fd::{AsRawFd, OwnedFd};
use std::os::unix::fs::{FileTypeExt, MetadataExt};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

#[cfg(test)]
mod tests;

pub(super) struct RetainedRecovery {
    socket_path: PathBuf,
    socket_identity: (u64, u64),
    process: platform::Process,
}

fn refused(reason: &str) -> io::Error {
    io::Error::new(io::ErrorKind::PermissionDenied, reason)
}

fn socket_identity(path: &Path) -> io::Result<(u64, u64)> {
    let metadata = std::fs::symlink_metadata(path)?;
    // SAFETY: geteuid has no preconditions.
    if !metadata.file_type().is_socket()
        || metadata.uid() != unsafe { libc::geteuid() }
        || metadata.mode() & 0o077 != 0
    {
        return Err(refused(
            "the retained socket is not a private socket owned by this user",
        ));
    }
    Ok((metadata.dev(), metadata.ino()))
}

impl RetainedRecovery {
    pub(super) fn capture(client: &maestro_shell::DaemonClient, path: &Path) -> io::Result<Self> {
        let identity = socket_identity(path)?;
        let socket = client.duplicate_startup_peer_socket()?;
        let process = platform::Process::capture(&socket)?;
        process.verify_daemon()?;
        if socket_identity(path)? != identity {
            return Err(refused("the retained socket changed during identification"));
        }
        Ok(Self {
            socket_path: path.into(),
            socket_identity: identity,
            process,
        })
    }

    /// Call only after the user accepts the explicit live-process-loss confirmation.
    pub(super) fn stop_confirmed(self, deadline: Instant) -> io::Result<()> {
        if socket_identity(&self.socket_path)? != self.socket_identity {
            return Err(refused(
                "the retained socket changed while confirmation was open",
            ));
        }
        let client = maestro_shell::DaemonClient::connect_before(&self.socket_path, deadline)
            .map_err(|error| io::Error::other(error.to_string()))?;
        let socket = client.duplicate_startup_peer_socket()?;
        self.process.verify_peer(&socket)?;
        self.process.verify_daemon()?;
        self.process.signal(libc::SIGTERM)?;
        // Wait for the pinned process, not a reused PID or a temporarily nonaccepting listener.
        // There is deliberately no SIGKILL escalation and no app-side socket deletion.
        while !self.process.exited()? {
            if Instant::now() >= deadline {
                return Err(io::Error::new(io::ErrorKind::TimedOut,
                    "the terminal service did not finish stopping; no replacement was started. Wait for its programs to finish, then reopen Hydra"));
            }
            std::thread::sleep(
                Duration::from_millis(25).min(deadline.saturating_duration_since(Instant::now())),
            );
        }
        Ok(())
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::*;
    use std::os::fd::FromRawFd;
    use std::os::unix::ffi::OsStrExt;

    // Public libproc.h ABI. Resolve the signal API at runtime so loading the app does not require
    // macOS 15. The token includes PID incarnation, unlike kill(pid, ...).
    type Signal = unsafe extern "C" fn(*mut [u32; 8], libc::c_int) -> libc::c_int;
    unsafe extern "C" {
        fn proc_pidpath_audittoken(
            token: *mut [u32; 8],
            buffer: *mut libc::c_void,
            size: u32,
        ) -> libc::c_int;
    }

    pub(super) struct Process {
        token: [u32; 8],
        pub(super) signal: Option<Signal>,
        exit_queue: OwnedFd,
    }

    fn token(socket: &OwnedFd) -> io::Result<[u32; 8]> {
        let mut value = [0_u32; 8];
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: the connected socket and correctly sized output remain live during getsockopt.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_LOCAL,
                libc::LOCAL_PEERTOKEN,
                value.as_mut_ptr().cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        // Audit token euid and pid are fields 1 and 5 of the public audit_token_t ABI.
        if length as usize != std::mem::size_of_val(&value)
            || value[1] != unsafe { libc::geteuid() }
            || value[5] == 0
            || value[5] == std::process::id()
        {
            return Err(refused(
                "the kernel could not prove a separate same-user daemon owner",
            ));
        }
        Ok(value)
    }

    impl Process {
        pub(super) fn capture(socket: &OwnedFd) -> io::Result<Self> {
            // SAFETY: symbol is a static NUL-terminated name; no library handle is closed.
            let symbol =
                unsafe { libc::dlsym(libc::RTLD_DEFAULT, c"proc_signal_with_audittoken".as_ptr()) };
            // SAFETY: signature is the public libproc.h declaration for this exact symbol.
            let signal = (!symbol.is_null())
                .then(|| unsafe { std::mem::transmute::<*mut libc::c_void, Signal>(symbol) });
            let token = token(socket)?;
            // SAFETY: kqueue has no parameters and returns a newly owned descriptor.
            let fd = unsafe { libc::kqueue() };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            let exit_queue = unsafe { OwnedFd::from_raw_fd(fd) };
            let event = libc::kevent {
                ident: token[5] as libc::uintptr_t,
                filter: libc::EVFILT_PROC,
                flags: libc::EV_ADD | libc::EV_ENABLE,
                fflags: libc::NOTE_EXIT,
                data: 0,
                udata: std::ptr::null_mut(),
            };
            // SAFETY: one initialized registration; no output list or timeout is requested.
            if unsafe { libc::kevent(fd, &event, 1, std::ptr::null_mut(), 0, std::ptr::null()) } < 0
            {
                return Err(io::Error::last_os_error());
            }
            let process = Self {
                token,
                signal,
                exit_queue,
            };
            process.verify_peer(socket)?;
            process.verify_daemon()?;
            Ok(process)
        }

        pub(super) fn verify_peer(&self, socket: &OwnedFd) -> io::Result<()> {
            if token(socket)? != self.token {
                return Err(refused("the terminal service owner changed"));
            }
            Ok(())
        }

        pub(super) fn verify_daemon(&self) -> io::Result<()> {
            let mut path = [0_u8; 4096];
            let mut token = self.token;
            // SAFETY: proc_pidpath_audittoken validates PID incarnation and writes at most size bytes.
            let length = unsafe {
                proc_pidpath_audittoken(&mut token, path.as_mut_ptr().cast(), path.len() as u32)
            };
            if length <= 0 {
                return Err(io::Error::last_os_error());
            }
            let length = path
                .iter()
                .position(|byte| *byte == 0)
                .unwrap_or(path.len());
            if Path::new(std::ffi::OsStr::from_bytes(&path[..length])).file_name()
                != Some(std::ffi::OsStr::new("pty-daemon"))
            {
                return Err(refused(
                    "the socket owner is not a Hydra pty-daemon executable",
                ));
            }
            Ok(())
        }

        pub(super) fn signal(&self, signal: i32) -> io::Result<()> {
            let Some(send) = self.signal else {
                // macOS11–14 lacks the incarnation-conditional signal API. Recheck the audit-
                // token-bound executable immediately before the one user-authorized SIGTERM.
                // A residual check-to-kill PID-reuse race exists here; do not claim atomic pinning.
                self.verify_daemon()?;
                if self.exited()? {
                    return Err(io::Error::from_raw_os_error(libc::ESRCH));
                }
                // SAFETY: positive same-user PID identified from this exact socket and revalidated.
                if unsafe { libc::kill(self.token[5] as libc::pid_t, signal) } != 0 {
                    return Err(io::Error::last_os_error());
                }
                return Ok(());
            };
            let mut token = self.token;
            // SAFETY: token captured from the kernel; API atomically checks its PID incarnation.
            // Unlike kill, this libproc API returns the errno value directly.
            let error = unsafe { send(&mut token, signal) };
            if error != 0 {
                return Err(io::Error::from_raw_os_error(error));
            }
            Ok(())
        }

        pub(super) fn exited(&self) -> io::Result<bool> {
            let mut event: libc::kevent = unsafe { std::mem::zeroed() };
            let timeout = libc::timespec {
                tv_sec: 0,
                tv_nsec: 0,
            };
            // SAFETY: one correctly sized event output and a zero/nonblocking timeout.
            let count = unsafe {
                libc::kevent(
                    self.exit_queue.as_raw_fd(),
                    std::ptr::null(),
                    0,
                    &mut event,
                    1,
                    &timeout,
                )
            };
            if count < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(count > 0 && event.fflags & libc::NOTE_EXIT != 0)
        }
    }
}

#[cfg(target_os = "linux")]
mod platform {
    use super::*;
    use std::os::fd::FromRawFd;

    pub(super) struct Process {
        pid: libc::pid_t,
        birth: String,
        handle: OwnedFd,
    }

    fn peer(socket: &OwnedFd) -> io::Result<libc::pid_t> {
        let mut value: libc::ucred = unsafe { std::mem::zeroed() };
        let mut length = std::mem::size_of_val(&value) as libc::socklen_t;
        // SAFETY: correctly sized writable credentials on a live connected socket.
        let result = unsafe {
            libc::getsockopt(
                socket.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_PEERCRED,
                (&mut value as *mut libc::ucred).cast(),
                &mut length,
            )
        };
        if result != 0 {
            return Err(io::Error::last_os_error());
        }
        if length as usize != std::mem::size_of_val(&value)
            || value.pid <= 0
            || value.uid != unsafe { libc::geteuid() }
            || value.pid as u32 == std::process::id()
        {
            return Err(refused(
                "the kernel could not prove a separate same-user daemon owner",
            ));
        }
        Ok(value.pid)
    }

    fn birth(pid: libc::pid_t) -> io::Result<String> {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat"))?;
        // comm may contain spaces and parentheses. The final ')' precedes field 3; starttime is22.
        stat.rsplit_once(')')
            .and_then(|(_, rest)| rest.split_whitespace().nth(19))
            .map(str::to_owned)
            .ok_or_else(|| refused("invalid retained-process birth identity"))
    }

    impl Process {
        pub(super) fn capture(socket: &OwnedFd) -> io::Result<Self> {
            let pid = peer(socket)?;
            let birth = birth(pid)?;
            // SAFETY: opens only a kernel process reference; never signals by PID. Linux5.3+.
            let fd = unsafe { libc::syscall(libc::SYS_pidfd_open, pid, 0_u32) };
            if fd < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: successful pidfd_open transfers one fresh owned descriptor.
            let process = Self {
                pid,
                birth,
                handle: unsafe { OwnedFd::from_raw_fd(fd as i32) },
            };
            process.verify_peer(socket)?;
            process.verify_daemon()?;
            Ok(process)
        }

        pub(super) fn verify_peer(&self, socket: &OwnedFd) -> io::Result<()> {
            if peer(socket)? != self.pid || birth(self.pid)? != self.birth || self.exited()? {
                return Err(refused("the terminal service owner changed"));
            }
            Ok(())
        }

        pub(super) fn verify_daemon(&self) -> io::Result<()> {
            let executable = std::fs::read_link(format!("/proc/{}/exe", self.pid))?;
            let name = executable.file_name().and_then(|name| name.to_str());
            if !matches!(name, Some("pty-daemon" | "pty-daemon (deleted)"))
                || birth(self.pid)? != self.birth
                || self.exited()?
            {
                return Err(refused(
                    "the socket owner is not the identified Hydra pty-daemon executable",
                ));
            }
            Ok(())
        }

        pub(super) fn signal(&self, signal: i32) -> io::Result<()> {
            // SAFETY: signals only our held process descriptor, never a reused numeric PID.
            let result = unsafe {
                libc::syscall(
                    libc::SYS_pidfd_send_signal,
                    self.handle.as_raw_fd(),
                    signal,
                    std::ptr::null::<libc::siginfo_t>(),
                    0_u32,
                )
            };
            if result < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(())
        }

        pub(super) fn exited(&self) -> io::Result<bool> {
            let mut fd = libc::pollfd {
                fd: self.handle.as_raw_fd(),
                events: libc::POLLIN,
                revents: 0,
            };
            // SAFETY: one correctly sized pollfd; a zero timeout is nonblocking.
            if unsafe { libc::poll(&mut fd, 1, 0) } < 0 {
                return Err(io::Error::last_os_error());
            }
            Ok(fd.revents & (libc::POLLIN | libc::POLLHUP) != 0)
        }
    }
}
