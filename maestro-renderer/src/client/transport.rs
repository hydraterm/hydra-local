//! Platform byte-stream connection and kernel peer identity; framing stays with the renderer.

#[cfg(windows)]
pub(super) use maestro_shell::WindowsPipeStream as Stream;
#[cfg(unix)]
pub(super) use std::os::unix::net::UnixStream as Stream;
#[cfg(unix)]
pub(super) use unix::{connect_until, reviewed_server_pid};

#[cfg(windows)]
pub(super) fn connect_until(
    endpoint: &str,
    deadline: std::time::Instant,
) -> std::io::Result<Stream> {
    Stream::connect_until(std::path::Path::new(endpoint), deadline)
}

#[cfg(windows)]
pub(super) fn reviewed_server_pid(stream: &Stream) -> std::io::Result<Option<u32>> {
    Ok(Some(stream.server_pid()))
}

#[cfg(windows)]
pub(super) fn process_witness_matches(
    stream: &Stream,
    witness: &maestro_shell::WindowsDaemonProcessWitness,
) -> bool {
    stream
        .daemon_process_witness()
        .matches_live(witness)
        .unwrap_or(false)
}

#[cfg(unix)]
mod unix {
    use std::io;
    use std::os::fd::{AsRawFd, FromRawFd};
    use std::os::unix::net::UnixStream;
    use std::time::Instant;

    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct LinuxPeerCredentials {
        pid: i32,
        uid: u32,
        gid: u32,
    }

    #[cfg(target_os = "linux")]
    unsafe extern "C" {
        fn geteuid() -> u32;
        fn getsockopt(
            socket: i32,
            level: i32,
            option_name: i32,
            option_value: *mut std::ffi::c_void,
            option_len: *mut u32,
        ) -> i32;
    }

    #[cfg(not(target_os = "linux"))]
    unsafe extern "C" {
        fn geteuid() -> u32;
        fn getpeereid(socket: i32, effective_uid: *mut u32, effective_gid: *mut u32) -> i32;
        fn getsockopt(
            socket: i32,
            level: i32,
            option_name: i32,
            option_value: *mut std::ffi::c_void,
            option_len: *mut u32,
        ) -> i32;
    }

    #[repr(C)]
    struct PollFd {
        fd: i32,
        events: i16,
        revents: i16,
    }

    #[cfg(target_os = "linux")]
    type PollCount = usize;
    #[cfg(not(target_os = "linux"))]
    type PollCount = u32;

    #[cfg(target_os = "linux")]
    #[repr(C)]
    struct UnixSocketAddress {
        family: u16,
        path: [i8; 108],
    }

    #[cfg(not(target_os = "linux"))]
    #[repr(C)]
    struct UnixSocketAddress {
        length: u8,
        family: u8,
        path: [i8; 104],
    }

    unsafe extern "C" {
        fn socket(domain: i32, socket_type: i32, protocol: i32) -> i32;
        fn connect(socket: i32, address: *const std::ffi::c_void, address_len: u32) -> i32;
        fn poll(fds: *mut PollFd, count: PollCount, timeout_ms: i32) -> i32;
        fn fcntl(fd: i32, command: i32, ...) -> i32;
    }

    fn effective_uid() -> u32 {
        // SAFETY: geteuid has no preconditions and cannot fail.
        unsafe { geteuid() }
    }

    /// Verify the kernel-authenticated server owner before any protocol bytes cross the socket and
    /// return the Linux peer PID used for exact handoff comparison.
    pub(crate) fn reviewed_server_pid(stream: &UnixStream) -> io::Result<Option<u32>> {
        #[cfg(target_os = "linux")]
        {
            const SOL_SOCKET: i32 = 1;
            const SO_PEERCRED: i32 = 17;
            let mut credentials = LinuxPeerCredentials {
                pid: 0,
                uid: 0,
                gid: 0,
            };
            let mut length = std::mem::size_of::<LinuxPeerCredentials>() as u32;
            // SAFETY: the stream owns a connected AF_UNIX fd and both output pointers reference
            // correctly sized live storage for Linux SO_PEERCRED.
            let status = unsafe {
                getsockopt(
                    stream.as_raw_fd(),
                    SOL_SOCKET,
                    SO_PEERCRED,
                    (&mut credentials as *mut LinuxPeerCredentials).cast(),
                    &mut length,
                )
            };
            if status != 0 {
                return Err(io::Error::last_os_error());
            }
            if length as usize != std::mem::size_of::<LinuxPeerCredentials>()
                || credentials.pid <= 0
                || credentials.uid != effective_uid()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Unix daemon peer identity was unavailable or did not match the effective uid",
                ));
            }
            Ok(Some(credentials.pid as u32))
        }

        #[cfg(not(target_os = "linux"))]
        {
            let mut uid = 0u32;
            let mut gid = 0u32;
            // SAFETY: the stream owns a connected AF_UNIX fd and both pointers reference writable ids.
            if unsafe { getpeereid(stream.as_raw_fd(), &mut uid, &mut gid) } != 0 {
                return Err(io::Error::last_os_error());
            }
            if uid != effective_uid() {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Unix daemon peer uid did not match the effective uid",
                ));
            }
            Ok(None)
        }
    }

    pub(crate) fn connect_until(socket_path: &str, deadline: Instant) -> io::Result<UnixStream> {
        const AF_UNIX: i32 = 1;
        const SOCK_STREAM: i32 = 1;
        const F_GETFD: i32 = 1;
        const F_SETFD: i32 = 2;
        const FD_CLOEXEC: i32 = 1;
        const POLLOUT: i16 = 0x0004;
        #[cfg(target_os = "linux")]
        const SOL_SOCKET: i32 = 1;
        #[cfg(not(target_os = "linux"))]
        const SOL_SOCKET: i32 = 0xffff;
        #[cfg(target_os = "linux")]
        const SO_ERROR: i32 = 4;
        #[cfg(not(target_os = "linux"))]
        const SO_ERROR: i32 = 0x1007;

        let path = socket_path.as_bytes();
        let max_path = unsafe { std::mem::zeroed::<UnixSocketAddress>() }
            .path
            .len();
        if path.is_empty() || path.len() >= max_path || path.contains(&0) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Unix daemon socket path is empty or too long",
            ));
        }
        // SAFETY: socket returns a new fd. Wrapping it immediately transfers cleanup to UnixStream on
        // every subsequent return path.
        let fd = unsafe { socket(AF_UNIX, SOCK_STREAM, 0) };
        if fd < 0 {
            return Err(io::Error::last_os_error());
        }
        let stream = unsafe { UnixStream::from_raw_fd(fd) };
        // SAFETY: fcntl reads/sets descriptor flags on this owned live fd.
        let descriptor_flags = unsafe { fcntl(fd, F_GETFD) };
        if descriptor_flags < 0 || unsafe { fcntl(fd, F_SETFD, descriptor_flags | FD_CLOEXEC) } < 0
        {
            return Err(io::Error::last_os_error());
        }
        stream.set_nonblocking(true)?;

        let mut address = unsafe { std::mem::zeroed::<UnixSocketAddress>() };
        #[cfg(target_os = "linux")]
        {
            address.family = AF_UNIX as u16;
        }
        #[cfg(not(target_os = "linux"))]
        {
            address.family = AF_UNIX as u8;
        }
        for (destination, source) in address.path.iter_mut().zip(path.iter().copied()) {
            *destination = source as i8;
        }
        let address_len = std::mem::offset_of!(UnixSocketAddress, path)
            .checked_add(path.len() + 1)
            .and_then(|length| u32::try_from(length).ok())
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "socket path overflow"))?;
        #[cfg(not(target_os = "linux"))]
        {
            address.length = u8::try_from(address_len).map_err(|_| {
                io::Error::new(io::ErrorKind::InvalidInput, "socket address overflow")
            })?;
        }
        // SAFETY: address points to a correctly initialized platform sockaddr_un prefix for address_len.
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "daemon connect deadline elapsed",
            ));
        }
        let status = unsafe {
            connect(
                fd,
                (&address as *const UnixSocketAddress).cast(),
                address_len,
            )
        };
        if status != 0 {
            let error = io::Error::last_os_error();
            #[cfg(target_os = "linux")]
            let in_progress = error.raw_os_error() == Some(115);
            #[cfg(not(target_os = "linux"))]
            let in_progress = error.raw_os_error() == Some(36);
            if !in_progress {
                return Err(error);
            }
            loop {
                let remaining =
                    deadline
                        .checked_duration_since(Instant::now())
                        .ok_or_else(|| {
                            io::Error::new(
                                io::ErrorKind::TimedOut,
                                "daemon connect deadline elapsed",
                            )
                        })?;
                let timeout_ms = remaining.as_millis().clamp(1, i32::MAX as u128) as i32;
                let mut descriptor = PollFd {
                    fd,
                    events: POLLOUT,
                    revents: 0,
                };
                // SAFETY: descriptor points to one live pollfd for the duration of this call.
                let polled = unsafe { poll(&mut descriptor, 1 as PollCount, timeout_ms) };
                if polled > 0 {
                    if Instant::now() >= deadline {
                        return Err(io::Error::new(
                            io::ErrorKind::TimedOut,
                            "daemon connect deadline elapsed",
                        ));
                    }
                    break;
                }
                if polled == 0 {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "daemon connect deadline elapsed",
                    ));
                }
                let error = io::Error::last_os_error();
                if error.kind() != io::ErrorKind::Interrupted {
                    return Err(error);
                }
            }
            let mut socket_error = 0i32;
            let mut socket_error_len = std::mem::size_of::<i32>() as u32;
            // SAFETY: socket_error and length are correctly sized outputs for SO_ERROR.
            if unsafe {
                getsockopt(
                    fd,
                    SOL_SOCKET,
                    SO_ERROR,
                    (&mut socket_error as *mut i32).cast(),
                    &mut socket_error_len,
                )
            } != 0
            {
                return Err(io::Error::last_os_error());
            }
            if socket_error != 0 {
                return Err(io::Error::from_raw_os_error(socket_error));
            }
        }
        if Instant::now() >= deadline {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "daemon connect deadline elapsed",
            ));
        }
        stream.set_nonblocking(false)?;
        Ok(stream)
    }
}

#[cfg(all(unix, test))]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::Shutdown;
    use std::os::unix::net::UnixListener;
    use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

    #[test]
    fn connected_stream_preserves_peer_timeout_clone_and_shutdown() {
        struct OwnedSocket(std::path::PathBuf);
        impl Drop for OwnedSocket {
            fn drop(&mut self) {
                let _ = std::fs::remove_file(&self.0);
            }
        }
        let nonce = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let path = std::path::PathBuf::from(format!(
            "/tmp/hydra-renderer-{}-{nonce}.sock",
            std::process::id()
        ));
        let listener = UnixListener::bind(&path).unwrap();
        let _owned_socket = OwnedSocket(path.clone());
        let mut client = connect_until(
            path.to_str().unwrap(),
            Instant::now() + Duration::from_secs(1),
        )
        .unwrap();
        let (mut server, _) = listener.accept().unwrap();
        server
            .set_read_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        let peer = reviewed_server_pid(&client).unwrap();
        assert_eq!(
            peer,
            cfg!(target_os = "linux").then_some(std::process::id())
        );
        client
            .set_write_timeout(Some(Duration::from_secs(1)))
            .unwrap();
        client.write_all(b"wire").unwrap();
        let mut bytes = [0; 4];
        server.read_exact(&mut bytes).unwrap();
        assert_eq!(&bytes, b"wire");
        let clone = client.try_clone().unwrap();
        client.set_read_timeout(None).unwrap();
        assert_eq!(client.read_timeout().unwrap(), None);
        clone.shutdown(Shutdown::Both).unwrap();
        assert_eq!(server.read(&mut bytes).unwrap(), 0);
    }

    #[test]
    fn invalid_path_and_elapsed_connect_budget_are_rejected() {
        for path in [String::new(), "x".repeat(108), "nul\0path".into()] {
            assert_eq!(
                connect_until(&path, Instant::now() + Duration::from_secs(1))
                    .unwrap_err()
                    .kind(),
                std::io::ErrorKind::InvalidInput
            );
        }
        assert_eq!(
            connect_until("unopened-fixture.sock", Instant::now())
                .unwrap_err()
                .kind(),
            std::io::ErrorKind::TimedOut
        );
    }
}
