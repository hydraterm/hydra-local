//! Peer-credential check for the daemon's Unix socket.
//!
//! The socket is already locked to mode 0600, so the filesystem keeps other UIDs
//! from connecting. This module is defense-in-depth on top of that: at accept()
//! time we read the connecting process's effective UID from the kernel and refuse
//! any peer whose UID differs from the daemon's own. That closes the window where
//! a permissions race, an inherited/passed fd, or a misconfigured runtime dir
//! could let a different user reach a socket that can spawn processes as us.
//!
//! Each platform exposes the kernel's answer through a different call —
//! `getpeereid(2)` on macOS/BSD, `getsockopt(SO_PEERCRED)` on Linux — but both
//! return the same fact: the peer's effective uid as the kernel saw it at
//! connect() time.

use std::io;
use std::os::unix::io::AsRawFd;

/// The effective UID of the process at the other end of `fd`.
///
/// `fd` must be a connected Unix-domain stream socket. Returns the kernel's view
/// of the peer's euid — it cannot be spoofed by the peer.
#[cfg(not(target_os = "linux"))]
fn peer_uid(fd: i32) -> io::Result<u32> {
    let mut uid: libc::uid_t = 0;
    let mut gid: libc::gid_t = 0;
    // SAFETY: `fd` is a valid connected socket fd for the lifetime of this call
    // (held by the caller's stream); `uid`/`gid` are valid out-params.
    let rc = unsafe { libc::getpeereid(fd, &mut uid, &mut gid) };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(uid as u32)
}

/// Linux: `SO_PEERCRED` fills a `ucred { pid, uid, gid }` with the credentials
/// captured by the kernel when the peer connected.
#[cfg(target_os = "linux")]
fn peer_uid(fd: i32) -> io::Result<u32> {
    let mut cred = libc::ucred {
        pid: 0,
        uid: 0,
        gid: 0,
    };
    let mut len = std::mem::size_of::<libc::ucred>() as libc::socklen_t;
    // SAFETY: `fd` is a valid connected socket fd for the lifetime of this call
    // (held by the caller's stream); `cred`/`len` are valid out-params sized to
    // the ucred struct the kernel writes.
    let rc = unsafe {
        libc::getsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            &mut cred as *mut libc::ucred as *mut libc::c_void,
            &mut len,
        )
    };
    if rc != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(cred.uid)
}

/// The daemon's own effective UID, matching the socket filename and ownership policy.
fn self_uid() -> u32 {
    // SAFETY: geteuid is always safe; it has no preconditions and cannot fail.
    unsafe { libc::geteuid() as u32 }
}

/// Allow the connection only if the peer's UID equals ours. Returns the peer UID
/// on success; on mismatch or a credential-read failure returns an error so the
/// caller drops the connection before processing any request.
pub fn authorize<S: AsRawFd>(stream: &S) -> io::Result<u32> {
    let ours = self_uid();
    let theirs = peer_uid(stream.as_raw_fd())?;
    if theirs != ours {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("peer uid {theirs} does not match daemon uid {ours}; refusing connection"),
        ));
    }
    Ok(theirs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::net::UnixStream;

    #[test]
    fn same_uid_peer_is_authorized() {
        // A locally-connected socketpair has both ends owned by this test process,
        // so the peer UID must equal our own and authorize() must accept it.
        let (a, _b) = UnixStream::pair().expect("socketpair");
        let uid = authorize(&a).expect("same-uid peer authorized");
        assert_eq!(uid, self_uid(), "reported peer uid is our own uid");
    }

    #[test]
    fn peer_uid_matches_self_uid_on_loopback() {
        let (a, b) = UnixStream::pair().expect("socketpair");
        assert_eq!(peer_uid(a.as_raw_fd()).unwrap(), self_uid());
        assert_eq!(peer_uid(b.as_raw_fd()).unwrap(), self_uid());
    }
}
