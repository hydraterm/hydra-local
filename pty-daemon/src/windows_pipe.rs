//! Windows local transport for the PTY authority.
//!
//! A connection can start arbitrary processes as the daemon account, so a discoverable pipe name
//! is never its security boundary. Every instance is created with a protected DACL containing only
//! the current Windows user SID, rejects remote clients, and authenticates the connected client's
//! user SID, elevation, and integrity level before any protocol byte is parsed or acted upon.
//! `FILE_FLAG_FIRST_PIPE_INSTANCE` on the first listener preserves the Unix split-brain invariant
//! without a stale filesystem endpoint.

use sha2::{Digest as _, Sha256};
use std::ffi::{c_void, OsString};
use std::io;
use std::mem::size_of;
use std::os::windows::io::AsRawHandle;
use std::ptr::null_mut;
use std::time::Duration;
use tokio::io::AsyncReadExt as _;
use tokio::net::windows::named_pipe::{NamedPipeServer, ServerOptions};
use windows_sys::Win32::Foundation::{CloseHandle, LocalFree, HANDLE};
use windows_sys::Win32::Security::Authorization::{
    ConvertSidToStringSidW, ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
};
use windows_sys::Win32::Security::{
    CopySid, EqualSid, GetLengthSid, GetTokenInformation, RevertToSelf, TokenElevation,
    TokenIntegrityLevel, TokenUser, PSID, SECURITY_ATTRIBUTES, TOKEN_ELEVATION,
    TOKEN_MANDATORY_LABEL, TOKEN_QUERY, TOKEN_USER,
};
use windows_sys::Win32::System::Pipes::ImpersonateNamedPipeClient;
use windows_sys::Win32::System::Threading::{
    GetCurrentProcess, GetCurrentThread, OpenProcessToken, OpenThreadToken,
};

const LOCAL_PIPE_PREFIX: &str = r"\\.\pipe\";
const PIPE_STEM: &str = "Hydra.Maestro.";
const MAX_PIPE_NAME_UTF16: usize = 256;
const AUTHENTICATION_BYTE_TIMEOUT: Duration = Duration::from_secs(5);

/// Aligned owned storage for one copied SID. Keeping a copy means no pointer escapes the token
/// information buffer returned by Windows.
struct OwnedSid {
    words: Vec<usize>,
    byte_len: u32,
}

impl OwnedSid {
    fn copy_from(sid: PSID, missing_message: &'static str) -> io::Result<Self> {
        if sid.is_null() {
            return Err(io::Error::new(io::ErrorKind::InvalidData, missing_message));
        }
        let sid_len = unsafe { GetLengthSid(sid) };
        if sid_len == 0 {
            return Err(io::Error::last_os_error());
        }
        let sid_word_count = (sid_len as usize)
            .checked_add(size_of::<usize>() - 1)
            .and_then(|bytes| bytes.checked_div(size_of::<usize>()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "SID size overflow"))?;
        let mut words = vec![0usize; sid_word_count];
        if unsafe { CopySid(sid_len, words.as_mut_ptr().cast(), sid) } == 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            words,
            byte_len: sid_len,
        })
    }

    fn from_token(token: HANDLE) -> io::Result<Self> {
        let mut needed = 0u32;
        // The first call intentionally supplies no buffer and obtains the exact byte count.
        unsafe {
            GetTokenInformation(token, TokenUser, null_mut(), 0, &mut needed);
        }
        if needed < size_of::<TOKEN_USER>() as u32 {
            return Err(io::Error::last_os_error());
        }

        let word_count = (needed as usize)
            .checked_add(size_of::<usize>() - 1)
            .and_then(|bytes| bytes.checked_div(size_of::<usize>()))
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "token SID size overflow"))?;
        let mut token_words = vec![0usize; word_count];
        if unsafe {
            GetTokenInformation(
                token,
                TokenUser,
                token_words.as_mut_ptr().cast(),
                needed,
                &mut needed,
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }

        // `token_words` has pointer alignment, and GetTokenInformation wrote a TOKEN_USER at its
        // beginning. Its SID pointer remains valid until this temporary buffer is dropped.
        let user = unsafe { &*(token_words.as_ptr().cast::<TOKEN_USER>()) };
        Self::copy_from(user.User.Sid, "Windows token did not contain a user SID")
    }

    fn current_process() -> io::Result<Self> {
        let mut token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);
        Self::from_token(token.0)
    }

    fn as_ptr(&self) -> PSID {
        self.words.as_ptr() as *mut c_void
    }

    fn to_string(&self) -> io::Result<String> {
        debug_assert!(self.byte_len > 0);
        let mut raw = null_mut();
        if unsafe { ConvertSidToStringSidW(self.as_ptr(), &mut raw) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let raw = LocalWideString(raw);
        let mut len = 0usize;
        // ConvertSidToStringSidW returns a NUL-terminated LocalAlloc buffer.
        while unsafe { *raw.0.add(len) } != 0 {
            len = len.checked_add(1).ok_or_else(|| {
                io::Error::new(io::ErrorKind::InvalidData, "SID string length overflow")
            })?;
        }
        String::from_utf16(unsafe { std::slice::from_raw_parts(raw.0, len) }).map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Windows returned a non-Unicode SID string",
            )
        })
    }
}

/// The token fields Hydra compares before accepting a same-account peer. This prevents the normal
/// UAC elevation/integrity boundary from being crossed through the daemon; it is deliberately not
/// described as full token equivalence or a child-process sandbox.
struct TokenAuthority {
    user_sid: OwnedSid,
    integrity_sid: OwnedSid,
    is_elevated: bool,
}

impl TokenAuthority {
    fn from_token(token: HANDLE) -> io::Result<Self> {
        Ok(Self {
            user_sid: OwnedSid::from_token(token)?,
            integrity_sid: token_integrity_sid(token)?,
            is_elevated: token_is_elevated(token)?,
        })
    }

    fn current_process() -> io::Result<Self> {
        let mut token = null_mut();
        if unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);
        Self::from_token(token.0)
    }

    fn matches(&self, observed: &Self) -> bool {
        (unsafe { EqualSid(self.user_sid.as_ptr(), observed.user_sid.as_ptr()) } != 0)
            && self.is_elevated == observed.is_elevated
            && (unsafe { EqualSid(self.integrity_sid.as_ptr(), observed.integrity_sid.as_ptr()) }
                != 0)
    }
}

fn token_is_elevated(token: HANDLE) -> io::Result<bool> {
    let mut elevation = TOKEN_ELEVATION::default();
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            TokenElevation,
            (&mut elevation as *mut TOKEN_ELEVATION).cast(),
            size_of::<TOKEN_ELEVATION>() as u32,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned < size_of::<TOKEN_ELEVATION>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned truncated token elevation information",
        ));
    }
    Ok(elevation.TokenIsElevated != 0)
}

fn token_integrity_sid(token: HANDLE) -> io::Result<OwnedSid> {
    let mut needed = 0u32;
    // TokenIntegrityLevel is variable-sized because TOKEN_MANDATORY_LABEL points at an integrity
    // SID in the same returned buffer. Obtain an aligned buffer, then copy that SID before the
    // token-information storage is released.
    unsafe {
        GetTokenInformation(token, TokenIntegrityLevel, null_mut(), 0, &mut needed);
    }
    if needed < size_of::<TOKEN_MANDATORY_LABEL>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned no token integrity information",
        ));
    }
    let word_count = (needed as usize)
        .checked_add(size_of::<usize>() - 1)
        .and_then(|bytes| bytes.checked_div(size_of::<usize>()))
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "token integrity size overflow")
        })?;
    let mut words = vec![0usize; word_count];
    let buffer_bytes = words
        .len()
        .checked_mul(size_of::<usize>())
        .and_then(|bytes| u32::try_from(bytes).ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidData, "token integrity size overflow")
        })?;
    let mut returned = 0u32;
    if unsafe {
        GetTokenInformation(
            token,
            TokenIntegrityLevel,
            words.as_mut_ptr().cast(),
            buffer_bytes,
            &mut returned,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    if returned < size_of::<TOKEN_MANDATORY_LABEL>() as u32 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Windows returned truncated token integrity information",
        ));
    }

    let label = unsafe { &*(words.as_ptr().cast::<TOKEN_MANDATORY_LABEL>()) };
    OwnedSid::copy_from(
        label.Label.Sid,
        "Windows token did not contain an integrity SID",
    )
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                CloseHandle(self.0);
            }
        }
    }
}

struct LocalWideString(*mut u16);

impl Drop for LocalWideString {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0.cast());
            }
        }
    }
}

struct LocalSecurityDescriptor(*mut c_void);

impl LocalSecurityDescriptor {
    fn for_user(sid: &str) -> io::Result<Self> {
        // Protected DACL, one full-access ACE, no broad defaults. SYSTEM is deliberately absent:
        // no system service has authority over this per-user process launcher in this milestone.
        let sddl = format!("D:P(A;;GA;;;{sid})");
        let encoded: Vec<u16> = sddl.encode_utf16().chain(std::iter::once(0)).collect();
        let mut descriptor = null_mut();
        if unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                encoded.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                null_mut(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error());
        }
        Ok(Self(descriptor))
    }
}

impl Drop for LocalSecurityDescriptor {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                LocalFree(self.0);
            }
        }
    }
}

/// Owns the protected current-user-only descriptor behind a Win32
/// `SECURITY_ATTRIBUTES` value. The descriptor allocation remains live for every syscall that
/// receives [`as_ptr`](Self::as_ptr); Windows copies it into the newly-created kernel object.
///
/// ConPTY uses this too for its short-lived private transport pipes. Keeping one constructor here
/// prevents the daemon authority pipe and the terminal transport from drifting to different ACLs.
pub(crate) struct CurrentUserSecurityAttributes {
    _descriptor: LocalSecurityDescriptor,
    attributes: SECURITY_ATTRIBUTES,
}

impl CurrentUserSecurityAttributes {
    fn for_sid(sid: &str) -> io::Result<Self> {
        let descriptor = LocalSecurityDescriptor::for_user(sid)?;
        let attributes = SECURITY_ATTRIBUTES {
            nLength: size_of::<SECURITY_ATTRIBUTES>() as u32,
            lpSecurityDescriptor: descriptor.0,
            bInheritHandle: 0,
        };
        Ok(Self {
            _descriptor: descriptor,
            attributes,
        })
    }

    pub(crate) fn as_ptr(&mut self) -> *mut SECURITY_ATTRIBUTES {
        &mut self.attributes
    }
}

/// Derive a stable per-user endpoint from the kernel user SID. The SID is not treated as a secret;
/// the protected DACL and peer-token authority comparison are the authority checks.
pub fn default_pipe_name() -> io::Result<OsString> {
    let sid = OwnedSid::current_process()?.to_string()?;
    let scope = pipe_scope_for_sid(&sid);
    validate_local_pipe_name(format!("{LOCAL_PIPE_PREFIX}{PIPE_STEM}{scope}").into())
}

fn pipe_scope_for_sid(sid: &str) -> String {
    // v2 deliberately does not collide with pre-retirement-barrier foundation daemons. A client
    // on this endpoint may therefore rely on Windows start-operation tombstones during recovery.
    let digest = Sha256::digest(format!("hydra-maestro-windows-user-v2\0{sid}").as_bytes());
    let mut scope = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut scope, "{byte:02x}").expect("writing to String cannot fail");
    }
    scope
}

/// Reject remote, ambiguous, overlong, or path-like explicit endpoints before calling Win32.
/// Explicit names exist for isolated tests and future launcher handoff, but remain in the local
/// named-pipe namespace and use a deliberately narrow suffix alphabet.
pub fn validate_local_pipe_name(name: OsString) -> io::Result<OsString> {
    let value = name.into_string().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "named-pipe endpoint must be valid Unicode",
        )
    })?;
    let prefix = value.get(..LOCAL_PIPE_PREFIX.len()).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            r"named-pipe endpoint must begin with \\.\pipe\",
        )
    })?;
    let suffix = &value[LOCAL_PIPE_PREFIX.len()..];
    let scope = suffix.strip_prefix(PIPE_STEM);
    let utf16_len = value.encode_utf16().count();
    if !prefix.eq_ignore_ascii_case(LOCAL_PIPE_PREFIX)
        || scope.is_none_or(str::is_empty)
        || utf16_len > MAX_PIPE_NAME_UTF16
        || !suffix
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-' | b'_'))
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "named-pipe endpoint is not a canonical local Hydra endpoint",
        ));
    }
    Ok(OsString::from(value))
}

fn create_server(
    pipe_name: &OsString,
    sid_string: &str,
    first: bool,
) -> io::Result<NamedPipeServer> {
    let mut security = CurrentUserSecurityAttributes::for_sid(sid_string)?;
    let mut options = ServerOptions::new();
    options
        .first_pipe_instance(first)
        .reject_remote_clients(true)
        .in_buffer_size(64 * 1024)
        .out_buffer_size(64 * 1024);
    // The descriptor and SECURITY_ATTRIBUTES remain live for the complete CreateNamedPipeW call;
    // Windows copies the security descriptor into the new kernel object before returning.
    unsafe { options.create_with_security_attributes_raw(pipe_name, security.as_ptr().cast()) }
}

fn connected_client_authority(pipe: &NamedPipeServer) -> io::Result<TokenAuthority> {
    let handle = pipe.as_raw_handle() as HANDLE;
    if unsafe { ImpersonateNamedPipeClient(handle) } == 0 {
        return Err(io::Error::last_os_error());
    }

    // No await or callback is permitted while this thread impersonates the client. Always revert
    // before returning, including when opening or reading the token fails.
    let result = (|| {
        let mut token = null_mut();
        if unsafe { OpenThreadToken(GetCurrentThread(), TOKEN_QUERY, 1, &mut token) } == 0 {
            return Err(io::Error::last_os_error());
        }
        let token = OwnedHandle(token);
        TokenAuthority::from_token(token.0)
    })();
    if unsafe { RevertToSelf() } == 0 {
        // Continuing this Tokio worker would let unrelated tasks run under a client's token.
        // Microsoft explicitly requires process termination when RevertToSelf fails. `abort`
        // avoids formatting, logging, allocation, or unwinding while still impersonating.
        std::process::abort();
    }
    result
}

fn authorize_client(pipe: &NamedPipeServer, expected: &TokenAuthority) -> io::Result<bool> {
    let observed = connected_client_authority(pipe)?;
    Ok(expected.matches(&observed))
}

/// One-daemon listener factory. The first handle remains alive while subsequent instances are
/// created, so another process requesting FIRST_PIPE_INSTANCE fails rather than splitting session
/// authority. Each accepted client is authenticated before it reaches the protocol parser.
pub struct Listener {
    pipe_name: OsString,
    sid_string: String,
    pending: NamedPipeServer,
}

impl Listener {
    pub fn bind(pipe_name: OsString) -> io::Result<Self> {
        let sid = OwnedSid::current_process()?;
        let sid_string = sid.to_string()?;
        let pending = create_server(&pipe_name, &sid_string, true)?;
        Ok(Self {
            pipe_name,
            sid_string,
            pending,
        })
    }

    pub async fn accept(&mut self) -> io::Result<NamedPipeServer> {
        // Keep the instance owned by `self` across the only await. `run_platform` selects this
        // future against handler completion and shutdown; cancellation must therefore leave a
        // usable listener behind. Tokio documents `NamedPipeServer::connect` itself as cancellation
        // safe, so a later call resumes without losing a connection event.
        self.pending.connect().await?;

        // Publish the next waiting instance before dispatching this connection for authentication.
        // A silent client therefore cannot block the accept loop or split retained-session authority.
        // If replacement creation fails, the connected first-instance handle remains alive until
        // this function returns and the caller treats the listener failure as fatal.
        let replacement = create_server(&self.pipe_name, &self.sid_string, false)?;
        Ok(std::mem::replace(&mut self.pending, replacement))
    }
}

/// Establish the client token context with one bounded read, compare its user SID, elevation, and
/// integrity level to the daemon token, and return the consumed byte for exact replay into the
/// protocol reader. Windows defines named-pipe impersonation in terms of the last message read by
/// the server, so authenticating immediately after `ConnectNamedPipe` is insufficient. No protocol
/// byte is parsed before this succeeds.
pub async fn authenticate_client(
    mut pipe: NamedPipeServer,
) -> io::Result<(NamedPipeServer, [u8; 1])> {
    let mut first_byte = [0u8; 1];
    let read = tokio::time::timeout(
        AUTHENTICATION_BYTE_TIMEOUT,
        pipe.read_exact(&mut first_byte),
    )
    .await
    .map_err(|_| {
        io::Error::new(
            io::ErrorKind::TimedOut,
            "named-pipe client sent no authentication byte before the deadline",
        )
    })?;
    read?;

    let expected = TokenAuthority::current_process()?;
    if !authorize_client(&pipe, &expected)? {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "named-pipe client token authority did not match the daemon token authority",
        ));
    }
    Ok((pipe, first_byte))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::net::windows::named_pipe::ClientOptions;

    fn unique_test_pipe(tag: &str) -> OsString {
        format!(
            r"\\.\pipe\Hydra.Maestro.test-{tag}-{}-{}",
            std::process::id(),
            uuid::Uuid::new_v4().simple()
        )
        .into()
    }

    fn test_integrity_sid(rid: u32) -> OwnedSid {
        use windows_sys::Win32::Security::{SECURITY_MANDATORY_LABEL_AUTHORITY, SID};

        let mut sid = SID {
            Revision: 1,
            SubAuthorityCount: 1,
            IdentifierAuthority: SECURITY_MANDATORY_LABEL_AUTHORITY,
            SubAuthority: [rid],
        };
        OwnedSid::copy_from((&mut sid as *mut SID).cast(), "test integrity SID")
            .expect("copy synthetic integrity SID")
    }

    fn test_authority(is_elevated: bool, integrity_rid: u32) -> TokenAuthority {
        TokenAuthority {
            user_sid: OwnedSid::current_process().expect("current process SID"),
            integrity_sid: test_integrity_sid(integrity_rid),
            is_elevated,
        }
    }

    #[test]
    fn windows_explicit_endpoint_must_be_local_and_canonical() {
        assert!(validate_local_pipe_name(r"\\.\pipe\Hydra.Maestro.test-1".into()).is_ok());
        assert!(validate_local_pipe_name(r"\\server\pipe\Hydra.Maestro.test".into()).is_err());
        assert!(validate_local_pipe_name(r"\\.\pipe\nested\name".into()).is_err());
        assert!(validate_local_pipe_name(r"\\.\pipe\".into()).is_err());
    }

    #[tokio::test]
    async fn windows_listener_accept_is_cancellation_safe() {
        let name = unique_test_pipe("cancelled-accept");
        let mut listener = Listener::bind(name.clone()).expect("bind test listener");

        assert!(
            tokio::time::timeout(Duration::from_millis(20), listener.accept())
                .await
                .is_err(),
            "an unconnected listener unexpectedly completed its first accept"
        );

        let client = ClientOptions::new()
            .open(&name)
            .expect("connect after cancelling the pending accept");
        let accepted = tokio::time::timeout(Duration::from_secs(2), listener.accept())
            .await
            .expect("listener did not recover from a cancelled accept")
            .expect("accept after cancellation failed");
        drop(accepted);
        drop(client);
    }

    #[test]
    fn windows_default_endpoint_is_user_scoped_local_pipe() {
        let name = default_pipe_name().expect("current process has a user SID");
        let name = name.to_string_lossy();
        let scope = name
            .strip_prefix(r"\\.\pipe\Hydra.Maestro.")
            .expect("canonical Hydra pipe prefix");
        assert_eq!(scope.len(), 64);
        assert!(scope.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn windows_default_endpoint_scope_matches_client_golden_vector() {
        assert_eq!(
            pipe_scope_for_sid("S-1-5-21-1-2-3-1001"),
            "81b527c1d181b5008810262ee7dbcc01fdc5340d320fa612b306318e5b8bc24e"
        );
    }

    #[test]
    fn windows_current_process_token_authority_is_readable_and_self_matching() {
        let expected = TokenAuthority::current_process().expect("current process token authority");
        let observed = TokenAuthority::current_process().expect("current process token authority");
        assert!(expected.matches(&observed));
    }

    #[test]
    fn windows_token_authority_requires_user_elevation_and_integrity_match() {
        const LOW_INTEGRITY_RID: u32 = 0x1000;
        const MEDIUM_INTEGRITY_RID: u32 = 0x2000;

        let expected = test_authority(false, MEDIUM_INTEGRITY_RID);
        assert!(expected.matches(&test_authority(false, MEDIUM_INTEGRITY_RID)));

        let wrong_user = TokenAuthority {
            user_sid: test_integrity_sid(MEDIUM_INTEGRITY_RID),
            integrity_sid: test_integrity_sid(MEDIUM_INTEGRITY_RID),
            is_elevated: false,
        };
        assert!(!expected.matches(&wrong_user));
        assert!(!expected.matches(&test_authority(true, MEDIUM_INTEGRITY_RID)));
        assert!(!expected.matches(&test_authority(false, LOW_INTEGRITY_RID)));
    }

    #[test]
    fn windows_generated_descriptor_is_protected_and_grants_only_the_current_user() {
        use windows_sys::Win32::Security::{
            AclSizeInformation, GetAce, GetAclInformation, GetSecurityDescriptorControl,
            GetSecurityDescriptorDacl, ACCESS_ALLOWED_ACE, ACL_SIZE_INFORMATION, SE_DACL_PROTECTED,
        };

        let expected = OwnedSid::current_process().expect("current process SID");
        let descriptor =
            LocalSecurityDescriptor::for_user(&expected.to_string().expect("SID string"))
                .expect("protected descriptor");
        let mut present = 0;
        let mut defaulted = 0;
        let mut acl = null_mut();
        assert_ne!(
            unsafe {
                GetSecurityDescriptorDacl(descriptor.0, &mut present, &mut acl, &mut defaulted)
            },
            0
        );
        assert_ne!(present, 0, "descriptor must contain a DACL");
        assert_eq!(defaulted, 0, "DACL must be explicit, not defaulted");
        assert!(!acl.is_null(), "a null DACL would grant universal access");

        let mut size = ACL_SIZE_INFORMATION::default();
        assert_ne!(
            unsafe {
                GetAclInformation(
                    acl,
                    (&mut size as *mut ACL_SIZE_INFORMATION).cast(),
                    size_of::<ACL_SIZE_INFORMATION>() as u32,
                    AclSizeInformation,
                )
            },
            0
        );
        assert_eq!(size.AceCount, 1, "DACL must contain exactly one ACE");

        let mut raw_ace = null_mut();
        assert_ne!(unsafe { GetAce(acl, 0, &mut raw_ace) }, 0);
        let ace = unsafe { &*raw_ace.cast::<ACCESS_ALLOWED_ACE>() };
        assert_eq!(ace.Header.AceType, 0, "the sole ACE must be access-allowed");
        let ace_sid = std::ptr::addr_of!(ace.SidStart) as PSID;
        assert_ne!(
            unsafe { EqualSid(expected.as_ptr(), ace_sid) },
            0,
            "the sole ACE must name the exact current user SID"
        );

        let mut control = 0u16;
        let mut revision = 0u32;
        assert_ne!(
            unsafe { GetSecurityDescriptorControl(descriptor.0, &mut control, &mut revision) },
            0
        );
        assert_ne!(control & SE_DACL_PROTECTED, 0, "DACL must be protected");
    }
}
