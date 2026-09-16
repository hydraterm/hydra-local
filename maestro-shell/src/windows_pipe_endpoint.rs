//! Current-user Windows daemon endpoint discovery, with no connection or process mutation.
//! Keeps the preserved Windows server's namespace and v2 scope bytes.
//! Win32 naming contract: https://learn.microsoft.com/en-us/windows/win32/ipc/pipe-names

use sha2::{Digest as _, Sha256};
use std::ffi::{OsStr, OsString};
use std::io;
use std::path::PathBuf;

#[cfg(windows)]
use crate::windows_identity::OwnedSid;

const LOCAL_PIPE_PREFIX: &str = r"\\.\pipe\";
const PIPE_STEM: &str = "Hydra.Maestro.";
const MAX_PIPE_NAME_UTF16: usize = 256;

/// Reject remote, path-like, non-Unicode, or overlong endpoints before calling Win32.
pub(crate) fn validate_local_pipe_name(name: &OsStr) -> io::Result<OsString> {
    let value = name.to_str().ok_or_else(|| {
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
    if !prefix.eq_ignore_ascii_case(LOCAL_PIPE_PREFIX)
        || scope.is_none_or(str::is_empty)
        || value.encode_utf16().count() > MAX_PIPE_NAME_UTF16
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

/// Return the same stable, privacy-preserving current-user pipe name as `pty-daemon.exe`.
#[cfg(windows)]
pub(crate) fn default_pipe_name() -> io::Result<PathBuf> {
    default_pipe_name_with_sid(|| OwnedSid::current_process()?.to_string())
}

fn default_pipe_name_with_sid(
    read_sid: impl FnOnce() -> io::Result<String>,
) -> io::Result<PathBuf> {
    let scope = pipe_scope_for_sid(&read_sid()?);
    let name = format!("{LOCAL_PIPE_PREFIX}{PIPE_STEM}{scope}");
    validate_local_pipe_name(OsStr::new(&name)).map(PathBuf::from)
}

fn pipe_scope_for_sid(sid: &str) -> String {
    // v2 isolates this client from pre-retirement-barrier foundation daemons. The protocol can
    // safely treat an acknowledged Windows tombstone as a late-Reserve/Start barrier.
    let digest = Sha256::digest(format!("hydra-maestro-windows-user-v2\0{sid}").as_bytes());
    let mut scope = String::with_capacity(digest.len() * 2);
    for byte in digest {
        use std::fmt::Write as _;
        write!(&mut scope, "{byte:02x}").expect("writing to String cannot fail");
    }
    scope
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use std::os::windows::ffi::OsStringExt as _;

    #[test]
    fn windows_pipe_name_validation_rejects_remote_and_path_like_names() {
        assert!(validate_local_pipe_name(OsStr::new(r"\\.\pipe\Hydra.Maestro.test-1")).is_ok());
        assert!(validate_local_pipe_name(OsStr::new(r"\\server\pipe\Hydra.Maestro.test")).is_err());
        assert!(validate_local_pipe_name(OsStr::new(r"\\.\pipe\nested\name")).is_err());
        assert!(validate_local_pipe_name(OsStr::new(r"\\.\pipe\")).is_err());
        assert!(validate_local_pipe_name(OsStr::new(r"\\.\pipe\Hydra.Other.test")).is_err());
        assert!(
            validate_local_pipe_name(OsStr::new("\\\\.\\pipe\\Hydra.Maestro.test\nname")).is_err()
        );

        #[cfg(windows)]
        {
            let non_unicode = OsString::from_wide(&[0xd800]);
            assert!(validate_local_pipe_name(&non_unicode).is_err());
        }
    }

    #[test]
    fn windows_pipe_name_validation_enforces_utf16_boundary() {
        let fixed = format!("{LOCAL_PIPE_PREFIX}{PIPE_STEM}");
        let fixed_len = fixed.encode_utf16().count();
        let at_limit = format!("{fixed}{}", "a".repeat(MAX_PIPE_NAME_UTF16 - fixed_len));
        assert_eq!(at_limit.encode_utf16().count(), MAX_PIPE_NAME_UTF16);
        assert!(validate_local_pipe_name(OsStr::new(&at_limit)).is_ok());

        let over_limit = format!("{at_limit}a");
        assert!(validate_local_pipe_name(OsStr::new(&over_limit)).is_err());
    }

    #[test]
    fn windows_pipe_scope_matches_daemon_golden_vector() {
        assert_eq!(
            pipe_scope_for_sid("S-1-5-21-1-2-3-1001"),
            "81b527c1d181b5008810262ee7dbcc01fdc5340d320fa612b306318e5b8bc24e"
        );
    }

    #[cfg(windows)]
    #[test]
    fn windows_default_pipe_is_stable_and_user_scoped() {
        let first = default_pipe_name().unwrap();
        let second = default_pipe_name().unwrap();
        assert_eq!(first, second);
        let value = first.to_string_lossy();
        let scope = value.strip_prefix(r"\\.\pipe\Hydra.Maestro.").unwrap();
        assert_eq!(scope.len(), 64);
        assert!(scope.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }
    #[test]
    fn sid_lookup_failure_is_returned_without_a_fallback_or_panic() {
        let error =
            default_pipe_name_with_sid(|| Err(io::Error::from_raw_os_error(5))).unwrap_err();
        assert_eq!(error.raw_os_error(), Some(5));
        let sid = "S-1-5-21-1-2-3-1001";
        let expected = format!("{LOCAL_PIPE_PREFIX}{PIPE_STEM}{}", pipe_scope_for_sid(sid));
        assert_eq!(
            default_pipe_name_with_sid(|| Ok(sid.into())).unwrap(),
            PathBuf::from(expected)
        );
    }
}
