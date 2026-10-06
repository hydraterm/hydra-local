//! Refresh only OS-baseline PATH for new Windows children of a retained daemon.
//!
//! A startup PATH differing from the current account's OS baseline might be intentional or
//! already stale: those cases cannot be distinguished safely, so both preserve inheritance.
//! Values compare losslessly and exactly (including order, quotes and empty entries); only
//! environment-variable names are case-insensitive. No filesystem/path normalization occurs.

use crate::windows_process_encoding::wide_case_cmp;
use std::cmp::Ordering;
use std::ffi::{c_void, OsStr, OsString};
use std::io;
use std::os::windows::ffi::OsStringExt as _;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::ptr::null_mut;
use std::sync::OnceLock;
use windows_sys::Win32::Security::{TOKEN_DUPLICATE, TOKEN_QUERY};
use windows_sys::Win32::System::Environment::{CreateEnvironmentBlock, DestroyEnvironmentBlock};
use windows_sys::Win32::System::Threading::{GetCurrentProcess, OpenProcessToken};

static STARTUP: OnceLock<PathPolicy> = OnceLock::new();

/// Called by synchronous daemon main, before creating the runtime or accepting any session.
/// An unavailable initial OS baseline stays inheritance-only for this daemon lifetime.
pub(super) fn initialize() {
    let inherited = std::env::var_os("PATH");
    let baseline = current_user_path().ok().flatten();
    let _ = STARTUP.set(PathPolicy::capture(
        inherited.as_deref(),
        baseline.as_deref(),
    ));
}

pub(super) fn refresh(environment: &mut [(OsString, OsString)]) {
    // Deliberately no lazy initialization: the first child may launch long after installation.
    if let Some(policy) = STARTUP.get() {
        policy.refresh(environment, || current_user_path().ok().flatten());
    }
}

pub(super) struct PathPolicy {
    baseline: Option<OsString>,
}

impl PathPolicy {
    pub(super) fn capture(inherited: Option<&OsStr>, baseline: Option<&OsStr>) -> Self {
        Self {
            baseline: inherited
                .zip(baseline)
                .filter(|(inherited, baseline)| inherited == baseline)
                .map(|(inherited, _)| inherited.to_owned()),
        }
    }

    pub(super) fn refresh(
        &self,
        environment: &mut [(OsString, OsString)],
        fresh_path: impl FnOnce() -> Option<OsString>,
    ) {
        let Some(baseline) = &self.baseline else {
            return;
        };
        let Some((_, path)) = environment
            .iter_mut()
            .find(|(key, _)| wide_case_cmp(key, OsStr::new("PATH")) == Ordering::Equal)
        else {
            return;
        };
        // Preserve a later explicit process/caller override as well as startup customization.
        if path == baseline {
            if let Some(fresh) = fresh_path() {
                *path = fresh;
            }
        }
    }
}

struct EnvironmentBlock(*mut c_void);

impl Drop for EnvironmentBlock {
    fn drop(&mut self) {
        unsafe { DestroyEnvironmentBlock(self.0) };
    }
}

/// Windows owns expansion/merging of the current account's system and user environment.
/// FALSE excludes this daemon's stale inherited block. Only PATH is copied from the result.
fn current_user_path() -> io::Result<Option<OsString>> {
    let mut token = null_mut();
    if unsafe {
        OpenProcessToken(
            GetCurrentProcess(),
            TOKEN_QUERY | TOKEN_DUPLICATE,
            &mut token,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    // OpenProcessToken transferred this exact primary token handle; all return paths close it.
    let token = unsafe { OwnedHandle::from_raw_handle(token) };
    let mut raw = null_mut();
    if unsafe { CreateEnvironmentBlock(&mut raw, token.as_raw_handle(), 0) } == 0 {
        return Err(io::Error::last_os_error());
    }
    let block = EnvironmentBlock(raw);
    if block.0.is_null() {
        return Err(io::Error::other(
            "Windows returned an empty environment pointer",
        ));
    }
    // The API guarantees a readable double-NUL-terminated UTF-16 block until destruction.
    let raw = block.0.cast::<u16>();
    let mut offset = 0;
    loop {
        let start = offset;
        while unsafe { *raw.add(offset) } != 0 {
            offset = offset
                .checked_add(1)
                .ok_or_else(|| io::Error::other("Windows environment offset overflow"))?;
        }
        if offset == start {
            return Ok(None);
        }
        let entry = unsafe { std::slice::from_raw_parts(raw.add(start), offset - start) };
        // Drive-local '=C:' entries cannot match PATH and need no special parsing here.
        if let Some(separator) = entry.iter().position(|unit| *unit == b'=' as u16) {
            let key = OsString::from_wide(&entry[..separator]);
            if wide_case_cmp(&key, OsStr::new("PATH")) == Ordering::Equal {
                return Ok(Some(OsString::from_wide(&entry[separator + 1..])));
            }
        }
        offset = offset
            .checked_add(1)
            .ok_or_else(|| io::Error::other("Windows environment offset overflow"))?;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_policy_preserves_custom_missing_failed_and_changed_inheritance() {
        let baseline = OsStr::new(r"C:\Windows;C:\tools;;");
        for inherited in [
            None,
            Some(OsStr::new("")),
            Some(OsStr::new(r"C:\custom")),
            Some(OsStr::new(r"c:\windows;C:\tools;;")),
            Some(OsStr::new(r"C:\tools;C:\Windows;;")),
        ] {
            let policy = PathPolicy::capture(inherited, Some(baseline));
            let mut environment = vec![("Path".into(), inherited.unwrap_or_default().into())];
            let original = environment.clone();
            policy.refresh(&mut environment, || panic!("custom PATH must not query OS"));
            assert_eq!(environment, original);
        }
        let mut environment = vec![("PATH".into(), baseline.into())];
        let original = environment.clone();
        PathPolicy::capture(Some(baseline), None).refresh(&mut environment, || {
            panic!("failed startup observation is not refreshable")
        });
        assert_eq!(environment, original);
        let policy = PathPolicy::capture(Some(baseline), Some(baseline));
        policy.refresh(&mut environment, || None);
        assert_eq!(environment, original, "failed current observation inherits");
        environment[0].1 = r"C:\later-custom".into();
        policy.refresh(&mut environment, || panic!("later override must win"));
        assert_eq!(environment[0].1, r"C:\later-custom");
        policy.refresh(&mut [], || panic!("missing PATH stays absent"));
        PathPolicy::capture(None, None)
            .refresh(&mut [], || panic!("absence is not an observed OS PATH"));
        let empty = OsStr::new("");
        let mut environment = vec![("Path".into(), empty.into())];
        PathPolicy::capture(Some(empty), Some(empty))
            .refresh(&mut environment, || Some(r"C:\new".into()));
        assert_eq!(environment[0].1, r"C:\new");
    }

    #[test]
    fn path_policy_changes_only_path_and_preserves_lossless_values_and_order() {
        let baseline = OsString::from_wide(&[b'C' as u16, b':' as u16, 0xd800]);
        let policy = PathPolicy::capture(Some(&baseline), Some(&baseline));
        let mut environment = vec![
            ("=C:".into(), r"C:\current".into()),
            ("pAtH".into(), baseline),
            ("HYDRA_CUSTOM".into(), OsString::from_wide(&[0xdfff])),
        ];
        let original = environment.clone();
        let fresh = OsString::from(r"C:\new;C:\Windows;;");
        policy.refresh(&mut environment, || Some(fresh.clone()));
        assert_eq!(environment[0], original[0]);
        assert_eq!(environment[1], ("pAtH".into(), fresh));
        assert_eq!(environment[2], original[2]);
    }

    #[test]
    fn current_account_environment_block_is_readable_without_process_mutation() {
        let inherited = crate::windows_process_encoding::snapshot_environment().unwrap();
        assert!(current_user_path().unwrap().is_some());
        assert!(
            crate::windows_process_encoding::snapshot_environment().unwrap() == inherited,
            "reading the OS baseline must not mutate the process environment"
        );
    }
}
