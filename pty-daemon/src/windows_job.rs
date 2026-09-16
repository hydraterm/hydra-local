//! Exact Job/process ownership extracted from Hydra's final Windows ConPTY backend.
//!
//! Until the complete ConPTY consumer is integrated, this module belongs only to the Windows
//! daemon test target. Real Win32 fixtures exercise the same ownership helpers without enabling
//! a partial production backend or changing the Unix PTY path.

use anyhow::{anyhow, Context as _, Result};
use std::alloc::{alloc_zeroed, dealloc, Layout};
use std::ffi::c_void;
use std::io;
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle};
use std::ptr::{null, null_mut, NonNull};
use windows_sys::Win32::Foundation::{
    DuplicateHandle, DUPLICATE_SAME_ACCESS, HANDLE, INVALID_HANDLE_VALUE, WAIT_FAILED,
    WAIT_OBJECT_0, WAIT_TIMEOUT,
};
use windows_sys::Win32::System::Console::HPCON;
use windows_sys::Win32::System::JobObjects::{
    CreateJobObjectW, JobObjectBasicAccountingInformation, JobObjectExtendedLimitInformation,
    QueryInformationJobObject, SetInformationJobObject, JOBOBJECT_BASIC_ACCOUNTING_INFORMATION,
    JOBOBJECT_EXTENDED_LIMIT_INFORMATION, JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE,
};
use windows_sys::Win32::System::Threading::{
    DeleteProcThreadAttributeList, GetCurrentProcess, GetExitCodeProcess,
    InitializeProcThreadAttributeList, UpdateProcThreadAttribute, WaitForSingleObject,
    PROC_THREAD_ATTRIBUTE_JOB_LIST, PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE,
};

pub(super) fn create_session_job() -> Result<OwnedHandle> {
    let job = unsafe { CreateJobObjectW(null(), null()) };
    let job = unsafe { owned_handle(job, "session Job")? };
    let mut limits = JOBOBJECT_EXTENDED_LIMIT_INFORMATION::default();
    limits.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
    if unsafe {
        SetInformationJobObject(
            raw_handle(&job),
            JobObjectExtendedLimitInformation,
            (&limits as *const JOBOBJECT_EXTENDED_LIMIT_INFORMATION).cast(),
            size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("set kill-on-close Job limit");
    }
    Ok(job)
}

pub(super) fn job_is_empty(job: &OwnedHandle) -> io::Result<bool> {
    let mut accounting = JOBOBJECT_BASIC_ACCOUNTING_INFORMATION::default();
    if unsafe {
        QueryInformationJobObject(
            raw_handle(job),
            JobObjectBasicAccountingInformation,
            (&mut accounting as *mut JOBOBJECT_BASIC_ACCOUNTING_INFORMATION).cast(),
            size_of::<JOBOBJECT_BASIC_ACCOUNTING_INFORMATION>() as u32,
            null_mut(),
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(accounting.ActiveProcesses == 0)
}

pub(super) fn process_exit_code(process: HANDLE, timeout_ms: u32) -> io::Result<Option<u32>> {
    match unsafe { WaitForSingleObject(process, timeout_ms) } {
        WAIT_OBJECT_0 => {
            let mut code = 0u32;
            if unsafe { GetExitCodeProcess(process, &mut code) } == 0 {
                Err(io::Error::last_os_error())
            } else {
                Ok(Some(code))
            }
        }
        WAIT_TIMEOUT => Ok(None),
        WAIT_FAILED => Err(io::Error::last_os_error()),
        unexpected => Err(io::Error::other(format!(
            "unexpected Windows process wait result: {unexpected}"
        ))),
    }
}

pub(super) struct ProcessAttributeList {
    pointer: NonNull<u8>,
    layout: Layout,
    initialized: bool,
}

impl ProcessAttributeList {
    pub(super) fn new(count: u32) -> Result<Self> {
        let mut required = 0usize;
        unsafe {
            InitializeProcThreadAttributeList(null_mut(), count, 0, &mut required);
        }
        if required == 0 {
            return Err(io::Error::last_os_error()).context("size process attribute list");
        }
        let layout = Layout::from_size_align(required, 16)
            .map_err(|_| anyhow!("invalid Windows process attribute allocation layout"))?;
        let pointer = NonNull::new(unsafe { alloc_zeroed(layout) })
            .ok_or_else(|| anyhow!("could not allocate Windows process attribute list"))?;
        let mut list = Self {
            pointer,
            layout,
            initialized: false,
        };
        if unsafe { InitializeProcThreadAttributeList(list.as_ptr(), count, 0, &mut required) } == 0
        {
            return Err(io::Error::last_os_error()).context("initialize process attribute list");
        }
        list.initialized = true;
        Ok(list)
    }

    pub(super) fn as_ptr(&self) -> *mut c_void {
        self.pointer.as_ptr().cast()
    }

    pub(super) fn set_job_list(&self, jobs: &[HANDLE; 1]) -> Result<()> {
        if unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_JOB_LIST as usize,
                jobs.as_ptr().cast(),
                size_of_val(jobs),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error())
                .context("set atomic Job-list process attribute");
        }
        Ok(())
    }

    pub(super) fn set_pseudoconsole(&self, hpc: HPCON) -> Result<()> {
        if unsafe {
            UpdateProcThreadAttribute(
                self.as_ptr(),
                0,
                PROC_THREAD_ATTRIBUTE_PSEUDOCONSOLE as usize,
                hpc as usize as *const c_void,
                size_of::<HPCON>(),
                null_mut(),
                null(),
            )
        } == 0
        {
            return Err(io::Error::last_os_error()).context("set pseudoconsole process attribute");
        }
        Ok(())
    }
}

impl Drop for ProcessAttributeList {
    fn drop(&mut self) {
        if self.initialized {
            unsafe { DeleteProcThreadAttributeList(self.as_ptr()) };
        }
        unsafe { dealloc(self.pointer.as_ptr(), self.layout) };
    }
}

pub(super) fn duplicate_handle(handle: &OwnedHandle) -> io::Result<OwnedHandle> {
    let current = unsafe { GetCurrentProcess() };
    let mut duplicate = null_mut();
    if unsafe {
        DuplicateHandle(
            current,
            raw_handle(handle),
            current,
            &mut duplicate,
            0,
            0,
            DUPLICATE_SAME_ACCESS,
        )
    } == 0
    {
        return Err(io::Error::last_os_error());
    }
    unsafe { owned_handle(duplicate, "duplicated handle") }
}

pub(super) unsafe fn owned_handle(handle: HANDLE, kind: &'static str) -> io::Result<OwnedHandle> {
    if handle.is_null() || handle == INVALID_HANDLE_VALUE {
        Err(io::Error::last_os_error())
    } else {
        // SAFETY: the caller transfers one newly-created Win32 handle and this wrapper is the sole
        // owner of that handle value.
        Ok(unsafe { OwnedHandle::from_raw_handle(handle) })
    }
    .map_err(|error| io::Error::new(error.kind(), format!("create {kind}: {error}")))
}

pub(super) fn raw_handle(handle: &OwnedHandle) -> HANDLE {
    handle.as_raw_handle() as HANDLE
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_process_encoding::{snapshot_environment, wide_case_cmp, PreparedProcess};
    use std::ffi::{OsStr, OsString};
    use std::os::windows::ffi::OsStringExt as _;
    use std::path::Path;
    use std::time::{Duration, Instant};
    use windows_sys::Win32::Foundation::{
        ERROR_DIRECTORY, ERROR_FILE_NOT_FOUND, ERROR_PATH_NOT_FOUND,
    };
    use windows_sys::Win32::System::JobObjects::{IsProcessInJob, TerminateJobObject};
    use windows_sys::Win32::System::Threading::{
        CreateProcessW, ResumeThread, TerminateProcess, CREATE_SUSPENDED,
        CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, PROCESS_INFORMATION,
        STARTUPINFOEXW,
    };

    const CHILD_TEST: &str = "windows_job::tests::owned_child_exits";
    const CHILD_EXIT: u32 = 37;
    const WAIT_MS: u32 = 5_000;
    const FIXTURE_ARGUMENT: &str = "two words \"quoted\" 🧭 C:\\tail\\";
    const FIXTURE_VALUE_KEY: &str = "HYDRA_WINDOWS_JOB_FIXTURE_VALUE";
    const FIXTURE_CWD_KEY: &str = "HYDRA_WINDOWS_JOB_FIXTURE_CWD";

    fn fixture_value() -> OsString {
        OsString::from_wide(&[b'a' as u16, 0xd800, b'z' as u16])
    }

    struct OwnedTestChild {
        process: OwnedHandle,
        thread: OwnedHandle,
    }

    impl OwnedTestChild {
        fn spawn_suspended(job: &OwnedHandle) -> Result<Self> {
            Self::spawn_executable(job, &std::env::current_exe()?)
        }

        fn spawn_executable(job: &OwnedHandle, executable: &Path) -> Result<Self> {
            let parent_cwd = std::env::current_dir()?;
            let child_cwd = parent_cwd.parent().unwrap_or(&parent_cwd);
            let mut environment = snapshot_environment()?;
            // Only the child's synthetic fixture keys are changed; never mutate the parent env.
            environment.retain(|(key, _)| {
                [FIXTURE_VALUE_KEY, FIXTURE_CWD_KEY]
                    .iter()
                    .all(|name| wide_case_cmp(key, OsStr::new(name)) != std::cmp::Ordering::Equal)
            });
            environment.push((FIXTURE_VALUE_KEY.into(), fixture_value()));
            environment.push((FIXTURE_CWD_KEY.into(), child_cwd.as_os_str().to_owned()));
            let arguments = [
                "--exact",
                CHILD_TEST,
                "--ignored",
                "--skip",
                FIXTURE_ARGUMENT,
            ]
            .map(OsString::from);
            let mut prepared = PreparedProcess::new(
                executable.as_os_str(),
                &arguments,
                &environment,
                Some(child_cwd.as_os_str()),
            )?;

            // UpdateProcThreadAttribute retains this address until DeleteProcThreadAttributeList.
            // Declare backing storage first, so error unwinding drops attributes before storage.
            let job_list = Box::new([raw_handle(job)]);
            let attributes = ProcessAttributeList::new(1)?;
            attributes.set_job_list(&job_list)?;
            let mut startup = STARTUPINFOEXW::default();
            startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
            startup.lpAttributeList = attributes.as_ptr();
            let mut information = PROCESS_INFORMATION::default();
            let created = unsafe {
                CreateProcessW(
                    prepared.application.as_ptr(),
                    prepared.command_line.as_mut_ptr(),
                    null(),
                    null(),
                    0, // Neither the Job nor any parent process/stdio handle is inherited.
                    EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT | CREATE_SUSPENDED,
                    prepared.environment.as_ptr().cast(),
                    prepared
                        .current_directory
                        .as_ref()
                        .map_or(null(), |cwd| cwd.as_ptr()),
                    &startup.StartupInfo,
                    &mut information,
                )
            };
            // Attribute destruction/handle cleanup may overwrite GetLastError.
            let launch_error = (created == 0).then(io::Error::last_os_error);
            drop(attributes);
            drop(job_list);
            if let Some(error) = launch_error {
                return Err(error).context("create exact owned test child");
            }
            // SAFETY: successful CreateProcessW transfers these two distinct owned handles.
            Ok(Self {
                process: unsafe { OwnedHandle::from_raw_handle(information.hProcess) },
                thread: unsafe { OwnedHandle::from_raw_handle(information.hThread) },
            })
        }

        fn exit_code(&self, timeout_ms: u32) -> io::Result<Option<u32>> {
            process_exit_code(raw_handle(&self.process), timeout_ms)
        }

        fn is_in_job(&self, job: &OwnedHandle) -> io::Result<bool> {
            let mut in_job = 0;
            if unsafe { IsProcessInJob(raw_handle(&self.process), raw_handle(job), &mut in_job) }
                == 0
            {
                return Err(io::Error::last_os_error());
            }
            Ok(in_job != 0)
        }

        fn resume(&self) -> io::Result<()> {
            match unsafe { ResumeThread(raw_handle(&self.thread)) } {
                u32::MAX => Err(io::Error::last_os_error()),
                1 => Ok(()),
                count => Err(io::Error::other(format!(
                    "unexpected suspend count: {count}"
                ))),
            }
        }
    }

    impl Drop for OwnedTestChild {
        fn drop(&mut self) {
            if !matches!(self.exit_code(0), Ok(Some(_))) {
                // Exact owned process object only; never reopen a potentially reused numeric PID.
                // The test's kill-on-close Job remains an independent cleanup backstop.
                unsafe { TerminateProcess(raw_handle(&self.process), 99) };
                let _ = self.exit_code(WAIT_MS);
            }
        }
    }

    fn wait_for_empty_job(job: &OwnedHandle) -> io::Result<()> {
        let deadline = Instant::now() + Duration::from_millis(u64::from(WAIT_MS));
        while !job_is_empty(job)? {
            if Instant::now() >= deadline {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "owned Job remained active",
                ));
            }
            std::thread::sleep(Duration::from_millis(5));
        }
        Ok(())
    }

    #[test]
    fn atomic_membership_precedes_first_instruction_and_exact_exit() -> Result<()> {
        let job = create_session_job()?;
        assert!(job_is_empty(&job)?);
        let child = OwnedTestChild::spawn_suspended(&job)?;
        // No AssignProcessToJobObject call exists: membership is established by CreateProcessW,
        // before ResumeThread permits even the first child instruction to run.
        assert!(child.is_in_job(&job)?);
        assert!(!job_is_empty(&job)?);
        assert_eq!(child.exit_code(0)?, None);
        let witness = duplicate_handle(&child.process)?;
        child.resume()?;
        assert_eq!(child.exit_code(WAIT_MS)?, Some(CHILD_EXIT));
        drop(child);
        assert_eq!(
            process_exit_code(raw_handle(&witness), 0)?,
            Some(CHILD_EXIT)
        );
        wait_for_empty_job(&job)?;
        Ok(())
    }

    #[test]
    fn explicit_job_termination_reaps_the_exact_owned_process() -> Result<()> {
        let job = create_session_job()?;
        let child = OwnedTestChild::spawn_suspended(&job)?;
        assert!(child.is_in_job(&job)?);
        assert_eq!(child.exit_code(0)?, None);
        if unsafe { TerminateJobObject(raw_handle(&job), 73) } == 0 {
            return Err(io::Error::last_os_error()).context("terminate exact test Job");
        }
        assert_eq!(child.exit_code(WAIT_MS)?, Some(73));
        wait_for_empty_job(&job)?;
        Ok(())
    }

    #[test]
    fn only_the_final_job_handle_close_terminates_the_owned_child() -> Result<()> {
        let job = create_session_job()?;
        let duplicate = duplicate_handle(&job)?;
        let child = OwnedTestChild::spawn_suspended(&job)?;
        assert!(child.is_in_job(&job)?);
        drop(job);
        assert!(child.is_in_job(&duplicate)?);
        assert_eq!(child.exit_code(100)?, None, "duplicate still owns the Job");
        drop(duplicate);
        assert!(child.exit_code(WAIT_MS)?.is_some());
        Ok(())
    }

    #[test]
    fn failed_create_process_preserves_os_error_and_leaves_job_empty() -> Result<()> {
        let job = create_session_job()?;
        // A directory below this already-existing executable file cannot be a valid child path.
        let missing = std::env::current_exe()?.join("missing-owned-child.exe");
        let error = match OwnedTestChild::spawn_executable(&job, &missing) {
            Ok(_) => anyhow::bail!("an executable file unexpectedly contained another executable"),
            Err(error) => error,
        };
        let os_error = error
            .downcast_ref::<io::Error>()
            .expect("original Win32 error");
        assert!(matches!(
            os_error.raw_os_error().map(|code| code as u32),
            Some(ERROR_FILE_NOT_FOUND | ERROR_PATH_NOT_FOUND | ERROR_DIRECTORY)
        ));
        assert!(job_is_empty(&job)?);
        Ok(())
    }

    #[test]
    #[ignore = "only launched by an exact owned CreateProcessW fixture"]
    fn owned_child_exits() {
        // Libtest accepts the escaped argument as a skip-filter value. The exact child entrypoint
        // verifies what CreateProcessW actually delivered, not just the parent's encoded buffer.
        let arguments: Vec<_> = std::env::args_os().collect();
        assert!(arguments.windows(2).any(|pair| {
            pair[0] == OsStr::new("--skip") && pair[1] == OsStr::new(FIXTURE_ARGUMENT)
        }));
        assert_eq!(std::env::var_os(FIXTURE_VALUE_KEY), Some(fixture_value()));
        let expected_cwd =
            std::env::var_os(FIXTURE_CWD_KEY).expect("fixture selected explicit cwd");
        assert_eq!(
            std::env::current_dir().unwrap().canonicalize().unwrap(),
            Path::new(&expected_cwd).canonicalize().unwrap(),
        );
        // A distinct exit code proves all native argv/environment/cwd checks actually ran.
        std::process::exit(CHILD_EXIT as i32);
    }
}
