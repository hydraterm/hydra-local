//! Complete private ConPTY consumer of the accepted Windows ownership and I/O modules.
//! Shared Session consumes this backend; operational listener/resize composition remains pending.
//! Native resize reports actual completion; it never kills a terminal because a timer elapsed.

use crate::windows_command::Command;
use crate::windows_job::{
    create_session_job, duplicate_handle, job_is_empty, owned_handle, process_exit_code,
    raw_handle, ProcessAttributeList,
};
use crate::windows_overlapped_io::{OverlappedReader, OverlappedWriter, PipeEndpoint};
use crate::windows_private_pipe::{private_pipe, Event, PipeDirection};
use crate::windows_process_encoding::PreparedProcess;
use anyhow::{anyhow, bail, Context as _, Result};
use portable_pty::{Child, ChildKiller, ExitStatus, MasterPty, PtySize};
use std::ffi::c_void;
use std::fmt;
use std::io::{self, Read, Write};
use std::mem::size_of;
use std::os::windows::io::{AsRawHandle as _, FromRawHandle as _, OwnedHandle, RawHandle};
use std::ptr::{null, null_mut};
use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};
use std::sync::{mpsc, Arc, Condvar, Mutex, Weak};
use std::time::Duration;
use windows_sys::Win32::Foundation::{GetLastError, INVALID_HANDLE_VALUE, WAIT_TIMEOUT};
use windows_sys::Win32::System::Console::{
    ClosePseudoConsole, CreatePseudoConsole, ResizePseudoConsole, COORD, HPCON,
};
use windows_sys::Win32::System::JobObjects::{
    JobObjectAssociateCompletionPortInformation, SetInformationJobObject, TerminateJobObject,
    JOBOBJECT_ASSOCIATE_COMPLETION_PORT,
};
use windows_sys::Win32::System::SystemServices::JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO;
use windows_sys::Win32::System::Threading::{
    CreateProcessW, CREATE_UNICODE_ENVIRONMENT, EXTENDED_STARTUPINFO_PRESENT, INFINITE,
    PROCESS_INFORMATION, STARTF_USESTDHANDLES, STARTUPINFOEXW,
};
use windows_sys::Win32::System::IO::{CreateIoCompletionPort, GetQueuedCompletionStatus};

const JOB_MONITOR_POLL_MS: u32 = 250;
const COMPLETION_KEY: usize = 0x4859_4452; // "HYDR"

/// The concrete pair is intentionally crate-private. `Session` uses the same `MasterPty` trait as
/// Unix, while the Windows slave consumes the caller's already-selected native process buffers.
pub(crate) struct PtyPair {
    pub(crate) master: Box<dyn MasterPty + Send>,
    pub(crate) slave: Slave,
}

pub(crate) fn openpty(size: PtySize) -> Result<PtyPair> {
    validate_size(size)?;

    // Hydra owns overlapped server ends. ConPTY receives synchronous client ends, matching the
    // public ConPTY contract while allowing CancelIoEx on every daemon-side operation.
    let (input_host, input_conpty) = private_pipe(PipeDirection::HydraWrites)?;
    let (output_host, output_conpty) = private_pipe(PipeDirection::HydraReads)?;

    let mut hpc: HPCON = 0;
    let result = unsafe {
        CreatePseudoConsole(
            coord(size),
            raw_handle(&input_conpty),
            raw_handle(&output_conpty),
            0,
            &mut hpc,
        )
    };
    if result < 0 {
        bail!(
            "CreatePseudoConsole failed with HRESULT 0x{:08x}",
            result as u32
        );
    }
    if hpc == 0 {
        bail!("CreatePseudoConsole returned a null pseudoconsole handle");
    }

    let control = ConptyControl::start(hpc)?;
    let input_cancel = Arc::new(Event::manual_reset()?);
    let output_cancel = Arc::new(Event::manual_reset()?);
    let job = create_session_job()?;
    let completion_port = create_job_completion_port(&job)?;
    let lifecycle = Arc::new(Lifecycle {
        control: control.clone(),
        input_cancel: input_cancel.clone(),
        output_cancel: output_cancel.clone(),
        closing: AtomicBool::new(false),
        #[cfg(test)]
        query_failure: Mutex::new(None),
        #[cfg(test)]
        monitor_observer: Mutex::new(None),
        job,
    });

    let master = Master {
        size: Mutex::new(size),
        control,
        lifecycle: lifecycle.clone(),
        reader: Arc::new(PipeEndpoint::new(output_host, output_cancel)),
        writer: Mutex::new(Some(Arc::new(PipeEndpoint::new(input_host, input_cancel)))),
    };
    let slave = Slave {
        lifecycle,
        resources: Mutex::new(SpawnResources {
            spawned: false,
            completion_port: Some(completion_port),
            input_conpty: Some(input_conpty),
            output_conpty: Some(output_conpty),
        }),
    };

    Ok(PtyPair {
        master: Box::new(master),
        slave,
    })
}

struct Master {
    size: Mutex<PtySize>,
    control: Arc<ConptyControl>,
    lifecycle: Arc<Lifecycle>,
    reader: Arc<PipeEndpoint>,
    writer: Mutex<Option<Arc<PipeEndpoint>>>,
}

impl MasterPty for Master {
    fn resize(&self, size: PtySize) -> Result<()> {
        validate_size(size)?;
        if self.lifecycle.is_closing() {
            bail!("Windows terminal is closing");
        }
        // This private consumer waits for actual native completion, never timeout-to-kill.
        // Production Session composition must enqueue/settle this off its client read loop.
        self.control.resize(size)?;
        *self.size.lock().unwrap() = size;
        Ok(())
    }

    fn get_size(&self) -> Result<PtySize> {
        Ok(*self.size.lock().unwrap())
    }

    fn try_clone_reader(&self) -> Result<Box<dyn Read + Send>> {
        Ok(Box::new(OverlappedReader::start(self.reader.clone())?))
    }

    fn take_writer(&self) -> Result<Box<dyn Write + Send>> {
        let endpoint = self
            .writer
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| anyhow!("Windows terminal writer was already taken"))?;
        Ok(Box::new(OverlappedWriter::start(endpoint)?))
    }
}

pub(crate) struct Slave {
    lifecycle: Arc<Lifecycle>,
    resources: Mutex<SpawnResources>,
}

struct SpawnResources {
    spawned: bool,
    completion_port: Option<OwnedHandle>,
    input_conpty: Option<OwnedHandle>,
    output_conpty: Option<OwnedHandle>,
}

impl Slave {
    pub(crate) fn session_lifetime(&self) -> SessionLifetime {
        SessionLifetime(self.lifecycle.clone())
    }

    pub(crate) fn spawn_native(&self, command: Command) -> Result<Box<dyn Child + Send + Sync>> {
        self.spawn_command(command.prepare()?)
    }

    pub(crate) fn spawn_command(
        &self,
        mut prepared: PreparedProcess,
    ) -> Result<Box<dyn Child + Send + Sync>> {
        // Guard before touching HPCON: a previous root may already have exited and its
        // monitor closed the console. No second attempt may inspect that retired handle.
        let mut resources = self.resources.lock().unwrap();
        if resources.spawned {
            bail!("a Windows pseudoconsole can spawn only one root process");
        }
        // Everything below this line that can fail before CreateProcess is prepared first. This
        // keeps CreateProcessW as the one command-publication point.
        // The attribute list borrows this array. Declare the backing storage first so Rust's
        // reverse local-drop order also deletes the list before releasing the array on every
        // early-return and unwind path.
        let job_list = Box::new([raw_handle(&self.lifecycle.job)]);
        let process_attributes = ProcessAttributeList::new(2)?;
        process_attributes.set_pseudoconsole(self.lifecycle.control.raw_hpc())?;
        process_attributes.set_job_list(&job_list)?;
        let monitor_port = duplicate_handle(
            resources
                .completion_port
                .as_ref()
                .ok_or_else(|| anyhow!("Windows Job completion port is unavailable"))?,
        )?;
        let monitor_lifecycle = Arc::downgrade(&self.lifecycle);
        let monitor_control = self.lifecycle.control.clone();
        let monitor_gate = MonitorGate::new();
        let monitor_start = monitor_gate.state.clone();
        let monitor = std::thread::Builder::new()
            .name("conpty-job-monitor".into())
            .spawn(move || {
                let (start, ready) = &*monitor_start;
                let mut start = start
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while start.is_none() {
                    start = ready
                        .wait(start)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                let published = *start == Some(true);
                drop(start);
                if published {
                    monitor_job_until_empty(monitor_lifecycle, monitor_port, monitor_control);
                }
            })?;
        #[cfg(test)]
        let monitor = match self.lifecycle.monitor_observer.lock().unwrap().take() {
            Some(observer) => {
                let _ = observer.send(monitor);
                None
            }
            None => Some(monitor),
        };
        drop(monitor);

        let mut startup = STARTUPINFOEXW::default();
        startup.StartupInfo.cb = size_of::<STARTUPINFOEXW>() as u32;
        // Force the child's ordinary standard handles to NULL so CreateProcessW cannot duplicate
        // redirected daemon stdio before ConPTY installs its console streams. Windows Terminal's
        // ConPTY launcher uses this exact flag-plus-NULL pattern with bInheritHandles=false.
        startup.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
        startup.lpAttributeList = process_attributes.as_ptr();

        let mut process_info = PROCESS_INFORMATION::default();
        let created = unsafe {
            CreateProcessW(
                prepared.application.as_ptr(),
                prepared.command_line.as_mut_ptr(),
                null(),
                null(),
                0,
                EXTENDED_STARTUPINFO_PRESENT | CREATE_UNICODE_ENVIRONMENT,
                prepared.environment.as_ptr().cast(),
                prepared
                    .current_directory
                    .as_ref()
                    .map_or(null(), |cwd| cwd.as_ptr()),
                &startup.StartupInfo,
                &mut process_info,
            )
        };
        let creation_error = (created == 0).then(io::Error::last_os_error);
        // Attribute values are borrowed by the list. Delete the list before releasing its stable
        // Job-array backing storage, on both the success and failure paths.
        drop(process_attributes);
        drop(job_list);
        if let Some(error) = creation_error {
            return Err(error).context("CreateProcessW failed for Windows terminal child");
        }

        resources.spawned = true;
        // CreateProcessW success guarantees both handles. From this point there must be no
        // fallible ownership conversion that could return while the published process runs.
        debug_assert!(!process_info.hProcess.is_null());
        debug_assert!(!process_info.hThread.is_null());
        let process = unsafe { OwnedHandle::from_raw_handle(process_info.hProcess) };
        let thread = unsafe { OwnedHandle::from_raw_handle(process_info.hThread) };
        drop(thread);
        // Microsoft documents retaining these synchronous ConPTY-side pipe handles until the
        // hosted process has been created. The pseudoconsole now owns its references.
        drop(resources.input_conpty.take());
        drop(resources.output_conpty.take());

        // Infallible local publication: no disconnected channel can turn a created process into
        // a generic spawn refusal. Earlier errors drop the gate and wake the monitor as Aborted.
        monitor_gate.publish();

        Ok(Box::new(WindowsChild {
            pid: process_info.dwProcessId,
            process: Arc::new(process),
            lifecycle: self.lifecycle.clone(),
        }))
    }
}

struct MonitorGate {
    state: Arc<(Mutex<Option<bool>>, Condvar)>,
}

impl MonitorGate {
    fn new() -> Self {
        Self {
            state: Arc::new((Mutex::new(None), Condvar::new())),
        }
    }

    fn publish(self) {
        let (state, ready) = &*self.state;
        *state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(true);
        ready.notify_one();
    }
}

impl Drop for MonitorGate {
    fn drop(&mut self) {
        let (state, ready) = &*self.state;
        let mut state = state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.is_none() {
            *state = Some(false);
            ready.notify_one();
        }
    }
}

/// Exact owned Job reference for the shared Session, not a PID or another owning OS handle.
#[derive(Clone)]
pub(crate) struct SessionLifetime(Arc<Lifecycle>);

impl SessionLifetime {
    pub(crate) fn is_retired(&self) -> io::Result<bool> {
        self.0.job_is_empty()
    }

    pub(crate) fn terminate(&self) -> io::Result<()> {
        self.0.terminate()
    }
}

#[derive(Clone)]
struct JobKiller {
    lifecycle: Arc<Lifecycle>,
}

impl fmt::Debug for JobKiller {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.debug_struct("WindowsJobKiller").finish()
    }
}

impl ChildKiller for JobKiller {
    fn kill(&mut self) -> io::Result<()> {
        self.lifecycle.terminate()
    }

    fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
        Box::new(self.clone())
    }
}

struct WindowsChild {
    pid: u32,
    process: Arc<OwnedHandle>,
    lifecycle: Arc<Lifecycle>,
}

impl fmt::Debug for WindowsChild {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("WindowsConPtyChild")
            .field("pid", &self.pid)
            .finish()
    }
}

impl ChildKiller for WindowsChild {
    fn kill(&mut self) -> io::Result<()> {
        self.lifecycle.terminate()
    }

    fn clone_killer(&self) -> Box<dyn ChildKiller + Send + Sync> {
        Box::new(JobKiller {
            lifecycle: self.lifecycle.clone(),
        })
    }
}

impl Child for WindowsChild {
    fn try_wait(&mut self) -> io::Result<Option<ExitStatus>> {
        // Root completion is observation, not authority to kill redirected descendants.
        // Same-id Session reuse must separately prove actual Job retirement.
        Ok(process_exit_code(raw_handle(&self.process), 0)?.map(ExitStatus::with_exit_code))
    }

    fn wait(&mut self) -> io::Result<ExitStatus> {
        let code = process_exit_code(raw_handle(&self.process), INFINITE)?.ok_or_else(|| {
            io::Error::other("infinite wait returned without Windows child completion")
        })?;
        Ok(ExitStatus::with_exit_code(code))
    }

    fn process_id(&self) -> Option<u32> {
        Some(self.pid)
    }

    fn as_raw_handle(&self) -> Option<RawHandle> {
        Some(self.process.as_raw_handle())
    }
}

struct Lifecycle {
    control: Arc<ConptyControl>,
    input_cancel: Arc<Event>,
    output_cancel: Arc<Event>,
    closing: AtomicBool,
    #[cfg(test)]
    query_failure: Mutex<Option<mpsc::Sender<()>>>,
    #[cfg(test)]
    monitor_observer: Mutex<Option<mpsc::Sender<std::thread::JoinHandle<()>>>>,
    // Keep this field last: Rust drops fields in declaration order after `Drop::drop`, so the Job
    // remains the final kill-on-close backstop while control and I/O teardown ownership unwind.
    job: OwnedHandle,
}

impl Lifecycle {
    fn is_closing(&self) -> bool {
        self.closing.load(AtomicOrdering::Acquire)
    }

    fn job_is_empty(&self) -> io::Result<bool> {
        #[cfg(test)]
        if let Some(notice) = self.query_failure.lock().unwrap().take() {
            let _ = notice.send(());
            return Err(io::Error::other("synthetic Job accounting query failure"));
        }
        job_is_empty(&self.job)
    }

    fn terminate(&self) -> io::Result<()> {
        self.closing.store(true, AtomicOrdering::Release);
        let cancel_error = self.input_cancel.set().err().map(|error| {
            io::Error::new(
                error.kind(),
                format!("signal Windows terminal input cancellation: {error}"),
            )
        });
        self.control.reject_resizes();
        if self.job_is_empty().unwrap_or(false) {
            self.control.close();
            return cancel_error.map_or(Ok(()), Err);
        }
        if unsafe { TerminateJobObject(raw_handle(&self.job), 1) } == 0 {
            let error = io::Error::last_os_error();
            if !self.job_is_empty().unwrap_or(false) {
                return Err(io::Error::new(
                    error.kind(),
                    format!("terminate Windows Session Job: {error}"),
                ));
            }
        }
        // The exact Job monitor closes ConPTY after all owned processes exit. Its output
        // remains readable to EOF; there is no arbitrary 500ms final-output cutoff.
        cancel_error.map_or(Ok(()), Err)
    }
}

impl Drop for Lifecycle {
    fn drop(&mut self) {
        self.closing.store(true, AtomicOrdering::Release);
        let _ = self.input_cancel.set();
        let _ = unsafe { TerminateJobObject(raw_handle(&self.job), 1) };
        let _ = self.output_cancel.set();
        self.control.close();
        // `job` drops last. KILL_ON_JOB_CLOSE is the crash/error backstop if explicit termination
        // above could not run to completion.
    }
}

struct ConptyControl {
    hpc: HPCON,
    tx: mpsc::SyncSender<ControlMessage>,
    closing: Arc<AtomicBool>,
}

enum ControlMessage {
    Resize(COORD, mpsc::Sender<io::Result<()>>),
    Close,
}

impl ConptyControl {
    fn start(hpc: HPCON) -> Result<Arc<Self>> {
        let (tx, rx) = mpsc::sync_channel(1);
        let closing = Arc::new(AtomicBool::new(false));
        let worker_closing = closing.clone();
        if let Err(error) = std::thread::Builder::new()
            .name("conpty-control".into())
            .spawn(move || {
                while !worker_closing.load(AtomicOrdering::Acquire) {
                    let Ok(message) = rx.recv() else { break };
                    if worker_closing.load(AtomicOrdering::Acquire) {
                        break;
                    }
                    match message {
                        ControlMessage::Resize(size, reply) => {
                            let result = unsafe { ResizePseudoConsole(hpc, size) };
                            let outcome = if result >= 0 {
                                Ok(())
                            } else {
                                Err(io::Error::other(format!(
                                    "ResizePseudoConsole failed with HRESULT 0x{:08x}",
                                    result as u32
                                )))
                            };
                            let _ = reply.send(outcome);
                        }
                        ControlMessage::Close => break,
                    }
                }
                // Before Windows 11 24H2 this can wait for output drain. It is neither
                // the reader thread nor the daemon authority/runtime thread.
                unsafe { ClosePseudoConsole(hpc) };
            })
        {
            // No child is attached yet; the caller still owns both synchronous pipe ends.
            unsafe { ClosePseudoConsole(hpc) };
            return Err(error.into());
        }
        Ok(Arc::new(Self { hpc, tx, closing }))
    }

    fn raw_hpc(&self) -> HPCON {
        self.hpc
    }

    fn resize(&self, size: PtySize) -> io::Result<()> {
        if self.closing.load(AtomicOrdering::Acquire) {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "Windows pseudoconsole is closing",
            ));
        }
        let (reply, result) = mpsc::channel();
        match self.tx.try_send(ControlMessage::Resize(coord(size), reply)) {
            Ok(()) => {}
            Err(mpsc::TrySendError::Full(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "ConPTY control queue is full",
                ));
            }
            Err(mpsc::TrySendError::Disconnected(_)) => {
                return Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "ConPTY control worker closed",
                ));
            }
        }
        result.recv().map_err(|_| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "ConPTY control worker stopped before completion",
            )
        })?
    }

    fn reject_resizes(&self) {
        self.closing.store(true, AtomicOrdering::Release);
    }

    fn close(&self) {
        self.closing.store(true, AtomicOrdering::Release);
        // Wake an idle worker; if its queue is full it observes closing before the next call.
        let _ = self.tx.try_send(ControlMessage::Close);
    }
}

fn create_job_completion_port(job: &OwnedHandle) -> Result<OwnedHandle> {
    let port = unsafe { CreateIoCompletionPort(INVALID_HANDLE_VALUE, null_mut(), 0, 1) };
    let port = unsafe { owned_handle(port, "Job completion port")? };
    let association = JOBOBJECT_ASSOCIATE_COMPLETION_PORT {
        CompletionKey: COMPLETION_KEY as *mut c_void,
        CompletionPort: raw_handle(&port),
    };
    if unsafe {
        SetInformationJobObject(
            raw_handle(job),
            JobObjectAssociateCompletionPortInformation,
            (&association as *const JOBOBJECT_ASSOCIATE_COMPLETION_PORT).cast(),
            size_of::<JOBOBJECT_ASSOCIATE_COMPLETION_PORT>() as u32,
        )
    } == 0
    {
        return Err(io::Error::last_os_error()).context("associate session Job completion port");
    }
    Ok(port)
}

fn monitor_job_until_empty(
    lifecycle: Weak<Lifecycle>,
    port: OwnedHandle,
    control: Arc<ConptyControl>,
) {
    let mut logged_status_failure = false;
    loop {
        // Never retain a second Job handle in this detached observer. A temporary strong reference
        // protects the authoritative handle only across the status query, then is released before
        // the bounded completion-port wait. If Session ownership disappears, Lifecycle::drop can
        // therefore close the last Job handle and KILL_ON_JOB_CLOSE remains a real backstop.
        let Some(owner) = lifecycle.upgrade() else {
            return;
        };
        let status = owner.job_is_empty();
        drop(owner);
        match status {
            Ok(true) => break,
            Ok(false) => logged_status_failure = false,
            Err(error) => {
                if !logged_status_failure {
                    eprintln!(
                        "pty-daemon: Windows Job status is unknown; retaining ConPTY: {error}"
                    );
                }
                logged_status_failure = true;
            }
        }

        let mut message = 0u32;
        let mut completion_key = 0usize;
        let mut overlapped = null_mut();
        let completed = unsafe {
            GetQueuedCompletionStatus(
                raw_handle(&port),
                &mut message,
                &mut completion_key,
                &mut overlapped,
                JOB_MONITOR_POLL_MS,
            )
        };
        if completed == 0 && unsafe { GetLastError() } != WAIT_TIMEOUT {
            // A broken wakeup source must not turn unknown accounting into a hot loop.
            std::thread::sleep(Duration::from_millis(JOB_MONITOR_POLL_MS as u64));
        }
        if completed != 0
            && completion_key == COMPLETION_KEY
            && message == JOB_OBJECT_MSG_ACTIVE_PROCESS_ZERO
        {
            let Some(owner) = lifecycle.upgrade() else {
                return;
            };
            if owner.job_is_empty().unwrap_or(false) {
                break;
            }
        }
        // Completion-port notifications are a wakeup, not the authority. Timeout, unrelated
        // messages, and delivery failures all return to the ActiveProcesses query at loop head.
    }
    control.close();
}

fn validate_size(size: PtySize) -> Result<()> {
    if size.cols == 0
        || size.rows == 0
        || size.cols > i16::MAX as u16
        || size.rows > i16::MAX as u16
    {
        bail!(
            "invalid Windows pseudoconsole size {}x{}",
            size.cols,
            size.rows
        );
    }
    Ok(())
}

fn coord(size: PtySize) -> COORD {
    COORD {
        X: size.cols as i16,
        Y: size.rows as i16,
    }
}

#[cfg(test)]
pub(super) mod tests {
    use super::*;
    use crate::windows_overlapped_io::tests::run_exact_owned_child;
    use crate::windows_process_encoding::snapshot_environment;
    use std::ffi::OsString;
    use std::io::BufRead as _;
    use std::os::windows::process::CommandExt as _;
    use std::process::{Command, Stdio};
    use std::time::Instant;
    use windows_sys::Win32::System::Console::{
        GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
    };
    use windows_sys::Win32::System::JobObjects::IsProcessInJob;
    use windows_sys::Win32::System::Threading::DETACHED_PROCESS;

    const CHILD: &str = "windows_conpty::tests::interactive_child";
    const CHILD_MARKER: &str = "HYDRA_WINDOWS_CONPTY_CHILD";
    const OBSERVATION: Duration = Duration::from_secs(5);

    #[test]
    fn monitor_publication_gate_preserves_success_and_aborts_unpublished_scope() {
        let gate = MonitorGate::new();
        let observed = gate.state.clone();
        drop(gate);
        assert_eq!(*observed.0.lock().unwrap(), Some(false));
        let gate = MonitorGate::new();
        let observed = gate.state.clone();
        gate.publish();
        assert_eq!(*observed.0.lock().unwrap(), Some(true));
    }

    fn selected_child(mode: &str) -> PreparedProcess {
        let mut environment = snapshot_environment().unwrap();
        environment.retain(|(key, _)| {
            !key.to_str()
                .is_some_and(|key| key.eq_ignore_ascii_case(CHILD_MARKER))
        });
        environment.push((CHILD_MARKER.into(), mode.into()));
        PreparedProcess::new(
            std::env::current_exe().unwrap().as_os_str(),
            &["--exact", CHILD, "--ignored", "--nocapture"].map(OsString::from),
            &environment,
            Some(std::env::current_dir().unwrap().as_os_str()),
        )
        .unwrap()
    }

    fn read_until(events: &mpsc::Receiver<Vec<u8>>, output: &mut Vec<u8>, marker: &str) {
        let deadline = Instant::now() + OBSERVATION;
        while !String::from_utf8_lossy(output).contains(marker) {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .expect("ConPTY output deadline");
            output.extend(
                events
                    .recv_timeout(remaining)
                    .expect("ConPTY output ended before marker"),
            );
        }
    }

    fn wait_job_empty(pair: &PtyPair) {
        let deadline = Instant::now() + OBSERVATION;
        while !pair.slave.lifecycle.job_is_empty().unwrap() {
            assert!(
                Instant::now() < deadline,
                "exact Job accounting did not retire"
            );
            std::thread::sleep(Duration::from_millis(10));
        }
    }

    fn drain_output(pair: &PtyPair) -> (mpsc::Receiver<Vec<u8>>, std::thread::JoinHandle<()>) {
        let mut reader = pair.master.try_clone_reader().unwrap();
        let (events, output) = mpsc::channel();
        let pump = std::thread::spawn(move || {
            let mut bytes = [0; 1024];
            loop {
                match reader.read(&mut bytes) {
                    Ok(0) | Err(_) => break,
                    Ok(count) => {
                        if events.send(bytes[..count].to_vec()).is_err() {
                            break;
                        }
                    }
                }
            }
        });
        (output, pump)
    }

    pub(crate) fn assert_native_command_output(command: crate::windows_command::Command) {
        let pair = openpty(PtySize {
            rows: 24,
            cols: 120,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
        let (output, pump) = drain_output(&pair);
        let mut child = pair.slave.spawn_native(command).unwrap();
        read_until(&output, &mut Vec::new(), "HYDRA_NATIVE_ARGUMENTS_OK");
        assert!(child.wait().unwrap().success());
        wait_job_empty(&pair);
        pump.join().unwrap();
    }

    #[test]
    fn actual_conpty_process_interacts_resizes_and_exits_in_owned_job() {
        const CASE: &str =
            "windows_conpty::tests::actual_conpty_process_interacts_resizes_and_exits_in_owned_job";
        if run_exact_owned_child(CASE) {
            return;
        }
        let pair = openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
        let mut writer = pair.master.take_writer().unwrap();
        assert!(
            pair.master.take_writer().is_err(),
            "exactly one writer can be admitted"
        );
        let (output, pump) = drain_output(&pair);
        // A failed native publication keeps the same resources reusable and Job empty.
        let missing =
            std::env::temp_dir().join(format!("hydra-absent-{}.exe", uuid::Uuid::new_v4()));
        let (monitor_observer, aborted_monitor) = mpsc::channel();
        *pair.slave.lifecycle.monitor_observer.lock().unwrap() = Some(monitor_observer);
        let failed = PreparedProcess::new(missing.as_os_str(), &[], &[], None).unwrap();
        let error = pair.slave.spawn_command(failed).unwrap_err();
        assert!(error.to_string().contains("CreateProcessW failed"));
        // The actual pre-created monitor has exited after native CreateProcess failure; this is
        // not just a local gate-state assertion. The outer owned child bounds a broken join.
        aborted_monitor
            .recv_timeout(OBSERVATION)
            .unwrap()
            .join()
            .unwrap();
        assert!(pair.slave.lifecycle.job_is_empty().unwrap());
        let (failed_query, observed_query) = mpsc::channel();
        *pair.slave.lifecycle.query_failure.lock().unwrap() = Some(failed_query);
        let mut child = pair
            .slave
            .spawn_command(selected_child("interactive"))
            .unwrap();
        observed_query.recv_timeout(OBSERVATION).unwrap();
        assert!(
            child.try_wait().unwrap().is_none(),
            "unknown Job status must not close ConPTY"
        );
        let mut member = 0;
        assert_ne!(
            unsafe {
                IsProcessInJob(
                    child.as_raw_handle().unwrap().cast(),
                    raw_handle(&pair.slave.lifecycle.job),
                    &mut member,
                )
            },
            0
        );
        assert_ne!(member, 0);
        assert!(
            pair.slave
                .spawn_command(selected_child("interactive"))
                .is_err(),
            "one root per pseudoconsole"
        );
        let mut transcript = Vec::new();
        read_until(&output, &mut transcript, "HYDRA_CONPTY_READY");
        let size = PtySize {
            rows: 35,
            cols: 100,
            pixel_width: 0,
            pixel_height: 0,
        };
        pair.master.resize(size).unwrap();
        assert_eq!(pair.master.get_size().unwrap(), size);
        writer.write_all(b"probe\r").unwrap();
        read_until(&output, &mut transcript, "HYDRA_CONPTY_SIZE:100x35");
        writer.write_all(b"quit\r").unwrap();
        read_until(&output, &mut transcript, "HYDRA_CONPTY_CHILD_DONE");
        assert!(child.wait().unwrap().success());
        wait_job_empty(&pair);
        pump.join().unwrap();
        assert!(pair
            .slave
            .spawn_command(selected_child("interactive"))
            .is_err());
        println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
    }

    #[test]
    fn explicit_kill_terminates_only_the_exact_conpty_job() {
        const CASE: &str =
            "windows_conpty::tests::explicit_kill_terminates_only_the_exact_conpty_job";
        if run_exact_owned_child(CASE) {
            return;
        }
        let pair = openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
        let (output, pump) = drain_output(&pair);
        let mut child = pair
            .slave
            .spawn_command(selected_child("interactive"))
            .unwrap();
        read_until(&output, &mut Vec::new(), "HYDRA_CONPTY_READY");
        assert!(child.try_wait().unwrap().is_none());
        let mut killer = child.clone_killer();
        killer.kill().unwrap();
        let deadline = Instant::now() + OBSERVATION;
        while child.try_wait().unwrap().is_none() {
            assert!(Instant::now() < deadline, "exact Job did not retire");
            std::thread::sleep(Duration::from_millis(10));
        }
        wait_job_empty(&pair);
        pump.join().unwrap();
        println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
    }

    #[test]
    fn root_observation_preserves_redirected_descendant_until_explicit_kill() {
        const CASE: &str = "windows_conpty::tests::root_observation_preserves_redirected_descendant_until_explicit_kill";
        if run_exact_owned_child(CASE) {
            return;
        }
        let pair = openpty(PtySize {
            rows: 24,
            cols: 80,
            pixel_width: 0,
            pixel_height: 0,
        })
        .unwrap();
        let (output, pump) = drain_output(&pair);
        let mut root = pair
            .slave
            .spawn_command(selected_child("descendant-root"))
            .unwrap();
        read_until(&output, &mut Vec::new(), "HYDRA_CONPTY_ROOT_DONE");
        assert!(root.wait().unwrap().success());
        assert!(root.try_wait().unwrap().unwrap().success());
        assert!(
            !pair.slave.lifecycle.job_is_empty().unwrap(),
            "observation must retain descendant"
        );
        root.clone_killer().kill().unwrap();
        wait_job_empty(&pair);
        pump.join().unwrap();
        println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
    }

    #[test]
    #[ignore = "owned native child entry; invoked only through the exact ConPTY fixture"]
    fn interactive_child() {
        let mode = std::env::var(CHILD_MARKER).unwrap();
        if mode == "descendant-root" {
            let mut descendant = Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "windows_conpty::tests::redirected_descendant",
                    "--ignored",
                ])
                .env(CHILD_MARKER, "descendant")
                .creation_flags(DETACHED_PROCESS)
                .stdin(Stdio::null())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            let stdout = descendant.stdout.take().unwrap();
            // libtest writes a preamble first. Require the exact framed marker; the outer
            // owned-process deadline bounds a missing marker, without assuming byte offset.
            assert!(std::io::BufReader::new(stdout)
                .lines()
                .any(|line| line.unwrap() == "HYDRA_REDIRECTED_READY"));
            // It inherits this root's exact Job, not its console/stdio. Dropping the process
            // handle does not terminate it; the fixture's Job remains the teardown authority.
            drop(descendant);
            println!("\nHYDRA_CONPTY_ROOT_DONE");
            std::io::stdout().flush().unwrap();
            return;
        }
        assert_eq!(mode, "interactive");
        println!("\nHYDRA_CONPTY_READY");
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "probe");
        let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
        assert_ne!(
            unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) },
            0
        );
        let cols = info.srWindow.Right - info.srWindow.Left + 1;
        let rows = info.srWindow.Bottom - info.srWindow.Top + 1;
        assert_eq!((cols, rows), (100, 35));
        println!("\nHYDRA_CONPTY_SIZE:{cols}x{rows}");
        std::io::stdout().flush().unwrap();
        line.clear();
        std::io::stdin().read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "quit");
        println!("\nHYDRA_CONPTY_CHILD_DONE");
        std::io::stdout().flush().unwrap();
    }

    #[test]
    #[ignore = "exact owned redirected descendant; the fixture Job terminates it"]
    fn redirected_descendant() {
        assert_eq!(std::env::var(CHILD_MARKER).as_deref(), Ok("descendant"));
        std::io::stdout()
            .write_all(b"\nHYDRA_REDIRECTED_READY\n")
            .unwrap();
        std::io::stdout().flush().unwrap();
        loop {
            std::thread::park();
        }
    }
}
