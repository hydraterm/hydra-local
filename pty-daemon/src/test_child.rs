//! Portable children for daemon invariant tests. Unix keeps the original executable/argv;
//! Windows runs an exact entry in this test executable, never a shell/PATH approximation.

use crate::daemon::{Daemon, SharedDaemon};
use crate::ids::SessionId;
use std::sync::OnceLock;

pub(crate) struct Command {
    program: String,
    arguments: Vec<String>,
}

impl Command {
    pub(crate) fn program(&self) -> &str {
        &self.program
    }

    pub(crate) fn args(&self) -> &[String] {
        &self.arguments
    }
}

fn command(unix_program: &str, unix_arguments: &[&str], child: &str) -> Command {
    #[cfg(not(windows))]
    {
        let _ = child;
        Command {
            program: unix_program.into(),
            arguments: unix_arguments.iter().map(|value| (*value).into()).collect(),
        }
    }
    #[cfg(windows)]
    {
        let _ = (unix_program, unix_arguments);
        Command {
            program: std::env::current_exe()
                .expect("exact fixture executable")
                .into_os_string()
                .into_string()
                .expect("fixture executable path is Unicode"),
            arguments: [
                "--exact",
                child,
                "--ignored",
                "--nocapture",
                "--test-threads=1",
            ]
            .map(str::to_owned)
            .into(),
        }
    }
}

pub(crate) fn idle() -> &'static Command {
    static COMMAND: OnceLock<Command> = OnceLock::new();
    COMMAND.get_or_init(|| command("sleep", &["30"], "test_child::idle_child"))
}

pub(crate) fn exits() -> &'static Command {
    static COMMAND: OnceLock<Command> = OnceLock::new();
    COMMAND.get_or_init(|| command("true", &[], "test_child::exit_child"))
}

pub(crate) fn echo() -> &'static Command {
    static COMMAND: OnceLock<Command> = OnceLock::new();
    COMMAND.get_or_init(|| command("cat", &[], "test_child::echo_child"))
}

/// Run a synchronous fixture's Windows daemon through the real async ownership adapter.
/// A dedicated runtime thread also permits cleanup from tests already inside a Tokio runtime.
/// No Session is dropped or removed while transferring the complete fixture-owned map.
#[cfg(windows)]
pub(crate) fn with_daemon<F, Fut, T>(daemon: &mut Daemon, run: F) -> T
where
    F: FnOnce(SharedDaemon) -> Fut + Send + 'static,
    Fut: std::future::Future<Output = T>,
    T: Send + 'static,
{
    let owned = std::mem::take(daemon);
    let (restored, result) = std::thread::spawn(move || {
        let shared = std::sync::Arc::new(tokio::sync::Mutex::new(owned));
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("fixture retirement runtime");
        let result = runtime.block_on(run(shared.clone()));
        drop(runtime);
        let restored = std::sync::Arc::try_unwrap(shared)
            .unwrap_or_else(|_| panic!("fixture retirement still owns daemon after completion"))
            .into_inner();
        (restored, result)
    })
    .join()
    .expect("fixture retirement worker");
    *daemon = restored;
    result
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) enum KillOutcome {
    Absent,
    GenerationMismatch,
    AttachmentInUse,
    Retired,
}

/// Same exact-generation/attachment assertions, using the platform's real retirement path.
pub(crate) async fn conditional_kill_shared(
    shared: &SharedDaemon,
    id: &SessionId,
    generation: &str,
) -> KillOutcome {
    #[cfg(not(windows))]
    {
        use crate::daemon::ConditionalSessionTake;
        let taken = shared
            .lock()
            .await
            .take_session_if_generation(id, generation);
        match taken {
            ConditionalSessionTake::Absent => KillOutcome::Absent,
            ConditionalSessionTake::GenerationMismatch => KillOutcome::GenerationMismatch,
            ConditionalSessionTake::AttachmentInUse => KillOutcome::AttachmentInUse,
            ConditionalSessionTake::Taken(session) => {
                session.kill_child();
                KillOutcome::Retired
            }
        }
    }
    #[cfg(windows)]
    {
        let expected = {
            let daemon = shared.lock().await;
            match daemon.session(id) {
                Err(_) => KillOutcome::Absent,
                Ok(session) if session.generation() != generation => {
                    KillOutcome::GenerationMismatch
                }
                Ok(session) if session.attachment_in_use() => KillOutcome::AttachmentInUse,
                Ok(_) => KillOutcome::Retired,
            }
        };
        let proof = shared.lock().await.session(id).ok().map(|session| {
            (
                session.generation(),
                session.grid_handle(),
                session.native_lifetime(),
            )
        });
        let result = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            crate::windows_session_retirement::kill(shared, id, generation),
        )
        .await
        .expect("exact native retirement exceeded fixture deadline");
        match expected {
            KillOutcome::Absent => assert!(result.is_ok()),
            KillOutcome::GenerationMismatch | KillOutcome::AttachmentInUse => {
                assert!(result.is_err(), "invalid retirement unexpectedly succeeded");
                assert_eq!(
                    shared.lock().await.session(id).unwrap().generation(),
                    proof.unwrap().0
                );
            }
            KillOutcome::Retired => {
                result.expect("exact native retirement failed");
                let (_, grid, lifetime) = proof.unwrap();
                assert!(
                    grid.exit_state().is_some(),
                    "retirement must publish final exit"
                );
                assert!(
                    lifetime.is_retired().unwrap(),
                    "exact native Job must retire"
                );
                assert!(shared.lock().await.session(id).is_err());
            }
        }
        expected
    }
}

pub(crate) fn conditional_kill(
    daemon: &mut Daemon,
    id: &SessionId,
    generation: &str,
) -> KillOutcome {
    #[cfg(windows)]
    {
        let id = id.clone();
        let generation = generation.to_owned();
        with_daemon(daemon, move |shared| async move {
            conditional_kill_shared(&shared, &id, &generation).await
        })
    }
    #[cfg(not(windows))]
    {
        use crate::daemon::ConditionalSessionTake;
        match daemon.take_session_if_generation(id, generation) {
            ConditionalSessionTake::Absent => KillOutcome::Absent,
            ConditionalSessionTake::GenerationMismatch => KillOutcome::GenerationMismatch,
            ConditionalSessionTake::AttachmentInUse => KillOutcome::AttachmentInUse,
            ConditionalSessionTake::Taken(session) => {
                session.kill_child();
                KillOutcome::Retired
            }
        }
    }
}

#[cfg(windows)]
const IDLE_READY: &str = "HYDRA_DAEMON_IDLE_CHILD_READY";

/// Separate native executable/console startup from a fixture's retirement deadline.
/// Observing the marker proves the owned child ran and the real output pump consumed bytes.
#[cfg(windows)]
pub(crate) fn wait_idle_ready(daemon: &Daemon, id: &SessionId) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(5);
    loop {
        let session = daemon
            .session(id)
            .expect("owned idle fixture remains mapped");
        let output = session.scrollback_snapshot();
        let ready = output
            .windows(IDLE_READY.len())
            .any(|bytes| bytes == IDLE_READY.as_bytes());
        let exited = session.exit_state();
        assert!(
            exited.is_none(),
            "idle fixture {id:?} exited before readiness: marker={ready}, output_bytes={}, exit={exited:?}",
            output.len()
        );
        if ready {
            return;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "idle fixture {id:?} readiness timed out: marker=false, output_bytes={}, exit={exited:?}, job_retired={:?}",
            output.len(),
            session.native_lifetime().is_retired()
        );
        std::thread::sleep(std::time::Duration::from_millis(10));
    }
}

#[cfg(windows)]
#[test]
#[ignore = "exact native child entry; only fixture parents invoke it"]
fn idle_child() {
    use std::io::Write as _;
    let mut stdout = std::io::stdout().lock();
    writeln!(stdout, "\n{IDLE_READY}").expect("idle fixture readiness");
    stdout.flush().expect("idle fixture readiness flush");
    drop(stdout);
    std::thread::sleep(std::time::Duration::from_secs(30));
}

#[cfg(windows)]
#[test]
#[ignore = "exact native child entry; only fixture parents invoke it"]
fn exit_child() {
    std::process::exit(0);
}

#[cfg(windows)]
#[test]
#[ignore = "exact native child entry; only fixture parents invoke it"]
fn echo_child() {
    use std::io::{Read as _, Write as _};
    use windows_sys::Win32::System::Console::{
        GetConsoleMode, GetStdHandle, SetConsoleMode, ENABLE_ECHO_INPUT, ENABLE_LINE_INPUT,
        STD_INPUT_HANDLE,
    };
    // The fixture consumes bytes, not shell syntax or cooked console line editing. This keeps
    // the shared Write tests' literal LF input meaningful on both native PTY backends.
    let input = unsafe { GetStdHandle(STD_INPUT_HANDLE) };
    let mut mode = 0;
    assert_ne!(unsafe { GetConsoleMode(input, &mut mode) }, 0);
    assert_ne!(
        unsafe { SetConsoleMode(input, mode & !(ENABLE_LINE_INPUT | ENABLE_ECHO_INPUT)) },
        0
    );
    let mut buffer = [0u8; 1024];
    let mut stdin = std::io::stdin().lock();
    let mut stdout = std::io::stdout().lock();
    loop {
        let count = stdin.read(&mut buffer).expect("native echo input");
        if count == 0 {
            break;
        }
        stdout
            .write_all(&buffer[..count])
            .expect("native echo output");
        stdout.flush().expect("native echo flush");
    }
}
