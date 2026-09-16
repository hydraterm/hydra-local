//! Actual shared Session fixtures. Native Windows execution is required; cross-compilation alone
//! does not prove ConPTY/retention behavior. Each parent runs in an exact owned child with a deadline.

use super::*;
use crate::windows_job::{owned_handle, process_exit_code, raw_handle};
use crate::windows_overlapped_io::tests::run_exact_owned_child;
use std::io::BufRead as _;
use std::os::windows::process::CommandExt as _;
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};
use windows_sys::Win32::System::Console::{
    GetConsoleScreenBufferInfo, GetStdHandle, CONSOLE_SCREEN_BUFFER_INFO, STD_OUTPUT_HANDLE,
};
use windows_sys::Win32::System::Threading::{
    OpenProcess, DETACHED_PROCESS, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_SYNCHRONIZE,
};

const CHILD: &str = "session::windows_session_tests::session_child";
const OBSERVATION: Duration = Duration::from_secs(5);

struct OwnedSession(Session);

impl Drop for OwnedSession {
    fn drop(&mut self) {
        // Fixture cleanup only, never a GUI-close policy. Parent deadline owns this exact process
        // if kernel cleanup cannot complete; final Job-handle closure is the descendant backstop.
        self.0.kill_and_wait(OBSERVATION);
    }
}

fn create_session(mode: &str, explicit_environment: bool) -> OwnedSession {
    let executable = std::env::current_exe().unwrap();
    let directory = std::env::current_dir().unwrap();
    let environment = maestro_protocol::ChildEnvironment {
        home: directory.to_str().unwrap().into(),
        shell: executable.to_str().unwrap().into(),
    };
    OwnedSession(
        Session::spawn(
            SessionId(format!("windows-session-{}", uuid::Uuid::new_v4())),
            directory.to_str().unwrap(),
            executable.to_str().unwrap(),
            &["--exact", CHILD, "--ignored", "--nocapture", "--", mode].map(str::to_owned),
            explicit_environment.then_some(&environment),
            120,
            30,
        )
        .unwrap(),
    )
}

fn wait_output(session: &Session, marker: &str) -> String {
    let deadline = Instant::now() + OBSERVATION;
    loop {
        let output = String::from_utf8(session.scrollback_snapshot()).unwrap();
        if output.contains(marker) {
            return output;
        }
        assert!(
            Instant::now() < deadline,
            "missing Session output: {marker}"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
}

fn wait_exit(session: &Session) {
    let deadline = Instant::now() + OBSERVATION;
    while session.exit_state().is_none() {
        assert!(
            Instant::now() < deadline,
            "Session did not publish final exit"
        );
        std::thread::sleep(Duration::from_millis(5));
    }
    assert!(session.native_lifetime.is_retired().unwrap());
}

#[test]
fn shared_session_retains_grid_generation_and_child_across_reattach() {
    const CASE: &str = "session::windows_session_tests::shared_session_retains_grid_generation_and_child_across_reattach";
    if run_exact_owned_child(CASE) {
        return;
    }
    // These are this exact disposable fixture process's values, before Session workers start.
    // No environment of the caller's daemon, GUI or another test process is changed.
    unsafe {
        std::env::set_var("TERM", "dumb");
        std::env::set_var("COLORTERM", "false");
        std::env::set_var("NO_COLOR", "1");
        std::env::set_var("PATH", r"C:\hydra-fixture-custom-path");
    }
    let owned = create_session("interactive", true);
    let session = &owned.0;
    let generation = session.generation();
    let attachment = session.acquire_attachment(None, 11).unwrap();
    let initial = session.attach_state();
    wait_output(session, "HYDRA_SESSION_READY");
    attachment.detach();
    drop(initial);
    assert!(!session.attachment_in_use());
    assert!(session.exit_state().is_none());
    let attachment = session.acquire_attachment(None, 12).unwrap();
    let restored = session.attach_state();
    assert_eq!(restored.snapshot.generation.to_string(), generation);
    let visible: String = restored
        .snapshot
        .rows_cells
        .iter()
        .flatten()
        .map(|cell| cell.text.as_str())
        .collect();
    assert!(visible.contains("HYDRA_SESSION_READY"));
    let handle = session.pty_handle();
    handle.resize(100, 35).unwrap();
    let grid = session.grid_snapshot();
    assert_eq!((grid.cols, grid.rows), (100, 35));
    assert_eq!(grid.generation.to_string(), generation);
    handle.write_input(b"probe\r").unwrap();
    wait_output(session, "HYDRA_SESSION_SIZE:100x35");
    handle.write_input(b"quit\r").unwrap();
    wait_output(session, "HYDRA_SESSION_DONE");
    wait_exit(session);
    assert_eq!(session.exit_state(), Some(Some(0)));
    let final_state = session.attach_state();
    assert_eq!(final_state.already_exited, Some(Some(0)));
    assert_eq!(final_state.snapshot.generation.to_string(), generation);
    attachment.detach();
    println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
}

#[test]
fn shared_session_keeps_exact_job_kill_after_root_exit_with_redirected_descendant() {
    const CASE: &str = "session::windows_session_tests::shared_session_keeps_exact_job_kill_after_root_exit_with_redirected_descendant";
    if run_exact_owned_child(CASE) {
        return;
    }
    let owned = create_session("descendant", false);
    let session = &owned.0;
    let generation = session.generation();
    let output = wait_output(session, "HYDRA_ROOT_WAITING");
    let pid: u32 = output
        .split("HYDRA_ROOT_PID:")
        .nth(1)
        .unwrap()
        .chars()
        .take_while(char::is_ascii_digit)
        .collect::<String>()
        .parse()
        .unwrap();
    // Capture a read/wait-only process handle while the known fixture root is gated on our input.
    // It still responds on this Session after capture, before exiting. No PID-based kill is used.
    let root = unsafe {
        owned_handle(
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_SYNCHRONIZE,
                0,
                pid,
            ),
            "fixture root",
        )
    }
    .unwrap();
    assert_eq!(process_exit_code(raw_handle(&root), 0).unwrap(), None);
    session.pty_handle().write_input(b"leave\r").unwrap();
    wait_output(session, "HYDRA_ROOT_DONE");
    assert_eq!(process_exit_code(raw_handle(&root), 5000).unwrap(), Some(0));
    assert!(!session.native_lifetime.is_retired().unwrap());
    assert!(
        session.exit_state().is_none(),
        "root exit must not publish final Session exit"
    );
    assert_eq!(
        session.live_generation().as_deref(),
        Some(generation.as_str())
    );
    // This is the actual shared explicit-kill path, after proven root completion.
    session.kill_child();
    wait_exit(session);
    assert_eq!(session.generation(), generation);
    println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
}

#[test]
fn windows_terminal_baseline_never_substitutes_unix_path() {
    for path in [
        None,
        Some(String::new()),
        Some(r"C:\custom;..\tools".into()),
    ] {
        let additions =
            terminal_env_overrides(|key| (key == "PATH").then(|| path.clone()).flatten());
        assert_eq!(
            additions,
            vec![("TERM", "xterm-256color"), ("COLORTERM", "truecolor")]
        );
        assert!(TERMINAL_ENV_REMOVALS.contains(&"NO_COLOR"));
    }
}

#[test]
#[ignore = "exact Session-owned interactive child entry"]
fn session_child() {
    let mode = std::env::args().next_back().unwrap();
    if mode == "descendant" {
        let mut descendant = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "session::windows_session_tests::redirected_child",
                "--ignored",
                "--nocapture",
            ])
            .creation_flags(DETACHED_PROCESS)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .unwrap();
        let output = descendant.stdout.take().unwrap();
        assert!(std::io::BufReader::new(output)
            .lines()
            .any(|line| line.unwrap() == "HYDRA_REDIRECTED_READY"));
        drop(descendant);
        println!(
            "\nHYDRA_ROOT_PID:{}\nHYDRA_ROOT_WAITING",
            std::process::id()
        );
        std::io::stdout().flush().unwrap();
        let mut line = String::new();
        std::io::stdin().read_line(&mut line).unwrap();
        assert_eq!(line.trim(), "leave");
        println!("\nHYDRA_ROOT_DONE");
        std::io::stdout().flush().unwrap();
        return;
    }
    assert_eq!(mode, "interactive");
    assert_eq!(std::env::var("TERM").unwrap(), "xterm-256color");
    assert_eq!(std::env::var("COLORTERM").unwrap(), "truecolor");
    assert!(std::env::var_os("NO_COLOR").is_none());
    assert_eq!(
        std::env::var("PATH").unwrap(),
        r"C:\hydra-fixture-custom-path"
    );
    // Direct Session composition preserves explicit Some values. The daemon validator still
    // rejects Windows Prefix components; this does not claim Windows headless wire support.
    assert_eq!(
        std::env::var_os("HOME").unwrap(),
        std::env::current_dir().unwrap()
    );
    assert_eq!(
        std::env::var_os("SHELL").unwrap(),
        std::env::current_exe().unwrap()
    );
    println!("\nHYDRA_SESSION_READY");
    std::io::stdout().flush().unwrap();
    let mut line = String::new();
    std::io::stdin().read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "probe");
    let mut info = CONSOLE_SCREEN_BUFFER_INFO::default();
    assert_ne!(
        unsafe { GetConsoleScreenBufferInfo(GetStdHandle(STD_OUTPUT_HANDLE), &mut info) },
        0
    );
    let size = (
        info.srWindow.Right - info.srWindow.Left + 1,
        info.srWindow.Bottom - info.srWindow.Top + 1,
    );
    assert_eq!(size, (100, 35));
    println!("\nHYDRA_SESSION_SIZE:100x35");
    std::io::stdout().flush().unwrap();
    line.clear();
    std::io::stdin().read_line(&mut line).unwrap();
    assert_eq!(line.trim(), "quit");
    println!("\nHYDRA_SESSION_DONE");
    std::io::stdout().flush().unwrap();
}

#[test]
#[ignore = "exact redirected descendant; only its fixture-owned Job terminates it"]
fn redirected_child() {
    std::io::stdout()
        .write_all(b"\nHYDRA_REDIRECTED_READY\n")
        .unwrap();
    std::io::stdout().flush().unwrap();
    loop {
        std::thread::park();
    }
}
