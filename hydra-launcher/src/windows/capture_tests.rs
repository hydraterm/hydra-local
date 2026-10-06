//! Real subprocess chain without opening a GUI or using the installed package.
use super::*;
use std::os::windows::io::{AsRawHandle, FromRawHandle, OwnedHandle};
use std::sync::mpsc;
use std::time::{Duration, Instant};
use windows_sys::Win32::Foundation::{WAIT_OBJECT_0, WAIT_TIMEOUT};
use windows_sys::Win32::System::Threading::{
    OpenProcess, QueryFullProcessImageNameW, TerminateProcess, WaitForSingleObject,
    PROCESS_NAME_WIN32, PROCESS_QUERY_LIMITED_INFORMATION, PROCESS_TERMINATE,
    SYNCHRONIZATION_SYNCHRONIZE,
};

const CHILD_TEST: &str = "windows::capture_tests::capture_chain_child";

fn child_command(role: &str, root: &Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args(["--exact", CHILD_TEST, "--ignored", "--nocapture"])
        .env("HYDRA_LAUNCHER_CAPTURE_TEST_ROLE", role)
        .env("HYDRA_LAUNCHER_CAPTURE_TEST_ROOT", root)
        .creation_flags(CREATE_NO_WINDOW);
    command
}

#[test]
#[ignore = "subprocess entrypoint; exercised by capture_eof_does_not_wait_for_retained_child"]
fn capture_chain_child() {
    let root = PathBuf::from(std::env::var_os("HYDRA_LAUNCHER_CAPTURE_TEST_ROOT").unwrap());
    match std::env::var("HYDRA_LAUNCHER_CAPTURE_TEST_ROLE")
        .unwrap()
        .as_str()
    {
        "launcher" => {
            // Same entrypoint bootstrap and captured GUI/log ownership as the real launcher.
            process_stdio::detach_capture_pipe_inheritance().unwrap();
            let file = File::create(root.join("gui.log")).unwrap();
            let log = Arc::new(Mutex::new(BoundedLog { file, written: 0 }));
            assert!(run_logged_gui(child_command("gui", &root), log)
                .unwrap()
                .success());
            println!("launcher-finished");
        }
        "gui" => {
            // The real app clears only its own standard pipes. It cannot see older pipes
            // inherited from the launcher, which is why the launcher also needs the fix.
            process_stdio::detach_capture_pipe_inheritance().unwrap();
            let retained = child_command("retained", &root)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .spawn()
                .unwrap();
            fs::write(root.join("retained.pid"), retained.id().to_string()).unwrap();
            println!("gui-stdout");
            eprintln!("gui-stderr");
            // Deliberately retain the child after the GUI exits, exactly like the daemon.
            drop(retained);
        }
        "retained" => loop {
            std::thread::sleep(Duration::from_secs(1));
        },
        role => panic!("unexpected subprocess role: {role}"),
    }
}

struct RetainedChild(OwnedHandle);

impl Drop for RetainedChild {
    fn drop(&mut self) {
        // This is the held, image-verified process handle, never a later PID lookup.
        unsafe {
            TerminateProcess(self.0.as_raw_handle(), 0);
            WaitForSingleObject(self.0.as_raw_handle(), 5000);
        }
    }
}

fn capture(mut stream: impl Read + Send + 'static) -> mpsc::Receiver<io::Result<Vec<u8>>> {
    let (send, receive) = mpsc::channel();
    std::thread::spawn(move || {
        let mut bytes = Vec::new();
        let result = stream.read_to_end(&mut bytes).map(|_| bytes);
        let _ = send.send(result);
    });
    receive
}

#[test]
fn capture_eof_does_not_wait_for_retained_child() {
    // Exclude the test runner's own unrelated capture handles, not the pipes under test.
    process_stdio::detach_capture_pipe_inheritance().unwrap();
    let root = std::env::temp_dir().join(format!(
        "hydra-launcher-capture-{}-{}",
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    ));
    fs::create_dir(&root).unwrap();
    let mut launcher = child_command("launcher", &root)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let stdout = capture(launcher.stdout.take().unwrap());
    let stderr = capture(launcher.stderr.take().unwrap());
    let deadline = Instant::now() + Duration::from_secs(10);
    let pid = loop {
        if let Ok(text) = fs::read_to_string(root.join("retained.pid")) {
            if let Ok(pid) = text.parse::<u32>() {
                break pid;
            }
        }
        if Instant::now() >= deadline {
            let _ = launcher.kill();
            let _ = launcher.wait();
            panic!("GUI did not publish its retained child identity");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    let raw = unsafe {
        OpenProcess(
            PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_TERMINATE | SYNCHRONIZATION_SYNCHRONIZE,
            0,
            pid,
        )
    };
    assert!(
        !raw.is_null(),
        "open retained process: {}",
        io::Error::last_os_error()
    );
    let handle = unsafe { OwnedHandle::from_raw_handle(raw) };
    let mut image = vec![0_u16; 32768];
    let mut length = image.len() as u32;
    assert_ne!(
        unsafe {
            QueryFullProcessImageNameW(
                handle.as_raw_handle(),
                PROCESS_NAME_WIN32,
                image.as_mut_ptr(),
                &mut length,
            )
        },
        0
    );
    assert_eq!(
        fs::canonicalize(PathBuf::from(
            String::from_utf16(&image[..length as usize]).unwrap()
        ))
        .unwrap(),
        fs::canonicalize(std::env::current_exe().unwrap()).unwrap()
    );
    let retained = RetainedChild(handle);
    let status = loop {
        if let Some(status) = launcher.try_wait().unwrap() {
            break status;
        }
        if Instant::now() >= deadline {
            let _ = launcher.kill();
            let _ = launcher.wait();
            panic!("launcher did not finish after its GUI exited");
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    assert!(status.success());
    let out = stdout
        .recv_timeout(Duration::from_secs(5))
        .expect("launcher stdout EOF while retained child lives")
        .unwrap();
    let err = stderr
        .recv_timeout(Duration::from_secs(5))
        .expect("launcher stderr EOF while retained child lives")
        .unwrap();
    assert!(String::from_utf8(out)
        .unwrap()
        .contains("launcher-finished"));
    assert!(err.is_empty());
    let log = fs::read_to_string(root.join("gui.log")).unwrap();
    assert!(log.contains("gui-stdout"));
    assert!(log.contains("gui-stderr"));
    assert_eq!(
        unsafe { WaitForSingleObject(retained.0.as_raw_handle(), 0) },
        WAIT_TIMEOUT
    );
    assert_ne!(
        unsafe { TerminateProcess(retained.0.as_raw_handle(), 0) },
        0
    );
    assert_eq!(
        unsafe { WaitForSingleObject(retained.0.as_raw_handle(), 5000) },
        WAIT_OBJECT_0
    );
    drop(retained);
    fs::remove_dir_all(root).unwrap();
}
