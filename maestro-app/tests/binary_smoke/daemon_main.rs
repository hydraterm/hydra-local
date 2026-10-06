//! Private integration-test fixture, never a distributed app binary.
#[cfg(windows)]
mod daemon;
#[cfg(windows)]
#[path = "../../src/bin_test_transport_windows.rs"]
mod test_transport;
#[cfg(windows)]
#[path = "../../src/windows_process_stdio.rs"]
mod windows_process_stdio;

#[cfg(not(windows))]
fn main() {}

#[cfg(windows)]
fn main() {
    let Some(endpoint) = std::env::args_os().nth(1) else {
        return;
    };
    // Cargo invokes harness-free tests without a pipe endpoint. Do not listen or mutate anything.
    if !endpoint
        .to_string_lossy()
        .starts_with(r"\\.\pipe\Hydra.Maestro.bin-test-")
    {
        return;
    }
    let config = std::env::current_exe()
        .expect("fixture exe")
        .with_extension("json");
    let values: std::collections::BTreeMap<String, String> =
        serde_json::from_slice(&std::fs::read(config).expect("read fixture sidecar"))
            .expect("decode fixture sidecar");
    // This is the single-threaded entrypoint of a dedicated fixture process, not the test runner.
    for (key, value) in values {
        assert!(key.starts_with("MAESTRO_FAKE_DAEMON_"));
        std::env::set_var(key, value);
    }
    std::env::set_var(daemon::FAKE_DAEMON_ENV, &endpoint);
    daemon::maybe_run_fake_daemon();
}
