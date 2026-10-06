//! Real headless CLI wiring; isolated records only, no daemon, GUI or provider.
use std::path::{Path, PathBuf};
use std::process::Command;

/// Permit an exact copied test artifact for the limited native qualification account.
/// Never search PATH or infer a newer build; Cargo's artifact remains the default.
fn app_bin() -> &'static Path {
    static BINARY: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
    BINARY
        .get_or_init(|| {
            let path = std::env::var_os("HYDRA_TEST_APP_BINARY")
                .map(PathBuf::from)
                .unwrap_or_else(|| PathBuf::from(env!("CARGO_BIN_EXE_maestro-app")));
            assert!(
                path.is_absolute() && path.is_file(),
                "HYDRA_TEST_APP_BINARY (or Cargo app artifact) must name an existing absolute file"
            );
            path
        })
        .as_path()
}

fn run(base: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(app_bin())
        .args(args)
        .arg("--base")
        .arg(base)
        .output()
        .unwrap()
}

#[test]
fn create_appends_and_returns_identity_even_when_order_save_fails() {
    let temp = tempfile::tempdir().unwrap();
    for id in ["z-first", "a-second"] {
        let output = run(temp.path(), &["window", "create", "--window-id", id]);
        assert!(output.status.success());
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["window_id"], id);
        assert!(result.get("window_order_warning").is_none());
    }
    let file = maestro_app::settings_file_path(temp.path());
    let saved: serde_json::Value = serde_json::from_slice(&std::fs::read(&file).unwrap()).unwrap();
    assert_eq!(
        saved["global_window_order"],
        serde_json::json!(["z-first", "a-second"])
    );
    std::fs::write(&file, "broken json").unwrap();
    let output = run(
        temp.path(),
        &["window", "create", "--window-id", "created-once"],
    );
    assert!(
        output.status.success(),
        "metadata failure must not invite creation retry"
    );
    let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(result["ok"], true);
    assert_eq!(result["window_id"], "created-once");
    assert!(result["window_order_warning"]
        .as_str()
        .unwrap()
        .contains("settings file malformed"));
    assert_eq!(std::fs::read_to_string(&file).unwrap(), "broken json");
    let shown = run(
        temp.path(),
        &["window", "show", "--window-id", "created-once"],
    );
    assert!(shown.status.success());
    let result: serde_json::Value = serde_json::from_slice(&shown.stdout).unwrap();
    assert_eq!(result["window_id"], "created-once");
    assert!(result.get("window_order_warning").is_none());
}

#[test]
fn global_window_cli_persists_subset_order_across_processes_and_keeps_tab_command_distinct() {
    let temp = tempfile::tempdir().unwrap();
    for id in ["a", "b", "c"] {
        let output = run(temp.path(), &["window", "create", "--window-id", id]);
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let output = run(temp.path(), &["window", "reorder", "--order", "c,a"]);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(json["command"], "window reorder");
    assert_eq!(json["window_order"], serde_json::json!(["c", "b", "a"]));
    let output = run(temp.path(), &["window", "reorder", "--order", "b"]);
    assert!(output.status.success());
    let reopened: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(reopened["window_order"], json["window_order"]);
    assert_eq!(reopened["changed"], false);
    let file = maestro_app::settings_file_path(temp.path());
    let before = std::fs::read(&file).unwrap();
    for order in ["a,a", "a,missing", "../a", "a,", ""] {
        let failed = run(temp.path(), &["window", "reorder", "--order", order]);
        assert!(!failed.status.success(), "bad order accepted: {order}");
        assert_eq!(std::fs::read(&file).unwrap(), before);
    }
    let failed = run(
        temp.path(),
        &[
            "window",
            "reorder-tabs",
            "--window-id",
            "a",
            "--order",
            "b,c",
        ],
    );
    assert!(
        !failed.status.success(),
        "pane reorder accepted foreign window IDs"
    );
    assert_eq!(std::fs::read(file).unwrap(), before);
    let unknown = run(
        temp.path(),
        &["window", "reorder", "--window-id", "a", "--order", "a"],
    );
    assert!(!unknown.status.success());
}
