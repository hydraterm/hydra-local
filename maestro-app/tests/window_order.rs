//! Real headless CLI wiring; isolated records only, no daemon, GUI or provider.
use std::process::Command;

fn run(base: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_maestro-app"))
        .args(args)
        .arg("--base")
        .arg(base)
        .output()
        .unwrap()
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
