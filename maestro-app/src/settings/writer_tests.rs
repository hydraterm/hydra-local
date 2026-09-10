use super::*;
use std::sync::mpsc;
use std::time::Duration;
#[cfg(unix)]
use std::time::Instant;

fn mutate(base: &Path, action: &str) -> Result<SettingsSetSuccess, SettingsFailure> {
    match action {
        "font" => set_font_size_px(base, 20),
        "theme" => set_theme(base, THEME_HIGH_CONTRAST_DARK),
        "chrome" => set_chrome_default(base, ChromeDefaultKey::CopyOnSelect, true),
        "consent" => {
            set_workspace_consent(base, WorkspaceConsentKey::WorktreeRequiresConsent, false)
        }
        "policy" => set_workspace_default_policy(base, WORKSPACE_POLICY_REPO_WRITE),
        "shell" => set_shell_default_argv(base, &["/bin/sh".into(), "-l".into()]),
        "reset_key" => reset_appearance_setting(base, SettingsResetTarget::FontSizePx),
        "reset_all" => reset_all_settings(base),
        _ => panic!("unknown settings fixture action"),
    }
}

fn publish_sibling(base: &Path, writer: &writer::SettingsWriteGuard) {
    let LoadedSettings::Honored(mut next) = load_persisted(&settings_file_path(base)) else {
        panic!("fixture must have settings")
    };
    next.appearance.font_size_px = 24;
    next.chrome.picker_overlay_default = Some(true);
    write_settings_atomic(base, &next, writer).unwrap();
}

#[test]
fn every_mutator_waits_before_reading_and_preserves_the_fresh_sibling() {
    for action in [
        "font",
        "theme",
        "chrome",
        "consent",
        "policy",
        "shell",
        "reset_key",
        "reset_all",
    ] {
        let base = tempfile::tempdir().unwrap();
        set_font_size_px(base.path(), 20).unwrap();
        let writer = writer::SettingsWriteGuard::acquire(base.path()).unwrap();
        let (ready_tx, ready_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let child_base = base.path().to_path_buf();
        let child = std::thread::spawn(move || {
            ready_tx.send(()).unwrap();
            done_tx.send(mutate(&child_base, action)).unwrap();
        });
        ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
        assert!(
            matches!(
                done_rx.recv_timeout(Duration::from_millis(100)),
                Err(mpsc::RecvTimeoutError::Timeout)
            ),
            "{action} bypassed the writer"
        );
        // This committed sibling and the font's changed/no-op decision must be read AFTER the lock.
        publish_sibling(base.path(), &writer);
        drop(writer);
        let result = done_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .unwrap();
        child.join().unwrap();
        assert!(result.changed, "{action} used a stale no-op decision");
        assert_eq!(
            result.settings.chrome.picker_overlay_default,
            action != "reset_all",
            "{action} lost the committed sibling"
        );
        assert_eq!(
            serde_json::to_value(&result.settings).unwrap(),
            serde_json::to_value(effective_settings(base.path())).unwrap()
        );
        if action == "font" {
            assert_eq!(result.settings.appearance.font_size_px, 20);
        }
        if action == "reset_key" || action == "reset_all" {
            assert_eq!(
                result.settings.appearance.font_size_px,
                DEFAULT_FONT_SIZE_PX
            );
        }
    }
}

#[test]
fn independent_threads_merge_different_settings_without_temp_file_collisions() {
    let base = tempfile::tempdir().unwrap();
    let barrier = std::sync::Arc::new(std::sync::Barrier::new(6));
    let children = ["font", "theme", "chrome", "consent", "policy", "shell"].map(|action| {
        let path = base.path().to_path_buf();
        let barrier = barrier.clone();
        std::thread::spawn(move || {
            barrier.wait();
            mutate(&path, action).unwrap();
        })
    });
    for child in children {
        child.join().unwrap();
    }
    let result = effective_settings(base.path());
    assert_eq!(result.appearance.font_size_px, 20);
    assert_eq!(result.appearance.theme, THEME_HIGH_CONTRAST_DARK);
    assert!(result.chrome.copy_on_select);
    assert!(!result.workspace.worktree_requires_consent);
    assert_eq!(result.workspace.default_policy, WORKSPACE_POLICY_REPO_WRITE);
    assert_eq!(
        result.shell.default_argv,
        Some(vec!["/bin/sh".into(), "-l".into()])
    );
    assert!(std::fs::read_dir(settings_dir(base.path()))
        .unwrap()
        .all(|entry| !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .contains(".tmp.")));
}

#[cfg(unix)]
#[test]
fn a_waiting_profile_does_not_block_an_independent_profile() {
    let base_a = tempfile::tempdir().unwrap();
    let base_b = tempfile::tempdir().unwrap();
    set_font_size_px(base_a.path(), 20).unwrap();
    let writer_a = writer::SettingsWriteGuard::acquire(base_a.path()).unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let (done_a_tx, done_a_rx) = mpsc::channel();
    let path_a = base_a.path().to_path_buf();
    let child_a = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        done_a_tx.send(mutate(&path_a, "theme")).unwrap();
    });
    ready_rx.recv_timeout(Duration::from_secs(3)).unwrap();
    let a_before_b = done_a_rx.recv_timeout(Duration::from_millis(100));
    let (done_b_tx, done_b_rx) = mpsc::channel();
    let path_b = base_b.path().to_path_buf();
    let child_b = std::thread::spawn(move || {
        done_b_tx.send(mutate(&path_b, "font")).unwrap();
    });
    // Capture progress before releasing A; release/join even if the old global mutex caused a
    // timeout, so the regression failure does not leave fixture threads waiting on our guard.
    let b_while_a_held = done_b_rx.recv_timeout(Duration::from_secs(3));
    let a_still_waiting = done_a_rx.try_recv();
    drop(writer_a);
    child_a.join().unwrap();
    child_b.join().unwrap();
    assert!(matches!(a_before_b, Err(mpsc::RecvTimeoutError::Timeout)));
    assert!(matches!(a_still_waiting, Err(mpsc::TryRecvError::Empty)));
    let result_b = b_while_a_held
        .expect("profile B must complete while profile A remains locked")
        .unwrap();
    assert_eq!(result_b.settings.appearance.font_size_px, 20);
    let result_a = done_a_rx.recv().unwrap().unwrap();
    assert_eq!(result_a.settings.appearance.font_size_px, 20);
    assert_eq!(result_a.settings.appearance.theme, THEME_HIGH_CONTRAST_DARK);
    assert_eq!(
        effective_settings(base_b.path()).appearance.theme,
        THEME_BUILT_IN_DARK
    );
}

#[test]
fn readers_remain_lock_free_and_reset_keeps_the_coordination_inode() {
    let base = tempfile::tempdir().unwrap();
    set_font_size_px(base.path(), 20).unwrap();
    let writer = writer::SettingsWriteGuard::acquire(base.path()).unwrap();
    let (done_tx, done_rx) = mpsc::channel();
    let path = base.path().to_path_buf();
    let reader = std::thread::spawn(move || {
        done_tx.send(effective_settings(&path)).unwrap();
    });
    assert_eq!(
        done_rx
            .recv_timeout(Duration::from_secs(3))
            .unwrap()
            .appearance
            .font_size_px,
        20
    );
    reader.join().unwrap();
    drop(writer);
    #[cfg(unix)]
    let inode = {
        use std::os::unix::fs::MetadataExt;
        std::fs::metadata(settings_dir(base.path()).join(".settings-writer.lock"))
            .unwrap()
            .ino()
    };
    reset_all_settings(base.path()).unwrap();
    assert!(!settings_file_path(base.path()).exists());
    set_theme(base.path(), THEME_HIGH_CONTRAST_DARK).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let metadata =
            std::fs::metadata(settings_dir(base.path()).join(".settings-writer.lock")).unwrap();
        assert_eq!(metadata.ino(), inode);
        assert_eq!(metadata.nlink(), 1);
        assert_eq!(metadata.permissions().mode() & 0o777, 0o600);
    }
}

#[test]
fn malformed_foreign_and_invalid_inputs_keep_existing_behavior() {
    for raw in [
        "{not-json",
        r#"{"schema_version":999,"appearance":{"font_size_px":16}}"#,
    ] {
        let base = tempfile::tempdir().unwrap();
        create_dir_private(&settings_dir(base.path())).unwrap();
        std::fs::write(settings_file_path(base.path()), raw).unwrap();
        for action in [
            "font",
            "theme",
            "chrome",
            "consent",
            "policy",
            "shell",
            "reset_key",
            "reset_all",
        ] {
            assert_eq!(
                mutate(base.path(), action).unwrap_err().error_kind,
                "settings_conflict"
            );
            assert_eq!(
                std::fs::read_to_string(settings_file_path(base.path())).unwrap(),
                raw
            );
        }
    }
    let base = tempfile::tempdir().unwrap();
    assert_eq!(
        set_font_size_px(base.path(), 1).unwrap_err().error_kind,
        "bad_usage"
    );
    assert_eq!(
        set_theme(base.path(), "invalid").unwrap_err().error_kind,
        "bad_usage"
    );
    assert_eq!(
        set_workspace_default_policy(base.path(), "invalid")
            .unwrap_err()
            .error_kind,
        "bad_usage"
    );
    assert_eq!(
        set_shell_default_argv(base.path(), &[])
            .unwrap_err()
            .error_kind,
        "bad_usage"
    );
    assert!(!settings_dir(base.path()).exists());
}

#[cfg(unix)]
struct ChildFixture(std::process::Child);

#[cfg(unix)]
impl Drop for ChildFixture {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[cfg(unix)]
fn wait_for(mut condition: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while !condition() {
        assert!(
            Instant::now() < deadline,
            "settings child fixture did not reach its checkpoint"
        );
        std::thread::sleep(Duration::from_millis(10));
    }
}

#[cfg(unix)]
#[test]
fn child_settings_writer() {
    let Some(base) = std::env::var_os("HYDRA_SETTINGS_WRITER_TEST_BASE") else {
        return;
    };
    let base = PathBuf::from(base);
    let action = std::env::var("HYDRA_SETTINGS_WRITER_TEST_ACTION").unwrap();
    std::fs::write(base.join("child-ready"), b"ready").unwrap();
    mutate(&base, &action).unwrap();
}

#[cfg(unix)]
#[test]
fn separate_process_set_and_reset_wait_for_the_same_complete_transaction() {
    for action in ["theme", "reset_all"] {
        let base = tempfile::tempdir().unwrap();
        set_font_size_px(base.path(), 20).unwrap();
        let writer = writer::SettingsWriteGuard::acquire(base.path()).unwrap();
        let mut child = ChildFixture(
            std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "settings::writer_tests::child_settings_writer",
                    "--nocapture",
                ])
                .env("HYDRA_SETTINGS_WRITER_TEST_BASE", base.path())
                .env("HYDRA_SETTINGS_WRITER_TEST_ACTION", action)
                .spawn()
                .unwrap(),
        );
        wait_for(|| base.path().join("child-ready").exists());
        std::thread::sleep(Duration::from_millis(100));
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "{action} bypassed cross-process locking"
        );
        publish_sibling(base.path(), &writer);
        drop(writer);
        let mut status = None;
        wait_for(|| {
            status = child.0.try_wait().unwrap();
            status.is_some()
        });
        assert!(status.unwrap().success());
        let result = effective_settings(base.path());
        if action == "reset_all" {
            assert_eq!(result.source, "defaults");
            assert!(!settings_file_path(base.path()).exists());
        } else {
            assert_eq!(result.appearance.font_size_px, 24);
            assert_eq!(result.appearance.theme, THEME_HIGH_CONTRAST_DARK);
            assert!(result.chrome.picker_overlay_default);
        }
    }
}
