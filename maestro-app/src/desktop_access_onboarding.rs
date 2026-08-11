//! Desktop-only Full Disk Access onboarding state.
//!
//! The persisted file records only that the current frozen application identity showed its
//! onboarding/action. It is never permission authority: every protected operation re-probes the
//! live capability through `maestro_shell::desktop_access`.

use std::io::{Read, Write};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};

use maestro_shell::desktop_access::{DesktopAccessStatus, FULL_DISK_ACCESS_REQUIRED_CODE};
use maestro_shell::AppPaths;
use serde::{Deserialize, Serialize};

const ACK_FILENAME: &str = "desktop-access-onboarding.json";
const MAX_ACK_BYTES: u64 = 4 * 1024;
const ACK_SCHEMA: u32 = 1;
static ACK_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(1);

/// Opaque version of the frozen responsible-code identity.
///
/// The suffix is the canonical binary designated-requirement SHA-256 for the official desktop
/// identity; it reveals neither signer name nor raw Team Identifier. A reviewed signing-identity
/// migration must change this value, which makes an
/// old acknowledgement inapplicable rather than silently carrying it to a new TCC identity.
pub const FROZEN_DESKTOP_ACCESS_IDENTITY: &str =
    "com.hydraterms.hydra:csreq-sha256:a9b02fd984e9ed2493df35266e817d04c86bf9913aac976c492e0f540b94f258";

/// Current System Settings deep link (macOS 13+).
pub const FULL_DISK_ACCESS_SETTINGS_URL: &str =
    "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Privacy_AllFiles";
/// Legacy System Preferences deep link (macOS 12 and earlier).
pub const LEGACY_FULL_DISK_ACCESS_SETTINGS_URL: &str =
    "x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles";
/// Final manual-pane fallback when either URL route is unavailable.
pub const SYSTEM_SETTINGS_BUNDLE_ID: &str = "com.apple.systempreferences";

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopAccessAcknowledgement {
    schema: u32,
    identity: String,
    acknowledged_at_ms: u64,
}

pub fn acknowledgement_path(paths: &AppPaths) -> PathBuf {
    paths.base().join(ACK_FILENAME)
}

/// Whether onboarding was acknowledged for the exact frozen responsible-code identity.
///
/// This value controls copy only. It must never be used to return `DesktopAccessStatus::Granted`
/// or to authorize filesystem/PTY work.
pub fn onboarding_acknowledged(paths: &AppPaths) -> bool {
    let path = acknowledgement_path(paths);
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let Ok(file) = options.open(path) else {
        return false;
    };
    let Ok(metadata) = file.metadata() else {
        return false;
    };
    if !metadata.file_type().is_file() || metadata.len() > MAX_ACK_BYTES {
        return false;
    }
    let mut body = Vec::with_capacity(metadata.len() as usize);
    if file.take(MAX_ACK_BYTES + 1).read_to_end(&mut body).is_err()
        || body.len() as u64 > MAX_ACK_BYTES
    {
        return false;
    }
    let Ok(record) = serde_json::from_slice::<DesktopAccessAcknowledgement>(&body) else {
        return false;
    };
    record.schema == ACK_SCHEMA
        && record.identity == FROZEN_DESKTOP_ACCESS_IDENTITY
        && record.acknowledged_at_ms > 0
}

/// Persist a non-authoritative onboarding acknowledgement atomically.
pub fn acknowledge_onboarding(paths: &AppPaths, acknowledged_at_ms: u64) -> std::io::Result<()> {
    let destination = acknowledgement_path(paths);
    let parent = destination
        .parent()
        .ok_or_else(|| std::io::Error::other("desktop access acknowledgement has no parent"))?;
    std::fs::create_dir_all(parent)?;

    let record = DesktopAccessAcknowledgement {
        schema: ACK_SCHEMA,
        identity: FROZEN_DESKTOP_ACCESS_IDENTITY.to_string(),
        acknowledged_at_ms: acknowledged_at_ms.max(1),
    };
    let body = serde_json::to_vec(&record)
        .map_err(|error| std::io::Error::other(format!("serialize acknowledgement: {error}")))?;
    let temporary = parent.join(format!(
        ".{ACK_FILENAME}.tmp.{}.{}",
        std::process::id(),
        ACK_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));

    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let mut file = options.open(&temporary)?;
    let result = file
        .write_all(&body)
        .and_then(|()| file.sync_all())
        .and_then(|()| {
            drop(file);
            std::fs::rename(&temporary, &destination)
        });
    if result.is_err() {
        let _ = std::fs::remove_file(&temporary);
    }
    result
}

pub fn status_wire(status: DesktopAccessStatus) -> &'static str {
    match status {
        DesktopAccessStatus::Granted => "granted",
        DesktopAccessStatus::Required => "required",
        DesktopAccessStatus::Unknown => "unknown",
        DesktopAccessStatus::NotApplicable => "not_applicable",
    }
}

pub fn dashboard_value(status: DesktopAccessStatus, acknowledged: bool) -> serde_json::Value {
    serde_json::json!({
        "status": status_wire(status),
        "onboarding_acknowledged": acknowledged,
        "required_error_code": FULL_DISK_ACCESS_REQUIRED_CODE,
    })
}

pub fn enrollment_allowed(status: DesktopAccessStatus) -> bool {
    matches!(
        status,
        DesktopAccessStatus::Granted | DesktopAccessStatus::NotApplicable
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    #[test]
    fn acknowledgement_is_tied_to_the_frozen_identity_and_not_a_grant() {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path());
        assert!(!onboarding_acknowledged(&paths));

        acknowledge_onboarding(&paths, 42).unwrap();
        assert!(onboarding_acknowledged(&paths));
        assert!(!enrollment_allowed(DesktopAccessStatus::Required));
        assert!(!enrollment_allowed(DesktopAccessStatus::Unknown));
    }

    #[test]
    fn stale_identity_malformed_and_oversize_records_are_ignored() {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path());
        let path = acknowledgement_path(&paths);

        std::fs::write(
            &path,
            br#"{"schema":1,"identity":"retired","acknowledged_at_ms":42}"#,
        )
        .unwrap();
        assert!(!onboarding_acknowledged(&paths));

        std::fs::write(&path, b"{").unwrap();
        assert!(!onboarding_acknowledged(&paths));

        std::fs::write(&path, vec![b'x'; MAX_ACK_BYTES as usize + 1]).unwrap();
        assert!(!onboarding_acknowledged(&paths));
    }

    #[test]
    fn dashboard_projection_is_typed_and_contains_no_permission_claim_from_ack() {
        assert_eq!(
            dashboard_value(DesktopAccessStatus::Required, true),
            serde_json::json!({
                "status": "required",
                "onboarding_acknowledged": true,
                "required_error_code": FULL_DISK_ACCESS_REQUIRED_CODE,
            })
        );
        assert!(enrollment_allowed(DesktopAccessStatus::Granted));
        assert!(enrollment_allowed(DesktopAccessStatus::NotApplicable));
    }

    #[test]
    fn settings_routes_are_fixed_system_targets() {
        assert!(FULL_DISK_ACCESS_SETTINGS_URL.starts_with("x-apple.systempreferences:"));
        assert!(LEGACY_FULL_DISK_ACCESS_SETTINGS_URL.starts_with("x-apple.systempreferences:"));
        assert_eq!(SYSTEM_SETTINGS_BUNDLE_ID, "com.apple.systempreferences");
    }

    #[cfg(unix)]
    #[test]
    fn acknowledgement_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;

        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path());
        acknowledge_onboarding(&paths, 42).unwrap();
        assert_eq!(
            std::fs::metadata(acknowledgement_path(&paths))
                .unwrap()
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
    }
}
