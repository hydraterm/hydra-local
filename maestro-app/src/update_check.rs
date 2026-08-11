//! Non-blocking update check against the published `downloads/version.json`.
//!
//! The stable desktop feed is a complete `hydra.desktop-update-manifest.v1`, not merely a version
//! string. The checker validates that exact shape, the release identity, every immutable artifact
//! path and digest, then publishes a small presentation model for the React dashboard. JavaScript
//! never supplies a URL: the typed update action can only open the validated immutable artifact for
//! this compiled platform in the system browser.
//!
//! This module deliberately does not replace the running application, invoke a package manager,
//! request elevation, or touch the PTY daemon. A real one-click installer needs a separately
//! reviewed signed-updater architecture. The current action is an explicit, user-visible download
//! step that leaves retained sessions alone.
//!
//! The request is a plain, content-blind GET with no device/account identifiers. It only exists as
//! automatic behavior when the binary is compiled with the default-off `official-distribution`
//! feature. Community/source builds therefore make no update request. Official builds use one
//! fixed HTTPS origin with no runtime override, retain hard time and size bounds, and may still be
//! disabled by `HYDRA_NO_UPDATE_CHECK=1`. A one-shot completion signal makes the foreground
//! listener publish the terminal result without waiting for an incidental UI event.

use serde::Serialize;
use std::process::Command;
use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc, Mutex, OnceLock,
};

#[cfg_attr(not(feature = "official-distribution"), allow(dead_code))]
const STABLE_MANIFEST_PATH: &str = "/downloads/version.json";
const RELEASE_ORIGIN: &str = "https://app.hydraterms.com";
const MAX_MANIFEST_BYTES: usize = 1024 * 1024;
const MANIFEST_SCHEMA: &str = "hydra.desktop-update-manifest.v1";
const PRODUCT: &str = "hydra";
const CHANNEL: &str = "stable";

static UPDATE_SNAPSHOT: OnceLock<Mutex<UpdateSnapshot>> = OnceLock::new();
static UPDATE_OPEN_GATE: OneInFlight = OneInFlight::new();

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateStatus {
    NotChecked,
    Checking,
    UpToDate,
    Available,
    Unavailable,
    Disabled,
}

/// Presentation-only update state included in every native dashboard model.
///
/// The immutable URL intentionally stays native-only. The dashboard receives enough exact release
/// identity for truthful UI and diagnostics, but its action is a no-payload typed intent.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct UpdateDashboardModel {
    pub status: UpdateStatus,
    pub current_version: String,
    pub latest_version: Option<String>,
    pub release_git_sha: Option<String>,
    pub published_at: Option<String>,
    pub download_artifact: Option<String>,
    pub download_sha256: Option<String>,
    pub action_available: bool,
}

/// One-shot signal that the foreground listener uses to publish the check's terminal state.
///
/// The receiver remains native-only. A completed or disconnected worker is consumed exactly once;
/// either result tells the listener to re-read [`dashboard_model`] immediately.
pub struct UpdateCheckCompletion {
    receiver: Option<mpsc::Receiver<()>>,
}

impl UpdateCheckCompletion {
    pub fn try_take(&mut self) -> bool {
        let Some(receiver) = self.receiver.as_ref() else {
            return false;
        };
        match receiver.try_recv() {
            Ok(()) | Err(mpsc::TryRecvError::Disconnected) => {
                self.receiver = None;
                true
            }
            Err(mpsc::TryRecvError::Empty) => false,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct UpdateSnapshot {
    dashboard: UpdateDashboardModel,
    download_url: Option<String>,
}

impl UpdateSnapshot {
    fn without_manifest(status: UpdateStatus, current_version: &str) -> Self {
        Self {
            dashboard: UpdateDashboardModel {
                status,
                current_version: current_version.to_string(),
                latest_version: None,
                release_git_sha: None,
                published_at: None,
                download_artifact: None,
                download_sha256: None,
                action_available: false,
            },
            download_url: None,
        }
    }
}

// Every shipping variant is exercised by the pure manifest tests even though one compiled binary
// constructs only its own target variant.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum UpdatePlatform {
    MacosUniversal,
    LinuxAmd64,
    LinuxArm64,
    Unsupported,
}

impl UpdatePlatform {
    fn artifact(self) -> Option<(&'static str, &'static str)> {
        match self {
            Self::MacosUniversal => Some(("macos-universal-dmg", "Hydra-macOS.dmg")),
            Self::LinuxAmd64 => Some(("linux-amd64-deb", "Hydra-linux-amd64.deb")),
            Self::LinuxArm64 => Some(("linux-arm64-deb", "Hydra-linux-arm64.deb")),
            Self::Unsupported => None,
        }
    }
}

fn current_platform() -> UpdatePlatform {
    #[cfg(target_os = "macos")]
    {
        return UpdatePlatform::MacosUniversal;
    }
    #[cfg(all(target_os = "linux", target_arch = "x86_64"))]
    {
        return UpdatePlatform::LinuxAmd64;
    }
    #[cfg(all(target_os = "linux", target_arch = "aarch64"))]
    {
        return UpdatePlatform::LinuxArm64;
    }
    #[allow(unreachable_code)]
    UpdatePlatform::Unsupported
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct DesktopUpdateManifest {
    schema: String,
    product: String,
    channel: String,
    version: String,
    git_sha: String,
    published_at: String,
    downloads: ManifestDownloads,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDownloads {
    #[serde(rename = "macos-universal-dmg")]
    macos_universal_dmg: ManifestDownload,
    #[serde(rename = "linux-amd64-deb")]
    linux_amd64_deb: ManifestDownload,
    #[serde(rename = "linux-arm64-deb")]
    linux_arm64_deb: ManifestDownload,
    #[serde(rename = "linux-amd64-tar")]
    linux_amd64_tar: ManifestDownload,
    #[serde(rename = "linux-arm64-tar")]
    linux_arm64_tar: ManifestDownload,
}

#[derive(Debug, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ManifestDownload {
    url: String,
    sha256: String,
}

impl ManifestDownloads {
    fn all(&self) -> [(&'static str, &'static str, &ManifestDownload); 5] {
        [
            (
                "macos-universal-dmg",
                "Hydra-macOS.dmg",
                &self.macos_universal_dmg,
            ),
            (
                "linux-amd64-deb",
                "Hydra-linux-amd64.deb",
                &self.linux_amd64_deb,
            ),
            (
                "linux-arm64-deb",
                "Hydra-linux-arm64.deb",
                &self.linux_arm64_deb,
            ),
            (
                "linux-amd64-tar",
                "Hydra-linux-amd64.tar.gz",
                &self.linux_amd64_tar,
            ),
            (
                "linux-arm64-tar",
                "Hydra-linux-arm64.tar.gz",
                &self.linux_arm64_tar,
            ),
        ]
    }

    fn for_platform(&self, platform: UpdatePlatform) -> Option<&ManifestDownload> {
        match platform {
            UpdatePlatform::MacosUniversal => Some(&self.macos_universal_dmg),
            UpdatePlatform::LinuxAmd64 => Some(&self.linux_amd64_deb),
            UpdatePlatform::LinuxArm64 => Some(&self.linux_arm64_deb),
            UpdatePlatform::Unsupported => None,
        }
    }
}

fn snapshot_store() -> &'static Mutex<UpdateSnapshot> {
    UPDATE_SNAPSHOT.get_or_init(|| {
        Mutex::new(UpdateSnapshot::without_manifest(
            UpdateStatus::NotChecked,
            env!("CARGO_PKG_VERSION"),
        ))
    })
}

fn publish_snapshot(snapshot: UpdateSnapshot) {
    *snapshot_store()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = snapshot;
}

fn current_snapshot() -> UpdateSnapshot {
    snapshot_store()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .clone()
}

/// Exact update state for inclusion in the native dashboard model.
pub fn dashboard_model() -> UpdateDashboardModel {
    current_snapshot().dashboard
}

/// Spawn the production stable-feed check once for this foreground launch and return immediately.
///
/// The caller owns the completion signal and must connect it to the dashboard listener. There is no
/// production URL override: development tests exercise the parser directly.
pub fn spawn_update_check() -> UpdateCheckCompletion {
    let (completion_tx, completion_rx) = mpsc::channel();
    let completion = UpdateCheckCompletion {
        receiver: Some(completion_rx),
    };
    let current = env!("CARGO_PKG_VERSION");
    let Some(manifest_url) = compiled_manifest_url() else {
        publish_snapshot(UpdateSnapshot::without_manifest(
            UpdateStatus::Disabled,
            current,
        ));
        let _ = completion_tx.send(());
        return completion;
    };
    if std::env::var_os("HYDRA_NO_UPDATE_CHECK").is_some() {
        publish_snapshot(UpdateSnapshot::without_manifest(
            UpdateStatus::Disabled,
            current,
        ));
        let _ = completion_tx.send(());
        return completion;
    }

    publish_snapshot(UpdateSnapshot::without_manifest(
        UpdateStatus::Checking,
        current,
    ));
    if std::thread::Builder::new()
        .name("hydra-update-check".to_string())
        .spawn(move || check_and_publish(&manifest_url, completion_tx))
        .is_err()
    {
        publish_snapshot(UpdateSnapshot::without_manifest(
            UpdateStatus::Unavailable,
            current,
        ));
        // The sender was dropped with the failed spawn closure. A disconnected receiver is the
        // explicit terminal signal, so the listener still publishes `unavailable`.
    }
    completion
}

fn check_and_publish(manifest_url: &str, completion: mpsc::Sender<()>) {
    let current = env!("CARGO_PKG_VERSION");
    let snapshot = fetch(manifest_url)
        .and_then(|body| evaluate_manifest(&body, current, RELEASE_ORIGIN, current_platform()).ok())
        .unwrap_or_else(|| UpdateSnapshot::without_manifest(UpdateStatus::Unavailable, current));
    let available_version = (snapshot.dashboard.status == UpdateStatus::Available)
        .then(|| snapshot.dashboard.latest_version.clone())
        .flatten();
    publish_snapshot(snapshot);
    let _ = completion.send(());

    if let Some(remote) = available_version {
        let download_page = download_page_url(RELEASE_ORIGIN)
            .unwrap_or_else(|| "https://app.hydraterms.com/#downloads".to_string());
        eprintln!(
            "hydra update: v{remote} is available (this is v{current}) — download at {download_page}"
        );
        notify(&remote, &download_page);
    }
}

fn compiled_manifest_url() -> Option<String> {
    #[cfg(feature = "official-distribution")]
    {
        return manifest_url_for(RELEASE_ORIGIN, STABLE_MANIFEST_PATH);
    }
    #[cfg(not(feature = "official-distribution"))]
    {
        None
    }
}

#[cfg_attr(not(feature = "official-distribution"), allow(dead_code))]
fn manifest_url_for(app_origin: &str, manifest_path: &str) -> Option<String> {
    (manifest_path == STABLE_MANIFEST_PATH && trusted_https_origin(app_origin))
        .then(|| format!("{app_origin}{manifest_path}"))
}

fn fetch(url: &str) -> Option<String> {
    let out = fetch_command(url)?.output().ok()?;
    if !out.status.success() || out.stdout.len() > MAX_MANIFEST_BYTES {
        return None;
    }
    String::from_utf8(out.stdout).ok()
}

fn fetch_command(url: &str) -> Option<Command> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mut command = Command::new("/usr/bin/curl");
        command.args([
            "-q",
            "-fsS",
            "--proto",
            "=https",
            "--max-time",
            "5",
            "--connect-timeout",
            "3",
            "--max-filesize",
            &MAX_MANIFEST_BYTES.to_string(),
            "--",
            url,
        ]);
        return Some(command);
    }
    #[allow(unreachable_code)]
    None
}

fn evaluate_manifest(
    json: &str,
    current_version: &str,
    app_origin: &str,
    platform: UpdatePlatform,
) -> Result<UpdateSnapshot, &'static str> {
    if json.len() > MAX_MANIFEST_BYTES {
        return Err("manifest too large");
    }
    let manifest: DesktopUpdateManifest =
        serde_json::from_str(json).map_err(|_| "manifest shape is invalid")?;
    if manifest.schema != MANIFEST_SCHEMA
        || manifest.product != PRODUCT
        || manifest.channel != CHANNEL
    {
        return Err("manifest identity is invalid");
    }
    let remote_version = parse_version(&manifest.version).ok_or("manifest version is invalid")?;
    let current = parse_version(current_version).ok_or("current version is invalid")?;
    if !is_lower_hex(&manifest.git_sha, 40) || !is_rfc3339_utc_seconds(&manifest.published_at) {
        return Err("manifest release identity is invalid");
    }
    if !trusted_https_origin(app_origin) {
        return Err("compiled application origin is invalid");
    }
    for (_, filename, download) in manifest.downloads.all() {
        let expected = format!("/downloads/releases/{}/{filename}", manifest.version);
        if download.url != expected || !is_lower_hex(&download.sha256, 64) {
            return Err("manifest artifact identity is invalid");
        }
    }

    let (artifact_key, artifact_filename) = platform
        .artifact()
        .ok_or("compiled platform is unsupported")?;
    let download = manifest
        .downloads
        .for_platform(platform)
        .ok_or("platform artifact is missing")?;
    let expected_path = format!(
        "/downloads/releases/{}/{}",
        manifest.version, artifact_filename
    );
    if download.url != expected_path {
        return Err("platform artifact path is invalid");
    }

    let available = remote_version > current;
    let download_url = available.then(|| format!("{app_origin}{}", download.url));
    Ok(UpdateSnapshot {
        dashboard: UpdateDashboardModel {
            status: if available {
                UpdateStatus::Available
            } else {
                UpdateStatus::UpToDate
            },
            current_version: current_version.to_string(),
            latest_version: Some(manifest.version),
            release_git_sha: Some(manifest.git_sha),
            published_at: Some(manifest.published_at),
            download_artifact: Some(artifact_key.to_string()),
            download_sha256: Some(download.sha256.clone()),
            action_available: available,
        },
        download_url,
    })
}

fn parse_version(value: &str) -> Option<(u64, u64, u64)> {
    let mut parts = value.split('.');
    let major = parse_version_part(parts.next()?)?;
    let minor = parse_version_part(parts.next()?)?;
    let patch = parse_version_part(parts.next()?)?;
    (parts.next().is_none()).then_some((major, minor, patch))
}

fn parse_version_part(value: &str) -> Option<u64> {
    (!value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit()))
        .then(|| value.parse().ok())
        .flatten()
}

fn is_lower_hex(value: &str, len: usize) -> bool {
    value.len() == len
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn is_rfc3339_utc_seconds(value: &str) -> bool {
    if value.len() != 20 {
        return false;
    }
    if !value.bytes().enumerate().all(|(index, byte)| match index {
        4 | 7 => byte == b'-',
        10 => byte == b'T',
        13 | 16 => byte == b':',
        19 => byte == b'Z',
        _ => byte.is_ascii_digit(),
    }) {
        return false;
    }
    let parse = |range: std::ops::Range<usize>| value.get(range)?.parse::<u32>().ok();
    let year = parse(0..4).unwrap_or(0);
    let month = parse(5..7).unwrap_or(0);
    let day = parse(8..10).unwrap_or(0);
    let hour = parse(11..13).unwrap_or(24);
    let minute = parse(14..16).unwrap_or(60);
    let second = parse(17..19).unwrap_or(60);
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&day) && hour < 24 && minute < 60 && second < 60
}

fn trusted_https_origin(value: &str) -> bool {
    let Some(host) = value.strip_prefix("https://") else {
        return false;
    };
    !host.is_empty()
        && !host.starts_with('.')
        && !host.ends_with('.')
        && host
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
}

fn download_page_url(app_origin: &str) -> Option<String> {
    trusted_https_origin(app_origin).then(|| format!("{app_origin}/#downloads"))
}

/// Native one-in-flight gate for opening an update in the system browser.
///
/// A permit is released by `Drop`, including when worker creation fails or the opener exits with a
/// failure status. Repeated dashboard intents while the first action is active are coalesced.
struct OneInFlight {
    active: AtomicBool,
}

impl OneInFlight {
    const fn new() -> Self {
        Self {
            active: AtomicBool::new(false),
        }
    }

    fn try_acquire(&self) -> Option<OneInFlightPermit<'_>> {
        self.active
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .ok()
            .map(|_| OneInFlightPermit {
                active: &self.active,
            })
    }
}

struct OneInFlightPermit<'a> {
    active: &'a AtomicBool,
}

impl Drop for OneInFlightPermit<'_> {
    fn drop(&mut self) {
        self.active.store(false, Ordering::Release);
    }
}

fn start_open_action_with<'a>(
    url: String,
    gate: &'a OneInFlight,
    spawn: impl FnOnce(String, OneInFlightPermit<'a>) -> Result<(), ()>,
) -> Result<(), &'static str> {
    let Some(permit) = gate.try_acquire() else {
        return Ok(());
    };
    spawn(url, permit).map_err(|_| "could not start the system-browser action")
}

/// Open the validated immutable platform artifact in the user's system browser.
///
/// This only starts a bounded opener worker. It never closes Hydra, touches the PTY daemon, invokes
/// a package manager, requests privilege, or accepts a URL from JavaScript. Repeated intents while
/// the system opener is running coalesce into that one action.
pub fn open_available_update() -> Result<(), &'static str> {
    let url = current_snapshot()
        .download_url
        .ok_or("no validated update download is available")?;
    start_open_action_with(url, &UPDATE_OPEN_GATE, |url, permit| {
        std::thread::Builder::new()
            .name("hydra-update-open".to_string())
            .spawn(move || {
                let _permit = permit;
                let status = open_url_command(&url).and_then(|mut command| command.status().ok());
                if !status.is_some_and(|status| status.success()) {
                    eprintln!(
                        "hydra update: could not open the validated download in the system browser"
                    );
                }
            })
            .map(|_| ())
            .map_err(|_| ())
    })
}

fn open_url_command(url: &str) -> Option<Command> {
    #[cfg(target_os = "macos")]
    {
        let mut command = Command::new("/usr/bin/open");
        command.args(["--", url]);
        return Some(command);
    }
    #[cfg(target_os = "linux")]
    {
        let mut command = Command::new("/usr/bin/xdg-open");
        command.arg(url);
        return Some(command);
    }
    #[allow(unreachable_code)]
    None
}

/// Best-effort desktop notification; failures are ignored because the dashboard state remains.
fn notify(remote: &str, download_page: &str) {
    let message = format!("Hydra v{remote} is available. Download at {download_page}");
    #[cfg(target_os = "macos")]
    {
        let script = format!(
            "display notification \"{}\" with title \"Hydra\"",
            message.replace('"', "'")
        );
        let _ = Command::new("/usr/bin/osascript")
            .args(["-e", &script])
            .status();
    }
    #[cfg(target_os = "linux")]
    {
        let _ = Command::new("/usr/bin/notify-send")
            .args(["Hydra", &message])
            .status();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RELEASE_SHA: &str = "0123456789abcdef0123456789abcdef01234567";
    const ARTIFACT_SHA: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    fn manifest(version: &str) -> String {
        serde_json::json!({
            "schema": MANIFEST_SCHEMA,
            "product": PRODUCT,
            "channel": CHANNEL,
            "version": version,
            "git_sha": RELEASE_SHA,
            "published_at": "2026-07-30T12:34:56Z",
            "downloads": {
                "macos-universal-dmg": {
                    "url": format!("/downloads/releases/{version}/Hydra-macOS.dmg"),
                    "sha256": ARTIFACT_SHA,
                },
                "linux-amd64-deb": {
                    "url": format!("/downloads/releases/{version}/Hydra-linux-amd64.deb"),
                    "sha256": ARTIFACT_SHA,
                },
                "linux-arm64-deb": {
                    "url": format!("/downloads/releases/{version}/Hydra-linux-arm64.deb"),
                    "sha256": ARTIFACT_SHA,
                },
                "linux-amd64-tar": {
                    "url": format!("/downloads/releases/{version}/Hydra-linux-amd64.tar.gz"),
                    "sha256": ARTIFACT_SHA,
                },
                "linux-arm64-tar": {
                    "url": format!("/downloads/releases/{version}/Hydra-linux-arm64.tar.gz"),
                    "sha256": ARTIFACT_SHA,
                },
            },
        })
        .to_string()
    }

    #[test]
    fn exact_manifest_selects_each_shipping_platform_artifact() {
        for (platform, artifact, filename) in [
            (
                UpdatePlatform::MacosUniversal,
                "macos-universal-dmg",
                "Hydra-macOS.dmg",
            ),
            (
                UpdatePlatform::LinuxAmd64,
                "linux-amd64-deb",
                "Hydra-linux-amd64.deb",
            ),
            (
                UpdatePlatform::LinuxArm64,
                "linux-arm64-deb",
                "Hydra-linux-arm64.deb",
            ),
        ] {
            let state = evaluate_manifest(
                &manifest("0.2.7"),
                "0.2.6",
                "https://app.hydraterms.com",
                platform,
            )
            .unwrap();
            assert_eq!(state.dashboard.status, UpdateStatus::Available);
            assert_eq!(state.dashboard.current_version, "0.2.6");
            assert_eq!(state.dashboard.latest_version.as_deref(), Some("0.2.7"));
            assert_eq!(
                state.dashboard.release_git_sha.as_deref(),
                Some(RELEASE_SHA)
            );
            assert_eq!(
                state.dashboard.published_at.as_deref(),
                Some("2026-07-30T12:34:56Z")
            );
            assert_eq!(state.dashboard.download_artifact.as_deref(), Some(artifact));
            assert_eq!(
                state.dashboard.download_sha256.as_deref(),
                Some(ARTIFACT_SHA)
            );
            assert!(state.dashboard.action_available);
            let expected_url =
                format!("https://app.hydraterms.com/downloads/releases/0.2.7/{filename}");
            assert_eq!(state.download_url.as_deref(), Some(expected_url.as_str()));
        }
    }

    #[test]
    fn same_or_older_feed_is_truthfully_up_to_date_without_an_action() {
        for remote in ["0.2.6", "0.2.5"] {
            let state = evaluate_manifest(
                &manifest(remote),
                "0.2.6",
                "https://app.hydraterms.com",
                UpdatePlatform::MacosUniversal,
            )
            .unwrap();
            assert_eq!(state.dashboard.status, UpdateStatus::UpToDate);
            assert_eq!(state.dashboard.latest_version.as_deref(), Some(remote));
            assert!(!state.dashboard.action_available);
            assert_eq!(state.download_url, None);
        }
    }

    #[test]
    fn manifest_identity_and_shape_fail_closed() {
        let valid: serde_json::Value = serde_json::from_str(&manifest("0.2.7")).unwrap();
        for value in [
            {
                let mut value = valid.clone();
                value["schema"] = serde_json::json!("other");
                value
            },
            {
                let mut value = valid.clone();
                value["product"] = serde_json::json!("other");
                value
            },
            {
                let mut value = valid.clone();
                value["channel"] = serde_json::json!("beta");
                value
            },
            {
                let mut value = valid.clone();
                value["version"] = serde_json::json!("v0.2.7");
                value
            },
            {
                let mut value = valid.clone();
                value["git_sha"] = serde_json::json!("ABC");
                value
            },
            {
                let mut value = valid.clone();
                value["published_at"] = serde_json::json!("soon");
                value
            },
        ] {
            assert!(evaluate_manifest(
                &value.to_string(),
                "0.2.6",
                "https://app.hydraterms.com",
                UpdatePlatform::MacosUniversal,
            )
            .is_err());
        }

        let mut unknown = valid;
        unknown["unexpected"] = serde_json::json!(true);
        assert!(evaluate_manifest(
            &unknown.to_string(),
            "0.2.6",
            "https://app.hydraterms.com",
            UpdatePlatform::MacosUniversal,
        )
        .is_err());
    }

    #[test]
    fn every_artifact_path_and_digest_is_validated_not_only_the_current_platform() {
        let mut wrong_path: serde_json::Value = serde_json::from_str(&manifest("0.2.7")).unwrap();
        wrong_path["downloads"]["linux-arm64-tar"]["url"] =
            serde_json::json!("/downloads/Hydra-linux-arm64.tar.gz");
        assert!(evaluate_manifest(
            &wrong_path.to_string(),
            "0.2.6",
            "https://app.hydraterms.com",
            UpdatePlatform::MacosUniversal,
        )
        .is_err());

        let mut wrong_digest: serde_json::Value = serde_json::from_str(&manifest("0.2.7")).unwrap();
        wrong_digest["downloads"]["linux-amd64-deb"]["sha256"] = serde_json::json!("ABC");
        assert!(evaluate_manifest(
            &wrong_digest.to_string(),
            "0.2.6",
            "https://app.hydraterms.com",
            UpdatePlatform::MacosUniversal,
        )
        .is_err());
    }

    #[test]
    fn origin_and_version_parsers_reject_ambiguous_inputs() {
        for invalid in ["", "v0.2.7", "0.2", "0.2.7.1", "0.2.beta", "0.2.7+meta"] {
            assert_eq!(parse_version(invalid), None);
        }
        assert_eq!(parse_version("0.2.7"), Some((0, 2, 7)));
        assert!(is_rfc3339_utc_seconds("2024-02-29T23:59:59Z"));
        for invalid in [
            "2025-02-29T23:59:59Z",
            "2026-13-01T00:00:00Z",
            "2026-07-30T24:00:00Z",
            "2026-07-30T12:60:00Z",
        ] {
            assert!(!is_rfc3339_utc_seconds(invalid));
        }
        assert!(trusted_https_origin("https://app.hydraterms.com"));
        for invalid in [
            "http://app.hydraterms.com",
            "https://app.hydraterms.com/path",
            "https://user@app.hydraterms.com",
            "https://app.hydraterms.com?x=1",
            "https://",
        ] {
            assert!(!trusted_https_origin(invalid));
        }
    }

    #[test]
    fn dashboard_state_has_no_javascript_control_over_the_download_url() {
        let state = evaluate_manifest(
            &manifest("0.2.7"),
            "0.2.6",
            "https://app.hydraterms.com",
            UpdatePlatform::MacosUniversal,
        )
        .unwrap();
        let value = serde_json::to_value(state.dashboard).unwrap();
        assert_eq!(value["status"], "available");
        assert_eq!(value["action_available"], true);
        assert!(value.get("download_url").is_none());
    }

    #[test]
    fn system_opener_is_fixed_and_never_uses_a_shell() {
        let url = "https://app.hydraterms.com/downloads/releases/0.2.7/Hydra-macOS.dmg";
        let command = open_url_command(url).expect("shipping desktop has a system opener");
        #[cfg(target_os = "macos")]
        {
            assert_eq!(command.get_program(), "/usr/bin/open");
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                vec![std::ffi::OsStr::new("--"), std::ffi::OsStr::new(url)]
            );
        }
        #[cfg(target_os = "linux")]
        {
            assert_eq!(command.get_program(), "/usr/bin/xdg-open");
            assert_eq!(
                command.get_args().collect::<Vec<_>>(),
                vec![std::ffi::OsStr::new(url)]
            );
        }
    }

    #[cfg(feature = "official-distribution")]
    #[test]
    fn official_distribution_fetcher_is_fixed_bounded_and_has_no_runtime_override() {
        let manifest_url = manifest_url_for(RELEASE_ORIGIN, STABLE_MANIFEST_PATH)
            .expect("the official desktop has an active stable feed");
        assert_eq!(
            compiled_manifest_url().as_deref(),
            Some(manifest_url.as_str())
        );
        assert_eq!(
            manifest_url,
            "https://app.hydraterms.com/downloads/version.json"
        );
        let command = fetch_command(&manifest_url).expect("shipping desktop has a system curl");
        assert_eq!(command.get_program(), "/usr/bin/curl");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                "-q",
                "-fsS",
                "--proto",
                "=https",
                "--max-time",
                "5",
                "--connect-timeout",
                "3",
                "--max-filesize",
                "1048576",
                "--",
                manifest_url.as_str(),
            ]
            .map(std::ffi::OsStr::new)
            .to_vec()
        );
        for (origin, path) in [
            ("https://preview.example.invalid", "/candidate/version.json"),
            (RELEASE_ORIGIN, "/downloads/channels/stable/version.json"),
            ("http://app.hydraterms.com", STABLE_MANIFEST_PATH),
        ] {
            assert_eq!(manifest_url_for(origin, path), None);
        }
    }

    #[cfg(not(feature = "official-distribution"))]
    #[test]
    fn community_build_disables_the_automatic_update_request_at_compile_time() {
        assert_eq!(compiled_manifest_url(), None);

        let mut completion = spawn_update_check();
        assert!(
            completion.try_take(),
            "disabled check must complete immediately"
        );
        let dashboard = dashboard_model();
        assert_eq!(dashboard.status, UpdateStatus::Disabled);
        assert!(!dashboard.action_available);
        assert_eq!(current_snapshot().download_url, None);
    }

    #[test]
    fn update_opener_coalesces_repeated_intents_and_releases_after_completion_or_failure() {
        let gate = OneInFlight::new();
        let first = gate.try_acquire().expect("first action owns the gate");
        for _ in 0..128 {
            assert!(gate.try_acquire().is_none());
        }
        drop(first);
        assert!(gate.try_acquire().is_some());

        let failing_gate = OneInFlight::new();
        assert_eq!(
            start_open_action_with(
                "https://app.hydraterms.com/downloads/releases/0.2.7/Hydra-macOS.dmg".to_string(),
                &failing_gate,
                |_url, _permit| Err(()),
            ),
            Err("could not start the system-browser action")
        );
        assert!(
            failing_gate.try_acquire().is_some(),
            "a failed worker start must release the native gate"
        );
    }

    #[test]
    fn completion_signal_is_consumed_exactly_once_even_if_worker_disconnects() {
        let (sent_tx, sent_rx) = mpsc::channel();
        let mut sent = UpdateCheckCompletion {
            receiver: Some(sent_rx),
        };
        assert!(!sent.try_take());
        sent_tx.send(()).unwrap();
        assert!(sent.try_take());
        assert!(!sent.try_take());

        let (dropped_tx, dropped_rx) = mpsc::channel::<()>();
        let mut dropped = UpdateCheckCompletion {
            receiver: Some(dropped_rx),
        };
        drop(dropped_tx);
        assert!(dropped.try_take());
        assert!(!dropped.try_take());
    }
}
