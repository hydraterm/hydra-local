//! Published model catalog — lets the model dropdowns gain new entries WITHOUT an app release.
//!
//! A background thread fetches the stable public catalog at launch and caches it atomically under
//! the app-support base. The dashboard model builder injects the cached
//! catalog into the React chrome, which merges it OVER its built-in per-agent lists — so a new
//! model (e.g. a vendor release that morning) appears in Split/New Window/Project dropdowns on
//! next launch, while offline/first-run users still get the built-ins.
//!
//! Same transport + trust posture as `update_check`: the automatic plain, content-blind GET exists
//! only when the binary is compiled with the default-off `official-distribution` feature. Production
//! uses that fixed public feed; staging and community/source builds make no catalog request. The URL
//! has no runtime override, requests apply hard timeouts and fail silently, and may still be disabled
//! with `HYDRA_NO_UPDATE_CHECK=1`. Catalog display metadata is not remote authority.
//!
//! The catalog can only affect dropdown labels; the daemon keeps the executable, flags, and
//! security policy in the signed application. V1 `{ "agents": ... }` catalogs remain readable.
//! V2 catalogs additionally validate revision/date/deprecation metadata and reject unknown fields.

use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Catalogs are dropdown metadata, not bulk content. Bound network and local-cache reads before
/// parsing so a corrupt origin or cache cannot make a desktop process allocate an unbounded body.
const MAX_CATALOG_BYTES: usize = 512 * 1024;

const CACHE_FILENAME: &str = "model-catalog.json";
#[cfg_attr(not(feature = "official-distribution"), allow(dead_code))]
const PRODUCTION_CATALOG_URL: &str =
    "https://app.hydraterms.com/downloads/model-catalog/channels/stable.json";

pub fn cache_filename() -> &'static str {
    CACHE_FILENAME
}

/// Spawn the background refresh. Call once per launch; returns immediately.
pub fn spawn_refresh(cache_path: PathBuf) {
    let Some(catalog_url) = compiled_catalog_url() else {
        return;
    };
    if std::env::var_os("HYDRA_NO_UPDATE_CHECK").is_some() {
        return;
    }
    std::thread::spawn(move || refresh(&cache_path, catalog_url));
}

fn compiled_catalog_url() -> Option<&'static str> {
    #[cfg(feature = "official-distribution")]
    {
        Some(PRODUCTION_CATALOG_URL)
    }
    #[cfg(not(feature = "official-distribution"))]
    {
        None
    }
}

#[cfg(test)]
fn production_catalog_url() -> &'static str {
    PRODUCTION_CATALOG_URL
}

fn refresh(cache_path: &Path, catalog_url: &str) {
    let max_bytes = MAX_CATALOG_BYTES.to_string();
    let Some(mut command) = refresh_command(catalog_url, &max_bytes) else {
        return;
    };
    let out = command.output();
    let Ok(out) = out else { return };
    if !out.status.success() {
        return;
    }
    if out.stdout.len() > MAX_CATALOG_BYTES {
        return;
    }
    let Ok(body) = String::from_utf8(out.stdout) else {
        return;
    };
    let Some(incoming) = validate(&body) else {
        return; // never cache junk — the previous cache (or built-ins) stay in effect
    };
    // Atomic write: temp file in the same dir, then rename, so a crash can't leave a torn cache.
    let Some(dir) = cache_path.parent() else {
        return;
    };
    if std::fs::create_dir_all(dir).is_err() {
        return;
    }
    let Some(_lock) = CacheWriteLock::acquire(dir) else {
        return;
    };
    if let Some(existing_body) = read_bounded_cache(cache_path) {
        if let Some(existing) = validate(&existing_body) {
            if !accept_revision(&existing_body, &existing, &body, &incoming) {
                return;
            }
        }
    }
    let tmp = dir.join(format!(
        ".{}.tmp.{}",
        cache_path
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or("model-catalog"),
        std::process::id()
    ));
    let _ = std::fs::remove_file(&tmp);
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let Ok(mut file) = options.open(&tmp) else {
        return;
    };
    let written = file
        .write_all(body.as_bytes())
        .and_then(|()| file.sync_all());
    drop(file);
    if written.is_ok() && std::fs::rename(&tmp, cache_path).is_ok() {
        return;
    }
    {
        let _ = std::fs::remove_file(&tmp);
    }
}

/// Construct the bounded catalog fetch without consulting `PATH`. Official desktop builds launch
/// this request automatically, so a project-local or inherited `curl` shim must never become code
/// execution during ordinary app startup. The shipping macOS and Linux packages both provide the
/// fixed system executable used by the update checker.
fn refresh_command(url: &str, max_bytes: &str) -> Option<Command> {
    #[cfg(any(target_os = "macos", target_os = "linux"))]
    {
        let mut command = Command::new("/usr/bin/curl");
        command.args([
            // Must be curl's first argument: ignore ~/.curlrc so a local tracing/output setting
            // cannot silently change this bounded, content-only request.
            "-q",
            "-fsSL",
            "--proto",
            "=https",
            "--proto-redir",
            "=https",
            "--max-time",
            "5",
            "--connect-timeout",
            "3",
            "--max-filesize",
            max_bytes,
            "--",
            url,
        ]);
        return Some(command);
    }
    #[allow(unreachable_code)]
    None
}

/// The cached catalog as a JSON value, or `None` when absent/invalid (callers fall back to
/// built-in lists). Returned shape is exactly the validated manifest object.
pub fn load_cached(cache_path: &Path) -> Option<serde_json::Value> {
    let body = read_bounded_cache(cache_path)?;
    validate(&body)
}

fn read_bounded_cache(cache_path: &Path) -> Option<String> {
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    // Open first and inspect that descriptor. A separate path metadata check would leave a race in
    // which an attacker (or another process) could replace the cache with a symlink before open().
    let file = options.open(cache_path).ok()?;
    let metadata = file.metadata().ok()?;
    if !metadata.file_type().is_file() || metadata.len() > MAX_CATALOG_BYTES as u64 {
        return None;
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((MAX_CATALOG_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .ok()?;
    if bytes.len() > MAX_CATALOG_BYTES {
        return None;
    }
    String::from_utf8(bytes).ok()
}

fn catalog_revision(value: &serde_json::Value) -> Option<u64> {
    (value.get("schema_version")?.as_u64()? == 2).then(|| value.get("revision")?.as_u64())?
}

/// V2 revisions are monotonic. A lower V2 response or a V1 response after V2 is a downgrade; the
/// same revision with different bytes is equivocation. In every case keep the last accepted cache.
fn accept_revision(
    existing_body: &str,
    existing: &serde_json::Value,
    incoming_body: &str,
    incoming: &serde_json::Value,
) -> bool {
    match (catalog_revision(existing), catalog_revision(incoming)) {
        (Some(_), None) => false,
        (Some(old), Some(new)) if new < old => false,
        (Some(old), Some(new)) if new == old => existing_body == incoming_body,
        _ => true,
    }
}

#[cfg(unix)]
struct CacheWriteLock(std::fs::File);

#[cfg(unix)]
impl CacheWriteLock {
    fn acquire(dir: &Path) -> Option<Self> {
        use std::os::fd::AsRawFd;
        use std::os::unix::fs::OpenOptionsExt;

        let path = dir.join(".model-catalog.lock");
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
            .open(path)
            .ok()?;
        if !file.metadata().ok()?.file_type().is_file() {
            return None;
        }
        // SAFETY: the owned descriptor remains live until Drop releases this process-scoped lock.
        if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
            return None;
        }
        Some(Self(file))
    }
}

#[cfg(unix)]
impl Drop for CacheWriteLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd;
        // SAFETY: the descriptor is still owned and live for this Drop invocation.
        let _ = unsafe { libc::flock(self.0.as_raw_fd(), libc::LOCK_UN) };
    }
}

#[cfg(not(unix))]
struct CacheWriteLock;

#[cfg(not(unix))]
impl CacheWriteLock {
    fn acquire(_dir: &Path) -> Option<Self> {
        Some(Self)
    }
}

/// Keep this boundary identical to the browser and optional-extension model-name sanitizer: trimmed,
/// non-empty, at most 96 Unicode scalar values, and no control characters. A byte limit here would
/// disagree for non-ASCII model names and could make the browser offer a choice the desktop drops.
const MODEL_NAME_MAX_CHARS: usize = 96;
const DEPRECATION_MESSAGE_MAX_CHARS: usize = 240;

fn safe_text(value: &str, max_chars: usize) -> bool {
    value == value.trim()
        && !value.is_empty()
        && value.chars().count() <= max_chars
        && !value.chars().any(char::is_control)
}

fn safe_model_name(value: &str) -> bool {
    safe_text(value, MODEL_NAME_MAX_CHARS)
}

fn safe_agent_name(value: &str) -> bool {
    let mut chars = value.chars();
    chars.next().is_some_and(|first| first.is_ascii_lowercase())
        && value.chars().count() <= 64
        && chars.all(|character| {
            character.is_ascii_lowercase()
                || character.is_ascii_digit()
                || character == '_'
                || character == '-'
        })
}

fn valid_source_date(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() != 10
        || bytes[4] != b'-'
        || bytes[7] != b'-'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 4 && index != 7 && !byte.is_ascii_digit())
    {
        return false;
    }
    let Ok(year) = value[0..4].parse::<u16>() else {
        return false;
    };
    let Ok(month) = value[5..7].parse::<u8>() else {
        return false;
    };
    let Ok(day) = value[8..10].parse::<u8>() else {
        return false;
    };
    let leap = year.is_multiple_of(4) && (!year.is_multiple_of(100) || year.is_multiple_of(400));
    let days = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    day >= 1 && day <= days
}

fn valid_published_at(value: &str) -> bool {
    // Publisher emits RFC3339 UTC. Keep the dependency-free client boundary deliberately strict:
    // YYYY-MM-DDTHH:MM:SS[.fraction]Z.
    if value.len() < 20 || !value.ends_with('Z') || value.as_bytes().get(10) != Some(&b'T') {
        return false;
    }
    if !valid_source_date(&value[..10]) {
        return false;
    }
    let time = &value[11..value.len() - 1];
    let (whole, fraction) = time
        .split_once('.')
        .map_or((time, None), |(a, b)| (a, Some(b)));
    let bytes = whole.as_bytes();
    if bytes.len() != 8
        || bytes[2] != b':'
        || bytes[5] != b':'
        || bytes
            .iter()
            .enumerate()
            .any(|(index, byte)| index != 2 && index != 5 && !byte.is_ascii_digit())
    {
        return false;
    }
    let valid_number = |range: std::ops::Range<usize>, max: u8| {
        whole[range].parse::<u8>().is_ok_and(|value| value <= max)
    };
    valid_number(0..2, 23)
        && valid_number(3..5, 59)
        && valid_number(6..8, 59)
        && fraction.is_none_or(|value| {
            !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_digit())
        })
}

fn validate_v2_metadata(value: &serde_json::Value) -> Option<()> {
    let object = value.as_object()?;
    const ALLOWED: &[&str] = &[
        "schema_version",
        "revision",
        "source_date",
        "published_at",
        "note",
        "agents",
        "deprecations",
    ];
    if object.keys().any(|key| !ALLOWED.contains(&key.as_str())) {
        return None;
    }
    if object.get("schema_version")?.as_u64()? != 2 {
        return None;
    }
    let revision = object.get("revision")?.as_u64()?;
    if revision == 0 {
        return None;
    }
    match (object.get("source_date"), object.get("published_at")) {
        (Some(date), None) if date.as_str().is_some_and(valid_source_date) => {}
        (None, Some(timestamp)) if timestamp.as_str().is_some_and(valid_published_at) => {}
        _ => return None,
    }
    if object
        .get("note")
        .is_some_and(|note| !note.as_str().is_some_and(|value| safe_text(value, 512)))
    {
        return None;
    }
    let deprecations = object.get("deprecations")?.as_object()?;
    for (agent, entries) in deprecations {
        if !safe_agent_name(agent) {
            return None;
        }
        for (model, metadata) in entries.as_object()? {
            if !safe_model_name(model) {
                return None;
            }
            let metadata = metadata.as_object()?;
            if metadata
                .keys()
                .any(|key| !["since_revision", "message", "replacement"].contains(&key.as_str()))
            {
                return None;
            }
            let since = metadata.get("since_revision")?.as_u64()?;
            if since == 0 || since > revision {
                return None;
            }
            if !metadata
                .get("message")?
                .as_str()
                .is_some_and(|message| safe_text(message, DEPRECATION_MESSAGE_MAX_CHARS))
            {
                return None;
            }
            if metadata
                .get("replacement")
                .is_some_and(|replacement| !replacement.as_str().is_some_and(safe_model_name))
            {
                return None;
            }
        }
    }
    Some(())
}

/// Accept only `{ "agents": { <agent>: ["model", ...] } }` with safe string entries; anything else
/// is rejected wholesale so a partial/corrupt file can't half-populate dropdowns.
fn validate(body: &str) -> Option<serde_json::Value> {
    let value: serde_json::Value = serde_json::from_str(body).ok()?;
    if value.get("schema_version").is_some() {
        validate_v2_metadata(&value)?;
    }
    let agents = value.get("agents")?.as_object()?;
    if agents.is_empty() {
        return None;
    }
    for (agent, models) in agents {
        if value.get("schema_version").is_some() && !safe_agent_name(agent) {
            return None;
        }
        let list = models.as_array()?;
        let mut seen = std::collections::HashSet::new();
        for model in list {
            let model = model.as_str()?;
            if !safe_model_name(model) || !seen.insert(model) {
                return None;
            }
        }
    }
    Some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn valid_catalog_round_trips() {
        let body = r#"{"updated_at":"x","agents":{"claude":["default","opus"],"codex":["default","gpt-5.6"]}}"#;
        let v = validate(body).expect("valid catalog accepted");
        assert_eq!(v["agents"]["codex"][1], "gpt-5.6");
    }

    #[test]
    fn release_catalog_url_and_cache_are_stable_public_inputs() {
        assert_eq!(production_catalog_url(), PRODUCTION_CATALOG_URL);
        assert_eq!(cache_filename(), CACHE_FILENAME);
        assert!(!production_catalog_url().contains("staging"));
    }

    #[cfg(not(feature = "official-distribution"))]
    #[test]
    fn community_build_disables_the_automatic_catalog_request_at_compile_time() {
        assert_eq!(compiled_catalog_url(), None);
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join(cache_filename());
        spawn_refresh(cache.clone());
        assert!(!cache.exists(), "disabled refresh must not create a cache");
    }

    #[cfg(feature = "official-distribution")]
    #[test]
    fn official_distribution_catalog_uses_one_fixed_url_without_runtime_override() {
        assert_eq!(compiled_catalog_url(), Some(PRODUCTION_CATALOG_URL));
        assert_eq!(
            compiled_catalog_url(),
            Some("https://app.hydraterms.com/downloads/model-catalog/channels/stable.json")
        );
    }

    #[cfg(any(target_os = "macos", target_os = "linux"))]
    #[test]
    fn catalog_fetch_uses_fixed_system_curl_even_with_a_hostile_path() {
        use std::os::unix::fs::PermissionsExt;

        let dir = tempfile::tempdir().unwrap();
        let fixture = dir.path().join("catalog.json");
        let body = r#"{"agents":{"codex":["default"]}}"#;
        std::fs::write(&fixture, body).unwrap();

        let marker = dir.path().join("path-curl-ran");
        let fake_curl = dir.path().join("curl");
        std::fs::write(
            &fake_curl,
            "#!/bin/sh\nprintf owned > \"$HYDRA_PATH_HIJACK_MARKER\"\nprintf malicious\n",
        )
        .unwrap();
        std::fs::set_permissions(&fake_curl, std::fs::Permissions::from_mode(0o755)).unwrap();

        let url = format!("file://{}", fixture.display());
        let max_bytes = MAX_CATALOG_BYTES.to_string();
        let mut command = refresh_command(&url, &max_bytes).expect("shipping system curl");
        assert_eq!(command.get_program(), "/usr/bin/curl");
        assert_eq!(
            command.get_args().collect::<Vec<_>>(),
            [
                "-q",
                "-fsSL",
                "--proto",
                "=https",
                "--proto-redir",
                "=https",
                "--max-time",
                "5",
                "--connect-timeout",
                "3",
                "--max-filesize",
                max_bytes.as_str(),
                "--",
                url.as_str(),
            ]
            .map(std::ffi::OsStr::new)
            .to_vec()
        );

        let output = command
            .env("PATH", dir.path())
            .env("HYDRA_PATH_HIJACK_MARKER", &marker)
            .output()
            .expect("fixed system curl executes");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!marker.exists(), "PATH-resolved fake curl executed");
    }

    #[test]
    fn v2_metadata_is_validated_without_breaking_v1() {
        let valid = r#"{
          "schema_version":2,"revision":3,"source_date":"2026-07-18",
          "note":"display labels only","agents":{"codex":["default","new"]},
          "deprecations":{"codex":{"old":{"since_revision":2,"message":"Use new","replacement":"new"}}}
        }"#;
        assert!(validate(valid).is_some());
        assert!(validate(r#"{"updated_at":"legacy","agents":{"codex":["default"]}}"#).is_some());

        for invalid in [
            valid.replace("\"revision\":3", "\"revision\":0"),
            valid.replace("2026-07-18", "2026-02-30"),
            valid.replace("\"since_revision\":2", "\"since_revision\":4"),
            valid.replace("\"agents\"", "\"command\":\"codex --yolo\",\"agents\""),
            valid.replace("\"deprecations\"", "\"deprecations_ignored\""),
            valid.replace("\"default\",\"new\"", "\"default\",\"default\""),
            valid.replace("\"codex\"", "\"Codex\""),
        ] {
            assert!(
                validate(&invalid).is_none(),
                "accepted invalid v2 catalog: {invalid}"
            );
        }
    }

    #[test]
    fn v2_accepts_a_strict_utc_publication_timestamp() {
        let body = r#"{
          "schema_version":2,"revision":1,"published_at":"2026-07-18T12:34:56.123Z",
          "agents":{"codex":["default"]},"deprecations":{}
        }"#;
        assert!(validate(body).is_some());
        assert!(validate(&body.replace("12:34:56.123Z", "25:34:56Z")).is_none());
    }

    #[test]
    fn junk_is_rejected_wholesale() {
        assert!(validate("not json").is_none());
        assert!(validate(r#"{"agents":{}}"#).is_none());
        assert!(validate(r#"{"agents":{"claude":"opus"}}"#).is_none()); // not a list
        assert!(validate(r#"{"agents":{"claude":[7]}}"#).is_none()); // non-string entry
        assert!(validate(r#"{"agents":{"claude":[""]}}"#).is_none()); // empty entry
        assert!(validate(r#"{"noagents":true}"#).is_none());
    }

    #[test]
    fn model_names_match_the_remote_unicode_and_control_boundary() {
        let at_limit = "🧠".repeat(MODEL_NAME_MAX_CHARS);
        let over_limit = "🧠".repeat(MODEL_NAME_MAX_CHARS + 1);
        assert!(validate(&format!(
            r#"{{"agents":{{"codex":[{}]}}}}"#,
            serde_json::to_string(&at_limit).unwrap()
        ))
        .is_some());
        assert!(validate(&format!(
            r#"{{"agents":{{"codex":[{}]}}}}"#,
            serde_json::to_string(&over_limit).unwrap()
        ))
        .is_none());
        assert!(validate(r#"{"agents":{"codex":["bad\nmodel"]}}"#).is_none());
    }

    #[test]
    fn cache_write_and_load_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join(cache_filename());
        assert!(load_cached(&cache).is_none()); // absent → None
        std::fs::write(&cache, r#"{"agents":{"claude":["default"]}}"#).unwrap();
        assert!(load_cached(&cache).is_some());
        std::fs::write(&cache, "corrupt").unwrap();
        assert!(load_cached(&cache).is_none()); // corrupt → None, never a panic
    }

    #[test]
    fn cached_reads_are_bounded_and_reject_symlinks() {
        let dir = tempfile::tempdir().unwrap();
        let cache = dir.path().join(cache_filename());
        std::fs::write(&cache, vec![b'x'; MAX_CATALOG_BYTES + 1]).unwrap();
        assert!(load_cached(&cache).is_none());

        #[cfg(unix)]
        {
            use std::os::unix::fs::symlink;
            let target = dir.path().join("target.json");
            std::fs::write(&target, r#"{"agents":{"codex":["default"]}}"#).unwrap();
            std::fs::remove_file(&cache).unwrap();
            symlink(&target, &cache).unwrap();
            assert!(load_cached(&cache).is_none());
        }
    }

    #[test]
    fn v2_revision_is_monotonic_and_same_revision_cannot_change_bytes() {
        let catalog = |revision: u64, model: &str| {
            format!(
                r#"{{"schema_version":2,"revision":{revision},"source_date":"2026-07-18","agents":{{"codex":["{model}"]}},"deprecations":{{}}}}"#
            )
        };
        let old_body = catalog(7, "old");
        let old = validate(&old_body).unwrap();
        let older_body = catalog(6, "older");
        let older = validate(&older_body).unwrap();
        let same_changed_body = catalog(7, "changed");
        let same_changed = validate(&same_changed_body).unwrap();
        let new_body = catalog(8, "new");
        let new = validate(&new_body).unwrap();
        let legacy_body = r#"{"agents":{"codex":["legacy"]}}"#;
        let legacy = validate(legacy_body).unwrap();

        assert!(!accept_revision(&old_body, &old, &older_body, &older));
        assert!(!accept_revision(
            &old_body,
            &old,
            &same_changed_body,
            &same_changed
        ));
        assert!(accept_revision(&old_body, &old, &old_body, &old));
        assert!(accept_revision(&old_body, &old, &new_body, &new));
        assert!(!accept_revision(&old_body, &old, legacy_body, &legacy));
        assert!(accept_revision(legacy_body, &legacy, &new_body, &new));
    }
}
