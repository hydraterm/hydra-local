// Build identity plus the agent-owned release trust binding.

mod build_support;

use base64::Engine as _;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};
use std::process::Command;

const SELECTOR: &str = "HYDRA_AGENT_RELEASE_ENVIRONMENT";
const SELF_MANAGED_DESCRIPTOR: &str = "HYDRA_AGENT_SELF_MANAGED_DESCRIPTOR";

fn required_str<'a>(value: &'a Value, field: &str) -> &'a str {
    value
        .get(field)
        .and_then(Value::as_str)
        .unwrap_or_else(|| panic!("agent release descriptor is missing string field {field}"))
}

fn expected_identity(
    name: &str,
) -> (
    &'static str,
    &'static str,
    &'static str,
    &'static str,
    &'static str,
) {
    match name {
        "production" => (
            "stable",
            "https://app.hydraterms.com",
            "https://api.hydraterms.com",
            "active",
            "/downloads/version.json",
        ),
        "staging" => (
            "staging",
            "https://staging.hydraterms.com",
            "https://api.staging.hydraterms.com",
            "planned",
            "/downloads/channels/staging/version.json",
        ),
        _ => panic!("{SELECTOR} must be production or staging"),
    }
}

fn descriptor_path(manifest_dir: &Path, environment: &str) -> PathBuf {
    manifest_dir
        .parent()
        .expect("hydra-agent has a repository parent")
        .join("deploy")
        .join("environments")
        .join(format!("{environment}.json"))
}

fn main() {
    emit_release_trust();

    let git = git_stamp().unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=HYDRA_BUILD_GIT={git}");

    let build_ms = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .unwrap_or(0);
    println!("cargo:rustc-env=HYDRA_BUILD_TIME={build_ms}");

    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/index");
}

/// Bind the agent to one reviewed tracked environment descriptor. The public application
/// cannot select or override any value in this tuple. The generated JSON is retained in the agent
/// binary so a signer can inspect non-native Linux artifacts without executing them.
fn emit_release_trust() {
    println!("cargo:rerun-if-env-changed={SELECTOR}");
    println!("cargo:rerun-if-env-changed={SELF_MANAGED_DESCRIPTOR}");
    let manifest_dir = PathBuf::from(
        std::env::var_os("CARGO_MANIFEST_DIR").expect("Cargo sets CARGO_MANIFEST_DIR"),
    );
    let public_path = build_support::self_managed_path(
        &manifest_dir,
        std::env::var_os(SELECTOR).is_some(),
        std::env::var_os(SELF_MANAGED_DESCRIPTOR).map(PathBuf::from),
    )
    .unwrap_or_else(|error| panic!("{error}"));
    if let Some(path) = public_path {
        emit_self_managed_trust(&path);
        return;
    }
    let environment = std::env::var(SELECTOR).unwrap_or_else(|_| "production".to_string());
    let (channel, app_origin, api_origin, update_status, update_manifest_path) =
        expected_identity(&environment);
    let path = descriptor_path(&manifest_dir, &environment);
    println!("cargo:rerun-if-changed={}", path.display());
    let raw = std::fs::read(&path)
        .unwrap_or_else(|error| panic!("could not read {}: {error}", path.display()));
    let descriptor: Value = serde_json::from_slice(&raw)
        .unwrap_or_else(|error| panic!("invalid {}: {error}", path.display()));

    assert_eq!(descriptor.get("schema").and_then(Value::as_u64), Some(2));
    assert_eq!(required_str(&descriptor, "name"), environment);
    assert_eq!(required_str(&descriptor, "channel"), channel);
    assert_eq!(required_str(&descriptor, "app_origin"), app_origin);
    assert_eq!(required_str(&descriptor, "api_origin"), api_origin);

    let update = descriptor
        .get("desktop_update_manifest")
        .and_then(Value::as_object)
        .expect("selected agent environment must have desktop_update_manifest");
    assert_eq!(
        update.len(),
        2,
        "desktop_update_manifest has an unexpected field"
    );
    assert_eq!(
        update.get("status").and_then(Value::as_str),
        Some(update_status)
    );
    assert_eq!(
        update.get("path").and_then(Value::as_str),
        Some(update_manifest_path)
    );

    let remote = descriptor
        .get("desktop_remote")
        .and_then(Value::as_object)
        .expect("selected agent environment must have desktop_remote");
    assert_eq!(remote.len(), 2, "desktop_remote has an unexpected field");
    assert_eq!(remote.get("status").and_then(Value::as_str), Some("active"));
    let public_key = remote
        .get("token_verification_public_key")
        .and_then(Value::as_str)
        .expect("active desktop_remote must pin a public key");
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(public_key)
        .expect("desktop token verification key must be canonical base64");
    assert_eq!(
        decoded.len(),
        32,
        "desktop token verification key must be 32 bytes"
    );
    assert_eq!(
        base64::engine::general_purpose::STANDARD.encode(decoded),
        public_key,
        "desktop token verification key must use canonical standard base64"
    );

    let descriptor_sha256 = Sha256::digest(&raw)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let binding_json = format!(
        concat!(
            "{{\"environment\":{},\"channel\":{},\"app_origin\":{},",
            "\"api_origin\":{},\"update_manifest_path\":{},\"token_verification_public_key\":{},",
            "\"descriptor_sha256\":{}}}"
        ),
        serde_json::to_string(&environment).expect("serialize environment"),
        serde_json::to_string(channel).expect("serialize channel"),
        serde_json::to_string(app_origin).expect("serialize app origin"),
        serde_json::to_string(api_origin).expect("serialize API origin"),
        serde_json::to_string(update_manifest_path).expect("serialize update manifest path"),
        serde_json::to_string(public_key).expect("serialize token verification public key"),
        serde_json::to_string(&descriptor_sha256).expect("serialize descriptor digest"),
    );
    let output_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    std::fs::write(output_dir.join("agent_release_binding.json"), binding_json)
        .expect("write generated private agent release binding");

    println!("cargo:rustc-env=HYDRA_RELEASE_ENVIRONMENT={environment}");
    println!("cargo:rustc-env=HYDRA_RELEASE_CLOUD_BASE={api_origin}");
    println!("cargo:rustc-env=HYDRA_RELEASE_ALLOWED_ORIGIN={app_origin}");
    println!("cargo:rustc-env=HYDRA_RELEASE_CLOUD_PUBKEY={public_key}");
}

fn emit_self_managed_trust(path: &Path) {
    use std::io::Read as _;
    println!("cargo:rerun-if-changed={}", path.display());
    let mut raw = Vec::new();
    std::fs::File::open(path)
        .expect("could not open self-managed agent descriptor")
        .take((build_support::MAX_DESCRIPTOR_BYTES + 1) as u64)
        .read_to_end(&mut raw)
        .expect("could not read self-managed agent descriptor");
    let trust =
        build_support::SelfManagedTrust::parse(&raw).unwrap_or_else(|error| panic!("{error}"));
    let output_dir = PathBuf::from(std::env::var_os("OUT_DIR").expect("Cargo sets OUT_DIR"));
    std::fs::write(
        output_dir.join("agent_release_binding.json"),
        trust.binding_json(&raw),
    )
    .expect("write generated self-managed agent release binding");
    println!("cargo:rustc-env=HYDRA_RELEASE_ENVIRONMENT=self-managed");
    println!(
        "cargo:rustc-env=HYDRA_RELEASE_CLOUD_BASE={}",
        trust.api_origin
    );
    println!(
        "cargo:rustc-env=HYDRA_RELEASE_ALLOWED_ORIGIN={}",
        trust.app_origin
    );
    println!(
        "cargo:rustc-env=HYDRA_RELEASE_CLOUD_PUBKEY={}",
        trust.token_verification_public_key
    );
}

/// `<short-sha>` or `<short-sha>-dirty` when the working tree has uncommitted changes.
fn git_stamp() -> Option<String> {
    let sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
        .filter(|value| !value.is_empty())?;
    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .map(|output| !output.stdout.is_empty())
        .unwrap_or(false);
    Some(if dirty { format!("{sha}-dirty") } else { sha })
}
