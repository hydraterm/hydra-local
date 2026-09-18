//! Desktop device identity for PRODUCTION enrollment. A stable ed25519 keypair lives on this machine; the
//! PRIVATE key NEVER leaves it (file mode 0600). Only the PUBLIC key is uploaded (to /v1/link/redeem) to
//! enroll the desktop under the account that issued the link code. After enrolling, the cloud-assigned
//! deviceId + accountId are persisted so `remote-peer` runs without hand-passing a dev account.
//!
//! Files (under the agent data dir, default ~/.local/share/hydra-agent/):
//!   device-key        — 32-byte ed25519 seed, base64, mode 0600 (PRIVATE — never uploaded/logged)
//!   device.json       — { deviceId, accountId, cloudBase } (NON-secret enrollment record)
//!   device-owner.json — active-enrollment consistency marker. It may survive ordinary revoke/remove for crash
//!                       recovery, but an explicit fresh-code enrollment releases it before contacting the cloud

use anyhow::{Context, Result};
use base64::Engine as _;
use ed25519_dalek::SigningKey;
use serde::{Deserialize, Serialize};
use std::fs;
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use zeroize::Zeroizing;

const KEY_FILE: &str = "device-key";
const RECORD_FILE: &str = "device.json";
const OWNER_FILE: &str = "device-owner.json";
pub const ENROLLMENT_DIAGNOSTICS_FILE: &str = "enrollment-diagnostics.v1.json";
pub const ENROLLMENT_DIAGNOSTICS_TEMP_FILE: &str = ".enrollment-diagnostics.v1.json.tmp";
pub const MAX_ENROLLMENT_DIAGNOSTICS_BYTES: usize = 32 * 1024;
const MAX_ENROLLMENT_DIAGNOSTIC_EVENTS: usize = 64;
const B64: base64::engine::general_purpose::GeneralPurpose =
    base64::engine::general_purpose::STANDARD;
const SUPPORTED_PASSKEY_ALGORITHMS: [&str; 3] = ["es256", "eddsa", "rs256"];
const SUPPORTED_ENROLLMENT_AUTHORIZATION_VERSIONS: [&str; 1] = ["passkey-uv-v1"];
// Enrollment is an authority-creating, one-shot response. Keep the wire body
// small enough to read under a fixed allocation before JSON parsing, even when
// the server omits Content-Length or streams with chunked transfer encoding.
const MAX_REDEEM_RESPONSE_BYTES: usize = 64 * 1024;
const ENROLLMENT_HTTP_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const MAX_OWNER_FILE_BYTES: usize = 64 * 1024;
const MAX_DEVICE_ID_BYTES: usize = 128;
const MAX_ACCOUNT_ID_BYTES: usize = 256;
const MAX_DEVICE_LABEL_BYTES: usize = 256;
const MAX_PASSKEY_SPKI_B64_BYTES: usize = 4_096;
const MAX_PASSKEY_RP_ID_BYTES: usize = 253;
const MAX_PASSKEY_CREDENTIAL_ID_BYTES: usize = 2_048;
const MAX_ERROR_CODE_BYTES: usize = 128;
const MAX_SAFE_JSON_INTEGER: u64 = 9_007_199_254_740_991;
static RECORD_TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
struct DeviceOwner {
    version: u32,
    account_id: String,
    cloud_base: String,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RedeemedDeviceKind {
    Desktop,
    Mobile,
    Browser,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RedeemedPublicKeyAlgorithm {
    Ed25519,
    P256,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "lowercase")]
enum RedeemedPasskeyAlgorithm {
    Es256,
    Eddsa,
    Rs256,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct RedeemedDevice {
    device_id: String,
    account_id: String,
    label: String,
    public_key: String,
    #[serde(default)]
    public_key_alg: Option<RedeemedPublicKeyAlgorithm>,
    kind: RedeemedDeviceKind,
    created_at_ms: u64,
    revoked: bool,
    #[serde(default)]
    last_seen_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemedPasskey {
    spki_b64: String,
    alg: RedeemedPasskeyAlgorithm,
    rp_id: String,
    credential_id: String,
}

#[derive(Debug, Deserialize)]
enum EnrollmentAuthorizationVersion {
    #[serde(rename = "passkey-uv-v1")]
    PasskeyUvV1,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemedEnrollmentAuthorization {
    version: EnrollmentAuthorizationVersion,
    credential_id: String,
    generation: u64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemSuccessResponse {
    device: RedeemedDevice,
    passkey: RedeemedPasskey,
    enrollment_authorization: RedeemedEnrollmentAuthorization,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemErrorResponse {
    error: String,
}

/// Closed enrollment outcomes shared with the optional desktop extension. The
/// variants intentionally carry no server body, identifier, URL, code, label,
/// key material, or free-form cause.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrollmentFailureKind {
    CodeInvalid,
    OwnerMismatch,
    AuthorityStale,
    Incompatible,
    TemporarilyUnavailable,
    LocalFailure,
    OutcomeUnconfirmed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct EnrollmentFailure {
    kind: EnrollmentFailureKind,
    request_attempted: bool,
    response_started: bool,
}

impl EnrollmentFailure {
    fn before_request(kind: EnrollmentFailureKind) -> Self {
        Self {
            kind,
            request_attempted: false,
            response_started: false,
        }
    }

    fn after_request(kind: EnrollmentFailureKind, response_started: bool) -> Self {
        Self {
            kind,
            request_attempted: true,
            response_started,
        }
    }

    pub const fn kind(&self) -> EnrollmentFailureKind {
        self.kind
    }
}

impl std::fmt::Display for EnrollmentFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self.kind {
            EnrollmentFailureKind::CodeInvalid => {
                "enrollment code is invalid, expired, or already used"
            }
            EnrollmentFailureKind::OwnerMismatch => {
                "the enrollment service refused this account binding"
            }
            EnrollmentFailureKind::AuthorityStale => {
                "the account authorization for this code is no longer current"
            }
            EnrollmentFailureKind::Incompatible => {
                "the desktop and enrollment service are incompatible"
            }
            EnrollmentFailureKind::TemporarilyUnavailable => {
                "the enrollment service is temporarily unavailable"
            }
            EnrollmentFailureKind::LocalFailure => {
                "local enrollment safety checks could not complete"
            }
            EnrollmentFailureKind::OutcomeUnconfirmed => {
                "the enrollment outcome could not be confirmed"
            }
        })
    }
}

impl std::error::Error for EnrollmentFailure {}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EnrollmentDiagnosticStage {
    RedeemTerminal,
    ActivationTerminal,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum EnrollmentDiagnosticOutcome {
    Ready,
    Refused,
    Unconfirmed,
    FailedClosed,
    CleanupIncomplete,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum EnrollmentActivationOutcome {
    Ready,
    FailedClosed,
    CleanupIncomplete,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentDiagnosticEvent {
    at_ms: u64,
    agent_build_git: String,
    agent_build_dirty: bool,
    agent_build_time_ms: u64,
    agent_crate_version: String,
    stage: EnrollmentDiagnosticStage,
    outcome: EnrollmentDiagnosticOutcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    reason: Option<EnrollmentFailureKind>,
    request_attempted: bool,
    response_started: bool,
    local_record_durable: bool,
    activation_attempted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollmentDiagnostics {
    version: u32,
    events: Vec<EnrollmentDiagnosticEvent>,
}

/// Borrowed request fields avoid constructing a general-purpose JSON value containing a second owned copy of
/// the single-use code. reqwest/serde must still transiently serialize the code into the HTTP request body; that
/// transport buffer is bounded to this one request and is not retained by the agent after send completes.
#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct LinkRedeemRequest<'a> {
    code: &'a str,
    label: &'a str,
    public_key: &'a str,
    kind: &'static str,
    supported_passkey_algorithms: &'static [&'static str],
    supported_enrollment_authorization_versions: &'static [&'static str],
    #[serde(skip_serializing_if = "Option::is_none")]
    expected_account_id: Option<&'a str>,
}

/// Agent-owned, zeroizing normalization for the authority-bearing link code.
///
/// The headless prompt already owns its bytes in a `Zeroizing<Vec<u8>>`; this
/// second bounded copy is also zeroized and is the only value borrowed by the
/// JSON request. In particular, validation must not route through the public
/// extension DTO, whose owned `String` is appropriate on the desktop IPC
/// boundary but would weaken the headless secret-lifetime guarantee here.
fn normalize_enrollment_code(
    code: &str,
) -> std::result::Result<Zeroizing<Vec<u8>>, EnrollmentFailure> {
    let mut normalized = Zeroizing::new(code.as_bytes().to_vec());
    while matches!(normalized.last(), Some(b'\n' | b'\r')) {
        normalized.pop();
    }
    for byte in normalized.iter_mut() {
        *byte = byte.to_ascii_uppercase();
    }
    if normalized.len() != maestro_extension_api::ENROLLMENT_CODE_LENGTH
        || !normalized.iter().all(|byte| {
            maestro_extension_api::ENROLLMENT_CODE_ALPHABET
                .as_bytes()
                .contains(byte)
        })
    {
        return Err(EnrollmentFailure::before_request(
            EnrollmentFailureKind::CodeInvalid,
        ));
    }
    Ok(normalized)
}

/// The persisted enrollment record (non-secret) the agent reads to run remote-peer in prod.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DeviceRecord {
    pub device_id: String,
    pub account_id: String,
    pub cloud_base: String,
    /// ACCESS PASSKEY (#11): the WebAuthn passkey PUBLIC key the user registered at enrollment. The desktop
    /// verifies a browser certificate against this — so a compromised cloud can't authorize a browser the
    /// user didn't. Existing pre-passkey records remain readable, but every new enrollment requires and writes
    /// an exact passkey-authorized response; absence is never accepted on the network boundary.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub passkey: Option<crate::browser_cert::PasskeyPublicKey>,
}

/// A persisted pre-passkey record remains readable so the owner can remove or deliberately re-enroll it, but it
/// no longer authorizes cloud/remote control. This check is intentionally non-destructive: it never removes the
/// enrollment record, device key, owner marker, or daemon-owned local PTYs.
pub fn require_passkey_for_remote_authority(record: &DeviceRecord) -> Result<()> {
    if record.passkey.is_none() {
        anyhow::bail!(
            "this desktop enrollment predates required passkey authorization; run `hydraterms remove-remote --apply`, then use Add Desktop and run `hydraterms remote` again (local terminal sessions were not changed)"
        );
    }
    Ok(())
}

/// Load the existing device signing key without creating authority as a side
/// effect. A missing key is distinct from a malformed key.
pub fn load_key(dir: &Path) -> Result<Option<SigningKey>> {
    let path = dir.join(KEY_FILE);
    read_private_file(&path, KEY_FILE)?
        .map(|bytes| signing_key_from_bytes(&bytes))
        .transpose()
}

/// Load the device signing key, or generate + persist one (mode 0600). The seed is the only secret here.
pub fn load_or_create_key(dir: &Path) -> Result<SigningKey> {
    crate::agent_dir::ensure_owned_safe_authority_directory(dir)
        .with_context(|| format!("create or validate agent dir {dir:?}"))?;
    let path = dir.join(KEY_FILE);
    if let Some(bytes) = read_private_file(&path, KEY_FILE)? {
        return signing_key_from_bytes(&bytes);
    }

    // Create the secret with owner-only permissions from the first observable instant. `create_new` also
    // prevents following or truncating a path an attacker raced into place. If another legitimate process
    // won the creation race, validate and use that key instead of replacing it.
    let mut seed = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut seed);
    match create_private_file(&path, KEY_FILE) {
        Ok(mut file) => {
            let encoded = B64.encode(seed);
            file.write_all(encoded.as_bytes())
                .context("write device-key")?;
            file.sync_all().context("sync device-key")?;
            validate_private_file(&file, KEY_FILE)?;
            drop(file);
            sync_directory(dir).context("sync device-key parent directory")?;
            let readback = read_private_file(&path, KEY_FILE)?
                .ok_or_else(|| anyhow::anyhow!("device-key vanished after durable publication"))?;
            if readback != encoded.as_bytes() {
                anyhow::bail!("device-key readback differs after durable publication");
            }
            Ok(SigningKey::from_bytes(&seed))
        }
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
            let bytes = read_private_file(&path, KEY_FILE)?
                .ok_or_else(|| anyhow::anyhow!("device-key disappeared during creation"))?;
            signing_key_from_bytes(&bytes)
        }
        Err(error) => Err(error).context("create device-key"),
    }
}

fn signing_key_from_bytes(bytes: &[u8]) -> Result<SigningKey> {
    let b64 = std::str::from_utf8(bytes).context("device-key utf8")?;
    let seed = B64.decode(b64.trim()).context("device-key base64")?;
    let arr: [u8; 32] = seed
        .as_slice()
        .try_into()
        .map_err(|_| anyhow::anyhow!("device-key must be 32 bytes"))?;
    Ok(SigningKey::from_bytes(&arr))
}

/// base64 of the 32-byte PUBLIC key — what we upload to enroll. (Never the private seed.)
pub fn public_key_b64(key: &SigningKey) -> String {
    B64.encode(key.verifying_key().to_bytes())
}

fn link_redeem_request_body<'a>(
    code: &'a str,
    label: &'a str,
    public_key: &'a str,
    expected_account_id: Option<&'a str>,
) -> LinkRedeemRequest<'a> {
    LinkRedeemRequest {
        code,
        label,
        public_key,
        kind: "desktop",
        // Capability negotiation prevents the cloud from enrolling this desktop with an account anchor it
        // cannot verify. Keep this list aligned with browser_cert::verify_browser_cert.
        supported_passkey_algorithms: &SUPPORTED_PASSKEY_ALGORITHMS,
        // The cloud refuses before code lookup/claim unless the agent proves it understands the mandatory
        // response marker. This prevents a predecessor agent from consuming a current code and persisting an
        // unanchored desktop record.
        supported_enrollment_authorization_versions: &SUPPORTED_ENROLLMENT_AUTHORIZATION_VERSIONS,
        expected_account_id,
    }
}

pub fn record_path(dir: &Path) -> PathBuf {
    dir.join(RECORD_FILE)
}

pub fn enrollment_diagnostics_path(dir: &Path) -> PathBuf {
    dir.join(ENROLLMENT_DIAGNOSTICS_FILE)
}

pub fn enrollment_diagnostics_temporary_path(dir: &Path) -> PathBuf {
    dir.join(ENROLLMENT_DIAGNOSTICS_TEMP_FILE)
}

fn owner_path(dir: &Path) -> PathBuf {
    dir.join(OWNER_FILE)
}

fn private_open_options() -> fs::OpenOptions {
    let mut options = fs::OpenOptions::new();
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    options
}

fn create_private_file(path: &Path, label: &str) -> std::io::Result<fs::File> {
    let mut options = private_open_options();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.mode(0o600);
    }
    options
        .open(path)
        .map_err(|error| std::io::Error::new(error.kind(), format!("{label}: {error}")))
}

fn open_existing_private(path: &Path, label: &str) -> Result<Option<fs::File>> {
    let mut options = private_open_options();
    options.read(true);
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("open {label}")),
    };
    validate_private_file(&file, label)?;
    Ok(Some(file))
}

fn open_existing_diagnostic(path: &Path, label: &str) -> Result<Option<fs::File>> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let file = match options.open(path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error).with_context(|| format!("open {label}")),
        };
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect {label}"))?;
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            anyhow::bail!("refusing {label}: diagnostic file metadata is unsafe");
        }
        Ok(Some(file))
    }
    #[cfg(not(unix))]
    {
        open_existing_private(path, label)
    }
}

#[cfg(unix)]
fn require_named_diagnostic_inode(path: &Path, file: &fs::File, label: &str) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let opened = file
        .metadata()
        .with_context(|| format!("reinspect opened {label}"))?;
    let named = fs::symlink_metadata(path).with_context(|| format!("reinspect named {label}"))?;
    if !named.file_type().is_file()
        || opened.dev() != named.dev()
        || opened.ino() != named.ino()
        || opened.uid() != unsafe { libc::geteuid() }
        || opened.permissions().mode() & 0o7777 != 0o600
        || opened.nlink() != 1
    {
        anyhow::bail!("refusing {label}: diagnostic inode binding changed");
    }
    Ok(())
}

fn validate_private_file(file: &fs::File, label: &str) -> Result<()> {
    #[cfg(unix)]
    {
        validate_private_file_for_uid(file, label, unsafe { libc::geteuid() })
    }
    #[cfg(not(unix))]
    {
        let metadata = file
            .metadata()
            .with_context(|| format!("inspect {label}"))?;
        if !metadata.file_type().is_file() {
            anyhow::bail!("refusing {label}: path is not a regular file");
        }
        Ok(())
    }
}

#[cfg(unix)]
fn validate_private_file_for_uid(file: &fs::File, label: &str, expected_uid: u32) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_file() {
        anyhow::bail!("refusing {label}: path is not a regular file");
    }
    if metadata.uid() != expected_uid {
        anyhow::bail!(
            "refusing {label}: file owner uid {} does not match process uid {expected_uid}",
            metadata.uid()
        );
    }
    if metadata.mode() & 0o077 != 0 {
        anyhow::bail!(
            "refusing {label}: group/world permissions {:03o} are not owner-only",
            metadata.mode() & 0o777
        );
    }
    if metadata.nlink() != 1 {
        anyhow::bail!(
            "refusing {label}: private identity file has {} hard links",
            metadata.nlink()
        );
    }
    Ok(())
}

fn read_private_file(path: &Path, label: &str) -> Result<Option<Vec<u8>>> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} has no parent directory"))?;
    match fs::symlink_metadata(parent) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("inspect {label} parent")),
        Ok(_) => crate::agent_dir::require_owned_safe_directory(parent)
            .with_context(|| format!("validate {label} parent"))?,
    }
    let Some(mut file) = open_existing_private(path, label)? else {
        return Ok(None);
    };
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    Ok(Some(bytes))
}

fn read_bounded_diagnostic_file(
    path: &Path,
    label: &str,
    max_bytes: usize,
) -> Result<Option<(Vec<u8>, bool)>> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} has no parent directory"))?;
    match fs::symlink_metadata(parent) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).with_context(|| format!("inspect {label} parent")),
        Ok(_) => crate::agent_dir::require_owned_safe_directory(parent)
            .with_context(|| format!("validate {label} parent"))?,
    }
    let Some(file) = open_existing_diagnostic(path, label)? else {
        return Ok(None);
    };
    let mut bytes = Vec::with_capacity(max_bytes.min(8 * 1024));
    file.take((max_bytes + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    let oversized = bytes.len() > max_bytes;
    Ok(Some((bytes, oversized)))
}

fn write_private_json<T: Serialize>(
    dir: &Path,
    file_name: &str,
    temporary_prefix: &str,
    value: &T,
) -> Result<()> {
    let path = dir.join(file_name);
    crate::agent_dir::ensure_owned_safe_authority_directory(dir)
        .context("create or validate enrollment directory")?;
    let expected = serde_json::to_vec_pretty(value)?;
    let temporary = dir.join(format!(
        ".{temporary_prefix}.tmp.{}.{}",
        std::process::id(),
        RECORD_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> Result<()> {
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        // Never replace a pre-existing enrollment file unless the exact opened inode is a regular,
        // owner-matching, owner-only file. This rejects symlink, foreign-owner, and loose-mode migrations.
        let _existing = open_existing_private(&path, file_name)?;
        let mut file = options
            .open(&temporary)
            .with_context(|| format!("create temporary {file_name}"))?;
        file.write_all(&expected)
            .with_context(|| format!("write temporary {file_name}"))?;
        file.sync_all()
            .with_context(|| format!("sync temporary {file_name}"))?;
        validate_private_file(&file, file_name)?;
        drop(file);
        fs::rename(&temporary, &path).with_context(|| format!("replace {file_name}"))?;
        sync_directory(dir).with_context(|| format!("sync {file_name} parent directory"))?;
        let readback = read_private_file(&path, file_name)?
            .ok_or_else(|| anyhow::anyhow!("{file_name} vanished after durable publication"))?;
        if readback != expected {
            anyhow::bail!("{file_name} readback differs after durable publication");
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result?;
    Ok(())
}

fn remove_safe_stale_diagnostic_temporary(dir: &Path) -> Result<()> {
    let path = enrollment_diagnostics_temporary_path(dir);
    let Some(file) = open_existing_diagnostic(&path, ENROLLMENT_DIAGNOSTICS_TEMP_FILE)? else {
        return Ok(());
    };
    #[cfg(unix)]
    require_named_diagnostic_inode(&path, &file, ENROLLMENT_DIAGNOSTICS_TEMP_FILE)?;
    drop(file);
    fs::remove_file(&path).context("remove stale enrollment diagnostic temporary")?;
    sync_directory(dir).context("sync stale enrollment diagnostic temporary removal")?;
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).context("verify stale enrollment diagnostic temporary removal"),
        Ok(_) => anyhow::bail!("enrollment diagnostic temporary reappeared after removal"),
    }
}

fn write_enrollment_diagnostics(dir: &Path, value: &EnrollmentDiagnostics) -> Result<()> {
    crate::agent_dir::ensure_owned_safe_authority_directory(dir)
        .context("create or validate enrollment diagnostic directory")?;
    let expected = serde_json::to_vec_pretty(value)?;
    if expected.len() > MAX_ENROLLMENT_DIAGNOSTICS_BYTES {
        anyhow::bail!("enrollment diagnostics exceed the byte bound");
    }
    remove_safe_stale_diagnostic_temporary(dir)?;

    let path = enrollment_diagnostics_path(dir);
    let existing = open_existing_diagnostic(&path, ENROLLMENT_DIAGNOSTICS_FILE)?;
    #[cfg(unix)]
    if let Some(file) = existing.as_ref() {
        require_named_diagnostic_inode(&path, file, ENROLLMENT_DIAGNOSTICS_FILE)?;
    }

    let temporary = enrollment_diagnostics_temporary_path(dir);
    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options
            .mode(0o600)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let mut file = options
        .open(&temporary)
        .context("create enrollment diagnostic temporary")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        file.set_permissions(fs::Permissions::from_mode(0o600))
            .context("set enrollment diagnostic temporary mode")?;
        let metadata = file.metadata()?;
        if !metadata.file_type().is_file()
            || metadata.uid() != unsafe { libc::geteuid() }
            || metadata.permissions().mode() & 0o7777 != 0o600
            || metadata.nlink() != 1
        {
            anyhow::bail!("enrollment diagnostic temporary metadata is unsafe");
        }
    }
    file.write_all(&expected)
        .context("write enrollment diagnostic temporary")?;
    file.sync_all()
        .context("sync enrollment diagnostic temporary")?;
    #[cfg(unix)]
    require_named_diagnostic_inode(&temporary, &file, ENROLLMENT_DIAGNOSTICS_TEMP_FILE)?;

    match existing.as_ref() {
        Some(existing) => {
            #[cfg(unix)]
            require_named_diagnostic_inode(&path, existing, ENROLLMENT_DIAGNOSTICS_FILE)?;
        }
        None => match fs::symlink_metadata(&path) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("reinspect enrollment diagnostic target"),
            Ok(_) => anyhow::bail!("enrollment diagnostic target appeared before publication"),
        },
    }
    drop(file);
    fs::rename(&temporary, &path).context("publish enrollment diagnostics")?;
    sync_directory(dir).context("sync enrollment diagnostics parent")?;

    let published = open_existing_diagnostic(&path, ENROLLMENT_DIAGNOSTICS_FILE)?
        .ok_or_else(|| anyhow::anyhow!("enrollment diagnostics vanished after publication"))?;
    #[cfg(unix)]
    require_named_diagnostic_inode(&path, &published, ENROLLMENT_DIAGNOSTICS_FILE)?;
    let mut readback = Vec::with_capacity(expected.len().min(MAX_ENROLLMENT_DIAGNOSTICS_BYTES));
    published
        .take((MAX_ENROLLMENT_DIAGNOSTICS_BYTES + 1) as u64)
        .read_to_end(&mut readback)
        .context("read back enrollment diagnostics")?;
    if readback.len() > MAX_ENROLLMENT_DIAGNOSTICS_BYTES {
        anyhow::bail!("published enrollment diagnostics exceed the byte bound");
    }
    if readback != expected {
        anyhow::bail!("enrollment diagnostics readback differs after publication");
    }
    Ok(())
}

fn canonical_diagnostic_build() -> Result<(String, bool, u64, String)> {
    let raw_git = crate::build_git();
    let (git, dirty) = raw_git
        .strip_suffix("-dirty")
        .map_or((raw_git, false), |git| (git, true));
    let git = if git == "unknown" {
        "unknown".to_string()
    } else if (7..=40).contains(&git.len())
        && git
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        git.to_string()
    } else {
        anyhow::bail!("build git projection is not canonical");
    };
    let build_time_ms = crate::build_time_ms()
        .parse::<u64>()
        .context("build time projection is not numeric")?;
    if build_time_ms > MAX_SAFE_JSON_INTEGER {
        anyhow::bail!("build time projection is not JSON-safe");
    }
    let crate_version = env!("CARGO_PKG_VERSION");
    if crate_version.is_empty()
        || crate_version.len() > 64
        || !crate_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
    {
        anyhow::bail!("agent crate version projection is not canonical");
    }
    Ok((git, dirty, build_time_ms, crate_version.to_string()))
}

fn diagnostic_now_ms() -> Result<u64> {
    let value = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .context("system clock predates the Unix epoch")?
        .as_millis();
    let value = u64::try_from(value).context("system clock exceeds the diagnostic bound")?;
    if value > MAX_SAFE_JSON_INTEGER {
        anyhow::bail!("system clock is not JSON-safe");
    }
    Ok(value)
}

fn validate_diagnostic_build(event: &EnrollmentDiagnosticEvent) -> Result<()> {
    if event.at_ms > MAX_SAFE_JSON_INTEGER
        || event.agent_build_time_ms > MAX_SAFE_JSON_INTEGER
        || event.agent_crate_version.is_empty()
        || event.agent_crate_version.len() > 64
        || !event
            .agent_crate_version
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'+' | b'-'))
    {
        anyhow::bail!("enrollment diagnostic build projection is invalid");
    }
    if event.agent_build_git != "unknown"
        && (!(7..=40).contains(&event.agent_build_git.len())
            || !event
                .agent_build_git
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase()))
    {
        anyhow::bail!("enrollment diagnostic git projection is invalid");
    }
    Ok(())
}

fn validate_diagnostic_event(event: &EnrollmentDiagnosticEvent) -> Result<()> {
    validate_diagnostic_build(event)?;
    if event.response_started && !event.request_attempted {
        anyhow::bail!("enrollment diagnostic response precedes request");
    }
    match event.stage {
        EnrollmentDiagnosticStage::RedeemTerminal => {
            if event.local_record_durable || event.activation_attempted || event.reason.is_none() {
                anyhow::bail!("enrollment redeem diagnostic has inconsistent flags");
            }
            let expected = match event.reason {
                Some(EnrollmentFailureKind::OutcomeUnconfirmed) => {
                    EnrollmentDiagnosticOutcome::Unconfirmed
                }
                Some(EnrollmentFailureKind::LocalFailure) => {
                    EnrollmentDiagnosticOutcome::FailedClosed
                }
                Some(_) => EnrollmentDiagnosticOutcome::Refused,
                None => unreachable!(),
            };
            if event.outcome != expected {
                anyhow::bail!("enrollment redeem diagnostic has inconsistent outcome");
            }
        }
        EnrollmentDiagnosticStage::ActivationTerminal => {
            if !event.request_attempted
                || !event.response_started
                || !event.local_record_durable
                || !event.activation_attempted
            {
                anyhow::bail!("enrollment activation diagnostic has inconsistent flags");
            }
            match (event.outcome, event.reason) {
                (EnrollmentDiagnosticOutcome::Ready, None)
                | (EnrollmentDiagnosticOutcome::FailedClosed, None)
                | (EnrollmentDiagnosticOutcome::CleanupIncomplete, None) => {}
                _ => anyhow::bail!("enrollment activation diagnostic has inconsistent outcome"),
            }
        }
    }
    Ok(())
}

fn append_enrollment_diagnostic(
    dir: &Path,
    locks: &crate::service::LifecycleLockSet,
    event: EnrollmentDiagnosticEvent,
) -> Result<()> {
    locks
        .require_agent_dir(dir)
        .context("enrollment diagnostic writer lacks the lifecycle lock")?;
    if crate::lifecycle_cleanup::load(dir)?.is_some_and(|pending| {
        pending.intent() == crate::lifecycle_cleanup::CleanupIntent::FullForget
    }) {
        anyhow::bail!("enrollment diagnostics are frozen by pending FullForget");
    }
    validate_diagnostic_event(&event)?;
    let path = enrollment_diagnostics_path(dir);
    let mut diagnostics = match read_bounded_diagnostic_file(
        &path,
        ENROLLMENT_DIAGNOSTICS_FILE,
        MAX_ENROLLMENT_DIAGNOSTICS_BYTES,
    )? {
        Some((_bytes, true)) => EnrollmentDiagnostics {
            version: 1,
            events: Vec::new(),
        },
        Some((bytes, false)) => (|| -> Result<EnrollmentDiagnostics> {
            let parsed: EnrollmentDiagnostics =
                serde_json::from_slice(&bytes).context("parse enrollment diagnostics")?;
            if parsed.version != 1 || parsed.events.len() > MAX_ENROLLMENT_DIAGNOSTIC_EVENTS {
                anyhow::bail!("enrollment diagnostics header is invalid");
            }
            for prior in &parsed.events {
                validate_diagnostic_event(prior)?;
            }
            Ok(parsed)
        })()
        .unwrap_or(EnrollmentDiagnostics {
            version: 1,
            events: Vec::new(),
        }),
        None => EnrollmentDiagnostics {
            version: 1,
            events: Vec::new(),
        },
    };
    diagnostics.events.push(event);
    diagnostics = bound_enrollment_diagnostics(
        diagnostics,
        MAX_ENROLLMENT_DIAGNOSTIC_EVENTS,
        MAX_ENROLLMENT_DIAGNOSTICS_BYTES,
    )?;
    write_enrollment_diagnostics(dir, &diagnostics)
}

fn bound_enrollment_diagnostics(
    mut diagnostics: EnrollmentDiagnostics,
    max_events: usize,
    max_bytes: usize,
) -> Result<EnrollmentDiagnostics> {
    while diagnostics.events.len() > max_events {
        diagnostics.events.remove(0);
    }
    loop {
        let encoded = serde_json::to_vec_pretty(&diagnostics)?;
        if encoded.len() <= max_bytes {
            break;
        }
        if diagnostics.events.len() <= 1 {
            anyhow::bail!("one enrollment diagnostic exceeds the byte bound");
        }
        diagnostics.events.remove(0);
    }
    Ok(diagnostics)
}

fn enrollment_diagnostic_event(
    stage: EnrollmentDiagnosticStage,
    outcome: EnrollmentDiagnosticOutcome,
    reason: Option<EnrollmentFailureKind>,
    request_attempted: bool,
    response_started: bool,
    local_record_durable: bool,
    activation_attempted: bool,
) -> Result<EnrollmentDiagnosticEvent> {
    let (agent_build_git, agent_build_dirty, agent_build_time_ms, agent_crate_version) =
        canonical_diagnostic_build()?;
    Ok(EnrollmentDiagnosticEvent {
        at_ms: diagnostic_now_ms()?,
        agent_build_git,
        agent_build_dirty,
        agent_build_time_ms,
        agent_crate_version,
        stage,
        outcome,
        reason,
        request_attempted,
        response_started,
        local_record_durable,
        activation_attempted,
    })
}

const MIN_DIAGNOSTIC_DEADLINE_MARGIN: std::time::Duration = std::time::Duration::from_secs(4);

fn best_effort_diagnostic(deadline: Option<std::time::Instant>, sink: impl FnOnce() -> Result<()>) {
    if deadline.is_some_and(|deadline| {
        deadline.saturating_duration_since(std::time::Instant::now())
            < MIN_DIAGNOSTIC_DEADLINE_MARGIN
    }) {
        return;
    }
    let _ = sink();
}

fn record_enrollment_failure_diagnostic(
    dir: &Path,
    locks: &crate::service::LifecycleLockSet,
    failure: EnrollmentFailure,
    deadline: Option<std::time::Instant>,
) {
    let outcome = match failure.kind {
        EnrollmentFailureKind::OutcomeUnconfirmed => EnrollmentDiagnosticOutcome::Unconfirmed,
        EnrollmentFailureKind::LocalFailure => EnrollmentDiagnosticOutcome::FailedClosed,
        _ => EnrollmentDiagnosticOutcome::Refused,
    };
    best_effort_diagnostic(deadline, || {
        let event = enrollment_diagnostic_event(
            EnrollmentDiagnosticStage::RedeemTerminal,
            outcome,
            Some(failure.kind),
            failure.request_attempted,
            failure.response_started,
            false,
            false,
        )?;
        append_enrollment_diagnostic(dir, locks, event)
    });
}

/// Record only the GUI optional-extension's terminal activation result. The
/// headless CLI reports activation failures synchronously and deliberately
/// does not project them into this ring. This sink is best-effort: a diagnostic
/// failure never changes enrollment, cleanup, or UI outcome.
pub fn record_enrollment_activation_terminal(
    dir: &Path,
    locks: &crate::service::LifecycleLockSet,
    activation: EnrollmentActivationOutcome,
    deadline: Option<std::time::Instant>,
) {
    if locks.require_agent_dir(dir).is_err() {
        return;
    }
    let outcome = match activation {
        EnrollmentActivationOutcome::Ready => EnrollmentDiagnosticOutcome::Ready,
        EnrollmentActivationOutcome::FailedClosed => EnrollmentDiagnosticOutcome::FailedClosed,
        EnrollmentActivationOutcome::CleanupIncomplete => {
            EnrollmentDiagnosticOutcome::CleanupIncomplete
        }
    };
    best_effort_diagnostic(deadline, || {
        let event = enrollment_diagnostic_event(
            EnrollmentDiagnosticStage::ActivationTerminal,
            outcome,
            None,
            true,
            true,
            true,
            true,
        )?;
        append_enrollment_diagnostic(dir, locks, event)
    });
}

fn parse_owner(bytes: &[u8]) -> Result<DeviceOwner> {
    let owner: DeviceOwner = serde_json::from_slice(bytes).context("parse device-owner.json")?;
    if owner.version != 1 || owner.account_id.is_empty() || owner.cloud_base.is_empty() {
        anyhow::bail!("invalid device-owner.json");
    }
    Ok(owner)
}

fn load_owner(dir: &Path) -> Result<Option<DeviceOwner>> {
    recover_completed_owner_publication(dir)?;
    let path = owner_path(dir);
    read_private_file(&path, OWNER_FILE)?
        .map(|bytes| parse_owner(&bytes))
        .transpose()
}

/// Release a retired owner marker before an explicit fresh-code enrollment.
///
/// The active `device.json` remains the hard boundary: if it exists, no owner
/// marker is changed. Once Remote has been removed, however, the user may bind
/// this OS profile to any passkey-authorized account without ending daemon-owned
/// PTYs or deleting local projects. Production callers hold the lifecycle lock
/// across this function and the subsequent one-shot redeem. The repeated record
/// check keeps the standalone test/helper entry point fail-closed as well.
fn release_retired_owner_for_reenrollment(
    dir: &Path,
    locks: &crate::service::LifecycleLockSet,
) -> Result<()> {
    locks
        .require_agent_dir(dir)
        .context("retired owner release lacks the lifecycle lock")?;
    if load_record(dir)?.is_some() {
        return Ok(());
    }
    recover_completed_owner_publication(dir)?;
    let path = owner_path(dir);
    let Some(owner_file) = open_existing_private(&path, OWNER_FILE)? else {
        return Ok(());
    };
    if load_record(dir)?.is_some() {
        anyhow::bail!("active enrollment appeared before retired owner release");
    }

    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        let opened = owner_file
            .metadata()
            .context("reinspect opened retired device-owner.json")?;
        let named =
            fs::symlink_metadata(&path).context("reinspect named retired device-owner.json")?;
        if !named.file_type().is_file()
            || opened.dev() != named.dev()
            || opened.ino() != named.ino()
            || opened.uid() != crate::agent_dir::trusted_uid()
            || opened.mode() & 0o077 != 0
            || opened.nlink() != 1
        {
            anyhow::bail!("retired device-owner.json binding changed before release");
        }
    }

    fs::remove_file(&path).context("release retired device-owner.json")?;
    sync_directory(dir).context("sync retired owner release")?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;

        if owner_file
            .metadata()
            .context("verify released device-owner.json inode")?
            .nlink()
            != 0
        {
            anyhow::bail!("retired device-owner.json retained another name after release");
        }
    }
    drop(owner_file);
    if open_existing_private(&path, OWNER_FILE)?.is_some() {
        anyhow::bail!("retired device-owner.json reappeared after release");
    }
    Ok(())
}

/// Complete the single crash window in the no-replace owner publication. A
/// crash after `hard_link(temp, final)` but before unlinking `temp` leaves the
/// two names bound to one valid inode (`nlink == 2`). Recover only that exact
/// shape; every other multi-link, name, owner, mode, or inode relationship
/// remains fail-closed.
fn recover_completed_owner_publication(dir: &Path) -> Result<()> {
    #[cfg(not(unix))]
    {
        let _ = dir;
        return Ok(());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

        match fs::symlink_metadata(dir) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("inspect owner recovery directory"),
            Ok(_) => {}
        }
        crate::agent_dir::require_owned_safe_directory(dir)
            .context("validate owner recovery directory")?;
        crate::agent_dir::require_rename_safe_ancestry(
            dir.parent()
                .ok_or_else(|| anyhow::anyhow!("owner recovery directory has no parent"))?,
        )
        .context("validate owner recovery ancestry")?;
        let mut directory_options = fs::OpenOptions::new();
        directory_options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
        let directory = directory_options
            .open(dir)
            .context("open owner recovery directory")?;
        let directory_metadata = directory
            .metadata()
            .context("inspect opened owner recovery directory")?;
        let named_directory =
            fs::symlink_metadata(dir).context("reinspect named owner recovery directory")?;
        if directory_metadata.dev() != named_directory.dev()
            || directory_metadata.ino() != named_directory.ino()
            || directory_metadata.uid() != crate::agent_dir::trusted_uid()
        {
            anyhow::bail!("owner recovery directory changed before inventory");
        }

        let path = owner_path(dir);
        let mut options = fs::OpenOptions::new();
        options
            .read(true)
            .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
        let mut final_file = match options.open(&path) {
            Ok(file) => file,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(error) => return Err(error).context("open device-owner.json for recovery"),
        };
        let metadata = final_file
            .metadata()
            .context("inspect device-owner.json recovery inode")?;
        if metadata.nlink() == 1 {
            return Ok(());
        }
        if !metadata.file_type().is_file()
            || metadata.uid() != crate::agent_dir::trusted_uid()
            || metadata.mode() & 0o077 != 0
            || metadata.nlink() != 2
        {
            anyhow::bail!("refusing device-owner.json: incomplete publication is not exact");
        }
        let mut bytes = Vec::with_capacity(MAX_OWNER_FILE_BYTES.min(8 * 1024));
        (&mut final_file)
            .take((MAX_OWNER_FILE_BYTES + 1) as u64)
            .read_to_end(&mut bytes)
            .context("read device-owner.json recovery inode")?;
        if bytes.len() > MAX_OWNER_FILE_BYTES {
            anyhow::bail!("device-owner.json recovery inode exceeds its byte bound");
        }
        let _ = parse_owner(&bytes)?;

        let mut matching = Vec::new();
        let mut entries = 0usize;
        for entry in
            fs::read_dir(dir).context("inventory enrollment directory for owner recovery")?
        {
            let entry = entry.context("read enrollment directory during owner recovery")?;
            entries += 1;
            if entries > 128 {
                anyhow::bail!("enrollment directory exceeds owner recovery inventory bound");
            }
            let Some(name) = entry.file_name().to_str().map(str::to_string) else {
                continue;
            };
            if !is_exact_owner_temporary_name(&name) {
                continue;
            }
            let candidate = fs::symlink_metadata(entry.path())
                .context("inspect owner publication temporary")?;
            if candidate.dev() == metadata.dev() && candidate.ino() == metadata.ino() {
                matching.push(entry.path());
            }
        }
        if matching.len() != 1 {
            // A concurrent publisher may have completed the unlink after our
            // first fstat. Accept only an exact single-link readback.
            if final_file.metadata()?.nlink() == 1 {
                return Ok(());
            }
            anyhow::bail!("device-owner.json recovery alias is missing or ambiguous");
        }
        let named_before_unlink = fs::symlink_metadata(&path)
            .context("reinspect device-owner.json before recovery unlink")?;
        let alias_before_unlink = fs::symlink_metadata(&matching[0])
            .context("reinspect owner publication temporary before unlink")?;
        let opened_before_unlink = final_file
            .metadata()
            .context("reinspect opened owner inode before unlink")?;
        let opened_directory_before_unlink = directory
            .metadata()
            .context("reinspect opened owner recovery directory before unlink")?;
        let named_directory_before_unlink = fs::symlink_metadata(dir)
            .context("reinspect named owner recovery directory before unlink")?;
        if opened_directory_before_unlink.dev() != directory_metadata.dev()
            || opened_directory_before_unlink.ino() != directory_metadata.ino()
            || named_directory_before_unlink.dev() != directory_metadata.dev()
            || named_directory_before_unlink.ino() != directory_metadata.ino()
            || opened_before_unlink.dev() != metadata.dev()
            || opened_before_unlink.ino() != metadata.ino()
            || opened_before_unlink.nlink() != 2
            || named_before_unlink.dev() != metadata.dev()
            || named_before_unlink.ino() != metadata.ino()
            || alias_before_unlink.dev() != metadata.dev()
            || alias_before_unlink.ino() != metadata.ino()
        {
            anyhow::bail!("device-owner.json recovery binding changed before unlink");
        }
        fs::remove_file(&matching[0]).context("unlink completed owner publication temporary")?;
        sync_directory(dir).context("sync recovered owner publication")?;
        let opened_after = final_file.metadata()?;
        let named_after = fs::symlink_metadata(&path)?;
        if opened_after.nlink() != 1
            || named_after.dev() != opened_after.dev()
            || named_after.ino() != opened_after.ino()
            || named_after.uid() != crate::agent_dir::trusted_uid()
            || named_after.mode() & 0o077 != 0
        {
            anyhow::bail!("device-owner.json recovery did not converge to one exact link");
        }
        Ok(())
    }
}

fn is_exact_owner_temporary_name(name: &str) -> bool {
    let Some(rest) = name.strip_prefix(".device-owner.json.tmp.") else {
        return false;
    };
    let Some((pid, sequence)) = rest.split_once('.') else {
        return false;
    };
    !pid.is_empty()
        && !sequence.is_empty()
        && pid.bytes().all(|byte| byte.is_ascii_digit())
        && sequence.bytes().all(|byte| byte.is_ascii_digit())
}

fn owner_for_record(rec: &DeviceRecord) -> DeviceOwner {
    DeviceOwner {
        version: 1,
        account_id: rec.account_id.clone(),
        cloud_base: rec.cloud_base.trim_end_matches('/').to_string(),
    }
}

/// Publish the first durable owner without replacing a marker another lifecycle
/// process won the race to create. The temporary and final names share a
/// directory, so the hard-link publication is atomic and no-clobber.
fn publish_owner_no_replace(dir: &Path, owner: &DeviceOwner) -> Result<()> {
    crate::agent_dir::ensure_owned_safe_authority_directory(dir)
        .context("create or validate enrollment directory")?;
    let path = owner_path(dir);
    let temporary = dir.join(format!(
        ".device-owner.json.tmp.{}.{}",
        std::process::id(),
        RECORD_TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let expected = serde_json::to_vec_pretty(owner).context("serialize device-owner.json")?;
    let result = (|| -> Result<()> {
        let mut file = create_private_file(&temporary, "temporary device-owner.json")
            .context("create temporary device-owner.json")?;
        file.write_all(&expected)
            .context("write temporary device-owner.json")?;
        file.sync_all()
            .context("sync temporary device-owner.json")?;
        validate_private_file(&file, "temporary device-owner.json")?;
        drop(file);
        match fs::hard_link(&temporary, &path) {
            Ok(()) => {
                match fs::remove_file(&temporary) {
                    Ok(()) => {}
                    Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                        // Another same-profile reader may have completed the
                        // exact nlink=2 crash-recovery shape for us.
                    }
                    Err(error) => return Err(error).context("unlink temporary device-owner.json"),
                }
                sync_directory(dir).context("sync enrollment directory")?;
                let readback = read_private_file(&path, OWNER_FILE)?.ok_or_else(|| {
                    anyhow::anyhow!("device-owner.json vanished after durable publication")
                })?;
                if readback != expected {
                    anyhow::bail!("device-owner.json readback differs after durable publication");
                }
                Ok(())
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let actual = read_private_file(&path, OWNER_FILE)?
                    .ok_or_else(|| anyhow::anyhow!("device-owner.json disappeared"))?;
                if parse_owner(&actual)? == *owner {
                    Ok(())
                } else {
                    anyhow::bail!("device-owner.json changed during owner claim")
                }
            }
            Err(error) => Err(error).context("publish device-owner.json"),
        }
    })();
    let _ = fs::remove_file(&temporary);
    result
}

fn sync_directory(path: &Path) -> std::io::Result<()> {
    fs::File::open(path)?.sync_all()
}

/// Establish or verify the durable owner before changing the replaceable enrollment record. On upgrades, a
/// legacy device.json is authoritative for the first owner marker. The marker is written before device.json so a
/// crash cannot leave a newly activated enrollment without its ownership boundary.
fn claim_or_verify_owner(dir: &Path, candidate: &DeviceRecord) -> Result<()> {
    let candidate_owner = owner_for_record(candidate);
    let loaded_owner = load_owner(dir)?;
    let owner_marker_missing = loaded_owner.is_none();
    let established = match loaded_owner {
        Some(owner) => Some(owner),
        None => load_record(dir)?.as_ref().map(owner_for_record),
    };
    if let Some(owner) = established {
        if owner.account_id != candidate_owner.account_id
            || owner.cloud_base != candidate_owner.cloud_base
        {
            anyhow::bail!(
                "active owner differs; cross-account replacement requires an explicit fresh-code enrollment after Remote removal"
            );
        }
        if owner_marker_missing {
            publish_owner_no_replace(dir, &owner)?;
        }
        return Ok(());
    }
    publish_owner_no_replace(dir, &candidate_owner)
}

/// Narrow migration seam: establish the canonical durable owner before a key
/// or active record is adopted. All validation and no-clobber publication stay
/// owned by this module.
pub(crate) fn claim_or_verify_owner_for_record(dir: &Path, candidate: &DeviceRecord) -> Result<()> {
    claim_or_verify_owner(dir, candidate)
}

pub(crate) fn verify_optional_owner_for_record(dir: &Path, candidate: &DeviceRecord) -> Result<()> {
    if load_owner(dir)?.is_some_and(|owner| owner != owner_for_record(candidate)) {
        anyhow::bail!("device-owner.json conflicts with the enrollment record");
    }
    Ok(())
}

pub(crate) fn verified_owner_marker_bytes(dir: &Path) -> Result<Vec<u8>> {
    let bytes = read_private_file(&owner_path(dir), OWNER_FILE)?
        .ok_or_else(|| anyhow::anyhow!("device-owner.json is absent"))?;
    let _ = parse_owner(&bytes)?;
    Ok(bytes)
}

/// Upgrade a legacy enrollment to the active-owner consistency boundary without changing its device record.
/// Callers that remove replaceable credentials establish this marker first so interrupted cleanup remains
/// recoverable; only a later explicit fresh-code enrollment may release the retired marker.
pub fn preserve_owner_marker(dir: &Path) -> Result<()> {
    if let Some(current) = load_record(dir)? {
        claim_or_verify_owner(dir, &current)?;
    }
    Ok(())
}

pub fn save_record(dir: &Path, rec: &DeviceRecord) -> Result<()> {
    claim_or_verify_owner_for_record(dir, rec)?;
    write_private_json(dir, RECORD_FILE, "device.json", rec)
}

pub fn load_record(dir: &Path) -> Result<Option<DeviceRecord>> {
    let path = record_path(dir);
    let Some(bytes) = read_private_file(&path, RECORD_FILE)? else {
        return Ok(None);
    };
    Ok(Some(
        serde_json::from_slice(&bytes).context("parse device.json")?,
    ))
}

/// Is this desktop already enrolled? Thin, non-erroring wrapper over [`load_record`] — a missing/unreadable
/// device.json is simply "not enrolled" (None). Used by the app to decide whether to show the "Add Remote" field or
/// the enrolled account.
pub fn is_enrolled(dir: &Path) -> Option<DeviceRecord> {
    load_record(dir).ok().flatten()
}

/// Fail-closed live binding check for an already-authenticated private peer.
/// Missing, unreadable, corrupt, or replaced enrollment state revokes the
/// channel on its next message/tick. The browser device id is intentionally not
/// part of this desktop-local record.
pub fn enrollment_binding_is_revoked(
    dir: &Path,
    authenticated_account_id: &str,
    expected_desktop_id: &str,
    expected_cloud_base: &str,
) -> bool {
    is_enrolled(dir).is_none_or(|record| {
        record.account_id != authenticated_account_id
            || record.device_id != expected_desktop_id
            || record.cloud_base.trim_end_matches('/') != expected_cloud_base.trim_end_matches('/')
    })
}

/// Delete the replaceable enrollment record (device.json). Idempotent — a missing file is Ok. The stable device
/// key and consistency marker may remain for cleanup recovery, but the next explicit fresh-code enrollment
/// releases the retired marker and may bind any account. Daemon-owned PTYs and local projects are untouched.
pub fn remove_record(dir: &Path) -> Result<()> {
    preserve_owner_marker(dir)?;
    let path = record_path(dir);
    match fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(e) => Err(e).with_context(|| format!("remove {path:?}")),
    }
}

/// Compare-and-delete used by an old heartbeat task after a cloud revoke. A
/// delayed 403 for device A must never erase a freshly enrolled device B.
pub fn remove_record_if_device_id(dir: &Path, expected_device_id: &str) -> Result<bool> {
    let _lock = crate::service::LifecycleLock::acquire(dir)
        .context("lock enrollment while applying cloud revoke")?;
    let Some(current) = load_record(dir)? else {
        return Ok(false);
    };
    if current.device_id != expected_device_id {
        return Ok(false);
    }
    remove_record(dir)?;
    Ok(true)
}

fn read_bounded_redeem_body(mut response: reqwest::blocking::Response) -> Result<Vec<u8>> {
    if response
        .content_length()
        .is_some_and(|length| length > MAX_REDEEM_RESPONSE_BYTES as u64)
    {
        anyhow::bail!("enrollment response body exceeds {MAX_REDEEM_RESPONSE_BYTES} bytes");
    }

    let mut body = Vec::new();
    let mut chunk = [0u8; 4 * 1024];
    loop {
        // At the boundary, perform one one-byte read without extending the
        // retained buffer. This distinguishes an exact-boundary body from an
        // oversized chunked body while never retaining more than the cap.
        if body.len() == MAX_REDEEM_RESPONSE_BYTES {
            let read = response
                .read(&mut chunk[..1])
                .context("read enrollment response body")?;
            if read == 0 {
                return Ok(body);
            }
            anyhow::bail!("enrollment response body exceeds {MAX_REDEEM_RESPONSE_BYTES} bytes");
        }

        let available = (MAX_REDEEM_RESPONSE_BYTES - body.len()).min(chunk.len());
        let read = response
            .read(&mut chunk[..available])
            .context("read enrollment response body")?;
        if read == 0 {
            return Ok(body);
        }
        body.try_reserve_exact(read)
            .context("reserve bounded enrollment response body")?;
        body.extend_from_slice(&chunk[..read]);
    }
}

fn require_identity(value: &str, max_bytes: usize, label: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > max_bytes
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'.'))
    {
        anyhow::bail!("{label} is invalid or exceeds {max_bytes} bytes");
    }
    Ok(())
}

fn require_bounded_nonempty(value: &str, max_bytes: usize, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > max_bytes {
        anyhow::bail!("{label} is empty or exceeds {max_bytes} bytes");
    }
    Ok(())
}

fn parse_redeem_success(body: &[u8], expected_public_key: &str) -> Result<DeviceRecord> {
    let response: RedeemSuccessResponse =
        serde_json::from_slice(body).context("parse closed enrollment response")?;
    let device = response.device;

    require_identity(
        &device.device_id,
        MAX_DEVICE_ID_BYTES,
        "enrollment device id",
    )?;
    require_identity(
        &device.account_id,
        MAX_ACCOUNT_ID_BYTES,
        "enrollment account id",
    )?;
    require_bounded_nonempty(
        &device.label,
        MAX_DEVICE_LABEL_BYTES,
        "enrollment device label",
    )?;
    if device.public_key != expected_public_key {
        anyhow::bail!("enrollment response public key does not match this desktop");
    }
    if !matches!(device.kind, RedeemedDeviceKind::Desktop) {
        anyhow::bail!("enrollment response is not for a desktop device");
    }
    if !matches!(
        device.public_key_alg,
        None | Some(RedeemedPublicKeyAlgorithm::Ed25519)
    ) {
        anyhow::bail!("enrollment response has the wrong desktop key algorithm");
    }
    if device.revoked {
        anyhow::bail!("enrollment response returned a revoked desktop");
    }
    if device.created_at_ms > MAX_SAFE_JSON_INTEGER
        || device
            .last_seen_ms
            .is_some_and(|value| value > MAX_SAFE_JSON_INTEGER)
    {
        anyhow::bail!("enrollment response contains an unsafe timestamp");
    }

    let enrollment_authorization = response.enrollment_authorization;
    let _version = enrollment_authorization.version;
    if enrollment_authorization.generation == 0
        || enrollment_authorization.generation > MAX_SAFE_JSON_INTEGER
    {
        anyhow::bail!("enrollment authorization generation is invalid");
    }
    if enrollment_authorization.credential_id != response.passkey.credential_id {
        anyhow::bail!("enrollment authorization does not bind the returned account passkey");
    }

    let passkey = (|passkey: RedeemedPasskey| -> Result<crate::browser_cert::PasskeyPublicKey> {
        require_bounded_nonempty(
            &passkey.spki_b64,
            MAX_PASSKEY_SPKI_B64_BYTES,
            "enrollment passkey public key",
        )?;
        let decoded = B64
            .decode(&passkey.spki_b64)
            .context("enrollment passkey public key is not standard base64")?;
        if decoded.is_empty() || decoded.len() > MAX_PASSKEY_SPKI_B64_BYTES {
            anyhow::bail!("enrollment passkey public key has an invalid decoded length");
        }
        require_bounded_nonempty(
            &passkey.rp_id,
            MAX_PASSKEY_RP_ID_BYTES,
            "enrollment passkey RP id",
        )?;
        if !passkey
            .rp_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'-'))
        {
            anyhow::bail!("enrollment passkey RP id is invalid");
        }
        require_bounded_nonempty(
            &passkey.credential_id,
            MAX_PASSKEY_CREDENTIAL_ID_BYTES,
            "enrollment passkey credential id",
        )?;
        if !passkey
            .credential_id
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-' | b'='))
        {
            anyhow::bail!("enrollment passkey credential id is invalid");
        }
        let alg = match passkey.alg {
            RedeemedPasskeyAlgorithm::Es256 => "es256",
            RedeemedPasskeyAlgorithm::Eddsa => "eddsa",
            RedeemedPasskeyAlgorithm::Rs256 => "rs256",
        };
        Ok(crate::browser_cert::PasskeyPublicKey {
            spki_b64: passkey.spki_b64,
            alg: alg.to_string(),
            rp_id: passkey.rp_id,
        })
    })(response.passkey)?;

    Ok(DeviceRecord {
        device_id: device.device_id,
        account_id: device.account_id,
        cloud_base: String::new(),
        passkey: Some(passkey),
    })
}

fn parse_redeem_error(body: &[u8]) -> &'static str {
    let Ok(response) = serde_json::from_slice::<RedeemErrorResponse>(body) else {
        return "unknown";
    };
    if response.error.is_empty()
        || response.error.len() > MAX_ERROR_CODE_BYTES
        || !response
            .error
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_')
    {
        return "unknown";
    }
    // The caller only needs this value while `response` is alive, but returning
    // a borrowed value would couple it to a local DTO. Keep the public error set
    // closed instead of reflecting arbitrary server text.
    match response.error.as_str() {
        "client_upgrade_required" => "client_upgrade_required",
        "not_found" => "not_found",
        "expired" => "expired",
        "already_redeemed" => "already_redeemed",
        "account_mismatch" => "account_mismatch",
        "passkey_required" => "passkey_required",
        "passkey_changed" => "passkey_changed",
        "authority_revoked" => "authority_revoked",
        "kind_mismatch" => "kind_mismatch",
        "bad_request" => "bad_request",
        "content_blind_violation" => "content_blind_violation",
        "client_source_unavailable" => "client_source_unavailable",
        "rate_limited" => "rate_limited",
        "rate_limit_unavailable" => "rate_limit_unavailable",
        "temporarily_unavailable" => "temporarily_unavailable",
        _ => "unknown",
    }
}

fn classify_redeem_refusal(status: reqwest::StatusCode, body: &[u8]) -> EnrollmentFailureKind {
    use EnrollmentFailureKind as Kind;

    // Without an idempotent redemption receipt, every 5xx is commit-ambiguous:
    // a proxy or service may have lost a success after the code was consumed.
    if status.is_server_error() {
        return Kind::OutcomeUnconfirmed;
    }
    let error = parse_redeem_error(body);
    match (status.as_u16(), error) {
        (409, "not_found" | "expired" | "already_redeemed") => Kind::CodeInvalid,
        (409, "account_mismatch") => Kind::OwnerMismatch,
        (401 | 409, "passkey_required" | "passkey_changed" | "authority_revoked") => {
            Kind::AuthorityStale
        }
        (
            400 | 409 | 422,
            "client_upgrade_required" | "kind_mismatch" | "bad_request" | "content_blind_violation",
        ) => Kind::Incompatible,
        (429, "rate_limited") => Kind::TemporarilyUnavailable,
        _ => Kind::OutcomeUnconfirmed,
    }
}

/// Redeem a short-lived enrollment CODE against the cloud and PERSIST the resulting device record — the single
/// enrollment path shared by the CLI (`enroll`) and the desktop app's "Add Remote" button. Loads/creates the stable
/// device keypair (private key never leaves the machine), uploads only the PUBLIC key to `<cloud>/v1/link/redeem`,
/// and on success writes `device.json` ({device_id, account_id, cloud_base}). The saved record has no expiry — the
/// binding is durable (survives restarts) until revoked/wiped; only the CODE is short-lived (≈5 min, single-use).
///
/// Errors are user-friendly (expired/used/wrong code, network) so callers can surface them directly. `label` names
/// the device in the account's device list (e.g. the hostname).
#[cfg(test)]
fn enroll_with_code(
    dir: &Path,
    cloud_base: &str,
    code: &str,
    label: &str,
) -> std::result::Result<DeviceRecord, EnrollmentFailure> {
    enroll_with_code_with_timeout(dir, cloud_base, code, label, ENROLLMENT_HTTP_TIMEOUT)
}

pub fn enroll_with_code_with_diagnostics(
    dir: &Path,
    cloud_base: &str,
    code: &str,
    label: &str,
    locks: &crate::service::LifecycleLockSet,
    diagnostic_deadline: Option<std::time::Instant>,
) -> std::result::Result<DeviceRecord, EnrollmentFailure> {
    locks
        .require_agent_dir(dir)
        .map_err(|_| EnrollmentFailure::before_request(EnrollmentFailureKind::LocalFailure))?;
    let result =
        enroll_with_code_inner(dir, cloud_base, code, label, locks, ENROLLMENT_HTTP_TIMEOUT);
    if let Err(failure) = result {
        record_enrollment_failure_diagnostic(dir, locks, failure, diagnostic_deadline);
    }
    result
}

#[cfg(test)]
fn enroll_with_code_with_timeout(
    dir: &Path,
    cloud_base: &str,
    code: &str,
    label: &str,
    timeout: std::time::Duration,
) -> std::result::Result<DeviceRecord, EnrollmentFailure> {
    crate::agent_dir::ensure_owned_safe_authority_directory(dir)
        .map_err(|_| EnrollmentFailure::before_request(EnrollmentFailureKind::LocalFailure))?;
    let locks = crate::service::LifecycleLockSet::acquire([dir.to_path_buf()])
        .map_err(|_| EnrollmentFailure::before_request(EnrollmentFailureKind::LocalFailure))?;
    enroll_with_code_inner(dir, cloud_base, code, label, &locks, timeout)
}

fn enroll_with_code_inner(
    dir: &Path,
    cloud_base: &str,
    code: &str,
    label: &str,
    locks: &crate::service::LifecycleLockSet,
    timeout: std::time::Duration,
) -> std::result::Result<DeviceRecord, EnrollmentFailure> {
    let code = normalize_enrollment_code(code)?;
    release_retired_owner_for_reenrollment(dir, locks)
        .map_err(|_| EnrollmentFailure::before_request(EnrollmentFailureKind::LocalFailure))?;
    // One OS profile owns one enrollment environment at a time. A staging build must not silently
    // overwrite a production identity (or vice versa) before the user explicitly removes Remote.
    // Check this before creating a key, consuming the one-time code, or making any network request.
    if let Some(existing) = load_record(dir)
        .map_err(|_| EnrollmentFailure::before_request(EnrollmentFailureKind::LocalFailure))?
    {
        if existing.cloud_base.trim_end_matches('/') != cloud_base.trim_end_matches('/') {
            return Err(EnrollmentFailure::before_request(
                EnrollmentFailureKind::LocalFailure,
            ));
        }
    }
    let owner = load_owner(dir)
        .map_err(|_| EnrollmentFailure::before_request(EnrollmentFailureKind::LocalFailure))?;
    if let Some(owner) = owner.as_ref() {
        if owner.cloud_base != cloud_base.trim_end_matches('/') {
            return Err(EnrollmentFailure::before_request(
                EnrollmentFailureKind::LocalFailure,
            ));
        }
    }
    // Stable device keypair (private 0600, never uploaded) → upload only the PUBLIC key.
    let key = load_or_create_key(dir)
        .map_err(|_| EnrollmentFailure::before_request(EnrollmentFailureKind::LocalFailure))?;
    let public_key = public_key_b64(&key);

    let url = format!("{}/v1/link/redeem", cloud_base.trim_end_matches('/'));
    let body = link_redeem_request_body(
        std::str::from_utf8(&code).expect("validated enrollment code is ASCII"),
        label,
        &public_key,
        owner.as_ref().map(|owner| owner.account_id.as_str()),
    );

    // One-shot blocking HTTPS POST (rustls). Enrollment is rare; not a hot path.
    let client = reqwest::blocking::Client::builder()
        .timeout(timeout)
        // Authority creation is intentionally one-shot. Disable reqwest's
        // transport/protocol retry layer in addition to issuing one explicit
        // POST in this function.
        .retry(reqwest::retry::never())
        // Enrollment codes are authority-bearing and single-use. Never follow a redirect to another
        // origin (or even a mutable same-origin route); the release-bound endpoint must answer directly.
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .map_err(|_| EnrollmentFailure::before_request(EnrollmentFailureKind::LocalFailure))?;
    let resp = client.post(&url).json(&body).send().map_err(|_| {
        EnrollmentFailure::after_request(EnrollmentFailureKind::OutcomeUnconfirmed, false)
    })?;
    let status = resp.status();
    let response_body = read_bounded_redeem_body(resp).map_err(|_| {
        EnrollmentFailure::after_request(EnrollmentFailureKind::OutcomeUnconfirmed, true)
    })?;
    if status != reqwest::StatusCode::CREATED {
        return Err(EnrollmentFailure::after_request(
            classify_redeem_refusal(status, &response_body),
            true,
        ));
    }
    let mut record = parse_redeem_success(&response_body, &public_key).map_err(|_| {
        EnrollmentFailure::after_request(EnrollmentFailureKind::OutcomeUnconfirmed, true)
    })?;
    record.cloud_base = cloud_base.to_string();
    save_record(dir, &record).map_err(|_| {
        EnrollmentFailure::after_request(EnrollmentFailureKind::OutcomeUnconfirmed, true)
    })?;
    Ok(record)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::sync::atomic::{AtomicU64, Ordering};
    use std::thread;
    use std::time::Duration;

    static ENROLLMENT_FIXTURE_SEQUENCE: AtomicU64 = AtomicU64::new(0);

    fn enrollment_test_dir(label: &str) -> PathBuf {
        identity_test_path(format!(
            "hydra-enrollment-{label}-{}-{}",
            std::process::id(),
            ENROLLMENT_FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ))
    }

    fn locked_enrollment_test_dir(label: &str) -> (PathBuf, crate::service::LifecycleLockSet) {
        let dir = enrollment_test_dir(label);
        let _ = fs::remove_dir_all(&dir);
        create_safe_identity_fixture_dir(&dir);
        let locks = crate::service::LifecycleLockSet::acquire([dir.clone()]).unwrap();
        (dir, locks)
    }

    fn read_enrollment_diagnostics(dir: &Path) -> EnrollmentDiagnostics {
        let bytes = fs::read(enrollment_diagnostics_path(dir)).unwrap();
        serde_json::from_slice(&bytes).unwrap()
    }

    #[cfg(unix)]
    fn write_owner_private_test_file(path: &Path, bytes: &[u8]) {
        use std::os::unix::fs::PermissionsExt as _;

        fs::write(path, bytes).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn create_safe_identity_fixture_dir(path: &Path) {
        fs::create_dir_all(path).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(path, fs::Permissions::from_mode(0o700)).unwrap();
        }
    }

    fn identity_test_path(name: String) -> PathBuf {
        fs::canonicalize(std::env::temp_dir()).unwrap().join(name)
    }

    fn read_http_request(stream: &mut TcpStream) -> Vec<u8> {
        stream
            .set_read_timeout(Some(Duration::from_secs(2)))
            .unwrap();
        let mut request = Vec::new();
        let mut buffer = [0u8; 2 * 1024];
        let mut expected = None;
        loop {
            let Ok(read) = stream.read(&mut buffer) else {
                return request;
            };
            if read == 0 {
                return request;
            }
            request.extend_from_slice(&buffer[..read]);
            if expected.is_none() {
                if let Some(header_end) =
                    request.windows(4).position(|window| window == b"\r\n\r\n")
                {
                    let headers = String::from_utf8_lossy(&request[..header_end]);
                    let content_length = headers
                        .lines()
                        .find_map(|line| {
                            let (name, value) = line.split_once(':')?;
                            name.eq_ignore_ascii_case("content-length")
                                .then(|| value.trim().parse::<usize>().ok())
                                .flatten()
                        })
                        .unwrap_or(0);
                    expected = Some(header_end + 4 + content_length);
                }
            }
            if expected.is_some_and(|length| request.len() >= length) {
                return request;
            }
        }
    }

    fn serve_redeem_response(
        body: Vec<u8>,
        declared_content_length: Option<usize>,
        chunked: bool,
        chunk_size: usize,
        delay: Duration,
    ) -> (String, thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let _request = read_http_request(&mut stream);
            if chunked {
                if stream
                    .write_all(
                        b"HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n",
                    )
                    .is_err()
                {
                    return;
                }
                for part in body.chunks(chunk_size.max(1)) {
                    if write!(stream, "{:X}\r\n", part.len()).is_err()
                        || stream.write_all(part).is_err()
                        || stream.write_all(b"\r\n").is_err()
                        || stream.flush().is_err()
                    {
                        return;
                    }
                    if !delay.is_zero() {
                        thread::sleep(delay);
                    }
                }
                let _ = stream.write_all(b"0\r\n\r\n");
            } else {
                let length = declared_content_length.unwrap_or(body.len());
                if write!(
                    stream,
                    "HTTP/1.1 201 Created\r\nContent-Type: application/json\r\nContent-Length: {length}\r\nConnection: close\r\n\r\n"
                )
                .is_err()
                {
                    return;
                }
                for part in body.chunks(chunk_size.max(1)) {
                    if stream.write_all(part).is_err() || stream.flush().is_err() {
                        return;
                    }
                    if !delay.is_zero() {
                        thread::sleep(delay);
                    }
                }
            }
        });
        (format!("http://{address}"), handle)
    }

    fn serve_redeem_exchange(
        status: &'static str,
        body: Vec<u8>,
    ) -> (String, thread::JoinHandle<Vec<u8>>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            request
        });
        (format!("http://{address}"), handle)
    }

    fn serve_one_redeem_exchange_and_count_connections(
        status: &'static str,
        body: Vec<u8>,
    ) -> (String, thread::JoinHandle<(Vec<u8>, usize)>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap();
        let handle = thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            write!(
                stream,
                "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
                body.len()
            )
            .unwrap();
            stream.write_all(&body).unwrap();
            drop(stream);

            listener.set_nonblocking(true).unwrap();
            let deadline = std::time::Instant::now() + Duration::from_millis(250);
            let mut connections = 1;
            while std::time::Instant::now() < deadline {
                match listener.accept() {
                    Ok((mut retry, _)) => {
                        connections += 1;
                        let _ = read_http_request(&mut retry);
                    }
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("accept retry probe: {error}"),
                }
            }
            (request, connections)
        });
        (format!("http://{address}"), handle)
    }

    fn request_json(request: &[u8]) -> serde_json::Value {
        let body_offset = request
            .windows(4)
            .position(|window| window == b"\r\n\r\n")
            .expect("HTTP request has a header terminator")
            + 4;
        serde_json::from_slice(&request[body_offset..]).unwrap()
    }

    fn valid_redeem_value(
        public_key: &str,
        device_id: &str,
        account_id: &str,
    ) -> serde_json::Value {
        serde_json::json!({
            "device": {
                "deviceId": device_id,
                "accountId": account_id,
                "label": "test desktop",
                "publicKey": public_key,
                "kind": "desktop",
                "createdAtMs": 1_786_000_000_000u64,
                "revoked": false
            },
            "passkey": {
                "spki_b64": B64.encode([0x30u8, 0x00]),
                "alg": "es256",
                "rp_id": "hydraterms.com",
                "credential_id": "Y3JlZGVudGlhbA"
            },
            "enrollment_authorization": {
                "version": "passkey-uv-v1",
                "credential_id": "Y3JlZGVudGlhbA",
                "generation": 1
            }
        })
    }

    fn assert_failed_enrollment_writes_no_record(
        label: &str,
        body_for_key: impl FnOnce(&str) -> Vec<u8>,
        declared_content_length: Option<usize>,
        chunked: bool,
    ) -> EnrollmentFailureKind {
        let dir = enrollment_test_dir(label);
        let _ = fs::remove_dir_all(&dir);
        let key = load_or_create_key(&dir).unwrap();
        let body = body_for_key(&public_key_b64(&key));
        let (cloud, server) =
            serve_redeem_response(body, declared_content_length, chunked, 1024, Duration::ZERO);
        let error = enroll_with_code(&dir, &cloud, "A2B3C4D5", "test desktop").unwrap_err();
        server.join().unwrap();
        assert!(
            load_record(&dir).unwrap().is_none(),
            "hostile enrollment response must not create device.json"
        );
        let kind = error.kind();
        let _ = fs::remove_dir_all(&dir);
        kind
    }

    #[test]
    fn key_is_stable_across_loads_and_pubkey_is_32_bytes() {
        let dir = identity_test_path(format!("hydra-devid-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let k1 = load_or_create_key(&dir).unwrap();
        let k2 = load_or_create_key(&dir).unwrap(); // same key on second load (stable)
        assert_eq!(k1.to_bytes(), k2.to_bytes());
        let pub_b64 = public_key_b64(&k1);
        assert_eq!(B64.decode(&pub_b64).unwrap().len(), 32);
        // the PUBLIC b64 must NOT equal the private seed b64 (we never upload the seed)
        let seed_b64 = fs::read_to_string(dir.join(KEY_FILE)).unwrap();
        assert_ne!(pub_b64, seed_b64.trim());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn delayed_revoke_cannot_delete_a_newer_enrollment() {
        let dir = identity_test_path(format!("hydra-devid-cas-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let newer = DeviceRecord {
            device_id: "device-b".to_string(),
            account_id: "account".to_string(),
            cloud_base: "https://example.invalid".to_string(),
            passkey: None,
        };
        save_record(&dir, &newer).unwrap();
        assert!(!remove_record_if_device_id(&dir, "device-a").unwrap());
        assert_eq!(load_record(&dir).unwrap().unwrap().device_id, "device-b");
        assert!(remove_record_if_device_id(&dir, "device-b").unwrap());
        assert!(load_record(&dir).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn link_redeem_advertises_every_passkey_verifier_the_agent_implements() {
        let body =
            serde_json::to_value(link_redeem_request_body("CODE", "desktop", "PUBLIC", None))
                .unwrap();
        assert_eq!(
            body.get("supportedPasskeyAlgorithms").unwrap(),
            &serde_json::json!(["es256", "eddsa", "rs256"])
        );
        assert_eq!(
            body.get("supportedEnrollmentAuthorizationVersions")
                .unwrap(),
            &serde_json::json!(["passkey-uv-v1"])
        );
        assert_eq!(body.get("kind").and_then(|v| v.as_str()), Some("desktop"));
    }

    #[cfg(unix)]
    #[test]
    fn private_key_file_is_0600() {
        use std::os::unix::fs::PermissionsExt;
        let dir = identity_test_path(format!("hydra-devid-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        load_or_create_key(&dir).unwrap();
        let mode = fs::metadata(dir.join(KEY_FILE))
            .unwrap()
            .permissions()
            .mode()
            & 0o777;
        assert_eq!(mode, 0o600);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn enrollment_files_are_owner_only_from_first_publish() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = identity_test_path(format!("hydra-private-enrollment-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let record = DeviceRecord {
            device_id: "dev_private".into(),
            account_id: "acct_private".into(),
            cloud_base: "https://api.hydraterms.com".into(),
            passkey: None,
        };
        save_record(&dir, &record).unwrap();

        for path in [record_path(&dir), owner_path(&dir)] {
            let mode = fs::metadata(path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn private_identity_paths_reject_symlinks() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};

        let root =
            std::env::temp_dir().join(format!("hydra-private-symlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();

        let key_dir = root.join("key");
        fs::create_dir_all(&key_dir).unwrap();
        let key_target = root.join("key-target");
        fs::write(&key_target, B64.encode([7u8; 32])).unwrap();
        fs::set_permissions(&key_target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&key_target, key_dir.join(KEY_FILE)).unwrap();
        assert!(load_or_create_key(&key_dir).is_err());

        let record_dir = root.join("record");
        fs::create_dir_all(&record_dir).unwrap();
        let record_target = root.join("record-target");
        fs::write(
            &record_target,
            serde_json::to_vec(&DeviceRecord {
                device_id: "dev".into(),
                account_id: "acct".into(),
                cloud_base: "https://api.hydraterms.com".into(),
                passkey: None,
            })
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&record_target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&record_target, record_path(&record_dir)).unwrap();
        assert!(load_record(&record_dir).is_err());

        let owner_dir = root.join("owner");
        fs::create_dir_all(&owner_dir).unwrap();
        let owner_target = root.join("owner-target");
        fs::write(
            &owner_target,
            serde_json::to_vec(&DeviceOwner {
                version: 1,
                account_id: "acct".into(),
                cloud_base: "https://api.hydraterms.com".into(),
            })
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&owner_target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&owner_target, owner_path(&owner_dir)).unwrap();
        assert!(load_owner(&owner_dir).is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn private_identity_paths_reject_group_or_world_access() {
        use std::os::unix::fs::PermissionsExt as _;

        let root = std::env::temp_dir().join(format!("hydra-private-mode-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let key_dir = root.join("key");
        fs::create_dir_all(&key_dir).unwrap();
        fs::write(key_dir.join(KEY_FILE), B64.encode([9u8; 32])).unwrap();
        fs::set_permissions(key_dir.join(KEY_FILE), fs::Permissions::from_mode(0o640)).unwrap();
        assert!(load_or_create_key(&key_dir).is_err());

        let record_dir = root.join("record");
        fs::create_dir_all(&record_dir).unwrap();
        fs::write(record_path(&record_dir), b"{}").unwrap();
        fs::set_permissions(record_path(&record_dir), fs::Permissions::from_mode(0o604)).unwrap();
        assert!(load_record(&record_dir).is_err());

        let owner_dir = root.join("owner");
        fs::create_dir_all(&owner_dir).unwrap();
        fs::write(owner_path(&owner_dir), b"{}").unwrap();
        fs::set_permissions(owner_path(&owner_dir), fs::Permissions::from_mode(0o660)).unwrap();
        assert!(load_owner(&owner_dir).is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn private_identity_paths_must_be_regular_files() {
        let root =
            std::env::temp_dir().join(format!("hydra-private-regular-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let key_dir = root.join("key");
        fs::create_dir_all(key_dir.join(KEY_FILE)).unwrap();
        assert!(load_or_create_key(&key_dir).is_err());

        let record_dir = root.join("record");
        fs::create_dir_all(record_path(&record_dir)).unwrap();
        assert!(load_record(&record_dir).is_err());

        let owner_dir = root.join("owner");
        fs::create_dir_all(owner_path(&owner_dir)).unwrap();
        assert!(load_owner(&owner_dir).is_err());

        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn private_identity_file_rejects_a_mismatched_owner_uid() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::env::temp_dir().join(format!("hydra-private-owner-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("owned-file");
        fs::write(&path, b"private").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let file = fs::File::open(path).unwrap();
        let actual_uid = unsafe { libc::geteuid() };
        let foreign_uid = actual_uid.wrapping_add(1);
        let error = validate_private_file_for_uid(&file, "owned-file", foreign_uid).unwrap_err();
        assert!(error.to_string().contains("does not match process uid"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn private_identity_files_reject_hard_links() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = identity_test_path(format!("hydra-private-hardlink-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        create_safe_identity_fixture_dir(&dir);
        let key_path = dir.join(KEY_FILE);
        fs::write(&key_path, B64.encode([5u8; 32])).unwrap();
        fs::set_permissions(&key_path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&key_path, dir.join("device-key-alias")).unwrap();

        let error = load_key(&dir).unwrap_err();
        assert!(error.to_string().contains("hard links"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn owner_publication_recovers_only_the_exact_post_link_crash_shape() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let dir = fs::canonicalize(root.path()).unwrap().join("hydra-agent");
        crate::agent_dir::ensure_owned_safe_authority_directory(&dir).unwrap();
        let owner = DeviceOwner {
            version: 1,
            account_id: "acct_synthetic".into(),
            cloud_base: "https://api.hydraterms.com".into(),
        };
        let bytes = serde_json::to_vec_pretty(&owner).unwrap();
        let temporary = dir.join(".device-owner.json.tmp.4242.7");
        fs::write(&temporary, &bytes).unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&temporary, owner_path(&dir)).unwrap();
        assert_eq!(fs::metadata(owner_path(&dir)).unwrap().nlink(), 2);

        assert_eq!(load_owner(&dir).unwrap(), Some(owner));
        assert!(!temporary.exists());
        assert_eq!(fs::metadata(owner_path(&dir)).unwrap().nlink(), 1);

        fs::remove_file(owner_path(&dir)).unwrap();
        let wrong_alias = dir.join("not-an-owner-publication-temp");
        fs::write(&wrong_alias, &bytes).unwrap();
        fs::set_permissions(&wrong_alias, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&wrong_alias, owner_path(&dir)).unwrap();
        assert!(load_owner(&dir).is_err());
        assert!(wrong_alias.exists(), "non-exact aliases are never removed");
        assert_eq!(fs::metadata(owner_path(&dir)).unwrap().nlink(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn owner_publication_recovery_rejects_unsafe_parent_without_unlinking() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().unwrap();
        let dir = fs::canonicalize(root.path())
            .unwrap()
            .join("unsafe-hydra-agent");
        fs::create_dir(&dir).unwrap();
        fs::set_permissions(&dir, fs::Permissions::from_mode(0o777)).unwrap();
        let owner = DeviceOwner {
            version: 1,
            account_id: "acct_synthetic".into(),
            cloud_base: "https://api.hydraterms.com".into(),
        };
        let temporary = dir.join(".device-owner.json.tmp.4242.8");
        fs::write(&temporary, serde_json::to_vec_pretty(&owner).unwrap()).unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&temporary, owner_path(&dir)).unwrap();

        assert!(load_owner(&dir).is_err());
        assert!(temporary.exists());
        assert_eq!(fs::metadata(owner_path(&dir)).unwrap().nlink(), 2);
    }

    #[cfg(unix)]
    #[test]
    fn owner_publication_recovery_rejects_oversized_exact_nlink_two_shape() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let dir = fs::canonicalize(root.path()).unwrap().join("hydra-agent");
        crate::agent_dir::ensure_owned_safe_authority_directory(&dir).unwrap();
        let temporary = dir.join(".device-owner.json.tmp.4242.9");
        fs::write(&temporary, vec![b'x'; MAX_OWNER_FILE_BYTES + 1]).unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&temporary, owner_path(&dir)).unwrap();

        let error = load_owner(&dir).unwrap_err();
        assert!(error.to_string().contains("exceeds its byte bound"));
        assert!(temporary.exists());
        assert_eq!(fs::metadata(owner_path(&dir)).unwrap().nlink(), 2);
    }

    #[test]
    fn record_roundtrips() {
        let dir = identity_test_path(format!("hydra-rec-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        create_safe_identity_fixture_dir(&dir);
        assert!(load_record(&dir).unwrap().is_none());
        let rec = DeviceRecord {
            device_id: "dev_x".into(),
            account_id: "acct_y".into(),
            cloud_base: "https://api".into(),
            passkey: None,
        };
        save_record(&dir, &rec).unwrap();
        let got = load_record(&dir).unwrap().unwrap();
        assert_eq!(got.device_id, "dev_x");
        assert_eq!(got.account_id, "acct_y");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn is_enrolled_reflects_device_json() {
        let dir = identity_test_path(format!("hydra-enrolled-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        create_safe_identity_fixture_dir(&dir);
        // no device.json → not enrolled
        assert!(is_enrolled(&dir).is_none());
        save_record(
            &dir,
            &DeviceRecord {
                device_id: "dev_1".into(),
                account_id: "acct_1".into(),
                cloud_base: "https://api".into(),
                passkey: None,
            },
        )
        .unwrap();
        let rec = is_enrolled(&dir).expect("enrolled after save");
        assert_eq!(rec.account_id, "acct_1");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn live_binding_revokes_missing_corrupt_or_replaced_enrollment() {
        let dir = identity_test_path(format!(
            "hydra-live-binding-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        create_safe_identity_fixture_dir(&dir);
        let revoked = || {
            enrollment_binding_is_revoked(
                &dir,
                "acct_expected",
                "dev_expected",
                "https://api.example",
            )
        };

        assert!(revoked(), "missing record must revoke");
        fs::write(record_path(&dir), b"not-json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(record_path(&dir), fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(revoked(), "corrupt record must revoke");
        fs::remove_file(record_path(&dir)).unwrap();

        let exact = DeviceRecord {
            device_id: "dev_expected".into(),
            account_id: "acct_expected".into(),
            cloud_base: "https://api.example/".into(),
            passkey: None,
        };
        save_record(&dir, &exact).unwrap();
        assert!(!revoked(), "exact live binding must stay authorized");

        for changed in [
            DeviceRecord {
                device_id: "dev_other".into(),
                ..exact.clone()
            },
            DeviceRecord {
                account_id: "acct_other".into(),
                ..exact.clone()
            },
            DeviceRecord {
                cloud_base: "https://other.example".into(),
                ..exact.clone()
            },
        ] {
            // Simulate hostile/on-disk replacement after the durable owner has been established. The normal
            // save path correctly refuses cross-account/cloud replacement, so this test deliberately exercises
            // the live channel's independent fail-closed binding check without weakening that write boundary.
            write_private_json(&dir, RECORD_FILE, "device.json", &changed).unwrap();
            assert!(revoked(), "every replaced binding field must revoke");
        }
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn remove_record_clears_enrollment_and_is_idempotent() {
        let dir = identity_test_path(format!("hydra-remove-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        create_safe_identity_fixture_dir(&dir);
        // removing when nothing exists is Ok (idempotent)
        remove_record(&dir).unwrap();
        save_record(
            &dir,
            &DeviceRecord {
                device_id: "dev_1".into(),
                account_id: "acct_1".into(),
                cloud_base: "https://api".into(),
                passkey: None,
            },
        )
        .unwrap();
        assert!(is_enrolled(&dir).is_some());
        remove_record(&dir).unwrap();
        assert!(
            is_enrolled(&dir).is_none(),
            "device.json cleared → not enrolled"
        );
        assert_eq!(load_owner(&dir).unwrap().unwrap().account_id, "acct_1");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn raw_record_save_cannot_bypass_explicit_fresh_code_rebind() {
        let dir = identity_test_path(format!("hydra-owner-transfer-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = DeviceRecord {
            device_id: "dev_a".into(),
            account_id: "acct_a".into(),
            cloud_base: "https://api.hydraterms.com/".into(),
            passkey: None,
        };
        save_record(&dir, &first).unwrap();
        remove_record(&dir).unwrap();

        let replacement = DeviceRecord {
            device_id: "dev_b".into(),
            account_id: "acct_b".into(),
            cloud_base: "https://api.hydraterms.com".into(),
            passkey: None,
        };
        let error = save_record(&dir, &replacement).unwrap_err();
        assert!(error
            .to_string()
            .contains("requires an explicit fresh-code enrollment"));
        assert!(load_record(&dir).unwrap().is_none());
        assert_eq!(load_owner(&dir).unwrap().unwrap().account_id, "acct_a");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn removed_enrollment_can_be_reissued_to_the_same_owner() {
        let dir = identity_test_path(format!("hydra-owner-reissue-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let first = DeviceRecord {
            device_id: "dev_a".into(),
            account_id: "acct_a".into(),
            cloud_base: "https://api.hydraterms.com".into(),
            passkey: None,
        };
        save_record(&dir, &first).unwrap();
        remove_record(&dir).unwrap();
        let replacement = DeviceRecord {
            device_id: "dev_a2".into(),
            ..first
        };
        save_record(&dir, &replacement).unwrap();
        assert_eq!(load_record(&dir).unwrap().unwrap().device_id, "dev_a2");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_record_is_backfilled_before_removal() {
        let dir = identity_test_path(format!("hydra-owner-backfill-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        create_safe_identity_fixture_dir(&dir);
        let legacy = DeviceRecord {
            device_id: "dev_legacy".into(),
            account_id: "acct_legacy".into(),
            cloud_base: "https://api.hydraterms.com".into(),
            passkey: None,
        };
        fs::write(record_path(&dir), serde_json::to_vec(&legacy).unwrap()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(record_path(&dir), fs::Permissions::from_mode(0o600)).unwrap();
        }
        assert!(!owner_path(&dir).exists());

        remove_record(&dir).unwrap();

        assert!(load_record(&dir).unwrap().is_none());
        assert_eq!(load_owner(&dir).unwrap().unwrap().account_id, "acct_legacy");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn malformed_owner_marker_fails_closed() {
        let dir = identity_test_path(format!("hydra-owner-corrupt-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        create_safe_identity_fixture_dir(&dir);
        fs::write(owner_path(&dir), b"not-json").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(owner_path(&dir), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let candidate = DeviceRecord {
            device_id: "dev_new".into(),
            account_id: "acct_new".into(),
            cloud_base: "https://api.hydraterms.com".into(),
            passkey: None,
        };
        assert!(save_record(&dir, &candidate).is_err());
        assert!(load_record(&dir).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enrollment_failure_is_closed_redacted_and_writes_no_record() {
        // Point at an unroutable address so the POST fails fast (no live cloud in unit tests). The keypair may be
        // created (that's local + harmless), but NO device.json must be written on failure.
        let dir = identity_test_path(format!("hydra-enroll-fail-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        // 127.0.0.1:1 — nothing listens; connection refused quickly.
        let err = enroll_with_code(&dir, "http://127.0.0.1:1", "A2B3C4D5", "test-mac").unwrap_err();
        assert_eq!(err.kind(), EnrollmentFailureKind::OutcomeUnconfirmed);
        for projection in [format!("{err}"), format!("{err:?}")] {
            for forbidden in [
                "A2B3C4D5",
                "test-mac",
                "http://127.0.0.1:1",
                "raw-server-body",
            ] {
                assert!(
                    !projection.contains(forbidden),
                    "closed enrollment failure leaked {forbidden:?}: {projection}"
                );
            }
        }
        // crucially: enrollment did NOT persist a record on failure
        assert!(
            load_record(&dir).unwrap().is_none(),
            "no device.json on failed enroll"
        );
        assert!(is_enrolled(&dir).is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn enrollment_code_normalization_stays_zeroizing_and_request_borrowed() {
        fn require_zeroizing_bytes(_: &Zeroizing<Vec<u8>>) {}

        let normalized = normalize_enrollment_code("a2b3c4d5\r\n").unwrap();
        require_zeroizing_bytes(&normalized);
        assert_eq!(normalized.as_slice(), b"A2B3C4D5");
        let borrowed = std::str::from_utf8(&normalized).unwrap();
        let request = link_redeem_request_body(borrowed, "desktop", "PUBLIC", None);
        assert_eq!(request.code.as_ptr(), borrowed.as_ptr());

        let source = include_str!("device_identity.rs");
        assert!(source.contains("let code = normalize_enrollment_code(code)?;"));
        let forbidden_owned_dto = ["maestro_extension_api::EnrollmentCode::", "new(code)"].concat();
        assert!(!source.contains(&forbidden_owned_dto));
    }

    #[test]
    fn private_monorepo_cloud_issuer_and_parser_match_the_shared_code_grammar() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .expect("hydra-agent has a repository parent");
        let cloud = root.join("hydra-cloud");
        let issuer_path = cloud.join("src/domain/passkey-webauthn.ts");
        let handler_path = cloud.join("src/api/handler.ts");
        if !issuer_path.exists() && !handler_path.exists() {
            // Public transport packages can share the cloud directory without
            // the hosted issuer/routes. Local grammar tests remain mandatory;
            // this cross-language parity check needs both private sources.
            return;
        }
        assert!(
            issuer_path.is_file() && handler_path.is_file(),
            "private grammar parity requires both source files"
        );
        let issuer = fs::read_to_string(issuer_path).expect("read private TypeScript issuer");
        let issuer_alphabet = issuer
            .split_once("const alphabet = '")
            .and_then(|(_, tail)| tail.split_once('\''))
            .map(|(alphabet, _)| alphabet)
            .expect("TypeScript issuer alphabet remains structurally visible");
        assert_eq!(
            issuer_alphabet,
            maestro_extension_api::ENROLLMENT_CODE_ALPHABET
        );

        let handler = fs::read_to_string(handler_path).expect("read private TypeScript link route");
        let class = handler
            .split_once("if (!/^[")
            .and_then(|(_, tail)| tail.split_once("]{8}$/.test(code))"))
            .map(|(class, _)| class)
            .expect("TypeScript route code grammar remains structurally visible");
        let mut expanded = String::new();
        let mut bytes = class.bytes().peekable();
        while let Some(byte) = bytes.next() {
            if bytes.peek() == Some(&b'-') {
                bytes.next();
                let end = bytes.next().expect("route range has an end");
                expanded.extend((byte..=end).map(char::from));
            } else {
                expanded.push(char::from(byte));
            }
        }
        assert_eq!(expanded, maestro_extension_api::ENROLLMENT_CODE_ALPHABET);
    }

    #[test]
    fn explicit_reenrollment_releases_retired_owner_and_omits_account_expectation() {
        let dir = enrollment_test_dir("expected-owner");
        let _ = fs::remove_dir_all(&dir);
        let key = load_or_create_key(&dir).unwrap();
        let key_bytes = fs::read(dir.join(KEY_FILE)).unwrap();
        let public_key = public_key_b64(&key);
        let response = serde_json::to_vec(&valid_redeem_value(
            &public_key,
            "dev_reissued",
            "acct_replacement",
        ))
        .unwrap();
        let (cloud, server) = serve_redeem_exchange("201 Created", response);
        save_record(
            &dir,
            &DeviceRecord {
                device_id: "dev_previous".into(),
                account_id: "acct_owner".into(),
                cloud_base: cloud.clone(),
                passkey: None,
            },
        )
        .unwrap();
        remove_record(&dir).unwrap();

        let record = enroll_with_code(&dir, &cloud, "a2b3c4d5\r\n", "test desktop").unwrap();
        let request = request_json(&server.join().unwrap());
        assert!(request.get("expectedAccountId").is_none());
        assert_eq!(request["code"], "A2B3C4D5");
        let keys = request
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "code",
                "kind",
                "label",
                "publicKey",
                "supportedEnrollmentAuthorizationVersions",
                "supportedPasskeyAlgorithms",
            ]
        );
        assert_eq!(record.account_id, "acct_replacement");
        assert_eq!(
            fs::read(dir.join(KEY_FILE)).unwrap(),
            key_bytes,
            "account rebind retains the exact private-key file bytes"
        );
        assert_eq!(
            load_owner(&dir).unwrap().unwrap().account_id,
            "acct_replacement"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn invalid_fresh_code_leaves_retired_owner_exactly_untouched() {
        use std::os::unix::fs::MetadataExt as _;

        let dir = enrollment_test_dir("invalid-code-retains-owner");
        let _ = fs::remove_dir_all(&dir);
        save_record(
            &dir,
            &DeviceRecord {
                device_id: "dev_previous".into(),
                account_id: "acct_previous".into(),
                cloud_base: "https://api.hydraterms.com".into(),
                passkey: None,
            },
        )
        .unwrap();
        remove_record(&dir).unwrap();
        let path = owner_path(&dir);
        let bytes = fs::read(&path).unwrap();
        let metadata = fs::metadata(&path).unwrap();

        let error =
            enroll_with_code(&dir, "http://127.0.0.1:1", "INVALID", "test desktop").unwrap_err();

        assert_eq!(error.kind(), EnrollmentFailureKind::CodeInvalid);
        let after = fs::metadata(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!((after.dev(), after.ino()), (metadata.dev(), metadata.ino()));
        assert!(load_record(&dir).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn active_enrollment_keeps_owner_inode_and_bytes_during_release_probe() {
        use std::os::unix::fs::MetadataExt as _;

        let (dir, locks) = locked_enrollment_test_dir("active-owner-release-probe");
        save_record(
            &dir,
            &DeviceRecord {
                device_id: "dev_active".into(),
                account_id: "acct_active".into(),
                cloud_base: "https://api.hydraterms.com".into(),
                passkey: None,
            },
        )
        .unwrap();
        let path = owner_path(&dir);
        let bytes = fs::read(&path).unwrap();
        let metadata = fs::metadata(&path).unwrap();

        release_retired_owner_for_reenrollment(&dir, &locks).unwrap();

        let after = fs::metadata(&path).unwrap();
        assert_eq!(fs::read(&path).unwrap(), bytes);
        assert_eq!((after.dev(), after.ino()), (metadata.dev(), metadata.ino()));
        assert_eq!(load_record(&dir).unwrap().unwrap().device_id, "dev_active");
        drop(locks);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn failed_rebind_releases_only_retired_owner_and_preserves_key_and_local_state() {
        let dir = enrollment_test_dir("failed-rebind-local-state");
        let _ = fs::remove_dir_all(&dir);
        let key = load_or_create_key(&dir).unwrap();
        let key_bytes = fs::read(dir.join(KEY_FILE)).unwrap();
        let sentinel = dir.join("retained-local-state.sentinel");
        fs::write(&sentinel, b"local-projects-and-ptys-stay-owned-locally").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
        }
        save_record(
            &dir,
            &DeviceRecord {
                device_id: "dev_previous".into(),
                account_id: "acct_previous".into(),
                cloud_base: "http://127.0.0.1:1".into(),
                passkey: None,
            },
        )
        .unwrap();
        remove_record(&dir).unwrap();

        let error =
            enroll_with_code(&dir, "http://127.0.0.1:1", "A2B3C4D5", "test desktop").unwrap_err();

        assert_eq!(error.kind(), EnrollmentFailureKind::OutcomeUnconfirmed);
        assert!(load_owner(&dir).unwrap().is_none());
        assert!(load_record(&dir).unwrap().is_none());
        assert_eq!(fs::read(dir.join(KEY_FILE)).unwrap(), key_bytes);
        assert_eq!(load_key(&dir).unwrap().unwrap().to_bytes(), key.to_bytes());
        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"local-projects-and-ptys-stay-owned-locally"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn retired_owner_release_recovers_exact_publication_then_removes_both_names() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let (dir, locks) = locked_enrollment_test_dir("owner-release-publication-recovery");
        let owner = DeviceOwner {
            version: 1,
            account_id: "acct_retired".into(),
            cloud_base: "https://api.hydraterms.com".into(),
        };
        let bytes = serde_json::to_vec_pretty(&owner).unwrap();
        let temporary = dir.join(".device-owner.json.tmp.4242.99");
        fs::write(&temporary, bytes).unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&temporary, owner_path(&dir)).unwrap();
        assert_eq!(fs::metadata(owner_path(&dir)).unwrap().nlink(), 2);

        release_retired_owner_for_reenrollment(&dir, &locks).unwrap();

        assert!(!temporary.exists());
        assert!(!owner_path(&dir).exists());
        drop(locks);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn retired_owner_release_refuses_unsafe_bindings_without_mutating_them() {
        use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

        let (hardlink_dir, hardlink_locks) = locked_enrollment_test_dir("owner-release-hardlink");
        let hardlink_path = owner_path(&hardlink_dir);
        write_owner_private_test_file(&hardlink_path, b"retired-owner");
        let hardlink_alias = hardlink_dir.join("unrelated-owner-alias");
        fs::hard_link(&hardlink_path, &hardlink_alias).unwrap();
        assert!(release_retired_owner_for_reenrollment(&hardlink_dir, &hardlink_locks).is_err());
        assert_eq!(fs::metadata(&hardlink_path).unwrap().nlink(), 2);
        assert_eq!(fs::read(&hardlink_path).unwrap(), b"retired-owner");
        assert_eq!(fs::read(&hardlink_alias).unwrap(), b"retired-owner");
        drop(hardlink_locks);
        let _ = fs::remove_dir_all(&hardlink_dir);

        let (symlink_dir, symlink_locks) = locked_enrollment_test_dir("owner-release-symlink");
        let symlink_target = symlink_dir.join("owner-target");
        write_owner_private_test_file(&symlink_target, b"symlink-target");
        symlink(&symlink_target, owner_path(&symlink_dir)).unwrap();
        assert!(release_retired_owner_for_reenrollment(&symlink_dir, &symlink_locks).is_err());
        assert!(fs::symlink_metadata(owner_path(&symlink_dir))
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&symlink_target).unwrap(), b"symlink-target");
        drop(symlink_locks);
        let _ = fs::remove_dir_all(&symlink_dir);

        let (loose_dir, loose_locks) = locked_enrollment_test_dir("owner-release-loose-mode");
        let loose_path = owner_path(&loose_dir);
        write_owner_private_test_file(&loose_path, b"loose-owner");
        fs::set_permissions(&loose_path, fs::Permissions::from_mode(0o640)).unwrap();
        let before = fs::metadata(&loose_path).unwrap();
        assert!(release_retired_owner_for_reenrollment(&loose_dir, &loose_locks).is_err());
        let after = fs::metadata(&loose_path).unwrap();
        assert_eq!(fs::read(&loose_path).unwrap(), b"loose-owner");
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.permissions().mode() & 0o777, 0o640);
        drop(loose_locks);
        let _ = fs::remove_dir_all(&loose_dir);
    }

    #[test]
    fn explicit_reenrollment_replaces_legacy_owner_without_touching_local_state_or_key() {
        let dir = enrollment_test_dir("legacy-owner-rebind");
        let _ = fs::remove_dir_all(&dir);
        let key = load_or_create_key(&dir).unwrap();
        let public_key = public_key_b64(&key);
        let sentinel = dir.join("retained-local-state.sentinel");
        fs::write(&sentinel, b"local-projects-and-ptys-stay-owned-locally").unwrap();
        fs::write(owner_path(&dir), b"retired-owner-format").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
            fs::set_permissions(owner_path(&dir), fs::Permissions::from_mode(0o600)).unwrap();
        }
        let response = serde_json::to_vec(&valid_redeem_value(
            &public_key,
            "dev_new_owner",
            "acct_new_owner",
        ))
        .unwrap();
        let (cloud, server) = serve_redeem_exchange("201 Created", response);

        let record = enroll_with_code(&dir, &cloud, "A2B3C4D5", "test desktop").unwrap();
        let request = request_json(&server.join().unwrap());
        assert!(request.get("expectedAccountId").is_none());
        assert_eq!(record.account_id, "acct_new_owner");
        assert_eq!(
            fs::read(&sentinel).unwrap(),
            b"local-projects-and-ptys-stay-owned-locally"
        );
        assert_eq!(
            public_key_b64(&load_key(&dir).unwrap().unwrap()),
            public_key,
            "account rebind retains the desktop key and unrelated local state"
        );
        assert_eq!(
            load_owner(&dir).unwrap().unwrap().account_id,
            "acct_new_owner"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn legacy_cloud_account_mismatch_is_closed_without_restoring_retired_owner() {
        let dir = enrollment_test_dir("account-mismatch");
        let _ = fs::remove_dir_all(&dir);
        let (cloud, server) =
            serve_redeem_exchange("409 Conflict", br#"{"error":"account_mismatch"}"#.to_vec());
        save_record(
            &dir,
            &DeviceRecord {
                device_id: "dev_previous".into(),
                account_id: "acct_owner".into(),
                cloud_base: cloud.clone(),
                passkey: None,
            },
        )
        .unwrap();
        remove_record(&dir).unwrap();

        let error = enroll_with_code(&dir, &cloud, "A2B3C4D5", "test desktop").unwrap_err();
        let request = request_json(&server.join().unwrap());
        assert!(request.get("expectedAccountId").is_none());
        assert_eq!(error.kind(), EnrollmentFailureKind::OwnerMismatch);
        for projection in [format!("{error}"), format!("{error:?}")] {
            assert!(!projection.contains("A2B3C4D5"));
            assert!(!projection.contains("test desktop"));
            assert!(!projection.contains(&cloud));
        }
        assert!(load_record(&dir).unwrap().is_none());
        assert!(load_owner(&dir).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn unknown_refusal_body_is_unconfirmed_and_never_reflected_or_persisted() {
        let (dir, locks) = locked_enrollment_test_dir("unknown-refusal-redaction");
        let (cloud, server) = serve_redeem_exchange(
            "409 Conflict",
            br#"{"error":"account_mismatch","detail":"raw-server-body"}"#.to_vec(),
        );
        let error = enroll_with_code_with_diagnostics(
            &dir,
            &cloud,
            "A2B3C4D5",
            "secret-label",
            &locks,
            None,
        )
        .unwrap_err();
        server.join().unwrap();
        assert_eq!(error.kind(), EnrollmentFailureKind::OutcomeUnconfirmed);
        for projection in [format!("{error}"), format!("{error:?}")] {
            for forbidden in [
                "A2B3C4D5",
                "secret-label",
                cloud.as_str(),
                "raw-server-body",
            ] {
                assert!(!projection.contains(forbidden));
            }
        }
        let encoded = fs::read_to_string(enrollment_diagnostics_path(&dir)).unwrap();
        for forbidden in [
            "A2B3C4D5",
            "secret-label",
            cloud.as_str(),
            "raw-server-body",
        ] {
            assert!(!encoded.contains(forbidden));
        }
        let diagnostics = read_enrollment_diagnostics(&dir);
        assert_eq!(diagnostics.events.len(), 1);
        assert_eq!(
            diagnostics.events[0].reason,
            Some(EnrollmentFailureKind::OutcomeUnconfirmed)
        );
        assert_eq!(
            diagnostics.events[0].outcome,
            EnrollmentDiagnosticOutcome::Unconfirmed
        );
        assert!(load_record(&dir).unwrap().is_none());
        drop(locks);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn v22_refusal_classifier_requires_exact_status_and_closed_error_pair() {
        use reqwest::StatusCode;
        use EnrollmentFailureKind as Kind;

        let cases = [
            (409, "not_found", Kind::CodeInvalid),
            (409, "expired", Kind::CodeInvalid),
            (409, "already_redeemed", Kind::CodeInvalid),
            (409, "account_mismatch", Kind::OwnerMismatch),
            (401, "passkey_required", Kind::AuthorityStale),
            (409, "passkey_changed", Kind::AuthorityStale),
            (409, "authority_revoked", Kind::AuthorityStale),
            (400, "client_upgrade_required", Kind::Incompatible),
            (409, "kind_mismatch", Kind::Incompatible),
            (422, "content_blind_violation", Kind::Incompatible),
            (429, "rate_limited", Kind::TemporarilyUnavailable),
            (404, "not_found", Kind::OutcomeUnconfirmed),
            (429, "device_quota_exceeded", Kind::OutcomeUnconfirmed),
            (400, "account_mismatch", Kind::OutcomeUnconfirmed),
            (503, "temporarily_unavailable", Kind::OutcomeUnconfirmed),
            (500, "not_found", Kind::OutcomeUnconfirmed),
            (409, "unknown_future_error", Kind::OutcomeUnconfirmed),
        ];
        for (status, error, expected) in cases {
            let body = serde_json::to_vec(&serde_json::json!({ "error": error })).unwrap();
            assert_eq!(
                classify_redeem_refusal(StatusCode::from_u16(status).unwrap(), &body),
                expected,
                "unexpected classification for {status} + {error}"
            );
        }
        assert_eq!(
            classify_redeem_refusal(StatusCode::CONFLICT, b"{"),
            Kind::OutcomeUnconfirmed
        );
    }

    #[test]
    fn malformed_committed_response_is_not_retried_and_stays_unconfirmed() {
        let dir = enrollment_test_dir("one-shot-malformed-success");
        let _ = fs::remove_dir_all(&dir);
        let (cloud, server) =
            serve_one_redeem_exchange_and_count_connections("201 Created", b"{".to_vec());
        let error = enroll_with_code(&dir, &cloud, "A2B3C4D5", "one shot").unwrap_err();
        let (request, connections) = server.join().unwrap();
        assert_eq!(error.kind(), EnrollmentFailureKind::OutcomeUnconfirmed);
        assert_eq!(
            connections, 1,
            "authority-creating POST must never auto-retry"
        );
        assert_eq!(request_json(&request)["code"], "A2B3C4D5");
        assert!(load_record(&dir).unwrap().is_none());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn default_enrollment_http_timeout_remains_ten_seconds() {
        assert_eq!(ENROLLMENT_HTTP_TIMEOUT, Duration::from_secs(10));
        assert!(include_str!("device_identity.rs").contains(".retry(reqwest::retry::never())"));
    }

    #[test]
    fn enrollment_response_body_is_bounded_before_json_parse() {
        let declared = assert_failed_enrollment_writes_no_record(
            "declared-oversize",
            |_| Vec::new(),
            Some(MAX_REDEEM_RESPONSE_BYTES + 1),
            false,
        );
        assert_eq!(declared, EnrollmentFailureKind::OutcomeUnconfirmed);

        let streamed = assert_failed_enrollment_writes_no_record(
            "streamed-oversize",
            |_| vec![b'x'; MAX_REDEEM_RESPONSE_BYTES + 1],
            None,
            true,
        );
        assert_eq!(streamed, EnrollmentFailureKind::OutcomeUnconfirmed);
    }

    #[test]
    fn enrollment_rejects_oversized_identity_unknown_fields_and_bad_json_without_record() {
        let oversized = assert_failed_enrollment_writes_no_record(
            "oversized-device-id",
            |public_key| {
                serde_json::to_vec(&valid_redeem_value(
                    public_key,
                    &"d".repeat(MAX_DEVICE_ID_BYTES + 1),
                    "acct_valid",
                ))
                .unwrap()
            },
            None,
            false,
        );
        assert_eq!(oversized, EnrollmentFailureKind::OutcomeUnconfirmed);

        let unknown = assert_failed_enrollment_writes_no_record(
            "unknown-field",
            |public_key| {
                let mut value = valid_redeem_value(public_key, "dev_valid", "acct_valid");
                value["device"]["remoteAuthority"] = serde_json::json!(true);
                serde_json::to_vec(&value).unwrap()
            },
            None,
            false,
        );
        assert_eq!(unknown, EnrollmentFailureKind::OutcomeUnconfirmed);

        for (label, body) in [
            ("malformed-json", b"{".to_vec()),
            (
                "truncated-json",
                br#"{"device":{"deviceId":"dev_truncated""#.to_vec(),
            ),
        ] {
            let malformed = assert_failed_enrollment_writes_no_record(label, |_| body, None, false);
            assert_eq!(malformed, EnrollmentFailureKind::OutcomeUnconfirmed);
        }
    }

    #[test]
    fn enrollment_binds_the_exact_desktop_identity_and_caps_passkey_fields() {
        let wrong_key = assert_failed_enrollment_writes_no_record(
            "wrong-public-key",
            |public_key| {
                let mut value = valid_redeem_value(public_key, "dev_valid", "acct_valid");
                value["device"]["publicKey"] = serde_json::json!(B64.encode([7u8; 32]));
                serde_json::to_vec(&value).unwrap()
            },
            None,
            false,
        );
        assert_eq!(wrong_key, EnrollmentFailureKind::OutcomeUnconfirmed);

        let wrong_kind = assert_failed_enrollment_writes_no_record(
            "wrong-device-kind",
            |public_key| {
                let mut value = valid_redeem_value(public_key, "dev_valid", "acct_valid");
                value["device"]["kind"] = serde_json::json!("browser");
                serde_json::to_vec(&value).unwrap()
            },
            None,
            false,
        );
        assert_eq!(wrong_kind, EnrollmentFailureKind::OutcomeUnconfirmed);

        let revoked = assert_failed_enrollment_writes_no_record(
            "revoked-device",
            |public_key| {
                let mut value = valid_redeem_value(public_key, "dev_valid", "acct_valid");
                value["device"]["revoked"] = serde_json::json!(true);
                serde_json::to_vec(&value).unwrap()
            },
            None,
            false,
        );
        assert_eq!(revoked, EnrollmentFailureKind::OutcomeUnconfirmed);

        let oversized_account = assert_failed_enrollment_writes_no_record(
            "oversized-account-id",
            |public_key| {
                serde_json::to_vec(&valid_redeem_value(
                    public_key,
                    "dev_valid",
                    &"a".repeat(MAX_ACCOUNT_ID_BYTES + 1),
                ))
                .unwrap()
            },
            None,
            false,
        );
        assert_eq!(oversized_account, EnrollmentFailureKind::OutcomeUnconfirmed);

        let oversized_passkey = assert_failed_enrollment_writes_no_record(
            "oversized-passkey-credential",
            |public_key| {
                let mut value = valid_redeem_value(public_key, "dev_valid", "acct_valid");
                let oversized = "c".repeat(MAX_PASSKEY_CREDENTIAL_ID_BYTES + 1);
                value["passkey"]["credential_id"] = serde_json::json!(&oversized);
                value["enrollment_authorization"]["credential_id"] = serde_json::json!(&oversized);
                serde_json::to_vec(&value).unwrap()
            },
            None,
            false,
        );
        assert_eq!(oversized_passkey, EnrollmentFailureKind::OutcomeUnconfirmed);
    }

    #[test]
    fn enrollment_requires_exact_passkey_uv_marker_before_writing_device_authority() {
        for (label, field) in [
            ("missing-passkey", "passkey"),
            ("missing-authorization-marker", "enrollment_authorization"),
        ] {
            let kind = assert_failed_enrollment_writes_no_record(
                label,
                |public_key| {
                    let mut value = valid_redeem_value(public_key, "dev_valid", "acct_valid");
                    value.as_object_mut().unwrap().remove(field);
                    serde_json::to_vec(&value).unwrap()
                },
                None,
                false,
            );
            assert_eq!(kind, EnrollmentFailureKind::OutcomeUnconfirmed);
        }

        let wrong_version = assert_failed_enrollment_writes_no_record(
            "wrong-authorization-version",
            |public_key| {
                let mut value = valid_redeem_value(public_key, "dev_valid", "acct_valid");
                value["enrollment_authorization"]["version"] = serde_json::json!("session-v1");
                serde_json::to_vec(&value).unwrap()
            },
            None,
            false,
        );
        assert_eq!(wrong_version, EnrollmentFailureKind::OutcomeUnconfirmed);

        let wrong_credential = assert_failed_enrollment_writes_no_record(
            "wrong-authorization-credential",
            |public_key| {
                let mut value = valid_redeem_value(public_key, "dev_valid", "acct_valid");
                value["enrollment_authorization"]["credential_id"] = serde_json::json!("b3RoZXI");
                serde_json::to_vec(&value).unwrap()
            },
            None,
            false,
        );
        assert_eq!(wrong_credential, EnrollmentFailureKind::OutcomeUnconfirmed);

        for generation in [0, MAX_SAFE_JSON_INTEGER + 1] {
            let invalid_generation = assert_failed_enrollment_writes_no_record(
                &format!("invalid-authorization-generation-{generation}"),
                |public_key| {
                    let mut value = valid_redeem_value(public_key, "dev_valid", "acct_valid");
                    value["enrollment_authorization"]["generation"] = serde_json::json!(generation);
                    serde_json::to_vec(&value).unwrap()
                },
                None,
                false,
            );
            assert_eq!(
                invalid_generation,
                EnrollmentFailureKind::OutcomeUnconfirmed
            );
        }
    }

    #[test]
    fn slow_chunked_enrollment_times_out_without_persisting_authority() {
        let dir = enrollment_test_dir("slow-timeout");
        let _ = fs::remove_dir_all(&dir);
        let key = load_or_create_key(&dir).unwrap();
        let body = serde_json::to_vec(&valid_redeem_value(
            &public_key_b64(&key),
            "dev_slow",
            "acct_slow",
        ))
        .unwrap();
        let first_chunk_bytes = body.len().saturating_sub(1).max(1);
        let (cloud, server) = serve_redeem_response(
            body,
            None,
            true,
            first_chunk_bytes,
            Duration::from_millis(100),
        );
        let error = enroll_with_code_with_timeout(
            &dir,
            &cloud,
            "A2B3C4D5",
            "test desktop",
            Duration::from_millis(25),
        )
        .unwrap_err();
        server.join().unwrap();
        assert_eq!(error.kind(), EnrollmentFailureKind::OutcomeUnconfirmed);
        assert!(
            load_record(&dir).unwrap().is_none(),
            "a timed-out response must not create device.json"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn exact_body_boundary_in_slow_chunks_persists_one_closed_record() {
        let dir = enrollment_test_dir("exact-boundary");
        let _ = fs::remove_dir_all(&dir);
        let key = load_or_create_key(&dir).unwrap();
        let public_key = public_key_b64(&key);
        let mut body = serde_json::to_vec(&valid_redeem_value(
            &public_key,
            &format!("dev_{}", "d".repeat(MAX_DEVICE_ID_BYTES - 4)),
            &format!("acct_{}", "a".repeat(MAX_ACCOUNT_ID_BYTES - 5)),
        ))
        .unwrap();
        assert!(body.len() < MAX_REDEEM_RESPONSE_BYTES);
        body.resize(MAX_REDEEM_RESPONSE_BYTES, b' ');

        let (cloud, server) =
            serve_redeem_response(body, None, true, 1024, Duration::from_millis(1));
        let record = enroll_with_code(&dir, &cloud, "A2B3C4D5", "test desktop").unwrap();
        server.join().unwrap();
        assert_eq!(record.device_id.len(), MAX_DEVICE_ID_BYTES);
        assert_eq!(record.account_id.len(), MAX_ACCOUNT_ID_BYTES);
        assert_eq!(record.cloud_base, cloud);
        let persisted = load_record(&dir).unwrap().unwrap();
        assert_eq!(persisted.device_id, record.device_id);
        assert_eq!(persisted.account_id, record.account_id);
        assert_eq!(persisted.cloud_base, record.cloud_base);
        assert_eq!(persisted.passkey, record.passkey);
        let records = fs::read_dir(&dir)
            .unwrap()
            .filter_map(|entry| entry.ok())
            .filter(|entry| entry.file_name() == RECORD_FILE)
            .count();
        assert_eq!(records, 1, "boundary-valid response persists exactly once");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_ring_is_private_closed_and_redacted() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

        let (dir, locks) = locked_enrollment_test_dir("diagnostic-redaction");
        let (cloud, server) =
            serve_redeem_exchange("409 Conflict", br#"{"error":"account_mismatch"}"#.to_vec());
        let error = enroll_with_code_with_diagnostics(
            &dir,
            &cloud,
            "A2B3C4D5",
            "secret-device-label",
            &locks,
            None,
        )
        .unwrap_err();
        server.join().unwrap();
        assert_eq!(error.kind(), EnrollmentFailureKind::OwnerMismatch);

        let path = enrollment_diagnostics_path(&dir);
        let metadata = fs::symlink_metadata(&path).unwrap();
        assert!(metadata.file_type().is_file());
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.uid(), unsafe { libc::geteuid() });
        assert_eq!(metadata.nlink(), 1);

        let encoded = fs::read_to_string(&path).unwrap();
        for forbidden in [
            "A2B3C4D5",
            "secret-device-label",
            cloud.as_str(),
            "device_id",
            "account_id",
            "credential_id",
            "public_key",
            "package_version",
        ] {
            assert!(
                !encoded.contains(forbidden),
                "diagnostic ring leaked forbidden value {forbidden:?}"
            );
        }
        let diagnostics = read_enrollment_diagnostics(&dir);
        assert_eq!(diagnostics.version, 1);
        assert_eq!(diagnostics.events.len(), 1);
        let event = serde_json::to_value(&diagnostics.events[0]).unwrap();
        let keys = event
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        assert_eq!(
            keys,
            [
                "activation_attempted",
                "agent_build_dirty",
                "agent_build_git",
                "agent_build_time_ms",
                "agent_crate_version",
                "at_ms",
                "local_record_durable",
                "outcome",
                "reason",
                "request_attempted",
                "response_started",
                "stage",
            ]
        );
        assert_eq!(event["stage"], "redeem_terminal");
        assert_eq!(event["outcome"], "refused");
        assert_eq!(event["reason"], "owner_mismatch");
        assert_eq!(event["request_attempted"], true);
        assert_eq!(event["response_started"], true);
        assert_eq!(event["local_record_durable"], false);
        assert_eq!(event["activation_attempted"], false);

        let file = fs::File::open(&path).unwrap();
        assert!(validate_private_file_for_uid(
            &file,
            ENROLLMENT_DIAGNOSTICS_FILE,
            unsafe { libc::geteuid() }.wrapping_add(1),
        )
        .is_err());
        drop(locks);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_success_is_written_only_after_terminal_activation() {
        let (dir, locks) = locked_enrollment_test_dir("diagnostic-terminal-only");
        let key = load_or_create_key(&dir).unwrap();
        let response = serde_json::to_vec(&valid_redeem_value(
            &public_key_b64(&key),
            "dev_terminal",
            "acct_terminal",
        ))
        .unwrap();
        let (cloud, server) = serve_redeem_exchange("201 Created", response);
        enroll_with_code_with_diagnostics(&dir, &cloud, "A2B3C4D5", "terminal only", &locks, None)
            .unwrap();
        server.join().unwrap();
        assert!(
            !enrollment_diagnostics_path(&dir).exists(),
            "durable device.json is the pre-activation crash barrier; no extra log rewrite"
        );

        record_enrollment_activation_terminal(
            &dir,
            &locks,
            EnrollmentActivationOutcome::Ready,
            None,
        );
        let diagnostics = read_enrollment_diagnostics(&dir);
        assert_eq!(diagnostics.events.len(), 1);
        assert_eq!(
            diagnostics.events[0].outcome,
            EnrollmentDiagnosticOutcome::Ready
        );
        assert!(diagnostics.events[0].local_record_durable);
        assert!(diagnostics.events[0].activation_attempted);

        record_enrollment_activation_terminal(
            &dir,
            &locks,
            EnrollmentActivationOutcome::FailedClosed,
            None,
        );
        record_enrollment_activation_terminal(
            &dir,
            &locks,
            EnrollmentActivationOutcome::CleanupIncomplete,
            None,
        );
        let outcomes = read_enrollment_diagnostics(&dir)
            .events
            .into_iter()
            .map(|event| event.outcome)
            .collect::<Vec<_>>();
        assert_eq!(
            outcomes,
            [
                EnrollmentDiagnosticOutcome::Ready,
                EnrollmentDiagnosticOutcome::FailedClosed,
                EnrollmentDiagnosticOutcome::CleanupIncomplete,
            ]
        );
        drop(locks);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_ring_recovers_only_owner_safe_corrupt_or_oversized_files() {
        let (dir, locks) = locked_enrollment_test_dir("diagnostic-recovery");
        let path = enrollment_diagnostics_path(&dir);

        write_owner_private_test_file(&path, b"not-json");
        record_enrollment_activation_terminal(
            &dir,
            &locks,
            EnrollmentActivationOutcome::Ready,
            None,
        );
        assert_eq!(read_enrollment_diagnostics(&dir).events.len(), 1);

        write_owner_private_test_file(&path, &vec![b'x'; MAX_ENROLLMENT_DIAGNOSTICS_BYTES + 1]);
        record_enrollment_activation_terminal(
            &dir,
            &locks,
            EnrollmentActivationOutcome::CleanupIncomplete,
            None,
        );
        let diagnostics = read_enrollment_diagnostics(&dir);
        assert_eq!(diagnostics.events.len(), 1);
        assert_eq!(
            diagnostics.events[0].outcome,
            EnrollmentDiagnosticOutcome::CleanupIncomplete
        );
        assert!(fs::metadata(&path).unwrap().len() <= MAX_ENROLLMENT_DIAGNOSTICS_BYTES as u64);
        drop(locks);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_writer_recovers_only_a_safe_fixed_crash_temporary() {
        use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

        let (dir, locks) = locked_enrollment_test_dir("diagnostic-safe-temp");
        let temporary = enrollment_diagnostics_temporary_path(&dir);
        write_owner_private_test_file(&temporary, b"crash-before-rename");
        record_enrollment_activation_terminal(
            &dir,
            &locks,
            EnrollmentActivationOutcome::Ready,
            None,
        );
        assert!(!temporary.exists());
        assert_eq!(read_enrollment_diagnostics(&dir).events.len(), 1);
        drop(locks);
        let _ = fs::remove_dir_all(&dir);

        let (symlink_dir, symlink_locks) = locked_enrollment_test_dir("diagnostic-temp-symlink");
        let target = symlink_dir.join("temp-target");
        write_owner_private_test_file(&target, b"symlink-temp-sentinel");
        let temporary = enrollment_diagnostics_temporary_path(&symlink_dir);
        symlink(&target, &temporary).unwrap();
        record_enrollment_activation_terminal(
            &symlink_dir,
            &symlink_locks,
            EnrollmentActivationOutcome::Ready,
            None,
        );
        assert!(fs::symlink_metadata(&temporary)
            .unwrap()
            .file_type()
            .is_symlink());
        assert_eq!(fs::read(&target).unwrap(), b"symlink-temp-sentinel");
        assert!(!enrollment_diagnostics_path(&symlink_dir).exists());
        drop(symlink_locks);
        let _ = fs::remove_dir_all(&symlink_dir);

        let (hardlink_dir, hardlink_locks) = locked_enrollment_test_dir("diagnostic-temp-hardlink");
        let temporary = enrollment_diagnostics_temporary_path(&hardlink_dir);
        write_owner_private_test_file(&temporary, b"hardlink-temp-sentinel");
        let second = hardlink_dir.join("temp-second-link");
        fs::hard_link(&temporary, &second).unwrap();
        assert_eq!(fs::metadata(&temporary).unwrap().nlink(), 2);
        record_enrollment_activation_terminal(
            &hardlink_dir,
            &hardlink_locks,
            EnrollmentActivationOutcome::Ready,
            None,
        );
        assert_eq!(fs::read(&temporary).unwrap(), b"hardlink-temp-sentinel");
        assert!(!enrollment_diagnostics_path(&hardlink_dir).exists());
        drop(hardlink_locks);
        let _ = fs::remove_dir_all(&hardlink_dir);

        let (mode_dir, mode_locks) = locked_enrollment_test_dir("diagnostic-temp-mode");
        let temporary = enrollment_diagnostics_temporary_path(&mode_dir);
        write_owner_private_test_file(&temporary, b"mode-temp-sentinel");
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o400)).unwrap();
        record_enrollment_activation_terminal(
            &mode_dir,
            &mode_locks,
            EnrollmentActivationOutcome::Ready,
            None,
        );
        assert_eq!(
            fs::metadata(&temporary).unwrap().permissions().mode() & 0o7777,
            0o400
        );
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&temporary).unwrap(), b"mode-temp-sentinel");
        assert!(!enrollment_diagnostics_path(&mode_dir).exists());
        drop(mode_locks);
        let _ = fs::remove_dir_all(&mode_dir);
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_ring_refuses_symlink_hardlink_and_loose_mode_without_replacement() {
        use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

        let (symlink_dir, symlink_locks) = locked_enrollment_test_dir("diagnostic-symlink");
        let symlink_target = symlink_dir.join("outside-target");
        write_owner_private_test_file(&symlink_target, b"symlink-sentinel");
        symlink(&symlink_target, enrollment_diagnostics_path(&symlink_dir)).unwrap();
        record_enrollment_activation_terminal(
            &symlink_dir,
            &symlink_locks,
            EnrollmentActivationOutcome::Ready,
            None,
        );
        assert!(
            fs::symlink_metadata(enrollment_diagnostics_path(&symlink_dir))
                .unwrap()
                .file_type()
                .is_symlink()
        );
        assert_eq!(fs::read(&symlink_target).unwrap(), b"symlink-sentinel");
        drop(symlink_locks);
        let _ = fs::remove_dir_all(&symlink_dir);

        let (hardlink_dir, hardlink_locks) = locked_enrollment_test_dir("diagnostic-hardlink");
        let hardlink_path = enrollment_diagnostics_path(&hardlink_dir);
        write_owner_private_test_file(&hardlink_path, b"hardlink-sentinel");
        let second_link = hardlink_dir.join("second-link");
        fs::hard_link(&hardlink_path, &second_link).unwrap();
        assert_eq!(fs::metadata(&hardlink_path).unwrap().nlink(), 2);
        record_enrollment_activation_terminal(
            &hardlink_dir,
            &hardlink_locks,
            EnrollmentActivationOutcome::Ready,
            None,
        );
        assert_eq!(fs::read(&hardlink_path).unwrap(), b"hardlink-sentinel");
        assert_eq!(fs::read(&second_link).unwrap(), b"hardlink-sentinel");
        drop(hardlink_locks);
        let _ = fs::remove_dir_all(&hardlink_dir);

        let (loose_dir, loose_locks) = locked_enrollment_test_dir("diagnostic-loose");
        let loose_path = enrollment_diagnostics_path(&loose_dir);
        for mode in [0o640, 0o400, 0o200, 0o700, 0o4600] {
            write_owner_private_test_file(&loose_path, b"loose-sentinel");
            fs::set_permissions(&loose_path, fs::Permissions::from_mode(mode)).unwrap();
            record_enrollment_activation_terminal(
                &loose_dir,
                &loose_locks,
                EnrollmentActivationOutcome::Ready,
                None,
            );
            let observed_mode = fs::metadata(&loose_path).unwrap().permissions().mode() & 0o7777;
            assert_eq!(observed_mode, mode);
            fs::set_permissions(&loose_path, fs::Permissions::from_mode(0o600)).unwrap();
            assert_eq!(fs::read(&loose_path).unwrap(), b"loose-sentinel");
        }
        drop(loose_locks);
        let _ = fs::remove_dir_all(&loose_dir);
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_nonregular_paths_return_promptly_and_remain_untouched() {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::fs::{FileTypeExt as _, PermissionsExt as _};
        use std::os::unix::net::UnixListener;

        let (fifo_dir, fifo_locks) = locked_enrollment_test_dir("diagnostic-fifo");
        let fifo = enrollment_diagnostics_path(&fifo_dir);
        let encoded = CString::new(fifo.as_os_str().as_bytes()).unwrap();
        assert_eq!(unsafe { libc::mkfifo(encoded.as_ptr(), 0o600) }, 0);
        fs::set_permissions(&fifo, fs::Permissions::from_mode(0o600)).unwrap();
        let started = std::time::Instant::now();
        record_enrollment_activation_terminal(
            &fifo_dir,
            &fifo_locks,
            EnrollmentActivationOutcome::Ready,
            None,
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(fs::symlink_metadata(&fifo).unwrap().file_type().is_fifo());
        drop(fifo_locks);
        let _ = fs::remove_dir_all(&fifo_dir);

        let socket_dir = fs::canonicalize("/tmp").unwrap().join(format!(
            "hds-{}-{}",
            std::process::id(),
            ENROLLMENT_FIXTURE_SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&socket_dir);
        create_safe_identity_fixture_dir(&socket_dir);
        let socket_locks = crate::service::LifecycleLockSet::acquire([socket_dir.clone()]).unwrap();
        let socket = enrollment_diagnostics_path(&socket_dir);
        let listener = UnixListener::bind(&socket).unwrap();
        let started = std::time::Instant::now();
        record_enrollment_activation_terminal(
            &socket_dir,
            &socket_locks,
            EnrollmentActivationOutcome::Ready,
            None,
        );
        assert!(started.elapsed() < Duration::from_secs(1));
        assert!(fs::symlink_metadata(&socket)
            .unwrap()
            .file_type()
            .is_socket());
        drop(listener);
        drop(socket_locks);
        let _ = fs::remove_dir_all(&socket_dir);
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_publication_is_exact_0600_under_owner_bit_umasks() {
        use std::os::unix::fs::PermissionsExt as _;

        const CHILD: &str = "HYDRA_ENROLLMENT_DIAGNOSTIC_UMASK_CHILD";
        if std::env::var_os(CHILD).is_none() {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .args([
                    "--exact",
                    "device_identity::tests::diagnostic_publication_is_exact_0600_under_owner_bit_umasks",
                    "--nocapture",
                ])
                .env(CHILD, "1")
                .status()
                .unwrap();
            assert!(status.success(), "isolated diagnostic umask proof failed");
            return;
        }

        for mask in [0o777, 0o077, 0o002] {
            let (dir, locks) = locked_enrollment_test_dir(&format!("diagnostic-umask-{mask:o}"));
            let previous = unsafe { libc::umask(mask) };
            record_enrollment_activation_terminal(
                &dir,
                &locks,
                EnrollmentActivationOutcome::Ready,
                None,
            );
            unsafe { libc::umask(previous) };
            assert_eq!(
                fs::symlink_metadata(enrollment_diagnostics_path(&dir))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o7777,
                0o600
            );
            drop(locks);
            let _ = fs::remove_dir_all(&dir);
        }
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_sink_failure_and_deadline_skip_never_change_enrollment_outcome() {
        use std::os::unix::fs::PermissionsExt as _;
        use std::sync::atomic::{AtomicBool, Ordering as AtomicOrdering};

        let (dir, locks) = locked_enrollment_test_dir("diagnostic-best-effort");
        let path = enrollment_diagnostics_path(&dir);
        write_owner_private_test_file(&path, b"unsafe-diagnostic-sentinel");
        fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
        let (cloud, server) =
            serve_redeem_exchange("409 Conflict", br#"{"error":"account_mismatch"}"#.to_vec());
        let error = enroll_with_code_with_diagnostics(
            &dir,
            &cloud,
            "A2B3C4D5",
            "sink failure",
            &locks,
            None,
        )
        .unwrap_err();
        server.join().unwrap();
        assert_eq!(error.kind(), EnrollmentFailureKind::OwnerMismatch);
        assert_eq!(fs::read(&path).unwrap(), b"unsafe-diagnostic-sentinel");

        let called = AtomicBool::new(false);
        best_effort_diagnostic(
            Some(std::time::Instant::now() + Duration::from_secs(1)),
            || {
                called.store(true, AtomicOrdering::Relaxed);
                thread::sleep(Duration::from_secs(5));
                Ok(())
            },
        );
        assert!(!called.load(AtomicOrdering::Relaxed));
        best_effort_diagnostic(None, || anyhow::bail!("injected diagnostic failure"));
        drop(locks);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn diagnostic_writer_allows_pending_remove_but_freezes_pending_full_forget() {
        use crate::lifecycle_cleanup::{
            AuthorityEvidence, CleanupIntent, CleanupTombstone, DesiredUnit, PriorActivation,
        };
        use std::collections::BTreeSet;

        for (intent, should_write) in [
            (CleanupIntent::Remove, true),
            (CleanupIntent::FullForget, false),
        ] {
            let parent = enrollment_test_dir(match intent {
                CleanupIntent::Remove => "diagnostic-pending-remove",
                CleanupIntent::FullForget => "diagnostic-pending-full-forget",
                _ => unreachable!(),
            });
            let _ = fs::remove_dir_all(&parent);
            create_safe_identity_fixture_dir(&parent);
            let dir = parent.join("hydra-agent");
            create_safe_identity_fixture_dir(&dir);
            let locks = crate::service::LifecycleLockSet::acquire([dir.clone()]).unwrap();
            #[cfg(target_os = "macos")]
            let unit = dir.join("com.hydra.agent.plist");
            #[cfg(not(target_os = "macos"))]
            let unit = dir.join("hydra-agent.service");
            let roots = BTreeSet::from([dir.clone()]);
            let pending = CleanupTombstone::new(
                intent,
                PriorActivation::ProvenClosed,
                AuthorityEvidence::NoActiveRecord,
                &dir,
                &roots,
                &roots,
                [],
                [],
                DesiredUnit::from_bytes(&unit, b"synthetic diagnostic freeze unit").unwrap(),
                None,
                &locks,
            )
            .unwrap();
            crate::lifecycle_cleanup::store(&dir, &pending, &locks).unwrap();
            record_enrollment_activation_terminal(
                &dir,
                &locks,
                EnrollmentActivationOutcome::Ready,
                None,
            );
            assert_eq!(enrollment_diagnostics_path(&dir).exists(), should_write);
            drop(locks);
            let _ = fs::remove_dir_all(&parent);
        }
    }

    #[test]
    fn diagnostic_ring_evicts_oldest_by_count_and_exact_pretty_byte_size() {
        let mut template = enrollment_diagnostic_event(
            EnrollmentDiagnosticStage::ActivationTerminal,
            EnrollmentDiagnosticOutcome::Ready,
            None,
            true,
            true,
            true,
            true,
        )
        .unwrap();
        template.agent_build_git = "a".repeat(40);
        template.agent_crate_version = "v".repeat(64);
        let events = (0..10)
            .map(|at_ms| {
                let mut event = template.clone();
                event.at_ms = at_ms;
                event
            })
            .collect::<Vec<_>>();
        let last_three = EnrollmentDiagnostics {
            version: 1,
            events: events[7..].to_vec(),
        };
        let exact_three_bytes = serde_json::to_vec_pretty(&last_three).unwrap().len();
        let bounded = bound_enrollment_diagnostics(
            EnrollmentDiagnostics { version: 1, events },
            10,
            exact_three_bytes,
        )
        .unwrap();
        assert_eq!(bounded.events.len(), 3);
        assert_eq!(bounded.events[0].at_ms, 7);
        assert_eq!(
            serde_json::to_vec_pretty(&bounded).unwrap().len(),
            exact_three_bytes
        );

        let sixty_five = (0..65)
            .map(|at_ms| {
                let mut event = template.clone();
                event.at_ms = at_ms;
                event
            })
            .collect::<Vec<_>>();
        let bounded = bound_enrollment_diagnostics(
            EnrollmentDiagnostics {
                version: 1,
                events: sixty_five,
            },
            MAX_ENROLLMENT_DIAGNOSTIC_EVENTS,
            MAX_ENROLLMENT_DIAGNOSTICS_BYTES,
        )
        .unwrap();
        assert_eq!(bounded.events.len(), MAX_ENROLLMENT_DIAGNOSTIC_EVENTS);
        assert_eq!(bounded.events[0].at_ms, 1);
        assert!(
            serde_json::to_vec_pretty(&bounded).unwrap().len() <= MAX_ENROLLMENT_DIAGNOSTICS_BYTES
        );
    }

    #[test]
    fn cross_environment_enroll_fails_before_key_or_network_and_preserves_record() {
        let dir = identity_test_path(format!("hydra-enroll-environment-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let existing = DeviceRecord {
            device_id: "prod-device".to_string(),
            account_id: "account".to_string(),
            cloud_base: "https://api.hydraterms.com".to_string(),
            passkey: None,
        };
        save_record(&dir, &existing).unwrap();
        let error = enroll_with_code(
            &dir,
            "https://api.staging.hydraterms.com",
            "A2B3C4D5",
            "test-desktop",
        )
        .unwrap_err();
        assert_eq!(error.kind(), EnrollmentFailureKind::LocalFailure);
        assert!(!dir.join(KEY_FILE).exists());
        assert_eq!(
            load_record(&dir).unwrap().unwrap().device_id,
            existing.device_id
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
