//! One-time adoption of Linux enrollment state created by the historical
//! `XDG_DATA_HOME` resolver.
//!
//! Current private authority is always the effective OS account's fixed
//! `~/.local/share/hydra-agent` directory. An explicitly configured legacy
//! `XDG_DATA_HOME` is migration input only: it never becomes the runtime state
//! root. Ambient XDG state is not authority: the caller must supply the exact
//! legacy agent directory recovered from an installed or running Hydra service.
//! Adoption copies the exact identity without replacing an existing one and
//! records enough local evidence to retire a complete legacy copy if the user
//! later removes Remote.

#![cfg_attr(not(target_os = "linux"), allow(dead_code))]

use anyhow::{bail, Context, Result};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::BTreeSet;
use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

const KEY_FILE: &str = "device-key";
const RECORD_FILE: &str = "device.json";
#[cfg(test)]
const OWNER_FILE: &str = "device-owner.json";
const MARKER_FILE: &str = "legacy-xdg-enrollment-adoption.v1.json";
const MAX_KEY_BYTES: usize = 512;
const MAX_RECORD_BYTES: usize = 64 * 1024;
const MAX_MARKER_BYTES: usize = 8 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdoptionOutcome {
    NotApplicable,
    NoLegacyEnrollment,
    AlreadyCanonical,
    Adopted,
    AlreadyAdopted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CorruptRecoveryOutcome {
    NotApplicable,
    Recovered,
}

/// Read-only, independently verified evidence for a malformed active record.
/// The exact bytes are captured before any recovery mutation so a lifecycle
/// journal can bind the owner and corrupt record even across a crash.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CorruptEnrollmentSnapshot {
    canonical_agent_dir: PathBuf,
    owner_bytes: Vec<u8>,
    record_bytes: Vec<u8>,
}

impl CorruptEnrollmentSnapshot {
    pub fn canonical_agent_dir(&self) -> &Path {
        &self.canonical_agent_dir
    }

    pub fn owner_bytes(&self) -> &[u8] {
        &self.owner_bytes
    }

    pub fn record_bytes(&self) -> &[u8] {
        &self.record_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptionMarker {
    schema: u8,
    source_agent_dir: String,
    account_id: String,
    device_id: String,
    key_sha256: String,
    record_sha256: String,
    owner_sha256: String,
}

struct EnrollmentSnapshot {
    key: Vec<u8>,
    record_bytes: Vec<u8>,
    record: crate::device_identity::DeviceRecord,
}

/// Adopt only an exact legacy agent directory recovered from structural Hydra
/// service provenance. A public launcher-controlled environment value is not
/// sufficient provenance. Once an adoption marker exists, its hash-bound source
/// is authoritative and `proven_legacy_agent_dir` is deliberately ignored.
pub fn adopt_proven_legacy_xdg_enrollment(
    canonical_agent_dir: &Path,
    proven_legacy_agent_dir: Option<&Path>,
    lifecycle_locks: &crate::service::LifecycleLockSet,
) -> Result<AdoptionOutcome> {
    require_mutation_locks(
        canonical_agent_dir,
        proven_legacy_agent_dir,
        lifecycle_locks,
    )?;
    #[cfg(target_os = "linux")]
    {
        adopt_from_legacy_agent_dir(
            canonical_agent_dir,
            proven_legacy_agent_dir,
            crate::agent_dir::trusted_uid(),
        )
    }
    #[cfg(not(target_os = "linux"))]
    {
        let _ = (canonical_agent_dir, proven_legacy_agent_dir);
        Ok(AdoptionOutcome::NotApplicable)
    }
}

/// Read-only candidate discovery for deterministic multi-root lock
/// acquisition. The caller acquires this complete normalized set in lexical
/// order, then calls this function again and retries if it changed.
pub fn adoption_lock_roots(
    canonical_agent_dir: &Path,
    proven_legacy_agent_dir: Option<&Path>,
) -> Result<BTreeSet<PathBuf>> {
    let mut roots =
        BTreeSet::from([fs::canonicalize(canonical_agent_dir)
            .context("resolve canonical enrollment lock root")?]);
    let marker_path = canonical_agent_dir.join(MARKER_FILE);
    if leaf_exists(&marker_path)? {
        let uid = crate::agent_dir::trusted_uid();
        let bytes =
            read_owned_private_regular(&marker_path, uid, MAX_MARKER_BYTES, "adoption marker")?;
        let marker: AdoptionMarker =
            serde_json::from_slice(&bytes).context("adoption marker is invalid")?;
        if marker.schema != 1 {
            bail!("adoption marker schema is unsupported");
        }
        let source = marker_source(&marker, canonical_agent_dir, uid)?;
        if leaf_exists(&source)? {
            roots.insert(fs::canonicalize(source).context("resolve legacy enrollment lock root")?);
        }
    } else if let Some(source) = proven_legacy_agent_dir {
        if leaf_exists(source)? {
            roots.insert(fs::canonicalize(source).context("resolve proven legacy lock root")?);
        }
    }
    Ok(roots)
}

fn require_mutation_locks(
    canonical_agent_dir: &Path,
    proven_legacy_agent_dir: Option<&Path>,
    lifecycle_locks: &crate::service::LifecycleLockSet,
) -> Result<()> {
    for root in adoption_lock_roots(canonical_agent_dir, proven_legacy_agent_dir)? {
        lifecycle_locks
            .require_agent_dir(&root)
            .with_context(|| format!("lifecycle lock set omits {}", root.display()))?;
    }
    Ok(())
}

fn adopt_from_legacy_agent_dir(
    canonical_agent_dir: &Path,
    proven_legacy_agent_dir: Option<&Path>,
    uid: u32,
) -> Result<AdoptionOutcome> {
    if !crate::agent_dir::is_canonically_encoded_absolute_path(canonical_agent_dir) {
        bail!("canonical enrollment migration path must be absolute");
    }

    ensure_owned_private_directory(canonical_agent_dir, uid)?;
    let target_key = canonical_agent_dir.join(KEY_FILE);
    let target_record = canonical_agent_dir.join(RECORD_FILE);
    let target_key_exists = leaf_exists(&target_key)?;
    let target_record_exists = leaf_exists(&target_record)?;

    let marker_exists = leaf_exists(&canonical_agent_dir.join(MARKER_FILE))?;

    // A completed marker carries its own immutable source path. Later XDG
    // changes, an absent environment, or a newer service definition cannot
    // redirect verification to a different directory.
    if marker_exists {
        if target_key_exists && target_record_exists {
            let canonical = load_snapshot(canonical_agent_dir, uid, "current enrollment")?;
            validate_snapshot_record(&canonical, "current enrollment")?;
            crate::device_identity::claim_or_verify_owner_for_record(
                canonical_agent_dir,
                &canonical.record,
            )?;
            verify_marker_for_complete_canonical(canonical_agent_dir, uid, &canonical)?;
            return Ok(AdoptionOutcome::AlreadyAdopted);
        }
        if target_key_exists && !target_record_exists {
            complete_interrupted_legacy_retirement(canonical_agent_dir, uid)?;
            return Ok(AdoptionOutcome::NoLegacyEnrollment);
        }
        bail!("adoption marker exists without a complete current enrollment");
    }

    let source = match proven_legacy_agent_dir {
        Some(source) if source == canonical_agent_dir => None,
        Some(source) => {
            validate_legacy_source_syntax(source, canonical_agent_dir)?;
            Some(source.to_path_buf())
        }
        None => None,
    };
    if let Some(source) = source.as_deref() {
        require_distinct_source_if_present(canonical_agent_dir, source, uid)?;
    }

    // A complete fixed-home identity is authoritative only when no structural
    // legacy service source is present. If an installed/running old service
    // still points at a complete source, exact equality proves an interrupted
    // adoption and completes its marker; disagreement is two live authorities
    // and fails closed without replacing either one.
    if target_key_exists && target_record_exists {
        let canonical = load_snapshot(canonical_agent_dir, uid, "current enrollment")?;
        validate_snapshot_record(&canonical, "current enrollment")?;
        crate::device_identity::claim_or_verify_owner_for_record(
            canonical_agent_dir,
            &canonical.record,
        )?;
        if let Some(source) = source.as_deref() {
            return reconcile_complete_canonical_with_source(
                canonical_agent_dir,
                source,
                uid,
                &canonical,
            );
        }
        return Ok(AdoptionOutcome::AlreadyCanonical);
    }

    let Some(source) = source else {
        // A generated key and/or durable owner without an active record is a
        // normal, inactive residue. It must not brick Status or a fresh-code
        // re-enrollment merely because no old service remains to identify its
        // former XDG path. A record without its key is never usable and remains
        // a fail-closed recovery case.
        if target_record_exists {
            bail!("current enrollment record exists without its private key");
        }
        return Ok(AdoptionOutcome::NoLegacyEnrollment);
    };

    let source_key_exists = leaf_exists(&source.join(KEY_FILE))?;
    let source_record_exists = leaf_exists(&source.join(RECORD_FILE))?;
    if !source_key_exists && !source_record_exists {
        // An owner marker without an active record is retired residue. A fresh
        // passkey-authorized enrollment may bind any account, so legacy
        // provenance must not resurrect that marker into canonical state.
        return Ok(AdoptionOutcome::NoLegacyEnrollment);
    }

    require_owned_directory(&source, uid, "legacy enrollment directory")?;
    if !source_record_exists {
        // A key remains useful for provider-revocation retry and stable device
        // identity, but a record-less owner carries no account restriction.
        // Validate/adopt only the key and deliberately leave any source owner
        // marker inert at its historical path.
        if source_key_exists {
            let source_key = read_owned_private_regular(
                &source.join(KEY_FILE),
                uid,
                MAX_KEY_BYTES,
                "legacy enrollment key",
            )?;
            validate_key_bytes(&source_key)?;
            if target_key_exists {
                let target_key = read_owned_private_regular(
                    &target_key,
                    uid,
                    MAX_KEY_BYTES,
                    "current enrollment key",
                )?;
                if target_key != source_key {
                    bail!("current enrollment key collides with legacy enrollment");
                }
            } else {
                publish_private_no_replace(&target_key, &source_key)?;
            }
        }
        return Ok(AdoptionOutcome::Adopted);
    }
    if !source_key_exists {
        bail!("legacy enrollment record exists without its private key");
    }

    let source_snapshot = load_snapshot(&source, uid, "legacy enrollment")?;
    validate_snapshot_record(&source_snapshot, "legacy enrollment")?;
    crate::device_identity::verify_optional_owner_for_record(&source, &source_snapshot.record)
        .context("legacy owner marker conflicts with the enrollment record")?;

    if target_key_exists {
        let bytes = read_owned_private_regular(&target_key, uid, MAX_KEY_BYTES, "current key")?;
        if bytes != source_snapshot.key {
            bail!("current enrollment key collides with legacy enrollment");
        }
    }
    if target_record_exists {
        let bytes =
            read_owned_private_regular(&target_record, uid, MAX_RECORD_BYTES, "current record")?;
        let _: crate::device_identity::DeviceRecord =
            serde_json::from_slice(&bytes).context("current enrollment record is invalid")?;
        let source_value: serde_json::Value = serde_json::from_slice(&source_snapshot.record_bytes)
            .context("legacy enrollment record is invalid")?;
        let current_value: serde_json::Value =
            serde_json::from_slice(&bytes).context("current enrollment record is invalid")?;
        if current_value != source_value {
            bail!("current enrollment record collides with legacy enrollment");
        }
    }

    // The durable account/cloud owner is established first, then the stable
    // key, and the active enrollment record last. A crash at any boundary is
    // inactive or same-owner and is safely completed by the next run.
    crate::device_identity::claim_or_verify_owner_for_record(
        canonical_agent_dir,
        &source_snapshot.record,
    )?;
    if !target_key_exists {
        publish_private_no_replace(&target_key, &source_snapshot.key)?;
    }
    if !target_record_exists {
        crate::device_identity::save_record(canonical_agent_dir, &source_snapshot.record)?;
    }

    let owner_bytes = crate::device_identity::verified_owner_marker_bytes(canonical_agent_dir)?;
    let marker = marker_for(&source, &source_snapshot, &owner_bytes)?;
    install_or_verify_marker(canonical_agent_dir, uid, &marker)?;
    let adopted = load_snapshot(canonical_agent_dir, uid, "adopted enrollment")?;
    let source_record: serde_json::Value = serde_json::from_slice(&source_snapshot.record_bytes)?;
    let adopted_record: serde_json::Value = serde_json::from_slice(&adopted.record_bytes)?;
    if adopted.key != source_snapshot.key || adopted_record != source_record {
        bail!("adopted enrollment readback differs from migration input");
    }

    Ok(if target_key_exists && target_record_exists {
        AdoptionOutcome::AlreadyAdopted
    } else {
        AdoptionOutcome::Adopted
    })
}

fn reconcile_complete_canonical_with_source(
    canonical_agent_dir: &Path,
    source: &Path,
    uid: u32,
    canonical: &EnrollmentSnapshot,
) -> Result<AdoptionOutcome> {
    let source_key_exists = leaf_exists(&source.join(KEY_FILE))?;
    let source_record_exists = leaf_exists(&source.join(RECORD_FILE))?;
    if !source_key_exists && !source_record_exists {
        // An owner-only historical source is retired residue, not a reason to
        // reject an already-complete canonical enrollment for a new account.
        return Ok(AdoptionOutcome::AlreadyCanonical);
    }

    require_owned_directory(source, uid, "legacy enrollment directory")?;
    if source_record_exists {
        if !source_key_exists {
            bail!("proven legacy enrollment record exists without its private key");
        }
        let legacy = load_snapshot(source, uid, "legacy enrollment")?;
        validate_snapshot_record(&legacy, "legacy enrollment")?;
        crate::device_identity::verify_optional_owner_for_record(source, &legacy.record)
            .context("legacy owner marker conflicts with the enrollment record")?;
        let canonical_record: serde_json::Value = serde_json::from_slice(&canonical.record_bytes)
            .context("current enrollment is invalid")?;
        let legacy_record: serde_json::Value =
            serde_json::from_slice(&legacy.record_bytes).context("legacy enrollment is invalid")?;
        if canonical.key != legacy.key || canonical_record != legacy_record {
            bail!("complete current and service-proven legacy enrollments conflict");
        }

        let owner_bytes = crate::device_identity::verified_owner_marker_bytes(canonical_agent_dir)?;
        let marker = marker_for(source, &legacy, &owner_bytes)?;
        install_or_verify_marker(canonical_agent_dir, uid, &marker)?;
        verify_marker_for_complete_canonical(canonical_agent_dir, uid, canonical)?;
        return Ok(AdoptionOutcome::AlreadyAdopted);
    }

    // A key without a record carries no account authority. Validate it so a
    // malformed service source cannot be used as a lifecycle bypass, but do not
    // let a stale generated key overwrite or brick a complete canonical owner.
    if source_key_exists {
        let key = read_owned_private_regular(
            &source.join(KEY_FILE),
            uid,
            MAX_KEY_BYTES,
            "legacy enrollment key",
        )?;
        validate_key_bytes(&key)?;
    }
    Ok(AdoptionOutcome::AlreadyCanonical)
}

fn complete_interrupted_legacy_retirement(canonical_agent_dir: &Path, uid: u32) -> Result<()> {
    let marker_bytes = read_owned_private_regular(
        &canonical_agent_dir.join(MARKER_FILE),
        uid,
        MAX_MARKER_BYTES,
        "adoption marker",
    )?;
    let marker: AdoptionMarker =
        serde_json::from_slice(&marker_bytes).context("adoption marker is invalid")?;
    let key = read_owned_private_regular(
        &canonical_agent_dir.join(KEY_FILE),
        uid,
        MAX_KEY_BYTES,
        "current enrollment key",
    )?;
    let owner = crate::device_identity::verified_owner_marker_bytes(canonical_agent_dir)?;
    let source = marker_source(&marker, canonical_agent_dir, uid)?;
    if marker.schema != 1
        || marker.key_sha256 != sha256(&key)
        || marker.owner_sha256 != sha256(&owner)
        || !is_sha256(&marker.record_sha256)
    {
        bail!("adoption marker conflicts with interrupted Remove state");
    }
    if !crate::agent_dir::is_canonically_encoded_absolute_path(&source) {
        bail!("adoption marker source is invalid");
    }
    retire_adopted_legacy_enrollment_unlocked(canonical_agent_dir)
        .context("complete interrupted legacy enrollment retirement")
}

fn verify_marker_for_complete_canonical(
    canonical_agent_dir: &Path,
    uid: u32,
    canonical: &EnrollmentSnapshot,
) -> Result<PathBuf> {
    let marker_bytes = read_owned_private_regular(
        &canonical_agent_dir.join(MARKER_FILE),
        uid,
        MAX_MARKER_BYTES,
        "adoption marker",
    )?;
    let marker: AdoptionMarker =
        serde_json::from_slice(&marker_bytes).context("adoption marker is invalid")?;
    let marker_source = marker_source(&marker, canonical_agent_dir, uid)?;
    let owner_bytes = crate::device_identity::verified_owner_marker_bytes(canonical_agent_dir)?;
    if marker.schema != 1
        || marker.account_id != canonical.record.account_id
        || marker.device_id != canonical.record.device_id
        || marker.key_sha256 != sha256(&canonical.key)
        || marker.owner_sha256 != sha256(&owner_bytes)
        || !is_sha256(&marker.record_sha256)
    {
        bail!("adoption marker conflicts with the complete current enrollment");
    }

    // A partial source after a completed adoption is tolerated, but every
    // remaining credential must still be the exact hash-bound migration input.
    if leaf_exists(&marker_source)? {
        require_owned_directory(&marker_source, uid, "legacy enrollment directory")?;
        for (name, max, expected, label) in [
            (
                KEY_FILE,
                MAX_KEY_BYTES,
                marker.key_sha256.as_str(),
                "legacy enrollment key",
            ),
            (
                RECORD_FILE,
                MAX_RECORD_BYTES,
                marker.record_sha256.as_str(),
                "legacy enrollment record",
            ),
        ] {
            let path = marker_source.join(name);
            if leaf_exists(&path)? {
                let bytes = read_owned_private_regular(&path, uid, max, label)?;
                if sha256(&bytes) != expected {
                    bail!("{label} changed after adoption");
                }
            }
        }
    }
    Ok(marker_source)
}

fn marker_source(marker: &AdoptionMarker, canonical_agent_dir: &Path, uid: u32) -> Result<PathBuf> {
    let source = PathBuf::from(&marker.source_agent_dir);
    validate_legacy_source_syntax(&source, canonical_agent_dir)
        .context("adoption marker source is invalid")?;
    require_distinct_source_if_present(canonical_agent_dir, &source, uid)
        .context("adoption marker source aliases current enrollment")?;
    Ok(source)
}

fn validate_legacy_source_syntax(source: &Path, canonical_agent_dir: &Path) -> Result<()> {
    if !crate::agent_dir::is_canonically_encoded_absolute_path(source)
        || source == canonical_agent_dir
        || source.file_name().and_then(|name| name.to_str()) != Some("hydra-agent")
    {
        bail!("legacy enrollment source path is not a distinct normalized agent directory");
    }
    Ok(())
}

fn require_distinct_source_if_present(
    canonical_agent_dir: &Path,
    source: &Path,
    uid: u32,
) -> Result<()> {
    if !leaf_exists(source)? {
        return Ok(());
    }
    require_owned_directory(source, uid, "legacy enrollment directory")?;
    require_distinct_directory_identity(canonical_agent_dir, source)
}

#[cfg(unix)]
fn require_distinct_directory_identity(canonical_agent_dir: &Path, source: &Path) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    let canonical = fs::symlink_metadata(canonical_agent_dir)
        .context("inspect canonical enrollment directory identity")?;
    let source =
        fs::symlink_metadata(source).context("inspect legacy enrollment directory identity")?;
    if canonical.dev() == source.dev() && canonical.ino() == source.ino() {
        bail!("legacy enrollment directory aliases the canonical enrollment directory");
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_distinct_directory_identity(canonical_agent_dir: &Path, source: &Path) -> Result<()> {
    let canonical = fs::canonicalize(canonical_agent_dir)
        .context("resolve canonical enrollment directory identity")?;
    let source =
        fs::canonicalize(source).context("resolve legacy enrollment directory identity")?;
    if canonical == source {
        bail!("legacy enrollment directory aliases the canonical enrollment directory");
    }
    Ok(())
}

fn validate_snapshot_record(snapshot: &EnrollmentSnapshot, label: &str) -> Result<()> {
    crate::release_trust::active()
        .validate_enrollment(&snapshot.record)
        .with_context(|| format!("{label} does not match this private release"))?;
    require_nonempty_identity(&snapshot.record.account_id, &format!("{label} account id"))?;
    require_nonempty_identity(&snapshot.record.device_id, &format!("{label} device id"))?;
    Ok(())
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
}

/// Return the exact legacy peer root only when a complete canonical enrollment
/// and its adoption marker verify together. Close/upgrade code may use this
/// bounded accessor to include the predecessor's readiness directory without
/// parsing marker bytes or treating ambient XDG as authority.
pub fn verified_completed_legacy_source(
    canonical_agent_dir: &Path,
    lifecycle_lock: &crate::service::LifecycleLock,
) -> Result<Option<PathBuf>> {
    lifecycle_lock
        .require_agent_dir(canonical_agent_dir)
        .context("legacy source lookup lock is bound to another agent directory")?;
    let marker_path = canonical_agent_dir.join(MARKER_FILE);
    if !leaf_exists(&marker_path)? {
        return Ok(None);
    }
    let uid = crate::agent_dir::trusted_uid();
    require_owned_directory(canonical_agent_dir, uid, "canonical enrollment directory")?;
    if !leaf_exists(&canonical_agent_dir.join(KEY_FILE))?
        || !leaf_exists(&canonical_agent_dir.join(RECORD_FILE))?
    {
        bail!("adoption marker exists without a complete canonical enrollment");
    }
    let canonical = load_snapshot(canonical_agent_dir, uid, "current enrollment")?;
    validate_snapshot_record(&canonical, "current enrollment")?;
    crate::device_identity::verify_optional_owner_for_record(
        canonical_agent_dir,
        &canonical.record,
    )?;
    verify_marker_for_complete_canonical(canonical_agent_dir, uid, &canonical).map(Some)
}

/// Capture corrupt-record evidence without changing the record, adoption
/// marker, legacy copy, key, or durable owner. Callers must durably journal
/// this snapshot before invoking any destructive recovery path.
pub fn snapshot_corrupt_canonical_for_remove(
    canonical_agent_dir: &Path,
    lifecycle_lock: &crate::service::LifecycleLock,
) -> Result<Option<CorruptEnrollmentSnapshot>> {
    lifecycle_lock
        .require_agent_dir(canonical_agent_dir)
        .context("corrupt enrollment snapshot lock is bound to another agent directory")?;
    #[cfg(unix)]
    {
        let record_path = canonical_agent_dir.join(RECORD_FILE);
        if !leaf_exists(&record_path)? {
            return Ok(None);
        }
        if crate::device_identity::load_record(canonical_agent_dir).is_ok() {
            return Ok(None);
        }
        let owner_bytes = crate::device_identity::verified_owner_marker_bytes(canonical_agent_dir)
            .context("corrupt enrollment has no recoverable durable owner")?;
        let record_bytes = read_owned_private_regular(
            &record_path,
            crate::agent_dir::trusted_uid(),
            MAX_RECORD_BYTES,
            "corrupt current enrollment record",
        )?;
        Ok(Some(CorruptEnrollmentSnapshot {
            canonical_agent_dir: fs::canonicalize(canonical_agent_dir)
                .context("resolve corrupt enrollment root")?,
            owner_bytes,
            record_bytes,
        }))
    }
    #[cfg(not(unix))]
    {
        let _ = canonical_agent_dir;
        Ok(None)
    }
}

/// Explicit fail-closed recovery used only by Remove Enrollment. A malformed
/// active record can be retired when, and only when, a separately validated
/// durable owner marker still binds the profile. Status and Enroll never call
/// this path, so corruption cannot be reinterpreted as an unenrolled profile.
pub fn recover_corrupt_canonical_for_remove(
    canonical_agent_dir: &Path,
    snapshot: &CorruptEnrollmentSnapshot,
    expected: &crate::lifecycle_cleanup::CleanupTombstone,
    lifecycle_locks: &crate::service::LifecycleLockSet,
) -> Result<CorruptRecoveryOutcome> {
    lifecycle_locks
        .require_agent_dir(canonical_agent_dir)
        .context("corrupt enrollment recovery lock set omits the canonical root")?;
    #[cfg(unix)]
    {
        if snapshot.canonical_agent_dir() != fs::canonicalize(canonical_agent_dir)? {
            bail!("corrupt enrollment snapshot belongs to another root");
        }
        if expected.intent() != crate::lifecycle_cleanup::CleanupIntent::Remove
            || expected.canonical_root() != fs::canonicalize(canonical_agent_dir)?
        {
            bail!("corrupt enrollment recovery is not bound to a Remove journal");
        }
        let Some((owner_sha256, record_sha256)) = expected.authority().corrupt_digests() else {
            bail!("corrupt enrollment recovery journal lacks corrupt authority evidence");
        };
        if sha256(snapshot.owner_bytes()) != owner_sha256
            || sha256(snapshot.record_bytes()) != record_sha256
        {
            bail!("corrupt enrollment snapshot disagrees with its durable journal");
        }
        // `execute_planned_deletion` first requires the exact durable journal,
        // exact complete lock set and revalidated owner marker, then performs
        // digest/inode-bound unlink + parent fsync + NotFound readback before
        // journaling completion. There is no convention-only raw unlink path.
        crate::lifecycle_cleanup::execute_planned_deletion(
            canonical_agent_dir,
            expected,
            &canonical_agent_dir.join(RECORD_FILE),
            lifecycle_locks,
        )?;
        Ok(CorruptRecoveryOutcome::Recovered)
    }
    #[cfg(not(unix))]
    {
        let _ = (canonical_agent_dir, snapshot);
        Ok(CorruptRecoveryOutcome::NotApplicable)
    }
}

/// Remove the exact compatibility copy recorded during adoption. This closes
/// the rollback path when the user deliberately removes Remote; an old binary
/// must not be able to reopen authority from the former XDG location.
pub fn retire_adopted_legacy_enrollment(
    canonical_agent_dir: &Path,
    lifecycle_locks: &crate::service::LifecycleLockSet,
) -> Result<()> {
    require_mutation_locks(canonical_agent_dir, None, lifecycle_locks)?;
    retire_adopted_legacy_enrollment_unlocked(canonical_agent_dir)
}

fn retire_adopted_legacy_enrollment_unlocked(canonical_agent_dir: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        let uid = crate::agent_dir::trusted_uid();
        let marker_path = canonical_agent_dir.join(MARKER_FILE);
        if !leaf_exists(&marker_path)? {
            return Ok(());
        }
        let bytes =
            read_owned_private_regular(&marker_path, uid, MAX_MARKER_BYTES, "adoption marker")?;
        let marker: AdoptionMarker =
            serde_json::from_slice(&bytes).context("adoption marker is invalid")?;
        if marker.schema != 1 {
            bail!("adoption marker schema is unsupported");
        }
        let source = marker_source(&marker, canonical_agent_dir, uid)?;
        if leaf_exists(&source)? {
            require_owned_directory(&source, uid, "legacy enrollment directory")?;
            retire_one_legacy_file(
                &source.join(RECORD_FILE),
                uid,
                MAX_RECORD_BYTES,
                &marker.record_sha256,
                "legacy enrollment record",
            )?;
            retire_one_legacy_file(
                &source.join(KEY_FILE),
                uid,
                MAX_KEY_BYTES,
                &marker.key_sha256,
                "legacy enrollment key",
            )?;
        }
        remove_regular_owned_file(&marker_path, uid, "adoption marker")?;
        Ok(())
    }
    #[cfg(not(unix))]
    {
        let _ = canonical_agent_dir;
        Ok(())
    }
}

fn retire_one_legacy_file(
    path: &Path,
    uid: u32,
    max_bytes: usize,
    expected_sha256: &str,
    label: &str,
) -> Result<()> {
    if !leaf_exists(path)? {
        return Ok(());
    }
    let bytes = read_owned_private_regular(path, uid, max_bytes, label)?;
    if sha256(&bytes) != expected_sha256 {
        bail!("{label} changed after adoption; refusing unsafe cleanup");
    }
    remove_regular_owned_file(path, uid, label)
}

fn marker_for(
    source: &Path,
    snapshot: &EnrollmentSnapshot,
    owner_bytes: &[u8],
) -> Result<AdoptionMarker> {
    let source_agent_dir = source
        .to_str()
        .ok_or_else(|| anyhow::anyhow!("legacy XDG path is not Unicode"))?
        .to_string();
    Ok(AdoptionMarker {
        schema: 1,
        source_agent_dir,
        account_id: snapshot.record.account_id.clone(),
        device_id: snapshot.record.device_id.clone(),
        key_sha256: sha256(&snapshot.key),
        record_sha256: sha256(&snapshot.record_bytes),
        owner_sha256: sha256(owner_bytes),
    })
}

fn require_nonempty_identity(value: &str, label: &str) -> Result<()> {
    if value.trim().is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn install_or_verify_marker(dir: &Path, uid: u32, marker: &AdoptionMarker) -> Result<()> {
    let path = dir.join(MARKER_FILE);
    let expected = serde_json::to_vec_pretty(marker).context("serialize adoption marker")?;
    if leaf_exists(&path)? {
        let actual = read_owned_private_regular(&path, uid, MAX_MARKER_BYTES, "adoption marker")?;
        if actual != expected {
            bail!("existing adoption marker conflicts with this migration");
        }
        return Ok(());
    }
    publish_private_no_replace(&path, &expected)
}

fn load_snapshot(dir: &Path, uid: u32, label: &str) -> Result<EnrollmentSnapshot> {
    let key = read_owned_private_regular(&dir.join(KEY_FILE), uid, MAX_KEY_BYTES, label)?;
    validate_key_bytes(&key)?;
    let record_bytes =
        read_owned_private_regular(&dir.join(RECORD_FILE), uid, MAX_RECORD_BYTES, label)?;
    let record = serde_json::from_slice(&record_bytes)
        .with_context(|| format!("{label} record is invalid"))?;
    Ok(EnrollmentSnapshot {
        key,
        record_bytes,
        record,
    })
}

fn validate_key_bytes(bytes: &[u8]) -> Result<()> {
    use base64::Engine as _;
    let text = std::str::from_utf8(bytes).context("enrollment key is not UTF-8")?;
    let trimmed = text.trim();
    let decoded = base64::engine::general_purpose::STANDARD
        .decode(trimmed)
        .context("enrollment key is not canonical base64")?;
    if decoded.len() != 32 || base64::engine::general_purpose::STANDARD.encode(decoded) != trimmed {
        bail!("enrollment key has an invalid encoding");
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn leaf_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect enrollment migration path"),
    }
}

#[cfg(unix)]
fn require_owned_directory(path: &Path, uid: u32, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        bail!("{label} has unsafe type, owner, or mode");
    }
    Ok(())
}

#[cfg(not(unix))]
fn require_owned_directory(_path: &Path, _uid: u32, _label: &str) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn ensure_owned_private_directory(path: &Path, uid: u32) -> Result<()> {
    use std::os::unix::fs::{DirBuilderExt as _, MetadataExt as _};
    if !leaf_exists(path)? {
        let mut builder = fs::DirBuilder::new();
        builder.recursive(true).mode(0o700);
        builder
            .create(path)
            .context("create fixed enrollment directory")?;
    }
    let metadata = fs::symlink_metadata(path).context("inspect fixed enrollment directory")?;
    if !metadata.file_type().is_dir() || metadata.uid() != uid || metadata.mode() & 0o022 != 0 {
        bail!("fixed enrollment directory has unsafe type, owner, or mode");
    }
    Ok(())
}

#[cfg(not(unix))]
fn ensure_owned_private_directory(path: &Path, _uid: u32) -> Result<()> {
    fs::create_dir_all(path).context("create fixed enrollment directory")
}

#[cfg(unix)]
fn read_owned_private_regular(path: &Path, uid: u32, max: usize, label: &str) -> Result<Vec<u8>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
    let mut options = OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK);
    let file = options
        .open(path)
        .with_context(|| format!("open {label}"))?;
    let metadata = file
        .metadata()
        .with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_file()
        || metadata.uid() != uid
        || metadata.nlink() != 1
        || metadata.mode() & 0o077 != 0
        || metadata.len() > max as u64
    {
        bail!("{label} has unsafe type, owner, mode, link count, or size");
    }
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    file.take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .with_context(|| format!("read {label}"))?;
    if bytes.len() > max {
        bail!("{label} exceeds its size limit");
    }
    Ok(bytes)
}

#[cfg(not(unix))]
fn read_owned_private_regular(path: &Path, _uid: u32, max: usize, label: &str) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    File::open(path)
        .with_context(|| format!("open {label}"))?
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        bail!("{label} exceeds its size limit");
    }
    Ok(bytes)
}

fn publish_private_no_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("enrollment publication has no parent"))?;
    let name = path
        .file_name()
        .and_then(|name| name.to_str())
        .ok_or_else(|| anyhow::anyhow!("enrollment publication filename is invalid"))?;
    let temporary = parent.join(format!(
        ".{name}.migrate.{}.{}",
        std::process::id(),
        TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let result = (|| -> Result<()> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
        }
        let mut file = options
            .open(&temporary)
            .context("create migration temporary file")?;
        file.write_all(bytes)
            .context("write migration temporary file")?;
        file.sync_all().context("sync migration temporary file")?;
        drop(file);
        rename_no_replace(&temporary, path).context("publish migrated enrollment file")?;
        File::open(parent)
            .and_then(|directory| directory.sync_all())
            .context("sync enrollment directory")?;
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(target_os = "linux")]
fn rename_no_replace(source: &Path, target: &Path) -> std::io::Result<()> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    let source = CString::new(source.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "migration source path contains a NUL byte",
        )
    })?;
    let target = CString::new(target.as_os_str().as_bytes()).map_err(|_| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "migration target path contains a NUL byte",
        )
    })?;
    // SAFETY: both C strings remain live for the syscall and RENAME_NOREPLACE
    // is an atomic no-clobber publication on Linux.
    let result = unsafe {
        libc::syscall(
            libc::SYS_renameat2,
            libc::AT_FDCWD,
            source.as_ptr(),
            libc::AT_FDCWD,
            target.as_ptr(),
            libc::RENAME_NOREPLACE,
        )
    };
    if result == 0 {
        Ok(())
    } else {
        Err(std::io::Error::last_os_error())
    }
}

#[cfg(not(target_os = "linux"))]
fn rename_no_replace(source: &Path, target: &Path) -> std::io::Result<()> {
    fs::hard_link(source, target)?;
    fs::remove_file(source)
}

#[cfg(unix)]
fn remove_regular_owned_file(path: &Path, uid: u32, label: &str) -> Result<()> {
    use std::os::unix::fs::MetadataExt as _;
    let metadata = fs::symlink_metadata(path).with_context(|| format!("inspect {label}"))?;
    if !metadata.file_type().is_file() || metadata.uid() != uid || metadata.nlink() != 1 {
        bail!("{label} has unsafe type, owner, or link count");
    }
    let parent = path
        .parent()
        .ok_or_else(|| anyhow::anyhow!("{label} has no parent directory"))?;
    fs::remove_file(path).with_context(|| format!("remove {label}"))?;
    fs::File::open(parent)
        .with_context(|| format!("open {label} parent after removal"))?
        .sync_all()
        .with_context(|| format!("sync {label} parent after removal"))?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Ok(_) => bail!("{label} still exists after durable removal"),
        Err(error) => Err(error).with_context(|| format!("prove {label} absence after removal")),
    }
}

#[cfg(test)]
fn adopt_from_legacy_data_home(
    canonical_agent_dir: &Path,
    legacy_data_home: &Path,
    uid: u32,
) -> Result<AdoptionOutcome> {
    adopt_from_legacy_agent_dir(
        canonical_agent_dir,
        Some(&legacy_data_home.join("hydra-agent")),
        uid,
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt as _;

    fn fixture(label: &str) -> (tempfile::TempDir, PathBuf, PathBuf) {
        // macOS commonly points TMPDIR at /var/folders/... whose intermediate
        // directories are group-writable without the sticky bit. Production
        // authority validation must reject that ancestry; the fixture must not
        // accidentally depend on it. Use the kernel-protected shared /tmp root
        // (canonicalized to /private/tmp on macOS) and make the test-owned leaf
        // private before creating any authority-bearing descendants.
        let root =
            crate::agent_dir::secure_authority_test_dir(&format!("hydra-xdg-adopt-{label}-"));
        let legacy_base = root.path().join("legacy-data");
        let legacy = legacy_base.join("hydra-agent");
        let target = root.path().join("fixed/hydra-agent");
        fs::create_dir_all(&legacy).unwrap();
        fs::set_permissions(&legacy, fs::Permissions::from_mode(0o700)).unwrap();
        let key = crate::device_identity::load_or_create_key(&legacy).unwrap();
        let record = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_migration".to_string(),
            account_id: "acct_synthetic_migration".to_string(),
            cloud_base: crate::release_trust::CLOUD_BASE.to_string(),
            passkey: None,
        };
        crate::device_identity::save_record(&legacy, &record).unwrap();
        assert_eq!(
            crate::device_identity::load_key(&legacy)
                .unwrap()
                .unwrap()
                .to_bytes(),
            key.to_bytes()
        );
        (root, legacy_base, target)
    }

    fn lifecycle_lock_set_for(target: &Path) -> crate::service::LifecycleLockSet {
        crate::service::LifecycleLockSet::acquire(adoption_lock_roots(target, None).unwrap())
            .unwrap()
    }

    #[cfg(unix)]
    #[test]
    fn existing_safe_canonical_directory_keeps_inode_and_mode() {
        use std::os::unix::fs::MetadataExt as _;

        for mode in [0o750, 0o755] {
            let root = crate::agent_dir::secure_authority_test_dir(&format!(
                "hydra-xdg-existing-safe-{mode:o}-"
            ));
            let target = root.path().join("fixed/hydra-agent");
            fs::create_dir_all(&target).unwrap();
            fs::set_permissions(&target, fs::Permissions::from_mode(mode)).unwrap();
            let before = fs::symlink_metadata(&target).unwrap();

            assert_eq!(
                adopt_from_legacy_agent_dir(&target, None, crate::agent_dir::trusted_uid(),)
                    .unwrap(),
                AdoptionOutcome::NoLegacyEnrollment
            );

            let after = fs::symlink_metadata(&target).unwrap();
            assert_eq!(after.dev(), before.dev());
            assert_eq!(after.ino(), before.ino());
            assert_eq!(after.uid(), before.uid());
            assert_eq!(after.mode() & 0o777, mode);
        }
    }

    fn corrupt_remove_tombstone(
        target: &Path,
        snapshot: &CorruptEnrollmentSnapshot,
        locks: &crate::service::LifecycleLockSet,
    ) -> crate::lifecycle_cleanup::CleanupTombstone {
        let target = fs::canonicalize(target).unwrap();
        let record = crate::lifecycle_cleanup::ExactFileEvidence::capture(
            &target,
            &target.join(RECORD_FILE),
            crate::lifecycle_cleanup::LifecycleFileKind::CanonicalRecord,
            locks,
        )
        .unwrap()
        .unwrap();
        #[cfg(target_os = "macos")]
        let unit = target
            .parent()
            .unwrap()
            .join("LaunchAgents/com.hydra.agent.plist");
        #[cfg(not(target_os = "macos"))]
        let unit = target.parent().unwrap().join("systemd/hydra-agent.service");
        let roots = std::collections::BTreeSet::from([target.clone()]);
        crate::lifecycle_cleanup::CleanupTombstone::new(
            crate::lifecycle_cleanup::CleanupIntent::Remove,
            crate::lifecycle_cleanup::PriorActivation::ProvenOpen,
            crate::lifecycle_cleanup::AuthorityEvidence::unavailable_corrupt(
                snapshot.owner_bytes(),
                snapshot.record_bytes(),
            )
            .unwrap(),
            &target,
            &roots,
            &roots,
            [],
            [record],
            crate::lifecycle_cleanup::DesiredUnit::from_bytes(&unit, b"synthetic desired service")
                .unwrap(),
            None,
            locks,
        )
        .unwrap()
    }

    fn copy_private(source: &Path, target: &Path) {
        fs::create_dir_all(target.parent().unwrap()).unwrap();
        fs::set_permissions(target.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::copy(source, target).unwrap();
        fs::set_permissions(target, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn assert_complete_target(target: &Path) {
        for name in [KEY_FILE, RECORD_FILE, OWNER_FILE, MARKER_FILE] {
            assert!(target.join(name).is_file(), "missing {name}");
        }
        let record: crate::device_identity::DeviceRecord =
            serde_json::from_slice(&fs::read(target.join(RECORD_FILE)).unwrap()).unwrap();
        crate::device_identity::claim_or_verify_owner_for_record(target, &record).unwrap();
        assert!(!crate::device_identity::verified_owner_marker_bytes(target)
            .unwrap()
            .is_empty());
    }

    #[test]
    fn exact_pair_is_adopted_once_and_read_back_idempotently() {
        let (_root, legacy_base, target) = fixture("success");
        let uid = crate::agent_dir::trusted_uid();
        assert_eq!(
            adopt_from_legacy_data_home(&target, &legacy_base, uid).unwrap(),
            AdoptionOutcome::Adopted
        );
        assert_eq!(
            adopt_from_legacy_data_home(&target, &legacy_base, uid).unwrap(),
            AdoptionOutcome::AlreadyAdopted
        );
        assert_eq!(
            fs::read(target.join(KEY_FILE)).unwrap(),
            fs::read(legacy_base.join("hydra-agent").join(KEY_FILE)).unwrap()
        );
        assert_complete_target(&target);
    }

    #[test]
    fn legacy_adoption_never_imports_private_enrollment_diagnostics() {
        let (_root, legacy_base, target) = fixture("diagnostics-not-imported");
        let source = legacy_base.join("hydra-agent");
        let diagnostics = source.join(crate::device_identity::ENROLLMENT_DIAGNOSTICS_FILE);
        let diagnostics_temporary =
            source.join(crate::device_identity::ENROLLMENT_DIAGNOSTICS_TEMP_FILE);
        fs::write(&diagnostics, br#"{"version":1,"events":[]}"#).unwrap();
        fs::write(&diagnostics_temporary, b"crash-before-rename").unwrap();
        fs::set_permissions(&diagnostics, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&diagnostics_temporary, fs::Permissions::from_mode(0o600)).unwrap();

        assert_eq!(
            adopt_from_legacy_data_home(&target, &legacy_base, crate::agent_dir::trusted_uid())
                .unwrap(),
            AdoptionOutcome::Adopted
        );
        assert!(
            diagnostics.exists(),
            "legacy diagnostics remain inert at source"
        );
        assert!(
            diagnostics_temporary.exists(),
            "legacy diagnostic temporary remains inert at source"
        );
        for name in [
            crate::device_identity::ENROLLMENT_DIAGNOSTICS_FILE,
            crate::device_identity::ENROLLMENT_DIAGNOSTICS_TEMP_FILE,
        ] {
            assert!(!target.join(name).exists());
        }
    }

    #[test]
    fn completed_marker_is_authoritative_when_xdg_is_unset_or_changed() {
        let (root, legacy_base, target) = fixture("marker-authority");
        let uid = crate::agent_dir::trusted_uid();
        assert_eq!(
            adopt_from_legacy_data_home(&target, &legacy_base, uid).unwrap(),
            AdoptionOutcome::Adopted
        );

        assert_eq!(
            adopt_from_legacy_agent_dir(&target, None, uid).unwrap(),
            AdoptionOutcome::AlreadyAdopted
        );
        let changed = root.path().join("different-data/hydra-agent");
        assert_eq!(
            adopt_from_legacy_agent_dir(&target, Some(&changed), uid).unwrap(),
            AdoptionOutcome::AlreadyAdopted
        );
        assert_complete_target(&target);
    }

    #[test]
    fn completed_marker_exposes_only_its_verified_exact_source() {
        let (_root, legacy_base, target) = fixture("verified-marker-source");
        let source = legacy_base.join("hydra-agent");
        adopt_from_legacy_agent_dir(&target, Some(&source), crate::agent_dir::trusted_uid())
            .unwrap();

        let lock = crate::service::LifecycleLock::acquire(&target).unwrap();
        assert_eq!(
            verified_completed_legacy_source(&target, &lock).unwrap(),
            Some(source)
        );
    }

    #[cfg(unix)]
    #[test]
    fn canonical_aliases_are_rejected_and_can_never_delete_canonical_credentials() {
        use std::os::unix::fs::symlink;

        let (root, legacy_base, target) = fixture("canonical-alias");
        let uid = crate::agent_dir::trusted_uid();
        fs::create_dir_all(target.parent().unwrap().join("spare")).unwrap();
        let parent_alias = target.parent().unwrap().join("spare/../hydra-agent");
        assert!(adopt_from_legacy_agent_dir(&target, Some(&parent_alias), uid).is_err());

        let symlinked_parent = root.path().join("alias-fixed");
        symlink(target.parent().unwrap(), &symlinked_parent).unwrap();
        let symlink_alias = symlinked_parent.join("hydra-agent");
        assert!(adopt_from_legacy_agent_dir(&target, Some(&symlink_alias), uid).is_err());

        let source = legacy_base.join("hydra-agent");
        adopt_from_legacy_agent_dir(&target, Some(&source), uid).unwrap();
        let marker_path = target.join(MARKER_FILE);
        let mut marker: AdoptionMarker =
            serde_json::from_slice(&fs::read(&marker_path).unwrap()).unwrap();
        marker.source_agent_dir = symlink_alias.to_string_lossy().into_owned();
        fs::write(&marker_path, serde_json::to_vec_pretty(&marker).unwrap()).unwrap();
        fs::set_permissions(&marker_path, fs::Permissions::from_mode(0o600)).unwrap();

        let lock = crate::service::LifecycleLock::acquire(&target).unwrap();
        assert!(verified_completed_legacy_source(&target, &lock).is_err());
        drop(lock);
        crate::device_identity::remove_record(&target).unwrap();
        let locks = crate::service::LifecycleLockSet::acquire([target.clone()]).unwrap();
        assert!(retire_adopted_legacy_enrollment(&target, &locks).is_err());
        assert!(target.join(KEY_FILE).is_file());
        assert!(target.join(OWNER_FILE).is_file());
        assert!(marker_path.is_file());
    }

    #[test]
    fn retired_owner_cannot_be_bypassed_by_a_raw_record_write() {
        let (_root, legacy_base, target) = fixture("retained-account-boundary");
        let uid = crate::agent_dir::trusted_uid();
        let exact_service_source = legacy_base.join("hydra-agent");
        assert_eq!(
            adopt_from_legacy_agent_dir(&target, Some(&exact_service_source), uid).unwrap(),
            AdoptionOutcome::Adopted
        );

        // Cloud revocation/removal can retire the replaceable record while the
        // independently owned daemon keeps A's PTYs. Migration leaves the
        // retired owner for the explicit fresh-code enrollment path to release;
        // a lower-level record write cannot bypass that lifecycle boundary.
        crate::device_identity::remove_record(&target).unwrap();
        assert_eq!(
            adopt_from_legacy_agent_dir(&target, None, uid).unwrap(),
            AdoptionOutcome::NoLegacyEnrollment
        );

        let account_b = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_b".into(),
            account_id: "acct_synthetic_b".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        let error = crate::device_identity::save_record(&target, &account_b)
            .unwrap_err()
            .to_string();
        assert!(error.contains("explicit fresh-code enrollment"));
        assert!(!target.join(RECORD_FILE).exists());
        assert!(target.join(OWNER_FILE).is_file());
    }

    #[test]
    fn no_proven_source_allows_first_local_binding_then_denies_transfer() {
        let root = crate::agent_dir::secure_authority_test_dir("hydra-first-local-binding-");
        let target = root.path().join("fixed/hydra-agent");
        let uid = crate::agent_dir::trusted_uid();

        // Existing local PTYs carry no remote-account fact. With no installed
        // or running old service source, first enrollment is therefore allowed.
        assert_eq!(
            adopt_from_legacy_agent_dir(&target, None, uid).unwrap(),
            AdoptionOutcome::NoLegacyEnrollment
        );
        crate::device_identity::load_or_create_key(&target).unwrap();
        let first = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_local_first".into(),
            account_id: "acct_synthetic_local_first".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::save_record(&target, &first).unwrap();
        crate::device_identity::remove_record(&target).unwrap();

        let other = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_local_other".into(),
            account_id: "acct_synthetic_local_other".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        assert!(crate::device_identity::save_record(&target, &other).is_err());
    }

    #[test]
    fn legacy_key_only_residue_is_adopted_without_inventing_an_owner() {
        let (_root, legacy_base, target) = fixture("key-only-residue");
        let source = legacy_base.join("hydra-agent");
        fs::remove_file(source.join(RECORD_FILE)).unwrap();
        fs::remove_file(source.join(OWNER_FILE)).unwrap();

        assert_eq!(
            adopt_from_legacy_agent_dir(&target, Some(&source), crate::agent_dir::trusted_uid())
                .unwrap(),
            AdoptionOutcome::Adopted
        );
        assert!(target.join(KEY_FILE).is_file());
        assert!(!target.join(RECORD_FILE).exists());
        assert!(!target.join(OWNER_FILE).exists());
        assert!(!target.join(MARKER_FILE).exists());

        let first_owner = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_first".into(),
            account_id: "acct_synthetic_first".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::save_record(&target, &first_owner).unwrap();
    }

    #[test]
    fn legacy_owner_only_residue_is_ignored_and_does_not_block_account_b() {
        let (_root, legacy_base, target) = fixture("owner-only-residue");
        let source = legacy_base.join("hydra-agent");
        fs::remove_file(source.join(KEY_FILE)).unwrap();
        fs::remove_file(source.join(RECORD_FILE)).unwrap();
        let source_owner = fs::read(source.join(OWNER_FILE)).unwrap();

        assert_eq!(
            adopt_from_legacy_agent_dir(&target, Some(&source), crate::agent_dir::trusted_uid())
                .unwrap(),
            AdoptionOutcome::NoLegacyEnrollment
        );
        for name in [KEY_FILE, RECORD_FILE, OWNER_FILE, MARKER_FILE] {
            assert!(!target.join(name).exists(), "unexpected canonical {name}");
        }
        assert_eq!(fs::read(source.join(OWNER_FILE)).unwrap(), source_owner);

        crate::device_identity::load_or_create_key(&target).unwrap();
        let account_b = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_owner_only_b".into(),
            account_id: "acct_synthetic_owner_only_b".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::save_record(&target, &account_b).unwrap();
        let adopted: crate::device_identity::DeviceRecord =
            serde_json::from_slice(&fs::read(target.join(RECORD_FILE)).unwrap()).unwrap();
        assert_eq!(adopted.account_id, account_b.account_id);
    }

    #[test]
    fn legacy_owner_and_key_without_record_adopts_key_but_not_retired_owner() {
        let (_root, legacy_base, target) = fixture("owner-key-residue");
        let source = legacy_base.join("hydra-agent");
        let source_key = fs::read(source.join(KEY_FILE)).unwrap();
        let source_owner = fs::read(source.join(OWNER_FILE)).unwrap();
        fs::remove_file(source.join(RECORD_FILE)).unwrap();

        assert_eq!(
            adopt_from_legacy_agent_dir(&target, Some(&source), crate::agent_dir::trusted_uid())
                .unwrap(),
            AdoptionOutcome::Adopted
        );
        assert_eq!(fs::read(target.join(KEY_FILE)).unwrap(), source_key);
        assert!(!target.join(OWNER_FILE).exists());
        assert!(!target.join(RECORD_FILE).exists());
        assert_eq!(fs::read(source.join(OWNER_FILE)).unwrap(), source_owner);

        let account_b = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_b".into(),
            account_id: "acct_synthetic_b".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::save_record(&target, &account_b).unwrap();
        let adopted: crate::device_identity::DeviceRecord =
            serde_json::from_slice(&fs::read(target.join(RECORD_FILE)).unwrap()).unwrap();
        assert_eq!(adopted.account_id, account_b.account_id);
        let owner: serde_json::Value =
            serde_json::from_slice(&fs::read(target.join(OWNER_FILE)).unwrap()).unwrap();
        assert_eq!(owner["account_id"], account_b.account_id);
    }

    #[test]
    fn complete_canonical_new_account_ignores_recordless_legacy_owner() {
        let (_root, legacy_base, target) = fixture("canonical-new-account-retired-owner");
        let source = legacy_base.join("hydra-agent");
        fs::remove_file(source.join(RECORD_FILE)).unwrap();
        let source_owner = fs::read(source.join(OWNER_FILE)).unwrap();

        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        crate::device_identity::load_or_create_key(&target).unwrap();
        let account_b = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_canonical_b".into(),
            account_id: "acct_synthetic_canonical_b".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::save_record(&target, &account_b).unwrap();
        let before_key = fs::read(target.join(KEY_FILE)).unwrap();
        let before_record = fs::read(target.join(RECORD_FILE)).unwrap();
        let before_owner = fs::read(target.join(OWNER_FILE)).unwrap();

        assert_eq!(
            adopt_from_legacy_agent_dir(&target, Some(&source), crate::agent_dir::trusted_uid(),)
                .unwrap(),
            AdoptionOutcome::AlreadyCanonical
        );
        assert_eq!(fs::read(target.join(KEY_FILE)).unwrap(), before_key);
        assert_eq!(fs::read(target.join(RECORD_FILE)).unwrap(), before_record);
        assert_eq!(fs::read(target.join(OWNER_FILE)).unwrap(), before_owner);
        assert!(!target.join(MARKER_FILE).exists());
        assert_eq!(fs::read(source.join(OWNER_FILE)).unwrap(), source_owner);
    }

    #[test]
    fn explicit_remove_recovers_corrupt_record_only_with_durable_owner() {
        let (_root, _legacy_base, target) = fixture("corrupt-recovery");
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let account_a = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_corrupt_a".into(),
            account_id: "acct_synthetic_corrupt_a".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::load_or_create_key(&target).unwrap();
        crate::device_identity::save_record(&target, &account_a).unwrap();
        fs::write(target.join(RECORD_FILE), b"{not-json").unwrap();
        fs::set_permissions(target.join(RECORD_FILE), fs::Permissions::from_mode(0o600)).unwrap();

        let locks = crate::service::LifecycleLockSet::acquire([target.clone()]).unwrap();
        let lock = locks.lock_for(&target).unwrap();
        let snapshot = snapshot_corrupt_canonical_for_remove(&target, lock)
            .unwrap()
            .unwrap();
        let tombstone = corrupt_remove_tombstone(&target, &snapshot, &locks);
        assert_eq!(
            snapshot.canonical_agent_dir(),
            fs::canonicalize(&target).unwrap()
        );
        assert_eq!(snapshot.record_bytes(), b"{not-json");
        assert!(!snapshot.owner_bytes().is_empty());
        assert!(target.join(RECORD_FILE).is_file());
        assert!(target.join(OWNER_FILE).is_file());
        assert!(
            recover_corrupt_canonical_for_remove(&target, &snapshot, &tombstone, &locks,).is_err()
        );
        assert!(target.join(RECORD_FILE).is_file());
        let durable = crate::lifecycle_cleanup::store(&target, &tombstone, &locks).unwrap();
        assert_eq!(
            recover_corrupt_canonical_for_remove(&target, &snapshot, &durable, &locks).unwrap(),
            CorruptRecoveryOutcome::Recovered
        );
        assert!(!target.join(RECORD_FILE).exists());
        assert!(target.join(OWNER_FILE).exists());

        let account_b = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_corrupt_b".into(),
            account_id: "acct_synthetic_corrupt_b".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        assert!(crate::device_identity::save_record(&target, &account_b).is_err());
    }

    #[test]
    fn corrupt_remove_unlink_before_proof_resumes_through_already_absent() {
        let (_root, _legacy_base, target) = fixture("corrupt-unlink-before-proof");
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let owner_record = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_corrupt_resume".into(),
            account_id: "acct_synthetic_corrupt_resume".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::load_or_create_key(&target).unwrap();
        crate::device_identity::save_record(&target, &owner_record).unwrap();
        fs::write(target.join(RECORD_FILE), b"{corrupt-resume").unwrap();
        fs::set_permissions(target.join(RECORD_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        let locks = crate::service::LifecycleLockSet::acquire([target.clone()]).unwrap();
        let lock = locks.lock_for(&target).unwrap();
        let snapshot = snapshot_corrupt_canonical_for_remove(&target, lock)
            .unwrap()
            .unwrap();
        let proposed = corrupt_remove_tombstone(&target, &snapshot, &locks);
        let durable = crate::lifecycle_cleanup::store(&target, &proposed, &locks).unwrap();
        let record_path = durable
            .deletion_targets()
            .find(|planned| {
                planned.evidence().kind()
                    == crate::lifecycle_cleanup::LifecycleFileKind::CanonicalRecord
            })
            .unwrap()
            .evidence()
            .path();
        // Simulate the exact crash boundary: the precommitted target was
        // unlinked, but the lifecycle journal did not yet record its durable
        // absence. Production has no raw-unlink API; recovery must resume the
        // journaled deletion through its AlreadyAbsent path.
        fs::remove_file(&record_path).unwrap();
        assert!(!record_path.exists());
        assert_eq!(
            recover_corrupt_canonical_for_remove(&target, &snapshot, &durable, &locks).unwrap(),
            CorruptRecoveryOutcome::Recovered
        );
        let completed = crate::lifecycle_cleanup::load(&target).unwrap().unwrap();
        assert!(completed.all_deletions_proven());
        assert!(target.join(OWNER_FILE).is_file());
    }

    #[test]
    fn corrupt_record_without_independent_owner_remains_fail_closed() {
        let root = crate::agent_dir::secure_authority_test_dir("hydra-corrupt-unowned-");
        let target = root.path().join("fixed/hydra-agent");
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        fs::write(target.join(RECORD_FILE), b"{not-json").unwrap();
        fs::set_permissions(target.join(RECORD_FILE), fs::Permissions::from_mode(0o600)).unwrap();

        let lock = crate::service::LifecycleLock::acquire(&target).unwrap();
        assert!(snapshot_corrupt_canonical_for_remove(&target, &lock).is_err());
        assert!(target.join(RECORD_FILE).exists());
        assert!(
            adopt_from_legacy_agent_dir(&target, None, crate::agent_dir::trusted_uid()).is_err()
        );
    }

    #[test]
    fn corrupt_snapshot_and_migration_helpers_reject_a_lock_for_another_root() {
        let root = crate::agent_dir::secure_authority_test_dir("hydra-corrupt-wrong-lock-");
        let first = root.path().join("first/hydra-agent");
        let second = root.path().join("second/hydra-agent");
        fs::create_dir_all(&first).unwrap();
        fs::create_dir_all(&second).unwrap();
        fs::set_permissions(&first, fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&second, fs::Permissions::from_mode(0o700)).unwrap();
        let owner_record = crate::device_identity::DeviceRecord {
            device_id: "dev_synthetic_wrong_lock".into(),
            account_id: "acct_synthetic_wrong_lock".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::load_or_create_key(&first).unwrap();
        crate::device_identity::save_record(&first, &owner_record).unwrap();
        fs::write(first.join(RECORD_FILE), b"{wrong-lock-corrupt").unwrap();
        fs::set_permissions(first.join(RECORD_FILE), fs::Permissions::from_mode(0o600)).unwrap();
        let wrong_locks = crate::service::LifecycleLockSet::acquire([first.clone()]).unwrap();
        let lock = wrong_locks.lock_for(&first).unwrap();
        let first_snapshot = snapshot_corrupt_canonical_for_remove(&first, lock)
            .unwrap()
            .unwrap();
        let first_tombstone = corrupt_remove_tombstone(&first, &first_snapshot, &wrong_locks);
        let synthetic_snapshot = CorruptEnrollmentSnapshot {
            canonical_agent_dir: fs::canonicalize(&second).unwrap(),
            owner_bytes: b"synthetic owner".to_vec(),
            record_bytes: b"{synthetic corrupt".to_vec(),
        };

        assert!(snapshot_corrupt_canonical_for_remove(&second, lock).is_err());
        assert!(recover_corrupt_canonical_for_remove(
            &second,
            &synthetic_snapshot,
            &first_tombstone,
            &wrong_locks,
        )
        .is_err());
        assert!(verified_completed_legacy_source(&second, lock).is_err());
        assert!(adopt_proven_legacy_xdg_enrollment(&second, None, &wrong_locks).is_err());
    }

    #[test]
    fn crash_boundaries_key_only_record_only_and_owner_only_resume_idempotently() {
        for state in ["key-only", "record-only", "owner-only"] {
            let (_root, legacy_base, target) = fixture(state);
            let source = legacy_base.join("hydra-agent");
            match state {
                "key-only" => copy_private(&source.join(KEY_FILE), &target.join(KEY_FILE)),
                "record-only" => copy_private(&source.join(RECORD_FILE), &target.join(RECORD_FILE)),
                "owner-only" => {
                    fs::create_dir_all(&target).unwrap();
                    fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
                    let record: crate::device_identity::DeviceRecord =
                        serde_json::from_slice(&fs::read(source.join(RECORD_FILE)).unwrap())
                            .unwrap();
                    crate::device_identity::claim_or_verify_owner_for_record(&target, &record)
                        .unwrap();
                }
                _ => unreachable!(),
            }
            assert_eq!(
                adopt_from_legacy_data_home(
                    &target,
                    &legacy_base,
                    crate::agent_dir::trusted_uid(),
                )
                .unwrap(),
                AdoptionOutcome::Adopted,
                "state {state}",
            );
            assert_complete_target(&target);
            assert_eq!(
                adopt_from_legacy_data_home(
                    &target,
                    &legacy_base,
                    crate::agent_dir::trusted_uid(),
                )
                .unwrap(),
                AdoptionOutcome::AlreadyAdopted,
            );
        }
    }

    #[test]
    fn crash_after_complete_copy_before_marker_is_completed_and_removable() {
        let (_root, legacy_base, target) = fixture("complete-before-marker");
        let source = legacy_base.join("hydra-agent");
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let record: crate::device_identity::DeviceRecord =
            serde_json::from_slice(&fs::read(source.join(RECORD_FILE)).unwrap()).unwrap();
        crate::device_identity::claim_or_verify_owner_for_record(&target, &record).unwrap();
        copy_private(&source.join(KEY_FILE), &target.join(KEY_FILE));
        crate::device_identity::save_record(&target, &record).unwrap();
        assert!(!target.join(MARKER_FILE).exists());

        assert_eq!(
            adopt_from_legacy_agent_dir(&target, Some(&source), crate::agent_dir::trusted_uid(),)
                .unwrap(),
            AdoptionOutcome::AlreadyAdopted
        );
        assert!(target.join(MARKER_FILE).is_file());

        crate::device_identity::remove_record(&target).unwrap();
        let locks = lifecycle_lock_set_for(&target);
        retire_adopted_legacy_enrollment(&target, &locks).unwrap();
        assert!(!source.join(KEY_FILE).exists());
        assert!(!source.join(RECORD_FILE).exists());
        assert!(!target.join(MARKER_FILE).exists());
    }

    #[test]
    fn owner_marker_collision_is_refused_before_credential_publication() {
        let (_root, legacy_base, target) = fixture("owner-collision");
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let wrong = crate::device_identity::DeviceRecord {
            device_id: "dev_other".into(),
            account_id: "acct_other".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::save_record(&target, &wrong).unwrap();
        fs::remove_file(target.join(RECORD_FILE)).unwrap();
        assert!(adopt_from_legacy_data_home(
            &target,
            &legacy_base,
            crate::agent_dir::trusted_uid(),
        )
        .is_err());
        assert!(!target.join(KEY_FILE).exists());
        assert!(!target.join(RECORD_FILE).exists());
    }

    #[test]
    fn complete_canonical_wins_without_source_but_conflicting_proven_source_fails() {
        let (_root, legacy_base, target) = fixture("collision");
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let other = crate::device_identity::DeviceRecord {
            device_id: "dev_other".into(),
            account_id: "acct_other".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::save_record(&target, &other).unwrap();
        crate::device_identity::load_or_create_key(&target).unwrap();
        let before_key = fs::read(target.join(KEY_FILE)).unwrap();
        let before_record = fs::read(target.join(RECORD_FILE)).unwrap();
        assert_eq!(
            adopt_from_legacy_agent_dir(&target, None, crate::agent_dir::trusted_uid()).unwrap(),
            AdoptionOutcome::AlreadyCanonical
        );
        assert_eq!(fs::read(target.join(KEY_FILE)).unwrap(), before_key);
        assert_eq!(fs::read(target.join(RECORD_FILE)).unwrap(), before_record);
        assert!(adopt_from_legacy_agent_dir(
            &target,
            Some(&legacy_base.join("hydra-agent")),
            crate::agent_dir::trusted_uid(),
        )
        .is_err());
        assert_eq!(fs::read(target.join(KEY_FILE)).unwrap(), before_key);
        assert_eq!(fs::read(target.join(RECORD_FILE)).unwrap(), before_record);
    }

    #[test]
    fn complete_canonical_refuses_a_proven_record_without_its_key() {
        let (_root, legacy_base, target) = fixture("canonical-partial-legacy");
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        let canonical = crate::device_identity::DeviceRecord {
            device_id: "dev_current".into(),
            account_id: "acct_current".into(),
            cloud_base: crate::release_trust::CLOUD_BASE.into(),
            passkey: None,
        };
        crate::device_identity::load_or_create_key(&target).unwrap();
        crate::device_identity::save_record(&target, &canonical).unwrap();
        let before_key = fs::read(target.join(KEY_FILE)).unwrap();
        let before_record = fs::read(target.join(RECORD_FILE)).unwrap();
        fs::remove_file(legacy_base.join("hydra-agent").join(KEY_FILE)).unwrap();

        assert!(adopt_from_legacy_data_home(
            &target,
            &legacy_base,
            crate::agent_dir::trusted_uid(),
        )
        .is_err());
        assert_eq!(fs::read(target.join(KEY_FILE)).unwrap(), before_key);
        assert_eq!(fs::read(target.join(RECORD_FILE)).unwrap(), before_record);
    }

    #[test]
    fn exact_marker_tolerates_partial_legacy_cleanup_after_adoption() {
        let (_root, legacy_base, target) = fixture("marked-partial-legacy");
        let uid = crate::agent_dir::trusted_uid();
        assert_eq!(
            adopt_from_legacy_data_home(&target, &legacy_base, uid).unwrap(),
            AdoptionOutcome::Adopted,
        );
        fs::remove_file(legacy_base.join("hydra-agent").join(KEY_FILE)).unwrap();
        assert_eq!(
            adopt_from_legacy_data_home(&target, &legacy_base, uid).unwrap(),
            AdoptionOutcome::AlreadyAdopted,
        );
        assert_complete_target(&target);
    }

    #[test]
    fn exact_marker_completes_partial_legacy_retirement_after_remove() {
        let (_root, legacy_base, target) = fixture("interrupted-retirement");
        let uid = crate::agent_dir::trusted_uid();
        adopt_from_legacy_data_home(&target, &legacy_base, uid).unwrap();
        crate::device_identity::preserve_owner_marker(&target).unwrap();
        crate::device_identity::remove_record(&target).unwrap();
        fs::remove_file(legacy_base.join("hydra-agent").join(RECORD_FILE)).unwrap();

        assert_eq!(
            adopt_from_legacy_data_home(&target, &legacy_base, uid).unwrap(),
            AdoptionOutcome::NoLegacyEnrollment,
        );
        assert!(!legacy_base.join("hydra-agent").join(KEY_FILE).exists());
        assert!(!target.join(MARKER_FILE).exists());
        assert!(!target.join(RECORD_FILE).exists());
        assert!(target.join(KEY_FILE).is_file());
        assert!(target.join(OWNER_FILE).is_file());
    }

    #[cfg(unix)]
    #[test]
    fn explicit_retry_of_nonblocking_lock_serializes_concurrent_adoption() {
        use std::sync::{Arc, Barrier};

        let (_root, legacy_base, target) = fixture("concurrent");
        // Lifecycle locks bind an already-canonical authority root. Production
        // preflight establishes that root before concurrent lifecycle work;
        // mirror the same ordering here so this remains a serialization test,
        // not a race to create the lock directory.
        fs::create_dir_all(&target).unwrap();
        fs::set_permissions(target.parent().unwrap(), fs::Permissions::from_mode(0o700)).unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o700)).unwrap();
        crate::agent_dir::ensure_owned_safe_authority_directory(&target).unwrap();
        let barrier = Arc::new(Barrier::new(2));
        let mut workers = Vec::new();
        for _ in 0..2 {
            let barrier = Arc::clone(&barrier);
            let legacy_base = legacy_base.clone();
            let target = target.clone();
            workers.push(std::thread::spawn(move || {
                barrier.wait();
                let _lock = loop {
                    match crate::service::LifecycleLock::acquire(&target) {
                        Ok(lock) => break lock,
                        Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::yield_now();
                        }
                        Err(error) => panic!("unexpected lifecycle lock error: {error}"),
                    }
                };
                adopt_from_legacy_data_home(&target, &legacy_base, crate::agent_dir::trusted_uid())
                    .unwrap()
            }));
        }
        let outcomes: Vec<_> = workers
            .into_iter()
            .map(|worker| worker.join().unwrap())
            .collect();
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == AdoptionOutcome::Adopted)
                .count(),
            1
        );
        assert_eq!(
            outcomes
                .iter()
                .filter(|outcome| **outcome == AdoptionOutcome::AlreadyAdopted)
                .count(),
            1
        );
        assert_complete_target(&target);
    }

    #[test]
    fn symlink_loose_mode_and_hardlink_sources_are_rejected() {
        let uid = crate::agent_dir::trusted_uid();

        let (_root, legacy_base, target) = fixture("symlink");
        let legacy = legacy_base.join("hydra-agent");
        let key = legacy.join(KEY_FILE);
        let real = legacy.join("real-key");
        fs::rename(&key, &real).unwrap();
        std::os::unix::fs::symlink(&real, &key).unwrap();
        assert!(adopt_from_legacy_data_home(&target, &legacy_base, uid).is_err());

        let (_root, legacy_base, target) = fixture("mode");
        fs::set_permissions(
            legacy_base.join("hydra-agent").join(RECORD_FILE),
            fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(adopt_from_legacy_data_home(&target, &legacy_base, uid).is_err());

        let (_root, legacy_base, target) = fixture("hardlink");
        let key = legacy_base.join("hydra-agent").join(KEY_FILE);
        fs::hard_link(&key, legacy_base.join("second-key-link")).unwrap();
        assert!(adopt_from_legacy_data_home(&target, &legacy_base, uid).is_err());
    }

    #[test]
    fn remove_remote_retires_only_the_exact_adopted_legacy_pair() {
        let (_root, legacy_base, target) = fixture("retire");
        let uid = crate::agent_dir::trusted_uid();
        adopt_from_legacy_data_home(&target, &legacy_base, uid).unwrap();
        crate::device_identity::preserve_owner_marker(&target).unwrap();
        crate::device_identity::remove_record(&target).unwrap();
        let locks = lifecycle_lock_set_for(&target);
        retire_adopted_legacy_enrollment(&target, &locks).unwrap();
        let legacy = legacy_base.join("hydra-agent");
        assert!(!legacy.join(KEY_FILE).exists());
        assert!(!legacy.join(RECORD_FILE).exists());
        assert!(!target.join(MARKER_FILE).exists());
        assert!(target.join(OWNER_FILE).exists());
        drop(locks);
        let locks = lifecycle_lock_set_for(&target);
        retire_adopted_legacy_enrollment(&target, &locks).unwrap();
    }

    #[test]
    fn changed_legacy_pair_is_not_deleted_from_a_stale_marker() {
        let (_root, legacy_base, target) = fixture("changed");
        let uid = crate::agent_dir::trusted_uid();
        adopt_from_legacy_data_home(&target, &legacy_base, uid).unwrap();
        let record = legacy_base.join("hydra-agent").join(RECORD_FILE);
        fs::write(&record, b"changed").unwrap();
        fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        let locks = lifecycle_lock_set_for(&target);
        assert!(retire_adopted_legacy_enrollment(&target, &locks).is_err());
        assert!(record.exists());
    }
}
