//! Durable, inert recovery evidence for remote-lifecycle transactions.
//!
//! `device.json` is active authority. This record is never accepted by the
//! enrollment or peer paths. It lives in a dedicated owner-private directory
//! so existing 0.2.8 agent roots (which can be 0755) remain compatible while a
//! crash after authority is cut cannot erase the facts needed to finish exact,
//! idempotent cleanup.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::collections::{BTreeMap, BTreeSet};
use std::fs::{self, OpenOptions};
use std::io::{Read as _, Write as _};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const DIRECTORY_NAME: &str = "lifecycle-recovery";
pub const FILE_NAME: &str = "remote-lifecycle-cleanup.v1.json";
pub const REVOCATION_OUTBOX_FILE_NAME: &str = "provider-revocation-outbox.v1.json";
const SCHEMA: u8 = 1;
const MAX_FILE_BYTES: usize = 64 * 1024;
const MAX_PATH_BYTES: usize = 4096;
const MAX_TEXT_BYTES: usize = 2048;
const MAX_ROOTS: usize = 5;
const MAX_UNITS: usize = 8;
// Worst shape: eight observed service definitions, two readiness artifacts
// for each of five roots, and six canonical/adopted authority artifacts.
const MAX_PRE_DIAGNOSTIC_DELETION_TARGETS: usize = MAX_UNITS + (2 * MAX_ROOTS) + 6;
const MAX_ENROLLMENT_DIAGNOSTIC_DELETION_TARGETS: usize = 2;
const MAX_DELETION_TARGETS: usize =
    MAX_PRE_DIAGNOSTIC_DELETION_TARGETS + MAX_ENROLLMENT_DIAGNOSTIC_DELETION_TARGETS;
const MAX_DESIRED_UNIT_BYTES: usize = 32 * 1024;
static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CleanupIntent {
    /// Replace historical service composition with the current fixed service.
    ConvergeOpen,
    /// Stop connectivity while retaining enrollment and its stable key.
    Close,
    /// Revoke enrollment and stop connectivity; retain the stable key and
    /// owner marker until an explicit later fresh-code enrollment releases it.
    Remove,
    /// Same as Remove, then delete the stable key only after provider cleanup
    /// and every local postcondition have succeeded.
    FullForget,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PriorActivation {
    ProvenOpen,
    ProvenClosed,
    Ambiguous,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationTarget {
    cloud_base: String,
    account_id: String,
    device_id: String,
}

impl RevocationTarget {
    pub fn new(cloud_base: String, account_id: String, device_id: String) -> Result<Self> {
        let value = Self {
            cloud_base,
            account_id,
            device_id,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn cloud_base(&self) -> &str {
        &self.cloud_base
    }

    pub fn account_id(&self) -> &str {
        &self.account_id
    }

    pub fn device_id(&self) -> &str {
        &self.device_id
    }

    fn validate(&self) -> Result<()> {
        bounded_text(&self.account_id, 512, "cleanup account id")?;
        bounded_text(&self.device_id, 512, "cleanup device id")?;
        bounded_text(&self.cloud_base, MAX_TEXT_BYTES, "cleanup cloud origin")?;
        if self.cloud_base != crate::release_trust::active().validate()?.cloud_base {
            bail!("cleanup cloud origin does not match this private release");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthorityEvidence {
    NotRequested,
    Target {
        target: RevocationTarget,
        record_sha256: String,
    },
    NoActiveRecord,
    /// The active record was unreadable. This digest binds the independent
    /// durable owner proof; corrupt enrollment bytes are never parsed for IDs.
    UnavailableCorruptRecord {
        owner_sha256: String,
        record_sha256: String,
    },
}

impl AuthorityEvidence {
    /// Parse the exact active enrollment bytes that authorize this provider
    /// target, then bind those same bytes into the durable cleanup record.
    /// Callers cannot pair a target from one record with deletion evidence from
    /// another record.
    pub fn target_from_record_bytes(record_bytes: &[u8]) -> Result<Self> {
        if record_bytes.is_empty() || record_bytes.len() > 64 * 1024 {
            bail!("active enrollment record is empty or unbounded");
        }
        let record: crate::device_identity::DeviceRecord =
            serde_json::from_slice(record_bytes).context("active enrollment record is invalid")?;
        let target = RevocationTarget::new(
            record.cloud_base.trim_end_matches('/').to_string(),
            record.account_id,
            record.device_id,
        )?;
        Ok(Self::Target {
            target,
            record_sha256: sha256(record_bytes),
        })
    }

    /// Construct provider authority only from the same inode/digest-bound
    /// canonical record evidence that the cleanup journal will later retire.
    /// This prevents a caller from parsing one record while precommitting a
    /// different file as the destructive target.
    pub fn target_from_exact_record(
        evidence: &ExactFileEvidence,
        locks: &crate::service::LifecycleLockSet,
    ) -> Result<Self> {
        if evidence.kind() != LifecycleFileKind::CanonicalRecord {
            bail!("provider authority evidence is not the canonical record");
        }
        Self::target_from_record_bytes(&evidence.reverified_bytes(locks)?)
    }

    pub fn target_ref(&self) -> Option<&RevocationTarget> {
        match self {
            Self::Target { target, .. } => Some(target),
            Self::NotRequested | Self::NoActiveRecord | Self::UnavailableCorruptRecord { .. } => {
                None
            }
        }
    }

    pub fn unavailable_corrupt(owner_bytes: &[u8], record_bytes: &[u8]) -> Result<Self> {
        if owner_bytes.is_empty() || record_bytes.is_empty() || record_bytes.len() > 64 * 1024 {
            bail!("corrupt-record recovery evidence is empty or unbounded");
        }
        Ok(Self::UnavailableCorruptRecord {
            owner_sha256: sha256(owner_bytes),
            record_sha256: sha256(record_bytes),
        })
    }

    pub fn corrupt_digests(&self) -> Option<(&str, &str)> {
        match self {
            Self::UnavailableCorruptRecord {
                owner_sha256,
                record_sha256,
            } => Some((owner_sha256, record_sha256)),
            _ => None,
        }
    }

    fn validate(&self) -> Result<()> {
        match self {
            Self::NotRequested => Ok(()),
            Self::Target {
                target,
                record_sha256,
            } => {
                target.validate()?;
                validate_sha256(record_sha256, "active enrollment record digest")
            }
            Self::NoActiveRecord => Ok(()),
            Self::UnavailableCorruptRecord {
                owner_sha256,
                record_sha256,
            } => {
                validate_sha256(owner_sha256, "corrupt-record owner digest")?;
                validate_sha256(record_sha256, "corrupt-record bytes digest")
            }
        }
    }
}

/// A service definition is a destructive instruction only while its exact
/// content still matches the captured digest. Missing is already-clean;
/// mismatch is ambiguity and must never be deleted.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnitRole {
    DesiredCurrent,
    LoadedEffective,
    HistoricalInstalled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObservedUnit {
    path: String,
    sha256: String,
    roles: BTreeSet<UnitRole>,
}

impl ObservedUnit {
    pub fn from_bytes(
        path: &Path,
        bytes: &[u8],
        roles: impl IntoIterator<Item = UnitRole>,
    ) -> Result<Self> {
        validate_unit_path(path)?;
        if bytes.is_empty() || bytes.len() > 128 * 1024 {
            bail!("observed service definition is empty or unbounded");
        }
        let value = Self {
            path: encode_path(path)?,
            sha256: sha256(bytes),
            roles: roles.into_iter().collect(),
        };
        value.validate()?;
        Ok(value)
    }

    pub fn path(&self) -> PathBuf {
        PathBuf::from(&self.path)
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    pub fn roles(&self) -> &BTreeSet<UnitRole> {
        &self.roles
    }

    fn validate(&self) -> Result<()> {
        validate_unit_path(Path::new(&self.path))?;
        validate_sha256(&self.sha256, "observed service definition digest")?;
        if self.roles.is_empty() || self.roles.len() > 3 {
            bail!("observed service definition roles are empty or unbounded");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DesiredUnit {
    path: String,
    sha256: String,
    bytes_b64: String,
}

impl DesiredUnit {
    pub fn from_bytes(path: &Path, bytes: &[u8]) -> Result<Self> {
        validate_unit_path(path)?;
        if bytes.is_empty() || bytes.len() > MAX_DESIRED_UNIT_BYTES {
            bail!("desired service definition is empty or unbounded");
        }
        Ok(Self {
            path: encode_path(path)?,
            sha256: sha256(bytes),
            bytes_b64: base64::engine::general_purpose::STANDARD.encode(bytes),
        })
    }

    pub fn path(&self) -> PathBuf {
        PathBuf::from(&self.path)
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    /// Exact precommitted bytes survive an application update, allowing an
    /// interrupted transaction to finish the old plan before any new plan is
    /// considered.
    pub fn bytes(&self) -> Result<Vec<u8>> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(&self.bytes_b64)
            .context("desired service definition is not canonical base64")?;
        if bytes.is_empty() || bytes.len() > MAX_DESIRED_UNIT_BYTES {
            bail!("desired service definition is empty or unbounded");
        }
        if base64::engine::general_purpose::STANDARD.encode(&bytes) != self.bytes_b64 {
            bail!("desired service definition base64 is not canonical");
        }
        Ok(bytes)
    }

    fn validate(&self) -> Result<()> {
        validate_unit_path(Path::new(&self.path))?;
        validate_sha256(&self.sha256, "desired service definition digest")?;
        let bytes = self.bytes()?;
        if sha256(&bytes) != self.sha256 {
            bail!("desired service definition bytes disagree with their digest");
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderTerminalOutcome {
    Revoked,
    AlreadyAbsent,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LifecycleFileKind {
    CanonicalRecord,
    CanonicalOwnerMarker,
    LegacyRecord,
    CanonicalStableKey,
    LegacyAdoptedKey,
    AdoptionMarker,
    ServiceReadiness,
    ServiceReadinessRequest,
    ServiceDefinition,
    EnrollmentDiagnostics,
    EnrollmentDiagnosticsTemporary,
}

impl LifecycleFileKind {
    fn expected_basename(self) -> &'static str {
        match self {
            Self::CanonicalRecord | Self::LegacyRecord => "device.json",
            Self::CanonicalOwnerMarker => "device-owner.json",
            Self::CanonicalStableKey | Self::LegacyAdoptedKey => "device-key",
            Self::AdoptionMarker => "legacy-xdg-enrollment-adoption.v1.json",
            Self::ServiceReadiness => crate::service_readiness::SERVICE_READINESS_FILE,
            Self::ServiceReadinessRequest => {
                crate::service_readiness::SERVICE_READINESS_REQUEST_FILE
            }
            Self::ServiceDefinition => {
                #[cfg(target_os = "macos")]
                return "com.hydra.agent.plist";
                #[cfg(not(target_os = "macos"))]
                return "hydra-agent.service";
            }
            Self::EnrollmentDiagnostics => crate::device_identity::ENROLLMENT_DIAGNOSTICS_FILE,
            Self::EnrollmentDiagnosticsTemporary => {
                crate::device_identity::ENROLLMENT_DIAGNOSTICS_TEMP_FILE
            }
        }
    }

    fn max_bytes(self) -> usize {
        match self {
            Self::CanonicalStableKey | Self::LegacyAdoptedKey => 512,
            Self::AdoptionMarker => 8 * 1024,
            Self::EnrollmentDiagnostics | Self::EnrollmentDiagnosticsTemporary => {
                crate::device_identity::MAX_ENROLLMENT_DIAGNOSTICS_BYTES
            }
            Self::CanonicalRecord
            | Self::CanonicalOwnerMarker
            | Self::LegacyRecord
            | Self::ServiceReadiness
            | Self::ServiceReadinessRequest => 64 * 1024,
            Self::ServiceDefinition => 128 * 1024,
        }
    }

    fn mode_allowed(self, mode: u32) -> bool {
        match self {
            // 0640 is the exact monotonic result of the reviewed historical
            // 0660 -> 0640 service-definition migration. It remains
            // non-writable by group/world and is safe lifecycle evidence.
            Self::ServiceDefinition => matches!(mode, 0o600 | 0o640 | 0o644),
            Self::CanonicalRecord
            | Self::CanonicalOwnerMarker
            | Self::LegacyRecord
            | Self::CanonicalStableKey
            | Self::LegacyAdoptedKey
            | Self::AdoptionMarker
            | Self::ServiceReadiness
            | Self::ServiceReadinessRequest
            | Self::EnrollmentDiagnostics
            | Self::EnrollmentDiagnosticsTemporary => mode == 0o600,
        }
    }

    fn is_canonical_only(self) -> bool {
        matches!(
            self,
            Self::CanonicalRecord
                | Self::CanonicalOwnerMarker
                | Self::CanonicalStableKey
                | Self::AdoptionMarker
                | Self::EnrollmentDiagnostics
                | Self::EnrollmentDiagnosticsTemporary
                | Self::ServiceDefinition
        )
    }

    fn is_legacy_only(self) -> bool {
        matches!(self, Self::LegacyRecord | Self::LegacyAdoptedKey)
    }

    fn parent_is_lock_root(self) -> bool {
        !matches!(self, Self::ServiceDefinition)
    }

    fn supports_absence_evidence(self) -> bool {
        matches!(
            self,
            Self::CanonicalRecord
                | Self::CanonicalStableKey
                | Self::LegacyRecord
                | Self::LegacyAdoptedKey
                | Self::AdoptionMarker
        )
    }
}

/// Exact file bytes and metadata captured under the complete lifecycle lock
/// set. The device/inode identity is persisted with the digest, owner and mode
/// and every field is revalidated immediately before deletion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExactFileEvidence {
    lock_root: String,
    path: String,
    sha256: String,
    mode: u32,
    owner_uid: u32,
    device: u64,
    inode: u64,
    kind: LifecycleFileKind,
}

impl ExactFileEvidence {
    pub fn capture(
        lock_root: &Path,
        path: &Path,
        kind: LifecycleFileKind,
        locks: &crate::service::LifecycleLockSet,
    ) -> Result<Option<Self>> {
        let locked_root = locks
            .lock_for(lock_root)
            .context("exact-file capture lock set omits its authority root")?
            .root()
            .to_path_buf();
        if kind.parent_is_lock_root() {
            let supplied_parent = path
                .parent()
                .ok_or_else(|| anyhow::anyhow!("exact lifecycle path has no parent"))?;
            if fs::canonicalize(supplied_parent)? != locked_root {
                bail!("exact lifecycle path is outside its supplied lock root");
            }
        }
        let captured_path = if kind.parent_is_lock_root() {
            locked_root.join(kind.expected_basename())
        } else {
            path.to_path_buf()
        };
        let encoded_root = encode_path(&locked_root)?;
        validate_agent_root(Path::new(&encoded_root))?;
        validate_lifecycle_file_path(&captured_path, kind)?;
        let Some(observed) = read_exact_owned_regular_if_present(&captured_path, kind.max_bytes())?
        else {
            return Ok(None);
        };
        if !kind.mode_allowed(observed.mode) {
            bail!("lifecycle file has an unexpected mode");
        }
        let value = Self {
            lock_root: encoded_root,
            path: encode_path(&captured_path)?,
            sha256: sha256(&observed.bytes),
            mode: observed.mode,
            owner_uid: observed.owner_uid,
            device: observed.device,
            inode: observed.inode,
            kind,
        };
        value.validate()?;
        Ok(Some(value))
    }

    pub fn path(&self) -> PathBuf {
        PathBuf::from(&self.path)
    }

    pub fn kind(&self) -> LifecycleFileKind {
        self.kind
    }

    pub fn lock_root(&self) -> PathBuf {
        PathBuf::from(&self.lock_root)
    }

    pub fn sha256(&self) -> &str {
        &self.sha256
    }

    fn validate(&self) -> Result<()> {
        validate_agent_root(Path::new(&self.lock_root))?;
        validate_lifecycle_file_path(Path::new(&self.path), self.kind)?;
        if self.kind.parent_is_lock_root()
            && Path::new(&self.path).parent() != Some(Path::new(&self.lock_root))
        {
            bail!("exact lifecycle file evidence is outside its lock root");
        }
        validate_sha256(&self.sha256, "lifecycle file digest")?;
        if !self.kind.mode_allowed(self.mode) {
            bail!("lifecycle file evidence has an unexpected mode");
        }
        if self.owner_uid != expected_uid() {
            bail!("lifecycle file evidence has an unexpected owner");
        }
        #[cfg(unix)]
        if self.inode == 0 {
            bail!("lifecycle file evidence has an invalid inode");
        }
        Ok(())
    }

    fn reverify(&self, locks: &crate::service::LifecycleLockSet) -> Result<()> {
        self.validate()?;
        locks
            .require_agent_dir(Path::new(&self.lock_root))
            .context("exact-file revalidation lock set omits its authority root")?;
        let observed =
            read_exact_owned_regular_if_present(Path::new(&self.path), self.kind.max_bytes())?
                .ok_or_else(|| anyhow::anyhow!("retained lifecycle evidence disappeared"))?;
        if observed.mode != self.mode
            || observed.owner_uid != self.owner_uid
            || observed.device != self.device
            || observed.inode != self.inode
            || sha256(&observed.bytes) != self.sha256
        {
            bail!("retained lifecycle evidence changed after its exact capture");
        }
        Ok(())
    }

    fn reverified_bytes(&self, locks: &crate::service::LifecycleLockSet) -> Result<Vec<u8>> {
        self.reverify(locks)?;
        let observed =
            read_exact_owned_regular_if_present(Path::new(&self.path), self.kind.max_bytes())?
                .ok_or_else(|| anyhow::anyhow!("captured lifecycle evidence disappeared"))?;
        Ok(observed.bytes)
    }
}

/// Durable proof that one authority-bearing file was absent while the exact
/// lifecycle lock set was held. The parent directory is synced between two
/// NotFound observations, so this is evidence of a durable absence rather than
/// an unchecked caller assertion.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DurableFileAbsence {
    lock_root: String,
    path: String,
    kind: LifecycleFileKind,
}

impl DurableFileAbsence {
    pub fn capture(
        lock_root: &Path,
        path: &Path,
        kind: LifecycleFileKind,
        locks: &crate::service::LifecycleLockSet,
    ) -> Result<Option<Self>> {
        if !kind.supports_absence_evidence() {
            bail!("lifecycle file kind cannot carry durable absence evidence");
        }
        validate_lifecycle_file_path(path, kind)?;
        let locked_root = locks
            .lock_for(lock_root)
            .context("absence capture lock set omits its authority root")?
            .root()
            .to_path_buf();
        let supplied_parent = path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("absence evidence path has no parent"))?;
        if fs::canonicalize(supplied_parent)? != locked_root {
            bail!("absence evidence path is outside its supplied lock root");
        }
        let captured_path = locked_root.join(kind.expected_basename());
        validate_lifecycle_file_path(&captured_path, kind)?;
        if captured_path.parent() != Some(locked_root.as_path()) {
            bail!("absence evidence path is outside its lock root");
        }
        if !prove_path_absent_durably(&captured_path)? {
            return Ok(None);
        }
        let value = Self {
            lock_root: encode_path(&locked_root)?,
            path: encode_path(&captured_path)?,
            kind,
        };
        value.validate()?;
        Ok(Some(value))
    }

    pub fn path(&self) -> PathBuf {
        PathBuf::from(&self.path)
    }

    pub fn kind(&self) -> LifecycleFileKind {
        self.kind
    }

    fn validate(&self) -> Result<()> {
        if !self.kind.supports_absence_evidence() {
            bail!("lifecycle file kind cannot carry durable absence evidence");
        }
        validate_agent_root(Path::new(&self.lock_root))?;
        validate_lifecycle_file_path(Path::new(&self.path), self.kind)?;
        if Path::new(&self.path).parent() != Some(Path::new(&self.lock_root)) {
            bail!("absence evidence path is outside its lock root");
        }
        Ok(())
    }

    fn reverify(&self, locks: &crate::service::LifecycleLockSet) -> Result<()> {
        self.validate()?;
        locks
            .require_agent_dir(Path::new(&self.lock_root))
            .context("absence revalidation lock set omits its authority root")?;
        if prove_path_absent_durably(Path::new(&self.path))? {
            Ok(())
        } else {
            bail!("durably absent lifecycle file reappeared")
        }
    }
}

/// One exact destructive filesystem instruction persisted before the first
/// authority cut. Completion is journaled separately so a crash after unlink
/// can retry as AlreadyAbsent without recapturing ambient filesystem state.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PlannedDeletion {
    evidence: ExactFileEvidence,
    proven_absent: bool,
}

impl PlannedDeletion {
    pub fn pending(evidence: ExactFileEvidence) -> Self {
        Self {
            evidence,
            proven_absent: false,
        }
    }

    pub fn evidence(&self) -> &ExactFileEvidence {
        &self.evidence
    }

    pub fn is_proven_absent(&self) -> bool {
        self.proven_absent
    }

    fn validate(&self, canonical_root: &Path, intent: CleanupIntent) -> Result<()> {
        self.evidence.validate()?;
        if self.evidence.kind == LifecycleFileKind::CanonicalOwnerMarker
            && intent != CleanupIntent::FullForget
        {
            bail!("durable enrollment owner evidence requires FullForget");
        }
        if matches!(
            self.evidence.kind,
            LifecycleFileKind::EnrollmentDiagnostics
                | LifecycleFileKind::EnrollmentDiagnosticsTemporary
        ) && intent != CleanupIntent::FullForget
        {
            bail!("enrollment diagnostics may be deleted only by FullForget");
        }
        let lock_root = Path::new(&self.evidence.lock_root);
        let path = Path::new(&self.evidence.path);
        if self.evidence.kind.parent_is_lock_root() && path.parent() != Some(lock_root) {
            bail!("lifecycle deletion target is outside its lock root");
        }
        if self.evidence.kind.is_canonical_only() && lock_root != canonical_root {
            bail!("canonical lifecycle deletion target uses a legacy lock root");
        }
        if self.evidence.kind.is_legacy_only() && lock_root == canonical_root {
            bail!("legacy lifecycle deletion target uses the canonical lock root");
        }
        match intent {
            CleanupIntent::ConvergeOpen | CleanupIntent::Close => {
                if matches!(
                    self.evidence.kind,
                    LifecycleFileKind::CanonicalRecord | LifecycleFileKind::CanonicalStableKey
                ) {
                    bail!("non-destructive lifecycle intent cannot delete canonical authority");
                }
            }
            CleanupIntent::Remove => {
                if self.evidence.kind == LifecycleFileKind::CanonicalStableKey {
                    bail!("ordinary Remove cannot delete the canonical stable key");
                }
            }
            CleanupIntent::FullForget => {}
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DurableRemovalOutcome {
    Removed,
    AlreadyAbsent,
    /// The exact captured file no longer occupies its path. A different,
    /// owner-safe service definition was installed there after capture and is
    /// deliberately retained rather than treated as deletion authority.
    Superseded,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CapturedFileState {
    Exact,
    Absent,
    Superseded,
}

fn captured_file_state(evidence: &ExactFileEvidence) -> Result<CapturedFileState> {
    let Some(observed) =
        read_exact_owned_regular_if_present(Path::new(&evidence.path), evidence.kind.max_bytes())?
    else {
        return Ok(CapturedFileState::Absent);
    };
    let same_inode = observed.device == evidence.device && observed.inode == evidence.inode;
    let exact = same_inode
        && observed.mode == evidence.mode
        && observed.owner_uid == evidence.owner_uid
        && sha256(&observed.bytes) == evidence.sha256;
    if exact {
        return Ok(CapturedFileState::Exact);
    }
    if same_inode {
        bail!("lifecycle file changed in place after its exact capture");
    }
    if evidence.kind != LifecycleFileKind::ServiceDefinition {
        bail!("lifecycle file changed after its exact capture");
    }
    if !evidence.kind.mode_allowed(observed.mode) {
        bail!("replacement service definition has an unsafe mode");
    }
    Ok(CapturedFileState::Superseded)
}

/// Remove one exact observed lifecycle file and make the absence durable.
/// Even AlreadyAbsent syncs the real parent directory before readback, which
/// closes the power-loss case where an earlier unlink had not been persisted.
fn remove_exact_file_durably(
    evidence: &ExactFileEvidence,
    locks: &crate::service::LifecycleLockSet,
) -> Result<DurableRemovalOutcome> {
    evidence.validate()?;
    locks
        .require_agent_dir(Path::new(&evidence.lock_root))
        .context("exact-file removal lock set omits its authority root")?;
    let target = Path::new(&evidence.path);
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("lifecycle file has no parent"))?;
    require_owned_safe_directory(parent)?;
    if captured_file_state(evidence)? == CapturedFileState::Superseded {
        // The captured file had nlink=1, so a different inode at its only path
        // proves that exact file is gone. Sync the directory and observe again
        // before journaling completion. The replacement is not ours to delete.
        sync_directory(parent).context("sync superseding service definition parent")?;
        return match captured_file_state(evidence)? {
            CapturedFileState::Absent | CapturedFileState::Superseded => {
                Ok(DurableRemovalOutcome::Superseded)
            }
            CapturedFileState::Exact => {
                bail!("captured service definition reappeared during cleanup")
            }
        };
    }
    remove_exact_file_durably_with(
        evidence,
        locks,
        |target| fs::remove_file(target).context("remove exact lifecycle file"),
        |parent| sync_directory(parent).context("sync lifecycle file parent after removal"),
        prove_path_absent,
    )
}

fn remove_exact_file_durably_with<Remove, SyncParent, Readback>(
    evidence: &ExactFileEvidence,
    locks: &crate::service::LifecycleLockSet,
    remove: Remove,
    sync_parent: SyncParent,
    readback_absent: Readback,
) -> Result<DurableRemovalOutcome>
where
    Remove: FnOnce(&Path) -> Result<()>,
    SyncParent: FnOnce(&Path) -> Result<()>,
    Readback: FnOnce(&Path) -> Result<bool>,
{
    evidence.validate()?;
    locks
        .require_agent_dir(Path::new(&evidence.lock_root))
        .context("exact-file removal lock set omits its authority root")?;
    let target = Path::new(&evidence.path);
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("lifecycle file has no parent"))?;
    require_owned_safe_directory(parent)?;
    let outcome = match read_exact_owned_regular_if_present(target, evidence.kind.max_bytes())? {
        Some(observed) => {
            if observed.mode != evidence.mode
                || observed.owner_uid != evidence.owner_uid
                || observed.device != evidence.device
                || observed.inode != evidence.inode
                || sha256(&observed.bytes) != evidence.sha256
            {
                bail!("lifecycle file changed after its exact capture");
            }
            remove(target)?;
            DurableRemovalOutcome::Removed
        }
        None => DurableRemovalOutcome::AlreadyAbsent,
    };
    sync_parent(parent)?;
    if readback_absent(target)? {
        Ok(outcome)
    } else {
        bail!("lifecycle file still exists after durable removal")
    }
}

fn prove_path_absent(target: &Path) -> Result<bool> {
    match fs::symlink_metadata(target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(true),
        Ok(_) => Ok(false),
        Err(error) => Err(error).context("prove lifecycle file absence after removal"),
    }
}

fn prove_path_absent_durably(target: &Path) -> Result<bool> {
    let parent = target
        .parent()
        .ok_or_else(|| anyhow::anyhow!("lifecycle absence path has no parent"))?;
    require_owned_safe_directory(parent)?;
    if !prove_path_absent(target)? {
        return Ok(false);
    }
    sync_directory(parent).context("sync lifecycle absence parent")?;
    prove_path_absent(target).context("repeat lifecycle absence readback after parent sync")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProviderTerminalReceipt {
    target: RevocationTarget,
    outcome: ProviderTerminalOutcome,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct LegacyRetirementBinding {
    marker_path: String,
    marker_sha256: String,
    source_root: String,
    record_sha256: String,
    key_sha256: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdoptionMarkerForRetirement {
    schema: u8,
    source_agent_dir: String,
    account_id: String,
    device_id: String,
    key_sha256: String,
    record_sha256: String,
    owner_sha256: String,
}

impl LegacyRetirementBinding {
    fn capture(
        canonical_root: &Path,
        marker: &ExactFileEvidence,
        deletion_targets: &BTreeMap<String, PlannedDeletion>,
        durable_absences: &mut BTreeMap<String, DurableFileAbsence>,
        locks: &crate::service::LifecycleLockSet,
    ) -> Result<Self> {
        if marker.kind != LifecycleFileKind::AdoptionMarker || marker.lock_root() != canonical_root
        {
            bail!("legacy retirement marker is not canonical");
        }
        let bytes = marker.reverified_bytes(locks)?;
        let parsed: AdoptionMarkerForRetirement =
            serde_json::from_slice(&bytes).context("adoption marker is invalid")?;
        if parsed.schema != 1 {
            bail!("adoption marker schema is unsupported");
        }
        bounded_text(&parsed.account_id, 512, "adoption marker account id")?;
        bounded_text(&parsed.device_id, 512, "adoption marker device id")?;
        validate_sha256(&parsed.key_sha256, "adoption marker key digest")?;
        validate_sha256(&parsed.record_sha256, "adoption marker record digest")?;
        validate_sha256(&parsed.owner_sha256, "adoption marker owner digest")?;
        let source = PathBuf::from(parsed.source_agent_dir);
        validate_agent_root(&source)?;
        if source == canonical_root {
            bail!("adoption marker source aliases the canonical root");
        }
        let source_lock = locks
            .lock_for(&source)
            .context("adoption marker source is outside the exact lock set")?;
        if source_lock.root() != source {
            bail!("adoption marker source is not its exact canonical root");
        }

        for (kind, digest) in [
            (
                LifecycleFileKind::LegacyRecord,
                parsed.record_sha256.as_str(),
            ),
            (
                LifecycleFileKind::LegacyAdoptedKey,
                parsed.key_sha256.as_str(),
            ),
        ] {
            let path = source.join(kind.expected_basename());
            let encoded = encode_path(&path)?;
            if let Some(target) = deletion_targets.get(&encoded) {
                if target.evidence.kind != kind
                    || target.evidence.lock_root() != source
                    || target.evidence.sha256() != digest
                {
                    bail!("legacy retirement target disagrees with its adoption marker");
                }
            } else {
                let absence = DurableFileAbsence::capture(&source, &path, kind, locks)?
                    .ok_or_else(|| {
                        anyhow::anyhow!(
                            "adoption marker names legacy authority omitted from cleanup"
                        )
                    })?;
                durable_absences.insert(encoded, absence);
            }
        }
        Ok(Self {
            marker_path: encode_path(&marker.path())?,
            marker_sha256: marker.sha256().to_string(),
            source_root: encode_path(&source)?,
            record_sha256: parsed.record_sha256,
            key_sha256: parsed.key_sha256,
        })
    }

    fn validate(&self) -> Result<()> {
        validate_lifecycle_file_path(
            Path::new(&self.marker_path),
            LifecycleFileKind::AdoptionMarker,
        )?;
        validate_agent_root(Path::new(&self.source_root))?;
        validate_sha256(&self.marker_sha256, "legacy retirement marker digest")?;
        validate_sha256(&self.record_sha256, "legacy retirement record digest")?;
        validate_sha256(&self.key_sha256, "legacy retirement key digest")
    }
}

/// Runtime identity used only to revalidate a newly observed live manager. No
/// PID is durable because PID reuse across a crash is expected. Every retry
/// inventories the same-UID process table and reparses exact argv/environment.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ManagerEvidence {
    agent_root: String,
    socket_path: String,
    build_stamp: String,
    binding_stamp: String,
}

impl ManagerEvidence {
    pub fn new(
        agent_root: &Path,
        socket_path: &Path,
        build_stamp: String,
        binding_stamp: String,
    ) -> Result<Self> {
        let value = Self {
            agent_root: encode_path(agent_root)?,
            socket_path: encode_path(socket_path)?,
            build_stamp,
            binding_stamp,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn agent_root(&self) -> PathBuf {
        PathBuf::from(&self.agent_root)
    }

    pub fn socket_path(&self) -> PathBuf {
        PathBuf::from(&self.socket_path)
    }

    pub fn build_stamp(&self) -> &str {
        &self.build_stamp
    }

    pub fn binding_stamp(&self) -> &str {
        &self.binding_stamp
    }

    fn validate(&self) -> Result<()> {
        validate_agent_root(Path::new(&self.agent_root))?;
        validate_absolute_path(Path::new(&self.socket_path), "manager socket path")?;
        validate_build_stamp(&self.build_stamp)?;
        validate_sha256(&self.binding_stamp, "manager binding stamp")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CleanupTombstone {
    schema: u8,
    intent: CleanupIntent,
    prior_activation: PriorActivation,
    authority: AuthorityEvidence,
    canonical_root: String,
    lock_roots: BTreeSet<String>,
    peer_roots: BTreeSet<String>,
    readiness_roots: BTreeSet<String>,
    observed_units: BTreeMap<String, ObservedUnit>,
    deletion_targets: BTreeMap<String, PlannedDeletion>,
    durable_absences: BTreeMap<String, DurableFileAbsence>,
    retained_evidence: BTreeMap<String, ExactFileEvidence>,
    #[serde(default)]
    legacy_retirement: Option<LegacyRetirementBinding>,
    desired_unit: DesiredUnit,
    manager: Option<ManagerEvidence>,
    #[serde(default)]
    provider_handoff: Option<RevocationTarget>,
    #[serde(default)]
    provider_terminal: Option<ProviderTerminalReceipt>,
}

impl CleanupTombstone {
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        intent: CleanupIntent,
        prior_activation: PriorActivation,
        authority: AuthorityEvidence,
        canonical_root: &Path,
        peer_roots: &BTreeSet<PathBuf>,
        readiness_roots: &BTreeSet<PathBuf>,
        observed_units: impl IntoIterator<Item = ObservedUnit>,
        deletion_targets: impl IntoIterator<Item = ExactFileEvidence>,
        desired_unit: DesiredUnit,
        manager: Option<ManagerEvidence>,
        locks: &crate::service::LifecycleLockSet,
    ) -> Result<Self> {
        let canonical_root = locks
            .lock_for(canonical_root)
            .context("cleanup constructor lock set omits the canonical root")?
            .root()
            .to_path_buf();
        let mut unit_map = BTreeMap::new();
        for unit in observed_units {
            let path = encode_path(&unit.path())?;
            if let Some(existing) = unit_map.insert(path, unit.clone()) {
                if existing != unit {
                    bail!("duplicate service path has conflicting captured bytes");
                }
            }
        }
        let mut deletion_map = BTreeMap::new();
        for evidence in deletion_targets {
            let path = encode_path(&evidence.path())?;
            let planned = PlannedDeletion::pending(evidence);
            if let Some(existing) = deletion_map.insert(path, planned.clone()) {
                if existing != planned {
                    bail!("duplicate deletion path has conflicting captured evidence");
                }
            }
        }
        let mut durable_absences = BTreeMap::new();
        if matches!(intent, CleanupIntent::Remove | CleanupIntent::FullForget)
            && !deletion_map
                .values()
                .any(|target| target.evidence.kind == LifecycleFileKind::CanonicalRecord)
        {
            if let Some(absence) = DurableFileAbsence::capture(
                &canonical_root,
                &canonical_root.join("device.json"),
                LifecycleFileKind::CanonicalRecord,
                locks,
            )? {
                durable_absences.insert(encode_path(&absence.path())?, absence);
            }
        }
        if intent == CleanupIntent::FullForget
            && !deletion_map
                .values()
                .any(|target| target.evidence.kind == LifecycleFileKind::CanonicalStableKey)
        {
            if let Some(absence) = DurableFileAbsence::capture(
                &canonical_root,
                &canonical_root.join("device-key"),
                LifecycleFileKind::CanonicalStableKey,
                locks,
            )? {
                durable_absences.insert(encode_path(&absence.path())?, absence);
            }
        }
        let marker_target = deletion_map
            .values()
            .find(|target| target.evidence.kind == LifecycleFileKind::AdoptionMarker)
            .map(|target| target.evidence.clone());
        let legacy_retirement =
            if matches!(intent, CleanupIntent::Remove | CleanupIntent::FullForget) {
                match marker_target.as_ref() {
                    Some(marker) => Some(LegacyRetirementBinding::capture(
                        &canonical_root,
                        marker,
                        &deletion_map,
                        &mut durable_absences,
                        locks,
                    )?),
                    None => {
                        let marker_path = canonical_root
                            .join(LifecycleFileKind::AdoptionMarker.expected_basename());
                        let absence = DurableFileAbsence::capture(
                            &canonical_root,
                            &marker_path,
                            LifecycleFileKind::AdoptionMarker,
                            locks,
                        )?
                        .ok_or_else(|| {
                            anyhow::anyhow!(
                                "present adoption marker was omitted from destructive cleanup"
                            )
                        })?;
                        durable_absences.insert(encode_path(&absence.path())?, absence);
                        None
                    }
                }
            } else {
                if marker_target.is_some() {
                    bail!("non-destructive cleanup cannot retire an adoption marker");
                }
                None
            };
        let mut retained_evidence = BTreeMap::new();
        if matches!(
            authority,
            AuthorityEvidence::UnavailableCorruptRecord { .. }
        ) {
            let owner = ExactFileEvidence::capture(
                &canonical_root,
                &canonical_root.join("device-owner.json"),
                LifecycleFileKind::CanonicalOwnerMarker,
                locks,
            )?
            .ok_or_else(|| anyhow::anyhow!("corrupt enrollment has no durable owner evidence"))?;
            retained_evidence.insert(encode_path(&owner.path())?, owner);
        }
        let lock_roots = locks
            .roots()
            .map(encode_path)
            .collect::<Result<BTreeSet<_>>>()?;
        let value = Self {
            schema: SCHEMA,
            intent,
            prior_activation,
            authority,
            canonical_root: encode_path(&canonical_root)?,
            lock_roots,
            peer_roots: encode_locked_paths(peer_roots, locks)?,
            readiness_roots: encode_locked_paths(readiness_roots, locks)?,
            observed_units: unit_map,
            deletion_targets: deletion_map,
            durable_absences,
            retained_evidence,
            legacy_retirement,
            desired_unit,
            manager,
            provider_handoff: None,
            provider_terminal: None,
        };
        value.validate()?;
        Ok(value)
    }

    pub fn intent(&self) -> CleanupIntent {
        self.intent
    }

    pub fn prior_activation(&self) -> PriorActivation {
        self.prior_activation
    }

    pub fn authority(&self) -> &AuthorityEvidence {
        &self.authority
    }

    pub fn canonical_root(&self) -> PathBuf {
        PathBuf::from(&self.canonical_root)
    }

    pub fn lock_roots(&self) -> Result<BTreeSet<PathBuf>> {
        decode_paths(&self.lock_roots)
    }

    pub fn revocation_target(&self) -> Option<&RevocationTarget> {
        self.authority.target_ref()
    }

    pub fn peer_roots(&self) -> Result<BTreeSet<PathBuf>> {
        decode_paths(&self.peer_roots)
    }

    pub fn readiness_roots(&self) -> Result<BTreeSet<PathBuf>> {
        decode_paths(&self.readiness_roots)
    }

    pub fn observed_units(&self) -> impl Iterator<Item = &ObservedUnit> {
        self.observed_units.values()
    }

    pub fn deletion_targets(&self) -> impl Iterator<Item = &PlannedDeletion> {
        self.deletion_targets.values()
    }

    pub fn retires_owner_marker(&self) -> bool {
        self.deletion_targets
            .values()
            .any(|target| target.evidence.kind == LifecycleFileKind::CanonicalOwnerMarker)
    }

    pub fn durable_absences(&self) -> impl Iterator<Item = &DurableFileAbsence> {
        self.durable_absences.values()
    }

    pub fn all_deletions_proven(&self) -> bool {
        self.deletion_targets
            .values()
            .all(PlannedDeletion::is_proven_absent)
    }

    /// Prove that every captured service-definition inode is retired. A
    /// package update may install a different safe unit at the same path while
    /// cleanup is pending; that replacement is retained and never inherits the
    /// old journal's deletion authority.
    pub fn prove_service_definitions_retired(
        &self,
        locks: &crate::service::LifecycleLockSet,
    ) -> Result<()> {
        self.require_exact_locks(locks)?;
        for planned in self
            .deletion_targets
            .values()
            .filter(|planned| planned.evidence.kind == LifecycleFileKind::ServiceDefinition)
        {
            if !planned.proven_absent {
                bail!("service-definition deletion is not durably complete");
            }
            if captured_file_state(&planned.evidence)? == CapturedFileState::Exact {
                bail!("captured service definition remains installed");
            }
        }
        Ok(())
    }

    pub fn desired_unit(&self) -> &DesiredUnit {
        &self.desired_unit
    }

    pub fn manager(&self) -> Option<&ManagerEvidence> {
        self.manager.as_ref()
    }

    pub fn provider_terminal_target(&self) -> Option<&RevocationTarget> {
        self.provider_terminal
            .as_ref()
            .map(|receipt| &receipt.target)
    }

    pub fn provider_terminal_outcome(&self) -> Option<ProviderTerminalOutcome> {
        self.provider_terminal
            .as_ref()
            .map(|receipt| receipt.outcome)
    }

    pub fn provider_handoff_target(&self) -> Option<&RevocationTarget> {
        self.provider_handoff.as_ref()
    }

    fn require_exact_locks(&self, locks: &crate::service::LifecycleLockSet) -> Result<()> {
        let expected = self.lock_roots()?;
        locks
            .require_exact_roots(&expected)
            .context("lifecycle mutation does not hold the exact captured lock set")
    }

    fn reverify_persisted_state(&self, locks: &crate::service::LifecycleLockSet) -> Result<()> {
        self.require_exact_locks(locks)?;
        for absence in self.durable_absences.values() {
            absence.reverify(locks)?;
        }
        for evidence in self.retained_evidence.values() {
            evidence.reverify(locks)?;
        }
        Ok(())
    }

    /// Merge only a fresh observation of the same pending intent. Intent
    /// supersession is an engine operation: it first moves any old provider
    /// target into the lock-bound outbox, then atomically replaces this record.
    pub fn merged_retry(&self, newer: &Self) -> Result<Self> {
        self.validate()?;
        newer.validate()?;
        if self.intent != newer.intent
            || self.prior_activation != newer.prior_activation
            || self.authority != newer.authority
            || self.canonical_root != newer.canonical_root
            || self.lock_roots != newer.lock_roots
            || self.peer_roots != newer.peer_roots
            || self.readiness_roots != newer.readiness_roots
            || self.legacy_retirement != newer.legacy_retirement
            || self.desired_unit != newer.desired_unit
        {
            bail!("repeated lifecycle transaction facts are inconsistent");
        }
        // Roles describe the newest manager snapshot. Carrying LoadedEffective
        // or DesiredCurrent forward by union would turn stale observations into
        // current authority. Start from the newest snapshot and retain only an
        // unresolved deletion-backed old unit, demoted to HistoricalInstalled.
        let mut observed_units = newer.observed_units.clone();
        for (path, newer_unit) in &observed_units {
            match self.observed_units.get(path) {
                Some(old) if old.sha256 == newer_unit.sha256 => {}
                Some(_)
                    if path == &self.desired_unit.path
                        && newer_unit.sha256 == self.desired_unit.sha256
                        && newer_unit.roles.contains(&UnitRole::DesiredCurrent) => {}
                Some(_) => bail!("service definition changed outside its planned transition"),
                None if path == &self.desired_unit.path
                    && newer_unit.sha256 == self.desired_unit.sha256
                    && newer_unit.roles.contains(&UnitRole::DesiredCurrent) => {}
                None => bail!("a new unplanned service definition appeared during cleanup"),
            }
        }
        for (path, old_target) in &self.deletion_targets {
            if old_target.proven_absent
                || old_target.evidence.kind != LifecycleFileKind::ServiceDefinition
            {
                continue;
            }
            let mut historical = self.observed_units.get(path).cloned().ok_or_else(|| {
                anyhow::anyhow!("pending service deletion lost its observed unit evidence")
            })?;
            historical.roles = BTreeSet::from([UnitRole::HistoricalInstalled]);
            match observed_units.get(path) {
                Some(current) if current.sha256 != historical.sha256 => {
                    bail!("pending historical service changed during retry")
                }
                Some(_) => {
                    observed_units.insert(path.clone(), historical);
                }
                None => {
                    observed_units.insert(path.clone(), historical);
                }
            }
        }
        let deletion_targets = self.deletion_targets.clone();
        for (path, newer_target) in &newer.deletion_targets {
            match deletion_targets.get(path) {
                Some(existing) if existing.evidence != newer_target.evidence => {
                    bail!("lifecycle deletion target changed during retry")
                }
                Some(_) => {}
                None => bail!("a new deletion target appeared during same-intent retry"),
            }
        }
        let value = Self {
            schema: SCHEMA,
            intent: self.intent,
            prior_activation: self.prior_activation,
            authority: self.authority.clone(),
            canonical_root: self.canonical_root.clone(),
            lock_roots: self.lock_roots.clone(),
            peer_roots: self.peer_roots.clone(),
            readiness_roots: self.readiness_roots.clone(),
            observed_units,
            deletion_targets,
            durable_absences: newer.durable_absences.clone(),
            retained_evidence: newer.retained_evidence.clone(),
            legacy_retirement: self.legacy_retirement.clone(),
            desired_unit: self.desired_unit.clone(),
            // Runtime processes can legitimately be replaced between retries.
            // The newest exact invocation tuple supersedes the old one; no PID
            // or previous manager identity is ever used as authority.
            manager: newer.manager.clone(),
            provider_handoff: match (&self.provider_handoff, &newer.provider_handoff) {
                (Some(existing), Some(candidate)) if existing != candidate => {
                    bail!("provider handoff receipt changed during retry")
                }
                (Some(existing), _) => Some(existing.clone()),
                (None, receipt) => receipt.clone(),
            },
            provider_terminal: match (&self.provider_terminal, &newer.provider_terminal) {
                (Some(existing), Some(candidate)) if existing != candidate => {
                    bail!("provider terminal receipt changed during retry")
                }
                (Some(existing), _) => Some(existing.clone()),
                (None, receipt) => receipt.clone(),
            },
        };
        value.validate()?;
        Ok(value)
    }

    fn merged_supersession_evidence(&self, requested: &Self) -> Result<Self> {
        self.validate()?;
        requested.validate()?;
        if !may_supersede(self.intent, requested.intent) {
            bail!("cleanup intent cannot supersede the pending transaction");
        }
        if self.canonical_root != requested.canonical_root {
            bail!("cleanup supersession cannot change its canonical lifecycle root");
        }
        if self.lock_roots != requested.lock_roots {
            bail!("cleanup supersession cannot change its captured lifecycle lock set");
        }
        // Unit roles are snapshot-relative: DesiredCurrent and LoadedEffective
        // from the old intent must not be carried into a freshly recaptured
        // descriptor. Under the complete deterministic lock set, the requested
        // snapshot is authoritative for files that still exist. Roots are
        // retained because readiness and peer cleanup can outlive a unit file.
        let mut observed_units = requested.observed_units.clone();
        let mut deletion_targets = BTreeMap::new();
        for (path, old_target) in &self.deletion_targets {
            if old_target.proven_absent {
                continue;
            }
            if old_target.evidence.kind == LifecycleFileKind::ServiceDefinition {
                let mut historical = self.observed_units.get(path).cloned().ok_or_else(|| {
                    anyhow::anyhow!("pending service deletion lost its observed unit evidence")
                })?;
                historical.roles = BTreeSet::from([UnitRole::HistoricalInstalled]);
                match observed_units.get(path) {
                    Some(current) if current.sha256 != historical.sha256 => {
                        bail!("pending historical service changed before supersession")
                    }
                    Some(_) => {
                        observed_units.insert(path.clone(), historical);
                    }
                    None => {
                        observed_units.insert(path.clone(), historical);
                    }
                }
            }
            deletion_targets.insert(path.clone(), old_target.clone());
        }
        for (path, requested_target) in &requested.deletion_targets {
            match deletion_targets.get(path) {
                Some(existing) if existing.evidence != requested_target.evidence => {
                    bail!("superseding lifecycle deletion target conflicts with pending evidence")
                }
                Some(_) => {}
                None => {
                    deletion_targets.insert(path.clone(), requested_target.clone());
                }
            }
        }
        if requested
            .durable_absences
            .keys()
            .any(|path| deletion_targets.contains_key(path))
        {
            bail!("superseding durable absence conflicts with a pending deletion proof");
        }
        let value = Self {
            schema: SCHEMA,
            intent: requested.intent,
            prior_activation: requested.prior_activation,
            authority: requested.authority.clone(),
            canonical_root: requested.canonical_root.clone(),
            lock_roots: requested.lock_roots.clone(),
            peer_roots: self
                .peer_roots
                .union(&requested.peer_roots)
                .cloned()
                .collect(),
            readiness_roots: self
                .readiness_roots
                .union(&requested.readiness_roots)
                .cloned()
                .collect(),
            observed_units,
            deletion_targets,
            durable_absences: requested.durable_absences.clone(),
            retained_evidence: requested.retained_evidence.clone(),
            legacy_retirement: requested.legacy_retirement.clone(),
            desired_unit: requested.desired_unit.clone(),
            manager: requested.manager.clone(),
            provider_handoff: requested.provider_handoff.clone(),
            provider_terminal: requested.provider_terminal.clone(),
        };
        value.validate()?;
        Ok(value)
    }

    fn validate_legacy_retirement(&self) -> Result<()> {
        let marker_targets = self
            .deletion_targets
            .values()
            .filter(|target| target.evidence.kind == LifecycleFileKind::AdoptionMarker)
            .collect::<Vec<_>>();
        let marker_absences = self
            .durable_absences
            .values()
            .filter(|absence| absence.kind == LifecycleFileKind::AdoptionMarker)
            .collect::<Vec<_>>();
        let destructive = matches!(
            self.intent,
            CleanupIntent::Remove | CleanupIntent::FullForget
        );
        if !destructive {
            if !marker_targets.is_empty()
                || !marker_absences.is_empty()
                || self.legacy_retirement.is_some()
                || self.deletion_targets.values().any(|target| {
                    matches!(
                        target.evidence.kind,
                        LifecycleFileKind::LegacyRecord | LifecycleFileKind::LegacyAdoptedKey
                    )
                })
                || self.durable_absences.values().any(|absence| {
                    matches!(
                        absence.kind,
                        LifecycleFileKind::LegacyRecord | LifecycleFileKind::LegacyAdoptedKey
                    )
                })
            {
                bail!("non-destructive cleanup carries legacy retirement state");
            }
            return Ok(());
        }
        if marker_targets.len() + marker_absences.len() != 1 {
            bail!("destructive cleanup requires one exact adoption-marker state");
        }

        let Some(binding) = &self.legacy_retirement else {
            if !marker_targets.is_empty() {
                bail!("present adoption marker lacks structural legacy retirement binding");
            }
            let absence = marker_absences[0];
            if absence.lock_root != self.canonical_root
                || Path::new(&absence.path).parent() != Some(Path::new(&self.canonical_root))
            {
                bail!("adoption-marker absence is not canonical");
            }
            if self.deletion_targets.values().any(|target| {
                matches!(
                    target.evidence.kind,
                    LifecycleFileKind::LegacyRecord | LifecycleFileKind::LegacyAdoptedKey
                )
            }) || self.durable_absences.values().any(|absence| {
                matches!(
                    absence.kind,
                    LifecycleFileKind::LegacyRecord | LifecycleFileKind::LegacyAdoptedKey
                )
            }) {
                bail!("legacy authority state exists without an adoption marker binding");
            }
            return Ok(());
        };

        binding.validate()?;
        if !marker_absences.is_empty() || marker_targets.len() != 1 {
            bail!("legacy retirement binding requires its exact present marker");
        }
        let marker = marker_targets[0];
        if marker.evidence.path != binding.marker_path
            || marker.evidence.sha256 != binding.marker_sha256
            || marker.evidence.lock_root != self.canonical_root
        {
            bail!("legacy retirement marker disagrees with its exact evidence");
        }
        if binding.source_root == self.canonical_root
            || !self.peer_roots.contains(&binding.source_root)
            || !self.lock_roots.contains(&binding.source_root)
        {
            bail!("legacy retirement source is outside the exact peer lock set");
        }
        for (kind, digest) in [
            (
                LifecycleFileKind::LegacyRecord,
                binding.record_sha256.as_str(),
            ),
            (
                LifecycleFileKind::LegacyAdoptedKey,
                binding.key_sha256.as_str(),
            ),
        ] {
            let expected_path = Path::new(&binding.source_root).join(kind.expected_basename());
            let encoded = encode_path(&expected_path)?;
            let target = self.deletion_targets.get(&encoded);
            let absence = self.durable_absences.get(&encoded);
            if target.is_some() == absence.is_some() {
                bail!("legacy retirement requires exactly one present-or-absent file state");
            }
            if let Some(target) = target {
                if target.evidence.kind != kind
                    || target.evidence.lock_root != binding.source_root
                    || target.evidence.sha256 != digest
                {
                    bail!("legacy retirement file evidence disagrees with its marker");
                }
            }
            if let Some(absence) = absence {
                if absence.kind != kind || absence.lock_root != binding.source_root {
                    bail!("legacy retirement absence disagrees with its marker");
                }
            }
        }
        let legacy_state_count = self
            .deletion_targets
            .values()
            .filter(|target| {
                matches!(
                    target.evidence.kind,
                    LifecycleFileKind::LegacyRecord | LifecycleFileKind::LegacyAdoptedKey
                )
            })
            .count()
            + self
                .durable_absences
                .values()
                .filter(|absence| {
                    matches!(
                        absence.kind,
                        LifecycleFileKind::LegacyRecord | LifecycleFileKind::LegacyAdoptedKey
                    )
                })
                .count();
        if legacy_state_count != 2 {
            bail!("legacy retirement contains surplus or missing authority state");
        }
        Ok(())
    }

    fn legacy_authority_absent_before_marker(&self) -> Result<bool> {
        let Some(binding) = &self.legacy_retirement else {
            return Ok(true);
        };
        for kind in [
            LifecycleFileKind::LegacyRecord,
            LifecycleFileKind::LegacyAdoptedKey,
        ] {
            let path = Path::new(&binding.source_root).join(kind.expected_basename());
            let encoded = encode_path(&path)?;
            if self
                .deletion_targets
                .get(&encoded)
                .is_some_and(|target| !target.proven_absent)
            {
                return Ok(false);
            }
            if !self.deletion_targets.contains_key(&encoded)
                && !self.durable_absences.contains_key(&encoded)
            {
                return Ok(false);
            }
        }
        Ok(true)
    }

    fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA {
            bail!("cleanup tombstone schema is unsupported");
        }
        validate_agent_root(Path::new(&self.canonical_root))?;
        validate_path_set(
            &self.lock_roots,
            MAX_ROOTS,
            validate_agent_root,
            "lock roots",
        )?;
        if !self.lock_roots.contains(&self.canonical_root) {
            bail!("cleanup lock roots omit the canonical lifecycle root");
        }
        self.authority.validate()?;
        match self.intent {
            CleanupIntent::ConvergeOpen => {
                if self.authority != AuthorityEvidence::NotRequested
                    || self.prior_activation == PriorActivation::Ambiguous
                {
                    bail!("Open cleanup has invalid authority or prior-state evidence");
                }
            }
            CleanupIntent::Close => {
                if self.authority != AuthorityEvidence::NotRequested {
                    bail!("Close cleanup cannot carry provider revocation authority");
                }
            }
            CleanupIntent::Remove => {
                if self.authority == AuthorityEvidence::NotRequested {
                    bail!("Remove cleanup omits authority-cut evidence");
                }
            }
            CleanupIntent::FullForget => {
                if matches!(
                    self.authority,
                    AuthorityEvidence::NotRequested
                        | AuthorityEvidence::UnavailableCorruptRecord { .. }
                ) {
                    bail!("FullForget lacks a terminal provider cleanup path");
                }
            }
        }
        validate_path_set(
            &self.peer_roots,
            MAX_ROOTS,
            validate_agent_root,
            "peer roots",
        )?;
        if !self.peer_roots.contains(&self.canonical_root)
            || !self.readiness_roots.contains(&self.canonical_root)
        {
            bail!("cleanup roots omit the canonical lifecycle root");
        }
        validate_path_set(
            &self.readiness_roots,
            MAX_ROOTS,
            validate_agent_root,
            "readiness roots",
        )?;
        let required_roots = self
            .peer_roots
            .union(&self.readiness_roots)
            .cloned()
            .collect::<BTreeSet<_>>();
        if required_roots.len() > MAX_ROOTS || required_roots != self.lock_roots {
            bail!("cleanup peer/readiness roots disagree with the exact captured lock set");
        }
        if self.observed_units.len() > MAX_UNITS {
            bail!("observed service definitions exceed their bound");
        }
        let mut loaded_effective_count = 0usize;
        for (path, unit) in &self.observed_units {
            unit.validate()?;
            if path != &unit.path {
                bail!("observed service definition key disagrees with its path");
            }
            if unit.roles.contains(&UnitRole::DesiredCurrent)
                && (path != &self.desired_unit.path || unit.sha256 != self.desired_unit.sha256)
            {
                bail!("DesiredCurrent role disagrees with the precommitted desired unit");
            }
            loaded_effective_count += usize::from(unit.roles.contains(&UnitRole::LoadedEffective));
        }
        if loaded_effective_count > 1 {
            bail!("more than one service definition is marked loaded effective");
        }
        if self.deletion_targets.len() > MAX_DELETION_TARGETS {
            bail!("lifecycle deletion targets exceed their bound");
        }
        for (path, target) in &self.deletion_targets {
            target.validate(Path::new(&self.canonical_root), self.intent)?;
            if path != &target.evidence.path {
                bail!("lifecycle deletion target key disagrees with its path");
            }
            match target.evidence.kind {
                LifecycleFileKind::ServiceReadiness
                | LifecycleFileKind::ServiceReadinessRequest => {
                    if !self.readiness_roots.contains(&target.evidence.lock_root) {
                        bail!("readiness deletion target is outside captured readiness roots");
                    }
                }
                LifecycleFileKind::LegacyRecord | LifecycleFileKind::LegacyAdoptedKey => {
                    if !self.peer_roots.contains(&target.evidence.lock_root) {
                        bail!("legacy deletion target is outside captured peer roots");
                    }
                }
                LifecycleFileKind::CanonicalRecord
                | LifecycleFileKind::CanonicalOwnerMarker
                | LifecycleFileKind::CanonicalStableKey
                | LifecycleFileKind::AdoptionMarker
                | LifecycleFileKind::EnrollmentDiagnostics
                | LifecycleFileKind::EnrollmentDiagnosticsTemporary
                | LifecycleFileKind::ServiceDefinition => {
                    if target.evidence.lock_root != self.canonical_root {
                        bail!("canonical deletion target is not bound to the canonical root");
                    }
                }
            }
            if target.evidence.kind == LifecycleFileKind::ServiceDefinition {
                let unit = self.observed_units.get(path).ok_or_else(|| {
                    anyhow::anyhow!("service deletion lacks observed unit evidence")
                })?;
                if unit.sha256 != target.evidence.sha256 {
                    bail!("service deletion digest disagrees with observed unit evidence");
                }
            }
        }
        if self.durable_absences.len() > 5 {
            bail!("durable lifecycle absences exceed their bound");
        }
        self.validate_legacy_retirement()?;
        for (path, absence) in &self.durable_absences {
            absence.validate()?;
            if path != &absence.path {
                bail!("durable absence key disagrees with its path");
            }
            match absence.kind {
                LifecycleFileKind::CanonicalRecord
                | LifecycleFileKind::CanonicalStableKey
                | LifecycleFileKind::AdoptionMarker => {
                    if absence.lock_root != self.canonical_root {
                        bail!("canonical authority absence uses a legacy lock root");
                    }
                }
                LifecycleFileKind::LegacyRecord | LifecycleFileKind::LegacyAdoptedKey => {
                    if absence.lock_root == self.canonical_root
                        || !self.peer_roots.contains(&absence.lock_root)
                    {
                        bail!("legacy authority absence is outside captured peer roots");
                    }
                }
                LifecycleFileKind::CanonicalOwnerMarker
                | LifecycleFileKind::ServiceReadiness
                | LifecycleFileKind::ServiceReadinessRequest
                | LifecycleFileKind::EnrollmentDiagnostics
                | LifecycleFileKind::EnrollmentDiagnosticsTemporary
                | LifecycleFileKind::ServiceDefinition => {
                    bail!("unsupported lifecycle absence kind")
                }
            }
            if self.deletion_targets.contains_key(path) {
                bail!("lifecycle path cannot be both present evidence and durable absence");
            }
        }
        if self.retained_evidence.len() > 1 {
            bail!("retained lifecycle evidence exceeds its bound");
        }
        for (path, evidence) in &self.retained_evidence {
            evidence.validate()?;
            if path != &evidence.path {
                bail!("retained lifecycle evidence key disagrees with its path");
            }
            if evidence.kind != LifecycleFileKind::CanonicalOwnerMarker
                || evidence.lock_root != self.canonical_root
            {
                bail!("retained lifecycle evidence is not the canonical owner marker");
            }
            if self.deletion_targets.contains_key(path) || self.durable_absences.contains_key(path)
            {
                bail!("retained lifecycle evidence conflicts with a destructive file state");
            }
        }
        let canonical_record_target = self
            .deletion_targets
            .values()
            .find(|target| target.evidence.kind == LifecycleFileKind::CanonicalRecord);
        let canonical_record_absence = self
            .durable_absences
            .values()
            .find(|absence| absence.kind == LifecycleFileKind::CanonicalRecord);
        let canonical_key_target = self
            .deletion_targets
            .values()
            .find(|target| target.evidence.kind == LifecycleFileKind::CanonicalStableKey);
        let canonical_key_absence = self
            .durable_absences
            .values()
            .find(|absence| absence.kind == LifecycleFileKind::CanonicalStableKey);
        match &self.authority {
            AuthorityEvidence::NotRequested => {
                if canonical_record_target.is_some()
                    || canonical_record_absence.is_some()
                    || !self.retained_evidence.is_empty()
                {
                    bail!("non-destructive lifecycle intent carries enrollment authority evidence");
                }
            }
            AuthorityEvidence::Target { record_sha256, .. } => {
                let target = canonical_record_target.ok_or_else(|| {
                    anyhow::anyhow!("provider target lacks exact canonical enrollment evidence")
                })?;
                if canonical_record_absence.is_some() || target.evidence.sha256 != *record_sha256 {
                    bail!("provider target disagrees with canonical enrollment evidence");
                }
                if !self.retained_evidence.is_empty() {
                    bail!("valid provider target cannot carry corrupt-owner evidence");
                }
            }
            AuthorityEvidence::NoActiveRecord => {
                if canonical_record_target.is_some()
                    || canonical_record_absence.is_none()
                    || !self.retained_evidence.is_empty()
                {
                    bail!("NoActiveRecord lacks its exact durable absence proof");
                }
            }
            AuthorityEvidence::UnavailableCorruptRecord {
                owner_sha256,
                record_sha256,
            } => {
                let target = canonical_record_target.ok_or_else(|| {
                    anyhow::anyhow!("corrupt enrollment lacks exact canonical record evidence")
                })?;
                let owner = self.retained_evidence.values().next().ok_or_else(|| {
                    anyhow::anyhow!("corrupt enrollment lacks retained owner evidence")
                })?;
                if canonical_record_absence.is_some()
                    || target.evidence.sha256 != *record_sha256
                    || owner.sha256 != *owner_sha256
                {
                    bail!("corrupt enrollment evidence digests are not structurally bound");
                }
            }
        }
        if self.intent == CleanupIntent::FullForget {
            if canonical_key_target.is_some() == canonical_key_absence.is_some() {
                bail!("FullForget requires exactly one canonical stable-key state");
            }
        } else if canonical_key_target.is_some() || canonical_key_absence.is_some() {
            bail!("only FullForget may carry canonical stable-key state");
        }
        self.desired_unit.validate()?;
        if let Some(manager) = &self.manager {
            manager.validate()?;
            if !self.peer_roots.contains(&manager.agent_root) {
                bail!("manager root is outside the captured peer roots");
            }
        }
        if let Some(handoff) = &self.provider_handoff {
            handoff.validate()?;
            if !matches!(
                self.intent,
                CleanupIntent::Remove | CleanupIntent::FullForget
            ) || self.authority.target_ref() != Some(handoff)
            {
                bail!("provider handoff is not bound to this destructive target");
            }
        }
        if let Some(receipt) = &self.provider_terminal {
            receipt.target.validate()?;
            if self.intent != CleanupIntent::FullForget
                || self.authority.target_ref() != Some(&receipt.target)
                || self.provider_handoff.as_ref() != Some(&receipt.target)
            {
                bail!("provider terminal receipt is not bound to this FullForget target");
            }
        }
        Ok(())
    }
}

fn intent_rank(intent: CleanupIntent) -> u8 {
    match intent {
        CleanupIntent::ConvergeOpen => 0,
        CleanupIntent::Close => 1,
        CleanupIntent::Remove => 2,
        CleanupIntent::FullForget => 3,
    }
}

pub fn may_supersede(pending: CleanupIntent, requested: CleanupIntent) -> bool {
    intent_rank(requested) > intent_rank(pending)
}

/// Provider revocation is intentionally separate from local cleanup. Ordinary
/// Remove can finish offline and permit a later explicit fresh-code enrollment,
/// including a non-destructive account rebind, while this bounded outbox keeps
/// retrying the exact old device. FullForget remains
/// pending until its target has left the outbox, because deleting the stable
/// key first would make provider cleanup impossible.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevocationOutbox {
    schema: u8,
    targets: BTreeMap<String, RevocationTarget>,
}

impl RevocationOutbox {
    fn empty() -> Self {
        Self {
            schema: SCHEMA,
            targets: BTreeMap::new(),
        }
    }

    pub fn targets(&self) -> impl Iterator<Item = &RevocationTarget> {
        self.targets.values()
    }

    fn validate(&self) -> Result<()> {
        if self.schema != SCHEMA || self.targets.len() > 16 {
            bail!("provider revocation outbox schema or bound is invalid");
        }
        for (device_id, target) in &self.targets {
            target.validate()?;
            if device_id != target.device_id() {
                bail!("provider revocation outbox key disagrees with its target");
            }
        }
        Ok(())
    }
}

pub fn revocation_outbox_path(agent_dir: &Path) -> PathBuf {
    recovery_dir(agent_dir).join(REVOCATION_OUTBOX_FILE_NAME)
}

pub fn load_revocation_outbox(agent_dir: &Path) -> Result<RevocationOutbox> {
    require_agent_parent(agent_dir)?;
    let recovery = recovery_dir(agent_dir);
    if !leaf_exists(&recovery)? {
        return Ok(RevocationOutbox::empty());
    }
    require_private_directory(&recovery)?;
    let Some(bytes) =
        read_private_regular_if_present(&revocation_outbox_path(agent_dir), MAX_FILE_BYTES)?
    else {
        return Ok(RevocationOutbox::empty());
    };
    let value: RevocationOutbox =
        serde_json::from_slice(&bytes).context("provider revocation outbox is invalid")?;
    value.validate()?;
    Ok(value)
}

pub fn enqueue_revocation(
    agent_dir: &Path,
    target: &RevocationTarget,
    lock: &crate::service::LifecycleLock,
) -> Result<()> {
    lock.require_agent_dir(agent_dir)
        .context("provider outbox lock is bound to another agent directory")?;
    target.validate()?;
    require_agent_parent(agent_dir)?;
    let recovery = recovery_dir(agent_dir);
    ensure_private_directory(&recovery)?;
    let mut outbox = load_revocation_outbox(agent_dir)?;
    if let Some(existing) = outbox.targets.get(target.device_id()) {
        if existing != target {
            bail!("provider revocation target conflicts with a queued device id");
        }
    } else {
        outbox
            .targets
            .insert(target.device_id().to_string(), target.clone());
    }
    outbox.validate()?;
    let bytes =
        serde_json::to_vec_pretty(&outbox).context("serialize provider revocation outbox")?;
    if bytes.len() > MAX_FILE_BYTES {
        bail!("provider revocation outbox exceeds its byte bound");
    }
    atomic_replace_private(&recovery, &revocation_outbox_path(agent_dir), &bytes)?;
    if load_revocation_outbox(agent_dir)? != outbox {
        bail!("provider revocation outbox readback differs from its durable write");
    }
    Ok(())
}

/// Durably hand an exact destructive target to the provider retry worker and
/// bind that fact into the lifecycle journal. The outbox write happens first
/// while the same canonical lifecycle lock is held; a crash before the receipt
/// simply retries the idempotent enqueue. Once this receipt exists, worker
/// completion may remove the outbox row without erasing proof that ordinary
/// Remove did not silently abandon provider cleanup.
pub fn handoff_revocation(
    agent_dir: &Path,
    target: &RevocationTarget,
    locks: &crate::service::LifecycleLockSet,
) -> Result<CleanupTombstone> {
    target.validate()?;
    let canonical_lock = locks
        .lock_for(agent_dir)
        .context("provider handoff lock set omits the canonical root")?;
    let mut tombstone = load(agent_dir)?
        .ok_or_else(|| anyhow::anyhow!("provider handoff has no pending transaction"))?;
    tombstone.reverify_persisted_state(locks)?;
    if !matches!(
        tombstone.intent(),
        CleanupIntent::Remove | CleanupIntent::FullForget
    ) || tombstone.revocation_target() != Some(target)
    {
        bail!("provider handoff target does not match the pending cleanup");
    }
    // A FullForget terminal receipt is the durable provider result. A retry
    // after the stable key was unlinked must never recreate the outbox row and
    // then wait forever for a key that was intentionally removed. If a crash
    // left the old row behind, finish that exact row without another network
    // call; if it is already absent, this is an idempotent no-op.
    if let Some(terminal) = tombstone.provider_terminal_target() {
        if terminal != target || tombstone.provider_handoff_target() != Some(target) {
            bail!("provider terminal receipt conflicts with the pending handoff");
        }
        complete_revocation(agent_dir, target.device_id(), canonical_lock)?;
        return load(agent_dir)?
            .ok_or_else(|| anyhow::anyhow!("provider-terminal lifecycle journal disappeared"));
    }
    enqueue_revocation(agent_dir, target, canonical_lock)?;
    if !load_revocation_outbox(agent_dir)?
        .targets()
        .any(|candidate| candidate == target)
    {
        bail!("provider handoff target was not durable in the retry outbox");
    }
    match &tombstone.provider_handoff {
        Some(existing) if existing != target => {
            bail!("provider handoff conflicts with its durable receipt")
        }
        Some(_) => return Ok(tombstone),
        None => tombstone.provider_handoff = Some(target.clone()),
    }
    publish_tombstone(agent_dir, &tombstone)
}

pub fn complete_revocation(
    agent_dir: &Path,
    device_id: &str,
    lock: &crate::service::LifecycleLock,
) -> Result<()> {
    lock.require_agent_dir(agent_dir)
        .context("provider outbox lock is bound to another agent directory")?;
    bounded_text(device_id, 512, "completed provider device id")?;
    let mut outbox = load_revocation_outbox(agent_dir)?;
    if outbox.targets.remove(device_id).is_none() {
        return Ok(());
    }
    let recovery = recovery_dir(agent_dir);
    if outbox.targets.is_empty() {
        let target = revocation_outbox_path(agent_dir);
        if read_private_regular_if_present(&target, MAX_FILE_BYTES)?.is_some() {
            fs::remove_file(&target).context("remove empty provider revocation outbox")?;
            sync_directory(&recovery)?;
        }
        match fs::symlink_metadata(&target) {
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Ok(_) => bail!("completed provider revocation outbox still exists"),
            Err(error) => return Err(error).context("prove provider outbox removal"),
        }
        remove_recovery_dir_if_empty(agent_dir)
    } else {
        let bytes =
            serde_json::to_vec_pretty(&outbox).context("serialize provider revocation outbox")?;
        if bytes.len() > MAX_FILE_BYTES {
            bail!("provider revocation outbox exceeds its byte bound");
        }
        atomic_replace_private(&recovery, &revocation_outbox_path(agent_dir), &bytes)?;
        if load_revocation_outbox(agent_dir)? != outbox {
            bail!("provider revocation outbox readback differs after completion");
        }
        Ok(())
    }
}

/// Persist the exact terminal provider result before removing it from the
/// retry outbox. A crash between these two durable writes is safe: the outbox
/// causes an idempotent provider retry, while key deletion remains blocked.
pub fn record_full_forget_provider_terminal(
    agent_dir: &Path,
    target: &RevocationTarget,
    outcome: ProviderTerminalOutcome,
    locks: &crate::service::LifecycleLockSet,
) -> Result<CleanupTombstone> {
    target.validate()?;
    let mut tombstone = load(agent_dir)?
        .ok_or_else(|| anyhow::anyhow!("provider terminal receipt has no pending transaction"))?;
    tombstone.reverify_persisted_state(locks)?;
    if tombstone.intent() != CleanupIntent::FullForget
        || tombstone.revocation_target() != Some(target)
        || tombstone.provider_handoff_target() != Some(target)
    {
        bail!("provider terminal result does not match the pending FullForget target");
    }
    let receipt = ProviderTerminalReceipt {
        target: target.clone(),
        outcome,
    };
    match &tombstone.provider_terminal {
        Some(existing) if existing != &receipt => {
            bail!("provider terminal result conflicts with its durable receipt")
        }
        Some(_) => return Ok(tombstone),
        None => tombstone.provider_terminal = Some(receipt),
    }
    publish_tombstone(agent_dir, &tombstone)
}

/// The stable device key begins the final FullForget authority cut. It is permitted
/// only while the exact lifecycle lock is held, after an exact target-bound
/// terminal receipt is durable, and after every queued provider cleanup has
/// been durably removed. A precommitted owner-marker deletion may remain; it
/// must run strictly after this key deletion.
pub fn full_forget_key_deletion_ready(
    agent_dir: &Path,
    locks: &crate::service::LifecycleLockSet,
) -> Result<bool> {
    let Some(tombstone) = load(agent_dir)? else {
        return Ok(false);
    };
    tombstone.validate()?;
    tombstone.reverify_persisted_state(locks)?;
    if tombstone.intent() != CleanupIntent::FullForget {
        return Ok(false);
    }
    let provider_terminal = match tombstone.authority() {
        AuthorityEvidence::Target { target, .. } => {
            tombstone.provider_handoff_target() == Some(target)
                && tombstone.provider_terminal_target() == Some(target)
        }
        AuthorityEvidence::NoActiveRecord => true,
        AuthorityEvidence::NotRequested | AuthorityEvidence::UnavailableCorruptRecord { .. } => {
            false
        }
    };
    let every_non_final_deletion_is_proven = tombstone.deletion_targets.values().all(|planned| {
        matches!(
            planned.evidence.kind,
            LifecycleFileKind::CanonicalStableKey | LifecycleFileKind::CanonicalOwnerMarker
        ) || planned.proven_absent
    });
    Ok(provider_terminal
        && every_non_final_deletion_is_proven
        && load_revocation_outbox(agent_dir)?
            .targets()
            .next()
            .is_none())
}

fn bounded_text(value: &str, max: usize, label: &str) -> Result<()> {
    if value.is_empty() || value.len() > max || value.chars().any(char::is_control) {
        bail!("{label} is empty, unbounded, or contains control characters");
    }
    Ok(())
}

fn validate_build_stamp(value: &str) -> Result<()> {
    let (git, built) = value
        .strip_prefix("git=")
        .and_then(|value| value.split_once(" built="))
        .ok_or_else(|| anyhow::anyhow!("manager build stamp has an invalid shape"))?;
    if git.is_empty()
        || git.len() > 96
        || !git
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        || built.is_empty()
        || built.len() > 24
        || !built.bytes().all(|byte| byte.is_ascii_digit())
    {
        bail!("manager build stamp is not canonical");
    }
    Ok(())
}

fn validate_sha256(value: &str, label: &str) -> Result<()> {
    if value.len() != 64
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        bail!("{label} is invalid");
    }
    Ok(())
}

fn sha256(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn validate_absolute_path(path: &Path, label: &str) -> Result<()> {
    if !crate::agent_dir::is_canonically_encoded_absolute_path(path)
        || path.as_os_str().len() > MAX_PATH_BYTES
    {
        bail!("{label} is not a bounded normalized absolute path");
    }
    Ok(())
}

fn validate_agent_root(path: &Path) -> Result<()> {
    validate_absolute_path(path, "agent root")?;
    if path.file_name().and_then(|name| name.to_str()) != Some("hydra-agent") {
        bail!("agent root has an unexpected basename");
    }
    Ok(())
}

fn validate_unit_path(path: &Path) -> Result<()> {
    validate_absolute_path(path, "service definition path")?;
    #[cfg(target_os = "macos")]
    let expected = "com.hydra.agent.plist";
    #[cfg(not(target_os = "macos"))]
    let expected = "hydra-agent.service";
    if path.file_name().and_then(|name| name.to_str()) != Some(expected) {
        bail!("service definition path has an unexpected basename");
    }
    Ok(())
}

fn validate_lifecycle_file_path(path: &Path, kind: LifecycleFileKind) -> Result<()> {
    validate_absolute_path(path, "lifecycle file path")?;
    if path.file_name().and_then(|name| name.to_str()) != Some(kind.expected_basename()) {
        bail!("lifecycle file path has an unexpected basename");
    }
    Ok(())
}

fn encode_path(path: &Path) -> Result<String> {
    validate_absolute_path(path, "cleanup evidence path")?;
    path.to_str()
        .map(str::to_string)
        .ok_or_else(|| anyhow::anyhow!("cleanup evidence path is not Unicode"))
}

fn encode_locked_paths(
    paths: &BTreeSet<PathBuf>,
    locks: &crate::service::LifecycleLockSet,
) -> Result<BTreeSet<String>> {
    paths
        .iter()
        .map(|path| {
            let root = locks
                .lock_for(path)
                .context("captured lifecycle root is not held by the lock set")?
                .root();
            encode_path(root)
        })
        .collect()
}

fn decode_paths(paths: &BTreeSet<String>) -> Result<BTreeSet<PathBuf>> {
    paths
        .iter()
        .map(|path| {
            let path = PathBuf::from(path);
            validate_absolute_path(&path, "cleanup evidence path")?;
            Ok(path)
        })
        .collect()
}

fn validate_path_set(
    paths: &BTreeSet<String>,
    max: usize,
    validator: fn(&Path) -> Result<()>,
    label: &str,
) -> Result<()> {
    if paths.is_empty() || paths.len() > max {
        bail!("cleanup {label} is empty or exceeds its bound");
    }
    for path in paths {
        validator(Path::new(path))?;
    }
    Ok(())
}

pub fn recovery_dir(agent_dir: &Path) -> PathBuf {
    agent_dir.join(DIRECTORY_NAME)
}

pub fn path(agent_dir: &Path) -> PathBuf {
    recovery_dir(agent_dir).join(FILE_NAME)
}

pub fn load(agent_dir: &Path) -> Result<Option<CleanupTombstone>> {
    require_agent_parent(agent_dir)?;
    let recovery = recovery_dir(agent_dir);
    if !leaf_exists(&recovery)? {
        return Ok(None);
    }
    require_private_directory(&recovery)?;
    let Some(bytes) = read_private_regular_if_present(&path(agent_dir), MAX_FILE_BYTES)? else {
        return Ok(None);
    };
    let value: CleanupTombstone =
        serde_json::from_slice(&bytes).context("cleanup tombstone is invalid")?;
    value.validate()?;
    Ok(Some(value))
}

pub fn store(
    agent_dir: &Path,
    proposed: &CleanupTombstone,
    locks: &crate::service::LifecycleLockSet,
) -> Result<CleanupTombstone> {
    proposed.validate()?;
    proposed.reverify_persisted_state(locks)?;
    require_agent_parent(agent_dir)?;
    let recovery = recovery_dir(agent_dir);
    ensure_private_directory(&recovery)?;
    let value = match load(agent_dir)? {
        Some(existing) => {
            existing.reverify_persisted_state(locks)?;
            existing.merged_retry(proposed)?
        }
        None => proposed.clone(),
    };
    value.reverify_persisted_state(locks)?;
    publish_tombstone(agent_dir, &value)
}

fn publish_tombstone(agent_dir: &Path, value: &CleanupTombstone) -> Result<CleanupTombstone> {
    value.validate()?;
    let recovery = recovery_dir(agent_dir);
    ensure_private_directory(&recovery)?;
    let bytes = serde_json::to_vec_pretty(&value).context("serialize cleanup tombstone")?;
    if bytes.len() > MAX_FILE_BYTES {
        bail!("cleanup tombstone exceeds its byte bound");
    }
    atomic_replace_private(&recovery, &path(agent_dir), &bytes)?;
    let readback = load(agent_dir)?.ok_or_else(|| anyhow::anyhow!("cleanup tombstone vanished"))?;
    if readback != *value {
        bail!("cleanup tombstone readback differs from its durable write");
    }
    Ok(readback)
}

/// Replace a weaker pending intent without an evidence gap. Any provider
/// target owned by the old transaction is first made durable in the outbox;
/// only then is the new journal atomically published and read back. A failure
/// in either step leaves the old journal authoritative.
pub fn supersede(
    agent_dir: &Path,
    requested: &CleanupTombstone,
    locks: &crate::service::LifecycleLockSet,
) -> Result<CleanupTombstone> {
    requested.validate()?;
    requested.reverify_persisted_state(locks)?;
    let mut pending = load(agent_dir)?
        .ok_or_else(|| anyhow::anyhow!("cleanup supersession has no pending transaction"))?;
    pending.reverify_persisted_state(locks)?;
    // A crash may unlink an old target before its proof write. A freshly
    // captured stronger intent then carries durable absence for that path.
    // Complete the old exact target (AlreadyAbsent) first, so the replacement
    // never contains contradictory present and absent evidence.
    let conflicting_absences = requested
        .durable_absences
        .keys()
        .filter(|path| {
            pending
                .deletion_targets
                .get(*path)
                .is_some_and(|target| !target.proven_absent)
        })
        .cloned()
        .collect::<Vec<_>>();
    for path in conflicting_absences {
        pending = execute_planned_deletion(agent_dir, &pending, Path::new(&path), locks)?;
    }
    let replacement = pending.merged_supersession_evidence(requested)?;
    let canonical_lock = locks
        .lock_for(agent_dir)
        .context("cleanup supersession lock set omits the canonical root")?;
    if let Some(target) = pending.revocation_target() {
        enqueue_revocation(agent_dir, target, canonical_lock)?;
        if !load_revocation_outbox(agent_dir)?
            .targets()
            .any(|candidate| candidate == target)
        {
            bail!("old provider target was not durable before supersession");
        }
    }
    publish_tombstone(agent_dir, &replacement)
}

/// Promote an already-durable ordinary Remove transaction to FullForget
/// without recapturing a weaker current filesystem view. The existing journal
/// remains the source of truth for roots, units, peers, and provider target;
/// this adds only the exact stable-key and private diagnostic states required by the stronger intent,
/// then routes through the normal supersession merge. Downgrades are never
/// represented by this API.
pub fn supersede_remove_with_full_forget(
    agent_dir: &Path,
    locks: &crate::service::LifecycleLockSet,
) -> Result<CleanupTombstone> {
    let pending = load(agent_dir)?
        .ok_or_else(|| anyhow::anyhow!("FullForget supersession has no pending transaction"))?;
    pending.reverify_persisted_state(locks)?;
    if pending.intent != CleanupIntent::Remove {
        bail!("only a pending Remove may be promoted to FullForget");
    }
    if matches!(
        pending.authority,
        AuthorityEvidence::NotRequested | AuthorityEvidence::UnavailableCorruptRecord { .. }
    ) {
        bail!("pending Remove lacks a safe FullForget provider path");
    }
    let mut requested = pending.clone();
    requested.intent = CleanupIntent::FullForget;
    for kind in [
        LifecycleFileKind::EnrollmentDiagnosticsTemporary,
        LifecycleFileKind::EnrollmentDiagnostics,
    ] {
        let diagnostics_path = Path::new(&requested.canonical_root).join(kind.expected_basename());
        if let Some(diagnostics) = ExactFileEvidence::capture(
            Path::new(&requested.canonical_root),
            &diagnostics_path,
            kind,
            locks,
        )? {
            requested.deletion_targets.insert(
                encode_path(&diagnostics.path())?,
                PlannedDeletion::pending(diagnostics),
            );
        }
    }
    let key_path = Path::new(&requested.canonical_root)
        .join(LifecycleFileKind::CanonicalStableKey.expected_basename());
    if let Some(key) = ExactFileEvidence::capture(
        Path::new(&requested.canonical_root),
        &key_path,
        LifecycleFileKind::CanonicalStableKey,
        locks,
    )? {
        let encoded = encode_path(&key.path())?;
        requested
            .deletion_targets
            .insert(encoded, PlannedDeletion::pending(key));
    } else {
        let absence = DurableFileAbsence::capture(
            Path::new(&requested.canonical_root),
            &key_path,
            LifecycleFileKind::CanonicalStableKey,
            locks,
        )?
        .ok_or_else(|| anyhow::anyhow!("stable-key state changed during supersession"))?;
        requested
            .durable_absences
            .insert(encode_path(&absence.path())?, absence);
    }
    requested.validate()?;
    supersede(agent_dir, &requested, locks)
}

/// Execute exactly one precommitted deletion and durably mark its proof in the
/// same journal. The expected snapshot prevents a stale finisher from
/// modifying a superseding transaction. A crash after unlink but before the
/// proof write retries through the primitive's AlreadyAbsent path.
pub fn execute_planned_deletion(
    agent_dir: &Path,
    expected: &CleanupTombstone,
    target_path: &Path,
    locks: &crate::service::LifecycleLockSet,
) -> Result<CleanupTombstone> {
    expected.validate()?;
    expected.reverify_persisted_state(locks)?;
    let current = load(agent_dir)?
        .ok_or_else(|| anyhow::anyhow!("planned deletion has no durable lifecycle journal"))?;
    if current != *expected {
        bail!("cleanup journal changed before planned deletion");
    }
    current.reverify_persisted_state(locks)?;
    let direct = encode_path(target_path)?;
    let encoded = if current.deletion_targets.contains_key(&direct) {
        direct
    } else {
        let parent = target_path
            .parent()
            .ok_or_else(|| anyhow::anyhow!("planned deletion path has no parent"))?;
        let canonical_parent = fs::canonicalize(parent)
            .context("resolve planned deletion parent under the captured lock set")?;
        let basename = target_path
            .file_name()
            .ok_or_else(|| anyhow::anyhow!("planned deletion path has no basename"))?;
        encode_path(&canonical_parent.join(basename))?
    };
    let planned = current
        .deletion_targets
        .get(&encoded)
        .ok_or_else(|| anyhow::anyhow!("path is not a precommitted lifecycle deletion target"))?;
    if planned.proven_absent {
        return Ok(current);
    }
    if planned.evidence.kind == LifecycleFileKind::CanonicalStableKey {
        if !full_forget_key_deletion_ready(agent_dir, locks)? {
            bail!("canonical stable key deletion is not provider-terminal and locally last");
        }
        if current.deletion_targets.iter().any(|(path, target)| {
            path != &encoded
                && target.evidence.kind != LifecycleFileKind::CanonicalOwnerMarker
                && !target.proven_absent
        }) {
            bail!("canonical stable key deletion must follow every non-owner deletion");
        }
    }
    if planned.evidence.kind == LifecycleFileKind::CanonicalOwnerMarker
        && (current.intent != CleanupIntent::FullForget
            || current.deletion_targets.values().any(|target| {
                target.evidence.kind != LifecycleFileKind::CanonicalOwnerMarker
                    && !target.proven_absent
            }))
    {
        bail!("canonical owner deletion must be the final FullForget deletion");
    }
    if planned.evidence.kind == LifecycleFileKind::AdoptionMarker
        && !current.legacy_authority_absent_before_marker()?
    {
        bail!("adoption marker deletion must follow exact legacy authority retirement");
    }
    remove_exact_file_durably(&planned.evidence, locks)?;
    let mut completed = current;
    completed
        .deletion_targets
        .get_mut(&encoded)
        .expect("validated deletion target remains present")
        .proven_absent = true;
    publish_tombstone(agent_dir, &completed)
}

pub fn clear(
    agent_dir: &Path,
    expected: &CleanupTombstone,
    locks: &crate::service::LifecycleLockSet,
) -> Result<()> {
    expected.validate()?;
    expected.reverify_persisted_state(locks)?;
    require_agent_parent(agent_dir)?;
    let recovery = recovery_dir(agent_dir);
    if !leaf_exists(&recovery)? {
        return Ok(());
    }
    require_private_directory(&recovery)?;
    // Validate the complete directory before deleting the durable journal. An
    // unexpected entry must leave recovery evidence intact.
    remove_stale_temporaries(&recovery)?;
    let target = path(agent_dir);
    if let Some(current) = load(agent_dir)? {
        if current != *expected {
            bail!("cleanup journal changed before completion could be cleared");
        }
        current.reverify_persisted_state(locks)?;
        if !current.all_deletions_proven() {
            bail!("cleanup journal still has unproven deletion targets");
        }
        current.prove_service_definitions_retired(locks)?;
        if matches!(
            current.intent,
            CleanupIntent::Remove | CleanupIntent::FullForget
        ) && current.authority.target_ref().is_some()
            && current.provider_handoff.as_ref() != current.authority.target_ref()
        {
            bail!("cleanup cannot clear before durable provider handoff");
        }
        if current.intent == CleanupIntent::FullForget
            && !full_forget_key_deletion_ready(agent_dir, locks)?
        {
            bail!("FullForget cannot clear before provider, outbox, and key completion");
        }
        fs::remove_file(&target).context("remove completed cleanup tombstone")?;
        sync_directory(&recovery).context("sync completed cleanup removal")?;
    }
    match fs::symlink_metadata(&target) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Ok(_) => bail!("completed cleanup tombstone still exists"),
        Err(error) => return Err(error).context("prove cleanup tombstone removal"),
    }
    remove_recovery_dir_if_empty(agent_dir)
}

fn remove_recovery_dir_if_empty(agent_dir: &Path) -> Result<()> {
    let recovery = recovery_dir(agent_dir);
    match fs::remove_dir(&recovery) {
        Ok(()) => sync_directory(agent_dir).context("sync lifecycle recovery directory removal"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::DirectoryNotEmpty => Ok(()),
        Err(error) => Err(error).context("remove lifecycle recovery directory"),
    }
}

fn remove_stale_temporaries(recovery: &Path) -> Result<()> {
    let prefix = format!(".{FILE_NAME}.");
    let outbox_prefix = format!(".{REVOCATION_OUTBOX_FILE_NAME}.");
    let mut count = 0usize;
    for entry in fs::read_dir(recovery).context("inventory lifecycle recovery directory")? {
        let entry = entry.context("read lifecycle recovery directory entry")?;
        let name = entry.file_name();
        let Some(name) = name.to_str() else {
            bail!("lifecycle recovery directory contains a non-Unicode entry");
        };
        if name == FILE_NAME || name == REVOCATION_OUTBOX_FILE_NAME {
            continue;
        }
        count += 1;
        if count > 8
            || (!(name.starts_with(&prefix) || name.starts_with(&outbox_prefix))
                || !name.ends_with(".tmp"))
        {
            bail!("lifecycle recovery directory contains an unreviewed entry");
        }
        if read_private_regular_if_present(&entry.path(), MAX_FILE_BYTES)?.is_none() {
            bail!("stale lifecycle temporary vanished ambiguously");
        }
        fs::remove_file(entry.path()).context("remove stale lifecycle temporary")?;
    }
    if count > 0 {
        sync_directory(recovery).context("sync stale lifecycle temporary cleanup")?;
    }
    Ok(())
}

fn leaf_exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error).context("inspect lifecycle recovery path"),
    }
}

#[cfg(unix)]
fn expected_uid() -> u32 {
    crate::agent_dir::trusted_uid()
}

#[cfg(unix)]
fn require_agent_parent(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    if !dir.is_absolute() {
        bail!("agent directory must be absolute");
    }
    let metadata = fs::symlink_metadata(dir).context("inspect agent directory")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid()
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("agent directory is not an owned real directory");
    }
    Ok(())
}

#[cfg(unix)]
fn ensure_private_directory(dir: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt as _;
    let mut builder = fs::DirBuilder::new();
    builder.mode(0o700);
    match builder.create(dir) {
        Ok(()) => sync_directory(dir.parent().expect("recovery directory has a parent"))?,
        Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
        Err(error) => return Err(error).context("create lifecycle recovery directory"),
    }
    require_private_directory(dir)
}

#[cfg(unix)]
fn require_private_directory(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = fs::symlink_metadata(dir).context("inspect lifecycle recovery directory")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid()
        || metadata.permissions().mode() & 0o777 != 0o700
    {
        bail!("lifecycle recovery directory is not owner-private");
    }
    Ok(())
}

#[cfg(unix)]
fn require_owned_safe_directory(dir: &Path) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let metadata = fs::symlink_metadata(dir).context("inspect lifecycle file parent")?;
    if !metadata.file_type().is_dir()
        || metadata.uid() != expected_uid()
        || metadata.permissions().mode() & 0o022 != 0
    {
        bail!("lifecycle file parent is not an owned safe directory");
    }
    Ok(())
}

#[cfg(unix)]
struct ExactRegularFile {
    bytes: Vec<u8>,
    mode: u32,
    owner_uid: u32,
    device: u64,
    inode: u64,
}

#[cfg(unix)]
fn read_exact_owned_regular_if_present(
    path: &Path,
    max: usize,
) -> Result<Option<ExactRegularFile>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let before = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect exact lifecycle file"),
    };
    if !before.file_type().is_file() || before.uid() != expected_uid() || before.nlink() != 1 {
        bail!("exact lifecycle file has unsafe metadata");
    }
    let mode = before.permissions().mode() & 0o7777;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .context("open exact lifecycle file")?;
    let opened = file.metadata().context("inspect opened lifecycle file")?;
    if !opened.file_type().is_file()
        || opened.uid() != expected_uid()
        || opened.nlink() != 1
        || opened.dev() != before.dev()
        || opened.ino() != before.ino()
        || opened.permissions().mode() & 0o7777 != mode
    {
        bail!("exact lifecycle file changed during capture");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read exact lifecycle file")?;
    if bytes.len() > max {
        bail!("exact lifecycle file exceeds its byte bound");
    }
    Ok(Some(ExactRegularFile {
        bytes,
        mode,
        owner_uid: opened.uid(),
        device: opened.dev(),
        inode: opened.ino(),
    }))
}

#[cfg(unix)]
fn read_private_regular_if_present(path: &Path, max: usize) -> Result<Option<Vec<u8>>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    let metadata = match fs::symlink_metadata(path) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("inspect cleanup tombstone"),
    };
    let safe = |metadata: &fs::Metadata| {
        metadata.file_type().is_file()
            && metadata.uid() == expected_uid()
            && metadata.nlink() == 1
            && metadata.permissions().mode() & 0o777 == 0o600
    };
    if !safe(&metadata) {
        bail!("cleanup tombstone has unsafe metadata");
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .context("open cleanup tombstone")?;
    if !safe(
        &file
            .metadata()
            .context("inspect opened cleanup tombstone")?,
    ) {
        bail!("opened cleanup tombstone has unsafe metadata");
    }
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)
        .context("read cleanup tombstone")?;
    if bytes.len() > max {
        bail!("cleanup tombstone exceeds its byte bound");
    }
    Ok(Some(bytes))
}

#[cfg(unix)]
fn atomic_replace_private(dir: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};
    // Every publisher holds this root's lifecycle lock. Removing only the
    // reviewed private temporary shape here makes a crash followed by PID and
    // process-counter reuse recoverable rather than permanently wedged.
    remove_stale_temporaries(dir)?;
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::Relaxed);
    let temporary = dir.join(format!(
        ".{FILE_NAME}.{}.{}.tmp",
        std::process::id(),
        sequence
    ));
    let mut file = OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(&temporary)
        .context("create cleanup tombstone temporary file")?;
    let result = (|| -> Result<()> {
        file.write_all(bytes).context("write cleanup tombstone")?;
        file.sync_all().context("sync cleanup tombstone")?;
        match fs::symlink_metadata(target) {
            Ok(metadata)
                if metadata.file_type().is_file()
                    && metadata.uid() == expected_uid()
                    && metadata.nlink() == 1
                    && metadata.permissions().mode() & 0o777 == 0o600 => {}
            Ok(_) => bail!("existing lifecycle record has unsafe metadata"),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error).context("inspect existing lifecycle record"),
        }
        fs::rename(&temporary, target).context("publish cleanup tombstone")?;
        sync_directory(dir).context("sync lifecycle recovery directory")
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

#[cfg(unix)]
fn sync_directory(dir: &Path) -> Result<()> {
    use std::os::unix::fs::OpenOptionsExt as _;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW)
        .open(dir)
        .context("open directory for durable sync")?
        .sync_all()
        .context("sync directory")
}

#[cfg(not(unix))]
fn require_agent_parent(dir: &Path) -> Result<()> {
    if dir.is_absolute() && dir.is_dir() {
        Ok(())
    } else {
        bail!("agent directory is unavailable")
    }
}

#[cfg(not(unix))]
fn ensure_private_directory(dir: &Path) -> Result<()> {
    fs::create_dir(dir).context("create lifecycle recovery directory")
}

#[cfg(not(unix))]
fn require_private_directory(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        Ok(())
    } else {
        bail!("lifecycle recovery directory is unavailable")
    }
}

#[cfg(not(unix))]
fn require_owned_safe_directory(dir: &Path) -> Result<()> {
    if dir.is_dir() {
        Ok(())
    } else {
        bail!("lifecycle file parent is unavailable")
    }
}

#[cfg(not(unix))]
struct ExactRegularFile {
    bytes: Vec<u8>,
    mode: u32,
    owner_uid: u32,
    device: u64,
    inode: u64,
}

#[cfg(not(unix))]
fn read_exact_owned_regular_if_present(
    path: &Path,
    max: usize,
) -> Result<Option<ExactRegularFile>> {
    let Some(bytes) = read_private_regular_if_present(path, max)? else {
        return Ok(None);
    };
    Ok(Some(ExactRegularFile {
        bytes,
        mode: 0o600,
        owner_uid: expected_uid(),
        device: 0,
        inode: 0,
    }))
}

#[cfg(not(unix))]
fn read_private_regular_if_present(path: &Path, max: usize) -> Result<Option<Vec<u8>>> {
    let mut file = match fs::File::open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error).context("open cleanup tombstone"),
    };
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((max + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        bail!("cleanup tombstone exceeds its byte bound");
    }
    Ok(Some(bytes))
}

#[cfg(not(unix))]
fn atomic_replace_private(dir: &Path, target: &Path, bytes: &[u8]) -> Result<()> {
    remove_stale_temporaries(dir)?;
    let temporary = dir.join(format!(".{FILE_NAME}.{}.tmp", std::process::id()));
    fs::write(&temporary, bytes)?;
    fs::rename(&temporary, target)?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_directory(_dir: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deletion_target_bound_includes_the_full_max_shape_and_two_diagnostics() {
        assert_eq!(MAX_PRE_DIAGNOSTIC_DELETION_TARGETS, 24);
        assert_eq!(MAX_ENROLLMENT_DIAGNOSTIC_DELETION_TARGETS, 2);
        assert_eq!(MAX_DELETION_TARGETS, 26);
        assert_eq!(MAX_DELETION_TARGETS, MAX_UNITS + (2 * MAX_ROOTS) + 6 + 2);
    }

    fn secure_tempdir() -> tempfile::TempDir {
        let base = fs::canonicalize(std::env::temp_dir()).unwrap();
        let temp = tempfile::Builder::new()
            .prefix("hydra-lifecycle-cleanup-")
            .tempdir_in(base)
            .unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(temp.path(), fs::Permissions::from_mode(0o700)).unwrap();
        }
        temp
    }

    fn synthetic_record_bytes() -> Vec<u8> {
        serde_json::to_vec(&serde_json::json!({
            "device_id": "dev_synthetic",
            "account_id": "acct_synthetic",
            "cloud_base": crate::release_trust::CLOUD_BASE,
        }))
        .unwrap()
    }

    fn lifecycle_lock_set(agent: &Path) -> crate::service::LifecycleLockSet {
        crate::service::LifecycleLockSet::acquire([agent.to_path_buf()]).unwrap()
    }

    fn create_safe_directory(path: &Path) {
        #[cfg(unix)]
        {
            use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _};
            let mut builder = fs::DirBuilder::new();
            builder.recursive(true).mode(0o700).create(path).unwrap();
            fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
        }
        #[cfg(not(unix))]
        fs::create_dir_all(path).unwrap();
    }

    fn exact_record_fixture() -> (
        tempfile::TempDir,
        PathBuf,
        PathBuf,
        crate::service::LifecycleLockSet,
        ExactFileEvidence,
    ) {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let record = agent.join("device.json");
        fs::write(&record, synthetic_record_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let locks = lifecycle_lock_set(&agent);
        let agent = fs::canonicalize(&agent).unwrap();
        let record = agent.join("device.json");
        let evidence =
            ExactFileEvidence::capture(&agent, &record, LifecycleFileKind::CanonicalRecord, &locks)
                .unwrap()
                .unwrap();
        (temp, agent, record, locks, evidence)
    }

    #[cfg(unix)]
    fn stored_remove_fixture() -> (tempfile::TempDir, PathBuf, crate::service::LifecycleLockSet) {
        use std::os::unix::fs::PermissionsExt as _;

        let (temp, agent, _record, locks, record_evidence) = exact_record_fixture();
        let key = agent.join("device-key");
        fs::write(&key, b"synthetic stable key").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let roots = BTreeSet::from([agent.clone()]);
        let remove = CleanupTombstone::new(
            CleanupIntent::Remove,
            PriorActivation::ProvenClosed,
            AuthorityEvidence::target_from_exact_record(&record_evidence, &locks).unwrap(),
            &agent,
            &roots,
            &roots,
            [],
            [record_evidence],
            DesiredUnit::from_bytes(
                &unit_path(temp.path()),
                b"synthetic desired service definition",
            )
            .unwrap(),
            None,
            &locks,
        )
        .unwrap();
        store(&agent, &remove, &locks).unwrap();
        (temp, agent, locks)
    }

    #[cfg(unix)]
    struct LegacyRetirementFixture {
        _temp: tempfile::TempDir,
        agent: PathBuf,
        legacy_record: PathBuf,
        legacy_key: PathBuf,
        marker: PathBuf,
        locks: crate::service::LifecycleLockSet,
        tombstone: CleanupTombstone,
    }

    #[cfg(unix)]
    fn legacy_retirement_fixture(
        legacy_record_present: bool,
        legacy_key_present: bool,
    ) -> LegacyRetirementFixture {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let agent = fs::canonicalize(&agent).unwrap();
        let canonical_record = agent.join("device.json");
        fs::write(&canonical_record, synthetic_record_bytes()).unwrap();
        fs::set_permissions(&canonical_record, fs::Permissions::from_mode(0o600)).unwrap();

        let legacy = temp.path().join("legacy/hydra-agent");
        create_safe_directory(&legacy);
        let legacy = fs::canonicalize(&legacy).unwrap();
        let legacy_record_bytes = b"synthetic legacy enrollment";
        let legacy_record = legacy.join("device.json");
        if legacy_record_present {
            fs::write(&legacy_record, legacy_record_bytes).unwrap();
            fs::set_permissions(&legacy_record, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let legacy_key_bytes = b"synthetic legacy seed";
        let legacy_key = legacy.join("device-key");
        if legacy_key_present {
            fs::write(&legacy_key, legacy_key_bytes).unwrap();
            fs::set_permissions(&legacy_key, fs::Permissions::from_mode(0o600)).unwrap();
        }

        let marker = agent.join(LifecycleFileKind::AdoptionMarker.expected_basename());
        fs::write(
            &marker,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema": 1,
                "source_agent_dir": legacy.to_str().unwrap(),
                "account_id": "acct_synthetic",
                "device_id": "dev_synthetic",
                "key_sha256": sha256(legacy_key_bytes),
                "record_sha256": sha256(legacy_record_bytes),
                "owner_sha256": sha256(b"synthetic owner marker"),
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();

        let locks =
            crate::service::LifecycleLockSet::acquire([agent.clone(), legacy.clone()]).unwrap();
        let mut deletion_targets = vec![
            ExactFileEvidence::capture(
                &agent,
                &canonical_record,
                LifecycleFileKind::CanonicalRecord,
                &locks,
            )
            .unwrap()
            .unwrap(),
            ExactFileEvidence::capture(&agent, &marker, LifecycleFileKind::AdoptionMarker, &locks)
                .unwrap()
                .unwrap(),
        ];
        if legacy_record_present {
            deletion_targets.push(
                ExactFileEvidence::capture(
                    &legacy,
                    &legacy_record,
                    LifecycleFileKind::LegacyRecord,
                    &locks,
                )
                .unwrap()
                .unwrap(),
            );
        }
        if legacy_key_present {
            deletion_targets.push(
                ExactFileEvidence::capture(
                    &legacy,
                    &legacy_key,
                    LifecycleFileKind::LegacyAdoptedKey,
                    &locks,
                )
                .unwrap()
                .unwrap(),
            );
        }
        let roots = BTreeSet::from([agent.clone(), legacy]);
        let tombstone = CleanupTombstone::new(
            CleanupIntent::Remove,
            PriorActivation::ProvenClosed,
            AuthorityEvidence::target_from_record_bytes(&synthetic_record_bytes()).unwrap(),
            &agent,
            &roots,
            &roots,
            [],
            deletion_targets,
            DesiredUnit::from_bytes(&unit_path(temp.path()), b"synthetic desired unit").unwrap(),
            None,
            &locks,
        )
        .unwrap();
        LegacyRetirementFixture {
            _temp: temp,
            agent,
            legacy_record,
            legacy_key,
            marker,
            locks,
            tombstone,
        }
    }

    fn unit_path(root: &Path) -> PathBuf {
        #[cfg(target_os = "macos")]
        return root.join("LaunchAgents/com.hydra.agent.plist");
        #[cfg(not(target_os = "macos"))]
        return root.join("systemd/hydra-agent.service");
    }

    fn sample(root: &Path, intent: CleanupIntent) -> CleanupTombstone {
        let requested_agent = root.join("hydra-agent");
        let agent = fs::canonicalize(&requested_agent).unwrap_or(requested_agent);
        let effective_root = agent.parent().unwrap_or(root);
        let unit = unit_path(effective_root);
        let record_bytes = synthetic_record_bytes();
        let authority = match intent {
            CleanupIntent::ConvergeOpen | CleanupIntent::Close => AuthorityEvidence::NotRequested,
            CleanupIntent::Remove | CleanupIntent::FullForget => {
                AuthorityEvidence::target_from_record_bytes(&record_bytes).unwrap()
            }
        };
        let mut deletion_targets = BTreeMap::new();
        if matches!(intent, CleanupIntent::Remove | CleanupIntent::FullForget) {
            let record = agent.join("device.json");
            let evidence = ExactFileEvidence {
                lock_root: encode_path(&agent).unwrap(),
                path: encode_path(&record).unwrap(),
                sha256: sha256(&record_bytes),
                mode: 0o600,
                owner_uid: expected_uid(),
                device: 1,
                inode: 1,
                kind: LifecycleFileKind::CanonicalRecord,
            };
            deletion_targets.insert(
                encode_path(&record).unwrap(),
                PlannedDeletion::pending(evidence),
            );
        }
        if intent == CleanupIntent::FullForget {
            let key = agent.join("device-key");
            let evidence = ExactFileEvidence {
                lock_root: encode_path(&agent).unwrap(),
                path: encode_path(&key).unwrap(),
                sha256: sha256(b"synthetic stable key"),
                mode: 0o600,
                owner_uid: expected_uid(),
                device: 2,
                inode: 2,
                kind: LifecycleFileKind::CanonicalStableKey,
            };
            deletion_targets.insert(
                encode_path(&key).unwrap(),
                PlannedDeletion::pending(evidence),
            );
        }
        let value = CleanupTombstone {
            schema: SCHEMA,
            intent,
            prior_activation: PriorActivation::ProvenOpen,
            authority,
            canonical_root: encode_path(&agent).unwrap(),
            lock_roots: BTreeSet::from([encode_path(&agent).unwrap()]),
            peer_roots: BTreeSet::from([encode_path(&agent).unwrap()]),
            readiness_roots: BTreeSet::from([encode_path(&agent).unwrap()]),
            observed_units: BTreeMap::from([(
                encode_path(&unit).unwrap(),
                ObservedUnit::from_bytes(
                    &unit,
                    b"synthetic old unit",
                    [UnitRole::LoadedEffective, UnitRole::HistoricalInstalled],
                )
                .unwrap(),
            )]),
            deletion_targets,
            durable_absences: if matches!(intent, CleanupIntent::Remove | CleanupIntent::FullForget)
            {
                let marker = agent.join(LifecycleFileKind::AdoptionMarker.expected_basename());
                BTreeMap::from([(
                    encode_path(&marker).unwrap(),
                    DurableFileAbsence {
                        lock_root: encode_path(&agent).unwrap(),
                        path: encode_path(&marker).unwrap(),
                        kind: LifecycleFileKind::AdoptionMarker,
                    },
                )])
            } else {
                BTreeMap::new()
            },
            retained_evidence: BTreeMap::new(),
            legacy_retirement: None,
            desired_unit: DesiredUnit::from_bytes(&unit, b"synthetic desired unit").unwrap(),
            manager: Some(
                ManagerEvidence::new(
                    &agent,
                    &effective_root.join("daemon.sock"),
                    "git=36d69db built=1786200000".into(),
                    "a19a9392b66ddab6be6139d56f915e6b832c7b9a79dd437bbeb2936b10c56984".into(),
                )
                .unwrap(),
            ),
            provider_handoff: None,
            provider_terminal: None,
        };
        value.validate().unwrap();
        value
    }

    fn no_active_sample(
        root: &Path,
        intent: CleanupIntent,
        locks: &crate::service::LifecycleLockSet,
    ) -> CleanupTombstone {
        assert!(matches!(
            intent,
            CleanupIntent::Remove | CleanupIntent::FullForget
        ));
        let agent = root.join("hydra-agent");
        let unit = unit_path(root);
        let roots = BTreeSet::from([agent.clone()]);
        CleanupTombstone::new(
            intent,
            PriorActivation::ProvenClosed,
            AuthorityEvidence::NoActiveRecord,
            &agent,
            &roots,
            &roots,
            [],
            [],
            DesiredUnit::from_bytes(&unit, b"synthetic desired unit").unwrap(),
            None,
            locks,
        )
        .unwrap()
    }

    #[test]
    fn existing_0755_agent_root_gets_private_recovery_directory() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&agent, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let locks = lifecycle_lock_set(&agent);
        let value = sample(temp.path(), CleanupIntent::Close);
        assert_eq!(store(&agent, &value, &locks).unwrap(), value);
        assert_eq!(load(&agent).unwrap(), Some(value.clone()));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            assert_eq!(
                fs::symlink_metadata(recovery_dir(&agent))
                    .unwrap()
                    .permissions()
                    .mode()
                    & 0o777,
                0o700
            );
        }
        clear(&agent, &value, &locks).unwrap();
        clear(&agent, &value, &locks).unwrap();
    }

    #[test]
    fn exact_file_removal_revalidates_digest_fsyncs_parent_and_proves_absence() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let record = agent.join("device.json");
        fs::write(&record, b"synthetic enrollment").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let locks = lifecycle_lock_set(&agent);
        let evidence =
            ExactFileEvidence::capture(&agent, &record, LifecycleFileKind::CanonicalRecord, &locks)
                .unwrap()
                .unwrap();

        assert_eq!(
            remove_exact_file_durably(&evidence, &locks).unwrap(),
            DurableRemovalOutcome::Removed
        );
        assert!(!record.exists());
        assert!(matches!(
            fs::symlink_metadata(&record),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[test]
    fn exact_file_removal_already_absent_still_proves_absence() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let record = agent.join("device.json");
        fs::write(&record, b"synthetic enrollment").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let locks = lifecycle_lock_set(&agent);
        let evidence =
            ExactFileEvidence::capture(&agent, &record, LifecycleFileKind::CanonicalRecord, &locks)
                .unwrap()
                .unwrap();
        fs::remove_file(&record).unwrap();

        let mut parent_synced = false;
        assert_eq!(
            remove_exact_file_durably_with(
                &evidence,
                &locks,
                |_| bail!("remove callback must not run for an absent target"),
                |parent| {
                    parent_synced = true;
                    sync_directory(parent)
                },
                prove_path_absent,
            )
            .unwrap(),
            DurableRemovalOutcome::AlreadyAbsent
        );
        assert!(parent_synced);
        assert!(matches!(
            fs::symlink_metadata(&record),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound
        ));
    }

    #[cfg(unix)]
    #[test]
    fn exact_file_removal_rejects_wrong_lock() {
        let (temp, _agent, _record, locks, evidence) = exact_record_fixture();
        let other_agent = temp.path().join("other/hydra-agent");
        create_safe_directory(&other_agent);
        let wrong_locks = lifecycle_lock_set(&other_agent);
        assert!(remove_exact_file_durably(&evidence, &wrong_locks).is_err());
        drop(locks);
    }

    #[cfg(unix)]
    #[test]
    fn exact_file_removal_rejects_owner_mismatch() {
        let (_temp, _agent, _record, locks, evidence) = exact_record_fixture();
        let mut wrong_owner = evidence.clone();
        wrong_owner.owner_uid = wrong_owner.owner_uid.wrapping_add(1);
        assert!(remove_exact_file_durably(&wrong_owner, &locks).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn exact_file_removal_rejects_digest_change() {
        let (_temp, _agent, record, locks, evidence) = exact_record_fixture();
        fs::write(&record, b"changed enrollment").unwrap();
        assert!(remove_exact_file_durably(&evidence, &locks).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn exact_file_removal_rejects_inode_replacement() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_temp, agent, record, locks, evidence) = exact_record_fixture();
        let replacement = agent.join("replacement");
        fs::write(&replacement, b"synthetic enrollment").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o600)).unwrap();
        fs::rename(&replacement, &record).unwrap();
        assert!(remove_exact_file_durably(&evidence, &locks).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn superseding_service_unit_is_retained_while_exact_old_inode_retires() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let agent = fs::canonicalize(&agent).unwrap();
        let unit = unit_path(temp.path());
        create_safe_directory(unit.parent().unwrap());
        fs::write(&unit, b"captured service unit").unwrap();
        fs::set_permissions(&unit, fs::Permissions::from_mode(0o644)).unwrap();
        let locks = lifecycle_lock_set(&agent);
        let evidence =
            ExactFileEvidence::capture(&agent, &unit, LifecycleFileKind::ServiceDefinition, &locks)
                .unwrap()
                .unwrap();
        let roots = BTreeSet::from([agent.clone()]);
        let pending = CleanupTombstone::new(
            CleanupIntent::Remove,
            PriorActivation::ProvenClosed,
            AuthorityEvidence::NoActiveRecord,
            &agent,
            &roots,
            &roots,
            [ObservedUnit::from_bytes(
                &unit,
                b"captured service unit",
                [UnitRole::HistoricalInstalled],
            )
            .unwrap()],
            [evidence],
            DesiredUnit::from_bytes(&unit, b"captured service unit").unwrap(),
            None,
            &locks,
        )
        .unwrap();
        let durable = store(&agent, &pending, &locks).unwrap();

        let replacement = unit.with_extension("replacement");
        fs::write(&replacement, b"new package service unit").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o644)).unwrap();
        fs::rename(&replacement, &unit).unwrap();
        sync_directory(unit.parent().unwrap()).unwrap();

        let completed = execute_planned_deletion(&agent, &durable, &unit, &locks).unwrap();
        assert!(completed.all_deletions_proven());
        completed.prove_service_definitions_retired(&locks).unwrap();
        assert_eq!(fs::read(&unit).unwrap(), b"new package service unit");
        clear(&agent, &completed, &locks).unwrap();
        assert!(load(&agent).unwrap().is_none());
        assert_eq!(fs::read(&unit).unwrap(), b"new package service unit");
    }

    #[cfg(unix)]
    #[test]
    fn superseding_service_unit_with_unsafe_mode_stays_fail_closed() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let unit = unit_path(temp.path());
        create_safe_directory(unit.parent().unwrap());
        fs::write(&unit, b"captured service unit").unwrap();
        fs::set_permissions(&unit, fs::Permissions::from_mode(0o644)).unwrap();
        let locks = lifecycle_lock_set(&agent);
        let evidence =
            ExactFileEvidence::capture(&agent, &unit, LifecycleFileKind::ServiceDefinition, &locks)
                .unwrap()
                .unwrap();
        let replacement = unit.with_extension("replacement");
        fs::write(&replacement, b"unsafe replacement service unit").unwrap();
        fs::set_permissions(&replacement, fs::Permissions::from_mode(0o666)).unwrap();
        fs::rename(&replacement, &unit).unwrap();

        let error = remove_exact_file_durably(&evidence, &locks).unwrap_err();
        assert!(format!("{error:#}").contains("unsafe mode"));
        assert_eq!(fs::read(&unit).unwrap(), b"unsafe replacement service unit");
    }

    #[cfg(unix)]
    #[test]
    fn in_place_service_unit_change_stays_fail_closed() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let unit = unit_path(temp.path());
        create_safe_directory(unit.parent().unwrap());
        fs::write(&unit, b"captured service unit").unwrap();
        fs::set_permissions(&unit, fs::Permissions::from_mode(0o644)).unwrap();
        let locks = lifecycle_lock_set(&agent);
        let evidence =
            ExactFileEvidence::capture(&agent, &unit, LifecycleFileKind::ServiceDefinition, &locks)
                .unwrap()
                .unwrap();
        fs::write(&unit, b"changed in place service unit").unwrap();

        let error = remove_exact_file_durably(&evidence, &locks).unwrap_err();
        assert!(format!("{error:#}").contains("changed in place"));
        assert_eq!(fs::read(&unit).unwrap(), b"changed in place service unit");
    }

    #[cfg(unix)]
    #[test]
    fn exact_file_removal_rejects_mode_change() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_temp, _agent, record, locks, evidence) = exact_record_fixture();
        fs::set_permissions(&record, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(remove_exact_file_durably(&evidence, &locks).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn exact_file_capture_rejects_symlink() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let (_temp, agent, record, locks, _evidence) = exact_record_fixture();
        fs::remove_file(&record).unwrap();
        let target = agent.join("target");
        fs::write(&target, b"synthetic enrollment").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        symlink(&target, &record).unwrap();
        assert!(ExactFileEvidence::capture(
            &agent,
            &record,
            LifecycleFileKind::CanonicalRecord,
            &locks,
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn exact_file_capture_rejects_hardlink() {
        use std::os::unix::fs::PermissionsExt as _;
        let (_temp, agent, record, locks, _evidence) = exact_record_fixture();
        fs::remove_file(&record).unwrap();
        let target = agent.join("target");
        fs::write(&target, b"synthetic enrollment").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&target, &record).unwrap();
        assert!(ExactFileEvidence::capture(
            &agent,
            &record,
            LifecycleFileKind::CanonicalRecord,
            &locks,
        )
        .is_err());
    }

    #[test]
    fn exact_file_removal_sync_failure_keeps_recovery_retryable() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let record = agent.join("device.json");
        fs::write(&record, b"synthetic enrollment").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let locks = lifecycle_lock_set(&agent);
        let evidence =
            ExactFileEvidence::capture(&agent, &record, LifecycleFileKind::CanonicalRecord, &locks)
                .unwrap()
                .unwrap();

        let error = remove_exact_file_durably_with(
            &evidence,
            &locks,
            |target| fs::remove_file(target).context("injected removal"),
            |_| bail!("injected parent sync failure"),
            prove_path_absent,
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("injected parent sync failure"));
        assert_eq!(
            remove_exact_file_durably(&evidence, &locks).unwrap(),
            DurableRemovalOutcome::AlreadyAbsent
        );
    }

    #[test]
    fn exact_file_removal_readback_reappearance_is_rejected() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let record = agent.join("device.json");
        fs::write(&record, b"synthetic enrollment").unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let locks = lifecycle_lock_set(&agent);
        let evidence =
            ExactFileEvidence::capture(&agent, &record, LifecycleFileKind::CanonicalRecord, &locks)
                .unwrap()
                .unwrap();

        let error = remove_exact_file_durably_with(
            &evidence,
            &locks,
            |target| fs::remove_file(target).context("injected removal"),
            sync_directory,
            |target| {
                fs::write(target, b"reappeared").context("inject reappeared file")?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt as _;
                    fs::set_permissions(target, fs::Permissions::from_mode(0o600))
                        .context("set reappeared file mode")?;
                }
                prove_path_absent(target)
            },
        )
        .unwrap_err();
        assert!(format!("{error:#}").contains("still exists"));
        assert!(record.exists());
    }

    #[test]
    fn journal_persists_exact_deletion_and_marks_only_after_absence_proof() {
        let (temp, agent, record, locks, evidence) = exact_record_fixture();
        let mut pending = sample(temp.path(), CleanupIntent::Remove);
        pending.deletion_targets.insert(
            encode_path(&evidence.path()).unwrap(),
            PlannedDeletion::pending(evidence.clone()),
        );
        pending.validate().unwrap();
        let durable = store(&agent, &pending, &locks).unwrap();
        let encoded = serde_json::to_vec(&durable).unwrap();
        assert!(encoded
            .windows(evidence.sha256().len())
            .any(|window| window == evidence.sha256().as_bytes()));
        assert!(!durable.all_deletions_proven());

        let completed = execute_planned_deletion(&agent, &durable, &record, &locks).unwrap();

        assert!(completed.all_deletions_proven());
        assert!(!record.exists());
        assert_eq!(load(&agent).unwrap(), Some(completed.clone()));
        let target = completed.revocation_target().unwrap().clone();
        let handed_off = handoff_revocation(&agent, &target, &locks).unwrap();
        clear(&agent, &handed_off, &locks).unwrap();
        assert!(load(&agent).unwrap().is_none());
    }

    #[test]
    fn clear_rejects_pending_deletion_and_stale_finisher() {
        let (temp, agent, _record, locks, evidence) = exact_record_fixture();
        let mut close = sample(temp.path(), CleanupIntent::Close);
        let unit = close.observed_units().next().unwrap().clone();
        let service_evidence = ExactFileEvidence {
            lock_root: encode_path(&agent).unwrap(),
            path: encode_path(&unit.path()).unwrap(),
            sha256: unit.sha256().to_string(),
            mode: 0o600,
            owner_uid: expected_uid(),
            device: evidence.device,
            inode: evidence.inode,
            kind: LifecycleFileKind::ServiceDefinition,
        };
        // A syntactically valid pending proof is sufficient here: clear must
        // inspect journal state before it performs any filesystem operation.
        close.deletion_targets.insert(
            encode_path(&service_evidence.path()).unwrap(),
            PlannedDeletion::pending(service_evidence),
        );
        close.validate().unwrap();
        store(&agent, &close, &locks).unwrap();
        assert!(clear(&agent, &close, &locks).is_err());

        // Complete a separate no-delete Close and supersede it; the old
        // expected value must never erase the newer journal.
        let _ = fs::remove_file(path(&agent));
        sync_directory(&recovery_dir(&agent)).unwrap();
        let no_delete = sample(temp.path(), CleanupIntent::Close);
        store(&agent, &no_delete, &locks).unwrap();
        let remove = sample(temp.path(), CleanupIntent::Remove);
        let superseding = supersede(&agent, &remove, &locks).unwrap();
        assert!(clear(&agent, &no_delete, &locks).is_err());
        assert_eq!(load(&agent).unwrap(), Some(superseding));
    }

    #[cfg(unix)]
    #[test]
    fn ordinary_remove_rejects_canonical_key_but_accepts_legacy_adopted_key() {
        use std::os::unix::fs::PermissionsExt as _;
        let (temp, agent, _record, canonical_locks, record_evidence) = exact_record_fixture();
        let canonical_key = agent.join("device-key");
        fs::write(&canonical_key, b"canonical seed").unwrap();
        fs::set_permissions(&canonical_key, fs::Permissions::from_mode(0o600)).unwrap();
        let canonical_evidence = ExactFileEvidence::capture(
            &agent,
            &canonical_key,
            LifecycleFileKind::CanonicalStableKey,
            &canonical_locks,
        )
        .unwrap()
        .unwrap();
        let mut remove = sample(temp.path(), CleanupIntent::Remove);
        remove.deletion_targets.insert(
            encode_path(&canonical_evidence.path()).unwrap(),
            PlannedDeletion::pending(canonical_evidence),
        );
        assert!(remove.validate().is_err());

        drop(canonical_locks);
        let legacy = temp.path().join("legacy/hydra-agent");
        create_safe_directory(&legacy);
        let legacy = fs::canonicalize(&legacy).unwrap();
        let legacy_record_bytes = b"synthetic legacy enrollment";
        let legacy_record = legacy.join("device.json");
        fs::write(&legacy_record, legacy_record_bytes).unwrap();
        fs::set_permissions(&legacy_record, fs::Permissions::from_mode(0o600)).unwrap();
        let legacy_key_bytes = b"synthetic legacy seed";
        let legacy_key = legacy.join("device-key");
        fs::write(&legacy_key, legacy_key_bytes).unwrap();
        fs::set_permissions(&legacy_key, fs::Permissions::from_mode(0o600)).unwrap();
        let marker = agent.join(LifecycleFileKind::AdoptionMarker.expected_basename());
        fs::write(
            &marker,
            serde_json::to_vec_pretty(&serde_json::json!({
                "schema": 1,
                "source_agent_dir": legacy.to_str().unwrap(),
                "account_id": "acct_synthetic",
                "device_id": "dev_synthetic",
                "key_sha256": sha256(legacy_key_bytes),
                "record_sha256": sha256(legacy_record_bytes),
                "owner_sha256": sha256(b"synthetic owner marker"),
            }))
            .unwrap(),
        )
        .unwrap();
        fs::set_permissions(&marker, fs::Permissions::from_mode(0o600)).unwrap();
        let locks =
            crate::service::LifecycleLockSet::acquire([agent.clone(), legacy.clone()]).unwrap();
        let legacy_record_evidence = ExactFileEvidence::capture(
            &legacy,
            &legacy_record,
            LifecycleFileKind::LegacyRecord,
            &locks,
        )
        .unwrap()
        .unwrap();
        let legacy_key_evidence = ExactFileEvidence::capture(
            &legacy,
            &legacy_key,
            LifecycleFileKind::LegacyAdoptedKey,
            &locks,
        )
        .unwrap()
        .unwrap();
        let marker_evidence =
            ExactFileEvidence::capture(&agent, &marker, LifecycleFileKind::AdoptionMarker, &locks)
                .unwrap()
                .unwrap();
        let roots = BTreeSet::from([agent.clone(), legacy]);
        let remove = CleanupTombstone::new(
            CleanupIntent::Remove,
            PriorActivation::ProvenClosed,
            AuthorityEvidence::target_from_record_bytes(&synthetic_record_bytes()).unwrap(),
            &agent,
            &roots,
            &roots,
            [],
            [
                record_evidence,
                legacy_record_evidence,
                legacy_key_evidence,
                marker_evidence,
            ],
            DesiredUnit::from_bytes(&unit_path(temp.path()), b"synthetic desired unit").unwrap(),
            None,
            &locks,
        )
        .unwrap();
        remove.validate().unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn legacy_retirement_accepts_missing_record_with_present_key() {
        let fixture = legacy_retirement_fixture(false, true);
        fixture.tombstone.validate().unwrap();
        assert!(fixture.tombstone.durable_absences().any(|absence| {
            absence.kind() == LifecycleFileKind::LegacyRecord
                && absence.path() == fixture.legacy_record
        }));
        assert!(fixture.tombstone.deletion_targets().any(|target| {
            target.evidence().kind() == LifecycleFileKind::LegacyAdoptedKey
                && target.evidence().path() == fixture.legacy_key
        }));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_retirement_accepts_present_record_with_missing_key() {
        let fixture = legacy_retirement_fixture(true, false);
        fixture.tombstone.validate().unwrap();
        assert!(fixture.tombstone.deletion_targets().any(|target| {
            target.evidence().kind() == LifecycleFileKind::LegacyRecord
                && target.evidence().path() == fixture.legacy_record
        }));
        assert!(fixture.tombstone.durable_absences().any(|absence| {
            absence.kind() == LifecycleFileKind::LegacyAdoptedKey
                && absence.path() == fixture.legacy_key
        }));
    }

    #[cfg(unix)]
    #[test]
    fn legacy_retirement_accepts_both_legacy_authority_files_absent() {
        let fixture = legacy_retirement_fixture(false, false);
        fixture.tombstone.validate().unwrap();
        for kind in [
            LifecycleFileKind::LegacyRecord,
            LifecycleFileKind::LegacyAdoptedKey,
        ] {
            assert!(fixture
                .tombstone
                .durable_absences()
                .any(|absence| absence.kind() == kind));
        }
    }

    #[cfg(unix)]
    #[test]
    fn adoption_marker_is_structurally_deleted_after_legacy_record_and_key() {
        let fixture = legacy_retirement_fixture(true, true);
        let durable = store(&fixture.agent, &fixture.tombstone, &fixture.locks).unwrap();
        assert!(execute_planned_deletion(
            &fixture.agent,
            &durable,
            &fixture.marker,
            &fixture.locks,
        )
        .is_err());
        let record_done = execute_planned_deletion(
            &fixture.agent,
            &durable,
            &fixture.legacy_record,
            &fixture.locks,
        )
        .unwrap();
        assert!(execute_planned_deletion(
            &fixture.agent,
            &record_done,
            &fixture.marker,
            &fixture.locks,
        )
        .is_err());
        let key_done = execute_planned_deletion(
            &fixture.agent,
            &record_done,
            &fixture.legacy_key,
            &fixture.locks,
        )
        .unwrap();
        let marker_done =
            execute_planned_deletion(&fixture.agent, &key_done, &fixture.marker, &fixture.locks)
                .unwrap();
        assert!(!fixture.marker.exists());
        assert!(marker_done.deletion_targets().any(|target| {
            target.evidence().kind() == LifecycleFileKind::AdoptionMarker
                && target.is_proven_absent()
        }));
    }

    #[cfg(unix)]
    #[test]
    fn full_forget_canonical_key_is_structurally_last() {
        use std::os::unix::fs::PermissionsExt as _;
        let (temp, agent, record, locks, record_evidence) = exact_record_fixture();
        let key = agent.join("device-key");
        fs::write(&key, b"stable seed").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let key_evidence =
            ExactFileEvidence::capture(&agent, &key, LifecycleFileKind::CanonicalStableKey, &locks)
                .unwrap()
                .unwrap();
        let mut pending = sample(temp.path(), CleanupIntent::FullForget);
        pending.deletion_targets.insert(
            encode_path(&record_evidence.path()).unwrap(),
            PlannedDeletion::pending(record_evidence),
        );
        pending.deletion_targets.insert(
            encode_path(&key_evidence.path()).unwrap(),
            PlannedDeletion::pending(key_evidence),
        );
        pending.validate().unwrap();
        let pending = store(&agent, &pending, &locks).unwrap();
        assert!(execute_planned_deletion(&agent, &pending, &key, &locks).is_err());
        let target = pending.revocation_target().unwrap().clone();
        let handed_off = handoff_revocation(&agent, &target, &locks).unwrap();
        let terminal = record_full_forget_provider_terminal(
            &agent,
            &target,
            ProviderTerminalOutcome::Revoked,
            &locks,
        )
        .unwrap();
        assert!(!full_forget_key_deletion_ready(&agent, &locks).unwrap());
        let lock = locks.lock_for(&agent).unwrap();
        complete_revocation(&agent, target.device_id(), lock).unwrap();
        let terminal_handoff = handoff_revocation(&agent, &target, &locks).unwrap();
        assert_eq!(terminal_handoff.provider_terminal_target(), Some(&target));
        assert!(load_revocation_outbox(&agent)
            .unwrap()
            .targets()
            .next()
            .is_none());
        assert_eq!(handed_off.provider_handoff_target(), Some(&target));
        let record_done = execute_planned_deletion(&agent, &terminal, &record, &locks).unwrap();
        assert!(full_forget_key_deletion_ready(&agent, &locks).unwrap());
        let key_done = execute_planned_deletion(&agent, &record_done, &key, &locks).unwrap();
        assert!(key_done.all_deletions_proven());
        assert!(!key.exists());
    }

    #[cfg(unix)]
    #[test]
    fn supersession_after_unlink_before_proof_retains_demoted_historical_target() {
        use std::os::unix::fs::PermissionsExt as _;
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let mut close = sample(temp.path(), CleanupIntent::Close);
        let unit_path = close.observed_units().next().unwrap().path();
        create_safe_directory(unit_path.parent().unwrap());
        fs::write(&unit_path, b"synthetic old unit").unwrap();
        fs::set_permissions(&unit_path, fs::Permissions::from_mode(0o600)).unwrap();
        let evidence = ExactFileEvidence::capture(
            &agent,
            &unit_path,
            LifecycleFileKind::ServiceDefinition,
            &locks,
        )
        .unwrap()
        .unwrap();
        close.deletion_targets.insert(
            encode_path(&unit_path).unwrap(),
            PlannedDeletion::pending(evidence.clone()),
        );
        close.validate().unwrap();
        store(&agent, &close, &locks).unwrap();
        assert_eq!(
            remove_exact_file_durably(&evidence, &locks).unwrap(),
            DurableRemovalOutcome::Removed
        );

        let mut requested = sample(temp.path(), CleanupIntent::Remove);
        requested.observed_units.clear();
        requested.manager = None;
        requested.validate().unwrap();
        let superseding = supersede(&agent, &requested, &locks).unwrap();
        let historical = superseding.observed_units().next().unwrap();
        assert_eq!(
            historical.roles(),
            &BTreeSet::from([UnitRole::HistoricalInstalled])
        );
        assert!(superseding.manager().is_none());
        let completed = execute_planned_deletion(&agent, &superseding, &unit_path, &locks).unwrap();
        assert!(completed
            .deletion_targets
            .get(&encode_path(&evidence.path()).unwrap())
            .unwrap()
            .is_proven_absent());
        assert!(!completed.all_deletions_proven());
    }

    #[test]
    fn supersession_converts_unlink_before_proof_into_durable_record_absence() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let record = agent.join("device.json");
        fs::write(&record, synthetic_record_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let locks = lifecycle_lock_set(&agent);
        let record_evidence =
            ExactFileEvidence::capture(&agent, &record, LifecycleFileKind::CanonicalRecord, &locks)
                .unwrap()
                .unwrap();
        let canonical_agent = fs::canonicalize(&agent).unwrap();
        let roots = BTreeSet::from([canonical_agent.clone()]);
        let unit = unit_path(canonical_agent.parent().unwrap());
        let pending = CleanupTombstone::new(
            CleanupIntent::Remove,
            PriorActivation::ProvenOpen,
            AuthorityEvidence::target_from_record_bytes(&synthetic_record_bytes()).unwrap(),
            &canonical_agent,
            &roots,
            &roots,
            [],
            [record_evidence.clone()],
            DesiredUnit::from_bytes(&unit, b"synthetic desired unit").unwrap(),
            None,
            &locks,
        )
        .unwrap();
        let pending = store(&agent, &pending, &locks).unwrap();
        remove_exact_file_durably(&record_evidence, &locks).unwrap();

        let requested = no_active_sample(temp.path(), CleanupIntent::FullForget, &locks);
        let old_target = pending.revocation_target().unwrap().clone();
        let durable = supersede(&agent, &requested, &locks).unwrap();

        assert_eq!(durable.intent(), CleanupIntent::FullForget);
        assert_eq!(durable.authority(), &AuthorityEvidence::NoActiveRecord);
        assert!(durable
            .deletion_targets()
            .all(|planned| { planned.evidence().kind() != LifecycleFileKind::CanonicalRecord }));
        assert!(durable
            .durable_absences()
            .any(|absence| absence.kind() == LifecycleFileKind::CanonicalRecord));
        assert!(load_revocation_outbox(&agent)
            .unwrap()
            .targets()
            .any(|target| target == &old_target));
    }

    #[test]
    fn newest_complete_retry_observation_can_remove_stale_manager_evidence() {
        let temp = secure_tempdir();
        let pending = sample(temp.path(), CleanupIntent::Close);
        let mut newer = pending.clone();
        newer.manager = None;
        assert!(pending.merged_retry(&newer).unwrap().manager().is_none());
    }

    #[test]
    fn newest_retry_snapshot_removes_stale_loaded_and_desired_roles() {
        let temp = secure_tempdir();
        let pending = sample(temp.path(), CleanupIntent::Close);
        let mut newer = pending.clone();
        let path = newer.observed_units().next().unwrap().path();
        newer.observed_units.insert(
            encode_path(&path).unwrap(),
            ObservedUnit::from_bytes(
                &path,
                b"synthetic old unit",
                [UnitRole::HistoricalInstalled],
            )
            .unwrap(),
        );

        let merged = pending.merged_retry(&newer).unwrap();
        let roles = merged.observed_units().next().unwrap().roles();
        assert_eq!(roles, &BTreeSet::from([UnitRole::HistoricalInstalled]));
        assert!(!roles.contains(&UnitRole::LoadedEffective));
        assert!(!roles.contains(&UnitRole::DesiredCurrent));
    }

    #[test]
    fn retry_replaces_runtime_evidence_without_pids() {
        let temp = secure_tempdir();
        let first = sample(temp.path(), CleanupIntent::Close);
        let mut second = sample(temp.path(), CleanupIntent::Close);
        second.manager = Some(
            ManagerEvidence::new(
                &temp.path().join("hydra-agent"),
                &temp.path().join("replacement.sock"),
                "git=new built=1786200001".into(),
                "b19a9392b66ddab6be6139d56f915e6b832c7b9a79dd437bbeb2936b10c56984".into(),
            )
            .unwrap(),
        );
        let merged = first.merged_retry(&second).unwrap();
        assert_eq!(
            merged.manager().unwrap().socket_path(),
            temp.path().join("replacement.sock")
        );
        let json = serde_json::to_string(&merged).unwrap();
        assert!(!json.contains("pid"));
    }

    #[test]
    fn authority_reduction_supersedes_but_positive_or_weaker_intent_does_not() {
        assert!(may_supersede(
            CleanupIntent::ConvergeOpen,
            CleanupIntent::Close
        ));
        assert!(may_supersede(CleanupIntent::Close, CleanupIntent::Remove));
        assert!(may_supersede(
            CleanupIntent::Remove,
            CleanupIntent::FullForget
        ));
        assert!(!may_supersede(
            CleanupIntent::Close,
            CleanupIntent::ConvergeOpen
        ));
        assert!(!may_supersede(CleanupIntent::Remove, CleanupIntent::Close));
    }

    #[cfg(unix)]
    #[test]
    fn pending_remove_promotes_to_full_forget_with_exact_key_and_no_downgrade() {
        use std::os::unix::fs::PermissionsExt as _;

        let (temp, agent, _record, locks, record_evidence) = exact_record_fixture();
        let key = agent.join("device-key");
        fs::write(&key, b"synthetic stable key").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        let diagnostics = agent.join(crate::device_identity::ENROLLMENT_DIAGNOSTICS_FILE);
        fs::write(&diagnostics, br#"{"version":1,"events":[]}"#).unwrap();
        fs::set_permissions(&diagnostics, fs::Permissions::from_mode(0o600)).unwrap();
        let diagnostics_temporary =
            agent.join(crate::device_identity::ENROLLMENT_DIAGNOSTICS_TEMP_FILE);
        fs::write(&diagnostics_temporary, b"crash-before-rename").unwrap();
        fs::set_permissions(&diagnostics_temporary, fs::Permissions::from_mode(0o600)).unwrap();
        let roots = BTreeSet::from([agent.clone()]);
        let remove = CleanupTombstone::new(
            CleanupIntent::Remove,
            PriorActivation::ProvenClosed,
            AuthorityEvidence::target_from_exact_record(&record_evidence, &locks).unwrap(),
            &agent,
            &roots,
            &roots,
            [],
            [record_evidence],
            DesiredUnit::from_bytes(
                &unit_path(temp.path()),
                b"synthetic desired service definition",
            )
            .unwrap(),
            None,
            &locks,
        )
        .unwrap();
        assert!(remove.deletion_targets().all(|target| {
            !matches!(
                target.evidence().kind(),
                LifecycleFileKind::EnrollmentDiagnostics
                    | LifecycleFileKind::EnrollmentDiagnosticsTemporary
            )
        }));
        assert!(diagnostics.exists(), "ordinary Remove retains diagnostics");
        assert!(
            diagnostics_temporary.exists(),
            "ordinary Remove retains diagnostic crash evidence"
        );
        store(&agent, &remove, &locks).unwrap();

        let promoted = supersede_remove_with_full_forget(&agent, &locks).unwrap();
        assert_eq!(promoted.intent(), CleanupIntent::FullForget);
        assert!(promoted.deletion_targets().any(|target| {
            target.evidence().kind() == LifecycleFileKind::CanonicalStableKey
                && target.evidence().path() == key
        }));
        assert!(promoted.deletion_targets().any(|target| {
            target.evidence().kind() == LifecycleFileKind::EnrollmentDiagnostics
                && target.evidence().path() == diagnostics
        }));
        assert!(promoted.deletion_targets().any(|target| {
            target.evidence().kind() == LifecycleFileKind::EnrollmentDiagnosticsTemporary
                && target.evidence().path() == diagnostics_temporary
        }));
        assert!(load_revocation_outbox(&agent)
            .unwrap()
            .targets()
            .any(|target| Some(target) == promoted.revocation_target()));
        assert!(supersede_remove_with_full_forget(&agent, &locks).is_err());
        assert_eq!(load(&agent).unwrap().unwrap(), promoted);

        fs::rename(&diagnostics, agent.join("diagnostics-old")).unwrap();
        fs::write(&diagnostics, b"replacement diagnostic").unwrap();
        fs::set_permissions(&diagnostics, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(execute_planned_deletion(&agent, &promoted, &diagnostics, &locks).is_err());
        assert!(diagnostics.exists());
        assert!(
            key.exists(),
            "diagnostic replacement must block the later key cut"
        );
    }

    #[cfg(unix)]
    #[test]
    fn full_forget_promotion_refuses_unsafe_or_oversized_diagnostics_unchanged() {
        use std::os::unix::fs::{symlink, MetadataExt as _, PermissionsExt as _};

        let (_temp, agent, locks) = stored_remove_fixture();
        let target = agent.join("diagnostic-symlink-target");
        fs::write(&target, b"symlink-sentinel").unwrap();
        fs::set_permissions(&target, fs::Permissions::from_mode(0o600)).unwrap();
        let temporary = agent.join(crate::device_identity::ENROLLMENT_DIAGNOSTICS_TEMP_FILE);
        symlink(&target, &temporary).unwrap();
        let before = fs::symlink_metadata(&temporary).unwrap();
        assert!(supersede_remove_with_full_forget(&agent, &locks).is_err());
        let after = fs::symlink_metadata(&temporary).unwrap();
        assert!(after.file_type().is_symlink());
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(fs::read(&target).unwrap(), b"symlink-sentinel");

        let (_temp, agent, locks) = stored_remove_fixture();
        let temporary = agent.join(crate::device_identity::ENROLLMENT_DIAGNOSTICS_TEMP_FILE);
        fs::write(&temporary, b"hardlink-sentinel").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        let second = agent.join("diagnostic-temp-second-link");
        fs::hard_link(&temporary, &second).unwrap();
        let before = fs::metadata(&temporary).unwrap();
        assert_eq!(before.nlink(), 2);
        assert!(supersede_remove_with_full_forget(&agent, &locks).is_err());
        let after = fs::metadata(&temporary).unwrap();
        assert_eq!(
            (after.dev(), after.ino(), after.nlink()),
            (before.dev(), before.ino(), 2)
        );
        assert_eq!(fs::read(&temporary).unwrap(), b"hardlink-sentinel");

        let (_temp, agent, locks) = stored_remove_fixture();
        let temporary = agent.join(crate::device_identity::ENROLLMENT_DIAGNOSTICS_TEMP_FILE);
        fs::write(&temporary, b"mode-sentinel").unwrap();
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o400)).unwrap();
        let before = fs::metadata(&temporary).unwrap();
        assert!(supersede_remove_with_full_forget(&agent, &locks).is_err());
        let after = fs::metadata(&temporary).unwrap();
        assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
        assert_eq!(after.permissions().mode() & 0o7777, 0o400);
        fs::set_permissions(&temporary, fs::Permissions::from_mode(0o600)).unwrap();
        assert_eq!(fs::read(&temporary).unwrap(), b"mode-sentinel");

        for (label, basename) in [
            (
                "canonical",
                crate::device_identity::ENROLLMENT_DIAGNOSTICS_FILE,
            ),
            (
                "temporary",
                crate::device_identity::ENROLLMENT_DIAGNOSTICS_TEMP_FILE,
            ),
        ] {
            let (_temp, agent, locks) = stored_remove_fixture();
            let path = agent.join(basename);
            let bytes = vec![b'x'; crate::device_identity::MAX_ENROLLMENT_DIAGNOSTICS_BYTES + 1];
            fs::write(&path, &bytes).unwrap();
            fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
            let before = fs::metadata(&path).unwrap();
            assert!(
                supersede_remove_with_full_forget(&agent, &locks).is_err(),
                "oversized {label} diagnostics must refuse FullForget"
            );
            let after = fs::metadata(&path).unwrap();
            assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
            assert_eq!(fs::read(&path).unwrap(), bytes);
        }
    }

    #[test]
    fn supersession_durably_queues_old_target_before_replacing_journal() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let historical_root = temp.path().join("historical/hydra-agent");
        create_safe_directory(&historical_root);
        let locks =
            crate::service::LifecycleLockSet::acquire([agent.clone(), historical_root.clone()])
                .unwrap();
        let historical_root = fs::canonicalize(&historical_root).unwrap();
        let mut pending = sample(temp.path(), CleanupIntent::Remove);
        pending
            .peer_roots
            .insert(encode_path(&historical_root).unwrap());
        pending
            .readiness_roots
            .insert(encode_path(&historical_root).unwrap());
        pending
            .lock_roots
            .insert(encode_path(&historical_root).unwrap());
        pending.validate().unwrap();
        let old_target = pending.revocation_target().unwrap().clone();
        store(&agent, &pending, &locks).unwrap();

        let mut requested = sample(temp.path(), CleanupIntent::FullForget);
        requested
            .peer_roots
            .insert(encode_path(&historical_root).unwrap());
        requested
            .readiness_roots
            .insert(encode_path(&historical_root).unwrap());
        requested
            .lock_roots
            .insert(encode_path(&historical_root).unwrap());
        requested.validate().unwrap();
        let durable = supersede(&agent, &requested, &locks).unwrap();

        assert_eq!(durable.intent(), CleanupIntent::FullForget);
        assert!(durable.peer_roots().unwrap().contains(&historical_root));
        assert!(durable
            .readiness_roots()
            .unwrap()
            .contains(&historical_root));
        assert_eq!(load(&agent).unwrap(), Some(durable));
        assert!(load_revocation_outbox(&agent)
            .unwrap()
            .targets()
            .any(|target| target == &old_target));
    }

    #[test]
    fn failed_or_weaker_supersession_leaves_the_pending_journal_intact() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let pending = sample(temp.path(), CleanupIntent::Remove);
        store(&agent, &pending, &locks).unwrap();

        let weaker = sample(temp.path(), CleanupIntent::Close);
        assert!(supersede(&agent, &weaker, &locks).is_err());
        assert_eq!(load(&agent).unwrap(), Some(pending));
    }

    #[test]
    fn outbox_retains_old_and_new_provider_targets_before_supersession() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let lock = locks.lock_for(&agent).unwrap();
        let first = RevocationTarget::new(
            crate::release_trust::CLOUD_BASE.to_string(),
            "acct_synthetic".into(),
            "dev_old".into(),
        )
        .unwrap();
        let second = RevocationTarget::new(
            crate::release_trust::CLOUD_BASE.to_string(),
            "acct_synthetic".into(),
            "dev_new".into(),
        )
        .unwrap();
        enqueue_revocation(&agent, &first, lock).unwrap();
        enqueue_revocation(&agent, &second, lock).unwrap();
        let outbox = load_revocation_outbox(&agent).unwrap();
        let ids = outbox
            .targets()
            .map(RevocationTarget::device_id)
            .collect::<BTreeSet<_>>();
        assert_eq!(ids, BTreeSet::from(["dev_old", "dev_new"]));
    }

    #[test]
    fn same_device_with_different_account_never_merges() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let lock = locks.lock_for(&agent).unwrap();
        let original = RevocationTarget::new(
            crate::release_trust::CLOUD_BASE.to_string(),
            "acct_synthetic".into(),
            "dev_synthetic".into(),
        )
        .unwrap();
        let conflicting = RevocationTarget::new(
            crate::release_trust::CLOUD_BASE.to_string(),
            "acct_other".into(),
            "dev_synthetic".into(),
        )
        .unwrap();
        enqueue_revocation(&agent, &original, lock).unwrap();
        assert!(enqueue_revocation(&agent, &conflicting, lock).is_err());
    }

    #[test]
    fn changed_unit_bytes_do_not_merge() {
        let temp = secure_tempdir();
        let close = sample(temp.path(), CleanupIntent::Close);
        let mut changed = close.clone();
        let path = changed.desired_unit().path();
        changed.observed_units.insert(
            encode_path(&path).unwrap(),
            ObservedUnit::from_bytes(&path, b"different bytes", [UnitRole::LoadedEffective])
                .unwrap(),
        );
        assert!(close.merged_retry(&changed).is_err());
    }

    #[test]
    fn retry_accepts_precommitted_desired_bytes_at_the_same_unit_path() {
        let temp = secure_tempdir();
        let pending = sample(temp.path(), CleanupIntent::Close);
        let mut observed_desired = pending.clone();
        let path = observed_desired.desired_unit().path();
        observed_desired.observed_units.insert(
            encode_path(&path).unwrap(),
            ObservedUnit::from_bytes(
                &path,
                b"synthetic desired unit",
                [UnitRole::DesiredCurrent, UnitRole::LoadedEffective],
            )
            .unwrap(),
        );

        let merged = pending.merged_retry(&observed_desired).unwrap();
        let unit = merged.observed_units().next().unwrap();
        assert_eq!(unit.path(), path);
        assert_eq!(unit.sha256(), merged.desired_unit().sha256());
        assert!(unit.roles().contains(&UnitRole::DesiredCurrent));
    }

    #[test]
    fn precommitted_desired_bytes_survive_a_binary_update_and_digest_is_checked() {
        let temp = secure_tempdir();
        create_safe_directory(&temp.path().join("hydra-agent"));
        let locks = lifecycle_lock_set(&temp.path().join("hydra-agent"));
        let pending = sample(temp.path(), CleanupIntent::ConvergeOpen);
        let encoded = serde_json::to_vec(&pending).unwrap();
        let restored: CleanupTombstone = serde_json::from_slice(&encoded).unwrap();
        restored.validate().unwrap();
        assert_eq!(
            restored.desired_unit().bytes().unwrap(),
            b"synthetic desired unit"
        );

        let newer_binary_plan = CleanupTombstone::new(
            CleanupIntent::ConvergeOpen,
            PriorActivation::ProvenOpen,
            AuthorityEvidence::NotRequested,
            &restored.canonical_root(),
            &restored.peer_roots().unwrap(),
            &restored.readiness_roots().unwrap(),
            restored.observed_units().cloned(),
            restored
                .deletion_targets()
                .map(|planned| planned.evidence().clone()),
            DesiredUnit::from_bytes(&restored.desired_unit().path(), b"new release unit").unwrap(),
            restored.manager().cloned(),
            &locks,
        )
        .unwrap();
        assert!(restored.merged_retry(&newer_binary_plan).is_err());

        let mut tampered: serde_json::Value = serde_json::from_slice(&encoded).unwrap();
        tampered["desired_unit"]["bytes_b64"] = serde_json::Value::String(
            base64::engine::general_purpose::STANDARD.encode(b"tampered"),
        );
        let tampered: CleanupTombstone = serde_json::from_value(tampered).unwrap();
        assert!(tampered.validate().is_err());
    }

    #[test]
    fn retry_rejects_arbitrary_bytes_and_new_unit_paths() {
        let temp = secure_tempdir();
        let pending = sample(temp.path(), CleanupIntent::Close);

        let mut arbitrary = pending.clone();
        let desired_path = arbitrary.desired_unit().path();
        arbitrary.observed_units.insert(
            encode_path(&desired_path).unwrap(),
            ObservedUnit::from_bytes(
                &desired_path,
                b"unplanned replacement",
                [UnitRole::LoadedEffective],
            )
            .unwrap(),
        );
        assert!(pending.merged_retry(&arbitrary).is_err());

        let mut desired_without_role = pending.clone();
        desired_without_role.observed_units.insert(
            encode_path(&desired_path).unwrap(),
            ObservedUnit::from_bytes(
                &desired_path,
                b"synthetic desired unit",
                [UnitRole::LoadedEffective],
            )
            .unwrap(),
        );
        assert!(pending.merged_retry(&desired_without_role).is_err());

        let mut extra = pending.clone();
        let new_path = unit_path(&temp.path().join("other-root"));
        extra.observed_units.insert(
            encode_path(&new_path).unwrap(),
            ObservedUnit::from_bytes(
                &new_path,
                b"unplanned extra unit",
                [UnitRole::HistoricalInstalled],
            )
            .unwrap(),
        );
        assert!(pending.merged_retry(&extra).is_err());
    }

    #[test]
    fn desired_current_role_requires_the_precommitted_path_and_digest() {
        let temp = secure_tempdir();
        let desired_path = unit_path(temp.path());
        let desired = DesiredUnit::from_bytes(&desired_path, b"desired bytes").unwrap();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let roots = BTreeSet::from([agent.clone()]);

        let wrong_digest =
            ObservedUnit::from_bytes(&desired_path, b"other bytes", [UnitRole::DesiredCurrent])
                .unwrap();
        assert!(CleanupTombstone::new(
            CleanupIntent::Close,
            PriorActivation::ProvenOpen,
            AuthorityEvidence::NotRequested,
            &agent,
            &roots,
            &roots,
            [wrong_digest],
            [],
            desired.clone(),
            None,
            &locks,
        )
        .is_err());

        let wrong_path = unit_path(&temp.path().join("other-root"));
        let wrong_location =
            ObservedUnit::from_bytes(&wrong_path, b"desired bytes", [UnitRole::DesiredCurrent])
                .unwrap();
        assert!(CleanupTombstone::new(
            CleanupIntent::Close,
            PriorActivation::ProvenOpen,
            AuthorityEvidence::NotRequested,
            &agent,
            &roots,
            &roots,
            [wrong_location],
            [],
            desired,
            None,
            &locks,
        )
        .is_err());
    }

    #[test]
    fn descriptor_rejects_multiple_loaded_effective_units() {
        let temp = secure_tempdir();
        let first_path = unit_path(temp.path());
        let second_path = unit_path(&temp.path().join("historical"));
        let desired = DesiredUnit::from_bytes(&first_path, b"desired bytes").unwrap();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let roots = BTreeSet::from([agent.clone()]);
        let units = [
            ObservedUnit::from_bytes(
                &first_path,
                b"desired bytes",
                [UnitRole::DesiredCurrent, UnitRole::LoadedEffective],
            )
            .unwrap(),
            ObservedUnit::from_bytes(
                &second_path,
                b"historical bytes",
                [UnitRole::LoadedEffective, UnitRole::HistoricalInstalled],
            )
            .unwrap(),
        ];

        assert!(CleanupTombstone::new(
            CleanupIntent::Close,
            PriorActivation::Ambiguous,
            AuthorityEvidence::NotRequested,
            &agent,
            &roots,
            &roots,
            units,
            [],
            desired,
            None,
            &locks,
        )
        .is_err());
    }

    #[test]
    fn corrupt_record_can_remove_with_owner_proof_but_cannot_full_forget() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let record_bytes = b"{malformed";
        let owner_bytes = b"verified synthetic owner marker";
        fs::write(agent.join("device.json"), record_bytes).unwrap();
        fs::write(agent.join("device-owner.json"), owner_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(agent.join("device.json"), fs::Permissions::from_mode(0o600))
                .unwrap();
            fs::set_permissions(
                agent.join("device-owner.json"),
                fs::Permissions::from_mode(0o600),
            )
            .unwrap();
        }
        let locks = lifecycle_lock_set(&agent);
        let record = ExactFileEvidence::capture(
            &agent,
            &agent.join("device.json"),
            LifecycleFileKind::CanonicalRecord,
            &locks,
        )
        .unwrap()
        .unwrap();
        let owner = ExactFileEvidence::capture(
            &agent,
            &agent.join("device-owner.json"),
            LifecycleFileKind::CanonicalOwnerMarker,
            &locks,
        )
        .unwrap()
        .unwrap();
        let mut remove = sample(temp.path(), CleanupIntent::Remove);
        remove.authority =
            AuthorityEvidence::unavailable_corrupt(owner_bytes, record_bytes).unwrap();
        remove.deletion_targets = BTreeMap::from([(
            encode_path(&record.path()).unwrap(),
            PlannedDeletion::pending(record),
        )]);
        remove.retained_evidence = BTreeMap::from([(encode_path(&owner.path()).unwrap(), owner)]);
        assert!(remove.validate().is_ok());
        remove.intent = CleanupIntent::FullForget;
        assert!(remove.validate().is_err());
    }

    #[test]
    fn corrupt_owner_is_rebound_before_each_destructive_resume() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let record_bytes = b"{corrupt-owner-rebind";
        let owner_bytes = b"synthetic durable owner";
        fs::write(agent.join("device.json"), record_bytes).unwrap();
        fs::write(agent.join("device-owner.json"), owner_bytes).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            for path in [agent.join("device.json"), agent.join("device-owner.json")] {
                fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
            }
        }
        let locks = lifecycle_lock_set(&agent);
        let record = ExactFileEvidence::capture(
            &agent,
            &agent.join("device.json"),
            LifecycleFileKind::CanonicalRecord,
            &locks,
        )
        .unwrap()
        .unwrap();
        let owner = ExactFileEvidence::capture(
            &agent,
            &agent.join("device-owner.json"),
            LifecycleFileKind::CanonicalOwnerMarker,
            &locks,
        )
        .unwrap()
        .unwrap();
        let mut remove = sample(temp.path(), CleanupIntent::Remove);
        remove.authority =
            AuthorityEvidence::unavailable_corrupt(owner_bytes, record_bytes).unwrap();
        remove.deletion_targets = BTreeMap::from([(
            encode_path(&record.path()).unwrap(),
            PlannedDeletion::pending(record.clone()),
        )]);
        remove.retained_evidence = BTreeMap::from([(encode_path(&owner.path()).unwrap(), owner)]);
        let durable = store(&agent, &remove, &locks).unwrap();

        fs::write(agent.join("device-owner.json"), b"changed durable owner").unwrap();
        assert!(execute_planned_deletion(&agent, &durable, &record.path(), &locks).is_err());
        assert!(agent.join("device.json").is_file());
    }

    #[test]
    fn remove_requires_record_target_or_lock_captured_durable_absence() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);

        let mut target_without_record = sample(temp.path(), CleanupIntent::Remove);
        target_without_record.deletion_targets.clear();
        assert!(target_without_record.validate().is_err());

        let mut no_record_without_absence = target_without_record.clone();
        no_record_without_absence.authority = AuthorityEvidence::NoActiveRecord;
        assert!(no_record_without_absence.validate().is_err());

        let absent = no_active_sample(temp.path(), CleanupIntent::Remove, &locks);
        assert_eq!(absent.durable_absences().count(), 2);
        absent.validate().unwrap();
        fs::write(agent.join("device.json"), synthetic_record_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(agent.join("device.json"), fs::Permissions::from_mode(0o600))
                .unwrap();
        }
        assert!(store(&agent, &absent, &locks).is_err());
    }

    #[test]
    fn descriptor_rejects_present_and_absent_evidence_for_the_same_path() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let record = agent.join("device.json");
        fs::write(&record, synthetic_record_bytes()).unwrap();
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt as _;
            fs::set_permissions(&record, fs::Permissions::from_mode(0o600)).unwrap();
        }
        let locks = lifecycle_lock_set(&agent);
        let agent = fs::canonicalize(&agent).unwrap();
        let record = agent.join("device.json");
        let evidence =
            ExactFileEvidence::capture(&agent, &record, LifecycleFileKind::CanonicalRecord, &locks)
                .unwrap()
                .unwrap();
        let mut descriptor = sample(temp.path(), CleanupIntent::Remove);
        descriptor.deletion_targets = BTreeMap::from([(
            encode_path(&record).unwrap(),
            PlannedDeletion::pending(evidence),
        )]);
        descriptor.durable_absences.insert(
            encode_path(&record).unwrap(),
            DurableFileAbsence {
                lock_root: encode_path(&agent).unwrap(),
                path: encode_path(&record).unwrap(),
                kind: LifecycleFileKind::CanonicalRecord,
            },
        );

        assert!(descriptor.validate().is_err());
    }

    #[test]
    fn retained_owner_evidence_must_be_inside_its_exact_lock_root() {
        let temp = secure_tempdir();
        let canonical = temp.path().join("hydra-agent");
        let outside = temp.path().join("outside/hydra-agent");
        create_safe_directory(&canonical);
        create_safe_directory(&outside);
        let mut evidence = ExactFileEvidence {
            lock_root: encode_path(&canonical).unwrap(),
            path: encode_path(&outside.join("device-owner.json")).unwrap(),
            sha256: sha256(b"synthetic owner"),
            mode: 0o600,
            owner_uid: expected_uid(),
            device: 1,
            inode: 1,
            kind: LifecycleFileKind::CanonicalOwnerMarker,
        };
        assert!(evidence.validate().is_err());

        evidence.path = encode_path(&canonical.join("device-owner.json")).unwrap();
        assert!(evidence.validate().is_ok());
    }

    #[test]
    fn provider_target_digest_is_bound_to_exact_canonical_record_evidence() {
        let temp = secure_tempdir();
        let mut remove = sample(temp.path(), CleanupIntent::Remove);
        let AuthorityEvidence::Target { record_sha256, .. } = &mut remove.authority else {
            unreachable!()
        };
        *record_sha256 = sha256(b"another enrollment record");
        assert!(remove.validate().is_err());
    }

    #[test]
    fn full_forget_requires_explicit_stable_key_target_or_durable_absence() {
        let temp = secure_tempdir();
        let mut missing = sample(temp.path(), CleanupIntent::FullForget);
        missing
            .deletion_targets
            .retain(|_, planned| planned.evidence.kind != LifecycleFileKind::CanonicalStableKey);
        assert!(missing.validate().is_err());

        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let absent = no_active_sample(temp.path(), CleanupIntent::FullForget, &locks);
        assert_eq!(absent.durable_absences().count(), 3);
        absent.validate().unwrap();
        let durable = store(&agent, &absent, &locks).unwrap();
        assert!(full_forget_key_deletion_ready(&agent, &locks).unwrap());
        clear(&agent, &durable, &locks).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn owner_transfer_is_full_forget_only_and_runs_after_stable_key() {
        use std::os::unix::fs::PermissionsExt as _;

        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let key = agent.join("device-key");
        let owner = agent.join("device-owner.json");
        fs::write(&key, b"synthetic stable key").unwrap();
        fs::write(&owner, b"synthetic durable owner").unwrap();
        fs::set_permissions(&key, fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&owner, fs::Permissions::from_mode(0o600)).unwrap();
        let locks = lifecycle_lock_set(&agent);
        let key_evidence =
            ExactFileEvidence::capture(&agent, &key, LifecycleFileKind::CanonicalStableKey, &locks)
                .unwrap()
                .unwrap();
        let owner_evidence = ExactFileEvidence::capture(
            &agent,
            &owner,
            LifecycleFileKind::CanonicalOwnerMarker,
            &locks,
        )
        .unwrap()
        .unwrap();
        let unit = unit_path(temp.path());
        let roots = BTreeSet::from([fs::canonicalize(&agent).unwrap()]);
        let transfer = CleanupTombstone::new(
            CleanupIntent::FullForget,
            PriorActivation::ProvenClosed,
            AuthorityEvidence::NoActiveRecord,
            &agent,
            &roots,
            &roots,
            [],
            [key_evidence, owner_evidence.clone()],
            DesiredUnit::from_bytes(&unit, b"synthetic desired unit").unwrap(),
            None,
            &locks,
        )
        .unwrap();
        let current = store(&agent, &transfer, &locks).unwrap();

        assert!(execute_planned_deletion(&agent, &current, &owner, &locks).is_err());
        assert!(owner.is_file());
        let current = execute_planned_deletion(&agent, &current, &key, &locks).unwrap();
        assert!(!key.exists());
        let current = execute_planned_deletion(&agent, &current, &owner, &locks).unwrap();
        assert!(!owner.exists());
        clear(&agent, &current, &locks).unwrap();

        let mut remove = sample(temp.path(), CleanupIntent::Remove);
        remove.deletion_targets.insert(
            encode_path(&owner_evidence.path()).unwrap(),
            PlannedDeletion::pending(owner_evidence),
        );
        assert!(remove.validate().is_err());
    }

    #[test]
    fn exact_lock_set_rejects_both_missing_and_surplus_roots() {
        let temp = secure_tempdir();
        let canonical = temp.path().join("hydra-agent");
        let peer = temp.path().join("peer/hydra-agent");
        create_safe_directory(&canonical);
        create_safe_directory(&peer);
        let both =
            crate::service::LifecycleLockSet::acquire([canonical.clone(), peer.clone()]).unwrap();
        let one_root = sample(temp.path(), CleanupIntent::Close);
        assert!(store(&canonical, &one_root, &both).is_err());
        drop(both);

        let one = lifecycle_lock_set(&canonical);
        let canonical = fs::canonicalize(&canonical).unwrap();
        let peer = fs::canonicalize(&peer).unwrap();
        let mut two_root = sample(temp.path(), CleanupIntent::Close);
        for roots in [
            &mut two_root.lock_roots,
            &mut two_root.peer_roots,
            &mut two_root.readiness_roots,
        ] {
            roots.insert(encode_path(&peer).unwrap());
        }
        two_root.canonical_root = encode_path(&canonical).unwrap();
        two_root.validate().unwrap();
        assert!(store(&canonical, &two_root, &one).is_err());
    }

    #[test]
    fn provider_outbox_survives_local_cleanup_for_independent_retry() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let lock = locks.lock_for(&agent).unwrap();
        let pending = sample(temp.path(), CleanupIntent::Remove);
        let target = pending.revocation_target().unwrap().clone();
        let mut completed = pending.clone();
        for target in completed.deletion_targets.values_mut() {
            target.proven_absent = true;
        }
        store(&agent, &completed, &locks).unwrap();
        let handed_off = handoff_revocation(&agent, &target, &locks).unwrap();
        clear(&agent, &handed_off, &locks).unwrap();
        let outbox = load_revocation_outbox(&agent).unwrap();
        assert_eq!(outbox.targets().collect::<Vec<_>>(), vec![&target]);
        complete_revocation(&agent, target.device_id(), lock).unwrap();
        complete_revocation(&agent, target.device_id(), lock).unwrap();
        assert_eq!(load_revocation_outbox(&agent).unwrap().targets().count(), 0);
    }

    #[test]
    fn full_forget_waits_for_terminal_provider_and_durable_outbox_completion() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let lock = locks.lock_for(&agent).unwrap();
        let tombstone = sample(temp.path(), CleanupIntent::FullForget);
        let target = tombstone.revocation_target().unwrap().clone();
        store(&agent, &tombstone, &locks).unwrap();
        handoff_revocation(&agent, &target, &locks).unwrap();

        assert!(!full_forget_key_deletion_ready(&agent, &locks).unwrap());
        record_full_forget_provider_terminal(
            &agent,
            &target,
            ProviderTerminalOutcome::Revoked,
            &locks,
        )
        .unwrap();
        assert!(!full_forget_key_deletion_ready(&agent, &locks).unwrap());

        complete_revocation(&agent, target.device_id(), lock).unwrap();
        let current = load(&agent).unwrap().unwrap();
        let record_path = current
            .deletion_targets()
            .find(|planned| planned.evidence().kind() == LifecycleFileKind::CanonicalRecord)
            .unwrap()
            .evidence()
            .path();
        execute_planned_deletion(&agent, &current, &record_path, &locks).unwrap();
        assert!(full_forget_key_deletion_ready(&agent, &locks).unwrap());
    }

    #[test]
    fn provider_outbox_rejects_overflow_without_changing_durable_entries() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let lock = crate::service::LifecycleLock::acquire(&agent).unwrap();
        for index in 0..16 {
            let target = RevocationTarget::new(
                crate::release_trust::CLOUD_BASE.to_string(),
                "acct_synthetic".into(),
                format!("dev_{index:02}"),
            )
            .unwrap();
            enqueue_revocation(&agent, &target, &lock).unwrap();
        }
        let overflow = RevocationTarget::new(
            crate::release_trust::CLOUD_BASE.to_string(),
            "acct_synthetic".into(),
            "dev_16".into(),
        )
        .unwrap();
        assert!(enqueue_revocation(&agent, &overflow, &lock).is_err());
        let durable = load_revocation_outbox(&agent).unwrap();
        assert_eq!(durable.targets().count(), 16);
        assert!(durable
            .targets()
            .all(|target| target.device_id() != "dev_16"));
    }

    #[test]
    fn provider_outbox_completion_has_durable_removal_readback() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let lock = crate::service::LifecycleLock::acquire(&agent).unwrap();
        let target = RevocationTarget::new(
            crate::release_trust::CLOUD_BASE.to_string(),
            "acct_synthetic".into(),
            "dev_completed".into(),
        )
        .unwrap();
        enqueue_revocation(&agent, &target, &lock).unwrap();
        assert!(revocation_outbox_path(&agent).is_file());

        complete_revocation(&agent, target.device_id(), &lock).unwrap();

        assert_eq!(load_revocation_outbox(&agent).unwrap().targets().count(), 0);
        assert!(!revocation_outbox_path(&agent).exists());
    }

    #[test]
    fn lifecycle_lock_rejects_journal_and_outbox_mutation_for_another_root() {
        let temp = secure_tempdir();
        let first = temp.path().join("first/hydra-agent");
        let second = temp.path().join("second/hydra-agent");
        create_safe_directory(&first);
        create_safe_directory(&second);
        let wrong_locks = lifecycle_lock_set(&first);
        let wrong_lock = wrong_locks.lock_for(&first).unwrap();
        let value = sample(second.parent().unwrap(), CleanupIntent::Close);
        let target = RevocationTarget::new(
            crate::release_trust::CLOUD_BASE.to_string(),
            "acct_synthetic".into(),
            "dev_synthetic".into(),
        )
        .unwrap();

        assert!(store(&second, &value, &wrong_locks).is_err());
        assert!(enqueue_revocation(&second, &target, wrong_lock).is_err());
        assert!(complete_revocation(&second, target.device_id(), wrong_lock).is_err());
        assert!(clear(&second, &value, &wrong_locks).is_err());
        assert!(!recovery_dir(&second).exists());
    }

    #[test]
    fn stale_private_temporary_does_not_wedge_idempotent_clear() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let pending = sample(temp.path(), CleanupIntent::Close);
        store(&agent, &pending, &locks).unwrap();
        let stale = recovery_dir(&agent).join(format!(".{FILE_NAME}.9.9.tmp"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&stale)
                .unwrap();
        }
        #[cfg(not(unix))]
        fs::write(&stale, b"").unwrap();
        clear(&agent, &pending, &locks).unwrap();
        clear(&agent, &pending, &locks).unwrap();
    }

    #[test]
    fn crash_left_temporary_cannot_wedge_the_next_atomic_write() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        store(&agent, &sample(temp.path(), CleanupIntent::Close), &locks).unwrap();
        let stale = recovery_dir(&agent).join(format!(
            ".{FILE_NAME}.{}.{}.tmp",
            std::process::id(),
            TEMP_SEQUENCE.load(Ordering::Relaxed)
        ));
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            OpenOptions::new()
                .create_new(true)
                .write(true)
                .mode(0o600)
                .open(&stale)
                .unwrap();
        }
        #[cfg(not(unix))]
        fs::write(&stale, b"").unwrap();

        store(&agent, &sample(temp.path(), CleanupIntent::Close), &locks).unwrap();

        assert!(!stale.exists());
        assert!(load(&agent).unwrap().is_some());
    }

    #[test]
    fn unexpected_recovery_entry_blocks_clear_without_losing_the_journal() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let pending = sample(temp.path(), CleanupIntent::Close);
        store(&agent, &pending, &locks).unwrap();
        fs::write(recovery_dir(&agent).join("unreviewed"), b"x").unwrap();

        assert!(clear(&agent, &pending, &locks).is_err());
        assert_eq!(load(&agent).unwrap(), Some(pending));
    }

    #[test]
    fn cleanup_tombstone_clear_has_durable_absence_readback() {
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let pending = sample(temp.path(), CleanupIntent::Close);
        store(&agent, &pending, &locks).unwrap();
        assert!(path(&agent).is_file());

        clear(&agent, &pending, &locks).unwrap();

        assert!(load(&agent).unwrap().is_none());
        assert!(!path(&agent).exists());
    }

    #[test]
    fn schema_rejects_unknown_fields_relative_paths_and_arbitrary_delete_targets() {
        let temp = secure_tempdir();
        let mut value = serde_json::to_value(sample(temp.path(), CleanupIntent::Close)).unwrap();
        value
            .as_object_mut()
            .unwrap()
            .insert("extra".into(), true.into());
        assert!(serde_json::from_value::<CleanupTombstone>(value).is_err());
        assert!(ObservedUnit::from_bytes(
            Path::new("relative.service"),
            b"x",
            [UnitRole::HistoricalInstalled],
        )
        .is_err());
        assert!(ObservedUnit::from_bytes(
            &temp.path().join("victim.txt"),
            b"x",
            [UnitRole::HistoricalInstalled],
        )
        .is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_recovery_directory_and_permissive_record_are_rejected() {
        use std::os::unix::fs::{symlink, PermissionsExt as _};
        let temp = secure_tempdir();
        let agent = temp.path().join("hydra-agent");
        create_safe_directory(&agent);
        let locks = lifecycle_lock_set(&agent);
        let outside = temp.path().join("outside");
        create_safe_directory(&outside);
        symlink(&outside, recovery_dir(&agent)).unwrap();
        assert!(store(&agent, &sample(temp.path(), CleanupIntent::Close), &locks).is_err());
        fs::remove_file(recovery_dir(&agent)).unwrap();
        store(&agent, &sample(temp.path(), CleanupIntent::Close), &locks).unwrap();
        fs::set_permissions(path(&agent), fs::Permissions::from_mode(0o644)).unwrap();
        assert!(load(&agent).is_err());
        fs::set_permissions(path(&agent), fs::Permissions::from_mode(0o600)).unwrap();
        fs::set_permissions(&agent, fs::Permissions::from_mode(0o777)).unwrap();
        assert!(load(&agent).is_err());
    }
}
