//! Crash-recoverable tightening for the one supported Linux 0.2.8 authority shape.
//!
//! The affected directory can be too permissive to hold its own recovery record. The receipt
//! therefore lives at one fixed, effective-account-derived path directly under HOME. This module
//! creates/removes that receipt, never chmods HOME itself, and never chmods any path outside the
//! exact default 0.2.8 authority, systemd-service, and service-log ancestry recorded below.

#![cfg_attr(not(target_os = "linux"), allow(dead_code, unused_imports))]

use maestro_extension_api::{
    FilesystemMode, FilesystemModeChange, FilesystemModeMigrationNotice,
    FilesystemModeMigrationNoticeId, FilesystemModeMigrationPhase,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use std::fmt;
use std::fs::File;
use std::io::{self, Read as _, Write as _};
use std::path::{Path, PathBuf};

const RECEIPT_SCHEMA: &str = "hydra.authority-mode-migration.v1";
const RECEIPT_FILENAME: &str = ".hydra-agent-authority-migration-v1.json";
const MAX_RECEIPT_BYTES: usize = 16 * 1024;
const MAX_SERVICE_BYTES: usize = 128 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum ReceiptPathKind {
    SharedDirectory,
    PrivateDirectory,
    ServiceFile,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptEntry {
    path: String,
    kind: ReceiptPathKind,
    device: u64,
    inode: u64,
    original_mode: u32,
    target_mode: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    byte_len: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    sha256: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReceiptPlan {
    schema: String,
    uid: u32,
    home: String,
    entries: Vec<ReceiptEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    schema: String,
    notice_id: String,
    uid: u32,
    home: String,
    receipt_device: u64,
    receipt_inode: u64,
    entries: Vec<ReceiptEntry>,
}

impl Receipt {
    fn from_plan(plan: ReceiptPlan, receipt_device: u64, receipt_inode: u64) -> io::Result<Self> {
        let notice_id = plan_notice_id(&plan)?;
        Ok(Self {
            schema: plan.schema,
            notice_id,
            uid: plan.uid,
            home: plan.home,
            receipt_device,
            receipt_inode,
            entries: plan.entries,
        })
    }

    fn plan(&self) -> ReceiptPlan {
        ReceiptPlan {
            schema: self.schema.clone(),
            uid: self.uid,
            home: self.home.clone(),
            entries: self.entries.clone(),
        }
    }
}

/// An apply error after the receipt is durable carries the exact interrupted notice. The caller
/// can therefore keep the recovery path visible instead of collapsing a partial migration into a
/// generic lifecycle error.
#[derive(Debug)]
pub struct ApplyFailure {
    source: io::Error,
    notice: Option<FilesystemModeMigrationNotice>,
}

impl ApplyFailure {
    fn before_receipt(source: io::Error) -> Self {
        Self {
            source,
            notice: None,
        }
    }

    fn after_receipt(source: io::Error, receipt: &Receipt, home: &Path) -> Self {
        let notice =
            notice_from_receipt(receipt, home, FilesystemModeMigrationPhase::Interrupted).ok();
        Self { source, notice }
    }

    pub fn notice(&self) -> Option<&FilesystemModeMigrationNotice> {
        self.notice.as_ref()
    }
}

impl fmt::Display for ApplyFailure {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("Hydra authority migration could not complete")
    }
}

impl std::error::Error for ApplyFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

#[cfg(unix)]
struct ReceiptGuard {
    file: File,
    receipt: Receipt,
    device: u64,
    inode: u64,
}

/// Exact, locked acknowledgement prepared before the extension begins service convergence.
/// Keeping this value alive holds the receipt flock and its inode binding until `commit` removes
/// the migration latch at the explicit acknowledgement boundary.
pub struct PreparedAcknowledgement {
    #[cfg(unix)]
    home: PathBuf,
    #[cfg(unix)]
    guard: ReceiptGuard,
}

impl PreparedAcknowledgement {
    /// Remove the exact validated receipt. Service lifecycle/status work must begin only after
    /// this commit point because that work is allowed to replace the bound legacy unit.
    pub fn commit(self) -> io::Result<()> {
        #[cfg(unix)]
        {
            commit_acknowledgement(self)
        }
        #[cfg(not(unix))]
        Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "filesystem mode migration is Unix-only",
        ))
    }

    /// Commit the receipt removal before invoking any operation that may inspect, replace, or
    /// restart the installed service. The closure cannot run when commit fails, and a failure in
    /// the closure cannot resurrect the already-acknowledged receipt.
    pub fn commit_then<T>(self, continue_lifecycle: impl FnOnce() -> T) -> io::Result<T> {
        self.commit()?;
        Ok(continue_lifecycle())
    }
}

/// Read-only status probe. It never creates a receipt and never changes a mode.
#[cfg(target_os = "linux")]
pub fn probe(
    verify_legacy_service: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<Option<FilesystemModeMigrationNotice>> {
    require_default_xdg_homes()?;
    let home = crate::agent_dir::trusted_home_dir()?;
    probe_with_home_and_provenance(&home, verify_legacy_service)
}

/// Non-Linux installations never carried the affected XDG authority shape.
#[cfg(not(target_os = "linux"))]
pub fn probe(
    _verify_legacy_service: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<Option<FilesystemModeMigrationNotice>> {
    Ok(None)
}

#[cfg(target_os = "linux")]
pub fn apply(
    expected_notice_id: &FilesystemModeMigrationNoticeId,
    verify_legacy_service: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<FilesystemModeMigrationNotice, ApplyFailure> {
    require_default_xdg_homes().map_err(ApplyFailure::before_receipt)?;
    let home = crate::agent_dir::trusted_home_dir().map_err(ApplyFailure::before_receipt)?;
    apply_with_home_and_hook_and_provenance(
        &home,
        expected_notice_id,
        verify_legacy_service,
        |_| Ok(()),
    )
}

#[cfg(not(target_os = "linux"))]
pub fn apply(
    _expected_notice_id: &FilesystemModeMigrationNoticeId,
    _verify_legacy_service: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> Result<FilesystemModeMigrationNotice, ApplyFailure> {
    Err(ApplyFailure::before_receipt(io::Error::new(
        io::ErrorKind::Unsupported,
        "filesystem mode migration is Linux-only",
    )))
}

#[cfg(target_os = "linux")]
pub fn prepare_acknowledgement(
    expected_notice_id: &FilesystemModeMigrationNoticeId,
    verify_legacy_service: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<PreparedAcknowledgement> {
    require_default_xdg_homes()?;
    let home = crate::agent_dir::trusted_home_dir()?;
    prepare_acknowledgement_with_home_and_provenance(
        &home,
        expected_notice_id,
        verify_legacy_service,
    )
}

#[cfg(target_os = "linux")]
fn require_default_xdg_homes() -> io::Result<()> {
    require_default_xdg_homes_with(|name| std::env::var_os(name))
}

#[cfg(any(target_os = "linux", test))]
fn require_default_xdg_homes_with(
    read: impl Fn(&str) -> Option<std::ffi::OsString>,
) -> io::Result<()> {
    for name in ["XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"] {
        if read(name).is_some_and(|value| !value.is_empty()) {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("custom {name} is outside the fixed authority migration contract"),
            ));
        }
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn prepare_acknowledgement(
    _expected_notice_id: &FilesystemModeMigrationNoticeId,
    _verify_legacy_service: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<PreparedAcknowledgement> {
    Err(io::Error::new(
        io::ErrorKind::Unsupported,
        "filesystem mode migration is Linux-only",
    ))
}

#[cfg(unix)]
fn receipt_path(home: &Path) -> PathBuf {
    home.join(RECEIPT_FILENAME)
}

#[cfg(unix)]
fn path_text(path: &Path) -> io::Result<String> {
    path.to_str().map(str::to_owned).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hydra authority migration path is not UTF-8",
        )
    })
}

#[cfg(unix)]
fn plan_notice_id(plan: &ReceiptPlan) -> io::Result<String> {
    let bytes = serde_json::to_vec(plan)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "serialize migration plan"))?;
    let digest = Sha256::digest(bytes);
    Ok(digest.iter().map(|byte| format!("{byte:02x}")).collect())
}

#[cfg(unix)]
fn notice_id(receipt: &Receipt) -> io::Result<FilesystemModeMigrationNoticeId> {
    FilesystemModeMigrationNoticeId::new(receipt.notice_id.clone()).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hydra authority receipt has an invalid notice id",
        )
    })
}

#[cfg(unix)]
fn mode_to_public(mode: u32) -> io::Result<FilesystemMode> {
    match mode {
        0o640 => Ok(FilesystemMode::OwnerGroupReadFile),
        0o644 => Ok(FilesystemMode::PublicReadFile),
        0o660 => Ok(FilesystemMode::LegacyGroupWritableFile),
        0o664 => Ok(FilesystemMode::LegacyPublicGroupWritableFile),
        0o700 => Ok(FilesystemMode::OwnerOnly),
        0o750 => Ok(FilesystemMode::OwnerGroupRead),
        0o755 => Ok(FilesystemMode::PublicRead),
        0o770 => Ok(FilesystemMode::LegacyGroupWritable),
        0o775 => Ok(FilesystemMode::LegacyPublicGroupWritable),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hydra authority receipt contains an unsupported changed mode",
        )),
    }
}

#[cfg(unix)]
fn notice_from_receipt(
    receipt: &Receipt,
    home: &Path,
    phase: FilesystemModeMigrationPhase,
) -> io::Result<FilesystemModeMigrationNotice> {
    let changes = receipt
        .entries
        .iter()
        .filter(|entry| entry.original_mode != entry.target_mode)
        .map(|entry| {
            FilesystemModeChange::new(
                entry.path.clone(),
                mode_to_public(entry.original_mode)?,
                mode_to_public(entry.target_mode)?,
            )
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Hydra authority receipt contains an invalid mode change",
                )
            })
        })
        .collect::<io::Result<Vec<_>>>()?;
    let recovery_record_path = (phase != FilesystemModeMigrationPhase::ReadyToApply)
        .then(|| path_text(&receipt_path(home)))
        .transpose()?;
    FilesystemModeMigrationNotice::new(notice_id(receipt)?, phase, changes, recovery_record_path)
        .map_err(|_| {
            io::Error::new(
                io::ErrorKind::InvalidData,
                "Hydra authority receipt cannot form a public notice",
            )
        })
}

#[cfg(unix)]
fn validate_home(home: &Path) -> io::Result<()> {
    use std::os::unix::fs::MetadataExt as _;

    if !crate::agent_dir::is_canonically_encoded_absolute_path(home) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "trusted home is not a canonical absolute path",
        ));
    }
    crate::agent_dir::require_rename_safe_ancestry(home)?;
    // A sticky bit can make a shared directory rename-safe, but HOME is also the receipt's direct
    // authority container. It must itself be owned and non-group/world-writable; this function
    // never chmods it.
    crate::agent_dir::require_owned_safe_directory(home)?;
    let metadata = std::fs::symlink_metadata(home)?;
    if !metadata.file_type().is_dir() || metadata.uid() != crate::agent_dir::trusted_uid() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "trusted home has unsafe metadata",
        ));
    }
    Ok(())
}

const FIXED_PATH_COUNT: usize = 10;
const AUTHORITY_LEAF_INDEX: usize = 2;
#[cfg(unix)]
const SERVICE_FILE_INDEX: usize = 6;

#[cfg(unix)]
fn fixed_paths(home: &Path) -> [(PathBuf, ReceiptPathKind); FIXED_PATH_COUNT] {
    let local = home.join(".local");
    let share = local.join("share");
    let authority = share.join("hydra-agent");
    let config = home.join(".config");
    let systemd = config.join("systemd");
    let systemd_user = systemd.join("user");
    let unit = systemd_user.join("hydra-agent.service");
    let state = local.join("state");
    let service_state = state.join("hydra-agent");
    let logs = service_state.join("logs");
    [
        (local, ReceiptPathKind::SharedDirectory),
        (share, ReceiptPathKind::SharedDirectory),
        (authority, ReceiptPathKind::PrivateDirectory),
        (config, ReceiptPathKind::SharedDirectory),
        (systemd, ReceiptPathKind::SharedDirectory),
        (systemd_user, ReceiptPathKind::SharedDirectory),
        (unit, ReceiptPathKind::ServiceFile),
        (state, ReceiptPathKind::SharedDirectory),
        (service_state, ReceiptPathKind::PrivateDirectory),
        (logs, ReceiptPathKind::PrivateDirectory),
    ]
}

#[cfg(unix)]
fn target_mode(kind: ReceiptPathKind, mode: u32) -> io::Result<u32> {
    if mode & 0o7000 != 0 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "default Hydra authority path has unsupported special mode bits",
        ));
    }
    match (kind, mode) {
        (ReceiptPathKind::SharedDirectory, 0o770) => Ok(0o750),
        (ReceiptPathKind::SharedDirectory, 0o775) => Ok(0o755),
        (ReceiptPathKind::PrivateDirectory, 0o770 | 0o775) => Ok(0o700),
        (ReceiptPathKind::ServiceFile, 0o660) => Ok(0o640),
        (ReceiptPathKind::ServiceFile, 0o664) => Ok(0o644),
        (_, safe) if safe & 0o022 == 0 => Ok(safe),
        _ => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "default Hydra authority path is not an exact supported legacy shape",
        )),
    }
}

#[cfg(unix)]
fn capture_service_bytes(file: &File) -> io::Result<Vec<u8>> {
    use std::io::{Read as _, Seek as _, SeekFrom};

    let metadata = file.metadata()?;
    if metadata.len() == 0 || metadata.len() > MAX_SERVICE_BYTES as u64 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "default Hydra service definition has invalid length",
        ));
    }
    let mut reader = file.try_clone()?;
    reader.seek(SeekFrom::Start(0))?;
    let mut bytes = Vec::with_capacity(metadata.len() as usize);
    reader
        .take((MAX_SERVICE_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() != metadata.len() as usize || bytes.len() > MAX_SERVICE_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "default Hydra service definition changed while it was read",
        ));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn sha256_hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

#[cfg(unix)]
fn discover_plan(home: &Path) -> io::Result<Option<ReceiptPlan>> {
    discover_plan_for_uid(home, crate::agent_dir::trusted_uid())
}

#[cfg(unix)]
fn discover_plan_for_uid(home: &Path, expected_uid: u32) -> io::Result<Option<ReceiptPlan>> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    validate_home(home)?;
    let paths = fixed_paths(home);
    let leaf = match std::fs::symlink_metadata(&paths[AUTHORITY_LEAF_INDEX].0) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    if !leaf.file_type().is_dir() || leaf.uid() != expected_uid {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "default Hydra authority leaf has unsafe metadata",
        ));
    }

    // A fresh or explicitly closed desktop has no installed connectivity unit. In that state
    // there is no published 0.2.8 service whose inode/bytes can authorize the legacy ten-path
    // chmod transaction. Admit the state only when every other existing path is already safe;
    // missing optional service/log ancestry is normal before first enrollment. Any supported
    // legacy-writable mode still fails closed below rather than bypassing provenance.
    match std::fs::symlink_metadata(&paths[SERVICE_FILE_INDEX].0) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            for (path, kind) in paths.iter() {
                if *kind == ReceiptPathKind::ServiceFile {
                    continue;
                }
                let metadata = match std::fs::symlink_metadata(path) {
                    Ok(metadata) => metadata,
                    Err(error) if error.kind() == io::ErrorKind::NotFound => continue,
                    Err(error) => return Err(error),
                };
                if !metadata.file_type().is_dir() || metadata.uid() != expected_uid {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "default Hydra authority path has unsafe metadata",
                    ));
                }
                let original_mode = metadata.permissions().mode() & 0o7777;
                if target_mode(*kind, original_mode)? != original_mode {
                    return Err(io::Error::new(
                        io::ErrorKind::PermissionDenied,
                        "legacy Hydra authority modes require the exact published service provenance",
                    ));
                }
            }
            return Ok(None);
        }
        Err(error) => return Err(error),
        Ok(_) => {}
    }

    let mut entries = Vec::with_capacity(paths.len());
    for (path, kind) in paths.iter() {
        let metadata = std::fs::symlink_metadata(path)?;
        let original_mode = metadata.permissions().mode() & 0o7777;
        let type_matches = match kind {
            ReceiptPathKind::SharedDirectory | ReceiptPathKind::PrivateDirectory => {
                metadata.file_type().is_dir()
            }
            ReceiptPathKind::ServiceFile => metadata.file_type().is_file() && metadata.nlink() == 1,
        };
        if !type_matches || metadata.uid() != expected_uid {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "default Hydra authority path has unsafe metadata",
            ));
        }
        let target_mode = target_mode(*kind, original_mode)?;
        let (byte_len, sha256) = if *kind == ReceiptPathKind::ServiceFile {
            use std::os::unix::fs::OpenOptionsExt as _;
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
            let file = options.open(path)?;
            let opened = file.metadata()?;
            if !opened.file_type().is_file()
                || opened.uid() != expected_uid
                || opened.nlink() != 1
                || opened.dev() != metadata.dev()
                || opened.ino() != metadata.ino()
                || opened.permissions().mode() & 0o7777 != original_mode
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "default Hydra service definition changed before capture",
                ));
            }
            let bytes = capture_service_bytes(&file)?;
            let after = file.metadata()?;
            let named_after = std::fs::symlink_metadata(path)?;
            if after.dev() != metadata.dev()
                || after.ino() != metadata.ino()
                || after.len() != metadata.len()
                || named_after.dev() != metadata.dev()
                || named_after.ino() != metadata.ino()
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "default Hydra service definition changed during capture",
                ));
            }
            (Some(bytes.len() as u64), Some(sha256_hex(&bytes)))
        } else {
            (None, None)
        };
        entries.push(ReceiptEntry {
            path: path_text(path)?,
            kind: *kind,
            device: metadata.dev(),
            inode: metadata.ino(),
            original_mode,
            target_mode,
            byte_len,
            sha256,
        });
    }
    if entries
        .iter()
        .all(|entry| entry.original_mode == entry.target_mode)
    {
        return Ok(None);
    }
    Ok(Some(ReceiptPlan {
        schema: RECEIPT_SCHEMA.to_string(),
        uid: expected_uid,
        home: path_text(home)?,
        entries,
    }))
}

#[cfg(unix)]
fn receipt_exists(home: &Path) -> io::Result<bool> {
    match std::fs::symlink_metadata(receipt_path(home)) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error),
    }
}

#[cfg(unix)]
fn flock_exclusive(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd as _;

    if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(unix)]
fn validate_receipt_file_binding(home: &Path, guard: &ReceiptGuard) -> io::Result<()> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    let opened = guard.file.metadata()?;
    let named = std::fs::symlink_metadata(receipt_path(home))?;
    if !opened.file_type().is_file()
        || !named.file_type().is_file()
        || opened.uid() != crate::agent_dir::trusted_uid()
        || opened.permissions().mode() & 0o7777 != 0o600
        || opened.nlink() != 1
        || opened.dev() != guard.device
        || opened.ino() != guard.inode
        || opened.dev() != guard.receipt.receipt_device
        || opened.ino() != guard.receipt.receipt_inode
        || named.dev() != guard.device
        || named.ino() != guard.inode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hydra authority recovery receipt changed or has unsafe metadata",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn validate_receipt_schema(home: &Path, receipt: &Receipt) -> io::Result<()> {
    if receipt.schema != RECEIPT_SCHEMA
        || receipt.uid != crate::agent_dir::trusted_uid()
        || receipt.home != path_text(home)?
        || receipt.notice_id != plan_notice_id(&receipt.plan())?
        || receipt.receipt_device == 0
        || receipt.receipt_inode == 0
        || receipt.entries.len() != FIXED_PATH_COUNT
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hydra authority recovery receipt does not match this account",
        ));
    }
    let paths = fixed_paths(home);
    for (entry, (expected_path, expected_kind)) in receipt.entries.iter().zip(paths) {
        let file_binding_valid = if expected_kind == ReceiptPathKind::ServiceFile {
            entry
                .byte_len
                .is_some_and(|length| length > 0 && length <= MAX_SERVICE_BYTES as u64)
                && entry.sha256.as_ref().is_some_and(|digest| {
                    digest.len() == 64
                        && digest
                            .bytes()
                            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
                })
        } else {
            entry.byte_len.is_none() && entry.sha256.is_none()
        };
        if entry.path != path_text(&expected_path)?
            || entry.kind != expected_kind
            || entry.device == 0
            || entry.inode == 0
            || entry.target_mode != target_mode(expected_kind, entry.original_mode)?
            || !file_binding_valid
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Hydra authority recovery receipt contains an invalid path binding",
            ));
        }
    }
    if receipt
        .entries
        .iter()
        .all(|entry| entry.original_mode == entry.target_mode)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hydra authority recovery receipt contains no mode change",
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn read_receipt(home: &Path) -> io::Result<ReceiptGuard> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};

    validate_home(home)?;
    let path = receipt_path(home);
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let mut file = options.open(&path)?;
    flock_exclusive(&file)?;
    let metadata = file.metadata()?;
    let mut bytes = Vec::new();
    std::io::Read::by_ref(&mut file)
        .take((MAX_RECEIPT_BYTES + 1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hydra authority recovery receipt has invalid length",
        ));
    }
    let receipt: Receipt = serde_json::from_slice(&bytes).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hydra authority recovery receipt is malformed",
        )
    })?;
    let canonical = serde_json::to_vec(&receipt).map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidData,
            "Hydra authority recovery receipt cannot be canonicalized",
        )
    })?;
    if bytes != canonical {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hydra authority recovery receipt is not canonical",
        ));
    }
    validate_receipt_schema(home, &receipt)?;
    let guard = ReceiptGuard {
        file,
        receipt,
        device: metadata.dev(),
        inode: metadata.ino(),
    };
    validate_receipt_file_binding(home, &guard)?;
    Ok(guard)
}

#[cfg(unix)]
fn initialize_unpublished_receipt(
    home: &Path,
    plan: ReceiptPlan,
    mut file: File,
) -> io::Result<(File, Receipt, u64, u64)> {
    use std::os::fd::AsRawFd as _;
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

    flock_exclusive(&file)?;
    // Both O_TMPFILE and OpenOptionsExt::mode are filtered by the ambient umask. Bind the new inode
    // by descriptor and make its private mode exact before any authority content is written.
    if unsafe { libc::fchmod(file.as_raw_fd(), 0o600) } != 0 {
        return Err(io::Error::last_os_error());
    }
    let metadata = file.metadata()?;
    if metadata.permissions().mode() & 0o7777 != 0o600 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hydra authority recovery receipt did not become owner-only",
        ));
    }
    let receipt = Receipt::from_plan(plan, metadata.dev(), metadata.ino())?;
    validate_receipt_schema(home, &receipt)?;
    let bytes = serde_json::to_vec(&receipt)
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "serialize migration receipt"))?;
    if bytes.is_empty() || bytes.len() > MAX_RECEIPT_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hydra authority recovery receipt exceeds its bound",
        ));
    }
    file.write_all(&bytes)?;
    file.sync_all()?;
    Ok((file, receipt, metadata.dev(), metadata.ino()))
}

#[cfg(unix)]
fn open_bound_home_directory(home: &Path) -> io::Result<File> {
    use std::os::unix::fs::OpenOptionsExt as _;

    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_DIRECTORY | libc::O_NOFOLLOW);
    options.open(home)
}

/// Linux publishes a complete receipt inode atomically. Before `linkat`, a crash closes and drops
/// the unnamed O_TMPFILE; after `linkat`, the final name can contain only the already-fsynced exact
/// canonical bytes. `/proc/self/fd` is used because `AT_EMPTY_PATH` publication requires a Linux
/// capability that an ordinary desktop/server account does not hold. The open descriptor remains
/// bound throughout the link and the existing reopen proof checks its device and inode. There is
/// no interval in which an empty or truncated final receipt is visible.
#[cfg(target_os = "linux")]
fn create_receipt_with_before_publish(
    home: &Path,
    plan: ReceiptPlan,
    before_publish: impl FnOnce(&File) -> io::Result<()>,
) -> io::Result<ReceiptGuard> {
    use std::ffi::CString;
    use std::os::fd::{AsRawFd as _, FromRawFd as _};

    validate_home(home)?;
    let home_directory = open_bound_home_directory(home)?;
    let dot = CString::new(".").expect("literal has no NUL");
    let descriptor = unsafe {
        libc::openat(
            home_directory.as_raw_fd(),
            dot.as_ptr(),
            libc::O_TMPFILE | libc::O_RDWR | libc::O_CLOEXEC,
            0o600 as libc::mode_t,
        )
    };
    if descriptor < 0 {
        return Err(io::Error::last_os_error());
    }
    let file = unsafe { File::from_raw_fd(descriptor) };
    let (file, _receipt, device, inode) = initialize_unpublished_receipt(home, plan, file)?;
    before_publish(&file)?;

    let descriptor_path = CString::new(format!("/proc/self/fd/{}", file.as_raw_fd()))
        .expect("descriptor path has no NUL");
    let name = CString::new(RECEIPT_FILENAME).expect("literal has no NUL");
    if unsafe {
        libc::linkat(
            libc::AT_FDCWD,
            descriptor_path.as_ptr(),
            home_directory.as_raw_fd(),
            name.as_ptr(),
            libc::AT_SYMLINK_FOLLOW,
        )
    } != 0
    {
        let error = io::Error::last_os_error();
        drop(file);
        if error.kind() == io::ErrorKind::AlreadyExists {
            return read_receipt(home);
        }
        return Err(error);
    }
    home_directory.sync_all()?;
    drop(file);
    let guard = read_receipt(home)?;
    if guard.device != device || guard.inode != inode {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hydra authority recovery receipt changed while reopening",
        ));
    }
    Ok(guard)
}

#[cfg(target_os = "linux")]
fn create_receipt(home: &Path, plan: ReceiptPlan) -> io::Result<ReceiptGuard> {
    create_receipt_with_before_publish(home, plan, |_| Ok(()))
}

/// Synthetic Unix tests also run on macOS, where O_TMPFILE/AT_EMPTY_PATH do not exist. The public
/// mutation entrypoint is Linux-only; this direct-name implementation is therefore test support,
/// not a production publication path. Linux tests exercise the atomic implementation above.
#[cfg(all(unix, not(target_os = "linux")))]
fn create_receipt(home: &Path, plan: ReceiptPlan) -> io::Result<ReceiptGuard> {
    use std::os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _};

    validate_home(home)?;
    let mut options = std::fs::OpenOptions::new();
    options
        .read(true)
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    let file = options.open(receipt_path(home))?;
    let (file, _receipt, device, inode) = initialize_unpublished_receipt(home, plan, file)?;
    open_bound_home_directory(home)?.sync_all()?;
    drop(file);
    let guard = read_receipt(home)?;
    if guard.device != device || guard.inode != inode {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hydra authority recovery receipt changed while reopening",
        ));
    }
    Ok(guard)
}

#[cfg(unix)]
fn validate_bound_paths(home: &Path, guard: &ReceiptGuard) -> io::Result<Vec<u32>> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    validate_home(home)?;
    validate_receipt_file_binding(home, guard)?;
    let mut modes = Vec::with_capacity(guard.receipt.entries.len());
    for entry in &guard.receipt.entries {
        let path = Path::new(&entry.path);
        if !crate::agent_dir::is_canonically_encoded_absolute_path(path) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "Hydra authority receipt path is not canonical",
            ));
        }
        let metadata = std::fs::symlink_metadata(path)?;
        let mode = metadata.permissions().mode() & 0o7777;
        let type_matches = match entry.kind {
            ReceiptPathKind::SharedDirectory | ReceiptPathKind::PrivateDirectory => {
                metadata.file_type().is_dir()
            }
            ReceiptPathKind::ServiceFile => metadata.file_type().is_file() && metadata.nlink() == 1,
        };
        if !type_matches
            || metadata.uid() != guard.receipt.uid
            || metadata.dev() != entry.device
            || metadata.ino() != entry.inode
            || !matches!(mode, current if current == entry.original_mode || current == entry.target_mode)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Hydra authority path changed during migration",
            ));
        }
        if entry.kind == ReceiptPathKind::ServiceFile {
            let mut options = std::fs::OpenOptions::new();
            options
                .read(true)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW | libc::O_NONBLOCK);
            let file = options.open(path)?;
            let opened = file.metadata()?;
            let bytes = capture_service_bytes(&file)?;
            let digest = sha256_hex(&bytes);
            let named_after = std::fs::symlink_metadata(path)?;
            if opened.dev() != entry.device
                || opened.ino() != entry.inode
                || opened.uid() != guard.receipt.uid
                || opened.nlink() != 1
                || opened.permissions().mode() & 0o7777 != mode
                || named_after.dev() != entry.device
                || named_after.ino() != entry.inode
                || Some(bytes.len() as u64) != entry.byte_len
                || entry.sha256.as_deref() != Some(digest.as_str())
            {
                return Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "Hydra service definition changed during migration",
                ));
            }
        }
        modes.push(mode);
    }
    Ok(modes)
}

#[cfg(unix)]
fn phase_from_modes(
    receipt: &Receipt,
    modes: &[u32],
    has_receipt: bool,
) -> io::Result<FilesystemModeMigrationPhase> {
    if modes.len() != receipt.entries.len() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Hydra authority mode inventory is incomplete",
        ));
    }
    if receipt
        .entries
        .iter()
        .zip(modes)
        .all(|(entry, mode)| *mode == entry.target_mode)
    {
        return Ok(FilesystemModeMigrationPhase::Applied);
    }
    Ok(if has_receipt {
        FilesystemModeMigrationPhase::Interrupted
    } else {
        FilesystemModeMigrationPhase::ReadyToApply
    })
}

#[cfg(unix)]
fn probe_with_home_and_provenance(
    home: &Path,
    verify_legacy_service: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<Option<FilesystemModeMigrationNotice>> {
    if receipt_exists(home)? {
        let guard = read_receipt(home)?;
        verify_legacy_service(home, &fixed_paths(home)[AUTHORITY_LEAF_INDEX].0)?;
        let modes = validate_bound_paths(home, &guard)?;
        let phase = phase_from_modes(&guard.receipt, &modes, true)?;
        return notice_from_receipt(&guard.receipt, home, phase).map(Some);
    }
    let Some(plan) = discover_plan(home)? else {
        return Ok(None);
    };
    verify_legacy_service(home, &fixed_paths(home)[AUTHORITY_LEAF_INDEX].0)?;
    if discover_plan(home)?.as_ref() != Some(&plan) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hydra authority plan changed while service provenance was verified",
        ));
    }
    // A ready notice exists before the receipt inode does. The receipt binding fields are not part
    // of the notice id and are used only after create-no-replace succeeds.
    let receipt = Receipt::from_plan(plan, 0, 0)?;
    notice_from_receipt(&receipt, home, FilesystemModeMigrationPhase::ReadyToApply).map(Some)
}

#[cfg(all(test, unix))]
fn probe_with_home(home: &Path) -> io::Result<Option<FilesystemModeMigrationNotice>> {
    probe_with_home_and_provenance(home, |_, _| Ok(()))
}

#[cfg(unix)]
fn open_bound_path(entry: &ReceiptEntry, current_mode: u32) -> io::Result<File> {
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    let mut flags = libc::O_CLOEXEC | libc::O_NOFOLLOW;
    if entry.kind != ReceiptPathKind::ServiceFile {
        flags |= libc::O_DIRECTORY;
    } else {
        flags |= libc::O_NONBLOCK;
    }
    options.custom_flags(flags);
    let directory = options.open(&entry.path)?;
    let metadata = directory.metadata()?;
    let type_matches = match entry.kind {
        ReceiptPathKind::SharedDirectory | ReceiptPathKind::PrivateDirectory => {
            metadata.file_type().is_dir()
        }
        ReceiptPathKind::ServiceFile => metadata.file_type().is_file() && metadata.nlink() == 1,
    };
    if !type_matches
        || metadata.uid() != crate::agent_dir::trusted_uid()
        || metadata.dev() != entry.device
        || metadata.ino() != entry.inode
        || metadata.permissions().mode() & 0o7777 != current_mode
    {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "Hydra authority path changed before mode update",
        ));
    }
    if entry.kind == ReceiptPathKind::ServiceFile {
        let bytes = capture_service_bytes(&directory)?;
        let digest = sha256_hex(&bytes);
        if Some(bytes.len() as u64) != entry.byte_len
            || entry.sha256.as_deref() != Some(digest.as_str())
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Hydra service definition bytes changed before mode update",
            ));
        }
    }
    Ok(directory)
}

#[cfg(unix)]
fn apply_with_home_and_hook_and_provenance(
    home: &Path,
    expected_notice_id: &FilesystemModeMigrationNoticeId,
    verify_legacy_service: impl FnOnce(&Path, &Path) -> io::Result<()>,
    mut after_change: impl FnMut(usize) -> io::Result<()>,
) -> Result<FilesystemModeMigrationNotice, ApplyFailure> {
    use std::os::fd::AsRawFd as _;

    let guard = if receipt_exists(home).map_err(ApplyFailure::before_receipt)? {
        let guard = read_receipt(home).map_err(ApplyFailure::before_receipt)?;
        verify_legacy_service(home, &fixed_paths(home)[AUTHORITY_LEAF_INDEX].0)
            .map_err(|error| ApplyFailure::after_receipt(error, &guard.receipt, home))?;
        guard
    } else {
        let plan = discover_plan(home)
            .map_err(ApplyFailure::before_receipt)?
            .ok_or_else(|| {
                ApplyFailure::before_receipt(io::Error::new(
                    io::ErrorKind::NotFound,
                    "no Hydra authority migration is pending",
                ))
            })?;
        if plan_notice_id(&plan).map_err(ApplyFailure::before_receipt)?
            != expected_notice_id.as_str()
        {
            return Err(ApplyFailure::before_receipt(io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hydra authority notice changed before apply",
            )));
        }
        verify_legacy_service(home, &fixed_paths(home)[AUTHORITY_LEAF_INDEX].0)
            .map_err(ApplyFailure::before_receipt)?;
        if discover_plan(home)
            .map_err(ApplyFailure::before_receipt)?
            .as_ref()
            != Some(&plan)
        {
            return Err(ApplyFailure::before_receipt(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "Hydra authority plan changed while service provenance was verified",
            )));
        }
        create_receipt(home, plan).map_err(ApplyFailure::before_receipt)?
    };

    if guard.receipt.notice_id != expected_notice_id.as_str() {
        return Err(ApplyFailure::after_receipt(
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "Hydra authority notice does not match its recovery receipt",
            ),
            &guard.receipt,
            home,
        ));
    }

    for index in 0..guard.receipt.entries.len() {
        let entry = &guard.receipt.entries[index];
        if entry.original_mode == entry.target_mode {
            continue;
        }
        let modes = validate_bound_paths(home, &guard)
            .map_err(|error| ApplyFailure::after_receipt(error, &guard.receipt, home))?;
        if modes[index] == entry.target_mode {
            continue;
        }
        let directory = open_bound_path(entry, modes[index])
            .map_err(|error| ApplyFailure::after_receipt(error, &guard.receipt, home))?;
        validate_bound_paths(home, &guard)
            .map_err(|error| ApplyFailure::after_receipt(error, &guard.receipt, home))?;
        if unsafe { libc::fchmod(directory.as_raw_fd(), entry.target_mode as libc::mode_t) } != 0 {
            return Err(ApplyFailure::after_receipt(
                io::Error::last_os_error(),
                &guard.receipt,
                home,
            ));
        }
        directory
            .sync_all()
            .map_err(|error| ApplyFailure::after_receipt(error, &guard.receipt, home))?;
        validate_bound_paths(home, &guard)
            .map_err(|error| ApplyFailure::after_receipt(error, &guard.receipt, home))?;
        after_change(index)
            .map_err(|error| ApplyFailure::after_receipt(error, &guard.receipt, home))?;
    }
    let modes = validate_bound_paths(home, &guard)
        .map_err(|error| ApplyFailure::after_receipt(error, &guard.receipt, home))?;
    if phase_from_modes(&guard.receipt, &modes, true)
        .map_err(|error| ApplyFailure::after_receipt(error, &guard.receipt, home))?
        != FilesystemModeMigrationPhase::Applied
    {
        return Err(ApplyFailure::after_receipt(
            io::Error::other("Hydra authority migration did not reach its target modes"),
            &guard.receipt,
            home,
        ));
    }
    notice_from_receipt(&guard.receipt, home, FilesystemModeMigrationPhase::Applied)
        .map_err(|error| ApplyFailure::after_receipt(error, &guard.receipt, home))
}

#[cfg(all(test, unix))]
fn apply_with_home_and_hook(
    home: &Path,
    expected_notice_id: &FilesystemModeMigrationNoticeId,
    after_change: impl FnMut(usize) -> io::Result<()>,
) -> Result<FilesystemModeMigrationNotice, ApplyFailure> {
    apply_with_home_and_hook_and_provenance(home, expected_notice_id, |_, _| Ok(()), after_change)
}

#[cfg(unix)]
fn prepare_acknowledgement_with_home(
    home: &Path,
    expected_notice_id: &FilesystemModeMigrationNoticeId,
) -> io::Result<PreparedAcknowledgement> {
    let guard = read_receipt(home)?;
    if guard.receipt.notice_id != expected_notice_id.as_str() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hydra authority notice changed before acknowledgement",
        ));
    }
    let modes = validate_bound_paths(home, &guard)?;
    if phase_from_modes(&guard.receipt, &modes, true)? != FilesystemModeMigrationPhase::Applied {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hydra authority migration is not complete",
        ));
    }
    validate_receipt_file_binding(home, &guard)?;
    Ok(PreparedAcknowledgement {
        home: home.to_path_buf(),
        guard,
    })
}

#[cfg(unix)]
fn prepare_acknowledgement_with_home_and_provenance(
    home: &Path,
    expected_notice_id: &FilesystemModeMigrationNoticeId,
    verify_legacy_service: impl FnOnce(&Path, &Path) -> io::Result<()>,
) -> io::Result<PreparedAcknowledgement> {
    let prepared = prepare_acknowledgement_with_home(home, expected_notice_id)?;
    verify_legacy_service(home, &fixed_paths(home)[AUTHORITY_LEAF_INDEX].0)?;
    let modes = validate_bound_paths(home, &prepared.guard)?;
    if phase_from_modes(&prepared.guard.receipt, &modes, true)?
        != FilesystemModeMigrationPhase::Applied
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "Hydra authority migration changed before acknowledgement",
        ));
    }
    validate_receipt_file_binding(home, &prepared.guard)?;
    Ok(prepared)
}

#[cfg(unix)]
fn commit_acknowledgement(prepared: PreparedAcknowledgement) -> io::Result<()> {
    // Open and sync HOME before the irreversible unlink so it is the final operation that can
    // prevent acknowledgement. A post-unlink directory fsync is still attempted for durability,
    // but cannot safely turn a completed unlink into an Error that would strand the host latch.
    let home_directory = open_bound_home_directory(&prepared.home)?;
    validate_receipt_file_binding(&prepared.home, &prepared.guard)?;
    home_directory.sync_all()?;
    std::fs::remove_file(receipt_path(&prepared.home))?;
    let _ = home_directory.sync_all();
    Ok(())
}

#[cfg(all(test, unix))]
fn acknowledge_with_home(
    home: &Path,
    expected_notice_id: &FilesystemModeMigrationNoticeId,
) -> io::Result<()> {
    prepare_acknowledgement_with_home(home, expected_notice_id)?.commit()
}

#[cfg(all(test, unix))]
mod tests {
    use super::*;
    use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _};

    #[test]
    fn every_custom_xdg_home_is_refused_while_unset_or_empty_is_default() {
        assert!(require_default_xdg_homes_with(|_| None).is_ok());
        assert!(require_default_xdg_homes_with(|_| Some(std::ffi::OsString::new())).is_ok());
        for selected in ["XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"] {
            let error = require_default_xdg_homes_with(|name| {
                (name == selected).then(|| std::ffi::OsString::from("/synthetic/custom"))
            })
            .unwrap_err();
            assert_eq!(error.kind(), io::ErrorKind::PermissionDenied);
            assert!(error.to_string().contains(selected));
        }
        assert!(require_default_xdg_homes_with(|_| {
            Some(std::ffi::OsString::from("/synthetic/custom"))
        })
        .is_err());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn production_probe_apply_and_ack_reject_custom_xdg_without_mutation() {
        const CHILD: &str = "HYDRA_AUTHORITY_CUSTOM_XDG_CHILD";
        const FIXTURE: &str = "HYDRA_AUTHORITY_CUSTOM_XDG_FIXTURE";
        const SENTINEL: &str = "HYDRA_AUTHORITY_CUSTOM_XDG_SENTINEL";
        if std::env::var_os(CHILD).is_some() {
            let custom = PathBuf::from(std::env::var_os(FIXTURE).unwrap());
            assert!(["XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"]
                .iter()
                .any(|name| std::env::var_os(name).as_deref() == Some(custom.as_os_str())));
            assert!(probe(|_, _| panic!("custom XDG must fail before service proof")).is_err());
            let notice_id = FilesystemModeMigrationNoticeId::new("a".repeat(64)).unwrap();
            let failure = apply(&notice_id, |_, _| {
                panic!("custom XDG must fail before apply service proof")
            })
            .unwrap_err();
            assert!(failure.notice().is_none());
            assert!(prepare_acknowledgement(&notice_id, |_, _| {
                panic!("custom XDG must fail before acknowledgement service proof")
            })
            .is_err());
            use std::os::unix::fs::OpenOptionsExt as _;
            let sentinel = PathBuf::from(std::env::var_os(SENTINEL).unwrap());
            let mut file = std::fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .mode(0o600)
                .open(&sentinel)
                .unwrap();
            file.write_all(b"custom-xdg-production-gates-ran\n")
                .unwrap();
            file.sync_all().unwrap();
            return;
        }

        let fixture =
            crate::agent_dir::secure_authority_test_dir("hydra-authority-custom-xdg-production-");
        let custom = fixture.path().join("custom-data/hydra-agent");
        std::fs::create_dir_all(&custom).unwrap();
        for path in [fixture.path().join("custom-data"), custom.clone()] {
            std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o775)).unwrap();
        }
        let before = [fixture.path().join("custom-data"), custom.clone()].map(|path| {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            (
                metadata.dev(),
                metadata.ino(),
                metadata.permissions().mode() & 0o7777,
            )
        });
        for mask in 1u8..8 {
            let sentinel = fixture.path().join(format!("custom-xdg-child-{mask}.txt"));
            let mut child = std::process::Command::new(std::env::current_exe().unwrap());
            child
                .arg("--exact")
                .arg("authority_migration::tests::production_probe_apply_and_ack_reject_custom_xdg_without_mutation")
                .arg("--nocapture")
                .env(CHILD, "1")
                .env(FIXTURE, &custom)
                .env(SENTINEL, &sentinel);
            for (bit, name) in ["XDG_DATA_HOME", "XDG_CONFIG_HOME", "XDG_STATE_HOME"]
                .iter()
                .enumerate()
            {
                child.env_remove(name);
                if mask & (1 << bit) != 0 {
                    child.env(name, &custom);
                }
            }
            assert!(child.status().unwrap().success());
            assert_eq!(
                std::fs::read(&sentinel).unwrap(),
                b"custom-xdg-production-gates-ran\n"
            );
        }
        let after = [fixture.path().join("custom-data"), custom].map(|path| {
            let metadata = std::fs::symlink_metadata(path).unwrap();
            (
                metadata.dev(),
                metadata.ino(),
                metadata.permissions().mode() & 0o7777,
            )
        });
        assert_eq!(after, before);
    }

    fn fixture(mode: u32) -> (tempfile::TempDir, PathBuf, [PathBuf; FIXED_PATH_COUNT]) {
        let handle = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(handle.path()).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let specs = fixed_paths(&home);
        let paths = specs.clone().map(|(path, _)| path);
        for (path, kind) in &specs {
            if *kind != ReceiptPathKind::ServiceFile {
                std::fs::create_dir_all(path).unwrap();
            }
        }
        std::fs::write(
            &paths[SERVICE_FILE_INDEX],
            b"synthetic exact service bytes\n",
        )
        .unwrap();
        for (index, path) in paths.iter().enumerate() {
            let fixture_mode = if index == SERVICE_FILE_INDEX {
                match mode {
                    0o770 => 0o660,
                    0o775 => 0o664,
                    other => other,
                }
            } else {
                mode
            };
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(fixture_mode)).unwrap();
        }
        (handle, home, paths)
    }

    fn modes(paths: &[PathBuf; FIXED_PATH_COUNT]) -> [u32; FIXED_PATH_COUNT] {
        std::array::from_fn(|index| {
            std::fs::symlink_metadata(&paths[index])
                .unwrap()
                .permissions()
                .mode()
                & 0o7777
        })
    }

    fn legacy_modes(mode: u32) -> [u32; FIXED_PATH_COUNT] {
        std::array::from_fn(|index| {
            if index == SERVICE_FILE_INDEX {
                match mode {
                    0o770 => 0o660,
                    0o775 => 0o664,
                    other => other,
                }
            } else {
                mode
            }
        })
    }

    fn applied_modes(mode: u32) -> [u32; FIXED_PATH_COUNT] {
        let legacy = legacy_modes(mode);
        let specs = fixed_paths(Path::new("/synthetic"));
        std::array::from_fn(|index| target_mode(specs[index].1, legacy[index]).unwrap())
    }

    #[test]
    fn safe_closed_desktop_without_service_has_no_legacy_migration() {
        let (_handle, home, paths) = fixture(0o775);
        for (index, path) in paths.iter().enumerate() {
            if index == SERVICE_FILE_INDEX {
                continue;
            }
            std::fs::set_permissions(
                path,
                std::fs::Permissions::from_mode(applied_modes(0o775)[index]),
            )
            .unwrap();
        }
        std::fs::remove_file(&paths[SERVICE_FILE_INDEX]).unwrap();

        assert_eq!(probe_with_home(&home).unwrap(), None);
        assert!(!receipt_path(&home).exists());
    }

    #[test]
    fn fresh_private_authority_without_optional_service_ancestry_has_no_migration() {
        let handle = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(handle.path()).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        let paths = fixed_paths(&home).map(|(path, _)| path);
        std::fs::create_dir_all(&paths[AUTHORITY_LEAF_INDEX]).unwrap();
        for path in [&paths[0], &paths[1], &paths[AUTHORITY_LEAF_INDEX]] {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
        }

        assert_eq!(probe_with_home(&home).unwrap(), None);
        assert!(!receipt_path(&home).exists());
    }

    #[test]
    fn missing_service_never_bypasses_legacy_writable_modes() {
        let (_handle, home, paths) = fixture(0o775);
        let before = modes(&paths);
        std::fs::remove_file(&paths[SERVICE_FILE_INDEX]).unwrap();

        assert!(probe_with_home(&home).is_err());
        for (index, path) in paths.iter().enumerate() {
            if index != SERVICE_FILE_INDEX {
                assert_eq!(
                    std::fs::symlink_metadata(path)
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o7777,
                    before[index]
                );
            }
        }
        assert!(!receipt_path(&home).exists());
    }

    #[test]
    fn probe_is_read_only_and_ready_notice_lists_the_exact_ten_path_closure() {
        for legacy in [0o770, 0o775] {
            let (_handle, home, paths) = fixture(legacy);
            let before = paths.each_ref().map(|path| {
                let metadata = std::fs::symlink_metadata(path).unwrap();
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.permissions().mode() & 0o7777,
                )
            });

            let notice = probe_with_home(&home).unwrap().unwrap();

            assert_eq!(notice.phase(), FilesystemModeMigrationPhase::ReadyToApply);
            assert_eq!(notice.recovery_record_path(), None);
            assert_eq!(notice.changes().len(), FIXED_PATH_COUNT);
            assert_eq!(
                notice
                    .changes()
                    .iter()
                    .map(FilesystemModeChange::path)
                    .collect::<Vec<_>>(),
                paths
                    .iter()
                    .map(|path| path.to_str().unwrap())
                    .collect::<Vec<_>>()
            );
            assert!(!receipt_path(&home).exists());
            let after = paths.each_ref().map(|path| {
                let metadata = std::fs::symlink_metadata(path).unwrap();
                (
                    metadata.dev(),
                    metadata.ino(),
                    metadata.permissions().mode() & 0o7777,
                )
            });
            assert_eq!(
                after, before,
                "status probe must not mutate any mode or inode"
            );
        }
    }

    #[test]
    fn legacy_service_provenance_is_required_before_ready_or_receipt_creation() {
        let (_handle, home, paths) = fixture(0o775);
        let before = modes(&paths);
        let denied = |_home: &Path, _leaf: &Path| {
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic service is not the published 0.2.8 generation",
            ))
        };

        assert!(probe_with_home_and_provenance(&home, denied).is_err());
        assert_eq!(modes(&paths), before);
        assert!(!receipt_path(&home).exists());

        let ready = probe_with_home_and_provenance(&home, |_, _| Ok(()))
            .unwrap()
            .unwrap();
        let failure =
            apply_with_home_and_hook_and_provenance(&home, ready.notice_id(), denied, |_| Ok(()))
                .unwrap_err();
        assert!(failure.notice().is_none());
        assert_eq!(modes(&paths), before);
        assert!(!receipt_path(&home).exists());
    }

    #[test]
    fn apply_is_parents_first_crash_recoverable_and_ack_is_exact() {
        let (_handle, home, paths) = fixture(0o775);
        let ready = probe_with_home(&home).unwrap().unwrap();
        let expected = ready.notice_id().clone();
        let failure = apply_with_home_and_hook(&home, &expected, |index| {
            (index != 0)
                .then_some(())
                .ok_or_else(|| io::Error::other("synthetic crash"))
        })
        .unwrap_err();
        let interrupted = failure
            .notice()
            .expect("durable receipt returns interruption");
        assert_eq!(
            interrupted.phase(),
            FilesystemModeMigrationPhase::Interrupted
        );
        let mut interrupted_modes = legacy_modes(0o775);
        interrupted_modes[0] = 0o755;
        assert_eq!(modes(&paths), interrupted_modes);
        assert_eq!(
            interrupted.recovery_record_path(),
            Some(receipt_path(&home).to_str().unwrap())
        );
        assert_eq!(
            probe_with_home(&home).unwrap().unwrap().phase(),
            FilesystemModeMigrationPhase::Interrupted
        );

        let applied = apply_with_home_and_hook(&home, &expected, |_| Ok(())).unwrap();
        assert_eq!(applied.phase(), FilesystemModeMigrationPhase::Applied);
        assert_eq!(modes(&paths), applied_modes(0o775));
        assert!(receipt_path(&home).exists());

        let wrong = FilesystemModeMigrationNoticeId::new("f".repeat(64)).unwrap();
        assert!(acknowledge_with_home(&home, &wrong).is_err());
        assert!(receipt_path(&home).exists());
        let prepared = prepare_acknowledgement_with_home(&home, &expected).unwrap();
        assert!(
            receipt_path(&home).exists(),
            "validation/status work must leave the receipt intact until commit"
        );
        drop(prepared);
        assert!(receipt_path(&home).exists());
        prepare_acknowledgement_with_home(&home, &expected)
            .unwrap()
            .commit()
            .unwrap();
        assert!(!receipt_path(&home).exists());
        assert!(probe_with_home(&home).unwrap().is_none());
    }

    #[test]
    fn acknowledgement_commit_precedes_service_lifecycle_and_both_failure_sides_are_recoverable() {
        let (_handle, home, paths) = fixture(0o775);
        let ready = probe_with_home(&home).unwrap().unwrap();
        apply_with_home_and_hook(&home, ready.notice_id(), |_| Ok(())).unwrap();
        let expected_modes = applied_modes(0o775);

        let prepared = prepare_acknowledgement_with_home(&home, ready.notice_id()).unwrap();
        let lifecycle_ran = std::cell::Cell::new(false);
        let boundary_result: io::Result<Result<(), io::Error>> = prepared.commit_then(|| {
            lifecycle_ran.set(true);
            assert!(!receipt_path(&home).exists());
            Err(io::Error::other(
                "synthetic crash before service convergence",
            ))
        });
        assert!(boundary_result.unwrap().is_err());
        assert!(lifecycle_ran.get());
        assert!(!receipt_path(&home).exists());
        assert_eq!(modes(&paths), expected_modes);
        assert!(probe_with_home(&home).unwrap().is_none());

        let (_handle, home, paths) = fixture(0o775);
        let ready = probe_with_home(&home).unwrap().unwrap();
        apply_with_home_and_hook(&home, ready.notice_id(), |_| Ok(())).unwrap();
        let prepared = prepare_acknowledgement_with_home(&home, ready.notice_id()).unwrap();
        std::fs::set_permissions(receipt_path(&home), std::fs::Permissions::from_mode(0o640))
            .unwrap();
        let lifecycle_ran = std::cell::Cell::new(false);
        assert!(prepared.commit_then(|| lifecycle_ran.set(true)).is_err());
        assert!(!lifecycle_ran.get());
        assert!(receipt_path(&home).exists());
        assert_eq!(modes(&paths), applied_modes(0o775));
        std::fs::set_permissions(receipt_path(&home), std::fs::Permissions::from_mode(0o600))
            .unwrap();
        prepare_acknowledgement_with_home(&home, ready.notice_id())
            .unwrap()
            .commit()
            .unwrap();
        assert!(!receipt_path(&home).exists());
    }

    #[test]
    fn acknowledgement_rechecks_live_service_provenance_while_receipt_is_locked() {
        let (_handle, home, paths) = fixture(0o775);
        let ready = probe_with_home(&home).unwrap().unwrap();
        apply_with_home_and_hook(&home, ready.notice_id(), |_| Ok(())).unwrap();
        let before = modes(&paths);
        let calls = std::cell::Cell::new(0usize);

        let denied =
            prepare_acknowledgement_with_home_and_provenance(&home, ready.notice_id(), |_, _| {
                calls.set(calls.get() + 1);
                Err(io::Error::new(
                    io::ErrorKind::PermissionDenied,
                    "synthetic manager FragmentPath changed",
                ))
            });
        assert!(denied.is_err());
        assert_eq!(calls.get(), 1);
        assert!(receipt_path(&home).exists());
        assert_eq!(modes(&paths), before);

        prepare_acknowledgement_with_home_and_provenance(&home, ready.notice_id(), |_, _| Ok(()))
            .unwrap()
            .commit()
            .unwrap();
        assert!(!receipt_path(&home).exists());
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn unpublished_atomic_receipt_failure_never_exposes_the_final_name() {
        let (_handle, home, paths) = fixture(0o775);
        let plan = discover_plan(&home).unwrap().unwrap();
        let before = modes(&paths);
        let error = match create_receipt_with_before_publish(&home, plan, |_| {
            Err(io::Error::other("synthetic crash before publication"))
        }) {
            Ok(_) => panic!("unpublished receipt unexpectedly succeeded"),
            Err(error) => error,
        };

        assert_eq!(error.kind(), io::ErrorKind::Other);
        assert!(!receipt_path(&home).exists());
        assert_eq!(modes(&paths), before);
        assert_eq!(
            probe_with_home(&home).unwrap().unwrap().phase(),
            FilesystemModeMigrationPhase::ReadyToApply
        );
    }

    #[test]
    fn receipt_is_exact_0600_single_link_canonical_and_replacement_fails_closed() {
        use std::os::unix::fs::symlink;

        let (_handle, home, paths) = fixture(0o770);
        let ready = probe_with_home(&home).unwrap().unwrap();
        let _ = apply_with_home_and_hook(&home, ready.notice_id(), |index| {
            (index != 0)
                .then_some(())
                .ok_or_else(|| io::Error::other("synthetic crash"))
        });
        let receipt = receipt_path(&home);
        let metadata = std::fs::symlink_metadata(&receipt).unwrap();
        assert_eq!(metadata.permissions().mode() & 0o7777, 0o600);
        assert_eq!(metadata.nlink(), 1);

        let bytes = std::fs::read(&receipt).unwrap();
        let parsed: Receipt = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(bytes, serde_json::to_vec(&parsed).unwrap());
        assert_eq!(parsed.schema, RECEIPT_SCHEMA);
        assert_eq!(parsed.entries.len(), FIXED_PATH_COUNT);
        for (entry, (path, kind)) in parsed.entries.iter().zip(fixed_paths(&home)) {
            assert_eq!(entry.path, path.to_str().unwrap());
            assert_eq!(entry.kind, kind);
            if kind == ReceiptPathKind::ServiceFile {
                let service_bytes = std::fs::read(&path).unwrap();
                assert_eq!(entry.byte_len, Some(service_bytes.len() as u64));
                assert_eq!(
                    entry.sha256.as_deref(),
                    Some(sha256_hex(&service_bytes).as_str())
                );
            } else {
                assert_eq!(entry.byte_len, None);
                assert_eq!(entry.sha256, None);
            }
        }

        let extra_link = home.join("receipt-hardlink");
        std::fs::hard_link(&receipt, &extra_link).unwrap();
        assert!(
            probe_with_home(&home).is_err(),
            "multi-link receipt must fail closed"
        );
        std::fs::remove_file(&extra_link).unwrap();
        assert!(probe_with_home(&home).is_ok());

        let replacement = home.join("replacement.json");
        std::fs::write(&replacement, &bytes).unwrap();
        std::fs::set_permissions(&replacement, std::fs::Permissions::from_mode(0o600)).unwrap();
        std::fs::remove_file(&receipt).unwrap();
        std::fs::rename(&replacement, &receipt).unwrap();
        assert!(
            probe_with_home(&home).is_err(),
            "inode replacement must fail closed"
        );

        std::fs::remove_file(&receipt).unwrap();
        symlink(&paths[0], &receipt).unwrap();
        assert!(
            probe_with_home(&home).is_err(),
            "symlink receipt must fail closed"
        );
    }

    #[test]
    fn receipt_mode_is_exact_under_restrictive_and_permissive_umasks() {
        const CHILD: &str = "HYDRA_AUTHORITY_RECEIPT_UMASK_CHILD";
        if std::env::var_os(CHILD).is_some() {
            for mask in [0o777, 0o077, 0o002] {
                let (_handle, home, _paths) = fixture(0o775);
                let ready = probe_with_home(&home).unwrap().unwrap();
                let previous = unsafe { libc::umask(mask) };
                let applied = apply_with_home_and_hook(&home, ready.notice_id(), |_| Ok(()));
                unsafe { libc::umask(previous) };
                applied.unwrap();
                assert_eq!(
                    std::fs::symlink_metadata(receipt_path(&home))
                        .unwrap()
                        .permissions()
                        .mode()
                        & 0o7777,
                    0o600
                );
            }
            return;
        }
        let status = std::process::Command::new(std::env::current_exe().unwrap())
            .arg("--exact")
            .arg("authority_migration::tests::receipt_mode_is_exact_under_restrictive_and_permissive_umasks")
            .arg("--nocapture")
            .env(CHILD, "1")
            .status()
            .unwrap();
        assert!(status.success());
    }

    #[test]
    fn published_028_ambient_umask_shapes_migrate_all_ten_paths_without_replacement_or_data_loss() {
        const CHILD: &str = "HYDRA_AUTHORITY_028_WRITER_CHILD";
        const MASK: &str = "HYDRA_AUTHORITY_028_WRITER_UMASK";
        if let Some(mask) = std::env::var_os(MASK) {
            let mask = u32::from_str_radix(mask.to_str().unwrap(), 8).unwrap();
            unsafe { libc::umask(mask as libc::mode_t) };
            let handle = tempfile::tempdir().unwrap();
            let home = std::fs::canonicalize(handle.path()).unwrap();
            std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
            let paths = fixed_paths(&home).map(|(path, _)| path);

            // Reproduce the published 0.2.8 creation primitives: recursive default-mode
            // directories plus File::create for the systemd unit, all shaped by ambient umask.
            std::fs::create_dir_all(&paths[AUTHORITY_LEAF_INDEX]).unwrap();
            std::fs::create_dir_all(paths[SERVICE_FILE_INDEX].parent().unwrap()).unwrap();
            let mut unit = File::create(&paths[SERVICE_FILE_INDEX]).unwrap();
            unit.write_all(b"published 0.2.8 synthetic service\n")
                .unwrap();
            unit.sync_all().unwrap();
            drop(unit);
            std::fs::create_dir_all(&paths[FIXED_PATH_COUNT - 1]).unwrap();

            let legacy_directory_mode = 0o777 & !mask;
            let legacy_file_mode = 0o666 & !mask;
            assert_eq!(modes(&paths), legacy_modes(legacy_directory_mode));
            assert_eq!(modes(&paths)[SERVICE_FILE_INDEX], legacy_file_mode);

            let before = paths.each_ref().map(|path| {
                let metadata = std::fs::symlink_metadata(path).unwrap();
                (metadata.dev(), metadata.ino())
            });
            let mut sentinels = Vec::new();
            for (index, (path, kind)) in fixed_paths(&home).iter().enumerate() {
                if *kind == ReceiptPathKind::ServiceFile {
                    continue;
                }
                let sentinel = path.join(format!("migration-sentinel-{index}"));
                let bytes = format!("sentinel-{index}-{mask:o}\n").into_bytes();
                let mut options = std::fs::OpenOptions::new();
                options.write(true).create_new(true).mode(0o600);
                let mut file = options.open(&sentinel).unwrap();
                file.write_all(&bytes).unwrap();
                file.sync_all().unwrap();
                sentinels.push((sentinel, bytes));
            }
            let service_bytes = std::fs::read(&paths[SERVICE_FILE_INDEX]).unwrap();

            let ready = probe_with_home(&home).unwrap().unwrap();
            assert_eq!(ready.changes().len(), FIXED_PATH_COUNT);
            let applied = apply_with_home_and_hook(&home, ready.notice_id(), |_| Ok(())).unwrap();
            assert_eq!(applied.phase(), FilesystemModeMigrationPhase::Applied);
            assert_eq!(modes(&paths), applied_modes(legacy_directory_mode));
            let after = paths.each_ref().map(|path| {
                let metadata = std::fs::symlink_metadata(path).unwrap();
                (metadata.dev(), metadata.ino())
            });
            assert_eq!(after, before);
            assert_eq!(
                std::fs::read(&paths[SERVICE_FILE_INDEX]).unwrap(),
                service_bytes
            );
            for (sentinel, bytes) in sentinels {
                assert_eq!(std::fs::read(sentinel).unwrap(), bytes);
            }
            prepare_acknowledgement_with_home(&home, ready.notice_id())
                .unwrap()
                .commit()
                .unwrap();
            assert!(!receipt_path(&home).exists());
            return;
        }

        assert!(std::env::var_os(CHILD).is_none());
        for mask in ["002", "007"] {
            let status = std::process::Command::new(std::env::current_exe().unwrap())
                .arg("--exact")
                .arg("authority_migration::tests::published_028_ambient_umask_shapes_migrate_all_ten_paths_without_replacement_or_data_loss")
                .arg("--nocapture")
                .env(CHILD, "1")
                .env(MASK, mask)
                .status()
                .unwrap();
            assert!(
                status.success(),
                "0.2.8 umask {mask} migration proof failed"
            );
        }
    }

    #[test]
    fn unsupported_or_custom_shapes_never_mutate() {
        for mode in [0o760, 0o777] {
            let (_handle, home, paths) = fixture(mode);
            assert!(probe_with_home(&home).is_err());
            assert_eq!(modes(&paths), legacy_modes(mode));
            assert!(!receipt_path(&home).exists());
        }

        let (_handle, home, paths) = fixture(0o775);
        std::fs::set_permissions(&paths[2], std::fs::Permissions::from_mode(0o700)).unwrap();
        let notice = probe_with_home(&home).unwrap().unwrap();
        assert_eq!(notice.changes().len(), FIXED_PATH_COUNT - 1);
        assert_eq!(modes(&paths)[AUTHORITY_LEAF_INDEX], 0o700);
        assert!(!receipt_path(&home).exists());
    }

    #[test]
    fn wrong_owner_and_each_world_writable_component_fail_without_mutation() {
        let (_handle, home, paths) = fixture(0o775);
        let before = modes(&paths);
        assert!(
            discover_plan_for_uid(&home, crate::agent_dir::trusted_uid().wrapping_add(1)).is_err()
        );
        assert_eq!(modes(&paths), before);
        assert!(!receipt_path(&home).exists());

        for changed_index in 0..FIXED_PATH_COUNT {
            let (_handle, home, paths) = fixture(0o775);
            std::fs::set_permissions(
                &paths[changed_index],
                std::fs::Permissions::from_mode(0o777),
            )
            .unwrap();
            let before = modes(&paths);
            assert!(probe_with_home(&home).is_err());
            assert_eq!(modes(&paths), before);
            assert!(!receipt_path(&home).exists());
        }
    }

    #[test]
    fn bound_directory_inode_replacement_after_receipt_fails_closed() {
        let (_handle, home, paths) = fixture(0o775);
        let plan = discover_plan(&home).unwrap().unwrap();
        drop(create_receipt(&home, plan).unwrap());
        let displaced = home.join("displaced-authority-leaf");
        std::fs::rename(&paths[2], &displaced).unwrap();
        std::fs::create_dir(&paths[2]).unwrap();
        std::fs::set_permissions(&paths[2], std::fs::Permissions::from_mode(0o775)).unwrap();

        assert!(probe_with_home(&home).is_err());
        assert!(receipt_path(&home).exists());
        assert_eq!(
            std::fs::symlink_metadata(&displaced)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o775
        );
        assert_eq!(modes(&paths), legacy_modes(0o775));
    }

    #[test]
    fn bound_service_bytes_inode_and_link_count_cannot_change_after_receipt() {
        for mutation in ["bytes", "inode", "hardlink"] {
            let (_handle, home, paths) = fixture(0o775);
            let plan = discover_plan(&home).unwrap().unwrap();
            let notice_id =
                FilesystemModeMigrationNoticeId::new(plan_notice_id(&plan).unwrap()).unwrap();
            drop(create_receipt(&home, plan).unwrap());
            let unit = &paths[SERVICE_FILE_INDEX];
            let before_modes = modes(&paths);
            let before = std::fs::symlink_metadata(unit).unwrap();
            let extra = home.join(format!("service-{mutation}-outside"));

            match mutation {
                "bytes" => {
                    let mut bytes = std::fs::read(unit).unwrap();
                    bytes[0] ^= 0x20;
                    std::fs::write(unit, bytes).unwrap();
                    let after = std::fs::symlink_metadata(unit).unwrap();
                    assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
                }
                "inode" => {
                    let bytes = std::fs::read(unit).unwrap();
                    std::fs::rename(unit, &extra).unwrap();
                    std::fs::write(unit, bytes).unwrap();
                    std::fs::set_permissions(unit, std::fs::Permissions::from_mode(0o664)).unwrap();
                    let after = std::fs::symlink_metadata(unit).unwrap();
                    assert_ne!((after.dev(), after.ino()), (before.dev(), before.ino()));
                }
                "hardlink" => std::fs::hard_link(unit, &extra).unwrap(),
                _ => unreachable!(),
            }

            assert!(
                probe_with_home(&home).is_err(),
                "{mutation} must fail probe"
            );
            let failure = apply_with_home_and_hook(&home, &notice_id, |_| Ok(())).unwrap_err();
            assert!(failure.notice().is_some());
            assert_eq!(
                modes(&paths),
                before_modes,
                "{mutation} must not chmod anything"
            );
            assert!(receipt_path(&home).exists());
        }
    }

    #[test]
    fn interrupted_retry_rechecks_service_provenance_before_another_chmod() {
        let (_handle, home, paths) = fixture(0o775);
        let ready = probe_with_home(&home).unwrap().unwrap();
        let failure = apply_with_home_and_hook(&home, ready.notice_id(), |index| {
            (index != 0)
                .then_some(())
                .ok_or_else(|| io::Error::other("synthetic crash"))
        })
        .unwrap_err();
        assert!(failure.notice().is_some());
        let interrupted_modes = modes(&paths);
        let calls = std::cell::Cell::new(0usize);
        let denied = |_: &Path, _: &Path| {
            calls.set(calls.get() + 1);
            Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "synthetic FragmentPath mismatch",
            ))
        };

        let retry =
            apply_with_home_and_hook_and_provenance(&home, ready.notice_id(), denied, |_| {
                panic!("no chmod hook may run after failed provenance")
            })
            .unwrap_err();
        assert!(retry.notice().is_some());
        assert_eq!(calls.get(), 1);
        assert_eq!(modes(&paths), interrupted_modes);
        assert!(receipt_path(&home).exists());
    }

    #[test]
    fn special_mode_bits_on_any_fixed_path_are_rejected_without_mutation() {
        for special_mode in [0o1775, 0o2775, 0o6770] {
            for changed_index in 0..FIXED_PATH_COUNT {
                let (_handle, home, paths) = fixture(0o775);
                std::fs::set_permissions(
                    &paths[changed_index],
                    std::fs::Permissions::from_mode(special_mode),
                )
                .unwrap();
                let before = modes(&paths);

                assert!(probe_with_home(&home).is_err());
                assert_eq!(modes(&paths), before);
                assert!(!receipt_path(&home).exists());
            }
        }
    }

    #[test]
    fn sticky_group_writable_home_is_not_a_receipt_anchor_and_nothing_changes() {
        let (_handle, home, paths) = fixture(0o775);
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o1770)).unwrap();
        let before = modes(&paths);
        assert!(probe_with_home(&home).is_err());
        assert_eq!(modes(&paths), before);
        assert_eq!(
            std::fs::symlink_metadata(&home)
                .unwrap()
                .permissions()
                .mode()
                & 0o7777,
            0o1770
        );
        assert!(!receipt_path(&home).exists());
    }

    #[test]
    fn symlink_substitution_of_each_fixed_path_is_rejected_without_target_mutation() {
        use std::os::unix::fs::symlink;

        for changed_index in 0..FIXED_PATH_COUNT {
            let (_handle, home, paths) = fixture(0o775);
            let path = &paths[changed_index];
            let displaced = home.join(format!("outside-symlink-{changed_index}"));
            std::fs::rename(path, &displaced).unwrap();
            let outside = std::fs::symlink_metadata(&displaced).unwrap();
            let outside_mode = outside.permissions().mode() & 0o7777;
            symlink(&displaced, path).unwrap();

            assert!(probe_with_home(&home).is_err());
            assert!(!receipt_path(&home).exists());
            let after = std::fs::symlink_metadata(&displaced).unwrap();
            assert_eq!((after.dev(), after.ino()), (outside.dev(), outside.ino()));
            assert_eq!(after.permissions().mode() & 0o7777, outside_mode);
        }
    }

    #[test]
    fn wrong_type_at_each_fixed_path_and_service_hardlink_are_rejected() {
        for changed_index in 0..FIXED_PATH_COUNT {
            let (_handle, home, paths) = fixture(0o775);
            let path = &paths[changed_index];
            let displaced = home.join(format!("outside-type-{changed_index}"));
            std::fs::rename(path, &displaced).unwrap();
            if changed_index == SERVICE_FILE_INDEX {
                std::fs::create_dir(path).unwrap();
            } else {
                std::fs::write(path, b"not a directory\n").unwrap();
                std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o664)).unwrap();
            }
            let before = std::fs::symlink_metadata(&displaced).unwrap();

            assert!(probe_with_home(&home).is_err());
            assert!(!receipt_path(&home).exists());
            let after = std::fs::symlink_metadata(&displaced).unwrap();
            assert_eq!((after.dev(), after.ino()), (before.dev(), before.ino()));
            assert_eq!(after.permissions().mode(), before.permissions().mode());
        }

        let (_handle, home, paths) = fixture(0o775);
        let link = home.join("second-unit-link");
        std::fs::hard_link(&paths[SERVICE_FILE_INDEX], &link).unwrap();
        let before = modes(&paths);
        assert!(probe_with_home(&home).is_err());
        assert_eq!(modes(&paths), before);
        assert!(!receipt_path(&home).exists());
    }

    #[test]
    fn safe_or_absent_leaf_needs_no_notice() {
        let handle = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(handle.path()).unwrap();
        std::fs::set_permissions(&home, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(probe_with_home(&home).unwrap().is_none());

        let paths = fixed_paths(&home).map(|(path, _)| path);
        for (path, kind) in fixed_paths(&home) {
            if kind != ReceiptPathKind::ServiceFile {
                std::fs::create_dir_all(path).unwrap();
            }
        }
        std::fs::write(
            &paths[SERVICE_FILE_INDEX],
            b"synthetic exact service bytes\n",
        )
        .unwrap();
        let safe_modes = [
            0o755, 0o750, 0o700, 0o755, 0o755, 0o755, 0o644, 0o755, 0o700, 0o700,
        ];
        for (path, mode) in paths.iter().zip(safe_modes) {
            std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
        }
        assert!(probe_with_home(&home).unwrap().is_none());
    }
}
