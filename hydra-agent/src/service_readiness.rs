//! On-demand, local readiness handshake for the installed Hydra agent service.
//!
//! The desktop CLI writes a metadata-only request. The manager-owned supervisor
//! answers once, only while its exact remote-peer child and daemon socket are
//! usable. This avoids a permanent heartbeat, polling timer, or 2Hz disk writes.

use serde::{de::DeserializeOwned, Deserialize, Serialize};
use std::fs::{self, OpenOptions};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

pub const SERVICE_READINESS_FILE: &str = "service-ready.json";
pub const SERVICE_READINESS_REQUEST_FILE: &str = "service-ready-request.json";
pub const SERVICE_READINESS_SCHEMA: &str = "hydra.agent.service_readiness";
pub const SERVICE_READINESS_REQUEST_SCHEMA: &str = "hydra.agent.service_readiness_request";
pub const SERVICE_READINESS_SCHEMA_VERSION: u32 = 3;
pub const REQUIRED_PROGRESS_OBSERVATIONS: u8 = 3;

static SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReadinessRequest {
    pub schema: String,
    pub schema_version: u32,
    pub request_id: String,
    pub expected_supervisor_pid: u32,
    pub socket_path: PathBuf,
    pub build_stamp: String,
    pub binding_stamp: String,
    pub requested_at_ms: u64,
}

impl ServiceReadinessRequest {
    pub fn new(
        expected_supervisor_pid: u32,
        socket_path: PathBuf,
        build_stamp: String,
        binding_stamp: String,
        requested_at_ms: u64,
    ) -> Self {
        Self {
            schema: SERVICE_READINESS_REQUEST_SCHEMA.to_string(),
            schema_version: SERVICE_READINESS_SCHEMA_VERSION,
            request_id: format!(
                "{}-{requested_at_ms}-{}",
                std::process::id(),
                SEQUENCE.fetch_add(1, Ordering::Relaxed)
            ),
            expected_supervisor_pid,
            socket_path,
            build_stamp,
            binding_stamp,
            requested_at_ms,
        }
    }

    fn validate(&self) -> Result<(), ServiceReadinessError> {
        if self.schema != SERVICE_READINESS_REQUEST_SCHEMA {
            return Err(ServiceReadinessError::InvalidRecord("request.schema"));
        }
        validate_common(
            self.schema_version,
            &self.request_id,
            &self.socket_path,
            &self.build_stamp,
            &self.binding_stamp,
        )?;
        if self.expected_supervisor_pid == 0 {
            return Err(ServiceReadinessError::InvalidRecord(
                "request.expected_supervisor_pid",
            ));
        }
        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServiceReadinessRecord {
    pub schema: String,
    pub schema_version: u32,
    pub request_id: String,
    pub supervisor_pid: u32,
    pub peer_pid: u32,
    pub socket_path: PathBuf,
    pub build_stamp: String,
    pub binding_stamp: String,
    pub answered_at_ms: u64,
}

impl ServiceReadinessRecord {
    pub fn answer(
        request: &ServiceReadinessRequest,
        supervisor_pid: u32,
        peer_pid: u32,
        answered_at_ms: u64,
    ) -> Self {
        Self {
            schema: SERVICE_READINESS_SCHEMA.to_string(),
            schema_version: SERVICE_READINESS_SCHEMA_VERSION,
            request_id: request.request_id.clone(),
            supervisor_pid,
            peer_pid,
            socket_path: request.socket_path.clone(),
            build_stamp: request.build_stamp.clone(),
            binding_stamp: request.binding_stamp.clone(),
            answered_at_ms,
        }
    }

    fn validate(&self) -> Result<(), ServiceReadinessError> {
        if self.schema != SERVICE_READINESS_SCHEMA {
            return Err(ServiceReadinessError::InvalidRecord("record.schema"));
        }
        validate_common(
            self.schema_version,
            &self.request_id,
            &self.socket_path,
            &self.build_stamp,
            &self.binding_stamp,
        )?;
        if self.supervisor_pid == 0 || self.peer_pid == 0 {
            return Err(ServiceReadinessError::InvalidRecord("record.pid"));
        }
        Ok(())
    }
}

fn validate_common(
    schema_version: u32,
    request_id: &str,
    socket_path: &Path,
    build_stamp: &str,
    binding_stamp: &str,
) -> Result<(), ServiceReadinessError> {
    if schema_version != SERVICE_READINESS_SCHEMA_VERSION {
        return Err(ServiceReadinessError::InvalidRecord("schema_version"));
    }
    if request_id.is_empty() || request_id.len() > 160 {
        return Err(ServiceReadinessError::InvalidRecord("request_id"));
    }
    if socket_path.as_os_str().is_empty() {
        return Err(ServiceReadinessError::InvalidRecord("socket_path"));
    }
    if build_stamp.is_empty() {
        return Err(ServiceReadinessError::InvalidRecord("build_stamp"));
    }
    if binding_stamp.len() != 64
        || !binding_stamp
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ServiceReadinessError::InvalidRecord("binding_stamp"));
    }
    Ok(())
}

#[derive(Debug, thiserror::Error)]
pub enum ServiceReadinessError {
    #[error("service readiness I/O failed: {0}")]
    Io(#[from] io::Error),
    #[error("service readiness JSON failed: {0}")]
    Json(#[from] serde_json::Error),
    #[error("invalid service readiness field: {0}")]
    InvalidRecord(&'static str),
    #[error("conflicting service readiness handshake: {0}")]
    HandshakeConflict(&'static str),
}

struct ReadinessLock {
    #[cfg(unix)]
    file: fs::File,
}

impl ReadinessLock {
    fn acquire(agent_dir: &Path) -> Result<Self, ServiceReadinessError> {
        crate::agent_dir::ensure_owned_safe_authority_directory(agent_dir)?;
        #[cfg(unix)]
        {
            use std::os::fd::AsRawFd as _;
            use std::os::unix::fs::OpenOptionsExt as _;
            let file = OpenOptions::new()
                .create(true)
                .truncate(false)
                .read(true)
                .write(true)
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
                .open(agent_dir.join("service-readiness.lock"))?;
            validate_private_regular(&file, "service readiness lock", Some(0o600))?;
            // SAFETY: flock borrows the owned descriptor until Drop.
            if unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) } != 0 {
                return Err(io::Error::last_os_error().into());
            }
            Ok(Self { file })
        }
        #[cfg(not(unix))]
        Ok(Self {})
    }
}

#[cfg(unix)]
impl Drop for ReadinessLock {
    fn drop(&mut self) {
        use std::os::fd::AsRawFd as _;
        // SAFETY: this is the same live descriptor locked in acquire().
        unsafe {
            libc::flock(self.file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

pub fn service_readiness_path(agent_dir: &Path) -> PathBuf {
    agent_dir.join(SERVICE_READINESS_FILE)
}

pub fn service_readiness_request_path(agent_dir: &Path) -> PathBuf {
    agent_dir.join(SERVICE_READINESS_REQUEST_FILE)
}

fn atomic_json<T: Serialize>(path: &Path, value: &T) -> Result<(), ServiceReadinessError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    crate::agent_dir::ensure_owned_safe_authority_directory(dir)?;
    let temporary = dir.join(format!(
        ".service-readiness.tmp.{}.{}",
        std::process::id(),
        SEQUENCE.fetch_add(1, Ordering::Relaxed)
    ));
    let mut bytes = serde_json::to_vec(value)?;
    bytes.push(b'\n');
    let result = (|| -> Result<(), ServiceReadinessError> {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt as _;
            options
                .mode(0o600)
                .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
        }
        let _existing = open_existing_private(path, "service readiness record")?;
        let mut file = options.open(&temporary)?;
        validate_private_regular(&file, "temporary service readiness record", Some(0o600))?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        validate_private_regular(&file, "temporary service readiness record", Some(0o600))?;
        drop(file);
        fs::rename(&temporary, path)?;
        sync_directory(dir)?;
        let mut readback = open_existing_private(path, "service readiness record")?
            .ok_or_else(|| io::Error::other("service readiness record vanished after rename"))?;
        validate_private_regular(&readback, "service readiness record", Some(0o600))?;
        let mut actual = Vec::new();
        readback.read_to_end(&mut actual)?;
        if actual != bytes {
            return Err(io::Error::other("service readiness record readback differs").into());
        }
        Ok(())
    })();
    if result.is_err() {
        let _ = fs::remove_file(&temporary);
    }
    result
}

fn load_json<T: DeserializeOwned>(path: &Path) -> Result<Option<T>, ServiceReadinessError> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error.into()),
        Ok(_) => crate::agent_dir::require_owned_safe_directory(dir)?,
    }
    let Some(mut file) = open_existing_private(path, "service readiness record")? else {
        return Ok(None);
    };
    const MAX_READINESS_BYTES: u64 = 64 * 1024;
    if file.metadata()?.len() > MAX_READINESS_BYTES {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "service readiness record exceeds its byte bound",
        )
        .into());
    }
    let mut bytes = Vec::new();
    file.read_to_end(&mut bytes)?;
    Ok(Some(serde_json::from_slice(&bytes)?))
}

pub fn write_service_readiness_request(
    agent_dir: &Path,
    request: &ServiceReadinessRequest,
) -> Result<(), ServiceReadinessError> {
    request.validate()?;
    let _lock = ReadinessLock::acquire(agent_dir)?;
    atomic_json(&service_readiness_request_path(agent_dir), request)
}

/// Re-publish the caller's immutable request only when both sides of the
/// handshake are absent under one lock. A supervisor consumes the request
/// only after publishing its exact answer; that response must therefore win
/// over repair. Any different request or answer is a concurrent/foreign
/// handshake and fails closed instead of being overwritten.
pub fn restore_service_readiness_request_if_empty(
    agent_dir: &Path,
    request: &ServiceReadinessRequest,
) -> Result<bool, ServiceReadinessError> {
    request.validate()?;
    let _lock = ReadinessLock::acquire(agent_dir)?;
    let existing_request: Option<ServiceReadinessRequest> =
        load_json(&service_readiness_request_path(agent_dir))?;
    if let Some(existing_request) = existing_request.as_ref() {
        existing_request.validate()?;
        if existing_request != request {
            return Err(ServiceReadinessError::HandshakeConflict("request"));
        }
    }
    let existing_record: Option<ServiceReadinessRecord> =
        load_json(&service_readiness_path(agent_dir))?;
    if let Some(existing_record) = existing_record.as_ref() {
        existing_record.validate()?;
        if !matches_expected_service(existing_record, request, request.expected_supervisor_pid) {
            return Err(ServiceReadinessError::HandshakeConflict("response"));
        }
    }
    if existing_request.is_some() || existing_record.is_some() {
        return Ok(false);
    }
    atomic_json(&service_readiness_request_path(agent_dir), request)?;
    Ok(true)
}

pub fn load_service_readiness_request(
    agent_dir: &Path,
) -> Result<Option<ServiceReadinessRequest>, ServiceReadinessError> {
    let request: Option<ServiceReadinessRequest> =
        load_json(&service_readiness_request_path(agent_dir))?;
    if let Some(request) = request.as_ref() {
        request.validate()?;
    }
    Ok(request)
}

pub fn remove_service_readiness_request_if(
    agent_dir: &Path,
    request_id: &str,
) -> Result<(), ServiceReadinessError> {
    let _lock = ReadinessLock::acquire(agent_dir)?;
    let path = service_readiness_request_path(agent_dir);
    let current: Option<ServiceReadinessRequest> = load_json(&path)?;
    if current.as_ref().map(|value| value.request_id.as_str()) == Some(request_id) {
        remove_if_exists(&path)?;
    }
    Ok(())
}

pub fn write_service_readiness(
    agent_dir: &Path,
    record: &ServiceReadinessRecord,
) -> Result<(), ServiceReadinessError> {
    record.validate()?;
    let _lock = ReadinessLock::acquire(agent_dir)?;
    atomic_json(&service_readiness_path(agent_dir), record)
}

pub fn load_service_readiness(
    agent_dir: &Path,
) -> Result<Option<ServiceReadinessRecord>, ServiceReadinessError> {
    let record: Option<ServiceReadinessRecord> = load_json(&service_readiness_path(agent_dir))?;
    if let Some(record) = record.as_ref() {
        record.validate()?;
    }
    Ok(record)
}

/// Remove only evidence owned by `supervisor_pid`; an overlapping old process
/// can never erase a newer manager-owned supervisor's answer.
pub fn remove_service_readiness_if_supervisor(
    agent_dir: &Path,
    supervisor_pid: u32,
) -> Result<(), ServiceReadinessError> {
    let _lock = ReadinessLock::acquire(agent_dir)?;
    let path = service_readiness_path(agent_dir);
    let current: Option<ServiceReadinessRecord> = load_json(&path)?;
    if current.as_ref().map(|value| value.supervisor_pid) == Some(supervisor_pid) {
        remove_if_exists(&path)?;
    }
    Ok(())
}

pub fn remove_all_service_readiness(agent_dir: &Path) -> Result<(), ServiceReadinessError> {
    let _lock = ReadinessLock::acquire(agent_dir)?;
    remove_if_exists(&service_readiness_path(agent_dir))?;
    remove_if_exists(&service_readiness_request_path(agent_dir))?;
    Ok(())
}

fn remove_if_exists(path: &Path) -> io::Result<()> {
    let dir = path.parent().unwrap_or_else(|| Path::new("."));
    match fs::symlink_metadata(dir) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(error) => return Err(error),
        Ok(_) => crate::agent_dir::require_owned_safe_directory(dir)?,
    }
    let Some(file) = open_existing_private(path, "service readiness record")? else {
        return Ok(());
    };
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt as _;
        let opened = file.metadata()?;
        let named = fs::symlink_metadata(path)?;
        if opened.dev() != named.dev() || opened.ino() != named.ino() {
            return Err(io::Error::other(
                "service readiness record changed before removal",
            ));
        }
    }
    fs::remove_file(path)?;
    sync_directory(dir)?;
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::other(
            "service readiness record remained after removal",
        )),
    }
}

fn open_existing_private(path: &Path, label: &str) -> io::Result<Option<fs::File>> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        options.custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW);
    }
    let file = match options.open(path) {
        Ok(file) => file,
        Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(error) => return Err(error),
    };
    validate_private_regular(&file, label, None)?;
    Ok(Some(file))
}

fn validate_private_regular(
    file: &fs::File,
    label: &str,
    exact_mode: Option<u32>,
) -> io::Result<()> {
    let metadata = file.metadata()?;
    if !metadata.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            format!("{label} is not a regular file"),
        ));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let mode = metadata.permissions().mode() & 0o777;
        if metadata.uid() != crate::agent_dir::trusted_uid()
            || metadata.nlink() != 1
            || mode & 0o077 != 0
            || exact_mode.is_some_and(|expected| mode != expected)
        {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("{label} has unsafe metadata"),
            ));
        }
    }
    #[cfg(not(unix))]
    let _ = (label, exact_mode);
    Ok(())
}

fn sync_directory(path: &Path) -> io::Result<()> {
    fs::File::open(path)?.sync_all()
}

pub fn matches_expected_service(
    record: &ServiceReadinessRecord,
    request: &ServiceReadinessRequest,
    expected_supervisor_pid: u32,
) -> bool {
    record.validate().is_ok()
        && request.validate().is_ok()
        && request.expected_supervisor_pid == expected_supervisor_pid
        && record.request_id == request.request_id
        && record.supervisor_pid == expected_supervisor_pid
        && record.socket_path == request.socket_path
        && record.build_stamp == request.build_stamp
        && record.binding_stamp == request.binding_stamp
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ServiceReadinessProgress {
    request_id: Option<String>,
    supervisor_pid: Option<u32>,
    peer_pid: Option<u32>,
    observations: u8,
}

impl ServiceReadinessProgress {
    pub fn observe(
        &mut self,
        record: Option<&ServiceReadinessRecord>,
        request: &ServiceReadinessRequest,
        expected_supervisor_pid: u32,
        peer_and_daemon_live: bool,
    ) -> bool {
        let Some(record) = record.filter(|record| {
            peer_and_daemon_live
                && matches_expected_service(record, request, expected_supervisor_pid)
        }) else {
            self.reset();
            return false;
        };
        let same = self.request_id.as_deref() == Some(record.request_id.as_str())
            && self.supervisor_pid == Some(record.supervisor_pid)
            && self.peer_pid == Some(record.peer_pid);
        if same {
            self.observations = self
                .observations
                .saturating_add(1)
                .min(REQUIRED_PROGRESS_OBSERVATIONS);
        } else {
            self.request_id = Some(record.request_id.clone());
            self.supervisor_pid = Some(record.supervisor_pid);
            self.peer_pid = Some(record.peer_pid);
            self.observations = 1;
        }
        self.observations >= REQUIRED_PROGRESS_OBSERVATIONS
    }

    pub fn reset(&mut self) {
        *self = Self::default();
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_dir(label: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = std::fs::canonicalize("/tmp").unwrap().join(format!(
            "hydra-readiness-{label}-{}-{}",
            std::process::id(),
            SEQUENCE.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir(&dir).unwrap();
        std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700)).unwrap();
        dir
    }

    fn request() -> ServiceReadinessRequest {
        ServiceReadinessRequest::new(
            101,
            PathBuf::from("/run/user/1000/hydra.sock"),
            "git=test built=1".to_string(),
            "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".to_string(),
            1_000,
        )
    }

    #[test]
    fn foreign_manager_pid_never_qualifies() {
        let request = request();
        let record = ServiceReadinessRecord::answer(&request, 101, 202, 1_100);
        let mut progress = ServiceReadinessProgress::default();
        for _ in 0..4 {
            assert!(!progress.observe(Some(&record), &request, 999, true));
        }
    }

    #[test]
    fn exact_answer_requires_three_live_observations() {
        let request = request();
        let record = ServiceReadinessRecord::answer(&request, 101, 202, 1_100);
        let mut progress = ServiceReadinessProgress::default();
        assert!(!progress.observe(Some(&record), &request, 101, true));
        assert!(!progress.observe(Some(&record), &request, 101, true));
        assert!(progress.observe(Some(&record), &request, 101, true));
        assert!(!progress.observe(Some(&record), &request, 101, false));
    }

    #[test]
    fn stale_binding_stamp_never_qualifies() {
        let request = request();
        let mut stale_request = request.clone();
        stale_request.binding_stamp =
            "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789".to_string();
        let stale_record = ServiceReadinessRecord::answer(&stale_request, 101, 202, 1_100);
        let mut progress = ServiceReadinessProgress::default();
        for _ in 0..4 {
            assert!(!progress.observe(Some(&stale_record), &request, 101, true));
        }
    }

    #[test]
    fn binding_stamp_accepts_only_canonical_lowercase_sha256() {
        assert!(request().validate().is_ok());
        let mut uppercase = request();
        uppercase.binding_stamp = "A".repeat(64);
        assert!(matches!(
            uppercase.validate(),
            Err(ServiceReadinessError::InvalidRecord("binding_stamp"))
        ));
    }

    #[test]
    fn another_request_or_peer_resets_progress() {
        let first = request();
        let mut second = request();
        second.request_id.push_str("-next");
        let one = ServiceReadinessRecord::answer(&first, 101, 202, 1_100);
        let two = ServiceReadinessRecord::answer(&second, 101, 203, 1_200);
        let mut progress = ServiceReadinessProgress::default();
        assert!(!progress.observe(Some(&one), &first, 101, true));
        assert!(!progress.observe(Some(&one), &first, 101, true));
        assert!(!progress.observe(Some(&two), &second, 101, true));
    }

    #[test]
    fn request_response_roundtrip_and_owned_cleanup() {
        let dir = test_dir("roundtrip");
        let request = request();
        write_service_readiness_request(&dir, &request).unwrap();
        assert_eq!(
            load_service_readiness_request(&dir).unwrap(),
            Some(request.clone())
        );
        let record = ServiceReadinessRecord::answer(&request, 101, 202, 1_100);
        write_service_readiness(&dir, &record).unwrap();
        remove_service_readiness_if_supervisor(&dir, 999).unwrap();
        assert_eq!(load_service_readiness(&dir).unwrap(), Some(record));
        remove_service_readiness_if_supervisor(&dir, 101).unwrap();
        assert!(load_service_readiness(&dir).unwrap().is_none());
        remove_service_readiness_request_if(&dir, &request.request_id).unwrap();
        assert!(load_service_readiness_request(&dir).unwrap().is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn startup_withdrawal_restores_the_same_request_until_an_exact_answer_exists() {
        #[cfg(unix)]
        use std::os::unix::fs::MetadataExt as _;

        let dir = test_dir("startup-request-race");
        let request = request();
        write_service_readiness_request(&dir, &request).unwrap();
        remove_all_service_readiness(&dir).unwrap();

        assert!(restore_service_readiness_request_if_empty(&dir, &request).unwrap());
        assert_eq!(
            load_service_readiness_request(&dir).unwrap(),
            Some(request.clone())
        );
        #[cfg(unix)]
        let request_inode = fs::metadata(service_readiness_request_path(&dir))
            .unwrap()
            .ino();
        assert!(!restore_service_readiness_request_if_empty(&dir, &request).unwrap());
        #[cfg(unix)]
        assert_eq!(
            fs::metadata(service_readiness_request_path(&dir))
                .unwrap()
                .ino(),
            request_inode,
            "an existing exact request must not be rewritten"
        );

        let record = ServiceReadinessRecord::answer(&request, 101, 202, 1_100);
        write_service_readiness(&dir, &record).unwrap();
        assert!(!restore_service_readiness_request_if_empty(&dir, &request).unwrap());
        assert_eq!(
            load_service_readiness_request(&dir).unwrap(),
            Some(request.clone()),
            "an exact response-write/request-consume overlap must not rewrite either side"
        );
        remove_service_readiness_request_if(&dir, &request.request_id).unwrap();
        assert!(!restore_service_readiness_request_if_empty(&dir, &request).unwrap());
        assert!(load_service_readiness_request(&dir).unwrap().is_none());
        assert_eq!(load_service_readiness(&dir).unwrap(), Some(record.clone()));

        let mut progress = ServiceReadinessProgress::default();
        assert!(!progress.observe(Some(&record), &request, 101, true));
        assert!(!progress.observe(Some(&record), &request, 101, true));
        assert!(progress.observe(Some(&record), &request, 101, true));
        remove_all_service_readiness(&dir).unwrap();
        assert!(load_service_readiness(&dir).unwrap().is_none());
        assert!(load_service_readiness_request(&dir).unwrap().is_none());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn request_repair_never_overwrites_foreign_or_unsafe_handshake_bytes() {
        use std::os::unix::fs::PermissionsExt as _;

        let dir = test_dir("request-repair-conflict");
        let expected = request();
        let mut foreign = request();
        foreign.request_id.push_str("-foreign");
        write_service_readiness_request(&dir, &foreign).unwrap();
        assert!(matches!(
            restore_service_readiness_request_if_empty(&dir, &expected),
            Err(ServiceReadinessError::HandshakeConflict("request"))
        ));
        assert_eq!(
            load_service_readiness_request(&dir).unwrap(),
            Some(foreign.clone())
        );

        remove_all_service_readiness(&dir).unwrap();
        let foreign_record = ServiceReadinessRecord::answer(&foreign, 101, 202, 1_100);
        write_service_readiness(&dir, &foreign_record).unwrap();
        assert!(matches!(
            restore_service_readiness_request_if_empty(&dir, &expected),
            Err(ServiceReadinessError::HandshakeConflict("response"))
        ));
        assert_eq!(load_service_readiness(&dir).unwrap(), Some(foreign_record));

        remove_all_service_readiness(&dir).unwrap();
        write_service_readiness_request(&dir, &expected).unwrap();
        let path = service_readiness_request_path(&dir);
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        let before = fs::read(&path).unwrap();
        assert!(restore_service_readiness_request_if_empty(&dir, &expected).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        let _ = fs::remove_dir_all(dir);

        let malformed_dir = test_dir("request-repair-malformed");
        let malformed_path = service_readiness_request_path(&malformed_dir);
        fs::write(&malformed_path, b"{not-json\n").unwrap();
        fs::set_permissions(&malformed_path, fs::Permissions::from_mode(0o600)).unwrap();
        let malformed = fs::read(&malformed_path).unwrap();
        assert!(restore_service_readiness_request_if_empty(&malformed_dir, &expected).is_err());
        assert_eq!(fs::read(&malformed_path).unwrap(), malformed);
        let _ = fs::remove_dir_all(malformed_dir);
    }
}
