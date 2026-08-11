//! Bounded, transport-neutral lifecycle contract for an optional remote-desktop extension.
//!
//! A host may encode these values as one JSON frame per stdin/stdout exchange, but this module
//! intentionally owns no process, pipe, cloud, key, account, origin, entitlement, or authorization
//! behavior. Capability negotiation is the only admission gate represented here; the extension
//! remains responsible for its private enrollment and remote-service authority.
//!
//! The stdin/stdout transport contract is a strict two-phase, one-request exchange:
//! 1. host writes one bounded [`crate::ExtensionHello`] frame; extension replies with one bounded
//!    hello frame; both sides call [`crate::negotiate`];
//! 2. host writes exactly one [`RemoteDesktopHostRequest`] frame; extension replies with exactly
//!    one [`RemoteDesktopExtensionResponse`] carrying the same nonzero request id, then the host
//!    closes the one-shot exchange.
//!
//! A lifecycle frame must never be decoded before the hello negotiation phase succeeds. The decoders live on
//! [`NegotiatedExtension`] so protocol or capability mismatch fails closed by construction. Frame
//! Frame delimiting and child-process lifetime belong to the transport adapter. The adapter must
//! call [`validate_remote_desktop_response`] before applying the response so delayed, replayed, or
//! out-of-order frames fail closed.

use crate::frame::{decode_bounded_json, FrameDecodeError};
use crate::negotiation::{KnownCapability, NegotiatedExtension};
use crate::viewport::{
    LeaseCursor, LeaseId, SessionKey, ViewportGeometry, ViewportMessageError,
    ViewportReclaimReason, MAX_LEASE_TTL_MS,
};
use serde::{Deserialize, Serialize};
use std::fmt;

pub const MAX_ENROLLMENT_CODE_BYTES: usize = 256;
pub const MAX_REMOTE_DESKTOP_ID_BYTES: usize = 128;
pub const MAX_REMOTE_DESKTOP_ERROR_BYTES: usize = 1_024;
pub const MAX_REMOTE_DESKTOP_VIEWPORTS: usize = 64;
pub const MAX_REMOTE_DESKTOP_CONNECTIONS: u16 = 1_024;
pub const MAX_FILESYSTEM_MODE_CHANGES: usize = 10;
pub const MAX_FILESYSTEM_MODE_PATH_BYTES: usize = 4_096;
pub const FILESYSTEM_MODE_MIGRATION_NOTICE_ID_BYTES: usize = 64;

fn bounded_visible_value(
    value: String,
    max: usize,
    error: RemoteDesktopMessageError,
) -> Result<String, RemoteDesktopMessageError> {
    if value.is_empty()
        || value.len() > max
        || value.chars().any(|character| character.is_control())
    {
        return Err(error);
    }
    Ok(value)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct RemoteDesktopRequestId(u64);

impl RemoteDesktopRequestId {
    pub fn new(value: u64) -> Result<Self, RemoteDesktopMessageError> {
        if value == 0 {
            return Err(RemoteDesktopMessageError::ZeroRequestId);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct EnrollmentCode(String);

impl EnrollmentCode {
    pub fn new(value: impl Into<String>) -> Result<Self, RemoteDesktopMessageError> {
        bounded_visible_value(
            value.into(),
            MAX_ENROLLMENT_CODE_BYTES,
            RemoteDesktopMessageError::InvalidEnrollmentCode,
        )
        .map(Self)
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for EnrollmentCode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("EnrollmentCode([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct RemoteDesktopId(String);

impl RemoteDesktopId {
    pub fn new(value: impl Into<String>) -> Result<Self, RemoteDesktopMessageError> {
        let value = bounded_visible_value(
            value.into(),
            MAX_REMOTE_DESKTOP_ID_BYTES,
            RemoteDesktopMessageError::InvalidRemoteDesktopId,
        )?;
        if value
            .chars()
            .any(|character| matches!(character, '/' | '\\'))
        {
            return Err(RemoteDesktopMessageError::InvalidRemoteDesktopId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RemoteDesktopErrorCode {
    InvalidRequest,
    NotEnrolled,
    AlreadyEnrolled,
    EnrollmentRejected,
    RemoteUnavailable,
    ViewportUnavailable,
    Busy,
    Internal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemoteDesktopResponseError {
    code: RemoteDesktopErrorCode,
    message: String,
    retryable: bool,
}

impl RemoteDesktopResponseError {
    pub fn new(
        code: RemoteDesktopErrorCode,
        message: impl Into<String>,
        retryable: bool,
    ) -> Result<Self, RemoteDesktopMessageError> {
        let message = bounded_visible_value(
            message.into(),
            MAX_REMOTE_DESKTOP_ERROR_BYTES,
            RemoteDesktopMessageError::InvalidErrorMessage,
        )?;
        Ok(Self {
            code,
            message,
            retryable,
        })
    }

    pub const fn code(&self) -> RemoteDesktopErrorCode {
        self.code
    }

    pub fn message(&self) -> &str {
        &self.message
    }

    pub const fn retryable(&self) -> bool {
        self.retryable
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemoteDesktopStatus {
    #[serde(skip_serializing_if = "Option::is_none")]
    enrollment_id: Option<RemoteDesktopId>,
    /// Display-only account identity. This is dashboard metadata, never remote authority.
    #[serde(skip_serializing_if = "Option::is_none")]
    account_id: Option<RemoteDesktopId>,
    remote_open: bool,
    active_connections: u16,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<RemoteDesktopResponseError>,
}

impl RemoteDesktopStatus {
    pub fn new(
        enrollment_id: Option<RemoteDesktopId>,
        account_id: Option<RemoteDesktopId>,
        remote_open: bool,
        active_connections: u16,
        last_error: Option<RemoteDesktopResponseError>,
    ) -> Result<Self, RemoteDesktopMessageError> {
        if enrollment_id.is_some() != account_id.is_some()
            || (remote_open && enrollment_id.is_none())
        {
            return Err(RemoteDesktopMessageError::InvalidStatus);
        }
        if active_connections > MAX_REMOTE_DESKTOP_CONNECTIONS
            || (!remote_open && active_connections != 0)
        {
            return Err(RemoteDesktopMessageError::InvalidConnectionCount {
                got: active_connections,
                max: MAX_REMOTE_DESKTOP_CONNECTIONS,
            });
        }
        Ok(Self {
            enrollment_id,
            account_id,
            remote_open,
            active_connections,
            last_error,
        })
    }

    pub fn enrollment_id(&self) -> Option<&RemoteDesktopId> {
        self.enrollment_id.as_ref()
    }

    pub fn account_id(&self) -> Option<&RemoteDesktopId> {
        self.account_id.as_ref()
    }

    pub const fn remote_open(&self) -> bool {
        self.remote_open
    }

    pub const fn active_connections(&self) -> u16 {
        self.active_connections
    }

    pub fn last_error(&self) -> Option<&RemoteDesktopResponseError> {
        self.last_error.as_ref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct RemoteDesktopViewport {
    session_id: SessionKey,
    lease_id: LeaseId,
    cursor: LeaseCursor,
    geometry: ViewportGeometry,
}

impl RemoteDesktopViewport {
    pub fn new(
        session_id: SessionKey,
        lease_id: LeaseId,
        cursor: LeaseCursor,
        geometry: ViewportGeometry,
    ) -> Self {
        Self {
            session_id,
            lease_id,
            cursor,
            geometry,
        }
    }

    pub fn session_id(&self) -> &SessionKey {
        &self.session_id
    }

    pub fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }

    pub const fn cursor(&self) -> LeaseCursor {
        self.cursor
    }

    pub const fn geometry(&self) -> ViewportGeometry {
        self.geometry
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct RemoteDesktopViewportList(Vec<RemoteDesktopViewport>);

impl RemoteDesktopViewportList {
    pub fn new(
        viewports: impl IntoIterator<Item = RemoteDesktopViewport>,
    ) -> Result<Self, RemoteDesktopMessageError> {
        let viewports = viewports
            .into_iter()
            .take(MAX_REMOTE_DESKTOP_VIEWPORTS + 1)
            .collect::<Vec<_>>();
        if viewports.len() > MAX_REMOTE_DESKTOP_VIEWPORTS {
            return Err(RemoteDesktopMessageError::TooManyViewports {
                got: viewports.len(),
                max: MAX_REMOTE_DESKTOP_VIEWPORTS,
            });
        }
        let mut sessions = std::collections::HashSet::with_capacity(viewports.len());
        let mut leases = std::collections::HashSet::with_capacity(viewports.len());
        for viewport in &viewports {
            if !sessions.insert(viewport.session_id.clone())
                || !leases.insert(viewport.lease_id.clone())
            {
                return Err(RemoteDesktopMessageError::DuplicateViewport);
            }
        }
        Ok(Self(viewports))
    }

    pub fn as_slice(&self) -> &[RemoteDesktopViewport] {
        &self.0
    }

    pub fn iter(&self) -> impl Iterator<Item = &RemoteDesktopViewport> {
        self.0.iter()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
#[serde(transparent)]
pub struct FilesystemModeMigrationNoticeId(String);

impl FilesystemModeMigrationNoticeId {
    pub fn new(value: impl Into<String>) -> Result<Self, RemoteDesktopMessageError> {
        let value = value.into();
        if value.len() != FILESYSTEM_MODE_MIGRATION_NOTICE_ID_BYTES
            || !value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
        {
            return Err(RemoteDesktopMessageError::InvalidFilesystemModeMigrationNoticeId);
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize)]
pub enum FilesystemMode {
    #[serde(rename = "0640")]
    OwnerGroupReadFile,
    #[serde(rename = "0644")]
    PublicReadFile,
    #[serde(rename = "0660")]
    LegacyGroupWritableFile,
    #[serde(rename = "0664")]
    LegacyPublicGroupWritableFile,
    #[serde(rename = "0700")]
    OwnerOnly,
    #[serde(rename = "0750")]
    OwnerGroupRead,
    #[serde(rename = "0755")]
    PublicRead,
    #[serde(rename = "0770")]
    LegacyGroupWritable,
    #[serde(rename = "0775")]
    LegacyPublicGroupWritable,
}

impl FilesystemMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::OwnerGroupReadFile => "0640",
            Self::PublicReadFile => "0644",
            Self::LegacyGroupWritableFile => "0660",
            Self::LegacyPublicGroupWritableFile => "0664",
            Self::OwnerOnly => "0700",
            Self::OwnerGroupRead => "0750",
            Self::PublicRead => "0755",
            Self::LegacyGroupWritable => "0770",
            Self::LegacyPublicGroupWritable => "0775",
        }
    }
}

fn canonical_posix_absolute_path(value: &str) -> bool {
    value.starts_with('/')
        && value.len() > 1
        && value.len() <= MAX_FILESYSTEM_MODE_PATH_BYTES
        && !value.ends_with('/')
        && !value.chars().any(char::is_control)
        && value
            .split('/')
            .skip(1)
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FilesystemModeChange {
    path: String,
    old_mode: FilesystemMode,
    new_mode: FilesystemMode,
}

impl FilesystemModeChange {
    pub fn new(
        path: impl Into<String>,
        old_mode: FilesystemMode,
        new_mode: FilesystemMode,
    ) -> Result<Self, RemoteDesktopMessageError> {
        let path = path.into();
        if !canonical_posix_absolute_path(&path) {
            return Err(RemoteDesktopMessageError::InvalidFilesystemModePath);
        }
        if !matches!(
            (old_mode, new_mode),
            (
                FilesystemMode::LegacyGroupWritable,
                FilesystemMode::OwnerGroupRead | FilesystemMode::OwnerOnly
            ) | (
                FilesystemMode::LegacyPublicGroupWritable,
                FilesystemMode::PublicRead | FilesystemMode::OwnerOnly
            ) | (
                FilesystemMode::LegacyGroupWritableFile,
                FilesystemMode::OwnerGroupReadFile
            ) | (
                FilesystemMode::LegacyPublicGroupWritableFile,
                FilesystemMode::PublicReadFile
            )
        ) {
            return Err(RemoteDesktopMessageError::InvalidFilesystemModeChange);
        }
        Ok(Self {
            path,
            old_mode,
            new_mode,
        })
    }

    pub fn path(&self) -> &str {
        &self.path
    }

    pub const fn old_mode(&self) -> FilesystemMode {
        self.old_mode
    }

    pub const fn new_mode(&self) -> FilesystemMode {
        self.new_mode
    }

    pub fn rollback_command(&self) -> String {
        let quoted_path = self.path.replace('\'', "'\\''");
        format!("chmod {} -- '{}'", self.old_mode.as_str(), quoted_path)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum FilesystemModeMigrationPhase {
    ReadyToApply,
    Interrupted,
    Applied,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct FilesystemModeMigrationNotice {
    notice_id: FilesystemModeMigrationNoticeId,
    phase: FilesystemModeMigrationPhase,
    changes: Vec<FilesystemModeChange>,
    #[serde(skip_serializing_if = "Option::is_none")]
    recovery_record_path: Option<String>,
}

impl FilesystemModeMigrationNotice {
    pub fn new(
        notice_id: FilesystemModeMigrationNoticeId,
        phase: FilesystemModeMigrationPhase,
        changes: impl IntoIterator<Item = FilesystemModeChange>,
        recovery_record_path: Option<String>,
    ) -> Result<Self, RemoteDesktopMessageError> {
        let changes = changes
            .into_iter()
            .take(MAX_FILESYSTEM_MODE_CHANGES + 1)
            .collect::<Vec<_>>();
        if changes.is_empty() || changes.len() > MAX_FILESYSTEM_MODE_CHANGES {
            return Err(
                RemoteDesktopMessageError::InvalidFilesystemModeChangeCount {
                    got: changes.len(),
                    max: MAX_FILESYSTEM_MODE_CHANGES,
                },
            );
        }
        let mut paths = std::collections::HashSet::with_capacity(changes.len());
        if changes.iter().any(|change| !paths.insert(&change.path)) {
            return Err(RemoteDesktopMessageError::DuplicateFilesystemModePath);
        }
        if recovery_record_path
            .as_deref()
            .is_some_and(|path| !canonical_posix_absolute_path(path))
            || (phase == FilesystemModeMigrationPhase::ReadyToApply)
                != recovery_record_path.is_none()
        {
            return Err(RemoteDesktopMessageError::InvalidFilesystemModeMigrationStatus);
        }
        Ok(Self {
            notice_id,
            phase,
            changes,
            recovery_record_path,
        })
    }

    pub fn notice_id(&self) -> &FilesystemModeMigrationNoticeId {
        &self.notice_id
    }

    pub const fn phase(&self) -> FilesystemModeMigrationPhase {
        self.phase
    }

    pub fn changes(&self) -> &[FilesystemModeChange] {
        &self.changes
    }

    pub fn recovery_record_path(&self) -> Option<&str> {
        self.recovery_record_path.as_deref()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteDesktopHostRequest {
    Status {
        request_id: RemoteDesktopRequestId,
    },
    Enroll {
        request_id: RemoteDesktopRequestId,
        code: EnrollmentCode,
    },
    SetRemoteOpen {
        request_id: RemoteDesktopRequestId,
        open: bool,
    },
    RemoveEnrollment {
        request_id: RemoteDesktopRequestId,
    },
    ApplyFilesystemModeMigration {
        request_id: RemoteDesktopRequestId,
        notice_id: FilesystemModeMigrationNoticeId,
    },
    AcknowledgeFilesystemModeMigration {
        request_id: RemoteDesktopRequestId,
        notice_id: FilesystemModeMigrationNoticeId,
    },
    SnapshotViewports {
        request_id: RemoteDesktopRequestId,
    },
    ReclaimViewport {
        request_id: RemoteDesktopRequestId,
        session_id: SessionKey,
        lease_id: LeaseId,
        cursor: LeaseCursor,
        reason: ViewportReclaimReason,
    },
}

impl RemoteDesktopHostRequest {
    pub const fn request_id(&self) -> RemoteDesktopRequestId {
        match self {
            Self::Status { request_id }
            | Self::Enroll { request_id, .. }
            | Self::SetRemoteOpen { request_id, .. }
            | Self::RemoveEnrollment { request_id }
            | Self::ApplyFilesystemModeMigration { request_id, .. }
            | Self::AcknowledgeFilesystemModeMigration { request_id, .. }
            | Self::SnapshotViewports { request_id }
            | Self::ReclaimViewport { request_id, .. } => *request_id,
        }
    }

    fn requires_viewport_capability(&self) -> bool {
        matches!(
            self,
            Self::SnapshotViewports { .. } | Self::ReclaimViewport { .. }
        )
    }

    fn requires_filesystem_mode_migration_capability(&self) -> bool {
        matches!(
            self,
            Self::ApplyFilesystemModeMigration { .. }
                | Self::AcknowledgeFilesystemModeMigration { .. }
        )
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RemoteDesktopExtensionResponse {
    Status {
        request_id: RemoteDesktopRequestId,
        status: RemoteDesktopStatus,
    },
    Enrolled {
        request_id: RemoteDesktopRequestId,
        status: RemoteDesktopStatus,
    },
    RemoteOpenSet {
        request_id: RemoteDesktopRequestId,
        status: RemoteDesktopStatus,
    },
    EnrollmentRemoved {
        request_id: RemoteDesktopRequestId,
        status: RemoteDesktopStatus,
    },
    FilesystemModeMigration {
        request_id: RemoteDesktopRequestId,
        notice: FilesystemModeMigrationNotice,
        #[serde(skip_serializing_if = "Option::is_none")]
        status: Option<RemoteDesktopStatus>,
    },
    FilesystemModeMigrationAcknowledged {
        request_id: RemoteDesktopRequestId,
        status: RemoteDesktopStatus,
    },
    ViewportSnapshot {
        request_id: RemoteDesktopRequestId,
        cursor: LeaseCursor,
        ttl_ms: u32,
        viewports: RemoteDesktopViewportList,
    },
    ViewportReclaimed {
        request_id: RemoteDesktopRequestId,
        session_id: SessionKey,
        lease_id: LeaseId,
    },
    Error {
        request_id: RemoteDesktopRequestId,
        error: RemoteDesktopResponseError,
    },
}

impl RemoteDesktopExtensionResponse {
    pub const fn request_id(&self) -> RemoteDesktopRequestId {
        match self {
            Self::Status { request_id, .. }
            | Self::Enrolled { request_id, .. }
            | Self::RemoteOpenSet { request_id, .. }
            | Self::EnrollmentRemoved { request_id, .. }
            | Self::FilesystemModeMigration { request_id, .. }
            | Self::FilesystemModeMigrationAcknowledged { request_id, .. }
            | Self::ViewportSnapshot { request_id, .. }
            | Self::ViewportReclaimed { request_id, .. }
            | Self::Error { request_id, .. } => *request_id,
        }
    }

    fn requires_viewport_capability(&self) -> bool {
        matches!(
            self,
            Self::ViewportSnapshot { .. } | Self::ViewportReclaimed { .. }
        )
    }

    fn requires_filesystem_mode_migration_capability(&self) -> bool {
        matches!(
            self,
            Self::FilesystemModeMigration { .. } | Self::FilesystemModeMigrationAcknowledged { .. }
        )
    }
}

/// Validate the second half of the one-shot exchange before an adapter applies any response.
/// Request ids reject delayed/replayed responses from another exchange, while the variant check
/// prevents a valid response for one lifecycle operation from being interpreted as another.
pub fn validate_remote_desktop_response(
    request: &RemoteDesktopHostRequest,
    response: &RemoteDesktopExtensionResponse,
) -> Result<(), RemoteDesktopExchangeError> {
    if request.request_id() != response.request_id() {
        return Err(RemoteDesktopExchangeError::RequestIdMismatch {
            expected: request.request_id(),
            got: response.request_id(),
        });
    }
    if let (
        RemoteDesktopHostRequest::ApplyFilesystemModeMigration { notice_id, .. },
        RemoteDesktopExtensionResponse::FilesystemModeMigration { notice, .. },
    ) = (request, response)
    {
        if notice_id != notice.notice_id() {
            return Err(RemoteDesktopExchangeError::NoticeIdMismatch);
        }
        if notice.phase() == FilesystemModeMigrationPhase::ReadyToApply {
            return Err(RemoteDesktopExchangeError::UnexpectedResponse);
        }
    }
    let expected_variant = matches!(
        (request, response),
        (_, RemoteDesktopExtensionResponse::Error { .. })
            | (
                RemoteDesktopHostRequest::Status { .. },
                RemoteDesktopExtensionResponse::Status { .. }
            )
            | (
                RemoteDesktopHostRequest::Enroll { .. },
                RemoteDesktopExtensionResponse::Enrolled { .. }
            )
            | (
                RemoteDesktopHostRequest::SetRemoteOpen { .. },
                RemoteDesktopExtensionResponse::RemoteOpenSet { .. }
            )
            | (
                RemoteDesktopHostRequest::RemoveEnrollment { .. },
                RemoteDesktopExtensionResponse::EnrollmentRemoved { .. }
            )
            | (
                RemoteDesktopHostRequest::ApplyFilesystemModeMigration { .. },
                RemoteDesktopExtensionResponse::FilesystemModeMigration { .. }
            )
            | (
                RemoteDesktopHostRequest::AcknowledgeFilesystemModeMigration { .. },
                RemoteDesktopExtensionResponse::FilesystemModeMigrationAcknowledged { .. }
            )
            | (
                RemoteDesktopHostRequest::Status { .. }
                    | RemoteDesktopHostRequest::Enroll { .. }
                    | RemoteDesktopHostRequest::SetRemoteOpen { .. }
                    | RemoteDesktopHostRequest::RemoveEnrollment { .. },
                RemoteDesktopExtensionResponse::FilesystemModeMigration { .. }
            )
            | (
                RemoteDesktopHostRequest::SnapshotViewports { .. },
                RemoteDesktopExtensionResponse::ViewportSnapshot { .. }
            )
            | (
                RemoteDesktopHostRequest::ReclaimViewport { .. },
                RemoteDesktopExtensionResponse::ViewportReclaimed { .. }
            )
    );
    if !expected_variant {
        return Err(RemoteDesktopExchangeError::UnexpectedResponse);
    }
    Ok(())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteDesktopExchangeError {
    RequestIdMismatch {
        expected: RemoteDesktopRequestId,
        got: RemoteDesktopRequestId,
    },
    UnexpectedResponse,
    NoticeIdMismatch,
}

impl fmt::Display for RemoteDesktopExchangeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::RequestIdMismatch { expected, got } => write!(
                formatter,
                "remote desktop response request_id {} does not match {}",
                got.get(),
                expected.get()
            ),
            Self::UnexpectedResponse => {
                formatter.write_str("unexpected remote desktop response variant")
            }
            Self::NoticeIdMismatch => {
                formatter.write_str("filesystem mode migration notice id does not match request")
            }
        }
    }
}

impl std::error::Error for RemoteDesktopExchangeError {}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCursor {
    epoch: u64,
    sequence: u64,
}

impl TryFrom<WireCursor> for LeaseCursor {
    type Error = RemoteDesktopMessageError;

    fn try_from(value: WireCursor) -> Result<Self, Self::Error> {
        LeaseCursor::new(value.epoch, value.sequence).map_err(RemoteDesktopMessageError::Viewport)
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireViewportReclaimReason {
    UserRequested,
    LocalViewportFocused,
}

impl From<WireViewportReclaimReason> for ViewportReclaimReason {
    fn from(value: WireViewportReclaimReason) -> Self {
        match value {
            WireViewportReclaimReason::UserRequested => Self::UserRequested,
            WireViewportReclaimReason::LocalViewportFocused => Self::LocalViewportFocused,
        }
    }
}

#[derive(Clone, Copy, Deserialize)]
enum WireFilesystemMode {
    #[serde(rename = "0640")]
    OwnerGroupReadFile,
    #[serde(rename = "0644")]
    PublicReadFile,
    #[serde(rename = "0660")]
    LegacyGroupWritableFile,
    #[serde(rename = "0664")]
    LegacyPublicGroupWritableFile,
    #[serde(rename = "0700")]
    OwnerOnly,
    #[serde(rename = "0750")]
    OwnerGroupRead,
    #[serde(rename = "0755")]
    PublicRead,
    #[serde(rename = "0770")]
    LegacyGroupWritable,
    #[serde(rename = "0775")]
    LegacyPublicGroupWritable,
}

impl From<WireFilesystemMode> for FilesystemMode {
    fn from(value: WireFilesystemMode) -> Self {
        match value {
            WireFilesystemMode::OwnerGroupReadFile => Self::OwnerGroupReadFile,
            WireFilesystemMode::PublicReadFile => Self::PublicReadFile,
            WireFilesystemMode::LegacyGroupWritableFile => Self::LegacyGroupWritableFile,
            WireFilesystemMode::LegacyPublicGroupWritableFile => {
                Self::LegacyPublicGroupWritableFile
            }
            WireFilesystemMode::OwnerOnly => Self::OwnerOnly,
            WireFilesystemMode::OwnerGroupRead => Self::OwnerGroupRead,
            WireFilesystemMode::PublicRead => Self::PublicRead,
            WireFilesystemMode::LegacyGroupWritable => Self::LegacyGroupWritable,
            WireFilesystemMode::LegacyPublicGroupWritable => Self::LegacyPublicGroupWritable,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFilesystemModeChange {
    path: String,
    old_mode: WireFilesystemMode,
    new_mode: WireFilesystemMode,
}

impl TryFrom<WireFilesystemModeChange> for FilesystemModeChange {
    type Error = RemoteDesktopMessageError;

    fn try_from(value: WireFilesystemModeChange) -> Result<Self, Self::Error> {
        Self::new(value.path, value.old_mode.into(), value.new_mode.into())
    }
}

#[derive(Clone, Copy, Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireFilesystemModeMigrationPhase {
    ReadyToApply,
    Interrupted,
    Applied,
}

impl From<WireFilesystemModeMigrationPhase> for FilesystemModeMigrationPhase {
    fn from(value: WireFilesystemModeMigrationPhase) -> Self {
        match value {
            WireFilesystemModeMigrationPhase::ReadyToApply => Self::ReadyToApply,
            WireFilesystemModeMigrationPhase::Interrupted => Self::Interrupted,
            WireFilesystemModeMigrationPhase::Applied => Self::Applied,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireFilesystemModeMigrationNotice {
    notice_id: String,
    phase: WireFilesystemModeMigrationPhase,
    changes: Vec<WireFilesystemModeChange>,
    #[serde(default)]
    recovery_record_path: Option<String>,
}

impl TryFrom<WireFilesystemModeMigrationNotice> for FilesystemModeMigrationNotice {
    type Error = RemoteDesktopMessageError;

    fn try_from(value: WireFilesystemModeMigrationNotice) -> Result<Self, Self::Error> {
        Self::new(
            FilesystemModeMigrationNoticeId::new(value.notice_id)?,
            value.phase.into(),
            value
                .changes
                .into_iter()
                .map(TryInto::try_into)
                .collect::<Result<Vec<_>, _>>()?,
            value.recovery_record_path,
        )
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WireRemoteDesktopHostRequest {
    Status {
        request_id: u64,
    },
    Enroll {
        request_id: u64,
        code: String,
    },
    SetRemoteOpen {
        request_id: u64,
        open: bool,
    },
    RemoveEnrollment {
        request_id: u64,
    },
    ApplyFilesystemModeMigration {
        request_id: u64,
        notice_id: String,
    },
    AcknowledgeFilesystemModeMigration {
        request_id: u64,
        notice_id: String,
    },
    SnapshotViewports {
        request_id: u64,
    },
    ReclaimViewport {
        request_id: u64,
        session_id: String,
        lease_id: String,
        cursor: WireCursor,
        reason: WireViewportReclaimReason,
    },
}

impl TryFrom<WireRemoteDesktopHostRequest> for RemoteDesktopHostRequest {
    type Error = RemoteDesktopMessageError;

    fn try_from(value: WireRemoteDesktopHostRequest) -> Result<Self, Self::Error> {
        Ok(match value {
            WireRemoteDesktopHostRequest::Status { request_id } => Self::Status {
                request_id: RemoteDesktopRequestId::new(request_id)?,
            },
            WireRemoteDesktopHostRequest::Enroll { request_id, code } => Self::Enroll {
                request_id: RemoteDesktopRequestId::new(request_id)?,
                code: EnrollmentCode::new(code)?,
            },
            WireRemoteDesktopHostRequest::SetRemoteOpen { request_id, open } => {
                Self::SetRemoteOpen {
                    request_id: RemoteDesktopRequestId::new(request_id)?,
                    open,
                }
            }
            WireRemoteDesktopHostRequest::RemoveEnrollment { request_id } => {
                Self::RemoveEnrollment {
                    request_id: RemoteDesktopRequestId::new(request_id)?,
                }
            }
            WireRemoteDesktopHostRequest::ApplyFilesystemModeMigration {
                request_id,
                notice_id,
            } => Self::ApplyFilesystemModeMigration {
                request_id: RemoteDesktopRequestId::new(request_id)?,
                notice_id: FilesystemModeMigrationNoticeId::new(notice_id)?,
            },
            WireRemoteDesktopHostRequest::AcknowledgeFilesystemModeMigration {
                request_id,
                notice_id,
            } => Self::AcknowledgeFilesystemModeMigration {
                request_id: RemoteDesktopRequestId::new(request_id)?,
                notice_id: FilesystemModeMigrationNoticeId::new(notice_id)?,
            },
            WireRemoteDesktopHostRequest::SnapshotViewports { request_id } => {
                Self::SnapshotViewports {
                    request_id: RemoteDesktopRequestId::new(request_id)?,
                }
            }
            WireRemoteDesktopHostRequest::ReclaimViewport {
                request_id,
                session_id,
                lease_id,
                cursor,
                reason,
            } => Self::ReclaimViewport {
                request_id: RemoteDesktopRequestId::new(request_id)?,
                session_id: SessionKey::new(session_id)
                    .map_err(RemoteDesktopMessageError::Viewport)?,
                lease_id: LeaseId::new(lease_id).map_err(RemoteDesktopMessageError::Viewport)?,
                cursor: cursor.try_into()?,
                reason: reason.into(),
            },
        })
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum WireRemoteDesktopErrorCode {
    InvalidRequest,
    NotEnrolled,
    AlreadyEnrolled,
    EnrollmentRejected,
    RemoteUnavailable,
    ViewportUnavailable,
    Busy,
    Internal,
}

impl From<WireRemoteDesktopErrorCode> for RemoteDesktopErrorCode {
    fn from(value: WireRemoteDesktopErrorCode) -> Self {
        match value {
            WireRemoteDesktopErrorCode::InvalidRequest => Self::InvalidRequest,
            WireRemoteDesktopErrorCode::NotEnrolled => Self::NotEnrolled,
            WireRemoteDesktopErrorCode::AlreadyEnrolled => Self::AlreadyEnrolled,
            WireRemoteDesktopErrorCode::EnrollmentRejected => Self::EnrollmentRejected,
            WireRemoteDesktopErrorCode::RemoteUnavailable => Self::RemoteUnavailable,
            WireRemoteDesktopErrorCode::ViewportUnavailable => Self::ViewportUnavailable,
            WireRemoteDesktopErrorCode::Busy => Self::Busy,
            WireRemoteDesktopErrorCode::Internal => Self::Internal,
        }
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRemoteDesktopError {
    code: WireRemoteDesktopErrorCode,
    message: String,
    retryable: bool,
}

impl TryFrom<WireRemoteDesktopError> for RemoteDesktopResponseError {
    type Error = RemoteDesktopMessageError;

    fn try_from(value: WireRemoteDesktopError) -> Result<Self, Self::Error> {
        Self::new(value.code.into(), value.message, value.retryable)
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRemoteDesktopStatus {
    #[serde(default)]
    enrollment_id: Option<String>,
    #[serde(default)]
    account_id: Option<String>,
    remote_open: bool,
    active_connections: u16,
    #[serde(default)]
    last_error: Option<WireRemoteDesktopError>,
}

impl TryFrom<WireRemoteDesktopStatus> for RemoteDesktopStatus {
    type Error = RemoteDesktopMessageError;

    fn try_from(value: WireRemoteDesktopStatus) -> Result<Self, Self::Error> {
        Self::new(
            value.enrollment_id.map(RemoteDesktopId::new).transpose()?,
            value.account_id.map(RemoteDesktopId::new).transpose()?,
            value.remote_open,
            value.active_connections,
            value.last_error.map(TryInto::try_into).transpose()?,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireGeometry {
    cols: u16,
    rows: u16,
    pixel_width: u32,
    pixel_height: u32,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireRemoteDesktopViewport {
    session_id: String,
    lease_id: String,
    cursor: WireCursor,
    geometry: WireGeometry,
}

fn validate_snapshot_ttl(ttl_ms: u32) -> Result<u32, RemoteDesktopMessageError> {
    if ttl_ms == 0 || ttl_ms > MAX_LEASE_TTL_MS {
        return Err(RemoteDesktopMessageError::Viewport(
            ViewportMessageError::InvalidTtl {
                got: ttl_ms,
                max: MAX_LEASE_TTL_MS,
            },
        ));
    }
    Ok(ttl_ms)
}

impl TryFrom<WireRemoteDesktopViewport> for RemoteDesktopViewport {
    type Error = RemoteDesktopMessageError;

    fn try_from(value: WireRemoteDesktopViewport) -> Result<Self, Self::Error> {
        Ok(Self::new(
            SessionKey::new(value.session_id).map_err(RemoteDesktopMessageError::Viewport)?,
            LeaseId::new(value.lease_id).map_err(RemoteDesktopMessageError::Viewport)?,
            value.cursor.try_into()?,
            ViewportGeometry::new(
                value.geometry.cols,
                value.geometry.rows,
                value.geometry.pixel_width,
                value.geometry.pixel_height,
            )
            .map_err(RemoteDesktopMessageError::Viewport)?,
        ))
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WireRemoteDesktopExtensionResponse {
    Status {
        request_id: u64,
        status: WireRemoteDesktopStatus,
    },
    Enrolled {
        request_id: u64,
        status: WireRemoteDesktopStatus,
    },
    RemoteOpenSet {
        request_id: u64,
        status: WireRemoteDesktopStatus,
    },
    EnrollmentRemoved {
        request_id: u64,
        status: WireRemoteDesktopStatus,
    },
    FilesystemModeMigration {
        request_id: u64,
        notice: WireFilesystemModeMigrationNotice,
        #[serde(default)]
        status: Option<WireRemoteDesktopStatus>,
    },
    FilesystemModeMigrationAcknowledged {
        request_id: u64,
        status: WireRemoteDesktopStatus,
    },
    ViewportSnapshot {
        request_id: u64,
        cursor: WireCursor,
        ttl_ms: u32,
        viewports: Vec<WireRemoteDesktopViewport>,
    },
    ViewportReclaimed {
        request_id: u64,
        session_id: String,
        lease_id: String,
    },
    Error {
        request_id: u64,
        error: WireRemoteDesktopError,
    },
}

impl TryFrom<WireRemoteDesktopExtensionResponse> for RemoteDesktopExtensionResponse {
    type Error = RemoteDesktopMessageError;

    fn try_from(
        value: WireRemoteDesktopExtensionResponse,
    ) -> Result<Self, RemoteDesktopMessageError> {
        let response = match value {
            WireRemoteDesktopExtensionResponse::Status { request_id, status } => Self::Status {
                request_id: RemoteDesktopRequestId::new(request_id)?,
                status: status.try_into()?,
            },
            WireRemoteDesktopExtensionResponse::Enrolled { request_id, status } => {
                let status: RemoteDesktopStatus = status.try_into()?;
                if status.enrollment_id().is_none() {
                    return Err(RemoteDesktopMessageError::InvalidStatus);
                }
                Self::Enrolled {
                    request_id: RemoteDesktopRequestId::new(request_id)?,
                    status,
                }
            }
            WireRemoteDesktopExtensionResponse::RemoteOpenSet { request_id, status } => {
                Self::RemoteOpenSet {
                    request_id: RemoteDesktopRequestId::new(request_id)?,
                    status: status.try_into()?,
                }
            }
            WireRemoteDesktopExtensionResponse::EnrollmentRemoved { request_id, status } => {
                let status: RemoteDesktopStatus = status.try_into()?;
                if status.enrollment_id().is_some() || status.remote_open() {
                    return Err(RemoteDesktopMessageError::InvalidStatus);
                }
                Self::EnrollmentRemoved {
                    request_id: RemoteDesktopRequestId::new(request_id)?,
                    status,
                }
            }
            WireRemoteDesktopExtensionResponse::FilesystemModeMigration {
                request_id,
                notice,
                status,
            } => {
                let notice: FilesystemModeMigrationNotice = notice.try_into()?;
                let status = status.map(TryInto::try_into).transpose()?;
                if notice.phase() != FilesystemModeMigrationPhase::Applied && status.is_some() {
                    return Err(RemoteDesktopMessageError::InvalidFilesystemModeMigrationStatus);
                }
                Self::FilesystemModeMigration {
                    request_id: RemoteDesktopRequestId::new(request_id)?,
                    notice,
                    status,
                }
            }
            WireRemoteDesktopExtensionResponse::FilesystemModeMigrationAcknowledged {
                request_id,
                status,
            } => Self::FilesystemModeMigrationAcknowledged {
                request_id: RemoteDesktopRequestId::new(request_id)?,
                status: status.try_into()?,
            },
            WireRemoteDesktopExtensionResponse::ViewportSnapshot {
                request_id,
                cursor,
                ttl_ms,
                viewports,
            } => {
                let cursor: LeaseCursor = cursor.try_into()?;
                let viewports = RemoteDesktopViewportList::new(
                    viewports
                        .into_iter()
                        .map(TryInto::try_into)
                        .collect::<Result<Vec<_>, _>>()?,
                )?;
                // The snapshot cursor is the connection-global high-water mark. Each lease keeps
                // the cursor of its own last upsert, so sequences can differ, but every entry must
                // belong to this process epoch and must not claim an event newer than the snapshot.
                if viewports.iter().any(|viewport| {
                    viewport.cursor().epoch() != cursor.epoch()
                        || viewport.cursor().sequence() > cursor.sequence()
                }) {
                    return Err(RemoteDesktopMessageError::SnapshotCursorMismatch);
                }
                Self::ViewportSnapshot {
                    request_id: RemoteDesktopRequestId::new(request_id)?,
                    cursor,
                    ttl_ms: validate_snapshot_ttl(ttl_ms)?,
                    viewports,
                }
            }
            WireRemoteDesktopExtensionResponse::ViewportReclaimed {
                request_id,
                session_id,
                lease_id,
            } => Self::ViewportReclaimed {
                request_id: RemoteDesktopRequestId::new(request_id)?,
                session_id: SessionKey::new(session_id)
                    .map_err(RemoteDesktopMessageError::Viewport)?,
                lease_id: LeaseId::new(lease_id).map_err(RemoteDesktopMessageError::Viewport)?,
            },
            WireRemoteDesktopExtensionResponse::Error { request_id, error } => Self::Error {
                request_id: RemoteDesktopRequestId::new(request_id)?,
                error: error.try_into()?,
            },
        };
        Ok(response)
    }
}

impl NegotiatedExtension {
    fn require_remote_desktop_capability(&self) -> Result<(), RemoteDesktopDecodeError> {
        if self.supports(KnownCapability::RemoteDesktopLifecycleV1) {
            Ok(())
        } else {
            Err(RemoteDesktopDecodeError::CapabilityNotNegotiated)
        }
    }

    fn require_remote_viewport_capability(&self) -> Result<(), RemoteDesktopDecodeError> {
        if self.supports(KnownCapability::ExternalViewportLeaseV1) {
            Ok(())
        } else {
            Err(RemoteDesktopDecodeError::ViewportCapabilityNotNegotiated)
        }
    }

    fn require_filesystem_mode_migration_capability(&self) -> Result<(), RemoteDesktopDecodeError> {
        if self.supports(KnownCapability::FilesystemModeMigrationV1) {
            Ok(())
        } else {
            Err(RemoteDesktopDecodeError::FilesystemModeMigrationCapabilityNotNegotiated)
        }
    }

    pub fn decode_remote_desktop_host_frame(
        &self,
        bytes: &[u8],
    ) -> Result<RemoteDesktopHostRequest, RemoteDesktopDecodeError> {
        self.require_remote_desktop_capability()?;
        let wire = decode_bounded_json::<WireRemoteDesktopHostRequest>(bytes)
            .map_err(RemoteDesktopDecodeError::Frame)?;
        let request: RemoteDesktopHostRequest =
            wire.try_into().map_err(RemoteDesktopDecodeError::Message)?;
        if request.requires_viewport_capability() {
            self.require_remote_viewport_capability()?;
        }
        if request.requires_filesystem_mode_migration_capability() {
            self.require_filesystem_mode_migration_capability()?;
        }
        Ok(request)
    }

    pub fn decode_remote_desktop_extension_frame(
        &self,
        bytes: &[u8],
    ) -> Result<RemoteDesktopExtensionResponse, RemoteDesktopDecodeError> {
        self.require_remote_desktop_capability()?;
        let wire = decode_bounded_json::<WireRemoteDesktopExtensionResponse>(bytes)
            .map_err(RemoteDesktopDecodeError::Frame)?;
        let response: RemoteDesktopExtensionResponse =
            wire.try_into().map_err(RemoteDesktopDecodeError::Message)?;
        if response.requires_viewport_capability() {
            self.require_remote_viewport_capability()?;
        }
        if response.requires_filesystem_mode_migration_capability() {
            self.require_filesystem_mode_migration_capability()?;
        }
        Ok(response)
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteDesktopDecodeError {
    CapabilityNotNegotiated,
    ViewportCapabilityNotNegotiated,
    FilesystemModeMigrationCapabilityNotNegotiated,
    Frame(FrameDecodeError),
    Message(RemoteDesktopMessageError),
}

impl fmt::Display for RemoteDesktopDecodeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityNotNegotiated => {
                formatter.write_str("remote desktop lifecycle capability was not negotiated")
            }
            Self::ViewportCapabilityNotNegotiated => {
                formatter.write_str("external viewport lease capability was not negotiated")
            }
            Self::FilesystemModeMigrationCapabilityNotNegotiated => {
                formatter.write_str("filesystem mode migration capability was not negotiated")
            }
            Self::Frame(error) => error.fmt(formatter),
            Self::Message(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RemoteDesktopDecodeError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RemoteDesktopMessageError {
    ZeroRequestId,
    InvalidEnrollmentCode,
    InvalidRemoteDesktopId,
    InvalidErrorMessage,
    InvalidStatus,
    InvalidConnectionCount { got: u16, max: u16 },
    InvalidFilesystemModeMigrationNoticeId,
    InvalidFilesystemModePath,
    InvalidFilesystemModeChange,
    InvalidFilesystemModeChangeCount { got: usize, max: usize },
    DuplicateFilesystemModePath,
    InvalidFilesystemModeMigrationStatus,
    TooManyViewports { got: usize, max: usize },
    DuplicateViewport,
    SnapshotCursorMismatch,
    Viewport(ViewportMessageError),
}

impl fmt::Display for RemoteDesktopMessageError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ZeroRequestId => formatter.write_str("request_id must be nonzero"),
            Self::InvalidEnrollmentCode => formatter.write_str("invalid enrollment code"),
            Self::InvalidRemoteDesktopId => formatter.write_str("invalid remote desktop id"),
            Self::InvalidErrorMessage => {
                formatter.write_str("invalid remote desktop error message")
            }
            Self::InvalidStatus => formatter.write_str("inconsistent remote desktop status"),
            Self::InvalidConnectionCount { got, max } => {
                write!(
                    formatter,
                    "invalid active connection count {got}; maximum is {max}"
                )
            }
            Self::InvalidFilesystemModeMigrationNoticeId => {
                formatter.write_str("invalid filesystem mode migration notice id")
            }
            Self::InvalidFilesystemModePath => {
                formatter.write_str("invalid filesystem mode migration path")
            }
            Self::InvalidFilesystemModeChange => {
                formatter.write_str("invalid filesystem mode transition")
            }
            Self::InvalidFilesystemModeChangeCount { got, max } => write!(
                formatter,
                "filesystem mode migration has {got} changes; maximum is {max}"
            ),
            Self::DuplicateFilesystemModePath => {
                formatter.write_str("filesystem mode migration contains a duplicate path")
            }
            Self::InvalidFilesystemModeMigrationStatus => {
                formatter.write_str("filesystem mode migration phase has an inconsistent status")
            }
            Self::TooManyViewports { got, max } => {
                write!(
                    formatter,
                    "remote viewport snapshot has {got} entries; maximum is {max}"
                )
            }
            Self::DuplicateViewport => formatter
                .write_str("remote viewport snapshot contains duplicate session or lease ids"),
            Self::SnapshotCursorMismatch => {
                formatter.write_str("remote viewport entries do not match the snapshot cursor")
            }
            Self::Viewport(error) => error.fmt(formatter),
        }
    }
}

impl std::error::Error for RemoteDesktopMessageError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::negotiation::{decode_hello_frame, negotiate, Capability, ExtensionHello};
    use crate::MAX_EXTENSION_FRAME_BYTES;

    fn negotiated(lifecycle: bool, viewport: bool) -> NegotiatedExtension {
        negotiated_with_migration(lifecycle, viewport, false)
    }

    fn negotiated_with_migration(
        lifecycle: bool,
        viewport: bool,
        filesystem_mode_migration: bool,
    ) -> NegotiatedExtension {
        let mut capabilities = Vec::new();
        if lifecycle {
            capabilities.push(Capability::remote_desktop_lifecycle_v1());
        }
        if viewport {
            capabilities.push(Capability::external_viewport_lease_v1());
        }
        if filesystem_mode_migration {
            capabilities.push(Capability::filesystem_mode_migration_v1());
        }
        let hello = ExtensionHello::host(capabilities).unwrap();
        negotiate(&hello, &hello).unwrap()
    }

    fn viewport_json(index: usize) -> String {
        format!(
            r#"{{"session_id":"session-{index}","lease_id":"lease-{index}","cursor":{{"epoch":1,"sequence":{}}},"geometry":{{"cols":120,"rows":40,"pixel_width":1920,"pixel_height":1080}}}}"#,
            index + 1
        )
    }

    #[test]
    fn lifecycle_requests_are_capability_gated_and_bounded() {
        let enroll = br#"{"type":"enroll","request_id":1,"code":"ABCD-1234"}"#;
        assert!(matches!(
            negotiated(false, false).decode_remote_desktop_host_frame(enroll),
            Err(RemoteDesktopDecodeError::CapabilityNotNegotiated)
        ));
        let request = negotiated(true, false)
            .decode_remote_desktop_host_frame(enroll)
            .unwrap();
        assert!(matches!(request, RemoteDesktopHostRequest::Enroll { .. }));

        let oversized = format!(
            r#"{{"type":"enroll","request_id":1,"code":"{}"}}"#,
            "x".repeat(MAX_ENROLLMENT_CODE_BYTES + 1)
        );
        assert!(matches!(
            negotiated(true, false).decode_remote_desktop_host_frame(oversized.as_bytes()),
            Err(RemoteDesktopDecodeError::Message(
                RemoteDesktopMessageError::InvalidEnrollmentCode
            ))
        ));
        assert!(matches!(
            negotiated(true, false).decode_remote_desktop_host_frame(&vec![
                b' ';
                MAX_EXTENSION_FRAME_BYTES
                    + 1
            ]),
            Err(RemoteDesktopDecodeError::Frame(
                FrameDecodeError::TooLarge { .. }
            ))
        ));
    }

    #[test]
    fn filesystem_mode_requests_carry_only_a_bounded_notice_id_and_require_the_capability() {
        let id = "a".repeat(FILESYSTEM_MODE_MIGRATION_NOTICE_ID_BYTES);
        let apply = format!(
            r#"{{"type":"apply_filesystem_mode_migration","request_id":9,"notice_id":"{id}"}}"#
        );
        assert!(matches!(
            negotiated(true, false).decode_remote_desktop_host_frame(apply.as_bytes()),
            Err(RemoteDesktopDecodeError::FilesystemModeMigrationCapabilityNotNegotiated)
        ));
        let request = negotiated_with_migration(true, false, true)
            .decode_remote_desktop_host_frame(apply.as_bytes())
            .unwrap();
        let encoded = serde_json::to_string(&request).unwrap();
        assert!(encoded.contains(&id));
        for forbidden in ["path", "old_mode", "new_mode", "chmod"] {
            assert!(!encoded.contains(forbidden));
        }

        let short =
            r#"{"type":"acknowledge_filesystem_mode_migration","request_id":9,"notice_id":"abc"}"#;
        assert!(matches!(
            negotiated_with_migration(true, false, true)
                .decode_remote_desktop_host_frame(short.as_bytes()),
            Err(RemoteDesktopDecodeError::Message(
                RemoteDesktopMessageError::InvalidFilesystemModeMigrationNoticeId
            ))
        ));
    }

    #[test]
    fn filesystem_mode_notice_is_bounded_strict_and_formats_copy_only_rollback() {
        let change = FilesystemModeChange::new(
            "/home/tester/a folder/it's-hydra",
            FilesystemMode::LegacyPublicGroupWritable,
            FilesystemMode::PublicRead,
        )
        .unwrap();
        assert_eq!(
            change.rollback_command(),
            "chmod 0775 -- '/home/tester/a folder/it'\\''s-hydra'"
        );
        let service_change = FilesystemModeChange::new(
            "/home/tester/.config/systemd/user/hydra-agent.service",
            FilesystemMode::LegacyPublicGroupWritableFile,
            FilesystemMode::PublicReadFile,
        )
        .unwrap();
        assert_eq!(
            service_change.rollback_command(),
            "chmod 0664 -- '/home/tester/.config/systemd/user/hydra-agent.service'"
        );
        assert!(FilesystemModeChange::new(
            "/home/tester/not-a-file-transition",
            FilesystemMode::LegacyPublicGroupWritableFile,
            FilesystemMode::PublicRead,
        )
        .is_err());
        for bad in [
            "relative/path",
            "/home/test//hydra-agent",
            "/home/test/./hydra-agent",
            "/home/test/../hydra-agent",
            "/home/test/hydra-agent/",
            "/home/test/hydra\nagent",
        ] {
            assert!(FilesystemModeChange::new(
                bad,
                FilesystemMode::LegacyGroupWritable,
                FilesystemMode::OwnerOnly,
            )
            .is_err());
        }
        assert!(FilesystemModeChange::new(
            "/home/tester/.local",
            FilesystemMode::PublicRead,
            FilesystemMode::OwnerOnly,
        )
        .is_err());

        let id = FilesystemModeMigrationNoticeId::new("b".repeat(64)).unwrap();
        let duplicate = FilesystemModeMigrationNotice::new(
            id.clone(),
            FilesystemModeMigrationPhase::ReadyToApply,
            [change.clone(), change.clone()],
            None,
        );
        assert!(matches!(
            duplicate,
            Err(RemoteDesktopMessageError::DuplicateFilesystemModePath)
        ));
        let exact_maximum = (0..MAX_FILESYSTEM_MODE_CHANGES)
            .map(|index| {
                if index == 6 {
                    service_change.clone()
                } else {
                    FilesystemModeChange::new(
                        format!("/home/tester/fixed-path-{index}"),
                        FilesystemMode::LegacyPublicGroupWritable,
                        FilesystemMode::PublicRead,
                    )
                    .unwrap()
                }
            })
            .collect::<Vec<_>>();
        let maximum_notice = FilesystemModeMigrationNotice::new(
            FilesystemModeMigrationNoticeId::new("c".repeat(64)).unwrap(),
            FilesystemModeMigrationPhase::ReadyToApply,
            exact_maximum,
            None,
        )
        .unwrap();
        assert_eq!(maximum_notice.changes().len(), MAX_FILESYSTEM_MODE_CHANGES);
        let encoded = serde_json::to_string(&maximum_notice).unwrap();
        assert!(encoded.contains("hydra-agent.service"));
        assert!(encoded.contains(r#""old_mode":"0664","new_mode":"0644""#));
        let repeated = std::iter::repeat_n(change, MAX_FILESYSTEM_MODE_CHANGES + 1);
        assert!(matches!(
            FilesystemModeMigrationNotice::new(
                id,
                FilesystemModeMigrationPhase::ReadyToApply,
                repeated,
                None,
            ),
            Err(RemoteDesktopMessageError::InvalidFilesystemModeChangeCount { .. })
        ));
    }

    #[test]
    fn filesystem_mode_action_required_response_is_capability_gated_and_correlated() {
        let id = "c".repeat(64);
        let response = format!(
            r#"{{"type":"filesystem_mode_migration","request_id":12,"notice":{{"notice_id":"{id}","phase":"ready_to_apply","changes":[{{"path":"/home/tester/.local","old_mode":"0775","new_mode":"0755"}}]}}}}"#
        );
        assert!(matches!(
            negotiated(true, false).decode_remote_desktop_extension_frame(response.as_bytes()),
            Err(RemoteDesktopDecodeError::FilesystemModeMigrationCapabilityNotNegotiated)
        ));
        let ready = negotiated_with_migration(true, false, true)
            .decode_remote_desktop_extension_frame(response.as_bytes())
            .unwrap();
        let request = RemoteDesktopHostRequest::ApplyFilesystemModeMigration {
            request_id: RemoteDesktopRequestId::new(12).unwrap(),
            notice_id: FilesystemModeMigrationNoticeId::new(id.clone()).unwrap(),
        };
        assert_eq!(
            validate_remote_desktop_response(&request, &ready),
            Err(RemoteDesktopExchangeError::UnexpectedResponse),
            "Apply cannot claim that no apply was attempted"
        );

        let interrupted = format!(
            r#"{{"type":"filesystem_mode_migration","request_id":12,"notice":{{"notice_id":"{id}","phase":"interrupted","changes":[{{"path":"/home/tester/.local","old_mode":"0775","new_mode":"0755"}}],"recovery_record_path":"/home/tester/.hydra-agent-authority-migration-v1.json"}}}}"#
        );
        let decoded = negotiated_with_migration(true, false, true)
            .decode_remote_desktop_extension_frame(interrupted.as_bytes())
            .unwrap();
        validate_remote_desktop_response(&request, &decoded).unwrap();

        let wrong = RemoteDesktopHostRequest::ApplyFilesystemModeMigration {
            request_id: RemoteDesktopRequestId::new(12).unwrap(),
            notice_id: FilesystemModeMigrationNoticeId::new("d".repeat(64)).unwrap(),
        };
        assert_eq!(
            validate_remote_desktop_response(&wrong, &decoded),
            Err(RemoteDesktopExchangeError::NoticeIdMismatch)
        );

        let inconsistent = format!(
            r#"{{"type":"filesystem_mode_migration","request_id":12,"notice":{{"notice_id":"{}","phase":"interrupted","changes":[{{"path":"/home/tester/.local","old_mode":"0775","new_mode":"0755"}}],"recovery_record_path":"/home/tester/.hydra-agent-authority-migration-v1.json"}},"status":{{"remote_open":false,"active_connections":0}}}}"#,
            "e".repeat(64)
        );
        assert!(matches!(
            negotiated_with_migration(true, false, true)
                .decode_remote_desktop_extension_frame(inconsistent.as_bytes()),
            Err(RemoteDesktopDecodeError::Message(
                RemoteDesktopMessageError::InvalidFilesystemModeMigrationStatus
            ))
        ));
    }

    #[test]
    fn filesystem_mode_notice_phase_and_recovery_record_shape_fail_closed() {
        let id = "f".repeat(64);
        for response in [
            format!(
                r#"{{"type":"filesystem_mode_migration","request_id":12,"notice":{{"notice_id":"{id}","phase":"ready_to_apply","changes":[{{"path":"/home/tester/.local","old_mode":"0775","new_mode":"0755"}}],"recovery_record_path":"/home/tester/.hydra-agent-authority-migration-v1.json"}}}}"#
            ),
            format!(
                r#"{{"type":"filesystem_mode_migration","request_id":12,"notice":{{"notice_id":"{id}","phase":"interrupted","changes":[{{"path":"/home/tester/.local","old_mode":"0775","new_mode":"0755"}}]}}}}"#
            ),
            format!(
                r#"{{"type":"filesystem_mode_migration","request_id":12,"notice":{{"notice_id":"{id}","phase":"applied","changes":[{{"path":"/home/tester/.local","old_mode":"0775","new_mode":"0755"}}]}}}}"#
            ),
        ] {
            assert!(matches!(
                negotiated_with_migration(true, false, true)
                    .decode_remote_desktop_extension_frame(response.as_bytes()),
                Err(RemoteDesktopDecodeError::Message(
                    RemoteDesktopMessageError::InvalidFilesystemModeMigrationStatus
                ))
            ));
        }
    }

    #[test]
    fn strict_two_phase_exchange_negotiates_before_one_typed_request() {
        let host_hello = decode_hello_frame(
            br#"{"protocol":{"min":1,"max":1},"capabilities":["remote_desktop_lifecycle_v1"]}"#,
        )
        .unwrap();
        let extension_hello = decode_hello_frame(
            br#"{"protocol":{"min":1,"max":1},"capabilities":["remote_desktop_lifecycle_v1"]}"#,
        )
        .unwrap();
        let exchange = negotiate(&host_hello, &extension_hello).unwrap();
        let request = exchange
            .decode_remote_desktop_host_frame(br#"{"type":"status","request_id":44}"#)
            .unwrap();
        assert_eq!(request.request_id().get(), 44);

        let response = exchange
            .decode_remote_desktop_extension_frame(
                br#"{"type":"status","request_id":44,"status":{"remote_open":false,"active_connections":0}}"#,
            )
            .unwrap();
        assert_eq!(response.request_id(), request.request_id());
        validate_remote_desktop_response(&request, &response).unwrap();
    }

    #[test]
    fn response_correlation_rejects_replayed_ids_and_wrong_variants() {
        let request = RemoteDesktopHostRequest::Status {
            request_id: RemoteDesktopRequestId::new(41).unwrap(),
        };
        let status = RemoteDesktopStatus::new(None, None, false, 0, None).unwrap();
        let matching = RemoteDesktopExtensionResponse::Status {
            request_id: RemoteDesktopRequestId::new(41).unwrap(),
            status: status.clone(),
        };
        validate_remote_desktop_response(&request, &matching).unwrap();

        let replayed = RemoteDesktopExtensionResponse::Status {
            request_id: RemoteDesktopRequestId::new(40).unwrap(),
            status: status.clone(),
        };
        assert!(matches!(
            validate_remote_desktop_response(&request, &replayed),
            Err(RemoteDesktopExchangeError::RequestIdMismatch { expected, got })
                if expected.get() == 41 && got.get() == 40
        ));

        let wrong_variant = RemoteDesktopExtensionResponse::Enrolled {
            request_id: RemoteDesktopRequestId::new(41).unwrap(),
            status,
        };
        assert_eq!(
            validate_remote_desktop_response(&request, &wrong_variant),
            Err(RemoteDesktopExchangeError::UnexpectedResponse)
        );

        let error = RemoteDesktopExtensionResponse::Error {
            request_id: RemoteDesktopRequestId::new(41).unwrap(),
            error: RemoteDesktopResponseError::new(
                RemoteDesktopErrorCode::RemoteUnavailable,
                "service unavailable",
                true,
            )
            .unwrap(),
        };
        validate_remote_desktop_response(&request, &error).unwrap();
    }

    #[test]
    fn enrollment_code_is_redacted_through_the_enclosing_request_debug() {
        let secret = "NEVER-LOG-THIS-CODE";
        let request = RemoteDesktopHostRequest::Enroll {
            request_id: RemoteDesktopRequestId::new(1).unwrap(),
            code: EnrollmentCode::new(secret).unwrap(),
        };
        let debug = format!("{request:?}");
        assert!(!debug.contains(secret));
        assert!(debug.contains("[REDACTED]"));
    }

    #[test]
    fn viewport_lifecycle_frames_require_both_capabilities() {
        let snapshot = br#"{"type":"snapshot_viewports","request_id":7}"#;
        assert!(matches!(
            negotiated(true, false).decode_remote_desktop_host_frame(snapshot),
            Err(RemoteDesktopDecodeError::ViewportCapabilityNotNegotiated)
        ));
        assert!(negotiated(true, true)
            .decode_remote_desktop_host_frame(snapshot)
            .is_ok());
    }

    #[test]
    fn response_decode_rejects_unknown_fields_inconsistent_status_and_unbounded_errors() {
        let session = negotiated(true, false);
        assert!(session
            .decode_remote_desktop_extension_frame(
                br#"{"type":"status","request_id":1,"status":{"remote_open":false,"active_connections":0},"token":"secret"}"#,
            )
            .is_err());
        assert!(session
            .decode_remote_desktop_extension_frame(
                br#"{"type":"status","request_id":1,"status":{"remote_open":true,"active_connections":1}}"#,
            )
            .is_err());
        assert!(session
            .decode_remote_desktop_extension_frame(
                br#"{"type":"status","request_id":1,"status":{"enrollment_id":"enrollment-1","remote_open":false,"active_connections":0}}"#,
            )
            .is_err());
        let oversized_account = format!(
            r#"{{"type":"status","request_id":1,"status":{{"enrollment_id":"enrollment-1","account_id":"{}","remote_open":false,"active_connections":0}}}}"#,
            "x".repeat(MAX_REMOTE_DESKTOP_ID_BYTES + 1)
        );
        assert!(session
            .decode_remote_desktop_extension_frame(oversized_account.as_bytes())
            .is_err());
        let error = format!(
            r#"{{"type":"error","request_id":1,"error":{{"code":"internal","message":"{}","retryable":false}}}}"#,
            "x".repeat(MAX_REMOTE_DESKTOP_ERROR_BYTES + 1)
        );
        assert!(session
            .decode_remote_desktop_extension_frame(error.as_bytes())
            .is_err());
    }

    #[test]
    fn viewport_snapshots_are_capped_and_deduplicated() {
        let entries = (0..=MAX_REMOTE_DESKTOP_VIEWPORTS)
            .map(viewport_json)
            .collect::<Vec<_>>()
            .join(",");
        let frame = format!(
            r#"{{"type":"viewport_snapshot","request_id":1,"cursor":{{"epoch":1,"sequence":1000}},"ttl_ms":5000,"viewports":[{entries}]}}"#
        );
        assert!(matches!(
            negotiated(true, true).decode_remote_desktop_extension_frame(frame.as_bytes()),
            Err(RemoteDesktopDecodeError::Message(
                RemoteDesktopMessageError::TooManyViewports { .. }
            ))
        ));

        let duplicate = format!(
            r#"{{"type":"viewport_snapshot","request_id":1,"cursor":{{"epoch":1,"sequence":1}},"ttl_ms":5000,"viewports":[{},{}]}}"#,
            viewport_json(0),
            viewport_json(0)
        );
        assert!(matches!(
            negotiated(true, true).decode_remote_desktop_extension_frame(duplicate.as_bytes()),
            Err(RemoteDesktopDecodeError::Message(
                RemoteDesktopMessageError::DuplicateViewport
            ))
        ));

        let viewport = RemoteDesktopViewport::new(
            SessionKey::new("session-infinite").unwrap(),
            LeaseId::new("lease-infinite").unwrap(),
            LeaseCursor::new(1, 1).unwrap(),
            ViewportGeometry::new(80, 24, 800, 600).unwrap(),
        );
        assert!(matches!(
            RemoteDesktopViewportList::new(std::iter::repeat(viewport)),
            Err(RemoteDesktopMessageError::TooManyViewports { got, .. })
                if got == MAX_REMOTE_DESKTOP_VIEWPORTS + 1
        ));
    }

    #[test]
    fn valid_status_and_viewport_snapshot_round_trip_without_authority_fields() {
        let status = RemoteDesktopStatus::new(
            Some(RemoteDesktopId::new("enrollment-1").unwrap()),
            Some(RemoteDesktopId::new("account-display-1").unwrap()),
            true,
            1,
            None,
        )
        .unwrap();
        let response = RemoteDesktopExtensionResponse::Status {
            request_id: RemoteDesktopRequestId::new(9).unwrap(),
            status,
        };
        let encoded = serde_json::to_vec(&response).unwrap();
        let decoded = negotiated(true, false)
            .decode_remote_desktop_extension_frame(&encoded)
            .unwrap();
        assert_eq!(decoded.request_id().get(), 9);
        let RemoteDesktopExtensionResponse::Status { status, .. } = &decoded else {
            panic!("expected status response");
        };
        assert_eq!(
            status.account_id().map(RemoteDesktopId::as_str),
            Some("account-display-1")
        );
        let text = String::from_utf8(encoded).unwrap();
        for forbidden in ["cloud", "key", "origin", "entitlement", "token"] {
            assert!(!text.contains(forbidden));
        }

        let snapshot = RemoteDesktopExtensionResponse::ViewportSnapshot {
            request_id: RemoteDesktopRequestId::new(10).unwrap(),
            cursor: LeaseCursor::new(1, 3).unwrap(),
            ttl_ms: 5_000,
            viewports: RemoteDesktopViewportList::new([
                RemoteDesktopViewport::new(
                    SessionKey::new("session-1").unwrap(),
                    LeaseId::new("lease-1").unwrap(),
                    LeaseCursor::new(1, 1).unwrap(),
                    ViewportGeometry::new(120, 40, 1920, 1080).unwrap(),
                ),
                RemoteDesktopViewport::new(
                    SessionKey::new("session-2").unwrap(),
                    LeaseId::new("lease-2").unwrap(),
                    LeaseCursor::new(1, 2).unwrap(),
                    ViewportGeometry::new(100, 30, 1280, 720).unwrap(),
                ),
            ])
            .unwrap(),
        };
        let encoded = serde_json::to_vec(&snapshot).unwrap();
        assert!(negotiated(true, true)
            .decode_remote_desktop_extension_frame(&encoded)
            .is_ok());
    }

    #[test]
    fn viewport_snapshot_rejects_foreign_epoch_future_entries_and_invalid_ttl() {
        for frame in [
            br#"{"type":"viewport_snapshot","request_id":10,"cursor":{"epoch":4,"sequence":8},"ttl_ms":5000,"viewports":[{"session_id":"s1","lease_id":"l1","cursor":{"epoch":5,"sequence":1},"geometry":{"cols":80,"rows":24,"pixel_width":800,"pixel_height":600}}]}"#.as_slice(),
            br#"{"type":"viewport_snapshot","request_id":10,"cursor":{"epoch":4,"sequence":8},"ttl_ms":5000,"viewports":[{"session_id":"s1","lease_id":"l1","cursor":{"epoch":4,"sequence":9},"geometry":{"cols":80,"rows":24,"pixel_width":800,"pixel_height":600}}]}"#.as_slice(),
            br#"{"type":"viewport_snapshot","request_id":10,"cursor":{"epoch":4,"sequence":8},"ttl_ms":0,"viewports":[]}"#.as_slice(),
        ] {
            assert!(negotiated(true, true)
                .decode_remote_desktop_extension_frame(frame)
                .is_err());
        }
    }
}
