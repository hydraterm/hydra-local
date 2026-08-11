use crate::frame::{decode_bounded_json, FrameDecodeError};
use crate::negotiation::{KnownCapability, NegotiatedExtension};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::fmt;

pub const MAX_OPAQUE_ID_BYTES: usize = 128;
pub const MAX_TERMINAL_DIMENSION: u16 = 2000;
pub const MAX_VIEWPORT_PIXEL_DIMENSION: u32 = 32_768;
pub const MAX_LEASE_TTL_MS: u32 = 30_000;
pub const MAX_ACTIVE_VIEWPORT_LEASES: usize = 64;

fn validate_opaque_id(kind: &'static str, value: &str) -> Result<(), ViewportMessageError> {
    if value.is_empty()
        || value.len() > MAX_OPAQUE_ID_BYTES
        || value
            .chars()
            .any(|character| !character.is_ascii_graphic() || matches!(character, '/' | '\\'))
    {
        return Err(ViewportMessageError::InvalidOpaqueId { kind });
    }
    Ok(())
}

macro_rules! opaque_id {
    ($name:ident, $kind:literal) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, Serialize)]
        #[serde(transparent)]
        pub struct $name(String);

        impl $name {
            pub fn new(value: impl Into<String>) -> Result<Self, ViewportMessageError> {
                let value = value.into();
                validate_opaque_id($kind, &value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }
    };
}

opaque_id!(LeaseId, "lease_id");
opaque_id!(SessionKey, "session_id");

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct LeaseCursor {
    epoch: u64,
    sequence: u64,
}

impl LeaseCursor {
    pub fn new(epoch: u64, sequence: u64) -> Result<Self, ViewportMessageError> {
        if epoch == 0 || sequence == 0 {
            return Err(ViewportMessageError::ZeroCursor);
        }
        Ok(Self { epoch, sequence })
    }

    pub const fn epoch(self) -> u64 {
        self.epoch
    }

    pub const fn sequence(self) -> u64 {
        self.sequence
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ViewportGeometry {
    cols: u16,
    rows: u16,
    pixel_width: u32,
    pixel_height: u32,
}

impl ViewportGeometry {
    pub fn new(
        cols: u16,
        rows: u16,
        pixel_width: u32,
        pixel_height: u32,
    ) -> Result<Self, ViewportMessageError> {
        if cols == 0 || rows == 0 || cols > MAX_TERMINAL_DIMENSION || rows > MAX_TERMINAL_DIMENSION
        {
            return Err(ViewportMessageError::InvalidCellDimensions { cols, rows });
        }
        if pixel_width == 0
            || pixel_height == 0
            || pixel_width > MAX_VIEWPORT_PIXEL_DIMENSION
            || pixel_height > MAX_VIEWPORT_PIXEL_DIMENSION
        {
            return Err(ViewportMessageError::InvalidPixelDimensions {
                width: pixel_width,
                height: pixel_height,
            });
        }
        Ok(Self {
            cols,
            rows,
            pixel_width,
            pixel_height,
        })
    }

    pub const fn cols(self) -> u16 {
        self.cols
    }

    pub const fn rows(self) -> u16 {
        self.rows
    }

    pub const fn pixel_width(self) -> u32 {
        self.pixel_width
    }

    pub const fn pixel_height(self) -> u32 {
        self.pixel_height
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExternalViewportLease {
    lease_id: LeaseId,
    session_id: SessionKey,
    cursor: LeaseCursor,
    geometry: ViewportGeometry,
    ttl_ms: u32,
}

impl ExternalViewportLease {
    pub fn new(
        lease_id: LeaseId,
        session_id: SessionKey,
        cursor: LeaseCursor,
        geometry: ViewportGeometry,
        ttl_ms: u32,
    ) -> Result<Self, ViewportMessageError> {
        if ttl_ms == 0 || ttl_ms > MAX_LEASE_TTL_MS {
            return Err(ViewportMessageError::InvalidTtl {
                got: ttl_ms,
                max: MAX_LEASE_TTL_MS,
            });
        }
        Ok(Self {
            lease_id,
            session_id,
            cursor,
            geometry,
            ttl_ms,
        })
    }

    pub fn lease_id(&self) -> &LeaseId {
        &self.lease_id
    }

    pub fn session_id(&self) -> &SessionKey {
        &self.session_id
    }

    pub const fn cursor(&self) -> LeaseCursor {
        self.cursor
    }

    pub const fn geometry(&self) -> ViewportGeometry {
        self.geometry
    }

    pub const fn ttl_ms(&self) -> u32 {
        self.ttl_ms
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum ExtensionToHost {
    UpsertViewportLease {
        lease: ExternalViewportLease,
    },
    ReleaseViewportLease {
        lease_id: LeaseId,
        cursor: LeaseCursor,
    },
    ReleaseAllViewportLeases {
        cursor: LeaseCursor,
    },
}

impl ExtensionToHost {
    fn cursor(&self) -> LeaseCursor {
        match self {
            Self::UpsertViewportLease { lease } => lease.cursor,
            Self::ReleaseViewportLease { cursor, .. }
            | Self::ReleaseAllViewportLeases { cursor } => *cursor,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ViewportReclaimReason {
    UserRequested,
    LocalViewportFocused,
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

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct ReclaimRequestId(u64);

impl ReclaimRequestId {
    pub fn new(value: u64) -> Result<Self, ViewportMessageError> {
        if value == 0 {
            return Err(ViewportMessageError::ZeroRequestId);
        }
        Ok(Self(value))
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum HostToExtension {
    RequestViewportReclaim {
        request_id: ReclaimRequestId,
        session_id: SessionKey,
        lease_id: LeaseId,
        cursor: LeaseCursor,
        reason: ViewportReclaimReason,
    },
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireCursor {
    epoch: u64,
    sequence: u64,
}

impl TryFrom<WireCursor> for LeaseCursor {
    type Error = ViewportMessageError;

    fn try_from(value: WireCursor) -> Result<Self, Self::Error> {
        Self::new(value.epoch, value.sequence)
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

impl TryFrom<WireGeometry> for ViewportGeometry {
    type Error = ViewportMessageError;

    fn try_from(value: WireGeometry) -> Result<Self, Self::Error> {
        Self::new(
            value.cols,
            value.rows,
            value.pixel_width,
            value.pixel_height,
        )
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireLease {
    lease_id: String,
    session_id: String,
    cursor: WireCursor,
    geometry: WireGeometry,
    ttl_ms: u32,
}

impl TryFrom<WireLease> for ExternalViewportLease {
    type Error = ViewportMessageError;

    fn try_from(value: WireLease) -> Result<Self, Self::Error> {
        Self::new(
            LeaseId::new(value.lease_id)?,
            SessionKey::new(value.session_id)?,
            value.cursor.try_into()?,
            value.geometry.try_into()?,
            value.ttl_ms,
        )
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WireExtensionToHost {
    UpsertViewportLease {
        lease: WireLease,
    },
    ReleaseViewportLease {
        lease_id: String,
        cursor: WireCursor,
    },
    ReleaseAllViewportLeases {
        cursor: WireCursor,
    },
}

impl TryFrom<WireExtensionToHost> for ExtensionToHost {
    type Error = ViewportMessageError;

    fn try_from(value: WireExtensionToHost) -> Result<Self, Self::Error> {
        match value {
            WireExtensionToHost::UpsertViewportLease { lease } => Ok(Self::UpsertViewportLease {
                lease: lease.try_into()?,
            }),
            WireExtensionToHost::ReleaseViewportLease { lease_id, cursor } => {
                Ok(Self::ReleaseViewportLease {
                    lease_id: LeaseId::new(lease_id)?,
                    cursor: cursor.try_into()?,
                })
            }
            WireExtensionToHost::ReleaseAllViewportLeases { cursor } => {
                Ok(Self::ReleaseAllViewportLeases {
                    cursor: cursor.try_into()?,
                })
            }
        }
    }
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum WireHostToExtension {
    RequestViewportReclaim {
        request_id: u64,
        session_id: String,
        lease_id: String,
        cursor: WireCursor,
        reason: WireViewportReclaimReason,
    },
}

impl TryFrom<WireHostToExtension> for HostToExtension {
    type Error = ViewportMessageError;

    fn try_from(value: WireHostToExtension) -> Result<Self, Self::Error> {
        match value {
            WireHostToExtension::RequestViewportReclaim {
                request_id,
                session_id,
                lease_id,
                cursor,
                reason,
            } => Ok(Self::RequestViewportReclaim {
                request_id: ReclaimRequestId::new(request_id)?,
                session_id: SessionKey::new(session_id)?,
                lease_id: LeaseId::new(lease_id)?,
                cursor: cursor.try_into()?,
                reason: reason.into(),
            }),
        }
    }
}

impl NegotiatedExtension {
    fn require_viewport_capability(&self) -> Result<(), ViewportDecodeError> {
        if self.supports(KnownCapability::ExternalViewportLeaseV1) {
            Ok(())
        } else {
            Err(ViewportDecodeError::CapabilityNotNegotiated)
        }
    }

    pub fn decode_extension_frame(
        &self,
        bytes: &[u8],
    ) -> Result<ExtensionToHost, ViewportDecodeError> {
        self.require_viewport_capability()?;
        let wire = decode_bounded_json::<WireExtensionToHost>(bytes)
            .map_err(ViewportDecodeError::Frame)?;
        wire.try_into().map_err(ViewportDecodeError::Message)
    }

    pub fn decode_host_frame(&self, bytes: &[u8]) -> Result<HostToExtension, ViewportDecodeError> {
        self.require_viewport_capability()?;
        let wire = decode_bounded_json::<WireHostToExtension>(bytes)
            .map_err(ViewportDecodeError::Frame)?;
        wire.try_into().map_err(ViewportDecodeError::Message)
    }

    pub fn viewport_lease_book(&self) -> Result<ViewportLeaseBook, ViewportApplyError> {
        if self.supports(KnownCapability::ExternalViewportLeaseV1) {
            Ok(ViewportLeaseBook::new())
        } else {
            Err(ViewportApplyError::CapabilityNotNegotiated)
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewportDecodeError {
    CapabilityNotNegotiated,
    Frame(FrameDecodeError),
    Message(ViewportMessageError),
}

impl fmt::Display for ViewportDecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityNotNegotiated => {
                write!(f, "external viewport lease capability was not negotiated")
            }
            Self::Frame(error) => error.fmt(f),
            Self::Message(error) => error.fmt(f),
        }
    }
}

impl std::error::Error for ViewportDecodeError {}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ActiveLease {
    lease: ExternalViewportLease,
    expires_at_ms: u64,
}

#[derive(Debug)]
pub struct ViewportLeaseBook {
    connection_epoch: Option<u64>,
    last_sequence: u64,
    leases: HashMap<LeaseId, ActiveLease>,
}

impl ViewportLeaseBook {
    fn new() -> Self {
        Self {
            connection_epoch: None,
            last_sequence: 0,
            leases: HashMap::new(),
        }
    }

    pub fn apply(
        &mut self,
        message: ExtensionToHost,
        received_at_ms: u64,
    ) -> Result<LeaseApplyOutcome, ViewportApplyError> {
        let cursor = message.cursor();
        // A replayed, out-of-order, or wrong-epoch frame has no authority to mutate even TTL
        // state. Callers may expire independently on their local clock, but rejected input must be
        // observationally read-only.
        self.check_cursor(cursor)?;
        let expired = self.expire(received_at_ms);

        let changed = match message {
            ExtensionToHost::UpsertViewportLease { lease } => {
                let existing = self.leases.get(&lease.lease_id);
                if let Some(existing) = existing {
                    if existing.lease.session_id != lease.session_id {
                        return Err(ViewportApplyError::LeaseIdRebound);
                    }
                } else {
                    if self
                        .leases
                        .values()
                        .any(|active| active.lease.session_id == lease.session_id)
                    {
                        return Err(ViewportApplyError::SessionAlreadyLeased);
                    }
                    if self.leases.len() >= MAX_ACTIVE_VIEWPORT_LEASES {
                        return Err(ViewportApplyError::TooManyActiveLeases {
                            max: MAX_ACTIVE_VIEWPORT_LEASES,
                        });
                    }
                }
                let active = ActiveLease {
                    expires_at_ms: received_at_ms.saturating_add(u64::from(lease.ttl_ms)),
                    lease,
                };
                self.leases
                    .insert(active.lease.lease_id.clone(), active.clone())
                    .as_ref()
                    != Some(&active)
            }
            ExtensionToHost::ReleaseViewportLease { lease_id, .. } => {
                self.leases.remove(&lease_id).is_some()
            }
            ExtensionToHost::ReleaseAllViewportLeases { .. } => {
                let changed = !self.leases.is_empty();
                self.leases.clear();
                changed
            }
        };

        self.connection_epoch = Some(cursor.epoch);
        self.last_sequence = cursor.sequence;
        Ok(LeaseApplyOutcome { changed, expired })
    }

    fn check_cursor(&self, cursor: LeaseCursor) -> Result<(), ViewportApplyError> {
        if let Some(expected) = self.connection_epoch {
            if cursor.epoch != expected {
                return Err(ViewportApplyError::UnexpectedEpoch {
                    expected,
                    got: cursor.epoch,
                });
            }
        }
        if cursor.sequence <= self.last_sequence {
            return Err(ViewportApplyError::StaleSequence {
                last: self.last_sequence,
                got: cursor.sequence,
            });
        }
        Ok(())
    }

    pub fn expire(&mut self, now_ms: u64) -> usize {
        let before = self.leases.len();
        self.leases
            .retain(|_, active| active.expires_at_ms > now_ms);
        before - self.leases.len()
    }

    pub fn lease_for_session(
        &mut self,
        session_id: &SessionKey,
        now_ms: u64,
    ) -> Option<&ExternalViewportLease> {
        self.expire(now_ms);
        self.leases
            .values()
            .find(|active| &active.lease.session_id == session_id)
            .map(|active| &active.lease)
    }

    pub fn reclaim_request(
        &mut self,
        request_id: u64,
        session_id: &SessionKey,
        reason: ViewportReclaimReason,
        now_ms: u64,
    ) -> Result<HostToExtension, ViewportApplyError> {
        let request_id =
            ReclaimRequestId::new(request_id).map_err(|_| ViewportApplyError::ZeroRequestId)?;
        let lease = self
            .lease_for_session(session_id, now_ms)
            .ok_or(ViewportApplyError::SessionNotLeased)?;
        Ok(HostToExtension::RequestViewportReclaim {
            request_id,
            session_id: lease.session_id.clone(),
            lease_id: lease.lease_id.clone(),
            cursor: lease.cursor,
            reason,
        })
    }

    pub fn clear_on_disconnect(&mut self) {
        self.connection_epoch = None;
        self.last_sequence = 0;
        self.leases.clear();
    }

    pub fn len(&self) -> usize {
        self.leases.len()
    }

    pub fn is_empty(&self) -> bool {
        self.leases.is_empty()
    }

    pub const fn connection_epoch(&self) -> Option<u64> {
        self.connection_epoch
    }

    pub const fn last_sequence(&self) -> u64 {
        self.last_sequence
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LeaseApplyOutcome {
    changed: bool,
    expired: usize,
}

impl LeaseApplyOutcome {
    pub const fn changed(self) -> bool {
        self.changed
    }

    pub const fn expired(self) -> usize {
        self.expired
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewportApplyError {
    CapabilityNotNegotiated,
    UnexpectedEpoch { expected: u64, got: u64 },
    StaleSequence { last: u64, got: u64 },
    TooManyActiveLeases { max: usize },
    LeaseIdRebound,
    SessionAlreadyLeased,
    SessionNotLeased,
    ZeroRequestId,
}

impl fmt::Display for ViewportApplyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::CapabilityNotNegotiated => {
                write!(f, "external viewport lease capability was not negotiated")
            }
            Self::UnexpectedEpoch { expected, got } => {
                write!(f, "unexpected lease epoch {got}; expected {expected}")
            }
            Self::StaleSequence { last, got } => {
                write!(f, "stale lease sequence {got}; last accepted is {last}")
            }
            Self::TooManyActiveLeases { max } => {
                write!(f, "active viewport lease limit reached ({max})")
            }
            Self::LeaseIdRebound => write!(f, "lease id cannot move to another session"),
            Self::SessionAlreadyLeased => write!(f, "session already has an active lease"),
            Self::SessionNotLeased => write!(f, "session has no active viewport lease"),
            Self::ZeroRequestId => write!(f, "request_id must be nonzero"),
        }
    }
}

impl std::error::Error for ViewportApplyError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ViewportMessageError {
    InvalidOpaqueId { kind: &'static str },
    ZeroCursor,
    ZeroRequestId,
    InvalidCellDimensions { cols: u16, rows: u16 },
    InvalidPixelDimensions { width: u32, height: u32 },
    InvalidTtl { got: u32, max: u32 },
}

impl fmt::Display for ViewportMessageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidOpaqueId { kind } => write!(f, "invalid opaque {kind}"),
            Self::ZeroCursor => write!(f, "lease epoch and sequence must be nonzero"),
            Self::ZeroRequestId => write!(f, "request_id must be nonzero"),
            Self::InvalidCellDimensions { cols, rows } => {
                write!(f, "invalid terminal cell dimensions {cols}x{rows}")
            }
            Self::InvalidPixelDimensions { width, height } => {
                write!(f, "invalid viewport pixel dimensions {width}x{height}")
            }
            Self::InvalidTtl { got, max } => {
                write!(f, "invalid viewport lease ttl {got}ms; maximum is {max}ms")
            }
        }
    }
}

impl std::error::Error for ViewportMessageError {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::negotiation::{negotiate, Capability, ExtensionHello};
    use crate::MAX_EXTENSION_FRAME_BYTES;

    fn negotiated(with_viewport: bool) -> NegotiatedExtension {
        let capabilities = with_viewport
            .then(Capability::external_viewport_lease_v1)
            .into_iter();
        let hello = ExtensionHello::host(capabilities).unwrap();
        negotiate(&hello, &hello).unwrap()
    }

    fn upsert_json(lease: &str, session: &str, epoch: u64, sequence: u64, ttl: u32) -> Vec<u8> {
        format!(
            r#"{{"type":"upsert_viewport_lease","lease":{{"lease_id":"{lease}","session_id":"{session}","cursor":{{"epoch":{epoch},"sequence":{sequence}}},"geometry":{{"cols":120,"rows":40,"pixel_width":1920,"pixel_height":1080}},"ttl_ms":{ttl}}}}}"#
        )
        .into_bytes()
    }

    fn release_all_json(epoch: u64, sequence: u64) -> Vec<u8> {
        format!(
            r#"{{"type":"release_all_viewport_leases","cursor":{{"epoch":{epoch},"sequence":{sequence}}}}}"#
        )
        .into_bytes()
    }

    #[test]
    fn bounded_decoder_is_capability_gated_and_semantically_validated() {
        let bytes = upsert_json("lease-1", "session-1", 7, 1, 10_000);
        assert!(matches!(
            negotiated(false).decode_extension_frame(&bytes),
            Err(ViewportDecodeError::CapabilityNotNegotiated)
        ));
        let decoded = negotiated(true).decode_extension_frame(&bytes).unwrap();
        assert_eq!(
            serde_json::to_value(decoded).unwrap()["lease"]["session_id"],
            "session-1"
        );

        assert!(matches!(
            negotiated(true).decode_extension_frame(&vec![b' '; MAX_EXTENSION_FRAME_BYTES + 1]),
            Err(ViewportDecodeError::Frame(
                FrameDecodeError::TooLarge { .. }
            ))
        ));
        assert!(matches!(
            negotiated(true).decode_extension_frame(&upsert_json("lease", "session", 0, 1, 10)),
            Err(ViewportDecodeError::Message(
                ViewportMessageError::ZeroCursor
            ))
        ));
        assert!(matches!(
            negotiated(true).decode_extension_frame(&upsert_json("lease", "session", 1, 1, 0)),
            Err(ViewportDecodeError::Message(
                ViewportMessageError::InvalidTtl { .. }
            ))
        ));
    }

    #[test]
    fn decoder_rejects_unknown_fields_paths_bad_geometry_and_zero_request_id() {
        let session = negotiated(true);
        assert!(session
            .decode_extension_frame(
                br#"{"type":"release_all_viewport_leases","cursor":{"epoch":1,"sequence":1},"command":"sh"}"#
            )
            .is_err());
        assert!(session
            .decode_extension_frame(
                br#"{"type":"release_viewport_lease","lease_id":"/tmp/lease","cursor":{"epoch":1,"sequence":1}}"#
            )
            .is_err());
        let bad_geometry = upsert_json("lease", "session", 1, 1, 10)
            .into_iter()
            .collect::<Vec<_>>();
        let bad_geometry = String::from_utf8(bad_geometry)
            .unwrap()
            .replace("\"cols\":120", "\"cols\":0");
        assert!(session
            .decode_extension_frame(bad_geometry.as_bytes())
            .is_err());
        assert!(session
            .decode_host_frame(
                br#"{"type":"request_viewport_reclaim","request_id":0,"session_id":"session","lease_id":"lease","cursor":{"epoch":1,"sequence":1},"reason":"user_requested"}"#
            )
            .is_err());
    }

    #[test]
    fn lease_book_pins_epoch_and_rejects_replay_before_mutation() {
        let session = negotiated(true);
        let mut book = session.viewport_lease_book().unwrap();
        let first = session
            .decode_extension_frame(&upsert_json("lease-1", "session-1", 9, 1, 100))
            .unwrap();
        book.apply(first, 1_000).unwrap();
        assert_eq!(book.connection_epoch(), Some(9));
        assert_eq!(book.last_sequence(), 1);

        let replay = session
            .decode_extension_frame(&upsert_json("lease-1", "session-1", 9, 1, 100))
            .unwrap();
        assert!(matches!(
            book.apply(replay, 1_001),
            Err(ViewportApplyError::StaleSequence { .. })
        ));
        let other_epoch = session
            .decode_extension_frame(&upsert_json("lease-1", "session-1", 10, 2, 100))
            .unwrap();
        assert!(matches!(
            book.apply(other_epoch, 1_001),
            Err(ViewportApplyError::UnexpectedEpoch { .. })
        ));
        assert_eq!(book.last_sequence(), 1);
        assert_eq!(book.len(), 1);
    }

    #[test]
    fn rejected_replay_cannot_expire_live_state_with_a_far_future_timestamp() {
        let session = negotiated(true);
        let mut book = session.viewport_lease_book().unwrap();
        let first = session
            .decode_extension_frame(&upsert_json("lease-1", "session-1", 9, 1, 100))
            .unwrap();
        book.apply(first, 1_000).unwrap();

        let replay = session
            .decode_extension_frame(&release_all_json(9, 1))
            .unwrap();
        assert!(matches!(
            book.apply(replay, u64::MAX),
            Err(ViewportApplyError::StaleSequence { .. })
        ));
        assert_eq!(book.len(), 1);
        assert_eq!(book.last_sequence(), 1);
    }

    #[test]
    fn active_lease_cap_is_enforced_without_eviction_or_cursor_advance() {
        let session = negotiated(true);
        let mut book = session.viewport_lease_book().unwrap();
        for index in 0..MAX_ACTIVE_VIEWPORT_LEASES {
            let message = session
                .decode_extension_frame(&upsert_json(
                    &format!("lease-{index}"),
                    &format!("session-{index}"),
                    3,
                    index as u64 + 1,
                    1_000,
                ))
                .unwrap();
            book.apply(message, 100).unwrap();
        }
        let overflow_sequence = MAX_ACTIVE_VIEWPORT_LEASES as u64 + 1;
        let overflow = session
            .decode_extension_frame(&upsert_json(
                "lease-overflow",
                "session-overflow",
                3,
                overflow_sequence,
                1_000,
            ))
            .unwrap();
        assert!(matches!(
            book.apply(overflow, 100),
            Err(ViewportApplyError::TooManyActiveLeases { .. })
        ));
        assert_eq!(book.len(), MAX_ACTIVE_VIEWPORT_LEASES);
        assert_eq!(book.last_sequence(), MAX_ACTIVE_VIEWPORT_LEASES as u64);
    }

    #[test]
    fn ttl_release_all_and_disconnect_have_exact_state_semantics() {
        let session = negotiated(true);
        let mut book = session.viewport_lease_book().unwrap();
        let first = session
            .decode_extension_frame(&upsert_json("lease-1", "session-1", 5, 1, 10))
            .unwrap();
        book.apply(first, 100).unwrap();
        let session_id = SessionKey::new("session-1").unwrap();
        assert!(book.lease_for_session(&session_id, 109).is_some());
        assert!(book.lease_for_session(&session_id, 110).is_none());

        let second = session
            .decode_extension_frame(&upsert_json("lease-2", "session-2", 5, 2, 10))
            .unwrap();
        book.apply(second, 200).unwrap();
        let release_all = session
            .decode_extension_frame(&release_all_json(5, 3))
            .unwrap();
        assert!(book.apply(release_all, 201).unwrap().changed());
        assert!(book.is_empty());

        let third = session
            .decode_extension_frame(&upsert_json("lease-3", "session-3", 5, 4, 10))
            .unwrap();
        book.apply(third, 300).unwrap();
        book.clear_on_disconnect();
        assert!(book.is_empty());
        assert_eq!(book.connection_epoch(), None);
        assert_eq!(book.last_sequence(), 0);
    }

    #[test]
    fn reclaim_is_exact_and_requires_a_live_lease() {
        let session = negotiated(true);
        let mut book = session.viewport_lease_book().unwrap();
        let session_id = SessionKey::new("session-1").unwrap();
        assert!(matches!(
            book.reclaim_request(1, &session_id, ViewportReclaimReason::UserRequested, 100),
            Err(ViewportApplyError::SessionNotLeased)
        ));
        let lease = session
            .decode_extension_frame(&upsert_json("lease-1", "session-1", 8, 1, 100))
            .unwrap();
        book.apply(lease, 100).unwrap();
        let reclaim = book
            .reclaim_request(
                7,
                &session_id,
                ViewportReclaimReason::LocalViewportFocused,
                101,
            )
            .unwrap();
        let encoded = serde_json::to_string(&reclaim).unwrap();
        assert!(encoded.contains("request_viewport_reclaim"));
        assert!(!encoded.contains("command"));
        assert!(!encoded.contains("path"));
    }
}
