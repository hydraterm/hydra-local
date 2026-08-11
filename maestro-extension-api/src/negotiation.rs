use crate::frame::{decode_bounded_json, FrameDecodeError};
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fmt;

pub const CURRENT_PROTOCOL_VERSION: u16 = 1;
pub const MAX_CAPABILITIES: usize = 32;
pub const MAX_CAPABILITY_NAME_BYTES: usize = 64;
const EXTERNAL_VIEWPORT_LEASE_V1: &str = "external_viewport_lease_v1";
const REMOTE_DESKTOP_LIFECYCLE_V1: &str = "remote_desktop_lifecycle_v1";
const FILESYSTEM_MODE_MIGRATION_V1: &str = "filesystem_mode_migration_v1";

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum KnownCapability {
    ExternalViewportLeaseV1,
    RemoteDesktopLifecycleV1,
    FilesystemModeMigrationV1,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(transparent)]
pub struct Capability(String);

impl Capability {
    pub fn new(name: impl Into<String>) -> Result<Self, ExtensionHelloError> {
        let name = name.into();
        if name.is_empty()
            || name.len() > MAX_CAPABILITY_NAME_BYTES
            || !name.bytes().all(|byte| {
                byte.is_ascii_lowercase()
                    || byte.is_ascii_digit()
                    || matches!(byte, b'_' | b'-' | b'.')
            })
        {
            return Err(ExtensionHelloError::InvalidCapabilityName);
        }
        Ok(Self(name))
    }

    pub fn external_viewport_lease_v1() -> Self {
        Self(EXTERNAL_VIEWPORT_LEASE_V1.to_string())
    }

    pub fn remote_desktop_lifecycle_v1() -> Self {
        Self(REMOTE_DESKTOP_LIFECYCLE_V1.to_string())
    }

    pub fn filesystem_mode_migration_v1() -> Self {
        Self(FILESYSTEM_MODE_MIGRATION_V1.to_string())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn known(&self) -> Option<KnownCapability> {
        match self.0.as_str() {
            EXTERNAL_VIEWPORT_LEASE_V1 => Some(KnownCapability::ExternalViewportLeaseV1),
            REMOTE_DESKTOP_LIFECYCLE_V1 => Some(KnownCapability::RemoteDesktopLifecycleV1),
            FILESYSTEM_MODE_MIGRATION_V1 => Some(KnownCapability::FilesystemModeMigrationV1),
            _ => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct ProtocolRange {
    min: u16,
    max: u16,
}

impl ProtocolRange {
    pub fn new(min: u16, max: u16) -> Result<Self, ExtensionHelloError> {
        if min == 0 || max == 0 || min > max {
            return Err(ExtensionHelloError::InvalidProtocolRange { min, max });
        }
        Ok(Self { min, max })
    }

    pub const fn current() -> Self {
        Self {
            min: CURRENT_PROTOCOL_VERSION,
            max: CURRENT_PROTOCOL_VERSION,
        }
    }

    pub const fn min(self) -> u16 {
        self.min
    }

    pub const fn max(self) -> u16 {
        self.max
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ExtensionHello {
    protocol: ProtocolRange,
    capabilities: Vec<Capability>,
}

impl ExtensionHello {
    pub fn new(
        protocol: ProtocolRange,
        capabilities: impl IntoIterator<Item = Capability>,
    ) -> Result<Self, ExtensionHelloError> {
        // Bound programmatic callers too: an untrusted or accidentally infinite iterator must not
        // be fully collected before the public limit is checked.
        let capabilities: Vec<_> = capabilities
            .into_iter()
            .take(MAX_CAPABILITIES + 1)
            .collect();
        if capabilities.len() > MAX_CAPABILITIES {
            return Err(ExtensionHelloError::TooManyCapabilities {
                got: capabilities.len(),
                max: MAX_CAPABILITIES,
            });
        }
        let unique: BTreeSet<_> = capabilities.iter().collect();
        if unique.len() != capabilities.len() {
            return Err(ExtensionHelloError::DuplicateCapability);
        }
        Ok(Self {
            protocol,
            capabilities,
        })
    }

    pub fn host(
        capabilities: impl IntoIterator<Item = Capability>,
    ) -> Result<Self, ExtensionHelloError> {
        Self::new(ProtocolRange::current(), capabilities)
    }

    pub const fn protocol(&self) -> ProtocolRange {
        self.protocol
    }

    pub fn capabilities(&self) -> &[Capability] {
        &self.capabilities
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireProtocolRange {
    min: u16,
    max: u16,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WireExtensionHello {
    protocol: WireProtocolRange,
    capabilities: Vec<String>,
}

pub fn decode_hello_frame(bytes: &[u8]) -> Result<ExtensionHello, ExtensionHelloError> {
    let wire: WireExtensionHello =
        decode_bounded_json(bytes).map_err(ExtensionHelloError::Frame)?;
    if wire.capabilities.len() > MAX_CAPABILITIES {
        return Err(ExtensionHelloError::TooManyCapabilities {
            got: wire.capabilities.len(),
            max: MAX_CAPABILITIES,
        });
    }
    let protocol = ProtocolRange::new(wire.protocol.min, wire.protocol.max)?;
    let capabilities = wire
        .capabilities
        .into_iter()
        .map(Capability::new)
        .collect::<Result<Vec<_>, _>>()?;
    ExtensionHello::new(protocol, capabilities)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NegotiatedExtension {
    protocol_version: u16,
    capabilities: BTreeSet<KnownCapability>,
}

impl NegotiatedExtension {
    pub const fn protocol_version(&self) -> u16 {
        self.protocol_version
    }

    pub fn supports(&self, capability: KnownCapability) -> bool {
        self.capabilities.contains(&capability)
    }

    pub fn capabilities(&self) -> impl Iterator<Item = KnownCapability> + '_ {
        self.capabilities.iter().copied()
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ExtensionHelloError {
    Frame(FrameDecodeError),
    InvalidProtocolRange { min: u16, max: u16 },
    InvalidCapabilityName,
    TooManyCapabilities { got: usize, max: usize },
    DuplicateCapability,
}

impl fmt::Display for ExtensionHelloError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Frame(error) => error.fmt(f),
            Self::InvalidProtocolRange { min, max } => {
                write!(f, "extension protocol range is invalid: {min}..={max}")
            }
            Self::InvalidCapabilityName => write!(f, "invalid extension capability name"),
            Self::TooManyCapabilities { got, max } => {
                write!(
                    f,
                    "extension advertised {got} capabilities; maximum is {max}"
                )
            }
            Self::DuplicateCapability => write!(f, "duplicate extension capability"),
        }
    }
}

impl std::error::Error for ExtensionHelloError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NegotiationError {
    NoCommonVersion {
        host: ProtocolRange,
        extension: ProtocolRange,
    },
}

impl fmt::Display for NegotiationError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoCommonVersion { host, extension } => write!(
                f,
                "no common extension protocol version (host {}..={}, extension {}..={})",
                host.min, host.max, extension.min, extension.max
            ),
        }
    }
}

impl std::error::Error for NegotiationError {}

pub fn negotiate(
    host: &ExtensionHello,
    extension: &ExtensionHello,
) -> Result<NegotiatedExtension, NegotiationError> {
    let min = host.protocol.min.max(extension.protocol.min);
    let max = host.protocol.max.min(extension.protocol.max);
    if min > max {
        return Err(NegotiationError::NoCommonVersion {
            host: host.protocol,
            extension: extension.protocol,
        });
    }

    let host_capabilities: BTreeSet<_> = host
        .capabilities
        .iter()
        .filter_map(Capability::known)
        .collect();
    let extension_capabilities: BTreeSet<_> = extension
        .capabilities
        .iter()
        .filter_map(Capability::known)
        .collect();
    let capabilities = host_capabilities
        .intersection(&extension_capabilities)
        .copied()
        .collect();

    Ok(NegotiatedExtension {
        protocol_version: max,
        capabilities,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::MAX_EXTENSION_FRAME_BYTES;

    fn hello(range: (u16, u16), capabilities: &[&str]) -> ExtensionHello {
        ExtensionHello::new(
            ProtocolRange::new(range.0, range.1).unwrap(),
            capabilities
                .iter()
                .map(|name| Capability::new(*name).unwrap()),
        )
        .unwrap()
    }

    #[test]
    fn negotiation_chooses_highest_common_version_and_known_intersection() {
        let host = hello((1, 3), &[EXTERNAL_VIEWPORT_LEASE_V1, "host_future"]);
        let extension = hello((2, 4), &[EXTERNAL_VIEWPORT_LEASE_V1, "peer_future"]);
        let negotiated = negotiate(&host, &extension).unwrap();
        assert_eq!(negotiated.protocol_version(), 3);
        assert!(negotiated.supports(KnownCapability::ExternalViewportLeaseV1));
        assert_eq!(negotiated.capabilities().count(), 1);
    }

    #[test]
    fn distinct_future_capabilities_are_preserved_and_ignored_not_rejected() {
        let decoded = decode_hello_frame(
            br#"{"protocol":{"min":1,"max":1},"capabilities":["external_viewport_lease_v1","future_a","future_b"]}"#,
        )
        .unwrap();
        assert_eq!(decoded.capabilities()[1].as_str(), "future_a");
        assert_eq!(decoded.capabilities()[2].as_str(), "future_b");

        let host = ExtensionHello::host([Capability::external_viewport_lease_v1()]).unwrap();
        let negotiated = negotiate(&host, &decoded).unwrap();
        assert!(negotiated.supports(KnownCapability::ExternalViewportLeaseV1));
        assert_eq!(negotiated.capabilities().count(), 1);
    }

    #[test]
    fn lifecycle_and_viewport_capabilities_negotiate_independently() {
        let host = ExtensionHello::host([
            Capability::external_viewport_lease_v1(),
            Capability::remote_desktop_lifecycle_v1(),
            Capability::filesystem_mode_migration_v1(),
        ])
        .unwrap();
        let lifecycle_only =
            ExtensionHello::host([Capability::remote_desktop_lifecycle_v1()]).unwrap();
        let negotiated = negotiate(&host, &lifecycle_only).unwrap();
        assert!(negotiated.supports(KnownCapability::RemoteDesktopLifecycleV1));
        assert!(!negotiated.supports(KnownCapability::ExternalViewportLeaseV1));
        assert!(!negotiated.supports(KnownCapability::FilesystemModeMigrationV1));

        let migration_only = ExtensionHello::host([
            Capability::remote_desktop_lifecycle_v1(),
            Capability::filesystem_mode_migration_v1(),
        ])
        .unwrap();
        let negotiated = negotiate(&host, &migration_only).unwrap();
        assert!(negotiated.supports(KnownCapability::RemoteDesktopLifecycleV1));
        assert!(negotiated.supports(KnownCapability::FilesystemModeMigrationV1));
        assert!(!negotiated.supports(KnownCapability::ExternalViewportLeaseV1));
    }

    #[test]
    fn invalid_or_disjoint_versions_fail_closed() {
        assert!(matches!(
            ProtocolRange::new(2, 1),
            Err(ExtensionHelloError::InvalidProtocolRange { .. })
        ));
        let current = ExtensionHello::host([]).unwrap();
        let future = hello((2, 2), &[]);
        assert!(matches!(
            negotiate(&current, &future),
            Err(NegotiationError::NoCommonVersion { .. })
        ));
    }

    #[test]
    fn duplicate_unbounded_or_malformed_capabilities_are_rejected() {
        assert!(matches!(
            ExtensionHello::host([
                Capability::external_viewport_lease_v1(),
                Capability::external_viewport_lease_v1(),
            ]),
            Err(ExtensionHelloError::DuplicateCapability)
        ));
        assert!(matches!(
            ExtensionHello::host(
                (0..=MAX_CAPABILITIES)
                    .map(|index| Capability::new(format!("future_{index}")).unwrap())
            ),
            Err(ExtensionHelloError::TooManyCapabilities { .. })
        ));
        assert!(Capability::new("UPPERCASE").is_err());
        assert!(Capability::new("contains/path").is_err());

        let infinite = std::iter::repeat_with(|| Capability::new("future").unwrap());
        assert!(matches!(
            ExtensionHello::host(infinite),
            Err(ExtensionHelloError::TooManyCapabilities {
                got,
                max: MAX_CAPABILITIES
            }) if got == MAX_CAPABILITIES + 1
        ));
    }

    #[test]
    fn bounded_decoder_rejects_oversize_unknown_fields_and_invalid_ranges() {
        assert!(matches!(
            decode_hello_frame(&vec![b' '; MAX_EXTENSION_FRAME_BYTES + 1]),
            Err(ExtensionHelloError::Frame(
                FrameDecodeError::TooLarge { .. }
            ))
        ));
        assert!(decode_hello_frame(
            br#"{"protocol":{"min":1,"max":1},"capabilities":[],"command":"sh"}"#
        )
        .is_err());
        assert!(
            decode_hello_frame(br#"{"protocol":{"min":0,"max":1},"capabilities":[]}"#).is_err()
        );
    }
}
