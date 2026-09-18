//! Agent-owned release trust.
//!
//! The build pins an official or explicitly self-managed tuple in `build.rs`. Desktop code
//! may start the optional agent, but it cannot choose the cloud API, browser
//! origin, or token verifier through argv or ambient runtime configuration.

use anyhow::{bail, Context, Result};
use base64::Engine as _;
use ed25519_dalek::VerifyingKey;

pub const ENVIRONMENT: &str = env!("HYDRA_RELEASE_ENVIRONMENT");
pub const CLOUD_BASE: &str = env!("HYDRA_RELEASE_CLOUD_BASE");
pub const ALLOWED_ORIGIN: &str = env!("HYDRA_RELEASE_ALLOWED_ORIGIN");
pub const CLOUD_PUBKEY: &str = env!("HYDRA_RELEASE_CLOUD_PUBKEY");

// Retain the exact descriptor-derived binding in the private executable. Release signing runs on
// macOS and cannot execute Linux arm64/amd64 artifacts, so the cohort verifier reads this bounded
// object section directly. Referencing it through `binding_json` also prevents linker collection.
#[cfg(any(target_os = "linux", target_os = "macos"))]
#[used]
#[cfg_attr(target_os = "linux", link_section = ".hydra.agent_binding")]
#[cfg_attr(target_os = "macos", link_section = "__DATA,__hydra_agent")]
static PACKAGED_AGENT_BINDING: [u8; include_bytes!(concat!(
    env!("OUT_DIR"),
    "/agent_release_binding.json"
))
.len()] = *include_bytes!(concat!(env!("OUT_DIR"), "/agent_release_binding.json"));

pub fn binding_json() -> &'static str {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        std::str::from_utf8(&PACKAGED_AGENT_BINDING)
            .expect("build script emits UTF-8 agent release binding JSON")
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        include_str!(concat!(env!("OUT_DIR"), "/agent_release_binding.json"))
    }
}

/// Runtime flags that used to let a launcher replace agent trust or identity.
/// They are rejected before any command performs I/O.
pub const FORBIDDEN_RUNTIME_FLAGS: [&str; 7] = [
    "--environment",
    "--expected-cloud",
    "--cloud",
    "--cloud-pubkey",
    "--allowed-origin",
    "--account",
    "--device-id",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReleaseTrust {
    pub environment: &'static str,
    pub cloud_base: &'static str,
    pub allowed_origin: &'static str,
    pub cloud_pubkey: &'static str,
}

pub const fn active() -> ReleaseTrust {
    ReleaseTrust {
        environment: ENVIRONMENT,
        cloud_base: CLOUD_BASE,
        allowed_origin: ALLOWED_ORIGIN,
        cloud_pubkey: CLOUD_PUBKEY,
    }
}

impl ReleaseTrust {
    /// Validate the compile-time tuple before it is used as authority. This is
    /// intentionally cheap and can be called at each process entry point.
    pub fn validate(self) -> Result<Self> {
        if !matches!(self.environment, "production" | "staging" | "self-managed") {
            bail!("agent release environment is not recognized");
        }
        if !exact_https_origin(self.cloud_base) {
            bail!("agent release cloud origin is invalid");
        }
        if !exact_https_origin(self.allowed_origin) {
            bail!("agent release browser origin is invalid");
        }
        let _ = self.verifying_key()?;
        Ok(self)
    }

    pub fn verifying_key(self) -> Result<VerifyingKey> {
        let bytes = base64::engine::general_purpose::STANDARD
            .decode(self.cloud_pubkey)
            .context("agent release token verifier is not base64")?;
        let bytes: [u8; 32] = bytes
            .as_slice()
            .try_into()
            .map_err(|_| anyhow::anyhow!("agent release token verifier must be 32 bytes"))?;
        VerifyingKey::from_bytes(&bytes)
            .map_err(|_| anyhow::anyhow!("agent release token verifier is invalid"))
    }

    pub fn validate_enrollment(self, record: &crate::device_identity::DeviceRecord) -> Result<()> {
        self.validate()?;
        if record.cloud_base.trim_end_matches('/') != self.cloud_base {
            bail!(
                "enrollment cloud does not match this agent release; remove remote access and re-enroll"
            );
        }
        Ok(())
    }
}

pub fn reject_runtime_overrides(args: &[String]) -> Result<()> {
    for argument in args.iter().skip(2) {
        if FORBIDDEN_RUNTIME_FLAGS.iter().any(|flag| {
            argument == flag
                || argument
                    .strip_prefix(flag)
                    .is_some_and(|suffix| suffix.starts_with('='))
        }) {
            bail!(
                "runtime cloud, origin, verifier, environment, and identity overrides are unavailable; this agent uses its compiled release trust"
            );
        }
    }
    Ok(())
}

fn exact_https_origin(value: &str) -> bool {
    let Ok(url) = reqwest::Url::parse(value) else {
        return false;
    };
    url.scheme() == "https"
        && url.username().is_empty()
        && url.password().is_none()
        && url.query().is_none()
        && url.fragment().is_none()
        && url.path() == "/"
        && url.origin().ascii_serialization() == value
}

#[cfg(test)]
#[path = "../build_support.rs"]
mod build_support;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn compiled_tuple_is_complete_and_cryptographically_valid() {
        let trust = active().validate().unwrap();
        assert!(matches!(
            trust.environment,
            "production" | "staging" | "self-managed"
        ));
        assert!(trust.cloud_base.starts_with("https://"));
        if trust.environment != "self-managed" {
            assert!(trust.cloud_base.starts_with("https://api."));
        }
        assert!(trust.allowed_origin.starts_with("https://"));
        assert_eq!(trust.verifying_key().unwrap().to_bytes().len(), 32);
        let binding: serde_json::Value = serde_json::from_str(binding_json()).unwrap();
        assert_eq!(binding["environment"], trust.environment);
        assert_eq!(binding["api_origin"], trust.cloud_base);
        assert_eq!(binding["app_origin"], trust.allowed_origin);
        assert_eq!(binding["token_verification_public_key"], trust.cloud_pubkey);
        assert_eq!(binding["descriptor_sha256"].as_str().unwrap().len(), 64);
    }

    #[test]
    fn every_legacy_runtime_trust_override_is_rejected_without_echoing_its_value() {
        for flag in FORBIDDEN_RUNTIME_FLAGS {
            for args in [
                vec!["hydra-agent", "remote-peer", flag, "attacker-value"],
                vec![
                    "hydra-agent",
                    "remote-peer",
                    &format!("{flag}=attacker-value"),
                ],
            ] {
                let args = args.into_iter().map(str::to_string).collect::<Vec<_>>();
                let error = reject_runtime_overrides(&args).unwrap_err().to_string();
                assert!(!error.contains("attacker-value"));
            }
        }
    }

    #[test]
    fn enrollment_must_match_the_compiled_cloud_exactly() {
        let record = crate::device_identity::DeviceRecord {
            device_id: "device".into(),
            account_id: "account".into(),
            cloud_base: active().cloud_base.into(),
            passkey: None,
        };
        active().validate_enrollment(&record).unwrap();
        let mut wrong = record;
        wrong.cloud_base = "https://attacker.invalid".into();
        assert!(active().validate_enrollment(&wrong).is_err());
    }
}
