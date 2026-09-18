//! Public, build-time-only trust input. Never read by the running agent.

use base64::Engine as _;
use serde::Deserialize;
use sha2::{Digest as _, Sha256};
use std::path::{Path, PathBuf};

pub const MAX_DESCRIPTOR_BYTES: usize = 16 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SelfManagedTrust {
    schema: u32,
    pub app_origin: String,
    pub api_origin: String,
    pub token_verification_public_key: String,
}

/// Explicit selection only: missing official configuration never falls back to this input.
pub fn self_managed_path(
    manifest_dir: &Path,
    official_selector_present: bool,
    path: Option<PathBuf>,
) -> Result<Option<PathBuf>, &'static str> {
    match path {
        None => Ok(None),
        Some(_) if official_selector_present => {
            Err("official and self-managed agent build selectors cannot be combined")
        }
        Some(path) if path.as_os_str().is_empty() => {
            Err("self-managed agent descriptor path must not be empty")
        }
        Some(path) => Ok(Some(manifest_dir.join(path))),
    }
}

impl SelfManagedTrust {
    pub fn parse(raw: &[u8]) -> Result<Self, &'static str> {
        if raw.len() > MAX_DESCRIPTOR_BYTES {
            return Err("self-managed agent descriptor is too large");
        }
        let value: Self = serde_json::from_slice(raw)
            .map_err(|_| "invalid self-managed agent descriptor structure")?;
        if value.schema != 1 {
            return Err("unsupported self-managed agent descriptor schema");
        }
        if !exact_https_origin(&value.app_origin) || !exact_https_origin(&value.api_origin) {
            return Err("self-managed agent requires canonical HTTPS origins");
        }
        let key = &value.token_verification_public_key;
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(key)
            .map_err(|_| "self-managed agent verifier must be canonical base64")?;
        let bytes: [u8; 32] = decoded
            .as_slice()
            .try_into()
            .map_err(|_| "self-managed agent verifier must be a 32-byte public key")?;
        if base64::engine::general_purpose::STANDARD.encode(bytes) != *key
            || ed25519_dalek::VerifyingKey::from_bytes(&bytes).is_err()
        {
            return Err("self-managed agent verifier is invalid");
        }
        Ok(value)
    }

    /// Same inspection fields as official artifacts, with an unambiguous non-official channel.
    /// There is no self-managed desktop updater contract in this agent-only input.
    pub fn binding_json(&self, raw: &[u8]) -> String {
        serde_json::json!({
            "environment": "self-managed",
            "channel": "self-managed",
            "app_origin": self.app_origin,
            "api_origin": self.api_origin,
            "update_manifest_path": "",
            "token_verification_public_key": self.token_verification_public_key,
            "descriptor_sha256": format!("{:x}", Sha256::digest(raw)),
        })
        .to_string()
    }
}

fn exact_https_origin(value: &str) -> bool {
    let Ok(url) = url::Url::parse(value) else {
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
mod tests {
    use super::*;

    fn descriptor() -> serde_json::Value {
        let key = ed25519_dalek::SigningKey::from_bytes(&[7; 32]).verifying_key();
        serde_json::json!({
            "schema": 1,
            "app_origin": "https://app.example.invalid",
            "api_origin": "https://broker.example.invalid",
            "token_verification_public_key": base64::engine::general_purpose::STANDARD.encode(key.as_bytes()),
        })
    }

    #[test]
    fn explicit_selection_never_changes_the_official_default() {
        let root = Path::new("/source/hydra-agent");
        assert_eq!(self_managed_path(root, false, None), Ok(None));
        assert_eq!(self_managed_path(root, true, None), Ok(None));
        assert!(self_managed_path(root, true, Some("public.json".into())).is_err());
        assert!(self_managed_path(root, false, Some("".into())).is_err());
        assert_eq!(
            self_managed_path(root, false, Some("public.json".into())),
            Ok(Some(root.join("public.json")))
        );
        assert_eq!(
            self_managed_path(root, false, Some("/config/public.json".into())),
            Ok(Some(PathBuf::from("/config/public.json")))
        );
    }

    #[test]
    fn binding_pins_only_public_trust_and_exact_descriptor_bytes() {
        let raw = serde_json::to_vec(&descriptor()).unwrap();
        let trust = SelfManagedTrust::parse(&raw).unwrap();
        let binding: serde_json::Value = serde_json::from_str(&trust.binding_json(&raw)).unwrap();
        assert_eq!(binding["environment"], "self-managed");
        assert_eq!(binding["channel"], "self-managed");
        assert_eq!(binding["update_manifest_path"], "");
        assert_eq!(binding["api_origin"], trust.api_origin);
        assert_eq!(binding["app_origin"], trust.app_origin);
        assert_eq!(
            binding["token_verification_public_key"],
            trust.token_verification_public_key
        );
        assert_eq!(
            binding["descriptor_sha256"],
            format!("{:x}", Sha256::digest(&raw))
        );
        assert_eq!(binding.as_object().unwrap().len(), 7);
    }

    #[test]
    fn noncanonical_or_non_https_origins_are_rejected() {
        for origin in [
            "http://broker.example.invalid",
            "https://broker.example.invalid/",
            "https://broker.example.invalid/path",
            "https://user@broker.example.invalid",
            "https://broker.example.invalid?query",
            "https://broker.example.invalid#fragment",
            "https://BROKER.example.invalid",
            "https://broker.example.invalid:443",
            "https://broker.example.invalid\n",
            "not-an-origin",
        ] {
            for field in ["app_origin", "api_origin"] {
                let mut value = descriptor();
                value[field] = origin.into();
                assert!(SelfManagedTrust::parse(&serde_json::to_vec(&value).unwrap()).is_err());
            }
        }
    }

    #[test]
    fn malformed_unknown_duplicate_and_oversized_inputs_fail_without_echo() {
        let mut value = descriptor();
        value["private_key"] = "sensitive-fixture-never-echo".into();
        let error = SelfManagedTrust::parse(&serde_json::to_vec(&value).unwrap())
            .err()
            .unwrap();
        assert!(!error.contains("sensitive-fixture-never-echo"));
        assert!(SelfManagedTrust::parse(b"{}").is_err());
        assert!(SelfManagedTrust::parse(&vec![b' '; MAX_DESCRIPTOR_BYTES + 1]).is_err());
        let raw = serde_json::to_string(&descriptor()).unwrap();
        let duplicate = raw.replacen('{', "{\"schema\":1,", 1);
        assert!(SelfManagedTrust::parse(duplicate.as_bytes()).is_err());
        for invalid in [serde_json::json!(2), serde_json::json!("1")] {
            let mut value = descriptor();
            value["schema"] = invalid;
            assert!(SelfManagedTrust::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }

    #[test]
    fn verifier_is_required_and_must_be_canonical_public_key() {
        let valid = descriptor()["token_verification_public_key"]
            .as_str()
            .unwrap()
            .to_string();
        for key in [
            String::new(),
            "not-base64".into(),
            valid.trim_end_matches('=').into(),
            base64::engine::general_purpose::STANDARD.encode([0; 31]),
            base64::engine::general_purpose::STANDARD.encode([0; 64]),
        ] {
            let mut value = descriptor();
            value["token_verification_public_key"] = key.into();
            assert!(SelfManagedTrust::parse(&serde_json::to_vec(&value).unwrap()).is_err());
        }
    }
}
