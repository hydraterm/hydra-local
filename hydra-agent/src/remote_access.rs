//! Retirement shim for the old persistent positive gate.
//!
//! `remote-access-authority.json` was signed, but it was still replayable by a
//! same-UID process after Close and the same UID could read the signing key.
//! It is therefore never read and can never authorize remote access. Effective
//! open state is now the exact reviewed user service being installed, running,
//! and locally ready; Close synchronously removes that service.

use anyhow::{Context, Result};
use std::path::{Path, PathBuf};

const RETIRED_AUTHORITY_FILE: &str = "remote-access-authority.json";

pub fn retired_authority_path(agent_dir: &Path) -> PathBuf {
    agent_dir.join(RETIRED_AUTHORITY_FILE)
}

/// Best-effort migration cleanup. Missing is already safe. No code path reads
/// this file, so restoring old bytes after this call has no effect.
pub fn remove_retired_authority(agent_dir: &Path) -> Result<()> {
    let path = retired_authority_path(agent_dir);
    match std::fs::remove_file(&path) {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error).with_context(|| format!("remove {}", path.display())),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retired_positive_bytes_are_deleted_but_never_interpreted() {
        let dir = std::env::temp_dir().join(format!(
            "hydra-retired-authority-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        let old = br#"{"schema":"hydra.agent.remote_access","record":{"enabled":true},"signature":"old"}"#;
        std::fs::write(retired_authority_path(&dir), old).unwrap();
        remove_retired_authority(&dir).unwrap();
        assert!(!retired_authority_path(&dir).exists());

        // Restoring a byte-identical historical grant creates only an inert
        // unreferenced file; this module intentionally exposes no read/verify
        // or `is_open` operation.
        std::fs::write(retired_authority_path(&dir), old).unwrap();
        assert_eq!(std::fs::read(retired_authority_path(&dir)).unwrap(), old);
        let _ = std::fs::remove_dir_all(dir);
    }
}
