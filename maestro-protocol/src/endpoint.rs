//! Shared identity for the per-user PTY daemon socket.
//!
//! Installed launchers, the standalone daemon, and every local client must derive the same
//! filename. Callers still own the runtime-directory choice and may pass an explicit or persisted
//! socket path; this module defines only the fresh-install filename.

/// Return the stable per-user daemon socket filename used by official macOS and Linux launchers.
pub fn daemon_socket_filename(effective_uid: u32) -> String {
    format!("hydra-maestro-{effective_uid}.sock")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn filename_is_stable_and_user_scoped() {
        assert_eq!(daemon_socket_filename(0), "hydra-maestro-0.sock");
        assert_eq!(daemon_socket_filename(501), "hydra-maestro-501.sock");
        assert_ne!(daemon_socket_filename(501), daemon_socket_filename(502));
    }
}
