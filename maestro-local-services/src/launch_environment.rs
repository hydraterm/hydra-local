//! Platform policy for launching provider CLIs through the desktop user's login shell.
//!
//! The local app and optional authenticated extensions can both create retained terminal sessions.
//! They must resolve provider executables in the same shell environment or an identical launch can
//! succeed through one entrypoint and exit with command-not-found through another.

/// Re-export the shell-owned execution policy so durable replay, preflight, local launch, and remote
/// launch cannot drift at a dependency boundary.
pub use maestro_shell::LOGIN_SHELL_COMMAND_FLAGS;

#[cfg(test)]
mod tests {
    use super::LOGIN_SHELL_COMMAND_FLAGS;

    #[test]
    fn login_shell_flags_match_the_platform_policy() {
        assert_eq!(LOGIN_SHELL_COMMAND_FLAGS, "-lic");
    }
}
