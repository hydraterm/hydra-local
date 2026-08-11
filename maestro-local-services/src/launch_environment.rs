//! Platform policy for launching provider CLIs through the desktop user's login shell.
//!
//! The local app and optional authenticated extensions can both create retained terminal sessions.
//! They must resolve provider executables in the same shell environment or an identical launch can
//! succeed through one entrypoint and exit with command-not-found through another.

/// Provider CLIs must be resolved in the interactive login-shell environment used by ordinary Hydra
/// terminal panes. A non-interactive login shell skips startup files such as zsh's `.zshrc` and the
/// bash profile chain that commonly loads `.bashrc`, where version managers and standalone
/// installers add their binaries to `PATH`.
///
/// Keep this policy shared by preflight and every retained-session launch: accepting an agent in one
/// shell environment and starting it in another would either publish a broken retained session or
/// reject a command that already works in Hydra's terminal.
pub const LOGIN_SHELL_COMMAND_FLAGS: &str = "-lic";

#[cfg(test)]
mod tests {
    use super::LOGIN_SHELL_COMMAND_FLAGS;

    #[test]
    fn login_shell_flags_match_the_platform_policy() {
        assert_eq!(LOGIN_SHELL_COMMAND_FLAGS, "-lic");
    }
}
