//! Read-only launch validation for React-created agent sessions.
//!
//! React launch intents record durable project/window/session topology before the PTY is started.
//! Canonical agents run through the user's login shell, so spawning that shell can succeed even when
//! the actual agent executable is absent; the child then exits with code 127 after the records have
//! already been published. This module probes only the canonical agent executables, using the
//! same login-shell environment as the real launch, before any durable mutation occurs.
//!
//! Arbitrary custom commands validate their actual argv[0] against the app process PATH (or a
//! direct-path X_OK check), matching their raw exec path rather than accepting shell-only aliases or
//! builtins. A bare custom executable is resolved to an absolute argv[0] before its durable launch
//! recipe is recorded. This is deliberate: a retained daemon may have an older/different PATH than
//! the newly launched GUI, so later execution must not repeat a PATH lookup in daemon state. Relative
//! and empty PATH entries are interpreted against the requested launch cwd, as `execvp` would after
//! changing into that directory. The actual argv wins over the selected provider, so a custom wrapper
//! is checked as itself rather than spuriously requiring the provider CLI it may eventually invoke.

// This file is compiled into both the library and binary targets. The binary owns the complete
// preflight surface while the library intentionally consumes only the prepared-argv reprobe.
#![allow(dead_code)]

use std::cell::RefCell;
#[cfg(unix)]
use std::ffi::CString;
use std::fmt;
#[cfg(unix)]
use std::os::unix::ffi::OsStrExt;
use std::path::{Path, PathBuf};

// Keep preflight and both local/remote PTY launch paths on one platform policy.
#[cfg(all(test, unix))]
pub(crate) use maestro_local_services::LOGIN_SHELL_COMMAND_FLAGS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SupportedAgentExecutable {
    Claude,
    Codex,
    Gemini,
    OpenCode,
    Copilot,
    Antigravity,
    Kimi,
    Kiro,
    Cursor,
    Amp,
    Devin,
    Factory,
}

impl SupportedAgentExecutable {
    pub(crate) fn command(self) -> &'static str {
        match self {
            Self::Claude => "claude",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::OpenCode => "opencode",
            Self::Copilot => "copilot",
            Self::Antigravity => "agy",
            Self::Kimi => "kimi",
            Self::Kiro => "kiro-cli",
            Self::Cursor => "agent",
            Self::Amp => "amp",
            Self::Devin => "devin",
            Self::Factory => "droid",
        }
    }

    fn display_name(self) -> &'static str {
        match self {
            Self::Claude => "Claude",
            Self::Codex => "Codex",
            Self::Gemini => "Gemini",
            Self::OpenCode => "OpenCode",
            Self::Copilot => "GitHub Copilot",
            Self::Antigravity => "Antigravity",
            Self::Kimi => "Kimi",
            Self::Kiro => "Kiro",
            Self::Cursor => "Cursor",
            Self::Amp => "Amp",
            Self::Devin => "Devin",
            Self::Factory => "Factory",
        }
    }

    fn from_canonical_command(value: &str) -> Option<Self> {
        match value {
            "claude" => Some(Self::Claude),
            "codex" => Some(Self::Codex),
            "gemini" => Some(Self::Gemini),
            "opencode" => Some(Self::OpenCode),
            "copilot" => Some(Self::Copilot),
            "agy" => Some(Self::Antigravity),
            "kimi" => Some(Self::Kimi),
            "kiro-cli" => Some(Self::Kiro),
            "agent" => Some(Self::Cursor),
            "amp" => Some(Self::Amp),
            "devin" => Some(Self::Devin),
            "droid" => Some(Self::Factory),
            _ => None,
        }
    }

    fn from_selected_name(value: &str) -> Option<Self> {
        let value = value.trim().to_ascii_lowercase();
        match value.as_str() {
            // The product-facing provider ID is `antigravity`; its canonical executable and
            // durable LaunchSpec ID are both `agy`. Accept the durable ID here as well so an
            // already-recorded launch can be preflighted without rewriting provider identity.
            "antigravity" | "agy" => Some(Self::Antigravity),
            "kiro" => Some(Self::Kiro),
            "cursor" => Some(Self::Cursor),
            "amp" => Some(Self::Amp),
            "devin" => Some(Self::Devin),
            "factory" | "droid" => Some(Self::Factory),
            _ => Self::from_canonical_command(value.as_str()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProbeTarget {
    LoginShell(SupportedAgentExecutable),
    ProcessPathCommand(String),
    DirectPath {
        agent: SupportedAgentExecutable,
        path: PathBuf,
    },
    DirectCommandPath(PathBuf),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum LaunchPreflightError {
    MalformedCommand,
    UnsupportedAgent,
    NonCanonicalCommandCase(SupportedAgentExecutable),
    InvalidWorkingDirectory,
    Missing(SupportedAgentExecutable),
    MissingWithHistoryStore(SupportedAgentExecutable),
    MissingCommand,
    MutationDaemonUnavailable,
    ProbeUnavailable(SupportedAgentExecutable),
    ProbeTimedOut(SupportedAgentExecutable),
}

impl LaunchPreflightError {
    pub(crate) fn code(&self) -> &'static str {
        match self {
            Self::MalformedCommand => "launch_command_invalid",
            Self::UnsupportedAgent => "agent_unsupported",
            Self::NonCanonicalCommandCase(_) => "agent_command_case_invalid",
            Self::InvalidWorkingDirectory => "launch_cwd_invalid",
            Self::Missing(_) => "agent_executable_missing",
            Self::MissingWithHistoryStore(_) => "agent_history_executable_missing",
            Self::MissingCommand => "launch_executable_missing",
            Self::MutationDaemonUnavailable => "daemon_mutation_unavailable",
            Self::ProbeUnavailable(_) => "agent_preflight_unavailable",
            Self::ProbeTimedOut(_) => "agent_preflight_timeout",
        }
    }

    pub(crate) fn user_message(&self) -> String {
        match self {
            Self::MalformedCommand => {
                "The launch command is not valid. Check its quotes and try again.".to_string()
            }
            Self::UnsupportedAgent => {
                "This agent is not supported. Choose a listed agent or Terminal.".to_string()
            }
            Self::NonCanonicalCommandCase(agent) => format!(
                "Agent command names are case-sensitive. Use the lowercase `{}` command for {}.",
                agent.command(),
                agent.display_name()
            ),
            Self::InvalidWorkingDirectory => {
                "The selected working directory is unavailable. Choose an existing folder and try again."
                    .to_string()
            }
            Self::Missing(agent) => format!(
                "{} is not installed or is unavailable in your login shell. Install it or choose Terminal.",
                agent.display_name()
            ),
            Self::MissingWithHistoryStore(agent) => format!(
                "Hydra found {}'s history storage, but its launcher is unavailable. Check the selected executable, installation, or login-shell PATH.",
                agent.display_name()
            ),
            Self::MissingCommand => {
                "The custom launch command is not installed or is unavailable in your login shell."
                    .to_string()
            }
            Self::MutationDaemonUnavailable => {
                "Hydra could not reach a compatible terminal service. Close and reopen this Hydra window, then retry. No new session was created."
                    .to_string()
            }
            Self::ProbeUnavailable(agent) => format!(
                "Hydra could not verify {} in your login shell. Check your shell configuration and try again.",
                agent.display_name()
            ),
            Self::ProbeTimedOut(agent) => format!(
                "Hydra timed out while checking {} in your login shell. Check your shell startup files and try again.",
                agent.display_name()
            ),
        }
    }
}

impl fmt::Display for LaunchPreflightError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // Intentionally bounded and secret-free: never print raw argv, cwd, PATH, or shell output.
        write!(f, "{}: {}", self.code(), self.user_message())
    }
}

/// Split the small argv-shaped command strings produced by the React dashboard. This is not a shell
/// evaluator: quotes and backslash escapes only preserve argument boundaries; operators are ordinary
/// arguments, matching the historical launch behavior.
pub(crate) fn split_command_line(command: &str) -> Result<Vec<String>, LaunchPreflightError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut chars = command.chars().peekable();
    let mut quote: Option<char> = None;
    let mut arg_started = false;
    while let Some(ch) = chars.next() {
        match (quote, ch) {
            (Some(q), c) if c == q => quote = None,
            (Some(_), '\\') => {
                let next = chars.next().ok_or(LaunchPreflightError::MalformedCommand)?;
                cur.push(next);
                arg_started = true;
            }
            (Some(_), c) => {
                cur.push(c);
                arg_started = true;
            }
            (None, '\'' | '"') => {
                quote = Some(ch);
                arg_started = true;
            }
            (None, '\\') => {
                let next = chars.next().ok_or(LaunchPreflightError::MalformedCommand)?;
                cur.push(next);
                arg_started = true;
            }
            (None, c) if c.is_whitespace() => {
                if arg_started {
                    out.push(std::mem::take(&mut cur));
                    arg_started = false;
                }
            }
            (None, c) => {
                cur.push(c);
                arg_started = true;
            }
        }
    }
    if quote.is_some() {
        return Err(LaunchPreflightError::MalformedCommand);
    }
    if arg_started {
        out.push(cur);
    }
    if out.is_empty() {
        return Err(LaunchPreflightError::MalformedCommand);
    }
    Ok(out)
}

pub(crate) fn is_canonical_cursor_argv(argv: &[String]) -> bool {
    let Some(command) = argv.first() else {
        return false;
    };
    if Path::new(command)
        .file_name()
        .and_then(|leaf| leaf.to_str())
        != Some("agent")
    {
        return false;
    }
    let mut idx = 1;
    let mut resume = false;
    let mut r#continue = false;
    let mut model = false;
    let mut yolo = false;
    while idx < argv.len() {
        match argv[idx].as_str() {
            "--continue" if !r#continue && !resume => {
                r#continue = true;
                idx += 1;
            }
            "--resume" if !resume && !r#continue => {
                let Some(id) = argv.get(idx + 1) else {
                    return false;
                };
                let Ok(parsed) = uuid::Uuid::parse_str(id) else {
                    return false;
                };
                if parsed.hyphenated().to_string() != *id {
                    return false;
                }
                resume = true;
                idx += 2;
            }
            "--model" if !model => {
                let Some(value) = argv.get(idx + 1) else {
                    return false;
                };
                if value.trim().is_empty()
                    || value.starts_with('-')
                    || value.chars().count() > 96
                    || value.chars().any(char::is_control)
                {
                    return false;
                }
                model = true;
                idx += 2;
            }
            "--yolo" if !yolo => {
                yolo = true;
                idx += 1;
            }
            _ => return false,
        }
    }
    true
}

/// Amp's provider store is deliberately not inspected yet, but Hydra can still persist an explicitly selected
/// launch as KnownSafe. Keep that provenance narrow: fresh, latest, or one exact documented thread target, plus
/// the installed CLI's boolean allow-all switch. Arbitrary `amp` subcommands remain ordinary custom commands.
pub(crate) fn is_canonical_amp_argv(argv: &[String]) -> bool {
    let Some(command) = argv.first() else {
        return false;
    };
    // KnownSafe provenance represents Hydra's canonical login-shell launch, not an arbitrary
    // user-supplied executable that merely happens to have an `amp` basename.
    if command != "amp" {
        return false;
    }

    let mut idx = 1;
    let mut target = false;
    let mut dangerous = false;
    while idx < argv.len() {
        match argv[idx].as_str() {
            "last" if !target => {
                target = true;
                idx += 1;
            }
            "threads" if !target && argv.get(idx + 1).map(String::as_str) == Some("continue") => {
                let Some(thread) = argv.get(idx + 2) else {
                    return false;
                };
                if thread.trim().is_empty()
                    || thread.starts_with('-')
                    || thread.chars().count() > 256
                    || thread.chars().any(char::is_control)
                {
                    return false;
                }
                target = true;
                idx += 3;
            }
            "--dangerously-allow-all" if !dangerous => {
                dangerous = true;
                idx += 1;
            }
            _ => return false,
        }
    }
    true
}

fn is_bounded_opaque_resume_id(value: &str) -> bool {
    value == value.trim()
        && !value.is_empty()
        && !value.starts_with('-')
        && value.chars().count() <= 256
        && !value.chars().any(char::is_control)
}

/// Devin KnownSafe provenance is granted only to Hydra's exact interactive CLI contract. A path whose basename
/// happens to be `devin`, a wrapper, a subcommand, or an unknown flag remains an ordinary custom command.
pub(crate) fn is_canonical_devin_argv(argv: &[String]) -> bool {
    if argv.first().map(String::as_str) != Some("devin") {
        return false;
    }
    let mut idx = 1;
    let mut target = false;
    let mut model = false;
    let mut dangerous = false;
    while idx < argv.len() {
        match argv[idx].as_str() {
            "--continue" if !target => {
                target = true;
                idx += 1;
            }
            "--resume" if !target => {
                let Some(id) = argv.get(idx + 1) else {
                    return false;
                };
                if !is_bounded_opaque_resume_id(id) {
                    return false;
                }
                target = true;
                idx += 2;
            }
            "--model" if !model => {
                let Some(value) = argv.get(idx + 1) else {
                    return false;
                };
                if value.trim().is_empty()
                    || value.starts_with('-')
                    || value.chars().count() > 96
                    || value.chars().any(char::is_control)
                {
                    return false;
                }
                model = true;
                idx += 2;
            }
            "--permission-mode=dangerous" if !dangerous => {
                dangerous = true;
                idx += 1;
            }
            _ => return false,
        }
    }
    true
}

/// Factory's interactive CLI supports fresh, latest (`--resume`), and exact (`--resume <id>`) launches. Hydra
/// deliberately does not pass the headless `droid exec` model/unsafe flags through this contract.
pub(crate) fn is_canonical_factory_argv(argv: &[String]) -> bool {
    if argv.first().map(String::as_str) != Some("droid") {
        return false;
    }
    let mut idx = 1;
    let mut target = false;
    let mut dangerous = false;
    while idx < argv.len() {
        match argv[idx].as_str() {
            "--resume" if !target => {
                target = true;
                match argv.get(idx + 1) {
                    Some(next) if !next.starts_with('-') => {
                        if !is_bounded_opaque_resume_id(next) {
                            return false;
                        }
                        idx += 2;
                    }
                    _ => idx += 1,
                }
            }
            "--auto=high" if !dangerous => {
                dangerous = true;
                idx += 1;
            }
            _ => return false,
        }
    }
    true
}

fn classify_target(
    argv: &[String],
    cwd: &Path,
    cursor_provenance: bool,
) -> Result<Option<ProbeTarget>, LaunchPreflightError> {
    let Some(command) = argv.first() else {
        return Err(LaunchPreflightError::MalformedCommand);
    };
    if command.is_empty() {
        return Err(LaunchPreflightError::MalformedCommand);
    }
    let path = Path::new(command);
    let Some(basename) = path
        .file_name()
        .and_then(|value| value.to_str())
        .filter(|value| !value.is_empty())
    else {
        return Err(LaunchPreflightError::MalformedCommand);
    };
    let agent = match SupportedAgentExecutable::from_canonical_command(basename) {
        Some(SupportedAgentExecutable::Cursor) if !cursor_provenance => {
            let path = if command.contains('/') {
                if path.is_absolute() {
                    path.to_path_buf()
                } else {
                    cwd.join(path)
                }
            } else {
                return Ok(Some(ProbeTarget::ProcessPathCommand(command.to_string())));
            };
            return Ok(Some(ProbeTarget::DirectCommandPath(path)));
        }
        Some(agent) => agent,
        None if !command.contains('/') => {
            if let Some(agent) = SupportedAgentExecutable::from_selected_name(basename) {
                if agent != SupportedAgentExecutable::Cursor || cursor_provenance {
                    return Err(LaunchPreflightError::NonCanonicalCommandCase(agent));
                }
            }
            return Ok(Some(ProbeTarget::ProcessPathCommand(command.to_string())));
        }
        None => {
            let path = if path.is_absolute() {
                path.to_path_buf()
            } else {
                cwd.join(path)
            };
            return Ok(Some(ProbeTarget::DirectCommandPath(path)));
        }
    };
    if command.contains('/') {
        let path = if path.is_absolute() {
            path.to_path_buf()
        } else {
            cwd.join(path)
        };
        Ok(Some(ProbeTarget::DirectPath { agent, path }))
    } else {
        Ok(Some(ProbeTarget::LoginShell(agent)))
    }
}

fn selected_agent_target(agent: Option<&str>) -> Result<Option<ProbeTarget>, LaunchPreflightError> {
    let Some(agent) = agent.map(str::trim).filter(|value| !value.is_empty()) else {
        return Ok(None);
    };
    if agent.eq_ignore_ascii_case("terminal") {
        return Ok(None);
    }
    SupportedAgentExecutable::from_selected_name(agent)
        .map(|agent| Some(ProbeTarget::LoginShell(agent)))
        .ok_or(LaunchPreflightError::UnsupportedAgent)
}

fn normalized_resolved_command<'a>(
    resolved_command: Option<&'a str>,
    selected_agent: Option<&str>,
) -> Option<&'a str> {
    match (resolved_command, selected_agent) {
        (Some(command), Some(agent))
            if command.trim().is_empty() && agent.trim().eq_ignore_ascii_case("terminal") =>
        {
            None
        }
        _ => resolved_command,
    }
}

fn target_for(
    resolved_command: Option<&str>,
    selected_agent: Option<&str>,
    cwd: &Path,
) -> Result<Option<ProbeTarget>, LaunchPreflightError> {
    // Reject an unknown provider even when a custom command is present. The actual argv still wins
    // among supported providers, but an unrecognized agent must never silently become an
    // Agent-kind fallback shell through a forged/stale IPC payload.
    if let Some(agent) = selected_agent
        .map(str::trim)
        .filter(|value| !value.is_empty() && !value.eq_ignore_ascii_case("terminal"))
    {
        if SupportedAgentExecutable::from_selected_name(agent).is_none() {
            return Err(LaunchPreflightError::UnsupportedAgent);
        }
    }
    let resolved_command = normalized_resolved_command(resolved_command, selected_agent);
    if let Some(command) = resolved_command {
        let argv = split_command_line(command)?;
        // The actual command wins. Canonical providers and custom wrappers are both validated, but
        // a wrapper is checked as its actual argv[0] rather than as the selected provider label.
        let cursor_provenance = selected_agent
            .is_some_and(|agent| agent.trim().eq_ignore_ascii_case("cursor"))
            && is_canonical_cursor_argv(&argv);
        return classify_target(&argv, cwd, cursor_provenance);
    }
    selected_agent_target(selected_agent)
}

trait AgentExecutableProbe {
    fn probe(&self, target: &ProbeTarget, cwd: &Path) -> Result<bool, LaunchPreflightError>;
}

struct LoginShellAgentProbe {
    login_shell: PathBuf,
    home: Option<PathBuf>,
    #[cfg(windows)]
    roaming_app_data: Option<std::ffi::OsString>,
    selected: RefCell<Option<maestro_shell::ProviderExecutable>>,
    #[cfg(test)]
    fixture_path: Option<std::ffi::OsString>,
}

impl maestro_shell::LaunchEnvLookup for LoginShellAgentProbe {
    fn shell_utf8(&self) -> Option<String> {
        self.login_shell.to_str().map(str::to_owned)
    }
    fn home_os(&self) -> Option<std::ffi::OsString> {
        self.home.as_ref().map(|home| home.as_os_str().to_owned())
    }
    #[cfg(windows)]
    fn roaming_app_data_os(&self) -> Option<std::ffi::OsString> {
        self.roaming_app_data.clone()
    }
    fn path_os(&self) -> Option<std::ffi::OsString> {
        #[cfg(test)]
        if let Some(path) = &self.fixture_path {
            return Some(path.clone());
        }
        std::env::var_os("PATH")
    }
    fn configured_provider_path(&self, provider: &str) -> Option<PathBuf> {
        #[cfg(test)]
        if self.fixture_path.is_some() {
            return None;
        }
        maestro_shell::provider_executable_override_variable(provider)
            .and_then(std::env::var_os)
            .map(PathBuf::from)
    }
}

impl LoginShellAgentProbe {
    fn from_process_env() -> Self {
        Self::from_launch_env(&maestro_shell::ProcessLaunchEnv)
    }

    fn from_launch_env(env: &impl maestro_shell::LaunchEnvLookup) -> Self {
        Self {
            // Match actual launch selection: USERPROFILE/COMSPEC on Windows, HOME/SHELL on
            // Unix. A Windows GUI normally has no HOME; skipping its native home silently
            // disabled the shared .local/bin, npm and OpenCode discovery roots.
            login_shell: PathBuf::from(maestro_shell::login_shell_program(env)),
            home: env.home_os().map(PathBuf::from),
            #[cfg(windows)]
            roaming_app_data: env.roaming_app_data_os(),
            selected: RefCell::new(None),
            #[cfg(test)]
            fixture_path: None,
        }
    }

    fn login_shell_has(
        &self,
        agent: SupportedAgentExecutable,
        cwd: &Path,
    ) -> Result<bool, LaunchPreflightError> {
        use maestro_shell::{ProviderLookupError, ProviderResolution};
        *self.selected.borrow_mut() = None;
        let resolution = maestro_shell::resolve_provider_executable(agent.command(), cwd, self)
            .map_err(|error| match error {
                ProviderLookupError::Unavailable => LaunchPreflightError::ProbeUnavailable(agent),
                ProviderLookupError::TimedOut => LaunchPreflightError::ProbeTimedOut(agent),
            })?;
        if let Some(ProviderResolution::Executable(selected)) = &resolution {
            *self.selected.borrow_mut() = Some(selected.clone());
        }
        Ok(resolution.is_some())
    }
}

/// Test the exact executable identity with the current user's real POSIX access, rather than
/// accepting a mode bit that may belong only to another user/group. Shared with the actual OpenCode
/// launch resolver so preflight and execution cannot disagree.
pub(crate) fn is_executable_file(path: &Path) -> bool {
    #[cfg(windows)]
    {
        // Match the ConPTY native-command adapter: cmd/bat provider shims are executed with
        // literal arguments by that adapter, never interpolated into dashboard-controlled text.
        path.is_file()
            && path.extension().is_some_and(|extension| {
                ["exe", "com", "cmd", "bat"]
                    .iter()
                    .any(|allowed| extension.eq_ignore_ascii_case(allowed))
            })
    }
    #[cfg(unix)]
    {
        if !path.metadata().map(|meta| meta.is_file()).unwrap_or(false) {
            return false;
        }
        let Ok(path) = CString::new(path.as_os_str().as_bytes()) else {
            return false;
        };
        // SAFETY: `path` is a live, NUL-terminated C string and `access` does not retain it.
        unsafe { access(path.as_ptr(), X_OK) == 0 }
    }
}

fn process_path_executable_in(
    process_path: &std::ffi::OsStr,
    command: &str,
    cwd: &Path,
) -> Option<PathBuf> {
    std::env::split_paths(process_path).find_map(|entry| {
        let base = if entry.is_absolute() {
            entry
        } else {
            cwd.join(entry)
        };
        let candidate = base.join(command);
        #[cfg(windows)]
        let candidate = if candidate.extension().is_none() {
            ["exe", "com", "cmd", "bat"]
                .iter()
                .map(|extension| candidate.with_extension(extension))
                .find(|path| is_executable_file(path))?
        } else {
            candidate
        };
        // LaunchSpec argv is UTF-8. Never claim that an executable was prepared if its exact path
        // cannot be represented without a lossy conversion.
        (candidate.to_str().is_some() && is_executable_file(&candidate)).then_some(candidate)
    })
}

fn process_path_executable(command: &str, cwd: &Path) -> Option<PathBuf> {
    let path = std::env::var_os("PATH")?;
    process_path_executable_in(&path, command, cwd)
}

#[cfg(unix)]
const X_OK: std::ffi::c_int = 1;

#[cfg(unix)]
unsafe extern "C" {
    fn access(path: *const std::ffi::c_char, mode: std::ffi::c_int) -> std::ffi::c_int;
    #[cfg(test)]
    fn getuid() -> u32;
}

fn normalize_supported_cwd(cwd: &Path, home: Option<&Path>) -> PathBuf {
    let Some(home) = home else {
        return cwd.to_path_buf();
    };
    if cwd == Path::new("~") {
        return home.to_path_buf();
    }
    match cwd.strip_prefix("~") {
        Ok(rest) if !rest.as_os_str().is_empty() => home.join(rest),
        _ => cwd.to_path_buf(),
    }
}

fn validated_cwd(cwd: &Path, home: Option<&Path>) -> Result<PathBuf, LaunchPreflightError> {
    let cwd = normalize_supported_cwd(cwd, home);
    let cwd = if cwd.is_absolute() {
        cwd
    } else {
        std::env::current_dir()
            .map_err(|_| LaunchPreflightError::InvalidWorkingDirectory)?
            .join(cwd)
    };
    cwd.is_dir()
        .then_some(cwd)
        .ok_or(LaunchPreflightError::InvalidWorkingDirectory)
}

impl AgentExecutableProbe for LoginShellAgentProbe {
    fn probe(&self, target: &ProbeTarget, cwd: &Path) -> Result<bool, LaunchPreflightError> {
        match target {
            ProbeTarget::LoginShell(agent) => {
                let available = self.login_shell_has(*agent, cwd)?;
                if !available {
                    return Err(missing_provider_error(*agent, self.home.as_deref()));
                }
                Ok(available)
            }
            ProbeTarget::ProcessPathCommand(command) => {
                Ok(process_path_executable(command, cwd).is_some())
            }
            ProbeTarget::DirectPath { path, agent } => {
                if is_executable_file(path) {
                    Ok(true)
                } else {
                    Err(missing_provider_error(*agent, self.home.as_deref()))
                }
            }
            ProbeTarget::DirectCommandPath(path) => Ok(is_executable_file(path)),
        }
    }
}

fn missing_provider_error(
    agent: SupportedAgentExecutable,
    home: Option<&Path>,
) -> LaunchPreflightError {
    use maestro_local_services::agent_history::{
        provider_history_store_presence, HistoryStorePresence,
    };
    let history_agent = match agent {
        SupportedAgentExecutable::Antigravity => "antigravity",
        SupportedAgentExecutable::Kiro => "kiro",
        SupportedAgentExecutable::Cursor => "cursor",
        _ => agent.command(),
    };
    if provider_history_store_presence(history_agent, home) == HistoryStorePresence::Present {
        LaunchPreflightError::MissingWithHistoryStore(agent)
    } else {
        LaunchPreflightError::Missing(agent)
    }
}

#[cfg(test)]
fn preflight_with(
    resolved_command: Option<&str>,
    selected_agent: Option<&str>,
    cwd: &Path,
    probe: &dyn AgentExecutableProbe,
) -> Result<(), LaunchPreflightError> {
    preflight_with_home(
        resolved_command,
        selected_agent,
        cwd,
        maestro_shell::LaunchEnvLookup::home_os(&maestro_shell::ProcessLaunchEnv)
            .as_deref()
            .map(Path::new),
        probe,
    )
}

fn preflight_with_home(
    resolved_command: Option<&str>,
    selected_agent: Option<&str>,
    cwd: &Path,
    home: Option<&Path>,
    probe: &dyn AgentExecutableProbe,
) -> Result<(), LaunchPreflightError> {
    let cwd = validated_cwd(cwd, home)?;
    let Some(target) = target_for(resolved_command, selected_agent, &cwd)? else {
        return Ok(());
    };
    let agent = match &target {
        ProbeTarget::LoginShell(agent) | ProbeTarget::DirectPath { agent, .. } => Some(*agent),
        ProbeTarget::ProcessPathCommand(_) | ProbeTarget::DirectCommandPath(_) => None,
    };
    match probe.probe(&target, &cwd)? {
        true => Ok(()),
        false => Err(match agent {
            Some(agent) => LaunchPreflightError::Missing(agent),
            None => LaunchPreflightError::MissingCommand,
        }),
    }
}

pub(crate) fn preflight(
    resolved_command: Option<&str>,
    selected_agent: Option<&str>,
    cwd: &Path,
) -> Result<(), LaunchPreflightError> {
    prepare(resolved_command, selected_agent, cwd).map(|_| ())
}

/// Validate a launch and return its parsed explicit argv, if one was supplied. Bare custom commands
/// are materialized to an absolute executable here so the durable recipe never depends on the
/// retained daemon's environment. Canonical agents retain their provider identity here; the full
/// preparation carries their selected executable separately for the current launch attempt.
pub(crate) fn prepare(
    resolved_command: Option<&str>,
    selected_agent: Option<&str>,
    cwd: &Path,
) -> Result<Option<Vec<String>>, LaunchPreflightError> {
    prepare_with_provider(resolved_command, selected_agent, cwd)
        .map(|prepared| prepared.explicit_argv)
}

pub(crate) struct PreparedLaunch {
    pub explicit_argv: Option<Vec<String>>,
    pub provider_executable: Option<maestro_shell::ProviderExecutable>,
}

pub(crate) fn prepare_with_provider(
    resolved_command: Option<&str>,
    selected_agent: Option<&str>,
    cwd: &Path,
) -> Result<PreparedLaunch, LaunchPreflightError> {
    prepare_with_probe(
        resolved_command,
        selected_agent,
        cwd,
        LoginShellAgentProbe::from_process_env(),
    )
}

fn prepare_with_probe(
    resolved_command: Option<&str>,
    selected_agent: Option<&str>,
    cwd: &Path,
    probe: LoginShellAgentProbe,
) -> Result<PreparedLaunch, LaunchPreflightError> {
    let resolved_command = normalized_resolved_command(resolved_command, selected_agent);
    preflight_with_home(
        resolved_command,
        selected_agent,
        cwd,
        probe.home.as_deref(),
        &probe,
    )?;

    let Some(command) = resolved_command else {
        return Ok(PreparedLaunch {
            explicit_argv: None,
            provider_executable: probe.selected.into_inner(),
        });
    };
    let cwd = validated_cwd(cwd, probe.home.as_deref())?;
    let mut argv = split_command_line(command)?;
    let cursor_provenance = selected_agent
        .is_some_and(|agent| agent.trim().eq_ignore_ascii_case("cursor"))
        && is_canonical_cursor_argv(&argv);
    match classify_target(&argv, &cwd, cursor_provenance)? {
        Some(ProbeTarget::ProcessPathCommand(command)) => {
            let resolved = process_path_executable(&command, &cwd)
                .ok_or(LaunchPreflightError::MissingCommand)?;
            argv[0] = resolved
                .into_os_string()
                .into_string()
                .map_err(|_| LaunchPreflightError::MissingCommand)?;
        }
        Some(ProbeTarget::DirectPath { path, .. } | ProbeTarget::DirectCommandPath(path)) => {
            argv[0] = path
                .into_os_string()
                .into_string()
                .map_err(|_| LaunchPreflightError::MissingCommand)?;
        }
        Some(ProbeTarget::LoginShell(_)) | None => {}
    }
    Ok(PreparedLaunch {
        explicit_argv: Some(argv),
        provider_executable: probe.selected.into_inner(),
    })
}

pub(crate) fn reprobe_selected_provider(
    argv: &[String],
    selected: &maestro_shell::ProviderExecutable,
) -> Result<(), LaunchPreflightError> {
    reprobe_selected_provider_with_home(
        argv,
        selected,
        maestro_shell::LaunchEnvLookup::home_os(&maestro_shell::ProcessLaunchEnv)
            .as_deref()
            .map(Path::new),
    )
}

fn reprobe_selected_provider_with_home(
    argv: &[String],
    selected: &maestro_shell::ProviderExecutable,
    home: Option<&Path>,
) -> Result<(), LaunchPreflightError> {
    let provider = argv.first().ok_or(LaunchPreflightError::MalformedCommand)?;
    if selected.remains_executable_for(provider) {
        Ok(())
    } else {
        let agent = SupportedAgentExecutable::from_canonical_command(provider)
            .filter(|_| selected.path_for(provider).is_some());
        Err(agent
            .map(|agent| missing_provider_error(agent, home))
            .unwrap_or(LaunchPreflightError::MissingCommand))
    }
}

/// Re-probe one already-materialized source argv at the exact cwd that will be sealed into a
/// prepared Session. The vector is read-only: absolute custom commands and preassigned provider
/// identities (notably Copilot's UUID) remain byte-identical to the first preflight.
pub(crate) fn reprobe_prepared_argv(
    argv: &[String],
    selected_agent: Option<&str>,
    cwd: &Path,
) -> Result<(), LaunchPreflightError> {
    if argv.first().is_none_or(|command| command.trim().is_empty()) {
        return Err(LaunchPreflightError::MalformedCommand);
    }
    // Preserve the initial unknown-provider refusal even though the already-materialized argv is
    // otherwise authoritative for executable selection.
    let _ = selected_agent_target(selected_agent)?;
    let probe = LoginShellAgentProbe::from_process_env();
    let cwd = validated_cwd(cwd, probe.home.as_deref())?;
    let cursor_provenance = selected_agent
        .is_some_and(|agent| agent.trim().eq_ignore_ascii_case("cursor"))
        && is_canonical_cursor_argv(argv);
    let target = classify_target(argv, &cwd, cursor_provenance)?
        .ok_or(LaunchPreflightError::MalformedCommand)?;
    let agent = match &target {
        ProbeTarget::LoginShell(agent) | ProbeTarget::DirectPath { agent, .. } => Some(*agent),
        ProbeTarget::ProcessPathCommand(_) | ProbeTarget::DirectCommandPath(_) => None,
    };
    match probe.probe(&target, &cwd)? {
        true => Ok(()),
        false => Err(match agent {
            Some(agent) => LaunchPreflightError::Missing(agent),
            None => LaunchPreflightError::MissingCommand,
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(unix)]
    use std::os::unix::fs::PermissionsExt;

    fn write_executable(path: &Path) {
        std::fs::write(
            path,
            if cfg!(windows) {
                "@exit /b 0\r\n"
            } else {
                "#!/bin/sh\nexit 0\n"
            },
        )
        .unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn native_executable(path: PathBuf) -> PathBuf {
        if cfg!(windows) {
            path.with_extension("cmd")
        } else {
            path
        }
    }

    struct StubProbe {
        available: bool,
    }

    #[test]
    fn preflight_snapshots_the_shared_launch_environment_without_new_defaults() {
        struct Env {
            shell: Option<String>,
            home: Option<std::ffi::OsString>,
        }
        impl maestro_shell::LaunchEnvLookup for Env {
            fn shell_utf8(&self) -> Option<String> {
                self.shell.clone()
            }
            fn home_os(&self) -> Option<std::ffi::OsString> {
                self.home.clone()
            }
        }
        let home = tempfile::tempdir().unwrap();
        let configured = Env {
            shell: Some(home.path().join("selected shell").to_str().unwrap().into()),
            home: Some(home.path().as_os_str().to_owned()),
        };
        let probe = LoginShellAgentProbe::from_launch_env(&configured);
        assert_eq!(
            probe.login_shell,
            PathBuf::from(configured.shell.as_ref().unwrap())
        );
        assert_eq!(probe.home.as_deref(), Some(home.path()));
        for shell in [None, Some(String::new()), Some("  ".into())] {
            let env = Env { shell, home: None };
            let probe = LoginShellAgentProbe::from_launch_env(&env);
            assert_eq!(
                probe.login_shell,
                PathBuf::from(maestro_shell::login_shell_program(&env))
            );
            assert!(probe.home.is_none(), "no guessed home directory");
        }
    }

    #[test]
    #[cfg(windows)]
    fn process_preflight_uses_userprofile_without_home() {
        const CHILD_ROOT: &str = "HYDRA_PREFLIGHT_USERPROFILE_FIXTURE";
        if let Some(root) = std::env::var_os(CHILD_ROOT) {
            let root = PathBuf::from(root);
            assert!(std::env::var_os("HOME").is_none());
            let probe = LoginShellAgentProbe::from_process_env();
            assert_eq!(probe.home.as_deref(), Some(root.as_path()));
            assert_eq!(
                probe.login_shell,
                PathBuf::from(std::env::var_os("COMSPEC").unwrap())
            );
            for (provider, folder) in [("claude", ".local"), ("opencode", ".opencode")] {
                let prepared = prepare_with_provider(None, Some(provider), &root).unwrap();
                let selected = prepared.provider_executable.unwrap();
                let expected = root
                    .join(folder)
                    .join("bin")
                    .join(format!("{provider}.cmd"));
                assert_eq!(selected.path_for(provider), Some(expected.as_path()));
                assert!(reprobe_selected_provider(&[provider.into()], &selected).is_ok());
                if provider == "claude" {
                    std::fs::remove_file(&expected).unwrap();
                    std::fs::create_dir_all(root.join(".claude").join("projects")).unwrap();
                    assert_eq!(
                        reprobe_selected_provider(&[provider.into()], &selected).unwrap_err(),
                        LaunchPreflightError::MissingWithHistoryStore(
                            SupportedAgentExecutable::Claude
                        )
                    );
                }
            }
            let selected = prepare_with_provider(None, Some("codex"), &root)
                .unwrap()
                .provider_executable
                .unwrap();
            assert_eq!(
                selected.path_for("codex"),
                Some(
                    root.join("redirected roaming")
                        .join("npm")
                        .join("codex.cmd")
                        .as_path()
                )
            );
            return;
        }
        use std::os::windows::process::CommandExt as _;
        use std::process::{Command, Stdio};
        let root = tempfile::tempdir().unwrap();
        let empty_path = root.path().join("empty-path");
        std::fs::create_dir(&empty_path).unwrap();
        for (provider, folder) in [("claude", ".local"), ("opencode", ".opencode")] {
            let bin = root.path().join(folder).join("bin");
            std::fs::create_dir_all(&bin).unwrap();
            write_executable(&bin.join(format!("{provider}.cmd")));
        }
        let roaming = root.path().join("redirected roaming");
        std::fs::create_dir_all(roaming.join("npm")).unwrap();
        write_executable(&roaming.join("npm").join("codex.cmd"));
        let mut child = Command::new(std::env::current_exe().unwrap())
            .args([
                "--exact",
                "launch_preflight::tests::process_preflight_uses_userprofile_without_home",
                "--nocapture",
            ])
            .env(CHILD_ROOT, root.path())
            .env("USERPROFILE", root.path())
            .env("APPDATA", &roaming)
            .env("PATH", empty_path)
            .env_remove("HOME")
            .env("COMSPEC", root.path().join("configured-command-shell.exe"))
            .env("SHELL", "/ignored/posix/shell")
            .env_remove("HYDRA_PROVIDER_CLAUDE_EXECUTABLE")
            .env_remove("HYDRA_PROVIDER_OPENCODE_EXECUTABLE")
            .env_remove("HYDRA_PROVIDER_CODEX_EXECUTABLE")
            .creation_flags(0x08000000)
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .unwrap();
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
        loop {
            if child.try_wait().unwrap().is_some() {
                break;
            }
            if std::time::Instant::now() >= deadline {
                let _ = child.kill();
                let _ = child.wait();
                panic!("owned native preflight fixture exceeded deadline");
            }
            std::thread::sleep(std::time::Duration::from_millis(10));
        }
        let output = child.wait_with_output().unwrap();
        assert!(
            output.status.success(),
            "native preflight fixture failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn missing_binary_probe(home: &Path) -> LoginShellAgentProbe {
        let login_shell = home.join("missing-provider-shell");
        std::fs::write(&login_shell, "#!/bin/sh\nexit 1\n").unwrap();
        #[cfg(unix)]
        std::fs::set_permissions(&login_shell, std::fs::Permissions::from_mode(0o700)).unwrap();
        LoginShellAgentProbe {
            login_shell,
            home: Some(home.to_path_buf()),
            #[cfg(windows)]
            roaming_app_data: None,
            selected: RefCell::new(None),
            fixture_path: Some(home.join("empty-fixture-path").into_os_string()),
        }
    }

    #[test]
    fn real_missing_provider_probe_distinguishes_store_presence_without_folder_claim() {
        let root = tempfile::tempdir().unwrap();
        let probe = missing_binary_probe(root.path());
        let check = || {
            preflight_with_home(
                Some("codex"),
                Some("claude"),
                root.path(),
                Some(root.path()),
                &probe,
            )
        };
        std::fs::create_dir_all(root.path().join(".claude/projects")).unwrap();
        assert_eq!(
            check(),
            Err(LaunchPreflightError::Missing(
                SupportedAgentExecutable::Codex
            ))
        );
        // An empty store for another folder is deliberately enough for store presence, never a
        // claim that the selected folder has a resumable session (visible or hidden).
        std::fs::create_dir_all(root.path().join(".codex/sessions/another-folder")).unwrap();
        let error = check().unwrap_err();
        assert_eq!(
            error,
            LaunchPreflightError::MissingWithHistoryStore(SupportedAgentExecutable::Codex)
        );
        assert_eq!(error.code(), "agent_history_executable_missing");
        let message = error.user_message();
        assert_eq!(message, "Hydra found Codex's history storage, but its launcher is unavailable. Check the selected executable, installation, or login-shell PATH.");
        assert!(!message.contains("folder"));
        assert!(error.to_string().len() < 256);
        assert!(!message.contains(root.path().to_str().unwrap()));
    }

    #[test]
    fn history_presence_enriches_known_direct_paths_but_not_custom_cwd_or_probe_errors() {
        let root = tempfile::tempdir().unwrap();
        #[cfg(unix)]
        let mut probe = missing_binary_probe(root.path());
        #[cfg(windows)]
        let probe = missing_binary_probe(root.path());
        std::fs::create_dir_all(root.path().join(".claude/projects")).unwrap();
        let direct = root.path().join("claude");
        assert_eq!(
            probe.probe(
                &ProbeTarget::DirectPath {
                    agent: SupportedAgentExecutable::Claude,
                    path: direct
                },
                root.path()
            ),
            Err(LaunchPreflightError::MissingWithHistoryStore(
                SupportedAgentExecutable::Claude
            ))
        );
        assert_eq!(
            preflight_with_home(
                Some("./missing-wrapper"),
                Some("claude"),
                root.path(),
                Some(root.path()),
                &probe
            ),
            Err(LaunchPreflightError::MissingCommand)
        );
        assert_eq!(
            preflight_with_home(
                Some("claude"),
                None,
                &root.path().join("missing-cwd"),
                Some(root.path()),
                &probe
            ),
            Err(LaunchPreflightError::InvalidWorkingDirectory)
        );
        // Only Unix discovery invokes a login shell. Native Windows discovery deliberately does
        // not depend on shell availability; its deterministic empty PATH remains a missing tool.
        #[cfg(unix)]
        {
            probe.login_shell = root.path().join("missing-shell");
            assert_eq!(
                preflight_with_home(Some("claude"), None, root.path(), Some(root.path()), &probe),
                Err(LaunchPreflightError::ProbeUnavailable(
                    SupportedAgentExecutable::Claude
                ))
            );
        }
    }

    #[test]
    fn canonical_provider_names_map_to_existing_history_adapters() {
        let root = tempfile::tempdir().unwrap();
        let probe = missing_binary_probe(root.path());
        for (selected, command, store, agent) in [
            (
                "antigravity",
                "agy",
                ".gemini/antigravity-cli",
                SupportedAgentExecutable::Antigravity,
            ),
            (
                "kiro",
                "kiro-cli chat",
                ".kiro/sessions/cli",
                SupportedAgentExecutable::Kiro,
            ),
            (
                "cursor",
                "agent",
                ".cursor/projects",
                SupportedAgentExecutable::Cursor,
            ),
        ] {
            std::fs::create_dir_all(root.path().join(store)).unwrap();
            assert_eq!(
                preflight_with_home(
                    Some(command),
                    Some(selected),
                    root.path(),
                    Some(root.path()),
                    &probe
                ),
                Err(LaunchPreflightError::MissingWithHistoryStore(agent))
            );
        }
    }

    #[test]
    #[cfg(unix)]
    fn canonical_probe_uses_the_shared_login_shell_mode() {
        let root = tempfile::tempdir().unwrap();
        let fake_shell = root.path().join("fake-shell");
        std::fs::write(
            &fake_shell,
            // Execute the real lookup with a fixture shell function. An empty successful exit
            // no longer proves provider discovery: the resolver requires its framed response.
            format!("#!/bin/sh\n[ \"$1\" = '{LOGIN_SHELL_COMMAND_FLAGS}' ] || exit 97\ncodex() {{ :; }}\neval \"$2\"\n"),
        )
        .unwrap();
        std::fs::set_permissions(&fake_shell, std::fs::Permissions::from_mode(0o700)).unwrap();

        let probe = LoginShellAgentProbe {
            login_shell: fake_shell,
            home: Some(root.path().to_path_buf()),
            selected: RefCell::new(None),
            fixture_path: Some(root.path().into()),
        };
        assert!(probe
            .login_shell_has(SupportedAgentExecutable::Codex, root.path())
            .unwrap());
        assert!(
            probe.selected.borrow().is_none(),
            "fixture is a shell function, not a selected executable"
        );
    }

    #[test]
    fn known_root_preparation_keeps_provider_grammar_and_selected_executable_separate() {
        let root = tempfile::tempdir().unwrap();
        let executable = native_executable(root.path().join(".local/bin/claude"));
        std::fs::create_dir_all(executable.parent().unwrap()).unwrap();
        write_executable(&executable);
        let prepared = prepare_with_probe(
            Some("claude --resume owned-conversation"),
            Some("claude"),
            root.path(),
            missing_binary_probe(root.path()),
        )
        .unwrap();
        let argv = prepared.explicit_argv.unwrap();
        assert_eq!(argv, ["claude", "--resume", "owned-conversation"]);
        let selected = prepared.provider_executable.unwrap();
        assert_eq!(selected.path_for("claude"), Some(executable.as_path()));
        assert!(reprobe_selected_provider(&argv, &selected).is_ok());
        assert!(reprobe_selected_provider(&["codex".into()], &selected).is_err());
        std::fs::remove_file(executable).unwrap();
        assert!(reprobe_selected_provider(&argv, &selected).is_err());
        std::fs::create_dir_all(root.path().join(".claude/projects")).unwrap();
        let error =
            reprobe_selected_provider_with_home(&argv, &selected, Some(root.path())).unwrap_err();
        assert_eq!(
            error,
            LaunchPreflightError::MissingWithHistoryStore(SupportedAgentExecutable::Claude)
        );
        assert!(error.user_message().contains("history storage"));
        assert!(!error.user_message().contains(root.path().to_str().unwrap()));
    }

    #[test]
    #[cfg(unix)]
    fn login_shell_mode_matches_the_qualified_platform_policy() {
        assert_eq!(LOGIN_SHELL_COMMAND_FLAGS, "-lic");
    }

    impl AgentExecutableProbe for StubProbe {
        fn probe(&self, _target: &ProbeTarget, _cwd: &Path) -> Result<bool, LaunchPreflightError> {
            Ok(self.available)
        }
    }

    fn cwd() -> &'static Path {
        #[cfg(unix)]
        return Path::new("/tmp");
        #[cfg(windows)]
        {
            static CWD: std::sync::OnceLock<PathBuf> = std::sync::OnceLock::new();
            CWD.get_or_init(std::env::temp_dir).as_path()
        }
    }

    #[test]
    #[cfg(windows)]
    fn native_direct_path_checks_supported_files_not_directories_or_unknown_formats() {
        let root = tempfile::tempdir().unwrap();
        for name in ["tool.exe", "tool.COM", "tool.cmd", "tool.BAT"] {
            let path = root.path().join(name);
            write_executable(&path);
            assert!(is_executable_file(&path), "native executable suffix {name}");
            std::fs::remove_file(&path).unwrap();
            assert!(!is_executable_file(&path));
            std::fs::create_dir(&path).unwrap();
            assert!(
                !is_executable_file(&path),
                "directory is never an executable"
            );
        }
        let text = root.path().join("tool.txt");
        write_executable(&text);
        assert!(!is_executable_file(&text));
    }

    #[test]
    fn canonical_agents_are_classified_from_actual_argv() {
        for command in [
            "claude",
            "codex --model x",
            "gemini",
            "opencode --continue",
            "copilot --continue",
            "agy --conversation conversation-123",
            "kimi --session session_abc123",
            "kiro-cli chat --resume-id 20000000-0000-4000-8000-000000000001",
            "amp last --dangerously-allow-all",
            "devin --continue --model opus --permission-mode=dangerous",
            "droid --resume --auto=high",
        ] {
            assert!(
                preflight_with(command.into(), None, cwd(), &StubProbe { available: true }).is_ok()
            );
            assert!(matches!(
                preflight_with(command.into(), None, cwd(), &StubProbe { available: false }),
                Err(LaunchPreflightError::Missing(_))
            ));
        }
    }

    #[test]
    fn amp_known_safe_argv_is_narrow_and_bounded() {
        fn argv(parts: &[&str]) -> Vec<String> {
            parts.iter().map(|part| (*part).to_string()).collect()
        }

        for accepted in [
            argv(&["amp"]),
            argv(&["amp", "last"]),
            argv(&["amp", "--dangerously-allow-all", "last"]),
            argv(&[
                "amp",
                "threads",
                "continue",
                "thread-id",
                "--dangerously-allow-all",
            ]),
        ] {
            assert!(is_canonical_amp_argv(&accepted), "argv={accepted:?}");
        }

        let oversized = "x".repeat(257);
        for rejected in [
            Vec::new(),
            argv(&["wrapper", "amp"]),
            argv(&["/example/bin/amp", "last"]),
            argv(&["amp", "config"]),
            argv(&["amp", "last", "last"]),
            argv(&["amp", "--dangerously-allow-all", "--dangerously-allow-all"]),
            argv(&["amp", "threads", "continue"]),
            argv(&["amp", "threads", "continue", "--help"]),
            argv(&["amp", "threads", "continue", "thread\nother"]),
            vec![
                "amp".into(),
                "threads".into(),
                "continue".into(),
                oversized.clone(),
            ],
        ] {
            assert!(!is_canonical_amp_argv(&rejected), "argv={rejected:?}");
        }
    }

    #[test]
    fn devin_and_factory_known_safe_argv_are_exact_and_bounded() {
        fn argv(parts: &[&str]) -> Vec<String> {
            parts.iter().map(|part| (*part).to_string()).collect()
        }

        for accepted in [
            argv(&["devin"]),
            argv(&["devin", "--continue"]),
            argv(&[
                "devin",
                "--resume",
                "session-one",
                "--model",
                "opus",
                "--permission-mode=dangerous",
            ]),
        ] {
            assert!(is_canonical_devin_argv(&accepted), "argv={accepted:?}");
        }
        for accepted in [
            argv(&["droid"]),
            argv(&["droid", "--resume"]),
            argv(&["droid", "--resume", "session-two", "--auto=high"]),
            argv(&["droid", "--auto=high", "--resume"]),
        ] {
            assert!(is_canonical_factory_argv(&accepted), "argv={accepted:?}");
        }

        let oversized = "x".repeat(257);
        for rejected in [
            Vec::new(),
            argv(&["/tmp/devin", "--continue"]),
            argv(&["wrapper", "devin"]),
            argv(&["devin", "--continue", "--resume", "id"]),
            argv(&["devin", "--resume", "--latest"]),
            argv(&["devin", "--resume", " session "]),
            argv(&["devin", "--permission-mode", "dangerous"]),
            argv(&["devin", "--unknown"]),
            vec!["devin".into(), "--resume".into(), oversized.clone()],
        ] {
            assert!(!is_canonical_devin_argv(&rejected), "argv={rejected:?}");
        }
        for rejected in [
            Vec::new(),
            argv(&["/tmp/droid", "--resume"]),
            argv(&["wrapper", "droid"]),
            argv(&["droid", "--model", "auto"]),
            argv(&["droid", "--resume", "bad\nid"]),
            argv(&["droid", "--resume", " session "]),
            argv(&["droid", "--resume", "id", "--resume"]),
            argv(&["droid", "exec", "--auto=high"]),
            vec!["droid".into(), "--resume".into(), oversized],
        ] {
            assert!(!is_canonical_factory_argv(&rejected), "argv={rejected:?}");
        }
    }

    #[test]
    fn generic_agent_command_requires_explicit_cursor_provenance_and_known_argv() {
        let exact = "agent --resume 123e4567-e89b-42d3-a456-426614174000 --model auto --yolo";
        assert!(matches!(
            target_for(Some(exact), Some("cursor"), cwd()).unwrap(),
            Some(ProbeTarget::LoginShell(SupportedAgentExecutable::Cursor))
        ));
        assert_eq!(
            target_for(Some(exact), None, cwd()).unwrap(),
            Some(ProbeTarget::ProcessPathCommand("agent".into()))
        );
        for unrelated in [
            "agent --serve",
            "agent --resume not-a-uuid",
            "agent --model auto --unknown",
        ] {
            assert_eq!(
                target_for(Some(unrelated), Some("cursor"), cwd()).unwrap(),
                Some(ProbeTarget::ProcessPathCommand("agent".into())),
                "unproven generic argv must remain a custom command: {unrelated}",
            );
        }
    }

    #[test]
    fn bare_canonical_commands_are_case_sensitive_but_selected_agent_names_are_not() {
        assert_eq!(
            target_for(Some("CLAUDE"), Some("claude"), cwd()),
            Err(LaunchPreflightError::NonCanonicalCommandCase(
                SupportedAgentExecutable::Claude
            ))
        );
        assert_eq!(
            target_for(Some("claude"), Some("CLAUDE"), cwd()).unwrap(),
            Some(ProbeTarget::LoginShell(SupportedAgentExecutable::Claude))
        );
        assert_eq!(
            target_for(None, Some("CLAUDE"), cwd()).unwrap(),
            Some(ProbeTarget::LoginShell(SupportedAgentExecutable::Claude))
        );
        assert_eq!(
            target_for(Some("AGY"), Some("antigravity"), cwd()),
            Err(LaunchPreflightError::NonCanonicalCommandCase(
                SupportedAgentExecutable::Antigravity
            ))
        );
        assert_eq!(
            target_for(Some("agy"), Some("ANTIGRAVITY"), cwd()).unwrap(),
            Some(ProbeTarget::LoginShell(
                SupportedAgentExecutable::Antigravity
            ))
        );
        assert_eq!(
            target_for(None, Some("ANTIGRAVITY"), cwd()).unwrap(),
            Some(ProbeTarget::LoginShell(
                SupportedAgentExecutable::Antigravity
            ))
        );
    }

    #[test]
    fn product_provider_ids_map_to_their_canonical_executables() {
        for (selected, executable) in [
            ("copilot", SupportedAgentExecutable::Copilot),
            ("antigravity", SupportedAgentExecutable::Antigravity),
            ("kimi", SupportedAgentExecutable::Kimi),
            ("kiro", SupportedAgentExecutable::Kiro),
            ("cursor", SupportedAgentExecutable::Cursor),
            ("amp", SupportedAgentExecutable::Amp),
            ("devin", SupportedAgentExecutable::Devin),
            ("factory", SupportedAgentExecutable::Factory),
            ("droid", SupportedAgentExecutable::Factory),
            // Durable launch metadata uses the executable ID and remains preflightable.
            ("agy", SupportedAgentExecutable::Antigravity),
            // Legacy Gemini records remain accepted even though new UI work may hide the picker.
            ("gemini", SupportedAgentExecutable::Gemini),
        ] {
            assert_eq!(
                target_for(None, Some(selected), cwd()).unwrap(),
                Some(ProbeTarget::LoginShell(executable))
            );
        }
        assert_eq!(SupportedAgentExecutable::Copilot.command(), "copilot");
        assert_eq!(SupportedAgentExecutable::Antigravity.command(), "agy");
        assert_eq!(SupportedAgentExecutable::Kiro.command(), "kiro-cli");
        assert_eq!(SupportedAgentExecutable::Cursor.command(), "agent");
        assert_eq!(SupportedAgentExecutable::Amp.command(), "amp");
        assert_eq!(SupportedAgentExecutable::Devin.command(), "devin");
        assert_eq!(SupportedAgentExecutable::Factory.command(), "droid");
    }

    #[test]
    fn terminal_without_command_bypasses_probe_but_custom_wrapper_is_checked_as_itself() {
        let missing = StubProbe { available: false };
        assert!(preflight_with(None, Some("terminal"), cwd(), &missing).is_ok());
        assert!(preflight_with(Some(""), Some("terminal"), cwd(), &missing).is_ok());
        assert!(preflight_with(Some("   "), Some("Terminal"), cwd(), &missing).is_ok());
        assert!(preflight_with(None, None, cwd(), &missing).is_ok());
        assert_eq!(target_for(Some(""), Some("terminal"), cwd()).unwrap(), None);
        assert_eq!(prepare(Some(""), Some("terminal"), cwd()).unwrap(), None);
        assert_eq!(
            preflight_with(
                Some("my-agent-wrapper --flag"),
                Some("claude"),
                cwd(),
                &missing
            ),
            Err(LaunchPreflightError::MissingCommand)
        );
        assert_eq!(
            target_for(Some("my-agent-wrapper --flag"), Some("claude"), cwd()).unwrap(),
            Some(ProbeTarget::ProcessPathCommand(
                "my-agent-wrapper".to_string()
            ))
        );
        assert_eq!(
            preflight_with(
                Some("terminal-wrapper --flag"),
                Some("terminal"),
                cwd(),
                &missing
            ),
            Err(LaunchPreflightError::MissingCommand),
            "Terminal bypasses probing only when it has no command"
        );
    }

    #[test]
    fn selected_agent_is_used_when_no_resolved_command_exists() {
        assert!(matches!(
            preflight_with(None, Some("claude"), cwd(), &StubProbe { available: false }),
            Err(LaunchPreflightError::Missing(
                SupportedAgentExecutable::Claude
            ))
        ));
        assert!(matches!(
            preflight_with(
                None,
                Some("unknown-provider"),
                cwd(),
                &StubProbe { available: true }
            ),
            Err(LaunchPreflightError::UnsupportedAgent)
        ));
    }

    #[test]
    fn every_real_launch_rejects_a_missing_working_directory_before_probe() {
        let missing = Path::new("/definitely/not/a/hydra/working-directory");
        assert_eq!(
            preflight_with(
                None,
                Some("terminal"),
                missing,
                &StubProbe { available: true }
            ),
            Err(LaunchPreflightError::InvalidWorkingDirectory)
        );
        assert_eq!(
            preflight_with(
                Some("claude"),
                Some("claude"),
                missing,
                &StubProbe { available: true }
            ),
            Err(LaunchPreflightError::InvalidWorkingDirectory)
        );
    }

    #[test]
    fn tilde_working_directories_use_the_same_home_expansion_as_project_launches() {
        let home = tempfile::tempdir().unwrap();
        let project = home.path().join("project");
        std::fs::create_dir(&project).unwrap();
        let probe = StubProbe { available: true };

        assert!(preflight_with_home(
            None,
            Some("terminal"),
            Path::new("~/project"),
            Some(home.path()),
            &probe,
        )
        .is_ok());
        assert!(preflight_with_home(
            None,
            Some("terminal"),
            Path::new("~"),
            Some(home.path()),
            &probe,
        )
        .is_ok());
        assert_eq!(
            preflight_with_home(
                None,
                Some("terminal"),
                Path::new("~other/project"),
                Some(home.path()),
                &probe,
            ),
            Err(LaunchPreflightError::InvalidWorkingDirectory)
        );
    }

    #[test]
    #[cfg(unix)]
    fn direct_path_check_uses_current_user_execute_access() {
        let dir = tempfile::tempdir().unwrap();
        let executable = dir.path().join("claude");
        std::fs::write(&executable, b"#!/bin/sh\nexit 0\n").unwrap();

        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(is_executable_file(&executable));

        std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o000)).unwrap();
        assert!(!is_executable_file(&executable));

        // For a non-root owner, an execute bit granted only to "other" must not be mistaken for
        // executable access. Root intentionally has different POSIX X_OK semantics.
        if unsafe { getuid() } != 0 {
            std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o001)).unwrap();
            assert!(!is_executable_file(&executable));
        }
    }

    #[test]
    fn custom_command_probe_uses_exec_path_and_never_shell_syntax() {
        let command = if cfg!(windows) { "cmd.exe" } else { "sh" };
        assert!(process_path_executable(command, cwd()).is_some());
        assert!(process_path_executable("sh; touch /tmp/nope", cwd()).is_none());
    }

    #[test]
    fn relative_and_empty_path_entries_resolve_against_launch_cwd() {
        let root = tempfile::tempdir().unwrap();
        let bin = root.path().join("bin");
        std::fs::create_dir(&bin).unwrap();
        let relative = native_executable(bin.join("relative-wrapper"));
        let empty = native_executable(root.path().join("cwd-wrapper"));
        for executable in [&relative, &empty] {
            write_executable(executable);
        }

        assert_eq!(
            process_path_executable_in(
                std::ffi::OsStr::new("bin"),
                "relative-wrapper",
                root.path()
            ),
            Some(relative)
        );
        assert_eq!(
            process_path_executable_in(
                std::ffi::OsStr::new(if cfg!(windows) { ";" } else { ":" }),
                "cwd-wrapper",
                root.path()
            ),
            Some(empty)
        );
        assert!(process_path_executable_in(
            std::ffi::OsStr::new("bin"),
            "cwd-wrapper",
            root.path()
        )
        .is_none());
    }

    #[test]
    fn malformed_explicit_command_fails_closed_instead_of_falling_back() {
        for command in ["claude 'unterminated", "", "   ", "''", "\"\" --flag", "/"] {
            assert_eq!(
                preflight_with(
                    Some(command),
                    Some("claude"),
                    cwd(),
                    &StubProbe { available: true }
                ),
                Err(LaunchPreflightError::MalformedCommand),
                "expected {command:?} to fail closed"
            );
        }
    }

    #[test]
    fn dashboard_quoted_arguments_round_trip_spaces_quotes_and_backslashes() {
        assert_eq!(
            split_command_line(
                r#"gemini --session-file "/tmp/Hydra Sessions/a \"quoted\" transcript.json" --model "model with spaces\\variant""#,
            )
            .unwrap(),
            vec![
                "gemini",
                "--session-file",
                "/tmp/Hydra Sessions/a \"quoted\" transcript.json",
                "--model",
                "model with spaces\\variant",
            ]
        );
        assert_eq!(
            split_command_line(r#"wrapper "" tail"#).unwrap(),
            vec!["wrapper", "", "tail"]
        );
        assert_eq!(
            split_command_line("wrapper trailing\\"),
            Err(LaunchPreflightError::MalformedCommand)
        );
    }

    #[test]
    fn actual_custom_command_takes_precedence_over_selected_agent() {
        assert!(preflight_with(
            Some("codex --model test"),
            Some("claude"),
            cwd(),
            &StubProbe { available: true }
        )
        .is_ok());
        assert_eq!(
            target_for(Some("codex --model test"), Some("claude"), cwd()).unwrap(),
            Some(ProbeTarget::LoginShell(SupportedAgentExecutable::Codex))
        );
    }

    #[test]
    fn quoted_direct_agent_path_resolves_against_launch_cwd() {
        assert_eq!(
            target_for(Some("'./claude' --resume abc"), Some("claude"), cwd()).unwrap(),
            Some(ProbeTarget::DirectPath {
                agent: SupportedAgentExecutable::Claude,
                path: cwd().join("./claude"),
            })
        );
    }

    #[test]
    fn prepared_direct_command_records_the_absolute_checked_identity() {
        let root = tempfile::tempdir().unwrap();
        let executable = native_executable(root.path().join("custom-wrapper"));
        write_executable(&executable);

        let command = format!(
            "./{} --flag",
            executable.file_name().unwrap().to_str().unwrap()
        );
        let prepared = prepare(Some(&command), Some("claude"), root.path())
            .expect("direct executable should prepare")
            .expect("explicit argv");
        assert_eq!(
            std::fs::canonicalize(&prepared[0]).unwrap(),
            std::fs::canonicalize(&executable).unwrap()
        );
        assert_eq!(prepared[1], "--flag");
        assert!(Path::new(&prepared[0]).is_absolute());
    }

    #[test]
    fn unavailable_daemon_message_does_not_claim_existing_sessions_survived() {
        let error = LaunchPreflightError::MutationDaemonUnavailable;
        assert_eq!(error.code(), "daemon_mutation_unavailable");
        assert_eq!(
            error.user_message(),
            "Hydra could not reach a compatible terminal service. Close and reopen this Hydra window, then retry. No new session was created."
        );
    }

    #[test]
    fn display_is_bounded_and_never_contains_raw_command_or_paths() {
        let values = [
            LaunchPreflightError::MalformedCommand,
            LaunchPreflightError::UnsupportedAgent,
            LaunchPreflightError::NonCanonicalCommandCase(SupportedAgentExecutable::OpenCode),
            LaunchPreflightError::InvalidWorkingDirectory,
            LaunchPreflightError::Missing(SupportedAgentExecutable::Claude),
            LaunchPreflightError::MissingCommand,
            LaunchPreflightError::MutationDaemonUnavailable,
            LaunchPreflightError::ProbeUnavailable(SupportedAgentExecutable::Codex),
            LaunchPreflightError::ProbeTimedOut(SupportedAgentExecutable::Gemini),
        ];
        let personal_root = ["/", "Users", "/"].concat();
        for value in values {
            let rendered = value.to_string();
            assert!(rendered.len() < 256);
            assert!(!rendered.contains(&personal_root));
            assert!(!rendered.contains("--dangerously"));
        }
    }
}
