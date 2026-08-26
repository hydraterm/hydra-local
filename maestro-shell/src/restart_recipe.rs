use crate::records::{LaunchSpec, SessionRecord};
use crate::store::{self, LoadOutcome, StoreError};
use crate::{AppPaths, RecordKind};

const KNOWN_SAFE_AGENTS: &[&str] = &[
    "claude", "codex", "gemini", "opencode", "copilot", "agy", "kimi", "kiro-cli", "agent", "amp",
    "devin", "droid",
];
// Cursor's executable is the generic word `agent`; only explicit KnownSafe provider provenance may opt into
// its restart rewriting. Devin and Factory also enter through their strict selected-provider validators, never
// basename/path inference. Inferring any of them from arbitrary ad-hoc argv would launder custom commands.
const INFERABLE_AGENTS: &[&str] = &[
    "claude", "codex", "gemini", "opencode", "copilot", "agy", "kimi", "kiro-cli",
];

pub fn canonical_launch_for_restart(launch: &LaunchSpec) -> LaunchSpec {
    match launch {
        LaunchSpec::KnownSafe {
            launch_spec_id,
            params,
        } if is_agent(launch_spec_id) => LaunchSpec::KnownSafe {
            launch_spec_id: launch_spec_id.clone(),
            params: canonical_agent_params(launch_spec_id, params),
        },
        LaunchSpec::AdHocRedacted {
            argv,
            redacted: false,
            ..
        } => canonical_adhoc_agent_launch(argv).unwrap_or_else(|| launch.clone()),
        _ => launch.clone(),
    }
}

/// Whether a trusted provider recipe names one exact provider conversation instead of a
/// workspace-latest fallback. This predicate is intentionally narrower than `KnownSafe` itself:
/// fresh-daemon recovery may use it to restore a visible pane whose durable status became
/// `Exited` during machine shutdown without guessing which provider conversation to reopen.
///
/// `AdHocRedacted`, wrappers, arbitrary commands, and provider "continue/latest" recipes never
/// satisfy this boundary. Provider-specific value validation mirrors the canonicalizer below so a
/// malformed identity cannot gain restart authority merely by following a familiar flag.
pub fn known_safe_provider_has_exact_resume(launch: &LaunchSpec) -> bool {
    strict_known_safe_provider_mode(launch) == Some(PreparedProviderLaunchMode::ExactResume)
}

pub(crate) fn strict_known_safe_provider_mode(
    launch: &LaunchSpec,
) -> Option<PreparedProviderLaunchMode> {
    let LaunchSpec::KnownSafe {
        launch_spec_id,
        params,
    } = launch
    else {
        return None;
    };

    if !is_agent(launch_spec_id) || canonical_agent_params(launch_spec_id, params) != *params {
        return None;
    }
    strict_prepared_provider_params(launch_spec_id, params)
}

/// Closed launch language accepted by transaction-prepared provider sessions.
///
/// `canonical_launch_for_restart` is deliberately a sanitizer for old durable records: it drops
/// unknown bytes and invents a workspace-latest fallback. It is therefore not an authorization
/// check for a brand-new launch. This parser rejects every byte outside the reviewed provider
/// grammar before either daemon argv or durable launch metadata is minted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PreparedProviderLaunchMode {
    ExactResume,
    /// A bare provider launch with no provider conversation identity. It may run once, but Hydra
    /// cannot publish a durable restart recipe without guessing from mutable history.
    FreshUnassigned,
    /// The user explicitly selected a non-exact provider operation such as latest, a picker search,
    /// an ordinal index, or a session import. It remains explicit-user-only restart authority.
    ExplicitNonExact,
    /// The provider's first launch is assigned a UUID up front; publication converts that create
    /// identity to the corresponding exact resume recipe.
    FreshWithAssignedIdentity,
}

pub(crate) fn strict_prepared_provider_launch(
    selected_provider: &str,
    source_argv: &[String],
) -> Option<(PreparedProviderLaunchMode, LaunchSpec)> {
    if source_argv.first().map(String::as_str) != Some(selected_provider)
        || !is_agent(selected_provider)
    {
        return None;
    }
    let params = &source_argv[1..];
    let mode = strict_prepared_provider_params(selected_provider, params)?;
    let canonical = canonical_launch_for_restart(&LaunchSpec::KnownSafe {
        launch_spec_id: selected_provider.to_string(),
        params: params.to_vec(),
    });
    let LaunchSpec::KnownSafe {
        launch_spec_id,
        params: _,
    } = &canonical
    else {
        return None;
    };
    if launch_spec_id != selected_provider {
        return None;
    }
    let exact = known_safe_provider_has_exact_resume(&canonical);
    match mode {
        PreparedProviderLaunchMode::ExactResume if exact => Some((mode, canonical)),
        PreparedProviderLaunchMode::FreshWithAssignedIdentity if exact => Some((mode, canonical)),
        PreparedProviderLaunchMode::FreshUnassigned
        | PreparedProviderLaunchMode::ExplicitNonExact
            if !exact =>
        {
            Some((mode, canonical))
        }
        _ => None,
    }
}

fn strict_prepared_provider_params(
    provider: &str,
    params: &[String],
) -> Option<PreparedProviderLaunchMode> {
    let mut idx = 0;
    let mut resume = None;
    let mut model_seen = false;
    let mut dangerous_seen = false;
    let mut kiro_chat_seen = false;

    let set_resume = |slot: &mut Option<PreparedProviderLaunchMode>, mode| {
        if slot.is_some() {
            None
        } else {
            *slot = Some(mode);
            Some(())
        }
    };
    while idx < params.len() {
        let token = params[idx].as_str();
        match (provider, token) {
            ("claude", "--session-id") => {
                params
                    .get(idx + 1)
                    .and_then(|value| canonical_provider_uuid(value))?;
                set_resume(
                    &mut resume,
                    PreparedProviderLaunchMode::FreshWithAssignedIdentity,
                )?;
                idx += 2;
            }
            ("claude", "--resume") => {
                let value = params.get(idx + 1).filter(|value| strict_opaque(value))?;
                let mode = if canonical_provider_uuid(value).is_some() {
                    PreparedProviderLaunchMode::ExactResume
                } else {
                    PreparedProviderLaunchMode::ExplicitNonExact
                };
                set_resume(&mut resume, mode)?;
                idx += 2;
            }
            ("claude", "--continue") => {
                set_resume(&mut resume, PreparedProviderLaunchMode::ExplicitNonExact)?;
                idx += 1;
            }
            ("codex", "resume") => {
                let value = params.get(idx + 1)?;
                let mode = if value == "--last" || strict_opaque(value) {
                    if canonical_provider_uuid(value).is_some() {
                        PreparedProviderLaunchMode::ExactResume
                    } else {
                        PreparedProviderLaunchMode::ExplicitNonExact
                    }
                } else {
                    return None;
                };
                set_resume(&mut resume, mode)?;
                idx += 2;
            }
            ("gemini", "--session-file") => {
                let value = params
                    .get(idx + 1)
                    .filter(|value| strict_path_value(value))?;
                // Importing a session file creates a new Gemini identity on every invocation; the
                // path is stable input, not exact resume authority.
                set_resume(&mut resume, PreparedProviderLaunchMode::ExplicitNonExact)?;
                let _ = value;
                idx += 2;
            }
            ("gemini", "--session-id") => {
                params
                    .get(idx + 1)
                    .and_then(|value| canonical_provider_uuid(value))?;
                set_resume(
                    &mut resume,
                    PreparedProviderLaunchMode::FreshWithAssignedIdentity,
                )?;
                idx += 2;
            }
            ("gemini", "--resume") => {
                let value = params.get(idx + 1)?;
                let mode = if value == "latest" || canonical_gemini_resume_index(value) {
                    PreparedProviderLaunchMode::ExplicitNonExact
                } else if canonical_provider_uuid(value).is_some() {
                    PreparedProviderLaunchMode::ExactResume
                } else {
                    return None;
                };
                set_resume(&mut resume, mode)?;
                idx += 2;
            }
            ("opencode", "--session") => {
                let value = params.get(idx + 1).filter(|value| strict_opaque(value))?;
                set_resume(&mut resume, PreparedProviderLaunchMode::ExactResume)?;
                let _ = value;
                idx += 2;
            }
            ("opencode", "--continue") => {
                set_resume(&mut resume, PreparedProviderLaunchMode::ExplicitNonExact)?;
                idx += 1;
            }
            ("copilot", value) if value.starts_with("--resume=") => {
                value
                    .strip_prefix("--resume=")
                    .and_then(canonical_provider_uuid)?;
                set_resume(&mut resume, PreparedProviderLaunchMode::ExactResume)?;
                idx += 1;
            }
            ("copilot", value) if value.starts_with("--session-id=") => {
                value
                    .strip_prefix("--session-id=")
                    .and_then(canonical_provider_uuid)?;
                set_resume(
                    &mut resume,
                    PreparedProviderLaunchMode::FreshWithAssignedIdentity,
                )?;
                idx += 1;
            }
            ("copilot", "--continue") => {
                set_resume(&mut resume, PreparedProviderLaunchMode::ExplicitNonExact)?;
                idx += 1;
            }
            ("agy", "--conversation") | ("kimi", "--session") => {
                let value = params.get(idx + 1).filter(|value| {
                    bounded_resume_id(value).is_some_and(|bounded| bounded == value.as_str())
                })?;
                let exact = if provider == "agy" {
                    canonical_provider_uuid(value).is_some()
                } else {
                    canonical_kimi_session_id(value)
                };
                set_resume(
                    &mut resume,
                    if exact {
                        PreparedProviderLaunchMode::ExactResume
                    } else {
                        PreparedProviderLaunchMode::ExplicitNonExact
                    },
                )?;
                idx += 2;
            }
            ("agy" | "kimi", "--continue") => {
                set_resume(&mut resume, PreparedProviderLaunchMode::ExplicitNonExact)?;
                idx += 1;
            }
            ("kiro-cli", "chat") => {
                if kiro_chat_seen || idx != 0 {
                    return None;
                }
                kiro_chat_seen = true;
                idx += 1;
            }
            ("kiro-cli", "--resume-id") => {
                params
                    .get(idx + 1)
                    .and_then(|value| canonical_provider_uuid(value))?;
                set_resume(&mut resume, PreparedProviderLaunchMode::ExactResume)?;
                idx += 2;
            }
            ("kiro-cli", "--resume") => {
                set_resume(&mut resume, PreparedProviderLaunchMode::ExplicitNonExact)?;
                idx += 1;
            }
            ("agent", "--resume") => {
                params
                    .get(idx + 1)
                    .and_then(|value| canonical_provider_uuid(value))?;
                set_resume(&mut resume, PreparedProviderLaunchMode::ExactResume)?;
                idx += 2;
            }
            ("agent", "--continue") => {
                set_resume(&mut resume, PreparedProviderLaunchMode::ExplicitNonExact)?;
                idx += 1;
            }
            ("amp", "last") => {
                set_resume(&mut resume, PreparedProviderLaunchMode::ExplicitNonExact)?;
                idx += 1;
            }
            ("amp", "threads") => {
                if params.get(idx + 1).map(String::as_str) != Some("continue") {
                    return None;
                }
                let value = params.get(idx + 2).filter(|value| {
                    bounded_amp_thread_target(value)
                        .is_some_and(|bounded| bounded == value.as_str())
                })?;
                set_resume(&mut resume, PreparedProviderLaunchMode::ExactResume)?;
                let _ = value;
                idx += 3;
            }
            ("devin", "--resume") => {
                let value = params.get(idx + 1).filter(|value| {
                    bounded_opaque_resume_id(value).is_some_and(|bounded| bounded == value.as_str())
                })?;
                set_resume(&mut resume, PreparedProviderLaunchMode::ExactResume)?;
                let _ = value;
                idx += 2;
            }
            ("devin", "--continue") => {
                set_resume(&mut resume, PreparedProviderLaunchMode::ExplicitNonExact)?;
                idx += 1;
            }
            ("droid", "--resume") => {
                if let Some(value) = params.get(idx + 1).filter(|value| strict_opaque(value)) {
                    set_resume(&mut resume, PreparedProviderLaunchMode::ExactResume)?;
                    let _ = value;
                    idx += 2;
                } else {
                    set_resume(&mut resume, PreparedProviderLaunchMode::ExplicitNonExact)?;
                    idx += 1;
                }
            }
            (_, "--model") if !matches!(provider, "amp" | "droid") => {
                let value = params
                    .get(idx + 1)
                    .filter(|value| strict_model_name(value))?;
                if model_seen {
                    return None;
                }
                model_seen = true;
                let _ = value;
                idx += 2;
            }
            ("claude", "--dangerously-skip-permissions")
            | ("codex", "--dangerously-bypass-approvals-and-sandbox")
            | ("gemini", "--yolo")
            | ("opencode", "--auto")
            | ("copilot", "--yolo")
            | ("agy", "--dangerously-skip-permissions")
            | ("kimi", "--yolo")
            | ("kiro-cli", "--trust-all-tools")
            | ("agent", "--yolo")
            | ("amp", "--dangerously-allow-all")
            | ("devin", "--permission-mode=dangerous")
            | ("droid", "--auto=high") => {
                if dangerous_seen {
                    return None;
                }
                dangerous_seen = true;
                idx += 1;
            }
            _ => return None,
        }
    }
    if (provider == "kiro-cli" && !kiro_chat_seen) || (provider == "copilot" && resume.is_none()) {
        return None;
    }
    Some(resume.unwrap_or(PreparedProviderLaunchMode::FreshUnassigned))
}

fn strict_opaque(value: &str) -> bool {
    bounded_opaque_resume_id(value).is_some_and(|bounded| bounded == value)
}

fn canonical_gemini_resume_index(value: &str) -> bool {
    value
        .parse::<usize>()
        .ok()
        .filter(|index| *index > 0)
        .is_some_and(|index| index.to_string() == value)
}

fn canonical_kimi_session_id(value: &str) -> bool {
    value
        .strip_prefix("session_")
        .and_then(canonical_provider_uuid)
        .is_some()
}

fn strict_path_value(value: &str) -> bool {
    !value.is_empty()
        && value.trim() == value
        && !value.starts_with('-')
        && value.chars().count() <= 1024
        && !value.chars().any(char::is_control)
}

fn strict_model_name(value: &str) -> bool {
    !value.starts_with('-') && bounded_model_name(value).is_some_and(|bounded| bounded == value)
}

pub fn canonicalize_session_restart_recipe(
    paths: &AppPaths,
    session_id: &str,
    now_ms: u64,
) -> Result<Option<SessionRecord>, StoreError> {
    let Some(outcome) = store::load_one::<SessionRecord>(paths, RecordKind::Session, session_id)?
    else {
        return Ok(None);
    };
    let LoadOutcome::Loaded(mut record) = outcome else {
        return Ok(None);
    };
    let canonical = canonical_launch_for_restart(&record.launch);
    if canonical == record.launch {
        return Ok(Some(record));
    }
    record.launch = canonical;
    store::write_record(paths, RecordKind::Session, session_id, now_ms, &record)?;
    Ok(Some(record))
}

pub fn canonicalize_all_session_restart_recipes(
    paths: &AppPaths,
    now_ms: u64,
) -> Result<usize, StoreError> {
    let outcomes = store::load_all::<SessionRecord>(paths, RecordKind::Session)?;
    let mut rewritten = 0;
    for outcome in outcomes {
        let LoadOutcome::Loaded(mut record) = outcome else {
            continue;
        };
        let canonical = canonical_launch_for_restart(&record.launch);
        if canonical == record.launch {
            continue;
        }
        record.launch = canonical;
        let session_id = record.session_id.clone();
        store::write_record(paths, RecordKind::Session, &session_id, now_ms, &record)?;
        rewritten += 1;
    }
    Ok(rewritten)
}

fn canonical_adhoc_agent_launch(argv: &[String]) -> Option<LaunchSpec> {
    let command = argv.first()?;
    let command_path = std::path::Path::new(command);
    if command.contains('/') && !command_path.is_absolute() {
        return None;
    }
    let provider = command_path.file_name()?.to_str()?;
    if !INFERABLE_AGENTS.contains(&provider) {
        return None;
    }
    let mut normalized = argv.to_vec();
    normalized[0] = provider.to_string();
    strict_prepared_provider_launch(provider, &normalized).map(|(_, canonical)| canonical)
}

fn is_agent(value: &str) -> bool {
    KNOWN_SAFE_AGENTS.contains(&value)
}

pub fn is_known_provider_id(value: &str) -> bool {
    is_agent(value)
}

pub fn is_strict_prepared_provider_launch(provider: &str, source_argv: &[String]) -> bool {
    strict_prepared_provider_launch(provider, source_argv).is_some()
}

pub fn is_valid_prepared_provider_custom_adhoc(provider: &str, source_argv: &[String]) -> bool {
    source_argv.first().map(String::as_str) == Some(provider)
        && is_known_provider_id(provider)
        && !prepared_provider_source_has_selector_shape(provider, &source_argv[1..])
}

pub(crate) fn prepared_provider_source_has_selector_shape(
    provider: &str,
    params: &[String],
) -> bool {
    match provider {
        "claude" => params.iter().any(|value| {
            value.starts_with("--resume")
                || value.starts_with("--continue")
                || value.starts_with("--session-id")
        }),
        "codex" => params
            .iter()
            .any(|value| value.starts_with("resume") || value.starts_with("--continue")),
        "gemini" => params.iter().any(|value| {
            value.starts_with("--resume")
                || value.starts_with("--session-id")
                || value.starts_with("--session-file")
        }),
        "opencode" => params
            .iter()
            .any(|value| value.starts_with("--session") || value.starts_with("--continue")),
        "copilot" => params.iter().any(|value| {
            value.starts_with("--resume")
                || value.starts_with("--session-id")
                || value.starts_with("--continue")
                || value == "-r"
                || value.starts_with("-r=")
                || value.starts_with("--connect")
        }),
        "agy" => params
            .iter()
            .any(|value| value.starts_with("--conversation") || value.starts_with("--continue")),
        "kimi" => params
            .iter()
            .any(|value| value.starts_with("--session") || value.starts_with("--continue")),
        "kiro-cli" => params
            .iter()
            .any(|value| value.starts_with("--resume-id") || value.starts_with("--resume")),
        "agent" | "devin" => params
            .iter()
            .any(|value| value.starts_with("--resume") || value.starts_with("--continue")),
        "droid" => params.iter().any(|value| value.starts_with("--resume")),
        "amp" => params.iter().any(|value| {
            value.starts_with("last")
                || value.starts_with("threads")
                || value.starts_with("continue")
        }),
        _ => false,
    }
}

fn canonical_agent_params(agent: &str, params: &[String]) -> Vec<String> {
    if agent == "devin" {
        return canonical_devin_params(params);
    }
    if agent == "droid" {
        return canonical_droid_params(params);
    }
    // Kiro's interactive CLI is a subcommand: every valid fresh/resume/restart recipe must retain `chat`
    // as argv[0]. Other providers have no mandatory base argv.
    let mut out = if agent == "kiro-cli" {
        vec!["chat".to_string()]
    } else {
        Vec::new()
    };
    let mut idx = 0;
    while idx < params.len() {
        let token = params[idx].as_str();
        match token {
            "--mini" if agent == "opencode" => {
                idx += 1;
            }
            "--session" if agent == "opencode" => {
                if let Some(id) = params.get(idx + 1).and_then(|s| non_flag(s)) {
                    push_pair_once(&mut out, "--session", id);
                }
                idx += 2;
            }
            "--resume" if agent == "claude" => {
                if let Some(id) = params.get(idx + 1).and_then(|s| non_flag(s)) {
                    push_pair_once(&mut out, "--resume", id);
                }
                idx += 2;
            }
            "--session-id" if agent == "claude" => {
                // Hydra uses this UUID only for the first Claude launch. Every durable restart must
                // resume the exact conversation instead of replaying create or guessing latest.
                if let Some(id) = params
                    .get(idx + 1)
                    .and_then(|value| canonical_provider_uuid(value))
                {
                    push_pair_once(&mut out, "--resume", id);
                }
                idx += 2;
            }
            "resume" if agent == "codex" => {
                if let Some(id) = params.get(idx + 1).and_then(|s| non_flag(s)) {
                    push_pair_once(&mut out, "resume", id);
                }
                idx += 2;
            }
            "--session-file" if agent == "gemini" => {
                if let Some(path) = params.get(idx + 1).and_then(|s| non_empty(s)) {
                    push_pair_once(&mut out, "--session-file", path);
                }
                idx += 2;
            }
            "--session-id" if agent == "gemini" => {
                // Gemini accepts a caller-chosen UUID for one new session. Persist only the exact
                // resume selector so a reboot cannot make sibling panes converge on `latest`.
                if let Some(id) = params
                    .get(idx + 1)
                    .and_then(|value| canonical_provider_uuid(value))
                {
                    push_pair_once(&mut out, "--resume", id);
                }
                idx += 2;
            }
            "--resume" if agent == "gemini" => {
                if let Some(target) = params.get(idx + 1).and_then(|value| {
                    (value == "latest")
                        .then_some(value.as_str())
                        .or_else(|| non_flag(value))
                }) {
                    push_pair_once(&mut out, "--resume", target);
                }
                idx += 2;
            }
            token if agent == "copilot" && token.starts_with("--resume=") => {
                if let Some(id) = token
                    .strip_prefix("--resume=")
                    .and_then(canonical_provider_uuid)
                {
                    push_prefixed_value_once(&mut out, "--resume=", id);
                }
                idx += 1;
            }
            token if agent == "copilot" && token.starts_with("--session-id=") => {
                // Hydra assigns this UUID before the first Copilot launch. A restart must resume that exact
                // provider session, not replay the create-or-resume flag or fall back to a different latest one.
                if let Some(id) = token
                    .strip_prefix("--session-id=")
                    .and_then(canonical_provider_uuid)
                {
                    push_prefixed_value_once(&mut out, "--resume=", id);
                }
                idx += 1;
            }
            "--conversation" if agent == "agy" => {
                if let Some(id) = params.get(idx + 1).and_then(|s| bounded_resume_id(s)) {
                    push_pair_flag_once(&mut out, "--conversation", id);
                }
                idx += 2;
            }
            "--session" if agent == "kimi" => {
                if let Some(id) = params.get(idx + 1).and_then(|s| bounded_resume_id(s)) {
                    push_pair_flag_once(&mut out, "--session", id);
                }
                idx += 2;
            }
            "chat" if agent == "kiro-cli" => {
                // Already inserted once at the canonical first position above.
                idx += 1;
            }
            "--resume-id" if agent == "kiro-cli" => {
                if let Some(id) = params
                    .get(idx + 1)
                    .and_then(|value| canonical_provider_uuid(value))
                {
                    push_pair_flag_once(&mut out, "--resume-id", id);
                }
                idx += 2;
            }
            "--resume" if agent == "kiro-cli" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "--resume" if agent == "agent" => {
                if let Some(id) = params
                    .get(idx + 1)
                    .and_then(|value| canonical_provider_uuid(value))
                {
                    push_pair_flag_once(&mut out, "--resume", id);
                }
                idx += 2;
            }
            "--continue" if agent == "agent" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "last" if agent == "amp" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "threads"
                if agent == "amp"
                    && params.get(idx + 1).map(String::as_str) == Some("continue") =>
            {
                if let Some(id) = params
                    .get(idx + 2)
                    .and_then(|value| bounded_amp_thread_target(value))
                {
                    if !out
                        .iter()
                        .any(|value| value == "last" || value == "threads")
                    {
                        out.extend([
                            "threads".to_string(),
                            "continue".to_string(),
                            id.to_string(),
                        ]);
                    }
                }
                idx += 3;
            }
            "--model" if agent != "amp" => {
                let model = params.get(idx + 1).and_then(|s| {
                    if matches!(agent, "copilot" | "agy" | "kimi" | "kiro-cli" | "agent") {
                        bounded_model_name(s)
                    } else {
                        non_empty(s)
                    }
                });
                if let Some(model) = model {
                    if matches!(agent, "copilot" | "agy" | "kimi" | "kiro-cli" | "agent") {
                        push_pair_flag_once(&mut out, "--model", model);
                    } else {
                        push_pair_once(&mut out, "--model", model);
                    }
                }
                idx += 2;
            }
            "--dangerously-skip-permissions" if agent == "claude" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "--dangerously-bypass-approvals-and-sandbox" if agent == "codex" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "--yolo" if agent == "gemini" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "--auto" if agent == "opencode" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "--yolo" if agent == "copilot" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "--dangerously-skip-permissions" if agent == "agy" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "--yolo" if agent == "kimi" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "--trust-all-tools" if agent == "kiro-cli" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "--yolo" if agent == "agent" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            "--dangerously-allow-all" if agent == "amp" => {
                push_flag_once(&mut out, token);
                idx += 1;
            }
            _ => idx += 1,
        }
    }
    if !has_resume_target(agent, &out) {
        if agent == "kiro-cli" {
            // `chat` is already canonical argv[0]; workspace-latest resume must immediately follow it.
            out.insert(1, "--resume".to_string());
            return out;
        }
        let fallback = match agent {
            "claude" => &["--continue"][..],
            "codex" => &["resume", "--last"][..],
            "gemini" => &["--resume", "latest"][..],
            "opencode" => &["--continue"][..],
            "copilot" => &["--continue"][..],
            "agy" => &["--continue"][..],
            "kimi" => &["--continue"][..],
            "agent" => &["--continue"][..],
            "amp" => &["last"][..],
            _ => &[][..],
        };
        let mut with_fallback = fallback
            .iter()
            .map(|token| (*token).to_string())
            .collect::<Vec<_>>();
        with_fallback.extend(out);
        out = with_fallback;
    }
    out
}

fn canonical_devin_params(params: &[String]) -> Vec<String> {
    let mut exact = None;
    let mut model = None;
    let mut dangerous = false;
    let mut idx = 0;
    while idx < params.len() {
        match params[idx].as_str() {
            "--resume" => {
                if exact.is_none() {
                    exact = params
                        .get(idx + 1)
                        .and_then(|value| bounded_opaque_resume_id(value))
                        .map(str::to_string);
                }
                idx += if params
                    .get(idx + 1)
                    .is_some_and(|value| !value.starts_with('-'))
                {
                    2
                } else {
                    1
                };
            }
            "--model" => {
                if model.is_none() {
                    model = params
                        .get(idx + 1)
                        .and_then(|value| bounded_model_name(value))
                        .map(str::to_string);
                }
                idx += if params
                    .get(idx + 1)
                    .is_some_and(|value| !value.starts_with('-'))
                {
                    2
                } else {
                    1
                };
            }
            "--permission-mode=dangerous" => {
                dangerous = true;
                idx += 1;
            }
            _ => idx += 1,
        }
    }

    let mut out = exact.map_or_else(
        || vec!["--continue".to_string()],
        |id| vec!["--resume".to_string(), id],
    );
    if let Some(model) = model {
        out.extend(["--model".to_string(), model]);
    }
    if dangerous {
        out.push("--permission-mode=dangerous".to_string());
    }
    out
}

fn canonical_droid_params(params: &[String]) -> Vec<String> {
    let mut exact = None;
    let mut dangerous = false;
    let mut idx = 0;
    while idx < params.len() {
        match params[idx].as_str() {
            "--resume" => {
                if exact.is_none() {
                    exact = params
                        .get(idx + 1)
                        .and_then(|value| bounded_opaque_resume_id(value))
                        .map(str::to_string);
                }
                idx += if params
                    .get(idx + 1)
                    .is_some_and(|value| !value.starts_with('-'))
                {
                    2
                } else {
                    1
                };
            }
            "--auto=high" => {
                dangerous = true;
                idx += 1;
            }
            _ => idx += 1,
        }
    }

    let mut out = exact.map_or_else(
        || vec!["--resume".to_string()],
        |id| vec!["--resume".to_string(), id],
    );
    if dangerous {
        out.push("--auto=high".to_string());
    }
    out
}

fn has_resume_target(agent: &str, params: &[String]) -> bool {
    match agent {
        "claude" => params.iter().any(|s| s == "--resume" || s == "--continue"),
        "codex" => params
            .windows(2)
            .any(|w| w[0] == "resume" && !w[1].is_empty()),
        "gemini" => params
            .iter()
            .any(|s| s == "--session-file" || s == "--resume"),
        "opencode" => params.iter().any(|s| s == "--session" || s == "--continue"),
        "copilot" => params
            .iter()
            .any(|s| s == "--continue" || valid_copilot_resume(s)),
        "agy" => params
            .iter()
            .any(|s| s == "--conversation" || s == "--continue"),
        "kimi" => params.iter().any(|s| s == "--session" || s == "--continue"),
        "kiro-cli" => params.iter().any(|s| s == "--resume-id" || s == "--resume"),
        "agent" => params.iter().any(|s| s == "--resume" || s == "--continue"),
        "amp" => {
            params.iter().any(|s| s == "last")
                || params
                    .windows(3)
                    .any(|w| w[0] == "threads" && w[1] == "continue" && !w[2].is_empty())
        }
        _ => false,
    }
}

fn valid_copilot_resume(value: &str) -> bool {
    value
        .strip_prefix("--resume=")
        .and_then(canonical_provider_uuid)
        .is_some()
}

fn canonical_provider_uuid(value: &str) -> Option<&str> {
    let value = non_flag(value)?;
    let parsed = uuid::Uuid::parse_str(value).ok()?;
    (parsed.hyphenated().to_string() == value).then_some(value)
}

fn bounded_resume_id(value: &str) -> Option<&str> {
    let value = non_flag(value)?;
    (value.len() <= 256 && !value.chars().any(char::is_control)).then_some(value)
}

fn bounded_amp_thread_target(value: &str) -> Option<&str> {
    let value = non_flag(value)?;
    (value.chars().count() <= 256 && !value.chars().any(char::is_control)).then_some(value)
}

fn bounded_opaque_resume_id(value: &str) -> Option<&str> {
    let value = non_flag(value)?;
    (value.chars().count() <= 256 && !value.chars().any(char::is_control)).then_some(value)
}

fn bounded_model_name(value: &str) -> Option<&str> {
    let value = non_empty(value)?;
    (value.chars().count() <= 96 && !value.chars().any(char::is_control)).then_some(value)
}

fn non_empty(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()).then_some(value)
}

fn non_flag(value: &str) -> Option<&str> {
    let value = non_empty(value)?;
    (!value.starts_with('-')).then_some(value)
}

fn push_flag_once(out: &mut Vec<String>, flag: &str) {
    if !out.iter().any(|existing| existing == flag) {
        out.push(flag.to_string());
    }
}

fn push_pair_once(out: &mut Vec<String>, flag: &str, value: &str) {
    if out
        .windows(2)
        .any(|pair| pair[0] == flag && pair[1] == value)
    {
        return;
    }
    out.push(flag.to_string());
    out.push(value.to_string());
}

fn push_pair_flag_once(out: &mut Vec<String>, flag: &str, value: &str) {
    if out.iter().any(|existing| existing == flag) {
        return;
    }
    out.push(flag.to_string());
    out.push(value.to_string());
}

fn push_prefixed_value_once(out: &mut Vec<String>, prefix: &str, value: &str) {
    if out.iter().any(|existing| existing.starts_with(prefix)) {
        return;
    }
    out.push(format!("{prefix}{value}"));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{SessionKind, SessionStatus, Workspace, WorkspaceConsent};
    use crate::WorkspacePolicy;
    use tempfile::TempDir;

    #[test]
    fn exact_provider_resume_boundary_accepts_only_one_named_conversation() {
        let exact = [
            (
                "claude",
                vec!["--resume", "50000000-0000-4000-8000-000000000001"],
            ),
            (
                "codex",
                vec!["resume", "60000000-0000-4000-8000-000000000001"],
            ),
            (
                "gemini",
                vec!["--resume", "30000000-0000-4000-8000-000000000001"],
            ),
            ("opencode", vec!["--session", "ses_123"]),
            (
                "copilot",
                vec!["--resume=123e4567-e89b-42d3-a456-426614174000"],
            ),
            (
                "agy",
                vec!["--conversation", "70000000-0000-4000-8000-000000000001"],
            ),
            (
                "kimi",
                vec!["--session", "session_80000000-0000-4000-8000-000000000001"],
            ),
            (
                "kiro-cli",
                vec![
                    "chat",
                    "--resume-id",
                    "20000000-0000-4000-8000-000000000001",
                ],
            ),
            (
                "agent",
                vec!["--resume", "123e4567-e89b-42d3-a456-426614174000"],
            ),
            ("amp", vec!["threads", "continue", "T-123"]),
            ("devin", vec!["--resume", "devin-session"]),
            ("droid", vec!["--resume", "droid-session"]),
        ];
        for (launch_spec_id, params) in exact {
            assert!(
                known_safe_provider_has_exact_resume(&LaunchSpec::KnownSafe {
                    launch_spec_id: launch_spec_id.into(),
                    params: params.into_iter().map(str::to_string).collect(),
                }),
                "{launch_spec_id} exact identity should be recoverable"
            );
        }
    }

    #[test]
    fn exact_provider_resume_boundary_rejects_latest_malformed_and_untrusted_recipes() {
        for launch in [
            LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: vec!["--continue".into()],
            },
            LaunchSpec::KnownSafe {
                launch_spec_id: "codex".into(),
                params: vec!["resume".into(), "--last".into()],
            },
            LaunchSpec::KnownSafe {
                launch_spec_id: "gemini".into(),
                params: vec!["--resume".into(), "latest".into()],
            },
            LaunchSpec::KnownSafe {
                launch_spec_id: "gemini".into(),
                params: vec!["--resume".into(), "5".into()],
            },
            LaunchSpec::KnownSafe {
                launch_spec_id: "gemini".into(),
                params: vec!["--session-file".into(), "/tmp/session.json".into()],
            },
            LaunchSpec::KnownSafe {
                launch_spec_id: "kiro-cli".into(),
                params: vec!["chat".into(), "--resume".into()],
            },
            LaunchSpec::KnownSafe {
                launch_spec_id: "amp".into(),
                params: vec!["last".into()],
            },
            LaunchSpec::AdHocRedacted {
                argv: vec![
                    "claude".into(),
                    "--resume".into(),
                    "provider-session".into(),
                ],
                redacted: false,
                restart_requires_user: true,
            },
            LaunchSpec::OptOut,
        ] {
            assert!(!known_safe_provider_has_exact_resume(&launch));
        }
    }

    #[test]
    fn opencode_ad_hoc_with_unreviewed_mini_remains_user_gated() {
        let launch = LaunchSpec::AdHocRedacted {
            argv: vec![
                "opencode".into(),
                "--mini".into(),
                "--session".into(),
                "ses_123".into(),
                "--auto".into(),
            ],
            redacted: false,
            restart_requires_user: true,
        };
        assert_eq!(canonical_launch_for_restart(&launch), launch);
    }

    #[test]
    fn claude_resume_preserves_safe_dangerous_flag() {
        let launch = LaunchSpec::AdHocRedacted {
            argv: vec![
                "/Users/test/.local/bin/claude".into(),
                "--resume".into(),
                "abc".into(),
                "--dangerously-skip-permissions".into(),
            ],
            redacted: false,
            restart_requires_user: true,
        };
        assert_eq!(
            canonical_launch_for_restart(&launch),
            LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: vec![
                    "--resume".into(),
                    "abc".into(),
                    "--dangerously-skip-permissions".into(),
                ],
            }
        );
    }

    #[test]
    fn fresh_agent_without_resume_gets_provider_continue_fallback() {
        let launch = LaunchSpec::AdHocRedacted {
            argv: vec!["claude".into()],
            redacted: false,
            restart_requires_user: true,
        };
        assert_eq!(
            canonical_launch_for_restart(&launch),
            LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: vec!["--continue".into()],
            }
        );
    }

    #[test]
    fn claude_assigned_identity_canonicalizes_to_exact_resume_with_safe_flags() {
        const UUID: &str = "01234567-89ab-4def-8123-456789abcdef";
        let canonical = canonical_launch_for_restart(&LaunchSpec::KnownSafe {
            launch_spec_id: "claude".into(),
            params: vec![
                "--model".into(),
                "opus".into(),
                "--session-id".into(),
                UUID.into(),
                "--dangerously-skip-permissions".into(),
            ],
        });
        assert_eq!(
            canonical,
            LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: vec![
                    "--model".into(),
                    "opus".into(),
                    "--resume".into(),
                    UUID.into(),
                    "--dangerously-skip-permissions".into(),
                ],
            }
        );
        assert!(known_safe_provider_has_exact_resume(&canonical));
    }

    #[test]
    fn codex_without_specific_id_restarts_latest_with_safe_flags() {
        let launch = LaunchSpec::KnownSafe {
            launch_spec_id: "codex".into(),
            params: vec!["--dangerously-bypass-approvals-and-sandbox".into()],
        };
        assert_eq!(
            canonical_launch_for_restart(&launch),
            LaunchSpec::KnownSafe {
                launch_spec_id: "codex".into(),
                params: vec![
                    "resume".into(),
                    "--last".into(),
                    "--dangerously-bypass-approvals-and-sandbox".into(),
                ],
            }
        );
    }

    #[test]
    fn copilot_duplicate_model_remains_user_gated() {
        let launch = LaunchSpec::AdHocRedacted {
            argv: vec![
                "/usr/local/bin/copilot".into(),
                "--resume=123e4567-e89b-12d3-a456-426614174000".into(),
                "--model".into(),
                "gpt-5:preview".into(),
                "--model".into(),
                "ignored-second-model".into(),
                "--yolo".into(),
            ],
            redacted: false,
            restart_requires_user: true,
        };
        assert_eq!(canonical_launch_for_restart(&launch), launch);
    }

    #[test]
    fn antigravity_preserves_conversation_and_uses_agy_launch_id() {
        let launch = LaunchSpec::AdHocRedacted {
            argv: vec![
                "/opt/antigravity/bin/agy".into(),
                "--conversation".into(),
                "conversation-123".into(),
                "--model".into(),
                "gemini-3.0-pro".into(),
                "--dangerously-skip-permissions".into(),
            ],
            redacted: false,
            restart_requires_user: true,
        };
        assert_eq!(
            canonical_launch_for_restart(&launch),
            LaunchSpec::KnownSafe {
                launch_spec_id: "agy".into(),
                params: vec![
                    "--conversation".into(),
                    "conversation-123".into(),
                    "--model".into(),
                    "gemini-3.0-pro".into(),
                    "--dangerously-skip-permissions".into(),
                ],
            }
        );
    }

    #[test]
    fn kimi_preserves_selected_session_model_and_yolo() {
        let launch = LaunchSpec::AdHocRedacted {
            argv: vec![
                "/Users/test/.kimi-code/bin/kimi".into(),
                "--session".into(),
                "session_abc123".into(),
                "--model".into(),
                "kimi-code/k3".into(),
                "--yolo".into(),
            ],
            redacted: false,
            restart_requires_user: true,
        };
        assert_eq!(
            canonical_launch_for_restart(&launch),
            LaunchSpec::KnownSafe {
                launch_spec_id: "kimi".into(),
                params: vec![
                    "--session".into(),
                    "session_abc123".into(),
                    "--model".into(),
                    "kimi-code/k3".into(),
                    "--yolo".into(),
                ],
            }
        );
    }

    #[test]
    fn kiro_preserves_chat_selected_uuid_model_and_trust_flag() {
        let launch = LaunchSpec::AdHocRedacted {
            argv: vec![
                "/usr/local/bin/kiro-cli".into(),
                "chat".into(),
                "--resume-id".into(),
                "20000000-0000-4000-8000-000000000001".into(),
                "--model".into(),
                "claude-sonnet-4.5".into(),
                "--trust-all-tools".into(),
            ],
            redacted: false,
            restart_requires_user: true,
        };
        assert_eq!(
            canonical_launch_for_restart(&launch),
            LaunchSpec::KnownSafe {
                launch_spec_id: "kiro-cli".into(),
                params: vec![
                    "chat".into(),
                    "--resume-id".into(),
                    "20000000-0000-4000-8000-000000000001".into(),
                    "--model".into(),
                    "claude-sonnet-4.5".into(),
                    "--trust-all-tools".into(),
                ],
            }
        );
    }

    #[test]
    fn fresh_kiro_restart_uses_workspace_resume_and_never_drops_chat() {
        for params in [
            vec!["chat".into()],
            vec![
                "chat".into(),
                "--model".into(),
                "deepseek-3.2".into(),
                "--trust-all-tools".into(),
            ],
        ] {
            let launch = LaunchSpec::KnownSafe {
                launch_spec_id: "kiro-cli".into(),
                params,
            };
            let LaunchSpec::KnownSafe {
                launch_spec_id,
                params,
            } = canonical_launch_for_restart(&launch)
            else {
                panic!("Kiro restart must remain KnownSafe");
            };
            assert_eq!(launch_spec_id, "kiro-cli");
            assert_eq!(&params[..2], &["chat", "--resume"]);
            assert_eq!(params.iter().filter(|arg| *arg == "chat").count(), 1);
        }
    }

    #[test]
    fn kiro_rejects_noncanonical_resume_ids_but_keeps_workspace_fallback() {
        for bad in [
            "not-a-uuid",
            "ABCDEFAB-0000-4000-8000-000000000001",
            "20000000000040008000000000000001",
        ] {
            let launch = LaunchSpec::KnownSafe {
                launch_spec_id: "kiro-cli".into(),
                params: vec!["chat".into(), "--resume-id".into(), bad.into()],
            };
            assert_eq!(
                canonical_launch_for_restart(&launch),
                LaunchSpec::KnownSafe {
                    launch_spec_id: "kiro-cli".into(),
                    params: vec!["chat".into(), "--resume".into()],
                }
            );
        }
    }

    #[test]
    fn cursor_preserves_exact_uuid_model_and_yolo() {
        let launch = LaunchSpec::KnownSafe {
            launch_spec_id: "agent".into(),
            params: vec![
                "--resume".into(),
                "123e4567-e89b-42d3-a456-426614174000".into(),
                "--model".into(),
                "auto".into(),
                "--yolo".into(),
            ],
        };
        assert_eq!(
            canonical_launch_for_restart(&launch),
            LaunchSpec::KnownSafe {
                launch_spec_id: "agent".into(),
                params: vec![
                    "--resume".into(),
                    "123e4567-e89b-42d3-a456-426614174000".into(),
                    "--model".into(),
                    "auto".into(),
                    "--yolo".into(),
                ],
            }
        );
    }

    #[test]
    fn amp_known_safe_restart_uses_last_or_preserves_one_exact_target() {
        assert_eq!(
            canonical_launch_for_restart(&LaunchSpec::KnownSafe {
                launch_spec_id: "amp".into(),
                params: Vec::new(),
            }),
            LaunchSpec::KnownSafe {
                launch_spec_id: "amp".into(),
                params: vec!["last".into()],
            }
        );

        assert_eq!(
            canonical_launch_for_restart(&LaunchSpec::KnownSafe {
                launch_spec_id: "amp".into(),
                params: vec![
                    "threads".into(),
                    "continue".into(),
                    "thread-id".into(),
                    "--model".into(),
                    "must-not-leak".into(),
                    "--dangerously-allow-all".into(),
                ],
            }),
            LaunchSpec::KnownSafe {
                launch_spec_id: "amp".into(),
                params: vec![
                    "threads".into(),
                    "continue".into(),
                    "thread-id".into(),
                    "--dangerously-allow-all".into(),
                ],
            }
        );
    }

    #[test]
    fn amp_rejects_unsafe_exact_targets_and_is_never_inferred_from_adhoc_argv() {
        for target in [
            "--help".to_string(),
            "thread\nother".to_string(),
            "x".repeat(257),
        ] {
            assert_eq!(
                canonical_launch_for_restart(&LaunchSpec::KnownSafe {
                    launch_spec_id: "amp".into(),
                    params: vec!["threads".into(), "continue".into(), target],
                }),
                LaunchSpec::KnownSafe {
                    launch_spec_id: "amp".into(),
                    params: vec!["last".into()],
                }
            );
        }

        for argv in [
            vec!["amp".into(), "last".into()],
            vec!["wrapper".into(), "amp".into(), "last".into()],
        ] {
            let launch = LaunchSpec::AdHocRedacted {
                argv,
                redacted: false,
                restart_requires_user: true,
            };
            assert_eq!(canonical_launch_for_restart(&launch), launch);
        }
    }

    #[test]
    fn devin_and_factory_restart_contracts_are_known_safe_only() {
        for (agent, latest, model_and_danger, exact) in [
            (
                "devin",
                vec!["--continue"],
                vec!["--model", "opus", "--permission-mode=dangerous"],
                vec!["--resume", "session-one"],
            ),
            (
                "droid",
                vec!["--resume"],
                vec!["--model", "must-not-leak", "--auto=high"],
                vec!["--resume", "session-two"],
            ),
        ] {
            let canonical = |params: Vec<&str>| {
                canonical_launch_for_restart(&LaunchSpec::KnownSafe {
                    launch_spec_id: agent.into(),
                    params: params.into_iter().map(str::to_string).collect(),
                })
            };
            assert_eq!(
                canonical(Vec::new()),
                LaunchSpec::KnownSafe {
                    launch_spec_id: agent.into(),
                    params: latest.iter().map(|value| (*value).into()).collect(),
                }
            );
            let expected_params = if agent == "devin" {
                vec![
                    "--continue".into(),
                    "--model".into(),
                    "opus".into(),
                    "--permission-mode=dangerous".into(),
                ]
            } else {
                vec!["--resume".into(), "--auto=high".into()]
            };
            assert_eq!(
                canonical(model_and_danger),
                LaunchSpec::KnownSafe {
                    launch_spec_id: agent.into(),
                    params: expected_params,
                }
            );
            assert_eq!(
                canonical(exact.clone()),
                LaunchSpec::KnownSafe {
                    launch_spec_id: agent.into(),
                    params: exact.into_iter().map(str::to_string).collect(),
                }
            );

            for argv in [
                vec![agent.into(), "--resume".into(), "session".into()],
                vec![format!("/tmp/{agent}"), "--resume".into(), "session".into()],
                vec!["wrapper".into(), agent.into(), "--resume".into()],
            ] {
                let launch = LaunchSpec::AdHocRedacted {
                    argv,
                    redacted: false,
                    restart_requires_user: true,
                };
                assert_eq!(canonical_launch_for_restart(&launch), launch);
            }
        }

        for agent in ["devin", "droid"] {
            for invalid in ["--latest", "bad\nid", &"x".repeat(257)] {
                let fallback = if agent == "devin" {
                    vec!["--continue".into()]
                } else {
                    vec!["--resume".into()]
                };
                assert_eq!(
                    canonical_launch_for_restart(&LaunchSpec::KnownSafe {
                        launch_spec_id: agent.into(),
                        params: vec!["--resume".into(), invalid.into()],
                    }),
                    LaunchSpec::KnownSafe {
                        launch_spec_id: agent.into(),
                        params: fallback,
                    }
                );
            }
        }
    }

    #[test]
    fn devin_and_factory_exact_resume_wins_and_duplicate_options_collapse() {
        assert_eq!(
            canonical_launch_for_restart(&LaunchSpec::KnownSafe {
                launch_spec_id: "devin".into(),
                params: vec![
                    "--continue".into(),
                    "--permission-mode=dangerous".into(),
                    "--resume".into(),
                    "exact-one".into(),
                    "--model".into(),
                    "opus".into(),
                    "--model".into(),
                    "ignored".into(),
                    "--permission-mode=dangerous".into(),
                    "--resume".into(),
                    "exact-two".into(),
                ],
            }),
            LaunchSpec::KnownSafe {
                launch_spec_id: "devin".into(),
                params: vec![
                    "--resume".into(),
                    "exact-one".into(),
                    "--model".into(),
                    "opus".into(),
                    "--permission-mode=dangerous".into(),
                ],
            }
        );
        assert_eq!(
            canonical_launch_for_restart(&LaunchSpec::KnownSafe {
                launch_spec_id: "droid".into(),
                params: vec![
                    "--resume".into(),
                    "--auto=high".into(),
                    "--resume".into(),
                    "exact-one".into(),
                    "--auto=high".into(),
                    "--resume".into(),
                    "exact-two".into(),
                ],
            }),
            LaunchSpec::KnownSafe {
                launch_spec_id: "droid".into(),
                params: vec!["--resume".into(), "exact-one".into(), "--auto=high".into(),],
            }
        );
    }

    #[test]
    fn generic_agent_executable_is_never_inferred_from_unproven_ad_hoc_argv() {
        for argv in [
            vec!["task-runner".into(), "agent".into(), "--resume".into()],
            vec!["agent".into(), "--serve".into()],
            vec![
                "/opt/unrelated/agent".into(),
                "--model".into(),
                "other".into(),
            ],
            vec!["./claude".into(), "--continue".into()],
            vec!["tools/claude".into(), "--continue".into()],
        ] {
            let launch = LaunchSpec::AdHocRedacted {
                argv,
                redacted: false,
                restart_requires_user: true,
            };
            assert_eq!(canonical_launch_for_restart(&launch), launch);
        }
    }

    #[test]
    fn new_providers_without_explicit_targets_use_continue_fallbacks() {
        for (agent, dangerous) in [
            ("copilot", "--yolo"),
            ("agy", "--dangerously-skip-permissions"),
            ("kimi", "--yolo"),
            ("agent", "--yolo"),
        ] {
            let launch = LaunchSpec::KnownSafe {
                launch_spec_id: agent.into(),
                params: vec![dangerous.into()],
            };
            assert_eq!(
                canonical_launch_for_restart(&launch),
                LaunchSpec::KnownSafe {
                    launch_spec_id: agent.into(),
                    params: vec!["--continue".into(), dangerous.into()],
                }
            );
        }
    }

    #[test]
    fn hydra_owned_fresh_copilot_id_becomes_the_exact_resume_target() {
        let id = "20000000-0000-4000-8000-000000000001";
        let launch = LaunchSpec::KnownSafe {
            launch_spec_id: "copilot".into(),
            params: vec![
                format!("--session-id={id}"),
                "--model".into(),
                "auto".into(),
            ],
        };
        assert_eq!(
            canonical_launch_for_restart(&launch),
            LaunchSpec::KnownSafe {
                launch_spec_id: "copilot".into(),
                params: vec![format!("--resume={id}"), "--model".into(), "auto".into()],
            }
        );
    }

    #[test]
    fn copilot_resume_requires_a_canonical_uuid() {
        for bad in [
            "not-a-uuid",
            "ABCDEFAB-0000-4000-8000-000000000001",
            "20000000000040008000000000000001",
        ] {
            let launch = LaunchSpec::KnownSafe {
                launch_spec_id: "copilot".into(),
                params: vec![format!("--resume={bad}")],
            };
            assert_eq!(
                canonical_launch_for_restart(&launch),
                LaunchSpec::KnownSafe {
                    launch_spec_id: "copilot".into(),
                    params: vec!["--continue".into()],
                }
            );
        }
    }

    #[test]
    fn new_provider_restart_models_are_bounded_but_legacy_gemini_is_unchanged() {
        let too_long = "x".repeat(97);
        let copilot = LaunchSpec::KnownSafe {
            launch_spec_id: "copilot".into(),
            params: vec!["--model".into(), too_long.clone()],
        };
        assert_eq!(
            canonical_launch_for_restart(&copilot),
            LaunchSpec::KnownSafe {
                launch_spec_id: "copilot".into(),
                params: vec!["--continue".into()],
            }
        );

        let gemini = LaunchSpec::KnownSafe {
            launch_spec_id: "gemini".into(),
            params: vec!["--model".into(), too_long.clone(), "--yolo".into()],
        };
        assert_eq!(
            canonical_launch_for_restart(&gemini),
            LaunchSpec::KnownSafe {
                launch_spec_id: "gemini".into(),
                params: vec![
                    "--resume".into(),
                    "latest".into(),
                    "--model".into(),
                    too_long,
                    "--yolo".into(),
                ],
            }
        );
    }

    #[test]
    fn canonicalize_session_rewrites_db_row() {
        let dir = TempDir::new().unwrap();
        let paths = crate::AppPaths::with_base(dir.path());
        crate::store::write_record(
            &paths,
            RecordKind::Project,
            "p",
            1,
            &crate::Project {
                project_id: "p".into(),
                name: "P".into(),
                root: "/tmp".into(),
                default_workspace_policy: WorkspacePolicy::ScratchCwd,
                created_at_ms: 1,
                last_active_at_ms: 1,
                icon: None,
                accent_color: None,
                launch_defaults: None,
                directories: Vec::new(),
                window_order: Vec::new(),
                system: false,
                hidden: false,
            },
        )
        .unwrap();
        crate::store::write_record(
            &paths,
            RecordKind::Workspace,
            "w",
            1,
            &Workspace {
                workspace_id: "w".into(),
                project_id: "p".into(),
                root: "/tmp".into(),
                policy: WorkspacePolicy::ScratchCwd,
                consent: WorkspaceConsent::default(),
            },
        )
        .unwrap();
        let record = SessionRecord {
            session_id: "s".into(),
            workspace_id: "w".into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::AdHocRedacted {
                argv: vec!["opencode".into(), "--session".into(), "ses".into()],
                redacted: false,
                restart_requires_user: true,
            },
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: None,
            status: SessionStatus::Exited,
        };
        crate::store::write_record(&paths, RecordKind::Session, "s", 1, &record).unwrap();

        canonicalize_session_restart_recipe(&paths, "s", 2)
            .unwrap()
            .unwrap();
        let loaded = crate::store::load_one::<SessionRecord>(&paths, RecordKind::Session, "s")
            .unwrap()
            .unwrap();
        let LoadOutcome::Loaded(loaded) = loaded else {
            panic!("expected loaded")
        };
        assert_eq!(
            loaded.launch,
            LaunchSpec::KnownSafe {
                launch_spec_id: "opencode".into(),
                params: vec!["--session".into(), "ses".into()],
            }
        );
    }

    fn provider_argv(provider: &str, params: &[&str]) -> Vec<String> {
        std::iter::once(provider)
            .chain(params.iter().copied())
            .map(str::to_string)
            .collect()
    }

    #[test]
    fn prepared_provider_grammar_classifies_fresh_latest_and_exact_for_closed_set() {
        const UUID: &str = "01234567-89ab-4def-8123-456789abcdef";
        type ProviderGrammarCase = (
            &'static str,
            &'static [&'static str],
            &'static [&'static str],
            &'static [&'static str],
        );
        let rows: &[ProviderGrammarCase] = &[
            ("claude", &[], &["--continue"], &["--resume", UUID]),
            ("codex", &[], &["resume", "--last"], &["resume", UUID]),
            ("gemini", &[], &["--resume", "latest"], &["--resume", UUID]),
            ("opencode", &[], &["--continue"], &["--session", "thread"]),
            (
                "copilot",
                &["--session-id=01234567-89ab-4def-8123-456789abcdef"],
                &["--continue"],
                &["--resume=01234567-89ab-4def-8123-456789abcdef"],
            ),
            ("agy", &[], &["--continue"], &["--conversation", UUID]),
            (
                "kimi",
                &[],
                &["--continue"],
                &["--session", "session_01234567-89ab-4def-8123-456789abcdef"],
            ),
            (
                "kiro-cli",
                &["chat"],
                &["chat", "--resume"],
                &["chat", "--resume-id", UUID],
            ),
            ("agent", &[], &["--continue"], &["--resume", UUID]),
            ("amp", &[], &["last"], &["threads", "continue", "thread"]),
            ("devin", &[], &["--continue"], &["--resume", "thread"]),
            ("droid", &[], &["--resume"], &["--resume", "thread"]),
        ];
        for (provider, fresh, latest, exact) in rows {
            let (fresh_mode, fresh_publication) =
                strict_prepared_provider_launch(provider, &provider_argv(provider, fresh))
                    .unwrap_or_else(|| panic!("fresh provider grammar rejected {provider}"));
            let expected_fresh = if *provider == "copilot" {
                PreparedProviderLaunchMode::FreshWithAssignedIdentity
            } else {
                PreparedProviderLaunchMode::FreshUnassigned
            };
            assert_eq!(fresh_mode, expected_fresh, "fresh provider={provider}");
            assert_eq!(
                strict_prepared_provider_launch(provider, &provider_argv(provider, latest))
                    .map(|(mode, _)| mode),
                Some(PreparedProviderLaunchMode::ExplicitNonExact),
                "latest provider={provider}"
            );
            assert_eq!(
                strict_prepared_provider_launch(provider, &provider_argv(provider, exact))
                    .map(|(mode, _)| mode),
                Some(PreparedProviderLaunchMode::ExactResume),
                "exact provider={provider}"
            );

            let mut conflicting = latest.to_vec();
            conflicting.extend_from_slice(exact);
            assert!(
                strict_prepared_provider_launch(provider, &provider_argv(provider, &conflicting))
                    .is_none(),
                "duplicate/conflicting selector accepted for provider={provider}"
            );

            match *provider {
                "copilot" => assert_eq!(
                    fresh_publication,
                    LaunchSpec::KnownSafe {
                        launch_spec_id: "copilot".into(),
                        params: vec![format!("--resume={UUID}")],
                    }
                ),
                "kiro-cli" => assert_eq!(
                    fresh_publication,
                    LaunchSpec::KnownSafe {
                        launch_spec_id: "kiro-cli".into(),
                        params: vec!["chat".into(), "--resume".into()],
                    }
                ),
                "droid" => assert_eq!(
                    fresh_publication,
                    LaunchSpec::KnownSafe {
                        launch_spec_id: "droid".into(),
                        params: vec!["--resume".into()],
                    }
                ),
                _ => {}
            }
        }
        let (claude_assigned_mode, claude_assigned_publication) = strict_prepared_provider_launch(
            "claude",
            &provider_argv(
                "claude",
                &[
                    "--session-id",
                    UUID,
                    "--model",
                    "opus",
                    "--dangerously-skip-permissions",
                ],
            ),
        )
        .expect("Hydra-assigned Claude identity must be sealed");
        assert_eq!(
            claude_assigned_mode,
            PreparedProviderLaunchMode::FreshWithAssignedIdentity
        );
        assert_eq!(
            claude_assigned_publication,
            LaunchSpec::KnownSafe {
                launch_spec_id: "claude".into(),
                params: vec![
                    "--resume".into(),
                    UUID.into(),
                    "--model".into(),
                    "opus".into(),
                    "--dangerously-skip-permissions".into(),
                ],
            }
        );
        let (gemini_assigned_mode, gemini_assigned_publication) = strict_prepared_provider_launch(
            "gemini",
            &provider_argv(
                "gemini",
                &["--session-id", UUID, "--model", "pro", "--yolo"],
            ),
        )
        .expect("Hydra-assigned Gemini identity must be sealed");
        assert_eq!(
            gemini_assigned_mode,
            PreparedProviderLaunchMode::FreshWithAssignedIdentity
        );
        assert_eq!(
            gemini_assigned_publication,
            LaunchSpec::KnownSafe {
                launch_spec_id: "gemini".into(),
                params: vec![
                    "--resume".into(),
                    UUID.into(),
                    "--model".into(),
                    "pro".into(),
                    "--yolo".into(),
                ],
            }
        );
        let (gemini_file_mode, gemini_file) = strict_prepared_provider_launch(
            "gemini",
            &provider_argv("gemini", &["--session-file", "/tmp/session.json"]),
        )
        .expect("Gemini session-file import must be sealed without exact authority");
        assert_eq!(
            gemini_file_mode,
            PreparedProviderLaunchMode::ExplicitNonExact
        );
        assert_eq!(
            gemini_file,
            LaunchSpec::KnownSafe {
                launch_spec_id: "gemini".into(),
                params: vec!["--session-file".into(), "/tmp/session.json".into()],
            }
        );
    }

    #[test]
    fn prepared_provider_grammar_rejects_malformed_duplicate_and_unknown_bytes() {
        const UUID: &str = "01234567-89ab-4def-8123-456789abcdef";
        let malformed: &[(&str, &[&str])] = &[
            ("claude", &["--resume=bad"]),
            ("claude", &["--session-id"]),
            ("claude", &["--session-id", "bad"]),
            (
                "claude",
                &["--session-id=01234567-89ab-4def-8123-456789abcdef"],
            ),
            (
                "claude",
                &["--session-id", "01234567-89AB-4DEF-8123-456789ABCDEF"],
            ),
            ("codex", &["resume"]),
            ("gemini", &["--session-file", "--yolo"]),
            ("gemini", &["--session-id"]),
            ("gemini", &["--session-id", "bad"]),
            ("gemini", &["--resume", "thread"]),
            (
                "gemini",
                &["--session-id=01234567-89ab-4def-8123-456789abcdef"],
            ),
            ("opencode", &["--mini"]),
            ("copilot", &["--session-id=bad"]),
            ("agy", &["--conversation", "--bad"]),
            ("kimi", &["--session", "--bad"]),
            ("kiro-cli", &["chat", "--resume-id", "bad"]),
            ("agent", &["--resume", "bad"]),
            ("amp", &["threads", "continue"]),
            ("devin", &["--resume", "--bad"]),
            ("droid", &["--model", "forbidden"]),
        ];
        for (provider, params) in malformed {
            assert!(
                strict_prepared_provider_launch(provider, &provider_argv(provider, params))
                    .is_none(),
                "malformed selector degraded to latest for provider={provider} params={params:?}"
            );
            let mut unknown = provider_argv(provider, &[]);
            if *provider == "kiro-cli" {
                unknown.push("chat".into());
            }
            unknown.extend(["--api-key".into(), UUID.into()]);
            assert!(
                strict_prepared_provider_launch(provider, &unknown).is_none(),
                "unknown secret-bearing bytes were accepted for provider={provider}"
            );
        }
        assert!(strict_prepared_provider_launch(
            "claude",
            &provider_argv("claude", &["--model", "opus", "--model", "sonnet"])
        )
        .is_none());
        assert!(strict_prepared_provider_launch(
            "claude",
            &provider_argv(
                "claude",
                &[
                    "--dangerously-skip-permissions",
                    "--dangerously-skip-permissions"
                ]
            )
        )
        .is_none());
        for conflicting in [
            vec!["--session-id", UUID, "--session-id", UUID],
            vec!["--session-id", UUID, "--continue"],
            vec!["--continue", "--session-id", UUID],
            vec!["--session-id", UUID, "--resume", "thread"],
            vec!["--resume", "thread", "--session-id", UUID],
        ] {
            assert!(
                strict_prepared_provider_launch("claude", &provider_argv("claude", &conflicting))
                    .is_none(),
                "conflicting Claude identity selectors were accepted: {conflicting:?}"
            );
        }
        assert_eq!(
            strict_prepared_provider_launch(
                "claude",
                &provider_argv("claude", &["--resume", "search term"])
            )
            .map(|(mode, _)| mode),
            Some(PreparedProviderLaunchMode::ExplicitNonExact)
        );
        assert_eq!(
            strict_prepared_provider_launch(
                "codex",
                &provider_argv("codex", &["resume", "named-session"])
            )
            .map(|(mode, _)| mode),
            Some(PreparedProviderLaunchMode::ExplicitNonExact)
        );
        assert_eq!(
            strict_prepared_provider_launch("gemini", &provider_argv("gemini", &["--resume", "5"]))
                .map(|(mode, _)| mode),
            Some(PreparedProviderLaunchMode::ExplicitNonExact)
        );
        for conflicting in [
            vec!["--session-id", UUID, "--session-id", UUID],
            vec!["--session-id", UUID, "--resume", "latest"],
            vec!["--resume", "thread", "--session-id", UUID],
            vec!["--session-file", "/tmp/session.json", "--session-id", UUID],
        ] {
            assert!(
                strict_prepared_provider_launch("gemini", &provider_argv("gemini", &conflicting))
                    .is_none(),
                "conflicting Gemini identity selectors were accepted: {conflicting:?}"
            );
        }
        for malformed_selector in [
            provider_argv("claude", &["--session-id"]),
            provider_argv("claude", &["--session-id=bad"]),
            provider_argv("gemini", &["--session-id"]),
            provider_argv("gemini", &["--session-id=bad"]),
        ] {
            let provider = malformed_selector[0].as_str();
            assert!(!is_valid_prepared_provider_custom_adhoc(
                provider,
                &malformed_selector
            ));
        }
    }
}
