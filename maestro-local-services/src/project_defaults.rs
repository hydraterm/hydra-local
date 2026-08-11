use std::borrow::Cow;

use maestro_shell::records::Project;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InheritedProjectLaunchInputs<'a> {
    pub agent: Option<Cow<'a, str>>,
    pub resolved_launch_command: Option<Cow<'a, str>>,
}

pub fn inherited_project_launch_inputs<'a>(
    project: Option<&'a Project>,
    explicit_agent: Option<&'a str>,
    explicit_resolved_launch_command: Option<&'a str>,
) -> InheritedProjectLaunchInputs<'a> {
    let agent = clean_value(explicit_agent).or_else(|| {
        project.and_then(|project| {
            project
                .launch_defaults
                .as_ref()
                .and_then(|defaults| clean_value(defaults.agent.as_deref()))
        })
    });
    let agent = agent.map(Cow::Borrowed);
    let explicit_resolved_launch_command = clean_value(explicit_resolved_launch_command);
    let terminal_without_explicit_command = explicit_resolved_launch_command.is_none()
        && agent
            .as_deref()
            .is_some_and(|agent| agent.eq_ignore_ascii_case("terminal"));
    let resolved_launch_command = if terminal_without_explicit_command {
        None
    } else {
        explicit_resolved_launch_command
            .map(Cow::Borrowed)
            .or_else(|| {
                project.and_then(|project| {
                    project
                        .launch_defaults
                        .as_ref()
                        .and_then(|defaults| clean_value(defaults.custom_command.as_deref()))
                        .map(Cow::Borrowed)
                })
            })
            .or_else(|| {
                project.and_then(|project| {
                    project
                        .launch_defaults
                        .as_ref()
                        .and_then(|defaults| {
                            synthesize_project_default_launch_command(defaults, &agent)
                        })
                        .map(Cow::Owned)
                })
            })
    };
    InheritedProjectLaunchInputs {
        agent,
        resolved_launch_command,
    }
}

fn clean_value(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn bounded_model_name(value: &str) -> Option<&str> {
    let value = clean_value(Some(value))?;
    (value.chars().count() <= 96 && !value.chars().any(char::is_control)).then_some(value)
}

fn quote_command_arg(value: &str) -> String {
    if value
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | ':' | '/' | '-'))
    {
        return value.to_string();
    }
    // This string is parsed by launch_preflight's argv-only parser and may later be displayed in the UI.
    // Quote every non-strict-safe value anyway so no future shell consumer can reinterpret punctuation. The
    // parser treats backslash as an escape even inside quotes, so double it; use the standard close/escape/reopen
    // sequence for a literal apostrophe.
    let mut quoted = String::from("'");
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '\'' => quoted.push_str("'\\''"),
            _ => quoted.push(ch),
        }
    }
    quoted.push('\'');
    quoted
}

fn synthesize_project_default_launch_command(
    defaults: &maestro_shell::records::ProjectLaunchDefaults,
    inherited_agent: &Option<Cow<'_, str>>,
) -> Option<String> {
    let agent = inherited_agent
        .as_deref()
        .and_then(|agent| clean_value(Some(agent)))
        .unwrap_or("claude");
    // "terminal" is plain bash, not an LLM — never synthesize a launch command for it (a terminal pane is Shell+OptOut).
    if agent.eq_ignore_ascii_case("terminal") {
        return None;
    }
    let resume_mode = clean_value(defaults.resume_mode.as_deref());
    let model = clean_value(defaults.model.as_deref()).filter(|model| *model != "default");
    // New provider integrations accept a single bounded model identifier as a discrete argv value.
    // Keep legacy providers byte-for-byte compatible here; their existing validation/migration
    // behavior must not change while old durable project defaults remain readable.
    let model = if agent.eq_ignore_ascii_case("amp") || agent.eq_ignore_ascii_case("factory") {
        // Amp and Factory do not expose Hydra's generic interactive `--model` contract. Do not pass the
        // persisted field through until either provider has a separately qualified typed contract.
        None
    } else if agent.eq_ignore_ascii_case("copilot")
        || agent.eq_ignore_ascii_case("antigravity")
        || agent.eq_ignore_ascii_case("agy")
        || agent.eq_ignore_ascii_case("kimi")
        || agent.eq_ignore_ascii_case("kiro")
        || agent.eq_ignore_ascii_case("cursor")
        || agent.eq_ignore_ascii_case("devin")
    {
        model.and_then(bounded_model_name)
    } else {
        model
    };
    let dangerous = defaults.dangerous_skip_permissions.unwrap_or(false);
    let has_synthesized_defaults =
        resume_mode.is_some() || model.is_some() || defaults.dangerous_skip_permissions.is_some();
    if !has_synthesized_defaults {
        return None;
    }
    // A fresh pane from project defaults starts a NEW session by default, not resume/continue — an
    // unspecified resume_mode must NOT silently become `claude --continue` / `codex resume --last` (which
    // reopens the folder's last session, or exits when there is none). Resume is an explicit choice.
    let resume_mode = resume_mode.unwrap_or("none");

    let mut parts = Vec::new();
    if agent.eq_ignore_ascii_case("codex") {
        if resume_mode == "none" || resume_mode == "new" {
            parts.push("codex".to_string());
        } else {
            parts.extend([
                "codex".to_string(),
                "resume".to_string(),
                "--last".to_string(),
            ]);
        }
    } else if agent.eq_ignore_ascii_case("gemini") {
        parts.push("gemini".to_string());
        if resume_mode != "none" && resume_mode != "new" {
            parts.extend(["--resume".to_string(), "latest".to_string()]);
        }
    } else if agent.eq_ignore_ascii_case("opencode") {
        parts.push("opencode".to_string());
        if resume_mode != "none" && resume_mode != "new" {
            parts.push("--continue".to_string());
        }
    } else if agent.eq_ignore_ascii_case("copilot") {
        parts.push("copilot".to_string());
        if resume_mode != "none" && resume_mode != "new" {
            parts.push("--continue".to_string());
        }
    } else if agent.eq_ignore_ascii_case("antigravity") || agent.eq_ignore_ascii_case("agy") {
        parts.push("agy".to_string());
        if resume_mode != "none" && resume_mode != "new" {
            parts.push("--continue".to_string());
        }
    } else if agent.eq_ignore_ascii_case("kimi") {
        parts.push("kimi".to_string());
        if resume_mode != "none" && resume_mode != "new" {
            parts.push("--continue".to_string());
        }
    } else if agent.eq_ignore_ascii_case("kiro") {
        parts.extend(["kiro-cli".to_string(), "chat".to_string()]);
        if resume_mode != "none" && resume_mode != "new" {
            parts.push("--resume".to_string());
        }
    } else if agent.eq_ignore_ascii_case("cursor") {
        parts.push("agent".to_string());
        if resume_mode != "none" && resume_mode != "new" {
            parts.push("--continue".to_string());
        }
    } else if agent.eq_ignore_ascii_case("amp") {
        parts.push("amp".to_string());
        if resume_mode != "none" && resume_mode != "new" {
            parts.push("last".to_string());
        }
    } else if agent.eq_ignore_ascii_case("devin") {
        parts.push("devin".to_string());
        if resume_mode != "none" && resume_mode != "new" {
            parts.push("--continue".to_string());
        }
    } else if agent.eq_ignore_ascii_case("factory") {
        parts.push("droid".to_string());
        if resume_mode != "none" && resume_mode != "new" {
            parts.push("--resume".to_string());
        }
    } else {
        parts.push("claude".to_string());
        if resume_mode != "none" && resume_mode != "new" {
            parts.push("--continue".to_string());
        }
    }

    if let Some(model) = model {
        parts.extend(["--model".to_string(), quote_command_arg(model)]);
    }
    if dangerous {
        if agent.eq_ignore_ascii_case("codex") {
            parts.push("--dangerously-bypass-approvals-and-sandbox".to_string());
        } else if agent.eq_ignore_ascii_case("gemini") {
            parts.push("--yolo".to_string());
        } else if agent.eq_ignore_ascii_case("opencode") {
            parts.push("--auto".to_string());
        } else if agent.eq_ignore_ascii_case("copilot") {
            parts.push("--yolo".to_string());
        } else if agent.eq_ignore_ascii_case("antigravity") || agent.eq_ignore_ascii_case("agy") {
            parts.push("--dangerously-skip-permissions".to_string());
        } else if agent.eq_ignore_ascii_case("kimi") {
            parts.push("--yolo".to_string());
        } else if agent.eq_ignore_ascii_case("kiro") {
            parts.push("--trust-all-tools".to_string());
        } else if agent.eq_ignore_ascii_case("cursor") {
            parts.push("--yolo".to_string());
        } else if agent.eq_ignore_ascii_case("amp") {
            parts.push("--dangerously-allow-all".to_string());
        } else if agent.eq_ignore_ascii_case("devin") {
            parts.push("--permission-mode=dangerous".to_string());
        } else if agent.eq_ignore_ascii_case("factory") {
            parts.push("--auto=high".to_string());
        } else {
            parts.push("--dangerously-skip-permissions".to_string());
        }
    }
    Some(parts.join(" "))
}

#[cfg(test)]
mod tests {
    use super::*;
    use maestro_shell::records::{Project, ProjectLaunchDefaults};

    fn project_with_defaults(agent: Option<&str>, custom_command: Option<&str>) -> Project {
        Project {
            project_id: "project-1".to_string(),
            name: "Project 1".to_string(),
            root: "/tmp/project-1".to_string(),
            default_workspace_policy: maestro_shell::WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: Some(ProjectLaunchDefaults {
                agent: agent.map(str::to_string),
                model: Some("opus".to_string()),
                resume_mode: Some("new".to_string()),
                dangerous_skip_permissions: Some(false),
                custom_command: custom_command.map(str::to_string),
            }),
            directories: Vec::new(),
            window_order: Vec::new(),
            system: false,
            hidden: false,
        }
    }

    #[test]
    fn explicit_launch_inputs_override_project_defaults() {
        let project = project_with_defaults(Some("claude"), Some("claude --default"));

        let inherited = inherited_project_launch_inputs(
            Some(&project),
            Some("codex"),
            Some("codex --explicit"),
        );

        assert_eq!(
            inherited,
            InheritedProjectLaunchInputs {
                agent: Some(Cow::Borrowed("codex")),
                resolved_launch_command: Some(Cow::Borrowed("codex --explicit")),
            }
        );
    }

    #[test]
    fn project_launch_defaults_fill_missing_inputs() {
        let project = project_with_defaults(Some("claude"), Some("claude --project-default"));

        let inherited = inherited_project_launch_inputs(Some(&project), None, None);

        assert_eq!(
            inherited,
            InheritedProjectLaunchInputs {
                agent: Some(Cow::Borrowed("claude")),
                resolved_launch_command: Some(Cow::Borrowed("claude --project-default")),
            }
        );
    }

    #[test]
    fn terminal_launch_does_not_inherit_a_stale_project_command() {
        let terminal_project =
            project_with_defaults(Some("terminal"), Some("claude --stale-project-command"));
        let claude_project =
            project_with_defaults(Some("claude"), Some("claude --stale-project-command"));

        for (project, explicit_agent, explicit_command) in [
            (&terminal_project, None, None),
            (&claude_project, Some("terminal"), None),
            (&claude_project, Some("terminal"), Some("   ")),
        ] {
            let inherited =
                inherited_project_launch_inputs(Some(project), explicit_agent, explicit_command);
            assert_eq!(inherited.agent.as_deref(), Some("terminal"));
            assert_eq!(inherited.resolved_launch_command, None);
        }

        let explicit = inherited_project_launch_inputs(
            Some(&terminal_project),
            Some("terminal"),
            Some("terminal-wrapper --flag"),
        );
        assert_eq!(
            explicit.resolved_launch_command.as_deref(),
            Some("terminal-wrapper --flag"),
            "an explicit nonblank command remains authoritative"
        );
    }

    #[test]
    fn project_launch_defaults_synthesize_window_launch_command() {
        let mut project = project_with_defaults(Some("codex"), None);
        project
            .launch_defaults
            .as_mut()
            .expect("fixture has defaults")
            .resume_mode = Some("resume".to_string());

        let inherited = inherited_project_launch_inputs(Some(&project), None, None);

        assert_eq!(
            inherited,
            InheritedProjectLaunchInputs {
                agent: Some(Cow::Borrowed("codex")),
                resolved_launch_command: Some(Cow::Owned(
                    "codex resume --last --model opus".to_string()
                )),
            }
        );
    }

    #[test]
    fn unspecified_resume_mode_defaults_to_a_fresh_session_not_continue() {
        // A project with SOME synthesized defaults (model/dangerous) but NO explicit resume_mode must NOT
        // silently continue the last session — the fresh-create bug. codex → bare `codex`, claude → bare `claude`.
        for (agent, expect) in [
            ("codex", "codex --model opus"),
            ("claude", "claude --model opus"),
        ] {
            let mut project = project_with_defaults(Some(agent), None);
            project
                .launch_defaults
                .as_mut()
                .expect("fixture has defaults")
                .resume_mode = None; // unspecified
            let inherited = inherited_project_launch_inputs(Some(&project), None, None);
            assert_eq!(
                inherited.resolved_launch_command.as_deref(),
                Some(expect),
                "agent {agent} with no resume_mode must start fresh, not resume --last / --continue"
            );
        }
    }

    #[test]
    fn project_launch_defaults_synthesize_dangerous_flag_per_agent() {
        let mut project = project_with_defaults(Some("gemini"), None);
        let defaults = project
            .launch_defaults
            .as_mut()
            .expect("fixture has defaults");
        defaults.resume_mode = Some("continue".to_string());
        defaults.dangerous_skip_permissions = Some(true);

        let inherited = inherited_project_launch_inputs(Some(&project), None, None);

        assert_eq!(
            inherited,
            InheritedProjectLaunchInputs {
                agent: Some(Cow::Borrowed("gemini")),
                resolved_launch_command: Some(Cow::Owned(
                    "gemini --resume latest --model opus --yolo".to_string()
                )),
            }
        );
    }

    #[test]
    fn new_provider_defaults_use_their_exact_commands_and_flags() {
        for (agent, expected) in [
            ("copilot", "copilot --continue --model opus --yolo"),
            (
                "antigravity",
                "agy --continue --model opus --dangerously-skip-permissions",
            ),
            // Durable/internal provider identity is also accepted without changing the emitted ID.
            (
                "agy",
                "agy --continue --model opus --dangerously-skip-permissions",
            ),
            ("kimi", "kimi --continue --model opus --yolo"),
            (
                "kiro",
                "kiro-cli chat --resume --model opus --trust-all-tools",
            ),
            ("cursor", "agent --continue --model opus --yolo"),
            ("amp", "amp last --dangerously-allow-all"),
            (
                "devin",
                "devin --continue --model opus --permission-mode=dangerous",
            ),
            ("factory", "droid --resume --auto=high"),
        ] {
            let mut project = project_with_defaults(Some(agent), None);
            let defaults = project
                .launch_defaults
                .as_mut()
                .expect("fixture has defaults");
            defaults.resume_mode = Some("continue".to_string());
            defaults.dangerous_skip_permissions = Some(true);

            let inherited = inherited_project_launch_inputs(Some(&project), None, None);

            assert_eq!(
                inherited.resolved_launch_command.as_deref(),
                Some(expected),
                "provider {agent} must not fall through to Claude launch semantics"
            );
        }
    }

    #[test]
    fn new_provider_defaults_start_fresh_unless_continue_is_explicit() {
        for (agent, expected) in [
            ("copilot", "copilot --model opus"),
            ("antigravity", "agy --model opus"),
            ("kimi", "kimi --model opus"),
            ("kiro", "kiro-cli chat --model opus"),
            ("cursor", "agent --model opus"),
            ("amp", "amp"),
            ("devin", "devin --model opus"),
            ("factory", "droid"),
        ] {
            let project = project_with_defaults(Some(agent), None);
            let inherited = inherited_project_launch_inputs(Some(&project), None, None);
            assert_eq!(
                inherited.resolved_launch_command.as_deref(),
                Some(expected),
                "provider {agent} must start a fresh session"
            );
        }
    }

    #[test]
    fn new_provider_model_defaults_are_bounded_single_arguments() {
        let mut project = project_with_defaults(Some("antigravity"), None);
        let defaults = project
            .launch_defaults
            .as_mut()
            .expect("fixture has defaults");
        defaults.model = Some("Gemini 3.5 Flash (High) / preview".into());
        defaults.resume_mode = None;
        defaults.dangerous_skip_permissions = None;
        let inherited = inherited_project_launch_inputs(Some(&project), None, None);
        assert_eq!(
            inherited.resolved_launch_command.as_deref(),
            Some("agy --model 'Gemini 3.5 Flash (High) / preview'")
        );

        for invalid in ["bad\nmodel".to_string(), "x".repeat(97)] {
            let mut project = project_with_defaults(Some("copilot"), None);
            let defaults = project
                .launch_defaults
                .as_mut()
                .expect("fixture has defaults");
            defaults.model = Some(invalid);
            defaults.resume_mode = None;
            defaults.dangerous_skip_permissions = None;

            let inherited = inherited_project_launch_inputs(Some(&project), None, None);
            assert_eq!(inherited.resolved_launch_command, None);
        }
    }

    #[test]
    fn new_provider_model_punctuation_stays_one_non_evaluated_argument() {
        for model in [
            "foo;rm -rf /",
            "$(touch should-not-run)",
            "`touch should-not-run`",
            "quote's \"and\" back\\slash",
        ] {
            let mut project = project_with_defaults(Some("antigravity"), None);
            let defaults = project.launch_defaults.as_mut().unwrap();
            defaults.model = Some(model.to_string());
            defaults.resume_mode = None;
            defaults.dangerous_skip_permissions = None;
            let inherited = inherited_project_launch_inputs(Some(&project), None, None);
            let command = inherited.resolved_launch_command.as_deref().unwrap();
            assert_eq!(
                command,
                format!("agy --model {}", quote_command_arg(model)),
                "non-safe punctuation must be contained in one quoted model argument: {model:?}"
            );
        }
    }

    #[test]
    fn blank_values_are_ignored() {
        let mut project = project_with_defaults(Some("  "), Some("  "));
        let defaults = project
            .launch_defaults
            .as_mut()
            .expect("fixture has defaults");
        defaults.model = Some("  ".to_string());
        defaults.resume_mode = None;
        defaults.dangerous_skip_permissions = None;

        let inherited = inherited_project_launch_inputs(Some(&project), Some("  "), Some("  "));

        assert_eq!(
            inherited,
            InheritedProjectLaunchInputs {
                agent: None,
                resolved_launch_command: None,
            }
        );
    }

    #[test]
    fn default_model_alone_does_not_synthesize_launch_command() {
        let mut project = project_with_defaults(Some("claude"), None);
        let defaults = project
            .launch_defaults
            .as_mut()
            .expect("fixture has defaults");
        defaults.model = Some("default".to_string());
        defaults.resume_mode = None;
        defaults.dangerous_skip_permissions = None;

        let inherited = inherited_project_launch_inputs(Some(&project), None, None);

        assert_eq!(
            inherited,
            InheritedProjectLaunchInputs {
                agent: Some(Cow::Borrowed("claude")),
                resolved_launch_command: None,
            }
        );
    }
}
