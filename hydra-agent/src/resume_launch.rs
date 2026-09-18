//! Content-blind builder for a per-agent "resume a specific prior session" launch, mirroring the desktop React
//! overlay command builders (`dashboard-ui/src/App.tsx` resolveOverlayWindowLaunchCommand). Roadmap item 5
//! (Session Picker Completion) requires the browser SessionPicker to resume each supported agent with the
//! tool's correct ID/path shape. The browser already sends a STRUCTURED descriptor
//! (`launchFlags: { resumeMode:'resume', resumeSessionId | resumeSessionFile }` + `agent`) — never a free-form
//! command — so resume stays within the KnownSafe/allowlisted boundary: this turns that structured descriptor into
//! a `(command, args)` pair for the daemon start line, with the agent allowlisted and the id/file passed as
//! discrete argv elements (a JSON array member, never interpolated into a shell string).
//!
//! This module is PURE and does not itself launch anything or touch the daemon. Its validated output is wired
//! into the live `start_session` paths by `session_creator` and `remote_daemon_backend`.

/// A validated, structured resume request extracted from the browser's `launch_flags`. Content-blind: an
/// allowlisted agent + an opaque session id and/or file path — no transcript text, no arbitrary command.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeDescriptor {
    pub agent: ResumeAgent,
    /// The provider's session id. Claude, Codex, Copilot, Antigravity, Kiro, Cursor, and Gemini
    /// exact resumes require canonical UUIDs; Kimi requires `session_<canonical UUID>`. OpenCode,
    /// Devin, and Factory use bounded provider-owned ids, while Amp uses a bounded opaque thread target.
    /// Empty values are absent.
    pub session_id: Option<String>,
    /// A legacy Gemini session-file import path. Import is not exact resume authority; when an exact
    /// provider UUID is also present, the UUID always wins. Trimmed; empty is treated as absent.
    pub session_file: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResumeAgent {
    Claude,
    Codex,
    Copilot,
    Antigravity,
    Kimi,
    Kiro,
    Cursor,
    Amp,
    Devin,
    Factory,
    Gemini,
    Opencode,
}

impl ResumeAgent {
    /// Allowlist the agent — the same set `sanitize_agent` enforces. Anything else is rejected (None), so a resume
    /// can never synthesize a command for an unknown/arbitrary "agent".
    pub fn parse(agent: &str) -> Option<Self> {
        match agent {
            "claude" => Some(ResumeAgent::Claude),
            "codex" => Some(ResumeAgent::Codex),
            "copilot" => Some(ResumeAgent::Copilot),
            "antigravity" => Some(ResumeAgent::Antigravity),
            "kimi" => Some(ResumeAgent::Kimi),
            "kiro" => Some(ResumeAgent::Kiro),
            "cursor" => Some(ResumeAgent::Cursor),
            "amp" => Some(ResumeAgent::Amp),
            "devin" => Some(ResumeAgent::Devin),
            "factory" => Some(ResumeAgent::Factory),
            "gemini" => Some(ResumeAgent::Gemini),
            "opencode" => Some(ResumeAgent::Opencode),
            _ => None,
        }
    }

    pub fn command(self) -> &'static str {
        match self {
            ResumeAgent::Claude => "claude",
            ResumeAgent::Codex => "codex",
            ResumeAgent::Copilot => "copilot",
            ResumeAgent::Antigravity => "agy",
            ResumeAgent::Kimi => "kimi",
            ResumeAgent::Kiro => "kiro-cli",
            ResumeAgent::Cursor => "agent",
            ResumeAgent::Amp => "amp",
            ResumeAgent::Devin => "devin",
            ResumeAgent::Factory => "droid",
            ResumeAgent::Gemini => "gemini",
            ResumeAgent::Opencode => "opencode",
        }
    }

    pub fn dangerous_flag(self) -> &'static str {
        match self {
            ResumeAgent::Claude | ResumeAgent::Antigravity => "--dangerously-skip-permissions",
            ResumeAgent::Codex => "--dangerously-bypass-approvals-and-sandbox",
            ResumeAgent::Copilot
            | ResumeAgent::Kimi
            | ResumeAgent::Cursor
            | ResumeAgent::Gemini => "--yolo",
            ResumeAgent::Kiro => "--trust-all-tools",
            ResumeAgent::Amp => "--dangerously-allow-all",
            ResumeAgent::Devin => "--permission-mode=dangerous",
            ResumeAgent::Factory => "--auto=high",
            ResumeAgent::Opencode => "--auto",
        }
    }
}

/// The daemon start-line launch: a program plus discrete argv. Because args are discrete (a JSON array on the
/// wire), an id/path can never break out into shell metacharacters.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ResumeLaunch {
    pub command: String,
    pub args: Vec<String>,
}

/// Build a fresh launch for an already-allowlisted provider. Claude, Gemini, and Copilot let Hydra choose the
/// provider-session UUID at creation time; assigning it up front makes the exact resume target durable instead
/// of trying to infer it from mutable transcript history later.
pub fn build_fresh_launch(agent: ResumeAgent) -> ResumeLaunch {
    let args = match agent {
        ResumeAgent::Claude | ResumeAgent::Gemini => {
            vec!["--session-id".to_string(), uuid::Uuid::new_v4().to_string()]
        }
        ResumeAgent::Copilot => vec![format!("--session-id={}", uuid::Uuid::new_v4())],
        ResumeAgent::Kiro => vec!["chat".to_string()],
        _ => Vec::new(),
    };
    ResumeLaunch {
        command: agent.command().to_string(),
        args,
    }
}

fn clean(value: &Option<String>) -> Option<&str> {
    value
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// Build the per-agent resume launch, mirroring the desktop overlay shapes exactly:
/// - claude, exact UUID:    `claude --resume <uuid>`
/// - codex, exact UUID:     `codex resume <uuid>`
/// - copilot, specific id:  `copilot --resume=<uuid>`
/// - antigravity, UUID:     `agy --conversation <uuid>`
/// - kimi, exact id:        `kimi --session session_<uuid>`
/// - kiro, specific id:     `kiro-cli chat --resume-id <uuid>`
/// - cursor, specific id:   `agent --resume <uuid>`
/// - amp, specific target:  `amp threads continue <target>`
/// - devin, specific id:     `devin --resume <id>`
/// - factory, specific id:   `droid --resume <id>`
/// - gemini, exact UUID:    `gemini --resume <uuid>`; legacy import: `gemini --session-file <f>`
/// - opencode, specific id: `opencode --session <id>`
///
/// Returns None if the descriptor lacks the target required by its provider or an exact-identity
/// provider receives a non-canonical identity. The caller may then start a fresh, separately identified
/// conversation instead of replaying a mutable latest alias.
pub fn build_resume_launch(descriptor: &ResumeDescriptor) -> Option<ResumeLaunch> {
    let command = descriptor.agent.command().to_string();
    let id = clean(&descriptor.session_id);
    let file = clean(&descriptor.session_file);
    let args = match descriptor.agent {
        ResumeAgent::Claude => {
            vec!["--resume".to_string(), canonical_uuid(id?)?.to_string()]
        }
        ResumeAgent::Codex => vec!["resume".to_string(), canonical_uuid(id?)?.to_string()],
        ResumeAgent::Copilot => {
            let id = id?;
            let parsed = uuid::Uuid::parse_str(id).ok()?;
            let canonical = parsed.hyphenated().to_string();
            if id != canonical {
                return None;
            }
            vec![format!("--resume={canonical}")]
        }
        ResumeAgent::Antigravity => {
            vec![
                "--conversation".to_string(),
                canonical_uuid(id?)?.to_string(),
            ]
        }
        ResumeAgent::Kimi => vec![
            "--session".to_string(),
            canonical_kimi_session_id(id?)?.to_string(),
        ],
        ResumeAgent::Kiro => {
            let id = canonical_uuid(id?)?;
            vec![
                "chat".to_string(),
                "--resume-id".to_string(),
                id.to_string(),
            ]
        }
        ResumeAgent::Cursor => {
            let id = canonical_uuid(id?)?;
            vec!["--resume".to_string(), id.to_string()]
        }
        ResumeAgent::Amp => vec![
            "threads".to_string(),
            "continue".to_string(),
            bounded_thread_target(id?)?.to_string(),
        ],
        ResumeAgent::Devin | ResumeAgent::Factory => vec![
            "--resume".to_string(),
            bounded_opaque_resume_id(id?)?.to_string(),
        ],
        ResumeAgent::Gemini => {
            if let Some(id) = id.and_then(canonical_uuid) {
                vec!["--resume".to_string(), id.to_string()]
            } else {
                vec!["--session-file".to_string(), file?.to_string()]
            }
        }
        ResumeAgent::Opencode => vec!["--session".to_string(), id?.to_string()],
    };
    Some(ResumeLaunch { command, args })
}

fn canonical_uuid(value: &str) -> Option<&str> {
    let parsed = uuid::Uuid::parse_str(value).ok()?;
    (parsed.hyphenated().to_string() == value).then_some(value)
}

fn canonical_kimi_session_id(value: &str) -> Option<&str> {
    value.strip_prefix("session_").and_then(canonical_uuid)?;
    Some(value)
}

fn bounded_thread_target(value: &str) -> Option<&str> {
    bounded_opaque_resume_id(value)
}

fn bounded_opaque_resume_id(value: &str) -> Option<&str> {
    let value = value.trim();
    (!value.is_empty()
        && !value.starts_with('-')
        && value.chars().count() <= 256
        && !value.chars().any(char::is_control))
    .then_some(value)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn agent_allowlist_rejects_unknown() {
        assert_eq!(ResumeAgent::parse("claude"), Some(ResumeAgent::Claude));
        assert_eq!(ResumeAgent::parse("codex"), Some(ResumeAgent::Codex));
        assert_eq!(ResumeAgent::parse("copilot"), Some(ResumeAgent::Copilot));
        assert_eq!(
            ResumeAgent::parse("antigravity"),
            Some(ResumeAgent::Antigravity)
        );
        assert_eq!(ResumeAgent::parse("kimi"), Some(ResumeAgent::Kimi));
        assert_eq!(ResumeAgent::parse("kiro"), Some(ResumeAgent::Kiro));
        assert_eq!(ResumeAgent::parse("cursor"), Some(ResumeAgent::Cursor));
        assert_eq!(ResumeAgent::parse("amp"), Some(ResumeAgent::Amp));
        assert_eq!(ResumeAgent::parse("devin"), Some(ResumeAgent::Devin));
        assert_eq!(ResumeAgent::parse("factory"), Some(ResumeAgent::Factory));
        assert_eq!(ResumeAgent::parse("gemini"), Some(ResumeAgent::Gemini));
        assert_eq!(ResumeAgent::parse("bash"), None);
        assert_eq!(ResumeAgent::parse("claude; rm -rf /"), None);
        assert_eq!(ResumeAgent::parse(""), None);
    }

    #[test]
    fn claude_resumes_by_id() {
        let d = ResumeDescriptor {
            agent: ResumeAgent::Claude,
            session_id: Some("fc9dbfd4-22f4-4b50-9fa4-68bf7816137d".into()),
            session_file: None,
        };
        assert_eq!(
            build_resume_launch(&d),
            Some(ResumeLaunch {
                command: "claude".into(),
                args: vec![
                    "--resume".into(),
                    "fc9dbfd4-22f4-4b50-9fa4-68bf7816137d".into()
                ],
            })
        );
    }

    #[test]
    fn codex_resumes_by_id() {
        let d = ResumeDescriptor {
            agent: ResumeAgent::Codex,
            session_id: Some("123e4567-e89b-42d3-a456-426614174000".into()),
            session_file: None,
        };
        assert_eq!(
            build_resume_launch(&d),
            Some(ResumeLaunch {
                command: "codex".into(),
                args: vec![
                    "resume".into(),
                    "123e4567-e89b-42d3-a456-426614174000".into()
                ],
            })
        );
    }

    #[test]
    fn gemini_resumes_by_session_file() {
        let d = ResumeDescriptor {
            agent: ResumeAgent::Gemini,
            session_id: None,
            session_file: Some("/tmp/gemini/session-7.json".into()),
        };
        assert_eq!(
            build_resume_launch(&d),
            Some(ResumeLaunch {
                command: "gemini".into(),
                args: vec!["--session-file".into(), "/tmp/gemini/session-7.json".into()],
            })
        );
    }

    #[test]
    fn gemini_prefers_exact_session_id_over_session_file() {
        let d = ResumeDescriptor {
            agent: ResumeAgent::Gemini,
            session_id: Some("fc9dbfd4-22f4-4b50-9fa4-68bf7816137d".into()),
            session_file: Some("/tmp/gemini/session-7.json".into()),
        };
        assert_eq!(
            build_resume_launch(&d),
            Some(ResumeLaunch {
                command: "gemini".into(),
                args: vec![
                    "--resume".into(),
                    "fc9dbfd4-22f4-4b50-9fa4-68bf7816137d".into()
                ],
            })
        );
    }

    #[test]
    fn copilot_resumes_by_canonical_uuid_in_one_argument() {
        let d = ResumeDescriptor {
            agent: ResumeAgent::Copilot,
            session_id: Some("fc9dbfd4-22f4-4b50-9fa4-68bf7816137d".into()),
            session_file: None,
        };
        assert_eq!(
            build_resume_launch(&d),
            Some(ResumeLaunch {
                command: "copilot".into(),
                args: vec!["--resume=fc9dbfd4-22f4-4b50-9fa4-68bf7816137d".into()],
            })
        );
    }

    #[test]
    fn copilot_rejects_noncanonical_or_non_uuid_resume_ids() {
        for id in [
            "not-a-uuid",
            "FC9DBFD4-22F4-4B50-9FA4-68BF7816137D",
            "fc9dbfd422f44b509fa468bf7816137d",
        ] {
            assert_eq!(
                build_resume_launch(&ResumeDescriptor {
                    agent: ResumeAgent::Copilot,
                    session_id: Some(id.into()),
                    session_file: None,
                }),
                None
            );
        }
    }

    #[test]
    fn antigravity_resumes_by_conversation_id() {
        let d = ResumeDescriptor {
            agent: ResumeAgent::Antigravity,
            session_id: Some("5f082f93-2ca4-4b7b-bc58-048e899edebb".into()),
            session_file: None,
        };
        assert_eq!(
            build_resume_launch(&d),
            Some(ResumeLaunch {
                command: "agy".into(),
                args: vec![
                    "--conversation".into(),
                    "5f082f93-2ca4-4b7b-bc58-048e899edebb".into()
                ],
            })
        );
    }

    #[test]
    fn kimi_resumes_by_session_id() {
        let d = ResumeDescriptor {
            agent: ResumeAgent::Kimi,
            session_id: Some("session_fc9dbfd4-22f4-4b50-9fa4-68bf7816137d".into()),
            session_file: None,
        };
        assert_eq!(
            build_resume_launch(&d),
            Some(ResumeLaunch {
                command: "kimi".into(),
                args: vec![
                    "--session".into(),
                    "session_fc9dbfd4-22f4-4b50-9fa4-68bf7816137d".into()
                ],
            })
        );
    }

    #[test]
    fn exact_resume_providers_reject_noncanonical_identity_shapes() {
        for (agent, invalid) in [
            (ResumeAgent::Claude, "not-a-uuid"),
            (ResumeAgent::Codex, "FC9DBFD4-22F4-4B50-9FA4-68BF7816137D"),
            (ResumeAgent::Antigravity, "fc9dbfd422f44b509fa468bf7816137d"),
            (ResumeAgent::Kimi, "fc9dbfd4-22f4-4b50-9fa4-68bf7816137d"),
            (ResumeAgent::Kimi, "session_not-a-uuid"),
        ] {
            assert_eq!(
                build_resume_launch(&ResumeDescriptor {
                    agent,
                    session_id: Some(invalid.into()),
                    session_file: None,
                }),
                None,
                "agent={agent:?} id={invalid:?}"
            );
        }
    }

    #[test]
    fn kiro_resumes_by_canonical_uuid_after_the_mandatory_chat_arg() {
        let d = ResumeDescriptor {
            agent: ResumeAgent::Kiro,
            session_id: Some("fc9dbfd4-22f4-4b50-9fa4-68bf7816137d".into()),
            session_file: None,
        };
        assert_eq!(
            build_resume_launch(&d),
            Some(ResumeLaunch {
                command: "kiro-cli".into(),
                args: vec![
                    "chat".into(),
                    "--resume-id".into(),
                    "fc9dbfd4-22f4-4b50-9fa4-68bf7816137d".into(),
                ],
            })
        );
        for invalid in [
            "not-a-uuid",
            "FC9DBFD4-22F4-4B50-9FA4-68BF7816137D",
            "fc9dbfd422f44b509fa468bf7816137d",
        ] {
            assert_eq!(
                build_resume_launch(&ResumeDescriptor {
                    agent: ResumeAgent::Kiro,
                    session_id: Some(invalid.into()),
                    session_file: None,
                }),
                None
            );
        }
    }

    #[test]
    fn cursor_resumes_by_canonical_uuid() {
        let d = ResumeDescriptor {
            agent: ResumeAgent::Cursor,
            session_id: Some("123e4567-e89b-42d3-a456-426614174000".into()),
            session_file: None,
        };
        assert_eq!(
            build_resume_launch(&d),
            Some(ResumeLaunch {
                command: "agent".into(),
                args: vec![
                    "--resume".into(),
                    "123e4567-e89b-42d3-a456-426614174000".into()
                ],
            })
        );
    }

    #[test]
    fn amp_fresh_exact_and_dangerous_shapes_are_explicit() {
        assert_eq!(
            build_fresh_launch(ResumeAgent::Amp),
            ResumeLaunch {
                command: "amp".into(),
                args: Vec::new(),
            }
        );
        assert_eq!(
            build_resume_launch(&ResumeDescriptor {
                agent: ResumeAgent::Amp,
                session_id: Some("https://ampcode.com/threads/T-example".into()),
                session_file: None,
            }),
            Some(ResumeLaunch {
                command: "amp".into(),
                args: vec![
                    "threads".into(),
                    "continue".into(),
                    "https://ampcode.com/threads/T-example".into(),
                ],
            })
        );
        assert_eq!(ResumeAgent::Amp.dangerous_flag(), "--dangerously-allow-all");
    }

    #[test]
    fn devin_and_factory_launch_shapes_are_exact_and_bounded() {
        for (agent, command, danger) in [
            (ResumeAgent::Devin, "devin", "--permission-mode=dangerous"),
            (ResumeAgent::Factory, "droid", "--auto=high"),
        ] {
            assert_eq!(
                build_fresh_launch(agent),
                ResumeLaunch {
                    command: command.into(),
                    args: Vec::new(),
                }
            );
            assert_eq!(agent.dangerous_flag(), danger);
            assert_eq!(
                build_resume_launch(&ResumeDescriptor {
                    agent,
                    session_id: Some("opaque-session-1".into()),
                    session_file: None,
                }),
                Some(ResumeLaunch {
                    command: command.into(),
                    args: vec!["--resume".into(), "opaque-session-1".into()],
                })
            );
            for invalid in ["", "-latest", "line\nother", &"x".repeat(257)] {
                assert_eq!(
                    build_resume_launch(&ResumeDescriptor {
                        agent,
                        session_id: Some(invalid.into()),
                        session_file: None,
                    }),
                    None,
                    "agent={agent:?} id={invalid:?}"
                );
            }
        }
    }

    #[test]
    fn amp_rejects_missing_flag_like_control_or_oversized_thread_targets() {
        for target in ["", "   ", "--help", "thread\nother", &"x".repeat(257)] {
            assert_eq!(
                build_resume_launch(&ResumeDescriptor {
                    agent: ResumeAgent::Amp,
                    session_id: Some(target.into()),
                    session_file: None,
                }),
                None,
                "target={target:?}",
            );
        }
    }

    #[test]
    fn fresh_claude_gemini_and_copilot_get_canonical_hydra_owned_session_ids() {
        for (agent, command) in [
            (ResumeAgent::Claude, "claude"),
            (ResumeAgent::Gemini, "gemini"),
        ] {
            let launch = build_fresh_launch(agent);
            assert_eq!(launch.command, command);
            assert_eq!(launch.args.len(), 2);
            assert_eq!(launch.args[0], "--session-id");
            let id = &launch.args[1];
            let parsed = uuid::Uuid::parse_str(id).expect("canonical UUID");
            assert_eq!(parsed.hyphenated().to_string(), *id);
        }

        let launch = build_fresh_launch(ResumeAgent::Copilot);
        assert_eq!(launch.command, "copilot");
        assert_eq!(launch.args.len(), 1);
        let id = launch.args[0]
            .strip_prefix("--session-id=")
            .expect("copilot fresh id flag");
        let parsed = uuid::Uuid::parse_str(id).expect("canonical UUID");
        assert_eq!(parsed.hyphenated().to_string(), id);
    }

    #[test]
    fn fresh_antigravity_maps_provider_identity_to_agy_executable() {
        assert_eq!(
            build_fresh_launch(ResumeAgent::Antigravity),
            ResumeLaunch {
                command: "agy".into(),
                args: Vec::new(),
            }
        );
    }

    #[test]
    fn fresh_kiro_always_starts_in_interactive_chat_mode() {
        assert_eq!(
            build_fresh_launch(ResumeAgent::Kiro),
            ResumeLaunch {
                command: "kiro-cli".into(),
                args: vec!["chat".into()],
            }
        );
    }

    #[test]
    fn provider_dangerous_flags_are_explicit_and_copilot_is_only_yolo() {
        assert_eq!(ResumeAgent::Copilot.dangerous_flag(), "--yolo");
        assert_eq!(ResumeAgent::Kimi.dangerous_flag(), "--yolo");
        assert_eq!(ResumeAgent::Cursor.dangerous_flag(), "--yolo");
        assert_eq!(ResumeAgent::Kiro.dangerous_flag(), "--trust-all-tools");
        assert_eq!(ResumeAgent::Amp.dangerous_flag(), "--dangerously-allow-all");
        assert_eq!(
            ResumeAgent::Antigravity.dangerous_flag(),
            "--dangerously-skip-permissions"
        );
        assert_eq!(
            ResumeAgent::Codex.dangerous_flag(),
            "--dangerously-bypass-approvals-and-sandbox"
        );
        assert_ne!(ResumeAgent::Copilot.dangerous_flag(), "--allow-all");
    }

    #[test]
    fn opencode_resumes_by_id() {
        let d = ResumeDescriptor {
            agent: ResumeAgent::Opencode,
            session_id: Some("ses_123".into()),
            session_file: None,
        };
        assert_eq!(
            build_resume_launch(&d),
            Some(ResumeLaunch {
                command: "opencode".into(),
                args: vec!["--session".into(), "ses_123".into()],
            })
        );
    }

    #[test]
    fn missing_target_returns_none_so_caller_falls_back_to_fresh() {
        // claude/codex with no id, gemini with no file → no resume shape; caller should start fresh, not break.
        assert_eq!(
            build_resume_launch(&ResumeDescriptor {
                agent: ResumeAgent::Claude,
                session_id: None,
                session_file: None,
            }),
            None
        );
        assert_eq!(
            build_resume_launch(&ResumeDescriptor {
                agent: ResumeAgent::Gemini,
                session_id: Some("wrong-shape-for-gemini".into()),
                session_file: None,
            }),
            None
        );
    }

    #[test]
    fn whitespace_only_target_is_treated_as_absent() {
        assert_eq!(
            build_resume_launch(&ResumeDescriptor {
                agent: ResumeAgent::Codex,
                session_id: Some("   ".into()),
                session_file: None,
            }),
            None
        );
    }

    #[test]
    fn id_and_file_are_discrete_argv_never_shell_interpolated() {
        // A hostile id is a single argv element, not a shell string — no metacharacter can escape.
        let d = ResumeDescriptor {
            agent: ResumeAgent::Opencode,
            session_id: Some("id; rm -rf /".into()),
            session_file: None,
        };
        let launch = build_resume_launch(&d).unwrap();
        assert_eq!(
            launch.args,
            vec!["--session".to_string(), "id; rm -rf /".to_string()]
        );
        // It stays ONE arg — the daemon receives it as a JSON array element, never a parsed shell command.
        assert_eq!(launch.args.len(), 2);
    }
}
