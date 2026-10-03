use super::*;
use std::os::unix::fs::{symlink, PermissionsExt};

struct Fixture {
    root: tempfile::TempDir,
    shell: String,
    path: OsString,
}

impl LaunchEnvLookup for Fixture {
    fn shell_utf8(&self) -> Option<String> {
        Some(self.shell.clone())
    }
    fn home_os(&self) -> Option<OsString> {
        Some(self.root.path().as_os_str().to_owned())
    }
    fn path_os(&self) -> Option<OsString> {
        Some(self.path.clone())
    }
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let shell = root.path().join("fixture-shell");
        Self::script(&shell, "#!/bin/sh\nexec /bin/sh -c \"$2\"\n");
        Self {
            root,
            shell: shell.to_str().unwrap().into(),
            path: "/usr/bin:/bin".into(),
        }
    }

    fn script(path: &Path, script: &str) {
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(path, script).unwrap();
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o700)).unwrap();
    }

    fn recipe(&self, path: &Path) -> LaunchSpec {
        LaunchSpec::BoundProvider {
            launch_spec_id: "claude".into(),
            params: vec![
                "--resume".into(),
                "00000000-0000-4000-8000-000000000017".into(),
            ],
            executable: path.to_str().unwrap().into(),
        }
    }

    fn run(&self, recipe: &LaunchSpec) -> String {
        let argv = known_safe_provider_login_shell_argv(recipe, self).unwrap();
        let output = std::process::Command::new(&argv[0])
            .args(&argv[1..])
            .env_clear()
            .env("HOME", self.root.path())
            .env("PATH", &self.path)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap()
    }
}

#[test]
fn persisted_locator_ignores_path_drift_and_follows_stable_symlink_upgrade() {
    let mut fixture = Fixture::new();
    let version1 = fixture.root.path().join("versions/claude-v1");
    let version2 = fixture.root.path().join("versions/claude-v2");
    Fixture::script(&version1, "#!/bin/sh\nprintf 'v1:%s:%s\\n' \"$1\" \"$2\"\n");
    Fixture::script(&version2, "#!/bin/sh\nprintf 'v2:%s:%s\\n' \"$1\" \"$2\"\n");
    let stable = fixture.root.path().join("stable launcher 'quoted'");
    symlink(&version1, &stable).unwrap();
    let json = serde_json::to_string(&fixture.recipe(&stable)).unwrap();
    let recipe: LaunchSpec = serde_json::from_str(&json).unwrap();
    assert_eq!(recipe.provider_recipe().unwrap().2, stable.to_str());
    Fixture::script(
        &fixture.root.path().join("other/claude"),
        "#!/bin/sh\nprintf 'WRONG-PATH'\n",
    );
    fixture.path = fixture.root.path().join("other").into_os_string();
    assert_eq!(
        fixture.run(&recipe),
        "v1:--resume:00000000-0000-4000-8000-000000000017\n"
    );
    std::fs::remove_file(&stable).unwrap();
    symlink(&version2, &stable).unwrap();
    assert_eq!(
        fixture.run(&recipe),
        "v2:--resume:00000000-0000-4000-8000-000000000017\n"
    );
    assert_eq!(serde_json::to_string(&recipe).unwrap(), json);
    std::fs::remove_file(&stable).unwrap();
    assert!(known_safe_provider_login_shell_argv(&recipe, &fixture).is_none());
}

#[test]
fn malformed_bound_recipe_never_gets_execution_or_exact_resume_authority() {
    let fixture = Fixture::new();
    let executable = fixture.root.path().join("claude");
    Fixture::script(&executable, "#!/bin/sh\nexit 0\n");
    for (provider, params, path) in [
        (
            "unknown",
            vec!["--resume", "00000000-0000-4000-8000-000000000017"],
            executable.to_str().unwrap(),
        ),
        ("claude", vec!["--unreviewed"], executable.to_str().unwrap()),
        (
            "claude",
            vec!["--resume", "00000000-0000-4000-8000-000000000017"],
            "relative/claude",
        ),
        (
            "claude",
            vec!["--resume", "00000000-0000-4000-8000-000000000017"],
            "/invalid\0path",
        ),
    ] {
        let recipe = LaunchSpec::BoundProvider {
            launch_spec_id: provider.into(),
            params: params.into_iter().map(str::to_owned).collect(),
            executable: path.into(),
        };
        assert!(!crate::known_safe_provider_has_exact_resume(&recipe));
        assert!(known_safe_provider_login_shell_argv(&recipe, &fixture).is_none());
        assert_eq!(crate::canonical_launch_for_restart(&recipe), recipe);
    }
}

#[test]
fn legacy_known_safe_and_custom_recipe_roundtrips_are_unchanged() {
    for json in [
        r#"{"tier":"known_safe","launch_spec_id":"claude","params":["--resume","00000000-0000-4000-8000-000000000017"]}"#,
        r#"{"tier":"ad_hoc_redacted","argv":["/custom/wrapper","private-mode"],"redacted":false,"restart_requires_user":true}"#,
        r#"{"tier":"opt_out"}"#,
    ] {
        let recipe: LaunchSpec = serde_json::from_str(json).unwrap();
        assert_eq!(serde_json::to_string(&recipe).unwrap(), json);
    }
}

#[test]
fn fresh_provider_audit_executes_only_the_sealed_first_launch_and_never_grants_replay() {
    let fixture = Fixture::new();
    let locator = fixture.root.path().join("renamed stable wrapper 'v2'");
    let version1 = fixture.root.path().join("versions/provider-v1");
    let version2 = fixture.root.path().join("versions/provider-v2");
    Fixture::script(&version1, "#!/bin/sh\nprintf 'old-version'\n");
    Fixture::script(&version2, "#!/bin/sh\nprintf 'first-launch'\n");
    symlink(&version1, &locator).unwrap();
    for provider in [
        "claude", "codex", "gemini", "opencode", "agy", "kimi", "kiro-cli", "agent", "amp",
        "devin", "droid",
    ] {
        let mut source = vec![provider.to_string()];
        if provider == "kiro-cli" {
            source.push("chat".into());
        }
        let selected = crate::ProviderExecutable::new(provider.into(), locator.clone());
        let environment = crate::SelectedProviderLaunchEnv {
            env: &fixture,
            selected: Some(&selected),
        };
        let prepared = crate::PreparedWorkspace::unsealed(
            crate::WorkspacePolicy::ScratchCwd,
            "ws",
            "session",
            fixture.root.path(),
        );
        let (params, audit, _, _) = prepared
            .provider_session_spec(provider, &source, &environment, 80, 24, 1)
            .unwrap_or_else(|error| panic!("fresh provider {provider}: {error:?}"))
            .into_parts();
        assert_eq!(params.launch, audit);
        assert_eq!(
            audit.fresh_provider_audit(),
            Some((provider, &source[1..], locator.to_str().unwrap()))
        );
        assert!(audit.provider_recipe().is_none());
        assert!(!crate::known_safe_provider_has_exact_resume(&audit));
        assert_eq!(crate::canonical_launch_for_restart(&audit), audit);
        assert!(known_safe_provider_login_shell_argv(&audit, &environment).is_none());
        if provider == "claude" {
            std::fs::remove_file(&locator).unwrap();
            symlink(&version2, &locator).unwrap();
        }
        let output = std::process::Command::new(&params.command)
            .args(&params.args)
            .env_clear()
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(output.stdout, b"first-launch");
    }
    for params in [
        vec!["resume".into(), "--last".into()],
        vec!["--secret-token".into(), "synthetic".into()],
    ] {
        let invalid = LaunchSpec::FreshProvider {
            launch_spec_id: "codex".into(),
            params,
            executable: locator.to_str().unwrap().into(),
        };
        assert!(invalid.fresh_provider_audit().is_none());
        assert!(invalid.provider_recipe().is_none());
        assert!(known_safe_provider_login_shell_argv(&invalid, &fixture).is_none());
    }
    for (provider, executable) in [
        ("unknown-provider", locator.to_str().unwrap()),
        ("codex", "relative/launcher"),
        ("codex", "/invalid\0launcher"),
    ] {
        let invalid = LaunchSpec::FreshProvider {
            launch_spec_id: provider.into(),
            params: vec![],
            executable: executable.into(),
        };
        assert!(invalid.fresh_provider_audit().is_none());
        assert!(known_safe_provider_login_shell_argv(&invalid, &fixture).is_none());
    }
}

#[test]
fn fresh_provider_audit_is_durable_downgrade_safe_and_not_an_existing_start() {
    use crate::{
        store, AppPaths, ExistingSessionStart, NewProject, ProjectService, RecordKind,
        SessionRecord, Workspace, WorkspacePolicy,
    };
    let fixture = Fixture::new();
    let paths = AppPaths::with_base(fixture.root.path().join("profile"));
    let cwd = fixture.root.path().to_str().unwrap();
    ProjectService::new(&paths)
        .create("project", "Fixture", cwd, NewProject::default(), 1)
        .unwrap();
    let Some(store::LoadOutcome::Loaded(project)) =
        store::load_one::<crate::Project>(&paths, RecordKind::Project, "project").unwrap()
    else {
        panic!()
    };
    let workspace = Workspace {
        workspace_id: "workspace".into(),
        project_id: "project".into(),
        root: cwd.into(),
        policy: WorkspacePolicy::ScratchCwd,
        consent: Default::default(),
    };
    store::write_record(&paths, RecordKind::Workspace, "workspace", 1, &workspace).unwrap();
    let locator = fixture.root.path().join("stable-codex");
    Fixture::script(&locator, "#!/bin/sh\nexit 0\n");
    let selected = crate::ProviderExecutable::new("codex".into(), locator.clone());
    let env = crate::SelectedProviderLaunchEnv {
        env: &fixture,
        selected: Some(&selected),
    };
    let prepared = crate::PreparedWorkspace::unsealed(
        workspace.policy,
        "workspace",
        "session",
        fixture.root.path(),
    );
    let spec = prepared
        .provider_session_spec("codex", &["codex".into()], &env, 80, 24, 2)
        .unwrap();
    let start = crate::WindowLayoutService::new(&paths)
        .prepare_unplaced_session_with_spec(&project, &workspace, spec)
        .unwrap();
    assert_eq!(start.unknown().launch, *start.publication_launch());
    let Some(store::LoadOutcome::Loaded(reloaded)) =
        store::load_one::<SessionRecord>(&paths, RecordKind::Session, "session").unwrap()
    else {
        panic!()
    };
    assert_eq!(&reloaded, start.unknown());
    assert_eq!(
        reloaded.launch.fresh_provider_audit().unwrap().2,
        locator.to_str().unwrap()
    );
    #[derive(serde::Deserialize)]
    #[serde(tag = "tier", rename_all = "snake_case")]
    enum PreviousLaunch {
        KnownSafe {},
        BoundProvider {},
        AdHocRedacted {},
        OptOut,
    }
    #[derive(serde::Deserialize)]
    struct PreviousSession {
        #[serde(rename = "launch")]
        _launch: PreviousLaunch,
    }
    assert!(matches!(
        store::load_one::<PreviousSession>(&paths, RecordKind::Session, "session").unwrap(),
        Some(store::LoadOutcome::Quarantined { .. })
    ));
    let mut exited = reloaded.clone();
    exited.status = crate::SessionStatus::Exited;
    exited.last_known_generation = Some("previous-generation".into());
    assert!(ExistingSessionStart::known_safe_exact(&exited, &workspace, &env, 80, 24, 3).is_err());
    assert!(ExistingSessionStart::known_safe_explicit_user_restart(
        &exited, &workspace, &env, 80, 24, 3
    )
    .is_err());
    let Some(store::LoadOutcome::Loaded(after)) =
        store::load_one::<SessionRecord>(&paths, RecordKind::Session, "session").unwrap()
    else {
        panic!()
    };
    assert_eq!(
        after, reloaded,
        "downgraded reads and restart refusal cannot rewrite the audit"
    );
}

#[test]
fn sqlite_reloaded_session_derives_restart_from_bound_locator_and_refuses_missing_locator() {
    use crate::{
        store, AppPaths, ExistingSessionStart, NewProject, ProjectService, RecordKind, SessionKind,
        SessionRecord, SessionStatus, Workspace, WorkspacePolicy,
    };
    let mut fixture = Fixture::new();
    let paths = AppPaths::with_base(fixture.root.path().join("profile"));
    let cwd = fixture.root.path().to_str().unwrap();
    ProjectService::new(&paths)
        .create("project", "Fixture", cwd, NewProject::default(), 1)
        .unwrap();
    let workspace = Workspace {
        workspace_id: "workspace".into(),
        project_id: "project".into(),
        root: cwd.into(),
        policy: WorkspacePolicy::ScratchCwd,
        consent: Default::default(),
    };
    store::write_record(&paths, RecordKind::Workspace, "workspace", 1, &workspace).unwrap();
    let stable = fixture.root.path().join("stable-claude");
    Fixture::script(&stable, "#!/bin/sh\nprintf 'bound:%s:%s' \"$1\" \"$2\"\n");
    let session = SessionRecord {
        session_id: "session".into(),
        workspace_id: "workspace".into(),
        kind: SessionKind::Agent,
        launch: fixture.recipe(&stable),
        cwd_resolved: cwd.into(),
        agent_task_id: None,
        created_at_ms: 1,
        last_attached_at_ms: 2,
        last_known_generation: Some("old-generation".into()),
        status: SessionStatus::Exited,
    };
    store::write_record(&paths, RecordKind::Session, "session", 2, &session).unwrap();
    let Some(store::LoadOutcome::Loaded(reloaded)) =
        store::load_one::<SessionRecord>(&paths, RecordKind::Session, "session").unwrap()
    else {
        panic!("durable bound session not readable")
    };
    assert_eq!(reloaded, session);
    // Model the previous reader's tagged enum: unknown bound recipes must be
    // excluded, not silently downgraded to PATH-based KnownSafe execution.
    #[derive(serde::Deserialize)]
    #[serde(tag = "tier", rename_all = "snake_case")]
    enum LegacyLaunch {
        KnownSafe {},
        AdHocRedacted {},
        OptOut,
    }
    #[derive(serde::Deserialize)]
    struct LegacySession {
        #[serde(rename = "launch")]
        _launch: LegacyLaunch,
    }
    assert!(matches!(
        store::load_one::<LegacySession>(&paths, RecordKind::Session, "session").unwrap(),
        Some(store::LoadOutcome::Quarantined { .. })
    ));
    Fixture::script(
        &fixture.root.path().join("other/claude"),
        "#!/bin/sh\nprintf 'WRONG'\n",
    );
    fixture.path = fixture.root.path().join("other").into_os_string();
    for start in [
        ExistingSessionStart::known_safe_exact(&reloaded, &workspace, &fixture, 80, 24, 3).unwrap(),
        ExistingSessionStart::known_safe_explicit_user_restart(
            &reloaded, &workspace, &fixture, 80, 24, 3,
        )
        .unwrap(),
    ] {
        let params = start.params();
        assert_eq!(params.launch, reloaded.launch);
        let output = std::process::Command::new(&params.command)
            .args(&params.args)
            .current_dir(&params.cwd)
            .env_clear()
            .env("PATH", &fixture.path)
            .output()
            .unwrap();
        assert!(output.status.success());
        assert_eq!(
            output.stdout,
            b"bound:--resume:00000000-0000-4000-8000-000000000017"
        );
    }
    std::fs::remove_file(stable).unwrap();
    assert!(
        ExistingSessionStart::known_safe_exact(&reloaded, &workspace, &fixture, 80, 24, 4).is_err()
    );
    assert!(ExistingSessionStart::known_safe_explicit_user_restart(
        &reloaded, &workspace, &fixture, 80, 24, 4
    )
    .is_err());
    let Some(store::LoadOutcome::Loaded(after)) =
        store::load_one::<SessionRecord>(&paths, RecordKind::Session, "session").unwrap()
    else {
        panic!()
    };
    assert_eq!(
        after, session,
        "refusal must leave durable session and conversation untouched"
    );
}
