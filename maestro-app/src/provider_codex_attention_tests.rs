use super::*;
use maestro_shell::{LaunchSpec, SessionKind};

const WAIT: &str = include_str!("../../maestro-shell/tests/fixtures/codex/0.159.2/permission.json");
const WORK: &str = include_str!("../../maestro-shell/tests/fixtures/codex/0.159.2/working.json");
const IDLE: &str = include_str!("../../maestro-shell/tests/fixtures/codex/0.159.2/idle.json");

fn launches() -> [LaunchSpec; 3] {
    [
        LaunchSpec::KnownSafe {
            launch_spec_id: "codex".into(),
            params: vec![],
        },
        LaunchSpec::BoundProvider {
            launch_spec_id: "codex".into(),
            params: vec![
                "resume".into(),
                "11111111-1111-4111-8111-111111111111".into(),
            ],
            executable: "/synthetic/stable-provider-wrapper".into(),
        },
        LaunchSpec::FreshProvider {
            launch_spec_id: "codex".into(),
            params: vec!["--model".into(), "gpt-6-luna".into()],
            executable: "/synthetic/stable-provider-wrapper".into(),
        },
    ]
}

fn record(launch: LaunchSpec) -> SessionRecord {
    SessionRecord {
        session_id: "s".into(),
        workspace_id: "w".into(),
        kind: SessionKind::Agent,
        launch,
        cwd_resolved: "/synthetic".into(),
        agent_task_id: None,
        created_at_ms: 1,
        last_attached_at_ms: 1,
        last_known_generation: Some("g".into()),
        status: SessionStatus::Live,
    }
}

#[test]
fn codex_known_bound_and_fresh_records_observe_real_rows_and_never_write_task_state() {
    for launch in launches() {
        for recovery in [WORK, IDLE] {
            integration_tests::recorded_prompt_recovery_for_launch(WAIT, recovery, launch.clone());
        }
    }
}

#[test]
fn exact_codex_identity_is_not_a_shell_argument_wrapper_basename_or_capture_option() {
    for launch in launches() {
        let mut record = record(launch);
        assert_eq!(eligible(&record, "g"), Some(ObservedProvider::Codex));
        assert_eq!(eligible(&record, "stale"), None);
        record.status = SessionStatus::Exited;
        assert_eq!(eligible(&record, "g"), None);
        assert!(
            !eligible_exit(&record, "g"),
            "Codex error inference remains out of scope"
        );
    }
    for launch in [
        LaunchSpec::KnownSafe {
            launch_spec_id: "bash".into(),
            params: vec!["-c".into(), "codex".into()],
        },
        LaunchSpec::KnownSafe {
            launch_spec_id: "codex".into(),
            params: vec!["--no-daemon".into()],
        },
        LaunchSpec::KnownSafe {
            launch_spec_id: "codex".into(),
            params: vec!["--model".into()],
        },
        LaunchSpec::AdHocRedacted {
            argv: vec!["codex".into()],
            redacted: false,
            restart_requires_user: true,
        },
        LaunchSpec::BoundProvider {
            launch_spec_id: "codex".into(),
            params: vec!["resume".into()],
            executable: "/synthetic/codex".into(),
        },
    ] {
        assert_eq!(eligible(&record(launch), "g"), None);
    }
}

#[test]
fn provider_replacement_with_same_generation_cannot_inherit_waiting_state() {
    let mut state = Broker::default();
    accept(
        &mut state.signals,
        "s".into(),
        "g".into(),
        ObservedProvider::OpenCode,
        5,
        Observation::Waiting,
        10,
    );
    next_batch(
        &mut state,
        BTreeMap::from([(
            "s".into(),
            ProviderLifetime {
                provider: ObservedProvider::Codex,
                generation: "g".into(),
            },
        )]),
    );
    assert!(state.signals.is_empty());
    accept(
        &mut state.signals,
        "s".into(),
        "g".into(),
        ObservedProvider::Codex,
        6,
        Observation::Waiting,
        20,
    );
    accept(
        &mut state.signals,
        "s".into(),
        "g".into(),
        ObservedProvider::OpenCode,
        7,
        Observation::Unknown,
        30,
    );
    assert_eq!(state.signals["s"].waiting_since, None);
}
