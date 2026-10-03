use super::*;

const PERMISSION: &str = include_str!("../tests/fixtures/codex/0.159.2/permission.json");
const WORKING: &str = include_str!("../tests/fixtures/codex/0.159.2/working.json");
const IDLE: &str = include_str!("../tests/fixtures/codex/0.159.2/idle.json");

fn classify(fixture: &str) -> ProviderAttentionObservation {
    let rows: Vec<String> = serde_json::from_str(fixture).unwrap();
    assert_eq!(rows.len(), 37);
    classify_codex_grid(&rows.iter().map(String::as_str).collect::<Vec<_>>())
}

#[test]
fn recorded_codex_permission_panel_is_waiting() {
    assert_eq!(classify(PERMISSION), ProviderAttentionObservation::Waiting);
}

#[test]
fn changing_highlighted_codex_approval_choice_does_not_change_waiting_truth() {
    for choice in ["2. Yes,", "3. No,"] {
        let rows: Vec<String> = serde_json::from_str(PERMISSION).unwrap();
        let rows = rows
            .into_iter()
            .map(|row| {
                let row = row.replacen("› 1.", "  1.", 1);
                if row.trim_start().starts_with(choice) {
                    format!("› {}", row.trim())
                } else {
                    row
                }
            })
            .collect::<Vec<_>>();
        assert_eq!(
            classify_codex_grid(&rows.iter().map(String::as_str).collect::<Vec<_>>()),
            ProviderAttentionObservation::Waiting
        );
    }
}

#[test]
fn recorded_codex_work_and_idle_are_positive_recovery_not_task_completion() {
    assert_eq!(classify(WORKING), ProviderAttentionObservation::Working);
    assert_eq!(classify(IDLE), ProviderAttentionObservation::Idle);
}

#[test]
fn genuine_idle_transcript_saying_approval_pending_is_not_waiting() {
    assert!(IDLE.contains("approval request is still pending"));
    assert_eq!(classify(IDLE), ProviderAttentionObservation::Idle);
}

#[test]
fn incomplete_or_changed_codex_approval_panel_stays_unknown() {
    for text in [
        "Would you like to run the following command?",
        "Environment: local",
        "Reason:",
        "$ /usr/bin/printf",
        "1. Yes, proceed (y)",
        "2. Yes, and don't ask again for commands that start with",
        "3. No, and tell Codex what to do differently (esc)",
        "Press enter to confirm or esc to cancel",
    ] {
        assert!(PERMISSION.contains(text), "{text}");
        assert_eq!(
            classify(&PERMISSION.replace(text, "changed")),
            ProviderAttentionObservation::Unknown,
            "{text}"
        );
    }
}

#[test]
fn quoted_codex_panel_above_live_composer_does_not_request_input() {
    let mut rows: Vec<String> = serde_json::from_str(PERMISSION).unwrap();
    let idle: Vec<String> = serde_json::from_str(IDLE).unwrap();
    rows.extend(idle[idle.len() - 4..].iter().cloned());
    assert_ne!(
        classify_codex_grid(&rows.iter().map(String::as_str).collect::<Vec<_>>()),
        ProviderAttentionObservation::Waiting
    );
}

#[test]
fn opencode_panel_unknown_and_oversized_rows_cannot_be_codex_waits() {
    let rows: Vec<String> = serde_json::from_str(include_str!(
        "../tests/fixtures/opencode/1.18.23/permission.json"
    ))
    .unwrap();
    assert_eq!(
        classify_codex_grid(&rows.iter().map(String::as_str).collect::<Vec<_>>()),
        ProviderAttentionObservation::Unknown
    );
    assert_eq!(
        classify_codex_grid(&["unrecognized provider output"]),
        ProviderAttentionObservation::Unknown
    );
    assert_eq!(
        classify_codex_grid(&vec![""; 257]),
        ProviderAttentionObservation::Unknown
    );
    assert_eq!(
        classify_codex_grid(&[&"x".repeat(65537)]),
        ProviderAttentionObservation::Unknown
    );
}
