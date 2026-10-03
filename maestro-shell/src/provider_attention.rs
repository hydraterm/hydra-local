//! Conservative, display-only observations of the current provider-owned terminal UI.
//! No history scan, raw VT parsing, task transition, launch restriction or completion inference.

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ProviderAttentionObservation {
    Waiting,
    Working,
    Idle,
    Unknown,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum ObservedProvider {
    OpenCode,
    Codex,
}

/// Narrow recorded Codex 0.159.2 UI observation; this never infers task completion.
pub fn classify_codex_grid(rows: &[&str]) -> ProviderAttentionObservation {
    use ProviderAttentionObservation::{Idle, Unknown, Waiting, Working};
    if rows.len() > 256 || rows.iter().map(|row| row.len()).sum::<usize>() > 64 * 1024 {
        return Unknown;
    }
    let rows = rows.iter().map(|row| row.trim()).collect::<Vec<_>>();
    let bottom = &rows[..];
    if bottom.last() == Some(&"Press enter to confirm or esc to cancel") {
        let Some(header) = bottom
            .iter()
            .rposition(|row| *row == "Would you like to run the following command?")
        else {
            return Unknown;
        };
        let panel = bottom[header + 1..]
            .iter()
            .map(|row| row.strip_prefix("› ").unwrap_or(row))
            .filter(|row| !row.is_empty())
            .collect::<Vec<_>>();
        // Commands/reasons may wrap, but all ordered provider actions and the actual bottom
        // confirmation footer must coexist. A transcript mention above the composer is not UI.
        let Some(yes) = panel.iter().position(|row| *row == "1. Yes, proceed (y)") else {
            return Unknown;
        };
        let before = &panel[..yes];
        let actions = &panel[yes..];
        return if before.first() == Some(&"Environment: local")
            && before.iter().any(|row| row.starts_with("Reason: "))
            && before.iter().any(|row| row.starts_with("$ "))
            && actions.get(1).is_some_and(|row| {
                row.starts_with("2. Yes, and don't ask again for commands that start with `")
            })
            && actions.len() >= 4
            && actions[actions.len() - 2] == "3. No, and tell Codex what to do differently (esc)"
            && actions.last() == Some(&"Press enter to confirm or esc to cancel")
        {
            Waiting
        } else {
            Unknown
        };
    }
    // Positive recovery requires the recorded bottom input composer and provider shortcut
    // footer, not assistant text claiming approval/completion. Other layouts stay unknown.
    if rows
        .last()
        .is_some_and(|row| row.starts_with("? for shortcuts"))
    {
        if let Some(composer) = rows
            .iter()
            .rposition(|row| *row == "› Ask Codex to do anything")
        {
            if rows.len() - composer == 4 {
                return if rows[composer.saturating_sub(5)..composer]
                    .iter()
                    .any(|row| row.starts_with("• Working (") && row.ends_with("esc to interrupt)"))
                {
                    Working
                } else {
                    Idle
                };
            }
        }
    }
    Unknown
}

#[cfg(test)]
#[path = "provider_attention_codex_tests.rs"]
mod codex_tests;

/// Classify only OpenCode's recorded UI structure, not words in its assistant transcript.
/// Unknown output never means success, and an idle input composer never finishes a Hydra task.
pub fn classify_opencode_grid(rows: &[&str]) -> ProviderAttentionObservation {
    use ProviderAttentionObservation::{Idle, Unknown, Waiting, Working};
    if rows.len() > 256 || rows.iter().map(|row| row.len()).sum::<usize>() > 64 * 1024 {
        return Unknown;
    }
    // The captured permission UI replaces the bottom input composer. Text quoting its labels in
    // the assistant body is not that UI. Require its border, exact header, tool heading, command,
    // and action row together in the current bottom panel, never a transcript-wide substring.
    let bottom = &rows[rows.len().saturating_sub(12)..];
    let panel = bottom
        .iter()
        .filter_map(|row| row.trim_start().strip_prefix('┃').map(str::trim))
        .collect::<Vec<_>>();
    if let Some(header) = panel
        .iter()
        .position(|line| *line == "△ Permission required")
    {
        let panel = &panel[header + 1..];
        let shell = panel.contains(&"# Shell command");
        let command = panel.iter().any(|line| line.starts_with("$ "));
        let actions = panel.iter().any(|line| {
            let words = line.split_whitespace().collect::<Vec<_>>().join(" ");
            words.starts_with("Allow once Allow always Reject ") && words.ends_with("enter confirm")
        });
        return if shell && command && actions {
            Waiting
        } else {
            Unknown
        };
    }
    // OpenCode 1.18.23's experimental plan_exit uses its own Question panel. Recognize only
    // this recorded approval, not arbitrary questions or a transcript mention of planning.
    // The disposable plan path can wrap, so join only the bordered bottom-panel prompt rows.
    if let Some(header) = panel.iter().position(|line| line.starts_with("Plan at ")) {
        let panel = &panel[header..];
        let Some(yes) = panel.iter().position(|line| *line == "1. Yes") else {
            return Unknown;
        };
        let prompt = panel[..yes].join(" ");
        let prompt = prompt.split_whitespace().collect::<Vec<_>>().join(" ");
        let actions = panel[yes..]
            .iter()
            .copied()
            .filter(|line| !line.is_empty())
            .collect::<Vec<_>>();
        return if prompt.ends_with(
            " is complete. Would you like to switch to the build agent and start implementing?",
        ) && actions
            == [
                "1. Yes",
                "Switch to build agent and start implementing the plan",
                "2. No",
                "Stay with plan agent to continue refining the plan",
                "↑↓ select  enter submit  esc dismiss",
            ] {
            Waiting
        } else {
            Unknown
        };
    }
    let composer = bottom.iter().any(|row| {
        row.trim_start().strip_prefix('┃').is_some_and(|body| {
            let body = body.trim_start();
            body.starts_with("Build · ") || body.starts_with("Plan · ")
        })
    });
    let divider = bottom.iter().any(|row| row.trim_start().starts_with("╹▀"));
    let footer = rows
        .iter()
        .rev()
        .take(3)
        .map(|row| row.split_whitespace().collect::<Vec<_>>().join(" "))
        .find(|row| row.contains("ctrl+p commands"));
    if composer && divider {
        if let Some(footer) = footer {
            return if footer.contains("esc interrupt") {
                Working
            } else {
                Idle
            };
        }
    }
    Unknown
}

#[cfg(test)]
mod tests {
    use super::*;

    const PERMISSION: &str = include_str!("../tests/fixtures/opencode/1.18.23/permission.json");
    const STREAMING: &str = include_str!("../tests/fixtures/opencode/1.18.23/streaming.json");
    const IDLE: &str = include_str!("../tests/fixtures/opencode/1.18.23/idle.json");
    const RESUMED: &str = include_str!("../tests/fixtures/opencode/1.18.23/resumed.json");
    const ERROR_UI: &str = include_str!("../tests/fixtures/opencode/1.18.23/error-ui.json");
    const LOOKALIKE: &str = include_str!("../tests/fixtures/opencode/1.18.23/lookalike.json");
    const PLAN_APPROVAL: &str =
        include_str!("../tests/fixtures/opencode/1.18.23/plan-approval.json");
    const PLAN_ACCEPTED: &str =
        include_str!("../tests/fixtures/opencode/1.18.23/plan-accepted.json");
    const PLAN_REJECTED: &str =
        include_str!("../tests/fixtures/opencode/1.18.23/plan-rejected.json");
    const PLAN_IDLE: &str = include_str!("../tests/fixtures/opencode/1.18.23/plan-idle.json");
    const PLAN_WORKING: &str = include_str!("../tests/fixtures/opencode/1.18.23/plan-working.json");

    fn classify(fixture: &str) -> ProviderAttentionObservation {
        let rows: Vec<String> = serde_json::from_str(fixture).unwrap();
        assert_eq!(rows.len(), 40, "recorded blank rows are preserved");
        classify_opencode_grid(&rows.iter().map(String::as_str).collect::<Vec<_>>())
    }

    #[test]
    fn real_recorded_permission_is_waiting() {
        assert_eq!(classify(PERMISSION), ProviderAttentionObservation::Waiting);
    }

    #[test]
    fn real_recorded_plan_exit_question_is_waiting() {
        assert_eq!(
            classify(PLAN_APPROVAL),
            ProviderAttentionObservation::Waiting
        );
    }

    #[test]
    fn real_recorded_plan_answers_and_normal_composer_recover_without_done() {
        for fixture in [PLAN_ACCEPTED, PLAN_REJECTED, PLAN_IDLE] {
            assert_eq!(classify(fixture), ProviderAttentionObservation::Idle);
        }
        assert_eq!(
            classify(PLAN_WORKING),
            ProviderAttentionObservation::Working
        );
    }

    #[test]
    fn changed_incomplete_or_transcript_plan_question_stays_unknown() {
        for (before, after) in [
            ("is complete.", "is incomplete."),
            ("1. Yes", "1. Maybe"),
            ("2. No", "2. Later"),
            (
                "Switch to build agent and start implementing the plan",
                "Unrecognized action",
            ),
            (
                "Stay with plan agent to continue refining the plan",
                "Unrecognized action",
            ),
            ("enter submit", "enter changed"),
        ] {
            assert_ne!(PLAN_APPROVAL, PLAN_APPROVAL.replace(before, after));
            assert_eq!(
                classify(&PLAN_APPROVAL.replace(before, after)),
                ProviderAttentionObservation::Unknown
            );
        }
        let mut rows: Vec<String> = serde_json::from_str(PLAN_APPROVAL).unwrap();
        rows.extend(vec![String::new(); 12]);
        assert_eq!(
            classify_opencode_grid(&rows.iter().map(String::as_str).collect::<Vec<_>>()),
            ProviderAttentionObservation::Unknown
        );
    }

    #[test]
    fn real_recorded_streaming_and_answer_recovery_are_working() {
        assert_eq!(classify(STREAMING), ProviderAttentionObservation::Working);
        assert_eq!(classify(RESUMED), ProviderAttentionObservation::Working);
    }

    #[test]
    fn real_idle_error_and_quoted_permission_labels_are_not_waiting_or_done() {
        for fixture in [IDLE, ERROR_UI, LOOKALIKE] {
            assert_eq!(classify(fixture), ProviderAttentionObservation::Idle);
        }
    }

    #[test]
    fn changed_prompt_fixture_breaks_the_recorded_waiting_contract() {
        let changed = PERMISSION.replace("Permission required", "Approval wording changed");
        assert_eq!(classify(&changed), ProviderAttentionObservation::Unknown);
        // Keeping the original fixture's expected Waiting state after this mutation is a failure.
        assert_ne!(classify(&changed), ProviderAttentionObservation::Waiting);
    }

    #[test]
    fn incomplete_or_unrelated_output_is_unknown() {
        for rows in [
            vec![],
            vec!["Permission required"],
            vec!["Allow once Allow always Reject"],
            vec!["a turn ended"],
        ] {
            assert_eq!(
                classify_opencode_grid(&rows),
                ProviderAttentionObservation::Unknown
            );
        }
    }

    #[test]
    fn oversized_observations_are_not_parsed() {
        assert_eq!(
            classify_opencode_grid(&vec![""; 257]),
            ProviderAttentionObservation::Unknown
        );
        let line = "x".repeat(64 * 1024 + 1);
        assert_eq!(
            classify_opencode_grid(&[&line]),
            ProviderAttentionObservation::Unknown
        );
    }
}
