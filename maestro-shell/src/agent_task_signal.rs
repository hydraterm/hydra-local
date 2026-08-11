//! The pure decision helper for reliable `WaitingOnUser` / `Blocked` detection.
//!
//! Agent-task state detection is deliberately conservative: a task only
//! changes state because a trusted local caller explicitly asserted it for a specific task. There is
//! **no** arbitrary terminal-text classification, no daemon, no filesystem, no process, and no
//! renderer here — this module is a pure function over already-gathered local evidence, so the one
//! genuinely new "what is allowed to decide a transition" surface is exhaustively unit-testable in
//! isolation.
//!
//! Persistence is NOT done here: a caller maps a returned [`TaskStateSignal`] to the existing
//! `AgentTaskService::mark_waiting_on_user` / `mark_blocked` (or, for `NoChange`, to no write).

use crate::records::AgentTaskState;

/// An explicit, trusted-local assertion that a specific task is waiting on the user or blocked.
///
/// This is the ONLY thing that can move a task to `WaitingOnUser` / `Blocked`.
/// It is a caller intent, never inferred from terminal output, process exit, or a dead session.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskStateAssertion {
    /// The caller asserts the named task is waiting on the user, with a short human reason.
    WaitingOnUser { reason: String },
    /// The caller asserts the named task is blocked, with a short human reason.
    Blocked { reason: String },
}

/// The already-gathered local evidence the classifier decides over.
///
/// `current_state` is the task's durable state as loaded from `AgentTaskService`. `assertion` is the
/// caller's explicit intent for THIS invocation, or `None` when nothing was asserted. The type holds
/// only explicit local inputs — it intentionally models no arbitrary terminal text, because the
/// service does not classify text at all.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskStateEvidence {
    pub current_state: AgentTaskState,
    pub assertion: Option<TaskStateAssertion>,
}

/// The classifier's decision. `NoChange` carries a short machine reason for the caller to echo (it
/// never maps to a write); the other two map to the matching existing `mark_*` transition.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskStateSignal {
    /// No transition: perform no write, preserve `updated_at_ms`. `reason` explains why.
    NoChange { reason: String },
    /// Move `Running -> WaitingOnUser`, carrying the caller's reason forward for echoing.
    WaitingOnUser { reason: String },
    /// Move `Running -> Blocked`, carrying the caller's reason forward for echoing.
    Blocked { reason: String },
}

/// Classify already-gathered local evidence into a state signal.
///
/// Pure: no filesystem, no daemon, no process, no renderer, and no arbitrary text parsing.
///
/// A transition is returned ONLY when the task is currently `Running` and the matching explicit
/// assertion is present. Every other case is `NoChange`:
/// - no assertion at all;
/// - a `Draft` task (not started);
/// - a terminal task (`Succeeded` / `Failed` / `Cancelled`);
/// - an already-`WaitingOnUser` or already-`Blocked` task (idempotent, no churn);
///
/// so a transition is never inferred from output, process exit, or a dead/exited session.
pub fn classify_task_signal(evidence: &TaskStateEvidence) -> TaskStateSignal {
    let Some(assertion) = &evidence.assertion else {
        return TaskStateSignal::NoChange {
            reason: "no assertion".to_string(),
        };
    };

    if evidence.current_state != AgentTaskState::Running {
        return TaskStateSignal::NoChange {
            reason: format!(
                "task is not Running (current: {:?}); only a Running task may transition",
                evidence.current_state
            ),
        };
    }

    match assertion {
        TaskStateAssertion::WaitingOnUser { reason } => TaskStateSignal::WaitingOnUser {
            reason: reason.clone(),
        },
        TaskStateAssertion::Blocked { reason } => TaskStateSignal::Blocked {
            reason: reason.clone(),
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn evidence(
        current_state: AgentTaskState,
        assertion: Option<TaskStateAssertion>,
    ) -> TaskStateEvidence {
        TaskStateEvidence {
            current_state,
            assertion,
        }
    }

    #[test]
    fn waiting_assertion_on_running_transitions() {
        let signal = classify_task_signal(&evidence(
            AgentTaskState::Running,
            Some(TaskStateAssertion::WaitingOnUser {
                reason: "needs approval".to_string(),
            }),
        ));
        assert_eq!(
            signal,
            TaskStateSignal::WaitingOnUser {
                reason: "needs approval".to_string()
            }
        );
    }

    #[test]
    fn blocked_assertion_on_running_transitions() {
        let signal = classify_task_signal(&evidence(
            AgentTaskState::Running,
            Some(TaskStateAssertion::Blocked {
                reason: "missing credential".to_string(),
            }),
        ));
        assert_eq!(
            signal,
            TaskStateSignal::Blocked {
                reason: "missing credential".to_string()
            }
        );
    }

    #[test]
    fn missing_assertion_is_no_change() {
        let signal = classify_task_signal(&evidence(AgentTaskState::Running, None));
        assert!(matches!(signal, TaskStateSignal::NoChange { .. }));
    }

    #[test]
    fn draft_is_no_change_even_with_assertion() {
        let signal = classify_task_signal(&evidence(
            AgentTaskState::Draft,
            Some(TaskStateAssertion::WaitingOnUser {
                reason: "r".to_string(),
            }),
        ));
        assert!(matches!(signal, TaskStateSignal::NoChange { .. }));
    }

    #[test]
    fn terminal_states_are_no_change() {
        for state in [
            AgentTaskState::Succeeded,
            AgentTaskState::Failed,
            AgentTaskState::Cancelled,
        ] {
            let signal = classify_task_signal(&evidence(
                state,
                Some(TaskStateAssertion::Blocked {
                    reason: "r".to_string(),
                }),
            ));
            assert!(
                matches!(signal, TaskStateSignal::NoChange { .. }),
                "{state:?} must be NoChange"
            );
        }
    }

    #[test]
    fn already_waiting_is_no_change() {
        let signal = classify_task_signal(&evidence(
            AgentTaskState::WaitingOnUser,
            Some(TaskStateAssertion::WaitingOnUser {
                reason: "r".to_string(),
            }),
        ));
        assert!(matches!(signal, TaskStateSignal::NoChange { .. }));
    }

    #[test]
    fn already_blocked_is_no_change() {
        let signal = classify_task_signal(&evidence(
            AgentTaskState::Blocked,
            Some(TaskStateAssertion::Blocked {
                reason: "r".to_string(),
            }),
        ));
        assert!(matches!(signal, TaskStateSignal::NoChange { .. }));
    }
}
