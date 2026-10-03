//! Listener-local feedback correlation. Tracking never cancels children or changes their logs.
use crate::plugins::ActionUpdate;
use std::collections::BTreeMap;

#[derive(Default)]
pub struct PluginInvocations {
    generation: u64,
    next: u64,
    latest: BTreeMap<String, u64>,
}

impl PluginInvocations {
    pub fn begin(&mut self, generation: u64, action_id: &str) -> u64 {
        if self.generation != generation {
            self.latest.clear();
            self.generation = generation;
        }
        self.next = self.next.wrapping_add(1);
        self.latest.insert(action_id.to_owned(), self.next);
        self.next
    }

    pub fn accepts(&self, update: &ActionUpdate) -> bool {
        update.generation == self.generation
            && self.latest.get(&update.action_id) == Some(&update.invocation)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn update(generation: u64, invocation: u64, action_id: &str, text: &str) -> ActionUpdate {
        ActionUpdate {
            generation,
            invocation,
            action_id: action_id.into(),
            text: text.into(),
        }
    }

    #[test]
    fn late_first_completion_cannot_replace_second_running_or_completed_status() {
        let mut runs = PluginInvocations::default();
        let action = "plugin:example:run";
        let first = runs.begin(7, action);
        assert!(runs.accepts(&update(7, first, action, "running; log first")));
        let second = runs.begin(7, action);
        assert_ne!(first, second);
        let mut visible = String::new();
        // Deterministic delivery order: new run starts, old run finishes, new run finishes.
        for message in [
            update(7, second, action, "running; log second"),
            update(7, first, action, "exited; log first"),
        ] {
            if runs.accepts(&message) {
                visible = message.text;
            }
        }
        assert_eq!(visible, "running; log second");
        let completed = update(7, second, action, "exited; log second");
        assert!(runs.accepts(&completed));
        visible = completed.text;
        assert!(!runs.accepts(&update(7, first, action, "delayed first status")));
        assert_eq!(visible, "exited; log second");
    }

    #[test]
    fn other_actions_remain_independent_and_new_palette_rejects_old_runs() {
        let mut runs = PluginInvocations::default();
        let first = runs.begin(1, "plugin:example:first");
        let second = runs.begin(1, "plugin:example:second");
        assert!(runs.accepts(&update(1, first, "plugin:example:first", "finished")));
        assert!(runs.accepts(&update(1, second, "plugin:example:second", "running")));
        let reopened = runs.begin(2, "plugin:example:first");
        assert!(!runs.accepts(&update(1, first, "plugin:example:first", "finished")));
        assert!(!runs.accepts(&update(
            2,
            first,
            "plugin:example:first",
            "wrong invocation"
        )));
        assert!(runs.accepts(&update(2, reopened, "plugin:example:first", "running")));
    }
}
