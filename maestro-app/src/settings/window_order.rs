//! Profile-wide presentation order. Project ownership and activation never write this vector.

use super::*;
use maestro_shell::{AppPaths, DashboardSnapshot, DashboardSnapshotService, RecordKind};
use std::collections::{HashMap, HashSet};

/// Apply saved presentation order to an already observed dashboard, without writing preferences
/// or records. Project hierarchy/recency and each window's pane order remain unchanged. The
/// returned cross-project order contains only observed IDs; absent saved IDs stay on disk.
/// Unseen windows follow the observed legacy order until an explicit order save includes them.
pub fn apply_window_presentation_order(
    paths: &AppPaths,
    snapshot: &mut DashboardSnapshot,
) -> Vec<String> {
    let observed: Vec<String> = snapshot
        .projects
        .iter()
        .flat_map(|project| project.windows.iter())
        .chain(snapshot.unassigned_windows.iter())
        .map(|window| window.window_id.clone())
        .collect();
    let saved = match load_persisted(&settings_file_path(paths.base())) {
        LoadedSettings::Honored(settings) => settings.global_window_order,
        LoadedSettings::Absent => None,
        LoadedSettings::Warn(message) => {
            eprintln!("window presentation order: {message}");
            None
        }
    };
    let Some(saved) = saved else {
        return observed;
    };
    if let Err(error) = validate_ids(paths, &saved) {
        eprintln!(
            "window presentation order: invalid saved order: {}",
            error.message
        );
        return observed;
    }
    let observed_ids: HashSet<&str> = observed.iter().map(String::as_str).collect();
    let mut order: Vec<String> = saved
        .into_iter()
        .filter(|id| observed_ids.contains(id.as_str()))
        .collect();
    let mut known: HashSet<String> = order.iter().cloned().collect();
    order.extend(observed.into_iter().filter(|id| known.insert(id.clone())));
    let ranks: HashMap<&str, usize> = order
        .iter()
        .enumerate()
        .map(|(rank, id)| (id.as_str(), rank))
        .collect();
    for project in &mut snapshot.projects {
        project
            .windows
            .sort_by_key(|window| ranks[window.window_id.as_str()]);
    }
    snapshot
        .unassigned_windows
        .sort_by_key(|window| ranks[window.window_id.as_str()]);
    order
}

#[derive(Debug, PartialEq, Eq, Serialize)]
pub struct WindowOrderSuccess {
    pub ok: bool,
    pub command: &'static str,
    pub changed: bool,
    /// Currently observed windows in the saved global order; absent entries stay on disk.
    pub window_order: Vec<String>,
}

/// Reorder a nonempty current subset within its global slots. Unmentioned, hidden, stashed and
/// temporarily absent windows retain their positions. This is JSON presentation metadata only:
/// it never changes Project.window_order, window owners, panes, session identities or epochs.
///
/// Settings lock precedes snapshot reads and stays through atomic save. No SQLite lock is held
/// during JSON I/O. The snapshot is an observation, not a cross-store transaction: a concurrent
/// create is appended on its next observation, and a disappearing ID cannot resurrect a record.
pub fn reorder_window_presentation(
    paths: &AppPaths,
    requested: &[String],
) -> Result<WindowOrderSuccess, SettingsFailure> {
    if requested.is_empty() {
        return Err(SettingsFailure::new(
            "bad_usage",
            "window order must not be empty",
        ));
    }
    let requested_ids = validate_ids(paths, requested)?;
    let writer = writer::SettingsWriteGuard::acquire(paths.base())?;
    let mut next = match load_persisted(&settings_file_path(paths.base())) {
        LoadedSettings::Absent => default_persisted(),
        LoadedSettings::Honored(existing) => existing,
        LoadedSettings::Warn(message) => {
            return Err(SettingsFailure::new("settings_conflict", message));
        }
    };
    if let Some(saved) = &next.global_window_order {
        validate_ids(paths, saved).map_err(|error| {
            SettingsFailure::new(
                "settings_conflict",
                format!("saved window order is invalid: {}", error.message),
            )
        })?;
    }
    let snapshot = DashboardSnapshotService::new(paths)
        .snapshot(None)
        .map_err(|error| SettingsFailure::new("window_order_failed", error.to_string()))?;
    let observed: Vec<String> = snapshot
        .projects
        .iter()
        .flat_map(|project| project.windows.iter())
        .chain(snapshot.unassigned_windows.iter())
        .map(|window| window.window_id.clone())
        .collect();
    let observed_ids = validate_ids(paths, &observed)?;
    if !requested_ids.is_subset(&observed_ids) {
        return Err(SettingsFailure::new(
            "window_order_stale",
            "a requested window no longer exists in the current window snapshot",
        ));
    }
    let mut order = next
        .global_window_order
        .clone()
        .unwrap_or_else(|| observed.clone());
    let mut known: HashSet<String> = order.iter().cloned().collect();
    order.extend(
        observed
            .iter()
            .filter(|id| known.insert((*id).clone()))
            .cloned(),
    );
    let mut replacements = requested.iter();
    for id in &mut order {
        if requested_ids.contains(id.as_str()) {
            *id = replacements
                .next()
                .expect("validated unique subset has one slot per id")
                .clone();
        }
    }
    let changed = next.global_window_order.as_ref() != Some(&order);
    if changed {
        next.global_window_order = Some(order.clone());
        write_settings_atomic(paths.base(), &next, &writer)
            .map_err(|error| SettingsFailure::new("io_error", error))?;
    }
    Ok(WindowOrderSuccess {
        ok: true,
        command: "window reorder",
        changed,
        window_order: order
            .into_iter()
            .filter(|id| observed_ids.contains(id.as_str()))
            .collect(),
    })
}

fn validate_ids<'a>(
    paths: &AppPaths,
    ids: &'a [String],
) -> Result<HashSet<&'a str>, SettingsFailure> {
    let mut unique = HashSet::new();
    for id in ids {
        paths
            .record_path(RecordKind::WindowLayout, id)
            .map_err(|error| SettingsFailure::new("bad_usage", error.to_string()))?;
        if !unique.insert(id.as_str()) {
            return Err(SettingsFailure::new(
                "bad_usage",
                "duplicate window id in requested order",
            ));
        }
    }
    Ok(unique)
}

#[cfg(test)]
mod tests;
