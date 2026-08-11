//! Durable workspace-layout preset service.
//!
//! [`LayoutPresetService`] is a thin, store-backed manager over [`LayoutPreset`] records: it
//! CAPTURES a window's current tab/pane topology into a named, reopenable preset, LISTS the saved
//! presets (optionally scoped to a project), LOADS one by id, and DELETES one. It is the persist
//! half of "reopen a working arrangement without rebuilding tabs and panes by hand"; the restore
//! (revive into live sessions) half lives in the app, which owns the daemon/session model.
//!
//! Hard boundaries (matching the rest of the shell's records layer):
//!
//! - NO daemon/socket/PTY/git/renderer/UI. Records in, records out, under an injected [`AppPaths`].
//! - Capture COPIES layout position only (order/title/pin/split provenance) plus a best-effort
//!   `session_id` HINT per slot. It never asserts a session is live; keeping running-session
//!   identity separate from layout position is a safety requirement so restore cannot relabel or
//!   restart the wrong pane.
//! - Future-version and corrupt preset records are surfaced as typed errors
//!   ([`LayoutPresetError::FutureVersion`] / [`LayoutPresetError::Corrupt`]); the store leaves a
//!   future record byte-identical in place and quarantines a corrupt one.

use std::error::Error;
use std::fmt;
use std::path::PathBuf;

use crate::paths::{AppPaths, RecordKind};
use crate::records::{LayoutPreset, LayoutPresetTab, SplitFrom, WindowLayout};
use crate::store::{self, LoadOutcome, StoreError};

/// Errors from the layout-preset service.
#[derive(Debug)]
pub enum LayoutPresetError {
    /// A load/delete targeted a `preset_id` with no current-version record on disk.
    PresetNotFound { preset_id: String },
    /// `capture_from_window` was given a `preset_id` that already names a current-version record.
    /// Nothing is rewritten (capture never silently clobbers an existing preset).
    PresetAlreadyExists { preset_id: String },
    /// The on-disk preset was written by a newer schema version than this build understands. It is
    /// left byte-identical in place; surfaced so the caller can tell the user.
    FutureVersion { path: PathBuf, ours: u32, got: u32 },
    /// The on-disk preset failed validation and was quarantined by the store (bytes preserved at
    /// `moved_to`).
    Corrupt {
        original: PathBuf,
        moved_to: PathBuf,
        reason: String,
    },
    /// Underlying store IO / id-validation error (an unsafe `preset_id` is refused here before any
    /// path is built).
    Store(StoreError),
}

impl fmt::Display for LayoutPresetError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LayoutPresetError::PresetNotFound { preset_id } => {
                write!(f, "no layout preset for preset_id {preset_id:?}")
            }
            LayoutPresetError::PresetAlreadyExists { preset_id } => {
                write!(
                    f,
                    "layout preset already exists for preset_id {preset_id:?}"
                )
            }
            LayoutPresetError::FutureVersion { path, ours, got } => write!(
                f,
                "layout preset at {path:?} is schema version {got} (this build understands {ours})"
            ),
            LayoutPresetError::Corrupt {
                original,
                moved_to,
                reason,
            } => write!(
                f,
                "corrupt layout preset {original:?} quarantined to {moved_to:?}: {reason}"
            ),
            LayoutPresetError::Store(e) => write!(f, "store error: {e}"),
        }
    }
}

impl Error for LayoutPresetError {}

impl From<StoreError> for LayoutPresetError {
    fn from(e: StoreError) -> Self {
        LayoutPresetError::Store(e)
    }
}

/// Store-backed manager for an app's layout presets, over an injected [`AppPaths`].
pub struct LayoutPresetService<'a> {
    paths: &'a AppPaths,
}

impl<'a> LayoutPresetService<'a> {
    pub fn new(paths: &'a AppPaths) -> Self {
        LayoutPresetService { paths }
    }

    /// Capture `window`'s current tab topology into a NEW preset named `name`. The preset records
    /// each NON-stashed tab's layout position (index/title/pin/split provenance) and a best-effort
    /// `session_id` hint; stashed (dormant) tabs are skipped since a preset is a snapshot of the
    /// live arrangement. Slots are renumbered to a contiguous `0..n` run in capture order.
    ///
    /// Refuses to overwrite an existing current-version preset
    /// ([`LayoutPresetError::PresetAlreadyExists`]); a future/corrupt record is surfaced typed.
    pub fn capture_from_window(
        &self,
        preset_id: &str,
        name: &str,
        project_id: Option<&str>,
        window: &WindowLayout,
        now_ms: u64,
    ) -> Result<LayoutPreset, LayoutPresetError> {
        if self.load(preset_id)?.is_some() {
            return Err(LayoutPresetError::PresetAlreadyExists {
                preset_id: preset_id.to_string(),
            });
        }
        let tabs: Vec<LayoutPresetTab> = window
            .tabs
            .iter()
            .filter(|t| !t.stashed)
            .enumerate()
            .map(|(i, t)| LayoutPresetTab {
                index: i as u32,
                title: t.title.clone(),
                pinned: t.pinned,
                split_from: t.split_from.clone(),
                session_id: Some(t.session_id.clone()),
                source_tab_id: t.tab_id.clone(),
            })
            .collect();
        let preset = LayoutPreset {
            preset_id: preset_id.to_string(),
            name: name.to_string(),
            project_id: project_id.map(str::to_string),
            created_at_ms: now_ms,
            tabs,
        };
        self.write(&preset, now_ms)?;
        Ok(preset)
    }

    /// Load the current-version preset for `preset_id`.
    ///
    /// - `Ok(None)` — no record on disk yet.
    /// - `Ok(Some(preset))` — a valid current-version preset.
    /// - `Err(FutureVersion/Corrupt)` — surfaced typed (store left/quarantined the bytes).
    /// - `Err(Store(Id(_)))` — `preset_id` is unsafe for a path (refused before any IO).
    pub fn load(&self, preset_id: &str) -> Result<Option<LayoutPreset>, LayoutPresetError> {
        match store::load_one::<LayoutPreset>(self.paths, RecordKind::LayoutPreset, preset_id)? {
            None => Ok(None),
            Some(LoadOutcome::Loaded(preset)) => Ok(Some(preset)),
            Some(LoadOutcome::FutureVersion { path, ours, got }) => {
                Err(LayoutPresetError::FutureVersion { path, ours, got })
            }
            Some(LoadOutcome::Quarantined {
                original,
                moved_to,
                reason,
            }) => Err(LayoutPresetError::Corrupt {
                original,
                moved_to,
                reason,
            }),
        }
    }

    /// List all current-version presets, sorted newest-first by `created_at_ms` then `preset_id`
    /// (a stable tiebreak). When `project_id` is `Some`, only presets with that exact
    /// `project_id` are returned; when `None`, ALL presets (every project + unassigned) are
    /// returned. Future-version and corrupt records are SKIPPED (the store quarantines corrupt
    /// ones); a list never fails because one stored preset is unreadable.
    pub fn list(&self, project_id: Option<&str>) -> Result<Vec<LayoutPreset>, LayoutPresetError> {
        let mut presets: Vec<LayoutPreset> =
            store::load_all::<LayoutPreset>(self.paths, RecordKind::LayoutPreset)?
                .into_iter()
                .filter_map(|outcome| match outcome {
                    LoadOutcome::Loaded(preset) => Some(preset),
                    _ => None,
                })
                .filter(|preset| match project_id {
                    Some(want) => preset.project_id.as_deref() == Some(want),
                    None => true,
                })
                .collect();
        presets.sort_by(|a, b| {
            b.created_at_ms
                .cmp(&a.created_at_ms)
                .then_with(|| a.preset_id.cmp(&b.preset_id))
        });
        Ok(presets)
    }

    /// Delete the preset named by `preset_id`. Errors with [`LayoutPresetError::PresetNotFound`]
    /// if there is no current-version record (a future/corrupt record is surfaced typed rather
    /// than deleted, so a misread never destroys bytes).
    pub fn delete(&self, preset_id: &str) -> Result<(), LayoutPresetError> {
        if self.load(preset_id)?.is_none() {
            return Err(LayoutPresetError::PresetNotFound {
                preset_id: preset_id.to_string(),
            });
        }
        // Delete the row (presets have no children to cascade). PresetNotFound is already handled above, so a false
        // return here would only mean a concurrent delete — treat as done (idempotent).
        crate::store::delete_record(self.paths, RecordKind::LayoutPreset, preset_id)
            .map_err(LayoutPresetError::Store)?;
        Ok(())
    }

    fn write(&self, preset: &LayoutPreset, now_ms: u64) -> Result<(), LayoutPresetError> {
        store::write_record(
            self.paths,
            RecordKind::LayoutPreset,
            &preset.preset_id,
            now_ms,
            preset,
        )?;
        Ok(())
    }
}

/// How one preset slot should be brought back to life at restore time. The PLANNER decides this
/// purely from the slot's `session_id` hint vs. the set of currently-live sessions; the APP then
/// executes it through the daemon/session model (reattach a survivor, or launch a fresh session in
/// the same layout position). Keeping the two cases explicit enforces the invariant that
/// restoring a layout never relabels or restarts the WRONG pane.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PresetRestoreAction {
    /// The slot's hinted session is still live: reattach to it (no relaunch, identity preserved).
    Reattach { session_id: String },
    /// No live session backs this slot (no hint, or the hinted session is gone): launch a fresh
    /// session in this layout position.
    LaunchFresh,
}

/// One ordered step of a preset restore: which layout position (title/pin/split provenance, copied
/// from the preset) and how to back it (reattach vs. launch fresh). Pure data — no ids minted, no
/// IO. `split_from` references another slot by its preset-local `index`; the executor resolves that
/// to a freshly-minted `tab_id` as it walks the slots in order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresetRestoreSlot {
    /// Preset-local order/identity of this slot (matches [`LayoutPresetTab::index`]).
    pub index: u32,
    pub title: String,
    pub pinned: bool,
    pub split_from: Option<SplitFrom>,
    pub action: PresetRestoreAction,
}

/// Pure restore planner. Walks `preset.tabs` IN ORDER and, for each slot, decides
/// [`PresetRestoreAction::Reattach`] when the slot's best-effort `session_id` hint names a session
/// in `live_session_ids`, else [`PresetRestoreAction::LaunchFresh`]. NEVER mints ids, touches the
/// store, talks to the daemon, or mutates anything — the caller turns the slots into a launch
/// SEQUENCE. Layout position (title/pin/split provenance) is copied verbatim so the rebuilt
/// arrangement matches the captured one regardless of which slots reattach vs. relaunch.
pub fn plan_preset_restore(
    preset: &LayoutPreset,
    live_session_ids: &[String],
) -> Vec<PresetRestoreSlot> {
    preset
        .tabs
        .iter()
        .map(|tab| {
            let action = match tab.session_id.as_deref() {
                Some(sid) if live_session_ids.iter().any(|live| live == sid) => {
                    PresetRestoreAction::Reattach {
                        session_id: sid.to_string(),
                    }
                }
                _ => PresetRestoreAction::LaunchFresh,
            };
            PresetRestoreSlot {
                index: tab.index,
                title: tab.title.clone(),
                pinned: tab.pinned,
                split_from: tab.split_from.clone(),
                action,
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::records::{AttentionState, SplitAxis, TabRecord};
    use tempfile::TempDir;

    fn paths(dir: &TempDir) -> AppPaths {
        AppPaths::with_base(dir.path().join("Maestro"))
    }

    /// Persist a minimal parent Project so a preset carrying `project_id` doesn't violate the
    /// relational store's `layout_presets.project_id → projects` FK. `project_id` is NULLABLE, so
    /// only presets captured WITH a project need this (production always creates the project first).
    fn seed_project(paths: &AppPaths, id: &str) {
        crate::project::ProjectService::new(paths)
            .create(id, id, "/r", crate::project::NewProject::default(), 1)
            .ok();
    }

    fn tab(tab_id: &str, session_id: &str, index: u32) -> TabRecord {
        TabRecord {
            tab_id: tab_id.to_string(),
            session_id: session_id.to_string(),
            index,
            title: format!("title-{tab_id}"),
            pinned: false,
            attention: AttentionState::default(),
            split_from: None,
            pane_rect: None,
            stashed_from: None,
            stashed: false,
        }
    }

    fn window(window_id: &str, tabs: Vec<TabRecord>) -> WindowLayout {
        WindowLayout {
            window_id: window_id.to_string(),
            name: None,
            tabs,
        }
    }

    #[test]
    fn capture_copies_topology_and_round_trips_through_the_store() {
        let dir = TempDir::new().unwrap();
        let paths = paths(&dir);
        seed_project(&paths, "proj-X");
        let svc = LayoutPresetService::new(&paths);

        let mut t1 = tab("tab-1", "sess-1", 0);
        t1.pinned = true;
        let mut t2 = tab("tab-2", "sess-2", 1);
        t2.split_from = Some(SplitFrom {
            tab_id: "tab-1".to_string(),
            axis: SplitAxis::Right,
            ratio_per_mille: Some(600),
        });
        let win = window("win-A", vec![t1, t2]);

        let captured = svc
            .capture_from_window("preset-1", "Backend + logs", Some("proj-X"), &win, 100)
            .unwrap();
        assert_eq!(captured.name, "Backend + logs");
        assert_eq!(captured.project_id.as_deref(), Some("proj-X"));
        assert_eq!(captured.tabs.len(), 2);
        assert!(captured.tabs[0].pinned);
        assert_eq!(captured.tabs[0].session_id.as_deref(), Some("sess-1"));
        assert_eq!(captured.tabs[0].source_tab_id, "tab-1");
        assert_eq!(captured.tabs[1].source_tab_id, "tab-2");
        // The split's source-tab pointer is the capture-time tab id of slot 0; restore maps it back
        // to that slot via `source_tab_id`, then to the freshly-minted tab id.
        assert_eq!(
            captured.tabs[1].split_from.as_ref().unwrap().tab_id,
            "tab-1"
        );
        assert_eq!(
            captured.tabs[1]
                .split_from
                .as_ref()
                .unwrap()
                .ratio_per_mille,
            Some(600)
        );

        // Reload from disk: byte round-trip through the envelope/store.
        let loaded = svc.load("preset-1").unwrap().unwrap();
        assert_eq!(loaded, captured);
    }

    #[test]
    fn capture_skips_stashed_tabs_and_renumbers_remaining_slots() {
        let dir = TempDir::new().unwrap();
        let paths = paths(&dir);
        let svc = LayoutPresetService::new(&paths);

        let mut stashed = tab("tab-2", "sess-2", 1);
        stashed.stashed = true;
        let win = window(
            "win-A",
            vec![
                tab("tab-1", "sess-1", 0),
                stashed,
                tab("tab-3", "sess-3", 2),
            ],
        );

        let captured = svc
            .capture_from_window("preset-1", "Two live", None, &win, 100)
            .unwrap();
        assert_eq!(captured.tabs.len(), 2);
        assert_eq!(captured.tabs[0].index, 0);
        assert_eq!(captured.tabs[0].session_id.as_deref(), Some("sess-1"));
        assert_eq!(captured.tabs[1].index, 1);
        assert_eq!(captured.tabs[1].session_id.as_deref(), Some("sess-3"));
    }

    #[test]
    fn capture_refuses_to_clobber_existing_preset() {
        let dir = TempDir::new().unwrap();
        let paths = paths(&dir);
        let svc = LayoutPresetService::new(&paths);
        let win = window("win-A", vec![tab("tab-1", "sess-1", 0)]);

        svc.capture_from_window("preset-1", "First", None, &win, 100)
            .unwrap();
        let err = svc
            .capture_from_window("preset-1", "Second", None, &win, 200)
            .unwrap_err();
        assert!(matches!(err, LayoutPresetError::PresetAlreadyExists { .. }));
        // The original is left intact.
        assert_eq!(svc.load("preset-1").unwrap().unwrap().name, "First");
    }

    #[test]
    fn list_filters_by_project_and_sorts_newest_first() {
        let dir = TempDir::new().unwrap();
        let paths = paths(&dir);
        seed_project(&paths, "proj-X");
        seed_project(&paths, "proj-Y");
        let svc = LayoutPresetService::new(&paths);
        let win = window("win-A", vec![tab("tab-1", "sess-1", 0)]);

        svc.capture_from_window("p-old", "Old", Some("proj-X"), &win, 100)
            .unwrap();
        svc.capture_from_window("p-new", "New", Some("proj-X"), &win, 300)
            .unwrap();
        svc.capture_from_window("p-other", "Other", Some("proj-Y"), &win, 200)
            .unwrap();
        svc.capture_from_window("p-global", "Global", None, &win, 250)
            .unwrap();

        let scoped = svc.list(Some("proj-X")).unwrap();
        assert_eq!(
            scoped
                .iter()
                .map(|p| p.preset_id.as_str())
                .collect::<Vec<_>>(),
            vec!["p-new", "p-old"]
        );

        let all = svc.list(None).unwrap();
        assert_eq!(all.len(), 4);
        // Newest-first across all projects.
        assert_eq!(all[0].preset_id, "p-new");
        assert_eq!(all[1].preset_id, "p-global");
        assert_eq!(all[2].preset_id, "p-other");
        assert_eq!(all[3].preset_id, "p-old");
    }

    #[test]
    fn delete_removes_only_the_named_preset() {
        let dir = TempDir::new().unwrap();
        let paths = paths(&dir);
        let svc = LayoutPresetService::new(&paths);
        let win = window("win-A", vec![tab("tab-1", "sess-1", 0)]);

        svc.capture_from_window("p-1", "One", None, &win, 100)
            .unwrap();
        svc.capture_from_window("p-2", "Two", None, &win, 200)
            .unwrap();

        svc.delete("p-1").unwrap();
        assert!(svc.load("p-1").unwrap().is_none());
        assert!(svc.load("p-2").unwrap().is_some());
    }

    // NOTE: the old `preset_without_optional_fields_deserializes_with_defaults` test wrote a raw JSON envelope FILE
    // for a legacy-shaped preset (tabs missing project_id / split_from / session_id / source_tab_id) to assert
    // serde `#[serde(default)]` filled them in. That per-record envelope-file mechanism is GONE in the SQLite store
    // (records are rows, not JSON files); a stored row that won't deserialize now surfaces as Quarantined, tested in
    // store::row_that_wont_deserialize_is_quarantined_and_excluded. The happy-path serde round-trip through the store
    // is still covered by capture_copies_topology_and_round_trips_through_the_store.

    fn preset_tab(index: u32, session_id: Option<&str>) -> LayoutPresetTab {
        LayoutPresetTab {
            index,
            title: format!("slot-{index}"),
            pinned: false,
            split_from: None,
            session_id: session_id.map(str::to_string),
            source_tab_id: format!("src-{index}"),
        }
    }

    fn preset(tabs: Vec<LayoutPresetTab>) -> LayoutPreset {
        LayoutPreset {
            preset_id: "p".to_string(),
            name: "P".to_string(),
            project_id: None,
            created_at_ms: 1,
            tabs,
        }
    }

    #[test]
    fn restore_plan_reattaches_live_hints_and_launches_fresh_otherwise() {
        let p = preset(vec![
            preset_tab(0, Some("sess-live")),
            preset_tab(1, Some("sess-gone")),
            preset_tab(2, None),
        ]);
        let plan = plan_preset_restore(&p, &["sess-live".to_string()]);
        assert_eq!(plan.len(), 3);
        assert_eq!(
            plan[0].action,
            PresetRestoreAction::Reattach {
                session_id: "sess-live".to_string()
            }
        );
        // Hinted-but-dead and no-hint both launch fresh.
        assert_eq!(plan[1].action, PresetRestoreAction::LaunchFresh);
        assert_eq!(plan[2].action, PresetRestoreAction::LaunchFresh);
    }

    #[test]
    fn restore_plan_preserves_order_and_split_provenance() {
        let mut t1 = preset_tab(1, None);
        t1.split_from = Some(SplitFrom {
            tab_id: "ignored-at-restore".to_string(),
            axis: SplitAxis::Down,
            ratio_per_mille: Some(400),
        });
        t1.pinned = true;
        let p = preset(vec![preset_tab(0, None), t1]);

        let plan = plan_preset_restore(&p, &[]);
        assert_eq!(plan.iter().map(|s| s.index).collect::<Vec<_>>(), vec![0, 1]);
        assert!(plan[1].pinned);
        assert_eq!(plan[1].split_from.as_ref().unwrap().axis, SplitAxis::Down);
        assert_eq!(
            plan[1].split_from.as_ref().unwrap().ratio_per_mille,
            Some(400)
        );
    }

    #[test]
    fn restore_plan_of_empty_preset_is_empty() {
        assert!(plan_preset_restore(&preset(vec![]), &["x".to_string()]).is_empty());
    }
}
