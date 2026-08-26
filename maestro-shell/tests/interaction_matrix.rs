//! Cross-operation integrity matrix.
//!
//! Every lifecycle action a local writer can perform (project/window/pane create, delete, stash,
//! revive, rename, reorder) is modeled as a self-preconditioning op; the matrix executes EVERY
//! ordered pair of ops (N×N) on a fresh seeded store and asserts the store invariant oracle
//! (`maestro_shell::invariants::check_store_invariants`) after EVERY step. With the singles and the
//! full-sequence run this is 144 pair cases + 12 singles + sequence checkpoints — >150 verified
//! action→store outcomes, all through the same maestro-shell services every local writer uses
//! (writer processes differ only in which process calls them, which the oracle cannot
//! see; origin attribution is covered by the mutation-context test at the bottom).
//!
//! If a new lifecycle op is added to the product, add it to `Op::ALL` and the matrix covers its
//! interaction with every existing op automatically.

use maestro_shell::invariants::check_store_invariants;
use maestro_shell::paths::{AppPaths, RecordKind};
use maestro_shell::policy::WorkspacePolicy;
use maestro_shell::project::{NewProject, ProjectService};
use maestro_shell::records::{
    Attention, AttentionSource, AttentionState, LaunchSpec, SessionKind, SessionRecord,
    SessionStatus, SplitAxis, Workspace, WorkspaceConsent,
};
use maestro_shell::window_layout::WindowLayoutService;
use maestro_shell::{
    store, write_trace, CasPublication, ConditionalWindowDelete, PendingReleaseReceipt,
    PreResolvedSessionGenerations, PreResolvedSessionState, ReleaseOperationOutcome,
    SessionReleaseService,
};
use tempfile::TempDir;

struct Fixture {
    _tmp: TempDir,
    paths: AppPaths,
    now: u64,
}

fn attn() -> AttentionState {
    AttentionState {
        attention: Attention::None,
        unseen: false,
        since_ms: 1,
        source: AttentionSource::Process,
    }
}

impl Fixture {
    /// Baseline every case starts from: project `p1` owning window `w1` with live pane `pane-1` —
    /// created through the same service chain every local writer uses (workspace + session + layout +
    /// FK stamp + window_order).
    fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let paths = AppPaths::with_base(tmp.path().join("Maestro"));
        let mut fx = Fixture {
            _tmp: tmp,
            paths,
            now: 1_000,
        };
        fx.create_project("p1");
        fx.create_window("p1", "w1");
        fx
    }

    fn tick(&mut self) -> u64 {
        self.now += 1;
        self.now
    }

    fn projects(&self) -> ProjectService<'_> {
        ProjectService::new(&self.paths)
    }
    fn windows(&self) -> WindowLayoutService<'_> {
        WindowLayoutService::new(&self.paths)
    }

    fn create_project(&mut self, id: &str) {
        if self.projects().load(id).unwrap().is_some() {
            return;
        }
        let now = self.tick();
        self.projects()
            .create(id, id, format!("/repos/{id}"), NewProject::default(), now)
            .unwrap();
    }

    /// Delete through the same prepared ownership contract as the app. This fixture has no daemon,
    /// so it explicitly treats the planned ids as already absent before committing.
    fn delete_project(&mut self, id: &str) {
        self.create_project(id);
        let plan = self.projects().plan_delete(id).unwrap();
        let pre_resolved = plan
            .unresolved_release_session_ids()
            .into_iter()
            .map(|session_id| {
                (
                    session_id.to_string(),
                    PreResolvedSessionState::ConfirmedAbsent,
                )
            })
            .collect::<PreResolvedSessionGenerations>();
        let now = self.tick();
        let result = self
            .projects()
            .commit_delete(&plan, &pre_resolved, now)
            .unwrap();
        self.drain_release(result.release_receipt);
    }

    /// The full app-like window chain: Workspace + Session records, empty layout, first pane,
    /// FK ownership stamp, window_order append.
    fn create_window(&mut self, project_id: &str, window_id: &str) {
        self.create_project(project_id);
        if self.windows().load(window_id).unwrap().is_some() {
            return;
        }
        let ws_id = format!("ws-{window_id}");
        let workspace = Workspace {
            workspace_id: ws_id.clone(),
            project_id: project_id.to_string(),
            root: format!("/repos/{project_id}"),
            policy: WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        };
        let now = self.tick();
        store::write_record(&self.paths, RecordKind::Workspace, &ws_id, now, &workspace).unwrap();
        self.create_session(window_id, "pane-1");
        let now = self.tick();
        self.windows().create_empty(window_id, now).unwrap();
        let now = self.tick();
        self.windows()
            .open_tab(
                window_id,
                "pane-1",
                &format!("s-{window_id}-pane-1"),
                "Pane 1",
                false,
                attn(),
                now,
            )
            .unwrap();
        store::set_window_project(&self.paths, window_id, project_id).unwrap();
        let mut order = self
            .projects()
            .load(project_id)
            .unwrap()
            .unwrap()
            .window_order;
        if !order.contains(&window_id.to_string()) {
            order.push(window_id.to_string());
            let now = self.tick();
            self.projects()
                .reorder_windows(project_id, &order, now)
                .unwrap();
        }
    }

    fn create_session(&mut self, window_id: &str, tab_id: &str) {
        let sid = format!("s-{window_id}-{tab_id}");
        if store::load_one::<SessionRecord>(&self.paths, RecordKind::Session, &sid)
            .unwrap()
            .is_some()
        {
            return;
        }
        let record = SessionRecord {
            session_id: sid.clone(),
            workspace_id: format!("ws-{window_id}"),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "ls-1".into(),
                params: vec![],
            },
            cwd_resolved: "/tmp".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: Some(format!("gen-{sid}")),
            status: SessionStatus::Live,
        };
        let now = self.tick();
        store::write_record(&self.paths, RecordKind::Session, &sid, now, &record).unwrap();
    }

    fn open_pane(&mut self, window_id: &str, tab_id: &str) {
        self.create_window("p1", window_id);
        let layout = self.windows().load(window_id).unwrap().unwrap();
        if layout.tabs.iter().any(|t| t.tab_id == tab_id) {
            return;
        }
        self.create_session(window_id, tab_id);
        let now = self.tick();
        self.windows()
            .open_tab(
                window_id,
                tab_id,
                &format!("s-{window_id}-{tab_id}"),
                tab_id,
                false,
                attn(),
                now,
            )
            .unwrap();
    }

    fn pane_exists(&self, window_id: &str, tab_id: &str, stashed: Option<bool>) -> bool {
        self.windows()
            .load(window_id)
            .unwrap()
            .map(|l| {
                l.tabs
                    .iter()
                    .any(|t| t.tab_id == tab_id && stashed.is_none_or(|s| t.stashed == s))
            })
            .unwrap_or(false)
    }

    fn drain_release(&self, receipt: Option<PendingReleaseReceipt>) {
        let Some(receipt) = receipt else {
            return;
        };
        assert!(matches!(
            SessionReleaseService::new(&self.paths).attempt_owned::<()>(
                receipt,
                |_| Ok(()),
                |_| CasPublication::Confirmed,
            ),
            ReleaseOperationOutcome::Complete { .. }
        ));
    }

    /// Reuse one schema/connection for the 144 pair cases. `maestro-shell` intentionally caches a
    /// connection plus schema-lease fd per app-support base for the process lifetime; allocating a
    /// new temp base for every matrix cell exceeds macOS's default 256-fd test limit before the
    /// behavioral matrix completes.
    fn reset_to_baseline(&mut self) {
        let connection = maestro_shell::db::conn_for(self.paths.base()).unwrap();
        let mut guard = connection.lock().unwrap();
        let tx = guard
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .unwrap();
        tx.execute_batch(
            "DELETE FROM pending_session_releases;
             DELETE FROM session_release_operations;
             DELETE FROM tabs;
             DELETE FROM worktree_provenance;
             DELETE FROM layout_presets;
             DELETE FROM agent_tasks;
             DELETE FROM sessions;
             DELETE FROM windows;
             DELETE FROM workspaces;
             DELETE FROM projects;
             DELETE FROM daemon_endpoint;
             DELETE FROM session_names;",
        )
        .unwrap();
        tx.pragma_update(None, "user_version", 0).unwrap();
        tx.commit().unwrap();
        drop(guard);

        self.now = 1_000;
        self.create_project("p1");
        self.create_window("p1", "w1");
    }
}

/// Every lifecycle op, self-preconditioning: an op first ensures whatever state it needs, so any
/// ordered pair (a, b) is executable and the matrix has no invalid cells.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    CreateProject,
    DeleteProject,
    CreateWindow,
    RemoveWindow,
    OpenPane,
    SplitPane,
    ClosePane,
    StashPane,
    RevivePane,
    RenameWindow,
    RenamePane,
    ReorderWindows,
}

impl Op {
    const ALL: [Op; 12] = [
        Op::CreateProject,
        Op::DeleteProject,
        Op::CreateWindow,
        Op::RemoveWindow,
        Op::OpenPane,
        Op::SplitPane,
        Op::ClosePane,
        Op::StashPane,
        Op::RevivePane,
        Op::RenameWindow,
        Op::RenamePane,
        Op::ReorderWindows,
    ];

    fn apply(self, fx: &mut Fixture) {
        match self {
            Op::CreateProject => fx.create_project("p2"),
            Op::DeleteProject => fx.delete_project("p2"),
            Op::CreateWindow => fx.create_window("p1", "w2"),
            Op::RemoveWindow => {
                fx.create_window("p1", "w2");
                let expected = fx.windows().load_snapshot("w2").unwrap().unwrap();
                let now = fx.tick();
                let mut receipt = match fx.windows().delete_if_unchanged(&expected, now).unwrap() {
                    ConditionalWindowDelete::Deleted(receipt) => receipt,
                    outcome => panic!("prepared matrix window delete was refused: {outcome:?}"),
                };
                assert!(receipt.unresolved_release_session_ids().is_empty());
                let release = receipt.take_release_receipt();
                fx.drain_release(release);
                // The stale window_order entry is tolerated by contract (snapshot ignores it).
            }
            Op::OpenPane => fx.open_pane("w1", "pane-2"),
            Op::SplitPane => {
                if !fx.pane_exists("w1", "pane-s", None) {
                    fx.create_session("w1", "pane-s");
                    let now = fx.tick();
                    fx.windows()
                        .split_tab(
                            "w1",
                            "pane-1",
                            "pane-s",
                            "s-w1-pane-s",
                            "split",
                            SplitAxis::Right,
                            now,
                        )
                        .unwrap();
                }
            }
            Op::ClosePane => {
                fx.open_pane("w1", "pane-2");
                let now = fx.tick();
                let closed = fx
                    .windows()
                    .close_pane_with_removed("w1", "pane-2", now)
                    .unwrap();
                assert!(closed.unresolved_release_session_ids.is_empty());
                fx.drain_release(closed.release_receipt);
            }
            Op::StashPane => {
                fx.open_pane("w1", "pane-2");
                if fx.pane_exists("w1", "pane-2", Some(false)) {
                    let now = fx.tick();
                    fx.windows().stash_pane("w1", "pane-2", now).unwrap();
                }
            }
            Op::RevivePane => {
                Op::StashPane.apply(fx);
                if fx.pane_exists("w1", "pane-2", Some(true)) {
                    let now = fx.tick();
                    fx.windows().revive_pane("w1", "pane-2", now).unwrap();
                }
            }
            Op::RenameWindow => {
                let now = fx.tick();
                fx.windows().rename_window("w1", "Renamed", now).unwrap();
            }
            Op::RenamePane => {
                let now = fx.tick();
                fx.windows()
                    .rename_tab("w1", "pane-1", "Renamed pane", now)
                    .unwrap();
            }
            Op::ReorderWindows => {
                fx.create_window("p1", "w2");
                let mut order = fx.projects().load("p1").unwrap().unwrap().window_order;
                order.reverse();
                let now = fx.tick();
                fx.projects().reorder_windows("p1", &order, now).unwrap();
            }
        }
    }
}

fn assert_healthy(fx: &Fixture, context: &str) {
    let violations = check_store_invariants(&fx.paths).unwrap();
    assert!(
        violations.is_empty(),
        "invariant violations after {context}: {violations:?}"
    );
}

/// The matrix: every ordered pair of lifecycle ops on a fresh store, oracle after every step.
/// 12×12 = 144 cases (+ oracle-after-first = 288 checkpoints).
#[test]
fn every_ordered_pair_of_lifecycle_ops_keeps_the_store_coherent() {
    let mut fx = Fixture::new();
    for a in Op::ALL {
        for b in Op::ALL {
            fx.reset_to_baseline();
            assert_healthy(&fx, "baseline");
            a.apply(&mut fx);
            assert_healthy(&fx, &format!("{a:?} (then {b:?})"));
            b.apply(&mut fx);
            assert_healthy(&fx, &format!("{a:?} → {b:?}"));
        }
    }
}

/// Each op alone, plus the full sequence in declaration order with a checkpoint after every step.
#[test]
fn singles_and_full_sequence_keep_the_store_coherent() {
    for op in Op::ALL {
        let mut fx = Fixture::new();
        op.apply(&mut fx);
        assert_healthy(&fx, &format!("single {op:?}"));
    }
    let mut fx = Fixture::new();
    for op in Op::ALL {
        op.apply(&mut fx);
        assert_healthy(&fx, &format!("sequence step {op:?}"));
    }
}

/// Deleting the baseline project must prepare every owned session before cascading its record
/// graph, and the store stays coherent.
#[test]
fn deleting_the_owning_project_cascades_and_stays_coherent() {
    let mut fx = Fixture::new();
    fx.open_pane("w1", "pane-2");
    let plan = fx.projects().plan_delete("p1").unwrap();
    assert!(plan.kill_session_ids.contains(&"s-w1-pane-1".to_string()));
    assert!(plan.kill_session_ids.contains(&"s-w1-pane-2".to_string()));
    let pre_resolved = plan
        .unresolved_release_session_ids()
        .into_iter()
        .map(|session_id| {
            (
                session_id.to_string(),
                PreResolvedSessionState::ConfirmedAbsent,
            )
        })
        .collect::<PreResolvedSessionGenerations>();
    let now = fx.tick();
    let result = fx
        .projects()
        .commit_delete(&plan, &pre_resolved, now)
        .unwrap();
    assert!(
        result.release_receipt.is_some(),
        "the exact owned Session generations must be journaled with the project cascade"
    );
    fx.drain_release(result.release_receipt);
    assert!(
        SessionReleaseService::new(&fx.paths)
            .claim_next()
            .unwrap()
            .is_none(),
        "the matrix drains the committed project-release journal"
    );
    assert_healthy(&fx, "delete p1");
    assert!(
        fx.windows().load("w1").unwrap().is_none(),
        "window cascaded"
    );
    assert!(
        store::window_project_owners(&fx.paths).unwrap().is_empty(),
        "no window rows survive the owner's deletion"
    );
}

/// I1 attribution: a mutation performed under a mutation context stamps its cause onto the
/// DB-write trace rows it produced (join key: unique ids per this test — the ring is process-global
/// and other tests run in parallel).
#[test]
fn mutation_context_attributes_matrix_actions_in_the_write_trace() {
    write_trace::set_writer_tag("matrix-test");
    let mut fx = Fixture::new();
    write_trace::with_mutation_context("remote:new_window rid=matrix-1", || {
        fx.create_window("p1", "w-attributed");
    });
    let events = write_trace::recent();
    let stamped: Vec<_> = events.iter().filter(|e| e.id == "w-attributed").collect();
    assert!(!stamped.is_empty(), "the window write must be traced");
    assert!(
        stamped
            .iter()
            .all(|e| e.ctx.as_deref() == Some("remote:new_window rid=matrix-1")),
        "every row the op caused carries its cause: {stamped:?}"
    );
}
