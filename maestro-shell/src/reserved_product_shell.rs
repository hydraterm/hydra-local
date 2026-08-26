//! Sealed launch authority for the two product-owned `Shell + OptOut` sessions.
//!
//! Ordinary `OptOut` records deliberately carry no replay authority.  The desktop product has two
//! fixed shells whose invocation is supplied by the reviewed product launcher: the visible built-in
//! Terminal and the hidden recovery terminal.  This module is the only exception.  It mints an
//! opaque, non-cloneable authority from one coherent durable graph snapshot, owns the live argv
//! without exposing it through `Debug`, and can revalidate the same graph inside the final Session
//! publication transaction.

// The sealed launch receipt stays inline so its consume-once ownership remains explicit.
#![allow(clippy::result_large_err, clippy::too_many_arguments)]

use std::fmt;

use rusqlite::{Connection, OptionalExtension, TransactionBehavior};
use serde::de::DeserializeOwned;

use crate::paths::{AppPaths, RecordKind};
use crate::policy::WorkspacePolicy;
use crate::records::{
    LaunchSpec, Project, ProjectLaunchDefaults, SessionKind, SessionRecord, TabRecord,
    WindowLayout, Workspace, WorkspaceConsent,
};
use crate::session_service::{SessionServiceError, StartParams};
use crate::store::StoreError;

pub const SYSTEM_TERMINAL_PROJECT_ID: &str = "system-terminal";
pub const SYSTEM_TERMINAL_WORKSPACE_ID: &str = "system-terminal-workspace-1";
pub const SYSTEM_TERMINAL_WINDOW_ID: &str = "system-terminal-window-1";
pub const SYSTEM_TERMINAL_TAB_ID: &str = "pane-1";
pub const SYSTEM_TERMINAL_SESSION_ID: &str = "system-terminal-pane-1";

pub const PRODUCT_RECOVERY_PROJECT_ID: &str = "system-product-recovery";
pub const PRODUCT_RECOVERY_WORKSPACE_ID: &str = "system-product-recovery-workspace";
pub const PRODUCT_RECOVERY_WINDOW_ID: &str = "system-product-recovery-window";
pub const PRODUCT_RECOVERY_TAB_ID: &str = "system-product-recovery-pane";
pub const PRODUCT_RECOVERY_SESSION_ID: &str = "system-product-recovery-session";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReservedProductShellKind {
    SystemTerminal,
    ProductRecovery,
}

impl ReservedProductShellKind {
    fn ids(self) -> ReservedProductShellIds {
        match self {
            Self::SystemTerminal => ReservedProductShellIds {
                project_id: SYSTEM_TERMINAL_PROJECT_ID,
                workspace_id: SYSTEM_TERMINAL_WORKSPACE_ID,
                window_id: SYSTEM_TERMINAL_WINDOW_ID,
                tab_id: SYSTEM_TERMINAL_TAB_ID,
                session_id: SYSTEM_TERMINAL_SESSION_ID,
            },
            Self::ProductRecovery => ReservedProductShellIds {
                project_id: PRODUCT_RECOVERY_PROJECT_ID,
                workspace_id: PRODUCT_RECOVERY_WORKSPACE_ID,
                window_id: PRODUCT_RECOVERY_WINDOW_ID,
                tab_id: PRODUCT_RECOVERY_TAB_ID,
                session_id: PRODUCT_RECOVERY_SESSION_ID,
            },
        }
    }
}

#[derive(Clone, Copy)]
struct ReservedProductShellIds {
    project_id: &'static str,
    workspace_id: &'static str,
    window_id: &'static str,
    tab_id: &'static str,
    session_id: &'static str,
}

#[derive(Clone, PartialEq, Eq)]
struct ReservedProductShellGraph {
    project: Project,
    workspace: Workspace,
    session: SessionRecord,
    layout: WindowLayout,
    owner_project_id: Option<String>,
    window_mutation_epoch: u32,
}

/// Opaque one-operation authority for a fixed product shell.
///
/// The constructor reloads the fixed ids itself; caller-provided Session/Workspace records are
/// never treated as authority.  `argv` is moved into the private live `StartParams`, is never
/// persisted, and is intentionally absent from `Debug`.
pub struct ReservedProductShellStart {
    kind: ReservedProductShellKind,
    graph: ReservedProductShellGraph,
    params: StartParams,
}

impl fmt::Debug for ReservedProductShellStart {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReservedProductShellStart")
            .field("kind", &self.kind)
            .field("session_id", &self.graph.session.session_id)
            .field("argv", &"<redacted>")
            .finish_non_exhaustive()
    }
}

impl ReservedProductShellStart {
    /// Mint the sealed authority from one `DEFERRED` SQLite snapshot.
    ///
    /// An empty invocation, contaminated reserved topology, or unreadable row refuses before any
    /// daemon request. The graph/Attach authority is intentionally independent of current cwd
    /// existence: a retained live lifetime remains exactly attachable after its directory is
    /// deleted. The exact recorded cwd is nevertheless captured verbatim, and a Missing/Absent
    /// replay checks that it is still a directory immediately before Start; this authority never
    /// performs HOME/project fallback or metadata migration.
    pub fn load(
        paths: &AppPaths,
        kind: ReservedProductShellKind,
        expected_session: &SessionRecord,
        expected_workspace: &Workspace,
        argv: Vec<String>,
        cols: u16,
        rows: u16,
        now_ms: u64,
    ) -> Result<Self, SessionServiceError> {
        let (command, args) = argv.split_first().ok_or_else(|| authority_lost(kind))?;
        if command.trim().is_empty() {
            return Err(authority_lost(kind));
        }
        let graph = load_graph_snapshot(paths, kind)?;
        if &graph.session != expected_session || &graph.workspace != expected_workspace {
            return Err(authority_lost(kind));
        }
        let params = StartParams {
            session_id: graph.session.session_id.clone(),
            workspace_id: graph.session.workspace_id.clone(),
            kind: graph.session.kind,
            launch: graph.session.launch.clone(),
            cwd: graph.session.cwd_resolved.clone(),
            command: command.clone(),
            args: args.to_vec(),
            cols,
            rows,
            agent_task_id: graph.session.agent_task_id.clone(),
            now_ms,
        };
        Ok(Self {
            kind,
            graph,
            params,
        })
    }

    pub(crate) fn session(&self) -> &SessionRecord {
        &self.graph.session
    }

    pub(crate) fn workspace(&self) -> &Workspace {
        &self.graph.workspace
    }

    pub(crate) fn params(&self) -> &StartParams {
        &self.params
    }

    pub(crate) fn graph_matches_in_snapshot(
        &self,
        paths: &AppPaths,
    ) -> Result<bool, SessionServiceError> {
        match load_graph_snapshot(paths, self.kind) {
            Ok(current) => Ok(current == self.graph),
            Err(SessionServiceError::AttachAuthorityLost { .. }) => Ok(false),
            Err(error) => Err(error),
        }
    }

    pub(crate) fn graph_matches_connection(
        &self,
        connection: &Connection,
    ) -> Result<bool, StoreError> {
        let Some(current) = load_graph_from_connection(connection, self.kind)? else {
            return Ok(false);
        };
        Ok(current == self.graph
            && graph_is_authorized_connection(connection, self.kind, &current)?)
    }
}

fn authority_lost(kind: ReservedProductShellKind) -> SessionServiceError {
    SessionServiceError::AttachAuthorityLost {
        session_id: kind.ids().session_id.to_string(),
    }
}

fn terminal_launch_defaults() -> ProjectLaunchDefaults {
    ProjectLaunchDefaults {
        agent: Some("terminal".to_string()),
        model: None,
        resume_mode: None,
        dangerous_skip_permissions: None,
        custom_command: None,
    }
}

fn reserved_session_shape(
    ids: ReservedProductShellIds,
    workspace: &Workspace,
    session: &SessionRecord,
) -> bool {
    session.session_id == ids.session_id
        && session.workspace_id == ids.workspace_id
        && session.kind == SessionKind::Shell
        && session.launch == LaunchSpec::OptOut
        && session.cwd_resolved == workspace.root
        && session.agent_task_id.is_none()
}

fn recovery_tab_shape(tab: &TabRecord) -> bool {
    tab.tab_id == PRODUCT_RECOVERY_TAB_ID
        && tab.session_id == PRODUCT_RECOVERY_SESSION_ID
        && tab.index == 0
        && tab.title == "Terminal"
        && !tab.pinned
        && tab.split_from.is_none()
        && tab.pane_rect.is_none()
        && tab.stashed_from.is_none()
        && !tab.stashed
}

fn graph_base_shape(kind: ReservedProductShellKind, graph: &ReservedProductShellGraph) -> bool {
    let ids = kind.ids();
    if graph.project.project_id != ids.project_id
        || graph.workspace.workspace_id != ids.workspace_id
        || graph.workspace.project_id != ids.project_id
        || graph.workspace.root != graph.project.root
        || graph.layout.window_id != ids.window_id
        || graph.owner_project_id.as_deref() != Some(ids.project_id)
        || !graph.project.system
        || !reserved_session_shape(ids, &graph.workspace, &graph.session)
    {
        return false;
    }

    match kind {
        ReservedProductShellKind::SystemTerminal => {
            !graph.project.hidden
                && graph.workspace.policy == WorkspacePolicy::ScratchCwd
                && graph.workspace.consent == WorkspaceConsent::default()
                && graph
                    .project
                    .window_order
                    .iter()
                    .filter(|window_id| window_id.as_str() == ids.window_id)
                    .count()
                    == 1
                && graph
                    .layout
                    .tabs
                    .iter()
                    .filter(|tab| {
                        tab.tab_id == ids.tab_id && tab.session_id == ids.session_id && !tab.stashed
                    })
                    .count()
                    == 1
        }
        ReservedProductShellKind::ProductRecovery => {
            graph.project.name == "Product Recovery"
                && graph.project.default_workspace_policy == WorkspacePolicy::ScratchCwd
                && graph.project.icon.is_none()
                && graph.project.accent_color.is_none()
                && graph.project.launch_defaults.as_ref() == Some(&terminal_launch_defaults())
                && graph.project.directories.is_empty()
                && graph.project.hidden
                && graph.project.window_order == [ids.window_id.to_string()]
                && graph.workspace.policy == WorkspacePolicy::ScratchCwd
                && graph.workspace.consent == WorkspaceConsent::default()
                && graph.layout.name.as_deref() == Some("Recovery")
                && matches!(graph.layout.tabs.as_slice(), [tab] if recovery_tab_shape(tab))
        }
    }
}

fn graph_is_authorized_connection(
    connection: &Connection,
    kind: ReservedProductShellKind,
    graph: &ReservedProductShellGraph,
) -> Result<bool, StoreError> {
    if !graph_base_shape(kind, graph) {
        return Ok(false);
    }
    let ids = kind.ids();
    let projects = load_all_typed::<Project>(connection, RecordKind::Project)?;
    if projects.iter().any(|project| {
        project.project_id != ids.project_id
            && project
                .window_order
                .iter()
                .any(|window_id| window_id == ids.window_id)
    }) {
        return Ok(false);
    }
    if kind != ReservedProductShellKind::ProductRecovery {
        return Ok(true);
    }
    let workspaces = load_all_typed::<Workspace>(connection, RecordKind::Workspace)?;
    if workspaces
        .iter()
        .filter(|workspace| workspace.project_id == ids.project_id)
        .any(|workspace| workspace.workspace_id != ids.workspace_id)
    {
        return Ok(false);
    }
    let sessions = load_all_typed::<SessionRecord>(connection, RecordKind::Session)?;
    if sessions
        .iter()
        .filter(|session| session.workspace_id == ids.workspace_id)
        .any(|session| session.session_id != ids.session_id)
    {
        return Ok(false);
    }
    let owners = window_owners(connection)?;
    Ok(!owners.iter().any(|(window_id, owner)| {
        owner.as_deref() == Some(ids.project_id) && window_id != ids.window_id
    }))
}

fn load_graph_snapshot(
    paths: &AppPaths,
    kind: ReservedProductShellKind,
) -> Result<ReservedProductShellGraph, SessionServiceError> {
    let arc = crate::db::conn_for(paths.base())
        .map_err(|error| SessionServiceError::Store(StoreError::Db(error.to_string())))?;
    let mut connection = arc.lock().unwrap();
    let tx = connection
        .transaction_with_behavior(TransactionBehavior::Deferred)
        .map_err(|error| SessionServiceError::Store(StoreError::Db(error.to_string())))?;
    let graph = load_graph_from_connection(&tx, kind)
        .map_err(SessionServiceError::Store)?
        .ok_or_else(|| authority_lost(kind))?;
    if !graph_is_authorized_connection(&tx, kind, &graph).map_err(SessionServiceError::Store)? {
        return Err(authority_lost(kind));
    }
    tx.commit()
        .map_err(|error| SessionServiceError::Store(StoreError::Db(error.to_string())))?;
    Ok(graph)
}

fn load_graph_from_connection(
    connection: &Connection,
    kind: ReservedProductShellKind,
) -> Result<Option<ReservedProductShellGraph>, StoreError> {
    let ids = kind.ids();
    let Some(project) = load_typed::<Project>(connection, RecordKind::Project, ids.project_id)?
    else {
        return Ok(None);
    };
    let Some(workspace) =
        load_typed::<Workspace>(connection, RecordKind::Workspace, ids.workspace_id)?
    else {
        return Ok(None);
    };
    let Some(session) =
        load_typed::<SessionRecord>(connection, RecordKind::Session, ids.session_id)?
    else {
        return Ok(None);
    };
    let Some(layout) =
        load_typed::<WindowLayout>(connection, RecordKind::WindowLayout, ids.window_id)?
    else {
        return Ok(None);
    };
    let owner_project_id = connection
        .query_row(
            "SELECT project_id FROM windows WHERE window_id = ?1",
            [ids.window_id],
            |row| row.get::<_, Option<String>>(0),
        )
        .optional()
        .map_err(|error| StoreError::Db(error.to_string()))?
        .flatten();
    let window_mutation_epoch = crate::db::window_mutation_epoch(connection)
        .map_err(|error| StoreError::Db(error.to_string()))?;
    Ok(Some(ReservedProductShellGraph {
        project,
        workspace,
        session,
        layout,
        owner_project_id,
        window_mutation_epoch,
    }))
}

fn load_typed<T: DeserializeOwned>(
    connection: &Connection,
    kind: RecordKind,
    id: &str,
) -> Result<Option<T>, StoreError> {
    crate::store_sqlite::load_one(connection, kind, id)
        .map_err(|error| StoreError::Map(error.to_string()))?
        .map(serde_json::from_value)
        .transpose()
        .map_err(|error| StoreError::Map(format!("decode reserved {kind:?} {id:?}: {error}")))
}

fn load_all_typed<T: DeserializeOwned>(
    connection: &Connection,
    kind: RecordKind,
) -> Result<Vec<T>, StoreError> {
    crate::store_sqlite::load_all(connection, kind)
        .map_err(|error| StoreError::Map(error.to_string()))?
        .into_iter()
        .map(|value| {
            serde_json::from_value(value).map_err(|error| {
                StoreError::Map(format!("decode reserved {kind:?} scope: {error}"))
            })
        })
        .collect()
}

fn window_owners(connection: &Connection) -> Result<Vec<(String, Option<String>)>, StoreError> {
    let mut statement = connection
        .prepare("SELECT window_id, project_id FROM windows ORDER BY window_id")
        .map_err(|error| StoreError::Db(error.to_string()))?;
    let rows = statement
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?)))
        .map_err(|error| StoreError::Db(error.to_string()))?;
    rows.collect::<Result<Vec<_>, _>>()
        .map_err(|error| StoreError::Db(error.to_string()))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::daemon_client::DaemonClient;
    use crate::records::{Attention, AttentionSource, AttentionState, SessionStatus};
    use crate::session_release::{SessionReleaseService, SessionReleaseTarget, SessionRowPolicy};
    use crate::session_service::{
        ExactExistingAttach, ExistingSessionAttach, ExistingSessionMissingStart, SessionService,
    };
    use crate::store::{self, ConditionalSessionAttachFinalize, LoadOutcome};
    use maestro_protocol::{AttachmentHandoff, ClientRequest};
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread::JoinHandle;
    use std::time::{Duration, Instant};
    use tempfile::TempDir;

    static STUB_DAEMON_TEST_SERIAL: std::sync::OnceLock<std::sync::Mutex<()>> =
        std::sync::OnceLock::new();

    struct StubDaemon {
        path: PathBuf,
        _dir: TempDir,
        _serial: std::sync::MutexGuard<'static, ()>,
        handle: Option<JoinHandle<()>>,
        requests: mpsc::Receiver<String>,
    }

    impl StubDaemon {
        fn spawn(
            serve: impl FnOnce(&mpsc::Sender<String>, &mut UnixStream) + Send + 'static,
        ) -> Self {
            // Reserved-shell tests intentionally share the product's fixed durable session IDs.
            // Their daemon scripts must not run in parallel because the transaction hook is
            // process-global and another exact attach to that same required ID could consume it.
            let serial = STUB_DAEMON_TEST_SERIAL
                .get_or_init(|| std::sync::Mutex::new(()))
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            let dir = TempDir::new().unwrap();
            let path = dir.path().join("reserved-product-shell.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let (request_tx, requests) = mpsc::channel();
            let handle = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                serve(&request_tx, &mut stream);
            });
            Self {
                path,
                _dir: dir,
                _serial: serial,
                handle: Some(handle),
                requests,
            }
        }

        fn collected_requests(&self) -> Vec<String> {
            self.requests.try_iter().collect()
        }
    }

    impl Drop for StubDaemon {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                handle.join().unwrap();
            }
        }
    }

    fn read_request(reader: &mut impl BufRead, requests: &mpsc::Sender<String>) -> Option<String> {
        let mut line = String::new();
        if reader.read_line(&mut line).unwrap() == 0 {
            return None;
        }
        let line = line.trim().to_string();
        requests.send(line.clone()).unwrap();
        Some(line)
    }

    fn strict_daemon_info(instance: &str) -> serde_json::Value {
        serde_json::json!({
            "ev": "daemon_info",
            "protocol_version": maestro_protocol::DAEMON_PROTOCOL_VERSION,
            "build_version": "reserved-product-shell-test",
            "daemon_instance_id": instance,
            "output_generation_echo": true,
            "child_environment": true,
            "generation_conditional_mutations": true,
            "attachment_aware_conditional_kill": true,
            "generation_conditional_start": true,
            "start_operation_ledger": true,
            "generation_conditional_attach": true,
        })
    }

    fn tab(tab_id: &str, session_id: &str, title: &str) -> TabRecord {
        TabRecord {
            tab_id: tab_id.into(),
            session_id: session_id.into(),
            index: 0,
            title: title.into(),
            pinned: false,
            attention: AttentionState::default(),
            split_from: None,
            pane_rect: None,
            stashed_from: None,
            stashed: false,
        }
    }

    fn seed_reserved(
        temp: &TempDir,
        kind: ReservedProductShellKind,
    ) -> (AppPaths, ReservedProductShellGraph) {
        let paths = AppPaths::with_base(temp.path().join("state"));
        let ids = kind.ids();
        let project = Project {
            project_id: ids.project_id.into(),
            name: match kind {
                ReservedProductShellKind::SystemTerminal => "User-renamed Terminal".into(),
                ReservedProductShellKind::ProductRecovery => "Product Recovery".into(),
            },
            root: temp.path().to_string_lossy().into_owned(),
            default_workspace_policy: WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 2,
            icon: (kind == ReservedProductShellKind::SystemTerminal).then(|| "⌘".into()),
            accent_color: None,
            launch_defaults: Some(terminal_launch_defaults()),
            directories: Vec::new(),
            window_order: vec![ids.window_id.into()],
            system: true,
            hidden: kind == ReservedProductShellKind::ProductRecovery,
        };
        let workspace = Workspace {
            workspace_id: ids.workspace_id.into(),
            project_id: ids.project_id.into(),
            root: project.root.clone(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        };
        let session = SessionRecord {
            session_id: ids.session_id.into(),
            workspace_id: ids.workspace_id.into(),
            kind: SessionKind::Shell,
            launch: LaunchSpec::OptOut,
            cwd_resolved: workspace.root.clone(),
            agent_task_id: None,
            created_at_ms: 3,
            last_attached_at_ms: 4,
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        let layout = WindowLayout {
            window_id: ids.window_id.into(),
            name: Some(match kind {
                ReservedProductShellKind::SystemTerminal => "A renamed window".into(),
                ReservedProductShellKind::ProductRecovery => "Recovery".into(),
            }),
            tabs: vec![tab(
                ids.tab_id,
                ids.session_id,
                match kind {
                    ReservedProductShellKind::SystemTerminal => "User title",
                    ReservedProductShellKind::ProductRecovery => "Terminal",
                },
            )],
        };
        store::write_record(&paths, RecordKind::Project, ids.project_id, 1, &project).unwrap();
        store::write_record(
            &paths,
            RecordKind::Workspace,
            ids.workspace_id,
            2,
            &workspace,
        )
        .unwrap();
        store::write_record(&paths, RecordKind::Session, ids.session_id, 3, &session).unwrap();
        store::write_record(&paths, RecordKind::WindowLayout, ids.window_id, 4, &layout).unwrap();
        store::set_window_project(&paths, ids.window_id, ids.project_id).unwrap();
        let graph = load_graph_snapshot(&paths, kind).unwrap();
        (paths, graph)
    }

    fn seed_live_system(
        temp: &TempDir,
    ) -> (
        AppPaths,
        ReservedProductShellGraph,
        ReservedProductShellStart,
    ) {
        let (paths, mut graph) = seed_reserved(temp, ReservedProductShellKind::SystemTerminal);
        graph.session.status = SessionStatus::Live;
        graph.session.last_known_generation = Some("generation-A".into());
        store::write_record(
            &paths,
            RecordKind::Session,
            SYSTEM_TERMINAL_SESSION_ID,
            10,
            &graph.session,
        )
        .unwrap();
        let authority = ReservedProductShellStart::load(
            &paths,
            ReservedProductShellKind::SystemTerminal,
            &graph.session,
            &graph.workspace,
            vec!["/bin/sh".into()],
            80,
            24,
            11,
        )
        .unwrap();
        let graph = load_graph_snapshot(&paths, ReservedProductShellKind::SystemTerminal).unwrap();
        (paths, graph, authority)
    }

    fn seed_system_with_recorded_cwd(
        temp: &TempDir,
        generation: Option<&str>,
    ) -> (
        AppPaths,
        ReservedProductShellGraph,
        ReservedProductShellStart,
        PathBuf,
    ) {
        let (paths, mut graph) = seed_reserved(temp, ReservedProductShellKind::SystemTerminal);
        let cwd = temp.path().join("recorded-cwd");
        std::fs::create_dir(&cwd).unwrap();
        let cwd = cwd.to_string_lossy().into_owned();
        graph.project.root = cwd.clone();
        graph.workspace.root = cwd.clone();
        graph.session.cwd_resolved = cwd.clone();
        graph.session.status = if generation.is_some() {
            SessionStatus::Live
        } else {
            SessionStatus::Unknown
        };
        graph.session.last_known_generation = generation.map(str::to_string);
        store::write_record(
            &paths,
            RecordKind::Project,
            SYSTEM_TERMINAL_PROJECT_ID,
            10,
            &graph.project,
        )
        .unwrap();
        store::write_record(
            &paths,
            RecordKind::Workspace,
            SYSTEM_TERMINAL_WORKSPACE_ID,
            10,
            &graph.workspace,
        )
        .unwrap();
        store::write_record(
            &paths,
            RecordKind::Session,
            SYSTEM_TERMINAL_SESSION_ID,
            10,
            &graph.session,
        )
        .unwrap();
        let authority = ReservedProductShellStart::load(
            &paths,
            ReservedProductShellKind::SystemTerminal,
            &graph.session,
            &graph.workspace,
            vec!["/bin/sh".into()],
            80,
            24,
            11,
        )
        .unwrap();
        let graph = load_graph_snapshot(&paths, ReservedProductShellKind::SystemTerminal).unwrap();
        (paths, graph, authority, PathBuf::from(cwd))
    }

    fn enqueue_generation_a_release(paths: &AppPaths) {
        let target = SessionReleaseTarget::new(
            SYSTEM_TERMINAL_SESSION_ID,
            "generation-A",
            SessionRowPolicy::MatchingRowIsProof,
        )
        .unwrap();
        SessionReleaseService::new(paths)
            .enqueue_recovered(&[target], 12)
            .unwrap()
            .expect("one pending release target");
    }

    fn pending_release_count(paths: &AppPaths) -> i64 {
        let connection = crate::db::conn_for(paths.base()).unwrap();
        let connection = connection.lock().unwrap();
        connection
            .query_row("SELECT COUNT(*) FROM pending_session_releases", [], |row| {
                row.get(0)
            })
            .unwrap()
    }

    #[test]
    fn system_authority_allows_user_presentation_and_sibling_topology() {
        let temp = TempDir::new().unwrap();
        let (paths, _) = seed_reserved(&temp, ReservedProductShellKind::SystemTerminal);

        let sibling_session = SessionRecord {
            session_id: "user-sibling-session".into(),
            workspace_id: SYSTEM_TERMINAL_WORKSPACE_ID.into(),
            kind: SessionKind::Shell,
            launch: LaunchSpec::OptOut,
            cwd_resolved: temp.path().to_string_lossy().into_owned(),
            agent_task_id: None,
            created_at_ms: 5,
            last_attached_at_ms: 5,
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        store::write_record(
            &paths,
            RecordKind::Session,
            &sibling_session.session_id,
            5,
            &sibling_session,
        )
        .unwrap();
        crate::WindowLayoutService::new(&paths)
            .open_tab(
                SYSTEM_TERMINAL_WINDOW_ID,
                "user-sibling-tab",
                &sibling_session.session_id,
                "Sibling",
                false,
                AttentionState::default(),
                6,
            )
            .unwrap();
        let sibling_layout = WindowLayout {
            window_id: "user-sibling-window".into(),
            name: Some("Sibling window".into()),
            tabs: vec![tab(
                "user-sibling-window-tab",
                &sibling_session.session_id,
                "Other",
            )],
        };
        store::write_record(
            &paths,
            RecordKind::WindowLayout,
            &sibling_layout.window_id,
            7,
            &sibling_layout,
        )
        .unwrap();
        store::set_window_project(
            &paths,
            &sibling_layout.window_id,
            SYSTEM_TERMINAL_PROJECT_ID,
        )
        .unwrap();
        let mut project = match store::load_one::<Project>(
            &paths,
            RecordKind::Project,
            SYSTEM_TERMINAL_PROJECT_ID,
        )
        .unwrap()
        .unwrap()
        {
            LoadOutcome::Loaded(project) => project,
            other => panic!("expected current Project, got {other:?}"),
        };
        project.window_order.push(sibling_layout.window_id);
        store::write_record(
            &paths,
            RecordKind::Project,
            SYSTEM_TERMINAL_PROJECT_ID,
            8,
            &project,
        )
        .unwrap();

        let expected =
            load_graph_snapshot(&paths, ReservedProductShellKind::SystemTerminal).unwrap();
        ReservedProductShellStart::load(
            &paths,
            ReservedProductShellKind::SystemTerminal,
            &expected.session,
            &expected.workspace,
            vec!["/bin/sh".into(), "-l".into()],
            80,
            24,
            9,
        )
        .expect("legitimate System sibling topology remains authorized");
    }

    #[test]
    fn recovery_attention_is_mutable_but_extra_owned_workspace_is_contamination() {
        let temp = TempDir::new().unwrap();
        let (paths, _) = seed_reserved(&temp, ReservedProductShellKind::ProductRecovery);
        let mut layout = crate::WindowLayoutService::new(&paths)
            .load(PRODUCT_RECOVERY_WINDOW_ID)
            .unwrap()
            .unwrap();
        layout.tabs[0].attention = AttentionState {
            attention: Attention::NeedsInput,
            unseen: true,
            since_ms: 55,
            source: AttentionSource::Process,
        };
        store::write_record(
            &paths,
            RecordKind::WindowLayout,
            PRODUCT_RECOVERY_WINDOW_ID,
            10,
            &layout,
        )
        .unwrap();
        let expected =
            load_graph_snapshot(&paths, ReservedProductShellKind::ProductRecovery).unwrap();
        let authority = ReservedProductShellStart::load(
            &paths,
            ReservedProductShellKind::ProductRecovery,
            &expected.session,
            &expected.workspace,
            vec!["secret-product-shell".into(), "--private".into()],
            80,
            24,
            11,
        )
        .expect("attention does not alter Recovery topology authority");
        let debug = format!("{authority:?}");
        assert!(!debug.contains("secret-product-shell"));
        assert!(!debug.contains("--private"));

        let extra = Workspace {
            workspace_id: "contaminating-workspace".into(),
            project_id: PRODUCT_RECOVERY_PROJECT_ID.into(),
            root: temp.path().to_string_lossy().into_owned(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        };
        store::write_record(
            &paths,
            RecordKind::Workspace,
            &extra.workspace_id,
            12,
            &extra,
        )
        .unwrap();
        assert!(matches!(
            ReservedProductShellStart::load(
                &paths,
                ReservedProductShellKind::ProductRecovery,
                authority.session(),
                authority.workspace(),
                vec!["/bin/sh".into()],
                80,
                24,
                13,
            ),
            Err(SessionServiceError::AttachAuthorityLost { .. })
        ));
    }

    #[test]
    fn reserved_exact_attach_rejects_graph_change_before_daemon_io() {
        let temp = TempDir::new().unwrap();
        let (paths, graph, authority) = seed_live_system(&temp);
        enqueue_generation_a_release(&paths);
        let proof =
            ExistingSessionAttach::exact(authority.session(), authority.workspace(), 13).unwrap();
        let mut changed_project = graph.project.clone();
        changed_project.hidden = true;
        store::write_record(
            &paths,
            RecordKind::Project,
            SYSTEM_TERMINAL_PROJECT_ID,
            14,
            &changed_project,
        )
        .unwrap();

        let stub = StubDaemon::spawn(|requests, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert!(read_request(&mut reader, requests).is_none());
        });
        let client = DaemonClient::connect_for_generation_mutation_before(
            &stub.path,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let error = match SessionService::new(&paths).attach_existing_exact_for_renderer(
            client,
            &proof,
            Some(&authority),
        ) {
            Err(error) => error,
            Ok(_) => panic!("contaminated reserved graph must refuse before daemon IO"),
        };
        assert!(matches!(
            error,
            SessionServiceError::AttachAuthorityLost { .. }
        ));
        assert!(matches!(
            stub.requests.recv_timeout(Duration::from_secs(1)),
            Err(mpsc::RecvTimeoutError::Disconnected)
        ));
        assert_eq!(pending_release_count(&paths), 1);
        assert!(matches!(
            store::load_one::<SessionRecord>(
                &paths,
                RecordKind::Session,
                SYSTEM_TERMINAL_SESSION_ID,
            )
            .unwrap(),
            Some(LoadOutcome::Loaded(current)) if current == graph.session
        ));
    }

    #[test]
    fn reserved_exact_attach_rechecks_graph_after_grid_before_publication() {
        let temp = TempDir::new().unwrap();
        let (paths, graph, authority) = seed_live_system(&temp);
        enqueue_generation_a_release(&paths);
        let proof =
            ExistingSessionAttach::exact(authority.session(), authority.workspace(), 15).unwrap();

        let instance = "77777777777747778777777777777777";
        let stub = StubDaemon::spawn(move |requests, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut reader, requests).expect("DaemonInfo request")
                )
                .unwrap(),
                ClientRequest::DaemonInfo
            ));
            writeln!(stream, "{}", strict_daemon_info(instance)).unwrap();
            stream.flush().unwrap();
            let attach = serde_json::from_str::<ClientRequest>(
                &read_request(&mut reader, requests).expect("exact Offer Attach"),
            )
            .unwrap();
            let output_generation = match attach {
                ClientRequest::Attach {
                    id,
                    expected_session_generation: Some(generation),
                    output_generation: Some(output_generation),
                    handoff: Some(AttachmentHandoff::Offer { .. }),
                    ..
                } if id.0 == SYSTEM_TERMINAL_SESSION_ID && generation == "generation-A" => {
                    output_generation
                }
                other => panic!("unexpected exact Attach request: {other:?}"),
            };
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "grid",
                    "id": SYSTEM_TERMINAL_SESSION_ID,
                    "output_generation": output_generation,
                    "grid": {"generation": "generation-A", "revision": 8}
                })
            )
            .unwrap();
            stream.flush().unwrap();
            assert!(read_request(&mut reader, requests).is_none());
        });
        // `StubDaemon::spawn` first acquires the reserved-shell serial guard. Install the global
        // transaction hook only after that boundary so another fixed-ID reserved attach cannot
        // consume it while this test is waiting for its daemon turn.
        let mut changed_project = graph.project.clone();
        changed_project.hidden = true;
        let hook_paths = paths.clone();
        let hook_fired = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let hook_fired_worker = std::sync::Arc::clone(&hook_fired);
        let _hook = crate::store_sqlite::install_window_layout_test_hook(
            SYSTEM_TERMINAL_SESSION_ID,
            move |stage, _| {
                if stage == "after-exact-attach-grid-before-finalize"
                    && !hook_fired_worker.swap(true, std::sync::atomic::Ordering::SeqCst)
                {
                    store::write_record(
                        &hook_paths,
                        RecordKind::Project,
                        SYSTEM_TERMINAL_PROJECT_ID,
                        16,
                        &changed_project,
                    )
                    .unwrap();
                }
            },
        );
        let client = DaemonClient::connect_for_generation_mutation_before(
            &stub.path,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let error = match SessionService::new(&paths).attach_existing_exact_for_renderer(
            client,
            &proof,
            Some(&authority),
        ) {
            Err(error) => error,
            Ok(_) => panic!("post-Grid graph race must not return an Offer authority"),
        };
        assert!(matches!(
            error,
            SessionServiceError::AttachAuthorityLost { .. }
        ));
        assert!(hook_fired.load(std::sync::atomic::Ordering::SeqCst));
        assert_eq!(stub.collected_requests().len(), 2);
        assert_eq!(pending_release_count(&paths), 1);
        assert!(matches!(
            store::load_one::<SessionRecord>(
                &paths,
                RecordKind::Session,
                SYSTEM_TERMINAL_SESSION_ID,
            )
            .unwrap(),
            Some(LoadOutcome::Loaded(current)) if current == graph.session
        ));
    }

    #[test]
    fn deleted_recorded_cwd_keeps_reserved_live_attach_but_cannot_replay_missing() {
        let temp = TempDir::new().unwrap();
        let (paths, _graph, authority, cwd) =
            seed_system_with_recorded_cwd(&temp, Some("generation-A"));
        std::fs::remove_dir(&cwd).unwrap();
        let proof =
            ExistingSessionAttach::exact(authority.session(), authority.workspace(), 20).unwrap();
        let instance = "88888888888848889888888888888888";
        let attached_stub = StubDaemon::spawn(move |requests, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut reader, requests).expect("DaemonInfo request")
                )
                .unwrap(),
                ClientRequest::DaemonInfo
            ));
            writeln!(stream, "{}", strict_daemon_info(instance)).unwrap();
            stream.flush().unwrap();
            let attach = serde_json::from_str::<ClientRequest>(
                &read_request(&mut reader, requests).expect("exact Attach"),
            )
            .unwrap();
            let output_generation = match attach {
                ClientRequest::Attach {
                    id,
                    expected_session_generation: Some(generation),
                    output_generation: Some(output_generation),
                    handoff: None,
                    ..
                } if id.0 == SYSTEM_TERMINAL_SESSION_ID && generation == "generation-A" => {
                    output_generation
                }
                other => panic!("unexpected retained Attach: {other:?}"),
            };
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "grid",
                    "id": SYSTEM_TERMINAL_SESSION_ID,
                    "output_generation": output_generation,
                    "grid": {"generation": "generation-A", "revision": 9}
                })
            )
            .unwrap();
            stream.flush().unwrap();
            assert!(read_request(&mut reader, requests).is_none());
        });
        let client = DaemonClient::connect_for_generation_mutation_before(
            &attached_stub.path,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        assert!(matches!(
            SessionService::new(&paths).attach_existing_exact_headless(
                client,
                &proof,
                Some(&authority),
            ),
            Ok(ExactExistingAttach::Attached(_, None))
        ));
        assert_eq!(attached_stub.collected_requests().len(), 2);
        drop(attached_stub);

        // A separate exact graph proves typed Missing still cannot turn a deleted cwd into a Start
        // or a fallback retarget.
        let missing_temp = TempDir::new().unwrap();
        let (missing_paths, _graph, missing_authority, missing_cwd) =
            seed_system_with_recorded_cwd(&missing_temp, Some("generation-A"));
        std::fs::remove_dir(&missing_cwd).unwrap();
        let missing_proof = ExistingSessionAttach::exact(
            missing_authority.session(),
            missing_authority.workspace(),
            21,
        )
        .unwrap();
        let missing_instance = "9999999999994999a999999999999999";
        let missing_stub = StubDaemon::spawn(move |requests, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut reader, requests).expect("first DaemonInfo")
                )
                .unwrap(),
                ClientRequest::DaemonInfo
            ));
            writeln!(stream, "{}", strict_daemon_info(missing_instance)).unwrap();
            stream.flush().unwrap();
            let attach = serde_json::from_str::<ClientRequest>(
                &read_request(&mut reader, requests).expect("conditional Attach"),
            )
            .unwrap();
            assert!(matches!(
                attach,
                ClientRequest::Attach {
                    expected_session_generation: Some(ref generation),
                    handoff: None,
                    ..
                } if generation == "generation-A"
            ));
            writeln!(
                stream,
                "{}",
                serde_json::json!({
                    "ev": "session_attach_refused",
                    "id": SYSTEM_TERMINAL_SESSION_ID,
                    "expected_generation": "generation-A",
                    "daemon_instance_id": missing_instance,
                    "reason": "missing"
                })
            )
            .unwrap();
            stream.flush().unwrap();
            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut reader, requests).expect("same-peer DaemonInfo")
                )
                .unwrap(),
                ClientRequest::DaemonInfo
            ));
            writeln!(stream, "{}", strict_daemon_info(missing_instance)).unwrap();
            stream.flush().unwrap();
            assert!(read_request(&mut reader, requests).is_none());
        });
        let client = DaemonClient::connect_for_generation_mutation_before(
            &missing_stub.path,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let ExactExistingAttach::StartIfAbsent(absent) = SessionService::new(&missing_paths)
            .attach_existing_exact_headless(client, &missing_proof, Some(&missing_authority))
            .unwrap()
        else {
            panic!("typed Missing must return one-shot Absent authority")
        };
        let error = SessionService::new(&missing_paths)
            .start_retained_absent_headless(
                absent,
                ExistingSessionMissingStart::ReservedProductShell(&missing_authority),
            )
            .unwrap_err();
        assert!(matches!(error, SessionServiceError::InvalidCwd { .. }));
        let requests = missing_stub.collected_requests();
        assert_eq!(requests.len(), 3);
        assert!(requests
            .iter()
            .all(|request| !request.contains("start_session")));
    }

    #[test]
    fn generation_none_deleted_cwd_sends_no_attach_or_start() {
        let temp = TempDir::new().unwrap();
        let (paths, _graph, authority, cwd) = seed_system_with_recorded_cwd(&temp, None);
        std::fs::remove_dir(&cwd).unwrap();
        let proof =
            ExistingSessionAttach::exact(authority.session(), authority.workspace(), 30).unwrap();
        let instance = "aaaaaaaaaaaa4aaabaaaaaaaaaaaaaaa";
        let stub = StubDaemon::spawn(move |requests, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            assert!(matches!(
                serde_json::from_str::<ClientRequest>(
                    &read_request(&mut reader, requests).expect("peer DaemonInfo")
                )
                .unwrap(),
                ClientRequest::DaemonInfo
            ));
            writeln!(stream, "{}", strict_daemon_info(instance)).unwrap();
            stream.flush().unwrap();
            assert!(read_request(&mut reader, requests).is_none());
        });
        let client = DaemonClient::connect_for_generation_mutation_before(
            &stub.path,
            Duration::from_secs(2),
            Instant::now() + Duration::from_secs(3),
        )
        .unwrap();
        let ExactExistingAttach::StartIfAbsent(absent) = SessionService::new(&paths)
            .attach_existing_exact_headless(client, &proof, Some(&authority))
            .unwrap()
        else {
            panic!("generation None must skip Attach and retain only Absent authority")
        };
        let error = SessionService::new(&paths)
            .start_retained_absent_headless(
                absent,
                ExistingSessionMissingStart::ReservedProductShell(&authority),
            )
            .unwrap_err();
        assert!(matches!(error, SessionServiceError::InvalidCwd { .. }));
        let requests = stub.collected_requests();
        assert_eq!(requests.len(), 1);
        assert!(requests.iter().all(|request| {
            !request.contains("\"op\":\"attach\"") && !request.contains("start_session")
        }));
    }

    #[test]
    fn reserved_finalizer_rechecks_graph_inside_its_immediate_transaction() {
        let temp = TempDir::new().unwrap();
        let (paths, graph) = seed_reserved(&temp, ReservedProductShellKind::SystemTerminal);
        let authority = ReservedProductShellStart::load(
            &paths,
            ReservedProductShellKind::SystemTerminal,
            &graph.session,
            &graph.workspace,
            vec!["/bin/sh".into()],
            80,
            24,
            20,
        )
        .unwrap();
        let mut changed_project = graph.project.clone();
        changed_project.hidden = true;
        store::write_record(
            &paths,
            RecordKind::Project,
            SYSTEM_TERMINAL_PROJECT_ID,
            21,
            &changed_project,
        )
        .unwrap();
        let mut replacement = graph.session.clone();
        replacement.status = SessionStatus::Live;
        replacement.last_known_generation = Some("generation-B".into());
        replacement.last_attached_at_ms = 22;
        let outcome = store::finalize_session_attach_if_unchanged_with_workspace_and_guard(
            &paths,
            &graph.session,
            &replacement,
            Some(&graph.workspace),
            "generation-B",
            22,
            |transaction| authority.graph_matches_connection(transaction),
        )
        .unwrap();
        assert_eq!(outcome, ConditionalSessionAttachFinalize::Changed);
        assert!(matches!(
            store::load_one::<SessionRecord>(
                &paths,
                RecordKind::Session,
                SYSTEM_TERMINAL_SESSION_ID,
            )
            .unwrap(),
            Some(LoadOutcome::Loaded(current)) if current == graph.session
        ));
    }

    #[test]
    fn reserved_authority_rejects_byte_identical_session_recreation_by_epoch() {
        let temp = TempDir::new().unwrap();
        let (paths, graph) = seed_reserved(&temp, ReservedProductShellKind::SystemTerminal);
        let authority = ReservedProductShellStart::load(
            &paths,
            ReservedProductShellKind::SystemTerminal,
            &graph.session,
            &graph.workspace,
            vec!["/bin/sh".into()],
            80,
            24,
            30,
        )
        .unwrap();
        assert!(
            store::delete_record(&paths, RecordKind::Session, SYSTEM_TERMINAL_SESSION_ID,).unwrap()
        );
        store::write_record(
            &paths,
            RecordKind::Session,
            SYSTEM_TERMINAL_SESSION_ID,
            31,
            &graph.session,
        )
        .unwrap();
        assert!(!authority.graph_matches_in_snapshot(&paths).unwrap());
    }
}
