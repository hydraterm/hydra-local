//! One bounded, latest-value worker for provider-history discovery.
//!
//! The foreground renderer listener owns dashboard intent ordering. Provider stores can contain
//! thousands of files, though, so filesystem discovery must never execute on that listener. Each
//! window owns exactly one worker. Its pending slot is coalescing rather than FIFO: a newer request
//! cancels and replaces queued work, while cooperative cancellation preempts a scan already running.

use std::path::PathBuf;
use std::sync::{mpsc, Arc, Condvar, Mutex};
use std::thread::JoinHandle;
use std::time::{Duration, Instant};

use maestro_app::agent_history::{
    self, AgentHistorySession, AgentPreviewLine, FolderSessionListing, HistoryCancellationToken,
};
use maestro_shell::paths::AppPaths;

const HISTORY_WORKER_SHUTDOWN_TIMEOUT: Duration = Duration::from_millis(500);
const HISTORY_WORKER_JOIN_POLL: Duration = Duration::from_millis(5);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum HistoryRequestKind {
    List,
    Preview,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HistoryListResponse {
    Visible,
    Hidden,
    Mutation { ok: bool },
}

#[derive(Debug)]
enum HistoryWork {
    List {
        request_id: String,
        paths: AppPaths,
        agent: String,
        cwd: PathBuf,
        response: HistoryListResponse,
        cancellation: HistoryCancellationToken,
    },
    Preview {
        request_id: String,
        paths: AppPaths,
        agent: String,
        cwd: PathBuf,
        session_id: String,
        max_lines: usize,
        cancellation: HistoryCancellationToken,
    },
    Delete {
        request_id: String,
        paths: AppPaths,
        agent: String,
        cwd: PathBuf,
        session_id: String,
        cancellation: HistoryCancellationToken,
    },
}

impl HistoryWork {
    fn kind(&self) -> HistoryRequestKind {
        match self {
            Self::List { .. } | Self::Delete { .. } => HistoryRequestKind::List,
            Self::Preview { .. } => HistoryRequestKind::Preview,
        }
    }

    fn cancel(&self) {
        match self {
            Self::List { cancellation, .. }
            | Self::Preview { cancellation, .. }
            | Self::Delete { cancellation, .. } => cancellation.cancel(),
        }
    }
}

#[derive(Debug)]
pub(crate) enum HistoryResult {
    FolderSessions {
        request_id: String,
        sessions: Vec<AgentHistorySession>,
    },
    HiddenSessions {
        request_id: String,
        sessions: Vec<AgentHistorySession>,
    },
    SessionMutation {
        request_id: String,
        ok: bool,
        sessions: Vec<AgentHistorySession>,
    },
    Preview {
        request_id: String,
        lines: Vec<AgentPreviewLine>,
    },
}

impl HistoryResult {
    pub(crate) fn request_id(&self) -> &str {
        match self {
            Self::FolderSessions { request_id, .. }
            | Self::HiddenSessions { request_id, .. }
            | Self::SessionMutation { request_id, .. }
            | Self::Preview { request_id, .. } => request_id,
        }
    }

    pub(crate) fn kind(&self) -> HistoryRequestKind {
        match self {
            Self::FolderSessions { .. }
            | Self::HiddenSessions { .. }
            | Self::SessionMutation { .. } => HistoryRequestKind::List,
            Self::Preview { .. } => HistoryRequestKind::Preview,
        }
    }
}

#[derive(Debug)]
struct ActiveRequest {
    request_id: String,
    cancellation: HistoryCancellationToken,
}

impl ActiveRequest {
    fn cancel(self) {
        self.cancellation.cancel();
    }
}

#[derive(Default)]
struct WorkQueueState {
    pending_list: Option<HistoryWork>,
    pending_preview: Option<HistoryWork>,
    shutdown: bool,
}

#[derive(Default)]
struct LatestWorkQueue {
    state: Mutex<WorkQueueState>,
    ready: Condvar,
}

impl LatestWorkQueue {
    fn submit(&self, work: HistoryWork) -> bool {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        if state.shutdown {
            work.cancel();
            return false;
        }
        let slot = match work.kind() {
            HistoryRequestKind::List => &mut state.pending_list,
            HistoryRequestKind::Preview => &mut state.pending_preview,
        };
        if let Some(superseded) = slot.replace(work) {
            superseded.cancel();
        }
        self.ready.notify_one();
        true
    }

    fn take(&self) -> Option<HistoryWork> {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        loop {
            if state.shutdown {
                cancel_pending(&mut state.pending_list);
                cancel_pending(&mut state.pending_preview);
                return None;
            }
            // Preview is the user's foreground action once the picker is populated. Prefer it over
            // a queued list while keeping one coalescing slot for each request class.
            if let Some(work) = state
                .pending_preview
                .take()
                .or_else(|| state.pending_list.take())
            {
                return Some(work);
            }
            state = self
                .ready
                .wait(state)
                .unwrap_or_else(|poison| poison.into_inner());
        }
    }

    fn shutdown(&self) {
        let mut state = self
            .state
            .lock()
            .unwrap_or_else(|poison| poison.into_inner());
        state.shutdown = true;
        cancel_pending(&mut state.pending_list);
        cancel_pending(&mut state.pending_preview);
        self.ready.notify_all();
    }
}

fn cancel_pending(slot: &mut Option<HistoryWork>) {
    if let Some(pending) = slot.take() {
        pending.cancel();
    }
}

/// Window-local owner for the single filesystem worker.
pub(crate) struct HistoryDiscovery {
    work: Arc<LatestWorkQueue>,
    result_rx: mpsc::Receiver<HistoryResult>,
    immediate_results: Vec<HistoryResult>,
    active_list: Option<ActiveRequest>,
    active_preview: Option<ActiveRequest>,
    worker: Option<JoinHandle<()>>,
}

impl HistoryDiscovery {
    pub(crate) fn spawn() -> Self {
        let work = Arc::new(LatestWorkQueue::default());
        let (result_tx, result_rx) = mpsc::channel();
        let worker_queue = Arc::clone(&work);
        let worker = match std::thread::Builder::new()
            .name("maestro-history-discovery".to_string())
            .spawn(move || run_worker(worker_queue, result_tx))
        {
            Ok(worker) => Some(worker),
            Err(error) => {
                eprintln!(
                    "hydra agent-history worker could not start; requests resolve empty (non-fatal): {error}"
                );
                None
            }
        };
        Self {
            work,
            result_rx,
            immediate_results: Vec::new(),
            active_list: None,
            active_preview: None,
            worker,
        }
    }

    pub(crate) fn list(
        &mut self,
        request_id: String,
        paths: AppPaths,
        agent: String,
        cwd: PathBuf,
    ) {
        self.queue_list(request_id, paths, agent, cwd, HistoryListResponse::Visible);
    }

    pub(crate) fn list_hidden(
        &mut self,
        request_id: String,
        paths: AppPaths,
        agent: String,
        cwd: PathBuf,
    ) {
        self.queue_list(request_id, paths, agent, cwd, HistoryListResponse::Hidden);
    }

    pub(crate) fn refresh_after_mutation(
        &mut self,
        request_id: String,
        paths: AppPaths,
        agent: String,
        cwd: PathBuf,
        ok: bool,
    ) {
        self.queue_list(
            request_id,
            paths,
            agent,
            cwd,
            HistoryListResponse::Mutation { ok },
        );
    }

    pub(crate) fn delete(
        &mut self,
        request_id: String,
        paths: AppPaths,
        agent: String,
        cwd: PathBuf,
        session_id: String,
    ) {
        cancel_slot(&mut self.active_list);
        let cancellation = HistoryCancellationToken::new();
        self.active_list = Some(ActiveRequest {
            request_id: request_id.clone(),
            cancellation: cancellation.clone(),
        });
        let work = HistoryWork::Delete {
            request_id: request_id.clone(),
            paths,
            agent,
            cwd,
            session_id,
            cancellation,
        };
        if self.worker.is_none() || !self.work.submit(work) {
            self.immediate_results.push(empty_list_result(
                request_id,
                HistoryListResponse::Mutation { ok: false },
            ));
        }
    }

    fn queue_list(
        &mut self,
        request_id: String,
        paths: AppPaths,
        agent: String,
        cwd: PathBuf,
        response: HistoryListResponse,
    ) {
        cancel_slot(&mut self.active_list);
        let cancellation = HistoryCancellationToken::new();
        self.active_list = Some(ActiveRequest {
            request_id: request_id.clone(),
            cancellation: cancellation.clone(),
        });
        let work = HistoryWork::List {
            request_id: request_id.clone(),
            paths,
            agent,
            cwd,
            response,
            cancellation,
        };
        if self.worker.is_none() || !self.work.submit(work) {
            self.immediate_results
                .push(empty_list_result(request_id, response));
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(crate) fn preview(
        &mut self,
        request_id: String,
        paths: AppPaths,
        agent: String,
        cwd: PathBuf,
        session_id: String,
        max_lines: usize,
    ) {
        cancel_slot(&mut self.active_preview);
        let cancellation = HistoryCancellationToken::new();
        self.active_preview = Some(ActiveRequest {
            request_id: request_id.clone(),
            cancellation: cancellation.clone(),
        });
        let work = HistoryWork::Preview {
            request_id: request_id.clone(),
            paths,
            agent,
            cwd,
            session_id,
            max_lines,
            cancellation,
        };
        if self.worker.is_none() || !self.work.submit(work) {
            self.immediate_results.push(HistoryResult::Preview {
                request_id,
                lines: Vec::new(),
            });
        }
    }

    pub(crate) fn cancel(&mut self, kind: HistoryRequestKind, request_id: &str) -> bool {
        let slot = self.slot_mut(kind);
        if slot
            .as_ref()
            .is_some_and(|active| active.request_id == request_id)
        {
            cancel_slot(slot);
            true
        } else {
            false
        }
    }

    pub(crate) fn cancel_all(&mut self) {
        cancel_slot(&mut self.active_list);
        cancel_slot(&mut self.active_preview);
    }

    /// Drain completed work and return only results that still own their request slot.
    pub(crate) fn take_ready(&mut self) -> Vec<HistoryResult> {
        let mut received = std::mem::take(&mut self.immediate_results);
        received.extend(self.result_rx.try_iter());
        let mut ready = Vec::new();
        for result in received {
            let slot = self.slot_mut(result.kind());
            let is_current = slot.as_ref().is_some_and(|active| {
                active.request_id == result.request_id() && !active.cancellation.is_cancelled()
            });
            if is_current {
                *slot = None;
                ready.push(result);
            }
        }
        ready
    }

    fn slot_mut(&mut self, kind: HistoryRequestKind) -> &mut Option<ActiveRequest> {
        match kind {
            HistoryRequestKind::List => &mut self.active_list,
            HistoryRequestKind::Preview => &mut self.active_preview,
        }
    }

    fn shutdown_worker(&mut self) {
        self.cancel_all();
        self.work.shutdown();
        let Some(worker) = self.worker.take() else {
            return;
        };
        let deadline = Instant::now() + HISTORY_WORKER_SHUTDOWN_TIMEOUT;
        while !worker.is_finished() && Instant::now() < deadline {
            std::thread::sleep(HISTORY_WORKER_JOIN_POLL);
        }
        if worker.is_finished() {
            if worker.join().is_err() {
                eprintln!("hydra agent-history worker panicked during shutdown (non-fatal)");
            }
        } else {
            eprintln!(
                "hydra agent-history worker did not stop within {}ms; detached after cancellation (non-fatal)",
                HISTORY_WORKER_SHUTDOWN_TIMEOUT.as_millis()
            );
        }
    }
}

impl Drop for HistoryDiscovery {
    fn drop(&mut self) {
        self.shutdown_worker();
    }
}

fn cancel_slot(slot: &mut Option<ActiveRequest>) {
    if let Some(active) = slot.take() {
        active.cancel();
    }
}

fn empty_list_result(request_id: String, response: HistoryListResponse) -> HistoryResult {
    match response {
        HistoryListResponse::Visible => HistoryResult::FolderSessions {
            request_id,
            sessions: Vec::new(),
        },
        HistoryListResponse::Hidden => HistoryResult::HiddenSessions {
            request_id,
            sessions: Vec::new(),
        },
        HistoryListResponse::Mutation { ok } => HistoryResult::SessionMutation {
            request_id,
            ok,
            sessions: Vec::new(),
        },
    }
}

fn list_result(
    request_id: String,
    response: HistoryListResponse,
    listing: FolderSessionListing,
) -> HistoryResult {
    match response {
        HistoryListResponse::Visible => HistoryResult::FolderSessions {
            request_id,
            sessions: listing.visible,
        },
        HistoryListResponse::Hidden => HistoryResult::HiddenSessions {
            request_id,
            sessions: listing.hidden,
        },
        HistoryListResponse::Mutation { ok } => HistoryResult::SessionMutation {
            request_id,
            ok,
            sessions: listing.visible,
        },
    }
}

fn run_worker(work: Arc<LatestWorkQueue>, result_tx: mpsc::Sender<HistoryResult>) {
    while let Some(request) = work.take() {
        match request {
            HistoryWork::List {
                request_id,
                paths,
                agent,
                cwd,
                response,
                cancellation,
            } => {
                if cancellation.is_cancelled() {
                    continue;
                }
                let Ok(listing) = agent_history::list_folder_sessions_partitioned_with_cancel(
                    &paths,
                    &agent,
                    &cwd,
                    &cancellation,
                ) else {
                    continue;
                };
                if !cancellation.is_cancelled()
                    && result_tx
                        .send(list_result(request_id, response, listing))
                        .is_err()
                {
                    break;
                }
            }
            HistoryWork::Preview {
                request_id,
                paths,
                agent,
                cwd,
                session_id,
                max_lines,
                cancellation,
            } => {
                if cancellation.is_cancelled() {
                    continue;
                }
                let Ok(lines) = agent_history::preview_folder_session_with_cancel(
                    &paths,
                    &agent,
                    &cwd,
                    &session_id,
                    max_lines,
                    &cancellation,
                ) else {
                    continue;
                };
                if !cancellation.is_cancelled()
                    && result_tx
                        .send(HistoryResult::Preview { request_id, lines })
                        .is_err()
                {
                    break;
                }
            }
            HistoryWork::Delete {
                request_id,
                paths,
                agent,
                cwd,
                session_id,
                cancellation,
            } => {
                if cancellation.is_cancelled() {
                    continue;
                }
                let deleted = agent_history::delete_folder_session_with_cancel(
                    &paths,
                    &agent,
                    &cwd,
                    &session_id,
                    &cancellation,
                );
                if let Err(error) = &deleted {
                    if cancellation.is_cancelled() {
                        continue;
                    }
                    eprintln!(
                        "hydra agent-history delete failed agent={agent:?} session={session_id:?} (non-fatal): {error}"
                    );
                }
                let Ok(listing) = agent_history::list_folder_sessions_partitioned_with_cancel(
                    &paths,
                    &agent,
                    &cwd,
                    &cancellation,
                ) else {
                    continue;
                };
                if !cancellation.is_cancelled()
                    && result_tx
                        .send(list_result(
                            request_id,
                            HistoryListResponse::Mutation {
                                ok: deleted.is_ok(),
                            },
                            listing,
                        ))
                        .is_err()
                {
                    break;
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn discovery_without_worker() -> HistoryDiscovery {
        let (_result_tx, result_rx) = mpsc::channel();
        HistoryDiscovery {
            work: Arc::new(LatestWorkQueue::default()),
            result_rx,
            immediate_results: Vec::new(),
            active_list: None,
            active_preview: None,
            worker: None,
        }
    }

    #[test]
    fn replacement_and_id_scoped_cancel_do_not_cancel_the_new_request() {
        let old = HistoryCancellationToken::new();
        let new = HistoryCancellationToken::new();
        let mut discovery = discovery_without_worker();
        discovery.active_list = Some(ActiveRequest {
            request_id: "old".to_string(),
            cancellation: old.clone(),
        });

        cancel_slot(&mut discovery.active_list);
        discovery.active_list = Some(ActiveRequest {
            request_id: "new".to_string(),
            cancellation: new.clone(),
        });
        assert!(old.is_cancelled());
        assert!(!discovery.cancel(HistoryRequestKind::List, "old"));
        assert!(!new.is_cancelled());
        assert!(discovery.cancel(HistoryRequestKind::List, "new"));
        assert!(new.is_cancelled());
    }

    #[test]
    fn cancelled_and_superseded_results_are_never_delivered() {
        let (result_tx, result_rx) = mpsc::channel();
        let current = HistoryCancellationToken::new();
        let mut discovery = HistoryDiscovery {
            work: Arc::new(LatestWorkQueue::default()),
            result_rx,
            immediate_results: Vec::new(),
            active_list: Some(ActiveRequest {
                request_id: "current".to_string(),
                cancellation: current,
            }),
            active_preview: None,
            worker: None,
        };
        result_tx
            .send(HistoryResult::FolderSessions {
                request_id: "stale".to_string(),
                sessions: Vec::new(),
            })
            .expect("queue stale result");
        assert!(discovery.take_ready().is_empty());

        result_tx
            .send(HistoryResult::FolderSessions {
                request_id: "current".to_string(),
                sessions: Vec::new(),
            })
            .expect("queue current result");
        assert_eq!(discovery.take_ready().len(), 1);
        assert!(discovery.active_list.is_none());
    }

    #[test]
    fn modal_close_cancels_list_and_preview_independently() {
        let list = HistoryCancellationToken::new();
        let preview = HistoryCancellationToken::new();
        let mut discovery = discovery_without_worker();
        discovery.active_list = Some(ActiveRequest {
            request_id: "list".to_string(),
            cancellation: list.clone(),
        });
        discovery.active_preview = Some(ActiveRequest {
            request_id: "preview".to_string(),
            cancellation: preview.clone(),
        });

        discovery.cancel_all();
        assert!(list.is_cancelled());
        assert!(preview.is_cancelled());
        assert!(discovery.active_list.is_none());
        assert!(discovery.active_preview.is_none());
    }

    #[test]
    fn latest_value_queue_cancels_and_replaces_pending_work() {
        let queue = LatestWorkQueue::default();
        let old = HistoryCancellationToken::new();
        let new = HistoryCancellationToken::new();
        let paths = AppPaths::with_base(PathBuf::from("/tmp/hydra-history-queue-test"));
        assert!(queue.submit(HistoryWork::List {
            request_id: "old".to_string(),
            paths: paths.clone(),
            agent: "codex".to_string(),
            cwd: PathBuf::from("/tmp"),
            response: HistoryListResponse::Visible,
            cancellation: old.clone(),
        }));
        assert!(queue.submit(HistoryWork::List {
            request_id: "new".to_string(),
            paths,
            agent: "codex".to_string(),
            cwd: PathBuf::from("/tmp"),
            response: HistoryListResponse::Visible,
            cancellation: new.clone(),
        }));
        assert!(old.is_cancelled());
        assert!(!new.is_cancelled());
        let work = queue.take().expect("latest work");
        assert!(matches!(
            work,
            HistoryWork::List { request_id, .. } if request_id == "new"
        ));
        queue.shutdown();
    }

    #[test]
    fn list_and_preview_keep_independent_bounded_pending_slots() {
        let queue = LatestWorkQueue::default();
        let paths = AppPaths::with_base(PathBuf::from("/tmp/hydra-history-two-slots"));
        let list_cancellation = HistoryCancellationToken::new();
        let preview_cancellation = HistoryCancellationToken::new();
        assert!(queue.submit(HistoryWork::List {
            request_id: "list".to_string(),
            paths: paths.clone(),
            agent: "codex".to_string(),
            cwd: PathBuf::from("/tmp"),
            response: HistoryListResponse::Visible,
            cancellation: list_cancellation.clone(),
        }));
        assert!(queue.submit(HistoryWork::Preview {
            request_id: "preview".to_string(),
            paths,
            agent: "codex".to_string(),
            cwd: PathBuf::from("/tmp"),
            session_id: "thread".to_string(),
            max_lines: 40,
            cancellation: preview_cancellation.clone(),
        }));
        assert!(!list_cancellation.is_cancelled());
        assert!(!preview_cancellation.is_cancelled());
        assert!(matches!(
            queue.take(),
            Some(HistoryWork::Preview { request_id, .. }) if request_id == "preview"
        ));
        assert!(matches!(
            queue.take(),
            Some(HistoryWork::List { request_id, .. }) if request_id == "list"
        ));
        queue.shutdown();
    }

    #[test]
    fn worker_start_failure_resolves_immediately_instead_of_waiting_for_timeout() {
        let mut discovery = discovery_without_worker();
        discovery.list(
            "list".to_string(),
            AppPaths::with_base(PathBuf::from("/tmp/hydra-history-no-worker")),
            "codex".to_string(),
            PathBuf::from("/tmp"),
        );
        assert!(matches!(
            discovery.take_ready().as_slice(),
            [HistoryResult::FolderSessions { request_id, sessions }]
                if request_id == "list" && sessions.is_empty()
        ));
    }

    #[test]
    fn real_worker_completes_latest_list_without_delivering_replaced_request() {
        const CHILD_MARKER: &str = "HYDRA_HISTORY_REAL_WORKER_CHILD";

        // HOME is process-global, while Rust runs tests in parallel. Isolate the provider fixture
        // in an exact-test child process instead of mutating this test process and relying on a
        // mutex that unrelated HOME readers do not share.
        if std::env::var_os(CHILD_MARKER).is_none() {
            let temp = tempfile::TempDir::new().expect("create worker fixture home");
            let project = temp.path().join("project");
            let codex_dir = temp.path().join(".codex/sessions/2026");
            std::fs::create_dir_all(&project).expect("create worker fixture project");
            std::fs::create_dir_all(&codex_dir).expect("create worker fixture provider store");
            let session_id = "11111111-1111-4111-8111-111111111111";
            std::fs::write(
                codex_dir.join("worker-root.jsonl"),
                format!(
                    "{}\n",
                    serde_json::json!({
                        "type": "session_meta",
                        "payload": {
                            "id": session_id,
                            "session_id": session_id,
                            "cwd": project.to_string_lossy(),
                            "source": "cli",
                            "title": "Real worker fixture"
                        }
                    })
                ),
            )
            .expect("write worker provider fixture");

            let test_name = std::thread::current()
                .name()
                .expect("test harness supplies the exact test name")
                .to_string();
            let status = std::process::Command::new(
                std::env::current_exe().expect("resolve current test executable"),
            )
            .arg("--exact")
            .arg(test_name)
            .arg("--nocapture")
            .env("HOME", temp.path())
            .env(CHILD_MARKER, "1")
            .status()
            .expect("run isolated real-worker test child");
            assert!(status.success(), "isolated real-worker child failed");
            return;
        }

        let home = PathBuf::from(std::env::var_os("HOME").expect("isolated HOME"));
        let project = home.join("project");
        let paths = AppPaths::with_base(home.join("app-state"));
        let mut discovery = HistoryDiscovery::spawn();
        assert!(
            discovery.worker.is_some(),
            "test must exercise a real worker"
        );

        discovery.list(
            "replaced".to_string(),
            paths.clone(),
            "codex".to_string(),
            project.clone(),
        );
        discovery.list("current".to_string(), paths, "codex".to_string(), project);

        let deadline = Instant::now() + Duration::from_secs(2);
        let mut delivered = Vec::new();
        while Instant::now() < deadline {
            delivered.extend(discovery.take_ready());
            if delivered
                .iter()
                .any(|result| result.request_id() == "current")
            {
                break;
            }
            std::thread::sleep(Duration::from_millis(5));
        }

        assert!(
            delivered
                .iter()
                .all(|result| result.request_id() != "replaced"),
            "the cancelled/replaced request must never be delivered"
        );
        assert_eq!(delivered.len(), 1, "only the latest request is deliverable");
        assert!(matches!(
            delivered.as_slice(),
            [HistoryResult::FolderSessions { request_id, sessions }]
                if request_id == "current"
                    && sessions.len() == 1
                    && sessions[0].id == "11111111-1111-4111-8111-111111111111"
        ));
    }
}
