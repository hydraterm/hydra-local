//! Ephemeral OpenCode permission and typed process-exit attention. One process-wide, coalesced
//! worker per app base observes retained grids; no task or attention records are written here.
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use maestro_shell::provider_attention::ObservedProvider;
use maestro_shell::{
    provider_attention::ProviderAttentionObservation as Observation, AgentTaskState, AppPaths,
    Attention, AttentionSource, AttentionState, DaemonClient, DashboardSnapshot,
    DashboardSnapshotService, LoadOutcome, RecordKind, SessionRecord, SessionStatus, WindowTabView,
};

const CADENCE: Duration = Duration::from_secs(2);
const MAX_GRIDS_PER_TICK: usize = 8;
const GRID_TIMEOUT: Duration = Duration::from_millis(150);

#[cfg(all(test, unix))]
#[path = "provider_attention_tests.rs"]
mod integration_tests;

#[cfg(all(test, unix))]
#[path = "provider_codex_attention_tests.rs"]
mod codex_tests;

#[cfg(test)]
#[path = "provider_exit_attention_tests.rs"]
mod exit_tests;

/// Observe a typed renderer exit after the durable generation-checked exit update succeeds.
/// Missing inventory or printed error text cannot call this path on their own. Recheck the record
/// here and at projection: a same-id replacement must never inherit this process error.
pub fn observe_exit(
    paths: &AppPaths,
    session_id: &str,
    code: Option<i32>,
    observed_generation: Option<&str>,
    outcome: maestro_shell::SessionExitObservation,
    now: u64,
) {
    use maestro_shell::SessionExitObservation::{AlreadyExited, MarkedExited};
    if code.is_none_or(|code| code == 0) || !matches!(outcome, MarkedExited | AlreadyExited) {
        return;
    }
    let Some(generation) = observed_generation.filter(|generation| !generation.is_empty()) else {
        return;
    };
    // Serialize validation+cache insertion with other exit observations. Otherwise an old record
    // read could overwrite a newer-generation signal inserted before this caller got the lock.
    let shared = broker(paths);
    let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
    let Ok(Some(LoadOutcome::Loaded(record))) =
        maestro_shell::store::load_one::<SessionRecord>(paths, RecordKind::Session, session_id)
    else {
        return;
    };
    if !eligible_exit(&record, generation) {
        return;
    }
    if state
        .exit_signals
        .get(session_id)
        .is_some_and(|signal| signal.generation == generation)
    {
        return; // Preserve the first timestamp; duplicates cannot rearm a user acknowledgement.
    }
    state.exit_signals.insert(
        session_id.to_owned(),
        ExitSignal {
            generation: generation.to_owned(),
            since: now,
            replayed: outcome == AlreadyExited,
        },
    );
    state.signals.remove(session_id);
    state.projection_revision = state.projection_revision.wrapping_add(1);
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ExitSignal {
    generation: String,
    since: u64,
    // After GUI restart no durable original exit timestamp exists. An AlreadyExited replay must
    // conservatively preserve any User clear instead of treating replay time as a fresh failure.
    replayed: bool,
}

fn eligible_exit(record: &SessionRecord, generation: &str) -> bool {
    if record.status != SessionStatus::Exited
        || record.last_known_generation.as_deref() != Some(generation)
    {
        return false;
    }
    provider_identity(record) == Some(ObservedProvider::OpenCode)
}

fn provider_identity(record: &SessionRecord) -> Option<ObservedProvider> {
    let (provider, params) = record
        .launch
        .fresh_provider_audit()
        .map(|(provider, params, _)| (provider, params))
        .or_else(|| {
            record
                .launch
                .provider_recipe()
                .map(|(provider, params, _)| (provider, params))
        })?;
    let identity = match provider {
        "opencode" => ObservedProvider::OpenCode,
        "codex" => ObservedProvider::Codex,
        _ => return None,
    };
    let argv = std::iter::once(provider.to_owned())
        .chain(params.iter().cloned())
        .collect::<Vec<_>>();
    maestro_shell::restart_recipe::is_strict_prepared_provider_launch(provider, &argv)
        .then_some(identity)
}

#[derive(Clone, Debug)]
struct Signal {
    provider: ObservedProvider,
    generation: String,
    revision: u64,
    waiting_since: Option<u64>,
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ProviderLifetime {
    provider: ObservedProvider,
    generation: String,
}

#[derive(Default)]
struct Broker {
    socket: PathBuf,
    last_started: Option<Instant>,
    busy: bool,
    cursor: usize,
    signals: HashMap<String, Signal>,
    exit_signals: HashMap<String, ExitSignal>,
    projection_revision: u64,
}

type SharedBroker = Arc<Mutex<Broker>>;
static BROKERS: OnceLock<Mutex<HashMap<PathBuf, SharedBroker>>> = OnceLock::new();

fn broker(paths: &AppPaths) -> SharedBroker {
    BROKERS
        .get_or_init(Default::default)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .entry(paths.base().to_owned())
        .or_default()
        .clone()
}

fn now_ms() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as u64
}

fn records(paths: &AppPaths) -> Option<HashMap<String, SessionRecord>> {
    Some(
        maestro_shell::store::load_all::<SessionRecord>(paths, RecordKind::Session)
            .ok()?
            .into_iter()
            .filter_map(|loaded| match loaded {
                LoadOutcome::Loaded(record) => Some((record.session_id.clone(), record)),
                _ => None,
            })
            .collect(),
    )
}

fn eligible(record: &SessionRecord, generation: &str) -> Option<ObservedProvider> {
    if record.status != SessionStatus::Live
        || record.last_known_generation.as_deref() != Some(generation)
    {
        return None;
    }
    provider_identity(record)
}

/// Called on every activated listener iteration, not just idle. The callback publishes only a
/// semantic change, and a failed delivery is retried. Daemon work is shared/coalesced independently
/// of event traffic; this never invokes session reconciliation or release/recovery scheduling.
pub fn service(
    paths: &AppPaths,
    socket: &Path,
    last_published: &mut u64,
    publish: impl FnOnce() -> bool,
) {
    schedule(paths, socket);
    let revision = broker(paths)
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .projection_revision;
    if revision != *last_published && publish() {
        *last_published = revision;
    }
}

fn waiting_projection(state: &Broker) -> BTreeMap<String, (ObservedProvider, String, u64)> {
    state
        .signals
        .iter()
        .filter_map(|(id, signal)| {
            signal.waiting_since.map(|since| {
                (
                    id.clone(),
                    (signal.provider, signal.generation.clone(), since),
                )
            })
        })
        .collect()
}

/// At most one live inventory and eight grids per shared turn. Inventory is queried only when
/// represented provider records exist. Exact live generation is daemon authority even when idle
/// record reconciliation is starved; a retained grid alone never proves a live permission request.
fn schedule(paths: &AppPaths, socket: &Path) {
    let shared = broker(paths);
    {
        let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
        if state.busy || state.last_started.is_some_and(|at| at.elapsed() < CADENCE) {
            return;
        }
        if state.socket != socket {
            let replace_socket = !state.socket.as_os_str().is_empty();
            if !waiting_projection(&state).is_empty()
                || (replace_socket && !state.exit_signals.is_empty())
            {
                state.projection_revision = state.projection_revision.wrapping_add(1);
            }
            state.signals.clear();
            if replace_socket {
                state.exit_signals.clear();
            }
            state.socket = socket.to_owned();
        }
        state.busy = true;
        state.last_started = Some(Instant::now());
    }
    let paths = paths.clone();
    let socket = socket.to_owned();
    let worker_state = shared.clone();
    if std::thread::Builder::new()
        .name("provider-attention".into())
        .spawn(move || {
            // Reuse this existing cadence only to invalidate cached exits; never poll for an exit
            // code or derive one from the live inventory. Projection performs the same recheck.
            let _ = current_exit_signals(&paths);
            let Some(mut cohort) = observation_cohort(&paths) else {
                // Failed metadata reads are not proof that a permission was answered. Keep the
                // semantic cache, but projection still requires a fresh valid lifetime record.
                worker_state.lock().unwrap_or_else(|e| e.into_inner()).busy = false;
                return;
            };
            if !cohort.is_empty() {
                let live = DaemonClient::connect_with_timeout(&socket, GRID_TIMEOUT)
                    .ok()
                    .and_then(|mut client| client.current_live_generations().ok());
                let Some(live) = live else {
                    // Unknown transport/protocol status is not positive recovery or completion.
                    worker_state.lock().unwrap_or_else(|e| e.into_inner()).busy = false;
                    return;
                };
                cohort.retain(|id, lifetime| {
                    live.generation_for(id) == Some(lifetime.generation.as_str())
                });
            }
            let batch = {
                let mut state = worker_state.lock().unwrap_or_else(|e| e.into_inner());
                let before = waiting_projection(&state);
                let batch = next_batch(&mut state, cohort);
                if waiting_projection(&state) != before {
                    state.projection_revision = state.projection_revision.wrapping_add(1);
                }
                batch
            };
            for (id, lifetime) in batch {
                // Each request uses a fresh read-only connection: a timeout cannot misattribute a
                // delayed reply to the next session. No Attach, history or input is ever sent.
                let observation = DaemonClient::connect_with_timeout(&socket, GRID_TIMEOUT)
                    .ok()
                    .and_then(|mut client| client.current_grid_frame(&id).ok())
                    .and_then(|frame| {
                        maestro_renderer::provider_observation::observe_provider_grid(
                            &frame,
                            &id,
                            &lifetime.generation,
                            lifetime.provider,
                        )
                    });
                if let Some(observation) = observation {
                    let mut state = worker_state.lock().unwrap_or_else(|e| e.into_inner());
                    let before = waiting_projection(&state);
                    accept(
                        &mut state.signals,
                        id,
                        lifetime.generation,
                        lifetime.provider,
                        observation.revision,
                        observation.state,
                        now_ms(),
                    );
                    if waiting_projection(&state) != before {
                        state.projection_revision = state.projection_revision.wrapping_add(1);
                    }
                }
            }
            worker_state.lock().unwrap_or_else(|e| e.into_inner()).busy = false;
        })
        .is_err()
    {
        shared.lock().unwrap_or_else(|e| e.into_inner()).busy = false;
    }
}

fn next_batch(
    state: &mut Broker,
    cohort: BTreeMap<String, ProviderLifetime>,
) -> Vec<(String, ProviderLifetime)> {
    state.signals.retain(|id, signal| {
        cohort.get(id).is_some_and(|lifetime| {
            lifetime.generation == signal.generation && lifetime.provider == signal.provider
        })
    });
    let ordered = cohort.into_iter().collect::<Vec<_>>();
    let count = ordered.len().min(MAX_GRIDS_PER_TICK);
    let batch = (0..count)
        .map(|offset| ordered[(state.cursor + offset) % ordered.len()].clone())
        .collect();
    state.cursor = if ordered.is_empty() {
        0
    } else {
        (state.cursor + count) % ordered.len()
    };
    batch
}

fn observation_cohort(paths: &AppPaths) -> Option<BTreeMap<String, ProviderLifetime>> {
    let snapshot = DashboardSnapshotService::new(paths).snapshot(None).ok()?;
    let represented: HashSet<_> = snapshot
        .projects
        .iter()
        .flat_map(|p| &p.windows)
        .chain(&snapshot.unassigned_windows)
        .flat_map(|w| &w.tabs)
        .map(|tab| tab.session_id.as_str())
        .collect();
    let records = records(paths)?;
    Some(
        records
            .values()
            .filter_map(|record| {
                let generation = record.last_known_generation.as_deref()?;
                let provider = eligible(record, generation)?;
                represented.contains(record.session_id.as_str()).then(|| {
                    (
                        record.session_id.clone(),
                        ProviderLifetime {
                            provider,
                            generation: generation.to_owned(),
                        },
                    )
                })
            })
            .collect(),
    )
}

fn accept(
    signals: &mut HashMap<String, Signal>,
    id: String,
    generation: String,
    provider: ObservedProvider,
    revision: u64,
    observation: Observation,
    now: u64,
) {
    let signal = signals.entry(id).or_insert_with(|| Signal {
        provider,
        generation: generation.clone(),
        revision: 0,
        waiting_since: None,
    });
    if signal.generation != generation || signal.provider != provider {
        *signal = Signal {
            provider,
            generation,
            revision: 0,
            waiting_since: None,
        };
    }
    if revision < signal.revision {
        return;
    }
    signal.revision = revision;
    match observation {
        Observation::Waiting => {
            signal.waiting_since.get_or_insert(now);
        }
        Observation::Working | Observation::Idle => signal.waiting_since = None,
        // Unknown output/disconnect is not proof that the user answered, completed or failed.
        Observation::Unknown => {}
    }
}

fn project(
    signal: &Signal,
    attention: &mut AttentionState,
    task: Option<AgentTaskState>,
    needs_attention: &mut bool,
) {
    let Some(since) = signal.waiting_since else {
        return;
    };
    project_attention(
        since,
        Attention::NeedsInput,
        AttentionSource::Agent,
        false,
        attention,
        task,
        needs_attention,
    );
}

fn project_attention(
    since: u64,
    kind: Attention,
    source: AttentionSource,
    replayed: bool,
    attention: &mut AttentionState,
    task: Option<AgentTaskState>,
    needs_attention: &mut bool,
) {
    if attention.attention == Attention::Error
        || task.is_some_and(|state| state != AgentTaskState::Running)
        || (attention.source == AttentionSource::User
            && (replayed || attention.attention != Attention::None || attention.since_ms >= since))
    {
        return;
    }
    *attention = AttentionState {
        attention: kind,
        unseen: true,
        since_ms: since,
        source,
    };
    *needs_attention = true;
}

fn current_exit_signals(paths: &AppPaths) -> HashMap<String, ExitSignal> {
    let shared = broker(paths);
    let observed = shared
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .exit_signals
        .clone();
    if observed.is_empty() {
        return HashMap::new();
    }
    let Some(records) = records(paths) else {
        return HashMap::new(); // Failed reads prove no invalidation; do not rewrite the cache.
    };
    let mut signals = observed.clone();
    signals.retain(|id, signal| {
        records
            .get(id)
            .is_some_and(|record| eligible_exit(record, &signal.generation))
    });
    let mut state = shared.lock().unwrap_or_else(|e| e.into_inner());
    let before = state.exit_signals.len();
    // Only prune the exact entries this record snapshot checked; concurrent new observations
    // must not be invalidated using a record read that preceded their insertion.
    state
        .exit_signals
        .retain(|id, signal| observed.get(id) != Some(signal) || signals.contains_key(id));
    if state.exit_signals.len() != before {
        state.projection_revision = state.projection_revision.wrapping_add(1);
    }
    signals
}

fn current_signals(paths: &AppPaths) -> HashMap<String, Signal> {
    let shared = broker(paths);
    let mut signals = shared
        .lock()
        .unwrap_or_else(|e| e.into_inner())
        .signals
        .clone();
    if signals.is_empty() {
        return signals;
    }
    let Some(records) = records(paths) else {
        return HashMap::new();
    };
    // Recheck the durable lifetime/provider at projection time, not just when a worker began.
    signals.retain(|id, signal| {
        records
            .get(id)
            .is_some_and(|record| eligible(record, &signal.generation) == Some(signal.provider))
    });
    signals
}

/// Overlay only a temporary view. Explicit task states and durable/user/error signals are never
/// rewritten. Positive recovery merely removes OUR overlay, exposing the original state again.
pub fn apply_dashboard(paths: &AppPaths, snapshot: &mut DashboardSnapshot) {
    let signals = current_signals(paths);
    let exits = current_exit_signals(paths);
    for tab in snapshot
        .projects
        .iter_mut()
        .flat_map(|p| &mut p.windows)
        .chain(&mut snapshot.unassigned_windows)
        .flat_map(|w| &mut w.tabs)
    {
        if let Some(signal) = signals.get(&tab.session_id) {
            project(
                signal,
                &mut tab.attention,
                tab.agent_task_state,
                &mut tab.needs_attention,
            );
        }
        if let Some(signal) = exits.get(&tab.session_id) {
            project_attention(
                signal.since,
                Attention::Error,
                AttentionSource::Process,
                signal.replayed,
                &mut tab.attention,
                tab.agent_task_state,
                &mut tab.needs_attention,
            );
        }
    }
}

pub(crate) fn apply_tab_views(paths: &AppPaths, views: &mut [WindowTabView]) {
    let signals = current_signals(paths);
    let exits = current_exit_signals(paths);
    for tab in views {
        if let Some(signal) = signals.get(&tab.session_id) {
            project(
                signal,
                &mut tab.attention,
                tab.agent_task_state,
                &mut tab.needs_attention,
            );
        }
        if let Some(signal) = exits.get(&tab.session_id) {
            project_attention(
                signal.since,
                Attention::Error,
                AttentionSource::Process,
                signal.replayed,
                &mut tab.attention,
                tab.agent_task_state,
                &mut tab.needs_attention,
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn signal() -> Signal {
        Signal {
            provider: ObservedProvider::OpenCode,
            generation: "generation".into(),
            revision: 1,
            waiting_since: Some(10),
        }
    }

    fn accept(
        signals: &mut HashMap<String, Signal>,
        id: String,
        generation: String,
        revision: u64,
        observation: Observation,
        now: u64,
    ) {
        super::accept(
            signals,
            id,
            generation,
            ObservedProvider::OpenCode,
            revision,
            observation,
            now,
        );
    }

    #[test]
    fn unlinked_and_running_tasks_receive_only_ephemeral_attention() {
        for task in [None, Some(AgentTaskState::Running)] {
            let mut attention = AttentionState::default();
            let mut needs = false;
            project(&signal(), &mut attention, task, &mut needs);
            assert_eq!(attention.attention, Attention::NeedsInput);
            assert_eq!(attention.source, AttentionSource::Agent);
            assert!(needs);
        }
    }

    #[test]
    fn explicit_task_user_and_error_signals_win() {
        for task in [
            AgentTaskState::Draft,
            AgentTaskState::WaitingOnUser,
            AgentTaskState::Blocked,
            AgentTaskState::Succeeded,
            AgentTaskState::Failed,
            AgentTaskState::Cancelled,
        ] {
            let original = AttentionState::default();
            let mut attention = original;
            let mut needs = true;
            project(&signal(), &mut attention, Some(task), &mut needs);
            assert_eq!(attention, original);
            assert!(needs);
        }
        for original in [
            AttentionState {
                attention: Attention::Error,
                ..Default::default()
            },
            AttentionState {
                source: AttentionSource::User,
                attention: Attention::Activity,
                ..Default::default()
            },
            AttentionState {
                source: AttentionSource::User,
                since_ms: 10,
                ..Default::default()
            },
        ] {
            let mut attention = original;
            let mut needs = false;
            project(&signal(), &mut attention, None, &mut needs);
            assert_eq!(attention, original);
            assert!(!needs);
        }
    }

    #[test]
    fn positive_recovery_clears_only_observer_and_a_new_wait_survives_old_ack() {
        let mut signals = HashMap::new();
        accept(
            &mut signals,
            "s".into(),
            "g".into(),
            1,
            Observation::Waiting,
            10,
        );
        accept(
            &mut signals,
            "s".into(),
            "g".into(),
            2,
            Observation::Waiting,
            20,
        );
        assert_eq!(signals["s"].waiting_since, Some(10));
        accept(
            &mut signals,
            "s".into(),
            "g".into(),
            3,
            Observation::Working,
            30,
        );
        assert_eq!(signals["s"].waiting_since, None);
        accept(
            &mut signals,
            "s".into(),
            "g".into(),
            4,
            Observation::Idle,
            40,
        );
        assert_eq!(signals["s"].waiting_since, None);
        accept(
            &mut signals,
            "s".into(),
            "g".into(),
            5,
            Observation::Waiting,
            50,
        );
        let mut attention = AttentionState {
            source: AttentionSource::User,
            since_ms: 20,
            ..Default::default()
        };
        let mut needs = false;
        project(&signals["s"], &mut attention, None, &mut needs);
        assert_eq!(attention.attention, Attention::NeedsInput);
        assert_eq!(attention.since_ms, 50);
    }

    #[test]
    fn unknown_and_old_revisions_never_manufacture_recovery() {
        let mut signals = HashMap::new();
        accept(
            &mut signals,
            "s".into(),
            "g".into(),
            5,
            Observation::Waiting,
            10,
        );
        accept(
            &mut signals,
            "s".into(),
            "g".into(),
            6,
            Observation::Unknown,
            20,
        );
        accept(
            &mut signals,
            "s".into(),
            "g".into(),
            4,
            Observation::Idle,
            30,
        );
        assert_eq!(signals["s"].waiting_since, Some(10));
        assert_eq!(signals["s"].revision, 6);
        accept(
            &mut signals,
            "s".into(),
            "new".into(),
            1,
            Observation::Unknown,
            40,
        );
        assert_eq!(signals["s"].waiting_since, None);
    }

    #[test]
    fn arbitrary_custom_and_wrong_generation_are_not_observed() {
        use maestro_shell::{LaunchSpec, SessionKind};
        let mut record = SessionRecord {
            session_id: "s".into(),
            workspace_id: "w".into(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::KnownSafe {
                launch_spec_id: "opencode".into(),
                params: vec![],
            },
            cwd_resolved: "/synthetic".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: Some("g".into()),
            status: SessionStatus::Live,
        };
        assert_eq!(eligible(&record, "g"), Some(ObservedProvider::OpenCode));
        assert_eq!(eligible(&record, "other"), None);
        record.launch = LaunchSpec::OptOut;
        assert_eq!(eligible(&record, "g"), None);
    }

    #[test]
    fn bounded_round_robin_covers_all_retained_panes_and_invalidates_removed_lifetimes() {
        let cohort: BTreeMap<String, ProviderLifetime> = (0..19)
            .map(|n| {
                (
                    format!("session-{n:02}"),
                    ProviderLifetime {
                        provider: ObservedProvider::OpenCode,
                        generation: "generation".into(),
                    },
                )
            })
            .collect();
        let mut broker = Broker::default();
        let mut covered = HashSet::new();
        for _ in 0..3 {
            let batch = next_batch(&mut broker, cohort.clone());
            assert_eq!(batch.len(), MAX_GRIDS_PER_TICK);
            covered.extend(batch.into_iter().map(|(id, _)| id));
        }
        assert_eq!(covered.len(), 19);
        broker.signals.insert("removed".into(), signal());
        broker.signals.insert(
            "session-00".into(),
            Signal {
                generation: "old".into(),
                ..signal()
            },
        );
        next_batch(&mut broker, cohort);
        assert!(broker.signals.is_empty());
        assert!(next_batch(&mut broker, BTreeMap::new()).is_empty());
    }
}
