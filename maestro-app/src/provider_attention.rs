//! Ephemeral, read-only OpenCode permission attention. One process-wide, coalesced worker per
//! app base observes retained grids; window listeners never attach or retain terminal content.
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    path::{Path, PathBuf},
    sync::{Arc, Mutex, OnceLock},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

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

#[derive(Clone, Debug)]
struct Signal {
    generation: String,
    revision: u64,
    waiting_since: Option<u64>,
}

#[derive(Default)]
struct Broker {
    socket: PathBuf,
    last_started: Option<Instant>,
    busy: bool,
    cursor: usize,
    signals: HashMap<String, Signal>,
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

fn eligible(record: &SessionRecord, generation: &str) -> bool {
    record.status == SessionStatus::Live
        && record.last_known_generation.as_deref() == Some(generation)
        && matches!(
            record.launch,
            maestro_shell::LaunchSpec::KnownSafe { .. }
                | maestro_shell::LaunchSpec::BoundProvider { .. }
                | maestro_shell::LaunchSpec::FreshProvider { .. }
        )
        && crate::agent_history::agent_from_session_record(record) == Some("opencode")
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

fn waiting_projection(state: &Broker) -> BTreeMap<String, (String, u64)> {
    state
        .signals
        .iter()
        .filter_map(|(id, signal)| {
            signal
                .waiting_since
                .map(|since| (id.clone(), (signal.generation.clone(), since)))
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
            if !waiting_projection(&state).is_empty() {
                state.projection_revision = state.projection_revision.wrapping_add(1);
            }
            state.signals.clear();
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
                cohort
                    .retain(|id, generation| live.generation_for(id) == Some(generation.as_str()));
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
            for (id, generation) in batch {
                // Each request uses a fresh read-only connection: a timeout cannot misattribute a
                // delayed reply to the next session. No Attach, history or input is ever sent.
                let observation = DaemonClient::connect_with_timeout(&socket, GRID_TIMEOUT)
                    .ok()
                    .and_then(|mut client| client.current_grid_frame(&id).ok())
                    .and_then(|frame| {
                        maestro_renderer::provider_observation::observe_opencode_grid(
                            &frame,
                            &id,
                            &generation,
                        )
                    });
                if let Some(observation) = observation {
                    let mut state = worker_state.lock().unwrap_or_else(|e| e.into_inner());
                    let before = waiting_projection(&state);
                    accept(
                        &mut state.signals,
                        id,
                        generation,
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

fn next_batch(state: &mut Broker, cohort: BTreeMap<String, String>) -> Vec<(String, String)> {
    state
        .signals
        .retain(|id, signal| cohort.get(id) == Some(&signal.generation));
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

fn observation_cohort(paths: &AppPaths) -> Option<BTreeMap<String, String>> {
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
                (represented.contains(record.session_id.as_str()) && eligible(record, generation))
                    .then(|| (record.session_id.clone(), generation.to_owned()))
            })
            .collect(),
    )
}

fn accept(
    signals: &mut HashMap<String, Signal>,
    id: String,
    generation: String,
    revision: u64,
    observation: Observation,
    now: u64,
) {
    let signal = signals.entry(id).or_insert_with(|| Signal {
        generation: generation.clone(),
        revision: 0,
        waiting_since: None,
    });
    if signal.generation != generation {
        *signal = Signal {
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
    if attention.attention == Attention::Error
        || task.is_some_and(|state| state != AgentTaskState::Running)
        || (attention.source == AttentionSource::User
            && (attention.attention != Attention::None || attention.since_ms >= since))
    {
        return;
    }
    *attention = AttentionState {
        attention: Attention::NeedsInput,
        unseen: true,
        since_ms: since,
        source: AttentionSource::Agent,
    };
    *needs_attention = true;
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
            .is_some_and(|record| eligible(record, &signal.generation))
    });
    signals
}

/// Overlay only a temporary view. Explicit task states and durable/user/error signals are never
/// rewritten. Positive recovery merely removes OUR overlay, exposing the original state again.
pub fn apply_dashboard(paths: &AppPaths, snapshot: &mut DashboardSnapshot) {
    let signals = current_signals(paths);
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
    }
}

pub(crate) fn apply_tab_views(paths: &AppPaths, views: &mut [WindowTabView]) {
    let signals = current_signals(paths);
    for tab in views {
        if let Some(signal) = signals.get(&tab.session_id) {
            project(
                signal,
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
            generation: "generation".into(),
            revision: 1,
            waiting_since: Some(10),
        }
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
        assert!(eligible(&record, "g"));
        assert!(!eligible(&record, "other"));
        record.launch = LaunchSpec::OptOut;
        assert!(!eligible(&record, "g"));
    }

    #[test]
    fn bounded_round_robin_covers_all_retained_panes_and_invalidates_removed_lifetimes() {
        let cohort: BTreeMap<String, String> = (0..19)
            .map(|n| (format!("session-{n:02}"), "generation".into()))
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
