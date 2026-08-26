//! Crash-recovery database authority for transaction-prepared AgentTask starts.
//!
//! The daemon mutation and the durable AgentTask/Session publication cannot share one atomic
//! transaction. `pending_agent_task_starts` therefore preserves a content-blind operation marker
//! across process loss. This module owns only the SQLite side of recovery: it claims one expired
//! marker, validates the complete A graph, and performs narrow, lease-fenced graph transitions.
//! Daemon lookup/retirement remains a caller responsibility represented here by opaque proofs.

use std::collections::HashSet;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

use maestro_protocol::{DaemonInstanceId, SessionStartOperationToken};
use rusqlite::{OptionalExtension as _, TransactionBehavior};
use sha2::{Digest as _, Sha256};

use crate::paths::{AppPaths, RecordKind};
use crate::records::{
    AgentTask, AgentTaskState, LaunchSpec, Project, SessionKind, SessionRecord, SessionStatus,
    Workspace,
};

/// A recovery lease covers one bounded daemon inspection/retirement exchange plus DB margin.
pub const AGENT_TASK_START_RECOVERY_LEASE_MS: u64 = 120_000;

/// Peer-binding state durably reached before a possible conditional Start write.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTaskStartBindingState {
    Unbound,
    Bound,
}

impl AgentTaskStartBindingState {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Unbound => "unbound",
            Self::Bound => "bound",
        }
    }
}

/// Forward-only purpose of a pending start marker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTaskStartDisposition {
    Finalize,
    Release,
}

impl AgentTaskStartDisposition {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Finalize => "finalize",
            Self::Release => "release",
        }
    }
}

/// Daemon lifecycle already proven for the operation's exact generation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AppliedAgentTaskStartState {
    Live,
    Exited,
    Removed,
}

impl AppliedAgentTaskStartState {
    fn as_sql(self) -> &'static str {
        match self {
            Self::Live => "live",
            Self::Exited => "exited",
            Self::Removed => "removed",
        }
    }
}

/// Result of revalidating the durable A graph under the claim's current SQLite snapshot.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimedAgentTaskStartGraph {
    ExactPreparedA,
    Changed,
    ClaimLost,
}

/// One oldest expired journal row after exact lease rotation.
///
/// The type is intentionally non-`Clone`. Debug output contains no row ids, operation/lease
/// tokens, socket path, launch metadata, or user-authored record fields.
pub struct ClaimedAgentTaskStart {
    row: JournalRow,
    initial_graph: ClaimedAgentTaskStartGraph,
}

impl ClaimedAgentTaskStart {
    pub fn session_id(&self) -> &str {
        &self.row.session_id
    }

    pub fn agent_task_id(&self) -> &str {
        &self.row.agent_task_id
    }

    pub(crate) fn operation_token(&self) -> &SessionStartOperationToken {
        &self.row.operation_token
    }

    pub fn binding_state(&self) -> AgentTaskStartBindingState {
        self.row.binding_state
    }

    pub(crate) fn daemon_instance_id(&self) -> Option<&DaemonInstanceId> {
        self.row.daemon_instance_id.as_ref()
    }

    pub(crate) fn server_pid(&self) -> Option<u32> {
        self.row.server_pid
    }

    pub(crate) fn socket_path(&self) -> Option<&Path> {
        self.row.socket_path.as_deref().map(Path::new)
    }

    pub fn disposition(&self) -> AgentTaskStartDisposition {
        self.row.disposition
    }

    pub fn applied_generation(&self) -> Option<&str> {
        self.row.applied_generation.as_deref()
    }

    pub fn applied_state(&self) -> Option<AppliedAgentTaskStartState> {
        self.row.applied_state
    }

    pub fn initial_graph(&self) -> ClaimedAgentTaskStartGraph {
        self.initial_graph
    }

    /// An unbound marker is itself proof that no conditional Start byte was authorized. Bound
    /// markers require an external operation-ledger retirement proof instead.
    pub fn prove_unbound_unapplied(&self) -> Option<ProvenUnappliedAgentTaskStart> {
        (self.row.binding_state == AgentTaskStartBindingState::Unbound
            && self.row.applied_generation.is_none())
        .then(|| ProvenUnappliedAgentTaskStart {
            operation_token: self.row.operation_token.clone(),
            daemon_instance_id: None,
        })
    }
}

impl std::fmt::Debug for ClaimedAgentTaskStart {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClaimedAgentTaskStart")
            .field("binding_state", &self.row.binding_state)
            .field("disposition", &self.row.disposition)
            .field(
                "has_applied_generation",
                &self.row.applied_generation.is_some(),
            )
            .field("applied_state", &self.row.applied_state)
            .field("initial_graph", &self.initial_graph)
            .finish_non_exhaustive()
    }
}

/// Proof that this exact operation can no longer apply a Start. For an unbound row the proof is
/// derived locally; a bound proof may only be minted by crate code after the daemon's retirement
/// barrier reports the exact token as unapplied/retired.
pub struct ProvenUnappliedAgentTaskStart {
    operation_token: SessionStartOperationToken,
    daemon_instance_id: Option<DaemonInstanceId>,
}

impl ProvenUnappliedAgentTaskStart {
    pub(crate) fn bound_operation_retired(
        operation_token: SessionStartOperationToken,
        daemon_instance_id: DaemonInstanceId,
    ) -> Self {
        Self {
            operation_token,
            daemon_instance_id: Some(daemon_instance_id),
        }
    }
}

impl std::fmt::Debug for ProvenUnappliedAgentTaskStart {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProvenUnappliedAgentTaskStart")
            .field("peer_bound", &self.daemon_instance_id.is_some())
            .finish_non_exhaustive()
    }
}

/// Proof that the daemon's process-lifetime operation-ledger authority for an applied exact
/// generation has been retired. Retiring this authority does not terminate the PTY.
pub struct RetiredAgentTaskStartOperation {
    operation_token: SessionStartOperationToken,
    daemon_instance_id: DaemonInstanceId,
    applied_generation: String,
}

/// Combined proof for abandoning an applied start whose durable A graph changed before B could be
/// published. Crate code may mint this only after both exact-generation lifetime cleanup (including
/// an idempotent already-cleaned result) and operation-ledger retirement (including an idempotent
/// already-retired result) are confirmed on the same daemon process.
pub struct CleanedAndRetiredAgentTaskStartOperation {
    operation_token: SessionStartOperationToken,
    daemon_instance_id: DaemonInstanceId,
    applied_generation: String,
}

impl CleanedAndRetiredAgentTaskStartOperation {
    pub(crate) fn confirmed(
        operation_token: SessionStartOperationToken,
        daemon_instance_id: DaemonInstanceId,
        applied_generation: impl Into<String>,
    ) -> Self {
        Self {
            operation_token,
            daemon_instance_id,
            applied_generation: applied_generation.into(),
        }
    }
}

impl std::fmt::Debug for CleanedAndRetiredAgentTaskStartOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("CleanedAndRetiredAgentTaskStartOperation")
            .finish_non_exhaustive()
    }
}

impl RetiredAgentTaskStartOperation {
    pub(crate) fn confirmed(
        operation_token: SessionStartOperationToken,
        daemon_instance_id: DaemonInstanceId,
        applied_generation: impl Into<String>,
    ) -> Self {
        Self {
            operation_token,
            daemon_instance_id,
            applied_generation: applied_generation.into(),
        }
    }
}

impl std::fmt::Debug for RetiredAgentTaskStartOperation {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RetiredAgentTaskStartOperation")
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTaskStartCompensationOutcome {
    Compensated,
    GraphChanged,
    ClaimLost,
    ProofMismatch,
    NotUnapplied,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTaskStartPublicationOutcome {
    PublishedLive,
    PublishedExited,
    GraphChanged,
    ClaimLost,
    NotPublishable,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTaskStartReleaseDeleteOutcome {
    Deleted,
    ClaimLost,
    ProofMismatch,
    NotRelease,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTaskStartAppliedMarkOutcome {
    Marked,
    ClaimLost,
    NotBound,
    InvalidGeneration,
    GenerationMismatch,
    ReverseTransition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTaskStartChangedCleanupDeleteOutcome {
    Deleted,
    AlreadyDeleted,
    ClaimLost,
    ProofMismatch,
    NotFinalize,
    Unapplied,
    NotRemoved,
    GraphStillExact,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTaskStartChangedUnappliedDeleteOutcome {
    Deleted,
    AlreadyDeleted,
    ClaimLost,
    ProofMismatch,
    NotFinalize,
    Applied,
    GraphStillExact,
}

/// Privacy-preserving journal failure. Underlying SQLite/serde text is deliberately discarded so
/// malformed user-authored records can never echo goal/result/launch bytes through diagnostics.
pub struct AgentTaskStartJournalError {
    kind: AgentTaskStartJournalErrorKind,
}

#[derive(Clone, Copy)]
enum AgentTaskStartJournalErrorKind {
    Database,
    Clock,
    Corrupt(&'static str),
}

impl AgentTaskStartJournalError {
    fn database<T>(_error: T) -> Self {
        Self {
            kind: AgentTaskStartJournalErrorKind::Database,
        }
    }

    fn clock() -> Self {
        Self {
            kind: AgentTaskStartJournalErrorKind::Clock,
        }
    }

    fn corrupt(field: &'static str) -> Self {
        Self {
            kind: AgentTaskStartJournalErrorKind::Corrupt(field),
        }
    }
}

impl std::fmt::Display for AgentTaskStartJournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self.kind {
            AgentTaskStartJournalErrorKind::Database => {
                formatter.write_str("AgentTask start journal database operation failed")
            }
            AgentTaskStartJournalErrorKind::Clock => {
                formatter.write_str("AgentTask start journal clock is unavailable")
            }
            AgentTaskStartJournalErrorKind::Corrupt(field) => {
                write!(formatter, "AgentTask start journal has invalid {field}")
            }
        }
    }
}

impl std::fmt::Debug for AgentTaskStartJournalError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        std::fmt::Display::fmt(self, formatter)
    }
}

impl std::error::Error for AgentTaskStartJournalError {}

#[derive(Clone, Copy, Eq, PartialEq)]
enum GraphState {
    ExactPreparedA,
    Changed,
}

struct GraphA {
    project: Project,
    workspace: Workspace,
    task: AgentTask,
    session: SessionRecord,
}

struct JournalRow {
    session_id: String,
    agent_task_id: String,
    project_id: String,
    workspace_id: String,
    operation_token: SessionStartOperationToken,
    binding_state: AgentTaskStartBindingState,
    daemon_instance_id: Option<DaemonInstanceId>,
    server_pid: Option<u32>,
    socket_path: Option<String>,
    session_a_sha256: [u8; 32],
    task_a_sha256: [u8; 32],
    project_sha256: [u8; 32],
    workspace_sha256: [u8; 32],
    publication_launch_json: String,
    publication_launch: LaunchSpec,
    publication_now_ms: u64,
    disposition: AgentTaskStartDisposition,
    applied_generation: Option<String>,
    applied_state: Option<AppliedAgentTaskStartState>,
    created_at_ms: u64,
    lease_token: String,
    lease_until_ms: u64,
}

struct RawJournalRow {
    session_id: String,
    agent_task_id: String,
    project_id: String,
    workspace_id: String,
    operation_token: String,
    binding_state: String,
    daemon_instance_id: Option<String>,
    server_pid: Option<i64>,
    socket_path: Option<String>,
    session_a_sha256: Vec<u8>,
    task_a_sha256: Vec<u8>,
    project_sha256: Vec<u8>,
    workspace_sha256: Vec<u8>,
    publication_launch_json: String,
    publication_now_ms: i64,
    disposition: String,
    applied_generation: Option<String>,
    applied_state: Option<String>,
    created_at_ms: i64,
    lease_token: Option<String>,
    lease_until_ms: Option<i64>,
}

impl RawJournalRow {
    fn from_sqlite(row: &rusqlite::Row<'_>) -> rusqlite::Result<Self> {
        Ok(Self {
            session_id: row.get(0)?,
            agent_task_id: row.get(1)?,
            project_id: row.get(2)?,
            workspace_id: row.get(3)?,
            operation_token: row.get(4)?,
            binding_state: row.get(5)?,
            daemon_instance_id: row.get(6)?,
            server_pid: row.get(7)?,
            socket_path: row.get(8)?,
            session_a_sha256: row.get(9)?,
            task_a_sha256: row.get(10)?,
            project_sha256: row.get(11)?,
            workspace_sha256: row.get(12)?,
            publication_launch_json: row.get(13)?,
            publication_now_ms: row.get(14)?,
            disposition: row.get(15)?,
            applied_generation: row.get(16)?,
            applied_state: row.get(17)?,
            created_at_ms: row.get(18)?,
            lease_token: row.get(19)?,
            lease_until_ms: row.get(20)?,
        })
    }
}

impl JournalRow {
    fn parse(raw: RawJournalRow) -> Result<Self, AgentTaskStartJournalError> {
        for (value, field) in [
            (&raw.session_id, "session id"),
            (&raw.agent_task_id, "AgentTask id"),
            (&raw.project_id, "project id"),
            (&raw.workspace_id, "workspace id"),
        ] {
            crate::validate_id(value).map_err(|_| AgentTaskStartJournalError::corrupt(field))?;
        }
        let operation_token = raw
            .operation_token
            .parse()
            .map_err(|_| AgentTaskStartJournalError::corrupt("operation token"))?;
        let binding_state = match raw.binding_state.as_str() {
            "unbound" => AgentTaskStartBindingState::Unbound,
            "bound" => AgentTaskStartBindingState::Bound,
            _ => return Err(AgentTaskStartJournalError::corrupt("binding state")),
        };
        let daemon_instance_id = raw
            .daemon_instance_id
            .map(|value| {
                value
                    .parse()
                    .map_err(|_| AgentTaskStartJournalError::corrupt("daemon identity"))
            })
            .transpose()?;
        let server_pid = raw
            .server_pid
            .map(|value| {
                u32::try_from(value)
                    .ok()
                    .filter(|value| *value != 0)
                    .ok_or_else(|| AgentTaskStartJournalError::corrupt("server pid"))
            })
            .transpose()?;
        if raw.socket_path.as_ref().is_some_and(|path| {
            path.is_empty() || path.len() > 4096 || path.as_bytes().contains(&0)
        }) {
            return Err(AgentTaskStartJournalError::corrupt("socket path"));
        }
        match binding_state {
            AgentTaskStartBindingState::Unbound
                if daemon_instance_id.is_some()
                    || server_pid.is_some()
                    || raw.socket_path.is_some() =>
            {
                return Err(AgentTaskStartJournalError::corrupt("unbound peer fields"));
            }
            AgentTaskStartBindingState::Bound
                if daemon_instance_id.is_none() || raw.socket_path.is_none() =>
            {
                return Err(AgentTaskStartJournalError::corrupt("bound peer fields"));
            }
            _ => {}
        }

        let session_a_sha256 = parse_hash(raw.session_a_sha256, "Session A hash")?;
        let task_a_sha256 = parse_hash(raw.task_a_sha256, "AgentTask A hash")?;
        let project_sha256 = parse_hash(raw.project_sha256, "project hash")?;
        let workspace_sha256 = parse_hash(raw.workspace_sha256, "workspace hash")?;
        let publication_launch: LaunchSpec = serde_json::from_str(&raw.publication_launch_json)
            .map_err(|_| AgentTaskStartJournalError::corrupt("publication launch"))?;
        let canonical_launch = serde_json::to_string(&publication_launch)
            .map_err(|_| AgentTaskStartJournalError::corrupt("publication launch"))?;
        if canonical_launch != raw.publication_launch_json {
            return Err(AgentTaskStartJournalError::corrupt(
                "canonical publication launch",
            ));
        }
        let publication_now_ms = parse_nonnegative(raw.publication_now_ms, "publication time")?;
        let disposition = match raw.disposition.as_str() {
            "finalize" => AgentTaskStartDisposition::Finalize,
            "release" => AgentTaskStartDisposition::Release,
            _ => return Err(AgentTaskStartJournalError::corrupt("disposition")),
        };
        let applied_state = match raw.applied_state.as_deref() {
            None => None,
            Some("live") => Some(AppliedAgentTaskStartState::Live),
            Some("exited") => Some(AppliedAgentTaskStartState::Exited),
            Some("removed") => Some(AppliedAgentTaskStartState::Removed),
            Some(_) => return Err(AgentTaskStartJournalError::corrupt("applied state")),
        };
        if raw.applied_generation.as_ref().is_some_and(|generation| {
            generation.is_empty() || generation.len() > crate::ids::MAX_ID_LEN
        }) {
            return Err(AgentTaskStartJournalError::corrupt("applied generation"));
        }
        if raw.applied_generation.is_some() != applied_state.is_some()
            || (raw.applied_generation.is_some()
                && binding_state != AgentTaskStartBindingState::Bound)
            || (disposition == AgentTaskStartDisposition::Release
                && raw.applied_generation.is_none())
        {
            return Err(AgentTaskStartJournalError::corrupt(
                "applied-state relationship",
            ));
        }
        let created_at_ms = parse_nonnegative(raw.created_at_ms, "creation time")?;
        let (lease_token, lease_until_ms) = match (raw.lease_token, raw.lease_until_ms) {
            (Some(token), Some(until)) => {
                validate_hyphenated_uuid_v4(&token, "lease token")?;
                (token, parse_nonnegative(until, "lease expiry")?)
            }
            _ => return Err(AgentTaskStartJournalError::corrupt("claimed lease")),
        };
        Ok(Self {
            session_id: raw.session_id,
            agent_task_id: raw.agent_task_id,
            project_id: raw.project_id,
            workspace_id: raw.workspace_id,
            operation_token,
            binding_state,
            daemon_instance_id,
            server_pid,
            socket_path: raw.socket_path,
            session_a_sha256,
            task_a_sha256,
            project_sha256,
            workspace_sha256,
            publication_launch_json: raw.publication_launch_json,
            publication_launch,
            publication_now_ms,
            disposition,
            applied_generation: raw.applied_generation,
            applied_state,
            created_at_ms,
            lease_token,
            lease_until_ms,
        })
    }
}

fn parse_hash(bytes: Vec<u8>, field: &'static str) -> Result<[u8; 32], AgentTaskStartJournalError> {
    bytes
        .try_into()
        .map_err(|_| AgentTaskStartJournalError::corrupt(field))
}

fn parse_nonnegative(value: i64, field: &'static str) -> Result<u64, AgentTaskStartJournalError> {
    u64::try_from(value).map_err(|_| AgentTaskStartJournalError::corrupt(field))
}

fn validate_hyphenated_uuid_v4(
    value: &str,
    field: &'static str,
) -> Result<(), AgentTaskStartJournalError> {
    let parsed =
        uuid::Uuid::parse_str(value).map_err(|_| AgentTaskStartJournalError::corrupt(field))?;
    if parsed.get_version_num() != 4 || parsed.hyphenated().to_string() != value {
        return Err(AgentTaskStartJournalError::corrupt(field));
    }
    Ok(())
}

fn clock_ms() -> Result<u64, AgentTaskStartJournalError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| AgentTaskStartJournalError::clock())?
        .as_millis()
        .try_into()
        .map_err(|_| AgentTaskStartJournalError::clock())
}

fn checked_sql_ms(value: u64) -> Result<i64, AgentTaskStartJournalError> {
    i64::try_from(value).map_err(|_| AgentTaskStartJournalError::clock())
}

fn new_lease(now_ms: u64) -> Result<(String, u64), AgentTaskStartJournalError> {
    let until = now_ms
        .checked_add(AGENT_TASK_START_RECOVERY_LEASE_MS)
        .ok_or_else(AgentTaskStartJournalError::clock)?;
    Ok((uuid::Uuid::new_v4().hyphenated().to_string(), until))
}

const JOURNAL_COLUMNS: &str =
    "session_id, agent_task_id, project_id, workspace_id, operation_token, binding_state, \
     daemon_instance_id, server_pid, socket_path, session_a_sha256, task_a_sha256, \
     project_sha256, workspace_sha256, publication_launch_json, publication_now_ms, \
     disposition, applied_generation, applied_state, created_at_ms, lease_token, lease_until_ms";

/// SQLite-only start recovery service for one app-support database.
pub struct AgentTaskStartJournalService<'a> {
    paths: &'a AppPaths,
}

impl<'a> AgentTaskStartJournalService<'a> {
    pub fn new(paths: &'a AppPaths) -> Self {
        Self { paths }
    }

    /// Claim at most one oldest unleased/expired row. Selection, strict row parsing, A-graph
    /// fingerprinting, and exact lease rotation share one `BEGIN IMMEDIATE` writer fence.
    pub fn claim_next(&self) -> Result<Option<ClaimedAgentTaskStart>, AgentTaskStartJournalError> {
        let arc =
            crate::db::conn_for(self.paths.base()).map_err(AgentTaskStartJournalError::database)?;
        let mut connection = arc.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AgentTaskStartJournalError::database)?;
        let now_ms = clock_ms()?;
        let now = checked_sql_ms(now_ms)?;
        let sql = format!(
            "SELECT {JOURNAL_COLUMNS} FROM pending_agent_task_starts \
             WHERE lease_token IS NULL OR lease_until_ms <= ?1 \
             ORDER BY created_at_ms, session_id LIMIT 1"
        );
        let raw = tx
            .query_row(&sql, [now], RawJournalRow::from_sqlite)
            .optional()
            .map_err(AgentTaskStartJournalError::database)?;
        let Some(mut raw) = raw else {
            tx.commit().map_err(AgentTaskStartJournalError::database)?;
            return Ok(None);
        };

        // Validate the pre-rotation lease strictly too. A malformed oldest row blocks later work
        // instead of being skipped and silently orphaned.
        match (&raw.lease_token, raw.lease_until_ms) {
            (None, None) => {}
            (Some(token), Some(until)) => {
                validate_hyphenated_uuid_v4(token, "lease token")?;
                parse_nonnegative(until, "lease expiry")?;
            }
            _ => return Err(AgentTaskStartJournalError::corrupt("lease relationship")),
        }
        let old_lease_token = raw.lease_token.clone();
        let old_lease_until_ms = raw.lease_until_ms;
        let (lease_token, lease_until_ms) = new_lease(now_ms)?;
        let updated = tx
            .execute(
                "UPDATE pending_agent_task_starts SET lease_token = ?3, lease_until_ms = ?4 \
                 WHERE session_id = ?1 AND operation_token = ?2 \
                   AND lease_token IS ?5 AND lease_until_ms IS ?6 \
                   AND (lease_token IS NULL OR lease_until_ms <= ?7)",
                rusqlite::params![
                    raw.session_id,
                    raw.operation_token,
                    lease_token,
                    checked_sql_ms(lease_until_ms)?,
                    old_lease_token,
                    old_lease_until_ms,
                    now,
                ],
            )
            .map_err(AgentTaskStartJournalError::database)?;
        if updated != 1 {
            return Err(AgentTaskStartJournalError::database("lease CAS lost"));
        }
        raw.lease_token = Some(lease_token);
        raw.lease_until_ms = Some(checked_sql_ms(lease_until_ms)?);
        let row = JournalRow::parse(raw)?;
        let initial_graph = match load_exact_graph_a(&tx, &row)? {
            (GraphState::ExactPreparedA, _) => ClaimedAgentTaskStartGraph::ExactPreparedA,
            (GraphState::Changed, _) => ClaimedAgentTaskStartGraph::Changed,
        };
        tx.commit().map_err(AgentTaskStartJournalError::database)?;
        Ok(Some(ClaimedAgentTaskStart { row, initial_graph }))
    }

    /// Recompute the A graph from a single read snapshot. This never changes graph or journal
    /// state; a stale/expired claim is reported separately from a changed graph.
    pub fn classify_claimed(
        &self,
        claim: &ClaimedAgentTaskStart,
    ) -> Result<ClaimedAgentTaskStartGraph, AgentTaskStartJournalError> {
        let arc =
            crate::db::conn_for(self.paths.base()).map_err(AgentTaskStartJournalError::database)?;
        let mut connection = arc.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Deferred)
            .map_err(AgentTaskStartJournalError::database)?;
        let now_ms = clock_ms()?;
        if !claim_is_current(&tx, &claim.row, now_ms)? {
            tx.commit().map_err(AgentTaskStartJournalError::database)?;
            return Ok(ClaimedAgentTaskStartGraph::ClaimLost);
        }
        let graph = match load_exact_graph_a(&tx, &claim.row)?.0 {
            GraphState::ExactPreparedA => ClaimedAgentTaskStartGraph::ExactPreparedA,
            GraphState::Changed => ClaimedAgentTaskStartGraph::Changed,
        };
        tx.commit().map_err(AgentTaskStartJournalError::database)?;
        Ok(graph)
    }

    /// Atomically delete the exact journal row and its still-Unknown Session A. Task A and all
    /// other graph records are preserved byte-for-byte. A bound marker additionally requires a
    /// caller-held exact operation-retirement proof.
    pub fn compensate_proven_unapplied(
        &self,
        claim: &ClaimedAgentTaskStart,
        proof: &ProvenUnappliedAgentTaskStart,
    ) -> Result<AgentTaskStartCompensationOutcome, AgentTaskStartJournalError> {
        if !unapplied_proof_matches(&claim.row, proof) {
            return Ok(AgentTaskStartCompensationOutcome::ProofMismatch);
        }
        if claim.row.disposition != AgentTaskStartDisposition::Finalize
            || claim.row.applied_generation.is_some()
            || claim.row.applied_state.is_some()
        {
            return Ok(AgentTaskStartCompensationOutcome::NotUnapplied);
        }
        let arc =
            crate::db::conn_for(self.paths.base()).map_err(AgentTaskStartJournalError::database)?;
        let mut connection = arc.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AgentTaskStartJournalError::database)?;
        let now_ms = clock_ms()?;
        if !claim_is_current(&tx, &claim.row, now_ms)? {
            return Ok(AgentTaskStartCompensationOutcome::ClaimLost);
        }
        let (graph_state, graph) = load_exact_graph_a(&tx, &claim.row)?;
        let Some(graph) = graph else {
            return Ok(AgentTaskStartCompensationOutcome::GraphChanged);
        };
        if graph_state != GraphState::ExactPreparedA {
            return Ok(AgentTaskStartCompensationOutcome::GraphChanged);
        }
        let removed = tx
            .execute(
                "DELETE FROM pending_agent_task_starts \
                 WHERE session_id = ?1 AND operation_token = ?2 AND lease_token = ?3 \
                   AND lease_until_ms = ?4 AND lease_until_ms > ?5 \
                   AND disposition = 'finalize' AND applied_generation IS NULL \
                   AND applied_state IS NULL",
                rusqlite::params![
                    claim.row.session_id,
                    claim.row.operation_token.as_str(),
                    claim.row.lease_token,
                    checked_sql_ms(claim.row.lease_until_ms)?,
                    checked_sql_ms(now_ms)?,
                ],
            )
            .map_err(AgentTaskStartJournalError::database)?;
        if removed != 1 {
            return Ok(AgentTaskStartCompensationOutcome::ClaimLost);
        }
        let deleted =
            crate::store_sqlite::delete(&tx, RecordKind::Session, &graph.session.session_id)
                .map_err(AgentTaskStartJournalError::database)?;
        if !deleted {
            return Ok(AgentTaskStartCompensationOutcome::GraphChanged);
        }
        // An explicit equality audit makes preservation of A part of the transaction contract.
        if load_typed::<AgentTask>(
            &tx,
            RecordKind::AgentTask,
            &graph.task.agent_task_id,
            "AgentTask",
        )?
        .as_ref()
            != Some(&graph.task)
        {
            return Ok(AgentTaskStartCompensationOutcome::GraphChanged);
        }
        tx.commit().map_err(AgentTaskStartJournalError::database)?;
        Ok(AgentTaskStartCompensationOutcome::Compensated)
    }

    /// Persist one exact daemon lifecycle observation and rotate/renew the caller's claim in the
    /// same writer transaction. A generation is immutable once first observed; lifecycle may only
    /// advance `live -> exited -> removed` (with the direct `live -> removed` proof also allowed).
    /// A first exact observation may already be exited or removed.
    pub fn mark_claimed_applied(
        &self,
        claim: &mut ClaimedAgentTaskStart,
        generation: &str,
        state: AppliedAgentTaskStartState,
    ) -> Result<AgentTaskStartAppliedMarkOutcome, AgentTaskStartJournalError> {
        if generation.is_empty() || generation.len() > crate::ids::MAX_ID_LEN {
            return Ok(AgentTaskStartAppliedMarkOutcome::InvalidGeneration);
        }
        if claim.row.binding_state != AgentTaskStartBindingState::Bound
            || claim.row.daemon_instance_id.is_none()
            || claim.row.socket_path.is_none()
        {
            return Ok(AgentTaskStartAppliedMarkOutcome::NotBound);
        }
        match claim.row.applied_generation.as_deref() {
            Some(current) if current != generation => {
                return Ok(AgentTaskStartAppliedMarkOutcome::GenerationMismatch);
            }
            Some(_) if !applied_state_may_advance(claim.row.applied_state, state) => {
                return Ok(AgentTaskStartAppliedMarkOutcome::ReverseTransition);
            }
            None if claim.row.applied_state.is_some() => {
                return Ok(AgentTaskStartAppliedMarkOutcome::ReverseTransition);
            }
            None | Some(_) => {}
        }

        let arc =
            crate::db::conn_for(self.paths.base()).map_err(AgentTaskStartJournalError::database)?;
        let mut connection = arc.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AgentTaskStartJournalError::database)?;
        let now_ms = clock_ms()?;
        if !claim_is_current(&tx, &claim.row, now_ms)? {
            return Ok(AgentTaskStartAppliedMarkOutcome::ClaimLost);
        }
        let (next_lease_token, next_lease_until_ms) = new_lease(now_ms)?;
        let updated = tx
            .execute(
                "UPDATE pending_agent_task_starts \
                 SET applied_generation = ?6, applied_state = ?7, \
                     lease_token = ?8, lease_until_ms = ?9 \
                 WHERE session_id = ?1 AND operation_token = ?2 AND lease_token = ?3 \
                   AND lease_until_ms = ?4 AND lease_until_ms > ?5 \
                   AND applied_generation IS ?10 AND applied_state IS ?11",
                rusqlite::params![
                    claim.row.session_id,
                    claim.row.operation_token.as_str(),
                    claim.row.lease_token,
                    checked_sql_ms(claim.row.lease_until_ms)?,
                    checked_sql_ms(now_ms)?,
                    generation,
                    state.as_sql(),
                    next_lease_token,
                    checked_sql_ms(next_lease_until_ms)?,
                    claim.row.applied_generation.as_deref(),
                    claim
                        .row
                        .applied_state
                        .map(AppliedAgentTaskStartState::as_sql),
                ],
            )
            .map_err(AgentTaskStartJournalError::database)?;
        if updated != 1 {
            return Ok(AgentTaskStartAppliedMarkOutcome::ClaimLost);
        }
        tx.commit().map_err(AgentTaskStartJournalError::database)?;
        claim.row.applied_generation = Some(generation.to_string());
        claim.row.applied_state = Some(state);
        claim.row.lease_token = next_lease_token;
        claim.row.lease_until_ms = next_lease_until_ms;
        Ok(AgentTaskStartAppliedMarkOutcome::Marked)
    }

    /// Publish exact Session B and Task B from the still-current A graph and the journal's applied
    /// generation. The graph writes and `finalize -> release` operation-authority transition share
    /// one `BEGIN IMMEDIATE` transaction.
    pub fn publish_applied(
        &self,
        claim: &mut ClaimedAgentTaskStart,
    ) -> Result<AgentTaskStartPublicationOutcome, AgentTaskStartJournalError> {
        let publication_state = match (
            claim.row.disposition,
            claim.row.applied_generation.as_deref(),
            claim.row.applied_state,
        ) {
            (
                AgentTaskStartDisposition::Finalize,
                Some(_),
                Some(AppliedAgentTaskStartState::Live),
            ) => SessionStatus::Live,
            (
                AgentTaskStartDisposition::Finalize,
                Some(_),
                Some(AppliedAgentTaskStartState::Exited),
            ) => SessionStatus::Exited,
            (
                AgentTaskStartDisposition::Finalize,
                Some(_),
                Some(AppliedAgentTaskStartState::Removed),
            ) => SessionStatus::Exited,
            _ => return Ok(AgentTaskStartPublicationOutcome::NotPublishable),
        };
        let arc =
            crate::db::conn_for(self.paths.base()).map_err(AgentTaskStartJournalError::database)?;
        let mut connection = arc.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AgentTaskStartJournalError::database)?;
        let now_ms = clock_ms()?;
        if !claim_is_current(&tx, &claim.row, now_ms)? {
            return Ok(AgentTaskStartPublicationOutcome::ClaimLost);
        }
        let (graph_state, graph) = load_exact_graph_a(&tx, &claim.row)?;
        let Some(graph) = graph else {
            return Ok(AgentTaskStartPublicationOutcome::GraphChanged);
        };
        if graph_state != GraphState::ExactPreparedA {
            return Ok(AgentTaskStartPublicationOutcome::GraphChanged);
        }
        let generation = claim
            .row
            .applied_generation
            .as_deref()
            .expect("publishable claim has an applied generation");
        let (session_b, task_b) =
            derive_publication(&claim.row, &graph, generation, publication_state)?;
        let session_value = serde_json::to_value(&session_b)
            .map_err(|_| AgentTaskStartJournalError::corrupt("derived Session B"))?;
        let task_value = serde_json::to_value(&task_b)
            .map_err(|_| AgentTaskStartJournalError::corrupt("derived AgentTask B"))?;
        crate::store_sqlite::upsert(
            &tx,
            RecordKind::Session,
            &session_b.session_id,
            &session_value,
        )
        .map_err(AgentTaskStartJournalError::database)?;
        crate::store_sqlite::upsert(
            &tx,
            RecordKind::AgentTask,
            &task_b.agent_task_id,
            &task_value,
        )
        .map_err(AgentTaskStartJournalError::database)?;
        if !published_cohort_matches(&tx, &claim.row, &graph, &session_b, &task_b)? {
            return Ok(AgentTaskStartPublicationOutcome::GraphChanged);
        }
        let transitioned = tx
            .execute(
                "UPDATE pending_agent_task_starts SET disposition = 'release' \
                 WHERE session_id = ?1 AND operation_token = ?2 AND lease_token = ?3 \
                   AND lease_until_ms = ?4 AND lease_until_ms > ?5 \
                   AND disposition = 'finalize' AND applied_generation = ?6 \
                   AND applied_state = ?7",
                rusqlite::params![
                    claim.row.session_id,
                    claim.row.operation_token.as_str(),
                    claim.row.lease_token,
                    checked_sql_ms(claim.row.lease_until_ms)?,
                    checked_sql_ms(now_ms)?,
                    generation,
                    claim.row.applied_state.expect("publishable state").as_sql(),
                ],
            )
            .map_err(AgentTaskStartJournalError::database)?;
        if transitioned != 1 {
            return Ok(AgentTaskStartPublicationOutcome::ClaimLost);
        }
        tx.commit().map_err(AgentTaskStartJournalError::database)?;
        claim.row.disposition = AgentTaskStartDisposition::Release;
        claim.initial_graph = ClaimedAgentTaskStartGraph::Changed;
        Ok(match publication_state {
            SessionStatus::Live => AgentTaskStartPublicationOutcome::PublishedLive,
            SessionStatus::Exited => AgentTaskStartPublicationOutcome::PublishedExited,
            SessionStatus::Unknown => unreachable!("publication state is never Unknown"),
        })
    }

    /// Delete only an exact `release` marker after the caller has retired the same operation token
    /// on the same daemon instance for the same applied generation. Session B/Task B are untouched.
    pub fn delete_release_after_operation_retired(
        &self,
        claim: &ClaimedAgentTaskStart,
        proof: &RetiredAgentTaskStartOperation,
    ) -> Result<AgentTaskStartReleaseDeleteOutcome, AgentTaskStartJournalError> {
        if !retired_proof_matches(&claim.row, proof) {
            return Ok(AgentTaskStartReleaseDeleteOutcome::ProofMismatch);
        }
        if claim.row.disposition != AgentTaskStartDisposition::Release {
            return Ok(AgentTaskStartReleaseDeleteOutcome::NotRelease);
        }
        let arc =
            crate::db::conn_for(self.paths.base()).map_err(AgentTaskStartJournalError::database)?;
        let mut connection = arc.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AgentTaskStartJournalError::database)?;
        let now_ms = clock_ms()?;
        if !claim_is_current(&tx, &claim.row, now_ms)? {
            return Ok(AgentTaskStartReleaseDeleteOutcome::ClaimLost);
        }
        let removed = tx
            .execute(
                "DELETE FROM pending_agent_task_starts \
                 WHERE session_id = ?1 AND operation_token = ?2 AND lease_token = ?3 \
                   AND lease_until_ms = ?4 AND lease_until_ms > ?5 \
                   AND disposition = 'release' AND daemon_instance_id = ?6 \
                   AND applied_generation = ?7",
                rusqlite::params![
                    claim.row.session_id,
                    claim.row.operation_token.as_str(),
                    claim.row.lease_token,
                    checked_sql_ms(claim.row.lease_until_ms)?,
                    checked_sql_ms(now_ms)?,
                    proof.daemon_instance_id.as_str(),
                    proof.applied_generation,
                ],
            )
            .map_err(AgentTaskStartJournalError::database)?;
        if removed != 1 {
            return Ok(AgentTaskStartReleaseDeleteOutcome::ClaimLost);
        }
        tx.commit().map_err(AgentTaskStartJournalError::database)?;
        Ok(AgentTaskStartReleaseDeleteOutcome::Deleted)
    }

    /// Abandon an applied `finalize` marker whose A graph no longer exists exactly. The caller's
    /// opaque proof attests both that exact generation's PTY lifetime is gone and that the same
    /// operation-ledger token is retired (first-time or idempotent confirmations). No Project,
    /// Workspace, AgentTask, or Session row is written or deleted here.
    pub fn delete_changed_finalize_after_cleanup_and_retirement(
        &self,
        claim: &ClaimedAgentTaskStart,
        proof: &CleanedAndRetiredAgentTaskStartOperation,
    ) -> Result<AgentTaskStartChangedCleanupDeleteOutcome, AgentTaskStartJournalError> {
        if claim.row.disposition != AgentTaskStartDisposition::Finalize {
            return Ok(AgentTaskStartChangedCleanupDeleteOutcome::NotFinalize);
        }
        if claim.row.applied_generation.is_none() || claim.row.applied_state.is_none() {
            return Ok(AgentTaskStartChangedCleanupDeleteOutcome::Unapplied);
        }
        if claim.row.applied_state != Some(AppliedAgentTaskStartState::Removed) {
            return Ok(AgentTaskStartChangedCleanupDeleteOutcome::NotRemoved);
        }
        if !cleaned_retired_proof_matches(&claim.row, proof) {
            return Ok(AgentTaskStartChangedCleanupDeleteOutcome::ProofMismatch);
        }

        let arc =
            crate::db::conn_for(self.paths.base()).map_err(AgentTaskStartJournalError::database)?;
        let mut connection = arc.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AgentTaskStartJournalError::database)?;
        let identity_absent: bool = tx
            .query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM pending_agent_task_starts \
                 WHERE session_id = ?1 OR operation_token = ?2)",
                rusqlite::params![claim.row.session_id, claim.row.operation_token.as_str()],
                |row| row.get(0),
            )
            .map_err(AgentTaskStartJournalError::database)?;
        if identity_absent {
            tx.commit().map_err(AgentTaskStartJournalError::database)?;
            return Ok(AgentTaskStartChangedCleanupDeleteOutcome::AlreadyDeleted);
        }
        let now_ms = clock_ms()?;
        if !claim_is_current(&tx, &claim.row, now_ms)? {
            return Ok(AgentTaskStartChangedCleanupDeleteOutcome::ClaimLost);
        }
        if load_exact_graph_a(&tx, &claim.row)?.0 == GraphState::ExactPreparedA {
            return Ok(AgentTaskStartChangedCleanupDeleteOutcome::GraphStillExact);
        }
        let removed = tx
            .execute(
                "DELETE FROM pending_agent_task_starts \
                 WHERE session_id = ?1 AND operation_token = ?2 AND lease_token = ?3 \
                   AND lease_until_ms = ?4 AND lease_until_ms > ?5 \
                   AND disposition = 'finalize' AND daemon_instance_id = ?6 \
                   AND applied_generation = ?7 AND applied_state = 'removed'",
                rusqlite::params![
                    claim.row.session_id,
                    claim.row.operation_token.as_str(),
                    claim.row.lease_token,
                    checked_sql_ms(claim.row.lease_until_ms)?,
                    checked_sql_ms(now_ms)?,
                    proof.daemon_instance_id.as_str(),
                    proof.applied_generation,
                ],
            )
            .map_err(AgentTaskStartJournalError::database)?;
        if removed != 1 {
            return Ok(AgentTaskStartChangedCleanupDeleteOutcome::ClaimLost);
        }
        tx.commit().map_err(AgentTaskStartJournalError::database)?;
        Ok(AgentTaskStartChangedCleanupDeleteOutcome::Deleted)
    }

    /// Remove a still-unapplied `finalize` marker when its A graph changed. An unbound marker uses
    /// its local no-wire proof; a bound marker requires the daemon's exact operation token to be
    /// retired as Unapplied. Exact A continues to use the stronger atomic journal-plus-Unknown-
    /// Session compensation path; this fallback touches no product row.
    pub fn delete_changed_finalize_after_proven_unapplied(
        &self,
        claim: &ClaimedAgentTaskStart,
        proof: &ProvenUnappliedAgentTaskStart,
    ) -> Result<AgentTaskStartChangedUnappliedDeleteOutcome, AgentTaskStartJournalError> {
        if claim.row.disposition != AgentTaskStartDisposition::Finalize {
            return Ok(AgentTaskStartChangedUnappliedDeleteOutcome::NotFinalize);
        }
        if claim.row.applied_generation.is_some() || claim.row.applied_state.is_some() {
            return Ok(AgentTaskStartChangedUnappliedDeleteOutcome::Applied);
        }
        if !unapplied_proof_matches(&claim.row, proof) {
            return Ok(AgentTaskStartChangedUnappliedDeleteOutcome::ProofMismatch);
        }

        let arc =
            crate::db::conn_for(self.paths.base()).map_err(AgentTaskStartJournalError::database)?;
        let mut connection = arc.lock().unwrap_or_else(|poisoned| poisoned.into_inner());
        let tx = connection
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(AgentTaskStartJournalError::database)?;
        let identity_absent: bool = tx
            .query_row(
                "SELECT NOT EXISTS(SELECT 1 FROM pending_agent_task_starts \
                 WHERE session_id = ?1 OR operation_token = ?2)",
                rusqlite::params![claim.row.session_id, claim.row.operation_token.as_str()],
                |row| row.get(0),
            )
            .map_err(AgentTaskStartJournalError::database)?;
        if identity_absent {
            tx.commit().map_err(AgentTaskStartJournalError::database)?;
            return Ok(AgentTaskStartChangedUnappliedDeleteOutcome::AlreadyDeleted);
        }
        let now_ms = clock_ms()?;
        if !claim_is_current(&tx, &claim.row, now_ms)? {
            return Ok(AgentTaskStartChangedUnappliedDeleteOutcome::ClaimLost);
        }
        if load_exact_graph_a(&tx, &claim.row)?.0 == GraphState::ExactPreparedA {
            return Ok(AgentTaskStartChangedUnappliedDeleteOutcome::GraphStillExact);
        }
        let removed = tx
            .execute(
                "DELETE FROM pending_agent_task_starts \
                 WHERE session_id = ?1 AND operation_token = ?2 AND lease_token = ?3 \
                   AND lease_until_ms = ?4 AND lease_until_ms > ?5 \
                   AND binding_state = ?6 AND daemon_instance_id IS ?7 \
                   AND disposition = 'finalize' AND applied_generation IS NULL \
                   AND applied_state IS NULL",
                rusqlite::params![
                    claim.row.session_id,
                    claim.row.operation_token.as_str(),
                    claim.row.lease_token,
                    checked_sql_ms(claim.row.lease_until_ms)?,
                    checked_sql_ms(now_ms)?,
                    claim.row.binding_state.as_sql(),
                    proof
                        .daemon_instance_id
                        .as_ref()
                        .map(DaemonInstanceId::as_str),
                ],
            )
            .map_err(AgentTaskStartJournalError::database)?;
        if removed != 1 {
            return Ok(AgentTaskStartChangedUnappliedDeleteOutcome::ClaimLost);
        }
        tx.commit().map_err(AgentTaskStartJournalError::database)?;
        Ok(AgentTaskStartChangedUnappliedDeleteOutcome::Deleted)
    }
}

fn claim_is_current(
    connection: &rusqlite::Connection,
    row: &JournalRow,
    now_ms: u64,
) -> Result<bool, AgentTaskStartJournalError> {
    if row.lease_until_ms <= now_ms {
        return Ok(false);
    }
    connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM pending_agent_task_starts \
             WHERE session_id = ?1 AND agent_task_id = ?2 AND project_id = ?3 \
               AND workspace_id = ?4 AND operation_token = ?5 AND binding_state = ?6 \
               AND daemon_instance_id IS ?7 AND server_pid IS ?8 AND socket_path IS ?9 \
               AND session_a_sha256 = ?10 AND task_a_sha256 = ?11 \
               AND project_sha256 = ?12 AND workspace_sha256 = ?13 \
               AND publication_launch_json = ?14 AND publication_now_ms = ?15 \
               AND disposition = ?16 AND applied_generation IS ?17 AND applied_state IS ?18 \
               AND created_at_ms = ?19 AND lease_token = ?20 AND lease_until_ms = ?21 \
               AND lease_until_ms > ?22)",
            rusqlite::params![
                row.session_id,
                row.agent_task_id,
                row.project_id,
                row.workspace_id,
                row.operation_token.as_str(),
                row.binding_state.as_sql(),
                row.daemon_instance_id
                    .as_ref()
                    .map(DaemonInstanceId::as_str),
                row.server_pid.map(i64::from),
                row.socket_path.as_deref(),
                row.session_a_sha256.as_slice(),
                row.task_a_sha256.as_slice(),
                row.project_sha256.as_slice(),
                row.workspace_sha256.as_slice(),
                row.publication_launch_json,
                checked_sql_ms(row.publication_now_ms)?,
                row.disposition.as_sql(),
                row.applied_generation.as_deref(),
                row.applied_state.map(AppliedAgentTaskStartState::as_sql),
                checked_sql_ms(row.created_at_ms)?,
                row.lease_token,
                checked_sql_ms(row.lease_until_ms)?,
                checked_sql_ms(now_ms)?,
            ],
            |sqlite_row| sqlite_row.get(0),
        )
        .map_err(AgentTaskStartJournalError::database)
}

fn unapplied_proof_matches(row: &JournalRow, proof: &ProvenUnappliedAgentTaskStart) -> bool {
    row.operation_token == proof.operation_token
        && match row.binding_state {
            AgentTaskStartBindingState::Unbound => proof.daemon_instance_id.is_none(),
            AgentTaskStartBindingState::Bound => {
                row.daemon_instance_id.as_ref() == proof.daemon_instance_id.as_ref()
            }
        }
}

fn retired_proof_matches(row: &JournalRow, proof: &RetiredAgentTaskStartOperation) -> bool {
    row.operation_token == proof.operation_token
        && row.daemon_instance_id.as_ref() == Some(&proof.daemon_instance_id)
        && row.applied_generation.as_deref() == Some(proof.applied_generation.as_str())
}

fn cleaned_retired_proof_matches(
    row: &JournalRow,
    proof: &CleanedAndRetiredAgentTaskStartOperation,
) -> bool {
    row.operation_token == proof.operation_token
        && row.daemon_instance_id.as_ref() == Some(&proof.daemon_instance_id)
        && row.applied_generation.as_deref() == Some(proof.applied_generation.as_str())
}

fn applied_state_may_advance(
    current: Option<AppliedAgentTaskStartState>,
    next: AppliedAgentTaskStartState,
) -> bool {
    match current {
        None => true,
        Some(AppliedAgentTaskStartState::Live) => matches!(
            next,
            AppliedAgentTaskStartState::Live
                | AppliedAgentTaskStartState::Exited
                | AppliedAgentTaskStartState::Removed
        ),
        Some(AppliedAgentTaskStartState::Exited) => matches!(
            next,
            AppliedAgentTaskStartState::Exited | AppliedAgentTaskStartState::Removed
        ),
        Some(AppliedAgentTaskStartState::Removed) => next == AppliedAgentTaskStartState::Removed,
    }
}

fn canonical_fingerprint<T: serde::Serialize>(
    value: &T,
) -> Result<[u8; 32], AgentTaskStartJournalError> {
    let bytes = serde_json::to_vec(value)
        .map_err(|_| AgentTaskStartJournalError::corrupt("canonical graph record"))?;
    Ok(Sha256::digest(bytes).into())
}

fn load_typed<T: serde::de::DeserializeOwned>(
    connection: &rusqlite::Connection,
    kind: RecordKind,
    id: &str,
    field: &'static str,
) -> Result<Option<T>, AgentTaskStartJournalError> {
    crate::store_sqlite::load_one(connection, kind, id)
        .map_err(AgentTaskStartJournalError::database)?
        .map(|value| {
            serde_json::from_value(value).map_err(|_| AgentTaskStartJournalError::corrupt(field))
        })
        .transpose()
}

fn load_exact_graph_a(
    connection: &rusqlite::Connection,
    row: &JournalRow,
) -> Result<(GraphState, Option<GraphA>), AgentTaskStartJournalError> {
    let project = load_typed::<Project>(
        connection,
        RecordKind::Project,
        &row.project_id,
        "Project A",
    )?;
    let workspace = load_typed::<Workspace>(
        connection,
        RecordKind::Workspace,
        &row.workspace_id,
        "Workspace A",
    )?;
    let task = load_typed::<AgentTask>(
        connection,
        RecordKind::AgentTask,
        &row.agent_task_id,
        "AgentTask A",
    )?;
    let session = load_typed::<SessionRecord>(
        connection,
        RecordKind::Session,
        &row.session_id,
        "Session A",
    )?;
    let (Some(project), Some(workspace), Some(task), Some(session)) =
        (project, workspace, task, session)
    else {
        return Ok((GraphState::Changed, None));
    };
    let graph = GraphA {
        project,
        workspace,
        task,
        session,
    };
    let hashes_match = canonical_fingerprint(&graph.session)? == row.session_a_sha256
        && canonical_fingerprint(&graph.task)? == row.task_a_sha256
        && canonical_fingerprint(&graph.project)? == row.project_sha256
        && canonical_fingerprint(&graph.workspace)? == row.workspace_sha256;
    if !hashes_match || !graph_a_relational_cohort_matches(connection, row, &graph)? {
        return Ok((GraphState::Changed, Some(graph)));
    }
    Ok((GraphState::ExactPreparedA, Some(graph)))
}

fn graph_a_relational_cohort_matches(
    connection: &rusqlite::Connection,
    row: &JournalRow,
    graph: &GraphA,
) -> Result<bool, AgentTaskStartJournalError> {
    if graph.project.project_id != row.project_id
        || graph.workspace.workspace_id != row.workspace_id
        || graph.workspace.project_id != row.project_id
        || graph.task.agent_task_id != row.agent_task_id
        || graph.task.project_id != row.project_id
        || graph.session.session_id != row.session_id
        || graph.session.workspace_id != row.workspace_id
        || graph.session.agent_task_id.as_deref() != Some(row.agent_task_id.as_str())
        || graph.session.kind != SessionKind::Agent
        || graph.session.status != SessionStatus::Unknown
        || graph.session.last_known_generation.is_some()
        || graph.session.created_at_ms != row.publication_now_ms
        || graph.session.last_attached_at_ms != row.publication_now_ms
    {
        return Ok(false);
    }
    let mut task_refs = HashSet::new();
    for id in &graph.task.session_history {
        if crate::validate_id(id).is_err() || !task_refs.insert(id.clone()) {
            return Ok(false);
        }
    }
    if let Some(current) = &graph.task.current_session_id {
        if crate::validate_id(current).is_err() || !task_refs.insert(current.clone()) {
            return Ok(false);
        }
    }
    if task_refs.contains(&row.session_id) {
        return Ok(false);
    }
    for referenced_id in &task_refs {
        if let Some(referenced) = load_typed::<SessionRecord>(
            connection,
            RecordKind::Session,
            referenced_id,
            "AgentTask referenced Session",
        )? {
            if referenced.agent_task_id.as_deref() != Some(row.agent_task_id.as_str()) {
                return Ok(false);
            }
            let Some(referenced_workspace) = load_typed::<Workspace>(
                connection,
                RecordKind::Workspace,
                &referenced.workspace_id,
                "AgentTask referenced Workspace",
            )?
            else {
                return Ok(false);
            };
            if referenced_workspace.project_id != row.project_id {
                return Ok(false);
            }
        }
    }
    let mut statement = connection
        .prepare("SELECT session_id FROM sessions WHERE agent_task_id = ?1 ORDER BY session_id")
        .map_err(AgentTaskStartJournalError::database)?;
    let backlink_rows = statement
        .query_map([&row.agent_task_id], |sqlite_row| {
            sqlite_row.get::<_, String>(0)
        })
        .map_err(AgentTaskStartJournalError::database)?;
    let mut saw_pending = false;
    for backlink in backlink_rows {
        let backlink = backlink.map_err(AgentTaskStartJournalError::database)?;
        if backlink == row.session_id {
            saw_pending = true;
        } else if !task_refs.contains(&backlink) {
            return Ok(false);
        }
    }
    drop(statement);
    if !saw_pending || session_has_unplaced_soft_owner(connection, &row.session_id)? {
        return Ok(false);
    }
    Ok(true)
}

fn session_has_unplaced_soft_owner(
    connection: &rusqlite::Connection,
    session_id: &str,
) -> Result<bool, AgentTaskStartJournalError> {
    let direct: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM tabs WHERE session_id = ?1) \
             OR EXISTS(SELECT 1 FROM worktree_provenance WHERE session_id = ?1)",
            [session_id],
            |row| row.get(0),
        )
        .map_err(AgentTaskStartJournalError::database)?;
    if direct {
        return Ok(true);
    }
    let mut task_statement = connection
        .prepare(
            "SELECT current_session_id, session_history_json FROM agent_tasks \
             ORDER BY agent_task_id",
        )
        .map_err(AgentTaskStartJournalError::database)?;
    let task_rows = task_statement
        .query_map([], |row| {
            Ok((row.get::<_, Option<String>>(0)?, row.get::<_, String>(1)?))
        })
        .map_err(AgentTaskStartJournalError::database)?;
    for task_row in task_rows {
        let (current, history_json) = task_row.map_err(AgentTaskStartJournalError::database)?;
        let history: Vec<String> = serde_json::from_str(&history_json)
            .map_err(|_| AgentTaskStartJournalError::corrupt("AgentTask session history"))?;
        if current.as_deref() == Some(session_id)
            || history.iter().any(|history_id| history_id == session_id)
        {
            return Ok(true);
        }
        if current
            .as_deref()
            .is_some_and(|id| crate::validate_id(id).is_err())
            || history.iter().any(|id| crate::validate_id(id).is_err())
        {
            return Err(AgentTaskStartJournalError::corrupt(
                "AgentTask session reference",
            ));
        }
    }
    drop(task_statement);
    let mut statement = connection
        .prepare("SELECT tabs_json FROM layout_presets ORDER BY preset_id")
        .map_err(AgentTaskStartJournalError::database)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(AgentTaskStartJournalError::database)?;
    for tabs_json in rows {
        let tabs_json = tabs_json.map_err(AgentTaskStartJournalError::database)?;
        let tabs: Vec<crate::records::LayoutPresetTab> = serde_json::from_str(&tabs_json)
            .map_err(|_| AgentTaskStartJournalError::corrupt("layout preset tabs"))?;
        if tabs
            .iter()
            .any(|tab| tab.session_id.as_deref() == Some(session_id))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

fn derive_publication(
    row: &JournalRow,
    graph: &GraphA,
    generation: &str,
    status: SessionStatus,
) -> Result<(SessionRecord, AgentTask), AgentTaskStartJournalError> {
    if generation.is_empty() || generation.len() > crate::ids::MAX_ID_LEN {
        return Err(AgentTaskStartJournalError::corrupt("applied generation"));
    }
    let mut session = graph.session.clone();
    session.launch = row.publication_launch.clone();
    session.last_attached_at_ms = row.publication_now_ms;
    session.last_known_generation = Some(generation.to_string());
    session.status = status;

    let mut task = graph.task.clone();
    if let Some(previous) = task.current_session_id.take() {
        if previous != session.session_id {
            task.session_history.push(previous);
        }
    }
    task.state = AgentTaskState::Running;
    task.current_session_id = Some(session.session_id.clone());
    task.result_summary = None;
    task.updated_at_ms = row.publication_now_ms;
    Ok((session, task))
}

fn published_cohort_matches(
    connection: &rusqlite::Connection,
    row: &JournalRow,
    graph_a: &GraphA,
    session_b: &SessionRecord,
    task_b: &AgentTask,
) -> Result<bool, AgentTaskStartJournalError> {
    if load_typed::<Project>(
        connection,
        RecordKind::Project,
        &row.project_id,
        "Project B",
    )?
    .as_ref()
        != Some(&graph_a.project)
        || load_typed::<Workspace>(
            connection,
            RecordKind::Workspace,
            &row.workspace_id,
            "Workspace B",
        )?
        .as_ref()
            != Some(&graph_a.workspace)
        || load_typed::<SessionRecord>(
            connection,
            RecordKind::Session,
            &row.session_id,
            "Session B",
        )?
        .as_ref()
            != Some(session_b)
        || load_typed::<AgentTask>(
            connection,
            RecordKind::AgentTask,
            &row.agent_task_id,
            "AgentTask B",
        )?
        .as_ref()
            != Some(task_b)
        || task_b.current_session_id.as_deref() != Some(row.session_id.as_str())
        || session_b.agent_task_id.as_deref() != Some(row.agent_task_id.as_str())
        || session_has_non_task_soft_owner(connection, &row.session_id)?
    {
        return Ok(false);
    }
    let mut allowed = task_b
        .session_history
        .iter()
        .cloned()
        .collect::<HashSet<_>>();
    if !allowed.insert(row.session_id.clone()) {
        return Ok(false);
    }
    let mut statement = connection
        .prepare("SELECT session_id FROM sessions WHERE agent_task_id = ?1 ORDER BY session_id")
        .map_err(AgentTaskStartJournalError::database)?;
    let rows = statement
        .query_map([&row.agent_task_id], |sqlite_row| {
            sqlite_row.get::<_, String>(0)
        })
        .map_err(AgentTaskStartJournalError::database)?;
    for session_id in rows {
        if !allowed.contains(&session_id.map_err(AgentTaskStartJournalError::database)?) {
            return Ok(false);
        }
    }
    Ok(true)
}

fn session_has_non_task_soft_owner(
    connection: &rusqlite::Connection,
    session_id: &str,
) -> Result<bool, AgentTaskStartJournalError> {
    let direct: bool = connection
        .query_row(
            "SELECT EXISTS(SELECT 1 FROM tabs WHERE session_id = ?1) \
             OR EXISTS(SELECT 1 FROM worktree_provenance WHERE session_id = ?1)",
            [session_id],
            |row| row.get(0),
        )
        .map_err(AgentTaskStartJournalError::database)?;
    if direct {
        return Ok(true);
    }
    let mut statement = connection
        .prepare("SELECT tabs_json FROM layout_presets ORDER BY preset_id")
        .map_err(AgentTaskStartJournalError::database)?;
    let rows = statement
        .query_map([], |row| row.get::<_, String>(0))
        .map_err(AgentTaskStartJournalError::database)?;
    for tabs_json in rows {
        let tabs_json = tabs_json.map_err(AgentTaskStartJournalError::database)?;
        let tabs: Vec<crate::records::LayoutPresetTab> = serde_json::from_str(&tabs_json)
            .map_err(|_| AgentTaskStartJournalError::corrupt("layout preset tabs"))?;
        if tabs
            .iter()
            .any(|tab| tab.session_id.as_deref() == Some(session_id))
        {
            return Ok(true);
        }
    }
    Ok(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::WorkspacePolicy;
    use crate::records::{ProjectLaunchDefaults, WorkspaceConsent};

    const PRIVATE_GOAL: &str = "PRIVATE_GOAL_NEVER_LOG";
    const PRIVATE_RESULT: &str = "PRIVATE_RESULT_NEVER_LOG";
    const PRIVATE_COMMAND: &str = "PRIVATE_COMMAND_NEVER_LOG";
    const PRIVATE_ARGV: &str = "PRIVATE_ARGV_NEVER_LOG";
    const PRIVATE_PARAM: &str = "PRIVATE_PARAM_NEVER_LOG";
    const PRIVATE_SOCKET: &str = "/tmp/PRIVATE_SOCKET_NEVER_LOG.sock";

    struct Fixture {
        session_a: SessionRecord,
        task_a: AgentTask,
        publication_launch: LaunchSpec,
        operation_token: SessionStartOperationToken,
        daemon_instance_id: Option<DaemonInstanceId>,
        generation: Option<String>,
    }

    fn test_paths() -> (tempfile::TempDir, AppPaths) {
        let temp = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_base(temp.path().join("Maestro"));
        (temp, paths)
    }

    fn seed(
        paths: &AppPaths,
        suffix: &str,
        binding: AgentTaskStartBindingState,
        applied: Option<AppliedAgentTaskStartState>,
        wrong_session_hash: bool,
    ) -> Fixture {
        let project_id = format!("project-{suffix}");
        let workspace_id = format!("workspace-{suffix}");
        let task_id = format!("task-{suffix}");
        let session_id = format!("session-{suffix}");
        let project = Project {
            project_id: project_id.clone(),
            name: "Private project name".into(),
            root: "/private/project/root".into(),
            default_workspace_policy: WorkspacePolicy::ScratchCwd,
            created_at_ms: 11,
            last_active_at_ms: 12,
            icon: None,
            accent_color: None,
            launch_defaults: Some(ProjectLaunchDefaults {
                custom_command: Some(PRIVATE_COMMAND.into()),
                ..ProjectLaunchDefaults::default()
            }),
            directories: Vec::new(),
            window_order: Vec::new(),
            system: false,
            hidden: false,
        };
        let workspace = Workspace {
            workspace_id: workspace_id.clone(),
            project_id: project_id.clone(),
            root: "/private/workspace/root".into(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        };
        let task_a = AgentTask {
            agent_task_id: task_id.clone(),
            project_id: project_id.clone(),
            goal: PRIVATE_GOAL.into(),
            state: AgentTaskState::Failed,
            current_session_id: None,
            session_history: Vec::new(),
            created_at_ms: 41,
            updated_at_ms: 42,
            result_summary: Some(PRIVATE_RESULT.into()),
        };
        let session_a = SessionRecord {
            session_id: session_id.clone(),
            workspace_id: workspace_id.clone(),
            kind: SessionKind::Agent,
            launch: LaunchSpec::AdHocRedacted {
                argv: vec![PRIVATE_ARGV.into()],
                redacted: true,
                restart_requires_user: true,
            },
            cwd_resolved: "/private/workspace/root".into(),
            agent_task_id: Some(task_id.clone()),
            created_at_ms: 77,
            last_attached_at_ms: 77,
            last_known_generation: None,
            status: SessionStatus::Unknown,
        };
        let publication_launch = LaunchSpec::KnownSafe {
            launch_spec_id: "provider_resume".into(),
            params: vec![PRIVATE_PARAM.into()],
        };
        crate::store::write_record(paths, RecordKind::Project, &project_id, 77, &project).unwrap();
        crate::store::write_record(paths, RecordKind::Workspace, &workspace_id, 77, &workspace)
            .unwrap();
        crate::store::write_record(paths, RecordKind::AgentTask, &task_id, 77, &task_a).unwrap();
        crate::store::write_record(paths, RecordKind::Session, &session_id, 77, &session_a)
            .unwrap();
        let operation_token: SessionStartOperationToken =
            uuid::Uuid::new_v4().simple().to_string().parse().unwrap();
        let daemon_instance_id = (binding == AgentTaskStartBindingState::Bound).then(|| {
            uuid::Uuid::new_v4()
                .simple()
                .to_string()
                .parse::<DaemonInstanceId>()
                .unwrap()
        });
        let generation = applied.map(|_| format!("generation-{suffix}"));
        let mut session_hash = canonical_fingerprint(&session_a).unwrap();
        if wrong_session_hash {
            session_hash[0] ^= 0xff;
        }
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let connection = arc.lock().unwrap();
        connection
            .execute(
                "INSERT INTO pending_agent_task_starts \
                 (session_id, agent_task_id, project_id, workspace_id, operation_token, \
                  binding_state, daemon_instance_id, server_pid, socket_path, session_a_sha256, \
                  task_a_sha256, project_sha256, workspace_sha256, publication_launch_json, \
                  publication_now_ms, disposition, applied_generation, applied_state, created_at_ms, \
                  lease_token, lease_until_ms) \
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10, ?11, ?12, ?13, ?14, \
                         77, 'finalize', ?15, ?16, 1, NULL, NULL)",
                rusqlite::params![
                    session_id,
                    task_id,
                    project_id,
                    workspace_id,
                    operation_token.as_str(),
                    binding.as_sql(),
                    daemon_instance_id.as_ref().map(DaemonInstanceId::as_str),
                    (binding == AgentTaskStartBindingState::Bound).then_some(4242_i64),
                    (binding == AgentTaskStartBindingState::Bound).then_some(PRIVATE_SOCKET),
                    session_hash.as_slice(),
                    canonical_fingerprint(&task_a).unwrap().as_slice(),
                    canonical_fingerprint(&project).unwrap().as_slice(),
                    canonical_fingerprint(&workspace).unwrap().as_slice(),
                    serde_json::to_string(&publication_launch).unwrap(),
                    generation.as_deref(),
                    applied.map(AppliedAgentTaskStartState::as_sql),
                ],
            )
            .unwrap();
        drop(connection);
        Fixture {
            session_a,
            task_a,
            publication_launch,
            operation_token,
            daemon_instance_id,
            generation,
        }
    }

    fn journal_count(paths: &AppPaths) -> i64 {
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let connection = arc.lock().unwrap();
        connection
            .query_row(
                "SELECT COUNT(*) FROM pending_agent_task_starts",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    fn load_record<T: serde::de::DeserializeOwned>(
        paths: &AppPaths,
        kind: RecordKind,
        id: &str,
    ) -> Option<T> {
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let connection = arc.lock().unwrap();
        load_typed(&connection, kind, id, "test record").unwrap()
    }

    #[test]
    fn oldest_expired_row_has_one_exact_rotated_lease_winner() {
        let (_temp, paths) = test_paths();
        seed(
            &paths,
            "lease-race",
            AgentTaskStartBindingState::Unbound,
            None,
            false,
        );
        let barrier = std::sync::Arc::new(std::sync::Barrier::new(3));
        let mut handles = Vec::new();
        for _ in 0..2 {
            let paths = paths.clone();
            let barrier = std::sync::Arc::clone(&barrier);
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                AgentTaskStartJournalService::new(&paths)
                    .claim_next()
                    .unwrap()
                    .is_some()
            }));
        }
        barrier.wait();
        let winners = handles
            .into_iter()
            .map(|handle| handle.join().unwrap())
            .filter(|won| *won)
            .count();
        assert_eq!(winners, 1);
        assert_eq!(journal_count(&paths), 1);
    }

    #[test]
    fn reclaimed_lease_rejects_every_stale_claim_mutation() {
        let (_temp, paths) = test_paths();
        seed(
            &paths,
            "lease-reclaim",
            AgentTaskStartBindingState::Unbound,
            None,
            false,
        );
        let service = AgentTaskStartJournalService::new(&paths);
        let stale = service.claim_next().unwrap().unwrap();
        let stale_proof = stale.prove_unbound_unapplied().unwrap();
        {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let connection = arc.lock().unwrap();
            connection
                .execute(
                    "UPDATE pending_agent_task_starts SET lease_until_ms = 0 \
                     WHERE session_id = ?1",
                    [stale.session_id()],
                )
                .unwrap();
        }
        let current = service.claim_next().unwrap().unwrap();
        assert_eq!(
            service
                .compensate_proven_unapplied(&stale, &stale_proof)
                .unwrap(),
            AgentTaskStartCompensationOutcome::ClaimLost
        );
        let current_proof = current.prove_unbound_unapplied().unwrap();
        assert_eq!(
            service
                .compensate_proven_unapplied(&current, &current_proof)
                .unwrap(),
            AgentTaskStartCompensationOutcome::Compensated
        );
    }

    #[test]
    fn applied_mark_rotates_claim_and_allows_only_same_generation_forward_lifecycle() {
        let (_temp, paths) = test_paths();
        let fixture = seed(
            &paths,
            "applied-mark",
            AgentTaskStartBindingState::Bound,
            None,
            false,
        );
        let service = AgentTaskStartJournalService::new(&paths);
        let mut claim = service.claim_next().unwrap().unwrap();
        let initial_lease = claim.row.lease_token.clone();
        let generation = "generation-applied-mark";
        assert_eq!(
            service
                .mark_claimed_applied(&mut claim, generation, AppliedAgentTaskStartState::Live)
                .unwrap(),
            AgentTaskStartAppliedMarkOutcome::Marked
        );
        assert_ne!(claim.row.lease_token, initial_lease);
        let live_lease = claim.row.lease_token.clone();
        assert_eq!(claim.applied_generation(), Some(generation));
        assert_eq!(
            service
                .mark_claimed_applied(&mut claim, generation, AppliedAgentTaskStartState::Live)
                .unwrap(),
            AgentTaskStartAppliedMarkOutcome::Marked
        );
        assert_ne!(claim.row.lease_token, live_lease);
        assert_eq!(
            service
                .mark_claimed_applied(&mut claim, generation, AppliedAgentTaskStartState::Exited,)
                .unwrap(),
            AgentTaskStartAppliedMarkOutcome::Marked
        );
        assert_eq!(
            service
                .mark_claimed_applied(&mut claim, generation, AppliedAgentTaskStartState::Removed,)
                .unwrap(),
            AgentTaskStartAppliedMarkOutcome::Marked
        );
        let removed_lease = claim.row.lease_token.clone();
        assert_eq!(
            service
                .mark_claimed_applied(&mut claim, generation, AppliedAgentTaskStartState::Exited,)
                .unwrap(),
            AgentTaskStartAppliedMarkOutcome::ReverseTransition
        );
        assert_eq!(claim.row.lease_token, removed_lease);
        assert_eq!(
            service
                .mark_claimed_applied(
                    &mut claim,
                    "different-generation",
                    AppliedAgentTaskStartState::Removed,
                )
                .unwrap(),
            AgentTaskStartAppliedMarkOutcome::GenerationMismatch
        );
        assert_eq!(
            service
                .mark_claimed_applied(&mut claim, "", AppliedAgentTaskStartState::Removed)
                .unwrap(),
            AgentTaskStartAppliedMarkOutcome::InvalidGeneration
        );
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let connection = arc.lock().unwrap();
        let stored: (String, String, String) = connection
            .query_row(
                "SELECT applied_generation, applied_state, lease_token \
                 FROM pending_agent_task_starts WHERE session_id = ?1",
                [&fixture.session_a.session_id],
                |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)),
            )
            .unwrap();
        assert_eq!(stored.0, generation);
        assert_eq!(stored.1, "removed");
        assert_eq!(stored.2, claim.row.lease_token);
    }

    #[test]
    fn changed_applied_finalize_requires_removed_cleanup_and_exact_retirement_proof() {
        let (_temp, paths) = test_paths();
        let fixture = seed(
            &paths,
            "changed-cleanup",
            AgentTaskStartBindingState::Bound,
            Some(AppliedAgentTaskStartState::Live),
            true,
        );
        let service = AgentTaskStartJournalService::new(&paths);
        let mut claim = service.claim_next().unwrap().unwrap();
        let generation = fixture.generation.as_deref().unwrap();
        let exact_proof = CleanedAndRetiredAgentTaskStartOperation::confirmed(
            fixture.operation_token.clone(),
            fixture.daemon_instance_id.clone().unwrap(),
            generation,
        );
        assert_eq!(
            service
                .delete_changed_finalize_after_cleanup_and_retirement(&claim, &exact_proof)
                .unwrap(),
            AgentTaskStartChangedCleanupDeleteOutcome::NotRemoved
        );
        assert_eq!(
            service
                .mark_claimed_applied(&mut claim, generation, AppliedAgentTaskStartState::Removed,)
                .unwrap(),
            AgentTaskStartAppliedMarkOutcome::Marked
        );
        let wrong_daemon = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .parse::<DaemonInstanceId>()
            .unwrap();
        let wrong_proof = CleanedAndRetiredAgentTaskStartOperation::confirmed(
            fixture.operation_token.clone(),
            wrong_daemon,
            generation,
        );
        assert_eq!(
            service
                .delete_changed_finalize_after_cleanup_and_retirement(&claim, &wrong_proof)
                .unwrap(),
            AgentTaskStartChangedCleanupDeleteOutcome::ProofMismatch
        );
        let session_before: SessionRecord =
            load_record(&paths, RecordKind::Session, &fixture.session_a.session_id).unwrap();
        let task_before: AgentTask =
            load_record(&paths, RecordKind::AgentTask, &fixture.task_a.agent_task_id).unwrap();
        assert_eq!(
            service
                .delete_changed_finalize_after_cleanup_and_retirement(&claim, &exact_proof)
                .unwrap(),
            AgentTaskStartChangedCleanupDeleteOutcome::Deleted
        );
        assert_eq!(journal_count(&paths), 0);
        assert_eq!(
            load_record::<SessionRecord>(
                &paths,
                RecordKind::Session,
                &fixture.session_a.session_id,
            ),
            Some(session_before)
        );
        assert_eq!(
            load_record::<AgentTask>(&paths, RecordKind::AgentTask, &fixture.task_a.agent_task_id,),
            Some(task_before)
        );
        assert_eq!(
            service
                .delete_changed_finalize_after_cleanup_and_retirement(&claim, &exact_proof)
                .unwrap(),
            AgentTaskStartChangedCleanupDeleteOutcome::AlreadyDeleted
        );

        let (_exact_temp, exact_paths) = test_paths();
        let exact_fixture = seed(
            &exact_paths,
            "exact-cleanup-refusal",
            AgentTaskStartBindingState::Bound,
            Some(AppliedAgentTaskStartState::Removed),
            false,
        );
        let exact_service = AgentTaskStartJournalService::new(&exact_paths);
        let exact_claim = exact_service.claim_next().unwrap().unwrap();
        let exact_graph_proof = CleanedAndRetiredAgentTaskStartOperation::confirmed(
            exact_fixture.operation_token,
            exact_fixture.daemon_instance_id.unwrap(),
            exact_fixture.generation.unwrap(),
        );
        assert_eq!(
            exact_service
                .delete_changed_finalize_after_cleanup_and_retirement(
                    &exact_claim,
                    &exact_graph_proof,
                )
                .unwrap(),
            AgentTaskStartChangedCleanupDeleteOutcome::GraphStillExact
        );
        assert_eq!(journal_count(&exact_paths), 1);
    }

    #[test]
    fn changed_bound_and_unbound_unapplied_finalize_delete_only_the_journal() {
        let (_temp, paths) = test_paths();
        let fixture = seed(
            &paths,
            "changed-unapplied",
            AgentTaskStartBindingState::Bound,
            None,
            true,
        );
        let service = AgentTaskStartJournalService::new(&paths);
        let claim = service.claim_next().unwrap().unwrap();
        let proof = ProvenUnappliedAgentTaskStart::bound_operation_retired(
            fixture.operation_token.clone(),
            fixture.daemon_instance_id.clone().unwrap(),
        );
        let session_before: SessionRecord =
            load_record(&paths, RecordKind::Session, &fixture.session_a.session_id).unwrap();
        let task_before: AgentTask =
            load_record(&paths, RecordKind::AgentTask, &fixture.task_a.agent_task_id).unwrap();
        assert_eq!(
            service
                .delete_changed_finalize_after_proven_unapplied(&claim, &proof)
                .unwrap(),
            AgentTaskStartChangedUnappliedDeleteOutcome::Deleted
        );
        assert_eq!(journal_count(&paths), 0);
        assert_eq!(
            load_record::<SessionRecord>(
                &paths,
                RecordKind::Session,
                &fixture.session_a.session_id,
            ),
            Some(session_before)
        );
        assert_eq!(
            load_record::<AgentTask>(&paths, RecordKind::AgentTask, &fixture.task_a.agent_task_id,),
            Some(task_before)
        );
        assert_eq!(
            service
                .delete_changed_finalize_after_proven_unapplied(&claim, &proof)
                .unwrap(),
            AgentTaskStartChangedUnappliedDeleteOutcome::AlreadyDeleted
        );

        let (_exact_temp, exact_paths) = test_paths();
        let exact_fixture = seed(
            &exact_paths,
            "exact-unapplied-refusal",
            AgentTaskStartBindingState::Bound,
            None,
            false,
        );
        let exact_service = AgentTaskStartJournalService::new(&exact_paths);
        let exact_claim = exact_service.claim_next().unwrap().unwrap();
        let exact_proof = ProvenUnappliedAgentTaskStart::bound_operation_retired(
            exact_fixture.operation_token,
            exact_fixture.daemon_instance_id.unwrap(),
        );
        assert_eq!(
            exact_service
                .delete_changed_finalize_after_proven_unapplied(&exact_claim, &exact_proof)
                .unwrap(),
            AgentTaskStartChangedUnappliedDeleteOutcome::GraphStillExact
        );

        let (_unbound_temp, unbound_paths) = test_paths();
        let unbound_fixture = seed(
            &unbound_paths,
            "changed-unbound",
            AgentTaskStartBindingState::Unbound,
            None,
            true,
        );
        let unbound_service = AgentTaskStartJournalService::new(&unbound_paths);
        let unbound_claim = unbound_service.claim_next().unwrap().unwrap();
        let unbound_proof = unbound_claim.prove_unbound_unapplied().unwrap();
        assert_eq!(
            unbound_service
                .delete_changed_finalize_after_proven_unapplied(&unbound_claim, &unbound_proof,)
                .unwrap(),
            AgentTaskStartChangedUnappliedDeleteOutcome::Deleted
        );
        assert_eq!(journal_count(&unbound_paths), 0);
        assert!(load_record::<SessionRecord>(
            &unbound_paths,
            RecordKind::Session,
            &unbound_fixture.session_a.session_id,
        )
        .is_some());
    }

    #[test]
    fn hash_and_live_graph_tamper_classify_changed_without_graph_mutation() {
        let (_temp, paths) = test_paths();
        let wrong_hash = seed(
            &paths,
            "wrong-hash",
            AgentTaskStartBindingState::Unbound,
            None,
            true,
        );
        let service = AgentTaskStartJournalService::new(&paths);
        let wrong_claim = service.claim_next().unwrap().unwrap();
        assert_eq!(
            wrong_claim.initial_graph(),
            ClaimedAgentTaskStartGraph::Changed
        );
        let wrong_proof = wrong_claim.prove_unbound_unapplied().unwrap();
        assert_eq!(
            service
                .compensate_proven_unapplied(&wrong_claim, &wrong_proof)
                .unwrap(),
            AgentTaskStartCompensationOutcome::GraphChanged
        );
        let unchanged: SessionRecord = load_record(
            &paths,
            RecordKind::Session,
            &wrong_hash.session_a.session_id,
        )
        .unwrap();
        assert_eq!(unchanged, wrong_hash.session_a);

        let graph = seed(
            &paths,
            "graph-tamper",
            AgentTaskStartBindingState::Unbound,
            None,
            false,
        );
        let graph_claim = service.claim_next().unwrap().unwrap();
        assert_eq!(
            graph_claim.initial_graph(),
            ClaimedAgentTaskStartGraph::ExactPreparedA
        );
        {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let connection = arc.lock().unwrap();
            connection
                .execute(
                    "UPDATE agent_tasks SET goal = 'changed' WHERE agent_task_id = ?1",
                    [&graph.task_a.agent_task_id],
                )
                .unwrap();
        }
        assert_eq!(
            service.classify_claimed(&graph_claim).unwrap(),
            ClaimedAgentTaskStartGraph::Changed
        );
        assert_eq!(journal_count(&paths), 2);
    }

    #[test]
    fn compensation_is_exact_atomic_fk_safe_and_preserves_task_a() {
        let (_temp, paths) = test_paths();
        let fixture = seed(
            &paths,
            "compensate",
            AgentTaskStartBindingState::Unbound,
            None,
            false,
        );
        let service = AgentTaskStartJournalService::new(&paths);
        let claim = service.claim_next().unwrap().unwrap();
        let proof = claim.prove_unbound_unapplied().unwrap();
        {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let connection = arc.lock().unwrap();
            assert!(connection
                .execute(
                    "DELETE FROM sessions WHERE session_id = ?1",
                    [&fixture.session_a.session_id],
                )
                .is_err());
            connection
                .execute_batch(&format!(
                    "CREATE TRIGGER test_abort_session_delete BEFORE DELETE ON sessions \
                     WHEN OLD.session_id = '{}' BEGIN SELECT RAISE(ABORT, 'fixed test abort'); END;",
                    fixture.session_a.session_id
                ))
                .unwrap();
        }
        assert!(service.compensate_proven_unapplied(&claim, &proof).is_err());
        assert_eq!(journal_count(&paths), 1);
        assert!(load_record::<SessionRecord>(
            &paths,
            RecordKind::Session,
            &fixture.session_a.session_id,
        )
        .is_some());
        {
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let connection = arc.lock().unwrap();
            connection
                .execute_batch("DROP TRIGGER test_abort_session_delete")
                .unwrap();
        }
        assert_eq!(
            service.compensate_proven_unapplied(&claim, &proof).unwrap(),
            AgentTaskStartCompensationOutcome::Compensated
        );
        assert_eq!(journal_count(&paths), 0);
        assert!(load_record::<SessionRecord>(
            &paths,
            RecordKind::Session,
            &fixture.session_a.session_id,
        )
        .is_none());
        assert_eq!(
            load_record::<AgentTask>(&paths, RecordKind::AgentTask, &fixture.task_a.agent_task_id,),
            Some(fixture.task_a)
        );
    }

    #[test]
    fn bound_compensation_requires_the_exact_retired_unapplied_peer_proof() {
        let (_temp, paths) = test_paths();
        let fixture = seed(
            &paths,
            "bound-compensate",
            AgentTaskStartBindingState::Bound,
            None,
            false,
        );
        let service = AgentTaskStartJournalService::new(&paths);
        let claim = service.claim_next().unwrap().unwrap();
        assert!(claim.prove_unbound_unapplied().is_none());
        let wrong_daemon = uuid::Uuid::new_v4()
            .simple()
            .to_string()
            .parse::<DaemonInstanceId>()
            .unwrap();
        let wrong = ProvenUnappliedAgentTaskStart::bound_operation_retired(
            fixture.operation_token.clone(),
            wrong_daemon,
        );
        assert_eq!(
            service.compensate_proven_unapplied(&claim, &wrong).unwrap(),
            AgentTaskStartCompensationOutcome::ProofMismatch
        );
        let exact = ProvenUnappliedAgentTaskStart::bound_operation_retired(
            fixture.operation_token,
            fixture.daemon_instance_id.unwrap(),
        );
        assert_eq!(
            service.compensate_proven_unapplied(&claim, &exact).unwrap(),
            AgentTaskStartCompensationOutcome::Compensated
        );
    }

    #[test]
    fn applied_live_exited_and_removed_publish_deterministic_b_then_retire_only_the_marker() {
        for (suffix, applied, expected_status, expected_outcome) in [
            (
                "publish-live",
                AppliedAgentTaskStartState::Live,
                SessionStatus::Live,
                AgentTaskStartPublicationOutcome::PublishedLive,
            ),
            (
                "publish-exited",
                AppliedAgentTaskStartState::Exited,
                SessionStatus::Exited,
                AgentTaskStartPublicationOutcome::PublishedExited,
            ),
            (
                "publish-removed",
                AppliedAgentTaskStartState::Removed,
                SessionStatus::Exited,
                AgentTaskStartPublicationOutcome::PublishedExited,
            ),
        ] {
            let (_temp, paths) = test_paths();
            let fixture = seed(
                &paths,
                suffix,
                AgentTaskStartBindingState::Bound,
                Some(applied),
                false,
            );
            let service = AgentTaskStartJournalService::new(&paths);
            let mut claim = service.claim_next().unwrap().unwrap();
            assert_eq!(
                service.publish_applied(&mut claim).unwrap(),
                expected_outcome
            );
            assert_eq!(claim.disposition(), AgentTaskStartDisposition::Release);
            let session_b: SessionRecord =
                load_record(&paths, RecordKind::Session, &fixture.session_a.session_id).unwrap();
            assert_eq!(session_b.status, expected_status);
            assert_eq!(session_b.launch, fixture.publication_launch);
            assert_eq!(session_b.last_known_generation, fixture.generation.clone());
            assert_eq!(session_b.last_attached_at_ms, 77);
            let task_b: AgentTask =
                load_record(&paths, RecordKind::AgentTask, &fixture.task_a.agent_task_id).unwrap();
            assert_eq!(task_b.state, AgentTaskState::Running);
            assert_eq!(
                task_b.current_session_id.as_deref(),
                Some(fixture.session_a.session_id.as_str())
            );
            assert!(task_b.result_summary.is_none());
            assert_eq!(task_b.updated_at_ms, 77);
            assert_eq!(journal_count(&paths), 1);

            let cleanup_proof = CleanedAndRetiredAgentTaskStartOperation::confirmed(
                fixture.operation_token.clone(),
                fixture.daemon_instance_id.clone().unwrap(),
                fixture.generation.clone().unwrap(),
            );
            assert_eq!(
                service
                    .delete_changed_finalize_after_cleanup_and_retirement(&claim, &cleanup_proof,)
                    .unwrap(),
                AgentTaskStartChangedCleanupDeleteOutcome::NotFinalize
            );

            let wrong = RetiredAgentTaskStartOperation::confirmed(
                fixture.operation_token.clone(),
                fixture.daemon_instance_id.clone().unwrap(),
                "wrong-generation",
            );
            assert_eq!(
                service
                    .delete_release_after_operation_retired(&claim, &wrong)
                    .unwrap(),
                AgentTaskStartReleaseDeleteOutcome::ProofMismatch
            );
            let exact = RetiredAgentTaskStartOperation::confirmed(
                fixture.operation_token,
                fixture.daemon_instance_id.unwrap(),
                fixture.generation.unwrap(),
            );
            assert_eq!(
                service
                    .delete_release_after_operation_retired(&claim, &exact)
                    .unwrap(),
                AgentTaskStartReleaseDeleteOutcome::Deleted
            );
            assert_eq!(journal_count(&paths), 0);
            assert!(load_record::<SessionRecord>(
                &paths,
                RecordKind::Session,
                &fixture.session_a.session_id,
            )
            .is_some());
        }
    }

    #[test]
    fn claim_proofs_and_corruption_errors_are_content_redacted() {
        let (_temp, paths) = test_paths();
        let fixture = seed(
            &paths,
            "privacy",
            AgentTaskStartBindingState::Bound,
            None,
            false,
        );
        let service = AgentTaskStartJournalService::new(&paths);
        let claim = service.claim_next().unwrap().unwrap();
        let proof = ProvenUnappliedAgentTaskStart::bound_operation_retired(
            fixture.operation_token.clone(),
            fixture.daemon_instance_id.clone().unwrap(),
        );
        let retired = RetiredAgentTaskStartOperation::confirmed(
            fixture.operation_token.clone(),
            fixture.daemon_instance_id.clone().unwrap(),
            "PRIVATE_GENERATION_NEVER_LOG",
        );
        let cleaned_retired = CleanedAndRetiredAgentTaskStartOperation::confirmed(
            fixture.operation_token,
            fixture.daemon_instance_id.unwrap(),
            "PRIVATE_GENERATION_NEVER_LOG",
        );
        for debug in [
            format!("{claim:?}"),
            format!("{proof:?}"),
            format!("{retired:?}"),
            format!("{cleaned_retired:?}"),
        ] {
            for private in [
                PRIVATE_GOAL,
                PRIVATE_RESULT,
                PRIVATE_COMMAND,
                PRIVATE_ARGV,
                PRIVATE_PARAM,
                PRIVATE_SOCKET,
                "PRIVATE_GENERATION_NEVER_LOG",
            ] {
                assert!(
                    !debug.contains(private),
                    "debug leaked private fixture bytes"
                );
            }
        }

        let (_corrupt_temp, corrupt_paths) = test_paths();
        seed(
            &corrupt_paths,
            "corrupt-privacy",
            AgentTaskStartBindingState::Unbound,
            None,
            false,
        );
        {
            let arc = crate::db::conn_for(corrupt_paths.base()).unwrap();
            let connection = arc.lock().unwrap();
            connection
                .execute_batch(
                    "DROP TRIGGER trg_pending_agent_task_starts_immutable_core; \
                     PRAGMA ignore_check_constraints = ON; \
                     UPDATE pending_agent_task_starts \
                     SET operation_token = 'PRIVATE_ARGV_NEVER_LOG';",
                )
                .unwrap();
        }
        let error = AgentTaskStartJournalService::new(&corrupt_paths)
            .claim_next()
            .unwrap_err();
        let debug = format!("{error:?}");
        assert!(!debug.contains(PRIVATE_ARGV));
        assert!(debug.contains("operation token"));
    }
}
