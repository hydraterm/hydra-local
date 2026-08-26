//! Durable, generation-bound PTY release journal.
//!
//! A durable ownership deletion and its daemon cleanup cannot share one transaction.  The shell
//! therefore records an exact PTY lifetime in SQLite in the *same* transaction as the destructive
//! graph change, then drains that intent forward with generation-conditional daemon mutations.
//! Crash recovery can reclaim an expired lease, but only the transaction initiator's still-current
//! lease may authorize the narrow zero-publication window compensation path.

// Release failures return their exact generation-bound receipt for deterministic forward recovery.
#![allow(clippy::result_large_err)]

use std::collections::BTreeMap;

use rusqlite::{OptionalExtension as _, TransactionBehavior};

use crate::paths::AppPaths;
use crate::store::StoreError;
use crate::{DaemonClient, DaemonClientError, KillSessionPublicationError};

/// Maximum exact PTY lifetimes one destructive transaction may journal.
pub const MAX_RELEASE_TARGETS_PER_OPERATION: usize = 4_096;
/// Maximum pending PTY lifetimes across the local database.
pub const MAX_PENDING_RELEASE_TARGETS: usize = 16_384;
/// A lease covers one bounded daemon CAS plus database margin.  The daemon client gives one
/// generation-conditional Kill a substantially smaller absolute deadline.
pub const SESSION_RELEASE_LEASE_MS: u64 = 120_000;

// A claimant renews before each target. Keep enough durable-update margin beyond the daemon's
// absolute one-target deadline; changing either bound incompatibly must fail at compile time.
const _: () =
    assert!(SESSION_RELEASE_LEASE_MS >= crate::daemon_client::GENERATION_KILL_DEADLINE_MS * 2);

#[cfg(test)]
static CONSUME_FAILURE_SESSION: std::sync::OnceLock<std::sync::Mutex<Option<String>>> =
    std::sync::OnceLock::new();
#[cfg(test)]
static CONSUME_FAILURE_SERIAL: std::sync::OnceLock<std::sync::Mutex<()>> =
    std::sync::OnceLock::new();

#[cfg(test)]
fn lock_consume_failure() -> std::sync::MutexGuard<'static, ()> {
    CONSUME_FAILURE_SERIAL
        .get_or_init(|| std::sync::Mutex::new(()))
        .lock()
        .unwrap()
}

#[cfg(test)]
fn inject_consume_failure(session_id: &str) {
    *CONSUME_FAILURE_SESSION
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap() = Some(session_id.to_string());
}

#[cfg(test)]
fn take_consume_failure(session_id: &str) -> bool {
    let mut slot = CONSUME_FAILURE_SESSION
        .get_or_init(|| std::sync::Mutex::new(None))
        .lock()
        .unwrap();
    if slot.as_deref() == Some(session_id) {
        slot.take();
        true
    } else {
        false
    }
}

/// How the transaction-local Session row participates in the later global-owner fence.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum SessionRowPolicy {
    /// The destructive transaction retained the Session row.  Its exact generation is proof of
    /// the candidate lifetime, not a live-owner veto.
    MatchingRowIsProof,
    /// The destructive transaction removed (or never had) the Session row.  Any later row is a
    /// new/ambiguous durable owner and suppresses the old release.
    RowMustBeAbsent,
}

impl SessionRowPolicy {
    const MATCHING_ROW_IS_PROOF: &'static str = "matching_row_is_proof";
    const ROW_MUST_BE_ABSENT: &'static str = "row_must_be_absent";

    fn as_sql(self) -> &'static str {
        match self {
            Self::MatchingRowIsProof => Self::MATCHING_ROW_IS_PROOF,
            Self::RowMustBeAbsent => Self::ROW_MUST_BE_ABSENT,
        }
    }

    fn from_sql(value: &str) -> Result<Self, SessionReleaseError> {
        match value {
            Self::MATCHING_ROW_IS_PROOF => Ok(Self::MatchingRowIsProof),
            Self::ROW_MUST_BE_ABSENT => Ok(Self::RowMustBeAbsent),
            other => Err(SessionReleaseError::JournalCorrupt {
                detail: format!("unknown session release row expectation {other:?}"),
            }),
        }
    }
}

/// One exact daemon lifetime.  `expected_generation` is deliberately non-optional: an id alone
/// never grants mutation authority.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct SessionReleaseTarget {
    session_id: String,
    expected_generation: String,
    row_policy: SessionRowPolicy,
}

impl SessionReleaseTarget {
    pub(crate) fn new(
        session_id: impl Into<String>,
        expected_generation: impl Into<String>,
        row_policy: SessionRowPolicy,
    ) -> Result<Self, SessionReleaseError> {
        let target = Self {
            session_id: session_id.into(),
            expected_generation: expected_generation.into(),
            row_policy,
        };
        validate_target(&target)?;
        Ok(target)
    }

    pub(crate) fn new_recovered(
        session_id: impl Into<String>,
        expected_generation: impl Into<String>,
        row_policy: SessionRowPolicy,
    ) -> Result<Self, SessionReleaseError> {
        Self::new(session_id, expected_generation, row_policy)
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn expected_generation(&self) -> &str {
        &self.expected_generation
    }

    pub fn row_policy(&self) -> SessionRowPolicy {
        self.row_policy
    }
}

/// A generation resolved from one authoritative daemon snapshot before a destructive transaction.
/// `ConfirmedAbsent` needs no journal row; `Generation` is revalidated against any transaction-
/// local Session row before insertion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PreResolvedSessionState {
    Generation(String),
    ConfirmedAbsent,
}

pub type PreResolvedSessionGenerations = BTreeMap<String, PreResolvedSessionState>;

/// Exact target presented to the daemon CAS callback after the central ownership fence admits it.
/// Fields stay accessor-only so a callback cannot weaken or rewrite the journal proof.
pub struct ProvenSessionReleaseTarget {
    session_id: String,
    expected_generation: String,
}

impl ProvenSessionReleaseTarget {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn expected_generation(&self) -> &str {
        &self.expected_generation
    }
}

impl std::fmt::Debug for ProvenSessionReleaseTarget {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ProvenSessionReleaseTarget")
            .finish_non_exhaustive()
    }
}

/// Publication classification returned by one bounded generation-conditional daemon CAS.
pub enum CasPublication<E> {
    Confirmed,
    NotPublished(E),
    PossiblyPublished(E),
}

/// Opaque initial ownership of a newly journaled operation.  It is intentionally non-`Clone`.
pub struct PendingReleaseReceipt {
    operation_id: String,
    lease_token: String,
    lease_until_ms: u64,
    target_count: usize,
}

impl std::fmt::Debug for PendingReleaseReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PendingReleaseReceipt")
            .field("target_count", &self.target_count)
            .finish_non_exhaustive()
    }
}

/// Opaque forward-only ownership of a crash-recovered operation.  It cannot authorize durable
/// compensation, even if its first daemon attempt is known not to have published.
pub struct ForwardReleaseClaim {
    operation_id: String,
    lease_token: String,
    lease_until_ms: u64,
    target_count: usize,
}

impl std::fmt::Debug for ForwardReleaseClaim {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ForwardReleaseClaim")
            .field("target_count", &self.target_count)
            .finish_non_exhaustive()
    }
}

/// The only capability that may accompany a window restore.  It exists solely when an initiating
/// operation published zero daemon mutations and its original lease is still current.
pub struct UnpublishedCompensationReceipt {
    operation_id: String,
    lease_token: String,
    lease_until_ms: u64,
}

impl std::fmt::Debug for UnpublishedCompensationReceipt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("UnpublishedCompensationReceipt")
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
pub(crate) struct ReleaseOperationBinding {
    operation_id: String,
    lease_token: String,
}

impl PendingReleaseReceipt {
    pub(crate) fn binding(&self) -> ReleaseOperationBinding {
        ReleaseOperationBinding {
            operation_id: self.operation_id.clone(),
            lease_token: self.lease_token.clone(),
        }
    }
}

impl UnpublishedCompensationReceipt {
    pub(crate) fn matches(&self, binding: &ReleaseOperationBinding) -> bool {
        self.operation_id == binding.operation_id && self.lease_token == binding.lease_token
    }
}

/// Either the daemon callback's own failure or a fail-closed journal/ownership failure.
#[derive(Debug)]
pub enum ReleaseFailure<E> {
    Cas(E),
    Journal(SessionReleaseError),
}

/// Aggregate result for one operation.  Only `UnpublishedFailure` carries compensation authority;
/// `ForwardOnly` means a daemon mutation was confirmed/ambiguous or the initial lease was lost.
#[derive(Debug)]
pub enum ReleaseOperationOutcome<E> {
    Complete {
        confirmed: usize,
        retained: usize,
    },
    UnpublishedFailure {
        compensation: UnpublishedCompensationReceipt,
        retained: usize,
        pending: usize,
        error: ReleaseFailure<E>,
    },
    ForwardOnly {
        confirmed: usize,
        retained: usize,
        possibly_published: usize,
        pending: usize,
        error: Option<ReleaseFailure<E>>,
    },
}

/// One exact daemon lifetime that the shared adapter proved gone or superseded. Fields are
/// accessor-only so cache owners can evict precisely `(id, generation)` after the database fence
/// returns without gaining authority to manufacture release dispositions.
pub struct ConfirmedSessionRelease {
    session_id: String,
    expected_generation: String,
}

impl ConfirmedSessionRelease {
    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn expected_generation(&self) -> &str {
        &self.expected_generation
    }
}

impl std::fmt::Debug for ConfirmedSessionRelease {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfirmedSessionRelease")
            .finish_non_exhaustive()
    }
}

/// Result of the production daemon adapter. Confirmed exact lifetimes are reported only after the
/// ownership-fenced attempt has returned; no cache/store observer runs inside the SQLite fence.
pub struct DaemonReleaseAttempt {
    outcome: ReleaseOperationOutcome<DaemonClientError>,
    confirmed_lifetimes: Vec<ConfirmedSessionRelease>,
}

impl DaemonReleaseAttempt {
    pub fn outcome(&self) -> &ReleaseOperationOutcome<DaemonClientError> {
        &self.outcome
    }

    pub fn confirmed_lifetimes(&self) -> &[ConfirmedSessionRelease] {
        &self.confirmed_lifetimes
    }

    pub fn into_parts(
        self,
    ) -> (
        ReleaseOperationOutcome<DaemonClientError>,
        Vec<ConfirmedSessionRelease>,
    ) {
        (self.outcome, self.confirmed_lifetimes)
    }
}

impl std::fmt::Debug for DaemonReleaseAttempt {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut debug = formatter.debug_struct("DaemonReleaseAttempt");
        match &self.outcome {
            ReleaseOperationOutcome::Complete {
                confirmed,
                retained,
            } => debug
                .field("outcome", &"complete")
                .field("confirmed", confirmed)
                .field("retained", retained),
            ReleaseOperationOutcome::UnpublishedFailure {
                retained, pending, ..
            } => debug
                .field("outcome", &"unpublished_failure")
                .field("retained", retained)
                .field("pending", pending),
            ReleaseOperationOutcome::ForwardOnly {
                confirmed,
                retained,
                possibly_published,
                pending,
                ..
            } => debug
                .field("outcome", &"forward_only")
                .field("confirmed", confirmed)
                .field("retained", retained)
                .field("possibly_published", possibly_published)
                .field("pending", pending),
        };
        debug
            .field("confirmed_count", &self.confirmed_lifetimes.len())
            .finish_non_exhaustive()
    }
}

/// Journal and ownership-fence failures.  Errors never include operation ids, lease tokens, or
/// terminal content.
#[derive(Debug)]
pub enum SessionReleaseError {
    Store(StoreError),
    InvalidTarget { detail: String },
    CapacityExceeded { scope: &'static str, limit: usize },
    ClockOverflow,
    ClaimUnavailable,
    ClaimLost,
    LeaseExpired,
    JournalCorrupt { detail: String },
    OwnershipUncertain { detail: String },
}

impl std::fmt::Display for SessionReleaseError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Store(error) => write!(formatter, "session release store error: {error}"),
            Self::InvalidTarget { detail } => {
                write!(formatter, "invalid session release target: {detail}")
            }
            Self::CapacityExceeded { scope, limit } => write!(
                formatter,
                "session release journal {scope} capacity {limit} is exhausted"
            ),
            Self::ClockOverflow => write!(formatter, "session release lease clock overflow"),
            Self::ClaimUnavailable => {
                write!(formatter, "session release operation is not claimable")
            }
            Self::ClaimLost => write!(
                formatter,
                "session release lease no longer belongs to this caller"
            ),
            Self::LeaseExpired => write!(formatter, "session release lease expired"),
            Self::JournalCorrupt { detail } => {
                write!(formatter, "session release journal is malformed: {detail}")
            }
            Self::OwnershipUncertain { detail } => {
                write!(
                    formatter,
                    "session release ownership is uncertain: {detail}"
                )
            }
        }
    }
}

impl std::error::Error for SessionReleaseError {}

fn db_error(error: impl std::fmt::Display) -> SessionReleaseError {
    SessionReleaseError::Store(StoreError::Db(error.to_string()))
}

fn checked_ms(value: u64) -> Result<i64, SessionReleaseError> {
    i64::try_from(value).map_err(|_| SessionReleaseError::ClockOverflow)
}

fn lease_until(now_ms: u64) -> Result<u64, SessionReleaseError> {
    now_ms
        .checked_add(SESSION_RELEASE_LEASE_MS)
        .ok_or(SessionReleaseError::ClockOverflow)
}

fn clock_ms() -> Result<u64, SessionReleaseError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_millis())
        .map_err(|_| SessionReleaseError::ClockOverflow)
        .and_then(|millis| u64::try_from(millis).map_err(|_| SessionReleaseError::ClockOverflow))
}

fn canonical_uuid_v4() -> String {
    uuid::Uuid::new_v4().hyphenated().to_string()
}

fn validate_uuid(value: &str, label: &'static str) -> Result<(), SessionReleaseError> {
    let parsed = uuid::Uuid::parse_str(value).map_err(|_| SessionReleaseError::JournalCorrupt {
        detail: format!("{label} is not a UUID"),
    })?;
    if parsed.get_version_num() != 4 || parsed.hyphenated().to_string() != value {
        return Err(SessionReleaseError::JournalCorrupt {
            detail: format!("{label} is not a canonical UUIDv4"),
        });
    }
    Ok(())
}

fn validate_generation(generation: &str) -> Result<(), SessionReleaseError> {
    if generation.is_empty() || generation.len() > 128 {
        return Err(SessionReleaseError::InvalidTarget {
            detail: "expected generation length must be 1..=128 bytes".into(),
        });
    }
    Ok(())
}

fn validate_target(target: &SessionReleaseTarget) -> Result<(), SessionReleaseError> {
    crate::ids::validate_id(&target.session_id).map_err(|error| {
        SessionReleaseError::InvalidTarget {
            detail: format!("invalid session id: {error}"),
        }
    })?;
    validate_generation(&target.expected_generation)
}

fn normalize_targets(
    targets: &[SessionReleaseTarget],
) -> Result<Vec<SessionReleaseTarget>, SessionReleaseError> {
    if targets.len() > MAX_RELEASE_TARGETS_PER_OPERATION {
        return Err(SessionReleaseError::CapacityExceeded {
            scope: "per-operation",
            limit: MAX_RELEASE_TARGETS_PER_OPERATION,
        });
    }
    let mut unique = BTreeMap::<String, SessionReleaseTarget>::new();
    for target in targets {
        validate_target(target)?;
        match unique.get(&target.session_id) {
            Some(existing) if existing != target => {
                return Err(SessionReleaseError::InvalidTarget {
                    detail: format!(
                        "session {:?} has conflicting release lifetimes",
                        target.session_id
                    ),
                })
            }
            Some(_) => {}
            None => {
                unique.insert(target.session_id.clone(), target.clone());
            }
        }
    }
    Ok(unique.into_values().collect())
}

/// Insert one already-exact target cohort into the caller's destructive SQLite transaction.  The
/// operation is initially leased so no background drainer can steal the compensation decision.
pub(crate) fn insert_pending_releases(
    tx: &rusqlite::Transaction<'_>,
    targets: &[SessionReleaseTarget],
    created_at_ms: u64,
) -> Result<Option<PendingReleaseReceipt>, SessionReleaseError> {
    let targets = normalize_targets(targets)?;
    if targets.is_empty() {
        return Ok(None);
    }

    let global_count: i64 = tx
        .query_row("SELECT COUNT(*) FROM pending_session_releases", [], |row| {
            row.get(0)
        })
        .map_err(db_error)?;
    let target_count =
        i64::try_from(targets.len()).map_err(|_| SessionReleaseError::CapacityExceeded {
            scope: "per-operation",
            limit: MAX_RELEASE_TARGETS_PER_OPERATION,
        })?;
    if global_count < 0
        || global_count
            .checked_add(target_count)
            .is_none_or(|count| count > MAX_PENDING_RELEASE_TARGETS as i64)
    {
        return Err(SessionReleaseError::CapacityExceeded {
            scope: "global",
            limit: MAX_PENDING_RELEASE_TARGETS,
        });
    }

    let operation_id = canonical_uuid_v4();
    let lease_token = canonical_uuid_v4();
    let lease_until_ms = lease_until(clock_ms()?)?;
    let created_at_i64 = checked_ms(created_at_ms)?;
    let lease_until_i64 = checked_ms(lease_until_ms)?;
    tx.execute(
        "INSERT INTO session_release_operations \
         (operation_id, created_at_ms, lease_token, lease_until_ms) VALUES (?1, ?2, ?3, ?4)",
        rusqlite::params![operation_id, created_at_i64, lease_token, lease_until_i64],
    )
    .map_err(db_error)?;
    for target in &targets {
        tx.execute(
            "INSERT INTO pending_session_releases \
             (operation_id, session_id, expected_generation, row_expectation, created_at_ms) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            rusqlite::params![
                operation_id,
                target.session_id,
                target.expected_generation,
                target.row_policy.as_sql(),
                created_at_i64,
            ],
        )
        .map_err(db_error)?;
    }
    Ok(Some(PendingReleaseReceipt {
        operation_id,
        lease_token,
        lease_until_ms,
        target_count: targets.len(),
    }))
}

/// Durable journal access and central ownership fencing for one app-support base.
pub struct SessionReleaseService<'a> {
    paths: &'a AppPaths,
}

struct DaemonReleaseAdapter<'a> {
    client: &'a mut DaemonClient,
    confirmed_lifetimes: Vec<ConfirmedSessionRelease>,
}

impl DaemonReleaseAdapter<'_> {
    fn preflight(&mut self, _targets: &[SessionReleaseTarget]) -> Result<(), DaemonClientError> {
        // Target bytes were already normalized while reading the journal. Daemon work stays lazy:
        // every retained target can be consumed without touching the socket, while the first
        // CAS-eligible target performs its strict bounded snapshot inside the ownership fence.
        Ok(())
    }

    fn cas(&mut self, target: &ProvenSessionReleaseTarget) -> CasPublication<DaemonClientError> {
        match self.client.release_session_lifetime_with_publication(
            maestro_protocol::SessionId(target.session_id().to_string()),
            target.expected_generation(),
        ) {
            Ok(()) => {
                self.confirmed_lifetimes.push(ConfirmedSessionRelease {
                    session_id: target.session_id().to_string(),
                    expected_generation: target.expected_generation().to_string(),
                });
                CasPublication::Confirmed
            }
            Err(KillSessionPublicationError::NotPublished { source }) => {
                CasPublication::NotPublished(source)
            }
            Err(KillSessionPublicationError::PossiblyPublished { source }) => {
                CasPublication::PossiblyPublished(source)
            }
        }
    }
}

/// Resolve an opaque destructive plan's unresolved ids from one bounded, strict v3 daemon
/// snapshot. An absent id is explicit proof that no journal target is needed; a live id carries its
/// exact generation. Legacy/partial metadata is an error and grants no mutation authority.
pub fn pre_resolve_session_generations<'b>(
    client: &mut DaemonClient,
    session_ids: impl IntoIterator<Item = &'b str>,
) -> Result<PreResolvedSessionGenerations, DaemonClientError> {
    let session_ids = session_ids.into_iter().collect::<Vec<_>>();
    for session_id in &session_ids {
        crate::ids::validate_id(session_id).map_err(|error| DaemonClientError::Protocol {
            detail: format!("invalid session release pre-resolution id: {error}"),
        })?;
    }
    if session_ids.is_empty() {
        return Ok(PreResolvedSessionGenerations::new());
    }
    let snapshot = client.generation_mutation_snapshot()?;
    Ok(session_ids
        .into_iter()
        .map(|session_id| {
            let state = snapshot
                .generation_for(session_id)
                .map_or(PreResolvedSessionState::ConfirmedAbsent, |generation| {
                    PreResolvedSessionState::Generation(generation.to_string())
                });
            (session_id.to_string(), state)
        })
        .collect())
}

impl<'a> SessionReleaseService<'a> {
    pub fn new(paths: &'a AppPaths) -> Self {
        Self { paths }
    }

    /// Journal an exact operation without another graph mutation (for example stable-orphan
    /// cleanup).  Empty cohorts deliberately create no operation row.
    pub fn enqueue_recovered(
        &self,
        targets: &[SessionReleaseTarget],
        created_at_ms: u64,
    ) -> Result<Option<PendingReleaseReceipt>, SessionReleaseError> {
        let targets = normalize_targets(targets)?;
        let arc = crate::db::conn_for(self.paths.base()).map_err(db_error)?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        // Reconciliation can observe the same stable orphan on every tick while the daemon is
        // unavailable. Coalesce an already-pending exact daemon lifetime regardless of row policy:
        // a second non-destructive operation for the same `(id, generation)` could otherwise
        // publish and disappear while a window compensation capability for that lifetime remains.
        // Destructive graph transactions deliberately bypass this recovered-only seam because
        // their private receipt/compensation authority is operation-specific.
        let mut novel = Vec::new();
        for target in targets {
            let exists: bool = tx
                .query_row(
                    "SELECT EXISTS(SELECT 1 FROM pending_session_releases \
                     WHERE session_id = ?1 AND expected_generation = ?2)",
                    rusqlite::params![&target.session_id, &target.expected_generation],
                    |row| row.get(0),
                )
                .map_err(db_error)?;
            if !exists {
                novel.push(target);
            }
        }
        let receipt = insert_pending_releases(&tx, &novel, created_at_ms)?;
        tx.commit().map_err(db_error)?;
        Ok(receipt)
    }

    /// Claim the oldest unleased/expired operation.  Reclaimed work is permanently forward-only.
    pub fn claim_next(&self) -> Result<Option<ForwardReleaseClaim>, SessionReleaseError> {
        let arc = crate::db::conn_for(self.paths.base()).map_err(db_error)?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let now_ms = clock_ms()?;
        let now = checked_ms(now_ms)?;
        let new_until_ms = lease_until(now_ms)?;
        let new_until = checked_ms(new_until_ms)?;
        let candidate: Option<(String, i64)> = tx
            .query_row(
                "SELECT operations.operation_id, COUNT(pending.session_id) \
                 FROM session_release_operations operations \
                 JOIN pending_session_releases pending \
                   ON pending.operation_id = operations.operation_id \
                 WHERE operations.lease_token IS NULL OR operations.lease_until_ms <= ?1 \
                 GROUP BY operations.operation_id, operations.created_at_ms \
                 ORDER BY operations.created_at_ms, operations.operation_id LIMIT 1",
                [now],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(db_error)?;
        let Some((operation_id, target_count)) = candidate else {
            tx.commit().map_err(db_error)?;
            return Ok(None);
        };
        validate_uuid(&operation_id, "operation id")?;
        let lease_token = canonical_uuid_v4();
        let latest_schedule: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(created_at_ms), ?1) FROM session_release_operations",
                [now],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let rotated_at = latest_schedule
            .max(now)
            .checked_add(1)
            .ok_or(SessionReleaseError::ClockOverflow)?;
        let updated = tx
            .execute(
                "UPDATE session_release_operations \
                 SET lease_token = ?2, lease_until_ms = ?3, created_at_ms = ?5 \
                 WHERE operation_id = ?1 \
                   AND (lease_token IS NULL OR lease_until_ms <= ?4)",
                rusqlite::params![operation_id, lease_token, new_until, now, rotated_at],
            )
            .map_err(db_error)?;
        if updated != 1 {
            return Err(SessionReleaseError::ClaimUnavailable);
        }
        tx.commit().map_err(db_error)?;
        Ok(Some(ForwardReleaseClaim {
            operation_id,
            lease_token,
            lease_until_ms: new_until_ms,
            target_count: usize::try_from(target_count).map_err(|_| {
                SessionReleaseError::JournalCorrupt {
                    detail: "negative or oversized target count".into(),
                }
            })?,
        }))
    }

    /// List the exact targets currently owned by `claim`.
    pub fn list_claimed(
        &self,
        claim: &ForwardReleaseClaim,
    ) -> Result<Vec<SessionReleaseTarget>, SessionReleaseError> {
        self.list_for_lease(&claim.operation_id, &claim.lease_token)
    }

    /// Renew a forward claim before beginning its next single-target ownership/CAS fence.
    pub fn renew_claim(&self, claim: &mut ForwardReleaseClaim) -> Result<(), SessionReleaseError> {
        claim.lease_until_ms = self.renew_lease(&claim.operation_id, &claim.lease_token)?;
        Ok(())
    }

    /// Relinquish a forward claim for later retry without consuming any target.
    pub fn retry_claim(&self, claim: ForwardReleaseClaim) -> Result<(), SessionReleaseError> {
        self.release_lease(&claim.operation_id, &claim.lease_token)
    }

    /// Permanently surrender zero-publication compensation authority and make the untouched
    /// operation immediately claimable for forward retry. Project/tab callers whose destructive
    /// graph commit is never restored must consume the capability here rather than leave work
    /// parked behind the initiator lease.
    pub fn release_unpublished_for_retry(
        &self,
        compensation: UnpublishedCompensationReceipt,
    ) -> Result<(), SessionReleaseError> {
        self.release_lease(&compensation.operation_id, &compensation.lease_token)
    }

    /// Shared production adapter for an initiator-owned journal operation. Journal validation is
    /// local; daemon probing is lazy and occurs only for a CAS-eligible target under its ownership
    /// fence. Each such callback publishes at most one bounded generation-bound release.
    pub fn attempt_owned_with_daemon(
        &self,
        receipt: PendingReleaseReceipt,
        client: &mut DaemonClient,
    ) -> DaemonReleaseAttempt {
        let adapter = std::cell::RefCell::new(DaemonReleaseAdapter {
            client,
            confirmed_lifetimes: Vec::new(),
        });
        let outcome = self.attempt_owned(
            receipt,
            |targets| adapter.borrow_mut().preflight(targets),
            |target| adapter.borrow_mut().cas(target),
        );
        let confirmed_lifetimes = std::mem::take(&mut adapter.borrow_mut().confirmed_lifetimes);
        DaemonReleaseAttempt {
            outcome,
            confirmed_lifetimes,
        }
    }

    /// Drain locally retained targets even when no reviewed daemon connection could be opened.
    /// The first CAS-eligible target returns the caller's pre-publication connection error; an
    /// all-retained operation completes without consulting or fabricating daemon authority.
    pub fn attempt_owned_with_daemon_unavailable(
        &self,
        receipt: PendingReleaseReceipt,
        error: DaemonClientError,
    ) -> DaemonReleaseAttempt {
        let error = std::cell::RefCell::new(Some(error));
        let outcome = self.attempt_owned(
            receipt,
            |_| Ok(()),
            |_| {
                CasPublication::NotPublished(error.borrow_mut().take().unwrap_or_else(|| {
                    DaemonClientError::Protocol {
                        detail: "offline release adapter was invoked more than once".into(),
                    }
                }))
            },
        );
        DaemonReleaseAttempt {
            outcome,
            confirmed_lifetimes: Vec::new(),
        }
    }

    /// Shared production adapter for crash-recovered forward-only work.
    pub fn attempt_claimed_with_daemon(
        &self,
        claim: ForwardReleaseClaim,
        client: &mut DaemonClient,
    ) -> DaemonReleaseAttempt {
        let adapter = std::cell::RefCell::new(DaemonReleaseAdapter {
            client,
            confirmed_lifetimes: Vec::new(),
        });
        let outcome = self.attempt_claimed(
            claim,
            |targets| adapter.borrow_mut().preflight(targets),
            |target| adapter.borrow_mut().cas(target),
        );
        let confirmed_lifetimes = std::mem::take(&mut adapter.borrow_mut().confirmed_lifetimes);
        DaemonReleaseAttempt {
            outcome,
            confirmed_lifetimes,
        }
    }

    /// Forward-only counterpart to [`Self::attempt_owned_with_daemon_unavailable`].
    pub fn attempt_claimed_with_daemon_unavailable(
        &self,
        claim: ForwardReleaseClaim,
        error: DaemonClientError,
    ) -> DaemonReleaseAttempt {
        let error = std::cell::RefCell::new(Some(error));
        let outcome = self.attempt_claimed(
            claim,
            |_| Ok(()),
            |_| {
                CasPublication::NotPublished(error.borrow_mut().take().unwrap_or_else(|| {
                    DaemonClientError::Protocol {
                        detail: "offline release adapter was invoked more than once".into(),
                    }
                }))
            },
        );
        DaemonReleaseAttempt {
            outcome,
            confirmed_lifetimes: Vec::new(),
        }
    }

    /// Drain an operation returned by the destructive transaction.  This is the sole path that can
    /// return zero-publication compensation authority.
    pub fn attempt_owned<E>(
        &self,
        mut receipt: PendingReleaseReceipt,
        preflight: impl FnOnce(&[SessionReleaseTarget]) -> Result<(), E>,
        mut cas: impl FnMut(&ProvenSessionReleaseTarget) -> CasPublication<E>,
    ) -> ReleaseOperationOutcome<E> {
        let mut pending = receipt.target_count;
        let mut confirmed = 0;
        let mut retained = 0;
        let mut possibly_published = 0;

        match self.renew_lease_now(&receipt.operation_id, &receipt.lease_token) {
            Ok(until) => receipt.lease_until_ms = until,
            Err(error) => {
                let _ = self.release_lease_now(&receipt.operation_id, &receipt.lease_token);
                return ReleaseOperationOutcome::ForwardOnly {
                    confirmed,
                    retained,
                    possibly_published,
                    pending,
                    error: Some(ReleaseFailure::Journal(error)),
                };
            }
        }
        let targets = match self.list_for_lease_now(&receipt.operation_id, &receipt.lease_token) {
            Ok(targets) => targets,
            Err(error) => return self.unpublished_failure(receipt, retained, pending, error),
        };
        pending = targets.len();
        if let Err(error) = preflight(&targets) {
            match self.renew_lease_now(&receipt.operation_id, &receipt.lease_token) {
                Ok(until) => receipt.lease_until_ms = until,
                Err(renew_error) => {
                    let _ = self.release_lease_now(&receipt.operation_id, &receipt.lease_token);
                    return ReleaseOperationOutcome::ForwardOnly {
                        confirmed,
                        retained,
                        possibly_published,
                        pending,
                        error: Some(ReleaseFailure::Journal(renew_error)),
                    };
                }
            }
            return ReleaseOperationOutcome::UnpublishedFailure {
                compensation: UnpublishedCompensationReceipt {
                    operation_id: receipt.operation_id,
                    lease_token: receipt.lease_token,
                    lease_until_ms: receipt.lease_until_ms,
                },
                retained,
                pending,
                error: ReleaseFailure::Cas(error),
            };
        }

        for target in targets {
            match self.renew_lease_now(&receipt.operation_id, &receipt.lease_token) {
                Ok(until) => receipt.lease_until_ms = until,
                Err(error) => {
                    let _ = self.release_lease_now(&receipt.operation_id, &receipt.lease_token);
                    return ReleaseOperationOutcome::ForwardOnly {
                        confirmed,
                        retained,
                        possibly_published,
                        pending,
                        error: Some(ReleaseFailure::Journal(error)),
                    };
                }
            }

            let decision = match self.fence_one(
                &receipt.operation_id,
                &receipt.lease_token,
                &target,
                &mut cas,
            ) {
                Ok(decision) => decision,
                Err(error) if confirmed == 0 && possibly_published == 0 && retained == 0 => {
                    return self.unpublished_failure(receipt, retained, pending, error)
                }
                Err(error) => {
                    let _ = self.release_lease_now(&receipt.operation_id, &receipt.lease_token);
                    return ReleaseOperationOutcome::ForwardOnly {
                        confirmed,
                        retained,
                        possibly_published,
                        pending,
                        error: Some(ReleaseFailure::Journal(error)),
                    };
                }
            };

            match decision {
                FencedDecision::Retained => {
                    // A completed ownership verdict is processed operation state. Even if the
                    // journal delete below fails, compensation may no longer treat the operation
                    // as wholly untouched.
                    retained += 1;
                    if let Err(error) = self.consume_target_now(
                        &receipt.operation_id,
                        &receipt.lease_token,
                        &target,
                    ) {
                        let _ = self.release_lease_now(&receipt.operation_id, &receipt.lease_token);
                        return ReleaseOperationOutcome::ForwardOnly {
                            confirmed,
                            retained,
                            possibly_published,
                            pending,
                            error: Some(ReleaseFailure::Journal(error)),
                        };
                    }
                    pending -= 1;
                }
                FencedDecision::Cas(CasPublication::Confirmed) => {
                    confirmed += 1;
                    if let Err(error) = self.consume_target_now(
                        &receipt.operation_id,
                        &receipt.lease_token,
                        &target,
                    ) {
                        let _ = self.release_lease_now(&receipt.operation_id, &receipt.lease_token);
                        return ReleaseOperationOutcome::ForwardOnly {
                            confirmed,
                            retained,
                            possibly_published,
                            pending,
                            error: Some(ReleaseFailure::Journal(error)),
                        };
                    }
                    pending -= 1;
                }
                FencedDecision::Cas(CasPublication::NotPublished(error)) => {
                    if confirmed == 0 && possibly_published == 0 && retained == 0 {
                        match self.renew_lease_now(&receipt.operation_id, &receipt.lease_token) {
                            Ok(until) => receipt.lease_until_ms = until,
                            Err(renew_error) => {
                                let _ = self
                                    .release_lease_now(&receipt.operation_id, &receipt.lease_token);
                                return ReleaseOperationOutcome::ForwardOnly {
                                    confirmed,
                                    retained,
                                    possibly_published,
                                    pending,
                                    error: Some(ReleaseFailure::Journal(renew_error)),
                                };
                            }
                        }
                        return ReleaseOperationOutcome::UnpublishedFailure {
                            compensation: UnpublishedCompensationReceipt {
                                operation_id: receipt.operation_id,
                                lease_token: receipt.lease_token,
                                lease_until_ms: receipt.lease_until_ms,
                            },
                            retained,
                            pending,
                            error: ReleaseFailure::Cas(error),
                        };
                    }
                    let _ = self.release_lease_now(&receipt.operation_id, &receipt.lease_token);
                    return ReleaseOperationOutcome::ForwardOnly {
                        confirmed,
                        retained,
                        possibly_published,
                        pending,
                        error: Some(ReleaseFailure::Cas(error)),
                    };
                }
                FencedDecision::Cas(CasPublication::PossiblyPublished(error)) => {
                    possibly_published += 1;
                    let _ = self.release_lease_now(&receipt.operation_id, &receipt.lease_token);
                    return ReleaseOperationOutcome::ForwardOnly {
                        confirmed,
                        retained,
                        possibly_published,
                        pending,
                        error: Some(ReleaseFailure::Cas(error)),
                    };
                }
            }
        }

        ReleaseOperationOutcome::Complete {
            confirmed,
            retained,
        }
    }

    /// Drain a crash-recovered claim.  Every non-complete result is forward-only.
    pub fn attempt_claimed<E>(
        &self,
        mut claim: ForwardReleaseClaim,
        preflight: impl FnOnce(&[SessionReleaseTarget]) -> Result<(), E>,
        mut cas: impl FnMut(&ProvenSessionReleaseTarget) -> CasPublication<E>,
    ) -> ReleaseOperationOutcome<E> {
        let mut pending = claim.target_count;
        let mut confirmed = 0;
        let mut retained = 0;
        let mut possibly_published = 0;
        let targets = match self.list_for_lease_now(&claim.operation_id, &claim.lease_token) {
            Ok(targets) => targets,
            Err(error) => {
                let _ = self.release_lease_now(&claim.operation_id, &claim.lease_token);
                return ReleaseOperationOutcome::ForwardOnly {
                    confirmed,
                    retained,
                    possibly_published,
                    pending,
                    error: Some(ReleaseFailure::Journal(error)),
                };
            }
        };
        pending = targets.len();
        if let Err(error) = preflight(&targets) {
            let _ = self.release_lease_now(&claim.operation_id, &claim.lease_token);
            return ReleaseOperationOutcome::ForwardOnly {
                confirmed,
                retained,
                possibly_published,
                pending,
                error: Some(ReleaseFailure::Cas(error)),
            };
        }
        for target in targets {
            match self.renew_lease_now(&claim.operation_id, &claim.lease_token) {
                Ok(until) => claim.lease_until_ms = until,
                Err(error) => {
                    let _ = self.release_lease_now(&claim.operation_id, &claim.lease_token);
                    return ReleaseOperationOutcome::ForwardOnly {
                        confirmed,
                        retained,
                        possibly_published,
                        pending,
                        error: Some(ReleaseFailure::Journal(error)),
                    };
                }
            }
            let decision =
                match self.fence_one(&claim.operation_id, &claim.lease_token, &target, &mut cas) {
                    Ok(decision) => decision,
                    Err(error) => {
                        let _ = self.release_lease_now(&claim.operation_id, &claim.lease_token);
                        return ReleaseOperationOutcome::ForwardOnly {
                            confirmed,
                            retained,
                            possibly_published,
                            pending,
                            error: Some(ReleaseFailure::Journal(error)),
                        };
                    }
                };
            match decision {
                FencedDecision::Retained => {
                    if let Err(error) =
                        self.consume_target_now(&claim.operation_id, &claim.lease_token, &target)
                    {
                        let _ = self.release_lease_now(&claim.operation_id, &claim.lease_token);
                        return ReleaseOperationOutcome::ForwardOnly {
                            confirmed,
                            retained,
                            possibly_published,
                            pending,
                            error: Some(ReleaseFailure::Journal(error)),
                        };
                    }
                    retained += 1;
                    pending -= 1;
                }
                FencedDecision::Cas(CasPublication::Confirmed) => {
                    confirmed += 1;
                    if let Err(error) =
                        self.consume_target_now(&claim.operation_id, &claim.lease_token, &target)
                    {
                        let _ = self.release_lease_now(&claim.operation_id, &claim.lease_token);
                        return ReleaseOperationOutcome::ForwardOnly {
                            confirmed,
                            retained,
                            possibly_published,
                            pending,
                            error: Some(ReleaseFailure::Journal(error)),
                        };
                    }
                    pending -= 1;
                }
                FencedDecision::Cas(CasPublication::NotPublished(error)) => {
                    let _ = self.release_lease_now(&claim.operation_id, &claim.lease_token);
                    return ReleaseOperationOutcome::ForwardOnly {
                        confirmed,
                        retained,
                        possibly_published,
                        pending,
                        error: Some(ReleaseFailure::Cas(error)),
                    };
                }
                FencedDecision::Cas(CasPublication::PossiblyPublished(error)) => {
                    possibly_published += 1;
                    let _ = self.release_lease_now(&claim.operation_id, &claim.lease_token);
                    return ReleaseOperationOutcome::ForwardOnly {
                        confirmed,
                        retained,
                        possibly_published,
                        pending,
                        error: Some(ReleaseFailure::Cas(error)),
                    };
                }
            }
        }
        ReleaseOperationOutcome::Complete {
            confirmed,
            retained,
        }
    }

    fn unpublished_failure<E>(
        &self,
        mut receipt: PendingReleaseReceipt,
        retained: usize,
        pending: usize,
        error: SessionReleaseError,
    ) -> ReleaseOperationOutcome<E> {
        match self.renew_lease_now(&receipt.operation_id, &receipt.lease_token) {
            Ok(until) => receipt.lease_until_ms = until,
            Err(renew_error) => {
                let _ = self.release_lease_now(&receipt.operation_id, &receipt.lease_token);
                return ReleaseOperationOutcome::ForwardOnly {
                    confirmed: 0,
                    retained,
                    possibly_published: 0,
                    pending,
                    error: Some(ReleaseFailure::Journal(renew_error)),
                };
            }
        }
        ReleaseOperationOutcome::UnpublishedFailure {
            compensation: UnpublishedCompensationReceipt {
                operation_id: receipt.operation_id,
                lease_token: receipt.lease_token,
                lease_until_ms: receipt.lease_until_ms,
            },
            retained,
            pending,
            error: ReleaseFailure::Journal(error),
        }
    }

    fn list_for_lease_now(
        &self,
        operation_id: &str,
        lease_token: &str,
    ) -> Result<Vec<SessionReleaseTarget>, SessionReleaseError> {
        self.list_for_lease(operation_id, lease_token)
    }

    fn renew_lease_now(
        &self,
        operation_id: &str,
        lease_token: &str,
    ) -> Result<u64, SessionReleaseError> {
        self.renew_lease(operation_id, lease_token)
    }

    fn release_lease_now(
        &self,
        operation_id: &str,
        lease_token: &str,
    ) -> Result<(), SessionReleaseError> {
        self.release_lease(operation_id, lease_token)
    }

    fn consume_target_now(
        &self,
        operation_id: &str,
        lease_token: &str,
        target: &SessionReleaseTarget,
    ) -> Result<(), SessionReleaseError> {
        self.consume_target(operation_id, lease_token, target)
    }

    fn list_for_lease(
        &self,
        operation_id: &str,
        lease_token: &str,
    ) -> Result<Vec<SessionReleaseTarget>, SessionReleaseError> {
        validate_uuid(operation_id, "operation id")?;
        validate_uuid(lease_token, "lease token")?;
        let arc = crate::db::conn_for(self.paths.base()).map_err(db_error)?;
        let conn = arc.lock().unwrap();
        let now = checked_ms(clock_ms()?)?;
        let lease_until: Option<i64> = conn
            .query_row(
                "SELECT lease_until_ms FROM session_release_operations \
                 WHERE operation_id = ?1 AND lease_token = ?2",
                rusqlite::params![operation_id, lease_token],
                |row| row.get(0),
            )
            .optional()
            .map_err(db_error)?;
        let Some(lease_until) = lease_until else {
            return Err(SessionReleaseError::ClaimLost);
        };
        if lease_until <= now {
            return Err(SessionReleaseError::LeaseExpired);
        }
        let mut statement = conn
            .prepare(
                "SELECT session_id, expected_generation, row_expectation \
                 FROM pending_session_releases WHERE operation_id = ?1 ORDER BY session_id",
            )
            .map_err(db_error)?;
        let rows = statement
            .query_map([operation_id], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                ))
            })
            .map_err(db_error)?;
        let mut targets = Vec::new();
        for row in rows {
            let (session_id, expected_generation, row_policy) = row.map_err(db_error)?;
            let target = SessionReleaseTarget {
                session_id,
                expected_generation,
                row_policy: SessionRowPolicy::from_sql(&row_policy)?,
            };
            validate_target(&target).map_err(|error| SessionReleaseError::JournalCorrupt {
                detail: error.to_string(),
            })?;
            targets.push(target);
            if targets.len() > MAX_RELEASE_TARGETS_PER_OPERATION {
                return Err(SessionReleaseError::JournalCorrupt {
                    detail: "operation exceeds target cap".into(),
                });
            }
        }
        if targets.is_empty() {
            return Err(SessionReleaseError::JournalCorrupt {
                detail: "operation has no pending targets".into(),
            });
        }
        Ok(targets)
    }

    fn renew_lease(
        &self,
        operation_id: &str,
        lease_token: &str,
    ) -> Result<u64, SessionReleaseError> {
        let arc = crate::db::conn_for(self.paths.base()).map_err(db_error)?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let now_ms = clock_ms()?;
        let now = checked_ms(now_ms)?;
        let until_ms = lease_until(now_ms)?;
        let until = checked_ms(until_ms)?;
        let updated = tx
            .execute(
                "UPDATE session_release_operations SET lease_until_ms = ?3 \
                 WHERE operation_id = ?1 AND lease_token = ?2 AND lease_until_ms > ?4",
                rusqlite::params![operation_id, lease_token, until, now],
            )
            .map_err(db_error)?;
        if updated != 1 {
            let still_owned: Option<i64> = tx
                .query_row(
                    "SELECT lease_until_ms FROM session_release_operations \
                     WHERE operation_id = ?1 AND lease_token = ?2",
                    rusqlite::params![operation_id, lease_token],
                    |row| row.get(0),
                )
                .optional()
                .map_err(db_error)?;
            return Err(match still_owned {
                Some(value) if value <= now => SessionReleaseError::LeaseExpired,
                _ => SessionReleaseError::ClaimLost,
            });
        }
        tx.commit().map_err(db_error)?;
        Ok(until_ms)
    }

    fn release_lease(
        &self,
        operation_id: &str,
        lease_token: &str,
    ) -> Result<(), SessionReleaseError> {
        let arc = crate::db::conn_for(self.paths.base()).map_err(db_error)?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let now = checked_ms(clock_ms()?)?;
        let latest_schedule: i64 = tx
            .query_row(
                "SELECT COALESCE(MAX(created_at_ms), ?1) FROM session_release_operations",
                [now],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        let rotated_at = latest_schedule
            .max(now)
            .checked_add(1)
            .ok_or(SessionReleaseError::ClockOverflow)?;
        let updated = tx
            .execute(
                "UPDATE session_release_operations \
                 SET lease_token = NULL, lease_until_ms = NULL, created_at_ms = ?4 \
                 WHERE operation_id = ?1 AND lease_token = ?2 AND lease_until_ms > ?3",
                rusqlite::params![operation_id, lease_token, now, rotated_at],
            )
            .map_err(db_error)?;
        if updated != 1 {
            return Err(SessionReleaseError::ClaimLost);
        }
        tx.commit().map_err(db_error)
    }

    fn consume_target(
        &self,
        operation_id: &str,
        lease_token: &str,
        target: &SessionReleaseTarget,
    ) -> Result<(), SessionReleaseError> {
        let arc = crate::db::conn_for(self.paths.base()).map_err(db_error)?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let now = checked_ms(clock_ms()?)?;
        #[cfg(test)]
        if take_consume_failure(&target.session_id) {
            return Err(SessionReleaseError::Store(StoreError::Db(
                "injected session-release consume failure".into(),
            )));
        }
        let lease_current: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM session_release_operations \
                 WHERE operation_id = ?1 AND lease_token = ?2 AND lease_until_ms > ?3)",
                rusqlite::params![operation_id, lease_token, now],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if !lease_current {
            return Err(SessionReleaseError::ClaimLost);
        }
        let removed = tx
            .execute(
                "DELETE FROM pending_session_releases \
                 WHERE operation_id = ?1 AND session_id = ?2 \
                   AND expected_generation = ?3 AND row_expectation = ?4",
                rusqlite::params![
                    operation_id,
                    target.session_id,
                    target.expected_generation,
                    target.row_policy.as_sql(),
                ],
            )
            .map_err(db_error)?;
        if removed != 1 {
            return Err(SessionReleaseError::JournalCorrupt {
                detail: "claimed target changed or disappeared".into(),
            });
        }
        let remaining: bool = tx
            .query_row(
                "SELECT EXISTS(SELECT 1 FROM pending_session_releases WHERE operation_id = ?1)",
                [operation_id],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if !remaining {
            let deleted = tx
                .execute(
                    "DELETE FROM session_release_operations \
                     WHERE operation_id = ?1 AND lease_token = ?2",
                    rusqlite::params![operation_id, lease_token],
                )
                .map_err(db_error)?;
            if deleted != 1 {
                return Err(SessionReleaseError::ClaimLost);
            }
        }
        tx.commit().map_err(db_error)
    }

    fn fence_one<E>(
        &self,
        operation_id: &str,
        lease_token: &str,
        target: &SessionReleaseTarget,
        cas: &mut impl FnMut(&ProvenSessionReleaseTarget) -> CasPublication<E>,
    ) -> Result<FencedDecision<E>, SessionReleaseError> {
        let arc = crate::db::conn_for(self.paths.base()).map_err(db_error)?;
        let mut conn = arc.lock().unwrap();
        let tx = conn
            .transaction_with_behavior(TransactionBehavior::Immediate)
            .map_err(db_error)?;
        let now = checked_ms(clock_ms()?)?;
        // The lease and exact row are mutation authority, not merely scheduling metadata.  Check
        // both under the SAME writer fence that will remain held through the one daemon CAS.  An
        // expired/reclaimed/cancelled claimant can therefore never publish after a stale list.
        let exact_claim: bool = tx
            .query_row(
                "SELECT EXISTS(\
                   SELECT 1 FROM session_release_operations operations \
                   JOIN pending_session_releases pending \
                     ON pending.operation_id = operations.operation_id \
                   WHERE operations.operation_id = ?1 \
                     AND operations.lease_token = ?2 \
                     AND operations.lease_until_ms > ?3 \
                     AND pending.session_id = ?4 \
                     AND pending.expected_generation = ?5 \
                     AND pending.row_expectation = ?6\
                 )",
                rusqlite::params![
                    operation_id,
                    lease_token,
                    now,
                    target.session_id,
                    target.expected_generation,
                    target.row_policy.as_sql(),
                ],
                |row| row.get(0),
            )
            .map_err(db_error)?;
        if !exact_claim {
            return Err(SessionReleaseError::ClaimLost);
        }
        let ownership = crate::project::session_ownership_graph(&tx).map_err(|error| {
            SessionReleaseError::OwnershipUncertain {
                detail: error.to_string(),
            }
        })?;

        let has_task_owner = ownership.task_refs.iter().any(|(_, references)| {
            references
                .iter()
                .any(|session_id| session_id == &target.session_id)
        });
        let has_tab_owner = ownership
            .tab_refs
            .iter()
            .any(|(_, _, session_id)| session_id == &target.session_id);
        let has_worktree_owner = ownership
            .worktree_refs
            .iter()
            .any(|(session_id, _, _)| session_id == &target.session_id);
        if has_task_owner || has_tab_owner || has_worktree_owner {
            drop(tx);
            drop(conn);
            return Ok(FencedDecision::Retained);
        }

        let session_row = ownership
            .session_rows
            .iter()
            .find(|(session_id, _, _)| session_id == &target.session_id);
        let row_admits = match (target.row_policy, session_row) {
            (SessionRowPolicy::MatchingRowIsProof, None) => true,
            (SessionRowPolicy::MatchingRowIsProof, Some((_, _, Some(generation)))) => {
                generation == &target.expected_generation
            }
            (SessionRowPolicy::MatchingRowIsProof, Some((_, _, None))) => false,
            (SessionRowPolicy::RowMustBeAbsent, None) => true,
            (SessionRowPolicy::RowMustBeAbsent, Some(_)) => false,
        };
        if !row_admits {
            drop(tx);
            drop(conn);
            return Ok(FencedDecision::Retained);
        }

        let proven = ProvenSessionReleaseTarget {
            session_id: target.session_id.clone(),
            expected_generation: target.expected_generation.clone(),
        };
        let result = cas(&proven);
        // This transaction performed ownership reads only.  Drop it after the publication result;
        // never run a fallible COMMIT that could erase or misclassify an external daemon fact.
        drop(tx);
        drop(conn);
        Ok(FencedDecision::Cas(result))
    }
}

enum FencedDecision<E> {
    Retained,
    Cas(CasPublication<E>),
}

/// Cancel an initiating operation inside the caller's already-open compensation transaction.
/// Deleting first is safe: any later restore failure rolls the transaction back and reinstates the
/// operation.  Token/expiry equality prevents a stale receipt from cancelling reclaimed work.
pub(crate) fn cancel_operation_in_transaction(
    tx: &rusqlite::Transaction<'_>,
    compensation: &UnpublishedCompensationReceipt,
) -> Result<bool, SessionReleaseError> {
    let now_ms = clock_ms()?;
    let now = checked_ms(now_ms)?;
    if compensation.lease_until_ms <= now_ms {
        return Ok(false);
    }
    let removed = tx
        .execute(
            "DELETE FROM session_release_operations \
             WHERE operation_id = ?1 AND lease_token = ?2 AND lease_until_ms > ?3",
            rusqlite::params![compensation.operation_id, compensation.lease_token, now,],
        )
        .map_err(db_error)?;
    Ok(removed == 1)
}

/// Resolve a transaction-local optional Session generation with a strictly validated preflight
/// observation.  A current row generation always wins; a missing/NULL row needs explicit daemon
/// proof and never falls back to an id-only request.
pub(crate) fn resolve_exact_target(
    session_id: &str,
    row_generation: Option<Option<&str>>,
    row_policy: SessionRowPolicy,
    pre_resolved: &PreResolvedSessionGenerations,
) -> Result<Option<SessionReleaseTarget>, SessionReleaseError> {
    crate::ids::validate_id(session_id).map_err(|error| SessionReleaseError::InvalidTarget {
        detail: format!("invalid session id: {error}"),
    })?;
    let generation = match row_generation.flatten() {
        Some(generation) => {
            validate_generation(generation)?;
            Some(generation.to_string())
        }
        None => match pre_resolved.get(session_id) {
            Some(PreResolvedSessionState::Generation(generation)) => {
                validate_generation(generation)?;
                Some(generation.clone())
            }
            Some(PreResolvedSessionState::ConfirmedAbsent) => None,
            None => {
                return Err(SessionReleaseError::InvalidTarget {
                    detail: format!(
                        "session {session_id:?} has no exact transaction-local or pre-resolved generation"
                    ),
                })
            }
        },
    };
    generation
        .map(|generation| SessionReleaseTarget::new(session_id, generation, row_policy))
        .transpose()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::io::{BufRead, BufReader, Write};
    use std::os::unix::net::{UnixListener, UnixStream};
    use std::path::PathBuf;
    use std::sync::mpsc;
    use std::thread::JoinHandle;

    fn paths() -> (tempfile::TempDir, AppPaths) {
        let temp = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_base(temp.path().join("Maestro"));
        (temp, paths)
    }

    fn target(session_id: &str, policy: SessionRowPolicy) -> SessionReleaseTarget {
        SessionReleaseTarget::new(session_id, format!("gen-{session_id}"), policy).unwrap()
    }

    fn seed_project_workspace(paths: &AppPaths, project_id: &str, workspace_id: &str) {
        crate::ProjectService::new(paths)
            .create(project_id, project_id, ".", crate::NewProject::default(), 1)
            .unwrap();
        let workspace = crate::Workspace {
            workspace_id: workspace_id.into(),
            project_id: project_id.into(),
            root: ".".into(),
            policy: crate::WorkspacePolicy::ScratchCwd,
            consent: crate::WorkspaceConsent::default(),
        };
        crate::write_record(
            paths,
            crate::RecordKind::Workspace,
            workspace_id,
            1,
            &workspace,
        )
        .unwrap();
    }

    fn seed_session(
        paths: &AppPaths,
        workspace_id: &str,
        session_id: &str,
        generation: Option<&str>,
    ) {
        let session = crate::SessionRecord {
            session_id: session_id.into(),
            workspace_id: workspace_id.into(),
            kind: crate::SessionKind::Shell,
            launch: crate::LaunchSpec::OptOut,
            cwd_resolved: ".".into(),
            agent_task_id: None,
            created_at_ms: 1,
            last_attached_at_ms: 1,
            last_known_generation: generation.map(str::to_string),
            status: crate::SessionStatus::Live,
        };
        crate::write_record(paths, crate::RecordKind::Session, session_id, 1, &session).unwrap();
    }

    fn pending_count(paths: &AppPaths) -> i64 {
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        conn.query_row("SELECT COUNT(*) FROM pending_session_releases", [], |row| {
            row.get(0)
        })
        .unwrap()
    }

    struct ReleaseStub {
        path: PathBuf,
        _temp: tempfile::TempDir,
        handle: Option<JoinHandle<()>>,
        requests: mpsc::Receiver<String>,
    }

    impl ReleaseStub {
        fn spawn(
            serve: impl FnOnce(&mpsc::Sender<String>, &mut UnixStream) + Send + 'static,
        ) -> Self {
            let temp = tempfile::tempdir().unwrap();
            let path = temp.path().join("release.sock");
            let listener = UnixListener::bind(&path).unwrap();
            let (request_tx, requests) = mpsc::channel();
            let handle = std::thread::spawn(move || {
                let (mut stream, _) = listener.accept().unwrap();
                serve(&request_tx, &mut stream);
            });
            Self {
                path,
                _temp: temp,
                handle: Some(handle),
                requests,
            }
        }

        fn collected_requests(&mut self) -> Vec<String> {
            if let Some(handle) = self.handle.take() {
                handle.join().unwrap();
            }
            self.requests.try_iter().collect()
        }
    }

    impl Drop for ReleaseStub {
        fn drop(&mut self) {
            if let Some(handle) = self.handle.take() {
                let _ = handle.join();
            }
        }
    }

    fn read_release_request(reader: &mut impl BufRead, requests: &mpsc::Sender<String>) -> String {
        let mut line = String::new();
        assert_ne!(reader.read_line(&mut line).unwrap(), 0);
        let line = line.trim().to_string();
        requests.send(line.clone()).unwrap();
        line
    }

    fn answer_release_probe(
        reader: &mut impl BufRead,
        requests: &mpsc::Sender<String>,
        stream: &mut UnixStream,
    ) {
        assert_eq!(
            read_release_request(reader, requests),
            r#"{"op":"daemon_info"}"#
        );
        writeln!(
            stream,
            "{{\"ev\":\"daemon_info\",\"protocol_version\":{},\"build_version\":\"test-v3\",\"daemon_instance_id\":\"22222222222242228222222222222222\",\"output_generation_echo\":true,\"child_environment\":true,\"generation_conditional_mutations\":true,\"attachment_aware_conditional_kill\":true,\"generation_conditional_start\":true,\"start_operation_ledger\":true,\"generation_conditional_attach\":true}}",
            maestro_protocol::DAEMON_PROTOCOL_VERSION
        )
        .unwrap();
        stream.flush().unwrap();
    }

    fn daemon_unavailable(label: &str) -> DaemonClientError {
        DaemonClientError::DaemonUnavailable {
            path: format!("<test-{label}>"),
            source: std::io::Error::new(std::io::ErrorKind::NotFound, label.to_string()),
        }
    }

    #[test]
    fn receipt_and_claim_debug_are_redacted() {
        let (_temp, paths) = paths();
        let receipt = SessionReleaseService::new(&paths)
            .enqueue_recovered(
                &[target("privacy-session", SessionRowPolicy::RowMustBeAbsent)],
                1,
            )
            .unwrap()
            .unwrap();
        let debug = format!("{receipt:?}");
        assert!(!debug.contains("privacy-session"));
        assert!(!debug.contains("gen-privacy-session"));
        assert!(!debug.contains(&receipt.operation_id));
        assert!(!debug.contains(&receipt.lease_token));
    }

    #[test]
    fn recovered_enqueue_coalesces_the_exact_pending_lifetime_across_policies() {
        let (_temp, paths) = paths();
        let service = SessionReleaseService::new(&paths);
        let target = target("dedup-session", SessionRowPolicy::RowMustBeAbsent);
        assert!(service
            .enqueue_recovered(std::slice::from_ref(&target), 1)
            .unwrap()
            .is_some());
        assert!(service
            .enqueue_recovered(std::slice::from_ref(&target), 2)
            .unwrap()
            .is_none());
        let other_policy = SessionReleaseTarget::new(
            target.session_id(),
            target.expected_generation(),
            SessionRowPolicy::MatchingRowIsProof,
        )
        .unwrap();
        assert!(service
            .enqueue_recovered(&[other_policy], 3)
            .unwrap()
            .is_none());
        assert_eq!(pending_count(&paths), 1);
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let operations: i64 = arc
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM session_release_operations",
                [],
                |row| row.get(0),
            )
            .unwrap();
        assert_eq!(operations, 1);
    }

    #[test]
    fn retry_rotates_a_stuck_operation_behind_ready_work() {
        let (_temp, paths) = paths();
        let service = SessionReleaseService::new(&paths);
        let a = service
            .enqueue_recovered(&[target("stuck-a", SessionRowPolicy::RowMustBeAbsent)], 1)
            .unwrap()
            .unwrap();
        let b = service
            .enqueue_recovered(&[target("ready-b", SessionRowPolicy::RowMustBeAbsent)], 2)
            .unwrap()
            .unwrap();
        let arc = crate::db::conn_for(paths.base()).unwrap();
        arc.lock()
            .unwrap()
            .execute(
                "UPDATE session_release_operations SET lease_until_ms = 0 \
                 WHERE operation_id IN (?1, ?2)",
                rusqlite::params![a.operation_id, b.operation_id],
            )
            .unwrap();
        let claim_a = service.claim_next().unwrap().unwrap();
        assert_eq!(
            service.list_claimed(&claim_a).unwrap()[0].session_id(),
            "stuck-a"
        );
        service.retry_claim(claim_a).unwrap();
        let claim_b = service.claim_next().unwrap().unwrap();
        assert_eq!(
            service.list_claimed(&claim_b).unwrap()[0].session_id(),
            "ready-b"
        );
    }

    #[test]
    fn exact_generation_is_required_before_journaling() {
        let (_temp, paths) = paths();
        let error = SessionReleaseService::new(&paths)
            .enqueue_recovered(
                &[SessionReleaseTarget {
                    session_id: "missing-generation".into(),
                    expected_generation: String::new(),
                    row_policy: SessionRowPolicy::RowMustBeAbsent,
                }],
                1,
            )
            .unwrap_err();
        assert!(matches!(error, SessionReleaseError::InvalidTarget { .. }));
    }

    #[test]
    fn crash_recovery_claim_is_forward_only_and_lease_cas_is_exact() {
        let (_temp, paths) = paths();
        let service = SessionReleaseService::new(&paths);
        let receipt = service
            .enqueue_recovered(
                &[target("crash-session", SessionRowPolicy::RowMustBeAbsent)],
                1,
            )
            .unwrap()
            .unwrap();
        assert!(service.claim_next().unwrap().is_none());
        let arc = crate::db::conn_for(paths.base()).unwrap();
        arc.lock()
            .unwrap()
            .execute(
                "UPDATE session_release_operations SET lease_until_ms = 0 WHERE operation_id = ?1",
                [&receipt.operation_id],
            )
            .unwrap();
        let mut claim = service
            .claim_next()
            .unwrap()
            .expect("expired initiator lease is reclaimable");
        assert_eq!(service.list_claimed(&claim).unwrap().len(), 1);
        service.renew_claim(&mut claim).unwrap();
        assert!(matches!(
            service.list_for_lease(&receipt.operation_id, &receipt.lease_token),
            Err(SessionReleaseError::ClaimLost)
        ));
    }

    #[test]
    fn owner_fence_consumes_a_retained_target_without_calling_cas() {
        let (_temp, paths) = paths();
        crate::WindowLayoutService::new(&paths)
            .create_empty("owner-window", 1)
            .unwrap();
        crate::WindowLayoutService::new(&paths)
            .open_stashed_tab(
                "owner-window",
                "owner-tab",
                "owned-session",
                "Owned",
                false,
                crate::AttentionState::default(),
                2,
            )
            .unwrap();
        let receipt = SessionReleaseService::new(&paths)
            .enqueue_recovered(
                &[target("owned-session", SessionRowPolicy::RowMustBeAbsent)],
                3,
            )
            .unwrap()
            .unwrap();
        let outcome = SessionReleaseService::new(&paths).attempt_owned::<()>(
            receipt,
            |_| Ok(()),
            |_| panic!("stashed tab must veto the daemon CAS"),
        );
        assert!(matches!(
            outcome,
            ReleaseOperationOutcome::Complete {
                confirmed: 0,
                retained: 1
            }
        ));
    }

    #[test]
    fn offline_adapter_completes_an_all_retained_operation_without_daemon_io() {
        let (_temp, paths) = paths();
        let windows = crate::WindowLayoutService::new(&paths);
        windows.create_empty("offline-owner-window", 1).unwrap();
        windows
            .open_stashed_tab(
                "offline-owner-window",
                "offline-owner-tab",
                "offline-owned-session",
                "Owned",
                false,
                crate::AttentionState::default(),
                2,
            )
            .unwrap();
        let receipt = SessionReleaseService::new(&paths)
            .enqueue_recovered(
                &[target(
                    "offline-owned-session",
                    SessionRowPolicy::RowMustBeAbsent,
                )],
                3,
            )
            .unwrap()
            .unwrap();
        let attempt = SessionReleaseService::new(&paths)
            .attempt_owned_with_daemon_unavailable(receipt, daemon_unavailable("all-retained"));
        assert!(attempt.confirmed_lifetimes().is_empty());
        assert!(matches!(
            attempt.outcome(),
            ReleaseOperationOutcome::Complete {
                confirmed: 0,
                retained: 1
            }
        ));
        assert_eq!(pending_count(&paths), 0);
        let debug = format!("{attempt:?}");
        assert!(!debug.contains("all-retained"));
        assert!(!debug.contains("offline-owned-session"));
    }

    #[test]
    fn mixed_retained_then_offline_cas_is_forward_only_and_retryable() {
        let (_temp, paths) = paths();
        let windows = crate::WindowLayoutService::new(&paths);
        windows.create_empty("mixed-owner-window", 1).unwrap();
        windows
            .open_tab(
                "mixed-owner-window",
                "mixed-owner-tab",
                "a-retained-session",
                "Owned",
                false,
                crate::AttentionState::default(),
                2,
            )
            .unwrap();
        let service = SessionReleaseService::new(&paths);
        let receipt = service
            .enqueue_recovered(
                &[
                    target("a-retained-session", SessionRowPolicy::RowMustBeAbsent),
                    target("b-release-session", SessionRowPolicy::RowMustBeAbsent),
                ],
                3,
            )
            .unwrap()
            .unwrap();
        let attempt = service
            .attempt_owned_with_daemon_unavailable(receipt, daemon_unavailable("mixed-offline"));
        assert!(matches!(
            attempt.outcome(),
            ReleaseOperationOutcome::ForwardOnly {
                confirmed: 0,
                retained: 1,
                possibly_published: 0,
                pending: 1,
                error: Some(ReleaseFailure::Cas(
                    DaemonClientError::DaemonUnavailable { .. }
                )),
            }
        ));
        assert_eq!(pending_count(&paths), 1);
        assert!(service.claim_next().unwrap().is_some());
    }

    #[test]
    fn daemon_adapter_reports_exact_confirmation_even_when_journal_consume_fails() {
        let (_temp, paths) = paths();
        let service = SessionReleaseService::new(&paths);
        let receipt = service
            .enqueue_recovered(
                &[SessionReleaseTarget::new(
                    "cache-session",
                    "gen-a",
                    SessionRowPolicy::RowMustBeAbsent,
                )
                .unwrap()],
                1,
            )
            .unwrap()
            .unwrap();
        let _consume_failure_guard = lock_consume_failure();
        inject_consume_failure("cache-session");

        let mut stub = ReleaseStub::spawn(|requests, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_release_probe(&mut reader, requests, stream);
            assert_eq!(
                read_release_request(&mut reader, requests),
                r#"{"op":"list_sessions"}"#
            );
            stream
                .write_all(
                    b"{\"ev\":\"sessions\",\"ids\":[\"cache-session\"],\"sessions\":[{\"id\":\"cache-session\",\"generation\":\"gen-b\"}]}\n",
                )
                .unwrap();
            stream.flush().unwrap();
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let attempt = service.attempt_owned_with_daemon(receipt, &mut client);
        drop(client);
        assert_eq!(
            stub.collected_requests(),
            vec![
                r#"{"op":"daemon_info"}"#.to_string(),
                r#"{"op":"list_sessions"}"#.to_string(),
            ]
        );
        assert!(
            matches!(
                attempt.outcome(),
                ReleaseOperationOutcome::ForwardOnly {
                    confirmed: 1,
                    retained: 0,
                    possibly_published: 0,
                    pending: 1,
                    error: Some(ReleaseFailure::Journal(_)),
                }
            ),
            "unexpected adapter outcome: {:?}",
            attempt.outcome()
        );
        assert_eq!(attempt.confirmed_lifetimes().len(), 1);
        assert_eq!(
            attempt.confirmed_lifetimes()[0].session_id(),
            "cache-session"
        );
        assert_eq!(
            attempt.confirmed_lifetimes()[0].expected_generation(),
            "gen-a"
        );
        assert_eq!(pending_count(&paths), 1);
    }

    #[test]
    fn empty_pre_resolution_cohort_performs_zero_daemon_requests() {
        let mut stub = ReleaseStub::spawn(|requests, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            let read = reader.read_line(&mut line).unwrap();
            if read != 0 {
                requests.send(line.trim().to_string()).unwrap();
            }
            assert_eq!(read, 0, "empty pre-resolution must not probe the daemon");
        });
        let mut client = DaemonClient::connect(&stub.path).unwrap();
        let resolved = pre_resolve_session_generations(&mut client, std::iter::empty::<&str>())
            .expect("empty unresolved cohort is local");
        assert!(resolved.is_empty());
        drop(client);
        assert!(stub.collected_requests().is_empty());
    }

    #[test]
    fn owned_offline_compensation_can_be_surrendered_to_a_forward_claim() {
        let (_temp, paths) = paths();
        let service = SessionReleaseService::new(&paths);
        let receipt = service
            .enqueue_recovered(
                &[target(
                    "offline-retry-session",
                    SessionRowPolicy::RowMustBeAbsent,
                )],
                1,
            )
            .unwrap()
            .unwrap();
        let owned =
            service.attempt_owned_with_daemon_unavailable(receipt, daemon_unavailable("initiator"));
        let (outcome, confirmed) = owned.into_parts();
        assert!(confirmed.is_empty());
        let compensation = match outcome {
            ReleaseOperationOutcome::UnpublishedFailure { compensation, .. } => compensation,
            other => {
                panic!("eligible initiator should retain zero-publication authority: {other:?}")
            }
        };
        service.release_unpublished_for_retry(compensation).unwrap();
        let claim = service.claim_next().unwrap().unwrap();
        let claimed =
            service.attempt_claimed_with_daemon_unavailable(claim, daemon_unavailable("forward"));
        assert!(matches!(
            claimed.outcome(),
            ReleaseOperationOutcome::ForwardOnly {
                confirmed: 0,
                retained: 0,
                possibly_published: 0,
                pending: 1,
                error: Some(ReleaseFailure::Cas(
                    DaemonClientError::DaemonUnavailable { .. }
                )),
            }
        ));
        assert_eq!(pending_count(&paths), 1);
    }

    #[test]
    fn fresh_forward_claim_consumes_old_a_after_live_b_supersedes_an_ambiguous_attempt() {
        let (_temp, paths) = paths();
        let service = SessionReleaseService::new(&paths);
        let receipt = service
            .enqueue_recovered(
                &[SessionReleaseTarget::new(
                    "aba-session",
                    "gen-a",
                    SessionRowPolicy::RowMustBeAbsent,
                )
                .unwrap()],
                1,
            )
            .unwrap()
            .unwrap();

        let mut first_stub = ReleaseStub::spawn(|requests, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_release_probe(&mut reader, requests, stream);
            assert_eq!(
                read_release_request(&mut reader, requests),
                r#"{"op":"list_sessions"}"#
            );
            stream
                .write_all(
                    b"{\"ev\":\"sessions\",\"ids\":[\"aba-session\"],\"sessions\":[{\"id\":\"aba-session\",\"generation\":\"gen-a\"}]}\n",
                )
                .unwrap();
            stream.flush().unwrap();
            read_release_request(&mut reader, requests); // exact Kill A
            read_release_request(&mut reader, requests); // confirmation, then EOF
        });
        let mut first_client = DaemonClient::connect(&first_stub.path).unwrap();
        let first = service.attempt_owned_with_daemon(receipt, &mut first_client);
        drop(first_client);
        assert!(matches!(
            first.outcome(),
            ReleaseOperationOutcome::ForwardOnly {
                confirmed: 0,
                retained: 0,
                possibly_published: 1,
                pending: 1,
                error: Some(ReleaseFailure::Cas(DaemonClientError::UnexpectedEof { .. })),
            }
        ));
        assert!(first.confirmed_lifetimes().is_empty());
        assert_eq!(first_stub.collected_requests().len(), 4);

        let claim = service.claim_next().unwrap().unwrap();
        let mut second_stub = ReleaseStub::spawn(|requests, stream| {
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            answer_release_probe(&mut reader, requests, stream);
            assert_eq!(
                read_release_request(&mut reader, requests),
                r#"{"op":"list_sessions"}"#
            );
            stream
                .write_all(
                    b"{\"ev\":\"sessions\",\"ids\":[\"aba-session\"],\"sessions\":[{\"id\":\"aba-session\",\"generation\":\"gen-b\"}]}\n",
                )
                .unwrap();
            stream.flush().unwrap();
        });
        let mut second_client = DaemonClient::connect(&second_stub.path).unwrap();
        let second = service.attempt_claimed_with_daemon(claim, &mut second_client);
        drop(second_client);
        assert!(matches!(
            second.outcome(),
            ReleaseOperationOutcome::Complete {
                confirmed: 1,
                retained: 0
            }
        ));
        assert_eq!(second.confirmed_lifetimes().len(), 1);
        assert_eq!(second.confirmed_lifetimes()[0].session_id(), "aba-session");
        assert_eq!(
            second.confirmed_lifetimes()[0].expected_generation(),
            "gen-a"
        );
        assert_eq!(second_stub.collected_requests().len(), 2);
        assert_eq!(pending_count(&paths), 0);
    }

    #[test]
    fn publication_classification_controls_compensation_authority() {
        let (_temp, paths) = paths();
        let service = SessionReleaseService::new(&paths);
        let unpublished = service
            .enqueue_recovered(
                &[target("not-published", SessionRowPolicy::RowMustBeAbsent)],
                1,
            )
            .unwrap()
            .unwrap();
        assert!(matches!(
            service.attempt_owned(
                unpublished,
                |_| Ok(()),
                |_| CasPublication::NotPublished("offline")
            ),
            ReleaseOperationOutcome::UnpublishedFailure { .. }
        ));

        let ambiguous = service
            .enqueue_recovered(&[target("ambiguous", SessionRowPolicy::RowMustBeAbsent)], 3)
            .unwrap()
            .unwrap();
        assert!(matches!(
            service.attempt_owned(
                ambiguous,
                |_| Ok(()),
                |_| CasPublication::PossiblyPublished("eof")
            ),
            ReleaseOperationOutcome::ForwardOnly {
                possibly_published: 1,
                ..
            }
        ));

        let confirmed = service
            .enqueue_recovered(&[target("confirmed", SessionRowPolicy::RowMustBeAbsent)], 5)
            .unwrap()
            .unwrap();
        assert!(matches!(
            service.attempt_owned::<()>(confirmed, |_| Ok(()), |_| CasPublication::Confirmed),
            ReleaseOperationOutcome::Complete {
                confirmed: 1,
                retained: 0
            }
        ));
    }

    #[test]
    fn complete_owner_graph_vetoes_task_history_current_and_worktree_provenance() {
        let (_temp, paths) = paths();
        seed_project_workspace(&paths, "owner-project", "owner-workspace");
        let arc = crate::db::conn_for(paths.base()).unwrap();
        let conn = arc.lock().unwrap();
        conn.execute(
            "INSERT INTO agent_tasks (
                 agent_task_id, project_id, goal, state, current_session_id,
                 session_history_json, created_at_ms, updated_at_ms, result_summary
             ) VALUES ('owner-task', 'owner-project', '', 'running',
                       'task-current-session', '[\"task-history-session\"]', 1, 1, NULL)",
            [],
        )
        .unwrap();
        conn.execute(
            "INSERT INTO worktree_provenance (
                 session_id, workspace_id, repo_root, target_path, branch, created_at_ms
             ) VALUES ('worktree-session', 'owner-workspace', '.', './worktree', 'branch', 1)",
            [],
        )
        .unwrap();
        drop(conn);
        drop(arc);

        let targets = [
            target("task-current-session", SessionRowPolicy::RowMustBeAbsent),
            target("task-history-session", SessionRowPolicy::RowMustBeAbsent),
            target("worktree-session", SessionRowPolicy::RowMustBeAbsent),
        ];
        let receipt = SessionReleaseService::new(&paths)
            .enqueue_recovered(&targets, 2)
            .unwrap()
            .unwrap();
        let outcome = SessionReleaseService::new(&paths).attempt_owned::<()>(
            receipt,
            |_| Ok(()),
            |_| panic!("a complete durable owner must veto daemon publication"),
        );
        assert!(matches!(
            outcome,
            ReleaseOperationOutcome::Complete {
                confirmed: 0,
                retained: 3
            }
        ));
        assert_eq!(pending_count(&paths), 0);
    }

    #[test]
    fn row_policies_fail_closed_on_mismatch_null_and_recreation() {
        for (suffix, row_generation, policy, expected_generation) in [
            (
                "mismatch",
                Some("new-generation"),
                SessionRowPolicy::MatchingRowIsProof,
                "old-generation",
            ),
            (
                "null",
                None,
                SessionRowPolicy::MatchingRowIsProof,
                "daemon-generation",
            ),
            (
                "recreated",
                Some("same-generation"),
                SessionRowPolicy::RowMustBeAbsent,
                "same-generation",
            ),
        ] {
            let (_temp, paths) = paths();
            let project_id = format!("project-{suffix}");
            let workspace_id = format!("workspace-{suffix}");
            let session_id = format!("session-{suffix}");
            seed_project_workspace(&paths, &project_id, &workspace_id);
            seed_session(&paths, &workspace_id, &session_id, row_generation);
            let receipt = SessionReleaseService::new(&paths)
                .enqueue_recovered(
                    &[
                        SessionReleaseTarget::new(&session_id, expected_generation, policy)
                            .unwrap(),
                    ],
                    2,
                )
                .unwrap()
                .unwrap();
            let outcome = SessionReleaseService::new(&paths).attempt_owned::<()>(
                receipt,
                |_| Ok(()),
                |_| panic!("ambiguous Session row must veto daemon publication"),
            );
            assert!(matches!(
                outcome,
                ReleaseOperationOutcome::Complete {
                    confirmed: 0,
                    retained: 1
                }
            ));
        }
    }

    #[test]
    fn reclaimed_initial_receipt_cannot_publish_or_mint_compensation() {
        let (_temp, paths) = paths();
        let service = SessionReleaseService::new(&paths);
        let receipt = service
            .enqueue_recovered(
                &[target(
                    "reclaimed-session",
                    SessionRowPolicy::RowMustBeAbsent,
                )],
                1,
            )
            .unwrap()
            .unwrap();
        let arc = crate::db::conn_for(paths.base()).unwrap();
        arc.lock()
            .unwrap()
            .execute(
                "UPDATE session_release_operations SET lease_until_ms = 0 WHERE operation_id = ?1",
                [&receipt.operation_id],
            )
            .unwrap();
        let claim = service
            .claim_next()
            .unwrap()
            .expect("expired receipt is reclaimed");
        let cas_calls = Cell::new(0);
        let outcome = service.attempt_owned::<()>(
            receipt,
            |_| Ok(()),
            |_| {
                cas_calls.set(cas_calls.get() + 1);
                CasPublication::Confirmed
            },
        );
        assert_eq!(cas_calls.get(), 0);
        assert!(matches!(
            outcome,
            ReleaseOperationOutcome::ForwardOnly {
                confirmed: 0,
                possibly_published: 0,
                ..
            }
        ));
        assert_eq!(service.list_claimed(&claim).unwrap().len(), 1);
    }

    #[test]
    fn crash_recovered_not_published_result_remains_forward_only() {
        let (_temp, paths) = paths();
        let service = SessionReleaseService::new(&paths);
        let receipt = service
            .enqueue_recovered(
                &[target(
                    "crash-not-published",
                    SessionRowPolicy::RowMustBeAbsent,
                )],
                1,
            )
            .unwrap()
            .unwrap();
        let arc = crate::db::conn_for(paths.base()).unwrap();
        arc.lock()
            .unwrap()
            .execute(
                "UPDATE session_release_operations SET lease_until_ms = 0 \
                 WHERE operation_id = ?1",
                [&receipt.operation_id],
            )
            .unwrap();
        let claim = service.claim_next().unwrap().unwrap();
        let outcome = service.attempt_claimed(
            claim,
            |_| Ok::<(), &'static str>(()),
            |_| CasPublication::NotPublished("offline"),
        );
        assert!(matches!(
            outcome,
            ReleaseOperationOutcome::ForwardOnly {
                confirmed: 0,
                possibly_published: 0,
                pending: 1,
                error: Some(ReleaseFailure::Cas("offline")),
                ..
            }
        ));
        assert_eq!(pending_count(&paths), 1);
        assert!(service.claim_next().unwrap().is_some());
    }

    #[test]
    fn writer_fence_prevents_a_second_claimant_crossing_the_cas() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (_temp, paths) = paths();
        let service = SessionReleaseService::new(&paths);
        let receipt = service
            .enqueue_recovered(
                &[target("fenced-session", SessionRowPolicy::RowMustBeAbsent)],
                1,
            )
            .unwrap()
            .unwrap();
        let (go_tx, go_rx) = mpsc::channel();
        let (started_tx, started_rx) = mpsc::channel();
        let (result_tx, result_rx) = mpsc::channel();
        let second_paths = AppPaths::with_base(paths.base().to_path_buf());
        let second = std::thread::spawn(move || {
            go_rx.recv().unwrap();
            started_tx.send(()).unwrap();
            let result = SessionReleaseService::new(&second_paths)
                .claim_next()
                .map(|claim| claim.is_some());
            result_tx.send(result).unwrap();
        });

        let outcome = service.attempt_owned::<()>(
            receipt,
            |_| Ok(()),
            |_| {
                go_tx.send(()).unwrap();
                started_rx.recv().unwrap();
                assert!(
                    result_rx.recv_timeout(Duration::from_millis(50)).is_err(),
                    "second claimant crossed the ownership/CAS writer fence"
                );
                CasPublication::Confirmed
            },
        );
        assert!(matches!(
            outcome,
            ReleaseOperationOutcome::Complete {
                confirmed: 1,
                retained: 0
            }
        ));
        assert!(!result_rx.recv().unwrap().unwrap());
        second.join().unwrap();
    }

    #[test]
    fn actual_tab_owner_writer_cannot_commit_across_the_daemon_cas_fence() {
        use std::sync::mpsc;
        use std::time::Duration;

        let (_temp, paths) = paths();
        crate::WindowLayoutService::new(&paths)
            .create_empty("late-owner-window", 1)
            .unwrap();
        let service = SessionReleaseService::new(&paths);
        let receipt = service
            .enqueue_recovered(
                &[target(
                    "late-owner-session",
                    SessionRowPolicy::RowMustBeAbsent,
                )],
                2,
            )
            .unwrap()
            .unwrap();
        let (go_tx, go_rx) = mpsc::channel();
        let (started_tx, started_rx) = mpsc::channel();
        let (committed_tx, committed_rx) = mpsc::channel();
        let writer_paths = AppPaths::with_base(paths.base().to_path_buf());
        let writer = std::thread::spawn(move || {
            go_rx.recv().unwrap();
            started_tx.send(()).unwrap();
            crate::WindowLayoutService::new(&writer_paths)
                .open_stashed_tab(
                    "late-owner-window",
                    "late-owner-tab",
                    "late-owner-session",
                    "Late owner",
                    false,
                    crate::AttentionState::default(),
                    3,
                )
                .unwrap();
            committed_tx.send(()).unwrap();
        });
        let outcome = service.attempt_owned::<()>(
            receipt,
            |_| Ok(()),
            |_| {
                go_tx.send(()).unwrap();
                started_rx.recv().unwrap();
                assert!(
                    committed_rx
                        .recv_timeout(Duration::from_millis(50))
                        .is_err(),
                    "a durable tab owner committed while the CAS fence was held"
                );
                CasPublication::Confirmed
            },
        );
        assert!(matches!(
            outcome,
            ReleaseOperationOutcome::Complete {
                confirmed: 1,
                retained: 0
            }
        ));
        committed_rx.recv().unwrap();
        writer.join().unwrap();
        assert!(crate::WindowLayoutService::new(&paths)
            .load("late-owner-window")
            .unwrap()
            .unwrap()
            .tabs
            .iter()
            .any(|tab| tab.session_id == "late-owner-session"));
    }

    #[test]
    fn matching_session_row_generation_is_proof_not_an_owner_veto() {
        let (_temp, paths) = paths();
        seed_project_workspace(&paths, "proof-project", "proof-workspace");
        seed_session(
            &paths,
            "proof-workspace",
            "proof-session",
            Some("proof-generation"),
        );
        let receipt = SessionReleaseService::new(&paths)
            .enqueue_recovered(
                &[SessionReleaseTarget::new(
                    "proof-session",
                    "proof-generation",
                    SessionRowPolicy::MatchingRowIsProof,
                )
                .unwrap()],
                2,
            )
            .unwrap()
            .unwrap();
        let calls = Cell::new(0);
        let outcome = SessionReleaseService::new(&paths).attempt_owned::<()>(
            receipt,
            |_| Ok(()),
            |target| {
                assert_eq!(target.session_id(), "proof-session");
                assert_eq!(target.expected_generation(), "proof-generation");
                calls.set(calls.get() + 1);
                CasPublication::Confirmed
            },
        );
        assert_eq!(calls.get(), 1);
        assert!(matches!(
            outcome,
            ReleaseOperationOutcome::Complete {
                confirmed: 1,
                retained: 0
            }
        ));
    }

    #[test]
    fn active_stashed_and_other_window_tabs_all_veto_release() {
        let (_temp, paths) = paths();
        let windows = crate::WindowLayoutService::new(&paths);
        windows.create_empty("owner-window-a", 1).unwrap();
        windows.create_empty("owner-window-b", 1).unwrap();
        windows
            .open_tab(
                "owner-window-a",
                "active-owner-tab",
                "active-owner-session",
                "Active",
                false,
                crate::AttentionState::default(),
                2,
            )
            .unwrap();
        windows
            .open_stashed_tab(
                "owner-window-b",
                "stashed-owner-tab",
                "stashed-owner-session",
                "Stashed",
                false,
                crate::AttentionState::default(),
                2,
            )
            .unwrap();
        let receipt = SessionReleaseService::new(&paths)
            .enqueue_recovered(
                &[
                    target("active-owner-session", SessionRowPolicy::RowMustBeAbsent),
                    target("stashed-owner-session", SessionRowPolicy::RowMustBeAbsent),
                ],
                3,
            )
            .unwrap()
            .unwrap();
        assert!(matches!(
            SessionReleaseService::new(&paths).attempt_owned::<()>(
                receipt,
                |_| Ok(()),
                |_| panic!("any active or stashed tab is a durable owner")
            ),
            ReleaseOperationOutcome::Complete {
                confirmed: 0,
                retained: 2
            }
        ));
    }

    #[test]
    fn malformed_history_and_orphan_provenance_fail_closed_without_cas() {
        for malformed_history in [true, false] {
            let (_temp, paths) = paths();
            seed_project_workspace(&paths, "malformed-project", "malformed-workspace");
            let arc = crate::db::conn_for(paths.base()).unwrap();
            let conn = arc.lock().unwrap();
            if malformed_history {
                conn.execute(
                    "INSERT INTO agent_tasks (
                         agent_task_id, project_id, goal, state, current_session_id,
                         session_history_json, created_at_ms, updated_at_ms, result_summary
                     ) VALUES ('malformed-task', 'malformed-project', '', 'running', NULL,
                               '{not-json', 1, 1, NULL)",
                    [],
                )
                .unwrap();
            } else {
                conn.execute(
                    "INSERT INTO worktree_provenance (
                         session_id, workspace_id, repo_root, target_path, branch, created_at_ms
                     ) VALUES ('orphan-session', 'missing-workspace', '.', './worktree', 'branch', 1)",
                    [],
                )
                .unwrap();
            }
            drop(conn);
            drop(arc);
            let receipt = SessionReleaseService::new(&paths)
                .enqueue_recovered(
                    &[target(
                        if malformed_history {
                            "malformed-history-target"
                        } else {
                            "orphan-provenance-target"
                        },
                        SessionRowPolicy::RowMustBeAbsent,
                    )],
                    2,
                )
                .unwrap()
                .unwrap();
            let calls = Cell::new(0);
            let outcome = SessionReleaseService::new(&paths).attempt_owned::<()>(
                receipt,
                |_| Ok(()),
                |_| {
                    calls.set(calls.get() + 1);
                    CasPublication::Confirmed
                },
            );
            assert_eq!(calls.get(), 0);
            assert!(matches!(
                outcome,
                ReleaseOperationOutcome::UnpublishedFailure {
                    error: ReleaseFailure::Journal(SessionReleaseError::OwnershipUncertain { .. }),
                    ..
                }
            ));
        }
    }

    #[test]
    fn partial_multi_target_publication_is_forward_only_and_retryable() {
        for ambiguous in [false, true] {
            let (_temp, paths) = paths();
            let service = SessionReleaseService::new(&paths);
            let receipt = service
                .enqueue_recovered(
                    &[
                        target("a-session", SessionRowPolicy::RowMustBeAbsent),
                        target("b-session", SessionRowPolicy::RowMustBeAbsent),
                        target("c-session", SessionRowPolicy::RowMustBeAbsent),
                    ],
                    1,
                )
                .unwrap()
                .unwrap();
            let calls = Cell::new(0);
            let outcome = service.attempt_owned(
                receipt,
                |_| Ok::<(), &'static str>(()),
                |_| {
                    let call = calls.get();
                    calls.set(call + 1);
                    match call {
                        0 => CasPublication::Confirmed,
                        1 if ambiguous => CasPublication::PossiblyPublished("ambiguous"),
                        1 => CasPublication::NotPublished("offline"),
                        _ => panic!("drain must stop at the first unconfirmed target"),
                    }
                },
            );
            assert!(matches!(
                outcome,
                ReleaseOperationOutcome::ForwardOnly {
                    confirmed: 1,
                    possibly_published,
                    pending: 2,
                    ..
                } if possibly_published == usize::from(ambiguous)
            ));
            assert_eq!(pending_count(&paths), 2);
            let claim = service
                .claim_next()
                .unwrap()
                .expect("partial operation is released for exact retry");
            assert!(matches!(
                service.attempt_claimed::<()>(claim, |_| Ok(()), |_| CasPublication::Confirmed),
                ReleaseOperationOutcome::Complete {
                    confirmed: 2,
                    retained: 0
                }
            ));
            assert_eq!(pending_count(&paths), 0);
        }
    }

    #[test]
    fn consume_failure_after_retained_or_confirmed_is_always_forward_only() {
        let _consume_failure_guard = lock_consume_failure();
        for retained in [false, true] {
            let (_temp, paths) = paths();
            let session_id = if retained {
                "consume-retained-session"
            } else {
                "consume-confirmed-session"
            };
            if retained {
                crate::WindowLayoutService::new(&paths)
                    .create_empty("consume-owner-window", 1)
                    .unwrap();
                crate::WindowLayoutService::new(&paths)
                    .open_stashed_tab(
                        "consume-owner-window",
                        "consume-owner-tab",
                        session_id,
                        "Owner",
                        false,
                        crate::AttentionState::default(),
                        2,
                    )
                    .unwrap();
            }
            let receipt = SessionReleaseService::new(&paths)
                .enqueue_recovered(&[target(session_id, SessionRowPolicy::RowMustBeAbsent)], 3)
                .unwrap()
                .unwrap();
            inject_consume_failure(session_id);
            let outcome = SessionReleaseService::new(&paths).attempt_owned::<()>(
                receipt,
                |_| Ok(()),
                |_| CasPublication::Confirmed,
            );
            assert!(matches!(
                outcome,
                ReleaseOperationOutcome::ForwardOnly {
                    confirmed,
                    retained: retained_count,
                    pending: 1,
                    error: Some(ReleaseFailure::Journal(_)),
                    ..
                } if confirmed == usize::from(!retained)
                    && retained_count == usize::from(retained)
            ));
            assert_eq!(pending_count(&paths), 1);
        }
    }

    #[test]
    fn independent_writer_expiry_cannot_be_crossed_by_stale_renew_or_release() {
        use std::sync::mpsc;
        use std::time::Duration;

        for renew in [false, true] {
            let (_temp, paths) = paths();
            let service = SessionReleaseService::new(&paths);
            let receipt = service
                .enqueue_recovered(
                    &[target(
                        "expiry-race-session",
                        SessionRowPolicy::RowMustBeAbsent,
                    )],
                    1,
                )
                .unwrap()
                .unwrap();
            let mut independent =
                rusqlite::Connection::open(crate::db::db_path(paths.base())).unwrap();
            independent
                .pragma_update(None, "foreign_keys", "ON")
                .unwrap();
            let expiry = independent
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            expiry
                .execute(
                    "UPDATE session_release_operations SET lease_until_ms = 0 \
                     WHERE operation_id = ?1",
                    [&receipt.operation_id],
                )
                .unwrap();

            let (started_tx, started_rx) = mpsc::channel();
            let (result_tx, result_rx) = mpsc::channel();
            let waiter_paths = AppPaths::with_base(paths.base().to_path_buf());
            let operation_id = receipt.operation_id.clone();
            let lease_token = receipt.lease_token.clone();
            let waiter = std::thread::spawn(move || {
                started_tx.send(()).unwrap();
                let service = SessionReleaseService::new(&waiter_paths);
                let result = if renew {
                    service.renew_lease(&operation_id, &lease_token).map(|_| ())
                } else {
                    service.release_lease(&operation_id, &lease_token)
                };
                result_tx.send(result).unwrap();
            });
            started_rx.recv().unwrap();
            assert!(
                result_rx.recv_timeout(Duration::from_millis(50)).is_err(),
                "lease transition did not wait for the independent writer fence"
            );
            expiry.commit().unwrap();
            let result = result_rx.recv().unwrap();
            assert!(matches!(
                result,
                Err(SessionReleaseError::LeaseExpired | SessionReleaseError::ClaimLost)
            ));
            waiter.join().unwrap();
            assert_eq!(pending_count(&paths), 1);
        }
    }

    #[test]
    fn cancellation_requires_the_exact_unexpired_lease() {
        for expire in [false, true] {
            let (_temp, paths) = paths();
            let service = SessionReleaseService::new(&paths);
            let receipt = service
                .enqueue_recovered(
                    &[target("cancel-session", SessionRowPolicy::RowMustBeAbsent)],
                    1,
                )
                .unwrap()
                .unwrap();
            let compensation = match service.attempt_owned(
                receipt,
                |_| Ok::<(), &'static str>(()),
                |_| CasPublication::NotPublished("offline"),
            ) {
                ReleaseOperationOutcome::UnpublishedFailure { compensation, .. } => compensation,
                other => panic!("expected compensation authority, got {other:?}"),
            };
            let arc = crate::db::conn_for(paths.base()).unwrap();
            if expire {
                arc.lock()
                    .unwrap()
                    .execute(
                        "UPDATE session_release_operations SET lease_until_ms = 0 \
                         WHERE operation_id = ?1",
                        [&compensation.operation_id],
                    )
                    .unwrap();
            } else {
                arc.lock()
                    .unwrap()
                    .execute(
                        "UPDATE session_release_operations \
                         SET lease_token = '20000000-0000-4000-8000-000000000001' \
                         WHERE operation_id = ?1",
                        [&compensation.operation_id],
                    )
                    .unwrap();
            }
            let mut conn = arc.lock().unwrap();
            let tx = conn
                .transaction_with_behavior(TransactionBehavior::Immediate)
                .unwrap();
            assert!(!cancel_operation_in_transaction(&tx, &compensation).unwrap());
            tx.commit().unwrap();
            drop(conn);
            drop(arc);
            assert_eq!(pending_count(&paths), 1);
        }
    }
}
