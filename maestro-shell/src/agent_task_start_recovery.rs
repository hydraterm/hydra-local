//! One-at-a-time forward recovery for durable AgentTask start journals.
//!
//! This service is deliberately content-blind at the daemon boundary. It claims one expired DB
//! marker, reconnects only to the exact socket/daemon/PID sealed before Start, and then resolves
//! the operation token through the daemon's process-lifetime ledger. Durable Live is published
//! only from a previously persisted Grid proof or a fresh exact Attach/Grid; Exited/Removed ledger
//! facts may publish only durable Exited. Changed product graphs are never rewritten.

// Recovery errors intentionally return the consume-once authority needed for a bounded retry.
#![allow(clippy::result_large_err)]

use std::error::Error;
use std::fmt;

use maestro_protocol::{
    SessionId, SessionStartOperationLifecycle, SessionStartOperationRetireOutcome,
    SessionStartOperationStatus,
};

use crate::agent_task_start_journal::{
    AgentTaskStartAppliedMarkOutcome, AgentTaskStartBindingState,
    AgentTaskStartChangedCleanupDeleteOutcome, AgentTaskStartChangedUnappliedDeleteOutcome,
    AgentTaskStartCompensationOutcome, AgentTaskStartDisposition, AgentTaskStartJournalError,
    AgentTaskStartJournalService, AgentTaskStartPublicationOutcome,
    AgentTaskStartReleaseDeleteOutcome, AppliedAgentTaskStartState, ClaimedAgentTaskStart,
    ClaimedAgentTaskStartGraph, CleanedAndRetiredAgentTaskStartOperation,
    ProvenUnappliedAgentTaskStart, RetiredAgentTaskStartOperation,
};
use crate::daemon_client::{
    ConditionalStartGridRecovery, ConditionalStartRecoveryAuthority, DaemonClient,
    DaemonClientError, KillSessionPublicationError, DEFAULT_TIMEOUT,
};
use crate::paths::AppPaths;

/// Coarse, privacy-safe result of one bounded recovery attempt. No variant exposes durable ids,
/// operation tokens, socket paths, launch bytes, task goals, or command arguments.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AgentTaskStartRecoveryOutcome {
    Idle,
    Compensated,
    PublishedLive,
    PublishedExited,
    ReleaseDeleted,
    ChangedJournalDeleted,
    ClaimLost,
    Deferred,
}

/// A retryable infrastructure failure while recovering one claimed marker. Claim leases expire,
/// so returning an error never abandons the durable authority.
pub enum AgentTaskStartRecoveryError {
    Journal(AgentTaskStartJournalError),
    Daemon(DaemonClientError),
    LifetimeRelease(KillSessionPublicationError),
    PeerChanged,
    InvalidBoundMarker,
}

impl fmt::Debug for AgentTaskStartRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(_) => formatter.write_str("AgentTaskStartRecoveryError::Journal"),
            Self::Daemon(_) => formatter.write_str("AgentTaskStartRecoveryError::Daemon"),
            Self::LifetimeRelease(_) => {
                formatter.write_str("AgentTaskStartRecoveryError::LifetimeRelease")
            }
            Self::PeerChanged => formatter.write_str("AgentTaskStartRecoveryError::PeerChanged"),
            Self::InvalidBoundMarker => {
                formatter.write_str("AgentTaskStartRecoveryError::InvalidBoundMarker")
            }
        }
    }
}

impl fmt::Display for AgentTaskStartRecoveryError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Journal(error) => write!(
                formatter,
                "AgentTask start journal recovery failed: {error}"
            ),
            Self::Daemon(error) => write!(formatter, "AgentTask daemon recovery failed: {error}"),
            Self::LifetimeRelease(error) => {
                write!(
                    formatter,
                    "AgentTask exact lifetime cleanup remains pending: {error}"
                )
            }
            Self::PeerChanged => formatter.write_str(
                "AgentTask recovery socket no longer belongs to the journal's exact daemon peer",
            ),
            Self::InvalidBoundMarker => {
                formatter.write_str("AgentTask recovery journal has an invalid bound state")
            }
        }
    }
}

impl Error for AgentTaskStartRecoveryError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            Self::Journal(error) => Some(error),
            Self::Daemon(error) => Some(error),
            Self::LifetimeRelease(error) => Some(error),
            Self::PeerChanged | Self::InvalidBoundMarker => None,
        }
    }
}

impl From<AgentTaskStartJournalError> for AgentTaskStartRecoveryError {
    fn from(error: AgentTaskStartJournalError) -> Self {
        Self::Journal(error)
    }
}

impl From<DaemonClientError> for AgentTaskStartRecoveryError {
    fn from(error: DaemonClientError) -> Self {
        Self::Daemon(error)
    }
}

impl From<KillSessionPublicationError> for AgentTaskStartRecoveryError {
    fn from(error: KillSessionPublicationError) -> Self {
        Self::LifetimeRelease(error)
    }
}

pub struct AgentTaskStartRecoveryService<'a> {
    paths: &'a AppPaths,
}

impl<'a> AgentTaskStartRecoveryService<'a> {
    pub fn new(paths: &'a AppPaths) -> Self {
        Self { paths }
    }

    /// Claim and settle at most one oldest expired marker. The bound is intentional: desktop
    /// callers coalesce this method on a background worker and run it at a fixed cadence.
    pub fn recover_next(
        &self,
    ) -> Result<AgentTaskStartRecoveryOutcome, AgentTaskStartRecoveryError> {
        let journal = AgentTaskStartJournalService::new(self.paths);
        let Some(mut claim) = journal.claim_next()? else {
            return Ok(AgentTaskStartRecoveryOutcome::Idle);
        };

        if claim.binding_state() == AgentTaskStartBindingState::Unbound {
            let proof = claim
                .prove_unbound_unapplied()
                .ok_or(AgentTaskStartRecoveryError::InvalidBoundMarker)?;
            return self.finish_unapplied(&journal, &claim, &proof);
        }

        let operation_token = claim.operation_token().clone();
        let daemon_instance_id = claim
            .daemon_instance_id()
            .cloned()
            .ok_or(AgentTaskStartRecoveryError::InvalidBoundMarker)?;
        let client = self.connect_exact_peer(&claim)?;
        let authority = ConditionalStartRecoveryAuthority::from_bound_absent_journal(
            SessionId(claim.session_id().to_string()),
            operation_token.clone(),
            daemon_instance_id.clone(),
            claim.applied_generation().map(str::to_string),
            client,
        );

        if claim.disposition() == AgentTaskStartDisposition::Release {
            let Some(generation) = claim.applied_generation().map(str::to_string) else {
                return Err(AgentTaskStartRecoveryError::InvalidBoundMarker);
            };
            return self.retire_and_delete_release(
                &journal,
                &claim,
                &authority,
                operation_token,
                daemon_instance_id,
                &generation,
            );
        }

        let status = authority.lookup_operation_status()?;
        if claim.applied_generation().is_some() || claim.applied_state().is_some() {
            return self.recover_durably_applied(
                &journal,
                &mut claim,
                &authority,
                operation_token,
                daemon_instance_id,
                status,
            );
        }

        match status {
            SessionStartOperationStatus::Unknown
            | SessionStartOperationStatus::Reserved
            | SessionStartOperationStatus::Refused => {
                match authority.retire_unapplied_operation()? {
                    SessionStartOperationRetireOutcome::Retired
                    | SessionStartOperationRetireOutcome::AlreadyRetired => {
                        let proof = ProvenUnappliedAgentTaskStart::bound_operation_retired(
                            operation_token,
                            daemon_instance_id,
                        );
                        self.finish_unapplied(&journal, &claim, &proof)
                    }
                    SessionStartOperationRetireOutcome::Conflict { .. } => {
                        Ok(AgentTaskStartRecoveryOutcome::Deferred)
                    }
                }
            }
            status @ SessionStartOperationStatus::Applied { .. } => self
                .observe_and_publish_applied(
                    &journal,
                    &mut claim,
                    &authority,
                    operation_token,
                    daemon_instance_id,
                    status,
                ),
        }
    }

    fn connect_exact_peer(
        &self,
        claim: &ClaimedAgentTaskStart,
    ) -> Result<DaemonClient, AgentTaskStartRecoveryError> {
        let socket_path = claim
            .socket_path()
            .ok_or(AgentTaskStartRecoveryError::InvalidBoundMarker)?;
        let expected_instance = claim
            .daemon_instance_id()
            .ok_or(AgentTaskStartRecoveryError::InvalidBoundMarker)?;
        let mut client =
            DaemonClient::connect_for_generation_mutation(socket_path, DEFAULT_TIMEOUT)?;
        let observed = client.conditional_start_peer_identity_before_current_deadline()?;
        if observed.daemon_instance_id() != expected_instance
            || observed.server_pid() != claim.server_pid()
        {
            client.abort_connection();
            return Err(AgentTaskStartRecoveryError::PeerChanged);
        }
        Ok(client)
    }

    fn finish_unapplied(
        &self,
        journal: &AgentTaskStartJournalService<'_>,
        claim: &ClaimedAgentTaskStart,
        proof: &ProvenUnappliedAgentTaskStart,
    ) -> Result<AgentTaskStartRecoveryOutcome, AgentTaskStartRecoveryError> {
        match journal.compensate_proven_unapplied(claim, proof)? {
            AgentTaskStartCompensationOutcome::Compensated => {
                Ok(AgentTaskStartRecoveryOutcome::Compensated)
            }
            AgentTaskStartCompensationOutcome::GraphChanged => {
                match journal.delete_changed_finalize_after_proven_unapplied(claim, proof)? {
                    AgentTaskStartChangedUnappliedDeleteOutcome::Deleted
                    | AgentTaskStartChangedUnappliedDeleteOutcome::AlreadyDeleted => {
                        Ok(AgentTaskStartRecoveryOutcome::ChangedJournalDeleted)
                    }
                    AgentTaskStartChangedUnappliedDeleteOutcome::ClaimLost => {
                        Ok(AgentTaskStartRecoveryOutcome::ClaimLost)
                    }
                    AgentTaskStartChangedUnappliedDeleteOutcome::ProofMismatch
                    | AgentTaskStartChangedUnappliedDeleteOutcome::NotFinalize
                    | AgentTaskStartChangedUnappliedDeleteOutcome::Applied
                    | AgentTaskStartChangedUnappliedDeleteOutcome::GraphStillExact => {
                        Ok(AgentTaskStartRecoveryOutcome::Deferred)
                    }
                }
            }
            AgentTaskStartCompensationOutcome::ClaimLost => {
                Ok(AgentTaskStartRecoveryOutcome::ClaimLost)
            }
            AgentTaskStartCompensationOutcome::ProofMismatch
            | AgentTaskStartCompensationOutcome::NotUnapplied => {
                Ok(AgentTaskStartRecoveryOutcome::Deferred)
            }
        }
    }

    fn recover_durably_applied(
        &self,
        journal: &AgentTaskStartJournalService<'_>,
        claim: &mut ClaimedAgentTaskStart,
        authority: &ConditionalStartRecoveryAuthority,
        operation_token: maestro_protocol::SessionStartOperationToken,
        daemon_instance_id: maestro_protocol::DaemonInstanceId,
        status: SessionStartOperationStatus,
    ) -> Result<AgentTaskStartRecoveryOutcome, AgentTaskStartRecoveryError> {
        let Some(generation) = claim.applied_generation().map(str::to_string) else {
            return Err(AgentTaskStartRecoveryError::InvalidBoundMarker);
        };
        let Some(current_state) = claim.applied_state() else {
            return Err(AgentTaskStartRecoveryError::InvalidBoundMarker);
        };
        let state = match status {
            SessionStartOperationStatus::Applied {
                generation: observed,
                lifecycle,
            } if observed == generation => match lifecycle {
                SessionStartOperationLifecycle::Live => current_state,
                SessionStartOperationLifecycle::Exited => AppliedAgentTaskStartState::Exited,
                SessionStartOperationLifecycle::Removed => AppliedAgentTaskStartState::Removed,
            },
            // A prior exact retirement may have won after persisting the Grid/lifecycle proof.
            SessionStartOperationStatus::Unknown => current_state,
            SessionStartOperationStatus::Applied { .. }
            | SessionStartOperationStatus::Reserved
            | SessionStartOperationStatus::Refused => {
                return Ok(AgentTaskStartRecoveryOutcome::Deferred)
            }
        };
        if !matches!(
            journal.mark_claimed_applied(claim, &generation, state)?,
            AgentTaskStartAppliedMarkOutcome::Marked
        ) {
            return Ok(AgentTaskStartRecoveryOutcome::ClaimLost);
        }
        self.publish_or_cleanup_applied(
            journal,
            claim,
            authority,
            operation_token,
            daemon_instance_id,
            &generation,
        )
    }

    fn observe_and_publish_applied(
        &self,
        journal: &AgentTaskStartJournalService<'_>,
        claim: &mut ClaimedAgentTaskStart,
        authority: &ConditionalStartRecoveryAuthority,
        operation_token: maestro_protocol::SessionStartOperationToken,
        daemon_instance_id: maestro_protocol::DaemonInstanceId,
        status: SessionStartOperationStatus,
    ) -> Result<AgentTaskStartRecoveryOutcome, AgentTaskStartRecoveryError> {
        let (generation, state) = match status {
            SessionStartOperationStatus::Applied {
                generation: _,
                lifecycle: SessionStartOperationLifecycle::Live,
            } => match authority.recover_with_exact_grid()? {
                ConditionalStartGridRecovery::GridProven {
                    attached,
                    lifecycle_at_lookup,
                } => {
                    let state = match lifecycle_at_lookup {
                        SessionStartOperationLifecycle::Live => AppliedAgentTaskStartState::Live,
                        SessionStartOperationLifecycle::Exited => {
                            AppliedAgentTaskStartState::Exited
                        }
                        SessionStartOperationLifecycle::Removed => {
                            AppliedAgentTaskStartState::Removed
                        }
                    };
                    (attached.generation, state)
                }
                ConditionalStartGridRecovery::OperationStatus(
                    SessionStartOperationStatus::Applied {
                        generation,
                        lifecycle: SessionStartOperationLifecycle::Exited,
                    },
                ) => (generation, AppliedAgentTaskStartState::Exited),
                ConditionalStartGridRecovery::OperationStatus(
                    SessionStartOperationStatus::Applied {
                        generation,
                        lifecycle: SessionStartOperationLifecycle::Removed,
                    },
                ) => (generation, AppliedAgentTaskStartState::Removed),
                ConditionalStartGridRecovery::OperationStatus(_) => {
                    return Ok(AgentTaskStartRecoveryOutcome::Deferred)
                }
            },
            SessionStartOperationStatus::Applied {
                generation,
                lifecycle: SessionStartOperationLifecycle::Exited,
            } => (generation, AppliedAgentTaskStartState::Exited),
            SessionStartOperationStatus::Applied {
                generation,
                lifecycle: SessionStartOperationLifecycle::Removed,
            } => (generation, AppliedAgentTaskStartState::Removed),
            SessionStartOperationStatus::Unknown
            | SessionStartOperationStatus::Reserved
            | SessionStartOperationStatus::Refused => {
                return Ok(AgentTaskStartRecoveryOutcome::Deferred)
            }
        };
        match journal.mark_claimed_applied(claim, &generation, state)? {
            AgentTaskStartAppliedMarkOutcome::Marked => {}
            AgentTaskStartAppliedMarkOutcome::ClaimLost => {
                return Ok(AgentTaskStartRecoveryOutcome::ClaimLost)
            }
            AgentTaskStartAppliedMarkOutcome::NotBound
            | AgentTaskStartAppliedMarkOutcome::InvalidGeneration
            | AgentTaskStartAppliedMarkOutcome::GenerationMismatch
            | AgentTaskStartAppliedMarkOutcome::ReverseTransition => {
                return Ok(AgentTaskStartRecoveryOutcome::Deferred)
            }
        }
        self.publish_or_cleanup_applied(
            journal,
            claim,
            authority,
            operation_token,
            daemon_instance_id,
            &generation,
        )
    }

    fn publish_or_cleanup_applied(
        &self,
        journal: &AgentTaskStartJournalService<'_>,
        claim: &mut ClaimedAgentTaskStart,
        authority: &ConditionalStartRecoveryAuthority,
        operation_token: maestro_protocol::SessionStartOperationToken,
        daemon_instance_id: maestro_protocol::DaemonInstanceId,
        generation: &str,
    ) -> Result<AgentTaskStartRecoveryOutcome, AgentTaskStartRecoveryError> {
        match journal.classify_claimed(claim)? {
            ClaimedAgentTaskStartGraph::ClaimLost => {
                return Ok(AgentTaskStartRecoveryOutcome::ClaimLost)
            }
            ClaimedAgentTaskStartGraph::Changed => {
                return self.cleanup_changed_applied(
                    journal,
                    claim,
                    authority,
                    operation_token,
                    daemon_instance_id,
                    generation,
                )
            }
            ClaimedAgentTaskStartGraph::ExactPreparedA => {}
        }

        let publication = journal.publish_applied(claim)?;
        let published = match publication {
            AgentTaskStartPublicationOutcome::PublishedLive => {
                AgentTaskStartRecoveryOutcome::PublishedLive
            }
            AgentTaskStartPublicationOutcome::PublishedExited => {
                AgentTaskStartRecoveryOutcome::PublishedExited
            }
            AgentTaskStartPublicationOutcome::GraphChanged => {
                return self.cleanup_changed_applied(
                    journal,
                    claim,
                    authority,
                    operation_token,
                    daemon_instance_id,
                    generation,
                )
            }
            AgentTaskStartPublicationOutcome::ClaimLost => {
                return Ok(AgentTaskStartRecoveryOutcome::ClaimLost)
            }
            AgentTaskStartPublicationOutcome::NotPublishable => {
                return Ok(AgentTaskStartRecoveryOutcome::Deferred)
            }
        };

        match self.retire_and_delete_release(
            journal,
            claim,
            authority,
            operation_token,
            daemon_instance_id,
            generation,
        )? {
            AgentTaskStartRecoveryOutcome::ReleaseDeleted => Ok(published),
            other => Ok(other),
        }
    }

    fn retire_and_delete_release(
        &self,
        journal: &AgentTaskStartJournalService<'_>,
        claim: &ClaimedAgentTaskStart,
        authority: &ConditionalStartRecoveryAuthority,
        operation_token: maestro_protocol::SessionStartOperationToken,
        daemon_instance_id: maestro_protocol::DaemonInstanceId,
        generation: &str,
    ) -> Result<AgentTaskStartRecoveryOutcome, AgentTaskStartRecoveryError> {
        match authority.retire_applied_operation(generation)? {
            SessionStartOperationRetireOutcome::Retired
            | SessionStartOperationRetireOutcome::AlreadyRetired => {
                let proof = RetiredAgentTaskStartOperation::confirmed(
                    operation_token,
                    daemon_instance_id,
                    generation,
                );
                match journal.delete_release_after_operation_retired(claim, &proof)? {
                    AgentTaskStartReleaseDeleteOutcome::Deleted => {
                        Ok(AgentTaskStartRecoveryOutcome::ReleaseDeleted)
                    }
                    AgentTaskStartReleaseDeleteOutcome::ClaimLost => {
                        Ok(AgentTaskStartRecoveryOutcome::ClaimLost)
                    }
                    AgentTaskStartReleaseDeleteOutcome::ProofMismatch
                    | AgentTaskStartReleaseDeleteOutcome::NotRelease => {
                        Ok(AgentTaskStartRecoveryOutcome::Deferred)
                    }
                }
            }
            SessionStartOperationRetireOutcome::Conflict { .. } => {
                Ok(AgentTaskStartRecoveryOutcome::Deferred)
            }
        }
    }

    fn cleanup_changed_applied(
        &self,
        journal: &AgentTaskStartJournalService<'_>,
        claim: &mut ClaimedAgentTaskStart,
        authority: &ConditionalStartRecoveryAuthority,
        operation_token: maestro_protocol::SessionStartOperationToken,
        daemon_instance_id: maestro_protocol::DaemonInstanceId,
        generation: &str,
    ) -> Result<AgentTaskStartRecoveryOutcome, AgentTaskStartRecoveryError> {
        let mut cleanup_client = self.connect_exact_peer(claim)?;
        cleanup_client.release_session_lifetime_with_publication(
            SessionId(claim.session_id().to_string()),
            generation,
        )?;
        match journal.mark_claimed_applied(
            claim,
            generation,
            AppliedAgentTaskStartState::Removed,
        )? {
            AgentTaskStartAppliedMarkOutcome::Marked => {}
            AgentTaskStartAppliedMarkOutcome::ClaimLost => {
                return Ok(AgentTaskStartRecoveryOutcome::ClaimLost)
            }
            AgentTaskStartAppliedMarkOutcome::NotBound
            | AgentTaskStartAppliedMarkOutcome::InvalidGeneration
            | AgentTaskStartAppliedMarkOutcome::GenerationMismatch
            | AgentTaskStartAppliedMarkOutcome::ReverseTransition => {
                return Ok(AgentTaskStartRecoveryOutcome::Deferred)
            }
        }
        match authority.retire_applied_operation(generation)? {
            SessionStartOperationRetireOutcome::Retired
            | SessionStartOperationRetireOutcome::AlreadyRetired => {
                let proof = CleanedAndRetiredAgentTaskStartOperation::confirmed(
                    operation_token,
                    daemon_instance_id,
                    generation,
                );
                match journal.delete_changed_finalize_after_cleanup_and_retirement(claim, &proof)? {
                    AgentTaskStartChangedCleanupDeleteOutcome::Deleted
                    | AgentTaskStartChangedCleanupDeleteOutcome::AlreadyDeleted => {
                        Ok(AgentTaskStartRecoveryOutcome::ChangedJournalDeleted)
                    }
                    AgentTaskStartChangedCleanupDeleteOutcome::ClaimLost => {
                        Ok(AgentTaskStartRecoveryOutcome::ClaimLost)
                    }
                    AgentTaskStartChangedCleanupDeleteOutcome::ProofMismatch
                    | AgentTaskStartChangedCleanupDeleteOutcome::NotFinalize
                    | AgentTaskStartChangedCleanupDeleteOutcome::Unapplied
                    | AgentTaskStartChangedCleanupDeleteOutcome::NotRemoved
                    | AgentTaskStartChangedCleanupDeleteOutcome::GraphStillExact => {
                        Ok(AgentTaskStartRecoveryOutcome::Deferred)
                    }
                }
            }
            SessionStartOperationRetireOutcome::Conflict { .. } => {
                Ok(AgentTaskStartRecoveryOutcome::Deferred)
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::agent_task_runtime::AgentTaskRuntime;
    use crate::policy::WorkspacePolicy;
    use crate::records::{
        AgentTask, AgentTaskState, Project, ProjectLaunchDefaults, SessionKind, SessionRecord,
        Workspace, WorkspaceConsent,
    };
    use crate::store::{load_one, write_record, LoadOutcome};
    use crate::workspace_exec::PreparedWorkspace;
    use crate::RecordKind;

    struct Fixture {
        _temp: tempfile::TempDir,
        paths: AppPaths,
        task_id: String,
        session_id: String,
    }

    fn prepared_unbound(suffix: &str) -> Fixture {
        let temp = tempfile::tempdir().unwrap();
        let paths = AppPaths::with_base(temp.path().join("Maestro"));
        let cwd = temp.path().join("cwd");
        std::fs::create_dir_all(&cwd).unwrap();
        let project_id = format!("recovery-project-{suffix}");
        let workspace_id = format!("recovery-workspace-{suffix}");
        let task_id = format!("recovery-task-{suffix}");
        let session_id = format!("recovery-session-{suffix}");
        let project = Project {
            project_id: project_id.clone(),
            name: "Recovery project".into(),
            root: cwd.to_string_lossy().into_owned(),
            default_workspace_policy: WorkspacePolicy::ScratchCwd,
            created_at_ms: 1,
            last_active_at_ms: 1,
            icon: None,
            accent_color: None,
            launch_defaults: Some(ProjectLaunchDefaults::default()),
            directories: Vec::new(),
            window_order: Vec::new(),
            system: false,
            hidden: false,
        };
        let workspace = Workspace {
            workspace_id: workspace_id.clone(),
            project_id: project_id.clone(),
            root: cwd.to_string_lossy().into_owned(),
            policy: WorkspacePolicy::ScratchCwd,
            consent: WorkspaceConsent::default(),
        };
        write_record(&paths, RecordKind::Project, &project_id, 1, &project).unwrap();
        write_record(&paths, RecordKind::Workspace, &workspace_id, 1, &workspace).unwrap();
        let prepared_workspace = PreparedWorkspace::unsealed(
            WorkspacePolicy::ScratchCwd,
            workspace_id,
            session_id.clone(),
            cwd,
        );
        let spec = prepared_workspace
            .adhoc_session_spec(
                SessionKind::Agent,
                &["sh".into(), "-c".into(), "exit 0".into()],
                80,
                24,
                2,
            )
            .unwrap();
        let start = AgentTaskRuntime::new(&paths)
            .prepare_new_agent_task_unplaced(
                &project,
                &workspace,
                &task_id,
                "private goal",
                2,
                spec,
            )
            .unwrap();
        drop(start);
        let connection = crate::db::conn_for(paths.base()).unwrap();
        connection
            .lock()
            .unwrap()
            .execute(
                "UPDATE pending_agent_task_starts SET lease_until_ms = 0 \
                 WHERE session_id = ?1",
                [&session_id],
            )
            .unwrap();
        Fixture {
            _temp: temp,
            paths,
            task_id,
            session_id,
        }
    }

    fn pending_count(paths: &AppPaths) -> i64 {
        crate::db::conn_for(paths.base())
            .unwrap()
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM pending_agent_task_starts",
                [],
                |row| row.get(0),
            )
            .unwrap()
    }

    #[test]
    fn unbound_expired_marker_compensates_unknown_session_and_preserves_draft() {
        let fixture = prepared_unbound("compensate");
        assert_eq!(
            AgentTaskStartRecoveryService::new(&fixture.paths)
                .recover_next()
                .unwrap(),
            AgentTaskStartRecoveryOutcome::Compensated
        );
        assert_eq!(pending_count(&fixture.paths), 0);
        assert!(load_one::<SessionRecord>(
            &fixture.paths,
            RecordKind::Session,
            &fixture.session_id,
        )
        .unwrap()
        .is_none());
        let task =
            load_one::<AgentTask>(&fixture.paths, RecordKind::AgentTask, &fixture.task_id).unwrap();
        assert!(matches!(
            task,
            Some(LoadOutcome::Loaded(AgentTask {
                state: AgentTaskState::Draft,
                current_session_id: None,
                ..
            }))
        ));
        crate::db::forget_cached(fixture.paths.base());
    }

    #[test]
    fn unbound_changed_graph_deletes_only_journal_and_preserves_product_bytes() {
        let fixture = prepared_unbound("changed");
        let mut task =
            match load_one::<AgentTask>(&fixture.paths, RecordKind::AgentTask, &fixture.task_id)
                .unwrap()
                .unwrap()
            {
                LoadOutcome::Loaded(task) => task,
                other => panic!("unexpected task load: {other:?}"),
            };
        task.goal = "concurrent product owner".into();
        write_record(
            &fixture.paths,
            RecordKind::AgentTask,
            &fixture.task_id,
            3,
            &task,
        )
        .unwrap();

        assert_eq!(
            AgentTaskStartRecoveryService::new(&fixture.paths)
                .recover_next()
                .unwrap(),
            AgentTaskStartRecoveryOutcome::ChangedJournalDeleted
        );
        assert_eq!(pending_count(&fixture.paths), 0);
        assert!(matches!(
            load_one::<AgentTask>(
                &fixture.paths,
                RecordKind::AgentTask,
                &fixture.task_id,
            )
            .unwrap(),
            Some(LoadOutcome::Loaded(ref current)) if current == &task
        ));
        assert!(matches!(
            load_one::<SessionRecord>(&fixture.paths, RecordKind::Session, &fixture.session_id,)
                .unwrap(),
            Some(LoadOutcome::Loaded(_))
        ));
        crate::db::forget_cached(fixture.paths.base());
    }
}
