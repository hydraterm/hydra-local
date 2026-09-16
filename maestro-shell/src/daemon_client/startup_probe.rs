//! Read-only startup probes share one caller-owned deadline without granting mutation authority.
use super::*;

struct StartupIdentity {
    protocol_version: u32,
    build_version: String,
    start_peer: Option<ConditionalStartPeerIdentity>,
}

impl DaemonClient {
    /// Connect within the caller's existing startup deadline. This does not start a daemon,
    /// create a socket or change the lifetime of any retained session.
    pub fn connect_before(
        socket_path: impl AsRef<Path>,
        deadline: Instant,
    ) -> Result<Self, DaemonClientError> {
        let remaining = deadline
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or(DaemonClientError::Timeout {
                during: "connecting for daemon startup probe",
            })?;
        let path = socket_path.as_ref();
        let stream = connect_platform_with_timeout(path, remaining)
            .map_err(|source| map_connect_error(path, source))?;
        if Instant::now() >= deadline {
            return Err(DaemonClientError::Timeout {
                during: "connecting for daemon startup probe",
            });
        }
        // A successful legacy probe may hand this connection to ordinary attach. Preserve its
        // existing idle timeout; only the startup probe temporarily shrinks it to the deadline.
        Self::from_connected_stream(path, stream, DEFAULT_TIMEOUT, None)
    }

    /// Read-only compatibility identity, including legacy versions, within one absolute deadline.
    pub fn daemon_info_before(
        &mut self,
        deadline: Instant,
    ) -> Result<(u32, String), DaemonClientError> {
        let identity = self.startup_identity_before(deadline)?;
        Ok((identity.protocol_version, identity.build_version))
    }

    /// The same strict readiness proof as `conditional_start_peer_identity`, without allowing
    /// its socket reads to acquire fresh time after the caller's startup deadline.
    pub fn conditional_start_peer_identity_before(
        &mut self,
        deadline: Instant,
    ) -> Result<ConditionalStartPeerIdentity, DaemonClientError> {
        let identity = self.startup_identity_before(deadline)?;
        #[cfg(windows)]
        if identity.start_peer.is_some() && !self.windows_start_operation_retirement_barrier {
            return Err(
                DaemonClientError::WindowsStartRetirementBarrierUnsupported {
                    observed: identity.protocol_version,
                },
            );
        }
        identity
            .start_peer
            .ok_or(DaemonClientError::MutationProtocolUnsupported {
                required: maestro_protocol::DAEMON_PROTOCOL_VERSION,
                observed: Some(identity.protocol_version),
            })
    }

    fn startup_identity_before(
        &mut self,
        deadline: Instant,
    ) -> Result<StartupIdentity, DaemonClientError> {
        // Reuse the existing shrinking-timeout framing implementation. This is not a mutation:
        // unrelated complete events consume time, never a new mutation/event-count allowance.
        let mut budget = self.generation_kill_budget()?;
        budget.deadline = self
            .operation_deadline
            .map_or(deadline, |existing| existing.min(deadline));
        let result = (|| {
            self.send_before(
                &ClientRequest::DaemonInfo,
                &budget,
                "writing daemon_info startup probe",
            )?;
            loop {
                match self.read_event_before(&budget, "reading daemon_info reply")? {
                    Some(ShellEvent::DaemonInfo {
                        protocol_version,
                        build_version,
                        daemon_instance_id,
                        output_generation_echo,
                        child_environment,
                        generation_conditional_mutations,
                        attachment_aware_conditional_kill,
                        generation_conditional_start,
                        start_operation_ledger,
                        generation_conditional_attach,
                        #[cfg(windows)]
                        windows_start_operation_retirement_barrier,
                    }) => {
                        #[cfg(windows)]
                        {
                            self.windows_start_operation_retirement_barrier =
                                windows_start_operation_retirement_barrier;
                        }
                        let instance = self.bind_daemon_instance_id(daemon_instance_id)?;
                        let start_peer = instance
                            .filter(|_| {
                                protocol_version == maestro_protocol::DAEMON_PROTOCOL_VERSION
                                    && output_generation_echo
                                    && generation_conditional_mutations
                                    && attachment_aware_conditional_kill
                                    && generation_conditional_start
                                    && start_operation_ledger
                                    && generation_conditional_attach
                            })
                            .map(|daemon_instance_id| ConditionalStartPeerIdentity {
                                daemon_instance_id,
                                server_pid: self.server_pid,
                                child_environment,
                            });
                        return Ok(StartupIdentity {
                            protocol_version,
                            build_version,
                            start_peer,
                        });
                    }
                    Some(ShellEvent::Error { message }) => {
                        return Err(DaemonClientError::DaemonError { message });
                    }
                    Some(_) => continue,
                    None => {
                        return Err(DaemonClientError::UnexpectedEof {
                            during: "reading daemon_info reply",
                        });
                    }
                }
            }
        })();
        if let Err(error) = self.restore_timeouts(&budget) {
            self.abort_connection();
            return Err(error);
        }
        // A complete daemon Error is the existing legacy compatibility response. Other failures
        // may leave a partial frame; close only this probe connection, never the retained daemon.
        if result
            .as_ref()
            .is_err_and(|error| !matches!(error, DaemonClientError::DaemonError { .. }))
        {
            self.abort_connection();
        }
        result
    }
}

#[cfg(all(test, unix))]
mod tests;
