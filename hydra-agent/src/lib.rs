//! hydra-agent library surface — exposes the agent's modules so both the binary and integration tests
//! can drive them. See `main.rs` for the CLI and `README.md` for the product trust
//! boundary.

/// The compile-time build stamp (git short SHA, `-dirty` if the tree had changes) captured by build.rs. Used in the
/// connect trace so browser↔agent version drift is visible in the log. "unknown" if git was unavailable at build.
pub fn build_git() -> &'static str {
    option_env!("HYDRA_BUILD_GIT").unwrap_or("unknown")
}

/// Build time (unix ms, as a string) captured by build.rs.
pub fn build_time_ms() -> &'static str {
    option_env!("HYDRA_BUILD_TIME").unwrap_or("0")
}

/// A compact one-line build stamp for logs/CLI, e.g. "git=37698b8 built=1783120000000".
pub fn build_stamp() -> String {
    format!("git={} built={}", build_git(), build_time_ms())
}

pub mod agent_dir;
pub mod authority_migration;
pub mod browser_cert;
pub mod browser_pop;
pub mod conn_trace;
pub mod consistency;
pub mod device_identity;
pub mod device_request_auth;
pub mod enrollment_migration;
pub mod extension;
pub mod headless;
pub mod health;
pub mod heartbeat;
pub mod heartbeat_status;
pub mod input_rate;
pub mod launchd;
pub mod lifecycle_cleanup;
pub mod release_trust;
pub mod remote_access;
pub mod remote_bridge;
pub mod remote_control;
pub mod remote_daemon_backend;
pub mod remote_frame;
#[cfg(feature = "webrtc")]
pub mod remote_peer;
pub mod remote_policy;
pub mod remote_signaling;
pub mod remote_token;
pub mod remote_webrtc;
pub mod resume_launch;
pub mod revocation;
pub mod seen_set;
pub mod service;
pub mod service_readiness;
pub mod session_creator;
#[cfg(feature = "webrtc")]
mod setup_deadline;
pub mod supervise;
pub mod systemd;
pub mod viewport_control;
pub mod winsize_owner;
