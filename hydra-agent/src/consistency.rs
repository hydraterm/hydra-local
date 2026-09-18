//! Consistency runner — a periodic (~5s) self-heal + observability pass over the agent's stale-prone state.
//!
//! WHY: several pieces the agent depends on are loaded ONCE (at process start) but can change underneath it while it
//! runs, leaving it serving stale state until a full restart:
//!   - the DESKTOP DAEMON SOCKET: the desktop app republishes `endpoint.json` with a NEW socket every time it
//!     restarts. remote-peer bound to the OLD socket then talks to a dead daemon → the browser sees "0 sessions /
//!     no projects" (the concrete bug that motivated this runner).
//!   - the ENROLLMENT (device.json): add / revoke / re-add / "Remove Remote" all rewrite or delete it; a running
//!     remote-peer keeps the OLD identity.
//!   - presence: the heartbeat can go stale (network, or a break-on-revoke without re-arm).
//!
//! WHAT: each tick, `evaluate()` produces a content-blind `ConsistencyReport` (paths/socket-ids/ages/booleans only —
//! NEVER terminal bytes, keys, or tokens). The supervise loop applies the safe HEAL actions (restart remote-peer onto
//! the live socket / fresh identity) and appends the report to `consistency.jsonl` so sync problems are observable
//! live. This module is PURE (no process control, no I/O beyond reading the state files + appending the log) so it's
//! unit-testable; the loop owns the actual restarts.

use serde::Serialize;
use std::path::{Path, PathBuf};

/// How often the supervise loop runs a consistency pass.
pub const CONSISTENCY_INTERVAL: std::time::Duration = std::time::Duration::from_secs(5);

/// A heal action the supervise loop should take after a check. Ordered by the loop; at most one restart per tick.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case", tag = "action")]
pub enum Heal {
    /// remote-peer is bound to a stale/dead daemon socket → restart it against `live_socket`.
    RestartPeerForSocket { live_socket: String },
    /// The enrollment on disk changed (add/revoke/re-add) → restart remote-peer to reload its identity.
    RestartPeerForEnrollment,
    /// Nothing to do this tick (all consistent).
    None,
}

/// One check's result — content-blind (no terminal/key/token material). Serialized into consistency.jsonl.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Check {
    /// short stable id, e.g. "daemon_socket", "enrollment", "heartbeat".
    pub name: &'static str,
    /// true = consistent, false = a discrepancy was found (and a heal may be proposed).
    pub ok: bool,
    /// a short, non-sensitive human detail (socket basenames, ages in ms, "revoked", etc.).
    pub detail: String,
}

/// The full result of one consistency pass.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct ConsistencyReport {
    pub checks: Vec<Check>,
    /// the single heal the loop should apply (if any) this tick.
    pub heal: Heal,
}

impl ConsistencyReport {
    /// true when every check passed (no heal needed) — the loop can skip the log write on the quiet path if it wants.
    pub fn all_ok(&self) -> bool {
        self.heal == Heal::None && self.checks.iter().all(|c| c.ok)
    }
}

/// The inputs a pass reads (kept as an explicit struct so the pure `evaluate` is fully testable without touching the
/// filesystem). The supervise loop fills this from disk each tick.
pub struct ConsistencyInputs {
    /// the socket remote-peer is CURRENTLY bound to (what supervise launched it with).
    pub running_socket: String,
    /// the socket the desktop app currently publishes (endpoint.json), if any.
    pub live_socket: Option<String>,
    /// does the CURRENTLY-published socket accept a connection right now?
    pub live_socket_responds: bool,
    /// how many CONSECUTIVE consistency ticks the live socket has held this same value. Used to DEBOUNCE: we only
    /// migrate remote-peer onto a NEW socket once it has been stable for a few ticks, so a desktop rapidly cycling
    /// sockets (app restart storm) doesn't make us thrash-restart the peer and kill the browser session every tick.
    pub live_socket_stable_ticks: u32,
    /// device.json fingerprint the running remote-peer was started with vs. now (mtime_nanos, len). None = absent.
    pub enrollment_fp_at_start: Option<(u128, u64)>,
    pub enrollment_fp_now: Option<(u128, u64)>,
    /// age of the last successful heartbeat in ms (None = never / unknown). Used for a LOG-only staleness note.
    pub heartbeat_age_ms: Option<u64>,
    /// the heartbeat interval in ms (so "stale" = age > 3× interval).
    pub heartbeat_interval_ms: u64,
}

/// PURE evaluation: given the observed state, produce the report + at most one heal. Socket staleness takes priority
/// over enrollment (a dead socket makes everything else moot); enrollment next; heartbeat is LOG-only (never a
/// restart — presence lag must not bounce a healthy serving peer).
pub fn evaluate(inp: &ConsistencyInputs) -> ConsistencyReport {
    let mut checks = Vec::new();
    let mut heal = Heal::None;

    // 1. Daemon socket freshness: the desktop republishes endpoint.json on every restart. The peer is stale when the
    //    live socket differs from what it's bound to. BUT we only MIGRATE when the new socket is (a) actually
    //    RESPONDING and (b) has been STABLE for a few ticks — otherwise a desktop cycling sockets rapidly (restart
    //    storm) makes us thrash-restart the peer and kill the browser session every tick (the "Connecting… forever"
    //    bug this debounce fixes). A same-but-dead socket is reported but NOT auto-restarted (nothing better to move
    //    to; the desktop is mid-restart and will republish shortly).
    const MIN_STABLE_TICKS: u32 = 2; // ~10s at the 5s cadence — long enough to skip a restart storm.
    let socket_differs = matches!(&inp.live_socket, Some(live) if *live != inp.running_socket);
    let safe_to_migrate = socket_differs
        && inp.live_socket_responds
        && inp.live_socket_stable_ticks >= MIN_STABLE_TICKS;
    checks.push(Check {
        name: "daemon_socket",
        ok: !socket_differs, // consistent when we're bound to the current socket
        detail: match &inp.live_socket {
            Some(live) if *live != inp.running_socket => format!(
                "running={} live={} responds={} stable_ticks={} → {}",
                base(&inp.running_socket),
                base(live),
                inp.live_socket_responds,
                inp.live_socket_stable_ticks,
                if safe_to_migrate {
                    "migrating"
                } else {
                    "waiting for it to settle"
                }
            ),
            Some(_) if !inp.live_socket_responds => {
                format!(
                    "socket {} not responding (desktop mid-restart?)",
                    base(&inp.running_socket)
                )
            }
            Some(_) => format!("bound to live socket {}", base(&inp.running_socket)),
            None => "no published endpoint (using --sock fallback)".to_string(),
        },
    });
    if safe_to_migrate {
        if let Some(live) = &inp.live_socket {
            heal = Heal::RestartPeerForSocket {
                live_socket: live.clone(),
            };
        }
    }

    // 2. Enrollment identity: add/revoke/re-add rewrite device.json; the running peer holds the old identity.
    let enrollment_changed = inp.enrollment_fp_at_start != inp.enrollment_fp_now;
    checks.push(Check {
        name: "enrollment",
        ok: !enrollment_changed,
        detail: match (inp.enrollment_fp_at_start, inp.enrollment_fp_now) {
            (Some(_), None) => {
                "device.json REMOVED since start (revoke / remove remote)".to_string()
            }
            (None, Some(_)) => "device.json ADDED since start (enrolled)".to_string(),
            (a, b) if a != b => "device.json CHANGED since start (re-enroll)".to_string(),
            _ => "unchanged".to_string(),
        },
    });
    // Only escalate to an enrollment restart if the socket wasn't already forcing one this tick (one restart max).
    if enrollment_changed && heal == Heal::None {
        heal = Heal::RestartPeerForEnrollment;
    }

    // 3. Heartbeat liveness: LOG-only (never a restart). Stale = older than 3× the interval.
    if let Some(age) = inp.heartbeat_age_ms {
        let stale = age > inp.heartbeat_interval_ms.saturating_mul(3);
        checks.push(Check {
            name: "heartbeat",
            ok: !stale,
            detail: format!(
                "last ok {age}ms ago (interval {}ms)",
                inp.heartbeat_interval_ms
            ),
        });
    } else {
        checks.push(Check {
            name: "heartbeat",
            ok: true, // never-yet-heartbeat is not a discrepancy (unenrolled / just started)
            detail: "no heartbeat recorded yet".to_string(),
        });
    }

    ConsistencyReport { checks, heal }
}

/// Basename of a socket path for compact, non-sensitive logging (the full /var/folders/… path is noise).
fn base(p: &str) -> String {
    Path::new(p)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or(p)
        .to_string()
}

/// Append one report to `<agent_dir>/consistency.jsonl` with a caller-supplied timestamp (kept out of the pure
/// evaluate for testability). Best-effort — a log write failure must never affect the agent. Content-blind by
/// construction (the report holds only paths/ids/ages/booleans).
pub fn append_log(agent_dir: &Path, report: &ConsistencyReport, ts_ms: u64) {
    #[derive(Serialize)]
    struct Line<'a> {
        ts_ms: u64,
        checks: &'a [Check],
        heal: &'a Heal,
    }
    let line = Line {
        ts_ms,
        checks: &report.checks,
        heal: &report.heal,
    };
    if let Ok(mut s) = serde_json::to_string(&line) {
        s.push('\n');
        use std::io::Write as _;
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(consistency_log_path(agent_dir))
        {
            let _ = f.write_all(s.as_bytes());
        }
    }
}

pub fn consistency_log_path(agent_dir: &Path) -> PathBuf {
    agent_dir.join("consistency.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn inputs() -> ConsistencyInputs {
        ConsistencyInputs {
            running_socket: "/tmp/sock-A".into(),
            live_socket: Some("/tmp/sock-A".into()),
            live_socket_responds: true,
            live_socket_stable_ticks: 5, // stable by default; individual tests override to test the debounce
            enrollment_fp_at_start: Some((1, 10)),
            enrollment_fp_now: Some((1, 10)),
            heartbeat_age_ms: Some(1_000),
            heartbeat_interval_ms: 45_000,
        }
    }

    #[test]
    fn all_consistent_proposes_no_heal() {
        let r = evaluate(&inputs());
        assert!(r.all_ok());
        assert_eq!(r.heal, Heal::None);
    }

    #[test]
    fn stale_socket_after_desktop_restart_proposes_restart_onto_live_socket() {
        let mut inp = inputs();
        inp.live_socket = Some("/tmp/sock-B".into()); // desktop republished a NEW socket
        let r = evaluate(&inp);
        assert!(!r.all_ok());
        assert_eq!(
            r.heal,
            Heal::RestartPeerForSocket {
                live_socket: "/tmp/sock-B".into()
            }
        );
        assert!(r.checks.iter().any(|c| c.name == "daemon_socket" && !c.ok));
    }

    #[test]
    fn a_new_socket_that_has_not_settled_does_not_restart_yet() {
        let mut inp = inputs();
        inp.live_socket = Some("/tmp/sock-B".into());
        inp.live_socket_stable_ticks = 1; // just changed → wait for it to settle (debounce)
        let r = evaluate(&inp);
        assert_eq!(
            r.heal,
            Heal::None,
            "must not thrash-restart on a churning socket"
        );
        assert!(r
            .checks
            .iter()
            .any(|c| c.name == "daemon_socket" && c.detail.contains("settle")));
    }

    #[test]
    fn a_new_socket_that_does_not_respond_does_not_restart() {
        let mut inp = inputs();
        inp.live_socket = Some("/tmp/sock-B".into());
        inp.live_socket_responds = false; // published but dead → don't migrate onto a corpse
        let r = evaluate(&inp);
        assert_eq!(r.heal, Heal::None);
    }

    #[test]
    fn same_socket_that_stopped_responding_is_reported_but_not_restarted() {
        let mut inp = inputs();
        inp.live_socket_responds = false; // desktop mid-restart; nothing better to move to
        let r = evaluate(&inp);
        assert_eq!(
            r.heal,
            Heal::None,
            "no migration target → wait, don't thrash"
        );
    }

    #[test]
    fn no_published_endpoint_is_not_judged_stale() {
        let mut inp = inputs();
        inp.live_socket = None; // --sock fallback / no desktop app
        inp.live_socket_responds = false;
        let r = evaluate(&inp);
        assert_eq!(r.heal, Heal::None);
        assert!(r.checks.iter().any(|c| c.name == "daemon_socket" && c.ok));
    }

    #[test]
    fn enrollment_change_proposes_reload_restart() {
        let mut inp = inputs();
        inp.enrollment_fp_now = None; // device.json removed (revoke / remove remote)
        let r = evaluate(&inp);
        assert_eq!(r.heal, Heal::RestartPeerForEnrollment);
    }

    #[test]
    fn socket_staleness_takes_priority_over_enrollment_one_restart_per_tick() {
        let mut inp = inputs();
        inp.live_socket = Some("/tmp/sock-B".into());
        inp.enrollment_fp_now = None;
        let r = evaluate(&inp);
        // socket wins (a dead socket makes the identity moot); only ONE restart is proposed.
        assert!(matches!(r.heal, Heal::RestartPeerForSocket { .. }));
    }

    #[test]
    fn stale_heartbeat_is_logged_but_never_restarts() {
        let mut inp = inputs();
        inp.heartbeat_age_ms = Some(200_000); // > 3× 45s
        let r = evaluate(&inp);
        assert_eq!(r.heal, Heal::None); // heartbeat never triggers a restart
        assert!(r.checks.iter().any(|c| c.name == "heartbeat" && !c.ok));
    }
}
