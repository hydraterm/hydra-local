//! Content-blind health surface for the persistent agent path. `assess` is a PURE function over a small set of
//! booleans (enrolled? key present? daemon socket up? supervise running? its remote-peer child up? launchd plist
//! present?) → a structured verdict + human lines. It NEVER reads or emits the device key, account/device ids,
//! cookies, tokens, signaling/SDP/ICE, or PTY output — only presence/up facts. The I/O that gathers the facts is
//! a thin, separately-tested layer (`gather`); the decision logic here is the part worth pinning with tests.

/// Content-blind facts an operator can observe without touching any secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HealthFacts {
    /// `device.json` exists (this Mac has an enrolled identity).
    pub enrolled: bool,
    /// `device-key` exists (the signing key is present alongside the record).
    pub key_present: bool,
    /// the pty-daemon unix socket exists and answers a content-blind list probe.
    pub socket_present: bool,
    /// a `hydra-agent supervise` process is running (the launchd-service runner).
    pub supervise_running: bool,
    /// a `hydra-agent remote-peer` process is running (supervise's child, or a standalone one).
    pub remote_peer_running: bool,
    /// a launchd plist for the service exists (the persistent install is configured).
    pub plist_present: bool,
    /// the last persisted heartbeat record (content-blind), or None if the agent hasn't heartbeat yet.
    pub heartbeat: Option<crate::heartbeat_status::HeartbeatStatus>,
    /// current unix-ms, for assessing heartbeat freshness (passed in so `assess` stays pure).
    pub now_ms: u64,
}

/// Per-check status. `Warn` = degraded but not necessarily fatal; `Bad` = a blocker for the remote path.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Level {
    Ok,
    Warn,
    Bad,
}

/// Overall verdict for the remote path: can the browser reach a session right now?
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// enrolled + daemon socket up + an agent (supervise/remote-peer) connecting presence.
    Healthy,
    /// reachable-ish but degraded (e.g. supervise up but its child not yet connected).
    Degraded,
    /// a blocker (not enrolled, or the daemon socket is down).
    NotReady,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Check {
    pub level: Level,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HealthReport {
    pub verdict: Verdict,
    pub checks: Vec<Check>,
}

/// The PURE decision logic. Same facts in → same report out; no I/O, no secrets.
pub fn assess(f: &HealthFacts) -> HealthReport {
    let mut checks = Vec::new();
    let ck = |level: Level, message: &str| Check {
        level,
        message: message.to_string(),
    };

    // identity — a hard prerequisite for the remote path.
    if f.enrolled && f.key_present {
        checks.push(ck(
            Level::Ok,
            "enrolled identity present (device record + signing key)",
        ));
    } else if f.enrolled && !f.key_present {
        checks.push(ck(
            Level::Bad,
            "device record present but signing key MISSING — re-enroll",
        ));
    } else {
        checks.push(ck(
            Level::Bad,
            "not enrolled (no device record) — run Add Desktop + enroll",
        ));
    }

    // daemon socket — the local terminal source the browser ultimately reaches.
    checks.push(if f.socket_present {
        ck(Level::Ok, "pty-daemon socket reachable")
    } else {
        ck(
            Level::Bad,
            "pty-daemon socket not reachable — the daemon is not running",
        )
    });

    // the agent process that maintains presence + the remote data path.
    match (f.supervise_running, f.remote_peer_running) {
        (true, true) => checks.push(ck(
            Level::Ok,
            "supervise running with a live remote-peer child",
        )),
        (true, false) => checks.push(ck(
            Level::Warn,
            "supervise running but no remote-peer child yet (starting or crash-looping)",
        )),
        (false, true) => checks.push(ck(
            Level::Ok,
            "standalone remote-peer running (presence will update)",
        )),
        (false, false) => checks.push(ck(
            Level::Bad,
            "no supervise or remote-peer process — presence won't update",
        )),
    }

    // persistent install — informational; the smoke/manual path works without it.
    checks.push(if f.plist_present {
        ck(
            Level::Ok,
            "service mode: persistent launchd install configured",
        )
    } else {
        ck(
            Level::Warn,
            "service mode: manual smoke / not installed persistently",
        )
    });

    // cloud reachability — the only signal that the agent is ACTUALLY talking to the cloud (not just that the
    // processes/socket exist). A fresh ok heartbeat = presence is updating; stale/refused/none = it may not be.
    const HEARTBEAT_FRESH_MS: u64 = 120_000; // 2 min — generous vs the ~30s cadence (a single miss isn't a fail).
    let heartbeat_ok = match &f.heartbeat {
        Some(hb) => {
            let line = crate::heartbeat_status::render_line(hb, f.now_ms);
            let fresh = crate::heartbeat_status::is_fresh(hb, f.now_ms, HEARTBEAT_FRESH_MS);
            checks.push(ck(if fresh { Level::Ok } else { Level::Warn }, &line));
            fresh
        }
        None => {
            checks.push(ck(
                Level::Warn,
                "last heartbeat: none recorded yet (agent may be starting)",
            ));
            false
        }
    };

    // verdict: hard blockers first, then degraded. A running agent with no fresh cloud heartbeat is Degraded —
    // it's locally up but presence may not be reaching the hosted app.
    let identity_ok = f.enrolled && f.key_present;
    let agent_running = f.supervise_running || f.remote_peer_running;
    let verdict = if !identity_ok || !f.socket_present || !agent_running {
        Verdict::NotReady
    } else if (f.supervise_running && !f.remote_peer_running) || !heartbeat_ok {
        Verdict::Degraded
    } else {
        Verdict::Healthy
    };

    HealthReport { verdict, checks }
}

/// Render the report as content-blind lines (a leading verdict + one line per check). No secrets by construction.
pub fn render(r: &HealthReport) -> String {
    let verdict = match r.verdict {
        Verdict::Healthy => "HEALTHY — the remote path is ready",
        Verdict::Degraded => "DEGRADED — reachable but not fully connected",
        Verdict::NotReady => "NOT READY — a blocker prevents the remote path",
    };
    let mut out = format!("hydra-agent health: {verdict}\n");
    for c in &r.checks {
        let tag = match c.level {
            Level::Ok => "ok",
            Level::Warn => "warn",
            Level::Bad => "BAD",
        };
        out.push_str(&format!("  [{tag}] {}\n", c.message));
    }
    out
}

/// Thin I/O layer: observe the content-blind facts. Separated from `assess` so the decision logic stays pure +
/// fully testable. `proc_matches(pat)` is injected so process detection can be faked in tests.
pub fn gather(
    dir: &std::path::Path,
    socket_path: &std::path::Path,
    plist_present: bool,
    now_ms: u64,
    proc_matches: impl Fn(&str) -> bool,
) -> HealthFacts {
    let socket_pattern = regex_escape(&socket_path.to_string_lossy());
    HealthFacts {
        enrolled: crate::device_identity::record_path(dir).exists(),
        key_present: dir.join("device-key").exists(),
        socket_present: daemon_responds(socket_path),
        supervise_running: proc_matches(&format!(
            r"(^|/)hydra-agent supervise .*--sock {socket_pattern}( |$)"
        )),
        remote_peer_running: proc_matches(&format!(
            r"(^|/)hydra-agent remote-peer .*--sock {socket_pattern}( |$)"
        )),
        plist_present,
        heartbeat: crate::heartbeat_status::load(dir),
        now_ms,
    }
}

fn regex_escape(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for ch in s.chars() {
        match ch {
            '.' | '+' | '*' | '?' | '^' | '$' | '(' | ')' | '[' | ']' | '{' | '}' | '|' | '\\' => {
                out.push('\\');
                out.push(ch);
            }
            _ => out.push(ch),
        }
    }
    out
}

fn daemon_responds(socket_path: &std::path::Path) -> bool {
    use std::io::{Read, Write};
    use std::os::unix::net::UnixStream;
    use std::time::Duration;

    let Ok(mut stream) = UnixStream::connect(socket_path) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(Duration::from_millis(500)));
    if stream.write_all(b"{\"op\":\"list_sessions\"}\n").is_err() {
        return false;
    }
    let mut buf = [0u8; 64];
    matches!(stream.read(&mut buf), Ok(n) if n > 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::heartbeat_status::{HeartbeatStatus, Outcome};

    const NOW: u64 = 1_700_000_000_000;

    fn facts() -> HealthFacts {
        HealthFacts {
            enrolled: true,
            key_present: true,
            socket_present: true,
            supervise_running: true,
            remote_peer_running: true,
            plist_present: true,
            // a fresh ok heartbeat (10s old) so the all-up fixture is Healthy.
            heartbeat: Some(HeartbeatStatus {
                outcome: Outcome::Ok,
                status_code: Some(200),
                ts_ms: NOW - 10_000,
            }),
            now_ms: NOW,
        }
    }

    #[test]
    fn fully_up_is_healthy() {
        let r = assess(&facts());
        assert_eq!(r.verdict, Verdict::Healthy);
        assert!(r.checks.iter().all(|c| c.level == Level::Ok));
    }

    #[test]
    fn not_enrolled_is_not_ready_and_flagged_bad() {
        let r = assess(&HealthFacts {
            enrolled: false,
            key_present: false,
            ..facts()
        });
        assert_eq!(r.verdict, Verdict::NotReady);
        assert!(r
            .checks
            .iter()
            .any(|c| c.level == Level::Bad && c.message.contains("not enrolled")));
    }

    #[test]
    fn record_without_key_is_a_blocker() {
        let r = assess(&HealthFacts {
            enrolled: true,
            key_present: false,
            ..facts()
        });
        assert_eq!(r.verdict, Verdict::NotReady);
        assert!(r
            .checks
            .iter()
            .any(|c| c.level == Level::Bad && c.message.contains("signing key MISSING")));
    }

    #[test]
    fn missing_socket_is_not_ready() {
        let r = assess(&HealthFacts {
            socket_present: false,
            ..facts()
        });
        assert_eq!(r.verdict, Verdict::NotReady);
        assert!(r
            .checks
            .iter()
            .any(|c| c.level == Level::Bad && c.message.contains("socket not reachable")));
    }

    #[test]
    fn supervise_without_child_is_degraded_not_fatal() {
        let r = assess(&HealthFacts {
            supervise_running: true,
            remote_peer_running: false,
            ..facts()
        });
        assert_eq!(r.verdict, Verdict::Degraded);
        assert!(r
            .checks
            .iter()
            .any(|c| c.level == Level::Warn && c.message.contains("no remote-peer child")));
    }

    #[test]
    fn standalone_remote_peer_is_healthy() {
        let r = assess(&HealthFacts {
            supervise_running: false,
            remote_peer_running: true,
            ..facts()
        });
        assert_eq!(r.verdict, Verdict::Healthy);
    }

    #[test]
    fn no_agent_process_is_not_ready() {
        let r = assess(&HealthFacts {
            supervise_running: false,
            remote_peer_running: false,
            ..facts()
        });
        assert_eq!(r.verdict, Verdict::NotReady);
    }

    #[test]
    fn no_plist_is_only_a_warning_not_a_blocker() {
        let r = assess(&HealthFacts {
            plist_present: false,
            ..facts()
        });
        assert_eq!(r.verdict, Verdict::Healthy); // running manually is fine
        assert!(r.checks.iter().any(|c| c.level == Level::Warn
            && c.message
                .contains("manual smoke / not installed persistently")));
    }

    #[test]
    fn plist_present_reports_persistent_service_mode() {
        let r = assess(&facts());
        assert!(r
            .checks
            .iter()
            .any(|c| c.level == Level::Ok
                && c.message.contains("persistent launchd install configured")));
    }

    #[test]
    fn render_is_content_blind_status_and_verdict_only() {
        // every documented failure-or-success message must be free of secret-shaped material.
        for f in [
            facts(),
            HealthFacts {
                enrolled: false,
                key_present: false,
                ..facts()
            },
            HealthFacts {
                socket_present: false,
                ..facts()
            },
            HealthFacts {
                supervise_running: true,
                remote_peer_running: false,
                ..facts()
            },
            HealthFacts {
                supervise_running: false,
                remote_peer_running: false,
                plist_present: false,
                ..facts()
            },
        ] {
            let out = render(&assess(&f));
            // no JWT/base64-key/cookie/account/device-id shapes leak.
            assert!(!out.contains("eyJ"), "{out}");
            assert!(!out.to_lowercase().contains("token"), "{out}");
            assert!(!out.to_lowercase().contains("cookie"), "{out}");
            assert!(!out.contains("acct_"), "{out}");
            assert!(!out.contains("dev_"), "{out}"); // device ids
            assert!(out.starts_with("hydra-agent health:"), "{out}");
        }
    }

    #[test]
    fn gather_reports_presence_facts_from_a_temp_dir() {
        let dir = std::env::temp_dir().join(format!("hydra-health-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        // not enrolled yet
        let f = gather(&dir, &dir.join("nope.sock"), false, NOW, |_| false);
        assert!(
            !f.enrolled
                && !f.key_present
                && !f.socket_present
                && !f.supervise_running
                && !f.plist_present
                && f.heartbeat.is_none()
        );
        // enroll: write a record + key, and fake the supervise process match
        std::fs::write(crate::device_identity::record_path(&dir), b"{}").unwrap();
        std::fs::write(dir.join("device-key"), b"x").unwrap();
        let f2 = gather(&dir, &dir.join("nope.sock"), true, NOW, |pat| {
            pat.contains("supervise")
        });
        assert!(
            f2.enrolled
                && f2.key_present
                && f2.supervise_running
                && !f2.remote_peer_running
                && f2.plist_present
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_or_missing_heartbeat_makes_a_running_agent_degraded() {
        // all processes up, but the last ok heartbeat is 5 min old → presence may be stale → Degraded.
        let stale = HeartbeatStatus {
            outcome: Outcome::Ok,
            status_code: Some(200),
            ts_ms: NOW - 300_000,
        };
        let r = assess(&HealthFacts {
            heartbeat: Some(stale),
            ..facts()
        });
        assert_eq!(r.verdict, Verdict::Degraded);
        assert!(r
            .checks
            .iter()
            .any(|c| c.level == Level::Warn && c.message.contains("last heartbeat")));

        // no heartbeat recorded yet → also Degraded (not a hard blocker; the agent may be starting).
        let r2 = assess(&HealthFacts {
            heartbeat: None,
            ..facts()
        });
        assert_eq!(r2.verdict, Verdict::Degraded);
        assert!(r2
            .checks
            .iter()
            .any(|c| c.message.contains("none recorded yet")));
    }

    #[test]
    fn a_refused_heartbeat_is_degraded_even_if_recent() {
        let refused = HeartbeatStatus {
            outcome: Outcome::Refused,
            status_code: Some(403),
            ts_ms: NOW - 5_000,
        };
        let r = assess(&HealthFacts {
            heartbeat: Some(refused),
            ..facts()
        });
        assert_eq!(r.verdict, Verdict::Degraded);
        assert!(r.checks.iter().any(|c| c.message.contains("REFUSED")));
    }

    #[test]
    fn heartbeat_check_is_content_blind() {
        for hb in [
            Some(HeartbeatStatus {
                outcome: Outcome::Ok,
                status_code: Some(200),
                ts_ms: NOW - 5_000,
            }),
            Some(HeartbeatStatus {
                outcome: Outcome::Refused,
                status_code: Some(403),
                ts_ms: NOW - 5_000,
            }),
            Some(HeartbeatStatus {
                outcome: Outcome::SendFailed,
                status_code: None,
                ts_ms: NOW - 5_000,
            }),
            None,
        ] {
            let out = render(&assess(&HealthFacts {
                heartbeat: hb,
                ..facts()
            }));
            assert!(
                !out.contains("eyJ")
                    && !out.to_lowercase().contains("token")
                    && !out.contains("acct_"),
                "{out}"
            );
        }
    }
}
