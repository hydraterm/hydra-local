//! Content-blind persisted heartbeat status. The heartbeat loop writes a tiny record each tick so an OFFLINE
//! tool (`hydra-agent health`) can tell whether the agent is actually reaching the cloud RECENTLY — not just
//! whether processes/socket exist. The record holds ONLY: an outcome enum, an optional HTTP status code, and a
//! unix-ms timestamp. It NEVER contains the device key, account/device ids, the request/response body, the
//! signature, signaling/SDP/ICE, or PTY output. HTTP status codes are not secrets.

use std::path::{Path, PathBuf};

/// The coarse outcome of a heartbeat attempt. Distinct from the HTTP code so a transport failure (no response)
/// is representable.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Outcome {
    /// the cloud accepted the heartbeat (2xx).
    Ok,
    /// the cloud responded but refused (e.g. 403 revoked / 400 rejected) — carries the status code.
    Refused,
    /// no response (network/timeout) — the agent could not reach the cloud.
    SendFailed,
}

impl Outcome {
    fn as_str(self) -> &'static str {
        match self {
            Outcome::Ok => "ok",
            Outcome::Refused => "refused",
            Outcome::SendFailed => "send_failed",
        }
    }
    fn from_str(s: &str) -> Option<Outcome> {
        match s {
            "ok" => Some(Outcome::Ok),
            "refused" => Some(Outcome::Refused),
            "send_failed" => Some(Outcome::SendFailed),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HeartbeatStatus {
    pub outcome: Outcome,
    /// the HTTP status code, when the cloud responded (None on a transport failure).
    pub status_code: Option<u16>,
    /// when this attempt happened, unix milliseconds.
    pub ts_ms: u64,
}

/// `last-heartbeat.json` under the agent data dir.
pub fn status_path(dir: &Path) -> PathBuf {
    dir.join("last-heartbeat.json")
}

/// Serialize to a tiny content-blind JSON. Hand-rolled (no serde derive churn) — three scalar fields only.
fn to_json(s: &HeartbeatStatus) -> String {
    let code = match s.status_code {
        Some(c) => c.to_string(),
        None => "null".to_string(),
    };
    format!(
        "{{\"outcome\":\"{}\",\"status_code\":{},\"ts_ms\":{}}}",
        s.outcome.as_str(),
        code,
        s.ts_ms
    )
}

/// Best-effort persist (atomic-ish: write a temp file then rename). A failure to write status NEVER affects the
/// heartbeat itself — the caller ignores the result.
pub fn save(dir: &Path, s: &HeartbeatStatus) -> std::io::Result<()> {
    let path = status_path(dir);
    let tmp = path.with_extension("json.tmp");
    std::fs::write(&tmp, to_json(s))?;
    std::fs::rename(&tmp, &path)
}

/// Parse the persisted record. Returns None if absent or malformed (treated as "no heartbeat yet").
pub fn load(dir: &Path) -> Option<HeartbeatStatus> {
    let raw = std::fs::read_to_string(status_path(dir)).ok()?;
    parse(&raw)
}

/// Pure parser, split out for tests. Tolerant: a missing/garbage field → None (no panic on bad input).
pub fn parse(raw: &str) -> Option<HeartbeatStatus> {
    let v: serde_json::Value = serde_json::from_str(raw).ok()?;
    let outcome = Outcome::from_str(v.get("outcome")?.as_str()?)?;
    let status_code = match v.get("status_code") {
        Some(serde_json::Value::Number(n)) => n.as_u64().map(|c| c as u16),
        _ => None,
    };
    let ts_ms = v.get("ts_ms")?.as_u64()?;
    Some(HeartbeatStatus {
        outcome,
        status_code,
        ts_ms,
    })
}

/// A content-blind one-line summary for `health`, given the record and the current time. Reports the outcome,
/// the code (if any), and how long ago — never any secret. `now_ms` is passed so this stays pure/testable.
pub fn render_line(s: &HeartbeatStatus, now_ms: u64) -> String {
    let age_s = now_ms.saturating_sub(s.ts_ms) / 1000;
    let age = if age_s < 90 {
        format!("{age_s}s ago")
    } else {
        format!("{}m ago", age_s / 60)
    };
    match (s.outcome, s.status_code) {
        (Outcome::Ok, _) => format!("last heartbeat: reached the cloud {age}"),
        (Outcome::Refused, Some(c)) => format!("last heartbeat: cloud REFUSED it ({c}) {age}"),
        (Outcome::Refused, None) => format!("last heartbeat: cloud refused it {age}"),
        (Outcome::SendFailed, _) => format!("last heartbeat: could NOT reach the cloud {age}"),
    }
}

/// Is the record fresh enough to count as "the agent is currently reaching the cloud"? A generous window so a
/// single missed tick isn't a failure.
pub fn is_fresh(s: &HeartbeatStatus, now_ms: u64, max_age_ms: u64) -> bool {
    s.outcome == Outcome::Ok && now_ms.saturating_sub(s.ts_ms) <= max_age_ms
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrips_through_json() {
        for s in [
            HeartbeatStatus {
                outcome: Outcome::Ok,
                status_code: Some(200),
                ts_ms: 1_700_000_000_000,
            },
            HeartbeatStatus {
                outcome: Outcome::Refused,
                status_code: Some(403),
                ts_ms: 1_700_000_000_000,
            },
            HeartbeatStatus {
                outcome: Outcome::SendFailed,
                status_code: None,
                ts_ms: 42,
            },
        ] {
            assert_eq!(parse(&to_json(&s)), Some(s));
        }
    }

    #[test]
    fn malformed_input_is_none_not_panic() {
        assert_eq!(parse("not json"), None);
        assert_eq!(parse("{}"), None);
        assert_eq!(
            parse("{\"outcome\":\"bogus\",\"status_code\":1,\"ts_ms\":1}"),
            None
        );
    }

    #[test]
    fn render_and_persisted_json_are_content_blind() {
        // no secret-shaped material in either the on-disk JSON or the health line.
        for s in [
            HeartbeatStatus {
                outcome: Outcome::Ok,
                status_code: Some(200),
                ts_ms: 1_700_000_000_000,
            },
            HeartbeatStatus {
                outcome: Outcome::Refused,
                status_code: Some(403),
                ts_ms: 1_700_000_000_000,
            },
            HeartbeatStatus {
                outcome: Outcome::SendFailed,
                status_code: None,
                ts_ms: 1_700_000_000_000,
            },
        ] {
            for out in [to_json(&s), render_line(&s, 1_700_000_060_000)] {
                let lo = out.to_lowercase();
                assert!(!out.contains("eyJ"), "{out}"); // JWT
                assert!(!lo.contains("token"), "{out}");
                assert!(!lo.contains("cookie"), "{out}");
                assert!(!lo.contains("signature"), "{out}");
                assert!(!out.contains("acct_"), "{out}");
                assert!(!out.contains("dev_"), "{out}");
            }
        }
    }

    #[test]
    fn freshness_window() {
        let s = HeartbeatStatus {
            outcome: Outcome::Ok,
            status_code: Some(200),
            ts_ms: 1000,
        };
        assert!(is_fresh(&s, 1000 + 30_000, 60_000)); // 30s old, 60s window
        assert!(!is_fresh(&s, 1000 + 90_000, 60_000)); // 90s old → stale
                                                       // a refused/failed status is never "fresh-healthy" even if recent.
        let bad = HeartbeatStatus {
            outcome: Outcome::Refused,
            status_code: Some(403),
            ts_ms: 1000,
        };
        assert!(!is_fresh(&bad, 1000, 60_000));
    }

    #[test]
    fn render_age_humanizes_minutes() {
        let s = HeartbeatStatus {
            outcome: Outcome::Ok,
            status_code: Some(200),
            ts_ms: 0,
        };
        assert!(render_line(&s, 5_000).contains("5s ago"));
        assert!(render_line(&s, 600_000).contains("10m ago"));
    }

    #[test]
    fn save_then_load_roundtrips_on_disk() {
        let dir = std::env::temp_dir().join(format!("hb-status-test-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let s = HeartbeatStatus {
            outcome: Outcome::Ok,
            status_code: Some(200),
            ts_ms: 1_700_000_000_000,
        };
        save(&dir, &s).unwrap();
        assert_eq!(load(&dir), Some(s));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
