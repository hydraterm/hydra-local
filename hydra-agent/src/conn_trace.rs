//! Agent side of the correlated connection trace. Mirrors the browser's ConnTrace schema
//! (web-client/src/bridge/conn-trace.ts) so a single `traceId` — minted by the browser and threaded through the wire
//! — greps the WHOLE connect/sync path across browser + agent (+ cloud + desktop) in one query.
//!
//! SHARED SCHEMA (keep in lockstep with the TS TraceEvent):
//!   { traceId, ts, side, leg, stage, status, detail }
//!     side   : "agent" here.
//!     leg    : the action/lifecycle group — "connect" | "session_list" | "attach" | "stash" | "revive" | "remove" | …
//!     stage  : a step — "offer" | "answer" | "ice" | "dtls" | "datachannel" | "sent" | "reply" | "timeout" | …
//!     status : "ok" | "pending" | "warn" | "error"
//!     detail : short NON-SENSITIVE string (session ids/socket names/counts/reason codes) — NEVER terminal bytes,
//!              keys, tokens, or SDP/ICE bodies.
//!
//! Output: appended as one JSON object per line to `<agent_dir>/conn-trace.jsonl` (like consistency.jsonl). A
//! `traceId` of "" (unknown — the browser didn't send one, or a pre-auth event) is still recorded so nothing is lost;
//! it just won't correlate. Best-effort I/O — a trace write must NEVER affect the connection.

use std::path::{Path, PathBuf};

/// Content-blind status of a traced step. Serialized lowercase to match the browser.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TraceStatus {
    Ok,
    Pending,
    Warn,
    Error,
}

impl TraceStatus {
    fn as_str(self) -> &'static str {
        match self {
            TraceStatus::Ok => "ok",
            TraceStatus::Pending => "pending",
            TraceStatus::Warn => "warn",
            TraceStatus::Error => "error",
        }
    }
}

/// Append one structured trace event to `<agent_dir>/conn-trace.jsonl`. `detail` MUST be content-blind. `ts_ms` is
/// passed in (wall clock) so callers can stamp with the same source they use elsewhere and this stays testable.
/// Best-effort: any I/O error is swallowed (tracing must never break the peer).
pub fn append(
    agent_dir: &Path,
    trace_id: &str,
    leg: &str,
    stage: &str,
    status: TraceStatus,
    detail: &str,
    ts_ms: u64,
) {
    let safe_detail = scrub_detail(detail);
    let line = build_line(trace_id, leg, stage, status, &safe_detail, ts_ms);
    use std::io::Write as _;
    let path = trace_log_path(agent_dir);
    // Bounded like db-write.jsonl: truncate once past the cap so the forensic log can't grow unbounded
    // in production (the wire trace now covers EVERY control message, so volume is higher than before).
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > 4 * 1024 * 1024 {
            let _ = std::fs::write(&path, b"");
        }
    }
    if let Ok(mut f) = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(&path)
    {
        let _ = f.write_all(line.as_bytes());
    }
    // Also emit to the normal tracing log so it shows up in agent.out.log alongside the STAGE lines, tagged with the
    // trace id for correlation there too.
    match status {
        TraceStatus::Error => {
            tracing::warn!(trace = %trace_id, leg, stage, "conn-trace: {safe_detail}")
        }
        _ => tracing::info!(trace = %trace_id, leg, stage, "conn-trace: {safe_detail}"),
    }
}

fn scrub_detail(detail: &str) -> String {
    let lower = detail.to_ascii_lowercase();
    if lower.contains("token=")
        || lower.contains("authorization=")
        || lower.contains("cookie=")
        || lower.contains("signature=")
        || lower.contains("candidate=")
        || lower.contains("offer=")
        || lower.contains("answer=")
        || lower.contains("sdp=")
        || lower.contains("path=")
        || lower.contains("cwd=")
        || lower.contains("folder=")
        || lower.contains("project=")
        || lower.contains("projectname=")
        || lower.contains("session=")
        || lower.contains("sessionname=")
        || lower.contains(concat!("/", "users/"))
        || lower.contains("private")
    {
        return "<redacted>".into();
    }
    if detail.chars().count() > 240 {
        format!("{}…", detail.chars().take(240).collect::<String>())
    } else {
        detail.to_string()
    }
}

/// Build the JSONL line (exposed for tests). One object per line, fields ordered to match the TS dump for easy merge.
pub fn build_line(
    trace_id: &str,
    leg: &str,
    stage: &str,
    status: TraceStatus,
    detail: &str,
    ts_ms: u64,
) -> String {
    // Hand-serialize with escaping so we don't pull serde_json into a hot-ish path for a tiny object; the fields are
    // all short + controlled, but escape defensively (detail could contain a quote from a reason string).
    format!(
        "{{\"traceId\":\"{}\",\"ts\":{},\"side\":\"agent\",\"leg\":\"{}\",\"stage\":\"{}\",\"status\":\"{}\",\"detail\":\"{}\"}}\n",
        esc(trace_id),
        ts_ms,
        esc(leg),
        esc(stage),
        status.as_str(),
        esc(detail),
    )
}

/// Minimal JSON string escaping (quotes, backslash, control chars). Detail is already content-blind; this just keeps
/// the line valid JSON.
fn esc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => out.push(' '), // drop other control chars
            c => out.push(c),
        }
    }
    out
}

pub fn trace_log_path(agent_dir: &Path) -> PathBuf {
    agent_dir.join("conn-trace.jsonl")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn line_matches_the_shared_schema_and_is_valid_json() {
        let l = build_line(
            "t_abc",
            "session_list",
            "reply",
            TraceStatus::Ok,
            "2 sessions",
            1700000000000,
        );
        assert!(l.ends_with('\n'));
        let v: serde_json::Value = serde_json::from_str(l.trim()).unwrap();
        assert_eq!(v["traceId"], "t_abc");
        assert_eq!(v["side"], "agent");
        assert_eq!(v["leg"], "session_list");
        assert_eq!(v["stage"], "reply");
        assert_eq!(v["status"], "ok");
        assert_eq!(v["detail"], "2 sessions");
        assert_eq!(v["ts"], 1700000000000i64);
    }

    #[test]
    fn detail_is_escaped_so_a_reason_with_quotes_stays_valid_json() {
        let l = build_line(
            "t_x",
            "connect",
            "refused",
            TraceStatus::Error,
            "reason=\"device_revoked\"",
            1,
        );
        let v: serde_json::Value = serde_json::from_str(l.trim()).unwrap();
        assert_eq!(v["detail"], "reason=\"device_revoked\"");
    }

    #[test]
    fn empty_trace_id_is_still_recorded_uncorrelated() {
        let l = build_line("", "connect", "offer", TraceStatus::Pending, "", 5);
        let v: serde_json::Value = serde_json::from_str(l.trim()).unwrap();
        assert_eq!(v["traceId"], "");
    }

    #[test]
    fn append_scrubs_secret_shaped_detail_before_building_line() {
        assert_eq!(scrub_detail("token=secret"), "<redacted>");
        assert_eq!(scrub_detail("candidate={...}"), "<redacted>");
        assert_eq!(scrub_detail("cwd=/Users/test/Desktop/Secret"), "<redacted>");
        assert_eq!(scrub_detail("project=SecretProject"), "<redacted>");
        assert_eq!(scrub_detail("sessionName=ClaudeRun"), "<redacted>");
        assert_eq!(scrub_detail("2 sessions"), "2 sessions");
    }
}
