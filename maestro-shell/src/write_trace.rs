//! DB-write log net — a CONTENT-BLIND, production-time record of EVERY mutation to the shared store,
//! so "which process wrote/deleted what, in what order" is answerable with evidence. Every supported
//! local-store writer funnels through `store::write_record` / `store::delete_record`, so this hooks
//! there — one append per mutation.
//!
//! CONTENT-BLIND by construction: a trace carries `{who, op, kind, id, fields, seq, ts}` — the record KIND + its ID +
//! WHICH top-level fields were present (names only) + a monotonic seq. NEVER values, terminal bytes, tokens, or paths.
//!
//! `who` (the WriterTag) is set ONCE at process startup (`set_writer_tag`) so every line is attributable to the
//! local writer process. Two sinks: a bounded in-memory ring (test-capturable + a cheap live dump) and a bounded
//! append to `<base>/db-write.jsonl` (production forensics; rotated by truncation at a cap).

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

/// Which process is writing — set once at startup so every trace line is attributable.
static WRITER_TAG: OnceLock<String> = OnceLock::new();
/// Monotonic write sequence across this process (ordering + gap detection in the log).
static WRITE_SEQ: AtomicU64 = AtomicU64::new(0);

/// Set the writer identity for this process (for example, "desktop-app" or "optional-extension").
/// First call wins; idempotent.
pub fn set_writer_tag(tag: &str) {
    let _ = WRITER_TAG.set(tag.to_string());
}

// The CAUSE of the current mutation, set by the caller around the handler that performs the writes
// (an optional extension's control seam / the desktop's intent dispatch) and stamped onto every trace the handler
// emits. Thread-local is sufficient: both writers perform their SQLite mutations synchronously on the
// handling thread. `None` (background/untagged work) is fine — ctx is additive forensics, not identity.
thread_local! {
    static MUTATION_CTX: std::cell::RefCell<Option<String>> = const { std::cell::RefCell::new(None) };
}

/// Run `f` with the mutation context set; restored on exit even on panic (RAII guard). `ctx` MUST be
/// content-blind — origin + op name + opaque request id (e.g. "remote:project_create rid=r42",
/// "local:createProject"), never payload/token/path values.
pub fn with_mutation_context<R>(ctx: &str, f: impl FnOnce() -> R) -> R {
    struct Reset;
    impl Drop for Reset {
        fn drop(&mut self) {
            MUTATION_CTX.with(|c| *c.borrow_mut() = None);
        }
    }
    MUTATION_CTX.with(|c| *c.borrow_mut() = Some(ctx.to_string()));
    let _reset = Reset;
    f()
}

/// Imperative variant of [`with_mutation_context`] for call sites where the handler body cannot be a
/// closure (e.g. the desktop's intent-dispatch loop, whose match arms use `continue`). The caller owns
/// the discipline: set `Some(...)` right before dispatch and reset to `None` at the TOP of every loop
/// iteration, so a stale context can never be stamped onto writes caused by a later event.
pub fn set_thread_mutation_context(ctx: Option<&str>) {
    MUTATION_CTX.with(|c| *c.borrow_mut() = ctx.map(str::to_string));
}

fn writer_tag() -> &'static str {
    WRITER_TAG.get().map(String::as_str).unwrap_or("unknown")
}

/// One content-blind write-trace event.
#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub struct WriteTrace {
    pub seq: u64,
    pub ts_ms: u64,
    pub who: String,
    /// "write" | "delete"
    pub op: &'static str,
    /// record kind (e.g. "Project", "WindowLayout") — NOT the value.
    pub kind: String,
    pub id: String,
    /// top-level field NAMES present in the written record (content-blind); empty for deletes.
    pub fields: Vec<String>,
    /// The CAUSE, when known: "<origin>:<op> rid=<request_id>" set via [`with_mutation_context`] around
    /// the handler that performed this write. The rid joins this row to the wire trace (conn-trace.jsonl
    /// both ends) — intent → wire → DB write becomes one greppable chain. `None` for background work.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ctx: Option<String>,
}

const RING_MAX: usize = 1000;

fn ring() -> &'static Mutex<Vec<WriteTrace>> {
    static RING: OnceLock<Mutex<Vec<WriteTrace>>> = OnceLock::new();
    RING.get_or_init(|| Mutex::new(Vec::new()))
}

/// Record a write. `field_names` are the record's top-level keys (names only — content-blind). `ts_ms` is passed in
/// (the store already has a timestamp) so this stays free of a clock dependency + is deterministic in tests.
pub fn trace_write(
    base: &std::path::Path,
    kind: &str,
    id: &str,
    field_names: &[String],
    ts_ms: u64,
) {
    emit(base, "write", kind, id, field_names.to_vec(), ts_ms);
}

/// Record a delete (no fields).
pub fn trace_delete(base: &std::path::Path, kind: &str, id: &str, ts_ms: u64) {
    emit(base, "delete", kind, id, Vec::new(), ts_ms);
}

fn emit(
    base: &std::path::Path,
    op: &'static str,
    kind: &str,
    id: &str,
    fields: Vec<String>,
    ts_ms: u64,
) {
    let seq = WRITE_SEQ.fetch_add(1, Ordering::Relaxed);
    let ev = WriteTrace {
        seq,
        ts_ms,
        who: writer_tag().to_string(),
        op,
        kind: kind.to_string(),
        id: id.to_string(),
        fields,
        ctx: MUTATION_CTX.with(|c| c.borrow().clone()),
    };
    // In-memory ring (bounded).
    if let Ok(mut r) = ring().lock() {
        r.push(ev.clone());
        if r.len() > RING_MAX {
            let drop = r.len() - RING_MAX;
            r.drain(0..drop);
        }
    }
    // Best-effort append to the jsonl sink (never let a logging failure break a write).
    append_jsonl(base, &ev);
}

fn append_jsonl(base: &std::path::Path, ev: &WriteTrace) {
    use std::io::Write;
    let path = base.join("db-write.jsonl");
    // Bounded: truncate once the file passes a cap so the forensic log can't grow unbounded in production.
    if let Ok(meta) = std::fs::metadata(&path) {
        if meta.len() > 4 * 1024 * 1024 {
            let _ = std::fs::write(&path, b"");
        }
    }
    if let Ok(line) = serde_json::to_string(ev) {
        if let Ok(mut f) = std::fs::OpenOptions::new()
            .create(true)
            .append(true)
            .open(&path)
        {
            let _ = writeln!(f, "{line}");
        }
    }
}

/// The in-memory ring (oldest → newest) — for tests + a live dump. Content-blind.
pub fn recent() -> Vec<WriteTrace> {
    ring().lock().map(|r| r.clone()).unwrap_or_default()
}

/// Tail the PERSISTENT `<base>/db-write.jsonl` — unlike [`recent`] (this process's ring only), the
/// file interleaves BOTH writers' events, so this is the two-writer timeline a debug surface wants.
/// Returns up to `max` most-recent parsed lines, oldest → newest. Unparseable lines (truncation
/// boundary) are skipped. Content-blind by construction — the file only ever holds trace events.
pub fn tail_jsonl(base: &std::path::Path, max: usize) -> Vec<serde_json::Value> {
    let Ok(text) = std::fs::read_to_string(base.join("db-write.jsonl")) else {
        return Vec::new();
    };
    let parsed: Vec<serde_json::Value> = text
        .lines()
        .filter_map(|l| serde_json::from_str(l).ok())
        .collect();
    let skip = parsed.len().saturating_sub(max);
    parsed.into_iter().skip(skip).collect()
}

// (No test-reset helper on purpose: the ring is process-global and tests run in parallel — a reset
// would clear OTHER tests' events mid-flight. Tests assert on their own unique ids, filtered.)

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_and_delete_are_traced_content_blind() {
        // NOTE: the ring is process-GLOBAL and lib tests run in parallel, so assert on THIS test's
        // unique ids (filtered), never on the ring's total length.
        set_writer_tag("test-writer");
        let base = std::env::temp_dir().join(format!("hydra-wt-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&base);

        trace_write(
            &base,
            "Project",
            "wt-p1",
            &["name".into(), "root".into()],
            100,
        );
        trace_delete(&base, "WindowLayout", "wt-w1", 101);

        let all = recent();
        let evs: Vec<_> = all
            .iter()
            .filter(|e| matches!(e.id.as_str(), "wt-p1" | "wt-w1"))
            .collect();
        assert_eq!(evs.len(), 2);
        assert_eq!(evs[0].op, "write");
        assert_eq!(evs[0].kind, "Project");
        assert_eq!(evs[0].id, "wt-p1");
        assert_eq!(evs[0].fields, vec!["name".to_string(), "root".to_string()]);
        assert_eq!(evs[0].who, "test-writer");
        assert_eq!(evs[1].op, "delete");
        assert!(evs[1].fields.is_empty());
        assert!(evs[1].seq > evs[0].seq, "seq is monotonic");

        // CONTENT-BLIND: the serialized trace carries only names/ids/counts, never values.
        let json = serde_json::to_string(&evs[0]).unwrap();
        assert!(json.contains("\"kind\":\"Project\"") && json.contains("\"id\":\"wt-p1\""));
        assert!(!json.contains("root=") && !json.to_lowercase().contains("token"));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn mutation_context_is_stamped_inside_the_scope_and_cleared_outside() {
        // Same parallel-safety rule as above: unique ids, filtered — never total-ring assertions.
        set_writer_tag("test-writer");
        let base = std::env::temp_dir().join(format!("hydra-wt-ctx-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&base);

        with_mutation_context("remote:project_create rid=r42", || {
            trace_write(&base, "Project", "ctx-p1", &["name".into()], 100);
            trace_delete(&base, "WindowLayout", "ctx-w1", 101);
        });
        trace_write(&base, "Session", "ctx-s1", &[], 102); // outside the scope → no ctx

        let evs = recent();
        let ours: Vec<_> = evs
            .iter()
            .filter(|e| matches!(e.id.as_str(), "ctx-p1" | "ctx-w1" | "ctx-s1"))
            .collect();
        assert_eq!(ours.len(), 3);
        assert_eq!(
            ours[0].ctx.as_deref(),
            Some("remote:project_create rid=r42")
        );
        assert_eq!(
            ours[1].ctx.as_deref(),
            Some("remote:project_create rid=r42")
        );
        assert_eq!(ours[2].ctx, None, "context must not leak past its scope");
        // ctx is omitted from the JSON entirely when absent (no noisy null FIELD in the forensic log;
        // note the id string itself is "ctx-s1", so assert on the quoted field name).
        assert!(!serde_json::to_string(ours[2]).unwrap().contains("\"ctx\""));

        let _ = std::fs::remove_dir_all(&base);
    }

    #[test]
    fn tail_jsonl_returns_most_recent_parsed_lines_in_order() {
        let base = std::env::temp_dir().join(format!("hydra-wt-tail-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&base);
        let _ = std::fs::create_dir_all(&base);
        for i in 0..5 {
            trace_write(&base, "Project", &format!("tail-{i}"), &[], 100 + i);
        }
        // Corrupt/truncated line (e.g. the 4MiB rotation boundary) must be skipped, not fail the tail.
        {
            use std::io::Write as _;
            let mut f = std::fs::OpenOptions::new()
                .append(true)
                .open(base.join("db-write.jsonl"))
                .unwrap();
            writeln!(f, "{{not json").unwrap();
        }
        let tail = tail_jsonl(&base, 3);
        let ids: Vec<&str> = tail.iter().filter_map(|v| v.get("id")?.as_str()).collect();
        assert_eq!(
            ids,
            vec!["tail-2", "tail-3", "tail-4"],
            "last N, oldest→newest"
        );
        assert!(
            tail_jsonl(&base, 100).len() >= 5,
            "max larger than file → all lines"
        );
        assert!(tail_jsonl(std::path::Path::new("/nonexistent-xyz"), 3).is_empty());
        let _ = std::fs::remove_dir_all(&base);
    }
}
