//! Bounded, metadata-only lifecycle maintenance. Never launches or retries a window/session.
use super::*;
use std::os::unix::fs::MetadataExt;
use std::sync::mpsc::{sync_channel, Receiver, SyncSender, TryRecvError};

type Completion = Result<bool, maestro_app::SettingsFailure>;

struct Worker {
    wake: SyncSender<()>,
    result: Receiver<Completion>,
    handle: std::thread::JoinHandle<()>,
    stopping: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

impl Drop for WindowOrderMaintenance {
    fn drop(&mut self) {
        if let Some(worker) = &self.worker {
            worker.stopping.store(true, Ordering::Release);
        }
        // Dropping the worker closes its only wake sender; idle recv exits without a GUI join.
        // An already admitted metadata save may finish, but it cannot create/replay any window.
    }
}

#[derive(Default)]
pub(super) struct WindowOrderMaintenance {
    worker: Option<Worker>,
    last_wake: Option<Instant>,
}

impl WindowOrderMaintenance {
    pub(super) fn poll(&mut self, paths: &AppPaths, admitted: bool) -> Option<Completion> {
        if !admitted {
            return None;
        }
        if let Some(worker) = &self.worker {
            match worker.result.try_recv() {
                Ok(result) => return Some(result),
                Err(TryRecvError::Disconnected) if worker.handle.is_finished() => {
                    self.worker.take();
                    return Some(Err(failure("window order worker stopped unexpectedly")));
                }
                _ => {}
            }
        }
        if self
            .last_wake
            .is_some_and(|last| last.elapsed() < LIVE_TAB_STRIP_REFRESH_INTERVAL)
        {
            return None;
        }
        self.last_wake = Some(Instant::now());
        if self.worker.is_none() {
            let paths = paths.clone();
            let (wake, requests) = sync_channel(1);
            let (results, result) = sync_channel(1);
            let stopping = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
            let worker_stop = stopping.clone();
            let handle = std::thread::Builder::new()
                .name("window-order".into())
                .spawn(move || run_worker(&paths, requests, results, &worker_stop));
            match handle {
                Ok(handle) => {
                    self.worker = Some(Worker {
                        wake,
                        result,
                        handle,
                        stopping,
                    })
                }
                Err(error) => return Some(Err(failure(error.to_string()))),
            }
        }
        if let Some(worker) = &self.worker {
            let _ = worker.wake.try_send(());
        }
        None
    }
}

fn run_worker(
    paths: &AppPaths,
    requests: Receiver<()>,
    results: SyncSender<Completion>,
    stopping: &std::sync::atomic::AtomicBool,
) {
    let mut discovery = Discovery::default();
    while requests.recv().is_ok() {
        if stopping.load(Ordering::Acquire) {
            break;
        }
        let completion = discovery.check(paths);
        if stopping.load(Ordering::Acquire) {
            break;
        }
        // Discovery has returned and released every DB/settings guard. It is safe for this
        // background thread to await the one completion slot; never drop the only changed/error
        // result. GUI polling and coalesced wakes stay nonblocking. Receiver drop exits the worker.
        if results.send(completion).is_err() {
            break;
        }
    }
}

fn failure(message: impl Into<String>) -> maestro_app::SettingsFailure {
    maestro_app::SettingsFailure::new("window_order_failed", message)
}

#[derive(Clone, PartialEq, Eq)]
struct SettingsStamp {
    device: u64,
    inode: u64,
    length: u64,
    modified: (i64, i64),
    changed: (i64, i64),
}

#[derive(Clone, PartialEq, Eq)]
struct Hints {
    database: (i64, u64),
    settings: Option<SettingsStamp>,
}

impl Hints {
    fn read(paths: &AppPaths) -> Result<Self, maestro_app::SettingsFailure> {
        // Read the same cached connection's external commit counter and local total_changes.
        // These are invalidation hints only, never an ownership/epoch proof. Both run off-thread.
        let connection = maestro_shell::db::conn_for(paths.base())
            .map_err(|error| failure(error.to_string()))?;
        let database = {
            let conn = connection
                .lock()
                .map_err(|_| failure("window metadata lock was poisoned"))?;
            (
                maestro_shell::db::data_version(&conn)
                    .map_err(|error| failure(error.to_string()))?,
                conn.total_changes(),
            )
        };
        let settings = match std::fs::metadata(maestro_app::settings_file_path(paths.base())) {
            Ok(value) => Some(SettingsStamp {
                device: value.dev(),
                inode: value.ino(),
                length: value.len(),
                modified: (value.mtime(), value.mtime_nsec()),
                changed: (value.ctime(), value.ctime_nsec()),
            }),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => None,
            Err(error) => return Err(failure(error.to_string())),
        };
        Ok(Self { database, settings })
    }
}

#[derive(Default)]
struct Discovery {
    hints: Option<Hints>,
    windows: Option<Vec<String>>,
}

impl Discovery {
    fn check(&mut self, paths: &AppPaths) -> Completion {
        let hints = Hints::read(paths)?;
        if self.hints.as_ref() == Some(&hints) {
            return Ok(false); // No window scan, settings-file read/lock, or new OS thread.
        }
        let windows = maestro_shell::store::window_ids_in_creation_order(paths)
            .map_err(|error| failure(error.to_string()))?;
        if self.windows.as_ref() == Some(&windows)
            && self
                .hints
                .as_ref()
                .is_some_and(|old| old.settings == hints.settings)
        {
            self.hints = Some(hints);
            return Ok(false); // Unrelated SQLite writes do not trigger JSON maintenance.
        }
        let changed = maestro_app::reconcile_window_presentation_order(paths, None)?;
        // Preserve pre-operation hints: a concurrent commit/save must be discovered next time.
        // Our own atomic JSON save may cause one extra confirmation, never a lost invalidation.
        // Failures do not reach this cache update and remain visible/retryable without clobbering.
        self.hints = Some(hints);
        self.windows = Some(windows);
        Ok(changed)
    }
}

/// A failed metadata save cannot undo creation or offer a creation retry. The exact reason stays
/// visible through subsequent model refreshes until an idempotent metadata reconciliation succeeds.
pub(super) fn apply_result(runtime: &mut RendererTabRuntime, result: Completion) -> bool {
    let (changed, warning) = match result {
        Ok(changed) => (changed, None),
        Err(error) => (
            false,
            Some(format!("Window order wasn't saved: {}", error.message)),
        ),
    };
    runtime.set_window_order_warning(warning) || changed
}

#[cfg(test)]
mod tests;
