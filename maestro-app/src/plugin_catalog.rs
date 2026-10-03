//! Window-local registry worker. Only snapshots cross back to the desktop listener.
use maestro_renderer::RendererCommandPaletteRow;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver, SyncSender};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc,
};

type Snapshot = Result<Vec<RendererCommandPaletteRow>, String>;

pub struct PluginCatalog {
    requests: SyncSender<()>,
    results: Receiver<(u64, Snapshot)>,
    generation: Arc<AtomicU64>,
    rows: Vec<RendererCommandPaletteRow>,
}

impl PluginCatalog {
    pub fn new(base: PathBuf) -> Result<Self, String> {
        Self::with_loader(move || crate::plugins::palette_rows(&base))
    }

    fn with_loader(mut load: impl FnMut() -> Snapshot + Send + 'static) -> Result<Self, String> {
        // Coalesce reopen requests; bound queued snapshots, not the user's catalog/argv.
        let (requests, request_rx) = mpsc::sync_channel(1);
        let (result_tx, results) = mpsc::sync_channel(1);
        let generation = Arc::new(AtomicU64::new(0));
        let requested_generation = Arc::clone(&generation);
        std::thread::Builder::new()
            .name("plugin-catalog".into())
            .spawn(move || {
                while request_rx.recv().is_ok() {
                    let generation = requested_generation.load(Ordering::Acquire);
                    if result_tx.send((generation, load())).is_err() {
                        break;
                    }
                }
            })
            .map_err(|e| format!("could not start plugin catalog worker: {e}"))?;
        let catalog = Self {
            requests,
            results,
            generation,
            rows: Vec::new(),
        };
        catalog.request(0);
        Ok(catalog)
    }

    pub fn request(&self, generation: u64) {
        self.generation.store(generation, Ordering::Release);
        let _ = self.requests.try_send(());
    }

    pub fn rows(&self) -> &[RendererCommandPaletteRow] {
        &self.rows
    }

    /// Nonblocking. A failed read clears stale actions; execution always revalidates registration.
    pub fn poll(&mut self) -> Option<(u64, Result<(), String>)> {
        let (generation, result) = self.results.try_recv().ok()?;
        Some((
            generation,
            match result {
                Ok(rows) => {
                    self.rows = rows;
                    Ok(())
                }
                Err(error) => {
                    self.rows.clear();
                    Err(error)
                }
            },
        ))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slow_registry_does_not_block_listener_and_reopens_coalesce() {
        let (entered_tx, entered_rx) = mpsc::channel();
        let (release_tx, release_rx) = mpsc::channel();
        let mut catalog = PluginCatalog::with_loader(move || {
            entered_tx.send(()).unwrap();
            release_rx.recv().unwrap();
            Ok(Vec::new())
        })
        .unwrap();
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert!(catalog.poll().is_none());
        for generation in 1..=100 {
            catalog.request(generation);
        }
        release_tx.send(()).unwrap();
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        let (generation, result) = catalog.poll().unwrap();
        assert_eq!(
            generation, 0,
            "in-flight result retains its original palette identity"
        );
        assert!(result.is_ok());
        release_tx.send(()).unwrap();
        let (generation, result) = catalog
            .results
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        assert_eq!(
            generation, 100,
            "coalescing preserves latest request identity"
        );
        assert!(result.is_ok());
        assert!(
            entered_rx.try_recv().is_err(),
            "only one pending refresh is retained"
        );
    }

    #[test]
    fn failure_replaces_cached_rows_with_empty_snapshot() {
        let (requests, _) = mpsc::sync_channel(1);
        let (tx, results) = mpsc::sync_channel(1);
        let mut catalog = PluginCatalog {
            requests,
            results,
            generation: Arc::new(AtomicU64::new(0)),
            rows: vec![RendererCommandPaletteRow {
                id: "plugin:test:run".into(),
                label: "Run".into(),
                category: "Plugins".into(),
                summary: String::new(),
                command: String::new(),
            }],
        };
        tx.send((0, Err("broken registry".into()))).unwrap();
        assert!(catalog.poll().unwrap().1.is_err());
        assert!(catalog.rows().is_empty());
    }

    #[test]
    fn closing_window_releases_worker_with_full_result_slot() {
        struct Finished(mpsc::Sender<()>);
        impl Drop for Finished {
            fn drop(&mut self) {
                let _ = self.0.send(());
            }
        }
        let (finished_tx, finished_rx) = mpsc::channel();
        let finished = Finished(finished_tx);
        let (entered_tx, entered_rx) = mpsc::channel();
        let catalog = PluginCatalog::with_loader(move || {
            let _keep_until_worker_exits = &finished;
            entered_tx.send(()).unwrap();
            Ok(Vec::new())
        })
        .unwrap();
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        catalog.request(1);
        entered_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
        // First result occupies the slot; the second send must unblock when the window drops.
        drop(catalog);
        finished_rx
            .recv_timeout(std::time::Duration::from_secs(5))
            .unwrap();
    }
}
