//! A queued destination is user intent, never renderer ownership or a saved topology proof.
use super::*;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Destination {
    project_id: String,
    window_id: String,
    pane: Option<(String, String)>,
}

#[derive(Default)]
pub(super) struct PendingNavigation(Option<Destination>);

pub(super) enum Frontier {
    NotReady,
    Ready(Destination),
    Event(maestro_renderer::RendererEvent),
    Yield,
    Disconnected,
}

impl PendingNavigation {
    pub(super) fn retain(&mut self, intent: &ReactChromeIntent) -> bool {
        self.0 = Some(match intent {
            ReactChromeIntent::FocusWindow {
                project_id,
                window_id,
            } => Destination {
                project_id: project_id.clone(),
                window_id: window_id.clone(),
                pane: None,
            },
            ReactChromeIntent::FocusSessionOrPane {
                project_id,
                window_id,
                tab_id,
                session_id,
            } => Destination {
                project_id: project_id.clone(),
                window_id: window_id.clone(),
                pane: Some((tab_id.clone(), session_id.clone())),
            },
            _ => return false,
        });
        true
    }

    pub(super) fn retain_pending_json(
        &mut self,
        json: &str,
        bound: bool,
        current_window_id: &str,
        stopping: bool,
    ) -> bool {
        if stopping {
            self.0 = None;
            return false;
        }
        if let Ok(intent) = parse_react_chrome_intent(json) {
            if (bound || !react_chrome_intent_requires_window_context(&intent))
                && !product_recovery_blocks_react_intent(&intent, current_window_id)
            {
                return self.retain(&intent);
            }
        }
        false
    }

    pub(super) fn drain_frontier(
        &mut self,
        receiver: &mpsc::Receiver<maestro_renderer::RendererEvent>,
        stop: &AtomicBool,
        pending: bool,
        activated: bool,
        bound: bool,
        current_window_id: &str,
    ) -> Frontier {
        let stopping = stop.load(Ordering::Acquire);
        if stopping || (!pending && !activated) {
            self.0 = None;
        }
        if pending || !activated || self.0.is_none() {
            return Frontier::NotReady;
        }
        // Do not start an older destination ahead of a newer click already behind Published.
        // Stop at the first other event: the caller dispatches that ONE event normally, in order.
        for _ in 0..32 {
            if stop.load(Ordering::Acquire) {
                self.0 = None;
                return Frontier::NotReady;
            }
            match receiver.try_recv() {
                Ok(maestro_renderer::RendererEvent::ReactChromeIntent {
                    json,
                    dialog_focus_ticket,
                }) => {
                    if !self.retain_pending_json(&json, bound, current_window_id, false) {
                        return Frontier::Event(
                            maestro_renderer::RendererEvent::ReactChromeIntent {
                                json,
                                dialog_focus_ticket,
                            },
                        );
                    }
                }
                Ok(event) => return Frontier::Event(event),
                Err(mpsc::TryRecvError::Empty) => {
                    return self
                        .take_ready(false, true, stop.load(Ordering::Acquire))
                        .map_or(Frontier::NotReady, Frontier::Ready);
                }
                Err(mpsc::TryRecvError::Disconnected) => {
                    self.0 = None;
                    return Frontier::Disconnected;
                }
            }
        }
        // The batch bound grants no activation authority; re-enter the loop and recheck stop.
        Frontier::Yield
    }

    pub(super) fn take_ready(
        &mut self,
        pending: bool,
        activated: bool,
        stopping: bool,
    ) -> Option<Destination> {
        if stopping || (!pending && !activated) {
            self.0 = None;
        }
        if pending {
            return None;
        }
        self.0.take()
    }
}

impl Destination {
    pub(super) fn intent_name(&self) -> &'static str {
        if self.pane.is_some() {
            "focusSessionOrPane"
        } else {
            "focusWindow"
        }
    }

    fn validate(
        &self,
        paths: &AppPaths,
        snapshot: &maestro_shell::WindowLayoutSnapshot,
    ) -> Result<(), String> {
        if self.window_id == PRODUCT_RECOVERY_WINDOW_ID
            || snapshot.layout.window_id != self.window_id
        {
            return Err(
                "focus destination no longer belongs to the requested project/window".into(),
            );
        }
        let matching_owner = snapshot.project_id.as_deref() == Some(self.project_id.as_str())
            && maestro_shell::ProjectService::new(paths)
                .load(&self.project_id)
                .map_err(|error| format!("load focus project: {error}"))?
                .is_some();
        if !matching_owner {
            // Reuse exactly the dashboard/startup-repair association, including valid-FK priority.
            // Legacy NULL/dangling ownership must not make a displayed row unclickable. No repair.
            let dashboard = maestro_shell::DashboardSnapshotService::new(paths)
                .snapshot(None)
                .map_err(|error| format!("resolve displayed focus owner: {error}"))?;
            if !dashboard.projects.iter().any(|project| {
                project.project_id == self.project_id
                    && project
                        .windows
                        .iter()
                        .any(|window| window.window_id == self.window_id)
            }) {
                return Err("focus destination no longer belongs to the displayed project".into());
            }
        }
        if let Some((tab_id, session_id)) = &self.pane {
            if !snapshot
                .layout
                .tabs
                .iter()
                .any(|tab| !tab.stashed && tab.tab_id == *tab_id && tab.session_id == *session_id)
            {
                return Err(
                    "requested pane is absent, stashed, or belongs to another session".into(),
                );
            }
        }
        Ok(())
    }

    fn resolve(&self, paths: &AppPaths) -> Result<(WindowLayout, String), String> {
        let snapshot = WindowLayoutService::new(paths)
            .load_snapshot(&self.window_id)
            .map_err(|error| format!("load focus destination: {error}"))?
            .ok_or("requested window no longer exists")?;
        self.validate(paths, &snapshot)?;
        let tab_id = match &self.pane {
            Some((tab_id, _)) => Some(tab_id.clone()),
            None => preferred_visible_recorded_tab_id(paths, &snapshot.layout),
        }
        .ok_or("requested window has no visible panes")?;
        Ok((snapshot.layout, tab_id))
    }

    fn prepare(&self, paths: &AppPaths, now: u64) -> Result<(WindowLayout, String), String> {
        // Reject stale coordinates before topology repair or project recency writes. Re-read after
        // repair: the queued ids do not authorize a replacement pane or a new window owner.
        self.resolve(paths)?;
        WindowLayoutService::new(paths)
            .repair_live_topology(&self.window_id, now)
            .map_err(|error| format!("repair focus destination: {error}"))?;
        let resolved = self.resolve(paths)?;
        maestro_shell::ProjectService::new(paths)
            .touch(&self.project_id, now)
            .map_err(|error| format!("select focus project: {error}"))?;
        Ok(resolved)
    }

    fn projection(
        &self,
        paths: &AppPaths,
        tab_id: &str,
    ) -> Result<maestro_app::RendererViewportProjection, String> {
        let snapshot = WindowLayoutService::new(paths)
            .load_viewport_snapshot(&self.window_id)
            .map_err(|error| format!("load focus viewport: {error}"))?;
        self.validate(paths, snapshot.window())?;
        maestro_app::renderer_viewport_projection_from_snapshot(&snapshot, tab_id)
            .map_err(|error| format!("build focus viewport: {error}"))
    }

    fn bind_primary(&self, layout: &WindowLayout, tab_id: &str) -> Result<Self, String> {
        let tab = layout
            .tabs
            .iter()
            .find(|tab| !tab.stashed && tab.tab_id == tab_id)
            .ok_or("selected focus pane is no longer visible")?;
        let pane = (tab.tab_id.clone(), tab.session_id.clone());
        if layout.window_id != self.window_id
            || self.pane.as_ref().is_some_and(|expected| expected != &pane)
        {
            return Err("selected focus pane no longer matches the requested destination".into());
        }
        Ok(Self {
            pane: Some(pane),
            ..self.clone()
        })
    }

    pub(super) fn focus(
        &self,
        paths: &AppPaths,
        socket_path: &Path,
        shell_default_argv: Option<&[String]>,
        open_policy: RecordedPaneOpenPolicy,
        tab_runtime: &mut RendererTabRuntime,
    ) -> Result<Option<maestro_app::RendererViewportProjection>, String> {
        if tab_runtime.handoff_is_pending() {
            return Err("focus destination must wait for the pending viewport".into());
        }
        let now = now_ms();
        let (layout, tab_id) = self.prepare(paths, now)?;
        // Window-only selection is resolved at execution, not while queued. From this point the
        // same selected tab/session must survive preflight, just as an explicit pane destination.
        let exact_primary = self.bind_primary(&layout, &tab_id)?;
        let fallback_argv =
            effective_session_argv(&[], shell_default_argv, |k| std::env::var(k).ok());
        let attachment = start_visible_recorded_pane_sessions(
            paths,
            socket_path,
            &layout,
            &tab_id,
            &fallback_argv,
            open_policy,
            now,
        )?;
        // Validate the same project/tab/session against the coherent all-pane snapshot used by
        // the renderer, including any changes that happened during daemon preflight.
        let projection = match exact_primary.projection(paths, &tab_id) {
            Ok(projection) => projection,
            Err(error) => {
                if let Some(authority) = attachment {
                    cancel_or_retain_attachment_handoff(authority);
                }
                return Err(error);
            }
        };
        request_prepared_renderer_viewport(tab_runtime, projection, attachment)
    }
}

#[cfg(test)]
mod tests;
