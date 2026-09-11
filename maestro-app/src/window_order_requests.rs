//! Explicit presentation saves have correlated results, independent from maintenance warnings.
use super::*;

#[derive(Debug, serde::Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
enum SaveResult {
    Saved,
    Failed { message: String },
    Partial { message: String },
    Unconfirmed { message: String },
}

struct Pending {
    request_id: Option<String>,
    worker: std::thread::JoinHandle<SaveResult>,
}

#[derive(Default)]
pub(super) struct WindowOrderRequests {
    pending: Option<Pending>,
}

impl WindowOrderRequests {
    pub(super) fn submit(
        &mut self,
        paths: &AppPaths,
        runtime: &mut RendererTabRuntime,
        request_id: Option<String>,
        project_id: Option<&str>,
        order: Vec<String>,
    ) {
        if self.pending.is_some() {
            respond(
                runtime,
                request_id.as_deref(),
                &SaveResult::Failed {
                    message:
                        "A previous window order save is still pending. No new order was applied."
                            .into(),
                },
            );
            return;
        }
        // Keep the existing synchronous SQL/epoch ordering in this listener. Only JSON save waits
        // move to the background; a busy request is rejected before this or any settings mutation.
        if let Some(project) = project_id {
            if let Err(error) = maestro_shell::ProjectService::new(paths).reorder_owned_windows(
                project,
                &order,
                now_ms(),
            ) {
                respond(
                    runtime,
                    request_id.as_deref(),
                    &SaveResult::Failed {
                        message: error.to_string(),
                    },
                );
                return;
            }
        }
        let project_accepted = project_id.is_some();
        let paths = paths.clone();
        match std::thread::Builder::new()
            .name("window-order-save".into())
            .spawn(
                move || match maestro_app::reorder_window_presentation(&paths, &order) {
                    Ok(_) => SaveResult::Saved,
                    Err(error) => save_failure(project_accepted, error.message),
                },
            ) {
            Ok(worker) => self.pending = Some(Pending { request_id, worker }),
            Err(error) => respond(
                runtime,
                request_id.as_deref(),
                &save_failure(project_accepted, error.to_string()),
            ),
        }
    }

    /// Poll before viewport gates; no join wait and no lost completion behind navigation events.
    pub(super) fn poll(&mut self, runtime: &mut RendererTabRuntime) -> bool {
        if !self
            .pending
            .as_ref()
            .is_some_and(|pending| pending.worker.is_finished())
        {
            return false;
        }
        let pending = self.pending.take().expect("finished request exists");
        let result = pending.worker.join().unwrap_or_else(|_| SaveResult::Unconfirmed {
            message: "Window order save stopped before confirmation. Check the current order before retrying.".into(),
        });
        respond(runtime, pending.request_id.as_deref(), &result);
        true
    }
}

fn save_failure(project_accepted: bool, message: String) -> SaveResult {
    if project_accepted {
        SaveResult::Partial {
            message: format!(
                "Project order was accepted, but global tab order was not saved: {message}"
            ),
        }
    } else {
        SaveResult::Failed { message }
    }
}

fn respond(runtime: &mut RendererTabRuntime, request_id: Option<&str>, result: &SaveResult) {
    let Some(request_id) = request_id else {
        if !matches!(result, SaveResult::Saved) {
            eprintln!("window order legacy request: {result:?}");
        }
        return;
    };
    let request = serde_json::to_string(request_id).expect("request id serializes");
    let result = serde_json::to_string(result).expect("order result serializes");
    let script = format!("window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_ORDER__?.({request}, {result});");
    if let Err(error) = runtime.evaluate_react_chrome_script(script) {
        eprintln!("window order response could not reach chrome: {error}");
    }
}

pub(super) fn decline(runtime: &mut RendererTabRuntime, intent: &ReactChromeIntent, reason: &str) {
    let request_id = match intent {
        ReactChromeIntent::ReorderWindowPresentation { request_id, .. } => {
            Some(request_id.as_str())
        }
        ReactChromeIntent::UpdateWindowOrder { request_id, .. } => request_id.as_deref(),
        _ => return,
    };
    respond(
        runtime,
        request_id,
        &SaveResult::Failed {
            message: reason.into(),
        },
    );
}

pub(super) fn decline_json(runtime: &mut RendererTabRuntime, json: &str, reason: &str) {
    if let Ok(intent) = parse_react_chrome_intent(json) {
        decline(runtime, &intent, reason);
    }
}

#[cfg(test)]
mod tests;
