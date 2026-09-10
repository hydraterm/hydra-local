//! Correlated replies report launch admission, not renderer publication or provider success.
use super::*;

pub(super) fn request_id(intent: &ReactChromeIntent) -> Option<&str> {
    match intent {
        ReactChromeIntent::CreateWindow { request_id, .. }
        | ReactChromeIntent::SplitPane { request_id, .. } => request_id.as_deref(),
        _ => None,
    }
}

fn response_script(request_id: &str, result: &Result<(), String>) -> String {
    let arguments = serde_json::json!([request_id, result.is_ok(), result.as_ref().err()]);
    format!("window.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_MUTATION__?.(...{arguments});")
}

pub(super) fn respond(
    runtime: &mut RendererTabRuntime,
    request_id: Option<&str>,
    result: Result<(), String>,
) {
    if let Err(message) = &result {
        eprintln!("{message}");
    }
    if let Some(request_id) = request_id {
        if let Err(error) =
            runtime.evaluate_react_chrome_script(response_script(request_id, &result))
        {
            eprintln!("launch response could not reach the dialog: {error}");
        }
    }
}

pub(super) fn reject(runtime: &mut RendererTabRuntime, request_id: Option<&str>, message: String) {
    respond(runtime, request_id, Err(message));
}

pub(super) fn reject_inactive_json(runtime: &mut RendererTabRuntime, json: &str, reason: &str) {
    if let Ok(intent) = parse_react_chrome_intent(json) {
        if let Some(id) = request_id(&intent) {
            reject(runtime, Some(id), reason.into());
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn actual_refusal_and_exact_request_are_json_data_not_script() {
        let message = "scratch creation failed: \"quoted\"\n</script>";
        let script = response_script("request-7", &Err(message.into()));
        let arguments: serde_json::Value = serde_json::from_str(
            script
                .strip_prefix("window.__HYDRA_DASHBOARD_RESOLVE_LAUNCH_MUTATION__?.(...")
                .unwrap()
                .strip_suffix(");")
                .unwrap(),
        )
        .unwrap();
        assert_eq!(arguments, serde_json::json!(["request-7", false, message]));
    }

    #[test]
    fn typed_mutation_ids_remain_optional_and_closed() {
        for kind in ["createWindow", "splitPane"] {
            let mut input = serde_json::json!({"type":kind, "project_id":"p"});
            if kind == "splitPane" {
                input["window_id"] = "w".into();
                input["tab_id"] = "t".into();
                input["dir"] = "h".into();
            }
            assert!(request_id(&parse_react_chrome_intent(&input.to_string()).unwrap()).is_none());
            input["request_id"] = "exact-request".into();
            assert_eq!(
                request_id(&parse_react_chrome_intent(&input.to_string()).unwrap()),
                Some("exact-request")
            );
            input["unrecognized"] = true.into();
            assert!(parse_react_chrome_intent(&input.to_string()).is_err());
        }
    }
}
