use super::*;

#[test]
fn early_viewport_gates_decline_only_exact_typed_rename_requests_without_mutation() {
    for (id, reason) in [
        (
            "handoff-rename",
            "The viewport is still changing. The window was not renamed.",
        ),
        (
            "neutral-rename",
            "No active viewport is available. The window was not renamed.",
        ),
    ] {
        let (mut runtime, commands) = RendererTabRuntime::new();
        let mut request = serde_json::json!({
            "type": "updateWindow", "request_id": id,
            "project_id": "project", "window_id": "window", "name": "Draft"
        });
        // The real early branches retain launch refusal before the rename-only callback.
        launch_mutation::reject_inactive_json(&mut runtime, &request.to_string(), reason);
        decline_react_window_rename_json(&mut runtime, &request.to_string(), reason);
        let maestro_renderer::RendererCommand::EvaluateReactChromeScript { script, .. } =
            commands.recv_timeout(Duration::from_secs(1)).unwrap()
        else {
            panic!("early refusal must only send the existing chrome acknowledgement")
        };
        let arguments = script
            .strip_prefix("window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_RENAME__?.(")
            .unwrap()
            .strip_suffix(");")
            .unwrap();
        let values: serde_json::Value = serde_json::from_str(&format!("[{arguments}]")).unwrap();
        assert_eq!(
            values,
            serde_json::json!([id, {"ok": false, "name": null, "message": reason}])
        );
        assert!(
            commands.try_recv().is_err(),
            "no focus, topology or duplicate reply"
        );
        request["unexpected"] = true.into();
        decline_react_window_rename_json(&mut runtime, &request.to_string(), reason);
        request.as_object_mut().unwrap().remove("unexpected");
        request.as_object_mut().unwrap().remove("request_id");
        decline_react_window_rename_json(&mut runtime, &request.to_string(), reason);
        request["type"] = "createWindow".into();
        request["request_id"] = id.into();
        request.as_object_mut().unwrap().remove("window_id");
        decline_react_window_rename_json(&mut runtime, &request.to_string(), reason);
        assert!(
            commands.try_recv().is_err(),
            "do not invent a rename correlation"
        );
    }
}

#[test]
fn update_window_accepts_optional_rename_correlation_and_rejects_unknown_fields() {
    for request in [None, Some("rename-request")] {
        let mut intent = serde_json::json!({
            "type": "updateWindow", "project_id": "project", "window_id": "window", "name": "Name"
        });
        if let Some(id) = request {
            intent["request_id"] = serde_json::json!(id);
        }
        let parsed = parse_react_chrome_intent(&intent.to_string()).unwrap();
        assert!(
            matches!(parsed, ReactChromeIntent::UpdateWindow { request_id, .. }
            if request_id.as_deref() == request)
        );
        intent["script"] = serde_json::json!("unexpected");
        assert!(parse_react_chrome_intent(&intent.to_string()).is_err());
    }
}

#[test]
fn rename_acknowledgement_serializes_content_as_data_for_the_existing_chrome_channel() {
    let (mut runtime, commands) = RendererTabRuntime::new();
    let request_id = "request\");window.injected=true;//";
    let message = "Could not rename window: \"missing\"\n<script>";
    respond_react_window_rename(&mut runtime, request_id, Err(message.into()));
    let maestro_renderer::RendererCommand::EvaluateReactChromeScript { script, .. } =
        commands.recv_timeout(Duration::from_secs(1)).unwrap()
    else {
        panic!("expected the existing local chrome result channel")
    };
    let arguments = script
        .strip_prefix("window.__HYDRA_DASHBOARD_RESOLVE_WINDOW_RENAME__?.(")
        .unwrap()
        .strip_suffix(");")
        .unwrap();
    let values: serde_json::Value = serde_json::from_str(&format!("[{arguments}]")).unwrap();
    assert_eq!(values[0], request_id);
    assert_eq!(
        values[1],
        serde_json::json!({"ok": false, "name": null, "message": message})
    );
}

#[test]
fn rename_uses_existing_native_normalization_and_missing_window_error_without_reordering() {
    let temp = tempfile::tempdir().unwrap();
    let paths = AppPaths::with_base(temp.path().join("base"));
    let projects = maestro_shell::ProjectService::new(&paths);
    projects
        .create(
            "project",
            "Custom project",
            temp.path().to_string_lossy(),
            maestro_shell::NewProject::default(),
            1,
        )
        .unwrap();
    let windows = WindowLayoutService::new(&paths);
    for id in ["first", "second"] {
        windows.create_empty(id, 2).unwrap();
    }
    projects
        .reorder_windows("project", &["second".into(), "first".into()], 3)
        .unwrap();
    let before = projects.load("project").unwrap().unwrap();
    windows.rename_window("first", "ledger rewrite", 4).unwrap();
    let updated = apply_react_window_rename(&paths, "project", "second", "ledger rewrite").unwrap();
    assert_eq!(
        updated.name,
        Some(unique_window_name(
            &paths,
            "project",
            "second",
            "ledger rewrite"
        ))
    );
    assert_ne!(updated.name.as_deref(), Some("ledger rewrite"));
    assert_eq!(projects.load("project").unwrap().unwrap(), before);
    assert!(apply_react_window_rename(&paths, "project", "missing", "draft").is_err());
    assert!(windows.load("missing").unwrap().is_none());
    assert_eq!(projects.load("project").unwrap().unwrap(), before);
}
