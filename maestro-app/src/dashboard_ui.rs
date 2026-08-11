//! Dashboard React-chrome asset resolution for the native WebView hosts.
//!
//! The Rust terminal remains native. This module only finds the bundled/static
//! React chrome entrypoint loaded by the platform WebView host.

use std::path::{Path, PathBuf};

pub const DASHBOARD_UI_RESOURCE_DIR: &str = "dashboard-ui";
pub const DASHBOARD_UI_INDEX_FILE: &str = "index.html";
pub const DASHBOARD_UI_DEFAULT_INTENT_POST: &str = "(function (intent) { (window.__HYDRA_DASHBOARD_INTENTS__ = window.__HYDRA_DASHBOARD_INTENTS__ || []).push(intent); })";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DashboardUiAssetSource {
    Explicit,
    AppBundle,
    DevRepo,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardUiAssetResolution {
    pub source: DashboardUiAssetSource,
    pub index_html: PathBuf,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DashboardUiAssetCandidates {
    pub explicit: Option<PathBuf>,
    pub app_bundle: PathBuf,
    pub dev_repo: PathBuf,
}

/// Asset sources the current binary is allowed to trust.
///
/// A production build is deliberately unable to select an explicit path or a development-tree
/// asset. This keeps the privileged dashboard WebView pinned to assets shipped beside the native
/// executable even if a future caller starts passing an environment-derived override.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum DashboardUiAssetPolicy {
    BundledOnly,
    Development,
}

impl DashboardUiAssetPolicy {
    const fn for_current_build() -> Self {
        if cfg!(debug_assertions) {
            Self::Development
        } else {
            Self::BundledOnly
        }
    }
}

pub fn dashboard_ui_index_in_resources(resources_dir: &Path) -> PathBuf {
    resources_dir
        .join(DASHBOARD_UI_RESOURCE_DIR)
        .join(DASHBOARD_UI_INDEX_FILE)
}

pub fn dashboard_ui_index_near_macos_executable(executable: &Path) -> PathBuf {
    let Some(executable_dir) = executable.parent() else {
        return PathBuf::from(DASHBOARD_UI_RESOURCE_DIR).join(DASHBOARD_UI_INDEX_FILE);
    };

    // Packaged Hydra launches the Rust binary from Contents/Resources/bin, not Contents/MacOS.
    // In that layout the dashboard lives beside bin under Contents/Resources/dashboard-ui.
    if executable_dir.file_name().is_some_and(|name| name == "bin") {
        if let Some(resources_dir) = executable_dir
            .parent()
            .filter(|path| path.file_name().is_some_and(|name| name == "Resources"))
        {
            return dashboard_ui_index_in_resources(resources_dir);
        }
    }

    executable_dir
        .parent()
        .map(|contents_dir| dashboard_ui_index_in_resources(&contents_dir.join("Resources")))
        .unwrap_or_else(|| PathBuf::from(DASHBOARD_UI_RESOURCE_DIR).join(DASHBOARD_UI_INDEX_FILE))
}

/// Resolve dashboard assets relative to the installed executable on every desktop platform.
/// Linux packages and relocatable tarballs use `<root>/bin/maestro-app` with assets at
/// `<root>/dashboard-ui/index.html`; macOS keeps `Contents/Resources/{bin,dashboard-ui}`.
pub fn dashboard_ui_index_near_packaged_executable(executable: &Path) -> PathBuf {
    let Some(executable_dir) = executable.parent() else {
        return PathBuf::from(DASHBOARD_UI_RESOURCE_DIR).join(DASHBOARD_UI_INDEX_FILE);
    };
    if executable_dir.file_name().is_some_and(|name| name == "bin") {
        if let Some(package_root) = executable_dir.parent() {
            if package_root
                .file_name()
                .is_some_and(|name| name == "Resources")
            {
                return dashboard_ui_index_in_resources(package_root);
            }
            return package_root
                .join(DASHBOARD_UI_RESOURCE_DIR)
                .join(DASHBOARD_UI_INDEX_FILE);
        }
    }
    dashboard_ui_index_near_macos_executable(executable)
}

pub fn dashboard_ui_index_in_dev_repo(repo_root: &Path) -> PathBuf {
    repo_root
        .join(DASHBOARD_UI_RESOURCE_DIR)
        .join("dist")
        .join(DASHBOARD_UI_INDEX_FILE)
}

pub fn dashboard_ui_asset_candidates(
    explicit_index_html: Option<&Path>,
    executable: &Path,
    repo_root: &Path,
) -> DashboardUiAssetCandidates {
    DashboardUiAssetCandidates {
        explicit: explicit_index_html.map(Path::to_path_buf),
        app_bundle: dashboard_ui_index_near_packaged_executable(executable),
        dev_repo: dashboard_ui_index_in_dev_repo(repo_root),
    }
}

pub fn resolve_dashboard_ui_asset(
    explicit_index_html: Option<&Path>,
    executable: &Path,
    repo_root: &Path,
) -> Option<DashboardUiAssetResolution> {
    resolve_dashboard_ui_asset_with_policy(
        DashboardUiAssetPolicy::for_current_build(),
        explicit_index_html,
        executable,
        repo_root,
    )
}

fn resolve_dashboard_ui_asset_with_policy(
    policy: DashboardUiAssetPolicy,
    explicit_index_html: Option<&Path>,
    executable: &Path,
    repo_root: &Path,
) -> Option<DashboardUiAssetResolution> {
    let candidates = dashboard_ui_asset_candidates(explicit_index_html, executable, repo_root);

    if policy == DashboardUiAssetPolicy::Development {
        if let Some(path) = candidates.explicit {
            if path.is_file() {
                return Some(DashboardUiAssetResolution {
                    source: DashboardUiAssetSource::Explicit,
                    index_html: path,
                });
            }
        }
    }

    if candidates.app_bundle.is_file() {
        return Some(DashboardUiAssetResolution {
            source: DashboardUiAssetSource::AppBundle,
            index_html: candidates.app_bundle,
        });
    }

    if policy == DashboardUiAssetPolicy::Development && candidates.dev_repo.is_file() {
        return Some(DashboardUiAssetResolution {
            source: DashboardUiAssetSource::DevRepo,
            index_html: candidates.dev_repo,
        });
    }

    None
}

pub fn dashboard_ui_file_url(index_html: &Path, query: Option<&str>) -> String {
    let mut url = String::from("file://");
    url.push_str(&percent_encode_file_path(&index_html.to_string_lossy()));
    if let Some(query) = query.and_then(non_empty_query) {
        url.push('?');
        url.push_str(query.trim_start_matches('?'));
    }
    url
}

fn non_empty_query(query: &str) -> Option<&str> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        None
    } else {
        Some(trimmed)
    }
}

fn percent_encode_file_path(path: &str) -> String {
    let mut out = String::new();
    for b in path.bytes() {
        match b {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'/' | b'-' | b'_' | b'.' | b'~' => {
                out.push(char::from(b))
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// Build the JavaScript preload bridge the native WebView host injects before the React dashboard
/// bundle runs. The injected object matches `dashboard-ui/src/ipc/bridge.ts`.
///
/// `initial_model` must already be the dashboard model envelope the React app consumes. The
/// `post_intent_expression` is a JavaScript expression called with one argument (`intent`), e.g. a
/// WebView message handler wrapper. Keeping it injectable lets tests and future macOS/WebKit code
/// share the same contract without adding a WebView dependency here.
pub fn dashboard_ui_host_preload_script(
    initial_model: &serde_json::Value,
    post_intent_expression: &str,
) -> String {
    let model_json = dashboard_ui_inline_json(initial_model);
    let post_intent_expression =
        sanitize_dashboard_ui_post_intent_expression(post_intent_expression);
    format!(
        r#"(function () {{
  "use strict";
  // This host bridge is injected TWICE: once via with_initialization_script (before the page runs), then AGAIN via
  // evaluate_script after the React page loads (inject_react_chrome_bridge_after_load). The second run must NOT rebuild
  // the bridge with a fresh empty listeners array — that would orphan React's already-registered onDashboardModel
  // listener, so native model pushes (window.__HYDRA_DASHBOARD_SET_MODEL__) would reach nobody and the sidebar/topbar
  // would go stale until app restart. Guard: if the bridge already exists, just refresh the model into the EXISTING
  // listeners and return. `listeners`/`model` also live on `window` so every injection AND React share ONE array.
  if (window.hydraDashboard && window.__HYDRA_DASHBOARD_SET_MODEL__) {{
    try {{ window.__HYDRA_DASHBOARD_SET_MODEL__({model_json}); }} catch (_) {{}}
    return;
  }}
  if (!window.__hydraDashboardListeners) {{ window.__hydraDashboardListeners = []; }}
  var listeners = window.__hydraDashboardListeners;
  var model = {model_json};
  var nextRequestId = 1;
  var folderPickers = {{}};
  var postIntent = {post_intent_expression};
  try {{
    var preloadMessage = JSON.stringify({{
      type: "dashboardPreloadBareProbe",
      has_ipc: !!(window.ipc && window.ipc.postMessage),
      has_webkit_ipc: !!(window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.ipc),
      href: String(window.location && window.location.href || ""),
      ready_state: String(document.readyState || "")
    }});
    if (window.ipc && window.ipc.postMessage) {{
      window.ipc.postMessage(preloadMessage);
    }}
    if (window.webkit && window.webkit.messageHandlers && window.webkit.messageHandlers.ipc) {{
      window.webkit.messageHandlers.ipc.postMessage(preloadMessage);
    }}
  }} catch (probeError) {{
    setTimeout(function () {{ throw probeError; }}, 0);
  }}
  function postDiagnostic(type, extra) {{
    try {{
      postIntent(Object.assign({{
        type: type,
        has_ipc: !!(window.ipc && window.ipc.postMessage),
        href: String(window.location && window.location.href || "")
      }}, extra || {{}}));
    }} catch (_) {{}}
  }}
  postDiagnostic("dashboardPreloadReady", {{ ready_state: String(document.readyState || "") }});
  window.addEventListener("error", function (event) {{
    postIntent({{ type: "dashboardRuntimeError", message: String(event.message || "error"), source: String(event.filename || ""), line: event.lineno || 0 }});
  }});
  window.addEventListener("unhandledrejection", function (event) {{
    postIntent({{ type: "dashboardRuntimeError", message: String(event.reason || "unhandled rejection"), source: "promise", line: 0 }});
  }});
  window.hydraDashboard = {{
    getDashboardModel: function () {{
      return model;
    }},
    postIntent: function (intent) {{
      postIntent(intent);
    }},
    pickProjectFolder: function () {{
      var requestId = "folder-" + String(nextRequestId++);
      postIntent({{ type: "pickProjectFolder", request_id: requestId }});
      return new Promise(function (resolve) {{
        folderPickers[requestId] = resolve;
      }});
    }},
    onDashboardModel: function (listener) {{
      listeners.push(listener);
      return function () {{
        // Splice in place — NEVER reassign `listeners` (that would drop the window-global identity so a later
        // __HYDRA_DASHBOARD_SET_MODEL__ push and this closure would diverge, re-orphaning React).
        var idx = listeners.indexOf(listener);
        if (idx !== -1) {{ listeners.splice(idx, 1); }}
      }};
    }}
  }};
  window.__HYDRA_DASHBOARD_SET_MODEL__ = function (nextModel) {{
    model = nextModel;
    listeners.slice().forEach(function (listener) {{ listener(model); }});
    window.dispatchEvent(new CustomEvent("hydra-dashboard-model", {{ detail: model }}));
  }};
  var previousFolderPickResolver = window.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__;
  window.__HYDRA_DASHBOARD_RESOLVE_FOLDER_PICK__ = function (requestId, path) {{
    var resolve = folderPickers[requestId];
    if (resolve) {{
      delete folderPickers[requestId];
      resolve(path || null);
      return;
    }}
    if (typeof previousFolderPickResolver === "function") {{
      previousFolderPickResolver(requestId, path || null);
    }}
  }};
}})();"#
    )
}

fn sanitize_dashboard_ui_post_intent_expression(raw: &str) -> &str {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('\n')
        || trimmed.contains('\r')
        || trimmed.contains("</script")
    {
        DASHBOARD_UI_DEFAULT_INTENT_POST
    } else {
        trimmed
    }
}

fn dashboard_ui_inline_json(value: &serde_json::Value) -> String {
    serde_json::to_string(value)
        .expect("serde_json::Value serializes")
        .replace("</", "<\\/")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dashboard_ui_index_in_resources_matches_packaged_layout() {
        let path = dashboard_ui_index_in_resources(Path::new("/App.app/Contents/Resources"));
        assert_eq!(
            path,
            PathBuf::from("/App.app/Contents/Resources/dashboard-ui/index.html")
        );
    }

    #[test]
    fn dashboard_ui_index_near_resources_bin_executable_matches_packaged_layout() {
        let path = dashboard_ui_index_near_macos_executable(Path::new(
            "/App.app/Contents/Resources/bin/maestro-app",
        ));
        assert_eq!(
            path,
            PathBuf::from("/App.app/Contents/Resources/dashboard-ui/index.html")
        );
    }

    #[test]
    fn dashboard_ui_index_near_linux_bin_is_relocatable() {
        let path = dashboard_ui_index_near_packaged_executable(Path::new(
            "/home/user/Apps/Hydra/bin/maestro-app",
        ));
        assert_eq!(
            path,
            PathBuf::from("/home/user/Apps/Hydra/dashboard-ui/index.html")
        );
    }

    #[test]
    fn dashboard_ui_index_near_macos_executable_matches_standard_layout() {
        let path =
            dashboard_ui_index_near_macos_executable(Path::new("/App.app/Contents/MacOS/Hydra"));
        assert_eq!(
            path,
            PathBuf::from("/App.app/Contents/Resources/dashboard-ui/index.html")
        );
    }

    #[test]
    fn dashboard_ui_index_near_macos_executable_walks_to_resources() {
        let path =
            dashboard_ui_index_near_macos_executable(Path::new("/App.app/Contents/MacOS/Hydra"));
        assert_eq!(
            path,
            PathBuf::from("/App.app/Contents/Resources/dashboard-ui/index.html")
        );
    }

    #[test]
    fn dashboard_ui_index_in_dev_repo_points_at_vite_dist() {
        let path = dashboard_ui_index_in_dev_repo(Path::new("/repo"));
        assert_eq!(path, PathBuf::from("/repo/dashboard-ui/dist/index.html"));
    }

    #[test]
    fn development_asset_policy_prefers_explicit_then_bundle_then_dev() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();

        let explicit = root.join("custom.html");
        let bundle = root.join("Hydra.app/Contents/Resources/dashboard-ui/index.html");
        let exe = root.join("Hydra.app/Contents/MacOS/Hydra");
        let dev = root.join("dashboard-ui/dist/index.html");

        std::fs::create_dir_all(bundle.parent().expect("bundle parent")).expect("bundle dirs");
        std::fs::create_dir_all(exe.parent().expect("exe parent")).expect("exe dirs");
        std::fs::create_dir_all(dev.parent().expect("dev parent")).expect("dev dirs");

        let resolve = || {
            resolve_dashboard_ui_asset_with_policy(
                DashboardUiAssetPolicy::Development,
                Some(&explicit),
                &exe,
                root,
            )
        };
        std::fs::write(&dev, "").expect("dev index");
        let resolved = resolve().expect("dev");
        assert_eq!(resolved.source, DashboardUiAssetSource::DevRepo);
        assert_eq!(resolved.index_html, dev);

        std::fs::write(&bundle, "").expect("bundle index");
        let resolved = resolve().expect("bundle");
        assert_eq!(resolved.source, DashboardUiAssetSource::AppBundle);
        assert_eq!(resolved.index_html, bundle);

        std::fs::write(&explicit, "").expect("explicit index");
        let resolved = resolve().expect("explicit");
        assert_eq!(resolved.source, DashboardUiAssetSource::Explicit);
        assert_eq!(resolved.index_html, explicit);
    }

    #[test]
    fn bundled_only_policy_rejects_explicit_and_dev_repo_assets() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let explicit = root.join("custom.html");
        let exe = root.join("Hydra/bin/maestro-app");
        let bundle = root.join("Hydra/dashboard-ui/index.html");
        let dev = root.join("dashboard-ui/dist/index.html");

        std::fs::create_dir_all(dev.parent().expect("dev parent")).expect("dev dirs");
        std::fs::write(&explicit, "explicit").expect("explicit index");
        std::fs::write(&dev, "dev").expect("dev index");

        assert_eq!(
            resolve_dashboard_ui_asset_with_policy(
                DashboardUiAssetPolicy::BundledOnly,
                Some(&explicit),
                &exe,
                root,
            ),
            None,
            "production policy must not load explicit or development-tree assets"
        );

        std::fs::create_dir_all(bundle.parent().expect("bundle parent")).expect("bundle dirs");
        std::fs::write(&bundle, "bundle").expect("bundle index");
        let resolved = resolve_dashboard_ui_asset_with_policy(
            DashboardUiAssetPolicy::BundledOnly,
            Some(&explicit),
            &exe,
            root,
        )
        .expect("bundled asset");
        assert_eq!(resolved.source, DashboardUiAssetSource::AppBundle);
        assert_eq!(resolved.index_html, bundle);
    }

    #[test]
    fn public_resolver_exposes_development_assets_only_in_debug_builds() {
        let tmp = tempfile::tempdir().expect("tempdir");
        let root = tmp.path();
        let exe = root.join("Hydra/bin/maestro-app");
        let dev = root.join("dashboard-ui/dist/index.html");

        std::fs::create_dir_all(dev.parent().expect("dev parent")).expect("dev dirs");
        std::fs::write(&dev, "dev").expect("dev index");

        let resolved = resolve_dashboard_ui_asset(None, &exe, root);
        if cfg!(debug_assertions) {
            assert_eq!(
                resolved,
                Some(DashboardUiAssetResolution {
                    source: DashboardUiAssetSource::DevRepo,
                    index_html: dev,
                })
            );
        } else {
            assert_eq!(
                resolved, None,
                "release resolver must ignore explicit and development-tree assets"
            );
        }
    }

    #[test]
    fn dashboard_ui_file_url_encodes_spaces_and_appends_query() {
        let url = dashboard_ui_file_url(
            Path::new("/Applications/Hydra App.app/Contents/Resources/dashboard-ui/index.html"),
            Some("chrome=sidebar"),
        );
        assert_eq!(
            url,
            "file:///Applications/Hydra%20App.app/Contents/Resources/dashboard-ui/index.html?chrome=sidebar"
        );
    }

    #[test]
    fn host_preload_installs_bridge_with_initial_model_and_intent_post() {
        let model = serde_json::json!({
            "ok": true,
            "projects": [
                { "project_id": "p1", "name": "Project One" }
            ]
        });

        let script = dashboard_ui_host_preload_script(
            &model,
            "(function (intent) { window.webkit.messageHandlers.hydra.postMessage(intent); })",
        );

        assert!(script.contains("window.hydraDashboard"));
        assert!(script.contains("getDashboardModel"));
        assert!(script.contains("postIntent"));
        assert!(script.contains("onDashboardModel"));
        assert!(script.contains("window.__HYDRA_DASHBOARD_SET_MODEL__"));
        assert!(script.contains("\"project_id\":\"p1\""));
        assert!(script.contains("window.webkit.messageHandlers.hydra.postMessage"));
        assert!(!script.contains("dashboardDocumentClick"));
        assert!(!script.contains("target.value"));
    }

    #[test]
    fn host_preload_falls_back_for_unsafe_post_expression() {
        let model = serde_json::json!({ "ok": true });
        let script = dashboard_ui_host_preload_script(&model, "x\n</script>");

        assert!(script.contains(DASHBOARD_UI_DEFAULT_INTENT_POST));
        assert!(!script.contains("x\n</script>"));
    }

    #[test]
    fn host_preload_escapes_inline_script_closer_in_model() {
        let model = serde_json::json!({ "label": "</script><script>alert(1)</script>" });
        let script = dashboard_ui_host_preload_script(&model, "");

        assert!(!script.contains("</script>"));
        assert!(script.contains("<\\/script>"));
    }
}
