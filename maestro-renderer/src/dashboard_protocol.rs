//! Private custom-protocol serving for the bundled dashboard UI.
//!
//! WRY turns a page's current URL into an `http::Request` before dispatching IPC on both WKWebView
//! and WebKitGTK. A bundled `file:///.../index.html` URL has no authority and is not a valid
//! HTTP-style request URI, so macOS skips the IPC callback and Linux can panic before reaching it.
//! Serve the same trusted files from `hydra://localhost/...` instead. The valid authority keeps WRY's
//! transport intact; exact-document navigation and IPC policy remain the responsibility of each host.

use std::borrow::Cow;
use std::path::{Component, Path, PathBuf};

pub(crate) const DASHBOARD_PROTOCOL_SCHEME: &str = "hydra";
const DASHBOARD_PROTOCOL_AUTHORITY: &str = "localhost";

/// Bundled dashboard asset root and the private URL one surface loads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DashboardAssetServing {
    root: PathBuf,
    pub(crate) url: String,
}

impl DashboardAssetServing {
    /// Derive a private custom-origin URL from the app's trusted
    /// `file:///.../index.html?chrome=...` configuration.
    pub(crate) fn from_file_url(file_url: &str) -> Option<Self> {
        let rest = file_url.strip_prefix("file://")?;
        if rest.contains('#') {
            return None;
        }
        let (path_part, query) = match rest.split_once('?') {
            Some((path, query)) if !query.is_empty() => (path, Some(query)),
            Some(_) => return None,
            None => (rest, None),
        };
        let decoded = percent_decode(path_part)?;
        let index_path = PathBuf::from(decoded);
        if !index_path.is_absolute() {
            return None;
        }
        let root = index_path.parent()?.to_path_buf();
        if root.as_os_str().is_empty() {
            return None;
        }
        let index_name = index_path.file_name()?.to_str()?;
        if index_name.is_empty() || index_name.contains('/') {
            return None;
        }
        let mut url =
            format!("{DASHBOARD_PROTOCOL_SCHEME}://{DASHBOARD_PROTOCOL_AUTHORITY}/{index_name}");
        if let Some(query) = query {
            url.push('?');
            url.push_str(query);
        }
        Some(Self { root, url })
    }

    /// Related surfaces may reuse one registered protocol only when they load the same bundle.
    pub(crate) fn shares_asset_root(&self, primary: &Self) -> bool {
        self.root == primary.root
    }

    /// Serve one request from the trusted bundle root. Only the exact private origin is accepted,
    /// and decoded traversal/absolute components are rejected before any filesystem read.
    pub(crate) fn serve(
        &self,
        request: wry::http::Request<Vec<u8>>,
    ) -> wry::http::Response<Cow<'static, [u8]>> {
        if request.uri().scheme_str() != Some(DASHBOARD_PROTOCOL_SCHEME)
            || request.uri().authority().map(|value| value.as_str())
                != Some(DASHBOARD_PROTOCOL_AUTHORITY)
        {
            eprintln!(
                "hydra-dashboard protocol rejected foreign origin uri_bytes={}",
                request.uri().to_string().len()
            );
            return not_found();
        }

        let relative = request.uri().path().trim_start_matches('/');
        let relative = if relative.is_empty() {
            "index.html"
        } else {
            relative
        };
        let Some(relative) = percent_decode(relative) else {
            eprintln!("hydra-dashboard protocol rejected malformed path encoding");
            return not_found();
        };
        let mut safe = PathBuf::new();
        for component in Path::new(&relative).components() {
            match component {
                Component::Normal(segment) => safe.push(segment),
                _ => {
                    eprintln!("hydra-dashboard protocol rejected unsafe path");
                    return not_found();
                }
            }
        }

        let full = self.root.join(safe);
        match std::fs::read(&full) {
            Ok(bytes) => wry::http::Response::builder()
                .status(200)
                .header("Content-Type", content_type_for(&full))
                .body(Cow::<'static, [u8]>::Owned(bytes))
                .unwrap_or_else(|error| {
                    eprintln!("hydra-dashboard protocol response build failed: {error}");
                    not_found()
                }),
            Err(error) => {
                eprintln!(
                    "hydra-dashboard protocol 404 for {} ({error})",
                    full.display()
                );
                not_found()
            }
        }
    }
}

fn percent_decode(value: &str) -> Option<String> {
    let bytes = value.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' {
            let high = (*bytes.get(index + 1)? as char).to_digit(16)?;
            let low = (*bytes.get(index + 2)? as char).to_digit(16)?;
            output.push((high * 16 + low) as u8);
            index += 3;
        } else {
            output.push(bytes[index]);
            index += 1;
        }
    }
    String::from_utf8(output).ok()
}

fn not_found() -> wry::http::Response<Cow<'static, [u8]>> {
    wry::http::Response::builder()
        .status(404)
        .header("Content-Type", "text/plain")
        .body(Cow::<'static, [u8]>::Borrowed(b"not found"))
        .expect("static 404 response is always valid")
}

fn content_type_for(path: &Path) -> &'static str {
    match path.extension().and_then(|extension| extension.to_str()) {
        Some("html") => "text/html",
        Some("js") | Some("mjs") => "text/javascript",
        Some("css") => "text/css",
        Some("json") => "application/json",
        Some("svg") => "image/svg+xml",
        Some("png") => "image/png",
        Some("jpg") | Some("jpeg") => "image/jpeg",
        Some("gif") => "image/gif",
        Some("webp") => "image/webp",
        Some("woff2") => "font/woff2",
        Some("woff") => "font/woff",
        Some("ttf") => "font/ttf",
        Some("ico") => "image/x-icon",
        Some("map") => "application/json",
        _ => "application/octet-stream",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SIDEBAR_FILE: &str = "file:///opt/hydra/dashboard-ui/index.html?chrome=sidebar";
    const SIDEBAR: &str = "hydra://localhost/index.html?chrome=sidebar";
    const TOPBAR: &str = "hydra://localhost/index.html?chrome=topbar";

    #[test]
    fn related_surfaces_share_only_the_same_asset_root() {
        let sidebar = DashboardAssetServing::from_file_url(SIDEBAR_FILE).unwrap();
        let topbar = DashboardAssetServing::from_file_url(
            "file:///opt/hydra/dashboard-ui/index.html?chrome=topbar",
        )
        .unwrap();
        let foreign =
            DashboardAssetServing::from_file_url("file:///tmp/index.html?chrome=topbar").unwrap();
        assert!(topbar.shares_asset_root(&sidebar));
        assert!(!foreign.shares_asset_root(&sidebar));
        assert_eq!(sidebar.url, SIDEBAR);
        assert_eq!(topbar.url, TOPBAR);
    }

    #[test]
    fn valid_authority_custom_url_avoids_the_file_url_invalid_uri() {
        assert!(wry::http::Uri::try_from(SIDEBAR_FILE).is_err());
        assert_eq!(
            wry::http::Uri::try_from(SIDEBAR).unwrap().to_string(),
            SIDEBAR
        );
    }

    #[test]
    fn serves_bundled_assets_and_rejects_foreign_or_traversal_requests() {
        let root = std::env::temp_dir().join(format!(
            "hydra-dashboard-protocol-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        std::fs::write(root.join("index.html"), b"dashboard").unwrap();
        let file_url = format!("file://{}/index.html?chrome=sidebar", root.display());
        let serving = DashboardAssetServing::from_file_url(&file_url).unwrap();

        let response = serving.serve(
            wry::http::Request::builder()
                .uri(&serving.url)
                .body(Vec::new())
                .unwrap(),
        );
        assert_eq!(response.status(), 200);
        assert_eq!(response.headers()["Content-Type"], "text/html");
        assert_eq!(response.body().as_ref(), b"dashboard");

        for uri in [
            "hydra://foreign.invalid/index.html",
            "hydra://localhost/%2e%2e/secret",
            "hydra://localhost/%zz",
        ] {
            let response = serving.serve(
                wry::http::Request::builder()
                    .uri(uri)
                    .body(Vec::new())
                    .unwrap(),
            );
            assert_eq!(response.status(), 404, "{uri}");
        }

        std::fs::remove_dir_all(root).unwrap();
    }
}
