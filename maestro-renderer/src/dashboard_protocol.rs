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

/// WebView2 exposes WRY's private scheme through an HTTPS host mapping. Navigation and IPC must
/// accept exactly the mapped document, never the public network origin or a neighboring surface.
#[cfg(any(windows, test))]
pub(crate) fn windows_dashboard_document_is_trusted(candidate: &str, canonical: &str) -> bool {
    canonical
        .strip_prefix("hydra://localhost/")
        .is_some_and(|document| candidate == format!("https://hydra.localhost/{document}"))
}

/// Bundled dashboard asset root and the private URL one surface loads.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DashboardAssetServing {
    root: PathBuf,
    pub(crate) url: String,
}

impl DashboardAssetServing {
    /// Derive a private custom-origin URL from the app's trusted
    /// `file:///.../index.html?chrome=...` configuration.
    #[cfg(any(unix, test))]
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
        // Standard Windows file URLs have one URI separator before the drive prefix. It is not
        // part of the native path (and would otherwise turn an absolute drive into a rooted path).
        #[cfg(windows)]
        let decoded = decoded
            .strip_prefix('/')
            .filter(|path| path.as_bytes().get(1) == Some(&b':'))
            .unwrap_or(&decoded);
        let index_path = PathBuf::from(decoded);
        Self::from_index_path(&index_path, query)
    }

    /// Preserve the native path, including Win32 verbatim/UNC semantics. It is app-owned bundle
    /// configuration, not a path supplied by JavaScript or reconstructed from a navigation URL.
    pub(crate) fn from_index_path(index_path: &Path, query: Option<&str>) -> Option<Self> {
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

    /// Native Windows descriptors preserve the original path separately from the private URL.
    /// Escape the basename only: directory names never enter the browser's URL or origin.
    pub(crate) fn native_surface(index_path: &Path, query: &str) -> Option<Self> {
        let mut serving = Self::from_index_path(index_path, Some(query))?;
        let mut name = String::new();
        for byte in index_path.file_name()?.to_str()?.bytes() {
            match byte {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    name.push(char::from(byte));
                }
                _ => name.push_str(&format!("%{byte:02X}")),
            }
        }
        serving.url =
            format!("{DASHBOARD_PROTOCOL_SCHEME}://{DASHBOARD_PROTOCOL_AUTHORITY}/{name}?{query}");
        Some(serving)
    }

    #[cfg(any(windows, test))]
    pub(crate) fn checked_native_surface(
        index_path: &Path,
        query: &str,
        expected_url: &str,
    ) -> Option<Self> {
        Self::native_surface(index_path, query).filter(|serving| serving.url == expected_url)
    }

    /// Related surfaces may reuse one registered protocol only when they load the same bundle.
    #[cfg(any(unix, test))]
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

    #[cfg(not(windows))]
    const SIDEBAR_FILE: &str = "file:///opt/hydra/dashboard-ui/index.html?chrome=sidebar";
    #[cfg(windows)]
    const SIDEBAR_FILE: &str = "file:///C:/Hydra/dashboard-ui/index.html?chrome=sidebar";
    const SIDEBAR: &str = "hydra://localhost/index.html?chrome=sidebar";
    const TOPBAR: &str = "hydra://localhost/index.html?chrome=topbar";

    #[test]
    fn related_surfaces_share_only_the_same_asset_root() {
        let sidebar = DashboardAssetServing::from_file_url(SIDEBAR_FILE).unwrap();
        let topbar =
            DashboardAssetServing::from_file_url(&SIDEBAR_FILE.replace("sidebar", "topbar"))
                .unwrap();
        let foreign = DashboardAssetServing::from_file_url(
            &SIDEBAR_FILE.replace("dashboard-ui", "other-assets"),
        )
        .unwrap();
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
    fn windows_accepts_only_exact_https_mapped_document_for_navigation_and_ipc() {
        assert!(windows_dashboard_document_is_trusted(
            "https://hydra.localhost/index.html?chrome=sidebar",
            SIDEBAR
        ));
        for other in [
            SIDEBAR,
            "http://hydra.localhost/index.html?chrome=sidebar",
            "https://hydra.localhost.evil.test/index.html?chrome=sidebar",
            "https://hydra.localhost/index.html?chrome=overlay",
            "https://hydra.localhost/index.html?chrome=sidebar#fragment",
            "https://hydra.localhost:443/index.html?chrome=sidebar",
        ] {
            assert!(!windows_dashboard_document_is_trusted(other, SIDEBAR));
        }
    }

    #[test]
    fn native_asset_path_keeps_root_and_serves_encoded_basename() {
        let root = std::env::temp_dir().join(format!(
            "hydra-native-asset-{}-{} #1% 工作区",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).unwrap();
        let index = root.join("screen #%.工作.html");
        std::fs::write(&index, b"native bundle").unwrap();
        let chrome =
            crate::RendererReactChrome::from_native_asset(&index, "preload".into(), 300, 44)
                .unwrap();
        let serving =
            DashboardAssetServing::checked_native_surface(&index, "chrome=sidebar", &chrome.url)
                .unwrap();
        assert_eq!(serving.root.as_os_str(), root.as_os_str());
        assert_eq!(
            chrome.url,
            "hydra://localhost/screen%20%23%25.%E5%B7%A5%E4%BD%9C.html?chrome=sidebar"
        );
        assert_eq!(chrome.initialization_script, "preload");
        for wrong_url in [
            &chrome.top_url,
            &format!("{}#fragment", chrome.url),
            "https://foreign.invalid/index.html?chrome=sidebar",
        ] {
            assert!(DashboardAssetServing::checked_native_surface(
                &index,
                "chrome=sidebar",
                wrong_url
            )
            .is_none());
        }
        let response = serving.serve(
            wry::http::Request::builder()
                .uri(&chrome.url)
                .body(Vec::new())
                .unwrap(),
        );
        assert_eq!(response.status(), 200);
        assert_eq!(response.body().as_ref(), b"native bundle");
        std::fs::remove_dir_all(root).unwrap();
    }

    #[cfg(windows)]
    #[test]
    fn windows_native_asset_paths_preserve_drive_unc_and_verbatim_semantics() {
        use std::os::windows::ffi::OsStringExt;
        for raw in [
            r"C:\Hydra #1%\工作区\index.html",
            r"C:/Hydra/工作区/index.html",
            r"\\server\share\Hydra #1%\index.html",
            r"\\?\C:\Hydra. \index.html",
            r"\\?\UNC\server\share\Hydra. \index.html",
        ] {
            let index = Path::new(raw);
            let chrome =
                crate::RendererReactChrome::from_native_asset(index, String::new(), 300, 44)
                    .unwrap();
            assert_eq!(chrome.index_html.as_os_str(), index.as_os_str());
            let serving = DashboardAssetServing::checked_native_surface(
                &chrome.index_html,
                "chrome=sidebar",
                &chrome.url,
            )
            .unwrap();
            assert_eq!(
                serving.root.as_os_str(),
                index.parent().unwrap().as_os_str()
            );
            assert_eq!(chrome.url, SIDEBAR);
        }
        for raw in [
            "",
            "relative/index.html",
            r"C:index.html",
            r"\index.html",
            r"\\.\COM1",
        ] {
            assert!(
                crate::RendererReactChrome::from_native_asset(
                    Path::new(raw),
                    String::new(),
                    300,
                    44
                )
                .is_err(),
                "{raw}"
            );
        }
        let invalid_name = Path::new(r"C:\Hydra").join(std::ffi::OsString::from_wide(&[0xD800]));
        assert!(crate::RendererReactChrome::from_native_asset(
            &invalid_name,
            String::new(),
            300,
            44
        )
        .is_err());
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
