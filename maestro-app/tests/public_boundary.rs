use std::path::Path;

const ROOT_MANIFEST: &str = include_str!("../../Cargo.toml");
const APP_MANIFEST: &str = include_str!("../Cargo.toml");
const APP_LIB: &str = include_str!("../src/lib.rs");
const APP_MAIN: &str = include_str!("../src/main.rs");
const MODEL_CATALOG: &str = include_str!("../src/model_catalog.rs");
const OPTIONAL_EXTENSION: &str = include_str!("../src/optional_extension.rs");
const UPDATE_CHECK: &str = include_str!("../src/update_check.rs");

fn optional_extension_production_source() -> &'static str {
    OPTIONAL_EXTENSION
        .split_once("\n#[cfg(test)]")
        .map(|(production, _tests)| production)
        .expect("optional extension keeps its tests behind one cfg(test) boundary")
}

#[test]
fn public_workspace_excludes_the_private_agent_and_cloud_build_binding() {
    assert!(!ROOT_MANIFEST.contains("\"hydra-agent\""));
    assert!(!ROOT_MANIFEST.contains("profile.dev.package.hydra-agent"));
    assert!(!APP_MANIFEST.contains("build = \"build.rs\""));
    assert!(!APP_LIB.contains("desktop_environment"));
    assert!(!APP_LIB.contains("pub mod remote_access"));

    let app_dir = Path::new(env!("CARGO_MANIFEST_DIR"));
    for removed in [
        "build.rs",
        "src/desktop_environment.rs",
        "src/remote_access.rs",
    ] {
        assert!(
            !app_dir.join(removed).exists(),
            "private boundary file returned to the public app: {removed}"
        );
    }
}

#[test]
fn public_app_contains_no_private_trust_tuple_or_agent_lifecycle_path() {
    // The public test proves the shape it owns without publishing the private verifier's exact
    // trust-marker denylist. There is no build hook, caller-selected executable, argument list,
    // environment injection, or generic command surface through which the public app could choose
    // a trust tuple. The private composition separately scans this whole tree for its exact values.
    assert!(!APP_MANIFEST.contains("build ="));
    let production = optional_extension_production_source();
    assert_eq!(production.matches("Command::new(").count(), 1);
    assert!(production.contains("Command::new(binary)"));
    assert!(production.contains(".arg(EXTENSION_COMMAND)"));
    assert!(!production.contains(".args("));
    assert!(!production.contains(".env("));
    assert!(!production.contains(".envs("));
    assert!(OPTIONAL_EXTENSION.contains(
        "pub fn discover_installed_extension(\n    current_exe: Option<&Path>,\n    is_executable_file: impl Fn(&Path) -> bool,"
    ));
    assert!(OPTIONAL_EXTENSION.contains("current_exe?.parent()?.join(EXTENSION_BINARY_NAME)"));
}

#[test]
fn public_app_defaults_remote_presentation_and_authority_off() {
    assert!(APP_MAIN.contains("\"remote_available\".to_string()"));
    assert!(APP_MAIN.contains("\"remote_open\".to_string()"));
    assert!(OPTIONAL_EXTENSION.contains("pub available: bool"));
    assert!(OPTIONAL_EXTENSION.contains("RemoteExtensionProjection::default()"));
    assert!(APP_MAIN.contains(
        "let available = projection.available && projection.filesystem_mode_migration.is_none();"
    ));
    assert!(APP_MAIN.contains("available && projection.remote_open"));
}

#[test]
fn optional_extension_has_one_fixed_command_and_no_secret_or_trust_argv() {
    let production = optional_extension_production_source();
    assert!(production.contains(".arg(EXTENSION_COMMAND)"));
    assert!(!production.contains(".args("));
    assert!(!production.contains(".env("));
    assert!(!production.contains(".envs("));
    assert!(OPTIONAL_EXTENSION.contains("RemoteDesktopHostRequest::Enroll { request_id, code }"));
}

#[test]
fn public_distribution_network_is_default_off_and_has_no_runtime_origin_override() {
    assert!(APP_MANIFEST.contains("default = []"));
    assert!(APP_MANIFEST.contains("official-distribution = []"));
    assert!(UPDATE_CHECK.contains("cfg(feature = \"official-distribution\")"));
    assert!(MODEL_CATALOG.contains("cfg(feature = \"official-distribution\")"));
    assert!(!UPDATE_CHECK.contains("HYDRA_UPDATE_URL"));
    assert!(!MODEL_CATALOG.contains("HYDRA_MODEL_CATALOG_URL"));
}
