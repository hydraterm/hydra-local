//! Trusted local executable plugins. The host resolves registered action IDs; renderers never
//! supply argv. Plugins run as the current user, with the complete existing CLI/socket surface.
use serde::{Deserialize, Serialize};
use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};

const MAX_BYTES: u64 = 256 * 1024;
pub const ACTION_PREFIX: &str = "plugin:";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    pub schema_version: u32,
    pub id: String,
    pub name: String,
    pub version: String,
    pub actions: Vec<Action>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Action {
    pub id: String,
    pub title: String,
    pub command: Vec<String>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Registration {
    pub manifest: Manifest,
    pub root: PathBuf,
    pub enabled: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Operation {
    InstallLocal(PathBuf),
    List,
    Enable(String, bool),
    Remove(String),
    Run {
        plugin: String,
        action: String,
        args: Vec<String>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PluginCommand {
    pub operation: Operation,
    pub base: Option<PathBuf>,
    pub socket: Option<PathBuf>,
}

pub fn parse(args: &[String]) -> Result<PluginCommand, String> {
    let mut positional = Vec::new();
    let mut base = None;
    let mut socket = None;
    let mut tail = Vec::new();
    let mut iter = args.iter();
    while let Some(arg) = iter.next() {
        match arg.as_str() {
            "--" => {
                tail.extend(iter.cloned());
                break;
            }
            "--base" | "--socket" => {
                let target = if arg == "--base" {
                    &mut base
                } else {
                    &mut socket
                };
                if target.is_some() {
                    return Err(format!("duplicate {arg}"));
                }
                *target = Some(PathBuf::from(
                    iter.next().ok_or_else(|| format!("{arg} needs a path"))?,
                ));
            }
            value if value.starts_with('-') => return Err(format!("unknown plugin flag {value}")),
            _ => positional.push(arg.as_str()),
        }
    }
    let operation = match positional.as_slice() {
        ["install-local", path] => Operation::InstallLocal(PathBuf::from(path)),
        ["list"] => Operation::List,
        ["enable", id] => Operation::Enable((*id).into(), true),
        ["disable", id] => Operation::Enable((*id).into(), false),
        ["remove", id] => Operation::Remove((*id).into()),
        ["run", plugin, action] => Operation::Run {
            plugin: (*plugin).into(), action: (*action).into(), args: tail.clone(),
        },
        _ => return Err("plugin: expected install-local <dir>, list, enable/disable/remove <id>, or run <id> <action> [-- args...]".into()),
    };
    if !matches!(operation, Operation::Run { .. }) && (socket.is_some() || !tail.is_empty()) {
        return Err("--socket and action arguments require plugin run".into());
    }
    Ok(PluginCommand {
        operation,
        base,
        socket,
    })
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-".contains(&b))
        && value != "."
        && value != ".."
}

fn display_text(value: &str) -> bool {
    !value.trim().is_empty() && value.len() <= 160 && !value.chars().any(char::is_control)
}

impl Manifest {
    pub fn validate(&self) -> Result<(), String> {
        if self.schema_version != 1
            || !identifier(&self.id)
            || !display_text(&self.name)
            || !display_text(&self.version)
            || self.actions.is_empty()
        {
            return Err("invalid plugin metadata, schema version, or action count".into());
        }
        let mut ids = BTreeSet::new();
        for action in &self.actions {
            if !identifier(&action.id)
                || !ids.insert(&action.id)
                || !display_text(&action.title)
                || action.command.is_empty()
                || action.command[0].is_empty()
                || action.command.iter().any(|arg| arg.contains('\0'))
            {
                return Err("invalid or duplicate plugin action".into());
            }
        }
        Ok(())
    }
}

fn read_json<T: serde::de::DeserializeOwned>(path: &Path) -> Result<T, String> {
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let file = options
        .open(path)
        .map_err(|e| format!("open plugin data: {e}"))?;
    let metadata = file.metadata().map_err(|e| e.to_string())?;
    if !metadata.is_file() || metadata.len() > MAX_BYTES {
        return Err("plugin data must be a regular file no larger than 256 KiB".into());
    }
    let mut bytes = Vec::new();
    file.take(MAX_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("plugin data exceeds 256 KiB".into());
    }
    serde_json::from_slice(&bytes).map_err(|e| format!("invalid plugin data: {e}"))
}

fn registry(base: &Path) -> PathBuf {
    base.join("plugins")
}

fn entry(base: &Path, id: &str) -> Result<PathBuf, String> {
    if !identifier(id) {
        return Err("invalid plugin id".into());
    }
    Ok(registry(base).join(format!("{id}.json")))
}

fn check_registry(base: &Path) -> Result<(), String> {
    let metadata = fs::symlink_metadata(registry(base)).map_err(|e| e.to_string())?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        return Err("plugin registry must be a real directory".into());
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if metadata.uid() != unsafe { libc::geteuid() } || metadata.mode() & 0o077 != 0 {
            return Err("plugin registry must be owned by this user with mode 0700".into());
        }
    }
    Ok(())
}

fn mutation_guard(base: &Path) -> Result<fs::File, String> {
    let dir = registry(base);
    if !dir.try_exists().map_err(|e| e.to_string())? {
        fs::create_dir_all(base).map_err(|e| e.to_string())?;
        let mut builder = fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        match builder.create(&dir) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(e) => return Err(e.to_string()),
        }
    }
    check_registry(base)?;
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
    }
    let lock = options
        .open(dir.join(".registry.lock"))
        .map_err(|e| e.to_string())?;
    if !lock.metadata().map_err(|e| e.to_string())?.is_file() {
        return Err("plugin registry lock is not a regular file".into());
    }
    #[cfg(unix)]
    {
        use std::os::fd::AsRawFd;
        if unsafe { libc::flock(lock.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
            return Err("plugin registry is being changed; retry this command".into());
        }
    }
    Ok(lock)
}

fn save(base: &Path, registration: &Registration) -> Result<(), String> {
    let dir = registry(base);
    check_registry(base)?;
    let destination = entry(base, &registration.manifest.id)?;
    let bytes = serde_json::to_vec_pretty(registration).map_err(|e| e.to_string())?;
    if bytes.len() as u64 > MAX_BYTES {
        return Err("plugin registration exceeds 256 KiB".into());
    }
    let temporary = dir.join(format!(".{}.tmp", uuid::Uuid::new_v4()));
    let result = (|| {
        let mut options = OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let mut file = options.open(&temporary).map_err(|e| e.to_string())?;
        file.write_all(&bytes)
            .and_then(|()| file.sync_all())
            .map_err(|e| e.to_string())?;
        fs::rename(&temporary, destination).map_err(|e| e.to_string())
    })();
    let _ = fs::remove_file(temporary);
    result
}

pub fn load(base: &Path, id: &str) -> Result<Registration, String> {
    check_registry(base)?;
    let registration: Registration = read_json(&entry(base, id)?)?;
    registration.manifest.validate()?;
    if registration.manifest.id != id || !registration.root.is_absolute() {
        return Err("plugin registration identity/root mismatch".into());
    }
    Ok(registration)
}

#[derive(Debug, Default, Serialize)]
pub struct Inventory {
    pub plugins: Vec<Registration>,
    pub diagnostics: Vec<Diagnostic>,
}

#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub id: String,
    pub error: String,
}

pub fn inventory(base: &Path) -> Result<Inventory, String> {
    if !registry(base).try_exists().map_err(|e| e.to_string())? {
        return Ok(Inventory::default());
    }
    check_registry(base)?;
    let mut result = Inventory::default();
    for child in fs::read_dir(registry(base)).map_err(|e| e.to_string())? {
        let path = child.map_err(|e| e.to_string())?.path();
        if path.extension().and_then(|s| s.to_str()) != Some("json") {
            continue;
        }
        let id = path
            .file_stem()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned();
        match load(base, &id) {
            Ok(registration) => result.plugins.push(registration),
            Err(error) => result.diagnostics.push(Diagnostic { id, error }),
        }
    }
    result
        .plugins
        .sort_by(|a, b| a.manifest.id.cmp(&b.manifest.id));
    result.diagnostics.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(result)
}

pub fn list(base: &Path) -> Result<Vec<Registration>, String> {
    Ok(inventory(base)?.plugins)
}

pub fn install_local(base: &Path, root: &Path) -> Result<Registration, String> {
    let root = root.canonicalize().map_err(|e| e.to_string())?;
    let manifest: Manifest = read_json(&root.join("hydra-plugin.json"))?;
    manifest.validate()?;
    let _guard = mutation_guard(base)?;
    if entry(base, &manifest.id)?
        .try_exists()
        .map_err(|e| e.to_string())?
    {
        return Err("plugin is already registered; remove it before reinstalling".into());
    }
    let registration = Registration {
        manifest,
        root,
        enabled: true,
    };
    save(base, &registration)?;
    Ok(registration)
}

pub fn set_enabled(base: &Path, id: &str, enabled: bool) -> Result<Registration, String> {
    let _guard = mutation_guard(base)?;
    let mut registration = load(base, id)?;
    registration.enabled = enabled;
    save(base, &registration)?;
    Ok(registration)
}

pub fn remove(base: &Path, id: &str) -> Result<(), String> {
    let _guard = mutation_guard(base)?;
    fs::remove_file(entry(base, id)?).map_err(|e| e.to_string())
}

#[derive(Default, Serialize)]
pub struct Context {
    pub window_id: Option<String>,
    pub session_id: Option<String>,
}

pub fn spawn_action(
    base: &Path,
    socket: Option<&Path>,
    plugin: &str,
    action_id: &str,
    args: &[String],
    context: &Context,
    interactive: bool,
) -> Result<Child, String> {
    let mut command = action_command(base, socket, plugin, action_id, args, context)?;
    if !interactive {
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
    }
    command
        .spawn()
        .map_err(|e| format!("could not launch plugin action: {e}"))
}

fn action_command(
    base: &Path,
    socket: Option<&Path>,
    plugin: &str,
    action_id: &str,
    args: &[String],
    context: &Context,
) -> Result<Command, String> {
    let registration = load(base, plugin)?;
    if !registration.enabled {
        return Err("plugin is disabled".into());
    }
    let action = registration
        .manifest
        .actions
        .iter()
        .find(|a| a.id == action_id)
        .ok_or("plugin action does not exist")?;
    let mut command = Command::new(&action.command[0]);
    command
        .args(&action.command[1..])
        .args(args)
        .current_dir(&registration.root)
        .env(
            "HYDRA_BIN_PATH",
            std::env::current_exe().map_err(|e| e.to_string())?,
        )
        .env(
            "HYDRA_BASE_DIR",
            base.canonicalize().map_err(|e| e.to_string())?,
        )
        .env("HYDRA_PLUGIN_ID", plugin)
        .env("HYDRA_PLUGIN_ROOT", &registration.root)
        .env("HYDRA_PLUGIN_ACTION_ID", action_id)
        .env(
            "HYDRA_PLUGIN_CONTEXT_JSON",
            serde_json::to_string(context).map_err(|e| e.to_string())?,
        );
    // Do not accidentally inherit a different daemon/window from the caller's environment.
    for key in ["HYDRA_SOCKET_PATH", "HYDRA_WINDOW_ID", "HYDRA_SESSION_ID"] {
        command.env_remove(key);
    }
    if let Some(socket) = socket {
        let socket = std::path::absolute(socket).map_err(|e| e.to_string())?;
        command.env("HYDRA_SOCKET_PATH", socket);
    }
    if let Some(window) = &context.window_id {
        command.env("HYDRA_WINDOW_ID", window);
    }
    if let Some(session) = &context.session_id {
        command.env("HYDRA_SESSION_ID", session);
    }
    Ok(command)
}

/// Pure ID projection; argv and source paths never cross into renderer authority.
pub fn palette_rows(
    base: &Path,
) -> Result<Vec<maestro_renderer::RendererCommandPaletteRow>, String> {
    Ok(list(base)?
        .into_iter()
        .filter(|r| r.enabled)
        .flat_map(|r| {
            r.manifest.actions.into_iter().map(move |a| {
                maestro_renderer::RendererCommandPaletteRow {
                    id: format!("{ACTION_PREFIX}{}:{}", r.manifest.id, a.id),
                    label: a.title,
                    category: "Plugins".into(),
                    summary: r.manifest.name.clone(),
                    command: format!("plugin run {} {}", r.manifest.id, a.id),
                }
            })
        })
        .collect())
}

pub fn split_palette_id(id: &str) -> Option<(&str, &str)> {
    let (plugin, action) = id.strip_prefix(ACTION_PREFIX)?.split_once(':')?;
    (identifier(plugin) && identifier(action)).then_some((plugin, action))
}

/// Feedback carries display correlation only; it never controls the child lifetime.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InvocationIdentity {
    pub generation: u64,
    pub invocation: u64,
}

#[derive(Debug)]
pub struct ActionUpdate {
    pub generation: u64,
    pub invocation: u64,
    pub action_id: String,
    pub text: String,
}

/// A worker owns and reaps each child; closing the GUI never kills retained PTYs.
pub fn start_background(
    base: &Path,
    socket: &Path,
    id: &str,
    context: Context,
    identity: InvocationIdentity,
    updates: std::sync::mpsc::Sender<ActionUpdate>,
) -> Result<(), String> {
    let (plugin, action) = split_palette_id(id).ok_or("invalid plugin action id")?;
    let (base, socket, plugin, action) = (
        base.to_owned(),
        socket.to_owned(),
        plugin.to_owned(),
        action.to_owned(),
    );
    let action_id = id.to_owned();
    std::thread::Builder::new()
        .name("plugin-action".into())
        .spawn(move || {
            let update = |text| {
                let _ = updates.send(ActionUpdate {
                    generation: identity.generation,
                    invocation: identity.invocation,
                    action_id: action_id.clone(),
                    text,
                });
            };
            let result = (|| {
                let mut command =
                    action_command(&base, Some(&socket), &plugin, &action, &[], &context)?;
                let path = registry(&base).join(format!(".action-{}.log", uuid::Uuid::new_v4()));
                let mut options = OpenOptions::new();
                options.write(true).create_new(true);
                #[cfg(unix)]
                {
                    use std::os::unix::fs::OpenOptionsExt;
                    options.mode(0o600);
                }
                let log = options.open(&path).map_err(|e| e.to_string())?;
                command
                    .stdin(Stdio::null())
                    .stdout(log.try_clone().map_err(|e| e.to_string())?)
                    .stderr(log);
                let mut child = command
                    .spawn()
                    .map_err(|e| format!("could not launch: {e}"))?;
                update(format!("{plugin}:{action} running; log {}", path.display()));
                let status = child.wait().map_err(|e| e.to_string())?;
                Ok::<_, String>(format!(
                    "{plugin}:{action} exited {status}; log {}",
                    path.display()
                ))
            })();
            let message =
                result.unwrap_or_else(|error| format!("{plugin}:{action} failed: {error}"));
            eprintln!("plugin: {message}");
            update(message);
        })
        .map_err(|e| format!("could not queue plugin action: {e}"))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(root: &Path) -> Manifest {
        let manifest = Manifest {
            schema_version: 1,
            id: "example.test".into(),
            name: "Test".into(),
            version: "0.1.0".into(),
            actions: vec![Action {
                id: "run".into(),
                title: "Run test".into(),
                command: vec!["sh".into(), "-c".into(), "exit 23".into()],
            }],
        };
        fs::create_dir_all(root).unwrap();
        fs::write(
            root.join("hydra-plugin.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        manifest
    }

    #[test]
    fn manifest_rejects_unsupported_fields_versions_duplicate_and_invalid_actions() {
        let temp = tempfile::tempdir().unwrap();
        let valid = fixture(temp.path());
        valid.validate().unwrap();
        let mut unknown = serde_json::to_value(&valid).unwrap();
        unknown["startup"] = serde_json::json!([]);
        assert!(serde_json::from_value::<Manifest>(unknown).is_err());
        for invalid in ["..", "../escape", "bad:id", "", "bad\n"] {
            let mut manifest = valid.clone();
            manifest.id = invalid.into();
            assert!(manifest.validate().is_err());
        }
        let mut manifest = valid.clone();
        manifest.schema_version = 2;
        assert!(manifest.validate().is_err());
        let mut manifest = valid.clone();
        manifest.actions.push(valid.actions[0].clone());
        assert!(manifest.validate().is_err());
        let mut manifest = valid;
        manifest.actions[0].command.clear();
        assert!(manifest.validate().is_err());
    }

    #[test]
    fn install_list_palette_disable_run_remove_preserves_source() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base");
        let root = temp.path().join("source");
        fixture(&root);
        assert!(list(&base).unwrap().is_empty());
        install_local(&base, &root).unwrap();
        assert!(install_local(&base, &root).is_err());
        let rows = palette_rows(&base).unwrap();
        assert_eq!(rows.len(), 1);
        assert_eq!(split_palette_id(&rows[0].id), Some(("example.test", "run")));
        assert_eq!(list(&base).unwrap().len(), 1);
        let mut child = spawn_action(
            &base,
            None,
            "example.test",
            "run",
            &[],
            &Context::default(),
            false,
        )
        .unwrap();
        assert_eq!(child.wait().unwrap().code(), Some(23));
        set_enabled(&base, "example.test", false).unwrap();
        assert!(palette_rows(&base).unwrap().is_empty());
        assert!(spawn_action(
            &base,
            None,
            "example.test",
            "run",
            &[],
            &Context::default(),
            false
        )
        .is_err());
        set_enabled(&base, "example.test", true).unwrap();
        assert_eq!(palette_rows(&base).unwrap().len(), 1);
        assert!(spawn_action(
            &base,
            None,
            "example.test",
            "missing",
            &[],
            &Context::default(),
            false
        )
        .is_err());
        remove(&base, "example.test").unwrap();
        assert!(list(&base).unwrap().is_empty());
        assert!(root.join("hydra-plugin.json").exists());
    }

    #[test]
    fn installed_manifest_is_snapshot_until_explicit_reinstall() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base");
        let root = temp.path().join("source");
        fixture(&root);
        install_local(&base, &root).unwrap();
        fs::write(root.join("hydra-plugin.json"), b"invalid new manifest").unwrap();
        assert_eq!(
            load(&base, "example.test").unwrap().manifest.actions[0].title,
            "Run test"
        );
    }

    #[cfg(unix)]
    #[test]
    fn mutations_serialize_and_invalid_registration_can_be_removed() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        fixture(&root);
        let base = temp.path().join("base");
        install_local(&base, &root).unwrap();
        let guard = mutation_guard(&base).unwrap();
        assert!(set_enabled(&base, "example.test", false).is_err());
        assert!(remove(&base, "example.test").is_err());
        drop(guard);
        fs::write(entry(&base, "example.test").unwrap(), b"bad manifest").unwrap();
        assert!(load(&base, "example.test").is_err());
        remove(&base, "example.test").unwrap();
        assert!(list(&base).unwrap().is_empty());
    }

    #[test]
    fn argv_is_literal_and_context_is_host_owned() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("base");
        let root = temp.path().join("source");
        let mut manifest = fixture(&root);
        manifest.actions[0].command = vec!["sh".into(), "-c".into(),
            "test \"$1\" = '$(exit 99)' && test \"$HYDRA_PLUGIN_ID\" = example.test && test \"$HYDRA_SESSION_ID\" = chosen && test \"$HYDRA_WINDOW_ID\" = window && test \"$HYDRA_PLUGIN_ACTION_ID\" = run && test \"$PWD\" = \"$HYDRA_PLUGIN_ROOT\" && test -n \"$HYDRA_BIN_PATH\"".into(), "fixture".into()];
        fs::write(
            root.join("hydra-plugin.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        install_local(&base, &root).unwrap();
        let context = Context {
            session_id: Some("chosen".into()),
            window_id: Some("window".into()),
        };
        assert!(spawn_action(
            &base,
            Some(Path::new("relative.sock")),
            "example.test",
            "run",
            &["$(exit 99)".into()],
            &context,
            false
        )
        .unwrap()
        .wait()
        .unwrap()
        .success());
    }

    #[test]
    fn parser_preserves_args_and_rejects_wrong_command_options() {
        let parse =
            |args: &[&str]| super::parse(&args.iter().map(|s| s.to_string()).collect::<Vec<_>>());
        let command = parse(&[
            "run",
            "example.test",
            "run",
            "--socket",
            "owned.sock",
            "--",
            "--base",
            "literal",
        ])
        .unwrap();
        assert_eq!(command.socket, Some("owned.sock".into()));
        assert!(
            matches!(command.operation, Operation::Run { args, .. } if args == ["--base", "literal"])
        );
        for args in [
            vec![],
            vec!["list", "--socket", "x"],
            vec!["install-local"],
            vec!["run", "x"],
            vec!["list", "--base"],
            vec!["list", "--unknown"],
            vec!["list", "--base", "a", "--base", "b"],
        ] {
            assert!(parse(&args).is_err(), "{args:?}");
        }
    }

    #[test]
    fn bounded_data_rejects_large_files_and_non_regular_files() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("large");
        fs::write(&path, vec![b' '; MAX_BYTES as usize + 1]).unwrap();
        assert!(read_json::<Manifest>(&path).is_err());
        assert!(read_json::<Manifest>(temp.path()).is_err());
    }

    #[test]
    fn healthy_plugins_survive_bad_registration_and_large_action_catalogs() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        let mut manifest = fixture(&root);
        manifest.actions = (0..300)
            .map(|n| Action {
                id: format!("action-{n}"),
                title: "Action".into(),
                command: vec!["true".into()],
            })
            .collect();
        manifest.actions[0].command = vec!["true".into(); 150];
        manifest.validate().unwrap();
        fs::write(
            root.join("hydra-plugin.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let base = temp.path().join("base");
        install_local(&base, &root).unwrap();
        fs::write(entry(&base, "example.broken").unwrap(), b"invalid").unwrap();
        let inventory = inventory(&base).unwrap();
        assert_eq!(inventory.plugins.len(), 1);
        assert_eq!(inventory.plugins[0].manifest.actions.len(), 300);
        assert_eq!(inventory.diagnostics[0].id, "example.broken");
        let rows = palette_rows(&base).unwrap();
        assert_eq!(rows.len(), 300);
        for (n, row) in rows.iter().enumerate() {
            assert_eq!(row.id, format!("plugin:example.test:action-{n}"));
        }
    }

    #[test]
    fn background_action_reports_exit_log_and_spawn_failure() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        let mut manifest = fixture(&root);
        manifest.actions[0].command = vec![
            "sh".into(),
            "-c".into(),
            "printf out; printf err >&2; exit 23".into(),
        ];
        fs::write(
            root.join("hydra-plugin.json"),
            serde_json::to_vec(&manifest).unwrap(),
        )
        .unwrap();
        let base = temp.path().join("base");
        install_local(&base, &root).unwrap();
        let (tx, rx) = std::sync::mpsc::channel();
        start_background(
            &base,
            Path::new("owned.sock"),
            "plugin:example.test:run",
            Context::default(),
            InvocationIdentity {
                generation: 7,
                invocation: 41,
            },
            tx.clone(),
        )
        .unwrap();
        assert!(rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap()
            .text
            .contains("running; log"));
        let completed = rx.recv_timeout(std::time::Duration::from_secs(10)).unwrap();
        assert_eq!(completed.generation, 7);
        assert_eq!(completed.invocation, 41);
        assert_eq!(completed.action_id, "plugin:example.test:run");
        assert!(completed.text.contains("23"));
        let log = completed.text.split_once("; log ").unwrap().1;
        let output = fs::read_to_string(log).unwrap();
        assert!(output.contains("out") && output.contains("err"));
        set_enabled(&base, "example.test", false).unwrap();
        start_background(
            &base,
            Path::new("owned.sock"),
            "plugin:example.test:run",
            Context::default(),
            InvocationIdentity {
                generation: 8,
                invocation: 42,
            },
            tx,
        )
        .unwrap();
        assert!(rx
            .recv_timeout(std::time::Duration::from_secs(10))
            .unwrap()
            .text
            .contains("disabled"));
    }

    #[cfg(unix)]
    #[test]
    fn registry_and_manifest_symlinks_are_rejected() {
        use std::os::unix::fs::symlink;
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("source");
        fixture(&root);
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();
        }
        install_local(&temp.path().join("ordinary-base"), &root).unwrap();
        let linked = temp.path().join("linked");
        fs::create_dir(&linked).unwrap();
        symlink(
            root.join("hydra-plugin.json"),
            linked.join("hydra-plugin.json"),
        )
        .unwrap();
        assert!(install_local(&temp.path().join("base"), &linked).is_err());
        let base = temp.path().join("base");
        fs::create_dir(&base).unwrap();
        symlink(&root, registry(&base)).unwrap();
        assert!(list(&base).is_err());
    }
}
