//! Native command preparation for the real ConPTY consumer, without changing process-wide cwd
//! or environment. Shared Session uses this private adapter for Windows child construction.

use crate::windows_process_encoding::{snapshot_environment, wide_case_cmp, PreparedProcess};
use anyhow::{anyhow, bail, Context as _, Result};
use std::cmp::Ordering;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use std::path::{Component, Path, PathBuf, Prefix};
use windows_sys::Win32::Storage::FileSystem::GetFullPathNameW;
use windows_sys::Win32::System::SystemInformation::GetSystemDirectoryW;

pub(super) struct Command {
    program: OsString,
    arguments: Vec<OsString>,
    environment: Vec<(OsString, OsString)>,
    directory: Option<OsString>,
}

impl Command {
    pub(super) fn new(program: impl AsRef<OsStr>) -> Result<Self> {
        Ok(Self::from_environment(
            program,
            snapshot_environment()?,
            crate::windows_child_path::refresh,
        ))
    }

    fn from_environment(
        program: impl AsRef<OsStr>,
        mut environment: Vec<(OsString, OsString)>,
        refresh_path: impl FnOnce(&mut [(OsString, OsString)]),
    ) -> Self {
        refresh_path(&mut environment);
        Self {
            program: program.as_ref().into(),
            arguments: Vec::new(),
            environment,
            directory: None,
        }
    }

    pub(super) fn args<I, S>(&mut self, arguments: I)
    where
        I: IntoIterator<Item = S>,
        S: AsRef<OsStr>,
    {
        self.arguments.extend(
            arguments
                .into_iter()
                .map(|argument| argument.as_ref().into()),
        );
    }

    pub(super) fn cwd(&mut self, directory: impl AsRef<OsStr>) {
        self.directory = Some(directory.as_ref().into());
    }

    pub(super) fn get_env(&self, key: impl AsRef<OsStr>) -> Option<&OsStr> {
        environment_value(&self.environment, key.as_ref())
    }

    pub(super) fn env(&mut self, key: impl AsRef<OsStr>, value: impl AsRef<OsStr>) {
        self.env_remove(key.as_ref());
        self.environment
            .push((key.as_ref().into(), value.as_ref().into()));
    }

    pub(super) fn env_remove(&mut self, key: impl AsRef<OsStr>) {
        self.environment
            .retain(|(candidate, _)| wide_case_cmp(candidate, key.as_ref()) != Ordering::Equal);
    }

    pub(super) fn prepare(self) -> Result<PreparedProcess> {
        let parent = std::env::current_dir().context("capture Windows process directory")?;
        let directory = absolute_path(
            self.directory.as_deref().unwrap_or(parent.as_os_str()),
            &parent,
            &self.environment,
        )?;
        let executable = resolve_executable(&self.program, &directory, &self.environment)?;
        let batch = executable.extension().is_some_and(|extension| {
            wide_case_cmp(extension, OsStr::new("cmd")) == Ordering::Equal
                || wide_case_cmp(extension, OsStr::new("bat")) == Ordering::Equal
        });
        if !batch {
            let executable = compatible_executable_spelling(executable);
            return PreparedProcess::new(
                executable.as_os_str(),
                &self.arguments,
                &self.environment,
                Some(directory.as_os_str()),
            );
        }
        let interpreter = match self.get_env("COMSPEC").filter(|value| !value.is_empty()) {
            Some(program) => resolve_executable(program, &directory, &self.environment)?,
            None => system_directory()?.join("cmd.exe"),
        };
        let interpreter = compatible_executable_spelling(interpreter);
        let script = batch_script_path(&executable)?;
        let line = batch_command_line(&script, &self.arguments)?;
        PreparedProcess::with_command_line(
            interpreter.as_os_str(),
            &line,
            &self.environment,
            Some(directory.as_os_str()),
        )
    }
}

// Some legacy .NET applications (including Windows PowerShell) cannot initialize from a
// verbatim executable name even though CreateProcessW accepts it. Change only the native
// launch spelling, never the selected/durable provider locator or any user argument.
fn compatible_executable_spelling(executable: PathBuf) -> PathBuf {
    let Some(ordinary) = ordinary_executable_candidate(&executable) else {
        return executable;
    };
    // This is a conservative equivalence check, not a new executable selection policy.
    // Keep the original on errors or different targets; do not fall back to another program.
    match (executable.canonicalize(), ordinary.canonicalize()) {
        (Ok(original), Ok(candidate)) if original == candidate => ordinary,
        _ => executable,
    }
}

fn ordinary_executable_candidate(executable: &Path) -> Option<PathBuf> {
    if !matches!(executable.components().next(), Some(Component::Prefix(prefix))
        if matches!(prefix.kind(), Prefix::VerbatimDisk(_) | Prefix::VerbatimUNC(_, _)))
    {
        return None;
    }
    // Reuse the existing exact Win32 normalization checks. Preserve long paths rather than
    // removing the namespace required by programs without long-path awareness.
    let ordinary = batch_script_path(executable).ok()?;
    let units: Vec<u16> = ordinary.as_os_str().encode_wide().collect();
    if units.len() >= 260
        || units
            .split(|unit| *unit == b'\\' as u16)
            .any(reserved_dos_component)
    {
        return None;
    }
    Some(ordinary)
}

fn reserved_dos_component(component: &[u16]) -> bool {
    let mut stem = component
        .split(|unit| *unit == b'.' as u16)
        .next()
        .unwrap_or_default();
    while stem.last() == Some(&(b' ' as u16)) {
        stem = &stem[..stem.len() - 1];
    }
    let stem = OsString::from_wide(stem);
    [
        "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$", "COM1", "COM2", "COM3", "COM4", "COM5",
        "COM6", "COM7", "COM8", "COM9", "LPT1", "LPT2", "LPT3", "LPT4", "LPT5", "LPT6", "LPT7",
        "LPT8", "LPT9", "COM¹", "COM²", "COM³", "LPT¹", "LPT²", "LPT³",
    ]
    .iter()
    .any(|name| wide_case_cmp(&stem, OsStr::new(name)) == Ordering::Equal)
}

fn environment_value<'a>(
    environment: &'a [(OsString, OsString)],
    key: &OsStr,
) -> Option<&'a OsStr> {
    environment
        .iter()
        .find(|(candidate, _)| wide_case_cmp(candidate, key) == Ordering::Equal)
        .map(|(_, value)| value.as_os_str())
}

fn native_path(mut fill: impl FnMut(*mut u16, u32) -> u32) -> Result<PathBuf> {
    let mut buffer = vec![0; 260];
    loop {
        let capacity = u32::try_from(buffer.len()).context("Windows path length overflow")?;
        let count = fill(buffer.as_mut_ptr(), capacity);
        if count == 0 {
            return Err(io::Error::last_os_error()).context("resolve native Windows path");
        }
        if count < capacity {
            buffer.truncate(count as usize);
            return Ok(PathBuf::from(OsString::from_wide(&buffer)));
        }
        buffer.resize(count as usize + 1, 0);
    }
}

fn system_directory() -> Result<PathBuf> {
    native_path(|buffer, capacity| unsafe { GetSystemDirectoryW(buffer, capacity) })
}

fn absolute_path(
    value: &OsStr,
    directory: &Path,
    environment: &[(OsString, OsString)],
) -> Result<PathBuf> {
    if value.encode_wide().any(|unit| unit == 0) {
        bail!("Windows path contains a NUL code unit");
    }
    let path = Path::new(value);
    let first = path.components().next();
    let joined = match first {
        Some(Component::Prefix(prefix)) if prefix.kind().is_verbatim() => return Ok(path.into()),
        Some(Component::Prefix(prefix)) if !path.has_root() => {
            let Prefix::Disk(drive) = prefix.kind() else {
                bail!("Windows path has no drive root");
            };
            let same_drive = matches!(directory.components().next(), Some(Component::Prefix(base))
                if matches!(base.kind(), Prefix::Disk(current) if current.eq_ignore_ascii_case(&drive)));
            let fallback = PathBuf::from(format!("{}:\\", char::from(drive)));
            let key = OsString::from(format!("={}:", char::from(drive)));
            let base = if same_drive {
                directory
            } else {
                environment_value(environment, &key)
                    .map(Path::new)
                    .filter(|base| base.is_absolute())
                    .unwrap_or(&fallback)
            };
            base.join(path.components().skip(1).collect::<PathBuf>())
        }
        _ => directory.join(path),
    };
    let wide: Vec<u16> = joined.as_os_str().encode_wide().chain(Some(0)).collect();
    native_path(|buffer, capacity| unsafe {
        GetFullPathNameW(wide.as_ptr(), capacity, buffer, std::ptr::null_mut())
    })
}

fn resolve_executable(
    program: &OsStr,
    directory: &Path,
    environment: &[(OsString, OsString)],
) -> Result<PathBuf> {
    if program.is_empty() || program.encode_wide().any(|unit| unit == 0) {
        bail!("Windows command must name an executable without NUL code units");
    }
    let path = Path::new(program);
    let suffixes: Vec<OsString> = if path.extension().is_some() {
        vec![OsString::new()]
    } else {
        let mut suffixes = vec![OsString::new()];
        let extensions = environment_value(environment, OsStr::new("PATHEXT"))
            .unwrap_or(OsStr::new(".COM;.EXE;.BAT;.CMD"));
        let units: Vec<u16> = extensions.encode_wide().collect();
        suffixes.extend(
            units
                .split(|unit| *unit == b';' as u16)
                .filter(|extension| !extension.is_empty())
                .map(OsString::from_wide),
        );
        suffixes
    };
    let explicit_path = path.components().count() != 1
        || !matches!(path.components().next(), Some(Component::Normal(_)));
    let mut directories = vec![directory.to_path_buf()];
    if !explicit_path {
        if let Some(paths) = environment_value(environment, OsStr::new("PATH")) {
            for entry in std::env::split_paths(paths) {
                directories.push(absolute_path(entry.as_os_str(), directory, environment)?);
            }
        }
        // Native system commands also work in a thin environment. This does not replace or
        // mutate the child's PATH, or take precedence over any user-supplied PATH entry.
        directories.push(system_directory()?);
    }
    for base in directories {
        for suffix in &suffixes {
            let mut candidate = program.to_owned();
            candidate.push(suffix);
            let candidate = absolute_path(&candidate, &base, environment)?;
            if candidate.is_file() {
                return Ok(candidate);
            }
        }
    }
    Err(anyhow!(
        "Windows executable was not found: {}",
        program.to_string_lossy()
    ))
}

fn batch_script_path(script: &Path) -> Result<PathBuf> {
    let Some(Component::Prefix(prefix)) = script.components().next() else {
        return Ok(script.into());
    };
    if !prefix.kind().is_verbatim() {
        return Ok(script.into());
    }
    let units: Vec<u16> = script.as_os_str().encode_wide().collect();
    let ordinary = match prefix.kind() {
        Prefix::VerbatimDisk(_) => OsString::from_wide(&units[4..]),
        Prefix::VerbatimUNC(_, _) => {
            let mut ordinary = vec![b'\\' as u16, b'\\' as u16];
            ordinary.extend_from_slice(&units[8..]);
            OsString::from_wide(&ordinary)
        }
        _ => bail!("cmd.exe cannot represent this verbatim Windows path namespace"),
    };
    // cmd cannot consume the verbatim prefix. Strip it only when the ordinary Win32 spelling
    // has the same meaning, never reinterpret literal dot/space components or forward slashes.
    // GetFullPathName alone is not a file-identity proof; reject those normalization-sensitive
    // components explicitly as well as requiring an exact native normalization roundtrip.
    let ordinary_units: Vec<u16> = ordinary.encode_wide().collect();
    if ordinary_units.contains(&(b'/' as u16))
        || ordinary_units
            .split(|unit| *unit == b'\\' as u16)
            .any(|part| part.last().is_some_and(|unit| matches!(*unit, 0x20 | 0x2e)))
    {
        bail!("cmd.exe cannot represent this verbatim script path without changing dot/space semantics");
    }
    let wide: Vec<u16> = ordinary.encode_wide().chain(Some(0)).collect();
    let normalized = native_path(|buffer, capacity| unsafe {
        GetFullPathNameW(wide.as_ptr(), capacity, buffer, std::ptr::null_mut())
    })?;
    if normalized.as_os_str() != ordinary {
        bail!("cmd.exe cannot represent this verbatim script path without normalizing its meaning");
    }
    Ok(normalized)
}

fn batch_command_line(script: &Path, arguments: &[OsString]) -> Result<OsString> {
    // cmd's grammar is not MSCRT argv. These switches apply only to this automatic script
    // invocation: extensions permit literal-percent escaping and delayed expansion stays off.
    // Reference: Rust 1.88 std/sys/args/windows.rs, make_bat_command_line/append_bat_arg.
    let mut line: Vec<u16> = "cmd.exe /e:ON /v:OFF /d /c \"".encode_utf16().collect();
    append_batch_argument(script.as_os_str(), &mut line)?;
    for argument in arguments {
        line.push(b' ' as u16);
        append_batch_argument(argument, &mut line)?;
    }
    line.push(b'"' as u16);
    Ok(OsString::from_wide(&line))
}

fn append_batch_argument(argument: &OsStr, output: &mut Vec<u16>) -> Result<()> {
    let units: Vec<u16> = argument.encode_wide().collect();
    if units.iter().any(|unit| matches!(*unit, 0 | 10 | 13)) {
        bail!("cmd.exe cannot carry a literal NUL or newline in a batch argument");
    }
    output.push(b'"' as u16);
    let mut slashes = 0;
    for unit in units {
        if unit == b'\\' as u16 {
            slashes += 1;
        } else {
            if unit == b'"' as u16 {
                output.extend(std::iter::repeat_n(b'\\' as u16, slashes));
                output.push(b'"' as u16);
            } else if unit == b'%' as u16 {
                // An empty dynamic-CD substring interrupts cmd's %NAME% expansion without
                // changing the literal percent, even when NAME exists in the child environment.
                output.extend("%%cd:~,".encode_utf16());
            }
            slashes = 0;
        }
        output.push(unit);
    }
    output.extend(std::iter::repeat_n(b'\\' as u16, slashes));
    output.push(b'"' as u16);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::windows_conpty::tests::assert_native_command_output;
    use crate::windows_overlapped_io::tests::run_exact_owned_child;
    use std::io::Write as _;

    const CHILD: &str = "windows_command::tests::argument_child";
    const MODE: &str = "HYDRA_NATIVE_COMMAND_FIXTURE";

    struct FixtureDirectory(PathBuf);

    impl FixtureDirectory {
        fn new() -> Self {
            let path = std::env::temp_dir().join(format!("hydra-native-{}", uuid::Uuid::new_v4()));
            std::fs::create_dir(&path).unwrap();
            Self(path)
        }
    }

    impl Drop for FixtureDirectory {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    fn arguments(mode: &str) -> Vec<OsString> {
        let mut arguments: Vec<OsString> = [
            "",
            "two words",
            "say\"hi",
            "slashes\\\\\"quote",
            "trailing space\\",
            "%HYDRA_EXPAND%",
            "a&b|c<d>e^f(!)",
            "Türkçe日本語",
            r"\\?\C:\literal\unchanged",
        ]
        .map(OsString::from)
        .into();
        if mode == "exe" {
            arguments.push("literal\nline".into());
            // libtest itself uses env::args before selecting this entry. Lone-surrogate argv
            // therefore belongs to the lossless codec tests, not this libtest child fixture.
        }
        arguments
    }

    fn child_command(program: impl AsRef<OsStr>, mode: &str, directory: &Path) -> Command {
        let mut command = Command::new(program).unwrap();
        command.cwd(directory);
        command.args(["--exact", CHILD, "--ignored", "--nocapture", "--"]);
        command.args(arguments(mode));
        command.env(MODE, mode);
        command.env("HYDRA_EXPECT_CWD", directory);
        command.env("HYDRA_EXPAND", "must-not-expand");
        command.env("Hydra_Case_Value", "before");
        command.env("HYDRA_CASE_VALUE", "after");
        command.env("HYDRA_REMOVED", "remove-me");
        command.env_remove("hydra_removed");
        command.env(
            "HYDRA_WIDE_VALUE",
            OsString::from_wide(&[0xd800, b'x' as u16]),
        );
        command
    }

    #[test]
    fn powershell_executable_spelling_starts_from_dos_and_verbatim_paths() {
        const CASE: &str = "windows_command::tests::powershell_executable_spelling_starts_from_dos_and_verbatim_paths";
        if run_exact_owned_child(CASE) {
            return;
        }
        let root = FixtureDirectory::new();
        let ordinary = system_directory()
            .unwrap()
            .join(r"WindowsPowerShell\v1.0\powershell.exe");
        let verbatim = ordinary.canonicalize().unwrap();
        assert_ne!(ordinary, verbatim);
        for program in [&ordinary, &verbatim] {
            let mut command = Command::new(program).unwrap();
            command.cwd(&root.0);
            command.args([
                "-NoLogo",
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                "[System.Net.ServicePointManager]::SecurityProtocol | Out-Null; [Console]::WriteLine('HYDRA_NATIVE_ARGUMENTS_OK')",
            ]);
            assert_native_command_output(command);
        }
        println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
    }

    #[test]
    fn executable_spelling_preserves_native_arguments_for_canonical_unicode_path() {
        const CASE: &str = "windows_command::tests::executable_spelling_preserves_native_arguments_for_canonical_unicode_path";
        if run_exact_owned_child(CASE) {
            return;
        }
        let root = FixtureDirectory::new();
        let executable = root.0.join("native Türkçe 日本語.exe");
        std::fs::copy(std::env::current_exe().unwrap(), &executable).unwrap();
        let canonical = executable.canonicalize().unwrap();
        let command = child_command(&canonical, "exe", &root.0);
        assert_eq!(command.program, canonical.as_os_str());
        assert_native_command_output(command);
        println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
    }

    #[test]
    fn executable_spelling_candidate_preserves_namespace_and_normalization_semantics() {
        assert_eq!(
            ordinary_executable_candidate(Path::new(r"\\?\C:\Windows\tool.exe")),
            Some(PathBuf::from(r"C:\Windows\tool.exe"))
        );
        // Candidate calculation does not access a network share.
        assert_eq!(
            ordinary_executable_candidate(Path::new(r"\\?\UNC\server\share\tool.exe")),
            Some(PathBuf::from(r"\\server\share\tool.exe"))
        );
        for path in [
            r"C:\Windows\tool.exe",
            r"\\?\Volume{abcd}\tool.exe",
            r"\\.\C:\tool.exe",
            r"\\?\C:\dir\..\tool.exe",
            r"\\?\C:\dir.\tool.exe",
            r"\\?\C:\dir \tool.exe",
            r"\\?\C:\dir\tool.exe.",
            r"\\?\C:\dir\tool.exe ",
            r"\\?\C:\dir/NUL.exe",
            r"\\?\C:\NUL.exe",
            r"\\?\C:\aux\tool.exe",
            r"\\?\C:\COM1.exe",
            r"\\?\C:\lpt².exe",
            r"\\?\C:\CONIN$",
        ] {
            assert_eq!(
                ordinary_executable_candidate(Path::new(path)),
                None,
                "{path}"
            );
        }
        let long = format!(r"\\?\C:\{}\tool.exe", "directory\\".repeat(30));
        assert_eq!(ordinary_executable_candidate(Path::new(&long)), None);
    }

    #[test]
    fn executable_spelling_requires_existing_equivalent_target() {
        let root = FixtureDirectory::new();
        let executable = root.0.join("ordinary.exe");
        std::fs::write(&executable, b"synthetic path identity fixture").unwrap();
        let canonical = executable.canonicalize().unwrap();
        let ordinary = compatible_executable_spelling(canonical.clone());
        assert_eq!(ordinary.canonicalize().unwrap(), canonical);
        assert!(
            matches!(ordinary.components().next(), Some(Component::Prefix(prefix))
            if matches!(prefix.kind(), Prefix::Disk(_)))
        );
        let missing = root.0.canonicalize().unwrap().join("missing.exe");
        assert_eq!(compatible_executable_spelling(missing.clone()), missing);
        let sensitive = root.0.canonicalize().unwrap().join("trailing.exe.");
        std::fs::write(&sensitive, b"literal trailing dot fixture").unwrap();
        assert_eq!(compatible_executable_spelling(sensitive.clone()), sensitive);
    }

    #[test]
    fn relative_path_native_executable_receives_exact_arguments_and_environment() {
        const CASE: &str = "windows_command::tests::relative_path_native_executable_receives_exact_arguments_and_environment";
        if run_exact_owned_child(CASE) {
            return;
        }
        let root = FixtureDirectory::new();
        let binaries = root.0.join("bin with space 日本語");
        let directory = root.0.join("project");
        std::fs::create_dir(&binaries).unwrap();
        std::fs::create_dir(&directory).unwrap();
        std::fs::copy(
            std::env::current_exe().unwrap(),
            binaries.join("hydra-child.EXE"),
        )
        .unwrap();
        let mut command = child_command("hydra-child", "exe", &directory);
        command.env("Path", "..\\bin with space 日本語");
        command.env("PATHEXT", ".EXE;.CMD");
        assert_native_command_output(command);
        println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
    }

    #[test]
    fn batch_shim_forwards_literal_arguments_to_real_conpty_child() {
        const CASE: &str =
            "windows_command::tests::batch_shim_forwards_literal_arguments_to_real_conpty_child";
        if run_exact_owned_child(CASE) {
            return;
        }
        let root = FixtureDirectory::new();
        std::fs::copy(std::env::current_exe().unwrap(), root.0.join("child.exe")).unwrap();
        // A normal provider-style batch shim: the executable receives the script's exact %*.
        std::fs::write(
            root.0.join("provider%HYDRA_EXPAND%.cmd"),
            "@echo off\r\n\"%~dp0child.exe\" %*\r\n",
        )
        .unwrap();
        let mut command = child_command("provider%HYDRA_EXPAND%", "batch", &root.0);
        command.env("PATH", &root.0);
        command.env("PATHEXT", ".EXE;.CMD");
        // Exercise the real system-interpreter fallback without changing the host environment.
        command.env_remove("COMSPEC");
        assert_native_command_output(command);
        let canonical_script =
            std::fs::canonicalize(root.0.join("provider%HYDRA_EXPAND%.cmd")).unwrap();
        assert!(
            matches!(canonical_script.components().next(), Some(Component::Prefix(prefix)) if prefix.kind().is_verbatim())
        );
        // A real canonicalized .cmd path takes the representation adapter, not just pure vectors.
        let mut canonical = child_command(&canonical_script, "batch", &root.0);
        canonical.env_remove("COMSPEC");
        assert_native_command_output(canonical);
        println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
    }

    #[test]
    #[ignore = "exact ConPTY-owned native argument observation entry"]
    fn argument_child() {
        let mode = std::env::var(MODE).unwrap();
        assert!(matches!(mode.as_str(), "exe" | "batch"));
        let observed: Vec<_> = std::env::args_os()
            .skip_while(|argument| argument != "--")
            .skip(1)
            .collect();
        assert_eq!(observed, arguments(&mode));
        assert_eq!(std::env::var("HYDRA_CASE_VALUE").unwrap(), "after");
        assert!(std::env::var_os("HYDRA_REMOVED").is_none());
        assert_eq!(
            std::env::var_os("HYDRA_WIDE_VALUE").unwrap(),
            OsString::from_wide(&[0xd800, b'x' as u16])
        );
        assert_eq!(
            std::fs::canonicalize(std::env::current_dir().unwrap()).unwrap(),
            std::fs::canonicalize(std::env::var_os("HYDRA_EXPECT_CWD").unwrap()).unwrap()
        );
        if let Some(expected) = std::env::var_os("HYDRA_EXPECT_REFRESH_PATH") {
            assert_eq!(std::env::var_os("PATH"), Some(expected));
        }
        println!("\nHYDRA_NATIVE_ARGUMENTS_OK");
        std::io::stdout().flush().unwrap();
    }

    #[test]
    fn os_baseline_refresh_reaches_native_shim_dependency_without_replacing_custom_environment() {
        use crate::windows_child_path::PathPolicy;

        const CASE: &str = "windows_command::tests::os_baseline_refresh_reaches_native_shim_dependency_without_replacing_custom_environment";
        if run_exact_owned_child(CASE) {
            return;
        }
        let root = FixtureDirectory::new();
        let old = root.0.join("old empty PATH");
        let installed = root.0.join("new dependency 日本語");
        let custom = root.0.join("explicit custom PATH");
        for directory in [&old, &installed, &custom] {
            std::fs::create_dir(directory).unwrap();
        }
        let dependency = format!("hydra-path-{}.exe", uuid::Uuid::new_v4().simple());
        for directory in [&installed, &custom] {
            std::fs::copy(
                std::env::current_exe().unwrap(),
                directory.join(&dependency),
            )
            .unwrap();
        }
        let shim = root.0.join("selected-provider.cmd");
        std::fs::write(&shim, format!("@echo off\r\n{dependency} %*\r\n")).unwrap();

        // Controlled OS observations exercise the production constructor/policy and real ConPTY
        // without editing the account's registry or process environment. The separate native OS
        // block test exercises token/block allocation and cleanup with the actual Windows API.
        for (inherited, startup_os, current_os, explicit, expected) in [
            (&old, &old, Some(&installed), None, &installed),
            (&custom, &old, Some(&installed), None, &custom),
            (&old, &old, Some(&installed), Some(&custom), &custom),
            (&custom, &custom, None, None, &custom),
        ] {
            let mut original = child_command(&shim, "batch", &root.0);
            original.env("pAtH", inherited);
            original.env("HYDRA_EXPECT_REFRESH_PATH", expected);
            original.env_remove("COMSPEC");
            let other_values: Vec<_> = original
                .environment
                .iter()
                .filter(|(key, _)| wide_case_cmp(key, OsStr::new("PATH")) != Ordering::Equal)
                .cloned()
                .collect();
            let policy =
                PathPolicy::capture(Some(inherited.as_os_str()), Some(startup_os.as_os_str()));
            let mut command =
                Command::from_environment(&shim, original.environment, |environment| {
                    policy.refresh(environment, || {
                        current_os.map(|path| path.as_os_str().to_owned())
                    });
                });
            command.arguments = original.arguments;
            command.directory = original.directory;
            if let Some(explicit) = explicit {
                command.env("PATH", explicit);
            }
            assert_eq!(command.get_env("path"), Some(expected.as_os_str()));
            assert!(
                command
                    .environment
                    .iter()
                    .filter(|(key, _)| wide_case_cmp(key, OsStr::new("PATH")) != Ordering::Equal)
                    .cloned()
                    .collect::<Vec<_>>()
                    == other_values,
                "refresh must preserve every other inherited value, including WTF-16"
            );
            assert_native_command_output(command);
        }
        println!("\nHYDRA_WINDOWS_IO_PASS:{CASE}");
    }

    #[test]
    fn relative_drive_unc_and_verbatim_paths_keep_their_native_meaning() {
        let directory = Path::new(r"C:\work\project");
        let environment = [("=D:".into(), r"D:\other\current".into())];
        for (input, expected) in [
            (r"..\tool.exe", r"C:\work\tool.exe"),
            (r"C:tool.exe", r"C:\work\project\tool.exe"),
            (r"D:tool.exe", r"D:\other\current\tool.exe"),
            (r"\tool.exe", r"C:\tool.exe"),
            (
                r"\\server\share\dir\..\tool.exe",
                r"\\server\share\tool.exe",
            ),
            (r"\\?\C:\kept.\..\tool.exe", r"\\?\C:\kept.\..\tool.exe"),
            (
                r"\\?\UNC\server\share\kept.\tool.exe",
                r"\\?\UNC\server\share\kept.\tool.exe",
            ),
        ] {
            assert_eq!(
                absolute_path(OsStr::new(input), directory, &environment).unwrap(),
                Path::new(expected)
            );
        }
    }

    #[test]
    fn child_path_order_and_suffix_order_are_not_replaced_or_filtered() {
        let root = FixtureDirectory::new();
        for name in ["first", "second"] {
            std::fs::create_dir(root.0.join(name)).unwrap();
            std::fs::write(root.0.join(name).join("tool.cmd"), "@exit /b 0").unwrap();
        }
        let environment = [
            ("Path".into(), "first;second".into()),
            ("PATHEXT".into(), ".CMD;.EXE".into()),
        ];
        assert_eq!(
            resolve_executable(OsStr::new("tool"), &root.0, &environment).unwrap(),
            // The chosen suffix preserves the caller's PATHEXT spelling. Windows
            // opens the same fixture file regardless of this lexical case difference.
            root.0.join("first").join("tool.CMD")
        );
        assert_eq!(
            resolve_executable(OsStr::new("second\\tool.cmd"), &root.0, &environment).unwrap(),
            root.0.join("second").join("tool.cmd")
        );
        assert!(
            resolve_executable(OsStr::new("missing-hydra-test"), &root.0, &environment).is_err()
        );
    }

    #[test]
    fn batch_verbatim_conversion_requires_an_equivalent_native_spelling() {
        for (input, expected) in [
            (r"\\?\C:\ordinary\shim.cmd", r"C:\ordinary\shim.cmd"),
            (r"\\?\UNC\server\share\shim.cmd", r"\\server\share\shim.cmd"),
            (r"C:\ordinary\shim.cmd", r"C:\ordinary\shim.cmd"),
        ] {
            assert_eq!(
                batch_script_path(Path::new(input)).unwrap(),
                Path::new(expected)
            );
        }
        for input in [
            r"\\?\C:\kept.\shim.cmd",
            r"\\?\C:\kept \shim.cmd",
            r"\\?\C:\folder\..\shim.cmd",
            r"\\?\C:\folder\.\shim.cmd",
            r"\\?\C:\folder/child\shim.cmd",
            r"\\?\GLOBALROOT\Device\Volume\shim.cmd",
        ] {
            assert!(batch_script_path(Path::new(input)).is_err(), "{input}");
        }
    }

    #[test]
    fn environment_edits_are_case_insensitive_and_batch_errors_are_specific() {
        let mut command = Command::new("cmd.exe").unwrap();
        command.env("Hydra_Value", "one");
        command.env("HYDRA_VALUE", "two");
        assert_eq!(command.get_env("hydra_value"), Some(OsStr::new("two")));
        assert_eq!(
            command
                .environment
                .iter()
                .filter(|(key, _)| wide_case_cmp(key, OsStr::new("hydra_value")) == Ordering::Equal)
                .count(),
            1
        );
        command.env_remove("hydra_value");
        assert!(command.get_env("HYDRA_VALUE").is_none());
        for value in ["one\ntwo", "one\rtwo", "one\0two"] {
            assert!(batch_command_line(Path::new(r"C:\shim.cmd"), &[value.into()]).is_err());
        }
        let line =
            batch_command_line(Path::new(r"C:\shim.cmd"), &["%HYDRA_VALUE%".into()]).unwrap();
        assert!(line
            .to_string_lossy()
            .contains("%%cd:~,%HYDRA_VALUE%%cd:~,%"));
        assert!(PreparedProcess::new(
            OsStr::new(r"C:\native.exe"),
            &["one\ntwo".into()],
            &[],
            None
        )
        .is_ok());
    }
}
