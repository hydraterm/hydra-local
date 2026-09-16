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
        Ok(Self {
            program: program.as_ref().into(),
            arguments: Vec::new(),
            environment: snapshot_environment()?,
            directory: None,
        })
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
        println!("\nHYDRA_NATIVE_ARGUMENTS_OK");
        std::io::stdout().flush().unwrap();
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
            root.0.join("first").join("tool.cmd")
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
