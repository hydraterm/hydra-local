//! Shared std-only build support for the launcher and actual GUI executable.
//! Does nothing for macOS/Linux/non-MSVC targets. All generated files stay in OUT_DIR.

use std::env;
use std::ffi::OsStr;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Command;

fn invalid(message: &str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, message)
}

fn needs_resource(target_os: &str, target_env: &str) -> bool {
    target_os == "windows" && target_env == "msvc"
}

fn sdk_version(name: &str) -> Option<[u32; 4]> {
    let fields: Vec<&str> = name.split('.').collect();
    if fields.len() != 4
        || fields
            .iter()
            .any(|field| field.is_empty() || !field.bytes().all(|b| b.is_ascii_digit()))
    {
        return None;
    }
    Some([
        fields[0].parse().ok()?,
        fields[1].parse().ok()?,
        fields[2].parse().ok()?,
        fields[3].parse().ok()?,
    ])
}

fn host_sdk_arch(host: &str) -> io::Result<&'static str> {
    match host.split('-').next() {
        Some("x86_64") => Ok("x64"),
        Some("aarch64") => Ok("arm64"),
        Some("i686") => Ok("x86"),
        _ => Err(invalid(
            "unsupported SDK compiler host; set HYDRA_WINDOWS_RC explicitly",
        )),
    }
}

fn select_rc(explicit: Option<&OsStr>, sdk_bin: &Path, host: &str) -> io::Result<PathBuf> {
    if let Some(path) = explicit {
        let path = PathBuf::from(path);
        if !path.is_absolute() || !path.is_file() {
            return Err(invalid(
                "HYDRA_WINDOWS_RC must name an existing absolute rc.exe path",
            ));
        }
        return Ok(path);
    }
    let architecture = host_sdk_arch(host)?;
    let mut candidates = Vec::new();
    for entry in fs::read_dir(sdk_bin)? {
        let entry = entry?;
        if !entry.file_type()?.is_dir() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if let Some(version) = sdk_version(&name) {
            let path = entry.path().join(architecture).join("rc.exe");
            if path.is_file() {
                candidates.push((version, name, path));
            }
        }
    }
    candidates.sort(); // Numeric SDK version, stable lexical tie-break, never PATH order.
    candidates
        .pop()
        .map(|(_, _, path)| path)
        .ok_or_else(|| invalid("no Windows Kits SDK rc.exe found; set HYDRA_WINDOWS_RC explicitly"))
}

fn run(command: &mut Command, label: &str) -> io::Result<()> {
    #[cfg(windows)]
    {
        use std::os::windows::process::CommandExt;
        command.creation_flags(0x08000000); // CREATE_NO_WINDOW; no transient desktop console.
    }
    let status = command.status()?;
    if !status.success() {
        return Err(io::Error::other(format!(
            "{label} failed ({status}); no icon resource linked"
        )));
    }
    Ok(())
}

pub fn compile(binary: &str) -> io::Result<()> {
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=../packaging/windows/build_icon.rs");
    if !needs_resource(
        &env::var("CARGO_CFG_TARGET_OS").unwrap_or_default(),
        &env::var("CARGO_CFG_TARGET_ENV").unwrap_or_default(),
    ) {
        return Ok(());
    }
    if !cfg!(windows) {
        return Err(invalid(
            "Windows/MSVC icon build needs the Windows SDK host; use a native Windows builder",
        ));
    }
    for variable in ["HYDRA_WINDOWS_RC", "ProgramFiles(x86)", "HOST"] {
        println!("cargo:rerun-if-env-changed={variable}");
    }
    let manifest = PathBuf::from(
        env::var_os("CARGO_MANIFEST_DIR").ok_or_else(|| invalid("missing CARGO_MANIFEST_DIR"))?,
    );
    let root = manifest
        .parent()
        .ok_or_else(|| invalid("missing workspace directory"))?;
    let support = root.join("packaging/windows");
    let source = root.join("assets/Hydra.png");
    let resource = support.join("Hydra.rc");
    let icon = support.join("Hydra.ico");
    for path in [&source, &icon, &resource] {
        println!("cargo:rerun-if-changed={}", path.display());
    }
    if !icon.is_file() {
        return Err(invalid(
            "missing packaging/windows/Hydra.ico; run New-HydraIcon.ps1 as an approved operator step and include the resulting asset",
        ));
    }
    let output = PathBuf::from(env::var_os("OUT_DIR").ok_or_else(|| invalid("missing OUT_DIR"))?);
    let explicit = env::var_os("HYDRA_WINDOWS_RC");
    let kits = env::var_os("ProgramFiles(x86)")
        .map(PathBuf::from)
        .unwrap_or_default()
        .join("Windows Kits/10/bin");
    if explicit.is_none() && !kits.is_absolute() {
        return Err(invalid(
            "Windows Kits root is unavailable; set HYDRA_WINDOWS_RC explicitly",
        ));
    }
    let compiler = select_rc(
        explicit.as_deref(),
        &kits,
        &env::var("HOST").unwrap_or_default(),
    )?;
    println!("cargo:rerun-if-changed={}", compiler.display());
    let compiled = output.join("Hydra.res");
    run(
        Command::new(compiler)
            .current_dir(&output)
            .arg("/nologo")
            .arg("/fo")
            .arg(&compiled)
            .arg("/i")
            .arg(&support)
            .arg(resource),
        "Windows SDK resource compilation",
    )?;
    if !compiled.is_file() {
        return Err(invalid("resource compiler did not produce Hydra.res"));
    }
    println!("cargo:rustc-link-arg-bin={binary}={}", compiled.display());
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn non_msvc_and_non_windows_targets_never_need_resources() {
        assert!(needs_resource("windows", "msvc"));
        for (os, abi) in [
            ("windows", "gnu"),
            ("macos", ""),
            ("linux", "gnu"),
            ("linux", "musl"),
        ] {
            assert!(!needs_resource(os, abi));
        }
    }

    #[test]
    fn sdk_versions_are_numeric_and_closed() {
        assert!(sdk_version("10.0.100.0") > sdk_version("10.0.99.0"));
        for name in ["x64", "10.0", "10.0.1.0-preview", "10.0..0", "10.0.1.0.0"] {
            assert_eq!(sdk_version(name), None);
        }
        assert_eq!(host_sdk_arch("x86_64-pc-windows-msvc").unwrap(), "x64");
    }

    #[test]
    fn explicit_sdk_selection_does_not_fall_back_to_path() {
        let root = env::temp_dir().join(format!("hydra-icon-sdk-{}", std::process::id()));
        fs::create_dir(&root).unwrap();
        struct Cleanup(PathBuf);
        impl Drop for Cleanup {
            fn drop(&mut self) {
                let _ = fs::remove_dir_all(&self.0);
            }
        }
        let _cleanup = Cleanup(root.clone());
        for version in ["10.0.99.0", "10.0.100.0"] {
            let directory = root.join(version).join("x64");
            fs::create_dir_all(&directory).unwrap();
            fs::write(directory.join("rc.exe"), b"selection fixture only").unwrap();
        }
        let host = "x86_64-pc-windows-msvc";
        let older = root.join("10.0.99.0/x64/rc.exe");
        assert_eq!(
            select_rc(None, &root, host).unwrap(),
            root.join("10.0.100.0/x64/rc.exe")
        );
        assert_eq!(
            select_rc(Some(older.as_os_str()), &root, host).unwrap(),
            older
        );
        assert!(select_rc(Some(OsStr::new("rc.exe")), &root, host).is_err());
        assert!(select_rc(Some(root.join("absent.exe").as_os_str()), &root, host).is_err());
    }

    #[test]
    fn resource_and_generator_keep_original_artwork_and_stable_ordinal() {
        assert!(include_str!("Hydra.rc").contains("1 ICON \"Hydra.ico\""));
        let generator = include_str!("New-HydraIcon.ps1");
        assert!(
            generator.contains("f083a299ea8eb42250c56338c5184a0eaaf59def36faafbf12758f07e9e0b31c")
        );
        assert!(generator.contains("@(16,20,24,32,40,48,64,128,256)"));
        assert!(!generator.contains("ExecutionPolicy"));
    }
}
