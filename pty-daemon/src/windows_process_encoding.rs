//! Lossless buffers for an already-selected native Windows process.
//!
//! These are the ConPTY backend's owned launch buffers, not executable discovery or a second
//! launch policy. Paths are preserved verbatim; the caller selects the
//! executable, environment and working directory before constructing these owned buffers.

use anyhow::{anyhow, bail, Context as _, Result};
use std::cmp::Ordering;
use std::ffi::{OsStr, OsString};
use std::io;
use std::os::windows::ffi::{OsStrExt as _, OsStringExt as _};
use windows_sys::Win32::Globalization::{
    CompareStringOrdinal, CSTR_EQUAL, CSTR_GREATER_THAN, CSTR_LESS_THAN,
};
use windows_sys::Win32::System::Environment::{FreeEnvironmentStringsW, GetEnvironmentStringsW};

// CreateProcessW's actual limit includes the terminating NUL, unlike the unrelated ANSI
// environment limit. No Hydra-defined environment size ceiling is imposed here.
const MAX_COMMAND_LINE_UNITS: usize = 32_767;

pub(super) struct PreparedProcess {
    pub(super) application: Vec<u16>,
    pub(super) command_line: Vec<u16>,
    pub(super) environment: Vec<u16>,
    pub(super) current_directory: Option<Vec<u16>>,
}

impl PreparedProcess {
    pub(super) fn new(
        executable: &OsStr,
        arguments: &[OsString],
        environment: &[(OsString, OsString)],
        current_directory: Option<&OsStr>,
    ) -> Result<Self> {
        if executable.is_empty() {
            bail!("Windows process must name an executable");
        }
        ensure_no_nul(executable, "executable")?;
        let mut command_line = Vec::new();
        append_windows_quoted(executable, &mut command_line);
        for argument in arguments {
            ensure_no_nul(argument, "command-line argument")?;
            command_line.push(b' ' as u16);
            append_windows_quoted(argument, &mut command_line);
        }
        Self::with_command_line(
            executable,
            &OsString::from_wide(&command_line),
            environment,
            current_directory,
        )
    }

    // Common owned-buffer finalization. The native adapter supplies cmd's distinct batch grammar;
    // ordinary native argv above still uses exactly the existing MSCRT encoder.
    pub(super) fn with_command_line(
        executable: &OsStr,
        line: &OsStr,
        environment: &[(OsString, OsString)],
        current_directory: Option<&OsStr>,
    ) -> Result<Self> {
        if executable.is_empty() {
            bail!("Windows process must name an executable");
        }
        ensure_no_nul(executable, "executable")?;
        ensure_no_nul(line, "command line")?;
        let application = executable.encode_wide().chain(Some(0)).collect();
        let command_line: Vec<_> = line.encode_wide().chain(Some(0)).collect();
        if command_line.len() > MAX_COMMAND_LINE_UNITS {
            bail!("Windows command line exceeds 32,767 UTF-16 code units");
        }
        let current_directory = current_directory
            .map(|directory| {
                ensure_no_nul(directory, "working directory")?;
                Ok::<_, anyhow::Error>(directory.encode_wide().chain(Some(0)).collect())
            })
            .transpose()?;
        Ok(Self {
            application,
            command_line,
            environment: build_environment_block(environment)?,
            current_directory,
        })
    }
}

fn ensure_no_nul(value: &OsStr, label: &str) -> Result<()> {
    if value.encode_wide().any(|unit| unit == 0) {
        bail!("Windows {label} contains a NUL code unit");
    }
    Ok(())
}

fn append_windows_quoted(argument: &OsStr, output: &mut Vec<u16>) {
    let units: Vec<u16> = argument.encode_wide().collect();
    let needs_quotes = units.is_empty()
        || units
            .iter()
            .any(|unit| matches!(*unit, 0x09 | 0x0a | 0x0b | 0x0d | 0x20 | 0x22));
    if !needs_quotes {
        output.extend(units);
        return;
    }

    output.push(b'"' as u16);
    let mut index = 0usize;
    while index < units.len() {
        let start = index;
        while index < units.len() && units[index] == b'\\' as u16 {
            index += 1;
        }
        let slashes = index - start;
        if index == units.len() {
            output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2));
            break;
        }
        if units[index] == b'"' as u16 {
            output.extend(std::iter::repeat_n(b'\\' as u16, slashes * 2 + 1));
        } else {
            output.extend(std::iter::repeat_n(b'\\' as u16, slashes));
        }
        output.push(units[index]);
        index += 1;
    }
    output.push(b'"' as u16);
}

struct EnvironmentStrings(*mut u16);

impl Drop for EnvironmentStrings {
    fn drop(&mut self) {
        unsafe {
            FreeEnvironmentStringsW(self.0);
        }
    }
}

pub(super) fn snapshot_environment() -> Result<Vec<(OsString, OsString)>> {
    let raw = unsafe { GetEnvironmentStringsW() };
    if raw.is_null() {
        return Err(io::Error::last_os_error()).context("snapshot Windows environment");
    }
    let raw = EnvironmentStrings(raw);
    let mut result = Vec::new();
    let mut offset = 0usize;
    loop {
        let start = offset;
        while unsafe { *raw.0.add(offset) } != 0 {
            offset = offset
                .checked_add(1)
                .ok_or_else(|| anyhow!("Windows environment size overflow"))?;
        }
        if offset == start {
            break;
        }
        let entry = unsafe { std::slice::from_raw_parts(raw.0.add(start), offset - start) };
        let separator = if entry.first() == Some(&(b'=' as u16)) {
            entry
                .iter()
                .enumerate()
                .skip(1)
                .find(|(_, unit)| **unit == b'=' as u16)
        } else {
            entry
                .iter()
                .enumerate()
                .find(|(_, unit)| **unit == b'=' as u16)
        }
        .map(|(index, _)| index)
        .ok_or_else(|| anyhow!("Windows returned a malformed environment entry"))?;
        if separator == 0 || separator + 1 > entry.len() {
            bail!("Windows returned an invalid environment-variable name");
        }
        result.push((
            OsString::from_wide(&entry[..separator]),
            OsString::from_wide(&entry[separator + 1..]),
        ));
        offset += 1;
    }
    Ok(result)
}

fn build_environment_block(env: &[(OsString, OsString)]) -> Result<Vec<u16>> {
    let mut entries: Vec<_> = env.iter().collect();
    entries.sort_by(|(left, _), (right, _)| wide_case_cmp(left, right));
    for pair in entries.windows(2) {
        if wide_case_cmp(&pair[0].0, &pair[1].0) == Ordering::Equal {
            bail!("duplicate case-insensitive Windows environment-variable name");
        }
    }

    let mut block = Vec::new();
    for (key, value) in entries {
        ensure_no_nul(key, "environment-variable name")?;
        ensure_no_nul(value, "environment-variable value")?;
        let key_units: Vec<u16> = key.encode_wide().collect();
        if key_units.is_empty()
            || key_units
                .iter()
                .enumerate()
                .any(|(index, unit)| *unit == b'=' as u16 && index != 0)
        {
            bail!("invalid Windows environment-variable name");
        }
        block.extend(key_units);
        block.push(b'=' as u16);
        block.extend(value.encode_wide());
        block.push(0);
    }
    if block.is_empty() {
        block.push(0);
    }
    block.push(0);
    Ok(block)
}

pub(super) fn wide_case_cmp(left: &OsStr, right: &OsStr) -> Ordering {
    let left: Vec<u16> = left.encode_wide().collect();
    let right: Vec<u16> = right.encode_wide().collect();
    let Ok(left_len) = i32::try_from(left.len()) else {
        return left.cmp(&right);
    };
    let Ok(right_len) = i32::try_from(right.len()) else {
        return left.cmp(&right);
    };
    match unsafe { CompareStringOrdinal(left.as_ptr(), left_len, right.as_ptr(), right_len, 1) } {
        CSTR_LESS_THAN => Ordering::Less,
        CSTR_EQUAL => Ordering::Equal,
        CSTR_GREATER_THAN => Ordering::Greater,
        _ => left.cmp(&right),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn quote(value: &str) -> String {
        let mut output = Vec::new();
        append_windows_quoted(OsStr::new(value), &mut output);
        String::from_utf16(&output).unwrap()
    }

    #[test]
    fn quoting_handles_empty_spaces_quotes_and_trailing_slashes() {
        assert_eq!(quote("plain"), "plain");
        assert_eq!(quote(""), "\"\"");
        assert_eq!(quote("two words"), "\"two words\"");
        assert_eq!(quote("say\\\"hi"), "\"say\\\\\\\"hi\"");
        assert_eq!(
            quote("C:\\path with space\\"),
            "\"C:\\path with space\\\\\""
        );
    }

    #[test]
    fn native_buffers_preserve_utf16_paths_arguments_and_environment() {
        let program = OsString::from_wide(&[b'C' as u16, b':' as u16, b'\\' as u16, 0xd800]);
        let argument = OsString::from_wide(&[b'a' as u16, 0xdc00]);
        let value = OsString::from_wide(&[0xd800, b'x' as u16]);
        let prepared = PreparedProcess::new(
            &program,
            std::slice::from_ref(&argument),
            &[("HYDRA_TEST".into(), value.clone())],
            Some(&program),
        )
        .unwrap();
        assert_eq!(
            prepared.application,
            program.encode_wide().chain(Some(0)).collect::<Vec<_>>()
        );
        assert_eq!(
            prepared.current_directory,
            Some(prepared.application.clone())
        );
        assert!(prepared
            .command_line
            .windows(2)
            .any(|pair| pair == [b'a' as u16, 0xdc00]));
        assert!(prepared
            .environment
            .windows(2)
            .any(|pair| pair == [0xd800, b'x' as u16]));
        assert_eq!(prepared.command_line.last(), Some(&0));
        assert!(prepared.environment.ends_with(&[0, 0]));
    }

    #[test]
    fn environment_is_sorted_case_insensitively_and_preserves_drive_entries() {
        let env = vec![
            (OsString::from("zLAST"), OsString::from("last")),
            (OsString::from("Path"), OsString::from("first")),
            (OsString::from("=C:"), OsString::from(r"C:\work")),
        ];
        let block = build_environment_block(&env).unwrap();
        assert_eq!(
            String::from_utf16(&block).unwrap(),
            "=C:=C:\\work\0Path=first\0zLAST=last\0\0"
        );
        assert_eq!(
            wide_case_cmp(OsStr::new("PATH"), OsStr::new("path")),
            Ordering::Equal
        );
        assert_eq!(build_environment_block(&[]).unwrap(), [0, 0]);
        let duplicate = [("Path".into(), "one".into()), ("PATH".into(), "two".into())];
        assert!(build_environment_block(&duplicate).is_err());
    }

    #[test]
    fn unicode_environment_has_no_ansi_or_hydra_one_million_unit_ceiling() {
        // Each variable is below the documented per-variable Windows size; the combined block
        // exceeds both the ANSI 32K block bound and the old arbitrary Hydra allocation ceiling.
        let env: Vec<_> = (0..64)
            .map(|index| {
                (
                    OsString::from(format!("HYDRA_TEST_LARGE_{index:02}")),
                    OsString::from("x".repeat(16_500)),
                )
            })
            .collect();
        let block = build_environment_block(&env).unwrap();
        assert!(block.len() > 1_048_576);
        assert!(block.ends_with(&[0, 0]));
    }

    #[test]
    fn command_line_uses_the_actual_win32_limit_including_terminating_nul() {
        let argument = OsString::from("x".repeat(MAX_COMMAND_LINE_UNITS - 3));
        let accepted = PreparedProcess::new(OsStr::new("p"), &[argument], &[], None).unwrap();
        assert_eq!(accepted.command_line.len(), MAX_COMMAND_LINE_UNITS);
        assert!(accepted.current_directory.is_none());
        let oversized = OsString::from("x".repeat(MAX_COMMAND_LINE_UNITS - 2));
        let error = PreparedProcess::new(OsStr::new("p"), &[oversized], &[], None)
            .err()
            .unwrap();
        assert!(error.to_string().contains("32,767"));
    }

    #[test]
    fn interior_nul_cannot_truncate_a_native_field() {
        let nul = OsString::from_wide(&[b'a' as u16, 0, b'b' as u16]);
        assert!(PreparedProcess::new(&nul, &[], &[], None).is_err());
        assert!(
            PreparedProcess::new(OsStr::new("p"), std::slice::from_ref(&nul), &[], None).is_err()
        );
        assert!(PreparedProcess::new(OsStr::new("p"), &[], &[], Some(&nul)).is_err());
        assert!(build_environment_block(&[(nul.clone(), "value".into())]).is_err());
        assert!(build_environment_block(&[("KEY".into(), nul)]).is_err());
        assert!(build_environment_block(&[("bad=key".into(), "value".into())]).is_err());
        assert!(build_environment_block(&[("".into(), "value".into())]).is_err());
        assert!(PreparedProcess::new(OsStr::new(""), &[], &[], None).is_err());
    }
}
