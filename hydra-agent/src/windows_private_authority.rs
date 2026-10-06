//! Windows adapter for the agent's existing private identity/lifecycle files.
//! All OS authority checks live in the shared shell boundary; no permissive non-Unix fallback.

pub(crate) use maestro_shell::{
    WindowsPrivateDirectory as Directory, WindowsPrivateFileIdentity as Identity,
};
use std::{
    ffi::OsString,
    fs::File,
    io::{self, Read},
    path::Path,
};

fn parent(path: &Path) -> io::Result<(Directory, OsString)> {
    let directory = path
        .parent()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no parent"))?;
    let name = path
        .file_name()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "private file has no name"))?;
    Ok((Directory::open(directory)?, name.to_os_string()))
}

pub(crate) fn open(path: &Path, create_new: bool) -> io::Result<File> {
    let (directory, name) = parent(path)?;
    directory.open_file(&name, create_new)
}

pub(crate) fn read(path: &Path, max: usize) -> io::Result<(Vec<u8>, Identity)> {
    let mut file = open(path, false)?;
    let identity = Directory::validate_file(&file)?;
    let mut bytes = Vec::new();
    file.by_ref()
        .take((max as u64).saturating_add(1))
        .read_to_end(&mut bytes)?;
    if bytes.len() > max {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "private authority exceeds its byte bound",
        ));
    }
    if Directory::validate_file(&file)? != identity {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private authority identity changed",
        ));
    }
    Ok((bytes, identity))
}

pub(crate) fn publish(path: &Path, bytes: &[u8], replace: bool) -> io::Result<()> {
    let (directory, name) = parent(path)?;
    directory.publish(&name, bytes, replace)
}

pub(crate) fn remove(path: &Path, expected: Option<Identity>) -> io::Result<()> {
    let (directory, name) = parent(path)?;
    let file = directory.open_file(&name, false)?;
    let observed = Directory::validate_file(&file)?;
    if expected.is_some_and(|expected| expected != observed) {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private deletion target was replaced",
        ));
    }
    directory.remove_opened_file(file)?;
    // Disposition is complete only after our handles close. Another live holder or a replacement
    // must not be mistaken for observed absence by the caller's retained recovery journal.
    match std::fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "private deletion target remained or was replaced",
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn captured_identity_cannot_retire_a_replacement() {
        let temp = tempfile::tempdir().unwrap();
        let base = temp.path().join("private-agent");
        let _root = Directory::ensure(&base).unwrap();
        let path = base.join("record.json");
        publish(&path, b"first", false).unwrap();
        let (_, original) = read(&path, 32).unwrap();
        // Retain the old object so the filesystem cannot recycle its identifier.
        let retained = open(&path, false).unwrap();
        publish(&path, b"replacement", true).unwrap();
        assert_eq!(
            remove(&path, Some(original)).unwrap_err().kind(),
            io::ErrorKind::PermissionDenied
        );
        assert_eq!(read(&path, 32).unwrap().0, b"replacement");
        assert_eq!(
            read(&path, 3).unwrap_err().kind(),
            io::ErrorKind::InvalidData
        );
        drop(retained);
        let (_, replacement) = read(&path, 32).unwrap();
        remove(&path, Some(replacement)).unwrap();
        assert_eq!(read(&path, 32).unwrap_err().kind(), io::ErrorKind::NotFound);
    }
}
