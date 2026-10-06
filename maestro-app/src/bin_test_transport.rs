//! Real local transport fixtures: Unix sockets or same-process Windows named pipes.
//! Protocol scripts stay identical; the production Windows client still authenticates the server.

use std::path::{Path, PathBuf};

pub(crate) fn endpoint(directory: &Path, name: &str) -> PathBuf {
    #[cfg(unix)]
    {
        directory.join(name)
    }
    #[cfg(windows)]
    {
        use std::hash::{Hash, Hasher};
        let mut hash = std::collections::hash_map::DefaultHasher::new();
        directory.hash(&mut hash);
        name.hash(&mut hash);
        PathBuf::from(format!(
            r"\\.\pipe\Hydra.Maestro.bin-test-{}-{:016x}",
            std::process::id(),
            hash.finish()
        ))
    }
}

#[cfg(unix)]
pub(crate) use std::os::unix::net::{UnixListener as Listener, UnixStream as Stream};
#[cfg(windows)]
pub(crate) use windows::{Listener, Stream};

#[cfg(windows)]
#[path = "bin_test_transport_windows.rs"]
mod windows;
