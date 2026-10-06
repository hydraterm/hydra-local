//! Native package entrypoint; product behavior remains in maestro-app.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[cfg(unix)]
mod unix;
#[cfg(windows)]
mod windows;

fn main() {
    #[cfg(unix)]
    unix::main();
    #[cfg(windows)]
    windows::main();
}
