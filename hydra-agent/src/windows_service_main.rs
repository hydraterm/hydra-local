//! The Windows scheduled service runs the same agent directly with a GUI PE subsystem, so
//! Task Scheduler never creates a console window. The interactive hydra-agent remains a console
//! executable with its existing stdout and wait behavior. No wrapper process or extra owner.
#![cfg_attr(windows, windows_subsystem = "windows")]

#[path = "main.rs"]
mod agent_cli;

fn main() -> anyhow::Result<()> {
    agent_cli::main()
}
