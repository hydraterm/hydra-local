//! Local desktop services shared by the native app and optional authenticated extensions.
//!
//! This crate owns local provider-history discovery and durable project-launch default resolution,
//! but no renderer, WebRTC, cloud, account, authorization, or transport behavior.

pub mod agent_history;
pub mod launch_environment;
pub mod project_defaults;

pub use launch_environment::LOGIN_SHELL_COMMAND_FLAGS;
pub use project_defaults::{inherited_project_launch_inputs, InheritedProjectLaunchInputs};
