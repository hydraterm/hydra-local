//! Shared app-wide constants for the `maestro-app` harness.
//!
//! Shared values are gathered here so the crate root stays a thin module/re-export hub. They are
//! re-exported from the crate root (`maestro_app::<NAME>`) for the binary, package qualification,
//! feature modules, and in-crate tests.

/// The default session id when `--session-id` is omitted. Passes `maestro_shell::validate_id`
/// (`[A-Za-z0-9_-]`), so it can be used both as the durable record id and the daemon `SessionId`.
pub const DEFAULT_SESSION_ID: &str = "maestro-app-dev";

/// Stable durable coordinates used by the installed desktop product's built-in Terminal startup.
/// The product launcher reuses these exact ids on every open so a relaunch attaches to the retained
/// PTY and its project-owned tab instead of minting an ad-hoc `main` window/session alongside it.
pub const SYSTEM_TERMINAL_PROJECT_ID: &str = "system-terminal";
pub const SYSTEM_TERMINAL_WORKSPACE_ID: &str = "system-terminal-workspace-1";
pub const SYSTEM_TERMINAL_WINDOW_ID: &str = "system-terminal-window-1";
pub const SYSTEM_TERMINAL_TAB_ID: &str = "pane-1";
pub const SYSTEM_TERMINAL_SESSION_ID: &str = "system-terminal-pane-1";

/// Reserved project identity for the product launcher's internal recovery shell. The project stays
/// durable so startup always has a safe terminal fallback, but app-facing dashboard and dock
/// projections exclude it by exact id.
pub const PRODUCT_RECOVERY_PROJECT_ID: &str = "system-product-recovery";

/// Default terminal geometry for the harness session.
pub const DEFAULT_COLS: u16 = 80;
pub const DEFAULT_ROWS: u16 = 24;

/// Maximum accepted `--title` length (characters), to keep window metadata bounded. A title longer
/// than this is rejected as a usage error rather than silently truncated.
pub const TITLE_MAX_LEN: usize = 256;

/// The bounded number of times the planner re-mints an id that collides with the snapshot before it
/// gives up with [`NewTabAbortReason::IdMintExhausted`](crate::NewTabAbortReason). Small by design: a
/// real UUIDv4 generator never collides, so any collision here means a deterministic/test generator
/// that cannot satisfy uniqueness, and looping forever would hang the foreground listener.
pub const ID_MINT_ATTEMPTS: u32 = 8;
