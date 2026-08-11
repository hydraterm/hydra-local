//! maestro-renderer — native GPU renderer for the pty-daemon's authoritative
//! grid. This binary is a thin CLI front-end: it parses arguments and dispatches
//! into the `maestro_renderer` library, which owns the entire runtime (window,
//! event loop, rendering, input, scrollback). See `lib.rs` for the runtime and
//! the public `run_renderer` / `run_demo_scene` / `run_stress` entrypoints, and
//! for the winit main-thread / event-loop-ownership constraint those calls carry.
//!
//! Usage: maestro-renderer [--font-size-px <px>] [--theme <id>] <socket-path> <session-id>
//!        maestro-renderer --demo-scene
//!        maestro-renderer --stress <mode>

use maestro_renderer::{
    parse_renderer_cli, run_demo_scene, run_renderer, run_stress, RendererLaunch, RendererRunError,
    StressMode,
};

fn print_usage() {
    eprintln!(
        "usage: maestro-renderer [--font-size-px <px>] [--theme <id>] <socket-path> <session-id>"
    );
    eprintln!("       maestro-renderer --demo-scene");
    eprintln!("       maestro-renderer --stress <{}>", StressMode::names());
}

fn main() {
    let args: Vec<String> = std::env::args().collect();

    // Deterministic, shell-independent test scene: paint a hand-built fixture grid
    // instead of attaching to the daemon. Isolates renderer correctness from shell
    // quoting and PTY behavior.
    if args.get(1).map(String::as_str) == Some("--demo-scene") {
        finish(run_demo_scene());
        return;
    }

    // Reproducible renderer stress mode: paint a fixed dense grid and, with
    // MAESTRO_RENDER_STATS=1, print per-frame cost so the hot path can be measured and
    // optimized deterministically.
    if args.get(1).map(String::as_str) == Some("--stress") {
        let mode = args.get(2).and_then(|s| StressMode::parse(s));
        match mode {
            Some(m) => finish(run_stress(m)),
            None => {
                eprintln!("usage: maestro-renderer --stress <{}>", StressMode::names());
                std::process::exit(2);
            }
        }
        return;
    }

    let cli = match parse_renderer_cli(&args[1..]) {
        Ok(cli) => cli,
        Err(msg) => {
            eprintln!("maestro-renderer: {msg}");
            print_usage();
            std::process::exit(2);
        }
    };

    // The CLI keeps the historical title (None -> `maestro-renderer`); app-owned titles come from
    // library callers like `maestro-app`, not the bare renderer binary. `font_size_px` / `theme`
    // are `None` for the bare positional form and `Some(..)` when `--font-size-px` / `--theme` are
    // supplied (the form the detached `maestro-app` child uses to inherit the resolved
    // `appearance.font_size_px` / `appearance.theme`).
    finish(run_renderer(RendererLaunch {
        socket_path: cli.socket_path,
        session_id: cli.session_id,
        window_title: None,
        status_label: None,
        tab_strip: None,
        top_tab_bar: false,
        dashboard_panel: None,
        picker: None,
        command_palette: None,
        font_size_px: cli.font_size_px,
        theme: cli.theme,
        react_chrome: None,
    }));
}

/// Map a renderer run result to process exit: success is a clean return; a runtime
/// error is reported on stderr and exits non-zero (1), distinct from the usage exit (2).
fn finish(result: Result<(), RendererRunError>) {
    if let Err(err) = result {
        eprintln!("maestro-renderer: {err}");
        std::process::exit(1);
    }
}
