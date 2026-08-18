# Local desktop architecture

This page describes the open local desktop in this repository. It does not describe the private
Hydra Remote implementation.

## Process and ownership map

```text
                              typed dashboard intents
  React dashboard chrome  ------------------------------+
       (WebView)                                           |
                                                           v
  hydra-launcher  --->  maestro-app  --->  maestro-shell / maestro-local-services
                            |                    |
                            |                    +-- projects, windows, panes,
                            |                        durable local records,
                            |                        provider discovery
                            |
                            +-- maestro-renderer
                            |      Rust/WGPU terminal rendering,
                            |      input, selection and geometry
                            |
                            +-- maestro-extension-api
                            |      bounded optional extension requests
                            |
                            +-- maestro-protocol client
                                      |
                                      v
                                 pty-daemon
                                      |
                                      +-- PTYs and child processes
                                      +-- terminal parsing and grids
                                      +-- scrollback and retained sessions
```

The important ownership rule is that `pty-daemon`, not the desktop window, owns live terminal
processes. Closing or crashing the UI can disconnect a client without terminating the retained PTY.

## Component responsibilities

| Component | Responsibility |
|---|---|
| `hydra-launcher` | Starts the packaged local application topology without resolving trusted binaries through ambient `PATH` |
| `pty-daemon` | Owns PTYs, terminal parsing, authoritative grids, scrollback and retained-session lifetime |
| `maestro-protocol` | Defines bounded local protocol types and framing shared with the daemon client |
| `maestro-renderer` | Draws the native WGPU terminal and owns terminal input, selection and geometry |
| `maestro-shell` | Owns projects, windows, panes, layouts and durable local records |
| `maestro-local-services` | Implements local provider history, project discovery and launch defaults |
| `maestro-app` | Composes the domain, daemon client, renderer and typed dashboard intents |
| `dashboard-ui` | Supplies React presentation chrome; it owns no PTY or generic shell execution |
| `maestro-extension-api` | Defines the bounded, version-negotiated request seam for an optional sibling extension |

## Native terminal and dashboard composition

Hydra is not Electron and the terminal is not an HTML terminal emulator. Rust parses terminal output
and WGPU draws the grid into a native presentation surface. Rust remains authoritative for the
terminal rectangle, cell geometry, input routing, selection and scrollback.

React renders project, pane, picker and settings chrome in platform WebViews. The dashboard sends a
closed set of typed intents to the Rust host. It cannot execute arbitrary commands, read arbitrary
files or take ownership of terminal geometry.

## macOS and Linux hosts

The shared renderer and product model do not fork by platform. Platform adapters provide the window
and presentation surfaces:

- macOS uses the established native winit renderer path and the platform WebView composition;
- Linux uses a Tao/GTK/WRY host;
- native Wayland presents WGPU through a real child `wl_subsurface`; and
- X11 presents through a GTK-owned child XID.

Wayland and X11 share the same GTK layout, input and product policy. Their native presentation
details differ, so renderer or window-host changes need physical qualification on both native
Wayland and real X11. XWayland is not a substitute for either claim.

## Durable local state

`maestro-shell` stores Hydra-owned local records in SQLite under an owner-only app-support
directory. Before opening the store, the filesystem boundary walks directory ancestry by
descriptor, refuses user-controlled symlinks and foreign ownership, and validates store files by
owner, type, mode and link count.

Provider-history discovery reads only the bounded metadata required for supported integrations.
Provider stores remain provider-owned; Hydra does not rewrite them merely to discover or list a
session.

## Local trust boundary

The daemon's private Unix socket and kernel peer credentials exclude other operating-system users.
Processes already running as the same user remain inside Hydra's trusted local-account boundary and
can normally access that user's terminal data and other secrets. Hydra does not claim to protect a
compromised user account from itself.

The optional extension API is not remote authority. The public app can invoke only a literal sibling
extension command, sends one bounded typed request over standard input and accepts one negotiated
response. It cannot choose a cloud, browser origin, verification key, account, device identity or
service definition. If the extension is missing or refuses a request, local Hydra continues to work
and Remote remains unavailable.

Read [the public/private boundary](public-private-boundary.md) before changing a process, protocol,
filesystem or extension boundary.

## Where changes belong

- PTY lifecycle, parsing, grids or scrollback: `pty-daemon`
- local wire types: `maestro-protocol` and every protocol mirror
- terminal drawing, input or geometry: `maestro-renderer`
- projects, panes, records or migrations: `maestro-shell`
- provider discovery and local launch defaults: `maestro-local-services`
- dashboard presentation: `dashboard-ui`
- typed intent orchestration and platform composition: `maestro-app`

Protocol, durable-record, renderer-host and extension-boundary changes are architectural. Open an
issue and obtain agreement before implementation, then update every affected mirror and test.
