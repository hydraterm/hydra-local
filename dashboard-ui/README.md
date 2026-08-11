# Hydra desktop dashboard UI

`dashboard-ui` is the React presentation chrome bundled into the native Hydra desktop app. It is not
a standalone terminal and does not own sessions, layouts or filesystem authority.

## Product boundary

- Rust (`maestro-app` and `maestro-shell`) owns projects, windows, panes, sessions, mutations and
  authoritative dashboard models.
- `maestro-renderer` owns the native WGPU terminal and terminal geometry.
- React renders sidebar, topbar and overlays, reads the host model, and emits typed intents through
  the bridge in `src/ipc/bridge.ts`.
- macOS hosts the chrome through WRY/WKWebView.
- Linux hosts WebKitGTK chrome beside a WGPU child surface on Wayland or X11.

Plain browser development can use the wire-shaped mock. Native builds inject
`window.hydraDashboard` and platform IPC. A mock or browser success is not evidence that a native
host routed an intent correctly.

## Commands

From the repository root:

```sh
npm --prefix dashboard-ui ci
npm --prefix dashboard-ui run typecheck
npm --prefix dashboard-ui test
npm --prefix dashboard-ui run build
```

The production build is inlined by `scripts/inline-dist.mjs` and packaged as trusted application
assets. Hosts still validate every message through the Rust intent decoder.

## Change rules

- Update React intent types and the Rust decoder/dispatcher together.
- Unknown, malformed, oversized or unavailable-context intents must not mutate state.
- Never add generic command execution, raw filesystem access, terminal content, long-lived
  credentials or account secrets to dashboard IPC.
- UI actions refresh from authoritative Rust state; do not maintain an independent mutation model.
- Validate keyboard navigation, focus, accessibility, collapse/resize, picker flows and both native
  hosts for shared chrome changes.

Read the [public/private boundary](../docs/public-private-boundary.md) before changing authority or
extension behavior. General contribution and platform-test requirements are in
[CONTRIBUTING.md](../CONTRIBUTING.md) and [DEVELOPMENT.md](../DEVELOPMENT.md).

