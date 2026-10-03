# Local executable plugins

Hydra's local plugin host registers a package, exposes its actions in the native command palette,
and invokes those actions through the app CLI or an explicit palette activation. This is app
functionality, not a Codex plugin or the private remote-access extension.

Plugins are ordinary programs running as your user. They inherit your environment and may use
your files, network, tools, and the full existing Hydra CLI. There is no sandbox or artificial
plugin-only command allowlist. Install code you trust; review its manifest and implementation.
Installation itself executes nothing. Only `plugin run` or selecting an action executes code.

## First plugin

Use the `maestro-app` executable from a build containing this feature. These commands are not a
claim that an already published Hydra binary contains it. Run from the repository root:

```sh
target/debug/maestro-app plugin install-local examples/plugins/retained-terminal
target/debug/maestro-app plugin list
target/debug/maestro-app plugin run example.retained-terminal open
```

The example requires Python 3. It calls the current app's `launch` command to create a real
retained terminal and native window. Closing the window or removing the plugin does not kill
that terminal. In an existing Hydra window, open the native command palette with Ctrl+K / Cmd+K, search for
`Plugin: open a retained terminal`, and activate it. Opening the palette shows cached rows and
refreshes its plugin catalog on a background worker. New rows appear without resetting a typed
query/selection or reopening a dismissed palette. Palette execution is asynchronous;
running/completion/launch errors appear only while the original palette and action remain selected.
Moving elsewhere hides late feedback but never stops the action or deletes its log.
Each palette invocation writes stdout/stderr to a private `<base>/plugins/.action-<uuid>.log`
file; the status includes its path. Logs are not automatically rotated or deleted in this slice.

All plugin commands accept `--base <directory>` to choose the app-support base; use the same base
as the GUI. `plugin run` also accepts `--socket <path>` to select an existing daemon explicitly.
The palette supplies its window's exact socket automatically. When no socket is provided, the
example uses `launch`'s existing default socket policy; it does not guess another running window.

```sh
target/debug/maestro-app plugin disable example.retained-terminal
target/debug/maestro-app plugin enable example.retained-terminal
target/debug/maestro-app plugin remove example.retained-terminal
```

Disable hides actions and refuses subsequent runs, but does not stop an already running action.
Remove deletes only registration, never source files, plugin-created files, or retained sessions.
`install-local` records a canonical source directory and a validated manifest snapshot under
`<base>/plugins`; it does not copy or download code. Script changes are live. Manifest changes
require explicit remove/reinstall. Keep the source directory available while using the plugin.

## Manifest and process contract

Place `hydra-plugin.json` at the package root:

```json
{
  "schema_version": 1,
  "id": "example.tools",
  "name": "My tools",
  "version": "0.1.0",
  "actions": [
    {"id": "run", "title": "Run my tool", "command": ["node", "index.js"]}
  ]
}
```

All shown fields are required; unknown fields are rejected. IDs use ASCII letters, digits,
dot, underscore, or hyphen (up to 80 bytes, excluding `.` and `..`). Action IDs must be unique.
Names/titles/version labels contain no control characters and are at most 160 bytes. Version is
package metadata, not a host-version compatibility promise. Schema version must be `1`.

Commands are argv arrays, not shell strings. No interpolation occurs. Use any installed language
or binary; explicitly invoke a shell if your implementation needs one. Relative executable
paths and script arguments resolve from the package directory. Arguments following
`plugin run <id> <action> --` are appended verbatim. CLI runs inherit stdio and return the
action's exit status. Palette actions have null stdin, logged output, and run off the desktop listener thread;
use a terminal launched through Hydra for an interactive tool. No runtime timeout is imposed.

The host overwrites these environment values:

| Variable | Meaning |
| --- | --- |
| `HYDRA_BIN_PATH` | Exact running app executable; invoke with argv, not a shell string. |
| `HYDRA_BASE_DIR` | Selected absolute app-support base; pass it to app CLI commands. |
| `HYDRA_SOCKET_PATH` | Explicit CLI socket or GUI window socket; absent when unspecified. |
| `HYDRA_PLUGIN_ID`, `HYDRA_PLUGIN_ROOT` | Registered identity and package working directory. |
| `HYDRA_PLUGIN_ACTION_ID` | Selected manifest action. |
| `HYDRA_PLUGIN_CONTEXT_JSON` | Object containing nullable `window_id` and `session_id`. |
| `HYDRA_WINDOW_ID`, `HYDRA_SESSION_ID` | GUI context when available; otherwise absent. |

Context describes selection, not a session lifetime proof. To read/write an existing terminal,
use the generation-safe client in `examples/local-control/hydra_client.py`: list sessions,
choose a target, attach its exact identity, then send text or watch output. Write completion
means bytes were sent, not that a shell/provider executed them. Do not blindly retry.

## Scope and qualification

The existing typed CLI provides projects, retained session launch/attach, dashboard snapshots,
and record-based window operations. Do not mistake record-based window commands for a live
split/focus API. This first slice does not yet add live pane topology control, lifecycle event
subscriptions, startup hooks, GitHub installation, or marketplace distribution. Those need
additional app/domain integration; no daemon protocol changes are required by this slice.
`plugin list` returns `result.plugins` and per-registration `result.diagnostics`; a malformed
registration does not hide healthy plugins. Remove the named broken registration to repair it.

Run the disposable real-daemon acceptance fixture (no user sessions or GUI touched):

```sh
python3 examples/local-control/plugin_demo.py \
  --app target/debug/maestro-app --daemon target/debug/pty-daemon \
  --plugin examples/plugins/retained-terminal
```

It installs the plugin in a temporary base, creates a retained terminal via the plugin, observes
a text round trip, checks disable/run refusal, and verifies unregister leaves the session alive.
Native GUI palette/window behavior still requires physical macOS/Linux qualification.
