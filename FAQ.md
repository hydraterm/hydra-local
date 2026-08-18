# Frequently asked questions

## What is Hydra?

Hydra is a local-first terminal desktop for running terminal sessions and coding-agent CLIs. Its
retained PTY service owns the live terminal processes, while the desktop supplies projects, panes,
layouts, provider-session discovery and a native terminal view.

This repository is the complete local desktop. Official packages may also include the separate,
proprietary Hydra Remote component described in the
[public/private boundary](docs/public-private-boundary.md).

## Why not use tmux or Zellij?

Use tmux or Zellij if a terminal multiplexer already gives you the workflow you want. They are
excellent at persistent terminal workspaces.

Hydra addresses a different layer: it discovers supported coding-agent sessions, associates panes
with local projects and durable records, renders terminals in its own desktop UI, and provides
agent-oriented launch and resume flows. Hydra does not run inside your existing terminal and does
not claim to replace every multiplexer workflow.

## Is Hydra an Electron application?

No. The terminal is parsed and rendered by Rust code with WGPU. React provides the dashboard chrome
inside the operating system's WebView; it does not own the PTY, terminal grid, terminal geometry or
generic command execution. See [the architecture overview](docs/architecture.md).

## What happens when I close Hydra?

Closing or relaunching the desktop does not terminate PTYs retained by the separately running local
daemon. Reopening Hydra can attach to those live sessions.

A computer restart is different: the operating system stops the terminal processes. Hydra can use
durable local records to resume supported provider sessions after login, but that is a new provider
process, not the original process surviving the reboot.

## How does provider discovery work?

Hydra reads bounded metadata from supported providers' local history stores and combines it with its
own local project and session records. Provider-owned formats can change, so support is maintained
provider by provider. Discovery is local; HydraTerms does not receive transcript content from this
repository's local desktop.

The current provider coverage and its limits are listed in the
[README](README.md#provider-interoperability).

## Why is Hydra Remote not open source?

Hydra Remote is a separate hosted product. Its desktop agent, browser client, cloud coordination,
identity, entitlement, billing, signaling and relay systems are maintained privately. The public
desktop remains fully usable without it.

This is a product and source boundary, not a claim that secrecy provides security. The private
agent must authenticate and authorize remote operations; a modified public app cannot grant itself
remote authority. The exact scope and trust model are documented in the
[public/private boundary](docs/public-private-boundary.md).

## What is Hydra's local security model?

Hydra trusts the current operating-system account and software that account deliberately runs. The
PTY daemon uses a private local socket and operating-system peer credentials to exclude other users,
but it is not a sandbox against another process already running as the same user.

The local store refuses unsafe symlinks, foreign ownership, ambiguous ancestry and unsafe file
types or link counts. Source builds do not contain Hydra Remote and do not fetch HydraTerms update
or model-catalog metadata automatically. Report suspected vulnerabilities privately as described
in [SECURITY.md](SECURITY.md).

## How is Hydra different from Herdr?

[Herdr](https://herdr.dev/) describes itself as a terminal-native agent runtime and multiplexer: one
server owns panes, its TUI runs in an existing terminal, and a local socket API lets tools and agents
control the runtime.

Hydra is a desktop terminal product. It combines a native WGPU terminal with project organization,
provider-history discovery, graphical panes and dashboard workflows. Both products retain terminal
sessions independently of the UI that is currently attached, but their interfaces and automation
models are different. Herdr is the stronger fit when terminal-native multiplexing and a socket API
are the priority; Hydra is designed for users who want a dedicated desktop workspace around their
existing agent CLIs.

## What is the difference between an official package and a source build?

A source build contains the public local desktop and uses development-only state when run through
the fast developer harness. It is unsigned, does not contain the private remote agent and does not
receive official update or model-catalog metadata by default.

Official packages are signed production artifacts with the installed launcher and service topology.
They may include Hydra Remote. Follow [DEVELOPMENT.md](DEVELOPMENT.md) when comparing source and
installed behavior.
