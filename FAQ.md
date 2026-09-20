# Frequently asked questions

## What is Hydra?

Hydra is a local-first terminal desktop for running terminal sessions and coding-agent CLIs. Its
retained PTY service owns the live terminal processes, while the desktop supplies projects, panes,
layouts, provider-session discovery and a native terminal view.

This repository contains the local desktop and Remote agent, browser engine and broker source.
Official packages also integrate the independently operated hosted-service
composition described in the
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

## Which parts of Hydra Remote are open source?

The local desktop, desktop/headless Remote agent, browser terminal/controller engine and
signaling broker in this repository are open source under the [MIT License](LICENSE).
They can be inspected, built, forked and extended without Clerk or Stripe dependencies.

The browser engine provides terminal rendering, session/layout control, reconnect and encrypted
transport. The agent authenticates and authorizes remote operations before forwarding them to
retained local PTYs. Independent integrations supply services through the typed interfaces.

The hosted account website and its surrounding UI, Clerk/Stripe integrations, hosted enrollment
and authorization-service composition, billing operations, deployment configuration and relay
infrastructure remain private. This is a source release, not a turnkey self-hosted service or
a new installer. Building the source does not grant access to HydraTerms' hosted service.

See the [browser/broker quickstart](docs/developer/remote-core-quickstart.md),
[agent build guide](hydra-agent/README.md) and [public/private boundary](docs/public-private-boundary.md).

## What is Hydra's local security model?

Hydra trusts the current operating-system account and software that account deliberately runs. The
PTY daemon uses a private local socket and operating-system peer credentials to exclude other users,
but it is not a sandbox against another process already running as the same user.

The local store refuses unsafe symlinks, foreign ownership, ambiguous ancestry and unsafe file
types or link counts. Source-built desktop packages do not include the desktop remote agent or
hosted service and do not fetch HydraTerms update or model-catalog metadata automatically. The
Remote libraries have a separate source build. Report suspected vulnerabilities privately as described
in [SECURITY.md](SECURITY.md).

## How is Hydra different from Herdr?

**Herdr is an agent-aware multiplexer. Hydra combines an agent-aware native terminal,
multiplexer, and cloud connectivity.**

Herdr's interface runs inside an existing terminal emulator. Hydra includes its own native,
GPU-rendered terminal and a mouse-first desktop interface: organize projects, rename windows,
split panes, and discover existing provider sessions without assembling separate tools.

The Remote setup is different too. [Herdr's documented remote workflow requires SSH access
to the target machine](https://herdr.dev/docs/connecting-machines/). Hydra Remote connects
you to the same sessions from a browser or phone without configuring an SSH server, SSH keys,
or an inbound SSH port. The sessions stay on your machine; Remote gives you another way to
reach them.

Both retain running sessions independently of the attached interface. Hydra brings the terminal,
multiplexing, session discovery, and remote access together in one product.

## What is the difference between an official package and a source build?

A source build contains the public local desktop and uses development-only state when run through
the fast developer harness. It is unsigned, does not contain the separately built remote agent and does not
receive official update or model-catalog metadata by default.

Official packages are signed production artifacts with the installed launcher and service topology.
They may include Hydra Remote. Follow [DEVELOPMENT.md](DEVELOPMENT.md) when comparing source and
installed behavior.
