# Hydra

Hydra is a local-first terminal desktop for macOS and Linux, built for terminal sessions and coding
agents.

[Download](https://hydraterms.com/#direct-downloads-heading) ·
[Features](#what-is-in-this-repository) · [Build](#build) ·
[Privacy](https://hydraterms.com/privacy.html)

![Synthetic Hydra local desktop showing a neutral project, retained panes and a local test run](docs/assets/hydra-local-demo.gif)

*Synthetic product illustration; no account, terminal transcript, personal path or live desktop was
recorded.*

Projects, windows, panes, terminal history and retained PTY sessions live on your machine.

## Start here

- [Remote library quickstart](docs/developer/remote-core-quickstart.md) — build the reusable browser
  transport and signaling broker, and implement your own adapters.

- [Frequently asked questions](FAQ.md) — tmux, Electron, retention, Remote, security and Herdr.
- [Architecture](docs/architecture.md) — PTY ownership, native rendering, dashboard composition and
  the macOS/Linux host split.
- [Troubleshooting](TROUBLESHOOTING.md) — local-data migration, agent discovery and Linux display
  backends.
- [Development](DEVELOPMENT.md) and [contributing](CONTRIBUTING.md) — build, test and contribution
  contracts.

## Install

Official macOS package:

```sh
brew install --cask hydraterm/hydra/hydraterms
```

Official Linux package:

```sh
curl -fsSL https://hydraterms.com/install.sh | sh
```

Official packages include the separate proprietary Hydra Remote component. A source build from
this repository is a complete local desktop; it does not include the private remote agent or access
to the hosted service.

## What is in this repository

- the PTY daemon and retained-session model;
- the native terminal renderer;
- local projects, windows, panes and layouts;
- local provider and previous-session discovery;
- the desktop dashboard;
- local macOS and Linux platform support;
- the bounded API used to request optional desktop extensions;
- the reusable browser WebRTC transport in `web-client`; and
- the content-blind signaling broker in `hydra-cloud`.

### Provider interoperability

Hydra reads provider-owned local session metadata so it can list and resume sessions created by
Claude Code, Codex CLI, GitHub Copilot CLI, Antigravity, Kimi CLI, Kiro CLI, OpenCode, Cursor Agent,
Devin CLI and the legacy Gemini CLI. These on-disk formats belong to their providers and may change.
Discovery runs locally; HydraTerms does not receive transcript content. Amp and Factory/Droid can
be launched and resumed through their CLIs, but Hydra does not read their history stores.

## Open source and Hydra Remote

Hydra's local desktop and the Remote transport/signaling libraries in this repository are open
source under the [MIT License](LICENSE). You can build, fork, extend and contribute to them.

The Remote libraries provide a browser WebRTC transport and a content-blind signaling broker with
typed integration interfaces. They do not require Clerk or Stripe. They are reusable components,
not a complete self-hosted Remote application or a replacement for Hydra's desktop remote agent.

The hosted account website, Clerk and Stripe integrations, account/billing operations, enrollment
and authorization-service composition, deployment configuration, relay operation and desktop agent
remain outside this source release. The local desktop works independently of those services.
Installing the libraries does not enable Remote controls in a source-built desktop or grant access
to HydraTerms' hosted service. The private agent remains the final authority for remote terminal
operations. See [the public/private boundary](docs/public-private-boundary.md) for the exact scope
and threat model.

## Build

Install the prerequisites in [DEVELOPMENT.md](DEVELOPMENT.md), then run:

```sh
./scripts/build-local.sh
cargo run -p maestro-app -- launch
```

That `cargo run` command is the fast, isolated developer harness. It uses development-only state
and is not the installed application topology. To exercise the local desktop through the same
launcher, daemon-retention and bundled-dashboard shape as a package, use the unsigned packaging
and launch instructions in [DEVELOPMENT.md](DEVELOPMENT.md).

The repository pins the normal contributor Rust toolchain separately from its minimum supported
Rust version. See DEVELOPMENT.md before substituting toolchain versions.

## Test

```sh
./scripts/test-local.sh
```

The repository also contains local-only unsigned packaging smoke scripts for macOS and Linux.
They never bundle the proprietary remote agent and do not produce an official signed release; see
[DEVELOPMENT.md](DEVELOPMENT.md).

Platform UI behavior still needs physical testing on macOS and, on Linux, both native Wayland and
X11. A browser-only dashboard test does not prove native host behavior.

### Compatibility names

Hydra is the product name. Some crates, environment variables, schemas and durable state paths
retain `maestro-*`, `MAESTRO_*`, `maestro.*` or `Maestro` names so existing local data and extension
interfaces remain compatible. They are stable implementation identifiers, not a second product or
a hidden remote component; changing them requires an explicit data migration.

## Contributing

Bug fixes, documentation, platform compatibility and packaging improvements are welcome.
Architectural changes require an accepted issue before implementation. See
[CONTRIBUTING.md](CONTRIBUTING.md) and [DEVELOPMENT.md](DEVELOPMENT.md).

Every contribution uses the [Developer Certificate of Origin](DCO.md). Sign off each commit with
`git commit -s`; the required DCO check verifies every pull request. HydraTerms does not require a
contributor licence agreement or copyright assignment.

## Security

Do not report vulnerabilities in a public issue. Follow [SECURITY.md](SECURITY.md) or email
[security@hydraterms.com](mailto:security@hydraterms.com).

## Licence and marks

First-party code in this repository is licensed under the [MIT License](LICENSE). That licence
does not include the private Hydra Remote implementation or hosted service, and it grants no rights
to HydraTerms names or logos. See [TRADEMARKS.md](TRADEMARKS.md).

Third-party dependencies retain their own licences; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).
Previously published Apache-2.0 versions remain available under their original licence grants.

## Sponsor

Hydra's development is funded by [Pairextr Teknoloji ve Yazılım A.Ş.](https://www.pairextr.com/)
Hydra and HydraTerms remain marks of HydraTerms Limited; sponsorship grants no ownership of the
project or its marks.
