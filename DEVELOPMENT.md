# Development

This repository builds the local Hydra desktop. It does not require the private Hydra Remote
repository or agent.

## Toolchains

- The normal contributor and release toolchain is pinned by `rust-toolchain.toml` to Rust 1.96.0.
- The workspace's declared minimum supported Rust version is 1.88. These are separate contracts:
  ordinary builds use the pinned toolchain, while the minimum version is checked independently.
- Node is pinned by `.nvmrc` to 22.23.1.
- npm is pinned to 10.9.8 for lockfile-stable dashboard installs.
- Python is pinned by `.python-version` to 3.13.15 for the repository's verification and packaging
  scripts. Those scripts deliberately do not rely on the macOS system Python.

With `nvm` installed:

```sh
nvm install
nvm use
npm install --global npm@10.9.8
pyenv install --skip-existing 3.13.15
pyenv local 3.13.15
rustup toolchain install 1.96.0
```

Verify the active versions before diagnosing a lockfile or compiler difference:

```sh
rustc --version
node --version
npm --version
python3 --version
```

`pyenv` is one way to honor `.python-version`; another version manager is fine if both `python`
and `python3` resolve to exactly Python 3.13.15. CI installs that exact version with a commit-pinned
`actions/setup-python` action in every job that executes a Python-backed repository script.

## Platform prerequisites

### macOS

Install current Xcode Command Line Tools:

```sh
xcode-select --install
```

Install Rust with `rustup` and Node with `nvm` (or another version manager that honors the exact
versions above). A source build is unsigned and is not equivalent to the notarized official app.

### Ubuntu 24.04

Install the native compiler, GTK/WebKit and graphics development packages:

```sh
sudo apt-get update
sudo apt-get install -y --no-install-recommends \
  build-essential \
  libgl1-mesa-dev \
  libgtk-3-dev \
  libssl-dev \
  libvulkan-dev \
  libwayland-dev \
  libwebkit2gtk-4.1-dev \
  libxkbcommon-dev \
  pkg-config
```

Install Rust with `rustup` and Node with `nvm`, then select the pinned versions above. Other Linux
distributions may use different package names and are supported through contributed packaging and
compatibility fixes.

## Build and run

### Fast developer harness

Build the bundled dashboard before launching the native application:

```sh
./scripts/build-local.sh
cargo run -p maestro-app -- launch
```

This starts an isolated inner-loop harness. It normally uses the development socket and
`Maestro-dev`/`maestro-dev` state namespace, and it is not the same process topology as an installed
Hydra package.

### Package-shaped local run

Use the platform's unsigned packaging smoke below when testing the installed-product shape. The
macOS archive contains the native Hydra launcher, local app, retained PTY daemon and dashboard. The
Linux archive contains its wrapper and the same local pieces. Neither archive contains Hydra
Remote or the private agent. Extract the resulting archive to a disposable directory, then launch
`Hydra.app` on macOS or `bin/hydra-local` on Linux.

If the optional private extension is absent or incompatible, the local desktop must remain usable
and Remote controls must remain unavailable. A source build must not need a sibling private
repository to compile or run.

## Test

Run the deterministic checks from the repository root:

```sh
./scripts/test-local.sh
```

The script requires a soft open-file limit of at least 1,024 on every host. If the shell starts
lower (including macOS shells that start at 256), it raises only that process's soft limit when the
existing hard limit permits; otherwise it stops before build work and prints the exact remedy. It
also defaults to four concurrent Rust test threads. Set
`HYDRA_TEST_THREADS` from 1 through 16 only when intentionally qualifying another bound.

From a source tree with generated output removed, run the publication-boundary inventory too:

```sh
./scripts/check-public-boundary.sh
```

It fails if private components, nested repositories, generated directories, unreviewed binary
assets, personal paths, environment identifiers, symlinks or publishable Cargo packages enter the
tree. The one-time history-free export check used before the first public commit is stricter:

```sh
HYDRA_REQUIRE_HISTORY_FREE=1 ./scripts/check-public-boundary.sh
```

That mode is recorded in the one-time publication evidence. Normal contributor and CI runs permit
the repository's own root `.git` directory while continuing to reject nested repositories.

Run the minimum-version check separately when changing Rust dependencies:

```sh
rustup toolchain install 1.88.0
cargo +1.88.0 check --workspace
```

Native rendering and window-host changes also require manual qualification:

- macOS on an installed or source-built local app, as appropriate;
- Linux on native Wayland; and
- Linux in a real X11 session.

Record which path was tested. XWayland is not a substitute for either native Wayland or a real X11
session.

The production Linux application uses its Tao/GTK host on native Wayland or X11. The standalone
`maestro-renderer --demo-scene` and `--stress` developer harnesses instead use winit's X11 backend;
on a Wayland desktop they therefore require XWayland, and they cannot run in a pure-Wayland session
with XWayland disabled. This limitation affects only those developer probes, not the application.

## Compatibility namespaces

Hydra is the product name. `maestro-*` crate names, `MAESTRO_*` environment variables,
`maestro.*` schema identifiers and Maestro-named durable paths are retained compatibility
contracts for existing local state and extensions. They do not denote a second product; do not
rename them without a reviewed migration.

## Dependency advisories

CI fails on new Rust soundness advisories. Three exact advisories are reviewed exceptions in the
locked Linux graphics stack. RUSTSEC-2024-0429 affects `glib::VariantStrIter` methods that Hydra
does not call. RUSTSEC-2026-0002 affects `lru::LruCache::iter_mut`, which neither Hydra nor locked
glyphon 0.6 calls. RUSTSEC-2026-0253 affects `lru::LruCache::pop()`; locked glyphon 0.6 calls
`pop_lru()` rather than `pop()`, and its `GlyphonCacheKey` is `Copy`. That reachability conclusion is
Hydra's reading of the locked source, not an upstream guarantee.

The exceptions remain explicit so every other present or future soundness advisory fails CI. Remove
an lru exception when the locked graph uses a version RustSec declares fixed for that advisory, or
when glyphon removes or moves off the affected lru dependency; requalify the renderer graph at that
point. Removing the glib exception requires moving off the affected GTK3/glib stack and qualifying
that migration, not a patch-level dependency update.

## Unsigned local-only packaging smoke

These scripts prove that this repository can assemble a runnable local layout without the private
agent. They are contributor artifacts, not notarized or supported Hydra releases:

```sh
# macOS host
./packaging/macos/package-unsigned.sh

# Linux host
./packaging/linux/package-unsigned.sh
```

Both write under `artifacts/` by default. The macOS source-build bundle uses a distinct bundle
identifier so it cannot impersonate or inherit permissions from the official signed application.
The Linux output is an unprivileged relocatable tarball. Each package contains a generated,
target-specific `THIRD_PARTY_LICENSES.txt`; read
[docs/third-party-licensing.md](docs/third-party-licensing.md) before changing dependency or
packaging inputs.

## Update metadata policy

Community and source builds are network-silent by default: they do not fetch HydraTerms update or
model-catalog metadata automatically. The fixed-origin `maestro-app/official-distribution` Cargo
feature enables the public model-catalog feed for HydraTerms' separately controlled official
package build, but the unsigned desktop update feed remains disabled for every feature set until
the binary can verify an application-pinned signed manifest and downloaded artifact bytes. The
feature exposes no runtime URL override and does not add the private remote agent.

## Design boundaries

- `pty-daemon` owns PTYs, terminal parsing, grids and retained sessions.
- `maestro-renderer` owns native terminal rendering and terminal geometry.
- `maestro-shell` owns local projects, windows, panes and durable records.
- `maestro-app` composes local behavior and typed dashboard intents.
- `dashboard-ui` is presentation chrome; it owns neither PTYs nor generic command execution.
- `maestro-extension-api` is a bounded optional mechanism, not remote authority.

Read [docs/public-private-boundary.md](docs/public-private-boundary.md) before changing a process,
protocol, filesystem or extension boundary.
