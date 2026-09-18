# Third-party licensing for source and binary packages

Hydra Local keeps two deliberately different records:

- `THIRD_PARTY_NOTICES.md` is the readable source-tree inventory. It describes the complete locked
  dependency inventories for contributors and reviewers.
- `THIRD_PARTY_LICENSES.txt` is a target-specific binary-distribution artifact. It is generated
  inside each unsigned packaging stage and is not checked in as generated source.

The binary artifact is produced by `scripts/generate-third-party-licenses.py`. The generator walks
the target-filtered Cargo normal/build graph (never dev-only dependencies) and the exact npm runtime
closure. For each target it verifies a reviewed digest over every Cargo package's name, version,
licence expression, registry source, enabled features and archive SHA-256; a package count is only a
supplementary sanity check. It then verifies every Cargo `.crate` archive against `Cargo.lock`,
includes the applicable licence, copyright, author and NOTICE files verbatim, and deduplicates only
byte-identical bodies. Every package-to-file attribution remains present after deduplication.

The npm runtime boundary is likewise content-addressed rather than count-based. The reviewed policy
pins the five exact runtime identities, dependency edges, tarball URLs and npm SHA-512 integrity
values, plus a digest over that whole closure. Both unsigned packaging paths invoke `build-local.sh`,
which runs `npm ci`; the licence generator then requires npm's installed-package lock receipt to
match the root lock and requires the installed licence-file SHA-256 values to match policy. A package
with the same name or count but a different version, edge, URL, integrity value, declared licence or
licence bytes fails closed.

The five-package dependency closure is not assumed to describe the shipped Vite bundle. A separate
write-free Vite analysis build records every `node_modules` module that reaches an emitted chunk and
requires its package identity to equal the reviewed three-package bundle set (`react`, `react-dom`
and `scheduler`). Importing an already-locked dev dependency into production source therefore fails
the licence gate even though neither the lock digest nor dependency count changed.

`scripts/third-party-license-policy.json` is the reviewed fail-closed boundary. A lockfile hash,
target closure digest, npm runtime closure, rootless crate, nested licence-like file, generated
protocol input, fallback text, or MPL-covered source reference changing without a policy review
stops packaging. The four approved targets are Apple Silicon and Intel macOS, plus arm64 and amd64
GNU/Linux.

The few locked crate archives that contain no root licence file use an exact package-version and
declared-expression fallback. Those decisions are explicit in the policy rather than inferred at
build time. A new version or changed licence expression cannot inherit an old decision.

Both unsigned packagers also remap the actual source, home and Cargo paths before compiling. The
finished archive is scanned byte-for-byte for those builder paths. Archive paths, ownership
metadata, extended attributes and links are also checked, and a packaged executable named
`hydra-agent` is rejected. Exact private trust-marker
checks live on the private composition side so the public verifier does not publish the private
needles it is meant to detect. A boundary match fails packaging rather than publishing a diagnostic
string from the builder's machine.

## Separate Remote source graphs

The browser terminal/controller engine and signaling-broker libraries are separately built source packages, not
new dependencies of the desktop binary. Their `web-client/package-lock.json` and
`hydra-cloud/package-lock.json` contain pinned build/test tools, with no runtime package
dependencies. `scripts/generate-third-party-notices.py` lists each tool graph separately and
binds all five source lock hashes. This inventory includes optional platform records; it is not
proof that every platform archive or all bundled-tool attribution was reviewed.

The Remote agent is a separate excluded Cargo workspace with its own
hydra-agent/Cargo.lock; it does not become a ninth desktop package. The source-notices
generator adds a distinct locked agent table using --manifest-path hydra-agent/Cargo.toml
and --features webrtc, excluding first-party public path crates. That source graph includes
build/test and optional-platform records. It is not a licence artifact for an agent binary
and does not alter the existing four desktop target policies or their dependency closures.
Anyone distributing an agent binary must review the exact artifact's dependencies and carry
their required licence, copyright and source materials. The local desktop packagers continue
to reject a bundled hydra-agent; source publication is not new binary packaging authority.

The library build scripts copy the public root MIT licence into each local tarball. The package
gate must prove the actual exports, declarations, MIT payload and emitted runtime module closure.
Current reviewed artifacts contain only Hydra code/types and no bundled third-party runtime
modules; this does not waive a future dependency's licence or notice obligations. Do not copy
development `node_modules` into those artifacts or mistake their licence labels for a full legal review.

After a Remote tool or agent lock changes, regenerate the source notices and review every changed
version, licence, upstream and applicable material, then rerun the library build/package/consumer
gates; qualify agent changes through its explicit standalone build/tests. Preserve compatible
pinned versions rather than upgrading opportunistically. Changes to
these separate development locks do not change the desktop four-target policy below; a real
desktop graph change still requires that independent policy review.

## Updating the reviewed desktop binary policy

After `Cargo.lock` or `dashboard-ui/package-lock.json` changes:

1. Regenerate `THIRD_PARTY_NOTICES.md` and review every changed package, licence expression and
   upstream source.
2. Inspect any new root and nested licence, copyright, author, attribution or NOTICE material. On
   Linux, compare every XML path passed to the Wayland code-generation macros; all exact inputs and
   their embedded notices belong in the binary artifact.
3. Update the exact lock and closure digests, package counts and only the policy decisions justified
   by that review.
4. Run `python3 scripts/verify-third-party-licenses.py` after `npm ci`. Its named checks generate all
   four target artifacts twice, assert byte stability and exact closures, run the Vite emitted-module
   proof, exercise every reviewed exception, and prove the Linux-only provenance is absent from
   macOS.
5. Build the appropriate unsigned package and confirm the archive boundary scan passes.

The generator being green is evidence that the recorded mechanical policy was followed. It is not
a substitute for legal review when a dependency's classification is uncertain.

## Eliminated ambiguity: generated Plasma protocol bindings

An earlier Linux graph enabled winit's Wayland backend even though Hydra Local's Linux owner loop is
Tao/GTK. That unused backend pulled in `wayland-protocols-plasma`, whose package metadata says MIT
while its vendored XML collection contains mixed terms, including `LGPL-2.1-or-later`. Whether the
generated Rust bindings inherited obligations from those XML inputs was not resolved.

Hydra Local removes the ambiguity instead of claiming a legal resolution. The residual winit
dependency is target-specific and X11-only on Linux. The locked normal/build closures for both
`x86_64-unknown-linux-gnu` and `aarch64-unknown-linux-gnu` exclude
`wayland-client`, `wayland-protocols`, `wayland-protocols-plasma`, `wayland-protocols-wlr`, and
`smithay-client-toolkit`. The target graphs consume no generated Wayland XML inputs. System
GTK/Wayland libraries remain represented through their ordinary FFI crates, while Linux licence
artifacts contain no Plasma protocol source or Plasma licence material.

Reintroducing winit's Wayland backend or any Plasma protocol dependency requires a fresh dependency,
licensing, packaging, and target-graph review. This removal closes the distribution gate by removing
the disputed dependency, not by determining how the removed generated bindings should be licensed.
The `serial 0.4.0` copyright notice remains preserved from that crate's README and is paired with the
exact reviewed MIT fallback text because its archive has no root licence file.
