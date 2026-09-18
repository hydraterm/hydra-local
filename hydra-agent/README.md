# Desktop Remote agent source

`hydra-agent` provides enrollment, local service supervision and authenticated WebRTC
bridging to Hydra's retained PTY daemon. It does not contain Clerk or Stripe adapters.
Publishing this source does not supply a turnkey independent control plane.

## Self-managed source build

Copy `self-managed.example.json` to a build-local JSON file and replace the origins
and verifier with your control plane's public values. Origins must be canonical
HTTPS origins without a trailing slash, path, credentials, query or fragment.
The verifier is the canonical standard-base64 encoding of an Ed25519 **public** key
(32 bytes). Never put its signing/private key, enrollment codes or credentials here.
The example deliberately cannot build unchanged.

From the workspace root, with `HYDRA_AGENT_RELEASE_ENVIRONMENT` unset:

```sh
HYDRA_AGENT_SELF_MANAGED_DESCRIPTOR=/absolute/path/to/public-trust.json \
  cargo build --locked --manifest-path hydra-agent/Cargo.toml --features webrtc
```

A relative descriptor path is resolved from `hydra-agent/`, not the invoking shell's
directory. This explicit build input needs no `deploy/environments` files. It embeds
the public trust tuple and exact descriptor digest, labelled `self-managed`; it does
not claim an official release channel or configure desktop updates. Rebuild to change
trust. Runtime cloud/origin/verifier overrides remain forbidden, and enrollment must
match the compiled broker. Passkey, proof-of-possession, token, origin and revocation
checks remain enforced. This input is not read by the running agent.

An independent control plane must implement the compatible enrollment/passkey,
signed authorization, heartbeat, revocation, signaling and relay-credential APIs;
an arbitrary WebSocket broker is insufficient. Existing hosted enrollment and
deployment infrastructure are not replaced by this build option.

The agent and `pty-daemon` are separate binaries. When running a source-built
supervisor, pass `--pty-daemon-bin /absolute/path/to/pty-daemon`; a standalone
agent build does not place the parent workspace's daemon in its own target directory.
Without `CARGO_TARGET_DIR`, the canonical workspace writes to `target/debug`, while
the standalone public agent writes to `hydra-agent/target/debug`. The parent-built
daemon remains in the parent workspace's target directory. An explicit target
directory changes these output locations, not agent trust or daemon discovery.

Official builds keep the existing production/staging descriptor selection when the
self-managed variable is absent. Combining the two selectors is an error; missing
official descriptors never silently fall back to a self-managed or insecure build.

The default Cargo feature set includes the token/control security core. `webrtc`
enables the actual peer transport. The optional `remote-diagnostics` feature is a non-shipping inspector; do not
enable it for an ordinary agent package. Private production-qualification tools are
not included in this source distribution.
