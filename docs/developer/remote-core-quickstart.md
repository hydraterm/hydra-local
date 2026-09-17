# Build and extend the Remote libraries

This guide targets the public Remote-library source layout, with the two library manifests below.
The private hosted composition uses different package metadata and is not covered by these commands.

| Directory | Package | Purpose |
| --- | --- | --- |
| `web-client` | `@hydraterm/remote-browser-core` | Browser WebRTC transport, connection lifecycle and signaling interfaces |
| `hydra-cloud` | `@hydraterm/signaling-broker-core` | Content-blind offer/answer/ICE broker and storage interfaces |

These are ESM libraries with TypeScript declarations, not a complete Remote server, browser app or
desktop agent. The source preview uses local tarballs; it is not an npm-registry release. No Clerk
or Stripe SDK is needed to build or use the libraries. A deployment must supply its own identity,
enrollment, authorization, storage and network composition. Installing these libraries does not
enable Remote controls in a source-built desktop or grant access to HydraTerms' hosted service.

## Build from a library checkout

Use Node 22.23.1 and npm 10.9.8. From the public library checkout's root on macOS/Linux:

```sh
npm --prefix web-client ci --ignore-scripts
npm --prefix web-client run typecheck
npm --prefix web-client test
npm --prefix web-client run build
npm --prefix hydra-cloud ci --ignore-scripts
npm --prefix hydra-cloud run typecheck
npm --prefix hydra-cloud test
npm --prefix hydra-cloud run build
ARTIFACTS="$(mktemp -d)"
(cd web-client && npm pack --ignore-scripts --pack-destination "$ARTIFACTS")
(cd hydra-cloud && npm pack --ignore-scripts --pack-destination "$ARTIFACTS")
```

Install the two resulting `.tgz` files in your application's directory with `npm install` and their
absolute local paths. Each build copies the root [MIT License](../../LICENSE) into its package
before packing. Development tools retain their own licenses; the library runtime bundles contain
Hydra code, not the installed development-tool dependency graph.

Keep generated package `LICENSE` copies, build output, tarballs and `node_modules` out of source PRs.
Run the source boundary check on a clean source tree, before dependency/build output is added.

## Check the actual packages in a fresh consumer

Before building in the source directories, the opt-in checker can copy the clean public library
snapshot into a new private output directory, build and pack both libraries, then install the
actual tarballs into an independent consumer. The package directories must contain only the
reviewed source files: no `node_modules`, build output, generated `LICENSE` copies or `.npmrc`.
This command refuses the private hosted manifests; it is not a way to export the private checkout.

Use the same Node/npm versions above and an existing npm cache that already contains the pinned
development tools. The checker never downloads missing dependencies: an offline cache miss is a
prerequisite to resolve separately, not permission to upgrade or change the lockfiles. Supply the
physical absolute path (with all symlinks resolved) to npm's `npm-cli.js` and to that cache.
For example, with those paths assigned to `NPM_CLI` and `NPM_CACHE`, from the clean public library checkout:

```sh
CHECK_ROOT="$(cd "$(mktemp -d)" && pwd -P)"
node scripts/check-remote-core-packages.mjs \
  --source "$(pwd -P)" --output "$CHECK_ROOT/qualification" \
  --npm-cli "$NPM_CLI" --cache "$NPM_CACHE"
```

The output must be a new directory outside every Git checkout. Logs and a digest-bound
`RESULT.json` remain there even when a package command fails; the checker does not modify the
input tree. It uses an empty HOME/npm configuration, preserves the exact tool lock, checks all
17 installed declaration roots under strict NodeNext, typechecks both examples below and verifies
the browser bundle consumes the installed artifact. The four consumer tests use synthetic peers
and memory storage, not an enrolled desktop or a deployed Remote service. The checks do not publish
to npm or GitHub and do not qualify real ICE/TURN, HTTP authentication or production persistence.

## Browser integration

```ts
import { WebrtcBridge, type WebrtcBridgeOptions } from '@hydraterm/remote-browser-core'
import type { SignalingPort } from '@hydraterm/remote-browser-core/signaling'

export function createTransport(
  signaling: SignalingPort,
  options: Omit<WebrtcBridgeOptions, 'signaling'>,
) {
  return new WebrtcBridge({ ...options, signaling })
}
```

Implement `SignalingPort` against your authenticated signaling service. This creates a transport,
not an authenticated terminal session: a connected DataChannel is not proof of authorization.
A Hydra-compatible production integration must request session-bound authorization with
`requireSessionBoundToken: true` and `mintToken`, supply the enrolled desktop key and browser
proof/certificate callbacks, and leave `allowUnverifiedDesktop` off. It must also implement the
peer protocol's hello/auth exchange before terminal operations. The generic library does not
perform that application handshake for you.

The bridge exposes `currentToken()` and `currentAuthorization()` for the calling composition.
Use the `refusal` and `signaling` entry points' error classes rather than recreating them:
connection retirement and compatibility fallback distinguish their identities. Never use a
synthetic test certificate or verification bypass as a production enrollment mechanism.

## Broker integration

```ts
import { SignalingBroker } from '@hydraterm/signaling-broker-core'
import type { SignalingBrokerStore } from '@hydraterm/signaling-broker-core/ports'

export function createBroker(store: SignalingBrokerStore) {
  return new SignalingBroker(store)
}
```

Implement the typed store's 11 methods. Preserve its consistent-read and atomic ICE-append contract,
including duplicate handling, shared quota and sequence allocation. The broker checks the supplied
device/account records and expires sessions on read; it does not authenticate an HTTP request for
you. Derive caller account/device identity from your authenticated server context, never directly
from untrusted request fields. The package's `ports` and `types` exports are type-only imports.

Terminal content belongs on the encrypted peer DataChannel, not in broker records or audit metadata.
The included tests use synthetic peers, generated keys and memory storage. They exercise real core
checks but do not qualify an enrolled agent, production passkey service, real ICE/TURN or deployment.
See the [public/private boundary](../public-private-boundary.md) for the source and authority scope.
