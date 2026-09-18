# Public source and hosted Remote boundary

Hydra has an open local desktop, Remote agent, browser terminal/controller engine and signaling
broker. Hosted account/billing and deployment composition remain private. This is a product and source boundary,
not a claim that obscurity protects the remote service.

## What is public

This repository contains the local desktop, the separately built Remote agent and two Remote
packages. The browser package includes its controller, terminal renderer and session/layout core:

| Component | Responsibility |
|---|---|
| `pty-daemon` | PTY ownership, terminal parsing, grids, scrollback and retained sessions |
| `maestro-protocol` | Local protocol types and framing |
| `maestro-shell` | Local projects, windows, panes, layouts and durable records |
| `maestro-local-services` | Local provider history, project discovery and launch defaults |
| `maestro-extension-api` | Bounded typed requests to an optional sibling extension |
| `maestro-renderer` | Native terminal rendering, input encoding and window hosts |
| `maestro-app` | Local application composition and typed dashboard intents |
| `dashboard-ui` | React presentation chrome for the native desktop |
| `hydra-launcher` | Local packaged-application launcher |
| `hydra-agent` | Authenticated Remote peer, local supervision and retained-PTY bridge |
| `web-client` | Browser terminal/controller engine, WebRTC transport and signaling interfaces |
| `hydra-cloud` | Reusable content-blind signaling broker and storage interfaces |

The desktop modules contain local safety checks and resource bounds; they do not grant remote
authority. The public transport validates pinned desktop answer proof and connection ownership.
The public broker checks device/account membership, revocation and session expiry against supplied
records. Those checks do not replace the deployment's identity/enrollment services or the desktop
agent's final authorization of terminal operations.

The published components have no Clerk or Stripe dependency and support independent adapters.
They do not supply a turnkey account/enrollment service, install the optional desktop extension,
or grant hosted-service access. See the [engine quickstart](developer/remote-core-quickstart.md)
and [agent build guide](../hydra-agent/README.md).

## What remains private

- The hosted account website and its surrounding browser UI.
- Hosted enrollment, account identity, token issuance and revocation-service composition.
- Clerk/Stripe integrations, entitlement and billing operations.
- Hosted HTTP/API composition, deployment descriptors, credentials and relay infrastructure.

The agent is the final authority before remote operations reach local sessions. Its build pins
the trusted API, public verification key and browser origin. Independent builders provide an
explicit public-only trust descriptor; official builds retain their own reviewed deployment inputs.
The local desktop cannot change these values at runtime.

## Trust model

Hydra trusts the operating-system account owner and programs that the owner deliberately runs as the
same OS user. A process already running as that user can normally read the user's SSH keys, browser
state, terminal data and saved credentials. Hydra does not claim to stay secure after that user
account, the operating system, or an administrator/root account is compromised.

Hydra treats network and remote-client input as hostile. A browser, relay, signaling message, token,
protocol frame, project path, provider-history record or peer remains untrusted until the agent
validates the checks that apply to it. Inputs remain bounded by size, time and resource limits
even after authentication.

This same-user boundary is deliberate. Protecting Hydra from a malicious process that already owns
the same user account would require a separately privileged identity, authenticated privileged IPC
and OS-mediated user-presence controls. It would not protect the user's other secrets already
available to that process. Running a modified public build is therefore not itself treated as local
account compromise, but it must never weaken the remote authorization checks.

The PTY daemon enforces a private socket and kernel peer credentials to exclude other operating-
system users. It is not a security boundary between processes running under the same effective
user ID: a same-UID process that can reach the socket can enumerate, attach to, send input to and
request operations on that user's terminal sessions. That authority is deliberately inside the
trusted local-account boundary above. The agent must authenticate and authorize remote
input before forwarding any operation to the local daemon.

## The optional extension seam

The public app may invoke the literal sibling command `hydra-agent extension`. It sends one bounded,
version-negotiated lifecycle request over standard input and expects one typed response. Enrollment
codes are request data, not command arguments or environment variables. The public side supplies no
cloud URL, browser origin, verification key, account or device identity, state directory or service
definition.

If the optional extension is absent, incompatible, times out, crashes or refuses a request, the local
desktop continues to work and Remote remains unavailable. A public UI flag or file is presentation
state, never proof of remote authority.

## What source visibility proves

The public source exposes PTY/session ownership and Remote browser rendering/controller, transport
proofs, signaling, agent authorization, supervision and retained-session bridging. Source tests do
not qualify a deployed service, real ICE/TURN paths or relay operations.

A modified local UI cannot mint a valid token or bypass the enrolled identity, passkey and proof
checks of its paired agent. Independent deployments choose their own trust at build time and own
their service configuration. Source visibility is not a substitute for remote authorization.
