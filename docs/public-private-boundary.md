# Public source and hosted Remote boundary

Hydra has an open local desktop and reusable Remote transport/signaling libraries. The desktop
remote agent and hosted service composition remain private. This is a product and source boundary,
not a claim that obscurity protects the remote service.

## What is public

This repository contains the local desktop components and two separately built Remote libraries:

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
| `web-client` | Reusable browser WebRTC transport, lifecycle and signaling interfaces |
| `hydra-cloud` | Reusable content-blind signaling broker and storage interfaces |

The desktop modules contain local safety checks and resource bounds; they do not grant remote
authority. The public transport validates pinned desktop answer proof and connection ownership.
The public broker checks device/account membership, revocation and session expiry against supplied
records. Those checks do not replace the deployment's identity/enrollment services or the desktop
agent's final authorization of terminal operations.

The libraries have no Clerk or Stripe dependency and support independently developed adapters. They
are not a complete self-hosted Remote application or desktop agent, and installing them does not
enable source-desktop Remote controls or grant hosted-service access. See the
[Remote library quickstart](developer/remote-core-quickstart.md).

## What remains private

The private product contains:

- the desktop remote agent and complete browser application;
- hosted account identity, enrollment, token issuance and revocation-service composition;
- Clerk and Stripe integrations, entitlement and billing workflows;
- hosted HTTP/API composition, deployment configuration and relay operation; and
- the reviewed environment descriptors and token-verification trust roots.

The private agent is the final authority before a remote operation can reach any public local
mechanism. It chooses its trusted cloud, verification key and allowed origins from its private build;
the public app does not supply or override them.

## Trust model

Hydra trusts the operating-system account owner and programs that the owner deliberately runs as the
same OS user. A process already running as that user can normally read the user's SSH keys, browser
state, terminal data and saved credentials. Hydra does not claim to stay secure after that user
account, the operating system, or an administrator/root account is compromised.

Hydra treats network and remote-client input as hostile. A browser, relay, signaling message, token,
protocol frame, project path, provider-history record or peer remains untrusted until the private
agent validates the checks that apply to it. Inputs remain bounded by size, time and resource limits
even after authentication.

This same-user boundary is deliberate. Protecting Hydra from a malicious process that already owns
the same user account would require a separately privileged identity, authenticated privileged IPC
and OS-mediated user-presence controls. It would not protect the user's other secrets already
available to that process. Running a modified public build is therefore not itself treated as local
account compromise, but it must never weaken the private remote checks.

The PTY daemon enforces a private socket and kernel peer credentials to exclude other operating-
system users. It is not a security boundary between processes running under the same effective
user ID: a same-UID process that can reach the socket can enumerate, attach to, send input to and
request operations on that user's terminal sessions. That authority is deliberately inside the
trusted local-account boundary above. The private agent must authenticate and authorize remote
input before forwarding any operation to the local daemon.

## The optional extension seam

The public app may invoke the literal sibling command `hydra-agent extension`. It sends one bounded,
version-negotiated lifecycle request over standard input and expects one typed response. Enrollment
codes are request data, not command arguments or environment variables. The public side supplies no
cloud URL, browser origin, verification key, account or device identity, state directory or service
definition.

If the private extension is absent, incompatible, times out, crashes or refuses a request, the local
desktop continues to work and Remote remains unavailable. A public UI flag or file is presentation
state, never proof of remote authority.

## What source visibility proves

The public repository lets anyone inspect how Hydra owns PTYs, renders terminal output, stores local
records and performs local discovery, plus the published transport proof/lifecycle and signaling
broker checks. Source visibility does not qualify an end-to-end deployment, identity/enrollment
service, desktop agent, real ICE/TURN path, relay operation or hosted billing. Claims about those
private or deployed components still need their own evidence.

The boundary is tested in the private composition: a rebuilt public app cannot select another cloud,
verification key or browser origin, mint a valid token, bypass entitlement or make an unauthenticated
remote peer authoritative.
