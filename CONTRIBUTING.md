# Contributing to Hydra

Thank you for helping improve Hydra's local desktop, Remote agent and browser engine.

## Accepted contribution scope

We welcome:

- bug fixes;
- documentation improvements;
- macOS and Linux platform compatibility work;
- accessibility and test improvements;
- packaging improvements for the public local desktop; and
- improvements and independently developed adapters for the published Remote transport/broker interfaces.

Open an issue and obtain agreement before starting an architectural change. This includes durable
record or protocol changes, new cross-process authority, renderer or PTY ownership changes, a new
platform host, and changes to the public/private extension boundary. A pull request is not the place
to establish a new architecture after it has already been implemented.

Independent integrations with the published Remote interfaces are welcome; the libraries do not
require HydraTerms' hosted identity or billing providers. See the
[Remote library quickstart](docs/developer/remote-core-quickstart.md).

Do not submit private hosted implementations, credentials or deployment data. Hosted account/billing,
enrollment, authorization-service and deployment composition remain private. Contributions to the
published Remote agent, browser engine and broker are welcome. Changes to protocol or authority boundaries still require architectural
agreement and security review; a library adapter is not permission to weaken those checks.

## Before opening a pull request

1. Search existing issues and pull requests.
2. For architecture, open and link an issue before writing the change.
3. Follow [DEVELOPMENT.md](DEVELOPMENT.md) from a clean checkout.
4. Add or update focused tests.
5. Run the Rust, dashboard or Remote library checks relevant to the change.
6. Remove generated output, credentials, local paths and personal data from the diff.
7. Sign off every commit with `git commit -s`.
8. Explain platform coverage and any manual testing in the pull request.

Changes to shared protocol, storage, renderer, packaging, workflow or security-boundary files
receive owner review. Native UI changes require physical evidence for each affected platform; Linux
claims must distinguish Wayland from X11.

## Developer Certificate of Origin

Contributions use the [Developer Certificate of Origin](DCO.md), not a contributor licence agreement
or copyright assignment. A sign-off certifies that you have the right to submit the contribution
under the repository's licence.

Create signed-off commits with:

```sh
git commit -s
```

Git adds a `Signed-off-by: Name <email>` trailer. Every commit in a pull request must carry a valid
sign-off matching its author; the required DCO check blocks a merge when one is missing. Read
[DCO.md](DCO.md) before signing off.

## Security and conduct

Report vulnerabilities privately as described in [SECURITY.md](SECURITY.md), never through a public
issue. Participation is governed by [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
