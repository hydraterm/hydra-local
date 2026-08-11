# Security policy

## Report privately

Do not disclose a suspected vulnerability in a public issue, discussion or pull request.

Email [security@hydraterms.com](mailto:security@hydraterms.com). If this repository's GitHub
**Security** tab offers a private **Report a vulnerability** form, that form reaches the same
private reporting process.

Reports about the public local desktop and the closed Hydra Remote service are both accepted through
these private routes. For non-security support, use
[info@hydraterms.com](mailto:info@hydraterms.com).

## What to include

Please include, when available:

- the affected Hydra version or source commit;
- operating system, version and display server where relevant;
- the security impact and who can trigger it;
- minimal reproduction steps or a proof of concept; and
- any mitigations you have already tested.

Do not send live credentials, private keys, recovery codes, terminal contents or other people's
personal data. Revoke an exposed credential first, then provide only the minimum redacted evidence
needed to identify it.

On macOS, launcher diagnostics live under `~/Library/Logs/Hydra`. Hydra restricts that directory to
the current user (`0700`), restricts each launch log to `0600`, and retains at most ten matching
launch files. The logs are not content-redacted, and an active file is not byte-rotated; paths,
provider identifiers and session identifiers can appear in diagnostics. Inspect and redact a log
before sharing it in any report.

## Response target

HydraTerms Limited aims to acknowledge a complete report within three business days. Triage,
remediation and disclosure timing depend on severity and reproducibility. We will coordinate a safe
disclosure date with the reporter where practical.

## Supported versions

The latest published stable release is supported. If a finding also affects an older release, state
which versions you tested; fixes may be issued only for the current release.
