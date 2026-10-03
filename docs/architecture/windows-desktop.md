# Native Windows desktop design

Status: accepted architectural direction; implementation and release qualification are incomplete.
This is the design handoff for [issue #16](https://github.com/hydraterm/hydra-local/issues/16),
not an announcement of a supported Windows download.

## Adopted product and ownership boundaries

Windows is a host for the same Hydra product, not a separate frontend or terminal implementation:

- winit owns the native window; WGPU renders the terminal, initially targeting DX12.
- WRY/WebView2 hosts the bundled React chrome. WebViews neither parse terminal bytes nor own PTYs.
- The app composes shared project, window, pane and task behavior through typed intents.
- An independent per-user `pty-daemon.exe` owns ConPTY sessions, terminal parsing, grids,
  scrollback and child lifecycle. It is not a system service. Closing or crashing the GUI must
  leave retained sessions available to the same authorized user.
- Platform adapters preserve shared geometry, input, selection and lifecycle contracts.
  Existing macOS and Linux paths remain intact; Windows support must not weaken them.

## Local transport and process lifetime

Use local named pipes as the Windows carrier for the shared terminal protocol, not loopback TCP.
The adopted boundary is a protected current-user pipe, remote-client rejection and a first-instance
guard. Both sides authenticate the exact peer process and matching user, elevation and integrity
context before protocol traffic. Session operations remain bound to exact daemon/session generations.
This local authority boundary is not a sandbox for launched programs.

The Windows backend owns ConPTY through the documented Win32 APIs. A private kill-on-close Job owns
each root process and its descendants from process creation. GUI detach is observation-only;
explicit pane termination targets the exact generation's Job. Natural exit retains the final grid.
Daemon failure uses Job ownership as a cleanup backstop, not an instantaneous descendant-exit receipt.

Pipe operations need absolute deadlines and cancellation-safe ownership: buffers and overlapped
state must remain alive until Windows completes cancellation. Potentially blocking ConPTY control
and teardown must not stall unrelated sessions. Caller deadlines are not claims of universally
bounded operating-system teardown. Ambiguous launch/recovery outcomes must not replay a fresh Start
or kill a daemon that another authenticated launcher has already adopted.

The foundation uses a compatibility capability before conditional desktop Start. Older retained
daemons cannot silently acquire newer mutation semantics. A private parent/child publication
handshake remains to be designed for safe cleanup of genuinely stalled, unpublished launchers.

## Product integration and local data

The runnable native-terminal foundation deliberately does not substitute a permissive Windows
record-store fallback for the product database. Full product integration must implement Windows
ACL/ownership, reparse-point, cross-process locking and schema-compatibility rules before project
and session persistence becomes authoritative.

Child launch preserves native Windows environment values and explicit executable selection.
Provider command-script shims require a separately reviewed quoting contract; do not concatenate
untrusted text into `cmd.exe /C`. Default-shell ordering remains a product decision, not an
assumption that every machine has PowerShell 7.

WebView2 must use an explicit per-user data directory, bundled assets and a closed trusted origin.
Navigation, popups and downloads must not bypass typed app intents. Terminal geometry stays in Rust.
Developer staging keeps the app, matching daemon and bundled assets together; the final install
layout, installer technology and WebView2 provisioning remain unresolved delivery decisions.

## Current evidence and limitations

The [progress record on issue #16](https://github.com/hydraterm/hydra-local/issues/16) distinguishes
published platform groundwork from newer implementation-branch qualification:

- Windows Server compatibility checks covered foundation transport and retained-session behavior.
  Those results do not establish Windows 11 product readiness.
- Native Windows 11 checks exercised terminal input, GUI close/reattach, retained output and the
  same surviving child process, plus focused transport/lifecycle checks.
- The inbox ConPTY integration set is **15/16**, not a full pass: combining-character width/fidelity
  remains incorrect. A separate Microsoft ConPTY runtime probe passed **16/16**, but that runtime
  has **not** been adopted or qualified for distribution. Runtime selection/loading/distribution
  is explicitly unresolved.
- The full React/WebView2 project/session host, clean-machine and token-context qualification,
  and installer/signing/update delivery are unfinished. There is no Windows installer or release
  claim. Source-level groundwork does not make the current public tree a complete Windows app.

Initial engineering qualification targets Windows 11 x64. Windows 10, Windows Server and arm64 are
not additional supported-product promises. There is no blanket native PASS or installed parity claim.

## Component implementation tracking

The design issue can close after this accepted design is linked and separate implementation issues
exist for the components below. Their delivery remains open; closing the design issue does not
waive their acceptance criteria.

- [ ] [Retained terminal and runtime (#42)](https://github.com/hydraterm/hydra-local/issues/42): resolve the Unicode/runtime decision; qualify exact-generation
  reconnect, resize, flooding, natural exit, explicit descendant termination, daemon failure and
  cancellation; settle the unpublished-launcher handshake without breaking retained sessions.
- [ ] [Product storage and launch (#43)](https://github.com/hydraterm/hydra-local/issues/43): integrate protected Windows persistence, locks and recovery;
  decide shell/provider launch contracts; reopen recorded projects/sessions without fresh duplicates.
- [ ] [Native window and React chrome (#44)](https://github.com/hydraterm/hydra-local/issues/44): integrate the shared project/session UI through WebView2,
  typed intents and native WGPU surfaces; qualify focus, geometry and GUI-loss retention.
- [ ] [Developer package and delivery (#45)](https://github.com/hydraterm/hydra-local/issues/45): define install layout, supported runtime/WebView2 provisioning,
  signing, installer and updates; validate clean-machine staging before publishing artifacts.
- [ ] [CI and target qualification (#46)](https://github.com/hydraterm/hydra-local/issues/46): integrate Windows compile/test coverage and source/binary-bound
  native receipts; keep compatibility smoke, Windows 11 functional evidence, token-context checks
  and installed-package acceptance distinct.

Protocol, persistence and renderer changes require their shared owners' review. Component work must
join the canonical product history before combined-product qualification; implementation branches
and isolated probes are evidence, not a second Windows product or an authorization to publish.
