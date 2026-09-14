# Local control developer preview

Build an outside tool that connects to Hydra's real local terminal sessions. This starter uses
Hydra's existing Unix-socket protocol and developer CLI. It is **not an installable dashboard
plugin**, a remote API, or a new server to configure.

Supported scope: macOS and Linux, Python 3.10+, daemon control protocol 3. The real disposable-daemon
acceptance was run on macOS; Linux uses the same wire/client but this starter has not yet had a
native Linux run. Windows is not qualified. No Hydra subscription, cloud token, or login is needed
for these local operations.

## What works

- Read the daemon identity/version and list live session IDs with their exact process generation.
- Attach multiple independent clients to a session and receive its restore Grid and live events.
- Send UTF-8 input to that exact session generation. Closing the client preserves the session.
- Use the existing app CLI to launch a retained session and record its window/tab.

The demo creates a terminal task that adds two numbers. Two clients observe `42`; both disconnect;
a third client revisits the same session and observes `43`. It also checks that stale-generation
attachment and input are refused. It runs no model jobs and requires no credentials.
After the stale write, the successful `43` response proves the wrong-generation `BAD_INPUT` did not
reach this JSON-reading fixture child.

Not provided: plugin installation, embedded dashboard UI, session lineage/prompt relationships,
provider token/cost accounting, or accepted/executed input receipts. Those are separate work;
[issue #21](https://github.com/hydraterm/hydra-local/issues/21) remains open.

## Run the real demo

From a matching source checkout, follow [Development](../../DEVELOPMENT.md) for native prerequisites,
then build both binaries from that same checkout:

```sh
cargo build -p maestro-app -p pty-daemon
python3 examples/local-control/demo.py \
  --app target/debug/maestro-app --daemon target/debug/pty-daemon
```

No Python packages are needed. The demo creates a private temporary directory, its own daemon and
socket, fresh app records, and one short-lived Python terminal task. It never discovers or connects
to an existing user daemon. On exit it stops only the daemon process it created and removes that
temporary state. The child also has a 45-second fixture lifetime as a cleanup backstop; that is not
a limit on sessions opened through the developer client.

The output is a JSON proof containing binary hashes, protocol version, observed fixture results,
two-client/disconnect checks, and `gui_opened: false`. A recorded window/tab is not proof that an
existing GUI refreshed or rendered it. Native visual qualification is separate.

To exercise installed binaries instead, use the matching pair inside the **same** installation.
Hydra 0.2.15's public request contract has the operations used here; this example/client was added
later and is obtained from current source, not assumed to be bundled with the installer.

```sh
# Standard macOS bundle location; adjust if you installed elsewhere.
python3 examples/local-control/demo.py \
  --app /Applications/Hydra.app/Contents/Resources/bin/maestro-app \
  --daemon /Applications/Hydra.app/Contents/Resources/bin/pty-daemon

# Standard Linux package location; adjust for your actual installation.
python3 examples/local-control/demo.py \
  --app /opt/hydra/bin/maestro-app --daemon /opt/hydra/bin/pty-daemon
```

The starter verifies the actual daemon protocol and capabilities. A differently versioned retained
daemon is not silently replaced, killed, or used for unguarded input. `DaemonInfo.build_version` is
the daemon crate's version; it is not necessarily the Hydra installer version.

## Connect to a session you choose

Programs deliberately run as the same OS user can access that user's local daemon. See the
[public/private boundary](../public-private-boundary.md). This starter does not weaken that
boundary or grant private Remote authority. It adds no network-off, command sandbox, or read-only
policy to your programs. Only run integrations you intend to trust as your local account.

Supply the exact socket path rather than guessing which running profile you meant. Official
launchers choose `hydra-maestro-<uid>.sock` under the first nonempty `XDG_RUNTIME_DIR`, `TMPDIR`, or
`/tmp`. An explicitly configured/QA socket can be different. The CLI's dev-safe records/socket
defaults are not a promise to select your production profile.

```sh
python3 examples/local-control/hydra_client.py --socket /path/to/hydra.sock info
python3 examples/local-control/hydra_client.py --socket /path/to/hydra.sock list
python3 examples/local-control/hydra_client.py --socket /path/to/hydra.sock watch --session SESSION_ID
```

`watch` explicitly reads terminal content and prints JSON events. Raw output is base64-encoded;
`SessionStream.output_bytes(event)` decodes it without corrupting split UTF-8 bytes. Closing `watch`
or pressing Ctrl-C disconnects that client only. Idle streams have no timeout by default; Python
callers can pass `next_event(timeout=...)`. Connection/query deadlines default to five seconds and
are configurable with `--timeout`; one deadline covers connect, hello, and each query.

Send exact input from stdin, including any Enter/newline you intend. For example, only in a shell
session you selected:

```sh
printf 'printf "hello from my integration\\n"\n' | \
  python3 examples/local-control/hydra_client.py --socket /path/to/hydra.sock \
  send --session SESSION_ID --generation GENERATION_FROM_LIST
```

Do not put secrets in command arguments or public logs. Input is terminal input: a shell command,
interactive provider prompt, or application keystroke depends on what is running in that pane.

## Use it from Python

Put `examples/local-control` on your Python import path, then:

```python
from hydra_client import Hydra

hydra = Hydra("/path/to/hydra.sock")
sessions = hydra.sessions()
selected = next(s for s in sessions if s.id == "SESSION_ID")
with hydra.attach(selected, raw_output=True) as terminal:
    print(terminal.initial)  # Explicit terminal-content access.
    result = terminal.send_text("your input\n")
    print(result)  # status=sent, executed=None; NOT an execution acknowledgement.
    print(terminal.next_event(timeout=10))
# Session remains owned by Hydra's daemon, not by this Python client.
```

Each attachment owns its connection; separate control queries cannot consume its queued events.
The exact daemon identity and process generation are checked before attachment, and every write
carries that generation. A mismatch is an error, not permission to retarget another session.

## Delivery and output semantics

`sent` means the complete JSON request was handed to the local socket. The current `Write` wire
operation has no success acknowledgement, input digest journal, idempotency key, or provider-turn
receipt. A connection failure can leave delivery unknown. Never automatically retry a write or
claim it executed; check application-specific output where appropriate. The demo's observed sums
are evidence for its own synthetic program, not a general execution-receipt API.
The current daemon refuses stale `Write` by closing that connection, not by sending a typed reason
or success ACK. Treat that transport failure as unknown delivery; do not infer execution or retry.

The existing frame cap is 16 MiB including JSON expansion, not a new prompt limit. Oversized input
is rejected without truncation or sending a partial request. The input method accepts UTF-8 text;
it is not an arbitrary binary-input API. `watch` exposes ordered protocol events, not a reconstructed
screen or guaranteed full transcript. `ResyncRequired` means output was lost; adopt the following
Grid baseline. If implementing a terminal, obey grid generation/revision rules and do not replay
output already included in that baseline. This starter does not implement a second terminal parser.

## Tests and extension architecture

```sh
python3 -B -m unittest discover -s examples/local-control -v
```

These focused client tests complement the real `demo.py` run. No full release qualification is
implied. The `maestro-extension-api` crate serves a different role: Hydra invokes the fixed optional
`hydra-agent extension` sibling for Remote lifecycle/viewport operations. Do not replace that binary
or treat its one-request stdio contract as a community plugin loader.
