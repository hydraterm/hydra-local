#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"

fail() {
  printf 'public-boundary: ERROR: %s\n' "$*" >&2
  exit 1
}

if [[ "${HYDRA_REQUIRE_HISTORY_FREE:-0}" == 1 && -e "$ROOT/.git" ]]; then
  fail "history-free publication staging must not contain .git"
fi
if find . -mindepth 2 -name .git -print -quit | grep -q .; then
  fail "nested Git repository is present"
fi

for forbidden in .gitmodules target node_modules dist coverage artifacts .cache __pycache__ \
  .DS_Store tsconfig.tsbuildinfo; do
  if find . -path './.git' -prune -o -mindepth 1 -name "$forbidden" -print -quit | grep -q .; then
    fail "generated or repository-private path is present: $forbidden"
  fi
done

readonly REVIEWED_DEMO='docs/assets/hydra-local-demo.gif'
readonly REVIEWED_DEMO_SHA256='ff400ac46275e299120a720279f1a1cc849a0aa65b895290bb84f39595ee1f2d'
[[ -f "$REVIEWED_DEMO" && ! -L "$REVIEWED_DEMO" ]] || \
  fail "reviewed synthetic demo is missing or is not a regular file"
[[ "$(shasum -a 256 "$REVIEWED_DEMO" | awk '{print $1}')" == "$REVIEWED_DEMO_SHA256" ]] || \
  fail "reviewed synthetic demo digest changed"

readonly REVIEWED_SIDEBAR='docs/assets/hydra-sidebar-82e88d7ec829.gif'
readonly REVIEWED_SIDEBAR_SHA256='82e88d7ec829f999488a4a447d2fef17fe6a4f3027d7af6f5be337490918a12f'
[[ -f "$REVIEWED_SIDEBAR" && ! -L "$REVIEWED_SIDEBAR" ]] || \
  fail "reviewed sidebar demo is missing or is not a regular file"
[[ "$(shasum -a 256 "$REVIEWED_SIDEBAR" | awk '{print $1}')" == "$REVIEWED_SIDEBAR_SHA256" ]] || \
  fail "reviewed sidebar demo digest changed"

if find . -path './.git' -prune -o -type f ! -path "./$REVIEWED_DEMO" ! -path "./$REVIEWED_SIDEBAR" \( \
  -iname '*.png' -o -iname '*.svg' -o -iname '*.gif' -o -iname '*.webp' \
  -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.mov' -o -iname '*.mp4' \
  -o -iname '*.pdf' -o -iname '*.zip' -o -iname '*.tar' -o -iname '*.gz' \
  -o -iname '*.dmg' -o -iname '*.deb' -o -iname '*.pkg' -o -iname '*.woff' \
  -o -iname '*.woff2' -o -iname '*.ttf' -o -iname '*.otf' -o -iname '*.mp3' \
  -o -iname '*.wav' -o -iname '*.m4a' \) -print -quit | grep -q .; then
  fail "unreviewed binary, image, recording, archive, installer, or font asset is present"
fi

python3 - "$ROOT" "$REVIEWED_DEMO" "$REVIEWED_DEMO_SHA256" "$REVIEWED_SIDEBAR" "$REVIEWED_SIDEBAR_SHA256" <<'PY'
import json
import hashlib
import ipaddress
import os
import pathlib
import re
import subprocess
import sys

root = pathlib.Path(sys.argv[1]).resolve()
reviewed_demo = sys.argv[2]
reviewed_demo_sha256 = sys.argv[3]
reviewed_binary_files = {
    reviewed_demo: reviewed_demo_sha256,
    sys.argv[4]: sys.argv[5],
}
allowed_root_entries = {
    ".editorconfig", ".git", ".github", ".gitignore", ".nvmrc", ".python-version",
    "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "Cargo.lock", "Cargo.toml",
    "DCO.md", "DEVELOPMENT.md", "FAQ.md", "LICENSE", "README.md", "SECURITY.md",
    "THIRD_PARTY_NOTICES.md", "TRADEMARKS.md", "TROUBLESHOOTING.md", "dashboard-ui", "docs",
    "hydra-agent", "hydra-cloud", "web-client",
    "hydra-launcher", "maestro-app",
    "maestro-extension-api", "maestro-local-services", "maestro-protocol",
    "maestro-renderer", "maestro-shell", "packaging", "pty-daemon", "rust-toolchain.toml",
    "scripts", "examples",
}
unexpected_root = sorted(path.name for path in root.iterdir() if path.name not in allowed_root_entries)
if unexpected_root:
    raise SystemExit(f"public-boundary: ERROR: unexpected top-level entries: {unexpected_root}")

allowed_docs = {
    "architecture.md",
    "assets/hydra-local-demo.gif",
    "assets/hydra-sidebar-82e88d7ec829.gif",
    "public-private-boundary.md",
    "third-party-licensing.md",
    "developer/local-control-quickstart.md",
    "developer/remote-core-quickstart.md",
}
unexpected_docs = sorted(
    str(path.relative_to(root / "docs"))
    for path in (root / "docs").rglob("*")
    if path.is_file() and str(path.relative_to(root / "docs")) not in allowed_docs
)
if unexpected_docs:
    raise SystemExit(f"public-boundary: ERROR: unexpected documentation files: {unexpected_docs}")

allowed_examples = {
    "local-control/demo.py",
    "local-control/hydra_client.py",
    "local-control/test_hydra_client.py",
}
unexpected_examples = sorted(
    str(path.relative_to(root / "examples"))
    for path in (root / "examples").rglob("*")
    if path.is_file() and str(path.relative_to(root / "examples")) not in allowed_examples
)
if unexpected_examples:
    raise SystemExit(f"public-boundary: ERROR: unexpected example files: {unexpected_examples}")

source_paths = [path for path in root.rglob("*") if ".git" not in path.relative_to(root).parts]
for path in sorted(source_paths):
    if not path.is_symlink():
        continue
    raise SystemExit(
        "public-boundary: ERROR: symlinks require an explicit path-and-digest review: "
        f"{path.relative_to(root)} -> {os.readlink(path)}"
    )

forbidden = re.compile(
    "|".join(
        [
            r"(?<![A-Za-z0-9._-])/" + r"Users/(?!test(?:/|[\"']|$)|private(?:/|[\"']|$)|example(?:/|[\"']|$)|me(?:/|[\"']|$)|user(?:/|[\"']|$))[^/< ]+",
            r"[A-Z]:\\" + r"Users\\",
            r"(?<![A-Za-z0-9._-])/" + r"home/(?!test(?:er)?(?:/|[\"']|$)|user(?:/|[\"']|$)|example(?:/|[\"']|$)|private(?:/|[\"']|$)|me(?:/|[\"']|$)|u(?:/|[\"']|$))[^/< ]+",
            r"@(?:gmail|hotmail|outlook|yahoo|icloud|protonmail)\.com",
            r"arn:aws:[^:\s]+:[^:\s]*:[0-9]{12}",
            r"realm[ =:]+'?[A-Za-z0-9._-]+-dev(?:[\"'\s]|$)",
        ]
    ),
    re.IGNORECASE,
)
ipv4 = re.compile(r"(?<![0-9])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![0-9])")
for path in sorted(candidate for candidate in source_paths if candidate.is_file()):
    payload = path.read_bytes()
    relative = path.relative_to(root).as_posix()
    expected_digest = reviewed_binary_files.get(relative)
    if expected_digest is not None:
        if hashlib.sha256(payload).hexdigest() != expected_digest:
            raise SystemExit(
                f"public-boundary: ERROR: reviewed binary digest changed: {relative}"
            )
        continue
    if b"\0" in payload:
        raise SystemExit(f"public-boundary: ERROR: unreviewed NUL-containing file: {path.relative_to(root)}")
    try:
        text = payload.decode("utf-8")
    except UnicodeDecodeError:
        raise SystemExit(f"public-boundary: ERROR: unreviewed non-UTF-8 file: {path.relative_to(root)}")
    match = forbidden.search(text)
    if match:
        line = text.count("\n", 0, match.start()) + 1
        raise SystemExit(
            "public-boundary: ERROR: personal path, account identifier, internal host, or "
            f"internal document reference at {path.relative_to(root)}:{line}"
        )
    for address_match in ipv4.finditer(text):
        try:
            address = ipaddress.ip_address(address_match.group())
        except ValueError:
            continue
        if address.is_global:
            line = text.count("\n", 0, address_match.start()) + 1
            raise SystemExit(
                "public-boundary: ERROR: globally routable IP address requires private review at "
                f"{path.relative_to(root)}:{line}"
            )

# Only the reviewed reusable library leaves belong here; hosted composition stays private.
# Source eligibility and exact runtime/test bytes are bound by the separate sync manifest.
remote_core_files = {
    "hydra-agent/Cargo.lock",
    "hydra-agent/Cargo.toml",
    "hydra-agent/README.md",
    "hydra-agent/build.rs",
    "hydra-agent/build_support.rs",
    "hydra-agent/self-managed.example.json",
    "hydra-agent/src/agent_dir.rs",
    "hydra-agent/src/authority_migration.rs",
    "hydra-agent/src/browser_cert.rs",
    "hydra-agent/src/browser_pop.rs",
    "hydra-agent/src/conn_trace.rs",
    "hydra-agent/src/consistency.rs",
    "hydra-agent/src/device_identity.rs",
    "hydra-agent/src/device_request_auth.rs",
    "hydra-agent/src/enrollment_migration.rs",
    "hydra-agent/src/extension.rs",
    "hydra-agent/src/headless.rs",
    "hydra-agent/src/health.rs",
    "hydra-agent/src/heartbeat.rs",
    "hydra-agent/src/heartbeat_status.rs",
    "hydra-agent/src/input_rate.rs",
    "hydra-agent/src/launchd.rs",
    "hydra-agent/src/lib.rs",
    "hydra-agent/src/lifecycle_cleanup.rs",
    "hydra-agent/src/main.rs",
    "hydra-agent/src/release_trust.rs",
    "hydra-agent/src/remote_access.rs",
    "hydra-agent/src/remote_bridge.rs",
    "hydra-agent/src/remote_control.rs",
    "hydra-agent/src/remote_daemon_backend.rs",
    "hydra-agent/src/remote_frame.rs",
    "hydra-agent/src/remote_peer.rs",
    "hydra-agent/src/remote_policy.rs",
    "hydra-agent/src/remote_signaling.rs",
    "hydra-agent/src/remote_token.rs",
    "hydra-agent/src/remote_webrtc.rs",
    "hydra-agent/src/resume_launch.rs",
    "hydra-agent/src/revocation.rs",
    "hydra-agent/src/seen_set.rs",
    "hydra-agent/src/service.rs",
    "hydra-agent/src/service_readiness.rs",
    "hydra-agent/src/session_creator.rs",
    "hydra-agent/src/setup_deadline.rs",
    "hydra-agent/src/supervise.rs",
    "hydra-agent/src/systemd.rs",
    "hydra-agent/src/viewport_control.rs",
    "hydra-agent/src/winsize_owner.rs",
    "hydra-agent/tests/agent_signaling.rs",
    "hydra-agent/tests/s4_live_pty_smoke.rs",
    "hydra-agent/tests/webrtc_peer.rs",
    "hydra-cloud/package-lock.json",
    "hydra-cloud/package.json",
    "hydra-cloud/src/domain/clock.ts",
    "hydra-cloud/src/domain/content-blind.ts",
    "hydra-cloud/src/domain/offer-wake.ts",
    "hydra-cloud/src/domain/signaling-ports.ts",
    "hydra-cloud/src/domain/signaling.ts",
    "hydra-cloud/src/domain/types.ts",
    "hydra-cloud/test/signaling-port.test.ts",
    "hydra-cloud/tsconfig.core-build.json",
    "hydra-cloud/tsconfig.json",
    "web-client/package-lock.json",
    "web-client/package.json",
    "web-client/src/bridge/account-reset.test.ts",
    "web-client/src/bridge/account-reset.ts",
    "web-client/src/bridge/auth-contract.test.ts",
    "web-client/src/bridge/auth-contract.ts",
    "web-client/src/bridge/bounded-chunk-reassembler.ts",
    "web-client/src/bridge/browser-engine-boundary.test.ts",
    "web-client/src/bridge/channel-router.test.ts",
    "web-client/src/bridge/channel-router.ts",
    "web-client/src/bridge/channel-terminal-bank.test.ts",
    "web-client/src/bridge/channel-terminal-bank.ts",
    "web-client/src/bridge/conn-trace.test.ts",
    "web-client/src/bridge/conn-trace.ts",
    "web-client/src/bridge/connect-deadline.test.ts",
    "web-client/src/bridge/connect-deadline.ts",
    "web-client/src/bridge/datachannel-send-queue.test.ts",
    "web-client/src/bridge/datachannel-send-queue.ts",
    "web-client/src/bridge/device-identity.ts",
    "web-client/src/bridge/device-label-store.test.ts",
    "web-client/src/bridge/device-label-store.ts",
    "web-client/src/bridge/diagnostic-flags.test.ts",
    "web-client/src/bridge/diagnostic-flags.ts",
    "web-client/src/bridge/ice-candidate-security.test.ts",
    "web-client/src/bridge/ice-candidate-security.ts",
    "web-client/src/bridge/ice-path-classifier.test.ts",
    "web-client/src/bridge/ice-path-classifier.ts",
    "web-client/src/bridge/inspector-hooks.ts",
    "web-client/src/bridge/last-opened-store.test.ts",
    "web-client/src/bridge/last-opened-store.ts",
    "web-client/src/bridge/layout-preset-store.test.ts",
    "web-client/src/bridge/layout-preset-store.ts",
    "web-client/src/bridge/multi-attach-manager.test.ts",
    "web-client/src/bridge/multi-attach-manager.ts",
    "web-client/src/bridge/multi-pane-terminal.test.ts",
    "web-client/src/bridge/multi-pane-terminal.ts",
    "web-client/src/bridge/pane-search-bank.test.ts",
    "web-client/src/bridge/pane-search-bank.ts",
    "web-client/src/bridge/pane-selection-bank.test.ts",
    "web-client/src/bridge/pane-selection-bank.ts",
    "web-client/src/bridge/passkey.test.ts",
    "web-client/src/bridge/passkey.ts",
    "web-client/src/bridge/reconnect-hints.ts",
    "web-client/src/bridge/relay-credential-cache.test.ts",
    "web-client/src/bridge/relay-credential-cache.ts",
    "web-client/src/bridge/relay-fallback.test.ts",
    "web-client/src/bridge/relay-fallback.ts",
    "web-client/src/bridge/remote-client.ts",
    "web-client/src/bridge/remote-entitlement.test.ts",
    "web-client/src/bridge/remote-entitlement.ts",
    "web-client/src/bridge/remote-layout-cloud.test.ts",
    "web-client/src/bridge/remote-layout-cloud.ts",
    "web-client/src/bridge/remote-layout-contract.test.ts",
    "web-client/src/bridge/remote-layout-contract.ts",
    "web-client/src/bridge/remote-layout-schema.ts",
    "web-client/src/bridge/remote-session.test.ts",
    "web-client/src/bridge/remote-session.ts",
    "web-client/src/bridge/remote-transport.ts",
    "web-client/src/bridge/render-metrics.test.ts",
    "web-client/src/bridge/render-metrics.ts",
    "web-client/src/bridge/safe-message.test.ts",
    "web-client/src/bridge/safe-message.ts",
    "web-client/src/bridge/scoped-storage-key.test.ts",
    "web-client/src/bridge/scoped-storage-key.ts",
    "web-client/src/bridge/sdp-security.test.ts",
    "web-client/src/bridge/sdp-security.ts",
    "web-client/src/bridge/session-cache-store.test.ts",
    "web-client/src/bridge/session-cache-store.ts",
    "web-client/src/bridge/session-favorites-store.test.ts",
    "web-client/src/bridge/session-favorites-store.ts",
    "web-client/src/bridge/session-label-store.test.ts",
    "web-client/src/bridge/session-label-store.ts",
    "web-client/src/bridge/session-order-store.test.ts",
    "web-client/src/bridge/session-order-store.ts",
    "web-client/src/bridge/session-visibility-store.test.ts",
    "web-client/src/bridge/session-visibility-store.ts",
    "web-client/src/bridge/setup-refusal-contract.test.ts",
    "web-client/src/bridge/setup-refusal-contract.ts",
    "web-client/src/bridge/signaling-client.test.ts",
    "web-client/src/bridge/signaling-client.ts",
    "web-client/src/bridge/signaling-contract.test.ts",
    "web-client/src/bridge/signaling-contract.ts",
    "web-client/src/bridge/terminal-codec-decoder.test.ts",
    "web-client/src/bridge/terminal-codec-decoder.ts",
    "web-client/src/bridge/webrtc-attempt-ownership.test.ts",
    "web-client/src/bridge/webrtc-bridge.ts",
    "web-client/src/bridge/webrtc-security.test.ts",
    "web-client/src/model/agent-provider-core.ts",
    "web-client/src/model/create-session-messages.test.ts",
    "web-client/src/model/create-session-messages.ts",
    "web-client/src/model/layout-preset.test.ts",
    "web-client/src/model/layout-preset.ts",
    "web-client/src/model/pane-layout.test.ts",
    "web-client/src/model/pane-layout.ts",
    "web-client/src/model/session-order.test.ts",
    "web-client/src/model/session-order.ts",
    "web-client/src/model/session-row.ts",
    "web-client/src/model/session-visibility.test.ts",
    "web-client/src/model/session-visibility.ts",
    "web-client/src/model/token-scope.test.ts",
    "web-client/src/model/token-scope.ts",
    "web-client/src/model/workspace-tree.ts",
    "web-client/src/protocol/bounded-control-json.test.ts",
    "web-client/src/protocol/bounded-control-json.ts",
    "web-client/src/protocol/control-messages.test.ts",
    "web-client/src/protocol/control-messages.ts",
    "web-client/src/protocol/terminal-frame.test.ts",
    "web-client/src/protocol/terminal-frame.ts",
    "web-client/src/protocol/web-protocol.test.ts",
    "web-client/src/protocol/web-protocol.ts",
    "web-client/src/terminal/grid-renderer.test.ts",
    "web-client/src/terminal/grid-renderer.ts",
    "web-client/src/terminal/input-encoder.test.ts",
    "web-client/src/terminal/input-encoder.ts",
    "web-client/src/terminal/search-highlight.test.ts",
    "web-client/src/terminal/search-highlight.ts",
    "web-client/src/terminal/search.test.ts",
    "web-client/src/terminal/search.ts",
    "web-client/src/terminal/selection-controller.test.ts",
    "web-client/src/terminal/selection-controller.ts",
    "web-client/src/terminal/selection.test.ts",
    "web-client/src/terminal/selection.ts",
    "web-client/src/terminal/terminal-sync.test.ts",
    "web-client/src/terminal/terminal-sync.ts",
    "web-client/src/terminal/theme.test.ts",
    "web-client/src/terminal/theme.ts",
    "web-client/src/terminal/viewport.test.ts",
    "web-client/src/terminal/viewport.ts",
    "web-client/src/vite-env.d.ts",
    "web-client/tsconfig.core-build.json",
    "web-client/tsconfig.json",
    "web-client/vite.config.ts",
}
remote_core_dirs = {
    parent.as_posix()
    for name in remote_core_files
    for parent in pathlib.PurePosixPath(name).parents
    if parent.as_posix() != "."
}
actual_remote_files = set()
for package in ("hydra-agent", "hydra-cloud", "web-client"):
    package_root = root / package
    if not package_root.is_dir():
        raise SystemExit(f"public-boundary: ERROR: missing Remote core package: {package}")
    for path in package_root.rglob("*"):
        name = path.relative_to(root).as_posix()
        if path.is_dir():
            if name not in remote_core_dirs:
                raise SystemExit(f"public-boundary: ERROR: unexpected Remote core directory: {name}")
        elif path.is_file():
            actual_remote_files.add(name)
        else:
            raise SystemExit(f"public-boundary: ERROR: non-regular Remote core path: {name}")
if actual_remote_files != remote_core_files:
    raise SystemExit(
        "public-boundary: ERROR: Remote core leaf inventory drifted: "
        f"missing={sorted(remote_core_files - actual_remote_files)} "
        f"extra={sorted(actual_remote_files - remote_core_files)}"
    )

# Exact bytes close exports, runtime dependencies, tooling, locks and build callers together.
# Build outputs and package LICENSE copies are generated, not additional source leaves.
remote_core_metadata = {
    "Cargo.lock": "26d6dd5cfd23c9af278ebe66eeb3dd882aef87a20572ccbc9351fbf8f7c7fce1",
    "Cargo.toml": "6864ad0639702ca59042634585776e3cbb77128b77f04e9e055c755fb8e05ab2",
    "LICENSE": "763a6e17187e1e6998d6d1af0d323c276e89fd54eff401bea96f20ba55d7828b",
    "hydra-agent/Cargo.lock": "7975a2d18916737df32457a372eedfb1f60c19217841999ec8671b022beb88d4",
    "hydra-agent/Cargo.toml": "c7d3b6f18fc647f9343c34beb602802d1f850b6aeef2e5bc4533c26100e048cc",
    "hydra-cloud/package-lock.json": "7f5ddebc65344d243e81b92debe52a231e7c5111a1d7abd007ebbffc81eea1ba",
    "hydra-cloud/package.json": "6a180d37a1c4eb42feed061f4b86d1efcdfd0c196aa702c66af76f169ec3a66c",
    "hydra-cloud/tsconfig.core-build.json": "14dac3664fc66ea4bfd2459158c2f9e0f7569975ff8b2cdb91253b07793b9ac4",
    "hydra-cloud/tsconfig.json": "55686b33aaa6786496c8a8a3c0b49d1f095a7e4a03a4190170b118a2361da4a4",
    "web-client/package-lock.json": "82a5509d84c09e94c73944ef5c757d892fff2bb5c3435dca1d96207330908168",
    "web-client/package.json": "eb3e7c53eb953932fbda26a4afc845baeb52d24d401b58b2e1bb1b72c5822cd7",
    "web-client/tsconfig.core-build.json": "d5d492691452dd3ac69cc2657d6dbda0379d0b1cb90cf986e43572d35c145c1d",
    "web-client/tsconfig.json": "725558f0dc7536ee201cf8915bd8bdc5d6088d03b1f9dfcd3f90e4eca030eddd",
    "web-client/vite.config.ts": "fd9710e76937601cef18b3907e654ca81a5e7728747d56aa10314a85b2b671b8"
}
for name, expected_digest in remote_core_metadata.items():
    if hashlib.sha256((root / name).read_bytes()).hexdigest() != expected_digest:
        raise SystemExit(f"public-boundary: ERROR: Remote core metadata digest drifted: {name}")

metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps"],
    cwd=root,
    text=True,
))
expected = {
    "hydra-launcher", "maestro-app", "maestro-extension-api", "maestro-local-services",
    "maestro-protocol", "maestro-renderer", "maestro-shell", "pty-daemon",
}
packages = {package["name"]: package for package in metadata["packages"]}
if set(packages) != expected:
    raise SystemExit(
        f"public-boundary: ERROR: unexpected workspace packages: {sorted(packages)}"
    )
# The agent is a separate excluded workspace, not a ninth desktop package.
if set(metadata["workspace_members"]) != {package["id"] for package in packages.values()}:
    raise SystemExit("public-boundary: ERROR: desktop workspace membership drifted")
agent_metadata = json.loads(subprocess.check_output(
    ["cargo", "metadata", "--locked", "--format-version", "1", "--no-deps",
     "--manifest-path", "hydra-agent/Cargo.toml", "--features", "webrtc"],
    cwd=root,
    text=True,
))
agent_packages = agent_metadata["packages"]
if len(agent_packages) != 1 or agent_packages[0]["name"] != "hydra-agent":
    raise SystemExit("public-boundary: ERROR: standalone agent package drifted")
agent_package = agent_packages[0]
if (agent_metadata["workspace_members"] != [agent_package["id"]]
        or pathlib.Path(agent_metadata["workspace_root"]).resolve() != root / "hydra-agent"
        or pathlib.Path(agent_package["manifest_path"]).resolve() != root / "hydra-agent/Cargo.toml"):
    raise SystemExit("public-boundary: ERROR: standalone agent workspace identity drifted")
agent_paths = {
    dependency["name"]: pathlib.Path(dependency["path"]).resolve()
    for dependency in agent_package["dependencies"] if dependency.get("path") is not None
}
expected_agent_paths = {
    name: root / name for name in
    ("maestro-protocol", "maestro-local-services", "maestro-shell", "maestro-extension-api")
}
if agent_paths != expected_agent_paths:
    raise SystemExit("public-boundary: ERROR: standalone agent path dependency closure drifted")
# Apply the existing MIT/publish=false/inside-root checks to both workspaces.
packages["hydra-agent"] = agent_package
for name, package in packages.items():
    if package.get("publish") != []:
        raise SystemExit(f"public-boundary: ERROR: {name} is publishable to a registry")
    if package.get("license") != "MIT":
        raise SystemExit(f"public-boundary: ERROR: {name} does not declare MIT")
    manifest = pathlib.Path(package["manifest_path"]).resolve()
    try:
        manifest.relative_to(root)
    except ValueError:
        raise SystemExit(
            f"public-boundary: ERROR: {name} resolves outside the public tree"
        )
    for dependency in package.get("dependencies", []):
        dependency_path = dependency.get("path")
        if dependency_path is None:
            continue
        resolved_dependency = pathlib.Path(dependency_path).resolve()
        try:
            resolved_dependency.relative_to(root)
        except ValueError:
            raise SystemExit(
                f"public-boundary: ERROR: {name} path dependency resolves outside the public tree"
            )
print("public-boundary: 8 desktop packages and 1 standalone agent checked")
PY

printf 'public-boundary: PASS\n'
