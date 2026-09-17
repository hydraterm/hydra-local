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

if find . -path './.git' -prune -o -type f ! -path "./$REVIEWED_DEMO" \( \
  -iname '*.png' -o -iname '*.svg' -o -iname '*.gif' -o -iname '*.webp' \
  -o -iname '*.jpg' -o -iname '*.jpeg' -o -iname '*.mov' -o -iname '*.mp4' \
  -o -iname '*.pdf' -o -iname '*.zip' -o -iname '*.tar' -o -iname '*.gz' \
  -o -iname '*.dmg' -o -iname '*.deb' -o -iname '*.pkg' -o -iname '*.woff' \
  -o -iname '*.woff2' -o -iname '*.ttf' -o -iname '*.otf' -o -iname '*.mp3' \
  -o -iname '*.wav' -o -iname '*.m4a' \) -print -quit | grep -q .; then
  fail "unreviewed binary, image, recording, archive, installer, or font asset is present"
fi

python3 - "$ROOT" "$REVIEWED_DEMO" "$REVIEWED_DEMO_SHA256" <<'PY'
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
}
allowed_root_entries = {
    ".editorconfig", ".git", ".github", ".gitignore", ".nvmrc", ".python-version",
    "CODE_OF_CONDUCT.md", "CONTRIBUTING.md", "Cargo.lock", "Cargo.toml",
    "DCO.md", "DEVELOPMENT.md", "FAQ.md", "LICENSE", "README.md", "SECURITY.md",
    "THIRD_PARTY_NOTICES.md", "TRADEMARKS.md", "TROUBLESHOOTING.md", "dashboard-ui", "docs",
    "hydra-cloud", "web-client",
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
    "web-client/src/bridge/connect-deadline.test.ts",
    "web-client/src/bridge/connect-deadline.ts",
    "web-client/src/bridge/datachannel-send-queue.test.ts",
    "web-client/src/bridge/datachannel-send-queue.ts",
    "web-client/src/bridge/ice-candidate-security.test.ts",
    "web-client/src/bridge/ice-candidate-security.ts",
    "web-client/src/bridge/ice-path-classifier.test.ts",
    "web-client/src/bridge/ice-path-classifier.ts",
    "web-client/src/bridge/relay-fallback.test.ts",
    "web-client/src/bridge/relay-fallback.ts",
    "web-client/src/bridge/remote-transport.ts",
    "web-client/src/bridge/sdp-security.test.ts",
    "web-client/src/bridge/sdp-security.ts",
    "web-client/src/bridge/setup-refusal-contract.ts",
    "web-client/src/bridge/signaling-contract.test.ts",
    "web-client/src/bridge/signaling-contract.ts",
    "web-client/src/bridge/webrtc-attempt-ownership.test.ts",
    "web-client/src/bridge/webrtc-bridge.ts",
    "web-client/src/bridge/webrtc-security.test.ts",
    "web-client/src/protocol/bounded-control-json.test.ts",
    "web-client/src/protocol/bounded-control-json.ts",
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
for package in ("hydra-cloud", "web-client"):
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
    "LICENSE": "763a6e17187e1e6998d6d1af0d323c276e89fd54eff401bea96f20ba55d7828b",
    "hydra-cloud/package-lock.json": "325f475dd0ab2f374d3086d4ed895da61fa0fb59a7c3affc9b1fb9115996d3c8",
    "hydra-cloud/package.json": "e7a03ce33c58941da71b7a281001c0a251a5e0d17da7ae421ee14c173de66809",
    "hydra-cloud/tsconfig.core-build.json": "14dac3664fc66ea4bfd2459158c2f9e0f7569975ff8b2cdb91253b07793b9ac4",
    "hydra-cloud/tsconfig.json": "55686b33aaa6786496c8a8a3c0b49d1f095a7e4a03a4190170b118a2361da4a4",
    "web-client/package-lock.json": "ef9c130a7481c2c23f7a02197beccc12a6925c99bc1ab281d347ba9a952c88e3",
    "web-client/package.json": "f908a8a1db1c62e635dddb6624bc83939c798c130898d6931d9f32f0826ce8f9",
    "web-client/tsconfig.core-build.json": "d5d492691452dd3ac69cc2657d6dbda0379d0b1cb90cf986e43572d35c145c1d",
    "web-client/tsconfig.json": "60c13f7d2d8b39dad5f29e8bb39598f26126c41021a129d7f43cf6c3f8edcbef",
    "web-client/vite.config.ts": "9e3df78c1e438fe868435ed21c7c4549d43a6b7351fe0cba90f0a45713cc5fa5",
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
print(f"public-boundary: {len(packages)} local-only packages checked")
PY

printf 'public-boundary: PASS\n'
