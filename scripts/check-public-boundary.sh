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
    "hydra-launcher", "maestro-app",
    "maestro-extension-api", "maestro-local-services", "maestro-protocol",
    "maestro-renderer", "maestro-shell", "packaging", "pty-daemon", "rust-toolchain.toml",
    "scripts",
}
unexpected_root = sorted(path.name for path in root.iterdir() if path.name not in allowed_root_entries)
if unexpected_root:
    raise SystemExit(f"public-boundary: ERROR: unexpected top-level entries: {unexpected_root}")

allowed_docs = {
    "architecture.md",
    "assets/hydra-local-demo.gif",
    "public-private-boundary.md",
    "third-party-licensing.md",
}
unexpected_docs = sorted(
    str(path.relative_to(root / "docs"))
    for path in (root / "docs").rglob("*")
    if path.is_file() and str(path.relative_to(root / "docs")) not in allowed_docs
)
if unexpected_docs:
    raise SystemExit(f"public-boundary: ERROR: unexpected documentation files: {unexpected_docs}")

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
    if package.get("license") != "Apache-2.0":
        raise SystemExit(f"public-boundary: ERROR: {name} does not declare Apache-2.0")
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
