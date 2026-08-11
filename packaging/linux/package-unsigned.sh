#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
OUTPUT="${1:-$ROOT/artifacts}"
source "$ROOT/scripts/require-python-version.sh"
[[ "$(uname -s)" == Linux ]] || { printf 'Linux host required\n' >&2; exit 1; }
[[ -z "${CARGO_TARGET_DIR+x}" && -z "${CARGO_BUILD_TARGET+x}" ]] || {
  printf 'packaging refuses external Cargo target selection\n' >&2
  exit 1
}

arch="$(uname -m)"
case "$arch" in
  x86_64) package_arch=amd64; target=x86_64-unknown-linux-gnu ;;
  aarch64|arm64) package_arch=arm64; target=aarch64-unknown-linux-gnu ;;
  *) printf 'Unsupported architecture: %s\n' "$arch" >&2; exit 1 ;;
esac
[[ "$(rustc -vV | sed -n 's/^host: //p')" == "$target" ]] || {
  printf 'Rust host does not match package target: %s\n' "$target" >&2
  exit 1
}
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export CARGO_TARGET_DIR="$work/cargo-target"
source "$ROOT/scripts/configure-release-path-remap.sh" "$ROOT"
"$ROOT/scripts/build-local.sh" --release --target "$target"
release_dir="$CARGO_TARGET_DIR/$target/release"

stage="$work/package-stage"
install -d "$stage"
third_party_licenses="$stage/THIRD_PARTY_LICENSES.txt"
python3 "$ROOT/scripts/generate-third-party-licenses.py" \
  --target "$target" \
  --output "$third_party_licenses"
[[ -s "$third_party_licenses" ]] || {
  printf 'third-party licence artifact was not generated\n' >&2
  exit 1
}
package_root="$stage/hydra-local-linux-$package_arch"
install -d "$package_root/bin" "$package_root/dashboard-ui" "$package_root/share/licenses"
install -m 0755 "$release_dir/maestro-app" "$package_root/bin/maestro-app"
install -m 0755 "$release_dir/pty-daemon" "$package_root/bin/pty-daemon"
install -m 0755 "$ROOT/packaging/linux/hydra-local" "$package_root/bin/hydra-local"
cp -R "$ROOT/dashboard-ui/dist/." "$package_root/dashboard-ui/"
find "$package_root/dashboard-ui" -type d -exec chmod 0755 {} +
find "$package_root/dashboard-ui" -type f -exec chmod 0644 {} +
install -m 0644 "$ROOT/LICENSE" "$package_root/share/licenses/LICENSE"
install -m 0644 "$third_party_licenses" "$package_root/share/licenses/THIRD_PARTY_LICENSES.txt"
if [[ -f "$ROOT/THIRD_PARTY_NOTICES.md" ]]; then
  install -m 0644 "$ROOT/THIRD_PARTY_NOTICES.md" "$package_root/share/licenses/THIRD_PARTY_NOTICES.md"
fi
find "$package_root" -type f -name 'hydra-agent' -print -quit | grep -q . && {
  printf 'private agent entered local-only package\n' >&2
  exit 1
}
mkdir -p "$OUTPUT"
archive="$OUTPUT/hydra-local-linux-$package_arch.tar.gz"
python3 "$ROOT/scripts/create-reproducible-tar.py" \
  --source "$package_root" --archive "$archive" --group-name root
python3 "$ROOT/scripts/verify-packaged-boundary.py" \
  --archive "$archive" --platform linux --arch "$package_arch" \
  --expected-binaries-dir "$release_dir" \
  --expected-third-party-licenses "$third_party_licenses" \
  --forbidden-path "$work"
printf 'Created %s\n' "$archive"
