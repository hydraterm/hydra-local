#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)"
OUTPUT="${1:-$ROOT/artifacts}"
source "$ROOT/scripts/require-python-version.sh"
[[ "$(uname -s)" == Darwin ]] || { printf 'macOS host required\n' >&2; exit 1; }
[[ -z "${CARGO_TARGET_DIR+x}" && -z "${CARGO_BUILD_TARGET+x}" ]] || {
  printf 'packaging refuses external Cargo target selection\n' >&2
  exit 1
}

target="$(rustc -vV | sed -n 's/^host: //p')"
case "$target" in
  aarch64-apple-darwin|x86_64-apple-darwin) ;;
  *) printf 'Unsupported macOS Rust target: %s\n' "$target" >&2; exit 1 ;;
esac
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
export CARGO_TARGET_DIR="$work/cargo-target"
source "$ROOT/scripts/configure-release-path-remap.sh" "$ROOT"
"$ROOT/scripts/build-local.sh" --release --target "$target"
release_dir="$CARGO_TARGET_DIR/$target/release"
version="$(sed -n 's/^version = "\([0-9][0-9.]*\)"/\1/p' "$ROOT/maestro-app/Cargo.toml" | head -1)"
[[ "$version" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || { printf 'Invalid app version\n' >&2; exit 1; }
build_number="${version//./}"

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
app="$stage/Hydra.app"
install -d "$app/Contents/MacOS" "$app/Contents/Resources/bin" \
  "$app/Contents/Resources/dashboard-ui" "$app/Contents/Resources/licenses"
install -m 0755 "$release_dir/hydra-launcher" "$app/Contents/MacOS/Hydra"
install -m 0755 "$release_dir/maestro-app" "$app/Contents/Resources/bin/maestro-app"
install -m 0755 "$release_dir/pty-daemon" "$app/Contents/Resources/bin/pty-daemon"
cp -R "$ROOT/dashboard-ui/dist/." "$app/Contents/Resources/dashboard-ui/"
find "$app/Contents/Resources/dashboard-ui" -type d -exec chmod 0755 {} +
find "$app/Contents/Resources/dashboard-ui" -type f -exec chmod 0644 {} +
install -m 0644 "$ROOT/LICENSE" "$app/Contents/Resources/licenses/LICENSE"
install -m 0644 "$third_party_licenses" \
  "$app/Contents/Resources/licenses/THIRD_PARTY_LICENSES.txt"
if [[ -f "$ROOT/THIRD_PARTY_NOTICES.md" ]]; then
  install -m 0644 "$ROOT/THIRD_PARTY_NOTICES.md" "$app/Contents/Resources/licenses/THIRD_PARTY_NOTICES.md"
fi
cat > "$app/Contents/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
  <key>CFBundleDisplayName</key><string>Hydra</string>
  <key>CFBundleExecutable</key><string>Hydra</string>
  <key>CFBundleIdentifier</key><string>com.hydraterms.hydra.source-build</string>
  <key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
  <key>CFBundleName</key><string>Hydra</string>
  <key>CFBundlePackageType</key><string>APPL</string>
  <key>CFBundleShortVersionString</key><string>$version</string>
  <key>CFBundleVersion</key><string>$build_number</string>
  <key>LSMinimumSystemVersion</key><string>13.0</string>
</dict></plist>
PLIST
chmod 0644 "$app/Contents/Info.plist"
plutil -lint "$app/Contents/Info.plist" >/dev/null
[[ ! -e "$app/Contents/Resources/bin/hydra-agent" ]] || {
  printf 'private agent entered local-only package\n' >&2
  exit 1
}
mkdir -p "$OUTPUT"
archive="$OUTPUT/hydra-local-macos-unsigned.tar.gz"
python3 "$ROOT/scripts/create-reproducible-tar.py" \
  --source "$app" --archive "$archive" --group-name wheel
python3 "$ROOT/scripts/verify-packaged-boundary.py" \
  --archive "$archive" --platform macos \
  --expected-binaries-dir "$release_dir" \
  --expected-third-party-licenses "$third_party_licenses" \
  --forbidden-path "$work"
printf 'Created %s\n' "$archive"
