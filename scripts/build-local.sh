#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
PROFILE=debug
OFFICIAL=0
TARGET=""

usage() {
  printf 'Usage: %s [--release] [--official-distribution] [--target <rust-target>]\n' "$0" >&2
}

while (($#)); do
  case "$1" in
    --release) PROFILE=release ;;
    --official-distribution) OFFICIAL=1 ;;
    --target)
      shift
      (($#)) || { usage; exit 2; }
      TARGET="$1"
      ;;
    -h|--help) usage; exit 0 ;;
    *) usage; exit 2 ;;
  esac
  shift
done

required_node="$(tr -d '[:space:]' < "$ROOT/.nvmrc")"
required_npm="$(node -p "require('$ROOT/dashboard-ui/package.json').packageManager.split('@')[1]")"
[[ "$(node --version)" == "v$required_node" ]] || {
  printf 'build-local: Node %s is required (found %s). Run nvm use.\n' "$required_node" "$(node --version)" >&2
  exit 1
}
[[ "$(npm --version)" == "$required_npm" ]] || {
  printf 'build-local: npm %s is required (found %s).\n' "$required_npm" "$(npm --version)" >&2
  exit 1
}

npm --prefix "$ROOT/dashboard-ui" ci
npm --prefix "$ROOT/dashboard-ui" run build

cargo_args=(build --locked --workspace)
[[ "$PROFILE" == release ]] && cargo_args+=(--release)
[[ "$OFFICIAL" == 1 ]] && cargo_args+=(--features maestro-app/official-distribution)
[[ -n "$TARGET" ]] && cargo_args+=(--target "$TARGET")
(cd "$ROOT" && cargo "${cargo_args[@]}")

printf 'build-local: PASS profile=%s official_distribution=%s target=%s\n' \
  "$PROFILE" "$OFFICIAL" "${TARGET:-host-default}"
