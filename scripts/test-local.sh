#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
cd "$ROOT"

source "$ROOT/scripts/require-python-version.sh"
source "$ROOT/scripts/ensure-open-file-limit.sh"
bash "$ROOT/scripts/test-open-file-limit.sh"
hydra_ensure_open_file_limit

required_node="$(tr -d '[:space:]' < .nvmrc)"
required_npm="$(node -p "require('./dashboard-ui/package.json').packageManager.split('@')[1]")"
test_threads="${HYDRA_TEST_THREADS:-4}"
[[ "$test_threads" =~ ^[1-9][0-9]*$ && "$test_threads" -le 16 ]] || {
  printf 'test-local: HYDRA_TEST_THREADS must be an integer from 1 through 16.\n' >&2
  exit 1
}
[[ "$(node --version)" == "v$required_node" ]] || {
  printf 'test-local: Node %s is required (found %s). Run nvm use.\n' "$required_node" "$(node --version)" >&2
  exit 1
}
[[ "$(npm --version)" == "$required_npm" ]] || {
  printf 'test-local: npm %s is required (found %s).\n' "$required_npm" "$(npm --version)" >&2
  exit 1
}

npm --prefix dashboard-ui ci
npm --prefix dashboard-ui audit --audit-level=low
npm --prefix dashboard-ui run typecheck
npm --prefix dashboard-ui test
npm --prefix dashboard-ui run build
python3 scripts/verify-third-party-licenses.py
python3 scripts/verify-packaging-controls.py

cargo fmt --all -- --check
cargo check --locked --workspace
cargo test --locked --workspace -- --test-threads="$test_threads"
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo check --locked -p maestro-app --features official-distribution
cargo test --locked -p maestro-app --test public_boundary --features official-distribution \
  -- --test-threads="$test_threads"

printf 'test-local: PASS test_threads=%s\n' "$test_threads"
