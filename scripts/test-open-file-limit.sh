#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd -P)"
HELPER="$ROOT/scripts/ensure-open-file-limit.sh"
proofs=0

source "$HELPER"
hydra_limit_is_at_least unlimited 1024
! hydra_limit_is_at_least 1023 1024
hydra_limit_is_at_least 1024 1024
proofs=$((proofs + 1))

bash -euo pipefail -c '
  ulimit -Sn 256
  source "$1"
  hydra_ensure_open_file_limit
  [[ "$(ulimit -Sn)" -ge 1024 ]]
' _ "$HELPER"
proofs=$((proofs + 1))

bash -euo pipefail -c '
  ulimit -Sn 1024
  before="$(ulimit -Sn)"
  source "$1"
  hydra_ensure_open_file_limit
  [[ "$(ulimit -Sn)" == "$before" ]]
' _ "$HELPER"
proofs=$((proofs + 1))

failure="$(mktemp)"
trap 'rm -f "$failure"' EXIT HUP INT TERM
if bash -euo pipefail -c '
  ulimit -Sn 512
  ulimit -Hn 512
  source "$1"
  hydra_ensure_open_file_limit
  printf reached-unexpected-command
' _ "$HELPER" >"$failure" 2>&1; then
  printf 'open-file-limit-tests: expected low hard-limit rejection\n' >&2
  exit 1
fi
grep -q 'hard limit 512 cannot meet required 1024' "$failure"
! grep -q 'reached-unexpected-command' "$failure"
proofs=$((proofs + 1))

[[ "$proofs" -eq 4 ]]
printf 'open-file-limit-tests: PASS proofs=%s\n' "$proofs"
