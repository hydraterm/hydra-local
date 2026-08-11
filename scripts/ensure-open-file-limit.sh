#!/usr/bin/env bash

readonly HYDRA_MIN_OPEN_FILES=1024

hydra_limit_is_at_least() {
  local value="$1"
  local minimum="$2"
  [[ "$value" == unlimited ]] || [[ "$value" =~ ^[0-9]+$ && "$value" -ge "$minimum" ]]
}

hydra_ensure_open_file_limit() {
  local soft hard updated
  soft="$(ulimit -Sn)"
  hard="$(ulimit -Hn)"
  if hydra_limit_is_at_least "$soft" "$HYDRA_MIN_OPEN_FILES"; then
    return 0
  fi
  if ! hydra_limit_is_at_least "$hard" "$HYDRA_MIN_OPEN_FILES"; then
    printf 'test-local: open-file soft limit %s and hard limit %s cannot meet required %s. Raise the shell hard limit, then run: ulimit -n %s\n' \
      "$soft" "$hard" "$HYDRA_MIN_OPEN_FILES" "$HYDRA_MIN_OPEN_FILES" >&2
    return 1
  fi
  if ! ulimit -Sn "$HYDRA_MIN_OPEN_FILES"; then
    printf 'test-local: could not raise open-file soft limit %s to %s (hard limit %s). Run: ulimit -n %s\n' \
      "$soft" "$HYDRA_MIN_OPEN_FILES" "$hard" "$HYDRA_MIN_OPEN_FILES" >&2
    return 1
  fi
  updated="$(ulimit -Sn)"
  if ! hydra_limit_is_at_least "$updated" "$HYDRA_MIN_OPEN_FILES"; then
    printf 'test-local: open-file soft limit remained %s; required %s. Run: ulimit -n %s\n' \
      "$updated" "$HYDRA_MIN_OPEN_FILES" "$HYDRA_MIN_OPEN_FILES" >&2
    return 1
  fi
}
