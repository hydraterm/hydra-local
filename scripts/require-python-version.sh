#!/usr/bin/env bash

required_python="$(tr -d '[:space:]' < "$ROOT/.python-version")"
if ! command -v python3 >/dev/null 2>&1; then
  printf 'Python %s is required (python3 was not found).\n' "$required_python" >&2
  exit 1
fi
if ! found_python="$(python3 -c 'import platform; print(platform.python_implementation(), platform.python_version())' 2>&1)"; then
  printf 'Python %s is required (python3 could not execute the version check: %s).\n' \
    "$required_python" "$found_python" >&2
  exit 1
fi
if [[ "$found_python" != "CPython $required_python" ]]; then
  printf 'CPython %s is required (found %s).\n' "$required_python" "$found_python" >&2
  exit 1
fi
