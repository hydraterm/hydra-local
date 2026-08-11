#!/usr/bin/env bash
# Source this file with the public source root as its only argument.

if (($# != 1)); then
  printf 'release-path-remap: expected the public source root\n' >&2
  return 1
fi
if [[ -n "${RUSTFLAGS:-}" || -n "${CARGO_ENCODED_RUSTFLAGS:-}" ]]; then
  printf 'release-path-remap: external Rust flags are not allowed for deterministic packaging\n' >&2
  return 1
fi

hydra_remap_root="$(cd "$1" && pwd -P)"
hydra_remap_home="$(cd "${HOME:?HOME is required}" && pwd -P)"
hydra_remap_cargo_home_input="${CARGO_HOME:-$hydra_remap_home/.cargo}"
if [[ ! -d "$hydra_remap_cargo_home_input" ]]; then
  printf 'release-path-remap: Cargo home does not exist: %s\n' "$hydra_remap_cargo_home_input" >&2
  return 1
fi
hydra_remap_cargo_home="$(cd "$hydra_remap_cargo_home_input" && pwd -P)"
case "$hydra_remap_root$hydra_remap_home$hydra_remap_cargo_home" in
  *$'\x1f'*|*=*)
    printf 'release-path-remap: source/home paths contain an unsupported separator\n' >&2
    return 1
    ;;
esac

hydra_encoded_flags=""
hydra_append_remap() {
  if [[ -n "$hydra_encoded_flags" ]]; then
    hydra_encoded_flags+=$'\x1f'
  fi
  hydra_encoded_flags+="--remap-path-prefix=$1=$2"
}

# rustc applies the last matching prefix, so general paths come first and exact package/source
# roots come last. This keeps the stable spellings distinct and makes the final byte scan useful.
hydra_append_remap "$hydra_remap_home" /home/example/build
hydra_append_remap "$hydra_remap_cargo_home" /cargo
hydra_append_remap "$hydra_remap_cargo_home/registry" /cargo/registry
hydra_append_remap "$hydra_remap_cargo_home/git" /cargo/git
hydra_append_remap "$hydra_remap_root" /usr/src/hydra-local

export CARGO_ENCODED_RUSTFLAGS="$hydra_encoded_flags"
export CARGO_INCREMENTAL=0
unset hydra_encoded_flags hydra_remap_root hydra_remap_home hydra_remap_cargo_home
unset hydra_remap_cargo_home_input
unset -f hydra_append_remap
