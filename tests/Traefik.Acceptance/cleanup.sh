#!/usr/bin/env bash
set -euo pipefail

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $# != 1 ]]; then
    printf 'Usage: %s /tmp/dorothy-traefik-acceptance.XXXXXXXX\n' "$0" >&2
    exit 2
fi
[[ ! -L "$1" ]] || { printf 'Refusing a symlinked cleanup target.\n' >&2; exit 2; }
state_dir=$(realpath -e -- "$1")
case "$state_dir" in
    /tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to clean a path outside the private acceptance temp root.\n' >&2; exit 2 ;;
esac
[[ -d "$state_dir" && ! -L "$state_dir" && -f "$state_dir/.owner" && ! -L "$state_dir/.owner" ]] || { printf 'Refusing to clean an unmarked acceptance directory.\n' >&2; exit 2; }
[[ "$(<"$state_dir/.owner")" == dorothy-traefik-acceptance-owned-state-v1 ]] || { printf 'Ownership marker does not match.\n' >&2; exit 2; }
[[ "$(stat -c %a "$state_dir")" == 700 && "$(stat -c %u "$state_dir")" == "$(id -u)" ]] || { printf 'Refusing cleanup of a state directory with unexpected ownership or permissions.\n' >&2; exit 2; }
bash "$script_dir/guest-barrier-check.sh" stop "$state_dir"
rm -rf -- "$state_dir"
printf 'Stopped the owned guest and private relays (if running) and removed %s\n' "$state_dir"
