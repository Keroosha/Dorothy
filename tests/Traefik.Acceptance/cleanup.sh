#!/usr/bin/env bash
set -euo pipefail

if [[ $# != 1 ]]; then
    printf 'Usage: %s /tmp/dorothy-traefik-acceptance.XXXXXXXX\n' "$0" >&2
    exit 2
fi
state_dir=$(realpath -e -- "$1")
case "$state_dir" in
    /tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to clean a path outside the private acceptance temp root.\n' >&2; exit 2 ;;
esac
[[ -d "$state_dir" && ! -L "$state_dir" && -f "$state_dir/.owner" ]] || { printf 'Refusing to clean an unmarked acceptance directory.\n' >&2; exit 2; }
[[ "$(<"$state_dir/.owner")" == dorothy-traefik-acceptance-owned-state-v1 ]] || { printf 'Ownership marker does not match.\n' >&2; exit 2; }

if [[ -s "$state_dir/qemu.pid" ]]; then
    pid=$(<"$state_dir/qemu.pid")
    if [[ "$pid" =~ ^[0-9]+$ ]] && [[ -r "/proc/$pid/cmdline" ]]; then
        command_line=$(tr '\0' ' ' < "/proc/$pid/cmdline")
        if [[ "$command_line" == *qemu-system-x86_64* && "$command_line" == *"$state_dir/guest.qcow2"* ]]; then
            kill -TERM "$pid"
            for _ in $(seq 1 50); do
                kill -0 "$pid" 2>/dev/null || break
                sleep 0.2
            done
            if kill -0 "$pid" 2>/dev/null; then
                command_line=$(tr '\0' ' ' < "/proc/$pid/cmdline" 2>/dev/null || true)
                if [[ "$command_line" == *qemu-system-x86_64* && "$command_line" == *"$state_dir/guest.qcow2"* ]]; then
                    kill -KILL "$pid"
                fi
            fi
        fi
    fi
fi
rm -rf -- "$state_dir"
printf 'Stopped the owned guest (if running) and removed %s\n' "$state_dir"
