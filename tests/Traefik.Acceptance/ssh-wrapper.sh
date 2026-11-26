#!/usr/bin/env bash
set -euo pipefail

: "${DOROTHY_ACCEPTANCE_SSH_CONFIG:?private SSH config is required}"
: "${DOROTHY_ACCEPTANCE_SSH_PORT:?private SSH forward port is required}"
[[ "$DOROTHY_ACCEPTANCE_SSH_PORT" =~ ^[0-9]+$ ]] || { printf 'Invalid private SSH forward port.\n' >&2; exit 2; }

args=()
target_seen=false
while (($#)); do
    case "$1" in
        -p)
            (($# >= 2)) || { printf 'Incomplete SSH port option.\n' >&2; exit 2; }
            port=$2
            if [[ "$port" == 22 ]]; then port=$DOROTHY_ACCEPTANCE_SSH_PORT; fi
            args+=(-p "$port")
            shift 2
            ;;
        -i|-o|-F|-l|-J|-S|-W|-b|-c|-D|-E|-e|-L|-m|-O|-R|-w)
            (($# >= 2)) || { printf 'Incomplete SSH option.\n' >&2; exit 2; }
            args+=("$1" "$2")
            shift 2
            ;;
        *)
            if [[ "$target_seen" == false && "$1" != -* ]]; then
                if [[ "$1" == root@192.0.2.1 ]]; then
                    args+=(root@127.0.0.1)
                    target_seen=true
                elif [[ "$1" == *@* ]]; then
                    printf 'SSH wrapper only permits the private acceptance fixture target.\n' >&2
                    exit 2
                else
                    args+=("$1")
                fi
            else
                args+=("$1")
            fi
            shift
            ;;
    esac
done
[[ "$target_seen" == true ]] || { printf 'SSH wrapper did not find the acceptance fixture target.\n' >&2; exit 2; }
exec /usr/bin/ssh -F "$DOROTHY_ACCEPTANCE_SSH_CONFIG" "${args[@]}"
