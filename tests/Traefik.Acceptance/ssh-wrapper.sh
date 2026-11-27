#!/usr/bin/env bash
set -euo pipefail

: "${DOROTHY_ACCEPTANCE_SSH_CONFIG:?private SSH config is required}"
: "${DOROTHY_ACCEPTANCE_SSH_PORT:?private SSH forward port is required}"
[[ "$DOROTHY_ACCEPTANCE_SSH_PORT" =~ ^[0-9]+$ ]] || { printf 'Invalid private SSH forward port.\n' >&2; exit 2; }

args=()
target_seen=false
while (($#)); do
    case "$1" in
        -T) args+=(-T); shift ;;
        -p)
            [[ ${2:-} == 22 ]] || { echo 'Unexpected logical management port.' >&2; exit 2; }
            args+=(-p "$DOROTHY_ACCEPTANCE_SSH_PORT"); shift 2 ;;
        -o)
            case "${2:-}" in
                BatchMode=yes|StrictHostKeyChecking=yes|ConnectTimeout=15|ControlMaster=no|ControlPath=none|IdentitiesOnly=yes)
                    args+=(-o "$2"); shift 2 ;;
                *) echo 'Unsupported SSH option in private fixture.' >&2; exit 2 ;;
            esac ;;
        -i)
            [[ ${2:-} == "${DOROTHY_ACCEPTANCE_SSH_CONFIG%/*}/id_ed25519" ]] || { echo 'Unexpected management identity.' >&2; exit 2; }
            args+=(-i "$2"); shift 2 ;;
        root@192.0.2.1)
            (( $# == 2 )) || { echo 'Expected exactly one remote command.' >&2; exit 2; }
            args+=(root@127.0.0.1 "$2"); target_seen=true; shift 2 ;;
        *) echo 'SSH wrapper accepts only the private fixture target and provider options.' >&2; exit 2 ;;
    esac
done
[[ "$target_seen" == true ]] || { printf 'SSH wrapper did not find the acceptance fixture target.\n' >&2; exit 2; }
outgoing_argv=(/usr/bin/ssh -F "$DOROTHY_ACCEPTANCE_SSH_CONFIG" -o ClearAllForwardings=yes -o ProxyCommand=none -o ForwardAgent=no "${args[@]}")
if [[ -n "${DOROTHY_ACCEPTANCE_SSH_AUDIT_FILE:-}" ]]; then
    audit_file=$DOROTHY_ACCEPTANCE_SSH_AUDIT_FILE
    token_file_list=${DOROTHY_ACCEPTANCE_DNS_TOKEN_FILES:-}
    [[ -n "$token_file_list" && ! -L "$audit_file" ]] || {
        printf 'SSH argv audit configuration is invalid.\n' >&2
        exit 2
    }
    token_files=()
    IFS=: read -r -a token_files <<< "$token_file_list"
    argv_count=${#outgoing_argv[@]}
    token_count=0
    comparison_count=0
    for token_file in "${token_files[@]}"; do
        [[ -n "$token_file" ]] || continue
        if [[ ! -e "$token_file" && ! -L "$token_file" ]]; then
            continue
        fi
        [[ -f "$token_file" && ! -L "$token_file" ]] || {
            printf 'SSH argv audit encountered an unsafe fixture file.\n' >&2
            exit 2
        }
        token=$(tr -d '\r\n' < "$token_file")
        [[ -n "$token" ]] || {
            printf 'SSH argv audit encountered an empty fixture token.\n' >&2
            exit 2
        }
        token_count=$((token_count + 1))
        for argument in "${outgoing_argv[@]}"; do
            comparison_count=$((comparison_count + 1))
            if [[ "$argument" == *"$token"* ]]; then
                printf 'SSH launch refused because an argv entry matched a DNS fixture token.\n' >&2
                exit 2
            fi
        done
    done
    [[ "$token_count" -gt 0 && "$comparison_count" -eq $((argv_count * token_count)) ]] || {
        printf 'SSH argv audit did not check every outgoing argument.\n' >&2
        exit 2
    }
    printf 'argv=%d tokens=%d comparisons=%d\n' "$argv_count" "$token_count" "$comparison_count" >> "$audit_file"
fi

exec "${outgoing_argv[@]}"
