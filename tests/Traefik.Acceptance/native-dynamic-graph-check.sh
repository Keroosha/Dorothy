#!/usr/bin/env bash
set -euo pipefail

native_dynamic_graph_check() {
    local root port port_number headers body
    root=$(realpath -e -- "${1:?private guest fixture root required}")
    port=${2:?loopback Traefik HTTP port required}
    case "$root" in
        /var/tmp/dorothy-traefik-acceptance.*) ;;
        *) printf 'Refusing to write outside the private guest fixture.\n' >&2; return 2 ;;
    esac
    [[ -d "$root/logs" && -w "$root/logs" ]] || {
        printf 'Private guest fixture logs directory is unavailable.\n' >&2
        return 2
    }
    [[ "$port" =~ ^[0-9]{1,5}$ ]] || {
        printf 'Expected a numeric loopback listener port.\n' >&2
        return 2
    }
    port_number=$((10#$port))
    (( port_number >= 1 && port_number <= 65535 )) || {
        printf 'Expected a numeric loopback listener port.\n' >&2
        return 2
    }

    headers="$root/logs/native-dynamic-graph.headers"
    body="$root/logs/native-dynamic-graph.body"
    curl --fail --silent --show-error --max-time 10 \
        --header 'Host: multi.example.test' \
        --dump-header "$headers" \
        --output "$body" \
        "http://127.0.0.1:${port_number}/multilayer/admin"
    [[ "$(<"$body")" == other ]] || {
        printf 'The parentRefs route selected the wrong backend.\n' >&2
        return 1
    }
    awk -F: '
        tolower($1) == "x-dorothy-service" {
            value = $2
            sub(/^[[:space:]]+/, "", value)
            sub(/\r$/, "", value)
            if (value == "native") found = 1
        }
        END { exit !found }
    ' "$headers" || {
        printf 'The service-level middleware response header was not observed.\n' >&2
        return 1
    }
    printf 'Native parentRefs child selection and service-level middleware were observed.\n'
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    if [[ $# != 2 ]]; then
        printf 'Usage: native-dynamic-graph-check.sh /var/tmp/dorothy-traefik-acceptance.XXXXXXXX PORT\n' >&2
        exit 2
    fi
    native_dynamic_graph_check "$1" "$2"
fi
