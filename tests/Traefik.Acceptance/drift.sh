#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
    printf 'Usage: drift.sh [/var/tmp/dorothy-traefik-acceptance.XXXXXXXX] | drift.sh {inject|assert-drift|assert-repaired} /var/tmp/dorothy-traefik-acceptance.XXXXXXXX\n' >&2
    exit 2
}

if [[ $# == 1 ]]; then
    mode=http
    guest_root=$1
elif [[ $# == 2 ]]; then
    mode=$1
    guest_root=$2
else
    usage
fi
case "$mode" in
    http|inject|assert-drift|assert-repaired) ;;
    *) usage ;;
esac
[[ -d "$guest_root" && ! -L "$guest_root" ]] || { printf 'Guest fixture root is not a real directory.\n' >&2; exit 2; }
root=$(realpath -e -- "$guest_root")
case "$root" in
    /var/tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to drift a path outside the private guest temp root.\n' >&2; exit 2 ;;
esac
[[ -f "$root/.owner" && ! -L "$root/.owner" && "$(<"$root/.owner")" == dorothy-traefik-acceptance-guest-v1 ]] || {
    printf 'Guest fixture ownership marker is missing.\n' >&2
    exit 2
}
[[ $EUID == 0 ]] || { printf 'Drift injection requires root on the disposable guest.\n' >&2; exit 2; }
for command in awk chmod chown cmp cp jq mktemp mv realpath sha256sum stat; do
    command -v "$command" >/dev/null 2>&1 || { printf 'Required drift tool is unavailable: %s\n' "$command" >&2; exit 2; }
done

configuration=/etc/keroosha-iac/traefik/dynamic/current.yml
[[ -f "$configuration" && ! -L "$configuration" ]] || { printf 'Owned dynamic configuration file is missing or unsafe.\n' >&2; exit 1; }
http_backup="$root/dynamic-before-drift.yml"
http_hash="$root/dynamic-drift.sha256"
udp_backup="$root/dynamic-before-udp-drift.yml"
udp_hash="$root/dynamic-udp-drift.sha256"

fail() {
    printf 'acceptance drift failure: %s\n' "$1" >&2
    exit 1
}

digest() { sha256sum -- "$1" | awk '{ print $1 }'; }

inject() {
    local backup=$1 hash_file=$2 expression=$3 predicate=$4
    local metadata mode uid gid current_hash temporary

    if [[ -e "$backup" || -e "$hash_file" ]]; then
        [[ -f "$backup" && ! -L "$backup" ]] || fail 'drift backup path is not a regular file'
        if [[ -s "$hash_file" ]]; then
            current_hash=$(digest "$configuration")
            [[ "$current_hash" == "$(<"$hash_file")" ]] && return 0
            fail 'dynamic configuration changed after drift injection'
        fi
        if jq -e "$predicate" "$configuration" >/dev/null 2>&1; then
            digest "$configuration" > "$hash_file"
            chmod 600 "$hash_file"
            return 0
        fi
        cmp -s -- "$configuration" "$backup" || fail 'incomplete drift state does not match the saved original'
    else
        cp --preserve=mode,ownership,timestamps -- "$configuration" "$backup"
        chmod 600 "$backup"
    fi

    metadata=$(stat -c '%a %u %g' "$configuration")
    read -r mode uid gid <<< "$metadata"
    temporary=$(mktemp "${configuration}.acceptance.XXXXXX")
    if ! jq "$expression" "$configuration" > "$temporary"; then
        rm -f -- "$temporary"
        fail 'could not create the requested dynamic drift'
    fi
    if ! jq -e "$predicate" "$temporary" >/dev/null; then
        rm -f -- "$temporary"
        fail 'generated drift did not have the expected protocol-specific shape'
    fi
    chown "$uid:$gid" "$temporary"
    chmod "$mode" "$temporary"
    mv -f -- "$temporary" "$configuration"
    digest "$configuration" > "$hash_file"
    chmod 600 "$hash_file"
}

assert_injected() {
    local hash_file=$1 predicate=$2 expected_hash
    [[ -s "$hash_file" ]] || fail 'drift evidence hash is missing'
    expected_hash=$(<"$hash_file")
    [[ "$(digest "$configuration")" == "$expected_hash" ]] || fail 'Read/refresh changed the injected dynamic configuration'
    jq -e "$predicate" "$configuration" >/dev/null || fail 'protocol-specific drift is not active'
}

case "$mode" in
    http)
        inject "$http_backup" "$http_hash" \
            '.http.services.catalog.loadBalancer.servers[0].url = "http://127.0.0.1:1"' \
            '.http.services.catalog.loadBalancer.servers[0].url == "http://127.0.0.1:1"'
        printf 'HTTP catalog drift injected; saved original: %s\n' "$http_backup"
        ;;
    inject)
        inject "$udp_backup" "$udp_hash" \
            '.udp.services["drift-unreachable"] = {loadBalancer:{servers:[{address:"127.0.0.1:18099"}]}} | .udp.routers.echo.service = "drift-unreachable"' \
            '(.udp.routers.echo.service == "drift-unreachable") and (.udp.routers["echo-other"].service == "echo") and (.http.routers.catalog != null)'
        printf 'UDP echo now targets the unreachable fixture endpoint; echo-other and HTTP were left intact.\n'
        ;;
    assert-drift)
        assert_injected "$udp_hash" \
            '(.udp.routers.echo.service == "drift-unreachable") and (.udp.routers["echo-other"].service == "echo") and (.http.routers.catalog != null)'
        printf 'UDP echo route drift remains active after Read/refresh; echo-other is intact.\n'
        ;;
    assert-repaired)
        [[ -s "$udp_hash" ]] || fail 'UDP drift evidence hash is missing'
        [[ "$(digest "$configuration")" != "$(<"$udp_hash")" ]] || fail 'Pulumi Update did not repair the UDP route drift'
        jq -e '(.udp.routers.echo.service == "echo") and (.udp.routers["echo-other"].service == "echo") and (.udp.services.echo.loadBalancer.servers[0].address == "127.0.0.1:19002") and (.udp.services["drift-unreachable"] == null) and (.http.routers.catalog != null)' \
            "$configuration" >/dev/null || fail 'Pulumi Update did not restore both UDP echo routes and the HTTP control'
        printf 'UDP echo routes and HTTP control were restored by Update.\n'
        ;;
esac
