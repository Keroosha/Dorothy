#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ROOT_MARKER=dorothy-traefik-acceptance-guest-v1
readonly RESOLVER=review-acme
readonly HOST=mtls.acceptance.test
readonly STATE_DIR=/var/lib/keroosha-traefik
readonly STATIC_CONFIG=/etc/keroosha-iac/traefik/static.yml

usage() {
    printf 'Usage: review-tls.sh {snapshot|remove|incomplete|restore|assert-switch} /var/tmp/dorothy-traefik-acceptance.XXXXXXXX\n' >&2
    exit 2
}

fail() {
    printf 'TLS ACME review fixture failed: %s\n' "$1" >&2
    exit 1
}

[[ $# == 2 ]] || usage
mode=$1
case "$mode" in
    snapshot|remove|incomplete|restore|assert-switch) ;;
    *) usage ;;
esac
[[ $EUID == 0 ]] || fail 'must run as root on the disposable guest'
for command in awk chmod chown cp id install jq mktemp mv realpath rm sha256sum stat; do
    command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done

[[ -d "$2" && ! -L "$2" ]] || fail 'guest fixture root is not a real directory'
root=$(realpath -e -- "$2")
[[ "$root" =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ ]] \
    || fail 'refusing a path outside the disposable guest temp root'
[[ -f "$root/.owner" && ! -L "$root/.owner" && "$(<"$root/.owner")" == "$ROOT_MARKER" ]] \
    || fail 'guest fixture ownership marker is missing'

readonly FIXTURE=$root/review-tls
readonly SNAPSHOT=$FIXTURE/snapshot.json
readonly SAVED_STORE=$FIXTURE/original-acme.json

if [[ -e "$FIXTURE" || -L "$FIXTURE" ]]; then
    [[ -d "$FIXTURE" && ! -L "$FIXTURE" && "$(realpath -e -- "$FIXTURE")" == "$FIXTURE" ]] \
        || fail 'TLS review fixture directory is unsafe'
fi

fail_if_unsafe_file() {
    [[ -f "$1" && ! -L "$1" && "$(realpath -e -- "$1")" == "$1" ]] \
        || fail 'owned ACME review file is missing or unsafe'
}

digest() { sha256sum -- "$1" | awk '{ print $1 }'; }
metadata() { stat --format='%a:%u:%g' -- "$1"; }

traefik_uid=$(id -u keroosha-traefik 2>/dev/null) || fail 'Traefik service account is unavailable'
traefik_gid=$(id -g keroosha-traefik 2>/dev/null) || fail 'Traefik service group is unavailable'
readonly EXPECTED_METADATA="600:$traefik_uid:$traefik_gid"

active_storage_path() {
    fail_if_unsafe_file "$STATIC_CONFIG"
    local path
    path=$(jq --exit-status --raw-output --arg resolver "$RESOLVER" \
        '.certificatesResolvers[$resolver].acme.storage | select(type == "string" and length > 0)' \
        "$STATIC_CONFIG") || fail 'active resolver storage path is unavailable'
    [[ "$path" =~ ^/var/lib/keroosha-traefik/acme-[0-9a-f]{64}\.json$ ]] \
        || fail 'active resolver storage path is outside the owned ACME namespace'
    [[ "$(realpath -m -- "$path")" == "$path" ]] \
        || fail 'active resolver storage path is not canonical'
    printf '%s' "$path"
}

# Exercise the otherwise unprobed client-auth-only route with a dedicated, verified client.
# Return only the public leaf digest. The disposable CA, client key and account stay in guest.
wire_leaf() {
    local ca_port=$1 ca="$FIXTURE/issuer-$1.pem" body="$FIXTURE/wire.body"
    curl --fail --silent --show-error --noproxy '*' --max-time 6 --cacert "$root/certs/pebble.minica.pem" \
        "https://localhost:$ca_port/roots/0" -o "$ca" || return 1
    curl --fail --silent --show-error --noproxy '*' --max-time 6 --resolve "$HOST:18444:127.0.0.1" \
        --cert "$root/certs/client.pem" --key "$root/certs/client.key" --cacert "$ca" \
        "https://$HOST:18444/review-store" -o "$body" || return 1
    grep -Fq 'http-backend:/review-store;forwarded:' "$body" || return 1
    timeout 6 openssl s_client -servername "$HOST" -connect 127.0.0.1:18444 -showcerts \
        -cert "$root/certs/client.pem" -key "$root/certs/client.key" -CAfile "$ca" \
        -verify_hostname "$HOST" -verify_return_error </dev/null 2>/dev/null \
        | awk '/BEGIN CERTIFICATE/{n++} n==1{print} /END CERTIFICATE/ && n==1{n++}' \
        | openssl x509 -outform DER | sha256sum | awk '{print $1}'
}

assert_cached_leaf() {
    [[ $(systemctl show --property=MainPID --value keroosha-traefik.service) == "$(<"$FIXTURE/original.pid")" ]] \
        || fail 'the server restarted during the store-only mutation'
    [[ $(wire_leaf 15000) == "$(<"$FIXTURE/original-leaf.sha256")" ]] \
        || fail 'store-only mutation did not leave the same authenticated leaf serving on the wire'
}

load_snapshot() {
    fail_if_unsafe_file "$SNAPSHOT"
    local path hash saved_metadata
    path=$(jq --exit-status --raw-output '.storagePath | strings' "$SNAPSHOT") || fail 'ACME snapshot is invalid'
    hash=$(jq --exit-status --raw-output '.sha256 | strings' "$SNAPSHOT") || fail 'ACME snapshot is invalid'
    saved_metadata=$(jq --exit-status --raw-output '.metadata | strings' "$SNAPSHOT") || fail 'ACME snapshot is invalid'
    [[ "$path" =~ ^/var/lib/keroosha-traefik/acme-[0-9a-f]{64}\.json$ ]] \
        || fail 'ACME snapshot path is outside the owned namespace'
    [[ "$hash" =~ ^[0-9a-f]{64}$ && "$saved_metadata" =~ ^600:[0-9]+:[0-9]+$ ]] \
        || fail 'ACME snapshot metadata is invalid'
    printf '%s\n%s\n%s' "$path" "$hash" "$saved_metadata"
}

load_saved_snapshot() {
    local snapshot
    snapshot=$(load_snapshot) || fail 'cannot load ACME snapshot'
    mapfile -t saved <<< "$snapshot"
}

check_saved_store() {
    local path=$1 expected_hash=$2 expected_metadata=$3
    fail_if_unsafe_file "$path"
    [[ "$(metadata "$path")" == "$expected_metadata" ]] || fail 'ACME store permissions or ownership changed'
    [[ "$(digest "$path")" == "$expected_hash" ]] || fail 'ACME store bytes changed unexpectedly'
}

replace_store_from_snapshot() {
    local path=$1 expected_hash=$2 expected_metadata=$3 mode uid gid stage
    fail_if_unsafe_file "$SAVED_STORE"
    [[ "$(digest "$SAVED_STORE")" == "$expected_hash" ]] || fail 'saved ACME store bytes are invalid'
    if [[ -e "$path" || -L "$path" ]]; then fail_if_unsafe_file "$path"; fi
    IFS=: read -r mode uid gid <<< "$expected_metadata"
    stage=$(mktemp "${path%/*}/.review-tls.XXXXXXXX") || fail 'cannot stage ACME store restoration'
    cp -- "$SAVED_STORE" "$stage" || fail 'cannot copy saved ACME store'
    chown "$uid:$gid" "$stage" || fail 'cannot restore ACME store ownership'
    chmod "$mode" "$stage" || fail 'cannot restore ACME store permissions'
    [[ "$(metadata "$stage")" == "$expected_metadata" && "$(digest "$stage")" == "$expected_hash" ]] \
        || fail 'staged ACME store does not match the saved file'
    mv -fT -- "$stage" "$path" || fail 'cannot restore ACME store atomically'
    [[ "$(metadata "$path")" == "$expected_metadata" && "$(digest "$path")" == "$expected_hash" ]] \
        || fail 'restored ACME store does not match the saved file'
}

case "$mode" in
    snapshot)
        [[ ! -e "$SNAPSHOT" && ! -L "$SNAPSHOT" ]] || fail 'ACME snapshot already exists'
        install -d -m 700 -- "$FIXTURE"
        store=$(active_storage_path)
        fail_if_unsafe_file "$store"
        [[ "$(metadata "$store")" == "$EXPECTED_METADATA" ]] || fail 'ACME store permissions or ownership are unsafe'
        store_hash=$(digest "$store")
        wire_leaf 15000 > "$FIXTURE/original-leaf.sha256" || fail 'baseline authenticated TLS route failed'
        grep -Eq '^[0-9a-f]{64}$' "$FIXTURE/original-leaf.sha256" || fail 'baseline public leaf digest is invalid'
        systemctl show --property=MainPID --value keroosha-traefik.service > "$FIXTURE/original.pid"
        store_metadata=$(metadata "$store")
        cp --preserve=mode,ownership,timestamps -- "$store" "$SAVED_STORE" || fail 'cannot preserve original ACME store'
        chmod 600 "$SAVED_STORE"
        jq -n --arg resolver "$RESOLVER" --arg host "$HOST" --arg storage "$store" \
            --arg sha256 "$store_hash" --arg metadata "$store_metadata" \
            '{resolver:$resolver,host:$host,storagePath:$storage,sha256:$sha256,metadata:$metadata}' \
            > "$SNAPSHOT.tmp"
        chmod 600 "$SNAPSHOT.tmp"
        mv -fT -- "$SNAPSHOT.tmp" "$SNAPSHOT"
        printf 'review-tls snapshot:ok\n'
        ;;
    remove)
        load_saved_snapshot
        store=${saved[0]}; store_hash=${saved[1]}; store_metadata=${saved[2]}
        [[ "$(active_storage_path)" == "$store" ]] || fail 'active ACME resolver storage changed before removal'
        check_saved_store "$store" "$store_hash" "$store_metadata"
        rm -- "$store" || fail 'cannot remove ACME store'
        assert_cached_leaf
        printf 'review-tls missing-store:injected\n'
        ;;
    incomplete)
        load_saved_snapshot
        store=${saved[0]}; store_hash=${saved[1]}; store_metadata=${saved[2]}
        [[ "$(active_storage_path)" == "$store" ]] || fail 'active ACME resolver storage changed before corruption'
        check_saved_store "$store" "$store_hash" "$store_metadata"
        stage=$(mktemp "${store%/*}/.review-tls.XXXXXXXX") || fail 'cannot stage incomplete ACME store'
        jq --exit-status --arg resolver "$RESOLVER" --arg host "$HOST" '
            .[$resolver].Certificates as $certificates
            | if ($certificates | type) != "array" then error("invalid certificate list")
              elif ([ $certificates[] | select((.domain.main? == $host) or (((.domain.sans? // []) | index($host)) != null)) ] | length) != 1 then error("missing unique route certificate")
              else .[$resolver].Certificates |= map(
                  if ((.domain.main? == $host) or (((.domain.sans? // []) | index($host)) != null))
                  then .key = ""
                  else .
                  end)
              end
        ' "$store" > "$stage" || fail 'cannot produce an incomplete ACME store'
        IFS=: read -r mode uid gid <<< "$store_metadata"
        chown "$uid:$gid" "$stage" || fail 'cannot preserve incomplete ACME store ownership'
        chmod "$mode" "$stage" || fail 'cannot preserve incomplete ACME store permissions'
        mv -fT -- "$stage" "$store" || fail 'cannot install incomplete ACME store'
        [[ "$(metadata "$store")" == "$store_metadata" ]] || fail 'incomplete ACME store metadata changed'
        assert_cached_leaf
        printf 'review-tls incomplete-store:injected\n'
        ;;
    restore)
        load_saved_snapshot
        store=${saved[0]}; store_hash=${saved[1]}; store_metadata=${saved[2]}
        [[ "$(active_storage_path)" == "$store" ]] || fail 'active ACME resolver storage changed before restoration'
        replace_store_from_snapshot "$store" "$store_hash" "$store_metadata"
        printf 'review-tls restore:ok\n'
        ;;
    assert-switch)
        load_saved_snapshot
        old_store=${saved[0]}; store_hash=${saved[1]}; store_metadata=${saved[2]}
        new_store=$(active_storage_path)
        [[ "$new_store" != "$old_store" ]] || fail 'same-name issuer switch reused the historical storage path'
        check_saved_store "$old_store" "$store_hash" "$store_metadata"
        fail_if_unsafe_file "$new_store"
        [[ "$(metadata "$new_store")" == "$EXPECTED_METADATA" ]] || fail 'new issuer store permissions or ownership are unsafe'
        switched_leaf=$(wire_leaf 15001) || fail 'switched same-name resolver did not serve a leaf verified by the second issuer'
        [[ "$switched_leaf" =~ ^[a-f0-9]{64}$ && "$switched_leaf" != "$(<"$FIXTURE/original-leaf.sha256")" ]] \
            || fail 'same-name issuer switch did not change the authenticated on-wire leaf'
        printf 'review-tls issuer-switch:isolated\n'
        ;;
esac
