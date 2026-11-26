#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly HOST=sni-proof.acceptance.test
readonly ADDRESS=127.0.0.2
readonly PORT=18449
readonly DYNAMIC_CONFIG=/etc/keroosha-iac/traefik/dynamic/current.yml
readonly CERT_DIR=/etc/keroosha-iac/traefik/dynamic/certificates
readonly UNIT=keroosha-traefik.service
readonly UNIT_PATH=/etc/systemd/system/keroosha-traefik.service
readonly ROOT_MARKER=dorothy-traefik-acceptance-guest-v1
readonly FIXTURE_MARKER=dorothy-traefik-sni-drift-v1

usage() {
    printf 'Usage: sni-drift.sh {prepare|inject|assert-drift|assert-positive|restore} /var/tmp/dorothy-traefik-acceptance.XXXXXXXX\n' >&2
    exit 2
}

fail() {
    printf 'SNI drift acceptance failed: %s\n' "$1" >&2
    exit 1
}

[[ $# == 2 ]] || usage
mode=$1
case "$mode" in
    prepare|inject|assert-drift|assert-positive|restore) ;;
    *) usage ;;
esac
[[ $EUID == 0 ]] || fail 'must run as root on the disposable guest'
for command in awk chmod chown cmp cp curl jq mktemp mv openssl realpath rm sha256sum stat systemctl timeout; do
    command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done

[[ -d "$2" && ! -L "$2" ]] || fail 'guest fixture root is not a real directory'
root=$(realpath -e -- "$2")
[[ "$root" =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ ]] \
    || fail 'refusing a path outside the disposable guest temp root'
[[ -f "$root/.owner" && ! -L "$root/.owner" && "$(<"$root/.owner")" == "$ROOT_MARKER" ]] \
    || fail 'guest fixture ownership marker is missing'

readonly FIXTURE=$root/sni-drift
readonly STATE=$FIXTURE/state.json
readonly EXPECTED_CERT=$FIXTURE/desired.crt
readonly EXPECTED_KEY=$FIXTURE/desired.key
readonly REPLACEMENT_CERT=$FIXTURE/replacement.crt
readonly REPLACEMENT_KEY=$FIXTURE/replacement.key

cert_path=
key_path=
cert_meta=
key_meta=
cert_sha=
key_sha=
leaf_sha=
replacement_sha=
config_sha=
phase=
stage=
recover=0
partial_fixture=0

digest() { sha256sum -- "$1" | awk '{ print $1 }'; }
metadata() { stat --format='%a:%u:%g' -- "$1"; }

safe_file() {
    [[ -f "$1" && ! -L "$1" && "$(realpath -e -- "$1")" == "$1" ]]
}

exact_san() {
    local extensions
    extensions=$(openssl x509 -in "$1" -noout -ext subjectAltName 2>/dev/null) || return 1
    printf '%s\n' "$extensions" | awk -v wanted="DNS:$HOST" '
        function check(line, fields, count, i, field) {
            count = split(line, fields, ",")
            for (i = 1; i <= count; i++) {
                field = fields[i]
                gsub(/^[[:space:]]+|[[:space:]]+$/, "", field)
                if (field == wanted) found = 1
            }
        }
        /Subject Alternative Name:/ {
            line = $0
            sub(/^.*Subject Alternative Name:[[:space:]]*/, "", line)
            if (line != $0) check(line)
            next
        }
        { check($0) }
        END { exit !found }
    '
}

check_pair() {
    local public_cert public_key
    openssl x509 -in "$1" -checkend 0 -noout >/dev/null 2>&1 \
        || fail 'TLS leaf is expired or malformed'
    openssl x509 -in "$1" -checkhost "$HOST" -noout >/dev/null 2>&1 \
        && exact_san "$1" || fail 'TLS leaf lacks the exact proof-host SAN'
    public_cert=$(openssl x509 -in "$1" -pubkey -noout 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null | sha256sum | awk '{print $1}') \
        || fail 'TLS leaf public key cannot be read'
    public_key=$(openssl pkey -in "$2" -pubout -outform DER 2>/dev/null \
        | sha256sum | awk '{print $1}') || fail 'TLS private key cannot be read'
    [[ "$public_cert" == "$public_key" ]] || fail 'TLS leaf and private key do not match'
}

find_pair() {
    local entries line certificate key host_matches=0 exact_matches=0
    local -a pairs=()
    safe_file "$DYNAMIC_CONFIG" || fail 'owned dynamic configuration is missing or unsafe'
    [[ -d "$CERT_DIR" && ! -L "$CERT_DIR" && "$(realpath -e -- "$CERT_DIR")" == "$CERT_DIR" ]] \
        || fail 'managed certificate directory is missing or unsafe'
    jq -e --arg host "$HOST" '
        (.http.routers["sni-proof"] // null) as $router
        | ($router != null)
          and ($router.rule == ("Host(\"" + $host + "\")"))
          and ($router.entryPoints == ["sni-proof"])
          and (($router.tls | type) == "object")
          and (($router.tls | has("certResolver")) | not)
          and ([.http.routers | to_entries[]?
                | select((.value.rule // "") | contains("Host(\"" + $host + "\")"))
                | .key] == ["sni-proof"])
    ' "$DYNAMIC_CONFIG" >/dev/null 2>&1 \
        || fail 'dynamic configuration does not contain the dedicated provided-certificate router'
    entries=$(jq -er '
        .tls.certificates | select(type == "array" and length > 0)
        | .[] | [.certFile, .keyFile] | @tsv
    ' "$DYNAMIC_CONFIG" 2>/dev/null) || fail 'dynamic TLS certificate list is absent or malformed'

    while IFS= read -r line; do
        IFS=$'\t' read -r certificate key <<< "$line"
        [[ "$certificate" =~ ^/etc/keroosha-iac/traefik/dynamic/certificates/[0-9a-f]{64}\.crt$ ]] \
            && [[ "$key" == "${certificate%.crt}.key" ]] \
            || fail 'dynamic TLS paths are outside the helper-managed certificate pair'
        safe_file "$certificate" && safe_file "$key" || fail 'managed TLS pair is missing or unsafe'
        for pair in "${pairs[@]}"; do
            [[ "$pair" != "$certificate:$key" ]] || fail 'dynamic TLS list contains a duplicate pair'
        done
        pairs+=("$certificate:$key")
        if openssl x509 -in "$certificate" -checkhost "$HOST" -noout >/dev/null 2>&1; then
            ((host_matches += 1))
            if exact_san "$certificate"; then
                ((exact_matches += 1))
                cert_path=$certificate
                key_path=$key
            fi
        fi
    done <<< "$entries"
    [[ $host_matches == 1 && $exact_matches == 1 ]] \
        || fail 'proof host does not identify exactly one managed leaf by SAN'
    check_pair "$cert_path" "$key_path"
}

load_state() {
    [[ -d "$FIXTURE" && ! -L "$FIXTURE" && "$(stat -c '%a:%u' "$FIXTURE")" == 700:0 ]] \
        || fail 'private SNI fixture directory is missing or unsafe'
    [[ -f "$FIXTURE/.owner" && ! -L "$FIXTURE/.owner" \
        && "$(<"$FIXTURE/.owner")" == "$FIXTURE_MARKER" \
        && "$(stat -c '%a:%u' "$FIXTURE/.owner")" == 600:0 ]] \
        || fail 'private SNI fixture marker is missing or unsafe'
    [[ -f "$STATE" && ! -L "$STATE" && "$(stat -c '%a:%u' "$STATE")" == 600:0 ]] \
        || fail 'private SNI state is missing or unsafe'
    jq -e '
        .schema == 1
        and (.phase == "prepared" or .phase == "injected" or .phase == "restored")
        and (.certificatePath | type == "string" and test("^/etc/keroosha-iac/traefik/dynamic/certificates/[0-9a-f]{64}\\.crt$"))
        and (.keyPath | type == "string" and test("^/etc/keroosha-iac/traefik/dynamic/certificates/[0-9a-f]{64}\\.key$"))
        and (.certificateMeta | type == "string" and test("^[0-7]{3,4}:[0-9]+:[0-9]+$"))
        and (.keyMeta | type == "string" and test("^[0-7]{3,4}:[0-9]+:[0-9]+$"))
        and (.certificateSha256 | type == "string" and test("^[0-9a-f]{64}$"))
        and (.keySha256 | type == "string" and test("^[0-9a-f]{64}$"))
        and (.leafSha256 | type == "string" and test("^[0-9a-f]{64}$"))
        and (.replacementSha256 | type == "string" and test("^[0-9a-f]{64}$"))
        and (.dynamicConfigSha256 | type == "string" and test("^[0-9a-f]{64}$"))
    ' "$STATE" >/dev/null 2>&1 || fail 'private SNI state is malformed'
    cert_path=$(jq -r '.certificatePath' "$STATE")
    key_path=$(jq -r '.keyPath' "$STATE")
    cert_meta=$(jq -r '.certificateMeta' "$STATE")
    key_meta=$(jq -r '.keyMeta' "$STATE")
    cert_sha=$(jq -r '.certificateSha256' "$STATE")
    key_sha=$(jq -r '.keySha256' "$STATE")
    leaf_sha=$(jq -r '.leafSha256' "$STATE")
    replacement_sha=$(jq -r '.replacementSha256' "$STATE")
    config_sha=$(jq -r '.dynamicConfigSha256' "$STATE")
    phase=$(jq -r '.phase' "$STATE")
    [[ "$key_path" == "${cert_path%.crt}.key" ]] || fail 'private SNI state has an unsafe file pair'
    safe_file "$cert_path" && safe_file "$key_path" || fail 'saved managed TLS files are missing or unsafe'
    for file in "$EXPECTED_CERT" "$EXPECTED_KEY" "$REPLACEMENT_CERT" "$REPLACEMENT_KEY"; do
        [[ -f "$file" && ! -L "$file" ]] || fail 'private SNI fixture material is incomplete'
    done
}

check_config_unchanged() {
    find_pair
    [[ "$cert_path" == "$(jq -r '.certificatePath' "$STATE")" \
        && "$key_path" == "$(jq -r '.keyPath' "$STATE")" \
        && "$(digest "$DYNAMIC_CONFIG")" == "$config_sha" ]] \
        || fail 'dynamic configuration changed during the SNI drift scenario'
}

assert_desired_files() {
    [[ "$(digest "$cert_path")" == "$cert_sha" && "$(metadata "$cert_path")" == "$cert_meta" \
        && "$(digest "$key_path")" == "$key_sha" && "$(metadata "$key_path")" == "$key_meta" ]] \
        || fail 'desired TLS file hashes or ownership/permissions changed'
    cmp -s -- "$cert_path" "$EXPECTED_CERT" && cmp -s -- "$key_path" "$EXPECTED_KEY" \
        || fail 'managed TLS files do not match their exact saved material'
}

service_active() {
    local fragment
    fragment=$(systemctl show --property=FragmentPath --value "$UNIT" 2>/dev/null) || return 1
    [[ "$fragment" == "$UNIT_PATH" ]] && systemctl is-active --quiet "$UNIT"
}

wire_leaf() {
    local pem="$FIXTURE/wire.pem" der="$FIXTURE/wire.der"
    rm -f -- "$pem" "$der"
    timeout --foreground --kill-after=1 5 \
        openssl s_client -connect "$ADDRESS:$PORT" -servername "$HOST" -showcerts \
        </dev/null > "$pem" 2> "$FIXTURE/s_client.log" || return 1
    openssl x509 -inform PEM -in "$pem" -outform DER -out "$der" 2>/dev/null || return 1
    chmod 600 "$pem" "$der" "$FIXTURE/s_client.log"
    digest "$der"
}

router_healthy() {
    local status
    status=$(timeout --foreground --kill-after=1 8 curl --silent --show-error --insecure \
        --connect-timeout 2 --max-time 5 --resolve "$HOST:$PORT:$ADDRESS" \
        --output /dev/null --write-out '%{http_code}' "https://$HOST:$PORT/sni-proof" \
        2> "$FIXTURE/curl.log") || return 1
    chmod 600 "$FIXTURE/curl.log"
    [[ "$status" =~ ^[23][0-9][0-9]$ ]]
}

probe() {
    local expected=$1 actual
    actual=$(wire_leaf) || fail 'SNI TLS handshake did not complete'
    [[ "$actual" == "$expected" ]] || fail 'SNI wire leaf fingerprint did not match the expected certificate'
    router_healthy || fail 'dedicated SNI router did not return a healthy HTTP status'
    printf '%s' "$actual"
}

replace_file() {
    local source=$1 target=$2 file_meta=$3 preserve=$4 mode uid gid
    IFS=: read -r mode uid gid <<< "$file_meta"
    stage=$(mktemp "${target%/*}/.sni-drift.XXXXXXXX") || fail 'cannot stage a protected TLS file'
    if [[ "$preserve" == true ]]; then
        cp --preserve=mode,ownership,timestamps -- "$source" "$stage" || fail 'cannot stage saved TLS material'
    else
        cp -- "$source" "$stage" || fail 'cannot stage replacement TLS material'
        chown "$uid:$gid" "$stage"
        chmod "$mode" "$stage"
    fi
    [[ "$(metadata "$stage")" == "$mode:$uid:$gid" ]] || fail 'staged TLS metadata does not match'
    mv -fT -- "$stage" "$target" || fail 'cannot replace protected TLS material'
    stage=
    [[ "$(metadata "$target")" == "$mode:$uid:$gid" ]] || fail 'installed TLS metadata does not match'
}

restore_files() {
    safe_file "$cert_path" && safe_file "$key_path" || fail 'refusing to restore outside the saved managed TLS pair'
    if [[ "$(digest "$cert_path")" != "$cert_sha" || "$(metadata "$cert_path")" != "$cert_meta" ]]; then
        replace_file "$EXPECTED_CERT" "$cert_path" "$cert_meta" true
    fi
    if [[ "$(digest "$key_path")" != "$key_sha" || "$(metadata "$key_path")" != "$key_meta" ]]; then
        replace_file "$EXPECTED_KEY" "$key_path" "$key_meta" true
    fi
    assert_desired_files
}

save_state() {
    local next_phase=$1 temp
    temp=$(mktemp "$FIXTURE/.state.XXXXXXXX")
    jq --arg phase "$next_phase" '.phase = $phase' "$STATE" > "$temp"
    chmod 600 "$temp"
    mv -fT -- "$temp" "$STATE"
}

restart_service() {
    service_active || [[ "$(systemctl show --property=FragmentPath --value "$UNIT" 2>/dev/null || true)" == "$UNIT_PATH" ]] \
        || fail 'refusing to restart a non-owned service'
    timeout --foreground --kill-after=2 30 systemctl restart "$UNIT" > "$FIXTURE/restart.log" 2>&1 \
        || fail 'owned Traefik service restart failed'
    chmod 600 "$FIXTURE/restart.log"
    for _ in {1..20}; do
        service_active && return 0
        sleep 1
    done
    fail 'owned Traefik service did not return'
}

recover_on_error() {
    local actual
    restore_files || return 1
    restart_service || return 1
    actual=$(wire_leaf) || return 1
    [[ "$actual" == "$leaf_sha" ]] && router_healthy
}


on_exit() {
    local status=$?
    trap - EXIT HUP INT TERM
    rm -f -- "$stage" 2>/dev/null || true
    if (( status != 0 )) && (( recover )); then
        printf 'SNI scenario failed; restoring the saved files and owned service.\n' >&2
        if (recover_on_error); then
            printf 'Emergency restoration returned the desired leaf to the wire.\n' >&2
        else
            printf 'Emergency restoration failed; the disposable guest needs manual recovery.\n' >&2
        fi
    elif (( status != 0 )) && (( partial_fixture )); then
        if [[ -f "$FIXTURE/.owner" && "$(<"$FIXTURE/.owner")" == "$FIXTURE_MARKER" ]]; then
            rm -rf -- "$FIXTURE"
        fi
    fi
    exit "$status"
}
trap on_exit EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP

prepare() {
    [[ ! -e "$FIXTURE" && ! -L "$FIXTURE" ]] || fail 'private SNI fixture already exists'
    mkdir -m 700 -- "$FIXTURE"
    partial_fixture=1
    printf '%s\n' "$FIXTURE_MARKER" > "$FIXTURE/.owner"
    chmod 600 "$FIXTURE/.owner"
    find_pair
    cert_meta=$(metadata "$cert_path")
    key_meta=$(metadata "$key_path")
    cp --preserve=mode,ownership,timestamps -- "$cert_path" "$EXPECTED_CERT"
    cp --preserve=mode,ownership,timestamps -- "$key_path" "$EXPECTED_KEY"
    cert_sha=$(digest "$EXPECTED_CERT")
    key_sha=$(digest "$EXPECTED_KEY")
    leaf_sha=$(openssl x509 -in "$EXPECTED_CERT" -outform DER 2>/dev/null | sha256sum | awk '{print $1}') \
        || fail 'cannot fingerprint desired TLS leaf'
    openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes -sha256 -days 2 \
        -keyout "$REPLACEMENT_KEY" -out "$REPLACEMENT_CERT" -subj "/CN=$HOST" \
        -addext 'basicConstraints=critical,CA:FALSE' \
        -addext 'keyUsage=critical,digitalSignature,keyEncipherment' \
        -addext 'extendedKeyUsage=serverAuth' -addext "subjectAltName=DNS:$HOST" \
        > "$FIXTURE/openssl-req.log" 2>&1 || fail 'cannot generate replacement TLS leaf'
    chmod 600 "$REPLACEMENT_KEY" "$FIXTURE/openssl-req.log"
    check_pair "$REPLACEMENT_CERT" "$REPLACEMENT_KEY"
    replacement_sha=$(openssl x509 -in "$REPLACEMENT_CERT" -outform DER 2>/dev/null | sha256sum | awk '{print $1}') \
        || fail 'cannot fingerprint replacement TLS leaf'
    [[ "$replacement_sha" != "$leaf_sha" && "$key_sha" != "$(digest "$REPLACEMENT_KEY")" ]] \
        || fail 'replacement TLS pair is not distinct'
    config_sha=$(digest "$DYNAMIC_CONFIG")
    jq -n --arg certificatePath "$cert_path" --arg keyPath "$key_path" \
        --arg certificateMeta "$cert_meta" --arg keyMeta "$key_meta" \
        --arg certificateSha256 "$cert_sha" --arg keySha256 "$key_sha" \
        --arg leafSha256 "$leaf_sha" --arg replacementSha256 "$replacement_sha" \
        --arg dynamicConfigSha256 "$config_sha" \
        '{schema:1,phase:"prepared",certificatePath:$certificatePath,keyPath:$keyPath,
          certificateMeta:$certificateMeta,keyMeta:$keyMeta,certificateSha256:$certificateSha256,
          keySha256:$keySha256,leafSha256:$leafSha256,replacementSha256:$replacementSha256,
          dynamicConfigSha256:$dynamicConfigSha256}' > "$STATE"
    chmod 600 "$STATE"
    load_state
    check_config_unchanged
    assert_desired_files
    local actual
    service_active || fail 'owned Traefik service is not active'
    actual=$(probe "$leaf_sha")
    partial_fixture=0
    printf 'SNI positive control passed: desired leaf %s is served by the healthy router.\n' "$actual"
}

inject() {
    load_state
    [[ "$phase" == prepared ]] || fail 'SNI injection requires a prepared fixture'
    check_config_unchanged
    assert_desired_files
    service_active || fail 'owned Traefik service is not active'
    probe "$leaf_sha" >/dev/null
    recover=1
    replace_file "$REPLACEMENT_CERT" "$cert_path" "$cert_meta" false
    replace_file "$REPLACEMENT_KEY" "$key_path" "$key_meta" false
    restart_service
    local actual= attempt
    local deadline=$((SECONDS + 20))
    while (( SECONDS < deadline )); do
        if actual=$(wire_leaf) && [[ "$actual" == "$replacement_sha" ]]; then break; fi
        sleep 1
    done
    [[ "$actual" == "$replacement_sha" ]] || fail 'Traefik did not serve the substituted leaf after restart'
    router_healthy || fail 'proof router became unhealthy with the replacement leaf'
    restore_files
    for attempt in 1 2 3; do
        actual=$(wire_leaf) || fail 'SNI handshake failed after restoring desired files'
        [[ "$actual" == "$replacement_sha" ]] || fail 'wire certificate changed when desired files were restored'
        router_healthy || fail 'proof router became unhealthy after restoring desired files'
        (( attempt == 3 )) || sleep 1
    done
    save_state injected
    recover=0
    printf 'SNI drift injected: desired hashes and ownership are restored on disk; replacement leaf %s remains on the wire.\n' "$actual"
}
assert_drift() {
    load_state
    recover=1
    [[ "$phase" == injected ]] || fail 'drift assertion requires a completed injection'
    check_config_unchanged
    assert_desired_files
    service_active || fail 'owned Traefik service is not active after refresh'
    local actual
    actual=$(probe "$replacement_sha")
    recover=0
    printf 'SNI drift survived Read/refresh: desired files match on disk; healthy router serves %s instead of %s.\n' \
        "$actual" "$leaf_sha"
}
assert_positive() {
    load_state
    recover=1
    find_pair
    [[ "$cert_path" == "$(jq -r '.certificatePath' "$STATE")" \
        && "$key_path" == "$(jq -r '.keyPath' "$STATE")" ]] \
        || fail 'repaired configuration no longer references the saved proof certificate'
    assert_desired_files
    service_active || fail 'owned Traefik service is not active after repair'
    local actual
    actual=$(probe "$leaf_sha")
    save_state restored
    recover=0
    printf 'SNI positive control passed after repair: desired leaf %s is served by the healthy router.\n' "$actual"
}


restore() {
    load_state
    recover=1
    restore_files
    local actual
    if ! service_active; then
        restart_service
    else
        actual=$(wire_leaf 2>/dev/null || true)
        if [[ "$actual" != "$leaf_sha" ]] || ! router_healthy; then
            restart_service
        fi
    fi
    actual=$(probe "$leaf_sha")
    save_state restored
    recover=0
    printf 'Emergency restoration passed: exact desired files and leaf %s are restored.\n' "$actual"
}

case "$mode" in
    prepare) prepare ;;
    inject) inject ;;
    assert-drift) assert_drift ;;
    assert-positive) assert_positive ;;
    restore) restore ;;
esac
