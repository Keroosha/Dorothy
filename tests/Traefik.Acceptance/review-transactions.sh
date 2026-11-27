#!/usr/bin/env bash
set -euo pipefail
umask 077

usage() {
    printf 'Usage: review-transactions.sh MODE /var/tmp/dorothy-traefik-acceptance.XXXXXXXX [old-pid old-sha256 new-sha256]\n' >&2
    exit 2
}

[[ $# -ge 2 ]] || usage
mode=$1
guest_root=$2
shift 2
case "$mode" in
    healthy-disk-inject|healthy-disk-refused|healthy-disk-reconcile) [[ $# == 0 ]] || usage ;;
    udp-drift-inject|udp-live-witness|udp-withdrawn-witness|binary-stage-inject|binary-stage-assert-clean|unverified-drift-inject|unverified-rollback-assert|unverified-repair-assert|restart-interrupt-install|restart-interrupt-remove|restart-interrupt-downgrade-v2) [[ $# == 0 ]] || usage ;;
    restart-interrupt-assert-staged) [[ $# == 3 ]] || usage ;;
    restart-interrupt-assert-restarted) [[ $# == 2 ]] || usage ;;
    restart-interrupt-assert-static-staged|restart-interrupt-assert-static-restarted) [[ $# == 2 ]] || usage ;;
    *) usage ;;
esac
[[ -d "$guest_root" && ! -L "$guest_root" ]] || { printf 'Guest fixture root is not a real directory.\n' >&2; exit 2; }
root=$(realpath -e -- "$guest_root")
case "$root" in
    /var/tmp/dorothy-traefik-acceptance.*) ;;
    *) printf 'Refusing to operate outside the private guest temp root.\n' >&2; exit 2 ;;
esac
[[ -f "$root/.owner" && ! -L "$root/.owner" && "$(<"$root/.owner")" == dorothy-traefik-acceptance-guest-v1 ]] || {
    printf 'Guest fixture ownership marker is missing.\n' >&2
    exit 2
}
[[ $EUID == 0 ]] || { printf 'Transaction acceptance cases require root on the disposable guest.\n' >&2; exit 2; }

for command in awk cat chmod chown cmp cp curl grep install jq mktemp mv perl realpath seq sha256sum sleep stat systemctl tcpdump timeout tr; do
    command -v "$command" >/dev/null 2>&1 || { printf 'Required transaction acceptance tool is unavailable: %s\n' "$command" >&2; exit 2; }
done

fail() {
    printf 'transaction acceptance failure: %s\n' "$1" >&2
    exit 1
}

config_dir=/etc/keroosha-iac/traefik
dynamic_file="$config_dir/dynamic/current.yml"
static_file="$config_dir/static.yml"
credentials_file="$config_dir/dns-credentials.env"
unit_file=/etc/systemd/system/keroosha-traefik.service
journal_file="$config_dir/.keroosha-rollback.json"
owner_marker="$config_dir/.keroosha-owner"
install_dir=/usr/local/libexec/keroosha-iac/traefik
binary_dir="$install_dir/3.7.16"
binary_file="$binary_dir/traefik"

verify_owned_service() {
    [[ -d "$config_dir" && ! -L "$config_dir" ]] || fail 'managed configuration directory is missing or unsafe'
    [[ -f "$owner_marker" && ! -L "$owner_marker" ]] || fail 'managed configuration owner marker is missing or unsafe'
    local owner
    owner=$(<"$owner_marker")
    [[ "$owner" =~ ^[a-f0-9]{64}$ ]] || fail 'managed configuration owner marker is malformed'
    [[ -f "$unit_file" && ! -L "$unit_file" ]] || fail 'managed systemd unit is missing or unsafe'
    grep -Fxq "# keroosha-owner=$owner" "$unit_file" || fail 'systemd unit owner does not match the configuration owner'
    [[ -f "$dynamic_file" && ! -L "$dynamic_file" ]] || fail 'managed dynamic configuration is missing or unsafe'
    printf '%s\n' "$owner"
}

digest_file() { sha256sum -- "$1" | awk '{ print $1 }'; }

main_pid() {
    local pid
    pid=$(systemctl show keroosha-traefik.service --property=MainPID --value)
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || fail 'Traefik does not have a live main process'
    printf '%s\n' "$pid"
}
binary_stage_inject() {
    local owner install_owner token filename stage
    owner=$(verify_owned_service)
    [[ -d "$install_dir" && ! -L "$install_dir" && -f "$install_dir/.keroosha-owner" && ! -L "$install_dir/.keroosha-owner" ]] \
        || fail 'managed Traefik installation owner marker is missing or unsafe'
    install_owner=$(<"$install_dir/.keroosha-owner")
    [[ "$install_owner" == "$owner" ]] || fail 'installation owner does not match the managed service owner'
    [[ -d "$binary_dir" && ! -L "$binary_dir" && -f "$binary_file" && ! -L "$binary_file" ]] \
        || fail 'pinned Traefik binary directory is missing or unsafe'
    token=$(printf '%s-%s-%s' "$$" "$RANDOM" "$RANDOM" | sha256sum | awk '{ print $1 }')
    filename=".traefik-install-${token:0:32}"
    stage="$binary_dir/$filename"
    [[ ! -e "$stage" && ! -L "$stage" ]] || fail 'generated binary staging path already exists'
    printf 'incomplete disposable staging file\n' > "$stage"
    chown root:root "$stage"
    chmod 700 "$stage"
    printf '%s\n' "$filename" > "$root/logs/binary-stage-file"
    chmod 600 "$root/logs/binary-stage-file"
    jq -n --arg case "owned-binary-stage-injected" --arg filename "$filename" --argjson ownerDigestMatched true \
        '{case:$case,filename:$filename,ownerDigestMatched:$ownerDigestMatched}' \
        > "$root/logs/review-transactions-binary-stage-injected.json"
    chmod 600 "$root/logs/review-transactions-binary-stage-injected.json"
}

binary_stage_assert_clean() {
    local owner install_owner filename stage
    local -a staging_files=()
    owner=$(verify_owned_service)
    install_owner=$(<"$install_dir/.keroosha-owner")
    [[ "$install_owner" == "$owner" ]] || fail 'installation owner changed while repairing the staging file'
    [[ -f "$root/logs/binary-stage-file" && ! -L "$root/logs/binary-stage-file" ]] || fail 'staging filename evidence is missing'
    filename=$(<"$root/logs/binary-stage-file")
    [[ "$filename" =~ ^\.traefik-install-[a-f0-9]{32}$ ]] || fail 'staging filename evidence is malformed'
    stage="$binary_dir/$filename"
    [[ ! -e "$stage" && ! -L "$stage" ]] || fail 'Apply left the stale owner-matched binary staging file behind'
    shopt -s nullglob
    staging_files=("$binary_dir"/.traefik-install-*)
    shopt -u nullglob
    ((${#staging_files[@]} == 0)) || fail 'Apply left a Traefik binary staging file in the pinned directory'
    jq -n --arg case "owned-binary-stage-removed" --arg filename "$filename" --argjson removed true --argjson ownerDigestMatched true \
        '{case:$case,filename:$filename,removed:$removed,ownerDigestMatched:$ownerDigestMatched}' \
        > "$root/logs/review-transactions-binary-stage-clean.json"
    chmod 600 "$root/logs/review-transactions-binary-stage-clean.json"
}


assert_http_control() {
    local body="$root/logs/review-transactions-http.body" status
    status=$(curl --noproxy '*' --silent --show-error --connect-timeout 2 --max-time 5 \
        --resolve shop.acceptance.test:18081:127.0.0.1 \
        --output "$body" --write-out '%{http_code}' \
        'http://shop.acceptance.test:18081/items/transactions-control') \
        || fail 'HTTP positive control request failed'
    [[ "$status" == 200 ]] || fail "HTTP positive control returned status $status"
    grep -Fq 'http-backend:/items/transactions-control' "$body" \
        || fail 'HTTP positive control reached the wrong backend'
}

capture_pid=''
stop_capture() {
    local status=0
    if [[ -n "$capture_pid" ]]; then
        kill -INT "$capture_pid" 2>/dev/null || true
        if wait "$capture_pid"; then :; else status=$?; fi
        capture_pid=''
    fi
    return "$status"
}
trap 'stop_capture || true' EXIT

start_capture() {
    local capture_file=$1 started=false
    tcpdump --immediate-mode -nn -l -A -s 0 -i lo 'udp and (dst port 19000 or dst port 19002 or dst port 19003)' \
        > "$capture_file" 2>&1 &
    capture_pid=$!
    for _ in $(seq 1 20); do
        if grep -Fq 'listening on lo' "$capture_file"; then
            started=true
            break
        fi
        if ! kill -0 "$capture_pid" 2>/dev/null; then break; fi
        sleep 0.05
    done
    [[ "$started" == true ]] || { stop_capture || true; fail 'bounded UDP capture did not start'; }
}

capture_has_payload_at() {
    local capture_file=$1 port=$2 payload=$3
    awk -v destination="> 127.0.0.1.$port:" -v needle="$payload" '
        / > / { current = index($0, destination) > 0; next }
        current && index($0, needle) { found = 1 }
        END { exit !found }
    ' "$capture_file"
}

udp_client_request() {
    local local_address=$1 port=$2 payload=$3 response_file=$4 error_file=$5
    timeout 2 perl -MIO::Socket::INET -e '
        use strict;
        use warnings;
        my ($local_address, $port, $payload) = @ARGV;
        my $socket = IO::Socket::INET->new(
            PeerAddr => "127.0.0.1",
            PeerPort => $port,
            LocalAddr => $local_address,
            Proto => "udp",
            Timeout => 1,
        ) or die "UDP socket: $!";
        defined($socket->send($payload)) or die "UDP send: $!";
        my $readable = "";
        vec($readable, fileno($socket), 1) = 1;
        exit 3 unless select($readable, undef, undef, 0.75);
        my $reply = "";
        defined($socket->recv($reply, 4096, 0)) or die "UDP receive: $!";
        print $reply;
    ' "$local_address" "$port" "$payload" > "$response_file" 2> "$error_file"
}

probe_udp() {
    local label=$1 port=$2 local_address=$3 expect_reply=$4 expect_backend=$5
    local payload="review-${label}-${RANDOM}-${RANDOM}-$$"
    local capture_file="$root/logs/review-${label}.tcpdump"
    local response_file="$root/logs/review-${label}.response"
    local request_status=0
    start_capture "$capture_file"
    if udp_client_request "$local_address" "$port" "$payload" "$response_file" "$root/logs/review-${label}.error"; then
        request_status=0
    else
        request_status=$?
    fi
    sleep 0.2
    stop_capture || fail 'bounded UDP capture did not stop cleanly'
    capture_has_payload_at "$capture_file" "$port" "$payload" || fail "UDP capture missed ingress nonce on :$port"
    if [[ "$expect_backend" == true ]]; then
        capture_has_payload_at "$capture_file" 19002 "$payload" || fail "positive UDP witness missed backend :19002 for $label"
    elif capture_has_payload_at "$capture_file" 19002 "$payload"; then
        fail "withdrawn UDP nonce reached old backend :19002 ($label)"
    fi
    if [[ "$expect_reply" == true ]]; then
        [[ "$request_status" == 0 && "$(<"$response_file")" == "$payload" ]] \
            || fail "positive UDP witness did not echo the complete fresh payload ($label)"
    else
        [[ "$request_status" != 0 && ! -s "$response_file" ]] \
            || fail "withdrawn UDP listener returned a response to a fresh peer ($label)"
    fi
}

udp_drift_inject() {
    local owner metadata mode uid gid temporary
    owner=$(verify_owned_service)
    jq -e '(.udp.routers.echo.entryPoints == ["udp"]) and (.udp.routers["echo-other"].entryPoints == ["udp-other"]) and (.udp.services.echo.loadBalancer.servers[0].address == "127.0.0.1:19002")' \
        "$dynamic_file" >/dev/null || fail 'prior UDP graph does not contain the accepted echo and surviving control routers'
    [[ ! -e "$root/udp-withdrawal-before.yml" && ! -L "$root/udp-withdrawal-before.yml" ]] \
        || fail 'UDP drift backup already exists'
    cp --preserve=mode,ownership,timestamps -- "$dynamic_file" "$root/udp-withdrawal-before.yml"
    chmod 600 "$root/udp-withdrawal-before.yml"
    digest_file "$dynamic_file" > "$root/logs/udp-withdrawal-original.sha256"
    chmod 600 "$root/logs/udp-withdrawal-original.sha256"
    digest_file "$static_file" > "$root/logs/udp-withdrawal-static.sha256"
    chmod 600 "$root/logs/udp-withdrawal-static.sha256"
    metadata=$(stat -c '%a %u %g' "$dynamic_file")
    read -r mode uid gid <<< "$metadata"
    temporary=$(mktemp "${dynamic_file}.review-transactions.XXXXXX")
    if ! jq 'del(.udp.routers.echo)' "$dynamic_file" > "$temporary"; then
        rm -f -- "$temporary"
        fail 'could not stage UDP route drift'
    fi
    jq -e '(.udp.routers.echo == null) and (.udp.routers["echo-other"].entryPoints == ["udp-other"]) and (.udp.services.echo.loadBalancer.servers[0].address == "127.0.0.1:19002")' \
        "$temporary" >/dev/null || { rm -f -- "$temporary"; fail 'staged UDP drift has an unexpected graph'; }
    chown "$uid:$gid" "$temporary"
    chmod "$mode" "$temporary"
    mv -f -- "$temporary" "$dynamic_file"
    digest_file "$dynamic_file" > "$root/logs/udp-withdrawal-drift.sha256"
    chmod 600 "$root/logs/udp-withdrawal-drift.sha256"
    main_pid > "$root/logs/udp-withdrawal-pid.before"
    chmod 600 "$root/logs/udp-withdrawal-pid.before"
    [[ -n "$owner" ]] || fail 'managed owner identity is empty'
}

udp_live_witness() {
    verify_owned_service >/dev/null
    jq -e '(.udp.routers.echo == null) and (.udp.routers["echo-other"].entryPoints == ["udp-other"]) and (.http.routers.catalog != null)' \
        "$dynamic_file" >/dev/null || fail 'disk drift no longer matches the requested last-route withdrawal case'
    [[ "$(digest_file "$dynamic_file")" == "$(<"$root/logs/udp-withdrawal-drift.sha256")" ]] \
        || fail 'Read/refresh changed the injected UDP drift before the requested Update'
    [[ -s "$root/logs/udp-withdrawal-pid.before" ]] || fail 'pre-drift Traefik PID evidence is missing'
    [[ "$(main_pid)" == "$(<"$root/logs/udp-withdrawal-pid.before")" ]] \
        || fail 'external file drift unexpectedly restarted Traefik before the Update'
    assert_http_control
    probe_udp drift-live 19000 127.0.0.3 true true
    probe_udp drift-survivor 19003 127.0.0.4 true true
    jq -n \
        --arg case "udp-drift-before-update" \
        --arg mainPid "$(main_pid)" \
        --arg staticSha256 "$(digest_file "$static_file")" \
        --arg dynamicSha256 "$(digest_file "$dynamic_file")" \
        --argjson ingressObserved true \
        --argjson backendObserved true \
        --argjson replyObserved true \
        --argjson httpControlStatus 200 \
        --argjson survivingUdpBackendObserved true \
        '{case:$case,mainPid:$mainPid,staticSha256:$staticSha256,dynamicSha256:$dynamicSha256,ingressObserved:$ingressObserved,backendObserved:$backendObserved,replyObserved:$replyObserved,httpControlStatus:$httpControlStatus,survivingUdpBackendObserved:$survivingUdpBackendObserved}' \
        > "$root/logs/review-transactions-udp-before.json"
    chmod 600 "$root/logs/review-transactions-udp-before.json"
}

udp_withdrawn_witness() {
    verify_owned_service >/dev/null
    jq -e '(.udp.routers.echo == null) and (.udp.routers["echo-other"].entryPoints == ["udp-other"]) and (.http.routers.catalog != null)' \
        "$dynamic_file" >/dev/null || fail 'Update did not leave only the independent UDP control router'
    [[ "$(digest_file "$static_file")" == "$(<"$root/logs/udp-withdrawal-static.sha256")" ]] \
        || fail 'UDP-only withdrawal changed the static configuration and could mask the restart cause'
    local current_pid rawdata
    current_pid=$(main_pid)
    [[ "$current_pid" != "$(<"$root/logs/udp-withdrawal-pid.before")" ]] \
        || fail 'requested UDP withdrawal did not restart the live Traefik process'
    rawdata="$root/logs/review-transactions-rawdata.json"
    curl --noproxy '*' --silent --show-error --fail --max-time 3 \
        --output "$rawdata" http://127.0.0.1:19080/api/rawdata \
        || fail 'live rawdata API was unavailable after UDP withdrawal'
    jq -e '(.udpRouters["echo@file"] == null) and (.udpRouters["echo-other@file"].status == "enabled")' \
        "$rawdata" >/dev/null || fail 'live rawdata did not show only the surviving UDP route'
    assert_http_control
    probe_udp withdrawn 19000 127.0.0.3 false false
    probe_udp surviving 19003 127.0.0.4 true true
    jq -n \
        --arg case "udp-withdrawn-after-update" \
        --arg priorMainPid "$(<"$root/logs/udp-withdrawal-pid.before")" \
        --arg mainPid "$current_pid" \
        --arg staticSha256 "$(digest_file "$static_file")" \
        --arg dynamicSha256 "$(digest_file "$dynamic_file")" \
        --argjson ingressObserved true \
        --argjson backendObserved false \
        --argjson replyObserved false \
        --argjson httpControlStatus 200 \
        --argjson survivingUdpBackendObserved true \
        '{case:$case,priorMainPid:$priorMainPid,mainPid:$mainPid,staticSha256:$staticSha256,dynamicSha256:$dynamicSha256,ingressObserved:$ingressObserved,backendObserved:$backendObserved,replyObserved:$replyObserved,httpControlStatus:$httpControlStatus,survivingUdpBackendObserved:$survivingUdpBackendObserved}' \
        > "$root/logs/review-transactions-udp-after.json"
    chmod 600 "$root/logs/review-transactions-udp-after.json"
}
catalog_observation() {
    local expected=$1 output=$2 nonce status raw leaf cursor record body
    nonce="/items/rollback-$(cat /proc/sys/kernel/random/uuid)"
    body="$root/logs/rollback-control.body"
    raw="$root/logs/rollback-control-api.json"
    for _ in $(seq 1 40); do
        curl -fsS --max-time 2 http://127.0.0.1:19080/api/rawdata > "$raw" &&
            jq -e --argjson expected "$expected" '
                .routers["catalog@file"].status=="enabled" and
                (.services["catalog@file"] | type=="object") and
                ((.services["catalog@file"].loadBalancer.servers // [] | map(.url)) ==
                 (if $expected==200 then ["http://127.0.0.1:8080"] else [] end))' "$raw" >/dev/null && break
        sleep .25
    done
    cursor=$(journalctl -u keroosha-traefik.service -n 1 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
    [[ -n "$cursor" ]] || fail 'missing pre-request journal cursor'
    status=$(curl --noproxy '*' --max-time 4 -sS -H 'Host: shop.acceptance.test' -o "$body" -w '%{http_code}' "http://127.0.0.1:18081$nonce")
    [[ "$status" == "$expected" ]] || fail "catalog returned $status instead of $expected"
    if [[ "$expected" == 200 ]]; then
        [[ $(<"$body") == "http-backend:$nonce;forwarded:127.0.0.1" ]] || fail 'wrong backend response'
    fi
    record=$(journalctl -u keroosha-traefik.service --after-cursor="$cursor" --no-pager -o cat |
        jq -Rsc --arg p "$nonce" '[split("\n")[]|fromjson?|select(.RequestPath==$p)|{status:.DownstreamStatus,backend:(.ServiceURL//null)}]|last')
    jq -e --argjson s "$expected" '.status==$s and .backend==(if $s==200 then "http://127.0.0.1:8080" else null end)' <<<"$record" >/dev/null || fail 'missing or wrong access-log upstream'
    leaf=$(timeout 6 openssl s_client -connect 127.0.0.2:18449 -servername sni-proof.acceptance.test -verify_hostname sni-proof.acceptance.test -verify_return_error -CAfile "$root/certs/sni-proof.pem" </dev/null 2>/dev/null | openssl x509 -outform DER | sha256sum | cut -d' ' -f1)
    jq -ce --argjson status "$expected" --argjson request "$record" --arg leaf "$leaf" --arg pid "$(main_pid)" --arg file "$(digest_file "$dynamic_file")" --argjson pending "$(test -e "$journal_file" && echo true || echo false)" '
        (.services["catalog@file"].loadBalancer.servers//[]|map(.url)) as $servers |
        select(.routers["catalog@file"].status=="enabled" and $servers==(if $status==200 then ["http://127.0.0.1:8080"] else [] end)) |
        {servers:$servers,request:$request,leaf:$leaf,pid:$pid,diskSha256:$file,pending:$pending}' "$raw" > "$output" || fail 'live API control failed'
}

healthy_disk_control() {
    verify_owned_service >/dev/null
    local backup="$root/healthy-disk.original" before="$root/logs/healthy-disk-before.json" after="$root/logs/healthy-disk-after.json"
    case "$mode" in
        healthy-disk-inject)
            [[ ! -e "$backup" && ! -e "$journal_file" ]] || fail 'unsafe healthy control starting state'
            cp -p -- "$dynamic_file" "$backup"
            local cursor temp
            cursor=$(journalctl -u keroosha-traefik.service -n 1 --show-cursor --no-pager | sed -n 's/^-- cursor: //p')
            temp=$(mktemp "${dynamic_file}.fixture.XXXXXXXX")
            printf '{"http":[' > "$temp"; chmod --reference="$dynamic_file" "$temp"; chown --reference="$dynamic_file" "$temp"; mv -T "$temp" "$dynamic_file"
            for _ in $(seq 1 40); do
                journalctl -u keroosha-traefik.service --after-cursor="$cursor" --no-pager -o cat | grep -F 'collecting file configs' >/dev/null && break
                sleep .25
            done
            journalctl -u keroosha-traefik.service --after-cursor="$cursor" --no-pager -o cat | grep -F 'collecting file configs' >/dev/null || fail 'watcher did not reject the damaged file'
            catalog_observation 200 "$before" ;;
        healthy-disk-refused)
            catalog_observation 200 "$after"; cmp -s "$before" "$after" && [[ ! -e "$journal_file" ]] || fail 'refusal altered live state, drift bytes or journal' ;;
        healthy-disk-reconcile)
            [[ "$(digest_file "$dynamic_file")" == "$(jq -er .diskSha256 "$before")" ]] || fail 'fixture no longer owns this edit'
            cp -p -- "$backup" "${backup}.restore"; mv -T "${backup}.restore" "$dynamic_file" ;;
    esac
}

unverified_drift_inject() {
    local owner metadata mode uid gid temporary pid
    owner=$(verify_owned_service)
    jq -e '(.http.services.catalog.loadBalancer.servers | type == "array") and (.http.routers.catalog != null) and (.udp.routers | (has("echo") | not) and has("echo-other"))' \
        "$dynamic_file" >/dev/null || fail 'valid baseline graph is unavailable for the drifted-baseline case'
    [[ ! -e "$root/unverified-dynamic-before.yml" && ! -L "$root/unverified-dynamic-before.yml" ]] \
        || fail 'unverified-baseline backup already exists'
    cp --preserve=mode,ownership,timestamps -- "$dynamic_file" "$root/unverified-dynamic-before.yml"
    chmod 600 "$root/unverified-dynamic-before.yml"
    digest_file "$dynamic_file" > "$root/logs/unverified-dynamic-original.sha256"
    chmod 600 "$root/logs/unverified-dynamic-original.sha256"
    digest_file "$static_file" > "$root/logs/unverified-static-original.sha256"
    chmod 600 "$root/logs/unverified-static-original.sha256"
    pid=$(main_pid)
    printf '%s\n' "$pid" > "$root/logs/unverified-baseline-pid"
    chmod 600 "$root/logs/unverified-baseline-pid"
    metadata=$(stat -c '%a %u %g' "$dynamic_file")
    read -r mode uid gid <<< "$metadata"
    temporary=$(mktemp "${dynamic_file}.review-transactions.XXXXXX")
    if ! jq 'del(.http.services.catalog.loadBalancer.servers)' "$dynamic_file" > "$temporary"; then
        rm -f -- "$temporary"
        fail 'could not stage invalid dynamic drift'
    fi
    jq -e '.http.services.catalog.loadBalancer | has("servers") | not' "$temporary" >/dev/null \
        || { rm -f -- "$temporary"; fail 'staged dynamic drift has an unexpected malformed field'; }
    chown "$uid:$gid" "$temporary"
    chmod "$mode" "$temporary"
    mv -f -- "$temporary" "$dynamic_file"
    digest_file "$dynamic_file" > "$root/logs/unverified-dynamic-drift.sha256"
    chmod 600 "$root/logs/unverified-dynamic-drift.sha256"
    [[ "$(main_pid)" == "$pid" ]] || fail 'external dynamic drift unexpectedly restarted Traefik'
    catalog_observation 503 "$root/logs/unhealthy-disk-before.json"
    jq -n --arg case "unverifiable-dynamic-baseline-injected" --arg mainPid "$pid" \
        --arg dynamicSha256 "$(<"$root/logs/unverified-dynamic-drift.sha256")" \
        --arg staticSha256 "$(<"$root/logs/unverified-static-original.sha256")" \
        --argjson liveProcessUnchanged true --argjson httpControlStatus 503 \
        '{case:$case,mainPid:$mainPid,dynamicSha256:$dynamicSha256,staticSha256:$staticSha256,liveProcessUnchanged:$liveProcessUnchanged,httpControlStatus:$httpControlStatus}' \
        > "$root/logs/review-transactions-unverified-drift.json"
    chmod 600 "$root/logs/review-transactions-unverified-drift.json"
    [[ -n "$owner" ]] || fail 'managed owner identity is empty'
}

unverified_rollback_assert() {
    local owner pid journal_mode
    owner=$(verify_owned_service)
    [[ "$(digest_file "$dynamic_file")" == "$(<"$root/logs/unverified-dynamic-drift.sha256")" ]] \
        || fail 'failed Apply did not restore the exact drifted baseline bytes'
    [[ "$(digest_file "$static_file")" == "$(<"$root/logs/unverified-static-original.sha256")" ]] \
        || fail 'failed dynamic-only Apply changed static configuration'
    pid=$(main_pid)
    [[ -f "$journal_file" && ! -L "$journal_file" ]] || fail 'unverifiable rollback cleared its owner journal'
    journal_mode=$(stat -c '%a %u' "$journal_file")
    [[ "$journal_mode" == '600 0' ]] || fail 'unverifiable rollback journal is not private root-owned mode 0600'
    jq -e --arg owner "$owner" '.version == 3 and .owner == $owner and .restartRequired == false' "$journal_file" >/dev/null \
        || fail 'unverifiable rollback journal lost its owner or restart intent'
    catalog_observation 503 "$root/logs/unhealthy-disk-after.json"
    jq -n --arg case "unverifiable-rollback-retained" --arg mainPid "$pid" \
        --arg dynamicSha256 "$(<"$root/logs/unverified-dynamic-drift.sha256")" \
        --argjson journalVersion 3 --argjson rollbackVerified false --argjson journalPresent true \
        --arg journalMode "0600" --argjson ownerDigestMatched true --argjson httpControlStatus 503 \
        '{case:$case,mainPid:$mainPid,dynamicSha256:$dynamicSha256,journalVersion:$journalVersion,rollbackVerified:$rollbackVerified,journalPresent:$journalPresent,journalMode:$journalMode,ownerDigestMatched:$ownerDigestMatched,httpControlStatus:$httpControlStatus}' \
        > "$root/logs/review-transactions-unverified-rollback.json"
    chmod 600 "$root/logs/review-transactions-unverified-rollback.json"
}

unverified_repair_assert() {
    local owner pid
    owner=$(verify_owned_service)
    jq -e '(.http.routers.catalog != null) and (.http.services.catalog.loadBalancer.servers[0].url == "http://127.0.0.1:8080") and (.udp.routers.echo != null) and (.http.services.catalog.loadBalancer.servers | type == "array")' \
        "$dynamic_file" >/dev/null || fail 'corrective Apply did not restore the valid desired graph'
    [[ ! -e "$journal_file" && ! -L "$journal_file" ]] || fail 'corrective Apply did not clear the verified transaction journal'
    pid=$(main_pid)
    [[ "$(digest_file "$dynamic_file")" != "$(<"$root/logs/unverified-dynamic-drift.sha256")" ]] \
        || fail 'corrective Apply left the invalid dynamic drift in place'
    assert_http_control
    jq -n --arg case "unverifiable-baseline-repaired" --arg mainPid "$pid" \
        --arg dynamicSha256 "$(digest_file "$dynamic_file")" --argjson journalPresent false \
        --argjson graphRestored true --argjson ownerDigestMatched true --argjson httpControlStatus 200 \
        '{case:$case,mainPid:$mainPid,dynamicSha256:$dynamicSha256,journalPresent:$journalPresent,graphRestored:$graphRestored,ownerDigestMatched:$ownerDigestMatched,httpControlStatus:$httpControlStatus}' \
        > "$root/logs/review-transactions-unverified-repair.json"
    chmod 600 "$root/logs/review-transactions-unverified-repair.json"
    [[ -n "$owner" ]] || fail 'managed owner identity is empty'
}


credential_hash_from_file() {
    local value
    value=$(awk -F'"' '$1 == "DNSUPDATE_TSIG_SECRET=" { print $2; found++ } END { if (found != 1) exit 1 }' "$credentials_file") \
        || fail 'DNS credential environment file has no unique TSIG secret'
    [[ -n "$value" ]] || fail 'DNS credential environment secret is empty'
    printf '%s' "$value" | sha256sum | awk '{ print $1 }'
}

credential_hash_from_process() {
    local pid=$1 value
    [[ -r "/proc/$pid/environ" ]] || fail 'Traefik process environment is unavailable'
    value=$(tr '\0' '\n' < "/proc/$pid/environ" \
        | awk -F= '$1 == "DNSUPDATE_TSIG_SECRET" { print substr($0, index($0, "=") + 1); found++ } END { if (found != 1) exit 1 }') \
        || fail 'Traefik process does not expose one loaded TSIG secret'
    printf '%s' "$value" | sha256sum | awk '{ print $1 }'
}

assert_secret_absent_from_managed_files_and_argv() {
    local value=$1 path content cmdline
    for path in "$unit_file" "$static_file" "$dynamic_file" "$root"/logs/*; do
        [[ -f "$path" && ! -L "$path" ]] || continue
        content=$(<"$path")
        [[ "$content" != *"$value"* ]] || fail 'new credential value appeared in a unit, Traefik config, or acceptance log'
    done
    for path in /proc/[0-9]*/cmdline; do
        [[ -r "$path" ]] || continue
        cmdline=$(tr '\0' ' ' < "$path" 2>/dev/null) || continue
        [[ "$cmdline" != *"$value"* ]] || fail 'new credential value appeared in a process command line'
    done
}

restart_interrupt_install() {
    verify_owned_service >/dev/null
    [[ -x /usr/bin/systemctl ]] || fail 'real systemctl executable is missing'
    [[ ! -e /usr/local/sbin/systemctl && ! -L /usr/local/sbin/systemctl ]] \
        || fail 'refusing to replace existing /usr/local/sbin/systemctl'
    [[ ! -e /usr/local/bin/systemctl && ! -L /usr/local/bin/systemctl ]] \
        || fail 'refusing to replace existing /usr/local/bin/systemctl'
    [[ ! -e "$root/systemctl-interposer.sh" && ! -L "$root/systemctl-interposer.sh" ]] || fail 'interposer script already exists in the private fixture'
    [[ ! -e "$root/.restart-interrupt-pending" && ! -L "$root/.restart-interrupt-pending" ]] || fail 'an earlier interruption marker remains'
    [[ ! -e "$root/.systemctl-interposer.sha256" && ! -L "$root/.systemctl-interposer.sha256" ]] || fail 'an earlier interposer digest remains'
    for evidence in "$root/logs/restart-interrupted" "$root/logs/restart-interrupted-helper.pid"; do
        if [[ -e "$evidence" || -L "$evidence" ]]; then
            [[ -f "$evidence" && ! -L "$evidence" && "$(stat -c '%u' "$evidence")" == 0 ]] \
                || fail 'refusing to replace foreign interruption evidence'
            rm -- "$evidence"
        fi
    done
    digest_file "$static_file" > "$root/logs/restart-interrupt-static.before.sha256"
    chmod 600 "$root/logs/restart-interrupt-static.before.sha256"
    main_pid > "$root/logs/restart-interrupt-pid.before"
    chmod 600 "$root/logs/restart-interrupt-pid.before"
    local shim="$root/systemctl-interposer.sh" sha
    cat > "$shim" <<EOF
#!/usr/bin/env bash
set -euo pipefail
root='$root'
if [[ "\${1:-}" == restart && "\${2:-}" == keroosha-traefik.service && -e "\$root/.restart-interrupt-pending" ]]; then
    rm -f -- "\$root/.restart-interrupt-pending"
    printf '%s\\n' "\$PPID" > "\$root/logs/restart-interrupted-helper.pid"
    printf 'fired\\n' > "\$root/logs/restart-interrupted"
    chmod 600 "\$root/logs/restart-interrupted-helper.pid" "\$root/logs/restart-interrupted"
    kill -KILL "\$PPID" 2>/dev/null || true
    exit 137
fi
exec /usr/bin/systemctl "\$@"
EOF
    chmod 700 "$shim"
    sha=$(digest_file "$shim")
    install -o root -g root -m 0755 -- "$shim" /usr/local/sbin/systemctl
    install -o root -g root -m 0755 -- "$shim" /usr/local/bin/systemctl
    printf '%s\n' "$sha" > "$root/.systemctl-interposer.sha256"
    chmod 600 "$root/.systemctl-interposer.sha256"
    : > "$root/.restart-interrupt-pending"
    chmod 600 "$root/.restart-interrupt-pending"
    hash -r
    [[ "$(command -v systemctl)" == /usr/local/sbin/systemctl || "$(command -v systemctl)" == /usr/local/bin/systemctl ]] \
        || fail 'transaction shell did not resolve the disposable systemctl interposer first'
}

restart_interrupt_assert_staged() {
    local expected_pid=$1 old_hash=$2 new_hash=$3 current_pid owner journal_mode value
    [[ "$expected_pid" =~ ^[1-9][0-9]*$ && "$old_hash" =~ ^[a-f0-9]{64}$ && "$new_hash" =~ ^[a-f0-9]{64}$ ]] \
        || fail 'interrupted environment assertions received malformed evidence'
    [[ -f "$root/logs/restart-interrupted" && "$(<"$root/logs/restart-interrupted")" == fired ]] \
        || fail 'the helper was not interrupted at the systemd restart boundary'
    [[ -f "$root/logs/restart-interrupted-helper.pid" && "$(<"$root/logs/restart-interrupted-helper.pid")" =~ ^[1-9][0-9]*$ ]] \
        || fail 'interrupted helper PID evidence is missing'
    current_pid=$(main_pid)
    [[ "$current_pid" == "$expected_pid" ]] || fail 'Traefik PID changed before the interrupted restart could occur'
    [[ "$(digest_file "$static_file")" == "$(<"$root/logs/restart-interrupt-static.before.sha256")" ]] \
        || fail 'credential-only interruption unexpectedly changed static configuration'
    [[ -f "$credentials_file" && ! -L "$credentials_file" ]] || fail 'managed credential environment file is missing or unsafe'
    [[ "$(stat -c '%a %u' "$credentials_file")" == '600 0' ]] || fail 'credential environment file is not private root-owned mode 0600'
    [[ "$(credential_hash_from_file)" == "$new_hash" ]] || fail 'credential environment file does not contain the requested new secret'
    [[ "$(credential_hash_from_process "$current_pid")" == "$old_hash" ]] || fail 'live Traefik process already consumed the new credential before the restart'
    [[ -f "$journal_file" && ! -L "$journal_file" ]] || fail 'owned interrupted transaction journal is missing'
    journal_mode=$(stat -c '%a %u' "$journal_file")
    [[ "$journal_mode" == '600 0' ]] || fail 'transaction journal is not private root-owned mode 0600'
    owner=$(verify_owned_service)
    jq -e --arg owner "$owner" '.version == 3 and .owner == $owner and .restartRequired == true' "$journal_file" >/dev/null \
        || fail 'owned transaction journal lost its durable restart intent'
    value=$(awk -F'"' '$1 == "DNSUPDATE_TSIG_SECRET=" { print $2; found++ } END { if (found != 1) exit 1 }' "$credentials_file") \
        || fail 'new credential value could not be inspected'
    assert_secret_absent_from_managed_files_and_argv "$value"
    jq -n \
        --arg case "credential-staged-before-restart" \
        --arg oldMainPid "$expected_pid" \
        --arg mainPid "$current_pid" \
        --arg envFileSha256 "$new_hash" \
        --arg processEnvSha256 "$old_hash" \
        --argjson journalVersion 3 \
        --argjson restartRequired true \
        --arg journalMode "0600" \
        '{case:$case,oldMainPid:$oldMainPid,mainPid:$mainPid,envFileSha256:$envFileSha256,processEnvSha256:$processEnvSha256,journalVersion:$journalVersion,restartRequired:$restartRequired,journalMode:$journalMode}' \
        > "$root/logs/review-transactions-credential-staged.json"
    chmod 600 "$root/logs/review-transactions-credential-staged.json"
}
restart_interrupt_assert_static_staged() {
    local expected_pid=$1 expected_hash=$2 current_pid owner journal_mode
    [[ "$expected_pid" =~ ^[1-9][0-9]*$ && "$expected_hash" =~ ^[a-f0-9]{64}$ ]] \
        || fail 'static interruption assertions received malformed evidence'
    [[ -f "$root/logs/restart-interrupted" && "$(<"$root/logs/restart-interrupted")" == fired ]] \
        || fail 'the helper was not interrupted at the systemd restart boundary'
    current_pid=$(main_pid)
    [[ "$current_pid" == "$expected_pid" ]] || fail 'static write restarted Traefik before the interrupted restart boundary'
    [[ "$(digest_file "$static_file")" != "$(<"$root/logs/restart-interrupt-static.before.sha256")" ]] \
        || fail 'static interruption did not write the changed static configuration'
    jq -e '.log.level == "INFO"' "$static_file" >/dev/null || fail 'staged static log level is not INFO'
    [[ "$(credential_hash_from_file)" == "$expected_hash" && "$(credential_hash_from_process "$current_pid")" == "$expected_hash" ]] \
        || fail 'static-only interruption changed the active DNS credential'
    [[ -f "$journal_file" && ! -L "$journal_file" ]] || fail 'owned interrupted transaction journal is missing'
    journal_mode=$(stat -c '%a %u' "$journal_file")
    [[ "$journal_mode" == '600 0' ]] || fail 'transaction journal is not private root-owned mode 0600'
    owner=$(verify_owned_service)
    jq -e --arg owner "$owner" '.version == 3 and .owner == $owner and .restartRequired == true' "$journal_file" >/dev/null \
        || fail 'static restart intent was not retained in the owner-authenticated journal'
    jq -n \
        --arg case "static-staged-before-restart" \
        --arg oldMainPid "$expected_pid" \
        --arg mainPid "$current_pid" \
        --arg baselineStaticSha256 "$(<"$root/logs/restart-interrupt-static.before.sha256")" \
        --arg staticSha256 "$(digest_file "$static_file")" \
        --arg logLevel "INFO" \
        --arg credentialEnvSha256 "$expected_hash" \
        --arg processEnvSha256 "$expected_hash" \
        --argjson journalVersion 3 \
        --argjson restartRequired true \
        '{case:$case,oldMainPid:$oldMainPid,mainPid:$mainPid,baselineStaticSha256:$baselineStaticSha256,staticSha256:$staticSha256,logLevel:$logLevel,credentialEnvSha256:$credentialEnvSha256,processEnvSha256:$processEnvSha256,journalVersion:$journalVersion,restartRequired:$restartRequired}' \
        > "$root/logs/review-transactions-static-staged.json"
    chmod 600 "$root/logs/review-transactions-static-staged.json"
}


restart_interrupt_downgrade_v2() {
    local owner temporary
    owner=$(verify_owned_service)
    [[ -f "$journal_file" && ! -L "$journal_file" ]] || fail 'transaction journal is unavailable for legacy migration check'
    jq -e --arg owner "$owner" '.version == 3 and .owner == $owner and .restartRequired == true' "$journal_file" >/dev/null \
        || fail 'legacy migration requires the exact owner-authenticated v3 intent journal'
    temporary=$(mktemp "$config_dir/.review-transactions-journal.XXXXXX")
    if ! jq 'del(.restartRequired) | .version = 2' "$journal_file" > "$temporary"; then
        rm -f -- "$temporary"
        fail 'could not stage the v2 journal migration fixture'
    fi
    chown root:root "$temporary"
    chmod 600 "$temporary"
    mv -f -- "$temporary" "$journal_file"
    [[ "$(stat -c '%a %u' "$journal_file")" == '600 0' ]] || fail 'legacy journal fixture lost private ownership or mode'
    jq -n --arg case "legacy-journal-v2" --argjson journalVersion 2 --argjson restartRequiredFieldPresent false --argjson ownerDigestMatched true \
        '{case:$case,journalVersion:$journalVersion,restartRequiredFieldPresent:$restartRequiredFieldPresent,ownerDigestMatched:$ownerDigestMatched}' \
        > "$root/logs/review-transactions-journal-v2.json"
    chmod 600 "$root/logs/review-transactions-journal-v2.json"
}

restart_interrupt_remove() {
    local expected_sha path
    [[ -f "$root/.systemctl-interposer.sha256" && ! -L "$root/.systemctl-interposer.sha256" ]] \
        || fail 'interposer ownership digest is missing'
    expected_sha=$(<"$root/.systemctl-interposer.sha256")
    [[ "$expected_sha" =~ ^[a-f0-9]{64}$ ]] || fail 'interposer ownership digest is malformed'
    for path in /usr/local/sbin/systemctl /usr/local/bin/systemctl; do
        [[ -f "$path" && ! -L "$path" && "$(digest_file "$path")" == "$expected_sha" ]] \
            || fail 'refusing to remove a changed or foreign systemctl interposer'
    done
    rm -- /usr/local/sbin/systemctl /usr/local/bin/systemctl
    rm -f -- "$root/.restart-interrupt-pending" "$root/.systemctl-interposer.sha256" "$root/systemctl-interposer.sh"
    hash -r
    [[ "$(command -v systemctl)" == /usr/bin/systemctl || "$(command -v systemctl)" == /bin/systemctl ]] \
        || fail 'real systemctl did not become active after interposer cleanup'
}

restart_interrupt_assert_restarted() {
    local expected_pid=$1 new_hash=$2 current_pid
    [[ "$expected_pid" =~ ^[1-9][0-9]*$ && "$new_hash" =~ ^[a-f0-9]{64}$ ]] \
        || fail 'restarted environment assertions received malformed evidence'
    current_pid=$(main_pid)
    [[ "$current_pid" != "$expected_pid" ]] || fail 'retry did not replace the old Traefik process'
    [[ "$(credential_hash_from_file)" == "$new_hash" ]] || fail 'credential environment file changed during recovery'
    [[ "$(digest_file "$static_file")" == "$(<"$root/logs/restart-interrupt-static.before.sha256")" ]] \
        || fail 'credential-only recovery changed static configuration'
    [[ "$(credential_hash_from_process "$current_pid")" == "$new_hash" ]] \
        || fail 'restarted Traefik process did not load the new credential'
    [[ ! -e "$journal_file" && ! -L "$journal_file" ]] || fail 'completed recovery left the transaction journal behind'
    local value
    value=$(awk -F'"' '$1 == "DNSUPDATE_TSIG_SECRET=" { print $2; found++ } END { if (found != 1) exit 1 }' "$credentials_file") \
        || fail 'new credential value could not be inspected after restart'
    assert_secret_absent_from_managed_files_and_argv "$value"
    jq -n \
        --arg case "credential-recovered-after-retry" \
        --arg oldMainPid "$expected_pid" \
        --arg mainPid "$current_pid" \
        --arg envFileSha256 "$new_hash" \
        --arg processEnvSha256 "$new_hash" \
        --argjson journalPresent false \
        '{case:$case,oldMainPid:$oldMainPid,mainPid:$mainPid,envFileSha256:$envFileSha256,processEnvSha256:$processEnvSha256,journalPresent:$journalPresent}' \
        > "$root/logs/review-transactions-credential-recovered.json"
    chmod 600 "$root/logs/review-transactions-credential-recovered.json"
}
restart_interrupt_assert_static_restarted() {
    local expected_pid=$1 expected_hash=$2 current_pid
    [[ "$expected_pid" =~ ^[1-9][0-9]*$ && "$expected_hash" =~ ^[a-f0-9]{64}$ ]] \
        || fail 'restarted static assertions received malformed evidence'
    current_pid=$(main_pid)
    [[ "$current_pid" != "$expected_pid" ]] || fail 'static retry did not replace the old Traefik process'
    jq -e '.log.level == "INFO"' "$static_file" >/dev/null || fail 'static retry did not retain log.level INFO'
    [[ "$(credential_hash_from_file)" == "$expected_hash" && "$(credential_hash_from_process "$current_pid")" == "$expected_hash" ]] \
        || fail 'static retry changed or failed to preserve the DNS credential'
    [[ ! -e "$journal_file" && ! -L "$journal_file" ]] || fail 'completed static recovery left its transaction journal behind'
    jq -n \
        --arg case "static-recovered-after-retry" \
        --arg oldMainPid "$expected_pid" \
        --arg mainPid "$current_pid" \
        --arg baselineStaticSha256 "$(<"$root/logs/restart-interrupt-static.before.sha256")" \
        --arg staticSha256 "$(digest_file "$static_file")" \
        --arg logLevel "INFO" \
        --arg credentialEnvSha256 "$expected_hash" \
        --arg processEnvSha256 "$expected_hash" \
        --argjson journalPresent false \
        '{case:$case,oldMainPid:$oldMainPid,mainPid:$mainPid,baselineStaticSha256:$baselineStaticSha256,staticSha256:$staticSha256,logLevel:$logLevel,credentialEnvSha256:$credentialEnvSha256,processEnvSha256:$processEnvSha256,journalPresent:$journalPresent}' \
        > "$root/logs/review-transactions-static-recovered.json"
    chmod 600 "$root/logs/review-transactions-static-recovered.json"
}


case "$mode" in
    healthy-disk-inject|healthy-disk-refused|healthy-disk-reconcile) healthy_disk_control ;;
    binary-stage-inject) binary_stage_inject ;;
    binary-stage-assert-clean) binary_stage_assert_clean ;;
    udp-drift-inject) udp_drift_inject ;;
    udp-live-witness) udp_live_witness ;;
    udp-withdrawn-witness) udp_withdrawn_witness ;;
    restart-interrupt-install) restart_interrupt_install ;;
    restart-interrupt-assert-staged) restart_interrupt_assert_staged "$@" ;;
    restart-interrupt-downgrade-v2) restart_interrupt_downgrade_v2 ;;
    restart-interrupt-remove) restart_interrupt_remove ;;
    restart-interrupt-assert-restarted) restart_interrupt_assert_restarted "$@" ;;
    restart-interrupt-assert-static-staged) restart_interrupt_assert_static_staged "$@" ;;
    restart-interrupt-assert-static-restarted) restart_interrupt_assert_static_restarted "$@" ;;
    unverified-drift-inject) unverified_drift_inject ;;
    unverified-rollback-assert) unverified_rollback_assert ;;
    unverified-repair-assert) unverified_repair_assert ;;
esac
printf 'Transaction acceptance case passed: %s\n' "$mode"
