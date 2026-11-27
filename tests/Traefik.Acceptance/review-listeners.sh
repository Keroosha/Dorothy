#!/usr/bin/env bash
set -euo pipefail
umask 077

readonly ROOT_MARKER=dorothy-traefik-acceptance-guest-v1
readonly FIXTURE_MARKER=dorothy-traefik-review-listeners-v1
readonly STATIC_CONFIG=/etc/keroosha-iac/traefik/static.yml
readonly DYNAMIC_CONFIG=/etc/keroosha-iac/traefik/dynamic/current.yml
readonly CONFIG_DIR=/etc/keroosha-iac/traefik
readonly UNIT=keroosha-traefik.service
readonly UNIT_PATH=/etc/systemd/system/keroosha-traefik.service
readonly ADMIN_PORT=19080
readonly OTEL_LOG_NAME=otelcol.log

usage() {
    printf 'Usage: review-listeners.sh {prepare|inject-forwarded|assert-forwarded-drift|restore-forwarded|assert-forwarded-restored|assert-forwarded-repaired|inject-proxy|assert-proxy-drift|restore-proxy|assert-proxy-restored|assert-proxy-repaired|assert-otlp-current|restore} /var/tmp/dorothy-traefik-acceptance.XXXXXXXX\n' >&2
    exit 2
}

fail() {
    printf 'Listener review acceptance failed: %s\n' "$1" >&2
    exit 1
}

[[ $# == 2 ]] || usage
mode=$1
case "$mode" in
    reconcile-forwarded|reconcile-proxy) ;;
    prepare|inject-forwarded|assert-forwarded-drift|restore-forwarded|assert-forwarded-restored|assert-forwarded-repaired|inject-proxy|assert-proxy-drift|restore-proxy|assert-proxy-restored|assert-proxy-repaired|assert-otlp-current|restore) ;;
    *) usage ;;
esac
[[ $EUID == 0 ]] || fail 'must run as root on the disposable guest'
for command in awk chmod chown cmp cp curl date jq mktemp mv openssl perl realpath rm sha256sum stat systemctl tail timeout; do
    command -v "$command" >/dev/null 2>&1 || fail 'a required guest command is unavailable'
done

[[ -d "$2" && ! -L "$2" ]] || fail 'guest fixture root is not a real directory'
root=$(realpath -e -- "$2")
[[ "$root" =~ ^/var/tmp/dorothy-traefik-acceptance\.[[:alnum:]]+$ ]] \
    || fail 'refusing a path outside the disposable guest temp root'
[[ -f "$root/.owner" && ! -L "$root/.owner" && "$(<"$root/.owner")" == "$ROOT_MARKER" ]] \
    || fail 'guest fixture ownership marker is missing'

readonly FIXTURE=$root/review-listeners
readonly OTEL_LOG=$root/logs/$OTEL_LOG_NAME
stage=
cleanup() {
    if [[ -n "$stage" && -f "$stage" && ! -L "$stage" ]]; then
        rm -f -- "$stage"
    fi
}
trap cleanup EXIT

digest() { sha256sum -- "$1" | awk '{ print $1 }'; }
metadata() { stat --format='%a:%u:%g' -- "$1"; }

safe_file() {
    [[ -f "$1" && ! -L "$1" && "$(realpath -e -- "$1")" == "$1" ]]
}

service_pid() {
    local fragment pid
    fragment=$(systemctl show --property=FragmentPath --value "$UNIT" 2>/dev/null) \
        || fail 'owned Traefik unit is unavailable'
    [[ "$fragment" == "$UNIT_PATH" ]] || fail 'refusing to use a non-owned Traefik unit'
    systemctl is-active --quiet "$UNIT" || fail 'owned Traefik service is not active'
    pid=$(systemctl show --property=MainPID --value "$UNIT" 2>/dev/null) \
        || fail 'owned Traefik process identity is unavailable'
    [[ "$pid" =~ ^[1-9][0-9]*$ ]] || fail 'owned Traefik process identity is invalid'
    printf '%s' "$pid"
}

api_entrypoints() {
    local destination=$FIXTURE/api-entrypoints.json
    safe_file "$STATIC_CONFIG" || fail 'owned static configuration is missing or unsafe'
    if [[ -L "$destination" ]]; then fail 'private API evidence path is unsafe'; fi
    curl --noproxy '*' --silent --show-error --fail \
        --connect-timeout 2 --max-time 5 \
        "http://127.0.0.1:$ADMIN_PORT/api/entrypoints?per_page=100&page=1" \
        --output "$destination" 2> "$FIXTURE/api-entrypoints.curl-error" \
        || fail 'private Traefik entrypoint API is unavailable'
    chmod 600 "$destination" "$FIXTURE/api-entrypoints.curl-error"
    jq -e 'type == "array"' "$destination" >/dev/null 2>&1 \
        || fail 'private Traefik entrypoint API returned invalid data'
}

api_trust_matches() {
    local name=$1 field=$2 expected=$3
    api_entrypoints
    jq -e --arg name "$name" --arg field "$field" --arg expected "$expected" '
        [.[] | select(.name == $name) | .[$field].trustedIPs[]?] == [$expected]
    ' "$FIXTURE/api-entrypoints.json" >/dev/null 2>&1
}

static_trust_matches() {
    local name=$1 field=$2 expected=$3
    jq -e --arg name "$name" --arg field "$field" --arg expected "$expected" '
        .entryPoints[$name][$field].trustedIPs == [$expected]
    ' "$STATIC_CONFIG" >/dev/null 2>&1
}

assert_review_configuration() {
    safe_file "$STATIC_CONFIG" || fail 'owned static configuration is missing or unsafe'
    safe_file "$DYNAMIC_CONFIG" || fail 'owned dynamic configuration is missing or unsafe'
    jq -e '
        .entryPoints["review-front"].address == "127.0.0.1:18445/tcp"
        and .entryPoints["review-front"].forwardedHeaders.trustedIPs == ["127.0.0.1/32"]
        and .entryPoints["review-proxy-v1"].address == "127.0.0.1:19010/tcp"
        and .entryPoints["review-proxy-v1"].proxyProtocol.trustedIPs == ["127.0.0.1/32"]
        and .entryPoints["keroosha-admin"].address == "127.0.0.1:19080"
        and .experimental.otlpLogs == true
        and .log.otlp.http.endpoint == "http://127.0.0.1:4318/v1/logs"
        and .accessLog.otlp.http.endpoint == "http://127.0.0.1:4318/v1/logs"
    ' "$STATIC_CONFIG" >/dev/null 2>&1 || fail 'review static listener or OTLP configuration is not the expected safe fixture'
    jq -e '
        .http.routers["review-forwarded"].entryPoints == ["review-front"]
        and .http.routers["review-otlp-event"].entryPoints == ["review-front"]
        and .tcp.routers["review-proxy-v1"].entryPoints == ["review-proxy-v1"]
    ' "$DYNAMIC_CONFIG" >/dev/null 2>&1 || fail 'review dynamic listener discriminator routes are missing'
}

record_snapshot() {
    local name=$1
    local path="$FIXTURE/$name.static"
    local meta="$FIXTURE/$name.meta"
    local sha="$FIXTURE/$name.sha256"
    [[ ! -e "$path" && ! -L "$path" && ! -e "$meta" && ! -L "$meta" \
       && ! -e "$sha" && ! -L "$sha" ]] || fail 'private listener snapshot already exists'
    cp -- "$STATIC_CONFIG" "$path"
    chmod 600 "$path"
    printf '%s\n' "$(metadata "$STATIC_CONFIG")" > "$meta"
    printf '%s\n' "$(digest "$STATIC_CONFIG")" > "$sha"
    chmod 600 "$meta" "$sha"
}

verify_snapshot() {
    local name=$1
    local path="$FIXTURE/$name.static"
    local meta="$FIXTURE/$name.meta"
    local sha="$FIXTURE/$name.sha256"
    [[ -f "$path" && ! -L "$path" && -f "$meta" && ! -L "$meta" \
       && -f "$sha" && ! -L "$sha" ]] || fail 'private listener snapshot is missing or unsafe'
    [[ "$(<"$sha")" == "$(digest "$path")" ]] || fail 'private listener snapshot checksum is inconsistent'
}

replace_static() {
    local source=$1 metadata_path=$2 mode uid gid
    safe_file "$source" || fail 'private listener replacement file is missing or unsafe'
    [[ -f "$metadata_path" && ! -L "$metadata_path" \
       && "$(realpath -e -- "$metadata_path")" == "$metadata_path" ]] \
        || fail 'private listener metadata file is missing or unsafe'
    IFS=: read -r mode uid gid < "$metadata_path"
    [[ "$mode" =~ ^[0-7]{3,4}$ && "$uid" =~ ^[0-9]+$ && "$gid" =~ ^[0-9]+$ ]] \
        || fail 'private listener file metadata is malformed'
    stage=$(mktemp "$CONFIG_DIR/.review-listeners.XXXXXXXX") \
        || fail 'cannot stage owned static configuration'
    cp -- "$source" "$stage" || fail 'cannot stage owned static configuration'
    chown "$uid:$gid" "$stage" || fail 'cannot preserve static configuration owner'
    chmod "$mode" "$stage" || fail 'cannot preserve static configuration mode'
    mv -fT -- "$stage" "$STATIC_CONFIG" || fail 'cannot atomically replace owned static configuration'
    stage=
    [[ "$(metadata "$STATIC_CONFIG")" == "$mode:$uid:$gid" ]] \
        || fail 'replaced static configuration metadata is inconsistent'
}

restore_snapshot() {
    local name=$1
    verify_snapshot "$name"
    replace_static "$FIXTURE/$name.static" "$FIXTURE/$name.meta"
    cmp -s -- "$STATIC_CONFIG" "$FIXTURE/$name.static" \
        || fail 'restored static configuration bytes differ from the saved desired file'
    [[ "$(metadata "$STATIC_CONFIG")" == "$(<"$FIXTURE/$name.meta")" ]] \
        || fail 'restored static configuration metadata differs from the saved desired file'
}

restart_service() {
    local before=$1 after=
    service_pid >/dev/null
    timeout --foreground --kill-after=2 30 systemctl restart "$UNIT" \
        > "$FIXTURE/restart.log" 2>&1 || fail 'owned Traefik service restart failed'
    chmod 600 "$FIXTURE/restart.log"
    for _ in {1..30}; do
        if systemctl is-active --quiet "$UNIT"; then
            after=$(systemctl show --property=MainPID --value "$UNIT" 2>/dev/null || true)
            if [[ "$after" =~ ^[1-9][0-9]*$ ]]; then break; fi
        fi
        sleep 1
    done
    [[ "$after" =~ ^[1-9][0-9]*$ && "$after" != "$before" ]] \
        || fail 'Traefik did not restart to load the listener policy'
    printf '%s' "$after"
}

new_token() {
    printf 'review-%s-%s-%s' "$$" "$RANDOM" "$RANDOM"
}

# The collector interleaves app logs, access logs and metrics under overlapping service names.
# Require the service and request marker to belong to a LogRecord in the same ResourceLog.
has_otlp_record() {
    awk -v service="$2" -v token="${3:-}" '
        /Resource(Log|Metrics|Spans) #[0-9]+/ { logs = /ResourceLog #/; named = 0; record = 0 }
        logs && index($0, "service.name: Str(" service ")") { named = 1 }
        /^LogRecord #[0-9]+/ { record = logs && named }
        record && (token == "" || index($0, token)) { found = 1; exit }
        END { exit !found }
    ' "$1"
}

probe_forwarded() {
    local trust=$1 label=$2 token body status
    token=$(new_token)
    body="$FIXTURE/http-$label.body"
    [[ ! -e "$body" && ! -L "$body" ]] || fail 'private forwarded-header evidence already exists'
    if ! status=$(timeout --foreground --kill-after=1 8 curl --noproxy '*' \
        --silent --show-error --connect-timeout 2 --max-time 5 \
        --resolve sni-proof.acceptance.test:18445:127.0.0.1 \
        --header 'X-Forwarded-For: 198.51.100.77' \
        --output "$body" --write-out '%{http_code}' \
        "http://sni-proof.acceptance.test:18445/forwarded/$token" \
        2> "$FIXTURE/http-$label.curl-error"); then
        fail 'plain HTTP forwarded-header probe did not complete'
    fi
    chmod 600 "$body" "$FIXTURE/http-$label.curl-error"
    [[ "$status" == 200 ]] || fail 'plain HTTP forwarded-header route returned an unexpected status'
    grep -Fq "http-backend:/forwarded/$token;forwarded:" "$body" \
        || fail 'plain HTTP forwarded-header request reached an unexpected backend'
    if [[ "$trust" == trusted ]]; then
        grep -Fq '198.51.100.77' "$body" \
            || fail 'trusted HTTP forwarded-header value was not preserved'
    else
        ! grep -Fq '198.51.100.77' "$body" \
            || fail 'untrusted HTTP forwarded-header value was preserved'
        grep -Fq '127.0.0.1' "$body" \
            || fail 'untrusted HTTP forwarded-header request did not use the actual peer address'
    fi
}

probe_proxy_v1() {
    local trust=$1 label=$2 token response
    token=$(new_token)
    response="$FIXTURE/proxy-$label.response"
    [[ ! -e "$response" && ! -L "$response" ]] || fail 'private PROXY evidence already exists'
    if ! timeout --foreground --kill-after=1 8 perl -MIO::Socket::INET - \
        19010 "$token" "$trust" "$response" \
        > "$FIXTURE/proxy-$label.client-log" 2>&1 <<'PERL'
use strict;
use warnings;
my ($port, $token, $trust, $path) = @ARGV;
my $socket = IO::Socket::INET->new(
    PeerAddr => "127.0.0.1", PeerPort => $port, LocalAddr => "127.0.0.1",
    Proto => "tcp", Timeout => 3,
) or die "connect failed";
binmode($socket);
my $socket_port = $socket->sockport;
my $client_header = "PROXY TCP4 203.0.113.55 127.0.0.1 32123 $port\r\n";
my $payload = "review-proxy-$token\r\n";
my $packet = $client_header . $payload;
my $offset = 0;
while ($offset < length($packet)) {
    my $written = syswrite($socket, $packet, length($packet) - $offset, $offset);
    defined($written) && $written > 0 or die "write failed";
    $offset += $written;
}
shutdown($socket, 1) or die "shutdown failed";
my $response = "";
while (1) {
    my $count = sysread($socket, my $chunk, 4096);
    defined($count) or die "read failed";
    last if $count == 0;
    $response .= $chunk;
}
close($socket);
my ($outgoing_header, $forwarded_payload) = split(/\r\n/, $response, 2);
my $expected_source = $trust eq "trusted" ? "203.0.113.55" : "127.0.0.1";
my $expected_port = $trust eq "trusted" ? 32123 : $socket_port;
$outgoing_header eq "PROXY TCP4 $expected_source 127.0.0.1 $expected_port $port"
    or die "outgoing PROXY tuple did not match inbound trust policy";
# The native listener consumes a valid input preface in both cases; the trust policy
# determines whether the backend sees its tuple or the real peer's tuple.
$forwarded_payload eq $payload or die "unexpected bytes after the outgoing PROXY header";
open(my $output, ">:raw", $path) or die "cannot write private response";
print {$output} $response;
close($output) or die "cannot close private response";
PERL
    then
        fail 'raw TCP PROXY listener probe did not complete'
    fi
    chmod 600 "$response" "$FIXTURE/proxy-$label.client-log"
}

mark() {
    local name=$1
    [[ "$name" =~ ^[a-z-]+$ ]] || fail 'invalid private listener phase marker'
    printf '%s\n' "$FIXTURE_MARKER" > "$FIXTURE/$name"
    chmod 600 "$FIXTURE/$name"
}

require_mark() {
    local name=$1
    [[ -f "$FIXTURE/$name" && ! -L "$FIXTURE/$name" \
       && "$(<"$FIXTURE/$name")" == "$FIXTURE_MARKER" ]] \
        || fail 'listener review phase is out of order'
}

load_fixture() {
    [[ -d "$FIXTURE" && ! -L "$FIXTURE" && "$(stat -c '%a:%u' "$FIXTURE")" == 700:0 ]] \
        || fail 'private listener fixture directory is missing or unsafe'
    [[ -f "$FIXTURE/.owner" && ! -L "$FIXTURE/.owner" \
       && "$(<"$FIXTURE/.owner")" == "$FIXTURE_MARKER" ]] \
        || fail 'private listener fixture marker is missing or unsafe'
    safe_file "$STATIC_CONFIG" || fail 'owned static configuration is missing or unsafe'
    safe_file "$DYNAMIC_CONFIG" || fail 'owned dynamic configuration is missing or unsafe'
}

case "$mode" in
    prepare)
        [[ ! -e "$FIXTURE" && ! -L "$FIXTURE" ]] || fail 'private listener fixture already exists'
        mkdir -m 700 -- "$FIXTURE"
        printf '%s\n' "$FIXTURE_MARKER" > "$FIXTURE/.owner"
        chmod 600 "$FIXTURE/.owner"
        assert_review_configuration
        service_pid >/dev/null
        record_snapshot forwarded-before
        [[ -f "$OTEL_LOG" && ! -L "$OTEL_LOG" ]] || fail 'OTLP collector log is missing or unsafe'
        stat --format='%s' "$OTEL_LOG" > "$FIXTURE/otel-before.bytes"
        chmod 600 "$FIXTURE/otel-before.bytes"
        mark prepared
        ;;
    inject-forwarded)
        load_fixture
        require_mark prepared
        verify_snapshot forwarded-before
        local_pid=$(service_pid)
        [[ ! -e "$FIXTURE/forwarded-mutated.json" && ! -L "$FIXTURE/forwarded-mutated.json" ]] \
            || fail 'private forwarded-header candidate already exists'
        jq '.entryPoints["review-front"].forwardedHeaders.trustedIPs = ["127.0.0.2/32"]' \
            "$STATIC_CONFIG" > "$FIXTURE/forwarded-mutated.json" 2>/dev/null \
            || fail 'cannot stage forwarded-header drift'
        chmod 600 "$FIXTURE/forwarded-mutated.json"
        replace_static "$FIXTURE/forwarded-mutated.json" "$FIXTURE/forwarded-before.meta"
        static_trust_matches review-front forwardedHeaders 127.0.0.2/32 \
            || fail 'forwarded-header drift was not installed'
        injected_pid=$(restart_service "$local_pid")
        printf '%s\n' "$injected_pid" > "$FIXTURE/forwarded-injected.pid"
        chmod 600 "$FIXTURE/forwarded-injected.pid"
        ;;
    assert-forwarded-drift)
        load_fixture
        require_mark prepared
        [[ "$(service_pid)" == "$(<"$FIXTURE/forwarded-injected.pid")" ]] \
            || fail 'forwarded-header drift process changed unexpectedly'
        api_trust_matches review-front forwardedHeaders 127.0.0.2/32 \
            || fail 'live API did not report drifted forwarded-header trust'
        probe_forwarded untrusted forwarded-drift
        ;;
    restore-forwarded)
        load_fixture
        require_mark prepared
        restore_snapshot forwarded-before
        [[ "$(service_pid)" == "$(<"$FIXTURE/forwarded-injected.pid")" ]] \
            || fail 'restoring desired forwarded-header bytes unexpectedly restarted Traefik'
        ;;
    reconcile-forwarded|reconcile-proxy)
        load_fixture
        kind=${mode#reconcile-}
        cmp -s "$STATIC_CONFIG" "$FIXTURE/$kind-before.static" || fail 'refusal changed desired static bytes'
        [[ $(service_pid) == "$(<"$FIXTURE/$kind-injected.pid")" && ! -e /etc/keroosha-iac/traefik/.keroosha-rollback.json ]] || fail 'refusal changed PID or created journal'
        if [[ $kind == forwarded ]]; then probe_forwarded untrusted forwarded-refused; else probe_proxy_v1 untrusted proxy-refused; fi
        replace_static "$FIXTURE/$kind-mutated.json" "$FIXTURE/$kind-before.meta"
        ;;
    assert-forwarded-restored)
        load_fixture
        require_mark prepared
        cmp -s -- "$STATIC_CONFIG" "$FIXTURE/forwarded-before.static" \
            || fail 'desired forwarded-header static bytes were not restored'
        [[ "$(service_pid)" == "$(<"$FIXTURE/forwarded-injected.pid")" ]] \
            || fail 'Read precondition changed the running Traefik process'
        api_trust_matches review-front forwardedHeaders 127.0.0.2/32 \
            || fail 'restoring desired files unexpectedly changed live forwarded-header trust'
        probe_forwarded untrusted forwarded-restored
        mark forwarded-restored
        ;;
    assert-forwarded-repaired)
        load_fixture
        require_mark forwarded-restored
        cmp -s -- "$STATIC_CONFIG" "$FIXTURE/forwarded-before.static" \
            || fail 'same-input Apply changed the restored forwarded-header static file'
        assert_review_configuration
        [[ "$(service_pid)" != "$(<"$FIXTURE/forwarded-injected.pid")" ]] \
            || fail 'Apply did not restart the drifted forwarded-header listener'
        api_trust_matches review-front forwardedHeaders 127.0.0.1/32 \
            || fail 'Apply did not restore effective forwarded-header trust'
        probe_forwarded trusted forwarded-repaired
        mark forwarded-repaired
        ;;
    inject-proxy)
        load_fixture
        require_mark forwarded-repaired
        record_snapshot proxy-before
        local_pid=$(service_pid)
        [[ ! -e "$FIXTURE/proxy-mutated.json" && ! -L "$FIXTURE/proxy-mutated.json" ]] \
            || fail 'private PROXY candidate already exists'
        jq '.entryPoints["review-proxy-v1"].proxyProtocol.trustedIPs = ["127.0.0.2/32"]' \
            "$STATIC_CONFIG" > "$FIXTURE/proxy-mutated.json" 2>/dev/null \
            || fail 'cannot stage PROXY trust drift'
        chmod 600 "$FIXTURE/proxy-mutated.json"
        replace_static "$FIXTURE/proxy-mutated.json" "$FIXTURE/proxy-before.meta"
        static_trust_matches review-proxy-v1 proxyProtocol 127.0.0.2/32 \
            || fail 'PROXY trust drift was not installed'
        injected_pid=$(restart_service "$local_pid")
        printf '%s\n' "$injected_pid" > "$FIXTURE/proxy-injected.pid"
        chmod 600 "$FIXTURE/proxy-injected.pid"
        ;;
    assert-proxy-drift)
        load_fixture
        require_mark forwarded-repaired
        [[ "$(service_pid)" == "$(<"$FIXTURE/proxy-injected.pid")" ]] \
            || fail 'PROXY drift process changed unexpectedly'
        api_trust_matches review-proxy-v1 proxyProtocol 127.0.0.2/32 \
            || fail 'live API did not report drifted PROXY trust'
        probe_proxy_v1 untrusted proxy-drift
        ;;
    restore-proxy)
        load_fixture
        require_mark forwarded-repaired
        restore_snapshot proxy-before
        [[ "$(service_pid)" == "$(<"$FIXTURE/proxy-injected.pid")" ]] \
            || fail 'restoring desired PROXY bytes unexpectedly restarted Traefik'
        ;;
    assert-proxy-restored)
        load_fixture
        require_mark forwarded-repaired
        cmp -s -- "$STATIC_CONFIG" "$FIXTURE/proxy-before.static" \
            || fail 'desired PROXY static bytes were not restored'
        [[ "$(service_pid)" == "$(<"$FIXTURE/proxy-injected.pid")" ]] \
            || fail 'Read precondition changed the running Traefik process'
        api_trust_matches review-proxy-v1 proxyProtocol 127.0.0.2/32 \
            || fail 'restoring desired files unexpectedly changed live PROXY trust'
        probe_proxy_v1 untrusted proxy-restored
        mark proxy-restored
        ;;
    assert-proxy-repaired)
        load_fixture
        require_mark proxy-restored
        cmp -s -- "$STATIC_CONFIG" "$FIXTURE/proxy-before.static" \
            || fail 'same-input Apply changed the restored PROXY static file'
        static_trust_matches review-proxy-v1 proxyProtocol 127.0.0.1/32 \
            || fail 'Apply did not restore desired PROXY trust in the static file'
        [[ "$(service_pid)" != "$(<"$FIXTURE/proxy-injected.pid")" ]] \
            || fail 'Apply did not restart the drifted PROXY listener'
        api_trust_matches review-proxy-v1 proxyProtocol 127.0.0.1/32 \
            || fail 'Apply did not restore effective PROXY trust'
        probe_proxy_v1 trusted proxy-repaired
        mark proxy-repaired
        ;;
    assert-otlp-current)
        load_fixture
        require_mark proxy-repaired
        assert_review_configuration
        [[ -f "$OTEL_LOG" && ! -L "$OTEL_LOG" ]] || fail 'OTLP collector log is missing or unsafe'
        baseline_offset=$(<"$FIXTURE/otel-before.bytes")
        [[ "$baseline_offset" =~ ^[0-9]+$ ]] || fail 'saved OTLP log boundary is malformed'
        current_size=$(stat --format='%s' "$OTEL_LOG")
        (( current_size >= baseline_offset )) || fail 'OTLP collector log shrank during the listener scenario'
        app_evidence="$FIXTURE/otel-application-current.log"
        for _ in {1..60}; do
            tail -c "+$((baseline_offset + 1))" "$OTEL_LOG" > "$app_evidence"
            if has_otlp_record "$app_evidence" dorothy-review-acceptance; then break; fi
            sleep 1
        done
        has_otlp_record "$app_evidence" dorothy-review-acceptance \
            || fail 'current application OTLP log event was not observed after listener restarts'
        chmod 600 "$app_evidence"

        event_token=$(new_token)
        access_offset=$(stat --format='%s' "$OTEL_LOG")
        body="$FIXTURE/otlp-event.body"
        current_access="$FIXTURE/otel-access-current.log"
        [[ ! -e "$body" && ! -L "$body" && ! -e "$current_access" && ! -L "$current_access" ]] \
            || fail 'private OTLP event evidence already exists'
        if ! status=$(timeout --foreground --kill-after=1 8 curl --noproxy '*' \
            --silent --show-error --connect-timeout 2 --max-time 5 \
            --resolve sni-proof.acceptance.test:18445:127.0.0.1 \
            --output "$body" --write-out '%{http_code}' \
            "http://sni-proof.acceptance.test:18445/otlp-event/$event_token" \
            2> "$FIXTURE/otlp-event.curl-error"); then
            fail 'unique OTLP access-log request did not complete'
        fi
        chmod 600 "$body" "$FIXTURE/otlp-event.curl-error"
        [[ "$status" == 200 ]] || fail 'unique OTLP access-log request returned an unexpected status'
        grep -Fq "http-backend:/otlp-event/$event_token;forwarded:" "$body" \
            || fail 'unique OTLP access-log request reached an unexpected backend'
        for _ in {1..60}; do
            current_size=$(stat --format='%s' "$OTEL_LOG")
            (( current_size >= access_offset )) || fail 'OTLP collector log shrank during access-log observation'
            tail -c "+$((access_offset + 1))" "$OTEL_LOG" > "$current_access"
            if has_otlp_record "$current_access" dorothy-review-access "$event_token"; then
                break
            fi
            sleep 1
        done
        has_otlp_record "$current_access" dorothy-review-access "$event_token" \
            || fail 'no current access LogRecord from the configured exporter contains the unique request'
        chmod 600 "$current_access"
        printf 'Current application and unique access OTLP log events were observed.\n'
        ;;
    restore)
        load_fixture
        if [[ -f "$FIXTURE/proxy-before.static" && ! -L "$FIXTURE/proxy-before.static" ]]; then
            restore_snapshot proxy-before
        elif [[ -f "$FIXTURE/forwarded-before.static" && ! -L "$FIXTURE/forwarded-before.static" ]]; then
            restore_snapshot forwarded-before
        else
            fail 'no saved desired static file is available for recovery'
        fi
        local_pid=$(service_pid)
        restart_service "$local_pid" >/dev/null
        printf 'Saved desired listener configuration was restored and restarted.\n'
        ;;
esac
